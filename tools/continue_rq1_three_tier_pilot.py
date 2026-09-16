"""Continue unattempted cells after explicitly reviewed sealed failures.

Run from the original frozen execution checkout. This never replaces a failed
cell, changes the manifest, or silently replays a delivered request. A new
failure pauses again. Review receipts and sealed failures remain permanent.
"""
from pathlib import Path
import argparse
import json
import os
import signal
import sys
import uuid

_bootstrap = argparse.ArgumentParser(add_help=False)
_bootstrap.add_argument("--execution-source", type=Path)
_runtime, _ = _bootstrap.parse_known_args()
PROJECT = (_runtime.execution_source or Path(__file__).resolve().parents[1]).resolve()
sys.path.insert(0, str(PROJECT))
from agentmembrane.host_v2.rq1_collab_v1.audit import canonical, _write_new, file_hash, verify
from agentmembrane.host_v2.rq1_collab_v3.contract import digest
from agentmembrane.host_v2.rq1_collab_v6.evaluation import read_evidence
from agentmembrane.host_v2.rq1_three_tier_formal_v1 import diagnostic


def verify_pre_actor_failure(folder, cell, manifest, acknowledgement):
    """Admit only a hash-anchored startup failure before any actor/request event."""
    row = diagnostic._load(folder / "failure.json")
    seal = diagnostic._load(folder / "evidence" / "seal.json")
    expected = acknowledgement.get("execution_seal_sha256")
    if (acknowledgement.get("failure_kind") != "pre_actor_infrastructure_failure"
            or not expected
            or acknowledgement.get("failure_record_sha256") != file_hash(folder / "failure.json")
            or not verify(folder / "evidence", expected_seal_hash=expected)["ok"]):
        raise ValueError("infrastructure_review_anchor_mismatch")
    cleanup = {"process_stop_confirmed": True, "secret_cleanup_confirmed": True}
    failure = seal.get("metadata", {}).get("formal_failure", {})
    events = [json.loads(line) for line in (folder / "evidence" / "events.jsonl").read_text().splitlines()]
    if (row.get("episode_id") != cell["episode_id"]
            or row.get("status") != "infrastructure_failure"
            or row.get("failure_class") != "ProxyLifecycleFailure"
            or row.get("model_request_count") != 0
            or row.get("G") is not None or row.get("L") is not None
            or row.get("cleanup") != cleanup
            or row.get("formal_sample_eligible") is not False
            or failure.get("formal_manifest_sha256") != manifest["manifest_sha256"]
            or failure.get("formal_cell_sha256") != digest(cell)
            or failure.get("episode_id") != cell["episode_id"]
            or failure.get("failure_class") != "ProxyLifecycleFailure"
            or failure.get("cleanup") != cleanup
            or failure.get("replacement_cell_permitted") is not False
            or failure.get("formal_evidence_admitted") is not False
            or [event["kind"] for event in events] != [
                "diagnostic_pilot_allocated", "formal_attempt_failed", "collector_seal"]
            or events[1]["data"] != failure
            or events[-1]["data"].get("model_request_terminal_status") != {}
            or events[-1]["data"].get("request_coverage") != "none_recorded"
            or any((folder / "evidence" / "model_requests").iterdir())):
        raise ValueError("infrastructure_failure_not_pre_actor_or_cleanup_unconfirmed")


def verify_sealed_controller_failure(folder, cell, manifest, acknowledgement, row, evidence):
    """Skip a reviewed cell-local ValueError; never replay it or admit auth failures."""
    expected_failures = [{"kind": "controller_failure", "error_type": "ValueError"}]
    anchor = diagnostic._load(folder / "execution-anchor.json")
    seal = diagnostic._load(folder / "evidence" / "seal.json")
    report = diagnostic._load(folder / "diagnostic-report.json")
    if (acknowledgement.get("failure_kind") != "sealed_controller_failure"
            or acknowledgement.get("execution_seal_sha256") != anchor["seal_sha256"]
            or acknowledgement.get("formal_cell_sha256") != digest(cell)
            or acknowledgement.get("failure_record_sha256") != file_hash(folder / "summary.json")
            or acknowledgement.get("execution_failures_sha256") != digest(expected_failures)
            or not verify(folder / "evidence", expected_seal_hash=anchor["seal_sha256"])["ok"]
            or anchor.get("manifest_sha256") != manifest["manifest_sha256"]
            or row.get("execution_seal_sha256") != anchor["seal_sha256"]
            or row.get("episode_id") != cell["episode_id"]
            or row.get("status") != "sealed_unknown"
            or row.get("G") is not None or row.get("L") is not None
            or row.get("cleanup_confirmed") is not True
            or row.get("evaluation_errors") != []
            or row.get("execution_failures") != expected_failures
            or evidence.get("failures") != expected_failures
            or evidence.get("config") != cell
            or evidence.get("closure_class") != "fatal_unknown"
            or evidence.get("terminal_reason") != "controller_failure"
            or report.get("execution_seal_sha256") != anchor["seal_sha256"]
            or report.get("evaluation_errors") != []
            or report.get("sealed_call_trace_complete") is not True
            or report.get("sealed_call_trace_gaps") != []):
        raise ValueError("sealed_controller_failure_not_safe_to_skip")
    receipt = diagnostic._load(folder / "evidence" / "artifacts" / "proxy-lifecycle-receipt.json")
    diagnostic.validate_cell_lifecycle_receipt(receipt, manifest=manifest, cell=cell)
    extension = seal["metadata"].get("formal_extension", {})
    events = [json.loads(line) for line in (folder / "evidence" / "events.jsonl").read_text().splitlines()]
    terminals = events[-1]["data"].get("model_request_terminal_status", {})
    if (extension.get("pilot_manifest_sha256") != manifest["manifest_sha256"]
            or extension.get("proxy_lifecycle_receipt_sha256") != receipt["receipt_sha256"]
            or receipt["model_request_count"] != row.get("model_request_count")
            or not terminals or len(terminals) != row.get("model_request_count")
            or set(terminals.values()) != {"delivered"}):
        raise ValueError("controller_failure_cleanup_or_request_delivery_unconfirmed")


def plan(manifest_path, review_path):
    manifest = diagnostic.validate_manifest(diagnostic._load(manifest_path))
    review = diagnostic._load(review_path)
    if (review.get("manifest_sha256") != manifest["manifest_sha256"]
            or review.get("retry_existing_cells") is not False
            or review.get("reason") not in {"isolated_upstream_timeout_reviewed", "sealed_failures_reviewed_no_replay"}
            or not isinstance(review.get("acknowledged_failures"), list)):
        raise ValueError("explicit_timeout_review_required")
    acknowledgements = review["acknowledged_failures"]
    if len({r["episode_id"] for r in acknowledgements}) != len(acknowledgements):
        raise ValueError("duplicate_timeout_acknowledgement")
    acknowledged = {r["episode_id"]: r for r in acknowledgements}
    pending, used = [], set()
    for cell in manifest["cells"]:
        folder = Path(manifest["run_parent"]) / cell["episode_id"]
        if not folder.exists():
            pending.append(cell)
            continue
        if (folder / "failure.json").exists():
            if (review.get("reason") != "sealed_failures_reviewed_no_replay"
                    or cell["episode_id"] not in acknowledged
                    or (folder / "summary.json").exists()):
                raise ValueError("unreviewed_infrastructure_failure_requires_attention")
            verify_pre_actor_failure(folder, cell, manifest, acknowledged[cell["episode_id"]])
            used.add(cell["episode_id"])
            continue
        row = diagnostic._load(folder / "summary.json")
        anchor = diagnostic._load(folder / "execution-anchor.json")
        if (anchor["manifest_sha256"] != manifest["manifest_sha256"]
                or anchor["seal_sha256"] != row["execution_seal_sha256"]):
            raise ValueError("prior_cell_anchor_mismatch")
        evidence = read_evidence(folder / "evidence", anchor["seal_sha256"])
        if evidence["config"] != cell or row["evaluation_errors"] or not row["cleanup_confirmed"]:
            raise ValueError("prior_cell_not_safe_to_continue")
        if row["status"] == "completed":
            continue
        if (review.get("reason") == "sealed_failures_reviewed_no_replay"
                and acknowledged.get(cell["episode_id"], {}).get("failure_kind") == "sealed_controller_failure"):
            verify_sealed_controller_failure(folder, cell, manifest,
                                             acknowledged[cell["episode_id"]], row, evidence)
            used.add(cell["episode_id"])
            continue
        failures = evidence["failures"]
        if (cell["episode_id"] not in acknowledged
                or acknowledged[cell["episode_id"]].get("execution_seal_sha256") != anchor["seal_sha256"]
                or row["G"] is not None or row["L"] is not None
                or not failures
                or any(f.get("http_status") != 408 or f.get("kind") != "model_service_error"
                       for f in failures)):
            raise ValueError("unreviewed_or_non_timeout_failure_requires_attention")
        used.add(cell["episode_id"])
    if used != set(acknowledged):
        raise ValueError("review_contains_nonfailed_or_unregistered_cells")
    return manifest, pending


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--review", required=True, type=Path)
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--execution-source", type=Path,
                        help="Import the unchanged manifest-bound execution source from this directory")
    args = parser.parse_args()
    manifest, pending = plan(args.manifest, args.review)
    if args.check_only:
        print(json.dumps({"verified": True, "remaining_cells": len(pending),
                          "existing_cells_will_not_repeat": True, "model_calls": 0}))
        return
    def interrupt(signum, frame):
        raise KeyboardInterrupt("reviewed_pilot_interrupted")
    signal.signal(signal.SIGTERM, interrupt)
    root = args.manifest.absolute().parent
    if str(root / "runs") != manifest["run_parent"]:
        raise ValueError("pilot_output_location_changed")
    lock = root / ".run.lock"
    fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, str(os.getpid()).encode())
        _write_new(root / "continuations" / (uuid.uuid4().hex + ".json"), canonical({
            "manifest_sha256": manifest["manifest_sha256"],
            "review_sha256": file_hash(args.review),
            "controller_source_sha256": file_hash(Path(__file__)),
            "execution_source": str(PROJECT),
            "code_bundle_sha256": manifest["code_bundle_sha256"],
            "unattempted_cells": [c["episode_id"] for c in pending],
            "automatic_cell_retry": False,
        }) + b"\n")
        for cell in pending:
            row = diagnostic.run_cell(manifest, cell)
            print(json.dumps({k: row[k] for k in (
                "episode_id", "status", "G", "L", "model_request_count", "elapsed_seconds")}), flush=True)
            if row["status"] != "completed" or row["evaluation_errors"]:
                break
    finally:
        os.close(fd)
        lock.unlink()
        (root / "pilot-summary.json").write_text(json.dumps(
            diagnostic.summarize(manifest), ensure_ascii=False, indent=2) + "\n")


if __name__ == "__main__":
    main()
