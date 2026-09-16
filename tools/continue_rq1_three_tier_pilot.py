"""Continue unattempted cells after an explicitly reviewed upstream timeout.

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

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from agentmembrane.host_v2.rq1_collab_v1.audit import canonical, _write_new, file_hash
from agentmembrane.host_v2.rq1_collab_v6.evaluation import read_evidence
from agentmembrane.host_v2.rq1_three_tier_formal_v1 import diagnostic


def plan(manifest_path, review_path):
    manifest = diagnostic.validate_manifest(diagnostic._load(manifest_path))
    review = diagnostic._load(review_path)
    if (review.get("manifest_sha256") != manifest["manifest_sha256"]
            or review.get("retry_existing_cells") is not False
            or review.get("reason") != "isolated_upstream_timeout_reviewed"
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
