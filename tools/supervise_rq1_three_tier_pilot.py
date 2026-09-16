"""Run the remaining fixed pilot cells, retaining reviewed isolated failures.

The supervisor owns the run lock for its entire lifetime. It never repeats a
cell. Frozen execution and the separately pinned continuation guard remain the
authority; automatic receipts are only proposals until that guard accepts them.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import sys
import uuid


def load(path):
    return json.loads(Path(path).read_text())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def create(path, value):
    with Path(path).open("x") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def propose_receipt(folder, row, cell, digest):
    failures = row.get("execution_failures")
    if (row.get("status") != "sealed_unknown" or row.get("cleanup_confirmed") is not True
            or row.get("evaluation_errors") != [] or row.get("G") is not None
            or row.get("L") is not None or not failures):
        raise ValueError("failure_requires_manual_attention")
    ack = {"episode_id": row["episode_id"],
           "execution_seal_sha256": row["execution_seal_sha256"]}
    if all(f.get("kind") == "model_service_error" and f.get("http_status") == 408 for f in failures):
        return ack
    if failures == [{"kind": "controller_failure", "error_type": "ValueError"}]:
        ack.update(failure_kind="sealed_controller_failure",
                   formal_cell_sha256=digest(cell),
                   failure_record_sha256=sha(folder / "summary.json"),
                   execution_failures_sha256=digest(failures))
        return ack
    raise ValueError("new_failure_class_requires_manual_attention")


def supervise(controller, manifest_path, review_path, audit, max_consecutive=3):
    manifest_path, review_path = Path(manifest_path).resolve(), Path(review_path).resolve()
    manifest, pending = controller.plan(manifest_path, review_path)
    base = manifest_path.parent
    if Path(manifest["run_parent"]).resolve() != base / "runs":
        raise ValueError("pilot_output_location_changed")
    audit.mkdir(exist_ok=False)
    lock = base / ".run.lock"
    fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    review = load(review_path)
    acknowledged = {a["episode_id"] for a in review["acknowledged_failures"]}
    streak = 0
    try:
        os.write(fd, str(os.getpid()).encode())
        create(audit / "start.json", {
            "pid": os.getpid(), "manifest_sha256": manifest["manifest_sha256"],
            "initial_review_sha256": sha(review_path),
            "supervisor_sha256": sha(__file__),
            "guard_sha256": sha(controller.__file__),
            "pending": [c["episode_id"] for c in pending],
            "automatic_cell_retry": False,
        })
        for cell in pending:
            folder = base / "runs" / cell["episode_id"]
            if folder.exists():
                raise ValueError("pending_cell_already_exists_no_replay")
            row = controller.diagnostic.run_cell(manifest, cell)
            print(json.dumps({k: row.get(k) for k in (
                "episode_id", "status", "G", "L", "model_request_count")}), flush=True)
            if row.get("status") == "completed" and not row.get("evaluation_errors"):
                if row.get("cleanup_confirmed") is not True:
                    raise ValueError("cleanup_unconfirmed")
                streak = 0
                continue
            streak += 1
            if streak >= max_consecutive:
                raise ValueError("consecutive_failed_cells_stop")
            ack = propose_receipt(folder, row, cell, controller.digest)
            if ack["episode_id"] in acknowledged:
                raise ValueError("duplicate_failure_receipt")
            review["reason"] = "sealed_failures_reviewed_no_replay"
            review["acknowledged_failures"].append(ack)
            review["automatic_skip_policy"] = "isolated_408_or_sealed_controller_ValueError_only_no_replay"
            next_review = audit / ("review-" + uuid.uuid4().hex + ".json")
            create(next_review, review)
            # This checks sealed events, native config, anchors, and all prior
            # failures. A proposed receipt alone never authorizes continuation.
            controller.plan(manifest_path, next_review)
            acknowledged.add(ack["episode_id"])
            review_path = next_review
            create(audit / ("accepted-" + uuid.uuid4().hex + ".json"), {
                "episode_id": ack["episode_id"], "review_sha256": sha(review_path),
                "result_retained_as_unknown": True, "cell_repeated": False,
            })
        _, remaining = controller.plan(manifest_path, review_path)
        if remaining:
            raise ValueError("registered_cells_still_pending")
        create(audit / "closed.json", {"registered_cells": len(manifest["cells"]),
               "review_sha256": sha(review_path), "final_review": str(review_path),
               "all_execution_closures_verified": True, "final_analysis_pending": True})
        return 0
    except BaseException as exc:
        create(audit / "attention.json", {"exception_type": type(exc).__name__,
               "reason": str(exc) if isinstance(exc, ValueError) else "supervisor_stopped",
               "review_path": str(review_path), "no_cell_replayed": True})
        raise
    finally:
        os.close(fd)
        if lock.exists() and lock.read_text().strip() == str(os.getpid()):
            lock.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--review", required=True, type=Path)
    parser.add_argument("--execution-source", required=True, type=Path)
    parser.add_argument("--guard", required=True, type=Path)
    parser.add_argument("--guard-sha256", required=True)
    parser.add_argument("--audit", required=True, type=Path)
    args = parser.parse_args()
    if sha(args.guard) != args.guard_sha256:
        raise ValueError("guard_source_changed")
    # Fail before allocating a benchmark cell if the host cannot bind a port.
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
    def interrupt(signum, frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupt)
    spec = importlib.util.spec_from_file_location("pilot_continuation_guard", args.guard.resolve())
    controller = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(controller)
    return supervise(controller, args.manifest, args.review, args.audit.resolve())


if __name__ == "__main__":
    sys.exit(main())
