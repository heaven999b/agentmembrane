"""Check that every prepared original can register its measurement before actors run.

This is an offline, fresh-process development preflight. It neither calls a
model nor treats a compiled contract as a completed RQ1 episode.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT))

from agentmembrane.host_v2.rq1_collab_v1.admission import TaskBundle
from agentmembrane.host_v2.rq1_collab_v1.audit import canonical
from agentmembrane.host_v2.rq1_collab_v1.process_backend import ProcessNativeTask
from agentmembrane.host_v2.rq1_collab_v6.workflow import load_manifest
from agentmembrane.host_v2.rq1_measurement_v1.contracts import compile_from_bundle
from agentmembrane.host_v2.rq1_measurement_v1.registry import attach_runtime_registry


def audit(manifest_path: Path, output: Path) -> dict:
    manifest = load_manifest(manifest_path)
    output.mkdir(parents=True, exist_ok=False)
    rows = []
    for bundle_hash, payload in manifest["bundles"].items():
        record = TaskBundle(canonical(payload), bundle_hash).record()
        native = None
        row = {"suite": record["suite"], "task_id": record["original_id"],
               "pre_run_measurement_ready": False, "reason": None}
        try:
            native = ProcessNativeTask(manifest["native_python"],
                manifest["source_root"], record["suite"], record["original_id"], timeout=30)
            compiled = compile_from_bundle(record, native.snapshot())
            attach_runtime_registry(compiled["score_contract"],
                manifest["system_spec"]["system_profile"])
            row["pre_run_measurement_ready"] = True
        except ValueError as error:
            # Only closed, non-secret reason codes may enter the audit.
            reason = str(error)
            row["reason"] = reason if reason in {
                "unregistered_original_task", "original_request_rule_not_supported",
                "source_identity_lock_mismatch", "original_snapshot_lock_mismatch",
                "original_public_request_or_goal_binding_mismatch"} else "value_error_other"
        except Exception as error:
            row["reason"] = type(error).__name__
        finally:
            if native is not None:
                native.shutdown()
        rows.append(row)
    summary = {"prepared_tasks": len(rows),
               "pre_run_measurement_ready_tasks": sum(r["pre_run_measurement_ready"] for r in rows),
               "model_calls": 0, "formal_ready": False,
               "status": "pre_run_contract_preflight_only"}
    (output / "rows.json").write_bytes(canonical(rows) + b"\n")
    (output / "summary.json").write_bytes(canonical(summary) + b"\n")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.manifest, args.output), ensure_ascii=False, sort_keys=True))
