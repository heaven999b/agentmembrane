"""Re-audit the 33 missing-policy source tasks without model or API calls."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(PROJECT))

from agentmembrane.host_v2.rq1_collab_v1.native import NativeTask
from agentmembrane.host_v2.rq1_collab_v1.policy import compile_task_policy, make_task_policy
from agentmembrane.host_v2.rq1_collab_v6.permissions import native_tools


HERE = Path(__file__).resolve().parent
DRAFTS = Path(os.environ.get(
    "RQ1_POLICY_DRAFTS",
    str(HERE.parent / "missing_policy_drafts_001" / "drafts.json"),
))
SOURCE = Path(os.environ.get(
    "AGENTDOJO_SOURCE_ROOT",
    str(PROJECT / "data/host_boundary_v2/upstream/agentdojo"),
))
def build():
    drafts = json.loads(DRAFTS.read_text())
    rows = []
    for draft in drafts:
        suite, task_id = draft["task"].split("/")
        native = NativeTask(str(SOURCE), suite, task_id)
        lock = draft["source_lock"]
        source_bound = all(native.record[field] == lock[field] for field in (
            "prompt_sha256", "initial_state_sha256", "class_source_sha256",
            "tool_schema_sha256", "source_file_sha256"))
        if not source_bound:
            raise ValueError("source_lock_changed:" + draft["task"])
        registered, grants, policy_error = False, None, None
        owner_workflow_executable = None
        try:
            manifest = compile_task_policy(suite, task_id, native.prompt)
            policy = make_task_policy(suite, task_id, native.prompt, manifest,
                                      [spec["name"] for spec in native.tool_specs])
            policy.labels("A3", native.snapshot())
            bound = {"suite": suite, "original_id": task_id}
            grants = {tier: native_tools(policy, bound, level)
                      for tier, level in (("low", "A0"), ("medium", "A3"), ("high", "A4"))}
            if grants["low"] or not set(grants["medium"]) <= set(grants["high"]):
                raise ValueError("non_nested_grant:" + draft["task"])
            registered = True
            owner_workflow_executable = manifest.get("facts_from_actor_prompt", {}).get(
                "owner_workflow_executable", True)
        except Exception as error:
            policy_error = type(error).__name__ + ":" + str(error)
        rows.append({"task": draft["task"], "source_bound": source_bound,
                     "policy_interface_ready": registered,
                     "owner_workflow_executable_by_policy": owner_workflow_executable,
                     "policy_error_if_not_ready": policy_error,
                     "strict_checker_ready": native._strict_checker_supported(),
                     "formal_pair_admitted": False,
                     "grants": grants,
                     "remaining_source_or_scoring_issues": draft["unresolved_before_implementation"]})
    report = {"schema_version": "rq1-policy-implementation-status/1",
              "task_count": len(rows),
              "source_bound_count": sum(row["source_bound"] for row in rows),
              "policy_interface_ready_count": sum(row["policy_interface_ready"] for row in rows),
              "strict_checker_ready_count": sum(row["strict_checker_ready"] for row in rows),
              "formal_pair_admitted_count": 0,
              "model_calls": 0, "api_calls": 0,
              "status": "offline_policy_implementation_partial_not_formal",
              "rows": rows}
    (HERE / "admission_status.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    return report


if __name__ == "__main__":
    result = build()
    print(json.dumps({key: value for key, value in result.items() if key != "rows"},
                     ensure_ascii=False, sort_keys=True))
