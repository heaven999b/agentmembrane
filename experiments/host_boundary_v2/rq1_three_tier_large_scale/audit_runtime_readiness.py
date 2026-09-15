"""Offline task-by-task three-tier development readiness audit.

No API/model calls are made.  A passed row says only that source, policy,
AttackSpec, and technical grants can be instantiated; it is not formal RQ1
admission, proof of end-to-end utility, or an observed attack outcome.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT))

from agentmembrane.host_v2.rq1_collab_v1.audit import canonical, strict_loads
from agentmembrane.host_v2.rq1_collab_v1.native import NativeTask
from agentmembrane.host_v2.rq1_collab_v1.policy import compile_task_policy, make_task_policy
from agentmembrane.host_v2.rq1_collab_v1.six_sample import identity_matches, verify_upstream
from agentmembrane.host_v2.rq1_collab_v6.attack_spec import compile_attack_spec
from agentmembrane.host_v2.rq1_collab_v6.permissions import native_tools


def audit(candidate_dir: Path, output: Path) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    source = strict_loads((candidate_dir / "candidate-manifest.json").read_bytes())
    assignments = strict_loads((candidate_dir / "goal-assignments-proposed.json").read_bytes())
    reviews = strict_loads((candidate_dir / "pair-review.json").read_bytes())
    selected = {(r["suite"], r["task_id"]): r for r in source["selection"]}
    if (source["formal_ready"] is not False or source["candidate_count"] != len(selected)
            or len(assignments) != len({(r["suite"], r["task_id"]) for r in assignments})):
        raise ValueError("candidate_manifest_integrity_failure")
    verify_upstream(source["source_root"], source["qualified_upstream_hashes"])
    by_assignment = {(r["suite"], r["task_id"]): r for r in assignments}
    rows = []
    for review in reviews:
        suite, task_id = review["suite"], review["task_id"]
        identity = suite, task_id
        blockers = list(review["blockers"])
        result = {"suite": suite, "task_id": task_id, "goal_id": review["goal_id"],
                  "source_candidate": identity in selected,
                  "pair_proposed": identity in by_assignment,
                  "blockers": blockers, "permission_grants": None,
                  "strict_checker_ready": None,
                  "technical_policy_instantiable": False,
                  "owner_workflow_executable": None,
                  "engineering_interface_ready": False,
                  "formal_pair_admitted": False}
        if not blockers:
            try:
                task = NativeTask(source["source_root"], suite, task_id)
                if not identity_matches(task.record, selected[identity]):
                    raise ValueError("fresh_native_source_identity_mismatch")
                policy_manifest = compile_task_policy(suite, task_id, task.prompt)
                policy = make_task_policy(suite, task_id, task.prompt, policy_manifest,
                    [spec["name"] for spec in task.tool_specs])
                result["technical_policy_instantiable"] = True
                executable = policy_manifest.get("facts_from_actor_prompt", {}).get(
                    "owner_workflow_executable", True)
                if type(executable) is not bool:
                    raise ValueError("owner_workflow_executable_not_boolean")
                result["owner_workflow_executable"] = executable
                bound = {"suite": suite, "original_id": task_id}
                grants = {level: native_tools(policy, bound, level)
                          for level in ("A0", "A3", "A4")}
                if grants["A0"] or not set(grants["A3"]).issubset(grants["A4"]):
                    raise ValueError("technical_grants_not_nested")
                spec = compile_attack_spec(review["public_goal"])
                if (spec["fixed"]["goal_binding"]["suite"] != suite
                        or spec["fixed"]["goal_binding"]["goal_id"] != review["goal_id"]):
                    raise ValueError("attack_spec_native_goal_mismatch")
                result["permission_grants"] = {"low": grants["A0"],
                                                "medium": grants["A3"],
                                                "high": grants["A4"]}
                result["strict_checker_ready"] = task._strict_checker_supported()
                result["engineering_interface_ready"] = executable
                if not executable:
                    blockers.append("owner_workflow_not_executable_under_current_contract")
            except Exception as error:
                blockers.append(type(error).__name__ + ":" + str(error)[:160])
        rows.append(result)
    verify_upstream(source["source_root"], source["qualified_upstream_hashes"])
    ready = [{"suite": row["suite"], "task_id": row["task_id"],
              "goal_id": row["goal_id"]} for row in rows if row["engineering_interface_ready"]]
    summary = {"native_catalog_total": 97,
               "static_inventory_workflow_candidates": len(rows),
               "source_identity_and_reference_qualified": len(selected),
               "pair_proposals": len(assignments),
               "technical_policy_instantiable_tasks": sum(
                   row["technical_policy_instantiable"] is True for row in rows),
               "owner_workflow_executable_tasks": sum(
                   row["owner_workflow_executable"] is True for row in rows),
               "engineering_interface_ready_tasks": len(ready),
               "strict_checker_ready_among_interface_ready": sum(
                   row["strict_checker_ready"] is True for row in rows if row["engineering_interface_ready"]),
               "planned_single_run_cells_if_all_interface_ready": 6 * len(ready),
               "actual_live_episodes": 0, "model_calls": 0,
               "topology": "H_E", "levels": ["low", "medium", "high"],
               "high_authority_profile": "ambient_experimental_high",
               "regimes": ["honest", "malicious"], "repeats_per_cell": 1,
               "formal_ready": False,
               "status": "offline_development_interface_audit_only"}
    for name, value in (("readiness-rows.json", rows),
                        ("interface-ready-goal-assignments.json", ready),
                        ("summary.json", summary)):
        (output / name).write_bytes(canonical(value) + b"\n")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate_dir", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.candidate_dir, args.output), ensure_ascii=False, sort_keys=True))
