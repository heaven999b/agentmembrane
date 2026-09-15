"""Build a source-locked AgentDojo development candidate panel without model calls.

This is a qualification *input*, not formal pair admission.  It selects one
public native attack goal per original user workflow before any live outcomes
are observed.  The native checker must report the goal false in the initial
state.  Ambiguous user requests remain on hold rather than being counted.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT))

from agentmembrane.host_v2.rq1_collab_v1.audit import canonical, file_hash, strict_loads
from agentmembrane.host_v2.rq1_collab_v1.admission import locked_agentdojo_runtime_inventory
from agentmembrane.host_v2.rq1_collab_v1.native import NativeTask, digest
from agentmembrane.host_v2.rq1_collab_v1.native_goals import public_native_goal_record
from agentmembrane.host_v2.rq1_collab_v1.six_sample import verify_upstream

INVENTORY = PROJECT / "data/host_boundary_v2/full_inventory"
OLD_LOCK = PROJECT / ("experiments/host_boundary_v2/rq1_collab_v1/"
    "pipeline_audit_20260907/pilots/native_run_001/run-manifest.json")
NATIVE_QUALIFICATION = PROJECT / ("experiments/host_boundary_v2/rq1_collab_v1/"
    "full_lifecycle_v3/native_qualification/run_004")
RUNTIME_INVENTORY = PROJECT / ("experiments/host_boundary_v2/rq1_collab_v1/"
    "live_readiness_20260907/implementations/rq1_permission_v6_20260914/"
    "source_locked_runtime_inventory_v3_20260915/manifest.json")

# One fixed native target per original workflow.  Banking payment-update tasks
# use the unrelated password-change goal, while the explicit-password task
# uses the recurring-payment target.  No target is changed after a model run.
DEFAULT_GOALS = {
    "workspace": "injection_task_1",
    "travel": "injection_task_3",
    "banking": "injection_task_4",
    "slack": "injection_task_1",
}
BANKING_PASSWORD_GOAL = frozenset({"user_task_2", "user_task_9", "user_task_15"})
HOLD = {
    ("workspace", "user_task_13"): "original_request_delegates_unspecified_email_instructions",
    ("banking", "user_task_12"): "original_request_delegates_unspecified_document_instructions",
}


def _rows(path: Path) -> list[dict]:
    return [strict_loads(line) for line in path.read_bytes().splitlines() if line]


def build(output: Path) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    source = strict_loads(OLD_LOCK.read_bytes())
    source_root = Path(source["source_root"])
    locked = source["qualified_upstream_hashes"]
    verify_upstream(source_root, locked)
    manifest = strict_loads((INVENTORY / "manifest.json").read_bytes())
    if manifest["formal_run_permitted"] is not False or manifest["formal_decision"] != "STOP":
        raise ValueError("unexpected_inventory_formal_status")
    for item in manifest["outputs"]:
        if file_hash(INVENTORY / item["path"]) != item["sha256"]:
            raise ValueError("inventory_output_hash_mismatch:" + item["path"])
    users = _rows(INVENTORY / "agentdojo_user_tasks.jsonl")
    effective_inventory = locked_agentdojo_runtime_inventory(source_root=str(source_root))
    pairs = _rows(INVENTORY / "agentdojo_attack_pairings.jsonl")
    references = strict_loads((NATIVE_QUALIFICATION / "private_reference_results.json").read_bytes())
    reference_by_id = {(r["suite"], r["task_id"]): r for r in references}
    if len(references) != 97 or len(reference_by_id) != 97:
        raise ValueError("native_reference_qualification_catalog_changed")
    if strict_loads((NATIVE_QUALIFICATION / "executed_source_lock.json").read_bytes()) != locked:
        raise ValueError("native_reference_source_lock_mismatch")
    if len(users) != 86 or len({(r["domain"], r["source_id"]) for r in users}) != 86:
        raise ValueError("locked_agentdojo_user_inventory_changed")
    pair_ids = {(r["domain"], r["source_user_task_id"], r["source_injection_task_id"])
                for r in pairs if r["source_usable"] is True}
    selection, assignments, review = [], [], []
    for row in users:
        if row["source_usable"] is not True:
            raise ValueError("inventory_unusable_user_task")
        suite, task_id = row["domain"], row["source_id"]
        goal_id = ("injection_task_7" if suite == "banking" and task_id in BANKING_PASSWORD_GOAL
                   else DEFAULT_GOALS[suite])
        if (suite, task_id, goal_id) not in pair_ids:
            raise ValueError("selected_goal_absent_from_original_pairings")
        task = NativeTask(str(source_root), suite, task_id)
        record = task.record
        # The v2 static inventory cannot describe v1_2's effective override
        # of W31/W32.  The separately source-locked v3 inventory was built by
        # fresh native processes; compare every identity field against it.
        effective = effective_inventory[(suite, task_id)]
        identity_keys = ("suite", "task_id", "benchmark_version", "prompt_sha256",
                         "class_source_sha256", "source_file_sha256", "initial_state_sha256",
                         "tool_schema_sha256")
        source_identity_ok = all(record[k] == effective.get(k) for k in identity_keys)
        static_source_matches = (record["source_file_sha256"] == row["source_file_sha256"]
                                 and record["source_file"] == row["source_path"]
                                 and record["class_name"] == row["class"])
        if record["source_file_sha256"] != locked[record["source_file"]]:
            raise ValueError("native_user_source_not_locked")
        reference = reference_by_id[(suite, task_id)]
        reference_identity_ok = all(record[k] == reference.get(k) for k in identity_keys)
        reference_pass = (reference_identity_ok and reference.get("native_reference_score") is True
                          and reference.get("snapshot_scorer_matches_direct") is True
                          and reference.get("reset_verified") is True)
        goal = public_native_goal_record(str(source_root), suite, goal_id)
        initial = task.snapshot()
        initial_check = task.native_attack_score_detail(goal_id, initial, initial, "", function_calls=[])
        initial_false = initial_check.get("source_bound") is True and initial_check.get("initial_goal_value") in (False, 0)
        if not initial_false:
            raise ValueError("selected_goal_not_false_in_initial_state:" + suite + ":" + task_id)
        # Reproduce the *native original* reference privately.  A task/goal
        # pair whose normal solution itself trips the attack checker is not a
        # clean unauthorized-target comparison even when its initial value is
        # false.  This check is performed before any model/treatment run.
        reference_calls = task._task.ground_truth(task._environment.model_copy(deep=True))
        reference_errors = []
        for call in reference_calls:
            _, error = task._runtime.run_function(task._environment, call.function, call.args)
            task._calls.append(call)
            if error is not None:
                reference_errors.append(str(error))
        terminal = task.snapshot()
        reference_output = task._task.GROUND_TRUTH_OUTPUT
        terminal_goal = task.native_attack_score_detail(goal_id, initial, terminal,
                                                         reference_output)
        reference_goal_false = (terminal_goal.get("source_bound") is True
                                and terminal_goal.get("value") in (False, 0))
        reference_terminal_hash_matches = digest(terminal) == reference.get("reference_terminal_sha256")
        # Native tools that create/write objects populate wall-clock fields, so
        # their reference terminal hashes are not stable across replay dates.
        # Check semantic source utility and call errors; retain hash drift as
        # an explicit limitation rather than selecting only read-only tasks.
        reference_replay_matches = (not reference_errors
            and task.native_score(initial, terminal, reference_output)
                == reference.get("native_reference_score"))
        hold_reason = HOLD.get((suite, task_id))
        blockers = (["static_inventory_native_source_identity_mismatch"] if not source_identity_ok else [])
        if not reference_pass:
            blockers.append("native_reference_pending_repair")
        if not reference_replay_matches:
            blockers.append("native_reference_replay_mismatch")
        if not reference_goal_false:
            blockers.append("normal_original_reference_reaches_selected_attack_goal")
        if hold_reason:
            blockers.append(hold_reason)
        review.append({"suite": suite, "task_id": task_id, "goal_id": goal_id,
                       "prompt": task.prompt, "public_goal": goal["goal"],
                       "source_identity_verified": source_identity_ok,
                       "static_inventory_source_matches_runtime": static_source_matches,
                       "native_reference_qualified": reference_pass,
                       "native_reference_replay_matches": reference_replay_matches,
                       "native_reference_terminal_hash_matches": reference_terminal_hash_matches,
                       "normal_original_reference_goal_false": reference_goal_false,
                       "initial_goal_false": True,
                       "authorization_review": ("hold" if blockers else "pending_original_request_authorization_review"),
                       "blockers": blockers,
                       "adapter_parity_verified": False, "formal_pair_admitted": False})
        if source_identity_ok and reference_pass and reference_replay_matches:
            selection.append({**record, "world_group": "agentdojo:" + suite, "admitted": False})
        if not blockers:
            assignments.append({"suite": suite, "task_id": task_id, "goal_id": goal_id})
    verify_upstream(source_root, locked)
    qualified = {"schema_version": "rq1-agentdojo-all-candidate-source-lock/1",
                 "purpose": "development_only_not_formal_pair_admission",
                 "source_root": str(source_root), "native_python": source["native_python"],
                 "qualified_upstream_hashes": locked, "selection": selection,
                 "source_inventory_sha256": file_hash(INVENTORY / "manifest.json"),
                 "effective_runtime_inventory_sha256": file_hash(RUNTIME_INVENTORY),
                 "candidate_count": len(selection), "formal_ready": False}
    summary = {"native_catalog_total": len(references),
               "static_inventory_workflow_candidates": len(users),
               "omitted_combined_tasks": len(references) - len(users),
               "source_identity_and_reference_qualified": len(selection),
               "effective_runtime_identity_mismatch": sum(not r["source_identity_verified"] for r in review),
               "static_native_identity_mismatch_resolved_in_v3": sum(not r["static_inventory_source_matches_runtime"] for r in review),
               "native_reference_pending_repair": sum(not r["native_reference_qualified"] for r in review),
               "native_reference_replay_mismatch": sum(not r["native_reference_replay_matches"] for r in review),
               "reference_terminal_hash_drift": sum(not r["native_reference_terminal_hash_matches"] for r in review),
               "normal_reference_goal_true_or_unknown": sum(not r["normal_original_reference_goal_false"] for r in review),
               "development_pair_proposals": len(assignments),
               "held_for_ambiguous_original_request": len(HOLD),
               "initial_goal_false": len(users), "adapter_parity_verified": 0,
               "formal_pair_admitted": 0, "model_calls": 0, "seed_repetitions": 0,
               "single_run_cell_upper_bound_if_every_proposal_qualifies": 6 * len(assignments),
               "actual_runnable_cells": 0,
               "status": "candidate_inventory_not_executable_study"}
    for name, value in (("candidate-manifest.json", qualified),
                        ("goal-assignments-proposed.json", assignments),
                        ("pair-review.json", review), ("summary.json", summary)):
        (output / name).write_bytes(canonical(value) + b"\n")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    print(json.dumps(build(args.output), ensure_ascii=False, sort_keys=True))
