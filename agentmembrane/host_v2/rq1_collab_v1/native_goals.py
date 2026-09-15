"""Public original-goal identity and honest task/goal coverage (never admission).

Only the source GOAL string and source identity are public. Checker constants,
reference calls and reference output are neither read nor serialized here.
"""
from __future__ import annotations

import inspect
from pathlib import Path
import re

V1_GOAL_FILES = {
    "workspace": "03e0894ffb544a79fd0bfd2c62cc5f90b19a2b1d429068d800239bfd020b6dcc",
    "travel": "9252be834b0ae0e28fe06744e052987d71d8ad3666b8d0b1f65f2875f998fca8",
    "banking": "fa2dedf8e66c95ffadb54f5a26648728b08c56f302858de4ee9a5cc0b3891618",
    "slack": "d5775da1689e13192b665837e72cee88ed76f622e9b998e9def18b700fdc5afc",
}
CORE_FILES = {
    "src/agentdojo/base_tasks.py": "08d3a4646d1a250968045b0f933803335650a4ed04c9d2387b17d08b1e0427c5",
    "src/agentdojo/task_suite/task_suite.py": "2e69da06f7e150dd6d238c53a74845b56eebeb224e07f694e1051a6e0c6a2bc1",
}


def normalize_goal_id(suite, goal_id):
    if suite not in V1_GOAL_FILES or not isinstance(goal_id, str):
        raise ValueError("invalid_native_goal_identity")
    if "/" in goal_id:
        prefix, goal_id = goal_id.split("/", 1)
        if prefix != suite:
            raise ValueError("goal_suite_mismatch")
    matched = re.fullmatch(r"(?:InjectionTask|injection_task_)(0|[1-9][0-9]*)", goal_id)
    if matched is None:
        raise ValueError("invalid_native_goal_identity")
    return "injection_task_" + matched.group(1)


def _goal_record(root, suite, goal, benchmark_version):
    from .native import _class_record, digest, file_digest
    if benchmark_version != "v1" or suite not in V1_GOAL_FILES:
        raise ValueError("native_goal_source_version_not_locked")
    locked = {**CORE_FILES, f"src/agentdojo/default_suites/v1/{suite}/injection_tasks.py": V1_GOAL_FILES[suite]}
    if any(file_digest(root / path) != expected for path, expected in locked.items()):
        raise ValueError("native_goal_source_lock_mismatch")
    identity = _class_record(goal, root)
    expected_module = f"agentdojo.default_suites.v1.{suite}.injection_tasks"
    if identity["class_module"] != expected_module or identity["source_file"] not in locked:
        raise ValueError("native_goal_class_provenance_mismatch")
    # Pin effective methods as well as the file. In-process method replacement
    # must not masquerade as the source method merely because the file matches.
    methods = {}
    for name in ("security", "security_from_traces"):
        method = getattr(type(goal), name)
        path = inspect.getfile(method)
        relative = str(Path(path).resolve().relative_to(root))
        if relative not in locked or method.__module__ not in {expected_module, "agentdojo.base_tasks"}:
            raise ValueError("native_goal_method_provenance_mismatch")
        methods[name] = digest(inspect.getsource(method))
    if not isinstance(goal.GOAL, str) or not goal.GOAL:
        raise ValueError("native_public_goal_missing")
    return {"schema_version": "rq1-public-native-goal/1", "source": "agentdojo", "suite": suite,
            "goal_id": normalize_goal_id(suite, goal.ID), "goal": goal.GOAL,
            "goal_sha256": digest(goal.GOAL), "benchmark_version": benchmark_version,
            **identity, "checker_source_lock_sha256": digest({"files": locked, "methods": methods})}


def public_native_goal_record(source_root, suite, goal_id, benchmark_version="v1"):
    """No credentials/model, no environment or hidden goal fields in result."""
    from .native import _load
    root, loader = _load(source_root)
    normalized = normalize_goal_id(suite, goal_id)
    task_suite = loader.get_suite(benchmark_version, suite)
    if normalized not in task_suite.injection_tasks:
        raise ValueError("undeclared_native_goal")
    return _goal_record(root, suite, task_suite.get_injection_task_by_id(normalized), benchmark_version)


def task_goal_coverage_report(source_root, benchmark_version="v1"):
    """Inspect every original task/goal without running reference solutions.

    A policy/checker implementation is not formal pair admission. No original
    catalog row, task/goal cross-product, repeated run or fixture adds study N.
    """
    from .native import NativeTask, _load, catalog, digest
    from .policy import SUPPORTED_TASKS, compile_task_policy, make_task_policy
    root, loader = _load(source_root)
    tasks, goals = [], []
    for suite_name, suite in sorted(loader.get_suites(benchmark_version).items()):
        for goal_id in sorted(suite.injection_tasks):
            try:
                record = public_native_goal_record(str(root), suite_name, goal_id, benchmark_version)
                goals.append({"goal_record": record, "checker_source_bound": True,
                              "pair_eligibility": "not_reviewed", "admitted": False})
            except Exception as exc:
                goals.append({"suite": suite_name, "goal_id": goal_id, "checker_source_bound": False,
                              "error_type": type(exc).__name__, "admitted": False})
    for identity in catalog(str(root), benchmark_version):
        suite_name, task_id = identity["suite"], identity["task_id"]
        row = {"task_record": identity, "policy_coverage": "unimplemented", "strict_checker_coverage": "unimplemented",
               "native_utility_checker": "not_exercised", "coverage_status": "reference_only", "admitted": False,
               "admission_status": "reference_only", "public_goal_ids": [], "initial_goal_checks": [],
               "blockers": ["formal_pair_admission_not_performed", "complete_risk_observation_not_verified"]}
        try:
            task = NativeTask(str(root), suite_name, task_id, benchmark_version=benchmark_version)
            row["initial_state_sha256"] = task.record["initial_state_sha256"]
            row["native_utility_checker"] = "source_present_not_reference_qualified"
            if (suite_name, task_id) in SUPPORTED_TASKS:
                try:
                    manifest = compile_task_policy(suite_name, task_id, task.prompt)
                    make_task_policy(suite_name, task_id, task.prompt, manifest, [s["name"] for s in task.tool_specs])
                    row["policy_coverage"] = "implemented_source_prompt_compiled"
                except Exception as exc:
                    row["policy_coverage"] = "blocked:" + type(exc).__name__
                if task._strict_checker_supported():
                    row["strict_checker_coverage"] = "implemented_source_locked"
                row["coverage_status"] = "pilot_policy_and_checker_supported" if row["policy_coverage"].startswith("implemented") and row["strict_checker_coverage"].startswith("implemented") else "blocked"
                row["admission_status"] = "blocked_pending_pair_validation"
            else:
                row["blockers"].append("task_policy_and_strict_checker_not_implemented")
            snapshot = task.snapshot()
            for goal_id in sorted(task.suite.injection_tasks):
                record = task.native_goal_record(goal_id)
                row["public_goal_ids"].append(record["goal_id"])
                initial = task.native_attack_score_detail(goal_id, snapshot, snapshot, "", function_calls=[])
                row["initial_goal_checks"].append({"goal_id": record["goal_id"], "value": initial["initial_goal_value"],
                                                   "reason": initial["initial_goal_reason"]})
        except Exception as exc:
            row.update(coverage_status="blocked", admission_status="blocked", error_type=type(exc).__name__)
        tasks.append(row)
    counts = {name: sum(row["coverage_status"] == name for row in tasks)
              for name in ("reference_only", "pilot_policy_and_checker_supported", "blocked")}
    return {"schema_version": "rq1-native-task-goal-coverage/1", "benchmark_version": benchmark_version,
            "tasks": tasks, "goals": goals, "counts": {"original_tasks": len(tasks), "original_goals": len(goals),
                **counts, "formally_admitted": 0, "study_n_added": 0},
            "catalog_sha256": digest({"tasks": tasks, "goals": goals}),
            "reference_execution_performed": False,
            "initial_goal_check_semantics": "original_checker(initial,initial,empty_output,empty_trace); some original rules require a state transition",
            "limitations": ["six_task_pilot_only", "task_goal_pair_admission_not_performed", "goal_success_not_all_hazards"]}
