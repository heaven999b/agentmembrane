"""Source-bound live engineering pilot using the production H/E controller.

This explicit diagnostic admission path does not activate the formal manifest
or fabricate final Q/I/D adjudication. Every selected original task contributes
all six cells. The same proxy lifecycle, tool policy, wire and native checkers
are exercised, while every seal and summary remains nonformal.
"""
from __future__ import annotations

from collections import Counter
import os
from pathlib import Path
import time

from ..rq1_collab_v1.admission import TaskBundle, load_development_bundles
from ..rq1_collab_v1.audit import EventCollector, _write_new, canonical, strict_loads
from ..rq1_collab_v1.process_backend import ProcessNativeTask, PipeWorker
from ..rq1_collab_v1.six_sample import verify_upstream
from ..rq1_collab_v3.contract import digest
from ..rq1_collab_v6.attack_spec import compile_attack_spec
from ..rq1_collab_v6.contract import make_config, PHASE_SCHEDULE
from ..rq1_collab_v6.evaluation import read_evidence
from ..rq1_collab_v6.runtime import run_episode
from .contract import FORMAL_PROTOCOL, MODEL_PROFILES
from .driver import FormalRoleModelDriver, role_prompts
from .evaluator import _calls, _bool_endpoint, _lineage
from .gate import code_bundle_sha256, file_binding, validate_goal_balance_candidate
from .proxy_lifecycle import (
    CELL_LIFECYCLE_PATH, PerCellProxyLifecycle, _route_runtime_binding,
    validate_cell_lifecycle_receipt,
)
from .runtime_impl import _seal_failed_attempt


SCHEMA = "rq1-three-tier-live-engineering-pilot/1"
CONDITIONS = [(level, regime) for level in ("low", "medium", "high")
              for regime in ("honest", "malicious")]


def _load(path):
    return strict_loads(Path(path).read_bytes())


def select_tasks(assignments, count):
    """Cover goal clusters first, then balance suites; never read run outcomes."""
    if type(count) is not int or not 1 <= count <= len(assignments):
        raise ValueError("pilot_task_count_out_of_range")
    ordered = sorted(assignments, key=lambda row: digest({
        "selection_rule": "cluster_then_suite_balance_v1",
        "task_key": row["task_key"],
    }))
    selected, clusters, suite_counts = [], set(), Counter()
    while len(selected) < count:
        candidates = [row for row in ordered if row not in selected]
        candidates.sort(key=lambda row: (
            row["goal_cluster_id"] in clusters,
            suite_counts[row["suite"]],
            ordered.index(row),
        ))
        row = candidates[0]
        selected.append(row)
        clusters.add(row["goal_cluster_id"])
        suite_counts[row["suite"]] += 1
    return selected


def prepare(*, qualified_path, pool_path, goals_path, route_binding_path,
            task_count, output):
    root = Path(output).absolute()
    if root.exists() or root.is_symlink():
        raise FileExistsError("new_pilot_directory_required")
    sources = {name: file_binding(path) for name, path in {
        "qualified_manifest": qualified_path, "task_pool": pool_path,
        "goal_balance_candidate": goals_path,
        "route_runtime_binding": route_binding_path,
    }.items()}
    pool, goals = _load(pool_path), _load(goals_path)
    validate_goal_balance_candidate(
        goals, task_keys=sorted(row["task_key"] for row in pool["tasks"]),
        identity_sha256=pool["study_identity_sha256"],
        task_pool_sha256=pool["task_pool_sha256"])
    selected = select_tasks(goals["assignments"], task_count)
    qualified = _load(qualified_path)
    bundles = load_development_bundles(qualified_path, [{
        "suite": row["suite"], "task_id": row["task_key"].split("/")[1],
        "goal_id": row["goal_id"],
    } for row in selected], native_python=qualified["native_python"])
    tasks, cells = [], []
    for index, (assignment, bundle) in enumerate(zip(selected, bundles)):
        record = bundle.record()
        if record["goal_admission"]["initial_goal_value"] is not False:
            raise ValueError("pilot_goal_not_initially_false")
        spec = compile_attack_spec(record["public"]["goal"]["goal"])
        if spec["spec_sha256"] != assignment["attack_spec_sha256"]:
            raise ValueError("pilot_goal_assignment_mismatch")
        task_cells, h_prompts = [], set()
        for level, regime in CONDITIONS:
            cfg = make_config(bundle.sha256, assignment["task_key"].replace("/", "-"),
                              "H_E", level, regime, 0, mode="live_diagnostic",
                              models=MODEL_PROFILES)
            prompts = role_prompts(cfg, record["public"]["user_request"],
                                   record["public"]["goal"]["goal"], attack_spec=spec)
            h_prompts.add(digest(prompts["H"]))
            task_cells.append(cfg)
        if len(h_prompts) != 1:
            raise ValueError("pilot_H_prompt_differs_between_conditions")
        # Counterbalance position without model replicates or sampled seeds.
        offset = index % 6
        cells.extend(task_cells[offset:] + task_cells[:offset])
        tasks.append({"task_key": assignment["task_key"],
                      "goal_cluster_id": assignment["goal_cluster_id"],
                      "goal_id": assignment["goal_id"],
                      "attack_spec_sha256": spec["spec_sha256"],
                      "bundle_sha256": bundle.sha256, "bundle": record,
                      "H_prompt_sha256": next(iter(h_prompts))})
    route = _load(route_binding_path)
    body = {
        "schema_version": SCHEMA, "purpose": "real_api_engineering_validation",
        "actor_protocol": FORMAL_PROTOCOL, "actor_set": ["H", "E"],
        "formal_ready": False, "formal_sample_eligible": False,
        "research_sample_count": 0, "automatic_retry": False,
        "old_campaign_resume_permitted": False, "repeats_per_cell": 1,
        "selection_uses_outcomes": False,
        "selection_rule": "cluster_then_suite_balance_v1",
        "task_count": task_count, "planned_cell_count": task_count * 6,
        "models": MODEL_PROFILES, "phase_schedule": PHASE_SCHEDULE,
        "tasks": tasks, "cells": cells, "source_bindings": sources,
        "route_runtime_binding_sha256": route["route_runtime_binding_sha256"],
        "code_bundle_sha256": code_bundle_sha256(),
        "native_python": qualified["native_python"],
        "native_python_binary": file_binding(Path(qualified["native_python"]).resolve()),
        "source_root": qualified["source_root"],
        "qualified_upstream_hashes": qualified["qualified_upstream_hashes"],
        "run_parent": str(root / "runs"),
        "QID_status": "diagnostic_observers_only_not_formally_qualified",
        "halt_on": ["unconfirmed_cleanup", "infrastructure_failure",
                    "evaluation_integrity_failure", "provider_delivery_unknown"],
    }
    manifest = {**body, "manifest_sha256": digest(body)}
    validate_manifest(manifest)
    root.mkdir(parents=True, mode=0o700)
    _write_new(root / "pilot-manifest.json", canonical(manifest) + b"\n")
    return manifest


def validate_manifest(value):
    if (type(value) is not dict or value.get("schema_version") != SCHEMA
            or value.get("manifest_sha256") != digest({
                k: v for k, v in value.items() if k != "manifest_sha256"})
            or value.get("formal_ready") is not False
            or value.get("formal_sample_eligible") is not False
            or value.get("research_sample_count") != 0
            or value.get("automatic_retry") is not False
            or value.get("repeats_per_cell") != 1
            or value.get("models") != MODEL_PROFILES
            or value.get("phase_schedule") != PHASE_SCHEDULE
            or value.get("code_bundle_sha256") != code_bundle_sha256()):
        raise ValueError("pilot_manifest_invalid_or_code_changed")
    for source in value["source_bindings"].values():
        if file_binding(source["path"]) != source:
            raise ValueError("pilot_bound_source_changed")
    if file_binding(Path(value["native_python"]).resolve()) != value["native_python_binary"]:
        raise ValueError("pilot_native_python_changed")
    _route_runtime_binding(value)
    verify_upstream(value["source_root"], value["qualified_upstream_hashes"])
    goals = _load(value["source_bindings"]["goal_balance_candidate"]["path"])
    selected = select_tasks(goals["assignments"], value["task_count"])
    if [r["task_key"] for r in value["tasks"]] != [r["task_key"] for r in selected]:
        raise ValueError("pilot_task_selection_changed")
    expected_cells = []
    for index, (task, assigned) in enumerate(zip(value["tasks"], selected)):
        record = task["bundle"]
        spec = compile_attack_spec(record["public"]["goal"]["goal"])
        if (digest(record) != task["bundle_sha256"]
                or task["goal_id"] != assigned["goal_id"]
                or record["public"]["goal"]["goal_id"] != assigned["goal_id"]
                or task["goal_cluster_id"] != assigned["goal_cluster_id"]
                or task["attack_spec_sha256"] != spec["spec_sha256"]
                or spec["spec_sha256"] != assigned["attack_spec_sha256"]):
            raise ValueError("pilot_bundle_or_goal_binding_changed")
        block = []
        for level, regime in CONDITIONS:
            cfg = make_config(task["bundle_sha256"], task["task_key"].replace("/", "-"),
                              "H_E", level, regime, 0, mode="live_diagnostic",
                              models=MODEL_PROFILES)
            prompt = role_prompts(cfg, record["public"]["user_request"],
                                  record["public"]["goal"]["goal"], attack_spec=spec)["H"]
            if digest(prompt) != task["H_prompt_sha256"]:
                raise ValueError("pilot_H_contract_changed")
            block.append(cfg)
        offset = index % 6
        expected_cells.extend(block[offset:] + block[:offset])
    if (value["cells"] != expected_cells
            or value["planned_cell_count"] != 6 * value["task_count"]):
        raise ValueError("pilot_requires_exact_six_cells_per_task")
    return value


def evaluate_pilot(evidence_dir, seal_hash, adapter, bundle):
    """Use the formal terminal G/L definitions, with explicit unqualified QID.

    The legacy measurement catalog pins old task/goal pairings and must not be
    substituted for the new candidate goal assignment. Scoring uses only calls
    reconstructed from the verified seal, in a separate native evaluator.
    """
    data = read_evidence(evidence_dir, seal_hash)
    if data["bundle_sha256"] != bundle.sha256:
        raise ValueError("pilot_evaluation_bundle_mismatch")
    calls, complete, gaps = _calls(data)
    errors, native, strict, goal = [], None, None, None
    lineage, lineage_detail = "unknown", None
    before, after = data["initial_snapshot"], data["terminal_snapshot"]
    if before is not None and after is not None:
        try:
            with PipeWorker(mode="evaluator", **adapter.arguments) as scorer:
                native = scorer.request("score", before=before, after=after,
                                        final_text=data["final_text"], function_calls=calls)
            strict = native["strict"]
            detail = adapter.native_attack_score_detail(
                bundle.record()["public"]["goal"]["goal_id"], before, after,
                data["final_text"], function_calls=calls)
            if _bool_endpoint(detail.get("initial_goal_value")) is False:
                goal = _bool_endpoint(detail.get("value"))
                if goal is True:
                    lineage, lineage_detail = _lineage(data, data["attack_spec"], True)
                elif complete:
                    lineage = "none"
                else:
                    goal = None
            if not complete:
                strict = {"value": None, "reason": "sealed_native_call_trace_incomplete"}
        except Exception as exc:
            errors.append({"stage": "native_terminal_checker", "error_type": type(exc).__name__})
    return {"schema_version": "rq1-engineering-pilot-evaluation/1",
            "execution_seal_sha256": seal_hash,
            "closure_class": data["closure_class"], "terminal_reason": data["terminal_reason"],
            "strict_task_result": strict, "native_goal_success": goal,
            "native_task_success": native.get("native") if native is not None else None,
            "native_goal_actor_lineage": lineage, "lineage_detail": lineage_detail,
            "evaluation_errors": errors, "execution_failures": data["failures"],
            "sealed_call_trace_complete": complete, "sealed_call_trace_gaps": gaps,
            "Q": None, "I": None, "D": None,
            "QID_reason": "candidate_goals_have_no_qualified_QID_observers",
            "formal_sample_eligible": False}


def run_cell(manifest, cell):
    validate_manifest(manifest)
    if cell not in manifest["cells"]:
        raise ValueError("pilot_cell_not_registered")
    task = next(row for row in manifest["tasks"]
                if row["bundle_sha256"] == cell["bundle_sha256"])
    bundle = TaskBundle(canonical(task["bundle"]), task["bundle_sha256"])
    run_dir = Path(manifest["run_parent"]) / cell["episode_id"]
    if run_dir.exists() or run_dir.is_symlink():
        raise FileExistsError("pilot_attempt_already_allocated_no_retry")
    evidence_dir = run_dir / "evidence"
    collector = EventCollector(evidence_dir, cell["episode_id"])
    lifecycle, adapter = None, None
    started = time.monotonic()
    try:
        collector.emit("diagnostic_pilot_allocated", {
            "manifest_sha256": manifest["manifest_sha256"],
            "task_key": task["task_key"], "formal_sample_eligible": False,
        }, evidence_quality="pre_actor_diagnostic_allocation")
        lifecycle = PerCellProxyLifecycle(manifest=manifest, cell=cell, collector=collector)
        transport = lifecycle.start()
        suite, task_id = task["task_key"].split("/")
        adapter = ProcessNativeTask(manifest["native_python"], manifest["source_root"],
                                    suite, task_id, timeout=30)
        prompts = role_prompts(cell, adapter.prompt, task["bundle"]["public"]["goal"]["goal"],
                               attack_spec=compile_attack_spec(task["bundle"]["public"]["goal"]["goal"]))
        driver = FormalRoleModelDriver(cell, prompts, collector, transport)

        def before_seal(**kwargs):
            receipt = lifecycle.finish_before_seal(
                model_request_count=len(collector._requests))
            validate_cell_lifecycle_receipt(receipt, manifest=manifest, cell=cell)
            _write_new(evidence_dir / CELL_LIFECYCLE_PATH, canonical(receipt) + b"\n")
            return {"formal_sample_eligible": False, "diagnostic_pilot": True,
                    "pilot_manifest_sha256": manifest["manifest_sha256"],
                    "proxy_lifecycle_receipt_sha256": receipt["receipt_sha256"]}

        execution = run_episode(cell, bundle, adapter, driver, collector,
                                actor_protocol=FORMAL_PROTOCOL, pre_seal_hook=before_seal)
        seal_hash = execution["seal"]["seal_hash"]
        # Publish the external anchor before evaluation; scorer failure cannot
        # erase a delivered cell or permit a model retry.
        _write_new(run_dir / "execution-anchor.json", canonical({
            "seal_sha256": seal_hash, "manifest_sha256": manifest["manifest_sha256"],
        }) + b"\n")
        report = evaluate_pilot(evidence_dir, seal_hash, adapter, bundle)
        _write_new(run_dir / "diagnostic-report.json", canonical(report) + b"\n")
        evidence = execution["evidence"]
        strict = report.get("strict_task_result")
        strict_value = strict.get("value") if type(strict) is dict else None
        unknown = report["closure_class"] == "fatal_unknown"
        requests = list(collector._requests.values())
        row = {
            "episode_id": cell["episode_id"], "task_key": task["task_key"],
            "level": cell["level"], "regime": cell["regime"],
            "goal_id": task["goal_id"], "goal_cluster_id": task["goal_cluster_id"],
            "status": "sealed_unknown" if unknown else "completed",
            "G": None if unknown else report["native_goal_success"],
            "L": None if unknown else strict_value,
            "native_clean_task_success": report["native_task_success"],
            "G_actor_lineage": report["native_goal_actor_lineage"],
            "closure_class": report["closure_class"],
            "terminal_reason": report["terminal_reason"],
            "model_request_count": len(requests),
            "execution_failures": report["execution_failures"],
            "evaluation_errors": report["evaluation_errors"],
            "native_calls": [{"actor": c["actor"], "tool": c["tool"],
                               "status": c["status"], "policy_reason": c.get("policy_reason"),
                               "backend_entered": c.get("evidence_quality", {}).get("backend_entered")}
                              for c in evidence["native_calls"]],
            "execution_seal_sha256": seal_hash,
            "cleanup_confirmed": True, "formal_sample_eligible": False,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "QID_status": manifest["QID_status"],
        }
        _write_new(run_dir / "summary.json", canonical(row) + b"\n")
        return row
    except BaseException as exc:
        cleanup = lifecycle.cleanup_after_failure() if lifecycle else {
            "process_stop_confirmed": True, "secret_cleanup_confirmed": True}
        _seal_failed_attempt(collector, manifest=manifest, cell=cell,
                             allocation=None, exc=exc, cleanup=cleanup)
        failure = {"episode_id": cell["episode_id"], "task_key": task["task_key"],
                   "level": cell["level"], "regime": cell["regime"],
                   "status": "infrastructure_failure", "G": None, "L": None,
                   "failure_class": type(exc).__name__, "cleanup": cleanup,
                   "formal_sample_eligible": False,
                   "model_request_count": len(collector._requests)}
        path = run_dir / "failure.json"
        if not path.exists():
            _write_new(path, canonical(failure) + b"\n")
        raise
    finally:
        if adapter is not None:
            adapter.shutdown()


def summarize(manifest):
    rows, partial = [], []
    for cell in manifest["cells"]:
        folder = Path(manifest["run_parent"]) / cell["episode_id"]
        if (folder / "summary.json").is_file():
            rows.append(_load(folder / "summary.json"))
        elif (folder / "failure.json").is_file():
            rows.append(_load(folder / "failure.json"))
        elif folder.exists():
            partial.append(cell["episode_id"])
    groups = []
    for level, regime in CONDITIONS:
        group = [r for r in rows if r["level"] == level and r["regime"] == regime]
        groups.append({"level": level, "regime": regime, "attempted": len(group),
                       **{metric: {"positive": sum(r.get(metric) in (True, 1) for r in group),
                                    "identified": sum(r.get(metric) is not None for r in group)}
                          for metric in ("G", "L")}})
    return {"schema_version": "rq1-three-tier-live-engineering-summary/1",
            "manifest_sha256": manifest["manifest_sha256"],
            "task_count": manifest["task_count"], "planned_cells": len(manifest["cells"]),
            "attempted": len(rows) + len(partial), "unsealed_or_unscored": partial,
            "model_request_count": sum(r.get("model_request_count", 0) for r in rows),
            "groups": groups, "rows": rows,
            "formal_sample_count": 0, "formal_ready": False,
            "verdict": "engineering_pilot_no_formal_RQ1_verdict"}


def run(manifest_path, *, max_new_cells=None):
    manifest = validate_manifest(_load(manifest_path))
    root = Path(manifest_path).absolute().parent
    if str(root / "runs") != manifest["run_parent"]:
        raise ValueError("pilot_output_location_changed")
    lock = root / ".run.lock"
    fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, str(os.getpid()).encode())
        new = 0
        for cell in manifest["cells"]:
            folder = Path(manifest["run_parent"]) / cell["episode_id"]
            if folder.exists():
                if not (folder / "summary.json").is_file():
                    raise ValueError("prior_partial_or_failed_attempt_requires_review")
                previous = _load(folder / "summary.json")
                if (previous["status"] != "completed" or previous["evaluation_errors"]
                        or any(f.get("delivery") == "delivery_unknown"
                               for f in previous["execution_failures"])):
                    raise ValueError("prior_unknown_attempt_requires_review")
                continue
            row = run_cell(manifest, cell)
            print(__import__("json").dumps({k: row[k] for k in (
                "episode_id", "status", "G", "L", "model_request_count", "elapsed_seconds")}), flush=True)
            new += 1
            if (row["status"] != "completed" or row["evaluation_errors"]
                    or any(f.get("delivery") == "delivery_unknown" for f in row["execution_failures"])):
                break
            if max_new_cells is not None and new >= max_new_cells:
                break
        return summarize(manifest)
    finally:
        os.close(fd)
        lock.unlink()
