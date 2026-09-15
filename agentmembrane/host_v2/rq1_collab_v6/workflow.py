"""Prepare / preflight / run / inspect real RQ1 workflow artifacts.

Defaults are the previously source-qualified PUBLIC development tasks. A new
manifest never authorizes a full study. No downloaded/generated actor code runs.
"""
from __future__ import annotations

import argparse
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import hmac
import json
import os
from pathlib import Path
import random
import re
import time

from ..rq1_collab_v1.admission import TaskBundle, load_development_bundles
from ..rq1_collab_v1.audit import EventCollector, _write_new, canonical, file_hash, strict_loads, verify
from ..rq1_collab_v1.process_backend import ProcessNativeTask
from ..rq1_collab_v1.six_sample import verify_upstream
from .contract import (PROTOCOL, REGIMES, TOPOLOGIES, LEVELS, FIXED_BUDGET,
                       PHASE_SCHEDULE, PHASE_SCHEDULE_SHA256, clone, digest,
                       matrix, model_readiness, validate_config)
from .driver import RoleModelDriver, role_prompts
from .attack_spec import compile_attack_spec, validate_attack_spec
from ..rq1_collab_v4.engineering import EngineeringDriver
from .evaluation import evaluate_closed
from .runtime import run_episode
from .report_codec import read_report, write_report
from .provider_route import (BoundRouteTransport, SHARED_IDENTITY, base_url, credential_fingerprint,
                             source_binding, verify_binding)
from .contract import system_spec, NATIVE_PROFILE, PROFILES
from ..rq1_collab_v3.contract import validate_profiles

PROJECT = Path(__file__).resolve().parents[3]
WORK = PROJECT / "experiments/host_boundary_v2/rq1_collab_v1/live_readiness_20260907"
QUALIFIED = WORK.parent / "pipeline_audit_20260907/pilots/native_run_001/run-manifest.json"
GOALS = WORK / "root_inputs/rqe_v2_goal_assignments.json"
INVENTORY = WORK / "root_inputs/rq1_three_actor_model_inventory_20260908.json"


def code_fingerprint():
    files = []
    for package in ("rq1_collab_v1", "rq1_collab_v3", "rq1_collab_v4", "rq1_collab_v6", "rq1_scorecard_v5", "rq1_measurement_v1"):
        files += [p for p in (Path(__file__).parent.parent / package).rglob("*") if p.is_file() and p.suffix in {".py", ".json"}]
    return {str(p.relative_to(PROJECT)): file_hash(p) for p in sorted(files)}


def write(path, data):
    _write_new(Path(path), canonical(data) + b"\n")


def inspect_shared_proxy_route(execution_root):
    """Summarize sealed response fingerprints without exposing proxy slot IDs.

    The fingerprint is an episode-local HMAC of the proxy's last selected
    authIndex. It cannot attest an account or every upstream retry/attempt.
    Call only after verifying the execution seal.
    """
    observed, fingerprints = 0, []
    with (Path(execution_root) / "events.jsonl").open("rb") as handle:
        for raw in handle:
            event = strict_loads(raw)
            if event.get("kind") != "model_response":
                continue
            observed += 1
            value = event["data"].get("shared_proxy_last_selected_slot_fingerprint")
            fingerprints.append(value if type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) else None)
    valid = [value for value in fingerprints if value is not None]
    distinct = len(set(valid))
    missing = observed - len(valid)
    status = ("no_gateway_response" if observed == 0 else
              "incomplete_selected_slot_evidence" if missing else
              "multiple_selected_slots_observed" if distinct > 1 else
              "same_selected_slot_observed" if observed > 1 else
              "single_selected_slot_observed")
    return {"status": status, "gateway_responses": observed,
            "fingerprinted_responses": len(valid), "missing_fingerprints": missing,
            "distinct_selected_slots": distinct,
            "account_identity": SHARED_IDENTITY}


def prepare(output, *, tasks, repeats=1, mode="engineering", qualified=QUALIFIED,
            goals=GOALS, inventory=INVENTORY, system_profile=NATIVE_PROFILE,
            models_file=None, budget_file=None, provider_route_file=None, topologies=TOPOLOGIES,
            levels=tuple(LEVELS), regimes=REGIMES):
    spec = system_spec(system_profile)
    profiles, model_source = None, None
    if models_file is not None:
        model_path = Path(models_file).resolve()
        profiles = validate_profiles(strict_loads(model_path.read_bytes()), ("H", "S", "E"))
        model_source = {"path": str(model_path), "sha256": file_hash(model_path),
                        "profiles_sha256": digest(profiles), "selection": "explicit_new_baseline_not_automatic_fallback"}
    budget, budget_source = None, None
    if budget_file is not None:
        budget_path = Path(budget_file).resolve()
        budget = strict_loads(budget_path.read_bytes())
        budget_source = {"path": str(budget_path), "sha256": file_hash(budget_path),
                         "budget_sha256": digest(budget),
                         "selection": "explicit_v6_bounded_phase_budget"}
        if budget != FIXED_BUDGET:
            raise ValueError("exact_v6_bounded_budget_file_required")
    provider_source = source_binding(provider_route_file) if provider_route_file is not None else None
    root = Path(output)
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    qualified, goals = Path(qualified).resolve(), Path(goals).resolve()
    selected = set(tasks)
    if not selected or len(selected) != len(tasks):
        raise ValueError("unique_public_task_selection_required")
    assignments = [g for g in strict_loads(goals.read_bytes()) if g["suite"] + ":" + g["task_id"] in selected]
    if {g["suite"] + ":" + g["task_id"] for g in assignments} != selected:
        raise ValueError("selected_task_has_no_reviewed_original_goal")
    bundles = load_development_bundles(qualified, assignments)
    if any(b.record()["goal_admission"]["initial_goal_value"] is not False for b in bundles):
        raise ValueError("selected_attack_goal_not_verified_false_initially")
    native = strict_loads(qualified.read_bytes())
    attack_specs = {
        bundle.sha256: compile_attack_spec(bundle.record()["public"]["goal"]["goal"])
        for bundle in bundles
    }
    cells = []
    for bundle in bundles:
        rec = bundle.record()
        cells += matrix(bundle.sha256, rec["suite"] + "-" + rec["original_id"],
                        repeats=repeats, mode=mode, models=profiles, budget=budget,
                        topologies=topologies, levels=levels, regimes=regimes)
    selection = {
        "topologies": [value for value in TOPOLOGIES if value in topologies],
        "levels": [value for value in LEVELS if value in levels],
        "regimes": [value for value in REGIMES if value in regimes],
    }
    random.Random(20260908).shuffle(cells)
    manifest = {"schema_version": "rq1-workflow/6", "protocol_version": PROTOCOL,
                "system_spec": spec, "system_spec_sha256": digest(spec),
                "phase_schedule": clone(PHASE_SCHEDULE),
                "phase_schedule_sha256": PHASE_SCHEDULE_SHA256,
                "regime_labels": {"honest": "control_no_attack", "malicious": "contextual_attack"},
                "created_at_unix": time.time(), "ordering_seed": 20260908,
                "execution_mode": mode, "qualified_manifest": str(qualified), "qualified_sha256": file_hash(qualified),
                "goal_assignments_path": str(goals), "goal_assignments_sha256": file_hash(goals),
                "source_root": native["source_root"], "native_python": native["native_python"],
                "upstream_hashes": native["qualified_upstream_hashes"], "code_sha256": code_fingerprint(),
                "bundles": {b.sha256: b.record() for b in bundles},
                "attack_specs": attack_specs,
                "attack_specs_sha256": digest(attack_specs), "cells": cells,
                "task_count": len(bundles), "condition_count": len(cells), "repeats": repeats,
                "cell_selection": selection,
                "sample_status": "predeclared_public_development_diagnostic_slice",
                "formal_ready": False,
                "research_sample_count": 0, "automatic_retry": False, "automatic_model_substitution": False,
                "credential_in_manifest": False}
    if profiles is not None:
        manifest.update(role_model_profiles=profiles, model_profile_source=model_source)
    if budget is not None:
        manifest.update(episode_budget=budget, budget_source=budget_source)
    if provider_source is not None:
        manifest["provider_route_source"] = provider_source
    manifest["manifest_sha256"] = digest(manifest)
    write(root / "run-manifest.json", manifest)
    inv = strict_loads(Path(inventory).read_bytes()) if Path(inventory).is_file() else {"model_ids": []}
    required = {m for c in cells for m in model_readiness(c, inv)["missing_models"]}
    write(root / "readiness.json", {"runtime_prepared": True, "missing_models": sorted(required),
          "live_generation_verified": False, "engineering_does_not_need_models": True, "model_calls": 0})
    return {"manifest": str(root / "run-manifest.json"), "condition_count": len(cells), "task_count": len(bundles),
            "missing_models": sorted(required), "model_calls": 0, "formal_ready": False}


def load_manifest(path):
    manifest = strict_loads(Path(path).read_bytes())
    unsigned = {k: v for k, v in manifest.items() if k != "manifest_sha256"}
    if manifest.get("schema_version") != "rq1-workflow/6" or digest(unsigned) != manifest.get("manifest_sha256"):
        raise ValueError("workflow_manifest_hash_mismatch")
    if manifest.get("system_spec") != system_spec(manifest["system_spec"]["system_profile"]) or digest(manifest["system_spec"]) != manifest.get("system_spec_sha256"):
        raise ValueError("system_profile_binding_mismatch")
    if (manifest.get("phase_schedule") != PHASE_SCHEDULE
            or manifest.get("phase_schedule_sha256") != PHASE_SCHEDULE_SHA256
            or manifest.get("regime_labels") != {"honest": "control_no_attack", "malicious": "contextual_attack"}):
        raise ValueError("v6_phase_or_regime_binding_mismatch")
    if manifest["code_sha256"] != code_fingerprint():
        raise ValueError("code_changed_prepare_a_new_workflow")
    if file_hash(manifest["qualified_manifest"]) != manifest["qualified_sha256"] or file_hash(manifest["goal_assignments_path"]) != manifest["goal_assignments_sha256"]:
        raise ValueError("public_admission_manifest_changed")
    verify_upstream(manifest["source_root"], manifest["upstream_hashes"])
    profiles = None
    if "role_model_profiles" in manifest or "model_profile_source" in manifest:
        if not {"role_model_profiles", "model_profile_source"} <= manifest.keys():
            raise ValueError("explicit_model_registration_incomplete")
        profiles = validate_profiles(manifest["role_model_profiles"], ("H", "S", "E"))
        origin = manifest["model_profile_source"]
        if (type(origin) is not dict or set(origin) != {"path", "sha256", "profiles_sha256", "selection"}
                or origin["selection"] != "explicit_new_baseline_not_automatic_fallback"
                or digest(profiles) != origin["profiles_sha256"]
                or file_hash(origin["path"]) != origin["sha256"]
                or strict_loads(Path(origin["path"]).read_bytes()) != profiles):
            raise ValueError("explicit_model_registration_changed")
    budget = None
    if "episode_budget" in manifest or "budget_source" in manifest:
        if not {"episode_budget", "budget_source"} <= manifest.keys():
            raise ValueError("explicit_budget_registration_incomplete")
        budget = manifest["episode_budget"]
        origin = manifest["budget_source"]
        if (type(origin) is not dict
                or set(origin) != {"path", "sha256", "budget_sha256", "selection"}
                or origin["selection"] != "explicit_v6_bounded_phase_budget"
                or digest(budget) != origin["budget_sha256"]
                or file_hash(origin["path"]) != origin["sha256"]
                or strict_loads(Path(origin["path"]).read_bytes()) != budget):
            raise ValueError("explicit_budget_registration_changed")
    if "provider_route_source" in manifest:
        verify_binding(manifest["provider_route_source"])
    selected = manifest.get("cell_selection", {
        "topologies": list(TOPOLOGIES), "levels": list(LEVELS),
        "regimes": list(REGIMES)})
    if (type(selected) is not dict
            or set(selected) != {"topologies", "levels", "regimes"}):
        raise ValueError("invalid_cell_selection")
    seen = set()
    expected = []
    attack_specs = manifest.get("attack_specs")
    if (type(attack_specs) is not dict
            or set(attack_specs) != set(manifest.get("bundles", {}))
            or manifest.get("attack_specs_sha256") != digest(attack_specs)):
        raise ValueError("workflow_attack_specs_missing_or_unbound")
    for bundle_hash, payload in manifest["bundles"].items():
        goal = payload["public"]["goal"]["goal"]
        if validate_attack_spec(attack_specs[bundle_hash], expected_goal=goal) != compile_attack_spec(goal):
            raise ValueError("workflow_attack_spec_definition_changed")
        expected += matrix(bundle_hash, payload["suite"] + "-" + payload["original_id"],
                           repeats=manifest["repeats"], mode=manifest["execution_mode"],
                           models=profiles, budget=budget,
                           topologies=selected["topologies"], levels=selected["levels"],
                           regimes=selected["regimes"])
    if (manifest["task_count"] != len(manifest["bundles"]) or manifest["condition_count"] != len(expected)
            or sorted(manifest["cells"], key=lambda c: c["episode_id"]) != sorted(expected, key=lambda c: c["episode_id"])):
        raise ValueError("incomplete_or_unmatched_condition_matrix")
    for cfg in manifest["cells"]:
        validate_config(cfg)
        if cfg["episode_id"] in seen or cfg["execution_mode"] != manifest["execution_mode"]:
            raise ValueError("duplicate_or_mixed_workflow_cell")
        seen.add(cfg["episode_id"])
        payload = manifest["bundles"].get(cfg["bundle_sha256"])
        if payload is None or digest(payload) != cfg["bundle_sha256"]:
            raise ValueError("workflow_bundle_hash_mismatch")
    return manifest


def run_cell(manifest_path, episode_id, output, *, execute_live=False, inventory=INVENTORY):
    manifest = load_manifest(manifest_path)
    found = [c for c in manifest["cells"] if c["episode_id"] == episode_id]
    if len(found) != 1:
        raise ValueError("exact_workflow_cell_required")
    cfg = found[0]
    attack_spec = validate_attack_spec(
        manifest["attack_specs"][cfg["bundle_sha256"]],
        expected_goal=manifest["bundles"][cfg["bundle_sha256"]]["public"]["goal"]["goal"],
    )
    source = manifest["bundles"][cfg["bundle_sha256"]]["source_record"]
    root = Path(output)
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    write(root / "allocation.json", {"manifest_sha256": manifest["manifest_sha256"], "config": cfg,
                                    "system_profile": manifest["system_spec"]["system_profile"],
                                    "system_spec_sha256": manifest["system_spec_sha256"],
                                    "source_version": "agentdojo:v1@" + digest(manifest["upstream_hashes"]),
                                    "task_binding": {"source": "agentdojo", **{k: source[k] for k in
                                        ("suite", "task_id", "initial_state_sha256", "class_source_sha256", "prompt_sha256")}},
                                    "source_record": source,
                                    "attack_spec_id": attack_spec["attack_spec_id"],
                                    "attack_spec_sha256": attack_spec["spec_sha256"],
                                    "attack_spec_visible_to": ["E"] if cfg["regime"] == "malicious" else [],
                                    "regime_label": manifest["regime_labels"][cfg["regime"]],
                                    "phase_schedule_sha256": manifest["phase_schedule_sha256"],
                                    "independent_world_id": "agentdojo:"+source["suite"]+":"+source["initial_state_sha256"],
                                    "created_at_unix": time.time(), "status": "allocated"})
    remote = cfg["execution_mode"] == "live_diagnostic"
    if remote:
        if not execute_live:
            write(root / "status.json", {"status": "not_run", "reason": "explicit_execute_live_flag_required", "model_calls": 0})
            return {"status": "not_run", "reason": "explicit_execute_live_flag_required"}
        provider_source = manifest.get("provider_route_source")
        if provider_source is None:
            status = {"status": "not_run", "reason": "provider_route_not_bound", "model_calls": 0}
            write(root / "status.json", status)
            return status
        route = verify_binding(provider_source)
        try:
            inv = strict_loads(Path(inventory).read_bytes())
            ready = model_readiness(cfg, inv)
            checked = inv.get("checked_at_unix")
            fresh = type(checked) in (int, float) and 0 <= time.time() - checked <= 300
        except (OSError, ValueError, TypeError, KeyError):
            status = {"status": "not_run", "reason": "inventory_unavailable_or_invalid", "model_calls": 0}
            write(root / "status.json", status)
            return status
        route_inventory_matches = (inv.get("schema_version") == "rq1-provider-inventory/1"
                                   and inv.get("base_url") == base_url(route)
                                   and inv.get("provider_route_sha256") == provider_source["sha256"]
                                   and inv.get("account_label") == route["account_label"]
                                   and inv.get("account_identity") == provider_source["account_identity"]
                                   and inv.get("model_calls") == 0)
        if not route_inventory_matches or not ready["listed"] or not fresh:
            write(root / "status.json", {"status": "not_run", "reason": "required_models_missing_or_inventory_stale", **ready, "model_calls": 0})
            return {"status": "not_run", **ready}
        try:
            fingerprint = credential_fingerprint(os.environ.get(route["credential_env"]),
                                                 inv.get("credential_salt"))
            credential_matches = (type(inv.get("credential_fingerprint")) is str
                                  and hmac.compare_digest(fingerprint, inv["credential_fingerprint"]))
        except ValueError:
            credential_matches = False
        if not credential_matches:
            status = {"status": "not_run", "reason": "provider_route_credential_changed", "model_calls": 0}
            write(root / "status.json", status)
            return status
    bundle = TaskBundle(canonical(manifest["bundles"][cfg["bundle_sha256"]]), cfg["bundle_sha256"])
    rec = bundle.record()
    native, collector = None, None
    failure_stage = "native_world_start"
    try:
        native = ProcessNativeTask(manifest["native_python"], manifest["source_root"], rec["suite"], rec["original_id"], timeout=30)
        # Compile against the untouched original world BEFORE any actor runs.
        # These private references never enter the driver's public observation.
        from ..rq1_measurement_v1.contracts import compile_from_bundle
        from ..rq1_measurement_v1.registry import attach_runtime_registry
        failure_stage = "pre_run_measurement_registration"
        locked = compile_from_bundle(rec, native.snapshot())
        registered = attach_runtime_registry(locked["score_contract"], manifest["system_spec"]["system_profile"])
        registered_hash = digest(registered)
        from ..rq1_measurement_v1.runtime_scope import definition as runtime_scope_definition
        from .qid_registration import compile_pre_run_registration
        runtime_scope = runtime_scope_definition(manifest["system_spec"]["system_profile"])
        prompts = role_prompts(
            cfg, native.prompt, rec["public"]["goal"]["goal"],
            manifest["system_spec"]["system_profile"], attack_spec=attack_spec,
        )
        qid_registration = compile_pre_run_registration(
            episode_id=cfg["episode_id"], bundle_sha256=cfg["bundle_sha256"],
            record=native.record, prompt=native.prompt, initial=native.snapshot(),
            public_h_prompt=prompts["H"],
            source_contract_sha256=locked["source_contract_sha256"],
            protected_contract_sha256=registered_hash,
            information_contract_sha256=locked["information_contract"]["contract_sha256"],
            reference_sha256=locked["reference"]["reference_sha256"],
            measurement_adapter=locked["reference"]["measurement_adapter"],
        )
        write(root / "pre-run-registration.json", {
            "source_contract_sha256": locked["source_contract_sha256"],
            "protected_contract_sha256": registered_hash,
            "information_contract_sha256": locked["information_contract"]["contract_sha256"],
            "private_facts_sha256": digest(locked["private_facts"]),
            "reference_sha256": locked["reference"]["reference_sha256"],
            "counts": locked["information_contract"]["counts"], "compiled_before_actor_execution": True,
            "system_spec_sha256": manifest["system_spec_sha256"],
            "episode_observable_definition": runtime_scope,
            "episode_observable_definition_sha256": digest(runtime_scope),
            "qid_pre_run_registration": qid_registration})
        # These source-expanded objects are tens of MB each. Only the locked
        # hashes are needed while other episodes' timed workers are running.
        del locked, registered
        collector = EventCollector(root / "execution", cfg["episode_id"])
        failure_stage = "driver_creation"
        if remote:
            transport = BoundRouteTransport(route, inv,
                timeout_seconds=PHASE_SCHEDULE["model_request_hard_timeout_seconds"])
            driver = RoleModelDriver(cfg, prompts,
                collector, transport)
        else:
            driver = EngineeringDriver(cfg, rec["public"], rec["original_id"], suite=rec["suite"])
        failure_stage = "episode_execution"
        capture = run_episode(
            cfg, bundle, native, driver, collector,
            system_profile=manifest["system_spec"]["system_profile"],
            qid_pre_run_registration=qid_registration,
        )
        write(root / "execution-anchor.json", {"execution_seal_sha256": capture["seal"]["seal_hash"],
                                               "manifest_sha256": manifest["manifest_sha256"]})
        failure_stage = "closed_evaluation"
        report = evaluate_closed(root / "execution", capture["seal"]["seal_hash"], native, bundle)
        if report.get("measurement") is not None and digest(report["measurement"]["contract"]) != registered_hash:
            raise ValueError("post_run_contract_differs_from_pre_run_registration")
        if (report.get("measurement") is not None and
                report["measurement"]["episode_observable"]["definition_sha256"] != digest(runtime_scope)):
            raise ValueError("post_run_observable_scope_differs_from_pre_run_registration")
        report_metadata = write_report(root, report)
        failure_stage = "seal_verification"
        verified = verify(root / "execution", expected_seal_hash=capture["seal"]["seal_hash"])
        closed_ok = verified["ok"] and not report["evaluation_errors"]
        status_name = ("completed" if closed_ok and report["closure_class"] == "host_final"
                       else "sealed_incomplete" if closed_ok and report["closure_class"] == "sealed_incomplete"
                       else "needs_review")
        status = {"status": status_name,
                  "episode_id": cfg["episode_id"], "execution_integrity": verified,
                  **report_metadata,
                  "closure_class": report["closure_class"],
                  "regime_label": report["regime_label"],
                  "external_phase_closed": report["phase_control"]["external_phase_closed"],
                  "host_entered": report["phase_control"]["host_entered"],
                  "host_finalization_entered": report["phase_control"]["host_finalization_entered"],
                  "native_task_success": report["native_task_success"], "native_goal_success": report["native_goal_success"],
                  "internal_worker_used": report["internal_worker_used"],
                  "observed_unauthorized_effect": report["outcomes"]["observed_unauthorized_effect"] if report["outcomes"] else None,
                  "execution_mode": cfg["execution_mode"], "formal_ready": False}
        if remote and route["schema_version"] == "rq1-provider-route/2" and verified["ok"]:
            status["shared_proxy_route_diagnostic"] = inspect_shared_proxy_route(root / "execution")
        write(root / "status.json", status)
        verify_upstream(manifest["source_root"], manifest["upstream_hashes"])
        return status
    except Exception as exc:
        # Keep every allocation, including crashes. Never retry/select the best.
        status = {"status": "needs_review", "episode_id": cfg["episode_id"],
                  "error_type": type(exc).__name__, "reason": "workflow_execution_or_evaluation_failed",
                  "failure_stage": failure_stage,
                  "execution_mode": cfg["execution_mode"], "formal_ready": False}
        if not (root / "status.json").exists():
            write(root / "status.json", status)
        else:
            write(root / "post_run_failure.json", status)
        return status
    finally:
        if native is not None:
            native.shutdown()
        if collector is not None:
            collector.abort()


def inspect_workflow(manifest_path, runs_root):
    manifest = load_manifest(manifest_path)
    allocations = {}
    for path in Path(runs_root).glob("*/allocation.json"):
        allocation = strict_loads(path.read_bytes())
        if allocation.get("manifest_sha256") != manifest["manifest_sha256"]:
            continue
        episode = allocation["config"]["episode_id"]
        if allocation["config"] not in manifest["cells"]:
            raise ValueError("allocation_configuration_mismatch")
        if episode in allocations:
            raise ValueError("duplicate_cell_attempts_require_explicit_analysis_not_best_result_selection")
        status_path = path.parent / "status.json"
        status = strict_loads(status_path.read_bytes()) if status_path.exists() else {"status": "unfinished_or_failed"}
        if status.get("status") in {"completed", "sealed_incomplete"}:
            try:
                anchor = strict_loads((path.parent / "execution-anchor.json").read_bytes())
                report = read_report(path.parent, status)
                good = (anchor["manifest_sha256"] == manifest["manifest_sha256"]
                        and report["config"] == allocation["config"]
                        and report["execution_seal_sha256"] == anchor["execution_seal_sha256"]
                        and verify(path.parent / "execution", expected_seal_hash=anchor["execution_seal_sha256"])["ok"]
                        and not (path.parent / "post_run_failure.json").exists())
                if good and manifest.get("provider_route_source", {}).get("account_identity") == SHARED_IDENTITY:
                    good = (status.get("shared_proxy_route_diagnostic")
                            == inspect_shared_proxy_route(path.parent / "execution"))
            except (ValueError, KeyError, OSError):
                good = False
            if not good:
                status = {"status": "needs_review", "reason": "closed_artifact_integrity_failure"}
        allocations[episode] = status
    rows = [{"episode_id": c["episode_id"], "topology": c["topology"], "level": c["level"], "regime": c["regime"],
             **allocations.get(c["episode_id"], {"status": "not_started"})} for c in manifest["cells"]]
    return {"assigned": len(rows), "completed": sum(r["status"] == "completed" for r in rows),
            "sealed_incomplete": sum(r["status"] == "sealed_incomplete" for r in rows),
            "needs_review": sum(r["status"] in {"needs_review", "unfinished_or_failed"} for r in rows),
            "not_run": sum(r["status"] in {"not_run", "not_started"} for r in rows),
            "rows": rows, "formal_ready": False, "public_task_count": manifest["task_count"],
            "distinct_public_worlds": len({b["world_id"] for b in manifest["bundles"].values()})}


def run_offline_batch(manifest_path, runs_root, *, max_cells=48, workers=1):
    """Bounded resumable engineering run. Cannot start paid calls."""
    manifest = load_manifest(manifest_path)
    if manifest["execution_mode"] != "engineering":
        raise ValueError("batch_is_offline_only_use_explicit_single_live_cell")
    if type(max_cells) is not int or not 1 <= max_cells <= 48:
        raise ValueError("offline_batch_limit_one_to_48")
    if type(workers) is not int or not 1 <= workers <= 4:
        raise ValueError("offline_workers_one_to_four")
    root = Path(runs_root)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    inspect_workflow(manifest_path, root)  # Refuse duplicate attempts before work.
    remaining = [c for c in manifest["cells"] if not (root / c["episode_id"]).exists()]
    selected, completed, stopped = iter(remaining[:max_cells]), 0, False
    with ThreadPoolExecutor(max_workers=workers) as pool:
        pending = {}
        def submit_next():
            cfg = next(selected, None)
            if cfg is not None:
                future = pool.submit(run_cell, manifest_path, cfg["episode_id"], root / cfg["episode_id"])
                pending[future] = cfg["episode_id"]
        for _ in range(workers):
            submit_next()
        while pending:
            done, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                episode = pending.pop(future)
                status = future.result()
                completed += 1
                print(json.dumps({"batch_step": completed, "episode_id": episode, "status": status["status"]}), flush=True)
                stopped = stopped or status["status"] != "completed"
            # On failure, drain already running cells but start no new ones.
            if not stopped:
                for _ in done:
                    submit_next()
    return inspect_workflow(manifest_path, root)


def main():
    parser = argparse.ArgumentParser(description="RQ1 actual three-actor workflow; offline by default")
    sub = parser.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("--output", required=True)
    prep.add_argument("--tasks", nargs="+", default=["workspace:user_task_8", "workspace:user_task_26"])
    prep.add_argument("--system-profile", choices=PROFILES, default=NATIVE_PROFILE)
    prep.add_argument("--repeats", type=int, default=1)
    prep.add_argument("--mode", choices=["engineering", "live_diagnostic"], default="engineering")
    prep.add_argument("--models-file", help="Explicit H/S/E profiles for a separately registered baseline; never fallback")
    prep.add_argument("--budget-file", help="Explicit bounded episode budget for this diagnostic slice")
    prep.add_argument("--provider-route-file", help="No-secret dedicated endpoint and credential environment binding")
    prep.add_argument("--topologies", nargs="+", choices=TOPOLOGIES, default=list(TOPOLOGIES))
    prep.add_argument("--levels", nargs="+", choices=tuple(LEVELS), default=list(LEVELS))
    prep.add_argument("--regimes", nargs="+", choices=REGIMES, default=list(REGIMES))
    prep.add_argument("--inventory", default=str(INVENTORY))
    prep.add_argument("--qualified", default=str(QUALIFIED),
                      help="Source-locked native qualification/candidate manifest")
    prep.add_argument("--goals", default=str(GOALS),
                      help="Predeclared original task-to-native-goal assignments")
    run = sub.add_parser("run")
    run.add_argument("--manifest", required=True)
    run.add_argument("--episode", required=True)
    run.add_argument("--output", required=True)
    run.add_argument("--execute-live", action="store_true")
    run.add_argument("--inventory", default=str(INVENTORY))
    inspect = sub.add_parser("status")
    inspect.add_argument("--manifest", required=True)
    inspect.add_argument("--runs", required=True)
    batch = sub.add_parser("run-offline")
    batch.add_argument("--manifest", required=True)
    batch.add_argument("--runs", required=True)
    batch.add_argument("--max-cells", type=int, default=48)
    batch.add_argument("--workers", type=int, default=1)
    args = parser.parse_args()
    if args.command == "prepare":
        result = prepare(args.output, tasks=args.tasks, repeats=args.repeats, mode=args.mode,
                         system_profile=args.system_profile, models_file=args.models_file,
                         budget_file=args.budget_file, provider_route_file=args.provider_route_file,
                         topologies=args.topologies,
                         levels=args.levels, regimes=args.regimes, inventory=args.inventory,
                         qualified=args.qualified, goals=args.goals)
    elif args.command == "run":
        result = run_cell(args.manifest, args.episode, args.output, execute_live=args.execute_live, inventory=args.inventory)
    elif args.command == "run-offline":
        result = run_offline_batch(args.manifest, args.runs, max_cells=args.max_cells, workers=args.workers)
    else:
        result = inspect_workflow(args.manifest, args.runs)
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
