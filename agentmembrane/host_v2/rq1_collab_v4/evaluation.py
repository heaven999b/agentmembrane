"""Read sealed v4 execution and evaluate ORIGINAL native endpoints separately.

The compatibility projection never mutates the source trajectory, never turns
memory calls into missing native calls, and never fabricates a native outcome.
"""
from __future__ import annotations

from pathlib import Path

from ..rq1_collab_v1.audit import verify, strict_loads
from ..rq1_collab_v3.contract import clone, digest
from ..rq1_collab_v3.evaluation import (validate_evidence as validate_v3,
    derive_outcomes as derive_v3, analysis_native_endpoints as analysis_v3)
from .contract import PROTOCOL, PROFILES, system_spec
from .attack_spec import attribute_attack, compile_attack_spec, is_registered_attack_goal


def native_view(data):
    """Copy only: v3 native evaluator sees actual resolved native arguments."""
    if type(data) is not dict or data.get("schema_version") not in {"rq1-evidence/3", "rq1-evidence/4"}:
        raise ValueError("v3_or_v4_evidence_required")
    view = clone(data)
    view["schema_version"] = "rq1-evidence/3"
    if data["schema_version"] == "rq1-evidence/4":
        projected = []
        for decision in view["decisions"]:
            action = decision.get("action", {})
            domain = decision.get("dispatch_domain")
            is_system = (domain == "memory" and action.get("type") == "tool_action"
                         and str(action.get("tool", "")).startswith("memory."))
            reference_rejected = domain == "memory_reference_rejected" and bool(action.get("argument_refs"))
            if is_system or reference_rejected:
                continue
            if "resolved_action" in decision:
                resolved = decision["resolved_action"]
                if (type(resolved) is not dict or resolved.get("type") != "tool_action"
                        or resolved.get("tool") != action.get("tool") or resolved.get("argument_refs")
                        or type(resolved.get("arguments")) is not dict):
                    raise ValueError("invalid_resolved_native_action")
                call_id = decision["event_id"] + ":native"
                call = next((row for row in view["native_calls"] if row["call_id"] == call_id), None)
                if call is not None and (call.get("tool") != resolved["tool"] or call.get("arguments") != resolved["arguments"]):
                    raise ValueError("resolved_action_does_not_match_real_native_dispatch")
                decision["action"] = clone(resolved)
            projected.append(decision)
        view["decisions"] = projected
    return view


def validate_evidence(data):
    if type(data) is not dict or data.get("schema_version") != "rq1-evidence/4":
        raise ValueError("v4_evidence_required")
    cfg = validate_v3(native_view(data))
    profile = data.get("system_profile")
    if profile not in PROFILES:
        raise ValueError("registered_v4_system_profile_required")
    # Missing closure artifacts remain observable missingness. If a spec IS
    # supplied, any mismatch is corruption, not another valid treatment.
    if data.get("system_spec") is not None:
        if data["system_spec"] != system_spec(profile) or digest(data["system_spec"]) != data.get("system_spec_sha256"):
            raise ValueError("v4_system_spec_binding_mismatch")
    if data.get("bundle_sha256") != cfg["bundle_sha256"]:
        raise ValueError("v4_bundle_configuration_mismatch")
    try:
        public_goal = data["bundle_public"]["goal"]["goal"]
    except (KeyError, TypeError) as exc:
        raise ValueError("v4_public_attack_goal_required") from exc
    expected_attack_spec = (
        compile_attack_spec(public_goal) if is_registered_attack_goal(public_goal) else None
    )
    attack_fields = {"attack_spec", "attack_spec_sha256", "attack_spec_visible_to"}
    present_attack_fields = attack_fields & set(data)
    if present_attack_fields and present_attack_fields != attack_fields:
        raise ValueError("v4_partial_attack_spec_binding")
    if expected_attack_spec is None:
        if cfg["execution_mode"] == "live_diagnostic":
            raise ValueError("v4_registered_live_attack_goal_required")
        if data.get("attack_spec") is not None or data.get("attack_spec_sha256") is not None:
            raise ValueError("v4_unregistered_engineering_attack_spec_must_be_absent")
    elif not present_attack_fields:
        # Read-only compatibility for already sealed engineering artifacts that
        # predate AttackSpec. New runtime evidence always writes all three keys;
        # live evidence is never admitted through this compatibility branch.
        if cfg["execution_mode"] == "live_diagnostic":
            raise ValueError("v4_live_attack_spec_binding_required")
    elif (data["attack_spec"] != expected_attack_spec
            or data["attack_spec_sha256"] != expected_attack_spec["spec_sha256"]):
        raise ValueError("v4_attack_spec_binding_mismatch")
    expected_visibility = (["E"] if cfg["regime"] == "malicious" else []) \
        if expected_attack_spec is not None else []
    if present_attack_fields and data.get("attack_spec_visible_to") != expected_visibility:
        raise ValueError("v4_attack_spec_visibility_mismatch")
    groups = list(data.get("runtime_trace", {}).items())
    groups += [("memory_events", data.get("memory", {}).get("events", []))]
    seen = {}
    for name, rows in groups:
        if name in {"closed", "closure_event_ids"}:
            continue
        if type(rows) is not list:
            raise ValueError("v4_event_collection_not_list:" + name)
        for row in rows:
            if type(row) is not dict:
                raise ValueError("v4_event_not_object")
            eid = row.get("event_id")
            if type(eid) is not str or not eid.startswith(data["episode_id"] + ":"):
                raise ValueError("v4_event_outside_episode")
            if eid in seen and seen[eid] != row:
                raise ValueError("v4_conflicting_event_identity")
            seen[eid] = row
            if name == "authority_snapshots":
                state = row.get("state", {})
                payload = {k: v for k, v in state.items() if k != "state_sha256"}
                if state.get("state_sha256") != digest(payload):
                    raise ValueError("authority_snapshot_digest_mismatch")
    return cfg


def read_evidence(run_dir, expected_seal_hash):
    integrity = verify(run_dir, expected_seal_hash=expected_seal_hash)
    if not integrity["ok"]:
        raise ValueError("execution_seal_invalid")
    root = Path(run_dir)
    seal = strict_loads((root / "seal.json").read_bytes())
    data = strict_loads((root / "artifacts/evidence-v4.json").read_bytes())
    validate_evidence(data)
    metadata = seal["metadata"]
    if (metadata.get("protocol_version") != PROTOCOL or metadata.get("evidence_path") != "artifacts/evidence-v4.json"
            or metadata.get("config_sha256") != digest(data["config"])
            or metadata.get("system_profile") != data["system_profile"]
            or seal["episode_id"] != data["episode_id"]):
        raise ValueError("seal_v4_configuration_mismatch")
    if data.get("system_spec_sha256") is not None and metadata.get("system_spec_sha256") != data["system_spec_sha256"]:
        raise ValueError("seal_v4_system_spec_mismatch")
    return data


def derive_outcomes(data):
    validate_evidence(data)
    result = derive_v3(native_view(data))
    result["source_schema_version"] = "rq1-evidence/4"
    result["native_projection_does_not_cover_memory_actions"] = True
    return result


def analysis_native_endpoints(data, native, goal):
    return analysis_v3(native_view(data), native, goal)


def evaluate_closed(run_dir, expected_seal_hash, adapter, bundle, *, semantic_judges=None):
    data = read_evidence(run_dir, expected_seal_hash)
    if data["bundle_sha256"] != bundle.sha256:
        raise ValueError("evaluation_task_binding_mismatch")
    before, after = data["initial_snapshot"], data["terminal_snapshot"]
    native, strict, goals, errors = None, None, [], []
    if before is not None and after is not None:
        try:
            native = adapter.native_score(before, after, data["final_text"])
            strict = adapter.strict_score(before, after, data["final_text"])
        except Exception as exc:
            errors.append({"stage": "task_checker", "error_type": type(exc).__name__})
        prefix = []
        goal_id = bundle.record()["public"]["goal"]["goal_id"]
        checkpoints = []
        for call in data["native_calls"]:
            if call.get("evidence_quality", {}).get("backend_entered") is True:
                prefix.append({"function": call["tool"], "args": clone(call["arguments"])})
            if call.get("after") is not None:
                checkpoints.append((call["after"], "", clone(prefix)))
        checkpoints.append((after, data["final_text"], clone(prefix)))
        for snapshot, answer, calls in checkpoints:
            try:
                goals.append(adapter.native_attack_score_detail(goal_id, before, snapshot, answer, function_calls=calls))
            except Exception as exc:
                goals.append({"value": None, "reason": "original_native_goal_checker_failed"})
                errors.append({"stage": "goal_checker", "error_type": type(exc).__name__})
    values = [g.get("value") for g in goals]
    goal_success = True if any(v is True or type(v) is int and v == 1 for v in values) else None if not values or any(v is None for v in values) else False
    try:
        outcomes = derive_outcomes(data)
    except Exception as exc:
        outcomes = None
        errors.append({"stage": "independent_native_outcomes", "error_type": type(exc).__name__})
    try:
        from ..rq1_measurement_v1.pipeline import evaluate
        measurement = evaluate(data, semantic_judges=semantic_judges)
        errors.extend({"stage": "measurement_observer", **row} for row in measurement.get("observer_errors", []))
    except Exception as exc:
        measurement = None
        errors.append({"stage": "measurement_v1", "error_type": type(exc).__name__})
    endpoints = analysis_native_endpoints(data, native, goal_success)
    attribution = (attribute_attack(data, data["attack_spec"])
                   if data.get("attack_spec") is not None else {
        "attack_spec_id": None, "attack_spec_sha256": None,
        "typed_target_request": None, "proposed": None,
        "any_target_step_dispatch_entered": None,
        "target_sequence_completed": None, "target_dispatch_complete": None,
        "observed_payload_bound": None, "matching_event_ids": [],
        "matching_call_ids": [], "steps": [],
        "limitations": ["unregistered_engineering_attack_goal"],
    })
    attack_process = {
        "schema_version": "rq1-attack-process/1",
        "attack_spec_id": attribution["attack_spec_id"],
        "attack_spec_sha256": attribution["attack_spec_sha256"],
        "typed_target_request": attribution["typed_target_request"],
        "any_target_step_proposed": attribution["proposed"],
        "any_target_step_dispatch_entered": attribution["any_target_step_dispatch_entered"],
        "target_sequence_completed": attribution["target_sequence_completed"],
        "target_dispatch_complete": attribution["target_dispatch_complete"],
        "observed_payload_bound": attribution["observed_payload_bound"],
        "native_attack_effect": endpoints["native_goal_success"],
        "matching_event_ids": attribution["matching_event_ids"],
        "matching_call_ids": attribution["matching_call_ids"],
        "steps": attribution["steps"],
        "limitations": attribution["limitations"],
    }
    return {"schema_version": "rq1-episode-report/4", "episode_id": data["episode_id"],
        "execution_seal_sha256": expected_seal_hash, "config": data["config"],
        "system_profile": data["system_profile"], "system_spec_sha256": data.get("system_spec_sha256"),
        "terminal_reason": data["terminal_reason"], "internal_worker_used": data["internal_worker_used"],
        "native_task_success": native, "native_task_success_raw": native, "strict_task_result": strict,
        "analysis_endpoints": endpoints, "attack_process": attack_process,
        "native_goal_success": goal_success, "native_goal_success_raw": goal_success,
        "native_goal_checkpoints": goals, "outcomes": outcomes, "measurement": measurement,
        "evaluation_errors": errors, "execution_failures": data["failures"], "budget": data["budget"],
        "behavioral_n": data["behavioral_n"], "formal_ready": False}
