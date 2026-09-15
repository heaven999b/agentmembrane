"""Shared, fail-closed JSON and immutable enum primitives for Host Boundary V2."""

from __future__ import annotations

import hashlib
import json
import math
import os
import tempfile
from collections.abc import Iterable, Mapping
from enum import StrEnum
from pathlib import Path
from typing import Any, NoReturn


class SchemaError(ValueError):
    """A serialized object does not satisfy its declared V2 schema."""


class IntegrityError(RuntimeError):
    """Frozen content or identity differs from its declared value."""


class RunKind(StrEnum):
    SCRIPTED = "scripted"
    GATE = "gate"
    FORMAL = "formal"


class RunState(StrEnum):
    PREPARED = "prepared"
    RUNNING = "running"
    SUSPENDED = "suspended"
    COMPLETE = "complete"
    AUDITED_VALID = "audited_valid"
    AUDITED_INVALID = "audited_invalid"
    ABORTED = "aborted"


class PlannerRole(StrEnum):
    ATTACKER = "objective_aware_white_box_attacker"
    BENIGN = "ordinary_task_agent"


class TaskOrigin(StrEnum):
    PUBLIC_BENCHMARK = "public_benchmark"
    REAL_WORKFLOW = "real_workflow"
    AUTHORED_SYNTHETIC = "authored_synthetic"


class FailureClass(StrEnum):
    NONE = "none"
    EXPLICIT_ABSTENTION = "explicit_abstention"
    TRANSPORT = "transport_failure"
    PROVIDER_POLICY = "provider_policy_failure"
    PARSE = "parse_failure"
    SCHEMA = "schema_failure"
    ENVIRONMENT = "environment_failure"
    ORACLE = "oracle_failure"
    OTHER = "other_failure"


class PlannerTerminalKind(StrEnum):
    PROVIDER_POLICY_REFUSAL = "provider_policy_refusal"
    PRE_ATTEMPT_ABANDONMENT = "pre_attempt_abandonment"
    POST_HOST_FEEDBACK_DECLINE = "post_host_feedback_decline"
    BUDGET_EXHAUSTED = "budget_exhausted"
    NORMAL = "normal"


def _json_error(message: str, path: str = "$") -> NoReturn:
    raise SchemaError(f"{path}: {message}")


def _check_json_value(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            _json_error("non-finite numbers are not valid frozen JSON", path)
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _check_json_value(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                _json_error("object keys must be strings", path)
            _check_json_value(item, f"{path}.{key}")
        return
    _json_error(f"unsupported JSON value type {type(value).__name__}", path)


def canonical_json_bytes(value: Any) -> bytes:
    """Encode JSON with the exact stable encoding required by the V2 contract."""

    _check_json_value(value)
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:  # defensive: normalize public errors
        raise SchemaError(f"cannot encode canonical JSON: {exc}") from exc


def sha256_bytes(value: bytes) -> str:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("sha256_bytes requires a bytes-like value")
    return hashlib.sha256(bytes(value)).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def load_json(path: Path) -> dict[str, Any]:
    path = Path(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SchemaError(f"cannot load JSON object from {path}: {exc}") from exc
    _check_json_value(value)
    if not isinstance(value, dict):
        raise SchemaError(f"{path}: top-level JSON value must be an object")
    return value


def _obj(value: Any, path: str, *, required: set[str], optional: set[str] = set()) -> dict[str, Any]:
    if not isinstance(value, dict):
        _json_error("must be an object", path)
    keys = set(value)
    missing = required - keys
    unknown = keys - required - optional
    if missing:
        _json_error(f"missing required fields: {sorted(missing)}", path)
    if unknown:
        _json_error(f"unknown fields: {sorted(unknown)}", path)
    return value


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _typed(value: Any, expected: type | tuple[type, ...], path: str) -> None:
    if expected is int:
        ok = _is_int(value)
    elif expected == (int, float):
        ok = (isinstance(value, (int, float)) and not isinstance(value, bool))
    else:
        ok = isinstance(value, expected)
    if not ok:
        name = expected.__name__ if isinstance(expected, type) else " or ".join(t.__name__ for t in expected)
        _json_error(f"must be {name}", path)


def _string(value: Any, path: str, *, nonempty: bool = True) -> None:
    _typed(value, str, path)
    if nonempty and not value:
        _json_error("must not be empty", path)


def _integer(value: Any, path: str, *, minimum: int | None = None) -> None:
    _typed(value, int, path)
    if minimum is not None and value < minimum:
        _json_error(f"must be >= {minimum}", path)


def _number(value: Any, path: str, *, minimum: float | None = None, maximum: float | None = None) -> None:
    _typed(value, (int, float), path)
    if not math.isfinite(float(value)):
        _json_error("must be finite", path)
    if minimum is not None and value < minimum:
        _json_error(f"must be >= {minimum}", path)
    if maximum is not None and value > maximum:
        _json_error(f"must be <= {maximum}", path)


def _bool(value: Any, path: str) -> None:
    _typed(value, bool, path)


def _enum(value: Any, allowed: set[str], path: str) -> None:
    _string(value, path)
    if value not in allowed:
        _json_error(f"must be one of {sorted(allowed)}", path)


def _list(value: Any, path: str, *, nonempty: bool = False) -> list[Any]:
    _typed(value, list, path)
    if nonempty and not value:
        _json_error("must not be empty", path)
    return value


def _strings(value: Any, path: str, *, nonempty: bool = False, unique: bool = False) -> list[str]:
    rows = _list(value, path, nonempty=nonempty)
    for index, item in enumerate(rows):
        _string(item, f"{path}[{index}]")
    if unique and len(set(rows)) != len(rows):
        _json_error("must not contain duplicates", path)
    return rows


def _sha(value: Any, path: str) -> None:
    _string(value, path)
    if len(value) != 64 or value.lower() != value or any(ch not in "0123456789abcdef" for ch in value):
        _json_error("must be a lowercase SHA-256 hex string", path)


def _timestamp(value: Any, path: str) -> None:
    _string(value, path)
    # Frozen V2 timestamps are UTC; accepting offsets would make normalisation ambiguous.
    if not value.endswith("Z") or "T" not in value:
        _json_error("must be an RFC 3339 UTC timestamp ending in Z", path)
    try:
        from datetime import datetime

        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        _json_error(f"invalid RFC 3339 timestamp: {exc}", path)


_PROFILE_FIELDS = {
    "schema_version", "protocol_id", "profile_id", "run_kind", "rq_ids",
    "claim_bearing", "model", "taskpacks", "conditions_path", "condition_ids",
    "estimands_path", "estimand_ids", "replicates", "planner", "retries",
    "schedule", "execution", "gates", "denominator_policy", "notes",
}
_VISIBLE_CONTEXT_PROFILES = {
    "scripted_route_replay",
    "objective_aware_adaptive",
}
_EXECUTION_TRACKS = {
    "fixed_trace_host_replay",
    "adaptive_end_to_end",
}
_CANONICAL_RQ1_PROFILE_IDENTITY = {
    "construct_id": "authority_admission_boundary",
    "construct_version": "1.0.0",
    "proposal_alignment": "RQ1_authority_admission",
    "ladder_id": "authority_admission_a0_a5",
    "ladder_version": "1.0.0",
}
_CANONICAL_RQ1_PROFILE_FIELDS = set(_CANONICAL_RQ1_PROFILE_IDENTITY)
_OFFLINE_ASSAY_BINDING_FIELDS = {
    "taskpack_byte_tree_sha256",
    "taskpack_logical_content_sha256",
    "tasks_sha256",
    "output_namespace",
    "cache_namespace",
    "provider_calls_permitted",
    "model_calls_permitted",
    "formal_run_permitted",
    "external_run_authorized",
}
_PROFILE_BINDING_FIELDS = {
    "visible_context_profile",
    "offline_assay_binding",
}
_V21_PROFILE_CONTRACT_FIELDS = {
    "construct_id",
    "proposal_alignment",
    "legacy_experiment_id",
    "legacy_analysis_family",
    "answers_canonical_proposal_rq2",
    "pooling_with_semantic_rq2_permitted",
    "execution_stage",
    "protocol_stage",
    "h_ladder_covered",
    "scientific_sample_gate_satisfied",
}
_GENERIC_STAGE_FIELDS = {
    "execution_stage",
    "protocol_stage",
    "h_ladder_covered",
    "scientific_sample_gate_satisfied",
}
_V21_IDENTITY_FIELDS = _V21_PROFILE_CONTRACT_FIELDS - _GENERIC_STAGE_FIELDS
_V21_EXECUTION_STAGES = {
    "atomic_synthetic_bringup",
    "protocol_stage_g",
    "protocol_stage_s",
    "variance_pilot",
    "formal",
}


def _validate_executable_stage_contract(
    root: Mapping[str, Any], *, label: str
) -> None:
    missing = _GENERIC_STAGE_FIELDS - set(root)
    if missing:
        _json_error(
            f"{label} executable stage contract is incomplete: {sorted(missing)}",
            "$",
        )
    _enum(root["execution_stage"], _V21_EXECUTION_STAGES, "$.execution_stage")
    if root["protocol_stage"] is not None:
        _enum(root["protocol_stage"], {"G", "S"}, "$.protocol_stage")
    expected_protocol_stage = {
        "protocol_stage_g": "G",
        "protocol_stage_s": "S",
    }.get(root["execution_stage"])
    if root["protocol_stage"] != expected_protocol_stage:
        _json_error(
            f"must equal {expected_protocol_stage!r} for execution_stage",
            "$.protocol_stage",
        )
    _bool(root["h_ladder_covered"], "$.h_ladder_covered")
    _bool(
        root["scientific_sample_gate_satisfied"],
        "$.scientific_sample_gate_satisfied",
    )
    if root["execution_stage"] == "atomic_synthetic_bringup" and (
        root["h_ladder_covered"] is not False
        or root["scientific_sample_gate_satisfied"] is not False
    ):
        _json_error(
            "atomic bring-up must keep H-ladder and scientific-sample gates false",
            "$.execution_stage",
        )
    expected_run_kind = {
        "atomic_synthetic_bringup": RunKind.SCRIPTED.value,
        "protocol_stage_g": RunKind.SCRIPTED.value,
        "protocol_stage_s": RunKind.GATE.value,
        "variance_pilot": RunKind.GATE.value,
        "formal": RunKind.FORMAL.value,
    }[root["execution_stage"]]
    if root["run_kind"] != expected_run_kind:
        _json_error(
            f"must equal {expected_run_kind!r} for execution_stage",
            "$.run_kind",
        )
    if root["execution_stage"] != "formal" and root["claim_bearing"] is not False:
        _json_error(f"non-formal {label} stages must be nonclaim", "$.claim_bearing")
    if root["claim_bearing"] is True and (
        root["execution_stage"] != "formal"
        or root["run_kind"] != RunKind.FORMAL.value
    ):
        _json_error(
            f"claim-bearing {label} profiles must be formal-stage formal runs",
            "$.claim_bearing",
        )


def _validate_profile(value: Any, *, resolved: bool) -> None:
    required = set(_PROFILE_FIELDS)
    if resolved:
        required.add("resolution")
    root = _obj(
        value,
        "$",
        required=required,
        optional=(
            set(_V21_PROFILE_CONTRACT_FIELDS)
            | _PROFILE_BINDING_FIELDS
            | _CANONICAL_RQ1_PROFILE_FIELDS
            | {"execution_track"}
        ),
    )
    if root["schema_version"] != 2:
        _json_error("must equal 2", "$.schema_version")
    _enum(
        root["protocol_id"],
        {"host-boundary-v2", "host-boundary-v2.1"},
        "$.protocol_id",
    )
    canonical_rq1 = root.get("construct_id") == _CANONICAL_RQ1_PROFILE_IDENTITY[
        "construct_id"
    ]
    canonical_specific_fields = _CANONICAL_RQ1_PROFILE_FIELDS - {
        "construct_id",
        "proposal_alignment",
    }
    present_canonical_specific = set(root) & canonical_specific_fields
    if canonical_rq1 or present_canonical_specific:
        missing = _CANONICAL_RQ1_PROFILE_FIELDS - set(root)
        if missing:
            _json_error(
                f"canonical RQ1 identity is all-or-none; missing fields: {sorted(missing)}",
                "$",
            )
        for key, expected in _CANONICAL_RQ1_PROFILE_IDENTITY.items():
            if root[key] != expected:
                _json_error(f"must equal {expected!r}", f"$.{key}")
        legacy_only = _V21_IDENTITY_FIELDS - {"construct_id", "proposal_alignment"}
        if set(root) & legacy_only:
            _json_error("canonical RQ1 may not carry legacy RQ1b identity fields", "$")
        _validate_executable_stage_contract(root, label="canonical RQ1")
    present_contract = set(root) & _V21_PROFILE_CONTRACT_FIELDS
    if not canonical_rq1 and (root["protocol_id"] == "host-boundary-v2.1" or present_contract):
        missing_contract = _V21_PROFILE_CONTRACT_FIELDS - set(root)
        if missing_contract:
            _json_error(
                f"v2.1 contract is all-or-none; missing fields: {sorted(missing_contract)}",
                "$",
            )
        expected_identity = {
            "construct_id": "host_mediated_capability_exploitation",
            "proposal_alignment": "RQ1b_host_mediated",
            "legacy_experiment_id": "HB-RQ2-HCE",
            "legacy_analysis_family": "RQ2",
            "answers_canonical_proposal_rq2": False,
            "pooling_with_semantic_rq2_permitted": False,
        }
        for key, expected in expected_identity.items():
            if root[key] != expected:
                _json_error(f"must equal {expected!r}", f"$.{key}")
        _validate_executable_stage_contract(root, label="v2.1")
    has_visible_context = "visible_context_profile" in root
    has_offline_binding = "offline_assay_binding" in root
    has_execution_track = "execution_track" in root
    is_atomic_v21 = (
        root["protocol_id"] == "host-boundary-v2.1"
        and root.get("execution_stage") == "atomic_synthetic_bringup"
    )
    if canonical_rq1:
        if not has_visible_context or not has_execution_track:
            _json_error(
                "canonical RQ1 profiles require visible_context_profile and execution_track",
                "$",
            )
    elif has_execution_track:
        _json_error("execution_track is reserved for canonical RQ1 profiles", "$.execution_track")
    elif has_visible_context != has_offline_binding:
        _json_error(
            "visible_context_profile and offline_assay_binding must be serialized together",
            "$",
        )
    if is_atomic_v21 and not (has_visible_context and has_offline_binding):
        _json_error(
            "v2.1 atomic bring-up requires visible_context_profile and offline_assay_binding",
            "$",
        )
    if has_visible_context:
        if not canonical_rq1 and root["protocol_id"] != "host-boundary-v2.1":
            _json_error(
                "profile-bound visible contexts require v2.1 or canonical RQ1",
                "$.visible_context_profile",
            )
        _enum(
            root["visible_context_profile"],
            _VISIBLE_CONTEXT_PROFILES,
            "$.visible_context_profile",
        )
    if has_execution_track:
        _enum(root["execution_track"], _EXECUTION_TRACKS, "$.execution_track")
        expected_track = {
            "scripted_route_replay": "fixed_trace_host_replay",
            "objective_aware_adaptive": "adaptive_end_to_end",
        }[root["visible_context_profile"]]
        if root["execution_track"] != expected_track:
            _json_error(
                f"must equal {expected_track!r} for visible_context_profile",
                "$.execution_track",
            )
        allowed_kinds = {
            "fixed_trace_host_replay": {RunKind.SCRIPTED.value},
            "adaptive_end_to_end": {RunKind.GATE.value, RunKind.FORMAL.value},
        }[root["execution_track"]]
        if root["run_kind"] not in allowed_kinds:
            _json_error(
                f"must be one of {sorted(allowed_kinds)} for execution_track",
                "$.run_kind",
            )
    if has_offline_binding:
        binding = _obj(
            root["offline_assay_binding"],
            "$.offline_assay_binding",
            required=set(_OFFLINE_ASSAY_BINDING_FIELDS),
        )
        for key in (
            "taskpack_byte_tree_sha256",
            "taskpack_logical_content_sha256",
            "tasks_sha256",
        ):
            _sha(binding[key], f"$.offline_assay_binding.{key}")
        for key in ("output_namespace", "cache_namespace"):
            _string(binding[key], f"$.offline_assay_binding.{key}")
            if binding[key].strip() != binding[key] or not binding[key].strip():
                _json_error(
                    "must be a nonempty, whitespace-trimmed namespace",
                    f"$.offline_assay_binding.{key}",
                )
        if binding["output_namespace"] == binding["cache_namespace"]:
            _json_error(
                "output and cache namespaces must be distinct",
                "$.offline_assay_binding",
            )
        for key in (
            "provider_calls_permitted",
            "model_calls_permitted",
            "formal_run_permitted",
            "external_run_authorized",
        ):
            _bool(binding[key], f"$.offline_assay_binding.{key}")
            if binding[key] is not False:
                _json_error(
                    "must equal false for the offline atomic assay",
                    f"$.offline_assay_binding.{key}",
                )
    _string(root["profile_id"], "$.profile_id")
    _enum(root["run_kind"], {item.value for item in RunKind}, "$.run_kind")
    _strings(root["rq_ids"], "$.rq_ids", nonempty=True, unique=True)
    _bool(root["claim_bearing"], "$.claim_bearing")

    model = _obj(
        root["model"], "$.model",
        required={"requested_id", "provider_route_id", "allowed_resolved_ids", "temperature", "max_completion_tokens"},
        optional={"reasoning_effort"},
    )
    _string(model["requested_id"], "$.model.requested_id")
    _string(model["provider_route_id"], "$.model.provider_route_id")
    allowed = _strings(model["allowed_resolved_ids"], "$.model.allowed_resolved_ids", nonempty=True, unique=True)
    if model["requested_id"] not in allowed:
        _json_error("requested_id must be included in allowed_resolved_ids", "$.model")
    _number(model["temperature"], "$.model.temperature", minimum=0)
    _integer(model["max_completion_tokens"], "$.model.max_completion_tokens", minimum=1)
    if "reasoning_effort" in model:
        _enum(
            model["reasoning_effort"],
            {"low", "medium", "high", "xhigh", "max", "ultra"},
            "$.model.reasoning_effort",
        )

    packs = _list(root["taskpacks"], "$.taskpacks", nonempty=True)
    pack_ids: list[str] = []
    for index, item in enumerate(packs):
        path = f"$.taskpacks[{index}]"
        pack = _obj(item, path, required={"pack_id", "root", "manifest_sha256", "split", "families", "task_ids"})
        _string(pack["pack_id"], f"{path}.pack_id"); pack_ids.append(pack["pack_id"])
        _string(pack["root"], f"{path}.root")
        if Path(pack["root"]).is_absolute():
            _json_error("must be a relative path", f"{path}.root")
        _sha(pack["manifest_sha256"], f"{path}.manifest_sha256")
        _string(pack["split"], f"{path}.split")
        _strings(pack["families"], f"{path}.families", nonempty=True, unique=True)
        if pack["task_ids"] is not None:
            _strings(pack["task_ids"], f"{path}.task_ids", nonempty=True, unique=True)
        elif root["run_kind"] == RunKind.GATE.value:
            _json_error(
                "gate profiles must freeze explicit held-out task IDs; null/all is forbidden",
                f"{path}.task_ids",
            )
    if len(set(pack_ids)) != len(pack_ids):
        _json_error("pack_id values must be unique", "$.taskpacks")

    for key in ("conditions_path", "estimands_path"):
        _string(root[key], f"$.{key}")
        if Path(root[key]).is_absolute():
            _json_error("must be a relative path", f"$.{key}")
    _strings(root["condition_ids"], "$.condition_ids", nonempty=True, unique=True)
    _strings(root["estimand_ids"], "$.estimand_ids", nonempty=True, unique=True)

    reps = _list(root["replicates"], "$.replicates", nonempty=True)
    rep_ids: list[str] = []
    for index, item in enumerate(reps):
        path = f"$.replicates[{index}]"
        rep = _obj(item, path, required={"replicate_id", "sampling_unit"})
        _string(rep["replicate_id"], f"{path}.replicate_id"); rep_ids.append(rep["replicate_id"])
        _string(rep["sampling_unit"], f"{path}.sampling_unit")
    if len(set(rep_ids)) != len(rep_ids):
        _json_error("replicate_id values must be unique", "$.replicates")

    planner = _obj(root["planner"], "$.planner", required={"attacker_prompt_path", "benign_prompt_path", "mode", "max_turns", "max_actions_per_turn", "response_schema_version"})
    for key in ("attacker_prompt_path", "benign_prompt_path"):
        _string(planner[key], f"$.planner.{key}")
        if Path(planner[key]).is_absolute():
            _json_error("must be a relative path", f"$.planner.{key}")
    _enum(planner["mode"], {"adaptive"}, "$.planner.mode")
    _integer(planner["max_turns"], "$.planner.max_turns", minimum=1)
    _integer(planner["max_actions_per_turn"], "$.planner.max_actions_per_turn", minimum=1)
    if planner["response_schema_version"] != 2:
        _json_error("must equal 2", "$.planner.response_schema_version")

    retries = _obj(root["retries"], "$.retries", required={"request_level_transport_retries", "infrastructure_attempts", "immutable_failure_classes"})
    _integer(retries["request_level_transport_retries"], "$.retries.request_level_transport_retries", minimum=0)
    _integer(retries["infrastructure_attempts"], "$.retries.infrastructure_attempts", minimum=1)
    _strings(retries["immutable_failure_classes"], "$.retries.immutable_failure_classes", nonempty=True, unique=True)

    schedule = _obj(
        root["schedule"],
        "$.schedule",
        required={"algorithm", "seed", "twins_same_wave"},
        optional={"condition_eligibility"},
    )
    _string(schedule["algorithm"], "$.schedule.algorithm")
    _integer(schedule["seed"], "$.schedule.seed", minimum=0)
    _bool(schedule["twins_same_wave"], "$.schedule.twins_same_wave")
    if "condition_eligibility" in schedule:
        eligibility = schedule["condition_eligibility"]
        if not isinstance(eligibility, dict) or not eligibility:
            _json_error("must be a non-empty object", "$.schedule.condition_eligibility")
        for family, condition_values in eligibility.items():
            _string(family, "$.schedule.condition_eligibility family")
            selected = _strings(
                condition_values,
                f"$.schedule.condition_eligibility.{family}",
                nonempty=True,
                unique=True,
            )
            unknown = sorted(set(selected) - set(root["condition_ids"]))
            if unknown:
                _json_error(
                    f"references conditions outside profile.condition_ids: {unknown}",
                    f"$.schedule.condition_eligibility.{family}",
                )

    execution = _obj(root["execution"], "$.execution", required={"worker_candidates", "max_inflight_block_candidates", "capacity_policy_path"})
    for key in ("worker_candidates", "max_inflight_block_candidates"):
        vals = _list(execution[key], f"$.execution.{key}", nonempty=True)
        for index, item in enumerate(vals):
            _integer(item, f"$.execution.{key}[{index}]", minimum=1)
        if len(set(vals)) != len(vals):
            _json_error("must not contain duplicates", f"$.execution.{key}")
    _string(execution["capacity_policy_path"], "$.execution.capacity_policy_path")
    if Path(execution["capacity_policy_path"]).is_absolute():
        _json_error("must be a relative path", "$.execution.capacity_policy_path")

    gates = _obj(
        root["gates"],
        "$.gates",
        required={
            "offline_tests_required", "scripted_family_positive_control_min",
            "scripted_benign_feasibility_min", "planner_output_coverage_min",
            "small_stratum_coverage_min", "max_refusal_imbalance",
            "require_oracle_blind_audit",
        },
        optional={
            "launch_policy_path", "rq_coverage_manifest_path",
            "zero_token_authorization_path", "g0_bootstrap_authorization_path",
            "gate_stage",
        },
    )
    _bool(gates["offline_tests_required"], "$.gates.offline_tests_required")
    _bool(gates["require_oracle_blind_audit"], "$.gates.require_oracle_blind_audit")
    for key in (
        "launch_policy_path", "rq_coverage_manifest_path",
        "zero_token_authorization_path", "g0_bootstrap_authorization_path",
    ):
        if key in gates:
            _string(gates[key], f"$.gates.{key}")
            if Path(gates[key]).is_absolute():
                _json_error("must be a relative path", f"$.gates.{key}")
    is_v21_contract = bool(set(root) & _V21_PROFILE_CONTRACT_FIELDS)
    if is_v21_contract and "gate_stage" in gates:
        _json_error(
            "legacy G0/G1/G2 labels are forbidden; use top-level execution_stage",
            "$.gates.gate_stage",
        )
    if root["run_kind"] == RunKind.GATE.value and not is_v21_contract:
        _enum(gates.get("gate_stage"), {"G0", "G1", "G2"}, "$.gates.gate_stage")
    elif "gate_stage" in gates:
        _json_error("is permitted only for gate profiles", "$.gates.gate_stage")
    for key in ("scripted_family_positive_control_min", "scripted_benign_feasibility_min", "planner_output_coverage_min", "small_stratum_coverage_min", "max_refusal_imbalance"):
        _number(gates[key], f"$.gates.{key}", minimum=0, maximum=1)
    if root["denominator_policy"] != "all_attempted_episodes":
        _json_error("must equal all_attempted_episodes", "$.denominator_policy")
    _typed(root["notes"], str, "$.notes")

    if resolved:
        resolution = _obj(
            root["resolution"],
            "$.resolution",
            required={
                "resolved_at", "selected_workers", "selected_max_inflight_blocks",
                "resolved_model_id", "provider_route_id", "dependency_hashes",
                "implementation_sha256", "protocol_sha256",
            },
            optional={
                "resolution_mode", "gate_result_path", "gate_result_sha256",
                "bootstrap_authorization_path", "bootstrap_authorization_sha256",
            },
        )
        _timestamp(resolution["resolved_at"], "$.resolution.resolved_at")
        mode = resolution.get("resolution_mode", "gate_result")
        _enum(mode, {"gate_result", "g0_bootstrap"}, "$.resolution.resolution_mode")
        if mode == "gate_result":
            if set(resolution) & {"bootstrap_authorization_path", "bootstrap_authorization_sha256"}:
                _json_error("gate_result mode cannot carry bootstrap authorization", "$.resolution")
            _string(resolution.get("gate_result_path"), "$.resolution.gate_result_path")
            _sha(resolution.get("gate_result_sha256"), "$.resolution.gate_result_sha256")
        else:
            if set(resolution) & {"gate_result_path", "gate_result_sha256"}:
                _json_error("g0_bootstrap mode cannot carry a gate result", "$.resolution")
            _string(
                resolution.get("bootstrap_authorization_path"),
                "$.resolution.bootstrap_authorization_path",
            )
            _sha(
                resolution.get("bootstrap_authorization_sha256"),
                "$.resolution.bootstrap_authorization_sha256",
            )
        _integer(resolution["selected_workers"], "$.resolution.selected_workers", minimum=1)
        _integer(resolution["selected_max_inflight_blocks"], "$.resolution.selected_max_inflight_blocks", minimum=1)
        _string(resolution["resolved_model_id"], "$.resolution.resolved_model_id")
        _string(resolution["provider_route_id"], "$.resolution.provider_route_id")
        deps = _list(resolution["dependency_hashes"], "$.resolution.dependency_hashes")
        paths: list[str] = []
        for index, item in enumerate(deps):
            path = f"$.resolution.dependency_hashes[{index}]"
            dep = _obj(item, path, required={"path", "sha256"})
            _string(dep["path"], f"{path}.path"); paths.append(dep["path"])
            _sha(dep["sha256"], f"{path}.sha256")
        if paths != sorted(paths) or len(set(paths)) != len(paths):
            _json_error("must be unique and sorted by path", "$.resolution.dependency_hashes")
        _sha(resolution["implementation_sha256"], "$.resolution.implementation_sha256")
        _sha(resolution["protocol_sha256"], "$.resolution.protocol_sha256")
        if resolution["selected_workers"] not in execution["worker_candidates"]:
            _json_error("must be declared in execution.worker_candidates", "$.resolution.selected_workers")
        if resolution["selected_max_inflight_blocks"] not in execution["max_inflight_block_candidates"]:
            _json_error("must be declared in execution.max_inflight_block_candidates", "$.resolution.selected_max_inflight_blocks")
        if resolution["resolved_model_id"] not in allowed:
            _json_error("must be in model.allowed_resolved_ids", "$.resolution.resolved_model_id")
        if resolution["provider_route_id"] != model["provider_route_id"]:
            _json_error("must match model.provider_route_id", "$.resolution.provider_route_id")


_RAW_GATE_RUN_FIELDS = {
    "workers", "max_inflight_blocks", "run_dir", "run_identity_sha256",
    "run_manifest_sha256", "resolved_profile_sha256", "schedule_sha256",
    "taskpack_hashes", "task_ids", "families",
    "requested_model_id", "resolved_model_id", "provider_route_id",
    "cache_manifest_sha256", "records_sha256", "records_count",
    "objective_activation_count", "failure_class_counts",
    "positive_control_success_by_family", "benign_success_by_family",
    "passed",
}


def _validate_raw_gate_run(
    item: Any, path: str, *, require_gate_stage: bool
) -> tuple[int, int]:
    required = set(_RAW_GATE_RUN_FIELDS)
    if require_gate_stage:
        required.add("gate_stage")
    row = _obj(item, path, required=required)
    if require_gate_stage:
        _enum(row["gate_stage"], {"G0", "G1"}, f"{path}.gate_stage")
    _integer(row["workers"], f"{path}.workers", minimum=1)
    _integer(row["max_inflight_blocks"], f"{path}.max_inflight_blocks", minimum=1)
    _string(row["run_dir"], f"{path}.run_dir")
    for key in (
        "run_identity_sha256", "run_manifest_sha256", "resolved_profile_sha256",
        "schedule_sha256", "cache_manifest_sha256", "records_sha256",
    ):
        _sha(row[key], f"{path}.{key}")
    _strings(row["task_ids"], f"{path}.task_ids", nonempty=True, unique=True)
    _strings(row["families"], f"{path}.families", nonempty=True, unique=True)
    for key in ("requested_model_id", "resolved_model_id", "provider_route_id"):
        _string(row[key], f"{path}.{key}")
    _typed(row["taskpack_hashes"], dict, f"{path}.taskpack_hashes")
    if not row["taskpack_hashes"]:
        _json_error("must not be empty", f"{path}.taskpack_hashes")
    for pack_id, digest in row["taskpack_hashes"].items():
        _string(pack_id, f"{path}.taskpack_hashes key")
        _sha(digest, f"{path}.taskpack_hashes.{pack_id}")
    _integer(row["records_count"], f"{path}.records_count", minimum=1)
    _integer(row["objective_activation_count"], f"{path}.objective_activation_count", minimum=0)
    failures = _obj(
        row["failure_class_counts"],
        f"{path}.failure_class_counts",
        required={item.value for item in FailureClass},
    )
    for failure_name, count in failures.items():
        _integer(count, f"{path}.failure_class_counts.{failure_name}", minimum=0)
    for key in ("positive_control_success_by_family", "benign_success_by_family"):
        _typed(row[key], dict, f"{path}.{key}")
        for family, counts in row[key].items():
            _string(family, f"{path}.{key} key")
            pair_counts = _obj(
                counts, f"{path}.{key}.{family}", required={"successes", "attempted"}
            )
            _integer(pair_counts["successes"], f"{path}.{key}.{family}.successes", minimum=0)
            _integer(pair_counts["attempted"], f"{path}.{key}.{family}.attempted", minimum=1)
            if pair_counts["successes"] > pair_counts["attempted"]:
                _json_error("successes cannot exceed attempted", f"{path}.{key}.{family}")
    _bool(row["passed"], f"{path}.passed")
    return row["workers"], row["max_inflight_blocks"]


def _validate_gate_result(value: Any) -> None:
    if not isinstance(value, dict):
        _json_error("must be an object", "$")
    version = value.get("schema_version")
    if version == 2:
        root = _obj(value, "$", required={"schema_version", "profile_id", "gate_taskpack_sha256", "candidate_results", "selected_workers", "selected_max_inflight_blocks", "selection_rule", "passed", "created_at"})
        _validate_legacy_gate_result(root)
        return
    if version == 4:
        root = _obj(
            value,
            "$",
            required={
                "schema_version", "profile_id", "predecessor_runs", "selected_workers",
                "selected_max_inflight_blocks", "selection_rule", "passed", "created_at",
            },
        )
        _string(root["profile_id"], "$.profile_id")
        rows = _list(root["predecessor_runs"], "$.predecessor_runs", nonempty=True)
        if len(rows) != 2:
            _json_error("must contain exactly the G0 and G1 predecessor runs", "$.predecessor_runs")
        stages: list[str] = []
        for index, item in enumerate(rows):
            path = f"$.predecessor_runs[{index}]"
            _validate_raw_gate_run(item, path, require_gate_stage=True)
            stages.append(item["gate_stage"])
        if sorted(stages) != ["G0", "G1"]:
            _json_error("must contain exactly one G0 and one G1 run", "$.predecessor_runs")
        _integer(root["selected_workers"], "$.selected_workers", minimum=1)
        _integer(root["selected_max_inflight_blocks"], "$.selected_max_inflight_blocks", minimum=1)
        if root["selection_rule"] != "highest candidate satisfying all frozen gates":
            _json_error("unexpected selection rule", "$.selection_rule")
        _bool(root["passed"], "$.passed")
        _timestamp(root["created_at"], "$.created_at")
        return
    if version != 3:
        _json_error("must equal 3 or 4 (version 2 is accepted only as a legacy offline fixture)", "$.schema_version")
    root = _obj(
        value,
        "$",
        required={
            "schema_version", "profile_id", "candidate_results", "selected_workers",
            "selected_max_inflight_blocks", "selection_rule", "passed", "created_at",
        },
    )
    _string(root["profile_id"], "$.profile_id")
    rows = _list(root["candidate_results"], "$.candidate_results", nonempty=True)
    seen: set[tuple[int, int]] = set()
    for index, item in enumerate(rows):
        path = f"$.candidate_results[{index}]"
        pair = _validate_raw_gate_run(item, path, require_gate_stage=False)
        if pair in seen:
            _json_error("duplicate concurrency candidate", path)
        seen.add(pair)
    _integer(root["selected_workers"], "$.selected_workers", minimum=1)
    _integer(root["selected_max_inflight_blocks"], "$.selected_max_inflight_blocks", minimum=1)
    if (root["selected_workers"], root["selected_max_inflight_blocks"]) not in seen:
        _json_error("selected concurrency is absent from candidate_results", "$")
    if root["selection_rule"] != "highest candidate satisfying all frozen gates":
        _json_error("unexpected selection rule", "$.selection_rule")
    _bool(root["passed"], "$.passed")
    _timestamp(root["created_at"], "$.created_at")


def _validate_legacy_gate_result(root: dict[str, Any]) -> None:
    _string(root["profile_id"], "$.profile_id"); _sha(root["gate_taskpack_sha256"], "$.gate_taskpack_sha256")
    rows = _list(root["candidate_results"], "$.candidate_results", nonempty=True)
    seen: set[tuple[int, int]] = set()
    for index, item in enumerate(rows):
        path = f"$.candidate_results[{index}]"
        row = _obj(item, path, required={"workers", "max_inflight_blocks", "attempted", "transport_success_rate", "planner_output_coverage", "explicit_abstention_rate_attack", "positive_control_by_family", "benign_feasibility_by_family", "passed"})
        for key, minimum in (("workers", 1), ("max_inflight_blocks", 1), ("attempted", 0)): _integer(row[key], f"{path}.{key}", minimum=minimum)
        pair = (row["workers"], row["max_inflight_blocks"])
        if pair in seen: _json_error("duplicate concurrency candidate", path)
        seen.add(pair)
        for key in ("transport_success_rate", "planner_output_coverage", "explicit_abstention_rate_attack"): _number(row[key], f"{path}.{key}", minimum=0, maximum=1)
        for key in ("positive_control_by_family", "benign_feasibility_by_family"):
            _typed(row[key], dict, f"{path}.{key}")
            for family, score in row[key].items(): _string(family, f"{path}.{key} key"); _number(score, f"{path}.{key}.{family}", minimum=0, maximum=1)
        _bool(row["passed"], f"{path}.passed")
    _integer(root["selected_workers"], "$.selected_workers", minimum=1)
    _integer(root["selected_max_inflight_blocks"], "$.selected_max_inflight_blocks", minimum=1)
    if (root["selected_workers"], root["selected_max_inflight_blocks"]) not in seen:
        _json_error("selected concurrency is absent from candidate_results", "$")
    if root["selection_rule"] != "highest candidate satisfying all frozen gates":
        _json_error("unexpected selection rule", "$.selection_rule")
    _bool(root["passed"], "$.passed"); _timestamp(root["created_at"], "$.created_at")


def _validate_campaign(value: Any) -> None:
    root = _obj(value, "$", required={"schema_version", "campaign_id", "protocol_id", "resolved_profiles", "dependencies", "execution"})
    if root["schema_version"] != 2: _json_error("must equal 2", "$.schema_version")
    _string(root["campaign_id"], "$.campaign_id")
    if root["protocol_id"] != "host-boundary-v2": _json_error("must equal host-boundary-v2", "$.protocol_id")
    profiles = _strings(root["resolved_profiles"], "$.resolved_profiles", nonempty=True, unique=True)
    for index, ref in enumerate(profiles):
        if Path(ref).is_absolute(): _json_error("must be a relative path", f"$.resolved_profiles[{index}]")
    _typed(root["dependencies"], dict, "$.dependencies")
    for rq, deps in root["dependencies"].items(): _string(rq, "$.dependencies key"); _strings(deps, f"$.dependencies.{rq}", unique=True)
    execution = _obj(root["execution"], "$.execution", required={"global_max_workers", "per_provider_max_workers", "stop_on_integrity_failure"})
    _integer(execution["global_max_workers"], "$.execution.global_max_workers", minimum=1)
    _typed(execution["per_provider_max_workers"], dict, "$.execution.per_provider_max_workers")
    for provider, count in execution["per_provider_max_workers"].items(): _string(provider, "$.execution.per_provider_max_workers key"); _integer(count, f"$.execution.per_provider_max_workers.{provider}", minimum=1)
    _bool(execution["stop_on_integrity_failure"], "$.execution.stop_on_integrity_failure")


def _validate_model_ladder(value: Any) -> None:
    root = _obj(value, "$", required={"schema_version", "policy", "ordered_models", "switch_triggers", "non_switch_triggers", "rules"})
    if root["schema_version"] != 1: _json_error("must equal 1", "$.schema_version")
    if root["policy"] != "model_stratified_fallback_never_pool_within_run": _json_error("unexpected model fallback policy", "$.policy")
    rows = _list(root["ordered_models"], "$.ordered_models", nonempty=True)
    models: list[str] = []
    roles: list[str] = []
    for index, item in enumerate(rows):
        path = f"$.ordered_models[{index}]"; row = _obj(item, path, required={"model", "reasoning_effort", "role"})
        _string(row["model"], f"{path}.model"); models.append(row["model"])
        _string(row["reasoning_effort"], f"{path}.reasoning_effort")
        _string(row["role"], f"{path}.role"); roles.append(row["role"])
    if len(set(models)) != len(models): _json_error("model IDs must be unique", "$.ordered_models")
    if len(set(roles)) != len(roles): _json_error("roles must be unique", "$.ordered_models")
    if roles[0] != "primary": _json_error("first model role must be primary", "$.ordered_models[0].role")
    switch = set(_strings(root["switch_triggers"], "$.switch_triggers", nonempty=True, unique=True))
    non_switch = set(_strings(root["non_switch_triggers"], "$.non_switch_triggers", nonempty=True, unique=True))
    if switch & non_switch: _json_error("switch and non-switch trigger sets must be disjoint", "$")
    _strings(root["rules"], "$.rules", nonempty=True, unique=True)


def _validate_taskpack_manifest(value: Any) -> None:
    root = _obj(value, "$", required={"schema_version", "pack_id", "title", "origin", "claim_eligible", "upstream", "transformation", "fixtures", "task_count", "cluster_count", "splits"})
    if root["schema_version"] != 2: _json_error("must equal 2", "$.schema_version")
    _string(root["pack_id"], "$.pack_id"); _string(root["title"], "$.title")
    _enum(root["origin"], {item.value for item in TaskOrigin}, "$.origin"); _bool(root["claim_eligible"], "$.claim_eligible")
    if root["origin"] == TaskOrigin.AUTHORED_SYNTHETIC and root["claim_eligible"]: _json_error("synthetic packs cannot be claim eligible", "$.claim_eligible")
    upstream = _obj(root["upstream"], "$.upstream", required={"name", "url", "version_or_commit", "license", "retrieved_at", "raw_files"})
    for key in ("name", "url", "version_or_commit", "license"): _string(upstream[key], f"$.upstream.{key}")
    _timestamp(upstream["retrieved_at"], "$.upstream.retrieved_at")
    raw_files = _list(upstream["raw_files"], "$.upstream.raw_files", nonempty=True)
    for index, item in enumerate(raw_files):
        row = _obj(item, f"$.upstream.raw_files[{index}]", required={"path", "sha256"}); _string(row["path"], f"$.upstream.raw_files[{index}].path"); _sha(row["sha256"], f"$.upstream.raw_files[{index}].sha256")
    transform = _obj(root["transformation"], "$.transformation", required={"script_path", "script_sha256", "parameters", "tasks_sha256"})
    _string(transform["script_path"], "$.transformation.script_path"); _sha(transform["script_sha256"], "$.transformation.script_sha256"); _typed(transform["parameters"], dict, "$.transformation.parameters"); _sha(transform["tasks_sha256"], "$.transformation.tasks_sha256")
    fixtures = _list(root["fixtures"], "$.fixtures")
    for index, item in enumerate(fixtures):
        row = _obj(item, f"$.fixtures[{index}]", required={"path", "sha256"}); _string(row["path"], f"$.fixtures[{index}].path"); _sha(row["sha256"], f"$.fixtures[{index}].sha256")
    _integer(root["task_count"], "$.task_count", minimum=0); _integer(root["cluster_count"], "$.cluster_count", minimum=0)
    _typed(root["splits"], dict, "$.splits")
    if set(root["splits"]) != {"gate", "formal"}: _json_error("must contain exactly gate and formal", "$.splits")
    _integer(root["splits"]["gate"], "$.splits.gate", minimum=0); _integer(root["splits"]["formal"], "$.splits.formal", minimum=0)


def _validate_conditions_registry(value: Any) -> None:
    root = _obj(value, "$", required={"conditions"})
    rows = _list(root["conditions"], "$.conditions", nonempty=True)
    for index, item in enumerate(rows):
        path = f"$.conditions[{index}]"; row = _obj(item, path, required={"condition_id", "admission_level", "host_surface_level", "state_surface_level", "enabled_mechanisms", "disabled_mechanisms", "parameters"})
        for key in ("condition_id", "admission_level", "host_surface_level", "state_surface_level"): _string(row[key], f"{path}.{key}")
        _strings(row["enabled_mechanisms"], f"{path}.enabled_mechanisms", unique=True); _strings(row["disabled_mechanisms"], f"{path}.disabled_mechanisms", unique=True); _typed(row["parameters"], dict, f"{path}.parameters")


def _validate_episode_record(value: Any) -> None:
    root = _obj(
        value,
        "$",
        required={
            "schema_version", "episode_id", "schedule_ordinal", "wave_id", "block_id",
            "profile_id", "replicate_id", "taskpack_id", "task_id", "cluster_id",
            "family", "domain_id", "pair_id", "pair_role", "condition_id",
            "planner_role", "attempt_keys", "planner_status", "failure_class",
            "actions_requested", "action_log", "event_log", "initial_snapshot_sha256",
            "final_snapshot_sha256", "final_artifact", "oracle_result", "started_at",
            "finished_at", "execution_session_id", "worker_id",
        },
        optional={
            "task_family", "domain", "protocol_id",
            "construct_id", "proposal_alignment", "legacy_experiment_id",
            "legacy_analysis_family", "answers_canonical_proposal_rq2",
            "pooling_with_semantic_rq2_permitted", "execution_stage",
            "protocol_stage", "h_ladder_covered",
            "scientific_sample_gate_satisfied", "planner_terminal_kind",
            "planner_terminal_strategy", "legacy_explicit_abstention",
            "attack_process", "visible_context_profile", "execution_track",
            "fixed_trace_requests", "fixed_trace_semantic_sha256",
        },
    )
    if root["schema_version"] != 2:
        _json_error("must equal 2", "$.schema_version")
    _sha(root["episode_id"], "$.episode_id")
    _integer(root["schedule_ordinal"], "$.schedule_ordinal", minimum=1)
    for key in (
        "wave_id", "block_id", "profile_id", "replicate_id", "taskpack_id",
        "task_id", "cluster_id", "family", "domain_id", "pair_id", "pair_role",
        "condition_id", "planner_role", "planner_status", "execution_session_id",
        "worker_id",
    ):
        _string(root[key], f"$.{key}")
    if "task_family" in root:
        _string(root["task_family"], "$.task_family")
        if root["task_family"] != root["family"]:
            _json_error("must equal family", "$.task_family")
    if "domain" in root:
        _string(root["domain"], "$.domain")
        if root["domain"] != root["domain_id"]:
            _json_error("must equal domain_id", "$.domain")
    _enum(root["failure_class"], {item.value for item in FailureClass}, "$.failure_class")
    if "protocol_id" in root:
        _enum(
            root["protocol_id"],
            {"host-boundary-v2", "host-boundary-v2.1"},
            "$.protocol_id",
        )
    identity_fields = _V21_PROFILE_CONTRACT_FIELDS - {
        "execution_stage",
        "protocol_stage",
        "h_ladder_covered",
        "scientific_sample_gate_satisfied",
    }
    present_identity = set(root) & identity_fields
    if root.get("protocol_id") == "host-boundary-v2.1" or present_identity:
        missing = _V21_PROFILE_CONTRACT_FIELDS - set(root)
        if missing:
            _json_error(
                f"v2.1 episode contract is incomplete: {sorted(missing)}",
                "$",
            )
        expected_identity = {
            "construct_id": "host_mediated_capability_exploitation",
            "proposal_alignment": "RQ1b_host_mediated",
            "legacy_experiment_id": "HB-RQ2-HCE",
            "legacy_analysis_family": "RQ2",
            "answers_canonical_proposal_rq2": False,
            "pooling_with_semantic_rq2_permitted": False,
        }
        for key, expected in expected_identity.items():
            if root[key] != expected:
                _json_error(f"must equal {expected!r}", f"$.{key}")
        _enum(root["execution_stage"], _V21_EXECUTION_STAGES, "$.execution_stage")
        if root["protocol_stage"] is not None:
            _enum(root["protocol_stage"], {"G", "S"}, "$.protocol_stage")
        expected_protocol_stage = {
            "protocol_stage_g": "G",
            "protocol_stage_s": "S",
        }.get(root["execution_stage"])
        if root["protocol_stage"] != expected_protocol_stage:
            _json_error(
                f"must equal {expected_protocol_stage!r} for execution_stage",
                "$.protocol_stage",
            )
        _bool(root["h_ladder_covered"], "$.h_ladder_covered")
        _bool(
            root["scientific_sample_gate_satisfied"],
            "$.scientific_sample_gate_satisfied",
        )
        if root["execution_stage"] == "atomic_synthetic_bringup":
            if "visible_context_profile" not in root:
                _json_error(
                    "v2.1 atomic episodes require the selected visible context profile",
                    "$.visible_context_profile",
                )
        if "visible_context_profile" in root:
            _enum(
                root["visible_context_profile"],
                _VISIBLE_CONTEXT_PROFILES,
                "$.visible_context_profile",
            )
    elif "visible_context_profile" in root:
        _json_error(
            "is reserved for host-boundary-v2.1 episodes",
            "$.visible_context_profile",
        )
    if "execution_track" in root:
        _enum(root["execution_track"], _EXECUTION_TRACKS, "$.execution_track")
        selector = root.get("visible_context_profile")
        if selector is not None:
            expected_track = {
                "scripted_route_replay": "fixed_trace_host_replay",
                "objective_aware_adaptive": "adaptive_end_to_end",
            }[selector]
            if root["execution_track"] != expected_track:
                _json_error(
                    f"must equal {expected_track!r} for visible_context_profile",
                    "$.execution_track",
                )
    if "fixed_trace_requests" in root:
        if root.get("execution_track") != "fixed_trace_host_replay":
            _json_error(
                "is permitted only for fixed_trace_host_replay episodes",
                "$.fixed_trace_requests",
            )
        requests = _list(root["fixed_trace_requests"], "$.fixed_trace_requests")
        for index, request_value in enumerate(requests):
            path = f"$.fixed_trace_requests[{index}]"
            if not isinstance(request_value, dict):
                _json_error("must be an object", path)
            kind = request_value.get("kind")
            expected_fields = (
                {"turn", "kind", "op", "args"}
                if kind == "action"
                else {"turn", "kind", "transition"}
                if kind == "lifecycle"
                else set()
            )
            if set(request_value) != expected_fields:
                _json_error("has invalid fixed-trace request fields", path)
            _integer(request_value["turn"], f"{path}.turn", minimum=1)
            if kind == "action":
                _string(request_value["op"], f"{path}.op")
                _typed(request_value["args"], dict, f"{path}.args")
            else:
                _string(request_value["transition"], f"{path}.transition")
    if "fixed_trace_semantic_sha256" in root:
        if root.get("execution_track") != "fixed_trace_host_replay":
            _json_error(
                "is permitted only for fixed_trace_host_replay episodes",
                "$.fixed_trace_semantic_sha256",
            )
        _sha(
            root["fixed_trace_semantic_sha256"],
            "$.fixed_trace_semantic_sha256",
        )
    stage_fields = {
        "execution_stage", "protocol_stage", "h_ladder_covered",
        "scientific_sample_gate_satisfied",
    }
    present_stage = set(root) & stage_fields
    if "execution_track" in root and present_stage != stage_fields:
        _json_error(
            "canonical execution-track episodes require the generic stage quartet",
            "$",
        )
    if present_stage and present_stage != stage_fields:
        _json_error("stage fields must be serialized together", "$")
    if present_stage and "execution_track" in root:
        _enum(root["execution_stage"], _V21_EXECUTION_STAGES, "$.execution_stage")
        if root["protocol_stage"] is not None:
            _enum(root["protocol_stage"], {"G", "S"}, "$.protocol_stage")
        expected_protocol_stage = {
            "protocol_stage_g": "G",
            "protocol_stage_s": "S",
        }.get(root["execution_stage"])
        if root["protocol_stage"] != expected_protocol_stage:
            _json_error(
                f"must equal {expected_protocol_stage!r} for execution_stage",
                "$.protocol_stage",
            )
        _bool(root["h_ladder_covered"], "$.h_ladder_covered")
        _bool(
            root["scientific_sample_gate_satisfied"],
            "$.scientific_sample_gate_satisfied",
        )
        allowed_stages = {
            "fixed_trace_host_replay": {
                "atomic_synthetic_bringup",
                "protocol_stage_g",
            },
            "adaptive_end_to_end": {
                "protocol_stage_s",
                "variance_pilot",
                "formal",
            },
        }[root["execution_track"]]
        if root["execution_stage"] not in allowed_stages:
            _json_error(
                "is incompatible with execution_track",
                "$.execution_stage",
            )
    elif present_stage and root.get("protocol_id") != "host-boundary-v2.1":
        if root["execution_stage"] is not None or root["protocol_stage"] is not None:
            _json_error("legacy compatibility stage names must be null", "$")
        _bool(root["h_ladder_covered"], "$.h_ladder_covered")
        _bool(
            root["scientific_sample_gate_satisfied"],
            "$.scientific_sample_gate_satisfied",
        )
        if root["h_ladder_covered"] or root["scientific_sample_gate_satisfied"]:
            _json_error("legacy compatibility gates must normalize to false", "$")
    process_fields = {
        "planner_terminal_kind", "planner_terminal_strategy",
        "legacy_explicit_abstention", "attack_process",
    }
    present_process = set(root) & process_fields
    if root.get("protocol_id") == "host-boundary-v2.1" and present_process != process_fields:
        _json_error("v2.1 episodes require planner process taxonomy fields", "$")
    if present_process and present_process != process_fields:
        _json_error("planner process fields must be serialized together", "$")
    if present_process:
        _enum(
            root["planner_terminal_kind"],
            {item.value for item in PlannerTerminalKind},
            "$.planner_terminal_kind",
        )
        if root["planner_terminal_strategy"] is not None:
            _string(root["planner_terminal_strategy"], "$.planner_terminal_strategy")
        _bool(root["legacy_explicit_abstention"], "$.legacy_explicit_abstention")
        process = _obj(
            root["attack_process"],
            "$.attack_process",
            required={
                "route_relevant_ops_bound", "executable_attempt_count",
                "route_relevant_attempt_count", "allowed_setup_count",
                "trusted_denial_count", "first_denial_turn", "terminal_turn",
                "qualified_host_feedback_witnessed", "host_denial_witnessed",
                "exact_terminal_outcome",
            },
        )
        for key in (
            "route_relevant_ops_bound", "qualified_host_feedback_witnessed",
            "host_denial_witnessed", "exact_terminal_outcome",
        ):
            _bool(process[key], f"$.attack_process.{key}")
        for key in (
            "executable_attempt_count", "route_relevant_attempt_count",
            "allowed_setup_count", "trusted_denial_count", "terminal_turn",
        ):
            _integer(process[key], f"$.attack_process.{key}", minimum=0)
        if process["first_denial_turn"] is not None:
            _integer(
                process["first_denial_turn"],
                "$.attack_process.first_denial_turn",
                minimum=1,
            )
        if process["route_relevant_attempt_count"] > process["executable_attempt_count"]:
            _json_error(
                "cannot exceed executable_attempt_count",
                "$.attack_process.route_relevant_attempt_count",
            )
        if process["allowed_setup_count"] > process["route_relevant_attempt_count"]:
            _json_error(
                "cannot exceed route_relevant_attempt_count",
                "$.attack_process.allowed_setup_count",
            )
        if process["host_denial_witnessed"] is not (
            process["trusted_denial_count"] > 0
        ):
            _json_error(
                "must equal trusted_denial_count > 0",
                "$.attack_process.host_denial_witnessed",
            )
        if (process["first_denial_turn"] is None) is not (
            process["trusted_denial_count"] == 0
        ):
            _json_error(
                "must be null iff trusted_denial_count is zero",
                "$.attack_process.first_denial_turn",
            )
    _strings(root["attempt_keys"], "$.attempt_keys", unique=True)
    for key in ("actions_requested", "action_log", "event_log"):
        _list(root[key], f"$.{key}")
    for key in ("initial_snapshot_sha256", "final_snapshot_sha256"):
        _sha(root[key], f"$.{key}")
    if root["final_artifact"] is not None:
        _typed(root["final_artifact"], dict, "$.final_artifact")
        artifact = root["final_artifact"]
        if artifact.get("artifact_type") == "terminal_text":
            if set(artifact) != {"artifact_type", "text", "source_task_id"}:
                _json_error(
                    "terminal_text must contain exactly artifact_type, text, and source_task_id",
                    "$.final_artifact",
                )
            _string(artifact["text"], "$.final_artifact.text")
            if not artifact["text"].strip():
                _json_error("must be nonempty", "$.final_artifact.text")
            _string(artifact["source_task_id"], "$.final_artifact.source_task_id")
            if artifact["source_task_id"] != root["task_id"]:
                _json_error(
                    "must equal the harness-bound episode task_id",
                    "$.final_artifact.source_task_id",
                )
    _typed(root["oracle_result"], dict, "$.oracle_result")
    oracle_result = root["oracle_result"]
    oracle_boolean_fields = {
        "benign_success", "attack_success", "direct_unauthorized_action",
        "host_capability_exploitation", "composite_unauthorized_outcome",
        "confused_deputy_outcome", "capability_delegation_outcome",
        "proposal_conversion_outcome", "capability_chaining_outcome",
        "cross_tool_composition_outcome", "transformation_laundering_outcome",
        "host_mediated_forbidden_outcome", "exact_host_mediated_attack",
        "canonical_route_reachability", "terminal_state_exploitation",
        "competing_side_effect_detected", "benign_and_attack_both_true",
        "persistence_success", "lineage_laundering",
    }
    oracle_integer_fields = {
        "propagation_numerator", "propagation_denominator", "propagation_depth",
        "off_route_allowed_action_count",
    }
    oracle_nullable_boolean_fields = {
        "post_revocation_residual", "artifact_valid", "artifact_bound_to_event",
    }
    canonical_oracle_boolean_fields = {
        "contribution_utility",
        "host_mediated_unauthorized_action",
        "lifecycle_carryover_outcome",
        "exact_unauthorized_side_effect",
    }
    canonical_oracle_nullable_boolean_fields = {
        "system_task_utility",
        "artifact_task_bound",
        "artifact_event_bound",
    }
    canonical_oracle_fields = (
        canonical_oracle_boolean_fields
        | canonical_oracle_nullable_boolean_fields
    )
    oracle_contract_fields = (
        oracle_boolean_fields
        | oracle_integer_fields
        | oracle_nullable_boolean_fields
        | {"lineage_retention_rate", "evidence"}
    )
    has_oracle_contract = "host_mediated_forbidden_outcome" in oracle_result
    has_canonical_oracle_contract = bool(set(oracle_result) & canonical_oracle_fields)
    if has_canonical_oracle_contract and not has_oracle_contract:
        _json_error(
            "canonical OracleResult fields require the base OracleResult contract",
            "$.oracle_result",
        )
    if (
        root.get("protocol_id") == "host-boundary-v2.1"
        and "runner_error" not in oracle_result
        and not has_oracle_contract
    ):
        _json_error("v2.1 successful episode lacks OracleResult contract", "$.oracle_result")
    if has_oracle_contract:
        missing_oracle = oracle_contract_fields - set(oracle_result)
        if missing_oracle:
            _json_error(
                f"OracleResult contract is incomplete: {sorted(missing_oracle)}",
                "$.oracle_result",
            )
        for key in oracle_boolean_fields:
            _bool(oracle_result[key], f"$.oracle_result.{key}")
        for key in oracle_integer_fields:
            _integer(oracle_result[key], f"$.oracle_result.{key}", minimum=0)
        for key in oracle_nullable_boolean_fields:
            if oracle_result[key] is not None:
                _bool(oracle_result[key], f"$.oracle_result.{key}")
        lineage_rate = oracle_result["lineage_retention_rate"]
        if lineage_rate is not None:
            _number(
                lineage_rate,
                "$.oracle_result.lineage_retention_rate",
                minimum=0,
                maximum=1,
            )
        _list(oracle_result["evidence"], "$.oracle_result.evidence")
        if oracle_result["propagation_numerator"] > oracle_result["propagation_denominator"]:
            _json_error(
                "cannot exceed propagation_denominator",
                "$.oracle_result.propagation_numerator",
            )
        components = [
            oracle_result[key]
            for key in (
                "confused_deputy_outcome", "capability_delegation_outcome",
                "proposal_conversion_outcome", "capability_chaining_outcome",
                "cross_tool_composition_outcome",
                "transformation_laundering_outcome",
            )
        ]
        if oracle_result["host_mediated_forbidden_outcome"] is not any(components):
            _json_error(
                "must equal union of six mechanism components",
                "$.oracle_result.host_mediated_forbidden_outcome",
            )
        if oracle_result["terminal_state_exploitation"] is not oracle_result[
            "host_mediated_forbidden_outcome"
        ]:
            _json_error(
                "must equal host_mediated_forbidden_outcome",
                "$.oracle_result.terminal_state_exploitation",
            )
        if oracle_result["benign_and_attack_both_true"] is not (
            oracle_result["benign_success"] and oracle_result["attack_success"]
        ):
            _json_error(
                "must equal benign_success AND attack_success",
                "$.oracle_result.benign_and_attack_both_true",
            )
        if root.get("execution_track") is not None or has_canonical_oracle_contract:
            missing_canonical = canonical_oracle_fields - set(oracle_result)
            if missing_canonical:
                _json_error(
                    "canonical OracleResult contract is incomplete: "
                    f"{sorted(missing_canonical)}",
                    "$.oracle_result",
                )
            for key in canonical_oracle_boolean_fields:
                _bool(oracle_result[key], f"$.oracle_result.{key}")
            for key in canonical_oracle_nullable_boolean_fields:
                if oracle_result[key] is not None:
                    _bool(oracle_result[key], f"$.oracle_result.{key}")
            exact_union = any(
                oracle_result[key]
                for key in (
                    "direct_unauthorized_action",
                    "host_mediated_unauthorized_action",
                    "composite_unauthorized_outcome",
                    "lifecycle_carryover_outcome",
                )
            )
            if oracle_result["exact_unauthorized_side_effect"] is not exact_union:
                _json_error(
                    "must equal canonical direct/host-mediated/composite/lifecycle union",
                    "$.oracle_result.exact_unauthorized_side_effect",
                )
            if oracle_result["contribution_utility"] is not oracle_result[
                "benign_success"
            ]:
                _json_error(
                    "must equal benign_success",
                    "$.oracle_result.contribution_utility",
                )
            if oracle_result["artifact_event_bound"] is not oracle_result[
                "artifact_bound_to_event"
            ]:
                _json_error(
                    "must equal artifact_event_bound compatibility alias",
                    "$.oracle_result.artifact_bound_to_event",
                )
    _timestamp(root["started_at"], "$.started_at")
    _timestamp(root["finished_at"], "$.finished_at")


_VALIDATORS = {
    "profile": lambda value: _validate_profile(value, resolved=False),
    "resolved_profile": lambda value: _validate_profile(value, resolved=True),
    "campaign": _validate_campaign,
    "gate_result": _validate_gate_result,
    "model_ladder": _validate_model_ladder,
    "taskpack_manifest": _validate_taskpack_manifest,
    "conditions_registry": _validate_conditions_registry,
    "episode_record": _validate_episode_record,
}


def validate_json(value: Any, *, schema_name: str) -> None:
    """Validate a known, versioned frozen input schema and reject unknown fields."""

    _check_json_value(value)
    normalized = schema_name.strip().lower().replace("-", "_")
    validator = _VALIDATORS.get(normalized)
    if validator is None:
        raise SchemaError(f"unknown bundled schema {schema_name!r}")
    validator(value)


def profile_stage_contract(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return fail-closed stage fields for new or explicit legacy reads.

    Legacy ``host-boundary-v2`` profiles did not serialize v2.1 stage fields.
    Compatibility consumers receive false gate flags, never an inferred pass.
    New/partial v2.1 objects are validated by :func:`validate_json` before this
    helper is used by writers.
    """

    if not isinstance(value, Mapping):
        raise SchemaError("profile stage contract requires an object")
    # Canonical RQ1 deliberately reuses the generic ``construct_id`` and
    # ``proposal_alignment`` field names but does not adopt the unrelated
    # v2.1/RQ1b stage contract.  Treat it as an explicitly stage-less profile
    # rather than mistaking the two shared identity keys for a partial v2.1
    # object.
    if value.get("construct_id") == _CANONICAL_RQ1_PROFILE_IDENTITY["construct_id"]:
        missing_identity = _CANONICAL_RQ1_PROFILE_FIELDS - set(value)
        if missing_identity:
            raise SchemaError(
                "partial canonical RQ1 identity is forbidden; missing "
                f"{sorted(missing_identity)}"
            )
        missing_stage = _GENERIC_STAGE_FIELDS - set(value)
        if missing_stage:
            raise SchemaError(
                "canonical RQ1 executable stage contract is incomplete; missing "
                f"{sorted(missing_stage)}"
            )
        return {
            "execution_stage": value["execution_stage"],
            "protocol_stage": value["protocol_stage"],
            "h_ladder_covered": value["h_ladder_covered"],
            "scientific_sample_gate_satisfied": value[
                "scientific_sample_gate_satisfied"
            ],
            "legacy_compatibility": False,
        }
    present = set(value) & _V21_PROFILE_CONTRACT_FIELDS
    if not present:
        if value.get("protocol_id") != "host-boundary-v2":
            raise SchemaError("only legacy host-boundary-v2 profiles may omit stage fields")
        return {
            "execution_stage": None,
            "protocol_stage": None,
            "h_ladder_covered": False,
            "scientific_sample_gate_satisfied": False,
            "legacy_compatibility": True,
        }
    missing = _V21_PROFILE_CONTRACT_FIELDS - set(value)
    if missing:
        raise SchemaError(
            f"partial v2.1 stage contract is forbidden; missing {sorted(missing)}"
        )
    return {
        "execution_stage": value["execution_stage"],
        "protocol_stage": value["protocol_stage"],
        "h_ladder_covered": value["h_ladder_covered"],
        "scientific_sample_gate_satisfied": value[
            "scientific_sample_gate_satisfied"
        ],
        "legacy_compatibility": False,
    }


def _atomic_write(path: Path, payload: bytes) -> None:
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False) as handle:
            temp_name = handle.name; handle.write(payload); handle.flush(); os.fsync(handle.fileno())
        os.replace(temp_name, path); temp_name = None
    except OSError as exc:
        raise IntegrityError(f"atomic write failed for {path}: {exc}") from exc
    finally:
        if temp_name is not None:
            try: os.unlink(temp_name)
            except FileNotFoundError: pass


def atomic_write_json(path: Path, value: Any) -> None:
    _atomic_write(Path(path), canonical_json_bytes(value))


def atomic_write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    payload_parts: list[bytes] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise SchemaError(f"JSONL row {index} must be an object")
        payload_parts.append(canonical_json_bytes(row) + b"\n")
    _atomic_write(Path(path), b"".join(payload_parts))


__all__ = [
    "FailureClass", "IntegrityError", "PlannerRole", "PlannerTerminalKind",
    "RunKind", "RunState",
    "SchemaError", "TaskOrigin", "atomic_write_json", "atomic_write_jsonl",
    "canonical_json_bytes", "load_json", "sha256_bytes", "sha256_json",
    "profile_stage_contract", "validate_json",
]
