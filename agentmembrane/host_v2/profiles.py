"""Profile, campaign, model-ladder, and frozen identity handling for V2."""

from __future__ import annotations

import copy
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .schema import (
    IntegrityError,
    SchemaError,
    canonical_json_bytes,
    load_json,
    sha256_bytes,
    sha256_json,
    validate_json,
)


_AUTHORIZATION_FIELDS = frozenset(
    {
        "schema_version", "protocol_id", "launch_policy_sha256",
        "rq_coverage_manifest_sha256", "assay_report_path",
        "assay_report_sha256", "authorized_stages", "passed", "reason",
    }
)
_AUTHORIZED_STAGE_FIELDS = frozenset(
    {
        "small_real_api_smoke", "variance_pilot", "formal_paid_gate",
        "large_scale_execution",
    }
)
_G0_BOOTSTRAP_FIELDS = frozenset(
    {
        "schema_version", "protocol_id", "authorization_type", "created_at",
        "authorized", "reason", "profile_path", "profile_sha256",
        "assay_report_path", "assay_report_sha256",
        "controlled_pack_manifest_path", "controlled_pack_manifest_sha256",
        "controlled_pack_content_sha256", "config_artifact_sha256s", "task_ids",
        "families", "model_id", "reasoning_effort", "provider_route_id", "selected_workers",
        "selected_max_inflight_blocks",
    }
)
_RQ2_G0_PROFILE_ID = "host-v2-rq2-lower-cost-g0-gate-template"
_RQ2_G0_TASK_IDS = frozenset(
    f"controlled-g0-m{index}-{role}"
    for index in range(1, 7)
    for role in ("benign", "adversarial")
)
_RQ2_G0_FAMILIES = frozenset(
    {
        "confused_deputy", "capability_delegation",
        "proposal_to_action_conversion", "multi_step_capability_chaining",
        "cross_tool_composition", "internal_transformation_action_laundering",
    }
)


@dataclass(frozen=True)
class Profile:
    raw: dict[str, Any]
    path: Path


@dataclass(frozen=True)
class ResolvedProfile:
    raw: dict[str, Any]
    source_path: Path
    resolved_path: Path | None


@dataclass(frozen=True)
class CampaignSpec:
    raw: dict[str, Any]
    path: Path


@dataclass(frozen=True)
class ModelTier:
    model: str
    reasoning_effort: str
    role: str


@dataclass(frozen=True)
class ModelLadder:
    policy: str
    ordered_models: tuple[ModelTier, ...]
    switch_triggers: frozenset[str]
    non_switch_triggers: frozenset[str]
    rules: tuple[str, ...]
    path: Path
    raw: dict[str, Any]


@dataclass(frozen=True)
class ModelSwitchDecision:
    current_model: str
    trigger: str
    next_model: ModelTier | None
    permitted: bool
    gate_required: bool
    requires_new_run_identity: bool
    may_pool_with_prior_run: bool = False


def load_profile(path: Path) -> Profile:
    path = Path(path).resolve()
    raw = load_json(path)
    validate_json(raw, schema_name="profile")
    return Profile(raw=raw, path=path)


def load_resolved_profile(path: Path) -> ResolvedProfile:
    path = Path(path).resolve()
    raw = load_json(path)
    validate_json(raw, schema_name="resolved_profile")
    return ResolvedProfile(raw=raw, source_path=path, resolved_path=path)


def load_campaign(path: Path) -> CampaignSpec:
    path = Path(path).resolve()
    raw = load_json(path)
    validate_json(raw, schema_name="campaign")
    return CampaignSpec(raw=raw, path=path)


def load_model_ladder(path: Path) -> ModelLadder:
    path = Path(path).resolve()
    raw = load_json(path)
    validate_json(raw, schema_name="model_ladder")
    return ModelLadder(
        policy=raw["policy"],
        ordered_models=tuple(ModelTier(**row) for row in raw["ordered_models"]),
        switch_triggers=frozenset(raw["switch_triggers"]),
        non_switch_triggers=frozenset(raw["non_switch_triggers"]),
        rules=tuple(raw["rules"]),
        path=path,
        raw=raw,
    )


def _contained_profile_ref(profile: Profile | ResolvedProfile, value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise SchemaError(f"{label} must be a nonempty relative path")
    reference = Path(value)
    if reference.is_absolute():
        raise IntegrityError(f"{label} must be a relative path")
    base = profile.path if isinstance(profile, Profile) else profile.source_path
    base_parent = Path(base).resolve().parent
    resolved = (base_parent / reference).resolve()
    repository_roots = [
        parent
        for parent in (base_parent, *base_parent.parents)
        if (parent / "agentmembrane" / "host_v2").is_dir()
        and (parent / "experiments" / "host_boundary_v2").is_dir()
    ]
    if repository_roots:
        try:
            resolved.relative_to(repository_roots[0])
        except ValueError as exc:
            raise IntegrityError(f"{label} escapes the repository root") from exc
    else:
        # Unit/portable config bundles conventionally store profiles one level
        # below their dependency root.  Permit that single contained ascent,
        # while retaining fail-closed behavior for arbitrary escape chains.
        fallback_root = (
            base_parent.parent
            if base_parent.name in {"profiles", "resolved"}
            else base_parent
        )
        try:
            resolved.relative_to(fallback_root)
        except ValueError as exc:
            raise IntegrityError(f"{label} escapes an unrecognized profile root") from exc
    return resolved


def _strict_fields(value: Any, expected: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SchemaError(f"{label} must be an object")
    observed = set(value)
    if observed != set(expected):
        raise SchemaError(
            f"{label} fields invalid: missing={sorted(set(expected) - observed)}, "
            f"unknown={sorted(observed - set(expected))}"
        )
    return value


def validate_provider_launch_authorization(
    profile: Profile | ResolvedProfile,
    *,
    required_stage: str | None = None,
) -> dict[str, Any]:
    """Recompute the three fail-closed provider launch locks.

    This helper has no dependency on runner/campaign and is therefore safe to
    call at every library-level prepare/execute entrypoint.  Missing paths,
    stale hashes, a false readiness manifest, or a false authorization all
    produce ``passed=False``.  No outcome/effect direction is an input.
    """

    raw = profile.raw
    resolution = raw.get("resolution", {})
    if isinstance(resolution, Mapping) and resolution.get("resolution_mode") == "g0_bootstrap":
        return validate_g0_bootstrap_authorization(
            profile,
            selected_workers=int(resolution.get("selected_workers", 0)),
            selected_max_inflight_blocks=int(
                resolution.get("selected_max_inflight_blocks", 0)
            ),
            authorization_path=_contained_profile_ref(
                profile,
                resolution.get("bootstrap_authorization_path"),
                "resolution.bootstrap_authorization_path",
            ),
        )
    if raw.get("run_kind") == "scripted":
        return {
            "passed": True,
            "required_stage": None,
            "checks": {"scripted_zero_provider_path": True},
            "errors": [],
            "not_applicable": True,
        }
    stage = required_stage or (
        "large_scale_execution" if raw.get("run_kind") == "formal"
        else "small_real_api_smoke"
    )
    if stage not in _AUTHORIZED_STAGE_FIELDS:
        raise SchemaError(f"unknown provider launch stage {stage!r}")
    checks: dict[str, bool] = {}
    errors: list[str] = []
    gates = raw.get("gates")
    if not isinstance(gates, Mapping):
        return {
            "passed": False,
            "required_stage": stage,
            "checks": {"authorization_paths_present": False},
            "errors": ["profile has no strict gates object"],
        }
    path_keys = {
        "launch": "launch_policy_path",
        "coverage": "rq_coverage_manifest_path",
        "authorization": "zero_token_authorization_path",
    }
    paths: dict[str, Path] = {}
    try:
        for name, key in path_keys.items():
            paths[name] = _contained_profile_ref(profile, gates.get(key), f"gates.{key}")
        checks["authorization_paths_present"] = True
        launch_bytes = paths["launch"].read_bytes()
        coverage_bytes = paths["coverage"].read_bytes()
        authorization_bytes = paths["authorization"].read_bytes()
        launch = load_json(paths["launch"])
        coverage = load_json(paths["coverage"])
        authorization = _strict_fields(
            load_json(paths["authorization"]), _AUTHORIZATION_FIELDS,
            "zero-token authorization",
        )
        stages = _strict_fields(
            authorization["authorized_stages"], _AUTHORIZED_STAGE_FIELDS,
            "zero-token authorization.authorized_stages",
        )
        assay_path = _contained_profile_ref(
            Profile(raw={}, path=paths["authorization"]),
            authorization["assay_report_path"],
            "zero-token authorization.assay_report_path",
        )
        assay_bytes = assay_path.read_bytes()
        assay = load_json(assay_path)
    except (OSError, SchemaError, IntegrityError, KeyError) as exc:
        checks["authorization_artifacts_load"] = False
        errors.append(f"authorization_artifacts_load: {exc}")
        return {
            "passed": False,
            "required_stage": stage,
            "checks": checks,
            "errors": errors,
        }

    checks.update(
        {
            "authorization_artifacts_load": True,
            "protocol_exact": (
                launch.get("protocol_id") == "host-boundary-v2"
                and coverage.get("protocol_id") == "host-boundary-v2"
                and authorization.get("protocol_id") == "host-boundary-v2"
            ),
            "launch_policy_hash_bound": (
                authorization.get("launch_policy_sha256") == sha256_bytes(launch_bytes)
            ),
            "coverage_manifest_hash_bound": (
                authorization.get("rq_coverage_manifest_sha256")
                == sha256_bytes(coverage_bytes)
            ),
            "zero_token_assay_hash_bound": (
                authorization.get("assay_report_sha256") == sha256_bytes(assay_bytes)
            ),
            "zero_token_assay_complete": bool(
                assay.get("zero_token") is True
                and assay.get("network_calls") == 0
                and assay.get("proxy_calls") == 0
                and assay.get("construct_integrity", {}).get("passed") is True
                and all(assay.get("rq_exercised", {}).get(rq) is True for rq in ("RQ1", "RQ2", "RQ3", "RQ4"))
            ),
            "coverage_paid_gate_ready": coverage.get("eligible_for_paid_model_gate") is True,
            "coverage_components_ready": coverage.get("all_required_components_ready") is True,
            "authorization_declared_pass": authorization.get("passed") is True,
            "authorization_stage_permitted": stages.get(stage) is True,
            "launch_policy_manual_override_forbidden": launch.get("manual_override_allowed") is False,
        }
    )
    launch_stage_field = {
        "small_real_api_smoke": "small_real_api_smoke_permitted",
        "variance_pilot": "variance_pilot_permitted",
        "formal_paid_gate": "formal_paid_gate_permitted",
        "large_scale_execution": "large_scale_execution_permitted",
    }[stage]
    checks["launch_policy_stage_permitted"] = launch.get(launch_stage_field) is True
    if stage in {"formal_paid_gate", "large_scale_execution"}:
        checks.update(
            {
                "coverage_formal_ready": coverage.get("eligible_for_formal_run") is True,
                "coverage_claim_data_ready": coverage.get("all_claim_bearing_rqs_have_real_data") is True,
                "launch_formal_run_permitted": launch.get("formal_run_permitted") is True,
            }
        )
    for name, passed in checks.items():
        if not passed:
            errors.append(f"{name} failed")
    return {
        "passed": bool(checks) and all(checks.values()),
        "required_stage": stage,
        "checks": checks,
        "errors": errors,
        "artifacts": {
            "launch_policy_path": str(paths["launch"]),
            "rq_coverage_manifest_path": str(paths["coverage"]),
            "zero_token_authorization_path": str(paths["authorization"]),
            "assay_report_path": str(assay_path),
        },
    }


def validate_g0_bootstrap_authorization(
    profile: Profile | ResolvedProfile,
    *,
    selected_workers: int,
    selected_max_inflight_blocks: int,
    authorization_path: Path | None = None,
) -> dict[str, Any]:
    """Authorize only the first exact RQ2 G0/Terra 12-episode calibration.

    This is not a generic manual override and cannot authorize G1, a variance
    pilot, formal execution, another model, or another task selection.
    """

    from .taskpacks import load_taskpack, taskpack_content_sha256

    raw = profile.raw
    checks: dict[str, bool] = {}
    errors: list[str] = []
    if authorization_path is None:
        try:
            authorization_path = _contained_profile_ref(
                profile,
                raw.get("gates", {}).get("g0_bootstrap_authorization_path"),
                "gates.g0_bootstrap_authorization_path",
            )
        except (SchemaError, IntegrityError) as exc:
            return {
                "passed": False,
                "checks": {"bootstrap_authorization_path": False},
                "errors": [str(exc)],
            }
    path = Path(authorization_path).resolve()
    try:
        authorization_bytes = path.read_bytes()
        authorization = _strict_fields(
            load_json(path), _G0_BOOTSTRAP_FIELDS, "G0 bootstrap authorization"
        )
        profile_path = _contained_profile_ref(
            Profile(raw={}, path=path), authorization["profile_path"],
            "bootstrap.profile_path",
        )
        assay_path = _contained_profile_ref(
            Profile(raw={}, path=path), authorization["assay_report_path"],
            "bootstrap.assay_report_path",
        )
        pack_manifest_path = _contained_profile_ref(
            Profile(raw={}, path=path), authorization["controlled_pack_manifest_path"],
            "bootstrap.controlled_pack_manifest_path",
        )
        assay = load_json(assay_path)
        pack = load_taskpack(pack_manifest_path.parent)
    except (OSError, SchemaError, IntegrityError, KeyError) as exc:
        return {
            "passed": False,
            "checks": {"bootstrap_artifacts_load": False},
            "errors": [f"bootstrap_artifacts_load: {exc}"],
        }
    packs = raw.get("taskpacks", [])
    selected_ids = {
        task_id
        for entry in packs if isinstance(entry, Mapping)
        for task_id in (entry.get("task_ids") or [])
    }
    selected_families = {
        family
        for entry in packs if isinstance(entry, Mapping)
        for family in (entry.get("families") or [])
    }
    resolution = raw.get("resolution", {})
    source_path = profile.path if isinstance(profile, Profile) else profile.source_path
    checks.update(
        {
            "bootstrap_artifacts_load": True,
            "authorization_schema": authorization.get("schema_version") == 1,
            "authorization_protocol": authorization.get("protocol_id") == "host-boundary-v2",
            "authorization_type_exact": authorization.get("authorization_type") == "rq2_g0_first_run_only",
            "authorization_declared_true": authorization.get("authorized") is True,
            "exact_profile_id": raw.get("profile_id") == _RQ2_G0_PROFILE_ID,
            "exact_run_scope": (
                raw.get("run_kind") == "gate"
                and raw.get("rq_ids") == ["RQ2"]
                and raw.get("claim_bearing") is False
                and raw.get("gates", {}).get("gate_stage") == "G0"
                and raw.get("condition_ids") == ["A5-C0"]
            ),
            "exact_model": (
                raw.get("model", {}).get("requested_id") == "gpt-5.6-terra"
                and raw.get("model", {}).get("allowed_resolved_ids") == ["gpt-5.6-terra"]
                and authorization.get("model_id") == "gpt-5.6-terra"
                and raw.get("model", {}).get("reasoning_effort") == "medium"
                and authorization.get("reasoning_effort") == "medium"
            ),
            "exact_provider": (
                raw.get("model", {}).get("provider_route_id") == "local-cli-proxy"
                and authorization.get("provider_route_id") == "local-cli-proxy"
            ),
            "exact_controlled_pack": (
                len(packs) == 1
                and packs[0].get("pack_id") == "host-v2-controlled-gates-v2"
                and pack.pack_id == "host-v2-controlled-gates-v2"
                and packs[0].get("split") == "gate"
            ),
            "exact_12_task_ids": (
                selected_ids == _RQ2_G0_TASK_IDS
                and set(authorization.get("task_ids", [])) == _RQ2_G0_TASK_IDS
                and len(authorization.get("task_ids", [])) == 12
            ),
            "exact_six_families": (
                selected_families == _RQ2_G0_FAMILIES
                and set(authorization.get("families", [])) == _RQ2_G0_FAMILIES
            ),
            "exact_concurrency": (
                selected_workers == authorization.get("selected_workers") == 12
                and selected_max_inflight_blocks
                == authorization.get("selected_max_inflight_blocks") == 6
                and raw.get("execution", {}).get("worker_candidates") == [12]
                and raw.get("execution", {}).get("max_inflight_block_candidates") == [6]
                and selected_workers in raw.get("execution", {}).get("worker_candidates", [])
                and selected_max_inflight_blocks
                in raw.get("execution", {}).get("max_inflight_block_candidates", [])
            ),
            "profile_path_exact": (
                True
                if isinstance(profile, ResolvedProfile)
                else profile_path.resolve() == Path(source_path).resolve()
            ),
            "profile_hash_bound": (
                authorization.get("profile_sha256") == sha256_bytes(profile_path.read_bytes())
            ),
            "assay_hash_bound": (
                authorization.get("assay_report_sha256") == sha256_bytes(assay_path.read_bytes())
            ),
            "pack_manifest_hash_bound": (
                authorization.get("controlled_pack_manifest_sha256")
                == sha256_bytes(pack_manifest_path.read_bytes())
            ),
            "pack_content_hash_bound": (
                authorization.get("controlled_pack_content_sha256")
                == taskpack_content_sha256(pack)
            ),
            "full_zero_token_assay_pass": bool(
                assay.get("assay_scope")
                == "rq2_full_registered_local_mechanism_and_pipeline_matrix"
                and assay.get("plumbing_checks_passed") is True
                and assay.get("construct_integrity", {}).get("passed") is True
                and assay.get("integration", {}).get("passed") is True
                and assay.get("planner_counters", {}).get("provider_calls") == 0
                and assay.get("proxy_calls") == 0
                and assay.get("small_real_api_smoke_go") is True
                and assay.get("rq_exercised", {}).get("RQ2") is True
                and assay.get("controlled_gate_stages", {}).get("G0") is True
                and assay.get("controlled_gate_stages", {}).get("G1") is True
                and assay.get("controlled_gate_stages", {}).get("G2") is True
                and assay.get("rq2_family_count") == 6
                and assay.get("rq2_twins_complete") is True
                and assay.get("runner_oracle_analysis_pipeline_passed") is True
            ),
        }
    )
    config_hashes = authorization.get("config_artifact_sha256s")
    config_valid = isinstance(config_hashes, Mapping) and bool(config_hashes)
    if config_valid:
        for relative, digest in config_hashes.items():
            try:
                artifact = _contained_profile_ref(
                    Profile(raw={}, path=path), relative,
                    f"bootstrap.config_artifact_sha256s[{relative!r}]",
                )
                if not isinstance(digest, str) or sha256_bytes(artifact.read_bytes()) != digest:
                    config_valid = False
                    break
            except (OSError, SchemaError, IntegrityError):
                config_valid = False
                break
    checks["config_artifacts_hash_bound"] = config_valid
    if isinstance(profile, ResolvedProfile):
        checks["resolved_bootstrap_hash_bound"] = (
            isinstance(resolution, Mapping)
            and resolution.get("resolution_mode") == "g0_bootstrap"
            and resolution.get("bootstrap_authorization_sha256")
            == sha256_bytes(authorization_bytes)
        )
    for name, passed in checks.items():
        if not passed:
            errors.append(f"{name} failed")
    return {
        "passed": bool(checks) and all(checks.values()),
        "checks": checks,
        "errors": errors,
        "authorization_path": str(path),
        "authorization_sha256": sha256_bytes(authorization_bytes),
        "scope": "rq2_g0_first_run_only",
    }


def validate_estimand_cell_coverage(
    profile: Profile | ResolvedProfile,
) -> dict[str, Any]:
    """Prove the frozen task selection covers every estimand arm/family/role cell.

    G0/G1 are deliberately narrower provider gates and instead require exactly
    six complete twins (12 explicit task IDs).  G2 and formal profiles must
    cover the complete selected estimand grid.  Conditions are crossed by the
    schedule, so condition presence is checked against the profile registry;
    family/role pairing is checked against the selected raw task records.
    """

    from .analysis import load_estimands
    from .taskpacks import load_taskpack, select_tasks

    errors: list[str] = []
    selected_tasks: list[Any] = []
    selected_ids: list[str] = []
    try:
        for entry in profile.raw["taskpacks"]:
            root = _resolve_ref(
                profile.path if isinstance(profile, Profile) else profile.source_path,
                entry["root"],
            )
            pack = load_taskpack(root)
            ids = entry.get("task_ids")
            if profile.raw.get("run_kind") == "gate" and ids is None:
                raise IntegrityError("gate profile task_ids=null/all is forbidden")
            tasks = select_tasks(
                pack,
                split=entry["split"],
                families=frozenset(entry["families"]),
                task_ids=None if ids is None else frozenset(ids),
            )
            selected_tasks.extend(tasks)
            selected_ids.extend(task.task_id for task in tasks)
    except (OSError, SchemaError, IntegrityError, KeyError) as exc:
        return {
            "passed": False,
            "checks": {"task_selection_load": False},
            "errors": [f"task_selection_load: {exc}"],
            "missing_cells": [],
        }

    checks: dict[str, bool] = {
        "task_selection_load": True,
        "task_ids_unique": len(selected_ids) == len(set(selected_ids)),
    }
    gate_stage = profile.raw.get("gates", {}).get("gate_stage")
    if profile.raw.get("run_kind") == "gate" and gate_stage in {"G0", "G1"}:
        pair_roles: dict[str, set[str]] = {}
        for task in selected_tasks:
            pair_roles.setdefault(task.pair_id, set()).add(task.pair_role)
        checks.update(
            {
                "exact_12_gate_tasks": len(selected_tasks) == 12,
                "exact_6_gate_twins": (
                    len(pair_roles) == 6
                    and all(roles == {"benign", "adversarial"} for roles in pair_roles.values())
                ),
            }
        )
        for name, passed in checks.items():
            if not passed:
                errors.append(f"{name} failed")
        return {
            "passed": all(checks.values()),
            "checks": checks,
            "errors": errors,
            "missing_cells": [],
            "selected_task_count": len(selected_tasks),
            "gate_stage": gate_stage,
        }

    try:
        registry = load_estimands(
            _resolve_ref(
                profile.path if isinstance(profile, Profile) else profile.source_path,
                profile.raw["estimands_path"],
            )
        )
        selected_estimands = [registry[name] for name in profile.raw["estimand_ids"]]
    except (OSError, SchemaError, IntegrityError, KeyError) as exc:
        checks["estimand_registry_load"] = False
        errors.append(f"estimand_registry_load: {exc}")
        return {
            "passed": False,
            "checks": checks,
            "errors": errors,
            "missing_cells": [],
        }
    checks["estimand_registry_load"] = True
    conditions = set(profile.raw["condition_ids"])
    family_pairs: dict[str, dict[str, set[str]]] = {}
    for task in selected_tasks:
        family = task.family
        by_pair = family_pairs.setdefault(family, {})
        by_pair.setdefault(task.pair_id, set()).add(task.pair_role)
    missing_cells: list[str] = []
    for estimand in selected_estimands:
        for condition_id in (*estimand.left_conditions, *estimand.right_conditions):
            if condition_id not in conditions:
                for family in estimand.task_families:
                    for role in ("benign", "adversarial"):
                        missing_cells.append(
                            f"{estimand.estimand_id}|{condition_id}|{family}|{role}|condition_absent"
                        )
                continue
            for family in estimand.task_families:
                pairs = family_pairs.get(family, {})
                complete = any(
                    {"benign", "adversarial"} <= roles for roles in pairs.values()
                )
                if not complete:
                    missing_cells.extend(
                        f"{estimand.estimand_id}|{condition_id}|{family}|{role}|unpaired"
                        for role in ("benign", "adversarial")
                    )
    checks["every_estimand_condition_family_role_cell_nonempty_paired"] = not missing_cells
    for name, passed in checks.items():
        if not passed:
            errors.append(f"{name} failed")
    return {
        "passed": all(checks.values()),
        "checks": checks,
        "errors": errors,
        "missing_cells": missing_cells,
        "selected_task_count": len(selected_tasks),
        "gate_stage": gate_stage,
    }


def plan_model_switch(
    ladder: ModelLadder,
    *,
    current_model: str,
    trigger: str,
    gate_passed_model_ids: frozenset[str] = frozenset(),
) -> ModelSwitchDecision:
    """Plan only predeclared quota/availability fallbacks, never result-driven ones.

    A permitted switch still starts a new model stratum and run identity.  The
    caller must retain an incomplete higher-ranked run rather than pooling it.
    """

    ids = [tier.model for tier in ladder.ordered_models]
    if current_model not in ids:
        raise SchemaError(f"model {current_model!r} is absent from the frozen ladder")
    if trigger in ladder.non_switch_triggers:
        return ModelSwitchDecision(
            current_model=current_model,
            trigger=trigger,
            next_model=None,
            permitted=False,
            gate_required=False,
            requires_new_run_identity=False,
        )
    if trigger not in ladder.switch_triggers:
        raise SchemaError(f"unregistered model-switch trigger {trigger!r}")
    index = ids.index(current_model)
    next_tier = ladder.ordered_models[index + 1] if index + 1 < len(ids) else None
    if next_tier is None:
        return ModelSwitchDecision(
            current_model=current_model,
            trigger=trigger,
            next_model=None,
            permitted=False,
            gate_required=False,
            requires_new_run_identity=False,
        )
    gate_required = next_tier.model not in gate_passed_model_ids
    return ModelSwitchDecision(
        current_model=current_model,
        trigger=trigger,
        next_model=next_tier,
        permitted=not gate_required,
        gate_required=gate_required,
        requires_new_run_identity=True,
    )


def select_fallback_model(
    ladder: ModelLadder,
    *,
    current_model: str,
    trigger: str,
    gate_passed_model_ids: frozenset[str],
) -> ModelTier:
    """Return the immediate next tier only after its own G0/G1/G2 gates pass."""

    decision = plan_model_switch(
        ladder,
        current_model=current_model,
        trigger=trigger,
        gate_passed_model_ids=gate_passed_model_ids,
    )
    if decision.next_model is None:
        raise IntegrityError(
            f"model switch from {current_model!r} is not permitted for {trigger!r}"
        )
    if decision.gate_required:
        raise IntegrityError(
            f"fallback {decision.next_model.model!r} must pass its own G0/G1/G2 gates"
        )
    if not decision.permitted:
        raise IntegrityError("frozen model ladder did not authorize the switch")
    return decision.next_model


def _resolve_ref(source_path: Path, ref: str) -> Path:
    candidate = Path(ref)
    if candidate.is_absolute():
        raise SchemaError(f"profile dependency must be relative: {ref!r}")
    return (source_path.parent / candidate).resolve()


def _taskpack_references(root: Path) -> list[Path]:
    paths = [root / "manifest.json", root / "tasks.jsonl"]
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        return paths
    manifest = load_json(manifest_path)
    validate_json(manifest, schema_name="taskpack_manifest")
    for row in manifest["upstream"]["raw_files"]:
        paths.append((root / row["path"]).resolve())
    paths.append((root / manifest["transformation"]["script_path"]).resolve())
    for row in manifest["fixtures"]:
        paths.append((root / row["path"]).resolve())
    return paths


def referenced_paths(profile: ResolvedProfile) -> tuple[Path, ...]:
    raw = profile.raw
    refs: list[Path] = [profile.source_path.resolve()]
    for key in ("conditions_path", "estimands_path"):
        refs.append(_resolve_ref(profile.source_path, raw[key]))
    for key in ("attacker_prompt_path", "benign_prompt_path"):
        refs.append(_resolve_ref(profile.source_path, raw["planner"][key]))
    refs.append(_resolve_ref(profile.source_path, raw["execution"]["capacity_policy_path"]))
    for key in (
        "launch_policy_path", "rq_coverage_manifest_path",
        "zero_token_authorization_path", "g0_bootstrap_authorization_path",
    ):
        reference = raw.get("gates", {}).get(key)
        if isinstance(reference, str) and reference:
            refs.append(_resolve_ref(profile.source_path, reference))
    for pack in raw["taskpacks"]:
        refs.extend(_taskpack_references(_resolve_ref(profile.source_path, pack["root"])))
    # The dependency ledger stores the gate hash explicitly.
    if "resolution" in raw:
        resolution = raw["resolution"]
        reference = (
            resolution.get("bootstrap_authorization_path")
            if resolution.get("resolution_mode") == "g0_bootstrap"
            else resolution.get("gate_result_path")
        )
        if isinstance(reference, str) and not Path(reference).is_absolute():
            refs.append(_resolve_ref(profile.source_path, reference))
    return tuple(sorted(set(refs), key=lambda item: item.as_posix()))


def validate_profile(
    profile: Profile,
    *,
    claim_bearing: bool,
    public_adapter_registry: Any | None = None,
    public_evidence_bindings: Mapping[str, Mapping[str, Any]] | None = None,
) -> list[str]:
    errors: list[str] = []
    try:
        validate_json(profile.raw, schema_name="profile")
    except SchemaError as exc:
        return [str(exc)]
    if profile.raw["claim_bearing"] is not claim_bearing:
        errors.append(
            f"claim_bearing argument {claim_bearing!r} does not match profile value "
            f"{profile.raw['claim_bearing']!r}"
        )
    if claim_bearing and profile.raw["run_kind"] != "formal":
        errors.append("claim-bearing profiles must use run_kind=formal")

    eligible_real_pack = False
    readiness_failures: list[str] = []
    public_formal_readiness_failures: list[str] = []
    for entry in profile.raw["taskpacks"]:
        root = _resolve_ref(profile.path, entry["root"])
        manifest_path = root / "manifest.json"
        if not manifest_path.is_file():
            errors.append(f"missing task-pack manifest: {manifest_path}")
            continue
        try:
            manifest_bytes = manifest_path.read_bytes()
            if sha256_bytes(manifest_bytes) != entry["manifest_sha256"]:
                errors.append(f"manifest hash mismatch for task pack {entry['pack_id']}")
            manifest = load_json(manifest_path)
            validate_json(manifest, schema_name="taskpack_manifest")
            if manifest["pack_id"] != entry["pack_id"]:
                errors.append(f"pack_id mismatch for {entry['pack_id']}")
            is_public = manifest["origin"] == "public_benchmark"
            public_formal = bool(
                is_public and profile.raw["run_kind"] == "formal"
            )
            candidate_for_population_claim = manifest["claim_eligible"] and manifest["origin"] in {
                "public_benchmark", "real_workflow"
            }
            requires_public_recompute = bool(is_public and (claim_bearing or public_formal))
            if requires_public_recompute:
                # A manifest declaration is not scientific readiness.  Load and
                # re-verify the complete pack so public adapters, executable
                # checker bindings, parity, mapping, and held-out split evidence
                # are all consumed by the same fail-closed path as execution.
                from .taskpacks import load_taskpack, verify_taskpack

                binding = (
                    public_evidence_bindings.get(entry["pack_id"])
                    if isinstance(public_evidence_bindings, Mapping)
                    else None
                )
                evidence_root: Path | None = None
                evidence_sha: str | None = None
                if binding is None:
                    errors.append(
                        "public formal/claim profile lacks an explicit evidence root/hash "
                        f"binding for {entry['pack_id']}"
                    )
                elif set(binding) != {"root", "manifest_sha256"}:
                    errors.append(
                        f"invalid public evidence binding fields for {entry['pack_id']}"
                    )
                else:
                    raw_root = binding.get("root")
                    raw_sha = binding.get("manifest_sha256")
                    if isinstance(raw_root, (str, Path)):
                        evidence_root = Path(raw_root)
                    if evidence_root is None or not evidence_root.is_absolute():
                        errors.append(
                            f"public evidence root must be absolute for {entry['pack_id']}"
                        )
                        evidence_root = None
                    if isinstance(raw_sha, str):
                        evidence_sha = raw_sha
                    else:
                        errors.append(
                            f"public evidence manifest hash missing for {entry['pack_id']}"
                        )
                if public_adapter_registry is None:
                    errors.append(
                        "public formal/claim profile lacks an explicit live adapter registry "
                        f"for {entry['pack_id']}"
                    )
                use_explicit = bool(
                    evidence_root is not None
                    and evidence_sha is not None
                    and public_adapter_registry is not None
                )
                pack = load_taskpack(
                    root,
                    public_adapter_registry=(public_adapter_registry if use_explicit else None),
                    public_evidence_root=(evidence_root if use_explicit else None),
                    public_evidence_manifest_sha256=(evidence_sha if use_explicit else None),
                )
                report = verify_taskpack(
                    pack,
                    public_adapter_registry=(public_adapter_registry if use_explicit else None),
                    public_evidence_root=(evidence_root if use_explicit else None),
                    public_evidence_manifest_sha256=(evidence_sha if use_explicit else None),
                )
                if report["population_claim_eligible"] is True and candidate_for_population_claim:
                    eligible_real_pack = True
                else:
                    readiness = report.get("public_readiness")
                    blocker_codes = (
                        readiness.get("blocker_codes", [])
                        if isinstance(readiness, Mapping)
                        else []
                    )
                    detail = ",".join(str(code) for code in blocker_codes) or "not verified"
                    failure = f"{entry['pack_id']} ({detail})"
                    readiness_failures.append(failure)
                    if public_formal:
                        public_formal_readiness_failures.append(failure)
            elif claim_bearing and candidate_for_population_claim:
                # Non-public real-workflow packs retain their existing
                # structural population-readiness path.
                from .taskpacks import load_taskpack, verify_taskpack

                pack = load_taskpack(root)
                report = verify_taskpack(pack)
                if report["population_claim_eligible"] is True:
                    eligible_real_pack = True
        except (OSError, SchemaError, IntegrityError) as exc:
            errors.append(f"invalid task pack {entry['pack_id']}: {exc}")
    if public_formal_readiness_failures:
        errors.append(
            "public formal profile requires recomputed executable readiness: "
            + "; ".join(public_formal_readiness_failures)
        )
    if claim_bearing and not eligible_real_pack:
        detail = f": {'; '.join(readiness_failures)}" if readiness_failures else ""
        errors.append(
            "claim-bearing profile has no verified population-claim-eligible "
            f"public or real-workflow task pack{detail}"
        )

    required_refs = [
        profile.raw["conditions_path"],
        profile.raw["estimands_path"],
        profile.raw["planner"]["attacker_prompt_path"],
        profile.raw["planner"]["benign_prompt_path"],
        profile.raw["execution"]["capacity_policy_path"],
    ]
    for ref in required_refs:
        path = _resolve_ref(profile.path, ref)
        if not path.is_file():
            errors.append(f"missing profile dependency: {path}")
    return errors


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def implementation_sha256(repository_root: Path | None = None) -> str:
    """Hash POSIX path, byte length, and bytes of every mandated source file."""

    root = Path(repository_root).resolve() if repository_root is not None else _repository_root()
    package = root / "agentmembrane" / "host_v2"
    files = sorted(package.rglob("*.py"), key=lambda path: path.relative_to(root).as_posix())
    proxy = root / "agentmembrane" / "proxy.py"
    if proxy.is_file():
        files.append(proxy)
    files = sorted(set(files), key=lambda path: path.relative_to(root).as_posix())
    if not files:
        raise IntegrityError(f"no V2 implementation files under {package}")
    digest = __import__("hashlib").sha256()
    for path in files:
        try:
            relative = path.relative_to(root).as_posix().encode("utf-8")
            payload = path.read_bytes()
        except (OSError, ValueError) as exc:
            raise IntegrityError(f"cannot hash implementation file {path}: {exc}") from exc
        digest.update(len(relative).to_bytes(8, "big")); digest.update(relative)
        digest.update(len(payload).to_bytes(8, "big")); digest.update(payload)
    return digest.hexdigest()


def _portable_dependency_path(path: Path, *, source_path: Path) -> str:
    return Path(os.path.relpath(path, source_path.parent)).as_posix()


def _dependency_hashes(source: Profile, extra_path: Path) -> list[dict[str, str]]:
    pseudo = ResolvedProfile(raw=source.raw, source_path=source.path, resolved_path=None)
    paths = [path for path in referenced_paths(pseudo) if path != source.path]
    paths.append(extra_path.resolve())
    rows: list[dict[str, str]] = []
    for path in sorted(set(paths), key=lambda item: _portable_dependency_path(item, source_path=source.path)):
        if not path.is_file():
            raise IntegrityError(f"missing protocol dependency: {path}")
        rows.append({
            "path": _portable_dependency_path(path, source_path=source.path),
            "sha256": sha256_bytes(path.read_bytes()),
        })
    return rows


def _protocol_ledger(raw: Mapping[str, Any]) -> dict[str, Any]:
    resolved = copy.deepcopy(dict(raw))
    resolution = resolved.get("resolution")
    if not isinstance(resolution, dict):
        raise SchemaError("protocol hash requires a resolved profile")
    resolution.pop("protocol_sha256", None)
    # The exact gate/dependency content hashes remain; local path and wall time do not.
    resolution.pop("resolved_at", None)
    resolution.pop("gate_result_path", None)
    resolution.pop("bootstrap_authorization_path", None)
    return {"hash_contract_version": 1, "resolved_profile": resolved}


def protocol_sha256(profile: ResolvedProfile | Mapping[str, Any]) -> str:
    raw = profile.raw if isinstance(profile, ResolvedProfile) else dict(profile)
    return sha256_json(_protocol_ledger(raw))


def run_identity_sha256(
    *,
    protocol_sha256_value: str,
    implementation_sha256_value: str,
    schedule_sha256_value: str,
    requested_model_id: str,
    resolved_model_id: str,
    provider_route_id: str,
    request_parameters: Mapping[str, Any],
    selected_workers: int,
    selected_max_inflight_blocks: int,
) -> str:
    for name, value in (
        ("protocol_sha256", protocol_sha256_value),
        ("implementation_sha256", implementation_sha256_value),
        ("schedule_sha256", schedule_sha256_value),
    ):
        if len(value) != 64 or value.lower() != value or any(ch not in "0123456789abcdef" for ch in value):
            raise SchemaError(f"{name} must be a lowercase SHA-256 hex string")
    if isinstance(selected_workers, bool) or not isinstance(selected_workers, int) or selected_workers < 1:
        raise SchemaError("selected_workers must be a positive integer")
    if isinstance(selected_max_inflight_blocks, bool) or not isinstance(selected_max_inflight_blocks, int) or selected_max_inflight_blocks < 1:
        raise SchemaError("selected_max_inflight_blocks must be a positive integer")
    return sha256_json({
        "protocol_sha256": protocol_sha256_value,
        "implementation_sha256": implementation_sha256_value,
        "schedule_sha256": schedule_sha256_value,
        "requested_model_id": requested_model_id,
        "resolved_model_id": resolved_model_id,
        "provider_route_id": provider_route_id,
        "request_parameters": dict(request_parameters),
        "selected_workers": selected_workers,
        "selected_max_inflight_blocks": selected_max_inflight_blocks,
    })


def resolve_profile(
    profile: Profile,
    *,
    selected_workers: int,
    selected_max_inflight_blocks: int,
    gate_result_path: Path,
) -> ResolvedProfile:
    errors = validate_profile(profile, claim_bearing=bool(profile.raw.get("claim_bearing")))
    if errors:
        raise SchemaError("profile validation failed: " + "; ".join(errors))
    gate_path = Path(gate_result_path).resolve()
    gate = load_json(gate_path)
    validate_json(gate, schema_name="gate_result")
    if gate["schema_version"] not in {3, 4} and profile.raw.get("run_kind") != "scripted":
        raise IntegrityError("all provider-consuming gate resolutions require raw-bound V3/V4")
    if not gate["passed"]:
        raise IntegrityError("gate result did not pass")
    if gate["profile_id"] != profile.raw["profile_id"]:
        raise IntegrityError("gate result belongs to a different profile")
    selected_pair = (selected_workers, selected_max_inflight_blocks)
    if selected_pair != (gate["selected_workers"], gate["selected_max_inflight_blocks"]):
        raise IntegrityError("selected concurrency differs from the frozen gate selection")
    if selected_workers not in profile.raw["execution"]["worker_candidates"]:
        raise SchemaError("selected_workers is not a predeclared candidate")
    if selected_max_inflight_blocks not in profile.raw["execution"]["max_inflight_block_candidates"]:
        raise SchemaError("selected_max_inflight_blocks is not a predeclared candidate")
    if gate["schema_version"] == 4:
        if (
            profile.raw.get("run_kind") != "gate"
            or profile.raw.get("claim_bearing") is not False
            or profile.raw.get("gates", {}).get("gate_stage") != "G2"
        ):
            raise IntegrityError("raw-bound V4 is reserved for the non-claim G2 gate")
        declared = {
            (workers, blocks)
            for workers in profile.raw["execution"]["worker_candidates"]
            for blocks in profile.raw["execution"]["max_inflight_block_candidates"]
        }
        if not declared or selected_pair != max(declared):
            raise IntegrityError("selection is not the highest predeclared G2 concurrency")
        if len(gate["predecessor_runs"]) != 2 or not all(
            row["passed"] for row in gate["predecessor_runs"]
        ):
            raise IntegrityError("both raw G0/G1 predecessor runs must declare pass")
    else:
        candidates = {
            (row["workers"], row["max_inflight_blocks"]): row
            for row in gate["candidate_results"]
        }
        selected_row = candidates.get(selected_pair)
        if selected_row is None or not selected_row["passed"]:
            raise IntegrityError("selected concurrency candidate did not pass its gates")
        passed_declared = [
            pair for pair, row in candidates.items()
            if row["passed"]
            and pair[0] in profile.raw["execution"]["worker_candidates"]
            and pair[1] in profile.raw["execution"]["max_inflight_block_candidates"]
        ]
        if not passed_declared or selected_pair != max(passed_declared):
            raise IntegrityError("selection is not the highest predeclared passing candidate")

    raw = copy.deepcopy(profile.raw)
    resolved_model = raw["model"]["requested_id"]
    if resolved_model not in raw["model"]["allowed_resolved_ids"]:
        raise IntegrityError("requested model is absent from allowed_resolved_ids")
    implementation = implementation_sha256()
    raw["resolution"] = {
        "resolved_at": gate["created_at"],
        "resolution_mode": "gate_result",
        "gate_result_path": _portable_dependency_path(gate_path, source_path=profile.path),
        "gate_result_sha256": sha256_bytes(gate_path.read_bytes()),
        "selected_workers": selected_workers,
        "selected_max_inflight_blocks": selected_max_inflight_blocks,
        "resolved_model_id": resolved_model,
        "provider_route_id": raw["model"]["provider_route_id"],
        "dependency_hashes": _dependency_hashes(profile, gate_path),
        "implementation_sha256": implementation,
        "protocol_sha256": "0" * 64,
    }
    provisional = ResolvedProfile(raw=raw, source_path=profile.path, resolved_path=None)
    raw["resolution"]["protocol_sha256"] = protocol_sha256(provisional)
    validate_json(raw, schema_name="resolved_profile")
    return ResolvedProfile(raw=raw, source_path=profile.path, resolved_path=None)


def resolve_g0_bootstrap_profile(
    profile: Profile,
    *,
    selected_workers: int,
    selected_max_inflight_blocks: int,
    authorization_path: Path,
) -> ResolvedProfile:
    """Resolve the one narrow first-run RQ2 G0 profile without a real gate result."""

    errors = validate_profile(profile, claim_bearing=False)
    if errors:
        raise SchemaError("profile validation failed: " + "; ".join(errors))
    authorization = Path(authorization_path).resolve()
    report = validate_g0_bootstrap_authorization(
        profile,
        selected_workers=selected_workers,
        selected_max_inflight_blocks=selected_max_inflight_blocks,
        authorization_path=authorization,
    )
    if not report["passed"]:
        raise IntegrityError("G0 bootstrap authorization STOP: " + "; ".join(report["errors"]))
    raw = copy.deepcopy(profile.raw)
    implementation = implementation_sha256()
    authorization_raw = load_json(authorization)
    raw["resolution"] = {
        "resolved_at": authorization_raw["created_at"],
        "resolution_mode": "g0_bootstrap",
        "bootstrap_authorization_path": _portable_dependency_path(
            authorization, source_path=profile.path
        ),
        "bootstrap_authorization_sha256": sha256_bytes(authorization.read_bytes()),
        "selected_workers": selected_workers,
        "selected_max_inflight_blocks": selected_max_inflight_blocks,
        "resolved_model_id": raw["model"]["requested_id"],
        "provider_route_id": raw["model"]["provider_route_id"],
        "dependency_hashes": _dependency_hashes(profile, authorization),
        "implementation_sha256": implementation,
        "protocol_sha256": "0" * 64,
    }
    provisional = ResolvedProfile(raw=raw, source_path=profile.path, resolved_path=None)
    raw["resolution"]["protocol_sha256"] = protocol_sha256(provisional)
    validate_json(raw, schema_name="resolved_profile")
    return ResolvedProfile(raw=raw, source_path=profile.path, resolved_path=None)


def freeze_profile(profile: ResolvedProfile, output_path: Path) -> str:
    validate_json(profile.raw, schema_name="resolved_profile")
    expected_protocol = protocol_sha256(profile)
    if profile.raw["resolution"]["protocol_sha256"] != expected_protocol:
        raise IntegrityError("resolved profile protocol hash does not recompute")
    payload = canonical_json_bytes(profile.raw)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        if output_path.read_bytes() != payload:
            raise IntegrityError(f"refusing to overwrite unequal frozen profile {output_path}")
        return sha256_bytes(payload)
    try:
        descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload); handle.flush(); os.fsync(handle.fileno())
    except FileExistsError:
        if output_path.read_bytes() != payload:
            raise IntegrityError(f"concurrent unequal freeze at {output_path}")
    except OSError as exc:
        raise IntegrityError(f"cannot freeze resolved profile {output_path}: {exc}") from exc
    return sha256_bytes(payload)


__all__ = [
    "CampaignSpec", "ModelLadder", "ModelSwitchDecision", "ModelTier", "Profile",
    "ResolvedProfile", "freeze_profile", "implementation_sha256", "load_campaign",
    "load_model_ladder", "load_profile", "load_resolved_profile", "plan_model_switch",
    "protocol_sha256", "referenced_paths", "resolve_profile", "resolve_g0_bootstrap_profile",
    "run_identity_sha256",
    "select_fallback_model", "validate_g0_bootstrap_authorization",
    "validate_profile", "validate_provider_launch_authorization",
]
