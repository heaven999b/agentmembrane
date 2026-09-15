"""Offline, fail-closed preflight for the RQ1 adaptive v2.3 overlay.

This module deliberately has no provider client and no executor.  Passing its
preflight means only that the versioned overlay, its immutable legacy
dependencies, and the proposed four-cell engineering contract agree.  It does
not authorize a run; a later, independently frozen authorization must bind the
complete integrated runner and planner implementations.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .rq1_adaptive_v23 import (
    BASE_LOGICAL_SHA256,
    BASE_MANIFEST_SHA256,
    BASE_PACK_ID,
    BASE_TASKS_SHA256,
    bind_task_view_v23,
    load_affordance_contract,
    load_lifecycle_timing,
    load_task_overlay,
)
from .schema import IntegrityError, canonical_json_bytes, sha256_bytes
from .taskpacks import load_taskpack, taskpack_content_sha256


PROFILE_ARTIFACT_TYPE = "agentmembrane_rq1_adaptive_contract_profile_template_v1"
PROFILE_ID = "canonical-rq1-resource-gpt56sol-max-v2.3-template"
PROFILE_RELATIVE_PATH = Path(
    "experiments/host_boundary_v2/config/"
    "rq1_adaptive_smoke_v2.3/profile.template.json"
)
NEW_AUTHORIZATION_RELATIVE_PATH = PROFILE_RELATIVE_PATH.with_name("authorization.json")
NEW_NAMESPACE_RELATIVE_PATH = Path(
    "experiments/host_boundary_v2/rq1_adaptive_smoke_v2.3/runs/"
    "resource-gpt56sol-max-20260831-v23-001"
)
PACK_ROOT = Path("data/host_boundary_v2/packs/rq1-controlled-v2.2")

OVERLAY_PATH = PROFILE_RELATIVE_PATH.with_name("adaptive-task-overlay-v2.3.json")
AFFORDANCE_PATH = PROFILE_RELATIVE_PATH.with_name(
    "runtime-affordance-contract-v2.3.json"
)
LIFECYCLE_PATH = PROFILE_RELATIVE_PATH.with_name(
    "adaptive-lifecycle-timing-v2.3.json"
)
BINDER_PATH = Path("agentmembrane/host_v2/rq1_adaptive_v23.py")

OVERLAY_FILE_SHA256 = (
    "cdabd4184d36216c654388df2902b434ef6bea959944423e869de548d009da74"
)
AFFORDANCE_FILE_SHA256 = (
    "b7af41272f1f04698f6861ad66749f0bd5e56807e41e6c69874c7b04af1a91af"
)
LIFECYCLE_FILE_SHA256 = (
    "bb398a4cd52ec0ce6645ab0dfb6fddabda0cac96ce6245af3ca9db0da9fabdbb"
)
BINDER_FILE_SHA256 = (
    "cd132e312dec29ffba18f13933aa4269cb6d364f404a345199d690996e32f774"
)

LEGACY_PROFILE_PATH = Path(
    "experiments/host_boundary_v2/config/rq1_adaptive_smoke_v2.2/profile.json"
)
LEGACY_PROFILE_SHA256 = (
    "f39432f9a9b4073aa6e9f611023560a88df47a6795087e93ed91f38c0cc82265"
)
LEGACY_AUTHORIZATION_PATH = LEGACY_PROFILE_PATH.with_name("authorization.json")
LEGACY_AUTHORIZATION_SHA256 = (
    "1fcf5569057643d39a15743455b1c2c47b02765f1b7da0b58b4314e00bfe76e8"
)
LEGACY_NAMESPACE_PATH = Path(
    "experiments/host_boundary_v2/rq1_adaptive_smoke_v2.2/runs/"
    "resource-gpt56sol-max-20260831-001"
)
LEGACY_NAMESPACE_FILE_COUNT = 12
LEGACY_NAMESPACE_TREE_SHA256 = (
    "dc455021007347f875ea1d4607d8cd43224e80eb1780e014c6794e309e88be20"
)

PACK_FIXTURE_SHA256 = (
    "0873b35c5fa366abf3b286541944aecba52a64c6ad3bff6486e59fc2c72b330b"
)
PACK_ORACLE_SHA256 = (
    "c941567550428de46aa64e228ac87ac3b24f48799fe761c380679a5c53834083"
)

RESOURCE_GOAL_SHA256 = (
    "101408fcb2b4d53cf1d7b9495791cee7d7f8e1e6f6dc8c4b51b080e1ce712627"
)
RESOURCE_SURFACE_SHA256 = (
    "9dea91289ad3dfe2706967a98ee8a83df6b85bb1a58c7ff39e7f4c5c9d7316c2"
)
RESOURCE_TASK_VIEW_SHA256 = (
    "d56b142ac8e2a545ecd415c5a22a8e7ff13364b99a8c2242857e1b25ae5c51ba"
)
F5_GOAL_SHA256 = (
    "bc3ede92aa0f23e5ad719c3b0889d69b80d9ddbad12234bf1fa0b128ea7c7aaf"
)
F5_SURFACE_SHA256 = (
    "f0026b0967636e087245d49d455ece4fdb346fc4019e02cedfa170818dcb24e5"
)
F5_TASK_VIEW_SHA256 = (
    "91b1762fdd4b9d3109692bc13fef502ec3ad031b6dbcecaa70c2ca060535ad3d"
)
F5_PUBLIC_AFFORDANCE_SHA256 = (
    "f0692ec20e5d07c701817c5188d7086f72fc52b40a80b6d34193d1ead427ec1b"
)
CONTRACT_BUNDLE_SHA256 = (
    "f31ee8254eab74d2d802c24f83252ce9ba8444d28091c5c34184b90af78c0a72"
)

RESOURCE_TASK_IDS = (
    "rq1-resource-benign-s01",
    "rq1-resource-adversarial-s01",
)
F5_TASK_IDS = (
    "rq1-f5-ambient-workflow-benign-s01",
    "rq1-f5-ambient-workflow-adversarial-s01",
)
EPISODE_ORDER = (
    ("rq1-resource-benign-s01", "RQ1-resource-protected"),
    ("rq1-resource-adversarial-s01", "RQ1-resource-protected"),
    ("rq1-resource-adversarial-s01", "RQ1-resource-vulnerable"),
    ("rq1-resource-benign-s01", "RQ1-resource-vulnerable"),
)

_PROFILE_FIELDS = frozenset(
    {
        "schema_version",
        "artifact_type",
        "profile_id",
        "adaptive_contract_version",
        "protocol_id",
        "construct_id",
        "execution_track",
        "visible_context_profile",
        "execution_authorized_by_profile",
        "execution_implementation_bindings",
        "taskpack_binding",
        "legacy_evidence_binding",
        "contract_artifacts",
        "binder_implementation",
        "contract_bundle_components",
        "contract_bundle_sha256",
        "selection",
        "model",
        "planner",
        "retries",
        "execution",
        "scientific_scope",
        "result_independence",
        "launch_isolation",
        "authorization",
        "integration_gates",
    }
)


class RQ1V23PreflightError(IntegrityError):
    """The v2.3 offline template is inconsistent or no longer pristine."""


@dataclass(frozen=True)
class OfflinePreflightV23:
    passed: bool
    authorization_ready: bool
    execution_authorized: bool
    profile_sha256: str
    contract_bundle_sha256: str
    namespace_root: str
    checks: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "authorization_ready": self.authorization_ready,
            "execution_authorized": self.execution_authorized,
            "profile_sha256": self.profile_sha256,
            "contract_bundle_sha256": self.contract_bundle_sha256,
            "namespace_root": self.namespace_root,
            "checks": list(self.checks),
        }


def _fail(message: str) -> None:
    raise RQ1V23PreflightError(message)


def _exact(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        _fail(f"{label} differs from the frozen v2.3 template")


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RQ1V23PreflightError(f"cannot load {label}: {exc}") from exc
    if not isinstance(value, dict):
        _fail(f"{label} must be a JSON object")
    canonical_json_bytes(value)
    return value


def _repo_path(repo_root: Path, value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        _fail(f"{label} must be a repository-relative path")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        _fail(f"{label} must remain inside the repository")
    root = Path(repo_root).resolve()
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise RQ1V23PreflightError(f"{label} escapes the repository") from exc
    return path


def _file_sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise RQ1V23PreflightError(f"cannot hash {path}: {exc}") from exc


def legacy_tree_manifest(repo_root: Path) -> tuple[int, str]:
    root = (Path(repo_root).resolve() / LEGACY_NAMESPACE_PATH).resolve()
    if not root.is_dir():
        _fail("legacy consumed namespace is missing")
    rows: list[dict[str, Any]] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        rows.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": _file_sha256(path),
                "size": path.stat().st_size,
            }
        )
    return len(rows), sha256_bytes(canonical_json_bytes(rows))


def _validate_file_binding(
    repo_root: Path,
    value: Any,
    *,
    expected_path: Path,
    expected_sha256: str,
    label: str,
) -> Path:
    _exact(
        value,
        {"path": expected_path.as_posix(), "sha256": expected_sha256},
        label,
    )
    path = _repo_path(repo_root, value["path"], f"{label}.path")
    _exact(_file_sha256(path), expected_sha256, f"{label}.sha256")
    return path


def _expected_bundle_components() -> dict[str, str]:
    return {
        "base_manifest_sha256": BASE_MANIFEST_SHA256,
        "base_tasks_sha256": BASE_TASKS_SHA256,
        "base_logical_content_sha256": BASE_LOGICAL_SHA256,
        "task_overlay_file_sha256": OVERLAY_FILE_SHA256,
        "runtime_affordance_contract_file_sha256": AFFORDANCE_FILE_SHA256,
        "adaptive_lifecycle_timing_file_sha256": LIFECYCLE_FILE_SHA256,
        "binder_implementation_sha256": BINDER_FILE_SHA256,
        "resource_goal_sha256": RESOURCE_GOAL_SHA256,
        "resource_surface_sha256": RESOURCE_SURFACE_SHA256,
        "resource_task_view_sha256": RESOURCE_TASK_VIEW_SHA256,
        "f5_goal_sha256": F5_GOAL_SHA256,
        "f5_surface_sha256": F5_SURFACE_SHA256,
        "f5_task_view_sha256": F5_TASK_VIEW_SHA256,
        "f5_public_affordance_sha256": F5_PUBLIC_AFFORDANCE_SHA256,
    }


def validate_profile_template_v23(
    repo_root: Path, profile_path: Path | None = None
) -> OfflinePreflightV23:
    """Validate the proposed v2.3 template without authorizing execution."""

    root = Path(repo_root).resolve()
    path = (
        (root / PROFILE_RELATIVE_PATH).resolve()
        if profile_path is None
        else Path(profile_path).resolve()
    )
    profile = _load_json(path, "v2.3 profile template")
    _exact(frozenset(profile), _PROFILE_FIELDS, "profile fields")
    for label, expected in (
        ("schema_version", 1),
        ("artifact_type", PROFILE_ARTIFACT_TYPE),
        ("profile_id", PROFILE_ID),
        ("adaptive_contract_version", "2.3.0"),
        ("protocol_id", "host-boundary-v2"),
        ("construct_id", "authority_admission_boundary"),
        ("execution_track", "adaptive_end_to_end"),
        ("visible_context_profile", "objective_aware_adaptive"),
        ("execution_authorized_by_profile", False),
    ):
        _exact(profile.get(label), expected, f"profile.{label}")

    _exact(
        profile.get("authorization"),
        {
            "execution_authorized": False,
            "artifact_status": "absent",
            "authorization_path": None,
        },
        "profile.authorization",
    )
    if (root / NEW_AUTHORIZATION_RELATIVE_PATH).exists():
        _fail("v2.3 authorization must remain absent during template preflight")

    taskpack_binding = {
        "pack_id": BASE_PACK_ID,
        "root": PACK_ROOT.as_posix(),
        "manifest_sha256": BASE_MANIFEST_SHA256,
        "tasks_sha256": BASE_TASKS_SHA256,
        "logical_content_sha256": BASE_LOGICAL_SHA256,
        "fixture_sha256": PACK_FIXTURE_SHA256,
        "oracle_sha256": PACK_ORACLE_SHA256,
    }
    _exact(profile.get("taskpack_binding"), taskpack_binding, "taskpack binding")
    _exact(
        _file_sha256(root / PACK_ROOT / "manifest.json"),
        BASE_MANIFEST_SHA256,
        "base manifest bytes",
    )
    _exact(
        _file_sha256(root / PACK_ROOT / "tasks.jsonl"),
        BASE_TASKS_SHA256,
        "base task bytes",
    )
    pack = load_taskpack(root / PACK_ROOT)
    _exact(taskpack_content_sha256(pack), BASE_LOGICAL_SHA256, "base logical pack")

    legacy = profile.get("legacy_evidence_binding")
    expected_legacy = {
        "profile": {
            "path": LEGACY_PROFILE_PATH.as_posix(),
            "sha256": LEGACY_PROFILE_SHA256,
        },
        "authorization": {
            "path": LEGACY_AUTHORIZATION_PATH.as_posix(),
            "sha256": LEGACY_AUTHORIZATION_SHA256,
        },
        "consumed_namespace": {
            "path": LEGACY_NAMESPACE_PATH.as_posix(),
            "file_count": LEGACY_NAMESPACE_FILE_COUNT,
            "tree_manifest_sha256": LEGACY_NAMESPACE_TREE_SHA256,
        },
        "interpretation": "preserve_only_not_poolable",
    }
    _exact(legacy, expected_legacy, "legacy evidence binding")
    _exact(
        _file_sha256(root / LEGACY_PROFILE_PATH),
        LEGACY_PROFILE_SHA256,
        "legacy profile bytes",
    )
    _exact(
        _file_sha256(root / LEGACY_AUTHORIZATION_PATH),
        LEGACY_AUTHORIZATION_SHA256,
        "legacy authorization bytes",
    )
    _exact(
        legacy_tree_manifest(root),
        (LEGACY_NAMESPACE_FILE_COUNT, LEGACY_NAMESPACE_TREE_SHA256),
        "legacy consumed namespace",
    )

    artifacts = profile.get("contract_artifacts")
    if not isinstance(artifacts, Mapping):
        _fail("profile.contract_artifacts must be an object")
    _exact(
        frozenset(artifacts),
        frozenset(
            {
                "task_overlay",
                "runtime_affordance_contract",
                "adaptive_lifecycle_timing",
            }
        ),
        "contract artifact names",
    )
    overlay_path = _validate_file_binding(
        root,
        artifacts["task_overlay"],
        expected_path=OVERLAY_PATH,
        expected_sha256=OVERLAY_FILE_SHA256,
        label="task overlay",
    )
    affordance_path = _validate_file_binding(
        root,
        artifacts["runtime_affordance_contract"],
        expected_path=AFFORDANCE_PATH,
        expected_sha256=AFFORDANCE_FILE_SHA256,
        label="runtime affordance contract",
    )
    lifecycle_path = _validate_file_binding(
        root,
        artifacts["adaptive_lifecycle_timing"],
        expected_path=LIFECYCLE_PATH,
        expected_sha256=LIFECYCLE_FILE_SHA256,
        label="adaptive lifecycle timing",
    )
    binder_path = _validate_file_binding(
        root,
        profile.get("binder_implementation"),
        expected_path=BINDER_PATH,
        expected_sha256=BINDER_FILE_SHA256,
        label="binder implementation",
    )
    del binder_path

    overlay = load_task_overlay(overlay_path)
    affordance = load_affordance_contract(affordance_path)
    load_lifecycle_timing(lifecycle_path)
    f5_affordance = affordance.raw["family_overrides"]["F5_ambient_workflow"]
    _exact(
        sha256_bytes(canonical_json_bytes(f5_affordance)),
        F5_PUBLIC_AFFORDANCE_SHA256,
        "F5 public affordance",
    )

    by_id = {task.task_id: task for task in pack.tasks}
    bound: dict[str, Any] = {}
    for task_id in RESOURCE_TASK_IDS + F5_TASK_IDS:
        if task_id not in by_id:
            _fail(f"base pack lacks selected task {task_id}")
        source = by_id[task_id]
        selected = bind_task_view_v23(
            source, overlay=overlay.raw, overlay_sha256=overlay.file_sha256
        )
        if selected.task.authorized_test_objective != source.authorized_test_objective:
            _fail(f"binder changed trusted attacker objective for {task_id}")
        bound[task_id] = selected

    expected_hashes = {
        RESOURCE_TASK_IDS: (
            RESOURCE_GOAL_SHA256,
            RESOURCE_SURFACE_SHA256,
            RESOURCE_TASK_VIEW_SHA256,
        ),
        F5_TASK_IDS: (F5_GOAL_SHA256, F5_SURFACE_SHA256, F5_TASK_VIEW_SHA256),
    }
    for pair, expected in expected_hashes.items():
        actual = {
            (
                bound[task_id].goal_sha256,
                bound[task_id].surface_sha256,
                bound[task_id].task_view_sha256,
            )
            for task_id in pair
        }
        _exact(actual, {expected}, f"shared twin task view for {pair[0]}")

    components = _expected_bundle_components()
    _exact(
        profile.get("contract_bundle_components"),
        components,
        "contract bundle components",
    )
    computed_bundle_sha = sha256_bytes(canonical_json_bytes(components))
    _exact(computed_bundle_sha, CONTRACT_BUNDLE_SHA256, "computed contract bundle")
    _exact(
        profile.get("contract_bundle_sha256"),
        CONTRACT_BUNDLE_SHA256,
        "profile contract bundle SHA",
    )

    _exact(
        profile.get("selection"),
        {
            "binding_family": "resource",
            "task_ids": list(RESOURCE_TASK_IDS),
            "condition_ids": [
                "RQ1-resource-vulnerable",
                "RQ1-resource-protected",
            ],
            "episode_order": [
                {"ordinal": ordinal, "task_id": task, "condition_id": condition}
                for ordinal, (task, condition) in enumerate(EPISODE_ORDER, start=1)
            ],
            "seed": 20260831,
        },
        "four-cell selection",
    )
    _exact(
        profile.get("model"),
        {
            "requested_id": "gpt-5.6-sol",
            "allowed_resolved_ids": ["gpt-5.6-sol"],
            "provider_route_id": "local-cli-proxy",
            "reasoning_effort": "max",
            "temperature": 0,
            "max_completion_tokens": 1100,
            "stream": False,
        },
        "model contract",
    )
    _exact(
        profile.get("planner"),
        {
            "mode": "adaptive",
            "max_turns": 6,
            "max_actions_per_turn": 1,
            "response_schema_version": 2,
            "visible_context_profile": "objective_aware_adaptive",
        },
        "planner contract",
    )
    _exact(
        profile.get("retries"),
        {
            "request_level_transport_retries": 0,
            "provider_internal_retries": 0,
            "infrastructure_attempts": 1,
            "immutable_failure_classes": [
                "provider_policy",
                "parse",
                "schema",
                "explicit_abstention",
                "transport_failure",
            ],
        },
        "retry contract",
    )
    _exact(
        profile.get("execution"),
        {
            "episodes": 4,
            "waves": 1,
            "blocks": 1,
            "workers": 1,
            "max_inflight": 1,
            "hard_api_call_cap": 24,
            "one_shot": True,
            "require_nonexistent_namespace": True,
            "resume_permitted": False,
            "redraw_permitted": False,
            "namespace_root": NEW_NAMESPACE_RELATIVE_PATH.as_posix(),
        },
        "one-shot execution contract",
    )
    if (root / NEW_NAMESPACE_RELATIVE_PATH).exists():
        _fail("proposed v2.3 one-shot namespace is not fresh")

    _exact(
        profile.get("scientific_scope"),
        {
            "claim_bearing": False,
            "nonestimating": True,
            "engineering_only": True,
            "adaptive_calibration_only": True,
            "formal_rows": 0,
            "independently_authored_pairs": 0,
            "population_claim_eligible": False,
        },
        "scientific scope",
    )
    _exact(
        profile.get("result_independence"),
        {
            "all_four_assigned_episodes_retained": True,
            "authorization_uses_adaptive_results": False,
            "continuation_depends_on_result_direction": False,
            "result_conditioned_expansion_permitted": False,
            "result_conditioned_retry_permitted": False,
        },
        "result independence",
    )
    _exact(
        profile.get("launch_isolation"),
        {
            "formal_launch_opened": False,
            "global_launch_policy_modified": False,
            "public_launch_opened": False,
            "rq1_narrow_authorization_only": True,
        },
        "launch isolation",
    )
    _exact(
        profile.get("execution_implementation_bindings"),
        {
            "adaptive_contract": {
                "path": "agentmembrane/host_v2/rq1_adaptive_v23.py",
                "sha256": None,
            },
            "attacker_prompt": {
                "path": "experiments/host_boundary_v2/config/prompts/attacker-primary.txt",
                "sha256": None,
            },
            "benign_prompt": {
                "path": "experiments/host_boundary_v2/config/prompts/benign-system.txt",
                "sha256": None,
            },
            "cache": {
                "path": "agentmembrane/host_v2/cache.py",
                "sha256": None,
            },
            "conditions": {
                "path": "agentmembrane/host_v2/conditions.py",
                "sha256": None,
            },
            "conditions_config": {
                "path": "experiments/host_boundary_v2/config/conditions.json",
                "sha256": None,
            },
            "contract_validator": {
                "path": "agentmembrane/host_v2/rq1_smoke_v23.py",
                "sha256": None,
            },
            "executor": {
                "path": "agentmembrane/host_v2/rq1_smoke_v23_exec.py",
                "sha256": None,
            },
            "host": {
                "path": "agentmembrane/host_v2/host.py",
                "sha256": None,
            },
            "kernel": {
                "path": "agentmembrane/kernel.py",
                "sha256": None,
            },
            "models": {
                "path": "agentmembrane/models.py",
                "sha256": None,
            },
            "oracle": {
                "path": "agentmembrane/host_v2/oracle.py",
                "sha256": None,
            },
            "planner": {
                "path": "agentmembrane/host_v2/planner.py",
                "sha256": None,
            },
            "postflight_client": {
                "path": "agentmembrane/host_v2/rq1_smoke.py",
                "sha256": None,
            },
            "profiles": {
                "path": "agentmembrane/host_v2/profiles.py",
                "sha256": None,
            },
            "proxy": {
                "path": "agentmembrane/proxy.py",
                "sha256": None,
            },
            "runner": {
                "path": "agentmembrane/host_v2/runner.py",
                "sha256": None,
            },
            "schedule": {
                "path": "agentmembrane/host_v2/schedule.py",
                "sha256": None,
            },
            "schema": {
                "path": "agentmembrane/host_v2/schema.py",
                "sha256": None,
            },
            "taskpacks": {
                "path": "agentmembrane/host_v2/taskpacks.py",
                "sha256": None,
            },
        },
        "unfrozen execution implementation bindings",
    )
    _exact(
        profile.get("integration_gates"),
        {
            "authorization_ready": False,
            "executor_implemented": False,
            "offline_preflight_independently_frozen": False,
            "planner_implementation_sha256": None,
            "runner_integration_ready": False,
            "runner_implementation_sha256": None,
            "runtime_affordance_projection_sha256": None,
        },
        "integration gates",
    )

    return OfflinePreflightV23(
        passed=True,
        authorization_ready=False,
        execution_authorized=False,
        profile_sha256=_file_sha256(path),
        contract_bundle_sha256=computed_bundle_sha,
        namespace_root=NEW_NAMESPACE_RELATIVE_PATH.as_posix(),
        checks=(
            "legacy_v2.2_bytes_preserved",
            "v2.3_contract_artifacts_bound",
            "resource_twin_goal_bytes_shared",
            "f5_corrected_surface_goal_and_affordance_bound",
            "event_driven_lifecycle_timing_bound",
            "four_cell_order_and_result_independence_frozen",
            "authorization_absent_and_execution_unauthorized",
            "fresh_namespace_absent",
        ),
    )


__all__ = [
    "AFFORDANCE_FILE_SHA256",
    "AFFORDANCE_PATH",
    "BINDER_FILE_SHA256",
    "BINDER_PATH",
    "CONTRACT_BUNDLE_SHA256",
    "F5_GOAL_SHA256",
    "F5_PUBLIC_AFFORDANCE_SHA256",
    "F5_SURFACE_SHA256",
    "F5_TASK_IDS",
    "F5_TASK_VIEW_SHA256",
    "LEGACY_NAMESPACE_TREE_SHA256",
    "LIFECYCLE_FILE_SHA256",
    "LIFECYCLE_PATH",
    "NEW_AUTHORIZATION_RELATIVE_PATH",
    "NEW_NAMESPACE_RELATIVE_PATH",
    "OVERLAY_FILE_SHA256",
    "OVERLAY_PATH",
    "OfflinePreflightV23",
    "PROFILE_RELATIVE_PATH",
    "RESOURCE_GOAL_SHA256",
    "RESOURCE_SURFACE_SHA256",
    "RESOURCE_TASK_IDS",
    "RESOURCE_TASK_VIEW_SHA256",
    "RQ1V23PreflightError",
    "legacy_tree_manifest",
    "validate_profile_template_v23",
]
