from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from agentmembrane.host_v2.rq1_adaptive_v23 import (
    F5_GOAL,
    F5_SURFACE,
    FAMILIES,
    RESOURCE_GOAL,
    augment_runtime_interface_v23,
    bind_task_view_v23,
    load_affordance_contract,
    load_lifecycle_timing,
    load_task_overlay,
    resolve_lifecycle_actions_v23,
    runtime_affordance_projection_v23,
    runtime_affordance_sha256_v23,
    validate_task_overlay,
)
from agentmembrane.host_v2.rq1_smoke_v23 import (
    AFFORDANCE_PATH,
    CONTRACT_BUNDLE_SHA256,
    F5_GOAL_SHA256,
    F5_PUBLIC_AFFORDANCE_SHA256,
    F5_SURFACE_SHA256,
    F5_TASK_VIEW_SHA256,
    LEGACY_NAMESPACE_TREE_SHA256,
    LIFECYCLE_PATH,
    NEW_AUTHORIZATION_RELATIVE_PATH,
    NEW_NAMESPACE_RELATIVE_PATH,
    OVERLAY_PATH,
    PROFILE_RELATIVE_PATH,
    RESOURCE_GOAL_SHA256,
    RESOURCE_SURFACE_SHA256,
    RESOURCE_TASK_VIEW_SHA256,
    RQ1V23PreflightError,
    legacy_tree_manifest,
    validate_profile_template_v23,
)
from agentmembrane.host_v2.schema import IntegrityError, canonical_json_bytes
from agentmembrane.host_v2.taskpacks import load_taskpack


REPO_ROOT = Path(__file__).resolve().parents[2]
PACK_ROOT = REPO_ROOT / "data/host_boundary_v2/packs/rq1-controlled-v2.2"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _contracts():
    overlay = load_task_overlay(REPO_ROOT / OVERLAY_PATH)
    affordance = load_affordance_contract(REPO_ROOT / AFFORDANCE_PATH)
    lifecycle = load_lifecycle_timing(REPO_ROOT / LIFECYCLE_PATH)
    return overlay, affordance, lifecycle


def test_legacy_v22_bytes_and_consumed_namespace_are_preserved() -> None:
    assert _sha(PACK_ROOT / "tasks.jsonl") == (
        "2124c76a5a2232cc880ed8b8c9a277b12b747ca6b24a6ec289fcb432f7f8afab"
    )
    assert _sha(PACK_ROOT / "manifest.json") == (
        "ae0328497262476b5e7f29a1a5f00c576237b34afb729f110a15ad9fd2d1ce04"
    )
    assert _sha(
        REPO_ROOT
        / "experiments/host_boundary_v2/config/rq1_adaptive_smoke_v2.2/profile.json"
    ) == "f39432f9a9b4073aa6e9f611023560a88df47a6795087e93ed91f38c0cc82265"
    assert _sha(
        REPO_ROOT
        / "experiments/host_boundary_v2/config/rq1_adaptive_smoke_v2.2/authorization.json"
    ) == "1fcf5569057643d39a15743455b1c2c47b02765f1b7da0b58b4314e00bfe76e8"
    assert legacy_tree_manifest(REPO_ROOT) == (12, LEGACY_NAMESPACE_TREE_SHA256)


def test_all_18_twin_pairs_share_goal_surface_and_view_bytes() -> None:
    overlay, _, _ = _contracts()
    pack = load_taskpack(PACK_ROOT)
    assert len(overlay.raw["families"]) == 18
    assert {task.family for task in pack.tasks} == set(FAMILIES)

    by_family = {family: [] for family in FAMILIES}
    for task in pack.tasks:
        bound = bind_task_view_v23(
            task, overlay=overlay.raw, overlay_sha256=overlay.file_sha256
        )
        by_family[task.family].append(bound)
        # The integration-safe binder must preserve runner-required trusted
        # metadata, including the profiles on which runner performs a second
        # selection step.
        assert bound.task.metadata["execution_tracks"] == task.metadata["execution_tracks"]
        assert "visible_context_profiles" in bound.task.metadata
        assert (
            bound.task.authorized_test_objective == task.authorized_test_objective
        )

    for family, pair in by_family.items():
        assert len(pair) == 2, family
        assert len({item.goal_sha256 for item in pair}) == 1
        assert len({item.surface_sha256 for item in pair}) == 1
        assert len({item.task_view_sha256 for item in pair}) == 1
        assert (
            pair[0].task.metadata["model_visible_context"]["task_goal_spec"]
            == pair[1].task.metadata["model_visible_context"]["task_goal_spec"]
        )


def test_resource_and_f5_exact_closure_hashes() -> None:
    overlay, affordance, _ = _contracts()
    pack = load_taskpack(PACK_ROOT)
    by_id = {task.task_id: task for task in pack.tasks}

    resource = bind_task_view_v23(
        by_id["rq1-resource-benign-s01"],
        overlay=overlay.raw,
        overlay_sha256=overlay.file_sha256,
    )
    assert resource.task.metadata["model_visible_context"]["task_goal_spec"] == RESOURCE_GOAL
    assert resource.goal_sha256 == RESOURCE_GOAL_SHA256
    assert resource.surface_sha256 == RESOURCE_SURFACE_SHA256
    assert resource.task_view_sha256 == RESOURCE_TASK_VIEW_SHA256

    f5 = bind_task_view_v23(
        by_id["rq1-f5-ambient-workflow-adversarial-s01"],
        overlay=overlay.raw,
        overlay_sha256=overlay.file_sha256,
    )
    assert f5.task.surface_task == F5_SURFACE
    assert f5.task.metadata["model_visible_context"]["task_goal_spec"] == F5_GOAL
    assert f5.goal_sha256 == F5_GOAL_SHA256
    assert f5.surface_sha256 == F5_SURFACE_SHA256
    assert f5.task_view_sha256 == F5_TASK_VIEW_SHA256
    serialized = canonical_json_bytes(
        {
            "surface_task": f5.task.surface_task,
            "task_goal_spec": f5.task.metadata["model_visible_context"][
                "task_goal_spec"
            ],
        }
    ).decode("utf-8")
    for forbidden in (
        "composition_id",
        "read_count",
        "return receipt",
        "Send the approved reset-local message",
        "RQ1-resource-protected",
        "RQ1-resource-vulnerable",
    ):
        assert forbidden not in serialized
    public_f5 = affordance.raw["family_overrides"]["F5_ambient_workflow"]
    assert hashlib.sha256(canonical_json_bytes(public_f5)).hexdigest() == (
        F5_PUBLIC_AFFORDANCE_SHA256
    )


def test_static_affordance_projection_ignores_live_opaque_handles() -> None:
    _, affordance, _ = _contracts()
    base = {
        "schema_version": 2,
        "operations": [
            {"name": "resource_read", "required_args": ["resource"]},
            {
                "name": "cross_tool_execute",
                "required_args": ["capability_id", "resource", "value"],
            },
        ],
        "resource_handles": ["public:guide", "project:item"],
        "capability_handles": ["capability:episode-one"],
        "record_handles": ["record:episode-one"],
    }
    changed = copy.deepcopy(base)
    changed["capability_handles"] = ["capability:episode-two"]
    changed["record_handles"] = ["record:episode-two"]
    changed["proposal_handles"] = ["proposal:episode-two"]

    first = augment_runtime_interface_v23(
        base, family="F5_ambient_workflow", affordance_contract=affordance.raw
    )
    projection = runtime_affordance_projection_v23(
        first, family="F5_ambient_workflow", affordance_contract=affordance.raw
    )
    assert projection["workflow_handles"] == [
        {
            "workflow_id": "authorized-chain",
            "display_name": "approved reset-local workflow",
            "terminal_operation": "cross_tool_execute",
            "input_event_kind": "resource_read",
            "minimum_distinct_input_events": 1,
            "same_session_required": True,
        }
    ]
    assert runtime_affordance_sha256_v23(
        base, family="F5_ambient_workflow", affordance_contract=affordance.raw
    ) == runtime_affordance_sha256_v23(
        changed, family="F5_ambient_workflow", affordance_contract=affordance.raw
    )
    visible = canonical_json_bytes(projection).decode("utf-8")
    assert "protected" not in visible.casefold()
    assert "vulnerable" not in visible.casefold()


@pytest.mark.parametrize(
    ("family", "event", "expected"),
    [
        ("self-grant", {"kind": "admission_granted"}, ("trusted_mint",)),
        (
            "renewal",
            {"kind": "admission_granted"},
            ("tick", "trusted_renew"),
        ),
        (
            "scope-mutation",
            {"kind": "admission_granted"},
            ("trusted_scope_replace",),
        ),
        (
            "queued-work",
            {"kind": "capability_work_queued", "work_id": "work:opaque"},
            ("tick", "trusted_reauthorize_work:work:opaque", "run_queued_work"),
        ),
        (
            "action-proposal",
            {"kind": "proposal_submitted", "proposal_id": "proposal:opaque"},
            (
                "tick",
                "trusted_reauthorize_proposal:proposal:opaque",
                "run_proposal:proposal:opaque",
            ),
        ),
        (
            "memory-artifact",
            {"kind": "memory_proposed", "record_id": "record:opaque"},
            (
                "tick",
                "trusted_reauthorize_record:record:opaque",
                "run_record:record:opaque",
            ),
        ),
    ],
)
def test_lifecycle_actions_are_event_driven(
    family: str, event: dict[str, str], expected: tuple[str, ...]
) -> None:
    _, _, lifecycle = _contracts()
    assert lifecycle.raw["model_visible"] is False
    assert lifecycle.raw["numeric_turn_triggers_forbidden"] is True
    assert all(
        "turn" not in row["trigger_event_kind"]
        for row in lifecycle.raw["families"]
    )
    assert resolve_lifecycle_actions_v23(
        family=family, event=event, timing_contract=lifecycle.raw
    ) == expected


def test_overlay_rejects_hidden_control_details_in_user_goal() -> None:
    overlay, _, _ = _contracts()
    leaked = copy.deepcopy(overlay.raw)
    leaked["families"][8]["task_goal_spec"]["read_count"] = 2
    with pytest.raises(IntegrityError, match="leaks control fields"):
        validate_task_overlay(leaked)


def test_profile_template_remains_unauthorized_after_finalization() -> None:
    # The separately authorized v2.3 one-shot has now been consumed.  Namespace
    # absence was only a pre-execution phase assertion; after consumption the
    # durable marker must remain, while the immutable template below must still
    # describe an unauthorized pre-finalization artifact.
    namespace = REPO_ROOT / NEW_NAMESPACE_RELATIVE_PATH
    assert namespace.is_dir()
    assert (namespace / "authorization-consumed.json").is_file()
    profile = json.loads((REPO_ROOT / PROFILE_RELATIVE_PATH).read_text())
    assert profile["execution_authorized_by_profile"] is False
    assert profile["authorization"] == {
        "execution_authorized": False,
        "artifact_status": "absent",
        "authorization_path": None,
    }
    assert profile["integration_gates"]["runner_integration_ready"] is False
    assert profile["integration_gates"]["executor_implemented"] is False

    # The pristine template is a pre-finalization artifact.  Once a separate
    # final authorization exists beside it, the template validator must fail
    # closed instead of pretending that the repository is still pre-authorized.
    assert (REPO_ROOT / NEW_AUTHORIZATION_RELATIVE_PATH).exists()
    with pytest.raises(
        RQ1V23PreflightError,
        match="authorization must remain absent during template preflight",
    ):
        validate_profile_template_v23(REPO_ROOT)


def test_profile_template_fails_closed_on_authorization_mutation(tmp_path: Path) -> None:
    profile = json.loads((REPO_ROOT / PROFILE_RELATIVE_PATH).read_text())
    profile["authorization"]["execution_authorized"] = True
    candidate = tmp_path / "profile.template.json"
    candidate.write_text(json.dumps(profile), encoding="utf-8")
    with pytest.raises(RQ1V23PreflightError, match="profile.authorization"):
        validate_profile_template_v23(REPO_ROOT, candidate)
