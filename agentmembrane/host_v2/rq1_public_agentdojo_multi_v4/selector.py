"""Deterministic private 12-workflow/48-cell RQ1 v4 selector."""

from __future__ import annotations

import copy
from dataclasses import asdict, dataclass, replace
from typing import Any, Literal

from ..schema import SchemaError, canonical_json_bytes, sha256_json
from .attack_baseline import ATTACK_BASELINE_ID
from .contracts import (
    CLAIM_ELIGIBLE,
    CONSTRUCT_STATUS,
    SELECTOR_ID,
    SOURCE_PACK_ID,
    SOURCE_VERSION_OR_COMMIT,
    WORKFLOWS,
    WorkflowContract,
    tool_profile,
    workflow_contract,
)


PairRole = Literal["benign", "adversarial"]
HostArm = Literal["vulnerable", "protected"]

_COORDINATES: tuple[tuple[PairRole, HostArm], ...] = (
    ("benign", "vulnerable"),
    ("benign", "protected"),
    ("adversarial", "vulnerable"),
    ("adversarial", "protected"),
)
ORDER_SCHEME_ID = "four-coordinate-latin-rotation-v1"
MODEL_TOOL_VIEW_KIND = "selector_only_opaque_native_refs"
_MODEL_PRIVATE_TERMS = (
    "pair_role",
    "host_arm",
    "adversarial",
    "vulnerable",
    "protected",
    "injection_enabled",
    "injection_task",
    "injection_vector",
    "fixture_ref",
    "oracle_ref",
    "claim_eligible",
    "attack_baseline_id",
    "attack_payload_sha256",
    "attack_text_sha256",
)

_ADVERSARIAL_BINDINGS: dict[str, tuple[str, str, str]] = {
    "banking-u0-i5": (
        "a82e0dbb55332841784154838dbbefb63c00f29df2cb710144e39bed63be9da3",
        "9e2365f91bebeaa5fb40d980bcbca92f617b5d06d87c0e651bddb830283de6a0",
        "93704b0ffaaaaf2b490c51f62475d81ec6a6b4519743eda91a50df13d10df74e",
    ),
    "banking-u2-i4": (
        "a1b940277ab6819704c599ae3f8978f2ffe5c42d9ebbb3abc3ae6cd17e1a52c8",
        "cb81391e6ebb417eb4068247ce784da03f077baf564995ba08fa9a352e512315",
        "e590903bec4666923018c594854d37cf6113e6cc2b2da207f71565a3043610bf",
    ),
    "banking-u3-i1": (
        "d63f16a94383448b06c4bae41a9431f7c1979d40e691931b4e0bb390d7a20d60",
        "8a24ac0bd1782a6959c8fcabcf77015dd88040c133aa6410f8f02853ab78fac4",
        "3fe8b2a74c30b1e946337c5e40503a5e2523fcccc34740764e055c8734db2da5",
    ),
    "slack-u0-i3": (
        "cb051d97f359df41132be4f7ec1c2ea5ed775f0cf88ab5cce12ceb8744b1f5cc",
        "d32b6fcb3230c8c81988811ee53846d8a42f7b39300860278565d4fd382732e3",
        "6f6f9db3cd7c00669f1e3f35988dc9fbcae005c3125086647c0deef30513e832",
    ),
    "slack-u2-i5": (
        "79f5717057cbf7721bd3fd9edc36efb0c416398aa38a6723a85ce46c5ec18de5",
        "8d23a000c77059eea04b57bc682b4c8610783ba768e8ba38271c7f2a7fae96f8",
        "dae04e2cdec636ee7e7514fe52e1e843e481b70fd9f306cecd271ebd63b58eed",
    ),
    "slack-u6-i1": (
        "401d6b7d95675782d80061be417beb2fd54d9adb2dcb24005c4dcf153a1540ee",
        "905370f30af1b79abf599a89a6bbaee14a360686d1bf7cf45f3f21c56962aed5",
        "79df5c394d8ab4ed7aeced11662cdb0e1f946785723751f35d6ca0bb775ed1a3",
    ),
    "travel-u0-i0": (
        "eeb009b7170eb68ab60a76efec9df481909914b3951a538890162c7cd0ae0661",
        "fa44dd8c61bf87b4fea146c7f28b6b7be43d3b664967f887bfa5dc15bd65162e",
        "11329b198938df9e24dbbd2eeccb8f4afbf04f31481f06077242363b2ec6cadd",
    ),
    "travel-u1-i2": (
        "8e85c7411cb8344118e111de29b3661d6f3daf96e930482a740fef804aeca78b",
        "e7476ccf6d2a3396198f85caef3b7dde32a12fb7179d9fd438a8c73281063eea",
        "65bfae04b14b3dfc42ee701fe17e3226ee38e91605617c2b45bb598fb410b5f4",
    ),
    "travel-u3-i1": (
        "6876dec1a44398b63716b11fa3c5c044abfcf18277223ec321e4045d4606e0d2",
        "a565144c3596619aed5a78d6a51cf6cab7f20a7feb8e6881ac6f2e5de3759364",
        "b8a24b0a64a5199aad0a7e93a67ec739849c79f9f8ce60da6af510ed52fc0374",
    ),
    "workspace-u13-i0": (
        "da362f4fc35822b0fc52b18c2bb967fa07d3b986ac2414b0c2905169361c2467",
        "592708292ce7952b98ef1dc372181f368635c48e1aae60a06d10023ca57f6f14",
        "e4d30b7fb4a9fe6f3e1a931cb1ef51b3d8f003f9901fdb75247bca794f318979",
    ),
    "workspace-u15-i2": (
        "377c317c1f11cb4b903008f39f252f0c2d59738abe2203763e6a9cc7e2dfd005",
        "f00c83c60a84547a471180923c22fda7e15c1d70835076055e0f38238faa820c",
        "f13d42a86e0c6981529221bc0b8e67e1eefa2dc055046d746fa65dde50c4b9f2",
    ),
    "workspace-u18-i3": (
        "f2ce7861002a4ec980330f886a62cb10ca2183bdb0f016584efc9cd3114cae55",
        "0e90e790fe4926e6abd31b66ff3df350cd3981efdef69dc0beea1f6c72b92749",
        "6c3cb7eb95ed45ec8ef20681643c10e49601774ddae9013b03a8ba19b7a80121",
    ),
}


@dataclass(frozen=True)
class EngineeringCell:
    """A Host-private coordinate with immutable source and tool bindings."""

    cell_id: str
    workflow_key: str
    domain: str
    workflow_id: str
    source_task_id: str
    upstream_task_id: str
    pair_role: PairRole
    host_arm: HostArm
    injection_enabled: bool
    fixture_ref: str
    fixture_sha256: str
    oracle_ref: str
    oracle_sha256: str
    initial_state_sha256: str
    native_tool_profile_id: str
    native_tool_profile_sha256: str
    attack_baseline_id: str | None = None
    attack_payload_sha256: str | None = None
    attack_text_sha256: str | None = None
    execution_ordinal: int | None = None
    order_rotation: int | None = None
    construct_status: str = CONSTRUCT_STATUS
    engineering_smoke: bool = True
    claim_eligible: bool = CLAIM_ELIGIBLE

    @property
    def workflow(self) -> WorkflowContract:
        return workflow_contract(self.workflow_key)

    def private_json(self) -> dict[str, Any]:
        """Return the complete selector row for Host-side scheduling."""

        return asdict(self)

    def model_visible_initial(self) -> dict[str, Any]:
        """Return only the ordinary-agent task and native tool surface."""

        profile = tool_profile(self.workflow.domain)
        view = {
            "messages": [
                {"role": "user", "content": self.workflow.surface_task}
            ],
            "tools": profile.model_visible_tools(),
        }
        rendered = canonical_json_bytes(view).decode("utf-8").casefold()
        for term in _MODEL_PRIVATE_TERMS:
            if term in rendered:
                raise RuntimeError(
                    f"condition-private selector value reached model view: {term}"
                )
        sha256_json(view)
        return view


def _resolve_workflow(identity: str) -> WorkflowContract:
    for workflow in WORKFLOWS:
        if identity in {
            workflow.workflow_key,
            workflow.workflow_id,
            workflow.source_task_id,
            workflow.upstream_task_id,
        }:
            return workflow
    raise SchemaError(f"unknown frozen workflow identity: {identity!r}")


def select_cell(
    workflow_identity: str,
    pair_role: PairRole,
    host_arm: HostArm,
) -> EngineeringCell:
    """Select one private coordinate from the frozen engineering matrix."""

    if pair_role not in {"benign", "adversarial"}:
        raise SchemaError("pair_role must be benign or adversarial")
    if host_arm not in {"vulnerable", "protected"}:
        raise SchemaError("host_arm must be vulnerable or protected")
    workflow = _resolve_workflow(workflow_identity)
    fixture_ref, fixture_sha256 = workflow.fixture_binding(pair_role)
    profile = tool_profile(workflow.domain)
    adversarial_binding = (
        _ADVERSARIAL_BINDINGS[workflow.workflow_key]
        if pair_role == "adversarial"
        else None
    )
    return EngineeringCell(
        cell_id=(
            f"rq1-agentdojo-{workflow.workflow_key}-{pair_role}-{host_arm}-v4"
        ),
        workflow_key=workflow.workflow_key,
        domain=workflow.domain,
        workflow_id=workflow.workflow_id,
        source_task_id=workflow.source_task_id,
        upstream_task_id=workflow.upstream_task_id,
        pair_role=pair_role,
        host_arm=host_arm,
        injection_enabled=pair_role == "adversarial",
        fixture_ref=fixture_ref,
        fixture_sha256=fixture_sha256,
        oracle_ref=workflow.oracle_ref,
        oracle_sha256=workflow.oracle_sha256,
        initial_state_sha256=(
            adversarial_binding[0]
            if adversarial_binding is not None
            else workflow.initial_state_sha256
        ),
        native_tool_profile_id=profile.profile_id,
        native_tool_profile_sha256=profile.profile_sha256,
        attack_baseline_id=(
            ATTACK_BASELINE_ID if adversarial_binding is not None else None
        ),
        attack_payload_sha256=(
            adversarial_binding[1] if adversarial_binding is not None else None
        ),
        attack_text_sha256=(
            adversarial_binding[2] if adversarial_binding is not None else None
        ),
    )


def workflow_cells(workflow_identity: str) -> tuple[EngineeringCell, ...]:
    """Return one workflow's Latin-rotated four-coordinate block."""

    workflow = _resolve_workflow(workflow_identity)
    workflow_index = WORKFLOWS.index(workflow)
    rotation = workflow_index % len(_COORDINATES)
    coordinate_order = _COORDINATES[rotation:] + _COORDINATES[:rotation]
    return tuple(
        replace(
            select_cell(workflow.workflow_key, pair_role, host_arm),
            execution_ordinal=(workflow_index * len(_COORDINATES)) + offset + 1,
            order_rotation=rotation,
        )
        for offset, (pair_role, host_arm) in enumerate(coordinate_order)
    )


def all_cells() -> tuple[EngineeringCell, ...]:
    """Return the exact 48-cell engineering smoke schedule."""

    return tuple(
        cell
        for workflow in WORKFLOWS
        for cell in workflow_cells(workflow.workflow_key)
    )


def engineering_smoke_schedule() -> tuple[EngineeringCell, ...]:
    """Named schedule entry point; selection alone never asserts parity."""

    return all_cells()


def execution_order_scheme() -> dict[str, Any]:
    """Return the explicit 12-block Latin rotation assignment."""

    base = [
        {"pair_role": pair_role, "host_arm": host_arm}
        for pair_role, host_arm in _COORDINATES
    ]
    assignments = []
    for index, workflow in enumerate(WORKFLOWS):
        rotation = index % len(_COORDINATES)
        rotated = base[rotation:] + base[:rotation]
        assignments.append(
            {
                "workflow_key": workflow.workflow_key,
                "rotation": rotation,
                "execution_ordinals": list(range(index * 4 + 1, index * 4 + 5)),
                "coordinate_order": copy.deepcopy(rotated),
            }
        )
    return {
        "scheme_id": ORDER_SCHEME_ID,
        "ordinal_base": 1,
        "base_coordinate_order": base,
        "rotation_count": 4,
        "workflows_per_rotation": 3,
        "assignments": assignments,
    }


def selector_manifest() -> dict[str, Any]:
    """Return the Host-private, non-claiming selector manifest."""

    cells = [cell.private_json() for cell in all_cells()]
    domain_counts = {
        domain: sum(workflow.domain == domain for workflow in WORKFLOWS)
        for domain in ("banking", "slack", "travel", "workspace")
    }
    return {
        "schema_version": 1,
        "artifact_type": "agentmembrane_rq1_agentdojo_multi_selector_v4",
        "selector_id": SELECTOR_ID,
        "construct_status": CONSTRUCT_STATUS,
        "source_pack_id": SOURCE_PACK_ID,
        "source_version_or_commit": SOURCE_VERSION_OR_COMMIT,
        "schedule_kind": "engineering_48_cell_smoke",
        "execution_order_scheme": execution_order_scheme(),
        "model_tool_view_kind": MODEL_TOOL_VIEW_KIND,
        "runner_tool_requirement": (
            "materialize_real_native_schemas_and_match_profile_sha256"
        ),
        "domain_workflow_counts": domain_counts,
        "workflow_count": len(WORKFLOWS),
        "cell_count": len(cells),
        "cells": copy.deepcopy(cells),
        "claim_eligible": CLAIM_ELIGIBLE,
    }


__all__ = [
    "EngineeringCell",
    "HostArm",
    "MODEL_TOOL_VIEW_KIND",
    "ORDER_SCHEME_ID",
    "PairRole",
    "all_cells",
    "engineering_smoke_schedule",
    "execution_order_scheme",
    "select_cell",
    "selector_manifest",
    "workflow_cells",
]
