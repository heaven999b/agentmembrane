"""Deterministic private 7-workflow/28-cell RQ1 v5 selector."""

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
SELECTION_SEED = "rq1-v5-gpt54mini-low-28"
SELECTED_WORKFLOW_KEYS = (
    "banking-u3-i1",
    "workspace-u13-i0",
    "workspace-u15-i2",
    "slack-u6-i1",
    "travel-u0-i0",
    "banking-u2-i4",
    "travel-u1-i2",
)
EXPERIMENT_WORKFLOWS = tuple(
    workflow for key in SELECTED_WORKFLOW_KEYS
    for workflow in WORKFLOWS if workflow.workflow_key == key
)
if tuple(workflow.workflow_key for workflow in EXPERIMENT_WORKFLOWS) != SELECTED_WORKFLOW_KEYS:
    raise RuntimeError("RQ1 v5 selected workflow contract is incomplete")
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
        "16427b4bf715e4c5c8ec3c51538719bcaf31ffc902016b0f744906c643bcc5e5",
        "fdb6bd76a5aab3418888f721e695370923ad40dc9141574b6557beb1d69f0472",
        "5a28be0e21ae76f3c11b26784a08a58429dfdde8499fbf1039158b07512b5565",
    ),
    "banking-u3-i1": (
        "97c2a0247565596149b4e63c24c4e0dad54d04aefa108fc0e014f6ace33f0f73",
        "861bae3e158bc5ee298717bacd7117d36b5e292a7b056dc2daf622cbf8445dd8",
        "363d914c400277cc68261eb10503d50c84322c1ffb27e721d4df408afc2d2a50",
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
        "c5b9b34c364c907545267f5c7ed6e47261a4ef3e94ec5ac5968fb795d6322261",
        "454abd29169ac1736055323c568707e78e20d7023dd1b44e18b125f761d27867",
        "8afb590861c0513fc3aaf609fbb3ba4464a245854099830e79004a3a39a0c41d",
    ),
    "travel-u0-i0": (
        "102db1902e50d85abc75d6c91f84daace3a4d901cc523496b8ba5566782e81d5",
        "0d8cdf600fce199d586c5180a64a1a73d459064c4023ca2fa71be2ef93366b6a",
        "39a5f71509dcf9054f8ecee4a54432bc102b77bea09c61717246b573a7a3fb73",
    ),
    "travel-u1-i2": (
        "b42cb50f4b5ce3169eb517456f2e2a1ad59fe9d572409f14f448c79f0ac0bb21",
        "eed3996d57b278b49b1a8202d5ba38b7e161b58cce4918aba8ebe9189083435f",
        "fabfe99e89a2ccb4918fd498a35d0498c24fa4f8cfc1d9bb9d3116df667a01d4",
    ),
    "travel-u3-i1": (
        "6876dec1a44398b63716b11fa3c5c044abfcf18277223ec321e4045d4606e0d2",
        "a565144c3596619aed5a78d6a51cf6cab7f20a7feb8e6881ac6f2e5de3759364",
        "b8a24b0a64a5199aad0a7e93a67ec739849c79f9f8ce60da6af510ed52fc0374",
    ),
    "workspace-u13-i0": (
        "7105a9b8c5d79e295eb16ad29298e09d99bd61371b42f856e5b7f260e94b3064",
        "996bb2a153489c7aa8dc2fadfe34d3705460c39f9495d0b1c723bc6e0ef0c886",
        "b81aeac214282f7cc6a0167f21aa9f0c74cfc18e823e6bf5fae456d8ea5c134a",
    ),
    "workspace-u15-i2": (
        "9d1a71ef350736e294e02db9d74efb34dd782474f94f422aaab9677ed6abb4f3",
        "52646974e7456d4eb55f80878290f16c9096954bb62cdb7ba8a37b63c90bf235",
        "f7050d4987fbc7ec8403b936832afacf049a59f7c446725365b528ae5ed5bac6",
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
            f"rq1-agentdojo-{workflow.workflow_key}-{pair_role}-{host_arm}-v5"
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
    if workflow not in EXPERIMENT_WORKFLOWS:
        raise SchemaError(f"workflow is outside the RQ1 v5 selection: {workflow_identity!r}")
    workflow_index = EXPERIMENT_WORKFLOWS.index(workflow)
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
    """Return the exact 28-cell weak-model engineering schedule."""

    return tuple(
        cell
        for workflow in EXPERIMENT_WORKFLOWS
        for cell in workflow_cells(workflow.workflow_key)
    )


def engineering_smoke_schedule() -> tuple[EngineeringCell, ...]:
    """Named schedule entry point; selection alone never asserts parity."""

    return all_cells()


def execution_order_scheme() -> dict[str, Any]:
    """Return the explicit seven-block Latin rotation assignment."""

    base = [
        {"pair_role": pair_role, "host_arm": host_arm}
        for pair_role, host_arm in _COORDINATES
    ]
    assignments = []
    for index, workflow in enumerate(EXPERIMENT_WORKFLOWS):
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
        "workflows_per_rotation": None,
        "assignments": assignments,
    }


def selector_manifest() -> dict[str, Any]:
    """Return the Host-private, non-claiming selector manifest."""

    cells = [cell.private_json() for cell in all_cells()]
    domain_counts = {
        domain: sum(workflow.domain == domain for workflow in EXPERIMENT_WORKFLOWS)
        for domain in ("banking", "slack", "travel", "workspace")
    }
    return {
        "schema_version": 1,
        "artifact_type": "agentmembrane_rq1_agentdojo_multi_selector_v5",
        "selector_id": SELECTOR_ID,
        "construct_status": CONSTRUCT_STATUS,
        "source_pack_id": SOURCE_PACK_ID,
        "source_version_or_commit": SOURCE_VERSION_OR_COMMIT,
        "schedule_kind": "engineering_28_cell_weak_model_smoke",
        "selection_seed": SELECTION_SEED,
        "selection_rule": (
            "lowest SHA256-ranked canonical workflow keys under the frozen "
            "selection seed, with offline authority-field coverage in every "
            "domain, until seven complete workflow blocks are selected"
        ),
        "execution_order_scheme": execution_order_scheme(),
        "model_tool_view_kind": MODEL_TOOL_VIEW_KIND,
        "runner_tool_requirement": (
            "materialize_real_native_schemas_and_match_profile_sha256"
        ),
        "domain_workflow_counts": domain_counts,
        "workflow_count": len(EXPERIMENT_WORKFLOWS),
        "cell_count": len(cells),
        "cells": copy.deepcopy(cells),
        "claim_eligible": CLAIM_ELIGIBLE,
    }


__all__ = [
    "EngineeringCell",
    "EXPERIMENT_WORKFLOWS",
    "HostArm",
    "MODEL_TOOL_VIEW_KIND",
    "ORDER_SCHEME_ID",
    "PairRole",
    "SELECTED_WORKFLOW_KEYS",
    "SELECTION_SEED",
    "all_cells",
    "engineering_smoke_schedule",
    "execution_order_scheme",
    "select_cell",
    "selector_manifest",
    "workflow_cells",
]
