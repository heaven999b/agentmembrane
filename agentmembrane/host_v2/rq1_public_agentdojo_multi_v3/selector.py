"""Deterministic private 12-workflow/48-cell RQ1 engineering selector."""

from __future__ import annotations

import copy
from dataclasses import asdict, dataclass, replace
from typing import Any, Literal

from ..schema import SchemaError, canonical_json_bytes, sha256_json
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
)


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
    return EngineeringCell(
        cell_id=(
            f"rq1-agentdojo-{workflow.workflow_key}-{pair_role}-{host_arm}-v3"
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
        initial_state_sha256=workflow.initial_state_sha256,
        native_tool_profile_id=profile.profile_id,
        native_tool_profile_sha256=profile.profile_sha256,
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
        "artifact_type": "agentmembrane_rq1_agentdojo_multi_selector_v3",
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
