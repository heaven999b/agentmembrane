"""Versioned RQ1-only four-cell selector with a condition-blind public view."""

from __future__ import annotations

import copy
from dataclasses import asdict, dataclass
from typing import Any, Literal

from ..schema import SchemaError, sha256_json
from .contracts import (
    ADAPTER_REF,
    OVERLAY_ID,
    SOURCE_TASK_ID,
    USER_PROMPT,
    live_tool_schemas,
    schema_provenance,
)


PairRole = Literal["benign", "adversarial"]
Arm = Literal["vulnerable", "protected"]


@dataclass(frozen=True)
class OverlayCell:
    task_id: str
    pair_role: PairRole
    arm: Arm
    injection_enabled: bool
    source_task_id: str = SOURCE_TASK_ID
    overlay_id: str = OVERLAY_ID
    adapter_ref: str = ADAPTER_REF
    execution_authorized: bool = False
    claim_eligible: bool = False

    def private_json(self) -> dict[str, Any]:
        """Return the Host-private selector row."""

        return asdict(self)

    def model_visible_initial(self) -> dict[str, Any]:
        """Return only ordinary-agent inputs, never experimental labels."""

        value = {
            "agent_role": "ordinary_assistant",
            "messages": [{"role": "user", "content": USER_PROMPT}],
            "tools": live_tool_schemas(),
            "tool_schema_provenance": schema_provenance(),
        }
        rendered = str(value).casefold()
        for prohibited in (
            "pair_role",
            "adversarial",
            "vulnerable",
            "protected",
            "authorized_test_objective",
            "injection_goal",
        ):
            if prohibited in rendered:
                raise RuntimeError(
                    f"condition-blind initial input contains {prohibited}"
                )
        sha256_json(value)
        return value


def select_cell(pair_role: PairRole, arm: Arm) -> OverlayCell:
    """Select one private cell without routing through any legacy task pack."""

    if pair_role not in {"benign", "adversarial"}:
        raise SchemaError("pair_role must be benign or adversarial")
    if arm not in {"vulnerable", "protected"}:
        raise SchemaError("arm must be vulnerable or protected")
    return OverlayCell(
        task_id=f"rq1-agentdojo-ordinary-{pair_role}-{arm}-v2",
        pair_role=pair_role,
        arm=arm,
        injection_enabled=pair_role == "adversarial",
    )


def all_cells() -> tuple[OverlayCell, ...]:
    """Return the exact four-cell matrix in stable execution order."""

    return tuple(
        select_cell(pair_role, arm)
        for pair_role, arm in (
            ("benign", "vulnerable"),
            ("benign", "protected"),
            ("adversarial", "vulnerable"),
            ("adversarial", "protected"),
        )
    )


def selector_manifest() -> dict[str, Any]:
    """Return a non-authorizing manifest for this versioned overlay."""

    cells = [cell.private_json() for cell in all_cells()]
    return {
        "schema_version": 1,
        "artifact_type": "agentmembrane_rq1_agentdojo_ordinary_selector_v2",
        "overlay_id": OVERLAY_ID,
        "adapter_ref": ADAPTER_REF,
        "source_task_id": SOURCE_TASK_ID,
        "cells": copy.deepcopy(cells),
        "cell_count": 4,
        "legacy_pack_binding_used": False,
        "execution_authorized": False,
        "claim_eligible": False,
    }


__all__ = [
    "Arm",
    "OverlayCell",
    "PairRole",
    "all_cells",
    "select_cell",
    "selector_manifest",
]
