"""Frozen 2-cell smoke and 50-session RQ1 activation schedules."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, replace
from typing import Any, Literal

from ..rq1_public_agentdojo_multi_v5.contracts import WORKFLOWS, WorkflowContract
from ..schema import canonical_json_bytes
from .attack_baseline import AttackStrength, baseline_id


RunKind = Literal["smoke", "sample50"]
SCHEDULE_SEED = "rq1-activation-calibration-v1-20260902"
SENTINEL_WORKFLOW_KEY = "banking-u0-i5"


@dataclass(frozen=True)
class CalibrationCell:
    cell_id: str
    run_kind: RunKind
    workflow_key: str
    domain: str
    source_task_id: str
    upstream_task_id: str
    attack_strength: AttackStrength
    attack_baseline_id: str
    repetition: int
    execution_ordinal: int
    pair_role: str = "adversarial"
    host_arm: str = "vulnerable"
    model_id: str = "gpt-5.6-luna"
    reasoning_effort: str = "low"
    natural_carrier_only: bool = True
    calibration_only: bool = True
    claim_eligible: bool = False

    @property
    def workflow(self) -> WorkflowContract:
        for workflow in WORKFLOWS:
            if workflow.workflow_key == self.workflow_key:
                return workflow
        raise RuntimeError("calibration workflow disappeared from frozen contracts")

    def private_json(self) -> dict[str, Any]:
        value = asdict(self)
        canonical_json_bytes(value)
        return value


def _cell(
    workflow: WorkflowContract,
    *,
    strength: AttackStrength,
    repetition: int,
    run_kind: RunKind,
) -> CalibrationCell:
    return CalibrationCell(
        cell_id=(
            f"rq1-activation-{run_kind}-{workflow.workflow_key}-{strength}-"
            f"r{repetition:02d}-v1"
        ),
        run_kind=run_kind,
        workflow_key=workflow.workflow_key,
        domain=workflow.domain,
        source_task_id=workflow.source_task_id,
        upstream_task_id=workflow.upstream_task_id,
        attack_strength=strength,
        attack_baseline_id=baseline_id(strength),
        repetition=repetition,
        execution_ordinal=0,
    )


def _ordered(cells: list[CalibrationCell]) -> tuple[CalibrationCell, ...]:
    ranked = sorted(
        cells,
        key=lambda cell: hashlib.sha256(
            f"{SCHEDULE_SEED}:{cell.cell_id}".encode()
        ).hexdigest(),
    )
    return tuple(
        replace(cell, execution_ordinal=index)
        for index, cell in enumerate(ranked, start=1)
    )


def smoke_schedule() -> tuple[CalibrationCell, ...]:
    """Two operational canaries, excluded from the 50-session calibration."""

    keys = ("banking-u0-i5", "workspace-u13-i0")
    strengths: tuple[AttackStrength, ...] = ("standard", "priority")
    workflows = {row.workflow_key: row for row in WORKFLOWS}
    return tuple(
        replace(
            _cell(
                workflows[key],
                strength=strength,
                repetition=0,
                run_kind="smoke",
            ),
            execution_ordinal=index,
        )
        for index, (key, strength) in enumerate(zip(keys, strengths), start=1)
    )


def calibration_schedule() -> tuple[CalibrationCell, ...]:
    """Return the exact 50-session development schedule.

    Forty-eight rows form a balanced 12-workflow × 2-strength × 2-repeat
    matrix. Two predeclared banking sentinels add one repetition per strength.
    Repetitions are repeated measurements, not independent workflows.
    """

    cells = [
        _cell(
            workflow,
            strength=strength,
            repetition=repetition,
            run_kind="sample50",
        )
        for workflow in WORKFLOWS
        for strength in ("standard", "priority")
        for repetition in (1, 2)
    ]
    sentinel = next(
        row for row in WORKFLOWS if row.workflow_key == SENTINEL_WORKFLOW_KEY
    )
    cells.extend(
        _cell(
            sentinel,
            strength=strength,
            repetition=3,
            run_kind="sample50",
        )
        for strength in ("standard", "priority")
    )
    schedule = _ordered(cells)
    if len(schedule) != 50 or len({row.cell_id for row in schedule}) != 50:
        raise RuntimeError("calibration schedule is not exactly 50 unique rows")
    return schedule


def schedule_manifest(run_kind: RunKind) -> dict[str, Any]:
    schedule = smoke_schedule() if run_kind == "smoke" else calibration_schedule()
    value = {
        "schema_version": 1,
        "artifact_type": "rq1_activation_schedule_manifest_v1",
        "run_kind": run_kind,
        "schedule_seed": SCHEDULE_SEED,
        "assigned_sessions": len(schedule),
        "unique_workflows": len({row.workflow_key for row in schedule}),
        "strength_counts": {
            strength: sum(row.attack_strength == strength for row in schedule)
            for strength in ("standard", "priority")
        },
        "repeated_measurements_are_independent_workflows": False,
        "host_arms": ["vulnerable"],
        "pair_roles": ["adversarial"],
        "calibration_only": True,
        "claim_eligible": False,
    }
    canonical_json_bytes(value)
    return value


__all__ = [
    "CalibrationCell",
    "RunKind",
    "SCHEDULE_SEED",
    "calibration_schedule",
    "schedule_manifest",
    "smoke_schedule",
]
