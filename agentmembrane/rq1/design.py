from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterable

from .artifacts import condition_blind_id
from .schema import (
    ArtifactCondition,
    AttackFamily,
    DecisionPolicy,
    ExposureMode,
    Label,
    SemanticRiskAnnotation,
    TaskEpisode,
)


@dataclass(frozen=True)
class AttackCase:
    episode: TaskEpisode
    annotation: SemanticRiskAnnotation

    @property
    def case_id(self) -> str:
        material = (
            f"{self.episode.episode_id}\0{self.annotation.attack_family.value}"
        ).encode("utf-8")
        return f"case-{hashlib.sha256(material).hexdigest()[:24]}"

    def validate(self) -> tuple[str, ...]:
        problems = list(self.episode.validate())
        problems.extend(self.annotation.validate(self.episode))
        return tuple(problems)


@dataclass(frozen=True)
class RunCell:
    cell_id: str
    condition_blind_id: str
    case_id: str
    episode_id: str
    independence_id: str
    attack_family: AttackFamily
    predefined_target_label: Label
    artifact_condition: ArtifactCondition
    exposure_mode: ExposureMode
    decision_policy: DecisionPolicy
    random_draw_id: int
    independent_unit: str = "document_id"

    @property
    def analysis_key(self) -> tuple[str, str, str, str]:
        return (
            self.attack_family.value,
            self.artifact_condition.value,
            self.exposure_mode.value,
            self.decision_policy.value,
        )


CORE_CELL_SPEC: tuple[
    tuple[ArtifactCondition, ExposureMode, DecisionPolicy], ...
] = (
    # Main semantic-influence stress contrast, including matched random omission.
    (
        ArtifactCondition.BALANCED,
        ExposureMode.PERSISTED_RETRIEVED,
        DecisionPolicy.FORCED_LABEL,
    ),
    (
        ArtifactCondition.RANDOM_OMISSION,
        ExposureMode.PERSISTED_RETRIEVED,
        DecisionPolicy.FORCED_LABEL,
    ),
    (
        ArtifactCondition.TARGETED_EXTRACTIVE,
        ExposureMode.PERSISTED_RETRIEVED,
        DecisionPolicy.FORCED_LABEL,
    ),
    # Carryover-availability control: no artifact is available in Session 2.
    (
        ArtifactCondition.BALANCED,
        ExposureMode.SESSION1_ONLY,
        DecisionPolicy.FORCED_LABEL,
    ),
    (
        ArtifactCondition.TARGETED_EXTRACTIVE,
        ExposureMode.SESSION1_ONLY,
        DecisionPolicy.FORCED_LABEL,
    ),
    # Matched Session-2 content: estimates storage/provenance framing, not
    # persistence itself.
    (
        ArtifactCondition.BALANCED,
        ExposureMode.DIRECT_SESSION2,
        DecisionPolicy.FORCED_LABEL,
    ),
    (
        ArtifactCondition.TARGETED_EXTRACTIVE,
        ExposureMode.DIRECT_SESSION2,
        DecisionPolicy.FORCED_LABEL,
    ),
    # Primary safety policy: request source or abstain is allowed.
    (
        ArtifactCondition.BALANCED,
        ExposureMode.PERSISTED_RETRIEVED,
        DecisionPolicy.SOURCE_ON_DEMAND,
    ),
    (
        ArtifactCondition.RANDOM_OMISSION,
        ExposureMode.PERSISTED_RETRIEVED,
        DecisionPolicy.SOURCE_ON_DEMAND,
    ),
    (
        ArtifactCondition.TARGETED_EXTRACTIVE,
        ExposureMode.PERSISTED_RETRIEVED,
        DecisionPolicy.SOURCE_ON_DEMAND,
    ),
    # Strong incumbent: complete immutable source is always available.
    (
        ArtifactCondition.BALANCED,
        ExposureMode.PERSISTED_RETRIEVED,
        DecisionPolicy.RAW_ALWAYS,
    ),
    (
        ArtifactCondition.TARGETED_EXTRACTIVE,
        ExposureMode.PERSISTED_RETRIEVED,
        DecisionPolicy.RAW_ALWAYS,
    ),
)


def _cell_id(
    episode_id: str,
    attack_family: AttackFamily,
    condition: ArtifactCondition,
    exposure: ExposureMode,
    policy: DecisionPolicy,
    *,
    blind_salt: str,
) -> str:
    material = "\0".join(
        (
            blind_salt,
            episode_id,
            attack_family.value,
            condition.value,
            exposure.value,
            policy.value,
        )
    ).encode("utf-8")
    return f"cell-{hashlib.sha256(material).hexdigest()[:24]}"


def build_core_schedule(
    cases: Iterable[AttackCase],
    *,
    blind_salt: str,
    random_draw_id: int = 0,
) -> tuple[RunCell, ...]:
    if not blind_salt:
        raise ValueError("blind_salt must be non-empty")
    if type(random_draw_id) is not int or random_draw_id < 0:
        raise ValueError("random_draw_id must be a non-negative integer")
    case_values = tuple(cases)
    cells: list[RunCell] = []
    for case in case_values:
        case_problems = case.validate()
        if case_problems:
            raise ValueError(
                f"invalid attack case {case.case_id}: {';'.join(case_problems)}"
            )
        episode = case.episode
        annotation = case.annotation
        for condition, exposure, policy in CORE_CELL_SPEC:
            draw_id = (
                random_draw_id
                if condition is ArtifactCondition.RANDOM_OMISSION
                else 0
            )
            cells.append(
                RunCell(
                    cell_id=_cell_id(
                        episode.episode_id,
                        annotation.attack_family,
                        condition,
                        exposure,
                        policy,
                        blind_salt=blind_salt,
                    ),
                    condition_blind_id=condition_blind_id(
                        episode.episode_id,
                        condition,
                        attack_family=annotation.attack_family,
                        blind_salt=blind_salt,
                        draw_id=draw_id,
                    ),
                    case_id=case.case_id,
                    episode_id=episode.episode_id,
                    independence_id=episode.independence_id,
                    attack_family=annotation.attack_family,
                    predefined_target_label=annotation.predefined_target_label,
                    artifact_condition=condition,
                    exposure_mode=exposure,
                    decision_policy=policy,
                    random_draw_id=draw_id,
                )
            )
    schedule = tuple(cells)
    problems = validate_core_schedule(schedule, cases=case_values)
    if problems:
        raise ValueError("invalid core schedule: " + ";".join(problems))
    return schedule


def validate_core_schedule(
    schedule: Iterable[RunCell],
    *,
    cases: Iterable[AttackCase],
) -> tuple[str, ...]:
    cells = tuple(schedule)
    case_values = tuple(cases)
    problems: list[str] = []
    expected_case_ids = {case.case_id for case in case_values}
    if len(expected_case_ids) != len(case_values):
        problems.append("duplicate_attack_case")
    by_case: dict[str, list[RunCell]] = {
        case_id: [] for case_id in expected_case_ids
    }
    for cell in cells:
        if cell.case_id not in by_case:
            problems.append(f"unknown_case:{cell.case_id}")
            continue
        by_case[cell.case_id].append(cell)
        if cell.independent_unit != "document_id":
            problems.append(f"wrong_independent_unit:{cell.cell_id}")
        if (
            cell.artifact_condition is not ArtifactCondition.RANDOM_OMISSION
            and cell.random_draw_id != 0
        ):
            problems.append(f"nonrandom_cell_has_draw:{cell.cell_id}")
    expected_spec = set(CORE_CELL_SPEC)
    case_lookup = {case.case_id: case for case in case_values}
    for case_id, case_cells in by_case.items():
        observed = {
            (
                cell.artifact_condition,
                cell.exposure_mode,
                cell.decision_policy,
            )
            for cell in case_cells
        }
        if len(case_cells) != len(CORE_CELL_SPEC):
            problems.append(f"wrong_cell_count:{case_id}")
        if observed != expected_spec:
            problems.append(f"wrong_cell_matrix:{case_id}")
        case = case_lookup[case_id]
        expected_independence = case.episode.independence_id
        if any(cell.independence_id != expected_independence for cell in case_cells):
            problems.append(f"independence_id_mismatch:{case_id}")
        if any(cell.episode_id != case.episode.episode_id for cell in case_cells):
            problems.append(f"episode_id_mismatch:{case_id}")
        if any(cell.attack_family != case.annotation.attack_family for cell in case_cells):
            problems.append(f"attack_family_mismatch:{case_id}")
        if any(
            cell.predefined_target_label != case.annotation.predefined_target_label
            for cell in case_cells
        ):
            problems.append(f"target_label_mismatch:{case_id}")
    ids = [cell.cell_id for cell in cells]
    if len(ids) != len(set(ids)):
        problems.append("duplicate_cell_id")
    return tuple(problems)
