"""Bank provenance and blocked scheduling for the original-RQ1 v2 study."""

from __future__ import annotations

import copy
from dataclasses import asdict, dataclass
import random
from typing import Any, Iterable

from .original_rq1 import ORIGINAL_RQ1_HAZARDS, ORIGINAL_RQ1_LEVEL_ORDER
from .schema import sha256_json


DATA_BANKS = ("development", "formal_holdout")
UTILITY_CLASSES = (
    "W0_response",
    "W1_public_read",
    "W2_proposal",
    "W3_scoped_action",
    "W4_ambient_workflow",
)
SAMPLING_STRATA = ("utility_probability", "hazard_stratified")
PROTECTION_ARMS = ("M0", "M1")


class OriginalRQ1DesignError(ValueError):
    """Raised when bank provenance or a schedule is not claim-safe."""


@dataclass(frozen=True)
class WorkflowCluster:
    cluster_id: str
    bank_id: str
    source_dataset: str
    source_task_id: str
    source_sha256: str
    source_license: str
    domain: str
    template_lineage_id: str
    utility_class: str
    minimum_authority_level: str
    sampling_strata: tuple[str, ...]
    hazard_routes: tuple[tuple[str, str], ...]
    adversarial_twin_origin: str
    prior_model_exposure: bool
    inclusion_probability: float | None = None
    design_weight: float | None = None

    def __post_init__(self) -> None:
        for field in (
            "cluster_id",
            "source_dataset",
            "source_task_id",
            "source_license",
            "domain",
            "template_lineage_id",
            "adversarial_twin_origin",
        ):
            if not isinstance(getattr(self, field), str) or not getattr(self, field):
                raise OriginalRQ1DesignError(f"{field} must be a nonempty string")
        if self.bank_id not in DATA_BANKS:
            raise OriginalRQ1DesignError(f"unknown data bank: {self.bank_id}")
        if (
            len(self.source_sha256) != 64
            or any(ch not in "0123456789abcdef" for ch in self.source_sha256)
        ):
            raise OriginalRQ1DesignError("source_sha256 must be lowercase SHA-256")
        if self.utility_class not in UTILITY_CLASSES:
            raise OriginalRQ1DesignError(
                f"unknown utility class: {self.utility_class}"
            )
        if self.minimum_authority_level not in ORIGINAL_RQ1_LEVEL_ORDER:
            raise OriginalRQ1DesignError(
                f"unknown minimum authority: {self.minimum_authority_level}"
            )
        if not self.sampling_strata or any(
            stratum not in SAMPLING_STRATA for stratum in self.sampling_strata
        ):
            raise OriginalRQ1DesignError("invalid or empty sampling_strata")
        if len(self.sampling_strata) != len(set(self.sampling_strata)):
            raise OriginalRQ1DesignError("sampling_strata must be unique")
        if len(self.hazard_routes) != len(set(self.hazard_routes)):
            raise OriginalRQ1DesignError("hazard routes must be unique")
        for hazard_id, route_id in self.hazard_routes:
            if hazard_id not in ORIGINAL_RQ1_HAZARDS:
                raise OriginalRQ1DesignError(f"unknown hazard: {hazard_id}")
            if route_id not in ORIGINAL_RQ1_HAZARDS[hazard_id]["routes"]:
                raise OriginalRQ1DesignError(
                    f"route {route_id!r} is not registered for {hazard_id}"
                )
        if self.bank_id == "formal_holdout" and self.prior_model_exposure:
            raise OriginalRQ1DesignError(
                "formal workflow cannot have prior model exposure"
            )
        if "utility_probability" in self.sampling_strata:
            if (
                self.inclusion_probability is None
                or not 0.0 < self.inclusion_probability <= 1.0
            ):
                raise OriginalRQ1DesignError(
                    "utility probability stratum requires inclusion_probability"
                )
            expected_weight = 1.0 / self.inclusion_probability
            if self.design_weight is None or abs(self.design_weight - expected_weight) > 1e-9:
                raise OriginalRQ1DesignError(
                    "design_weight must equal inverse inclusion probability"
                )
        elif self.inclusion_probability is not None or self.design_weight is not None:
            raise OriginalRQ1DesignError(
                "non-probability-only cluster cannot declare utility weights"
            )
        object.__setattr__(self, "sampling_strata", tuple(self.sampling_strata))
        object.__setattr__(self, "hazard_routes", tuple(self.hazard_routes))

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["sampling_strata"] = list(self.sampling_strata)
        result["hazard_routes"] = [
            {"hazard_id": hazard, "route_id": route}
            for hazard, route in self.hazard_routes
        ]
        return result


def audit_bank_disjointness(
    development: Iterable[WorkflowCluster],
    formal: Iterable[WorkflowCluster],
) -> dict[str, Any]:
    development_rows = tuple(development)
    formal_rows = tuple(formal)
    wrong_bank_rows = [
        row.cluster_id
        for row in development_rows
        if row.bank_id != "development"
    ] + [
        row.cluster_id
        for row in formal_rows
        if row.bank_id != "formal_holdout"
    ]

    def values(rows: tuple[WorkflowCluster, ...], attribute: str) -> set[Any]:
        return {getattr(row, attribute) for row in rows}

    dev_sources = {
        (row.source_dataset, row.source_task_id) for row in development_rows
    }
    formal_sources = {
        (row.source_dataset, row.source_task_id) for row in formal_rows
    }
    overlaps = {
        "cluster_id": sorted(
            values(development_rows, "cluster_id")
            & values(formal_rows, "cluster_id")
        ),
        "source_task": sorted(dev_sources & formal_sources),
        "template_lineage_id": sorted(
            values(development_rows, "template_lineage_id")
            & values(formal_rows, "template_lineage_id")
        ),
    }
    duplicates = {
        "development_cluster_id": _duplicates(
            row.cluster_id for row in development_rows
        ),
        "formal_cluster_id": _duplicates(row.cluster_id for row in formal_rows),
        "development_source_task": _duplicates(
            (row.source_dataset, row.source_task_id) for row in development_rows
        ),
        "formal_source_task": _duplicates(
            (row.source_dataset, row.source_task_id) for row in formal_rows
        ),
    }
    exposed_formal = sorted(
        row.cluster_id for row in formal_rows if row.prior_model_exposure
    )
    passed = bool(development_rows) and bool(formal_rows) and not (
        wrong_bank_rows
        or exposed_formal
        or any(overlaps.values())
        or any(duplicates.values())
    )
    return {
        "passed": passed,
        "development_count": len(development_rows),
        "formal_count": len(formal_rows),
        "wrong_bank_rows": sorted(wrong_bank_rows),
        "exposed_formal_rows": exposed_formal,
        "overlaps": overlaps,
        "duplicates": duplicates,
    }


def _duplicates(values: Iterable[Any]) -> list[Any]:
    seen: set[Any] = set()
    duplicates: set[Any] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    return sorted(duplicates)


@dataclass(frozen=True)
class OriginalRQ1ScheduleRow:
    ordinal: int
    episode_id: str
    block_id: str
    pair_id: str
    cluster_id: str
    bank_id: str
    original_authority_level: str
    arm: str
    condition_id: str
    role: str
    hazard_id: str | None
    route_id: str | None
    randomized_seed: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_blocked_schedule(
    clusters: Iterable[WorkflowCluster], *, seed: int
) -> tuple[OriginalRQ1ScheduleRow, ...]:
    """Create reproducible complete blocks with adjacent M0/M1 pairs."""

    if isinstance(seed, bool) or not isinstance(seed, int):
        raise OriginalRQ1DesignError("seed must be an integer")
    rows = list(clusters)
    if not rows:
        raise OriginalRQ1DesignError("at least one workflow cluster is required")
    if len({row.bank_id for row in rows}) != 1:
        raise OriginalRQ1DesignError("a schedule cannot mix development and formal banks")
    if len({row.cluster_id for row in rows}) != len(rows):
        raise OriginalRQ1DesignError("schedule clusters must be unique")

    rng = random.Random(seed)
    rng.shuffle(rows)
    scheduled: list[OriginalRQ1ScheduleRow] = []
    ordinal = 0
    pair_index = rng.randrange(2)
    for cluster in rows:
        levels = list(ORIGINAL_RQ1_LEVEL_ORDER)
        rng.shuffle(levels)
        tasks: list[tuple[str, str | None, str | None]] = [
            ("benign", None, None)
        ] + [
            ("adversarial", hazard_id, route_id)
            for hazard_id, route_id in cluster.hazard_routes
        ]
        rng.shuffle(tasks)
        for level in levels:
            for role, hazard_id, route_id in tasks:
                pair_index += 1
                arm_order = (
                    PROTECTION_ARMS
                    if pair_index % 2 == 0
                    else tuple(reversed(PROTECTION_ARMS))
                )
                pair_payload = {
                    "cluster_id": cluster.cluster_id,
                    "bank_id": cluster.bank_id,
                    "authority": level,
                    "role": role,
                    "hazard_id": hazard_id,
                    "route_id": route_id,
                    "seed": seed,
                }
                pair_id = f"pair-{sha256_json(pair_payload)[:20]}"
                for arm in arm_order:
                    ordinal += 1
                    condition_id = f"ORIG-RQ1-{level}-{arm}"
                    episode_payload = {
                        **pair_payload,
                        "arm": arm,
                        "ordinal": ordinal,
                    }
                    scheduled.append(
                        OriginalRQ1ScheduleRow(
                            ordinal=ordinal,
                            episode_id=f"episode-{sha256_json(episode_payload)[:24]}",
                            block_id=f"block-{cluster.cluster_id}",
                            pair_id=pair_id,
                            cluster_id=cluster.cluster_id,
                            bank_id=cluster.bank_id,
                            original_authority_level=level,
                            arm=arm,
                            condition_id=condition_id,
                            role=role,
                            hazard_id=hazard_id,
                            route_id=route_id,
                            randomized_seed=seed,
                        )
                    )
    audit = audit_blocked_schedule(scheduled)
    if not audit["passed"]:
        raise OriginalRQ1DesignError(
            f"generated schedule failed its own audit: {audit['errors']}"
        )
    return tuple(scheduled)


def audit_blocked_schedule(
    rows: Iterable[OriginalRQ1ScheduleRow],
) -> dict[str, Any]:
    scheduled = tuple(rows)
    errors: list[str] = []
    if not scheduled:
        return {"passed": False, "errors": ["empty_schedule"]}
    if [row.ordinal for row in scheduled] != list(range(1, len(scheduled) + 1)):
        errors.append("ordinals_not_contiguous")
    if len({row.episode_id for row in scheduled}) != len(scheduled):
        errors.append("duplicate_episode_id")
    if len({row.bank_id for row in scheduled}) != 1:
        errors.append("mixed_banks")

    by_pair: dict[str, list[OriginalRQ1ScheduleRow]] = {}
    for row in scheduled:
        by_pair.setdefault(row.pair_id, []).append(row)
    m0_first = 0
    m1_first = 0
    for pair_id, pair in by_pair.items():
        pair = sorted(pair, key=lambda row: row.ordinal)
        if len(pair) != 2 or {row.arm for row in pair} != set(PROTECTION_ARMS):
            errors.append(f"invalid_pair:{pair_id}")
            continue
        if pair[1].ordinal != pair[0].ordinal + 1:
            errors.append(f"nonadjacent_pair:{pair_id}")
        invariant = {
            (
                row.cluster_id,
                row.bank_id,
                row.original_authority_level,
                row.role,
                row.hazard_id,
                row.route_id,
            )
            for row in pair
        }
        if len(invariant) != 1:
            errors.append(f"pair_changes_more_than_arm:{pair_id}")
        m0_first += pair[0].arm == "M0"
        m1_first += pair[0].arm == "M1"
    if abs(m0_first - m1_first) > 1:
        errors.append("arm_order_not_counterbalanced")

    condition_ids = {
        f"ORIG-RQ1-{level}-{arm}"
        for level in ORIGINAL_RQ1_LEVEL_ORDER
        for arm in PROTECTION_ARMS
    }
    if any(row.condition_id not in condition_ids for row in scheduled):
        errors.append("unknown_condition_id")
    return {
        "passed": not errors,
        "errors": errors,
        "row_count": len(scheduled),
        "pair_count": len(by_pair),
        "cluster_count": len({row.cluster_id for row in scheduled}),
        "m0_first": m0_first,
        "m1_first": m1_first,
        "schedule_sha256": sha256_json([row.to_dict() for row in scheduled]),
    }
