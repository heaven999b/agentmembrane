"""Claim-safe bank, split, schedule, and seal primitives for original RQ1 v3.

This module is deliberately data-source agnostic.  Source reviewers must first
provide task semantics, lineage metadata, checker contracts, and route
applicability.  The code here only groups those records, selects whole lineage
components, freezes design weights, and constructs the matched A0--A4 x B1/M1
schedule.  It never opens a formal payload or approves task semantics.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, replace
from datetime import datetime
from typing import Any, Iterable, Mapping, Sequence

from .schema import sha256_json


LEVELS = ("A0", "A1", "A2", "A3", "A4")
ARMS = ("B1", "M1")
HAZARDS = ("H-MEM", "H-TOOL", "H-XAG", "H-CAP", "H-CTRL")
BANKS = ("development", "formal_holdout")
APPLICABILITY_STATES = ("applicable", "not_applicable", "unresolved")
ROUTE_STATES = (
    "structurally_unavailable",
    "candidate_requires_witness",
    "reachable_witnessed",
    "invalid_contract_breach",
)


class OriginalRQ1V3BankError(ValueError):
    """Raised when a bank or schedule would not support the frozen claim."""


def _is_sha256(value: str) -> bool:
    if value.startswith("sha256:"):
        value = value[7:]
    return len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def _require_sha256(name: str, value: str) -> None:
    if not isinstance(value, str) or not _is_sha256(value):
        raise OriginalRQ1V3BankError(f"{name} must be a lowercase SHA-256")


def _require_nonempty(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise OriginalRQ1V3BankError(f"{name} must be a nonempty string")


def _duplicates(values: Iterable[Any]) -> list[Any]:
    seen: set[Any] = set()
    duplicated: set[Any] = set()
    for value in values:
        if value in seen:
            duplicated.add(value)
        seen.add(value)
    return sorted(duplicated)


@dataclass(frozen=True)
class RouteApplicability:
    """Outcome-blind task/route applicability adjudication."""

    hazard_id: str
    route_id: str
    applicability: str
    reason_code: str
    required_legitimate_operation: str | None
    required_visible_operations: tuple[str, ...]
    first_reachable_level: str | None
    reachability_status: str
    reachability_witness_sha256: str | None
    attack_template_lineage_id: str | None
    fixed_terminal_event: str | None
    effect_target_sha256: str | None
    adjudication_version: str

    def __post_init__(self) -> None:
        if self.hazard_id not in HAZARDS:
            raise OriginalRQ1V3BankError(f"unknown hazard: {self.hazard_id}")
        for name in ("route_id", "reason_code", "adjudication_version"):
            _require_nonempty(name, getattr(self, name))
        if self.applicability not in APPLICABILITY_STATES:
            raise OriginalRQ1V3BankError(
                f"unknown applicability state: {self.applicability}"
            )
        if self.reachability_status not in ROUTE_STATES:
            raise OriginalRQ1V3BankError(
                f"unknown reachability status: {self.reachability_status}"
            )
        if len(self.required_visible_operations) != len(
            set(self.required_visible_operations)
        ):
            raise OriginalRQ1V3BankError("required visible operations must be unique")
        if self.first_reachable_level is not None and self.first_reachable_level not in LEVELS:
            raise OriginalRQ1V3BankError("first_reachable_level must be A0--A4 or null")
        if self.applicability == "applicable":
            if self.reachability_status != "reachable_witnessed":
                raise OriginalRQ1V3BankError(
                    "an applicable route must be reachable_witnessed"
                )
            for name in (
                "required_legitimate_operation",
                "first_reachable_level",
                "attack_template_lineage_id",
                "fixed_terminal_event",
            ):
                value = getattr(self, name)
                if not isinstance(value, str) or not value:
                    raise OriginalRQ1V3BankError(
                        f"applicable route requires {name}"
                    )
            for name in ("reachability_witness_sha256", "effect_target_sha256"):
                value = getattr(self, name)
                if not isinstance(value, str):
                    raise OriginalRQ1V3BankError(f"applicable route requires {name}")
                _require_sha256(name, value)
            if not self.required_visible_operations:
                raise OriginalRQ1V3BankError(
                    "applicable route requires visible operations"
                )
        object.__setattr__(
            self, "required_visible_operations", tuple(self.required_visible_operations)
        )

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["required_visible_operations"] = list(
            self.required_visible_operations
        )
        return result


@dataclass(frozen=True)
class CandidateRecord:
    """Metadata-only candidate frame row supplied by semantic reviewers."""

    candidate_id: str
    cluster_id: str
    source_dataset: str
    source_task_id: str
    source_payload_sha256: str
    source_template_id: str
    source_template_sha256: str
    parameter_family_id: str
    normalized_task_contract_sha256: str
    authorized_effect_target_sha256: str
    checker_contract_sha256: str
    initial_state_sha256: str
    domain: str
    utility_eligible: bool
    utility_stratum: str
    route_applicability: tuple[RouteApplicability, ...]
    historical_exposure_component_id: str
    prior_model_exposure: bool
    prior_human_tuning_exposure: bool
    eligibility_status: str
    exclusion_reasons: tuple[str, ...]
    source_program_sha256: str | None = None
    source_scenario_sha256: str | None = None
    generator_lineage_id: str | None = None
    benchmark_family_id: str | None = None
    normalized_prompt_sha256: str | None = None
    prohibited_effect_target_family_sha256: str | None = None
    twin_lineage_id: str | None = None
    paraphrase_lineage_id: str | None = None
    checker_fixture_lineage_id: str | None = None
    lineage_links: tuple[str, ...] = ()
    declared_lineage_group_id: str | None = None

    def __post_init__(self) -> None:
        for name in (
            "candidate_id",
            "cluster_id",
            "source_dataset",
            "source_task_id",
            "source_template_id",
            "parameter_family_id",
            "domain",
            "utility_stratum",
            "historical_exposure_component_id",
        ):
            _require_nonempty(name, getattr(self, name))
        for name in (
            "source_payload_sha256",
            "source_template_sha256",
            "normalized_task_contract_sha256",
            "authorized_effect_target_sha256",
            "checker_contract_sha256",
            "initial_state_sha256",
        ):
            _require_sha256(name, getattr(self, name))
        for name in (
            "source_program_sha256",
            "source_scenario_sha256",
            "normalized_prompt_sha256",
            "prohibited_effect_target_family_sha256",
        ):
            value = getattr(self, name)
            if value is not None:
                _require_sha256(name, value)
        if self.declared_lineage_group_id is not None:
            _require_sha256(
                "declared_lineage_group_id", self.declared_lineage_group_id
            )
        if self.eligibility_status not in {"eligible", "exclude", "unresolved"}:
            raise OriginalRQ1V3BankError(
                f"unknown eligibility status: {self.eligibility_status}"
            )
        if self.eligibility_status == "eligible" and self.exclusion_reasons:
            raise OriginalRQ1V3BankError(
                "eligible candidate cannot declare exclusion reasons"
            )
        if self.eligibility_status != "eligible" and not self.exclusion_reasons:
            raise OriginalRQ1V3BankError(
                "non-eligible candidate requires an exclusion reason"
            )
        route_keys = [(route.hazard_id, route.route_id) for route in self.route_applicability]
        if _duplicates(route_keys):
            raise OriginalRQ1V3BankError("candidate route decisions must be unique")
        if self.candidate_id in self.lineage_links:
            raise OriginalRQ1V3BankError("candidate cannot link to itself")
        object.__setattr__(self, "route_applicability", tuple(self.route_applicability))
        object.__setattr__(self, "exclusion_reasons", tuple(self.exclusion_reasons))
        object.__setattr__(self, "lineage_links", tuple(self.lineage_links))

    def to_dict(self, *, lineage_group_id: str | None = None) -> dict[str, Any]:
        result = asdict(self)
        result["route_applicability"] = [
            route.to_dict() for route in self.route_applicability
        ]
        result["exclusion_reasons"] = list(self.exclusion_reasons)
        result["lineage_links"] = list(self.lineage_links)
        if lineage_group_id is not None:
            result["lineage_group_id"] = lineage_group_id
        return result


class _UnionFind:
    def __init__(self, values: Iterable[str]) -> None:
        self.parent = {value: value for value in values}

    def find(self, value: str) -> str:
        parent = self.parent[value]
        if parent != value:
            self.parent[value] = self.find(parent)
        return self.parent[value]

    def union(self, left: str, right: str) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            if left_root > right_root:
                left_root, right_root = right_root, left_root
            self.parent[right_root] = left_root


def _lineage_keys(candidate: CandidateRecord) -> tuple[tuple[str, str], ...]:
    values: list[tuple[str, str]] = [
        # ``cluster_id`` is the source-workflow cluster, not an observation ID.
        # Multiple task contracts or transformed variants may therefore share
        # it and must remain in one independent lineage component.
        ("source_workflow_cluster", candidate.cluster_id),
        ("source_task", f"{candidate.source_dataset}\0{candidate.source_task_id}"),
        ("source_payload", candidate.source_payload_sha256),
        ("source_template", candidate.source_template_sha256),
        ("parameter_family", candidate.parameter_family_id),
        ("task_contract", candidate.normalized_task_contract_sha256),
        ("authorized_effect_target", candidate.authorized_effect_target_sha256),
        ("historical_exposure", candidate.historical_exposure_component_id),
    ]
    optional = {
        "source_program": candidate.source_program_sha256,
        "source_scenario": candidate.source_scenario_sha256,
        "generator_lineage": candidate.generator_lineage_id,
        "benchmark_family": candidate.benchmark_family_id,
        "normalized_prompt": candidate.normalized_prompt_sha256,
        "prohibited_effect_target": candidate.prohibited_effect_target_family_sha256,
        "twin_lineage": candidate.twin_lineage_id,
        "paraphrase_lineage": candidate.paraphrase_lineage_id,
        "checker_fixture_lineage": candidate.checker_fixture_lineage_id,
    }
    values.extend((name, value) for name, value in optional.items() if value)
    values.extend(("attack_template_lineage", route.attack_template_lineage_id) for route in candidate.route_applicability if route.attack_template_lineage_id)
    return tuple(sorted(values))


@dataclass(frozen=True)
class LineageGroup:
    lineage_group_id: str
    member_candidate_ids: tuple[str, ...]
    member_cluster_ids: tuple[str, ...]
    relation_fingerprint_sha256: str
    prior_exposure: bool

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["member_candidate_ids"] = list(self.member_candidate_ids)
        result["member_cluster_ids"] = list(self.member_cluster_ids)
        return result


@dataclass(frozen=True)
class LineageGraph:
    groups: tuple[LineageGroup, ...]
    candidate_to_group: Mapping[str, str]
    graph_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "groups": [group.to_dict() for group in self.groups],
            "candidate_to_group": dict(sorted(self.candidate_to_group.items())),
            "graph_sha256": self.graph_sha256,
        }


def build_lineage_graph(candidates: Iterable[CandidateRecord]) -> LineageGraph:
    rows = tuple(candidates)
    if not rows:
        raise OriginalRQ1V3BankError("candidate frame cannot be empty")
    if _duplicates(row.candidate_id for row in rows):
        raise OriginalRQ1V3BankError("candidate IDs must be unique")

    by_id = {row.candidate_id: row for row in rows}
    union = _UnionFind(by_id)
    by_key: dict[tuple[str, str], list[str]] = defaultdict(list)
    for row in rows:
        for key in _lineage_keys(row):
            by_key[key].append(row.candidate_id)
        for linked_id in row.lineage_links:
            if linked_id not in by_id:
                raise OriginalRQ1V3BankError(
                    f"lineage link references unknown candidate: {linked_id}"
                )
            union.union(row.candidate_id, linked_id)
    for member_ids in by_key.values():
        for candidate_id in member_ids[1:]:
            union.union(member_ids[0], candidate_id)

    components: dict[str, list[CandidateRecord]] = defaultdict(list)
    for row in rows:
        components[union.find(row.candidate_id)].append(row)

    groups: list[LineageGroup] = []
    candidate_to_group: dict[str, str] = {}
    for members in components.values():
        member_ids = {row.candidate_id for row in members}
        relations = [
            {
                "kind": kind,
                "value_sha256": sha256_json(value),
                "members": sorted(member_ids & set(ids)),
            }
            for (kind, value), ids in sorted(by_key.items())
            if len(member_ids & set(ids)) >= 1
        ]
        explicit_links = sorted(
            [row.candidate_id, linked]
            for row in members
            for linked in row.lineage_links
            if linked in member_ids and row.candidate_id < linked
        )
        identity = {
            "members": [
                {
                    "candidate_id": row.candidate_id,
                    "cluster_id": row.cluster_id,
                    "source_dataset": row.source_dataset,
                    "source_task_id": row.source_task_id,
                    "source_payload_sha256": row.source_payload_sha256,
                }
                for row in sorted(members, key=lambda item: item.candidate_id)
            ],
            "relations": relations,
            "explicit_links": explicit_links,
        }
        relation_hash = sha256_json(identity)
        group_id = f"sha256:{relation_hash}"
        for row in members:
            if row.declared_lineage_group_id is not None and row.declared_lineage_group_id != group_id:
                raise OriginalRQ1V3BankError(
                    f"declared lineage group mismatch for {row.candidate_id}"
                )
            candidate_to_group[row.candidate_id] = group_id
        groups.append(
            LineageGroup(
                lineage_group_id=group_id,
                member_candidate_ids=tuple(sorted(member_ids)),
                member_cluster_ids=tuple(sorted({row.cluster_id for row in members})),
                relation_fingerprint_sha256=relation_hash,
                prior_exposure=any(
                    row.prior_model_exposure or row.prior_human_tuning_exposure
                    for row in members
                ),
            )
        )
    groups.sort(key=lambda group: group.lineage_group_id)
    payload = {
        "groups": [group.to_dict() for group in groups],
        "candidate_to_group": dict(sorted(candidate_to_group.items())),
    }
    return LineageGraph(
        groups=tuple(groups),
        candidate_to_group=candidate_to_group,
        graph_sha256=sha256_json(payload),
    )


@dataclass(frozen=True)
class BankAssignment:
    candidate_id: str
    cluster_id: str
    lineage_group_id: str
    bank_id: str
    selection_stratum: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class FrozenWeight:
    weight_id: str
    estimand: str
    lineage_group_id: str
    stratum: str
    target_mass: float
    eligible_group_count: int
    inclusion_probability: float
    raw_design_weight: float
    normalized_weight: float
    hazard_id: str | None = None
    route_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class BankSplit:
    selection_seed: int
    candidate_frame_sha256: str
    lineage_graph: LineageGraph
    assignments: tuple[BankAssignment, ...]
    excluded_candidate_ids: tuple[str, ...]
    old_exposed_identifiers: tuple[str, ...]
    utility_weights: tuple[FrozenWeight, ...]
    safety_weights: tuple[FrozenWeight, ...]
    split_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "selection_seed": self.selection_seed,
            "candidate_frame_sha256": self.candidate_frame_sha256,
            "lineage_graph": self.lineage_graph.to_dict(),
            "assignments": [row.to_dict() for row in self.assignments],
            "excluded_candidate_ids": list(self.excluded_candidate_ids),
            "old_exposed_identifiers": list(self.old_exposed_identifiers),
            "utility_weights": [row.to_dict() for row in self.utility_weights],
            "safety_weights": [row.to_dict() for row in self.safety_weights],
            "split_sha256": self.split_sha256,
        }


def _validate_target_masses(name: str, masses: Mapping[str, float]) -> None:
    if not masses:
        raise OriginalRQ1V3BankError(f"{name} cannot be empty")
    if any(isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0 for value in masses.values()):
        raise OriginalRQ1V3BankError(f"{name} values must be positive numbers")
    if abs(sum(float(value) for value in masses.values()) - 1.0) > 1e-12:
        raise OriginalRQ1V3BankError(f"{name} must sum to one")


def _group_sampling_stratum(strata: Iterable[str]) -> str:
    """Return the sampling profile for one independent lineage component.

    A lineage that supplies both W0 and W2 tasks is sampled once from the
    composite profile, rather than independently once per task stratum.  The
    task-level strata remain available for utility weighting after selection.
    """

    values = tuple(sorted(set(strata)))
    if not values:
        raise OriginalRQ1V3BankError("lineage group has no eligible task stratum")
    if len(values) == 1:
        return values[0]
    return f"multistratum[{'|'.join(values)}]"


def split_candidate_frame(
    candidates: Iterable[CandidateRecord],
    *,
    formal_counts_by_stratum: Mapping[str, int],
    development_counts_by_stratum: Mapping[str, int] | None,
    utility_target_masses: Mapping[str, float],
    safety_target_masses: Mapping[str, float],
    selection_seed: int,
    old_exposed_identifiers: Iterable[str] = (),
) -> BankSplit:
    """Select whole lineage components and freeze inclusion/design weights.

    ``old_exposed_identifiers`` can contain candidate IDs, historical exposure
    component IDs, or computed/declared lineage group IDs.  Any matching group
    is barred from formal selection but remains eligible for development.
    """

    if isinstance(selection_seed, bool) or not isinstance(selection_seed, int):
        raise OriginalRQ1V3BankError("selection_seed must be an integer")
    rows = tuple(candidates)
    graph = build_lineage_graph(rows)
    by_id = {row.candidate_id: row for row in rows}
    groups_by_id = {group.lineage_group_id: group for group in graph.groups}
    old_exposed = frozenset(str(value) for value in old_exposed_identifiers)
    _validate_target_masses("utility_target_masses", utility_target_masses)
    _validate_target_masses("safety_target_masses", safety_target_masses)

    excluded_ids = {
        row.candidate_id
        for row in rows
        if row.eligibility_status != "eligible"
        or any(route.applicability == "unresolved" for route in row.route_applicability)
    }
    eligible_group_members: dict[str, list[CandidateRecord]] = defaultdict(list)
    for row in rows:
        if row.candidate_id not in excluded_ids:
            eligible_group_members[graph.candidate_to_group[row.candidate_id]].append(row)

    group_stratum: dict[str, str] = {}
    group_utility_strata: dict[str, frozenset[str]] = {}
    group_exposed: dict[str, bool] = {}
    for group_id, members in eligible_group_members.items():
        strata = frozenset(row.utility_stratum for row in members)
        group_utility_strata[group_id] = strata
        group_stratum[group_id] = _group_sampling_stratum(strata)
        identifiers = {
            group_id,
            *groups_by_id[group_id].member_candidate_ids,
            *(row.historical_exposure_component_id for row in members),
            *(row.declared_lineage_group_id for row in members if row.declared_lineage_group_id),
        }
        group_exposed[group_id] = groups_by_id[group_id].prior_exposure or bool(
            identifiers & old_exposed
        )

    available_strata = set(group_stratum.values())
    if set(formal_counts_by_stratum) != available_strata:
        raise OriginalRQ1V3BankError(
            "formal counts must cover every and only eligible selection stratum"
        )
    if development_counts_by_stratum is not None and set(development_counts_by_stratum) != available_strata:
        raise OriginalRQ1V3BankError(
            "development counts must cover every and only eligible selection stratum"
        )
    for mapping_name, counts in (
        ("formal", formal_counts_by_stratum),
        ("development", development_counts_by_stratum or {}),
    ):
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in counts.values()):
            raise OriginalRQ1V3BankError(
                f"{mapping_name} counts must be nonnegative integers"
            )

    groups_in_stratum: dict[str, list[str]] = defaultdict(list)
    for group_id, stratum in group_stratum.items():
        groups_in_stratum[stratum].append(group_id)
    groups_in_utility_stratum: dict[str, list[str]] = defaultdict(list)
    for group_id, strata in group_utility_strata.items():
        for stratum in strata:
            groups_in_utility_stratum[stratum].append(group_id)

    formal_utility_strata = {
        row.utility_stratum
        for group_id, members in eligible_group_members.items()
        if not group_exposed[group_id]
        for row in members
        if row.utility_eligible
    }
    if set(utility_target_masses) != formal_utility_strata:
        raise OriginalRQ1V3BankError(
            "utility target masses must cover every and only unexposed eligible task stratum"
        )
    formal_safety_strata = {
        f"{decision.hazard_id}:{decision.route_id}"
        for group_id, members in eligible_group_members.items()
        if not group_exposed[group_id]
        for member in members
        for decision in member.route_applicability
        if decision.applicability == "applicable"
    }
    if set(safety_target_masses) != formal_safety_strata:
        raise OriginalRQ1V3BankError(
            "safety target masses must cover every and only unexposed applicable route stratum"
        )

    formal_groups: set[str] = set()
    development_groups: set[str] = set()
    formal_inclusion_probability: dict[str, float] = {}
    for stratum in sorted(available_strata):
        all_groups = sorted(groups_in_stratum[stratum])
        formal_frame = [group_id for group_id in all_groups if not group_exposed[group_id]]
        formal_n = formal_counts_by_stratum[stratum]
        if formal_n > len(formal_frame):
            raise OriginalRQ1V3BankError(
                f"insufficient unexposed groups in {stratum} for formal selection"
            )
        ordered = sorted(
            formal_frame,
            key=lambda group_id: sha256_json(
                {"selection_seed": selection_seed, "stratum": stratum, "group": group_id}
            ),
        )
        chosen_formal = set(ordered[:formal_n])
        formal_groups.update(chosen_formal)
        if formal_n:
            probability = formal_n / len(formal_frame)
            formal_inclusion_probability.update(
                {group_id: probability for group_id in formal_frame}
            )
        remaining = [group_id for group_id in all_groups if group_id not in chosen_formal]
        dev_n = len(remaining) if development_counts_by_stratum is None else development_counts_by_stratum[stratum]
        if dev_n > len(remaining):
            raise OriginalRQ1V3BankError(
                f"insufficient remaining groups in {stratum} for development selection"
            )
        ordered_dev = sorted(
            remaining,
            key=lambda group_id: sha256_json(
                {"selection_seed": selection_seed, "stratum": stratum, "development_group": group_id}
            ),
        )
        development_groups.update(ordered_dev[:dev_n])

    assignments: list[BankAssignment] = []
    for row in rows:
        group_id = graph.candidate_to_group[row.candidate_id]
        bank_id = (
            "formal_holdout"
            if group_id in formal_groups
            else "development"
            if group_id in development_groups
            else None
        )
        if bank_id is not None and row.candidate_id not in excluded_ids:
            assignments.append(
                BankAssignment(
                    candidate_id=row.candidate_id,
                    cluster_id=row.cluster_id,
                    lineage_group_id=group_id,
                    bank_id=bank_id,
                    selection_stratum=group_stratum[group_id],
                )
            )
    assignments.sort(key=lambda row: (row.bank_id, row.lineage_group_id, row.candidate_id))

    formal_assigned_groups = {row.lineage_group_id for row in assignments if row.bank_id == "formal_holdout"}
    utility_raw: list[FrozenWeight] = []
    for stratum, target_mass in sorted(utility_target_masses.items()):
        frame_groups = {
            group_id
            for group_id in groups_in_utility_stratum.get(stratum, ())
            if not group_exposed[group_id]
            and any(row.utility_eligible for row in eligible_group_members[group_id])
        }
        selected = sorted(frame_groups & formal_assigned_groups)
        if not frame_groups or not selected:
            raise OriginalRQ1V3BankError(
                f"utility stratum lacks formal support: {stratum}"
            )
        for group_id in selected:
            inclusion = formal_inclusion_probability[group_id]
            population_mass = float(target_mass) / len(frame_groups)
            raw_weight = population_mass / inclusion
            utility_raw.append(
                FrozenWeight(
                    weight_id="pending",
                    estimand="utility",
                    lineage_group_id=group_id,
                    stratum=stratum,
                    target_mass=float(target_mass),
                    eligible_group_count=len(frame_groups),
                    inclusion_probability=inclusion,
                    raw_design_weight=raw_weight,
                    normalized_weight=0.0,
                )
            )
    utility_total = sum(row.raw_design_weight for row in utility_raw)
    utility_weights = tuple(
        replace(
            row,
            weight_id=f"uw-{sha256_json(asdict(row) | {'normalized_weight': row.raw_design_weight / utility_total})[:20]}",
            normalized_weight=row.raw_design_weight / utility_total,
        )
        for row in utility_raw
    )

    safety_raw: list[FrozenWeight] = []
    for route_stratum, target_mass in sorted(safety_target_masses.items()):
        try:
            hazard_id, route_id = route_stratum.split(":", 1)
        except ValueError as exc:
            raise OriginalRQ1V3BankError(
                "safety target-mass keys must be 'hazard_id:route_id'"
            ) from exc
        if hazard_id not in HAZARDS or not route_id:
            raise OriginalRQ1V3BankError(f"invalid safety stratum: {route_stratum}")
        frame_groups = {
            group_id
            for group_id, members in eligible_group_members.items()
            if not group_exposed[group_id]
            and any(
                decision.hazard_id == hazard_id
                and decision.route_id == route_id
                and decision.applicability == "applicable"
                for member in members
                for decision in member.route_applicability
            )
        }
        selected = sorted(frame_groups & formal_assigned_groups)
        if not frame_groups or not selected:
            raise OriginalRQ1V3BankError(
                f"safety stratum lacks formal support: {route_stratum}"
            )
        raw_for_stratum: list[tuple[str, float, float]] = []
        for group_id in selected:
            inclusion = formal_inclusion_probability[group_id]
            raw_for_stratum.append(
                (group_id, inclusion, (float(target_mass) / len(frame_groups)) / inclusion)
            )
        safety_raw.extend(
            FrozenWeight(
                weight_id="pending",
                estimand="safety",
                lineage_group_id=group_id,
                stratum=route_stratum,
                target_mass=float(target_mass),
                eligible_group_count=len(frame_groups),
                inclusion_probability=inclusion,
                raw_design_weight=raw,
                normalized_weight=0.0,
                hazard_id=hazard_id,
                route_id=route_id,
            )
            for group_id, inclusion, raw in raw_for_stratum
        )
    safety_total = sum(row.raw_design_weight for row in safety_raw)
    safety_weights = tuple(
        replace(
            row,
            weight_id=f"sw-{sha256_json(asdict(row) | {'normalized_weight': row.raw_design_weight / safety_total})[:20]}",
            normalized_weight=row.raw_design_weight / safety_total,
        )
        for row in safety_raw
    )

    candidate_frame_payload = [
        row.to_dict(lineage_group_id=graph.candidate_to_group[row.candidate_id])
        for row in sorted(rows, key=lambda item: item.candidate_id)
    ]
    base = {
        "selection_seed": selection_seed,
        "candidate_frame_sha256": sha256_json(candidate_frame_payload),
        "lineage_graph_sha256": graph.graph_sha256,
        "assignments": [row.to_dict() for row in assignments],
        "excluded_candidate_ids": sorted(excluded_ids),
        "old_exposed_identifiers": sorted(old_exposed),
        "utility_weights": [row.to_dict() for row in utility_weights],
        "safety_weights": [row.to_dict() for row in safety_weights],
    }
    split = BankSplit(
        selection_seed=selection_seed,
        candidate_frame_sha256=base["candidate_frame_sha256"],
        lineage_graph=graph,
        assignments=tuple(assignments),
        excluded_candidate_ids=tuple(sorted(excluded_ids)),
        old_exposed_identifiers=tuple(sorted(old_exposed)),
        utility_weights=utility_weights,
        safety_weights=safety_weights,
        split_sha256=sha256_json(base),
    )
    audit = audit_bank_split(split, rows)
    if not audit["passed"]:
        raise OriginalRQ1V3BankError(
            f"generated split failed its own audit: {audit['errors']}"
        )
    return split


def audit_bank_split(
    split: BankSplit, candidates: Iterable[CandidateRecord]
) -> dict[str, Any]:
    rows = tuple(candidates)
    by_id = {row.candidate_id: row for row in rows}
    errors: list[str] = []
    if len(by_id) != len(rows):
        errors.append("duplicate_candidate_id")
    try:
        rebuilt_graph = build_lineage_graph(rows)
    except OriginalRQ1V3BankError as exc:
        rebuilt_graph = None
        errors.append(f"lineage_graph_invalid:{exc}")
    if rebuilt_graph is not None and (
        rebuilt_graph.graph_sha256 != split.lineage_graph.graph_sha256
        or dict(rebuilt_graph.candidate_to_group)
        != dict(split.lineage_graph.candidate_to_group)
    ):
        errors.append("lineage_graph_fingerprint_mismatch")
    if rebuilt_graph is not None:
        candidate_frame_payload = [
            row.to_dict(
                lineage_group_id=rebuilt_graph.candidate_to_group[row.candidate_id]
            )
            for row in sorted(rows, key=lambda item: item.candidate_id)
        ]
        if split.candidate_frame_sha256 != sha256_json(candidate_frame_payload):
            errors.append("candidate_frame_fingerprint_mismatch")
    if _duplicates(row.candidate_id for row in split.assignments):
        errors.append("candidate_assigned_more_than_once")
    dev_groups = {row.lineage_group_id for row in split.assignments if row.bank_id == "development"}
    formal_groups = {row.lineage_group_id for row in split.assignments if row.bank_id == "formal_holdout"}
    if dev_groups & formal_groups:
        errors.append("lineage_overlap")
    if any(row.bank_id not in BANKS for row in split.assignments):
        errors.append("unknown_bank")
    old_exposed = set(split.old_exposed_identifiers)
    groups_by_id = {
        group.lineage_group_id: group for group in split.lineage_graph.groups
    }
    for assignment in split.assignments:
        candidate = by_id.get(assignment.candidate_id)
        if candidate is None:
            errors.append(f"unknown_candidate:{assignment.candidate_id}")
            continue
        if split.lineage_graph.candidate_to_group.get(candidate.candidate_id) != assignment.lineage_group_id:
            errors.append(f"wrong_lineage:{candidate.candidate_id}")
        if candidate.eligibility_status != "eligible" or any(
            route.applicability == "unresolved" for route in candidate.route_applicability
        ):
            errors.append(f"unresolved_or_ineligible_selected:{candidate.candidate_id}")
        group = groups_by_id.get(assignment.lineage_group_id)
        if group is None:
            errors.append(f"unknown_lineage_group:{assignment.lineage_group_id}")
        if assignment.bank_id == "formal_holdout" and (
            candidate.prior_model_exposure
            or candidate.prior_human_tuning_exposure
            or candidate.candidate_id in old_exposed
            or candidate.historical_exposure_component_id in old_exposed
            or assignment.lineage_group_id in old_exposed
            or group is None
            or group.prior_exposure
            or bool(set(group.member_candidate_ids) & old_exposed)
        ):
            errors.append(f"exposed_formal:{candidate.candidate_id}")
    dev_candidates = [by_id[row.candidate_id] for row in split.assignments if row.bank_id == "development" and row.candidate_id in by_id]
    formal_candidates = [by_id[row.candidate_id] for row in split.assignments if row.bank_id == "formal_holdout" and row.candidate_id in by_id]
    dev_keys = {key for row in dev_candidates for key in _lineage_keys(row)}
    formal_keys = {key for row in formal_candidates for key in _lineage_keys(row)}
    if dev_keys & formal_keys:
        errors.append("leakage_key_overlap")
    if split.utility_weights and abs(sum(row.normalized_weight for row in split.utility_weights) - 1.0) > 1e-12:
        errors.append("utility_weights_do_not_sum_to_one")
    if split.safety_weights and abs(sum(row.normalized_weight for row in split.safety_weights) - 1.0) > 1e-12:
        errors.append("safety_weights_do_not_sum_to_one")
    if any(row.inclusion_probability <= 0 or row.inclusion_probability > 1 for row in (*split.utility_weights, *split.safety_weights)):
        errors.append("invalid_inclusion_probability")
    for weight in (*split.utility_weights, *split.safety_weights):
        prefix = "uw-" if weight.estimand == "utility" else "sw-"
        expected_id = f"{prefix}{sha256_json(asdict(replace(weight, weight_id='pending')))[:20]}"
        if weight.weight_id != expected_id:
            errors.append(f"weight_fingerprint_mismatch:{weight.weight_id}")
        if weight.lineage_group_id not in formal_groups:
            errors.append(f"weight_for_nonformal_group:{weight.weight_id}")
    base = {
        "selection_seed": split.selection_seed,
        "candidate_frame_sha256": split.candidate_frame_sha256,
        "lineage_graph_sha256": split.lineage_graph.graph_sha256,
        "assignments": [row.to_dict() for row in split.assignments],
        "excluded_candidate_ids": list(split.excluded_candidate_ids),
        "old_exposed_identifiers": list(split.old_exposed_identifiers),
        "utility_weights": [row.to_dict() for row in split.utility_weights],
        "safety_weights": [row.to_dict() for row in split.safety_weights],
    }
    if split.split_sha256 != sha256_json(base):
        errors.append("split_fingerprint_mismatch")
    return {
        "passed": not errors,
        "errors": errors,
        "development_lineage_count": len(dev_groups),
        "formal_lineage_count": len(formal_groups),
        "development_candidate_count": len(dev_candidates),
        "formal_candidate_count": len(formal_candidates),
        "split_sha256": split.split_sha256,
    }


@dataclass(frozen=True)
class ScheduleRow:
    ordinal: int
    episode_id: str
    track: str
    bank_id: str
    lineage_group_id: str
    cluster_id: str
    pair_role: str
    hazard_id: str | None
    route_id: str | None
    attack_template_lineage_id: str | None
    authority_level: str
    arm: str
    condition_id: str
    replicate_id: str
    generation_seed: int | None
    selection_seed: int
    schedule_seed: int
    pair_id: str
    block_id: str
    counterbalance_stratum: str
    expected_structural_exposure: bool
    task_contract_id: str
    weight_id: str | None
    weight: float | None
    utility_weight_id: str | None
    safety_weight_id: str | None
    initial_state_sha256: str
    task_payload_sha256: str
    target_effect_sha256: str | None
    checker_contract_sha256: str
    prompt_bundle_sha256: str
    surface_contract_sha256: str
    time_block_id: str = ""
    level_order_position: int = -1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    # Read-only aliases keep local callers readable while the serialized row
    # has one canonical vocabulary shared with the artifact ledger.
    @property
    def role(self) -> str:
        return self.pair_role

    @property
    def original_authority_level(self) -> str:
        return self.authority_level

    @property
    def model_seed(self) -> int | None:
        return self.generation_seed

    @property
    def schedule_randomization_seed(self) -> int:
        return self.schedule_seed


def adaptive_block_id(
    *,
    lineage_group_id: str,
    cluster_id: str,
    task_contract_id: str,
    pair_role: str,
    hazard_id: str | None,
    route_id: str | None,
) -> str:
    """Return the route-aware matched block used by bank and ledger audits."""

    return sha256_json(
        {
            "namespace": "original-rq1-v3-adaptive-block-1",
            "lineage_group_id": lineage_group_id,
            "cluster_id": cluster_id,
            "task_contract_id": task_contract_id,
            "pair_role": pair_role,
            "hazard_id": hazard_id,
            "route_id": route_id,
        }
    )


def adaptive_pair_id(
    *,
    lineage_group_id: str,
    cluster_id: str,
    task_contract_id: str,
    pair_role: str,
    hazard_id: str | None,
    route_id: str | None,
    authority_level: str,
    replicate_id: str,
    generation_seed: int | None,
    selection_seed: int,
    schedule_seed: int,
) -> str:
    """Return an arm-independent identity for exactly one B1/M1 pair."""

    return "pair-" + sha256_json(
        {
            "namespace": "original-rq1-v3-adaptive-pair-2",
            "lineage_group_id": lineage_group_id,
            "cluster_id": cluster_id,
            "task_contract_id": task_contract_id,
            "pair_role": pair_role,
            "hazard_id": hazard_id,
            "route_id": route_id,
            "authority_level": authority_level,
            "replicate_id": replicate_id,
            "generation_seed": generation_seed,
            "selection_seed": selection_seed,
            "schedule_seed": schedule_seed,
        }
    )[:24]


def _counterbalance_stratum(
    candidate: CandidateRecord,
    *,
    pair_role: str,
    hazard_id: str | None,
    route_id: str | None,
    replicate_id: str,
) -> str:
    return "cb-" + sha256_json(
        {
            "namespace": "original-rq1-v3-counterbalance-stratum-1",
            "source_dataset": candidate.source_dataset,
            "domain": candidate.domain,
            "pair_role": pair_role,
            "hazard_id": hazard_id,
            "route_id": route_id,
            "replicate_id": replicate_id,
        }
    )[:24]


def _time_block_id(
    counterbalance_stratum: str, batch_index: int, schedule_seed: int
) -> str:
    return "time-" + sha256_json(
        {
            "namespace": "original-rq1-v3-time-block-1",
            "counterbalance_stratum": counterbalance_stratum,
            "batch_index": batch_index,
            "schedule_seed": schedule_seed,
        }
    )[:24]


def _applicable_routes(candidate: CandidateRecord) -> tuple[RouteApplicability, ...]:
    return tuple(
        route
        for route in candidate.route_applicability
        if route.applicability == "applicable"
    )


def build_matched_schedule(
    split: BankSplit,
    candidates: Iterable[CandidateRecord],
    *,
    bank_id: str,
    model_seeds: Sequence[int] | None = None,
    schedule_randomization_seed: int,
    prompt_bundle_sha256: str,
    surface_contract_sha256: str,
    replicate_generation_seeds: Mapping[str, int | None] | None = None,
) -> tuple[ScheduleRow, ...]:
    if bank_id not in BANKS:
        raise OriginalRQ1V3BankError(f"unknown bank: {bank_id}")
    if (model_seeds is None) == (replicate_generation_seeds is None):
        raise OriginalRQ1V3BankError(
            "provide exactly one replication seed specification"
        )
    if model_seeds is not None:
        seeds = tuple(model_seeds)
        if len(seeds) < 3 or len(set(seeds)) != len(seeds) or any(
            isinstance(seed, bool) or not isinstance(seed, int) for seed in seeds
        ):
            raise OriginalRQ1V3BankError(
                "at least three unique integer model seeds are required"
            )
        replications = tuple((f"seed-{seed}", seed) for seed in seeds)
    else:
        assert replicate_generation_seeds is not None
        replications = tuple(sorted(replicate_generation_seeds.items()))
        if len(replications) < 3 or any(
            not isinstance(replicate_id, str)
            or not replicate_id
            or isinstance(seed, bool)
            or (seed is not None and not isinstance(seed, int))
            for replicate_id, seed in replications
        ):
            raise OriginalRQ1V3BankError(
                "at least three replication IDs with integer-or-null generation seeds are required"
            )
        nonnull_seeds = [seed for _, seed in replications if seed is not None]
        if nonnull_seeds and (
            len(nonnull_seeds) != len(replications)
            or len(set(nonnull_seeds)) != len(nonnull_seeds)
        ):
            raise OriginalRQ1V3BankError(
                "generation seeds must be all null or all unique integers"
            )
    if isinstance(schedule_randomization_seed, bool) or not isinstance(schedule_randomization_seed, int):
        raise OriginalRQ1V3BankError(
            "schedule_randomization_seed must be an integer"
        )
    generation_seeds = {
        seed for _, seed in replications if seed is not None
    }
    if split.selection_seed == schedule_randomization_seed or split.selection_seed in generation_seeds or schedule_randomization_seed in generation_seeds:
        raise OriginalRQ1V3BankError(
            "selection, schedule, and model seed values must be distinct"
        )
    _require_sha256("prompt_bundle_sha256", prompt_bundle_sha256)
    _require_sha256("surface_contract_sha256", surface_contract_sha256)
    by_id = {row.candidate_id: row for row in candidates}
    selected = [row for row in split.assignments if row.bank_id == bank_id]
    if not selected:
        raise OriginalRQ1V3BankError(f"no selected candidates for {bank_id}")
    utility_weight = {
        (row.lineage_group_id, row.stratum): row.weight_id
        for row in split.utility_weights
    }
    safety_weight = {
        (row.lineage_group_id, row.hazard_id, row.route_id): row.weight_id
        for row in split.safety_weights
    }

    unit_specs: list[dict[str, Any]] = []
    for assignment in selected:
        candidate = by_id.get(assignment.candidate_id)
        if candidate is None:
            raise OriginalRQ1V3BankError(
                f"selected candidate metadata missing: {assignment.candidate_id}"
            )
        if candidate.eligibility_status != "eligible":
            raise OriginalRQ1V3BankError("schedule cannot contain an ineligible task")
        roles: list[tuple[str, RouteApplicability | None]] = [("honest", None)]
        roles.extend(("adversarial", route) for route in _applicable_routes(candidate))
        for replicate_id, generation_seed in replications:
            for role, route in roles:
                unit_specs.append(
                    {
                        "assignment": assignment,
                        "candidate": candidate,
                        "replicate_id": replicate_id,
                        "generation_seed": generation_seed,
                        "role": role,
                        "route": route,
                        "counterbalance_stratum": _counterbalance_stratum(
                            candidate,
                            pair_role=role,
                            hazard_id=route.hazard_id if route else None,
                            route_id=route.route_id if route else None,
                            replicate_id=replicate_id,
                        ),
                    }
                )

    # Each counterbalance stratum is partitioned into deterministic time blocks
    # of at most five task units.  Cyclic rotations of one seed-derived level
    # permutation make every level occupy every order position once per full
    # block; an incomplete final block differs by at most one.
    units_by_stratum: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for unit in unit_specs:
        units_by_stratum[unit["counterbalance_stratum"]].append(unit)
    pair_specs: list[dict[str, Any]] = []
    for counterbalance_stratum in sorted(units_by_stratum):
        units = sorted(
            units_by_stratum[counterbalance_stratum],
            key=lambda unit: sha256_json(
                {
                    "schedule_seed": schedule_randomization_seed,
                    "counterbalance_stratum": counterbalance_stratum,
                    "lineage_group_id": unit["assignment"].lineage_group_id,
                    "candidate_id": unit["candidate"].candidate_id,
                    "task_contract_id": unit["candidate"].normalized_task_contract_sha256,
                }
            ),
        )
        base_level_order = tuple(
            sorted(
                LEVELS,
                key=lambda level: sha256_json(
                    {
                        "schedule_seed": schedule_randomization_seed,
                        "counterbalance_stratum": counterbalance_stratum,
                        "level": level,
                    }
                ),
            )
        )
        for unit_index, unit in enumerate(units):
            rotation = unit_index % len(LEVELS)
            level_order = (
                base_level_order[rotation:] + base_level_order[:rotation]
            )
            time_block_id = _time_block_id(
                counterbalance_stratum,
                unit_index // len(LEVELS),
                schedule_randomization_seed,
            )
            for position, level in enumerate(level_order):
                pair_specs.append(
                    {
                        **unit,
                        "level": level,
                        "time_block_id": time_block_id,
                        "level_order_position": position,
                    }
                )

    first_arm_counter: dict[tuple[str, str], int] = defaultdict(int)
    result: list[ScheduleRow] = []
    for spec in pair_specs:
        assignment: BankAssignment = spec["assignment"]
        candidate: CandidateRecord = spec["candidate"]
        route: RouteApplicability | None = spec["route"]
        counterbalance_stratum = spec["counterbalance_stratum"]
        arm_balance_key = (spec["time_block_id"], spec["level"])
        arm_order = (
            ARMS
            if first_arm_counter[arm_balance_key] % 2 == 0
            else tuple(reversed(ARMS))
        )
        first_arm_counter[arm_balance_key] += 1
        replicate_id = spec["replicate_id"]
        task_contract_id = candidate.normalized_task_contract_sha256
        route_id = route.route_id if route else None
        block_id = adaptive_block_id(
            lineage_group_id=assignment.lineage_group_id,
            cluster_id=candidate.cluster_id,
            task_contract_id=task_contract_id,
            pair_role=spec["role"],
            hazard_id=route.hazard_id if route else None,
            route_id=route_id,
        )
        utility_weight_id = utility_weight.get(
            (assignment.lineage_group_id, candidate.utility_stratum)
        )
        safety_weight_id = (
            safety_weight.get(
                (assignment.lineage_group_id, route.hazard_id, route.route_id)
            )
            if route
            else None
        )
        selected_weight_id = safety_weight_id if route else utility_weight_id
        selected_weight_lookup = {
            row.weight_id: row.normalized_weight
            for row in (*split.utility_weights, *split.safety_weights)
        }
        pair_id = adaptive_pair_id(
            lineage_group_id=assignment.lineage_group_id,
            cluster_id=candidate.cluster_id,
            task_contract_id=task_contract_id,
            pair_role=spec["role"],
            hazard_id=route.hazard_id if route else None,
            route_id=route_id,
            authority_level=spec["level"],
            replicate_id=replicate_id,
            generation_seed=spec["generation_seed"],
            selection_seed=split.selection_seed,
            schedule_seed=schedule_randomization_seed,
        )
        for arm in arm_order:
            onset_index = LEVELS.index(route.first_reachable_level) if route and route.first_reachable_level else len(LEVELS)
            result.append(
                ScheduleRow(
                    ordinal=len(result) + 1,
                    episode_id="pending",
                    track="adaptive_end_to_end",
                    bank_id=bank_id,
                    lineage_group_id=assignment.lineage_group_id,
                    cluster_id=candidate.cluster_id,
                    pair_role=spec["role"],
                    hazard_id=route.hazard_id if route else None,
                    route_id=route_id,
                    attack_template_lineage_id=route.attack_template_lineage_id if route else None,
                    authority_level=spec["level"],
                    arm=arm,
                    condition_id=f"ORIG-RQ1-V3-{spec['level']}-{arm}",
                    replicate_id=replicate_id,
                    generation_seed=spec["generation_seed"],
                    selection_seed=split.selection_seed,
                    schedule_seed=schedule_randomization_seed,
                    pair_id=pair_id,
                    block_id=block_id,
                    counterbalance_stratum=counterbalance_stratum,
                    expected_structural_exposure=(
                        route is not None and LEVELS.index(spec["level"]) >= onset_index
                    ),
                    task_contract_id=task_contract_id,
                    weight_id=selected_weight_id,
                    weight=selected_weight_lookup.get(selected_weight_id),
                    utility_weight_id=utility_weight_id,
                    safety_weight_id=safety_weight_id,
                    initial_state_sha256=candidate.initial_state_sha256,
                    task_payload_sha256=candidate.source_payload_sha256,
                    target_effect_sha256=route.effect_target_sha256 if route else None,
                    checker_contract_sha256=candidate.checker_contract_sha256,
                    prompt_bundle_sha256=prompt_bundle_sha256,
                    surface_contract_sha256=surface_contract_sha256,
                    time_block_id=spec["time_block_id"],
                    level_order_position=spec["level_order_position"],
                )
            )
            result[-1] = replace(
                result[-1],
                episode_id=sha256_json(
                    {
                        key: value
                        for key, value in result[-1].to_dict().items()
                        if key != "episode_id"
                    }
                ),
            )
    scheduled = tuple(result)
    audit = audit_matched_schedule(
        scheduled,
        selected_candidates=[by_id[row.candidate_id] for row in selected],
        expected_replications=dict(replications),
    )
    if not audit["passed"]:
        raise OriginalRQ1V3BankError(
            f"generated schedule failed its own audit: {audit['errors']}"
        )
    return scheduled


def audit_matched_schedule(
    rows: Iterable[ScheduleRow],
    *,
    selected_candidates: Iterable[CandidateRecord] | None = None,
    expected_replications: Mapping[str, int | None] | None = None,
) -> dict[str, Any]:
    scheduled = tuple(rows)
    errors: list[str] = []
    if not scheduled:
        return {"passed": False, "errors": ["empty_schedule"]}
    if [row.ordinal for row in scheduled] != list(range(1, len(scheduled) + 1)):
        errors.append("ordinals_not_contiguous")
    if _duplicates(row.episode_id for row in scheduled):
        errors.append("duplicate_episode_id")
    if len({row.bank_id for row in scheduled}) != 1:
        errors.append("mixed_banks")
    if len({row.selection_seed for row in scheduled}) != 1:
        errors.append("mixed_selection_seeds")
    if len({row.schedule_seed for row in scheduled}) != 1:
        errors.append("mixed_schedule_seeds")
    replicate_ids = {row.replicate_id for row in scheduled}
    if len(replicate_ids) < 3:
        errors.append("fewer_than_three_replications")
    generation_seeds = {row.generation_seed for row in scheduled}
    if None in generation_seeds:
        if generation_seeds != {None}:
            errors.append("mixed_generation_seed_support")
    elif len(generation_seeds) < 3:
        errors.append("fewer_than_three_generation_seeds")
    observed_replications: dict[str, set[int | None]] = defaultdict(set)
    for row in scheduled:
        observed_replications[row.replicate_id].add(row.generation_seed)
    if any(len(values) != 1 for values in observed_replications.values()):
        errors.append("replicate_maps_to_multiple_generation_seeds")
    if expected_replications is not None:
        if set(observed_replications) != set(expected_replications):
            errors.append("missing_or_extra_replication")
        for replicate_id, expected_seed in expected_replications.items():
            if observed_replications.get(replicate_id) != {expected_seed}:
                errors.append(f"replication_seed_mismatch:{replicate_id}")

    by_pair: dict[str, list[ScheduleRow]] = defaultdict(list)
    for row in scheduled:
        by_pair[row.pair_id].append(row)
    first_counts: dict[tuple[str, str], dict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    for pair_id, pair in by_pair.items():
        ordered = sorted(pair, key=lambda row: row.ordinal)
        if len(ordered) != 2 or {row.arm for row in ordered} != set(ARMS):
            errors.append(f"invalid_pair:{pair_id}")
            continue
        if ordered[1].ordinal != ordered[0].ordinal + 1:
            errors.append(f"nonadjacent_pair:{pair_id}")
        left = ordered[0].to_dict()
        right = ordered[1].to_dict()
        for name in ("ordinal", "episode_id", "arm", "condition_id"):
            left.pop(name)
            right.pop(name)
        if left != right:
            errors.append(f"pair_changes_more_than_arm:{pair_id}")
        row = ordered[0]
        expected_pair = adaptive_pair_id(
            lineage_group_id=row.lineage_group_id,
            cluster_id=row.cluster_id,
            task_contract_id=row.task_contract_id,
            pair_role=row.pair_role,
            hazard_id=row.hazard_id,
            route_id=row.route_id,
            authority_level=row.authority_level,
            replicate_id=row.replicate_id,
            generation_seed=row.generation_seed,
            selection_seed=row.selection_seed,
            schedule_seed=row.schedule_seed,
        )
        if pair_id != expected_pair:
            errors.append(f"pair_fingerprint_mismatch:{pair_id}")
        first_counts[(row.time_block_id, row.authority_level)][row.arm] += 1
    for stratum, counts in first_counts.items():
        if abs(counts["B1"] - counts["M1"]) > 1:
            errors.append(f"arm_order_not_counterbalanced:{stratum}")

    rows_by_block_replication: dict[tuple[str, str], list[ScheduleRow]] = defaultdict(list)
    rows_by_time_block: dict[str, list[ScheduleRow]] = defaultdict(list)
    for row in scheduled:
        if row.track != "adaptive_end_to_end":
            errors.append(f"wrong_track:{row.episode_id}")
        if row.authority_level not in LEVELS or row.arm not in ARMS:
            errors.append(f"unknown_condition:{row.episode_id}")
        if not row.time_block_id:
            errors.append(f"missing_time_block:{row.episode_id}")
        if row.level_order_position not in range(len(LEVELS)):
            errors.append(f"invalid_level_order_position:{row.episode_id}")
        unsigned = row.to_dict()
        unsigned.pop("episode_id")
        if row.episode_id != sha256_json(unsigned):
            errors.append(f"episode_fingerprint_mismatch:{row.episode_id}")
        expected_block = adaptive_block_id(
            lineage_group_id=row.lineage_group_id,
            cluster_id=row.cluster_id,
            task_contract_id=row.task_contract_id,
            pair_role=row.pair_role,
            hazard_id=row.hazard_id,
            route_id=row.route_id,
        )
        if row.block_id != expected_block:
            errors.append(f"block_fingerprint_mismatch:{row.episode_id}")
        rows_by_block_replication[(row.block_id, row.replicate_id)].append(row)
        rows_by_time_block[row.time_block_id].append(row)
        if row.pair_role == "honest":
            if any((row.hazard_id, row.route_id, row.attack_template_lineage_id, row.target_effect_sha256, row.safety_weight_id)):
                errors.append(f"honest_has_attack_fields:{row.episode_id}")
            if row.expected_structural_exposure:
                errors.append(f"honest_marked_exposed:{row.episode_id}")
            if row.weight_id != row.utility_weight_id:
                errors.append(f"honest_weight_mismatch:{row.episode_id}")
        elif row.pair_role == "adversarial":
            if not row.hazard_id or not row.route_id or not row.target_effect_sha256:
                errors.append(f"adversarial_missing_route:{row.episode_id}")
            if row.bank_id == "formal_holdout" and not row.safety_weight_id:
                errors.append(f"formal_adversarial_missing_weight:{row.episode_id}")
            if row.weight_id != row.safety_weight_id:
                errors.append(f"adversarial_weight_mismatch:{row.episode_id}")
        else:
            errors.append(f"unknown_role:{row.episode_id}")
        if row.bank_id == "formal_holdout" and (
            row.weight_id is None
            or isinstance(row.weight, bool)
            or not isinstance(row.weight, (int, float))
            or row.weight <= 0
        ):
            errors.append(f"formal_weight_invalid:{row.episode_id}")

    expected_block_coordinates = {
        (level, arm) for level in LEVELS for arm in ARMS
    }
    replications_by_block: dict[str, set[str]] = defaultdict(set)
    for (block_id, replicate_id), block_rows in rows_by_block_replication.items():
        replications_by_block[block_id].add(replicate_id)
        coordinates = [
            (row.authority_level, row.arm) for row in block_rows
        ]
        if (
            set(coordinates) != expected_block_coordinates
            or len(coordinates) != len(expected_block_coordinates)
        ):
            errors.append(
                f"incomplete_or_duplicate_block_replication:{block_id}:{replicate_id}"
            )
        if len({row.time_block_id for row in block_rows}) != 1:
            errors.append(f"block_replication_spans_time_blocks:{block_id}:{replicate_id}")
        positions_by_level = {
            row.authority_level: row.level_order_position for row in block_rows
        }
        if (
            set(positions_by_level) != set(LEVELS)
            or set(positions_by_level.values()) != set(range(len(LEVELS)))
        ):
            errors.append(f"invalid_level_permutation:{block_id}:{replicate_id}")
    for block_id, observed in replications_by_block.items():
        if observed != replicate_ids:
            errors.append(f"block_missing_or_extra_replication:{block_id}")

    for time_block_id, time_rows in rows_by_time_block.items():
        if len({row.counterbalance_stratum for row in time_rows}) != 1:
            errors.append(f"time_block_mixes_strata:{time_block_id}")
        ordinals = sorted(row.ordinal for row in time_rows)
        if ordinals != list(range(ordinals[0], ordinals[-1] + 1)):
            errors.append(f"time_block_not_contiguous:{time_block_id}")
        units = {
            (row.block_id, row.replicate_id) for row in time_rows
        }
        for position in range(len(LEVELS)):
            counts = {
                level: len(
                    {
                        (row.block_id, row.replicate_id)
                        for row in time_rows
                        if row.level_order_position == position
                        and row.authority_level == level
                    }
                )
                for level in LEVELS
            }
            if sum(counts.values()) != len(units) or max(counts.values()) - min(counts.values()) > 1:
                errors.append(
                    f"level_order_not_counterbalanced:{time_block_id}:position-{position}"
                )

    if selected_candidates is not None:
        candidates = tuple(selected_candidates)
        if _duplicates(
            candidate.normalized_task_contract_sha256 for candidate in candidates
        ):
            errors.append("duplicate_selected_task_contract")
        route_lookup = {
            (
                candidate.normalized_task_contract_sha256,
                route.hazard_id,
                route.route_id,
            ): route
            for candidate in candidates
            for route in _applicable_routes(candidate)
        }
        expected: set[
            tuple[str, str, str, str, str, str | None, str | None]
        ] = set()
        for candidate in candidates:
            for replicate_id in replicate_ids:
                for level in LEVELS:
                    expected.add(
                        (
                            candidate.normalized_task_contract_sha256,
                            candidate.cluster_id,
                            "honest",
                            level,
                            replicate_id,
                            None,
                            None,
                        )
                    )
                    expected.update(
                        (
                            candidate.normalized_task_contract_sha256,
                            candidate.cluster_id,
                            "adversarial",
                            level,
                            replicate_id,
                            route.hazard_id,
                            route.route_id,
                        )
                        for route in _applicable_routes(candidate)
                    )
        actual = {
            (
                row.task_contract_id,
                row.cluster_id,
                row.pair_role,
                row.authority_level,
                row.replicate_id,
                row.hazard_id,
                row.route_id,
            )
            for row in scheduled
        }
        if actual != expected:
            errors.append("incomplete_or_extra_schedule_cells")
        for cell in expected:
            matches = [
                row
                for row in scheduled
                if (
                    row.task_contract_id,
                    row.cluster_id,
                    row.pair_role,
                    row.authority_level,
                    row.replicate_id,
                    row.hazard_id,
                    row.route_id,
                )
                == cell
            ]
            if len(matches) != 2 or {row.arm for row in matches} != set(ARMS):
                errors.append(f"incomplete_arm_pair:{cell}")
        for row in scheduled:
            if row.pair_role != "adversarial":
                continue
            route = route_lookup.get(
                (row.task_contract_id, row.hazard_id, row.route_id)
            )
            if route is None or route.first_reachable_level is None:
                errors.append(f"scheduled_unapproved_route:{row.episode_id}")
                continue
            expected_exposure = LEVELS.index(
                row.authority_level
            ) >= LEVELS.index(route.first_reachable_level)
            if row.expected_structural_exposure != expected_exposure:
                errors.append(f"wrong_structural_exposure:{row.episode_id}")
    return {
        "passed": not errors,
        "errors": errors,
        "row_count": len(scheduled),
        "pair_count": len(by_pair),
        "lineage_count": len({row.lineage_group_id for row in scheduled}),
        "cluster_count": len({row.cluster_id for row in scheduled}),
        "replication_count": len(replicate_ids),
        "schedule_sha256": sha256_json([row.to_dict() for row in scheduled]),
    }


REQUIRED_SEAL_GATES = (
    "authority",
    "baseline_parity",
    "route_activation",
    "utility_checkers",
    "oracle",
    "power",
    "development_activation",
)
REQUIRED_SEAL_ARTIFACTS = (
    "proposal",
    "candidate_frame",
    "lineage_graph",
    "split_assignments",
    "bank_weights",
    "formal_payload_manifest",
    "formal_schedule",
    "route_registry",
    "authority_surfaces",
    "baseline_implementations",
    "prompt_bundle",
    "checkers",
    "initial_state_fixtures",
    "runner",
    "statistics",
    "analysis",
    "power_report",
    "environment",
    "model_config",
    "failure_policy",
    "retry_policy",
    "exposure_log",
)


def create_formal_seal(
    split: BankSplit,
    schedule: Iterable[ScheduleRow],
    candidates: Iterable[CandidateRecord],
    *,
    artifact_hashes: Mapping[str, str],
    prerequisite_gates: Mapping[str, bool],
    custodian: str,
    locked_at: str,
    formal_payload_accessed: bool = False,
) -> dict[str, Any]:
    """Create a metadata-only deterministic seal; never read formal content."""

    _require_nonempty("custodian", custodian)
    try:
        timestamp = datetime.fromisoformat(locked_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OriginalRQ1V3BankError("locked_at must be an ISO-8601 timestamp") from exc
    if timestamp.tzinfo is None:
        raise OriginalRQ1V3BankError("locked_at must include a timezone")
    if formal_payload_accessed:
        raise OriginalRQ1V3BankError(
            "cannot seal after the formal payload was accessed"
        )
    if set(prerequisite_gates) != set(REQUIRED_SEAL_GATES) or not all(prerequisite_gates.values()):
        raise OriginalRQ1V3BankError(
            "all and only required pre-formal gates must pass before sealing"
        )
    if set(artifact_hashes) != set(REQUIRED_SEAL_ARTIFACTS):
        raise OriginalRQ1V3BankError(
            "artifact hash manifest does not exactly match the seal contract"
        )
    for name, value in artifact_hashes.items():
        _require_sha256(f"artifact_hashes[{name}]", value)
    candidate_rows = tuple(candidates)
    split_audit = audit_bank_split(split, candidate_rows)
    if not split_audit["passed"]:
        raise OriginalRQ1V3BankError("only an audited bank split can be sealed")
    formal_candidate_ids = {
        row.candidate_id
        for row in split.assignments
        if row.bank_id == "formal_holdout"
    }
    formal_candidates = tuple(
        row for row in candidate_rows if row.candidate_id in formal_candidate_ids
    )
    scheduled = tuple(schedule)
    schedule_audit = audit_matched_schedule(
        scheduled, selected_candidates=formal_candidates
    )
    if not schedule_audit["passed"] or {row.bank_id for row in scheduled} != {"formal_holdout"}:
        raise OriginalRQ1V3BankError("only a complete formal schedule can be sealed")
    if artifact_hashes["candidate_frame"] != split.candidate_frame_sha256:
        raise OriginalRQ1V3BankError("candidate-frame hash does not match split")
    if artifact_hashes["lineage_graph"] != split.lineage_graph.graph_sha256:
        raise OriginalRQ1V3BankError("lineage-graph hash does not match split")
    if artifact_hashes["split_assignments"] != split.split_sha256:
        raise OriginalRQ1V3BankError("split hash does not match seal manifest")
    if artifact_hashes["formal_schedule"] != schedule_audit["schedule_sha256"]:
        raise OriginalRQ1V3BankError("formal schedule hash does not match rows")
    weights_hash = sha256_json(
        {
            "utility": [row.to_dict() for row in split.utility_weights],
            "safety": [row.to_dict() for row in split.safety_weights],
        }
    )
    if artifact_hashes["bank_weights"] != weights_hash:
        raise OriginalRQ1V3BankError("bank-weight hash does not match split")
    body = {
        "schema_version": "original-rq1-v3-formal-seal.1",
        "status": "sealed",
        "locked_at": locked_at,
        "custodian": custodian,
        "formal_unsealed_at": None,
        "formal_payload_accessed_before_lock": False,
        "selection_seed": split.selection_seed,
        "replicate_ids": sorted({row.replicate_id for row in scheduled}),
        "generation_seeds": sorted(
            {
                row.generation_seed
                for row in scheduled
                if row.generation_seed is not None
            }
        ),
        "schedule_seed": scheduled[0].schedule_seed,
        "prerequisite_gates": dict(sorted(prerequisite_gates.items())),
        "artifact_hashes": dict(sorted(artifact_hashes.items())),
    }
    return {**body, "seal_sha256": sha256_json(body)}


def verify_formal_seal(seal: Mapping[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    body = dict(seal)
    recorded = body.pop("seal_sha256", None)
    if not isinstance(recorded, str) or recorded != sha256_json(body):
        errors.append("seal_fingerprint_mismatch")
    if body.get("status") != "sealed" or body.get("formal_unsealed_at") is not None:
        errors.append("not_sealed_or_already_unsealed")
    artifacts = body.get("artifact_hashes")
    if not isinstance(artifacts, dict) or set(artifacts) != set(REQUIRED_SEAL_ARTIFACTS):
        errors.append("artifact_manifest_mismatch")
    elif any(not isinstance(value, str) or not _is_sha256(value) for value in artifacts.values()):
        errors.append("invalid_artifact_hash")
    gates = body.get("prerequisite_gates")
    if not isinstance(gates, dict) or set(gates) != set(REQUIRED_SEAL_GATES) or not all(gates.values()):
        errors.append("prerequisite_gate_mismatch")
    if len(body.get("replicate_ids", ())) < 3:
        errors.append("fewer_than_three_replications")
    if body.get("generation_seeds") and len(body["generation_seeds"]) < 3:
        errors.append("fewer_than_three_generation_seeds")
    return {"passed": not errors, "errors": errors, "seal_sha256": recorded}
