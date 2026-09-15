"""Deterministic two-bank compiler for the original-RQ1 v2 study.

The compiler uses public benchmark identities only.  It never calls a model,
and it never places prompt text in the bank manifests.  Formal selection is
performed before development selection inside every declared stratum so the
holdout is not chosen in response to development behavior.
"""

from __future__ import annotations

import copy
from collections import Counter, defaultdict
from dataclasses import dataclass
import json
from pathlib import Path
import random
from typing import Any, Iterable

from .original_rq1 import ORIGINAL_RQ1_HAZARDS
from .original_rq1_design import (
    WorkflowCluster,
    audit_bank_disjointness,
    build_blocked_schedule,
)
from .schema import sha256_json


BFCL_COMMIT = "f7cf7359b7ac615a0b294831c5ba2bc95ee4a000"
SELECTION_SEED = 20260905
FORMAL_SOURCE_TARGET_WEIGHT = 1.0 / 3.0


@dataclass(frozen=True)
class Candidate:
    cluster_id: str
    source_dataset: str
    source_task_id: str
    source_sha256: str
    source_license: str
    domain: str
    utility_class: str
    minimum_authority_level: str
    selection_stratum: str


def _jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number} is not an object")
            rows.append(value)
    return rows


def _bfcl_candidates(repo_root: Path) -> list[Candidate]:
    data_root = (
        repo_root
        / "data/host_boundary_v2/upstream/bfcl-f7cf735"
        / "berkeley-function-call-leaderboard/bfcl_eval/data"
    )
    categories = (
        (
            "BFCL_v4_irrelevance.json",
            None,
            "W0_response",
            "A0",
            "bfcl_irrelevance",
        ),
        (
            "BFCL_v4_simple_python.json",
            "possible_answer/BFCL_v4_simple_python.json",
            "W1_public_read",
            "A1",
            "bfcl_simple_python",
        ),
        (
            "BFCL_v4_multiple.json",
            "possible_answer/BFCL_v4_multiple.json",
            "W2_proposal",
            "A2",
            "bfcl_multiple",
        ),
    )
    result: list[Candidate] = []
    for question_file, answer_file, utility_class, level, stratum in categories:
        questions = _jsonl(data_root / question_file)
        answers = (
            {str(row["id"]): row for row in _jsonl(data_root / answer_file)}
            if answer_file is not None
            else {}
        )
        for row in questions:
            task_id = str(row["id"])
            if answer_file is not None and task_id not in answers:
                raise ValueError(f"BFCL ground truth missing for {task_id}")
            source_payload = {
                "question": row,
                "ground_truth": answers.get(task_id),
                "commit": BFCL_COMMIT,
            }
            result.append(
                Candidate(
                    cluster_id=f"bfcl:{BFCL_COMMIT[:8]}:{task_id}",
                    source_dataset=f"BFCL@{BFCL_COMMIT}",
                    source_task_id=task_id,
                    source_sha256=sha256_json(source_payload),
                    source_license="Apache-2.0",
                    domain=stratum,
                    utility_class=utility_class,
                    minimum_authority_level=level,
                    selection_stratum=stratum,
                )
            )
    return result


def _agentdojo_candidates(repo_root: Path) -> list[Candidate]:
    path = repo_root / "data/host_boundary_v2/full_inventory/agentdojo_user_tasks.jsonl"
    result: list[Candidate] = []
    for row in _jsonl(path):
        if row.get("source_usable") is not True:
            continue
        domain = str(row["domain"])
        utility_class = (
            "W4_ambient_workflow"
            if domain in {"slack", "workspace"}
            else "W3_scoped_action"
        )
        level = "A4" if utility_class == "W4_ambient_workflow" else "A3"
        result.append(
            Candidate(
                cluster_id=str(row["cluster_id"]),
                source_dataset="AgentDojo-v0.1.35-v1",
                source_task_id=f"{domain}:{row['source_id']}",
                source_sha256=str(row["source_class_sha256"]),
                source_license="MIT",
                domain=f"agentdojo_{domain}",
                utility_class=utility_class,
                minimum_authority_level=level,
                selection_stratum=f"agentdojo_{domain}",
            )
        )
    return result


def _tau2_candidates(repo_root: Path) -> list[Candidate]:
    path = repo_root / "data/host_boundary_v2/full_inventory/tau2_tasks.jsonl"
    by_cluster: dict[str, dict[str, Any]] = {}
    for row in _jsonl(path):
        if row.get("source_usable") is not True or row.get("boundary_adaptable") is not True:
            continue
        cluster_id = str(row["cluster_id"])
        current = by_cluster.get(cluster_id)
        if current is None or str(row["workflow_id"]) < str(current["workflow_id"]):
            by_cluster[cluster_id] = row
    result: list[Candidate] = []
    for cluster_id, row in sorted(by_cluster.items()):
        domain = str(row["domain"])
        result.append(
            Candidate(
                cluster_id=cluster_id,
                source_dataset="tau2-bench-v1.0.1",
                source_task_id=str(row["workflow_id"]),
                source_sha256=str(row["source_task_sha256"]),
                source_license="MIT",
                domain=f"tau2_{domain}",
                utility_class="W3_scoped_action",
                minimum_authority_level="A3",
                selection_stratum=f"tau2_{domain}",
            )
        )
    return result


def load_candidate_frame(repo_root: Path) -> tuple[Candidate, ...]:
    candidates = [
        *_bfcl_candidates(repo_root),
        *_agentdojo_candidates(repo_root),
        *_tau2_candidates(repo_root),
    ]
    if len({row.cluster_id for row in candidates}) != len(candidates):
        raise ValueError("candidate cluster IDs are not globally unique")
    return tuple(candidates)


FORMAL_QUOTAS = {
    "bfcl_irrelevance": 14,
    "bfcl_simple_python": 13,
    "bfcl_multiple": 13,
    "agentdojo_banking": 10,
    "agentdojo_slack": 10,
    "agentdojo_travel": 10,
    "agentdojo_workspace": 10,
    "tau2_airline": 6,
    "tau2_banking_knowledge": 17,
    "tau2_retail": 14,
    "tau2_telecom": 3,
}

DEVELOPMENT_QUOTAS = {
    "bfcl_irrelevance": 4,
    "bfcl_simple_python": 3,
    "bfcl_multiple": 3,
    "agentdojo_banking": 3,
    "agentdojo_slack": 2,
    "agentdojo_travel": 2,
    "agentdojo_workspace": 3,
    "tau2_airline": 2,
    "tau2_banking_knowledge": 3,
    "tau2_retail": 3,
    "tau2_telecom": 2,
}


def _source_family(candidate: Candidate) -> str:
    if candidate.source_dataset.startswith("BFCL@"):
        return "BFCL"
    if candidate.source_dataset.startswith("AgentDojo"):
        return "AgentDojo"
    if candidate.source_dataset.startswith("tau2"):
        return "tau2"
    raise ValueError(candidate.source_dataset)


def _route_assignment(index: int) -> tuple[tuple[str, str], ...]:
    return tuple(
        (hazard_id, contract["routes"][index % len(contract["routes"])])
        for hazard_id, contract in ORIGINAL_RQ1_HAZARDS.items()
    )


def _select(
    candidates: Iterable[Candidate], *, seed: int
) -> tuple[list[Candidate], list[Candidate], dict[str, int]]:
    by_stratum: dict[str, list[Candidate]] = defaultdict(list)
    for candidate in candidates:
        by_stratum[candidate.selection_stratum].append(candidate)
    if set(by_stratum) != set(FORMAL_QUOTAS) or set(by_stratum) != set(DEVELOPMENT_QUOTAS):
        raise ValueError("candidate strata do not match frozen quotas")
    formal: list[Candidate] = []
    development: list[Candidate] = []
    frame_counts: dict[str, int] = {}
    for stratum in sorted(by_stratum):
        rows = sorted(by_stratum[stratum], key=lambda row: row.cluster_id)
        random.Random(f"{seed}:{stratum}").shuffle(rows)
        formal_n = FORMAL_QUOTAS[stratum]
        development_n = DEVELOPMENT_QUOTAS[stratum]
        if len(rows) < formal_n + development_n:
            raise ValueError(f"insufficient candidates in {stratum}")
        formal.extend(rows[:formal_n])
        development.extend(rows[formal_n : formal_n + development_n])
        frame_counts[stratum] = len(rows)
    return development, formal, frame_counts


def _formal_stratum_target_weights(frame_counts: dict[str, int]) -> dict[str, float]:
    weights: dict[str, float] = {}
    bfcl = [key for key in frame_counts if key.startswith("bfcl_")]
    dojo = [key for key in frame_counts if key.startswith("agentdojo_")]
    tau = [key for key in frame_counts if key.startswith("tau2_")]
    for key in bfcl:
        weights[key] = FORMAL_SOURCE_TARGET_WEIGHT / len(bfcl)
    for key in dojo:
        weights[key] = FORMAL_SOURCE_TARGET_WEIGHT / len(dojo)
    tau_total = sum(frame_counts[key] for key in tau)
    for key in tau:
        weights[key] = (
            FORMAL_SOURCE_TARGET_WEIGHT * frame_counts[key] / tau_total
        )
    return weights


def compile_original_rq1_banks(
    repo_root: Path, *, seed: int = SELECTION_SEED
) -> dict[str, Any]:
    frame = load_candidate_frame(repo_root)
    development_candidates, formal_candidates, frame_counts = _select(
        frame, seed=seed
    )
    formal_target_weights = _formal_stratum_target_weights(frame_counts)

    selected_by_bank = {
        "development": sorted(development_candidates, key=lambda row: row.cluster_id),
        "formal_holdout": sorted(formal_candidates, key=lambda row: row.cluster_id),
    }
    clusters_by_bank: dict[str, list[WorkflowCluster]] = defaultdict(list)
    metadata: dict[str, dict[str, Any]] = {}
    for bank_id, selected in selected_by_bank.items():
        for index, candidate in enumerate(selected):
            formal = bank_id == "formal_holdout"
            inclusion_probability = (
                FORMAL_QUOTAS[candidate.selection_stratum]
                / frame_counts[candidate.selection_stratum]
                if formal
                else None
            )
            cluster = WorkflowCluster(
                cluster_id=candidate.cluster_id,
                bank_id=bank_id,
                source_dataset=candidate.source_dataset,
                source_task_id=candidate.source_task_id,
                source_sha256=candidate.source_sha256,
                source_license=candidate.source_license,
                domain=candidate.domain,
                template_lineage_id=(
                    "rq1-v2-formal-holdout-template-set-v1"
                    if formal
                    else "rq1-v2-development-template-set-v1"
                ),
                utility_class=candidate.utility_class,
                minimum_authority_level=candidate.minimum_authority_level,
                sampling_strata=(
                    ("utility_probability", "hazard_stratified")
                    if formal
                    else ("hazard_stratified",)
                ),
                hazard_routes=_route_assignment(index),
                adversarial_twin_origin=(
                    "agentmembrane_authored_route_bound_to_public_workflow"
                ),
                prior_model_exposure=not formal,
                inclusion_probability=inclusion_probability,
                design_weight=(
                    1.0 / inclusion_probability
                    if inclusion_probability is not None
                    else None
                ),
            )
            clusters_by_bank[bank_id].append(cluster)
            metadata[cluster.cluster_id] = {
                "source_family": _source_family(candidate),
                "selection_stratum": candidate.selection_stratum,
                "primary_source_balanced_weight": (
                    formal_target_weights[candidate.selection_stratum]
                    / FORMAL_QUOTAS[candidate.selection_stratum]
                    if formal
                    else None
                ),
            }

    development = tuple(clusters_by_bank["development"])
    formal = tuple(clusters_by_bank["formal_holdout"])
    bank_audit = audit_bank_disjointness(development, formal)
    development_schedule = build_blocked_schedule(development, seed=seed + 1)

    route_counts: Counter[tuple[str, str]] = Counter(
        route for cluster in formal for route in cluster.hazard_routes
    )
    family_counts: Counter[str] = Counter(
        hazard_id for cluster in formal for hazard_id, _ in cluster.hazard_routes
    )
    family_domains: dict[str, set[str]] = defaultdict(set)
    for cluster in formal:
        for hazard_id, _ in cluster.hazard_routes:
            family_domains[hazard_id].add(cluster.domain)
    formal_weights = {
        cluster.cluster_id: metadata[cluster.cluster_id][
            "primary_source_balanced_weight"
        ]
        for cluster in formal
    }
    source_weight_sums: dict[str, float] = defaultdict(float)
    for cluster in formal:
        source_weight_sums[metadata[cluster.cluster_id]["source_family"]] += float(
            formal_weights[cluster.cluster_id]
        )
    checks = {
        "candidate_frame_has_expected_counts": (
            Counter(_source_family(row) for row in frame)
            == {"BFCL": 840, "AgentDojo": 86, "tau2": 142}
        ),
        "exactly_two_disjoint_banks": bank_audit["passed"],
        "development_has_30_clusters": len(development) == 30,
        "formal_has_120_clusters": len(formal) == 120,
        "formal_has_40_clusters_per_source": Counter(
            metadata[row.cluster_id]["source_family"] for row in formal
        ) == {"BFCL": 40, "AgentDojo": 40, "tau2": 40},
        "formal_covers_all_utility_classes": {
            row.utility_class for row in formal
        } == {"W0_response", "W1_public_read", "W2_proposal", "W3_scoped_action", "W4_ambient_workflow"},
        "each_hazard_has_at_least_100_independent_clusters": all(
            family_counts[hazard_id] >= 100 for hazard_id in ORIGINAL_RQ1_HAZARDS
        ),
        "each_required_route_has_at_least_20_clusters": all(
            route_counts[(hazard_id, route_id)] >= 20
            for hazard_id, contract in ORIGINAL_RQ1_HAZARDS.items()
            for route_id in contract["routes"]
        ),
        "each_hazard_has_multiple_domains": all(
            len(family_domains[hazard_id]) >= 2
            for hazard_id in ORIGINAL_RQ1_HAZARDS
        ),
        "formal_primary_weights_sum_to_one": abs(
            sum(float(value) for value in formal_weights.values()) - 1.0
        ) < 1e-12,
        "formal_source_weights_are_equal_thirds": all(
            abs(source_weight_sums[source] - FORMAL_SOURCE_TARGET_WEIGHT) < 1e-12
            for source in ("BFCL", "AgentDojo", "tau2")
        ),
        "development_schedule_is_nonformal": all(
            row.bank_id == "development" for row in development_schedule
        ),
    }
    return {
        "schema_version": 1,
        "protocol_id": "original-rq1-authority-boundary-v2.0",
        "selection_seed": seed,
        "bfcl_commit": BFCL_COMMIT,
        "candidate_frame_counts": dict(
            sorted(Counter(_source_family(row) for row in frame).items())
        ),
        "candidate_stratum_counts": dict(sorted(frame_counts.items())),
        "checks": checks,
        "passed": all(checks.values()),
        "bank_audit": bank_audit,
        "formal_family_counts": dict(sorted(family_counts.items())),
        "formal_route_counts": {
            f"{hazard_id}:{route_id}": count
            for (hazard_id, route_id), count in sorted(route_counts.items())
        },
        "formal_family_domain_counts": {
            hazard_id: len(domains)
            for hazard_id, domains in sorted(family_domains.items())
        },
        "formal_source_weight_sums": dict(sorted(source_weight_sums.items())),
        "development": [
            {**row.to_dict(), **copy.deepcopy(metadata[row.cluster_id])}
            for row in development
        ],
        "formal_holdout": [
            {**row.to_dict(), **copy.deepcopy(metadata[row.cluster_id])}
            for row in formal
        ],
        "development_schedule": [row.to_dict() for row in development_schedule],
    }
