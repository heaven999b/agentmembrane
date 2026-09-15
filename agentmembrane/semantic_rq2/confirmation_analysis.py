from __future__ import annotations

import hashlib
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from .analysis import cluster_bootstrap_ci
from .schema import RECEPTOR_ORDER, Receptor


CONFIRMATION_ANALYSIS_ID = "semantic-rq2-full-confirmation-analysis-v1"
PRIMARY_LOWER = Receptor.R1
PRIMARY_UPPER = Receptor.R2


def _exact_two_sided_sign_p(positive: int, negative: int) -> float:
    nonzero = positive + negative
    if nonzero == 0:
        return 1.0
    tail = sum(
        math.comb(nonzero, index)
        for index in range(0, min(positive, negative) + 1)
    ) / (2**nonzero)
    return min(1.0, 2.0 * tail)


def _derived_seed(base_seed: int, *parts: object) -> int:
    material = "|".join([str(base_seed), *(str(part) for part in parts)])
    return int(hashlib.sha256(material.encode("utf-8")).hexdigest()[:16], 16)


def _seed_key(value: object) -> str:
    return "unseeded" if value is None else str(value)


def _completed(row: Mapping[str, Any] | None) -> bool:
    return row is not None and row.get("terminal_status") == "completed"


def _case_effect(
    arms: Mapping[str, Mapping[str, Any]],
    receptor: Receptor,
    *,
    valid_only: bool,
) -> tuple[float, str] | None:
    honest = arms.get(f"honest:{receptor.value}")
    attack = arms.get(f"attack:{receptor.value}")
    if not _completed(honest) or not _completed(attack):
        return None
    assert honest is not None and attack is not None
    if honest.get("assigned_target") != attack.get("assigned_target"):
        raise ValueError(f"assigned-target mismatch at {receptor.value}")
    if honest.get("cluster_id") != attack.get("cluster_id"):
        raise ValueError(f"document-cluster mismatch at {receptor.value}")
    if valid_only and not (
        honest.get("hard_valid") is True and attack.get("hard_valid") is True
    ):
        return None
    target = honest.get("assigned_target")
    effect = float(int(attack.get("label") == target) - int(honest.get("label") == target))
    return effect, str(honest["cluster_id"])


def _direct_rows(
    blocks: Mapping[str, Mapping[str, Mapping[str, Any]]],
    receptor: Receptor,
    *,
    valid_only: bool,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for case_id, arms in sorted(blocks.items()):
        result = _case_effect(arms, receptor, valid_only=valid_only)
        if result is None:
            continue
        effect, cluster_id = result
        rows.append({"case_id": case_id, "cluster_id": cluster_id, "delta": effect})
    return rows


def _contrast_rows(
    blocks: Mapping[str, Mapping[str, Mapping[str, Any]]],
    *,
    lower: Receptor,
    upper: Receptor,
    valid_only: bool,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for case_id, arms in sorted(blocks.items()):
        lower_result = _case_effect(arms, lower, valid_only=valid_only)
        upper_result = _case_effect(arms, upper, valid_only=valid_only)
        if lower_result is None or upper_result is None:
            continue
        lower_effect, lower_cluster = lower_result
        upper_effect, upper_cluster = upper_result
        if lower_cluster != upper_cluster:
            raise ValueError(f"document-cluster mismatch across receptors for {case_id}")
        rows.append(
            {
                "case_id": case_id,
                "cluster_id": lower_cluster,
                "delta": upper_effect - lower_effect,
            }
        )
    return rows


def _effect_summary(
    rows: list[dict[str, Any]],
    *,
    planned_case_n: int,
    bootstrap_seed: int,
    bootstrap_samples: int,
) -> dict[str, Any]:
    by_cluster: dict[str, list[float]] = defaultdict(list)
    for row in rows:
        by_cluster[str(row["cluster_id"])].append(float(row["delta"]))
    cluster_means = {
        cluster_id: statistics.mean(values) for cluster_id, values in by_cluster.items()
    }
    cluster_positive = sum(value > 0 for value in cluster_means.values())
    cluster_negative = sum(value < 0 for value in cluster_means.values())
    case_values = [float(row["delta"]) for row in rows]
    return {
        "planned_case_n": planned_case_n,
        "completed_case_n": len(rows),
        "case_coverage": len(rows) / planned_case_n if planned_case_n else None,
        "completed_document_cluster_n": len(cluster_means),
        "case_weighted_point": statistics.mean(case_values) if case_values else None,
        "case_positive_n": sum(value > 0 for value in case_values),
        "case_negative_n": sum(value < 0 for value in case_values),
        "document_cluster_positive_n": cluster_positive,
        "document_cluster_negative_n": cluster_negative,
        "document_cluster_nonzero_n": cluster_positive + cluster_negative,
        "exact_two_sided_document_cluster_sign_p": _exact_two_sided_sign_p(
            cluster_positive, cluster_negative
        ),
        "document_cluster_bootstrap_95ci": cluster_bootstrap_ci(
            rows,
            value=lambda row: float(row["delta"]),
            seed=bootstrap_seed,
            samples=bootstrap_samples,
        ),
    }


def _paired_views(
    blocks: Mapping[str, Mapping[str, Mapping[str, Any]]],
    *,
    lower: Receptor | None,
    upper: Receptor,
    planned_case_n: int,
    bootstrap_seed: int,
    bootstrap_samples: int,
) -> dict[str, Any]:
    def rows(valid_only: bool) -> list[dict[str, Any]]:
        if lower is None:
            return _direct_rows(blocks, upper, valid_only=valid_only)
        return _contrast_rows(
            blocks,
            lower=lower,
            upper=upper,
            valid_only=valid_only,
        )

    all_attempt_rows = rows(False)
    valid_rows = rows(True)
    all_attempt = _effect_summary(
        all_attempt_rows,
        planned_case_n=planned_case_n,
        bootstrap_seed=bootstrap_seed,
        bootstrap_samples=bootstrap_samples,
    )
    valid = _effect_summary(
        valid_rows,
        planned_case_n=planned_case_n,
        bootstrap_seed=bootstrap_seed + 1,
        bootstrap_samples=bootstrap_samples,
    )
    valid["source_fidelity_common_valid_case_n"] = len(valid_rows)
    valid["source_fidelity_common_valid_coverage"] = (
        len(valid_rows) / planned_case_n if planned_case_n else None
    )
    return {
        "all_attempt_robustness": all_attempt,
        "source_fidelity_valid": valid,
    }


def _index_group(
    rows: Iterable[Mapping[str, Any]],
) -> dict[str, dict[str, Mapping[str, Any]]]:
    blocks: dict[str, dict[str, Mapping[str, Any]]] = defaultdict(dict)
    for row in rows:
        case_id = row.get("case_id")
        arm_id = row.get("arm_id")
        if not isinstance(case_id, str) or not case_id:
            raise ValueError("confirmation record missing case_id")
        if not isinstance(arm_id, str) or not arm_id:
            raise ValueError(f"confirmation record missing arm_id for {case_id}")
        if arm_id in blocks[case_id]:
            raise ValueError(f"duplicate arm for confirmation block: {case_id}/{arm_id}")
        blocks[case_id][arm_id] = row
    return dict(blocks)


def _analyze_group(
    rows: list[Mapping[str, Any]],
    *,
    downstream_id: str,
    seed_value: object,
    bootstrap_seed: int,
    bootstrap_samples: int,
) -> dict[str, Any]:
    blocks = _index_group(rows)
    planned_case_n = len(blocks)
    cluster_ids = {
        str(row["cluster_id"])
        for row in rows
        if row.get("cluster_id") is not None
    }
    primary = _paired_views(
        blocks,
        lower=PRIMARY_LOWER,
        upper=PRIMARY_UPPER,
        planned_case_n=planned_case_n,
        bootstrap_seed=_derived_seed(
            bootstrap_seed, downstream_id, seed_value, "primary_gamma_r2"
        ),
        bootstrap_samples=bootstrap_samples,
    )

    curve: dict[str, Any] = {}
    for receptor in RECEPTOR_ORDER:
        curve[receptor.value] = _paired_views(
            blocks,
            lower=None,
            upper=receptor,
            planned_case_n=planned_case_n,
            bootstrap_seed=_derived_seed(
                bootstrap_seed, downstream_id, seed_value, receptor.value
            ),
            bootstrap_samples=bootstrap_samples,
        )
    r4_minus_r1 = _paired_views(
        blocks,
        lower=Receptor.R1,
        upper=Receptor.R4,
        planned_case_n=planned_case_n,
        bootstrap_seed=_derived_seed(
            bootstrap_seed, downstream_id, seed_value, "r4_minus_r1"
        ),
        bootstrap_samples=bootstrap_samples,
    )
    return {
        "downstream_id": downstream_id,
        "seed": seed_value,
        "planned_case_n": planned_case_n,
        "independent_document_cluster_n": len(cluster_ids),
        "primary_gamma_r2": {
            "primary_view": "source_fidelity_valid",
            "formula": "Delta_R2_structured_inference - Delta_R1_evidence_annotation",
            **primary,
        },
        "secondary": {
            "r2_direct_effect": curve[Receptor.R2.value],
            "r4_direct_effect": curve[Receptor.R4.value],
            "r4_minus_r1": {
                "formula": "Delta_R4_free_form - Delta_R1_evidence_annotation",
                **r4_minus_r1,
            },
            "complete_receptor_curve": curve,
        },
    }


def analyze_confirmation_records(
    records: list[dict[str, Any]],
    *,
    bootstrap_seed: int,
    bootstrap_samples: int = 10_000,
) -> dict[str, Any]:
    """Analyze frozen neutral-P0 confirmation records without pooling seeds.

    The primary estimate uses only cases for which all four R1/R2 honest/attack
    artifacts are completed and source-fidelity ``hard_valid``.  Point estimates
    remain case-weighted, while uncertainty resamples document clusters.  The exact
    sign test first averages every case delta inside its document, so two questions
    from one contract contribute only one sign.
    """

    if bootstrap_samples < 100:
        raise ValueError("bootstrap_samples must be at least 100")
    grouped: dict[tuple[str, object], list[Mapping[str, Any]]] = defaultdict(list)
    for row in records:
        downstream_id = row.get("downstream_id")
        if not isinstance(downstream_id, str) or not downstream_id:
            raise ValueError("confirmation record missing downstream_id")
        grouped[(downstream_id, row.get("seed"))].append(row)

    per_downstream: dict[str, dict[str, Any]] = {}
    for downstream_id in sorted({key[0] for key in grouped}):
        seed_values = sorted(
            (key[1] for key in grouped if key[0] == downstream_id),
            key=lambda value: (value is not None, str(value)),
        )
        per_downstream[downstream_id] = {
            "seed_results": {
                _seed_key(seed_value): _analyze_group(
                    grouped[(downstream_id, seed_value)],
                    downstream_id=downstream_id,
                    seed_value=seed_value,
                    bootstrap_seed=bootstrap_seed,
                    bootstrap_samples=bootstrap_samples,
                )
                for seed_value in seed_values
            }
        }
    return {
        "analysis_id": CONFIRMATION_ANALYSIS_ID,
        "construct_id": "semantic_receptor_expressiveness",
        "primary_estimand": "Gamma_R2=Delta_R2-Delta_R1_on_common_source_fidelity_valid_cases",
        "statistical_unit": "document_cluster",
        "point_weighting": "case_weighted",
        "exact_test": "two_sided_sign_test_on_within_document_mean_case_delta",
        "bootstrap": "document_cluster_resampling_with_all_cases_retained",
        "bootstrap_samples": bootstrap_samples,
        "seed_policy": "downstream-by-seed results are separate; no seed is an independent document",
        "per_downstream": per_downstream,
    }


def render_confirmation_report(analysis: Mapping[str, Any]) -> str:
    def percent(value: object) -> str:
        return "NA" if not isinstance(value, (int, float)) else f"{100 * float(value):.1f} pp"

    def interval(value: object) -> str:
        if not isinstance(value, list) or len(value) != 2:
            return "NA"
        return f"[{100 * float(value[0]):.1f}, {100 * float(value[1]):.1f}] pp"

    lines = [
        "# RQ2 full-confirmation analysis",
        "",
        "Primary inference uses common source-fidelity-valid R1/R2 pairs. Exact sign tests count one sign per document cluster; point estimates remain case-weighted.",
        "",
    ]
    for downstream_id, downstream in analysis.get("per_downstream", {}).items():
        lines.extend([f"## {downstream_id}", ""])
        for seed_key, result in downstream.get("seed_results", {}).items():
            primary = result["primary_gamma_r2"]["source_fidelity_valid"]
            curve = result["secondary"]["complete_receptor_curve"]
            lines.extend(
                [
                    f"### Seed {seed_key}",
                    "",
                    (
                        f"Primary Gamma_R2: {percent(primary['case_weighted_point'])}; "
                        f"cluster bootstrap 95% CI {interval(primary['document_cluster_bootstrap_95ci'])}; "
                        f"cluster sign p={primary['exact_two_sided_document_cluster_sign_p']:.6g}; "
                        f"{primary['completed_case_n']} cases in "
                        f"{primary['completed_document_cluster_n']} document clusters."
                    ),
                    "",
                    "| Receptor | Valid effect | Cluster 95% CI | Valid cases |",
                    "|---|---:|---:|---:|",
                ]
            )
            for receptor in RECEPTOR_ORDER:
                row = curve[receptor.value]["source_fidelity_valid"]
                lines.append(
                    f"| {receptor.value} | {percent(row['case_weighted_point'])} | "
                    f"{interval(row['document_cluster_bootstrap_95ci'])} | "
                    f"{row['completed_case_n']} |"
                )
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write_confirmation_json(path: Path, analysis: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(analysis, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def write_confirmation_report(path: Path, analysis: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(render_confirmation_report(analysis), encoding="utf-8")
    temporary.replace(path)
