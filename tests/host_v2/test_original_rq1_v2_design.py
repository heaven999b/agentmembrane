from __future__ import annotations

from dataclasses import replace

import pytest

from agentmembrane.host_v2.original_rq1_design import (
    OriginalRQ1DesignError,
    WorkflowCluster,
    audit_bank_disjointness,
    audit_blocked_schedule,
    build_blocked_schedule,
)


def _cluster(
    cluster_id: str,
    bank_id: str,
    *,
    source_task_id: str | None = None,
    lineage: str | None = None,
    exposed: bool | None = None,
) -> WorkflowCluster:
    return WorkflowCluster(
        cluster_id=cluster_id,
        bank_id=bank_id,
        source_dataset="fixture-benchmark",
        source_task_id=source_task_id or cluster_id,
        source_sha256="a" * 64,
        source_license="fixture-license",
        domain="fixture-domain",
        template_lineage_id=lineage or f"lineage-{cluster_id}",
        utility_class="W4_ambient_workflow",
        minimum_authority_level="A4",
        sampling_strata=("utility_probability", "hazard_stratified"),
        hazard_routes=(
            ("H-MEM", "direct_commit"),
            ("H-CTRL", "acl_or_policy_change"),
        ),
        adversarial_twin_origin="agentmembrane_authored",
        prior_model_exposure=(bank_id == "development" if exposed is None else exposed),
        inclusion_probability=0.25,
        design_weight=4.0,
    )


def test_bank_audit_requires_source_cluster_and_lineage_disjointness() -> None:
    development = [_cluster("dev-1", "development")]
    formal = [_cluster("formal-1", "formal_holdout")]
    audit = audit_bank_disjointness(development, formal)
    assert audit["passed"], audit

    overlap = [
        _cluster(
            "formal-2",
            "formal_holdout",
            source_task_id="dev-1",
            lineage="lineage-dev-1",
        )
    ]
    audit = audit_bank_disjointness(development, overlap)
    assert not audit["passed"]
    assert audit["overlaps"]["source_task"]
    assert audit["overlaps"]["template_lineage_id"]


def test_formal_cluster_rejects_prior_model_exposure_and_invalid_weights() -> None:
    with pytest.raises(OriginalRQ1DesignError, match="prior model exposure"):
        _cluster("formal-exposed", "formal_holdout", exposed=True)
    with pytest.raises(OriginalRQ1DesignError, match="inverse inclusion"):
        replace(_cluster("formal-weight", "formal_holdout"), design_weight=3.0)


def test_blocked_schedule_is_reproducible_complete_adjacent_and_counterbalanced() -> None:
    clusters = [
        _cluster("formal-1", "formal_holdout"),
        _cluster("formal-2", "formal_holdout"),
    ]
    first = build_blocked_schedule(clusters, seed=9173)
    second = build_blocked_schedule(clusters, seed=9173)
    different = build_blocked_schedule(clusters, seed=9174)
    assert first == second
    assert first != different

    audit = audit_blocked_schedule(first)
    assert audit["passed"], audit
    assert audit["cluster_count"] == 2
    assert audit["row_count"] == 2 * 5 * 3 * 2
    assert audit["pair_count"] == 2 * 5 * 3
    assert abs(audit["m0_first"] - audit["m1_first"]) <= 1

    for pair_id in {row.pair_id for row in first}:
        pair = sorted(
            (row for row in first if row.pair_id == pair_id),
            key=lambda row: row.ordinal,
        )
        assert pair[1].ordinal == pair[0].ordinal + 1
        assert {row.arm for row in pair} == {"M0", "M1"}


def test_schedule_refuses_to_mix_banks() -> None:
    with pytest.raises(OriginalRQ1DesignError, match="cannot mix"):
        build_blocked_schedule(
            [
                _cluster("dev-1", "development"),
                _cluster("formal-1", "formal_holdout"),
            ],
            seed=4,
        )
