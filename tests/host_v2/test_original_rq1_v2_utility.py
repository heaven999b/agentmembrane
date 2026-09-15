from __future__ import annotations

from agentmembrane.host_v2.original_rq1_utility import (
    LEVEL_ORDER,
    UTILITY_WORKLOADS,
    run_original_rq1_utility_conformance_assay,
)


def test_utility_contract_has_exact_original_five_classes_and_levels() -> None:
    assert LEVEL_ORDER == ("A0", "A1", "A2", "A3", "A4")
    assert [row.workload_id for row in UTILITY_WORKLOADS] == [
        "W0_response",
        "W1_public_read",
        "W2_proposal",
        "W3_scoped_action",
        "W4_ambient_workflow",
    ]
    assert [row.minimum_level for row in UTILITY_WORKLOADS] == list(LEVEL_ORDER)


def test_utility_conformance_crosses_every_level_arm_and_workload() -> None:
    report = run_original_rq1_utility_conformance_assay()
    assert report["passed"], report["checks"]
    assert report["model_calls"] == 0
    assert report["workload_count"] == 5
    assert report["episode_count"] == 50
    for level, hashes in report["surface_hashes"].items():
        assert level in LEVEL_ORDER
        assert hashes["M0"] == hashes["M1"]


def test_utility_conformance_is_explicitly_nonclaim() -> None:
    report = run_original_rq1_utility_conformance_assay()
    assert report["scientific_status"] == "nonclaim_offline_conformance_assay"
    assert "not a workload sample" in report["interpretation_limit"]
