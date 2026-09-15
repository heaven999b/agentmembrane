from __future__ import annotations

from collections import Counter
from pathlib import Path

from agentmembrane.host_v2.original_rq1_banks import (
    BFCL_COMMIT,
    compile_original_rq1_banks,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_two_bank_compiler_passes_all_frozen_coverage_checks() -> None:
    report = compile_original_rq1_banks(REPO_ROOT)
    assert report["passed"], report["checks"]
    assert report["bfcl_commit"] == BFCL_COMMIT
    assert report["candidate_frame_counts"] == {
        "AgentDojo": 86,
        "BFCL": 840,
        "tau2": 142,
    }
    assert len(report["development"]) == 30
    assert len(report["formal_holdout"]) == 120


def test_formal_holdout_is_unexposed_weighted_and_route_complete() -> None:
    report = compile_original_rq1_banks(REPO_ROOT)
    formal = report["formal_holdout"]
    assert all(row["prior_model_exposure"] is False for row in formal)
    assert all(row["bank_id"] == "formal_holdout" for row in formal)
    assert {row["utility_class"] for row in formal} == {
        "W0_response",
        "W1_public_read",
        "W2_proposal",
        "W3_scoped_action",
        "W4_ambient_workflow",
    }
    assert report["formal_family_counts"] == {
        "H-CAP": 120,
        "H-CTRL": 120,
        "H-MEM": 120,
        "H-TOOL": 120,
        "H-XAG": 120,
    }
    assert min(report["formal_route_counts"].values()) >= 20
    assert abs(
        sum(row["primary_source_balanced_weight"] for row in formal) - 1.0
    ) < 1e-12
    assert Counter(row["source_family"] for row in formal) == {
        "BFCL": 40,
        "AgentDojo": 40,
        "tau2": 40,
    }


def test_development_schedule_contains_only_development_clusters() -> None:
    report = compile_original_rq1_banks(REPO_ROOT)
    schedule = report["development_schedule"]
    assert len(schedule) == 30 * 5 * 6 * 2
    assert all(row["bank_id"] == "development" for row in schedule)
    assert {row["condition_id"] for row in schedule} == {
        f"ORIG-RQ1-A{level}-{arm}"
        for level in range(5)
        for arm in ("M0", "M1")
    }
