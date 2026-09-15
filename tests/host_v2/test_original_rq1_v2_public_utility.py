import hashlib
import json
from pathlib import Path

from agentmembrane.host_v2.original_rq1_public_utility import (
    EXPECTED_UTILITY_CLASSES,
    audit_development_utility_bindings,
    load_development_utility_bindings,
    run_bfcl_native_parity,
)
from agentmembrane.host_v2.schema import sha256_json


REPO_ROOT = Path(__file__).resolve().parents[2]
REPORT = (
    REPO_ROOT
    / "experiments/host_boundary_v2/rq1_original_a0_a4_v2/"
    "assays/g2-public-utility-parity-v1/report.json"
)


def test_development_bindings_are_exactly_the_frozen_eight_and_never_formal():
    rows = load_development_utility_bindings(REPO_ROOT)
    assert len(rows) == 8
    assert len({row.cluster_id for row in rows}) == 8
    assert {row.utility_class for row in rows} == EXPECTED_UTILITY_CLASSES
    assert {row.source_family for row in rows} == {"BFCL", "AgentDojo", "tau2"}
    audit = audit_development_utility_bindings(REPO_ROOT)
    assert audit["passed"] is True
    assert audit["formal_holdout_touched"] is False
    assert audit["source_counts"] == {"BFCL": 3, "AgentDojo": 3, "tau2": 2}


def test_bfcl_official_or_source_faithful_checkers_discriminate_counterexamples():
    result = run_bfcl_native_parity(REPO_ROOT)
    assert result["passed"] is True
    assert result["formal_holdout_touched"] is False
    assert {row["source_task_id"] for row in result["rows"]} == {
        "irrelevance_148",
        "multiple_46",
        "simple_python_339",
    }
    assert all(row["known_good_passed"] is True for row in result["rows"])
    assert all(row["known_bad_passed"] is False for row in result["rows"])


def test_persisted_public_utility_parity_report_is_bound_and_nonclaim():
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    assert report["passed"] is True
    assert report["scientific_status"] == "nonclaim_development_native_checker_parity"
    assert report["formal_holdout_touched"] is False
    assert report["model_calls"] == 0
    rows = [
        row
        for section in report["benchmarks"].values()
        for row in section["rows"]
    ]
    assert len(rows) == 8
    assert all(row["counterexample_discriminates"] is True for row in rows)
    current_files = {
        relative: hashlib.sha256((REPO_ROOT / relative).read_bytes()).hexdigest()
        for relative in report["implementation_files"]
    }
    assert current_files == report["implementation_files"]
    assert report["implementation_sha256"] == sha256_json(current_files)
