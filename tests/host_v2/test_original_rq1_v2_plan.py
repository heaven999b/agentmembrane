from __future__ import annotations

import importlib.util
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = (
    REPO_ROOT
    / "experiments"
    / "host_boundary_v2"
    / "rq1_original_a0_a4_v2"
    / "validate_plan.py"
)


def _load_validator():
    spec = importlib.util.spec_from_file_location("original_rq1_v2_validate_plan", VALIDATOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_original_rq1_v2_plan_passes_fail_closed_audit() -> None:
    result = _load_validator().audit()
    assert result["passed"] is True, result["errors"]
    assert result["computed"]["primary_cell_count"] == 10
    assert result["computed"]["planned_minimum_n"] >= result["computed"]["mathematical_minimum_n"]


def test_original_rq1_v2_plan_uses_exact_original_construct() -> None:
    result = _load_validator().audit()
    checks = result["checks"]
    assert checks["construct_is_original_authority_boundary"]
    assert checks["exact_five_level_mapping"]
    assert checks["later_delegation_not_a_level"]
    assert checks["exact_five_original_hazards"]
    assert checks["exactly_two_banks"]
