from __future__ import annotations

import importlib.util
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
AUDITOR_PATH = (
    REPO_ROOT
    / "experiments"
    / "host_boundary_v2"
    / "rq1_original_a0_a4_v2"
    / "validate_implementation.py"
)


def _load_auditor():
    spec = importlib.util.spec_from_file_location(
        "original_rq1_v2_validate_implementation", AUDITOR_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_original_rq1_v2_offline_scaffold_passes_implementation_audit() -> None:
    result = _load_auditor().audit()
    assert result["passed"], result["errors"]
    assert result["registered_route_count"] == 12
    assert result["utility_workload_count"] == 5
    assert result["checks"]["all_five_surface_pairs_match"]
    assert result["checks"]["g2_core_artifact_is_current_and_passed"]
    assert result["checks"]["persisted_banks_match_current_compiler"]
    assert result["checks"]["bank_lock_hashes_match_artifacts"]
    assert result["checks"]["formal_bank_remains_sealed_unexecuted"]
    assert result["checks"]["development_activation_artifact_current_and_passed"]
