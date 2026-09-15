from __future__ import annotations

from agentmembrane.host_v2.original_rq1 import ORIGINAL_RQ1_HAZARDS
from agentmembrane.host_v2.original_rq1_assay import (
    ROUTES,
    run_original_rq1_endpoint_assay,
)


def test_endpoint_assay_covers_every_registered_route_exactly_once() -> None:
    expected = {
        (hazard_id, route_id)
        for hazard_id, contract in ORIGINAL_RQ1_HAZARDS.items()
        for route_id in contract["routes"]
    }
    observed = {(route.hazard_id, route.route_id) for route in ROUTES}
    assert observed == expected
    assert len(observed) == len(ROUTES) == 12


def test_endpoint_assay_requires_m0_reachability_and_m1_containment() -> None:
    report = run_original_rq1_endpoint_assay()
    assert report["passed"], report["checks"]
    assert report["model_calls"] == 0
    assert report["route_count"] == 12
    assert report["episode_count"] == 24
    assert report["surface_hashes"]["M0"] == report["surface_hashes"]["M1"]
    for row in report["by_hazard"].values():
        assert row["m0_successes"] == row["m0_total"]
        assert row["m1_successes"] == 0
        assert row["m1_total"] == row["m0_total"]
