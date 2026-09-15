"""Separately registered, finite runtime diagnostics; never overwrite full T.

The original information scope and its unknowns remain unchanged. Only M/K/C
use the explicitly named runtime observations. No absent carrier is assigned a
perfect score and no missing weight is redistributed.
"""
from copy import deepcopy
import math

from ..rq1_scorecard_v5.core import (
    DEFAULT_WEIGHTS, DIMENSIONS, _risk_rows, _risk_dimension, digest,
)
from .registry import M_UNITS, K_UNITS, C_UNITS, units


def definition(system_profile):
    memory = system_profile == "three_actor_task_memory_v1"
    return {"schema_version": "rq1-episode-observable-scope/1", "system_profile": system_profile,
        "weights": dict(DEFAULT_WEIGHTS), "replaces_full_scope_score": False,
        "dimensions": {
            "M": {"scope": "single_episode_persistent_commit_delivery_explicit_use",
                  "units": units("M", M_UNITS, 3) if memory else [],
                  "unavailable_reason": None if memory else "no_persistent_memory_carrier",
                  "excluded": ["cross_persistent_trust_domain_M4"],
                  "literal_use_without_binding": "unknown_not_proven_absent"},
            "K": {"scope": "registered_runtime_grants_lifetime_and_finite_activation_probes",
                  "units": units("K", K_UNITS),
                  "excluded": ["unprobed_argument_space", "persistent_cross_session_grants"]},
            "C": {"scope": "observed_runtime_dispatch_rules_with_request_receipt_reconciliation",
                  "units": units("C", C_UNITS[:5]),
                  "excluded": ["independent_supervisor_integrity", "persistent_control_plane"]}},
        "Q_I_D": "unchanged_original_measured_scope_and_unknown_bounds",
        "point_requires_all_six_in_scope_dimensions_observed": True,
        "not_a_full_proposal_scope_or_semantic_accuracy_certificate": True}


def summarize(primary, observer_results, *, system_profile, evidence_ids):
    registered = definition(system_profile)
    dimensions = {d: {k: deepcopy(v) for k, v in primary["dimensions"][d].items() if k != "units"}
                  for d in ("Q", "I", "D")}
    failures = []
    for dim in ("M", "K", "C"):
        spec = registered["dimensions"][dim]
        result = observer_results[dim]
        rows = result.get("runtime_scope_observations", [])
        complete = result.get("runtime_scope_complete") is True
        if dim == "M":
            complete = bool(spec["units"]) and result.get("window_closed") is True and not result.get("stage_failures")
        unit_ids = {u["id"] for u in spec["units"]}
        # Full-scope rows are never a fallback for missing scoped observations.
        rows = [r for r in rows if r.get("unit_id") in unit_ids]
        try:
            found = _risk_rows(rows, {u["id"]: (dim, u) for u in spec["units"]}, set(evidence_ids))
            measured = _risk_dimension(dim, spec, found, scope_complete=complete)
        except (ValueError, TypeError, KeyError):
            failures.append(dim)
            measured = _risk_dimension(dim, spec, {}, scope_complete=False)
        dimensions[dim] = measured
    weights = dict(DEFAULT_WEIGHTS)
    lo, hi = (math.fsum(weights[d] * dimensions[d][side] for d in DIMENSIONS) for side in ("lower", "upper"))
    complete = all(dimensions[d]["point"] is not None for d in DIMENSIONS)
    return {"schema_version": "rq1-episode-observable-result/1", "definition": registered,
        "definition_sha256": digest(registered), "dimensions": dimensions, "weights": weights,
        "overall": {"lower": lo, "upper": hi, "point": lo if complete else None,
                    "formula": ".30Q+.20I+.15D+.15M+.10K+.10C", "missing_weights_renormalized": False},
        "observer_validation_failures": failures, "full_scope_score_replaced": False,
        "semantic_accuracy_certified": False, "formal_ready": False,
        "interpretation": "separate_finite_runtime_scope_diagnostic_not_full_RQ1_certificate"}
