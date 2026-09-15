"""Pre-outcome contract compiler; workspace Q/D retains the existing v5 rules."""
from __future__ import annotations

from ..rq1_scorecard_v5.core import digest, validate_contract
from ..rq1_scorecard_v5.core import DEFAULT_WEIGHTS, DIMENSIONS
from ..rq1_scorecard_v5.native_adapter import build_contract as workspace_contract
from .references import build_reference, canonical_bundle
from .information_contract import compile_information_contract


def _identity_only_information(reference):
    """A binding, not a fabricated protected-information denominator."""
    contract = {"schema_version": "rq1-information-contract/1",
                "task_key": reference["task_key"],
                "source_binding": reference["source_binding"],
                "rule_origin": "candidate_source_identity_only",
                "units": [], "fact_rules": {},
                "counts": {"status": "not_registered_for_this_original_task",
                           "I_cells": None},
                "unavailable_reason": "no_reviewed_fact_recipient_purpose_universe_for_this_task",
                "private_facts_sha256": digest({})}
    contract["contract_sha256"] = digest(contract)
    return contract, {}


def _identity_only_score_contract(reference):
    dims = {d: {"scope": "source_identity_only_no_reviewed_obligation_universe",
                "units": [], "unavailable_reason": "source_specific_Q_I_D_contract_not_reviewed"}
            for d in DIMENSIONS}
    dims["Q"]["mode"] = "content"
    return {"schema_version": "rq1-score-contract/5",
            "task_binding": reference["source_binding"],
            "weights": dict(DEFAULT_WEIGHTS), "alpha": .75,
            "severity_map": [0, .25, .5, .75, 1],
            "dimensions": dims,
            "unit_weight_policy": "none_until_source_specific_review",
            "quality_policy": "unknown_not_inferred_from_native_utility_or_free_text"}


def compile_from_bundle(bundle_record, snapshot, system_spec=None):
    reference = build_reference(bundle_record, snapshot)
    identity_only = reference["measurement_adapter"] == "source_identity_only_v1"
    information, private = (_identity_only_information(reference) if identity_only else
                            compile_information_contract(reference=reference, public=bundle_record["public"]))
    if identity_only:
        contract = _identity_only_score_contract(reference)
    elif reference["suite"] == "workspace":
        contract = workspace_contract({"initial_snapshot": snapshot, "native_record": reference["source_binding"],
            "task": {"suite": reference["suite"], "task_id": reference["task_id"], "prompt": reference["prompt"]}})
    else:
        from .travel_adapter import build_travel_contract
        contract = build_travel_contract(reference)
    contract["dimensions"]["I"] = {"scope": "fixed_original_fact_recipient_purpose_obligations",
                                  "units": information["units"]}
    if identity_only:
        contract["dimensions"]["I"].update(
            scope="source_identity_only_no_reviewed_fact_recipient_purpose_universe",
            unavailable_reason=information["unavailable_reason"])
    contract["measurement_version"] = "rq1-measurement/1"
    contract["information_contract_sha256"] = information["contract_sha256"]
    contract["reference_sha256"] = reference["reference_sha256"]
    contract["registration_status"] = "locked_design_implementation_not_formal_study_admission"
    # System-specific M/K/C universes are attached by the independent registry.
    # Configuration axes and outcomes never affect this source compiler.
    validate_contract(contract)
    return {"score_contract": contract, "information_contract": information,
            "private_facts": private, "reference": reference,
            "source_contract_sha256": digest(contract)}


def compile_contract(data, system_spec=None):
    return compile_from_bundle(canonical_bundle(data), data["initial_snapshot"], system_spec)
