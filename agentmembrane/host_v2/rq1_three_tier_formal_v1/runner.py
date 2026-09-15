"""Public, fail-closed entry point for the formal three-tier runtime.

The sealed H/E controller core is implemented and tested, but the production
entry point does not yet own the required per-cell proxy lifecycle.  A one-off
proxy rehearsal cannot establish that every research cell starts a fresh
process, checks readiness, stops it, removes its secret root, and seals that
cleanup result with the cell.  Until that outer controller exists, neither a
caller-supplied driver nor transport is accepted here.
"""
from __future__ import annotations

from .contract import FORMAL_PROTOCOL


FORMAL_CORE_RUNTIME_IMPLEMENTED = True
FORMAL_PER_CELL_PROXY_LIFECYCLE_IMPLEMENTED = False
FORMAL_RUNTIME_IMPLEMENTED = False
FORMAL_EVIDENCE_SCHEMA = "rq1-evidence-formal/1"
FORMAL_ACTION_SCHEMAS = {
    "H": {
        "actors": ["H", "E"],
        "message_recipient_enum": [],
        "delegate_recipient_enum": [],
        "final_owner": "H",
    },
    "E": {
        "actors": ["H", "E"],
        "message_recipient_enum": ["H"],
        "delegate_recipient_enum": [],
        "final_handoff_recipient": "H",
    },
}


def run_formal_cell(*, manifest=None, episode_id=None, run_parent=None):
    """Refuse production execution until this entry point owns lifecycle.

    The eventual public API deliberately has no ``driver`` or ``transport``
    parameter.  Those objects must be created from the manifest-bound route by
    the production lifecycle controller, never supplied by its caller.
    """
    if manifest is None:
        raise RuntimeError("activated_formal_manifest_required")
    if FORMAL_PER_CELL_PROXY_LIFECYCLE_IMPLEMENTED is not True:
        raise RuntimeError(
            "formal_per_cell_proxy_lifecycle_not_implemented")
    raise RuntimeError("formal_production_runtime_unavailable")


def evidence_envelope_contract() -> dict:
    return {
        "schema_version": FORMAL_EVIDENCE_SCHEMA,
        "protocol_version": FORMAL_PROTOCOL,
        "required_manifest_rule": "exact_registered_manifest_sha256",
        "legacy_source": False,
        "allocated_after_manifest_registration": True,
        "allocation_source": "fresh_collector_lock_and_registered_cell",
        "one_shot_runtime_object_claim": True,
        "fake_transport_proves_proxy_process_lifecycle": False,
        "production_proxy_lifecycle_receipt_required_by_gate": True,
        "per_cell_proxy_lifecycle_implemented": False,
        "offline_core_evidence_eligible_for_formal_results": False,
        "formal_activation_blocker": (
            "per_cell_start_readiness_run_stop_secret_cleanup_not_integrated"),
        "formal_evidence_written_before_execution_seal": True,
    }
