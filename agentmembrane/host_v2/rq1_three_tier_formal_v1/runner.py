"""Production entry point for one manifest-bound three-tier formal cell.

The caller may select only an activated manifest, registered episode, and fresh
output parent.  This module owns every execution object and the per-cell proxy
lifecycle.  A cell is sealed as production evidence only after the exact bound
runner has started a fresh proxy, readiness has passed, actor execution has
closed, the transport credential has been cleared, the process has stopped,
and the private secret root has been removed.
"""
from __future__ import annotations

from pathlib import Path

from ..rq1_collab_v1.audit import EventCollector
from ..rq1_collab_v6.attack_spec import compile_attack_spec
from .contract import FORMAL_PROTOCOL
from .driver import FormalRoleModelDriver, role_prompts
from .proxy_lifecycle import PerCellProxyLifecycle
from .runtime_impl import (
    _run_production_formal_cell_core,
    _seal_failed_attempt,
    inner_config,
    registered_execution_resource,
    validate_cell,
)


FORMAL_CORE_RUNTIME_IMPLEMENTED = True
FORMAL_PER_CELL_PROXY_LIFECYCLE_IMPLEMENTED = True
FORMAL_RUNTIME_IMPLEMENTED = True
FORMAL_EVIDENCE_SCHEMA = "rq1-evidence-formal/2"
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


def _registered_cell(manifest: dict, episode_id: str) -> dict:
    matches = [cell for cell in manifest.get("cells", [])
               if cell.get("episode_id") == episode_id]
    if len(matches) != 1:
        raise ValueError("exact_registered_formal_cell_required")
    return validate_cell(matches[0])


def _fresh_run_dir(run_parent: str | Path, episode_id: str) -> Path:
    parent = Path(run_parent)
    if parent.is_symlink():
        raise ValueError("formal_run_parent_symlink_not_allowed")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not parent.is_dir():
        raise ValueError("formal_run_parent_directory_required")
    run_dir = parent / episode_id
    if run_dir.exists() or run_dir.is_symlink():
        raise FileExistsError("formal_attempt_directory_already_exists")
    return run_dir


def run_formal_cell(*, manifest=None, episode_id=None, run_parent=None):
    """Execute exactly one fresh registered cell with no injectable runtime."""
    if manifest is None:
        raise RuntimeError("activated_formal_manifest_required")
    if type(episode_id) is not str or not episode_id:
        raise ValueError("registered_formal_episode_id_required")
    if run_parent is None:
        raise ValueError("fresh_formal_run_parent_required")
    from .gate import validate_formal_manifest

    manifest = validate_formal_manifest(manifest)
    cell = _registered_cell(manifest, episode_id)
    run_dir = _fresh_run_dir(run_parent, episode_id)
    collector = EventCollector(run_dir, episode_id)
    lifecycle = None
    try:
        lifecycle = PerCellProxyLifecycle(
            manifest=manifest, cell=cell, collector=collector)
        transport = lifecycle.start()
        with registered_execution_resource(
                manifest, cell["task_key"]) as resource:
            bundle, adapter = resource["bundle"], resource["adapter"]
            cfg = inner_config(cell, bundle.sha256)
            public_goal = bundle.record()["public"]["goal"]["goal"]
            prompts = role_prompts(
                cfg, adapter.prompt, public_goal,
                attack_spec=compile_attack_spec(public_goal),
            )
            driver = FormalRoleModelDriver(
                cfg, prompts, collector, transport)
            result = _run_production_formal_cell_core(
                manifest=manifest, episode_id=episode_id,
                bundle=bundle, adapter=adapter, driver=driver,
                collector=collector, lifecycle=lifecycle,
            )
        return result
    except BaseException as exc:
        cleanup = (lifecycle.cleanup_after_failure()
                   if lifecycle is not None else {
                       "process_stop_confirmed": True,
                       "secret_cleanup_confirmed": True,
                   })
        _seal_failed_attempt(
            collector, manifest=manifest, cell=cell,
            allocation=None, exc=exc, cleanup=cleanup,
        )
        raise


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
        "per_cell_proxy_lifecycle_implemented": True,
        "offline_core_evidence_eligible_for_formal_results": False,
        "production_seal_order": [
            "proxy_process_started", "readiness_probe_passed",
            "formal_actor_run_closed", "proxy_process_stopped",
            "secret_cleanup_completed", "formal_evidence_admitted",
            "collector_seal",
        ],
        "formal_evidence_written_before_execution_seal": True,
    }
