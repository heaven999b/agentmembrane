"""Pre-outcome binding for candidate Q/I/D contracts.

The source-specific Q/I/D observers were added after some v6 episodes had
already been sealed.  Their existence must never make those old episodes look
as though they were run under the new answer and measurement contract.  This
module therefore records a small, public, deterministic descriptor before the
first actor executes.  The descriptor is evidence of registration timing; it
does not promote a review draft to a formal contract and it does not score an
outcome.
"""
from __future__ import annotations

import hashlib

from ..rq1_collab_v3.contract import clone, digest


VERSION = "rq1-qid-pre-run-registration/1"
STATUS = "candidate_bound_before_actor_not_formal"


def _sha256_text(value: str) -> str:
    if type(value) is not str or not value:
        raise ValueError("nonempty_public_H_prompt_required")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _task_binding(record: dict, prompt: str) -> dict:
    required = (
        "suite", "task_id", "initial_state_sha256", "class_source_sha256",
        "prompt_sha256",
    )
    if type(record) is not dict or any(type(record.get(key)) is not str for key in required):
        raise ValueError("complete_native_source_binding_required")
    # NativeTask binds strings with the repository's canonical-JSON digest,
    # while the public H prompt below is deliberately a raw UTF-8 text hash.
    if digest(prompt) != record["prompt_sha256"]:
        raise ValueError("qid_prompt_source_binding_mismatch")
    return {key: record[key] for key in required}


def _workspace_candidate(record: dict, prompt: str, initial: dict) -> dict:
    from .workspace_qid_readonly import source_bound_workspace_draft

    draft = source_bound_workspace_draft(record, prompt, initial)
    q_units = draft["Q"]["units"]
    info = draft["I"]
    damage = draft["D"]
    return {
        "family": "workspace_source_locked_review_draft_v1",
        "draft_sha256": draft["draft_sha256"],
        "Q": {
            "registered_unit_count": len(q_units),
            "point_certified_pre_outcome": False,
            "reason": "outcome_observer_exists_but_review_draft_is_not_formal_registration",
        },
        "I": {
            "candidate_full_denominator": info["proposed_I_cells"],
            "point_certified_pre_outcome": False,
            "reason": "unmatched_fact_recipient_cells_remain_unknown_without_semantic_absence_proof",
        },
        "D": {
            "registered_unit_count": damage["proposed_D_units"],
            "point_certified_pre_outcome": False,
            "reason": "outcome_observer_exists_but_review_draft_is_not_formal_registration",
        },
        "formal_blockers": [
            "workspace_review_draft_not_independently_adjudicated",
            "full_information_nonarrival_not_certified",
            "candidate_not_promoted_to_formal_contract_or_report_admission",
        ],
    }


def _other_candidate(record: dict, prompt: str, initial: dict) -> dict:
    from ..rq1_measurement_v1.qid_other_effects import _CONTRACTS, score_effects
    from ..rq1_measurement_v1.qid_other_information_full import compile_full_candidate_contract
    from ..rq1_measurement_v1.qid_other_quality import quality_registration_summary

    task_key = record["suite"] + "/" + record["task_id"]
    draft = _CONTRACTS.get(task_key)
    if draft is None:
        raise ValueError("qid_other_task_not_registered")
    # This is a source-lock check against the untouched initial world, not an
    # outcome measurement.  A mismatch leaves the task unregistrable.
    effects = score_effects(task_key, initial, initial, record)
    if effects.get("D") != 0:
        raise ValueError("qid_other_source_or_initial_world_mismatch")
    information, private_facts = compile_full_candidate_contract(
        task_key, initial, record)
    if (information.get("formal_activation") is not False
            or information.get("private_facts_sha256") != digest(private_facts)
            or type(information.get("counts", {}).get("I_cells")) is not int):
        raise ValueError("qid_other_full_information_candidate_not_source_bound")
    quality = quality_registration_summary(task_key)
    return {
        "family": "other_source_locked_review_draft_v1",
        "draft_sha256": digest(draft),
        "Q": {
            "registered_unit_count": quality["registered_atom_count"],
            "mechanically_implemented_unit_count": quality["mechanically_implemented_atom_count"],
            "intrinsically_unknown_unit_count": quality["intrinsically_unknown_atom_count"],
            "answer_contract_version": quality["answer_contract_version"],
            "point_certified_pre_outcome": False,
            "reason": "answer_contract_not_explicitly_activated_by_a_formal_manifest",
        },
        "I": {
            "registered_source_fact_count": information["counts"]["I_field_count"],
            "registered_recipient_count": information["counts"]["R"],
            "candidate_raw_fact_recipient_cells": information["counts"]["raw_fact_recipient_cells"],
            "legal_cells_excluded": information["counts"]["legal_cells_excluded"],
            "candidate_full_denominator": information["counts"]["I_cells"],
            "candidate_contract_sha256": information["contract_sha256"],
            "unknown_regions": clone(information["unknown_regions"]),
            "point_certified_pre_outcome": False,
            "reason": "full_candidate_denominator_bound_but_nonarrival_and_review_blockers_remain",
        },
        "D": {
            "source_locked_terminal_observer": True,
            "point_certified_pre_outcome": False,
            "reason": "review_draft_is_not_formal_registration",
        },
        "formal_blockers": [
            "other_review_draft_not_independently_adjudicated",
            "full_information_nonarrival_not_certified",
            "formal_answer_contract_not_manifest_activated",
            "candidate_not_promoted_to_formal_contract_or_report_admission",
        ] + clone(information["formal_blockers"]) + (
            ["one_or_more_Q_atoms_intrinsically_ambiguous"]
            if quality["intrinsically_unknown_atom_count"] else []),
    }


def _existing_candidate() -> dict:
    """Describe tasks already handled by the pre-existing v1 compiler."""
    return {
        "family": "existing_v1_source_registered_measurement",
        "draft_sha256": None,
        "Q": {"registration": "existing_v1_source_contract"},
        "I": {
            "registration": "existing_v1_source_contract",
            "point_certified_pre_outcome": False,
            "reason": "semantic_nonarrival_is_not_certified_for_every_registered_cell",
        },
        "D": {"registration": "existing_v1_source_contract"},
        "formal_blockers": [
            "full_information_nonarrival_not_certified",
            "candidate_not_promoted_to_formal_contract_or_report_admission",
        ],
    }


def _unregistered_candidate(record: dict) -> dict:
    """Bind absence of a source-specific candidate without blocking v6.

    This descriptor registers no units and permits no Q/I/D inference.  It is
    useful only to prove that the task identity and public H prompt were fixed
    before actor execution.
    """
    task_key = record["suite"] + "/" + record["task_id"]
    return {
        "family": "source_bound_qid_candidate_not_registered_v1",
        "task_key": task_key,
        "draft_sha256": None,
        "coverage_status": "not_registered_for_this_task",
        "Q": {
            "registered_unit_count": 0,
            "point_certified_pre_outcome": False,
            "reason": "no_source_specific_Q_candidate_registered",
        },
        "I": {
            "candidate_full_denominator": None,
            "point_certified_pre_outcome": False,
            "reason": "no_source_specific_I_candidate_registered",
        },
        "D": {
            "registered_unit_count": 0,
            "point_certified_pre_outcome": False,
            "reason": "no_source_specific_D_candidate_registered",
        },
        "formal_blockers": [
            "source_specific_QID_candidate_not_registered_for_task",
        ],
    }


def compile_pre_run_registration(*, episode_id: str, bundle_sha256: str,
                                 record: dict, prompt: str, initial: dict,
                                 public_h_prompt: str,
                                 source_contract_sha256: str,
                                 protected_contract_sha256: str,
                                 information_contract_sha256: str,
                                 reference_sha256: str,
                                 measurement_adapter: str) -> dict:
    """Compile a non-secret candidate descriptor before actor execution.

    All supplied measurement hashes are the hashes already written by the v6
    workflow's pre-run compiler.  No terminal state, model response, delivery,
    or attack outcome is accepted by this function.
    """
    hashes = {
        "source_contract_sha256": source_contract_sha256,
        "protected_contract_sha256": protected_contract_sha256,
        "information_contract_sha256": information_contract_sha256,
        "reference_sha256": reference_sha256,
    }
    if (type(episode_id) is not str or not episode_id
            or type(bundle_sha256) is not str or len(bundle_sha256) != 64
            or any(type(value) is not str or len(value) != 64 for value in hashes.values())):
        raise ValueError("complete_pre_run_measurement_hashes_required")
    binding = _task_binding(record, prompt)
    if measurement_adapter not in {"source_identity_only_v1", "reviewed_six_v1"}:
        raise ValueError("known_measurement_adapter_required")
    if measurement_adapter != "source_identity_only_v1":
        candidate = _existing_candidate()
    elif record["suite"] == "workspace":
        from .workspace_qid_readonly import registered_workspace_draft_task_keys
        task_key = record["suite"] + "/" + record["task_id"]
        candidate = (_workspace_candidate(record, prompt, initial)
                     if task_key in registered_workspace_draft_task_keys()
                     else _unregistered_candidate(record))
    elif record["suite"] in {"banking", "slack", "travel"}:
        from ..rq1_measurement_v1.qid_other_effects import _CONTRACTS
        task_key = record["suite"] + "/" + record["task_id"]
        candidate = (_other_candidate(record, prompt, initial)
                     if task_key in _CONTRACTS else _unregistered_candidate(record))
    else:
        candidate = _unregistered_candidate(record)
    body = {
        "schema_version": VERSION,
        "status": STATUS,
        "episode_id": episode_id,
        "bundle_sha256": bundle_sha256,
        "task_binding": binding,
        "public_H_prompt_sha256": _sha256_text(public_h_prompt),
        "measurement_contract_hashes": hashes,
        "measurement_adapter": measurement_adapter,
        "candidate": candidate,
        "compiled_before_actor_execution": True,
        "formal_activation": False,
    }
    return {**body, "registration_sha256": digest(body)}


def validate_pre_run_registration(registration: dict, *, data: dict,
                                  public_h_prompt: str) -> dict:
    """Validate a sealed descriptor and return a small admission summary."""
    if type(registration) is not dict:
        raise ValueError("qid_pre_run_registration_object_required")
    body = {key: clone(value) for key, value in registration.items()
            if key != "registration_sha256"}
    if (registration.get("schema_version") != VERSION
            or registration.get("status") != STATUS
            or registration.get("registration_sha256") != digest(body)
            or registration.get("compiled_before_actor_execution") is not True
            or registration.get("formal_activation") is not False):
        raise ValueError("qid_pre_run_registration_integrity_failure")
    expected_binding = _task_binding(data["native_record"], data["task"]["prompt"])
    if (registration.get("episode_id") != data.get("episode_id")
            or registration.get("bundle_sha256") != data.get("bundle_sha256")
            or registration.get("task_binding") != expected_binding
            or registration.get("public_H_prompt_sha256") != _sha256_text(public_h_prompt)):
        raise ValueError("qid_pre_run_registration_execution_binding_mismatch")
    candidate = registration.get("candidate")
    if (type(candidate) is not dict or candidate.get("family") not in {
            "workspace_source_locked_review_draft_v1",
            "other_source_locked_review_draft_v1",
            "existing_v1_source_registered_measurement",
            "source_bound_qid_candidate_not_registered_v1",
            } or type(candidate.get("formal_blockers")) is not list
            or not candidate["formal_blockers"]):
        raise ValueError("qid_pre_run_candidate_status_invalid")
    return {
        "status": "bound_candidate_not_formal",
        "registration_sha256": registration["registration_sha256"],
        "family": candidate["family"],
        "formal_activation": False,
        "formal_blockers": clone(candidate["formal_blockers"]),
    }


def evidence_registration_status(data: dict, *, public_h_prompt: str) -> dict:
    """Fail closed for legacy evidence instead of retroactively activating QID."""
    registration = data.get("qid_pre_run_registration")
    if registration is None:
        return {
            "status": "not_bound_before_episode",
            "registration_sha256": None,
            "family": None,
            "formal_activation": False,
            "formal_blockers": ["sealed_evidence_has_no_pre_run_QID_binding"],
        }
    return validate_pre_run_registration(
        registration, data=data, public_h_prompt=public_h_prompt,
    )
