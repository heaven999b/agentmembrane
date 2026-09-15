"""Read-only Q/I/D diagnostic over a sealed v6 Workspace evidence payload.

This is deliberately separate from the formal v6 measurement entry point:
the 18 source drafts still need independent review and several quality/effect
observers. It produces bounded observations, never formal admission.
"""
from __future__ import annotations

import copy

from ..rq1_collab_v1.native import digest
from ..rq1_measurement_v1.information import derive_information_effects
from .evaluation import validate_evidence
from .workspace_qid_information import compile_workspace_draft_information
from .workspace_qid_priority_quality import PRIORITY, priority_quality
from .workspace_qid_remaining_quality import SUPPORTED as REMAINING_Q, remaining_quality
from .workspace_qid_readonly import (readonly_damage_contract, observe_readonly_damage,
                                     source_bound_workspace_draft)
from .workspace_qid_calendar_effect import calendar_damage_contract, observe_calendar_damage


def evaluate_workspace_qid_diagnostic(data: dict) -> dict:
    validate_evidence(data)
    source_hash = digest(data)
    record, task, initial = data["native_record"], data["task"], data["initial_snapshot"]
    draft = source_bound_workspace_draft(record, task["prompt"], initial)
    info_contract, facts = compile_workspace_draft_information(record, task["prompt"], initial)
    info_view = copy.deepcopy(data)
    info_view["schema_version"] = "rq1-evidence/5"
    info = derive_information_effects(info_view, {"information_contract": info_contract,
                                                  "private_facts": facts})
    if task["task_id"] in PRIORITY:
        quality = priority_quality(record, task["prompt"], initial, data["final_text"],
                                   terminal_reason=data["terminal_reason"],
                                   episode_id=data["episode_id"])
    elif task["task_id"] in REMAINING_Q:
        quality = remaining_quality(data)
    else:
        quality = {"content": {"lower": 0, "upper": 1, "evidence_ids": [],
                               "method": "source_specific_Q_observer_not_implemented",
                               "raw": {"required": draft["Q"]["unit_count"]}},
                   "effect": None,
                   "status": "diagnostic_only_not_formal_QID_registration",
                   "draft_sha256": draft["draft_sha256"]}
    if draft["D"]["allowed_native_effect"]["kind"] == "read_only":
        damage_contract = readonly_damage_contract(record, task["prompt"], initial)
        damage = observe_readonly_damage(data, damage_contract)
    else:
        damage_contract = calendar_damage_contract(record, task["prompt"], initial)
        damage = observe_calendar_damage(data, damage_contract)
    positive_by_recipient: dict[str, int] = {}
    for row in info["observations"]:
        if row["affected"] == 1:
            recipient = row["unit_id"].rsplit("@", 1)[1]
            positive_by_recipient[recipient] = positive_by_recipient.get(recipient, 0) + 1
    result = {"schema_version": "rq1-workspace-QID-diagnostic/1",
              "status": "diagnostic_only_not_formal_QID_registration",
              "episode_id": data["episode_id"], "task_key": draft["task_key"],
              "source_evidence_sha256": source_hash, "draft_sha256": draft["draft_sha256"],
              "Q": quality, "I": {"observations": info["observations"],
                                   "scope_incomplete": info["scope_incomplete"],
                                   "coverage": info["coverage"],
                                   "protected_unit_count": info_contract["counts"]["I_cells"],
                                   "confirmed_positive_by_recipient": positive_by_recipient,
                                   "unmatched_units_are_unknown": True,
                                   "status": info_contract["status"]},
              "D": damage,
              "limitations": ["development_draft_not_independently_reviewed",
                              "exact_information_receipts_are_lower_bounds",
                              "free_prose_quality_requires_calibrated_semantic_evidence",
                              "W28_W30_content_atomization_unresolved"],
              "formal_ready": False}
    if digest(data) != source_hash:
        raise ValueError("workspace_qid_diagnostic_mutated_evidence")
    return result
