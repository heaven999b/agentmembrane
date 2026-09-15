"""Candidate QID registration is pre-outcome, tamper evident, and non-formal."""
from __future__ import annotations

import copy
import unittest

from agentmembrane.host_v2.rq1_collab_v3.contract import digest
from agentmembrane.host_v2.rq1_collab_v6.qid_registration import (
    compile_pre_run_registration, evidence_registration_status,
    validate_pre_run_registration,
)


class QIDPreRunRegistrationTests(unittest.TestCase):
    def setUp(self):
        self.prompt = "A source-bound public request"
        self.h_prompt = "exact public H system prompt"
        self.record = {
            "suite": "workspace", "task_id": "user_task_35",
            "initial_state_sha256": "1" * 64,
            "class_source_sha256": "2" * 64,
            "prompt_sha256": digest(self.prompt),
        }
        self.registration = compile_pre_run_registration(
            episode_id="episode-1", bundle_sha256="3" * 64,
            record=self.record, prompt=self.prompt, initial={},
            public_h_prompt=self.h_prompt,
            source_contract_sha256="4" * 64,
            protected_contract_sha256="5" * 64,
            information_contract_sha256="6" * 64,
            reference_sha256="7" * 64,
            measurement_adapter="reviewed_six_v1",
        )
        self.data = {
            "episode_id": "episode-1", "bundle_sha256": "3" * 64,
            "native_record": self.record,
            "task": {"prompt": self.prompt},
            "qid_pre_run_registration": self.registration,
        }

    def test_candidate_is_bound_but_never_formally_activated(self):
        status = validate_pre_run_registration(
            self.registration, data=self.data, public_h_prompt=self.h_prompt)
        self.assertEqual(status["status"], "bound_candidate_not_formal")
        self.assertFalse(status["formal_activation"])
        self.assertTrue(status["formal_blockers"])

    def test_registration_tamper_is_rejected(self):
        forged = copy.deepcopy(self.registration)
        forged["formal_activation"] = True
        with self.assertRaisesRegex(ValueError, "integrity_failure"):
            validate_pre_run_registration(
                forged, data=self.data, public_h_prompt=self.h_prompt)

    def test_execution_binding_tamper_is_rejected(self):
        forged_data = copy.deepcopy(self.data)
        forged_data["episode_id"] = "other-episode"
        with self.assertRaisesRegex(ValueError, "execution_binding_mismatch"):
            validate_pre_run_registration(
                self.registration, data=forged_data,
                public_h_prompt=self.h_prompt)

    def test_legacy_evidence_is_explicitly_unbound(self):
        legacy = copy.deepcopy(self.data)
        legacy.pop("qid_pre_run_registration")
        status = evidence_registration_status(
            legacy, public_h_prompt=self.h_prompt)
        self.assertEqual(status["status"], "not_bound_before_episode")
        self.assertFalse(status["formal_activation"])
        self.assertEqual(status["formal_blockers"],
                         ["sealed_evidence_has_no_pre_run_QID_binding"])

    def test_workspace_15_without_qid_draft_does_not_block_v6(self):
        record = copy.deepcopy(self.record)
        record["task_id"] = "user_task_15"
        registration = compile_pre_run_registration(
            episode_id="episode-w15", bundle_sha256="8" * 64,
            record=record, prompt=self.prompt, initial={},
            public_h_prompt=self.h_prompt,
            source_contract_sha256="4" * 64,
            protected_contract_sha256="5" * 64,
            information_contract_sha256="6" * 64,
            reference_sha256="7" * 64,
            measurement_adapter="source_identity_only_v1",
        )
        candidate = registration["candidate"]
        self.assertEqual(candidate["family"],
                         "source_bound_qid_candidate_not_registered_v1")
        self.assertEqual(candidate["coverage_status"],
                         "not_registered_for_this_task")
        self.assertEqual(candidate["Q"]["registered_unit_count"], 0)
        self.assertIsNone(candidate["I"]["candidate_full_denominator"])
        self.assertEqual(candidate["D"]["registered_unit_count"], 0)
        self.assertFalse(registration["formal_activation"])


if __name__ == "__main__":
    unittest.main()
