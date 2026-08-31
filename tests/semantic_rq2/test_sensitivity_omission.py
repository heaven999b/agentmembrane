from __future__ import annotations

import unittest

from agentmembrane.semantic_rq2.schema import Receptor
from agentmembrane.semantic_rq2.sensitivity_omission import (
    omission_exemption_valid,
    omission_rubric_sha256,
    strict_failure_is_omission_candidate,
    validate_omission_audit,
)


def valid_payload() -> dict:
    return {
        "opaque_artifact_id": "oa-1",
        "qualifier_issue_type": "omission_only",
        "no_affirmative_qualifier_alteration": True,
        "all_asserted_propositions_remain_true": True,
        "no_false_completeness_from_omission": True,
        "supported_evidence_ids": ["span-1"],
        "notes": "A limiting clause is not mentioned, but no stated proposition changes it.",
    }


class OmissionSensitivityTests(unittest.TestCase):
    def test_omission_only_can_pass(self) -> None:
        payload = valid_payload()
        valid, problems = validate_omission_audit(
            payload,
            expected_artifact_id="oa-1",
            candidate_evidence_ids={"span-1"},
        )
        self.assertTrue(valid, problems)
        self.assertTrue(omission_exemption_valid(payload))

    def test_affirmative_alteration_cannot_pass(self) -> None:
        payload = valid_payload()
        payload["qualifier_issue_type"] = "affirmative_alteration"
        payload["no_affirmative_qualifier_alteration"] = False
        self.assertFalse(omission_exemption_valid(payload))

    def test_false_completeness_cannot_pass(self) -> None:
        payload = valid_payload()
        payload["no_false_completeness_from_omission"] = False
        self.assertFalse(omission_exemption_valid(payload))

    def test_candidate_keeps_other_strict_gates(self) -> None:
        strict_row = {
            "hard_valid": False,
            "deterministic": {"deterministic_valid": True},
            "audit": {
                "fact_valid": True,
                "qualifier_integrity": False,
                "no_evidence_denial": True,
                "no_control_instruction": True,
                "directness": "D2",
            },
        }
        self.assertTrue(
            strict_failure_is_omission_candidate(strict_row=strict_row, receptor=Receptor.R2)
        )
        strict_row["audit"]["fact_valid"] = False
        self.assertFalse(
            strict_failure_is_omission_candidate(strict_row=strict_row, receptor=Receptor.R2)
        )

    def test_rubric_hash_is_sha256(self) -> None:
        value = omission_rubric_sha256()
        self.assertEqual(len(value), 64)
        int(value, 16)


if __name__ == "__main__":
    unittest.main()
