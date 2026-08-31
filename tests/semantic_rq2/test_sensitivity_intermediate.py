from __future__ import annotations

import unittest

from agentmembrane.semantic_rq2.schema import Receptor
from agentmembrane.semantic_rq2.sensitivity_intermediate import (
    final_conclusion_exemption_valid,
    intermediate_rubric_sha256,
    strict_failure_is_final_conclusion_candidate,
    validate_intermediate_audit,
)


def valid_payload() -> dict:
    return {
        "opaque_artifact_id": "oa-1",
        "explicit_final_conclusion_present": True,
        "all_nonfinal_propositions_entailed": True,
        "unsupported_content_confined_to_final_conclusion": True,
        "final_conclusion_support": "unsupported",
        "supported_evidence_ids": ["span-1"],
        "audited_nonfinal_proposition_count": 2,
        "notes": "The supporting propositions are entailed; the final recommendation is unsupported.",
    }


class IntermediateSensitivityTests(unittest.TestCase):
    def test_only_final_conclusion_support_is_exempt(self) -> None:
        payload = valid_payload()
        valid, problems = validate_intermediate_audit(
            payload,
            expected_artifact_id="oa-1",
            candidate_evidence_ids={"span-1"},
        )
        self.assertTrue(valid, problems)
        self.assertTrue(final_conclusion_exemption_valid(payload))

    def test_unsupported_nonfinal_reasoning_still_fails(self) -> None:
        payload = valid_payload()
        payload["all_nonfinal_propositions_entailed"] = False
        self.assertFalse(final_conclusion_exemption_valid(payload))

    def test_only_r3_r4_strict_fact_only_failures_are_candidates(self) -> None:
        strict_row = {
            "hard_valid": False,
            "deterministic": {"deterministic_valid": True},
            "audit": {
                "fact_valid": False,
                "qualifier_integrity": True,
                "no_evidence_denial": True,
                "no_control_instruction": True,
                "directness": "D3",
            },
        }
        self.assertTrue(
            strict_failure_is_final_conclusion_candidate(
                strict_row=strict_row,
                receptor=Receptor.R3,
            )
        )
        self.assertFalse(
            strict_failure_is_final_conclusion_candidate(
                strict_row=strict_row,
                receptor=Receptor.R2,
            )
        )
        strict_row["audit"]["qualifier_integrity"] = False
        self.assertFalse(
            strict_failure_is_final_conclusion_candidate(
                strict_row=strict_row,
                receptor=Receptor.R4,
            )
        )

    def test_intermediate_audit_remains_bound_to_artifact_and_packet(self) -> None:
        payload = valid_payload()
        valid, problems = validate_intermediate_audit(
            payload,
            expected_artifact_id="other",
            candidate_evidence_ids={"span-2"},
        )
        self.assertFalse(valid)
        self.assertIn("opaque_artifact_id_mismatch", problems)
        self.assertIn("supported_evidence_ids_outside_packet", problems)

    def test_rubric_hash_is_sha256(self) -> None:
        value = intermediate_rubric_sha256()
        self.assertEqual(len(value), 64)
        int(value, 16)


if __name__ == "__main__":
    unittest.main()
