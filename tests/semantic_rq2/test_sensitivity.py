from __future__ import annotations

import unittest

from agentmembrane.semantic_rq2.sensitivity import (
    relaxed_hard_valid,
    relaxed_rubric_sha256,
    validate_relaxed_audit,
)
from agentmembrane.semantic_rq2.schema import Receptor


def valid_payload() -> dict:
    return {
        "opaque_artifact_id": "oa-1",
        "source_fact_fidelity": True,
        "source_qualifier_integrity": True,
        "no_evidence_denial": True,
        "no_control_instruction": True,
        "task_conclusion_support": "unsupported",
        "directness": "D3",
        "supported_evidence_ids": ["span-1"],
        "atomic_source_claim_count": 1,
        "notes": "The source fact is faithful; the task conclusion is contestable.",
    }


class RelaxedSensitivityTests(unittest.TestCase):
    def test_unsupported_task_conclusion_does_not_fail_source_fidelity(self) -> None:
        payload = valid_payload()
        valid, problems = validate_relaxed_audit(
            payload,
            expected_artifact_id="oa-1",
            candidate_evidence_ids={"span-1"},
        )
        self.assertTrue(valid, problems)
        self.assertTrue(
            relaxed_hard_valid(
                deterministic_valid=True,
                audit=payload,
                receptor=Receptor.R3,
            )
        )

    def test_source_fidelity_still_fails_closed(self) -> None:
        payload = valid_payload()
        payload["source_fact_fidelity"] = False
        self.assertFalse(
            relaxed_hard_valid(
                deterministic_valid=True,
                audit=payload,
                receptor=Receptor.R4,
            )
        )

    def test_relaxed_audit_remains_bound_to_artifact_and_packet(self) -> None:
        payload = valid_payload()
        valid, problems = validate_relaxed_audit(
            payload,
            expected_artifact_id="oa-other",
            candidate_evidence_ids={"span-2"},
        )
        self.assertFalse(valid)
        self.assertIn("opaque_artifact_id_mismatch", problems)
        self.assertIn("supported_evidence_ids_outside_packet", problems)

    def test_rubric_hash_is_stable_sha256(self) -> None:
        value = relaxed_rubric_sha256()
        self.assertEqual(len(value), 64)
        int(value, 16)


if __name__ == "__main__":
    unittest.main()
