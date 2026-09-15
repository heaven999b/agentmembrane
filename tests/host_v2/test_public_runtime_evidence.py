from __future__ import annotations

import copy
import unittest

from agentmembrane.host_v2.public_runtime_evidence import (
    build_public_runtime_evidence,
    validate_public_runtime_evidence,
)
from agentmembrane.host_v2.schema import IntegrityError, SchemaError


class PublicRuntimeEvidenceTests(unittest.TestCase):
    def _artifact(self):
        return build_public_runtime_evidence(
            gate_id="synthetic-offline-gate",
            generated_at="2026-08-30T00:00:00Z",
        )

    def test_missing_receipts_remain_deterministic_no_go(self) -> None:
        first = self._artifact()
        second = self._artifact()
        self.assertEqual(first.as_json(), second.as_json())
        self.assertEqual(first.decision, "NO_GO")
        self.assertIn("REQUIRED_RUNTIME_RECEIPT_MISSING", first.blocker_codes)
        self.assertEqual(first.offline_execution.task_executions, 0)
        self.assertEqual(first.offline_execution.parity_executions, 0)
        self.assertEqual(first.offline_execution.runtime_probe_network_attempts, 0)
        self.assertFalse(any(first.run_authorizations.as_json().values()))
        self.assertFalse(any(first.scientific_claims.as_json().values()))
        self.assertEqual(validate_public_runtime_evidence(first), first)

    def test_task_parity_and_every_authorization_are_fail_closed(self) -> None:
        for section, field, value in (
            ("offline_execution", "task_executions", 1),
            ("offline_execution", "parity_executions", 1),
            ("offline_execution", "runtime_probe_network_attempts", 1),
            ("run_authorizations", "checker_parity", True),
            ("run_authorizations", "provider_calls", True),
            ("run_authorizations", "formal_run", True),
            ("scientific_claims", "native_checker_parity_established", True),
        ):
            with self.subTest(section=section, field=field):
                raw = copy.deepcopy(self._artifact().as_json())
                raw[section][field] = value
                with self.assertRaises(IntegrityError):
                    validate_public_runtime_evidence(raw)

    def test_artifact_hash_and_no_go_decision_are_verified(self) -> None:
        raw = copy.deepcopy(self._artifact().as_json())
        raw["gate_id"] = "tampered"
        with self.assertRaisesRegex(IntegrityError, "artifact_sha256 mismatch"):
            validate_public_runtime_evidence(raw)
        raw = copy.deepcopy(self._artifact().as_json())
        raw["decision"] = "GO"
        with self.assertRaisesRegex(IntegrityError, "decision must equal NO_GO"):
            validate_public_runtime_evidence(raw)

    def test_unknown_field_is_rejected(self) -> None:
        raw = self._artifact().as_json()
        raw["native_verdict"] = True
        with self.assertRaises(SchemaError):
            validate_public_runtime_evidence(raw)


if __name__ == "__main__":
    unittest.main()
