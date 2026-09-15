"""A denied Banking tool call must remain sealable without admitting secrets."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agentmembrane.host_v2.rq1_collab_v1.audit import EventCollector, verify


def _denied_receipt() -> dict:
    return {
        "call_id": "fixture:native", "actor": "E", "principal": "external",
        "tool": "send_money",
        "arguments": {"recipient": "unrelated", "amount": 1.0},
        "before": {"user_account": {"password": "simulated-state-value"}},
        "after": None, "status": "rejected",
        "policy_reason": "refund_outside_original_recipient_amount",
        "record_origin": "trusted_native_adapter",
        "evidence_quality": {"backend_entered": False, "commit_status": "confirmed"},
    }


class BankingRejectedNativeEvidenceTests(unittest.TestCase):
    def test_denial_preserves_before_state_and_seals(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "run"
            collector = EventCollector(root, "banking-denial")
            receipt = _denied_receipt()
            event = collector.emit("native_rejected", receipt, actor="E")
            seal = collector.seal({"purpose": "banking_denial_regression"})
            self.assertEqual(event["data"]["before"], receipt["before"])
            self.assertTrue(verify(root, expected_seal_hash=seal["seal_hash"])["ok"])

    def test_exception_does_not_admit_actor_or_untrusted_passwords(self):
        mutations = (
            {"arguments": {"password": "actor-supplied"}},
            {"record_origin": "untrusted"},
            {"after": {"user_account": {"password": "unexpected"}}},
            {"evidence_quality": {"backend_entered": True, "commit_status": "confirmed"}},
        )
        with tempfile.TemporaryDirectory() as directory:
            collector = EventCollector(Path(directory) / "run", "banking-denial")
            for mutation in mutations:
                with self.subTest(mutation=mutation):
                    receipt = _denied_receipt()
                    receipt.update(mutation)
                    with self.assertRaisesRegex(ValueError, "credential/header field forbidden"):
                        collector.emit("native_rejected", receipt, actor="E")
            collector.abort()


if __name__ == "__main__":
    unittest.main()
