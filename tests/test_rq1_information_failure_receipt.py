"""Delivered provider failures remain model-consumption receipts."""
from __future__ import annotations

import copy
import unittest

from agentmembrane.host_v2.rq1_measurement_v1.information import actual_receipts


class DeliveredFailureReceiptTests(unittest.TestCase):
    def setUp(self):
        self.payload = {"actor": "E", "history": [], "private": "example-secret"}
        self.delivery = {
            "event_id": "episode:7", "actor": "E",
            "status": "model_response_observed", "payload": self.payload,
            "model_binding": None, "request_id": "model-000005-deadbeef",
        }
        self.failure = {
            "actor": "E", "request_id": "model-000005-deadbeef",
            "code": "actor_token_budget_exceeded", "kind": "budget_exhausted",
            "delivery": "delivered", "gateway_response": "received",
            "model_acceptance": "response_observed", "http_status": 200,
            "finish_reason": "tool_calls", "automatic_retry_allowed": False,
        }

    def test_unique_matched_failure_proves_model_consumption(self):
        receipts, gaps = actual_receipts({
            "deliveries": [self.delivery], "failures": [self.failure],
            "native_calls": [],
        })
        self.assertEqual(gaps, [])
        self.assertEqual(receipts, [{
            "recipient": "role:E", "payload": self.payload,
            "event_id": "episode:7",
            "kind": "model_consumption_via_failure_ledger",
        }])

    def test_unmatched_or_unknown_failure_stays_a_gap(self):
        for field, value in (
                ("request_id", "other-request"),
                ("delivery", "delivery_unknown"),
                ("gateway_response", "not_observed"),
                ("model_acceptance", "unknown"),
                ("http_status", 500),
                ("automatic_retry_allowed", True)):
            with self.subTest(field=field):
                failure = copy.deepcopy(self.failure)
                failure[field] = value
                receipts, gaps = actual_receipts({
                    "deliveries": [self.delivery], "failures": [failure],
                    "native_calls": [],
                })
                self.assertEqual(receipts, [])
                self.assertEqual(gaps, ["episode:7"])

    def test_duplicate_failure_identity_is_not_accepted(self):
        receipts, gaps = actual_receipts({
            "deliveries": [self.delivery],
            "failures": [self.failure, copy.deepcopy(self.failure)],
            "native_calls": [],
        })
        self.assertEqual(receipts, [])
        self.assertEqual(gaps, ["episode:7"])


if __name__ == "__main__":
    unittest.main()
