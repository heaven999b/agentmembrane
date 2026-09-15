"""Shared CLI Proxy route evidence using fake HTTP replies, never a socket."""
from __future__ import annotations

from email.message import Message
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.rq1_collab_v6.contract import PROTOCOL
from agentmembrane.host_v2.rq1_collab_v6.model_provider import V6ModelDriver
from agentmembrane.host_v2.rq1_collab_v6.provider_route import (
    BoundRouteTransport, SHARED_IDENTITY, SHARED_PROXY_CREDENTIAL_ENV_ENV,
    SHARED_PROXY_ENDPOINT_ENV, SHARED_PROXY_LABEL_ENV, credential_fingerprint,
)
from agentmembrane.host_v2.rq1_collab_v6.workflow import inspect_shared_proxy_route
from tests.rq1_collab_v1.test_provider_action_protocol import Collector


SYNTHETIC_SHARED_ENDPOINT = "http://127.0.0.1:19876/v1/chat/completions"
SYNTHETIC_SHARED_CREDENTIAL_ENV = "RQ1_SYNTHETIC_SHARED_PROXY_KEY"
SYNTHETIC_SHARED_LABEL = "synthetic_shared_pool"
SHARED_POLICY_ENV = {
    SHARED_PROXY_ENDPOINT_ENV: SYNTHETIC_SHARED_ENDPOINT,
    SHARED_PROXY_CREDENTIAL_ENV_ENV: SYNTHETIC_SHARED_CREDENTIAL_ENV,
    SHARED_PROXY_LABEL_ENV: SYNTHETIC_SHARED_LABEL,
}
ROUTE = {"schema_version": "rq1-provider-route/2", "routing_mode": "shared_pool_unattributed",
         "endpoint": SYNTHETIC_SHARED_ENDPOINT,
         "credential_env": SYNTHETIC_SHARED_CREDENTIAL_ENV,
         "account_label": SYNTHETIC_SHARED_LABEL}
BODY = json.dumps({"model": "unit-model", "choices": [{"index": 0, "finish_reason": "tool_calls",
    "message": {"role": "assistant", "content": None, "tool_calls": [{"id": "call-fake",
        "type": "function", "function": {"name": "submit_action",
        "arguments": '{"type":"final","content":"done"}'}}]}}],
    "usage": {"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10}}).encode()


class FakeHTTPResponse:
    def __init__(self, trace):
        self.headers = Message()
        self.headers["Content-Length"] = str(len(BODY))
        if trace is not None:
            self.headers["X-CPA-TRACE-ID"] = trace

    def read(self, _limit):
        return BODY


def bound_transport():
    salt = "11" * 32
    return BoundRouteTransport(ROUTE, {"credential_salt": salt,
        "credential_fingerprint": credential_fingerprint("unit-key", salt)},
        timeout_seconds=10)


class ProxyRouteDiagnosticTests(unittest.TestCase):
    def _run_replies(self, traces):
        with patch.dict(os.environ, {
            **SHARED_POLICY_ENV,
            SYNTHETIC_SHARED_CREDENTIAL_ENV: "unit-key",
        }):
            transport = bound_transport()
            replies = [transport._read_reply(FakeHTTPResponse(trace), 200) for trace in traces]
            collector = Collector()
            driver = V6ModelDriver({"model": "unit-model", "max_completion_tokens": 64},
                {"H": "Return a final action"}, collector, transport, request_limit=len(replies),
                action_protocol="single_tool_v1")
            with patch.object(transport, "request", side_effect=replies):
                for _ in replies:
                    self.assertEqual(json.loads(driver.next_action("H", {"protocol_version": PROTOCOL}))["type"], "final")
            responses = [event for event in collector.events if event["kind"] == "model_response"]
            with tempfile.TemporaryDirectory() as temp:
                path = Path(temp)
                (path / "events.jsonl").write_text("".join(json.dumps(row) + "\n" for row in responses))
                summary = inspect_shared_proxy_route(path)
        return transport, responses, summary

    def test_same_proxy_slot_is_only_an_anonymous_within_episode_consistency_signal(self):
        traces = ["20260914123456-slotAlpha-requestA", "20260914123457-slotAlpha-requestB"]
        transport, responses, summary = self._run_replies(traces)
        self.assertEqual(summary, {"status": "same_selected_slot_observed", "gateway_responses": 2,
            "fingerprinted_responses": 2, "missing_fingerprints": 0,
            "distinct_selected_slots": 1, "account_identity": SHARED_IDENTITY})
        values = [row["data"]["shared_proxy_last_selected_slot_fingerprint"] for row in responses]
        self.assertEqual(values[0], values[1])
        self.assertNotIn("slotAlpha", json.dumps(responses))
        self.assertNotIn("X-CPA-TRACE-ID", json.dumps(responses))
        self.assertNotIn(traces[0], json.dumps(responses))
        self.assertIsNotNone(transport._response_diagnostic_salt)
        self.assertNotIn(transport._response_diagnostic_salt.hex(), json.dumps(responses))
        with patch.dict(os.environ, SHARED_POLICY_ENV):
            another = bound_transport()
            other = another._read_reply(FakeHTTPResponse(traces[0]), 200)
        self.assertNotEqual(values[0], other.response_metadata["route_fingerprint"])

    def test_different_proxy_slots_are_visible_without_raw_identifiers(self):
        _, responses, summary = self._run_replies([
            "20260914123456-slotAlpha-requestA", "20260914123457-slotBeta-requestB"])
        self.assertEqual(summary["status"], "multiple_selected_slots_observed")
        self.assertEqual(summary["distinct_selected_slots"], 2)
        self.assertNotIn("slotBeta", json.dumps(responses))

    def test_missing_or_malformed_header_is_explicitly_incomplete(self):
        _, responses, summary = self._run_replies([
            "20260914123456-slotAlpha-requestA", None, "raw-secret-slot"])
        self.assertEqual(summary["status"], "incomplete_selected_slot_evidence")
        self.assertEqual(summary["missing_fingerprints"], 2)
        self.assertEqual(summary["fingerprinted_responses"], 1)
        for row in responses[1:]:
            self.assertNotIn("shared_proxy_last_selected_slot_fingerprint", row["data"])

    def test_no_response_does_not_claim_a_route(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            (path / "events.jsonl").write_bytes(b"")
            summary = inspect_shared_proxy_route(path)
        self.assertEqual(summary["status"], "no_gateway_response")
        self.assertEqual(summary["distinct_selected_slots"], 0)


if __name__ == "__main__":
    unittest.main()
