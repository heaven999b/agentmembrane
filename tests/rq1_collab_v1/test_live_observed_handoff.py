"""Regression controls for the actual 2026-09-08 A0 final/recipient failure.

These are apparatus tests, not generated research tasks or attack samples.
"""
import json
import unittest

from agentmembrane.host_v2.rq1_collab_v1.authority import PROTOCOL_V2
from agentmembrane.host_v2.rq1_collab_v1.providers import ProviderFailure
from agentmembrane.host_v2.rq1_collab_v1.runtime import ActionError, parse_action
from tests.rq1_collab_v1.test_provider_action_protocol import driver, reply
from tests.rq1_collab_v1.test_runtime import Scripted, final, tool
from tests.rq1_collab_v1 import test_v2_runtime as v2_fixtures


class ObservedProviderBoundaryTests(unittest.TestCase):
    def test_redundant_final_recipient_is_exact_delivered_but_not_executable(self):
        raw = ' {"type":"final","content":"handoff","recipient":"H"} '
        obj, collector, sent = driver(reply(raw), strict=True)
        observation = {"actor": "E", "protocol_version": PROTOCOL_V2}
        self.assertEqual(obj.next_action("E", observation), raw)
        self.assertFalse(obj.budget_snapshot()["halted"])
        self.assertEqual(obj.budget_snapshot()["actors"]["E"]["total_tokens"], 17)
        self.assertEqual(obj.last_completion_binding("E")["serialized_body"].encode(), sent[0])
        with self.assertRaisesRegex(ActionError, "unsupported_or_extra_action_fields"):
            parse_action(raw, protocol_version=PROTOCOL_V2)

    def test_claimed_authority_extra_field_still_cannot_pass_runtime(self):
        raw = json.dumps({"type": "tool_action", "tool": "delete_file",
                          "arguments": {"file_id": "13"}, "authority": "root"})
        obj, _, _ = driver(reply(raw), strict=True)
        self.assertEqual(obj.next_action("E", {"protocol_version": PROTOCOL_V2}), raw)
        with self.assertRaises(ActionError):
            parse_action(raw, protocol_version=PROTOCOL_V2)

    def test_ambiguous_wire_and_code_execution_still_halt_without_action(self):
        for raw in ('{"type":"code_execution","code":"x","language":"python"}',
                    '{"type":"final","type":"final","content":"x"}',
                    '{"type":"tool_action","arguments":{"x":1e999}}',
                    '[]', '{"type":"unknown"}'):
            with self.subTest(raw=raw):
                obj, _, _ = driver(reply(raw), strict=True)
                with self.assertRaises(ProviderFailure):
                    obj.next_action("E", {"protocol_version": PROTOCOL_V2})
                self.assertTrue(obj.budget_snapshot()["halted"])
                self.assertIsNone(obj.last_completion_binding("E"))


class ObservedRuntimeBoundaryTests(unittest.TestCase):
    def test_invalid_handoff_has_no_dispatch_and_corrected_handoff_reaches_host(self):
        bad = {"type": "final", "content": "handoff", "recipient": "H"}
        scripted = Scripted([tool("get_current_day"), final()], [bad, final()])
        helper = v2_fixtures.V2RuntimeTests()
        result, native = helper.run_fixture(scripted)
        self.assertEqual(result["termination"], "host_final")
        self.assertEqual(len(scripted.observations["E"]), 2)
        self.assertTrue(any(h.get("content", {}).get("status") == "format_error"
                            for h in scripted.observations["E"][1]["history"]
                            if isinstance(h.get("content"), dict)))
        self.assertEqual([c["actor"] for c in result["native_calls"]], ["H"])
        self.assertEqual(len(native.calls), 1)
        self.assertEqual(result["driver_failures"], [])


if __name__ == "__main__":
    unittest.main()
