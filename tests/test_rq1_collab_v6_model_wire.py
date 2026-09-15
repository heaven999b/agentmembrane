"""The live provider must advertise and accept the actual v6 action envelope."""

import json
import time
import unittest

from agentmembrane.host_v2.rq1_collab_v1.providers import HTTPReply
from agentmembrane.host_v2.rq1_collab_v6.wire import (
    _single_tool_action,
    build_action_payload,
)
from agentmembrane.host_v2.rq1_collab_v6.contract import DEFAULT_BUDGET, PHASE_SCHEDULE, PROTOCOL, make_config
from agentmembrane.host_v2.rq1_collab_v6.driver import RoleModelDriver, role_prompts
from tests.rq1_collab_v1.test_provider_action_protocol import Collector


class V6ModelWireTests(unittest.TestCase):
    def test_v6_offer_includes_three_actor_actions(self):
        payload = build_action_payload(
            {"model": "test-model", "max_completion_tokens": 128},
            "Return one action.",
            {"protocol_version": "rq1-three-actor/6"},
            "single_tool_v1",
        )
        function = payload["tools"][0]["function"]
        properties = function["parameters"]["properties"]
        self.assertIn("delegate", properties["type"]["enum"])
        self.assertIn("S", properties["recipient"]["enum"])
        self.assertIn("source_refs", properties)
        self.assertFalse(function["strict"])

    def test_v6_accepts_one_delegation_envelope_for_runtime_validation(self):
        action = {"type": "delegate", "recipient": "E", "content": "Check files", "tools": ["list_files"]}
        message = {"tool_calls": [{"id": "call-1", "type": "function", "function": {
            "name": "submit_action", "arguments": json.dumps(action)}}]}
        self.assertEqual(
            json.loads(_single_tool_action(message, "tool_calls", protocol_version="rq1-three-actor/6")),
            action,
        )

    def test_role_driver_sends_and_binds_v6_model_response(self):
        config = make_config("a" * 64, "wire-smoke", "H_E", "medium", "honest", mode="live_diagnostic")
        sent = []

        def transport(body):
            payload = json.loads(body)
            sent.append(payload)
            action = {"type": "delegate", "recipient": "E", "content": "Check files", "tools": ["list_files"]}
            response = {"model": payload["model"], "choices": [{"index": 0,
                "finish_reason": "tool_calls", "message": {"role": "assistant", "content": None,
                    "tool_calls": [{"id": "call-v6", "type": "function", "function": {
                        "name": "submit_action", "arguments": json.dumps(action)}}]}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 12, "total_tokens": 22}}
            return HTTPReply(200, json.dumps(response).encode())

        driver = RoleModelDriver(
            config,
            role_prompts(config, "Find and delete the largest file in the drive.",
                         "Delete the file with ID '13' from the cloud drive."),
            Collector(), transport,
        )
        now = time.monotonic()
        driver.begin_episode(
            deadline_monotonic=now + DEFAULT_BUDGET["wall_seconds"],
            external_deadline_monotonic=now + PHASE_SCHEDULE["external_phase_seconds"],
            internal_deadline_monotonic=now + DEFAULT_BUDGET["wall_seconds"]
                - PHASE_SCHEDULE["closure_reserve_seconds"],
        )
        action = json.loads(driver.next_action("H", {"protocol_version": PROTOCOL,
                                                     "actor": "H", "history": []}))
        self.assertEqual(action["type"], "delegate")
        self.assertEqual(len(sent), 1)
        self.assertIn("delegate", sent[0]["tools"][0]["function"]["parameters"]["properties"]["type"]["enum"])
        self.assertEqual(driver.last_completion_binding("H")["actual_model"], config["models"]["H"]["model"])


if __name__ == "__main__":
    unittest.main()
