"""Model-visible formal H/E permissions must match the registered topology."""
from __future__ import annotations

import json
import re
import time
import unittest

from agentmembrane.host_v2.rq1_collab_v1.providers import HTTPReply
from agentmembrane.host_v2.rq1_collab_v6.contract import (
    DEFAULT_BUDGET,
    PHASE_SCHEDULE,
    make_config,
)
from agentmembrane.host_v2.rq1_three_tier_formal_v1.contract import (
    FORMAL_PROTOCOL,
    MODEL_PROFILES,
)
from agentmembrane.host_v2.rq1_three_tier_formal_v1.driver import (
    FormalRoleModelDriver,
    role_prompts,
)
from agentmembrane.host_v2.rq1_three_tier_formal_v1.wire import (
    _single_tool_action,
    build_action_payload,
)
from tests.rq1_collab_v1.test_provider_action_protocol import Collector


def config():
    return make_config(
        "a" * 64, "formal-wire", "H_E", "medium", "honest",
        mode="live_diagnostic", models=MODEL_PROFILES,
    )


def observation(actor="E", *, tools=None, finalization=False):
    tools = [] if tools is None else tools
    return {
        "protocol_version": FORMAL_PROTOCOL,
        "actor": actor,
        "available_tools": tools,
        "permissions": {
            "tools": sorted(t["name"] for t in tools),
            "can_delegate": False,
            "recipients": ["H"] if actor == "E" else [],
        },
        "history": [],
        "finalization_only": finalization,
    }


class FormalWireTests(unittest.TestCase):
    def test_E_no_business_tools_has_only_message_and_final(self):
        payload = build_action_payload(
            MODEL_PROFILES["E"], "formal E", observation("E"),
        )
        function = payload["tools"][0]["function"]
        props = function["parameters"]["properties"]
        self.assertEqual(props["type"]["enum"], ["send_message", "final"])
        self.assertEqual(props["recipient"]["enum"], ["H"])
        self.assertNotIn("tools", props)
        self.assertNotRegex(json.dumps(function, sort_keys=True),
                            r'(?<![A-Za-z0-9_])S(?![A-Za-z0-9_])|delegate')

    def test_business_tool_and_finalization_surfaces_are_phase_exact(self):
        tool = {"name": "list_files", "description": "List files", "parameters": {
            "type": "object", "properties": {}}}
        e = build_action_payload(
            MODEL_PROFILES["E"], "formal E", observation("E", tools=[tool]),
        )
        h = build_action_payload(
            MODEL_PROFILES["H"], "formal H", observation("H", tools=[tool]),
        )
        final = build_action_payload(
            MODEL_PROFILES["H"], "formal H", observation("H", finalization=True),
        )
        enum = lambda p: p["tools"][0]["function"]["parameters"]["properties"]["type"]["enum"]
        self.assertEqual(enum(e), ["tool_action", "send_message", "final"])
        self.assertEqual(enum(h), ["tool_action", "final"])
        self.assertEqual(enum(final), ["final"])

    def test_formal_parser_rejects_legacy_S_and_delegation(self):
        def message(action):
            return {"tool_calls": [{"id": "call-1", "type": "function",
                "function": {"name": "submit_action",
                             "arguments": json.dumps(action)}}]}
        for action in (
            {"type": "send_message", "recipient": "S", "content": "x"},
            {"type": "delegate", "recipient": "E", "content": "x", "tools": []},
        ):
            with self.assertRaisesRegex(ValueError, "formal_action"):
                _single_tool_action(
                    message(action), "tool_calls", protocol_version=FORMAL_PROTOCOL,
                )

    def test_prompts_are_exact_H_E_and_H_is_condition_invariant(self):
        h_prompts = []
        for level in ("low", "medium", "high"):
            for regime in ("honest", "malicious"):
                cfg = make_config(
                    "a" * 64, "formal-wire", "H_E", level, regime,
                    mode="live_diagnostic", models=MODEL_PROFILES,
                )
                prompts = role_prompts(cfg, "task", "fixture goal")
                self.assertEqual(set(prompts), {"H", "E"})
                self.assertFalse(any(re.search(
                    r"(?<![A-Za-z0-9_])S(?![A-Za-z0-9_])|role:S|S's", text,
                ) for text in prompts.values()))
                h_prompts.append(prompts["H"])
        self.assertEqual(len(set(h_prompts)), 1)

    def test_role_driver_sends_exact_formal_wire(self):
        cfg = config()
        prompts = role_prompts(cfg, "task", "fixture goal")
        sent = []

        def transport(body):
            payload = json.loads(body)
            sent.append(payload)
            action = {"type": "send_message", "recipient": "H", "content": "done"}
            reply = {"model": payload["model"], "choices": [{"index": 0,
                "finish_reason": "tool_calls", "message": {"role": "assistant",
                    "content": None, "tool_calls": [{"id": "call-formal",
                        "type": "function", "function": {"name": "submit_action",
                        "arguments": json.dumps(action)}}]}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 8,
                          "total_tokens": 18}}
            return HTTPReply(200, json.dumps(reply).encode())

        driver = FormalRoleModelDriver(cfg, prompts, Collector(), transport)
        now = time.monotonic()
        driver.begin_episode(
            deadline_monotonic=now + DEFAULT_BUDGET["wall_seconds"],
            external_deadline_monotonic=now + PHASE_SCHEDULE["external_phase_seconds"],
            internal_deadline_monotonic=now + DEFAULT_BUDGET["wall_seconds"]
                - PHASE_SCHEDULE["closure_reserve_seconds"],
        )
        obs = observation("E")
        self.assertEqual(json.loads(driver.next_action("E", obs))["recipient"], "H")
        encoded = json.dumps(sent[0]["tools"][0]["function"], sort_keys=True)
        self.assertNotIn("delegate", encoded)
        self.assertNotRegex(encoded, r'(?<![A-Za-z0-9_])S(?![A-Za-z0-9_])')


if __name__ == "__main__":
    unittest.main()
