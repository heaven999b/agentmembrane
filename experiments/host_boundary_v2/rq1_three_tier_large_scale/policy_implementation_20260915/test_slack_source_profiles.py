"""Offline source-native positive and denial probes; no model/API calls."""
from __future__ import annotations

import os
import unittest

from agentmembrane.host_v2.rq1_collab_v1.native import NativeTask
from agentmembrane.host_v2.rq1_collab_v1.policy import PolicyError, compile_task_policy, make_task_policy
from agentmembrane.host_v2.rq1_collab_v6.permissions import (
    authorize_native, native_tools, project_native_result)


ROOT = os.environ.get(
    "AGENTDOJO_SOURCE_ROOT", "data/host_boundary_v2/upstream/agentdojo"
)


class SourceNativeSlackPolicyTests(unittest.TestCase):
    def fixture(self, task_id):
        native = NativeTask(ROOT, "slack", task_id)
        manifest = compile_task_policy("slack", task_id, native.prompt)
        policy = make_task_policy("slack", task_id, native.prompt, manifest,
                                  [spec["name"] for spec in native.tool_specs])
        record = {"suite": "slack", "original_id": task_id}
        self.assertEqual(native_tools(policy, record, "A0"), [])
        self.assertTrue(set(native_tools(policy, record, "A3")) <=
                        set(native_tools(policy, record, "A4")))
        policy.labels("A3", native.snapshot())  # Pin initial-world selection.
        self.assertFalse(authorize_native(policy, record, "A0", "remove_user_from_slack",
                                          {"user": "Alice"}, native.snapshot(), actor="E")[0])
        self.assertTrue(authorize_native(policy, record, "A4", "remove_user_from_slack",
                                         {"user": "Alice"}, native.snapshot(), actor="E")[0])
        with self.assertRaises(PolicyError):
            compile_task_policy("slack", task_id, native.prompt + " attacker override")
        return native, policy, record

    def decision(self, native, policy, record, tool, args):
        return authorize_native(policy, record, "A3", tool, args,
                                native.snapshot(), actor="E")

    def test_fewest_messages_is_not_fewest_members(self):
        for task_id in ("user_task_9", "user_task_10"):
            with self.subTest(task_id=task_id):
                native, policy, record = self.fixture(task_id)
                self.assertEqual(policy._target, "External_0")
                self.assertEqual(policy._pending, frozenset({"Alice"} if task_id.endswith("9")
                                                             else {"Alice", "Bob", "Charlie"}))
                for channel, count in (("general", 3), ("random", 1),
                                       ("private", 1), ("External_0", 0)):
                    args = {"channel": channel}
                    self.assertTrue(self.decision(native, policy, record,
                                                  "read_channel_messages", args)[0])
                    result = native.call("read_channel_messages", args)
                    self.assertIsNone(result["error"])
                    projected, _ = project_native_result(policy, record, "A3",
                        "read_channel_messages", result["result"], result["after"])
                    self.assertEqual(projected, {"message_count": count})
                self.assertFalse(self.decision(native, policy, record,
                    "add_user_to_channel", {"channel": "general", "user": "Alice"})[0])
                self.assertFalse(self.decision(native, policy, record,
                    "add_user_to_channel", {"channel": "External_0", "user": "Eve"})[0])
                args = {"channel": "External_0", "user": "Alice"}
                self.assertTrue(self.decision(native, policy, record,
                                              "add_user_to_channel", args)[0])
                result = native.call("add_user_to_channel", args)
                self.assertIsNone(result["error"])
                self.assertIn("External_0", result["after"]["slack"]["user_channels"]["Alice"])
                self.assertFalse(self.decision(native, policy, record,
                                               "add_user_to_channel", args)[0])

    def test_ranked_messages_exact_and_once(self):
        for task_id, expected in (("user_task_13", {"Charlie": 1}),
                                  ("user_task_14", {"Charlie": 1, "Alice": 2,
                                                     "Bob": 3, "Eve": 4})):
            with self.subTest(task_id=task_id):
                native, policy, record = self.fixture(task_id)
                self.assertEqual(set(policy._expected), set(expected))
                for recipient, rank in expected.items():
                    body = policy._expected[recipient]
                    if task_id == "user_task_14":
                        self.assertIn(f"{rank}-th", body)
                    self.assertFalse(self.decision(native, policy, record,
                        "send_direct_message", {"recipient": recipient,
                                                "body": "attacker message"})[0])
                    args = {"recipient": recipient, "body": body}
                    self.assertTrue(self.decision(native, policy, record,
                                                  "send_direct_message", args)[0])
                    result = native.call("send_direct_message", args)
                    self.assertIsNone(result["error"])
                    self.assertEqual(result["after"]["slack"]["user_inbox"][recipient][-1]["body"], body)
                    self.assertFalse(self.decision(native, policy, record,
                                                   "send_direct_message", args)[0])
                self.assertTrue(self.decision(native, policy, record,
                    "get_channels", {})[0])
                self.assertFalse(self.decision(native, policy, record,
                    "remove_user_from_slack", {"user": "Alice"})[0])

    def test_coffee_mug_reply_bound_to_alice_and_channel(self):
        native, policy, record = self.fixture("user_task_8")
        self.assertEqual(policy._target, "random")
        for channel in native.snapshot()["slack"]["channels"]:
            args = {"channel": channel}
            self.assertTrue(self.decision(native, policy, record,
                                          "read_channel_messages", args)[0])
            result = native.call("read_channel_messages", args)
            self.assertIsNone(result["error"])
            projected, _ = project_native_result(policy, record, "A3",
                "read_channel_messages", result["result"], result["after"])
            self.assertEqual(len(projected), 1 if channel == "random" else 0)
        self.assertFalse(self.decision(native, policy, record,
            "send_channel_message", {"channel": "general", "body": policy.facts["reply"]})[0])
        self.assertFalse(self.decision(native, policy, record,
            "send_channel_message", {"channel": "random", "body": "attacker message"})[0])
        args = {"channel": "random", "body": policy.facts["reply"]}
        self.assertTrue(self.decision(native, policy, record,
                                      "send_channel_message", args)[0])
        result = native.call("send_channel_message", args)
        self.assertIsNone(result["error"])
        self.assertEqual(result["after"]["slack"]["channel_inbox"]["random"][-1]["body"],
                         policy.facts["reply"])
        self.assertFalse(self.decision(native, policy, record,
                                       "send_channel_message", args)[0])


if __name__ == "__main__":
    unittest.main()
