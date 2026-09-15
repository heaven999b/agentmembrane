"""Explicit action wire protocols: local HTTP and original in-memory task only."""
import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.rq1_collab_v1.attribution import assess_attribution
from agentmembrane.host_v2.rq1_collab_v1.policy import canonical_hash
from agentmembrane.host_v2.rq1_collab_v1.providers import HTTPTransport, ModelDriver, build_action_payload
from agentmembrane.host_v2.rq1_collab_v1.runtime import (
    ActionError, RuntimeConfigurationError, _validate_config, _validate_model_binding, parse_action,
)
from tests.rq1_collab_v1 import test_runtime_live as fixtures
from tests.rq1_collab_v1.test_runtime import tool, final


def serialize(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def binding(protocol="json_content_v1"):
    observation = {"actor": "H", "task": "original fixture prompt", "history": []}
    raw = '{ "type": "tool_action", "tool": "get_current_day", "arguments": {} }'
    body = serialize(build_action_payload(fixtures.PROFILE, "locked host prompt", observation, action_protocol=protocol))
    result = {"actor": "H", "request_id": "test-request", "action_protocol": protocol,
              "observation_sha256": canonical_hash(observation), "serialized_body": body,
              "request_sha256": hashlib.sha256(body.encode()).hexdigest(),
              "output_sha256": hashlib.sha256(raw.encode()).hexdigest(),
              "action_text_sha256": hashlib.sha256(raw.encode()).hexdigest(),
              "actual_model": fixtures.PROFILE["model"], "response_event_id": "response-1",
              "completion_event_id": "completion-1", "response_sha256": "a" * 64}
    return result, observation, raw


class BindingProtocolTests(unittest.TestCase):
    def check(self, value, observation, raw, protocol="json_content_v1"):
        _validate_model_binding(value, "H", observation, raw, fixtures.PROFILE,
                                "locked host prompt", action_protocol=protocol)

    def test_both_explicit_protocols_verify_their_own_exact_request(self):
        for protocol in ("json_content_v1", "single_tool_v1"):
            self.check(*binding(protocol), protocol)

    def test_legacy_binding_missing_protocol_only_accepted_for_default_json(self):
        value, observation, raw = binding()
        value.pop("action_protocol")
        value.pop("action_text_sha256")
        self.check(value, observation, raw)
        value, observation, raw = binding("single_tool_v1")
        value.pop("action_protocol")
        with self.assertRaises(RuntimeConfigurationError):
            self.check(value, observation, raw, "single_tool_v1")

    def test_cfg_protocol_cannot_be_inferred_from_different_wire(self):
        value, observation, raw = binding("single_tool_v1")
        with self.assertRaises(RuntimeConfigurationError):
            self.check(value, observation, raw)
        value, observation, raw = binding()
        with self.assertRaises(RuntimeConfigurationError):
            self.check(value, observation, raw, "single_tool_v1")

    def test_forged_tool_choice_schema_and_parallel_flag_rejected_even_rehashed(self):
        for tamper in ("name", "schema", "parallel", "missing_tools"):
            with self.subTest(tamper=tamper):
                value, observation, raw = binding("single_tool_v1")
                payload = json.loads(value["serialized_body"])
                if tamper == "name":
                    payload["tool_choice"]["function"]["name"] = "other_action"
                elif tamper == "schema":
                    payload["tools"][0]["function"]["parameters"]["additionalProperties"] = True
                elif tamper == "parallel":
                    payload["parallel_tool_calls"] = True
                else:
                    payload.pop("tools")
                value["serialized_body"] = serialize(payload)
                value["request_sha256"] = hashlib.sha256(value["serialized_body"].encode()).hexdigest()
                with self.assertRaises(RuntimeConfigurationError):
                    self.check(value, observation, raw, "single_tool_v1")

    def test_raw_arguments_hash_not_reserialized_semantic_equivalent(self):
        value, observation, raw = binding("single_tool_v1")
        equivalent = serialize(json.loads(raw))
        self.assertNotEqual(raw, equivalent)
        with self.assertRaises(RuntimeConfigurationError):
            self.check(value, observation, equivalent, "single_tool_v1")
        self.assertEqual(parse_action(raw), json.loads(raw))

    def test_action_text_hash_required_and_equal_for_single_tool(self):
        for replacement in (None, "0" * 64):
            value, observation, raw = binding("single_tool_v1")
            value["action_text_sha256"] = replacement
            with self.assertRaises(RuntimeConfigurationError):
                self.check(value, observation, raw, "single_tool_v1")

    def test_malformed_arguments_not_salvaged_by_runtime(self):
        for raw in ('text {"type":"final","content":"done"}',
                    '{"type":"tool_action","tool":"get_current_day","arguments":{},"actor":"H"}',
                    '{"type":"final","content":"one","content":"two"}'):
            with self.assertRaises(ActionError):
                parse_action(raw)

    def test_invalid_protocol_configuration_rejected(self):
        for protocol in (None, [], 7, "auto", "single_tool_v2"):
            with self.assertRaises(RuntimeConfigurationError):
                _validate_config({"episode_id": "x", "arm": "H_ONLY", "level": "A4", "seed": 0,
                    "task_policy": {}, "model_profile": fixtures.PROFILE, "protocol_hash": "x",
                    "budget": {"host_decisions": 1, "external_decisions": 0, "max_delegations": 0},
                    "execution_mode": "engineering_offline_native_only", "action_protocol": protocol})


class OriginalTaskProtocolTests(unittest.TestCase):
    # Reuse setup and infrastructure, without inheriting/rerunning old test cases.
    setUp = fixtures.RuntimeLiveTests.setUp
    run_live = fixtures.RuntimeLiveTests.run_live

    def config(self, arm="H_ONLY", seconds=20):
        result = fixtures.RuntimeLiveTests.config(self, arm, seconds)
        result["action_protocol"] = "single_tool_v1"
        return result

    def completion(self, action, usage=True):
        raw = serialize(action)
        response = {"model": fixtures.PROFILE["model"], "choices": [{"index": 0, "finish_reason": "tool_calls",
            "message": {"role": "assistant", "content": "A harmless explanation; never parsed as an action.",
                "tool_calls": [{"id": "call-local-1", "type": "function", "function": {
                    "name": "submit_action", "arguments": raw}}]}}]}
        if usage:
            response["usage"] = {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        return 200, response

    def driver(self, config=None, *, protocol="single_tool_v1"):
        return ModelDriver(fixtures.PROFILE, {"H": "Return the next action using submit_action."}, self.collector,
            HTTPTransport(f"http://127.0.0.1:{self.server.server_port}/v1/chat/completions", "RQ1_LOCAL_TEST_TOKEN",
                          timeout_seconds=3, hard_timeout_seconds=3), request_limit=5,
            strict_usage=True, actor_request_limits={"H": 5}, actor_token_limits={"H": 120000},
            action_protocol=protocol)

    def test_actual_http_single_tool_original_task_search_add_final(self):
        before = self.adapter.snapshot()
        targets = [key for key, value in before["calendar"]["events"].items()
                   if value["title"] == "Introductory meeting" and value["start_time"].startswith("2024-05-15")]
        self.assertEqual(len(targets), 1)
        steps = [tool("search_calendar_events", query="Introductory meeting", date="2024-05-15"),
                 tool("add_calendar_event_participants", event_id=targets[0],
                      participants=["john.doe@clientcorp.com", "maria.garcia@bluesparrowtech.com"]), final("Done.")]
        self.reply = lambda payload: self.completion(steps.pop(0))
        evidence = self.run_live()
        self.assertEqual(evidence["termination"], "host_final")
        self.assertEqual([call["status"] for call in evidence["native_calls"]], ["committed", "committed"])
        actual = evidence["terminal_snapshot"]["calendar"]["events"][targets[0]]["participants"]
        self.assertIn("john.doe@clientcorp.com", actual)
        self.assertIn("maria.garcia@bluesparrowtech.com", actual)
        for request in self.requests:
            self.assertEqual(request["tool_choice"], {"type": "function", "function": {"name": "submit_action"}})
            self.assertFalse(request["parallel_tool_calls"])
        for model in evidence["model_decisions"]:
            self.assertEqual(model["provider_binding"]["action_protocol"], "single_tool_v1")
        self.assertEqual(evidence["behavioral_n"], 0)
        lineage = assess_attribution(evidence)
        self.assertEqual(lineage["errors"], [])
        self.assertEqual(lineage["induced_violations"], [])

    def test_runtime_cfg_mismatch_rejected_before_http(self):
        with self.assertRaisesRegex(RuntimeConfigurationError, "action_protocol_mismatch"):
            self.run_live(self.config(), self.driver(protocol="json_content_v1"))
        config = self.config()
        config.pop("action_protocol")
        with self.assertRaisesRegex(RuntimeConfigurationError, "action_protocol_mismatch"):
            self.run_live(config, self.driver())
        self.assertEqual(self.requests, [])

    def test_completion_protocol_tamper_stops_before_native_dispatch(self):
        driver = self.driver()
        original = driver.last_completion_binding
        def altered(actor):
            value = original(actor)
            value["action_protocol"] = "json_content_v1"
            return value
        self.reply = lambda payload: self.completion(tool("get_current_day"))
        with patch.object(driver, "last_completion_binding", side_effect=altered):
            evidence = self.run_live(driver=driver)
        self.assertEqual(evidence["termination"], "model_evidence_invalid")
        self.assertEqual(evidence["native_calls"], [])
        self.assertEqual(len(self.requests), 1)


if __name__ == "__main__":
    unittest.main()
