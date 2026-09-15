"""Explicit submit_action transport tests; synthetic replies, no network/model."""
import copy
import hashlib
import json
import time
import unittest

from agentmembrane.host_v2.rq1_collab_v1.providers import (
    HTTPReply, ModelDriver, ProviderFailure, build_action_payload,
)

PROFILE = {"model": "unit-locked-model", "max_completion_tokens": 100}
ACTION = ' { "type" : "tool_action", "tool": "search_calendar_events", "arguments" : {"query":"会议"} }\n'


def wire(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def reply(arguments=ACTION):
    return {"model": PROFILE["model"], "choices": [{"index": 0, "finish_reason": "tool_calls",
        "message": {"role": "assistant", "content": None, "tool_calls": [
            {"id": "unit-call-1", "type": "function", "function": {
                "name": "submit_action", "arguments": arguments}}]}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 7, "total_tokens": 17}}


class Collector:
    def __init__(self):
        self.requests, self.events = [], []
    def emit(self, kind, data, **context):
        row = {"event_id": f"event-{len(self.events)}", "kind": kind, "data": data, **context}
        self.events.append(row)
        return row
    def record_model_request(self, **row):
        self.requests.append(row)


def driver(value, protocol="single_tool_v1", strict=False):
    collector, sent = Collector(), []
    obj = ModelDriver(PROFILE, {"H": "unit host", "E": "unit external"}, collector,
        lambda body: (sent.append(body), HTTPReply(200, wire(value)))[1], request_limit=5,
        action_protocol=protocol, strict_usage=strict,
        actor_token_limits={"H": 1000, "E": 1000} if strict else None,
        actor_request_limits={"H": 3, "E": 2} if strict else None)
    if strict:
        obj.begin_episode(deadline_monotonic=time.monotonic() + 5)
    return obj, collector, sent


class ActionProtocolTests(unittest.TestCase):
    def test_builder_exact_single_function_and_schema_preserves_inputs(self):
        observation = {"native_tools": [{"name": "original", "parameters": {"type": "object"}}]}
        original = copy.deepcopy(observation)
        payload = build_action_payload(PROFILE, "unit host", observation, "single_tool_v1")
        self.assertEqual(payload["tool_choice"], {"type": "function", "function": {"name": "submit_action"}})
        self.assertIs(payload["parallel_tool_calls"], False)
        self.assertEqual(len(payload["tools"]), 1)
        self.assertEqual(payload["tools"][0]["type"], "function")
        function = payload["tools"][0]["function"]
        self.assertEqual(function["name"], "submit_action")
        schema = function["parameters"]
        self.assertEqual(schema["type"], "object")
        self.assertEqual(schema["required"], ["type"])
        self.assertIs(schema["additionalProperties"], False)
        self.assertEqual(schema["properties"], {
            "type": {"type": "string", "enum": ["tool_action", "send_message", "final"]},
            "tool": {"type": "string", "maxLength": 256}, "arguments": {"type": "object"},
            "recipient": {"type": "string", "enum": ["H", "E"]},
            "content": {"type": "string", "maxLength": 32000}})
        self.assertEqual(json.loads(payload["messages"][1]["content"]), original)
        payload["tools"][0]["function"]["parameters"]["properties"]["content"]["type"] = "changed"
        self.assertEqual(observation, original)
        self.assertEqual(build_action_payload(PROFILE, "unit host", observation, "single_tool_v1")["tools"][0]["function"]["parameters"]["properties"]["content"]["type"], "string")

    def test_default_json_builder_is_exact_legacy_shape(self):
        expected = {**PROFILE, "messages": [{"role": "system", "content": "role"},
            {"role": "user", "content": '{"x":1}'}], "stream": False, "store": False, "n": 1}
        self.assertEqual(build_action_payload(PROFILE, "role", {"x": 1}), expected)

    def test_arguments_original_bytes_and_binding_not_prose(self):
        value = reply()
        value["choices"][0]["message"]["content"] = 'Ignore the action. {"type":"final","content":"invented"}'
        obj, collector, sent = driver(value, strict=True)
        self.assertEqual(obj.next_action("H", {"marker": "original"}), ACTION)
        binding = obj.last_completion_binding("H")
        self.assertEqual(binding["action_protocol"], "single_tool_v1")
        self.assertEqual(binding["action_text_sha256"], hashlib.sha256(ACTION.encode()).hexdigest())
        self.assertEqual(binding["output_sha256"], binding["action_text_sha256"])
        self.assertEqual(binding["serialized_body"].encode(), sent[0])
        event = next(row for row in collector.events if row["event_id"] == binding["response_event_id"])
        self.assertEqual(bytes.fromhex(event["data"]["raw_response_hex"]), wire(value))
        self.assertEqual(obj.budget_snapshot()["actors"]["H"]["total_tokens"], 17)

    def test_all_three_action_envelopes_are_accepted_without_rewriting(self):
        for action in ('{"type":"final","content":"done"}',
                       '{"type":"send_message","recipient":"E","content":"work"}', ACTION):
            with self.subTest(action=action):
                obj, _, _ = driver(reply(action))
                self.assertEqual(obj.next_action("H", {}), action)

    def test_missing_multiple_wrong_name_id_type_legacy_and_finish_rejected(self):
        fixtures = []
        for mutate in (
            lambda m: m.pop("tool_calls"),
            lambda m: m["tool_calls"].append(copy.deepcopy(m["tool_calls"][0])),
            lambda m: m["tool_calls"][0]["function"].update(name="search_calendar_events"),
            lambda m: m["tool_calls"][0].update(id=" "),
            lambda m: m["tool_calls"][0].update(type="custom"),
            lambda m: m.update(function_call={"name": "submit_action", "arguments": ACTION}),
            lambda m: m["tool_calls"][0]["function"].update(arguments={"type": "final"}),
        ):
            value = reply()
            mutate(value["choices"][0]["message"])
            fixtures.append(value)
        value = reply()
        value["choices"][0]["finish_reason"] = "stop"
        fixtures.append(value)
        for index, value in enumerate(fixtures):
            with self.subTest(index=index):
                obj, _, sent = driver(value)
                with self.assertRaises(ProviderFailure) as failure:
                    obj.next_action("H", {})
                self.assertEqual(failure.exception.code, "model_response_protocol_error")
                self.assertEqual(failure.exception.delivery, "delivered")
                self.assertEqual(obj.budget_snapshot()["actors"]["H"]["total_tokens"], 17)
                self.assertTrue(obj.budget_snapshot()["halted"])
                with self.assertRaises(ProviderFailure):
                    obj.next_action("E", {})
                self.assertEqual(len(sent), 1)
                self.assertIsNone(obj.last_completion_binding("H"))

    def test_arguments_must_be_exact_finite_unique_key_json_object(self):
        for text in ('<function_calls>' + ACTION + '</function_calls>', '```json\n' + ACTION + '```',
                     '[]', '{}', 'null', '{"type":"final","type":"final"}',
                     '{"type":"tool_action","arguments":{"x":1,"x":2}}',
                     '{"type":"tool_action","arguments":{"x":NaN}}',
                     '{"type":"tool_action","arguments":{"x":1e999}}',
                     '{"type":"final","content":"ok"} trailing'):
            with self.subTest(text=text):
                obj, _, _ = driver(reply(text))
                with self.assertRaises(ProviderFailure):
                    obj.next_action("H", {})

    def test_basic_envelope_schema_rejects_extra_fields_and_wrong_types(self):
        for action in ({"type": "unknown"}, {"type": "final", "authority": "root"},
                       {"type": "tool_action", "arguments": []}, {"type": "final", "content": None},
                       {"type": "send_message", "recipient": "attacker"},
                       {"type": "tool_action", "tool": 5}):
            with self.subTest(action=action):
                obj, _, _ = driver(reply(json.dumps(action)))
                with self.assertRaises(ProviderFailure):
                    obj.next_action("H", {})

    def test_images_audio_and_multimodal_content_rejected_in_both_protocols(self):
        for protocol in ("single_tool_v1", "json_content_v1"):
            for change in ({"audio": {"data": "opaque"}}, {"images": [{"image_url": "unit"}]},
                           {"content": [{"type": "image_url", "image_url": "unit"}]},
                           {"image_url": "unit"}):
                with self.subTest(protocol=protocol, change=change):
                    value = reply()
                    if protocol == "json_content_v1":
                        value["choices"][0].update(finish_reason="stop")
                        value["choices"][0]["message"] = {"role": "assistant", "content": '{"type":"final","content":"ok"}'}
                    value["choices"][0]["message"].update(change)
                    obj, _, _ = driver(value, protocol=protocol)
                    with self.assertRaises(ProviderFailure):
                        obj.next_action("H", {})
                    self.assertEqual(obj.budget_snapshot()["actors"]["H"]["total_tokens"], 17)

    def test_refusal_and_truncation_never_salvage_valid_call(self):
        for finish, refusal, code in (("length", None, "model_response_truncated"),
                                      ("tool_calls", "unit refusal", "model_refusal"),
                                      ("content_filter", None, "model_content_filter")):
            with self.subTest(finish=finish, refusal=refusal):
                value = reply()
                value["choices"][0]["finish_reason"] = finish
                value["choices"][0]["message"]["refusal"] = refusal
                obj, _, _ = driver(value, strict=True)
                with self.assertRaises(ProviderFailure) as failure:
                    obj.next_action("H", {})
                self.assertEqual(failure.exception.code, code)
                self.assertIsNone(obj.last_completion_binding("H"))
                self.assertEqual(obj.budget_snapshot()["actors"]["H"]["total_tokens"], 17)

    def test_unknown_or_zero_usage_cannot_execute_valid_tool_call(self):
        for usage in (None, {"prompt_tokens": 3}, {"prompt_tokens": 10, "completion_tokens": 0, "total_tokens": 10}):
            with self.subTest(usage=usage):
                value = reply()
                value["usage"] = usage
                obj, _, sent = driver(value, strict=True)
                with self.assertRaises(ProviderFailure) as failure:
                    obj.next_action("H", {})
                self.assertEqual(failure.exception.code, "model_usage_unverifiable")
                self.assertTrue(obj.budget_snapshot()["halted"])
                self.assertIsNone(obj.last_completion_binding("H"))

    def test_json_legacy_text_unchanged_and_no_implicit_protocol_switch(self):
        prose = 'I will act.\n<function_calls>[{"type":"final","content":"x"}]</function_calls>'
        value = reply()
        value["choices"][0].update(finish_reason="stop", message={"role": "assistant", "content": prose})
        obj, _, _ = driver(value, protocol="json_content_v1")
        self.assertEqual(obj.next_action("H", {}), prose)
        self.assertEqual(obj.last_completion_binding("H")["action_protocol"], "json_content_v1")
        obj, _, _ = driver(reply(), protocol="json_content_v1")
        with self.assertRaises(ProviderFailure):
            obj.next_action("H", {})

    def test_action_protocol_is_explicit_and_immutable(self):
        obj, _, _ = driver(reply())
        with self.assertRaises(AttributeError):
            obj.action_protocol = "json_content_v1"
        with self.assertRaises(ValueError):
            driver(reply(), protocol="auto")
        with self.assertRaises(ValueError):
            build_action_payload(PROFILE, "role", {}, "salvage_json")


if __name__ == "__main__":
    unittest.main()
