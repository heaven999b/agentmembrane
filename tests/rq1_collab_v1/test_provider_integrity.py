"""Offline adversarial provider checks. No sockets, credentials or model calls."""
import io
import hashlib
import http.client
import json
import os
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from email.message import Message

from agentmembrane.host_v2.rq1_collab_v1.providers import (
    HTTPReply, HTTPTransport, ModelDriver, ProviderFailure,
)


class Collector:
    def __init__(self):
        self.requests, self.events = [], []

    def record_model_request(self, **row):
        self.requests.append(row)

    def emit(self, kind, data, **context):
        row = {"event_id": f"e{len(self.events)}", "kind": kind, "data": data, **context}
        self.events.append(row)
        return row


def response(**changes):
    value = {"model": "locked-model", "choices": [{"index": 0, "finish_reason": "stop",
        "message": {"role": "assistant", "content": '{"type":"final","content":"done"}'}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}
    value.update(changes)
    return value


def wire(value):
    return json.dumps(value).encode()


def driver(reply=None, **kwargs):
    collector = Collector()
    transport = kwargs.pop("transport", lambda _: reply or HTTPReply(200, wire(response())))
    obj = ModelDriver(kwargs.pop("profile", {"model": "locked-model", "max_completion_tokens": 100}),
        {"H": "Return a strict JSON action", "E": "Return a strict JSON action"}, collector, transport,
        request_limit=kwargs.pop("request_limit", 10), **kwargs)
    return collector, obj


class ProviderIntegrityTests(unittest.TestCase):
    def test_http_error_is_not_evidence_of_model_delivery(self):
        for status in (302, 400, 401, 403, 404, 408, 429, 500, 503):
            with self.subTest(status=status):
                c, d = driver(HTTPReply(status, b'{"error":{"message":"rejected"}}'))
                with self.assertRaises(ProviderFailure) as caught:
                    d.next_action("E", {})
                self.assertEqual(caught.exception.delivery, "delivery_unknown")
                self.assertNotIn("delivered", [r["status"] for r in c.requests])
                self.assertEqual(d.requests, 1)

    def test_http_200_gateway_error_is_not_model_delivery(self):
        for body in (b'<html>gateway failed</html>', b'{"error":{"code":"busy"}}', b'[]'):
            with self.subTest(body=body):
                c, d = driver(HTTPReply(200, body))
                with self.assertRaises(ProviderFailure) as caught:
                    d.next_action("H", {})
                self.assertEqual(caught.exception.delivery, "delivery_unknown")
                self.assertNotIn("delivered", [r["status"] for r in c.requests])

    def test_refusal_and_truncation_have_distinct_observed_statuses(self):
        for finish, content, refusal, expected in (
            ("length", '{"type":"final"', None, "model_response_truncated"),
            ("content_filter", None, None, "model_content_filter"),
            ("stop", None, "I cannot help", "model_refusal"),
        ):
            with self.subTest(finish=finish, refusal=refusal):
                value = response()
                choice = value["choices"][0]
                choice["finish_reason"] = finish
                choice["message"].update(content=content, refusal=refusal)
                c, d = driver(HTTPReply(200, wire(value)))
                with self.assertRaises(ProviderFailure) as caught:
                    d.next_action("H", {})
                self.assertEqual(caught.exception.code, expected)
                self.assertEqual(caught.exception.delivery, "delivered")
                self.assertEqual(c.requests[-1]["status"], "delivered")

    def test_ambiguous_parallel_tool_channel_is_rejected(self):
        value = response()
        value["choices"][0]["message"]["tool_calls"] = [{"id": "call-1", "function": {"name": "delete"}}]
        c, d = driver(HTTPReply(200, wire(value)))
        with self.assertRaises(ProviderFailure):
            d.next_action("H", {})
        self.assertEqual(d.records, [])

    def test_empty_text_and_non_assistant_role_rejected(self):
        for updates in ({"content": "   "}, {"role": "tool"}, {"refusal": False}):
            with self.subTest(updates=updates):
                value = response()
                value["choices"][0]["message"].update(updates)
                _, d = driver(HTTPReply(200, wire(value)))
                with self.assertRaises(ProviderFailure):
                    d.next_action("H", {})

    def test_invalid_usage_is_not_accepted_as_real_token_accounting(self):
        for usage in ({"prompt_tokens": True}, {"completion_tokens": -1},
                      {"total_tokens": "30"}, {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 1}):
            with self.subTest(usage=usage):
                _, d = driver(HTTPReply(200, wire(response(usage=usage))))
                with self.assertRaises(ProviderFailure):
                    d.next_action("H", {})

    def test_missing_usage_is_explicit_unknown_not_zero(self):
        value = response()
        value.pop("usage")
        _, d = driver(HTTPReply(200, wire(value)))
        d.next_action("H", {})
        self.assertEqual(d.records[-1]["usage_status"], "unknown")
        self.assertIsNone(d.records[-1]["usage"])

    def test_numeric_profile_validation(self):
        for extra in ({"temperature": True}, {"temperature": -1}, {"temperature": 2.1},
                      {"seed": True}, {"seed": "1"}, {"reasoning_effort": []},
                      {"reasoning_effort": "invented-effort"}):
            with self.subTest(extra=extra):
                with self.assertRaises(ValueError):
                    driver(profile={"model": "locked-model", "max_completion_tokens": 100, **extra})

    def test_profile_cannot_mutate_after_construction(self):
        sent = []
        def transport(body):
            sent.append(json.loads(body))
            return HTTPReply(200, wire(response()))
        _, d = driver(transport=transport)
        view = d.profile
        view["model"] = "silently-changed"
        d.next_action("H", {})
        self.assertEqual(sent[0]["model"], "locked-model")

    def test_role_prompt_view_and_route_are_immutable(self):
        sent = []
        _, d = driver(transport=lambda b: (sent.append(json.loads(b)), HTTPReply(200, wire(response())))[1])
        view = d.role_prompts
        view["H"] = "changed prompt"
        d.next_action("H", {})
        self.assertNotEqual(sent[0]["messages"][0]["content"], "changed prompt")
        transport = HTTPTransport("http://127.0.0.1:19876/v1/chat/completions", "RQ1_PROVIDER_AUDIT_KEY")
        with self.assertRaises(AttributeError):
            transport.endpoint = "https://different.example/v1/chat/completions"

    def test_usage_on_truncation_is_not_dropped(self):
        value = response()
        value["choices"][0]["finish_reason"] = "length"
        c, d = driver(HTTPReply(200, wire(value)))
        with self.assertRaises(ProviderFailure):
            d.next_action("H", {})
        self.assertEqual(d.attempt_records[-1]["usage"], value["usage"])
        self.assertEqual(d.attempt_records[-1]["status"], "model_response_truncated")

    def test_invalid_message_does_not_invalidate_real_usage_counters(self):
        value = response()
        value["choices"][0]["message"]["role"] = "tool"
        _, d = driver(HTTPReply(200, wire(value)))
        with self.assertRaises(ProviderFailure):
            d.next_action("H", {})
        self.assertEqual(d.attempt_records[-1]["usage_status"], "reported")
        self.assertEqual(d.attempt_records[-1]["usage"], value["usage"])

    def test_reported_output_over_budget_never_executes_as_action(self):
        _, d = driver(HTTPReply(200, wire(response(usage={"completion_tokens": 101}))))
        with self.assertRaises(ProviderFailure):
            d.next_action("H", {})
        self.assertEqual(d.records, [])

    def test_utf16_bom_and_invalid_utf8_are_not_silently_normalized(self):
        for body in (json.dumps(response()).encode("utf-16"), b'\xef\xbb\xbf' + wire(response()), b'\xff'):
            with self.subTest(body_prefix=body[:4]):
                _, d = driver(HTTPReply(200, body))
                with self.assertRaises(ProviderFailure):
                    d.next_action("H", {})

    def test_json_action_text_not_repaired_by_provider(self):
        value = response()
        text = '{"type":"final","content":"done"}}'
        value["choices"][0]["message"]["content"] = text
        _, d = driver(HTTPReply(200, wire(value)))
        self.assertEqual(d.next_action("H", {}), text)  # Strict action validation belongs to runtime.

    def test_collector_failure_prevents_network_dispatch(self):
        calls = []
        c, d = driver(transport=lambda b: calls.append(b))
        c.record_model_request = lambda **_: (_ for _ in ()).throw(OSError("disk failed"))
        with self.assertRaises(OSError):
            d.next_action("H", {})
        self.assertEqual(calls, [])

    def test_transport_return_shape_is_stable_provider_failure(self):
        for reply in ({"status": 200}, HTTPReply(True, b'{}'), HTTPReply(200, "not-bytes")):
            with self.subTest(reply=reply):
                _, d = driver(transport=lambda _, r=reply: r)
                with self.assertRaises(ProviderFailure):
                    d.next_action("H", {})

    def test_known_credential_echo_never_enters_collector(self):
        key = "test-only-not-a-real-credential-123456"
        transport = HTTPTransport("http://127.0.0.1:19876/v1/chat/completions", "RQ1_PROVIDER_AUDIT_KEY")
        c, d = driver(transport=transport)
        error = HTTPError(transport.endpoint, 401, "denied", {"x-request-id": key},
                          io.BytesIO(("Bearer " + key).encode()))
        with patch.dict(os.environ, {"RQ1_PROVIDER_AUDIT_KEY": key}), patch.object(transport.opener, "open", side_effect=error):
            with self.assertRaises(ProviderFailure):
                d.next_action("E", {})
        serialized = repr(c.events) + repr(c.requests)
        self.assertNotIn(key, serialized)
        self.assertNotIn(key.encode().hex(), serialized)

    def test_credential_newline_rejected_before_transport_attempt(self):
        transport = HTTPTransport("http://127.0.0.1:19876/v1/chat/completions", "RQ1_PROVIDER_AUDIT_KEY")
        c, d = driver(transport=transport)
        with patch.dict(os.environ, {"RQ1_PROVIDER_AUDIT_KEY": "synthetic\r\ninvalid"}), patch.object(transport.opener, "open") as opened:
            with self.assertRaises(ProviderFailure) as caught:
                d.next_action("E", {})
            self.assertEqual(caught.exception.delivery, "prepared_only")
            opened.assert_not_called()
        self.assertEqual([r["status"] for r in c.requests], ["prepared_only"])

    def test_json_escaped_credential_success_body_is_not_logged(self):
        key = "synthetic-credential-987654"
        transport = HTTPTransport("http://127.0.0.1:19876/v1/chat/completions", "RQ1_PROVIDER_AUDIT_KEY")
        c, d = driver(transport=transport)
        value = response()
        value["choices"][0]["message"]["content"] = key
        body = wire(value).replace(key.encode(), b'\\u0073' + key[1:].encode())
        class Reply(io.BytesIO):
            status = 200
            headers = {}
        with patch.dict(os.environ, {"RQ1_PROVIDER_AUDIT_KEY": key}), patch.object(transport.opener, "open", return_value=Reply(body)):
            with self.assertRaises(ProviderFailure):
                d.next_action("H", {})
        event = next(row for row in c.events if row["kind"] == "model_response")
        self.assertTrue(event["data"]["response_redacted"])
        self.assertEqual(event["data"]["raw_response_hex"], "")

    def test_known_credential_in_request_rejected_before_recording_body(self):
        key = "synthetic-credential-987654"
        transport = HTTPTransport("http://127.0.0.1:19876/v1/chat/completions", "RQ1_PROVIDER_AUDIT_KEY")
        c, d = driver(transport=transport)
        with patch.dict(os.environ, {"RQ1_PROVIDER_AUDIT_KEY": key}), patch.object(transport.opener, "open") as opened:
            with self.assertRaises(ProviderFailure):
                d.next_action("H", {"accidental": key})
            opened.assert_not_called()
        self.assertEqual(c.requests, [])
        self.assertNotIn(key, repr(c.events))

    def test_failure_metadata_is_non_secret_and_preserves_category(self):
        value = response()
        value["choices"][0]["message"].update(content=None, refusal="private refusal text")
        _, d = driver(HTTPReply(200, wire(value)))
        with self.assertRaises(ProviderFailure) as caught:
            d.next_action("H", {})
        metadata = caught.exception.audit_metadata()
        self.assertEqual(metadata["kind"], "model_refusal")
        self.assertEqual(metadata["model_acceptance"], "response_observed")
        self.assertFalse(metadata["automatic_retry_allowed"])
        self.assertNotIn("private refusal", repr(metadata))

    def test_bounded_reply_and_timeout_are_not_retried(self):
        _, d = driver(HTTPReply(200, b'x' * 101), max_response_bytes=100)
        with self.assertRaises(ProviderFailure):
            d.next_action("E", {})
        self.assertEqual(d.requests, 1)
        calls = []
        def timeout(body):
            calls.append(body)
            raise TimeoutError("synthetic secret error")
        c, d = driver(transport=timeout)
        with self.assertRaises(ProviderFailure) as caught:
            d.next_action("E", {})
        self.assertEqual(caught.exception.delivery, "delivery_unknown")
        self.assertEqual(len(calls), 1)
        self.assertNotIn("synthetic secret", repr(c.events))

    def test_error_body_closed_even_on_http_failure(self):
        body = io.BytesIO(b'{"error":"denied"}')
        transport = HTTPTransport("http://127.0.0.1:19876/v1/chat/completions", "RQ1_PROVIDER_AUDIT_KEY")
        transport._credential = "synthetic-key"
        error = HTTPError(transport.endpoint, 401, "denied", {}, body)
        with patch.object(transport.opener, "open", side_effect=error):
            reply = transport(b'{}')
        self.assertEqual(reply.status, 401)
        self.assertTrue(body.closed)

    def test_short_content_length_valid_json_is_retained_but_not_executed(self):
        body = wire(response())
        class Reply(io.BytesIO):
            status = 200
            headers = {"Content-Length": str(len(body) + 71)}
        transport = HTTPTransport("http://127.0.0.1:19876/v1/chat/completions", "RQ1_PROVIDER_AUDIT_KEY")
        c, d = driver(transport=transport)
        with patch.dict(os.environ, {"RQ1_PROVIDER_AUDIT_KEY": "synthetic-key"}), patch.object(transport.opener, "open", return_value=Reply(body)) as opened:
            with self.assertRaises(ProviderFailure) as caught:
                d.next_action("H", {})
        self.assertEqual(caught.exception.code, "model_http_body_incomplete")
        self.assertEqual(caught.exception.kind, "transport_error")
        self.assertEqual(caught.exception.delivery, "delivery_unknown")
        self.assertEqual(caught.exception.gateway_response, "received")
        self.assertEqual(caught.exception.model_acceptance, "unknown")
        self.assertEqual(opened.call_count, 1)
        self.assertNotIn("delivered", [row["status"] for row in c.requests])
        event = next(row["data"] for row in c.events if row["kind"] == "model_response")
        self.assertEqual(event["response_hash_scope"], "observed_prefix")
        self.assertEqual(event["response_sha256"], hashlib.sha256(body).hexdigest())
        self.assertEqual(bytes.fromhex(event["raw_response_hex"]), body)
        self.assertFalse(event["response_capture_complete"])
        self.assertEqual(d.records, [])

    def test_valid_length_and_close_delimited_reads_remain_complete(self):
        body = wire(response())
        transport = HTTPTransport("http://127.0.0.1:19876/v1/chat/completions", "RQ1_PROVIDER_AUDIT_KEY")
        for headers in ({"Content-Length": str(len(body))}, {}):
            with self.subTest(headers=headers):
                stream = io.BytesIO(body)
                stream.headers = headers
                reply = transport._read_reply(stream, 200)
                self.assertTrue(reply.body_complete)
                self.assertEqual(reply.body, body)

    def test_chunk_incomplete_read_preserves_observed_prefix(self):
        body = wire(response())
        class Reply:
            headers = {"Transfer-Encoding": "chunked"}
            def read(self, size):
                raise http.client.IncompleteRead(body, 1)
        transport = HTTPTransport("http://127.0.0.1:19876/v1/chat/completions", "RQ1_PROVIDER_AUDIT_KEY")
        reply = transport._read_reply(Reply(), 200)
        self.assertFalse(reply.body_complete)
        self.assertEqual(reply.body, body)

    def test_invalid_or_conflicting_http_framing_never_attests_complete(self):
        body = wire(response())
        transport = HTTPTransport("http://127.0.0.1:19876/v1/chat/completions", "RQ1_PROVIDER_AUDIT_KEY")
        for entries in (
            [("Content-Length", "-1")], [("Content-Length", "not-a-number")],
            [("Content-Length", str(len(body))), ("Content-Length", str(len(body) + 71))],
            [("Transfer-Encoding", "chunked"), ("Content-Length", str(len(body)))],
            [("Transfer-Encoding", "gzip, chunked")],
        ):
            with self.subTest(entries=entries):
                stream = io.BytesIO(body)
                stream.headers = Message()
                for key, value in entries:
                    stream.headers[key] = value
                self.assertFalse(transport._read_reply(stream, 200).body_complete)

    def test_real_collector_seals_exact_wire_and_unknown_gateway_error(self):
        from agentmembrane.host_v2.rq1_collab_v1.audit import EventCollector, verify
        with tempfile.TemporaryDirectory(prefix="rq1-provider-audit-") as directory:
            collector = EventCollector(Path(directory) / "episode", "provider-integration")
            sent = []
            def transport(body):
                sent.append(body)
                return HTTPReply(401, b'{"error":"unauthorized"}', "gateway-only")
            obj = ModelDriver({"model": "locked-model", "max_completion_tokens": 100},
                              {"H": "Return JSON"}, collector, transport, request_limit=1)
            with self.assertRaises(ProviderFailure):
                obj.next_action("H", {"reminder": "ephemeral actual input"})
            collector.seal({"test_only": True})
            self.assertTrue(verify(collector.run_dir)["ok"])
            request_file = next((collector.run_dir / "model_requests").glob("*.body.json"))
            self.assertEqual(request_file.read_bytes(), sent[0])
            events = [json.loads(line) for line in (collector.run_dir / "events.jsonl").read_bytes().splitlines()]
            terminal = events[-1]["data"]["model_request_terminal_status"]
            self.assertEqual(list(terminal.values()), ["delivery_unknown"])


if __name__ == "__main__":
    unittest.main()
