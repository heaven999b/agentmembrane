"""Synthetic transport checks only: no shared proxy, account or model API access."""
import contextlib
from email.message import Message
import hashlib
import http.server
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.rq1_collab_v1.audit import canonical, strict_loads
from agentmembrane.host_v2.rq1_collab_v1.providers import (
    HTTPReply, HTTPTransport, response_error_metadata, safe_response_metadata)
from agentmembrane.host_v2.rq1_collab_v4.model_probe import probe_profile

PROJECT = Path(__file__).resolve().parents[2]
SCRIPT = PROJECT / "experiments/host_boundary_v2/rq1_collab_v1/live_readiness_20260907/implementations/rq1_delivery_20260910/fixed_ok_route_diagnostic.py"


def diagnostic_module():
    spec = importlib.util.spec_from_file_location("fixed_ok_diagnostic_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def stream(body, trace=None):
    obj = io.BytesIO(body)
    obj.headers = Message()
    obj.headers["Content-Length"] = str(len(body))
    if trace is not None:
        obj.headers["X-CPA-TRACE-ID"] = trace
    return obj


class FakeTransport:
    def __init__(self, response, calls=None):
        self.response = response
        self.calls = [] if calls is None else calls
        self.salt = None
    def set_response_diagnostic_salt(self, salt):
        self.salt = salt
    def prepare(self):
        pass
    def contains_credential(self, body):
        return b"SYNTHETIC-PRIVATE-KEY" in body
    def __call__(self, body):
        self.calls.append(body)
        return self.response


class ResponseDiagnosticsTests(unittest.TestCase):
    profile = {"model": "gpt-5.5", "reasoning_effort": "medium", "max_completion_tokens": 512}

    def transport(self, salt=b"x" * 32):
        transport = HTTPTransport("http://127.0.0.1:19876/v1/chat/completions", "SYNTHETIC_KEY")
        if salt is not None:
            transport.set_response_diagnostic_salt(salt)
        return transport

    def test_reply_extension_backward_compatible_and_not_shared(self):
        a, b = HTTPReply(200, b"{}"), HTTPReply(200, b"{}")
        a.response_metadata["synthetic"] = True
        self.assertEqual(b.response_metadata, {})
        self.assertTrue(a.body_complete)

    def test_error_metadata_is_closed_not_arbitrary_text(self):
        body = canonical({"error": {"type": "invalid_request_error", "code": "model_not_found",
                                    "message": "SYNTHETIC-PRIVATE-KEY", "account": "private@example.invalid"}})
        self.assertEqual(response_error_metadata(body), {
            "error_type": "invalid_request_error", "error_code": "model_not_found"})
        self.assertEqual(response_error_metadata(canonical({"error": {"code": ["secret"], "type": {}}})), {})
        self.assertEqual(response_error_metadata(b"<html>private</html>"), {})
        self.assertEqual(response_error_metadata(b'{"error":{"code":"model_not_found","code":"private"}}'), {})

    def test_metadata_sanitizer_drops_unrecognized_values_and_keys(self):
        self.assertEqual(safe_response_metadata({"error_code": "SYNTHETIC-PRIVATE-KEY",
            "route_fingerprint": "private@example.invalid", "raw_header": "secret", "account": "secret"}), {})
        self.assertEqual(safe_response_metadata({"route_fingerprint": "a" * 64}), {"route_fingerprint": "a" * 64})
        self.assertEqual(safe_response_metadata([]), {})

    def test_route_stable_within_diagnostic_but_unlinkable_across_salts(self):
        body = b"{}"
        t = self.transport()
        a = t._read_reply(stream(body, "20260910010203-abc123-route_one"), 200).response_metadata
        b = t._read_reply(stream(body, "20260910040506-abc123-route_two"), 404).response_metadata
        c = self.transport(b"y" * 32)._read_reply(stream(body, "20260910010203-abc123-route_one"), 200).response_metadata
        d = t._read_reply(stream(body, "20260910010203-other-route_one"), 200).response_metadata
        self.assertEqual(a["route_fingerprint"], b["route_fingerprint"])
        self.assertNotEqual(a, c)
        self.assertNotEqual(a, d)
        self.assertNotIn(b"abc123", canonical(a))

    def test_route_default_off_and_malformed_or_duplicate_rejected(self):
        self.assertEqual(self.transport(None)._read_reply(stream(b"{}", "20260910010203-abc123-id"), 200).response_metadata, {})
        for value in ("private@example.invalid", "20260910-abc-id", "20260910010203-abc-id\nsecret", "x" * 10000):
            with self.subTest(value=value[:12]):
                self.assertEqual(self.transport()._read_reply(stream(b"{}", value), 200).response_metadata, {})
        reply = stream(b"{}", "20260910010203-abc-id")
        reply.headers["X-CPA-TRACE-ID"] = "20260910010203-def-id"
        self.assertEqual(self.transport()._read_reply(reply, 200).response_metadata, {})

    def test_salt_validation_never_echoes_input(self):
        for value in ("secret", b"secret", b"x" * 31, b"x" * 33, None):
            with self.assertRaisesRegex(ValueError, "response_diagnostic_salt_must_be_32_bytes"):
                self.transport().set_response_diagnostic_salt(value)

    def test_probe_non_json_gateway_error_is_still_http_error(self):
        body = b"<html>private server details</html>"
        reply = HTTPReply(404, body, response_metadata={"route_fingerprint": "a" * 64, "raw_header": "secret"})
        result = probe_profile(self.profile, FakeTransport(reply))
        self.assertEqual(result["status"], "gateway_error")
        self.assertEqual(result["response_sha256"], hashlib.sha256(body).hexdigest())
        self.assertEqual(result["response_metadata"], {"route_fingerprint": "a" * 64})
        self.assertNotIn(b"private", canonical(result))
        self.assertNotIn(b"raw_header", canonical(result))

    def test_quarantine_precedes_metadata_and_response_hash(self):
        result = probe_profile(self.profile, FakeTransport(HTTPReply(404, b"SYNTHETIC-PRIVATE-KEY",
            response_metadata={"route_fingerprint": "a" * 64})))
        self.assertEqual(result["status"], "response_quarantined")
        self.assertNotIn("response_metadata", result)
        self.assertNotIn("response_sha256", result)

    def test_incomplete_body_not_classified_as_complete_error(self):
        body = canonical({"error": {"code": "model_not_found"}})
        source = stream(body)
        source.headers.replace_header("Content-Length", str(len(body) + 5))
        reply = self.transport()._read_reply(source, 404)
        self.assertFalse(reply.body_complete)
        self.assertEqual(reply.response_metadata, {})

    def test_isolated_worker_propagates_only_safe_metadata(self):
        received = []
        body = canonical({"error": {"code": "model_not_found", "message": "private error text"}})
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_POST(self):
                received.append(self.rfile.read(int(self.headers["Content-Length"])))
                self.send_response(404)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-CPA-TRACE-ID", "20260910010203-synthetic_auth-request_id")
                self.send_header("X-Private-Account", "private@example.invalid")
                self.end_headers()
                self.wfile.write(body)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        thread.start()
        try:
            with patch.dict(os.environ, {"SYNTHETIC_KEY": "synthetic-local-key"}):
                t = HTTPTransport(f"http://127.0.0.1:{server.server_port}/v1/chat/completions", "SYNTHETIC_KEY",
                                  timeout_seconds=3, hard_timeout_seconds=3)
                t.set_response_diagnostic_salt(b"z" * 32)
                first, second = t(b"{}"), t(b"{}")
            self.assertEqual(first.response_metadata, second.response_metadata)
            self.assertEqual(set(first.response_metadata), {"route_fingerprint", "error_code"})
            self.assertEqual(first.status, 404)
            self.assertEqual(received, [b"{}", b"{}"])
            self.assertTrue(t.last_attempt_metadata["local_worker_reaped"])
            for private in (b"synthetic_auth", b"private@example.invalid", b"private error text", b"synthetic-local-key"):
                self.assertNotIn(private, canonical(first.response_metadata))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)


class FixedOKDiagnosticTests(unittest.TestCase):
    def test_requires_live_flag_before_creating_output(self):
        module = diagnostic_module()
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "run"
            with self.assertRaises(ValueError):
                module.run(output)
            self.assertFalse(output.exists())

    def test_four_identical_requests_even_when_all_404_no_retry_or_fallback(self):
        module, calls, transports = diagnostic_module(), [], []
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "run"
            def factory():
                ordinal = len(transports) + 1
                self.assertTrue((output / "config.json").is_file())
                self.assertTrue((output / "started.json").is_file())
                self.assertTrue((output / f"{ordinal:06d}-started.json").is_file())
                if ordinal > 1:
                    self.assertTrue((output / f"{ordinal - 1:06d}-result.json").is_file())
                t = FakeTransport(HTTPReply(404, b"not-json-private-error"), calls)
                transports.append(t)
                return t
            result = module.run(output, execute_live=True, factory=factory)
            self.assertEqual(result["transport_invocations"], 4)
            self.assertEqual(len(calls), 4)
            self.assertEqual(len(set(calls)), 1)
            payload = strict_loads(calls[0])
            self.assertEqual(payload["model"], "gpt-5.5")
            self.assertEqual(payload["reasoning_effort"], "medium")
            self.assertEqual(payload["max_completion_tokens"], 512)
            self.assertNotIn("tools", payload)
            self.assertEqual(len({t.salt for t in transports}), 1)
            self.assertEqual(len(transports[0].salt), 32)
            artifact_bytes = b"".join(p.read_bytes() for p in output.iterdir())
            self.assertNotIn(transports[0].salt.hex().encode(), artifact_bytes)
            self.assertNotIn(b"not-json-private-error", artifact_bytes)
            self.assertIsNone(result["upstream_attempt_count"])
            self.assertFalse(result["formal_ready"])
            self.assertFalse(result["scores_updated"])
            self.assertTrue(result["implementation_unchanged"])

    def test_setup_failures_preserved_without_calls_or_secret_exception_text(self):
        module = diagnostic_module()
        with tempfile.TemporaryDirectory() as tmp:
            def factory():
                raise ValueError("SYNTHETIC-PRIVATE-KEY")
            result = module.run(Path(tmp)/"run", execute_live=True, factory=factory)
            self.assertEqual(result["transport_invocations"], 0)
            self.assertEqual(len(result["rows"]), 4)
            self.assertNotIn(b"SYNTHETIC-PRIVATE-KEY", canonical(result))

    def test_implementation_change_stops_remaining_preallocated_slots(self):
        module, calls, checks = diagnostic_module(), [], []
        def hashes():
            checks.append(1)
            return {"code": "first" if len(checks) < 3 else "changed"}
        with tempfile.TemporaryDirectory() as tmp, patch.object(module, "_hashes", side_effect=hashes):
            result = module.run(Path(tmp)/"run", execute_live=True,
                factory=lambda: FakeTransport(HTTPReply(404, b"{}"), calls))
            self.assertEqual(len(calls), 1)
            self.assertEqual(result["stop_reason"], "registered_diagnostic_changed")
            self.assertEqual([row["status"] for row in result["rows"]][1:], ["not_scheduled"] * 3)

    def test_credential_quarantine_stops_remaining_slots(self):
        module, calls = diagnostic_module(), []
        with tempfile.TemporaryDirectory() as tmp:
            result = module.run(Path(tmp)/"run", execute_live=True,
                factory=lambda: FakeTransport(HTTPReply(200, b"SYNTHETIC-PRIVATE-KEY"), calls))
            self.assertEqual(len(calls), 1)
            self.assertEqual(result["stop_reason"], "response_quarantined")
            self.assertEqual(result["transport_invocations"], 1)


if __name__ == "__main__":
    unittest.main()
