"""Synthetic loopback transport and usage stop-line tests; zero proxy/model calls."""
import contextlib
import hashlib
import http.server
import json
import os
import threading
import time
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.rq1_collab_v1.providers import HTTPReply, HTTPTransport, ModelDriver, ProviderFailure


class Collector:
    def __init__(self):
        self.events, self.requests = [], []
    def emit(self, kind, data, **kwargs):
        row = {"event_id": str(len(self.events)), "kind": kind, "data": data, **kwargs}
        self.events.append(row)
        return row
    def record_model_request(self, **kwargs):
        self.requests.append(kwargs)


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def completion(usage=None):
    return {"model": "synthetic-model", "choices": [{"index": 0, "finish_reason": "stop",
        "message": {"role": "assistant", "content": '{"type":"final","content":"ok"}'}}],
        "usage": usage if usage is not None else {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}}


def strict_driver(transport=None, *, limits=None, request_limits=None, output=10):
    collector = Collector()
    obj = ModelDriver({"model": "synthetic-model", "max_completion_tokens": output},
        {"H": "host", "E": "external"}, collector, transport or (lambda _: HTTPReply(200, wire(completion()))),
        strict_usage=True, actor_token_limits=limits or {"H": 100, "E": 100},
        actor_request_limits=request_limits or {"H": 4, "E": 3}, request_limit=7)
    obj.begin_episode(deadline_monotonic=time.monotonic() + 10)
    return collector, obj


@contextlib.contextmanager
def local_http(mode):
    received = []
    body = wire(completion())
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *_):
            pass
        def do_POST(self):
            received.append(self.rfile.read(int(self.headers["Content-Length"])))
            try:
                if mode == "headers":
                    time.sleep(2)
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                if mode == "drip":
                    for offset in range(0, len(body), 4):
                        self.wfile.write(body[offset:offset + 4])
                        self.wfile.flush()
                        time.sleep(.025)
                else:
                    self.wfile.write(body)
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            self.close_connection = True
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/v1/chat/completions", received
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


class LiveLimitTests(unittest.TestCase):
    def test_normal_hard_transport_and_exact_binding(self):
        with local_http("normal") as (url, received), patch.dict(os.environ, {"RQ1_SYNTHETIC_TEST_KEY": "synthetic-key"}):
            transport = HTTPTransport(url, "RQ1_SYNTHETIC_TEST_KEY", hard_timeout_seconds=3)
            _, driver = strict_driver(transport)
            observation = {"reminder": "真正发送的临时提醒"}
            self.assertIn('"final"', driver.next_action("H", observation))
            binding = driver.last_completion_binding("H")
            self.assertEqual(binding["serialized_body"].encode(), received[0])
            self.assertEqual(binding["observation_sha256"], hashlib.sha256(wire(observation)).hexdigest())
            self.assertEqual(binding["request_sha256"], hashlib.sha256(received[0]).hexdigest())
            binding["actor"] = "tampered"
            self.assertEqual(driver.last_completion_binding("H")["actor"], "H")
            self.assertTrue(transport.last_attempt_metadata["local_worker_reaped"])
            self.assertFalse(driver.budget_snapshot()["halted"])

    def test_hard_deadline_covers_headers_and_body_and_reaps_worker(self):
        for mode in ("headers", "drip"):
            with self.subTest(mode=mode), local_http(mode) as (url, sent), patch.dict(os.environ, {"RQ1_SYNTHETIC_TEST_KEY": "synthetic-key"}):
                transport = HTTPTransport(url, "RQ1_SYNTHETIC_TEST_KEY", timeout_seconds=3, hard_timeout_seconds=1.2)
                collector, driver = strict_driver(transport)
                start = time.monotonic()
                with self.assertRaises(ProviderFailure) as caught:
                    driver.next_action("H", {})
                self.assertLess(time.monotonic() - start, 2.5)
                self.assertEqual(caught.exception.code, "model_request_wall_deadline")
                self.assertEqual(caught.exception.delivery, "delivery_unknown")
                evidence = transport.last_attempt_metadata
                self.assertTrue(evidence["local_worker_reaped"])
                with self.assertRaises(ProcessLookupError):
                    os.kill(evidence["worker_pid"], 0)
                self.assertEqual(evidence["upstream_cancellation"], "unknown")
                self.assertIsNone(driver.last_completion_binding("H"))
                self.assertTrue(driver.budget_snapshot()["halted"])
                with self.assertRaises(ProviderFailure) as retry:
                    driver.next_action("E", {})
                self.assertEqual(retry.exception.code, "provider_halted")
                self.assertEqual(len(sent), 1)
                self.assertNotIn("delivered", [row["status"] for row in collector.requests])

    def test_episode_deadline_shortens_request_limit(self):
        with local_http("drip") as (url, _), patch.dict(os.environ, {"RQ1_SYNTHETIC_TEST_KEY": "synthetic-key"}):
            transport = HTTPTransport(url, "RQ1_SYNTHETIC_TEST_KEY", hard_timeout_seconds=5)
            transport.prepare()
            start = time.monotonic()
            with self.assertRaises(ProviderFailure):
                transport.request(b'{}', deadline_monotonic=time.monotonic() + .25)
            self.assertLess(time.monotonic() - start, 1)
            self.assertTrue(transport.last_attempt_metadata["local_worker_reaped"])

    def test_unknown_partial_invalid_usage_stops_all_actors_without_execution(self):
        for usage in (None, {}, {"prompt_tokens": 2}, {"prompt_tokens": True},
                      {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                      {"prompt_tokens": 3, "completion_tokens": 0, "total_tokens": 3},
                      {"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 100}):
            with self.subTest(usage=usage):
                body = completion()
                body["usage"] = usage
                calls = []
                collector, driver = strict_driver(lambda b: (calls.append(b), HTTPReply(200, wire(body)))[1])
                with self.assertRaises(ProviderFailure) as caught:
                    driver.next_action("H", {})
                self.assertEqual(caught.exception.code, "model_usage_unverifiable")
                self.assertEqual(caught.exception.delivery, "delivered")
                self.assertEqual(driver.records, [])
                self.assertIsNone(driver.last_completion_binding("H"))
                with self.assertRaises(ProviderFailure):
                    driver.next_action("E", {})
                self.assertEqual(len(calls), 1)
                self.assertEqual(len(driver.attempt_records), 2)
                self.assertTrue(driver.budget_snapshot()["halted"])

    def test_unknown_http_failure_latches_global_stop(self):
        _, driver = strict_driver(lambda _: HTTPReply(401, b'{"error":"synthetic"}'))
        with self.assertRaises(ProviderFailure):
            driver.next_action("E", {})
        with self.assertRaises(ProviderFailure) as caught:
            driver.next_action("H", {})
        self.assertEqual(caught.exception.code, "provider_halted")
        snapshot = driver.budget_snapshot()
        self.assertEqual(snapshot["actors"]["E"]["unverifiable_attempts"], 1)
        self.assertEqual(driver.requests, 1)

    def test_actor_usage_is_independent_and_refusal_is_accounted(self):
        reply = completion({"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10})
        _, driver = strict_driver(lambda _: HTTPReply(200, wire(reply)), limits={"H": 20, "E": 100})
        driver.next_action("H", {})
        driver.next_action("H", {})
        with self.assertRaises(ProviderFailure) as caught:
            driver.next_action("H", {})
        self.assertEqual(caught.exception.code, "actor_token_budget_exhausted")
        driver.next_action("E", {})
        reply["choices"][0]["message"].update(content=None, refusal="unit refusal")
        with self.assertRaises(ProviderFailure):
            driver.next_action("E", {})
        snapshot = driver.budget_snapshot()
        self.assertEqual(snapshot["actors"]["H"]["total_tokens"], 20)
        self.assertEqual(snapshot["actors"]["E"]["total_tokens"], 20)
        self.assertFalse(snapshot["halted"])
        self.assertIsNone(driver.last_completion_binding("E"))

    def test_reported_overrun_not_misrepresented_as_precharged_cap(self):
        _, driver = strict_driver(lambda _: HTTPReply(200, wire(completion(
            {"prompt_tokens": 100, "completion_tokens": 1, "total_tokens": 101}))), limits={"H": 20, "E": 20})
        with self.assertRaises(ProviderFailure) as caught:
            driver.next_action("H", {})
        self.assertEqual(caught.exception.code, "actor_token_budget_exceeded")
        self.assertEqual(driver.budget_snapshot()["actors"]["H"]["total_tokens"], 101)
        self.assertEqual(driver.records, [])
        self.assertIn("not_exact_billing", driver.budget_snapshot()["accounting_semantics"])

    def test_request_limits_and_episode_cannot_reset(self):
        _, driver = strict_driver(request_limits={"H": 1, "E": 1})
        driver.next_action("H", {})
        with self.assertRaises(ValueError):
            driver.begin_episode(deadline_monotonic=time.monotonic() + 100)
        with self.assertRaises(ProviderFailure) as caught:
            driver.next_action("H", {})
        self.assertEqual(caught.exception.code, "actor_request_budget_exhausted")
        driver.next_action("E", {})
        self.assertEqual(driver.requests, 2)

    def test_expired_deadline_and_missing_begin_never_send(self):
        calls = []
        collector = Collector()
        driver = ModelDriver({"model": "synthetic-model", "max_completion_tokens": 10}, {"H": "host"},
            collector, lambda b: calls.append(b), request_limit=1, strict_usage=True,
            actor_token_limits={"H": 100}, actor_request_limits={"H": 1})
        with self.assertRaises(ProviderFailure) as caught:
            driver.next_action("H", {})
        self.assertEqual(caught.exception.code, "episode_deadline_not_set")
        driver.begin_episode(deadline_monotonic=time.monotonic() + .01)
        time.sleep(.02)
        with self.assertRaises(ProviderFailure) as caught:
            driver.next_action("H", {})
        self.assertEqual(caught.exception.code, "episode_deadline_exhausted")
        self.assertEqual(calls, [])

    def test_late_injected_reply_is_not_executable(self):
        def late(_):
            time.sleep(.03)
            return HTTPReply(200, wire(completion()))
        collector = Collector()
        driver = ModelDriver({"model": "synthetic-model", "max_completion_tokens": 10}, {"H": "host"},
            collector, late, request_limit=1, strict_usage=True,
            actor_token_limits={"H": 100}, actor_request_limits={"H": 1})
        driver.begin_episode(deadline_monotonic=time.monotonic() + .01)
        with self.assertRaises(ProviderFailure) as caught:
            driver.next_action("H", {})
        self.assertEqual(caught.exception.code, "episode_deadline_exhausted")
        self.assertIsNone(driver.last_completion_binding("H"))

    def test_limits_cannot_be_reconfigured_or_reset_through_public_views(self):
        _, driver = strict_driver()
        for name, value in (("request_limit", 999), ("max_request_bytes", 99999999),
                            ("strict_usage", False)):
            with self.subTest(name=name), self.assertRaises(AttributeError):
                setattr(driver, name, value)
        view = driver.actor_token_limits
        view["H"] = 99999
        self.assertEqual(driver.actor_token_limits["H"], 100)
        snapshot = driver.budget_snapshot()
        snapshot["actors"]["H"]["total_tokens"] = 999
        self.assertEqual(driver.budget_snapshot()["actors"]["H"]["total_tokens"], 0)

    def test_reported_output_limit_violation_stops_followup(self):
        _, driver = strict_driver(lambda _: HTTPReply(200, wire(completion(
            {"prompt_tokens": 1, "completion_tokens": 11, "total_tokens": 12}))))
        with self.assertRaises(ProviderFailure) as caught:
            driver.next_action("H", {})
        self.assertEqual(caught.exception.code, "reported_output_budget_exceeded")
        self.assertTrue(driver.budget_snapshot()["halted"])
        self.assertEqual(driver.budget_snapshot()["actors"]["H"]["total_tokens"], 12)
        with self.assertRaises(ProviderFailure):
            driver.next_action("E", {})

    def test_strict_live_transport_requires_hard_deadline_and_exact_actor_limits(self):
        with self.assertRaises(ValueError):
            strict_driver(HTTPTransport("http://127.0.0.1:19876/v1/chat/completions", "RQ1_SYNTHETIC_TEST_KEY"))
        with self.assertRaises(ValueError):
            strict_driver(limits={"H": 100})

    def test_h_only_can_pool_total_budget_without_inventing_external_actor(self):
        obj = ModelDriver({"model": "synthetic-model", "max_completion_tokens": 2048}, {"H": "host"},
            Collector(), lambda _: HTTPReply(200, wire(completion())), request_limit=40,
            strict_usage=True, actor_token_limits={"H": 120000}, actor_request_limits={"H": 40})
        obj.begin_episode(deadline_monotonic=time.monotonic() + 600)
        obj.next_action("H", {})
        self.assertEqual(set(obj.budget_snapshot()["actors"]), {"H"})
        self.assertEqual(obj.actor_token_limits, {"H": 120000})


if __name__ == "__main__":
    unittest.main()
