"""Local HTTP only + original AgentDojo memory process; zero remote model calls."""
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.rq1_collab_v1.audit import EventCollector
from agentmembrane.host_v2.rq1_collab_v1.attribution import assess_attribution
from agentmembrane.host_v2.rq1_collab_v1.policy import compile_user_task8_policy
from agentmembrane.host_v2.rq1_collab_v1.process_backend import NativeProcessFailure, PipeWorker, ProcessNativeTask
from agentmembrane.host_v2.rq1_collab_v1.providers import HTTPTransport, ModelDriver
from agentmembrane.host_v2.rq1_collab_v1.runtime import RuntimeConfigurationError, run_episode
from agentmembrane.host_v2.rq1_collab_v1.services import SystemServices
from tests.rq1_collab_v1.test_runtime import NativeFixture, Scripted, final, tool

ROOT = Path(__file__).resolve().parents[2]
PYTHON = ROOT / "experiments/host_boundary_v2/runtime_envs/agentdojo-0.1.35-py3123-lock-395e3d0a5921-rq1v4/bin/python"
SOURCE = ROOT / "data/host_boundary_v2/upstream/agentdojo"
PROFILE = {"model": "local-engineering-http-model", "max_completion_tokens": 100}


class RuntimeLiveTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="rq1-runtime-live-local-")
        self.addCleanup(self.directory.cleanup)
        self.collector = EventCollector(Path(self.directory.name) / "evidence", "local-model-diagnostic")
        self.addCleanup(self.collector.abort)
        self.services = SystemServices(str(Path(self.directory.name) / "services.sqlite"), "local-model-diagnostic")
        self.addCleanup(self.services.disconnect)
        self.adapter = ProcessNativeTask(str(PYTHON), str(SOURCE), "workspace", "user_task_8", timeout=20)
        self.addCleanup(self.adapter.shutdown)
        self.requests = []
        self.reply = lambda payload: self.completion(final())
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                raw = self.rfile.read(int(self.headers["Content-Length"]))
                payload = json.loads(raw)
                owner.requests.append(payload)
                status, body = owner.reply(payload)
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                try:
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.env = patch.dict(os.environ, {"RQ1_LOCAL_TEST_TOKEN": "nonsecret-local-only-token"})
        self.env.start()
        self.addCleanup(self.env.stop)

    def completion(self, action, usage=True):
        reply = {"model": PROFILE["model"], "choices": [{"index": 0, "finish_reason": "stop",
                 "message": {"role": "assistant", "content": json.dumps(action)}}]}
        if usage:
            reply["usage"] = {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        return 200, reply

    def config(self, arm="H_ONLY", seconds=20):
        return {"episode_id": "local-model-diagnostic", "arm": arm, "level": "A0", "seed": 0,
                "budget": {"host_decisions": 3, "external_decisions": 2, "max_delegations": 2,
                           "episode_wall_seconds": seconds},
                "task_policy": compile_user_task8_policy(self.adapter.prompt), "model_profile": PROFILE,
                "protocol_hash": "localhost-engineering-only", "execution_mode": "remote_text_mediated_diagnostic"}

    def driver(self, config=None, *, hard=3, strict=True):
        config = config or self.config()
        roles = {"H": "Host: return one strict JSON action."}
        limits, tokens = {"H": 5}, {"H": 120000}
        if config["arm"] != "H_ONLY":
            roles["E"] = "External: return one strict JSON action."
            limits, tokens = {"H": 3, "E": 2}, {"H": 72000, "E": 48000}
        transport = HTTPTransport(f"http://127.0.0.1:{self.server.server_port}/v1/chat/completions",
                                  "RQ1_LOCAL_TEST_TOKEN", timeout_seconds=3, hard_timeout_seconds=hard)
        return ModelDriver(PROFILE, roles, self.collector, transport, request_limit=5,
                           strict_usage=strict, actor_token_limits=tokens, actor_request_limits=limits)

    def run_live(self, config=None, driver=None):
        config = config or self.config()
        evidence = run_episode(config, self.adapter, driver or self.driver(config), self.services, self.collector)
        self.assertNotEqual(evidence["status"], "failed_to_seal", evidence.get("unknown_reasons"))
        return evidence

    def test_real_http_reply_dispatches_original_api_and_binds_exact_request(self):
        steps = [tool("get_current_day"), final("finished")]
        self.reply = lambda p: self.completion(steps.pop(0))
        evidence = self.run_live()
        self.assertEqual(evidence["termination"], "host_final")
        self.assertEqual(evidence["native_calls"][0]["status"], "committed")
        self.assertEqual(evidence["behavioral_n"], 0)
        self.assertEqual(len(evidence["model_decisions"]), 2)
        model = evidence["model_decisions"][0]["provider_binding"]
        self.assertEqual(model["request_sha256"], hashlib.sha256(model["serialized_body"].encode()).hexdigest())
        result = assess_attribution(evidence)
        self.assertEqual(result["errors"], [])
        self.assertTrue(any(row["call_input_lineage"] == "verified_invocation_lineage" for row in result["call_links"]))
        self.assertEqual(result["induced_violations"], [])
        for payload in self.requests:
            observation = json.loads(payload["messages"][1]["content"])
            self.assertNotIn("snapshot", observation)
            self.assertNotIn("native_record", observation)
            self.assertNotIn("ground_truth", observation)
        self.assertEqual(evidence["model_budget"]["actors"]["H"]["total_tokens"], 30)

    def test_unknown_usage_reply_never_executes_its_action_and_stops_episode(self):
        self.reply = lambda p: self.completion(tool("get_current_day"), usage=False)
        evidence = self.run_live()
        self.assertEqual(evidence["termination"], "model_budget_or_usage_halted")
        self.assertEqual(evidence["native_calls"], [])
        self.assertEqual(len(self.requests), 1)
        self.assertTrue(evidence["model_budget"]["halted"])
        self.assertEqual(evidence["information_deliveries"][0]["delivery_status"], "delivered")

    def test_http401_is_unknown_delivery_and_no_native_action(self):
        self.reply = lambda p: (401, b"unauthorized-local-test")
        evidence = self.run_live()
        self.assertEqual(evidence["termination"], "model_budget_or_usage_halted")
        self.assertEqual(evidence["native_calls"], [])
        self.assertEqual(evidence["information_deliveries"][0]["delivery_status"], "delivery_unknown")
        self.assertEqual(evidence["driver_failures"][0]["provider"]["http_status"], 401)

    def test_code_and_unregistered_dynamic_tool_are_rejected(self):
        steps = [{"type": "code_execution", "language": "python", "code": "raise RuntimeError('must never run')"},
                 tool("dynamic.real_shell", cmd="must never run"), final()]
        self.reply = lambda p: self.completion(steps.pop(0))
        evidence = self.run_live()
        self.assertEqual(evidence["termination"], "host_final")
        self.assertEqual(evidence["native_calls"], [])
        serialized = json.dumps(self.requests)
        self.assertIn("code_execution_not_in_diagnostic_surface", serialized)
        self.assertIn("tool_not_in_reviewed_diagnostic_registry", serialized)

    def test_actual_episode_deadline_kills_slow_http_then_closes_without_action(self):
        def delayed(payload):
            time.sleep(2.5)
            return self.completion(tool("get_current_day"))
        self.reply = delayed
        config = self.config(seconds=1.5)
        started = time.monotonic()
        evidence = self.run_live(config)
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(evidence["termination"], "episode_deadline_exhausted", evidence["unknown_reasons"])
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(evidence["native_calls"], [])
        self.assertEqual(evidence["post_close_probe"]["old_leases_accepted"], {"H": False})
        self.assertIsNotNone(evidence["terminal_snapshot"])

    def test_returned_after_deadline_action_not_dispatched_even_if_reply_valid(self):
        driver = self.driver(self.config(seconds=1.5))
        original = driver.next_action
        def delayed(actor, observation):
            raw = original(actor, observation)
            time.sleep(1.6)
            return raw
        # Intentional TCB delay after real successful localhost reply. This is
        # fault injection, not evidence that the upstream model ignored a limit.
        with patch.object(driver, "next_action", side_effect=delayed):
            self.reply = lambda p: self.completion(tool("get_current_day"))
            evidence = self.run_live(self.config(seconds=1.5), driver)
        self.assertEqual(evidence["termination"], "episode_deadline_exhausted", evidence["unknown_reasons"])
        self.assertEqual(len(evidence["model_decisions"]), 1)
        self.assertEqual(evidence["native_calls"], [])

    def test_service_dispatch_cannot_start_after_slow_label_snapshot(self):
        original = self.adapter.snapshot
        snapshots = 0
        def delayed_snapshot():
            nonlocal snapshots
            snapshots += 1
            result = original()
            # setup snapshot; initial consume snapshot; context-ceiling snapshot;
            # send_message's recipient label snapshot is the fourth.
            if snapshots == 4:
                time.sleep(1.6)
            return result
        self.reply = lambda p: self.completion({"type": "send_message", "recipient": "E", "content": "late"})
        with patch.object(self.adapter, "snapshot", side_effect=delayed_snapshot):
            evidence = self.run_live(self.config(seconds=1.5))
        self.assertEqual(evidence["termination"], "episode_deadline_exhausted", evidence["unknown_reasons"])
        self.assertFalse(any(c["action"] == "route.send" for c in evidence["service_calls"]))
        self.assertEqual(evidence["terminal_service_snapshot"]["messages"], [])

    def test_h_e_real_messages_remain_separate_inputs_and_no_causal_promotion(self):
        config = self.config("PLAIN")
        self.reply = lambda p: self.completion(final("E observation" if json.loads(p["messages"][1]["content"])["actor"] == "E" else "H answer"))
        evidence = self.run_live(config)
        self.assertEqual(evidence["termination"], "host_final")
        actual = [json.loads(p["messages"][1]["content"]) for p in self.requests]
        self.assertEqual([o["actor"] for o in actual], ["E", "H"])
        self.assertEqual(actual[0]["history"], [])
        self.assertIn("E observation", json.dumps(actual[1]["history"]))
        self.assertEqual(evidence["model_budget"]["actors"]["E"]["total_tokens"], 15)
        self.assertEqual(evidence["model_budget"]["actors"]["H"]["total_tokens"], 15)
        self.assertEqual(assess_attribution(evidence)["induced_violations"], [])

    def test_driver_fixture_and_unbounded_transport_cannot_bypass_mode_gate(self):
        with self.assertRaisesRegex(RuntimeConfigurationError, "reviewed_model_driver"):
            run_episode(self.config(), self.adapter, Scripted([final()], []), self.services, self.collector)
        driver = self.driver()
        with self.assertRaisesRegex(RuntimeConfigurationError, "original_in_memory"):
            run_episode(self.config(), NativeFixture(), driver, self.services, self.collector)
        driver = self.driver(hard=None, strict=False)
        with self.assertRaisesRegex(RuntimeConfigurationError, "strict_usage_and_hard"):
            self.run_live(driver=driver)

    def test_changed_model_profile_and_collector_rejected_before_network(self):
        config = self.config()
        config["model_profile"] = {**PROFILE, "model": "different-model"}
        with self.assertRaisesRegex(RuntimeConfigurationError, "model_profile_mismatch"):
            self.run_live(config, self.driver())
        self.assertEqual(self.requests, [])

    def test_model_output_reference_tamper_stops_instead_of_executes(self):
        driver = self.driver()
        original = driver.last_completion_binding
        def changed(actor):
            binding = original(actor)
            binding["output_sha256"] = "0" * 64
            return binding
        self.reply = lambda p: self.completion(tool("get_current_day"))
        with patch.object(driver, "last_completion_binding", side_effect=changed):
            evidence = self.run_live(driver=driver)
        self.assertEqual(evidence["termination"], "model_evidence_invalid")
        self.assertEqual(evidence["native_calls"], [])
        self.assertEqual(len(self.requests), 1)

    def test_expired_native_deadline_sends_nothing_cleanup_is_only_readonly(self):
        self.adapter.begin_episode(deadline_monotonic=time.monotonic() + 0.03)
        time.sleep(0.04)
        sequence = self.adapter.worker.seq
        with self.assertRaises(NativeProcessFailure) as caught:
            self.adapter.call("get_current_day", {})
        self.assertFalse(caught.exception.commit_unknown)
        self.assertEqual(self.adapter.worker.seq, sequence)
        with self.assertRaisesRegex(NativeProcessFailure, "cleanup_requires_closed"):
            self.adapter.snapshot_after_close()
        self.adapter.close_admission()
        self.assertIn("calendar", self.adapter.snapshot_after_close())
        with self.assertRaisesRegex(NativeProcessFailure, "admission_closed"):
            self.adapter.call("get_current_day", {})
        with self.assertRaises(ValueError):
            self.adapter.begin_episode(deadline_monotonic=time.monotonic() + 5)

    def test_native_rpc_uses_episode_deadline_and_poison_after_uncertain_send(self):
        self.adapter.begin_episode(deadline_monotonic=time.monotonic() + 5)
        observed = []
        original = self.adapter.worker._receive
        def receive(*, deadline=None, commit_unknown=True):
            observed.append(deadline)
            return original(deadline=deadline, commit_unknown=commit_unknown)
        with patch.object(self.adapter.worker, "_receive", side_effect=receive):
            self.adapter.call("get_current_day", {})
        self.assertLessEqual(observed[0], self.adapter._episode_deadline)
        with patch.object(self.adapter.worker, "_receive", side_effect=NativeProcessFailure("fault", commit_unknown=True)):
            with self.assertRaises(NativeProcessFailure):
                self.adapter.call("get_current_day", {})
        self.assertTrue(self.adapter.worker.poisoned)
        self.adapter.close_admission()
        with self.assertRaises(NativeProcessFailure):
            self.adapter.snapshot_after_close()


if __name__ == "__main__":
    unittest.main()
