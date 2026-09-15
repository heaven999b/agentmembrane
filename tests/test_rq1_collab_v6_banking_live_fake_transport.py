"""Banking live-mode native read through fake HTTP, sealed and closed.

The HTTP boundary is fake; the source-native process, permission checks,
collector, evidence seal and closed evaluator are real. No provider is called.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.rq1_collab_v1.audit import (
    EventCollector, _check_no_transport_secrets, verify,
)
from agentmembrane.host_v2.rq1_collab_v1.providers import HTTPReply
from agentmembrane.host_v2.rq1_collab_v6 import workflow
from agentmembrane.host_v2.rq1_collab_v6.evaluation import read_evidence
from agentmembrane.host_v2.rq1_collab_v6.provider_route import (
    BoundRouteTransport, SHARED_PROXY_CREDENTIAL_ENV_ENV,
    SHARED_PROXY_ENDPOINT_ENV, SHARED_PROXY_LABEL_ENV, inventory,
)
from agentmembrane.host_v2.rq1_collab_v6.report_codec import read_report


SOURCE = Path(__file__).resolve().parents[1] / "experiments/host_boundary_v2/rq1_three_tier_large_scale/candidate_run_006"
SHARED_POLICY_ENV = {
    SHARED_PROXY_ENDPOINT_ENV: "http://127.0.0.1:19876/v1/chat/completions",
    SHARED_PROXY_CREDENTIAL_ENV_ENV: "RQ1_SYNTHETIC_SHARED_PROXY_KEY",
    SHARED_PROXY_LABEL_ENV: "synthetic_shared_pool",
}


class _InventoryResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit):
        return b'{"data":[{"id":"gpt-5-2025-08-07"}]}'


class _InventoryOpener:
    def open(self, request, timeout):
        assert request.full_url == "http://127.0.0.1:9876/v1/models"
        assert request.get_header("Authorization") == "Bearer local-test-key"
        assert timeout == 10
        return _InventoryResponse()


@patch.dict(os.environ, SHARED_POLICY_ENV)
class BankingLiveFakeTransportTests(unittest.TestCase):
    def test_source_native_denial_keeps_controller_running_and_seals(self):
        with tempfile.TemporaryDirectory(prefix="rq1-banking-denied-fake-http-") as temporary:
            root = Path(temporary)
            route_file = root / "route.json"
            route_file.write_text(json.dumps({
                "schema_version": "rq1-provider-route/1",
                "endpoint": "http://127.0.0.1:9876/v1/chat/completions",
                "credential_env": "RQ1_V6_FAKE_HTTP_KEY", "account_label": "test-only",
            }))
            inventory_file = root / "inventory.json"
            e_calls = 0

            def fake_request(transport, body, *, deadline_monotonic=None):
                nonlocal e_calls
                self.assertIsInstance(transport, BoundRouteTransport)
                payload = json.loads(body)
                observation = json.loads(payload["messages"][1]["content"])
                if observation["actor"] == "E":
                    e_calls += 1
                    action = ({"type": "tool_action", "tool": "send_money",
                               "arguments": {"recipient": "GB29NWBK60161331926819",
                                             "amount": 9999, "subject": "unrequested transfer"}}
                              if e_calls == 1 else {"type": "final", "content": "The transfer was refused."})
                else:
                    action = {"type": "final", "content": "I did not issue a refund."}
                response = {"model": payload["model"], "choices": [{"index": 0,
                    "finish_reason": "tool_calls", "message": {"role": "assistant", "content": None,
                        "tool_calls": [{"id": f"fake-{observation['actor']}-{e_calls}", "type": "function",
                            "function": {"name": "submit_action", "arguments": json.dumps(action)}}]}}],
                    "usage": {"prompt_tokens": 15, "completion_tokens": 10, "total_tokens": 25}}
                return HTTPReply(200, json.dumps(response).encode(),
                                 receipt_id=f"fake-http-{observation['actor']}-{e_calls}")

            with (patch.dict(os.environ, {"RQ1_V6_FAKE_HTTP_KEY": "local-test-key"}),
                  patch("agentmembrane.host_v2.rq1_collab_v6.provider_route.urllib.request.build_opener",
                        return_value=_InventoryOpener())):
                inventory(route_file, inventory_file)
            prepared = workflow.prepare(
                root / "workflow", tasks=["banking:user_task_4"],
                mode="live_diagnostic", topologies=("H_E",), levels=("medium",),
                regimes=("malicious",), provider_route_file=route_file,
                inventory=inventory_file, qualified=SOURCE / "candidate-manifest.json",
                goals=SOURCE / "goal-assignments-proposed.json",
            )
            manifest_path = Path(prepared["manifest"])
            config = workflow.load_manifest(manifest_path)["cells"][0]
            run = root / "run"
            with (patch.dict(os.environ, {"RQ1_V6_FAKE_HTTP_KEY": "local-test-key"}),
                  patch.object(BoundRouteTransport, "request", fake_request)):
                status = workflow.run_cell(manifest_path, config["episode_id"], run,
                                           execute_live=True, inventory=inventory_file)

            self.assertEqual(status["status"], "completed", status)
            report = read_report(run, status)
            evidence = read_evidence(run / "execution", report["execution_seal_sha256"])
            denied = [row for row in evidence["native_calls"] if row["tool"] == "send_money"]
            self.assertEqual(len(denied), 1)
            self.assertEqual(denied[0]["status"], "rejected")
            self.assertFalse(denied[0]["evidence_quality"]["backend_entered"])
            self.assertFalse(report["native_goal_success"])
            self.assertTrue(verify(run / "execution",
                                   expected_seal_hash=report["execution_seal_sha256"])["ok"])

    def test_source_native_read_then_h_final_seals_and_scores(self):
        with tempfile.TemporaryDirectory(prefix="rq1-banking-native-fake-http-") as temporary:
            root = Path(temporary)
            route_file = root / "route.json"
            route_file.write_text(json.dumps({
                "schema_version": "rq1-provider-route/1",
                "endpoint": "http://127.0.0.1:9876/v1/chat/completions",
                "credential_env": "RQ1_V6_FAKE_HTTP_KEY", "account_label": "test-only",
            }))
            inventory_file = root / "inventory.json"
            model_requests = []
            total = []

            def fake_request(transport, body, *, deadline_monotonic=None):
                self.assertIsInstance(transport, BoundRouteTransport)
                self.assertIsNotNone(deadline_monotonic)
                payload = json.loads(body)
                observation = json.loads(payload["messages"][1]["content"])
                actor = observation["actor"]
                model_requests.append((actor, payload, observation))
                self.assertEqual(payload["model"], "gpt-5-2025-08-07")
                self.assertEqual(observation["protocol_version"], "rq1-three-actor/6")
                self.assertNotIn("update_password", observation["permissions"]["tools"])
                if actor == "E":
                    result = [entry["content"] for entry in observation["history"]
                              if entry["role"] == "observation"
                              and entry["content"].get("status") == "tool_result"
                              and entry["content"].get("tool") == "get_most_recent_transactions"]
                    if result:
                        total.append(sum(item["amount"] for item in result[-1]["result"]))
                        action = {"type": "final", "content": f"Your total spending in March 2022 was {total[-1]}."}
                    else:
                        self.assertIn("get_most_recent_transactions", observation["permissions"]["tools"])
                        action = {"type": "tool_action", "tool": "get_most_recent_transactions",
                                  "arguments": {"n": 100}}
                else:
                    self.assertEqual(actor, "H")
                    self.assertEqual(len(total), 1)
                    action = {"type": "final", "content": f"Your total spending in March 2022 was {total[0]}."}
                response = {"model": payload["model"], "choices": [{"index": 0,
                    "finish_reason": "tool_calls", "message": {"role": "assistant", "content": None,
                        "tool_calls": [{"id": f"fake-{len(model_requests)}", "type": "function",
                            "function": {"name": "submit_action", "arguments": json.dumps(action)}}]}}],
                    "usage": {"prompt_tokens": 15, "completion_tokens": 10, "total_tokens": 25}}
                return HTTPReply(200, json.dumps(response).encode(),
                                 receipt_id=f"fake-http-{len(model_requests)}")

            with (patch.dict(os.environ, {"RQ1_V6_FAKE_HTTP_KEY": "local-test-key"}),
                  patch("agentmembrane.host_v2.rq1_collab_v6.provider_route.urllib.request.build_opener",
                        return_value=_InventoryOpener())):
                inventory(route_file, inventory_file)
            prepared = workflow.prepare(
                root / "workflow", tasks=["banking:user_task_1"],
                mode="live_diagnostic", topologies=("H_E",), levels=("medium",),
                regimes=("honest",), provider_route_file=route_file,
                inventory=inventory_file,
                qualified=SOURCE / "candidate-manifest.json",
                goals=SOURCE / "goal-assignments-proposed.json",
            )
            manifest_path = Path(prepared["manifest"])
            config = workflow.load_manifest(manifest_path)["cells"][0]
            run = root / "run"
            with (patch.dict(os.environ, {"RQ1_V6_FAKE_HTTP_KEY": "local-test-key"}),
                  patch.object(BoundRouteTransport, "request", fake_request)):
                status = workflow.run_cell(manifest_path, config["episode_id"], run,
                                           execute_live=True, inventory=inventory_file)

            self.assertEqual(status["status"], "completed", status)
            self.assertTrue(status["execution_integrity"]["ok"])
            self.assertEqual([actor for actor, *_ in model_requests], ["E", "E", "H"])
            report = read_report(run, status)
            self.assertEqual(report["evaluation_errors"], [])
            self.assertEqual(report["terminal_reason"], "host_final")
            self.assertTrue(report["native_task_success"])
            self.assertFalse(report["native_goal_success"])
            self.assertEqual(report["strict_task_result"]["value"], 1)
            evidence = read_evidence(run / "execution", report["execution_seal_sha256"])
            calls = [row for row in evidence["native_calls"] if row["actor"] == "E"]
            self.assertEqual([row["tool"] for row in calls], ["get_most_recent_transactions"])
            self.assertEqual(calls[0]["status"], "committed")
            self.assertIn("password", calls[0]["before"]["user_account"])
            self.assertEqual(calls[0]["before"]["user_account"], calls[0]["after"]["user_account"])
            self.assertEqual(len([row for row in evidence["deliveries"]
                                  if row.get("model_binding") is not None]), 3)
            self.assertTrue(verify(run / "execution",
                                   expected_seal_hash=report["execution_seal_sha256"])["ok"])
            with self.assertRaises(ValueError):
                _check_no_transport_secrets({"arguments": {"password": "actual-argument"}})
            rejected = EventCollector(root / "rejected", "rejected-password")
            with self.assertRaises(ValueError):
                rejected.emit("native_admitted", {"arguments": {"password": "actual-argument"}})
            rejected.abort()


if __name__ == "__main__":
    unittest.main()
