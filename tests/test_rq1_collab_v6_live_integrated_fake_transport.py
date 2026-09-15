"""A live-mode source-native cell with only the HTTP request boundary faked.

This does not infer model behavior. It proves the route-bound v6 model wire can
drive the real W35 native subprocess, sealed runtime, and closed evaluator.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.rq1_collab_v1.audit import strict_loads, verify
from agentmembrane.host_v2.rq1_collab_v1.providers import HTTPReply
from agentmembrane.host_v2.rq1_collab_v6 import workflow
from agentmembrane.host_v2.rq1_collab_v6.report_codec import read_report
from agentmembrane.host_v2.rq1_collab_v6.evaluation import read_evidence
from agentmembrane.host_v2.rq1_collab_v6.provider_route import (
    BoundRouteTransport, SHARED_PROXY_CREDENTIAL_ENV_ENV,
    SHARED_PROXY_ENDPOINT_ENV, SHARED_PROXY_LABEL_ENV, inventory,
)


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
class LiveIntegratedFakeTransportTests(unittest.TestCase):
    def test_source_native_live_cell_seals_model_bound_e_actions(self):
        with tempfile.TemporaryDirectory(prefix="rq1-v6-live-fake-http-") as temporary:
            root = Path(temporary)
            route_file = root / "route.json"
            route_file.write_text(json.dumps({
                "schema_version": "rq1-provider-route/1",
                "endpoint": "http://127.0.0.1:9876/v1/chat/completions",
                "credential_env": "RQ1_V6_FAKE_HTTP_KEY", "account_label": "test-only",
            }))
            inventory_file = root / "inventory.json"
            model_requests = []

            def fake_request(transport, body, *, deadline_monotonic=None):
                self.assertIsInstance(transport, BoundRouteTransport)
                self.assertIsNotNone(deadline_monotonic)
                payload = json.loads(body)
                observation = json.loads(payload["messages"][1]["content"])
                actor = observation["actor"]
                model_requests.append((actor, payload, observation))
                self.assertEqual(payload["model"], "gpt-5-2025-08-07")
                self.assertEqual(observation["protocol_version"], "rq1-three-actor/6")
                self.assertIn("delegate", payload["tools"][0]["function"]
                              ["parameters"]["properties"]["type"]["enum"])
                if actor == "E":
                    history = [entry["content"] for entry in observation["history"]
                               if entry["role"] == "observation"
                               and entry["content"].get("status") == "tool_result"]
                    deleted = [entry for entry in history if entry.get("tool") == "delete_file"]
                    listed = [entry for entry in history if entry.get("tool") == "list_files"]
                    if deleted:
                        action = {"type": "final", "content": "The largest file was deleted."}
                    elif listed:
                        files = listed[-1]["result"]
                        maximum = max(file["size"] for file in files)
                        largest = [file for file in files if file["size"] == maximum]
                        self.assertEqual(len(largest), 1)
                        action = {"type": "tool_action", "tool": "delete_file",
                                  "arguments": {"file_id": largest[0]["id_"]}}
                    else:
                        self.assertIn("delete_file", observation["permissions"]["tools"])
                        action = {"type": "tool_action", "tool": "list_files", "arguments": {}}
                else:
                    self.assertEqual(actor, "H")
                    action = {"type": "final", "content": "The requested largest file was deleted."}
                response = {"model": payload["model"], "choices": [{"index": 0,
                    "finish_reason": "tool_calls", "message": {"role": "assistant", "content": None,
                        "tool_calls": [{"id": f"fake-{len(model_requests)}", "type": "function",
                            "function": {"name": "submit_action",
                                         "arguments": json.dumps(action)}}]}}],
                    "usage": {"prompt_tokens": 15, "completion_tokens": 10,
                              "total_tokens": 25}}
                return HTTPReply(200, json.dumps(response).encode(),
                                 receipt_id=f"fake-http-{len(model_requests)}")

            with (patch.dict(os.environ, {"RQ1_V6_FAKE_HTTP_KEY": "local-test-key"}),
                  patch("agentmembrane.host_v2.rq1_collab_v6.provider_route.urllib.request.build_opener",
                        return_value=_InventoryOpener())):
                inventory(route_file, inventory_file)
            prepared = workflow.prepare(
                root / "workflow", tasks=["workspace:user_task_35"],
                mode="live_diagnostic", topologies=("H_E",), levels=("medium",),
                regimes=("honest",), provider_route_file=route_file,
                inventory=inventory_file,
            )
            manifest_path = Path(prepared["manifest"])
            manifest = workflow.load_manifest(manifest_path)
            config = manifest["cells"][0]
            run = root / "run"
            with (patch.dict(os.environ, {"RQ1_V6_FAKE_HTTP_KEY": "local-test-key"}),
                  patch.object(BoundRouteTransport, "request", fake_request)):
                status = workflow.run_cell(manifest_path, config["episode_id"], run,
                                           execute_live=True, inventory=inventory_file)

            self.assertEqual(status["status"], "completed", status)
            self.assertTrue(status["execution_integrity"]["ok"])
            self.assertEqual([actor for actor, *_ in model_requests], ["E", "E", "E", "H"])
            report = read_report(run, status)
            self.assertEqual(report["behavioral_n"], 1)
            self.assertEqual(report["evaluation_errors"], [])
            self.assertEqual(report["terminal_reason"], "host_final")
            self.assertTrue(report["native_task_success"])
            self.assertFalse(report["native_goal_success"])
            self.assertEqual(report["strict_task_result"]["value"], 1)
            evidence = read_evidence(run / "execution", report["execution_seal_sha256"])
            self.assertEqual([row["tool"] for row in evidence["native_calls"]
                              if row["actor"] == "E"], ["list_files", "delete_file"])
            self.assertTrue(all(row["status"] == "committed" for row in evidence["native_calls"]
                                if row["actor"] == "E"))
            bindings = [row["model_binding"] for row in evidence["deliveries"]
                        if row.get("model_binding") is not None]
            self.assertEqual(len(bindings), 4)
            self.assertTrue(all(binding["actual_model"] == "gpt-5-2025-08-07"
                                for binding in bindings))
            self.assertTrue(verify(run / "execution",
                                   expected_seal_hash=report["execution_seal_sha256"])["ok"])


if __name__ == "__main__":
    unittest.main()
