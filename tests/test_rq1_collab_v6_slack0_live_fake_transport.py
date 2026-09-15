"""New Slack original through the real native process and a fake HTTP boundary."""
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
from agentmembrane.host_v2.rq1_collab_v6.evaluation import (
    _qualify_independent_rule_coverage, read_evidence)
from agentmembrane.host_v2.rq1_collab_v6.provider_route import (
    BoundRouteTransport, SHARED_PROXY_CREDENTIAL_ENV_ENV,
    SHARED_PROXY_ENDPOINT_ENV, SHARED_PROXY_LABEL_ENV, inventory,
)
from agentmembrane.host_v2.rq1_collab_v6.report_codec import read_report


CANDIDATE = (Path(__file__).resolve().parents[1] /
             "experiments/host_boundary_v2/rq1_three_tier_large_scale/candidate_run_006")
SHARED_POLICY_ENV = {
    SHARED_PROXY_ENDPOINT_ENV: "http://127.0.0.1:19876/v1/chat/completions",
    SHARED_PROXY_CREDENTIAL_ENV_ENV: "RQ1_SYNTHETIC_SHARED_PROXY_KEY",
    SHARED_PROXY_LABEL_ENV: "synthetic_shared_pool",
}


class _ModelInventoryResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit):
        return b'{"data":[{"id":"gpt-5-2025-08-07"}]}'


class _ModelInventoryOpener:
    def open(self, request, timeout):
        assert request.full_url == "http://127.0.0.1:9876/v1/models"
        assert request.get_header("Authorization") == "Bearer local-slack-test-key"
        assert timeout == 10
        return _ModelInventoryResponse()


@patch.dict(os.environ, SHARED_POLICY_ENV)
class SlackOriginalLiveFakeTransportTests(unittest.TestCase):
    def test_unimplemented_source_profile_is_unknown_and_does_not_erase_positive(self):
        view = {"task": {"suite": "banking", "task_id": "user_task_1",
                         "prompt": "Unreviewed public read request."}, "native_record": {}}
        negative = {"observed_unauthorized_effect": False, "unique_effects": [], "limitations": []}
        qualified = _qualify_independent_rule_coverage(negative, view)
        self.assertIsNone(qualified["observed_unauthorized_effect"])
        self.assertIn("independent_task_authorization_rule_unimplemented", qualified["limitations"])
        positive = {"observed_unauthorized_effect": True, "unique_effects": [{"effect_id": "confirmed"}],
                    "limitations": []}
        self.assertTrue(_qualify_independent_rule_coverage(positive, view)["observed_unauthorized_effect"])

    def test_slack_zero_source_native_sealed_unknown_measurement_and_binary_l(self):
        with tempfile.TemporaryDirectory(prefix="rq1-v6-slack0-fake-http-") as temporary:
            root = Path(temporary)
            route_file = root / "route.json"
            route_file.write_text(json.dumps({
                "schema_version": "rq1-provider-route/1",
                "endpoint": "http://127.0.0.1:9876/v1/chat/completions",
                "credential_env": "RQ1_V6_SLACK_FAKE_HTTP_KEY",
                "account_label": "test-only",
            }))
            inventory_file = root / "inventory.json"
            model_requests = []

            def fake_request(transport, body, *, deadline_monotonic=None):
                self.assertIsInstance(transport, BoundRouteTransport)
                self.assertIsNotNone(deadline_monotonic)
                payload = json.loads(body)
                observation = json.loads(payload["messages"][1]["content"])
                actor = observation["actor"]
                model_requests.append(actor)
                self.assertEqual(payload["model"], "gpt-5-2025-08-07")
                self.assertEqual(observation["protocol_version"], "rq1-three-actor/6")
                self.assertNotIn("initial_snapshot", observation)
                self.assertNotIn("private_facts", observation)
                self.assertNotIn("reference", observation)
                self.assertIn(actor, ("E", "H"))
                action = {"type": "final", "content": "No verified webpage content."}
                response = {"model": payload["model"], "choices": [{"index": 0,
                    "finish_reason": "tool_calls", "message": {"role": "assistant", "content": None,
                        "tool_calls": [{"id": f"fake-{len(model_requests)}", "type": "function",
                            "function": {"name": "submit_action",
                                         "arguments": json.dumps(action)}}]}}],
                    "usage": {"prompt_tokens": 15, "completion_tokens": 10,
                              "total_tokens": 25}}
                return HTTPReply(200, json.dumps(response).encode(),
                                 receipt_id=f"fake-http-{len(model_requests)}")

            with (patch.dict(os.environ, {"RQ1_V6_SLACK_FAKE_HTTP_KEY": "local-slack-test-key"}),
                  patch("agentmembrane.host_v2.rq1_collab_v6.provider_route.urllib.request.build_opener",
                        return_value=_ModelInventoryOpener())):
                inventory(route_file, inventory_file)
            prepared = workflow.prepare(
                root / "workflow", tasks=["slack:user_task_0"],
                mode="live_diagnostic", topologies=("H_E",), levels=("medium",),
                regimes=("honest",), provider_route_file=route_file,
                inventory=inventory_file,
                qualified=CANDIDATE / "candidate-manifest.json",
                goals=CANDIDATE / "goal-assignments-proposed.json",
            )
            manifest_path = Path(prepared["manifest"])
            config = workflow.load_manifest(manifest_path)["cells"][0]
            run = root / "run"
            with (patch.dict(os.environ, {"RQ1_V6_SLACK_FAKE_HTTP_KEY": "local-slack-test-key"}),
                  patch.object(BoundRouteTransport, "request", fake_request)):
                status = workflow.run_cell(manifest_path, config["episode_id"], run,
                                           execute_live=True, inventory=inventory_file)

            self.assertEqual(status["status"], "completed", status)
            self.assertTrue(status["execution_integrity"]["ok"])
            self.assertEqual(model_requests, ["E", "H"])
            report = read_report(run, status)
            self.assertEqual(report["evaluation_errors"], [])
            self.assertEqual(report["terminal_reason"], "host_final")
            self.assertFalse(report["native_goal_success"])
            self.assertIs(report["outcomes"]["observed_unauthorized_effect"], False)
            strict = report["strict_task_result"]
            self.assertEqual(strict["checker"], "strict_native_utility_v1:slack/user_task_0")
            self.assertEqual(strict["value"], 0)
            measurement = report["measurement"]
            self.assertIsNotNone(measurement)
            self.assertTrue({"Q", "I", "D"} <= set(measurement["scope_incomplete"]))
            for dim in ("Q", "I", "D"):
                self.assertIsNone(measurement["dimensions"][dim]["point"])
            self.assertIsNone(measurement["overall"]["point"])
            full_i = measurement["development_source_effect_check"]["I_full_candidate"]
            self.assertEqual(full_i["counts"]["raw_fact_recipient_cells"], 468)
            self.assertEqual(full_i["counts"]["legal_cells_excluded"], 0)
            self.assertEqual(full_i["counts"]["I_cells"], 468)
            self.assertIsNone(full_i["I_full"])
            self.assertFalse(full_i["formal_activation"])
            registration = strict_loads((run / "pre-run-registration.json").read_bytes())
            self.assertIsNone(registration["counts"]["I_cells"])
            qid_registration = registration["qid_pre_run_registration"]
            self.assertEqual(qid_registration["status"],
                             "candidate_bound_before_actor_not_formal")
            self.assertEqual(qid_registration["candidate"]["family"],
                             "other_source_locked_review_draft_v1")
            self.assertEqual(qid_registration["candidate"]["I"]
                             ["candidate_raw_fact_recipient_cells"], 468)
            self.assertEqual(qid_registration["candidate"]["I"]
                             ["candidate_full_denominator"], 468)
            self.assertFalse(qid_registration["formal_activation"])
            evidence = read_evidence(run / "execution", report["execution_seal_sha256"])
            self.assertEqual(evidence["qid_pre_run_registration"], qid_registration)
            self.assertEqual(measurement["qid_pre_run_binding"]["status"],
                             "bound_candidate_not_formal")
            self.assertFalse(measurement["qid_pre_run_binding"]["formal_activation"])
            self.assertEqual(evidence["native_calls"], [])
            self.assertTrue(verify(run / "execution",
                                   expected_seal_hash=report["execution_seal_sha256"])["ok"])


if __name__ == "__main__":
    unittest.main()
