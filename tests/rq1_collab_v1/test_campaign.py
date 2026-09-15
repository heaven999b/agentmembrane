"""Engineering fixtures only: none of these count as empirical RQ1 episodes."""
from __future__ import annotations

import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.rq1_collab_v1.audit import EventCollector, canonical, sha256, strict_loads, verify
from agentmembrane.host_v2.rq1_collab_v1.campaign import allocate_attempt, plan_panel, preflight
from agentmembrane.host_v2.rq1_collab_v1.cli import main


def engineering_task(index=0):
    """Synthetic schema fixture, not a public task admission certificate."""
    return {"task_id": f"fixture-{index}", "source": "AgentDojo", "suite": "workspace",
            "original_id": f"fixture-{index}", "group_id": "fixture-group", "world_id": "fixture-world",
            "admission_status": "admitted", "task_bundle_hash": "a" * 64,
            "initial_state_hash": "b" * 64, "task_authorization_hash": "c" * 64,
            "eligible_goals": [{"goal_id": "fixture-goal", "public_goal_hash": "d" * 64,
                                "eligibility_status": "admitted", "target_exists": True,
                                "initially_satisfied": False, "conflicts_with_user_intent": True}]}


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def make_collector(self, name="run"):
        collector = EventCollector(self.root / name, "episode-one")
        self.addCleanup(collector.abort)
        return collector

    def test_event_chain_seal_and_tamper(self):
        collector = self.make_collector()
        collector.emit("native_enter", {"tool": "search", "observed": True}, actor="E", session="s1", call="c1", permit_epoch=1)
        collector.emit("native_commit", {"effects": []}, actor="E", parent_ids=["episode-one:1"])
        seal = collector.seal({"termination": "host_final", "coverage": "engineering_only"})
        result = verify(collector.run_dir, expected_seal_hash=seal["seal_hash"])
        self.assertTrue(result["ok"], result)
        self.assertFalse(result["semantic_completeness_proven"])
        events = collector.run_dir / "events.jsonl"
        events.write_bytes(events.read_bytes().replace(b"search", b"altered"))
        self.assertFalse(verify(collector.run_dir)["ok"])

    def test_extra_artifact_and_wrong_external_anchor_fail(self):
        collector = self.make_collector()
        collector.seal({})
        self.assertFalse(verify(collector.run_dir, expected_seal_hash="f" * 64)["ok"])
        (collector.run_dir / "late.json").write_text("{}")
        self.assertFalse(verify(collector.run_dir)["ok"])

    def test_single_writer_existing_attempt_and_post_seal_rejected(self):
        collector = self.make_collector()
        with self.assertRaises(FileExistsError):
            EventCollector(collector.run_dir, "another")
        collector.seal({})
        with self.assertRaises(RuntimeError):
            collector.emit("late", {})

    def test_reserved_identity_and_nonfinite_rejected(self):
        collector = self.make_collector()
        with self.assertRaises(ValueError):
            collector.emit("spoof", {}, episode_id="other")
        with self.assertRaises(ValueError):
            collector.emit("bad", {"value": float("nan")})
        with self.assertRaises(ValueError):
            strict_loads('{"same":1,"same":2}')

    def test_request_preserves_exact_serialized_body_and_status(self):
        collector = self.make_collector()
        payload = b'{ "model" : "fixture", "messages": [{"role":"system","content":"temporary reminder"}] }'
        profile = {"model": "fixture", "backend": "never_called"}
        collector.record_model_request("r1", payload, status="prepared_only", actor="H", model_profile=profile)
        collector.record_model_request("r1", payload, status="delivery_unknown", actor="H", model_profile=profile)
        collector.record_model_request("r1", payload, status="delivered", actor="H", model_profile=profile,
                                       receipt={"acceptance_evidence": {"response_hash": "a" * 64, "http_status": 200}})
        self.assertEqual((collector.run_dir / "model_requests/r1.body.json").read_bytes(), payload)
        with self.assertRaises(ValueError):
            collector.record_model_request("r1", payload, status="prepared_only", actor="H", model_profile=profile)
        seal = collector.seal({})
        self.assertTrue(verify(collector.run_dir)["ok"])
        final = strict_loads((collector.run_dir / "events.jsonl").read_bytes().splitlines()[-1])
        self.assertEqual(final["data"]["model_request_terminal_status"], {"r1": "delivered"})

    def test_request_no_header_secret_or_unprepared_delivery(self):
        collector = self.make_collector()
        for payload in (b'{"api_key":"secret"}', b'{"headers":{"Authorization":"secret"}}', b'{"model":"x","model":"y"}'):
            with self.assertRaises(ValueError):
                collector.record_model_request("r1", payload, status="prepared_only", actor="E", model_profile={"model": "fixture"})
        with self.assertRaises(ValueError):
            collector.record_model_request("r1", b'{}', status="delivered", actor="E", model_profile={"model": "fixture"}, receipt={"acceptance_evidence": "fixture"})

    def test_raw_numeric_exponent_overflow_rejected_before_recording(self):
        collector = self.make_collector()
        for token in ("1e999", "-1e999", "1.8e308"):
            payload = ('{"outer":{"value":' + token + '}}').encode("utf-8")
            with self.subTest(token=token):
                with self.assertRaises(ValueError):
                    strict_loads(payload)
                with self.assertRaises(ValueError):
                    collector.record_model_request("overflow", payload, status="prepared_only",
                                                   actor="E", model_profile={"model": "fixture"})
                self.assertFalse((collector.run_dir / "model_requests/overflow.body.json").exists())
        self.assertEqual(strict_loads(b'{"finite":1e100}'), {"finite": 1e100})

    def test_request_changed_body_and_unsupported_receipt_rejected(self):
        collector = self.make_collector()
        profile = {"model": "fixture"}
        collector.record_model_request("r1", b'{}', status="prepared_only", actor="E", model_profile=profile)
        with self.assertRaises(ValueError):
            collector.record_model_request("r1", b'{"changed":true}', status="delivery_unknown", actor="E", model_profile=profile)
        with self.assertRaises(ValueError):
            collector.record_model_request("r1", b'{}', status="delivered", actor="E", model_profile=profile, receipt={})

    def test_unsealed_failed_attempt_is_invalid_but_retained(self):
        collector = self.make_collector()
        collector.emit("failure", {"effects": "unknown"})
        collector.abort()
        self.assertFalse(verify(collector.run_dir)["ok"])
        self.assertTrue((collector.run_dir / "events.jsonl").exists())

    def test_artifact_symlink_rejected(self):
        collector = self.make_collector()
        (collector.run_dir / "snapshots" / "escape").symlink_to(self.root)
        with self.assertRaises(ValueError):
            collector.seal({})


class CampaignTests(unittest.TestCase):
    def test_matched_deterministic_draws_and_independent_identities(self):
        args = dict(n=20, master_seeds=[11, 22, 33], protocol_hash="0" * 64, campaign_id="fixture")
        plan = plan_panel([engineering_task(0), engineering_task(1)], **args)
        self.assertEqual(plan, plan_panel([engineering_task(0), engineering_task(1)], **args))
        self.assertEqual(plan["planned_episode_count"], 320)
        self.assertEqual(plan["unique_group_count"], 1)
        self.assertEqual(plan["unique_world_count"], 1)
        self.assertEqual(len({row["execution_id"] for row in plan["rows"]}), 320)
        self.assertEqual(len({value for row in plan["rows"] for value in row["actor_sessions"].values()}), 640)
        for draw in plan["draws"]:
            siblings = [row for row in plan["rows"] if row["pair_id"] == draw["pair_id"]]
            self.assertEqual(len(siblings), 16)
            self.assertEqual(len({row["task_id"] for row in siblings}), 1)
            self.assertEqual(len({row["goal_id"] for row in siblings}), 1)
            self.assertEqual(len({row["seed"] for row in siblings}), 1)
            self.assertEqual(len({row["initial_state_hash"] for row in siblings}), 1)

    def test_duplicate_unadmitted_goal_and_wrong_panel_rejected(self):
        args = dict(n=3, master_seeds=[1, 2, 3], protocol_hash="a" * 64, campaign_id="fixture")
        with self.assertRaises(ValueError):
            plan_panel([engineering_task(), engineering_task()], **args)
        task = engineering_task()
        task["admission_status"] = "pending"
        with self.assertRaises(ValueError):
            plan_panel([task], **args)
        task = engineering_task()
        task["eligible_goals"][0]["initially_satisfied"] = True
        with self.assertRaises(ValueError):
            plan_panel([task], **args)
        with self.assertRaises(ValueError):
            plan_panel([engineering_task()], panel="U", **args)

    def test_retry_preserves_failed_attempt_and_statistical_identity(self):
        plan = plan_panel([engineering_task()], n=1, master_seeds=[1, 2, 3], protocol_hash="a" * 64, campaign_id="fixture")
        with tempfile.TemporaryDirectory() as temp:
            row = plan["rows"][0]
            first = allocate_attempt(temp, row)
            collector = EventCollector(first["run_dir"], row["episode_id"])
            collector.emit("unknown", {"termination": "transport_error"})
            collector.abort()
            prior_bytes = (Path(first["run_dir"]) / "events.jsonl").read_bytes()
            second = allocate_attempt(temp, row, previous_attempt=first["run_dir"])
            self.assertNotEqual(first["run_dir"], second["run_dir"])
            self.assertFalse(second["manifest"]["counts_as_new_independent_draw"])
            self.assertFalse(second["manifest"]["previous_attempt"]["verification"]["ok"])
            self.assertEqual((Path(first["run_dir"]) / "events.jsonl").read_bytes(), prior_bytes)
            changed = {**row, "level": "A4"}
            with self.assertRaises(ValueError):
                allocate_attempt(temp, changed, previous_attempt=first["run_dir"])

    def test_formal_flags_and_linux_name_cannot_bypass_isolation(self):
        with patch("agentmembrane.host_v2.rq1_collab_v1.campaign.platform.system", return_value="Linux"):
            result = preflight({"mode": "formal", "verified": True,
                                "isolation": {"verified": True}, "gates": {"containment": {"verified": True}}})
        self.assertFalse(result["ok"])
        self.assertFalse(result["formal_ready"])
        self.assertIn("containment:no_reviewed_live_three_domain_launcher_registered", result["errors"])
        self.assertIn("admission:missing_content_addressed_reference", result["errors"])
        self.assertIn("budget:missing", result["errors"])

    def test_offline_requires_zero_budget_and_no_generated_code(self):
        good = {"mode": "offline_native", "model_requests_budget": 0, "network_requests_budget": 0}
        self.assertTrue(preflight(good)["ok"])
        self.assertFalse(preflight({**good, "execute_untrusted_code": True})["ok"])
        self.assertFalse(preflight({**good, "model_requests_budget": 1})["ok"])
        self.assertFalse(preflight({"mode": "engineering"})["ok"])

    def test_cli_preflight_emits_real_sealed_result(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = root / "config.json"
            config.write_bytes(canonical({"mode": "formal"}))
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                code = main(["preflight", str(config), "--evidence-dir", str(root / "evidence")])
            self.assertEqual(code, 2)
            result = strict_loads(stream.getvalue())
            self.assertFalse(result["ok"])
            self.assertTrue(verify(root / "evidence", expected_seal_hash=result["evidence_seal_hash"])["ok"])


if __name__ == "__main__":
    unittest.main()
