"""Campaign control-flow fixtures, never research tasks or paid model calls."""
import hashlib
import json
import os
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.rq1_collab_v1 import paired_campaign as campaign
from agentmembrane.host_v2.rq1_collab_v1.audit import canonical, file_hash


PROXY_SETTINGS_ENV = {
    campaign.legacy.PROXY_BASE_ENV: "http://127.0.0.1:19876/v1",
    campaign.legacy.PROXY_CONFIG_ENV: "/synthetic/not-read.yaml",
    campaign.legacy.PROXY_CREDENTIAL_ENV_ENV: "RQ1_SYNTHETIC_PROXY_KEY",
}


def put(path, value):
    path.write_bytes(canonical(value) + b"\n")


class PairedCampaignTests(unittest.TestCase):
    def setUp(self):
        self.proxy_settings_patch = patch.dict(os.environ, PROXY_SETTINGS_ENV)
        self.proxy_settings_patch.start()
        self.addCleanup(self.proxy_settings_patch.stop)
        self.directory = tempfile.TemporaryDirectory(prefix="paired-campaign-unit-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root / "upstream"
        self.source.mkdir()
        (self.source / "fixture.txt").write_text("synthetic source, not an admitted task")
        self.goal = {"schema_version": "rq1-public-native-goal/1", "source": "agentdojo",
            "suite": "workspace", "goal_id": "injection_task_1", "goal": "Unit public hostile goal",
            "goal_sha256": campaign._hash("Unit public hostile goal"), "benchmark_version": "v1",
            "source_file_sha256": "1" * 64, "class_source_sha256": "2" * 64,
            "checker_source_lock_sha256": "3" * 64}
        self.goal_patch = patch.object(campaign, "_goal_record", return_value=self.goal)
        self.goal_patch.start()
        self.addCleanup(self.goal_patch.stop)
        self.code_patch = patch.object(campaign, "source_lock", return_value={"unit-source": "4" * 64})
        self.code_patch.start()
        self.addCleanup(self.code_patch.stop)
        self.manifest, self.inventory = self.root / "qualified.json", self.root / "inventory.json"
        put(self.manifest, {"selection": [{"suite": suite, "task_id": task, "benchmark_version": "v1",
            "initial_state_sha256": "5" * 64} for suite, task in campaign.TASKS],
            "source_root": str(self.source), "native_python": "/synthetic/not-executed-python",
            "qualified_upstream_hashes": {"fixture.txt": file_hash(self.source / "fixture.txt")}})
        put(self.inventory, {"base_url": campaign.legacy.proxy_base(), "model_ids": ["unit-model"]})
        self.contract_path, self.release_path, self.output = self.root / "contract.json", self.root / "release.json", self.root / "run"

    def prepare(self, **options):
        campaign.prepare_paired(self.contract_path, self.manifest, self.inventory, "unit-model",
            [{"suite": "workspace", "task_id": "user_task_8", "goal_id": "injection_task_1"}],
            campaign_id="unit-registered-run", level_subset=("A0", "A4"), **options)
        self.contract = json.loads(self.contract_path.read_text())
        self.release = {"kind": "root_paired_campaign_release", "authorized_by": "root",
            "contract_sha256": file_hash(self.contract_path), "output_path": str(self.output),
            "code_hashes": self.contract["code_hashes"], "reviewed_evidence": [],
            **{key: self.contract[key] for key in ("schedule_sha256", "goal_records_sha256", "role_prompts_sha256")}}
        for kind in ("offline_regression", "nonauthor_review"):
            path = self.root / (kind + ".json")
            put(path, {"fixture_only": True, "kind": kind})
            self.release["reviewed_evidence"].append({"kind": kind, "path": str(path), "sha256": file_hash(path)})
        put(self.release_path, self.release)
        return self.contract

    def resave(self):
        put(self.contract_path, self.contract)
        self.release["contract_sha256"] = file_hash(self.contract_path)
        for key in ("schedule_sha256", "goal_records_sha256", "role_prompts_sha256"):
            self.release[key] = self.contract[key]
        put(self.release_path, self.release)

    def unit_row(self, root, item, contract):
        row = {**item, "status": "executed", "strict_utility": 0, "native_attack_success": 0,
            "risk_union": None, "formal_rq1_n": 0, "baseline_pass": False, "flow_valid": True,
            "bounded_outcomes": {"verified": True},
            "initial_hash": item["initial_state_sha256"], "audit": {"ok": True},
            "driver_failures": [], "runtime_unknown_reasons": [], "system_status": "closed",
            "drain": {"status": "settled", "inflight": []}, "model_lineage": {"ok": True, "completion_count": 1, "failed": []},
            "post_close_probe": {"fresh_reader": {"snapshot_matches": True}, "old_leases_accepted": {"H": False}},
            "model_budget_snapshot": {"halted": False, "actors": {"H": {"total_tokens": 10}}},
            "actual_model_requests": 1, "completed_model_generations": 1}
        campaign._write(root / "condition_results" / (item["episode_id"] + ".json"), row)
        return row

    def test_preassigned_pairs_ids_repeats_and_fixed_host(self):
        value = self.prepare(repetitions=2)
        rows = value["schedule"]
        self.assertEqual(len(rows), 18)
        for key in ("episode_id", "assignment_id"):
            self.assertEqual(len({row[key] for row in rows}), len(rows))
        self.assertEqual({row["repetition"] for row in rows}, {1, 2})
        for row in rows:
            self.assertEqual(row["seed"], value["seed"] + row["repetition"] - 1)
        self.assertEqual({row["role_prompts"]["H"] for row in rows}, {campaign.legacy.ROLE_PROMPTS["H"]})
        for row in rows:
            self.assertNotIn(self.goal["goal"], row["role_prompts"]["H"])
            if row["regime"] == "attack":
                partner = next(p for p in rows if p["pair_id"] == row["pair_id"] and p["regime"] == "clean")
                self.assertEqual(row["world_id"], partner["world_id"])
                self.assertIn(self.goal["goal"], row["role_prompts"]["E"])
                self.assertNotIn(self.goal["goal"], partner["role_prompts"]["E"])
        self.assertEqual(value["total_request_limit"], 18 * 40)
        campaign.check_paired_release(self.contract_path, self.release_path, self.output)

    def test_genuine_reference_failure_does_not_filter_any_comparison(self):
        value = self.prepare()
        with patch.object(campaign.legacy, "load_proxy_key", return_value="synthetic-key"), patch.object(campaign.legacy, "_condition", side_effect=self.unit_row) as condition:
            result = campaign.run_paired(self.contract_path, self.release_path, self.output)
        self.assertEqual(condition.call_count, len(value["schedule"]))
        self.assertEqual(result["not_run"], 0)
        self.assertEqual(result["executed"], 9)
        self.assertTrue(all(row["strict_utility"] == 0 for row in result["rows"]))
        self.assertIsNone(result["stopped_reason"])
        self.assertEqual(result["formal_rq1_n"], 0)

    def test_infrastructure_failure_records_every_pending_assignment(self):
        value = self.prepare()
        def broken(root, item, contract):
            row = self.unit_row(root, item, contract)
            row["audit"]["ok"] = False
            return row
        with patch.object(campaign.legacy, "load_proxy_key", return_value="synthetic-key"), patch.object(campaign.legacy, "_condition", side_effect=broken) as condition:
            result = campaign.run_paired(self.contract_path, self.release_path, self.output)
        self.assertEqual(condition.call_count, 1)
        self.assertEqual(len(result["rows"]), len(value["schedule"]))
        self.assertEqual(result["not_run"], 8)
        self.assertTrue(all(row["native_attack_success"] is None and row["strict_utility"] is None for row in result["rows"][1:]))
        self.assertEqual(len(list((self.output / "condition_results").glob("*.json"))), 9)

    def test_release_tamper_rejected_before_key_or_transport(self):
        self.prepare()
        self.release["contract_sha256"] = "0" * 64
        put(self.release_path, self.release)
        with patch.object(campaign.legacy, "load_proxy_key") as key, patch.object(campaign.legacy, "_condition") as condition:
            with self.assertRaises(ValueError):
                campaign.run_paired(self.contract_path, self.release_path, self.output)
            key.assert_not_called()
            condition.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_even_rehashed_host_prompt_tamper_is_rejected(self):
        self.prepare()
        self.contract["schedule"][0]["role_prompts"]["H"] = "changed host instructions"
        self.contract["schedule"][0]["role_prompts_sha256"] = campaign._hash(self.contract["schedule"][0]["role_prompts"])
        self.contract["schedule_sha256"] = campaign._hash(self.contract["schedule"])
        self.resave()
        with self.assertRaisesRegex(ValueError, "schedule_or_condition_prompt"):
            campaign.check_paired_release(self.contract_path, self.release_path, self.output)

    def test_native_goal_tamper_is_rejected_not_treated_as_new_public_goal(self):
        self.prepare()
        value = self.contract["goal_records"]["workspace/injection_task_1"]
        value["goal"] = "invented goal"
        value["goal_sha256"] = campaign._hash(value["goal"])
        self.contract["goal_records_sha256"] = campaign._hash(self.contract["goal_records"])
        self.resave()
        with self.assertRaisesRegex(ValueError, "public_goal_changed"):
            campaign.check_paired_release(self.contract_path, self.release_path, self.output)

    def test_source_and_review_evidence_tampering_fail_preflight(self):
        self.prepare()
        (self.source / "fixture.txt").write_text("changed source")
        with self.assertRaises(RuntimeError):
            campaign.check_paired_release(self.contract_path, self.release_path, self.output)
        (self.source / "fixture.txt").write_text("synthetic source, not an admitted task")
        Path(self.release["reviewed_evidence"][0]["path"]).write_text("changed review")
        with self.assertRaisesRegex(ValueError, "reviewed_evidence_changed"):
            campaign.check_paired_release(self.contract_path, self.release_path, self.output)

    def test_duplicate_episode_or_assignment_ids_rejected_after_rehash(self):
        self.prepare()
        self.contract["schedule"][1]["episode_id"] = self.contract["schedule"][0]["episode_id"]
        self.contract["schedule_sha256"] = campaign._hash(self.contract["schedule"])
        self.resave()
        with self.assertRaises(ValueError):
            campaign.check_paired_release(self.contract_path, self.release_path, self.output)

    def test_same_release_cannot_run_twice_or_move_output(self):
        self.prepare()
        with self.assertRaisesRegex(ValueError, "output_path_mismatch"):
            campaign.check_paired_release(self.contract_path, self.release_path, self.root / "other")
        with patch.object(campaign.legacy, "load_proxy_key", return_value="synthetic-key"), patch.object(campaign.legacy, "_condition", side_effect=self.unit_row):
            campaign.run_paired(self.contract_path, self.release_path, self.output)
        with patch.object(campaign.legacy, "load_proxy_key") as key:
            with self.assertRaises(FileExistsError):
                campaign.run_paired(self.contract_path, self.release_path, self.output)
            key.assert_not_called()

    def test_credential_failure_records_all_cells_without_spending(self):
        self.prepare()
        credential_env = campaign.legacy.proxy_credential_env()
        with patch.dict(os.environ, {credential_env: "synthetic-previous-key"}), patch.object(campaign.legacy, "load_proxy_key", side_effect=ValueError("not logged secret")), patch.object(campaign.legacy, "_condition") as condition:
            result = campaign.run_paired(self.contract_path, self.release_path, self.output)
            self.assertEqual(os.environ[credential_env], "synthetic-previous-key")
            condition.assert_not_called()
        self.assertEqual(result["not_run"], 9)
        self.assertEqual(result["actual_model_requests"], 0)
        self.assertNotIn("not logged secret", json.dumps(result))

    def test_exception_retains_unknown_spend_and_all_pending(self):
        self.prepare()
        with patch.object(campaign.legacy, "load_proxy_key", return_value="synthetic-key"), patch.object(campaign.legacy, "_condition", side_effect=OSError("unit secret exception")):
            result = campaign.run_paired(self.contract_path, self.release_path, self.output)
        self.assertEqual(result["failed"], 1)
        self.assertEqual(result["not_run"], 8)
        self.assertTrue(result["request_count_unknown"])
        self.assertIsNone(result["rows"][0]["actual_model_requests"])
        self.assertEqual(result["reserved_request_bound"], 40)
        self.assertNotIn("unit secret exception", json.dumps(result))

    def test_bounded_options_reject_expansion_and_unsupported_levels(self):
        with self.assertRaises(ValueError):
            campaign._options("../escape", 1, True, ["A0"])
        with self.assertRaises(ValueError):
            campaign._options("valid", 4, True, ["A0"])
        with self.assertRaises(ValueError):
            campaign._options("valid", 1, True, ["A2"])
        with self.assertRaises(ValueError):
            campaign._assignments([{"suite": "workspace", "task_id": "user_task_999", "goal_id": "injection_task_1"}])

    def test_seeded_order_reproducible_but_pair_ids_do_not_depend_on_order(self):
        value = self.prepare()
        first = campaign._schedule(value)
        self.assertEqual(first, campaign._schedule(value))
        second = campaign._copy(value)
        second["ordering_seed"] += 1
        shuffled = campaign._schedule(second)
        self.assertEqual(first[0]["regime"], "reference")
        self.assertNotEqual([row["episode_id"] for row in first], [row["episode_id"] for row in shuffled])
        self.assertEqual({row["episode_id"] for row in first}, {row["episode_id"] for row in shuffled})
        self.assertEqual({row["pair_id"] for row in first}, {row["pair_id"] for row in shuffled})

    def test_missing_bounded_artifact_verification_stops_not_goal_zero(self):
        self.prepare()
        def broken(root, item, contract):
            row = self.unit_row(root, item, contract)
            row["bounded_outcomes"]["verified"] = False
            return row
        with patch.object(campaign.legacy, "load_proxy_key", return_value="synthetic-key"), patch.object(campaign.legacy, "_condition", side_effect=broken):
            result = campaign.run_paired(self.contract_path, self.release_path, self.output)
        self.assertEqual(result["not_run"], 8)

    def test_wall_budget_stops_with_all_pending_in_summary(self):
        self.prepare()
        with patch.object(campaign.legacy, "load_proxy_key", return_value="synthetic-key"), patch.object(campaign.legacy, "_condition", side_effect=self.unit_row) as condition, patch.object(campaign.time, "monotonic", side_effect=[0, 0, 7000, 7000]):
            result = campaign.run_paired(self.contract_path, self.release_path, self.output)
        self.assertEqual(condition.call_count, 1)
        self.assertEqual(result["not_run"], 8)
        self.assertEqual(result["stopped_reason"], "insufficient_remaining_wall_budget")

    def test_real_native_goal_record_prepares_without_credentials_or_model(self):
        project = Path(__file__).resolve().parents[2]
        old = project / "experiments/host_boundary_v2/rq1_collab_v1/live_readiness_20260907/root_inputs/live_contract_004.json"
        settings = json.loads(old.read_text())
        python = Path(settings["native_python"])
        packages = python.parent.parent / "lib/python3.12/site-packages"
        script = '''import sys,json,tempfile
from pathlib import Path
sys.path[:0] = [sys.argv[1],sys.argv[2]]
from unittest.mock import patch
from agentmembrane.host_v2.rq1_collab_v1 import paired_campaign as c
old=json.loads(Path(sys.argv[3]).read_text())
record=c._goal_record(old["source_root"],"workspace","injection_task_1","v1")
assert c._validate_goal(record,"workspace","injection_task_1")==record
assert record["goal_sha256"]==c._hash(record["goal"])
with tempfile.TemporaryDirectory(prefix="paired-real-source-prepare-") as d:
 with patch.object(c.legacy,"load_proxy_key",side_effect=AssertionError("credentials forbidden")):
  out=Path(d)/"contract.json"
  result=c.prepare_paired(out,old["qualified_manifest_path"],old["inventory_path"],old["model_profile"]["model"],
   [{"suite":"workspace","task_id":"user_task_8","goal_id":"injection_task_1"}],campaign_id="native-source-unit",level_subset=["A0","A4"])
  prepared=json.loads(out.read_text())
  assert prepared["goal_records"]["workspace/injection_task_1"]==record
  assert len(prepared["schedule"])==9
print(json.dumps({"native_goal_record_valid":True,"prepared_conditions":9,"model_calls":0,"root_release_created":False}))
'''
        result = subprocess.run([str(python), "-I", "-S", "-c", script, str(project), str(packages), str(old)],
            capture_output=True, timeout=60, env={"PYDANTIC_DISABLE_PLUGINS": "__all__"})
        self.assertEqual(result.returncode, 0, result.stderr.decode()[-1500:])
        facts = json.loads(result.stdout.decode().splitlines()[-1])
        self.assertTrue(facts["native_goal_record_valid"])
        self.assertEqual(facts["prepared_conditions"], 9)
        self.assertEqual(facts["model_calls"], 0)


if __name__ == "__main__":
    unittest.main()
