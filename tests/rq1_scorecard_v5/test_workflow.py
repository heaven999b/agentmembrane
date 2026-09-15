"""Actual sealed engineering panel, never a claim of behavioral validation."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.rq1_scorecard_v5.core import DIMENSIONS, digest
from agentmembrane.host_v2.rq1_scorecard_v5 import workflow

PROJECT = Path(__file__).resolve().parents[2]
PANEL = PROJECT / "experiments/host_boundary_v2/rq1_collab_v1/live_readiness_20260907/pilots/rq1_three_actor_implementation_20260909_revision2"
MANIFEST = PANEL / "workflow/run-manifest.json"


@unittest.skipUnless(MANIFEST.is_file(), "sealed development panel unavailable")
class WorkflowTests(unittest.TestCase):
    def test_sealed48_end_to_end_no_network(self):
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp)/"scores"
            with patch("agentmembrane.host_v2.rq1_scorecard_v5.judge_provider.JudgePool", side_effect=AssertionError("offline must not initialize transport")):
                result=workflow.run(MANIFEST,PANEL/"runs",output)
            self.assertEqual(result["assigned_episodes"],48)
            self.assertEqual(result["scored_episodes"],48)
            self.assertFalse(result["failures"])
            self.assertEqual(result["dimensions_with_point_scores"],dict(Q=48,I=0,D=48,M=0,K=0,C=0))
            self.assertEqual(result["full_six_dimension_point_scores"],0)
            self.assertEqual(result["episodes_with_critical_incident"],8)
            self.assertEqual(result["matched_contrast_count"],96)
            self.assertEqual(result["scored_contrast_count"],96)
            self.assertEqual(result["model_calls"],0)
            self.assertEqual(result["behavioral_episode_count"],0)
            self.assertEqual(result["independent_world_count"],1)
            self.assertTrue(result["all_allocations_accounted_for"])
            rows=json.loads((output/"condition-summary.json").read_bytes())["conditions"]
            self.assertEqual(len(rows),12)
            for row in rows:
                self.assertEqual(row["assigned"],4)
                self.assertIsNone(row["overall"]["point"])
                if row["regime"]=="honest":
                    self.assertEqual(row["dimensions"]["Q"]["point"],100)
                    self.assertEqual(row["dimensions"]["D"]["point"],100)
                if row["regime"]=="malicious" and row["level"]=="high":
                    self.assertAlmostEqual(row["dimensions"]["D"]["point"],43.4593023255814)
                for dim in "IMKC":
                    self.assertEqual(row["dimensions"][dim],dict(lower=0,upper=100,point=None))

    def test_missing_runs_keep_every_allocation_and_pair_unknown(self):
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp)/"scores"
            result=workflow.run(MANIFEST,Path(temp)/"missing-runs",output)
            self.assertEqual(result["scored_episodes"],0)
            self.assertEqual(len(result["failures"]),48)
            self.assertEqual(result["matched_contrast_count"],96)
            self.assertEqual(result["scored_contrast_count"],0)
            self.assertTrue(result["all_allocations_accounted_for"])
            for row in json.loads((output/"condition-summary.json").read_bytes())["conditions"]:
                self.assertEqual(row["overall"],dict(lower=0,upper=100,point=None))
                self.assertEqual(row["native_endpoints"]["native_task_success"]["unknown"],4)

    def test_scoring_failure_preserves_verified_original_endpoints(self):
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp)/"scores"
            with patch.object(workflow,"evaluate",side_effect=ValueError("deliberate_engineering_failure")):
                result=workflow.run(MANIFEST,PANEL/"runs",output)
            self.assertEqual(len(result["failures"]),48)
            self.assertTrue(all("native_task_success" in f["verified_original_scores"] for f in result["failures"]))
            for row in json.loads((output/"condition-summary.json").read_bytes())["conditions"]:
                self.assertEqual(row["native_endpoints"]["native_task_success"]["unknown"],0)
                self.assertIsNone(row["overall"]["point"])

    def test_refuses_overwrite_and_execution_tree_output(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(FileExistsError):
                workflow.run(MANIFEST,PANEL/"runs",Path(temp))
        with self.assertRaisesRegex(ValueError,"outside_execution_runs"):
            workflow.run(MANIFEST,PANEL/"runs",PANEL/"runs"/"unwanted")

    def test_explicit_judge_enablement_required_before_any_output(self):
        for options in ({"judge_config_path":"not-a-file"},{"execute_judges":True},
                        {"inventory_path":"not-a-file"}):
            with tempfile.TemporaryDirectory() as temp:
                output=Path(temp)/"should-not-exist"
                with self.assertRaises(ValueError):
                    workflow.run(MANIFEST,PANEL/"runs",output,**options)
                self.assertFalse(output.exists())

    def test_tampered_or_incomplete_matrix_rejected(self):
        original=json.loads(MANIFEST.read_bytes())
        for rehash in (False,True):
            manifest=copy.deepcopy(original)
            manifest["cells"].pop()
            if rehash:
                manifest["condition_count"]-=1
                manifest["manifest_sha256"]=digest({k:v for k,v in manifest.items() if k!="manifest_sha256"})
            with tempfile.TemporaryDirectory() as temp:
                path=Path(temp)/"manifest.json"
                workflow.write(path,manifest)
                with self.assertRaises(ValueError):
                    workflow.load_history(path)

    def test_partial_equal_bounds_do_not_manufacture_complete_point(self):
        cells=[dict(episode_id="only",topology="H_E",level="low",regime="honest")]
        report={"dimensions":{d:dict(lower=0,upper=0,point=None) for d in DIMENSIONS},
                "overall":dict(lower=0,upper=0,point=None)}
        row=workflow.aggregate(cells,{"only":report},[])["conditions"][0]
        self.assertIsNone(row["overall"]["point"])
        self.assertTrue(all(v["point"] is None for v in row["dimensions"].values()))

    def test_no_detected_effect_never_becomes_verified_zero_global_risk(self):
        cells=[dict(episode_id="only",topology="H_E",level="low",regime="honest")]
        report={"dimensions":{d:dict(lower=0,upper=100,point=None) for d in DIMENSIONS},
                "overall":dict(lower=0,upper=100,point=None),"auxiliary_outcomes":{"observed_unauthorized_effect":False}}
        risk=workflow.aggregate(cells,{"only":report},[])["conditions"][0]["native_endpoints"]["observed_unauthorized_effect"]
        self.assertEqual((risk["lower"],risk["upper"],risk["unknown"]),(0,1,1))
        report["auxiliary_outcomes"]["observed_unauthorized_effect"]=True
        risk=workflow.aggregate(cells,{"only":report},[])["conditions"][0]["native_endpoints"]["observed_unauthorized_effect"]
        self.assertEqual((risk["lower"],risk["upper"],risk["unknown"]),(1,1,0))

    def test_launcher_defaults_new_scores_and_preserves_v4(self):
        script=(PROJECT/"run_rq1_three_actor.sh").read_text()
        self.assertIn('"${1:-}" == "score"',script)
        self.assertIn('RQ1_MODULE="agentmembrane.host_v2.rq1_scorecard_v5"',script)
        self.assertIn('"${1:-}" == "score-v4"',script)

    def test_judge_invocations_survive_later_scoring_failure(self):
        from agentmembrane.host_v2.rq1_scorecard_v5.semantic import judge_field
        judges=[dict(id=name,model="mock",complete=lambda packet: {"value":True}) for name in ("a","b")]
        def fail_after_six(data,*,semantic_judges):
            judge_field({"instructions":"mock engineering test"},semantic_judges,lambda x:x)
            raise ValueError("deliberate_engineering_failure_after_six")
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp)/"scores"
            with patch.object(workflow,"evaluate",side_effect=fail_after_six):
                result=workflow.run(MANIFEST,PANEL/"runs",output,semantic_judges=judges)
            self.assertEqual(result["semantic_completion_invocations"],48*6)
            self.assertEqual(result["semantic_invocations_in_successful_reports"],0)
            self.assertEqual(len(list((output/"semantic-calls").glob("*.result.json"))),48*6)
            self.assertIsNone(result["model_calls"])


if __name__=="__main__":
    unittest.main()
