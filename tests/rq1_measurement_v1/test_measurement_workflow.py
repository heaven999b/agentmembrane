"""Workflow plumbing over original public source; outputs are test controls.

Injected callbacks here are not LLM data or independent calibration samples.
"""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.rq1_collab_v1.audit import file_hash, strict_loads
from agentmembrane.host_v2.rq1_measurement_v1.pipeline import evaluate
from agentmembrane.host_v2.rq1_measurement_v1.workflow import run_score
from tests.rq1_measurement_v1 import test_pipeline as pipeline_tests
from tests.rq1_collab_v3.test_runtime_evaluation import Script, final


class ScoringWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pipeline_tests.PipelineTests.setUpClass()
        cls.helper = pipeline_tests.PipelineTests("test_native_runtime_sealed_end_to_end_no_fake_six_dim_point")
        cls.data, capture, _, _, collector = cls.helper.run_case(task="workspace/user_task_26",
            script=Script(E=[final()], H=[final("Engineering free text without a complete file claim.")]))
        cls.source_run, cls.seal = collector.run_dir, capture["seal"]["seal_hash"]
        cls.mechanical = evaluate(cls.data)
    @classmethod
    def tearDownClass(cls):
        cls.helper.doCleanups()
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name)/"score.json"

    def test_default_has_actual_applicability_no_fake_votes(self):
        status = run_score(self.source_run, self.seal, self.output)
        self.assertEqual(status["model_calls"], 0)
        self.assertEqual(status["completion_invocations"], 0)
        self.assertEqual(status["status"], "applicability_only_no_judges")
        report = strict_loads(self.output.read_bytes())
        self.assertEqual(report["overall"], self.mechanical["overall"])
        self.assertEqual(report["dimensions"], self.mechanical["dimensions"])
        self.assertEqual(report["measurement_quality"]["format_sensitivity"]["status"], "NOT_RUN")
        self.assertTrue((Path(status["audit_dir"])/"calibration-lock.json").is_file())

    def test_lock_persisted_before_all_twelve_callbacks(self):
        hashes, phases = [], []
        audit_dir = self.output.with_name(self.output.name+".audit")
        def complete(packet):
            hashes.append(file_hash(audit_dir/"calibration-lock.json"))
            self.assertTrue((audit_dir/"semantic-plan.json").is_file())
            self.assertTrue((audit_dir/"mechanical-score-before-judges.json").is_file())
            phases.append(packet["phase"])
            return {"complete_or_ambiguous": "ambiguous", "fields": []}
        judges = [{"id": "fixture-a", "model": "fixture-a", "complete": complete},
                  {"id": "fixture-b", "model": "fixture-b", "complete": complete}]
        status = run_score(self.source_run, self.seal, self.output, semantic_judges=judges, match=True)
        self.assertEqual(status["completion_invocations"], 12)
        self.assertEqual(phases.count("extract"), 6)
        self.assertEqual(phases.count("match"), 6)
        self.assertEqual(len(set(hashes)), 1)
        report = strict_loads(self.output.read_bytes())
        self.assertEqual(report["overall"], self.mechanical["overall"])
        self.assertFalse(report["measurement_quality"]["semantic_accuracy_certified"])

    def test_judge_exceptions_leave_slots_unknown_no_score_upgrade(self):
        calls = []
        def failed(packet):
            calls.append(packet)
            raise TimeoutError("PRIVATE-TEST-ERROR")
        judges = [{"id": "fixture-a", "model": "fixture-a", "complete": failed},
                  {"id": "fixture-b", "model": "fixture-b", "complete": failed}]
        status = run_score(self.source_run, self.seal, self.output, semantic_judges=judges)
        self.assertEqual(len(calls), 6)
        audit = strict_loads((Path(status["audit_dir"])/"semantic-audit.json").read_bytes())
        votes = next(r for r in audit["rows"] if r["field_type"] == "filename_claim")["phases"]["extract"]["votes"]
        self.assertEqual(sum(v["status"] == "invalid_or_failed" for v in votes), 6)
        self.assertNotIn("PRIVATE-TEST-ERROR", json.dumps(audit))
        self.assertEqual(strict_loads(self.output.read_bytes())["overall"], self.mechanical["overall"])

    def test_sealed_source_and_existing_output_cannot_be_overwritten(self):
        with self.assertRaisesRegex(ValueError, "outside_sealed"):
            run_score(self.source_run, self.seal, self.source_run/"new-score.json")
        run_score(self.source_run, self.seal, self.output)
        original = file_hash(self.output)
        with self.assertRaises(FileExistsError):
            run_score(self.source_run, self.seal, self.output)
        self.assertEqual(file_hash(self.output), original)

    def test_opt_in_cannot_be_inferred_from_config(self):
        with self.assertRaisesRegex(ValueError, "config_flag_and_inventory"):
            run_score(self.source_run, self.seal, self.output, judge_config_path="not-read.json")

    def test_audit_error_preserves_mechanical_report_and_marks_failure(self):
        with patch("agentmembrane.host_v2.rq1_measurement_v1.semantic_audit.execute_audit", side_effect=ValueError("PRIVATE-TEST-ERROR")):
            status = run_score(self.source_run, self.seal, self.output)
        self.assertEqual(status["status"], "needs_review")
        self.assertEqual(strict_loads(self.output.read_bytes())["overall"], self.mechanical["overall"])
        self.assertNotIn("PRIVATE-TEST-ERROR", json.dumps(status))


if __name__ == "__main__":
    unittest.main()
