"""Endpoint semantics that the original native utility cannot express."""
import unittest

from agentmembrane.host_v2.rq1_collab_v6.paired_v2 import (
    UNKNOWN, _formal_dimension_point, _formal_endpoint_gate, _q, _strict_task, conjunction,
)
from agentmembrane.host_v2.rq1_collab_v1.native import STRICT_WORKSPACE8_CLASS_HASH
from agentmembrane.host_v2.rq1_collab_v1.pilot_checkers import (
    UTILITY_FILE_LOCKS, UTILITY_SOURCE_LOCKS,
)


class PairedV2EndpointTests(unittest.TestCase):
    def setUp(self):
        self.source = {"suite": "workspace", "task_id": "user_task_35",
                       "class_source_sha256": "a" * 64}
        self.strict = {"checker": "strict_profile_v2:workspace/user_task_35",
                       "source_lock": "a" * 64,
                       "answer_protocol": "source_fact_semantics_v2",
                       "unrelated_harms_scored_separately": True, "value": 1}

    def test_strict_and_native_utility_may_disagree(self):
        self.assertIs(_strict_task({"strict_task_result": self.strict,
                                    "analysis_endpoints": {"native_task_success": False}}, self.source), True)
        self.assertEqual(_strict_task({}, self.source), UNKNOWN)
        with self.assertRaisesRegex(ValueError, "strict_checker_source_lock_mismatch"):
            _strict_task({"strict_task_result": {**self.strict, "source_lock": "b" * 64}}, self.source)
        with self.assertRaisesRegex(ValueError, "strict_checker_harm_separation_required"):
            _strict_task({"strict_task_result": {**self.strict,
                                                 "unrelated_harms_scored_separately": False}}, self.source)

    def test_legacy_workspace8_checker_is_bound_by_class_hash(self):
        source = {"suite": "workspace", "task_id": "user_task_8",
                  "class_source_sha256": STRICT_WORKSPACE8_CLASS_HASH}
        strict = {"checker": "strict_workspace_UserTask8_v1",
                  "unrelated_harms_scored_separately": True, "value": 1}
        self.assertIs(_strict_task({"strict_task_result": strict}, source), True)
        with self.assertRaisesRegex(ValueError, "strict_legacy_checker_or_source_mismatch"):
            _strict_task({"strict_task_result": strict}, {**source, "class_source_sha256": "b" * 64})

    def test_expanded_native_utility_checker_requires_registered_source(self):
        suite, task_id = "banking", "user_task_1"
        class_hash, prompt_hash = UTILITY_SOURCE_LOCKS[(suite, task_id)]
        source = {"suite": suite, "task_id": task_id, "benchmark_version": "v1",
                  "class_source_sha256": class_hash, "prompt_sha256": prompt_hash,
                  "source_file_sha256": UTILITY_FILE_LOCKS[suite]}
        strict = {"checker": f"strict_native_utility_v1:{suite}/{task_id}",
                  "source_lock": class_hash,
                  "unrelated_harms_scored_separately": True, "value": 1}
        self.assertIs(_strict_task({"strict_task_result": strict}, source), True)
        with self.assertRaisesRegex(ValueError, "strict_native_utility_source_not_registered"):
            _strict_task({"strict_task_result": strict},
                         {**source, "prompt_sha256": "b" * 64})
        with self.assertRaisesRegex(ValueError, "strict_checker_source_lock_mismatch"):
            _strict_task({"strict_task_result": {**strict, "source_lock": "b" * 64}}, source)

    def test_unimplemented_strict_checker_is_unknown(self):
        self.assertEqual(_strict_task({"strict_task_result": {
            "value": None, "reason": "strict_checker_not_implemented_for_this_task"}},
            self.source), UNKNOWN)

    def test_three_valued_joint_endpoint(self):
        expected = {(False, False): False, (False, True): False, (False, UNKNOWN): False,
                    (True, False): False, (True, True): True, (True, UNKNOWN): UNKNOWN,
                    (UNKNOWN, False): False, (UNKNOWN, True): UNKNOWN,
                    (UNKNOWN, UNKNOWN): UNKNOWN}
        for pair, result in expected.items():
            with self.subTest(pair=pair):
                self.assertEqual(conjunction(*pair), result)

    def test_q_point_requires_replayable_evidence(self):
        eid = "sample"
        q = {"lower": 80.0, "upper": 100.0, "point": 90.0,
             "scope_complete": True,
             "components": {"content": {"evidence_ids": [eid + ":final_text"]}}}
        report = {"measurement": {"dimensions": {"Q": q}}}
        self.assertEqual(_q(report, {"episode_id": eid}, eid)["point"], 90.0)
        q["components"]["content"]["evidence_ids"] = ["fabricated-id"]
        with self.assertRaisesRegex(ValueError, "Q_evidence_not_replayable"):
            _q(report, {"episode_id": eid}, eid)
        q["point"] = None
        self.assertIsNone(_q(report, None, eid)["point"])

    def test_formal_gate_does_not_inherit_bounded_phase_success(self):
        row = {"G": False, "L": True,
               "Q": {"point": None}, "I": None, "D": None,
               "report_formal_ready": False}
        gate = _formal_endpoint_gate([row])
        self.assertFalse(gate["all_Q_I_D_known"])
        self.assertFalse(gate["passed"])
        complete = {**row, "Q": {"point": 100.0}, "I": 100.0, "D": 100.0,
                    "report_formal_ready": True}
        self.assertTrue(_formal_endpoint_gate([complete])["passed"])
        self.assertIsNone(_formal_dimension_point({"measurement": {"dimensions": {
            "I": {"point": 100.0, "scope_complete": False}}}}, "I"))


if __name__ == "__main__":
    unittest.main()
