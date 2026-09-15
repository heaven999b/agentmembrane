"""Trusted, no-model native regression checks, not research attack samples."""
from __future__ import annotations
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.rq1_collab_v1.native import (
    NativeTask, ORDER_METADATA, _restore_environment, catalog, digest, public_goal_catalog, qualify_reference,
)

PROJECT = Path(__file__).resolve().parents[2]
SOURCE = os.environ.get("RQ1_NATIVE_SOURCE_ROOT", str(PROJECT / "data/host_boundary_v2/upstream/agentdojo"))
AVAILABLE = importlib.util.find_spec("pydantic") is not None


@unittest.skipUnless(AVAILABLE, "native tests require registered AgentDojo dependency environment")
class NativeTests(unittest.TestCase):
    def task(self):
        return NativeTask(SOURCE, "workspace", "user_task_8")

    def test_real_reference_and_noop(self):
        result = qualify_reference(SOURCE, "workspace", "user_task_8")
        self.assertTrue(result["native_reference_score"])
        self.assertEqual(result["strict_reference_score"]["value"], 1)
        self.assertFalse(result["native_noop_score"])
        self.assertTrue(result["reset_verified"])
        self.assertFalse(result["admitted"])

    def test_constructor_never_executes_reference(self):
        first = self.task()
        with patch.object(type(first._task), "ground_truth", side_effect=AssertionError("gold executed")):
            second = self.task()
            self.assertEqual(second.snapshot(), first.snapshot())
            self.assertFalse(second.qualification()["reference_executed"])

    def test_wrong_event_native_false_positive_is_strictly_rejected(self):
        task = self.task()
        before = task.snapshot()
        other_id = next(k for k in before["calendar"]["events"] if k != "24")
        result = task.call("add_calendar_event_participants", {
            "event_id": other_id, "participants": ["john.doe@clientcorp.com", "maria.garcia@bluesparrowtech.com"]})
        self.assertIsNone(result["error"])
        self.assertTrue(task.native_score(before, result["after"], ""))
        self.assertEqual(task.strict_score(before, result["after"], "")["value"], 0)

    def test_partial_legal_addition_is_not_task_completion(self):
        task = self.task()
        before = task.snapshot()
        result = task.call("add_calendar_event_participants", {"event_id": "24", "participants": ["john.doe@clientcorp.com"]})
        self.assertEqual(task.strict_score(before, result["after"], "")["value"], 0)
        result = task.call("add_calendar_event_participants", {"event_id": "24", "participants": ["maria.garcia@bluesparrowtech.com"]})
        self.assertEqual(task.strict_score(before, result["after"], "")["value"], 1)

    def test_actual_effects_and_return_not_fictitious_email(self):
        task = self.task()
        result = task.call("add_calendar_event_participants", {"event_id": "24", "participants": ["john.doe@clientcorp.com"]})
        self.assertTrue(result["effects"])
        self.assertEqual(result["before"]["inbox"], result["after"]["inbox"])
        self.assertEqual(result["result"]["id_"], "24")
        self.assertEqual(result["evidence_quality"]["primitive_internal_reads"], "unknown")

    def test_extra_argument_rejected_before_backend_entry(self):
        task = self.task()
        result = task.call("add_calendar_event_participants", {"event_id": "24", "participants": [], "spoof": True})
        self.assertIsNotNone(result["error"])
        self.assertFalse(result["evidence_quality"]["backend_entered"])
        self.assertEqual(result["before"], result["after"])

    def test_nonfinite_argument_rejected(self):
        task = self.task()
        result = task.call("search_calendar_events", {"query": float("nan")})
        self.assertIsNotNone(result["error"])
        self.assertFalse(result["evidence_quality"]["backend_entered"])

    def test_independent_reset_no_world_leakage(self):
        first = self.task()
        first.call("add_calendar_event_participants", {"event_id": "24", "participants": ["john.doe@clientcorp.com"]})
        second = self.task()
        self.assertNotEqual(first.snapshot(), second.snapshot())
        self.assertEqual(digest(second.snapshot()), second.record["initial_state_sha256"])

    def test_created_objects_survive_private_json_restore(self):
        task = NativeTask(SOURCE, "workspace", "user_task_9")
        before = task.snapshot()
        for call in task._task.ground_truth(task._environment.model_copy(deep=True)):
            task._runtime.run_function(task._environment, call.function, call.args, raise_on_error=True)
            task._calls.append(call)
        after = task.snapshot()
        self.assertGreater(len(after["calendar"]["events"]), len(before["calendar"]["events"]))
        restored = _restore_environment(task.suite.environment_type, after)
        self.assertEqual(restored.model_dump(mode="json"), {k: v for k, v in after.items() if k != ORDER_METADATA})
        self.assertTrue(task.native_score(before, after, task._task.GROUND_TRUTH_OUTPUT))

    def test_catalog_reports_actual_registered_classes_not_admission(self):
        records = catalog(SOURCE)
        self.assertEqual(len(records), 97)
        self.assertEqual(len({(r["suite"], r["task_id"]) for r in records}), 97)
        self.assertTrue(all(r["class_source_sha256"] and not r["admitted"] for r in records))

    def test_public_goal_catalog_does_not_export_private_attributes(self):
        goals = public_goal_catalog(SOURCE)
        self.assertEqual(len(goals), 27)
        self.assertTrue(all("goal" in g and "ground_truth" not in g and "GROUND_TRUTH_OUTPUT" not in g for g in goals))
        self.assertTrue(all(g["pair_eligibility"] == "not_reviewed" for g in goals))

    def test_wrong_class_hash_does_not_reuse_strict_checker(self):
        task = self.task()
        task.record["class_source_sha256"] = "not_the_locked_class"
        self.assertIsNone(task.strict_score(task.snapshot(), task.snapshot(), "")["value"])
        self.assertFalse(task.qualification()["strict_checker_ready"])

    def test_sorted_json_pipe_preserves_native_dictionary_iteration(self):
        task = self.task()
        initial = task.snapshot()
        sorted_pipe = json.loads(json.dumps(initial, sort_keys=True))
        detail = task.native_score_detail(sorted_pipe, sorted_pipe, "", function_calls=[])
        self.assertIsNone(detail["error"])
        self.assertFalse(detail["value"])
        restored = _restore_environment(task.suite.environment_type, sorted_pipe)
        self.assertEqual(list(restored.inbox.emails), list(task._environment.inbox.emails))


if __name__ == "__main__":
    unittest.main()
