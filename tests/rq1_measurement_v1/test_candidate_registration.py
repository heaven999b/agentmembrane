"""Source-only pre-run registration for the enlarged development task pool."""
from __future__ import annotations

import copy
import unittest

from agentmembrane.host_v2.rq1_collab_v1.native import NativeTask
from agentmembrane.host_v2.rq1_measurement_v1.contracts import compile_from_bundle
from agentmembrane.host_v2.rq1_measurement_v1.references import (
    DEFAULT_SOURCE_ROOT, registration_catalog, source_catalog,
)
from agentmembrane.host_v2.rq1_scorecard_v5.core import score


class CandidateRegistrationTests(unittest.TestCase):
    def test_old_reviewed_catalog_is_unchanged_and_expansion_is_explicit(self):
        self.assertEqual(len(source_catalog()), 6)
        expanded = registration_catalog()
        self.assertEqual(len(expanded), 83)
        self.assertIn("banking/user_task_1", expanded)
        self.assertIn("slack/user_task_0", expanded)
        self.assertNotIn("banking/user_task_999", expanded)

    def test_fresh_native_new_families_bind_but_unreviewed_scores_remain_unknown(self):
        for key in ("banking/user_task_1", "slack/user_task_0"):
            with self.subTest(key=key):
                bundle = registration_catalog()[key]
                native = NativeTask(str(DEFAULT_SOURCE_ROOT), bundle["suite"], bundle["original_id"])
                locked = compile_from_bundle(bundle, native.snapshot())
                self.assertEqual(locked["reference"]["measurement_adapter"], "source_identity_only_v1")
                self.assertEqual(locked["reference"]["source_binding"]["class_source_sha256"],
                                 native.record["class_source_sha256"])
                self.assertEqual(locked["private_facts"], {})
                self.assertEqual(locked["information_contract"]["units"], [])
                self.assertIsNone(locked["information_contract"]["counts"]["I_cells"])
                for dim in ("Q", "I", "D"):
                    self.assertEqual(locked["score_contract"]["dimensions"][dim]["units"], [])
                    self.assertTrue(locked["score_contract"]["dimensions"][dim]["unavailable_reason"])
                result = score(locked["score_contract"], {"content": None, "effect": None}, [],
                               evidence_ids={"engineering:initial"},
                               scope_incomplete={"Q", "I", "D"})
                for dim in ("Q", "I", "D"):
                    self.assertIsNone(result["dimensions"][dim]["point"])
                    self.assertEqual((result["dimensions"][dim]["lower"],
                                      result["dimensions"][dim]["upper"]), (0, 100))
                self.assertIsNone(result["overall"]["point"])

    def test_every_new_candidate_binds_the_actual_fresh_native_world(self):
        reviewed, expanded = source_catalog(), registration_catalog()
        count = 0
        for key, bundle in expanded.items():
            if key in reviewed:
                continue
            native = NativeTask(str(DEFAULT_SOURCE_ROOT), bundle["suite"], bundle["original_id"])
            locked = compile_from_bundle(bundle, native.snapshot())
            self.assertEqual(locked["reference"]["source_binding"]["prompt_sha256"],
                             native.record["prompt_sha256"], key)
            self.assertEqual(locked["reference"]["source_binding"]["class_module"],
                             native.record["class_module"], key)
            count += 1
        self.assertEqual(count, 77)

    def test_changed_request_source_goal_or_world_is_rejected(self):
        bundle = registration_catalog()["banking/user_task_1"]
        native = NativeTask(str(DEFAULT_SOURCE_ROOT), "banking", "user_task_1")
        snapshot = native.snapshot()
        for variant in ("prompt", "class", "goal", "world"):
            altered, before = copy.deepcopy(bundle), copy.deepcopy(snapshot)
            if variant == "prompt":
                altered["public"]["user_request"] += " extra"
            elif variant == "class":
                altered["source_record"]["class_source_sha256"] = "0" * 64
            elif variant == "goal":
                altered["public"]["goal"]["goal"] += " extra"
            else:
                before["banking_measurement_test_mutation"] = True
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                compile_from_bundle(altered, before)


if __name__ == "__main__":
    unittest.main()
