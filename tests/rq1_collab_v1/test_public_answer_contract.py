"""Engineering calibration of the public answer interface, not research data."""
import copy
import hashlib
import unittest

from agentmembrane.host_v2.rq1_collab_v1 import live_pilot
from agentmembrane.host_v2.rq1_collab_v1.providers import build_action_payload


class PublicAnswerContractTests(unittest.TestCase):
    def test_contract_is_in_both_actual_role_prompts(self):
        for actor in ("H", "E"):
            self.assertIn(live_pilot.PUBLIC_ANSWER_CONTRACT, live_pilot.ROLE_PROMPTS[actor])
            self.assertEqual(live_pilot.ROLE_PROMPTS[actor].count(live_pilot.ANSWER_CONTRACT_PROTOCOL), 1)

    def test_actual_wire_exposes_contract_before_answer_not_after_grading(self):
        observation = {"actor": "H", "task": "public task only", "history": [], "tools": []}
        profile = {"model": "offline-interface-test", "max_completion_tokens": 2048}
        payload = build_action_payload(profile, live_pilot.ROLE_PROMPTS["H"], observation,
                                       live_pilot.ACTION_PROTOCOL)
        self.assertEqual(payload["messages"][0]["role"], "system")
        self.assertIn(live_pilot.PUBLIC_ANSWER_CONTRACT, payload["messages"][0]["content"])
        self.assertEqual(payload["tool_choice"]["function"]["name"], "submit_action")
        self.assertFalse(payload["parallel_tool_calls"])

    def test_no_known_private_targets_or_fixture_answers_in_public_contract(self):
        text = live_pilot.PUBLIC_ANSWER_CONTRACT
        # Sentinels from original native facts, used ONLY in this private test.
        for private in ("recipe-collection.docx", "Le Baratin", "New Asiaway", "Le Marais Boutique",
                        "463820", "2025-01-11", "2025-01-15", "3183"):
            self.assertNotIn(private, text)
        for field in ("initial_snapshot", "terminal_snapshot", "class_source_sha256", "strict_profile_score"):
            self.assertNotIn(field, text)

    def test_semantic_bindings_and_unavailable_facts_are_public(self):
        text = live_pilot.PUBLIC_ANSWER_CONTRACT
        for required in ("sender, subject, body", "attachments", "filename", "reviews",
                         "start_day", "end_day", "price_per_person", "own observed",
                         "marking them read", "incomplete", "actual terminal state"):
            self.assertIn(required, text)

    def test_verification_pass_fail_unknown_are_distinct_without_mutation(self):
        for value, expected in ((1, "pass"), (0, "fail"), (None, "not_determined")):
            strict = {"value": value, "reason": "test_reason", "checker": "source_locked_test"}
            old = copy.deepcopy(strict)
            observed = live_pilot.utility_verification(strict)
            self.assertEqual(observed["result"], expected)
            self.assertTrue(observed["verification_attempted"])
            self.assertEqual(observed["determined"], value is not None)
            self.assertEqual(observed["value"], value)
            self.assertEqual(strict, old)
            self.assertEqual(observed["scope"], "task_utility_only_not_risk_or_process_quality")

    def test_unknown_format_and_source_fact_errors_remain_unknown(self):
        for reason in ("unsupported_or_invalid_semantic_answer_format",
                       "native_fact_or_target_unavailable:KeyError",
                       "source_class_or_prompt_not_locked_supported_profile"):
            row = live_pilot.utility_verification({"value": None, "reason": reason})
            self.assertTrue(row["verification_attempted"])
            self.assertFalse(row["determined"])
            self.assertIsNone(row["value"])
            self.assertEqual(row["reason"], reason)

    def test_false_success_statement_cannot_override_effect_failure(self):
        row = live_pilot.utility_verification({"value": 0, "requested_effect_complete": False,
                                              "reason": "requested_effect_incomplete"})
        self.assertEqual(row["result"], "fail")
        self.assertFalse(row["requested_effect_complete"])

    def test_verification_carries_exact_public_contract_version(self):
        row = live_pilot.utility_verification({"value": None})
        self.assertEqual(row["answer_contract_protocol"], live_pilot.ANSWER_CONTRACT_PROTOCOL)
        self.assertEqual(row["answer_contract_sha256"],
                         hashlib.sha256(live_pilot.PUBLIC_ANSWER_CONTRACT.encode()).hexdigest())


if __name__ == "__main__":
    unittest.main()
