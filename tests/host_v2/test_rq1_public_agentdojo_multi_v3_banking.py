from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import unittest

from agentmembrane.host_v2.rq1_public_agentdojo_multi_v3.domain_witnesses import (
    banking,
)


EXPECTED_SOURCE_REFS = {
    "agentdojo-v1-banking-u0-i5": {
        "user_ground_truth": (
            "agentdojo.default_suites.v1.banking.user_tasks."
            "UserTask0.ground_truth:21"
        ),
        "utility_checker": (
            "agentdojo.default_suites.v1.banking.user_tasks."
            "UserTask0.utility:40"
        ),
        "injection_ground_truth": (
            "agentdojo.default_suites.v1.banking.injection_tasks."
            "InjectionTask5.ground_truth:247"
        ),
        "security_checker": (
            "agentdojo.default_suites.v1.banking.injection_tasks."
            "InjectionTask5.security:266"
        ),
    },
    "agentdojo-v1-banking-u2-i4": {
        "user_ground_truth": (
            "agentdojo.default_suites.v1.banking.user_tasks."
            "UserTask2.ground_truth:89"
        ),
        "utility_checker": (
            "agentdojo.default_suites.v1.banking.user_tasks."
            "UserTask2.utility:107"
        ),
        "injection_ground_truth": (
            "agentdojo.default_suites.v1.banking.injection_tasks."
            "InjectionTask4.ground_truth:218"
        ),
        "security_checker": (
            "agentdojo.default_suites.v1.banking.injection_tasks."
            "InjectionTask4.security:233"
        ),
    },
    "agentdojo-v1-banking-u3-i1": {
        "user_ground_truth": (
            "agentdojo.default_suites.v1.banking.user_tasks."
            "UserTask3.ground_truth:127"
        ),
        "utility_checker": (
            "agentdojo.default_suites.v1.banking.user_tasks."
            "UserTask3.utility:146"
        ),
        "injection_ground_truth": (
            "agentdojo.default_suites.v1.banking.injection_tasks."
            "InjectionTask1.ground_truth:77"
        ),
        "security_checker": (
            "agentdojo.default_suites.v1.banking.injection_tasks."
            "InjectionTask1.security:96"
        ),
    },
}


def _action_projection(record):
    return {"operation": record["operation"], "args": record["args"]}


def _action_sha256(record) -> str:
    raw = json.dumps(
        _action_projection(record),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class BankingNativeWitnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.result = banking.run_banking_native_witnesses()
        cls.by_id = {
            row["source_ids"]["source_task_id"]: row
            for row in cls.result["workflows"]
        }

    def test_deterministic_first_three_pack_sources_are_exact(self) -> None:
        expected = {
            "agentdojo-v1-banking-u0-i5": (
                "user_task_0",
                "injection_task_5",
                "injection_bill_text",
            ),
            "agentdojo-v1-banking-u2-i4": (
                "user_task_2",
                "injection_task_4",
                "injection_landloard_notice",
            ),
            "agentdojo-v1-banking-u3-i1": (
                "user_task_3",
                "injection_task_1",
                "injection_incoming_transaction",
            ),
        }
        self.assertEqual(set(self.by_id), set(expected))
        self.assertEqual(
            [spec.source_task_id for spec in banking.WORKFLOW_SPECS],
            list(expected),
        )
        for source_task_id, ids in expected.items():
            with self.subTest(source_task_id=source_task_id):
                source = self.by_id[source_task_id]["source_ids"]
                self.assertEqual(
                    (
                        source["user_task_id"],
                        source["injection_task_id"],
                        source["injection_vector_id"],
                    ),
                    ids,
                )

    def test_exact_native_source_refs_and_hashes_are_reported(self) -> None:
        for source_task_id, expected in EXPECTED_SOURCE_REFS.items():
            with self.subTest(source_task_id=source_task_id):
                source = self.by_id[source_task_id]["source_ids"]
                for name, callable_ref in expected.items():
                    self.assertEqual(source[name]["callable"], callable_ref)
                    self.assertRegex(source[name]["source_sha256"], r"^[0-9a-f]{64}$")
                self.assertEqual(
                    source["user_ground_truth"]["source_sha256"],
                    source["utility_checker"]["source_sha256"],
                )
                self.assertEqual(
                    source["injection_ground_truth"]["source_sha256"],
                    source["security_checker"]["source_sha256"],
                )

    def test_surface_action_reaches_injected_native_carrier(self) -> None:
        for source_task_id, row in self.by_id.items():
            with self.subTest(source_task_id=source_task_id):
                carrier = row["carrier"]
                self.assertTrue(row["surface_task"])
                self.assertEqual(carrier["script_role"], "reachability_only")
                self.assertTrue(
                    carrier["injection_goal_present_in_native_observation"]
                )
                self.assertEqual(carrier["native_dispatches"], 1)
                self.assertEqual(
                    carrier["native_tool_schema"],
                    row["native_tool_schemas"][carrier["action"]["operation"]],
                )
                self.assertEqual(
                    carrier["pre_state_sha256"], carrier["post_state_sha256"]
                )
                self.assertRegex(carrier["observation_sha256"], r"^[0-9a-f]{64}$")

    def test_every_action_is_bound_to_a_native_runtime_schema(self) -> None:
        for source_task_id, row in self.by_id.items():
            schemas = row["native_tool_schemas"]
            actions = list(row["benign"]["source_action_sequence"])
            actions += list(row["vulnerable"]["source_injection_action_sequence"])
            actions.append(row["carrier"]["action"])
            with self.subTest(source_task_id=source_task_id):
                for action in actions:
                    self.assertIn(action["operation"], schemas)
                    self.assertEqual(action["action_sha256"], _action_sha256(action))
                candidate = row["protected_predispatch"]["candidate_action"]
                self.assertEqual(
                    row["protected_predispatch"]["candidate_native_tool_schema"],
                    schemas[candidate["operation"]],
                )

    def test_benign_sequences_pass_the_native_utility_checker(self) -> None:
        exact_steps = {
            "agentdojo-v1-banking-u0-i5": 2,
            "agentdojo-v1-banking-u2-i4": 3,
            "agentdojo-v1-banking-u3-i1": 2,
        }
        for source_task_id, expected_steps in exact_steps.items():
            with self.subTest(source_task_id=source_task_id):
                benign = self.by_id[source_task_id]["benign"]
                self.assertEqual(benign["native_dispatches"], expected_steps)
                self.assertEqual(benign["native_checker_calls"], 1)
                self.assertIs(benign["native_utility_checker"]["result"], True)
                self.assertEqual(
                    benign["native_utility_checker"]["pre_state_sha256"],
                    benign["native_utility_checker"]["post_state_sha256"],
                )
                self.assertEqual(
                    benign["source_action_sequence"],
                    [effect["action"] for effect in benign["native_effects"]],
                )

    def test_vulnerable_sequences_have_exact_effect_and_native_security(self) -> None:
        for source_task_id, row in self.by_id.items():
            with self.subTest(source_task_id=source_task_id):
                vulnerable = row["vulnerable"]
                final = vulnerable["exact_final_effect"]
                self.assertEqual(vulnerable["native_dispatches"], 2)
                self.assertEqual(vulnerable["native_checker_calls"], 1)
                self.assertIs(
                    vulnerable["native_security_checker"]["result"], True
                )
                self.assertEqual(
                    vulnerable["native_security_checker"]["pre_state_sha256"],
                    vulnerable["native_security_checker"]["post_state_sha256"],
                )
                self.assertNotEqual(
                    final["pre_state_sha256"], final["post_state_sha256"]
                )
                self.assertEqual(
                    final["action"],
                    vulnerable["source_injection_action_sequence"][-1],
                )
                self.assertEqual(final["action_sha256"], _action_sha256(final["action"]))

    def test_protected_simulation_denies_exact_final_action_pre_dispatch(self) -> None:
        for source_task_id, row in self.by_id.items():
            protected = row["protected_predispatch"]
            vulnerable_final = row["vulnerable"]["exact_final_effect"]
            authorized = [
                _action_projection(action)
                for action in protected["authorized_user_ground_truth_actions"]
            ]
            with self.subTest(source_task_id=source_task_id):
                self.assertEqual(
                    protected["mode"], "offline_source_bound_simulation_only"
                )
                self.assertEqual(protected["decision"], "deny")
                self.assertEqual(
                    protected["reason"], "not_an_exact_user_ground_truth_action"
                )
                self.assertTrue(
                    protected["candidate_matches_vulnerable_final_action"]
                )
                self.assertEqual(
                    protected["candidate_action_sha256"],
                    vulnerable_final["action_sha256"],
                )
                self.assertNotIn(
                    _action_projection(protected["candidate_action"]), authorized
                )
                self.assertEqual(protected["native_dispatches"], 0)
                self.assertEqual(protected["native_checker_calls"], 0)
                self.assertEqual(
                    protected["pre_state_sha256"], protected["post_state_sha256"]
                )
                self.assertFalse(protected["execution_authorized"])

    def test_exact_call_budget_is_zero_token_and_zero_network(self) -> None:
        self.assertEqual(
            self.result["execution_counts"],
            {
                "api_calls": 0,
                "llm_tokens": 0,
                "model_calls": 0,
                "native_checker_calls": 6,
                "native_dispatches": 13,
                "network_calls": 0,
                "provider_calls": 0,
            },
        )
        self.assertFalse(self.result["execution_authorized"])
        self.assertFalse(self.result["claim_eligible"])

    def test_cached_result_validator_fails_closed_on_checker_or_dispatch_forgery(self) -> None:
        mutated = copy.deepcopy(self.result)
        mutated["workflows"][0]["benign"]["native_utility_checker"]["result"] = False
        with self.assertRaises(banking.BankingWitnessError):
            banking.validate_banking_native_witnesses(mutated)

        mutated = copy.deepcopy(self.result)
        protected = mutated["workflows"][0]["protected_predispatch"]
        protected["native_dispatches"] = 1
        with self.assertRaises(banking.BankingWitnessError):
            banking.validate_banking_native_witnesses(mutated)

    def test_native_actions_and_sink_values_are_not_embedded_in_witness_code(self) -> None:
        source = Path(banking.__file__).read_text(encoding="utf-8")
        # Source IDs are intentionally frozen here; native action names, values,
        # schemas, and attacker targets must instead arrive from AgentDojo.
        self.assertNotIn("US133000000121212121212", source)
        self.assertNotIn('"send_money"', source)
        self.assertNotIn('"update_scheduled_transaction"', source)


if __name__ == "__main__":
    unittest.main()
