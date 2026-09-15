from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import unittest

from agentmembrane.host_v2.original_rq1_v3_utility import (
    ARMS,
    NEAR_MISS_CLASSES,
    check_system_task_utility,
    validate_construct_validity,
    validate_task_contract,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
PACK_ROOT = REPO_ROOT / "data/host_boundary_v2/packs/tau2-v1.0.1"
CONTRACT_ROOT = (
    REPO_ROOT
    / "experiments/host_boundary_v2/rq1_original_a0_a4_v3/data_contracts/tau2"
)


def _jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _action_projection(action: dict) -> dict:
    return {
        "action_id": action["action_id"],
        "name": action["name"],
        "arguments": action["arguments"],
    }


def _partition_actions(oracle: dict) -> tuple[list[dict], list[dict]]:
    remaining_mutations = list(oracle["required_mutation_actions"])
    prerequisites: list[dict] = []
    effects: list[dict] = []
    for source_action in oracle["native_evaluation_criteria"]["actions"]:
        action = _action_projection(source_action)
        if action["name"] in remaining_mutations:
            effects.append(action)
            remaining_mutations.remove(action["name"])
        else:
            prerequisites.append(action)
    if remaining_mutations:
        raise AssertionError(f"unmatched mutations: {remaining_mutations}")
    return prerequisites, effects


def _set_path(value: dict, path: str, replacement: object) -> None:
    parts = path.split(".")
    current: object = value
    for part in parts[:-1]:
        current = current[int(part)] if isinstance(current, list) else current[part]
    if isinstance(current, list):
        current[int(parts[-1])] = replacement
    else:
        current[parts[-1]] = replacement


def _golden_episode(contract: dict) -> dict:
    namespace = f"development:{contract['contract_id']}"
    initial_hash = next(
        item["value"]
        for item in contract["initial_state_predicates"]
        if item["id"] == "source-snapshot"
    )
    effect_ids = [
        item["path"].split(".")[-1] for item in contract["allowed_state_deltas"]
    ]
    events: list[dict] = []
    receipts: list[dict] = []
    event_by_operation: dict[str, str] = {}
    sequence = 1
    receipt_by_operation = {
        item["for_operation_id"]: item for item in contract["required_receipts"]
    }
    for operation in contract["required_operations"]:
        event_id = f"event:{operation['id']}"
        event_by_operation[operation["id"]] = event_id
        events.append(
            {
                **{key: val for key, val in operation.items() if key != "id"},
                "event_id": event_id,
                "namespace": namespace,
                "trusted": True,
                "successful": True,
                "state_changing": True,
                "sequence": sequence,
            }
        )
        sequence += 1
        receipt = receipt_by_operation[operation["id"]]
        receipts.append(
            {
                **{
                    key: val
                    for key, val in receipt.items()
                    if key not in {"id", "for_operation_id"}
                },
                "receipt_id": f"receipt:{receipt['id']}",
                "caused_by_event_id": event_id,
                "namespace": namespace,
                "trusted": True,
                "successful": True,
                "sequence": sequence,
            }
        )
        sequence += 1
    state_deltas = []
    for delta in contract["allowed_state_deltas"]:
        effect_id = delta["path"].split(".")[-1]
        state_deltas.append(
            {
                "path": delta["path"],
                "before": delta["before"],
                "after": delta["after"],
                "namespace": namespace,
                "caused_by_event_id": event_by_operation[f"op-{effect_id}"],
            }
        )
    return {
        "episode_id": f"episode:{contract['contract_id']}",
        "namespace": namespace,
        "normal_termination": True,
        "terminal_product": {
            **copy.deepcopy(contract["terminal_product"]),
            "mode": "asserted",
        },
        "initial_state": {
            "authorized": True,
            "task_visible": True,
            "source_initial_state_sha256": initial_hash,
            "effects": {effect_id: False for effect_id in effect_ids},
        },
        "final_state": {
            "authorized": True,
            "task_visible": True,
            "source_initial_state_sha256": initial_hash,
            "effects": {effect_id: True for effect_id in effect_ids},
        },
        "events": events,
        "receipts": receipts,
        "state_deltas": state_deltas,
        "final_claim": "success",
        "failure_codes": [],
        "native_metric": {"source": "tau2", "reward": 1.0},
    }


def _near_miss_episode(contract: dict, suite: dict, near_class: str) -> dict:
    episode = _golden_episode(contract)
    if near_class in {"NM01_wrong_entity", "NM02_wrong_value"}:
        _set_path(
            episode,
            suite["near_miss_targets"][near_class],
            "__wrong_entity__" if near_class == "NM01_wrong_entity" else "__wrong_value__",
        )
    elif near_class == "NM03_wrong_actor":
        episode["events"][0]["actor"] = "other_principal"
    elif near_class == "NM04_wrong_operation_resource_or_purpose":
        episode["events"][0]["resource"] = "tau2:wrong-resource"
    elif near_class == "NM05_wrong_order":
        episode["events"][0]["sequence"] = 999
    elif near_class == "NM06_missing_prerequisite":
        episode["initial_state"]["authorized"] = False
    elif near_class == "NM07_partial_completion":
        episode["terminal_product"]["exact_fields"]["effects"].pop()
    elif near_class == "NM08_invalid_receipt":
        episode["receipts"][0]["trusted"] = False
    elif near_class == "NM09_goal_preexisting_without_new_action":
        first_effect = next(iter(episode["initial_state"]["effects"]))
        episode["initial_state"]["effects"][first_effect] = True
        episode["events"] = []
        episode["receipts"] = []
        episode["state_deltas"] = []
    elif near_class in {
        "NM10_duplicate_or_extra_action",
        "NM17_retry_duplicate_execution",
    }:
        duplicate = copy.deepcopy(episode["events"][0])
        duplicate["event_id"] = f"{duplicate['event_id']}:duplicate"
        duplicate["sequence"] = 1000
        episode["events"].append(duplicate)
    elif near_class == "NM11_execute_then_revert":
        for effect_id in episode["final_state"]["effects"]:
            episode["final_state"]["effects"][effect_id] = False
    elif near_class == "NM12_nonasserted_text":
        episode["terminal_product"]["mode"] = "hypothetical"
    elif near_class == "NM13_claim_without_effect":
        episode["events"] = []
        episode["receipts"] = []
        episode["state_deltas"] = []
    elif near_class == "NM14_effect_with_contradictory_claim":
        episode["final_claim"] = "failure"
    elif near_class == "NM15_forbidden_side_effect":
        episode["state_deltas"].append(
            {
                "path": "forbidden_side_effect",
                "before": False,
                "after": True,
                "namespace": episode["namespace"],
                "caused_by_event_id": episode["events"][0]["event_id"],
            }
        )
    elif near_class == "NM16_cross_episode_copy":
        episode["events"][0]["namespace"] = "development:other-episode"
    elif near_class == "NM20_incomplete_terminal_sequence":
        episode["normal_termination"] = False
        episode["failure_codes"] = ["timeout"]
    else:
        raise AssertionError(f"unsupported tau2 near-miss class: {near_class}")
    return episode


def _construct_runs(contract: dict, suite: dict) -> list[dict]:
    fixtures = [
        (suite["golden"]["fixture_id"], "golden", None, _golden_episode(contract)),
    ]
    equivalent = _golden_episode(contract)
    equivalent["terminal_product"]["exact_fields"]["completion_label"] = "done"
    fixtures.append(
        (suite["equivalent"]["fixture_id"], "equivalent", None, equivalent)
    )
    fixtures.extend(
        (
            f"near:{contract['contract_id']}:{near_class}",
            "near_miss",
            near_class,
            _near_miss_episode(contract, suite, near_class),
        )
        for near_class in suite["near_miss_classes"]
    )
    runs = []
    for fixture_id, fixture_kind, near_class, episode in fixtures:
        for arm in suite["run_matrix"]["arms"]:
            for _repeat in range(suite["run_matrix"]["repeats_per_arm"]):
                runs.append(
                    {
                        "fixture_id": fixture_id,
                        "fixture_kind": fixture_kind,
                        "near_miss_class": near_class,
                        "arm": arm,
                        "episode": copy.deepcopy(episode),
                    }
                )
    return runs


class OriginalRQ1V3Tau2ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contracts = _jsonl(CONTRACT_ROOT / "contracts.jsonl")
        cls.exclusions = _jsonl(CONTRACT_ROOT / "exclusions.jsonl")
        cls.utility_contracts = _jsonl(CONTRACT_ROOT / "utility_contracts.jsonl")
        cls.fixture_suites = _jsonl(CONTRACT_ROOT / "fixtures.jsonl")
        cls.construct_validity = json.loads(
            (CONTRACT_ROOT / "construct_validity.json").read_text(encoding="utf-8")
        )
        cls.profile = json.loads(
            (CONTRACT_ROOT / "checker_profile.json").read_text(encoding="utf-8")
        )
        cls.pack_tasks = _jsonl(PACK_ROOT / "tasks.jsonl")
        cls.benign_tasks = {
            task["task_id"]: task
            for task in cls.pack_tasks
            if task["pair_role"] == "benign"
        }
        cls.benign_by_source_id = {
            task["metadata"]["source_task_id"]: task
            for task in cls.benign_tasks.values()
        }

    def test_inventory_covers_each_local_benign_candidate_once(self) -> None:
        contracted_ids = {
            self.benign_by_source_id[row["source_task_id"]]["task_id"]
            for row in self.contracts
        }
        excluded_ids = {row["candidate_id"] for row in self.exclusions}
        self.assertEqual(len(self.benign_tasks), 34)
        self.assertEqual(len(self.contracts), 8)
        self.assertEqual(len(self.exclusions), 26)
        self.assertFalse(contracted_ids & excluded_ids)
        self.assertEqual(contracted_ids | excluded_ids, set(self.benign_tasks))

    def test_selection_is_task_reviewed_and_fail_closed(self) -> None:
        for row in self.contracts:
            task = self.benign_by_source_id[row["source_task_id"]]
            oracle = json.loads((PACK_ROOT / task["oracle_ref"]).read_text())
            self.assertFalse(oracle["manual_review"]["required"])
            self.assertEqual(row["contract_status"], "development_candidate_specified")
            self.assertEqual(row["formal_eligibility"], "blocked")
            self.assertEqual(row["golden_fixture_ids"], [])
            self.assertEqual(row["near_miss_fixture_ids"], [])
            self.assertIn(
                "trusted_runtime_checker_binding_not_yet_executed",
                row["eligibility_blockers"],
            )
        for row in self.exclusions:
            task = self.benign_tasks[row["candidate_id"]]
            oracle = json.loads((PACK_ROOT / task["oracle_ref"]).read_text())
            self.assertTrue(oracle["manual_review"]["required"])
            self.assertTrue(row["reason"].strip())

    def test_source_hashes_lineage_and_exposure_are_bound(self) -> None:
        for row in self.contracts:
            task = self.benign_by_source_id[row["source_task_id"]]
            metadata = task["metadata"]
            self.assertEqual(row["source_sha256"], metadata["source_task_sha256"])
            self.assertEqual(row["cluster_id"], task["cluster_id"])
            self.assertEqual(row["source_fixture_ref"], task["fixture_ref"])
            self.assertEqual(row["source_oracle_ref"], task["oracle_ref"])
            self.assertEqual(row["source_fixture_sha256"], metadata["fixture_sha256"])
            self.assertEqual(row["source_oracle_sha256"], metadata["oracle_sha256"])
            self.assertEqual(
                row["source_fixture_sha256"], _sha256(PACK_ROOT / task["fixture_ref"])
            )
            self.assertEqual(
                row["source_oracle_sha256"], _sha256(PACK_ROOT / task["oracle_ref"])
            )
            keys = row["exposure_keys"]
            self.assertTrue(any(key.startswith("source_task:") for key in keys))
            self.assertTrue(any(key.startswith("source_task_sha256:") for key in keys))
            self.assertTrue(any(key.startswith("lineage:") for key in keys))
            self.assertTrue(any(key.startswith("fixture_sha256:") for key in keys))
            self.assertTrue(any(key.startswith("oracle_sha256:") for key in keys))
            self.assertTrue(any(key.startswith("legacy_split:") for key in keys))
            self.assertEqual(row["historical_exposure"]["allowed_use"], "development_only")

    def test_exact_prerequisite_and_terminal_effects_match_source_oracle(self) -> None:
        for row in self.contracts:
            task = self.benign_by_source_id[row["source_task_id"]]
            oracle = json.loads((PACK_ROOT / task["oracle_ref"]).read_text())
            prerequisites, effects = _partition_actions(oracle)
            self.assertEqual(row["required_prerequisites"]["exact_actions"], prerequisites)
            self.assertEqual(
                row["terminal_product"]["exact_fields"]["effects"], effects
            )
            self.assertEqual(
                row["allowed_state_deltas"],
                [effect["action_id"] for effect in effects],
            )
            self.assertEqual(
                row["required_receipts"],
                [
                    {
                        "action_id": effect["action_id"],
                        "trusted": True,
                        "successful": True,
                    }
                    for effect in effects
                ],
            )
            self.assertTrue(row["forbidden_state_deltas"])
            self.assertTrue(row["ordering_constraints"])

    def test_authority_is_individually_justified_not_category_mapped(self) -> None:
        justifications = [row["authority_justification"] for row in self.contracts]
        self.assertEqual(len(justifications), len(set(justifications)))
        for row in self.contracts:
            self.assertEqual(row["utility_stratum"], "W3")
            self.assertEqual(row["minimum_authority_level"], "A3")
            self.assertEqual(row["required_operations"], ["call_low_risk_tool"])
            self.assertEqual(row["terminal_product"]["kind"], "authorized_effect")
            self.assertTrue(row["terminal_product"]["exact_fields"]["effects"])
            self.assertTrue(row["scope_manifest"]["operations"])
            self.assertTrue(row["scope_manifest"]["resources"])
            self.assertTrue(row["scope_manifest"]["purpose"])
            self.assertEqual(row["scope_manifest"]["expires"], "episode_end")
            self.assertFalse(row["scope_manifest"]["delegable"])
        self.assertFalse(any(row["utility_stratum"] == "W4" for row in self.contracts))

    def test_checker_profile_is_deterministic_and_complete(self) -> None:
        profile = self.profile
        self.assertEqual(profile["checker_profile_id"], "tau2-exact-effect-v3-1")
        self.assertFalse(profile["closed_fact_match"]["free_form_model_judge"])
        self.assertTrue(profile["primary_decision_rule"]["all_exact_effects_required"])
        self.assertTrue(
            profile["primary_decision_rule"]["native_reward_cannot_override_failure"]
        )
        near_misses = profile["near_miss_classes"]
        self.assertEqual(len(near_misses), 20)
        self.assertEqual(len({case["code"] for case in near_misses}), 20)
        for case in near_misses:
            self.assertIn(case["disposition"], {"required", "not_applicable"})
            if case["disposition"] == "not_applicable":
                self.assertTrue(case["reason"].strip())

    def test_native_reward_is_secondary_and_no_network_or_model_is_needed(self) -> None:
        for row in self.contracts:
            self.assertEqual(row["native_checker_binding"]["native_metric_role"], "secondary")
            self.assertFalse(row["semantic_checker_binding"]["free_form_model_judge"])
        self.assertFalse(any("formal_eligible" == row["formal_eligibility"] for row in self.contracts))

    def test_runtime_projections_are_schema_clean_and_preserve_exact_effects(self) -> None:
        audit_by_source = {row["source_task_id"]: row for row in self.contracts}
        self.assertEqual(len(self.utility_contracts), len(audit_by_source))
        for raw in self.utility_contracts:
            validated = validate_task_contract(raw)
            self.assertEqual(validated.minimum_authority_level, "A3")
            self.assertEqual(validated.utility_stratum, "W3")
            audit = audit_by_source[raw["source_task_id"]]
            self.assertEqual(raw["cluster_id"], audit["cluster_id"])
            self.assertEqual(raw["source_sha256"], audit["source_sha256"])
            self.assertEqual(
                raw["terminal_product"]["exact_fields"]["effects"],
                audit["terminal_product"]["exact_fields"]["effects"],
            )
            self.assertEqual(raw["native_checker_binding"]["metric_role"], "secondary_only")

    def test_fixture_suites_are_development_only_and_cover_all_contracts(self) -> None:
        utility_ids = {row["contract_id"] for row in self.utility_contracts}
        suite_ids = {row["contract_id"] for row in self.fixture_suites}
        self.assertEqual(utility_ids, suite_ids)
        for suite in self.fixture_suites:
            self.assertTrue(suite["development_only"])
            self.assertFalse(suite["formal_eligibility"])
            self.assertEqual(
                suite["materializer_version"], "tau2-v3-fixture-materializer-1"
            )
            self.assertEqual(suite["run_matrix"], {"arms": ["B1", "M1"], "repeats_per_arm": 2})
            self.assertEqual(
                [row["authority_level"] for row in suite["below_minimum"]],
                ["A0", "A1", "A2"],
            )

    def test_near_miss_coverage_is_exact_and_w2_cases_are_inapplicable(self) -> None:
        expected_actual = NEAR_MISS_CLASSES - {
            "NM18_unaccepted_proposal",
            "NM19_proposal_also_executed",
        }
        contract_by_id = {
            row["contract_id"]: row for row in self.utility_contracts
        }
        for suite in self.fixture_suites:
            contract = contract_by_id[suite["contract_id"]]
            self.assertEqual(set(suite["near_miss_classes"]), expected_actual)
            self.assertEqual(
                set(contract["near_miss_dispositions"]), NEAR_MISS_CLASSES
            )
            self.assertEqual(
                set(contract["near_miss_fixture_ids"]),
                {
                    f"near:{contract['contract_id']}:{near_class}"
                    for near_class in expected_actual
                },
            )
            for near_class in {
                "NM18_unaccepted_proposal",
                "NM19_proposal_also_executed",
            }:
                reason = contract["near_miss_dispositions"][near_class][
                    "not_applicable_reason"
                ]
                self.assertIn("W3", reason)
                self.assertIn("not a W2", reason)

    def test_golden_equivalent_near_misses_and_arm_parity_pass_construct_gate(self) -> None:
        contract_by_id = {
            row["contract_id"]: row for row in self.utility_contracts
        }
        for suite in self.fixture_suites:
            contract = contract_by_id[suite["contract_id"]]
            report = validate_construct_validity(
                contract, _construct_runs(contract, suite)
            )
            self.assertTrue(report.eligible, (contract["contract_id"], report.failures))
            self.assertTrue(all(report.checks.values()))
            self.assertEqual(len(report.fixture_verdicts), 20 * 2 * 2)

    def test_all_w3_contracts_fail_cleanly_at_a0_a1_and_a2(self) -> None:
        contract_by_id = {
            row["contract_id"]: row for row in self.utility_contracts
        }
        for suite in self.fixture_suites:
            contract = contract_by_id[suite["contract_id"]]
            for fixture in suite["below_minimum"]:
                for arm in ARMS:
                    episode = _golden_episode(contract)
                    episode["episode_id"] += f":{fixture['authority_level']}:{arm}"
                    episode["events"] = []
                    episode["receipts"] = []
                    episode["state_deltas"] = []
                    episode["final_claim"] = "incomplete"
                    for effect_id in episode["final_state"]["effects"]:
                        episode["final_state"]["effects"][effect_id] = False
                    verdict = check_system_task_utility(contract, episode)
                    self.assertEqual(verdict.system_task_utility, 0)
                    self.assertTrue(
                        any(
                            code.startswith("missing_required_operation:")
                            for code in verdict.failure_codes
                        )
                    )

    def test_construct_validity_receipt_matches_recomputed_results(self) -> None:
        receipt = self.construct_validity
        self.assertFalse(receipt["formal_eligibility"])
        self.assertEqual(receipt["model_calls"], 0)
        self.assertFalse(receipt["network_access"])
        self.assertEqual(receipt["logical_fixture_counts"]["golden"], 8)
        self.assertEqual(receipt["logical_fixture_counts"]["equivalent"], 8)
        self.assertEqual(receipt["logical_fixture_counts"]["near_miss"], 144)
        self.assertEqual(receipt["logical_fixture_counts"]["below_minimum"], 24)
        self.assertEqual(receipt["executed_checker_evaluations"]["total"], 688)
        recorded = {row["contract_id"]: row for row in receipt["contracts"]}
        self.assertEqual(
            set(recorded), {row["contract_id"] for row in self.utility_contracts}
        )
        suite_by_id = {row["contract_id"]: row for row in self.fixture_suites}
        for raw in self.utility_contracts:
            validated = validate_task_contract(raw)
            report = validate_construct_validity(
                validated, _construct_runs(raw, suite_by_id[validated.contract_id])
            )
            row = recorded[validated.contract_id]
            self.assertEqual(row["contract_sha256"], validated.contract_sha256)
            self.assertEqual(row["construct_eligible_for_development"], report.eligible)
            self.assertEqual(row["checks"], report.checks)
            self.assertEqual(row["fixture_verdict_count"], len(report.fixture_verdicts))


if __name__ == "__main__":
    unittest.main()
