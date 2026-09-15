from __future__ import annotations

from collections import Counter, defaultdict
import json
from pathlib import Path
import tempfile
import unittest

from agentmembrane.host_v2.full_inventory import (
    AGENTDOJO_RQ2_MECHANISMS,
    FORMAL_CLUSTER_FLOORS,
    FIXED_HELDOUT_CLUSTER_COST,
    SPLIT_ORDER,
    TAU2_RQ1_CONTRASTS,
    _assign_nonformal_splits,
    build_full_inventory,
    check_full_inventory,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
INVENTORY_ROOT = REPO_ROOT / "data/host_boundary_v2/full_inventory"


def _json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"expected object in {path}")
    return value


def _jsonl(path: Path) -> list[dict]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    if not all(isinstance(row, dict) for row in rows):
        raise AssertionError(f"expected object rows in {path}")
    return rows


class FullPublicInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = _json(INVENTORY_ROOT / "manifest.json")
        cls.eligibility = _json(INVENTORY_ROOT / "eligibility_shortfall.json")
        cls.splits = _json(INVENTORY_ROOT / "proposed_splits.json")
        cls.tau2 = _jsonl(INVENTORY_ROOT / "tau2_tasks.jsonl")
        cls.users = _jsonl(INVENTORY_ROOT / "agentdojo_user_tasks.jsonl")
        cls.injections = _jsonl(INVENTORY_ROOT / "agentdojo_injection_tasks.jsonl")
        cls.pairings = _jsonl(INVENTORY_ROOT / "agentdojo_attack_pairings.jsonl")

    def test_committed_inventory_reproduces_byte_for_byte(self) -> None:
        report = check_full_inventory(repo_root=REPO_ROOT, output_root=INVENTORY_ROOT)
        self.assertTrue(report["valid"], report)
        self.assertEqual(report["expected_tree_sha256"], report["actual_tree_sha256"])
        self.assertEqual(report["missing"], [])
        self.assertEqual(report["unexpected"], [])
        self.assertEqual(report["changed"], [])

    def test_direct_build_is_offline_and_complete(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            built = build_full_inventory(
                repo_root=REPO_ROOT, output_root=Path(temp) / "inventory"
            )
            self.assertEqual(built.tau2_task_count, 2546)
            self.assertEqual(built.agentdojo_user_task_count, 86)
            self.assertEqual(built.agentdojo_attack_pairing_count, 567)
            generated = _json(built.root / "manifest.json")
            self.assertEqual(generated["execution"]["network_calls"], 0)
            self.assertEqual(generated["execution"]["model_calls"], 0)
            self.assertFalse(generated["execution"]["imports_upstream_runtime"])

    def test_full_source_counts_and_data_class_are_exact(self) -> None:
        self.assertEqual(len(self.tau2), 2546)
        self.assertEqual(len(self.users), 86)
        self.assertEqual(len(self.injections), 27)
        self.assertEqual(len(self.pairings), 567)
        self.assertFalse(self.manifest["production_data"])
        self.assertEqual(self.manifest["schema_version"], 2)
        self.assertEqual(
            self.manifest["inventory_id"], "host-boundary-v2-full-public-inventory-v2"
        )
        self.assertEqual(
            self.manifest["data_class"], "established_public_realistic_simulation"
        )
        for row in (*self.tau2, *self.users, *self.injections, *self.pairings):
            self.assertFalse(row["production_data"])
            self.assertEqual(
                row["data_class"], "established_public_realistic_simulation"
            )

        summary = self.eligibility["summary"]
        self.assertEqual(summary["tau2_usable_task_count"], 2546)
        self.assertEqual(summary["tau2_boundary_adaptable_task_count"], 1915)
        self.assertEqual(summary["tau2_boundary_independent_cluster_count"], 142)
        self.assertTrue(summary["tau2_boundary_cluster_count_is_upper_bound"])
        self.assertEqual(
            summary["tau2_banking_knowledge_primary_conservative_upper_bound"],
            63,
        )
        self.assertEqual(
            summary[
                "tau2_banking_knowledge_verified_identity_merge_sensitivity_upper_bound"
            ],
            68,
        )
        self.assertEqual(
            summary["tau2_banking_knowledge_evaluator_field_component_upper_bound"],
            70,
        )
        self.assertEqual(
            summary["tau2_banking_knowledge_document_connected_sensitivity_cluster_count"],
            4,
        )
        self.assertEqual(summary["agentdojo_user_task_count"], 86)
        self.assertEqual(summary["agentdojo_native_attack_pairing_count"], 567)
        self.assertEqual(summary["agentdojo_independent_cluster_count"], 86)
        self.assertTrue(summary["agentdojo_cluster_count_is_upper_bound"])

    def test_tau2_preserves_every_source_id_and_native_oracle_hash(self) -> None:
        expected_counts = {
            "retail": 114,
            "airline": 50,
            "telecom": 2285,
            "banking_knowledge": 97,
        }
        source_root = (
            REPO_ROOT / "data/host_boundary_v2/upstream/tau2-bench/data/tau2/domains"
        )
        by_domain: dict[str, list[dict]] = defaultdict(list)
        for row in self.tau2:
            by_domain[row["domain"]].append(row)
            self.assertTrue(row["source_usable"])
            self.assertFalse(row["native_adversarial_task"])
            self.assertEqual(row["oracle"]["source_field"], "evaluation_criteria")
            self.assertTrue(row["oracle"]["reward_basis"])
            self.assertEqual(len(row["source_task_sha256"]), 64)
            self.assertEqual(len(row["oracle"]["sha256"]), 64)
        self.assertEqual({key: len(value) for key, value in by_domain.items()}, expected_counts)

        for domain, rows in by_domain.items():
            upstream = json.loads((source_root / domain / "tasks.json").read_text())
            self.assertEqual(
                {row["source_task_id"] for row in rows},
                {task["id"] for task in upstream},
            )
            row_by_id = {row["source_task_id"]: row for row in rows}
            for task in upstream:
                row = row_by_id[task["id"]]
                self.assertEqual(
                    row["oracle"]["reward_basis"],
                    task["evaluation_criteria"]["reward_basis"],
                )
                self.assertEqual(
                    row["oracle"]["expected_action_names_in_order"],
                    [action["name"] for action in task["evaluation_criteria"].get("actions") or []],
                )

        tau_source = next(
            source
            for source in self.manifest["sources"]
            if source["source_id"] == "tau2-bench-v1.0.1"
        )
        locks = {entry["path"]: entry for entry in tau_source["input_files"]}
        self.assertIn("data/tau2/domains/banking_knowledge/tasks.json", locks)
        self.assertIn("data/tau2/domains/banking_knowledge/db.json", locks)
        document_lock = locks[
            "data/tau2/domains/banking_knowledge/documents"
        ]
        self.assertEqual(document_lock["kind"], "fixed_infrastructure_corpus")
        self.assertEqual(document_lock["file_count"], 698)
        self.assertEqual(len(document_lock["sha256"]), 64)

    def test_variants_and_attack_pairings_do_not_inflate_independent_n(self) -> None:
        boundary = [row for row in self.tau2 if row["boundary_adaptable"]]
        tau_counts = {
            domain: (
                sum(row["domain"] == domain for row in boundary),
                len({row["cluster_id"] for row in boundary if row["domain"] == domain}),
            )
            for domain in ("retail", "airline", "telecom", "banking_knowledge")
        }
        self.assertEqual(
            tau_counts,
            {
                "retail": (104, 51),
                "airline": (26, 21),
                "telecom": (1688, 7),
                "banking_knowledge": (97, 63),
            },
        )
        telecom = [row for row in self.tau2 if row["domain"] == "telecom"]
        self.assertEqual(len(telecom), 2285)
        self.assertEqual(len({row["cluster_id"] for row in telecom}), 11)
        self.assertTrue(all(row["variant"]["counts_as_independent_cluster"] is False for row in telecom))

        banking = [row for row in self.tau2 if row["domain"] == "banking_knowledge"]
        self.assertEqual(len(banking), 97)
        self.assertEqual(len({row["cluster_id"] for row in banking}), 63)
        self.assertEqual(
            len(
                {
                    row["cluster_basis"][
                        "verified_identity_sensitivity_cluster_id"
                    ]
                    for row in banking
                }
            ),
            68,
        )
        self.assertEqual(
            len(
                {
                    row["cluster_basis"][
                        "explicit_principal_sensitivity_cluster_id"
                    ]
                    for row in banking
                }
            ),
            70,
        )
        aliases = {
            (tuple(alias["task_ids"]), alias["evidence_tier"])
            for row in banking
            for alias in row["cluster_basis"]["conservative_alias_groups_applied"]
        }
        self.assertEqual(
            aliases,
            {
                (("task_004", "task_005"), "strong_verified_alias"),
                (("task_014", "task_015"), "strong_verified_alias"),
                (("task_032", "task_044"), "same_name_collision_conflict"),
                (("task_033", "task_051"), "same_name_collision_conflict"),
                (("task_035", "task_019"), "same_name_collision_conflict"),
                (("task_012", "task_024"), "same_name_collision_conflict"),
                (("task_007", "task_060"), "same_name_collision_conflict"),
            },
        )
        self.assertTrue(
            all(
                row["document_dependency_sensitivity"][
                    "required_document_corpus_is_fixed_infrastructure"
                ]
                for row in banking
            )
        )
        self.assertEqual(
            len(
                {
                    row["document_dependency_sensitivity"][
                        "document_connected_component_id"
                    ]
                    for row in banking
                }
            ),
            4,
        )

        expected_pairs = {"workspace": 33 * 6, "banking": 16 * 9, "slack": 17 * 5, "travel": 20 * 7}
        self.assertEqual(Counter(row["domain"] for row in self.pairings), expected_pairs)
        for domain, pair_count in expected_pairs.items():
            domain_pairs = [row for row in self.pairings if row["domain"] == domain]
            domain_users = [row for row in self.users if row["domain"] == domain]
            self.assertEqual(len(domain_pairs), pair_count)
            self.assertEqual(
                {row["cluster_id"] for row in domain_pairs},
                {row["cluster_id"] for row in domain_users},
            )
            self.assertTrue(
                all(row["counts_as_independent_cluster"] is False for row in domain_pairs)
            )

    def test_agentdojo_source_ids_and_oracle_polarity_are_preserved(self) -> None:
        self.assertEqual(len({(row["domain"], row["source_id"]) for row in self.users}), 86)
        self.assertEqual(
            len({(row["domain"], row["source_id"]) for row in self.injections}), 27
        )
        self.assertTrue(all(row["oracle_method"] == "utility" for row in self.users))
        self.assertTrue(all(row["oracle_method"] == "security" for row in self.injections))
        self.assertTrue(
            all("benign utility success" in row["oracle_semantics"] for row in self.users)
        )
        self.assertTrue(
            all("attack success" in row["oracle_semantics"] for row in self.injections)
        )
        for pair in self.pairings:
            self.assertEqual(pair["outcome_semantics"]["safety"], "not attack_success")
            self.assertTrue(pair["native_cartesian_pairing"])
            self.assertEqual(
                pair["injection_vector_resolution"]["mode"],
                "native_ground_truth_reachability",
            )

    def test_eligibility_uses_pooled_cross_domain_population_without_opening_gate(self) -> None:
        self.assertEqual(FORMAL_CLUSTER_FLOORS, (60, 100))
        self.assertEqual(FIXED_HELDOUT_CLUSTER_COST, 32)
        self.assertEqual(self.eligibility["decision"], "STOP")
        self.assertFalse(self.eligibility["formal_run_permitted"])
        populations = self.eligibility["populations"]
        expected_population_count = (
            len(TAU2_RQ1_CONTRASTS) + len(AGENTDOJO_RQ2_MECHANISMS) + 2 + 1
        )
        self.assertEqual(len(populations), expected_population_count)
        self.assertEqual(
            self.eligibility["estimand_contract"][
                "per_domain_minimum_cluster_requirement"
            ],
            None,
        )
        for row in populations:
            self.assertEqual(row["estimand"], "pooled_cross_domain_workflow_population")
            self.assertIsNone(row["per_domain_minimum_cluster_requirement"])
            if row["domains"]:
                self.assertAlmostEqual(
                    sum(row["primary_equal_domain_weights"].values()), 1.0
                )
                self.assertAlmostEqual(
                    sum(row["sensitivity_workflow_proportional_weights"].values()),
                    1.0,
                )
            self.assertTrue(row["independent_cluster_count_is_upper_bound"])
            self.assertEqual(row["verified_truly_independent_cluster_count"], 0)
            self.assertEqual(row["formal_selected_cluster_count"], 0)
            self.assertEqual(row["formal_decision"], "STOP")
            self.assertEqual(row["adapter_verified_cluster_count"], 0)

        rq1 = [row for row in populations if row["rq_id"] == "RQ1"]
        self.assertEqual(len(rq1), len(TAU2_RQ1_CONTRASTS))
        self.assertTrue(all(row["independent_cluster_count"] == 142 for row in rq1))
        self.assertTrue(all(row["meets_100_after_fixed_heldout"] for row in rq1))
        rq2 = [row for row in populations if row["rq_id"] == "RQ2"]
        self.assertEqual(len(rq2), len(AGENTDOJO_RQ2_MECHANISMS))
        self.assertTrue(all(row["independent_cluster_count"] == 86 for row in rq2))
        self.assertTrue(all(row["meets_60"] for row in rq2))
        self.assertTrue(all(not row["meets_60_after_fixed_heldout"] for row in rq2))
        rq3 = [row for row in populations if row["rq_id"] == "RQ3"]
        self.assertEqual([row["independent_cluster_count"] for row in rq3], [0, 0])
        rq4 = next(row for row in populations if row["rq_id"] == "RQ4")
        self.assertEqual(rq4["independent_cluster_count"], 228)
        self.assertTrue(rq4["meets_100_after_fixed_heldout"])
        upper = self.eligibility["per_rq_pooled_upper_bounds"]
        self.assertEqual(
            {
                rq: (
                    row["source_workflow_cluster_upper_bounds"],
                    row["after_fixed_G0_G1_pilot_upper_bounds"],
                )
                for rq, row in upper.items()
            },
            {
                "RQ1": ([142], [110]),
                "RQ2": ([86], [54]),
                "RQ3": ([0], [0]),
                "RQ4": ([228], [164]),
            },
        )
        self.assertTrue(
            all(row["formal_selected_cluster_count"] == 0 for row in upper.values())
        )

        cost = self.eligibility["heldout_cost"]
        self.assertEqual(cost["G0_episode_count"], 12)
        self.assertEqual(cost["G1_additional_episode_count"], 12)
        self.assertEqual(cost["variance_pilot_independent_workflows"], 20)
        self.assertEqual(cost["fixed_independent_workflows_removed_before_formal"], 32)
        self.assertIn("dynamic", cost["G2"])

    def test_proposed_splits_are_cluster_disjoint_and_formal_empty(self) -> None:
        self.assertEqual(tuple(self.splits["split_order"]), SPLIT_ORDER)
        self.assertFalse(self.splits["split_overlap_allowed"])
        self.assertFalse(self.splits["formal_run_permitted"])
        self.assertTrue(self.splits["formal_split_empty"])
        for population_id, population in self.splits["populations"].items():
            snapshots = population["splits"]
            self.assertEqual(set(snapshots), set(SPLIT_ORDER))
            sets = {split: set(snapshots[split]["cluster_ids"]) for split in SPLIT_ORDER}
            for index, left in enumerate(SPLIT_ORDER):
                for right in SPLIT_ORDER[index + 1 :]:
                    self.assertTrue(sets[left].isdisjoint(sets[right]))
            self.assertEqual(sets["formal"], set())
            self.assertEqual(sets["G2"], set())
            self.assertEqual(snapshots["formal"]["observation_ids"], [])
            self.assertEqual(snapshots["pilot"]["cluster_count"], 20)
            self.assertEqual(snapshots["G0"]["cluster_count"], 6)
            self.assertEqual(snapshots["G1"]["cluster_count"], 6)
            self.assertTrue(population["all_pairwise_cluster_intersections_empty"])
            self.assertEqual(population["formal_decision"], "STOP", population_id)

        # Every variant/pairing that shares a cluster inherits one split.
        for population_id, rows in (
            ("tau2_boundary_adaptable", [row for row in self.tau2 if row["boundary_adaptable"]]),
            ("agentdojo_native_attack_pairings", self.pairings),
        ):
            cluster_to_split = {}
            for split, snapshot in self.splits["populations"][population_id]["splits"].items():
                for cluster_id in snapshot["cluster_ids"]:
                    self.assertNotIn(cluster_id, cluster_to_split)
                    cluster_to_split[cluster_id] = split
            self.assertEqual({row["cluster_id"] for row in rows}, set(cluster_to_split))

    def test_split_assignment_does_not_create_clusters(self) -> None:
        clusters = {"a": "x", "b": "x", "c": "y", "d": "y"}
        assignment = _assign_nonformal_splits(clusters)
        self.assertEqual(set(assignment), set(clusters))
        self.assertNotIn("formal", assignment.values())
        self.assertEqual(
            assignment,
            _assign_nonformal_splits(dict(reversed(list(clusters.items())))),
        )

    def test_current_candidate_manifests_are_strict_subsets(self) -> None:
        coverage = self.eligibility["current_candidate_builder_coverage"]
        self.assertTrue(coverage["candidate_manifests_are_inventories_not_executable_packs"])
        self.assertEqual(coverage["tau2"]["selected_source_task_count"], 34)
        self.assertEqual(coverage["tau2"]["selected_full_cluster_count"], 27)
        self.assertEqual(coverage["agentdojo"]["selected_pairing_count"], 20)
        self.assertEqual(coverage["agentdojo"]["selected_full_cluster_count"], 20)
        self.assertLess(coverage["tau2"]["selected_source_task_count"], len(self.tau2))
        self.assertLess(coverage["agentdojo"]["selected_pairing_count"], len(self.pairings))


if __name__ == "__main__":
    unittest.main()
