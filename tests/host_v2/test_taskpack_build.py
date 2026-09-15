from __future__ import annotations

from collections import defaultdict
import json
from pathlib import Path
import unittest

from agentmembrane.host_v2.schema import canonical_json_bytes, sha256_bytes, sha256_json
from agentmembrane.host_v2.taskpack_build import (
    AGENTDOJO_PACK_DIR,
    AGENTDOJO_PACK_ID,
    PROTOCOL_SPLITS,
    TAU2_PACK_DIR,
    TAU2_PACK_ID,
    assign_protocol_splits,
    check_taskpacks,
)
from agentmembrane.host_v2.taskpacks import load_taskpack, verify_taskpack


REPO_ROOT = Path(__file__).resolve().parents[2]
PACKS_ROOT = REPO_ROOT / "data/host_boundary_v2/packs"
TASKPACK_INPUT_ROOT = REPO_ROOT / "data/host_boundary_v2/taskpacks"


def _json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"expected an object in {path}")
    return value


def _sha(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


PACK_CASES = (
    {
        "directory": TAU2_PACK_DIR,
        "pack_id": TAU2_PACK_ID,
        "candidate_file": "tau2_candidate_manifest.json",
        "candidate_count": 34,
        "cluster_count": 27,
        "task_count": 68,
        "domain_count": 3,
        "split_cluster_counts": {"G0": 6, "G1": 6, "G2": 6, "pilot": 9, "formal": 0},
        "pilot_shortfall": 11,
        "formal_shortfalls": (33, 73),
    },
    {
        "directory": AGENTDOJO_PACK_DIR,
        "pack_id": AGENTDOJO_PACK_ID,
        "candidate_file": "agentdojo_candidate_manifest.json",
        "candidate_count": 20,
        "cluster_count": 20,
        "task_count": 40,
        "domain_count": 4,
        "split_cluster_counts": {"G0": 6, "G1": 6, "G2": 6, "pilot": 2, "formal": 0},
        "pilot_shortfall": 18,
        "formal_shortfalls": (40, 80),
    },
)


class FrozenTaskPackBuildTests(unittest.TestCase):
    def test_committed_outputs_reproduce_byte_for_byte(self) -> None:
        report = check_taskpacks(repo_root=REPO_ROOT, output_root=PACKS_ROOT)
        self.assertTrue(report["valid"], report)
        self.assertEqual(report["expected_tree_sha256"], report["actual_tree_sha256"])
        self.assertEqual(report["missing"], [])
        self.assertEqual(report["unexpected"], [])
        self.assertEqual(report["changed"], [])

    def test_build_report_forbids_formal_or_external_execution(self) -> None:
        report = _json(PACKS_ROOT / "build_report.json")
        self.assertEqual(report["status"], "calibration_variance_only")
        self.assertFalse(report["formal_run_permitted"])
        self.assertFalse(report["external_services_used"])
        self.assertEqual(report["model_calls"], 0)
        self.assertEqual({item["pack_id"] for item in report["packs"]}, {TAU2_PACK_ID, AGENTDOJO_PACK_ID})

    def test_manifests_lock_every_input_transform_fixture_and_task(self) -> None:
        required_parameters = {
            "source_id",
            "source_url",
            "version_or_commit",
            "license",
            "data_class",
            "source_split",
            "raw_file_hashes",
            "selection_rule",
            "selected_source_task_ids",
            "transformation_script_hash",
            "transformed_task_hash",
            "fixture_hashes",
            "initial_state_hashes",
            "oracle_hashes",
            "gate_split_ids",
            "variance_pilot_split_ids",
            "formal_split_ids",
        }
        for case in PACK_CASES:
            with self.subTest(pack=case["pack_id"]):
                root = PACKS_ROOT / case["directory"]
                pack = load_taskpack(root)
                report = verify_taskpack(pack)
                self.assertTrue(report["valid"], report)
                self.assertFalse(report["claim_eligible"])
                self.assertFalse(report["population_claim_eligible"])
                self.assertEqual(report["task_count"], case["task_count"])
                self.assertEqual(report["cluster_count"], case["cluster_count"])

                manifest = pack.manifest
                self.assertFalse(manifest["claim_eligible"])
                self.assertEqual(manifest["splits"], {"gate": case["task_count"], "formal": 0})
                parameters = manifest["transformation"]["parameters"]
                self.assertLessEqual(required_parameters, set(parameters))
                self.assertEqual(
                    parameters["raw_file_hashes"],
                    {item["path"]: item["sha256"] for item in manifest["upstream"]["raw_files"]},
                )
                self.assertEqual(
                    parameters["fixture_hashes"],
                    {item["path"]: item["sha256"] for item in manifest["fixtures"]},
                )
                self.assertEqual(
                    parameters["transformation_script_hash"],
                    manifest["transformation"]["script_sha256"],
                )
                self.assertEqual(
                    parameters["transformed_task_hash"],
                    manifest["transformation"]["tasks_sha256"],
                )
                for item in manifest["upstream"]["raw_files"] + manifest["fixtures"]:
                    self.assertEqual(_sha(root / item["path"]), item["sha256"])
                self.assertEqual(
                    _sha(root / manifest["transformation"]["script_path"]),
                    manifest["transformation"]["script_sha256"],
                )
                self.assertEqual(
                    _sha(root / "tasks.jsonl"), manifest["transformation"]["tasks_sha256"]
                )

    def test_protocol_splits_are_cluster_disjoint_and_formal_is_empty(self) -> None:
        self.assertEqual(PROTOCOL_SPLITS, ("G0", "G1", "G2", "pilot", "formal"))
        for case in PACK_CASES:
            with self.subTest(pack=case["pack_id"]):
                root = PACKS_ROOT / case["directory"]
                pack = load_taskpack(root)
                split = _json(root / "fixtures/split_manifest.json")
                self.assertEqual(tuple(split["split_order"]), PROTOCOL_SPLITS)
                self.assertFalse(split["split_overlap_allowed"])
                self.assertTrue(split["all_pairwise_cluster_intersections_empty"])
                self.assertEqual(set(split["splits"]), set(PROTOCOL_SPLITS))

                cluster_sets = {
                    name: set(value["cluster_ids"])
                    for name, value in split["splits"].items()
                }
                for index, left in enumerate(PROTOCOL_SPLITS):
                    for right in PROTOCOL_SPLITS[index + 1 :]:
                        self.assertTrue(cluster_sets[left].isdisjoint(cluster_sets[right]))
                self.assertEqual(
                    set().union(*cluster_sets.values()),
                    {task.cluster_id for task in pack.tasks},
                )
                self.assertEqual(
                    {name: len(values) for name, values in cluster_sets.items()},
                    case["split_cluster_counts"],
                )
                self.assertEqual(split["splits"]["formal"]["task_ids"], [])
                self.assertEqual(split["splits"]["formal"]["cluster_ids"], [])

                task_by_id = {task.task_id: task for task in pack.tasks}
                parameters = pack.manifest["transformation"]["parameters"]
                self.assertEqual(parameters["formal_split_ids"], [])
                self.assertEqual(
                    parameters["variance_pilot_split_ids"], split["splits"]["pilot"]["task_ids"]
                )
                self.assertEqual(
                    parameters["gate_split_ids"],
                    {name: split["splits"][name]["task_ids"] for name in ("G0", "G1", "G2")},
                )
                for name, snapshot in split["splits"].items():
                    for task_id in snapshot["task_ids"]:
                        task = task_by_id[task_id]
                        self.assertEqual(task.metadata["protocol_split"], name)
                        self.assertEqual(task.split, "formal" if name == "formal" else "gate")
                        self.assertEqual(task.metadata["claim_bearing"], name == "formal")

    def test_machine_readable_shortfall_matches_real_inventory(self) -> None:
        for case in PACK_CASES:
            with self.subTest(pack=case["pack_id"]):
                root = PACKS_ROOT / case["directory"]
                shortfall = _json(root / "fixtures/shortfall.json")
                self.assertEqual(shortfall["status"], "calibration_variance_only")
                self.assertFalse(shortfall["claim_eligible"])
                self.assertFalse(shortfall["claim_bearing"])
                self.assertFalse(shortfall["formal_run_permitted"])
                self.assertTrue(shortfall["formal_split_empty"])
                self.assertEqual(shortfall["inventory"]["cluster_count"], case["cluster_count"])
                self.assertEqual(shortfall["inventory"]["domain_count"], case["domain_count"])
                self.assertEqual(shortfall["variance_pilot"]["required_clusters_per_primary_contrast"], 20)
                self.assertEqual(
                    shortfall["variance_pilot"]["selected_disjoint_cluster_count"],
                    case["split_cluster_counts"]["pilot"],
                )
                self.assertEqual(shortfall["variance_pilot"]["shortfall"], case["pilot_shortfall"])
                formal = shortfall["formal_requirement"]
                self.assertEqual(formal["minimum_clusters_if_q_at_or_below_0_30"], 60)
                self.assertEqual(formal["minimum_clusters_if_q_above_0_30"], 100)
                self.assertEqual(
                    (formal["inventory_shortfall_to_60"], formal["inventory_shortfall_to_100"]),
                    case["formal_shortfalls"],
                )
                self.assertEqual(formal["selected_formal_clusters"], 0)
                self.assertFalse(formal["invented_variants_permitted"])
                for contrast in shortfall["contrasts"]:
                    self.assertEqual(contrast["status"], "formal_shortfall")
                    self.assertEqual(contrast["inventory_cluster_count"], case["cluster_count"])
                    self.assertEqual(contrast["formal_selected_cluster_count"], 0)
                    self.assertEqual(
                        (contrast["inventory_shortfall_to_60"], contrast["inventory_shortfall_to_100"]),
                        case["formal_shortfalls"],
                    )

    def test_each_candidate_has_exact_benign_adversarial_fixtures_and_oracle(self) -> None:
        for case in PACK_CASES:
            with self.subTest(pack=case["pack_id"]):
                root = PACKS_ROOT / case["directory"]
                pack = load_taskpack(root)
                candidates = _json(TASKPACK_INPUT_ROOT / case["candidate_file"])["candidates"]
                self.assertEqual(len(candidates), case["candidate_count"])
                by_pair: dict[str, list] = defaultdict(list)
                for task in pack.tasks:
                    by_pair[task.pair_id].append(task)
                    fixture_path = root / task.fixture_ref
                    oracle_path = root / task.oracle_ref
                    fixture = _json(fixture_path)
                    oracle = _json(oracle_path)
                    self.assertEqual(task.metadata["fixture_sha256"], _sha(fixture_path))
                    self.assertEqual(task.metadata["oracle_sha256"], _sha(oracle_path))
                    self.assertEqual(fixture["oracle_ref"], task.oracle_ref)
                    self.assertEqual(fixture["oracle_sha256"], _sha(oracle_path))
                    self.assertEqual(fixture["pair_role"], task.pair_role)
                    self.assertEqual(
                        fixture["initial_state_sha256"], sha256_json(fixture["initial_state"])
                    )
                    self.assertEqual(
                        fixture["initial_state_sha256"], task.metadata["initial_state_sha256"]
                    )
                    self.assertEqual(fixture["execution_mode"], "offline_declarative_fixture")
                    self.assertFalse(fixture["network_access"])
                    self.assertFalse(fixture["imports_upstream_runtime"])
                    self.assertFalse(oracle["network_access"])
                self.assertEqual(len(by_pair), case["candidate_count"])
                for tasks in by_pair.values():
                    self.assertEqual({task.pair_role for task in tasks}, {"benign", "adversarial"})
                    self.assertEqual(len(tasks), 2)
                    self.assertEqual(len({task.cluster_id for task in tasks}), 1)
                    self.assertEqual(len({task.metadata["protocol_split"] for task in tasks}), 1)

    def test_candidate_identity_and_source_hashes_survive_conversion(self) -> None:
        tau_candidates = _json(TASKPACK_INPUT_ROOT / "tau2_candidate_manifest.json")["candidates"]
        tau_by_source = {
            f"{item['domain']}:{item['upstream_task_id']}": item for item in tau_candidates
        }
        tau = load_taskpack(PACKS_ROOT / TAU2_PACK_DIR)
        self.assertEqual(
            tau.manifest["transformation"]["parameters"]["selected_source_task_ids"],
            sorted(tau_by_source),
        )
        for task in tau.tasks:
            candidate = tau_by_source[task.metadata["source_task_id"]]
            fixture = _json(tau.root / task.fixture_ref)
            oracle = _json(tau.root / task.oracle_ref)
            self.assertEqual(task.metadata["source_task_sha256"], candidate["source_hash"])
            self.assertEqual(fixture["upstream_task_sha256"], candidate["source_hash"])
            self.assertEqual(sha256_json(fixture["upstream_task"]), candidate["source_hash"])
            self.assertEqual(oracle["source_task_sha256"], candidate["source_hash"])
            self.assertEqual(oracle["policy_profile_id"], candidate["policy_requirement"])
            self.assertEqual(
                fixture["extension"] is None,
                task.pair_role == "benign",
            )

        dojo_candidates = _json(
            TASKPACK_INPUT_ROOT / "agentdojo_candidate_manifest.json"
        )["candidates"]
        dojo_by_id = {item["candidate_id"]: item for item in dojo_candidates}
        dojo = load_taskpack(PACKS_ROOT / AGENTDOJO_PACK_DIR)
        self.assertEqual(
            dojo.manifest["transformation"]["parameters"]["selected_source_task_ids"],
            sorted(dojo_by_id),
        )
        for task in dojo.tasks:
            candidate = dojo_by_id[task.metadata["candidate_id"]]
            fixture = _json(dojo.root / task.fixture_ref)
            oracle = _json(dojo.root / task.oracle_ref)
            self.assertEqual(task.metadata["candidate_sha256"], sha256_json(candidate))
            self.assertEqual(fixture["user_task"], candidate["original_user_task"])
            self.assertEqual(oracle["user_task"]["id"], candidate["original_user_task"]["id"])
            if task.pair_role == "adversarial":
                self.assertTrue(fixture["injection_enabled"])
                self.assertEqual(fixture["injection_task"], candidate["original_injection_task"])
                self.assertEqual(fixture["injection_vector"], candidate["injection_vector"])
            else:
                self.assertFalse(fixture["injection_enabled"])
                self.assertIsNone(fixture["injection_task"])
                self.assertIsNone(fixture["injection_vector"])

    def test_split_assignment_is_order_independent_and_does_not_invent_clusters(self) -> None:
        clusters = {
            "alpha-1": "alpha",
            "alpha-2": "alpha",
            "beta-1": "beta",
            "beta-2": "beta",
            "gamma-1": "gamma",
        }
        forward = assign_protocol_splits(clusters, gate_cluster_target=1)
        reverse = assign_protocol_splits(dict(reversed(tuple(clusters.items()))), gate_cluster_target=1)
        self.assertEqual(forward, reverse)
        self.assertEqual(set(forward), set(clusters))
        self.assertEqual(set(forward.values()), {"G0", "G1", "G2", "pilot"})

    def test_canonical_json_hash_helper_matches_fixture_bytes(self) -> None:
        # Generated JSON is deliberately canonical plus one trailing newline.
        for case in PACK_CASES:
            root = PACKS_ROOT / case["directory"]
            value = _json(root / "fixtures/shortfall.json")
            self.assertEqual(
                (root / "fixtures/shortfall.json").read_bytes(),
                canonical_json_bytes(value) + b"\n",
            )


if __name__ == "__main__":
    unittest.main()
