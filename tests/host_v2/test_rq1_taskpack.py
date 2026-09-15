from __future__ import annotations

from collections import Counter, defaultdict
import json
from pathlib import Path
import tempfile
import unittest

from agentmembrane.host_v2.rq1_taskpack import (
    ADMISSION_FAMILIES,
    BINDING_LIFECYCLE_FAMILIES,
    COMMITTED_PACK_ROOT,
    DEFERRED_CARRIER_FAMILIES,
    LIFECYCLE_MATRIX_BOUNDARIES,
    PACK_ID,
    load_rq1_taskpack,
    materialize_rq1_taskpack,
    validate_rq1_taskpack,
)
from agentmembrane.host_v2.taskpacks import taskpack_content_sha256, verify_taskpack


class RQ1TaskpackTests(unittest.TestCase):
    def test_committed_pack_is_hashed_nonclaim_sentinel_bank(self) -> None:
        pack = load_rq1_taskpack(COMMITTED_PACK_ROOT)
        generic = verify_taskpack(pack)
        canonical = validate_rq1_taskpack(pack)

        self.assertEqual(pack.pack_id, PACK_ID)
        parameters = pack.manifest["transformation"]["parameters"]
        self.assertEqual(parameters["construct_id"], "authority_admission_boundary")
        self.assertEqual(parameters["proposal_alignment"], "RQ1_authority_admission")
        self.assertTrue(generic["valid"])
        self.assertFalse(generic["claim_eligible"])
        self.assertFalse(generic["population_claim_eligible"])
        self.assertTrue(canonical["valid"])
        self.assertEqual(pack.manifest["splits"], {"gate": 36, "formal": 0})
        self.assertEqual(pack.manifest["task_count"], 36)
        self.assertEqual(pack.manifest["cluster_count"], 18)
        self.assertEqual(len(taskpack_content_sha256(pack)), 64)
        self.assertEqual(canonical["formal_rows"], 0)
        self.assertEqual(canonical["independently_authored_pairs"], 0)
        self.assertEqual(canonical["scientific_status"], "nonclaim_engineering_bank")

        source = json.loads(
            (pack.root / "source" / "source_inventory.json").read_text(encoding="utf-8")
        )
        self.assertFalse(source["claim_eligible"])
        self.assertEqual(source["construct_id"], "authority_admission_boundary")
        self.assertEqual(source["proposal_alignment"], "RQ1_authority_admission")
        self.assertFalse(source["authorship"]["independently_authored"])
        self.assertEqual(source["declared_pairs_per_family"], 1)
        self.assertEqual(source["formal_rows"], 0)
        self.assertIn("not ten", source["scale_shortfall"].lower())

    def test_every_family_has_one_honest_benign_adversarial_twin(self) -> None:
        pack = load_rq1_taskpack(COMMITTED_PACK_ROOT)
        expected = (*ADMISSION_FAMILIES, *BINDING_LIFECYCLE_FAMILIES)
        self.assertEqual(
            Counter(task.family for task in pack.tasks),
            Counter({family: 2 for family in expected}),
        )
        pairs: dict[str, list[object]] = defaultdict(list)
        for task in pack.tasks:
            pairs[task.pair_id].append(task)
            self.assertEqual(task.split, "gate")
            self.assertEqual(task.origin.value, "authored_synthetic")
            self.assertFalse(task.metadata["claim_bearing"])
            self.assertEqual(task.metadata["construct_id"], "authority_admission_boundary")
            self.assertEqual(task.metadata["proposal_alignment"], "RQ1_authority_admission")
            self.assertFalse(task.metadata["authorship"]["independently_authored"])
            self.assertFalse(task.metadata["eligibility"]["formal"])
            self.assertTrue(task.metadata["eligibility"]["zero_token_assay"])
            self.assertTrue(task.metadata["reset_contract"]["fresh_session_per_execution"])
            self.assertFalse(task.metadata["reset_contract"]["cross_arm_state_reuse_permitted"])
            self.assertEqual(
                task.metadata["utility_contract"]["system_task_utility"][
                    "source_task_id"
                ],
                task.metadata["source_task_id"],
            )
        self.assertEqual(len(pairs), 18)
        for pair in pairs.values():
            self.assertEqual({task.pair_role for task in pair}, {"benign", "adversarial"})
            self.assertEqual(len({task.cluster_id for task in pair}), 1)
            self.assertEqual(len({task.family for task in pair}), 1)

    def test_f0_and_lifecycle_oracles_use_exact_canonical_contracts(self) -> None:
        pack = load_rq1_taskpack(COMMITTED_PACK_ROOT)
        f0 = next(
            task
            for task in pack.tasks
            if task.family == "F0_response" and task.pair_role == "benign"
        )
        response = f0.metadata["oracle_spec"]["outcomes"]["benign"]
        self.assertTrue(response["response_only"])
        self.assertEqual(
            response["artifact"]["expected"],
            {
                "artifact_type": "terminal_text",
                "source_task_id": "rq1-f0-response-benign-s01",
                "text": "rq1-response-ok",
            },
        )
        self.assertEqual(
            response["artifact"]["source_task_id"],
            "rq1-f0-response-benign-s01",
        )

        carrier_by_family = {
            "queued-work": ["capability_work_queued"],
            "action-proposal": ["proposal_submitted"],
            "memory-artifact": ["memory_proposed"],
        }
        for task in pack.tasks:
            outcomes = task.metadata["oracle_spec"]["outcomes"]
            lifecycle = outcomes.get("lifecycle_carryover")
            if lifecycle is None:
                continue
            self.assertNotIn("boundary", lifecycle)
            self.assertEqual(lifecycle["boundary_kinds"], ["capability_expired"])
            self.assertTrue(lifecycle["event"]["unauthorized"])
            if task.family in carrier_by_family:
                self.assertEqual(
                    lifecycle["carrier_kinds"], carrier_by_family[task.family]
                )
        renewal = next(
            task
            for task in pack.tasks
            if task.family == "renewal" and task.pair_role == "adversarial"
        )
        self.assertEqual(
            set(renewal.metadata["oracle_spec"]["outcomes"]),
            {"direct", "lifecycle_carryover"},
        )

    def test_fixed_trace_and_adaptive_context_are_separate_and_nonleaking(self) -> None:
        pack = load_rq1_taskpack(COMMITTED_PACK_ROOT)
        for task in pack.tasks:
            metadata = task.metadata
            fixed = metadata["trusted_fixed_trace"]
            adaptive = metadata["visible_context_profiles"]["objective_aware_adaptive"]
            self.assertFalse(fixed["model_visible"])
            self.assertEqual(adaptive["execution_track"], "adaptive_end_to_end")
            self.assertEqual(
                metadata["execution_tracks"],
                {
                    "scripted_route_replay": "fixed_trace_host_replay",
                    "objective_aware_adaptive": "adaptive_end_to_end",
                },
            )
            serialized = json.dumps(adaptive, sort_keys=True).lower()
            for forbidden in (
                "trace_id",
                "trace_ref",
                "oracle_ref",
                "vulnerable",
                "protected",
                "condition_id",
                "binding_contrast",
                "ordered_operation_names",
                "symbolic_action_templates",
            ):
                self.assertNotIn(forbidden, serialized)
            for forbidden in (
                "condition_id",
                "oracle_spec",
                "trusted_fixed_trace",
                "capability_id",
            ):
                self.assertNotIn(forbidden, serialized)
            self.assertIsInstance(metadata["lifecycle_transitions"], list)
            for row in metadata["lifecycle_transitions"]:
                self.assertEqual(set(row), {"after_turn", "transition"})
                self.assertIsInstance(row["after_turn"], int)
                self.assertIsInstance(row["transition"], str)

            trace = json.loads(
                (pack.root / fixed["trace_ref"]).read_text(encoding="utf-8")
            )
            first = trace["turns"][0]
            self.assertEqual(len(first["actions"]), 1)
            self.assertEqual(first["actions"][0]["op"], "request_admission")
            self.assertTrue(
                all(
                    row["after_turn"] >= 2
                    for row in metadata["lifecycle_transitions"]
                )
            )

    def test_frozen_admission_requests_and_lifecycle_matrix_are_complete(self) -> None:
        pack = load_rq1_taskpack(COMMITTED_PACK_ROOT)
        matrix_cells: set[tuple[str, str]] = set()
        for task in pack.tasks:
            request = task.metadata["host_fixture"]["admission_request"]
            first_turn = json.loads(
                (
                    pack.root
                    / task.metadata["trusted_fixed_trace"]["trace_ref"]
                ).read_text(encoding="utf-8")
            )["turns"][0]
            self.assertEqual(first_turn["actions"][0]["op"], "request_admission")
            self.assertEqual(
                set(request),
                {
                    "principal_id",
                    "lease_id",
                    "declared_purpose",
                    "requested_receptor",
                    "requested_capability_set",
                    "resource_scopes",
                    "delegation",
                    "maximum_delegation_depth",
                },
            )
            if task.family not in DEFERRED_CARRIER_FAMILIES:
                self.assertNotIn("fixed_trace_lifecycle_matrix", task.metadata)
                continue
            matrix = task.metadata["fixed_trace_lifecycle_matrix"]
            self.assertFalse(matrix["authored_pair_expansion"])
            self.assertEqual(matrix["independent_authored_pairs_added"], 0)
            self.assertEqual(
                set(matrix["boundaries"]), set(LIFECYCLE_MATRIX_BOUNDARIES)
            )
            self.assertEqual(len(matrix["cells"]), 3)
            for cell in matrix["cells"]:
                matrix_cells.add((cell["boundary"], cell["carrier"]))
                self.assertTrue(
                    all(row["after_turn"] == 2 for row in cell["lifecycle_transitions"])
                )
                self.assertEqual(cell["authored_pair_expansion"], False)
        self.assertEqual(
            matrix_cells,
            {
                (boundary, carrier)
                for boundary in LIFECYCLE_MATRIX_BOUNDARIES
                for carrier in DEFERRED_CARRIER_FAMILIES
            },
        )

    def test_adversarial_oracles_cover_exactly_four_canonical_endpoints(self) -> None:
        pack = load_rq1_taskpack(COMMITTED_PACK_ROOT)
        categories = {
            category
            for task in pack.tasks
            if task.pair_role == "adversarial"
            for category in task.metadata["oracle_spec"]["outcomes"]
        }
        self.assertEqual(
            categories,
            {"direct", "host_mediated", "composite", "lifecycle_carryover"},
        )
        f5 = next(
            task
            for task in pack.tasks
            if task.family == "F5_ambient_workflow"
            and task.pair_role == "adversarial"
        )
        composite = f5.metadata["oracle_spec"]["outcomes"]["composite"]
        self.assertEqual(composite["event"]["kind"], "cross_tool_terminal")
        self.assertEqual(composite["event"]["resource"], "project:item")
        self.assertEqual(composite["minimum_parent_events"], 2)

    def test_materialization_is_deterministic_and_tamper_evident(self) -> None:
        committed = load_rq1_taskpack(COMMITTED_PACK_ROOT)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "rq1-controlled-v2.2"
            materialize_rq1_taskpack(root)
            rebuilt = load_rq1_taskpack(root)
            self.assertEqual(
                taskpack_content_sha256(rebuilt), taskpack_content_sha256(committed)
            )
            fixture = next((root / "fixtures" / "traces").glob("*.json"))
            fixture.write_bytes(fixture.read_bytes() + b"\n")
            report = verify_taskpack(rebuilt)
            self.assertFalse(report["valid"])
            self.assertTrue(any(not value for key, value in report["checks"].items() if key.startswith("fixture_")))


if __name__ == "__main__":
    unittest.main()
