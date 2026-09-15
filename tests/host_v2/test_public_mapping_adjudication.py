from __future__ import annotations

from copy import deepcopy
import unittest

from agentmembrane.host_v2.public_mapping_adjudication import (
    ALLOWED_DECISION_BASES,
    EXPECTED_PUBLIC_MAPPING_ROW_COUNT,
    adjudicate_mapping_reviews,
    validate_independent_mapping_review,
    validate_parity_fixture_plan,
)
from agentmembrane.host_v2.public_readiness import (
    HOST_ACTION_MECHANISMS,
    REQUIRED_PARITY_CATEGORIES,
)
from agentmembrane.host_v2.schema import IntegrityError, SchemaError


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
SHA_F = "f" * 64


def _expectations() -> tuple[dict, dict]:
    bindings = {
        "pack-a": {
            "manifest_sha256": SHA_A,
            "tasks_sha256": SHA_B,
            "taskpack_content_sha256": SHA_C,
        },
        "pack-b": {
            "manifest_sha256": SHA_D,
            "tasks_sha256": SHA_E,
            "taskpack_content_sha256": SHA_F,
        },
    }
    sources = {
        "pack-a": {f"a-{index:03d}": f"source-a-{index:03d}" for index in range(40)},
        "pack-b": {f"b-{index:03d}": f"source-b-{index:03d}" for index in range(68)},
    }
    return bindings, sources


def _evidence(index: int = 1) -> dict:
    return {
        "path": "data/host_boundary_v2/packs/example/tasks.jsonl",
        "file_sha256": SHA_A,
        "note": "Task-specific frozen row evidence.",
        "locator": {"kind": "line_range", "start": index, "end": index},
    }


def _review(review_id: str = "M1", reviewer_id: str = "reviewer-m1") -> dict:
    bindings, sources = _expectations()
    packs = []
    for pack_id in sorted(bindings):
        rows = []
        for index, (task_id, source_id) in enumerate(sources[pack_id].items(), start=1):
            rows.append(
                {
                    "task_id": task_id,
                    "source_workflow_id": source_id,
                    "status": "excluded",
                    "mechanisms": [],
                    "decision_basis": ["explicit_no_mechanism_analysis"],
                    "rationale": "Task-specific evidence excludes all six trusted mechanisms.",
                    "evidence": [_evidence(index)],
                }
            )
        packs.append({"pack_id": pack_id, **bindings[pack_id], "rows": rows})
    return {
        "schema_version": 1,
        "artifact_type": "agentmembrane_public_independent_mapping_review",
        "review_id": review_id,
        "reviewer": {
            "reviewer_id": reviewer_id,
            "mapping_author_id": "mapping-author",
            "independent_from_mapping_author": True,
            "independent_from_other_reviewer": True,
            "reviewed_at": "2026-08-30T12:00:00Z",
            "method": "Task-by-task review of frozen evidence.",
        },
        "definitions_sha256": SHA_F,
        "packs": packs,
    }


def _evidence_pointer(path: str, sha: str, pointer: str, note: str) -> dict:
    return {
        "path": path,
        "file_sha256": sha,
        "note": note,
        "locator": {"kind": "json_pointer", "pointer": pointer},
    }


def _plan(source_count: int = 20) -> dict:
    sources = []
    for source_index in range(source_count):
        cases = []
        for category in sorted(REQUIRED_PARITY_CATEGORIES):
            case_id = f"case-{source_index:02d}-{category}"
            cases.append(
                {
                    "case_id": case_id,
                    "category": category,
                    "native_evidence": [
                        _evidence_pointer(
                            "data/upstream/native-fixtures.json",
                            SHA_A,
                            f"/sources/{source_index}/{category}",
                            "Native-checker input and expected contract.",
                        )
                    ],
                    "projected_evidence": [
                        {
                            "path": "agentmembrane/host_v2/projected_checker.py",
                            "file_sha256": SHA_B,
                            "note": "Independent trusted-event projection contract.",
                            "locator": {"kind": "line_range", "start": 1, "end": 3},
                        }
                    ],
                    "expected_signals": {
                        "native": {"utility": True, "security": False},
                        "projected": {"utility": True, "security": False},
                        "expected_match": True,
                    },
                }
            )
        sources.append(
            {
                "source_task_id": f"source-{source_index:02d}",
                "task_id": f"task-{source_index:02d}",
                "cases": cases,
            }
        )
    return {
        "schema_version": 1,
        "artifact_type": "agentmembrane_public_checker_parity_fixture_plan",
        "plan_id": "offline-parity-fixture-plan",
        "benchmark": "example-public-benchmark",
        "pack_binding": {
            "pack_id": "pack-a",
            "manifest_sha256": SHA_A,
            "tasks_sha256": SHA_B,
            "taskpack_content_sha256": SHA_C,
        },
        "runtime_binding": {
            "runtime_id": "runtime-a",
            "runtime_implementation_sha256": SHA_D,
        },
        "adapter_binding": {
            "adapter_id": "adapter-a",
            "adapter_implementation_sha256": SHA_E,
        },
        "projected_checker_binding": {
            "projected_checker_id": "projected-a",
            "projected_checker_implementation_sha256": SHA_F,
        },
        "execution_authorized": False,
        "actual_execution_counts": {
            "task_execution_count": 0,
            "reset_count": 0,
            "dispatch_count": 0,
            "native_checker_invocation_count": 0,
            "projected_checker_invocation_count": 0,
            "parity_comparison_count": 0,
            "external_call_count": 0,
        },
        "namespace_contract": {
            "strategy": "fresh_per_case",
            "require_nonexistent_before_case": True,
            "reuse_permitted": False,
            "cleanup_required": True,
            "cleanup_verification": "Compare post-cleanup state SHA to pristine reset state.",
            "cleanup_on_failure": True,
        },
        "source_cases": sources,
    }


class IndependentMappingReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.bindings, self.sources = _expectations()

    def validate(self, artifact: dict) -> dict:
        return validate_independent_mapping_review(
            artifact,
            expected_pack_bindings=self.bindings,
            expected_task_sources=self.sources,
            definitions_sha256=SHA_F,
        )

    def test_valid_review_covers_two_packs_and_exactly_108_rows(self) -> None:
        result = self.validate(_review())
        self.assertEqual(result["pack_count"], 2)
        self.assertEqual(result["row_count"], EXPECTED_PUBLIC_MAPPING_ROW_COUNT)
        self.assertEqual(result["status_counts"]["excluded"], 108)
        self.assertEqual(len(ALLOWED_DECISION_BASES), 6)
        self.assertEqual(len(HOST_ACTION_MECHANISMS), 6)

    def test_status_and_evidence_fail_closed(self) -> None:
        no_evidence = _review()
        no_evidence["packs"][0]["rows"][0]["evidence"] = []
        with self.assertRaises(SchemaError):
            self.validate(no_evidence)

        mislabeled = _review()
        mislabeled["packs"][0]["rows"][0]["decision_basis"] = ["family"]
        with self.assertRaises(IntegrityError):
            self.validate(mislabeled)

        mapped_empty = _review()
        mapped_empty["packs"][0]["rows"][0]["status"] = "mapped"
        with self.assertRaises(IntegrityError):
            self.validate(mapped_empty)

        excluded_labeled = _review()
        excluded_labeled["packs"][0]["rows"][0]["mechanisms"] = [
            sorted(HOST_ACTION_MECHANISMS)[0]
        ]
        with self.assertRaises(IntegrityError):
            self.validate(excluded_labeled)

    def test_identity_hash_coverage_and_locator_mutations_fail(self) -> None:
        duplicate = _review()
        duplicate["packs"][0]["rows"][1]["task_id"] = duplicate["packs"][0]["rows"][0]["task_id"]
        with self.assertRaises(IntegrityError):
            self.validate(duplicate)

        wrong_source = _review()
        wrong_source["packs"][0]["rows"][0]["source_workflow_id"] = "other"
        with self.assertRaises(IntegrityError):
            self.validate(wrong_source)

        wrong_hash = _review()
        wrong_hash["packs"][0]["manifest_sha256"] = SHA_F
        with self.assertRaises(IntegrityError):
            self.validate(wrong_hash)

        escaping = _review()
        escaping["packs"][0]["rows"][0]["evidence"][0]["path"] = "../secret"
        with self.assertRaises(IntegrityError):
            self.validate(escaping)

        bad_line = _review()
        bad_line["packs"][0]["rows"][0]["evidence"][0]["locator"]["start"] = 0
        with self.assertRaises(IntegrityError):
            self.validate(bad_line)

    def test_adjudication_is_exact_intersection_and_never_approved(self) -> None:
        m1 = _review("M1", "reviewer-m1")
        m2 = _review("M2", "reviewer-m2")
        m2["packs"][0]["rows"][0]["status"] = "mapped"
        m2["packs"][0]["rows"][0]["mechanisms"] = [
            sorted(HOST_ACTION_MECHANISMS)[0]
        ]
        m2["packs"][0]["rows"][0]["decision_basis"] = ["explicit_authority_analysis"]
        result = adjudicate_mapping_reviews(
            m1,
            m2,
            expected_pack_bindings=self.bindings,
            expected_task_sources=self.sources,
            definitions_sha256=SHA_F,
        )
        self.assertEqual(result["decision"], "NO_GO")
        self.assertEqual(result["mapping_status"], "partial_consensus")
        self.assertFalse(result["approved_formal_mapping"])
        self.assertEqual(result["summary"]["consensus_count"], 107)
        self.assertEqual(result["summary"]["consensus_status_counts"]["excluded"], 107)
        self.assertEqual(result["summary"]["accepted_mapped_count"], 0)
        self.assertEqual(result["summary"]["disagreement_count"], 1)
        disputed = result["packs"][0]["rows"][0]
        self.assertEqual(disputed["status"], "unreviewed")
        self.assertEqual(disputed["mechanisms"], [])
        self.assertEqual(len(disputed["review_decisions"]), 2)
        self.assertTrue(all(not pack["approved_formal_mapping"] for pack in result["packs"]))

    def test_dual_review_independence_is_required(self) -> None:
        with self.assertRaises(IntegrityError):
            adjudicate_mapping_reviews(
                _review("M1", "same"),
                _review("M2", "same"),
                expected_pack_bindings=self.bindings,
                expected_task_sources=self.sources,
                definitions_sha256=SHA_F,
            )


class ParityFixturePlanTests(unittest.TestCase):
    def test_valid_plan_has_20_sources_120_cases_and_no_execution(self) -> None:
        plan = _plan()
        expected = {
            name: deepcopy(plan[name])
            for name in (
                "pack_binding",
                "runtime_binding",
                "adapter_binding",
                "projected_checker_binding",
            )
        }
        result = validate_parity_fixture_plan(plan, expected_bindings=expected)
        self.assertEqual(result["source_count"], 20)
        self.assertEqual(result["case_count"], 120)
        self.assertEqual(result["actual_execution_count"], 0)
        self.assertEqual(result["decision"], "NO_GO")

    def test_minimum_sources_and_exact_six_categories_fail_closed(self) -> None:
        with self.assertRaises(IntegrityError):
            validate_parity_fixture_plan(_plan(19))
        missing = _plan()
        missing["source_cases"][0]["cases"].pop()
        with self.assertRaises(IntegrityError):
            validate_parity_fixture_plan(missing)
        duplicate_category = _plan()
        duplicate_category["source_cases"][0]["cases"][1]["category"] = (
            duplicate_category["source_cases"][0]["cases"][0]["category"]
        )
        with self.assertRaises(IntegrityError):
            validate_parity_fixture_plan(duplicate_category)

    def test_case_ids_bindings_and_execution_counts_fail_closed(self) -> None:
        duplicate = _plan()
        duplicate["source_cases"][1]["cases"][0]["case_id"] = (
            duplicate["source_cases"][0]["cases"][0]["case_id"]
        )
        with self.assertRaises(IntegrityError):
            validate_parity_fixture_plan(duplicate)
        executed = _plan()
        executed["actual_execution_counts"]["native_checker_invocation_count"] = 1
        with self.assertRaises(IntegrityError):
            validate_parity_fixture_plan(executed)
        authorized = _plan()
        authorized["execution_authorized"] = True
        with self.assertRaises(IntegrityError):
            validate_parity_fixture_plan(authorized)
        reused = _plan()
        reused["namespace_contract"]["reuse_permitted"] = True
        with self.assertRaises(IntegrityError):
            validate_parity_fixture_plan(reused)

    def test_native_and_projected_evidence_and_signals_are_independent(self) -> None:
        copied_evidence = _plan()
        case = copied_evidence["source_cases"][0]["cases"][0]
        case["projected_evidence"] = deepcopy(case["native_evidence"])
        with self.assertRaises(IntegrityError):
            validate_parity_fixture_plan(copied_evidence)

        absent_projected_signal = _plan()
        signals = absent_projected_signal["source_cases"][0]["cases"][0]["expected_signals"]
        signals["projected"] = {"utility": None, "security": None}
        with self.assertRaises(IntegrityError):
            validate_parity_fixture_plan(absent_projected_signal)

        mismatch = _plan()
        mismatch["source_cases"][0]["cases"][0]["expected_signals"]["projected"]["security"] = True
        with self.assertRaises(IntegrityError):
            validate_parity_fixture_plan(mismatch)

    def test_unknown_fields_and_wrong_binding_are_rejected(self) -> None:
        unknown = _plan()
        unknown["observed_parity"] = 1.0
        with self.assertRaises(SchemaError):
            validate_parity_fixture_plan(unknown)
        plan = _plan()
        expected = {
            name: deepcopy(plan[name])
            for name in (
                "pack_binding",
                "runtime_binding",
                "adapter_binding",
                "projected_checker_binding",
            )
        }
        expected["adapter_binding"]["adapter_implementation_sha256"] = SHA_A
        with self.assertRaises(IntegrityError):
            validate_parity_fixture_plan(plan, expected_bindings=expected)


if __name__ == "__main__":
    unittest.main()
