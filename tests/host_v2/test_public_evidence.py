from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from agentmembrane.host_v2.public_evidence import (
    MINIMUM_FORMAL_CLUSTERS,
    OVERLAY_ID,
    PREFERRED_FORMAL_CLUSTERS,
    SPLIT_ORDER,
    TRUSTED_MECHANISM_IDS,
    build_overlay_documents,
    materialize_public_evidence_overlay,
    validate_mechanism_mapping_draft,
    verify_public_evidence_overlay,
)
from agentmembrane.host_v2.public_readiness import (
    HOST_ACTION_MECHANISMS,
    validate_mechanism_mapping,
)
from agentmembrane.host_v2.schema import IntegrityError, sha256_bytes
from agentmembrane.host_v2.taskpacks import load_taskpack, taskpack_content_sha256


REPO_ROOT = Path(__file__).resolve().parents[2]
PACKS_ROOT = REPO_ROOT / "data/host_boundary_v2/packs"
PACK_DIRECTORIES = {
    "host-v2-agentdojo-v0.1.35-v1": "agentdojo-v0.1.35-v1",
    "host-v2-tau2-v1.0.1": "tau2-v1.0.1",
}
EXPECTED_CONTENT_SHA256S = {
    "host-v2-agentdojo-v0.1.35-v1": (
        "2711f5d019a597e54fdb62b56de99db4133127cf58f633908a34b641c3aa2774"
    ),
    "host-v2-tau2-v1.0.1": (
        "7a4bb8bc0596f66e831bedbc7c96350d6d55e8fc8ad5f8d6efef52e4dee71179"
    ),
}


def _object(payload: bytes) -> dict:
    value = json.loads(payload.decode("utf-8"))
    if not isinstance(value, dict):
        raise AssertionError("fixture payload is not an object")
    return value


class PublicEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.documents = build_overlay_documents(REPO_ROOT)
        cls.manifest = _object(cls.documents["manifest.json"])
        cls.packs = {
            pack_id: load_taskpack(PACKS_ROOT / directory)
            for pack_id, directory in PACK_DIRECTORIES.items()
        }

    def test_exact_six_trusted_definitions_are_frozen(self) -> None:
        definitions = _object(self.documents["mechanism_definitions.json"])
        ids = [entry["mechanism_id"] for entry in definitions["definitions"]]
        self.assertEqual(tuple(ids), TRUSTED_MECHANISM_IDS)
        self.assertEqual(set(ids), HOST_ACTION_MECHANISMS)
        self.assertEqual(len(ids), 6)
        self.assertFalse(definitions["pooling_with_semantic_rq2_permitted"])
        self.assertEqual(definitions["proposal_alignment"], "RQ1b_host_mediated")

    def test_mapping_drafts_cover_every_task_without_label_inference(self) -> None:
        definitions_sha = sha256_bytes(self.documents["mechanism_definitions.json"])
        for pack_id, pack in self.packs.items():
            path = f"packs/{pack_id}/mechanism_mapping.draft.json"
            mapping = _object(self.documents[path])
            self.assertEqual(mapping["definitions_sha256"], definitions_sha)
            self.assertFalse(mapping["review"]["independent_from_mapping_author"])
            self.assertEqual(mapping["review"]["decision"], "not_reviewed")
            self.assertEqual(len(mapping["rows"]), len(pack.tasks))
            self.assertEqual(
                {row["task_id"] for row in mapping["rows"]},
                {task.task_id for task in pack.tasks},
            )
            self.assertEqual({row["status"] for row in mapping["rows"]}, {"ambiguous"})
            self.assertTrue(all(row["mechanisms"] == [] for row in mapping["rows"]))
            for row in mapping["rows"]:
                rationale = row["rationale"].casefold()
                self.assertNotIn("family=", rationale)
                self.assertNotIn("rq_targets", rationale)
                self.assertNotIn("adversarial implies", rationale)
                self.assertGreaterEqual(len(row["evidence_refs"]), 3)
            logical_sha = taskpack_content_sha256(pack)
            validate_mechanism_mapping_draft(
                mapping, pack=pack, taskpack_sha256=logical_sha
            )
            with self.assertRaises(IntegrityError):
                validate_mechanism_mapping(
                    mapping, pack=pack, taskpack_sha256=logical_sha
                )

    def test_mapping_draft_status_semantics_fail_closed(self) -> None:
        pack_id = "host-v2-agentdojo-v0.1.35-v1"
        pack = self.packs[pack_id]
        mapping = deepcopy(
            _object(self.documents[f"packs/{pack_id}/mechanism_mapping.draft.json"])
        )
        mapping["rows"][0]["mechanisms"] = [TRUSTED_MECHANISM_IDS[0]]
        with self.assertRaises(IntegrityError):
            validate_mechanism_mapping_draft(
                mapping, pack=pack, taskpack_sha256=taskpack_content_sha256(pack)
            )

    def test_explicit_exclusion_requires_zero_mechanisms_and_reason(self) -> None:
        pack_id = "host-v2-agentdojo-v0.1.35-v1"
        pack = self.packs[pack_id]
        logical_sha = taskpack_content_sha256(pack)
        mapping = deepcopy(
            _object(self.documents[f"packs/{pack_id}/mechanism_mapping.draft.json"])
        )
        mapping["rows"][0]["status"] = "excluded"
        mapping["rows"][0]["mechanisms"] = []
        mapping["rows"][0]["rationale"] = (
            "Explicit task-specific evidence excludes all six trusted mechanisms; "
            "independent review is still pending."
        )
        validate_mechanism_mapping_draft(
            mapping, pack=pack, taskpack_sha256=logical_sha
        )

        with_mechanism = deepcopy(mapping)
        with_mechanism["rows"][0]["mechanisms"] = [TRUSTED_MECHANISM_IDS[0]]
        with self.assertRaises(IntegrityError):
            validate_mechanism_mapping_draft(
                with_mechanism, pack=pack, taskpack_sha256=logical_sha
            )

        without_reason = deepcopy(mapping)
        without_reason["rows"][0]["rationale"] = ""
        with self.assertRaises(IntegrityError):
            validate_mechanism_mapping_draft(
                without_reason, pack=pack, taskpack_sha256=logical_sha
            )

    def test_split_diagnostics_preserve_protocol_and_pair_clusters(self) -> None:
        for pack_id, pack in self.packs.items():
            split = _object(
                self.documents[f"packs/{pack_id}/split_diagnostic.json"]
            )
            self.assertEqual(split["decision"], "NO_GO")
            self.assertEqual(split["split_order"], list(SPLIT_ORDER))
            self.assertTrue(split["twins_and_source_variants_single_cluster"])
            self.assertTrue(split["all_source_task_intersections_empty"])
            self.assertEqual(split["splits"]["formal"]["task_count"], 0)
            self.assertEqual(split["splits"]["train"]["task_count"], 0)
            self.assertIn("FORMAL_SPLIT_EMPTY", split["blocker_codes"])
            self.assertIn("G2_COST_UNRESOLVED", split["blocker_codes"])
            self.assertIn(
                "FORMAL_SELECTION_REQUIRES_NEW_VERSIONED_DERIVED_PACK",
                split["blocker_codes"],
            )
            actual = {
                task.task_id: task.metadata["protocol_split"] for task in pack.tasks
            }
            emitted = {row["task_id"]: row["protocol_split"] for row in split["rows"]}
            self.assertEqual(emitted, actual)
            pair_clusters: dict[str, set[str]] = {}
            for row in split["rows"]:
                pair_clusters.setdefault(row["pair_id"], set()).add(row["cluster_id"])
            self.assertTrue(all(len(value) == 1 for value in pair_clusters.values()))

    def test_initial_state_overlap_is_reported_not_hidden(self) -> None:
        tau2 = _object(
            self.documents[
                "packs/host-v2-tau2-v1.0.1/split_diagnostic.json"
            ]
        )
        self.assertFalse(tau2["all_initial_state_graph_intersections_empty"])
        self.assertIn("INITIAL_STATE_GRAPH_SPLIT_OVERLAP", tau2["blocker_codes"])
        overlaps = [
            item
            for item in tau2["intersections"]
            if item["initial_state_sha256_overlap"]
        ]
        self.assertTrue(overlaps)
        self.assertTrue(all(item["source_task_disjoint"] for item in overlaps))

    def test_power_diagnostic_preserves_frozen_no_go(self) -> None:
        power = _object(self.documents["power_diagnostic.json"])
        self.assertEqual(power["decision"], "NO_GO")
        self.assertFalse(power["formal_run_permitted"])
        self.assertEqual(power["rq2_after_fixed_heldout_upper_bound"], 54)
        self.assertEqual(power["rq2_minimum_cluster_floor"], MINIMUM_FORMAL_CLUSTERS)
        self.assertEqual(power["rq2_preferred_cluster_floor"], PREFERRED_FORMAL_CLUSTERS)
        self.assertFalse(power["rq2_meets_minimum_60_after_fixed_heldout"])
        self.assertEqual(power["rq2_adapter_verified_cluster_count"], 0)
        self.assertEqual(power["rq2_formal_selected_cluster_count"], 0)
        self.assertEqual(
            power["pack_cluster_counts"],
            {
                "host-v2-agentdojo-v0.1.35-v1": 20,
                "host-v2-tau2-v1.0.1": 27,
            },
        )

    def test_every_oracle_is_byte_bound_and_reference_only(self) -> None:
        expected_oracles = {
            "host-v2-agentdojo-v0.1.35-v1": 20,
            "host-v2-tau2-v1.0.1": 34,
        }
        for pack_id, count in expected_oracles.items():
            oracle = _object(
                self.documents[f"packs/{pack_id}/oracle_diagnostic.json"]
            )
            self.assertEqual(oracle["decision"], "NO_GO")
            self.assertEqual(oracle["oracle_count"], count)
            self.assertEqual(oracle["executable_oracle_count"], 0)
            self.assertEqual(
                oracle["blocker_codes"], ["ORACLE_REFERENCE_ONLY_SCHEMA_V1"]
            )
            self.assertTrue(all(row["schema_version"] == 1 for row in oracle["rows"]))
            self.assertTrue(all(row["executable"] is False for row in oracle["rows"]))

    def test_manifest_references_are_bounded_and_byte_locked(self) -> None:
        self.assertEqual(self.manifest["overlay_id"], OVERLAY_ID)
        self.assertEqual(self.manifest["decision"], "NO_GO")
        self.assertFalse(self.manifest["claim_eligible"])
        self.assertFalse(self.manifest["formal_run_permitted"])
        self.assertEqual(len(self.manifest["packs"]), 2)
        for pack_entry in self.manifest["packs"]:
            pack_id = pack_entry["pack_id"]
            self.assertEqual(
                pack_entry["taskpack_content_sha256"], EXPECTED_CONTENT_SHA256S[pack_id]
            )
            self.assertEqual(pack_entry["decision"], "NO_GO")
            for name, ref in pack_entry["evidence"].items():
                if name in {"runtime_preflight", "checker_parity"}:
                    self.assertEqual(
                        ref,
                        {
                            "path": None,
                            "present": False,
                            "sha256": None,
                            "status": "missing",
                        },
                    )
                    continue
                rel = Path(ref["path"])
                self.assertFalse(rel.is_absolute())
                self.assertNotIn("..", rel.parts)
                self.assertEqual(sha256_bytes(self.documents[ref["path"]]), ref["sha256"])
            self.assertIn("RUNTIME_PREFLIGHT_MISSING", pack_entry["blocker_codes"])
            self.assertIn("NATIVE_CHECKER_PARITY_MISSING", pack_entry["blocker_codes"])
            self.assertIn(
                "INDEPENDENT_MAPPING_REVIEW_MISSING", pack_entry["blocker_codes"]
            )
        self.assertNotIn(b'"decision":"PASS"', b"".join(self.documents.values()))

    def test_materialization_is_byte_idempotent_and_reuse_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "overlay"
            first = materialize_public_evidence_overlay(REPO_ROOT, output)
            before = {
                path.relative_to(output).as_posix(): path.read_bytes()
                for path in output.rglob("*")
                if path.is_file()
            }
            second = materialize_public_evidence_overlay(REPO_ROOT, output)
            after = {
                path.relative_to(output).as_posix(): path.read_bytes()
                for path in output.rglob("*")
                if path.is_file()
            }
            self.assertEqual(first, second)
            self.assertEqual(before, after)
            verified = verify_public_evidence_overlay(REPO_ROOT, output)
            self.assertTrue(verified["valid"])

            (output / "decision.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaises(IntegrityError):
                materialize_public_evidence_overlay(REPO_ROOT, output)
            with self.assertRaises(IntegrityError):
                verify_public_evidence_overlay(REPO_ROOT, output)


if __name__ == "__main__":
    unittest.main()
