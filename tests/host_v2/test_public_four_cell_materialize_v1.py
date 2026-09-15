from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile
import unittest

from agentmembrane.host_v2.public_four_cell_v1.contracts import (
    FAMILY_ID,
    PROTECTED_CONDITION_ID,
    VULNERABLE_CONDITION_ID,
)
from agentmembrane.host_v2.public_four_cell_v1.materialize import (
    AUTHORIZED_VALUE,
    IMPLEMENTATION_SPECS,
    MaterializationError,
    build_documents,
    materialize,
    validate_documents,
    validate_execution_authorization,
)
from agentmembrane.host_v2.public_four_cell_v1.selector import SelectionError, select_mode


REPO_ROOT = Path(__file__).resolve().parents[2]


class PublicFourCellMaterializationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.documents = build_documents(REPO_ROOT)

    def parsed(self, name: str) -> dict[str, object]:
        value = json.loads(self.documents[name])
        self.assertIsInstance(value, dict)
        return value

    def test_build_is_byte_deterministic(self) -> None:
        self.assertEqual(self.documents, build_documents(REPO_ROOT))
        self.assertTrue(all(payload.endswith(b"\n") for payload in self.documents.values()))
        manifest = self.parsed("materialization-manifest.json")
        self.assertEqual(len(manifest["canonical_materialization_digest"]), 64)
        self.assertIs(manifest["shared_active_bytes_read_or_hashed"], False)

    def test_exact_four_cells_and_explicit_mapped_eligibility(self) -> None:
        derived = self.parsed("derived-pack.json")
        tasks = derived["tasks"]
        self.assertIsInstance(tasks, list)
        self.assertEqual(
            [(row["pair_role"], row["condition_id"]) for row in tasks],
            [
                ("benign", VULNERABLE_CONDITION_ID),
                ("benign", PROTECTED_CONDITION_ID),
                ("adversarial", VULNERABLE_CONDITION_ID),
                ("adversarial", PROTECTED_CONDITION_ID),
            ],
        )
        eligibility = self.parsed("eligibility.json")
        self.assertEqual(eligibility["eligibility_mode"], "mapped")
        self.assertIs(eligibility["eligibility_applied"], True)
        self.assertIs(eligibility["implicit_single_family_fallback_permitted"], False)
        self.assertEqual(
            eligibility["family_to_condition_ids"],
            {FAMILY_ID: [VULNERABLE_CONDITION_ID, PROTECTED_CONDITION_ID]},
        )

    def test_u3_i1_structural_evidence_is_pre_call_and_nonclaim(self) -> None:
        derived = self.parsed("derived-pack.json")
        evidence = derived["source_structural_evidence"]
        self.assertEqual(evidence["selection_method"], "pre_call_structural_eligibility_only")
        self.assertIs(evidence["adversarial_injection_target_distinct_from_prompt_authority"], True)
        self.assertIs(evidence["native_utility_checker_state_based"], True)
        self.assertIs(evidence["native_security_checker_state_based"], True)
        self.assertIs(evidence["text_judge_used"], False)
        self.assertIs(derived["claim_bearing"], False)
        self.assertEqual(derived["construct_status"], "unadjudicated")

    def test_prompt_authority_is_exact_and_hidden_evidence_is_not_model_visible(self) -> None:
        authority = self.parsed("prompt-authority-manifest.json")
        model_visible = self.documents["model-visible-input.json"]
        source_fixture = json.loads(
            (
                REPO_ROOT
                / "data/host_boundary_v2/packs/agentdojo-v0.1.35-v1/fixtures/"
                "agentdojo-v1-banking-u3-i1-adversarial.json"
            ).read_bytes()
        )
        source_oracle = (
            REPO_ROOT
            / "data/host_boundary_v2/packs/agentdojo-v0.1.35-v1/oracles/"
            "agentdojo-v1-banking-u3-i1.json"
        ).read_bytes()
        injection_goal = source_fixture["injection_task"]["goal"].encode("utf-8")
        self.assertEqual(authority["authorized_value"], AUTHORIZED_VALUE)
        self.assertEqual(authority["derivation_method"], "exact_user_prompt_substring_only")
        self.assertNotIn(injection_goal, model_visible)
        self.assertNotIn(source_oracle, model_visible)
        self.assertNotIn(b"injection_task_1", model_visible)
        self.assertNotIn(b"security_checker_ref", model_visible)

    def test_all_execution_authorizations_are_false_and_unflippable(self) -> None:
        for name in (
            "run-chain-manifest.json",
            "profile.json",
            "authorization.json",
            "materialization-manifest.json",
        ):
            document = self.parsed(name)
            self.assertIs(document["execution_authorized"], False)
            validate_execution_authorization(document)
        mutated = self.parsed("authorization.json")
        mutated["execution_authorized"] = True
        with self.assertRaises(MaterializationError):
            validate_execution_authorization(mutated)

    def test_profile_binds_complete_runtime_and_implementation_set(self) -> None:
        profile = self.parsed("profile.json")
        self.assertEqual(set(profile["implementation_bindings"]), set(IMPLEMENTATION_SPECS))
        runtime = profile["runtime"]
        self.assertEqual(
            set(runtime["evidence"]),
            {"receipt", "live_validator", "adapter_import_preflight"},
        )
        execution = profile["execution"]
        self.assertEqual(execution["workers"], 1)
        self.assertEqual(execution["max_inflight"], 1)
        self.assertEqual(execution["request_level_transport_retries"], 0)
        self.assertIs(execution["atomic_namespace_reservation_required"], True)
        self.assertIs(execution["namespace_reservation_performed_by_materializer"], False)
        self.assertEqual(profile["model"]["requested_id"], "gpt-5.6-sol")
        self.assertEqual(profile["model"]["reasoning_effort"], "max")
        self.assertEqual(profile["model"]["temperature"], 0)

    def test_run_chain_is_zeroed_and_referenced_by_profile(self) -> None:
        chain = self.parsed("run-chain-manifest.json")
        profile = self.parsed("profile.json")
        self.assertEqual(chain["budget_unit"], "client_attempt")
        self.assertEqual(chain["consumed"], 0)
        self.assertEqual(chain["remaining"], chain["cap"])
        self.assertTrue(all(value == 0 for value in chain["counters"].values()))
        self.assertEqual(chain["predecessor_attempts"], [])
        self.assertEqual(
            profile["run_chain_manifest"]["sha256"],
            __import__("hashlib").sha256(self.documents["run-chain-manifest.json"]).hexdigest(),
        )

    def test_double_materialization_is_exact_and_changed_bytes_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "config"
            first = materialize(REPO_ROOT, root)
            snapshot = {path.name: path.read_bytes() for path in root.iterdir()}
            second = materialize(REPO_ROOT, root)
            self.assertEqual(first.artifact_sha256, second.artifact_sha256)
            self.assertEqual(snapshot, {path.name: path.read_bytes() for path in root.iterdir()})
            changed = root / "authorization.json"
            changed.write_bytes(changed.read_bytes() + b" ")
            with self.assertRaises(MaterializationError):
                materialize(REPO_ROOT, root)

    def test_validator_rejects_eligibility_fallback_mutation(self) -> None:
        mutated = dict(self.documents)
        eligibility = json.loads(mutated["eligibility.json"])
        eligibility["eligibility_mode"] = "single_family"
        mutated["eligibility.json"] = (
            json.dumps(eligibility, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        )
        with self.assertRaises(MaterializationError):
            validate_documents(REPO_ROOT, mutated, rebuild=False)

    def test_rq1_selector_is_opaque_and_does_not_touch_shared_bytes(self) -> None:
        result = select_mode(mode="rq1", repo_root=Path("/path/need/not/exist"))
        self.assertEqual(result["mode"], "rq1")
        self.assertEqual(result["selection_kind"], "opaque_locator_only")
        self.assertEqual(result["byte_bindings"], [])
        self.assertIs(result["dependency_audit"]["shared_rq1_bytes_parsed"], False)
        self.assertIs(result["dependency_audit"]["shared_rq1_bytes_hashed"], False)
        self.assertIs(result["dependency_audit"]["shared_rq1_modules_imported"], False)

    def test_rq2_selector_binds_only_overlay_config_and_public_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            isolated_root = Path(temporary) / "repo"
            overlay_source = REPO_ROOT / "agentmembrane/host_v2/public_four_cell_v1"
            overlay_target = isolated_root / "agentmembrane/host_v2/public_four_cell_v1"
            overlay_target.mkdir(parents=True)
            for source in overlay_source.glob("*.py"):
                shutil.copy2(source, overlay_target / source.name)
            config_target = (
                isolated_root / "experiments/host_boundary_v2/public_four_cell_v1/config"
            )
            config_target.mkdir(parents=True)
            for name, payload in self.documents.items():
                (config_target / name).write_bytes(payload)
            upstream_relatives = (
                "manifest.json",
                "tasks.jsonl",
                "fixtures/agentdojo-v1-banking-u3-i1-adversarial.json",
                "fixtures/agentdojo-v1-banking-u3-i1-benign.json",
                "oracles/agentdojo-v1-banking-u3-i1.json",
            )
            upstream_source = (
                REPO_ROOT / "data/host_boundary_v2/packs/agentdojo-v0.1.35-v1"
            )
            upstream_target = (
                isolated_root / "data/host_boundary_v2/packs/agentdojo-v0.1.35-v1"
            )
            for relative in upstream_relatives:
                target = upstream_target / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(upstream_source / relative, target)
            result = select_mode(mode="rq2", repo_root=isolated_root)
        self.assertEqual(result["mode"], "rq2")
        self.assertIs(result["execution_authorized"], False)
        audit = result["dependency_audit"]
        self.assertIs(audit["shared_rq1_bytes_parsed"], False)
        self.assertIs(audit["shared_rq1_bytes_hashed"], False)
        self.assertEqual(audit["forbidden_shared_reference_count"], 0)
        bindings = result["byte_bindings"]
        self.assertTrue(
            all(
                row["path"].startswith("agentmembrane/host_v2/public_four_cell_v1/")
                for row in bindings["overlay"]
            )
        )
        self.assertTrue(
            all(
                row["path"].startswith(
                    "experiments/host_boundary_v2/public_four_cell_v1/config/"
                )
                for row in bindings["config"]
            )
        )
        self.assertTrue(
            all(
                row["path"].startswith(
                    "data/host_boundary_v2/packs/agentdojo-v0.1.35-v1/"
                )
                for row in bindings["immutable_upstream_public_data"]
            )
        )

    def test_selector_rejects_ambiguous_mode(self) -> None:
        with self.assertRaises(SelectionError):
            select_mode(mode="RQ2", repo_root=REPO_ROOT)


if __name__ == "__main__":
    unittest.main()
