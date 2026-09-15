from __future__ import annotations

import copy
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentmembrane.host_v2 import assay
from agentmembrane.host_v2.assay import AssayBindingError, run_zero_token_assay
from agentmembrane.host_v2.runner import bind_visible_context_profile
from agentmembrane.host_v2.schema import IntegrityError, SchemaError
from agentmembrane.host_v2.taskpacks import load_taskpack


class CommittedProfileAssayTests(unittest.TestCase):
    def test_committed_assay_binds_profile_pack_and_observed_adaptive_surface(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = run_zero_token_assay(root)

            self.assertEqual(report["schema_version"], 2)
            self.assertEqual(report["assay_mode"], "committed_profile")
            self.assertTrue(report["passed"])
            self.assertTrue(report["zero_token"])
            for key in ("provider_calls", "model_calls", "proxy_calls", "network_calls"):
                self.assertEqual(report[key], 0)

            binding = report["binding"]
            self.assertEqual(binding["profile_id"], assay.EXPECTED_PROFILE_ID)
            self.assertEqual(binding["pack_id"], assay.EXPECTED_PACK_ID)
            self.assertEqual(binding["profile_sha256"], assay.EXPECTED_PROFILE_SHA256)
            self.assertEqual(binding["manifest_sha256"], assay.EXPECTED_MANIFEST_SHA256)
            self.assertEqual(
                binding["taskpack_byte_tree_sha256"],
                assay.EXPECTED_BYTE_TREE_SHA256,
            )
            self.assertEqual(
                binding["taskpack_logical_content_sha256"],
                assay.EXPECTED_LOGICAL_CONTENT_SHA256,
            )
            self.assertEqual(binding["tasks_sha256"], assay.EXPECTED_TASKS_SHA256)
            self.assertEqual(binding["task_ids"], list(assay.EXPECTED_TASK_IDS))
            self.assertEqual(binding["families"], list(assay.RQ2_FAMILIES))
            self.assertEqual(binding["task_count"], 24)
            self.assertEqual(binding["family_count"], 6)
            self.assertEqual(binding["execution_stage"], "atomic_synthetic_bringup")
            self.assertIsNone(binding["protocol_stage"])

            self.assertEqual(report["permissions"], assay.EXPECTED_PERMISSIONS)
            self.assertTrue(
                all(value is False for value in report["permissions"].values())
            )
            selector = report["selector_exercise"]
            self.assertTrue(selector["passed"])
            self.assertEqual(selector["declared_selector"], assay.EXPECTED_SELECTOR)
            self.assertEqual(
                selector["runner_observed_selector"], assay.EXPECTED_SELECTOR
            )
            self.assertEqual(selector["selected_task_count"], 24)
            self.assertEqual(selector["runner_episode_count"], 24)
            self.assertEqual(selector["planner_observation_count"], 24)
            self.assertEqual(selector["deterministic_planner_calls"], 24)
            self.assertEqual(selector["adapter_loads"], 24)
            self.assertEqual(selector["oracle_loads"], 24)
            self.assertTrue(selector["planner_metadata_minimized"])
            self.assertTrue(all(selector["forbidden_surface_checks"].values()))
            self.assertEqual(selector["provider_calls"], 0)
            self.assertEqual(selector["model_calls"], 0)
            self.assertEqual(selector["network_calls"], 0)

            self.assertTrue(report["scripted_engineering_positive_control"]["passed"])
            self.assertFalse(
                report["scripted_engineering_positive_control"]["claim_bearing"]
            )
            pack = report["committed_pack_engineering_assay"]
            self.assertTrue(pack["passed"])
            self.assertEqual(
                pack["splits"],
                {
                    "G0": 12,
                    "G1": 12,
                    "G2": 24,
                    "formal": 0,
                    "g0_g1_disjoint": True,
                    "g2_is_union": True,
                },
            )
            self.assertTrue(pack["protected_blocks"])
            self.assertTrue(pack["protected_benign_success"])

            status = report["scientific_status"]
            self.assertTrue(status["synthetic"])
            self.assertFalse(status["claim_bearing"])
            self.assertEqual(status["formal_rows"], 0)
            self.assertFalse(status["h_ladder_covered"])
            self.assertFalse(status["scientific_sample_gate_satisfied"])
            self.assertFalse(status["effect_estimated"])
            self.assertEqual(status["calibration_status"], "NO-GO")
            self.assertEqual(status["formal_status"], "NO-GO")
            self.assertEqual(status["claim_status"], "NO-GO")
            for key in (
                "calibration_go",
                "small_real_api_smoke_go",
                "formal_go",
                "scale_go",
                "claim_go",
            ):
                self.assertFalse(report[key])

            output = root / assay.EXPECTED_OUTPUT_NAMESPACE
            cache = root / assay.EXPECTED_CACHE_NAMESPACE
            persisted = json.loads((output / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(persisted, report)
            markdown = (output / "report.md").read_text(encoding="utf-8")
            self.assertIn("selector actually observed by runner planner", markdown)
            self.assertIn("NO-GO", markdown)
            reservation = json.loads(
                (cache / "reservation.json").read_text(encoding="utf-8")
            )
            self.assertEqual(reservation["profile_sha256"], assay.EXPECTED_PROFILE_SHA256)
            self.assertEqual(reservation["permissions"], assay.EXPECTED_PERMISSIONS)

    def test_namespace_reuse_is_fail_closed_and_does_not_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_zero_token_assay(root)
            report_path = root / assay.EXPECTED_OUTPUT_NAMESPACE / "report.json"
            before = report_path.read_bytes()
            with self.assertRaisesRegex(AssayBindingError, "namespace reuse"):
                run_zero_token_assay(root)
            self.assertEqual(report_path.read_bytes(), before)

    def test_legacy_scratch_mode_cannot_satisfy_new_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(SchemaError, "committed_profile"):
                run_zero_token_assay(directory, mode="legacy_scratch")
            self.assertEqual(list(Path(directory).iterdir()), [])


class AssayBindingMutationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.profile_raw = json.loads(
            assay.COMMITTED_PROFILE_PATH.read_text(encoding="utf-8")
        )

    def assert_raw_rejected(self, raw: dict[str, object]) -> None:
        with self.assertRaises((AssayBindingError, IntegrityError, SchemaError)):
            assay._validate_profile_contract_raw(raw)

    def test_every_frozen_profile_identity_stage_hash_selector_and_permission_mutation_fails(self) -> None:
        mutations: list[tuple[str, object, object]] = [
            ("protocol_id", "protocol_id", "host-boundary-v2"),
            ("profile_id", "profile_id", "mutated-profile"),
            ("rq_ids", "rq_ids", ["RQ1b_host_mediated"]),
            ("construct_id", "construct_id", "other_construct"),
            ("proposal_alignment", "proposal_alignment", "RQ2"),
            ("legacy_experiment_id", "legacy_experiment_id", "other-experiment"),
            ("legacy_analysis_family", "legacy_analysis_family", "RQ1"),
            ("answers_semantic", "answers_canonical_proposal_rq2", True),
            ("semantic_pooling", "pooling_with_semantic_rq2_permitted", True),
            ("execution_stage", "execution_stage", "protocol_stage_g"),
            ("protocol_stage", "protocol_stage", "G"),
            ("h_ladder", "h_ladder_covered", True),
            ("scientific_gate", "scientific_sample_gate_satisfied", True),
            ("claim_bearing", "claim_bearing", True),
            ("run_kind", "run_kind", "gate"),
            ("selector", "visible_context_profile", "scripted_route_replay"),
        ]
        for name, key, value in mutations:
            with self.subTest(name=name):
                raw = copy.deepcopy(self.profile_raw)
                raw[str(key)] = value
                self.assert_raw_rejected(raw)

        for key in (
            "taskpack_byte_tree_sha256",
            "taskpack_logical_content_sha256",
            "tasks_sha256",
        ):
            with self.subTest(binding_hash=key):
                raw = copy.deepcopy(self.profile_raw)
                raw["offline_assay_binding"][key] = "0" * 64
                self.assert_raw_rejected(raw)
        for key in (
            "provider_calls_permitted",
            "model_calls_permitted",
            "formal_run_permitted",
            "external_run_authorized",
        ):
            with self.subTest(permission=key):
                raw = copy.deepcopy(self.profile_raw)
                raw["offline_assay_binding"][key] = True
                self.assert_raw_rejected(raw)

    def test_every_task_id_and_family_mutation_fails(self) -> None:
        for index in range(24):
            with self.subTest(task_id_index=index):
                raw = copy.deepcopy(self.profile_raw)
                raw["taskpacks"][0]["task_ids"][index] = f"mutated-task-{index}"
                self.assert_raw_rejected(raw)
        for index in range(6):
            with self.subTest(family_index=index):
                raw = copy.deepcopy(self.profile_raw)
                raw["taskpacks"][0]["families"][index] = f"mutated-family-{index}"
                self.assert_raw_rejected(raw)

    def test_pack_id_manifest_root_split_model_and_namespace_mutations_fail(self) -> None:
        cases = (
            ("pack_id", lambda raw: raw["taskpacks"][0].__setitem__("pack_id", "other-pack")),
            (
                "manifest_sha256",
                lambda raw: raw["taskpacks"][0].__setitem__("manifest_sha256", "0" * 64),
            ),
            ("pack_root", lambda raw: raw["taskpacks"][0].__setitem__("root", "../../controlled-v2")),
            ("split", lambda raw: raw["taskpacks"][0].__setitem__("split", "formal")),
            (
                "requested_model",
                lambda raw: (
                    raw["model"].__setitem__("requested_id", "other-local"),
                    raw["model"].__setitem__("allowed_resolved_ids", ["other-local"]),
                ),
            ),
            (
                "provider_route",
                lambda raw: raw["model"].__setitem__("provider_route_id", "other-route"),
            ),
            (
                "output_namespace",
                lambda raw: raw["offline_assay_binding"].__setitem__(
                    "output_namespace", "mutated-output"
                ),
            ),
            (
                "cache_namespace",
                lambda raw: raw["offline_assay_binding"].__setitem__(
                    "cache_namespace", "mutated-cache"
                ),
            ),
            (
                "same_namespace",
                lambda raw: raw["offline_assay_binding"].__setitem__(
                    "cache_namespace", raw["offline_assay_binding"]["output_namespace"]
                ),
            ),
        )
        for name, mutate in cases:
            with self.subTest(name=name):
                raw = copy.deepcopy(self.profile_raw)
                mutate(raw)
                self.assert_raw_rejected(raw)

    def test_profile_and_each_runtime_hash_constant_are_independently_bound(self) -> None:
        constants = (
            "EXPECTED_PROFILE_SHA256",
            "EXPECTED_MANIFEST_SHA256",
            "EXPECTED_BYTE_TREE_SHA256",
            "EXPECTED_LOGICAL_CONTENT_SHA256",
            "EXPECTED_TASKS_SHA256",
        )
        for name in constants:
            with self.subTest(name=name), patch.object(assay, name, "0" * 64):
                with self.assertRaises(AssayBindingError):
                    assay._load_committed_binding()

    def test_missing_profile_and_pack_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing_profile = Path(directory) / "missing-profile.json"
            with patch.object(assay, "COMMITTED_PROFILE_PATH", missing_profile):
                with self.assertRaisesRegex(AssayBindingError, "profile is missing"):
                    assay._load_committed_binding()
            missing_pack = Path(directory) / "missing-pack"
            with patch.object(assay, "COMMITTED_PACK_ROOT", missing_pack):
                with self.assertRaises(AssayBindingError):
                    assay._load_committed_binding()

    def test_selector_missing_mismatch_and_each_leak_class_fail_closed(self) -> None:
        task = load_taskpack(assay.COMMITTED_PACK_ROOT).tasks[0]
        missing_metadata = copy.deepcopy(task.metadata)
        del missing_metadata["visible_context_profiles"][assay.EXPECTED_SELECTOR]
        with self.assertRaises(IntegrityError):
            bind_visible_context_profile(
                replace(task, metadata=missing_metadata),
                assay.EXPECTED_SELECTOR,
                required=True,
            )

        mismatch_metadata = copy.deepcopy(task.metadata)
        mismatch_metadata["visible_context_profiles"][assay.EXPECTED_SELECTOR][
            "visible_context_profile"
        ] = "scripted_route_replay"
        with self.assertRaises(IntegrityError):
            bind_visible_context_profile(
                replace(task, metadata=mismatch_metadata),
                assay.EXPECTED_SELECTOR,
                required=True,
            )

        injections = {
            "route_template": ("symbolic_action_templates", {"leak": []}),
            "ordered_ops": ("ordered_operation_names", ["write_low_risk"]),
            "hidden_target": ("red_team_target", {"resource": "restricted:secret"}),
            "oracle": ("oracle_ref", task.oracle_ref),
            "arm": ("arm", "protected"),
            "mechanism": ("mechanism", task.family),
        }
        for name, (key, value) in injections.items():
            with self.subTest(leak=name):
                metadata = copy.deepcopy(task.metadata)
                metadata["visible_context_profiles"][assay.EXPECTED_SELECTOR][key] = value
                with self.assertRaises(IntegrityError):
                    bind_visible_context_profile(
                        replace(task, metadata=metadata),
                        assay.EXPECTED_SELECTOR,
                        required=True,
                    )


if __name__ == "__main__":
    unittest.main()
