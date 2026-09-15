from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

from agentmembrane.host_v2.public_four_cell_v1 import canary_authorization as AUTH


REPO_ROOT = Path(__file__).resolve().parents[2]
PREPARE_PATH = (
    REPO_ROOT
    / "experiments/host_boundary_v2/public_four_cell_canary_v1/prepare.py"
)


def _load_prepare():
    spec = importlib.util.spec_from_file_location(
        "public_four_cell_canary_v1_prepare_test", PREPARE_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load canary prepare module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


PREPARE = _load_prepare()


def _canonical_write(path: Path, value: object) -> str:
    payload = AUTH.canonical_json_bytes(value) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _binding(root: Path, relative: str | Path) -> dict[str, str]:
    rel = Path(relative).as_posix()
    return {
        "path": rel,
        "sha256": hashlib.sha256((root / rel).read_bytes()).hexdigest(),
    }


class _Fixture:
    def __init__(self) -> None:
        self._repo_temp = tempfile.TemporaryDirectory(dir="/private/tmp")
        self._runtime_temp = tempfile.TemporaryDirectory(
            prefix="agentmembrane-rq2-agentdojo-runtime-fixture-", dir="/private/tmp"
        )
        self.root = Path(self._repo_temp.name)
        self.runtime_root = Path(self._runtime_temp.name) / "environment-v2"
        self.runtime_root.mkdir()
        (self.runtime_root / "runtime.bin").write_bytes(b"frozen-runtime")
        self._write_overlay()
        self._write_immutable_sources()
        self.runtime_evidence = self._write_runtime_triplet()
        self._write_native_gate_inputs()
        self.profile = self._profile()
        self.profile_path = (
            self.root
            / "experiments/host_boundary_v2/public_four_cell_canary_v1/config/"
            "profile.draft.json"
        )
        _canonical_write(self.profile_path, self.profile)
        self.authorization = self._authorization()
        self.authorization_path = self.profile_path.with_name("authorization.draft.json")
        _canonical_write(self.authorization_path, self.authorization)

    def close(self) -> None:
        self._runtime_temp.cleanup()
        self._repo_temp.cleanup()

    def _write_overlay(self) -> None:
        for index, relative in enumerate(AUTH.COMPONENT_PATHS.values()):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"COMPONENT = {index!r}\n", encoding="utf-8")

    def _write_immutable_sources(self) -> None:
        for index, relative in enumerate(AUTH.IMMUTABLE_SOURCE_PATHS):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"immutable-{index}\n", encoding="utf-8")

    def _write_runtime_triplet(self) -> dict[str, dict[str, str]]:
        upstream = self.root / "data/host_boundary_v2/upstream/agentdojo/src/native.py"
        upstream.parent.mkdir(parents=True, exist_ok=True)
        upstream.write_text("NATIVE = True\n", encoding="utf-8")
        upstream_sha = hashlib.sha256(upstream.read_bytes()).hexdigest()
        tree_sha, tree_count = AUTH._tree_manifest_sha256(self.runtime_root)
        runtime_id = "agentdojo-recovered-fixture"
        callable_rows = [
            {
                "binding_id": binding_id,
                "source_path": str(upstream),
                "source_sha256": upstream_sha,
            }
            for binding_id in sorted(AUTH.REQUIRED_NATIVE_CALLABLE_BINDING_IDS)
        ]
        receipt = {
            "artifact_type": "agentmembrane_native_runtime_provisioning_receipt",
            "runtime_id": runtime_id,
            "environment": {"root": str(self.runtime_root), "tree_sha256": tree_sha},
            "callable_bindings": callable_rows,
            "execution_counts": {"api_calls": 0, "task_executions": 0},
            "authorizations": {"api_calls": False, "task_execution": False},
        }
        receipt_rel = (
            "experiments/host_boundary_v2/runtime_envs/receipts/recovered/fixture.json"
        )
        receipt_sha = _canonical_write(self.root / receipt_rel, receipt)
        live = {
            "artifact_type": "agentmembrane_agentdojo_recovered_runtime_live_validator",
            "runtime_id": runtime_id,
            "environment_root": str(self.runtime_root),
            "environment_tree_sha256": tree_sha,
            "environment_manifest_entry_count": tree_count,
            "receipt_sha256": receipt_sha,
            "validation": {
                "canonical_receipt": True,
                "generic_live_validator_passed": True,
                "offline_sync": True,
                "old_runtime_id_rejected": True,
                "source_tree_unchanged": True,
                "tree_independently_recomputed": True,
            },
            "execution_counts": {"api_calls": 0, "task_executions": 0},
            "authorizations": {"api_calls": False, "task_execution": False},
        }
        live_rel = (
            "experiments/host_boundary_v2/runtime_envs/recovery_v1/fixture.live.json"
        )
        live_sha = _canonical_write(self.root / live_rel, live)
        preflight = {
            "artifact_type": (
                "agentmembrane_agentdojo_recovered_adapter_import_only_preflight"
            ),
            "scope": "adapter_import_only",
            "runtime_id": runtime_id,
            "environment_root": str(self.runtime_root),
            "environment_tree_sha256": tree_sha,
            "receipt_sha256": receipt_sha,
            "live_validator_sha256": live_sha,
            "checks": {"importable": True, "network_unused": True},
            "adapter": {"callable": True, "network_attempts": 0},
            "execution_counts": {"api_calls": 0, "task_executions": 0},
            "scientific_claims": {
                "native_checker_parity_established": False,
                "public_readiness_established": False,
            },
        }
        preflight_rel = (
            "experiments/host_boundary_v2/runtime_envs/recovery_v1/fixture.preflight.json"
        )
        _canonical_write(self.root / preflight_rel, preflight)
        return {
            "receipt": _binding(self.root, receipt_rel),
            "live_validator": _binding(self.root, live_rel),
            "adapter_import_preflight": _binding(self.root, preflight_rel),
        }

    def _write_native_gate_inputs(self) -> None:
        implementation = (
            self.root
            / "experiments/host_boundary_v2/public_four_cell_canary_v1/"
            "native_hook_gate.py"
        )
        implementation.parent.mkdir(parents=True, exist_ok=True)
        implementation.write_text("EXECUTION_AUTHORIZED = False\n", encoding="utf-8")
        preparer = self.root / AUTH.PREPARER_PATH
        preparer.write_text("EXECUTION_AUTHORIZED = False\n", encoding="utf-8")
        focused_test = (
            self.root / "tests/host_v2/test_public_four_cell_native_hook_gate_v1.py"
        )
        focused_test.parent.mkdir(parents=True, exist_ok=True)
        focused_test.write_text("def test_gate(): pass\n", encoding="utf-8")

    def _profile(self) -> dict[str, object]:
        overlay_root = self.root / AUTH.OVERLAY_ROOT
        overlay = {
            path.relative_to(self.root).as_posix(): _binding(
                self.root, path.relative_to(self.root)
            )
            for path in sorted(overlay_root.glob("*.py"))
        }
        components = {
            role: _binding(self.root, relative)
            for role, relative in AUTH.COMPONENT_PATHS.items()
        }
        suffix = "host-public-four-cell-u3-i1-20990101-000001"
        return {
            "schema_version": 1,
            "artifact_type": AUTH.PROFILE_ARTIFACT_TYPE,
            "profile_id": "fixture-public-four-cell-canary-v1",
            "canonical_label": AUTH.CANONICAL_LABEL,
            "source_task_id": AUTH.SOURCE_TASK_ID,
            "construct_status": "unadjudicated",
            "execution_authorized": False,
            "claim_eligible": False,
            "scientific_claim_permitted": False,
            "cell_ids": list(AUTH.EXACT_CELL_IDS),
            "model": {
                "requested_id": AUTH.MODEL_ID,
                "allowed_resolved_ids": [AUTH.MODEL_ID],
                "provider_route_id": AUTH.PROVIDER_ROUTE_ID,
                "reasoning_effort": AUTH.REASONING_EFFORT,
                "temperature": 0,
                "request_level_transport_retries": 0,
            },
            "execution": {
                "episodes": 4,
                "workers": 1,
                "max_inflight": 1,
                "delivered_call_cap": 24,
                "delivered_calls_consumed": 0,
                "require_fresh_namespaces": True,
                "atomic_namespace_reservation_required": True,
                "fresh_namespaces": {
                    kind: (
                        AUTH.CANARY_ROOT / kind / suffix
                    ).as_posix()
                    for kind in ("outputs", "cache", "native")
                },
            },
            "actual_execution_counts": dict(AUTH.ZERO_PREPARE_COUNTS),
            "overlay_bindings": overlay,
            "component_bindings": components,
            "immutable_source_bindings": [
                _binding(self.root, relative)
                for relative in AUTH.IMMUTABLE_SOURCE_PATHS
            ],
            "runtime_evidence": self.runtime_evidence,
            "preparer_binding": _binding(self.root, AUTH.PREPARER_PATH),
            "native_hook_gate": {
                "mode": "zero_model_local_native_hook_gate",
                "implementation_binding": _binding(
                    self.root, AUTH.CANARY_ROOT / "native_hook_gate.py"
                ),
                "focused_test_binding": _binding(
                    self.root,
                    "tests/host_v2/test_public_four_cell_native_hook_gate_v1.py",
                ),
                "post_run_result_binding": None,
                "post_run_result_required_for_separate_authorization": True,
                "api_calls": 0,
                "model_calls": 0,
                "provider_calls": 0,
                "network_calls": 0,
                "execution_authorized": False,
                "claim_eligible": False,
            },
            "external_preflight_classification": [
                dict(row) for row in AUTH.EXTERNAL_PREFLIGHT_NOT_IN_SCOPE
            ],
        }

    def _authorization(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "artifact_type": AUTH.AUTHORIZATION_ARTIFACT_TYPE,
            "authorization_id": "fixture-prepare-only-no-go-v1",
            "decision": "PREPARE_ONLY_NO_GO",
            "execution_authorized": False,
            "claim_eligible": False,
            "lead_all_gates_passed": False,
            "separate_authorization_required": True,
            "profile_binding": _binding(
                self.root, self.profile_path.relative_to(self.root)
            ),
            "double_prepare_report_binding": None,
            "native_hook_post_run_result_binding": None,
            "blocker_codes": [
                "LEAD_ALL_GATES_NOT_ATTESTED",
                "NATIVE_HOOK_POST_RUN_RESULT_NOT_BOUND",
                "DOUBLE_PREPARE_REPORT_NOT_BOUND",
                "SEPARATE_EXECUTION_AUTHORIZATION_NOT_MATERIALIZED",
            ],
        }


class PublicFourCellCanaryAuthorizationV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = _Fixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def test_exact_profile_validates_but_is_not_authorized(self) -> None:
        report = AUTH.validate_profile_draft(self.fixture.root, self.fixture.profile)
        self.assertFalse(report["execution_authorized"])
        self.assertFalse(report["ready_for_separate_narrow_authorization"])
        self.assertTrue(report["runtime"]["environment_tree_recomputed"])
        self.assertTrue(report["pack_hygiene"]["passed"])
        self.assertTrue(
            all(
                row["classification"] == "external_preflight_not_in_scope"
                and row["overlay_failure"] is False
                for row in report["external_preflight_classification"]
            )
        )

    def test_profile_rejects_authorized_or_nonexact_execution_contract(self) -> None:
        for path, value in (
            (("execution_authorized",), True),
            (("model", "requested_id"), "gpt-5.6-terra"),
            (("model", "reasoning_effort"), "high"),
            (("model", "temperature"), 1),
            (("model", "request_level_transport_retries"), 1),
            (("execution", "workers"), 2),
            (("execution", "delivered_call_cap"), 25),
            (("cell_ids",), list(reversed(AUTH.EXACT_CELL_IDS))),
        ):
            mutated = copy.deepcopy(self.fixture.profile)
            target = mutated
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(AUTH.CanaryAuthorizationError):
                AUTH.validate_profile_draft(self.fixture.root, mutated)

    def test_current_authorization_cannot_be_flipped(self) -> None:
        report = AUTH.validate_authorization_draft(
            self.fixture.root,
            self.fixture.authorization,
            profile_path=self.fixture.profile_path,
        )
        self.assertFalse(report["execution_authorized"])
        mutated = copy.deepcopy(self.fixture.authorization)
        mutated["execution_authorized"] = True
        mutated["decision"] = "AUTHORIZE"
        mutated["lead_all_gates_passed"] = True
        with self.assertRaises(AUTH.CanaryAuthorizationError):
            AUTH.validate_authorization_draft(
                self.fixture.root, mutated, profile_path=self.fixture.profile_path
            )

    def test_component_cannot_bind_shared_mutable_runner(self) -> None:
        shared = self.fixture.root / "agentmembrane/host_v2/runner.py"
        shared.parent.mkdir(parents=True, exist_ok=True)
        shared.write_text("MUTABLE = True\n", encoding="utf-8")
        mutated = copy.deepcopy(self.fixture.profile)
        mutated["component_bindings"]["runner"] = _binding(
            self.fixture.root, "agentmembrane/host_v2/runner.py"
        )
        with self.assertRaises(AUTH.CanaryAuthorizationError):
            AUTH.validate_profile_draft(self.fixture.root, mutated)

    def test_pack_hygiene_rejects_transform_cache_and_bytecode(self) -> None:
        report = AUTH.audit_binding_hygiene(
            [
                {"path": "pack/transform/build.py"},
                {"path": "overlay/__pycache__/a.pyc"},
                {"path": "overlay/direct.pyc"},
            ]
        )
        self.assertFalse(report["passed"])
        self.assertFalse(report["whole_tests_tree_used_as_gate"])
        self.assertEqual(
            {row["reason"] for row in report["violations"]},
            {
                "transform_not_runtime_input",
                "python_cache_not_runtime_input",
                "bytecode_not_runtime_input",
            },
        )

    def test_runtime_tree_drift_fails_closed_without_native_execution(self) -> None:
        (self.fixture.runtime_root / "drift.bin").write_bytes(b"drift")
        with self.assertRaises(AUTH.CanaryAuthorizationError):
            AUTH.validate_profile_draft(self.fixture.root, self.fixture.profile)

    def test_fresh_namespace_collision_fails_closed(self) -> None:
        output = self.fixture.profile["execution"]["fresh_namespaces"]["outputs"]
        (self.fixture.root / output).mkdir(parents=True)
        with self.assertRaises(AUTH.CanaryAuthorizationError):
            AUTH.validate_profile_draft(self.fixture.root, self.fixture.profile)

    def test_double_prepare_is_identical_and_still_no_go(self) -> None:
        report = PREPARE.run_double_prepare(
            self.fixture.root,
            self.fixture.profile_path,
            self.fixture.authorization_path,
        )
        self.assertTrue(report["double_prepare"]["byte_identical"])
        self.assertEqual(report["double_prepare"]["prepare_passes"], 2)
        self.assertFalse(
            report["double_prepare"]["all_preconditions_for_separate_authorization"]
        )
        self.assertEqual(report["status"], "PREPARE_ONLY_NO_GO")
        self.assertFalse(report["execution_authorized"])
        self.assertEqual(report["actual_execution_counts"], AUTH.ZERO_PREPARE_COUNTS)

    def test_prepare_snapshot_drift_is_detected(self) -> None:
        first = AUTH.build_prepare_snapshot(
            self.fixture.root, self.fixture.profile_path
        )
        second = copy.deepcopy(first)
        second["bindings"]["component:runner"] = "f" * 64
        unsigned = dict(second)
        unsigned.pop("prepare_digest")
        second["prepare_digest"] = AUTH.sha256_bytes(AUTH.canonical_json_bytes(unsigned))
        report = AUTH.compare_prepare_snapshots(first, second)
        self.assertFalse(report["byte_identical"])
        self.assertEqual(report["drifted_bindings"], ["component:runner"])
        self.assertFalse(report["execution_authorized"])

    def test_post_run_binding_only_makes_prepare_eligible_for_later_review(self) -> None:
        result = (
            self.fixture.root
            / AUTH.CANARY_ROOT
            / "outputs/native_hook_gate_fixture/result.json"
        )
        _canonical_write(
            result,
            {
                "schema_version": 1,
                "artifact_type": "agentmembrane_public_four_cell_native_hook_gate",
                "gate_id": "public-four-cell-agentdojo-native-hook-gate-v1",
                "scope": "zero_model_real_native_hook",
                "source_task_id": AUTH.SOURCE_TASK_ID,
                "single_worker": True,
                "engineering_native_execution_completed": True,
                "native_checker_scope": "engineering_hook_only_nonclaim",
                "execution_authorized": False,
                "claim_eligible": False,
                "formal_result": False,
                "execution_counts": dict(AUTH.NATIVE_HOOK_EXECUTION_COUNTS),
                "runtime_triplet": {
                    "runtime_id": "agentdojo-recovered-fixture",
                    "environment_root": str(self.fixture.runtime_root),
                    "environment_tree_sha256": AUTH._tree_manifest_sha256(
                        self.fixture.runtime_root
                    )[0],
                    "receipt_path": self.fixture.runtime_evidence["receipt"]["path"],
                    "receipt_sha256": self.fixture.runtime_evidence["receipt"]["sha256"],
                    "triplet_revalidated": True,
                    "environment_tree_recomputed": True,
                    "upstream_callable_bindings_valid": True,
                    "runtime_pycache_dir_count": 0,
                    "runtime_pyc_file_count": 0,
                    "callable_source_sha256": dict(
                        AUTH.DIRECT_CALLABLE_SOURCE_SHA256
                    ),
                },
                "overlay_hygiene": {
                    "runtime_transform_count": 0,
                    "pack_transform_count": 0,
                    "runtime_pycache_dir_count": 0,
                    "pack_pycache_dir_count": 0,
                    "runtime_pyc_file_count": 0,
                    "pack_pyc_file_count": 0,
                    "passed": True,
                },
                "preflight_classification": {
                    "overlay": {
                        "classification": "overlay_owned_required_gate",
                        "status": "PASS",
                        "blockers": [],
                    },
                    "external": {
                        "classification": "external_not_in_scope",
                        "status": "NOT_IN_SCOPE",
                        "findings": [
                            "tau2_seven_zero_byte_targets",
                            "historical_receipt_drift",
                            "full_inventory_drift",
                        ],
                    },
                },
                "cells": [
                    {
                        "cell_id": cell_id,
                        "allowed": cell_id != "adversarial-protected",
                        "reason": (
                            "resource_binding_denied_pre_dispatch"
                            if cell_id == "adversarial-protected"
                            else "agentdojo_native_dispatch_succeeded"
                        ),
                        "direct_authority_witness": cell_id.startswith("benign-"),
                        "malicious_native_dispatch": cell_id
                        == "adversarial-vulnerable",
                        "native_dispatch_count_after": (
                            0 if cell_id == "adversarial-protected" else 1
                        ),
                        "pre_action_state_sha256": "a" * 64,
                        "post_action_state_sha256": (
                            "a" * 64
                            if cell_id == "adversarial-protected"
                            else "b" * 64
                        ),
                        "initial_state_sha256": "a" * 64,
                        "cleanup_state_sha256": "a" * 64,
                        "cleanup_succeeded": True,
                        "execution_authorized": False,
                        "claim_eligible": False,
                        "native_checker": {
                            "scope": "engineering_hook_only_nonclaim",
                            "source_task_id": AUTH.SOURCE_TASK_ID,
                            "utility": cell_id.startswith("benign-"),
                            "injection_success": (
                                True
                                if cell_id == "adversarial-vulnerable"
                                else False
                                if cell_id == "adversarial-protected"
                                else None
                            ),
                        },
                    }
                    for cell_id in AUTH.EXACT_CELL_IDS
                ],
            },
        )
        mutated = copy.deepcopy(self.fixture.profile)
        mutated["native_hook_gate"]["post_run_result_binding"] = _binding(
            self.fixture.root, result.relative_to(self.fixture.root)
        )
        report = AUTH.validate_profile_draft(self.fixture.root, mutated)
        self.assertTrue(report["ready_for_separate_narrow_authorization"])
        self.assertFalse(report["execution_authorized"])


if __name__ == "__main__":
    unittest.main()
