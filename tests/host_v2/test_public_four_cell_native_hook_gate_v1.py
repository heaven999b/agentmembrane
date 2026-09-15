from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

from agentmembrane.host_v2.public_four_cell_v1.bridge import (
    ActionOutcome,
    BRIDGE_CONSTRUCT_STATUS,
    HOST_OWNED_TERMINAL_ROUTE,
)
from agentmembrane.host_v2.public_four_cell_v1.contracts import FOUR_CELLS


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = (
    ROOT
    / "experiments/host_boundary_v2/public_four_cell_canary_v1/native_hook_gate.py"
)
SPEC = importlib.util.spec_from_file_location("native_hook_gate_v1", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


H0 = "0" * 64
H1 = "1" * 64
H2 = "2" * 64
H3 = "3" * 64
H4 = "4" * 64
H5 = "5" * 64
H6 = "6" * 64
H7 = "7" * 64
ROOT_NS = "experiments/host_boundary_v2/public_four_cell_canary_v1/native/gate-001"


def _state(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class _FakeBinding:
    environment_root = "/private/tmp/fresh-runtime"


class _FakeEvidence:
    def __init__(self, value: dict) -> None:
        self._value = value

    def as_json(self) -> dict:
        return copy.deepcopy(self._value)


class _FakeIdentity:
    def __init__(self, pair_role: str) -> None:
        self.pair_role = pair_role
        self.task_id = f"{gate.SOURCE_TASK_ID}-{pair_role}"

    @classmethod
    def for_pair_role(cls, pair_role: str):
        return cls(pair_role)


class _FakeNativeSession:
    def __init__(
        self,
        runtime_root,
        episode_namespace,
        task_identity,
        *,
        runtime_binding,
    ) -> None:
        del runtime_root, runtime_binding
        self.namespace = episode_namespace
        self.identity = task_identity
        self.initial = _state({"role": task_identity.pair_role, "baseline": True})
        self.current = self.initial
        self.count = 0
        self.closed = False
        self.cleaned = False
        self.terminal = False

    @property
    def preflight_evidence(self):
        return {
            "checks": {
                "pack_transform_valid": True,
                "pack_locks_exact": True,
                "pack_cache_pollution_absent": True,
                "runtime_cache_pollution_absent": True,
                "runtime_triplet_exact": True,
            }
        }

    def interface_description(self):
        return {
            "schema_version": 1,
            "user_prompt": "same",
            "operations": [
                {
                    "name": "send_money",
                    "description": "native",
                    "argument_schema": {
                        "type": "object",
                        "properties": {
                            "recipient": {"type": "string"},
                            "amount": {"type": "number"},
                            "subject": {"type": "string"},
                            "date": {"type": "string"},
                        },
                        "required": ["recipient", "amount", "subject", "date"],
                    },
                }
            ],
        }

    def apply(self, action):
        before = self.current
        self.count += 1
        self.current = _state(
            {"role": self.identity.pair_role, "args": action.args, "count": self.count}
        )
        return ActionOutcome(
            allowed=True,
            reason="agentdojo_native_dispatch_succeeded",
            observation={"ok": True},
            effects=(
                {
                    "effect_id": f"{self.namespace}:effect:{self.count}",
                    "pre_state_sha256": before,
                    "post_state_sha256": self.current,
                },
            ),
            events=(
                {
                    "event_id": f"{self.namespace}:native:{self.count}",
                    "kind": "agentdojo_native_dispatch",
                },
            ),
        )

    def snapshot(self):
        return {
            "schema_version": 1,
            "adapter_id": "fake",
            "state_sha256": self.current,
            "initial_state_sha256": self.initial,
            "action_count": self.count,
            "ended": False,
            "cleaned": self.cleaned,
            "terminal_captured": self.terminal,
            "native_checkers_evaluated": False,
        }

    def capture_terminal_state(self, *, final_assistant_text, terminal_reason=None):
        del final_assistant_text, terminal_reason
        self.terminal = True
        return {"state_sha256": self.current, "action_count": self.count}

    def evaluate_native_checkers(self):
        role = self.identity.pair_role
        security = (self.count == 1) if role == "adversarial" else None
        return {
            "schema_version": 1,
            "adapter_id": "fake",
            "source_task_id": gate.SOURCE_TASK_ID,
            "task_id": self.identity.task_id,
            "pair_role": role,
            "utility": role == "benign" and self.count == 1,
            "security": security,
            "injection_success": security,
            "checker_binding_ids": ["native-utility", "native-security"],
            "state_sha256": self.current,
            "action_count": self.count,
        }

    def end_external_task(self):
        return ()

    def advance_lifecycle(self, transition):
        del transition
        return ()

    def cleanup(self):
        self.current = self.initial
        self.count = 0
        self.cleaned = True
        return self.initial

    def close(self):
        self.closed = True


class _FakeAdapter:
    AgentDojoTaskIdentity = _FakeIdentity
    AgentDojoNativeHostSession = _FakeNativeSession

    @staticmethod
    def validate_runtime_triplet(*, repo_root, runtime_root, binding):
        del repo_root, runtime_root, binding
        runtime = copy.deepcopy(valid_result()["runtime_triplet"])
        for field in (
            "triplet_revalidated",
            "environment_tree_recomputed",
            "upstream_callable_bindings_valid",
        ):
            runtime.pop(field)
        return _FakeEvidence(runtime)

    @staticmethod
    def validate_pack_preflight(*, repo_root):
        del repo_root
        return _FakeEvidence(
            {
                "schema_version": 1,
                "pack_id": "fake-pack",
                "pack_root": "/fake-pack",
                "pack_transform_valid": True,
                "pack_locks_exact": True,
                "pack_pycache_dir_count": 0,
                "pack_pyc_file_count": 0,
                "bindings": [],
            }
        )


def _decision(cell, namespace: str, direct: bool, denied: bool) -> dict:
    return {
        "schema_version": 1,
        "decision_id": namespace + ":decision",
        "event_id": namespace + ":event:2",
        "episode_namespace": namespace,
        "cell_id": cell.cell_id,
        "condition_id": cell.condition_id,
        "treatment_arm": cell.treatment_arm.value,
        "pair_role": cell.pair_role.value,
        "request_sha256": H4,
        "authorization_manifest_sha256": H1,
        "operation": "send_money",
        "resource_argument": "recipient",
        "requested_resource": "GB29" if direct else "US13",
        "direct_authority_witness": direct,
        "host_owned_route_witness": True,
        "decision_kind": (
            "deny_before_native_dispatch" if denied else "allow_native_dispatch"
        ),
        "reason_code": (
            "resource_binding_denied_pre_dispatch"
            if denied
            else "exact_direct_user_authority"
            if direct
            else "vulnerable_resource_binding_toggle_disabled"
        ),
        "pre_dispatch_sequence": 2,
        "native_dispatch_authorized": not denied,
        "native_dispatch_observed": False,
        "execution_authorized": False,
        "construct_status": "unadjudicated",
        "claim_eligible": False,
    }


def _cell(cell, index: int) -> dict:
    role = cell.pair_role.value
    arm = cell.treatment_arm.value
    direct = role == "benign"
    denied = role == "adversarial" and arm == "protected"
    namespace = f"{ROOT_NS}/{index}-{cell.cell_id}"
    after = H0 if denied else str(index + 1) * 64
    return {
        "cell_id": cell.cell_id,
        "condition_id": cell.condition_id,
        "treatment_arm": arm,
        "pair_role": role,
        "episode_namespace": namespace,
        "interface_sha256": H2,
        "authorization_manifest_sha256": H1,
        "direct_authority_witness": direct,
        "host_owned_route_witness": True,
        "host_owned_terminal_route": HOST_OWNED_TERMINAL_ROUTE,
        "pre_dispatch_decision": _decision(cell, namespace, direct, denied),
        "allowed": not denied,
        "reason": (
            "resource_binding_denied_pre_dispatch" if denied else "native_dispatch_succeeded"
        ),
        "route_event_kinds": (
            ["request_received", "policy_evaluated", "policy_denied"]
            if denied
            else [
                "request_received",
                "policy_evaluated",
                "native_dispatch_started",
                "native_dispatch_completed",
            ]
        ),
        "initial_state_sha256": H0,
        "pre_action_state_sha256": H0,
        "post_action_state_sha256": after,
        "cleanup_state_sha256": H0,
        "native_dispatch_count_before": 0,
        "native_dispatch_count_after": 0 if denied else 1,
        "malicious_native_dispatch": role == "adversarial" and not denied,
        "native_checker": {
            "schema_version": 1,
            "source_task_id": gate.SOURCE_TASK_ID,
            "task_id": "banking-user_task_3-injection_task_1",
            "pair_role": role,
            "utility": False,
            "security": None if role == "benign" else False,
            "injection_success": None if role == "benign" else False,
            "injection_success_semantics": "injection_objective_achieved",
            "checker_binding_ids": ["native-utility", "native-security"],
            "state_sha256": after,
            "action_count": 0 if denied else 1,
            "scope": gate.NATIVE_CHECKER_SCOPE,
        },
        "cleanup_succeeded": True,
        "execution_authorized": False,
        "claim_eligible": False,
    }


def valid_result() -> dict:
    return {
        "schema_version": 1,
        "artifact_type": gate.NATIVE_HOOK_ARTIFACT_TYPE,
        "gate_id": gate.NATIVE_HOOK_GATE_ID,
        "scope": "zero_model_real_native_hook",
        "source_task_id": gate.SOURCE_TASK_ID,
        "runtime_triplet": {
            "schema_version": 1,
            "runtime_id": "agentdojo-pinned-runtime",
            "environment_root": "/private/tmp/fresh-runtime",
            "environment_tree_sha256": H3,
            "python_executable": "/private/tmp/fresh-runtime/bin/python",
            "base_executable": "/Library/Python/3.12/bin/python3.12",
            "receipt_sha256": H4,
            "receipt_path": "experiments/runtime/receipt.json",
            "binding_sha256": H5,
            "binding_path": "experiments/runtime/binding.json",
            "callable_source_sha256": {
                "agentdojo.task_suite.load_suites:get_suite": H1,
                "agentdojo.functions_runtime:FunctionsRuntime": H2,
                "agentdojo.functions_runtime:FunctionCall": H3,
                "agentdojo.task_suite.task_suite:TaskSuite._check_user_task_utility": H4,
                "agentdojo.task_suite.task_suite:TaskSuite._check_injection_task_security": H5,
            },
            "python_version": "3.12.3",
            "base_executable_sha256": H7,
            "runtime_pycache_dir_count": 0,
            "runtime_pyc_file_count": 0,
            "triplet_revalidated": True,
            "environment_tree_recomputed": True,
            "upstream_callable_bindings_valid": True,
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
        "preflight_attempt_audit": {
            "attempts_total": 6,
            "successful_attempts": 4,
            "failed_before_native_attempts": 2,
            "failure_classes": [
                "CLI_IMPORT_PATH_MISSING_BEFORE_PREFLIGHT",
                "FRESH_BINDING_PATH_POLICY_MISMATCH_BEFORE_TRIPLET_VALIDATION",
            ],
            "native_resets_during_failed_attempts": 0,
            "native_dispatches_during_failed_attempts": 0,
            "native_checker_calls_during_failed_attempts": 0,
            "api_model_provider_network_calls_during_failed_attempts": 0,
            "state_mutations_during_failed_attempts": 0,
        },
        "single_worker": True,
        "fresh_namespace_root": ROOT_NS,
        "authorization_manifest_sha256": H1,
        "interface_sha256": H2,
        "cells": [_cell(cell, index) for index, cell in enumerate(FOUR_CELLS)],
        "execution_counts": {
            "episodes": 4,
            "resets": 4,
            "native_dispatches": 3,
            "native_checker_calls": 4,
            "task_executions": 4,
            "cleanup_attempts": 4,
            "cleanup_successes": 4,
            "api_calls": 0,
            "model_calls": 0,
            "provider_calls": 0,
            "network_attempts": 0,
            "shared_read_only_import_attempts": 1,
            "state_mutations": 0,
        },
        "engineering_native_execution_completed": True,
        "native_checker_scope": gate.NATIVE_CHECKER_SCOPE,
        "construct_status": BRIDGE_CONSTRUCT_STATUS,
        "execution_authorized": False,
        "claim_eligible": False,
        "formal_result": False,
        "excluded_non_overlay_evidence": [
            "tests.host_v2.test_agentdojo_adapter:21/21:shared_read_only_not_gate_evidence"
        ],
    }


class NativeHookGateTest(unittest.TestCase):
    def test_exact_four_cell_gate_passes(self) -> None:
        validated = gate.validate_native_hook_gate_result(valid_result())
        self.assertTrue(validated["validated"])
        self.assertTrue(validated["benign_dual_arm_native_reach"])
        self.assertTrue(validated["adversarial_protected_predispatch_block"])

    def test_concrete_runner_shape_with_synthetic_native_adapter(self) -> None:
        result = gate.execute_native_hook_gate(
            repo_root=ROOT,
            runtime_binding=_FakeBinding(),
            namespace_root=ROOT_NS,
            adapter_api=_FakeAdapter,
        )
        validated = gate.validate_native_hook_gate_result(result)
        self.assertTrue(validated["validated"])
        by_id = {row["cell_id"]: row for row in result["cells"]}
        self.assertTrue(
            by_id["adversarial-vulnerable"]["native_checker"]["security"]
        )
        self.assertFalse(
            by_id["adversarial-protected"]["native_checker"]["security"]
        )

    def test_rejects_nonzero_external_call(self) -> None:
        value = valid_result()
        value["execution_counts"]["api_calls"] = 1
        with self.assertRaises(gate.NativeHookGateError):
            gate.validate_native_hook_gate_result(value)

    def test_rejects_unrevalidated_runtime(self) -> None:
        value = valid_result()
        value["runtime_triplet"]["triplet_revalidated"] = False
        with self.assertRaises(gate.NativeHookGateError):
            gate.validate_native_hook_gate_result(value)

    def test_rejects_overlay_transform_or_python_cache(self) -> None:
        for field in (
            "runtime_transform_count",
            "pack_transform_count",
            "runtime_pycache_dir_count",
            "pack_pyc_file_count",
        ):
            value = valid_result()
            value["overlay_hygiene"][field] = 1
            with self.subTest(field=field), self.assertRaises(gate.NativeHookGateError):
                gate.validate_native_hook_gate_result(value)

    def test_external_findings_are_not_overlay_blockers(self) -> None:
        value = valid_result()
        validated = gate.validate_native_hook_gate_result(value)
        self.assertEqual(
            validated["preflight_classification"]["external"]["status"],
            "NOT_IN_SCOPE",
        )
        value["preflight_classification"]["external"]["status"] = "PASS"
        with self.assertRaises(gate.NativeHookGateError):
            gate.validate_native_hook_gate_result(value)

    def test_rejects_schema_or_manifest_drift(self) -> None:
        for field in ("interface_sha256", "authorization_manifest_sha256"):
            value = valid_result()
            value["cells"][1][field] = H7
            with self.subTest(field=field), self.assertRaises(gate.NativeHookGateError):
                gate.validate_native_hook_gate_result(value)

    def test_rejects_duplicate_namespace(self) -> None:
        value = valid_result()
        value["cells"][1]["episode_namespace"] = value["cells"][0]["episode_namespace"]
        value["cells"][1]["pre_dispatch_decision"]["episode_namespace"] = value["cells"][0]["episode_namespace"]
        with self.assertRaises(gate.NativeHookGateError):
            gate.validate_native_hook_gate_result(value)

    def test_rejects_benign_arm_that_does_not_reach_native(self) -> None:
        value = valid_result()
        value["cells"][0]["allowed"] = False
        with self.assertRaises(gate.NativeHookGateError):
            gate.validate_native_hook_gate_result(value)

    def test_rejects_vulnerable_attack_without_native_dispatch(self) -> None:
        value = valid_result()
        attack = next(row for row in value["cells"] if row["cell_id"] == "adversarial-vulnerable")
        attack["native_dispatch_count_after"] = 0
        with self.assertRaises(gate.NativeHookGateError):
            gate.validate_native_hook_gate_result(value)

    def test_rejects_protected_attack_dispatch_or_state_change(self) -> None:
        for field, replacement in (
            ("native_dispatch_count_after", 1),
            ("post_action_state_sha256", H7),
        ):
            value = valid_result()
            attack = next(row for row in value["cells"] if row["cell_id"] == "adversarial-protected")
            attack[field] = replacement
            with self.subTest(field=field), self.assertRaises(gate.NativeHookGateError):
                gate.validate_native_hook_gate_result(value)

    def test_rejects_route_bypass(self) -> None:
        value = valid_result()
        value["cells"][2]["host_owned_route_witness"] = False
        value["cells"][2]["pre_dispatch_decision"]["host_owned_route_witness"] = False
        with self.assertRaises(gate.NativeHookGateError):
            gate.validate_native_hook_gate_result(value)

    def test_rejects_cleanup_mismatch(self) -> None:
        value = valid_result()
        value["cells"][0]["cleanup_state_sha256"] = H7
        with self.assertRaises(gate.NativeHookGateError):
            gate.validate_native_hook_gate_result(value)

    def test_rejects_native_security_alias_drift(self) -> None:
        value = valid_result()
        attack = next(row for row in value["cells"] if row["cell_id"] == "adversarial-vulnerable")
        attack["native_checker"]["injection_success"] = True
        with self.assertRaises(gate.NativeHookGateError):
            gate.validate_native_hook_gate_result(value)

    def test_rejects_claim_or_formal_upgrade(self) -> None:
        for field in ("execution_authorized", "claim_eligible", "formal_result"):
            value = valid_result()
            value[field] = True
            with self.subTest(field=field), self.assertRaises(gate.NativeHookGateError):
                gate.validate_native_hook_gate_result(value)

    def test_rejects_unexpected_field(self) -> None:
        value = valid_result()
        value["scientific_result"] = True
        with self.assertRaises(gate.NativeHookGateError):
            gate.validate_native_hook_gate_result(value)


if __name__ == "__main__":
    unittest.main()
