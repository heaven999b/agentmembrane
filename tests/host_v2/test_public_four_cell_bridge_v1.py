from __future__ import annotations

import ast
import copy
from dataclasses import replace
import inspect
from pathlib import Path
import unittest

from agentmembrane.host_v2.public_four_cell_v1.bridge import (
    ActionOutcome,
    ActionRequest,
    BRIDGE_CONSTRUCT_STATUS,
    FourCellBridgeError,
    FourCellPublicHostSession,
    IntegrityError,
    authorization_manifest_sha256,
    bridge_descriptor,
    build_authorization_manifest,
    sha256_json,
)
from agentmembrane.host_v2.public_four_cell_v1.contracts import (
    PROTECTED_CONDITION_ID,
    PairRole,
    TreatmentArm,
    VULNERABLE_CONDITION_ID,
)
from agentmembrane.host_v2.public_four_cell_v1.reference_traces import (
    AUTHORIZED_RECIPIENT,
    OUT_OF_SCOPE_RECIPIENT,
    REFERENCE_USER_PROMPT,
    ReferenceTraceError,
    run_zero_token_reference_trace_gate,
    validate_reference_trace_gate,
)


INITIAL_STATE = sha256_json({"transfers": []})


class _FakeNativeSession:
    def __init__(self, *, schema=None):
        self.schema = schema or {
            "operations": [
                {
                    "name": "send_money",
                    "argument_schema": {
                        "type": "object",
                        "properties": {
                            "recipient": {"type": "string"},
                            "amount": {"type": "number"},
                        },
                        "required": ["recipient", "amount"],
                    },
                }
            ]
        }
        self.dispatch_calls = []
        self.terminal_calls = []
        self.checker_calls = 0
        self.transfers = []
        self.closed = False

    def _state_sha(self):
        return sha256_json({"transfers": self.transfers})

    def interface_description(self):
        return copy.deepcopy(self.schema)

    def apply(self, action):
        self.dispatch_calls.append(copy.deepcopy(action))
        before = self._state_sha()
        self.transfers.append(copy.deepcopy(action.args))
        after = self._state_sha()
        return ActionOutcome(
            allowed=True,
            reason="native_ok",
            observation={"native_success": True, "state_sha256": after},
            effects=(
                {
                    "effect": "transfer",
                    "pre_state_sha256": before,
                    "post_state_sha256": after,
                },
            ),
            events=({"kind": "native_transfer", "event_id": "native:1"},),
        )

    def capture_terminal_state(self, *, final_assistant_text, terminal_reason=None):
        self.terminal_calls.append((final_assistant_text, terminal_reason))
        return {"state_sha256": self._state_sha(), "model_output": final_assistant_text}

    def evaluate_native_checkers(self):
        self.checker_calls += 1
        return {"utility": True, "security": None}

    def end_external_task(self):
        return ()

    def advance_lifecycle(self, transition):
        return ()

    def snapshot(self):
        return {
            "state_sha256": self._state_sha(),
            "action_count": len(self.dispatch_calls),
        }

    def cleanup(self):
        self.transfers.clear()
        return INITIAL_STATE

    def close(self):
        self.closed = True


def _manifest():
    start = REFERENCE_USER_PROMPT.index(AUTHORIZED_RECIPIENT)
    return build_authorization_manifest(
        user_prompt=REFERENCE_USER_PROMPT,
        user_prompt_path="immutable-upstream/user-task-3.prompt",
        authorized_value=AUTHORIZED_RECIPIENT,
        substring_start=start,
        substring_end=start + len(AUTHORIZED_RECIPIENT),
    )


def _session(arm, role=PairRole.ADVERSARIAL, *, native=None, manifest=None):
    condition = (
        PROTECTED_CONDITION_ID
        if arm is TreatmentArm.PROTECTED
        else VULNERABLE_CONDITION_ID
    )
    return FourCellPublicHostSession(
        delegate=native or _FakeNativeSession(),
        treatment_arm=arm,
        pair_role=role,
        condition_id=condition,
        episode_namespace=f"test-{role.value}-{arm.value}",
        authorization_manifest=manifest or _manifest(),
        user_prompt=REFERENCE_USER_PROMPT,
    )


def _send(recipient):
    return ActionRequest(
        op="send_money", args={"recipient": recipient, "amount": 6.0}
    )


class PublicFourCellBridgeV1Tests(unittest.TestCase):
    def test_authorization_manifest_is_exact_prompt_substring_only(self):
        manifest = _manifest()
        self.assertEqual(manifest.authorized_operation, "send_money")
        self.assertEqual(manifest.authorized_argument, "recipient")
        self.assertEqual(manifest.authorized_value, AUTHORIZED_RECIPIENT)
        self.assertEqual(
            REFERENCE_USER_PROMPT[manifest.substring_start : manifest.substring_end],
            AUTHORIZED_RECIPIENT,
        )
        self.assertEqual(manifest.derivation_method, "exact_user_prompt_substring_only")
        fields = set(manifest.__dataclass_fields__)
        for forbidden in ("pair_role", "injection", "oracle", "checker", "outcome"):
            self.assertNotIn(forbidden, fields)
        signature = inspect.signature(build_authorization_manifest)
        for forbidden in ("pair_role", "injection", "oracle", "checker", "outcome"):
            self.assertNotIn(forbidden, signature.parameters)

    def test_prompt_hash_or_offset_mismatch_fails_closed(self):
        manifest = _manifest()
        bad_hash = replace(manifest, user_prompt_sha256="0" * 64)
        with self.assertRaises(IntegrityError):
            _session(TreatmentArm.PROTECTED, manifest=bad_hash)
        bad_offset = replace(manifest, substring_start=manifest.substring_start + 1)
        with self.assertRaises(IntegrityError):
            _session(TreatmentArm.PROTECTED, manifest=bad_offset)

    def test_two_arms_expose_byte_equivalent_schema_and_shared_manifest(self):
        manifest = _manifest()
        vulnerable = _session(TreatmentArm.VULNERABLE, manifest=manifest)
        protected = _session(TreatmentArm.PROTECTED, manifest=manifest)
        self.assertEqual(
            sha256_json(vulnerable.interface_description()),
            sha256_json(protected.interface_description()),
        )
        self.assertEqual(
            vulnerable.authorization_manifest_sha256,
            protected.authorization_manifest_sha256,
        )
        self.assertEqual(
            vulnerable.authorization_manifest_sha256,
            authorization_manifest_sha256(manifest),
        )

    def test_protected_out_of_scope_request_denied_before_native_dispatch(self):
        native = _FakeNativeSession()
        protected = _session(TreatmentArm.PROTECTED, native=native)
        before = native.snapshot()
        outcome = protected.apply(_send(OUT_OF_SCOPE_RECIPIENT))
        after = native.snapshot()
        self.assertFalse(outcome.allowed)
        self.assertEqual(outcome.reason, "resource_binding_denied_pre_dispatch")
        self.assertEqual(native.dispatch_calls, [])
        self.assertEqual(before, after)
        self.assertEqual(
            [event["kind"] for event in outcome.events],
            ["request_received", "policy_evaluated", "policy_denied"],
        )
        denial = outcome.events[-1]
        self.assertFalse(denial["direct_authority_witness"])
        self.assertTrue(denial["host_owned_route_witness"])
        self.assertEqual(denial["native_dispatch_count_before"], 0)
        self.assertEqual(denial["native_dispatch_count_after"], 0)
        self.assertEqual(denial["pre_state_sha256"], denial["post_state_sha256"])

    def test_vulnerable_uses_same_mediation_layer_but_toggle_is_off(self):
        native = _FakeNativeSession()
        vulnerable = _session(TreatmentArm.VULNERABLE, native=native)
        outcome = vulnerable.apply(_send(OUT_OF_SCOPE_RECIPIENT))
        self.assertTrue(outcome.allowed)
        self.assertEqual(len(native.dispatch_calls), 1)
        evidence = vulnerable.treatment_evidence()
        self.assertFalse(evidence["resource_binding_enforced"])
        self.assertEqual(
            evidence["pre_dispatch_decisions"][0]["reason_code"],
            "vulnerable_resource_binding_toggle_disabled",
        )
        kinds = [event["kind"] for event in evidence["trusted_event_log"]]
        self.assertEqual(
            kinds,
            [
                "request_received",
                "policy_evaluated",
                "native_dispatch_started",
                "native_dispatch_completed",
            ],
        )

    def test_benign_direct_authority_reaches_native_in_both_arms(self):
        for arm in (TreatmentArm.VULNERABLE, TreatmentArm.PROTECTED):
            with self.subTest(arm=arm.value):
                native = _FakeNativeSession()
                session = _session(arm, PairRole.BENIGN, native=native)
                outcome = session.apply(_send(AUTHORIZED_RECIPIENT))
                self.assertTrue(outcome.allowed)
                self.assertEqual(len(native.dispatch_calls), 1)
                decision = session.treatment_evidence()["pre_dispatch_decisions"][0]
                self.assertTrue(decision["direct_authority_witness"])
                self.assertEqual(decision["reason_code"], "exact_direct_user_authority")

    def test_ordering_and_hash_witnesses_are_complete_and_monotone(self):
        session = _session(TreatmentArm.PROTECTED)
        session.apply(_send(OUT_OF_SCOPE_RECIPIENT))
        evidence = session.treatment_evidence()
        events = evidence["trusted_event_log"]
        self.assertEqual([event["event_seq"] for event in events], [1, 2, 3])
        self.assertEqual(len({event["request_sha256"] for event in events}), 1)
        self.assertEqual(
            {event["authorization_manifest_sha256"] for event in events},
            {evidence["authorization_manifest_sha256"]},
        )
        self.assertIsNone(events[0]["decision_sha256"])
        self.assertEqual(events[1]["decision_sha256"], events[2]["decision_sha256"])
        decision = evidence["pre_dispatch_decisions"][0]
        self.assertEqual(decision["event_id"], events[1]["event_id"])
        self.assertEqual(decision["pre_dispatch_sequence"], events[1]["event_seq"])
        self.assertTrue(all(event["trusted"] for event in events))

    def test_malformed_bound_request_and_condition_mismatch_fail_closed(self):
        native = _FakeNativeSession()
        protected = _session(TreatmentArm.PROTECTED, native=native)
        with self.assertRaises(FourCellBridgeError):
            protected.apply(ActionRequest(op="send_money", args={"amount": 6.0}))
        self.assertEqual(native.dispatch_calls, [])
        with self.assertRaises(IntegrityError):
            FourCellPublicHostSession(
                delegate=_FakeNativeSession(),
                treatment_arm=TreatmentArm.PROTECTED,
                pair_role=PairRole.BENIGN,
                condition_id=VULNERABLE_CONDITION_ID,
                episode_namespace="wrong-condition",
                authorization_manifest=_manifest(),
                user_prompt=REFERENCE_USER_PROMPT,
            )

    def test_terminal_capture_and_native_checker_remain_separate(self):
        native = _FakeNativeSession()
        session = _session(TreatmentArm.PROTECTED, PairRole.BENIGN, native=native)
        self.assertEqual(native.checker_calls, 0)
        terminal = session.capture_terminal_state(final_assistant_text="done")
        self.assertEqual(terminal["model_output"], "done")
        verdict = session.evaluate_native_checkers()
        self.assertEqual(verdict, {"utility": True, "security": None})
        self.assertEqual(native.checker_calls, 1)

    def test_descriptor_is_unadjudicated_nonclaim_and_execution_false(self):
        descriptor = bridge_descriptor()
        self.assertEqual(descriptor["construct_status"], BRIDGE_CONSTRUCT_STATUS)
        self.assertFalse(descriptor["execution_authorized"])
        self.assertFalse(descriptor["claim_eligible"])
        self.assertFalse(descriptor["canonical_six_mechanism_claim_eligible"])
        self.assertFalse(descriptor["hcer_claim_eligible"])
        self.assertTrue(descriptor["vulnerable_mediation_layer_installed"])

    def test_zero_token_reference_gate_covers_all_four_required_witnesses(self):
        result = run_zero_token_reference_trace_gate()
        self.assertTrue(result["validated"])
        self.assertTrue(result["schema_byte_equivalent"])
        self.assertTrue(result["shared_authorization_manifest"])
        self.assertTrue(result["direct_authority_absent_attack_witness"])
        self.assertTrue(result["host_owned_terminal_route_witness"])
        self.assertTrue(result["vulnerable_native_reach_witness"])
        self.assertTrue(result["protected_predispatch_block_witness"])
        self.assertTrue(result["dual_arm_benign_reach_witness"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["claim_eligible"])

    def test_reference_gate_mutation_fails_closed(self):
        result = run_zero_token_reference_trace_gate()
        mutated = copy.deepcopy(result)
        protected = next(
            trace
            for trace in mutated["traces"]
            if trace["cell_id"] == "adversarial-protected"
        )
        protected["native_dispatch_count_after"] = 1
        with self.assertRaises(ReferenceTraceError):
            validate_reference_trace_gate(mutated)

    def test_overlay_imports_are_local_or_stdlib_only(self):
        overlay = Path(
            "agentmembrane/host_v2/public_four_cell_v1/bridge.py"
        ).read_text(encoding="utf-8")
        tree = ast.parse(overlay)
        forbidden = {
            "planner",
            "runner",
            "cache",
            "public_host_bridge",
            "conditions",
            "prompts",
            "analysis",
            "schedule",
            "schema",
            "integrity",
            "host",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                self.assertTrue(
                    node.level == 1 and module == "contracts"
                    or node.level == 0
                    and module.split(".")[0]
                    in {
                        "__future__",
                        "copy",
                        "dataclasses",
                        "hashlib",
                        "json",
                        "pathlib",
                        "re",
                        "typing",
                    }
                )
                self.assertFalse(any(part in forbidden for part in module.split(".")))


if __name__ == "__main__":
    unittest.main()
