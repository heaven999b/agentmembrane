from __future__ import annotations

import unittest

from agentmembrane.host_v2.projected_checker import (
    AuthorizationDecision,
    FieldProvenance,
    MECHANISM_IDS,
    MechanismEvidence,
    PROJECTED_CHECKER_CONTRACT_VERSION,
    TrustedEvent,
    TrustedStateDelta,
    TrustedTerminal,
    evaluate_projected_snapshot,
    make_projected_snapshot,
    projected_snapshot_from_mapping,
)
from agentmembrane.host_v2.public_evidence import TRUSTED_MECHANISM_IDS
from agentmembrane.host_v2.schema import SchemaError, sha256_bytes


def _sha(label: str) -> str:
    return sha256_bytes(label.encode("utf-8"))


def _provenance(kind: str, field: str) -> tuple[FieldProvenance, ...]:
    return (
        FieldProvenance(
            source_id=f"source:{kind}",
            source_kind=kind,
            source_sha256=_sha(f"source:{kind}"),
            field_path=field,
        ),
    )


def _event(index: int, event_type: str) -> TrustedEvent:
    event_id = f"event-{index}"
    return TrustedEvent(
        event_id=event_id,
        sequence_index=index,
        event_type=event_type,
        actor_id="fixture-host",
        action=f"fixture-action-{index}",
        payload_sha256=_sha(f"payload-{index}"),
        authorization=AuthorizationDecision(
            decision_id=f"decision-{index}",
            principal_id="fixture-principal",
            action=f"fixture-action-{index}",
            outcome="authorized",
            credential_id=None,
            provenance=_provenance("authorization_log", f"$.events[{index}].auth"),
        ),
        provenance=_provenance("adapter_trace", f"$.events[{index}]"),
    )


def _snapshot():
    events = (
        _event(0, "cross_boundary_handoff"),
        _event(1, "authorization_decision"),
        _event(2, "tool_invocation"),
        _event(3, "host_action"),
        _event(4, "follow_on_action"),
        _event(5, "terminal_output"),
        _event(6, "state_observation"),
    )
    mechanisms = (
        MechanismEvidence(
            MECHANISM_IDS[0], "eligible", ("event-0",), None, None,
            _provenance("mechanism_mapping", "$.mechanisms[0]"),
        ),
        MechanismEvidence(
            MECHANISM_IDS[1], "eligible", (), None, None,
            _provenance("mechanism_mapping", "$.mechanisms[1]"),
        ),
        MechanismEvidence(
            MECHANISM_IDS[2], "excluded", (), "OUT_OF_SCOPE", "No second tool.",
            _provenance("mechanism_mapping", "$.mechanisms[2]"),
        ),
        MechanismEvidence(
            MECHANISM_IDS[3], "eligible", ("event-3",), None, None,
            _provenance("mechanism_mapping", "$.mechanisms[3]"),
        ),
        MechanismEvidence(
            MECHANISM_IDS[4], "excluded", (), "NO_FOLLOW_ON", "Not eligible.",
            _provenance("mechanism_mapping", "$.mechanisms[4]"),
        ),
        MechanismEvidence(
            MECHANISM_IDS[5], "eligible", (), None, None,
            _provenance("mechanism_mapping", "$.mechanisms[5]"),
        ),
    )
    return make_projected_snapshot(
        contract_version=PROJECTED_CHECKER_CONTRACT_VERSION,
        benchmark="synthetic-benchmark",
        task_id="synthetic-task",
        trace_id="synthetic-trace",
        events=events,
        pre_state_sha256=_sha("pre"),
        post_state_sha256=_sha("post"),
        state_delta=TrustedStateDelta(
            delta_id="delta-1",
            delta_kind="updated",
            before_sha256=_sha("pre"),
            after_sha256=_sha("post"),
            changed_paths=("$.fixture",),
            witness_event_ids=("event-6",),
            provenance=_provenance("state_snapshot", "$.state_delta"),
        ),
        terminal=TrustedTerminal(
            output_sha256=_sha("terminal"),
            reason="completed",
            witness_event_ids=("event-5",),
            provenance=_provenance("terminal_capture", "$.terminal"),
        ),
        mechanism_evidence=mechanisms,
    )


class ProjectedCheckerTests(unittest.TestCase):
    def test_mechanism_ids_equal_established_host_action_construct(self) -> None:
        self.assertEqual(MECHANISM_IDS, TRUSTED_MECHANISM_IDS)

    def test_complete_synthetic_snapshot_is_deterministic_but_no_go(self) -> None:
        first = evaluate_projected_snapshot(_snapshot())
        second = evaluate_projected_snapshot(_snapshot())
        self.assertEqual(first.as_json(), second.as_json())
        self.assertEqual(first.decision, "NO_GO")
        self.assertTrue(first.checker_complete)
        self.assertEqual(
            [item.status for item in first.mechanisms],
            [
                "observed",
                "not_observed",
                "not_applicable",
                "observed",
                "not_applicable",
                "not_observed",
            ],
        )
        self.assertIn("NATIVE_PARITY_NOT_ESTABLISHED", first.blocker_codes)

    def test_digest_mismatch_fails_all_six_closed(self) -> None:
        raw = _snapshot().as_json()
        raw["state_delta"]["before_sha256"] = _sha("wrong")
        result = evaluate_projected_snapshot(projected_snapshot_from_mapping(raw))
        self.assertFalse(result.checker_complete)
        self.assertIn("STATE_DIGEST_MISMATCH", result.blocker_codes)
        self.assertEqual(
            {item.status for item in result.mechanisms}, {"insufficient_evidence"}
        )

    def test_unrecognized_event_and_wrong_source_kind_fail_closed(self) -> None:
        raw = _snapshot().as_json()
        raw["events"][0]["event_type"] = "native_checker_verdict"
        raw["terminal"]["provenance"][0]["source_kind"] = "adapter_trace"
        result = evaluate_projected_snapshot(projected_snapshot_from_mapping(raw))
        self.assertIn("EVENT_TYPE_UNRECOGNIZED", result.blocker_codes)
        self.assertIn("PROHIBITED_NATIVE_SIGNAL", result.blocker_codes)
        self.assertIn("TERMINAL_PROVENANCE_INVALID", result.blocker_codes)
        self.assertTrue(
            all(item.status == "insufficient_evidence" for item in result.mechanisms)
        )

    def test_missing_explicit_exclusion_is_insufficient(self) -> None:
        raw = _snapshot().as_json()
        raw["mechanism_evidence"][2]["exclusion_code"] = None
        result = evaluate_projected_snapshot(projected_snapshot_from_mapping(raw))
        by_id = {item.mechanism_id: item for item in result.mechanisms}
        self.assertEqual(by_id[MECHANISM_IDS[2]].status, "insufficient_evidence")
        self.assertIn("EXPLICIT_EXCLUSION_MISSING", result.blocker_codes)

    def test_exact_parser_rejects_native_verdict_or_reward_fields(self) -> None:
        for field in ("native_verdict", "reward"):
            with self.subTest(field=field):
                raw = _snapshot().as_json()
                raw[field] = True
                with self.assertRaises(SchemaError):
                    projected_snapshot_from_mapping(raw)


if __name__ == "__main__":
    unittest.main()
