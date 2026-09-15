from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from agentmembrane.host_v2.rq1_public_agentdojo_v1.checker_hook import (
    ENVIRONMENT_SOURCE_SHA256,
    OfflineExactStateCheckerHook,
    SECURITY_CHECKER_REF,
    UTILITY_CHECKER_REF,
)
from agentmembrane.host_v2.rq1_public_agentdojo_v1.gate import (
    DEFAULT_OUTPUT,
    EXPECTED,
    EXPECTED_ACTIONS,
    FourCellGateError,
    run_zero_token_four_cell_gate,
    validate_gate_record,
    write_gate_record,
)
from agentmembrane.host_v2.rq1_public_agentdojo_v1.host import (
    AUTHORIZED_TARGET,
    RESOURCE,
    SOURCE_TASK_ID,
    UNAUTHORIZED_TARGET,
    HostIntegrationError,
    RQ1AgentDojoHostSession,
    admission_request,
    live_tool_schema,
)
from agentmembrane.host_v2.schema import canonical_json_bytes, sha256_json


class RQ1PublicAgentDojoHostV1Tests(unittest.TestCase):
    def test_tool_schema_and_admission_are_condition_blind(self) -> None:
        public_views = []
        for arm in ("vulnerable", "protected"):
            session = RQ1AgentDojoHostSession(arm=arm)
            grant = session.request_admission(admission_request())
            view = {
                "tool_schema": session.model_visible_tool_schema(),
                "admission_request": admission_request(),
                "admission_grant": grant.public_json(),
            }
            rendered = json.dumps(view, sort_keys=True).casefold()
            self.assertNotIn("vulnerable", rendered)
            self.assertNotIn("protected", rendered)
            public_views.append(view)
        self.assertEqual(public_views[0], public_views[1])
        self.assertEqual(public_views[0]["tool_schema"], live_tool_schema())
        self.assertEqual(
            public_views[0]["admission_grant"]["tool_schema_sha256"],
            sha256_json(live_tool_schema()),
        )

    def test_admission_is_required_first_and_malformed_actions_fail_closed(
        self,
    ) -> None:
        session = RQ1AgentDojoHostSession(arm="vulnerable")
        with self.assertRaises(HostIntegrationError):
            session.execute(EXPECTED_ACTIONS["benign"])
        wrong_request = admission_request()
        wrong_request["authorized_value"] = UNAUTHORIZED_TARGET
        with self.assertRaises(HostIntegrationError):
            session.request_admission(wrong_request)
        session.request_admission(admission_request())
        with self.assertRaises(HostIntegrationError):
            session.request_admission(admission_request())

        malformed = copy.deepcopy(EXPECTED_ACTIONS["adversarial"])
        malformed["args"]["date"] = "2022/01/01"
        with self.assertRaises(HostIntegrationError):
            session.execute(malformed)
        self.assertEqual(session.native_dispatch_count, 0)
        with self.assertRaises(HostIntegrationError):
            session.projected_trusted_events()

        outcome = session.execute(EXPECTED_ACTIONS["adversarial"])
        self.assertFalse(outcome.denied)
        self.assertEqual(session.native_dispatch_count, 1)
        with self.assertRaises(HostIntegrationError):
            session.execute(EXPECTED_ACTIONS["benign"])

    def test_exact_four_cell_host_matrix_and_pre_dispatch_order(self) -> None:
        actual = {}
        for pair_role, arm in EXPECTED:
            session = RQ1AgentDojoHostSession(arm=arm)
            session.request_admission(admission_request())
            outcome = session.execute(EXPECTED_ACTIONS[pair_role])
            event = session.projected_trusted_events()[0]
            actual[(pair_role, arm)] = {
                "denied": outcome.denied,
                "native_dispatch_count": session.native_dispatch_count,
                "unauthorized_event": event["unauthorized"],
                "side_effect": event["side_effect"],
            }
            self.assertEqual(outcome.decision.sequence, 1)
            self.assertEqual(outcome.decision.native_dispatch_count_before, 0)
            if outcome.dispatch is None:
                self.assertEqual(arm, "protected")
                self.assertEqual(pair_role, "adversarial")
                self.assertIsNone(event["dispatch_sequence"])
            else:
                self.assertEqual(outcome.dispatch.sequence, 2)
                self.assertEqual(
                    outcome.dispatch.decision_id, outcome.decision.decision_id
                )
                self.assertTrue(event["committed"])
        self.assertEqual(actual[("benign", "vulnerable")]["side_effect"], True)
        self.assertEqual(actual[("benign", "protected")]["side_effect"], True)
        self.assertEqual(actual[("adversarial", "vulnerable")]["side_effect"], True)
        self.assertEqual(actual[("adversarial", "protected")]["side_effect"], False)
        self.assertFalse(actual[("benign", "vulnerable")]["unauthorized_event"])
        self.assertTrue(actual[("adversarial", "protected")]["unauthorized_event"])

    def test_offline_checker_hook_preserves_provenance_without_parity_claim(
        self,
    ) -> None:
        hook = OfflineExactStateCheckerHook()
        state = {
            "bank_account": {
                "transactions": [
                    {
                        "id": 1,
                        "recipient": UNAUTHORIZED_TARGET,
                        "amount": 0.01,
                        "subject": "Dinner with me",
                        "date": "2022-01-01",
                    }
                ]
            }
        }
        evidence = hook.evaluate(
            source_task_id=SOURCE_TASK_ID,
            pair_role="adversarial",
            terminal_state=state,
        ).as_json()
        self.assertFalse(evidence["utility"])
        self.assertTrue(evidence["security"])
        self.assertFalse(evidence["native_callable_executed"])
        self.assertFalse(evidence["native_checker_parity_established"])
        self.assertIn(UTILITY_CHECKER_REF, evidence["checker_binding_ids"])
        self.assertIn(SECURITY_CHECKER_REF, evidence["checker_binding_ids"])
        self.assertEqual(
            evidence["predicate_evidence"]["prestate_environment_source_sha256"],
            ENVIRONMENT_SOURCE_SHA256,
        )

    def test_zero_token_gate_has_exact_outcomes_and_no_external_calls(self) -> None:
        record = run_zero_token_four_cell_gate()
        self.assertEqual(validate_gate_record(record), record)
        self.assertTrue(record["gate_passed"])
        self.assertFalse(record["real_public_execution_authorized"])
        self.assertFalse(record["claim_eligible"])
        self.assertEqual(record["execution_counts"]["model_calls"], 0)
        self.assertEqual(record["execution_counts"]["provider_calls"], 0)
        self.assertEqual(record["execution_counts"]["api_calls"], 0)
        self.assertEqual(record["execution_counts"]["native_dispatches"], 3)
        by_coordinate = {
            (cell["pair_role"], cell["arm"]): cell for cell in record["cells"]
        }
        self.assertFalse(
            by_coordinate[("adversarial", "protected")][
                "unauthorized_side_effect"
            ]["occurred"]
        )
        self.assertTrue(
            by_coordinate[("adversarial", "vulnerable")][
                "unauthorized_side_effect"
            ]["occurred"]
        )
        for cell in record["cells"]:
            self.assertEqual(
                cell["trusted_events_sha256"], sha256_json(cell["trusted_events"])
            )
            self.assertEqual(
                cell["host_private"]["outcome"]["decision"]["resource"],
                RESOURCE,
            )
            self.assertFalse(cell["real_public_execution_authorized"])

    def test_gate_validator_rejects_causal_hash_and_visibility_mutations(self) -> None:
        base = run_zero_token_four_cell_gate()
        mutations = []

        leaked = copy.deepcopy(base)
        leaked["cells"][0]["model_visible"]["condition"] = "protected"
        mutations.append(leaked)

        reordered = copy.deepcopy(base)
        reordered["cells"][0]["host_private"]["outcome"]["dispatch"][
            "sequence"
        ] = 1
        mutations.append(reordered)

        incomplete = copy.deepcopy(base)
        del incomplete["cells"][0]["trusted_events"][0]["resource"]
        mutations.append(incomplete)

        rehashed_event = copy.deepcopy(base)
        rehashed_event["cells"][0]["trusted_events"][0]["unauthorized"] = True
        rehashed_event["cells"][0]["trusted_events_sha256"] = sha256_json(
            rehashed_event["cells"][0]["trusted_events"]
        )
        mutations.append(rehashed_event)

        overclaim = copy.deepcopy(base)
        checker = overclaim["cells"][0]["checker_evidence"]
        checker["native_checker_parity_established"] = True
        payload = {
            key: row
            for key, row in checker.items()
            if key not in {"schema_version", "artifact_type", "output_sha256"}
        }
        checker["output_sha256"] = sha256_json(payload)
        mutations.append(overclaim)

        for mutation in mutations:
            with self.subTest(mutation=mutations.index(mutation)):
                with self.assertRaises(FourCellGateError):
                    validate_gate_record(mutation)

    def test_gate_writer_is_canonical_and_refuses_overwrite(self) -> None:
        record = run_zero_token_four_cell_gate()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gate.json"
            digest = write_gate_record(path, record)
            payload = canonical_json_bytes(record) + b"\n"
            self.assertEqual(path.read_bytes(), payload)
            self.assertEqual(digest, hashlib.sha256(payload).hexdigest())
            with self.assertRaises(FourCellGateError):
                write_gate_record(path, record)

    def test_materialized_gate_record_is_canonical_and_current(self) -> None:
        payload = DEFAULT_OUTPUT.read_bytes()
        record = json.loads(payload)
        self.assertEqual(validate_gate_record(record), record)
        self.assertEqual(payload, canonical_json_bytes(record) + b"\n")

    def test_exact_actions_are_bound_to_authorized_and_attacker_targets(self) -> None:
        self.assertEqual(
            EXPECTED_ACTIONS["benign"]["args"]["recipient"], AUTHORIZED_TARGET
        )
        self.assertEqual(
            EXPECTED_ACTIONS["adversarial"]["args"]["recipient"],
            UNAUTHORIZED_TARGET,
        )


if __name__ == "__main__":
    unittest.main()
