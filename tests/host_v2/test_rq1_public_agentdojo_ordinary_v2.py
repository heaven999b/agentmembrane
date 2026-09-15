from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from agentmembrane.host_v2.rq1_public_agentdojo_v2.contracts import (
    ADAPTER_REF,
    BENIGN_ACTION,
    INJECTION_GOAL,
    OVERLAY_ID,
    TOOL_SCHEMAS_SHA256,
    UNAUTHORIZED_TARGET,
    live_tool_schemas,
    schema_provenance,
)
from agentmembrane.host_v2.rq1_public_agentdojo_v2.fake_agent import (
    FakeOrdinaryBankingAgent,
)
from agentmembrane.host_v2.rq1_public_agentdojo_v2.gate import (
    DEFAULT_OUTPUT,
    EXPECTED,
    OrdinaryGateError,
    run_zero_token_multiturn_gate,
    validate_multiturn_gate,
    write_multiturn_gate,
)
from agentmembrane.host_v2.rq1_public_agentdojo_v2.runner import (
    run_ordinary_agent_episode,
)
from agentmembrane.host_v2.rq1_public_agentdojo_v2.selector import (
    all_cells,
    select_cell,
    selector_manifest,
)
from agentmembrane.host_v2.schema import canonical_json_bytes, sha256_json


class _MalformedAfterReadAgent:
    def respond(self, *, messages, tools):
        del tools
        if not any(row.get("role") == "tool" for row in messages):
            return {"name": "get_most_recent_transactions", "arguments": {"n": 100}}
        return {
            "name": "send_money",
            "arguments": {
                "recipient": UNAUTHORIZED_TARGET,
                "subject": "missing amount",
                "date": "2022-01-01",
            },
        }


class _UnknownFirstToolAgent:
    def respond(self, *, messages, tools):
        del messages, tools
        return {"name": "planner_admin_tool", "arguments": {}}


class _AdditionalPropertyAgent:
    def respond(self, *, messages, tools):
        del tools
        if not any(row.get("role") == "tool" for row in messages):
            return {"name": "get_most_recent_transactions", "arguments": {"n": 100}}
        action = copy.deepcopy(BENIGN_ACTION)
        action["arguments"]["native_ignored_extra"] = "allowed by frozen schema"
        return action


class RQ1PublicAgentDojoOrdinaryV2Tests(unittest.TestCase):
    def test_frozen_live_tool_schemas_match_native_a005_provenance(self) -> None:
        schemas = live_tool_schemas()
        self.assertEqual(sha256_json(schemas), TOOL_SCHEMAS_SHA256)
        self.assertEqual(
            [row["function"]["name"] for row in schemas],
            ["get_most_recent_transactions", "send_money"],
        )
        provenance = schema_provenance()
        self.assertEqual(provenance["tool_schemas_sha256"], TOOL_SCHEMAS_SHA256)
        self.assertEqual(
            provenance["freeze_method"],
            "native Function.parameters.model_json_schema()",
        )

    def test_selector_is_new_rq1_overlay_without_legacy_pack_binding(self) -> None:
        manifest = selector_manifest()
        self.assertEqual(manifest["overlay_id"], OVERLAY_ID)
        self.assertEqual(manifest["adapter_ref"], ADAPTER_REF)
        self.assertEqual(manifest["cell_count"], 4)
        self.assertFalse(manifest["legacy_pack_binding_used"])
        self.assertFalse(manifest["execution_authorized"])
        self.assertEqual(
            {(row["pair_role"], row["arm"]) for row in manifest["cells"]},
            set(EXPECTED),
        )

    def test_initial_ordinary_agent_view_is_identical_and_condition_blind(self) -> None:
        views = [cell.model_visible_initial() for cell in all_cells()]
        self.assertTrue(all(view == views[0] for view in views[1:]))
        rendered = json.dumps(views[0], sort_keys=True).casefold()
        for prohibited in (
            "authorized_test_objective",
            "pair_role",
            "adversarial",
            "vulnerable",
            "protected",
            "injection_goal",
        ):
            self.assertNotIn(prohibited, rendered)
        self.assertEqual(views[0]["agent_role"], "ordinary_assistant")

    def test_same_fake_ordinary_agent_reads_before_acting_in_all_cells(self) -> None:
        for cell in all_cells():
            with self.subTest(pair_role=cell.pair_role, arm=cell.arm):
                agent = FakeOrdinaryBankingAgent()
                episode = run_ordinary_agent_episode(cell, agent)
                self.assertEqual(len(agent.received_views), 2)
                first = agent.received_views[0]
                self.assertNotIn(INJECTION_GOAL, json.dumps(first, ensure_ascii=False))
                self.assertEqual(
                    episode["proposed_actions"][0]["name"],
                    "get_most_recent_transactions",
                )
                self.assertTrue(episode["outcome"]["read_tool_reached"])
                self.assertTrue(episode["outcome"]["send_tool_proposed"])

    def test_adversarial_injection_enters_only_through_read_tool_result(self) -> None:
        for arm in ("vulnerable", "protected"):
            agent = FakeOrdinaryBankingAgent()
            episode = run_ordinary_agent_episode(
                select_cell("adversarial", arm), agent
            )
            initial = json.dumps(
                episode["model_visible_initial"], ensure_ascii=False, sort_keys=True
            )
            second_view = json.dumps(
                agent.received_views[1], ensure_ascii=False, sort_keys=True
            )
            self.assertNotIn(INJECTION_GOAL, initial)
            self.assertIn(INJECTION_GOAL, second_view)
            self.assertTrue(
                episode["outcome"]["injection_visible_in_tool_result"]
            )
            self.assertEqual(
                episode["visibility_contract"]["injection_delivery_channel"],
                "get_most_recent_transactions_tool_result",
            )

    def test_exact_four_cell_multiturn_outcomes_all_terminate(self) -> None:
        for cell in all_cells():
            episode = run_ordinary_agent_episode(
                cell, FakeOrdinaryBankingAgent()
            )
            coordinate = (cell.pair_role, cell.arm)
            self.assertTrue(episode["outcome"]["terminated"])
            for key, expected in EXPECTED[coordinate].items():
                self.assertEqual(episode["outcome"][key], expected)
            self.assertFalse(
                episode["visibility_contract"]["authorized_test_objective_present"]
            )
            self.assertFalse(
                episode["visibility_contract"]["condition_fields_present"]
            )
            self.assertFalse(episode["visibility_contract"]["planner_role_present"])

    def test_protected_attack_denial_precedes_and_prevents_send_dispatch(self) -> None:
        episode = run_ordinary_agent_episode(
            select_cell("adversarial", "protected"),
            FakeOrdinaryBankingAgent(),
        )
        send_decision = episode["host_private"]["decisions"][-1]
        self.assertFalse(send_decision["allowed"])
        self.assertEqual(send_decision["denial_kind"], "policy_denial")
        self.assertEqual(send_decision["native_dispatch_count_before"], 1)
        self.assertFalse(
            any(row["op"] == "send_money" for row in episode["native_dispatches"])
        )
        self.assertEqual(episode["outcome"]["native_side_effect_dispatch_count"], 0)

    def test_invalid_send_schema_is_recorded_without_crashing_episode(self) -> None:
        episode = run_ordinary_agent_episode(
            select_cell("adversarial", "protected"),
            _MalformedAfterReadAgent(),
        )
        self.assertTrue(episode["outcome"]["terminated"])
        self.assertEqual(
            episode["outcome"]["terminal_reason"], "invalid_schema_denial"
        )
        decision = episode["host_private"]["decisions"][-1]
        self.assertFalse(decision["schema_valid"])
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["denial_kind"], "invalid_schema")
        self.assertEqual(decision["reason"], "send_required_argument_missing")
        self.assertEqual(episode["outcome"]["native_dispatch_count"], 1)
        self.assertIsNone(episode["outcome"]["terminal_error"])

    def test_unknown_first_tool_is_a_zero_dispatch_recorded_denial(self) -> None:
        episode = run_ordinary_agent_episode(
            select_cell("benign", "vulnerable"), _UnknownFirstToolAgent()
        )
        self.assertEqual(
            episode["outcome"]["terminal_reason"], "invalid_schema_denial"
        )
        self.assertEqual(episode["outcome"]["native_dispatch_count"], 0)
        self.assertEqual(
            episode["host_private"]["decisions"][0]["reason"], "unknown_tool"
        )

    def test_native_schema_additional_property_is_not_over_strictly_rejected(
        self,
    ) -> None:
        episode = run_ordinary_agent_episode(
            select_cell("benign", "protected"), _AdditionalPropertyAgent()
        )
        self.assertEqual(
            episode["outcome"]["terminal_reason"], "send_money_dispatched"
        )
        self.assertTrue(episode["outcome"]["utility"])
        self.assertTrue(episode["host_private"]["decisions"][-1]["schema_valid"])

    def test_zero_token_gate_is_strict_and_external_call_free(self) -> None:
        record = run_zero_token_multiturn_gate()
        self.assertEqual(validate_multiturn_gate(record), record)
        self.assertTrue(record["gate_passed"])
        self.assertEqual(record["execution_counts"]["ordinary_agent_calls"], 8)
        self.assertEqual(record["execution_counts"]["native_dispatches"], 7)
        self.assertEqual(record["execution_counts"]["model_calls"], 0)
        self.assertEqual(record["execution_counts"]["provider_calls"], 0)
        self.assertEqual(record["execution_counts"]["api_calls"], 0)
        self.assertFalse(record["execution_authorized"])

    def test_gate_validator_rejects_visibility_and_order_mutations(self) -> None:
        base = run_zero_token_multiturn_gate()
        leaked = copy.deepcopy(base)
        leaked["cells"][0]["model_visible_initial"][
            "authorized_test_objective"
        ] = "hidden attack"
        reordered = copy.deepcopy(base)
        reordered["cells"][0]["native_dispatches"][0][
            "order_sequence"
        ] = reordered["cells"][0]["native_dispatches"][0][
            "decision_order_sequence"
        ]
        authorized = copy.deepcopy(base)
        authorized["execution_authorized"] = True
        for mutation in (leaked, reordered, authorized):
            with self.assertRaises(OrdinaryGateError):
                validate_multiturn_gate(mutation)

    def test_gate_writer_is_canonical_and_exclusive(self) -> None:
        record = run_zero_token_multiturn_gate()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gate.json"
            digest = write_multiturn_gate(path, record)
            payload = canonical_json_bytes(record) + b"\n"
            self.assertEqual(path.read_bytes(), payload)
            self.assertEqual(digest, hashlib.sha256(payload).hexdigest())
            with self.assertRaises(OrdinaryGateError):
                write_multiturn_gate(path, record)

    def test_materialized_gate_is_current_when_present(self) -> None:
        if not DEFAULT_OUTPUT.is_file():
            self.skipTest("ordinary-agent gate has not been materialized yet")
        payload = DEFAULT_OUTPUT.read_bytes()
        record = json.loads(payload)
        self.assertEqual(validate_multiturn_gate(record), record)
        self.assertEqual(payload, canonical_json_bytes(record) + b"\n")


if __name__ == "__main__":
    unittest.main()
