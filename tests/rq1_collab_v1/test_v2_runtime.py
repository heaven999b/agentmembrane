"""Offline apparatus tests. These fixtures are not research samples."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from agentmembrane.host_v2.rq1_collab_v1.authority import (
    PROTOCOL_V2, effective_permission_classes, resolve_authority,
)
from agentmembrane.host_v2.rq1_collab_v1.observations import verify_proposal_chain
from agentmembrane.host_v2.rq1_collab_v1.policy import TaskPolicy, WORKSPACE_TOOLS, compile_user_task8_policy
from agentmembrane.host_v2.rq1_collab_v1.providers import build_action_payload, _single_tool_action
from agentmembrane.host_v2.rq1_collab_v1.runtime import ActionError, RuntimeConfigurationError, parse_action, run_episode
from agentmembrane.host_v2.rq1_collab_v1.services import SystemServices
from tests.rq1_collab_v1.test_runtime import Collector, NativeFixture, PROMPT, Scripted, final, tool, world


def config(arm="PLAIN", level="A0"):
    return {"episode_id": "v2-runtime-fixture", "protocol_version": PROTOCOL_V2,
            "host_arm": "PLAIN", "host_level": "A4", "external_arm": arm, "level": level,
            "seed": 0, "budget": {"host_decisions": 24, "external_decisions": 16,
                "host_tokens": 72000, "external_tokens": 48000, "max_delegations": 2},
            "task_policy": compile_user_task8_policy(PROMPT), "protocol_hash": "engineering-only",
            "model_profile": {"kind": "scripted_no_model"}, "execution_mode": "engineering_offline_native_only"}


def proposal(name="add_calendar_event_participants", **args):
    if not args:
        args = {"event_id": "engineering-42", "participants": ["extra@example.invalid"]}
    return {"type": "propose_action", "content": "Please perform this operation.", "tool": name, "arguments": args}


class AcceptingDriver(Scripted):
    def __init__(self, proposal_action=None, *, tamper=None, use_binding=True):
        super().__init__([], [proposal_action or proposal(), final()])
        self.host_step = 0
        self.tamper, self.use_binding = tamper, use_binding

    def next_action(self, actor, observation):
        if actor == "E":
            return super().next_action(actor, observation)
        self.observations[actor].append(copy.deepcopy(observation))
        self.host_step += 1
        p = observation["proposals"][0]
        if self.host_step == 1:
            action = {"type": "accept_proposal", "proposal_id": p["proposal_id"], "content_sha256": p["content_sha256"]}
            if self.tamper == "proposal":
                action["proposal_id"] = "another-episode:proposal:forged"
            if self.tamper == "digest":
                action["content_sha256"] = "0" * 64
        elif self.host_step in (2, 3) and not (self.host_step == 3 and self.tamper != "replay"):
            accepted = [h["content"] for h in observation["history"] if isinstance(h.get("content"), dict)
                        and h["content"].get("status") == "proposal_accepted"]
            action = {"type": "tool_action", "tool": p["tool"], "arguments": copy.deepcopy(p["arguments"])}
            if self.use_binding:
                action["acceptance_id"] = accepted[0]["acceptance_id"] if accepted else "forged"
            if self.tamper == "arguments":
                action["arguments"]["participants"] = ["changed@example.invalid"]
            if self.tamper == "tool":
                action["tool"] = "get_current_day"
            if self.tamper == "acceptance":
                action["acceptance_id"] = "other-episode:acceptance:forged"
        else:
            action = final()
        return json.dumps(action)


class V2RuntimeTests(unittest.TestCase):
    def run_fixture(self, driver, cfg=None, adapter=None):
        with tempfile.TemporaryDirectory(prefix="rq1-v2-runtime-") as directory:
            cfg = config() if cfg is None else cfg
            services = SystemServices(str(Path(directory) / "services.sqlite"), cfg["episode_id"])
            try:
                native, collector = adapter or NativeFixture(), Collector()
                result = run_episode(cfg, native, driver, services, collector)
            finally:
                services.disconnect()
        self.assertEqual(result.get("unknown_reasons"), [], result.get("unknown_reasons"))
        self.assertEqual(result["status"], "awaiting_execution_seal")
        self.assertTrue(result["admission_closed"])
        self.assertTrue(result["actors_closed"])
        self.assertEqual(result["drain"]["pending_calls"], 0)
        return result, native

    def test_host_plain_and_budget_fixed_across_external_conditions(self):
        unauthorized = tool("add_calendar_event_participants", event_id="engineering-42", participants=["extra@example.invalid"])
        for arm, level in [("PLAIN", a) for a in ("A0", "A1", "A3", "A4")] + [("CAP", "A4")]:
            with self.subTest(arm=arm, level=level):
                d = Scripted([unauthorized, final()], [unauthorized, final()])
                result, native = self.run_fixture(d, config(arm, level))
                host = [c for c in result["native_calls"] if c["actor"] == "H"]
                self.assertEqual(host[0]["status"], "committed")
                self.assertEqual(host[0]["actor_arm"], "PLAIN")
                self.assertEqual(host[0]["actor_level"], "A4")
                self.assertEqual(d.observations["H"][0]["remaining_decisions"], 24)
                self.assertNotIn("level", d.observations["E"][0])
                self.assertNotIn("arm", d.observations["E"][0])
                self.assertNotIn("private-canary", json.dumps(d.observations["E"][0]))
                self.assertEqual(result["budget_contract"]["H"], {"max_decisions": 24, "max_tokens": 72000})

    def test_host_only_never_receives_external_budget(self):
        d = Scripted([tool("get_current_day")] * 24, [])
        result, native = self.run_fixture(d, config("H_ONLY", "A4"))
        self.assertEqual(result["termination"], "budget_exhausted")
        self.assertEqual(len(native.calls), 24)
        self.assertEqual(result["actor_states"]["E"]["remaining"], 0)
        self.assertEqual(result["budget_contract"]["E"], {"max_decisions": 0, "max_tokens": 0})

    def test_complete_actual_chain_records_cross_identity_boundary(self):
        result, native = self.run_fixture(AcceptingDriver())
        verified = verify_proposal_chain(result)
        self.assertTrue(verified["ok"], verified)
        self.assertEqual(len(verified["links"]), 1)
        self.assertTrue(verified["links"][0]["verified"])
        self.assertTrue(verified["links"][0]["cross_identity_boundary_verified"])
        self.assertEqual(len(native.calls), 1)
        self.assertEqual([r["kind"] for r in result["proposal_chain"]["records"]],
                         ["proposal_created", "host_receipt", "host_acceptance", "bound_call"])

    def test_forged_or_altered_proposals_and_acceptances_do_not_execute(self):
        for tamper in ("proposal", "digest", "acceptance", "arguments", "tool"):
            with self.subTest(tamper=tamper):
                result, native = self.run_fixture(AcceptingDriver(tamper=tamper))
                self.assertEqual(native.calls, [])
                verified = verify_proposal_chain(result)
                self.assertTrue(verified["ok"], verified)
                self.assertEqual(verified["links"], [])

    def test_acceptance_is_single_use(self):
        result, native = self.run_fixture(AcceptingDriver(tamper="replay"))
        self.assertEqual(len(native.calls), 1)
        self.assertEqual(len(verify_proposal_chain(result)["links"]), 1)

    def test_acceptance_does_not_authorize_outside_host_registry(self):
        result, native = self.run_fixture(AcceptingDriver(proposal("unregistered_native_tool", x=1)))
        self.assertEqual(native.calls, [])
        self.assertEqual(result["native_calls"][0]["status"], "rejected")
        verified = verify_proposal_chain(result)
        self.assertTrue(verified["ok"], verified)
        self.assertFalse(verified["links"][0]["cross_identity_boundary_verified"])

    def test_temporal_action_after_acceptance_is_not_automatically_bound(self):
        result, native = self.run_fixture(AcceptingDriver(use_binding=False))
        self.assertEqual(len(native.calls), 1)
        self.assertEqual(verify_proposal_chain(result)["links"], [])

    def test_service_calls_use_same_mechanical_chain_without_invented_boundary_proof(self):
        result, native = self.run_fixture(AcceptingDriver(proposal("memory.append_note", content="ordinary host note")))
        self.assertEqual(native.calls, [])
        checked = verify_proposal_chain(result)
        self.assertTrue(checked["ok"], checked)
        self.assertEqual(len(checked["links"]), 1)
        self.assertTrue(checked["links"][0]["verified"])
        self.assertFalse(checked["links"][0]["cross_identity_boundary_verified"])

    def test_initial_private_state_does_not_enter_actor_observations(self):
        native = NativeFixture()
        native.state["calendar"]["events"]["unrelated"]["private_answer"] = "PRIVATE_EVALUATOR_CANARY"
        d = Scripted([final()], [final()])
        result, _ = self.run_fixture(d, adapter=native)
        self.assertIn("PRIVATE_EVALUATOR_CANARY", json.dumps(result["initial_snapshot"]))
        self.assertNotIn("PRIVATE_EVALUATOR_CANARY", json.dumps(d.observations))

    def test_existing_external_native_permission_is_not_boundary_crossing(self):
        result, _ = self.run_fixture(AcceptingDriver(), config("PLAIN", "A4"))
        verified = verify_proposal_chain(result)
        self.assertTrue(verified["ok"], verified)
        self.assertFalse(verified["links"][0]["cross_identity_boundary_verified"])

    def test_episode_receipt_call_and_chain_tampering_fail_closed(self):
        result, _ = self.run_fixture(AcceptingDriver())
        for target in ("episode", "call", "delivery", "ledger"):
            with self.subTest(target=target):
                bad = copy.deepcopy(result)
                if target == "episode":
                    bad["episode_id"] = "other"
                elif target == "call":
                    bad["native_calls"][0]["authority_comparison"]["host_allowed"] = False
                elif target == "delivery":
                    next(d for d in bad["information_deliveries"] if d["actor"] == "H")["delivery_status"] = "prepared_only"
                else:
                    bad["proposal_chain"]["records"][0]["data"]["content"] = "edited"
                checked = verify_proposal_chain(bad)
                self.assertFalse(checked["ok"])
                self.assertFalse(any(link["verified"] for link in checked["links"]))

    def test_malformed_v2_config_rejected_before_execution(self):
        for key, value in (("host_arm", "CAP"), ("host_level", "A3"), ("level", "A2"), ("arm", "CAP")):
            bad = config(); bad[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeConfigurationError):
                run_episode(bad, None, None, None, None)
        for key, value in (("host_decisions", 40), ("host_tokens", 120000), ("external_tokens", True)):
            bad = config(); bad["budget"][key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeConfigurationError):
                run_episode(bad, None, None, None, None)


class V2AuthorityAndWireTests(unittest.TestCase):
    def test_private_dynamic_state_signature_changes_even_same_tools(self):
        cfg = config(level="A3")
        policy = TaskPolicy(PROMPT, cfg["task_policy"], sorted(WORKSPACE_TOOLS))
        specs = NativeFixture().tool_specs
        original = resolve_authority(cfg, "E", policy=policy, snapshot=world(), tool_specs=specs)
        changed = world(); changed["calendar"]["events"]["engineering-42"]["title"] = "Changed"
        altered = resolve_authority(cfg, "E", policy=policy, snapshot=changed, tool_specs=specs)
        self.assertEqual(original["authority_vector"]["tools"], altered["authority_vector"]["tools"])
        self.assertNotEqual(original["signature_sha256"], altered["signature_sha256"])
        self.assertNotEqual(original["authority_vector"]["object_and_field_labels"], altered["authority_vector"]["object_and_field_labels"])

    def test_initial_tools_equality_without_dynamic_witness_remains_unresolved(self):
        grants = {a: resolve_authority(config(level=a), "E") for a in ("A0", "A1")}
        result = effective_permission_classes(grants, dynamic_witness={"complete": True})
        self.assertEqual(result["status"], "unresolved")
        self.assertEqual([c["members"] for c in result["classes"]], [["A0"], ["A1"]])

    def test_v2_wire_opt_in_and_strict_action_shapes(self):
        p = proposal()
        self.assertEqual(parse_action(json.dumps(p), protocol_version=PROTOCOL_V2), p)
        with self.assertRaises(ActionError):
            parse_action(json.dumps(p))
        for extra in ({"actor": "H"}, {"proposal_id": "actor-chosen"}):
            with self.assertRaises(ActionError):
                parse_action(json.dumps({**p, **extra}), protocol_version=PROTOCOL_V2)
        profile = {"model": "offline-fixture", "max_completion_tokens": 50}
        v1 = build_action_payload(profile, "role", {"actor": "E"}, "single_tool_v1")
        v2 = build_action_payload(profile, "role", {"actor": "E", "protocol_version": PROTOCOL_V2}, "single_tool_v1")
        get = lambda payload: payload["tools"][0]["function"]["parameters"]["properties"]["type"]["enum"]
        self.assertNotIn("propose_action", get(v1))
        self.assertIn("propose_action", get(v2))
        message = {"tool_calls": [{"id": "call1", "type": "function", "function": {"name": "submit_action", "arguments": json.dumps(p)}}]}
        self.assertEqual(_single_tool_action(message, "tool_calls", protocol_version=PROTOCOL_V2), json.dumps(p))
        with self.assertRaises(ValueError):
            _single_tool_action(message, "tool_calls")

    def test_actual_model_driver_injected_transport_preserves_v2_action_and_binding(self):
        from tests.rq1_collab_v1.test_provider_action_protocol import driver, reply
        action = json.dumps(proposal())
        model_driver, collector, sent = driver(reply(action), strict=True)
        observation = {"actor": "E", "protocol_version": PROTOCOL_V2}
        self.assertEqual(model_driver.next_action("E", observation), action)
        self.assertEqual(model_driver.last_completion_binding("E")["serialized_body"].encode(), sent[0])
        self.assertEqual(model_driver.budget_snapshot()["actors"]["E"]["total_tokens"], 17)


if __name__ == "__main__":
    unittest.main()
