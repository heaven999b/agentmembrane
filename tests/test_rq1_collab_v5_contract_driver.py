import json
import time
import unittest
from unittest import mock

from agentmembrane.host_v2.rq1_collab_v1.providers import (
    HTTPReply,
    ProviderFailure,
    build_action_payload,
)
from agentmembrane.host_v2.rq1_collab_v3.contract import DEFAULT_MODELS
from agentmembrane.host_v2.rq1_collab_v5.attack_spec import (
    TRAVEL_EXFILTRATION_GOAL,
    WORKSPACE_DELETE_GOAL,
)
from agentmembrane.host_v2.rq1_collab_v5.contract import (
    DEFAULT_BUDGET,
    PHASE_SCHEDULE,
    PHASE_SCHEDULE_SHA256,
    PROTOCOL,
    digest,
    make_config,
    matrix,
    system_spec,
    validate_config,
)
from agentmembrane.host_v2.rq1_collab_v5.driver import RoleModelDriver, role_prompts
from tests.rq1_collab_v1.test_provider_action_protocol import Collector


def config(*, regime="malicious", topology="H_S_E"):
    return make_config("a" * 64, "v5-unit", topology, "high", regime)


def observation(actor):
    return {
        "protocol_version": PROTOCOL,
        "actor": actor,
        "history": [actor + "-private-context"],
    }


class ContractTests(unittest.TestCase):
    def test_phase_schedule_and_budget_are_exact_and_hash_bound(self):
        self.assertEqual(set(PHASE_SCHEDULE), {
            "schema_version",
            "external_max_decisions",
            "internal_work_max_decisions",
            "host_finalization_decisions",
            "external_phase_seconds",
            "host_finalization_reserve_seconds",
            "closure_reserve_seconds",
            "model_request_hard_timeout_seconds",
            "transport_termination_grace_seconds",
            "target_step_backend_dispatch_cap",
            "external_phase_permanently_closes",
        })
        self.assertEqual(PHASE_SCHEDULE["external_max_decisions"], 3)
        self.assertEqual(PHASE_SCHEDULE["model_request_hard_timeout_seconds"], 50)
        self.assertEqual(PHASE_SCHEDULE["transport_termination_grace_seconds"], 1)
        self.assertLessEqual(
            PHASE_SCHEDULE["model_request_hard_timeout_seconds"]
            + PHASE_SCHEDULE["transport_termination_grace_seconds"],
            PHASE_SCHEDULE["host_finalization_reserve_seconds"],
        )
        self.assertEqual(
            PHASE_SCHEDULE["internal_work_max_decisions"]
            + PHASE_SCHEDULE["host_finalization_decisions"],
            DEFAULT_BUDGET["internal_decisions"],
        )
        self.assertEqual(DEFAULT_BUDGET, {
            "internal_decisions": 9,
            "external_decisions": 3,
            "internal_tokens": 120000,
            "external_tokens": 48000,
            "max_delegations": 1,
            "wall_seconds": 360,
        })
        spec = system_spec()
        self.assertEqual(spec["phase_schedule"], PHASE_SCHEDULE)
        self.assertEqual(spec["phase_schedule_sha256"], PHASE_SCHEDULE_SHA256)
        self.assertEqual(digest(spec["phase_schedule"]), PHASE_SCHEDULE_SHA256)
        spec["phase_schedule"]["external_max_decisions"] = 99
        self.assertEqual(system_spec()["phase_schedule"], PHASE_SCHEDULE)

    def test_cell_keeps_v3_shape_but_rejects_any_budget_drift(self):
        cfg = config()
        self.assertEqual(set(cfg), {
            "protocol_version", "episode_id", "topology", "level", "regime",
            "repeat", "models", "budget", "internal_level", "execution_mode",
            "bundle_sha256",
        })
        for key in DEFAULT_BUDGET:
            changed = json.loads(json.dumps(cfg))
            changed["budget"][key] += 1
            with self.subTest(key=key), self.assertRaisesRegex(
                    ValueError, "exact_v5_bounded_budget_required"):
                validate_config(changed)

    def test_selected_matrix_uses_fixed_budget_in_both_regimes(self):
        cells = matrix(
            "a" * 64, "pilot", repeats=1, topologies=("H_E",),
            levels=("high",), regimes=("honest", "malicious"),
        )
        self.assertEqual(len(cells), 2)
        self.assertEqual({cell["regime"] for cell in cells}, {"honest", "malicious"})
        self.assertTrue(all(cell["budget"] == DEFAULT_BUDGET for cell in cells))


class PromptAndWireTests(unittest.TestCase):
    def test_malicious_attack_contract_is_e_only_and_schedule_is_visible(self):
        prompts = role_prompts(config(), "LEGITIMATE_TASK", TRAVEL_EXFILTRATION_GOAL)
        self.assertIn("ATTACK_SPEC_JSON=", prompts["E"])
        self.assertIn("external phase", prompts["E"])
        self.assertIn("One additional decision is reserved", prompts["H"])
        self.assertIn(PHASE_SCHEDULE_SHA256, prompts["H"] + prompts["S"] + prompts["E"])
        self.assertNotIn(TRAVEL_EXFILTRATION_GOAL, prompts["H"] + prompts["S"])
        self.assertNotIn("ATTACK_SPEC_JSON=", prompts["H"] + prompts["S"])

    def test_honest_prompts_never_receive_attack_target(self):
        prompts = role_prompts(
            config(regime="honest"), "LEGITIMATE_TASK", WORKSPACE_DELETE_GOAL,
        )
        self.assertNotIn(WORKSPACE_DELETE_GOAL, "\n".join(prompts.values()))
        self.assertNotIn("ATTACK_SPEC_JSON=", "\n".join(prompts.values()))

    def test_v5_wire_reuses_v4_three_actor_memory_schema_without_v3_drift(self):
        profile = DEFAULT_MODELS["H"]
        payloads = {
            version: build_action_payload(
                profile, "role", {"protocol_version": version, "actor": "H"},
                "single_tool_v1",
            )
            for version in (
                "rq1-three-actor/3", "rq1-three-actor/4", PROTOCOL,
            )
        }
        v3_function = payloads["rq1-three-actor/3"]["tools"][0]["function"]
        v4_function = payloads["rq1-three-actor/4"]["tools"][0]["function"]
        v5_function = payloads[PROTOCOL]["tools"][0]["function"]
        self.assertEqual(v4_function, v5_function)
        self.assertIn("delegate", v3_function["parameters"]["properties"]["type"]["enum"])
        self.assertNotIn("argument_refs", v3_function["parameters"]["properties"])
        self.assertIn("argument_refs", v5_function["parameters"]["properties"])


class RoleDriverTests(unittest.TestCase):
    def make_driver(self, *, transport=None):
        cfg = config()
        self.sent = []

        if transport is None:
            def transport(body):
                payload = json.loads(body)
                self.sent.append(payload)
                response = {
                    "model": payload["model"],
                    "choices": [{
                        "index": 0,
                        "finish_reason": "tool_calls",
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [{
                                "id": "test-call",
                                "type": "function",
                                "function": {
                                    "name": "submit_action",
                                    "arguments": '{"type":"final","content":"done"}',
                                },
                            }],
                        },
                    }],
                    "usage": {
                        "prompt_tokens": 10,
                        "completion_tokens": 7,
                        "total_tokens": 17,
                    },
                }
                return HTTPReply(200, json.dumps(response).encode())

        driver = RoleModelDriver(
            cfg,
            role_prompts(cfg, "public", WORKSPACE_DELETE_GOAL),
            Collector(),
            transport,
        )
        now = time.monotonic()
        driver.begin_episode(
            deadline_monotonic=now + DEFAULT_BUDGET["wall_seconds"],
            external_deadline_monotonic=now + PHASE_SCHEDULE["external_phase_seconds"],
            internal_deadline_monotonic=(
                now + DEFAULT_BUDGET["wall_seconds"]
                - PHASE_SCHEDULE["closure_reserve_seconds"]
            ),
        )
        return driver

    def test_external_request_cap_closes_only_external_pool(self):
        driver = self.make_driver()
        for _ in range(DEFAULT_BUDGET["external_decisions"]):
            self.assertEqual(json.loads(driver.next_action("E", observation("E")))["type"], "final")
        with self.assertRaisesRegex(ProviderFailure, "v5_external_pool_exhausted"):
            driver.next_action("E", observation("E"))
        snapshot = driver.budget_snapshot()
        self.assertIsNone(snapshot["fatal_halt_reason"])
        self.assertIsNotNone(snapshot["pool_halt_reasons"]["external"])
        self.assertIsNone(snapshot["pool_halt_reasons"]["internal"])
        self.assertEqual(json.loads(driver.next_action("H", observation("H")))["type"], "final")

    def test_external_actor_deadline_does_not_poison_internal_pool(self):
        driver = self.make_driver()
        external_deadline = driver.budget_snapshot()["deadlines"]["external"]
        with mock.patch(
                "agentmembrane.host_v2.rq1_collab_v1.providers.time.monotonic",
                return_value=external_deadline + 0.01):
            with self.assertRaisesRegex(ProviderFailure, "episode_deadline_exhausted"):
                driver.next_action("E", observation("E"))
        snapshot = driver.budget_snapshot()
        self.assertEqual(
            snapshot["pool_halt_reasons"]["external"],
            "episode_deadline_exhausted",
        )
        self.assertIsNone(snapshot["fatal_halt_reason"])
        self.assertEqual(json.loads(driver.next_action("H", observation("H")))["type"], "final")

    def test_delivered_external_output_budget_stop_does_not_poison_h(self):
        def transport(body):
            payload = json.loads(body)
            is_external = "You are E" in payload["messages"][0]["content"]
            completion_tokens = 9000 if is_external else 7
            response = {
                "model": payload["model"],
                "choices": [{
                    "index": 0,
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [{
                            "id": "test-call",
                            "type": "function",
                            "function": {
                                "name": "submit_action",
                                "arguments": '{"type":"final","content":"done"}',
                            },
                        }],
                    },
                }],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": completion_tokens,
                    "total_tokens": completion_tokens + 10,
                },
            }
            return HTTPReply(200, json.dumps(response).encode())

        driver = self.make_driver(transport=transport)
        with self.assertRaisesRegex(ProviderFailure, "reported_output_budget_exceeded"):
            driver.next_action("E", observation("E"))
        snapshot = driver.budget_snapshot()
        self.assertEqual(
            snapshot["pool_halt_reasons"]["external"],
            "reported_output_budget_exceeded",
        )
        self.assertIsNone(snapshot["fatal_halt_reason"])
        self.assertEqual(json.loads(driver.next_action("H", observation("H")))["type"], "final")

    def test_internal_pool_cap_does_not_close_external_pool(self):
        driver = self.make_driver()
        actors = ("H", "S")
        for index in range(DEFAULT_BUDGET["internal_decisions"]):
            actor = actors[index % len(actors)]
            driver.next_action(actor, observation(actor))
        with self.assertRaisesRegex(ProviderFailure, "v5_internal_pool_exhausted"):
            driver.next_action("H", observation("H"))
        snapshot = driver.budget_snapshot()
        self.assertIsNone(snapshot["fatal_halt_reason"])
        self.assertIsNotNone(snapshot["pool_halt_reasons"]["internal"])
        self.assertIsNone(snapshot["pool_halt_reasons"]["external"])
        self.assertEqual(json.loads(driver.next_action("E", observation("E")))["type"], "final")

    def test_delivery_unknown_is_fatal_across_pools(self):
        calls = []

        def transport(body):
            calls.append(body)
            raise ProviderFailure(
                "synthetic_delivery_unknown", delivery="delivery_unknown",
                request_id="transport-request", kind="transport_error",
            )

        driver = self.make_driver(transport=transport)
        with self.assertRaises(ProviderFailure):
            driver.next_action("E", observation("E"))
        self.assertEqual(driver.fatal_halt_reason, "synthetic_delivery_unknown")
        with self.assertRaisesRegex(ProviderFailure, "v5_fatal_provider_halted"):
            driver.next_action("H", observation("H"))
        self.assertEqual(len(calls), 1)

    def test_distinct_deadlines_are_locked_into_role_children(self):
        driver = self.make_driver()
        deadlines = driver.budget_snapshot()["deadlines"]
        self.assertEqual(
            driver.children["E"].budget_snapshot()["episode_deadline_monotonic"],
            deadlines["external"],
        )
        for actor in ("H", "S"):
            self.assertEqual(
                driver.children[actor].budget_snapshot()["episode_deadline_monotonic"],
                deadlines["internal"],
            )
        with self.assertRaisesRegex(ValueError, "already_locked"):
            driver.begin_episode(
                deadline_monotonic=deadlines["episode"],
                external_deadline_monotonic=deadlines["external"],
                internal_deadline_monotonic=deadlines["internal"],
            )


if __name__ == "__main__":
    unittest.main()
