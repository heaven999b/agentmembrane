"""Travel profile unit/native-contract checks, never model experiment samples."""
from __future__ import annotations

import copy
import inspect
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.rq1_collab_v1.native import NativeTask
from agentmembrane.host_v2.rq1_collab_v1 import profiles_travel
from agentmembrane.host_v2.rq1_collab_v1.profiles_travel import (
    CONTACT_LABEL, PUBLIC_TOOLS, TRAVEL_TOOLS, TravelEngineeringDriver, TravelPolicy, compile_travel_policy,
)
from agentmembrane.host_v2.rq1_collab_v1.policy import PolicyError, canonical_hash

PROJECT = Path(__file__).resolve().parents[2]
SOURCE = str(PROJECT / "data/host_boundary_v2/upstream/agentdojo")


def observation(task, actor, tools=None, history=None, level="A4"):
    return {"task": task.prompt, "actor": actor, "level": level,
            "remaining_decisions": 20, "history": history if history is not None else [],
            "tools": task.tool_specs if tools is None else tools, "service_scopes": []}


def run_actor(driver, actor, task, policy, *, level="A4", arm="PLAIN", history=None):
    history = [] if history is None else copy.deepcopy(history)
    steps = []
    tools = [tool for tool in task.tool_specs if tool["name"] in policy.native_tools(level)]
    for index in range(20):
        action = json.loads(driver.next_action(actor, observation(task, actor, tools, history, level)))
        history.append({"role": "action", "content": json.dumps(action)})
        if action["type"] == "final":
            return action, steps, history
        if action["type"] != "tool_action":
            raise AssertionError("unexpected engineering action")
        permit, reason = policy.authorize(level, arm, action["tool"], action["arguments"], task.snapshot())
        steps.append(action)
        if not permit:
            history.append({"role": "observation", "content": {"status": "denied", "reason_code": reason}})
            continue
        call = task.call(action["tool"], action["arguments"])
        if call["error"]:
            history.append({"role": "observation", "content": {"status": "tool_error", "error": call["error"]}})
            continue
        result, _ = policy.project_result(level, arm, action["tool"], call["result"], call["after"])
        history.append({"role": "observation", "content": {"status": "tool_result", "call_id": f"test-{index}", "result": result}})
    raise AssertionError("driver exhausted 20 test steps")


class TravelProfileTests(unittest.TestCase):
    def task(self, number=0):
        return NativeTask(SOURCE, "travel", f"user_task_{number}")

    def policy(self, task):
        task_id = task.record.get("task_id", task.record.get("original_id"))
        # Task number is passed by the caller's actual task record, never any
        # hidden answer or reference trace. Current NativeTask records use id.
        if task_id is None:
            task_id = task.record.get("id")
        manifest = compile_travel_policy(task_id, task.prompt)
        return TravelPolicy(task.prompt, manifest, [item["name"] for item in task.tool_specs])

    def test_original_prompt_compilation_is_request_only_and_mutation_sensitive(self):
        task = self.task()
        manifest = compile_travel_policy("user_task_0", task.prompt)
        facts = manifest["facts_from_actor_prompt"]
        self.assertEqual(manifest["task"], "travel/user_task_0")
        self.assertFalse(manifest["policy_reads_gold"])
        self.assertEqual(set(facts), {"city", "hotel_name", "rating_strictly_greater_than", "start_day", "end_day"})
        changed = task.prompt.replace(facts["hotel_name"], "Public Request Hotel")
        revised = compile_travel_policy("travel/user_task_0", changed)
        self.assertEqual(revised["facts_from_actor_prompt"]["hotel_name"], "Public Request Hotel")
        self.assertNotEqual(revised["policy_hash"], manifest["policy_hash"])
        with self.assertRaises(PolicyError):
            TravelPolicy(changed, manifest, [item["name"] for item in task.tool_specs])

    def test_profile_has_no_answer_or_private_checker_import(self):
        source = inspect.getsource(profiles_travel)
        for forbidden in ("GROUND_TRUTH_OUTPUT", "ground_truth(", "pilot_checkers", "_HOTEL_NAME", "Le Baratin", "New Asiaway"):
            self.assertNotIn(forbidden, source)

    def test_native_tools_genuinely_nested_and_public_retrieval_real(self):
        for number in (0, 2):
            task = self.task(number)
            policy = TravelPolicy(task.prompt, compile_travel_policy(f"user_task_{number}", task.prompt), [s["name"] for s in task.tool_specs])
            self.assertEqual(set(s["name"] for s in task.tool_specs), set(TRAVEL_TOOLS))
            levels = [set(policy.native_tools(level)) for level in ("A0", "A1", "A3", "A4")]
            self.assertFalse(levels[0])
            self.assertEqual(levels[1], set(PUBLIC_TOOLS))
            self.assertTrue(all(left <= right for left, right in zip(levels, levels[1:])))
            self.assertIn("get_all_restaurants_in_city", levels[1])
            self.assertNotIn("get_user_information", levels[1])
            if number == 2:
                self.assertEqual(levels[1], levels[2])
            else:
                self.assertIn("reserve_hotel", levels[2])

    def test_same_level_phone_projection_equal_across_arms(self):
        task = self.task()
        policy = TravelPolicy(task.prompt, compile_travel_policy("user_task_0", task.prompt), [s["name"] for s in task.tool_specs])
        result = task.call("get_user_information", {})
        plain = policy.project_result("A3", "PLAIN", "get_user_information", result["result"], result["after"])
        cap = policy.project_result("A3", "CAP", "get_user_information", result["result"], result["after"])
        self.assertEqual(plain, cap)
        self.assertEqual(set(plain[0]), {"Phone Number"})
        self.assertEqual(plain[1], [CONTACT_LABEL])
        self.assertEqual(policy.project_result("A4", "PLAIN", "get_user_information", result["result"], result["after"])[0], result["result"])
        self.assertGreater(len(result["result"]), len(plain[0]))
        self.assertTrue(policy.authorize("A3", "CAP", "get_user_information", {}, task.snapshot())[0])
        self.assertFalse(policy.authorize("A4", "CAP", "get_user_information", {}, task.snapshot())[0])
        self.assertTrue(policy.authorize("A4", "PLAIN", "get_user_information", {}, task.snapshot())[0])

    def test_cap_checks_dates_and_live_rating_not_hidden_reference(self):
        task = self.task()
        policy = TravelPolicy(task.prompt, compile_travel_policy("user_task_0", task.prompt), [s["name"] for s in task.tool_specs])
        facts = policy.facts
        args = {"hotel": facts["hotel_name"], "start_day": facts["start_day"], "end_day": facts["end_day"]}
        snapshot = task.snapshot()
        self.assertTrue(policy.authorize("A3", "CAP", "reserve_hotel", args, snapshot)[0])
        changed_dates = {**args, "end_day": "2025-02-01"}
        self.assertTrue(policy.authorize("A3", "PLAIN", "reserve_hotel", changed_dates, snapshot)[0])
        self.assertFalse(policy.authorize("A3", "CAP", "reserve_hotel", changed_dates, snapshot)[0])
        low = copy.deepcopy(snapshot)
        matches = [h for h in low["hotels"]["hotel_list"] if h["name"] == facts["hotel_name"] and h["city"] == facts["city"]]
        self.assertEqual(len(matches), 1)
        matches[0]["rating"] = facts["rating_strictly_greater_than"]
        self.assertFalse(policy.authorize("A3", "CAP", "reserve_hotel", args, low)[0])
        self.assertTrue(policy.authorize("A3", "PLAIN", "reserve_hotel", args, low)[0])
        ambiguous = copy.deepcopy(snapshot)
        ambiguous["hotels"]["hotel_list"].append(copy.deepcopy(matches[0]))
        self.assertFalse(policy.authorize("A3", "CAP", "reserve_hotel", args, ambiguous)[0])
        self.assertFalse(policy.authorize("A1", "PLAIN", "reserve_hotel", args, snapshot)[0])

    def test_readonly_restaurant_task_blocks_writes_in_cap(self):
        task = self.task(2)
        policy = TravelPolicy(task.prompt, compile_travel_policy("user_task_2", task.prompt), [s["name"] for s in task.tool_specs])
        self.assertFalse(policy.authorize("A4", "CAP", "send_email", {}, task.snapshot())[0])
        self.assertTrue(policy.authorize("A4", "PLAIN", "send_email", {}, task.snapshot())[0])
        self.assertFalse(policy.authorize("A1", "CAP", "get_all_restaurants_in_city", {"city": "Outside City"}, task.snapshot())[0])
        self.assertTrue(policy.authorize("A1", "CAP", "get_all_restaurants_in_city", {"city": policy.facts["city"]}, task.snapshot())[0])

    def test_duplicate_reservation_guard_and_native_idempotence_are_distinct(self):
        task = self.task()
        policy = TravelPolicy(task.prompt, compile_travel_policy("user_task_0", task.prompt), [s["name"] for s in task.tool_specs])
        args = {"hotel": policy.facts["hotel_name"], "start_day": policy.facts["start_day"], "end_day": policy.facts["end_day"]}
        first = task.call("reserve_hotel", args)
        self.assertIsNone(first["error"])
        self.assertEqual(policy.authorize("A3", "CAP", "reserve_hotel", args, task.snapshot()),
                         (False, "request_already_fulfilled_no_repeat_submission"))
        self.assertTrue(policy.authorize("A3", "PLAIN", "reserve_hotel", args, task.snapshot())[0])
        second = task.call("reserve_hotel", args)
        self.assertIsNone(second["error"])
        self.assertEqual(first["after"], second["after"])
        self.assertEqual(second["effects"], [])

    def test_host_only_native_original_tasks_complete_from_observations(self):
        for number in (0, 2):
            task = self.task(number)
            policy = TravelPolicy(task.prompt, compile_travel_policy(f"user_task_{number}", task.prompt), [s["name"] for s in task.tool_specs])
            before = task.snapshot()
            final, steps, _ = run_actor(TravelEngineeringDriver(f"user_task_{number}"), "H", task, policy, arm="H_ONLY")
            self.assertTrue(task.native_score(before, task.snapshot(), final["content"]))
            self.assertIsInstance(json.loads(final["content"]), dict)
            self.assertGreaterEqual(len(steps), 2)
            if number == 2:
                self.assertEqual(before, task.snapshot())

    def test_e_reads_only_and_host_consumes_actual_mailbox_observation(self):
        for number in (0, 2):
            task = self.task(number)
            policy = TravelPolicy(task.prompt, compile_travel_policy(f"user_task_{number}", task.prompt), [s["name"] for s in task.tool_specs])
            driver = TravelEngineeringDriver(f"user_task_{number}")
            before = task.snapshot()
            external, e_steps, _ = run_actor(driver, "E", task, policy, level="A1", arm="CAP")
            self.assertTrue(all(step["tool"] in PUBLIC_TOOLS for step in e_steps))
            self.assertEqual(before, task.snapshot())
            no_mail = json.loads(driver.next_action("H", observation(task, "H")))
            self.assertEqual(no_mail["type"], "tool_action")
            # This unit test supplies the runtime's actual message shape; root
            # integration separately verifies real route.send/consume effects.
            history = [{"role": "observation", "content": {"status": "messages", "messages": [{"sender": "E", "content": external["content"]}]}}]
            final, h_steps, _ = run_actor(driver, "H", task, policy, arm="CAP", history=history)
            self.assertTrue(task.native_score(before, task.snapshot(), final["content"]))
            self.assertEqual([step["tool"] for step in h_steps], ["reserve_hotel"] if number == 0 else [])

    def test_low_level_unavailability_and_live_denial_not_overridden(self):
        task = self.task()
        driver = TravelEngineeringDriver("user_task_0")
        denied = json.loads(driver.next_action("E", observation(task, "E", tools=[], level="A0")))
        self.assertEqual(denied["type"], "final")
        first = json.loads(driver.next_action("H", observation(task, "H")))
        history = [{"role": "action", "content": json.dumps(first)}, {"role": "observation", "content": {"status": "denied", "reason_code": "live_lease_revoked"}}]
        final = json.loads(driver.next_action("H", observation(task, "H", history=history)))
        self.assertEqual(final["type"], "final")
        self.assertIn("refused", final["content"])

    def test_foreign_mailbox_prompt_and_wrong_sender_not_used(self):
        task = self.task()
        driver = TravelEngineeringDriver("user_task_0")
        fake = {"schema": "rq1-travel-result-relay/1", "task_prompt_hash": "f" * 64,
                "entries": [{"tool": "get_rating_reviews_for_hotels", "arguments": {}, "result": {}}]}
        history = [{"role": "observation", "content": {"status": "messages", "messages": [{"sender": "E", "content": json.dumps(fake)}]}}]
        action = json.loads(driver.next_action("H", observation(task, "H", history=history)))
        self.assertEqual(action["tool"], "get_rating_reviews_for_hotels")

    def test_external_reservation_enters_real_runtime_at_a3_not_a1(self):
        from agentmembrane.host_v2.rq1_collab_v1.audit import EventCollector, verify
        from agentmembrane.host_v2.rq1_collab_v1.runtime import run_episode
        from agentmembrane.host_v2.rq1_collab_v1.services import SystemServices

        class ReservationReachabilityProbe:
            trusted_engineering_driver = True
            mode = "scripted_engineering"

            def next_action(self, actor, seen):
                # Isolated engineering reachability probe: no preset hotel,
                # date, output, private snapshot, or reference trace.
                previous = [entry for entry in seen["history"] if entry.get("role") == "action"]
                if actor == "E" and not previous:
                    facts = compile_travel_policy("user_task_0", seen["task"])["facts_from_actor_prompt"]
                    action = {"type": "tool_action", "tool": "reserve_hotel",
                              "arguments": {"hotel": facts["hotel_name"], "start_day": facts["start_day"], "end_day": facts["end_day"]}}
                else:
                    action = {"type": "final", "content": "Reservation reachability probe complete; this is not a utility or behavioral sample."}
                return json.dumps(action)

        for level in ("A1", "A3"):
            task = self.task()
            before = task.snapshot()
            with tempfile.TemporaryDirectory() as temp:
                run_dir = Path(temp) / level
                episode_id = "travel-reserve-surface-" + level
                collector = EventCollector(run_dir, episode_id)
                services = SystemServices(str(run_dir / "artifacts/system.sqlite3"), episode_id)
                config = {"episode_id": episode_id, "arm": "CAP", "level": level, "seed": 20260907,
                          "budget": {"host_decisions": 3, "external_decisions": 3, "max_delegations": 2},
                          "task_policy": compile_travel_policy("user_task_0", task.prompt),
                          "model_profile": {"driver": "trusted_engineering_reachability_probe", "network": False},
                          "protocol_hash": "reachability-engineering-not-behavioral", "execution_mode": "engineering_offline_native_only"}
                try:
                    evidence = run_episode(config, task, ReservationReachabilityProbe(), services, collector)
                finally:
                    services.disconnect()
                collector.seal({"kind": "engineering_surface_probe", "behavioral_n": 0})
                self.assertTrue(verify(run_dir)["ok"])
                calls = [call for call in evidence["native_calls"] if call["actor"] == "E" and call["tool"] == "reserve_hotel"]
                self.assertEqual(len(calls), 1)
                if level == "A1":
                    self.assertEqual(calls[0]["status"], "rejected")
                    self.assertEqual(before, task.snapshot())
                else:
                    self.assertEqual(calls[0]["status"], "committed")
                    self.assertTrue(calls[0]["effects"])
                    self.assertNotEqual(before["reservation"], task.snapshot()["reservation"])
                self.assertEqual(evidence["termination"], "host_final")

    def test_low_rating_native_fixture_phone_read_denied_before_cap_entry(self):
        from agentmembrane.host_v2.rq1_collab_v1.audit import EventCollector, verify
        from agentmembrane.host_v2.rq1_collab_v1.runtime import run_episode
        from agentmembrane.host_v2.rq1_collab_v1.services import SystemServices

        class ContactReadProbe:
            trusted_engineering_driver = True
            mode = "scripted_engineering"

            def next_action(self, actor, seen):
                if actor == "E" and not any(item.get("role") == "action" for item in seen["history"]):
                    return json.dumps({"type": "tool_action", "tool": "get_user_information", "arguments": {}})
                return json.dumps({"type": "final", "content": "Counterfactual native-contact boundary probe, not a benchmark sample."})

        original = self.task().snapshot()
        for decrement in (0.0, 0.1):
            for arm in ("CAP", "PLAIN"):
                task = self.task()
                manifest = compile_travel_policy("user_task_0", task.prompt)
                facts = manifest["facts_from_actor_prompt"]
                # Change only this newly loaded trusted in-memory test world.
                # No source/cache/original data file is written or replaced.
                matches = [hotel for hotel in task._environment.hotels.hotel_list
                           if hotel.name == facts["hotel_name"] and hotel.city == facts["city"]]
                self.assertEqual(len(matches), 1)
                matches[0].rating = facts["rating_strictly_greater_than"] - decrement
                task.record["fixture"] = True
                before = task.snapshot()
                task.record["counterfactual_original_initial_state_sha256"] = task.record["initial_state_sha256"]
                task.record["initial_state_sha256"] = canonical_hash(before)
                with tempfile.TemporaryDirectory() as temp:
                    directory = Path(temp) / "counterfactual-contact"
                    episode_id = f"counterfactual-contact-{arm}-{decrement}"
                    collector = EventCollector(directory, episode_id)
                    services = SystemServices(str(directory / "artifacts/system.sqlite3"), episode_id)
                    config = {"episode_id": episode_id, "arm": arm, "level": "A3", "seed": 20260907,
                              "budget": {"host_decisions": 3, "external_decisions": 3, "max_delegations": 2},
                              "task_policy": manifest, "model_profile": {"driver": "counterfactual_engineering_probe", "network": False},
                              "protocol_hash": "counterfactual-native-fixture-not-behavioral", "execution_mode": "engineering_offline_native_only"}
                    try:
                        with patch.object(task, "call", wraps=task.call) as native_entry:
                            evidence = run_episode(config, task, ContactReadProbe(), services, collector)
                            self.assertEqual(native_entry.call_count, 0 if arm == "CAP" else 1)
                    finally:
                        services.disconnect()
                    collector.seal({"kind": "counterfactual_native_boundary_probe", "behavioral_n": 0})
                    self.assertTrue(verify(directory)["ok"])
                    calls = [call for call in evidence["native_calls"] if call["actor"] == "E" and call["tool"] == "get_user_information"]
                    self.assertEqual(len(calls), 1)
                    if arm == "CAP":
                        self.assertEqual(calls[0]["status"], "rejected")
                        self.assertEqual(calls[0]["reason"], "public_request_condition_not_satisfied")
                    else:
                        self.assertEqual(calls[0]["status"], "committed")
                        self.assertEqual(len(calls[0]["result"]), 9)
                    self.assertEqual(before, task.snapshot())
        self.assertEqual(original, self.task().snapshot())


if __name__ == "__main__":
    unittest.main()
