"""Permission probes against the registered source-native AgentDojo tasks."""
import copy
import os
from pathlib import Path
import unittest

from agentmembrane.host_v2.rq1_collab_v1.native import NativeTask
from agentmembrane.host_v2.rq1_collab_v1.policy import (
    PolicyError, compile_task_policy, make_task_policy,
)
from agentmembrane.host_v2.rq1_collab_v6.permissions import (
    VERSION, authorize_native, native_tools, project_native_result,
)


SOURCE = str(Path(os.environ.get(
    "AGENTDOJO_SOURCE_ROOT",
    Path(__file__).resolve().parents[1]
    / "data/host_boundary_v2/upstream/agentdojo",
)).expanduser().resolve())
TASKS = (("workspace", 8), ("workspace", 24), ("workspace", 26),
         ("workspace", 35), ("travel", 0), ("travel", 2))


def native_policy(suite, number):
    task_id = f"user_task_{number}"
    task = NativeTask(SOURCE, suite, task_id)
    record = {"suite": suite, "original_id": task_id}
    policy = make_task_policy(suite, task_id, task.prompt,
                              compile_task_policy(suite, task_id, task.prompt),
                              [spec["name"] for spec in task.tool_specs])
    return task, record, policy


class ThreeTierPermissionTests(unittest.TestCase):
    def test_six_registered_task_grants_are_nested_and_high_is_native_broad(self):
        self.assertEqual(VERSION, "rq1-three-tier-task-scoped/11")
        for suite, number in TASKS:
            with self.subTest(suite=suite, task=number):
                task, record, policy = native_policy(suite, number)
                low = set(native_tools(policy, record, "A0"))
                medium = set(native_tools(policy, record, "A3"))
                high = set(native_tools(policy, record, "A4"))
                self.assertEqual(low, set())
                self.assertTrue(medium < high)
                self.assertEqual(high, {spec["name"] for spec in task.tool_specs})
                if (suite, number) == ("workspace", 35):
                    self.assertEqual(medium, {"list_files", "get_file_by_id", "delete_file"})
                if (suite, number) == ("travel", 0):
                    self.assertNotIn("get_user_information", medium)
                    self.assertIn("reserve_hotel", medium)

    def test_middle_delete_initial_unique_largest_real_native_transition(self):
        task, record, policy = native_policy("workspace", 35)
        before = task.snapshot()
        policy.labels("A3", before)  # runtime's initial-snapshot priming contract
        files = before["cloud_drive"]["files"]
        top_size = max(value["size"] for value in files.values())
        targets = [key for key, value in files.items() if value["size"] == top_size]
        self.assertEqual(len(targets), 1)
        target = targets[0]
        args = {"file_id": target}

        self.assertTrue(authorize_native(policy, record, "A3", "list_files", {}, before, actor="E")[0])
        listed = task.call("list_files", {})
        self.assertIsNone(listed["error"])
        metadata, labels = project_native_result(policy, record, "A3", "list_files",
                                                 listed["result"], listed["after"])
        self.assertEqual(set(metadata[0]), {"id_", "filename", "size"})
        self.assertTrue(set(labels) <= set(policy.labels("A3", listed["after"])))
        self.assertTrue(authorize_native(policy, record, "A3", "delete_file", args, listed["after"], actor="E")[0])
        deleted = task.call("delete_file", args)
        self.assertIsNone(deleted["error"])
        self.assertNotIn(target, deleted["after"]["cloud_drive"]["files"])
        projected, labels = project_native_result(policy, record, "A3", "delete_file",
                                                  deleted["result"], deleted["after"])
        self.assertEqual(projected, {key: files[target][key] for key in ("id_", "filename", "size")})
        self.assertEqual(set(labels), {"public", policy.file_metadata_label(target)})
        self.assertTrue(set(labels) <= set(policy.labels("A3", deleted["after"])))
        self.assertFalse(authorize_native(policy, record, "A3", "delete_file", args, deleted["after"], actor="E")[0])
        self.assertFalse(authorize_native(policy, record, "A3", "delete_file",
                                          {"file_id": next(k for k in files if k != target)}, deleted["after"], actor="E")[0])

    def test_middle_delete_denies_wrong_target_tie_changed_world_and_bad_receipt(self):
        task, record, policy = native_policy("workspace", 35)
        initial = task.snapshot()
        policy.labels("A3", initial)
        files = initial["cloud_drive"]["files"]
        target = policy._initial_largest_ids[0]
        other = next(key for key in files if key != target)
        self.assertFalse(authorize_native(policy, record, "A3", "delete_file", {"file_id": other}, initial, actor="E")[0])
        self.assertFalse(authorize_native(policy, record, "A3", "delete_file", {"file_id": target, "extra": 1}, initial, actor="E")[0])
        changed = copy.deepcopy(initial)
        changed["cloud_drive"]["files"][other]["size"] = files[target]["size"]
        self.assertFalse(authorize_native(policy, record, "A3", "delete_file", {"file_id": target}, changed, actor="E")[0])
        unprimed_task, unprimed_record, unprimed_policy = native_policy("workspace", 35)
        tied_initial = unprimed_task.snapshot()
        tied_files = tied_initial["cloud_drive"]["files"]
        tied_target = max(tied_files, key=lambda key: tied_files[key]["size"])
        tied_other = next(key for key in tied_files if key != tied_target)
        tied_files[tied_other]["size"] = tied_files[tied_target]["size"]
        unprimed_policy.labels("A3", tied_initial)
        self.assertFalse(authorize_native(unprimed_policy, unprimed_record, "A3", "delete_file",
                                          {"file_id": tied_target}, tied_initial, actor="E")[0])
        absent = copy.deepcopy(initial)
        absent["cloud_drive"]["files"].pop(target)
        receipt = copy.deepcopy(files[target])
        receipt["content"] = "secret cannot be delivered"
        with self.assertRaises(PolicyError):
            project_native_result(policy, record, "A3", "delete_file", files[other], absent)
        with self.assertRaises(PolicyError):
            project_native_result(policy, record, "A3", "delete_file", receipt, initial)

    def test_host_request_object_guard_keeps_external_ambient_arm(self):
        task, record, policy = native_policy("workspace", 35)
        initial = task.snapshot()
        policy.labels("A3", initial)
        target = policy._initial_largest_ids[0]
        other = next(key for key in initial["cloud_drive"]["files"] if key != target)
        self.assertEqual(authorize_native(policy, record, "A4", "delete_file",
                                          {"file_id": other}, initial, actor="H"),
                         (False, "delete_outside_requested_unique_largest"))
        self.assertEqual(authorize_native(policy, record, "A4", "delete_file",
                                          {"file_id": target}, initial, actor="H"),
                         (True, "delete_original_unique_largest_once"))
        self.assertEqual(authorize_native(policy, record, "A4", "delete_file",
                                          {"file_id": other}, initial, actor="E"),
                         (True, "technical_scope"))
        with self.assertRaises(PolicyError):
            authorize_native(policy, record, "A4", "delete_file",
                             {"file_id": target}, initial, actor="unknown")

    def test_calendar_add_rejects_duplicate_and_preexisting_participants(self):
        task, record, policy = native_policy("workspace", 8)
        initial = task.snapshot()
        event_id = policy.target_ids(initial)[0]
        first, second = policy.facts["requested_participants"]
        call = lambda participants, world, actor="E", level="A3": authorize_native(
            policy, record, level, "add_calendar_event_participants",
            {"event_id": event_id, "participants": participants}, world,
            actor=actor)
        self.assertEqual(call([first, first], initial)[1],
                         "empty_or_duplicate_requested_participants")
        self.assertEqual(call([], initial)[1],
                         "empty_or_duplicate_requested_participants")
        self.assertEqual(call([first], initial)[0], True)
        self.assertEqual(call([first, first], initial, actor="H", level="A4")[0], False)
        existing = copy.deepcopy(initial)
        existing["calendar"]["events"][event_id]["participants"].append(first)
        self.assertEqual(call([first], existing, actor="H", level="A4")[1],
                         "participant_already_present")
        self.assertEqual(call([first], initial, actor="E", level="A4"),
                         (True, "technical_scope"))
        added_first = task.call("add_calendar_event_participants",
                                {"event_id": event_id, "participants": [first]})
        self.assertIsNone(added_first["error"])
        self.assertEqual(call([first], added_first["after"])[1],
                         "participant_already_present")
        self.assertTrue(call([second], added_first["after"])[0])
        added_second = task.call("add_calendar_event_participants",
                                 {"event_id": event_id, "participants": [second]})
        self.assertIsNone(added_second["error"])
        final = added_second["after"]["calendar"]["events"][event_id]["participants"]
        self.assertEqual(final.count(first), 1)
        self.assertEqual(final.count(second), 1)
        self.assertEqual(call([second], added_second["after"])[1],
                         "participant_already_present")

    def test_hotel_middle_books_without_explicit_full_user_read(self):
        task, record, policy = native_policy("travel", 0)
        before = task.snapshot()
        facts = policy.facts
        hotel = next(item for item in before["hotels"]["hotel_list"]
                     if item["name"] == facts["hotel_name"] and item["city"] == facts["city"])
        self.assertGreater(hotel["rating"], facts["rating_strictly_greater_than"])
        args = {"hotel": facts["hotel_name"], "start_day": facts["start_day"],
                "end_day": facts["end_day"]}
        self.assertFalse(authorize_native(policy, record, "A3", "get_user_information", {}, before, actor="E")[0])
        self.assertTrue(authorize_native(policy, record, "A3", "reserve_hotel", args, before, actor="E")[0])
        booked = task.call("reserve_hotel", args)
        self.assertIsNone(booked["error"])
        self.assertEqual(booked["after"]["reservation"]["title"], facts["hotel_name"])
        projected, labels = project_native_result(policy, record, "A3", "reserve_hotel",
                                                  booked["result"], booked["after"])
        self.assertEqual(projected, booked["result"])
        self.assertTrue(set(labels) <= set(policy.labels("A3", booked["after"])))
        self.assertFalse(authorize_native(policy, record, "A3", "reserve_hotel", args, booked["after"], actor="E")[0])


if __name__ == "__main__":
    unittest.main()
