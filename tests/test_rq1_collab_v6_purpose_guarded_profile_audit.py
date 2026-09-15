"""Source-native permission audit for the separate purpose-guarded profile.

This checks the advertised business APIs and dispatch predicates against all
six registered AgentDojo tasks. It is an engineering audit, not model evidence.
"""
from __future__ import annotations

from pathlib import Path
import unittest

from agentmembrane.host_v2.rq1_collab_v1.native import NativeTask
from agentmembrane.host_v2.rq1_collab_v1.policy import compile_task_policy, make_task_policy
from agentmembrane.host_v2.rq1_collab_v1.profiles_travel import PUBLIC_TOOLS as TRAVEL_PUBLIC_TOOLS
from agentmembrane.host_v2.rq1_collab_v6.permissions import (
    NATIVE_PURPOSE_GUARDED_PROFILE,
    authorize_native,
    native_tools,
)


SOURCE = str(Path(__file__).resolve().parents[1] / "data/host_boundary_v2/upstream/agentdojo")
TASKS = (("workspace", 8), ("workspace", 24), ("workspace", 26),
         ("workspace", 35), ("travel", 0), ("travel", 2))
MEDIUM_TOOLS = {
    ("workspace", 8): {"get_current_day", "search_calendar_events",
                       "get_day_calendar_events", "add_calendar_event_participants"},
    ("workspace", 24): {"get_unread_emails"},
    ("workspace", 26): {"list_files", "get_file_by_id"},
    ("workspace", 35): {"list_files", "get_file_by_id", "delete_file"},
    ("travel", 0): {"get_all_hotels_in_city", "get_hotels_prices",
                    "get_rating_reviews_for_hotels", "get_hotels_address", "reserve_hotel"},
    ("travel", 2): {"get_all_restaurants_in_city", "get_cuisine_type_for_restaurants",
                    "get_restaurants_address", "get_rating_reviews_for_restaurants",
                    "get_dietary_restrictions_for_all_restaurants",
                    "get_contact_information_for_restaurants",
                    "get_price_for_restaurants", "check_restaurant_opening_hours"},
}
WORKSPACE_MUTATION_OR_EXFIL = {"send_email", "delete_email", "create_calendar_event",
                               "cancel_calendar_event", "reschedule_calendar_event",
                               "add_calendar_event_participants", "append_to_file",
                               "create_file", "delete_file", "share_file"}
WORKSPACE_PROTECTED_UNRELATED_READS = {"get_sent_emails", "get_received_emails",
                                       "get_draft_emails", "search_emails",
                                       "search_contacts_by_name", "search_contacts_by_email",
                                       "search_files_by_filename", "search_files"}
TRAVEL_MUTATION_OR_EXFIL = {"reserve_hotel", "reserve_car_rental",
                            "reserve_restaurant", "create_calendar_event",
                            "cancel_calendar_event", "send_email"}


def source_policy(suite: str, number: int):
    task_id = f"user_task_{number}"
    task = NativeTask(SOURCE, suite, task_id)
    record = {"suite": suite, "original_id": task_id}
    policy = make_task_policy(suite, task_id, task.prompt,
                              compile_task_policy(suite, task_id, task.prompt),
                              [spec["name"] for spec in task.tool_specs])
    return task, record, policy


class PurposeGuardedProfileAudit(unittest.TestCase):
    def test_six_native_grants_have_only_reviewed_task_effects(self):
        for suite, number in TASKS:
            with self.subTest(suite=suite, task=number):
                task, record, policy = source_policy(suite, number)
                source_tools = {spec["name"] for spec in task.tool_specs}
                low = set(native_tools(policy, record, "A0",
                                       profile=NATIVE_PURPOSE_GUARDED_PROFILE))
                medium = set(native_tools(policy, record, "A3",
                                          profile=NATIVE_PURPOSE_GUARDED_PROFILE))
                high = set(native_tools(policy, record, "A4",
                                        profile=NATIVE_PURPOSE_GUARDED_PROFILE))
                self.assertEqual(low, set())
                self.assertTrue(MEDIUM_TOOLS[(suite, number)] <= source_tools)
                self.assertEqual(medium, MEDIUM_TOOLS[(suite, number)])
                extras = ({"get_current_day"} if suite == "workspace"
                          else TRAVEL_PUBLIC_TOOLS)
                self.assertEqual(high, medium | (extras & source_tools))
                self.assertTrue(high <= source_tools)
                if suite == "workspace":
                    self.assertEqual(high & WORKSPACE_MUTATION_OR_EXFIL,
                                     medium & WORKSPACE_MUTATION_OR_EXFIL)
                    self.assertFalse(high & WORKSPACE_PROTECTED_UNRELATED_READS)
                    self.assertFalse(high & {"get_user_information", "send_email",
                                             "get_received_emails", "search_files"})
                else:
                    self.assertEqual(high & TRAVEL_MUTATION_OR_EXFIL,
                                     medium & TRAVEL_MUTATION_OR_EXFIL)
                    self.assertFalse(high & {"get_user_information", "send_email"})
                    self.assertTrue((TRAVEL_PUBLIC_TOOLS & source_tools) <= high)
                self.assertLess(len(high), len(source_tools))

    def test_w35_guarded_high_and_host_reject_wrong_object_before_backend(self):
        task, record, policy = source_policy("workspace", 35)
        initial = task.snapshot()
        policy.labels("A3", initial)
        self.assertEqual(policy._initial_largest_ids, ("11",))
        self.assertIn("13", initial["cloud_drive"]["files"])
        for actor in ("E", "H"):
            with self.subTest(actor=actor):
                self.assertEqual(authorize_native(
                    policy, record, "A4", "delete_file", {"file_id": "13"}, initial,
                    actor=actor, profile=NATIVE_PURPOSE_GUARDED_PROFILE),
                    (False, "delete_outside_requested_unique_largest"))
                self.assertEqual(authorize_native(
                    policy, record, "A4", "delete_file", {"file_id": "11"}, initial,
                    actor=actor, profile=NATIVE_PURPOSE_GUARDED_PROFILE),
                    (True, "delete_original_unique_largest_once"))
        self.assertIn("13", task.snapshot()["cloud_drive"]["files"])

    def test_t0_private_read_and_email_denied_but_requested_booking_allowed(self):
        task, record, policy = source_policy("travel", 0)
        initial = task.snapshot()
        args = {"hotel": policy.facts["hotel_name"],
                "start_day": policy.facts["start_day"],
                "end_day": policy.facts["end_day"]}
        for actor in ("E", "H"):
            with self.subTest(actor=actor):
                for tool in ("get_user_information", "send_email"):
                    self.assertEqual(authorize_native(
                        policy, record, "A4", tool, {}, initial, actor=actor,
                        profile=NATIVE_PURPOSE_GUARDED_PROFILE),
                        (False, "outside_task_scoped_tool_grant"))
                self.assertEqual(authorize_native(
                    policy, record, "A4", "reserve_hotel", args, initial,
                    actor=actor, profile=NATIVE_PURPOSE_GUARDED_PROFILE),
                    (True, "request_purpose"))
        # High keeps genuinely extra public Travel discovery, including a
        # different service family. It grants no corresponding reservation.
        self.assertIn("get_all_car_rental_companies_in_city", set(native_tools(
            policy, record, "A4", profile=NATIVE_PURPOSE_GUARDED_PROFILE)))
        self.assertTrue(authorize_native(
            policy, record, "A4", "get_all_car_rental_companies_in_city",
            {"city": "Toronto"}, initial, actor="E",
            profile=NATIVE_PURPOSE_GUARDED_PROFILE)[0])
        self.assertFalse(authorize_native(
            policy, record, "A4", "reserve_car_rental", {}, initial, actor="E",
            profile=NATIVE_PURPOSE_GUARDED_PROFILE)[0])
        booked = task.call("reserve_hotel", args)
        self.assertIsNone(booked["error"])
        self.assertEqual(booked["after"]["reservation"]["title"],
                         policy.facts["hotel_name"])
        self.assertFalse(authorize_native(
            policy, record, "A4", "reserve_hotel", args, booked["after"],
            actor="E", profile=NATIVE_PURPOSE_GUARDED_PROFILE)[0])


if __name__ == "__main__":
    unittest.main()
