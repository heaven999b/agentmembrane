from __future__ import annotations

import copy
import inspect
import json
from pathlib import Path
import subprocess
import unittest

from agentmembrane.host_v2.rq1_public_agentdojo_multi_v3.domain_authority.core import (
    build_authority_grant,
    build_profile,
    decide_authority,
    validate_native_tool_coverage,
)
from agentmembrane.host_v2.rq1_public_agentdojo_multi_v3.domain_authority.travel import (
    PROFILE,
    TRAVEL_SOURCE_WORKFLOWS,
    TRAVEL_TOOL_AUTHORITY,
    match_travel_authority_effect,
    normalize_travel_authority_args,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PINNED_RUNTIME = (
    REPOSITORY_ROOT
    / "experiments/host_boundary_v2/runtime_envs"
    / "agentdojo-0.1.35-py3123-lock-395e3d0a5921"
)
PINNED_PYTHON = PINNED_RUNTIME / "bin/python"
UPSTREAM_SOURCE = REPOSITORY_ROOT / "data/host_boundary_v2/upstream/agentdojo/src"

UNRESTRICTED_METADATA = {
    "get_all_hotels_in_city",
    "get_hotels_prices",
    "get_rating_reviews_for_hotels",
    "get_hotels_address",
    "get_all_restaurants_in_city",
    "get_cuisine_type_for_restaurants",
    "get_restaurants_address",
    "get_rating_reviews_for_restaurants",
    "get_dietary_restrictions_for_all_restaurants",
    "get_contact_information_for_restaurants",
    "get_price_for_restaurants",
    "check_restaurant_opening_hours",
    "get_all_car_rental_companies_in_city",
    "get_car_types_available",
    "get_rating_reviews_for_car_rental",
    "get_car_fuel_options",
    "get_car_rental_address",
    "get_car_price_per_day",
    "get_flight_information",
}

CONTROLLED_READS = {
    "get_user_information",
    "search_calendar_events",
    "get_day_calendar_events",
}

CONTROLLED_MUTATIONS = {
    "create_calendar_event",
    "cancel_calendar_event",
    "reserve_hotel",
    "reserve_car_rental",
    "reserve_restaurant",
    "send_email",
}

EXPECTED_TOOLS = UNRESTRICTED_METADATA | CONTROLLED_READS | CONTROLLED_MUTATIONS


def _load_native_authority_inputs() -> dict:
    script = r'''
import json
from pathlib import Path
import sys

repository_root = Path(sys.argv[1]).resolve()
source_root = Path(sys.argv[2]).resolve()
runtime_root = Path(sys.argv[3]).resolve()
if Path(sys.prefix).resolve() != runtime_root:
    raise RuntimeError("pinned runtime prefix differs")
sys.path.insert(0, str(repository_root))
sys.path.insert(0, str(source_root))

from agentdojo.task_suite.load_suites import get_suite
from agentmembrane.host_v2.rq1_public_agentdojo_multi_v3.domain_authority.travel import (
    PROFILE,
    build_travel_authority,
)

suite = get_suite("v1", "travel")
workflows = {
    "agentdojo-v1-travel-u0-i0": ("user_task_0", "injection_task_0"),
    "agentdojo-v1-travel-u1-i2": ("user_task_1", "injection_task_2"),
    "agentdojo-v1-travel-u3-i1": ("user_task_3", "injection_task_1"),
}
benign_calls = {}
paired_calls = {}
grants = {}
for source_task_id, (user_task_id, paired_task_id) in workflows.items():
    user_task = suite.get_user_task_by_id(user_task_id)
    environment = suite.load_and_inject_default_environment({})
    environment = user_task.init_environment(environment)
    pre_environment = environment.model_copy(deep=True)
    calls = user_task.ground_truth(pre_environment)
    benign_calls[source_task_id] = [
        {"function": call.function, "args": dict(call.args)}
        for call in calls
    ]
    # Paired source actions are test candidates only.  The authority profile
    # and grant builder above never receive this object or an outcome checker.
    paired_task = suite.get_injection_task_by_id(paired_task_id)
    paired_calls[source_task_id] = [
        {"function": call.function, "args": dict(call.args)}
        for call in paired_task.ground_truth(pre_environment)
    ]
    grants[source_task_id] = build_travel_authority(
        suite, user_task
    ).as_json()

print(json.dumps({
    "python": sys.version.split()[0],
    "tool_names": [tool.name for tool in suite.tools],
    "benign_calls": benign_calls,
    "paired_calls": paired_calls,
    "grants": grants,
    "profile": PROFILE.as_json(),
}, ensure_ascii=False, allow_nan=False, sort_keys=True))
'''
    completed = subprocess.run(
        [
            str(PINNED_PYTHON),
            "-I",
            "-B",
            "-c",
            script,
            str(REPOSITORY_ROOT),
            str(UPSTREAM_SOURCE),
            str(PINNED_RUNTIME),
        ],
        cwd=REPOSITORY_ROOT,
        env={
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
        },
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if completed.stderr:
        raise AssertionError(f"native authority worker stderr: {completed.stderr}")
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise AssertionError("native authority worker did not return an object")
    return value


def _changed_value(field: str, current: object) -> object:
    if current is None:
        return ["authority-change@example.com"]
    if isinstance(current, list):
        return [*current, "authority-change@example.com"]
    if isinstance(current, bool):
        return not current
    if isinstance(current, int | float):
        return current + 1
    return f"{current}-authority-change"


class RQ1PublicAgentDojoMultiV3TravelAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.native = _load_native_authority_inputs()
        cls.grants = {
            row["source_task_id"]: build_authority_grant(
                PROFILE,
                source_task_id=(
                    "agentdojo:v1:travel:" + row["user_task_id"]
                ),
                ground_truth_calls=cls.native["benign_calls"][
                    row["source_task_id"]
                ],
            )
            for row in TRAVEL_SOURCE_WORKFLOWS
        }

    def test_profile_exhaustively_classifies_all_28_native_tools(self) -> None:
        self.assertEqual(self.native["python"], "3.12.3")
        self.assertEqual(len(self.native["tool_names"]), 28)
        self.assertEqual(set(self.native["tool_names"]), EXPECTED_TOOLS)
        self.assertEqual(set(TRAVEL_TOOL_AUTHORITY), EXPECTED_TOOLS)
        validate_native_tool_coverage(PROFILE, self.native["tool_names"])
        self.assertEqual(
            {
                name
                for name, row in TRAVEL_TOOL_AUTHORITY.items()
                if row["mode"] == "unrestricted"
            },
            UNRESTRICTED_METADATA,
        )
        self.assertEqual(
            {
                name
                for name, row in TRAVEL_TOOL_AUTHORITY.items()
                if row["mode"] == "controlled_read"
            },
            CONTROLLED_READS,
        )
        self.assertEqual(
            {
                name
                for name, row in TRAVEL_TOOL_AUTHORITY.items()
                if row["mode"] == "controlled_mutation"
            },
            CONTROLLED_MUTATIONS,
        )

    def test_effect_level_authority_fields_are_exact(self) -> None:
        expected_controlled = {
            "get_user_information": (),
            "search_calendar_events": ("query", "date"),
            "get_day_calendar_events": ("day",),
            "create_calendar_event": (
                "title",
                "start_time",
                "end_time",
                "participants",
            ),
            "cancel_calendar_event": ("event_id",),
            "reserve_hotel": ("hotel", "start_day", "end_day"),
            "reserve_car_rental": ("company", "start_time", "end_time"),
            "reserve_restaurant": ("restaurant", "start_time"),
            "send_email": ("recipients", "cc", "bcc", "attachments"),
        }
        actual = {
            name: tuple(row["authority_fields"])
            for name, row in TRAVEL_TOOL_AUTHORITY.items()
            if row["mode"] != "unrestricted"
        }
        self.assertEqual(actual, expected_controlled)
        self.assertNotIn(
            "description",
            TRAVEL_TOOL_AUTHORITY["create_calendar_event"]["authority_fields"],
        )
        self.assertNotIn(
            "location",
            TRAVEL_TOOL_AUTHORITY["create_calendar_event"]["authority_fields"],
        )
        self.assertNotIn(
            "subject", TRAVEL_TOOL_AUTHORITY["send_email"]["authority_fields"]
        )
        self.assertNotIn(
            "body", TRAVEL_TOOL_AUTHORITY["send_email"]["authority_fields"]
        )

    def test_grants_are_exact_reset_time_user_ground_truth_projections(self) -> None:
        expected_functions = {
            "agentdojo-v1-travel-u0-i0": [
                "get_rating_reviews_for_hotels",
                "reserve_hotel",
            ],
            "agentdojo-v1-travel-u1-i2": [
                "get_rating_reviews_for_hotels",
                "get_hotels_prices",
                "get_hotels_address",
                "create_calendar_event",
            ],
            "agentdojo-v1-travel-u3-i1": [
                "get_all_hotels_in_city",
                "get_rating_reviews_for_hotels",
                "get_hotels_prices",
                "get_hotels_address",
                "send_email",
            ],
        }
        for workflow_id, expected in expected_functions.items():
            with self.subTest(workflow_id=workflow_id):
                calls = self.native["benign_calls"][workflow_id]
                self.assertEqual(
                    [row["function"] for row in calls],
                    expected,
                )
                grant = self.grants[workflow_id].as_json()
                self.assertEqual(len(grant["entries"]), 1)
                self.assertEqual(
                    grant,
                    self.native["grants"][workflow_id],
                )
                self.assertEqual(
                    grant["source_kind"],
                    "user_task_ground_truth_no_injection",
                )

    def test_every_benign_ground_truth_projection_is_allowed(self) -> None:
        for workflow_id, calls in self.native["benign_calls"].items():
            grant = self.grants[workflow_id]
            consumed: list[int] = []
            for action in calls:
                with self.subTest(workflow_id=workflow_id, action=action):
                    decision = decide_authority(
                        PROFILE,
                        grant,
                        action=action,
                        consumed_grant_indexes=tuple(consumed),
                    )
                    self.assertTrue(decision.within_authority)
                    if decision.matched_grant_index is not None:
                        consumed.append(decision.matched_grant_index)

    def test_each_paired_source_action_is_denied_without_a_checker(self) -> None:
        expected_final_functions = {
            "agentdojo-v1-travel-u0-i0": "reserve_hotel",
            "agentdojo-v1-travel-u1-i2": "create_calendar_event",
            "agentdojo-v1-travel-u3-i1": "send_email",
        }
        for workflow_id, calls in self.native["paired_calls"].items():
            with self.subTest(workflow_id=workflow_id):
                self.assertEqual(len(calls), 1)
                self.assertEqual(
                    calls[0]["function"], expected_final_functions[workflow_id]
                )
                decision = decide_authority(
                    PROFILE,
                    self.grants[workflow_id],
                    action=calls[0],
                )
                self.assertFalse(decision.within_authority)
                self.assertEqual(
                    decision.reason, "no_matching_user_authority_grant"
                )
                self.assertIsNone(decision.matched_grant_index)

    def test_non_authority_content_changes_remain_allowed(self) -> None:
        u1 = self.native["benign_calls"]["agentdojo-v1-travel-u1-i2"][-1]
        for field, changed in (
            ("description", "A newly composed useful reminder."),
            ("location", "A more precise display location."),
        ):
            action = copy.deepcopy(u1)
            action["args"][field] = changed
            with self.subTest(workflow="u1", field=field):
                self.assertTrue(
                    decide_authority(
                        PROFILE,
                        self.grants["agentdojo-v1-travel-u1-i2"],
                        action=action,
                    ).within_authority
                )

        u3 = self.native["benign_calls"]["agentdojo-v1-travel-u3-i1"][-1]
        for field, changed in (
            ("subject", "Updated hotel summary"),
            ("body", "A newly composed hotel summary."),
        ):
            action = copy.deepcopy(u3)
            action["args"][field] = changed
            with self.subTest(workflow="u3", field=field):
                self.assertTrue(
                    decide_authority(
                        PROFILE,
                        self.grants["agentdojo-v1-travel-u3-i1"],
                        action=action,
                    ).within_authority
                )

    def test_each_single_authority_field_change_is_denied(self) -> None:
        for workflow_id in (
            "agentdojo-v1-travel-u0-i0",
            "agentdojo-v1-travel-u1-i2",
            "agentdojo-v1-travel-u3-i1",
        ):
            benign = self.native["benign_calls"][workflow_id][-1]
            fields = TRAVEL_TOOL_AUTHORITY[benign["function"]]["authority_fields"]
            for field in fields:
                action = copy.deepcopy(benign)
                current = action["args"].get(field)
                action["args"][field] = _changed_value(field, current)
                with self.subTest(workflow_id=workflow_id, field=field):
                    decision = decide_authority(
                        PROFILE,
                        self.grants[workflow_id],
                        action=action,
                    )
                    self.assertFalse(decision.within_authority)
                    self.assertIsNone(decision.matched_grant_index)

    def test_u1_participant_optional_defaults_are_authority_equivalent(self) -> None:
        workflow_id = "agentdojo-v1-travel-u1-i2"
        action = self.native["benign_calls"][workflow_id][-1]
        self.assertNotIn("participants", action["args"])
        variants = []
        variants.append(copy.deepcopy(action))
        for value in (None, []):
            variant = copy.deepcopy(action)
            variant["args"]["participants"] = value
            variants.append(variant)
        projections = []
        for index, variant in enumerate(variants):
            with self.subTest(index=index):
                decision = decide_authority(
                    PROFILE,
                    self.grants[workflow_id],
                    action=variant,
                )
                self.assertTrue(decision.within_authority)
                self.assertEqual(
                    decision.projection["value"]["participants"], []
                )
                projections.append(
                    {
                        key: value
                        for key, value in decision.projection.items()
                        if key != "authority_provenance"
                    }
                )
        self.assertTrue(all(row == projections[0] for row in projections[1:]))

        nonempty = copy.deepcopy(action)
        nonempty["args"]["participants"] = ["other@example.com"]
        self.assertFalse(
            decide_authority(
                PROFILE,
                self.grants[workflow_id],
                action=nonempty,
            ).within_authority
        )

    def test_u1_date_only_calendar_grant_contains_same_day_subinterval(self) -> None:
        workflow_id = "agentdojo-v1-travel-u1-i2"
        granted = self.grants[workflow_id].entries[0]
        action = copy.deepcopy(self.native["benign_calls"][workflow_id][-1])
        action["args"].update(
            {
                "start_time": "2025-01-02 09:00",
                "end_time": "2025-01-02 09:30",
            }
        )
        decision = decide_authority(
            PROFILE,
            self.grants[workflow_id],
            action=action,
        )
        self.assertTrue(decision.within_authority)
        self.assertEqual(decision.reason, "authority_grant_relation_match")
        self.assertEqual(decision.matched_grant_index, 0)
        self.assertTrue(decision.consumes_grant)
        projected = PROFILE.project(
            action,
            provenance={"source_kind": "date-only-authority-test"},
        )
        assert projected is not None
        granted_effect = {
            key: copy.deepcopy(granted[key])
            for key in ("op", "resource", "value")
        }
        candidate_effect = {
            key: copy.deepcopy(projected[key])
            for key in ("op", "resource", "value")
        }
        self.assertTrue(
            match_travel_authority_effect(granted_effect, candidate_effect)
        )

        for start_time, end_time in (
            ("2025-01-02 00:00", "2025-01-02 00:01"),
            ("2025-01-02 23:58", "2025-01-02 23:59"),
        ):
            candidate = copy.deepcopy(candidate_effect)
            candidate["value"].update(
                {"start_time": start_time, "end_time": end_time}
            )
            with self.subTest(start_time=start_time, end_time=end_time):
                self.assertTrue(
                    match_travel_authority_effect(granted_effect, candidate)
                )

    def test_u1_date_only_calendar_containment_fails_closed(self) -> None:
        workflow_id = "agentdojo-v1-travel-u1-i2"
        granted = self.grants[workflow_id].entries[0]
        granted_effect = {
            key: copy.deepcopy(granted[key])
            for key in ("op", "resource", "value")
        }
        invalid_windows = (
            # Other dates and cross-day windows.
            ("2025-01-03 09:00", "2025-01-03 09:30"),
            ("2025-01-02 23:30", "2025-01-03 00:30"),
            # Empty and reversed windows.
            ("2025-01-02 09:00", "2025-01-02 09:00"),
            ("2025-01-02 09:30", "2025-01-02 09:00"),
            # Invalid or non-native representations, including timezone cues.
            ("2025-02-30 09:00", "2025-02-30 09:30"),
            ("2025-01-02T09:00", "2025-01-02T09:30"),
            ("2025-01-02 09:00:00", "2025-01-02 09:30:00"),
            ("2025-01-02 09:00Z", "2025-01-02 09:30Z"),
            ("2025-01-02 09:00+00:00", "2025-01-02 09:30+00:00"),
        )
        for start_time, end_time in invalid_windows:
            candidate = copy.deepcopy(granted_effect)
            candidate["value"].update(
                {"start_time": start_time, "end_time": end_time}
            )
            action = copy.deepcopy(self.native["benign_calls"][workflow_id][-1])
            action["args"].update(
                {"start_time": start_time, "end_time": end_time}
            )
            with self.subTest(start_time=start_time, end_time=end_time):
                self.assertFalse(
                    match_travel_authority_effect(granted_effect, candidate)
                )
                decision = decide_authority(
                    PROFILE,
                    self.grants[workflow_id],
                    action=action,
                )
                self.assertFalse(decision.within_authority)
                self.assertEqual(
                    decision.reason, "no_matching_user_authority_grant"
                )
                self.assertIsNone(decision.matched_grant_index)
                self.assertFalse(decision.consumes_grant)

        for field, changed in (
            ("title", "Different title"),
            ("participants", ["other@example.com"]),
        ):
            candidate = copy.deepcopy(granted_effect)
            candidate["value"].update(
                {
                    "start_time": "2025-01-02 09:00",
                    "end_time": "2025-01-02 09:30",
                    field: changed,
                }
            )
            action = copy.deepcopy(self.native["benign_calls"][workflow_id][-1])
            action["args"].update(
                {
                    "start_time": "2025-01-02 09:00",
                    "end_time": "2025-01-02 09:30",
                    field: changed,
                }
            )
            with self.subTest(field=field):
                self.assertFalse(
                    match_travel_authority_effect(granted_effect, candidate)
                )
                self.assertFalse(
                    decide_authority(
                        PROFILE,
                        self.grants[workflow_id],
                        action=action,
                    ).within_authority
                )

    def test_exact_time_calendar_grant_does_not_gain_date_authority(self) -> None:
        exact = {
            "function": "create_calendar_event",
            "args": {
                "title": "Exact appointment",
                "start_time": "2025-01-02 09:00",
                "end_time": "2025-01-02 10:00",
            },
        }
        grant = build_authority_grant(
            PROFILE,
            source_task_id="agentdojo:v1:travel:synthetic-exact-time-test",
            ground_truth_calls=[exact],
        )
        granted = grant.entries[0]
        granted_effect = {
            key: copy.deepcopy(granted[key])
            for key in ("op", "resource", "value")
        }
        exact_decision = decide_authority(PROFILE, grant, action=exact)
        self.assertTrue(exact_decision.within_authority)
        self.assertEqual(exact_decision.reason, "authority_grant_match")
        self.assertTrue(
            match_travel_authority_effect(granted_effect, granted_effect)
        )

        candidate = copy.deepcopy(granted_effect)
        candidate["value"].update(
            {
                "start_time": "2025-01-02 09:15",
                "end_time": "2025-01-02 09:30",
            }
        )
        self.assertFalse(
            match_travel_authority_effect(granted_effect, candidate)
        )
        changed_exact = copy.deepcopy(exact)
        changed_exact["args"].update(
            {
                "start_time": "2025-01-02 09:15",
                "end_time": "2025-01-02 09:30",
            }
        )
        self.assertFalse(
            decide_authority(
                PROFILE,
                grant,
                action=changed_exact,
            ).within_authority
        )

    def test_u3_email_optional_defaults_are_authority_equivalent(self) -> None:
        workflow_id = "agentdojo-v1-travel-u3-i1"
        action = self.native["benign_calls"][workflow_id][-1]
        for field in ("cc", "bcc", "attachments"):
            self.assertNotIn(field, action["args"])
            for representation in ("omitted", "none", "empty"):
                variant = copy.deepcopy(action)
                if representation == "none":
                    variant["args"][field] = None
                elif representation == "empty":
                    variant["args"][field] = []
                with self.subTest(field=field, representation=representation):
                    decision = decide_authority(
                        PROFILE,
                        self.grants[workflow_id],
                        action=variant,
                    )
                    self.assertTrue(decision.within_authority)
                    self.assertEqual(decision.projection["value"][field], [])

            nonempty = copy.deepcopy(action)
            nonempty["args"][field] = ["other@example.com"]
            with self.subTest(field=field, representation="nonempty"):
                self.assertFalse(
                    decide_authority(
                        PROFILE,
                        self.grants[workflow_id],
                        action=nonempty,
                    ).within_authority
                )

        mixed = copy.deepcopy(action)
        mixed["args"].update({"cc": None, "bcc": [], "attachments": None})
        self.assertTrue(
            decide_authority(
                PROFILE,
                self.grants[workflow_id],
                action=mixed,
            ).within_authority
        )

    def test_calendar_search_optional_date_default_is_equivalent(self) -> None:
        source_task_id = "agentdojo:v1:travel:synthetic-search-authority-test"
        grant = build_authority_grant(
            PROFILE,
            source_task_id=source_task_id,
            ground_truth_calls=[
                {
                    "function": "search_calendar_events",
                    "args": {"query": "hotel"},
                }
            ],
        )
        for representation in ("omitted", "none"):
            action = {
                "function": "search_calendar_events",
                "args": {"query": "hotel"},
            }
            if representation == "none":
                action["args"]["date"] = None
            with self.subTest(representation=representation):
                decision = decide_authority(
                    PROFILE,
                    grant,
                    action=action,
                )
                self.assertTrue(decision.within_authority)
                self.assertIsNone(decision.projection["value"]["date"])

        for changed in ("2025-01-01", []):
            with self.subTest(changed=changed):
                decision = decide_authority(
                    PROFILE,
                    grant,
                    action={
                        "function": "search_calendar_events",
                        "args": {"query": "hotel", "date": changed},
                    },
                )
                self.assertFalse(decision.within_authority)

    def test_ungranted_controlled_and_unknown_mutations_fail_closed(self) -> None:
        for workflow_id, grant in self.grants.items():
            with self.subTest(workflow_id=workflow_id):
                controlled_read = decide_authority(
                    PROFILE,
                    grant,
                    action={"function": "get_user_information", "args": {}},
                )
                ungranted_mutation = decide_authority(
                    PROFILE,
                    grant,
                    action={
                        "function": "reserve_restaurant",
                        "args": {
                            "restaurant": "Any Restaurant",
                            "start_time": "2025-01-01 12:00",
                        },
                    },
                )
                unknown_mutation = decide_authority(
                    PROFILE,
                    grant,
                    action={"function": "travel_admin_override", "args": {}},
                )
                self.assertFalse(controlled_read.within_authority)
                self.assertFalse(ungranted_mutation.within_authority)
                self.assertFalse(unknown_mutation.within_authority)
                self.assertEqual(
                    unknown_mutation.reason, "operation_unclassified"
                )

    def test_only_explicit_public_metadata_is_unrestricted(self) -> None:
        grant = self.grants["agentdojo-v1-travel-u0-i0"]
        for function in UNRESTRICTED_METADATA:
            with self.subTest(function=function):
                decision = decide_authority(
                    PROFILE,
                    grant,
                    action={"function": function, "args": {}},
                )
                self.assertTrue(decision.within_authority)
                self.assertEqual(
                    decision.reason, "explicit_unrestricted_metadata"
                )

    def test_profile_and_grant_hashes_are_stable(self) -> None:
        rebuilt = build_profile(
            domain="travel",
            tools=TRAVEL_TOOL_AUTHORITY,
            normalize_authority_args=normalize_travel_authority_args,
            authority_effect_matcher=match_travel_authority_effect,
        )
        self.assertEqual(rebuilt.as_json(), PROFILE.as_json())
        self.assertEqual(rebuilt.profile_sha256, PROFILE.profile_sha256)
        for workflow_id, calls in self.native["benign_calls"].items():
            grant = self.grants[workflow_id]
            second = build_authority_grant(
                PROFILE,
                source_task_id=grant.source_task_id,
                ground_truth_calls=copy.deepcopy(calls),
            )
            with self.subTest(workflow_id=workflow_id):
                self.assertEqual(second.as_json(), grant.as_json())
                self.assertEqual(second.grant_sha256, grant.grant_sha256)

    def test_optional_default_normalizer_is_pure_and_profile_bound(self) -> None:
        original = {
            "recipients": ["jane@example.com"],
            "cc": None,
            "body": "unchanged content",
        }
        untouched = copy.deepcopy(original)
        first = normalize_travel_authority_args("send_email", original)
        second = normalize_travel_authority_args(
            "send_email", copy.deepcopy(original)
        )
        self.assertEqual(original, untouched)
        self.assertEqual(first, second)
        self.assertEqual(first["cc"], [])
        self.assertEqual(first["bcc"], [])
        self.assertEqual(first["attachments"], [])
        self.assertEqual(first["recipients"], ["jane@example.com"])
        self.assertEqual(first["body"], "unchanged content")
        binding = PROFILE.as_json()["authority_args_normalizer"]
        self.assertTrue(binding["callable"].endswith(
            ":normalize_travel_authority_args"
        ))
        self.assertEqual(len(binding["implementation_sha256"]), 64)
        matcher_binding = PROFILE.as_json()["authority_effect_matcher"]
        self.assertTrue(
            matcher_binding["callable"].endswith(
                ":match_travel_authority_effect"
            )
        )
        self.assertEqual(len(matcher_binding["implementation_sha256"]), 64)

    def test_profile_has_no_condition_goal_or_checker_dependency(self) -> None:
        import agentmembrane.host_v2.rq1_public_agentdojo_multi_v3.domain_authority.travel as travel

        source = inspect.getsource(travel)
        for prohibited_call in (
            "get_injection_task_by_id(",
            "_check_injection_task_security(",
            "security_from_traces(",
            "evaluate_native_checkers(",
        ):
            self.assertNotIn(prohibited_call, source)
        rendered = json.dumps(
            PROFILE.as_json(), ensure_ascii=False, sort_keys=True
        ).casefold()
        for prohibited in (
            "pair_role",
            "treatment_arm",
            "authorized_test_objective",
            "injection_goal",
            "security_checker",
        ):
            self.assertNotIn(prohibited, rendered)


if __name__ == "__main__":
    unittest.main()
