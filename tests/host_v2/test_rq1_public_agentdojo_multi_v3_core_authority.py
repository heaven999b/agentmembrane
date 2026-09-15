from __future__ import annotations

import copy
import inspect
import unittest

from agentmembrane.host_v2.rq1_public_agentdojo_multi_v3.domain_authority.core import (
    AuthorityContractError,
    build_authority_grant,
    build_profile,
    decide_authority,
)
from agentmembrane.host_v2.schema import sha256_json


_MATCHER_CALLS: list[tuple[dict, dict]] = []
_NONDETERMINISTIC_STATE = False


def _travel_interval_contained(grant_effect, candidate_effect):
    grant = grant_effect["value"]
    candidate = candidate_effect["value"]
    return (
        grant.get("date") == candidate.get("date")
        and type(grant.get("start_minute")) is int
        and type(grant.get("end_minute")) is int
        and type(candidate.get("start_minute")) is int
        and type(candidate.get("end_minute")) is int
        and grant["start_minute"] <= candidate["start_minute"]
        and candidate["end_minute"] <= grant["end_minute"]
        and candidate["start_minute"] < candidate["end_minute"]
    )


def _travel_interval_contained_source_drift(grant_effect, candidate_effect):
    # Deliberately equivalent behavior with different complete source bytes.
    grant = grant_effect["value"]
    candidate = candidate_effect["value"]
    return (
        grant.get("date") == candidate.get("date")
        and type(grant.get("start_minute")) is int
        and type(grant.get("end_minute")) is int
        and type(candidate.get("start_minute")) is int
        and type(candidate.get("end_minute")) is int
        and grant["start_minute"] <= candidate["start_minute"]
        and candidate["end_minute"] <= grant["end_minute"]
        and candidate["start_minute"] < candidate["end_minute"]
    )


def _workspace_phrase_refinement(grant_effect, candidate_effect):
    grant_phrase = grant_effect["value"].get("query")
    candidate_phrase = candidate_effect["value"].get("query")
    if not isinstance(grant_phrase, str) or not isinstance(candidate_phrase, str):
        return False
    grant_tokens = tuple(grant_phrase.casefold().split())
    candidate_tokens = tuple(candidate_phrase.casefold().split())
    return bool(grant_tokens) and all(
        token in candidate_tokens for token in grant_tokens
    )


def _record_relation_call(grant_effect, candidate_effect):
    _MATCHER_CALLS.append(
        (copy.deepcopy(grant_effect), copy.deepcopy(candidate_effect))
    )
    return True


def _raise_relation(grant_effect, candidate_effect):
    del grant_effect, candidate_effect
    raise RuntimeError("relation hook failed")


def _non_bool_relation(grant_effect, candidate_effect):
    del grant_effect, candidate_effect
    return 1


def _nondeterministic_relation(grant_effect, candidate_effect):
    del grant_effect, candidate_effect
    global _NONDETERMINISTIC_STATE
    _NONDETERMINISTIC_STATE = not _NONDETERMINISTIC_STATE
    return _NONDETERMINISTIC_STATE


def _mutating_relation(grant_effect, candidate_effect):
    grant_effect["value"]["window"]["slots"].append("hook-poison")
    candidate_effect["value"]["window"]["slots"].clear()
    return True


def _travel_profile(matcher=None):
    return build_profile(
        "travel",
        {
            "book_window": {
                "mode": "controlled_mutation",
                "effect_op": "book",
                "resource": "travel:calendar_window",
                "authority_fields": ("date", "start_minute", "end_minute"),
            }
        },
        authority_effect_matcher=matcher,
    )


def _all_day_call():
    return {
        "function": "book_window",
        "args": {
            "date": "2026-09-01",
            "start_minute": 0,
            "end_minute": 1440,
        },
    }


def _subinterval_call():
    return {
        "function": "book_window",
        "args": {
            "date": "2026-09-01",
            "start_minute": 600,
            "end_minute": 660,
        },
    }


class CoreAuthorityEffectRelationTests(unittest.TestCase):
    def test_no_hook_preserves_strict_equality_and_exact_reason(self):
        profile = _travel_profile()
        grant = build_authority_grant(
            profile,
            source_task_id="travel-task",
            ground_truth_calls=[_all_day_call()],
        )

        denied = decide_authority(profile, grant, action=_subinterval_call())
        exact = decide_authority(profile, grant, action=_all_day_call())

        self.assertFalse(denied.within_authority)
        self.assertEqual(denied.reason, "no_matching_user_authority_grant")
        self.assertTrue(exact.within_authority)
        self.assertEqual(exact.reason, "authority_grant_match")
        self.assertNotIn("authority_effect_matcher", profile.as_json())

    def test_matcher_complete_source_and_identity_are_profile_hash_bound(self):
        first = _travel_profile(_travel_interval_contained)
        drifted = _travel_profile(_travel_interval_contained_source_drift)
        binding = first.as_json()["authority_effect_matcher"]
        expected_source_sha = sha256_json(
            {
                "artifact_type": "authority_effect_matcher_python_source_v1",
                "source": inspect.getsource(_travel_interval_contained),
            }
        )

        self.assertEqual(
            binding["callable"],
            f"{__name__}:_travel_interval_contained",
        )
        self.assertEqual(binding["implementation_sha256"], expected_source_sha)
        self.assertNotEqual(
            binding["implementation_sha256"],
            drifted.as_json()["authority_effect_matcher"][
                "implementation_sha256"
            ],
        )
        self.assertNotEqual(first.profile_sha256, drifted.profile_sha256)

        grant = build_authority_grant(
            first,
            source_task_id="travel-task",
            ground_truth_calls=[_all_day_call()],
        )
        with self.assertRaisesRegex(
            AuthorityContractError, "grant/profile binding differs"
        ):
            decide_authority(drifted, grant, action=_subinterval_call())

    def test_travel_contains_same_day_subinterval_but_not_outside_interval(self):
        profile = _travel_profile(_travel_interval_contained)
        grant = build_authority_grant(
            profile,
            source_task_id="travel-task",
            ground_truth_calls=[_all_day_call()],
        )

        contained = decide_authority(profile, grant, action=_subinterval_call())
        next_day = copy.deepcopy(_subinterval_call())
        next_day["args"]["date"] = "2026-09-02"
        outside = copy.deepcopy(_subinterval_call())
        outside["args"]["end_minute"] = 1500

        self.assertTrue(contained.within_authority)
        self.assertEqual(contained.reason, "authority_grant_relation_match")
        self.assertEqual(contained.matched_grant_index, 0)
        self.assertTrue(contained.consumes_grant)
        self.assertFalse(
            decide_authority(profile, grant, action=next_day).within_authority
        )
        self.assertFalse(
            decide_authority(profile, grant, action=outside).within_authority
        )

    def test_workspace_query_phrase_refinement_is_a_nonconsuming_relation(self):
        profile = build_profile(
            "workspace",
            {
                "search_workspace": {
                    "mode": "controlled_read",
                    "effect_op": "query",
                    "resource": "workspace:search",
                    "authority_fields": ("query",),
                }
            },
            authority_effect_matcher=_workspace_phrase_refinement,
        )
        grant = build_authority_grant(
            profile,
            source_task_id="workspace-task",
            ground_truth_calls=[
                {
                    "function": "search_workspace",
                    "args": {"query": "quarterly roadmap"},
                }
            ],
        )

        refined = decide_authority(
            profile,
            grant,
            action={
                "function": "search_workspace",
                "args": {"query": "quarterly roadmap launch dates"},
            },
        )
        unrelated = decide_authority(
            profile,
            grant,
            action={
                "function": "search_workspace",
                "args": {"query": "payroll launch dates"},
            },
        )

        self.assertTrue(refined.within_authority)
        self.assertEqual(refined.reason, "authority_grant_relation_match")
        self.assertFalse(refined.consumes_grant)
        self.assertFalse(unrelated.within_authority)

    def test_exact_match_precedes_relation_and_never_calls_matcher(self):
        _MATCHER_CALLS.clear()
        profile = _travel_profile(_record_relation_call)
        grant = build_authority_grant(
            profile,
            source_task_id="travel-task",
            ground_truth_calls=[_all_day_call(), _subinterval_call()],
        )

        exact = decide_authority(profile, grant, action=_subinterval_call())

        self.assertTrue(exact.within_authority)
        self.assertEqual(exact.reason, "authority_grant_match")
        self.assertEqual(exact.matched_grant_index, 1)
        self.assertEqual(_MATCHER_CALLS, [])

    def test_different_operation_or_resource_never_calls_matcher(self):
        _MATCHER_CALLS.clear()
        profile = build_profile(
            "travel",
            {
                "grant_other_resource": {
                    "mode": "controlled_mutation",
                    "effect_op": "book",
                    "resource": "travel:other",
                    "authority_fields": ("key",),
                },
                "grant_other_operation": {
                    "mode": "controlled_mutation",
                    "effect_op": "cancel",
                    "resource": "travel:calendar_window",
                    "authority_fields": ("key",),
                },
                "candidate": {
                    "mode": "controlled_mutation",
                    "effect_op": "book",
                    "resource": "travel:calendar_window",
                    "authority_fields": ("key",),
                },
            },
            authority_effect_matcher=_record_relation_call,
        )
        grant = build_authority_grant(
            profile,
            source_task_id="travel-task",
            ground_truth_calls=[
                {"function": "grant_other_resource", "args": {"key": "x"}},
                {"function": "grant_other_operation", "args": {"key": "x"}},
            ],
        )

        decision = decide_authority(
            profile,
            grant,
            action={"function": "candidate", "args": {"key": "y"}},
        )

        self.assertFalse(decision.within_authority)
        self.assertEqual(_MATCHER_CALLS, [])

    def test_exception_non_bool_and_nondeterminism_all_fail_closed(self):
        global _NONDETERMINISTIC_STATE
        for matcher in (
            _raise_relation,
            _non_bool_relation,
            _nondeterministic_relation,
        ):
            with self.subTest(matcher=matcher.__name__):
                _NONDETERMINISTIC_STATE = False
                profile = _travel_profile(matcher)
                grant = build_authority_grant(
                    profile,
                    source_task_id="travel-task",
                    ground_truth_calls=[_all_day_call()],
                )

                decision = decide_authority(
                    profile, grant, action=_subinterval_call()
                )

                self.assertFalse(decision.within_authority)
                self.assertEqual(
                    decision.reason, "no_matching_user_authority_grant"
                )
                self.assertIsNone(decision.matched_grant_index)

    def test_hook_input_mutation_cannot_pollute_grant_or_candidate(self):
        profile = build_profile(
            "travel",
            {
                "book_slots": {
                    "mode": "controlled_mutation",
                    "effect_op": "book",
                    "resource": "travel:slots",
                    "authority_fields": ("window",),
                }
            },
            authority_effect_matcher=_mutating_relation,
        )
        grant = build_authority_grant(
            profile,
            source_task_id="travel-task",
            ground_truth_calls=[
                {
                    "function": "book_slots",
                    "args": {"window": {"slots": ["all-day"]}},
                }
            ],
        )
        candidate = {
            "function": "book_slots",
            "args": {"window": {"slots": ["10:00", "11:00"]}},
        }
        grant_before = grant.as_json()
        candidate_before = copy.deepcopy(candidate)

        decision = decide_authority(profile, grant, action=candidate)

        self.assertTrue(decision.within_authority)
        self.assertEqual(grant.as_json(), grant_before)
        self.assertEqual(candidate, candidate_before)

    def test_consumed_mutation_relation_grant_cannot_be_reused(self):
        profile = _travel_profile(_travel_interval_contained)
        grant = build_authority_grant(
            profile,
            source_task_id="travel-task",
            ground_truth_calls=[_all_day_call()],
        )
        first = decide_authority(profile, grant, action=_subinterval_call())
        replay = decide_authority(
            profile,
            grant,
            action=_subinterval_call(),
            consumed_grant_indexes=(first.matched_grant_index,),
        )

        self.assertTrue(first.consumes_grant)
        self.assertFalse(replay.within_authority)
        self.assertIsNone(replay.matched_grant_index)
        self.assertFalse(replay.consumes_grant)


if __name__ == "__main__":
    unittest.main()
