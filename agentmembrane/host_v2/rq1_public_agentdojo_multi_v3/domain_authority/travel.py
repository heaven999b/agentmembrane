"""Oracle-independent source-authority profile for AgentDojo travel tools.

All 28 native travel-suite-v1 tools are classified explicitly.  Public
travel-catalog lookups are unrestricted metadata reads.  Reads of the current
user or calendar and every state mutation are authority controlled by a
reset-time grant derived from the unmodified user's native ground truth.

Authority fields identify the resource, target identity, or effect window.
Descriptive content such as email subject/body and calendar description or
location is intentionally outside the authority projection, so changing such
content cannot manufacture or expand authority.  This module contains no
condition-dependent policy and consults no outcome checker or oracle.
"""

from __future__ import annotations

import datetime
from typing import Any, Final, Mapping, Sequence

from .core import (
    AuthorityDecision,
    AuthorityGrant,
    DomainAuthorityProfile,
    build_profile,
    validate_native_tool_coverage,
)


DOMAIN: Final = "travel"

# Exact deterministic first-three travel source workflows selected for v3.
# Only the public source row and user task identity are retained here.
TRAVEL_SOURCE_WORKFLOWS: Final = (
    {
        "source_task_id": "agentdojo-v1-travel-u0-i0",
        "user_task_id": "user_task_0",
    },
    {
        "source_task_id": "agentdojo-v1-travel-u1-i2",
        "user_task_id": "user_task_1",
    },
    {
        "source_task_id": "agentdojo-v1-travel-u3-i1",
        "user_task_id": "user_task_3",
    },
)


# ``effect_op`` and ``resource`` form the stable Host-side effect projection.
# ``authority_fields`` contain only arguments that select an authority-bearing
# target, identity, resource, or effect window.  Informational prose is not an
# authority field.
TRAVEL_TOOL_AUTHORITY: Final = {
    # Current-user identity is private even though the native call has no args.
    "get_user_information": {
        "mode": "controlled_read",
        "effect_op": "read",
        "resource": "travel:current_user_identity",
        "authority_fields": (),
    },
    # Hotel catalog metadata.
    "get_all_hotels_in_city": {
        "mode": "unrestricted",
        "effect_op": "read",
        "resource": "travel:hotel_catalog",
        "authority_fields": (),
    },
    "get_hotels_prices": {
        "mode": "unrestricted",
        "effect_op": "read",
        "resource": "travel:hotel_catalog",
        "authority_fields": (),
    },
    "get_rating_reviews_for_hotels": {
        "mode": "unrestricted",
        "effect_op": "read",
        "resource": "travel:hotel_catalog",
        "authority_fields": (),
    },
    "get_hotels_address": {
        "mode": "unrestricted",
        "effect_op": "read",
        "resource": "travel:hotel_catalog",
        "authority_fields": (),
    },
    # Restaurant catalog metadata.
    "get_all_restaurants_in_city": {
        "mode": "unrestricted",
        "effect_op": "read",
        "resource": "travel:restaurant_catalog",
        "authority_fields": (),
    },
    "get_cuisine_type_for_restaurants": {
        "mode": "unrestricted",
        "effect_op": "read",
        "resource": "travel:restaurant_catalog",
        "authority_fields": (),
    },
    "get_restaurants_address": {
        "mode": "unrestricted",
        "effect_op": "read",
        "resource": "travel:restaurant_catalog",
        "authority_fields": (),
    },
    "get_rating_reviews_for_restaurants": {
        "mode": "unrestricted",
        "effect_op": "read",
        "resource": "travel:restaurant_catalog",
        "authority_fields": (),
    },
    "get_dietary_restrictions_for_all_restaurants": {
        "mode": "unrestricted",
        "effect_op": "read",
        "resource": "travel:restaurant_catalog",
        "authority_fields": (),
    },
    "get_contact_information_for_restaurants": {
        "mode": "unrestricted",
        "effect_op": "read",
        "resource": "travel:restaurant_catalog",
        "authority_fields": (),
    },
    "get_price_for_restaurants": {
        "mode": "unrestricted",
        "effect_op": "read",
        "resource": "travel:restaurant_catalog",
        "authority_fields": (),
    },
    "check_restaurant_opening_hours": {
        "mode": "unrestricted",
        "effect_op": "read",
        "resource": "travel:restaurant_catalog",
        "authority_fields": (),
    },
    # Car-rental catalog metadata.
    "get_all_car_rental_companies_in_city": {
        "mode": "unrestricted",
        "effect_op": "read",
        "resource": "travel:car_rental_catalog",
        "authority_fields": (),
    },
    "get_car_types_available": {
        "mode": "unrestricted",
        "effect_op": "read",
        "resource": "travel:car_rental_catalog",
        "authority_fields": (),
    },
    "get_rating_reviews_for_car_rental": {
        "mode": "unrestricted",
        "effect_op": "read",
        "resource": "travel:car_rental_catalog",
        "authority_fields": (),
    },
    "get_car_fuel_options": {
        "mode": "unrestricted",
        "effect_op": "read",
        "resource": "travel:car_rental_catalog",
        "authority_fields": (),
    },
    "get_car_rental_address": {
        "mode": "unrestricted",
        "effect_op": "read",
        "resource": "travel:car_rental_catalog",
        "authority_fields": (),
    },
    "get_car_price_per_day": {
        "mode": "unrestricted",
        "effect_op": "read",
        "resource": "travel:car_rental_catalog",
        "authority_fields": (),
    },
    # Calendar reads expose the current user's resource and are scope-bound.
    "search_calendar_events": {
        "mode": "controlled_read",
        "effect_op": "read",
        "resource": "travel:current_user_calendar",
        "authority_fields": ("query", "date"),
    },
    "get_day_calendar_events": {
        "mode": "controlled_read",
        "effect_op": "read",
        "resource": "travel:current_user_calendar",
        "authority_fields": ("day",),
    },
    # Calendar mutations bind event identity/window and external participants.
    # Description and location remain ordinary non-authority content.
    "create_calendar_event": {
        "mode": "controlled_mutation",
        "effect_op": "create",
        "resource": "travel:current_user_calendar",
        "authority_fields": (
            "title",
            "start_time",
            "end_time",
            "participants",
        ),
    },
    "cancel_calendar_event": {
        "mode": "controlled_mutation",
        "effect_op": "cancel",
        "resource": "travel:current_user_calendar",
        "authority_fields": ("event_id",),
    },
    # Reservation calls overwrite the current user's reservation resource.
    "reserve_hotel": {
        "mode": "controlled_mutation",
        "effect_op": "reserve",
        "resource": "travel:current_user_hotel_reservation",
        "authority_fields": ("hotel", "start_day", "end_day"),
    },
    "reserve_car_rental": {
        "mode": "controlled_mutation",
        "effect_op": "reserve",
        "resource": "travel:current_user_car_reservation",
        "authority_fields": ("company", "start_time", "end_time"),
    },
    "reserve_restaurant": {
        "mode": "controlled_mutation",
        "effect_op": "reserve",
        "resource": "travel:current_user_restaurant_reservation",
        "authority_fields": ("restaurant", "start_time"),
    },
    # Flight lookup is public catalog metadata.
    "get_flight_information": {
        "mode": "unrestricted",
        "effect_op": "read",
        "resource": "travel:flight_catalog",
        "authority_fields": (),
    },
    # Destination identities and attached resources carry authority.  Subject
    # and body are non-authority content and may be composed by the agent.
    "send_email": {
        "mode": "controlled_mutation",
        "effect_op": "send",
        "resource": "travel:outbound_email",
        "authority_fields": ("recipients", "cc", "bcc", "attachments"),
    },
}


def normalize_travel_authority_args(
    function: str,
    args: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Canonicalize only native-equivalent optional travel defaults.

    AgentDojo treats an omitted optional collection, ``None``, and an empty
    collection identically for calendar participants and optional email
    collections.  Calendar search likewise treats omitted ``date`` and
    ``None`` identically.  No nonempty authority-bearing value is rewritten.
    The function is deliberately static, mutation-isolated, and independent of
    environment, task, trace, outcome, or experimental coordinates.
    """

    normalized = dict(args)
    if function == "create_calendar_event":
        if normalized.get("participants") in (None, []):
            normalized["participants"] = []
    elif function == "send_email":
        for field in ("cc", "bcc", "attachments"):
            if normalized.get(field) in (None, []):
                normalized[field] = []
    elif function == "search_calendar_events":
        if normalized.get("date") is None:
            normalized["date"] = None
    return normalized


def match_travel_authority_effect(
    granted_effect: Mapping[str, Any],
    candidate_effect: Mapping[str, Any],
) -> bool:
    """Match a candidate effect against one frozen travel grant.

    Exact effect equality remains the default.  The sole asymmetric exception
    is a native calendar grant whose start and end encode one complete explicit
    date (``00:00`` through ``23:59``).  Such a grant represents the user's
    date-only choice, so it contains any positive-duration event wholly within
    that same date.  Exact-time grants never enter this branch.

    Parsing deliberately accepts only the native naive minute format.  ISO
    timezone offsets, ``Z``, seconds, ``T`` separators, invalid dates, cross-day
    windows, and non-positive durations therefore fail closed rather than being
    converted across timezone or calendar boundaries.
    """

    if granted_effect == candidate_effect:
        return True
    effect_keys = {"op", "resource", "value"}
    if (
        set(granted_effect) != effect_keys
        or set(candidate_effect) != effect_keys
        or granted_effect.get("op") != "create"
        or candidate_effect.get("op") != "create"
        or granted_effect.get("resource")
        != "travel:current_user_calendar"
        or candidate_effect.get("resource")
        != "travel:current_user_calendar"
    ):
        return False
    granted_value = granted_effect.get("value")
    candidate_value = candidate_effect.get("value")
    authority_fields = {
        "title",
        "start_time",
        "end_time",
        "participants",
    }
    if (
        not isinstance(granted_value, Mapping)
        or not isinstance(candidate_value, Mapping)
        or set(granted_value) != authority_fields
        or set(candidate_value) != authority_fields
        or granted_value.get("title") != candidate_value.get("title")
        or granted_value.get("participants")
        != candidate_value.get("participants")
    ):
        return False

    def strict_native_minute(value: Any) -> datetime.datetime | None:
        if not isinstance(value, str) or len(value) != 16:
            return None
        try:
            parsed = datetime.datetime.strptime(value, "%Y-%m-%d %H:%M")
        except ValueError:
            return None
        if parsed.strftime("%Y-%m-%d %H:%M") != value:
            return None
        return parsed

    grant_start = strict_native_minute(granted_value.get("start_time"))
    grant_end = strict_native_minute(granted_value.get("end_time"))
    candidate_start = strict_native_minute(candidate_value.get("start_time"))
    candidate_end = strict_native_minute(candidate_value.get("end_time"))
    if None in (grant_start, grant_end, candidate_start, candidate_end):
        return False
    assert grant_start is not None
    assert grant_end is not None
    assert candidate_start is not None
    assert candidate_end is not None
    grant_date = grant_start.date()
    return bool(
        grant_end.date() == grant_date
        and grant_start.time() == datetime.time(0, 0)
        and grant_end.time() == datetime.time(23, 59)
        and candidate_start.date() == grant_date
        and candidate_end.date() == grant_date
        and candidate_end > candidate_start
    )


PROFILE: Final[DomainAuthorityProfile] = build_profile(
    domain=DOMAIN,
    tools=TRAVEL_TOOL_AUTHORITY,
    normalize_authority_args=normalize_travel_authority_args,
    authority_effect_matcher=match_travel_authority_effect,
)

# Neutral aliases ease domain aggregation without changing the frozen profile.
TOOL_AUTHORITY: Final = TRAVEL_TOOL_AUTHORITY
WORKFLOW_AUTHORITY_PROFILES: Final = TRAVEL_SOURCE_WORKFLOWS


def _suite_from_active(active_or_suite: Any) -> Any:
    suite = getattr(active_or_suite, "suite", active_or_suite)
    if getattr(suite, "name", None) != DOMAIN:
        raise ValueError("travel authority requires the native travel suite")
    tools = getattr(suite, "tools", None)
    if not isinstance(tools, Sequence) or isinstance(tools, (str, bytes)):
        raise TypeError("native travel suite tools are unavailable")
    names = []
    for tool in tools:
        name = getattr(tool, "name", None)
        if not isinstance(name, str) or not name:
            raise TypeError("native travel suite contains an invalid tool")
        names.append(name)
    validate_native_tool_coverage(PROFILE, names)
    return suite


def _clean_source_task_id(user_task: Any) -> str:
    user_task_id = getattr(user_task, "ID", None)
    if not isinstance(user_task_id, str) or not user_task_id:
        raise TypeError("native travel user task has no stable ID")
    return f"agentdojo:v1:travel:{user_task_id}"


def build_travel_authority(
    active_or_suite: Any,
    user_task: Any,
) -> AuthorityGrant:
    """Build reset-time grants solely from native benign ground truth.

    A fresh default environment with an empty overlay mapping is used even if
    an active episode is supplied.  Current episode state, trace, experimental
    coordinate, model output, and outcome evaluators are not inputs.
    """

    suite = _suite_from_active(active_or_suite)
    loader = getattr(suite, "load_and_inject_default_environment", None)
    initializer = getattr(user_task, "init_environment", None)
    ground_truth = getattr(user_task, "ground_truth", None)
    if not callable(loader) or not callable(initializer) or not callable(ground_truth):
        raise TypeError("native travel reset-time authority inputs are unavailable")
    environment = initializer(loader({}))
    copier = getattr(environment, "model_copy", None)
    if not callable(copier):
        raise TypeError("native travel environment cannot be copied")
    pre_environment = copier(deep=True)
    calls = ground_truth(pre_environment)
    if not isinstance(calls, Sequence) or isinstance(calls, (str, bytes)):
        raise TypeError("native travel user ground truth is not an action sequence")
    return PROFILE.grants_from_ground_truth(
        _clean_source_task_id(user_task),
        tuple(calls),
    )


def decide_travel(
    grant: AuthorityGrant,
    action: Mapping[str, Any],
    *,
    consumed_grant_indexes: Sequence[int] = (),
) -> AuthorityDecision:
    """Decide one native travel call without dispatch or outcome evaluation."""

    return PROFILE.authorize(
        grant,
        action,
        consumed_grant_indexes=tuple(consumed_grant_indexes),
    )


__all__ = [
    "DOMAIN",
    "PROFILE",
    "TOOL_AUTHORITY",
    "TRAVEL_SOURCE_WORKFLOWS",
    "TRAVEL_TOOL_AUTHORITY",
    "WORKFLOW_AUTHORITY_PROFILES",
    "build_travel_authority",
    "decide_travel",
    "match_travel_authority_effect",
    "normalize_travel_authority_args",
]
