"""Capture the actual controller state, not an evaluator-maintained mirror."""
from copy import deepcopy
from ..rq1_collab_v3.contract import clone, digest, PRINCIPALS
from .permissions import native_tools, authorize_native


def native_grant_key(authority):
    """Ignore consumption counters, not native grant/admission transitions."""
    return digest({"episode_id": authority["episode_id"], "task_hash": authority["task_hash"],
        "admission_open": authority["admission_open"], "permit_epoch": authority["permit_epoch"],
        "actors": {a: {k: s[k] for k in ("principal", "level", "delegated_tools")}
                   for a, s in authority["actors"].items()}})


def snapshot_effective_authority(*, actor_state, config, task_policy, record,
                                 permit_epoch, active_actor, admission_open, profile):
    actors = {}
    for actor, state in actor_state.items():
        ceiling = set(native_tools(task_policy, record, state["level"], profile=profile))
        effective = ceiling if state["tools"] is None else ceiling & set(state["tools"])
        actors[actor] = {"principal": PRINCIPALS[actor], "level": state["level"],
            "delegated_tools": clone(state["tools"]), "effective_tools": sorted(effective),
            "remaining": state["remaining"], "state": state["state"]}
    result = {"episode_id": config["episode_id"], "task_hash": config["bundle_sha256"],
        "permit_epoch": permit_epoch, "active_actor": active_actor,
        "admission_open": bool(admission_open), "actors": actors}
    result["state_sha256"] = digest(result)
    return result


def probe_authority_readonly(snapshot, request, *, policy, record, business_state, profile):
    """Decision-only production probe. Expected values are computed separately."""
    before = digest(business_state)
    actor = request["actor"]
    state = snapshot["actors"].get(actor)
    allowed, reason = (False, "closed_or_unregistered_identity")
    if state and snapshot["admission_open"]:
        # Some production policies prime/cache initial object identities during
        # authorization. A read-only probe must not prime the live policy either.
        allowed, reason = authorize_native(deepcopy(policy), record, state["level"],
                                           request["tool"], request["arguments"],
                                           clone(business_state), actor=actor, profile=profile)
        if state["delegated_tools"] is not None and request["tool"] not in state["delegated_tools"]:
            allowed, reason = False, "outside_delegated_tool_subset"
    if digest(business_state) != before:
        raise ValueError("readonly_probe_changed_world")
    return {"snapshot_sha256": snapshot["state_sha256"], "request": clone(request),
            "actual_allowed": allowed, "reason": reason, "backend_entered": False,
            "coverage": "one_registered_probe_not_complete_permission_space"}


def registered_probe_requests(record, initial_state, tool_specs):
    """Source-bound engineering probes, never backend calls or study examples.

    This is deliberately a PARTIAL permission partition. Empty arguments are
    used only for registered zero-argument APIs; source-object probes reference
    actual original IDs. Arbitrary missing tool arguments are not fabricated.
    """
    available = {s["name"] for s in tool_specs}
    result = []
    def add(tool, arguments):
        if tool in available:
            value = {"tool": tool, "arguments": arguments}
            result.append({**value, "probe_id": digest(value)})
    for tool in ("get_current_day", "get_unread_emails", "get_sent_emails",
                 "get_received_emails", "get_draft_emails", "list_files",
                 "get_user_information"):
        add(tool, {})
    for fid in sorted(initial_state.get("cloud_drive", {}).get("files", {})):
        for tool in ("get_file_by_id", "delete_file"):
            add(tool, {"file_id": str(fid)})
    facts = record.get("task_policy", {}).get("facts_from_actor_prompt", {})
    if record.get("suite") == "workspace" and record.get("original_id") == "user_task_8":
        add("search_calendar_events", {"query": facts["event_title"], "date": facts["event_date"]})
        add("get_day_calendar_events", {"day": facts["event_date"]})
        for eid in sorted(initial_state.get("calendar", {}).get("events", {})):
            add("add_calendar_event_participants", {"event_id": str(eid), "participants": facts["requested_participants"]})
    if record.get("suite") == "travel":
        if record.get("original_id") == "user_task_0":
            add("get_all_hotels_in_city", {"city": facts["city"]})
            for tool in ("get_hotels_prices", "get_rating_reviews_for_hotels"):
                add(tool, {"hotel_names": [facts["hotel_name"]]})
            add("get_hotels_address", {"hotel_name": facts["hotel_name"]})
            add("reserve_hotel", {"hotel": facts["hotel_name"], "start_day": facts["start_day"], "end_day": facts["end_day"]})
        else:
            # Source-native travel profiles use either a single ``city`` or
            # a public-recommendation ``cities`` list. Probe only cities that
            # were actually parsed from the user's request.
            cities = ([facts["city"]] if "city" in facts else facts.get("cities", []))
            if type(cities) is not list or any(type(city) is not str or not city for city in cities):
                raise ValueError("invalid_source_bound_travel_probe_cities")
            for city in sorted(set(cities)):
                add("get_all_restaurants_in_city", {"city": city})
                names = [r["name"] for r in initial_state.get("restaurants", {}).get("restaurant_list", []) if r.get("city") == city]
                if names:
                    for tool in ("get_cuisine_type_for_restaurants", "get_rating_reviews_for_restaurants", "get_price_for_restaurants"):
                        add(tool, {"restaurant_names": sorted(names)})
    return result
