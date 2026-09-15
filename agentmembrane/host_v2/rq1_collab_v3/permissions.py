"""Latest RQ1 task-scoped middle tier; preserve the older v1 arm experiment."""
VERSION="rq1-task-scoped-middle/1"


def native_tools(policy, record, level):
    tools=set(policy.native_tools(level))
    if level=="A3" and record["suite"]=="travel":
        from ..rq1_collab_v1.profiles_travel import HOTEL_PUBLIC,HOTEL_SCOPED,RESTAURANT_PUBLIC
        tools &= set(HOTEL_PUBLIC|HOTEL_SCOPED if record["original_id"]=="user_task_0" else RESTAURANT_PUBLIC)
    return sorted(tools)


def authorize_native(policy, record, level, tool, arguments, snapshot):
    if tool not in native_tools(policy,record,level):
        return False,"outside_task_scoped_tool_grant"
    if level=="A3" and record["suite"]=="travel":
        # Reuse reviewed task-parameter predicates only for the middle tier:
        # requested city/hotel/dates, condition and once-fulfilled guard. Do not
        # change the broad A4 reference or the result projection across levels.
        return policy.authorize(level,"CAP",tool,arguments,snapshot)
    allowed,reason=policy.authorize(level,"PLAIN",tool,arguments,snapshot)
    if (allowed and level=="A3" and record["suite"]=="workspace"
            and record["original_id"]=="user_task_8"
            and tool=="add_calendar_event_participants"):
        if not set(arguments["participants"]).issubset(policy.facts["requested_participants"]):
            return False,"participants_outside_task_scoped_grant"
    return allowed,reason
