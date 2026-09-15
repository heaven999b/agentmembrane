"""Oracle-independent source-authority profile for AgentDojo Slack tools.

The profile classifies every native Slack-suite-v1 tool.  Resource-bearing
reads and mutations are controlled by reset-time grants derived solely from
the unmodified user task's ground truth in the default environment.  Message
or page content is intentionally not an authority field: authority controls
the recipient/channel/URL, while ordinary agents may still compose content.

No injection task, security checker, utility checker, oracle, experimental
condition, or treatment arm is consulted here.
"""

from __future__ import annotations

from typing import Any, Final, Mapping

from .core import AuthorityContractError, DomainAuthorityProfile, build_profile


DOMAIN: Final = "slack"

# Exact deterministic first-three Slack source workflows selected for v3.
# The IDs bind only the public source rows and native user tasks; they carry no
# treatment coordinate or hidden objective.
SLACK_SOURCE_WORKFLOWS: Final = (
    {
        "source_task_id": "agentdojo-v1-slack-u0-i3",
        "user_task_id": "user_task_0",
    },
    {
        "source_task_id": "agentdojo-v1-slack-u2-i5",
        "user_task_id": "user_task_2",
    },
    {
        "source_task_id": "agentdojo-v1-slack-u6-i1",
        "user_task_id": "user_task_6",
    },
)


# effect_op and resource form the stable Host-side resource projection.
# authority_fields contain only permission-bearing arguments.  In particular,
# message bodies and posted webpage content are not permission fields.
SLACK_TOOL_AUTHORITY: Final = {
    "get_channels": {
        "mode": "unrestricted",
        "effect_op": "read",
        "resource": "slack:channel_directory",
        "authority_fields": (),
    },
    "add_user_to_channel": {
        "mode": "controlled_mutation",
        "effect_op": "membership_add",
        "resource": "slack:channel_membership",
        "authority_fields": ("user", "channel"),
    },
    "read_channel_messages": {
        "mode": "controlled_read",
        "effect_op": "read",
        "resource": "slack:channel_messages",
        "authority_fields": ("channel",),
    },
    "read_inbox": {
        "mode": "controlled_read",
        "effect_op": "read",
        "resource": "slack:user_inbox",
        "authority_fields": ("user",),
    },
    "send_direct_message": {
        "mode": "controlled_mutation",
        "effect_op": "append",
        "resource": "slack:user_inbox",
        "authority_fields": ("recipient",),
    },
    "send_channel_message": {
        "mode": "controlled_mutation",
        "effect_op": "append",
        "resource": "slack:channel_messages",
        "authority_fields": ("channel",),
    },
    "get_users_in_channel": {
        "mode": "controlled_read",
        "effect_op": "read",
        "resource": "slack:channel_membership",
        "authority_fields": ("channel",),
    },
    "invite_user_to_slack": {
        "mode": "controlled_mutation",
        "effect_op": "membership_add",
        "resource": "slack:workspace_membership",
        "authority_fields": ("user", "user_email"),
    },
    "remove_user_from_slack": {
        "mode": "controlled_mutation",
        "effect_op": "membership_remove",
        "resource": "slack:workspace_membership",
        "authority_fields": ("user",),
    },
    "get_webpage": {
        "mode": "controlled_read",
        "effect_op": "read",
        "resource": "web:page",
        "authority_fields": ("url",),
    },
    "post_webpage": {
        "mode": "controlled_mutation",
        "effect_op": "write",
        "resource": "web:page",
        "authority_fields": ("url",),
    },
}


def normalize_slack_authority_args(
    function: str,
    args: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Project the exact native Slack web-tool URL effect identity.

    AgentDojo v1 ``tools/web.py::standardize_url`` performs two literal,
    case-sensitive prefix checks: it first removes an exact lower-case
    ``https://`` prefix, then an exact lower-case ``http://`` prefix.  This
    authority normalizer deliberately mirrors only those operations.  It does
    not parse the URL or normalize case, IDNA, ports, paths, root slashes,
    queries, fragments, userinfo, or compatibility Unicode characters.

    Preserving every other byte is security-significant: only a candidate that
    reaches the same native web-content key as the bare-host ground truth may
    match its grant.  The function remains static and independent of task,
    environment, trace, treatment, preview, or checker state.
    """

    if not isinstance(function, str) or not isinstance(args, Mapping):
        raise AuthorityContractError("Slack authority normalizer input is invalid")
    if any(not isinstance(key, str) for key in args):
        raise AuthorityContractError("Slack authority argument keys must be strings")
    normalized = dict(args)
    if function not in {"get_webpage", "post_webpage"} or "url" not in normalized:
        return normalized

    raw_url = normalized["url"]
    if not isinstance(raw_url, str):
        raise AuthorityContractError("Slack webpage URL must be a string")
    if raw_url.startswith("https://"):
        raw_url = raw_url[8:]
    if raw_url.startswith("http://"):
        raw_url = raw_url[7:]
    normalized["url"] = raw_url
    return normalized


PROFILE: Final[DomainAuthorityProfile] = build_profile(
    domain=DOMAIN,
    tools=SLACK_TOOL_AUTHORITY,
    normalize_authority_args=normalize_slack_authority_args,
)


__all__ = [
    "DOMAIN",
    "PROFILE",
    "SLACK_SOURCE_WORKFLOWS",
    "SLACK_TOOL_AUTHORITY",
    "normalize_slack_authority_args",
]
