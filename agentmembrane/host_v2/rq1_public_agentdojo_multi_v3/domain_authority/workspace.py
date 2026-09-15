"""Oracle-independent source-authority profile for AgentDojo workspace.

All 24 suite-v1 workspace functions are exhaustively classified below.
Resource-bearing reads and every mutation require a reset-time grant derived
only from the selected user task's ground-truth calls in the default,
uninjected environment.  The sole unrestricted operation is current-day
metadata introspection.

Authority fields identify recipients, resource identities, identities being
looked up, or permission assignments.  Calendar creation additionally binds
the title, start/end time, and location because these values determine the
authorized event.  Ordinary content fields such as email bodies, event
descriptions, and appended file content may vary without expanding the grant.
This module does not load an oracle or invoke an injection, utility, or
security checker.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any, Final, Iterable, Mapping

from ...schema import IntegrityError, SchemaError, canonical_json_bytes
from .core import (
    AuthorityDecision,
    AuthorityGrant,
    DomainAuthorityProfile,
    build_authority_grant,
    build_profile,
    decide_authority,
    validate_native_tool_coverage,
)


DOMAIN: Final = "workspace"

# Exact deterministic first-three workspace workflows selected for v3.  Only
# source/user identities appear here: no pair role, arm, injection goal, or
# hidden experimental condition participates in authority construction.
WORKSPACE_SOURCE_WORKFLOWS: Final = (
    {
        "source_task_id": "agentdojo-v1-workspace-u13-i0",
        "user_task_id": "user_task_13",
    },
    {
        "source_task_id": "agentdojo-v1-workspace-u15-i2",
        "user_task_id": "user_task_15",
    },
    {
        "source_task_id": "agentdojo-v1-workspace-u18-i3",
        "user_task_id": "user_task_18",
    },
)


# ``effect_op`` + ``resource`` is the stable Host-side resource projection.
# Every controlled mutation declares the complete set of arguments which can
# expand authority.  Optional destination fields are included so adding a CC,
# BCC, attachment, or participant cannot reuse a narrower grant.
WORKSPACE_TOOL_AUTHORITY: Final = {
    # Email: reading a mailbox/message set is identity/resource bearing.
    "send_email": {
        "mode": "controlled_mutation",
        "effect_op": "send",
        "resource": "workspace:email:outbound",
        "authority_fields": ("recipients", "cc", "bcc", "attachments"),
    },
    "delete_email": {
        "mode": "controlled_mutation",
        "effect_op": "delete",
        "resource": "workspace:email:message",
        "authority_fields": ("email_id",),
    },
    # AgentDojo marks all returned unread messages as read, so this is a
    # mutation even though its name begins with ``get``.
    "get_unread_emails": {
        "mode": "controlled_mutation",
        "effect_op": "mark_read",
        "resource": "workspace:email:unread_set",
        "authority_fields": (),
    },
    "get_sent_emails": {
        "mode": "controlled_read",
        "effect_op": "read",
        "resource": "workspace:email:sent_set",
        "authority_fields": (),
    },
    "get_received_emails": {
        "mode": "controlled_read",
        "effect_op": "read",
        "resource": "workspace:email:received_set",
        "authority_fields": (),
    },
    "get_draft_emails": {
        "mode": "controlled_read",
        "effect_op": "read",
        "resource": "workspace:email:draft_set",
        "authority_fields": (),
    },
    "search_emails": {
        "mode": "controlled_read",
        "effect_op": "read",
        "resource": "workspace:email:search",
        "authority_fields": ("query", "sender"),
    },
    "search_contacts_by_name": {
        "mode": "controlled_read",
        "effect_op": "read_identity",
        "resource": "workspace:email:contacts",
        "authority_fields": ("query",),
    },
    "search_contacts_by_email": {
        "mode": "controlled_read",
        "effect_op": "read_identity",
        "resource": "workspace:email:contacts",
        "authority_fields": ("query",),
    },
    # Calendar: current day is condition-invariant metadata; event lookups are
    # resource-bearing and remain controlled.
    "get_current_day": {
        "mode": "unrestricted",
        "effect_op": "read_metadata",
        "resource": "workspace:calendar:current_day",
        "authority_fields": (),
    },
    "search_calendar_events": {
        "mode": "controlled_read",
        "effect_op": "read",
        "resource": "workspace:calendar:event_search",
        "authority_fields": ("query", "date"),
    },
    "get_day_calendar_events": {
        "mode": "controlled_read",
        "effect_op": "read",
        "resource": "workspace:calendar:day",
        "authority_fields": ("day",),
    },
    "create_calendar_event": {
        "mode": "controlled_mutation",
        "effect_op": "create",
        "resource": "workspace:calendar:event",
        "authority_fields": (
            "title",
            "start_time",
            "end_time",
            "location",
            "participants",
        ),
    },
    "cancel_calendar_event": {
        "mode": "controlled_mutation",
        "effect_op": "cancel",
        "resource": "workspace:calendar:event",
        "authority_fields": ("event_id",),
    },
    "reschedule_calendar_event": {
        "mode": "controlled_mutation",
        "effect_op": "reschedule",
        "resource": "workspace:calendar:event",
        "authority_fields": ("event_id",),
    },
    "add_calendar_event_participants": {
        "mode": "controlled_mutation",
        "effect_op": "membership_add",
        "resource": "workspace:calendar:event_participants",
        "authority_fields": ("event_id", "participants"),
    },
    # Cloud drive: file IDs/names/search selectors identify accessed resources;
    # content is intentionally not an authority-bearing argument.
    "append_to_file": {
        "mode": "controlled_mutation",
        "effect_op": "append",
        "resource": "workspace:cloud_drive:file",
        "authority_fields": ("file_id",),
    },
    "search_files_by_filename": {
        "mode": "controlled_read",
        "effect_op": "read",
        "resource": "workspace:cloud_drive:filename_search",
        "authority_fields": ("filename",),
    },
    "create_file": {
        "mode": "controlled_mutation",
        "effect_op": "create",
        "resource": "workspace:cloud_drive:file",
        "authority_fields": ("filename",),
    },
    "delete_file": {
        "mode": "controlled_mutation",
        "effect_op": "delete",
        "resource": "workspace:cloud_drive:file",
        "authority_fields": ("file_id",),
    },
    "get_file_by_id": {
        "mode": "controlled_read",
        "effect_op": "read",
        "resource": "workspace:cloud_drive:file",
        "authority_fields": ("file_id",),
    },
    "list_files": {
        "mode": "controlled_read",
        "effect_op": "read",
        "resource": "workspace:cloud_drive:file_set",
        "authority_fields": (),
    },
    "share_file": {
        "mode": "controlled_mutation",
        "effect_op": "delegate",
        "resource": "workspace:cloud_drive:file_permission",
        "authority_fields": ("file_id", "email", "permission"),
    },
    "search_files": {
        "mode": "controlled_read",
        "effect_op": "read",
        "resource": "workspace:cloud_drive:content_search",
        "authority_fields": ("query",),
    },
}


def normalize_workspace_authority_args(
    function: str,
    args: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Canonicalize only native-equivalent optional workspace arguments.

    The native schemas treat omitted, ``null``, and an empty list identically
    for these collection-valued fields.  ``search_emails.sender`` has a scalar
    ``null`` default, so omission is normalized to ``None``.  Nonempty values,
    required arguments, and every other workspace function remain untouched.
    """

    normalized = copy.deepcopy(dict(args))
    if function == "send_email":
        for field in ("cc", "bcc", "attachments"):
            if normalized.get(field) in (None, []):
                normalized[field] = []
    elif function == "search_emails":
        if normalized.get("sender") is None:
            normalized["sender"] = None
    elif function == "create_calendar_event":
        if normalized.get("participants") in (None, []):
            normalized["participants"] = []
    return normalized


def workspace_authority_effect_matcher(
    grant_effect: Mapping[str, Any],
    candidate_effect: Mapping[str, Any],
) -> bool:
    """Match only proven-narrower native email-search effects.

    This is deliberately narrower than token-set containment.  AgentDojo's
    native ``search_emails`` implementation performs a case-insensitive
    *literal substring* search over each subject and body.  Consequently, a
    plain candidate query which contains the complete granted query denotes a
    subset of the granted result set.  Deleting or reordering granted tokens
    does not provide that guarantee.

    Sender changes are never inferred as safe: the sender selector remains an
    exact authority field.  The native search has no operator grammar, so
    punctuation, boolean-looking words, and wildcard-looking characters remain
    literal text and are safe when the full granted literal is still present.

    The relation is scoped to the exact controlled-read operation and resource;
    no calendar mutation, participant change, other Workspace search, or other
    effect can use it.
    """

    if set(grant_effect) != {"op", "resource", "value"} or set(
        candidate_effect
    ) != {"op", "resource", "value"}:
        return False
    if (
        grant_effect["op"] != "read"
        or candidate_effect["op"] != "read"
        or grant_effect["resource"] != "workspace:email:search"
        or candidate_effect["resource"] != "workspace:email:search"
    ):
        return False
    granted_value = grant_effect["value"]
    candidate_value = candidate_effect["value"]
    if not isinstance(granted_value, Mapping) or not isinstance(
        candidate_value, Mapping
    ):
        return False
    if set(granted_value) != {"query", "sender"} or set(candidate_value) != {
        "query",
        "sender",
    }:
        return False
    granted_query = granted_value["query"]
    candidate_query = candidate_value["query"]
    if not isinstance(granted_query, str) or not isinstance(candidate_query, str):
        return False
    if not granted_query or candidate_value["sender"] != granted_value["sender"]:
        return False
    return granted_query.lower() in candidate_query.lower()


PROFILE: Final[DomainAuthorityProfile] = build_profile(
    domain=DOMAIN,
    tools=WORKSPACE_TOOL_AUTHORITY,
    normalize_authority_args=normalize_workspace_authority_args,
    authority_effect_matcher=workspace_authority_effect_matcher,
)


RUNTIME_ID: Final = "agentdojo-0.1.35-py3123-lock-395e3d0a5921"
RUNTIME_RECEIPT_SHA256: Final = (
    "bb3b21725c80390065b01d64a5a610271f2c6426a106db6de507d7515f6a6e5a"
)
USER_TASK_SOURCE_SHA256: Final = (
    "d2a550b812b7f40ee2dea17ac19d44f2dd063d103524118216b563eca6e44171"
)

_REPO_ROOT = Path(__file__).resolve().parents[4]
_SOURCE_ROOT = _REPO_ROOT / "data/host_boundary_v2/upstream/agentdojo/src"
_RUNTIME_ROOT = _REPO_ROOT / (
    "experiments/host_boundary_v2/runtime_envs/"
    "agentdojo-0.1.35-py3123-lock-395e3d0a5921"
)
_RUNTIME_PYTHON = _RUNTIME_ROOT / "bin/python"
_RUNTIME_RECEIPT = _REPO_ROOT / (
    "experiments/host_boundary_v2/runtime_envs/receipts/"
    "agentdojo-0.1.35-py3123-lock-395e3d0a5921.json"
)
_USER_TASK_SOURCE = _SOURCE_ROOT / (
    "agentdojo/default_suites/v1/workspace/user_tasks.py"
)
_WORKFLOW_BY_SOURCE = {
    row["source_task_id"]: row for row in WORKSPACE_SOURCE_WORKFLOWS
}
_WORKFLOW_BY_SOURCE.update(
    {row["user_task_id"]: row for row in WORKSPACE_SOURCE_WORKFLOWS}
)


class WorkspaceAuthorityError(IntegrityError):
    """Pinned source-authority extraction failed closed."""


def _sha_file(path: Path) -> str:
    if not path.is_file():
        raise WorkspaceAuthorityError(f"required pinned file is missing: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _validate_runtime() -> None:
    if not _RUNTIME_PYTHON.exists():
        raise WorkspaceAuthorityError("pinned AgentDojo interpreter is missing")
    if _sha_file(_RUNTIME_RECEIPT) != RUNTIME_RECEIPT_SHA256:
        raise WorkspaceAuthorityError("pinned AgentDojo runtime receipt differs")
    if _sha_file(_USER_TASK_SOURCE) != USER_TASK_SOURCE_SHA256:
        raise WorkspaceAuthorityError("pinned workspace user-task source differs")
    try:
        receipt = json.loads(_RUNTIME_RECEIPT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkspaceAuthorityError("cannot load runtime receipt") from exc
    if (
        receipt.get("runtime_id") != RUNTIME_ID
        or receipt.get("environment", {}).get("root") != str(_RUNTIME_ROOT)
    ):
        raise WorkspaceAuthorityError("pinned AgentDojo runtime identity differs")


_GROUND_TRUTH_PROGRAM = r'''
import enum
import json
from pathlib import Path
import socket
import sys

request = json.loads(sys.stdin.read())
source_root = Path(request["source_root"]).resolve()
runtime_root = Path(request["runtime_root"]).resolve()
if Path(sys.prefix).resolve() != runtime_root:
    raise RuntimeError("PINNED_RUNTIME_PREFIX_DIFFERS")

network_attempts = 0
def deny_network(*args, **kwargs):
    global network_attempts
    network_attempts += 1
    raise RuntimeError("WORKSPACE_AUTHORITY_NETWORK_FORBIDDEN")

class NetworkDeniedSocket(socket.socket):
    def connect(self, *args, **kwargs):
        return deny_network(*args, **kwargs)
    def connect_ex(self, *args, **kwargs):
        return deny_network(*args, **kwargs)

socket.socket = NetworkDeniedSocket
socket.create_connection = deny_network
socket.getaddrinfo = deny_network
sys.path.insert(0, str(source_root))

from agentdojo.task_suite.load_suites import get_suite

def safe(value):
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, enum.Enum):
        return safe(value.value)
    if isinstance(value, dict):
        result = {str(key): safe(item) for key, item in value.items()}
        for key in ("participants", "recipients", "cc", "bcc"):
            if isinstance(result.get(key), list):
                result[key] = sorted(result[key], key=repr)
        return result
    if isinstance(value, (list, tuple)):
        return [safe(item) for item in value]
    if isinstance(value, set):
        return sorted((safe(item) for item in value), key=repr)
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return safe(model_dump(mode="json"))
    raise RuntimeError("NON_JSON_GROUND_TRUTH_VALUE:" + type(value).__name__)

suite = get_suite("v1", "workspace")
user_task = suite.get_user_task_by_id(request["user_task_id"])
environment = suite.load_and_inject_default_environment({})
environment = user_task.init_environment(environment)
calls = [
    {"function": call.function, "args": safe(dict(call.args))}
    for call in user_task.ground_truth(environment.model_copy(deep=True))
]
result = {
    "user_task_id": user_task.ID,
    "user_prompt": user_task.PROMPT,
    "ground_truth_calls": calls,
    "native_tool_names": sorted(tool.name for tool in suite.tools),
    "injection_inputs": {},
    "network_attempts": network_attempts,
    "model_calls": 0,
    "provider_calls": 0,
    "api_calls": 0,
}
print(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False))
'''


def load_default_ground_truth_calls(
    source_identity: str,
    *,
    timeout_seconds: float = 20.0,
) -> tuple[dict[str, Any], ...]:
    """Load one user task's ground truth from the uninjected pinned runtime."""

    if not isinstance(source_identity, str) or not source_identity:
        raise SchemaError("workspace source identity must be a nonempty string")
    try:
        workflow = _WORKFLOW_BY_SOURCE[source_identity]
    except KeyError as exc:
        raise SchemaError(f"unknown workspace source identity: {source_identity}") from exc
    if not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
        raise SchemaError("timeout_seconds must be positive")
    _validate_runtime()
    request = {
        "source_root": str(_SOURCE_ROOT),
        "runtime_root": str(_RUNTIME_ROOT),
        "user_task_id": workflow["user_task_id"],
    }
    try:
        completed = subprocess.run(
            [str(_RUNTIME_PYTHON), "-I", "-B", "-c", _GROUND_TRUTH_PROGRAM],
            input=json.dumps(request, sort_keys=True, separators=(",", ":")),
            text=True,
            capture_output=True,
            timeout=float(timeout_seconds),
            check=False,
            cwd=str(_REPO_ROOT),
            env={
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise WorkspaceAuthorityError(
            f"native ground-truth extraction failed: {exc}"
        ) from exc
    if completed.returncode != 0:
        raise WorkspaceAuthorityError(
            "native ground-truth extraction failed: "
            + completed.stderr.strip()[-2000:]
        )
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise WorkspaceAuthorityError(
            "native ground-truth extraction returned invalid JSON"
        ) from exc
    if (
        not isinstance(result, dict)
        or result.get("user_task_id") != workflow["user_task_id"]
        or result.get("injection_inputs") != {}
        or result.get("network_attempts") != 0
        or result.get("model_calls") != 0
        or result.get("provider_calls") != 0
        or result.get("api_calls") != 0
        or not isinstance(result.get("ground_truth_calls"), list)
        or not isinstance(result.get("native_tool_names"), list)
    ):
        raise WorkspaceAuthorityError("native ground-truth extraction differs")
    validate_native_tool_coverage(PROFILE, result["native_tool_names"])
    calls = tuple(copy.deepcopy(result["ground_truth_calls"]))
    canonical_json_bytes(list(calls))
    return calls


def build_workspace_authority_grant(
    source_identity: str,
    *,
    timeout_seconds: float = 20.0,
) -> AuthorityGrant:
    """Build one condition-blind grant from uninjected native user ground truth."""

    try:
        workflow = _WORKFLOW_BY_SOURCE[source_identity]
    except KeyError as exc:
        raise SchemaError(f"unknown workspace source identity: {source_identity}") from exc
    calls = load_default_ground_truth_calls(
        source_identity, timeout_seconds=timeout_seconds
    )
    return build_authority_grant(
        PROFILE,
        source_task_id=workflow["source_task_id"],
        ground_truth_calls=calls,
    )


def build_workspace_authority_grants(
    source_identities: Iterable[str] | None = None,
    *,
    timeout_seconds: float = 20.0,
) -> tuple[AuthorityGrant, ...]:
    """Build the stable three-workflow authority bank in selector order."""

    identities = (
        [row["source_task_id"] for row in WORKSPACE_SOURCE_WORKFLOWS]
        if source_identities is None
        else list(source_identities)
    )
    if not identities or len(set(identities)) != len(identities):
        raise SchemaError("workspace authority selection must be nonempty and unique")
    return tuple(
        build_workspace_authority_grant(
            identity, timeout_seconds=timeout_seconds
        )
        for identity in identities
    )


def authorize_workspace_action(
    grant: AuthorityGrant,
    action: Mapping[str, Any],
    *,
    consumed_grant_indexes: Iterable[int] = (),
) -> AuthorityDecision:
    """Decide one proposed workspace call against one reset-time grant."""

    return decide_authority(
        PROFILE,
        grant,
        action=action,
        consumed_grant_indexes=tuple(consumed_grant_indexes),
    )


__all__ = [
    "DOMAIN",
    "PROFILE",
    "RUNTIME_ID",
    "USER_TASK_SOURCE_SHA256",
    "WORKSPACE_SOURCE_WORKFLOWS",
    "WORKSPACE_TOOL_AUTHORITY",
    "WorkspaceAuthorityError",
    "authorize_workspace_action",
    "build_workspace_authority_grant",
    "build_workspace_authority_grants",
    "load_default_ground_truth_calls",
    "normalize_workspace_authority_args",
    "workspace_authority_effect_matcher",
]
