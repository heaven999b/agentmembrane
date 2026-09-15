"""Source-authority profile for the pinned AgentDojo banking suite.

Every native suite-v1 banking tool is classified.  All banking reads expose a
file, account, transaction collection, or user profile, so none is treated as
unrestricted metadata.  Controlled grants are derived only from the selected
user task's ground-truth calls in a freshly loaded default environment.

Transfer memo/date fields are deliberately outside the authority projection:
they do not select a recipient, amount, recurring capability, record, or user
field.  Changing them therefore does not manufacture a new authority target.
"""

from __future__ import annotations

from typing import Any, Final, Mapping, Sequence

from .core import (
    AuthorityContractError,
    AuthorityDecision,
    AuthorityGrant,
    DomainAuthorityProfile,
    build_profile,
    validate_native_tool_coverage,
)


DOMAIN: Final = "banking"

BANKING_SOURCE_WORKFLOWS: Final = (
    {
        "source_task_id": "agentdojo-v1-banking-u0-i5",
        "user_task_id": "user_task_0",
    },
    {
        "source_task_id": "agentdojo-v1-banking-u2-i4",
        "user_task_id": "user_task_2",
    },
    {
        "source_task_id": "agentdojo-v1-banking-u3-i1",
        "user_task_id": "user_task_3",
    },
)


# The mapping is exhaustive over task_suite.TOOLS.  ``authority_fields`` are
# values that change the permission-bearing target/scope.  Other native schema
# fields remain runtime-validated but do not alter the authority grant.
BANKING_TOOL_AUTHORITY: Final = {
    "get_iban": {
        "mode": "controlled_read",
        "effect_op": "read",
        "resource": "bank:current_account_iban",
        "authority_fields": (),
    },
    "send_money": {
        "mode": "controlled_mutation",
        "effect_op": "create",
        "resource": "bank:outgoing_transfer",
        "authority_fields": ("recipient", "amount"),
    },
    "schedule_transaction": {
        "mode": "controlled_mutation",
        "effect_op": "create",
        "resource": "bank:scheduled_transfer",
        "authority_fields": ("recipient", "amount", "recurring"),
    },
    "update_scheduled_transaction": {
        "mode": "controlled_mutation",
        "effect_op": "update",
        "resource": "bank:scheduled_transfer",
        "authority_fields": ("id", "recipient", "amount", "recurring"),
    },
    "get_balance": {
        "mode": "controlled_read",
        "effect_op": "read",
        "resource": "bank:current_account_balance",
        "authority_fields": (),
    },
    "get_most_recent_transactions": {
        "mode": "controlled_read",
        "effect_op": "read",
        "resource": "bank:transaction_history",
        "authority_fields": ("n",),
    },
    "get_scheduled_transactions": {
        "mode": "controlled_read",
        "effect_op": "read",
        "resource": "bank:scheduled_transfers",
        "authority_fields": (),
    },
    "read_file": {
        "mode": "controlled_read",
        "effect_op": "read",
        "resource": "filesystem:file",
        "authority_fields": ("file_path",),
    },
    "get_user_info": {
        "mode": "controlled_read",
        "effect_op": "read",
        "resource": "user:profile",
        "authority_fields": (),
    },
    "update_password": {
        "mode": "controlled_mutation",
        "effect_op": "update",
        "resource": "user:password",
        "authority_fields": ("password",),
    },
    "update_user_info": {
        "mode": "controlled_mutation",
        "effect_op": "update",
        "resource": "user:profile",
        "authority_fields": ("first_name", "last_name", "street", "city"),
    },
}


def normalize_banking_authority_args(
    function: str,
    args: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Canonicalize only native-equivalent banking authority arguments.

    The transaction-history tool defaults an omitted ``n`` to 100.  A request
    for any positive sub-window of that authorized 100-row window cannot widen
    read authority, so it is projected to the same canonical window.  Invalid
    values fail closed before matching.  Native optional update arguments set
    to ``None`` have the same effect as omission and are removed; non-null
    permission-bearing values remain exact.
    """

    if not isinstance(function, str) or not isinstance(args, Mapping):
        raise AuthorityContractError("banking authority normalizer input is invalid")
    if any(not isinstance(key, str) for key in args):
        raise AuthorityContractError("banking authority argument keys must be strings")
    normalized = dict(args)
    if function == "get_most_recent_transactions":
        n = normalized.get("n", 100)
        if type(n) is not int or not 1 <= n <= 100:
            raise AuthorityContractError(
                "banking transaction-history window must be an integer from 1 to 100"
            )
        normalized["n"] = 100
    elif function == "update_scheduled_transaction":
        for field in ("recipient", "amount", "recurring"):
            if normalized.get(field) is None:
                normalized.pop(field, None)
    elif function == "update_user_info":
        for field in ("first_name", "last_name", "street", "city"):
            if normalized.get(field) is None:
                normalized.pop(field, None)
    return normalized


PROFILE: Final[DomainAuthorityProfile] = build_profile(
    domain=DOMAIN,
    tools=BANKING_TOOL_AUTHORITY,
    normalize_authority_args=normalize_banking_authority_args,
)


def _suite_from_active(active_or_suite: Any) -> Any:
    suite = getattr(active_or_suite, "suite", active_or_suite)
    if getattr(suite, "name", None) != DOMAIN:
        raise ValueError("banking authority requires the native banking suite")
    tools = getattr(suite, "tools", None)
    if not isinstance(tools, Sequence) or isinstance(tools, (str, bytes)):
        raise TypeError("native banking suite tools are unavailable")
    names = []
    for tool in tools:
        name = getattr(tool, "name", None)
        if not isinstance(name, str) or not name:
            raise TypeError("native banking suite contains an invalid tool")
        names.append(name)
    validate_native_tool_coverage(PROFILE, names)
    return suite


def _clean_source_task_id(user_task: Any) -> str:
    user_task_id = getattr(user_task, "ID", None)
    if not isinstance(user_task_id, str) or not user_task_id:
        raise TypeError("native banking user task has no stable ID")
    return f"agentdojo:v1:banking:{user_task_id}"


def build_banking_authority(
    active_or_suite: Any,
    user_task: Any,
) -> AuthorityGrant:
    """Build reset-time grants from the native user's default ground truth.

    The environment is always freshly loaded with an empty overlay mapping;
    an active episode's current environment and trace are intentionally ignored.
    The returned grant stores stable projections/hashes produced by the shared
    core and contains no experimental condition coordinate.
    """

    suite = _suite_from_active(active_or_suite)
    user_task_id = getattr(user_task, "ID", None)
    task_getter = getattr(suite, "get_user_task_by_id", None)
    if not isinstance(user_task_id, str) or not callable(task_getter):
        raise TypeError("native banking user-task binding is unavailable")
    try:
        registered_user_task = task_getter(user_task_id)
    except Exception as exc:
        raise ValueError("banking user task is not registered by the native suite") from exc
    if type(registered_user_task) is not type(user_task):
        raise ValueError("banking user task differs from the native suite registration")
    loader = getattr(suite, "load_and_inject_default_environment", None)
    initializer = getattr(user_task, "init_environment", None)
    ground_truth = getattr(user_task, "ground_truth", None)
    if not callable(loader) or not callable(initializer) or not callable(ground_truth):
        raise TypeError("native banking reset-time authority inputs are unavailable")
    environment = initializer(loader({}))
    copier = getattr(environment, "model_copy", None)
    if not callable(copier):
        raise TypeError("native banking environment cannot be copied")
    pre_environment = copier(deep=True)
    calls = ground_truth(pre_environment)
    if not isinstance(calls, Sequence) or isinstance(calls, (str, bytes)):
        raise TypeError("native banking user ground truth is not an action sequence")
    return PROFILE.grants_from_ground_truth(
        _clean_source_task_id(user_task),
        tuple(calls),
    )


def decide_banking(
    grant: AuthorityGrant,
    action: Any,
    *,
    consumed_grant_indexes: Sequence[int] = (),
) -> AuthorityDecision:
    """Decide one native call against the reset-time banking grant."""

    return PROFILE.authorize(
        grant,
        action,
        consumed_grant_indexes=tuple(consumed_grant_indexes),
    )


__all__ = [
    "BANKING_SOURCE_WORKFLOWS",
    "BANKING_TOOL_AUTHORITY",
    "DOMAIN",
    "PROFILE",
    "build_banking_authority",
    "decide_banking",
    "normalize_banking_authority_args",
]
