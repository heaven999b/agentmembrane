"""Shared static authority grants for the multi-domain AgentDojo runtime.

Authority is derived exclusively from a user task's upstream ground-truth calls
in a no-injection environment.  Candidate admission never executes the call
and never consults an injection task or security checker.  Domain profiles
classify every native operation as explicit unrestricted metadata,
authority-controlled read, or authority-controlled mutation.
"""

from __future__ import annotations

import copy
import inspect
from dataclasses import dataclass, field
from typing import Any, Callable, Literal, Mapping, Sequence

from ...schema import SchemaError, canonical_json_bytes, sha256_json


AuthorityMode = Literal[
    "unrestricted", "controlled_read", "controlled_mutation"
]
AuthorityArgsNormalizer = Callable[[str, Mapping[str, Any]], Mapping[str, Any]]
AuthorityEffectMatcher = Callable[
    [Mapping[str, Any], Mapping[str, Any]], bool
]
_MODES = frozenset(
    {"unrestricted", "controlled_read", "controlled_mutation"}
)


class AuthorityContractError(SchemaError):
    """A profile, grant, or action violates the static authority contract."""


def _json_value(value: Any) -> Any:
    if hasattr(value, "model_dump") and callable(value.model_dump):
        try:
            return _json_value(value.model_dump(mode="json"))
        except TypeError:
            return _json_value(value.model_dump())
    if value is None or isinstance(value, (str, bool, int, float)):
        canonical_json_bytes(value)
        return value
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise AuthorityContractError("authority mapping keys must be strings")
        result = {key: _json_value(item) for key, item in value.items()}
        canonical_json_bytes(result)
        return result
    if isinstance(value, (list, tuple)):
        result = [_json_value(item) for item in value]
        # Authority-bearing identity collections (recipients, participants,
        # hotel names, and similar native arguments) are set-like.  Canonical
        # JSON ordering lets an ordinary agent choose a semantically equivalent
        # order without broadening the granted identities.
        result.sort(key=canonical_json_bytes)
        canonical_json_bytes(result)
        return result
    raise AuthorityContractError(
        f"authority value is not strict JSON: {type(value).__name__}"
    )


@dataclass(frozen=True)
class ToolAuthority:
    function: str
    mode: AuthorityMode
    effect_op: str
    resource: str
    authority_fields: tuple[str, ...]

    def as_json(self) -> dict[str, Any]:
        return {
            "function": self.function,
            "mode": self.mode,
            "effect_op": self.effect_op,
            "resource": self.resource,
            "authority_fields": list(self.authority_fields),
        }


@dataclass(frozen=True)
class AuthorityGrant:
    domain: str
    source_task_id: str
    profile_sha256: str
    entries: tuple[Mapping[str, Any], ...]
    grant_sha256: str

    def as_json(self) -> dict[str, Any]:
        value = {
            "schema_version": 1,
            "artifact_type": "agentdojo_user_authority_grant_v1",
            "domain": self.domain,
            "source_task_id": self.source_task_id,
            "profile_sha256": self.profile_sha256,
            "source_kind": "user_task_ground_truth_no_injection",
            "entries": [copy.deepcopy(dict(row)) for row in self.entries],
        }
        if sha256_json(value) != self.grant_sha256:
            raise AuthorityContractError("authority grant bytes drifted")
        value["grant_sha256"] = self.grant_sha256
        return value


@dataclass(frozen=True)
class AuthorityDecision:
    within_authority: bool
    reason: str
    projection: Mapping[str, Any] | None
    matched_grant_index: int | None
    consumes_grant: bool
    decision_sha256: str

    def as_json(self) -> dict[str, Any]:
        value = {
            "schema_version": 1,
            "within_authority": self.within_authority,
            "reason": self.reason,
            "projection": (
                copy.deepcopy(dict(self.projection))
                if self.projection is not None
                else None
            ),
            "matched_grant_index": self.matched_grant_index,
            "consumes_grant": self.consumes_grant,
        }
        if sha256_json(value) != self.decision_sha256:
            raise AuthorityContractError("authority decision bytes drifted")
        value["decision_sha256"] = self.decision_sha256
        return value


@dataclass(frozen=True)
class DomainAuthorityProfile:
    domain: str
    tools: tuple[ToolAuthority, ...]
    profile_sha256: str
    authority_args_normalizer_binding: Mapping[str, str] | None = None
    authority_effect_matcher_binding: Mapping[str, str] | None = None
    normalize_authority_args: AuthorityArgsNormalizer | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    authority_effect_matcher: AuthorityEffectMatcher | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    def as_json(self) -> dict[str, Any]:
        value = {
            "schema_version": 1,
            "artifact_type": "agentdojo_domain_authority_profile_v1",
            "domain": self.domain,
            "scope": "native_operation_resource_and_authority_fields",
            "tools": [row.as_json() for row in self.tools],
        }
        if self.authority_args_normalizer_binding is not None:
            value["authority_args_normalizer"] = copy.deepcopy(
                dict(self.authority_args_normalizer_binding)
            )
        if self.authority_effect_matcher_binding is not None:
            value["authority_effect_matcher"] = copy.deepcopy(
                dict(self.authority_effect_matcher_binding)
            )
        if sha256_json(value) != self.profile_sha256:
            raise AuthorityContractError("domain authority profile bytes drifted")
        value["profile_sha256"] = self.profile_sha256
        return value

    def tool(self, function: str) -> ToolAuthority | None:
        for row in self.tools:
            if row.function == function:
                return row
        return None

    def project(
        self, action: Mapping[str, Any], provenance: Mapping[str, Any]
    ) -> dict[str, Any] | None:
        return project_action(self, action=action, provenance=provenance)

    def grants_from_ground_truth(
        self, source_task_id: str, calls: Sequence[Any]
    ) -> AuthorityGrant:
        return build_authority_grant(
            self,
            source_task_id=source_task_id,
            ground_truth_calls=calls,
        )

    def authorize(
        self,
        grant: AuthorityGrant,
        action: Mapping[str, Any],
        consumed_grant_indexes: Sequence[int] = (),
    ) -> AuthorityDecision:
        return decide_authority(
            self,
            grant,
            action=action,
            consumed_grant_indexes=consumed_grant_indexes,
        )


def build_profile(
    domain: str,
    tools: Mapping[str, Mapping[str, Any]] | Sequence[Mapping[str, Any]],
    *,
    normalize_authority_args: AuthorityArgsNormalizer | None = None,
    authority_effect_matcher: AuthorityEffectMatcher | None = None,
) -> DomainAuthorityProfile:
    """Build one canonical, exhaustive domain classification.

    A domain may register one module-level, pure static argument normalizer for
    native-equivalent parameter spellings/defaults.  It runs before authority
    fields are projected.  It may also register one module-level, pure effect
    relation matcher for narrowly accepting a candidate effect contained by a
    ground-truth grant.  Hook callable identities and complete implementation
    source are bound into the profile; profiles without hooks retain strict
    identity behavior.
    """

    if not isinstance(domain, str) or not domain:
        raise AuthorityContractError("authority profile domain must be nonempty")
    raw_rows: list[dict[str, Any]] = []
    if isinstance(tools, Mapping):
        for function, raw in tools.items():
            if not isinstance(function, str) or not isinstance(raw, Mapping):
                raise AuthorityContractError("authority tool mapping is invalid")
            row = dict(raw)
            supplied = row.pop("function", function)
            if supplied != function:
                raise AuthorityContractError("authority tool function key differs")
            row["function"] = function
            raw_rows.append(row)
    elif not isinstance(tools, (str, bytes, bytearray)):
        for raw in tools:
            if not isinstance(raw, Mapping):
                raise AuthorityContractError("authority tool row must be an object")
            raw_rows.append(dict(raw))
    else:
        raise AuthorityContractError("authority tools must be rows or a mapping")
    parsed: list[ToolAuthority] = []
    seen: set[str] = set()
    for raw in raw_rows:
        if set(raw) != {
            "function",
            "mode",
            "effect_op",
            "resource",
            "authority_fields",
        }:
            raise AuthorityContractError("authority tool row fields differ")
        function = raw["function"]
        mode = raw["mode"]
        effect_op = raw["effect_op"]
        resource = raw["resource"]
        fields = raw["authority_fields"]
        if (
            not isinstance(function, str)
            or not function
            or function in seen
            or mode not in _MODES
            or not isinstance(effect_op, str)
            or not effect_op
            or not isinstance(resource, str)
            or not resource
            or isinstance(fields, (str, bytes, bytearray))
        ):
            raise AuthorityContractError("authority tool row values are invalid")
        field_tuple = tuple(fields)
        if (
            any(not isinstance(field, str) or not field for field in field_tuple)
            or len(set(field_tuple)) != len(field_tuple)
            or (mode == "unrestricted" and field_tuple)
        ):
            raise AuthorityContractError("authority fields are invalid")
        parsed.append(
            ToolAuthority(
                function=function,
                mode=mode,
                effect_op=effect_op,
                resource=resource,
                authority_fields=field_tuple,
            )
        )
        seen.add(function)
    if not parsed:
        raise AuthorityContractError("authority profile must classify tools")
    parsed.sort(key=lambda row: row.function)
    normalizer_binding = _bind_authority_args_normalizer(
        normalize_authority_args
    )
    effect_matcher_binding = _bind_authority_effect_matcher(
        authority_effect_matcher
    )
    base = {
        "schema_version": 1,
        "artifact_type": "agentdojo_domain_authority_profile_v1",
        "domain": domain,
        "scope": "native_operation_resource_and_authority_fields",
        "tools": [row.as_json() for row in parsed],
    }
    if normalizer_binding is not None:
        base["authority_args_normalizer"] = copy.deepcopy(
            normalizer_binding
        )
    if effect_matcher_binding is not None:
        base["authority_effect_matcher"] = copy.deepcopy(
            effect_matcher_binding
        )
    profile = DomainAuthorityProfile(
        domain=domain,
        tools=tuple(parsed),
        profile_sha256=sha256_json(base),
        authority_args_normalizer_binding=(
            copy.deepcopy(normalizer_binding)
            if normalizer_binding is not None
            else None
        ),
        authority_effect_matcher_binding=(
            copy.deepcopy(effect_matcher_binding)
            if effect_matcher_binding is not None
            else None
        ),
        normalize_authority_args=normalize_authority_args,
        authority_effect_matcher=authority_effect_matcher,
    )
    profile.as_json()
    return profile


def validate_native_tool_coverage(
    profile: DomainAuthorityProfile, native_tool_names: Sequence[str]
) -> None:
    if not isinstance(profile, DomainAuthorityProfile):
        raise TypeError("profile must be DomainAuthorityProfile")
    native = tuple(native_tool_names)
    if any(not isinstance(name, str) or not name for name in native):
        raise AuthorityContractError("native tool names are invalid")
    classified = {row.function for row in profile.tools}
    if len(set(native)) != len(native) or classified != set(native):
        raise AuthorityContractError(
            "domain authority profile does not exhaust the native tool surface"
        )


def _action_parts(action: Any) -> tuple[str, dict[str, Any]]:
    if isinstance(action, Mapping):
        function = action.get("function", action.get("name"))
        args = action.get("args", action.get("arguments"))
    else:
        function = getattr(action, "function", None)
        args = getattr(action, "args", None)
    if not isinstance(function, str) or not function:
        raise AuthorityContractError("authority action function is invalid")
    if not isinstance(args, Mapping) or any(not isinstance(key, str) for key in args):
        raise AuthorityContractError("authority action args are invalid")
    return function, _json_value(args)


def _bind_authority_args_normalizer(
    normalizer: AuthorityArgsNormalizer | None,
) -> dict[str, str] | None:
    if normalizer is None:
        return None
    if not inspect.isfunction(normalizer):
        raise AuthorityContractError(
            "authority argument normalizer must be a module-level function"
        )
    module = getattr(normalizer, "__module__", None)
    qualname = getattr(normalizer, "__qualname__", None)
    if (
        not isinstance(module, str)
        or not module
        or not isinstance(qualname, str)
        or not qualname
        or "<locals>" in qualname
    ):
        raise AuthorityContractError(
            "authority argument normalizer must be a module-level function"
        )
    try:
        source = inspect.getsource(normalizer)
    except (OSError, TypeError) as exc:
        raise AuthorityContractError(
            "authority argument normalizer source is unavailable"
        ) from exc
    return {
        "callable": f"{module}:{qualname}",
        "implementation_sha256": sha256_json(
            {
                "artifact_type": "authority_args_normalizer_python_source_v1",
                "source": source,
            }
        ),
    }


def _bind_authority_effect_matcher(
    matcher: AuthorityEffectMatcher | None,
) -> dict[str, str] | None:
    if matcher is None:
        return None
    if not inspect.isfunction(matcher):
        raise AuthorityContractError(
            "authority effect matcher must be a module-level function"
        )
    module = getattr(matcher, "__module__", None)
    qualname = getattr(matcher, "__qualname__", None)
    if (
        not isinstance(module, str)
        or not module
        or not isinstance(qualname, str)
        or not qualname
        or "<locals>" in qualname
    ):
        raise AuthorityContractError(
            "authority effect matcher must be a module-level function"
        )
    try:
        source = inspect.getsource(matcher)
    except (OSError, TypeError) as exc:
        raise AuthorityContractError(
            "authority effect matcher source is unavailable"
        ) from exc
    return {
        "callable": f"{module}:{qualname}",
        "implementation_sha256": sha256_json(
            {
                "artifact_type": "authority_effect_matcher_python_source_v1",
                "source": source,
            }
        ),
    }


def _normalized_action_args(
    profile: DomainAuthorityProfile,
    *,
    function: str,
    args: Mapping[str, Any],
) -> dict[str, Any]:
    normalizer = profile.normalize_authority_args
    binding = profile.authority_args_normalizer_binding
    if normalizer is None:
        if binding is not None:
            raise AuthorityContractError(
                "authority argument normalizer binding has no callable"
            )
        return copy.deepcopy(dict(args))
    if binding is None:
        raise AuthorityContractError(
            "authority argument normalizer callable has no profile binding"
        )

    # The hook sees only a function name and a mutation-isolated strict-JSON
    # mapping.  Running it twice rejects stateful/nondeterministic policy code;
    # no environment, task, trace, preview, or checker is available here.
    outputs: list[dict[str, Any]] = []
    for _ in range(2):
        hook_input = copy.deepcopy(dict(args))
        try:
            raw_output = normalizer(function, hook_input)
        except Exception as exc:
            raise AuthorityContractError(
                "authority argument normalizer failed closed"
            ) from exc
        if not isinstance(raw_output, Mapping):
            raise AuthorityContractError(
                "authority argument normalizer must return a mapping"
            )
        normalized = _json_value(raw_output)
        if not isinstance(normalized, dict):
            raise AuthorityContractError(
                "authority argument normalizer must return a JSON object"
            )
        outputs.append(normalized)
    if outputs[0] != outputs[1]:
        raise AuthorityContractError(
            "authority argument normalizer is nondeterministic"
        )
    return copy.deepcopy(outputs[0])


def project_action(
    profile: DomainAuthorityProfile,
    *,
    action: Any,
    provenance: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Project only canonical op/resource/authority values and provenance."""

    function, args = _action_parts(action)
    tool = profile.tool(function)
    if tool is None:
        return None
    args = _normalized_action_args(
        profile,
        function=function,
        args=args,
    )
    value = {
        field: copy.deepcopy(args[field])
        for field in tool.authority_fields
        if field in args
    }
    safe_provenance = _json_value(provenance)
    if not isinstance(safe_provenance, dict):
        raise AuthorityContractError("authority provenance must be an object")
    if profile.normalize_authority_args is not None:
        assert profile.authority_args_normalizer_binding is not None
        safe_provenance["authority_args_normalizer"] = copy.deepcopy(
            dict(profile.authority_args_normalizer_binding)
        )
        # Bind only the canonical authority-bearing value.  Ordinary native
        # arguments such as wording, date, subject, and body remain outside
        # the authority projection and therefore cannot perturb its bytes.
        safe_provenance["normalized_authority_value_sha256"] = sha256_json(
            {
                "artifact_type": "normalized_authority_value_v1",
                "normalizer": copy.deepcopy(
                    dict(profile.authority_args_normalizer_binding)
                ),
                "value": value,
            }
        )
    projection = {
        "op": tool.effect_op,
        "resource": tool.resource,
        "value": value,
        "authority_provenance": safe_provenance,
    }
    canonical_json_bytes(projection)
    return projection


def build_authority_grant(
    profile: DomainAuthorityProfile,
    *,
    source_task_id: str,
    ground_truth_calls: Sequence[Any],
) -> AuthorityGrant:
    """Freeze controlled ground-truth effects from a no-injection environment."""

    if not isinstance(profile, DomainAuthorityProfile):
        raise TypeError("profile must be DomainAuthorityProfile")
    if not isinstance(source_task_id, str) or not source_task_id:
        raise AuthorityContractError("grant source_task_id must be nonempty")
    if isinstance(ground_truth_calls, (str, bytes, bytearray)):
        raise AuthorityContractError("ground_truth_calls must be a sequence")
    entries: list[dict[str, Any]] = []
    for index, call in enumerate(ground_truth_calls):
        function, _args = _action_parts(call)
        tool = profile.tool(function)
        if tool is None:
            raise AuthorityContractError(
                "ground truth uses a tool absent from the authority profile"
            )
        if tool.mode == "unrestricted":
            continue
        projection = project_action(
            profile,
            action=call,
            provenance={
                "source_kind": "user_task_ground_truth_no_injection",
                "source_task_id": source_task_id,
                "domain": profile.domain,
                "profile_sha256": profile.profile_sha256,
                "ground_truth_call_index": index,
            },
        )
        assert projection is not None
        entries.append(projection)
    base = {
        "schema_version": 1,
        "artifact_type": "agentdojo_user_authority_grant_v1",
        "domain": profile.domain,
        "source_task_id": source_task_id,
        "profile_sha256": profile.profile_sha256,
        "source_kind": "user_task_ground_truth_no_injection",
        "entries": entries,
    }
    grant = AuthorityGrant(
        domain=profile.domain,
        source_task_id=source_task_id,
        profile_sha256=profile.profile_sha256,
        entries=tuple(copy.deepcopy(entries)),
        grant_sha256=sha256_json(base),
    )
    grant.as_json()
    return grant


def _projection_effect(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "op": copy.deepcopy(value["op"]),
        "resource": copy.deepcopy(value["resource"]),
        "value": copy.deepcopy(value["value"]),
    }


def _matches_authority_effect_relation(
    profile: DomainAuthorityProfile,
    *,
    grant_effect: Mapping[str, Any],
    candidate_effect: Mapping[str, Any],
) -> bool | None:
    """Return the stable relation result, or ``None`` to fail closed."""

    matcher = profile.authority_effect_matcher
    binding = profile.authority_effect_matcher_binding
    if matcher is None or binding is None:
        return None

    # Each invocation receives fresh, strict-JSON effect copies.  The hook has
    # no environment, task, trace, preview, checker, or provenance input.
    results: list[bool] = []
    for _ in range(2):
        try:
            isolated_grant = _json_value(copy.deepcopy(dict(grant_effect)))
            isolated_candidate = _json_value(
                copy.deepcopy(dict(candidate_effect))
            )
            if not isinstance(isolated_grant, dict) or not isinstance(
                isolated_candidate, dict
            ):
                return None
            raw_result = matcher(isolated_grant, isolated_candidate)
        except Exception:
            return None
        if type(raw_result) is not bool:
            return None
        results.append(raw_result)
    if results[0] != results[1]:
        return None
    return results[0]


def decide_authority(
    profile: DomainAuthorityProfile,
    grant: AuthorityGrant,
    *,
    action: Mapping[str, Any],
    consumed_grant_indexes: Sequence[int] = (),
) -> AuthorityDecision:
    """Decide statically; never dispatch, preview, or invoke a checker."""

    if not isinstance(profile, DomainAuthorityProfile):
        raise TypeError("profile must be DomainAuthorityProfile")
    if not isinstance(grant, AuthorityGrant):
        raise TypeError("grant must be AuthorityGrant")
    if (
        grant.domain != profile.domain
        or grant.profile_sha256 != profile.profile_sha256
    ):
        raise AuthorityContractError("grant/profile binding differs")
    consumed = tuple(consumed_grant_indexes)
    if any(
        not isinstance(index, int)
        or isinstance(index, bool)
        or index < 0
        or index >= len(grant.entries)
        for index in consumed
    ) or len(set(consumed)) != len(consumed):
        raise AuthorityContractError("consumed grant indexes are invalid")
    function, _args = _action_parts(action)
    tool = profile.tool(function)
    projection = project_action(
        profile,
        action=action,
        provenance={
            "source_kind": "candidate_native_action",
            "source_task_id": grant.source_task_id,
            "domain": profile.domain,
            "profile_sha256": profile.profile_sha256,
        },
    )
    matched: int | None = None
    consumes_grant = False
    if tool is None:
        within = False
        reason = "operation_unclassified"
    elif tool.mode == "unrestricted":
        within = True
        reason = "explicit_unrestricted_metadata"
    else:
        assert projection is not None
        candidate_effect = _projection_effect(projection)
        # Exact identity always has precedence and never invokes the optional
        # relation hook, even if an earlier grant row is relation-compatible.
        for index, entry in enumerate(grant.entries):
            if index not in consumed and _projection_effect(entry) == candidate_effect:
                matched = index
                break
        relation_matched = False
        relation_failed_closed = False
        matcher = profile.authority_effect_matcher
        matcher_binding = profile.authority_effect_matcher_binding
        if matched is None and matcher is not None and matcher_binding is not None:
            for index, entry in enumerate(grant.entries):
                if index in consumed:
                    continue
                grant_effect = _projection_effect(entry)
                if (
                    grant_effect["op"] != candidate_effect["op"]
                    or grant_effect["resource"]
                    != candidate_effect["resource"]
                ):
                    continue
                relation_result = _matches_authority_effect_relation(
                    profile,
                    grant_effect=grant_effect,
                    candidate_effect=candidate_effect,
                )
                if relation_result is None:
                    relation_failed_closed = True
                    break
                if relation_result:
                    matched = index
                    relation_matched = True
                    break
        elif matched is None and (
            matcher is not None or matcher_binding is not None
        ):
            # A malformed in-memory profile with only one half of the bound
            # hook pair must never broaden authority.
            relation_failed_closed = True
        within = matched is not None
        if relation_failed_closed:
            matched = None
            within = False
            relation_matched = False
        consumes_grant = bool(
            within and tool.mode == "controlled_mutation"
        )
        reason = (
            "authority_grant_relation_match"
            if relation_matched
            else (
                "authority_grant_match"
                if within
                else "no_matching_user_authority_grant"
            )
        )
    base = {
        "schema_version": 1,
        "within_authority": within,
        "reason": reason,
        "projection": copy.deepcopy(projection),
        "matched_grant_index": matched,
        "consumes_grant": consumes_grant,
    }
    decision = AuthorityDecision(
        within_authority=within,
        reason=reason,
        projection=(copy.deepcopy(projection) if projection is not None else None),
        matched_grant_index=matched,
        consumes_grant=consumes_grant,
        decision_sha256=sha256_json(base),
    )
    decision.as_json()
    return decision


def load_domain_profile(domain: str) -> DomainAuthorityProfile:
    """Load one of the four RQ1-owned exhaustive domain profiles."""

    if domain not in {"banking", "slack", "travel", "workspace"}:
        raise AuthorityContractError(f"unsupported authority domain: {domain!r}")
    module_name = f"{__package__}.{domain}"
    try:
        module = __import__(module_name, fromlist=["PROFILE"])
        profile = getattr(module, "PROFILE")
    except Exception as exc:
        raise AuthorityContractError(
            f"authority profile is unavailable for {domain}"
        ) from exc
    if not isinstance(profile, DomainAuthorityProfile) or profile.domain != domain:
        raise AuthorityContractError("loaded domain authority profile is invalid")
    return profile


__all__ = [
    "AuthorityArgsNormalizer",
    "AuthorityContractError",
    "AuthorityDecision",
    "AuthorityEffectMatcher",
    "AuthorityGrant",
    "AuthorityMode",
    "DomainAuthorityProfile",
    "ToolAuthority",
    "build_authority_grant",
    "build_profile",
    "decide_authority",
    "load_domain_profile",
    "project_action",
    "validate_native_tool_coverage",
]
