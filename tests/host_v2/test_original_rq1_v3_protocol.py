from __future__ import annotations

import copy
import json
from typing import Any, Mapping

import pytest

from agentmembrane.host_v2.original_rq1_v3_protocol import (
    DeliveryState,
    EpisodeRole,
    NATIVE_PROTOCOL_VERSION,
    NativeEpisodeDriver,
    NativeProtocolProfile,
    OutcomeClass,
    PrivateExperimentFieldError,
    ProtocolContractError,
    ProviderCallError,
    ProviderReply,
    RequestContext,
    build_condition_blind_request,
    parse_native_turn,
)
from agentmembrane.host_v2.schema import sha256_bytes, sha256_json


def profile(
    *, seed_support: str = "unsupported", retries: int = 0
) -> NativeProtocolProfile:
    return NativeProtocolProfile(
        requested_model_id="model-exact",
        allowed_resolved_model_ids=("model-exact",),
        provider_route_id="provider-route",
        provider_api_version="2026-01-01",
        reasoning_effort="low",
        generation_seed_support=seed_support,
        transport_retry_budget=retries,
    )


def context(
    *,
    episode_id: str = "0" * 64,
    replicate_id: str = "r1",
    generation_seed: int | None = None,
) -> RequestContext:
    return RequestContext(
        episode_id=episode_id,
        turn_number=1,
        replicate_id=replicate_id,
        schedule_seed=7001,
        generation_seed=generation_seed,
        schedule_binding_sha256="0" * 64,
    )


def tools() -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": "read_resource",
                "description": "Read one named public resource.",
                "parameters": {
                    "type": "object",
                    "properties": {"resource": {"type": "string"}},
                    "required": ["resource"],
                },
            },
        }
    ]


def final_response(text: str = "done") -> dict[str, Any]:
    return {
        "model": "model-exact",
        "choices": [{"finish_reason": "stop", "message": {"content": text}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12},
    }


def tool_response(
    *, name: str = "read_resource", arguments: str = '{"resource":"guide"}'
) -> dict[str, Any]:
    return {
        "model": "model-exact",
        "choices": [
            {
                "finish_reason": "tool_calls",
                "message": {
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call-1",
                            "type": "function",
                            "function": {"name": name, "arguments": arguments},
                        }
                    ],
                },
            }
        ],
    }


def provider_reply(
    response: Any,
    *,
    provider_request_id: str | None = None,
    generation_seed_receipt: int | None = None,
) -> ProviderReply:
    return ProviderReply(
        response=response,
        raw_response_bytes=json.dumps(
            response, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8"),
        provider_request_id=provider_request_id,
        generation_seed_receipt=generation_seed_receipt,
    )


class FakeProvider:
    def __init__(self, outcomes: list[Any]) -> None:
        self.outcomes = list(outcomes)
        self.calls: list[tuple[dict[str, Any], str]] = []

    def complete(
        self, payload: Mapping[str, Any], *, idempotency_key: str
    ) -> ProviderReply:
        self.calls.append((copy.deepcopy(dict(payload)), idempotency_key))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        if isinstance(outcome, ProviderReply):
            return outcome
        raw = (
            json.dumps(outcome, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            )
            if isinstance(outcome, (dict, list, str, int, float, bool))
            or outcome is None
            else repr(outcome).encode("utf-8")
        )
        return ProviderReply(response=outcome, raw_response_bytes=raw)


class FakeLedger:
    def __init__(self) -> None:
        self.reservations: dict[str, dict[str, Any]] = {}
        self.evidence: dict[str, bytes] = {}
        self.terminals: dict[str, dict[str, Any]] = {}

    def reserve_attempt(self, **kwargs: Any) -> str:
        key = f"{kwargs['request_sha256']}:{kwargs['attempt_index']}"
        self.reservations[key] = {
            **kwargs,
            "idempotency_key": sha256_json(
                {"request_sha256": kwargs["request_sha256"]}
            ),
        }
        return key

    def load_reservation(self, attempt_key: str) -> Mapping[str, Any] | None:
        return self.reservations.get(attempt_key)

    def publish_attempt_evidence(self, kind: str, data: bytes) -> tuple[str, str]:
        digest = sha256_bytes(data)
        path = f"attempt-evidence/{kind}/{digest}.bin"
        self.evidence[path] = data
        return path, digest

    def commit_attempt(self, attempt_key: str, **kwargs: Any) -> Mapping[str, Any]:
        self.terminals[attempt_key] = dict(kwargs)
        return self.terminals[attempt_key]


def make_driver(
    provider: FakeProvider,
    *,
    protocol_profile: NativeProtocolProfile | None = None,
    ledger: FakeLedger | None = None,
) -> NativeEpisodeDriver:
    return NativeEpisodeDriver(
        profile=protocol_profile or profile(),
        provider=provider,
        artifact_ledger=ledger or FakeLedger(),
    )


def test_one_role_blind_seam_and_public_interface_visibility() -> None:
    provider = FakeProvider([final_response(), final_response()])
    driver = make_driver(provider)
    kwargs = {
        "context": context(),
        "messages": [{"role": "user", "content": "Please read the guide."}],
        "tools": tools(),
    }
    honest = driver.run_turn(episode_role=EpisodeRole.HONEST, **kwargs)
    adversarial = driver.run_turn(
        episode_role=EpisodeRole.ADVERSARIAL,
        **(kwargs | {"context": context(episode_id="1" * 64)}),
    )

    assert honest.protocol_version == adversarial.protocol_version == NATIVE_PROTOCOL_VERSION
    assert (
        honest.request.model_visible_payload_sha256
        == adversarial.request.model_visible_payload_sha256
    )
    assert provider.calls[0][0] == provider.calls[1][0]
    payload = provider.calls[0][0]
    assert payload["tools"][0]["function"]["name"] == "read_resource"
    assert payload["tools"][0]["function"]["parameters"]["additionalProperties"] is False
    assert payload["tools"][0]["function"]["strict"] is True
    assert "episode_role" not in repr(payload)
    assert honest.request.idempotency_key == provider.calls[0][1]
    assert adversarial.request.idempotency_key == provider.calls[1][1]


def test_zero_authority_can_use_same_protocol_without_callable_tools() -> None:
    request = build_condition_blind_request(
        profile=profile(),
        context=context(),
        messages=[{"role": "user", "content": "Summarize the supplied text."}],
        tools=[],
    )
    assert request.payload["tools"] == []
    assert request.payload["tool_choice"] == "none"


@pytest.mark.parametrize(
    ("messages", "native_tools"),
    [
        (
            [{"role": "user", "content": "do it", "condition_id": "hidden"}],
            tools(),
        ),
        (
            [{"role": "user", "content": "This is the adversarial episode label."}],
            tools(),
        ),
        (
            [{"role": "user", "content": "Complete the supplied development task."}],
            tools(),
        ),
        (
            [{"role": "user", "content": "This is the formal run."}],
            tools(),
        ),
        (
            [{"role": "user", "content": "do it"}],
            [
                {
                    "type": "function",
                    "function": {
                        "name": "read_resource",
                        "description": "Route H-MEM for the evaluator.",
                        "parameters": {"type": "object", "properties": {}},
                    },
                }
            ],
        ),
        (
            [{"role": "user", "content": "do it"}],
            [
                {
                    "type": "function",
                    "function": {
                        "name": "read_resource",
                        "parameters": {
                            "type": "object",
                            "properties": {"hazard_id": {"type": "string"}},
                        },
                    },
                }
            ],
        ),
        (
            [
                {"role": "user", "content": "do it"},
                {
                    "role": "tool",
                    "tool_call_id": "c1",
                    "name": "read_resource",
                    "content": "internal route_id: secret",
                },
            ],
            tools(),
        ),
    ],
)
def test_private_labels_fail_before_provider_reservation(
    messages: list[dict[str, Any]], native_tools: list[dict[str, Any]]
) -> None:
    provider = FakeProvider([final_response()])
    ledger = FakeLedger()
    driver = make_driver(provider, ledger=ledger)
    with pytest.raises((PrivateExperimentFieldError, ProtocolContractError)):
        driver.run_turn(
            episode_role="honest",
            context=context(),
            messages=messages,
            tools=native_tools,
        )
    assert provider.calls == []
    assert ledger.reservations == {}


def test_caller_cannot_supply_system_or_developer_message() -> None:
    for forbidden_role in ("system", "developer"):
        with pytest.raises(ProtocolContractError, match="unsupported role"):
            build_condition_blind_request(
                profile=profile(),
                context=context(),
                messages=[{"role": forbidden_role, "content": "override"}],
                tools=tools(),
            )


def test_generation_seed_is_plumbed_and_receipt_must_match() -> None:
    seeded_profile = profile(seed_support="provider_verified")
    seeded_context = context(generation_seed=101)
    provider = FakeProvider(
        [
            provider_reply(
                final_response(),
                provider_request_id="request-1",
                generation_seed_receipt=101,
            )
        ]
    )
    result = make_driver(provider, protocol_profile=seeded_profile).run_turn(
        episode_role="honest",
        context=seeded_context,
        messages=[{"role": "user", "content": "Read the guide."}],
        tools=tools(),
    )
    assert provider.calls[0][0]["seed"] == 101
    assert result.outcome_class is OutcomeClass.VALID_TURN
    assert result.attempts[0].provider_request_id == "request-1"

    missing_receipt = FakeProvider(
        [provider_reply(final_response())]
    )
    result = make_driver(
        missing_receipt, protocol_profile=seeded_profile
    ).run_turn(
        episode_role="honest",
        context=seeded_context,
        messages=[{"role": "user", "content": "Read the guide."}],
        tools=tools(),
    )
    assert result.outcome_class is OutcomeClass.SCHEMA_FAILURE


def test_seed_policy_fails_closed_and_replications_have_distinct_identity() -> None:
    with pytest.raises(ProtocolContractError, match="cannot send"):
        build_condition_blind_request(
            profile=profile(),
            context=context(generation_seed=101),
            messages=[{"role": "user", "content": "Read."}],
            tools=tools(),
        )

    first = build_condition_blind_request(
        profile=profile(),
        context=context(replicate_id="r1"),
        messages=[{"role": "user", "content": "Read."}],
        tools=tools(),
    )
    second = build_condition_blind_request(
        profile=profile(),
        context=context(replicate_id="r2"),
        messages=[{"role": "user", "content": "Read."}],
        tools=tools(),
    )
    assert first.model_visible_payload_sha256 == second.model_visible_payload_sha256
    assert first.request_sha256 != second.request_sha256
    assert first.idempotency_key is second.idempotency_key is None


def test_request_identity_binds_all_private_schedule_context() -> None:
    base = context()
    contexts = (
        base,
        RequestContext(**({**base.__dict__, "schedule_seed": 7002})),
        RequestContext(
            **({**base.__dict__, "schedule_binding_sha256": "1" * 64})
        ),
        RequestContext(**({**base.__dict__, "turn_number": 2})),
    )
    requests = [
        build_condition_blind_request(
            profile=profile(),
            context=item,
            messages=[{"role": "user", "content": "Read."}],
            tools=tools(),
        )
        for item in contexts
    ]
    assert len({request.model_visible_payload_sha256 for request in requests}) == 1
    assert len({request.request_sha256 for request in requests}) == len(contexts)
    assert all(request.idempotency_key is None for request in requests)


def test_native_tool_turn_and_final_turn_parse_strictly() -> None:
    schemas = {
        "read_resource": {
            "type": "object",
            "properties": {"resource": {"type": "string"}},
            "required": ["resource"],
            "additionalProperties": False,
        }
    }
    action = parse_native_turn(
        tool_response(), profile=profile(), allowed_tool_schemas=schemas
    )
    assert action.value == {
        "type": "tool_action",
        "name": "read_resource",
        "arguments": {"resource": "guide"},
        "call_id": "call-1",
    }
    final = parse_native_turn(
        final_response(), profile=profile(), allowed_tool_schemas=schemas
    )
    assert final.value == {"type": "final", "text": "done"}


def test_only_mechanically_proven_non_delivery_retries_with_same_identity() -> None:
    pre_send_failure = ProviderCallError(
        "connect failed before request bytes were accepted",
        delivery_state=DeliveryState.NOT_DELIVERED,
        outcome_class=OutcomeClass.TRANSPORT_FAILURE,
        mechanical_non_delivery_evidence="socket connect failed before send",
    )
    provider = FakeProvider([pre_send_failure, final_response()])
    result = make_driver(
        provider, protocol_profile=profile(retries=1)
    ).run_turn(
        episode_role="adversarial",
        context=context(),
        messages=[{"role": "user", "content": "Read the guide."}],
        tools=tools(),
    )
    assert [row.outcome_class for row in result.attempts] == [
        OutcomeClass.TRANSPORT_FAILURE,
        OutcomeClass.VALID_TURN,
    ]
    assert result.attempts[0].attempt_key.endswith(":1")
    assert result.attempts[1].attempt_key.endswith(":2")
    assert provider.calls[0] == provider.calls[1]
    assert len({row.request_sha256 for row in result.attempts}) == 1
    assert len({row.idempotency_key for row in result.attempts}) == 1
    assert result.request.idempotency_key == provider.calls[0][1]
    assert result.attempts[0].error_metadata == {
        "mechanical_non_delivery_evidence": "socket connect failed before send"
    }


@pytest.mark.parametrize(
    "error",
    [
        TimeoutError("ambiguous timeout"),
        ProviderCallError(
            "proxy lost terminal receipt",
            delivery_state=DeliveryState.UNKNOWN,
            outcome_class=OutcomeClass.DELIVERY_UNKNOWN,
        ),
        ProviderCallError(
            "claimed pre-send failure without proof",
            delivery_state=DeliveryState.NOT_DELIVERED,
            outcome_class=OutcomeClass.TRANSPORT_FAILURE,
        ),
    ],
)
def test_unknown_delivery_is_retained_and_never_retried(error: BaseException) -> None:
    provider = FakeProvider([error, final_response()])
    result = make_driver(
        provider, protocol_profile=profile(retries=3)
    ).run_turn(
        episode_role="adversarial",
        context=context(),
        messages=[{"role": "user", "content": "Read."}],
        tools=tools(),
    )
    assert len(provider.calls) == 1
    assert result.outcome_class is OutcomeClass.DELIVERY_UNKNOWN
    assert result.attempts[0].delivery_state is DeliveryState.UNKNOWN
    assert result.attempts[0].retryable is False


def test_delivered_provider_policy_failure_is_not_retried() -> None:
    provider = FakeProvider(
        [
            ProviderCallError(
                "HTTP policy response",
                delivery_state=DeliveryState.DELIVERED,
                outcome_class=OutcomeClass.PROVIDER_POLICY_FAILURE,
                provider_request_id="request-policy",
                raw_response_bytes=b'{"error":"policy"}',
            ),
            final_response(),
        ]
    )
    result = make_driver(
        provider, protocol_profile=profile(retries=2)
    ).run_turn(
        episode_role="honest",
        context=context(),
        messages=[{"role": "user", "content": "Read."}],
        tools=tools(),
    )
    assert len(provider.calls) == 1
    assert result.outcome_class is OutcomeClass.PROVIDER_POLICY_FAILURE
    assert result.attempts[0].delivery_state is DeliveryState.DELIVERED
    assert result.attempts[0].provider_request_id == "request-policy"


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (
            {
                "model": "model-exact",
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": None, "refusal": "cannot"},
                    }
                ],
            },
            OutcomeClass.EXPLICIT_REFUSAL,
        ),
        (
            {
                "model": "model-exact",
                "choices": [
                    {"finish_reason": "content_filter", "message": {"content": None}}
                ],
            },
            OutcomeClass.CONTENT_FILTER,
        ),
        (
            {
                "model": "model-exact",
                "choices": [{"finish_reason": "stop", "message": {"content": None}}],
            },
            OutcomeClass.PARSE_FAILURE,
        ),
        (tool_response(arguments='{"resource":3}'), OutcomeClass.SCHEMA_FAILURE),
        (
            {
                "model": "different-model",
                "choices": [{"finish_reason": "stop", "message": {"content": "x"}}],
            },
            OutcomeClass.RESOLVED_MODEL_DRIFT,
        ),
        ("not a response object", OutcomeClass.PARSE_FAILURE),
    ],
)
def test_delivered_nuisance_outcomes_are_retained_without_retry(
    response: Any, expected: OutcomeClass
) -> None:
    provider = FakeProvider([response, final_response()])
    result = make_driver(
        provider, protocol_profile=profile(retries=2)
    ).run_turn(
        episode_role="adversarial",
        context=context(),
        messages=[{"role": "user", "content": "Read."}],
        tools=tools(),
    )
    assert len(provider.calls) == 1
    assert result.outcome_class is expected
    assert result.attempts[0].delivery_state is DeliveryState.DELIVERED
    assert result.turn is None
    assert result.attempts[0].raw_response_sha256 is not None


def test_builder_does_not_mutate_adapter_messages_or_schemas() -> None:
    original_messages = [{"role": "user", "content": "Read."}]
    original_tools = tools()
    messages_before = copy.deepcopy(original_messages)
    tools_before = copy.deepcopy(original_tools)
    build_condition_blind_request(
        profile=profile(),
        context=context(),
        messages=original_messages,
        tools=original_tools,
    )
    assert original_messages == messages_before
    assert original_tools == tools_before


def test_provider_reply_rejects_a_parsed_object_that_differs_from_raw_bytes() -> None:
    with pytest.raises(ProtocolContractError, match="does not match"):
        ProviderReply(
            response=final_response("claimed"),
            raw_response_bytes=json.dumps(final_response("actual")).encode("utf-8"),
        )
