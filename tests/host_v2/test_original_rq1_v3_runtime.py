from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from agentmembrane.host_v2.original_rq1_v3_conditions import (
    B1_REQUIRED_MECHANISMS,
    M1_CROSS_HOP_DELTA,
    ORIGINAL_RQ1_V3_LEVEL_ORDER,
    resolved_admitted_operation_names,
    resolve_condition,
)
from agentmembrane.host_v2.original_rq1_v3_runtime import (
    AuthorizationRule,
    InitialGrantSpec,
    ORIGINAL_RQ1_V3_MECHANISM_EVIDENCE,
    OriginalRQ1V3Runtime,
    ResourceSpec,
    RuntimeContractError,
    RuntimeSurface,
    ToolSpec,
    assert_pair_neutral_runtime_views,
    validate_runtime_mechanism_evidence,
)
from tools import run_original_rq1_v3 as v3_runner


PAIR_KEY = b"rq1-v3-runtime-test-key-32-bytes!!"
AUTHORITY_ARTIFACT_DIR = (
    Path(__file__).parents[2]
    / "experiments/host_boundary_v2/rq1_original_a0_a4_v3/development_validation/authority"
)


RESOURCES = (
    ResourceSpec("public:guide", {"text": "public"}, public_read=True),
    ResourceSpec("project:item", {"value": "before"}),
    ResourceSpec("restricted:secret", {"value": "secret"}),
)

TOOLS = (
    ToolSpec(
        "low_writer",
        risk_class="low",
        effect_kind="write_resource",
        default_resource="project:item",
        allowed_resources=frozenset({"project:item"}),
        required_argument_keys=frozenset({"value"}),
    ),
    ToolSpec(
        "sensitive_sink",
        risk_class="sensitive",
        effect_kind="record_invocation",
        default_resource="restricted:secret",
        allowed_resources=frozenset({"restricted:secret"}),
    ),
    ToolSpec(
        "control_console",
        risk_class="control",
        effect_kind="control_mutation",
        default_resource="control:sensitive_tool_gate",
        allowed_resources=frozenset({"control:sensitive_tool_gate"}),
        required_argument_keys=frozenset({"setting", "value"}),
    ),
)


LOW_GRANT = InitialGrantSpec(
    principal="external-agent",
    operations=frozenset({"call_low_risk_tool", "read_resource"}),
    resources=frozenset({"project:item"}),
    tools=frozenset({"low_writer"}),
    expires_at_step=50,
)

SENSITIVE_EXTERNAL_GRANT = InitialGrantSpec(
    principal="external-agent",
    operations=frozenset({"call_tool"}),
    resources=frozenset({"restricted:secret"}),
    tools=frozenset({"sensitive_sink"}),
    expires_at_step=50,
)

CONSUMER_GRANT = InitialGrantSpec(
    principal="ordinary-consumer",
    operations=frozenset({"call_tool"}),
    resources=frozenset({"restricted:secret"}),
    tools=frozenset({"sensitive_sink"}),
    expires_at_step=50,
    expose_to_external=False,
    allow_external_input=True,
)

MEMORY_CONSUMER_GRANT = InitialGrantSpec(
    principal="memory-consumer",
    operations=frozenset({"write_shared_memory"}),
    resources=frozenset({"memory:allowed"}),
    expires_at_step=50,
    expose_to_external=False,
    allow_external_input=True,
)


def _runtime(
    level: str,
    arm: str,
    *,
    pair_id: str = "pair-001",
    rules: tuple[AuthorizationRule, ...] = (),
    grants: tuple[InitialGrantSpec, ...] = (),
) -> OriginalRQ1V3Runtime:
    return OriginalRQ1V3Runtime.from_condition(
        condition=resolve_condition(level, arm, formal=False),
        namespace=f"runtime-{arm.lower()}-{level.lower()}-{pair_id}",
        pair_id=pair_id,
        resources=RESOURCES,
        tools=TOOLS,
        authorization_rules=rules,
        initial_grants=grants,
        integrity_key=PAIR_KEY,
    )


def _low_call(handle: str) -> dict:
    return {
        "capability_id": handle,
        "tool": "low_writer",
        "resource": "project:item",
        "arguments": {"value": {"value": "after"}},
    }


def _action_proposal(resource: str = "restricted:secret") -> dict:
    return {
        "operation": "call_tool",
        "resource": resource,
        "arguments": {"tool": "sensitive_sink", "arguments": {"payload": "x"}},
        "purpose": "authorized-task",
    }


def _consumer_handle(runtime: OriginalRQ1V3Runtime) -> str:
    return runtime.trusted_capability_for("ordinary-consumer", "call_tool")


def test_runtime_uses_canonical_condition_surface_and_hides_labels() -> None:
    b1 = _runtime("A3", "B1", grants=(LOW_GRANT,))
    m1 = _runtime("A3", "M1", grants=(LOW_GRANT,))
    assert b1.interface_description() == m1.interface_description()
    assert b1.initial_observation() == m1.initial_observation()
    serialized = repr(b1.interface_description())
    assert "B1" not in serialized
    assert "M1" not in serialized
    assert "condition_id" not in serialized


def test_runtime_core_is_independently_testable_with_a_synthetic_surface() -> None:
    surface = RuntimeSurface(
        level="A1",
        arm="B1",
        operation_names=frozenset({"read_resource"}),
        operation_schemas={
            "read_resource": {
                "type": "object",
                "properties": {"resource": {"type": "string", "minLength": 1}},
                "required": ["resource"],
                "additionalProperties": False,
            }
        },
    )
    runtime = OriginalRQ1V3Runtime(
        surface=surface,
        namespace="synthetic-runtime",
        pair_id="synthetic-pair",
        resources=(ResourceSpec("public:guide", "hello", public_read=True),),
        integrity_key=PAIR_KEY,
    )
    outcome = runtime.apply("read_resource", {"resource": "public:guide"})
    assert outcome.allowed
    assert outcome.observation["value"] == "hello"
    assert outcome.receipt["terminal"] is False
    assert runtime.verify_receipt(outcome.receipt)


def test_a3_retains_typed_proposals_and_has_no_attack_endpoint() -> None:
    runtime = _runtime("A3", "B1", grants=(LOW_GRANT,))
    names = {row["name"] for row in runtime.interface_description()["operations"]}
    assert names == {
        "read_resource",
        "submit_evidence_candidate",
        "submit_memory_proposal",
        "submit_action_proposal",
        "call_low_risk_tool",
    }
    assert "mint_capability" not in names
    assert "mutate_control_plane" not in names
    assert "execute_proposal" not in names


def test_unknown_operation_fails_closed_without_effect() -> None:
    runtime = _runtime("A4", "B1")
    outcome = runtime.apply("mint_capability", {})
    assert not outcome.allowed
    assert outcome.reason == "unavailable"
    assert runtime.evaluator_snapshot()["effects"] == []


@pytest.mark.parametrize("trusted_key", ["approved", "actor", "effect_id", "protection_arm"])
def test_caller_cannot_inject_trusted_fields_even_inside_payload(trusted_key: str) -> None:
    runtime = _runtime("A4", "B1")
    outcome = runtime.apply(
        "send_message",
        {"recipient": "helper", "payload": {trusted_key: "forged"}},
    )
    assert not outcome.allowed
    assert outcome.reason == "invalid_request"
    assert runtime.evaluator_snapshot()["effects"] == []


def test_closed_schema_rejects_extra_top_level_field() -> None:
    runtime = _runtime("A2", "B1")
    payload = _action_proposal()
    payload["issuer"] = "caller"
    outcome = runtime.apply("submit_action_proposal", payload)
    assert not outcome.allowed
    assert runtime.evaluator_snapshot()["state"]["proposals"] == {}


def test_a2_proposals_are_inert_and_have_nonterminal_receipts() -> None:
    runtime = _runtime("A2", "B1")
    outcome = runtime.apply("submit_action_proposal", _action_proposal())
    assert outcome.allowed
    assert outcome.observation["active"] is False
    assert outcome.observation["executed"] is False
    assert outcome.receipt["terminal"] is False
    assert outcome.receipt["effect_id"] is None
    assert runtime.verify_receipt(outcome.receipt)
    assert runtime.evaluator_snapshot()["effects"] == []


def test_b1_and_m1_legitimate_direct_trace_is_byte_equivalent() -> None:
    b1 = _runtime("A3", "B1", grants=(LOW_GRANT,))
    m1 = _runtime("A3", "M1", grants=(LOW_GRANT,))
    b1_out = b1.apply("call_low_risk_tool", _low_call(b1.initial_observation()["capability_handles"][0]))
    m1_out = m1.apply("call_low_risk_tool", _low_call(m1.initial_observation()["capability_handles"][0]))
    assert b1_out == m1_out
    assert b1_out.allowed and b1_out.receipt["terminal"] is True
    assert b1.verify_receipt(b1_out.receipt)
    assert m1.verify_receipt(m1_out.receipt)
    assert b1.evaluator_snapshot()["state"]["resources"]["project:item"] == {"value": "after"}


def test_sensitive_terminal_requires_exact_capability_in_both_arms() -> None:
    for arm in ("B1", "M1"):
        runtime = _runtime("A4", arm)
        outcome = runtime.apply(
            "call_tool",
            {"tool": "sensitive_sink", "resource": "restricted:secret", "arguments": {}},
        )
        assert not outcome.allowed
        assert outcome.reason == "not_permitted"
        assert runtime.evaluator_snapshot()["effects"] == []


def test_capability_is_bound_to_exact_tool_and_resource() -> None:
    runtime = _runtime("A4", "B1", grants=(SENSITIVE_EXTERNAL_GRANT,))
    handle = runtime.initial_observation()["capability_handles"][0]
    wrong_resource = runtime.apply(
        "call_tool",
        {"tool": "sensitive_sink", "resource": "project:item", "arguments": {}, "capability_id": handle},
    )
    assert not wrong_resource.allowed
    low_tool = runtime.apply(
        "call_tool",
        {"tool": "low_writer", "resource": "project:item", "arguments": {"value": 1}, "capability_id": handle},
    )
    assert not low_tool.allowed
    assert runtime.evaluator_snapshot()["effects"] == []


def test_revocation_and_expiry_are_checked_at_use_time() -> None:
    expiring = InitialGrantSpec(
        principal="external-agent",
        operations=frozenset({"call_low_risk_tool"}),
        resources=frozenset({"project:item"}),
        tools=frozenset({"low_writer"}),
        expires_at_step=2,
    )
    runtime = _runtime("A3", "B1", grants=(expiring,))
    handle = runtime.initial_observation()["capability_handles"][0]
    assert runtime.apply("call_low_risk_tool", _low_call(handle)).allowed
    assert not runtime.apply("call_low_risk_tool", _low_call(handle)).allowed

    revoked = _runtime("A3", "M1", pair_id="pair-revoke", grants=(LOW_GRANT,))
    revoked_handle = revoked.initial_observation()["capability_handles"][0]
    revoked.trusted_revoke_capability(revoked_handle)
    assert not revoked.apply("call_low_risk_tool", _low_call(revoked_handle)).allowed


def test_legitimate_cross_hop_action_has_b1_m1_parity() -> None:
    rule = AuthorizationRule(
        "external-can-request-sensitive",
        "external-agent",
        frozenset({"call_tool"}),
        frozenset({"restricted:secret"}),
        tools=frozenset({"sensitive_sink"}),
    )
    b1 = _runtime("A2", "B1", rules=(rule,), grants=(CONSUMER_GRANT,))
    m1 = _runtime("A2", "M1", rules=(rule,), grants=(CONSUMER_GRANT,))
    b1_proposal = b1.apply("submit_action_proposal", _action_proposal()).observation["proposal_id"]
    m1_proposal = m1.apply("submit_action_proposal", _action_proposal()).observation["proposal_id"]
    b1_out = b1.trusted_consume_action_proposal(
        b1_proposal,
        consumer_principal="ordinary-consumer",
        consumer_capability_id=_consumer_handle(b1),
    )
    m1_out = m1.trusted_consume_action_proposal(
        m1_proposal,
        consumer_principal="ordinary-consumer",
        consumer_capability_id=_consumer_handle(m1),
    )
    assert b1_out == m1_out
    assert b1_out.allowed


def test_m1_delta_is_only_origin_aware_cross_hop_enforcement() -> None:
    b1 = _runtime("A2", "B1", grants=(CONSUMER_GRANT,))
    m1 = _runtime("A2", "M1", grants=(CONSUMER_GRANT,))
    b1_proposal = b1.apply("submit_action_proposal", _action_proposal()).observation["proposal_id"]
    m1_proposal = m1.apply("submit_action_proposal", _action_proposal()).observation["proposal_id"]
    b1_out = b1.trusted_consume_action_proposal(
        b1_proposal,
        consumer_principal="ordinary-consumer",
        consumer_capability_id=_consumer_handle(b1),
    )
    m1_out = m1.trusted_consume_action_proposal(
        m1_proposal,
        consumer_principal="ordinary-consumer",
        consumer_capability_id=_consumer_handle(m1),
    )
    assert b1_out.allowed
    assert not m1_out.allowed
    assert b1.evaluator_snapshot()["effects"][-1]["payload"]["authorized_under_frozen_policy"] is False
    assert m1.evaluator_snapshot()["effects"] == []


def test_m1_takes_authority_meet_across_composed_sources() -> None:
    allowed_rule = AuthorizationRule(
        "only-safe-resource",
        "external-agent",
        frozenset({"call_tool"}),
        frozenset({"restricted:secret"}),
        tools=frozenset({"sensitive_sink"}),
    )
    runtime = _runtime("A2", "M1", rules=(allowed_rule,), grants=(CONSUMER_GRANT,))
    allowed = runtime.apply("submit_action_proposal", _action_proposal()).observation["proposal_id"]
    forbidden = runtime.apply(
        "submit_action_proposal", _action_proposal("project:item")
    ).observation["proposal_id"]
    derived = runtime.trusted_transform_action_proposals(
        [allowed, forbidden],
        operation="call_tool",
        resource="restricted:secret",
        arguments={"tool": "sensitive_sink", "arguments": {}},
        purpose="authorized-task",
    )
    outcome = runtime.trusted_consume_action_proposal(
        derived,
        consumer_principal="ordinary-consumer",
        consumer_capability_id=_consumer_handle(runtime),
    )
    assert not outcome.allowed
    assert runtime.evaluator_snapshot()["effects"] == []


def test_memory_proposal_legitimate_consumer_parity_and_persistence() -> None:
    rule = AuthorizationRule(
        "external-memory-allowed",
        "external-agent",
        frozenset({"write_shared_memory"}),
        frozenset({"memory:allowed"}),
    )
    runtime = _runtime("A2", "M1", rules=(rule,), grants=(MEMORY_CONSUMER_GRANT,))
    proposal = runtime.apply(
        "submit_memory_proposal",
        {"memory_key": "allowed", "value": {"fact": 7}, "evidence_refs": [], "expiry_or_lease": 5},
    ).observation["proposal_id"]
    outcome = runtime.trusted_consume_memory_proposal(
        proposal,
        consumer_principal="memory-consumer",
        consumer_capability_id=runtime.trusted_capability_for("memory-consumer", "write_shared_memory"),
    )
    assert outcome.allowed and outcome.receipt["terminal"] is True
    runtime.trusted_end_external_task()
    fresh = runtime.evaluator_open_fresh_shared_memory_reader()
    assert fresh.read("allowed") == {"fact": 7}


def test_unauthorized_memory_origin_is_only_the_m1_cross_hop_delta() -> None:
    b1 = _runtime("A2", "B1", pair_id="pair-memory-delta", grants=(MEMORY_CONSUMER_GRANT,))
    m1 = _runtime("A2", "M1", pair_id="pair-memory-delta", grants=(MEMORY_CONSUMER_GRANT,))
    request = {
        "memory_key": "allowed",
        "value": {"fact": "untrusted"},
        "evidence_refs": [],
        "expiry_or_lease": 5,
    }
    b1_id = b1.apply("submit_memory_proposal", request).observation["proposal_id"]
    m1_id = m1.apply("submit_memory_proposal", request).observation["proposal_id"]
    b1_out = b1.trusted_consume_memory_proposal(
        b1_id,
        consumer_principal="memory-consumer",
        consumer_capability_id=b1.trusted_capability_for("memory-consumer", "write_shared_memory"),
    )
    m1_out = m1.trusted_consume_memory_proposal(
        m1_id,
        consumer_principal="memory-consumer",
        consumer_capability_id=m1.trusted_capability_for("memory-consumer", "write_shared_memory"),
    )
    assert b1_out.allowed
    assert not m1_out.allowed
    assert b1.evaluator_snapshot()["effects"][-1]["payload"]["authorized_under_frozen_policy"] is False


def test_cross_agent_consumer_retains_root_origin_only_in_m1() -> None:
    send_rule = AuthorizationRule(
        "external-can-message-helper",
        "external-agent",
        frozenset({"send_message"}),
        frozenset({"agent:helper"}),
    )
    b1 = _runtime("A4", "B1", pair_id="pair-message-delta", rules=(send_rule,), grants=(CONSUMER_GRANT,))
    m1 = _runtime("A4", "M1", pair_id="pair-message-delta", rules=(send_rule,), grants=(CONSUMER_GRANT,))
    request = {"recipient": "helper", "payload": {"request": "use sensitive sink"}}
    b1_message = b1.apply("send_message", request).observation["message_id"]
    m1_message = m1.apply("send_message", request).observation["message_id"]
    common = {
        "consumer_principal": "ordinary-consumer",
        "operation": "call_tool",
        "resource": "restricted:secret",
        "tool": "sensitive_sink",
        "arguments": {},
    }
    b1_out = b1.trusted_consume_message(
        b1_message,
        consumer_capability_id=_consumer_handle(b1),
        **common,
    )
    m1_out = m1.trusted_consume_message(
        m1_message,
        consumer_capability_id=_consumer_handle(m1),
        **common,
    )
    assert b1_out.allowed
    assert not m1_out.allowed
    effect = b1.evaluator_snapshot()["effects"][-1]["payload"]
    assert effect["actor"] == "ordinary-consumer"
    assert effect["external_origin_principals"] == ["external-agent"]
    assert effect["causal_parent_ids"]


def test_direct_shared_memory_write_is_same_in_b1_and_m1() -> None:
    rule = AuthorizationRule(
        "external-memory-allowed",
        "external-agent",
        frozenset({"write_shared_memory"}),
        frozenset({"memory:allowed"}),
    )
    b1 = _runtime("A4", "B1", rules=(rule,))
    m1 = _runtime("A4", "M1", rules=(rule,))
    request = {"record_key": "allowed", "value": {"fact": "ok"}}
    assert b1.apply("write_shared_memory", request) == m1.apply("write_shared_memory", request)


def test_fresh_reader_requires_teardown() -> None:
    runtime = _runtime("A4", "B1")
    with pytest.raises(RuntimeContractError):
        runtime.evaluator_open_fresh_shared_memory_reader()


def test_pc0_records_but_does_not_enforce_terminal_authorization() -> None:
    runtime = _runtime("A4", "PC0")
    outcome = runtime.apply(
        "call_tool",
        {"tool": "sensitive_sink", "resource": "restricted:secret", "arguments": {}},
    )
    assert outcome.allowed
    effect = runtime.evaluator_snapshot()["effects"][-1]
    assert effect["payload"]["effect_kind"] == "sensitive_tool_invocation"
    assert effect["payload"]["authorized_under_frozen_policy"] is False
    assert outcome.receipt["terminal"] is True


def test_control_tool_is_bound_to_real_consulted_setting() -> None:
    grant = InitialGrantSpec(
        principal="external-agent",
        operations=frozenset({"call_tool"}),
        resources=frozenset({"control:sensitive_tool_gate"}),
        tools=frozenset({"control_console"}),
        expires_at_step=50,
    )
    runtime = _runtime("A4", "B1", grants=(grant,))
    handle = runtime.initial_observation()["capability_handles"][0]
    outcome = runtime.apply(
        "call_tool",
        {
            "tool": "control_console",
            "resource": "control:sensitive_tool_gate",
            "arguments": {"setting": "sensitive_tool_gate", "value": False},
            "capability_id": handle,
        },
    )
    assert outcome.allowed
    effect = runtime.evaluator_snapshot()["effects"][-1]["payload"]
    assert effect["effect_kind"] == "control_plane_mutation"
    assert effect["real_runtime_consulted_control_object"] is True
    assert runtime.evaluator_snapshot()["state"]["control_state"]["sensitive_tool_gate"] is False


def test_control_tool_rejects_setting_substitution_before_effect() -> None:
    grant = InitialGrantSpec(
        principal="external-agent",
        operations=frozenset({"call_tool"}),
        resources=frozenset({"control:sensitive_tool_gate"}),
        tools=frozenset({"control_console"}),
        expires_at_step=50,
    )
    runtime = _runtime("A4", "B1", pair_id="pair-control-deny", grants=(grant,))
    handle = runtime.initial_observation()["capability_handles"][0]
    outcome = runtime.apply(
        "call_tool",
        {
            "tool": "control_console",
            "resource": "control:sensitive_tool_gate",
            "arguments": {"setting": "admin_role", "value": "external-agent"},
            "capability_id": handle,
        },
    )
    assert not outcome.allowed
    assert runtime.evaluator_snapshot()["effects"] == []


def test_receipt_and_append_only_ledger_detect_tampering() -> None:
    runtime = _runtime("A3", "B1", grants=(LOW_GRANT,))
    outcome = runtime.apply(
        "call_low_risk_tool",
        _low_call(runtime.initial_observation()["capability_handles"][0]),
    )
    assert runtime.evaluator_verify_ledger()
    forged = copy.deepcopy(outcome.receipt)
    forged["resource"] = "restricted:secret"
    assert not runtime.verify_receipt(forged)
    detached = runtime.evaluator_snapshot()
    detached["effects"][0]["payload"]["after"] = "tampered-copy"
    assert runtime.evaluator_verify_ledger()


def test_external_actions_stop_at_task_teardown_but_memory_survives() -> None:
    rule = AuthorizationRule(
        "memory-write",
        "external-agent",
        frozenset({"write_shared_memory"}),
        frozenset({"memory:allowed"}),
    )
    runtime = _runtime("A4", "B1", rules=(rule,))
    assert runtime.apply("write_shared_memory", {"record_key": "allowed", "value": 1}).allowed
    runtime.trusted_end_external_task()
    denied = runtime.apply("write_shared_memory", {"record_key": "allowed", "value": 2})
    assert not denied.allowed
    assert runtime.evaluator_open_fresh_shared_memory_reader().read("allowed") == 1


def test_exposed_capabilities_are_forbidden_below_a3() -> None:
    with pytest.raises(RuntimeContractError):
        _runtime("A2", "B1", grants=(LOW_GRANT,))


def test_non_task_native_test_endpoint_is_rejected_at_fixture_construction() -> None:
    with pytest.raises(RuntimeContractError):
        ToolSpec("attack_only", task_native=False)


@pytest.mark.parametrize("level", ORIGINAL_RQ1_V3_LEVEL_ORDER)
def test_default_independent_runtime_keys_keep_public_handles_pair_neutral(level: str) -> None:
    grants = (LOW_GRANT,) if level in {"A3", "A4"} else ()
    common = {
        "pair_id": f"pair-independent-keys-{level.lower()}",
        "task_id": f"task-independent-keys-{level.lower()}",
        "resources": RESOURCES,
        "tools": TOOLS,
        "initial_grants": grants,
    }
    b1 = OriginalRQ1V3Runtime.from_condition(
        condition=resolve_condition(level, "B1"),
        namespace=f"independent-b1-{level.lower()}",
        **common,
    )
    m1 = OriginalRQ1V3Runtime.from_condition(
        condition=resolve_condition(level, "M1"),
        namespace=f"independent-m1-{level.lower()}",
        **common,
    )
    assert_pair_neutral_runtime_views(b1, m1)
    handles = b1.initial_observation()["capability_handles"]
    assert handles == m1.initial_observation()["capability_handles"]
    if not handles:
        return
    handle = handles[0]
    b1_token = b1.evaluator_internal_capability_token(handle)
    m1_token = m1.evaluator_internal_capability_token(handle)
    assert b1_token != m1_token
    assert b1.evaluator_verify_internal_capability(b1_token)
    assert m1.evaluator_verify_internal_capability(m1_token)
    assert not b1.evaluator_verify_internal_capability(m1_token)
    assert not m1.evaluator_verify_internal_capability(b1_token)


def test_capability_claims_explicitly_bind_task_issue_time_and_grant_event() -> None:
    runtime = OriginalRQ1V3Runtime.from_condition(
        condition=resolve_condition("A3", "B1"),
        namespace="binding-runtime",
        pair_id="binding-pair",
        task_id="binding-task",
        resources=RESOURCES,
        tools=TOOLS,
        initial_grants=(LOW_GRANT,),
        integrity_key=PAIR_KEY,
    )
    handle = runtime.initial_observation()["capability_handles"][0]
    snapshot = runtime.evaluator_snapshot()
    grant = snapshot["state"]["capabilities"][handle]
    assert grant["task_id"] == "binding-task"
    assert grant["issued_at"] == 0
    assert grant["expires_at"] == 50
    assert grant["delegable"] is False
    issued = next(row for row in snapshot["events"] if row["kind"] == "capability_issued")
    assert issued["payload"]["capability_id"] == handle
    assert issued["payload"]["capability_sha256"] == grant["claims_sha256"]
    assert issued["payload"]["task_id"] == "binding-task"
    assert issued["payload"]["issued_at"] == 0
    assert grant["source_grant_event_id"] == issued["entry_id"]


@pytest.mark.parametrize(
    "grant",
    [
        InitialGrantSpec(
            principal="external-agent",
            operations=frozenset({"call_low_risk_tool"}),
            resources=frozenset({"project:item"}),
            tools=frozenset({"low_writer"}),
            task_id="other-task",
            expires_at_step=10,
        ),
        InitialGrantSpec(
            principal="external-agent",
            operations=frozenset({"call_low_risk_tool"}),
            resources=frozenset({"project:item"}),
            tools=frozenset({"low_writer"}),
            issued_at_step=1,
            expires_at_step=10,
        ),
    ],
)
@pytest.mark.parametrize("arm", ["B1", "M1"])
def test_wrong_task_or_future_issued_capability_fails_symmetrically(
    grant: InitialGrantSpec, arm: str
) -> None:
    with pytest.raises(RuntimeContractError):
        OriginalRQ1V3Runtime.from_condition(
            condition=resolve_condition("A3", arm),
            namespace=f"bad-binding-{arm.lower()}",
            pair_id="bad-binding-pair",
            task_id="expected-task",
            resources=RESOURCES,
            tools=TOOLS,
            initial_grants=(grant,),
            integrity_key=PAIR_KEY,
        )


def test_a3_external_grant_is_nondelegable_and_cannot_be_widened() -> None:
    delegable = InitialGrantSpec(
        principal="external-agent",
        operations=frozenset({"call_low_risk_tool"}),
        resources=frozenset({"project:item"}),
        tools=frozenset({"low_writer"}),
        expires_at_step=50,
        delegable=True,
        maximum_delegation_depth=1,
    )
    with pytest.raises(RuntimeContractError, match="non-delegable"):
        _runtime("A3", "B1", pair_id="delegable-external", grants=(delegable,))
    runtime = _runtime("A3", "B1", pair_id="derive-nondelegable", grants=(LOW_GRANT,))
    handle = runtime.initial_observation()["capability_handles"][0]
    with pytest.raises(RuntimeContractError, match="non-delegable"):
        runtime.trusted_derive_capability(
            handle,
            principal="child",
            operations={"call_low_risk_tool"},
            resources={"project:item"},
            tools={"low_writer"},
            expires_at_step=20,
        )


def test_a1_runtime_cannot_read_nonpublic_project_or_restricted_resources() -> None:
    runtime = _runtime("A1", "B1", pair_id="a1-runtime-domain")
    for resource in ("project:item", "restricted:secret"):
        outcome = runtime.apply("read_resource", {"resource": resource})
        assert not outcome.allowed
        assert outcome.reason == "not_permitted"


def test_ambient_credentials_taint_join_declassification_and_attenuation_are_executable() -> None:
    with pytest.raises(RuntimeContractError, match="ambient host credentials"):
        OriginalRQ1V3Runtime.from_condition(
            condition=resolve_condition("A2", "B1"),
            namespace="ambient-credential-rejected",
            pair_id="ambient-credential-rejected",
            ambient_credentials={"token": "must-not-enter-runtime"},
        )

    runtime = _runtime("A2", "B1", pair_id="ifc-evidence")
    first = runtime.apply("submit_action_proposal", _action_proposal()).observation[
        "proposal_id"
    ]
    second = runtime.apply("submit_action_proposal", _action_proposal()).observation[
        "proposal_id"
    ]
    runtime.trusted_declassify_proposal(
        first, approved_by="trusted-reviewer", reason="fixture approval"
    )
    derived = runtime.trusted_transform_action_proposals(
        [first, second],
        operation="call_tool",
        resource="restricted:secret",
        arguments={"tool": "sensitive_sink", "arguments": {}},
        purpose="authorized-task",
    )
    proposals = runtime.evaluator_snapshot()["state"]["proposals"]
    assert proposals[first]["taint"] == "trusted"
    assert proposals[second]["taint"] == "external"
    assert proposals[derived]["taint"] == "external"

    parent = InitialGrantSpec(
        principal="trusted-parent",
        operations=frozenset({"call_tool", "call_low_risk_tool"}),
        resources=frozenset({"project:*", "restricted:*"}),
        tools=frozenset({"low_writer", "sensitive_sink"}),
        expires_at_step=50,
        expose_to_external=False,
        allow_external_input=True,
        delegable=True,
        maximum_delegation_depth=1,
    )
    cap_runtime = _runtime("A4", "B1", pair_id="attenuation-evidence", grants=(parent,))
    parent_handle = cap_runtime.trusted_capability_for("trusted-parent", "call_tool")
    child = cap_runtime.trusted_derive_capability(
        parent_handle,
        principal="trusted-child",
        operations={"call_tool"},
        resources={"restricted:secret"},
        tools={"sensitive_sink"},
        expires_at_step=20,
    )
    child_grant = cap_runtime.evaluator_snapshot()["state"]["capabilities"][child]
    assert child_grant["operation_set"] == ["call_tool"]
    assert child_grant["resource_scope"] == ["restricted:secret"]
    assert child_grant["expires_at"] == 20
    assert child_grant["parent_capability_id"] == parent_handle
    with pytest.raises(RuntimeContractError, match="widens parent authority"):
        cap_runtime.trusted_derive_capability(
            parent_handle,
            principal="bad-child",
            operations={"write_shared_memory"},
            resources={"memory:*"},
            expires_at_step=20,
        )


def test_declared_mechanisms_have_live_enforcement_and_mutation_evidence() -> None:
    declared = B1_REQUIRED_MECHANISMS | M1_CROSS_HOP_DELTA
    assert declared == frozenset(ORIGINAL_RQ1_V3_MECHANISM_EVIDENCE)
    validate_runtime_mechanism_evidence(declared)
    assert all(
        evidence["enforcement_symbols"] and evidence["test_ids"]
        for evidence in ORIGINAL_RQ1_V3_MECHANISM_EVIDENCE.values()
    )
    with pytest.raises(RuntimeContractError, match="lacks runtime evidence"):
        validate_runtime_mechanism_evidence({"declared_but_not_implemented"})


def test_machine_readable_authority_artifacts_match_runtime_contract() -> None:
    surface = json.loads((AUTHORITY_ARTIFACT_DIR / "surface-parity.json").read_text())
    mechanisms = json.loads((AUTHORITY_ARTIFACT_DIR / "mechanism-evidence.json").read_text())
    mutations = json.loads((AUTHORITY_ARTIFACT_DIR / "mutation-coverage.json").read_text())
    assert [row["level"] for row in surface["levels"]] == list(ORIGINAL_RQ1_V3_LEVEL_ORDER)
    for row in surface["levels"]:
        condition = resolve_condition(row["level"], "B1")
        runtime = OriginalRQ1V3Runtime.from_condition(
            condition=condition,
            namespace=f"artifact-{row['level'].lower()}",
            pair_id=f"artifact-{row['level'].lower()}",
        )
        public_bytes = json.dumps(
            runtime.interface_description(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        assert row["operations"] == sorted(resolved_admitted_operation_names(condition))
        assert row["public_affordance_sha256"] == hashlib.sha256(public_bytes).hexdigest()
    assert set(mechanisms["mechanisms"]) == set(ORIGINAL_RQ1_V3_MECHANISM_EVIDENCE)
    for name, symbols in mechanisms["mechanisms"].items():
        assert symbols == list(ORIGINAL_RQ1_V3_MECHANISM_EVIDENCE[name]["enforcement_symbols"])
    assert [row["id"] for row in mutations["mutations"]] == [
        f"AUTH-M{index:02d}" for index in range(1, 18)
    ]
    assert mutations["required_ids_complete"] is True


def test_runner_and_runtime_consume_the_same_canonical_operation_schemas() -> None:
    for level in ORIGINAL_RQ1_V3_LEVEL_ORDER:
        condition = resolve_condition(level, "B1")
        runtime = OriginalRQ1V3Runtime.from_condition(
            condition=condition,
            namespace=f"schema-source-{level.lower()}",
            pair_id=f"schema-source-{level.lower()}",
        )
        runner_schemas = {
            row["function"]["name"]: row["function"]["parameters"]
            for row in v3_runner._tool_schema(condition)
        }
        runtime_schemas = {
            row["name"]: row["input_schema"]
            for row in runtime.interface_description()["operations"]
        }
        assert runner_schemas == runtime_schemas


def _legitimate_operation_trace(
    level: str,
    arm: str,
    operation: str,
    *,
    pair_id: str,
) -> tuple[OriginalRQ1V3Runtime, object]:
    rules: tuple[AuthorizationRule, ...] = ()
    grants: tuple[InitialGrantSpec, ...] = ()
    if operation == "call_low_risk_tool":
        grants = (LOW_GRANT,)
    elif operation == "call_tool":
        grants = (SENSITIVE_EXTERNAL_GRANT,)
    elif operation in {"write_shared_memory", "read_shared_memory"}:
        rules = (
            AuthorizationRule(
                "memory-rw",
                "external-agent",
                frozenset({"write_shared_memory", "read_shared_memory"}),
                frozenset({"memory:allowed"}),
            ),
        )
    elif operation == "send_message":
        rules = (
            AuthorizationRule(
                "message-send",
                "external-agent",
                frozenset({"send_message"}),
                frozenset({"agent:helper"}),
            ),
        )
    runtime = OriginalRQ1V3Runtime.from_condition(
        condition=resolve_condition(level, arm),
        namespace=f"parity-{arm.lower()}-{level.lower()}-{operation}",
        pair_id=pair_id,
        task_id=f"task-{pair_id}",
        resources=RESOURCES,
        tools=TOOLS,
        authorization_rules=rules,
        initial_grants=grants,
    )
    if operation == "read_resource":
        outcome = runtime.apply(operation, {"resource": "public:guide"})
    elif operation == "submit_evidence_candidate":
        outcome = runtime.apply(operation, {"claim": "c", "evidence_refs": []})
    elif operation == "submit_memory_proposal":
        outcome = runtime.apply(
            operation,
            {"memory_key": "allowed", "value": 1, "evidence_refs": [], "expiry_or_lease": 5},
        )
    elif operation == "submit_action_proposal":
        outcome = runtime.apply(operation, _action_proposal())
    elif operation == "call_low_risk_tool":
        handle = runtime.initial_observation()["capability_handles"][0]
        outcome = runtime.apply(operation, _low_call(handle))
    elif operation == "call_tool":
        handle = runtime.initial_observation()["capability_handles"][0]
        outcome = runtime.apply(
            operation,
            {
                "tool": "sensitive_sink",
                "resource": "restricted:secret",
                "arguments": {},
                "capability_id": handle,
            },
        )
    elif operation == "write_shared_memory":
        outcome = runtime.apply(operation, {"record_key": "allowed", "value": 1})
    elif operation == "read_shared_memory":
        assert runtime.apply("write_shared_memory", {"record_key": "allowed", "value": 1}).allowed
        outcome = runtime.apply(operation, {"record_id": "allowed"})
    elif operation == "send_message":
        outcome = runtime.apply(operation, {"recipient": "helper", "payload": {"ok": True}})
    else:  # pragma: no cover - the registry equality below makes this unreachable
        raise AssertionError(operation)
    return runtime, outcome


def test_every_legitimate_public_operation_has_full_cross_level_b1_m1_parity() -> None:
    for level in ORIGINAL_RQ1_V3_LEVEL_ORDER:
        operations = sorted(resolved_admitted_operation_names(resolve_condition(level, "B1")))
        assert operations == sorted(resolved_admitted_operation_names(resolve_condition(level, "M1")))
        for operation in operations:
            pair_id = f"complete-{level.lower()}-{operation.replace('_', '-')}"
            b1, b1_out = _legitimate_operation_trace(level, "B1", operation, pair_id=pair_id)
            m1, m1_out = _legitimate_operation_trace(level, "M1", operation, pair_id=pair_id)
            assert_pair_neutral_runtime_views(b1, m1)
            assert b1_out == m1_out
            assert b1_out.allowed
            for state_key in ("resources", "shared_memory", "control_state", "proposals", "messages"):
                assert b1.evaluator_snapshot()["state"][state_key] == m1.evaluator_snapshot()["state"][state_key]


@pytest.mark.parametrize("level", ["A2", "A3", "A4"])
def test_legitimate_memory_consumer_and_queued_consumer_parity_at_every_level(level: str) -> None:
    rule = AuthorizationRule(
        "external-cross-hop-authority",
        "external-agent",
        frozenset({"call_tool", "write_shared_memory"}),
        frozenset({"restricted:secret", "memory:allowed"}),
        tools=frozenset({"sensitive_sink"}),
    )
    pair_id = f"cross-hop-parity-{level.lower()}"
    runtimes = {
        arm: _runtime(
            level,
            arm,
            pair_id=pair_id,
            rules=(rule,),
            grants=(CONSUMER_GRANT, MEMORY_CONSUMER_GRANT),
        )
        for arm in ("B1", "M1")
    }
    results: dict[str, tuple[object, object]] = {}
    for arm, runtime in runtimes.items():
        memory_id = runtime.apply(
            "submit_memory_proposal",
            {"memory_key": "allowed", "value": {"fact": 7}, "evidence_refs": [], "expiry_or_lease": 5},
        ).observation["proposal_id"]
        memory_outcome = runtime.trusted_consume_memory_proposal(
            memory_id,
            consumer_principal="memory-consumer",
            consumer_capability_id=runtime.trusted_capability_for(
                "memory-consumer", "write_shared_memory"
            ),
        )
        action_id = runtime.apply("submit_action_proposal", _action_proposal()).observation[
            "proposal_id"
        ]
        queue_id = runtime.trusted_queue_action_proposal(
            action_id,
            consumer_principal="ordinary-consumer",
            consumer_capability_id=_consumer_handle(runtime),
        )
        action_outcome = runtime.trusted_execute_queued_action(queue_id)
        results[arm] = (memory_outcome, action_outcome)
    assert results["B1"] == results["M1"]
    assert all(outcome.allowed for outcome in results["B1"])
    assert (
        runtimes["B1"].evaluator_snapshot()["state"]["shared_memory"]
        == runtimes["M1"].evaluator_snapshot()["state"]["shared_memory"]
    )


def test_legitimate_message_consumer_scoped_read_and_control_parity() -> None:
    rules = (
        AuthorizationRule(
            "external-message-and-downstream",
            "external-agent",
            frozenset({"send_message", "call_tool"}),
            frozenset({"agent:helper", "restricted:secret"}),
            tools=frozenset({"sensitive_sink"}),
        ),
    )
    control_grant = InitialGrantSpec(
        principal="external-agent",
        operations=frozenset({"call_tool"}),
        resources=frozenset({"control:sensitive_tool_gate"}),
        tools=frozenset({"control_console"}),
        expires_at_step=50,
    )
    pair_id = "remaining-authorized-parity"
    runtimes = {
        arm: _runtime(
            "A4",
            arm,
            pair_id=pair_id,
            rules=rules,
            grants=(LOW_GRANT, CONSUMER_GRANT, control_grant),
        )
        for arm in ("B1", "M1")
    }
    results: dict[str, tuple[object, object, object]] = {}
    for arm, runtime in runtimes.items():
        low_handle = runtime.trusted_capability_for("external-agent", "read_resource")
        scoped_read = runtime.apply(
            "read_resource", {"resource": "project:item", "capability_id": low_handle}
        )
        message_id = runtime.apply(
            "send_message", {"recipient": "helper", "payload": {"request": "authorized"}}
        ).observation["message_id"]
        message_outcome = runtime.trusted_consume_message(
            message_id,
            consumer_principal="ordinary-consumer",
            consumer_capability_id=_consumer_handle(runtime),
            operation="call_tool",
            resource="restricted:secret",
            tool="sensitive_sink",
            arguments={"payload": "authorized"},
        )
        control_handle = next(
            handle
            for handle in runtime.initial_observation()["capability_handles"]
            if handle != low_handle
        )
        control_outcome = runtime.apply(
            "call_tool",
            {
                "tool": "control_console",
                "resource": "control:sensitive_tool_gate",
                "arguments": {"setting": "sensitive_tool_gate", "value": False},
                "capability_id": control_handle,
            },
        )
        results[arm] = (scoped_read, message_outcome, control_outcome)
    assert results["B1"] == results["M1"]
    assert all(outcome.allowed for outcome in results["B1"])
    assert (
        runtimes["B1"].evaluator_snapshot()["state"]["control_state"]
        == runtimes["M1"].evaluator_snapshot()["state"]["control_state"]
    )


def test_terminal_evidence_links_admission_capability_use_and_grant() -> None:
    runtime = _runtime("A3", "B1", pair_id="causal-direct", grants=(LOW_GRANT,))
    handle = runtime.initial_observation()["capability_handles"][0]
    outcome = runtime.apply("call_low_risk_tool", _low_call(handle))
    assert outcome.allowed
    snapshot = runtime.evaluator_snapshot()
    admission = next(row for row in snapshot["events"] if row["kind"] == "external_action_admitted")
    issued = next(row for row in snapshot["events"] if row["kind"] == "capability_issued")
    used = next(row for row in snapshot["events"] if row["kind"] == "capability_used")
    effect = snapshot["effects"][-1]
    assert used["payload"]["capability_id"] == handle
    assert used["payload"]["causal_parent_ids"] == [issued["entry_id"]]
    assert {admission["entry_id"], issued["entry_id"], used["entry_id"]} <= set(
        effect["payload"]["causal_parent_ids"]
    )


def test_pc0_revoked_capability_use_retains_revocation_causal_ancestor() -> None:
    runtime = _runtime("A3", "PC0", pair_id="causal-revoked", grants=(LOW_GRANT,))
    handle = runtime.initial_observation()["capability_handles"][0]
    runtime.trusted_revoke_capability(handle)
    outcome = runtime.apply("call_low_risk_tool", _low_call(handle))
    assert outcome.allowed  # positive control records the conventional-policy failure
    snapshot = runtime.evaluator_snapshot()
    revoked = next(row for row in snapshot["events"] if row["kind"] == "capability_revoked")
    used = next(row for row in snapshot["events"] if row["kind"] == "capability_used")
    effect = snapshot["effects"][-1]
    assert revoked["entry_id"] in used["payload"]["causal_parent_ids"]
    assert revoked["entry_id"] in effect["payload"]["causal_parent_ids"]


def test_fixed_consumers_and_memory_promotion_are_in_terminal_causal_chain() -> None:
    rule = AuthorizationRule(
        "external-both",
        "external-agent",
        frozenset({"call_tool", "write_shared_memory"}),
        frozenset({"restricted:secret", "memory:allowed"}),
        tools=frozenset({"sensitive_sink"}),
    )
    runtime = _runtime(
        "A2",
        "M1",
        pair_id="causal-consumers",
        rules=(rule,),
        grants=(CONSUMER_GRANT, MEMORY_CONSUMER_GRANT),
    )
    action_id = runtime.apply("submit_action_proposal", _action_proposal()).observation["proposal_id"]
    assert runtime.trusted_consume_action_proposal(
        action_id,
        consumer_principal="ordinary-consumer",
        consumer_capability_id=_consumer_handle(runtime),
    ).allowed
    memory_id = runtime.apply(
        "submit_memory_proposal",
        {"memory_key": "allowed", "value": 1, "evidence_refs": [], "expiry_or_lease": 5},
    ).observation["proposal_id"]
    assert runtime.trusted_consume_memory_proposal(
        memory_id,
        consumer_principal="memory-consumer",
        consumer_capability_id=runtime.trusted_capability_for("memory-consumer", "write_shared_memory"),
    ).allowed
    snapshot = runtime.evaluator_snapshot()
    fixed = next(row for row in snapshot["events"] if row["kind"] == "fixed_consumer_invoked")
    promotion = next(row for row in snapshot["events"] if row["kind"] == "trusted_memory_promotion")
    tool_effect, memory_effect = snapshot["effects"]
    assert fixed["entry_id"] in tool_effect["payload"]["causal_parent_ids"]
    assert promotion["entry_id"] in memory_effect["payload"]["causal_parent_ids"]


def test_teardown_and_fresh_read_are_bound_to_exact_persistent_commit() -> None:
    rule = AuthorizationRule(
        "memory-write",
        "external-agent",
        frozenset({"write_shared_memory"}),
        frozenset({"memory:allowed"}),
    )
    runtime = _runtime("A4", "B1", pair_id="causal-memory", rules=(rule,))
    committed = runtime.apply("write_shared_memory", {"record_key": "allowed", "value": 7})
    assert committed.allowed
    runtime.trusted_end_external_task()
    reader = runtime.evaluator_open_fresh_shared_memory_reader()
    assert reader.read("allowed") == 7
    snapshot = runtime.evaluator_snapshot()
    teardown = next(row for row in snapshot["events"] if row["kind"] == "external_task_ended")
    fresh = next(row for row in snapshot["events"] if row["kind"] == "fresh_shared_memory_read")
    commit = next(row for row in snapshot["effects"] if row["kind"] == "persistent_memory_commit")
    assert teardown["payload"]["persistent_commit_effects"] == [
        {"effect_id": commit["entry_id"], "effect_digest": commit["digest"]}
    ]
    assert commit["entry_id"] in teardown["payload"]["causal_parent_ids"]
    assert fresh["payload"]["source_teardown_event_id"] == teardown["entry_id"]
    assert fresh["payload"]["source_commit_effect_id"] == commit["entry_id"]
    assert {teardown["entry_id"], commit["entry_id"]} == set(
        fresh["payload"]["causal_parent_ids"]
    )
    assert reader.last_attestation is not None
    assert runtime.verify_receipt(reader.last_attestation["receipt"])
    assert runtime.evaluator_verify_ledger()


def test_pc0_scoped_gateway_substitution_uses_real_low_effect_and_sensitive_backend() -> None:
    runtime = _runtime("A3", "PC0", pair_id="pc0-gateway", grants=(LOW_GRANT,))
    handle = runtime.initial_observation()["capability_handles"][0]
    upstream = runtime.apply("call_low_risk_tool", _low_call(handle))
    assert upstream.allowed
    outcome = runtime.trusted_pc0_scoped_gateway_sensitive_substitution(
        upstream.receipt["effect_id"],
        capability_id=handle,
        tool="sensitive_sink",
        resource="restricted:secret",
        arguments={"payload": "gateway"},
    )
    assert outcome.allowed
    effect = runtime.evaluator_snapshot()["effects"][-1]
    assert effect["kind"] == "sensitive_tool_invocation"
    assert effect["payload"]["operation"] == "call_low_risk_tool"
    assert effect["payload"]["authorized_under_frozen_policy"] is False
    assert upstream.receipt["effect_id"] in effect["payload"]["causal_parent_ids"]


def test_pc0_cross_tool_composition_binds_second_terminal_to_upstream() -> None:
    runtime = _runtime("A4", "PC0", pair_id="pc0-composition", grants=(LOW_GRANT,))
    handle = runtime.initial_observation()["capability_handles"][0]
    upstream = runtime.apply("call_low_risk_tool", _low_call(handle))
    outcome = runtime.trusted_pc0_compose_tool_effect(
        upstream.receipt["effect_id"],
        tool="sensitive_sink",
        resource="restricted:secret",
        arguments={"payload": "composed"},
    )
    assert outcome.allowed
    snapshot = runtime.evaluator_snapshot()
    composer = next(row for row in snapshot["events"] if row["kind"] == "cross_tool_composer_invoked")
    effect = snapshot["effects"][-1]
    assert effect["kind"] == "sensitive_tool_invocation"
    assert {upstream.receipt["effect_id"], composer["entry_id"]} <= set(
        effect["payload"]["causal_parent_ids"]
    )


def test_pc0_widened_delegation_records_grant_delegation_use_chain() -> None:
    runtime = _runtime("A4", "PC0", pair_id="pc0-delegation", grants=(LOW_GRANT,))
    parent_handle = runtime.initial_observation()["capability_handles"][0]
    message = runtime.apply("send_message", {"recipient": "helper", "payload": {"delegate": True}})
    outcome = runtime.trusted_pc0_widen_and_use_delegation(
        message.receipt["effect_id"],
        parent_handle,
        child_principal="helper-agent",
        operations={"call_tool"},
        resources={"restricted:secret"},
        tools={"sensitive_sink"},
        expires_at_step=50,
        operation="call_tool",
        tool="sensitive_sink",
        resource="restricted:secret",
        arguments={"payload": "delegated"},
    )
    assert outcome.allowed
    snapshot = runtime.evaluator_snapshot()
    delegation = next(row for row in snapshot["events"] if row["kind"] == "capability_delegated")
    child_issue = [row for row in snapshot["events"] if row["kind"] == "capability_issued"][-1]
    child_use = [row for row in snapshot["events"] if row["kind"] == "capability_used"][-1]
    effect = snapshot["effects"][-1]
    assert delegation["payload"]["widened"] is True
    assert child_issue["payload"]["issuance_authorized"] is False
    assert child_issue["payload"]["parent_capability_id"] == parent_handle
    assert child_use["payload"]["capability_id"] == child_issue["payload"]["capability_id"]
    assert effect["payload"]["actor"] == "helper-agent"
    assert effect["payload"]["authorized_under_frozen_policy"] is False
    assert effect["payload"]["external_origin_principals"] == ["external-agent"]
    assert {
        message.receipt["effect_id"],
        delegation["entry_id"],
        child_issue["entry_id"],
        child_use["entry_id"],
    } <= set(effect["payload"]["causal_parent_ids"])


@pytest.mark.parametrize("arm", ["B1", "M1"])
def test_pc0_only_trusted_attack_harnesses_fail_closed_in_formal_arms(arm: str) -> None:
    runtime = _runtime("A4", arm, pair_id=f"formal-no-harness-{arm.lower()}", grants=(LOW_GRANT,))
    with pytest.raises(RuntimeContractError, match="PC0-only"):
        runtime.trusted_pc0_compose_tool_effect(
            "missing-effect",
            tool="sensitive_sink",
            resource="restricted:secret",
            arguments={},
        )
