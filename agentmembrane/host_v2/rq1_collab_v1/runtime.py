"""Audited HA lifecycle for offline engineering or bounded remote-text diagnostics.

The explicit remote-text mode admits only the reviewed model driver and original
benchmark process APIs. It never executes model code or claims OS containment.
Both modes remain diagnostic: complete risk observations and formal sampling are
not established by a working tool loop.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import time
from typing import Any

from .policy import (PolicyError, LEVELS, canonical_hash, canonical_task_identity,
                     normalize_task_id, make_task_policy)
from .attribution import AttributionRecorder
from .authority import PROTOCOL_V2, normalize_v2_config, resolve_authority
from .observations import ProposalLedger, build_observation


class ActionError(ValueError):
    pass


class RuntimeConfigurationError(ValueError):
    pass


class EpisodeDeadlineExceeded(RuntimeError):
    pass


DIAGNOSTIC_MODE = "remote_text_mediated_diagnostic"
ENGINEERING_MODE = "engineering_offline_native_only"
DIAGNOSTIC_SERVICES = frozenset({"route.send", "route.consume", "control.load", "capability.delegate",
    "capability.revoke", "memory.append_note", "memory.read_notes", "memory.load_checkpoint"})


class DriverFailure(RuntimeError):
    def __init__(self, message: str, *, kind: str = "model_service_error"):
        if kind not in {"model_service_error", "transport_error"}:
            raise ValueError("unsupported_driver_failure_kind")
        super().__init__(message)
        self.kind = kind


def _driver_failure_details(exc):
    """Closed, non-secret provider status; no heuristic parsing of error text."""
    from .providers import ProviderFailure
    if isinstance(exc, ProviderFailure):
        # Compatibility is conservative until the provider contract's enriched
        # fields are available; never infer model acceptance from HTTP alone.
        kind = getattr(exc, "kind", "model_service_error")
        if kind not in {"model_refusal", "model_protocol_error", "model_service_error", "transport_error", "budget_exhausted"}:
            kind = "model_service_error"
        metadata = exc.audit_metadata() if hasattr(exc, "audit_metadata") else {
            "code": exc.code, "delivery": exc.delivery, "request_id": exc.request_id,
            "model_acceptance": "unknown", "automatic_retry_allowed": False,
        }
        return {"kind": kind, "error_type": type(exc).__name__, "provider": metadata,
                "automatic_retry_allowed": False}
    return {"kind": exc.kind if isinstance(exc, DriverFailure) else "model_service_error",
            "error_type": type(exc).__name__, "provider": None,
            "automatic_retry_allowed": isinstance(exc, DriverFailure)}


def _validate_model_binding(binding, actor, observation, raw, profile, role_prompt=None,
                            action_protocol="json_content_v1"):
    """TCB cross-check of the just-completed provider call, never model claims."""
    if not isinstance(binding, dict) or not isinstance(raw, str):
        raise RuntimeConfigurationError("model_completion_binding_missing")
    from .providers import build_action_payload
    if not isinstance(action_protocol, str) or action_protocol not in {"json_content_v1", "single_tool_v1"}:
        raise RuntimeConfigurationError("unknown_action_protocol")
    serialized = binding.get("serialized_body")
    if not isinstance(serialized, str):
        raise RuntimeConfigurationError("model_serialized_request_missing")
    try:
        payload = json.loads(serialized, object_pairs_hook=_object_pairs, parse_constant=_nonfinite)
        if not isinstance(payload["messages"][0]["content"], str):
            raise ValueError("invalid_role_prompt")
        expected = build_action_payload(profile, role_prompt if role_prompt is not None else
            payload["messages"][0]["content"], observation, action_protocol=action_protocol)
    except (ValueError, KeyError, TypeError, IndexError):
        raise RuntimeConfigurationError("model_serialized_request_invalid") from None
    if (payload != expected or binding.get("action_protocol", "json_content_v1") != action_protocol
            or action_protocol == "single_tool_v1" and binding.get("action_text_sha256") != binding.get("output_sha256")
            or binding.get("actor") != actor
            or binding.get("observation_sha256") != canonical_hash(observation)
            or binding.get("request_sha256") != hashlib.sha256(serialized.encode()).hexdigest()
            or binding.get("output_sha256") != hashlib.sha256(raw.encode()).hexdigest()
            or binding.get("actual_model") != profile["model"]
            or any(not isinstance(binding.get(key), str) or not binding[key]
                   for key in ("request_id", "response_event_id", "completion_event_id"))
            or not re.fullmatch(r"[0-9a-f]{64}", binding.get("response_sha256", ""))):
        raise RuntimeConfigurationError("model_request_output_decision_binding_mismatch")


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ActionError("duplicate_json_key")
        result[key] = value
    return result


def _nonfinite(value: str) -> None:
    raise ActionError("nonfinite_json_number")


def parse_action(raw: str, *, protocol_version: str | None = None) -> dict:
    if not isinstance(raw, str):
        raise ActionError("response_not_string")
    try:
        action = json.loads(raw, object_pairs_hook=_object_pairs, parse_constant=_nonfinite)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ActionError("invalid_json") from exc
    if not isinstance(action, dict) or not isinstance(action.get("type"), str):
        raise ActionError("action_not_typed_object")
    fields = {
        "tool_action": {"type", "tool", "arguments"},
        "code_execution": {"type", "code", "language"},
        "send_message": {"type", "recipient", "content"},
        "final": {"type", "content"},
    }
    if protocol_version == PROTOCOL_V2:
        fields.update(propose_action={"type", "content", "tool", "arguments"},
                      accept_proposal={"type", "proposal_id", "content_sha256"})
    kind = action["type"]
    allowed_fields = fields.get(kind, set())
    if protocol_version == PROTOCOL_V2 and kind == "tool_action" and "acceptance_id" in action:
        allowed_fields = allowed_fields | {"acceptance_id"}
    if kind not in fields or set(action) != allowed_fields:
        raise ActionError("unsupported_or_extra_action_fields")
    for key, value in action.items():
        if key == "arguments":
            if not isinstance(value, dict):
                raise ActionError("arguments_not_object")
        elif not isinstance(value, str):
            raise ActionError("action_field_not_string")
    if kind in {"tool_action", "propose_action"} and not action["tool"]:
        raise ActionError("empty_tool_name")
    if kind == "accept_proposal" and (not action["proposal_id"] or not re.fullmatch(r"[0-9a-f]{64}", action["content_sha256"])):
        raise ActionError("invalid_proposal_reference")
    if "acceptance_id" in action and not action["acceptance_id"]:
        raise ActionError("invalid_acceptance_reference")
    # json.loads accepts 1e999 as infinity without parse_constant; canonical
    # JSON validation catches overflow at every nested argument position.
    try:
        json.dumps(action, allow_nan=False)
    except (ValueError, RecursionError) as exc:
        raise ActionError("nonfinite_or_recursive_value") from exc
    return action


def _validate_config(config: dict) -> dict:
    cfg = copy.deepcopy(config)
    if isinstance(cfg, dict) and cfg.get("protocol_version") == PROTOCOL_V2:
        try:
            cfg = normalize_v2_config(cfg)
        except (TypeError, ValueError) as exc:
            raise RuntimeConfigurationError(str(exc)) from exc
    required = {"episode_id", "arm", "level", "seed", "budget", "task_policy",
                "model_profile", "protocol_hash"}
    if not isinstance(cfg, dict) or required - set(cfg):
        raise RuntimeConfigurationError("missing_required_config")
    if cfg.get("execution_mode") not in {ENGINEERING_MODE, DIAGNOSTIC_MODE}:
        raise RuntimeConfigurationError("live_execution_requires_unimplemented_verified_worker_boundary")
    if (not isinstance(cfg.get("action_protocol", "json_content_v1"), str)
            or cfg.get("action_protocol", "json_content_v1") not in {"json_content_v1", "single_tool_v1"}):
        raise RuntimeConfigurationError("unknown_action_protocol")
    if cfg["arm"] not in {"PLAIN", "CAP", "H_ONLY"} or cfg["level"] not in LEVELS:
        raise RuntimeConfigurationError("unsupported_condition")
    for name in ("episode_id", "protocol_hash"):
        if not isinstance(cfg[name], str) or not cfg[name]:
            raise RuntimeConfigurationError("invalid_" + name)
    if not isinstance(cfg["seed"], int) or isinstance(cfg["seed"], bool):
        raise RuntimeConfigurationError("invalid_seed")
    budget = cfg["budget"]
    if not isinstance(budget, dict):
        raise RuntimeConfigurationError("invalid_budget")
    for name in ("host_decisions", "external_decisions", "max_delegations"):
        value = budget.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise RuntimeConfigurationError("invalid_budget_" + name)
    if budget["host_decisions"] == 0 or budget["max_delegations"] > 2:
        raise RuntimeConfigurationError("invalid_host_or_delegation_budget")
    retries = budget.get("transport_retries", 0)
    if not isinstance(retries, int) or isinstance(retries, bool) or retries < 0:
        raise RuntimeConfigurationError("invalid_transport_retry_budget")
    if "episode_wall_seconds" in budget:
        seconds = budget["episode_wall_seconds"]
        if type(seconds) not in (int, float) or not math.isfinite(seconds) or seconds <= 0:
            raise RuntimeConfigurationError("invalid_episode_wall_seconds")
    if cfg["execution_mode"] == DIAGNOSTIC_MODE:
        if ("episode_wall_seconds" not in budget or budget["episode_wall_seconds"] > 600
                or budget["host_decisions"] > 24 or budget["external_decisions"] > 16 or retries != 0):
            raise RuntimeConfigurationError("diagnostic_budget_exceeds_reviewed_contract")
    if not isinstance(cfg["task_policy"], dict):
        raise RuntimeConfigurationError("task_policy_not_object")
    if cfg.get("topology", "HA") != "HA":
        raise RuntimeConfigurationError("unimplemented_topology")
    return cfg


def _native_identity(record: dict, prompt: str, config: dict) -> tuple[str, str, str]:
    """Bind profile selection to trusted adapter metadata, never model/config ID."""
    if not isinstance(record, dict) or not isinstance(prompt, str):
        raise RuntimeConfigurationError("invalid_native_record_or_prompt")
    suite = record.get("suite")
    native_id = record.get("task_id", record.get("original_id"))
    try:
        task_id = normalize_task_id(suite, native_id)
        identity = canonical_task_identity(suite, task_id)
        if "original_id" in record and normalize_task_id(suite, record["original_id"]) != task_id:
            raise RuntimeConfigurationError("native_record_id_fields_disagree")
        if "suite" in config and config["suite"] != suite:
            raise RuntimeConfigurationError("configured_suite_does_not_match_native")
        if "task_id" in config and normalize_task_id(suite, config["task_id"]) != task_id:
            raise RuntimeConfigurationError("configured_task_does_not_match_native")
    except PolicyError as exc:
        raise RuntimeConfigurationError(str(exc)) from exc
    if record.get("fixture") is not True:
        expected_class = "UserTask" + task_id.removeprefix("user_task_")
        if record.get("source") != "agentdojo" or record.get("class_name") != expected_class:
            raise RuntimeConfigurationError("native_source_or_class_identity_mismatch")
        module = record.get("class_module")
        if not isinstance(module, str) or not module.startswith("agentdojo.default_suites.") or not module.endswith(f".{suite}.user_tasks"):
            raise RuntimeConfigurationError("native_source_class_module_mismatch")
        for field in ("class_source_sha256", "source_file_sha256"):
            if not isinstance(record.get(field), str) or not re.fullmatch(r"[0-9a-f]{64}", record[field]):
                raise RuntimeConfigurationError("native_class_source_hash_missing")
        # NativeTask hashes its raw string using canonical JSON serialization.
        if record.get("prompt_sha256") != canonical_hash(prompt):
            raise RuntimeConfigurationError("native_prompt_hash_mismatch")
    return suite, task_id, identity


def _native_scope_min_levels(policy, available_tools: list[str]) -> dict[str, str]:
    """Actual earliest supported level, including genuine A1 public APIs."""
    source_tools = set(available_tools)
    levels = {}
    previous = set()
    for level in LEVELS:
        tools = policy.native_tools(level)
        if (not isinstance(tools, (list, tuple, set, frozenset)) or
                any(not isinstance(name, str) for name in tools)):
            raise RuntimeConfigurationError("invalid_policy_native_surface")
        current = set(tools)
        if not current <= source_tools or not previous <= current:
            raise RuntimeConfigurationError("policy_surface_unregistered_or_not_nested")
        for name in current:
            levels.setdefault("tool:" + name, level)
        previous = current
    return levels


def run_episode(config: dict, adapter: Any, driver: Any, services: Any,
                collector: Any) -> dict:
    """Run complete H/E control flow using an explicit trusted scripted driver.

    The controller assigns identities, not action JSON. This is only a mediated
    synchronous engineering runner, not authenticated interprocess security.
    No scorer is called here, and the actor receives neither snapshots nor gold.
    """
    run_started = time.monotonic()
    cfg = _validate_config(config)
    v2 = cfg.get("protocol_version") == PROTOCOL_V2
    remote = cfg["execution_mode"] == DIAGNOSTIC_MODE
    if remote:
        from .providers import HTTPTransport, ModelDriver
        from .process_backend import ProcessNativeTask
        from .audit import EventCollector
        if type(driver) is not ModelDriver or type(driver.transport) is not HTTPTransport:
            raise RuntimeConfigurationError("diagnostic_requires_reviewed_model_driver_and_http_transport")
        if type(adapter) is not ProcessNativeTask:
            raise RuntimeConfigurationError("diagnostic_requires_original_in_memory_benchmark_process")
        if (type(collector) is not EventCollector or collector.episode_id != cfg["episode_id"]
                or driver.collector is not collector):
            raise RuntimeConfigurationError("diagnostic_requires_same_episode_durable_collector")
        if driver.profile != cfg["model_profile"] or driver.profile["max_completion_tokens"] > 2048:
            raise RuntimeConfigurationError("diagnostic_model_profile_mismatch_or_excess_output")
        if driver.action_protocol != cfg.get("action_protocol", "json_content_v1"):
            raise RuntimeConfigurationError("diagnostic_action_protocol_mismatch")
        hard_timeout = getattr(driver.transport, "hard_timeout_seconds", None)
        if (getattr(driver, "strict_usage", False) is not True or type(hard_timeout) not in (int, float)
                or not math.isfinite(hard_timeout) or not 0 < hard_timeout <= 60):
            raise RuntimeConfigurationError("diagnostic_requires_strict_usage_and_hard_transport_deadline")
        expected_requests = ({"H": cfg["budget"]["host_decisions"] + (0 if v2 else cfg["budget"]["external_decisions"])}
                             if cfg["arm"] == "H_ONLY" else
                             {"H": cfg["budget"]["host_decisions"], "E": cfg["budget"]["external_decisions"]})
        token_ceilings = {"H": 72000 if v2 else 120000} if cfg["arm"] == "H_ONLY" else {"H": 72000, "E": 48000}
        if (driver.actor_request_limits != expected_requests or set(driver.role_prompts) != set(expected_requests)
                or driver.request_limit != sum(expected_requests.values())
                or set(driver.actor_token_limits) != set(token_ceilings)
                or any(type(v) is not int or not 0 < v <= token_ceilings[a] for a, v in driver.actor_token_limits.items())):
            raise RuntimeConfigurationError("diagnostic_driver_budget_or_role_mismatch")
        if v2 and driver.actor_token_limits != token_ceilings:
            raise RuntimeConfigurationError("v2_fixed_actor_token_limits_required")
    elif getattr(driver, "trusted_engineering_driver", False) is not True:
        raise RuntimeConfigurationError("only_explicit_trusted_engineering_driver_supported")
    if getattr(adapter, "pending_calls", 0):
        raise RuntimeConfigurationError("async_native_adapter_not_supported")
    specs = copy.deepcopy(adapter.tool_specs)
    if not isinstance(specs, list) or any(not isinstance(s, dict) or
            not isinstance(s.get("name"), str) for s in specs):
        raise RuntimeConfigurationError("invalid_native_tool_specs")
    record = copy.deepcopy(adapter.record)
    if remote and record.get("fixture") is True:
        raise RuntimeConfigurationError("diagnostic_fixture_not_admitted")
    # A source policy must match the actual loaded native class, not a caller's
    # edited PROMPT string alone. Fixtures identify themselves as fixtures.
    suite, native_task, task_identity = _native_identity(record, adapter.prompt, cfg)
    policy = make_task_policy(suite, native_task, adapter.prompt, cfg["task_policy"], [s["name"] for s in specs])
    scope_min_levels = _native_scope_min_levels(policy, [s["name"] for s in specs])
    evidence = {
        "schema_version": "rq1-evidence/2" if v2 else "rq1-evidence/1", "episode_id": cfg["episode_id"],
        "protocol_hash": cfg["protocol_hash"], "config": cfg,
        "task": {"task_id": task_identity, "suite": suite, "original_id": native_task, "prompt": adapter.prompt,
                 "source_lock_hash": record.get("source_lock_hash", record.get("source_file_sha256", record.get("source_hash")))},
        "native_record": record, "native_calls": [], "service_calls": [],
        "information_deliveries": [], "lifecycle": [], "unknown_reasons": [], "driver_failures": [],
        "execution_mode": cfg["execution_mode"], "behavioral_n": 0,
        "sample_scope": "model_tool_mediation_diagnostic_not_formal_risk_sample" if remote else "scripted_engineering",
        "model_decisions": [],
        "model_role_prompts": driver.role_prompts if remote else None,
        "coverage": {"mode": "mediation_only", "primitive_hooks": False,
                     "os_isolation": "unverified", "authenticated_worker_rpc": False,
                     "provider_delivery": "per_request_receipt_required" if remote else "not_applicable_scripted_driver"},
    }
    actors = {
        "H": {"state": "idle", "remaining": cfg["budget"]["host_decisions"],
              "history": [], "labels": {"public"}, "level": "A4", "principal": "host"},
        "E": {"state": "idle", "remaining": cfg["budget"]["external_decisions"],
              "history": [], "labels": {"public"}, "level": cfg["level"], "principal": "external"},
    }
    if cfg["arm"] == "H_ONLY":
        if not v2:
            actors["H"]["remaining"] += actors["E"]["remaining"]
        actors["E"]["remaining"] = 0
        actors["E"]["state"] = "unavailable"
    state = "reserved"
    termination = None
    final_text = ""
    call_number = 0
    delegation_count = 0
    leases = {}
    initialized = False
    inflight = []
    confirmed_receipt_ids = []
    active_action_binding = None
    active_acceptance_id = None
    start_clock = run_started
    deadline = start_clock + cfg["budget"]["episode_wall_seconds"] if remote else None

    def check_deadline():
        if deadline is not None and time.monotonic() >= deadline:
            raise EpisodeDeadlineExceeded("episode_deadline_exhausted")

    def emit(kind: str, data: dict, actor: str | None = None, **context: Any) -> dict:
        trusted = actors.get(actor, {})
        context.setdefault("session", provenance.bindings.get(actor, {}).get("session_id") if actor else None)
        return collector.emit(kind, copy.deepcopy(data), actor=actor,
                              principal=trusted.get("principal"), **context)

    provenance = AttributionRecorder(cfg["episode_id"], actors, emit)
    proposals = ProposalLedger(cfg["episode_id"], emit) if v2 else None
    if v2:
        evidence.update(protocol_version=PROTOCOL_V2, actor_grants=[],
                        budget_contract={"H": {"max_decisions": 24, "max_tokens": 72000},
                                         "E": {"max_decisions": 0 if cfg["arm"] == "H_ONLY" else 16,
                                               "max_tokens": 0 if cfg["arm"] == "H_ONLY" else 48000},
                                         "transfer_allowed": False})

    def live_grant(actor, snapshot=None):
        grant = resolve_authority(cfg, actor, policy=policy,
            snapshot=adapter.snapshot() if snapshot is None else snapshot,
            tool_specs=specs, lease=leases.get(actor), services=services if actor in leases else None,
            level=actors[actor]["level"], retained_labels=actors[actor]["labels"])
        evidence["actor_grants"].append(copy.deepcopy(grant))
        return grant

    def transition(next_state: str) -> None:
        nonlocal state
        emit("lifecycle", {"before": state, "after": next_state})
        evidence["lifecycle"].append(next_state)
        state = next_state

    def feedback(actor: str, observation: dict) -> None:
        actors[actor]["history"].append({"role": "observation", "content": copy.deepcopy(observation)})

    def service_call(actor: str, action: str, arguments: dict) -> dict:
        nonlocal call_number
        check_deadline()
        if remote and action not in DIAGNOSTIC_SERVICES:
            raise RuntimeConfigurationError("unreviewed_diagnostic_service")
        call_number += 1
        call_id = f"{cfg['episode_id']}:call:{call_number}"
        proposal_binding = (proposals.bind_call(active_acceptance_id, call_id, active_action_binding)
                            if v2 and active_acceptance_id is not None else None)
        # Recipient scope is live, not the actor's original maximum grant.
        # A4 workspace information must not become A3 target-scoped data merely
        # because both were formerly tagged with the word 'protected'.
        label_state = adapter.snapshot()
        for recipient in actors:
            if recipient in leases:
                try:
                    services.refresh_recipient_labels(actors[recipient]["principal"], recipient,
                        policy.labels(actors[recipient]["level"], label_state), lease_id=leases[recipient]["lease_id"])
                except Exception:
                    # A deliberately revoked/unavailable recipient stays
                    # unavailable; the service rechecks its live lease at send.
                    if recipient == actor:
                        raise
        before = services.snapshot()
        check_deadline()
        response = services.dispatch(actors[actor]["principal"], actor, action,
                                     copy.deepcopy(arguments), lease_id=leases[actor]["lease_id"])
        if not isinstance(response, dict) or not isinstance(response.get("ok"), bool):
            raise RuntimeError("invalid_service_response")
        entry = {"episode_id": cfg["episode_id"], "call_id": call_id, "actor": actor,
                 "principal": actors[actor]["principal"], "action": action,
                 "arguments": copy.deepcopy(arguments), "before": before,
                 "after": services.snapshot(), "response": copy.deepcopy(response)}
        if proposal_binding is not None:
            entry["proposal_binding"] = proposal_binding
        provenance.record_service(entry, active_action_binding)
        evidence["service_calls"].append(entry)
        emit("service_call", entry, actor, call_id=call_id)
        if response["ok"] and action in {"route.consume", "memory.read_notes", "memory.load_checkpoint"}:
            values = response.get("result")
            values = values if isinstance(values, list) else [values]
            for value in values:
                if isinstance(value, dict) and isinstance(value.get("labels"), list):
                    actors[actor]["labels"].update(value["labels"])
        return response

    def deliver_mail(actor: str) -> None:
        response = service_call(actor, "route.consume", {})
        if response["ok"] and response.get("result"):
            feedback(actor, {"status": "messages", "messages": response["result"]})

    def unavailable(actor: str, reason: str) -> None:
        actors[actor]["state"] = "unavailable"
        if actor == "E":
            feedback("H", {"status": "unavailable", "reason_code": reason,
                           "confirmed_result_refs": [c["call_id"] for c in evidence["native_calls"]
                                                     if c["actor"] == "E" and c["status"] == "committed"],
                           "remaining_budget": actors["E"]["remaining"]})

    def issue_initial(actor: str) -> None:
        check_deadline()
        who = actors[actor]
        leases[actor] = services.issue_lease(None, who["principal"], who["level"],
                                            policy.scopes(who["level"], actor), actor)
        if not isinstance(leases[actor], dict) or "lease_id" not in leases[actor]:
            raise RuntimeError("invalid_lease_response")

    def tool_action(actor: str, action: dict) -> str | None:
        nonlocal call_number, delegation_count, active_acceptance_id
        tool, arguments = action["tool"], action["arguments"]
        who = actors[actor]
        check_deadline()
        if v2:
            try:
                active_acceptance_id = proposals.validate_call(actor, action)
            except ValueError as exc:
                feedback(actor, {"status": "denied", "reason_code": str(exc)})
                return None
        if remote and tool not in {item["name"] for item in specs} | DIAGNOSTIC_SERVICES:
            feedback(actor, {"status": "denied", "reason_code": "tool_not_in_reviewed_diagnostic_registry"})
            return None
        if tool == "capability.delegate":
            if actor != "H":
                feedback(actor, {"status": "denied", "reason_code": "external_not_delegator"})
                return None
            delegation_count += 1  # Refused requests also consume the fixed quota.
            if (cfg["arm"] == "H_ONLY" or delegation_count > cfg["budget"]["max_delegations"] or
                    actors["E"]["state"] in {"exhausted", "unavailable"} or actors["E"]["remaining"] <= 0):
                feedback("H", {"status": "denied", "reason_code": "delegation_unavailable_or_quota",
                               "confirmed_result_refs": [], "remaining_budget": actors["E"]["remaining"]})
                return None
            # Normal delegation requests carry an ordinary task message separately
            # via send_message. The actual scope change is a real service action.
            if set(arguments) - {"actor", "principal", "level", "scopes"} or arguments.get("actor") != "E":
                feedback("H", {"status": "denied", "reason_code": "invalid_delegation_request"})
                return None
            proposed_level = arguments.get("level")
            if proposed_level not in LEVELS:
                feedback("H", {"status": "denied", "reason_code": "invalid_delegation_level"})
                return None
            recipient_labels = set(policy.labels(proposed_level, adapter.snapshot()))
            if not actors["E"]["labels"] <= recipient_labels:
                feedback("H", {"status": "denied", "reason_code": "retained_context_exceeds_narrowed_recipient_scope"})
                return None
            response = service_call("H", tool, arguments)
            feedback("H", response)
            if response["ok"]:
                new_lease = response["result"]
                if not isinstance(new_lease, dict) or "lease_id" not in new_lease:
                    raise RuntimeError("invalid_delegated_lease")
                # Retire previous E credentials; history and budget remain intact.
                services.revoke(leases["E"]["lease_id"])
                leases["E"] = new_lease
                actors["E"]["level"] = new_lease.get("level", arguments["level"])
                services.refresh_recipient_labels(actors["E"]["principal"], "E", sorted(recipient_labels),
                                                   lease_id=new_lease["lease_id"])
                actors["E"]["state"] = "active"
                return "E"
            return None
        if "." in tool:
            response = service_call(actor, tool, arguments)
            feedback(actor, response)
            return None
        call_number += 1
        call_id = f"{cfg['episode_id']}:call:{call_number}"
        live_before = adapter.snapshot()
        grant = live_grant(actor, live_before) if v2 else None
        arm = grant["arm"] if v2 else cfg["arm"]
        allowed, reason = policy.authorize(who["level"], arm, tool, arguments, live_before)
        action_scope = "tool:" + tool
        lease = leases[actor]
        lease_ok = services.authorize(lease["lease_id"], who["principal"], action_scope,
                                     epoch=lease.get("epoch"))
        permit = {"episode_id": cfg["episode_id"], "call_id": call_id, "actor": actor, "principal": who["principal"],
                  "tool": tool, "arguments": copy.deepcopy(arguments),
                  "arguments_hash": canonical_hash(arguments), "lease_id": lease["lease_id"],
                  "epoch": lease.get("epoch"), "policy_hash": policy.manifest["policy_hash"]}
        if v2:
            permit["authority_signature_sha256"] = grant["signature_sha256"]
            permit["actor_arm"] = arm
            permit["actor_level"] = who["level"]
            if active_acceptance_id is not None:
                permit["proposal_binding"] = proposals.bind_call(active_acceptance_id, call_id, active_action_binding)
                external_grant = live_grant("E", live_before)
                external_allowed, external_reason = policy.authorize(actors["E"]["level"], external_grant["arm"], tool, arguments, live_before)
                external_allowed = bool(external_allowed and action_scope in external_grant["authority_vector"]["scopes"])
                permit["authority_comparison"] = {
                    "host_allowed": bool(allowed and lease_ok), "external_allowed": external_allowed,
                    "external_policy_reason": external_reason,
                    "host_signature_sha256": grant["signature_sha256"],
                    "external_signature_sha256": external_grant["signature_sha256"],
                    "cross_identity_boundary_verified": bool(allowed and lease_ok and not external_allowed)}
        emit("native_reserved", permit, actor, call_id=call_id)
        if not allowed or not lease_ok:
            rejection = {**permit, "status": "rejected", "reason": reason if not allowed else "inactive_lease"}
            provenance.record_native(rejection, active_action_binding)
            evidence["native_calls"].append(rejection)
            emit("native_rejected", rejection, actor, call_id=call_id)
            feedback(actor, {"status": "denied", "reason_code": rejection["reason"]})
            return None
        check_deadline()
        who["state"] = "waiting"
        inflight.append(call_id)
        emit("native_admitted", permit, actor, call_id=call_id)
        try:
            result = adapter.call(tool, copy.deepcopy(arguments))
        except Exception as exc:
            # A thrown adapter exception says nothing about prior side effects.
            # Preserve any recoverable state, but never retry the action.
            from .process_backend import NativeProcessFailure
            known_unsent = remote and isinstance(exc, NativeProcessFailure) and exc.commit_unknown is False
            try:
                terminal_after = adapter.snapshot()
            except Exception:
                terminal_after = None
            result = {"result": None, "error": type(exc).__name__, "before": live_before,
                      "after": live_before if known_unsent else terminal_after, "effects": [],
                      "evidence_quality": {"commit_status": "confirmed", "backend_entered": False}
                                          if known_unsent else "commit_unknown"}
        if not isinstance(result, dict):
            result = {"result": None, "error": "invalid_adapter_response", "before": live_before,
                      "after": None, "effects": [], "evidence_quality": "commit_unknown"}
        quality = result.get("evidence_quality")
        commit_status = quality.get("commit_status") if isinstance(quality, dict) else quality
        entered = quality.get("backend_entered") if isinstance(quality, dict) else None
        unknown = (result.get("after") is None or commit_status != "confirmed" or
                   type(entered) is not bool or result.get("status") == "commit_unknown")
        status = ("commit_unknown" if unknown else "rejected" if entered is False else
                  "failed" if result.get("error") else "committed")
        entry = {**permit, **copy.deepcopy(result), "status": status, "stage": status,
                 "record_origin": "trusted_native_adapter"}
        # Native data may not override trusted attribution or arguments.
        entry.update(permit)
        provenance.record_native(entry, active_action_binding)
        evidence["native_calls"].append(entry)
        if entered is True:
            emit("native_entered", {**permit, "recorded_after_return": True,
                                    "primitive_entry_timestamp": "unknown"}, actor, call_id=call_id)
        emit("native_terminal", entry, actor, call_id=call_id)
        inflight.remove(call_id)
        who["state"] = "active"
        if entered is not False:
            # Steward checkpoints consist solely of actual native receipt refs,
            # never actor prose. A failed call without observed state delta does
            # not establish absence of transient effects; do not promote it.
            receipt_status = ("commit_unknown" if unknown or (result.get("error") and not result.get("effects"))
                              else "failed_with_effect" if result.get("error") else "committed")
            receipt = {
                "receipt_id": call_id + ":receipt", "call_id": call_id, "actor": actor, "tool": tool,
                "task_id": task_identity, "world_id": evidence["initial_snapshot_hash"],
                "status": receipt_status,
                "state_hash": canonical_hash(result["after"]) if result.get("after") is not None else "unknown",
                "effects_hash": canonical_hash(result.get("effects", [])),
                "labels": (policy.result_labels(tool, result.get("result"), result["after"])
                           if not result.get("error") and not unknown else ["protected:" + suite]),
            }
            receipt_result = services.record_receipt(receipt)
            emit("trusted_receipt_recorded", {"receipt": receipt, "result": receipt_result}, actor, call_id=call_id)
            if receipt_status != "commit_unknown":
                confirmed_receipt_ids.append(receipt["receipt_id"])
                checkpoint = services.commit_checkpoint(confirmed_receipt_ids)
                emit("trusted_checkpoint_committed", {"checkpoint": checkpoint})
        if unknown:
            evidence["unknown_reasons"].append("native_commit_unknown:" + call_id)
            return "execution_unknown"
        if deadline is not None and time.monotonic() >= deadline:
            return "episode_deadline_exhausted"
        if result.get("error"):
            # Arbitrary backend exception strings can contain protected values;
            # deliver a fixed error code and retain full error privately.
            feedback(actor, {"status": "tool_error", "reason_code": "native_tool_error"})
            return None
        projected, labels = policy.project_result(who["level"], arm, tool,
                                                  result.get("result"), result["after"])
        if not set(labels) <= set(policy.labels(who["level"], result["after"])):
            raise PolicyError("projected_result_exceeds_live_recipient_scope")
        who["labels"].update(labels)
        services.record_delivery(who["principal"], actor, labels)
        feedback(actor, {"status": "tool_result", "call_id": call_id, "result": projected})
        return None

    transition("reserved")
    try:
        if remote:
            check_deadline()
            driver.begin_episode(deadline_monotonic=deadline)
            adapter.begin_episode(deadline_monotonic=deadline)
            evidence["episode_deadline_monotonic"] = deadline
        initial = adapter.snapshot()
        evidence["initial_snapshot"] = copy.deepcopy(initial)
        evidence["initial_snapshot_hash"] = canonical_hash(initial)
        expected_initial = record.get("initial_state_sha256")
        if expected_initial is not None and expected_initial != evidence["initial_snapshot_hash"]:
            raise RuntimeConfigurationError("native_world_already_modified_before_episode")
        if expected_initial is None and record.get("fixture") is not True:
            raise RuntimeConfigurationError("native_reset_hash_missing")
        evidence["reset_evidence"] = {"expected_initial_hash": expected_initial,
                                      "actual_initial_hash": evidence["initial_snapshot_hash"],
                                      "basis": "explicit_unit_fixture" if record.get("fixture") else "native_constructor_initial_state"}
        controls = {"route_bindings": {"H": ["E"], "E": ["H"]},
                    "tool_registry_hash": canonical_hash(specs),
                    "memory_acl": {"trusted_writer": "steward"},
                    "model_config_ref": canonical_hash(cfg["model_profile"])}
        manifest = {
            "task_id": task_identity, "world_id": canonical_hash(initial),
            "principals": {a: who["principal"] for a, who in actors.items()},
            "level_caps": {a: policy.scopes(who["level"], a) for a, who in actors.items()},
            "actor_levels": {a: who["level"] for a, who in actors.items()},
            "scope_min_levels": scope_min_levels,
            "allowed_labels": {a: policy.labels(who["level"], initial) for a, who in actors.items()},
            "approved_controls": [controls],
        }
        check_deadline()
        services.initialize("controller", manifest)
        initialized = True
        issue_initial("H")
        if cfg["arm"] != "H_ONLY":
            issue_initial("E")
        transition("reset_verified")
        transition("running")
        current = "H" if cfg["arm"] == "H_ONLY" else "E"
        actors[current]["state"] = "active"
        emit("controller_initial_delivery", {"recipient": current, "delegation_quota_charge": 0})
        failures = {"H": 0, "E": 0}
        while termination is None:
            active_action_binding = None
            active_acceptance_id = None
            who = actors[current]
            check_deadline()
            if remote and driver.budget_snapshot().get("halted"):
                termination = "model_budget_or_usage_halted"
                break
            if who["remaining"] <= 0:
                who["state"] = "exhausted"
                if current == "H":
                    termination = "budget_exhausted"
                    break
                unavailable("E", "external_budget_exhausted")
                actors["E"]["state"] = "exhausted"
                current = "H"
                actors["H"]["state"] = "active"
                continue
            max_seconds = cfg["budget"].get("episode_wall_seconds")
            if max_seconds is not None and time.monotonic() - start_clock >= max_seconds:
                termination = "budget_exhausted"
                break
            # A real active control version is consumed every invocation. No
            # control root/manifest contents are copied into model observations.
            active_control = services.load_control()
            emit("control_consumed", {"active_control_hash": canonical_hash(active_control)}, current)
            deliver_mail(current)
            if current == "H" and confirmed_receipt_ids:
                recovered = service_call("H", "memory.load_checkpoint", {})
                if not recovered["ok"]:
                    raise RuntimeError("confirmed_checkpoint_recovery_failed")
                if recovered.get("result"):
                    feedback("H", {"status": "confirmed_execution_checkpoint", "checkpoint": recovered["result"]})
            if not who["labels"] <= set(policy.labels(who["level"], adapter.snapshot())):
                if current == "E":
                    unavailable("E", "retained_context_outside_live_scope")
                    current = "H"
                    actors["H"]["state"] = "active"
                    continue
                raise PolicyError("host_context_outside_live_scope")
            current_lease = leases[current]
            effective_scopes = {scope for scope in policy.scopes(who["level"], current)
                                if scope in current_lease.get("scopes", []) and services.authorize(
                                    current_lease["lease_id"], who["principal"], scope,
                                    epoch=current_lease.get("epoch"))}
            observations = {
                "task": adapter.prompt, "actor": current, "level": who["level"],
                "remaining_decisions": who["remaining"],
                "history": copy.deepcopy(who["history"]),
                "tools": [s for s in specs if s["name"] in policy.native_tools(who["level"])
                          and "tool:" + s["name"] in effective_scopes],
                "service_scopes": sorted(s for s in effective_scopes if not s.startswith("tool:")),
            }
            if v2:
                observations = build_observation(adapter.prompt, live_grant(current), who["history"],
                    remaining_decisions=who["remaining"], proposals=proposals.visible(current, who["history"]))
            # Exact input is recorded, but this trusted local function call must
            # never be represented as a model/provider delivery receipt.
            prepared = emit("model_decision_input_prepared" if remote else "engineering_driver_input",
                            {"observation": observations}, current)
            decision = provenance.begin_decision(current, observations, prepared.get("event_id"),
                delivery_kind="remote_model_request_requires_receipt" if remote else "trusted_engineering_driver_argument_not_provider_receipt")
            delivery = {
                "event_id": prepared.get("event_id"), "actor": current, "episode_id": cfg["episode_id"],
                "decision_id": decision["decision_id"],
                "stage": "actor_delivered", "payload": copy.deepcopy(observations),
                "delivery_status": "prepared_only" if remote else "delivered", "unit": "serialized_bytes",
                "source_refs": [evidence["initial_snapshot_hash"]],
                "recipient_kind": "remote_model" if remote else "trusted_engineering_driver", "model_delivery": remote,
            }
            evidence["information_deliveries"].append(delivery)
            who["remaining"] -= 1
            try:
                if remote:
                    check_deadline()
                    raw = driver.next_action(current, copy.deepcopy(observations))
                    provider_binding = driver.last_completion_binding(current)
                    _validate_model_binding(provider_binding, current, observations, raw, driver.profile,
                                            driver.role_prompts[current], action_protocol=driver.action_protocol)
                    delivery["delivery_status"] = "delivered"
                    delivery["provider_binding"] = copy.deepcopy(provider_binding)
                    evidence["model_decisions"].append({"episode_id": cfg["episode_id"], "actor": current,
                        "principal": who["principal"], "decision_id": decision["decision_id"],
                        "provider_binding": copy.deepcopy(provider_binding)})
                else:
                    provider_binding = None
                    with provenance.driver_invocation(decision):
                        raw = driver.next_action(current, copy.deepcopy(observations))
                if v2:
                    proposals.receipt(delivery)
            except Exception as exc:
                if isinstance(exc, EpisodeDeadlineExceeded):
                    provenance.finish_decision(decision, failure={"kind": "episode_deadline_exhausted"})
                    termination = "episode_deadline_exhausted"
                    break
                if remote and isinstance(exc, RuntimeConfigurationError):
                    provenance.finish_decision(decision, failure={"kind": "model_evidence_invalid"})
                    termination = "model_evidence_invalid"
                    evidence["unknown_reasons"].append(str(exc))
                    break
                failure = _driver_failure_details(exc)
                reason = failure["kind"]
                if remote:
                    provider = failure.get("provider") or {}
                    delivery["delivery_status"] = provider.get("delivery", "delivery_unknown")
                    delivery["provider_failure"] = copy.deepcopy(provider)
                provenance.finish_decision(decision, failure=failure)
                evidence["driver_failures"].append({"actor": current, "decision_id": decision["decision_id"], **failure})
                emit("driver_failure", {"reason": reason, **failure}, current)
                if remote and (driver.budget_snapshot().get("halted") or time.monotonic() >= deadline):
                    termination = "episode_deadline_exhausted" if time.monotonic() >= deadline else "model_budget_or_usage_halted"
                    break
                if current == "E":
                    unavailable("E", reason)
                    current = "H"
                    actors["H"]["state"] = "active"
                    continue
                failures["H"] += 1
                if failure["automatic_retry_allowed"] and failures["H"] <= cfg["budget"].get("transport_retries", 0):
                    feedback("H", {"status": "driver_retry", "reason_code": reason})
                    continue
                termination = reason
                break
            failures[current] = 0
            raw = provenance.finish_decision(decision, raw, provider_binding=provider_binding)
            emit("model_decision_response" if remote else "engineering_driver_response", {"raw": raw,
                 "provider_binding": provider_binding} if remote else {"raw": raw}, current)
            # A valid response received at/after cutoff remains evidence but its
            # requested action is never dispatched after the episode deadline.
            check_deadline()
            who["history"].append({"role": "action", "content": raw})
            try:
                action = parse_action(raw, protocol_version=cfg.get("protocol_version"))
            except ActionError as exc:
                feedback(current, {"status": "format_error", "reason_code": str(exc)})
                continue
            active_action_binding = provenance.bind_action(decision, action)
            if v2 and action["type"] == "propose_action":
                try:
                    proposal = proposals.prepare(current, action)
                    from .audit import canonical
                    response = service_call(current, "route.send", {"recipient": "H",
                        "content": canonical(proposal).decode(), "labels": sorted(who["labels"])})
                    if response["ok"]:
                        proposals.register(proposal, active_action_binding, evidence["service_calls"][-1])
                        feedback(current, {"status": "proposal_sent", "proposal_id": proposal["proposal_id"],
                                           "content_sha256": proposal["content_sha256"]})
                    else:
                        feedback(current, response)
                except ValueError as exc:
                    feedback(current, {"status": "denied", "reason_code": str(exc)})
            elif v2 and action["type"] == "accept_proposal":
                try:
                    feedback(current, proposals.accept(current, action, active_action_binding))
                except ValueError as exc:
                    feedback(current, {"status": "denied", "reason_code": str(exc)})
            elif action["type"] == "code_execution":
                feedback(current, {"status": "denied", "reason_code": "code_execution_not_in_diagnostic_surface" if remote
                                   else "verified_compute_isolation_unavailable"})
            elif action["type"] == "send_message":
                response = service_call(current, "route.send", {
                    "recipient": action["recipient"], "content": action["content"],
                    "labels": sorted(who["labels"]),
                })
                feedback(current, response)
            elif action["type"] == "tool_action":
                outcome = tool_action(current, action)
                if outcome == "E":
                    current = "E"
                elif outcome:
                    termination = outcome
            elif current == "E":
                response = service_call("E", "route.send", {
                    "recipient": "H", "content": action["content"], "labels": sorted(who["labels"]),
                })
                who["state"] = "yielded"
                if not response["ok"]:
                    feedback("H", {"status": "external_yield", "reason_code": "reply_delivery_denied",
                                   "confirmed_result_refs": [], "remaining_budget": who["remaining"]})
                current = "H"
                actors["H"]["state"] = "active"
            else:
                final_text = action["content"]
                who["state"] = "yielded"
                termination = "host_final"
    except Exception as exc:
        # Known effects are already append-only events. A systemic exception
        # stops all admission, never fabricates a rollback or utility result.
        termination = ("episode_deadline_exhausted" if isinstance(exc, EpisodeDeadlineExceeded)
                       or remote and deadline is not None and time.monotonic() >= deadline and not inflight else
                       "execution_unknown" if inflight else "environment_error")
        evidence["unknown_reasons"].append(type(exc).__name__ + ":" + str(exc))
        try:
            emit("runtime_failure", {"error_type": type(exc).__name__, "reason": str(exc)})
        except Exception:
            pass
    # Closing first revokes admission; potentially slow snapshots come later.
    try:
        transition("closing")
        evidence["closing_cutoff"] = {"termination": termination, "inflight": list(inflight)}
        if remote:
            adapter.close_admission()
            evidence["model_budget"] = driver.budget_snapshot()
        if initialized:
            evidence["revocation"] = services.close()
        else:
            evidence["revocation"] = {"status": "not_initialized"}
        def closing_snapshot(label):
            try:
                return adapter.snapshot_after_close(timeout_seconds=5) if remote else adapter.snapshot()
            except Exception as capture_error:
                if not remote:
                    raise
                evidence["unknown_reasons"].append(label + ":" + type(capture_error).__name__)
                return None

        evidence["stop_snapshot"] = closing_snapshot("stop_snapshot_unavailable")
        transition("draining")
        # Calls are synchronous. Unresolved exception outcomes stay unknown;
        # there is no hidden background actor or blind retry/drain success claim.
        evidence["drain"] = {"mode": "synchronous_adapter", "inflight": list(inflight),
                             "status": "unknown" if inflight or termination == "execution_unknown" else "settled"}
        if v2:
            evidence["drain"]["pending_calls"] = getattr(adapter, "pending_calls", 0)
            evidence["actors_closed"] = True
            evidence["admission_closed"] = initialized and evidence["revocation"].get("status") == "closed"
        evidence["terminal_snapshot"] = closing_snapshot("terminal_snapshot_unavailable")
        evidence["terminal_snapshot_hash"] = (canonical_hash(evidence["terminal_snapshot"])
                                              if evidence["terminal_snapshot"] is not None else None)
        transition("post_close_probe")
        probe = {}
        for actor, lease in leases.items():
            probe[actor] = services.authorize(lease["lease_id"], actors[actor]["principal"],
                                              "route.send", epoch=lease.get("epoch"))
        evidence["post_close_probe"] = {"old_leases_accepted": probe,
                                       "fresh_reader": "not_performed_by_runtime"}
        if any(probe.values()):
            raise RuntimeError("post_close_lease_still_accepted")
        evidence["system_terminal_snapshot"] = services.snapshot() if initialized else None
        evidence["terminal_service_snapshot"] = evidence["system_terminal_snapshot"]
        evidence["termination"] = termination
        evidence["final_text"] = final_text
        evidence["actor_states"] = {a: {"state": who["state"], "remaining": who["remaining"]}
                                    for a, who in actors.items()}
        evidence["delegations_charged"] = delegation_count
        evidence["decision_lineage"] = provenance.export()
        # A root/private evaluator must score captured state before final audit
        # seal; do not call the runtime 'sealed' before that independent step.
        evidence["status"] = "awaiting_execution_seal" if v2 else "awaiting_private_evaluation_and_seal"
        if v2:
            evidence["proposal_chain"] = proposals.export()
        evidence["runtime_evidence_hash"] = canonical_hash(evidence)
        emit("runtime_closed", {"runtime_evidence_hash": evidence["runtime_evidence_hash"],
                                "status": evidence["status"], "termination": termination})
    except Exception as exc:
        evidence["decision_lineage"] = provenance.export()
        if v2:
            evidence["proposal_chain"] = proposals.export()
        evidence["status"] = "failed_to_seal"
        evidence["termination"] = termination
        evidence["unknown_reasons"].append("close_failure:" + type(exc).__name__ + ":" + str(exc))
        evidence["final_text"] = final_text
    return evidence
