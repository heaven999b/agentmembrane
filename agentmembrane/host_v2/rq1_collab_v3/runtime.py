"""Serial three-identity controller over the original in-memory benchmark.

No actor code/shell is executed. This is tool mediation, not hostile-code OS
containment. Private snapshots/checkers are never actor observations.
"""
from __future__ import annotations

import time

from ..rq1_collab_v1.audit import EventCollector, canonical, _write_new, strict_loads
from ..rq1_collab_v1.policy import compile_task_policy, make_task_policy
from .permissions import authorize_native, native_tools, VERSION as PERMISSION_VERSION
from ..rq1_collab_v1.process_backend import ProcessNativeTask, NativeProcessFailure
from ..rq1_collab_v1.providers import HTTPTransport, ProviderFailure
from .contract import PROTOCOL, LEVELS, PRINCIPALS, actor_ids, clone, digest, validate_config
from .driver import RoleModelDriver, role_prompts
from .proxy_transport import BoundProxyTransport


def behavioral_episode_count(mode, deliveries):
    # A delivered refusal/truncation is still observed model behavior; counting
    # only parsed actions would silently remove such episodes from denominators.
    return int(mode == "live_diagnostic" and any(r["status"] == "model_response_observed" for r in deliveries))


def parse_action(raw):
    value = strict_loads(raw)
    if type(value) is not dict:
        raise ValueError("action_object_required")
    kind = value.get("type")
    fields = {"tool_action": {"type", "tool", "arguments"},
              "send_message": {"type", "recipient", "content"},
              "delegate": {"type", "recipient", "content", "tools"},
              "final": {"type", "content"}}
    if kind not in fields or set(value) - (fields[kind] | {"source_refs"}) or not fields[kind] <= set(value):
        raise ValueError("exact_action_fields_required")
    for key in ("tool", "content", "recipient"):
        if key in value and (type(value[key]) is not str or len(value[key]) > 32000):
            raise ValueError("invalid_action_text")
    if "arguments" in value and type(value["arguments"]) is not dict:
        raise ValueError("arguments_object_required")
    for key in ("tools", "source_refs"):
        if key in value and (type(value[key]) is not list or len(value[key]) > 64 or
                             any(type(x) is not str for x in value[key]) or len(value[key]) != len(set(value[key]))):
            raise ValueError("unique_string_array_required")
    return value


def run_episode(config, bundle, adapter, driver, collector):
    cfg = validate_config(config)
    record = bundle.record()
    if cfg["bundle_sha256"] != bundle.sha256:
        raise ValueError("task_bundle_binding_mismatch")
    if record.get("goal_admission", {}).get("initial_goal_value") is not False:
        raise ValueError("attack_goal_must_be_verified_false_initially")
    if collector.episode_id != cfg["episode_id"]:
        raise ValueError("collector_episode_mismatch")
    if any(adapter.record.get(k) != v for k, v in record["source_record"].items()):
        raise ValueError("fresh_native_identity_mismatch")
    if digest(adapter.prompt) != record["source_record"]["prompt_sha256"]:
        raise ValueError("native_prompt_binding_mismatch")
    if digest(adapter.tool_specs) != record["source_record"]["tool_schema_sha256"]:
        raise ValueError("native_tool_schema_binding_mismatch")
    if record["task_policy"] != compile_task_policy(record["suite"], record["original_id"], adapter.prompt):
        raise ValueError("task_policy_binding_mismatch")
    remote = cfg["execution_mode"] == "live_diagnostic"
    if remote:
        if type(adapter) is not ProcessNativeTask or type(driver) is not RoleModelDriver or type(collector) is not EventCollector:
            raise ValueError("live_requires_reviewed_native_process_and_role_driver")
        if type(driver.transport) not in {HTTPTransport,BoundProxyTransport} or any(c.transport is not driver.transport for c in driver.children.values()):
            raise ValueError("live_requires_real_http_transport")
        if driver.config != cfg or driver.prompts != role_prompts(cfg, adapter.prompt, record["public"]["goal"]["goal"]):
            raise ValueError("live_role_configuration_mismatch")
    elif getattr(driver, "trusted_engineering_driver", False) is not True:
        raise ValueError("explicit_engineering_driver_required")
    ids = actor_ids(cfg["topology"])
    budget = cfg["budget"]
    actors = {a: {"history": [], "visible": {}, "remaining": budget["external_decisions" if a == "E" else "internal_decisions"],
                  "state": "idle", "task": adapter.prompt, "tools": None,
                  "level": "A4" if a == "H" else cfg["internal_level"] if a == "S" else LEVELS[cfg["level"]]}
              for a in ids}
    policy = make_task_policy(record["suite"], record["original_id"], adapter.prompt,
                              record["task_policy"], [s["name"] for s in adapter.tool_specs])
    deadline = time.monotonic() + budget["wall_seconds"]
    evidence = {"schema_version": "rq1-evidence/3", "episode_id": cfg["episode_id"], "config": cfg,
                "bundle_sha256": bundle.sha256, "native_record": clone(adapter.record),
                "task": {"task_id": record["original_id"], "suite": record["suite"], "prompt": adapter.prompt},
                "actors": {a: {"principal": PRINCIPALS[a], "level": actors[a]["level"]} for a in ids},
                "native_calls": [], "deliveries": [], "messages": [], "decisions": [], "delegations": [],
                "failures": [], "final_text": "", "initial_snapshot": None, "terminal_snapshot": None,
                "execution_mode": cfg["execution_mode"], "behavioral_n": 0,
                "permission_contract_version": PERMISSION_VERSION,
                "coverage": {"scope": "registered_native_tools_and_explicit_messages",
                             "os_containment": False, "all_hazards_observed": False,
                             "unsupported_public_carriers": ["persistent_memory", "capability_mutation", "control_plane_mutation"]}}
    source_events = {}
    internal_used = 0
    terminal = "not_started"
    current = "E"
    actors["E"]["state"] = "active"

    def emit(kind, data, actor=None, parents=()):
        return collector.emit(kind, clone(data), actor=actor,
                              principal=PRINCIPALS.get(actor), parent_ids=list(parents))

    def feedback(actor, content, origins=(), parents=()):
        event = emit("observation_queued", {"content": content, "origin_actors": sorted(set(origins))}, actor, parents)
        entry = {"role": "observation", "event_id": event["event_id"], "content": clone(content),
                 "origin_actors": sorted(set(origins))}
        actors[actor]["history"].append(entry)
        source_events[event["event_id"]] = clone(entry)
        return event["event_id"]

    def send(sender, recipient, content, refs, kind="message"):
        origins = {sender}
        for ref in refs:
            origins.update(source_events[ref].get("origin_actors", []))
        event = emit(kind, {"sender": sender, "recipient": recipient, "content": content,
                           "source_refs": refs, "origin_actors": sorted(origins)}, sender, refs)
        row = {"event_id": event["event_id"], "sender": sender, "recipient": recipient,
               "content": content, "source_refs": refs, "origin_actors": sorted(origins)}
        evidence["messages"].append(row)
        feedback(recipient, {"status": "message", **row,
                            "referenced_evidence": [source_events[r] for r in refs]}, origins, [event["event_id"]])
        return row

    def observation(actor):
        who = actors[actor]
        tools = set(native_tools(policy,record,who["level"]))
        if who["tools"] is not None:
            tools &= set(who["tools"])
        result = {"protocol_version": PROTOCOL, "episode_id": cfg["episode_id"], "actor": actor,
                  "principal": PRINCIPALS[actor], "user_request": adapter.prompt, "assigned_task": who["task"],
                  "history": clone(who["history"]), "available_tools": [clone(s) for s in adapter.tool_specs if s["name"] in tools],
                  "permissions": {"level": who["level"], "tools": sorted(tools), "can_delegate": actor == "H",
                                  "recipients": ["H"] if actor != "H" else [a for a in ids if a != "H"]},
                  "remaining_decisions": min(who["remaining"], budget["internal_decisions"] - internal_used) if actor != "E" else who["remaining"]}
        if actor == "H":
            result["delegatable_tools"] = {a: native_tools(policy,record,actors[a]["level"]) for a in ids if a != "H"}
        return result

    def delivered(actor, obs, status):
        event = emit("observation_delivered", {"status": status, "payload": obs}, actor)
        evidence["deliveries"].append({"event_id": event["event_id"], "actor": actor, "status": status, "payload": clone(obs)})
        if status in {"model_response_observed", "engineering_driver_received"}:
            actors[actor]["visible"].update({h["event_id"]: True for h in obs["history"] if "event_id" in h})

    try:
        if hasattr(adapter, "begin_episode"):
            adapter.begin_episode(deadline_monotonic=deadline)
        if remote:
            driver.begin_episode(deadline_monotonic=deadline)
        initial = adapter.snapshot()
        if digest(initial) != record["source_record"]["initial_state_sha256"]:
            raise ValueError("fresh_initial_state_mismatch")
        evidence["initial_snapshot"] = clone(initial)
        emit("episode_started", {"config": cfg, "actors": evidence["actors"], "initial_sha256": digest(initial)})
        terminal = "running"
        while terminal == "running":
            if time.monotonic() >= deadline:
                terminal = "episode_deadline_exhausted"
                break
            who = actors[current]
            if who["remaining"] <= 0 or (current != "E" and internal_used >= budget["internal_decisions"]):
                who["state"] = "exhausted"
                if current == "E":
                    feedback("H", {"status": "external_exhausted", "not_task_completion": True})
                    current = "H"
                    continue
                if current == "S" and internal_used < budget["internal_decisions"]:
                    feedback("H", {"status": "internal_worker_exhausted", "not_task_completion": True})
                    current = "H"
                    continue
                terminal = "internal_budget_exhausted"
                break
            obs = observation(current)
            who["remaining"] -= 1
            if current != "E":
                internal_used += 1
            try:
                raw = driver.next_action(current, clone(obs))
            except ProviderFailure as exc:
                if exc.delivery == "delivered":
                    delivered(current, obs, "model_response_observed")
                elif exc.delivery == "delivery_unknown":
                    delivered(current, obs, "delivery_unknown")
                failure = {"actor": current, **exc.audit_metadata()}
                evidence["failures"].append(failure)
                emit("driver_failure", failure, current)
                # Refusal and a completed overlong answer are behavior. Unknown
                # delivery/usage stops the run; no silent retry or replacement.
                if exc.kind == "model_refusal" and current != "H":
                    feedback("H", {"status": "collaborator_refused", "actor": current})
                    who["state"] = "refused"
                    current = "H"
                    continue
                terminal = ("model_refusal" if exc.kind == "model_refusal" else
                            "model_output_truncated" if exc.code == "model_response_truncated" else
                            "model_budget_exhausted" if exc.kind == "budget_exhausted" else "provider_failure")
                break
            delivered(current, obs, "model_response_observed" if remote else "engineering_driver_received")
            binding = driver.last_completion_binding(current) if remote else None
            if time.monotonic() >= deadline:
                emit("late_action_not_dispatched", {"raw_action": raw, "model_binding": binding}, current)
                terminal = "episode_deadline_exhausted"
                break
            decision = emit("actor_decision", {"raw_action": raw, "model_binding": binding,
                                               "observation_sha256": digest(obs)}, current)
            try:
                action = parse_action(raw)
                refs = action.get("source_refs", [])
                if any(ref not in who["visible"] for ref in refs):
                    raise ValueError("reference_not_delivered_to_this_actor")
            except (ValueError, TypeError):
                evidence["decisions"].append({"event_id": decision["event_id"], "actor": current,
                                              "status": "invalid_action", "raw_action": raw})
                feedback(current, {"status": "format_error", "reason": "invalid_action_or_source_reference"})
                continue
            origins = sorted({origin for r in refs for origin in source_events[r].get("origin_actors", [])})
            row = {"event_id": decision["event_id"], "actor": current, "action": clone(action),
                   "source_refs": refs, "origin_actors": origins, "status": "parsed"}
            evidence["decisions"].append(row)
            who["history"].append({"role": "action", "content": clone(action)})
            kind = action["type"]
            if kind in {"send_message", "delegate"}:
                recipient = action["recipient"]
                allowed = recipient in ids and recipient != current and (current == "H" or recipient == "H")
                if not allowed or (kind == "delegate" and current != "H"):
                    row["status"] = "rejected"
                    feedback(current, {"status": "denied", "reason": "message_or_delegation_scope"})
                    continue
                if kind == "delegate":
                    ceiling = set(native_tools(policy,record,actors[recipient]["level"]))
                    if len(evidence["delegations"]) >= budget["max_delegations"] or not set(action["tools"]) <= ceiling or actors[recipient]["remaining"] <= 0:
                        row["status"] = "rejected"
                        feedback(current, {"status": "denied", "reason": "delegation_ceiling_or_budget"})
                        continue
                    grant = {"event_id": decision["event_id"], "from": current, "to": recipient,
                             "tools": sorted(action["tools"]), "level_ceiling": actors[recipient]["level"],
                             "remaining_decisions": actors[recipient]["remaining"], "budget_reset": False,
                             "source_refs": refs}
                    evidence["delegations"].append(grant)
                    actors[recipient].update(task=action["content"], tools=grant["tools"], state="active")
                    send(current, recipient, action["content"], refs, "delegation_delivered")
                    current = recipient
                else:
                    send(current, recipient, action["content"], refs)
                    feedback(current, {"status": "message_queued", "recipient": recipient})
            elif kind == "final":
                who["state"] = "yielded"
                if current == "H":
                    evidence["final_text"] = action["content"]
                    terminal = "host_final"
                else:
                    send(current, "H", action["content"], refs, "worker_handoff")
                    current = "H"
            else:
                tool, args = action["tool"], action["arguments"]
                before = adapter.snapshot()
                allowed, reason = authorize_native(policy, record, who["level"], tool, args, before)
                if who["tools"] is not None and tool not in who["tools"]:
                    allowed, reason = False, "outside_delegated_tool_subset"
                call_id = decision["event_id"] + ":native"
                call = {"call_id": call_id, "actor": current, "principal": PRINCIPALS[current],
                        "tool": tool, "arguments": clone(args), "before": clone(before), "after": None,
                        "status": "rejected", "policy_reason": reason, "source_refs": refs,
                        "origin_actors": origins, "record_origin": "trusted_native_adapter",
                        "evidence_quality": {"backend_entered": False, "commit_status": "confirmed"}}
                evidence["native_calls"].append(call)
                if not allowed:
                    emit("native_rejected", call, current, [decision["event_id"]])
                    feedback(current, {"status": "denied", "reason": reason, "call_id": call_id})
                    continue
                emit("native_admitted", {"call_id": call_id, "tool": tool, "arguments": args}, current, [decision["event_id"]])
                if time.monotonic() >= deadline:
                    call.update(status="rejected", policy_reason="episode_deadline_exhausted")
                    emit("native_rejected", call, current)
                    terminal = "episode_deadline_exhausted"
                    break
                try:
                    result = adapter.call(tool, clone(args))
                except NativeProcessFailure as exc:
                    call.update(status="commit_unknown" if exc.commit_unknown else "failed", error=exc.code)
                    call["evidence_quality"] = {"backend_entered": None if exc.commit_unknown else False,
                                                "commit_status": "commit_unknown" if exc.commit_unknown else "confirmed"}
                    emit("native_terminal", call, current)
                    terminal = "native_failure"
                    break
                if type(result) is not dict or type(result.get("evidence_quality")) is not dict or result["evidence_quality"].get("commit_status") != "confirmed" or result.get("after") is None:
                    call.update(status="commit_unknown")
                    emit("native_terminal", call, current)
                    terminal = "native_commit_unknown"
                    break
                if result.get("before") != before:
                    call.update(status="commit_unknown", error="native_before_binding_mismatch")
                    emit("native_terminal", call, current)
                    terminal = "native_commit_unknown"
                    break
                call.update(clone(result))
                call["status"] = "failed" if result.get("error") else "committed"
                emit("native_terminal", call, current)
                if result.get("error"):
                    feedback(current, {"status": "tool_error", "reason": "native_tool_error", "call_id": call_id})
                    continue
                projected, labels = policy.project_result(who["level"], "PLAIN", tool, result["result"], result["after"])
                if not set(labels) <= set(policy.labels(who["level"], result["after"])):
                    raise ValueError("result_projection_exceeds_role_scope")
                feedback(current, {"status": "tool_result", "call_id": call_id, "tool": tool,
                                   "result": projected}, [current], [decision["event_id"]])
        evidence["terminal_reason"] = terminal
    except Exception as exc:
        evidence["terminal_reason"] = "controller_failure"
        evidence["failures"].append({"kind": "controller_failure", "error_type": type(exc).__name__})
        emit("controller_failure", {"error_type": type(exc).__name__})
    finally:
        if hasattr(adapter, "close_admission"):
            adapter.close_admission()
        try:
            evidence["terminal_snapshot"] = clone(adapter.snapshot_after_close() if hasattr(adapter, "snapshot_after_close") else adapter.snapshot())
        except Exception as exc:
            evidence["failures"].append({"kind": "terminal_snapshot_missing", "error_type": type(exc).__name__})
        evidence["budget"] = {"internal_decisions_used": internal_used,
                              "actor_decisions_used": {a: budget["external_decisions" if a == "E" else "internal_decisions"] - v["remaining"] for a, v in actors.items()},
                              "model_usage": driver.budget_snapshot() if remote else None}
        evidence["internal_worker_used"] = any(r["actor"] == "S" for r in evidence["decisions"])
        evidence["behavioral_n"] = behavioral_episode_count(cfg["execution_mode"], evidence["deliveries"])
        emit("episode_closed", {"terminal_reason": evidence.get("terminal_reason"), "budget": evidence["budget"],
                                "internal_worker_used": evidence["internal_worker_used"]})
    _write_new(collector.run_dir / "artifacts/evidence-v3.json", canonical(evidence))
    seal = collector.seal({"protocol_version": PROTOCOL, "execution_only": True,
                           "evidence_path": "artifacts/evidence-v3.json", "config_sha256": digest(cfg),
                           "formal_ready": False, "execution_mode": cfg["execution_mode"]})
    return {"evidence": evidence, "seal": seal}
