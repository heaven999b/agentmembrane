"""Runtime-only wiring. Actor inputs never select trusted receipts or writers."""
from __future__ import annotations

import time
from ..rq1_collab_v1.audit import canonical, _write_new
from .contract import clone, digest, system_spec, MEMORY_PROFILE, PRINCIPALS
from .authority_state import snapshot_effective_authority, probe_authority_readonly, registered_probe_requests, native_grant_key
from .control_trace import control_snapshot


def memory_reads(value, validator=None):
    found = {}
    def walk(item):
        if type(item) is dict:
            if (item.get("status") == "memory_read_prepared" and type(item.get("read_event_id")) is str
                    and (validator is None or validator(item))):
                found[item["read_event_id"]] = item
            for child in item.values(): walk(child)
        elif type(item) is list:
            for child in item: walk(child)
    walk(value)
    return found


class RuntimeMonitor:
    def __init__(self, *, cfg, record, collector, actors, policy, adapter, deadline, profile):
        self.cfg, self.record, self.collector = cfg, record, collector
        self.actors, self.policy, self.adapter, self.deadline = actors, policy, adapter, deadline
        self.spec = system_spec(profile)
        self.epoch, self.memory, self.open = 0, None, True
        self.trace = {"authority_snapshots": [], "control_decisions": [], "outer_dispatch": [],
                      "closure_event_ids": [], "closed": False, "memory_use_links": [],
                      "authority_registrations": [], "authority_probes": []}
        self.memory_result = {"carrier_exists": False, "unsupported_reason": "native_profile_has_no_memory"}
        self.own_reads = {a: {} for a in actors}
        self.probe_requests, self.grant_event_ids, self.last_deliveries = [], [], {}
        self.last_probe_state = None

    def emit(self, kind, data, actor=None, parents=()):
        event = self.collector.emit(kind, clone(data), actor=actor,
            principal=PRINCIPALS.get(actor), parent_ids=list(parents))
        return {**clone(data), "event_id": event["event_id"]}

    def start(self, public_request):
        initial = self.adapter.snapshot()
        self.probe_requests = registered_probe_requests(self.record, initial, self.adapter.tool_specs)
        registration = self.emit("authority_probe_registration", {
            "schema_version": "rq1-registered-native-probes/1", "suite": self.record["suite"],
            "task_id": self.record["original_id"], "initial_state_sha256": digest(initial),
            "tool_schema_sha256": digest(self.adapter.tool_specs),
            "tool_specs": clone(self.adapter.tool_specs), "requests": self.probe_requests,
            "complete_parameter_partition": False,
            "scope": "source_bound_selected_native_authorization_requests"})
        self.trace["authority_registrations"].append(registration)
        if self.spec["memory_enabled"]:
            from .task_memory import TaskMemoryService
            self.memory = TaskMemoryService(self.collector.run_dir, self.cfg["episode_id"],
                self.cfg["bundle_sha256"], self.cfg["topology"], self.cfg["level"],
                emit=lambda kind, data: self.emit(kind, data), world_id=self.record["suite"],
                deadline_monotonic=self.deadline, projector=self.project_memory)
            self.memory.seed_source(public_request)

    def project_memory(self, actor, record, received_value, grant):
        # A note remains attributed candidate text; it never becomes a native fact.
        if record.get("record_kind") != "native_observation":
            return clone(received_value) if grant["active"] else None
        tool = record.get("original_tool")
        if tool not in grant["tools"]:
            return None
        snapshot = self.adapter.snapshot()
        projected, labels = self.policy.project_result("A3", "PLAIN", tool,
            clone(received_value), snapshot)
        if not set(labels) <= set(self.policy.labels("A3", snapshot)):
            return None
        return projected

    def augment_observation(self, actor, obs):
        if self.memory is None:
            return obs
        from .task_memory import TOOL_SPECS
        namespaces = [namespace for namespace in self.memory.namespaces.values()
                      if self.memory._access(actor, namespace)]
        # Internal grant qualification is enforced by service on every operation.
        available = [] if actor == "E" and self.cfg["level"] == "low" else clone(TOOL_SPECS)
        obs["system_tools"] = available
        obs["memory_profile_sha256"] = self.memory.profile_hash
        obs["memory_namespaces"] = namespaces
        if actor in {"H", "S"}:
            packet = self.memory.restore(actor=actor)
            obs["memory_context"] = packet
            for read in packet.get("values", []):
                if read.get("status") == "memory_read_prepared" and self.memory.verify_prepared_read(actor=actor, read=read):
                    self.own_reads[actor][read["read_event_id"]] = clone(read)
        return obs

    def delivered(self, actor, obs, status, *, request_id):
        self.last_deliveries[actor] = {"request_id": request_id,
            "observation_sha256": digest(obs), "status": status}
        ids = list(memory_reads(obs, validator=lambda read: self.memory is not None and
            self.own_reads[actor].get(read.get("read_event_id")) == read and
            self.memory.verify_prepared_read(actor=actor, read=read)))
        if self.memory is not None:
            self.memory.mark_delivered(actor=actor, read_event_ids=ids,
                receipt_status=status, request_id=request_id)
        return ids if status in {"model_response_observed", "confirmed_model_refusal", "engineering_driver_received"} else []

    def forward_reference(self, sender, recipient, source):
        def forward(item):
            if type(item) is dict:
                if (self.memory is not None and self.memory.verify_prepared_read(actor=sender, read=item)):
                    metadata = {"status": "memory_reference_metadata", "source_sha256": digest(item)}
                    read = self.memory.get(actor=recipient, record_id=item["record"]["record_id"],
                        expected_version=item["record"]["version"], request_id="forward:" + item["read_event_id"])
                    if (read.get("status") == "memory_read_prepared" and
                            self.memory.verify_prepared_read(actor=recipient, read=read)):
                        self.own_reads[recipient][read["read_event_id"]] = clone(read)
                        return read
                    metadata["forward_status"] = "not_authorized_or_version_unavailable"
                    return metadata
                return {key: forward(value) for key, value in item.items()}
            if type(item) is list: return [forward(value) for value in item]
            return item
        return forward(source)

    def state(self, point, actor, internal_used, delegation_count, **extra):
        probe_world = extra.pop("_probe_world", None)
        authority = snapshot_effective_authority(actor_state=self.actors, config=self.cfg,
            task_policy=self.policy, record=self.record, permit_epoch=self.epoch,
            active_actor=actor, admission_open=self.open)
        ar = self.emit("authority_snapshot", {"point": point, "state": authority,
            "delegation_event_ids": list(self.grant_event_ids)}, actor)
        self.trace["authority_snapshots"].append(ar)
        # Probe only changes to native grants/admission, not every token/budget
        # update. These are bounded read-only diagnostics, never backend effects.
        probe_key = native_grant_key(authority)
        if self.trace["authority_registrations"] and probe_key != self.last_probe_state:
            receipts, failure = [], None
            try:
                world = probe_world if probe_world is not None else self.adapter.snapshot()
                if world is None: raise ValueError("probe_world_unavailable")
                for recipient in sorted(authority["actors"]):
                    for request in self.probe_requests:
                        receipt = probe_authority_readonly(authority, {"actor": recipient,
                            "tool": request["tool"], "arguments": request["arguments"]},
                            policy=self.policy, record=self.record, business_state=world)
                        receipts.append({**receipt, "probe_id": request["probe_id"]})
            except Exception as exc:
                failure = type(exc).__name__
            probe = self.emit("authority_probe_batch", {"authority_event_id": ar["event_id"],
                "snapshot_sha256": authority["state_sha256"],
                "registration_event_id": self.trace["authority_registrations"][0]["event_id"],
                "receipts": receipts, "error_type": failure,
                "complete_parameter_partition": False}, actor, [ar["event_id"]])
            self.trace["authority_probes"].append(probe)
            self.last_probe_state = probe_key
        state = control_snapshot(active_actor=actor, actors=self.actors, internal_used=internal_used,
            delegation_count=delegation_count, deadline=self.deadline, admission_open=self.open,
            config_hash=digest(self.cfg), now=time.monotonic())
        row = self.emit("control_decision", {"point": point, "state": state,
            "authority_sha256": authority["state_sha256"], **extra}, actor)
        self.trace["control_decisions"].append(row)
        return row

    def dispatch(self, control, *, actor, kind, status, binding=None, call=None):
        row = self.emit("outer_dispatch_receipt", {"control_event_id": control["event_id"],
            "authority_sha256": control["authority_sha256"], "actor": actor, "kind": kind,
            "status": status, "binding": binding, "call_id": call.get("call_id") if call else None,
            "tool": call.get("tool") if call else None,
            "arguments_sha256": digest(call["arguments"]) if call else None,
            "delivery_receipt": clone(self.last_deliveries.get(actor)) if kind in {"model", "engineering"} else None}, actor, [control["event_id"]])
        self.trace["outer_dispatch"].append(row)
        return row

    def delegate(self, *, recipient, tools, event_id, refs):
        self.epoch += 1
        self.grant_event_ids.append(event_id)
        if self.memory is not None and recipient == "S":
            self.memory.set_delegation(epoch=self.epoch, tools=tools, event_id=event_id)
            for ref in refs:
                if ref in self.own_reads["H"]:
                    try:
                        self.memory.transfer(sender="H", recipient="S", read_event_id=ref,
                            transfer_event_id=event_id, delegation_epoch=self.epoch)
                    except ValueError:
                        self.emit("memory_transfer_not_authorized", {"read_event_id": ref,
                            "reason": "actual_receipt_full_pages_or_current_version_required"}, "H")

    def worker_finished(self, actor):
        if self.memory is not None and actor == "S":
            self.epoch += 1
            self.memory.set_delegation(epoch=self.epoch, tools=[], event_id="worker-finished", active=False)

    def memory_action(self, actor, action, request_id, visible):
        if self.memory is None:
            return {"status": "rejected", "reason": "memory_not_in_system_profile"}
        self.memory.allow_source_refs(actor, visible)
        allowed = {"memory.put": (self.memory.put, {"namespace", "key", "value", "source_refs", "expected_version"}),
                   "memory.get": (self.memory.get, {"namespace", "key", "record_id", "expected_version", "offset_bytes", "limit_bytes"}),
                   "memory.list": (self.memory.list, {"namespace", "cursor"})}
        target = allowed.get(action["tool"])
        if target is None or set(action["arguments"]) - target[1] or action.get("argument_refs"):
            return {"status": "rejected", "reason": "invalid_memory_action_fields"}
        try:
            result = target[0](actor=actor, request_id=request_id, **action["arguments"])
        except (TypeError, ValueError):
            return {"status": "rejected", "reason": "invalid_memory_action_arguments"}
        if (action["tool"] == "memory.get" and result.get("status") == "memory_read_prepared"
                and self.memory.verify_prepared_read(actor=actor, read=result)):
            self.own_reads[actor][result["read_event_id"]] = clone(result)
        return result

    def cache_result(self, actor, call, projected, queued_id):
        if self.memory is None: return
        if actor in {"H", "S"}:
            self.memory.cache_native_result(actor=actor, call_id=call["call_id"], tool=call["tool"],
                projected_value=projected, source_refs=[queued_id], dependency_hash=digest(call["after"]))
            # Read-side-effect results describe the before-query snapshot, not
            # a fresh current query. Conservatively mark all caches historical.
            if call["before"] != call["after"]:
                self.memory.invalidate(call_id=call["call_id"], before_hash=digest(call["before"]), after_hash=digest(call["after"]))

    def native_transition(self, call):
        # Error does not mean rollback. Every confirmed state transition must
        # invalidate previous query dependencies before another actor turn.
        if self.memory is not None:
            self.memory.invalidate(call_id=call["call_id"], before_hash=digest(call["before"]),
                                   after_hash=digest(call["after"]))

    def resolve(self, actor, action):
        if not action.get("argument_refs"): return action, []
        if self.memory is None: raise ValueError("memory_not_available")
        return self.memory.resolve_arguments(action, actor=actor)

    def native_use(self, actor, call, bindings):
        if not bindings: return
        confirmed = call.get("evidence_quality", {}).get("backend_entered") is True
        ingress = next((r for r in reversed(self.trace["outer_dispatch"])
                        if r.get("call_id") == call["call_id"] and r["kind"] == "native"), None)
        row = self.emit("memory_bound_to_action", {"kind": "memory_bound_to_action",
            "record_origin": "trusted_native_ingress", "episode_id": self.cfg["episode_id"],
            "task_hash": self.cfg["bundle_sha256"],
            "backend_receipt_event_id": ingress["event_id"] if ingress else None,
            "actor": actor, "call_id": call["call_id"],
            "bindings": bindings, "backend_entered": call.get("evidence_quality", {}).get("backend_entered"),
            "arguments_sha256": digest(call["arguments"]), "use_confirmed": confirmed,
            "execution_mode": self.cfg["execution_mode"]}, actor)
        self.trace["memory_use_links"].append(row)

    def close(self, evidence, current, internal_used):
        self.open = False
        row = self.state("closed", current, internal_used, len(evidence["delegations"]),
                         _probe_world=evidence.get("terminal_snapshot"))
        self.trace["closure_event_ids"] = [row["event_id"]]
        if self.memory is not None:
            self.memory_result = self.memory.close()
        self.trace["closed"] = True
        evidence.update(system_spec=self.spec, system_spec_sha256=digest(self.spec),
            system_profile=self.spec["system_profile"], runtime_trace=self.trace, memory=self.memory_result)
        artifacts = {"system-state-manifest.json": self.spec, "state-coverage.json": {
            "full_proposal_scope_complete": False, "persistent_K_C": "unsupported", "M4": "unsupported"}}
        for name, value in artifacts.items():
            _write_new(self.collector.run_dir / "artifacts" / name, canonical(value))
        for name, rows in (("authority-snapshots.jsonl", self.trace["authority_snapshots"]),
                           ("authority-probe-registration.jsonl", self.trace["authority_registrations"]),
                           ("authority-probes.jsonl", self.trace["authority_probes"]),
                           ("control-decisions.jsonl", self.trace["control_decisions"]),
                           ("outer-dispatch-receipts.jsonl", self.trace["outer_dispatch"]),
                           ("memory-use-links.jsonl", self.trace["memory_use_links"]),
                           ("memory-events.jsonl", self.memory_result.get("events", []))):
            _write_new(self.collector.run_dir / "artifacts" / name, b"".join(canonical(r)+b"\n" for r in rows))
