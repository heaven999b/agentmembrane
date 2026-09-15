"""V2 observations and a TCB-owned proposal/receipt/acceptance/call ledger.

Acceptance records a dependency choice only. The runtime always rechecks the
ordinary host grant at dispatch. All returned values are detached copies.
"""
from __future__ import annotations

import copy
import uuid

from .audit import canonical, sha256, strict_loads
from .authority import PROTOCOL_V2, _json

SCHEMA = "rq1-proposal-chain/2"


def _hash(value):
    return sha256(canonical(value))


def build_observation(public_task, grant, history, *, remaining_decisions=None,
                      proposals=()) -> dict:
    """Only public task text, actual actor history and exposed tool schemas.

Never serialize the private grant's state, object inventory or source hashes.
Nominal levels/mechanism labels are absent from the actor-facing interface.
"""
    if not isinstance(public_task, str) or not isinstance(grant, dict) or grant.get("status") != "resolved_at_state":
        raise ValueError("public_task_and_resolved_grant_required")
    vector = grant["authority_vector"]
    remaining = grant["max_decisions"] if remaining_decisions is None else remaining_decisions
    if type(remaining) is not int or not 0 <= remaining <= grant["max_decisions"]:
        raise ValueError("invalid_remaining_decisions")
    result = {"task": public_task, "actor": grant["actor"], "protocol_version": PROTOCOL_V2,
              "remaining_decisions": remaining, "history": _json(history),
              "tools": _json(vector["tools"]),
              "service_scopes": [s for s in vector["scopes"] if not s.startswith("tool:")],
              "proposals": _json(list(proposals)),
              "proposal_protocol": {
                  "propose_action": {"type": "propose_action", "content": "untrusted recommendation", "tool": "exact tool name", "arguments": {}},
                  "accept_proposal": {"type": "accept_proposal", "proposal_id": "received proposal ID", "content_sha256": "received content digest"},
                  "bound_tool_action": {"type": "tool_action", "tool": "exact proposed tool", "arguments": {}, "acceptance_id": "TCB acceptance ID"},
                  "semantics": "E proposes; H explicitly accepts a received proposal then references the acceptance on an exact call. Acceptance grants no permissions."}}
    return _json(result)


def _messages(observation):
    for item in observation.get("history", []):
        if not isinstance(item, dict) or item.get("role") != "observation":
            continue
        value = item.get("content")
        if not isinstance(value, dict):
            continue
        rows = value.get("messages") if value.get("status") == "messages" else value.get("result") if value.get("ok") is True else None
        if isinstance(rows, list):
            for row in rows:
                if isinstance(row, dict) and row.get("consumed") is True:
                    yield row


class ProposalLedger:
    def __init__(self, episode_id, emit):
        if not isinstance(episode_id, str) or not episode_id:
            raise ValueError("episode_id_required")
        self.episode_id, self.emit = episode_id, emit
        self._records, self._proposals, self._receipts, self._acceptances = [], {}, {}, {}
        self._used = set()

    def _append(self, kind, actor, data):
        seq = len(self._records) + 1
        row = {"episode_id": self.episode_id, "record_id": f"{self.episode_id}:proposal-chain:{seq}",
               "seq": seq, "kind": kind, "actor": actor, "data": _json(data),
               "previous_hash": self._records[-1]["record_hash"] if self._records else "0" * 64}
        row["record_hash"] = _hash(row)
        self._records.append(row)
        self.emit("proposal_chain", row, actor)
        return copy.deepcopy(row)

    def prepare(self, actor, action):
        if actor != "E":
            raise ValueError("only_external_can_propose")
        proposal = {"proposal_id": f"{self.episode_id}:proposal:{uuid.uuid4().hex}",
                    "episode_id": self.episode_id, "content": action["content"],
                    "tool": action["tool"], "arguments": _json(action["arguments"])}
        proposal["content_sha256"] = _hash({k: proposal[k] for k in ("content", "tool", "arguments")})
        return proposal

    def register(self, proposal, binding, send_call):
        result = send_call.get("response", {}).get("result", {})
        if (send_call.get("actor") != "E" or send_call.get("action") != "route.send"
                or send_call.get("response", {}).get("ok") is not True
                or result.get("sender") != "E" or result.get("recipient") != "H"
                or result.get("content") != canonical(proposal).decode()):
            raise ValueError("proposal_requires_actual_trusted_route_send")
        data = {**_json(proposal), "arguments_sha256": _hash(proposal["arguments"]),
                "action_binding": _json(binding), "decision_id": binding["decision_id"],
                "message_id": result["message_id"], "send_call_id": send_call["call_id"]}
        row = self._append("proposal_created", "E", data)
        self._proposals[proposal["proposal_id"]] = row
        return copy.deepcopy(proposal)

    def visible(self, actor, history):
        if actor != "H":
            return []
        messages = {m.get("message_id"): m for m in _messages({"history": history})}
        result = []
        for row in self._proposals.values():
            data = row["data"]
            message = messages.get(data["message_id"], {})
            proposal = {k: data[k] for k in ("proposal_id", "episode_id", "content", "tool", "arguments", "content_sha256")}
            if (message.get("sender") == "E" and message.get("recipient") == "H"
                    and message.get("content") == canonical(proposal).decode()):
                result.append(proposal)
        return copy.deepcopy(result)

    def receipt(self, delivery):
        if delivery.get("actor") != "H" or delivery.get("delivery_status") != "delivered":
            return
        actual = self.visible("H", delivery["payload"]["history"])
        if actual != delivery["payload"].get("proposals"):
            raise ValueError("proposal_delivery_mismatch")
        for proposal in actual:
            pid = proposal["proposal_id"]
            if pid not in self._receipts:
                self._receipts[pid] = self._append("host_receipt", "H", {
                    "proposal_id": pid, "content_sha256": proposal["content_sha256"],
                    "proposal_record_id": self._proposals[pid]["record_id"],
                    "delivery_event_id": delivery["event_id"], "decision_id": delivery["decision_id"]})

    def accept(self, actor, action, binding):
        if actor != "H":
            raise ValueError("only_host_can_accept")
        pid = action["proposal_id"]
        if pid not in self._receipts or pid not in self._proposals:
            raise ValueError("proposal_not_received_by_host")
        proposal = self._proposals[pid]["data"]
        if action["content_sha256"] != proposal["content_sha256"]:
            raise ValueError("proposal_content_binding_mismatch")
        aid = f"{self.episode_id}:acceptance:{uuid.uuid4().hex}"
        data = {"proposal_id": pid, "acceptance_id": aid, "content_sha256": proposal["content_sha256"],
                "receipt_record_id": self._receipts[pid]["record_id"], "decision_id": binding["decision_id"],
                "action_binding": _json(binding), "tool": proposal["tool"],
                "arguments": proposal["arguments"], "arguments_sha256": proposal["arguments_sha256"],
                "authorization_changed": False}
        row = self._append("host_acceptance", "H", data)
        self._acceptances[aid] = row
        return {"status": "proposal_accepted", "acceptance_id": aid, "proposal_id": pid,
                "content_sha256": data["content_sha256"], "tool": data["tool"],
                "arguments": copy.deepcopy(data["arguments"]), "authorization_changed": False}

    def validate_call(self, actor, action):
        aid = action.get("acceptance_id")
        if aid is None:
            return None
        if actor != "H" or aid not in self._acceptances or aid in self._used:
            raise ValueError("unknown_wrong_actor_or_consumed_acceptance")
        accepted = self._acceptances[aid]["data"]
        if action["tool"] != accepted["tool"] or _hash(action["arguments"]) != accepted["arguments_sha256"]:
            raise ValueError("accepted_proposal_tool_or_parameters_changed")
        return aid

    def bind_call(self, acceptance_id, call_id, binding):
        row = self._acceptances[acceptance_id]
        data = row["data"]
        if acceptance_id in self._used:
            raise ValueError("acceptance_already_consumed")
        self._used.add(acceptance_id)
        record = self._append("bound_call", "H", {
            "proposal_id": data["proposal_id"], "acceptance_id": acceptance_id,
            "acceptance_record_id": row["record_id"], "content_sha256": data["content_sha256"],
            "call_id": call_id, "tool": data["tool"], "arguments_sha256": data["arguments_sha256"],
            "decision_id": binding["decision_id"], "action_binding": _json(binding)})
        return {"record_id": record["record_id"], "proposal_id": data["proposal_id"],
                "acceptance_id": acceptance_id, "content_sha256": data["content_sha256"],
                "arguments_sha256": data["arguments_sha256"]}

    def export(self):
        return {"schema_version": SCHEMA, "episode_id": self.episode_id,
                "records": copy.deepcopy(self._records),
                "head_hash": self._records[-1]["record_hash"] if self._records else "0" * 64,
                "outer_execution_seal_required": True}


def verify_proposal_chain(evidence):
    """Verify recorded proposal dependence, never infer psychological causality.

The caller must first verify the execution seal. Invalid/absent chains cannot
erase independently observed effects, and never establish cross-agent risk.
"""
    output = {"ok": False, "errors": [], "links": [], "outer_execution_seal_required": True}
    try:
        evidence = _json(evidence)
        episode = evidence["episode_id"]
        ledger = evidence["proposal_chain"]
        if ledger.get("schema_version") != SCHEMA or ledger.get("episode_id") != episode:
            raise ValueError("proposal_chain_episode_or_schema_mismatch")
        rows, prior = {}, "0" * 64
        for seq, row in enumerate(ledger["records"], 1):
            if (row["episode_id"] != episode or row["seq"] != seq or row["record_id"] != f"{episode}:proposal-chain:{seq}"
                    or row["previous_hash"] != prior or row["record_hash"] != _hash({k:v for k,v in row.items() if k != "record_hash"})):
                raise ValueError("proposal_chain_hash_or_order_invalid")
            rows[row["record_id"]] = row
            prior = row["record_hash"]
        if ledger["head_hash"] != prior:
            raise ValueError("proposal_chain_head_mismatch")
        lineage = evidence["decision_lineage"]
        decisions, prior = {}, "0" * 64
        if lineage.get("episode_id") != episode:
            raise ValueError("decision_lineage_episode_mismatch")
        for seq, row in enumerate(lineage["records"], 1):
            if (row["episode_id"] != episode or row["seq"] != seq or row["previous_hash"] != prior
                    or row["record_hash"] != _hash({k:v for k,v in row.items() if k != "record_hash"})
                    or row["record_id"] in decisions):
                raise ValueError("decision_lineage_invalid")
            decisions[row["record_id"]] = row
            prior = row["record_hash"]
        if lineage["head_hash"] != prior:
            raise ValueError("decision_lineage_head_mismatch")
        deliveries = {d["event_id"]: d for d in evidence["information_deliveries"]}
        calls_list = evidence.get("native_calls", []) + evidence.get("service_calls", [])
        calls = {c["call_id"]: c for c in calls_list}
        if len(calls) != len(calls_list) or len(deliveries) != len(evidence["information_deliveries"]):
            raise ValueError("duplicate_evidence_identifiers")
        from .attribution import _call_digest
        for call in calls_list:
            reference = decisions[call["attribution"]["record_id"]]
            if (reference["kind"] not in {"native_call", "service_call"}
                    or reference["data"]["call_id"] != call["call_id"]
                    or reference["data"]["call_hash"] != _call_digest(call)
                    or call.get("episode_id") != episode):
                raise ValueError("proposal_call_evidence_fingerprint_invalid")

        def decision(binding, actor):
            parsed = decisions[binding["action_record_id"]]
            data = parsed["data"]
            response = decisions[data["response_record_id"]]
            request = decisions[data["input_record_id"]]
            delivered = deliveries[request["data"]["input_event_id"]]
            if (parsed["kind"] != "parsed_action" or response["kind"] != "decision_response"
                    or request["kind"] != "decision_input" or not request["seq"] < response["seq"] < parsed["seq"]
                    or any(r["data"].get("actor") != actor or r["data"].get("decision_id") != binding["decision_id"]
                           or r["data"].get("principal") != ("host" if actor == "H" else "external") for r in (parsed, response, request))
                    or response["data"].get("failure") is not None
                    or strict_loads(response["data"]["response_raw"]) != data["action"]
                    or _hash(data["action"]) != binding["action_hash"] or data["action_hash"] != binding["action_hash"]
                    or delivered.get("delivery_status") != "delivered" or delivered.get("episode_id") != episode
                    or delivered.get("actor") != actor or delivered.get("decision_id") != binding["decision_id"]
                    or request["data"]["input_hash"] != _hash(delivered["payload"])):
                raise ValueError("proposal_decision_not_bound_to_actual_delivery_and_action")
            return data["action"], parsed["seq"]

        proposals, receipts, acceptances, used = {}, {}, {}, set()
        for row in ledger["records"]:
            data, kind = row["data"], row["kind"]
            if kind == "proposal_created":
                action, action_seq = decision(data["action_binding"], "E")
                proposal = {k: data[k] for k in ("proposal_id", "episode_id", "content", "tool", "arguments", "content_sha256")}
                send = calls[data["send_call_id"]]
                body = {k: data[k] for k in ("content", "tool", "arguments")}
                if (row["actor"] != "E" or data["episode_id"] != episode or data["proposal_id"] in proposals
                        or not data["proposal_id"].startswith(episode + ":proposal:")
                        or action != {"type": "propose_action", **body} or data["content_sha256"] != _hash(body)
                        or data["arguments_sha256"] != _hash(data["arguments"])
                        or send.get("episode_id") != episode or send.get("actor") != "E" or send.get("action") != "route.send"
                        or send.get("response", {}).get("ok") is not True
                        or send["response"]["result"].get("message_id") != data["message_id"]
                        or send["response"]["result"].get("recipient") != "H"
                        or send["response"]["result"].get("content") != canonical(proposal).decode()):
                    raise ValueError("proposal_not_bound_to_external_action_and_route")
                proposals[data["proposal_id"]] = (row, action_seq)
            elif kind == "host_receipt":
                proposal, _ = proposals[data["proposal_id"]]
                delivery = deliveries[data["delivery_event_id"]]
                p = proposal["data"]
                visible = {k: p[k] for k in ("proposal_id", "episode_id", "content", "tool", "arguments", "content_sha256")}
                messages = list(_messages(delivery["payload"]))
                consumed = [c for c in evidence["service_calls"] if c.get("actor") == "H" and c.get("action") == "route.consume"
                            and c.get("response", {}).get("ok") is True and any(m.get("message_id") == p["message_id"]
                            and m.get("consumed") is True for m in c["response"].get("result", []))]
                if (row["actor"] != "H" or proposal["seq"] >= row["seq"] or p["content_sha256"] != data["content_sha256"]
                        or data["proposal_record_id"] != proposal["record_id"] or delivery.get("actor") != "H"
                        or delivery.get("episode_id") != episode or delivery.get("decision_id") != data["decision_id"]
                        or delivery.get("delivery_status") != "delivered" or visible not in delivery["payload"].get("proposals", [])
                        or not consumed or not any(m.get("message_id") == p["message_id"] and m.get("sender") == "E"
                            and m.get("recipient") == "H" and m.get("content") == canonical(visible).decode() for m in messages)):
                    raise ValueError("host_proposal_receipt_not_actual_delivery")
                receipts[row["record_id"]] = row
            elif kind == "host_acceptance":
                receipt = receipts[data["receipt_record_id"]]
                p, source_seq = proposals[data["proposal_id"]]
                action, action_seq = decision(data["action_binding"], "H")
                receipt_inputs = [r for r in decisions.values() if r["kind"] == "decision_input"
                                  and r["data"]["decision_id"] == receipt["data"]["decision_id"]]
                if (row["actor"] != "H" or receipt["seq"] >= row["seq"] or source_seq >= action_seq
                        or len(receipt_inputs) != 1 or receipt_inputs[0]["seq"] >= action_seq
                        or receipt["data"]["proposal_id"] != data["proposal_id"]
                        or action != {"type": "accept_proposal", "proposal_id": data["proposal_id"], "content_sha256": p["data"]["content_sha256"]}
                        or any(data[k] != p["data"][k] for k in ("tool", "arguments", "arguments_sha256", "content_sha256"))
                        or data.get("authorization_changed") is not False or data["acceptance_id"] in acceptances
                        or not data["acceptance_id"].startswith(episode + ":acceptance:")):
                    raise ValueError("host_acceptance_invalid")
                acceptances[data["acceptance_id"]] = (row, action_seq)
            elif kind == "bound_call":
                accepted, acceptance_seq = acceptances[data["acceptance_id"]]
                action, action_seq = decision(data["action_binding"], "H")
                call = calls[data["call_id"]]
                expected_binding = {"record_id": row["record_id"], **{k: data[k] for k in ("proposal_id", "acceptance_id", "content_sha256", "arguments_sha256")}}
                a = accepted["data"]
                if (row["actor"] != "H" or accepted["seq"] >= row["seq"] or acceptance_seq >= action_seq
                        or data["acceptance_record_id"] != accepted["record_id"] or data["acceptance_id"] in used
                        or any(data[k] != a[k] for k in ("proposal_id", "tool", "arguments_sha256", "content_sha256"))
                        or action != {"type": "tool_action", "tool": a["tool"], "arguments": a["arguments"], "acceptance_id": a["acceptance_id"]}
                        or call.get("actor") != "H" or call.get("principal") != "host" or call.get("episode_id") != episode
                        or call.get("tool", call.get("action")) != a["tool"] or _hash(call["arguments"]) != a["arguments_sha256"]
                        or call.get("proposal_binding") != expected_binding
                        or call.get("attribution", {}).get("action_binding") != data["action_binding"]):
                    raise ValueError("proposal_call_not_exact_content_parameter_bound")
                used.add(data["acceptance_id"])
                comparison = call.get("authority_comparison", {})
                grants = evidence.get("actor_grants", [])
                bound_grants = {actor: [g for g in grants if g.get("actor") == actor
                    and g.get("signature_sha256") == comparison.get(key)
                    and g.get("signature_sha256") == _hash(g.get("authority_vector"))]
                    for actor, key in (("H", "host_signature_sha256"), ("E", "external_signature_sha256"))}
                boundary = (comparison.get("cross_identity_boundary_verified") is True
                    and comparison.get("host_allowed") is True and comparison.get("external_allowed") is False
                    and all(bound_grants.values()))
                output["links"].append({"call_id": call["call_id"], "verified": True,
                    "proposal_id": data["proposal_id"], "acceptance_id": data["acceptance_id"],
                    "cross_identity_boundary_verified": boundary,
                    "evidence_ids": [proposals[data["proposal_id"]][0]["record_id"], a["receipt_record_id"], accepted["record_id"], row["record_id"]]})
            else:
                raise ValueError("unknown_proposal_chain_record_kind")
        output["ok"] = True
    except (KeyError, TypeError, ValueError, AttributeError, IndexError, RecursionError) as exc:
        output["errors"].append(str(exc))
        for link in output["links"]:
            link["verified"] = False
    return output
