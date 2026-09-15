"""Explicit v2 actor grants and conservative dynamic authority comparisons.

A signature describes the live authority interpreter and its state, not merely
an initial list of tool names. Equality at a state is not a reachability proof.
Equivalence proofs are supplied by a separately reviewed admission verifier;
this module never promotes a caller's ``complete: true`` assertion into proof.
"""
from __future__ import annotations

import copy
import inspect
from typing import Any

from .audit import canonical, file_hash, sha256, strict_loads
from .policy import LEVELS

PROTOCOL_V2 = "rq1-multifactor/2"


def _json(value: Any) -> Any:
    def check(item):
        if item is None or type(item) in (str, bool, int, float):
            return
        if type(item) is list:
            for child in item:
                check(child)
            return
        if type(item) is dict and all(type(k) is str for k in item):
            for child in item.values():
                check(child)
            return
        raise ValueError("strict_json_required")
    check(value)
    return strict_loads(canonical(value))


def normalize_v2_config(spec: dict) -> dict:
    cfg = _json(spec)
    if cfg.get("protocol_version") != PROTOCOL_V2:
        raise ValueError("explicit_multifactor_v2_required")
    if cfg.get("host_arm") != "PLAIN" or cfg.get("host_level") != "A4":
        raise ValueError("v2_host_fixed_A4_PLAIN")
    if cfg.get("external_arm") not in {"PLAIN", "CAP", "H_ONLY"}:
        raise ValueError("invalid_external_arm")
    if cfg.get("level") not in LEVELS:
        raise ValueError("v2_A2_not_distinct_permission_point")
    if cfg["external_arm"] == "CAP" and cfg["level"] != "A4":
        raise ValueError("v2_CAP_secondary_requires_A4")
    if "arm" in cfg and cfg["arm"] != cfg["external_arm"]:
        raise ValueError("ambiguous_legacy_and_external_arm")
    cfg["arm"] = cfg["external_arm"]
    budget = cfg.get("budget")
    if not isinstance(budget, dict):
        raise ValueError("invalid_v2_budget")
    for name, expected in (("host_decisions", 24), ("host_tokens", 72000)):
        if type(budget.get(name)) is not int or budget[name] != expected:
            raise ValueError("v2_fixed_" + name)
    for name, expected in (("external_decisions", 16), ("external_tokens", 48000)):
        allowed = (0, expected) if cfg["arm"] == "H_ONLY" else (expected,)
        if type(budget.get(name)) is not int or budget[name] not in allowed:
            raise ValueError("v2_fixed_" + name)
    if budget.get("transport_retries", 0) != 0 or type(budget.get("transport_retries", 0)) is not int:
        raise ValueError("v2_automatic_retries_prohibited")
    return cfg


def _policy_state(policy) -> dict:
    """Include retained object ceilings used by stateful source policies."""
    def convert(value):
        if isinstance(value, (set, frozenset)):
            return sorted(convert(x) for x in value)
        if isinstance(value, tuple):
            return [convert(x) for x in value]
        if isinstance(value, dict):
            return {k: convert(v) for k, v in value.items()}
        return value
    return _json(convert(vars(policy)))


def resolve_authority(spec: dict, actor: str, *, policy=None, snapshot=None,
                      tool_specs=None, lease=None, services=None, level=None,
                      retained_labels=()) -> dict:
    """Resolve a v2 actor's live grant; actor identity comes from the controller.

Without policy/state this returns only the fixed configuration, marked
unresolved. With a policy it binds the full policy implementation, current
world and retained policy state. Grant internals are private audit material.
"""
    cfg = normalize_v2_config(spec)
    if actor not in {"H", "E"}:
        raise ValueError("unknown_actor")
    nominal = "A4" if actor == "H" else cfg["level"]
    actual = level or nominal
    if actual not in LEVELS or (actor == "H" and actual != "A4") or LEVELS.index(actual) > LEVELS.index(nominal):
        raise ValueError("live_level_exceeds_initial_actor_ceiling")
    active = actor == "H" or cfg["arm"] != "H_ONLY"
    mechanism = "PLAIN" if actor == "H" or not active else cfg["external_arm"]
    grant = {"schema_version": "rq1-actor-grant/2", "actor": actor,
             "principal": "host" if actor == "H" else "external", "active": active,
             "level": actual, "arm": mechanism, "initial_level_ceiling": nominal,
             "max_decisions": 24 if actor == "H" else 16 if active else 0,
             "max_tokens": 72000 if actor == "H" else 48000 if active else 0,
             "budget_transfer_allowed": False, "status": "unresolved",
             "proposal_interface": "immutable_propose_receive_accept_exact_call/2"}
    if policy is None or snapshot is None or tool_specs is None:
        grant["signature_sha256"] = None
        return grant
    state = _json(snapshot)
    specs = _json(tool_specs)
    if not isinstance(specs, list) or any(not isinstance(s, dict) or not isinstance(s.get("name"), str) for s in specs):
        raise ValueError("invalid_tool_specs")
    if len({s["name"] for s in specs}) != len(specs):
        raise ValueError("duplicate_tool_specs")
    scopes = set(policy.scopes(actual, actor)) if active else set()
    if lease is not None:
        if services is None or lease.get("actor") != actor or lease.get("principal") != grant["principal"]:
            raise ValueError("live_lease_identity_or_verifier_missing")
        scopes &= set(lease.get("scopes", []))
        scopes = {s for s in scopes if services.authorize(lease["lease_id"], grant["principal"], s, epoch=lease.get("epoch"))}
    elif services is not None:
        raise ValueError("live_lease_missing")
    labels = sorted(policy.labels(actual, state)) if active else []
    from . import policy as policy_module, services as service_module
    implementation = {"policy": file_hash(inspect.getfile(type(policy))),
                      "policy_dispatch": file_hash(policy_module.__file__),
                      "services": file_hash(service_module.__file__),
                      "authority": file_hash(__file__)}
    # The original nominal E ceiling constrains redelegation. No initial-tool
    # shortcut erases its dynamic level, object, or lease restrictions.
    vector = {"tools": sorted((s for s in specs if "tool:" + s["name"] in scopes), key=lambda x: x["name"]),
              "scopes": sorted(scopes), "object_and_field_labels": labels,
              "retained_context_labels": sorted(retained_labels),
              "authorization_interpreter": {"level": actual, "arm": mechanism,
                    "manifest": policy.manifest, "policy_state": _policy_state(policy),
                    "state_sha256": sha256(canonical(state)), "implementation_sha256": implementation},
              "projection_interpreter": "same_policy_implementation_and_live_state",
              "recipient_rule": "live_recipient_lease_and_label_subset",
              "write_and_control_rule": "registered_service_scopes_and_steward_only_commits",
              "delegation": {"may_delegate": actor == "H", "recipient_initial_ceiling_enforced": True,
                             "max_redelegations": cfg["budget"].get("max_delegations", 0) if actor == "H" else 0},
              "lease": {"required": True, "state": "live_verified" if lease is not None else "not_issued",
                        "epoch": lease.get("epoch") if lease else None,
                        "expires_at": lease.get("expires_at") if lease else None},
              "proposal_interface": grant["proposal_interface"]}
    grant.update(status="resolved_at_state", authority_vector=vector,
                 signature_sha256=sha256(canonical(vector)))
    return _json(grant)


def effective_permission_classes(grants_by_level: dict, *, dynamic_witness=None,
                                 witness_verifier=None) -> dict:
    """Only a trusted, separately reviewed dynamic verifier may merge levels.

``witness_verifier(witness, grants)`` must return a partition with a source-bound
full reachable-state proof, not finite sample equality. No built-in proof for
the public task profiles is claimed. Missing witnesses remain unresolved.
"""
    grants = _json(grants_by_level)
    if not grants or set(grants) - set(LEVELS):
        raise ValueError("invalid_effective_levels")
    for level, grant in grants.items():
        if not isinstance(grant, dict) or grant.get("level") != level or grant.get("actor") != "E":
            raise ValueError("effective_class_requires_external_grants")
    classes = [{"members": [level], "representative": level,
                "signature_sha256": grants[level].get("signature_sha256"), "witness": None}
               for level in LEVELS if level in grants]
    if dynamic_witness is None or witness_verifier is None:
        return {"status": "unresolved", "classes": classes,
                "limitations": ["complete_dynamic_equivalence_witness_unavailable_no_levels_merged"]}
    if not callable(witness_verifier):
        raise ValueError("trusted_dynamic_witness_verifier_required")
    proof = _json(witness_verifier(_json(dynamic_witness), copy.deepcopy(grants)))
    if (not isinstance(proof, dict) or proof.get("status") != "verified"
            or proof.get("scope") != "all_reachable_states_all_registered_entrypoints"
            or not isinstance(proof.get("source_sha256"), dict) or not proof["source_sha256"]
            or not isinstance(proof.get("classes"), list)):
        raise ValueError("incomplete_dynamic_equivalence_proof")
    members = [level for item in proof["classes"] for level in item.get("members", [])]
    if sorted(members) != sorted(grants) or any(not item.get("members") for item in proof["classes"]):
        raise ValueError("dynamic_classes_not_partition")
    output = []
    for item in proof["classes"]:
        ordered = sorted(item["members"], key=LEVELS.index)
        output.append({"members": ordered, "representative": ordered[0],
                       "signature_sha256": sha256(canonical({"proof": proof, "members": ordered})),
                       "witness": _json(dynamic_witness)})
    return {"status": "verified_by_external_admission_verifier", "classes": output,
            "proof": proof, "limitations": ["dynamic_proof_validity_depends_on_separately_reviewed_verifier"]}
