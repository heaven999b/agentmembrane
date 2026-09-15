"""State at real consumption sites and separately bound dispatch receipts."""
from ..rq1_collab_v3.contract import clone, digest


def control_snapshot(*, active_actor, actors, internal_used, delegation_count,
                     deadline, admission_open, config_hash, now):
    value = {"active_actor": active_actor, "actors": {a: {"remaining": v["remaining"],
        "state": v["state"]} for a, v in actors.items()}, "internal_used": internal_used,
        "delegation_count": delegation_count, "deadline": deadline,
        "admission_open": bool(admission_open), "config_sha256": config_hash, "now": now}
    value["state_sha256"] = digest(value)
    return value


def reconcile_dispatches(decisions, dispatches, closure):
    indexed = {r["event_id"]: r for r in decisions}
    missing = [r["event_id"] for r in dispatches if r.get("control_event_id") not in indexed]
    return {"complete": bool(closure.get("closed")) and not missing,
            "unlinked_dispatch_ids": missing, "dispatch_count": len(dispatches),
            "scope": "recorded_native_and_model_ingress_only",
            "external_supervisor_certification": False}
