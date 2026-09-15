"""V2 execution-only sealing. Private evaluation lives outside this directory.

The existing collector remains the sole writer and integrity implementation.
A separately retained seal anchor is necessary against wholesale replacement;
neither chmod nor a hash is isolation from another process with the same UID.
"""
from __future__ import annotations

import math
import os
from pathlib import Path
import re

from .audit import EventCollector, canonical, sha256, strict_loads, verify

SCHEMA = "rq1-execution-checkpoint/2"
EVIDENCE_PATH = "execution/evidence.json"


def json_copy(value):
    """Strict JSON tree, without tuple coercion, numeric keys, or NaN."""
    def check(item):
        if type(item) is dict:
            if any(type(key) is not str for key in item):
                raise ValueError("JSON object keys must be strings")
            for child in item.values():
                check(child)
        elif type(item) is list:
            for child in item:
                check(child)
        elif type(item) is float:
            if not math.isfinite(item):
                raise ValueError("nonfinite JSON value")
        elif item is not None and type(item) not in (str, int, bool):
            raise ValueError("strict JSON values required")
    check(value)
    return strict_loads(canonical(value))


def validate_evidence(evidence):
    data = json_copy(evidence)
    if type(data) is not dict or data.get("schema_version") not in {"rq1-evidence/1", "rq1-evidence/2"}:
        raise ValueError("unsupported execution evidence schema")
    episode = data.get("episode_id")
    if type(episode) is not str or not episode:
        raise ValueError("execution episode_id required")
    branch = data.get("branch_kind", "actual")
    if branch not in {"actual", "shadow"}:
        raise ValueError("unknown execution branch")
    if branch == "shadow" and not re.fullmatch(r"[0-9a-f]{64}", data.get("parent_execution_seal_sha256", "")):
        raise ValueError("shadow requires parent execution seal")
    if branch == "actual" and data.get("parent_execution_seal_sha256") is not None:
        raise ValueError("actual branch cannot carry shadow parent")
    def identity(row):
        if type(row) is not dict:
            raise ValueError("execution record must be object")
        if "episode_id" in row and row["episode_id"] != episode:
            raise ValueError("cross-episode evidence")
        if "branch_kind" in row and row["branch_kind"] != branch:
            raise ValueError("mixed actual/shadow evidence")
    identity(data.get("config", {}))
    if data.get("config", {}).get("protocol_version") != "rq1-multifactor/2":
        raise ValueError("explicit rq1-multifactor/2 configuration required")
    call_ids = set()
    for key in ("native_calls", "service_calls", "information_deliveries", "model_decisions"):
        rows = data.get(key, [])
        if type(rows) is not list:
            raise ValueError(key + " must be a list")
        seen = set()
        for row in rows:
            identity(row)
            rid = row.get("call_id" if key.endswith("calls") else "event_id")
            if key.endswith("calls"):
                if type(rid) is not str or not rid.startswith(episode + ":") or rid in call_ids:
                    raise ValueError("duplicate/unbound call_id")
                call_ids.add(rid)
            if key == "information_deliveries":
                if type(rid) is not str or not rid.startswith(episode + ":") or rid in seen:
                    raise ValueError("duplicate/unbound delivery event_id")
                seen.add(rid)
            if key in {"native_calls", "service_calls", "information_deliveries"} and row.get("actor") not in {"H", "E"}:
                raise ValueError("unbound execution actor")
    for key in ("proposal_chain", "decision_lineage"):
        if key in data:
            identity(data[key])
            for row in data[key].get("records", []):
                identity(row)
    for key in ("system_terminal_snapshot", "terminal_service_snapshot"):
        snapshot = data.get(key)
        if type(snapshot) is dict and "episode" in snapshot:
            identity(snapshot["episode"])
    # Results are an evaluation artifact, never part of actor execution.
    if any(key in data for key in ("quality_truth", "private_checker_results", "utility", "hard_facts", "judge_votes")):
        raise ValueError("private evaluation cannot precede execution seal")
    return data


def lifecycle_completeness(data):
    reasons = []
    life = data.get("lifecycle", [])
    stages = ("closing", "draining", "post_close_probe")
    if type(life) is not list or any(stage not in life for stage in stages) or [life.index(s) for s in stages] != sorted(life.index(s) for s in stages):
        reasons.append("close_drain_probe_sequence_unverified")
    if data.get("status") != "awaiting_execution_seal":
        reasons.append("runtime_not_ready_for_execution_seal")
    drain = data.get("drain", {})
    if drain.get("status") != "settled" or drain.get("inflight") != []:
        reasons.append("pending_native_work_or_unknown_commit")
    if "pending_calls" in drain and (type(drain["pending_calls"]) is not int or drain["pending_calls"] != 0):
        reasons.append("pending_adapter_calls_not_zero")
    if data.get("closing_cutoff", {}).get("inflight") != []:
        reasons.append("closing_inflight_not_empty")
    if data.get("revocation", {}).get("status") != "closed":
        reasons.append("service_admission_not_closed")
    probe = data.get("post_close_probe", {}).get("old_leases_accepted")
    if type(probe) is not dict or not probe or any(value is not False for value in probe.values()):
        reasons.append("lease_revocation_not_verified")
    for key in ("initial_snapshot", "terminal_snapshot"):
        if type(data.get(key)) is not dict:
            reasons.append(key + "_unavailable")
    if any(call.get("status") == "commit_unknown" for call in data.get("native_calls", [])):
        reasons.append("native_commit_unknown")
    for key in ("pending_calls", "pending_requests"):
        if key in data and (type(data[key]) is not int or data[key] != 0):
            reasons.append(key + "_not_zero")
    if data.get("actors_closed") is not True or data.get("admission_closed") is not True:
        reasons.append("actor_admission_closure_unverified")
    return {"complete": not reasons, "reasons": sorted(set(reasons))}


def _no_evaluation(root):
    private = root / "private_evaluation"
    if private.exists() and any(p.is_file() or p.is_symlink() for p in private.rglob("*")):
        raise ValueError("private evaluation must be outside sealed execution")
    for raw in (root / "events.jsonl").read_bytes().splitlines():
        event = strict_loads(raw)
        episode = event.get("episode_id")
        for ref in event.get("parent_ids", []):
            if type(ref) is not str or not ref.startswith(episode + ":"):
                raise ValueError("cross-episode collector causal reference")
        for key in ("call_id", "decision_id"):
            if key in event and (type(event[key]) is not str or not event[key].startswith(episode + ":")):
                raise ValueError("cross-episode collector identity")
        if event.get("kind", "").startswith(("private_scoring", "private_evaluation", "judge_", "factor_score")):
            raise ValueError("private evaluation was run before execution seal")


def seal_execution(run_dir, evidence, collector):
    """Seal once, preserving incomplete execution as incomplete, never as zero."""
    root = Path(run_dir)
    if root.is_symlink() or not isinstance(collector, EventCollector) or collector.run_dir.resolve() != root.resolve():
        raise ValueError("collector/run directory mismatch")
    data = validate_evidence(evidence)
    if collector.episode_id != data["episode_id"]:
        raise ValueError("collector/execution episode mismatch")
    _no_evaluation(root)
    completeness = lifecycle_completeness(data)
    destination = root / EVIDENCE_PATH
    if destination.parent.is_symlink():
        raise ValueError("execution artifact directory cannot be symlink")
    destination.parent.mkdir(exist_ok=True, mode=0o700)
    # Exclusive creation and collector's own lock prevent reopening an attempt.
    with collector._mutex:
        if collector._sealed:
            raise RuntimeError("execution already sealed")
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonical(data) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        metadata = {"protocol_version": "rq1-multifactor/2", "execution_only": True,
                    "evidence_path": EVIDENCE_PATH, "evidence_sha256": sha256(canonical(data)),
                    "branch_kind": data.get("branch_kind", "actual"), "capture_completeness": completeness}
        collector.emit("execution_capture_persisted", metadata, evidence_quality="collector_integrity")
        manifest = collector.seal(metadata)
    return load_execution(root, expected_seal_sha256=manifest["seal_hash"])


def load_execution(run_dir, *, expected_seal_sha256=None):
    """Verify every sealed artifact before returning an isolated JSON snapshot."""
    if expected_seal_sha256 is not None and (type(expected_seal_sha256) is not str or not re.fullmatch(r"[0-9a-f]{64}", expected_seal_sha256)):
        raise ValueError("invalid expected execution seal")
    root = Path(run_dir)
    result = verify(root, expected_seal_hash=expected_seal_sha256)
    if not result["ok"]:
        raise ValueError("execution seal verification failed: " + ",".join(result["errors"]))
    manifest = strict_loads((root / "seal.json").read_bytes())
    metadata = manifest.get("metadata", {})
    if metadata.get("execution_only") is not True or metadata.get("protocol_version") != "rq1-multifactor/2" or metadata.get("evidence_path") != EVIDENCE_PATH:
        raise ValueError("not a v2 execution-only seal")
    data = validate_evidence(strict_loads((root / EVIDENCE_PATH).read_bytes()))
    if data["episode_id"] != manifest["episode_id"] or sha256(canonical(data)) != metadata.get("evidence_sha256"):
        raise ValueError("execution evidence/seal binding mismatch")
    completeness = lifecycle_completeness(data)
    if completeness != metadata.get("capture_completeness") or data.get("branch_kind", "actual") != metadata.get("branch_kind"):
        raise ValueError("execution lifecycle/branch binding mismatch")
    _no_evaluation(root)
    return {"schema_version": SCHEMA, "episode_id": data["episode_id"],
            "execution_seal_sha256": manifest["seal_hash"],
            "evidence_path": str((root / EVIDENCE_PATH).resolve()),
            "evidence_sha256": sha256(canonical(data)), "evidence": data,
            "manifest": manifest, "capture_completeness": completeness,
            "externally_anchored": expected_seal_sha256 is not None,
            "limitations": ["hash integrity requires independently retained seal anchor",
                            "collector closure is not same-UID filesystem isolation"]}


def verified_checkpoint(checkpoint):
    """Re-read disk for private evaluation; mutated in-memory evidence is rejected."""
    if type(checkpoint) is not dict or checkpoint.get("schema_version") != SCHEMA:
        raise ValueError("verified execution checkpoint required")
    path = Path(checkpoint.get("evidence_path", ""))
    fresh = load_execution(path.parent.parent, expected_seal_sha256=checkpoint.get("execution_seal_sha256"))
    for key in ("episode_id", "evidence_sha256", "evidence", "capture_completeness"):
        if checkpoint.get(key) != fresh[key]:
            raise ValueError("checkpoint changed after execution seal: " + key)
    return fresh
