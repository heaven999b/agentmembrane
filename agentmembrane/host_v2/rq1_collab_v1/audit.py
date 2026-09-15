"""Append-only experiment evidence, not an OS containment or provenance claim.

The collector is intended to be owned by the trusted collector process. Hashes
detect modification relative to a separately retained seal hash; they cannot
prove that the producer emitted every event or prevent a writer replacing the
entire run. A failed/incomplete attempt is never reopened or overwritten.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
import threading
import time
import uuid
from typing import Any


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _finite_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        raise ValueError(f"nonfinite JSON number: {token}")
    return value


def strict_loads(value: str | bytes) -> Any:
    return json.loads(value, object_pairs_hook=_pairs,
                      parse_float=_finite_float,
                      parse_constant=lambda token: (_ for _ in ()).throw(ValueError(f"nonfinite JSON: {token}")))


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_hash(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


_CREDENTIAL_FIELDS = {"authorization", "proxy_authorization", "api_key", "apikey",
                      "access_token", "refresh_token", "client_secret", "password",
                      "headers", "request_headers"}

# A native tool's JSON Schema names the *field* accepted by update_password;
# that schema contains no password value. The only two trusted event locations
# that carry source-locked native tool specifications are registration and the
# actor's delivered available_tools. Do not extend this exception to actions,
# arguments, history, or arbitrary nested objects named "properties".
_NATIVE_PASSWORD_SCHEMA_PATHS = {
    "authority_probe_registration": re.compile(
        r"^root\.tool_specs\[[0-9]+\]\.parameters\.properties$"),
    "observation_delivered": re.compile(
        r"^root\.payload\.available_tools\[[0-9]+\]\.parameters\.properties$"),
}
_NATIVE_STATE_PASSWORD_PATH = re.compile(
    r"^root\.(?:before|after)\.user_account$"
)


def _is_native_password_schema_label(path: str, key: str, item: Any,
                                     schema_context: str | None) -> bool:
    allowed = _NATIVE_PASSWORD_SCHEMA_PATHS.get(schema_context)
    return (key == "password" and allowed is not None and allowed.fullmatch(path) is not None
            and type(item) is dict and item.get("type") == "string"
            and set(item) <= {"type", "title", "description", "minLength", "maxLength", "pattern"})


def _is_locked_native_state_password(path: str, key: str, item: Any,
                                     schema_context: str | None) -> bool:
    # NativeTask snapshots carry the simulated account's password even for a
    # read-only transaction call. Preserve the exact before/after worlds in
    # the sealed native receipt, whose producer and source identity are checked
    # by runtime/evaluation. This value is never an actor argument or delivery.
    return (schema_context in {"native_terminal_trusted_state", "native_rejected_trusted_before"}
            and key == "password"
            and _NATIVE_STATE_PASSWORD_PATH.fullmatch(path) is not None
            and type(item) is str)


def _check_no_transport_secrets(value: Any, path: str = "root", *,
                                schema_context: str | None = None) -> None:
    """Fail, never redact, because a redacted request is not its exact body.

    This enforces a structural no-credentials contract. It cannot detect an
    arbitrary secret pasted into free text; the transport must never insert
    credentials into a model body, and that boundary needs independent review.
    """
    if isinstance(value, dict):
        for key, item in value.items():
            if (str(key).lower().replace("-", "_") in _CREDENTIAL_FIELDS
                    and not _is_native_password_schema_label(path, key, item, schema_context)
                    and not _is_locked_native_state_password(path, key, item, schema_context)):
                raise ValueError(f"credential/header field forbidden in evidence: {path}.{key}")
            _check_no_transport_secrets(item, f"{path}.{key}", schema_context=schema_context)
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _check_no_transport_secrets(item, f"{path}[{index}]", schema_context=schema_context)


def _write_new(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def _inventory(root: Path) -> dict[str, dict]:
    files = {}
    for directory, dirs, names in os.walk(root, followlinks=False):
        for name in dirs:
            if (Path(directory) / name).is_symlink():
                raise ValueError("symlink directory in evidence")
        for name in names:
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"nonregular evidence artifact: {relative}")
            if relative in {"seal.json", ".collector.lock"}:
                continue
            files[relative] = {"sha256": file_hash(path), "bytes": path.stat().st_size}
    return dict(sorted(files.items()))


class EventCollector:
    """Single writer to a fresh run directory; seal once, never resume in place."""

    def __init__(self, run_dir: str | Path, episode_id: str):
        if not isinstance(episode_id, str) or not episode_id:
            raise ValueError("episode_id is required")
        self.run_dir = Path(run_dir)
        if self.run_dir.is_symlink():
            raise ValueError("run directory cannot be a symlink")
        self.run_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        if (self.run_dir / "events.jsonl").exists() or (self.run_dir / "seal.json").exists():
            raise FileExistsError("existing attempt must be preserved; allocate a new attempt directory")
        _write_new(self.run_dir / ".collector.lock", canonical({"episode_id": episode_id, "collector_id": uuid.uuid4().hex}))
        self.episode_id = episode_id
        self._seq = 0
        self._head = "0" * 64
        self._sealed = False
        self._mutex = threading.RLock()
        self._requests: dict[str, dict] = {}
        self._handle = (self.run_dir / "events.jsonl").open("xb")
        os.chmod(self.run_dir / "events.jsonl", 0o600)
        for name in ("model_requests", "native_trace", "snapshots", "artifacts", "private_evaluation"):
            (self.run_dir / name).mkdir(exist_ok=True, mode=0o700)

    def emit(self, kind: str, data: dict, **context) -> dict:
        with self._mutex:
            if self._sealed:
                raise RuntimeError("sealed collector cannot accept events")
            if not isinstance(kind, str) or not kind or not isinstance(data, dict):
                raise ValueError("event needs nonempty kind and object data")
            scan_context = kind
            if kind == "native_terminal":
                quality = data.get("evidence_quality")
                scan_context = ("native_terminal_trusted_state"
                                if data.get("record_origin") == "trusted_native_adapter"
                                and type(quality) is dict and quality.get("backend_entered") is True
                                and type(data.get("before")) is dict
                                and type(data.get("after")) is dict else None)
            elif kind == "native_rejected":
                quality = data.get("evidence_quality")
                scan_context = ("native_rejected_trusted_before"
                                if data.get("record_origin") == "trusted_native_adapter"
                                and data.get("status") == "rejected"
                                and type(quality) is dict
                                and quality.get("backend_entered") is False
                                and quality.get("commit_status") == "confirmed"
                                and type(data.get("before")) is dict
                                and data.get("after") is None else None)
            _check_no_transport_secrets(data, schema_context=scan_context)
            _check_no_transport_secrets(context)
            reserved = {"episode_id", "seq", "event_id", "previous_hash", "event_hash", "data", "kind", "data_ref"}
            if reserved.intersection(context):
                raise ValueError("trusted collector identity/hash fields cannot be overridden")
            seq = self._seq + 1
            event = {
                "episode_id": self.episode_id, "seq": seq,
                "event_id": f"{self.episode_id}:{seq}", "actor": None,
                "session": None, "call": None, "parent_ids": [],
                "monotonic_time": time.monotonic(), "kind": kind,
                "state_before": None, "state_after": None, "permit_epoch": None,
                "evidence_quality": "producer_reported", **context,
                "data_ref": {"kind": "inline", "sha256": sha256(canonical(data))},
                "data": data, "previous_hash": self._head,
            }
            encoded = canonical(event)
            event["event_hash"] = sha256(encoded)
            self._handle.write(canonical(event) + b"\n")
            self._handle.flush()
            os.fsync(self._handle.fileno())
            self._seq, self._head = seq, event["event_hash"]
            return event

    def record_model_request(self, request_id: str, serialized_body: bytes | str, *,
                             status: str, actor: str, model_profile: dict,
                             receipt: dict | None = None, **context) -> dict:
        """Capture bytes AFTER transport serialization, before sending.

        Call prepared_only before transport I/O. Update the same request ID
        with delivery_unknown when submission may have happened, and delivered
        only with a receipt evidencing provider acceptance/response. Requests
        cannot regress or change bytes/profile. No headers are accepted.
        """
        with self._mutex:
            if self._sealed:
                raise RuntimeError("sealed collector cannot accept requests")
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", request_id) or request_id in {".", ".."}:
                raise ValueError("unsafe request_id")
            if status not in {"prepared_only", "delivery_unknown", "delivered"}:
                raise ValueError("invalid model request delivery status")
            if not isinstance(actor, str) or not actor or not isinstance(model_profile, dict) or not model_profile:
                raise ValueError("actor and exact model_profile required")
            body = serialized_body.encode("utf-8") if isinstance(serialized_body, str) else serialized_body
            if not isinstance(body, bytes):
                raise ValueError("serialized_body must be exact JSON bytes or text")
            parsed = strict_loads(body)
            if not isinstance(parsed, dict):
                raise ValueError("model body must be a JSON object")
            _check_no_transport_secrets(parsed)
            _check_no_transport_secrets(model_profile)
            _check_no_transport_secrets(receipt)
            digest = sha256(body)
            identity = {"body_sha256": digest, "actor": actor, "model_profile": model_profile}
            prior = self._requests.get(request_id)
            if prior is None and status != "prepared_only":
                raise ValueError("must capture prepared_only before transport")
            if prior is not None:
                if any(prior[key] != value for key, value in identity.items()):
                    raise ValueError("request bytes/actor/profile changed after preparation")
                allowed = {"prepared_only": {"delivery_unknown", "delivered"},
                           "delivery_unknown": {"delivered"}, "delivered": set()}
                if status not in allowed[prior["status"]]:
                    raise ValueError("invalid/repeated request delivery transition")
            if status == "delivered" and (not isinstance(receipt, dict) or not receipt.get("acceptance_evidence")):
                raise ValueError("delivered requires actual transport acceptance/response evidence")
            if prior is None:
                _write_new(self.run_dir / "model_requests" / f"{request_id}.body.json", body)
            record = {"request_id": request_id, **identity, "status": status,
                      "body_path": f"model_requests/{request_id}.body.json",
                      "body_bytes": len(body), "receipt": receipt,
                      "wall_time_ns": time.time_ns(),
                      "provider_internal_retention": "unknown"}
            event = self.emit("model_request", record, actor=actor, **context)
            # Retain a value snapshot, never a caller-owned mutable profile.
            self._requests[request_id] = strict_loads(canonical(record))
            return event

    def seal(self, metadata: dict) -> dict:
        with self._mutex:
            if self._sealed:
                raise RuntimeError("already sealed")
            if not isinstance(metadata, dict):
                raise ValueError("seal metadata must be an object")
            _check_no_transport_secrets(metadata)
            self.emit("collector_seal", {"metadata": metadata,
                      "model_request_terminal_status": {key: value["status"] for key, value in self._requests.items()},
                      "request_coverage": "none_recorded" if not self._requests else "recorded_not_completeness_proof"},
                      evidence_quality="collector_integrity")
            self._handle.close()
            manifest = {"schema": "rq1-evidence-seal/v1", "episode_id": self.episode_id,
                        "event_count": self._seq, "event_chain_head": self._head,
                        "artifacts": _inventory(self.run_dir), "metadata": metadata,
                        "semantic_completeness": "not_established_by_hash_chain",
                        "source_authentication": "requires_external_seal_anchor_and_trusted_collector"}
            manifest["seal_hash"] = sha256(canonical(manifest))
            _write_new(self.run_dir / "seal.json", canonical(manifest) + b"\n")
            self._sealed = True
            return manifest

    def abort(self) -> None:
        """Leave an unsealed immutable attempt for diagnosis; never delete it."""
        with self._mutex:
            if not self._handle.closed:
                self._handle.flush()
                os.fsync(self._handle.fileno())
                self._handle.close()
            self._sealed = True


def verify(run_dir: str | Path, *, expected_seal_hash: str | None = None) -> dict:
    root = Path(run_dir)
    errors: list[str] = []
    seal = None
    count = 0
    head = "0" * 64
    episode_id = None
    try:
        if root.is_symlink():
            raise ValueError("symlink run directory")
        seal = strict_loads((root / "seal.json").read_bytes())
        if not isinstance(seal, dict) or seal.get("schema") != "rq1-evidence-seal/v1":
            raise ValueError("unknown seal schema")
        seal_hash = seal.get("seal_hash")
        unsigned = {key: value for key, value in seal.items() if key != "seal_hash"}
        if seal_hash != sha256(canonical(unsigned)):
            errors.append("seal_hash_mismatch")
        if expected_seal_hash is not None and seal_hash != expected_seal_hash:
            errors.append("external_seal_anchor_mismatch")
        actual = _inventory(root)
        if actual != seal.get("artifacts"):
            errors.append("artifact_inventory_mismatch")
        with (root / "events.jsonl").open("rb") as handle:
            for raw in handle:
                if not raw.endswith(b"\n"):
                    raise ValueError("partial event line")
                event = strict_loads(raw)
                count += 1
                required = {"episode_id", "seq", "event_id", "actor", "session", "call", "parent_ids", "monotonic_time", "kind", "state_before", "state_after", "permit_epoch", "data_ref", "data", "evidence_quality", "previous_hash", "event_hash"}
                if not isinstance(event, dict) or not required.issubset(event):
                    raise ValueError(f"event schema incomplete at {count}")
                if event["seq"] != count or event["previous_hash"] != head:
                    errors.append(f"chain_sequence_mismatch:{count}")
                if episode_id is None:
                    episode_id = event["episode_id"]
                if event["episode_id"] != episode_id or event["event_id"] != f"{episode_id}:{count}":
                    errors.append(f"event_identity_mismatch:{count}")
                calculated = sha256(canonical({key: value for key, value in event.items() if key != "event_hash"}))
                if calculated != event["event_hash"]:
                    errors.append(f"event_hash_mismatch:{count}")
                if event["data_ref"] != {"kind": "inline", "sha256": sha256(canonical(event["data"]))}:
                    errors.append(f"event_data_mismatch:{count}")
                if not isinstance(event["monotonic_time"], (int, float)) or not math.isfinite(event["monotonic_time"]):
                    errors.append(f"invalid_event_time:{count}")
                head = calculated
        if count != seal.get("event_count") or head != seal.get("event_chain_head"):
            errors.append("seal_event_summary_mismatch")
        if not count or episode_id != seal.get("episode_id"):
            errors.append("seal_episode_identity_mismatch")
    except (OSError, ValueError, TypeError, KeyError, UnicodeError) as exc:
        errors.append(f"invalid_or_unsealed_evidence:{type(exc).__name__}:{exc}")
    return {"ok": not errors, "errors": errors, "event_count": count,
            "seal_hash": seal.get("seal_hash") if isinstance(seal, dict) else None,
            "externally_anchored": expected_seal_hash is not None,
            "semantic_completeness_proven": False, "os_isolation_proven": False}
