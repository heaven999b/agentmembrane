"""Persistent, broker-facing RQ1 services; not an OS authentication boundary.

Only a trusted controller/broker may construct this object or invoke kernel
methods. ``dispatch`` takes the principal/actor from that authenticated broker,
never from model JSON. All service authorization and writes share one SQLite
transaction, so closing/revocation linearizes before or after a dispatch.
Actor free text never becomes a trusted checkpoint or control configuration.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from types import MappingProxyType
from typing import Any


LEVELS = {"A0": 0, "A1": 1, "A3": 3, "A4": 4}
# These are kernel minima, not model- or manifest-supplied defaults. In this
# four-level protocol low-level scratch is NOT the shared SQLite note service.
# A manifest may tighten a floor, never lower it (including for "private" notes).
SERVICE_MIN_LEVELS = MappingProxyType({
    "route.send": "A0", "route.consume": "A0", "control.load": "A0",
    "memory.append_note": "A4", "memory.read_notes": "A4",
    "memory.load_checkpoint": "A0", "capability.delegate": "A0",
    "capability.revoke": "A0",
})
ACTOR_ACTIONS = frozenset(SERVICE_MIN_LEVELS)
HOST_ONLY_ACTIONS = frozenset({"memory.load_checkpoint", "capability.delegate", "capability.revoke"})
PRIVILEGED_ACTIONS = frozenset({"memory.commit_checkpoint", "control.commit"})


class ServiceError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class ServiceTransactionFailure(sqlite3.OperationalError):
    """A failed commit/cleanup is not an ordinary denied service operation."""
    def __init__(self, code: str, fault: dict):
        super().__init__(code)
        self.code = code
        self.commit_unknown = bool(fault["commit_unknown"])
        self.fault = fault


def _json(value: Any) -> str:
    """Stable JSON, with no nonfinite values or non-JSON Python objects."""
    remaining = [100_000]
    def check(item: Any, depth: int = 0) -> None:
        remaining[0] -= 1
        if depth > 64 or remaining[0] < 0:
            raise ServiceError("invalid_json", "JSON exceeds structural limits")
        if item is None or type(item) in (str, bool, int):
            return
        if type(item) is float:
            if not (float("-inf") < item < float("inf")):
                raise ServiceError("invalid_json", "nonfinite number")
            return
        if type(item) is list:
            for child in item:
                check(child, depth + 1)
            return
        if type(item) is dict and all(type(key) is str for key in item):
            for child in item.values():
                check(child, depth + 1)
            return
        raise ServiceError("invalid_json", "only strict JSON values are accepted")
    check(value)
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))


def _text(value: Any, field: str, *, limit: int = 200_000, empty: bool = False) -> str:
    if type(value) is not str or (not empty and not value) or len(value) > limit or "\x00" in value:
        raise ServiceError("invalid_arguments", f"invalid {field}")
    return value


def _strings(value: Any, field: str) -> list[str]:
    if type(value) is not list or len(value) > 10_000:
        raise ServiceError("invalid_arguments", f"{field} must be a bounded string list")
    values = [_text(item, field, limit=1024) for item in value]
    if len(set(values)) != len(values):
        raise ServiceError("invalid_arguments", f"duplicate {field}")
    return sorted(values)


def _fields(arguments: Any, required: set[str], optional: set[str] | None = None) -> None:
    if type(arguments) is not dict or not required <= arguments.keys() or arguments.keys() - required - (optional or set()):
        raise ServiceError("invalid_arguments", "missing or additional fields")
    _json(arguments)


class SystemServices:
    """One persistent episode store. Reopening never resets epochs or leases."""

    def __init__(self, db_path: str, episode_id: str):
        self.db_path = str(db_path)
        self.episode_id = _text(episode_id, "episode_id", limit=1024)
        if self.db_path == ":memory:":
            raise ServiceError("nonpersistent_store", "use a real episode-local SQLite path")
        path = Path(self.db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        # This directory must be private to the broker in the deployment boundary.
        # File permissions alone do not protect against same-UID actor processes.
        if path.is_symlink():
            raise ServiceError("unsafe_store", "database path must not be a symlink")
        self._lock = threading.RLock()
        self._fault_path = Path(self.db_path + ".transaction_failures.jsonl")
        self._pending_transaction_faults: list[dict] = []
        self._fault_journal_error: str | None = None
        self._admission_faulted = bool(self._transaction_faults())
        self._db = sqlite3.connect(self.db_path, isolation_level=None, check_same_thread=False, timeout=10)
        os.chmod(self.db_path, 0o600)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS episode (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1), episode_id TEXT NOT NULL,
                task_id TEXT NOT NULL, world_id TEXT NOT NULL, status TEXT NOT NULL,
                epoch INTEGER NOT NULL, controller TEXT NOT NULL, steward TEXT NOT NULL,
                manifest TEXT NOT NULL, signing_key TEXT NOT NULL, created_at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS principals (
                actor TEXT PRIMARY KEY, principal TEXT UNIQUE NOT NULL, level TEXT NOT NULL,
                scopes TEXT NOT NULL, allowed_labels TEXT NOT NULL, context_labels TEXT NOT NULL,
                active_lease_id TEXT);
            CREATE TABLE IF NOT EXISTS leases (
                lease_id TEXT PRIMARY KEY, parent_id TEXT, principal TEXT NOT NULL, actor TEXT NOT NULL,
                level TEXT NOT NULL, scopes TEXT NOT NULL, epoch INTEGER NOT NULL,
                expires_at REAL NOT NULL, issued_by TEXT NOT NULL, signature TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(parent_id) REFERENCES leases(lease_id));
            CREATE TABLE IF NOT EXISTS notes (
                note_id TEXT PRIMARY KEY, actor TEXT NOT NULL, principal TEXT NOT NULL,
                visibility TEXT NOT NULL, content TEXT NOT NULL, labels TEXT NOT NULL, epoch INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS receipts (
                receipt_id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS checkpoints (
                checkpoint_id TEXT PRIMARY KEY, payload TEXT NOT NULL, writer TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS messages (
                message_id TEXT PRIMARY KEY, sender TEXT NOT NULL, sender_principal TEXT NOT NULL,
                recipient TEXT NOT NULL, content TEXT NOT NULL, labels TEXT NOT NULL,
                epoch INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS controls (
                version INTEGER PRIMARY KEY, manifest TEXT NOT NULL, manifest_hash TEXT NOT NULL,
                writer TEXT NOT NULL, active INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS audit (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL);
        """)
        columns = {row["name"] for row in self._db.execute("PRAGMA table_info(principals)")}
        if "active_lease_id" not in columns:
            self._db.execute("ALTER TABLE principals ADD COLUMN active_lease_id TEXT")
        row = self._db.execute("SELECT episode_id FROM episode").fetchone()
        if row and row["episode_id"] != self.episode_id:
            self._db.close()
            raise ServiceError("episode_mismatch", "database belongs to a different episode")

    @contextmanager
    def _transaction(self):
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield
            except BaseException as original_error:
                rollback_status = self._rollback_after_failure()
                if rollback_status == "rollback_failed":
                    fault = self._record_transaction_fault("body_rollback", original_error, rollback_status)
                    raise ServiceTransactionFailure("service_transaction_cleanup_unknown", fault) from original_error
                raise
            else:
                try:
                    self._db.execute("COMMIT")
                except BaseException as original_error:
                    # COMMIT may have actually succeeded before its completion
                    # notification failed. An inactive connection is NOT proof
                    # of rollback; preserve durable rows and uncertainty.
                    rollback_status = self._rollback_after_failure()
                    fault = self._record_transaction_fault("commit", original_error, rollback_status)
                    raise ServiceTransactionFailure("service_transaction_commit_unknown", fault) from original_error

    def _rollback_after_failure(self) -> str:
        try:
            if not self._db.in_transaction:
                return "no_active_transaction_outcome_not_inferred"
            self._db.execute("ROLLBACK")
            return "active_transaction_rolled_back" if not self._db.in_transaction else "rollback_failed"
        except BaseException:
            return "rollback_failed"

    def _record_transaction_fault(self, phase: str, error: BaseException, rollback_status: str) -> dict:
        self._admission_faulted = True
        record = {"episode_id": self.episode_id, "fault_id": secrets.token_hex(16),
                  "phase": phase, "error_class": type(error).__name__,
                  "rollback_status": rollback_status, "commit_unknown": True,
                  "actor_admission_stopped": True, "time_unix": time.time()}
        # An append-only side journal avoids relying on the transaction whose
        # COMMIT failed. It contains no message content, credentials or keys.
        # The private collector seals this artifact with the SQLite snapshot.
        try:
            flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self._fault_path, flags, 0o600)
            try:
                os.fchmod(descriptor, 0o600)
                raw = (_json(record) + "\n").encode()
                written = os.write(descriptor, raw)
                if written != len(raw):
                    raise OSError("transaction_fault_journal_short_write")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except (OSError, ValueError) as journal_error:
            self._fault_journal_error = type(journal_error).__name__
            self._pending_transaction_faults.append(record)
        return {**record, "journal_error": self._fault_journal_error}

    def _transaction_faults(self) -> list[dict]:
        if self._fault_path.is_symlink():
            raise ServiceError("unsafe_store", "transaction fault journal must not be a symlink")
        records = []
        if self._fault_path.exists():
            try:
                with self._fault_path.open("r", encoding="utf-8") as handle:
                    for line in handle:
                        if not line.endswith("\n"):
                            raise ValueError("truncated_transaction_fault_record")
                        value = json.loads(line)
                        if type(value) is not dict or value.get("episode_id") != self.episode_id or value.get("commit_unknown") is not True:
                            raise ValueError("invalid_transaction_fault_record")
                        records.append(value)
            except (OSError, ValueError) as error:
                raise ServiceError("transaction_fault_journal_unreadable", "transaction uncertainty cannot be recovered safely") from error
        known = {record.get("fault_id") for record in records}
        records.extend(record for record in self._pending_transaction_faults if record["fault_id"] not in known)
        return records

    def _episode(self) -> sqlite3.Row:
        row = self._db.execute("SELECT * FROM episode").fetchone()
        if row is None:
            raise ServiceError("not_initialized", "initialize through the trusted controller first")
        return row

    def _open(self) -> sqlite3.Row:
        row = self._episode()
        if row["status"] != "open":
            raise ServiceError("episode_closed", "episode admits no new actor work")
        if self._admission_faulted or self._transaction_faults():
            raise ServiceError("service_admission_faulted", "transaction outcome is uncertain; only trusted close/recovery may continue")
        return row

    def _principal(self, principal: str, actor: str) -> sqlite3.Row:
        row = self._db.execute("SELECT * FROM principals WHERE actor=?", (actor,)).fetchone()
        if row is None or row["principal"] != principal:
            raise ServiceError("identity_mismatch", "broker principal and registered actor do not match")
        return row

    def _effect(self, kind: str, principal: str, actor: str, object_type: str,
                object_id: str, before: Any, after: Any) -> dict:
        record = {"kind": kind, "episode_id": self.episode_id, "epoch": self._episode()["epoch"],
                  "principal": principal, "actor": actor, "object_type": object_type,
                  "object_id": object_id, "before": before, "after": after}
        cur = self._db.execute("INSERT INTO audit(payload) VALUES (?)", (_json(record),))
        record["service_seq"] = cur.lastrowid
        return record

    @staticmethod
    def _control_manifest(manifest: Any) -> dict:
        _fields(manifest, {"route_bindings", "tool_registry_hash", "memory_acl", "model_config_ref"})
        if type(manifest["route_bindings"]) is not dict or type(manifest["memory_acl"]) is not dict:
            raise ServiceError("invalid_arguments", "route bindings and memory ACL must be objects")
        for actor, recipients in manifest["route_bindings"].items():
            _text(actor, "route actor", limit=128)
            _strings(recipients, "route recipients")
        _fields(manifest["memory_acl"], {"trusted_writer"})
        _text(manifest["memory_acl"]["trusted_writer"], "trusted_writer")
        _text(manifest["tool_registry_hash"], "tool_registry_hash")
        _text(manifest["model_config_ref"], "model_config_ref")
        return json.loads(_json(manifest))

    def initialize(self, controller_identity: str, manifest: dict) -> dict:
        """Trusted kernel call only. Exact replay is idempotent, never a reset."""
        _text(controller_identity, "controller_identity")
        _fields(manifest, {"task_id", "world_id", "principals", "level_caps"},
                {"actor_levels", "allowed_labels", "approved_controls", "steward_identity",
                 "protocol_hash", "lease_ttl_seconds", "scope_min_levels", "label_min_levels"})
        _text(manifest["task_id"], "task_id")
        _text(manifest["world_id"], "world_id")
        principals, caps = manifest["principals"], manifest["level_caps"]
        if type(principals) is not dict or "H" not in principals or type(caps) is not dict or set(caps) != set(principals):
            raise ServiceError("invalid_manifest", "register H and an explicit scope ceiling for every actor")
        if set(principals) & {"controller", "steward"}:
            raise ServiceError("invalid_manifest", "TCB role names cannot be actor names")
        values = [_text(value, "principal") for value in principals.values()]
        steward = manifest.get("steward_identity", "steward")
        _text(steward, "steward_identity")
        if len(set(values)) != len(values) or controller_identity in values or steward in values or steward == controller_identity:
            raise ServiceError("invalid_manifest", "actors and TCB principals must have distinct identities")
        ttl = manifest.get("lease_ttl_seconds", 3600)
        if type(ttl) not in (int, float) or not 0 < ttl <= 86400:
            raise ServiceError("invalid_manifest", "lease TTL must be in (0,86400]")
        levels = manifest.get("actor_levels", {})
        allowed = manifest.get("allowed_labels", {})
        if type(levels) is not dict or type(allowed) is not dict or set(levels) - principals.keys() or set(allowed) - principals.keys():
            raise ServiceError("invalid_manifest", "unregistered level or label owner")
        rows = []
        for actor, principal in principals.items():
            _text(actor, "actor", limit=128)
            level = levels.get(actor, "A4" if actor == "H" else "A0")
            if type(level) is not str or level not in LEVELS:
                raise ServiceError("invalid_manifest", "unknown level")
            scopes = _strings(caps[actor], "level_caps")
            if any("*" in scope or scope in PRIVILEGED_ACTIONS for scope in scopes):
                raise ServiceError("invalid_manifest", "no wildcard or TCB write capabilities")
            if actor != "H" and set(scopes) & HOST_ONLY_ACTIONS:
                raise ServiceError("invalid_manifest", "external actors cannot administer grants or trusted recovery")
            labels = _strings(allowed.get(actor, ["public", "protected"] if LEVELS[level] >= 3 else ["public"]), "allowed_labels")
            rows.append((actor, principal, level, _json(scopes), _json(labels), _json(["public"])))
        minimums = manifest.get("scope_min_levels", {})
        if type(minimums) is not dict or any(type(value) is not str or value not in LEVELS for value in minimums.values()):
            raise ServiceError("invalid_manifest", "scope_min_levels must map explicit scopes to canonical levels")
        known_scopes = {scope for row in rows for scope in json.loads(row[3])}
        if set(minimums) - known_scopes:
            raise ServiceError("invalid_manifest", "minimum level supplied for an unregistered scope")
        for scope, floor in minimums.items():
            if scope in SERVICE_MIN_LEVELS and LEVELS[floor] < LEVELS[SERVICE_MIN_LEVELS[scope]]:
                raise ServiceError("invalid_manifest", "a manifest cannot lower a kernel service minimum")
        for row in rows:
            if any(self._scope_floor(scope, row[2], minimums) > LEVELS[row[2]] for scope in json.loads(row[3])):
                raise ServiceError("invalid_manifest", "registered scope is above the actor's level ceiling")
        label_minimums = manifest.get("label_min_levels", {})
        if type(label_minimums) is not dict or any(type(value) is not str or value not in LEVELS for value in label_minimums.values()):
            raise ServiceError("invalid_manifest", "label_min_levels must contain canonical levels")
        controls = manifest.get("approved_controls", [])
        if type(controls) is not list:
            raise ServiceError("invalid_manifest", "approved_controls must be a list")
        for control in controls:
            self._control_manifest(control)
            if control["memory_acl"]["trusted_writer"] != steward:
                raise ServiceError("invalid_manifest", "approved control may not replace the fixed checkpoint steward")
            if set(control["route_bindings"]) - principals.keys() or any(set(recipients) - principals.keys() for recipients in control["route_bindings"].values()):
                raise ServiceError("invalid_manifest", "control routes may name registered actors only")
        serialized = _json(manifest)
        with self._transaction():
            existing = self._db.execute("SELECT * FROM episode").fetchone()
            if existing:
                if existing["controller"] != controller_identity or existing["manifest"] != serialized:
                    raise ServiceError("initialization_conflict", "cannot replace an episode's original manifest")
                return {"episode_id": self.episode_id, "status": existing["status"], "epoch": existing["epoch"], "effects": []}
            self._db.execute("INSERT INTO episode VALUES (1,?,?,?,?,?,?,?,?,?,?)",
                             (self.episode_id, manifest["task_id"], manifest["world_id"], "open", 0,
                              controller_identity, steward, serialized, secrets.token_hex(32), time.time()))
            self._db.executemany("INSERT INTO principals(actor,principal,level,scopes,allowed_labels,context_labels) VALUES (?,?,?,?,?,?)", rows)
            effects = [self._effect("episode_initialized", controller_identity, "controller", "episode", self.episode_id,
                                    None, {"status": "open", "epoch": 0, "manifest": manifest})]
            if controls:
                _, effect = self._commit_control(controls[0], controller_identity)
                effects.append(effect)
            return {"episode_id": self.episode_id, "status": "open", "epoch": 0, "effects": effects}

    def _lease_payload(self, row: dict | sqlite3.Row) -> dict:
        return {key: row[key] for key in ("lease_id", "parent_id", "principal", "actor", "level", "scopes", "epoch", "expires_at", "issued_by")}

    def _sign(self, payload: dict) -> str:
        key = bytes.fromhex(self._episode()["signing_key"])
        return hmac.new(key, _json(payload).encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def _export_lease(row: sqlite3.Row | dict) -> dict:
        result = {key: row[key] for key in ("lease_id", "parent_id", "principal", "actor", "level", "epoch", "expires_at", "issued_by", "revoked")}
        result["scopes"] = json.loads(row["scopes"])
        result["revoked"] = bool(result["revoked"])
        return result

    @staticmethod
    def _scope_floor(scope: str, recipient_ceiling: str, configured: dict) -> int:
        if scope in SERVICE_MIN_LEVELS:
            return max(LEVELS[SERVICE_MIN_LEVELS[scope]], LEVELS[configured.get(scope, SERVICE_MIN_LEVELS[scope])])
        # Source-specific native tools are not guessed by their names. If the
        # trusted profile does not declare their floor, retain its ceiling.
        return LEVELS[configured.get(scope, recipient_ceiling)]

    def _valid_lease(self, lease_id: str) -> sqlite3.Row:
        episode = self._open()
        row = self._db.execute("SELECT * FROM leases WHERE lease_id=?", (lease_id,)).fetchone()
        if row is None:
            raise ServiceError("unknown_lease", "unknown or forged lease")
        current, seen = row, set()
        while current:
            if current["lease_id"] in seen:
                raise ServiceError("invalid_lease_chain", "cycle in parent grants")
            seen.add(current["lease_id"])
            if current["revoked"] or current["epoch"] != episode["epoch"] or current["expires_at"] <= time.time():
                raise ServiceError("inactive_lease", "revoked, stale, or expired lease")
            if not hmac.compare_digest(current["signature"], self._sign(self._lease_payload(current))):
                raise ServiceError("invalid_signature", "grant integrity check failed")
            if not current["parent_id"]:
                break
            child = current
            current = self._db.execute("SELECT * FROM leases WHERE lease_id=?", (child["parent_id"],)).fetchone()
            if current is None or not set(json.loads(child["scopes"])) <= set(json.loads(current["scopes"])) or LEVELS[child["level"]] > LEVELS[current["level"]] or child["expires_at"] > current["expires_at"]:
                raise ServiceError("invalid_lease_chain", "child exceeds or lacks a valid parent")
        return row

    def _check(self, lease_id: str, principal: str, actor: str, action: str, epoch: int | None = None) -> sqlite3.Row:
        identity = self._principal(principal, actor)
        row = self._valid_lease(lease_id)
        if row["principal"] != principal or row["actor"] != actor:
            raise ServiceError("identity_mismatch", "lease is bound to a different broker principal")
        if identity["active_lease_id"] != lease_id:
            raise ServiceError("inactive_lease", "lease is not the actor's current effective grant")
        if epoch is not None and (type(epoch) is not int or epoch != row["epoch"]):
            raise ServiceError("stale_epoch", "permit epoch does not match its active lease")
        if action not in json.loads(row["scopes"]) or action not in json.loads(identity["scopes"]):
            raise ServiceError("scope_denied", "action is outside the effective registered grant")
        if actor != "H" and action in HOST_ONLY_ACTIONS:
            raise ServiceError("issuer_denied", "service is restricted to the registered host role")
        configured = json.loads(self._episode()["manifest"]).get("scope_min_levels", {})
        if LEVELS[row["level"]] < self._scope_floor(action, identity["level"], configured):
            raise ServiceError("scope_level_mismatch", "effective grant is below the kernel or configured action minimum")
        if LEVELS[row["level"]] > LEVELS[identity["level"]]:
            raise ServiceError("ceiling_exceeded", "grant level exceeds its registered ceiling")
        return row

    def issue_lease(self, parent_id: str | None, principal: str, level: str, scopes: list[str], actor: str,
                    issuer: str = "controller") -> dict:
        """Kernel-only initial issuance. H delegation uses authenticated dispatch."""
        with self._transaction():
            if issuer != self._open()["controller"]:
                raise ServiceError("issuer_denied", "only the trusted controller issues initial grants")
            lease, effects = self._issue(parent_id, principal, level, scopes, actor, issuer)
            return {**lease, "effects": effects}

    def _issue(self, parent_id: str | None, principal: str, level: str, scopes: list[str], actor: str, issuer: str):
        episode = self._open()
        identity = self._principal(principal, actor)
        scopes = _strings(scopes, "scopes")
        if type(level) is not str or level not in LEVELS or LEVELS[level] > LEVELS[identity["level"]] or not set(scopes) <= set(json.loads(identity["scopes"])):
            raise ServiceError("ceiling_exceeded", "requested grant exceeds the recipient's registered ceiling")
        manifest = json.loads(episode["manifest"])
        minimums = manifest.get("scope_min_levels", {})
        for scope in scopes:
            if actor != "H" and scope in HOST_ONLY_ACTIONS:
                raise ServiceError("issuer_denied", "external recipients cannot receive host-only services")
            if LEVELS[level] < self._scope_floor(scope, identity["level"], minimums):
                raise ServiceError("scope_level_mismatch", "a lower lease level cannot retain a higher-level scope")
        ttl = manifest.get("lease_ttl_seconds", 3600)
        expires = time.time() + ttl
        if parent_id is not None:
            parent = self._valid_lease(parent_id)
            if parent["actor"] == actor:
                raise ServiceError("delegation_denied", "replacement grant cannot depend on its own superseded grant")
            if not set(scopes) <= set(json.loads(parent["scopes"])) or LEVELS[level] > LEVELS[parent["level"]]:
                raise ServiceError("delegation_expansion", "child grant must be contained in the parent")
            expires = min(expires, parent["expires_at"])
        payload = {"lease_id": secrets.token_urlsafe(32), "parent_id": parent_id, "principal": principal,
                   "actor": actor, "level": level, "scopes": _json(scopes), "epoch": episode["epoch"],
                   "expires_at": expires, "issued_by": issuer}
        signature = self._sign(payload)
        effects = []
        if identity["active_lease_id"] is not None:
            effects.extend(self._revoke(identity["active_lease_id"], issuer, "controller" if issuer == episode["controller"] else "H")["effects"])
        self._db.execute("INSERT INTO leases VALUES (?,?,?,?,?,?,?,?,?,?,0)",
                         tuple(payload[key] for key in ("lease_id", "parent_id", "principal", "actor", "level", "scopes", "epoch", "expires_at", "issued_by")) + (signature,))
        self._db.execute("UPDATE principals SET active_lease_id=? WHERE actor=?", (payload["lease_id"], actor))
        exported = self._export_lease({**payload, "revoked": 0})
        effects.append(self._effect("lease_issued", issuer, "controller" if issuer == episode["controller"] else "H",
                                    "lease", payload["lease_id"], None, exported))
        return exported, effects

    def authorize(self, lease_id: str, principal: str, action: str, epoch: int | None = None) -> bool:
        """Check the current grant; native backends must recheck at actual entry.

        This result is not a permit that remains valid across close/revoke. Service
        dispatch itself performs check plus write in one transaction.
        """
        try:
            _text(lease_id, "lease_id")
            _text(principal, "principal")
            _text(action, "action")
            with self._transaction():
                row = self._db.execute("SELECT actor FROM leases WHERE lease_id=?", (lease_id,)).fetchone()
                if row is None:
                    return False
                self._check(lease_id, principal, row["actor"], action, epoch)
            return True
        except ServiceError:
            return False

    def _descendants(self, lease_id: str) -> list[sqlite3.Row]:
        row = self._db.execute("SELECT * FROM leases WHERE lease_id=?", (lease_id,)).fetchone()
        if row is None:
            raise ServiceError("unknown_lease", "lease does not exist")
        found, stack, seen = [], [row], set()
        while stack:
            current = stack.pop()
            if current["lease_id"] in seen:
                raise ServiceError("invalid_lease_chain", "cycle in lease descendants")
            seen.add(current["lease_id"])
            found.append(current)
            stack.extend(self._db.execute("SELECT * FROM leases WHERE parent_id=?", (current["lease_id"],)).fetchall())
        return found

    def _revoke(self, lease_id: str, issuer: str, actor: str) -> dict:
        effects = []
        for row in self._descendants(lease_id):
            if not row["revoked"]:
                before = self._export_lease(row)
                self._db.execute("UPDATE leases SET revoked=1 WHERE lease_id=?", (row["lease_id"],))
                effects.append(self._effect("lease_revoked", issuer, actor, "lease", row["lease_id"], before, {**before, "revoked": True}))
        return {"lease_id": lease_id, "revoked": True, "effects": effects}

    def revoke(self, lease_id: str, issuer: str = "controller") -> dict:
        with self._transaction():
            if issuer != self._episode()["controller"]:
                raise ServiceError("issuer_denied", "kernel revoke requires the controller")
            return self._revoke(lease_id, issuer, "controller")

    def record_delivery(self, principal: str, actor: str, labels: list[str]) -> dict:
        """Trusted instrumentation hook AFTER actual delivery, not an actor API.

        Record even an erroneously delivered label outside the recipient ceiling;
        otherwise a boundary defect would vanish from the evidence. No declassification.
        """
        labels = _strings(labels, "labels")
        with self._transaction():
            self._open()
            identity = self._principal(principal, actor)
            before = json.loads(identity["context_labels"])
            after = sorted(set(before) | set(labels))
            self._db.execute("UPDATE principals SET context_labels=? WHERE actor=?", (_json(after), actor))
            effect = self._effect("delivery_labels_updated", principal, actor, "context", actor, before, after)
            return {"labels": after, "effects": [effect]}

    def _outgoing_labels(self, identity: sqlite3.Row, arguments: dict) -> list[str]:
        labels = _strings(arguments.get("labels", []), "labels")
        return sorted(set(json.loads(identity["context_labels"])) | set(labels))

    def _label_floor(self, label: str) -> int:
        minimums = json.loads(self._episode()["manifest"]).get("label_min_levels", {})
        if label in minimums:
            return LEVELS[minimums[label]]
        if label == "public" or label.startswith("public:"):
            return 0
        if label == "protected:workspace":
            return 4
        if label == "protected" or label.startswith("protected:"):
            return 3
        return 4

    def _can_receive(self, recipient: sqlite3.Row, labels: list[str]) -> bool:
        if not recipient["active_lease_id"]:
            return False
        try:
            lease = self._valid_lease(recipient["active_lease_id"])
        except ServiceError:
            return False
        return (set(labels) <= set(json.loads(recipient["allowed_labels"]))
                and all(self._label_floor(label) <= LEVELS[lease["level"]] for label in labels))

    def refresh_recipient_labels(self, principal: str, actor: str, labels: list[str], *, lease_id: str) -> dict:
        """Trusted broker recomputes the role/object view from live native state.

        This is NOT exposed in actor dispatch. It updates permission to receive
        future information; previously delivered context labels are never erased.
        """
        labels = _strings(labels, "labels")
        with self._transaction():
            identity = self._principal(principal, actor)
            lease = self._valid_lease(lease_id)
            if lease["principal"] != principal or lease["actor"] != actor or identity["active_lease_id"] != lease_id:
                raise ServiceError("identity_mismatch", "label refresh requires the current principal-bound grant")
            if any(self._label_floor(label) > LEVELS[lease["level"]] for label in labels):
                raise ServiceError("label_level_mismatch", "recipient labels exceed the effective lease level")
            before = json.loads(identity["allowed_labels"])
            self._db.execute("UPDATE principals SET allowed_labels=? WHERE actor=?", (_json(labels), actor))
            effect = self._effect("recipient_labels_refreshed", self._episode()["controller"], "controller", "recipient_view", actor, before, labels)
            return {"labels": labels, "effects": [effect]}

    def record_receipt(self, receipt: dict, issuer: str = "controller") -> dict:
        """Trusted native-service evidence ingestion, never dispatched to actors."""
        _fields(receipt, {"receipt_id", "task_id", "world_id", "status", "state_hash", "labels"},
                {"call_id", "actor", "tool", "effects_hash"})
        for key in receipt.keys() - {"labels"}:
            _text(receipt[key], key)
        _strings(receipt["labels"], "labels")
        if receipt["status"] not in {"committed", "failed_without_effect", "failed_with_effect", "commit_unknown"}:
            raise ServiceError("invalid_receipt", "unknown receipt status")
        with self._transaction():
            episode = self._episode()
            if issuer not in {episode["controller"], episode["steward"]}:
                raise ServiceError("issuer_denied", "receipt ingestion is trusted-native-only")
            if receipt["task_id"] != episode["task_id"] or receipt["world_id"] != episode["world_id"]:
                raise ServiceError("receipt_mismatch", "receipt belongs to another task/world")
            existing = self._db.execute("SELECT payload FROM receipts WHERE receipt_id=?", (receipt["receipt_id"],)).fetchone()
            payload = _json(receipt)
            if existing:
                if existing["payload"] != payload:
                    raise ServiceError("receipt_conflict", "receipt identifiers are immutable")
                return {"receipt_id": receipt["receipt_id"], "effects": []}
            # Late confirmed effects can be recorded after close, never silently lost.
            self._db.execute("INSERT INTO receipts VALUES (?,?)", (receipt["receipt_id"], payload))
            effect = self._effect("receipt_recorded", issuer, "steward", "receipt", receipt["receipt_id"], None, receipt)
            return {"receipt_id": receipt["receipt_id"], "effects": [effect]}

    def commit_checkpoint(self, receipt_ids: list[str], *, issuer: str = "steward") -> dict:
        """TCB steward writes confirmed receipts only; it cannot promote free text."""
        receipt_ids = _strings(receipt_ids, "receipt_ids")
        if not receipt_ids:
            raise ServiceError("invalid_checkpoint", "checkpoint requires at least one confirmed receipt")
        with self._transaction():
            episode = self._episode()
            if issuer != episode["steward"]:
                raise ServiceError("issuer_denied", "only the fixed steward commits checkpoints")
            control = self._load_control()
            if control is None or control["manifest"]["memory_acl"]["trusted_writer"] != issuer:
                raise ServiceError("checkpoint_acl_denied", "active control does not authorize this fixed steward")
            refs, labels = [], set()
            for receipt_id in receipt_ids:
                row = self._db.execute("SELECT payload FROM receipts WHERE receipt_id=?", (receipt_id,)).fetchone()
                if row is None:
                    raise ServiceError("unknown_receipt", "cannot checkpoint an unconfirmed receipt reference")
                receipt = json.loads(row["payload"])
                if receipt["status"] == "commit_unknown":
                    raise ServiceError("unconfirmed_receipt", "unknown commit cannot become a confirmed checkpoint")
                refs.append({"receipt_id": receipt_id, "status": receipt["status"],
                             "receipt_hash": hashlib.sha256(row["payload"].encode()).hexdigest()})
                labels.update(receipt["labels"])
            checkpoint = {"episode_id": self.episode_id, "task_id": episode["task_id"], "world_id": episode["world_id"],
                          "epoch": episode["epoch"], "receipts": refs, "labels": sorted(labels), "status": "confirmed_receipts"}
            checkpoint_id = hashlib.sha256(_json(checkpoint).encode()).hexdigest()
            checkpoint["checkpoint_id"] = checkpoint_id
            existing = self._db.execute("SELECT payload FROM checkpoints WHERE checkpoint_id=?", (checkpoint_id,)).fetchone()
            effects = []
            if existing is None:
                self._db.execute("INSERT INTO checkpoints VALUES (?,?,?)", (checkpoint_id, _json(checkpoint), issuer))
                effects.append(self._effect("checkpoint_committed", issuer, "steward", "checkpoint", checkpoint_id, None, checkpoint))
            return {**checkpoint, "effects": effects}

    def load_checkpoint(self, checkpoint_id: str | None = None) -> dict | None:
        """Trusted recovery/fresh-reader path. Read-only and valid after close."""
        with self._transaction():
            episode = self._episode()
            query = "SELECT payload FROM checkpoints WHERE checkpoint_id=?" if checkpoint_id else "SELECT payload FROM checkpoints ORDER BY rowid DESC LIMIT 1"
            row = self._db.execute(query, (checkpoint_id,) if checkpoint_id else ()).fetchone()
            if row is None:
                return None
            checkpoint = json.loads(row["payload"])
            if checkpoint["task_id"] != episode["task_id"] or checkpoint["world_id"] != episode["world_id"] or checkpoint["epoch"] > episode["epoch"]:
                raise ServiceError("checkpoint_mismatch", "checkpoint does not match the stored task/world/epoch")
            for ref in checkpoint["receipts"]:
                receipt = self._db.execute("SELECT payload FROM receipts WHERE receipt_id=?", (ref["receipt_id"],)).fetchone()
                if receipt is None or hashlib.sha256(receipt["payload"].encode()).hexdigest() != ref["receipt_hash"]:
                    raise ServiceError("checkpoint_corrupt", "checkpoint receipt integrity failed")
            return checkpoint

    def _commit_control(self, manifest: dict, issuer: str):
        manifest = self._control_manifest(manifest)
        episode = self._episode()
        if issuer != episode["controller"]:
            raise ServiceError("issuer_denied", "only the controller commits approved control manifests")
        approved = json.loads(episode["manifest"]).get("approved_controls", [])
        if _json(manifest) not in {_json(value) for value in approved}:
            raise ServiceError("unapproved_control", "control is absent from the initial approved manifest list")
        old = self._db.execute("SELECT * FROM controls WHERE active=1").fetchone()
        version = self._db.execute("SELECT COALESCE(MAX(version),0)+1 FROM controls").fetchone()[0]
        self._db.execute("UPDATE controls SET active=0")
        digest = hashlib.sha256(_json(manifest).encode()).hexdigest()
        self._db.execute("INSERT INTO controls VALUES (?,?,?,?,1)", (version, _json(manifest), digest, issuer))
        result = {"version": version, "manifest": manifest, "manifest_hash": digest, "writer": issuer, "active": True}
        before = None if old is None else {"version": old["version"], "manifest": json.loads(old["manifest"]), "manifest_hash": old["manifest_hash"]}
        return result, self._effect("control_committed", issuer, "controller", "control", str(version), before, result)

    def commit_control(self, manifest: dict, *, issuer: str = "controller") -> dict:
        with self._transaction():
            self._open()
            result, effect = self._commit_control(manifest, issuer)
            return {**result, "effects": [effect]}

    def _load_control(self) -> dict | None:
        row = self._db.execute("SELECT * FROM controls WHERE active=1").fetchone()
        if row is None:
            return None
        manifest = json.loads(row["manifest"])
        digest = hashlib.sha256(_json(manifest).encode()).hexdigest()
        if digest != row["manifest_hash"] or _json(manifest) not in {_json(value) for value in json.loads(self._episode()["manifest"]).get("approved_controls", [])}:
            raise ServiceError("control_corrupt", "active control does not match a registered approved manifest")
        return {"version": row["version"], "manifest": manifest, "manifest_hash": digest, "writer": row["writer"], "active": True}

    def load_control(self) -> dict | None:
        """Trusted broker/driver reads actual active configuration on each use."""
        with self._transaction():
            self._episode()
            return self._load_control()

    def dispatch(self, principal: str, actor: str, action: str, arguments: dict, *, lease_id: str) -> dict:
        """Authenticated actor API. Identifiers in arguments never override actor."""
        try:
            for value, field in ((principal, "principal"), (actor, "actor"), (action, "action"), (lease_id, "lease_id")):
                _text(value, field, limit=1024)
            if type(arguments) is not dict:
                raise ServiceError("invalid_arguments", "arguments must be an object")
            _json(arguments)
            if action not in ACTOR_ACTIONS:
                raise ServiceError("unknown_or_privileged_action", "action is not exposed to actors")
            with self._transaction():
                lease = self._check(lease_id, principal, actor, action)
                identity = self._principal(principal, actor)
                result, effects = self._dispatch(principal, actor, action, arguments, lease, identity)
            return {"ok": True, "result": result, "error": None, "effects": effects}
        except ServiceError as error:
            return {"ok": False, "result": None, "error": {"code": error.code, "message": str(error)}, "effects": []}

    def _dispatch(self, principal: str, actor: str, action: str, arguments: dict,
                  lease: sqlite3.Row, identity: sqlite3.Row):
        epoch = self._episode()["epoch"]
        if action == "route.send":
            _fields(arguments, {"recipient", "content"}, {"labels"})
            recipient_id = _text(arguments["recipient"], "recipient", limit=128)
            recipient = self._db.execute("SELECT * FROM principals WHERE actor=?", (recipient_id,)).fetchone()
            if recipient is None or (actor != "H" and LEVELS[lease["level"]] < 4 and recipient_id != "H"):
                raise ServiceError("recipient_denied", "recipient is outside the fixed registered route")
            control = self._load_control()
            if control is None or recipient_id not in control["manifest"]["route_bindings"].get(actor, []):
                raise ServiceError("route_binding_denied", "active control does not bind this sender to this recipient")
            labels = self._outgoing_labels(identity, arguments)
            if not self._can_receive(recipient, labels):
                raise ServiceError("information_flow_denied", "recipient cannot receive the sender's accumulated source labels")
            content = _text(arguments["content"], "content", empty=True)
            message_id = secrets.token_hex(16)
            result = {"message_id": message_id, "sender": actor, "sender_principal": principal,
                      "recipient": recipient_id, "content": content, "labels": labels, "epoch": epoch, "consumed": False}
            self._db.execute("INSERT INTO messages VALUES (?,?,?,?,?,?,?,0)", (message_id, actor, principal, recipient_id, content, _json(labels), epoch))
            return result, [self._effect("mailbox_sent", principal, actor, "message", message_id, None, result)]
        if action == "route.consume":
            _fields(arguments, set(), {"limit"})
            limit = arguments.get("limit", 100)
            if type(limit) is not int or not 1 <= limit <= 1000:
                raise ServiceError("invalid_arguments", "consume limit must be 1..1000")
            rows = self._db.execute("SELECT * FROM messages WHERE recipient=? AND consumed=0 ORDER BY rowid LIMIT ?", (actor, limit)).fetchall()
            results, effects, context = [], [], set(json.loads(identity["context_labels"]))
            for row in rows:
                control = self._load_control()
                if control is None or actor not in control["manifest"]["route_bindings"].get(row["sender"], []):
                    raise ServiceError("route_binding_denied", "active control no longer permits this queued delivery")
                labels = json.loads(row["labels"])
                if not self._can_receive(identity, labels):
                    raise ServiceError("information_flow_denied", "stored message labels exceed recipient capability")
                before = dict(row)
                before["labels"], before["consumed"] = labels, False
                after = {**before, "consumed": True}
                self._db.execute("UPDATE messages SET consumed=1 WHERE message_id=?", (row["message_id"],))
                effects.append(self._effect("mailbox_consumed", principal, actor, "message", row["message_id"], before, after))
                results.append(after)
                context.update(labels)
            self._db.execute("UPDATE principals SET context_labels=? WHERE actor=?", (_json(sorted(context)), actor))
            return results, effects
        if action == "memory.append_note":
            _fields(arguments, {"content"}, {"visibility", "labels"})
            visibility = arguments.get("visibility", "private")
            if type(visibility) is not str or visibility not in {"private", "shared"}:
                raise ServiceError("invalid_arguments", "visibility must be private or shared")
            if visibility == "shared" and LEVELS[lease["level"]] < 4:
                raise ServiceError("scope_denied", "shared collaboration notes require A4")
            labels = self._outgoing_labels(identity, arguments)
            content = _text(arguments["content"], "content", empty=True)
            note_id = secrets.token_hex(16)
            result = {"note_id": note_id, "actor": actor, "principal": principal, "visibility": visibility,
                      "content": content, "labels": labels, "epoch": epoch}
            self._db.execute("INSERT INTO notes VALUES (?,?,?,?,?,?,?)", (note_id, actor, principal, visibility, content, _json(labels), epoch))
            return result, [self._effect("note_appended", principal, actor, "note", note_id, None, result)]
        if action == "memory.read_notes":
            _fields(arguments, set(), {"visibility"})
            visibility = arguments.get("visibility", "accessible")
            if type(visibility) is not str or visibility not in {"private", "shared", "accessible"}:
                raise ServiceError("invalid_arguments", "unknown note view")
            results, context = [], set(json.loads(identity["context_labels"]))
            for row in self._db.execute("SELECT * FROM notes ORDER BY rowid").fetchall():
                own = row["actor"] == actor
                shared_access = row["visibility"] == "shared" and (actor == "H" or LEVELS[lease["level"]] >= 4)
                if not own and not shared_access:
                    continue
                if visibility != "accessible" and row["visibility"] != visibility:
                    continue
                labels = json.loads(row["labels"])
                if not own and not self._can_receive(identity, labels):
                    continue
                result = {**dict(row), "labels": labels}
                results.append(result)
                context.update(labels)
            self._db.execute("UPDATE principals SET context_labels=? WHERE actor=?", (_json(sorted(context)), actor))
            effect = self._effect("notes_read", principal, actor, "note_view", actor, None,
                                  {"note_ids": [row["note_id"] for row in results], "labels": sorted(context)})
            return results, [effect]
        if action == "capability.delegate":
            _fields(arguments, {"actor", "level", "scopes"}, {"principal"})
            if actor != "H":
                raise ServiceError("delegation_denied", "only H may request a narrowed delegate")
            child_actor = _text(arguments["actor"], "actor", limit=128)
            if child_actor == "H":
                raise ServiceError("delegation_denied", "H cannot delegate to itself")
            child = self._db.execute("SELECT * FROM principals WHERE actor=?", (child_actor,)).fetchone()
            if child is None or arguments.get("principal", child["principal"]) != child["principal"]:
                raise ServiceError("identity_mismatch", "delegation recipient must match a pre-registered external principal")
            result, effects = self._issue(lease["lease_id"], child["principal"], arguments["level"], arguments["scopes"], child_actor, principal)
            return result, effects
        if action == "capability.revoke":
            _fields(arguments, {"lease_id"})
            if actor != "H":
                raise ServiceError("issuer_denied", "external actors cannot revoke grants")
            target = _text(arguments["lease_id"], "lease_id")
            descendants = {row["lease_id"] for row in self._descendants(lease["lease_id"])} - {lease["lease_id"]}
            if target not in descendants:
                raise ServiceError("issuer_denied", "H may revoke only descendants of its current lease")
            result = self._revoke(target, principal, actor)
            return {key: value for key, value in result.items() if key != "effects"}, result["effects"]
        if action == "control.load":
            _fields(arguments, set())
            control = self._load_control()
            result = None if control is None else {"version": control["version"], "manifest_hash": control["manifest_hash"]}
            return result, [self._effect("control_loaded", principal, actor, "control_view", actor, None, result)]
        if action == "memory.load_checkpoint":
            _fields(arguments, set(), {"checkpoint_id"})
            if actor != "H":
                raise ServiceError("issuer_denied", "trusted recovery is restricted to H")
            # Avoid nested transactions; use the same verifier as the kernel path
            # through this explicit inline lookup and receipt validation.
            checkpoint_id = arguments.get("checkpoint_id")
            if "checkpoint_id" in arguments:
                _text(checkpoint_id, "checkpoint_id")
            query = "SELECT payload FROM checkpoints WHERE checkpoint_id=?" if checkpoint_id else "SELECT payload FROM checkpoints ORDER BY rowid DESC LIMIT 1"
            row = self._db.execute(query, (checkpoint_id,) if checkpoint_id else ()).fetchone()
            if row is None:
                return None, []
            checkpoint = json.loads(row["payload"])
            episode = self._episode()
            if checkpoint["task_id"] != episode["task_id"] or checkpoint["world_id"] != episode["world_id"] or checkpoint["epoch"] > episode["epoch"]:
                raise ServiceError("checkpoint_mismatch", "recovery task/world/epoch mismatch")
            if not self._can_receive(identity, checkpoint["labels"]):
                raise ServiceError("information_flow_denied", "checkpoint labels exceed H visibility")
            for ref in checkpoint["receipts"]:
                receipt = self._db.execute("SELECT payload FROM receipts WHERE receipt_id=?", (ref["receipt_id"],)).fetchone()
                if receipt is None or hashlib.sha256(receipt["payload"].encode()).hexdigest() != ref["receipt_hash"]:
                    raise ServiceError("checkpoint_corrupt", "checkpoint receipt integrity failed")
            context = sorted(set(json.loads(identity["context_labels"])) | set(checkpoint["labels"]))
            self._db.execute("UPDATE principals SET context_labels=? WHERE actor=?", (_json(context), actor))
            return checkpoint, [self._effect("checkpoint_loaded", principal, actor, "checkpoint", checkpoint["checkpoint_id"], None, checkpoint)]
        raise ServiceError("unknown_action", "unimplemented action")

    def close(self) -> dict:
        """Atomic admission stop, epoch advance and recursive grant invalidation.

        This closes actor services, not the SQLite connection. Native in-flight
        effects must be drained by the runtime and can be recorded as receipts.
        """
        with self._transaction():
            episode = self._episode()
            if episode["status"] == "closed":
                return {"status": "closed", "epoch": episode["epoch"], "effects": []}
            old_epoch = episode["epoch"]
            leases = self._db.execute("SELECT * FROM leases WHERE revoked=0").fetchall()
            self._db.execute("UPDATE episode SET status='closed',epoch=epoch+1")
            self._db.execute("UPDATE leases SET revoked=1")
            effects = []
            for row in leases:
                before = self._export_lease(row)
                effects.append(self._effect("lease_revoked", episode["controller"], "controller", "lease", row["lease_id"], before, {**before, "revoked": True}))
            effects.append(self._effect("episode_closed", episode["controller"], "controller", "episode", self.episode_id,
                                        {"status": "open", "epoch": old_epoch}, {"status": "closed", "epoch": old_epoch + 1}))
            return {"status": "closed", "epoch": old_epoch + 1, "revoked_count": len(leases), "effects": effects}

    def snapshot(self) -> dict:
        """Private evaluation export: real objects, never the grant signing key."""
        with self._transaction():
            episode = self._episode()
            result = {"episode": {key: episode[key] for key in ("episode_id", "task_id", "world_id", "status", "epoch", "controller", "steward")},
                      "manifest": json.loads(episode["manifest"])}
            result["transaction_failures"] = self._transaction_faults()
            result["transaction_fault_journal_error"] = self._fault_journal_error
            result["principals"] = [{**dict(row), "scopes": json.loads(row["scopes"]), "allowed_labels": json.loads(row["allowed_labels"]), "context_labels": json.loads(row["context_labels"])}
                                    for row in self._db.execute("SELECT * FROM principals ORDER BY actor")]
            result["leases"] = [self._export_lease(row) for row in self._db.execute("SELECT * FROM leases ORDER BY rowid")]
            for table in ("notes", "messages"):
                rows = []
                for row in self._db.execute(f"SELECT * FROM {table} ORDER BY rowid"):
                    value = {**dict(row), "labels": json.loads(row["labels"])}
                    if table == "messages":
                        value["consumed"] = bool(value["consumed"])
                    rows.append(value)
                result[table] = rows
            for table in ("receipts", "checkpoints"):
                result[table] = [json.loads(row["payload"]) for row in self._db.execute(f"SELECT payload FROM {table} ORDER BY rowid")]
            result["controls"] = [{**dict(row), "manifest": json.loads(row["manifest"]), "active": bool(row["active"])}
                                  for row in self._db.execute("SELECT * FROM controls ORDER BY version")]
            result["audit"] = [{**json.loads(row["payload"]), "service_seq": row["seq"]} for row in self._db.execute("SELECT * FROM audit ORDER BY seq")]
            return result

    def disconnect(self) -> None:
        """Release the trusted database connection without altering episode state."""
        with self._lock:
            self._db.close()
