"""Immutable cache, run lock, and run-state primitives for Host-Boundary V2."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import threading
from typing import Any, Mapping
from uuid import uuid4

from .schema import (
    IntegrityError,
    RunState,
    atomic_write_json,
    canonical_json_bytes,
    sha256_bytes,
)


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ATTEMPT_KEY_RE = re.compile(r"^(?P<request>[0-9a-f]{64}):(?P<index>[1-9][0-9]*)$")
_TRANSPORT_FAILURES = frozenset({"transport", "transport_failure"})
_IMMUTABLE_DELIVERED_FAILURES = frozenset(
    {
        "none",
        "explicit_abstention",
        "provider_policy",
        "provider_policy_failure",
        "parse",
        "parse_failure",
        "schema",
        "schema_failure",
        "environment_failure",
        "oracle_failure",
        "other_failure",
    }
)
_RUN_STATE_FIELDS = frozenset(
    {
        "schema_version",
        "run_id",
        "state",
        "revision",
        "updated_at",
        "completed_episodes",
        "expected_episodes",
        "active_execution_session_id",
        "last_completed_ordinal",
        "suspension_reason",
        "terminal_reason",
    }
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _require_sha256(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise IntegrityError(f"{field} must be a lowercase SHA-256")
    return value


def _load_json_mapping(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"cannot read valid JSON from {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise IntegrityError(f"{path} must contain a JSON object")
    return value


def _nonnegative_integer(value: Any, *, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise IntegrityError(f"{field} must be a non-negative integer")
    return value


def _positive_integer(value: Any, *, field: str) -> int:
    result = _nonnegative_integer(value, field=field)
    if result == 0:
        raise IntegrityError(f"{field} must be a positive integer")
    return result


def _request_retry_budget(request: Mapping[str, Any]) -> int:
    policy = request.get("retry_policy")
    if not isinstance(policy, Mapping):
        raise IntegrityError("request.retry_policy must be a mapping")
    return _nonnegative_integer(
        policy.get("request_level_transport_retries"),
        field="request.retry_policy.request_level_transport_retries",
    )


def _fsync_directory(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:  # pragma: no cover - only unusual filesystems
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_immutable_json(path: Path, value: Mapping[str, Any]) -> None:
    """Publish complete bytes once; concurrent unequal writers cannot win."""

    data = canonical_json_bytes(dict(value))
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.{uuid4().hex}.tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            # Linking, unlike replace(), cannot overwrite an entry published by
            # another worker between our existence check and publication.
            os.link(temporary, path)
            _fsync_directory(path.parent)
        except FileExistsError:
            try:
                existing = path.read_bytes()
            except OSError as exc:  # pragma: no cover - filesystem corruption
                raise IntegrityError(f"cannot inspect immutable cache entry {path}") from exc
            if existing != data:
                raise IntegrityError(f"immutable cache collision at {path}")
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


@dataclass(frozen=True)
class CacheIdentity:
    implementation_sha256: str
    protocol_sha256: str
    resolved_model_id: str
    provider_route_id: str

    def __post_init__(self) -> None:
        _require_sha256(self.implementation_sha256, field="implementation_sha256")
        _require_sha256(self.protocol_sha256, field="protocol_sha256")
        if not isinstance(self.resolved_model_id, str) or not self.resolved_model_id:
            raise IntegrityError("resolved_model_id must be non-empty")
        if not isinstance(self.provider_route_id, str) or not self.provider_route_id:
            raise IntegrityError("provider_route_id must be non-empty")

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def episode_id(schedule_row: dict[str, Any], *, protocol_sha256: str) -> str:
    """Bind an episode to its complete row and protocol, without recursion."""

    _require_sha256(protocol_sha256, field="protocol_sha256")
    row = dict(schedule_row)
    row.pop("episode_id", None)
    return sha256_bytes(
        canonical_json_bytes(
            {"namespace": "host-v2-episode", "protocol_sha256": protocol_sha256, "row": row}
        )
    )


def attempt_key(request_key: str, attempt_index: int) -> str:
    _require_sha256(request_key, field="request_key")
    if not isinstance(attempt_index, int) or isinstance(attempt_index, bool) or attempt_index < 1:
        raise IntegrityError("attempt_index must be a positive integer")
    return f"{request_key}:{attempt_index}"


def _split_attempt_key(value: str) -> tuple[str, int]:
    if not isinstance(value, str):
        raise IntegrityError("attempt_key must be a string")
    match = _ATTEMPT_KEY_RE.fullmatch(value)
    if match is None:
        raise IntegrityError("attempt_key is not a canonical namespaced key")
    return match.group("request"), int(match.group("index"))


def failure_is_retryable(value: Mapping[str, Any]) -> bool:
    """Only an already-recorded transport failure may be retried."""

    failure_class = value.get("failure_class")
    if not isinstance(failure_class, str):
        failure_class = getattr(failure_class, "value", None)
    return failure_class in _TRANSPORT_FAILURES


class RunLock:
    """Non-blocking process lock for one run directory.

    The lock file is retained as an audit location.  Kernel locking, not file
    deletion, controls ownership, so a crashed process cannot leave a false
    permanent lock behind.
    """

    _process_guard = threading.Lock()
    _owned_paths: set[Path] = set()

    def __init__(self, run_dir: Path) -> None:
        self.run_dir = Path(run_dir)
        self.path = self.run_dir / "run.lock"
        self._handle: Any = None
        self._owner_token: str | None = None

    @property
    def owned(self) -> bool:
        return self._handle is not None and self._owner_token is not None

    def acquire(self) -> "RunLock":
        self.run_dir.mkdir(parents=True, exist_ok=True)
        canonical_path = self.path.resolve()
        with self._process_guard:
            if canonical_path in self._owned_paths:
                raise IntegrityError(f"run lock is already owned: {self.path}")
            handle = self.path.open("a+", encoding="utf-8")
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                handle.close()
                raise IntegrityError(f"run lock is already owned: {self.path}") from exc
            token = uuid4().hex
            handle.seek(0)
            handle.truncate()
            handle.write(
                json.dumps(
                    {"pid": os.getpid(), "owner_token": token, "acquired_at": _utc_now()},
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            handle.flush()
            os.fsync(handle.fileno())
            self._handle = handle
            self._owner_token = token
            self._owned_paths.add(canonical_path)
        return self

    def release(self) -> None:
        if not self.owned:
            return
        canonical_path = self.path.resolve()
        with self._process_guard:
            handle = self._handle
            self._handle = None
            self._owner_token = None
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            finally:
                handle.close()
                self._owned_paths.discard(canonical_path)

    def __enter__(self) -> "RunLock":
        return self.acquire()

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.release()


_ALLOWED_TRANSITIONS: dict[RunState, frozenset[RunState]] = {
    RunState.PREPARED: frozenset({RunState.RUNNING, RunState.ABORTED}),
    RunState.RUNNING: frozenset({RunState.SUSPENDED, RunState.COMPLETE, RunState.ABORTED}),
    RunState.SUSPENDED: frozenset({RunState.RUNNING, RunState.ABORTED}),
    RunState.COMPLETE: frozenset({RunState.AUDITED_VALID, RunState.AUDITED_INVALID}),
    RunState.AUDITED_VALID: frozenset(),
    RunState.AUDITED_INVALID: frozenset(),
    RunState.ABORTED: frozenset(),
}


class RunStateStore:
    """Atomic, revisioned state-machine storage guarded by :class:`RunLock`."""

    def __init__(self, run_dir: Path) -> None:
        self.run_dir = Path(run_dir)
        self.path = self.run_dir / "run-state.json"

    def initialize(self, *, run_id: str, expected_episodes: int) -> dict[str, Any]:
        if not isinstance(run_id, str) or not run_id:
            raise IntegrityError("run_id must be non-empty")
        expected_episodes = _nonnegative_integer(
            expected_episodes, field="expected_episodes"
        )
        value = {
            "schema_version": 2,
            "run_id": run_id,
            "state": RunState.PREPARED.value,
            "revision": 0,
            "updated_at": _utc_now(),
            "completed_episodes": 0,
            "expected_episodes": expected_episodes,
            "active_execution_session_id": None,
            "last_completed_ordinal": None,
            "suspension_reason": None,
            "terminal_reason": None,
        }
        _write_immutable_json(self.path, value)
        return self.load()

    def load(self) -> dict[str, Any]:
        value = _load_json_mapping(self.path)
        self._validate_state(value)
        return value

    def _validate_state(self, value: Mapping[str, Any]) -> None:
        if set(value) != _RUN_STATE_FIELDS:
            missing = sorted(_RUN_STATE_FIELDS - set(value))
            unknown = sorted(set(value) - _RUN_STATE_FIELDS)
            raise IntegrityError(
                f"run-state.json fields differ from schema (missing={missing!r}, unknown={unknown!r})"
            )
        if value.get("schema_version") != 2:
            raise IntegrityError("run-state.json has an unsupported schema_version")
        if not isinstance(value.get("run_id"), str) or not value["run_id"]:
            raise IntegrityError("run-state.json has an invalid run_id")
        raw_state = value.get("state")
        if not isinstance(raw_state, str):
            raise IntegrityError("run-state.json contains an unknown state")
        try:
            state = RunState(raw_state)
        except (TypeError, ValueError) as exc:
            raise IntegrityError("run-state.json contains an unknown state") from exc
        revision = _nonnegative_integer(value.get("revision"), field="revision")
        del revision
        expected = _nonnegative_integer(
            value.get("expected_episodes"), field="expected_episodes"
        )
        completed = _nonnegative_integer(
            value.get("completed_episodes"), field="completed_episodes"
        )
        if completed > expected:
            raise IntegrityError("completed_episodes exceeds the frozen schedule")
        if not isinstance(value.get("updated_at"), str) or not value["updated_at"]:
            raise IntegrityError("run-state.json has an invalid updated_at")
        last = value.get("last_completed_ordinal")
        if last is not None:
            last = _positive_integer(last, field="last_completed_ordinal")
            if last > completed:
                raise IntegrityError("last_completed_ordinal exceeds completed_episodes")
        session = value.get("active_execution_session_id")
        if state is RunState.RUNNING:
            if not isinstance(session, str) or not session:
                raise IntegrityError("RUNNING requires an active execution session")
        elif session is not None:
            raise IntegrityError("only RUNNING may name an active execution session")
        suspension = value.get("suspension_reason")
        if state is RunState.SUSPENDED:
            if not isinstance(suspension, str) or not suspension.strip():
                raise IntegrityError("SUSPENDED requires a reason")
        elif suspension is not None:
            raise IntegrityError("only SUSPENDED may retain a suspension reason")
        terminal = value.get("terminal_reason")
        if state is RunState.ABORTED:
            if not isinstance(terminal, str) or not terminal.strip():
                raise IntegrityError("ABORTED requires a terminal reason")
        elif terminal is not None:
            raise IntegrityError("only ABORTED may retain a terminal reason")
        if state is RunState.PREPARED and (completed != 0 or last is not None):
            raise IntegrityError("PREPARED cannot contain completed work")
        if state in {RunState.COMPLETE, RunState.AUDITED_VALID, RunState.AUDITED_INVALID}:
            if completed != expected:
                raise IntegrityError(f"{state.value} requires every scheduled episode")
            if expected and last != expected:
                raise IntegrityError(f"{state.value} requires the final scheduled ordinal")

    def _verify_scheduled_episode_set(self, *, expected_episodes: int) -> None:
        schedule_path = self.run_dir / "schedule.json"
        try:
            schedule = json.loads(schedule_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise IntegrityError(f"cannot verify frozen schedule for COMPLETE: {exc}") from exc
        if not isinstance(schedule, list):
            raise IntegrityError("schedule.json must contain a row list")
        scheduled: set[str] = set()
        for index, row in enumerate(schedule, start=1):
            if not isinstance(row, Mapping):
                raise IntegrityError(f"schedule row {index} must be an object")
            identifier = _require_sha256(
                row.get("episode_id"), field=f"schedule row {index} episode_id"
            )
            if identifier in scheduled:
                raise IntegrityError("schedule.json contains duplicate episode IDs")
            scheduled.add(identifier)
        if len(schedule) != expected_episodes:
            raise IntegrityError("run state expected_episodes differs from schedule.json")

        episodes_dir = self.run_dir / "episodes"
        observed: set[str] = set()
        if episodes_dir.exists():
            for path in episodes_dir.iterdir():
                if not path.is_file() or path.suffix != ".json":
                    raise IntegrityError(f"unexpected entry in episodes directory: {path.name}")
                _require_sha256(path.stem, field="episode filename")
                record = _load_json_mapping(path)
                if record.get("episode_id") != path.stem:
                    raise IntegrityError(f"episode file {path.name} embeds another ID")
                observed.add(path.stem)
        if observed != scheduled:
            missing = sorted(scheduled - observed)
            unexpected = sorted(observed - scheduled)
            raise IntegrityError(
                "COMPLETE requires exactly the scheduled episode set "
                f"(missing={missing!r}, unexpected={unexpected!r})"
            )

    def transition(
        self,
        new_state: RunState | str,
        *,
        lock: RunLock,
        completed_episodes: int | None = None,
        active_execution_session_id: str | None = None,
        last_completed_ordinal: int | None = None,
        suspension_reason: str | None = None,
        terminal_reason: str | None = None,
    ) -> dict[str, Any]:
        if not lock.owned or lock.run_dir.resolve() != self.run_dir.resolve():
            raise IntegrityError("the matching run lock must be owned before a state transition")
        try:
            target = new_state if isinstance(new_state, RunState) else RunState(new_state)
        except ValueError as exc:
            raise IntegrityError(f"unknown target run state {new_state!r}") from exc
        current = self.load()
        source = RunState(current["state"])
        if target not in _ALLOWED_TRANSITIONS[source]:
            raise IntegrityError(f"illegal run state transition {source.value} -> {target.value}")

        completed = current["completed_episodes"] if completed_episodes is None else completed_episodes
        expected = current["expected_episodes"]
        if (
            not isinstance(completed, int)
            or isinstance(completed, bool)
            or completed < current["completed_episodes"]
        ):
            raise IntegrityError("completed_episodes must be monotone")
        if completed > expected:
            raise IntegrityError("completed_episodes exceeds the frozen schedule")
        if target is RunState.COMPLETE and completed != expected:
            raise IntegrityError("COMPLETE requires exactly every scheduled episode")
        if target is RunState.SUSPENDED and (
            not isinstance(suspension_reason, str) or not suspension_reason.strip()
        ):
            raise IntegrityError("SUSPENDED requires a reason")
        if target is RunState.ABORTED and (
            not isinstance(terminal_reason, str) or not terminal_reason.strip()
        ):
            raise IntegrityError("ABORTED requires a terminal reason")
        last_value = (
            current["last_completed_ordinal"]
            if last_completed_ordinal is None
            else last_completed_ordinal
        )
        if last_value is not None:
            _positive_integer(last_value, field="last_completed_ordinal")
        if target is RunState.COMPLETE:
            if expected and last_value != expected:
                raise IntegrityError("COMPLETE requires the final scheduled ordinal")
            self._verify_scheduled_episode_set(expected_episodes=expected)

        updated = dict(current)
        updated.update(
            {
                "state": target.value,
                "revision": int(current["revision"]) + 1,
                "updated_at": _utc_now(),
                "completed_episodes": completed,
                "active_execution_session_id": active_execution_session_id,
                "last_completed_ordinal": last_value,
                "suspension_reason": suspension_reason,
                "terminal_reason": terminal_reason,
            }
        )
        self._validate_state(updated)
        atomic_write_json(self.path, updated)
        return updated


class RunCache:
    _reservation_guard = threading.Lock()
    _active_reservations: dict[
        tuple[Path, str], tuple[Any, int, int, str]
    ] = {}

    def __init__(self, run_dir: Path, identity: CacheIdentity) -> None:
        self.run_dir = Path(run_dir)
        self.identity = identity
        self._instance_token = uuid4().hex
        self.attempts_dir = self.run_dir / "attempts"
        self.episodes_dir = self.run_dir / "episodes"
        self.attempts_dir.mkdir(parents=True, exist_ok=True)
        self.episodes_dir.mkdir(parents=True, exist_ok=True)
        # A run directory is one exact model stratum.  This marker also closes
        # the gap for cache-only tests/directories that do not have a manifest.
        _write_immutable_json(self.run_dir / "cache-identity.json", identity.to_dict())

    def request_key(self, request: dict[str, Any]) -> str:
        if not isinstance(request, dict):
            raise IntegrityError("request must be a mapping")
        # The exact request is intentionally not normalized.  Thus model
        # settings, prompt text/bytes representation, turn, retry policy, and
        # prior-feedback hash all participate whenever present in the request.
        material = {
            "namespace": "host-v2-request",
            "cache_identity": self.identity.to_dict(),
            "request": request,
        }
        return sha256_bytes(canonical_json_bytes(material))

    def _attempt_path(self, key: str) -> Path:
        request, index = _split_attempt_key(key)
        return self.attempts_dir / request / f"{index}.json"

    def _episode_path(self, value: str) -> Path:
        _require_sha256(value, field="episode_id")
        return self.episodes_dir / f"{value}.json"

    def _attempt_indices(self, request_key: str) -> list[int]:
        _require_sha256(request_key, field="request_key")
        directory = self.attempts_dir / request_key
        if not directory.exists():
            return []
        indices: list[int] = []
        for path in directory.iterdir():
            if path.name in {".ledger.lock", ".reservation"}:
                if not path.is_file():
                    raise IntegrityError(f"unexpected attempt ledger entry {path.name}")
                continue
            if (
                not path.is_file()
                or path.suffix != ".json"
                or not re.fullmatch(r"[1-9][0-9]*", path.stem)
            ):
                raise IntegrityError(f"unexpected attempt filename {path.name}")
            indices.append(int(path.stem))
        indices.sort()
        if len(indices) != len(set(indices)) or indices != list(range(1, len(indices) + 1)):
            raise IntegrityError("attempt ledger is not contiguous")
        return indices

    def _reservation_coordinate(self, request_key: str) -> tuple[Path, str]:
        return (self.run_dir.resolve(), request_key)

    def _reservation_path(self, request_key: str) -> Path:
        return self.attempts_dir / request_key / ".reservation"

    def _inspect_durable_reservation(self, request_key: str) -> None:
        """Clear a post-commit remnant, but never redraw an unresolved call."""

        path = self._reservation_path(request_key)
        if not path.exists():
            return
        value = _load_json_mapping(path)
        if (
            value.get("schema_version") != 2
            or value.get("request_key") != request_key
            or value.get("cache_identity") != self.identity.to_dict()
        ):
            raise IntegrityError(f"request {request_key} has a malformed durable reservation")
        index = _positive_integer(value.get("attempt_index"), field="reserved attempt_index")
        key = attempt_key(request_key, index)
        if self._attempt_path(key).exists():
            # A crash after immutable publication but before cleanup is safe: the
            # delivered attempt is already in the all-attempt ledger.
            attempt = self.load_attempt(key)
            if attempt is None:  # pragma: no cover - guarded by exists()
                raise IntegrityError(f"request {request_key} lost a published attempt")
            path.unlink()
            _fsync_directory(path.parent)
            return
        raise IntegrityError(
            f"request {request_key} has an unresolved durable attempt reservation"
        )

    def _publish_durable_reservation(self, request_key: str, index: int) -> None:
        _write_immutable_json(
            self._reservation_path(request_key),
            {
                "schema_version": 2,
                "request_key": request_key,
                "attempt_index": index,
                "cache_identity": self.identity.to_dict(),
                "pid": os.getpid(),
                "thread_id": threading.get_ident(),
                "reserved_at": _utc_now(),
            },
        )

    def _clear_durable_reservation(self, request_key: str) -> None:
        path = self._reservation_path(request_key)
        try:
            path.unlink()
        except FileNotFoundError:
            return
        _fsync_directory(path.parent)

    def _acquire_ledger_lock(self, request_key: str) -> Any:
        directory = self.attempts_dir / request_key
        directory.mkdir(parents=True, exist_ok=True)
        handle = (directory / ".ledger.lock").open("a+", encoding="utf-8")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            handle.close()
            raise IntegrityError(f"request {request_key} already has an attempt in flight") from exc
        return handle

    @staticmethod
    def _release_ledger_lock(handle: Any) -> None:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()

    def _reserve_ledger(self, request_key: str, index: int) -> Any:
        coordinate = self._reservation_coordinate(request_key)
        owner = threading.get_ident()
        with self._reservation_guard:
            if coordinate in self._active_reservations:
                raise IntegrityError(f"request {request_key} already has an attempt in flight")
            handle = self._acquire_ledger_lock(request_key)
            self._active_reservations[coordinate] = (
                handle,
                index,
                owner,
                self._instance_token,
            )
        return handle

    def _take_store_lock(self, request_key: str, index: int) -> tuple[Any, bool]:
        coordinate = self._reservation_coordinate(request_key)
        owner = threading.get_ident()
        with self._reservation_guard:
            reserved = self._active_reservations.get(coordinate)
            if reserved is not None:
                handle, reserved_index, reserved_owner, token = reserved
                if token != self._instance_token or reserved_owner != owner:
                    raise IntegrityError(f"request {request_key} has an attempt reserved elsewhere")
                if reserved_index != index:
                    raise IntegrityError(
                        f"reserved attempt index {reserved_index} does not match store index {index}"
                    )
                return handle, True
            return self._acquire_ledger_lock(request_key), False

    def _release_store_lock(
        self, request_key: str, handle: Any, reserved: bool, *, committed: bool
    ) -> None:
        try:
            if reserved:
                coordinate = self._reservation_coordinate(request_key)
                with self._reservation_guard:
                    current = self._active_reservations.get(coordinate)
                    if current is not None and current[0] is handle:
                        self._active_reservations.pop(coordinate, None)
                if committed:
                    self._clear_durable_reservation(request_key)
        finally:
            self._release_ledger_lock(handle)

    def load_attempt(self, attempt_key: str) -> dict[str, Any] | None:
        path = self._attempt_path(attempt_key)
        if not path.exists():
            return None
        value = _load_json_mapping(path)
        self._validate_attempt(attempt_key, value)
        return value

    def _validate_attempt(self, key: str, value: Mapping[str, Any]) -> None:
        request_key_value, index = _split_attempt_key(key)
        if value.get("schema_version") != 2:
            raise IntegrityError(f"attempt file {key} has an unsupported schema_version")
        if value.get("attempt_key") != key:
            raise IntegrityError(f"attempt file {key} embeds a different attempt_key")
        if value.get("request_key") != request_key_value or value.get("attempt_index") != index:
            raise IntegrityError(f"attempt file {key} has inconsistent request coordinates")
        request = value.get("request")
        if not isinstance(request, dict) or self.request_key(request) != request_key_value:
            raise IntegrityError(f"attempt file {key} does not match its frozen request")
        retry_budget = _request_retry_budget(request)
        if index > 1 + retry_budget:
            raise IntegrityError(f"attempt file {key} exceeds its frozen retry budget")
        episode = _require_sha256(
            value.get("episode_id"), field=f"attempt file {key} episode_id"
        )
        if request.get("episode_id", episode) != episode:
            raise IntegrityError(
                f"attempt file {key} is bound to a different schedule episode than its request"
            )
        turn = _positive_integer(value.get("turn_number"), field="turn_number")
        if request.get("turn_number") != turn:
            raise IntegrityError(f"attempt file {key} disagrees with its request turn_number")
        required_identity = {
            "implementation_sha256": self.identity.implementation_sha256,
            "protocol_sha256": self.identity.protocol_sha256,
            "provider_route_id": self.identity.provider_route_id,
        }
        for field, expected in required_identity.items():
            if value.get(field) != expected:
                raise IntegrityError(f"attempt file {key} has mismatched {field}")
        if value.get("requested_model_id") != request.get("requested_model_id"):
            raise IntegrityError(f"attempt file {key} has mismatched requested_model_id")
        if request.get("resolved_model_id", self.identity.resolved_model_id) != (
            self.identity.resolved_model_id
        ):
            raise IntegrityError(f"attempt file {key} requests another resolved model")
        if request.get("provider_route_id", self.identity.provider_route_id) != (
            self.identity.provider_route_id
        ):
            raise IntegrityError(f"attempt file {key} requests another provider route")
        resolved_model = value.get("resolved_model_id")
        if resolved_model is not None and resolved_model != self.identity.resolved_model_id:
            raise IntegrityError(f"attempt file {key} has mismatched resolved_model_id")
        failure_class = value.get("failure_class")
        if not isinstance(failure_class, str):
            failure_class = getattr(failure_class, "value", None)
        if failure_class not in _TRANSPORT_FAILURES | _IMMUTABLE_DELIVERED_FAILURES:
            raise IntegrityError(f"attempt file {key} has unknown failure_class")
        status = value.get("planner_status")
        raw_response = value.get("raw_response")
        error = value.get("error")
        error_metadata = value.get("error_metadata")
        has_raw = isinstance(raw_response, str)
        has_error = (
            isinstance(error, str)
            and bool(error)
            and isinstance(error_metadata, Mapping)
            and bool(error_metadata)
        )
        if not has_raw and not has_error:
            raise IntegrityError(f"attempt file {key} lacks raw response or error evidence")
        if has_raw and resolved_model != self.identity.resolved_model_id:
            raise IntegrityError(f"attempt file {key} delivered bytes without the exact model ID")
        if failure_class == "none":
            if status != "ok" or not has_raw or resolved_model != self.identity.resolved_model_id:
                raise IntegrityError(f"attempt file {key} has inconsistent successful outcome")
        elif failure_class == "explicit_abstention":
            if (
                status != "explicit_abstention"
                or not has_raw
                or resolved_model != self.identity.resolved_model_id
            ):
                raise IntegrityError(f"attempt file {key} has inconsistent abstention outcome")
        elif status != "failed":
            raise IntegrityError(f"attempt file {key} failure must have planner_status='failed'")
        if failure_class in _TRANSPORT_FAILURES and has_raw:
            raise IntegrityError(f"attempt file {key} classifies delivered bytes as transport failure")
        if not isinstance(value.get("actions"), list):
            raise IntegrityError(f"attempt file {key} actions must be a list")
        if status == "failed" and value.get("actions"):
            raise IntegrityError(f"attempt file {key} failed but contains executable actions")

    def store_attempt(self, attempt_key: str, value: dict[str, Any]) -> None:
        request, index = _split_attempt_key(attempt_key)
        handle, reserved = self._take_store_lock(request, index)
        committed = False
        try:
            if not reserved:
                self._inspect_durable_reservation(request)
            self._validate_attempt(attempt_key, value)
            indices = self._attempt_indices(request)
            if index > len(indices) + 1:
                raise IntegrityError("transport retries must form a contiguous attempt ledger")
            if index <= len(indices):
                # Immutable publication below accepts only exact idempotent replay.
                _write_immutable_json(self._attempt_path(attempt_key), value)
                committed = True
                return
            if index > 1:
                previous_key = globals()["attempt_key"](request, index - 1)
                previous = self.load_attempt(previous_key)
                if previous is None:
                    raise IntegrityError("transport retries must form a contiguous attempt ledger")
                if not failure_is_retryable(previous):
                    raise IntegrityError(
                        "parse/schema/policy/refusal/delivered outputs may not be redrawn"
                    )
            _write_immutable_json(self._attempt_path(attempt_key), value)
            committed = True
        finally:
            self._release_store_lock(
                request, handle, reserved, committed=committed
            )

    def next_attempt_index(
        self, request_key: str, *, request_level_transport_retries: int
    ) -> int | None:
        """Return the only permitted next index under a frozen transport budget."""

        _require_sha256(request_key, field="request_key")
        requested_budget = _nonnegative_integer(
            request_level_transport_retries,
            field="request_level_transport_retries",
        )
        handle = self._reserve_ledger(request_key, 0)
        keep_reservation = False
        try:
            self._inspect_durable_reservation(request_key)
            indices = self._attempt_indices(request_key)
            if not indices:
                candidate = 1
            else:
                latest = self.load_attempt(attempt_key(request_key, indices[-1]))
                assert latest is not None
                frozen_budget = _request_retry_budget(latest["request"])
                if requested_budget != frozen_budget:
                    raise IntegrityError(
                        "request_level_transport_retries differs from the frozen request"
                    )
                if not failure_is_retryable(latest) or indices[-1] >= 1 + frozen_budget:
                    return None
                candidate = indices[-1] + 1
            coordinate = self._reservation_coordinate(request_key)
            with self._reservation_guard:
                reserved = self._active_reservations.get(coordinate)
                if reserved is None or reserved[0] is not handle:
                    raise IntegrityError("attempt reservation was lost")
                self._active_reservations[coordinate] = (
                    handle,
                    candidate,
                    reserved[2],
                    reserved[3],
                )
            self._publish_durable_reservation(request_key, candidate)
            keep_reservation = True
            return candidate
        finally:
            if not keep_reservation:
                coordinate = self._reservation_coordinate(request_key)
                with self._reservation_guard:
                    current = self._active_reservations.get(coordinate)
                    if current is not None and current[0] is handle:
                        self._active_reservations.pop(coordinate, None)
                self._release_ledger_lock(handle)

    def _validate_episode_references(self, episode_id: str, value: Mapping[str, Any]) -> None:
        if value.get("schema_version") != 2:
            raise IntegrityError(f"episode file {episode_id} has an unsupported schema_version")
        if value.get("episode_id") != episode_id:
            raise IntegrityError(f"episode file {episode_id} embeds another ID")

        for field in ("attempt_keys", "actions_requested", "action_log", "event_log"):
            if not isinstance(value.get(field), list):
                raise IntegrityError(f"episode file {episode_id} {field} must be a list")
        attempt_keys = value["attempt_keys"]
        if len(attempt_keys) != len(set(attempt_keys)) or any(
            not isinstance(key, str) for key in attempt_keys
        ):
            raise IntegrityError(f"episode file {episode_id} has duplicate/invalid attempt keys")

        attempts: list[dict[str, Any]] = []
        for key in attempt_keys:
            attempt = self.load_attempt(key)
            if attempt is None:
                raise IntegrityError(f"episode file {episode_id} references missing attempt {key}")
            if attempt.get("episode_id") != episode_id:
                raise IntegrityError(f"episode file {episode_id} references another episode's attempt")
            attempts.append(attempt)

        request_groups: dict[str, list[tuple[int, int, dict[str, Any]]]] = {}
        request_order: list[str] = []
        previous_turn = 0
        for attempt in attempts:
            request_key_value = str(attempt["request_key"])
            index = int(attempt["attempt_index"])
            turn = int(attempt["turn_number"])
            if turn < previous_turn:
                raise IntegrityError(f"episode file {episode_id} attempt turns are not ordered")
            previous_turn = turn
            if request_key_value not in request_groups:
                request_order.append(request_key_value)
            request_groups.setdefault(request_key_value, []).append((turn, index, attempt))
        seen_turn_requests: dict[int, str] = {}
        terminal_actions: list[Any] = []
        for request_key_value in request_order:
            group = request_groups[request_key_value]
            turns = {item[0] for item in group}
            if len(turns) != 1:
                raise IntegrityError(f"episode file {episode_id} reuses a request across turns")
            turn = next(iter(turns))
            other = seen_turn_requests.setdefault(turn, request_key_value)
            if other != request_key_value:
                raise IntegrityError(f"episode file {episode_id} has multiple requests for turn {turn}")
            indices = [item[1] for item in group]
            if indices != list(range(1, len(indices) + 1)):
                raise IntegrityError(
                    f"episode file {episode_id} attempt keys are not in numeric ledger order"
                )
            if indices != self._attempt_indices(request_key_value):
                raise IntegrityError(
                    f"episode file {episode_id} does not reference the complete attempt ledger"
                )
            for _, _, attempt in group[:-1]:
                if not failure_is_retryable(attempt):
                    raise IntegrityError(
                        f"episode file {episode_id} has a successor after a delivered outcome"
                    )
            terminal = group[-1][2]
            if failure_is_retryable(terminal):
                budget = _request_retry_budget(terminal["request"])
                if terminal["attempt_index"] != 1 + budget:
                    raise IntegrityError(
                        f"episode file {episode_id} stops before exhausting transport retries"
                    )
            terminal_actions.extend(terminal["actions"])
        if attempts:
            observed_turns = sorted(seen_turn_requests)
            if observed_turns != list(range(1, observed_turns[-1] + 1)):
                raise IntegrityError(f"episode file {episode_id} has a missing planner turn")
            if terminal_actions != value["actions_requested"]:
                raise IntegrityError(
                    f"episode file {episode_id} actions_requested differs from attempt ledger"
                )

        action_requests: list[Any] = []
        action_coordinates: set[tuple[int, int]] = set()
        for action in value["action_log"]:
            if not isinstance(action, Mapping):
                raise IntegrityError(f"episode file {episode_id} action_log contains a non-object")
            turn = _positive_integer(action.get("turn_number"), field="action turn_number")
            index = _positive_integer(action.get("action_index"), field="action_index")
            coordinate = (turn, index)
            if coordinate in action_coordinates:
                raise IntegrityError(f"episode file {episode_id} duplicates an action coordinate")
            action_coordinates.add(coordinate)
            if "request" not in action:
                raise IntegrityError(f"episode file {episode_id} action lacks its request")
            action_requests.append(action["request"])
            if not isinstance(action.get("events"), list):
                raise IntegrityError(f"episode file {episode_id} action events must be a list")
        if action_requests != value["actions_requested"]:
            oracle = value.get("oracle_result")
            interrupted_apply = (
                isinstance(oracle, Mapping)
                and isinstance(oracle.get("runner_error"), str)
                and action_requests == value["actions_requested"][: len(action_requests)]
                and len(value["actions_requested"]) == len(action_requests) + 1
            )
            if not interrupted_apply:
                raise IntegrityError(
                    f"episode file {episode_id} action log reverses/drops requests"
                )

        event_by_id: dict[str, Mapping[str, Any]] = {}
        for event in value["event_log"]:
            if not isinstance(event, Mapping):
                raise IntegrityError(f"episode file {episode_id} event_log contains a non-object")
            event_id_value = event.get("event_id")
            if not isinstance(event_id_value, str) or not event_id_value:
                raise IntegrityError(f"episode file {episode_id} event lacks event_id")
            if event_id_value in event_by_id:
                raise IntegrityError(f"episode file {episode_id} duplicates event_id {event_id_value}")
            parents = event.get("parent_event_ids", [])
            if not isinstance(parents, list) or len(parents) != len(set(parents)) or any(
                not isinstance(parent, str) or not parent for parent in parents
            ):
                raise IntegrityError(f"episode file {episode_id} has invalid parent event refs")
            if any(parent not in event_by_id for parent in parents):
                raise IntegrityError(
                    f"episode file {episode_id} has a forward/missing parent event ref"
                )
            event_by_id[event_id_value] = event
        for action in value["action_log"]:
            for event in action["events"]:
                if not isinstance(event, Mapping) or event.get("event_id") not in event_by_id:
                    raise IntegrityError(f"episode file {episode_id} action references a missing event")
                if canonical_json_bytes(dict(event)) != canonical_json_bytes(
                    dict(event_by_id[str(event["event_id"])])
                ):
                    raise IntegrityError(f"episode file {episode_id} action event bytes differ")

        oracle = value.get("oracle_result")
        if not isinstance(oracle, Mapping):
            raise IntegrityError(f"episode file {episode_id} oracle_result must be an object")
        if "evidence" in oracle:
            evidence = oracle["evidence"]
            if not isinstance(evidence, list):
                raise IntegrityError(f"episode file {episode_id} oracle evidence must be a list")
            for item in evidence:
                if not isinstance(item, Mapping):
                    raise IntegrityError(f"episode file {episode_id} has non-object oracle evidence")
                reference = item.get("event_id")
                if not isinstance(reference, str) or reference not in event_by_id:
                    raise IntegrityError(
                        f"episode file {episode_id} oracle evidence references a missing event"
                    )

    def load_episode(self, episode_id: str) -> dict[str, Any] | None:
        path = self._episode_path(episode_id)
        if not path.exists():
            return None
        value = _load_json_mapping(path)
        self._validate_episode_references(episode_id, value)
        return value

    def store_episode(self, episode_id: str, value: dict[str, Any]) -> None:
        self._validate_episode_references(episode_id, value)
        _write_immutable_json(self._episode_path(episode_id), value)

    def completed_episode_ids(self) -> frozenset[str]:
        result: set[str] = set()
        if not self.episodes_dir.exists():
            return frozenset()
        for path in self.episodes_dir.glob("*.json"):
            _require_sha256(path.stem, field="episode filename")
            self.load_episode(path.stem)
            result.add(path.stem)
        return frozenset(result)

    def store_run_manifest(self, value: dict[str, Any]) -> None:
        """Create the immutable run manifest with no overwrite window."""

        identity_fields = self.identity.to_dict()
        for field, expected in identity_fields.items():
            if field in value and value[field] != expected:
                raise IntegrityError(f"run manifest has mismatched {field}")
        _write_immutable_json(self.run_dir / "run-manifest.json", value)

    def verify(self) -> dict[str, Any]:
        errors: list[str] = []
        attempt_count = 0
        episode_count = 0
        attempts: dict[str, dict[str, Any]] = {}
        try:
            marker = _load_json_mapping(self.run_dir / "cache-identity.json")
            if marker != self.identity.to_dict():
                errors.append("cache identity marker differs from the active model stratum")
        except IntegrityError as exc:
            errors.append(str(exc))
        for directory in sorted(self.attempts_dir.iterdir(), key=lambda path: path.name):
            if not directory.is_dir():
                errors.append(f"unexpected entry in attempts directory: {directory.name}")
                continue
            try:
                indices = self._attempt_indices(directory.name)
            except IntegrityError as exc:
                errors.append(str(exc))
                continue
            reservation = directory / ".reservation"
            if reservation.exists():
                errors.append(
                    f"request {directory.name} retains a durable attempt reservation"
                )
            terminal_seen = False
            for index in indices:
                attempt_count += 1
                key = attempt_key(directory.name, index)
                try:
                    value = self.load_attempt(key)
                    assert value is not None
                    attempts[key] = value
                    if terminal_seen:
                        errors.append(f"attempt {key} redraws an immutable delivered outcome")
                    if not failure_is_retryable(value):
                        terminal_seen = True
                except (IntegrityError, AssertionError) as exc:
                    errors.append(str(exc))

        references: dict[str, int] = {}
        for path in sorted(self.episodes_dir.iterdir(), key=lambda path: path.name):
            if not path.is_file() or path.suffix != ".json":
                errors.append(f"unexpected entry in episodes directory: {path.name}")
                continue
            episode_count += 1
            try:
                value = self.load_episode(path.stem)
                assert value is not None
                for key in value["attempt_keys"]:
                    references[key] = references.get(key, 0) + 1
            except IntegrityError as exc:
                errors.append(str(exc))
            except AssertionError as exc:  # pragma: no cover - defensive filesystem race
                errors.append(str(exc))
        for key in sorted(attempts, key=lambda item: _split_attempt_key(item)):
            count = references.get(key, 0)
            if count != 1:
                errors.append(f"attempt {key} is referenced by {count} episode records")
        for key in sorted(set(references) - set(attempts)):
            errors.append(f"episode ledger references unknown attempt {key}")
        return {
            "valid": not errors,
            "errors": errors,
            "attempt_count": attempt_count,
            "episode_count": episode_count,
            "cache_identity": self.identity.to_dict(),
        }
