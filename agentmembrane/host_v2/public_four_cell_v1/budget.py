"""Immutable, data-driven call budgeting for the public four-cell overlay.

The budget unit is a *client attempt*.  This deliberately charges transport
and pre-model failures as well as delivered responses.  Provider acceptance,
delivery, and token use remain separate counters so that none of those events
can be inferred from the headline budget number.

This module only materializes/validates execution-authorized-false manifests.
It performs no provider or native-runtime work.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Iterable, Mapping
from uuid import uuid4

from .contracts import ContractError


RUN_CHAIN_SCHEMA_VERSION = 1
RUN_CHAIN_ARTIFACT_TYPE = "agentmembrane_run_chain_budget_manifest"
BUDGET_UNIT = "client_attempt"
FRESH_NAMESPACE_KEYS = ("output", "cache", "native")

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ATTEMPT_KEY_RE = re.compile(r"^(?P<request>[0-9a-f]{64}):(?P<index>[1-9][0-9]*)$")


class RunChainBudgetError(ContractError):
    """The immutable run-chain budget contract was violated."""


def _check_json_value(value: Any, *, field: str = "$") -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise RunChainBudgetError(f"{field} contains a non-finite number")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _check_json_value(item, field=f"{field}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise RunChainBudgetError(f"{field} has a non-string key")
            _check_json_value(item, field=f"{field}.{key}")
        return
    raise RunChainBudgetError(f"{field} has unsupported type {type(value).__name__}")


def _canonical_json_bytes(value: Any) -> bytes:
    _check_json_value(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require_nonnegative_int(value: Any, *, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RunChainBudgetError(f"{field} must be a non-negative integer")
    return value


def _require_sha256(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise RunChainBudgetError(f"{field} must be a lowercase SHA-256")
    return value


def _repo_relative_path(repo_root: Path, value: Any, *, field: str) -> tuple[str, Path]:
    if not isinstance(value, (str, Path)) or not str(value):
        raise RunChainBudgetError(
            f"{field} must be a non-empty repository-relative path"
        )
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise RunChainBudgetError(f"{field} must remain repository-relative")
    root = Path(repo_root).resolve()
    resolved = (root / relative).resolve()
    try:
        normalized = resolved.relative_to(root).as_posix()
    except ValueError as exc:
        raise RunChainBudgetError(f"{field} escapes the repository") from exc
    return normalized, resolved


def _load_json_object(path: Path, *, field: str) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RunChainBudgetError(f"cannot read {field} as JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise RunChainBudgetError(f"{field} must contain a JSON object")
    return value


def _write_immutable_json(path: Path, value: Mapping[str, Any]) -> None:
    """Publish bytes once; an unequal replay is an integrity failure."""

    target = Path(path)
    data = _canonical_json_bytes(dict(value))
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.parent / f".{target.name}.{uuid4().hex}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, target)
        except FileExistsError:
            try:
                existing = target.read_bytes()
            except OSError as exc:
                raise RunChainBudgetError(
                    f"cannot inspect immutable artifact {target}"
                ) from exc
            if existing != data:
                raise RunChainBudgetError(f"immutable artifact collision at {target}")
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


@dataclass(frozen=True)
class AttemptCounters:
    """Orthogonal cumulative facts about request attempts."""

    client_attempts: int = 0
    provider_accepted_requests: int = 0
    delivered_model_responses: int = 0
    token_bearing_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0

    def __post_init__(self) -> None:
        for field in self.__dataclass_fields__:
            _require_nonnegative_int(getattr(self, field), field=f"counters.{field}")
        if self.provider_accepted_requests > self.client_attempts:
            raise RunChainBudgetError("provider acceptance exceeds client attempts")
        if self.delivered_model_responses > self.provider_accepted_requests:
            raise RunChainBudgetError("delivered responses exceed provider acceptances")
        if self.token_bearing_calls > self.delivered_model_responses:
            raise RunChainBudgetError("token-bearing calls exceed delivered responses")
        if self.total_tokens != self.input_tokens + self.output_tokens:
            raise RunChainBudgetError("total_tokens must equal input_tokens + output_tokens")
        if self.token_bearing_calls == 0 and self.total_tokens != 0:
            raise RunChainBudgetError(
                "nonzero tokens require at least one token-bearing call"
            )

    def __add__(self, other: "AttemptCounters") -> "AttemptCounters":
        if not isinstance(other, AttemptCounters):
            return NotImplemented
        return AttemptCounters(
            **{
                field: getattr(self, field) + getattr(other, field)
                for field in self.__dataclass_fields__
            }
        )

    def to_dict(self) -> dict[str, int]:
        return {field: getattr(self, field) for field in self.__dataclass_fields__}

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "AttemptCounters":
        if not isinstance(value, Mapping) or set(value) != set(cls.__dataclass_fields__):
            raise RunChainBudgetError("counters have missing or unexpected fields")
        return cls(**{field: value[field] for field in cls.__dataclass_fields__})


def counters_for_attempt(attempt: Mapping[str, Any]) -> AttemptCounters:
    """Derive counters from one immutable Host V2 attempt record.

    A provider acceptance is evidenced by delivered provider bytes.  Merely
    reaching a proxy that returns an HTTP error is not counted as an accepted
    inference request.  This makes the classification conservative and fully
    derivable from the attempt artifact.
    """

    if not isinstance(attempt, Mapping):
        raise RunChainBudgetError("attempt must be an object")
    match = _ATTEMPT_KEY_RE.fullmatch(str(attempt.get("attempt_key")))
    if match is None:
        raise RunChainBudgetError("attempt has no canonical attempt_key")
    if attempt.get("request_key") != match.group("request"):
        raise RunChainBudgetError("attempt request_key disagrees with attempt_key")
    if attempt.get("attempt_index") != int(match.group("index")):
        raise RunChainBudgetError("attempt_index disagrees with attempt_key")
    if not isinstance(attempt.get("planner_status"), str):
        raise RunChainBudgetError("attempt lacks planner_status")
    if not isinstance(attempt.get("failure_class"), str):
        raise RunChainBudgetError("attempt lacks failure_class")

    usage = attempt.get("usage")
    if not isinstance(usage, Mapping):
        raise RunChainBudgetError("attempt lacks usage")
    input_tokens = _require_nonnegative_int(
        usage.get("input_tokens"), field="attempt.usage.input_tokens"
    )
    output_tokens = _require_nonnegative_int(
        usage.get("output_tokens"), field="attempt.usage.output_tokens"
    )
    total_tokens = _require_nonnegative_int(
        usage.get("total_tokens"), field="attempt.usage.total_tokens"
    )
    if total_tokens != input_tokens + output_tokens:
        raise RunChainBudgetError("attempt token total is inconsistent")
    delivered = isinstance(attempt.get("raw_response"), str)
    token_bearing = total_tokens > 0
    if token_bearing and not delivered:
        raise RunChainBudgetError(
            "attempt claims tokens without delivered provider bytes"
        )
    if delivered and not isinstance(attempt.get("resolved_model_id"), str):
        raise RunChainBudgetError("delivered attempt lacks resolved_model_id")
    return AttemptCounters(
        client_attempts=1,
        provider_accepted_requests=int(delivered),
        delivered_model_responses=int(delivered),
        token_bearing_calls=int(token_bearing),
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=total_tokens,
    )


@dataclass(frozen=True)
class PredecessorAttempt:
    path: str
    sha256: str
    attempt_key: str
    planner_status: str
    failure_class: str
    counters: AttemptCounters

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "attempt_key": self.attempt_key,
            "planner_status": self.planner_status,
            "failure_class": self.failure_class,
            "counters": self.counters.to_dict(),
        }


@dataclass(frozen=True)
class RunChainBudget:
    """A validated immutable manifest view."""

    chain_id: str
    cap: int
    predecessors: tuple[PredecessorAttempt, ...]
    counters: AttemptCounters
    consumed: int
    remaining: int
    fresh_namespaces: Mapping[str, str]
    manifest_payload_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.chain_id, str) or not self.chain_id.strip():
            raise RunChainBudgetError("chain_id must be non-empty")
        if not isinstance(self.cap, int) or isinstance(self.cap, bool) or self.cap <= 0:
            raise RunChainBudgetError("cap must be a positive integer")
        if self.consumed != self.counters.client_attempts:
            raise RunChainBudgetError("consumed must equal cumulative client attempts")
        if self.remaining != self.cap - self.consumed or self.remaining < 0:
            raise RunChainBudgetError("remaining must equal cap - consumed")
        if set(self.fresh_namespaces) != set(FRESH_NAMESPACE_KEYS):
            raise RunChainBudgetError(
                "fresh_namespaces must contain output/cache/native exactly"
            )
        values = tuple(self.fresh_namespaces[key] for key in FRESH_NAMESPACE_KEYS)
        if len(set(values)) != len(values) or any(not value for value in values):
            raise RunChainBudgetError(
                "fresh namespace paths must be non-empty and distinct"
            )
        _require_sha256(self.manifest_payload_sha256, field="manifest_payload_sha256")

    def assert_can_consume(self, additional_client_attempts: int = 1) -> None:
        additional = _require_nonnegative_int(
            additional_client_attempts, field="additional_client_attempts"
        )
        if additional == 0:
            return
        if additional > self.remaining:
            raise RunChainBudgetError(
                f"run-chain budget exhausted: requested {additional}, remaining {self.remaining}"
            )

    def to_manifest(self) -> dict[str, Any]:
        payload = {
            "schema_version": RUN_CHAIN_SCHEMA_VERSION,
            "artifact_type": RUN_CHAIN_ARTIFACT_TYPE,
            "execution_authorized": False,
            "budget_unit": BUDGET_UNIT,
            "chain_id": self.chain_id,
            "cap": self.cap,
            "consumed": self.consumed,
            "remaining": self.remaining,
            "counters": self.counters.to_dict(),
            "predecessor_attempts": [row.to_dict() for row in self.predecessors],
            "fresh_namespaces": {
                key: self.fresh_namespaces[key] for key in FRESH_NAMESPACE_KEYS
            },
        }
        return {
            **payload,
            "manifest_payload_sha256": _sha256_bytes(_canonical_json_bytes(payload)),
        }


def _load_predecessor(repo_root: Path, value: Any, *, index: int) -> PredecessorAttempt:
    normalized, path = _repo_relative_path(
        repo_root, value, field=f"predecessor_attempt_paths[{index}]"
    )
    if not path.is_file():
        raise RunChainBudgetError(f"predecessor attempt does not exist: {normalized}")
    data = path.read_bytes()
    attempt = _load_json_object(path, field=f"predecessor attempt {normalized}")
    counters = counters_for_attempt(attempt)
    return PredecessorAttempt(
        path=normalized,
        sha256=_sha256_bytes(data),
        attempt_key=str(attempt["attempt_key"]),
        planner_status=str(attempt["planner_status"]),
        failure_class=str(attempt["failure_class"]),
        counters=counters,
    )


def build_run_chain_budget(
    *,
    repo_root: Path,
    chain_id: str,
    cap: int,
    predecessor_attempt_paths: Iterable[str | Path],
    fresh_namespaces: Mapping[str, str | Path],
    require_fresh: bool = True,
) -> RunChainBudget:
    """Build a deterministic manifest view from the predecessor evidence."""

    root = Path(repo_root).resolve()
    if not root.is_dir():
        raise RunChainBudgetError("repo_root must be an existing directory")
    if not isinstance(chain_id, str) or not chain_id.strip():
        raise RunChainBudgetError("chain_id must be non-empty")
    if not isinstance(cap, int) or isinstance(cap, bool) or cap <= 0:
        raise RunChainBudgetError("cap must be a positive integer")

    predecessors = tuple(
        _load_predecessor(root, value, index=index)
        for index, value in enumerate(predecessor_attempt_paths)
    )
    paths = [row.path for row in predecessors]
    keys = [row.attempt_key for row in predecessors]
    if len(paths) != len(set(paths)) or len(keys) != len(set(keys)):
        raise RunChainBudgetError(
            "predecessor attempts must be unique by path and attempt_key"
        )
    counters = AttemptCounters()
    for row in predecessors:
        counters = counters + row.counters
    if counters.client_attempts > cap:
        raise RunChainBudgetError(
            "predecessor attempts already exceed the run-chain cap"
        )

    if not isinstance(fresh_namespaces, Mapping) or set(fresh_namespaces) != set(
        FRESH_NAMESPACE_KEYS
    ):
        raise RunChainBudgetError(
            "fresh_namespaces must contain output/cache/native exactly"
        )
    normalized_namespaces: dict[str, str] = {}
    namespace_paths: list[Path] = []
    for key in FRESH_NAMESPACE_KEYS:
        normalized, path = _repo_relative_path(
            root, fresh_namespaces[key], field=f"fresh_namespaces.{key}"
        )
        normalized_namespaces[key] = normalized
        namespace_paths.append(path)
        if require_fresh and path.exists():
            raise RunChainBudgetError(f"fresh_namespaces.{key} already exists")
    if len(set(normalized_namespaces.values())) != len(FRESH_NAMESPACE_KEYS):
        raise RunChainBudgetError("fresh namespace paths must be distinct")
    for left_index, left in enumerate(namespace_paths):
        for right in namespace_paths[left_index + 1 :]:
            if left in right.parents or right in left.parents:
                raise RunChainBudgetError(
                    "fresh namespace paths must not contain one another"
                )

    provisional = RunChainBudget(
        chain_id=chain_id,
        cap=cap,
        predecessors=predecessors,
        counters=counters,
        consumed=counters.client_attempts,
        remaining=cap - counters.client_attempts,
        fresh_namespaces=normalized_namespaces,
        manifest_payload_sha256="0" * 64,
    )
    manifest = provisional.to_manifest()
    return RunChainBudget(
        chain_id=chain_id,
        cap=cap,
        predecessors=predecessors,
        counters=counters,
        consumed=counters.client_attempts,
        remaining=cap - counters.client_attempts,
        fresh_namespaces=normalized_namespaces,
        manifest_payload_sha256=manifest["manifest_payload_sha256"],
    )


def materialize_run_chain_budget(
    path: Path,
    *,
    repo_root: Path,
    chain_id: str,
    cap: int,
    predecessor_attempt_paths: Iterable[str | Path],
    fresh_namespaces: Mapping[str, str | Path],
) -> RunChainBudget:
    """Create one immutable execution-authorized-false budget manifest."""

    budget = build_run_chain_budget(
        repo_root=repo_root,
        chain_id=chain_id,
        cap=cap,
        predecessor_attempt_paths=predecessor_attempt_paths,
        fresh_namespaces=fresh_namespaces,
        require_fresh=True,
    )
    _write_immutable_json(Path(path), budget.to_manifest())
    return budget


def validate_run_chain_budget(
    *, repo_root: Path, manifest_path: Path, require_fresh: bool = True
) -> RunChainBudget:
    """Recompute a manifest from its hash-bound attempts and namespaces."""

    manifest = _load_json_object(Path(manifest_path), field="run-chain manifest")
    required_fields = {
        "schema_version",
        "artifact_type",
        "execution_authorized",
        "budget_unit",
        "chain_id",
        "cap",
        "consumed",
        "remaining",
        "counters",
        "predecessor_attempts",
        "fresh_namespaces",
        "manifest_payload_sha256",
    }
    if set(manifest) != required_fields:
        raise RunChainBudgetError(
            "run-chain manifest has missing or unexpected fields"
        )
    if (
        manifest["schema_version"] != RUN_CHAIN_SCHEMA_VERSION
        or manifest["artifact_type"] != RUN_CHAIN_ARTIFACT_TYPE
        or manifest["execution_authorized"] is not False
        or manifest["budget_unit"] != BUDGET_UNIT
    ):
        raise RunChainBudgetError(
            "run-chain manifest identity/authorization is invalid"
        )
    predecessor_rows = manifest.get("predecessor_attempts")
    if not isinstance(predecessor_rows, list) or any(
        not isinstance(row, Mapping) or not isinstance(row.get("path"), str)
        for row in predecessor_rows
    ):
        raise RunChainBudgetError(
            "predecessor_attempts must be an array of path-bound objects"
        )
    rebuilt = build_run_chain_budget(
        repo_root=repo_root,
        chain_id=manifest["chain_id"],
        cap=manifest["cap"],
        predecessor_attempt_paths=[row["path"] for row in predecessor_rows],
        fresh_namespaces=manifest["fresh_namespaces"],
        require_fresh=require_fresh,
    )
    if _canonical_json_bytes(manifest) != _canonical_json_bytes(rebuilt.to_manifest()):
        raise RunChainBudgetError(
            "run-chain manifest differs from deterministic reconstruction"
        )
    return rebuilt


def claim_fresh_namespaces(*, repo_root: Path, budget: RunChainBudget) -> dict[str, Any]:
    """Atomically elect one namespace owner, then claim all three roots.

    The output-root ``mkdir`` is the linearization point: concurrent claimers
    of one manifest cannot both succeed.  If a later namespace is unexpectedly
    occupied, the already-created output claim is deliberately retained as a
    fail-closed tombstone instead of being deleted and made reusable.
    """

    if not isinstance(budget, RunChainBudget):
        raise RunChainBudgetError("budget must be a RunChainBudget")
    root = Path(repo_root).resolve()
    paths: dict[str, Path] = {}
    for key in FRESH_NAMESPACE_KEYS:
        normalized, path = _repo_relative_path(
            root, budget.fresh_namespaces[key], field=f"fresh_namespaces.{key}"
        )
        if normalized != budget.fresh_namespaces[key]:
            raise RunChainBudgetError("budget contains a noncanonical namespace path")
        paths[key] = path
    claim = {
        "schema_version": RUN_CHAIN_SCHEMA_VERSION,
        "artifact_type": "agentmembrane_run_chain_namespace_claim",
        "execution_authorized": False,
        "chain_id": budget.chain_id,
        "run_chain_manifest_payload_sha256": budget.manifest_payload_sha256,
        "fresh_namespaces": {
            key: budget.fresh_namespaces[key] for key in FRESH_NAMESPACE_KEYS
        },
    }
    try:
        paths["output"].mkdir(parents=True, exist_ok=False)
    except FileExistsError as exc:
        raise RunChainBudgetError("output namespace atomic claim lost or was reused") from exc
    _write_immutable_json(paths["output"] / ".namespace-claim.json", claim)
    for key in ("cache", "native"):
        try:
            paths[key].mkdir(parents=True, exist_ok=False)
        except FileExistsError as exc:
            raise RunChainBudgetError(
                f"{key} namespace collision after atomic output claim"
            ) from exc
        _write_immutable_json(paths[key] / ".namespace-claim.json", claim)
    return {
        **claim,
        "claim_sha256": _sha256_bytes(_canonical_json_bytes(claim)),
    }


__all__ = [
    "AttemptCounters",
    "BUDGET_UNIT",
    "PredecessorAttempt",
    "RUN_CHAIN_ARTIFACT_TYPE",
    "RUN_CHAIN_SCHEMA_VERSION",
    "RunChainBudget",
    "RunChainBudgetError",
    "build_run_chain_budget",
    "claim_fresh_namespaces",
    "counters_for_attempt",
    "materialize_run_chain_budget",
    "validate_run_chain_budget",
]
