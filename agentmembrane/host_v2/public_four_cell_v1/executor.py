"""Fail-closed execution primitives for the public four-cell overlay.

This is a versioned seam, not an authorization entry point.  In particular,
the module does not call a provider or a native task.  A future authorized
runner can compose these primitives around ``ModelPlanner`` and the public
bridge while retaining the invariants tested here.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any, Callable, Iterable, Mapping, Protocol, Sequence

from .budget import (
    AttemptCounters,
    RunChainBudget,
    RunChainBudgetError,
    _canonical_json_bytes,
    _sha256_bytes,
    _write_immutable_json,
    counters_for_attempt,
)
from .contracts import ContractError, FOUR_CELLS, SOURCE_TASK_ID


EXECUTOR_ID = "host-v2-public-four-cell-executor-v1"
EXECUTION_AUTHORIZED = False
FAILURE_RECORD_SCHEMA_VERSION = 1
FAILURE_RECORD_ARTIFACT_TYPE = "agentmembrane_public_four_cell_planner_failure"
TEXT_CAPABILITY_CONTRACT = "confirmed_assistant_text_equivalence-v1"
CONFIRMED_ASSISTANT_TEXT_MODE = "confirmed_assistant_text"
RAW_RESPONSE_ENVELOPE_MODE = "modelplanner_raw_response_envelope"
TERMINAL_TEXT_MODES = frozenset(
    {CONFIRMED_ASSISTANT_TEXT_MODE, RAW_RESPONSE_ENVELOPE_MODE}
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ATTEMPT_KEY_RE = re.compile(r"^(?P<request>[0-9a-f]{64}):(?P<index>[1-9][0-9]*)$")
_CELL_IDS = frozenset(cell.cell_id for cell in FOUR_CELLS)


class ExecutorContractError(ContractError):
    """The versioned public four-cell executor contract was violated."""


class AttemptCache(Protocol):
    run_dir: Path

    def load_attempt(self, attempt_key: str) -> dict[str, Any] | None: ...


class PlannerTurnView(Protocol):
    """Hash-bound adapter seam; deliberately independent of the active planner."""

    request_key: str
    actions: Sequence[Any]
    final_artifact: Mapping[str, Any] | None
    strategy: str | None
    status: str
    explicit_abstention: bool
    failure_class: Any
    terminal_error: str | None
    attempt_keys: Sequence[str]


def _failure_class_value(value: Any) -> str:
    normalized = getattr(value, "value", value)
    if not isinstance(normalized, str) or not normalized:
        raise ExecutorContractError("planner failure_class must be a non-empty string")
    return normalized


def _validate_turn_view(turn: Any) -> PlannerTurnView:
    required = (
        "request_key",
        "actions",
        "final_artifact",
        "strategy",
        "status",
        "explicit_abstention",
        "failure_class",
        "terminal_error",
        "attempt_keys",
    )
    if any(not hasattr(turn, field) for field in required):
        raise ExecutorContractError("turn does not satisfy PlannerTurnView")
    if turn.status not in {"ok", "complete", "explicit_abstention", "failed"}:
        raise ExecutorContractError("planner turn has an unknown status")
    _failure_class_value(turn.failure_class)
    if not isinstance(turn.request_key, str) or not turn.request_key:
        raise ExecutorContractError("planner turn request_key must be non-empty")
    if not isinstance(turn.attempt_keys, Sequence) or isinstance(
        turn.attempt_keys, (str, bytes)
    ):
        raise ExecutorContractError("planner turn attempt_keys must be a sequence")
    return turn


def _repo_relative_file(repo_root: Path, path: Path, *, field: str) -> tuple[str, Path]:
    root = Path(repo_root).resolve()
    resolved = Path(path).resolve()
    try:
        relative = resolved.relative_to(root).as_posix()
    except ValueError as exc:
        raise ExecutorContractError(f"{field} escapes the repository") from exc
    if not resolved.is_file():
        raise ExecutorContractError(f"{field} is not an existing file")
    return relative, resolved


def _attempt_path(cache: AttemptCache, key: str) -> Path:
    match = _ATTEMPT_KEY_RE.fullmatch(key)
    if match is None:
        raise ExecutorContractError("planner attempt key is not canonical")
    return (
        Path(cache.run_dir)
        / "attempts"
        / match.group("request")
        / f"{match.group('index')}.json"
    )


@dataclass(frozen=True)
class CheckerTextCapability:
    """Source/checker-specific proof of terminal-text compatibility."""

    source_task_id: str
    checker_binding_id: str
    reads_terminal_text: bool
    raw_response_envelope_compatible: bool
    compatibility_contract: str | None = None
    evidence_path: str | None = None
    evidence_sha256: str | None = None

    def __post_init__(self) -> None:
        if self.source_task_id != SOURCE_TASK_ID:
            raise ExecutorContractError(
                "checker capability is not bound to the frozen source task"
            )
        if not isinstance(self.checker_binding_id, str) or not self.checker_binding_id:
            raise ExecutorContractError("checker_binding_id must be non-empty")
        if not isinstance(self.reads_terminal_text, bool):
            raise ExecutorContractError("reads_terminal_text must be Boolean")
        if not isinstance(self.raw_response_envelope_compatible, bool):
            raise ExecutorContractError(
                "raw_response_envelope_compatible must be Boolean"
            )
        if self.raw_response_envelope_compatible and not self.reads_terminal_text:
            raise ExecutorContractError(
                "a state-only checker must not claim raw-response compatibility"
            )
        if self.reads_terminal_text and self.raw_response_envelope_compatible:
            if self.compatibility_contract != TEXT_CAPABILITY_CONTRACT:
                raise ExecutorContractError(
                    "text checker has the wrong compatibility contract"
                )
            if not isinstance(self.evidence_path, str) or not self.evidence_path:
                raise ExecutorContractError(
                    "compatible text checker lacks an evidence path"
                )
            if (
                not isinstance(self.evidence_sha256, str)
                or _SHA256_RE.fullmatch(self.evidence_sha256) is None
            ):
                raise ExecutorContractError(
                    "compatible text checker lacks an evidence SHA-256"
                )
        elif any(
            value is not None
            for value in (
                self.compatibility_contract,
                self.evidence_path,
                self.evidence_sha256,
            )
        ):
            raise ExecutorContractError(
                "unproven/state-only checker must not carry compatibility evidence"
            )


def validate_checker_text_capabilities(
    *,
    repo_root: Path,
    source_task_id: str,
    checker_binding_ids: Sequence[str],
    capabilities: Iterable[CheckerTextCapability],
    terminal_text_mode: str,
) -> tuple[CheckerTextCapability, ...]:
    """Require one exact capability row per native checker and fail closed."""

    expected = tuple(checker_binding_ids)
    if not expected or any(not isinstance(value, str) or not value for value in expected):
        raise ExecutorContractError(
            "checker_binding_ids must be a non-empty string sequence"
        )
    if len(expected) != len(set(expected)):
        raise ExecutorContractError("checker_binding_ids must be unique")
    rows = tuple(capabilities)
    if any(not isinstance(row, CheckerTextCapability) for row in rows):
        raise ExecutorContractError(
            "capabilities must contain CheckerTextCapability rows"
        )
    by_id = {row.checker_binding_id: row for row in rows}
    if len(by_id) != len(rows) or set(by_id) != set(expected):
        raise ExecutorContractError(
            "checker capability coverage differs from native checker bindings"
        )
    root = Path(repo_root).resolve()
    if terminal_text_mode not in TERMINAL_TEXT_MODES:
        raise ExecutorContractError("terminal text mode is missing or undeclared")
    for checker_id in expected:
        row = by_id[checker_id]
        if row.source_task_id != source_task_id:
            raise ExecutorContractError(
                "checker capability is bound to another source task"
            )
        if row.reads_terminal_text and not row.raw_response_envelope_compatible:
            raise ExecutorContractError(
                f"text-sensitive checker {checker_id!r} lacks raw-response compatibility proof"
            )
        if row.reads_terminal_text:
            if terminal_text_mode != CONFIRMED_ASSISTANT_TEXT_MODE:
                raise ExecutorContractError(
                    "text-sensitive checker requires confirmed_assistant_text mode"
                )
            evidence = Path(str(row.evidence_path))
            if evidence.is_absolute() or ".." in evidence.parts:
                raise ExecutorContractError(
                    "checker capability evidence path must be repository-relative"
                )
            path = (root / evidence).resolve()
            try:
                path.relative_to(root)
            except ValueError as exc:
                raise ExecutorContractError(
                    "checker capability evidence escapes repository"
                ) from exc
            if not path.is_file():
                raise ExecutorContractError(
                    "checker capability evidence does not exist"
                )
            if _sha256_bytes(path.read_bytes()) != row.evidence_sha256:
                raise ExecutorContractError("checker capability evidence SHA mismatch")
    return tuple(by_id[checker_id] for checker_id in expected)


@dataclass(frozen=True)
class TurnResolution:
    status: str
    terminal_text: str
    checker_capabilities: tuple[CheckerTextCapability, ...]

    def __post_init__(self) -> None:
        if self.status not in {"ok", "complete", "explicit_abstention"}:
            raise ExecutorContractError(
                "TurnResolution requires a delivered planner status"
            )
        if not isinstance(self.terminal_text, str) or not self.terminal_text.strip():
            raise ExecutorContractError(
                "delivered turn lacks ledger-confirmed terminal text"
            )


class ImmutablePlannerFailure(ExecutorContractError):
    """Raised only after a failed PlannerTurn has an immutable diagnostic."""

    def __init__(self, message: str, *, record_path: Path, record_sha256: str) -> None:
        super().__init__(message)
        self.record_path = Path(record_path)
        self.record_sha256 = record_sha256


def build_failed_turn_record(
    *,
    repo_root: Path,
    cache: AttemptCache,
    turn: PlannerTurnView,
    source_task_id: str,
    cell_id: str,
    run_chain_manifest_sha256: str,
) -> dict[str, Any]:
    """Bind a failed turn to the terminal immutable attempt without text use."""

    if turn.status != "failed":
        raise ExecutorContractError(
            "failure records may only be built for failed PlannerTurn values"
        )
    if source_task_id != SOURCE_TASK_ID:
        raise ExecutorContractError(
            "failure record is not bound to the frozen source task"
        )
    if cell_id not in _CELL_IDS:
        raise ExecutorContractError(
            "failure record is not bound to one frozen four-cell row"
        )
    if (
        not isinstance(run_chain_manifest_sha256, str)
        or _SHA256_RE.fullmatch(run_chain_manifest_sha256) is None
    ):
        raise ExecutorContractError(
            "failure record lacks a run-chain manifest SHA-256"
        )
    failure_class = _failure_class_value(turn.failure_class)
    key = str(turn.attempt_keys[-1]) if turn.attempt_keys else None
    attempt: Mapping[str, Any] | None = None
    attempt_path: str | None = None
    attempt_sha256: str | None = None
    ledger_status = "malformed"
    ledger_error: str | None = None
    counters = AttemptCounters()
    delivered_failure_bytes_present = False
    try:
        if key is None:
            raise ExecutorContractError("failed turn has no attempt key")
        candidate = _attempt_path(cache, key)
        root = Path(repo_root).resolve()
        resolved = candidate.resolve()
        try:
            attempt_path = resolved.relative_to(root).as_posix()
        except ValueError as exc:
            raise ExecutorContractError("terminal attempt escapes repository") from exc
        loaded = cache.load_attempt(key)
        if loaded is None:
            ledger_status = "missing"
            raise ExecutorContractError("terminal attempt is absent")
        attempt = loaded
        if not resolved.is_file():
            ledger_status = "missing"
            raise ExecutorContractError("terminal attempt file is absent")
        if attempt.get("attempt_key") != key or attempt.get("planner_status") != "failed":
            raise ExecutorContractError("terminal attempt status/coordinate mismatch")
        if attempt.get("failure_class") != failure_class:
            raise ExecutorContractError("terminal attempt failure_class mismatch")
        if attempt.get("error") != turn.terminal_error:
            raise ExecutorContractError("terminal attempt error mismatch")
        counters = counters_for_attempt(attempt)
        attempt_sha256 = _sha256_bytes(resolved.read_bytes())
        delivered_failure_bytes_present = isinstance(
            attempt.get("raw_response"), str
        )
        ledger_status = "verified"
    except Exception as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit, GeneratorExit)):
            raise
        ledger_error = f"{type(exc).__name__}: {exc}"
    record = {
        "schema_version": FAILURE_RECORD_SCHEMA_VERSION,
        "artifact_type": FAILURE_RECORD_ARTIFACT_TYPE,
        "executor_id": EXECUTOR_ID,
        "execution_authorized": False,
        "source_task_id": source_task_id,
        "cell_id": cell_id,
        "run_chain_manifest_sha256": run_chain_manifest_sha256,
        "request_key": turn.request_key,
        "attempt_keys": list(turn.attempt_keys),
        "terminal_attempt": {
            "path": attempt_path,
            "sha256": attempt_sha256,
            "attempt_key": key,
        },
        "ledger_status": ledger_status,
        "ledger_validation_error": ledger_error,
        "planner_status": "failed",
        "failure_class": failure_class,
        "terminal_error": turn.terminal_error,
        "error_metadata": (
            copy.deepcopy(attempt.get("error_metadata"))
            if isinstance(attempt, Mapping)
            else None
        ),
        "usage": (
            copy.deepcopy(attempt.get("usage"))
            if isinstance(attempt, Mapping)
            else None
        ),
        "attempt_counters": counters.to_dict(),
        "delivered_failure_bytes_present": delivered_failure_bytes_present,
        "terminal_text_extraction_attempted": False,
        "native_checker_invocation_count": 0,
        "native_dispatch_observed": False,
    }
    _canonical_json_bytes(record)
    return record


def publish_failed_turn_record(path: Path, record: Mapping[str, Any]) -> str:
    """Publish a diagnostic once and return its exact byte hash."""

    if not isinstance(record, Mapping):
        raise ExecutorContractError("failure record must be an object")
    if (
        record.get("artifact_type") != FAILURE_RECORD_ARTIFACT_TYPE
        or record.get("execution_authorized") is not False
        or record.get("planner_status") != "failed"
        or record.get("terminal_text_extraction_attempted") is not False
        or record.get("native_checker_invocation_count") != 0
        or record.get("native_dispatch_observed") is not False
    ):
        raise ExecutorContractError(
            "failure record violates the fail-closed contract"
        )
    try:
        _write_immutable_json(Path(path), record)
    except RunChainBudgetError as exc:
        raise ExecutorContractError(str(exc)) from exc
    return _sha256_bytes(Path(path).read_bytes())


def resolve_planner_turn(
    *,
    repo_root: Path,
    cache: AttemptCache,
    turn: PlannerTurnView,
    source_task_id: str,
    cell_id: str,
    run_chain_manifest_sha256: str,
    failure_record_path: Path,
    checker_binding_ids: Sequence[str],
    checker_capabilities: Iterable[CheckerTextCapability],
    terminal_text_mode: str,
    terminal_text_loader: Callable[[], str],
) -> TurnResolution:
    """Resolve a turn with failure handling strictly before text extraction.

    Ordering is security-relevant and intentionally explicit:

    1. Failed status -> immutable diagnostic -> raise.
    2. Checker text-capability coverage/proof.
    3. Ledger-confirmed terminal-text extraction.

    Thus neither a failed turn nor an unproven text-sensitive checker can
    reach terminal capture or native checker execution.
    """

    turn = _validate_turn_view(turn)
    if not callable(terminal_text_loader):
        raise ExecutorContractError("terminal_text_loader must be callable")

    if turn.status == "failed":
        record = build_failed_turn_record(
            repo_root=repo_root,
            cache=cache,
            turn=turn,
            source_task_id=source_task_id,
            cell_id=cell_id,
            run_chain_manifest_sha256=run_chain_manifest_sha256,
        )
        record_sha = publish_failed_turn_record(failure_record_path, record)
        raise ImmutablePlannerFailure(
            f"planner turn failed with {_failure_class_value(turn.failure_class)}: "
            f"{turn.terminal_error}",
            record_path=failure_record_path,
            record_sha256=record_sha,
        )

    validated_capabilities = validate_checker_text_capabilities(
        repo_root=repo_root,
        source_task_id=source_task_id,
        checker_binding_ids=checker_binding_ids,
        capabilities=checker_capabilities,
        terminal_text_mode=terminal_text_mode,
    )
    text = terminal_text_loader()
    if not isinstance(text, str) or not text.strip():
        raise ExecutorContractError(
            "terminal text loader did not return delivered assistant bytes"
        )
    return TurnResolution(
        status=turn.status,
        terminal_text=text,
        checker_capabilities=validated_capabilities,
    )


@dataclass(frozen=True)
class BudgetSnapshot:
    cap: int
    consumed: int
    remaining: int
    counters: AttemptCounters
    pending_client_attempt: int | None


class RunChainBudgetGuard:
    """In-memory cap enforcement for a manifest-bound future client wrapper."""

    def __init__(self, budget: RunChainBudget) -> None:
        if not isinstance(budget, RunChainBudget):
            raise ExecutorContractError("budget must be a RunChainBudget")
        self._budget = budget
        self._counters = budget.counters
        self._pending: int | None = None

    def reserve_client_attempt(self) -> int:
        """Charge one attempt immediately before transport invocation."""

        if self._pending is not None:
            raise ExecutorContractError(
                "a client attempt is already pending classification"
            )
        consumed = self._counters.client_attempts
        if consumed >= self._budget.cap:
            raise ExecutorContractError("run-chain client-attempt cap exhausted")
        ordinal = consumed + 1
        self._counters = self._counters + AttemptCounters(client_attempts=1)
        self._pending = ordinal
        return ordinal

    def classify_reserved_attempt(
        self,
        ordinal: int,
        *,
        provider_accepted: bool,
        delivered_model_response: bool,
        input_tokens: int = 0,
        output_tokens: int = 0,
    ) -> None:
        """Finish the orthogonal classification without changing consumption."""

        if self._pending != ordinal:
            raise ExecutorContractError(
                "attempt classification does not match the reservation"
            )
        if not isinstance(provider_accepted, bool) or not isinstance(
            delivered_model_response, bool
        ):
            raise ExecutorContractError(
                "provider/delivery classifications must be Boolean"
            )
        input_count = (
            input_tokens
            if isinstance(input_tokens, int)
            and not isinstance(input_tokens, bool)
            and input_tokens >= 0
            else None
        )
        output_count = (
            output_tokens
            if isinstance(output_tokens, int)
            and not isinstance(output_tokens, bool)
            and output_tokens >= 0
            else None
        )
        if input_count is None or output_count is None:
            raise ExecutorContractError(
                "token counts must be non-negative integers"
            )
        if delivered_model_response and not provider_accepted:
            raise ExecutorContractError("delivery requires provider acceptance")
        total = input_count + output_count
        if total and not delivered_model_response:
            raise ExecutorContractError(
                "token-bearing classification requires a delivered response"
            )
        # ``AttemptCounters`` represents a valid cumulative state, not a loose
        # delta.  Client consumption was already charged at reservation time.
        self._counters = AttemptCounters(
            client_attempts=self._counters.client_attempts,
            provider_accepted_requests=(
                self._counters.provider_accepted_requests + int(provider_accepted)
            ),
            delivered_model_responses=(
                self._counters.delivered_model_responses
                + int(delivered_model_response)
            ),
            token_bearing_calls=(
                self._counters.token_bearing_calls + int(total > 0)
            ),
            input_tokens=self._counters.input_tokens + input_count,
            output_tokens=self._counters.output_tokens + output_count,
            total_tokens=self._counters.total_tokens + total,
        )
        self._pending = None

    def snapshot(self) -> BudgetSnapshot:
        consumed = self._counters.client_attempts
        return BudgetSnapshot(
            cap=self._budget.cap,
            consumed=consumed,
            remaining=self._budget.cap - consumed,
            counters=self._counters,
            pending_client_attempt=self._pending,
        )

    def assert_settled(self) -> None:
        if self._pending is not None:
            raise ExecutorContractError(
                "run-chain budget has an unclassified client attempt"
            )


__all__ = [
    "BudgetSnapshot",
    "CheckerTextCapability",
    "CONFIRMED_ASSISTANT_TEXT_MODE",
    "EXECUTION_AUTHORIZED",
    "EXECUTOR_ID",
    "ExecutorContractError",
    "FAILURE_RECORD_ARTIFACT_TYPE",
    "ImmutablePlannerFailure",
    "RunChainBudgetGuard",
    "RAW_RESPONSE_ENVELOPE_MODE",
    "TEXT_CAPABILITY_CONTRACT",
    "TurnResolution",
    "build_failed_turn_record",
    "publish_failed_turn_record",
    "resolve_planner_turn",
    "validate_checker_text_capabilities",
]
