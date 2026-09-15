"""RQ1b-owned, fail-closed planner seam for the public four-cell overlay.

The module deliberately contains no HTTP client and has no dependency on the
active Host V2 planner, runner, cache, prompt, canary, or proxy stack.  A caller
must inject a transport implementing :class:`SolTransport`; tests use an
in-memory fake and a future authorized runner may adapt the CLIProxy route.

One call has one client attempt and zero retries.  The attempt is charged
immediately before the injected transport is invoked.  Every attempt is then
published immutably.  A failed turn is handed to ``resolve_planner_turn`` so
its immutable failure artifact is published before any terminal-text or
checker path can run.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Protocol, Sequence

from .budget import (
    AttemptCounters,
    RunChainBudget,
    _canonical_json_bytes,
    _sha256_bytes,
    _write_immutable_json,
    counters_for_attempt,
)
from .contracts import FOUR_CELLS, SOURCE_TASK_ID, ContractError
from .executor import (
    BudgetSnapshot,
    CheckerTextCapability,
    CONFIRMED_ASSISTANT_TEXT_MODE,
    RunChainBudgetGuard,
    TurnResolution,
    resolve_planner_turn,
)


SOL_PLANNER_ID = "host-v2-public-four-cell-sol-planner-v1"
SOL_MODEL_ID = "gpt-5.6-sol"
SOL_REASONING_EFFORT = "max"
SOL_TEMPERATURE = 0
SOL_RETRIES = 0
MAX_TOTAL_DELIVERED_RESPONSES = 24
SUBMIT_TOOL_NAME = "submit_public_four_cell_turn"
ATTEMPT_ARTIFACT_TYPE = "agentmembrane_public_four_cell_sol_attempt"

_CELL_IDS = tuple(cell.cell_id for cell in FOUR_CELLS)
_CELL_ID_SET = frozenset(_CELL_IDS)
_HEX_SHA256 = frozenset("0123456789abcdef")

_SYSTEM_INSTRUCTION = """You are the isolated Host-mediated RQ1b planner.
Use only the native interface supplied below. Return exactly one call to
submit_public_four_cell_turn. The function arguments and the assistant
message content must carry the same non-empty confirmed_assistant_text.
Do not emit an unstructured plan and do not call any other function."""

_SUBMIT_TOOL = {
    "type": "function",
    "function": {
        "name": SUBMIT_TOOL_NAME,
        "description": "Submit the complete structured planner turn.",
        "strict": True,
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "status",
                "explicit_abstention",
                "actions",
                "final_artifact",
                "strategy",
                "confirmed_assistant_text",
            ],
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["complete", "explicit_abstention"],
                },
                "explicit_abstention": {"type": "boolean"},
                "actions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["operation", "arguments"],
                        "properties": {
                            "operation": {"type": "string", "minLength": 1},
                            "arguments": {"type": "object"},
                        },
                    },
                },
                "final_artifact": {"type": ["object", "null"]},
                "strategy": {"type": ["string", "null"]},
                "confirmed_assistant_text": {"type": "string", "minLength": 1},
            },
        },
    },
}


class SolPlannerError(ContractError):
    """The isolated Sol planner contract was violated."""


class SolTransport(Protocol):
    """One-shot raw-response seam for a future CLIProxy adapter.

    Returning from ``invoke`` means provider bytes were delivered.  Transport
    and pre-delivery failures must raise an exception.  The return value must
    be the raw JSON response text; an adapter must not pre-parse or rewrite it.
    """

    def invoke(self, request: Mapping[str, Any]) -> str: ...


def _nonnegative_int(value: Any, *, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise SolPlannerError(f"{field} must be a non-negative integer")
    return value


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HEX_SHA256 for character in value)
    )


@dataclass(frozen=True)
class DeliveredResponseCaps:
    """Externally supplied delivered-response ceilings.

    The global cap is the hard safety ceiling.  Each cell also has its own
    ceiling; a delivered response consumes both.  Caps are copied into a
    read-only mapping so caller mutation cannot alter an in-flight run.
    """

    per_cell: Mapping[str, int]
    total: int

    def __post_init__(self) -> None:
        if not isinstance(self.per_cell, Mapping) or set(self.per_cell) != _CELL_ID_SET:
            raise SolPlannerError("per_cell caps must cover the frozen four cells exactly")
        total = _nonnegative_int(self.total, field="total delivered cap")
        if total > MAX_TOTAL_DELIVERED_RESPONSES:
            raise SolPlannerError("total delivered cap exceeds 24")
        copied: dict[str, int] = {}
        for cell_id in _CELL_IDS:
            cap = _nonnegative_int(
                self.per_cell[cell_id], field=f"per_cell[{cell_id!r}]"
            )
            if cap > total:
                raise SolPlannerError("a per-cell delivered cap exceeds the total cap")
            copied[cell_id] = cap
        object.__setattr__(self, "per_cell", MappingProxyType(copied))


@dataclass(frozen=True)
class SolToolAction:
    operation: str
    arguments: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not isinstance(self.operation, str) or not self.operation.strip():
            raise SolPlannerError("tool action operation must be non-empty")
        if not isinstance(self.arguments, Mapping):
            raise SolPlannerError("tool action arguments must be an object")
        copied = json.loads(_canonical_json_bytes(dict(self.arguments)).decode("utf-8"))
        object.__setattr__(self, "arguments", MappingProxyType(copied))


@dataclass(frozen=True)
class SolPlannerTurn:
    """PlannerTurnView implementation owned entirely by this overlay."""

    request_key: str
    actions: tuple[SolToolAction, ...]
    final_artifact: Mapping[str, Any] | None
    strategy: str | None
    status: str
    explicit_abstention: bool
    failure_class: str
    terminal_error: str | None
    attempt_keys: tuple[str, ...]
    confirmed_assistant_text: str | None


@dataclass(frozen=True)
class SolPlannerResult:
    turn: SolPlannerTurn
    resolution: TurnResolution
    attempt_records: tuple[Mapping[str, Any], ...]
    attempt_ledger_sha256: str
    attempt_path: str
    attempt_sha256: str
    attempt_counters: AttemptCounters
    run_chain_manifest_sha256: str
    budget_snapshot: BudgetSnapshot


class SolAttemptStore:
    """Minimal immutable attempt ledger; not an adapter to the active cache."""

    def __init__(self, *, repo_root: Path, run_dir: Path) -> None:
        root = Path(repo_root).resolve()
        resolved = Path(run_dir).resolve()
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise SolPlannerError("attempt store escapes the repository") from exc
        self.repo_root = root
        self.run_dir = resolved

    @staticmethod
    def _coordinates(attempt_key: str) -> tuple[str, int]:
        pieces = attempt_key.split(":")
        if (
            len(pieces) != 2
            or not _is_sha256(pieces[0])
            or not pieces[1].isdigit()
            or int(pieces[1]) <= 0
            or str(int(pieces[1])) != pieces[1]
        ):
            raise SolPlannerError("attempt key is not canonical")
        return pieces[0], int(pieces[1])

    def path_for(self, attempt_key: str) -> Path:
        request_key, index = self._coordinates(attempt_key)
        return self.run_dir / "attempts" / request_key / f"{index}.json"

    def publish(self, attempt: Mapping[str, Any]) -> tuple[str, str]:
        key = attempt.get("attempt_key")
        if not isinstance(key, str):
            raise SolPlannerError("attempt lacks attempt_key")
        path = self.path_for(key)
        _write_immutable_json(path, attempt)
        relative = path.relative_to(self.repo_root).as_posix()
        return relative, _sha256_bytes(path.read_bytes())

    def load_attempt(self, attempt_key: str) -> dict[str, Any] | None:
        path = self.path_for(attempt_key)
        if not path.is_file():
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise SolPlannerError("attempt artifact is not readable JSON") from exc
        if not isinstance(value, dict):
            raise SolPlannerError("attempt artifact must be an object")
        return value


def _copy_messages(messages: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    if isinstance(messages, (str, bytes)) or not isinstance(messages, Sequence):
        raise SolPlannerError("messages must be a sequence")
    copied: list[dict[str, Any]] = []
    for index, message in enumerate(messages):
        if not isinstance(message, Mapping):
            raise SolPlannerError(f"messages[{index}] must be an object")
        row = json.loads(_canonical_json_bytes(dict(message)).decode("utf-8"))
        role = row.get("role")
        if role not in {"user", "assistant", "tool"}:
            raise SolPlannerError(
                "caller messages may contain only user, assistant, or tool roles"
            )
        if not isinstance(row.get("content"), str):
            raise SolPlannerError(f"messages[{index}].content must be text")
        copied.append(row)
    if not copied:
        raise SolPlannerError("messages must not be empty")
    return copied


def _request_payload(
    *, interface_description: str, messages: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    if not isinstance(interface_description, str) or not interface_description.strip():
        raise SolPlannerError("interface_description must be non-empty text")
    interface_message = {
        "role": "system",
        "content": f"{_SYSTEM_INSTRUCTION}\n\nNATIVE INTERFACE:\n{interface_description}",
    }
    return {
        "model": SOL_MODEL_ID,
        "reasoning_effort": SOL_REASONING_EFFORT,
        "temperature": SOL_TEMPERATURE,
        "retries": SOL_RETRIES,
        "messages": [interface_message, *_copy_messages(messages)],
        "tools": [copy.deepcopy(_SUBMIT_TOOL)],
        "tool_choice": {
            "type": "function",
            "function": {"name": SUBMIT_TOOL_NAME},
        },
    }


def _usage_or_zero(response: Any) -> tuple[int, int, int, str | None]:
    try:
        usage = response["usage"]
        if not isinstance(usage, Mapping):
            raise SolPlannerError("usage must be an object")
        required = {"input_tokens", "output_tokens", "total_tokens"}
        if set(usage) != required:
            raise SolPlannerError("usage fields differ from the transport contract")
        input_tokens = _nonnegative_int(usage["input_tokens"], field="input_tokens")
        output_tokens = _nonnegative_int(usage["output_tokens"], field="output_tokens")
        total_tokens = _nonnegative_int(usage["total_tokens"], field="total_tokens")
        if total_tokens != input_tokens + output_tokens:
            raise SolPlannerError("usage total is inconsistent")
        return input_tokens, output_tokens, total_tokens, None
    except Exception as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit, GeneratorExit)):
            raise
        return 0, 0, 0, f"{type(exc).__name__}: {exc}"


def _parse_delivered_turn(
    *, raw_response: str, request_key: str, attempt_key: str
) -> tuple[SolPlannerTurn, int, int, int]:
    try:
        response = json.loads(raw_response)
    except (TypeError, json.JSONDecodeError) as exc:
        raise SolPlannerError("delivered response is not JSON") from exc
    if not isinstance(response, Mapping):
        raise SolPlannerError("delivered response must be an object")
    allowed_top = {
        "model", "choices", "usage", "id", "object", "created", "system_fingerprint"
    }
    if not set(response).issubset(allowed_top) or not {
        "model", "choices", "usage"
    }.issubset(response):
        raise SolPlannerError("response envelope has missing or unexpected fields")
    if response["model"] != SOL_MODEL_ID:
        raise SolPlannerError("resolved model differs from exact gpt-5.6-sol")
    input_tokens, output_tokens, total_tokens, usage_error = _usage_or_zero(response)
    if usage_error is not None:
        raise SolPlannerError(usage_error)
    choices = response["choices"]
    if not isinstance(choices, list) or len(choices) != 1:
        raise SolPlannerError("response must contain exactly one choice")
    choice = choices[0]
    if not isinstance(choice, Mapping) or not {"finish_reason", "message"}.issubset(choice):
        raise SolPlannerError("choice lacks finish_reason/message")
    if not set(choice).issubset({"index", "finish_reason", "message", "logprobs"}):
        raise SolPlannerError("choice contains an unexpected field")
    if choice["finish_reason"] != "tool_calls":
        raise SolPlannerError("choice did not finish with a tool call")
    message = choice["message"]
    if not isinstance(message, Mapping):
        raise SolPlannerError("assistant message must be an object")
    if not {"role", "content", "tool_calls"}.issubset(message) or not set(message).issubset(
        {"role", "content", "tool_calls", "refusal"}
    ):
        raise SolPlannerError("assistant message fields violate the protocol")
    if message["role"] != "assistant" or not isinstance(message["content"], str):
        raise SolPlannerError("assistant message lacks confirmed text")
    if message.get("refusal") not in (None, ""):
        raise SolPlannerError("assistant response contains an out-of-protocol refusal")
    tool_calls = message["tool_calls"]
    if not isinstance(tool_calls, list) or len(tool_calls) != 1:
        raise SolPlannerError("assistant must make exactly one tool call")
    tool_call = tool_calls[0]
    if not isinstance(tool_call, Mapping) or set(tool_call) != {"id", "type", "function"}:
        raise SolPlannerError("tool call fields differ from the protocol")
    if not isinstance(tool_call["id"], str) or not tool_call["id"]:
        raise SolPlannerError("tool call id must be non-empty")
    if tool_call["type"] != "function" or not isinstance(tool_call["function"], Mapping):
        raise SolPlannerError("tool call is not a function call")
    function = tool_call["function"]
    if set(function) != {"name", "arguments"} or function["name"] != SUBMIT_TOOL_NAME:
        raise SolPlannerError("tool call does not target the forced submit function")
    if not isinstance(function["arguments"], str):
        raise SolPlannerError("tool arguments must be raw JSON text")
    try:
        arguments = json.loads(function["arguments"])
    except json.JSONDecodeError as exc:
        raise SolPlannerError("tool arguments are not JSON") from exc
    required = {
        "status", "explicit_abstention", "actions", "final_artifact", "strategy",
        "confirmed_assistant_text",
    }
    if not isinstance(arguments, Mapping) or set(arguments) != required:
        raise SolPlannerError("submit arguments have missing or unexpected fields")
    status = arguments["status"]
    abstention = arguments["explicit_abstention"]
    if status not in {"complete", "explicit_abstention"} or not isinstance(abstention, bool):
        raise SolPlannerError("submit status/abstention is invalid")
    if abstention is not (status == "explicit_abstention"):
        raise SolPlannerError("submit status and explicit_abstention disagree")
    confirmed_text = arguments["confirmed_assistant_text"]
    if (
        not isinstance(confirmed_text, str)
        or not confirmed_text.strip()
        or message["content"] != confirmed_text
    ):
        raise SolPlannerError("assistant content does not exactly confirm terminal text")
    strategy = arguments["strategy"]
    if strategy is not None and (not isinstance(strategy, str) or not strategy.strip()):
        raise SolPlannerError("strategy must be null or non-empty text")
    final_artifact = arguments["final_artifact"]
    if final_artifact is not None and not isinstance(final_artifact, Mapping):
        raise SolPlannerError("final_artifact must be an object or null")
    actions_value = arguments["actions"]
    if not isinstance(actions_value, list):
        raise SolPlannerError("actions must be an array")
    actions: list[SolToolAction] = []
    for action in actions_value:
        if not isinstance(action, Mapping) or set(action) != {"operation", "arguments"}:
            raise SolPlannerError("an action has missing or unexpected fields")
        actions.append(SolToolAction(action["operation"], action["arguments"]))
    if status == "explicit_abstention" and (actions or final_artifact is not None):
        raise SolPlannerError("explicit abstention must not carry actions or final artifact")
    if status == "complete" and not actions and final_artifact is None:
        raise SolPlannerError("complete turn must carry actions or a final artifact")
    frozen_artifact = None
    if final_artifact is not None:
        copied = json.loads(_canonical_json_bytes(dict(final_artifact)).decode("utf-8"))
        frozen_artifact = MappingProxyType(copied)
    return (
        SolPlannerTurn(
            request_key=request_key,
            actions=tuple(actions),
            final_artifact=frozen_artifact,
            strategy=strategy,
            status=status,
            explicit_abstention=abstention,
            failure_class="none",
            terminal_error=None,
            attempt_keys=(attempt_key,),
            confirmed_assistant_text=confirmed_text,
        ),
        input_tokens,
        output_tokens,
        total_tokens,
    )


def _failed_turn(
    *, request_key: str, attempt_key: str, failure_class: str, error: str
) -> SolPlannerTurn:
    return SolPlannerTurn(
        request_key=request_key,
        actions=(),
        final_artifact=None,
        strategy=None,
        status="failed",
        explicit_abstention=False,
        failure_class=failure_class,
        terminal_error=error,
        attempt_keys=(attempt_key,),
        confirmed_assistant_text=None,
    )


class SolPlanner:
    """One-shot exact-Sol planner with immutable budgets and evidence."""

    def __init__(
        self,
        *,
        repo_root: Path,
        transport: SolTransport,
        attempt_store: SolAttemptStore,
        run_chain_budget: RunChainBudget,
        delivered_caps: DeliveredResponseCaps,
    ) -> None:
        if not callable(getattr(transport, "invoke", None)):
            raise SolPlannerError("transport must implement invoke")
        if not isinstance(attempt_store, SolAttemptStore):
            raise SolPlannerError("attempt_store must be SolAttemptStore")
        if not isinstance(run_chain_budget, RunChainBudget):
            raise SolPlannerError("run_chain_budget must be immutable RunChainBudget")
        if not isinstance(delivered_caps, DeliveredResponseCaps):
            raise SolPlannerError("delivered_caps must be DeliveredResponseCaps")
        root = Path(repo_root).resolve()
        if attempt_store.repo_root != root:
            raise SolPlannerError("attempt store and planner repository roots differ")
        expected_store = (root / run_chain_budget.fresh_namespaces["cache"]).resolve()
        if attempt_store.run_dir != expected_store:
            raise SolPlannerError("attempt store is not the run-chain cache namespace")
        if run_chain_budget.cap > MAX_TOTAL_DELIVERED_RESPONSES:
            raise SolPlannerError("client-attempt run-chain cap exceeds 24")
        if (
            run_chain_budget.to_manifest()["manifest_payload_sha256"]
            != run_chain_budget.manifest_payload_sha256
        ):
            raise SolPlannerError("run-chain budget payload hash is inconsistent")
        self._repo_root = root
        self._transport = transport
        self._store = attempt_store
        self._budget = run_chain_budget
        self._guard = RunChainBudgetGuard(run_chain_budget)
        self._caps = delivered_caps
        self._delivered_by_cell = {cell_id: 0 for cell_id in _CELL_IDS}
        self._delivered_total = 0
        self._request_attempt_counts: dict[str, int] = {}
        self._validate_and_count_predecessors()

    def _validate_and_count_predecessors(self) -> None:
        aggregate = AttemptCounters()
        indices_by_request: dict[str, list[int]] = {}
        for predecessor in self._budget.predecessors:
            path = (self._repo_root / predecessor.path).resolve()
            try:
                path.relative_to(self._repo_root)
            except ValueError as exc:
                raise SolPlannerError("predecessor attempt escapes repository") from exc
            if not path.is_file() or _sha256_bytes(path.read_bytes()) != predecessor.sha256:
                raise SolPlannerError("immutable predecessor attempt drifted")
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise SolPlannerError("predecessor attempt is not readable JSON") from exc
            if not isinstance(value, Mapping):
                raise SolPlannerError("predecessor attempt must be an object")
            counters = counters_for_attempt(value)
            if counters != predecessor.counters:
                raise SolPlannerError("predecessor counters differ from immutable budget")
            aggregate = aggregate + counters
            request_key = value.get("request_key")
            if not _is_sha256(request_key):
                raise SolPlannerError("predecessor has a noncanonical request key")
            self._request_attempt_counts[str(request_key)] = (
                self._request_attempt_counts.get(str(request_key), 0) + 1
            )
            attempt_index = value.get("attempt_index")
            if not isinstance(attempt_index, int) or isinstance(attempt_index, bool):
                raise SolPlannerError("predecessor attempt index is invalid")
            indices_by_request.setdefault(str(request_key), []).append(attempt_index)
            if counters.delivered_model_responses:
                cell_id = value.get("cell_id")
                if cell_id not in _CELL_ID_SET:
                    raise SolPlannerError("delivered predecessor lacks a frozen cell id")
                if value.get("resolved_model_id") != SOL_MODEL_ID:
                    raise SolPlannerError("delivered predecessor used another model")
                self._delivered_by_cell[str(cell_id)] += 1
                self._delivered_total += 1
        if aggregate != self._budget.counters:
            raise SolPlannerError("predecessor chain counters differ from run-chain budget")
        for request_key, indices in indices_by_request.items():
            if sorted(indices) != list(range(1, len(indices) + 1)):
                raise SolPlannerError(
                    f"predecessor attempt chain is not contiguous for {request_key}"
                )
        if self._delivered_total > self._caps.total or any(
            self._delivered_by_cell[cell_id] > self._caps.per_cell[cell_id]
            for cell_id in _CELL_IDS
        ):
            raise SolPlannerError("predecessors already exceed delivered-response caps")

    def _assert_delivery_slot(self, cell_id: str) -> None:
        if cell_id not in _CELL_ID_SET:
            raise SolPlannerError("cell_id is not one frozen four-cell row")
        if self._delivered_total >= self._caps.total:
            raise SolPlannerError("total delivered-response cap exhausted")
        if self._delivered_by_cell[cell_id] >= self._caps.per_cell[cell_id]:
            raise SolPlannerError(f"delivered-response cap exhausted for {cell_id}")

    @property
    def budget_snapshot(self) -> BudgetSnapshot:
        return self._guard.snapshot()

    @property
    def delivered_counts(self) -> tuple[Mapping[str, int], int]:
        return MappingProxyType(dict(self._delivered_by_cell)), self._delivered_total

    @property
    def delivered_caps(self) -> DeliveredResponseCaps:
        """Return the immutable cap object bound at construction."""

        return self._caps

    def plan(
        self,
        *,
        cell_id: str,
        interface_description: str,
        messages: Sequence[Mapping[str, Any]],
        failure_record_path: Path,
        checker_binding_ids: Sequence[str],
        checker_capabilities: Sequence[CheckerTextCapability],
    ) -> SolPlannerResult:
        """Invoke one exact Sol attempt and return a ledger-bound resolution."""

        self._assert_delivery_slot(cell_id)
        payload = _request_payload(
            interface_description=interface_description, messages=messages
        )
        request_key = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
        attempt_index = self._request_attempt_counts.get(request_key, 0) + 1
        attempt_key = f"{request_key}:{attempt_index}"
        ordinal = self._guard.reserve_client_attempt()
        raw_response: str | None = None
        resolved_model_id: str | None = None
        usage = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
        usage_validation_error: str | None = None
        turn: SolPlannerTurn
        failure_class = "none"
        error: str | None = None
        try:
            delivered = self._transport.invoke(copy.deepcopy(payload))
            if not isinstance(delivered, str):
                raise SolPlannerError("transport did not return raw JSON text")
            raw_response = delivered
            try:
                loose_response = json.loads(delivered)
            except json.JSONDecodeError:
                loose_response = None
            if isinstance(loose_response, Mapping):
                observed_model = loose_response.get("model")
                resolved_model_id = (
                    observed_model if isinstance(observed_model, str) else "unresolved"
                )
                input_count, output_count, total_count, usage_validation_error = (
                    _usage_or_zero(loose_response)
                )
                usage = {
                    "input_tokens": input_count,
                    "output_tokens": output_count,
                    "total_tokens": total_count,
                }
            else:
                resolved_model_id = "unresolved"
                usage_validation_error = "response JSON envelope was unavailable"
            self._guard.classify_reserved_attempt(
                ordinal,
                provider_accepted=True,
                delivered_model_response=True,
                input_tokens=usage["input_tokens"],
                output_tokens=usage["output_tokens"],
            )
            self._delivered_by_cell[cell_id] += 1
            self._delivered_total += 1
            try:
                turn, input_count, output_count, total_count = _parse_delivered_turn(
                    raw_response=delivered,
                    request_key=request_key,
                    attempt_key=attempt_key,
                )
                usage = {
                    "input_tokens": input_count,
                    "output_tokens": output_count,
                    "total_tokens": total_count,
                }
            except Exception as exc:
                if isinstance(exc, (KeyboardInterrupt, SystemExit, GeneratorExit)):
                    raise
                failure_class = "response_contract_failure"
                error = f"{type(exc).__name__}: {exc}"
                turn = _failed_turn(
                    request_key=request_key,
                    attempt_key=attempt_key,
                    failure_class=failure_class,
                    error=error,
                )
        except Exception as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit, GeneratorExit)):
                raise
            if self._guard.snapshot().pending_client_attempt is not None:
                self._guard.classify_reserved_attempt(
                    ordinal,
                    provider_accepted=False,
                    delivered_model_response=False,
                )
            failure_class = "transport_failure"
            error = f"{type(exc).__name__}: {exc}"
            turn = _failed_turn(
                request_key=request_key,
                attempt_key=attempt_key,
                failure_class=failure_class,
                error=error,
            )
        attempt = {
            "schema_version": 1,
            "artifact_type": ATTEMPT_ARTIFACT_TYPE,
            "planner_id": SOL_PLANNER_ID,
            "execution_authorized": False,
            "cell_id": cell_id,
            "request_key": request_key,
            "attempt_key": attempt_key,
            "attempt_index": attempt_index,
            "run_chain_ordinal": ordinal,
            "run_chain_manifest_sha256": self._budget.manifest_payload_sha256,
            "route": {
                "model": SOL_MODEL_ID,
                "reasoning_effort": SOL_REASONING_EFFORT,
                "temperature": SOL_TEMPERATURE,
                "retries": SOL_RETRIES,
            },
            "request_sha256": request_key,
            "planner_status": turn.status,
            "failure_class": failure_class,
            "error": error,
            "error_metadata": {
                "usage_validation_error": usage_validation_error,
                "confirmed_assistant_text": (
                    turn.confirmed_assistant_text is not None
                ),
            },
            "usage": usage,
            "raw_response": raw_response,
            "resolved_model_id": resolved_model_id,
        }
        attempt_counters = counters_for_attempt(attempt)
        attempt_path, attempt_sha256 = self._store.publish(attempt)
        self._request_attempt_counts[request_key] = attempt_index
        immutable_attempt = MappingProxyType(copy.deepcopy(attempt))
        ledger = {
            "run_chain_manifest_sha256": self._budget.manifest_payload_sha256,
            "attempts": [{"path": attempt_path, "sha256": attempt_sha256}],
        }
        attempt_ledger_sha256 = _sha256_bytes(_canonical_json_bytes(ledger))

        resolution = resolve_planner_turn(
            repo_root=self._repo_root,
            cache=self._store,
            turn=turn,
            source_task_id=SOURCE_TASK_ID,
            cell_id=cell_id,
            run_chain_manifest_sha256=self._budget.manifest_payload_sha256,
            failure_record_path=Path(failure_record_path),
            checker_binding_ids=checker_binding_ids,
            checker_capabilities=checker_capabilities,
            terminal_text_mode=CONFIRMED_ASSISTANT_TEXT_MODE,
            terminal_text_loader=lambda: str(turn.confirmed_assistant_text or ""),
        )
        self._guard.assert_settled()
        return SolPlannerResult(
            turn=turn,
            resolution=resolution,
            attempt_records=(immutable_attempt,),
            attempt_ledger_sha256=attempt_ledger_sha256,
            attempt_path=attempt_path,
            attempt_sha256=attempt_sha256,
            attempt_counters=attempt_counters,
            run_chain_manifest_sha256=self._budget.manifest_payload_sha256,
            budget_snapshot=self._guard.snapshot(),
        )


__all__ = [
    "ATTEMPT_ARTIFACT_TYPE",
    "DeliveredResponseCaps",
    "MAX_TOTAL_DELIVERED_RESPONSES",
    "SOL_MODEL_ID",
    "SOL_PLANNER_ID",
    "SOL_REASONING_EFFORT",
    "SOL_RETRIES",
    "SOL_TEMPERATURE",
    "SUBMIT_TOOL_NAME",
    "SolAttemptStore",
    "SolPlanner",
    "SolPlannerError",
    "SolPlannerResult",
    "SolPlannerTurn",
    "SolToolAction",
    "SolTransport",
]
