"""Fresh-namespace provider engineering executor for the RQ1 v2 overlay.

This entrypoint accepts engineering test doubles only.  It is a runnability
gate, not real-execution authorization.  Every cell is written immediately
with O_EXCL, and provider/parse/schema failures do not stop later cells.
No expected outcome or oracle direction is consulted.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from ...proxy import Completion, ReasoningEffort
from ..schema import IntegrityError, canonical_json_bytes
from .provider_agent import (
    MAX_COMPLETION_TOKENS,
    MODEL_ID,
    REASONING_EFFORT,
    REQUEST_RETRIES,
    SYSTEM_PROMPT,
    ProviderBackedOrdinaryAgent,
)
from .runner import run_ordinary_agent_episode
from .selector import all_cells, selector_manifest


_NAMESPACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{5,80}\Z")


class EngineeringExecutorError(IntegrityError):
    """The non-authorizing provider engineering batch failed closed."""


class OfflineScriptedCompletionClient:
    """Sealed finite completion script with no network implementation."""

    __slots__ = ("_calls", "_next_step", "_steps")

    def __init_subclass__(cls, **kwargs: Any) -> None:
        del kwargs
        raise TypeError("OfflineScriptedCompletionClient cannot be subclassed")

    def __init__(self, steps: Sequence[Completion | Exception]) -> None:
        if isinstance(steps, (str, bytes)) or not isinstance(steps, Sequence):
            raise TypeError("steps must be a finite sequence")
        prepared: list[tuple[str, Completion | dict[str, str]]] = []
        for index, step in enumerate(steps, start=1):
            if type(step) is Completion:
                prepared.append(
                    (
                        "completion",
                        Completion(
                            text=step.text,
                            model=step.model,
                            latency_ms=step.latency_ms,
                            input_tokens=step.input_tokens,
                            output_tokens=step.output_tokens,
                            total_tokens=step.total_tokens,
                        ),
                    )
                )
            elif isinstance(step, Exception):
                prepared.append(
                    (
                        "exception",
                        {
                            "type": type(step).__name__,
                            "message": str(step),
                        },
                    )
                )
            else:
                raise TypeError(
                    f"offline script step {index} must be Completion or Exception"
                )
        self._steps = tuple(prepared)
        self._next_step = 0
        self._calls: list[dict[str, Any]] = []

    @property
    def calls(self) -> tuple[dict[str, Any], ...]:
        return tuple(copy.deepcopy(self._calls))

    @property
    def call_count(self) -> int:
        return len(self._calls)

    @property
    def step_count(self) -> int:
        return len(self._steps)

    @property
    def remaining_step_count(self) -> int:
        return len(self._steps) - self._next_step

    def complete(
        self,
        *,
        model: str,
        system: str,
        user: str,
        max_completion_tokens: int,
        retries: int,
        reasoning_effort: ReasoningEffort | None,
    ) -> Completion:
        """Consume one step only when the exact RQ1 completion kwargs match."""

        if (
            model != MODEL_ID
            or system != SYSTEM_PROMPT
            or max_completion_tokens != MAX_COMPLETION_TOKENS
            or retries != REQUEST_RETRIES
            or reasoning_effort != REASONING_EFFORT
            or not isinstance(user, str)
        ):
            raise EngineeringExecutorError("offline completion kwargs drifted")
        try:
            user_value = json.loads(user)
        except json.JSONDecodeError as exc:
            raise EngineeringExecutorError(
                "offline completion user payload is not JSON"
            ) from exc
        if canonical_json_bytes(user_value).decode("utf-8") != user:
            raise EngineeringExecutorError(
                "offline completion user payload is not canonical JSON"
            )
        self._calls.append(
            {
                "model": model,
                "system": system,
                "user": user,
                "max_completion_tokens": max_completion_tokens,
                "retries": retries,
                "reasoning_effort": reasoning_effort,
            }
        )
        if self._next_step >= len(self._steps):
            raise RuntimeError("offline completion script exhausted")
        kind, value = self._steps[self._next_step]
        self._next_step += 1
        if kind == "exception":
            assert isinstance(value, dict)
            raise RuntimeError(
                f"offline scripted {value['type']}: {value['message']}"
            )
        assert type(value) is Completion
        return value


def _write_exclusive(path: Path, value: Mapping[str, Any]) -> str:
    payload = canonical_json_bytes(dict(value)) + b"\n"
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    except FileExistsError as exc:
        raise EngineeringExecutorError(f"refusing to overwrite artifact: {path}") from exc
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    return hashlib.sha256(payload).hexdigest()


def _reserve_namespace(output_root: Path, namespace: str) -> Path:
    if not isinstance(namespace, str) or _NAMESPACE.fullmatch(namespace) is None:
        raise EngineeringExecutorError("namespace must be one fresh safe component")
    root = Path(output_root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    target = root / namespace
    try:
        target.mkdir(mode=0o700, exist_ok=False)
    except FileExistsError as exc:
        raise EngineeringExecutorError(f"namespace is not fresh: {target}") from exc
    if target.resolve().parent != root:
        raise EngineeringExecutorError("namespace escapes output root")
    return target


def _classify_episode(episode: Mapping[str, Any]) -> str:
    outcome = episode.get("outcome")
    if not isinstance(outcome, Mapping):
        return "executor_failure"
    reason = outcome.get("terminal_reason")
    error = outcome.get("terminal_error")
    error_type = error.get("type") if isinstance(error, Mapping) else None
    if reason == "agent_error" and error_type == "ProviderCallError":
        return "provider_failure"
    if reason == "agent_error" and error_type == "ProviderResponseError":
        return "parse_failure"
    if reason == "invalid_schema_denial":
        return "schema_failure"
    if reason in {
        "send_money_dispatched",
        "protected_policy_denial",
        "max_agent_turns",
    }:
        return "episode_completed"
    return "episode_failure"


def _correct_offline_execution_counts(
    episode: Mapping[str, Any], *, completion_client_calls: int
) -> dict[str, Any]:
    """Correct a copied legacy episode only under the sealed offline client."""

    corrected = copy.deepcopy(dict(episode))
    legacy = corrected.get("execution_counts")
    if not isinstance(legacy, Mapping):
        raise EngineeringExecutorError("episode has no legacy execution counts")
    legacy_copy = copy.deepcopy(dict(legacy))
    corrected["execution_counts"] = {
        "api_calls": 0,
        "completion_client_calls": completion_client_calls,
        "model_calls": 0,
        "native_dispatches": legacy_copy.get("native_dispatches"),
        "ordinary_agent_calls": legacy_copy.get("ordinary_agent_calls"),
        "provider_calls": 0,
    }
    corrected["execution_counts_provenance"] = {
        "accounting_basis": "exact_sealed_offline_scripted_completion_client",
        "completion_client_calls_source": (
            "ProviderBackedOrdinaryAgent.request_count"
        ),
        "legacy_source_execution_counts": legacy_copy,
        "legacy_source_fields_unconditionally_zero": [
            "api_calls",
            "model_calls",
            "provider_calls",
        ],
        "real_api_calls_proven_zero_by_exact_client_type": True,
        "runner_source_left_unmodified_to_preserve_materialized_gate_binding": True,
    }
    canonical_json_bytes(corrected)
    return corrected


def run_provider_engineering_batch(
    client: OfflineScriptedCompletionClient,
    *,
    output_root: Path,
    namespace: str,
    engineering_test_double: bool = False,
) -> dict[str, Any]:
    """Run all cells independently with a test-double provider and persist each."""

    if (
        engineering_test_double is not True
        or type(client) is not OfflineScriptedCompletionClient
    ):
        raise EngineeringExecutorError(
            "this entrypoint requires the exact sealed offline client type"
        )
    if client.call_count != 0:
        raise EngineeringExecutorError("offline completion client must be fresh")
    namespace_path = _reserve_namespace(Path(output_root), namespace)
    reservation = {
        "schema_version": 1,
        "artifact_type": "agentmembrane_rq1_provider_namespace_reservation_v2",
        "namespace": namespace,
        "selector_manifest": selector_manifest(),
        "engineering_test_double_required": True,
        "exact_offline_client_type_required": True,
        "offline_client_type": (
            "agentmembrane.host_v2.rq1_public_agentdojo_v2."
            "engineering_executor:OfflineScriptedCompletionClient"
        ),
        "offline_script_step_count": client.step_count,
        "network_capability": False,
        "execution_authorized": False,
        "real_public_execution_authorized": False,
    }
    reservation_path = namespace_path / "reservation.json"
    reservation_sha = _write_exclusive(reservation_path, reservation)
    cell_rows: list[dict[str, Any]] = []
    total_provider_requests = 0
    for index, cell in enumerate(all_cells(), start=1):
        agent = ProviderBackedOrdinaryAgent(client)
        try:
            episode = run_ordinary_agent_episode(cell, agent)
            episode = _correct_offline_execution_counts(
                episode,
                completion_client_calls=agent.request_count,
            )
            classification = _classify_episode(episode)
            cell_artifact = {
                "schema_version": 1,
                "artifact_type": (
                    "agentmembrane_rq1_provider_engineering_cell_v2"
                ),
                "cell_index": index,
                "task_id": cell.task_id,
                "host_private_coordinate": {
                    "pair_role": cell.pair_role,
                    "arm": cell.arm,
                },
                "classification": classification,
                "episode": episode,
                "provider_request_count": agent.request_count,
                "provider_request_records": copy.deepcopy(agent.request_records),
                "real_api_calls": 0,
                "real_api_calls_zero_basis": (
                    "exact_type_is_OfflineScriptedCompletionClient"
                ),
                "offline_client_exact_type_verified": True,
                "execution_authorized": False,
                "real_public_execution_authorized": False,
            }
        except Exception as exc:
            classification = "executor_failure"
            cell_artifact = {
                "schema_version": 1,
                "artifact_type": (
                    "agentmembrane_rq1_provider_engineering_cell_diagnostic_v2"
                ),
                "cell_index": index,
                "task_id": cell.task_id,
                "host_private_coordinate": {
                    "pair_role": cell.pair_role,
                    "arm": cell.arm,
                },
                "classification": classification,
                "error": {
                    "type": type(exc).__name__,
                    "message": str(exc),
                },
                "provider_request_count": agent.request_count,
                "provider_request_records": copy.deepcopy(agent.request_records),
                "real_api_calls": 0,
                "real_api_calls_zero_basis": (
                    "exact_type_is_OfflineScriptedCompletionClient"
                ),
                "offline_client_exact_type_verified": True,
                "execution_authorized": False,
                "real_public_execution_authorized": False,
            }
        total_provider_requests += agent.request_count
        cell_path = namespace_path / f"cell-{index:02d}-{cell.task_id}.json"
        cell_sha = _write_exclusive(cell_path, cell_artifact)
        cell_rows.append(
            {
                "cell_index": index,
                "task_id": cell.task_id,
                "classification": classification,
                "path": cell_path.name,
                "sha256": cell_sha,
                "provider_request_count": agent.request_count,
            }
        )
    if client.call_count != total_provider_requests:
        raise EngineeringExecutorError(
            "offline client calls differ from episode request accounting"
        )
    completed = sum(
        row["classification"] == "episode_completed" for row in cell_rows
    )
    summary = {
        "schema_version": 1,
        "artifact_type": "agentmembrane_rq1_provider_engineering_batch_v2",
        "namespace": namespace,
        "namespace_path": str(namespace_path),
        "reservation": {
            "path": reservation_path.name,
            "sha256": reservation_sha,
        },
        "selector_manifest": selector_manifest(),
        "cells": cell_rows,
        "cell_count": 4,
        "completed_episode_count": completed,
        "failed_episode_count": 4 - completed,
        "provider_request_count": total_provider_requests,
        "offline_client_call_count": client.call_count,
        "offline_client_call_count_matches": True,
        "offline_client_exact_type_verified": True,
        "offline_script_step_count": client.step_count,
        "offline_script_remaining_step_count": client.remaining_step_count,
        "offline_script_fully_consumed": client.remaining_step_count == 0,
        "expected_outcome_gate_used": False,
        "oracle_direction_gate_used": False,
        "continue_after_cell_failure": True,
        "fresh_namespace_required": True,
        "real_api_calls": 0,
        "real_api_calls_zero_basis": (
            "exact_type_is_OfflineScriptedCompletionClient"
        ),
        "execution_authorized": False,
        "real_public_execution_authorized": False,
        "claim_eligible": False,
    }
    summary_path = namespace_path / "summary.json"
    summary_sha = _write_exclusive(summary_path, summary)
    return {
        "namespace_path": str(namespace_path),
        "summary_path": str(summary_path),
        "summary_sha256": summary_sha,
        "summary": summary,
    }


def load_engineering_batch(path: Path) -> dict[str, Any]:
    """Load one written summary for tests and offline inspection."""

    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EngineeringExecutorError(f"cannot load batch summary: {exc}") from exc
    if not isinstance(value, dict):
        raise EngineeringExecutorError("batch summary must be an object")
    canonical_json_bytes(value)
    return value


__all__ = [
    "EngineeringExecutorError",
    "OfflineScriptedCompletionClient",
    "load_engineering_batch",
    "run_provider_engineering_batch",
]
