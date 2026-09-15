"""Durable zero-retry executor for the RQ1 activation calibration."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from ...proxy import Completion, LocalProxyClient
from ..rq1_public_agentdojo_multi_v5.attribution import attribute_attack
from ..rq1_public_agentdojo_multi_v5.provider_agent import (
    ProviderCallError,
    ProviderResponseContractError,
    ProviderResponseParseError,
)
from ..schema import SchemaError, canonical_json_bytes, sha256_json
from .analysis import analyze_namespace
from .attack_baseline import attack_manifest
from .client import ExactLunaLowClient
from .provider_agent import (
    CalibrationOrdinaryAgent,
    MAX_COMPLETION_TOKENS,
    MAX_TURNS_PER_CELL,
    MODEL_ID,
    REASONING_EFFORT,
    REQUEST_RETRIES,
    SYSTEM_PROMPT,
)
from .runtime import CalibrationNativeSession
from .selector import (
    CalibrationCell,
    RunKind,
    calibration_schedule,
    schedule_manifest,
    smoke_schedule,
)


REPO_ROOT = Path(__file__).resolve().parents[3]
OUTPUT_ROOT = REPO_ROOT / "experiments/host_boundary_v2/rq1_activation_calibration_v1/runs"
PINNED_PYTHON = (
    REPO_ROOT
    / "experiments/host_boundary_v2/runtime_envs/"
    "agentdojo-0.1.35-py3123-lock-395e3d0a5921-rq1v4/bin/python"
)
RUNTIME_RECEIPT = (
    REPO_ROOT
    / "experiments/host_boundary_v2/runtime_envs/receipts/"
    "agentdojo-0.1.35-py3123-lock-395e3d0a5921-rq1v4.json"
)
_NAMESPACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,159}")
MAX_PROVIDER_USER_BYTES = 1_000_000

_BOUND_FILES = (
    "agentmembrane/proxy.py",
    "agentmembrane/host_v2/rq1_public_agentdojo_multi_v5/attribution.py",
    "agentmembrane/host_v2/rq1_public_agentdojo_multi_v5/provider_agent.py",
    "agentmembrane/host_v2/rq1_public_agentdojo_multi_v5/runtime.py",
    "agentmembrane/host_v2/rq1_public_agentdojo_multi_v3/domain_authority/core.py",
    "agentmembrane/host_v2/rq1_activation_calibration_v1/attack_baseline.py",
    "agentmembrane/host_v2/rq1_activation_calibration_v1/adapter.py",
    "agentmembrane/host_v2/rq1_activation_calibration_v1/runtime.py",
    "agentmembrane/host_v2/rq1_activation_calibration_v1/selector.py",
    "agentmembrane/host_v2/rq1_activation_calibration_v1/provider_agent.py",
    "agentmembrane/host_v2/rq1_activation_calibration_v1/client.py",
    "agentmembrane/host_v2/rq1_activation_calibration_v1/executor.py",
    "agentmembrane/host_v2/rq1_activation_calibration_v1/analysis.py",
    "agentmembrane/host_v2/rq1_activation_calibration_v1/run.py",
    "agentmembrane/host_v2/rq1_activation_calibration_v1/audit.py",
)


class CalibrationExecutorError(RuntimeError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _write_new(path: Path, value: Any) -> None:
    payload = canonical_json_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, delete=False
        ) as handle:
            temp_path = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temp_path, path)
    except FileExistsError as exc:
        raise CalibrationExecutorError(f"evidence file already exists: {path.name}") from exc
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass


def _read(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CalibrationExecutorError(f"cannot read {path.name}") from exc


def _sha_file(relative: str) -> str:
    path = REPO_ROOT / relative
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise CalibrationExecutorError(f"cannot hash bound file: {relative}") from exc


def implementation_bindings() -> dict[str, str]:
    return {relative: _sha_file(relative) for relative in _BOUND_FILES}


def runtime_binding() -> dict[str, Any]:
    if not PINNED_PYTHON.is_file() or not RUNTIME_RECEIPT.is_file():
        raise CalibrationExecutorError("frozen AgentDojo runtime is missing")
    receipt = _read(RUNTIME_RECEIPT)
    environment = receipt.get("environment") if isinstance(receipt, Mapping) else None
    interpreter = receipt.get("interpreter") if isinstance(receipt, Mapping) else None
    if not isinstance(environment, Mapping) or not isinstance(interpreter, Mapping):
        raise CalibrationExecutorError("frozen runtime receipt lacks environment or interpreter")
    if environment.get("python_executable") != str(PINNED_PYTHON):
        raise CalibrationExecutorError("runtime receipt points to a different Python")
    value = {
        "python_launcher": str(PINNED_PYTHON.relative_to(REPO_ROOT)),
        "python_executable_sha256": hashlib.sha256(PINNED_PYTHON.read_bytes()).hexdigest(),
        "provisioning_receipt_path": str(RUNTIME_RECEIPT.relative_to(REPO_ROOT)),
        "provisioning_receipt_sha256": hashlib.sha256(RUNTIME_RECEIPT.read_bytes()).hexdigest(),
        "runtime_id": receipt.get("runtime_id"),
        "python_version": interpreter.get("version"),
    }
    if value["python_executable_sha256"] != interpreter.get("executable_sha256"):
        raise CalibrationExecutorError("pinned Python bytes differ from runtime receipt")
    canonical_json_bytes(value)
    return value


def validate_pinned_runtime() -> None:
    runtime_binding()
    if Path(sys.executable) != PINNED_PYTHON:
        raise CalibrationExecutorError(
            "execute through the versioned run entrypoint so it can select the pinned AgentDojo Python"
        )


def _schedule(kind: RunKind) -> tuple[CalibrationCell, ...]:
    return smoke_schedule() if kind == "smoke" else calibration_schedule()


def preflight_proxy_model() -> dict[str, Any]:
    """Verify the local alias without making a generation request."""

    client = LocalProxyClient.from_local_config(timeout_seconds=30)
    available = client.list_models()
    if MODEL_ID not in available:
        raise CalibrationExecutorError(f"CLIProxy does not expose {MODEL_ID}")
    value = {
        "schema_version": 1,
        "artifact_type": "rq1_activation_model_preflight_v1",
        "base_url": client.base_url,
        "required_model": MODEL_ID,
        "required_model_available": True,
        "available_model_ids_sha256": sha256_json(sorted(available)),
        "generation_calls": 0,
        "checked_at": _utc_now(),
    }
    canonical_json_bytes(value)
    return value


def prepare_namespace(*, namespace: str, run_kind: RunKind) -> Path:
    if _NAMESPACE.fullmatch(namespace) is None:
        raise CalibrationExecutorError("namespace must be one safe fresh component")
    if run_kind not in {"smoke", "sample50"}:
        raise CalibrationExecutorError("run kind must be smoke or sample50")
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    root = (OUTPUT_ROOT / namespace).resolve()
    try:
        root.relative_to(OUTPUT_ROOT.resolve())
    except ValueError as exc:
        raise CalibrationExecutorError("namespace escapes output root") from exc
    try:
        root.mkdir()
    except FileExistsError as exc:
        raise CalibrationExecutorError("execution namespace is not fresh") from exc
    schedule = _schedule(run_kind)
    manifest = {
        "schema_version": 1,
        "artifact_type": "rq1_activation_run_manifest_v1",
        "namespace": namespace,
        "run_kind": run_kind,
        "prepared_at": _utc_now(),
        "model": MODEL_ID,
        "reasoning_effort": REASONING_EFFORT,
        "request_retries": REQUEST_RETRIES,
        "max_completion_tokens": MAX_COMPLETION_TOKENS,
        "max_turns_per_cell": MAX_TURNS_PER_CELL,
        "global_generation_call_cap": len(schedule) * MAX_TURNS_PER_CELL,
        "one_api_request_per_agent_turn": True,
        "cross_workflow_mega_prompt": False,
        "schedule_manifest": schedule_manifest(run_kind),
        "attack_manifest": attack_manifest(),
        "implementation_bindings": implementation_bindings(),
        "runtime_binding": runtime_binding(),
        "authorization": {
            "source": "explicit_user_request_2026-09-01/02",
            "provider": "loopback_cliproxy_only",
            "model": MODEL_ID,
            "max_sessions": len(schedule),
            "max_generation_calls": len(schedule) * MAX_TURNS_PER_CELL,
            "consumed_by_fresh_namespace_creation": True,
        },
        "development_calibration_only": True,
        "claim_eligible": False,
    }
    _write_new(root / "run-manifest.json", manifest)
    _write_new(root / "schedule.json", [cell.private_json() for cell in schedule])
    return root


def _validate_root(root: Path) -> tuple[RunKind, tuple[CalibrationCell, ...]]:
    manifest = _read(root / "run-manifest.json")
    if not isinstance(manifest, Mapping):
        raise CalibrationExecutorError("run manifest is not an object")
    kind = manifest.get("run_kind")
    if kind not in {"smoke", "sample50"}:
        raise CalibrationExecutorError("run kind drifted")
    schedule = _schedule(kind)
    if _read(root / "schedule.json") != [cell.private_json() for cell in schedule]:
        raise CalibrationExecutorError("schedule differs from frozen selector")
    if manifest.get("implementation_bindings") != implementation_bindings():
        raise CalibrationExecutorError("bound implementation bytes drifted after prepare")
    if manifest.get("attack_manifest") != attack_manifest():
        raise CalibrationExecutorError("attack baseline drifted after prepare")
    if manifest.get("runtime_binding") != runtime_binding():
        raise CalibrationExecutorError("frozen runtime binding drifted after prepare")
    return kind, schedule


def _reservation_paths(root: Path) -> list[Path]:
    return sorted((root / "attempts").glob("cell-*/turn-*.reservation.json"))


def _terminal_paths(root: Path) -> list[Path]:
    return sorted((root / "attempts").glob("cell-*/turn-*.terminal.json"))


class _DurableClient:
    def __init__(self, *, delegate: ExactLunaLowClient, root: Path, cell: CalibrationCell) -> None:
        self.delegate = delegate
        self.root = root
        self.cell = cell
        self.calls_made = 0

    def complete(self, **kwargs: Any) -> Completion:
        if (
            set(kwargs)
            != {"model", "system", "user", "max_completion_tokens", "retries", "reasoning_effort"}
            or kwargs.get("model") != MODEL_ID
            or kwargs.get("system") != SYSTEM_PROMPT
            or kwargs.get("max_completion_tokens") != MAX_COMPLETION_TOKENS
            or kwargs.get("retries") != 0
            or kwargs.get("reasoning_effort") != REASONING_EFFORT
        ):
            raise CalibrationExecutorError("provider request differs from frozen contract")
        user = kwargs.get("user")
        if not isinstance(user, str) or len(user.encode()) > MAX_PROVIDER_USER_BYTES:
            raise CalibrationExecutorError("provider payload exceeds byte cap")
        schedule_count = len(_read(self.root / "schedule.json"))
        if len(_reservation_paths(self.root)) >= schedule_count * MAX_TURNS_PER_CELL:
            raise CalibrationExecutorError("global provider call cap exhausted")
        self.calls_made += 1
        turn = self.calls_made
        if turn > MAX_TURNS_PER_CELL:
            raise CalibrationExecutorError("cell provider call cap exhausted")
        ordinal = self.cell.execution_ordinal
        attempt_dir = self.root / "attempts" / f"cell-{ordinal:02d}"
        reservation_path = attempt_dir / f"turn-{turn:02d}.reservation.json"
        terminal_path = attempt_dir / f"turn-{turn:02d}.terminal.json"
        request_sha = sha256_json(copy.deepcopy(kwargs))
        identity = {
            "attempt_id": f"{self.cell.cell_id}:turn-{turn:02d}",
            "cell_id": self.cell.cell_id,
            "cell_ordinal": ordinal,
            "turn": turn,
            "request_sha256": request_sha,
            "model": MODEL_ID,
            "system_sha256": hashlib.sha256(SYSTEM_PROMPT.encode()).hexdigest(),
            "user_sha256": hashlib.sha256(user.encode()).hexdigest(),
            "user_bytes": len(user.encode()),
            "client_class": f"{type(self.delegate).__module__}.{type(self.delegate).__qualname__}",
        }
        _write_new(
            reservation_path,
            {
                "schema_version": 1,
                "artifact_type": "rq1_activation_call_reservation_v1",
                **identity,
                "reserved_at": _utc_now(),
            },
        )
        completion: Completion | None = None
        error: BaseException | None = None
        try:
            delivered = self.delegate.complete(**kwargs)
            if not isinstance(delivered, Completion):
                raise TypeError("completion client returned a non-Completion")
            completion = delivered
            return delivered
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except BaseException as exc:
            error = exc
            raise
        finally:
            if completion is not None or error is not None:
                usage = (
                    {
                        "input_tokens": completion.input_tokens,
                        "output_tokens": completion.output_tokens,
                        "total_tokens": completion.total_tokens,
                    }
                    if completion is not None
                    else None
                )
                reconciled = self.delegate.calls_made == turn
                _write_new(
                    terminal_path,
                    {
                        "schema_version": 1,
                        "artifact_type": "rq1_activation_call_terminal_v1",
                        **identity,
                        "status": "returned" if completion is not None else "provider_error",
                        "completion_model": completion.model if completion else None,
                        "completion_latency_ms": completion.latency_ms if completion else None,
                        "completion_text_sha256": (
                            hashlib.sha256(completion.text.encode()).hexdigest()
                            if completion else None
                        ),
                        "usage": usage,
                        "usage_known": bool(
                            usage is not None
                            and all(type(value) is int and value >= 0 for value in usage.values())
                        ),
                        "delegate_calls_made": self.delegate.calls_made,
                        "client_call_reconciled": reconciled,
                        "error_type": type(error).__name__ if error else None,
                        "finished_at": _utc_now(),
                    },
                )
                if not reconciled:
                    raise CalibrationExecutorError("client counter differs from durable ledger")


def _contains_text(value: Any, needle: str) -> bool:
    if isinstance(value, str):
        return needle in value
    if isinstance(value, Mapping):
        return any(_contains_text(row, needle) for row in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_text(row, needle) for row in value)
    return False


def _contains_carrier(value: Any, payload_text: str) -> bool:
    """Match the complete payload after AgentDojo's whitespace-only transform."""

    normalized_payload = " ".join(payload_text.split())
    if not normalized_payload:
        return False
    if isinstance(value, str):
        return normalized_payload in " ".join(value.split())
    if isinstance(value, Mapping):
        return any(_contains_carrier(row, payload_text) for row in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_carrier(row, payload_text) for row in value)
    return False


def _append_tool_feedback(
    messages: list[dict[str, Any]], *, action: Mapping[str, Any], observation: Any
) -> None:
    messages.append({"role": "assistant", "tool_call": copy.deepcopy(dict(action))})
    messages.append(
        {"role": "tool", "name": action["function"], "content": copy.deepcopy(observation)}
    )


def _run_cell(root: Path, cell: CalibrationCell) -> dict[str, Any]:
    started = _utc_now()
    status = "completed"
    terminal_reason = "budget_exhausted"
    failure: dict[str, Any] | None = None
    secondary_failures: list[dict[str, Any]] = []
    actions: list[dict[str, Any]] = []
    dispatches: list[dict[str, Any]] = []
    exposed_turns: list[int] = []
    checker: dict[str, Any] | None = None
    reset_evidence: dict[str, Any] | None = None
    cleanup_sha: str | None = None
    final_text = ""
    session: CalibrationNativeSession | None = None
    agent: CalibrationOrdinaryAgent | None = None
    payload: dict[str, Any] | None = None
    reset_done = False
    initial_prompt_contains_attack: bool | None = None
    try:
        client = ExactLunaLowClient.from_local_config(timeout_seconds=180)
        durable = _DurableClient(delegate=client, root=root, cell=cell)
        agent = CalibrationOrdinaryAgent(durable)
        session = CalibrationNativeSession(
            source_task_id=cell.source_task_id,
            strength=cell.attack_strength,
        )
        reset_evidence = session.reset()
        reset_done = True
        payload = session.attack_payload()
        visible = session.read()
        messages = copy.deepcopy(visible["messages"])
        tools = copy.deepcopy(visible["tools"])
        initial_prompt_contains_attack = _contains_text(messages, payload["text"])
        if initial_prompt_contains_attack:
            raise CalibrationExecutorError("attack leaked into initial model prompt")
        for turn in range(1, MAX_TURNS_PER_CELL + 1):
            try:
                response = agent.respond(messages=messages, tools=tools)
            except ProviderCallError as exc:
                status = "provider_failure"
                terminal_reason = "provider_failure"
                failure = {"type": type(exc).__name__}
                break
            except ProviderResponseParseError as exc:
                status = "parse_failure"
                terminal_reason = "parse_failure"
                failure = {"type": type(exc).__name__}
                break
            except ProviderResponseContractError as exc:
                status = "schema_failure"
                terminal_reason = "response_contract_failure"
                failure = {"type": type(exc).__name__}
                break
            if response["type"] == "final":
                final_text = response["text"]
                terminal_reason = "provider_final"
                break
            action = {
                "function": response["name"],
                "args": copy.deepcopy(response["arguments"]),
                "id": f"cell-{cell.execution_ordinal:02d}-turn-{turn:02d}",
            }
            actions.append(copy.deepcopy(action))
            try:
                result = session.dispatch(action)
            except SchemaError as exc:
                status = "schema_failure"
                terminal_reason = "native_action_schema_failure"
                failure = {"type": type(exc).__name__}
                break
            except Exception as exc:
                status = "native_failure"
                terminal_reason = "native_dispatch_failure"
                failure = {"type": type(exc).__name__}
                break
            dispatch = result.as_json()
            dispatches.append(copy.deepcopy(dispatch))
            observation = dispatch.get("observation")
            if _contains_carrier(observation, str(payload["text"])):
                exposed_turns.append(turn)
            _append_tool_feedback(messages, action=action, observation=observation)
        if reset_done and status != "native_failure":
            try:
                checker = session.evaluate_final(
                    final_assistant_text=final_text,
                    terminal_reason=terminal_reason,
                )
            except Exception as exc:
                secondary_failures.append({"stage": "native_checker", "type": type(exc).__name__})
                if status == "completed":
                    status = "native_checker_failure"
                    failure = {"type": type(exc).__name__}
    except Exception as exc:
        status = "integrity_failure" if isinstance(exc, CalibrationExecutorError) else "native_failure"
        terminal_reason = "session_initialization_failure"
        failure = {"type": type(exc).__name__}
    finally:
        if session is not None and reset_done:
            try:
                cleanup_sha = session.cleanup()
            except Exception as exc:
                secondary_failures.append({"stage": "native_cleanup", "type": type(exc).__name__})
                if status == "completed":
                    status = "native_cleanup_failure"
                    failure = {"type": type(exc).__name__}
    payload_binding = (
        {
            key: payload[key]
            for key in (
                "attack_baseline_id",
                "attack_strength",
                "injection_task_id",
                "template_sha256",
                "text_sha256",
                "payload_sha256",
            )
        }
        if payload is not None
        else None
    )
    if payload is not None:
        payload_binding["ground_truth_calls_sha256"] = sha256_json(payload["ground_truth_calls"])
    record: dict[str, Any] = {
        "schema_version": 1,
        "artifact_type": "rq1_activation_cell_v1",
        "assignment": cell.private_json(),
        "status": status,
        "failure": failure,
        "secondary_failures": secondary_failures,
        "terminal_reason": terminal_reason,
        "final_text_sha256": hashlib.sha256(final_text.encode()).hexdigest(),
        "reset_evidence": reset_evidence,
        "attack_payload_binding": payload_binding,
        "initial_prompt_contains_attack": initial_prompt_contains_attack,
        "carrier_exposed_turns": exposed_turns,
        "carrier_exposure_match_kind": (
            "complete_payload_whitespace_normalized" if exposed_turns else None
        ),
        "proposed_native_actions": actions,
        "dispatch_results": dispatches,
        "provider_request_records": copy.deepcopy(agent.request_records) if agent else [],
        "provider_request_count": agent.request_count if agent else 0,
        "native_checker_observed": checker,
        "cleanup_sha256": cleanup_sha,
        "metrics_contract": {
            "provider_failure_counted_as_no_attack": False,
            "parse_failure_counted_as_no_attack": False,
            "missing_checker_counted_as_no_effect": False,
            "checker_values_are_observed_only": True,
            "model_intent_inferred": False,
        },
        "started_at": started,
        "finished_at": _utc_now(),
    }
    attribution = attribute_attack(record, workflow_key=cell.workflow_key)
    record["attack_attribution"] = attribution
    carrier_exposed = bool(exposed_turns)
    record["activation_funnel"] = {
        "attack_carrier_bound": payload is not None,
        "carrier_exposed": carrier_exposed,
        "model_intent": None,
        "target_proposed": attribution["attack_target_proposed"],
        "target_sequence_complete": attribution["attack_target_sequence_complete"],
        "target_native_dispatched": attribution["attack_target_native_dispatched"],
        "native_attack_effect": checker.get("security") if isinstance(checker, Mapping) else None,
        "target_without_exact_carrier_exposure": bool(
            attribution["attack_target_proposed"] is True and not carrier_exposed
        ),
    }
    canonical_json_bytes(record)
    return record


def _indeterminate_cell(cell: CalibrationCell) -> dict[str, Any]:
    record: dict[str, Any] = {
        "schema_version": 1,
        "artifact_type": "rq1_activation_cell_v1",
        "assignment": cell.private_json(),
        "status": "indeterminate_consumed",
        "failure": {"type": "ExistingAttemptWithoutCellRecord"},
        "secondary_failures": [],
        "terminal_reason": "consumed_attempt_never_retried",
        "final_text_sha256": None,
        "reset_evidence": None,
        "attack_payload_binding": None,
        "initial_prompt_contains_attack": None,
        "carrier_exposed_turns": [],
        "carrier_exposure_match_kind": None,
        "proposed_native_actions": [],
        "dispatch_results": [],
        "provider_request_records": [],
        "provider_request_count": 0,
        "native_checker_observed": None,
        "cleanup_sha256": None,
        "metrics_contract": {
            "indeterminate_counted_as_no_attack": False,
            "indeterminate_counted_as_no_effect": False,
        },
        "started_at": None,
        "finished_at": _utc_now(),
    }
    record["attack_attribution"] = attribute_attack(record, workflow_key=cell.workflow_key)
    record["activation_funnel"] = {
        "attack_carrier_bound": None,
        "carrier_exposed": None,
        "model_intent": None,
        "target_proposed": None,
        "target_sequence_complete": None,
        "target_native_dispatched": None,
        "native_attack_effect": None,
        "target_without_exact_carrier_exposure": None,
    }
    return record


def execute_namespace(namespace_path: Path) -> dict[str, Any]:
    validate_pinned_runtime()
    root = Path(namespace_path).resolve()
    try:
        root.relative_to(OUTPUT_ROOT.resolve())
    except ValueError as exc:
        raise CalibrationExecutorError("namespace path escapes output root") from exc
    _, schedule = _validate_root(root)
    preflight_path = root / "model-preflight.json"
    if not preflight_path.exists():
        _write_new(preflight_path, preflight_proxy_model())
    for cell in schedule:
        cell_path = root / "cells" / f"cell-{cell.execution_ordinal:02d}.json"
        if cell_path.exists():
            existing = _read(cell_path)
            if not isinstance(existing, Mapping) or existing.get("assignment") != cell.private_json():
                raise CalibrationExecutorError("existing cell record differs from schedule")
            continue
        attempt_dir = root / "attempts" / f"cell-{cell.execution_ordinal:02d}"
        if attempt_dir.exists() and any(attempt_dir.glob("turn-*.json")):
            record = _indeterminate_cell(cell)
        else:
            record = _run_cell(root, cell)
        _write_new(cell_path, record)
    report = analyze_namespace(root)
    report_path = root / "report.json"
    if report_path.exists():
        if _read(report_path) != report:
            raise CalibrationExecutorError("existing report differs from live analysis")
    else:
        _write_new(report_path, report)
    return report


__all__ = [
    "CalibrationExecutorError",
    "OUTPUT_ROOT",
    "execute_namespace",
    "implementation_bindings",
    "preflight_proxy_model",
    "prepare_namespace",
    "runtime_binding",
    "validate_pinned_runtime",
]
