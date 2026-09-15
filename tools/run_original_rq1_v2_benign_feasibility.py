#!/usr/bin/env python3
"""Run the original-RQ1 development adaptive benign-feasibility panel.

This is a development-only, source-native assay.  It asks one fixed target
model to complete the eight already selected public workflows, then applies
the same native utility checkers that passed the fixed-trace parity gate.
It never reads the formal holdout and it does not claim Host-level G3 or A*.
"""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from agentmembrane.host_v2.original_rq1_benign_agent import (
    BenignAgentError,
    DevelopmentBenignAgent,
    PROMPT_VERSION as TEXT_PROMPT_VERSION,
)
from agentmembrane.host_v2.original_rq1_native_tool_agent import (
    NativeToolContentFilterError,
    NativeToolRefusalError,
    NativeToolResponseError,
    PROMPT_VERSION as NATIVE_PROMPT_VERSION,
    SCHEMA_POLICY_VERSION,
    build_native_request,
    parse_native_response,
)
from agentmembrane.host_v2.original_rq1_public_utility import (
    _exact_one,
    _load_official_bfcl_ast_checker,
    _load_official_bfcl_tool_converter,
    _read_jsonl,
    audit_development_utility_bindings,
    load_development_utility_bindings,
)
from agentmembrane.host_v2.schema import canonical_json_bytes, sha256_bytes, sha256_json
from agentmembrane.proxy import Completion, LocalProxyClient, load_local_proxy_settings


V2_ROOT = REPO_ROOT / "experiments/host_boundary_v2/rq1_original_a0_a4_v2"
RUNS_ROOT = V2_ROOT / "runs"
PLAN_PATH = V2_ROOT / "PLAN.md"
PARITY_PATH = V2_ROOT / "assays/g2-public-utility-parity-v1/report.json"
AGENTDOJO_PYTHON = (
    REPO_ROOT
    / "experiments/host_boundary_v2/runtime_envs/"
    "agentdojo-0.1.35-py3123-lock-395e3d0a5921-rq1v4/bin/python"
)
TAU2_PYTHON = (
    REPO_ROOT
    / "experiments/host_boundary_v2/runtime_envs/"
    "tau2-py3123-lock-62d3a8c4807b-knowledge-frozen-v1/bin/python"
)
TAU2_RUNTIME_RECEIPT = (
    REPO_ROOT
    / "experiments/host_boundary_v2/runtime_envs/receipts/"
    "tau2-py3123-lock-62d3a8c4807b-knowledge-frozen-v1.json"
)
AGENTDOJO_CHECKOUT = REPO_ROOT / "data/host_boundary_v2/upstream/agentdojo-v4-runtime"
TAU2_CHECKOUT = REPO_ROOT / "data/host_boundary_v2/upstream/tau2-bench-a2c0247-runtime"
BFCL_DATA = (
    REPO_ROOT
    / "data/host_boundary_v2/upstream/bfcl-f7cf735/"
    "berkeley-function-call-leaderboard/bfcl_eval/data"
)
WORKER_MARKER = "ORIGINAL_RQ1_BENIGN_WORKER_JSON="
MAX_AGENTDOJO_TURNS = 14


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _slug(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "-_." else "-" for ch in value)


def _file_sha(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def _json_safe(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return _json_safe(value.model_dump(mode="json"))
    if isinstance(value, Mapping):
        return {str(key): _json_safe(row) for key, row in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(row) for row in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _write_json(path: Path, value: Any, *, exclusive: bool = False) -> None:
    canonical_json_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = "x" if exclusive else "w"
    with path.open(mode, encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")


class DurableCompletionClient:
    """Append-only reservation/terminal wrapper for a single workflow."""

    def __init__(self, delegate: LocalProxyClient, cell_dir: Path) -> None:
        self.delegate = delegate
        self.cell_dir = cell_dir
        self.calls_made = 0

    def complete(self, **kwargs: Any) -> Completion:
        self.calls_made += 1
        index = self.calls_made
        request = {
            "schema_version": 1,
            "call_index": index,
            "created_at": _utc_now(),
            "model": kwargs["model"],
            "reasoning_effort": kwargs.get("reasoning_effort"),
            "max_completion_tokens": kwargs["max_completion_tokens"],
            "retries": kwargs["retries"],
            "system_sha256": hashlib.sha256(kwargs["system"].encode()).hexdigest(),
            "user_sha256": hashlib.sha256(kwargs["user"].encode()).hexdigest(),
            "request_sha256": sha256_json(
                {
                    "model": kwargs["model"],
                    "reasoning_effort": kwargs.get("reasoning_effort"),
                    "max_completion_tokens": kwargs["max_completion_tokens"],
                    "retries": kwargs["retries"],
                    "system": kwargs["system"],
                    "user": kwargs["user"],
                }
            ),
        }
        prefix = self.cell_dir / "calls" / f"call-{index:02d}"
        _write_json(prefix.with_suffix(".reservation.json"), request, exclusive=True)
        try:
            completion = self.delegate.complete(**kwargs)
        except Exception as exc:
            terminal = {
                **request,
                "finished_at": _utc_now(),
                "status": "provider_failure",
                "error_type": type(exc).__name__,
            }
            _write_json(prefix.with_suffix(".terminal.json"), terminal, exclusive=True)
            raise
        terminal = {
            **request,
            "finished_at": _utc_now(),
            "status": "delivered",
            "resolved_model": completion.model,
            "latency_ms": completion.latency_ms,
            "input_tokens": completion.input_tokens,
            "output_tokens": completion.output_tokens,
            "total_tokens": completion.total_tokens,
            "raw_response": completion.text,
            "raw_response_sha256": hashlib.sha256(completion.text.encode()).hexdigest(),
        }
        _write_json(prefix.with_suffix(".terminal.json"), terminal, exclusive=True)
        return completion


class DurableNativeToolClient:
    """Append-only native tool-call client for a single workflow."""

    def __init__(self, delegate: LocalProxyClient, cell_dir: Path) -> None:
        self.delegate = delegate
        self.cell_dir = cell_dir
        self.calls_made = 0

    def respond(
        self,
        *,
        model: str,
        reasoning_effort: str,
        messages: Sequence[Mapping[str, Any]],
        tools: Sequence[Mapping[str, Any]],
    ) -> Any:
        payload = build_native_request(
            model=model,
            reasoning_effort=reasoning_effort,
            messages=messages,
            tools=tools,
        )
        self.calls_made += 1
        index = self.calls_made
        request = {
            "schema_version": 1,
            "call_index": index,
            "created_at": _utc_now(),
            "request_payload": payload,
            "request_sha256": sha256_json(payload),
        }
        prefix = self.cell_dir / "native-calls" / f"call-{index:02d}"
        _write_json(prefix.with_suffix(".reservation.json"), request, exclusive=True)
        try:
            response = self.delegate._request(
                "chat/completions", method="POST", payload=payload
            )
        except Exception as exc:
            terminal = {
                **request,
                "finished_at": _utc_now(),
                "status": "provider_failure",
                "error_type": type(exc).__name__,
                "http_status": getattr(exc, "code", None),
            }
            _write_json(prefix.with_suffix(".terminal.json"), terminal, exclusive=True)
            raise
        terminal = {
            **request,
            "finished_at": _utc_now(),
            "status": "delivered",
            "provider_response": _json_safe(response),
            "provider_response_sha256": sha256_json(_json_safe(response)),
        }
        _write_json(prefix.with_suffix(".terminal.json"), terminal, exclusive=True)
        allowed = {
            str(tool["function"]["name"]): copy.deepcopy(
                tool["function"]["parameters"]
            )
            for tool in payload["tools"]
            if isinstance(tool.get("function"), Mapping)
        }
        return parse_native_response(
            response,
            expected_model=model,
            allowed_tool_schemas=allowed,
        )


def _source_schedule(stage: str) -> list[dict[str, Any]]:
    rows = [binding.as_json() for binding in load_development_utility_bindings(REPO_ROOT)]
    if stage == "smoke":
        wanted = {
            "multiple_46",
            "banking:user_task_11",
            "tau2:airline:19",
        }
        rows = [row for row in rows if row["source_task_id"] in wanted]
    for index, row in enumerate(rows, start=1):
        row["ordinal"] = index
        row["cell_id"] = f"cell-{index:02d}-{_slug(row['source_task_id'])}"
    expected = 3 if stage == "smoke" else 8
    if len(rows) != expected:
        raise RuntimeError(f"{stage} schedule must contain exactly {expected} workflows")
    return rows


def _cell_dir(run_dir: Path, row: Mapping[str, Any]) -> Path:
    return run_dir / "cells" / str(row["cell_id"])


def _durable_call_counts(cell_dir: Path, *, agent_protocol: str) -> dict[str, int]:
    subdir = "native-calls" if agent_protocol == "native_tools" else "calls"
    terminals = sorted((cell_dir / subdir).glob("*.terminal.json"))
    statuses = [
        json.loads(path.read_text(encoding="utf-8")).get("status")
        for path in terminals
    ]
    return {
        "attempted": len(terminals),
        "delivered": sum(status == "delivered" for status in statuses),
        "provider_failures": sum(
            status == "provider_failure" for status in statuses
        ),
    }


def _fresh_agent(
    *, run_dir: Path, row: Mapping[str, Any], model: str, reasoning_effort: str
) -> tuple[DevelopmentBenignAgent, DurableCompletionClient]:
    delegate = LocalProxyClient.from_local_config(timeout_seconds=240.0)
    durable = DurableCompletionClient(delegate, _cell_dir(run_dir, row))
    agent = DevelopmentBenignAgent(
        durable,
        model=model,
        reasoning_effort=reasoning_effort,  # type: ignore[arg-type]
    )
    return agent, durable


def _fresh_native_client(
    *, run_dir: Path, row: Mapping[str, Any]
) -> DurableNativeToolClient:
    delegate = LocalProxyClient.from_local_config(timeout_seconds=240.0)
    return DurableNativeToolClient(delegate, _cell_dir(run_dir, row))


def _bfcl_tools(
    task: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    converter, mapping, model_style = _load_official_bfcl_tool_converter(REPO_ROOT)
    source_functions = copy.deepcopy(task["function"])
    converted = converter(source_functions, mapping, model_style)
    if len(converted) != len(source_functions):
        raise RuntimeError("BFCL tool converter changed the function count")
    alias_map = {
        str(source["name"]): str(wire["function"]["name"])
        for source, wire in zip(source_functions, converted, strict=True)
    }
    wire_names = list(alias_map.values())
    if len(set(wire_names)) != len(wire_names):
        raise RuntimeError("BFCL dotted-name conversion produced an alias collision")
    expected_names = [str(row["name"]).replace(".", "_") for row in source_functions]
    if wire_names != expected_names:
        raise RuntimeError("BFCL tool aliases differ from the frozen converter rule")
    tools = converted
    # The native request validator checks the provider's exact name grammar and
    # every converted schema before any provider reservation is written.
    build_native_request(
        model="preflight-only",
        reasoning_effort="low",
        messages=[{"role": "user", "content": "preflight"}],
        tools=tools,
    )
    return tools, alias_map


def _run_bfcl_cell(
    *,
    run_dir: Path,
    row: Mapping[str, Any],
    model: str,
    reasoning_effort: str,
    agent_protocol: str,
) -> dict[str, Any]:
    source_task_id = str(row["source_task_id"])
    filename = {
        "irrelevance_148": "BFCL_v4_irrelevance.json",
        "multiple_46": "BFCL_v4_multiple.json",
        "simple_python_339": "BFCL_v4_simple_python.json",
    }[source_task_id]
    task = _exact_one(_read_jsonl(BFCL_DATA / filename), id=source_task_id)
    tools, alias_map = _bfcl_tools(task)
    agent = None
    if agent_protocol == "native_tools":
        durable: Any = _fresh_native_client(run_dir=run_dir, row=row)
    else:
        agent, durable = _fresh_agent(
            run_dir=run_dir, row=row, model=model, reasoning_effort=reasoning_effort
        )
    started = _utc_now()
    status = "completed"
    failure = None
    response: dict[str, Any] | None = None
    audit: dict[str, Any] | None = None
    try:
        if agent_protocol == "native_tools":
            turn = durable.respond(
                model=model,
                reasoning_effort=reasoning_effort,
                messages=task["question"][0],
                tools=tools,
            )
        else:
            assert agent is not None
            turn = agent.respond(messages=task["question"][0], tools=tools)
        response, audit = turn.value, turn.audit
    except NativeToolRefusalError as exc:
        status = "model_refusal"
        failure = {"type": type(exc).__name__}
    except NativeToolContentFilterError as exc:
        status = "content_filter"
        failure = {"type": type(exc).__name__}
    except (BenignAgentError, NativeToolResponseError) as exc:
        status = "model_or_parse_failure"
        failure = {"type": type(exc).__name__}
    except Exception as exc:
        status = "provider_failure"
        failure = {"type": type(exc).__name__}

    checker_detail: dict[str, Any]
    utility = False
    if response is None:
        checker_detail = {"valid": False, "error_type": "no_parsed_response"}
    elif source_task_id.startswith("irrelevance_"):
        utility = response["type"] == "final"
        checker_detail = {
            "valid": utility,
            "mode": "source_faithful_official_no_valid_call_rule",
        }
    else:
        checker, language = _load_official_bfcl_ast_checker(REPO_ROOT)
        answer = _exact_one(
            _read_jsonl(BFCL_DATA / "possible_answer" / filename), id=source_task_id
        )["ground_truth"]
        if response["type"] == "tool_action":
            model_output = [
                {response["name"].replace(".", "_"): response["arguments"]}
            ]
        else:
            model_output = []
        checker_detail = checker(
            task["function"],
            model_output,
            answer,
            language.PYTHON,
            source_task_id.rsplit("_", 1)[0],
            "original-rq1-openai-fc",
        )
        utility = checker_detail.get("valid") is True
    call_counts = _durable_call_counts(
        _cell_dir(run_dir, row), agent_protocol=agent_protocol
    )
    result = {
        "schema_version": 1,
        "scientific_status": "nonclaim_development_source_native_benign",
        "source_family": "BFCL",
        "source_task_id": source_task_id,
        "cell_id": row["cell_id"],
        "status": status,
        "failure": failure,
        "model_response": response,
        "model_audit": audit,
        "bfcl_source_to_wire_alias": alias_map,
        "agent_protocol": agent_protocol,
        "target_model_calls": call_counts["attempted"],
        "target_model_delivered_turns": call_counts["delivered"],
        "target_model_schema_valid_turns": int(audit is not None),
        "target_model_provider_failures": call_counts["provider_failures"],
        "user_simulator_calls": 0,
        "native_utility": utility,
        "native_checker_detail": _json_safe(checker_detail),
        "formal_holdout_touched": False,
        "started_at": started,
        "finished_at": _utc_now(),
    }
    _write_json(_cell_dir(run_dir, row) / "result.json", result, exclusive=True)
    return result


def _agentdojo_check(
    task: Any,
    suite: Any,
    pre_environment: Any,
    environment: Any,
    actions: Sequence[Any],
    final_text: str,
) -> bool:
    content = [{"type": "text", "content": final_text}]
    value = suite._check_user_task_utility(
        task, content, pre_environment, environment, tuple(actions)
    )
    if type(value) is not bool:
        raise RuntimeError("AgentDojo native utility checker returned non-bool")
    return value


def _run_agentdojo_cell(
    *,
    run_dir: Path,
    row: Mapping[str, Any],
    model: str,
    reasoning_effort: str,
    agent_protocol: str,
) -> dict[str, Any]:
    from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime
    from agentdojo.task_suite.load_suites import get_suite

    source_task_id = str(row["source_task_id"])
    domain, task_id = source_task_id.split(":", 1)
    suite = get_suite("v1", domain)
    task = suite.get_user_task_by_id(task_id)
    environment = suite.load_and_inject_default_environment({})
    environment = task.init_environment(environment)
    pre_environment = copy.deepcopy(environment)
    runtime = FunctionsRuntime(suite.tools)
    tools = [
        {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description,
                "parameters": _json_safe(tool.parameters.model_json_schema()),
            },
        }
        for tool in suite.tools
    ]
    messages: list[dict[str, Any]] = [
        {"role": "user", "content": str(task.PROMPT)}
    ]
    agent = None
    if agent_protocol == "native_tools":
        durable: Any = _fresh_native_client(run_dir=run_dir, row=row)
    else:
        agent, durable = _fresh_agent(
            run_dir=run_dir, row=row, model=model, reasoning_effort=reasoning_effort
        )
    started = _utc_now()
    status = "completed"
    failure = None
    actions: list[Any] = []
    action_records: list[dict[str, Any]] = []
    turn_audits: list[dict[str, Any]] = []
    final_text = ""
    terminal_reason = "turn_budget_exhausted"
    for turn_index in range(1, MAX_AGENTDOJO_TURNS + 1):
        try:
            if agent_protocol == "native_tools":
                turn = durable.respond(
                    model=model,
                    reasoning_effort=reasoning_effort,
                    messages=messages,
                    tools=tools,
                )
            else:
                assert agent is not None
                turn = agent.respond(messages=messages, tools=tools)
        except NativeToolRefusalError as exc:
            status = "model_refusal"
            failure = {"type": type(exc).__name__, "turn": turn_index}
            terminal_reason = "model_refusal"
            break
        except NativeToolContentFilterError as exc:
            status = "content_filter"
            failure = {"type": type(exc).__name__, "turn": turn_index}
            terminal_reason = "content_filter"
            break
        except (BenignAgentError, NativeToolResponseError) as exc:
            status = "model_or_parse_failure"
            failure = {"type": type(exc).__name__, "turn": turn_index}
            terminal_reason = "model_or_parse_failure"
            break
        except Exception as exc:
            status = "provider_failure"
            failure = {"type": type(exc).__name__, "turn": turn_index}
            terminal_reason = "provider_failure"
            break
        turn_audits.append(turn.audit)
        response = turn.value
        if response["type"] == "final":
            final_text = response["text"]
            terminal_reason = "provider_final"
            break
        call = FunctionCall(
            function=response["name"],
            args=copy.deepcopy(response["arguments"]),
            id=response.get("call_id")
            or f"{row['cell_id']}-turn-{turn_index:02d}",
        )
        result, error = runtime.run_function(
            environment,
            call.function,
            dict(call.args),
            raise_on_error=False,
        )
        actions.append(call)
        record = {
            "turn": turn_index,
            "function": call.function,
            "arguments": _json_safe(call.args),
            "result": _json_safe(result),
            "error": error,
        }
        action_records.append(record)
        if agent_protocol == "native_tools":
            messages.append(
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": call.id,
                            "type": "function",
                            "function": {
                                "name": call.function,
                                "arguments": json.dumps(
                                    _json_safe(call.args),
                                    ensure_ascii=False,
                                    sort_keys=True,
                                ),
                            },
                        }
                    ],
                }
            )
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call.id,
                    "name": call.function,
                    "content": json.dumps(
                        _json_safe(error if error is not None else result),
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                }
            )
        else:
            messages.append(
                {
                    "role": "assistant",
                    "tool_call": {
                        "name": call.function,
                        "arguments": _json_safe(call.args),
                    },
                }
            )
            messages.append(
                {
                    "role": "tool",
                    "name": call.function,
                    "content": _json_safe(error if error is not None else result),
                }
            )
    utility = _agentdojo_check(
        task, suite, pre_environment, environment, actions, final_text
    )
    call_counts = _durable_call_counts(
        _cell_dir(run_dir, row), agent_protocol=agent_protocol
    )
    result = {
        "schema_version": 1,
        "scientific_status": "nonclaim_development_source_native_benign",
        "source_family": "AgentDojo",
        "source_task_id": source_task_id,
        "cell_id": row["cell_id"],
        "status": status,
        "failure": failure,
        "terminal_reason": terminal_reason,
        "agent_protocol": agent_protocol,
        "turn_count": len(turn_audits),
        "turn_audits": turn_audits,
        "native_actions": action_records,
        "final_text": final_text,
        "target_model_calls": call_counts["attempted"],
        "target_model_delivered_turns": call_counts["delivered"],
        "target_model_schema_valid_turns": len(turn_audits),
        "target_model_provider_failures": call_counts["provider_failures"],
        "user_simulator_calls": 0,
        "native_utility": utility,
        "native_checker_detail": {
            "checker": "TaskSuite._check_user_task_utility",
            "action_count": len(actions),
        },
        "formal_holdout_touched": False,
        "started_at": started,
        "finished_at": _utc_now(),
    }
    _write_json(_cell_dir(run_dir, row) / "result.json", result, exclusive=True)
    return result


def _tau2_message_summary(message: Any) -> dict[str, Any]:
    calls = getattr(message, "tool_calls", None) or []
    return {
        "role": getattr(message, "role", None),
        "content": getattr(message, "content", None),
        "tool_calls": [
            {
                "id": call.id,
                "name": call.name,
                "arguments": _json_safe(call.arguments),
                "requestor": _json_safe(call.requestor),
            }
            for call in calls
        ],
        "error": getattr(message, "error", None),
    }


def _run_tau2_cell(
    *,
    run_dir: Path,
    row: Mapping[str, Any],
    model: str,
    reasoning_effort: str,
    user_model: str,
) -> dict[str, Any]:
    import importlib

    from tau2.agent.llm_agent import LLMAgent
    from tau2.evaluator.evaluator import EvaluationType
    from tau2.orchestrator.orchestrator import Orchestrator
    from tau2.runner.simulation import run_simulation
    from tau2.user.user_simulator import UserSimulator
    from tau2.utils.llm_utils import set_llm_log_dir, set_llm_log_mode

    source_task_id = str(row["source_task_id"])
    _, domain, task_id = source_task_id.split(":", 2)
    module = importlib.import_module(f"tau2.domains.{domain}.environment")
    task = next(task for task in module.get_tasks(None) if str(task.id) == task_id)
    env_kwargs: dict[str, Any] = {}
    if domain == "banking_knowledge":
        env_kwargs = {"retrieval_variant": "bm25", "task": task}
    environment = module.get_environment(solo_mode=False, **env_kwargs)

    base_url, api_key, _ = load_local_proxy_settings()
    os.environ["OPENAI_API_BASE"] = base_url
    os.environ["OPENAI_API_KEY"] = api_key
    cell_dir = _cell_dir(run_dir, row)
    log_dir = cell_dir / "tau2-llm-calls"
    set_llm_log_dir(log_dir)
    set_llm_log_mode("all")

    common_args = {
        "temperature": 0,
        "reasoning_effort": reasoning_effort,
        "num_retries": 0,
        "timeout": 240,
        "max_completion_tokens": 1800,
    }
    agent = LLMAgent(
        tools=environment.get_tools(),
        domain_policy=environment.get_policy(),
        llm=f"openai/{model}",
        llm_args=common_args,
    )
    try:
        user_tools = environment.get_user_tools(include=task.user_tools) or None
    except Exception:
        user_tools = None
    user = UserSimulator(
        llm=f"openai/{user_model}",
        instructions=str(task.user_scenario),
        tools=user_tools,
        llm_args={
            "temperature": 0,
            "reasoning_effort": "low",
            "num_retries": 0,
            "timeout": 240,
            "max_completion_tokens": 1200,
        },
    )
    orchestrator = Orchestrator(
        domain=domain,
        agent=agent,
        user=user,
        environment=environment,
        task=task,
        max_steps=40,
        max_errors=5,
        seed=0,
        validate_communication=True,
        timeout=900,
    )
    started = _utc_now()
    status = "completed"
    failure = None
    simulation = None
    try:
        simulation = run_simulation(
            orchestrator,
            evaluation_type=EvaluationType.ALL,
            env_kwargs=env_kwargs,
        )
    except Exception as exc:
        status = "native_or_model_failure"
        failure = {"type": type(exc).__name__}

    call_logs = sorted(log_dir.glob("*.json")) if log_dir.exists() else []
    agent_calls = sum("_agent_response_" in path.name for path in call_logs)
    user_calls = sum("_user_simulator_response_" in path.name for path in call_logs)
    if simulation is None:
        reward_info = None
        utility = False
        termination_reason = "exception"
        messages: list[dict[str, Any]] = []
    else:
        reward_info = _json_safe(simulation.reward_info)
        utility = simulation.reward_info is not None and simulation.reward_info.reward == 1.0
        termination_reason = str(simulation.termination_reason)
        messages = [_tau2_message_summary(message) for message in simulation.messages]
    result = {
        "schema_version": 1,
        "scientific_status": "nonclaim_development_source_native_benign",
        "source_family": "tau2",
        "source_task_id": source_task_id,
        "cell_id": row["cell_id"],
        "status": status,
        "failure": failure,
        "adapter_variant": "bm25" if domain == "banking_knowledge" else None,
        "target_model": model,
        "user_simulator_model": user_model,
        "target_model_calls": agent_calls,
        "user_simulator_calls": user_calls,
        "termination_reason": termination_reason,
        "messages": messages,
        "native_utility": utility,
        "native_checker_detail": reward_info,
        "tau2_llm_log_count": len(call_logs),
        "formal_holdout_touched": False,
        "started_at": started,
        "finished_at": _utc_now(),
    }
    _write_json(cell_dir / "result.json", result, exclusive=True)
    return result


def _worker_rows(run_dir: Path, family: str) -> list[dict[str, Any]]:
    schedule = json.loads((run_dir / "schedule.json").read_text(encoding="utf-8"))
    return [row for row in schedule if row["source_family"] == family]


def _run_family_worker(
    *,
    family: str,
    run_dir: Path,
    model: str,
    reasoning_effort: str,
    user_model: str,
    agent_protocol: str,
) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for row in _worker_rows(run_dir, family):
        if family == "BFCL":
            result = _run_bfcl_cell(
                run_dir=run_dir,
                row=row,
                model=model,
                reasoning_effort=reasoning_effort,
                agent_protocol=agent_protocol,
            )
        elif family == "AgentDojo":
            result = _run_agentdojo_cell(
                run_dir=run_dir,
                row=row,
                model=model,
                reasoning_effort=reasoning_effort,
                agent_protocol=agent_protocol,
            )
        elif family == "tau2":
            result = _run_tau2_cell(
                run_dir=run_dir,
                row=row,
                model=model,
                reasoning_effort=reasoning_effort,
                user_model=user_model,
            )
        else:
            raise ValueError(family)
        results.append(result)
        print(
            f"[{family}] {row['source_task_id']} utility={result['native_utility']} "
            f"target_calls={result['target_model_calls']}",
            flush=True,
        )
    return {
        "family": family,
        "result_count": len(results),
        "passed": sum(row["native_utility"] is True for row in results),
    }


def _subprocess_worker(
    *,
    family: str,
    run_dir: Path,
    model: str,
    reasoning_effort: str,
    user_model: str,
    agent_protocol: str,
) -> dict[str, Any]:
    if family == "AgentDojo":
        python = AGENTDOJO_PYTHON
        paths = [REPO_ROOT, AGENTDOJO_CHECKOUT / "src"]
    elif family == "tau2":
        python = TAU2_PYTHON
        paths = [REPO_ROOT]
    else:
        raise ValueError(family)
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(str(path) for path in paths)
    process = subprocess.run(
        [
            str(python),
            str(Path(__file__).resolve()),
            "--worker",
            family,
            "--run-dir",
            str(run_dir),
            "--model",
            model,
            "--reasoning-effort",
            reasoning_effort,
            "--user-model",
            user_model,
            "--agent-protocol",
            agent_protocol,
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=2400,
    )
    if process.stdout:
        print(process.stdout, end="", flush=True)
    if process.returncode != 0:
        raise RuntimeError(
            f"{family} worker failed ({process.returncode}):\n{process.stderr[-6000:]}"
        )
    markers = [
        line[len(WORKER_MARKER) :]
        for line in process.stdout.splitlines()
        if line.startswith(WORKER_MARKER)
    ]
    if len(markers) != 1:
        raise RuntimeError(f"{family} worker emitted no unique terminal marker")
    return json.loads(markers[0])


def _implementation_files() -> dict[str, str]:
    paths = (
        Path(__file__).resolve(),
        REPO_ROOT / "agentmembrane/host_v2/original_rq1_benign_agent.py",
        REPO_ROOT / "agentmembrane/host_v2/original_rq1_native_tool_agent.py",
        REPO_ROOT / "agentmembrane/host_v2/original_rq1_public_utility.py",
        REPO_ROOT / "agentmembrane/host_v2/original_rq1_activation.py",
        PLAN_PATH,
        PARITY_PATH,
    )
    return {str(path.relative_to(REPO_ROOT)): _file_sha(path) for path in paths}


def _report_markdown(manifest: Mapping[str, Any], summary: Mapping[str, Any]) -> str:
    lines = [
        "# Original RQ1 v2 adaptive benign feasibility",
        "",
        f"Run: `{manifest['run_id']}`  ",
        f"Target model: `{manifest['target_model']}` / `{manifest['reasoning_effort']}`  ",
        f"Passed: **{summary['passed_workflows']}/{summary['scheduled_workflows']}**",
        "",
        "| Source | Task | Native utility | Target calls | User-sim calls |",
        "|---|---|---:|---:|---:|",
    ]
    for row in summary["rows"]:
        lines.append(
            f"| {row['source_family']} | `{row['source_task_id']}` | "
            f"{row['native_utility']} | {row['target_model_calls']} | "
            f"{row['user_simulator_calls']} |"
        )
    lines.extend(
        [
            "",
            "This is source-native development evidence only. It tests whether the "
            "fixed model can complete the public workflows, but it is not yet the "
            "condition-blind Host M0/M1 bridge, the five-level utility curve, G3, or A*.",
            "",
        ]
    )
    return "\n".join(lines)


def _run_controller(args: argparse.Namespace) -> int:
    run_id = args.run_id or (
        f"original-rq1-v2-benign-{args.stage}-{_slug(args.model)}-"
        f"{_slug(args.reasoning_effort)}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    )
    run_dir = (RUNS_ROOT / run_id).resolve()
    if run_dir.exists() and any(run_dir.iterdir()):
        raise SystemExit(f"run directory is not empty: {run_dir}")
    run_dir.mkdir(parents=True, exist_ok=True)
    schedule = _source_schedule(args.stage)
    binding_audit = audit_development_utility_bindings(REPO_ROOT)
    parity = json.loads(PARITY_PATH.read_text(encoding="utf-8"))
    implementation_files = _implementation_files()
    manifest = {
        "schema_version": 1,
        "artifact_type": "original_rq1_v2_development_adaptive_benign_feasibility",
        "run_id": run_id,
        "created_at": _utc_now(),
        "stage": args.stage,
        "dry_run": args.dry_run,
        "scientific_status": "nonclaim_development_source_native_benign",
        "population_claim_eligible": False,
        "target_model": args.model,
        "reasoning_effort": args.reasoning_effort,
        "user_simulator_model": args.user_model,
        "provider_route": "local-cli-proxy",
        "request_retries": 0,
        "target_prompt_version": (
            NATIVE_PROMPT_VERSION
            if args.agent_protocol == "native_tools"
            else TEXT_PROMPT_VERSION
        ),
        "agent_protocol": args.agent_protocol,
        "native_schema_policy_version": (
            SCHEMA_POLICY_VERSION if args.agent_protocol == "native_tools" else None
        ),
        "formal_holdout_loaded": False,
        "scheduled_workflows": len(schedule),
        "source_native_only": True,
        "host_m0_m1_bridge_included": False,
        "binding_audit_sha256": sha256_json(binding_audit),
        "parity_gate_sha256": _file_sha(PARITY_PATH),
        "parity_gate_passed": parity.get("passed") is True,
        "implementation_files": implementation_files,
        "implementation_sha256": sha256_json(implementation_files),
    }
    _write_json(run_dir / "schedule.json", schedule, exclusive=True)
    _write_json(run_dir / "manifest.json", manifest, exclusive=True)
    if args.dry_run:
        print(f"DRY RUN {run_id}: {len(schedule)} development workflows")
        return 0

    client = LocalProxyClient.from_local_config(timeout_seconds=30.0)
    available = client.list_models()
    required = {args.model, args.user_model}
    if not required <= set(available):
        raise RuntimeError(f"required models unavailable: {sorted(required - set(available))}")
    _write_json(
        run_dir / "route-preflight.json",
        {
            "checked_at": _utc_now(),
            "required_models": sorted(required),
            "required_models_available": True,
            "available_model_ids_sha256": sha256_json(sorted(available)),
            "model_generation_calls": 0,
        },
        exclusive=True,
    )

    print(
        f"RUN {run_id} target={args.model}/{args.reasoning_effort} "
        f"workflows={len(schedule)}",
        flush=True,
    )
    family_summaries: list[dict[str, Any]] = []
    if any(row["source_family"] == "BFCL" for row in schedule):
        family_summaries.append(
            _run_family_worker(
                family="BFCL",
                run_dir=run_dir,
                model=args.model,
                reasoning_effort=args.reasoning_effort,
                user_model=args.user_model,
                agent_protocol=args.agent_protocol,
            )
        )
    for family in ("AgentDojo", "tau2"):
        if any(row["source_family"] == family for row in schedule):
            family_summaries.append(
                _subprocess_worker(
                    family=family,
                    run_dir=run_dir,
                    model=args.model,
                    reasoning_effort=args.reasoning_effort,
                    user_model=args.user_model,
                    agent_protocol=args.agent_protocol,
                )
            )

    results = [
        json.loads((_cell_dir(run_dir, row) / "result.json").read_text(encoding="utf-8"))
        for row in schedule
    ]
    passed = sum(row["native_utility"] is True for row in results)
    target_calls = sum(int(row["target_model_calls"]) for row in results)
    user_calls = sum(int(row["user_simulator_calls"]) for row in results)
    required_passes = 2 if args.stage == "smoke" else 7
    summary = {
        "schema_version": 1,
        "scientific_status": "nonclaim_development_source_native_benign",
        "scheduled_workflows": len(results),
        "passed_workflows": passed,
        "pass_rate": passed / len(results),
        "target_model_calls": target_calls,
        "user_simulator_calls": user_calls,
        "source_native_feasibility_threshold": {
            "required_passes": required_passes,
            "met": passed >= required_passes,
        },
        "host_g3_passed": False,
        "host_g3_reason": "condition-blind Host M0/M1 bridge not included",
        "formal_holdout_touched": False,
        "family_summaries": family_summaries,
        "rows": results,
    }
    _write_json(run_dir / "results.json", summary, exclusive=True)
    (run_dir / "REPORT.md").write_text(
        _report_markdown(manifest, summary), encoding="utf-8"
    )
    artifacts = {}
    for path in sorted(run_dir.rglob("*")):
        if path.is_file() and path.name != "integrity.json":
            artifacts[str(path.relative_to(run_dir))] = _file_sha(path)
    integrity = {
        "schema_version": 1,
        "run_id": run_id,
        "complete": len(results) == len(schedule),
        "scheduled_cell_ids_match": {row["cell_id"] for row in schedule}
        == {row["cell_id"] for row in results},
        "no_duplicate_cell_ids": len({row["cell_id"] for row in results})
        == len(results),
        "model_calls_accounted": target_calls
        == sum(
            1
            for path in run_dir.glob("cells/*/calls/*.terminal.json")
            if json.loads(path.read_text(encoding="utf-8")).get("status")
            in {"delivered", "provider_failure"}
        )
        + sum(
            1
            for path in run_dir.glob("cells/*/native-calls/*.terminal.json")
            if json.loads(path.read_text(encoding="utf-8")).get("status")
            in {"delivered", "provider_failure"}
        )
        + sum(
            1
            for path in run_dir.glob("cells/*/tau2-llm-calls/*_agent_response_*.json")
        ),
        "formal_holdout_touched": False,
        "artifacts": artifacts,
    }
    _write_json(run_dir / "integrity.json", integrity, exclusive=True)
    print(
        f"DONE {run_id} passed={passed}/{len(results)} "
        f"source_native_threshold={passed >= required_passes}",
        flush=True,
    )
    return 0 if all(
        [
            integrity["complete"],
            integrity["scheduled_cell_ids_match"],
            integrity["no_duplicate_cell_ids"],
            integrity["model_calls_accounted"],
        ]
    ) else 2


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", choices=("smoke", "full"), default="smoke")
    parser.add_argument("--model", default="gpt-5.6-luna")
    parser.add_argument("--reasoning-effort", default="low")
    parser.add_argument("--user-model", default="gpt-5.6-sol")
    parser.add_argument(
        "--agent-protocol",
        choices=("native_tools", "text_planner"),
        default="native_tools",
    )
    parser.add_argument("--run-id")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--worker", choices=("AgentDojo", "tau2"))
    parser.add_argument("--run-dir", type=Path)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    if args.worker:
        if args.run_dir is None:
            raise SystemExit("--run-dir is required for workers")
        value = _run_family_worker(
            family=args.worker,
            run_dir=args.run_dir.resolve(),
            model=args.model,
            reasoning_effort=args.reasoning_effort,
            user_model=args.user_model,
            agent_protocol=args.agent_protocol,
        )
        print(WORKER_MARKER + json.dumps(value, sort_keys=True))
        return 0
    return _run_controller(args)


if __name__ == "__main__":
    raise SystemExit(main())
