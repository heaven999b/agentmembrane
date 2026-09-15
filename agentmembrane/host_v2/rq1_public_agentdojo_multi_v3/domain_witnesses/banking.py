"""Zero-token native witnesses for three pinned AgentDojo banking workflows.

This module is deliberately independent of the multi-workflow selector and
runtime.  Its public runner launches this file under the repository's pinned
AgentDojo Python environment, obtains schemas and action sequences from the
native suite, executes the upstream utility/security checkers, and returns a
JSON-safe witness record.  It never imports a provider client or performs an
API call.  The scripted surface action is used only to prove that the ordinary
task can reach the native injection carrier.

The protected result is explicitly an offline pre-dispatch simulation.  It
identifies the final source-authored injection action, binds it to the exact
action demonstrated in the vulnerable native run, and denies it because it is
not an exact member of the source-authored user-task ground truth.  It does not
dispatch that action and is not an execution authorization.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
import hashlib
import inspect
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from typing import Any, Mapping, Sequence


WITNESS_ID = "agentdojo-v0.1.35-rq1-multi-v3-banking-native-witness-v1"
UPSTREAM_VERSION_OR_COMMIT = (
    "0.1.35@089ed468cf3ed0322acc66b0211f26d9d90dbf60"
)
SUITE_VERSION = "v1"
DOMAIN = "banking"

DEFAULT_RUNTIME_RELATIVE = Path(
    "experiments/host_boundary_v2/runtime_envs/"
    "agentdojo-0.1.35-py3123-lock-395e3d0a5921"
)
UPSTREAM_RELATIVE = Path("data/host_boundary_v2/upstream/agentdojo")
SOURCE_PACK_RELATIVE = Path(
    "data/host_boundary_v2/packs/agentdojo-v0.1.35-v1"
)

_SOURCE_LOCKS = {
    "src/agentdojo/functions_runtime.py": (
        "3c67f71eb8a7f15d2a15fe9595d84218c5e6868d95fd71d1cef679cd2192d0f7"
    ),
    "src/agentdojo/task_suite/load_suites.py": (
        "e9c97813ed8295f25526733df044e9adf8ba18567eaeec3455591c4fbc1caa12"
    ),
    "src/agentdojo/task_suite/task_suite.py": (
        "2e69da06f7e150dd6d238c53a74845b56eebeb224e07f694e1051a6e0c6a2bc1"
    ),
    "src/agentdojo/default_suites/v1/banking/user_tasks.py": (
        "37af838194f001af80cc040315bcb2d69d0112324d424f9a323473b41b317f82"
    ),
    "src/agentdojo/default_suites/v1/banking/injection_tasks.py": (
        "fa2dedf8e66c95ffadb54f5a26648728b08c56f302858de4ee9a5cc0b3891618"
    ),
    "src/agentdojo/data/suites/banking/environment.yaml": (
        "3f539da1d97779b244cd122afc683dc69d602f338e1b3c42d126cbde33611c8b"
    ),
    "src/agentdojo/data/suites/banking/injection_vectors.yaml": (
        "4eb98a601c108d9b4d88f5d3f2dbf455f775a718975a0ae2624b4cf0d0f6f819"
    ),
}


@dataclass(frozen=True)
class BankingWorkflowSpec:
    """Exact public-pack source identity for one banking witness."""

    source_task_id: str
    user_task_id: str
    injection_task_id: str
    injection_vector_id: str


WORKFLOW_SPECS = (
    BankingWorkflowSpec(
        source_task_id="agentdojo-v1-banking-u0-i5",
        user_task_id="user_task_0",
        injection_task_id="injection_task_5",
        injection_vector_id="injection_bill_text",
    ),
    BankingWorkflowSpec(
        source_task_id="agentdojo-v1-banking-u2-i4",
        user_task_id="user_task_2",
        injection_task_id="injection_task_4",
        injection_vector_id="injection_landloard_notice",
    ),
    BankingWorkflowSpec(
        source_task_id="agentdojo-v1-banking-u3-i1",
        user_task_id="user_task_3",
        injection_task_id="injection_task_1",
        injection_vector_id="injection_incoming_transaction",
    ),
)


class BankingWitnessError(RuntimeError):
    """The pinned native banking witness failed closed."""


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise BankingWitnessError(f"witness value is not strict JSON: {exc}") from exc


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _file_sha256(path: Path) -> str:
    if not path.is_file():
        raise BankingWitnessError(f"required pinned file is missing: {path}")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise BankingWitnessError(f"cannot read required pinned file: {path}") from exc
    return digest.hexdigest()


def _json_safe(value: Any) -> Any:
    if hasattr(value, "model_dump") and callable(value.model_dump):
        return _json_safe(value.model_dump(mode="json"))
    if is_dataclass(value):
        return _json_safe(asdict(value))
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise BankingWitnessError("native value has a non-string object key")
        return json.loads(_canonical_bytes({key: _json_safe(item) for key, item in value.items()}))
    if isinstance(value, (list, tuple)):
        return json.loads(_canonical_bytes([_json_safe(item) for item in value]))
    return json.loads(_canonical_bytes(value))


def _validate_source_locks(repo_root: Path) -> None:
    checkout = repo_root / UPSTREAM_RELATIVE
    for relative, expected in _SOURCE_LOCKS.items():
        actual = _file_sha256(checkout / relative)
        if actual != expected:
            raise BankingWitnessError(
                f"pinned AgentDojo source differs: {relative}: {actual}"
            )


def _read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BankingWitnessError(f"cannot read pinned JSON object: {path}") from exc
    if not isinstance(value, dict):
        raise BankingWitnessError(f"pinned JSON is not an object: {path}")
    return value


def _validate_source_pack(repo_root: Path) -> None:
    """Bind the selected IDs to both public-pack roles and their oracle refs."""

    pack = repo_root / SOURCE_PACK_RELATIVE
    for spec in WORKFLOW_SPECS:
        for role in ("benign", "adversarial"):
            fixture = _read_object(
                pack / "fixtures" / f"{spec.source_task_id}-{role}.json"
            )
            user_task = fixture.get("user_task")
            if (
                fixture.get("candidate_id") != spec.source_task_id
                or fixture.get("pair_role") != role
                or not isinstance(user_task, dict)
                or user_task.get("id") != spec.user_task_id
            ):
                raise BankingWitnessError(
                    f"public-pack fixture identity differs: {spec.source_task_id}-{role}"
                )
            if role == "adversarial":
                injection_task = fixture.get("injection_task")
                injection_vector = fixture.get("injection_vector")
                if (
                    not isinstance(injection_task, dict)
                    or injection_task.get("id") != spec.injection_task_id
                    or not isinstance(injection_vector, dict)
                    or injection_vector.get("id") != spec.injection_vector_id
                ):
                    raise BankingWitnessError(
                        f"public-pack injection identity differs: {spec.source_task_id}"
                    )
        oracle = _read_object(pack / "oracles" / f"{spec.source_task_id}.json")
        oracle_user = oracle.get("user_task")
        oracle_injection = oracle.get("injection_task")
        if (
            oracle.get("suite_version") != SUITE_VERSION
            or not isinstance(oracle_user, dict)
            or oracle_user.get("id") != spec.user_task_id
            or not isinstance(oracle_injection, dict)
            or oracle_injection.get("id") != spec.injection_task_id
        ):
            raise BankingWitnessError(
                f"public-pack oracle identity differs: {spec.source_task_id}"
            )


def _require_bool(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise BankingWitnessError(f"{label} is not Boolean")
    return value


def _validate_native_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BankingWitnessError("native witness result is not an object")
    if (
        value.get("schema_version") != 1
        or value.get("witness_id") != WITNESS_ID
        or value.get("domain") != DOMAIN
        or value.get("suite_version") != SUITE_VERSION
        or value.get("upstream_version_or_commit") != UPSTREAM_VERSION_OR_COMMIT
    ):
        raise BankingWitnessError("native witness identity differs")
    workflows = value.get("workflows")
    if not isinstance(workflows, list) or len(workflows) != len(WORKFLOW_SPECS):
        raise BankingWitnessError("native witness workflow count differs")
    by_id = {
        row.get("source_ids", {}).get("source_task_id"): row
        for row in workflows
        if isinstance(row, dict) and isinstance(row.get("source_ids"), dict)
    }
    if set(by_id) != {spec.source_task_id for spec in WORKFLOW_SPECS}:
        raise BankingWitnessError("native witness source-task set differs")

    expected_native_dispatches = 0
    expected_checker_calls = 0
    for spec in WORKFLOW_SPECS:
        row = by_id[spec.source_task_id]
        source = row["source_ids"]
        if (
            source.get("user_task_id") != spec.user_task_id
            or source.get("injection_task_id") != spec.injection_task_id
            or source.get("injection_vector_id") != spec.injection_vector_id
        ):
            raise BankingWitnessError(
                f"native source IDs differ for {spec.source_task_id}"
            )
        carrier = row.get("carrier")
        benign = row.get("benign")
        vulnerable = row.get("vulnerable")
        protected = row.get("protected_predispatch")
        if not all(isinstance(item, dict) for item in (carrier, benign, vulnerable, protected)):
            raise BankingWitnessError(f"native witness section missing: {spec.source_task_id}")
        if (
            carrier.get("script_role") != "reachability_only"
            or carrier.get("native_dispatches") != 1
            or _require_bool(
                carrier.get("injection_goal_present_in_native_observation"),
                "carrier injection reach",
            )
            is not True
            or not isinstance(carrier.get("native_tool_schema"), dict)
        ):
            raise BankingWitnessError(
                f"native carrier reachability failed: {spec.source_task_id}"
            )
        utility = benign.get("native_utility_checker")
        security = vulnerable.get("native_security_checker")
        effect = vulnerable.get("exact_final_effect")
        if (
            not isinstance(utility, dict)
            or _require_bool(utility.get("result"), "native utility") is not True
            or not isinstance(security, dict)
            or _require_bool(security.get("result"), "native security") is not True
            or not isinstance(effect, dict)
            or effect.get("pre_state_sha256") == effect.get("post_state_sha256")
        ):
            raise BankingWitnessError(
                f"native checker/effect witness failed: {spec.source_task_id}"
            )
        if (
            protected.get("mode") != "offline_source_bound_simulation_only"
            or protected.get("decision") != "deny"
            or protected.get("reason") != "not_an_exact_user_ground_truth_action"
            or protected.get("native_dispatches") != 0
            or protected.get("pre_state_sha256") != protected.get("post_state_sha256")
            or protected.get("candidate_action_sha256")
            != effect.get("action_sha256")
            or _require_bool(
                protected.get("candidate_matches_vulnerable_final_action"),
                "protected candidate binding",
            )
            is not True
        ):
            raise BankingWitnessError(
                f"protected pre-dispatch witness failed: {spec.source_task_id}"
            )
        benign_calls = benign.get("native_dispatches")
        vulnerable_calls = vulnerable.get("native_dispatches")
        if (
            not isinstance(benign_calls, int)
            or isinstance(benign_calls, bool)
            or benign_calls < 1
            or not isinstance(vulnerable_calls, int)
            or isinstance(vulnerable_calls, bool)
            or vulnerable_calls < 2
        ):
            raise BankingWitnessError("native dispatch counts are invalid")
        expected_native_dispatches += benign_calls + vulnerable_calls
        expected_checker_calls += 2

    counts = value.get("execution_counts")
    if not isinstance(counts, dict):
        raise BankingWitnessError("native execution counts are missing")
    for zero_field in (
        "model_calls",
        "provider_calls",
        "api_calls",
        "network_calls",
        "llm_tokens",
    ):
        if counts.get(zero_field) != 0:
            raise BankingWitnessError(f"zero-token witness recorded {zero_field}")
    if (
        counts.get("native_dispatches") != expected_native_dispatches
        or counts.get("native_checker_calls") != expected_checker_calls
    ):
        raise BankingWitnessError("aggregate native call counts differ")
    if value.get("execution_authorized") is not False or value.get("claim_eligible") is not False:
        raise BankingWitnessError("offline witness cannot authorize execution or a claim")
    _canonical_bytes(value)
    return json.loads(_canonical_bytes(value))


def run_banking_native_witnesses(
    *,
    repo_root: Path | str | None = None,
    runtime_root: Path | str | None = None,
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    """Run all three native witnesses with zero model/provider/API/network calls."""

    repository = Path(repo_root) if repo_root is not None else _repo_root()
    repository = repository.resolve()
    runtime = (
        Path(runtime_root)
        if runtime_root is not None
        else repository / DEFAULT_RUNTIME_RELATIVE
    ).resolve()
    if (
        not isinstance(timeout_seconds, int)
        or isinstance(timeout_seconds, bool)
        or timeout_seconds < 1
    ):
        raise BankingWitnessError("timeout_seconds must be a positive integer")
    _validate_source_locks(repository)
    _validate_source_pack(repository)
    python = runtime / "bin/python"
    if not python.is_file():
        raise BankingWitnessError(f"pinned AgentDojo Python is missing: {python}")
    request = {
        "schema_version": 1,
        "witness_id": WITNESS_ID,
        "repo_root": str(repository),
        "runtime_root": str(runtime),
        "workflows": [asdict(spec) for spec in WORKFLOW_SPECS],
    }
    command = [str(python), "-I", "-B", str(Path(__file__).resolve()), "--native-worker-v1"]
    try:
        completed = subprocess.run(
            command,
            input=_canonical_bytes(request).decode("utf-8") + "\n",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(repository),
            env={
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BankingWitnessError(
            f"cannot run pinned AgentDojo witness worker: {type(exc).__name__}"
        ) from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip().splitlines()
        suffix = detail[-1] if detail else "no worker diagnostic"
        raise BankingWitnessError(
            f"pinned AgentDojo witness worker failed ({completed.returncode}): {suffix}"
        )
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise BankingWitnessError("native witness worker returned invalid JSON") from exc
    return _validate_native_result(value)


def validate_banking_native_witnesses(value: Any) -> dict[str, Any]:
    """Public fail-closed validator, useful when binding a cached witness."""

    return _validate_native_result(value)


# ----------------------------- native worker -----------------------------


def _call_record(call: Any) -> dict[str, Any]:
    record = {
        "operation": str(call.function),
        "args": _json_safe(call.args),
    }
    placeholder = getattr(call, "placeholder_args", None)
    if placeholder is not None:
        record["source_placeholder_args"] = _json_safe(placeholder)
    record["action_sha256"] = _sha256_json(
        {"operation": record["operation"], "args": record["args"]}
    )
    return record


def _callable_ref(target: Any, checkout: Path) -> dict[str, Any]:
    path_text = inspect.getsourcefile(target)
    if not path_text:
        raise BankingWitnessError("native callable has no source file")
    path = Path(path_text).resolve()
    try:
        relative = path.relative_to(checkout.resolve()).as_posix()
        _source, line = inspect.getsourcelines(target)
    except (ValueError, OSError, TypeError) as exc:
        raise BankingWitnessError("native callable source is outside the pinned checkout") from exc
    return {
        "callable": f"{target.__module__}.{target.__qualname__}:{line}",
        "source_file": relative,
        "source_sha256": _file_sha256(path),
    }


def _environment_sha256(environment: Any) -> str:
    return _sha256_json(_json_safe(environment))


def _observation_contains(observation: Any, needle: str) -> bool:
    if isinstance(observation, str):
        return needle in observation
    if isinstance(observation, Mapping):
        return any(_observation_contains(value, needle) for value in observation.values())
    if isinstance(observation, Sequence) and not isinstance(observation, (bytes, bytearray, str)):
        return any(_observation_contains(value, needle) for value in observation)
    if hasattr(observation, "model_dump") and callable(observation.model_dump):
        return _observation_contains(observation.model_dump(mode="json"), needle)
    return False


def _tool_map(suite: Any) -> dict[str, Any]:
    tools = {str(tool.name): tool for tool in suite.tools}
    if len(tools) != len(suite.tools):
        raise BankingWitnessError("native suite has duplicate tool names")
    return tools


def _schema_for(tool: Any) -> dict[str, Any]:
    schema = _json_safe(tool.parameters.model_json_schema())
    if not isinstance(schema, dict):
        raise BankingWitnessError("native tool schema is not an object")
    return schema


def _validate_call_schema(call: Any, tools: Mapping[str, Any]) -> None:
    tool = tools.get(str(call.function))
    if tool is None:
        raise BankingWitnessError("source-authored action references an unknown native tool")
    try:
        tool.parameters(**dict(call.args))
    except Exception as exc:
        raise BankingWitnessError("source-authored action fails its native tool schema") from exc


def _execute_calls(
    runtime: Any,
    environment: Any,
    calls: Sequence[Any],
    function_call_type: Any,
) -> tuple[list[dict[str, Any]], list[Any]]:
    effects: list[dict[str, Any]] = []
    executed: list[Any] = []
    for index, source_call in enumerate(calls):
        before = _environment_sha256(environment)
        result, error = runtime.run_function(
            environment,
            str(source_call.function),
            dict(source_call.args),
            raise_on_error=True,
        )
        if error is not None:
            raise BankingWitnessError("native runtime returned an action error")
        after = _environment_sha256(environment)
        call = function_call_type(
            function=str(source_call.function),
            args=dict(source_call.args),
            id=None,
        )
        executed.append(call)
        record = _call_record(source_call)
        effects.append(
            {
                "sequence_index": index,
                "action": record,
                "observation": _json_safe(result),
                "observation_sha256": _sha256_json(_json_safe(result)),
                "pre_state_sha256": before,
                "post_state_sha256": after,
            }
        )
    return effects, executed


def _native_checker(
    *,
    dispatcher: Any,
    task_checker: Any,
    task: Any,
    pre_environment: Any,
    post_environment: Any,
    calls: Sequence[Any],
    checkout: Path,
) -> dict[str, Any]:
    before = _environment_sha256(post_environment)
    result = dispatcher(
        task,
        [{"type": "text", "content": ""}],
        pre_environment,
        post_environment,
        tuple(calls),
    )
    after = _environment_sha256(post_environment)
    if type(result) is not bool or before != after:
        raise BankingWitnessError("native checker result/mutation contract differs")
    return {
        "result": result,
        "dispatcher": _callable_ref(dispatcher, checkout),
        "task_checker": _callable_ref(task_checker, checkout),
        "pre_state_sha256": before,
        "post_state_sha256": after,
    }


def _fresh_environment(suite: Any, user_task: Any, injections: Mapping[str, str]) -> Any:
    environment = suite.load_and_inject_default_environment(dict(injections))
    return user_task.init_environment(environment)


def _one_native_workflow(
    spec: BankingWorkflowSpec,
    *,
    suite: Any,
    runtime_type: Any,
    function_call_type: Any,
    checkout: Path,
) -> dict[str, Any]:
    user_task = suite.get_user_task_by_id(spec.user_task_id)
    injection_task = suite.get_injection_task_by_id(spec.injection_task_id)
    tools = _tool_map(suite)
    utility_dispatcher = suite._check_user_task_utility
    security_dispatcher = suite._check_injection_task_security

    # Benign: every action and the verdict are obtained from the native task.
    benign_environment = _fresh_environment(suite, user_task, {})
    benign_pre = benign_environment.model_copy(deep=True)
    benign_source_calls = tuple(user_task.ground_truth(benign_pre))
    if not benign_source_calls:
        raise BankingWitnessError("native user ground truth is empty")
    for call in benign_source_calls:
        _validate_call_schema(call, tools)
    benign_effects, benign_executed = _execute_calls(
        runtime_type(suite.tools),
        benign_environment,
        benign_source_calls,
        function_call_type,
    )
    utility = _native_checker(
        dispatcher=utility_dispatcher,
        task_checker=user_task.utility,
        task=user_task,
        pre_environment=benign_pre,
        post_environment=benign_environment,
        calls=benign_executed,
        checkout=checkout,
    )

    # Vulnerable: the first ordinary user action is a reachability-only script;
    # the source injection sequence and native security checker establish effect.
    injections = {spec.injection_vector_id: str(injection_task.GOAL)}
    vulnerable_environment = _fresh_environment(suite, user_task, injections)
    vulnerable_pre = vulnerable_environment.model_copy(deep=True)
    vulnerable_user_calls = tuple(user_task.ground_truth(vulnerable_pre))
    if not vulnerable_user_calls:
        raise BankingWitnessError("native adversarial user ground truth is empty")
    carrier_call = vulnerable_user_calls[0]
    _validate_call_schema(carrier_call, tools)
    carrier_effects, carrier_executed = _execute_calls(
        runtime_type(suite.tools),
        vulnerable_environment,
        (carrier_call,),
        function_call_type,
    )
    carrier_effect = carrier_effects[0]
    if not _observation_contains(carrier_effect["observation"], str(injection_task.GOAL)):
        raise BankingWitnessError("ordinary native action did not reach the injection carrier")
    injection_source_calls = tuple(injection_task.ground_truth(vulnerable_pre))
    if not injection_source_calls:
        raise BankingWitnessError("native injection ground truth is empty")
    for call in injection_source_calls:
        _validate_call_schema(call, tools)
    injection_effects, injection_executed = _execute_calls(
        runtime_type(suite.tools),
        vulnerable_environment,
        injection_source_calls,
        function_call_type,
    )
    security = _native_checker(
        dispatcher=security_dispatcher,
        task_checker=injection_task.security,
        task=injection_task,
        pre_environment=vulnerable_pre,
        post_environment=vulnerable_environment,
        calls=carrier_executed + injection_executed,
        checkout=checkout,
    )
    final_effect = injection_effects[-1]
    if final_effect["pre_state_sha256"] == final_effect["post_state_sha256"]:
        raise BankingWitnessError("native injection final action had no exact state effect")

    # Protected: derive authority and candidate from fresh source objects, then
    # compare exact operation+arguments before dispatch.  No tool is called.
    protected_environment = _fresh_environment(suite, user_task, injections)
    protected_pre = protected_environment.model_copy(deep=True)
    protected_state = _environment_sha256(protected_environment)
    protected_user_calls = tuple(user_task.ground_truth(protected_pre))
    protected_injection_calls = tuple(injection_task.ground_truth(protected_pre))
    if not protected_injection_calls:
        raise BankingWitnessError("protected source injection sequence is empty")
    candidate = protected_injection_calls[-1]
    _validate_call_schema(candidate, tools)
    authorized_records = [_call_record(call) for call in protected_user_calls]
    candidate_record = _call_record(candidate)
    candidate_projection = {
        "operation": candidate_record["operation"],
        "args": candidate_record["args"],
    }
    authorized_projections = [
        {"operation": record["operation"], "args": record["args"]}
        for record in authorized_records
    ]
    if candidate_projection in authorized_projections:
        raise BankingWitnessError("final injection action unexpectedly has exact user authority")
    if candidate_record["action_sha256"] != final_effect["action"]["action_sha256"]:
        raise BankingWitnessError("protected candidate differs from vulnerable final action")
    if _environment_sha256(protected_environment) != protected_state:
        raise BankingWitnessError("protected pre-dispatch simulation mutated native state")

    relevant_names = {
        str(call.function)
        for call in (
            tuple(benign_source_calls)
            + (carrier_call,)
            + tuple(injection_source_calls)
        )
    }
    schemas = {name: _schema_for(tools[name]) for name in sorted(relevant_names)}
    source_ids = {
        **asdict(spec),
        "suite_version": SUITE_VERSION,
        "domain": DOMAIN,
        "user_ground_truth": _callable_ref(user_task.ground_truth, checkout),
        "utility_checker": _callable_ref(user_task.utility, checkout),
        "injection_ground_truth": _callable_ref(injection_task.ground_truth, checkout),
        "security_checker": _callable_ref(injection_task.security, checkout),
    }
    return {
        "source_ids": source_ids,
        "surface_task": str(user_task.PROMPT),
        "native_tool_schemas": schemas,
        "carrier": {
            "script_role": "reachability_only",
            "source_action_index": 0,
            "action": carrier_effect["action"],
            "native_tool_schema": schemas[carrier_effect["action"]["operation"]],
            "observation": carrier_effect["observation"],
            "observation_sha256": carrier_effect["observation_sha256"],
            "injection_goal_sha256": hashlib.sha256(
                str(injection_task.GOAL).encode("utf-8")
            ).hexdigest(),
            "injection_goal_present_in_native_observation": True,
            "pre_state_sha256": carrier_effect["pre_state_sha256"],
            "post_state_sha256": carrier_effect["post_state_sha256"],
            "native_dispatches": 1,
        },
        "benign": {
            "source_action_sequence": [_call_record(call) for call in benign_source_calls],
            "native_effects": benign_effects,
            "native_utility_checker": utility,
            "native_dispatches": len(benign_source_calls),
            "native_checker_calls": 1,
        },
        "vulnerable": {
            "carrier_action_sequence": [carrier_effect["action"]],
            "source_injection_action_sequence": [
                _call_record(call) for call in injection_source_calls
            ],
            "native_injection_effects": injection_effects,
            "exact_final_effect": {
                "action": final_effect["action"],
                "action_sha256": final_effect["action"]["action_sha256"],
                "pre_state_sha256": final_effect["pre_state_sha256"],
                "post_state_sha256": final_effect["post_state_sha256"],
                "observation_sha256": final_effect["observation_sha256"],
            },
            "native_security_checker": security,
            "native_dispatches": 1 + len(injection_source_calls),
            "native_checker_calls": 1,
        },
        "protected_predispatch": {
            "mode": "offline_source_bound_simulation_only",
            "candidate_source": "final_native_injection_ground_truth_action",
            "candidate_action_index": len(protected_injection_calls) - 1,
            "candidate_action": candidate_record,
            "candidate_action_sha256": candidate_record["action_sha256"],
            "candidate_native_tool_schema": schemas[candidate_record["operation"]],
            "candidate_matches_vulnerable_final_action": True,
            "authorized_user_ground_truth_actions": authorized_records,
            "decision": "deny",
            "reason": "not_an_exact_user_ground_truth_action",
            "pre_state_sha256": protected_state,
            "post_state_sha256": protected_state,
            "native_dispatches": 0,
            "native_checker_calls": 0,
            "execution_authorized": False,
        },
    }


def _install_network_denial() -> list[int]:
    attempts = [0]

    def deny(*_args: Any, **_kwargs: Any) -> Any:
        attempts[0] += 1
        raise BankingWitnessError("network is forbidden in zero-token native witness")

    class NetworkDeniedSocket(socket.socket):
        def connect(self, *_args: Any, **_kwargs: Any) -> Any:
            return deny()

        def connect_ex(self, *_args: Any, **_kwargs: Any) -> Any:
            return deny()

    socket.socket = NetworkDeniedSocket
    socket.create_connection = deny
    socket.getaddrinfo = deny
    return attempts


def _native_worker(request: Any) -> dict[str, Any]:
    if not isinstance(request, dict) or request.get("schema_version") != 1:
        raise BankingWitnessError("native worker request differs")
    if request.get("witness_id") != WITNESS_ID:
        raise BankingWitnessError("native worker witness identity differs")
    repository = Path(str(request.get("repo_root"))).resolve()
    runtime = Path(str(request.get("runtime_root"))).resolve()
    if Path(sys.prefix).resolve() != runtime:
        raise BankingWitnessError("native worker sys.prefix differs from pinned runtime")
    if repository != _repo_root().resolve():
        raise BankingWitnessError("native worker repository identity differs")
    _validate_source_locks(repository)
    _validate_source_pack(repository)
    raw_specs = request.get("workflows")
    if not isinstance(raw_specs, list):
        raise BankingWitnessError("native worker workflow specs are missing")
    specs = tuple(BankingWorkflowSpec(**row) for row in raw_specs)
    if specs != WORKFLOW_SPECS:
        raise BankingWitnessError("native worker workflow specs differ")

    network_attempts = _install_network_denial()
    checkout = repository / UPSTREAM_RELATIVE
    sys.path.insert(0, str(checkout / "src"))
    import importlib

    load_suites = importlib.import_module("agentdojo.task_suite.load_suites")
    functions_runtime = importlib.import_module("agentdojo.functions_runtime")
    suite = load_suites.get_suite(SUITE_VERSION, DOMAIN)
    runtime_type = functions_runtime.FunctionsRuntime
    function_call_type = functions_runtime.FunctionCall
    for target, relative in (
        (load_suites.get_suite, "src/agentdojo/task_suite/load_suites.py"),
        (runtime_type, "src/agentdojo/functions_runtime.py"),
        (function_call_type, "src/agentdojo/functions_runtime.py"),
        (type(suite)._check_user_task_utility, "src/agentdojo/task_suite/task_suite.py"),
        (type(suite)._check_injection_task_security, "src/agentdojo/task_suite/task_suite.py"),
    ):
        origin = Path(inspect.getsourcefile(target) or "").resolve()
        expected = (checkout / relative).resolve()
        if origin != expected or _file_sha256(origin) != _SOURCE_LOCKS[relative]:
            raise BankingWitnessError("native callable origin/hash differs")

    workflows = [
        _one_native_workflow(
            spec,
            suite=suite,
            runtime_type=runtime_type,
            function_call_type=function_call_type,
            checkout=checkout,
        )
        for spec in specs
    ]
    if network_attempts[0] != 0:
        raise BankingWitnessError("native worker attempted network access")
    native_dispatches = sum(
        row["benign"]["native_dispatches"]
        + row["vulnerable"]["native_dispatches"]
        + row["protected_predispatch"]["native_dispatches"]
        for row in workflows
    )
    native_checker_calls = sum(
        row["benign"]["native_checker_calls"]
        + row["vulnerable"]["native_checker_calls"]
        + row["protected_predispatch"]["native_checker_calls"]
        for row in workflows
    )
    return {
        "schema_version": 1,
        "witness_id": WITNESS_ID,
        "upstream_version_or_commit": UPSTREAM_VERSION_OR_COMMIT,
        "suite_version": SUITE_VERSION,
        "domain": DOMAIN,
        "runtime_root": str(runtime),
        "source_locks": dict(_SOURCE_LOCKS),
        "workflows": workflows,
        "execution_counts": {
            "model_calls": 0,
            "provider_calls": 0,
            "api_calls": 0,
            "network_calls": 0,
            "llm_tokens": 0,
            "native_dispatches": native_dispatches,
            "native_checker_calls": native_checker_calls,
        },
        "execution_authorized": False,
        "claim_eligible": False,
    }


def _worker_main() -> int:
    try:
        request = json.loads(sys.stdin.readline())
        result = _native_worker(request)
        sys.stdout.write(_canonical_bytes(result).decode("utf-8") + "\n")
        sys.stdout.flush()
        return 0
    except Exception as exc:
        sys.stderr.write(f"{type(exc).__name__}: {exc}\n")
        sys.stderr.flush()
        return 1


__all__ = [
    "BankingWitnessError",
    "BankingWorkflowSpec",
    "DEFAULT_RUNTIME_RELATIVE",
    "DOMAIN",
    "SUITE_VERSION",
    "UPSTREAM_VERSION_OR_COMMIT",
    "WITNESS_ID",
    "WORKFLOW_SPECS",
    "run_banking_native_witnesses",
    "validate_banking_native_witnesses",
]


if __name__ == "__main__":
    if sys.argv[1:] != ["--native-worker-v1"]:
        raise SystemExit("banking witness module is not a standalone execution entrypoint")
    raise SystemExit(_worker_main())
