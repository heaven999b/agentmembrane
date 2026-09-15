"""Offline native-checker parity for the canonical RQ1 AgentDojo slice.

The runner launches the frozen cache-free Python environment with ``-I -B``,
constructs four in-memory AgentDojo environments, follows the already-gated
Host dispatch plan, and invokes the upstream utility/security dispatchers.
It never calls a model, provider, API, or network endpoint.  Native security
remains an informational injection-success signal and is not consumed by
admission or by the exact unauthorized-effect oracle.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
from typing import Any, Mapping, Sequence

from ..public_execution import (
    ExactCommittedTrustedEventOracle,
    assess_public_execution_binding,
)
from ..schema import IntegrityError, canonical_json_bytes, sha256_json
from .checker_hook import (
    INJECTION_TASK_SOURCE_SHA256,
    SECURITY_CHECKER_REF,
    SECURITY_DISPATCHER_REF,
    TASK_SUITE_SOURCE_SHA256,
    USER_TASK_SOURCE_SHA256,
    UTILITY_CHECKER_REF,
    UTILITY_DISPATCHER_REF,
)
from .gate import (
    EXPECTED,
    EXPECTED_ACTIONS,
    MAPPING_PATH,
    ORACLE_PATH,
    PACK_ROOT,
    validate_gate_record,
)


REPO_ROOT = Path(__file__).resolve().parents[3]
SOURCE_ROOT = REPO_ROOT / "data/host_boundary_v2/upstream/agentdojo"
RUNTIME_RUN_ROOT = Path(
    "/private/tmp/agentmembrane-rq1-agentdojo-runtime-preflight-20260831a005"
)
RUNTIME_ROOT = RUNTIME_RUN_ROOT / "environment-v2"
RUNTIME_ARTIFACT_ROOT = RUNTIME_RUN_ROOT / "artifacts"
RUNTIME_ID = (
    "agentdojo-0.1.35-py3123-lock-395e3d0a5921-"
    "rq1-public-preflight-20260831a005"
)
RUNTIME_RECEIPT = RUNTIME_ARTIFACT_ROOT / f"{RUNTIME_ID}.receipt.json"
RUNTIME_BINDING = RUNTIME_ARTIFACT_ROOT / f"{RUNTIME_ID}.binding.json"
RUNTIME_LIVE = RUNTIME_ARTIFACT_ROOT / f"{RUNTIME_ID}.live.json"
ZERO_TOKEN_GATE = REPO_ROOT / (
    "experiments/host_boundary_v2/rq1_public_agentdojo_host_v1/"
    "zero_token_four_cell_gate.json"
)
DEFAULT_OUTPUT = REPO_ROOT / (
    "experiments/host_boundary_v2/rq1_public_agentdojo_host_v1/"
    "native_checker_parity_a005_v1.json"
)

EXPECTED_RUNTIME_TREE_SHA256 = (
    "068ea9a21736a3c1cdfbb14886fed18f07ac7b56443b63c0e3680147fb04bc38"
)
EXPECTED_RUNTIME_ENTRY_COUNT = 5253
EXPECTED_RECEIPT_SHA256 = (
    "7ad6b1cba429265e1b5baf141dc394131b14b8a8d3e62203c946462030902965"
)
EXPECTED_BINDING_SHA256 = (
    "9bf36e14ebb55fa0f36d768aa8acceac42cde6de38956c51cb3d43644833c37b"
)
EXPECTED_LIVE_SHA256 = (
    "9d588b39a2bb2ffc8a22d9b2cb33fd127389b7c8774f10b90d72ed53ee45d205"
)
EXPECTED_SOURCE_TREE_SHA256 = (
    "3675668d8c10e4632adc3b2b541d87ed795a613fb9d0284bae2975be63ab889d"
)
EXPECTED_LOCK_SHA256 = (
    "395e3d0a59214515008d27c4462c9723ab7594374243f561ad5f19b3aa8a5330"
)

EXPECTED_CALLABLE_SOURCES = {
    UTILITY_DISPATCHER_REF: TASK_SUITE_SOURCE_SHA256,
    SECURITY_DISPATCHER_REF: TASK_SUITE_SOURCE_SHA256,
    UTILITY_CHECKER_REF: USER_TASK_SOURCE_SHA256,
    SECURITY_CHECKER_REF: INJECTION_TASK_SOURCE_SHA256,
}


class NativeParityError(IntegrityError):
    """The isolated native-checker parity run failed closed."""


def _sha_file(path: Path) -> str:
    if not path.is_file():
        raise NativeParityError(f"required file is missing: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NativeParityError(f"cannot load JSON binding {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise NativeParityError(f"JSON binding must be an object: {path}")
    canonical_json_bytes(value)
    return value


def _tree_manifest_sha256(root: Path) -> tuple[str, int]:
    if not root.is_dir():
        raise NativeParityError(f"runtime root is missing: {root}")
    rows: list[dict[str, str]] = []
    for directory, directory_names, file_names in os.walk(
        root, topdown=True, followlinks=False
    ):
        directory_names.sort()
        file_names.sort()
        parent = Path(directory)
        for name in list(directory_names):
            path = parent / name
            if path.is_symlink():
                rows.append(
                    {
                        "path": path.relative_to(root).as_posix(),
                        "type": "symlink",
                        "target": os.readlink(path),
                    }
                )
                directory_names.remove(name)
        for name in file_names:
            path = parent / name
            mode = path.lstat().st_mode
            relative = path.relative_to(root).as_posix()
            if stat.S_ISLNK(mode):
                rows.append(
                    {
                        "path": relative,
                        "type": "symlink",
                        "target": os.readlink(path),
                    }
                )
            elif stat.S_ISREG(mode):
                rows.append(
                    {
                        "path": relative,
                        "type": "file",
                        "sha256": _sha_file(path),
                    }
                )
            else:
                raise NativeParityError(f"unsupported runtime entry: {path}")
    rows.sort(key=lambda row: row["path"])
    return hashlib.sha256(canonical_json_bytes(rows)).hexdigest(), len(rows)


def _validate_runtime_bindings(runtime_root: Path) -> dict[str, Any]:
    receipt_hash = _sha_file(RUNTIME_RECEIPT)
    binding_hash = _sha_file(RUNTIME_BINDING)
    live_hash = _sha_file(RUNTIME_LIVE)
    if (
        receipt_hash != EXPECTED_RECEIPT_SHA256
        or binding_hash != EXPECTED_BINDING_SHA256
        or live_hash != EXPECTED_LIVE_SHA256
    ):
        raise NativeParityError("fresh runtime triplet hash differs")
    receipt = _load_json(RUNTIME_RECEIPT)
    binding = _load_json(RUNTIME_BINDING)
    live = _load_json(RUNTIME_LIVE)
    expected_root = str(runtime_root.resolve())
    if (
        receipt.get("runtime_id") != RUNTIME_ID
        or binding.get("runtime_id") != RUNTIME_ID
        or live.get("runtime_id") != RUNTIME_ID
        or receipt.get("environment", {}).get("root") != expected_root
        or binding.get("environment_root") != expected_root
        or live.get("environment_root") != expected_root
    ):
        raise NativeParityError("fresh runtime identity/root differs")
    if (
        receipt.get("environment", {}).get("tree_sha256")
        != EXPECTED_RUNTIME_TREE_SHA256
        or binding.get("environment_tree_sha256")
        != EXPECTED_RUNTIME_TREE_SHA256
        or live.get("environment_tree_sha256") != EXPECTED_RUNTIME_TREE_SHA256
    ):
        raise NativeParityError("fresh runtime receipt tree binding differs")
    if (
        receipt.get("source", {}).get("tree_sha256")
        != EXPECTED_SOURCE_TREE_SHA256
        or receipt.get("source", {}).get("lock_sha256") != EXPECTED_LOCK_SHA256
        or live.get("hygiene")
        != {
            "compressed_file_count": 0,
            "dataless_file_count": 0,
            "file_count": EXPECTED_RUNTIME_ENTRY_COUNT,
            "pyc_count": 0,
            "pycache_dir_count": 0,
            "transform_dir_count": 0,
        }
    ):
        raise NativeParityError("fresh runtime source/hygiene binding differs")
    return {
        "runtime_id": RUNTIME_ID,
        "runtime_root": expected_root,
        "runtime_tree_sha256": EXPECTED_RUNTIME_TREE_SHA256,
        "runtime_entry_count": EXPECTED_RUNTIME_ENTRY_COUNT,
        "receipt": {"path": str(RUNTIME_RECEIPT), "sha256": receipt_hash},
        "binding": {"path": str(RUNTIME_BINDING), "sha256": binding_hash},
        "live_validator": {"path": str(RUNTIME_LIVE), "sha256": live_hash},
        "prior_preflight_authorized_native_execution": receipt.get(
            "authorizations", {}
        ).get("native_execution"),
    }


def _probe_source(specs: Sequence[Mapping[str, Any]]) -> str:
    specs_json = json.dumps(list(specs), sort_keys=True, separators=(",", ":"))
    return f'''import hashlib
import inspect
import json
from pathlib import Path
import socket
import sys

network_attempts = 0
def deny_network(*args, **kwargs):
    global network_attempts
    network_attempts += 1
    raise RuntimeError("RQ1_NATIVE_PARITY_NETWORK_FORBIDDEN")
socket.create_connection = deny_network
socket.getaddrinfo = deny_network
socket.socket.connect = deny_network

source_root = Path({str(SOURCE_ROOT)!r}).resolve()
sys.path.insert(0, str(source_root / "src"))

from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite

def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")

def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def safe(value):
    if value is None or isinstance(value, (str, bool, int, float)):
        canonical(value)
        return value
    if isinstance(value, dict):
        result = {{}}
        for key, item in value.items():
            if not isinstance(key, str):
                raise RuntimeError("NATIVE_NON_STRING_KEY")
            result[key] = safe(item)
        canonical(result)
        return result
    if isinstance(value, (list, tuple)):
        result = [safe(item) for item in value]
        canonical(result)
        return result
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        try:
            return safe(model_dump(mode="json"))
        except TypeError:
            return safe(model_dump())
    raise RuntimeError("NATIVE_NON_JSON_VALUE:" + type(value).__name__)

suite = get_suite("v1", "banking")
user_task = suite.get_user_task_by_id("user_task_3")
injection_task = suite.get_injection_task_by_id("injection_task_1")
binding_objects = {{
    {UTILITY_DISPATCHER_REF!r}: type(suite)._check_user_task_utility,
    {SECURITY_DISPATCHER_REF!r}: type(suite)._check_injection_task_security,
    {UTILITY_CHECKER_REF!r}: type(user_task).utility,
    {SECURITY_CHECKER_REF!r}: type(injection_task).security,
}}
bindings = []
for ref, obj in sorted(binding_objects.items()):
    path = Path(inspect.getsourcefile(obj) or "").resolve()
    try:
        path.relative_to(source_root)
    except ValueError as exc:
        raise RuntimeError("NATIVE_CALLABLE_ESCAPES_SOURCE_ROOT") from exc
    bindings.append({{
        "callable_ref": ref,
        "source_path": str(path),
        "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }})

specs = json.loads({specs_json!r})
rows = []
utility_calls = 0
security_calls = 0
native_dispatches = 0
for spec in specs:
    pair_role = spec["pair_role"]
    injections = {{}}
    if pair_role == "adversarial":
        injections["injection_incoming_transaction"] = injection_task.GOAL
    environment = suite.load_and_inject_default_environment(injections)
    environment = user_task.init_environment(environment)
    pre_environment = environment.model_copy(deep=True)
    pre_state = safe(pre_environment)
    before_transactions = safe(environment.bank_account.transactions)
    function_calls = []
    native_result = None
    action = spec["action"]
    if action is not None:
        runtime = FunctionsRuntime(suite.tools)
        result, error = runtime.run_function(
            environment,
            action["function"],
            dict(action["args"]),
            raise_on_error=True,
        )
        if error is not None:
            raise RuntimeError("NATIVE_DISPATCH_RETURNED_ERROR")
        function_calls.append(FunctionCall(
            function=action["function"],
            args=dict(action["args"]),
            id=None,
        ))
        native_result = safe(result)
        native_dispatches += 1
    post_state = safe(environment)
    after_transactions = safe(environment.bank_account.transactions)
    new_transactions = after_transactions[len(before_transactions):]
    content = [{{"type": "text", "content": ""}}]
    utility = suite._check_user_task_utility(
        user_task,
        content,
        pre_environment,
        environment,
        tuple(function_calls),
    )
    utility_calls += 1
    security = None
    if pair_role == "adversarial":
        security = suite._check_injection_task_security(
            injection_task,
            content,
            pre_environment,
            environment,
            tuple(function_calls),
        )
        security_calls += 1
    if type(utility) is not bool or (
        security is not None and type(security) is not bool
    ):
        raise RuntimeError("NATIVE_CHECKER_NON_BOOLEAN")
    output = {{
        "pair_role": pair_role,
        "arm": spec["arm"],
        "action": action,
        "native_dispatch_count": int(action is not None),
        "native_result": native_result,
        "pre_state_sha256": digest(pre_state),
        "post_state_sha256": digest(post_state),
        "new_transactions": new_transactions,
        "function_calls_sha256": digest([safe(call) for call in function_calls]),
        "utility": utility,
        "security": security,
    }}
    output["native_output_sha256"] = digest(output)
    rows.append(output)

print(json.dumps({{
    "schema_version": 1,
    "runtime_id": {RUNTIME_ID!r},
    "network_attempts": network_attempts,
    "callable_bindings": bindings,
    "cells": rows,
    "execution_counts": {{
        "api_calls": 0,
        "model_calls": 0,
        "native_checker_calls": utility_calls + security_calls,
        "native_dispatches": native_dispatches,
        "native_environment_constructions": len(rows),
        "network_attempts": network_attempts,
        "provider_calls": 0,
        "security_checker_calls": security_calls,
        "utility_checker_calls": utility_calls,
    }},
}}, sort_keys=True, separators=(",", ":")))
'''


def _run_native_probe(
    runtime_root: Path, specs: Sequence[Mapping[str, Any]]
) -> tuple[dict[str, Any], dict[str, Any]]:
    interpreter = runtime_root / "bin/python"
    if not interpreter.is_file():
        raise NativeParityError("cache-free runtime interpreter is missing")
    source = _probe_source(specs)
    environment = {
        "ALL_PROXY": "http://127.0.0.1:9",
        "HTTPS_PROXY": "http://127.0.0.1:9",
        "HTTP_PROXY": "http://127.0.0.1:9",
        "NO_PROXY": "*",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
    }
    completed = subprocess.run(
        [str(interpreter), "-I", "-B", "-c", source],
        cwd=SOURCE_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    if completed.returncode != 0:
        raise NativeParityError(
            "native parity probe failed with "
            f"{completed.returncode}: {completed.stderr.strip()}"
        )
    if completed.stderr.strip():
        raise NativeParityError(
            f"native parity probe produced stderr: {completed.stderr.strip()}"
        )
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise NativeParityError("native parity probe did not emit exact JSON") from exc
    if not isinstance(value, dict):
        raise NativeParityError("native parity probe output must be an object")
    invocation = {
        "interpreter": str(interpreter.resolve()),
        "arguments_prefix": ["-I", "-B", "-c"],
        "probe_source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "subprocess_returncode": completed.returncode,
        "stderr_sha256": hashlib.sha256(completed.stderr.encode("utf-8")).hexdigest(),
        "stdout_sha256": hashlib.sha256(completed.stdout.encode("utf-8")).hexdigest(),
    }
    return value, invocation


def _validate_native_output(
    value: Mapping[str, Any], gate: Mapping[str, Any]
) -> list[dict[str, Any]]:
    expected_counts = {
        "api_calls": 0,
        "model_calls": 0,
        "native_checker_calls": 6,
        "native_dispatches": 3,
        "native_environment_constructions": 4,
        "network_attempts": 0,
        "provider_calls": 0,
        "security_checker_calls": 2,
        "utility_checker_calls": 4,
    }
    if (
        value.get("schema_version") != 1
        or value.get("runtime_id") != RUNTIME_ID
        or value.get("network_attempts") != 0
        or value.get("execution_counts") != expected_counts
    ):
        raise NativeParityError("native parity probe identity/counts differ")
    bindings = value.get("callable_bindings")
    if not isinstance(bindings, list) or len(bindings) != 4:
        raise NativeParityError("native callable binding set is incomplete")
    actual_bindings = {
        row.get("callable_ref"): row.get("source_sha256")
        for row in bindings
        if isinstance(row, Mapping)
    }
    if actual_bindings != EXPECTED_CALLABLE_SOURCES:
        raise NativeParityError("native callable source hashes differ")

    gate_cells = {
        (cell["pair_role"], cell["arm"]): cell for cell in gate["cells"]
    }
    raw_cells = value.get("cells")
    if not isinstance(raw_cells, list) or len(raw_cells) != 4:
        raise NativeParityError("native parity probe must contain four cells")
    seen: set[tuple[str, str]] = set()
    rows: list[dict[str, Any]] = []
    for raw in raw_cells:
        if not isinstance(raw, Mapping):
            raise NativeParityError("native parity cell is not an object")
        coordinate = (raw.get("pair_role"), raw.get("arm"))
        if coordinate not in EXPECTED or coordinate in seen:
            raise NativeParityError(f"native parity coordinate differs: {coordinate}")
        seen.add(coordinate)
        pair_role, arm = coordinate
        gate_cell = gate_cells[coordinate]
        expected = EXPECTED[coordinate]
        expected_action = (
            None
            if expected["native_dispatch_count"] == 0
            else {
                "function": EXPECTED_ACTIONS[pair_role]["op"],
                "args": EXPECTED_ACTIONS[pair_role]["args"],
            }
        )
        if raw.get("action") != expected_action or raw.get(
            "native_dispatch_count"
        ) != expected["native_dispatch_count"]:
            raise NativeParityError(f"native action/dispatch differs for {coordinate}")
        if raw.get("utility") is not expected["utility"] or raw.get(
            "security"
        ) is not expected["security"]:
            raise NativeParityError(f"native checker outcome differs for {coordinate}")
        checker = gate_cell["checker_evidence"]
        parity = {
            "utility": raw.get("utility") is checker.get("utility"),
            "security": raw.get("security") is checker.get("security"),
        }
        if not all(parity.values()):
            raise NativeParityError(
                f"offline/native checker parity differs: {coordinate}"
            )
        native_output = {
            key: copy.deepcopy(row)
            for key, row in raw.items()
            if key != "native_output_sha256"
        }
        if raw.get("native_output_sha256") != sha256_json(native_output):
            raise NativeParityError(f"native output hash differs for {coordinate}")
        new_transactions = raw.get("new_transactions")
        if not isinstance(new_transactions, list) or len(
            new_transactions
        ) != expected["native_dispatch_count"]:
            raise NativeParityError(f"native state delta differs for {coordinate}")
        if expected_action is not None:
            transaction = new_transactions[0]
            if not isinstance(transaction, Mapping) or any(
                transaction.get(field) != expected_action["args"][field]
                for field in ("recipient", "amount", "subject", "date")
            ):
                raise NativeParityError(
                    f"native transaction does not match exact action: {coordinate}"
                )
        rows.append(
            {
                "pair_role": pair_role,
                "arm": arm,
                "host_gate": {
                    "denied": gate_cell["host_private"]["outcome"]["denied"],
                    "decision_sequence": gate_cell["host_private"]["outcome"][
                        "decision"
                    ]["sequence"],
                    "dispatch_sequence": (
                        None
                        if gate_cell["host_private"]["outcome"]["dispatch"] is None
                        else gate_cell["host_private"]["outcome"]["dispatch"][
                            "sequence"
                        ]
                    ),
                    "native_dispatch_count": gate_cell["native_dispatch_count"],
                },
                "native_checker": copy.deepcopy(dict(raw)),
                "offline_checker": {
                    "utility": checker["utility"],
                    "security": checker["security"],
                    "output_sha256": checker["output_sha256"],
                    "native_callable_executed": checker[
                        "native_callable_executed"
                    ],
                    "native_checker_parity_established": checker[
                        "native_checker_parity_established"
                    ],
                },
                "numeric_parity": parity,
            }
        )
    if seen != set(EXPECTED):
        raise NativeParityError("native parity four-cell matrix is incomplete")
    return rows


def _independent_effect_rows(
    gate: Mapping[str, Any], cells: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    tasks = [
        json.loads(line)
        for line in (PACK_ROOT / "tasks.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    task_by_coordinate = {
        (task["pair_role"], task["metadata"]["arm"]): task for task in tasks
    }
    oracle_document = _load_json(ORACLE_PATH)
    gate_by_coordinate = {
        (cell["pair_role"], cell["arm"]): cell for cell in gate["cells"]
    }
    output: list[dict[str, Any]] = []
    for cell in cells:
        coordinate = (cell["pair_role"], cell["arm"])
        task = task_by_coordinate[coordinate]
        gate_cell = gate_by_coordinate[coordinate]
        assessment = assess_public_execution_binding(task, oracle_document)
        if not assessment.executable or assessment.binding is None:
            raise NativeParityError(f"executable oracle binding differs: {coordinate}")
        effect = ExactCommittedTrustedEventOracle(
            oracle_document["unauthorized_side_effect"]["oracle_id"]
        ).evaluate(
            binding=assessment.binding,
            reset=None,
            dispatches=(),
            assistant_output=None,
            terminal_state=None,
            trusted_events=gate_cell["trusted_events"],
        )
        if effect.as_json() != gate_cell["unauthorized_side_effect"]:
            raise NativeParityError(f"independent effect replay differs: {coordinate}")
        output.append(
            {
                "pair_role": coordinate[0],
                "arm": coordinate[1],
                "occurred": effect.occurred,
                "oracle_output_sha256": effect.oracle_output_sha256,
                "input_source": "host_projected_trusted_events",
                "native_security_consumed": False,
                "native_utility_consumed": False,
            }
        )
    return output


def run_native_checker_parity(
    *,
    runtime_root: Path = RUNTIME_ROOT,
    gate_path: Path = ZERO_TOKEN_GATE,
) -> dict[str, Any]:
    """Invoke all native checkers and return a strict non-authorizing record."""

    runtime_root = Path(runtime_root).resolve()
    if runtime_root != RUNTIME_ROOT.resolve():
        raise NativeParityError("runtime root differs from the frozen a005 binding")
    runtime_binding = _validate_runtime_bindings(runtime_root)
    before_tree_sha, before_count = _tree_manifest_sha256(runtime_root)
    if (
        before_tree_sha != EXPECTED_RUNTIME_TREE_SHA256
        or before_count != EXPECTED_RUNTIME_ENTRY_COUNT
    ):
        raise NativeParityError("runtime tree differs before native invocation")

    gate_path = Path(gate_path)
    gate = validate_gate_record(_load_json(gate_path))
    specs = []
    for cell in gate["cells"]:
        coordinate = (cell["pair_role"], cell["arm"])
        action = None
        if EXPECTED[coordinate]["native_dispatch_count"] == 1:
            mapped = EXPECTED_ACTIONS[cell["pair_role"]]
            action = {"function": mapped["op"], "args": mapped["args"]}
        specs.append(
            {
                "pair_role": cell["pair_role"],
                "arm": cell["arm"],
                "action": action,
            }
        )
    native, invocation = _run_native_probe(runtime_root, specs)
    cells = _validate_native_output(native, gate)
    effect_rows = _independent_effect_rows(gate, cells)

    after_tree_sha, after_count = _tree_manifest_sha256(runtime_root)
    if (after_tree_sha, after_count) != (before_tree_sha, before_count):
        raise NativeParityError("cache-free runtime tree changed during parity run")
    implementation_path = Path(__file__).resolve()
    record = {
        "schema_version": 1,
        "artifact_type": "agentmembrane_rq1_agentdojo_native_checker_parity_v1",
        "parity_id": "rq1-agentdojo-banking-u3-i1-native-parity-a005-v1",
        "scope": "offline_native_checker_parity_only",
        "runtime_binding": runtime_binding,
        "runtime_integrity": {
            "before_tree_sha256": before_tree_sha,
            "after_tree_sha256": after_tree_sha,
            "before_entry_count": before_count,
            "after_entry_count": after_count,
            "tree_unchanged": True,
            "bytecode_disabled": True,
            "network_denied_in_process": True,
        },
        "input_bindings": {
            "zero_token_host_gate": {
                "path": gate_path.relative_to(REPO_ROOT).as_posix(),
                "sha256": _sha_file(gate_path),
            },
            "derived_pack_manifest": {
                "path": (PACK_ROOT / "manifest.json")
                .relative_to(REPO_ROOT)
                .as_posix(),
                "sha256": _sha_file(PACK_ROOT / "manifest.json"),
            },
            "mapping": {
                "path": MAPPING_PATH.relative_to(REPO_ROOT).as_posix(),
                "sha256": _sha_file(MAPPING_PATH),
            },
            "executable_oracle": {
                "path": ORACLE_PATH.relative_to(REPO_ROOT).as_posix(),
                "sha256": _sha_file(ORACLE_PATH),
            },
            "implementation": {
                "path": implementation_path.relative_to(REPO_ROOT).as_posix(),
                "sha256": _sha_file(implementation_path),
            },
        },
        "native_invocation": invocation,
        "callable_bindings": native["callable_bindings"],
        "cells": cells,
        "independent_unauthorized_effect": effect_rows,
        "semantic_separation": {
            "native_security_semantics": (
                "informational_upstream_injection_success_signal"
            ),
            "agentmembrane_effect_semantics": (
                "exact_committed_unauthorized_resource_value_effect"
            ),
            "native_security_used_for_admission": False,
            "native_security_used_for_unauthorized_effect": False,
            "native_utility_used_for_admission": False,
            "numeric_parity_does_not_assert_semantic_equivalence": True,
        },
        "execution_counts": native["execution_counts"],
        "result": {
            "native_callable_executed": True,
            "native_checker_parity_established": True,
            "offline_native_numeric_parity_cells": 4,
            "checker_blocker_cleared": True,
            "public_real_api_decision": "NO_GO",
            "remaining_blockers": [
                "EXPLICIT_EXECUTION_AUTHORIZATION_FALSE",
                "OFFLINE_PARITY_IS_NOT_A_LIVE_PROVIDER_RUN",
            ],
        },
        "execution_authorized": False,
        "real_public_execution_authorized": False,
        "claim_eligible": False,
    }
    validate_native_parity_record(record)
    return record


def validate_native_parity_record(value: Any) -> dict[str, Any]:
    """Validate the strict parity outcome without re-running native code."""

    if not isinstance(value, Mapping):
        raise NativeParityError("native parity record must be an object")
    record = copy.deepcopy(dict(value))
    if record.get("schema_version") != 1 or record.get("artifact_type") != (
        "agentmembrane_rq1_agentdojo_native_checker_parity_v1"
    ):
        raise NativeParityError("native parity record identity differs")
    if (
        record.get("parity_id")
        != "rq1-agentdojo-banking-u3-i1-native-parity-a005-v1"
        or record.get("scope") != "offline_native_checker_parity_only"
    ):
        raise NativeParityError("native parity record scope differs")
    result = record.get("result")
    if not isinstance(result, Mapping) or result != {
        "native_callable_executed": True,
        "native_checker_parity_established": True,
        "offline_native_numeric_parity_cells": 4,
        "checker_blocker_cleared": True,
        "public_real_api_decision": "NO_GO",
        "remaining_blockers": [
            "EXPLICIT_EXECUTION_AUTHORIZATION_FALSE",
            "OFFLINE_PARITY_IS_NOT_A_LIVE_PROVIDER_RUN",
        ],
    }:
        raise NativeParityError("native parity result differs")
    if any(
        record.get(name) is not False
        for name in (
            "execution_authorized",
            "real_public_execution_authorized",
            "claim_eligible",
        )
    ):
        raise NativeParityError("native parity record overclaims authorization")
    runtime = record.get("runtime_integrity")
    if not isinstance(runtime, Mapping) or (
        runtime.get("before_tree_sha256") != EXPECTED_RUNTIME_TREE_SHA256
        or runtime.get("after_tree_sha256") != EXPECTED_RUNTIME_TREE_SHA256
        or runtime.get("before_entry_count") != EXPECTED_RUNTIME_ENTRY_COUNT
        or runtime.get("after_entry_count") != EXPECTED_RUNTIME_ENTRY_COUNT
        or runtime.get("tree_unchanged") is not True
        or runtime.get("bytecode_disabled") is not True
        or runtime.get("network_denied_in_process") is not True
    ):
        raise NativeParityError("native parity runtime integrity differs")
    runtime_binding = record.get("runtime_binding")
    if not isinstance(runtime_binding, Mapping) or runtime_binding != {
        "runtime_id": RUNTIME_ID,
        "runtime_root": str(RUNTIME_ROOT.resolve()),
        "runtime_tree_sha256": EXPECTED_RUNTIME_TREE_SHA256,
        "runtime_entry_count": EXPECTED_RUNTIME_ENTRY_COUNT,
        "receipt": {
            "path": str(RUNTIME_RECEIPT),
            "sha256": EXPECTED_RECEIPT_SHA256,
        },
        "binding": {
            "path": str(RUNTIME_BINDING),
            "sha256": EXPECTED_BINDING_SHA256,
        },
        "live_validator": {
            "path": str(RUNTIME_LIVE),
            "sha256": EXPECTED_LIVE_SHA256,
        },
        "prior_preflight_authorized_native_execution": False,
    }:
        raise NativeParityError("native parity runtime binding differs")
    input_bindings = record.get("input_bindings")
    expected_inputs = {
        "zero_token_host_gate": {
            "path": ZERO_TOKEN_GATE.relative_to(REPO_ROOT).as_posix(),
            "sha256": _sha_file(ZERO_TOKEN_GATE),
        },
        "derived_pack_manifest": {
            "path": (PACK_ROOT / "manifest.json")
            .relative_to(REPO_ROOT)
            .as_posix(),
            "sha256": _sha_file(PACK_ROOT / "manifest.json"),
        },
        "mapping": {
            "path": MAPPING_PATH.relative_to(REPO_ROOT).as_posix(),
            "sha256": _sha_file(MAPPING_PATH),
        },
        "executable_oracle": {
            "path": ORACLE_PATH.relative_to(REPO_ROOT).as_posix(),
            "sha256": _sha_file(ORACLE_PATH),
        },
        "implementation": {
            "path": Path(__file__).resolve().relative_to(REPO_ROOT).as_posix(),
            "sha256": _sha_file(Path(__file__).resolve()),
        },
    }
    if input_bindings != expected_inputs:
        raise NativeParityError("native parity input binding differs")
    invocation = record.get("native_invocation")
    specs = []
    for pair_role, arm in (
        ("benign", "vulnerable"),
        ("benign", "protected"),
        ("adversarial", "vulnerable"),
        ("adversarial", "protected"),
    ):
        action = None
        if EXPECTED[(pair_role, arm)]["native_dispatch_count"] == 1:
            mapped = EXPECTED_ACTIONS[pair_role]
            action = {"function": mapped["op"], "args": mapped["args"]}
        specs.append({"pair_role": pair_role, "arm": arm, "action": action})
    if not isinstance(invocation, Mapping) or (
        invocation.get("interpreter") != str((RUNTIME_ROOT / "bin/python").resolve())
        or invocation.get("arguments_prefix") != ["-I", "-B", "-c"]
        or invocation.get("probe_source_sha256")
        != hashlib.sha256(_probe_source(specs).encode("utf-8")).hexdigest()
        or invocation.get("subprocess_returncode") != 0
        or invocation.get("stderr_sha256") != hashlib.sha256(b"").hexdigest()
    ):
        raise NativeParityError("native parity invocation binding differs")
    stdout_sha = invocation.get("stdout_sha256")
    if not isinstance(stdout_sha, str) or len(stdout_sha) != 64:
        raise NativeParityError("native parity stdout binding differs")
    bindings = record.get("callable_bindings")
    if not isinstance(bindings, list) or len(bindings) != 4:
        raise NativeParityError("native callable evidence differs")
    binding_map = {
        row.get("callable_ref"): row.get("source_sha256")
        for row in bindings
        if isinstance(row, Mapping)
    }
    if binding_map != EXPECTED_CALLABLE_SOURCES:
        raise NativeParityError("native callable evidence hash differs")
    for row in bindings:
        if not isinstance(row, Mapping) or not isinstance(
            row.get("source_path"), str
        ):
            raise NativeParityError("native callable source path differs")
        path = Path(row["source_path"]).resolve()
        try:
            path.relative_to(SOURCE_ROOT.resolve())
        except ValueError as exc:
            raise NativeParityError("native callable escapes source root") from exc
        if _sha_file(path) != row.get("source_sha256"):
            raise NativeParityError("native callable source bytes drifted")
    counts = record.get("execution_counts")
    if counts != {
        "api_calls": 0,
        "model_calls": 0,
        "native_checker_calls": 6,
        "native_dispatches": 3,
        "native_environment_constructions": 4,
        "network_attempts": 0,
        "provider_calls": 0,
        "security_checker_calls": 2,
        "utility_checker_calls": 4,
    }:
        raise NativeParityError("native parity execution counts differ")
    cells = record.get("cells")
    effects = record.get("independent_unauthorized_effect")
    if not isinstance(cells, list) or len(cells) != 4:
        raise NativeParityError("native parity cells differ")
    if not isinstance(effects, list) or len(effects) != 4:
        raise NativeParityError("independent effect rows differ")
    seen: set[tuple[str, str]] = set()
    for cell in cells:
        if not isinstance(cell, Mapping):
            raise NativeParityError("native parity cell is not an object")
        coordinate = (cell.get("pair_role"), cell.get("arm"))
        if coordinate not in EXPECTED or coordinate in seen:
            raise NativeParityError("native parity cell coordinate differs")
        seen.add(coordinate)
        parity = cell.get("numeric_parity")
        native = cell.get("native_checker")
        offline = cell.get("offline_checker")
        host_gate = cell.get("host_gate")
        if parity != {"utility": True, "security": True} or not isinstance(
            native, Mapping
        ):
            raise NativeParityError("native/offline numeric parity differs")
        if not isinstance(offline, Mapping) or (
            offline.get("utility") is not EXPECTED[coordinate]["utility"]
            or offline.get("security") is not EXPECTED[coordinate]["security"]
            or offline.get("native_callable_executed") is not False
            or offline.get("native_checker_parity_established") is not False
        ):
            raise NativeParityError("bound offline checker evidence differs")
        expected_dispatch_count = EXPECTED[coordinate]["native_dispatch_count"]
        if not isinstance(host_gate, Mapping) or host_gate != {
            "denied": EXPECTED[coordinate]["denied"],
            "decision_sequence": 1,
            "dispatch_sequence": 2 if expected_dispatch_count == 1 else None,
            "native_dispatch_count": expected_dispatch_count,
        }:
            raise NativeParityError("bound host gate evidence differs")
        if native.get("utility") is not EXPECTED[coordinate]["utility"] or native.get(
            "security"
        ) is not EXPECTED[coordinate]["security"]:
            raise NativeParityError("native checker matrix differs")
        expected_action = None
        if expected_dispatch_count == 1:
            mapped = EXPECTED_ACTIONS[coordinate[0]]
            expected_action = {"function": mapped["op"], "args": mapped["args"]}
        if (
            native.get("action") != expected_action
            or native.get("native_dispatch_count") != expected_dispatch_count
        ):
            raise NativeParityError("native action evidence differs")
        native_payload = {
            key: copy.deepcopy(row)
            for key, row in native.items()
            if key != "native_output_sha256"
        }
        if native.get("native_output_sha256") != sha256_json(native_payload):
            raise NativeParityError("native output evidence hash differs")
    if seen != set(EXPECTED):
        raise NativeParityError("native parity matrix is incomplete")
    effect_seen: set[tuple[str, str]] = set()
    for effect in effects:
        if not isinstance(effect, Mapping):
            raise NativeParityError("independent effect evidence differs")
        coordinate = (effect.get("pair_role"), effect.get("arm"))
        if coordinate not in EXPECTED or coordinate in effect_seen:
            raise NativeParityError("independent effect coordinate differs")
        effect_seen.add(coordinate)
        if (
            effect.get("occurred")
            is not EXPECTED[coordinate]["unauthorized_side_effect"]
            or effect.get("input_source") != "host_projected_trusted_events"
            or effect.get("native_security_consumed") is not False
            or effect.get("native_utility_consumed") is not False
        ):
            raise NativeParityError("independent effect replay differs")
        output_sha = effect.get("oracle_output_sha256")
        if not isinstance(output_sha, str) or len(output_sha) != 64:
            raise NativeParityError("independent effect output binding differs")
    if effect_seen != set(EXPECTED):
        raise NativeParityError("independent effect matrix is incomplete")
    separation = record.get("semantic_separation")
    if not isinstance(separation, Mapping) or any(
        separation.get(name) is not False
        for name in (
            "native_security_used_for_admission",
            "native_security_used_for_unauthorized_effect",
            "native_utility_used_for_admission",
        )
    ):
        raise NativeParityError("native/effect separation differs")
    if (
        separation.get("numeric_parity_does_not_assert_semantic_equivalence")
        is not True
    ):
        raise NativeParityError("native/effect semantic caveat is missing")
    canonical_json_bytes(record)
    return record


def write_native_parity_record(path: Path, record: Mapping[str, Any]) -> str:
    """Write one canonical parity record without replacing prior evidence."""

    validate_native_parity_record(record)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json_bytes(dict(record)) + b"\n"
    try:
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    except FileExistsError as exc:
        raise NativeParityError(
            f"refusing to overwrite parity record: {target}"
        ) from exc
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    return hashlib.sha256(payload).hexdigest()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-root", type=Path, default=RUNTIME_ROOT)
    parser.add_argument("--gate", type=Path, default=ZERO_TOKEN_GATE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    arguments = parser.parse_args(argv)
    record = run_native_checker_parity(
        runtime_root=arguments.runtime_root,
        gate_path=arguments.gate,
    )
    digest = write_native_parity_record(arguments.output, record)
    print(
        json.dumps(
            {
                "native_callable_executed": True,
                "native_checker_parity_established": True,
                "output": str(arguments.output.resolve()),
                "sha256": digest,
                "execution_counts": record["execution_counts"],
                "public_real_api_decision": "NO_GO",
                "real_public_execution_authorized": False,
            },
            sort_keys=True,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "DEFAULT_OUTPUT",
    "NativeParityError",
    "run_native_checker_parity",
    "validate_native_parity_record",
    "write_native_parity_record",
]
