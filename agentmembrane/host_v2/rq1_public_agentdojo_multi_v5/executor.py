"""Durable 28-cell executor for the RQ1 v5 weak-model baseline.

The executor is provider-capable but provider-agnostic: callers supply one
fresh completion client per cell.  Tests use :class:`OfflineScriptedClient`,
which has no network implementation.  Every provider call is durably reserved
before delegation and receives an immutable terminal record after return or a
normal exception.  A reservation without a terminal record is conservatively
consumed and is never retried during recovery.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Callable, Mapping, Protocol, Sequence

from ...proxy import Completion
from ..agentdojo_adapter import AgentDojoAdapter
from ..agentdojo_runtime import (
    AGENTDOJO_RUNTIME_ID,
    FROZEN_PYTHON_EXECUTABLE,
    FROZEN_PYTHON_SHA256,
    FROZEN_PYTHON_VERSION,
)
from .client import ExactRQ1GPT54MiniLowClient
from ..runtime_provisioning import load_provisioning_receipt
from ..schema import IntegrityError, SchemaError, canonical_json_bytes, sha256_json
from .contracts import contracts_manifest
from .gate import validate_integration_gate
from .provider_agent import (
    MAX_COMPLETION_TOKENS,
    MODEL_ID,
    REASONING_EFFORT,
    REQUEST_RETRIES,
    SYSTEM_PROMPT,
    ProviderBackedOrdinaryMultiSourceAgent,
    ProviderCallError,
    ProviderResponseContractError,
    ProviderResponseParseError,
)
from .attack_baseline import attack_baseline_manifest
from .adapter import ToolKnowledgeAgentDojoAdapter
from .attribution import attribute_attack
from .runtime import FrozenNativeSession
from .runtime_receipt import (
    V4_RECEIPT_FILENAME,
    V4_RUNTIME_ENVIRONMENT_NAME,
    v4_runtime_expectation,
    validate_v5_runtime_receipt,
)
from .selector import EngineeringCell, engineering_smoke_schedule, selector_manifest


SCHEMA_VERSION = 1
PROFILE_ARTIFACT_TYPE = "agentmembrane_rq1_multi_source_real_profile_v5"
AUTHORIZATION_ARTIFACT_TYPE = "agentmembrane_rq1_multi_source_real_authorization_v5"
CONSUMPTION_ARTIFACT_TYPE = (
    "agentmembrane_rq1_multi_source_authorization_consumption_v5"
)
CELL_ARTIFACT_TYPE = "agentmembrane_rq1_multi_source_cell_v5"
REPORT_ARTIFACT_TYPE = "agentmembrane_rq1_multi_source_report_v5"
CALL_RESERVATION_ARTIFACT_TYPE = "agentmembrane_rq1_multi_source_call_reservation_v5"
CALL_TERMINAL_ARTIFACT_TYPE = "agentmembrane_rq1_multi_source_call_terminal_v5"
CELL_COUNT = 28
MAX_TURNS_PER_CELL = 6
GLOBAL_CALL_CAP = 168
CANARY_CELL_COUNT = 2
CANARY_CALL_CAP = 12
CONTINUATION_CELL_COUNT = 26
CONTINUATION_CALL_CAP = 156
CANARY_ORDINALS = (3, 4)
MAX_PROVIDER_USER_BYTES = 1_048_576
_NAMESPACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{5,96}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PARSED_RESPONSE_STATUSES = frozenset(
    {
        "parsed_exact_union",
        "parsed_single_trailing_brace_repair",
    }
)
_FAILED_RESPONSE_STATUSES = {
    "json_parse_failed": (
        "response_parse_error",
        ProviderResponseParseError.failure_class,
        ProviderResponseParseError.__name__,
    ),
    "json_parse_failed_after_single_trailing_brace_repair": (
        "response_parse_error",
        ProviderResponseParseError.failure_class,
        ProviderResponseParseError.__name__,
    ),
    "union_contract_failed": (
        "response_contract_error",
        ProviderResponseContractError.failure_class,
        ProviderResponseContractError.__name__,
    ),
    "union_contract_failed_after_single_trailing_brace_repair": (
        "response_contract_error",
        ProviderResponseContractError.failure_class,
        ProviderResponseContractError.__name__,
    ),
}
_PINNED_RUNTIME_RELATIVE = Path(
    "experiments/host_boundary_v2/runtime_envs"
) / V4_RUNTIME_ENVIRONMENT_NAME
_PINNED_PYTHON_RELATIVE = _PINNED_RUNTIME_RELATIVE / "bin/python"
_PINNED_RECEIPT_RELATIVE = Path(
    "experiments/host_boundary_v2/runtime_envs/receipts"
) / V4_RECEIPT_FILENAME
_CODE_RELATIVE_PATHS = {
    "agentdojo_adapter": Path("agentmembrane/host_v2/agentdojo_adapter.py"),
    "agentdojo_runtime": Path("agentmembrane/host_v2/agentdojo_runtime.py"),
    "analysis": Path("agentmembrane/host_v2/rq1_public_agentdojo_multi_v5/analysis.py"),
    "attack_attribution": Path(
        "agentmembrane/host_v2/rq1_public_agentdojo_multi_v5/attribution.py"
    ),
    "attack_baseline": Path(
        "agentmembrane/host_v2/rq1_public_agentdojo_multi_v5/attack_baseline.py"
    ),
    "attack_adapter": Path(
        "agentmembrane/host_v2/rq1_public_agentdojo_multi_v5/adapter.py"
    ),
    "contracts": Path(
        "agentmembrane/host_v2/rq1_public_agentdojo_multi_v5/contracts.py"
    ),
    "domain_authority_banking": Path(
        "agentmembrane/host_v2/rq1_public_agentdojo_multi_v3/"
        "domain_authority/banking.py"
    ),
    "domain_authority_core": Path(
        "agentmembrane/host_v2/rq1_public_agentdojo_multi_v3/"
        "domain_authority/core.py"
    ),
    "domain_authority_slack": Path(
        "agentmembrane/host_v2/rq1_public_agentdojo_multi_v3/"
        "domain_authority/slack.py"
    ),
    "domain_authority_travel": Path(
        "agentmembrane/host_v2/rq1_public_agentdojo_multi_v3/"
        "domain_authority/travel.py"
    ),
    "domain_authority_workspace": Path(
        "agentmembrane/host_v2/rq1_public_agentdojo_multi_v3/"
        "domain_authority/workspace.py"
    ),
    "domain_witness_banking": Path(
        "agentmembrane/host_v2/rq1_public_agentdojo_multi_v3/"
        "domain_witnesses/banking.py"
    ),
    "domain_witness_slack": Path(
        "agentmembrane/host_v2/rq1_public_agentdojo_multi_v3/"
        "domain_witnesses/slack.py"
    ),
    "domain_witness_travel": Path(
        "agentmembrane/host_v2/rq1_public_agentdojo_multi_v3/"
        "domain_witnesses/travel.py"
    ),
    "domain_witness_workspace": Path(
        "agentmembrane/host_v2/rq1_public_agentdojo_multi_v3/"
        "domain_witnesses/workspace.py"
    ),
    "executor": Path("agentmembrane/host_v2/rq1_public_agentdojo_multi_v5/executor.py"),
    "gate": Path("agentmembrane/host_v2/rq1_public_agentdojo_multi_v5/gate.py"),
    "provider_agent": Path(
        "agentmembrane/host_v2/rq1_public_agentdojo_multi_v5/provider_agent.py"
    ),
    "production_client": Path(
        "agentmembrane/host_v2/rq1_public_agentdojo_multi_v5/client.py"
    ),
    "proxy": Path("agentmembrane/proxy.py"),
    "rq1_smoke": Path("agentmembrane/host_v2/rq1_smoke.py"),
    "runtime_provisioning": Path("agentmembrane/host_v2/runtime_provisioning.py"),
    "runtime": Path("agentmembrane/host_v2/rq1_public_agentdojo_multi_v5/runtime.py"),
    "runtime_receipt": Path(
        "agentmembrane/host_v2/rq1_public_agentdojo_multi_v5/runtime_receipt.py"
    ),
    "selector": Path("agentmembrane/host_v2/rq1_public_agentdojo_multi_v5/selector.py"),
}


class MultiSourceExecutorError(IntegrityError):
    """The execution contract or its durable ledger is invalid."""


class MultiSourceGlobalFatal(MultiSourceExecutorError):
    """Isolation or the frozen global call budget cannot be guaranteed."""


class CompletionClient(Protocol):
    def complete(self, **kwargs: Any) -> Completion:
        ...


ClientFactory = Callable[[EngineeringCell], CompletionClient]
SessionFactory = Callable[..., Any]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise MultiSourceExecutorError(
            f"cannot hash implementation file {path}"
        ) from exc


def _inside(root: Path, candidate: Path, *, label: str) -> Path:
    resolved_root = root.resolve()
    resolved = candidate.resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise MultiSourceExecutorError(f"{label} escapes repository root") from exc
    return resolved


def _validated_gate_receipt(
    repo_root: Path, value: Mapping[str, Any] | Path | str
) -> tuple[dict[str, Any], str]:
    """Load and live-validate the complete zero-token gate receipt."""

    root = Path(repo_root).resolve()
    if isinstance(value, (Path, str)):
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = root / candidate
        candidate = _inside(root, candidate, label="integration gate receipt")
        record = _read_object(candidate, "integration gate receipt")
        try:
            raw = candidate.read_bytes()
        except OSError as exc:
            raise MultiSourceExecutorError(
                "cannot read integration gate receipt"
            ) from exc
        canonical = canonical_json_bytes(record)
        if raw not in {canonical, canonical + b"\n"}:
            raise MultiSourceExecutorError(
                "integration gate receipt path is not canonical JSON"
            )
    elif isinstance(value, Mapping):
        record = copy.deepcopy(dict(value))
    else:
        raise MultiSourceExecutorError(
            "integration gate receipt must be a mapping or repository path"
        )
    try:
        validated = validate_integration_gate(record)
    except Exception as exc:
        raise MultiSourceExecutorError(
            "integration gate receipt failed live validation"
        ) from exc
    if not isinstance(validated, dict):
        raise MultiSourceExecutorError("integration gate validator returned no object")
    canonical_json_bytes(validated)
    return copy.deepcopy(validated), sha256_json(validated)


def _adapter_preflight_under_pinned_python(root: Path) -> dict[str, Any]:
    launcher = root / _PINNED_PYTHON_RELATIVE
    script = (
        "import json,sys\n"
        f"sys.path.insert(0,{str(root)!r})\n"
        "from agentmembrane.host_v2.rq1_public_agentdojo_multi_v5.adapter "
        "import ToolKnowledgeAgentDojoAdapter\n"
        "print(json.dumps(ToolKnowledgeAgentDojoAdapter().preflight(),sort_keys=True,"
        "separators=(',',':')))\n"
    )
    try:
        completed = subprocess.run(
            [str(launcher), "-I", "-B", "-c", script],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        value = json.loads(completed.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        raise MultiSourceExecutorError(
            "pinned AgentDojo adapter preflight could not be executed"
        ) from exc
    if not isinstance(value, dict):
        raise MultiSourceExecutorError("pinned adapter preflight is not an object")
    return value


def _runtime_binding(
    repo_root: Path, *, require_active_process: bool
) -> dict[str, Any]:
    """Revalidate the exact provisioned interpreter, receipt, and adapter."""

    root = Path(repo_root).resolve()
    environment = root / _PINNED_RUNTIME_RELATIVE
    launcher = root / _PINNED_PYTHON_RELATIVE
    receipt_path = root / _PINNED_RECEIPT_RELATIVE
    if (
        not launcher.is_file()
        or launcher.resolve() != FROZEN_PYTHON_EXECUTABLE.resolve()
        or _sha(launcher) != FROZEN_PYTHON_SHA256
    ):
        raise MultiSourceExecutorError("pinned AgentDojo Python binding differs")
    if require_active_process and (
        Path(sys.executable).absolute() != launcher.absolute()
        or Path(sys.prefix).resolve() != environment.resolve()
        or sys.dont_write_bytecode is not True
        or ".".join(str(part) for part in sys.version_info[:3]) != FROZEN_PYTHON_VERSION
    ):
        raise MultiSourceGlobalFatal(
            "production execution requires the fixed AgentDojo Python launcher"
        )
    try:
        validated_receipt = load_provisioning_receipt(
            receipt_path,
            expectation=v4_runtime_expectation(repo_root=root),
            expected_receipt_sha256=_sha(receipt_path),
            verify_live_files=True,
        )
        import_preflight = validate_v5_runtime_receipt(
            validated_receipt.receipt.as_json(),
            expected_receipt_sha256=validated_receipt.receipt_sha256,
            repo_root=root,
        )
    except Exception as exc:
        raise MultiSourceExecutorError(
            "pinned AgentDojo provisioning receipt failed validation"
        ) from exc
    if (
        import_preflight.get("import_executable") is not True
        or import_preflight.get("checker_dispatchers_importable") is not True
        or import_preflight.get("runtime_id") != AGENTDOJO_RUNTIME_ID
    ):
        raise MultiSourceExecutorError(
            "pinned AgentDojo import preflight is not executable"
        )
    adapter_preflight = (
        dict(ToolKnowledgeAgentDojoAdapter().preflight())
        if require_active_process
        else _adapter_preflight_under_pinned_python(root)
    )
    checks = adapter_preflight.get("checks")
    if (
        adapter_preflight.get("executable") is not True
        or adapter_preflight.get("adapter_id")
        != ToolKnowledgeAgentDojoAdapter.adapter_id
        or not isinstance(checks, Mapping)
        or any(value is not True for value in checks.values())
    ):
        raise MultiSourceExecutorError("pinned AgentDojo adapter preflight differs")
    result = {
        "runtime_id": AGENTDOJO_RUNTIME_ID,
        "environment_root": _PINNED_RUNTIME_RELATIVE.as_posix(),
        "python_launcher": _PINNED_PYTHON_RELATIVE.as_posix(),
        "python_version": FROZEN_PYTHON_VERSION,
        "python_executable_sha256": FROZEN_PYTHON_SHA256,
        "provisioning_receipt_path": _PINNED_RECEIPT_RELATIVE.as_posix(),
        "provisioning_receipt_sha256": validated_receipt.receipt_sha256,
        "import_preflight_sha256": sha256_json(import_preflight),
        "adapter_preflight_sha256": sha256_json(adapter_preflight),
        "adapter_implementation_sha256": adapter_preflight.get("implementation_sha256"),
        "upstream_version_or_commit": adapter_preflight.get(
            "upstream_version_or_commit"
        ),
        "source_and_pack_locks_exact": bool(
            checks.get("source_locks_exact") is True
            and checks.get("pack_locks_exact") is True
        ),
    }
    canonical_json_bytes(result)
    return result


def _write_new(path: Path, value: Any) -> str:
    payload = canonical_json_bytes(value) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        raise MultiSourceGlobalFatal(
            f"cannot create immutable artifact {path}"
        ) from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    return hashlib.sha256(payload).hexdigest()


def _read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MultiSourceExecutorError(f"cannot read {label}") from exc
    if not isinstance(value, dict):
        raise MultiSourceExecutorError(f"{label} must be a JSON object")
    canonical_json_bytes(value)
    return value


def _schedule() -> tuple[EngineeringCell, ...]:
    cells = engineering_smoke_schedule()
    if (
        len(cells) != CELL_COUNT
        or tuple(cell.execution_ordinal for cell in cells)
        != tuple(range(1, CELL_COUNT + 1))
        or len({cell.cell_id for cell in cells}) != CELL_COUNT
    ):
        raise MultiSourceExecutorError(
            "selector did not return the frozen 28-cell schedule"
        )
    return cells


def _canary_cells() -> tuple[EngineeringCell, ...]:
    by_ordinal = {int(cell.execution_ordinal or 0): cell for cell in _schedule()}
    try:
        cells = tuple(by_ordinal[ordinal] for ordinal in CANARY_ORDINALS)
    except KeyError as exc:
        raise MultiSourceExecutorError(
            "matched-pair canary ordinal is unavailable"
        ) from exc
    if (
        len(cells) != CANARY_CELL_COUNT
        or len({cell.workflow_key for cell in cells}) != 1
        or {cell.pair_role for cell in cells} != {"adversarial"}
        or {cell.host_arm for cell in cells} != {"vulnerable", "protected"}
    ):
        raise MultiSourceExecutorError(
            "canary must be one matched adversarial vulnerable/protected pair"
        )
    return cells


def _continuation_cells() -> tuple[EngineeringCell, ...]:
    canary_ids = {cell.cell_id for cell in _canary_cells()}
    cells = tuple(cell for cell in _schedule() if cell.cell_id not in canary_ids)
    if len(cells) != CONTINUATION_CELL_COUNT:
        raise MultiSourceExecutorError("continuation schedule must contain 26 cells")
    return cells


def build_profile_document(
    repo_root: Path,
    *,
    gate_receipt: Mapping[str, Any] | Path | str,
) -> dict[str, Any]:
    """Recompute the exact non-claiming execution profile without authorizing it."""

    root = Path(repo_root).resolve()
    validated_gate, gate_receipt_sha256 = _validated_gate_receipt(root, gate_receipt)
    runtime_binding = _runtime_binding(root, require_active_process=False)
    code_bindings = {
        name: {"path": relative.as_posix(), "sha256": _sha(root / relative)}
        for name, relative in sorted(_CODE_RELATIVE_PATHS.items())
    }
    cells = _schedule()
    profile = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": PROFILE_ARTIFACT_TYPE,
        "profile_id": "rq1-agentdojo-gpt54mini-low-tool-knowledge-v5",
        "execution_authorized_by_profile": False,
        "claim_eligible": False,
        "selector_manifest_sha256": sha256_json(selector_manifest()),
        "source_contracts_sha256": sha256_json(contracts_manifest()),
        "attack_baseline": attack_baseline_manifest(),
        "integration_gate": {
            "gate_id": validated_gate.get("gate_id"),
            "gate_sha256": validated_gate.get("gate_sha256"),
            "canonical_receipt_sha256": gate_receipt_sha256,
        },
        "runtime_binding": runtime_binding,
        "code_bindings": code_bindings,
        "model_contract": {
            "model": MODEL_ID,
            "reasoning_effort": REASONING_EFFORT,
            "max_completion_tokens": MAX_COMPLETION_TOKENS,
            "request_retries": REQUEST_RETRIES,
        },
        "execution_contract": {
            "cell_count": CELL_COUNT,
            "maximum_turns_per_cell": MAX_TURNS_PER_CELL,
            "maximum_provider_user_bytes": MAX_PROVIDER_USER_BYTES,
            "global_call_hard_cap": GLOBAL_CALL_CAP,
            "fresh_session_per_cell": True,
            "fresh_client_per_cell": True,
            "continuation_independent_of_utility_security_direction": True,
            "continuation_requires_operational_canary_pass": True,
            "orphan_reservation_policy": "indeterminate_consumed_never_retry",
            "canary_ordinals": list(CANARY_ORDINALS),
            "cell_ids": [cell.cell_id for cell in cells],
        },
    }
    canonical_json_bytes(profile)
    return profile


def build_authorization_document(
    *, profile: Mapping[str, Any], namespace: str
) -> dict[str, Any]:
    """Return the exact two-stage grant; execution still requires these bytes."""

    if not isinstance(namespace, str) or _NAMESPACE.fullmatch(namespace) is None:
        raise MultiSourceExecutorError("namespace must be one fresh safe component")
    canary_cells = _canary_cells()
    continuation_cells = _continuation_cells()
    profile_copy = copy.deepcopy(dict(profile))
    canonical_json_bytes(profile_copy)
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": AUTHORIZATION_ARTIFACT_TYPE,
        "authorization_id": f"{namespace}-authorization-v5",
        "decision": "AUTHORIZE_EXACT_28_CELL_GPT54MINI_LOW_RUN",
        "execution_authorized": True,
        "namespace": namespace,
        "profile_sha256": sha256_json(profile_copy),
        "selector_manifest_sha256": profile_copy.get("selector_manifest_sha256"),
        "source_contracts_sha256": profile_copy.get("source_contracts_sha256"),
        "integration_gate": copy.deepcopy(profile_copy.get("integration_gate")),
        "runtime_binding": copy.deepcopy(profile_copy.get("runtime_binding")),
        "code_bindings": copy.deepcopy(profile_copy.get("code_bindings")),
        "grants": {
            "canary": {
                "cell_ids": [cell.cell_id for cell in canary_cells],
                "execution_ordinals": list(CANARY_ORDINALS),
                "cell_count": CANARY_CELL_COUNT,
                "call_hard_cap": CANARY_CALL_CAP,
            },
            "continuation": {
                "cell_ids": [cell.cell_id for cell in continuation_cells],
                "execution_ordinals": [
                    int(cell.execution_ordinal or 0) for cell in continuation_cells
                ],
                "cell_count": CONTINUATION_CELL_COUNT,
                "call_hard_cap": CONTINUATION_CALL_CAP,
            },
        },
        "global_call_hard_cap": GLOBAL_CALL_CAP,
        "zero_retry": True,
        "partial_cell_never_retried": True,
        "continuation_independent_of_utility_security_direction": True,
        "continuation_requires_operational_canary_pass": True,
        "claim_eligible": False,
    }


def _validate_documents(
    *,
    repo_root: Path,
    namespace: str,
    gate_receipt: Mapping[str, Any] | Path | str,
    profile: Mapping[str, Any],
    authorization: Mapping[str, Any],
    production: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    expected_profile = build_profile_document(repo_root, gate_receipt=gate_receipt)
    supplied_profile = copy.deepcopy(dict(profile))
    if canonical_json_bytes(supplied_profile) != canonical_json_bytes(expected_profile):
        raise MultiSourceExecutorError("profile differs from live source/code bindings")
    expected_authorization = build_authorization_document(
        profile=expected_profile, namespace=namespace
    )
    supplied_authorization = copy.deepcopy(dict(authorization))
    if canonical_json_bytes(supplied_authorization) != canonical_json_bytes(
        expected_authorization
    ):
        raise MultiSourceExecutorError("authorization differs from the exact grant")
    if production:
        live_runtime = _runtime_binding(repo_root, require_active_process=True)
        if live_runtime != expected_profile.get("runtime_binding"):
            raise MultiSourceGlobalFatal("live production runtime differs from profile")
    return expected_profile, expected_authorization


def _reserve_namespace(
    *,
    output_root: Path,
    namespace: str,
    profile: Mapping[str, Any],
    authorization: Mapping[str, Any],
) -> Path:
    root = Path(output_root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    target = root / namespace
    try:
        target.mkdir(mode=0o700, exist_ok=False)
    except FileExistsError as exc:
        raise MultiSourceGlobalFatal("execution namespace is not fresh") from exc
    if target.resolve().parent != root:
        raise MultiSourceGlobalFatal("execution namespace escapes output root")
    _write_new(target / "profile.json", profile)
    _write_new(target / "authorization.json", authorization)
    _write_new(
        target / "authorization-consumed.json",
        {
            "schema_version": SCHEMA_VERSION,
            "artifact_type": CONSUMPTION_ARTIFACT_TYPE,
            "authorization_id": authorization["authorization_id"],
            "profile_sha256": sha256_json(profile),
            "authorization_sha256": sha256_json(authorization),
            "consumption_semantics": "namespace_creation_consumes_exact_grants",
            "consumed_at": _utc_now(),
        },
    )
    _write_new(target / "schedule.json", [cell.private_json() for cell in _schedule()])
    (target / "cells").mkdir(mode=0o700)
    (target / "attempts").mkdir(mode=0o700)
    return target


def _reservation_paths(root: Path) -> list[Path]:
    return sorted((root / "attempts").glob("cell-*/turn-*.reservation.json"))


def _terminal_paths(root: Path) -> list[Path]:
    return sorted((root / "attempts").glob("cell-*/turn-*.terminal.json"))


class _DurableCompletionClient:
    """Charge a grant before one zero-retry provider delegation."""

    def __init__(
        self,
        *,
        delegate: CompletionClient,
        root: Path,
        cell: EngineeringCell,
        production: bool,
    ) -> None:
        self.delegate = delegate
        self.root = root
        self.cell = cell
        self.production = production
        self.calls_made = 0

    def complete(self, **kwargs: Any) -> Completion:
        if (
            set(kwargs)
            != {
                "model",
                "system",
                "user",
                "max_completion_tokens",
                "retries",
                "reasoning_effort",
            }
            or kwargs.get("model") != MODEL_ID
            or kwargs.get("system") != SYSTEM_PROMPT
            or kwargs.get("max_completion_tokens") != MAX_COMPLETION_TOKENS
            or kwargs.get("reasoning_effort") != REASONING_EFFORT
            or kwargs.get("retries") != 0
        ):
            raise MultiSourceGlobalFatal(
                "provider request differs from frozen zero-retry contract"
            )
        user = kwargs.get("user")
        if (
            not isinstance(user, str)
            or len(user.encode("utf-8")) > MAX_PROVIDER_USER_BYTES
        ):
            raise MultiSourceGlobalFatal(
                "provider user payload exceeds the frozen byte cap"
            )
        existing = len(_reservation_paths(self.root))
        ordinal = int(self.cell.execution_ordinal or 0)
        grant_name = "canary" if ordinal in CANARY_ORDINALS else "continuation"
        grant_cap = CANARY_CALL_CAP if grant_name == "canary" else CONTINUATION_CALL_CAP
        grant_reservations = sum(
            (int(path.parent.name.split("-")[1]) in CANARY_ORDINALS)
            == (grant_name == "canary")
            for path in _reservation_paths(self.root)
        )
        if existing >= GLOBAL_CALL_CAP or grant_reservations >= grant_cap:
            raise MultiSourceGlobalFatal("provider call hard cap is exhausted")
        self.calls_made += 1
        turn = self.calls_made
        if turn > MAX_TURNS_PER_CELL:
            raise MultiSourceGlobalFatal("cell exceeded six provider calls")
        attempt_dir = self.root / "attempts" / f"cell-{ordinal:02d}"
        reservation_path = attempt_dir / f"turn-{turn:02d}.reservation.json"
        terminal_path = attempt_dir / f"turn-{turn:02d}.terminal.json"
        request = copy.deepcopy(kwargs)
        request_sha256 = sha256_json(request)
        attempt_id = f"{self.cell.cell_id}:turn-{turn:02d}"
        request_identity = {
            "attempt_id": attempt_id,
            "cell_id": self.cell.cell_id,
            "cell_ordinal": ordinal,
            "turn": turn,
            "grant": grant_name,
            "request_sha256": request_sha256,
            "model": MODEL_ID,
            "system_sha256": hashlib.sha256(SYSTEM_PROMPT.encode("utf-8")).hexdigest(),
            "user_sha256": hashlib.sha256(user.encode("utf-8")).hexdigest(),
            "user_bytes": len(user.encode("utf-8")),
            "client_class": (
                f"{type(self.delegate).__module__}."
                f"{type(self.delegate).__qualname__}"
            ),
        }
        _write_new(
            reservation_path,
            {
                "schema_version": SCHEMA_VERSION,
                "artifact_type": CALL_RESERVATION_ARTIFACT_TYPE,
                **request_identity,
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
            return completion
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit, GeneratorExit)):
                raise
            error = exc
            raise
        finally:
            if completion is not None or error is not None:
                delegate_calls = getattr(self.delegate, "calls_made", None)
                client_call_reconciled = delegate_calls == turn
                usage = None
                if completion is not None:
                    usage = {
                        "input_tokens": completion.input_tokens,
                        "output_tokens": completion.output_tokens,
                        "total_tokens": completion.total_tokens,
                    }
                _write_new(
                    terminal_path,
                    {
                        "schema_version": SCHEMA_VERSION,
                        "artifact_type": CALL_TERMINAL_ARTIFACT_TYPE,
                        **request_identity,
                        "status": "returned"
                        if completion is not None
                        else "provider_error",
                        "completion_model": completion.model
                        if completion is not None
                        else None,
                        "completion_latency_ms": completion.latency_ms
                        if completion is not None
                        else None,
                        "completion_text_sha256": (
                            hashlib.sha256(completion.text.encode("utf-8")).hexdigest()
                            if completion is not None
                            and isinstance(completion.text, str)
                            else None
                        ),
                        "usage": usage,
                        "usage_known": bool(
                            usage is not None
                            and all(
                                type(value) is int and value >= 0
                                for value in usage.values()
                            )
                        ),
                        "delegate_calls_made": delegate_calls,
                        "client_call_reconciled": client_call_reconciled,
                        "error_type": type(error).__name__
                        if error is not None
                        else None,
                        "finished_at": _utc_now(),
                    },
                )
                if self.production and not client_call_reconciled:
                    raise MultiSourceGlobalFatal(
                        "exact client call counter differs from durable ledger"
                    )


def _append_tool_feedback(
    messages: list[dict[str, Any]],
    *,
    action: Mapping[str, Any],
    dispatch: Mapping[str, Any],
) -> None:
    messages.append(
        {
            "role": "assistant",
            "tool_call": copy.deepcopy(dict(action)),
        }
    )
    messages.append(
        {
            "role": "tool",
            "name": action["function"],
            # The runtime owns this condition-neutral observation. Host-private
            # denial reasons and authority evidence never enter model context.
            "content": copy.deepcopy(dispatch.get("observation")),
        }
    )


def _run_cell(
    *,
    root: Path,
    cell: EngineeringCell,
    client_factory: ClientFactory,
    session_factory: SessionFactory,
    production: bool,
) -> dict[str, Any]:
    ordinal = int(cell.execution_ordinal or 0)
    started_at = _utc_now()
    status = "completed"
    failure: dict[str, Any] | None = None
    final_text = ""
    terminal_reason = "budget_exhausted"
    actions: list[dict[str, Any]] = []
    dispatches: list[dict[str, Any]] = []
    checker: dict[str, Any] | None = None
    cleanup_sha: str | None = None
    session: Any | None = None
    agent: ProviderBackedOrdinaryMultiSourceAgent | None = None
    client: CompletionClient | None = None
    calls_before = len(_reservation_paths(root))
    try:
        client = client_factory(cell)
        if not callable(getattr(client, "complete", None)):
            raise TypeError("client factory returned no complete()")
        if production and type(client) is not ExactRQ1GPT54MiniLowClient:
            raise MultiSourceGlobalFatal(
                "production client factory returned a non-exact client"
            )
        if getattr(client, "calls_made", None) != 0:
            raise MultiSourceGlobalFatal("client factory returned a non-fresh client")
        durable = _DurableCompletionClient(
            delegate=client,
            root=root,
            cell=cell,
            production=production,
        )
        agent = ProviderBackedOrdinaryMultiSourceAgent(durable)
        session = session_factory(
            source_task_id=cell.source_task_id,
            pair_role=cell.pair_role,
            arm=cell.host_arm,
        )
        session.reset()
        visible = session.read()
        messages = copy.deepcopy(visible["messages"])
        tools = copy.deepcopy(visible["tools"])
        for turn in range(1, MAX_TURNS_PER_CELL + 1):
            try:
                response = agent.respond(messages=messages, tools=tools)
            except ProviderCallError as exc:
                if isinstance(exc.__cause__, MultiSourceGlobalFatal):
                    raise exc.__cause__
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
                "id": f"cell-{ordinal:02d}-turn-{turn:02d}",
            }
            actions.append(copy.deepcopy(action))
            try:
                dispatch_result = session.dispatch(action)
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
            dispatch = dispatch_result.as_json()
            dispatches.append(copy.deepcopy(dispatch))
            _append_tool_feedback(messages, action=action, dispatch=dispatch)
        if status == "completed":
            try:
                checker = session.evaluate_final(
                    final_assistant_text=final_text,
                    terminal_reason=terminal_reason,
                )
            except Exception as exc:
                status = "native_checker_failure"
                failure = {"type": type(exc).__name__}
    except MultiSourceGlobalFatal:
        raise
    except MultiSourceExecutorError as exc:
        status = "integrity_failure"
        terminal_reason = "cell_integrity_failure"
        failure = {"type": type(exc).__name__}
    except Exception as exc:
        status = "native_failure"
        terminal_reason = "session_or_client_initialization_failure"
        failure = {"type": type(exc).__name__}
    finally:
        if session is not None:
            try:
                cleanup_sha = session.cleanup()
            except Exception as exc:
                if failure is None:
                    status = "native_cleanup_failure"
                    failure = {"type": type(exc).__name__}
    calls_after = len(_reservation_paths(root))
    record = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": CELL_ARTIFACT_TYPE,
        "assignment": cell.private_json(),
        "status": status,
        "failure": failure,
        "terminal_reason": terminal_reason,
        "final_text_sha256": hashlib.sha256(final_text.encode("utf-8")).hexdigest(),
        "proposed_native_actions": actions,
        "dispatch_results": dispatches,
        "provider_request_records": (
            copy.deepcopy(agent.request_records) if agent is not None else []
        ),
        "provider_request_count": agent.request_count if agent is not None else 0,
        "provider_call_reservations": calls_after - calls_before,
        "native_checker_observed": copy.deepcopy(checker),
        "cleanup_sha256": cleanup_sha,
        "metrics_contract": {
            "checker_values_are_observed_only": True,
            "expected_direction_asserted": False,
            "provider_failure_counted_as_safety": False,
            "parse_failure_counted_as_safety": False,
            "abstention_counted_as_safety": False,
        },
        "started_at": started_at,
        "finished_at": _utc_now(),
    }
    record["attack_attribution"] = (
        attribute_attack(record, workflow_key=cell.workflow_key)
        if cell.pair_role == "adversarial"
        else None
    )
    canonical_json_bytes(record)
    return record


def _indeterminate_cell(root: Path, cell: EngineeringCell) -> dict[str, Any]:
    ordinal = int(cell.execution_ordinal or 0)
    reservations = sorted(
        (root / "attempts" / f"cell-{ordinal:02d}").glob("turn-*.reservation.json")
    )
    terminals = sorted(
        (root / "attempts" / f"cell-{ordinal:02d}").glob("turn-*.terminal.json")
    )
    record = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": CELL_ARTIFACT_TYPE,
        "assignment": cell.private_json(),
        "status": "indeterminate_consumed",
        "failure": {"type": "OrphanCallReservation"},
        "terminal_reason": "orphan_reservation_never_retried",
        "final_text_sha256": None,
        "proposed_native_actions": [],
        "dispatch_results": [],
        "provider_request_records": [],
        "provider_request_count": 0,
        "provider_call_reservations": len(reservations),
        "provider_terminal_records": len(terminals),
        "native_checker_observed": None,
        "cleanup_sha256": None,
        "metrics_contract": {
            "checker_values_are_observed_only": True,
            "expected_direction_asserted": False,
            "provider_failure_counted_as_safety": False,
            "parse_failure_counted_as_safety": False,
            "abstention_counted_as_safety": False,
        },
        "started_at": None,
        "finished_at": _utc_now(),
    }
    record["attack_attribution"] = (
        attribute_attack(record, workflow_key=cell.workflow_key)
        if cell.pair_role == "adversarial"
        else None
    )
    return record


def _attempt_path_coordinate(path: Path, *, kind: str) -> tuple[int, int]:
    parent = re.fullmatch(r"cell-([0-9]{2})", path.parent.name)
    name = re.fullmatch(rf"turn-([0-9]{{2}})\.{kind}\.json", path.name)
    if parent is None or name is None:
        raise MultiSourceGlobalFatal("attempt ledger path identity is invalid")
    return int(parent.group(1)), int(name.group(1))


def _usage_summary(
    root: Path, *, cell_ordinals: frozenset[int] | None = None
) -> dict[str, Any]:
    reservations = _reservation_paths(root)
    terminals = _terminal_paths(root)
    if cell_ordinals is not None:
        reservations = [
            path
            for path in reservations
            if int(path.parent.name.split("-")[1]) in cell_ordinals
        ]
        terminals = [
            path
            for path in terminals
            if int(path.parent.name.split("-")[1]) in cell_ordinals
        ]
    reservation_values = [
        _read_object(path, "call reservation") for path in reservations
    ]
    terminal_values = [_read_object(path, "call terminal") for path in terminals]
    reservation_by_attempt: dict[str, dict[str, Any]] = {}
    cell_id_by_ordinal = {
        int(cell.execution_ordinal or 0): cell.cell_id for cell in _schedule()
    }
    identity_fields = (
        "attempt_id",
        "cell_id",
        "cell_ordinal",
        "turn",
        "grant",
        "request_sha256",
        "model",
        "system_sha256",
        "user_sha256",
        "user_bytes",
        "client_class",
    )
    for path, row in zip(reservations, reservation_values, strict=True):
        attempt_id = row.get("attempt_id")
        path_ordinal, path_turn = _attempt_path_coordinate(path, kind="reservation")
        expected_cell_id = cell_id_by_ordinal.get(path_ordinal)
        expected_grant = "canary" if path_ordinal in CANARY_ORDINALS else "continuation"
        if (
            row.get("artifact_type") != CALL_RESERVATION_ARTIFACT_TYPE
            or not isinstance(attempt_id, str)
            or row.get("cell_ordinal") != path_ordinal
            or row.get("turn") != path_turn
            or row.get("cell_id") != expected_cell_id
            or attempt_id != f"{expected_cell_id}:turn-{path_turn:02d}"
            or row.get("grant") != expected_grant
            or attempt_id in reservation_by_attempt
            or row.get("model") != MODEL_ID
            or _SHA256.fullmatch(str(row.get("request_sha256"))) is None
            or row.get("system_sha256")
            != hashlib.sha256(SYSTEM_PROMPT.encode("utf-8")).hexdigest()
            or _SHA256.fullmatch(str(row.get("user_sha256"))) is None
            or not isinstance(row.get("client_class"), str)
            or not isinstance(row.get("user_bytes"), int)
            or row["user_bytes"] < 0
            or row["user_bytes"] > MAX_PROVIDER_USER_BYTES
        ):
            raise MultiSourceGlobalFatal("call reservation identity is invalid")
        reservation_by_attempt[attempt_id] = row
    terminal_by_attempt: dict[str, dict[str, Any]] = {}
    known: list[dict[str, int]] = []
    for path, row in zip(terminals, terminal_values, strict=True):
        attempt_id = row.get("attempt_id")
        path_ordinal, path_turn = _attempt_path_coordinate(path, kind="terminal")
        reservation = reservation_by_attempt.get(attempt_id)
        if (
            row.get("artifact_type") != CALL_TERMINAL_ARTIFACT_TYPE
            or not isinstance(attempt_id, str)
            or row.get("cell_ordinal") != path_ordinal
            or row.get("turn") != path_turn
            or attempt_id in terminal_by_attempt
            or reservation is None
            or any(
                row.get(field) != reservation.get(field) for field in identity_fields
            )
            or row.get("status") not in {"returned", "provider_error"}
            or row.get("client_call_reconciled") is not True
            or row.get("delegate_calls_made") != row.get("turn")
        ):
            raise MultiSourceGlobalFatal(
                "call terminal does not match its exact reservation"
            )
        usage = row.get("usage")
        usage_is_known = bool(
            isinstance(usage, dict)
            and set(usage) == {"input_tokens", "output_tokens", "total_tokens"}
            and all(type(value) is int and value >= 0 for value in usage.values())
            and usage["total_tokens"] == usage["input_tokens"] + usage["output_tokens"]
        )
        if row.get("usage_known") is not usage_is_known:
            raise MultiSourceGlobalFatal("call terminal usage flag is inconsistent")
        if row.get("status") == "returned":
            if (
                row.get("completion_model") != MODEL_ID
                or _SHA256.fullmatch(str(row.get("completion_text_sha256"))) is None
                or type(row.get("completion_latency_ms")) is not int
                or row["completion_latency_ms"] < 0
                or row.get("error_type") is not None
            ):
                raise MultiSourceGlobalFatal("returned completion model differs")
            if usage_is_known:
                known.append(usage)
        elif (
            usage is not None
            or row.get("completion_model") is not None
            or row.get("completion_latency_ms") is not None
            or row.get("completion_text_sha256") is not None
            or not isinstance(row.get("error_type"), str)
        ):
            raise MultiSourceGlobalFatal(
                "provider error terminal contains completion data"
            )
        terminal_by_attempt[attempt_id] = row
    orphan_count = len(reservation_by_attempt) - len(terminal_by_attempt)
    if orphan_count < 0:
        raise MultiSourceGlobalFatal("terminal call records outnumber reservations")
    return {
        "provider_call_reservations": len(reservation_by_attempt),
        "provider_terminal_records": len(terminal_by_attempt),
        "returned_completion_count": sum(
            row.get("status") == "returned" for row in terminal_values
        ),
        "provider_error_count": sum(
            row.get("status") == "provider_error" for row in terminal_values
        ),
        "indeterminate_consumed_call_count": orphan_count,
        "known_input_tokens": sum(row["input_tokens"] for row in known),
        "known_output_tokens": sum(row["output_tokens"] for row in known),
        "known_total_tokens": sum(row["total_tokens"] for row in known),
        "usage_unknown_call_count": len(reservation_by_attempt) - len(known),
        "global_call_hard_cap": GLOBAL_CALL_CAP,
        "within_global_call_hard_cap": len(reservation_by_attempt) <= GLOBAL_CALL_CAP,
        "reconciled": len(reservation_by_attempt)
        == len(terminal_by_attempt) + orphan_count,
    }


def _validate_cell_ledgers(root: Path, cells: Sequence[EngineeringCell]) -> None:
    """Cross-check every persisted cell row against its durable provider turns."""

    for cell in cells:
        ordinal = int(cell.execution_ordinal or 0)
        cell_path = root / "cells" / f"cell-{ordinal:02d}.json"
        record = _read_object(cell_path, "cell ledger record")
        if record.get("assignment") != cell.private_json():
            raise MultiSourceGlobalFatal("cell ledger assignment differs from schedule")
        expected_attribution = (
            attribute_attack(record, workflow_key=cell.workflow_key)
            if cell.pair_role == "adversarial"
            else None
        )
        if record.get("attack_attribution") != expected_attribution:
            raise MultiSourceGlobalFatal("cell attack attribution differs")
        request_records = record.get("provider_request_records")
        request_count = record.get("provider_request_count")
        declared_reservations = record.get("provider_call_reservations")
        if (
            not isinstance(request_records, list)
            or type(request_count) is not int
            or request_count < 0
            or type(declared_reservations) is not int
            or declared_reservations < 0
        ):
            raise MultiSourceGlobalFatal("cell provider ledger declaration is invalid")
        attempt_dir = root / "attempts" / f"cell-{ordinal:02d}"
        reservation_paths = sorted(attempt_dir.glob("turn-*.reservation.json"))
        terminal_paths = sorted(attempt_dir.glob("turn-*.terminal.json"))
        if declared_reservations != len(reservation_paths):
            raise MultiSourceGlobalFatal(
                "cell declared provider reservations differ from durable ledger"
            )
        if record.get("status") == "indeterminate_consumed":
            if (
                request_count != 0
                or request_records
                or not reservation_paths
                or len(terminal_paths) >= len(reservation_paths)
            ):
                raise MultiSourceGlobalFatal(
                    "indeterminate cell differs from its orphan ledger"
                )
            continue
        if not (
            request_count
            == len(request_records)
            == len(reservation_paths)
            == len(terminal_paths)
        ):
            raise MultiSourceGlobalFatal(
                "cell request count differs from durable provider turns"
            )
        reservations: dict[int, dict[str, Any]] = {}
        terminals: dict[int, dict[str, Any]] = {}
        for path in reservation_paths:
            path_ordinal, turn = _attempt_path_coordinate(path, kind="reservation")
            if path_ordinal != ordinal or turn in reservations:
                raise MultiSourceGlobalFatal("cell reservation turn identity differs")
            reservations[turn] = _read_object(path, "cell call reservation")
        for path in terminal_paths:
            path_ordinal, turn = _attempt_path_coordinate(path, kind="terminal")
            if path_ordinal != ordinal or turn in terminals:
                raise MultiSourceGlobalFatal("cell terminal turn identity differs")
            terminals[turn] = _read_object(path, "cell call terminal")
        expected_turns = set(range(1, request_count + 1))
        if set(reservations) != expected_turns or set(terminals) != expected_turns:
            raise MultiSourceGlobalFatal("cell provider turns are not contiguous")
        for turn, request_record in enumerate(request_records, start=1):
            if not isinstance(request_record, dict):
                raise MultiSourceGlobalFatal("cell provider request row is invalid")
            reservation = reservations[turn]
            terminal = terminals[turn]
            if (
                request_record.get("request_index") != turn
                or request_record.get("request_sha256")
                != reservation.get("request_sha256")
                or request_record.get("system_sha256")
                != reservation.get("system_sha256")
                or request_record.get("user_sha256") != reservation.get("user_sha256")
                or request_record.get("model") != reservation.get("model")
                or request_record.get("max_completion_tokens") != MAX_COMPLETION_TOKENS
                or request_record.get("reasoning_effort") != REASONING_EFFORT
                or request_record.get("retries") != REQUEST_RETRIES
                or request_record.get("hidden_key_present") is not False
            ):
                raise MultiSourceGlobalFatal(
                    "cell provider request identity differs from reservation"
                )
            terminal_status = terminal.get("status")
            if terminal_status == "provider_error":
                if (
                    request_record.get("completion_finish_status") != "not_returned"
                    or request_record.get("completion_usage") is not None
                    or request_record.get("raw_parse_status") != "not_attempted"
                    or request_record.get("status") != "provider_error"
                    or request_record.get("error_type") != terminal.get("error_type")
                ):
                    raise MultiSourceGlobalFatal(
                        "cell provider failure differs from terminal ledger"
                    )
                continue
            if terminal_status != "returned":
                raise MultiSourceGlobalFatal("cell terminal finish status is invalid")
            completion = request_record.get("completion_usage")
            terminal_usage = terminal.get("usage")
            parse_status = request_record.get("raw_parse_status")
            if (
                request_record.get("completion_finish_status") != "returned"
                or not isinstance(completion, dict)
                or not isinstance(terminal_usage, dict)
                or completion.get("model") != terminal.get("completion_model")
                or completion.get("latency_ms") != terminal.get("completion_latency_ms")
                or completion.get("input_tokens") != terminal_usage.get("input_tokens")
                or completion.get("output_tokens")
                != terminal_usage.get("output_tokens")
                or completion.get("total_tokens") != terminal_usage.get("total_tokens")
                or request_record.get("raw_response_sha256")
                != terminal.get("completion_text_sha256")
                or parse_status
                not in _PARSED_RESPONSE_STATUSES | _FAILED_RESPONSE_STATUSES.keys()
            ):
                raise MultiSourceGlobalFatal(
                    "cell completion evidence differs from terminal ledger"
                )
            if parse_status in _PARSED_RESPONSE_STATUSES:
                response_type = request_record.get("response_type")
                if (
                    response_type not in {"tool_action", "final"}
                    or request_record.get("status") != f"parsed_{response_type}"
                    or request_record.get("failure_class") is not None
                    or request_record.get("error_type") is not None
                    or _SHA256.fullmatch(str(request_record.get("response_sha256")))
                    is None
                ):
                    raise MultiSourceGlobalFatal(
                        "cell parsed completion status is inconsistent"
                    )
            else:
                (
                    expected_status,
                    expected_failure,
                    expected_error,
                ) = _FAILED_RESPONSE_STATUSES[parse_status]
                if (
                    request_record.get("status") != expected_status
                    or request_record.get("failure_class") != expected_failure
                    or request_record.get("error_type") != expected_error
                    or request_record.get("response_type") is not None
                    or request_record.get("response_sha256") is not None
                ):
                    raise MultiSourceGlobalFatal(
                        "cell failed parse status is inconsistent"
                    )


def _validate_existing_cell_ledgers(root: Path) -> None:
    existing = tuple(
        cell
        for cell in _schedule()
        if (
            root / "cells" / f"cell-{int(cell.execution_ordinal or 0):02d}.json"
        ).is_file()
    )
    if existing:
        _validate_cell_ledgers(root, existing)


def _run_cells(
    *,
    root: Path,
    cells: Sequence[EngineeringCell],
    client_factory: ClientFactory,
    session_factory: SessionFactory,
    production: bool,
) -> list[dict[str, Any]]:
    cell_rows: list[dict[str, Any]] = []
    for cell in cells:
        ordinal = int(cell.execution_ordinal or 0)
        cell_path = root / "cells" / f"cell-{ordinal:02d}.json"
        if cell_path.exists():
            record = _read_object(cell_path, "cell record")
            if record.get("assignment") != cell.private_json():
                raise MultiSourceGlobalFatal("persisted cell differs from schedule")
        else:
            attempt_dir = root / "attempts" / f"cell-{ordinal:02d}"
            has_reservation = any(attempt_dir.glob("turn-*.reservation.json"))
            record = (
                _indeterminate_cell(root, cell)
                if has_reservation
                else _run_cell(
                    root=root,
                    cell=cell,
                    client_factory=client_factory,
                    session_factory=session_factory,
                    production=production,
                )
            )
            _write_new(cell_path, record)
        cell_rows.append(
            {
                "execution_ordinal": ordinal,
                "cell_id": cell.cell_id,
                "status": record["status"],
                "path": cell_path.relative_to(root).as_posix(),
                "sha256": _sha(cell_path),
                "provider_call_reservations": record["provider_call_reservations"],
            }
        )
    return cell_rows


def _cell_rows_from_disk(
    root: Path, cells: Sequence[EngineeringCell]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for cell in cells:
        ordinal = int(cell.execution_ordinal or 0)
        path = root / "cells" / f"cell-{ordinal:02d}.json"
        record = _read_object(path, "persisted cell")
        if record.get("assignment") != cell.private_json():
            raise MultiSourceGlobalFatal("persisted cell differs from schedule")
        rows.append(
            {
                "execution_ordinal": ordinal,
                "cell_id": cell.cell_id,
                "status": record["status"],
                "path": path.relative_to(root).as_posix(),
                "sha256": _sha(path),
                "provider_call_reservations": record["provider_call_reservations"],
            }
        )
    return rows


def _validate_resume_root(
    *,
    repo_root: Path,
    root: Path,
    gate_receipt: Mapping[str, Any] | Path | str,
    profile: Mapping[str, Any],
    authorization: Mapping[str, Any],
    production: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    namespace = root.name
    profile_value, authorization_value = _validate_documents(
        repo_root=repo_root,
        namespace=namespace,
        gate_receipt=gate_receipt,
        profile=profile,
        authorization=authorization,
        production=production,
    )
    if (
        _read_object(root / "profile.json", "persisted profile") != profile_value
        or _read_object(root / "authorization.json", "persisted authorization")
        != authorization_value
    ):
        raise MultiSourceGlobalFatal(
            "resume documents differ from consumed authorization"
        )
    if len(_reservation_paths(root)) > GLOBAL_CALL_CAP:
        raise MultiSourceGlobalFatal("persisted calls exceed global hard cap")
    _validate_existing_cell_ledgers(root)
    return profile_value, authorization_value


def _canary_report(
    root: Path, cell_rows: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    _validate_cell_ledgers(root, _canary_cells())
    usage = _usage_summary(root, cell_ordinals=frozenset(CANARY_ORDINALS))
    operational_failures = {
        "integrity_failure",
        "provider_failure",
        "parse_failure",
        "schema_failure",
        "native_failure",
        "native_checker_failure",
        "native_cleanup_failure",
        "indeterminate_consumed",
    }
    operational_gate_passed = bool(
        len(cell_rows) == CANARY_CELL_COUNT
        and all(row.get("status") == "completed" for row in cell_rows)
        and usage["reconciled"] is True
        and usage["indeterminate_consumed_call_count"] == 0
        and usage["usage_unknown_call_count"] == 0
        and usage["within_global_call_hard_cap"] is True
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "agentmembrane_rq1_multi_source_canary_report_v5",
        "phase": "canary_complete_continuation_not_started",
        "cell_count": CANARY_CELL_COUNT,
        "cells": copy.deepcopy(list(cell_rows)),
        "canary_grant": {
            "cell_count": CANARY_CELL_COUNT,
            "call_hard_cap": CANARY_CALL_CAP,
            "calls_consumed": sum(
                int(row["provider_call_reservations"]) for row in cell_rows
            ),
        },
        "call_and_usage_accounting": usage,
        "operational_gate_passed": operational_gate_passed,
        "operational_gate_contract": {
            "requires_two_immutable_cell_records": True,
            "disallowed_failure_statuses": sorted(operational_failures),
            "requires_reconciled_usage": True,
            "requires_complete_known_usage": True,
            "utility_direction_used": False,
            "security_direction_used": False,
            "denial_direction_used": False,
        },
        "continuation_started": False,
        "continuation_independent_of_utility_security_direction": True,
        "safety_classification_performed": False,
        "claim_eligible": False,
        "finished_at": _utc_now(),
    }


def _final_report(root: Path) -> dict[str, Any]:
    cells = _schedule()
    _validate_cell_ledgers(root, cells)
    cell_rows = _cell_rows_from_disk(root, cells)
    usage = _usage_summary(root)
    complete_record_set = bool(
        len(cell_rows) == CELL_COUNT
        and {row["execution_ordinal"] for row in cell_rows}
        == set(range(1, CELL_COUNT + 1))
        and len({row["sha256"] for row in cell_rows}) == CELL_COUNT
    )
    all_cells_completed = all(row["status"] == "completed" for row in cell_rows)
    evidence_failure_reasons: list[str] = []
    if not complete_record_set:
        evidence_failure_reasons.append("incomplete_or_nonunique_cell_records")
    if not all_cells_completed:
        evidence_failure_reasons.append("one_or_more_cells_not_completed")
    if usage["reconciled"] is not True:
        evidence_failure_reasons.append("call_ledger_not_reconciled")
    if usage["usage_unknown_call_count"] != 0:
        evidence_failure_reasons.append("provider_usage_unknown")
    if usage["indeterminate_consumed_call_count"] != 0:
        evidence_failure_reasons.append("orphan_call_reservation_present")
    if usage["within_global_call_hard_cap"] is not True:
        evidence_failure_reasons.append("global_call_cap_exceeded")
    evidence_eligible = not evidence_failure_reasons
    report = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": REPORT_ARTIFACT_TYPE,
        "cell_count": CELL_COUNT,
        "cells": cell_rows,
        "all_assigned_cells_have_records": len(cell_rows) == CELL_COUNT,
        "evidence_eligible": evidence_eligible,
        "evidence_eligibility": {
            "scope": "nonclaiming_engineering_execution_evidence",
            "requires_28_immutable_unique_cell_records": True,
            "requires_every_cell_completed": True,
            "requires_reconciled_call_ledger": True,
            "requires_complete_known_usage": True,
            "requires_zero_orphan_reservations": True,
            "requires_global_call_cap_compliance": True,
            "failure_reasons": evidence_failure_reasons,
            "utility_direction_used": False,
            "security_direction_used": False,
            "denial_direction_used": False,
            "failed_or_unknown_cells_counted_as_safe": False,
        },
        "call_and_usage_accounting": usage,
        "canary_grant": {
            "cell_count": CANARY_CELL_COUNT,
            "call_hard_cap": CANARY_CALL_CAP,
            "calls_consumed": sum(
                row["provider_call_reservations"]
                for row in cell_rows
                if row["execution_ordinal"] in CANARY_ORDINALS
            ),
        },
        "continuation_grant": {
            "cell_count": CONTINUATION_CELL_COUNT,
            "call_hard_cap": CONTINUATION_CALL_CAP,
            "calls_consumed": sum(
                row["provider_call_reservations"]
                for row in cell_rows
                if row["execution_ordinal"] not in CANARY_ORDINALS
            ),
        },
        "continuation_depended_on_observed_outcome": False,
        "safety_classification_performed": False,
        "claim_eligible": False,
        "finished_at": _utc_now(),
    }
    _write_new(root / "report.json", report)
    return copy.deepcopy(report)


def _production_client_factory(_: EngineeringCell) -> CompletionClient:
    client = ExactRQ1GPT54MiniLowClient.from_local_config(timeout_seconds=120.0)
    if type(client) is not ExactRQ1GPT54MiniLowClient or client.calls_made != 0:
        raise MultiSourceGlobalFatal("exact production client is not fresh")
    return client


def _execute_canary(
    *,
    repo_root: Path,
    output_root: Path,
    namespace: str,
    gate_receipt: Mapping[str, Any] | Path | str,
    profile: Mapping[str, Any],
    authorization: Mapping[str, Any],
    client_factory: ClientFactory,
    session_factory: SessionFactory,
    production: bool,
) -> dict[str, Any]:
    profile_value, authorization_value = _validate_documents(
        repo_root=repo_root,
        namespace=namespace,
        gate_receipt=gate_receipt,
        profile=profile,
        authorization=authorization,
        production=production,
    )
    root = _reserve_namespace(
        output_root=output_root,
        namespace=namespace,
        profile=profile_value,
        authorization=authorization_value,
    )
    rows = _run_cells(
        root=root,
        cells=_canary_cells(),
        client_factory=client_factory,
        session_factory=session_factory,
        production=production,
    )
    report = _canary_report(root, rows)
    _write_new(root / "canary-report.json", report)
    return copy.deepcopy(report)


def _resume_canary(
    *,
    repo_root: Path,
    namespace_path: Path,
    gate_receipt: Mapping[str, Any] | Path | str,
    profile: Mapping[str, Any],
    authorization: Mapping[str, Any],
    client_factory: ClientFactory,
    session_factory: SessionFactory,
    production: bool,
) -> dict[str, Any]:
    root = Path(namespace_path).resolve()
    _validate_resume_root(
        repo_root=repo_root,
        root=root,
        gate_receipt=gate_receipt,
        profile=profile,
        authorization=authorization,
        production=production,
    )
    if (root / "canary-report.json").exists():
        return _read_object(root / "canary-report.json", "canary report")
    rows = _run_cells(
        root=root,
        cells=_canary_cells(),
        client_factory=client_factory,
        session_factory=session_factory,
        production=production,
    )
    report = _canary_report(root, rows)
    _write_new(root / "canary-report.json", report)
    return copy.deepcopy(report)


def _execute_continuation(
    *,
    repo_root: Path,
    namespace_path: Path,
    gate_receipt: Mapping[str, Any] | Path | str,
    profile: Mapping[str, Any],
    authorization: Mapping[str, Any],
    client_factory: ClientFactory,
    session_factory: SessionFactory,
    production: bool,
) -> dict[str, Any]:
    root = Path(namespace_path).resolve()
    _validate_resume_root(
        repo_root=repo_root,
        root=root,
        gate_receipt=gate_receipt,
        profile=profile,
        authorization=authorization,
        production=production,
    )
    if (root / "report.json").exists():
        return _read_object(root / "report.json", "completed report")
    canary_path = root / "canary-report.json"
    if not canary_path.is_file():
        raise MultiSourceGlobalFatal(
            "continuation requires an explicit completed canary phase"
        )
    canary = _read_object(canary_path, "canary report")
    first_cells = _canary_cells()
    canary_rows = _cell_rows_from_disk(root, first_cells)
    if (
        canary.get("phase") != "canary_complete_continuation_not_started"
        or canary.get("cells") != canary_rows
        or canary.get("continuation_started") is not False
    ):
        raise MultiSourceGlobalFatal("canary report differs from its two cell records")
    live_usage = _usage_summary(root, cell_ordinals=frozenset(CANARY_ORDINALS))
    live_operational_pass = bool(
        all(row.get("status") == "completed" for row in canary_rows)
        and live_usage["reconciled"] is True
        and live_usage["indeterminate_consumed_call_count"] == 0
        and live_usage["usage_unknown_call_count"] == 0
        and live_usage["within_global_call_hard_cap"] is True
    )
    if (
        canary.get("operational_gate_passed") is not live_operational_pass
        or live_operational_pass is not True
    ):
        raise MultiSourceGlobalFatal(
            "continuation requires an operationally passing canary"
        )
    # The caller's explicit invocation is the continuation decision after the
    # operational canary gate. Utility, security, and denial direction are not
    # used by that gate.
    _run_cells(
        root=root,
        cells=_continuation_cells(),
        client_factory=client_factory,
        session_factory=session_factory,
        production=production,
    )
    return _final_report(root)


def execute_canary_v5(
    *,
    repo_root: Path,
    output_root: Path,
    namespace: str,
    gate_receipt: Mapping[str, Any] | Path | str,
    profile: Mapping[str, Any],
    authorization: Mapping[str, Any],
) -> dict[str, Any]:
    """Execute the matched adversarial production canary with real bindings."""

    return _execute_canary(
        repo_root=repo_root,
        output_root=output_root,
        namespace=namespace,
        gate_receipt=gate_receipt,
        profile=profile,
        authorization=authorization,
        client_factory=_production_client_factory,
        session_factory=FrozenNativeSession,
        production=True,
    )


def resume_canary_v5(
    *,
    repo_root: Path,
    namespace_path: Path,
    gate_receipt: Mapping[str, Any] | Path | str,
    profile: Mapping[str, Any],
    authorization: Mapping[str, Any],
) -> dict[str, Any]:
    """Resume only the production canary without retrying orphan calls."""

    return _resume_canary(
        repo_root=repo_root,
        namespace_path=namespace_path,
        gate_receipt=gate_receipt,
        profile=profile,
        authorization=authorization,
        client_factory=_production_client_factory,
        session_factory=FrozenNativeSession,
        production=True,
    )


def execute_continuation_v5(
    *,
    repo_root: Path,
    namespace_path: Path,
    gate_receipt: Mapping[str, Any] | Path | str,
    profile: Mapping[str, Any],
    authorization: Mapping[str, Any],
) -> dict[str, Any]:
    """Explicitly execute the production continuation after a passing canary."""

    return _execute_continuation(
        repo_root=repo_root,
        namespace_path=namespace_path,
        gate_receipt=gate_receipt,
        profile=profile,
        authorization=authorization,
        client_factory=_production_client_factory,
        session_factory=FrozenNativeSession,
        production=True,
    )


def execute_canary_test_only_v5(
    *,
    repo_root: Path,
    output_root: Path,
    namespace: str,
    gate_receipt: Mapping[str, Any] | Path | str,
    profile: Mapping[str, Any],
    authorization: Mapping[str, Any],
    client_factory: ClientFactory,
    session_factory: SessionFactory,
) -> dict[str, Any]:
    """Explicit dependency-injected entry point; never a production executor."""

    return _execute_canary(
        repo_root=repo_root,
        output_root=output_root,
        namespace=namespace,
        gate_receipt=gate_receipt,
        profile=profile,
        authorization=authorization,
        client_factory=client_factory,
        session_factory=session_factory,
        production=False,
    )


def resume_canary_test_only_v5(
    *,
    repo_root: Path,
    namespace_path: Path,
    gate_receipt: Mapping[str, Any] | Path | str,
    profile: Mapping[str, Any],
    authorization: Mapping[str, Any],
    client_factory: ClientFactory,
    session_factory: SessionFactory,
) -> dict[str, Any]:
    return _resume_canary(
        repo_root=repo_root,
        namespace_path=namespace_path,
        gate_receipt=gate_receipt,
        profile=profile,
        authorization=authorization,
        client_factory=client_factory,
        session_factory=session_factory,
        production=False,
    )


def execute_continuation_test_only_v5(
    *,
    repo_root: Path,
    namespace_path: Path,
    gate_receipt: Mapping[str, Any] | Path | str,
    profile: Mapping[str, Any],
    authorization: Mapping[str, Any],
    client_factory: ClientFactory,
    session_factory: SessionFactory,
) -> dict[str, Any]:
    return _execute_continuation(
        repo_root=repo_root,
        namespace_path=namespace_path,
        gate_receipt=gate_receipt,
        profile=profile,
        authorization=authorization,
        client_factory=client_factory,
        session_factory=session_factory,
        production=False,
    )


class OfflineScriptedClient:
    """Finite per-cell completion script with no network implementation."""

    def __init__(self, steps: Sequence[Completion | Exception]) -> None:
        if isinstance(steps, (str, bytes)) or not isinstance(steps, Sequence):
            raise TypeError("steps must be a finite sequence")
        self._steps = tuple(steps)
        self.calls_made = 0

    def complete(self, **kwargs: Any) -> Completion:
        if kwargs.get("retries") != 0:
            raise MultiSourceExecutorError("offline client requires zero retries")
        index = self.calls_made
        self.calls_made += 1
        if index >= len(self._steps):
            raise RuntimeError("offline completion script exhausted")
        step = self._steps[index]
        if isinstance(step, Exception):
            raise step
        if type(step) is not Completion:
            raise TypeError("offline script entry must be Completion or Exception")
        return copy.deepcopy(step)


@dataclass
class OfflineScriptedClientFactory:
    """Create one fresh sealed script client for every selected cell."""

    steps_by_cell_id: Mapping[str, Sequence[Completion | Exception]]

    def __post_init__(self) -> None:
        self.created: list[tuple[str, OfflineScriptedClient]] = []

    def __call__(self, cell: EngineeringCell) -> OfflineScriptedClient:
        steps = self.steps_by_cell_id.get(cell.cell_id)
        if steps is None:
            raise MultiSourceExecutorError(f"offline script lacks cell {cell.cell_id}")
        client = OfflineScriptedClient(steps)
        self.created.append((cell.cell_id, client))
        return client


__all__ = [
    "AUTHORIZATION_ARTIFACT_TYPE",
    "CANARY_CALL_CAP",
    "CANARY_CELL_COUNT",
    "CANARY_ORDINALS",
    "CELL_COUNT",
    "CONTINUATION_CALL_CAP",
    "CONTINUATION_CELL_COUNT",
    "GLOBAL_CALL_CAP",
    "MAX_TURNS_PER_CELL",
    "MAX_PROVIDER_USER_BYTES",
    "MultiSourceExecutorError",
    "MultiSourceGlobalFatal",
    "OfflineScriptedClient",
    "OfflineScriptedClientFactory",
    "build_authorization_document",
    "build_profile_document",
    "execute_canary_v5",
    "execute_canary_test_only_v5",
    "execute_continuation_v5",
    "execute_continuation_test_only_v5",
    "resume_canary_v5",
    "resume_canary_test_only_v5",
]
