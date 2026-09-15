"""Fresh-namespace driver for native public-checker parity evidence.

The driver never treats registration, reference checkers, or a copied native
verdict as parity.  It requires an executable live preflight, invokes native
checkers separately from trusted-event projection, cleans up every attempted
case, and writes a readiness-shaped PASS report only after every gate passes.
All failures write a different diagnostic artifact type with ``NO_GO``.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from .public_adapters import (
    AdapterRuntimePreflight,
    NativeCheckerVerdict,
    ProjectedCheckerVerdict,
    PublicBenchmarkAdapter,
    describe_adapter_type,
    normalize_runtime_preflight,
)
from .schema import IntegrityError, SchemaError, canonical_json_bytes, sha256_bytes


CHECKER_PARITY_SCHEMA_VERSION = 1
CHECKER_PARITY_ARTIFACT_TYPE = "agentmembrane_public_checker_parity"
CHECKER_PARITY_DIAGNOSTIC_ARTIFACT_TYPE = (
    "agentmembrane_public_checker_parity_diagnostic"
)
MINIMUM_PARITY_SOURCE_TASKS = 20
REQUIRED_CHECKER_PARITY_CATEGORIES = frozenset(
    {
        "positive",
        "negative",
        "wrong_mutation",
        "wrong_order",
        "partial_state",
        "communication_only",
    }
)
_ATTACK_SEMANTICS = frozenset(
    {
        "native_upstream_security_checker",
        "agentmembrane_derived_security_extension_not_upstream_benchmark",
    }
)


@dataclass(frozen=True)
class CheckerParityCase:
    """One explicit perturbation case for a frozen upstream source task."""

    trace_id: str
    task_id: str
    source_task_id: str
    case_category: str
    actions: tuple[Mapping[str, Any], ...]

    def input_json(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "task_id": self.task_id,
            "source_task_id": self.source_task_id,
            "case_category": self.case_category,
            "actions": [dict(action) for action in self.actions],
        }


@dataclass(frozen=True)
class CheckerParityRunResult:
    """Path and bytes identity for either a PASS report or NO-GO diagnostic."""

    decision: str
    artifact_path: str
    artifact_sha256: str
    namespace_path: str
    artifact: Mapping[str, Any]


def _nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SchemaError(f"{label} must be a nonempty string")
    return value


def _sha256(value: Any, label: str) -> str:
    text = _nonempty_string(value, label)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise SchemaError(f"{label} must be a lowercase SHA-256")
    return text


def _optional_verdict(value: Any, label: str) -> bool | None:
    if value is not None and not isinstance(value, bool):
        raise SchemaError(f"{label} must be boolean or null")
    return value


def _write_exclusive(path: Path, value: Mapping[str, Any]) -> str:
    payload = canonical_json_bytes(dict(value))
    try:
        with path.open("xb") as handle:
            handle.write(payload)
    except FileExistsError as exc:
        raise IntegrityError(f"parity evidence path already exists: {path}") from exc
    return sha256_bytes(payload)


def _reserve_namespace(
    output_root: Path,
    namespace: str,
    *,
    parity_id: str,
    pack_id: str,
    adapter_id: str,
    generated_at: str,
) -> tuple[Path, dict[str, Any], str]:
    name = Path(_nonempty_string(namespace, "namespace"))
    if name.is_absolute() or len(name.parts) != 1 or name.name in {".", ".."}:
        raise IntegrityError("parity namespace must be one fresh relative path component")
    root = Path(output_root)
    root.mkdir(parents=True, exist_ok=True)
    resolved_root = root.resolve()
    namespace_path = resolved_root / name.name
    try:
        namespace_path.mkdir(mode=0o700, exist_ok=False)
    except FileExistsError as exc:
        raise IntegrityError(f"parity namespace is not fresh: {namespace_path}") from exc
    if namespace_path.resolve().parent != resolved_root:
        raise IntegrityError("parity namespace escapes its output root")
    reservation = {
        "schema_version": 1,
        "artifact_type": "agentmembrane_public_checker_parity_namespace_reservation",
        "reservation_id": f"{parity_id}:{name.name}",
        "namespace": name.name,
        "parity_id": parity_id,
        "pack_id": pack_id,
        "adapter_id": adapter_id,
        "generated_at": generated_at,
    }
    reservation_sha256 = _write_exclusive(
        namespace_path / "reservation.json", reservation
    )
    return namespace_path, reservation, reservation_sha256


def _blocker(code: str, message: str) -> dict[str, str]:
    return {
        "code": _nonempty_string(code, "blocker.code"),
        "message": _nonempty_string(message, "blocker.message"),
    }


def _emit_diagnostic(
    namespace_path: Path,
    *,
    parity_id: str,
    pack_id: str,
    taskpack_content_sha256: str,
    adapter_id: str,
    adapter_implementation_sha256: str,
    upstream_version_or_commit: str,
    generated_at: str,
    reservation_sha256: str,
    reservation_path: str,
    runtime_preflight_sha256: str | None,
    blockers: Sequence[Mapping[str, str]],
    partial_traces: Sequence[Mapping[str, Any]],
) -> CheckerParityRunResult:
    ordered_blockers = sorted(
        ({"code": item["code"], "message": item["message"]} for item in blockers),
        key=lambda item: (item["code"], item["message"]),
    )
    diagnostic = {
        "schema_version": CHECKER_PARITY_SCHEMA_VERSION,
        "artifact_type": CHECKER_PARITY_DIAGNOSTIC_ARTIFACT_TYPE,
        "diagnostic_id": f"{parity_id}:NO_GO",
        "pack_id": pack_id,
        "taskpack_content_sha256": taskpack_content_sha256,
        "adapter_id": adapter_id,
        "adapter_implementation_sha256": adapter_implementation_sha256,
        "upstream_version_or_commit": upstream_version_or_commit,
        "generated_at": generated_at,
        "namespace_reservation": {
            "path": reservation_path,
            "sha256": reservation_sha256,
        },
        "runtime_preflight_sha256": runtime_preflight_sha256,
        "blocker_codes": sorted({item["code"] for item in ordered_blockers}),
        "blockers": ordered_blockers,
        "partial_traces": [dict(trace) for trace in partial_traces],
        "decision": "NO_GO",
    }
    path = namespace_path / "diagnostic.json"
    artifact_sha256 = _write_exclusive(path, diagnostic)
    return CheckerParityRunResult(
        decision="NO_GO",
        artifact_path=str(path),
        artifact_sha256=artifact_sha256,
        namespace_path=str(namespace_path),
        artifact=diagnostic,
    )


def _validate_case_set(
    cases: Sequence[CheckerParityCase], formal_task_ids: Sequence[str]
) -> tuple[list[CheckerParityCase], list[str], set[str]]:
    if not isinstance(cases, Sequence) or isinstance(cases, (str, bytes)) or not cases:
        raise SchemaError("checker parity cases must be a nonempty sequence")
    validated: list[CheckerParityCase] = []
    trace_ids: set[str] = set()
    source_by_task: dict[str, str] = {}
    categories: set[str] = set()
    for index, case in enumerate(cases):
        if not isinstance(case, CheckerParityCase):
            raise SchemaError(f"checker parity cases[{index}] must be CheckerParityCase")
        trace_id = _nonempty_string(case.trace_id, f"cases[{index}].trace_id")
        if trace_id in trace_ids:
            raise IntegrityError(f"duplicate checker parity trace_id: {trace_id}")
        trace_ids.add(trace_id)
        task_id = _nonempty_string(case.task_id, f"cases[{index}].task_id")
        source_task_id = _nonempty_string(
            case.source_task_id, f"cases[{index}].source_task_id"
        )
        prior_source = source_by_task.setdefault(task_id, source_task_id)
        if prior_source != source_task_id:
            raise IntegrityError(f"parity task has inconsistent source identity: {task_id}")
        category = _nonempty_string(
            case.case_category, f"cases[{index}].case_category"
        )
        if category not in REQUIRED_CHECKER_PARITY_CATEGORIES:
            raise IntegrityError(f"unsupported checker parity category: {category}")
        categories.add(category)
        if not isinstance(case.actions, tuple):
            raise SchemaError(f"cases[{index}].actions must be a tuple")
        for action_index, action in enumerate(case.actions):
            if not isinstance(action, Mapping):
                raise SchemaError(
                    f"cases[{index}].actions[{action_index}] must be an object"
                )
        canonical_json_bytes(case.input_json())
        validated.append(case)

    formal = [_nonempty_string(item, "formal_task_ids item") for item in formal_task_ids]
    if not formal or len(formal) != len(set(formal)):
        raise IntegrityError("formal_task_ids must be nonempty and duplicate-free")
    held_out = sorted(source_by_task)
    if set(held_out) != set(formal):
        raise IntegrityError(
            "checker parity held-out task IDs must exactly cover the formal task IDs"
        )
    distinct_sources = set(source_by_task.values())
    if len(distinct_sources) < MINIMUM_PARITY_SOURCE_TASKS:
        raise IntegrityError(
            "checker parity requires at least "
            f"{MINIMUM_PARITY_SOURCE_TASKS} distinct upstream source tasks"
        )
    missing_categories = sorted(REQUIRED_CHECKER_PARITY_CATEGORIES - categories)
    if missing_categories:
        raise IntegrityError(
            f"checker parity lacks required case categories: {missing_categories}"
        )
    return validated, held_out, categories


def _validate_native_verdict(
    verdict: Any, *, expected_binding_ids: set[str]
) -> NativeCheckerVerdict:
    if not isinstance(verdict, NativeCheckerVerdict):
        raise SchemaError("native checker must return NativeCheckerVerdict")
    utility = _optional_verdict(verdict.utility, "native checker utility")
    security = _optional_verdict(verdict.security, "native checker security")
    if utility is None and security is None:
        raise IntegrityError("native checker returned no utility or security verdict")
    binding_ids = tuple(
        _nonempty_string(item, "native checker binding ID")
        for item in verdict.checker_binding_ids
    )
    if len(binding_ids) != len(set(binding_ids)):
        raise IntegrityError("native checker returned duplicate binding IDs")
    if set(binding_ids) != expected_binding_ids:
        raise IntegrityError("native checker bindings differ from runtime preflight")
    _sha256(verdict.native_output_sha256, "native checker output SHA-256")
    return verdict


def _validate_projected_verdict(value: Any) -> ProjectedCheckerVerdict:
    if not isinstance(value, ProjectedCheckerVerdict):
        raise SchemaError("projected checker must return ProjectedCheckerVerdict")
    utility = _optional_verdict(value.utility, "projected checker utility")
    security = _optional_verdict(value.security, "projected checker security")
    if utility is None and security is None:
        raise IntegrityError("projected checker returned no utility or security verdict")
    _sha256(value.projected_output_sha256, "projected checker output SHA-256")
    return value


def validate_namespace_reservation(
    report: Mapping[str, Any], *, evidence_root: Path
) -> dict[str, Any]:
    """Load and verify the byte-bound fresh-namespace reservation for a report."""

    reference = report.get("namespace_reservation")
    if not isinstance(reference, Mapping) or set(reference) != {"path", "sha256"}:
        raise SchemaError("namespace_reservation must contain exactly path and sha256")
    relative = Path(_nonempty_string(reference["path"], "namespace_reservation.path"))
    if relative.is_absolute() or ".." in relative.parts:
        raise IntegrityError("namespace reservation path must remain inside evidence root")
    root = Path(evidence_root).resolve()
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise IntegrityError("namespace reservation path escapes evidence root") from exc
    if not path.is_file():
        raise IntegrityError(f"namespace reservation is missing: {relative.as_posix()}")
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise IntegrityError(f"cannot read namespace reservation: {exc}") from exc
    expected_sha256 = _sha256(reference["sha256"], "namespace_reservation.sha256")
    actual_sha256 = sha256_bytes(payload)
    if actual_sha256 != expected_sha256:
        raise IntegrityError(
            "namespace reservation SHA-256 mismatch: "
            f"declared={expected_sha256}, actual={actual_sha256}"
        )
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SchemaError(f"cannot decode namespace reservation: {exc}") from exc
    fields = {
        "schema_version",
        "artifact_type",
        "reservation_id",
        "namespace",
        "parity_id",
        "pack_id",
        "adapter_id",
        "generated_at",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise SchemaError("namespace reservation fields are not exact")
    if value["schema_version"] != 1 or value["artifact_type"] != (
        "agentmembrane_public_checker_parity_namespace_reservation"
    ):
        raise SchemaError("invalid namespace reservation identity")
    for field in (
        "reservation_id",
        "namespace",
        "parity_id",
        "pack_id",
        "adapter_id",
        "generated_at",
    ):
        _nonempty_string(value[field], f"namespace reservation.{field}")
    for field in ("parity_id", "pack_id", "adapter_id", "generated_at"):
        if value[field] != report.get(field):
            raise IntegrityError(f"namespace reservation differs from parity report: {field}")
    if value["reservation_id"] != f"{value['parity_id']}:{value['namespace']}":
        raise IntegrityError("namespace reservation_id is not derived")
    if relative != Path(value["namespace"]) / "reservation.json":
        raise IntegrityError("namespace reservation path differs from reserved namespace")
    return value


def _verdicts_match(
    native: NativeCheckerVerdict, projected: ProjectedCheckerVerdict
) -> bool:
    comparisons: list[bool] = []
    for native_value, projected_value in (
        (native.utility, projected.utility),
        (native.security, projected.security),
    ):
        if (native_value is None) != (projected_value is None):
            return False
        if native_value is not None:
            comparisons.append(native_value == projected_value)
    return bool(comparisons) and all(comparisons)


def run_checker_parity(
    adapter: PublicBenchmarkAdapter,
    cases: Sequence[CheckerParityCase],
    *,
    output_root: Path,
    namespace: str,
    parity_id: str,
    pack_id: str,
    taskpack_content_sha256: str,
    formal_task_ids: Sequence[str],
    generated_at: str,
    attack_semantics: str,
) -> CheckerParityRunResult:
    """Run isolated native/projected checker parity or emit diagnostic NO-GO.

    This is an offline plumbing operation.  Callers remain responsible for
    authorization of any public benchmark execution before invoking it with a
    real benchmark adapter.
    """

    if not isinstance(adapter, PublicBenchmarkAdapter):
        raise TypeError("adapter must be a PublicBenchmarkAdapter instance")
    parity_id = _nonempty_string(parity_id, "parity_id")
    pack_id = _nonempty_string(pack_id, "pack_id")
    taskpack_content_sha256 = _sha256(
        taskpack_content_sha256, "taskpack_content_sha256"
    )
    generated_at = _nonempty_string(generated_at, "generated_at")
    if attack_semantics not in _ATTACK_SEMANTICS:
        raise SchemaError("unsupported attack_semantics")

    descriptor = describe_adapter_type(type(adapter))
    namespace_path, reservation, reservation_sha256 = _reserve_namespace(
        Path(output_root),
        namespace,
        parity_id=parity_id,
        pack_id=pack_id,
        adapter_id=descriptor.adapter_id,
        generated_at=generated_at,
    )
    preflight: AdapterRuntimePreflight | None = None
    preflight_sha256: str | None = None

    def diagnostic(
        blockers: Sequence[Mapping[str, str]],
        partial_traces: Sequence[Mapping[str, Any]] = (),
    ) -> CheckerParityRunResult:
        return _emit_diagnostic(
            namespace_path,
            parity_id=parity_id,
            pack_id=pack_id,
            taskpack_content_sha256=taskpack_content_sha256,
            adapter_id=descriptor.adapter_id,
            adapter_implementation_sha256=descriptor.implementation_sha256,
            upstream_version_or_commit=descriptor.upstream_version_or_commit,
            generated_at=generated_at,
            reservation_sha256=reservation_sha256,
            reservation_path=f"{reservation['namespace']}/reservation.json",
            runtime_preflight_sha256=preflight_sha256,
            blockers=blockers,
            partial_traces=partial_traces,
        )

    try:
        preflight = normalize_runtime_preflight(
            adapter.preflight(), descriptor=descriptor
        )
        preflight_sha256 = _write_exclusive(
            namespace_path / "runtime_preflight.json", preflight.as_json()
        )
    except Exception as exc:  # preflight imports are an untrusted runtime boundary
        return diagnostic(
            [
                _blocker(
                    "RUNTIME_PREFLIGHT_INVALID",
                    f"{type(exc).__name__}: {exc}",
                )
            ]
        )
    if not preflight.executable:
        blockers = [
            _blocker(item.code, item.message) for item in preflight.blockers
        ] or [
            _blocker(
                "RUNTIME_PREFLIGHT_NOT_EXECUTABLE",
                "validated runtime preflight is not executable",
            )
        ]
        return diagnostic(blockers)

    try:
        validated_cases, held_out, categories = _validate_case_set(
            cases, formal_task_ids
        )
    except (SchemaError, IntegrityError) as exc:
        return diagnostic(
            [_blocker("PARITY_INPUT_INVALID", f"{type(exc).__name__}: {exc}")]
        )

    expected_binding_ids = {
        binding.binding_id for binding in preflight.checker_bindings
    }
    traces: list[dict[str, Any]] = []
    blockers: list[dict[str, str]] = []
    for case in validated_cases:
        reset_state: Mapping[str, Any] | None = None
        native_trace: tuple[Mapping[str, Any], ...] = ()
        native_verdict: NativeCheckerVerdict | None = None
        projected_verdict: ProjectedCheckerVerdict | None = None
        cleanup_state_sha256: str | None = None
        attempt_started = False
        try:
            attempt_started = True
            reset_state = adapter.reset(case.source_task_id)
            if not isinstance(reset_state, Mapping):
                raise SchemaError("adapter.reset must return an object")
            canonical_json_bytes(dict(reset_state))
            trace_items: list[Mapping[str, Any]] = []
            for action in case.actions:
                result = adapter.dispatch_native_action(action)
                if not isinstance(result, Mapping):
                    raise SchemaError("dispatch_native_action must return an object")
                canonical_json_bytes(dict(result))
                trace_items.append(result)
            native_trace = tuple(trace_items)
            terminal_state = adapter.capture_terminal_state(
                reset_state=reset_state, native_trace=native_trace
            )
            if not isinstance(terminal_state, Mapping):
                raise SchemaError("capture_terminal_state must return an object")
            canonical_json_bytes(dict(terminal_state))

            # Native invocation receives native evidence.  Projection happens
            # only afterwards and its checker receives trusted events only.
            native_verdict = _validate_native_verdict(
                adapter.evaluate_native_checkers(
                    source_task_id=case.source_task_id,
                    native_trace=native_trace,
                    terminal_state=terminal_state,
                ),
                expected_binding_ids=expected_binding_ids,
            )
            trusted_events = adapter.project_trusted_events(native_trace)
            if not isinstance(trusted_events, tuple) or not all(
                isinstance(event, Mapping) for event in trusted_events
            ):
                raise SchemaError("project_trusted_events must return a tuple of objects")
            canonical_json_bytes([dict(event) for event in trusted_events])
            projected_verdict = _validate_projected_verdict(
                adapter.evaluate_projected_checkers(
                    source_task_id=case.source_task_id,
                    trusted_events=trusted_events,
                )
            )
        except Exception as exc:  # adapter boundaries must become NO-GO evidence
            blockers.append(
                _blocker(
                    "NATIVE_PARITY_CASE_FAILED",
                    f"{case.trace_id}: {type(exc).__name__}: {exc}",
                )
            )
        finally:
            if attempt_started:
                try:
                    cleanup_state_sha256 = _sha256(
                        adapter.cleanup(), f"{case.trace_id} cleanup state SHA-256"
                    )
                except Exception as exc:
                    blockers.append(
                        _blocker(
                            "NATIVE_CLEANUP_FAILED",
                            f"{case.trace_id}: {type(exc).__name__}: {exc}",
                        )
                    )

        if native_verdict is None or projected_verdict is None:
            break
        matches = _verdicts_match(native_verdict, projected_verdict)
        trace = {
            "trace_id": case.trace_id,
            "task_id": case.task_id,
            "source_task_id": case.source_task_id,
            "case_category": case.case_category,
            "trace_sha256": sha256_bytes(
                canonical_json_bytes(
                    {
                        "reset_state": dict(reset_state or {}),
                        "native_trace": [dict(item) for item in native_trace],
                    }
                )
            ),
            "upstream_input_sha256": sha256_bytes(
                canonical_json_bytes(case.input_json())
            ),
            "native_output_sha256": native_verdict.native_output_sha256,
            "projected_output_sha256": projected_verdict.projected_output_sha256,
            "utility_native": native_verdict.utility,
            "utility_adapter": projected_verdict.utility,
            "security_native": native_verdict.security,
            "security_adapter": projected_verdict.security,
            "cleanup_state_sha256": cleanup_state_sha256,
            "cleanup_succeeded": cleanup_state_sha256 is not None,
            "matches": matches,
        }
        traces.append(trace)
        if not matches:
            blockers.append(
                _blocker(
                    "NATIVE_CHECKER_PARITY_MISMATCH",
                    f"native/projected verdict mismatch: {case.trace_id}",
                )
            )
            break
        if blockers:
            break

    if len(traces) != len(validated_cases):
        blockers.append(
            _blocker(
                "PARITY_TRACE_COVERAGE_INCOMPLETE",
                f"completed {len(traces)} of {len(validated_cases)} parity traces",
            )
        )
    if any(trace["cleanup_succeeded"] is not True for trace in traces):
        blockers.append(
            _blocker(
                "NATIVE_CLEANUP_INCOMPLETE",
                "not every parity trace records successful cleanup",
            )
        )
    if blockers:
        return diagnostic(blockers, traces)

    report = {
        "schema_version": CHECKER_PARITY_SCHEMA_VERSION,
        "artifact_type": CHECKER_PARITY_ARTIFACT_TYPE,
        "parity_id": parity_id,
        "pack_id": pack_id,
        "taskpack_content_sha256": taskpack_content_sha256,
        "adapter_id": descriptor.adapter_id,
        "adapter_implementation_sha256": descriptor.implementation_sha256,
        "upstream_version_or_commit": descriptor.upstream_version_or_commit,
        "runtime_preflight_sha256": preflight_sha256,
        "namespace_reservation": {
            "path": f"{reservation['namespace']}/reservation.json",
            "sha256": reservation_sha256,
        },
        "checker_bindings": preflight.as_json()["checker_bindings"],
        "attack_semantics": attack_semantics,
        "generated_at": generated_at,
        "held_out_task_ids": held_out,
        "case_categories": sorted(categories),
        "traces": traces,
        "summary": {
            "trace_count": len(traces),
            "match_count": len(traces),
            "distinct_source_task_count": len(
                {case.source_task_id for case in validated_cases}
            ),
            "agreement": 1.0,
            "required_categories_covered": True,
            "formal_tasks_covered": True,
            "cleanup_complete": True,
            "decision": "PASS",
        },
    }
    validate_namespace_reservation(report, evidence_root=Path(output_root))
    report_path = namespace_path / "report.json"
    report_sha256 = _write_exclusive(report_path, report)
    return CheckerParityRunResult(
        decision="PASS",
        artifact_path=str(report_path),
        artifact_sha256=report_sha256,
        namespace_path=str(namespace_path),
        artifact=report,
    )


__all__ = [
    "CHECKER_PARITY_ARTIFACT_TYPE",
    "CHECKER_PARITY_DIAGNOSTIC_ARTIFACT_TYPE",
    "CHECKER_PARITY_SCHEMA_VERSION",
    "CheckerParityCase",
    "CheckerParityRunResult",
    "MINIMUM_PARITY_SOURCE_TASKS",
    "REQUIRED_CHECKER_PARITY_CATEGORIES",
    "run_checker_parity",
    "validate_namespace_reservation",
]
