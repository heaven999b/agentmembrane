"""Crash-resistant, direction-independent four-cell execution process for RQ1 v2.4.

This module deliberately does not authorize execution, create a production
profile, or interpret an oracle result.  It owns only the fixed assignment,
fresh namespace, zero-retry provider framing, per-cell durable envelopes, and
final attempt-ledger reconciliation.  Provider/planner failures are cell
outcomes and therefore never suppress later assigned cells.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence
from uuid import uuid4

from .cache import CacheIdentity, RunCache, episode_id as cache_episode_id
from .conditions import load_conditions
from .profiles import ResolvedProfile
from .rq1_safety_framing_v24 import (
    CONTRACT_RELATIVE_PATH,
    SafetyFramedModelPlannerV24,
    load_contract_v24,
)
from .schedule import ScheduleRow
from .schema import (
    IntegrityError,
    PlannerRole,
    canonical_json_bytes,
    sha256_bytes,
    validate_json,
)
from .taskpacks import load_taskpack


SCHEMA_VERSION = 1
PROCESS_ARTIFACT_TYPE = "agentmembrane_rq1_v24_resilient_process_v1"
CELL_ARTIFACT_TYPE = "agentmembrane_rq1_v24_assigned_cell_v1"
CALL_FRAME_ARTIFACT_TYPE = "agentmembrane_rq1_v24_provider_call_frame_v1"
REPORT_ARTIFACT_TYPE = "agentmembrane_rq1_v24_resilient_report_v1"
EPISODE_COUNT = 4
MAX_TURNS_PER_EPISODE = 6
HARD_CALL_CAP = 24
MODEL_ID = "gpt-5.6-sol"
PROVIDER_ROUTE_ID = "local-cli-proxy"
PACK_RELATIVE_PATH = Path("data/host_boundary_v2/packs/rq1-controlled-v2.2")
CONDITIONS_RELATIVE_PATH = Path(
    "experiments/host_boundary_v2/config/conditions.json"
)
V23_PROFILE_TEMPLATE_RELATIVE_PATH = Path(
    "experiments/host_boundary_v2/config/rq1_adaptive_smoke_v2.3/"
    "profile.template.json"
)
EPISODE_ORDER = (
    ("rq1-resource-benign-s01", "RQ1-resource-protected"),
    ("rq1-resource-adversarial-s01", "RQ1-resource-protected"),
    ("rq1-resource-adversarial-s01", "RQ1-resource-vulnerable"),
    ("rq1-resource-benign-s01", "RQ1-resource-vulnerable"),
)
_CELL_FAILURE_CLASSES = frozenset(
    {
        "provider_policy_failure",
        "parse_failure",
        "schema_failure",
        "explicit_abstention",
        "transport_failure",
        "environment_failure",
        "oracle_failure",
        "other_failure",
    }
)


class RQ1V24ProcessError(IntegrityError):
    """The v2.4 process or durable ledger is invalid."""


class RQ1V24GlobalFatal(RQ1V24ProcessError):
    """Isolation or the global provider budget can no longer be guaranteed."""


class EpisodeRunnerV24(Protocol):
    def __call__(
        self,
        *,
        assignment: Mapping[str, Any],
        client: Any,
        max_turns: int,
    ) -> Mapping[str, Any]: ...


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RQ1V24ProcessError(f"cannot load {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise RQ1V24ProcessError(f"{label} must be a JSON object")
    canonical_json_bytes(value)
    return value


def _repo_file(repo_root: Path, relative: Path, label: str) -> Path:
    root = Path(repo_root).resolve()
    if relative.is_absolute() or ".." in relative.parts:
        raise RQ1V24ProcessError(f"{label} must be repository-relative")
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise RQ1V24ProcessError(f"{label} escapes the repository") from exc
    if not path.is_file():
        raise RQ1V24ProcessError(f"{label} is unavailable: {path}")
    return path


def _resolved_production_profile_v24(
    *, repo_root: Path, contract_sha256: str, profile_template: Mapping[str, Any]
) -> tuple[ResolvedProfile, CacheIdentity, str]:
    root = Path(repo_root).resolve()
    implementation_sha256 = sha256_bytes(
        canonical_json_bytes(
            {
                "namespace": "rq1-v2.4-safety-framed-production-runner",
                "executor_sha256": sha256_bytes(Path(__file__).read_bytes()),
                "planner_sha256": sha256_bytes(
                    (root / "agentmembrane/host_v2/planner.py").read_bytes()
                ),
                "runner_sha256": sha256_bytes(
                    (root / "agentmembrane/host_v2/runner.py").read_bytes()
                ),
                "safety_framing_contract_sha256": contract_sha256,
            }
        )
    )
    protocol_sha256 = sha256_bytes(
        canonical_json_bytes(
            {
                "namespace": "rq1-v2.4-safety-framed-four-cell-protocol",
                "safety_framing_contract_sha256": contract_sha256,
                "adaptive_contract_bundle_sha256": profile_template.get(
                    "contract_bundle_sha256"
                ),
                "episode_order": list(fixed_assignments_v24()),
            }
        )
    )
    model = profile_template.get("model")
    retries = profile_template.get("retries")
    if not isinstance(model, Mapping) or not isinstance(retries, Mapping):
        raise RQ1V24ProcessError("v2.3 profile template lacks model/retry contract")
    if (
        model.get("requested_id") != MODEL_ID
        or model.get("provider_route_id") != PROVIDER_ROUTE_ID
        or model.get("reasoning_effort") != "max"
    ):
        raise RQ1V24ProcessError("production model contract is not exact Sol/max")
    raw = {
        "model": copy.deepcopy(dict(model)),
        "planner": {
            "attacker_prompt_path": "../prompts/attacker-primary.txt",
            "benign_prompt_path": "../prompts/benign-system.txt",
            "max_turns": MAX_TURNS_PER_EPISODE,
            "max_actions_per_turn": 1,
            "response_schema_version": 2,
        },
        "retries": copy.deepcopy(dict(retries)),
        "resolution": {
            "resolved_model_id": MODEL_ID,
            "provider_route_id": PROVIDER_ROUTE_ID,
            "reasoning_effort": "max",
            "implementation_sha256": implementation_sha256,
            "protocol_sha256": protocol_sha256,
        },
    }
    resolved = ResolvedProfile(
        raw=raw,
        source_path=root / CONTRACT_RELATIVE_PATH,
        resolved_path=None,
    )
    identity = CacheIdentity(
        implementation_sha256=implementation_sha256,
        protocol_sha256=protocol_sha256,
        resolved_model_id=MODEL_ID,
        provider_route_id=PROVIDER_ROUTE_ID,
    )
    return resolved, identity, protocol_sha256


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _write_new(path: Path, value: Any) -> None:
    payload = canonical_json_bytes(value) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        raise RQ1V24GlobalFatal(f"cannot create fresh durable file {path}: {exc}") from exc
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


def fixed_assignments_v24() -> tuple[dict[str, Any], ...]:
    return tuple(
        {
            "ordinal": ordinal,
            "task_id": task_id,
            "condition_id": condition_id,
            "max_turns": MAX_TURNS_PER_EPISODE,
            "max_actions_per_turn": 1,
        }
        for ordinal, (task_id, condition_id) in enumerate(EPISODE_ORDER, start=1)
    )


class FramedClientV24:
    """Persist a provider-call reservation before delegating to a client."""

    def __init__(self, client: Any, *, ledger_dir: Path) -> None:
        if not callable(getattr(client, "complete", None)):
            raise RQ1V24ProcessError("v2.4 framed client requires complete()")
        underlying_calls = getattr(client, "calls_made", 0)
        if underlying_calls != 0:
            raise RQ1V24GlobalFatal("v2.4 requires a fresh zero-call client")
        self.client = client
        self.ledger_dir = Path(ledger_dir)
        self.ledger_dir.mkdir(parents=True, exist_ok=False)
        self.calls_made = 0
        self._active_assignment: dict[str, Any] | None = None
        self._frames: list[dict[str, Any]] = []

    def begin_cell(self, assignment: Mapping[str, Any]) -> None:
        if self._active_assignment is not None:
            raise RQ1V24GlobalFatal("v2.4 framed client already has an active cell")
        self._active_assignment = copy.deepcopy(dict(assignment))

    def end_cell(self) -> None:
        self._active_assignment = None

    def complete(self, **kwargs: Any) -> Any:
        assignment = self._active_assignment
        if assignment is None:
            raise RQ1V24GlobalFatal("provider call occurred outside an assigned cell")
        if kwargs.get("retries") != 0:
            raise RQ1V24GlobalFatal("v2.4 provider calls require retries=0")
        cell_calls = sum(
            frame["cell_ordinal"] == assignment["ordinal"] for frame in self._frames
        )
        if cell_calls >= MAX_TURNS_PER_EPISODE:
            raise RQ1V24GlobalFatal("v2.4 cell exceeded its six-call/turn frame")
        if self.calls_made >= HARD_CALL_CAP:
            raise RQ1V24GlobalFatal("v2.4 global 24-call budget is exhausted")
        user = kwargs.get("user")
        if isinstance(user, str):
            try:
                visible = json.loads(user)
            except json.JSONDecodeError:
                visible = None
            if isinstance(visible, Mapping):
                turn = visible.get("turn_number")
                if (
                    not isinstance(turn, int)
                    or isinstance(turn, bool)
                    or not 1 <= turn <= MAX_TURNS_PER_EPISODE
                ):
                    raise RQ1V24GlobalFatal(
                        "v2.4 provider call lies outside the six-turn cell frame"
                    )
        self.calls_made += 1
        request = copy.deepcopy(kwargs)
        canonical_json_bytes(request)
        frame = {
            "schema_version": SCHEMA_VERSION,
            "artifact_type": CALL_FRAME_ARTIFACT_TYPE,
            "call_index": self.calls_made,
            "cell_ordinal": assignment["ordinal"],
            "task_id": assignment["task_id"],
            "condition_id": assignment["condition_id"],
            "retries": 0,
            "request_sha256": sha256_bytes(canonical_json_bytes(request)),
            "reserved_at": _utc_now(),
        }
        _write_new(
            self.ledger_dir / f"call-{self.calls_made:02d}.json",
            frame,
        )
        self._frames.append(copy.deepcopy(frame))
        return self.client.complete(**kwargs)

    @property
    def frames(self) -> tuple[dict[str, Any], ...]:
        return tuple(copy.deepcopy(self._frames))


@dataclass(frozen=True)
class ExecutionResultV24:
    namespace: Path
    report: dict[str, Any]


class ProductionEpisodeRunnerV24:
    """Run the fixed resource cells through the real canonical episode seam."""

    def __init__(
        self, *, repo_root: Path, cache_root: Path, client: FramedClientV24
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        contract_path = _repo_file(
            self.repo_root, CONTRACT_RELATIVE_PATH, "v2.4 framing contract"
        )
        profile_path = _repo_file(
            self.repo_root,
            V23_PROFILE_TEMPLATE_RELATIVE_PATH,
            "v2.3 adaptive profile template",
        )
        self.pack_root = (
            _repo_file(
                self.repo_root,
                PACK_RELATIVE_PATH / "manifest.json",
                "RQ1 taskpack manifest",
            ).parent
        )
        conditions_path = _repo_file(
            self.repo_root, CONDITIONS_RELATIVE_PATH, "condition registry"
        )
        self.contract = load_contract_v24(contract_path)
        self.profile_template = _load_json_object(
            profile_path, "v2.3 adaptive profile template"
        )
        artifacts = self.profile_template.get("contract_artifacts")
        bundle_sha = self.profile_template.get("contract_bundle_sha256")
        if not isinstance(artifacts, Mapping) or not isinstance(bundle_sha, str):
            raise RQ1V24ProcessError(
                "v2.3 adaptive profile template lacks its contract bundle"
            )
        resolved, identity, self.protocol_sha256 = (
            _resolved_production_profile_v24(
                repo_root=self.repo_root,
                contract_sha256=self.contract.file_sha256,
                profile_template=self.profile_template,
            )
        )
        cache_path = Path(cache_root).resolve()
        if cache_path.exists():
            raise RQ1V24GlobalFatal("v2.4 production cache namespace is not fresh")
        self.cache = RunCache(cache_path, identity)
        self.client = client
        self.planner = SafetyFramedModelPlannerV24(
            resolved_profile=resolved,
            cache=self.cache,
            client=client,
            contract=self.contract.raw,
        )
        pack = load_taskpack(self.pack_root)
        self.tasks = {
            task.task_id: task
            for task in pack.tasks
            if task.task_id in {task_id for task_id, _ in EPISODE_ORDER}
        }
        if set(self.tasks) != {task_id for task_id, _ in EPISODE_ORDER}:
            raise RQ1V24ProcessError("RQ1 taskpack lacks a fixed resource twin")
        self.conditions = load_conditions(conditions_path)
        if not {condition_id for _, condition_id in EPISODE_ORDER} <= set(
            self.conditions
        ):
            raise RQ1V24ProcessError("condition registry lacks a fixed resource arm")
        self.execution_session_id = uuid4().hex
        self.profile_contract = {
            "protocol_id": "host-boundary-v2",
            "construct_id": "authority_admission_boundary",
            "proposal_alignment": "RQ1_authority_admission",
            "execution_stage": "protocol_stage_s",
            "protocol_stage": "S",
            "h_ladder_covered": False,
            "scientific_sample_gate_satisfied": False,
            "visible_context_profile": "objective_aware_adaptive",
            "execution_track": "adaptive_end_to_end",
            "adaptive_contract_version": "2.3.0",
            "contract_artifacts": copy.deepcopy(dict(artifacts)),
            "contract_bundle_sha256": bundle_sha,
        }

    def __call__(
        self,
        *,
        assignment: Mapping[str, Any],
        client: Any,
        max_turns: int,
    ) -> Mapping[str, Any]:
        if client is not self.client:
            raise RQ1V24GlobalFatal(
                "production episode runner received a different framed client"
            )
        if max_turns != MAX_TURNS_PER_EPISODE:
            raise RQ1V24GlobalFatal(
                "production episode runner requires the fixed six-turn budget"
            )
        ordinal = assignment.get("ordinal")
        if (
            isinstance(ordinal, bool)
            or not isinstance(ordinal, int)
            or not 1 <= ordinal <= EPISODE_COUNT
        ):
            raise RQ1V24ProcessError("assigned cell ordinal is invalid")
        expected_task, expected_condition = EPISODE_ORDER[ordinal - 1]
        if (
            assignment.get("task_id"),
            assignment.get("condition_id"),
            assignment.get("max_turns"),
            assignment.get("max_actions_per_turn"),
        ) != (expected_task, expected_condition, MAX_TURNS_PER_EPISODE, 1):
            raise RQ1V24ProcessError("production cell differs from fixed assignment")
        task = self.tasks[expected_task]
        planner_role = (
            PlannerRole.BENIGN
            if task.pair_role == "benign"
            else PlannerRole.ATTACKER
        )
        row = ScheduleRow(
            ordinal=ordinal,
            wave_id="rq1-v24-wave-0001",
            block_id="rq1-v24-resource-block-0001",
            episode_id="0" * 64,
            profile_id="canonical-rq1-resource-safety-framed-v2.4",
            replicate_id="engineering-r1",
            condition_id=expected_condition,
            taskpack_id="rq1-controlled-v2.2",
            task_id=expected_task,
            cluster_id=task.cluster_id,
            pair_id=task.pair_id,
            pair_role=task.pair_role,
            planner_role=planner_role,
        )
        row = replace(
            row,
            episode_id=cache_episode_id(
                row.to_dict(), protocol_sha256=self.protocol_sha256
            ),
        )
        from .runner import (
            _default_adapter_loader,
            _default_oracle_loader,
            _execute_episode,
        )

        record = _execute_episode(
            row=row,
            task=task,
            condition=self.conditions[expected_condition],
            taskpack_root=self.pack_root,
            planner=self.planner,
            adapter_loader=_default_adapter_loader,
            oracle_loader=_default_oracle_loader,
            cache=self.cache,
            max_turns=MAX_TURNS_PER_EPISODE,
            execution_session_id=self.execution_session_id,
            profile_contract=self.profile_contract,
        )
        validate_json(record, schema_name="episode_record")
        return record


def _record_status(record: Mapping[str, Any]) -> str:
    failure = record.get("failure_class", "none")
    terminal = record.get("planner_terminal_kind")
    status = record.get("planner_status")
    aliases = {
        "provider_policy": "provider_policy_failure",
        "parse": "parse_failure",
        "schema": "schema_failure",
    }
    normalized_failure = aliases.get(failure, failure)
    if normalized_failure in _CELL_FAILURE_CLASSES:
        return str(normalized_failure)
    if failure != "none":
        return "returned_unclassified_failure"
    if terminal == "budget_exhausted":
        return "budget_exhausted"
    if status == "explicit_abstention":
        return "explicit_abstention"
    return "recorded"


def _attempt_keys(record: Mapping[str, Any]) -> tuple[str, ...]:
    raw = record.get("attempt_keys", ())
    if not isinstance(raw, (list, tuple)) or any(
        not isinstance(key, str) or not key for key in raw
    ):
        raise RQ1V24ProcessError("episode attempt_keys must be a string sequence")
    if len(set(raw)) != len(raw):
        raise RQ1V24ProcessError("episode attempt_keys contain duplicates")
    return tuple(raw)


def _validate_returned_record(
    record: Mapping[str, Any], assignment: Mapping[str, Any]
) -> tuple[dict[str, Any], tuple[str, ...]]:
    value = copy.deepcopy(dict(record))
    canonical_json_bytes(value)
    for field in ("task_id", "condition_id"):
        if field in value and value[field] != assignment[field]:
            raise RQ1V24ProcessError(
                f"returned episode {field} differs from its frozen assignment"
            )
    ordinal = value.get("schedule_ordinal")
    if ordinal is not None and ordinal != assignment["ordinal"]:
        raise RQ1V24ProcessError(
            "returned episode schedule_ordinal differs from its assignment"
        )
    return value, _attempt_keys(value)


def _cell_frame_count(frames: Sequence[Mapping[str, Any]], ordinal: int) -> int:
    return sum(frame.get("cell_ordinal") == ordinal for frame in frames)


def execute_resilient_four_cell_v24(
    *,
    namespace: Path,
    client: Any,
    episode_runner: EpisodeRunnerV24 | None = None,
    repo_root: Path | None = None,
    framed_client_factory: Callable[..., FramedClientV24] = FramedClientV24,
) -> ExecutionResultV24:
    """Execute all assigned cells and durably record every cell disposition."""

    root = Path(namespace).resolve()
    if root.exists():
        raise RQ1V24GlobalFatal("v2.4 namespace must be fresh")
    root.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.mkdir(root, 0o700)
    except OSError as exc:
        raise RQ1V24GlobalFatal(f"cannot reserve v2.4 namespace: {exc}") from exc
    cells_dir = root / "cells"
    cells_dir.mkdir(mode=0o700)
    assignments = fixed_assignments_v24()
    _write_new(root / "assignments.json", list(assignments))
    framed = framed_client_factory(client, ledger_dir=root / "attempts")
    if episode_runner is None:
        if repo_root is None:
            raise RQ1V24GlobalFatal(
                "production v2.4 execution requires an explicit repository root"
            )
        episode_runner = ProductionEpisodeRunnerV24(
            repo_root=repo_root,
            cache_root=root / "cache",
            client=framed,
        )
    statuses: list[dict[str, Any]] = []
    all_attempt_keys: list[str] = []
    global_fatal: dict[str, str] | None = None

    for assignment in assignments:
        ordinal = int(assignment["ordinal"])
        started_at = _utc_now()
        frames_before = framed.calls_made
        envelope: dict[str, Any]
        framed.begin_cell(assignment)
        try:
            raw_record = episode_runner(
                assignment=copy.deepcopy(assignment),
                client=framed,
                max_turns=MAX_TURNS_PER_EPISODE,
            )
            if not isinstance(raw_record, Mapping):
                raise RQ1V24ProcessError("episode runner returned a non-object")
            record, attempt_keys = _validate_returned_record(raw_record, assignment)
            if set(all_attempt_keys) & set(attempt_keys):
                raise RQ1V24GlobalFatal(
                    "attempt key was reused across assigned cells"
                )
            all_attempt_keys.extend(attempt_keys)
            status = _record_status(record)
            envelope = {
                "schema_version": SCHEMA_VERSION,
                "artifact_type": CELL_ARTIFACT_TYPE,
                "assignment": copy.deepcopy(assignment),
                "status": status,
                "record": record,
                "error": None,
                "attempt_keys": list(attempt_keys),
                "provider_call_frames": framed.calls_made - frames_before,
                "started_at": started_at,
                "finished_at": _utc_now(),
            }
        except RQ1V24GlobalFatal as exc:
            status = "global_fatal"
            global_fatal = {"error_type": type(exc).__name__, "error": str(exc)}
            envelope = {
                "schema_version": SCHEMA_VERSION,
                "artifact_type": CELL_ARTIFACT_TYPE,
                "assignment": copy.deepcopy(assignment),
                "status": status,
                "record": None,
                "error": copy.deepcopy(global_fatal),
                "attempt_keys": [],
                "provider_call_frames": framed.calls_made - frames_before,
                "started_at": started_at,
                "finished_at": _utc_now(),
            }
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit, GeneratorExit)):
                raise
            status = "runner_error"
            envelope = {
                "schema_version": SCHEMA_VERSION,
                "artifact_type": CELL_ARTIFACT_TYPE,
                "assignment": copy.deepcopy(assignment),
                "status": status,
                "record": None,
                "error": {"error_type": type(exc).__name__, "error": str(exc)},
                "attempt_keys": [],
                "provider_call_frames": framed.calls_made - frames_before,
                "started_at": started_at,
                "finished_at": _utc_now(),
            }
        finally:
            framed.end_cell()

        _write_new(cells_dir / f"cell-{ordinal:02d}.json", envelope)
        statuses.append(
            {
                "ordinal": ordinal,
                "task_id": assignment["task_id"],
                "condition_id": assignment["condition_id"],
                "status": status,
                "cell_path": f"cells/cell-{ordinal:02d}.json",
                "attempt_key_count": len(envelope["attempt_keys"]),
                "provider_call_frames": envelope["provider_call_frames"],
            }
        )
        if global_fatal is not None:
            break

    if global_fatal is not None:
        completed_ordinals = {row["ordinal"] for row in statuses}
        for assignment in assignments:
            ordinal = int(assignment["ordinal"])
            if ordinal in completed_ordinals:
                continue
            envelope = {
                "schema_version": SCHEMA_VERSION,
                "artifact_type": CELL_ARTIFACT_TYPE,
                "assignment": copy.deepcopy(assignment),
                "status": "not_run_global_fatal",
                "record": None,
                "error": copy.deepcopy(global_fatal),
                "attempt_keys": [],
                "provider_call_frames": 0,
                "started_at": None,
                "finished_at": _utc_now(),
            }
            _write_new(cells_dir / f"cell-{ordinal:02d}.json", envelope)
            statuses.append(
                {
                    "ordinal": ordinal,
                    "task_id": assignment["task_id"],
                    "condition_id": assignment["condition_id"],
                    "status": "not_run_global_fatal",
                    "cell_path": f"cells/cell-{ordinal:02d}.json",
                    "attempt_key_count": 0,
                    "provider_call_frames": 0,
                }
            )

    frames = framed.frames
    underlying_calls = getattr(client, "calls_made", framed.calls_made)
    calls_match_underlying = underlying_calls == framed.calls_made
    error_statuses = {"runner_error", "global_fatal", "not_run_global_fatal"}
    returned_cells_match = all(
        row["status"] in error_statuses
        or row["attempt_key_count"] == row["provider_call_frames"]
        for row in statuses
    )
    error_cell_unbound_frames = sum(
        row["provider_call_frames"]
        for row in statuses
        if row["status"] in error_statuses
    )
    framed_calls_match_cells = framed.calls_made == sum(
        row["provider_call_frames"] for row in statuses
    )
    all_frames_accounted = (
        len(all_attempt_keys) + error_cell_unbound_frames == framed.calls_made
    )
    ledger_reconciled = bool(
        len(frames) == framed.calls_made
        and len(all_attempt_keys) == len(set(all_attempt_keys))
        and calls_match_underlying
        and returned_cells_match
        and framed_calls_match_cells
        and all_frames_accounted
        and framed.calls_made <= HARD_CALL_CAP
    )
    report = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": REPORT_ARTIFACT_TYPE,
        "process_artifact_type": PROCESS_ARTIFACT_TYPE,
        "assigned_cells": sorted(statuses, key=lambda row: row["ordinal"]),
        "assigned_count": EPISODE_COUNT,
        "provider_calls_framed": framed.calls_made,
        "hard_call_cap": HARD_CALL_CAP,
        "zero_retry_required": True,
        "max_turns_per_cell": MAX_TURNS_PER_EPISODE,
        "attempt_ledger": {
            "frame_count": len(frames),
            "returned_attempt_key_count": len(all_attempt_keys),
            "unique_attempt_key_count": len(set(all_attempt_keys)),
            "underlying_calls": underlying_calls,
            "error_cell_unbound_frame_count": error_cell_unbound_frames,
            "calls_match_underlying": calls_match_underlying,
            "framed_calls_match_cells": framed_calls_match_cells,
            "returned_cells_match_frames": returned_cells_match,
            "all_frames_accounted": all_frames_accounted,
            "reconciled": ledger_reconciled,
        },
        "global_fatal": copy.deepcopy(global_fatal),
        "execution_status": "global_fatal" if global_fatal else "all_cells_attempted",
        "continuation_depended_on_oracle_direction": False,
        "finished_at": _utc_now(),
    }
    _write_new(root / "report.json", report)
    return ExecutionResultV24(namespace=root, report=copy.deepcopy(report))


__all__ = [
    "CALL_FRAME_ARTIFACT_TYPE",
    "CELL_ARTIFACT_TYPE",
    "EPISODE_COUNT",
    "EPISODE_ORDER",
    "ExecutionResultV24",
    "FramedClientV24",
    "HARD_CALL_CAP",
    "MAX_TURNS_PER_EPISODE",
    "MODEL_ID",
    "PACK_RELATIVE_PATH",
    "ProductionEpisodeRunnerV24",
    "PROVIDER_ROUTE_ID",
    "REPORT_ARTIFACT_TYPE",
    "RQ1V24GlobalFatal",
    "RQ1V24ProcessError",
    "execute_resilient_four_cell_v24",
    "fixed_assignments_v24",
]
