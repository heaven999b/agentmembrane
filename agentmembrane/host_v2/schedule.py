"""Deterministic, fully materialized schedules for Host-Boundary V2.

The scheduler is deliberately side-effect free: it assigns complete workflow
blocks and records sliding-window metadata, but it never submits work.  The
runner is responsible for respecting the frozen wave and block boundaries.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import random
from types import MappingProxyType
from typing import Any, Iterable, Mapping, TYPE_CHECKING

from .cache import episode_id as make_episode_id
from .schema import PlannerRole, canonical_json_bytes, sha256_bytes

if TYPE_CHECKING:  # pragma: no cover - imports are only for static checking
    from .conditions import ConditionSpec
    from .profiles import ResolvedProfile
    from .taskpacks import TaskSpec


class ScheduleError(ValueError):
    """Raised when a schedule cannot be constructed without ambiguity."""


@dataclass(frozen=True)
class ConditionEligibilityUniverse:
    """One canonical interpretation of the profile's condition/family design.

    Analysis and integrity import this object rather than independently
    reimplementing the eligibility default.  Multi-family v2.1 profiles fail
    closed without a map.  The full-factorial default is retained only for an
    explicitly marked legacy profile (or a schema-v2 profile that predates the
    v2.1 construct fields).
    """

    by_family: Mapping[str, tuple[str, ...]]
    eligibility_applied: bool
    mode: str
    sha256: str

    @property
    def cells(self) -> frozenset[tuple[str, str]]:
        return frozenset(
            (condition_id, family)
            for family, condition_ids in self.by_family.items()
            for condition_id in condition_ids
        )


@dataclass(frozen=True)
class ScheduleRow:
    ordinal: int
    wave_id: str
    block_id: str
    episode_id: str
    profile_id: str
    replicate_id: str
    condition_id: str
    taskpack_id: str
    task_id: str
    cluster_id: str
    pair_id: str
    pair_role: str
    planner_role: PlannerRole

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["planner_role"] = self.planner_role.value
        return value


def _profile_raw(profile: "ResolvedProfile") -> Mapping[str, Any]:
    raw = getattr(profile, "raw", None)
    if not isinstance(raw, Mapping):
        raise ScheduleError("profile.raw must be a mapping")
    return raw


def _nonempty_string(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ScheduleError(f"{field} must be a non-empty string")
    return value


def _profile_taskpack_ids(raw: Mapping[str, Any]) -> tuple[str, ...]:
    specs = raw.get("taskpacks")
    if not isinstance(specs, list) or not specs:
        raise ScheduleError("profile.taskpacks must be a non-empty list")
    result: list[str] = []
    for index, spec in enumerate(specs):
        if not isinstance(spec, Mapping):
            raise ScheduleError(f"profile.taskpacks[{index}] must be a mapping")
        result.append(_nonempty_string(spec.get("pack_id"), field="taskpack pack_id"))
    if len(result) != len(set(result)):
        raise ScheduleError("profile contains duplicate taskpack IDs")
    return tuple(result)


def _taskpack_id(task: "TaskSpec", configured: tuple[str, ...]) -> str:
    metadata = getattr(task, "metadata", {})
    value: Any = None
    if isinstance(metadata, Mapping):
        value = metadata.get("taskpack_id", metadata.get("pack_id"))
    if value is None and len(configured) == 1:
        value = configured[0]
    result = _nonempty_string(value, field=f"taskpack ID for task {task.task_id!r}")
    if result not in configured:
        raise ScheduleError(f"task {task.task_id!r} names unconfigured taskpack {result!r}")
    return result


def _planner_role(pair_role: str) -> PlannerRole:
    if pair_role == "benign":
        return PlannerRole.BENIGN
    if pair_role in {"adversarial", "attack", "attacker"}:
        return PlannerRole.ATTACKER
    raise ScheduleError(f"unsupported pair_role {pair_role!r}")


def _block_id(
    *, profile_id: str, replicate_id: str, taskpack_id: str, cluster_id: str
) -> str:
    material = {
        "profile_id": profile_id,
        "replicate_id": replicate_id,
        "taskpack_id": taskpack_id,
        "cluster_id": cluster_id,
    }
    return f"block-{sha256_bytes(canonical_json_bytes(material))[:24]}"


def _protocol_sha(raw: Mapping[str, Any]) -> str:
    resolution = raw.get("resolution")
    if not isinstance(resolution, Mapping):
        raise ScheduleError("resolved profile is missing resolution")
    value = _nonempty_string(
        resolution.get("protocol_sha256"), field="resolution.protocol_sha256"
    )
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ScheduleError("resolution.protocol_sha256 must be lowercase SHA-256")
    return value


def _replicate_ids(raw: Mapping[str, Any]) -> tuple[str, ...]:
    values = raw.get("replicates")
    if not isinstance(values, list) or not values:
        raise ScheduleError("profile.replicates must be a non-empty list")
    result: list[str] = []
    for index, value in enumerate(values):
        if not isinstance(value, Mapping):
            raise ScheduleError(f"profile.replicates[{index}] must be a mapping")
        result.append(
            _nonempty_string(value.get("replicate_id"), field="replicate_id")
        )
    if len(result) != len(set(result)):
        raise ScheduleError("profile contains duplicate replicate IDs")
    return tuple(result)


def _schedule_settings(raw: Mapping[str, Any]) -> tuple[int, int]:
    schedule = raw.get("schedule")
    if not isinstance(schedule, Mapping):
        raise ScheduleError("profile.schedule must be a mapping")
    if schedule.get("algorithm") != "paired_block_randomized_sliding_window_v2":
        raise ScheduleError("unsupported schedule algorithm")
    if schedule.get("twins_same_wave") is not True:
        raise ScheduleError("twins_same_wave must be true")
    seed = schedule.get("seed")
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise ScheduleError("profile.schedule.seed must be an integer")
    resolution = raw.get("resolution")
    if not isinstance(resolution, Mapping):
        raise ScheduleError("resolved profile is missing resolution")
    window = resolution.get("selected_max_inflight_blocks")
    if not isinstance(window, int) or isinstance(window, bool) or window < 1:
        raise ScheduleError("selected_max_inflight_blocks must be a positive integer")
    return seed, window


def _condition_eligibility(
    raw: Mapping[str, Any], *, frozen_condition_ids: tuple[str, ...]
) -> dict[str, tuple[str, ...]] | None:
    schedule = raw.get("schedule")
    if not isinstance(schedule, Mapping):
        raise ScheduleError("profile.schedule must be a mapping")
    value = schedule.get("condition_eligibility")
    if value is None:
        return None
    if not isinstance(value, Mapping) or not value:
        raise ScheduleError("schedule.condition_eligibility must be a non-empty mapping")
    frozen = set(frozen_condition_ids)
    result: dict[str, tuple[str, ...]] = {}
    for family, condition_values in value.items():
        family_name = _nonempty_string(family, field="condition eligibility family")
        if not isinstance(condition_values, list) or not condition_values:
            raise ScheduleError(
                f"condition eligibility for family {family_name!r} must be a non-empty list"
            )
        selected = tuple(
            _nonempty_string(item, field=f"eligible condition for {family_name!r}")
            for item in condition_values
        )
        if len(selected) != len(set(selected)):
            raise ScheduleError(
                f"condition eligibility for family {family_name!r} contains duplicates"
            )
        unknown = sorted(set(selected) - frozen)
        if unknown:
            raise ScheduleError(
                f"condition eligibility for family {family_name!r} names unknown arms {unknown!r}"
            )
        result[family_name] = selected
    return result


def condition_eligibility_universe(
    raw: Mapping[str, Any],
    *,
    condition_ids: Iterable[str],
    families: Iterable[str],
) -> ConditionEligibilityUniverse:
    """Resolve and validate eligible ``(condition, family)`` cells once.

    ``condition_ids`` and ``families`` are the cells requested by the caller,
    not an invitation to silently discard a missing family.  A declared map
    must cover every requested family and at least one requested condition for
    each family.  New multi-family profiles without a map are rejected.
    """

    requested_conditions = tuple(sorted({str(value) for value in condition_ids}))
    requested_families = tuple(sorted({str(value) for value in families}))
    if not requested_conditions:
        raise ScheduleError("condition eligibility requires at least one condition")
    if not requested_families:
        raise ScheduleError("condition eligibility requires at least one family")
    if any(not value for value in requested_conditions + requested_families):
        raise ScheduleError("condition eligibility names must be non-empty strings")

    frozen_raw = raw.get("condition_ids")
    frozen_conditions = (
        tuple(str(value) for value in frozen_raw)
        if isinstance(frozen_raw, list) and frozen_raw
        else requested_conditions
    )
    schedule_value = raw.get("schedule")
    parsed = (
        _condition_eligibility(
            raw, frozen_condition_ids=tuple(sorted(set(frozen_conditions)))
        )
        if isinstance(schedule_value, Mapping)
        else None
    )
    if parsed is None:
        schedule = raw.get("schedule", {})
        explicit_legacy = bool(
            isinstance(schedule, Mapping)
            and schedule.get("eligibility_mode") == "legacy_full_factorial"
        )
        predates_v21 = bool(
            raw.get("schema_version") == 2 and "construct_id" not in raw
        )
        if len(requested_families) > 1 and not (explicit_legacy or predates_v21):
            raise ScheduleError(
                "profile.schedule.condition_eligibility is required for a "
                "multi-family non-legacy profile"
            )
        mapping = {
            family: requested_conditions for family in requested_families
        }
        mode = "legacy_full_factorial" if len(requested_families) > 1 else "single_family"
        applied = False
    else:
        missing = sorted(set(requested_families) - set(parsed))
        if missing:
            raise ScheduleError(
                f"task family {missing[0]!r} has no frozen condition eligibility entry"
            )
        requested_set = set(requested_conditions)
        mapping: dict[str, tuple[str, ...]] = {}
        for family in requested_families:
            selected = tuple(
                condition_id
                for condition_id in parsed[family]
                if condition_id in requested_set
            )
            if not selected:
                raise ScheduleError(
                    f"condition eligibility for family {family!r} has no requested arms"
                )
            mapping[family] = selected
        mode = "mapped"
        applied = True

    canonical = {family: tuple(mapping[family]) for family in sorted(mapping)}
    hash_payload = {family: list(values) for family, values in canonical.items()}
    return ConditionEligibilityUniverse(
        by_family=MappingProxyType(canonical),
        eligibility_applied=applied,
        mode=mode,
        sha256=sha256_bytes(canonical_json_bytes(hash_payload)),
    )


def _eligible_conditions_for_tasks(
    tasks: Iterable["TaskSpec"],
    *,
    all_condition_ids: tuple[str, ...],
    eligibility: Mapping[str, tuple[str, ...]] | None,
) -> tuple[str, ...]:
    if eligibility is None:
        return all_condition_ids
    families = {str(getattr(task, "family", "")) for task in tasks}
    if len(families) != 1:
        raise ScheduleError("one task pair must have exactly one family for condition eligibility")
    family = next(iter(families))
    try:
        return eligibility[family]
    except KeyError as exc:
        raise ScheduleError(
            f"task family {family!r} has no frozen condition eligibility entry"
        ) from exc


def _validate_task_twins(
    tasks: Iterable["TaskSpec"], *, configured_packs: tuple[str, ...]
) -> None:
    """Validate twins in their serialized (taskpack, cluster, pair) scope."""

    pair_tasks: dict[tuple[str, str, str], list["TaskSpec"]] = {}
    pair_families: dict[tuple[str, str, str], set[str]] = {}
    seen_task_ids: set[tuple[str, str]] = set()
    for task in tasks:
        task_id = _nonempty_string(getattr(task, "task_id", None), field="task_id")
        cluster_id = _nonempty_string(
            getattr(task, "cluster_id", None), field=f"cluster_id for task {task_id!r}"
        )
        pair_id = _nonempty_string(
            getattr(task, "pair_id", None), field=f"pair_id for task {task_id!r}"
        )
        pair_role = getattr(task, "pair_role", None)
        if not isinstance(pair_role, str):
            raise ScheduleError(f"pair_role for task {task_id!r} must be a string")
        _planner_role(pair_role)
        pack_id = _taskpack_id(task, configured_packs)
        coordinate = (pack_id, task_id)
        if coordinate in seen_task_ids:
            raise ScheduleError(f"duplicate task coordinate {coordinate!r}")
        seen_task_ids.add(coordinate)
        key = (pack_id, cluster_id, pair_id)
        pair_tasks.setdefault(key, []).append(task)
        pair_families.setdefault(key, set()).add(str(getattr(task, "family", "")))
    for key, twins in pair_tasks.items():
        roles = sorted(task.pair_role for task in twins)
        if sorted(roles) != ["adversarial", "benign"]:
            raise ScheduleError(
                f"pair {key!r} must contain exactly one benign and one adversarial twin"
            )
        if len(pair_families[key]) != 1:
            raise ScheduleError(f"pair {key!r} mixes task families")


def build_schedule(
    *,
    profile: "ResolvedProfile",
    tasks: tuple["TaskSpec", ...],
    conditions: tuple["ConditionSpec", ...],
) -> tuple[ScheduleRow, ...]:
    """Build the complete frozen schedule without performing any execution."""

    if not tasks:
        raise ScheduleError("cannot schedule zero tasks")
    if not conditions:
        raise ScheduleError("cannot schedule zero conditions")
    raw = _profile_raw(profile)
    profile_id = _nonempty_string(raw.get("profile_id"), field="profile_id")
    protocol_sha256 = _protocol_sha(raw)
    replicate_ids = _replicate_ids(raw)
    seed, window_size = _schedule_settings(raw)
    configured_packs = _profile_taskpack_ids(raw)
    _validate_task_twins(tasks, configured_packs=configured_packs)

    supplied_condition_ids = [
        _nonempty_string(getattr(condition, "condition_id", None), field="condition_id")
        for condition in conditions
    ]
    if len(supplied_condition_ids) != len(set(supplied_condition_ids)):
        raise ScheduleError("duplicate condition IDs")
    frozen_condition_ids = raw.get("condition_ids")
    if not isinstance(frozen_condition_ids, list):
        raise ScheduleError("profile.condition_ids must be a list")
    frozen_condition_ids = [
        _nonempty_string(value, field="profile condition_id")
        for value in frozen_condition_ids
    ]
    if len(frozen_condition_ids) != len(set(frozen_condition_ids)):
        raise ScheduleError("profile.condition_ids contains duplicates")
    if set(supplied_condition_ids) != set(frozen_condition_ids) or len(
        supplied_condition_ids
    ) != len(
        frozen_condition_ids
    ):
        raise ScheduleError("conditions do not exactly match frozen profile.condition_ids")
    # Seeded shuffles must start from a canonical sequence, not caller order.
    condition_ids = tuple(sorted(supplied_condition_ids))
    task_families = {str(getattr(task, "family", "")) for task in tasks}
    universe = condition_eligibility_universe(
        raw, condition_ids=condition_ids, families=task_families
    )
    eligibility = universe.by_family

    # A block is the entire taskpack/workflow-cluster/replicate cell.  It
    # contains every task pair and every condition arm, so neither twins nor
    # contrast arms can drift into a later provider-time wave.
    blocks: dict[tuple[str, str, str], list["TaskSpec"]] = {}
    for task in tasks:
        cluster_id = _nonempty_string(task.cluster_id, field="cluster_id")
        pack_id = _taskpack_id(task, configured_packs)
        for replicate_id in replicate_ids:
            blocks.setdefault((replicate_id, pack_id, cluster_id), []).append(task)
    observed_packs = {key[1] for key in blocks}
    if observed_packs != set(configured_packs):
        missing = sorted(set(configured_packs) - observed_packs)
        raise ScheduleError(f"no tasks supplied for configured taskpacks {missing!r}")

    rng = random.Random(seed)
    ordered_block_keys = sorted(blocks)
    rng.shuffle(ordered_block_keys)

    rows: list[ScheduleRow] = []
    ordinal = 1
    for block_position, block_key in enumerate(ordered_block_keys):
        replicate_id, pack_id, cluster_id = block_key
        block_tasks = blocks[block_key]
        block_id = _block_id(
            profile_id=profile_id,
            replicate_id=replicate_id,
            taskpack_id=pack_id,
            cluster_id=cluster_id,
        )
        wave_id = f"wave-{block_position // window_size + 1:06d}"

        pair_groups: dict[str, list["TaskSpec"]] = {}
        for task in block_tasks:
            pair_groups.setdefault(task.pair_id, []).append(task)
        pair_keys = sorted(pair_groups)
        rng.shuffle(pair_keys)

        for pair_key in pair_keys:
            pair_tasks = sorted(
                pair_groups[pair_key], key=lambda item: (item.pair_role, item.task_id)
            )
            if sorted(task.pair_role for task in pair_tasks) != ["adversarial", "benign"]:
                raise ScheduleError(f"invalid twins inside block {block_id}: {pair_key!r}")
            arm_order = list(
                _eligible_conditions_for_tasks(
                    pair_tasks,
                    all_condition_ids=condition_ids,
                    eligibility=eligibility,
                )
            )
            rng.shuffle(arm_order)
            for condition_id in arm_order:
                twins = list(pair_tasks)
                rng.shuffle(twins)
                for task in twins:
                    payload = {
                        "ordinal": ordinal,
                        "wave_id": wave_id,
                        "block_id": block_id,
                        "profile_id": profile_id,
                        "replicate_id": replicate_id,
                        "condition_id": condition_id,
                        "taskpack_id": pack_id,
                        "task_id": task.task_id,
                        "cluster_id": cluster_id,
                        "pair_id": task.pair_id,
                        "pair_role": task.pair_role,
                        "planner_role": _planner_role(task.pair_role).value,
                    }
                    current_episode_id = make_episode_id(
                        payload, protocol_sha256=protocol_sha256
                    )
                    rows.append(
                        ScheduleRow(
                            ordinal=ordinal,
                            wave_id=wave_id,
                            block_id=block_id,
                            episode_id=current_episode_id,
                            profile_id=profile_id,
                            replicate_id=replicate_id,
                            condition_id=condition_id,
                            taskpack_id=pack_id,
                            task_id=task.task_id,
                            cluster_id=cluster_id,
                            pair_id=task.pair_id,
                            pair_role=task.pair_role,
                            planner_role=_planner_role(task.pair_role),
                        )
                    )
                    ordinal += 1

    result = tuple(rows)
    errors = validate_schedule(result, profile=profile)
    if errors:
        raise ScheduleError("invalid generated schedule: " + "; ".join(errors))
    return result


def validate_schedule(
    rows: tuple[ScheduleRow, ...], *, profile: "ResolvedProfile"
) -> list[str]:
    """Return all structural errors in a materialized schedule."""

    errors: list[str] = []
    try:
        raw = _profile_raw(profile)
        profile_id = _nonempty_string(raw.get("profile_id"), field="profile_id")
        protocol_sha256 = _protocol_sha(raw)
        replicate_ids = set(_replicate_ids(raw))
        configured_packs = set(_profile_taskpack_ids(raw))
        _, window_size = _schedule_settings(raw)
        condition_ids = raw.get("condition_ids")
        if not isinstance(condition_ids, list):
            raise ScheduleError("profile.condition_ids must be a list")
        frozen_conditions = [
            _nonempty_string(value, field="profile condition_id") for value in condition_ids
        ]
        if len(frozen_conditions) != len(set(frozen_conditions)):
            raise ScheduleError("profile.condition_ids contains duplicates")
        expected_conditions = set(frozen_conditions)
        declared_families = {
            str(family)
            for taskpack in raw.get("taskpacks", [])
            if isinstance(taskpack, Mapping)
            for family in (taskpack.get("families") or [])
        }
        if declared_families:
            eligibility = condition_eligibility_universe(
                raw,
                condition_ids=frozen_conditions,
                families=declared_families,
            ).by_family
        else:
            eligibility = _condition_eligibility(
                raw, frozen_condition_ids=tuple(frozen_conditions)
            )
        allowed_condition_sets = (
            {frozenset(expected_conditions)}
            if eligibility is None
            else {frozenset(value) for value in eligibility.values()}
        )
    except ScheduleError as exc:
        return [str(exc)]

    if not rows:
        return ["schedule is empty"]
    if [row.ordinal for row in rows] != list(range(1, len(rows) + 1)):
        errors.append("ordinals must be contiguous and one-based")
    if len({row.episode_id for row in rows}) != len(rows):
        errors.append("episode IDs must be unique")

    block_waves: dict[str, set[str]] = {}
    wave_blocks: dict[str, set[str]] = {}
    block_keys: dict[str, set[tuple[str, str, str, str]]] = {}
    block_pairs: dict[str, dict[str, dict[str, list[tuple[int, str, str]]]]] = {}
    target_keys: set[tuple[str, str, str, str, str]] = set()
    task_coordinates: dict[tuple[str, str], set[tuple[str, str, str]]] = {}
    cluster_replicates: dict[
        tuple[str, str], dict[str, set[tuple[str, str, str]]]
    ] = {}
    block_sequence: list[str] = []
    prior_block: str | None = None
    closed_blocks: set[str] = set()

    for row in rows:
        if row.profile_id != profile_id:
            errors.append(f"row {row.ordinal} profile_id mismatch")
        if row.replicate_id not in replicate_ids:
            errors.append(f"row {row.ordinal} has unknown replicate_id")
        if row.condition_id not in expected_conditions:
            errors.append(f"row {row.ordinal} has unknown condition_id")
        if row.taskpack_id not in configured_packs:
            errors.append(f"row {row.ordinal} has unknown taskpack_id")
        for field in ("wave_id", "block_id", "task_id", "cluster_id", "pair_id"):
            if not isinstance(getattr(row, field), str) or not getattr(row, field):
                errors.append(f"row {row.ordinal} has invalid {field}")
        try:
            expected_role = _planner_role(row.pair_role)
        except ScheduleError:
            errors.append(f"row {row.ordinal} has invalid pair_role")
        else:
            if row.planner_role != expected_role:
                errors.append(f"row {row.ordinal} planner_role does not match pair_role")
        planner_role_value = (
            row.planner_role.value
            if isinstance(row.planner_role, PlannerRole)
            else str(row.planner_role)
        )
        payload = {
            "ordinal": row.ordinal,
            "wave_id": row.wave_id,
            "block_id": row.block_id,
            "profile_id": row.profile_id,
            "replicate_id": row.replicate_id,
            "condition_id": row.condition_id,
            "taskpack_id": row.taskpack_id,
            "task_id": row.task_id,
            "cluster_id": row.cluster_id,
            "pair_id": row.pair_id,
            "pair_role": row.pair_role,
            "planner_role": planner_role_value,
        }
        expected_episode_id = make_episode_id(payload, protocol_sha256=protocol_sha256)
        if row.episode_id != expected_episode_id:
            errors.append(f"row {row.ordinal} episode_id mismatch")

        target_key = (
            row.profile_id,
            row.replicate_id,
            row.condition_id,
            row.taskpack_id,
            row.task_id,
        )
        if target_key in target_keys:
            errors.append(f"row {row.ordinal} duplicates target key {target_key!r}")
        target_keys.add(target_key)

        expected_block_id = _block_id(
            profile_id=row.profile_id,
            replicate_id=row.replicate_id,
            taskpack_id=row.taskpack_id,
            cluster_id=row.cluster_id,
        )
        if row.block_id != expected_block_id:
            errors.append(f"row {row.ordinal} block_id mismatch")
        if row.block_id != prior_block:
            if prior_block is not None:
                closed_blocks.add(prior_block)
            if row.block_id in closed_blocks:
                errors.append(f"block {row.block_id} is not contiguous")
            block_sequence.append(row.block_id)
            prior_block = row.block_id

        block_waves.setdefault(row.block_id, set()).add(row.wave_id)
        wave_blocks.setdefault(row.wave_id, set()).add(row.block_id)
        block_keys.setdefault(row.block_id, set()).add(
            (row.profile_id, row.replicate_id, row.taskpack_id, row.cluster_id)
        )
        block_pairs.setdefault(row.block_id, {}).setdefault(row.pair_id, {}).setdefault(
            row.condition_id, []
        ).append((row.ordinal, row.task_id, row.pair_role))
        task_coordinates.setdefault((row.taskpack_id, row.task_id), set()).add(
            (row.cluster_id, row.pair_id, row.pair_role)
        )
        cluster_replicates.setdefault(
            (row.taskpack_id, row.cluster_id), {}
        ).setdefault(row.replicate_id, set()).add(
            (row.pair_id, row.task_id, row.pair_role)
        )

    for block_id, waves in block_waves.items():
        if len(waves) != 1:
            errors.append(f"block {block_id} is split across waves")
    for wave_id, block_ids in wave_blocks.items():
        if len(block_ids) > window_size:
            errors.append(f"wave {wave_id} exceeds max inflight block metadata")
    for position, block_id in enumerate(block_sequence):
        expected_wave = f"wave-{position // window_size + 1:06d}"
        if block_waves.get(block_id) != {expected_wave}:
            errors.append(f"block {block_id} has noncanonical wave assignment")
    for block_id, keys in block_keys.items():
        if len(keys) != 1:
            errors.append(f"block {block_id} mixes workflow-cluster cells")
    for block_id, pairs in block_pairs.items():
        for pair_id, arms in pairs.items():
            if frozenset(arms) not in allowed_condition_sets:
                errors.append(f"block {block_id} pair {pair_id} lacks complete condition arms")
            for condition_id, twins in arms.items():
                roles = sorted(item[2] for item in twins)
                ordinals = sorted(item[0] for item in twins)
                if roles != ["adversarial", "benign"]:
                    errors.append(
                        f"block {block_id} pair {pair_id} condition {condition_id} lacks twins"
                    )
                if len(ordinals) != 2 or ordinals[1] != ordinals[0] + 1:
                    errors.append(
                        f"block {block_id} pair {pair_id} condition {condition_id} twins are not adjacent"
                    )
            task_twins = {
                condition_id: {(item[1], item[2]) for item in twins}
                for condition_id, twins in arms.items()
            }
            if task_twins and len({frozenset(value) for value in task_twins.values()}) != 1:
                errors.append(
                    f"block {block_id} pair {pair_id} changes twin task IDs across conditions"
                )
    for coordinate, bindings in task_coordinates.items():
        if len(bindings) != 1:
            errors.append(f"task coordinate {coordinate!r} has inconsistent pair binding")
    for cluster, by_replicate in cluster_replicates.items():
        if set(by_replicate) != replicate_ids:
            errors.append(f"workflow cluster {cluster!r} lacks complete replicate blocks")
            continue
        signatures = {frozenset(value) for value in by_replicate.values()}
        if len(signatures) != 1:
            errors.append(f"workflow cluster {cluster!r} changes tasks across replicates")
        for replicate_id, signature in by_replicate.items():
            for pair_id, task_id, pair_role in signature:
                observed = {
                    row.condition_id
                    for row in rows
                    if row.taskpack_id == cluster[0]
                    and row.cluster_id == cluster[1]
                    and row.replicate_id == replicate_id
                    and row.pair_id == pair_id
                    and row.task_id == task_id
                    and row.pair_role == pair_role
                }
                expected_for_pair = {
                    row.condition_id
                    for row in rows
                    if row.taskpack_id == cluster[0]
                    and row.cluster_id == cluster[1]
                    and row.replicate_id == replicate_id
                    and row.pair_id == pair_id
                }
                if (
                    frozenset(expected_for_pair) not in allowed_condition_sets
                    or observed != expected_for_pair
                ):
                    errors.append(
                        f"target {(cluster[0], replicate_id, task_id)!r} lacks complete condition arms"
                    )
    if {row.taskpack_id for row in rows} != configured_packs:
        errors.append("schedule does not cover every configured taskpack")
    return errors


def schedule_sha256(rows: tuple[ScheduleRow, ...]) -> str:
    """Hash the complete canonical row list, including ordinals and waves."""

    return sha256_bytes(canonical_json_bytes([row.to_dict() for row in rows]))


def sliding_window_metadata(
    rows: tuple[ScheduleRow, ...], *, profile: "ResolvedProfile"
) -> dict[str, Any]:
    """Describe frozen waves without launching or otherwise executing them."""

    raw = _profile_raw(profile)
    seed, window_size = _schedule_settings(raw)
    waves: dict[str, list[str]] = {}
    for row in rows:
        block_ids = waves.setdefault(row.wave_id, [])
        if row.block_id not in block_ids:
            block_ids.append(row.block_id)
    return {
        "algorithm": "paired_block_randomized_sliding_window_v2",
        "seed": seed,
        "max_inflight_blocks": window_size,
        "execution_performed": False,
        "waves": [
            {"wave_id": wave_id, "block_ids": tuple(block_ids)}
            for wave_id, block_ids in waves.items()
        ],
    }
