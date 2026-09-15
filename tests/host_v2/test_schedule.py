from __future__ import annotations

from dataclasses import dataclass, replace
from types import SimpleNamespace
import unittest

from agentmembrane.host_v2.schedule import (
    ScheduleError,
    build_schedule,
    condition_eligibility_universe,
    schedule_sha256,
    sliding_window_metadata,
    validate_schedule,
)


@dataclass(frozen=True)
class FakeTask:
    task_id: str
    cluster_id: str
    pair_id: str
    pair_role: str
    family: str = "workflow"
    metadata: dict[str, str] | None = None

    def __post_init__(self) -> None:
        if self.metadata is None:
            object.__setattr__(self, "metadata", {"taskpack_id": "pack-real"})


def _profile(
    *, seed: int = 17, window: int = 2, packs: tuple[str, ...] = ("pack-real",)
) -> SimpleNamespace:
    return SimpleNamespace(
        raw={
            "profile_id": "formal-rq",
            "resolution": {
                "protocol_sha256": "a" * 64,
                "selected_max_inflight_blocks": window,
            },
            "schedule": {
                "algorithm": "paired_block_randomized_sliding_window_v2",
                "seed": seed,
                "twins_same_wave": True,
            },
            "replicates": [
                {"replicate_id": "r1", "sampling_unit": "upstream_task"},
                {"replicate_id": "r2", "sampling_unit": "upstream_task"},
            ],
            "taskpacks": [{"pack_id": value} for value in packs],
            "condition_ids": ["left", "right", "control"],
        }
    )


def _conditions() -> tuple[SimpleNamespace, ...]:
    return tuple(SimpleNamespace(condition_id=value) for value in ("left", "right", "control"))


def _tasks(clusters: int = 4) -> tuple[FakeTask, ...]:
    result: list[FakeTask] = []
    for index in range(clusters):
        cluster = f"workflow-{index}"
        pair = f"pair-{index}"
        result.extend(
            (
                FakeTask(f"{pair}-benign", cluster, pair, "benign"),
                FakeTask(f"{pair}-attack", cluster, pair, "adversarial"),
            )
        )
    return tuple(result)


class ScheduleTests(unittest.TestCase):
    def test_family_condition_eligibility_avoids_cross_family_cartesian_product(self) -> None:
        profile = _profile(window=2)
        profile.raw["schedule"]["condition_eligibility"] = {
            "family-a": ["left", "right"],
            "family-b": ["right", "control"],
        }
        base = _tasks(clusters=2)
        tasks = tuple(
            replace(task, family="family-a" if task.cluster_id.endswith("0") else "family-b")
            for task in base
        )
        rows = build_schedule(profile=profile, tasks=tasks, conditions=_conditions())
        # 2 workflows x 2 replicates x 2 eligible arms x 2 twins.
        self.assertEqual(len(rows), 16)
        for row in rows:
            expected = (
                {"left", "right"}
                if row.cluster_id.endswith("0")
                else {"right", "control"}
            )
            observed = {
                item.condition_id
                for item in rows
                if item.block_id == row.block_id and item.pair_id == row.pair_id
            }
            self.assertEqual(observed, expected)
        self.assertEqual(validate_schedule(rows, profile=profile), [])

        universe = condition_eligibility_universe(
            profile.raw,
            condition_ids=("left", "right", "control"),
            families=("family-a", "family-b"),
        )
        self.assertEqual(universe.by_family["family-a"], ("left", "right"))
        with self.assertRaises(TypeError):
            universe.by_family["family-a"] = ("control",)  # type: ignore[index]

    def test_family_condition_eligibility_requires_every_task_family(self) -> None:
        profile = _profile()
        profile.raw["schedule"]["condition_eligibility"] = {
            "different-family": ["left", "right"]
        }
        with self.assertRaisesRegex(ScheduleError, "has no frozen condition eligibility"):
            build_schedule(profile=profile, tasks=_tasks(), conditions=_conditions())

    def test_multi_family_missing_eligibility_fails_closed_but_legacy_is_explicit(self) -> None:
        profile = _profile()
        base = _tasks(clusters=2)
        tasks = tuple(
            replace(task, family="family-a" if task.cluster_id.endswith("0") else "family-b")
            for task in base
        )
        with self.assertRaisesRegex(ScheduleError, "required for a multi-family"):
            build_schedule(profile=profile, tasks=tasks, conditions=_conditions())

        profile.raw["schema_version"] = 2
        rows = build_schedule(profile=profile, tasks=tasks, conditions=_conditions())
        self.assertEqual(len(rows), 24)
        universe = condition_eligibility_universe(
            profile.raw,
            condition_ids=("left", "right", "control"),
            families=("family-a", "family-b"),
        )
        self.assertEqual(universe.mode, "legacy_full_factorial")
        self.assertFalse(universe.eligibility_applied)
        self.assertEqual(len(universe.cells), 6)

    def test_schedule_is_deterministic_and_seed_randomized(self) -> None:
        first = build_schedule(profile=_profile(seed=11), tasks=_tasks(), conditions=_conditions())
        second = build_schedule(profile=_profile(seed=11), tasks=_tasks(), conditions=_conditions())
        other_seed = build_schedule(
            profile=_profile(seed=9382), tasks=_tasks(), conditions=_conditions()
        )
        self.assertEqual(first, second)
        self.assertEqual(schedule_sha256(first), schedule_sha256(second))
        self.assertNotEqual(first, other_seed)
        self.assertNotEqual(schedule_sha256(first), schedule_sha256(other_seed))

    def test_seeded_schedule_is_independent_of_task_and_condition_input_order(self) -> None:
        profile = _profile(seed=41)
        tasks = _tasks()
        conditions = _conditions()
        canonical = build_schedule(profile=profile, tasks=tasks, conditions=conditions)
        reversed_inputs = build_schedule(
            profile=profile,
            tasks=tuple(reversed(tasks)),
            conditions=tuple(reversed(conditions)),
        )
        self.assertEqual(canonical, reversed_inputs)
        self.assertEqual(schedule_sha256(canonical), schedule_sha256(reversed_inputs))

    def test_complete_cluster_superblocks_twins_and_arms_share_wave(self) -> None:
        rows = build_schedule(profile=_profile(window=2), tasks=_tasks(), conditions=_conditions())
        # 4 workflows x 2 replicates x 3 conditions x 2 twins.
        self.assertEqual(len(rows), 48)
        blocks: dict[str, list] = {}
        for row in rows:
            blocks.setdefault(row.block_id, []).append(row)
        self.assertEqual(len(blocks), 8)
        for block_rows in blocks.values():
            self.assertEqual(len({row.wave_id for row in block_rows}), 1)
            self.assertEqual(len({row.cluster_id for row in block_rows}), 1)
            self.assertEqual(len({row.replicate_id for row in block_rows}), 1)
            self.assertEqual({row.condition_id for row in block_rows}, {"left", "right", "control"})
            for condition in ("left", "right", "control"):
                twins = [row for row in block_rows if row.condition_id == condition]
                self.assertEqual({row.pair_role for row in twins}, {"benign", "adversarial"})
                self.assertEqual(max(row.ordinal for row in twins) - min(row.ordinal for row in twins), 1)
        for wave in {row.wave_id for row in rows}:
            self.assertLessEqual(len({row.block_id for row in rows if row.wave_id == wave}), 2)
        self.assertEqual(validate_schedule(rows, profile=_profile(window=2)), [])

    def test_sliding_window_is_frozen_metadata_not_execution(self) -> None:
        profile = _profile(window=2)
        rows = build_schedule(profile=profile, tasks=_tasks(), conditions=_conditions())
        metadata = sliding_window_metadata(rows, profile=profile)
        self.assertFalse(metadata["execution_performed"])
        self.assertEqual(metadata["max_inflight_blocks"], 2)
        self.assertEqual(sum(len(wave["block_ids"]) for wave in metadata["waves"]), 8)

    def test_validation_detects_episode_and_wave_tampering(self) -> None:
        profile = _profile(window=2)
        rows = build_schedule(profile=profile, tasks=_tasks(), conditions=_conditions())
        tampered = list(rows)
        tampered[0] = replace(tampered[0], wave_id="wave-tampered")
        errors = validate_schedule(tuple(tampered), profile=profile)
        self.assertTrue(any("split across waves" in error for error in errors))
        self.assertTrue(any("episode_id mismatch" in error for error in errors))

    def test_incomplete_or_lexical_only_twins_are_rejected(self) -> None:
        with self.assertRaises(ScheduleError):
            build_schedule(profile=_profile(), tasks=_tasks()[:-1], conditions=_conditions())

    def test_conditions_must_match_frozen_profile_exactly(self) -> None:
        with self.assertRaises(ScheduleError):
            build_schedule(
                profile=_profile(),
                tasks=_tasks(),
                conditions=(SimpleNamespace(condition_id="left"),),
            )

    def test_task_ids_are_scoped_by_taskpack_and_all_packs_are_covered(self) -> None:
        tasks: list[FakeTask] = []
        for pack in ("pack-a", "pack-b"):
            tasks.extend(
                [
                    FakeTask(
                        "shared-benign",
                        "workflow-shared",
                        "pair-shared",
                        "benign",
                        metadata={"taskpack_id": pack},
                    ),
                    FakeTask(
                        "shared-attack",
                        "workflow-shared",
                        "pair-shared",
                        "adversarial",
                        metadata={"taskpack_id": pack},
                    ),
                ]
            )
        profile = _profile(packs=("pack-a", "pack-b"))
        rows = build_schedule(
            profile=profile, tasks=tuple(reversed(tasks)), conditions=_conditions()
        )
        self.assertEqual({row.taskpack_id for row in rows}, {"pack-a", "pack-b"})
        self.assertEqual(validate_schedule(rows, profile=profile), [])
        with self.assertRaises(ScheduleError):
            build_schedule(
                profile=profile,
                tasks=tuple(task for task in tasks if task.metadata["taskpack_id"] == "pack-a"),
                conditions=_conditions(),
            )

    def test_validation_rejects_duplicate_and_incomplete_target_keys(self) -> None:
        profile = _profile(window=2)
        rows = build_schedule(profile=profile, tasks=_tasks(), conditions=_conditions())
        incomplete = tuple(row for index, row in enumerate(rows) if index != 0)
        errors = validate_schedule(incomplete, profile=profile)
        self.assertTrue(any("lacks complete condition arms" in error for error in errors))

        duplicate = list(rows)
        duplicate[1] = replace(
            duplicate[1],
            condition_id=duplicate[0].condition_id,
            task_id=duplicate[0].task_id,
            pair_role=duplicate[0].pair_role,
            planner_role=duplicate[0].planner_role,
            episode_id=duplicate[0].episode_id,
        )
        errors = validate_schedule(tuple(duplicate), profile=profile)
        self.assertTrue(any("duplicates target key" in error for error in errors))

    def test_validation_recomputes_block_and_wave_assignments(self) -> None:
        profile = _profile(window=2)
        rows = build_schedule(profile=profile, tasks=_tasks(), conditions=_conditions())
        tampered = list(rows)
        for index, row in enumerate(tampered):
            if row.block_id == rows[0].block_id:
                tampered[index] = replace(row, block_id="block-forged")
        errors = validate_schedule(tuple(tampered), profile=profile)
        self.assertTrue(any("block_id mismatch" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
