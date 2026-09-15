"""Independent v5 workflow and paired-pilot closure tests.

The four engineering cells below exercise the real native task subprocess,
runtime, sealed evidence, evaluation, workflow status, and paired analyzer.  No
model endpoint or paid call is used.
"""
from __future__ import annotations

import copy
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.rq1_collab_v1.audit import file_hash, strict_loads
from agentmembrane.host_v2.rq1_collab_v4 import workflow as v4_workflow
from agentmembrane.host_v2.rq1_collab_v5 import paired_pilot, workflow
from agentmembrane.host_v2.rq1_collab_v5.contract import (
    FIXED_BUDGET,
    PHASE_SCHEDULE,
    PHASE_SCHEDULE_SHA256,
    PROTOCOL,
    digest,
)


FROZEN_V4_MANIFEST = (
    Path(__file__).resolve().parents[1]
    / "experiments/host_boundary_v2/rq1_collab_v1/live_readiness_20260907"
    / "implementations/rq1_contextual_attack_pilot_20260910/workflow/run-manifest.json"
)


class V5WorkflowEndToEndTests(unittest.TestCase):
    """One real two-task by two-regime engineering cohort shared by the tests."""

    @classmethod
    def setUpClass(cls):
        cls._temporary = tempfile.TemporaryDirectory(prefix="rq1-v5-workflow-test-")
        cls.addClassCleanup(cls._temporary.cleanup)
        cls.root = Path(cls._temporary.name)
        cls.workflow_root = cls.root / "workflow"
        cls.runs_root = cls.root / "runs"
        cls.budget_path = cls.root / "budget.json"
        workflow.write(cls.budget_path, FIXED_BUDGET)
        prepared = workflow.prepare(
            cls.workflow_root,
            tasks=["workspace:user_task_26", "travel:user_task_2"],
            repeats=1,
            mode="engineering",
            budget_file=cls.budget_path,
            topologies=("H_E",),
            levels=("high",),
            regimes=("honest", "malicious"),
        )
        cls.manifest_path = Path(prepared["manifest"])
        cls.manifest = strict_loads(cls.manifest_path.read_bytes())
        cls.batch_status = workflow.run_offline_batch(
            cls.manifest_path, cls.runs_root, max_cells=4, workers=4
        )
        cls.selection_path = cls.root / "paired-selection.json"
        workflow.write(
            cls.selection_path,
            {
                "schema_version": "rq1-paired-pilot-selection/1",
                "manifest_sha256": cls.manifest["manifest_sha256"],
                "episode_ids": [cell["episode_id"] for cell in cls.manifest["cells"]],
            },
        )
        cls.analysis = paired_pilot.analyze(
            cls.manifest_path, cls.runs_root, cls.selection_path
        )

    def test_fixed_budget_and_two_by_two_matched_matrix(self):
        manifest = workflow.load_manifest(self.manifest_path)
        self.assertEqual(manifest["schema_version"], "rq1-workflow/5")
        self.assertEqual(manifest["protocol_version"], PROTOCOL)
        self.assertEqual(manifest["condition_count"], 4)
        self.assertEqual(manifest["task_count"], 2)
        self.assertEqual(manifest["episode_budget"], FIXED_BUDGET)
        self.assertEqual(manifest["phase_schedule"], PHASE_SCHEDULE)
        self.assertEqual(manifest["phase_schedule_sha256"], PHASE_SCHEDULE_SHA256)
        self.assertEqual(
            manifest["regime_labels"],
            {"honest": "control_no_attack", "malicious": "contextual_attack"},
        )

        by_bundle = {}
        for cell in manifest["cells"]:
            self.assertEqual(cell["budget"], FIXED_BUDGET)
            self.assertEqual(cell["topology"], "H_E")
            self.assertEqual(cell["level"], "high")
            self.assertEqual(cell["repeat"], 0)
            by_bundle.setdefault(cell["bundle_sha256"], {})[cell["regime"]] = cell
        self.assertEqual(len(by_bundle), 2)
        for arms in by_bundle.values():
            self.assertEqual(set(arms), {"honest", "malicious"})
            honest, malicious = arms["honest"], arms["malicious"]
            for field in (
                "protocol_version",
                "topology",
                "level",
                "repeat",
                "models",
                "budget",
                "internal_level",
                "execution_mode",
                "bundle_sha256",
            ):
                self.assertEqual(honest[field], malicious[field], field)

    def test_wrong_budget_is_rejected_before_output_directory_creation(self):
        bad_budget = copy.deepcopy(FIXED_BUDGET)
        bad_budget["external_decisions"] += 1
        bad_budget_path = self.root / "wrong-budget.json"
        workflow.write(bad_budget_path, bad_budget)
        output = self.root / "wrong-budget-workflow"
        with self.assertRaisesRegex(ValueError, "exact_v5_bounded_budget_file_required"):
            workflow.prepare(
                output,
                tasks=["workspace:user_task_26", "travel:user_task_2"],
                repeats=1,
                mode="engineering",
                budget_file=bad_budget_path,
                topologies=("H_E",),
                levels=("high",),
                regimes=("honest", "malicious"),
            )
        self.assertFalse(output.exists())

    def test_rehashed_phase_schedule_hash_and_regime_label_tampering_is_rejected(self):
        mutations = {
            "schedule": lambda value: value["phase_schedule"].__setitem__(
                "external_max_decisions", 4
            ),
            "schedule_hash": lambda value: value.__setitem__(
                "phase_schedule_sha256", "0" * 64
            ),
            "regime_labels": lambda value: value["regime_labels"].__setitem__(
                "malicious", "renamed_attack"
            ),
        }
        for index, (name, mutate) in enumerate(mutations.items()):
            with self.subTest(name=name):
                candidate = copy.deepcopy(self.manifest)
                mutate(candidate)
                unsigned = {
                    key: value
                    for key, value in candidate.items()
                    if key != "manifest_sha256"
                }
                candidate["manifest_sha256"] = digest(unsigned)
                path = self.root / f"tampered-{index}-{name}.json"
                workflow.write(path, candidate)
                with self.assertRaisesRegex(
                    ValueError, "v5_phase_or_regime_binding_mismatch"
                ):
                    workflow.load_manifest(path)

    def test_real_four_cell_engineering_path_is_closed_and_inspectable(self):
        self.assertEqual(self.batch_status["assigned"], 4)
        self.assertEqual(self.batch_status["completed"], 4)
        self.assertEqual(self.batch_status["sealed_incomplete"], 0)
        self.assertEqual(self.batch_status["needs_review"], 0)
        self.assertEqual(self.batch_status["not_run"], 0)
        self.assertEqual(self.batch_status["distinct_public_worlds"], 2)

        for cell in self.manifest["cells"]:
            folder = self.runs_root / cell["episode_id"]
            allocation = strict_loads((folder / "allocation.json").read_bytes())
            report = strict_loads((folder / "report.json").read_bytes())
            status = strict_loads((folder / "status.json").read_bytes())
            self.assertEqual(status["status"], "completed")
            self.assertEqual(status["closure_class"], "host_final")
            self.assertTrue(status["execution_integrity"]["ok"])
            self.assertTrue(status["external_phase_closed"])
            self.assertTrue(status["host_entered"])
            self.assertEqual(report["terminal_reason"], "host_final")
            self.assertEqual(report["closure_class"], "host_final")
            self.assertEqual(report["evaluation_errors"], [])
            self.assertEqual(
                allocation["regime_label"],
                self.manifest["regime_labels"][cell["regime"]],
            )
            self.assertEqual(
                allocation["attack_spec_visible_to"],
                ["E"] if cell["regime"] == "malicious" else [],
            )
            self.assertEqual(
                allocation["phase_schedule_sha256"], PHASE_SCHEDULE_SHA256
            )

    def test_real_paired_analysis_passes_every_bounded_phase_gate(self):
        self.assertEqual(self.analysis["selected_episode_count"], 4)
        self.assertEqual(self.analysis["pair_count"], 2)
        self.assertFalse(self.analysis["inferential_statistics_performed"])
        self.assertTrue(self.analysis["single_repeat_noninferential_warning"])
        self.assertEqual(
            self.analysis["bounded_phase_gate"],
            {
                "all_runs_completed": True,
                "all_evaluations_clean": True,
                "all_execution_seals_verified": True,
                "all_external_phases_closed": True,
                "all_hosts_entered": True,
                "all_hosts_final": True,
                "no_fatal_unknown_closure": True,
                "all_primary_endpoints_known": True,
                "passed": True,
            },
        )

    def _synthetic_episode(self, cfg, expected_world):
        metrics = {
            "task_success": True,
            "native_goal_success": False,
            "unauthorized_effect": paired_pilot.UNKNOWN,
            "behavioral_n": 0,
            **{name: False for name in paired_pilot.ATTACK_METRICS},
        }
        row = {
            "episode_id": cfg["episode_id"],
            "regime": cfg["regime"],
            "regime_label": self.manifest["regime_labels"][cfg["regime"]],
            "artifact_status": "sealed_report_with_unknown_metrics",
            "run_status": "completed",
            "allocation_present": True,
            **metrics,
            "negative_endpoint_observation_complete": True,
            "terminal_reason": "host_final",
            "closure_class": "host_final",
            "external_phase_closed": True,
            "host_entered": True,
            "host_finalization_entered": True,
            "evaluation_clean": True,
            "attack_process_evidence": {
                "matching_event_ids": [], "matching_call_ids": [], "steps": []
            },
            "unknown_metrics": ["unauthorized_effect"],
            "unknown_reasons": ["synthetic_nonprimary_unknown"],
        }
        control = {
            "allocation_present": True,
            "initial_world_id": expected_world,
            "source_version": "agentdojo:test-v5",
            "system_profile": self.manifest["system_spec"]["system_profile"],
            "system_spec_sha256": self.manifest["system_spec_sha256"],
        }
        return row, control

    def test_gate_fails_closed_when_each_required_condition_is_absent(self):
        cases = {
            "all_runs_completed": ("run_status", "needs_review"),
            "all_evaluations_clean": ("evaluation_clean", False),
            "all_execution_seals_verified": ("artifact_status", paired_pilot.UNKNOWN),
            "all_external_phases_closed": ("external_phase_closed", False),
            "all_hosts_entered": ("host_entered", False),
            "all_hosts_final": ("terminal_reason", "host_finalization_exhausted"),
            "no_fatal_unknown_closure": ("closure_class", "fatal_unknown"),
            "all_primary_endpoints_known": ("task_success", paired_pilot.UNKNOWN),
        }
        target_episode = self.manifest["cells"][0]["episode_id"]
        compatibility = {
            "status": "prepared_code_unchanged",
            "mismatched_paths": [],
            "analyzer_path": "paired_pilot.py",
            "analyzer_sha256": "a" * 64,
            "prepared_analyzer_sha256": "a" * 64,
        }
        for gate_name, (field, replacement) in cases.items():
            with self.subTest(gate=gate_name):
                def episode_side_effect(
                    unused_root, unused_manifest, cfg, expected_world,
                    unused_binding, unused_attack_spec,
                ):
                    row, control = self._synthetic_episode(cfg, expected_world)
                    if cfg["episode_id"] == target_episode:
                        row[field] = replacement
                    return row, control

                with patch.object(
                    paired_pilot, "_load_manifest", return_value=copy.deepcopy(self.manifest)
                ), patch.object(
                    paired_pilot, "_analysis_code_compatibility", return_value=compatibility
                ), patch.object(
                    paired_pilot, "_episode", side_effect=episode_side_effect
                ):
                    result = paired_pilot.analyze(
                        self.manifest_path, self.runs_root, self.selection_path
                    )
                self.assertFalse(result["bounded_phase_gate"][gate_name])
                self.assertFalse(result["bounded_phase_gate"]["passed"])
                for other_name, value in result["bounded_phase_gate"].items():
                    if other_name not in {gate_name, "passed"}:
                        self.assertTrue(value, other_name)

    def _copy_runs_and_replace_json(self, name, episode_id, filename, mutate):
        copied = self.root / name
        shutil.copytree(self.runs_root, copied)
        path = copied / episode_id / filename
        payload = strict_loads(path.read_bytes())
        mutate(payload)
        replacement = path.with_name(filename + ".replacement")
        workflow.write(replacement, payload)
        replacement.replace(path)
        return copied

    def test_needs_review_status_fails_all_runs_completed_gate(self):
        cell = self.manifest["cells"][0]
        copied = self._copy_runs_and_replace_json(
            "runs-with-needs-review",
            cell["episode_id"],
            "status.json",
            lambda status: status.__setitem__("status", "needs_review"),
        )
        result = paired_pilot.analyze(
            self.manifest_path, copied, self.selection_path
        )
        self.assertFalse(result["bounded_phase_gate"]["all_runs_completed"])
        self.assertTrue(result["bounded_phase_gate"]["all_evaluations_clean"])
        self.assertFalse(result["bounded_phase_gate"]["passed"])

    def test_nonempty_report_evaluation_errors_fails_clean_evaluation_gate(self):
        cell = self.manifest["cells"][0]
        copied = self._copy_runs_and_replace_json(
            "runs-with-evaluation-error",
            cell["episode_id"],
            "report.json",
            lambda report: report.__setitem__(
                "evaluation_errors", ["forced_test_evaluation_error"]
            ),
        )
        report_path = copied / cell["episode_id"] / "report.json"
        status_path = copied / cell["episode_id"] / "status.json"
        status = strict_loads(status_path.read_bytes())
        status["report_sha256"] = file_hash(report_path)
        replacement = status_path.with_name("status.json.replacement")
        workflow.write(replacement, status)
        replacement.replace(status_path)

        result = paired_pilot.analyze(
            self.manifest_path, copied, self.selection_path
        )
        self.assertTrue(result["bounded_phase_gate"]["all_runs_completed"])
        self.assertFalse(result["bounded_phase_gate"]["all_evaluations_clean"])
        self.assertFalse(result["bounded_phase_gate"]["passed"])

    def test_frozen_v4_manifest_format_remains_loadable_by_v4_validator(self):
        frozen = strict_loads(FROZEN_V4_MANIFEST.read_bytes())
        self.assertEqual(frozen["schema_version"], "rq1-workflow/4")
        self.assertEqual(frozen["protocol_version"], "rq1-three-actor/4")
        # Shared provider/measurement source extensions correctly change the
        # execution fingerprint.  Freezing that one provenance input exercises
        # the original v4 parser/contract without pretending the old cohort is
        # executable under changed code.
        with patch.object(
            v4_workflow, "code_fingerprint", return_value=frozen["code_sha256"]
        ):
            loaded = v4_workflow.load_manifest(FROZEN_V4_MANIFEST)
        self.assertEqual(loaded["manifest_sha256"], frozen["manifest_sha256"])
        self.assertEqual(loaded["schema_version"], "rq1-workflow/4")
        self.assertNotIn("phase_schedule", loaded)
        self.assertNotIn("regime_labels", loaded)
        # v4 deliberately retained the v3-shaped cell contract even though the
        # enclosing workflow/system protocol is v4.
        self.assertTrue(
            all(cell["protocol_version"] == "rq1-three-actor/3" for cell in loaded["cells"])
        )


if __name__ == "__main__":
    unittest.main()
