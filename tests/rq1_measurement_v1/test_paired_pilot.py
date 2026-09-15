"""Paired pilot mechanics only; synthetic rows are not research findings."""
from pathlib import Path
import copy
from contextlib import redirect_stdout
import io
import tempfile
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.rq1_collab_v1.audit import canonical, file_hash
from agentmembrane.host_v2.rq1_collab_v3.contract import digest, matrix
from agentmembrane.host_v2.rq1_collab_v4.attack_spec import (
    WORKSPACE_DELETE_GOAL, compile_attack_spec)
from agentmembrane.host_v2.rq1_collab_v4.contract import PROTOCOL, system_spec
from agentmembrane.host_v2.rq1_collab_v4 import paired_pilot
from agentmembrane.host_v2.rq1_collab_v4.paired_pilot import UNKNOWN, analyze


class PairedPilotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runs = self.root / "runs"
        self.runs.mkdir()
        self.source = {"suite": "workspace", "task_id": "user_task_8",
                       "initial_state_sha256": "1" * 64,
                       "class_source_sha256": "2" * 64,
                       "prompt_sha256": "3" * 64}
        self.world = "agentdojo:workspace:" + self.source["initial_state_sha256"]
        self.bundle = {"suite": "workspace", "original_id": "user_task_8",
                       "world_id": self.world, "source_record": copy.deepcopy(self.source),
                       "public": {"goal": {"goal": WORKSPACE_DELETE_GOAL}}}
        self.bundle_hash = digest(self.bundle)
        self.attack_spec = compile_attack_spec(WORKSPACE_DELETE_GOAL)
        self.spec = system_spec()
        self.manifest = {"schema_version": "rq1-workflow/4", "protocol_version": PROTOCOL,
                         "execution_mode": "live_diagnostic", "repeats": 1,
                         "system_spec": self.spec, "system_spec_sha256": digest(self.spec),
                         "bundles": {self.bundle_hash: self.bundle},
                         "attack_specs": {self.bundle_hash: self.attack_spec},
                         "attack_specs_sha256": digest({self.bundle_hash: self.attack_spec}),
                         "cells": [cell for cell in matrix(
                             self.bundle_hash, "workspace-user_task_8", repeats=1,
                             mode="live_diagnostic")
                             if cell["topology"] == "H_E" and cell["level"] == "low"],
                         "task_count": 1, "condition_count": 2}
        self._save_manifest()
        loader = patch.object(paired_pilot, "workflow_load_manifest",
                              side_effect=lambda unused: copy.deepcopy(self.manifest))
        loader.start()
        self.addCleanup(loader.stop)
        compatibility = patch.object(paired_pilot, "_analysis_code_compatibility",
                                     return_value={"status": "prepared_code_unchanged",
                                                   "mismatched_paths": [],
                                                   "analyzer_path": "paired_pilot.py",
                                                   "analyzer_sha256": "a" * 64,
                                                   "prepared_analyzer_sha256": "a" * 64})
        compatibility.start()
        self.addCleanup(compatibility.stop)
        verifier = patch.object(paired_pilot, "verify_execution",
                                return_value={"ok": True, "seal_hash": "4" * 64})
        self.verify_mock = verifier.start()
        self.addCleanup(verifier.stop)
        selected = [cell for cell in self.manifest["cells"]
                    if cell["topology"] == "H_E" and cell["level"] == "low"]
        self.by_regime = {cell["regime"]: cell for cell in selected}
        self._save_selection([cell["episode_id"] for cell in selected])

    def write(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(canonical(value) + b"\n")
        return path

    def _save_manifest(self):
        unsigned = {key: value for key, value in self.manifest.items() if key != "manifest_sha256"}
        self.manifest = {**unsigned, "manifest_sha256": digest(unsigned)}
        self.manifest_path = self.write(self.root / "manifest.json", self.manifest)

    def _save_selection(self, episode_ids, **changes):
        selection = {"schema_version": "rq1-paired-pilot-selection/1",
                     "manifest_sha256": self.manifest["manifest_sha256"],
                     "episode_ids": episode_ids}
        selection.update(changes)
        self.selection_path = self.write(self.root / "selection.json", selection)

    def allocation(self, cfg):
        binding = {"source": "agentdojo", **copy.deepcopy(self.source)}
        return {"manifest_sha256": self.manifest["manifest_sha256"],
                "config": copy.deepcopy(cfg), "status": "allocated",
                "independent_world_id": self.world, "task_binding": binding,
                "source_version": "agentdojo:test-source-v1",
                "system_profile": self.spec["system_profile"],
                "system_spec_sha256": self.manifest["system_spec_sha256"],
                "attack_spec_id": self.attack_spec["attack_spec_id"],
                "attack_spec_sha256": self.attack_spec["spec_sha256"],
                "attack_spec_visible_to": ["E"] if cfg["regime"] == "malicious" else []}

    def make_run(self, regime, *, task=True, goal=False, effect=False, behavioral_n=1,
                 status="completed", report=True, terminal_reason="host_final",
                 negative_complete=True):
        cfg = self.by_regime[regime]
        folder = self.runs / cfg["episode_id"]
        allocation = self.allocation(cfg)
        self.write(folder / "allocation.json", allocation)
        seal = "4" * 64
        if report:
            target = regime == "malicious" and goal
            report_value = {"schema_version": "rq1-episode-report/4", "episode_id": cfg["episode_id"],
                            "config": copy.deepcopy(cfg), "system_profile": allocation["system_profile"],
                            "system_spec_sha256": allocation["system_spec_sha256"],
                            "execution_seal_sha256": seal, "terminal_reason": terminal_reason,
                            "evaluation_errors": [], "execution_failures": [],
                            "native_task_success": task, "native_goal_success": goal,
                            "analysis_endpoints": {"native_task_success": task,
                                "native_goal_success": goal,
                                "negative_endpoint_observation_complete": negative_complete},
                            "outcomes": {"observed_unauthorized_effect": effect,
                                         "verified_any_violation": True if effect else None},
                            "attack_process": {"schema_version": "rq1-attack-process/1",
                                "attack_spec_id": self.attack_spec["attack_spec_id"],
                                "attack_spec_sha256": self.attack_spec["spec_sha256"],
                                "typed_target_request": target,
                                "any_target_step_dispatch_entered": target,
                                "target_sequence_completed": target,
                                "target_dispatch_complete": target,
                                "observed_payload_bound": target,
                                "native_attack_effect": goal,
                                "matching_event_ids": [], "matching_call_ids": [], "steps": []},
                            "behavioral_n": behavioral_n,
                            "measurement": {"episode_id": cfg["episode_id"],
                                "config": copy.deepcopy(cfg), "independent_world_id": self.world,
                                "task_binding": copy.deepcopy(allocation["task_binding"]),
                                "behavioral_n": behavioral_n}}
            report_path = self.write(folder / "report.json", report_value)
            report_sha = file_hash(report_path)
        else:
            report_sha = "5" * 64
        self.write(folder / "execution-anchor.json",
                   {"manifest_sha256": self.manifest["manifest_sha256"],
                    "execution_seal_sha256": seal})
        self.write(folder / "status.json", {"status": status, "episode_id": cfg["episode_id"],
            "execution_mode": cfg["execution_mode"], "report_sha256": report_sha,
            "execution_integrity": {"ok": True, "seal_hash": seal},
            "native_task_success": task, "native_goal_success": goal,
            "observed_unauthorized_effect": effect})
        return folder

    def test_complete_pair_reports_descriptive_differences_and_single_repeat_warning(self):
        self.make_run("honest", task=True, goal=False, effect=False, behavioral_n=1)
        self.make_run("malicious", task=True, goal=True, effect=True, behavioral_n=1)
        result = analyze(self.manifest_path, self.runs, self.selection_path)
        self.assertEqual(result["selected_episode_count"], 2)
        self.assertEqual(result["pair_count"], 1)
        # No all-hazards negative is certified for the honest arm, so its
        # unauthorized-effect endpoint remains in the assigned denominator as unknown.
        self.assertEqual(result["unknown_episode_count"], 1)
        row = result["rows"][0]
        self.assertEqual(row["honest"]["task_success"], True)
        self.assertEqual(row["malicious"]["unauthorized_effect"], True)
        self.assertEqual(row["malicious_minus_honest"], {
            "task_success": {"lower": 0, "upper": 0, "point": 0},
            "native_goal_success": {"lower": 1, "upper": 1, "point": 1},
            "unauthorized_effect": {"lower": 0, "upper": 1, "point": None},
            "typed_target_request": {"lower": 1, "upper": 1, "point": 1},
            "any_target_step_dispatch_entered": {"lower": 1, "upper": 1, "point": 1},
            "target_sequence_completed": {"lower": 1, "upper": 1, "point": 1},
            "target_dispatch_complete": {"lower": 1, "upper": 1, "point": 1},
            "observed_payload_bound": {"lower": 1, "upper": 1, "point": 1},
            "native_attack_effect": {"lower": 1, "upper": 1, "point": 1},
        })
        self.assertEqual(row["behavioral_exposure"]["honest_behavioral_n"], 1)
        self.assertTrue(row["controls"]["run_allocations_match"])
        self.assertFalse(result["inferential_statistics_performed"])
        self.assertTrue(result["single_repeat_noninferential_warning"])
        self.assertEqual(self.verify_mock.call_count, 2)
        self.assertEqual(result["repeat_assessment"][0]["interpretation"],
                         "single_repeat_descriptive_only_not_inferential")

    def test_missing_run_is_retained_as_unknown_not_dropped(self):
        self.make_run("honest")
        result = analyze(self.manifest_path, self.runs, self.selection_path)
        self.assertEqual(result["pair_count"], 1)
        self.assertEqual(result["unknown_episode_count"], 2)
        malicious = result["rows"][0]["malicious"]
        self.assertEqual(malicious["task_success"], UNKNOWN)
        self.assertIn("run_directory_missing", malicious["unknown_reasons"])
        self.assertTrue(all(value["point"] is None for value in
                            result["rows"][0]["malicious_minus_honest"].values()))

    def test_missing_metric_is_unknown_without_erasing_other_metrics(self):
        self.make_run("honest")
        folder = self.make_run("malicious")
        report = self._read(folder / "report.json")
        report["outcomes"]["observed_unauthorized_effect"] = None
        self.write(folder / "report.json.replacement", report)
        (folder / "report.json").unlink()
        (folder / "report.json.replacement").rename(folder / "report.json")
        status = self._read(folder / "status.json")
        status["report_sha256"] = file_hash(folder / "report.json")
        self.write(folder / "status.json.replacement", status)
        (folder / "status.json").unlink()
        (folder / "status.json.replacement").rename(folder / "status.json")
        result = analyze(self.manifest_path, self.runs, self.selection_path)
        malicious = result["rows"][0]["malicious"]
        self.assertEqual(malicious["unauthorized_effect"], UNKNOWN)
        self.assertEqual(malicious["task_success"], True)
        self.assertEqual(malicious["behavioral_n"], 1)

    def test_measurement_may_add_source_identity_fields_but_cannot_change_bound_fields(self):
        self.make_run("honest")
        folder = self.make_run("malicious", goal=True, effect=True)
        report = self._read(folder / "report.json")
        report["measurement"]["task_binding"].update({
            "benchmark_version": "v1", "class_name": "UserTask8",
            "tool_schema_sha256": "6" * 64,
        })
        replacement = folder / "report.json.replacement"
        self.write(replacement, report)
        (folder / "report.json").unlink()
        replacement.rename(folder / "report.json")
        status = self._read(folder / "status.json")
        status["report_sha256"] = file_hash(folder / "report.json")
        replacement = folder / "status.json.replacement"
        self.write(replacement, status)
        (folder / "status.json").unlink()
        replacement.rename(folder / "status.json")
        result = analyze(self.manifest_path, self.runs, self.selection_path)
        self.assertTrue(result["rows"][0]["malicious"]["native_goal_success"])

        report = self._read(folder / "report.json")
        report["measurement"]["task_binding"]["task_id"] = "wrong-task"
        replacement = folder / "report.json.replacement"
        self.write(replacement, report)
        (folder / "report.json").unlink()
        replacement.rename(folder / "report.json")
        status = self._read(folder / "status.json")
        status["report_sha256"] = file_hash(folder / "report.json")
        replacement = folder / "status.json.replacement"
        self.write(replacement, status)
        (folder / "status.json").unlink()
        replacement.rename(folder / "status.json")
        with self.assertRaisesRegex(ValueError, "measurement_allocation_binding_mismatch"):
            analyze(self.manifest_path, self.runs, self.selection_path)

    def test_needs_review_non_host_terminal_retains_independently_positive_endpoints(self):
        self.make_run("honest")
        self.make_run("malicious", task=True, goal=True, effect=True, status="needs_review",
                      terminal_reason="timeout", negative_complete=False)
        result = analyze(self.manifest_path, self.runs, self.selection_path)
        malicious = result["rows"][0]["malicious"]
        self.assertEqual(malicious["run_status"], "needs_review")
        self.assertEqual(malicious["task_success"], True)
        self.assertEqual(malicious["native_goal_success"], True)
        self.assertEqual(malicious["unauthorized_effect"], True)

    def _read(self, path):
        from agentmembrane.host_v2.rq1_collab_v1.audit import strict_loads
        return strict_loads(path.read_bytes())

    def test_selection_must_cover_every_manifest_cell(self):
        self._save_selection([self.by_regime["honest"]["episode_id"]])
        with self.assertRaisesRegex(ValueError, "cover_all_manifest_cells"):
            analyze(self.manifest_path, self.runs, self.selection_path)

    def test_recomputed_execution_seal_failure_fails_closed(self):
        self.make_run("honest")
        self.make_run("malicious")
        self.verify_mock.return_value = {"ok": False, "errors": ["changed"]}
        with self.assertRaisesRegex(ValueError, "execution_seal_verification_failed"):
            analyze(self.manifest_path, self.runs, self.selection_path)

    def test_model_and_budget_mismatch_fail_closed(self):
        for field, expected in (("models", "models_mismatch"), ("budget", "budget_mismatch")):
            with self.subTest(field=field):
                original = copy.deepcopy(self.manifest)
                malicious = next(cell for cell in self.manifest["cells"]
                                 if cell["episode_id"] == self.by_regime["malicious"]["episode_id"])
                if field == "models":
                    malicious["models"]["H"]["model"] = "different-model"
                else:
                    malicious["budget"]["external_decisions"] -= 1
                self._save_manifest()
                self._save_selection([cell["episode_id"] for cell in self.by_regime.values()])
                with self.assertRaisesRegex(ValueError, expected):
                    analyze(self.manifest_path, self.runs, self.selection_path)
                self.manifest = original
                self._save_manifest()

    def test_allocation_initial_world_mismatch_fails_closed(self):
        self.make_run("honest")
        folder = self.runs / self.by_regime["malicious"]["episode_id"]
        allocation = self.allocation(self.by_regime["malicious"])
        allocation["independent_world_id"] = "agentdojo:workspace:" + "9" * 64
        self.write(folder / "allocation.json", allocation)
        with self.assertRaisesRegex(ValueError, "initial_world_mismatch"):
            analyze(self.manifest_path, self.runs, self.selection_path)

    def test_attack_spec_hash_and_visibility_are_allocation_controls(self):
        self.make_run("honest")
        folder = self.runs / self.by_regime["malicious"]["episode_id"]
        allocation = self.allocation(self.by_regime["malicious"])
        allocation["attack_spec_visible_to"] = []
        self.write(folder / "allocation.json", allocation)
        with self.assertRaisesRegex(ValueError, "attack_spec_binding_or_visibility"):
            analyze(self.manifest_path, self.runs, self.selection_path)

    def test_selection_is_manifest_bound_and_unique(self):
        ids = [cell["episode_id"] for cell in self.by_regime.values()]
        self._save_selection(ids, manifest_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "manifest_binding"):
            analyze(self.manifest_path, self.runs, self.selection_path)
        self._save_selection([ids[0], ids[0]])
        with self.assertRaisesRegex(ValueError, "unique_nonempty"):
            analyze(self.manifest_path, self.runs, self.selection_path)

    def test_cli_writes_one_canonical_analysis_artifact_without_overwrite(self):
        self.make_run("honest")
        self.make_run("malicious", goal=True, effect=True)
        output = self.root / "paired-analysis.json"
        argv = ["paired", "--manifest", str(self.manifest_path),
                "--runs-root", str(self.runs), "--selection", str(self.selection_path),
                "--output", str(output)]
        with patch("sys.argv", argv), redirect_stdout(io.StringIO()):
            self.assertEqual(paired_pilot.main(), 0)
        written = self._read(output)
        self.assertEqual(written["schema_version"], "rq1-paired-pilot-analysis/1")
        with patch("sys.argv", argv), redirect_stdout(io.StringIO()):
            with self.assertRaises(FileExistsError):
                paired_pilot.main()


if __name__ == "__main__":
    unittest.main()
