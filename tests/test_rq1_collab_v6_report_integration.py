"""Fast end-to-end report artifact checks at the workflow/analysis read boundaries."""
from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.rq1_collab_v1.audit import canonical
from agentmembrane.host_v2.rq1_collab_v6 import paired_pilot, paired_v2, workflow
from agentmembrane.host_v2.rq1_collab_v6.report_codec import read_report, write_report


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical(value) + b"\n")


class ReportIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="rq1-v6-report-integration-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.episode_id = "workspace-user_task_35-H_E-medium-honest-r0"
        self.cfg = {"episode_id": self.episode_id, "topology": "H_E",
                    "level": "medium", "regime": "honest", "execution_mode": "engineering"}
        self.manifest = {"manifest_sha256": "m" * 64, "cells": [self.cfg],
                         "task_count": 1, "bundles": {"bundle": {"world_id": "world"}}}
        self.folder = self.root / self.episode_id
        self.folder.mkdir()
        self.seal = "s" * 64
        self.report = {"schema_version": "rq1-episode-report/6",
                       "episode_id": self.episode_id, "config": self.cfg,
                       "execution_seal_sha256": self.seal,
                       "system_profile": "profile", "system_spec_sha256": "p" * 64,
                       "phase_schedule_sha256": "q" * 64,
                       "regime_label": "control_no_attack",
                       "evaluation_errors": [], "measurement": None,
                       "analysis_endpoints": {"native_task_success": True,
                                              "native_goal_success": False,
                                              "negative_endpoint_observation_complete": True},
                       "outcomes": {"verified_any_violation": None},
                       "behavioral_n": 0}
        self.allocation = {"config": self.cfg, "system_profile": "profile",
                           "system_spec_sha256": "p" * 64,
                           "phase_schedule_sha256": "q" * 64,
                           "regime_label": "control_no_attack"}
        _write_json(self.folder / "allocation.json", {
            **self.allocation, "manifest_sha256": self.manifest["manifest_sha256"]})
        _write_json(self.folder / "execution-anchor.json", {
            "manifest_sha256": self.manifest["manifest_sha256"],
            "execution_seal_sha256": self.seal})

    def _status(self, *, legacy=False):
        if legacy:
            raw = canonical(self.report) + b"\n"
            (self.folder / "report.json").write_bytes(raw)
            metadata = {"report_sha256": hashlib.sha256(raw).hexdigest()}
        else:
            metadata = write_report(self.folder, self.report)
        status = {"status": "completed", "episode_id": self.episode_id,
                  "execution_mode": "engineering", **metadata}
        _write_json(self.folder / "status.json", status)
        return status

    def _inspect(self):
        with (patch.object(workflow, "load_manifest", return_value=self.manifest),
              patch.object(workflow, "verify", return_value={"ok": True})):
            return workflow.inspect_workflow(self.root / "manifest.json", self.root)

    def test_workflow_inspects_compressed_and_legacy_reports(self):
        for legacy in (False, True):
            with self.subTest(legacy=legacy):
                if legacy:
                    (self.folder / "report.json.gz").unlink(missing_ok=True)
                status = self._status(legacy=legacy)
                self.assertEqual(read_report(self.folder, status), self.report)
                self.assertEqual(self._inspect()["completed"], 1)

    def test_workflow_marks_corrupt_or_ambiguous_report_for_review(self):
        status = self._status()
        path = self.folder / "report.json.gz"
        raw = path.read_bytes()
        path.write_bytes(raw[:-1])
        self.assertEqual(self._inspect()["rows"][0]["status"], "needs_review")
        path.write_bytes(raw)
        (self.folder / "report.json").write_bytes(b"{}\n")
        self.assertEqual(self._inspect()["rows"][0]["status"], "needs_review")
        self.assertEqual(status["report_encoding"], "gzip")

    def test_paired_pilot_reads_both_encodings_and_rejects_damage(self):
        for legacy in (False, True):
            with self.subTest(legacy=legacy):
                if legacy:
                    (self.folder / "report.json.gz").unlink(missing_ok=True)
                status = self._status(legacy=legacy)
                control = {"initial_world_id": "world"}
                with patch.object(paired_pilot, "verify_execution", return_value={"ok": True}):
                    row, _ = paired_pilot._reported_episode(
                        self.folder, self.manifest, self.cfg, self.allocation,
                        control, status, {"attack_spec_id": "a", "spec_sha256": "b"})
                self.assertIn(row["artifact_status"],
                              {"sealed_report", "sealed_report_with_unknown_metrics"})
                report_path = self.folder / ("report.json" if legacy else "report.json.gz")
                report_path.write_bytes(report_path.read_bytes()[:-1])
                with (patch.object(paired_pilot, "verify_execution", return_value={"ok": True}),
                      self.assertRaises(ValueError)):
                    paired_pilot._reported_episode(
                        self.folder, self.manifest, self.cfg, self.allocation,
                        control, status, {"attack_spec_id": "a", "spec_sha256": "b"})
                report_path.unlink()

    def test_paired_v2_enrichment_reads_both_encodings(self):
        status = self._status()
        self.report["strict_task_result"] = {
            "checker": "strict_profile_v2:workspace/user_task_35",
            "source_lock": "c" * 64,
            "answer_protocol": "source_fact_semantics_v2",
            "unrelated_harms_scored_separately": True, "value": 1}
        # Replace the test's one report with a new sealed artifact, matching
        # the same append-only writer contract used by workflow.run_cell.
        (self.folder / "report.json.gz").unlink()
        status.update(write_report(self.folder, self.report))
        _write_json(self.folder / "status.json", status)
        _write_json(self.folder / "execution" / "artifacts" / "evidence-v1.json",
                    {"episode_id": self.episode_id})
        arm = {"artifact_status": "sealed_report", "episode_id": self.episode_id,
               "task_success": True, "native_goal_success": False}
        source = {"suite": "workspace", "task_id": "user_task_35",
                  "class_source_sha256": "c" * 64}
        result = paired_v2._enrich(arm, self.folder, source)
        self.assertIs(result["L"], True)
        self.assertIs(result["J"], False)
        (self.folder / "report.json.gz").unlink()
        raw = canonical(self.report) + b"\n"
        (self.folder / "report.json").write_bytes(raw)
        status = {"status": "completed", "episode_id": self.episode_id,
                  "report_sha256": hashlib.sha256(raw).hexdigest()}
        _write_json(self.folder / "status.json", status)
        legacy_result = paired_v2._enrich(arm, self.folder, source)
        self.assertEqual(legacy_result, result)


if __name__ == "__main__":
    unittest.main()
