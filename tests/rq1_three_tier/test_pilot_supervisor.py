import hashlib
import json
from pathlib import Path
import tempfile
import types
import unittest

from tools.supervise_rq1_three_tier_pilot import create, load, supervise


class SupervisorTests(unittest.TestCase):
    def scenario(self, outcomes, *, reject_review=False, preexisting=False):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        base = Path(temp.name)
        (base / "runs").mkdir()
        cells = [{"episode_id": f"cell-{i}"} for i in range(len(outcomes))]
        manifest = {"run_parent": str(base / "runs"), "manifest_sha256": "manifest", "cells": cells}
        create(base / "manifest.json", manifest)
        create(base / "review.json", {"acknowledged_failures": [], "retry_existing_cells": False})
        calls = []

        def plan(manifest_path, review_path):
            review = load(review_path)
            acknowledged = {r["episode_id"] for r in review["acknowledged_failures"]}
            if reject_review and acknowledged:
                raise ValueError("sealed_evidence_rejected")
            pending = []
            for cell in cells:
                folder = base / "runs" / cell["episode_id"]
                if (folder / "summary.json").exists():
                    row = load(folder / "summary.json")
                    if row["status"] != "completed" and cell["episode_id"] not in acknowledged:
                        raise ValueError("missing_failure_review")
                else:
                    pending.append(cell)
            return manifest, pending

        def run_cell(manifest, cell):
            index = int(cell["episode_id"].split("-")[-1])
            outcome = outcomes[index]
            calls.append(cell["episode_id"])
            folder = base / "runs" / cell["episode_id"]
            folder.mkdir()
            failure = ({"kind": "controller_failure", "error_type": "ValueError"}
                       if outcome == "controller" else
                       {"kind": "model_service_error", "http_status": 401 if outcome == "auth" else 408})
            row = {"episode_id": cell["episode_id"], "status": "completed" if outcome == "ok" else "sealed_unknown",
                   "cleanup_confirmed": outcome != "cleanup_failed", "evaluation_errors": [],
                   "G": False if outcome == "ok" else None, "L": 1 if outcome == "ok" else None,
                   "execution_failures": [] if outcome == "ok" else [failure], "execution_seal_sha256": "seal"}
            create(folder / "summary.json", row)
            return row

        controller = types.SimpleNamespace(plan=plan, diagnostic=types.SimpleNamespace(run_cell=run_cell),
            __file__=__file__, digest=lambda x: hashlib.sha256(json.dumps(x, sort_keys=True).encode()).hexdigest())
        if preexisting:
            (base / "runs" / "cell-0").mkdir()
        return base, controller, calls

    def run_scenario(self, base, controller):
        return supervise(controller, base / "manifest.json", base / "review.json", base / "audit")

    def test_timeout_and_controller_failure_skip_without_replay(self):
        base, ctl, calls = self.scenario(["ok", "timeout", "ok", "controller", "ok"])
        self.assertEqual(self.run_scenario(base, ctl), 0)
        self.assertEqual(calls, [f"cell-{i}" for i in range(5)])
        self.assertEqual(len(list((base / "audit").glob("accepted-*.json"))), 2)
        self.assertTrue(load(base / "audit/closed.json")["all_execution_closures_verified"])
        self.assertFalse((base / ".run.lock").exists())

    def test_evidence_rejection_stops_before_next_cell(self):
        base, ctl, calls = self.scenario(["timeout", "ok"], reject_review=True)
        with self.assertRaisesRegex(ValueError, "sealed_evidence_rejected"):
            self.run_scenario(base, ctl)
        self.assertEqual(calls, ["cell-0"])
        self.assertTrue((base / "audit/attention.json").exists())

    def test_auth_and_cleanup_failure_never_skip(self):
        for failure in ("auth", "cleanup_failed"):
            with self.subTest(failure=failure):
                base, ctl, calls = self.scenario([failure, "ok"])
                with self.assertRaises(ValueError):
                    self.run_scenario(base, ctl)
                self.assertEqual(calls, ["cell-0"])

    def test_three_consecutive_failures_stop(self):
        base, ctl, calls = self.scenario(["timeout"] * 4)
        with self.assertRaisesRegex(ValueError, "consecutive_failed_cells_stop"):
            self.run_scenario(base, ctl)
        self.assertEqual(calls, ["cell-0", "cell-1", "cell-2"])

    def test_preexisting_cell_is_not_overwritten(self):
        base, ctl, calls = self.scenario(["ok"], preexisting=True)
        with self.assertRaisesRegex(ValueError, "already_exists_no_replay"):
            self.run_scenario(base, ctl)
        self.assertEqual(calls, [])

    def test_existing_run_lock_is_not_removed(self):
        base, ctl, calls = self.scenario(["ok"])
        (base / ".run.lock").write_text("other-runner")
        with self.assertRaises(FileExistsError):
            self.run_scenario(base, ctl)
        self.assertEqual((base / ".run.lock").read_text(), "other-runner")
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
