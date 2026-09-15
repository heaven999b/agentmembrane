"""Failure-injection fixtures, not benchmark samples or model outcomes."""
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.rq1_collab_v1 import six_sample
from agentmembrane.host_v2.rq1_collab_v1.audit import file_hash, verify
from agentmembrane.host_v2.rq1_collab_v1.integration import persist_runtime_capture


class CaptureFaultTests(unittest.TestCase):
    def test_private_capture_is_exclusive_and_keeps_partial_close_unknown(self):
        evidence = {"initial_snapshot": {"counter": 0}, "status": "failed_to_seal"}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            persist_runtime_capture(root, evidence)
            capture = root / "private_evaluation/runtime_capture.json"
            self.assertEqual(json.loads(capture.read_text()), evidence)
            self.assertFalse((root / "snapshots/terminal_snapshot.json").exists())
            original = capture.read_bytes()
            with self.assertRaises(FileExistsError):
                persist_runtime_capture(root, {"initial_snapshot": {"counter": 99}})
            self.assertEqual(capture.read_bytes(), original)

    def test_scorer_failure_preserves_terminal_and_cleanup_failure_does_not_hide_it(self):
        case = self
        class Adapter:
            prompt = "explicit unit fixture"
            record = {"fixture": True}
            def native_score(self, *args):
                cell = root / "workspace-user_task_8-H_ONLY-A4"
                events = [json.loads(line) for line in (cell / "events.jsonl").read_text().splitlines()]
                case.assertEqual([event["kind"] for event in events[-2:]],
                                 ["runtime_capture_persisted", "private_scoring_started"])
                saved = events[-2]["data"]["files"]
                case.assertEqual(len(saved), 4)
                for relative, expected_hash in saved.items():
                    case.assertEqual(file_hash(cell / relative), expected_hash)
                raise RuntimeError("injected_checker_failure")
            def shutdown(self):
                raise OSError("injected_shutdown_failure")

        captured = {"initial_snapshot": {"counter": 0}, "stop_snapshot": {"counter": 1},
                    "terminal_snapshot": {"counter": 1}, "final_text": "done",
                    "fixture_only": True}
        contract = {"code_hashes": {}, "source_root": "/fixture-not-executed",
                    "qualified_upstream_hashes": {}, "native_python": sys.executable,
                    "seed": 0, "budget": {"host_decisions": 1, "external_decisions": 1,
                                         "max_delegations": 0}}
        with tempfile.TemporaryDirectory() as temporary, contextlib.ExitStack() as stack:
            for name, value in (("source_lock", {}), ("verify_upstream", {}),
                                ("ProcessNativeTask", Adapter()), ("identity_matches", True),
                                ("compile_task_policy", {}), ("run_episode", copy.deepcopy(captured))):
                stack.enter_context(patch.object(six_sample, name, return_value=value))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            root = Path(temporary)
            row = six_sample._condition(root, "workspace", "user_task_8", "H_ONLY", "A4", contract, {})
            cell = root / row["episode_id"]
            self.assertEqual(row["status"], "failed")
            self.assertEqual(row["error"], "injected_checker_failure")
            self.assertIn({"stage": "native_shutdown", "error_class": "OSError"}, row["cleanup_errors"])
            self.assertFalse(row["engineering_pass"])
            self.assertEqual(json.loads((cell / "private_evaluation/runtime_capture.json").read_text()), captured)
            for name in ("initial_snapshot", "stop_snapshot", "terminal_snapshot"):
                self.assertEqual(json.loads((cell / "snapshots" / (name + ".json")).read_text()), captured[name])
            self.assertEqual(json.loads((root / "condition_results" / (row["episode_id"] + ".json")).read_text()), row)
            self.assertTrue((root / "failures" / (row["episode_id"] + ".json")).exists())
            self.assertFalse(verify(cell)["ok"])


if __name__ == "__main__":
    unittest.main()
