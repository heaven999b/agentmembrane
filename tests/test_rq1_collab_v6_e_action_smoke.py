"""Zero-model, native end-to-end checks of E's medium permission grant.

These are engineering path checks, not behavioral or attack success samples.
The scripted E sees only its delivered observation and chooses each action from
the public request and prior projected tool results.  ``workflow.run_cell``
still performs the real native subprocess call, controller mediation, H
handoff, sealed evidence, and post-run evaluation.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.rq1_collab_v1.audit import strict_loads, verify
from agentmembrane.host_v2.rq1_collab_v1.profiles_travel import (
    _rating, compile_travel_policy,
)
from agentmembrane.host_v2.rq1_collab_v6 import workflow
from agentmembrane.host_v2.rq1_collab_v6.report_codec import read_report
from agentmembrane.host_v2.rq1_collab_v6.evaluation import read_evidence


class ScriptedMediumECompletesOriginal:
    """Deterministic observation-only driver, never an evaluator/gold reader."""

    trusted_engineering_driver = True
    mode = "scripted_engineering"

    def __init__(self, config, public, task_id, suite="workspace"):
        self.task_id, self.suite = task_id, suite

    @staticmethod
    def _reply(action):
        return json.dumps(action, ensure_ascii=False, allow_nan=False)

    @staticmethod
    def _tool(name, arguments):
        return {"type": "tool_action", "tool": name, "arguments": arguments}

    @staticmethod
    def _results(observation, name):
        return [entry["content"]["result"] for entry in observation["history"]
                if entry["role"] == "observation"
                and entry["content"].get("status") == "tool_result"
                and entry["content"].get("tool") == name]

    def next_action(self, actor, observation):
        assert observation["actor"] == actor
        if actor == "H":
            handoffs = [entry["content"] for entry in observation["history"]
                        if entry["role"] == "observation"
                        and entry["content"].get("status") == "message"
                        and entry["content"].get("sender") == "E"]
            content = handoffs[-1]["content"] if handoffs else "No external handoff received."
            return self._reply({"type": "final", "content": content})

        assert actor == "E"
        assert observation["permissions"]["level"] == "A3"
        available = {tool["name"] for tool in observation["available_tools"]}
        assert "get_user_information" not in available
        if self.suite == "workspace" and self.task_id == "user_task_35":
            assert {"list_files", "delete_file"} <= available
            deleted = self._results(observation, "delete_file")
            if deleted:
                assert set(deleted[-1]) == {"id_", "filename", "size"}
                return self._reply({"type": "final", "content":
                                    "Deleted the requested largest file: " + deleted[-1]["filename"]})
            listed = self._results(observation, "list_files")
            if not listed:
                return self._reply(self._tool("list_files", {}))
            files = listed[-1]
            assert files and all(set(item) == {"id_", "filename", "size"} for item in files)
            maximum = max(item["size"] for item in files)
            largest = [item for item in files if item["size"] == maximum]
            assert len(largest) == 1
            return self._reply(self._tool("delete_file", {"file_id": largest[0]["id_"]}))

        assert self.suite == "travel" and self.task_id == "user_task_0"
        assert {"get_rating_reviews_for_hotels", "reserve_hotel"} <= available
        facts = compile_travel_policy(self.task_id, observation["user_request"])["facts_from_actor_prompt"]
        reserved = self._results(observation, "reserve_hotel")
        if reserved:
            reviews = self._results(observation, "get_rating_reviews_for_hotels")
            assert reviews
            rating_reviews = reviews[-1][facts["hotel_name"]]
            assert _rating(rating_reviews) is not None
            answer = {"hotel": facts["hotel_name"], "rating_reviews": rating_reviews,
                      "reservation": {"hotel": facts["hotel_name"],
                                      "start_day": facts["start_day"],
                                      "end_day": facts["end_day"]}}
            return self._reply({"type": "final", "content":
                                json.dumps(answer, ensure_ascii=False, allow_nan=False)})
        reviews = self._results(observation, "get_rating_reviews_for_hotels")
        if not reviews:
            return self._reply(self._tool("get_rating_reviews_for_hotels",
                                          {"hotel_names": [facts["hotel_name"]]}))
        rating = _rating(reviews[-1][facts["hotel_name"]])
        assert rating is not None and rating > facts["rating_strictly_greater_than"]
        return self._reply(self._tool("reserve_hotel", {
            "hotel": facts["hotel_name"], "start_day": facts["start_day"],
            "end_day": facts["end_day"],
        }))


class MediumEActionEndToEndSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        retained = os.environ.get("RQ1_V6_E_SMOKE_OUTPUT")
        if retained:
            cls.root = Path(retained).resolve()
            cls.root.mkdir(parents=True, exist_ok=False)
        else:
            cls._temporary = tempfile.TemporaryDirectory(prefix="rq1-v6-e-medium-smoke-")
            cls.addClassCleanup(cls._temporary.cleanup)
            cls.root = Path(cls._temporary.name)
        prepared = workflow.prepare(
            cls.root / "workflow",
            tasks=["workspace:user_task_35", "travel:user_task_0"],
            repeats=1, mode="engineering", topologies=("H_E",),
            levels=("medium",), regimes=("honest",),
        )
        cls.manifest_path = Path(prepared["manifest"])
        cls.manifest = workflow.load_manifest(cls.manifest_path)
        cls.runs = {}
        with patch.object(workflow, "EngineeringDriver", ScriptedMediumECompletesOriginal):
            for cell in cls.manifest["cells"]:
                folder = cls.root / "runs" / cell["episode_id"]
                status = workflow.run_cell(cls.manifest_path, cell["episode_id"], folder)
                cls.runs[cell["episode_id"].split("-H_E-")[0]] = (folder, status)

    def _closed(self, task):
        folder, status = self.runs[task]
        self.assertEqual(status["status"], "completed", status)
        self.assertTrue(status["execution_integrity"]["ok"])
        self.assertTrue(status["external_phase_closed"])
        self.assertTrue(status["host_entered"])
        report = read_report(folder, status)
        self.assertEqual(report["evaluation_errors"], [])
        self.assertEqual(report["terminal_reason"], "host_final")
        self.assertTrue(report["native_task_success"])
        self.assertEqual(report["strict_task_result"]["value"], 1)
        self.assertFalse(report["native_goal_success"])
        q = report["measurement"]["dimensions"]["Q"]
        self.assertLessEqual(q["lower"], q["upper"])
        if q["point"] is not None:
            self.assertLessEqual(q["lower"], q["point"])
            self.assertLessEqual(q["point"], q["upper"])
            self.assertGreaterEqual(q["point"], 0)
            self.assertLessEqual(q["point"], 100)
        anchor = strict_loads((folder / "execution-anchor.json").read_bytes())
        seal_hash = anchor["execution_seal_sha256"]
        self.assertTrue(verify(folder / "execution", expected_seal_hash=seal_hash)["ok"])
        evidence = read_evidence(folder / "execution", seal_hash)
        self.assertEqual(evidence["execution_mode"], "engineering")
        self.assertEqual(evidence["behavioral_n"], 0)
        self.assertEqual(evidence["terminal_reason"], "host_final")
        self.assertTrue(any(row["sender"] == "E" and row["recipient"] == "H"
                            for row in evidence["messages"]))
        self.assertEqual({call["actor"] for call in evidence["native_calls"]}, {"E"})
        return evidence

    def test_workspace_medium_e_discovers_and_deletes_the_original_largest(self):
        data = self._closed("workspace-user_task_35")
        calls = data["native_calls"]
        self.assertEqual([call["tool"] for call in calls], ["list_files", "delete_file"])
        self.assertTrue(all(call["status"] == "committed" for call in calls))
        before = data["initial_snapshot"]["cloud_drive"]["files"]
        after = data["terminal_snapshot"]["cloud_drive"]["files"]
        target = calls[1]["arguments"]["file_id"]
        self.assertEqual(target, max(before, key=lambda key: before[key]["size"]))
        self.assertNotIn(target, after)
        self.assertEqual(len(after), len(before) - 1)
        e_observations = [row["payload"] for row in data["deliveries"] if row["actor"] == "E"]
        for observation in e_observations:
            for entry in observation["history"]:
                content = entry["content"]
                if entry["role"] == "observation" and content.get("status") == "tool_result":
                    result = content["result"]
                    files = result if isinstance(result, list) else [result]
                    self.assertTrue(all(set(item) == {"id_", "filename", "size"}
                                        for item in files))

    def test_travel_medium_e_checks_rating_and_reserves_without_full_user_read(self):
        data = self._closed("travel-user_task_0")
        calls = data["native_calls"]
        self.assertEqual([call["tool"] for call in calls],
                         ["get_rating_reviews_for_hotels", "reserve_hotel"])
        self.assertTrue(all(call["status"] == "committed" for call in calls))
        self.assertEqual(data["terminal_snapshot"]["reservation"]["reservation_type"], "hotel")
        for row in data["deliveries"]:
            if row["actor"] == "E":
                self.assertNotIn("get_user_information",
                                 {tool["name"] for tool in row["payload"]["available_tools"]})


if __name__ == "__main__":
    unittest.main()
