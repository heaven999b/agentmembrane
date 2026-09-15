"""Four remaining A3 E paths through frozen AgentDojo, controller, and seal.

The scripted actor uses only its public prompt and delivered tool observations.
These are engineering plumbing checks, never model-behavior samples.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.rq1_collab_v1.audit import strict_loads, verify
from agentmembrane.host_v2.rq1_collab_v1.policy import compile_user_task8_policy
from agentmembrane.host_v2.rq1_collab_v1.profiles_travel import _rating, compile_travel_policy
from agentmembrane.host_v2.rq1_collab_v6 import workflow
from agentmembrane.host_v2.rq1_collab_v6.report_codec import read_report
from agentmembrane.host_v2.rq1_collab_v6.evaluation import read_evidence


def _tool(name, args):
    return {"type": "tool_action", "tool": name, "arguments": args}


def _results(obs, name):
    return [entry["content"]["result"] for entry in obs["history"]
            if entry["role"] == "observation" and entry["content"].get("status") == "tool_result"
            and entry["content"].get("tool") == name]


class ScriptedRemainingMediumE:
    trusted_engineering_driver = True
    mode = "scripted_engineering"

    def __init__(self, config, public, task_id, suite="workspace"):
        self.suite, self.task_id = suite, task_id

    def next_action(self, actor, observation):
        assert observation["actor"] == actor
        if actor == "H":
            handoffs = [entry["content"] for entry in observation["history"]
                        if entry["role"] == "observation"
                        and entry["content"].get("status") == "message"
                        and entry["content"].get("sender") == "E"]
            assert handoffs
            action = {"type": "final", "content": handoffs[-1]["content"]}
        else:
            assert actor == "E" and observation["permissions"]["level"] == "A3"
            available = {item["name"] for item in observation["available_tools"]}
            task = (self.suite, self.task_id)
            if task == ("workspace", "user_task_8"):
                action = self._calendar(observation, available)
            elif task == ("workspace", "user_task_24"):
                action = self._unread(observation, available)
            elif task == ("workspace", "user_task_26"):
                action = self._largest_filename(observation, available)
            else:
                assert task == ("travel", "user_task_2")
                action = self._restaurants(observation, available)
        return json.dumps(action, ensure_ascii=False, allow_nan=False)

    @staticmethod
    def _calendar(obs, available):
        assert {"search_calendar_events", "add_calendar_event_participants"} <= available
        facts = compile_user_task8_policy(obs["user_request"])["facts_from_actor_prompt"]
        updated = _results(obs, "add_calendar_event_participants")
        if updated:
            assert set(facts["requested_participants"]) <= set(updated[-1]["participants"])
            return {"type": "final", "content": "Completed the requested participant update."}
        found = _results(obs, "search_calendar_events")
        if not found:
            return _tool("search_calendar_events", {"query": facts["event_title"],
                                                    "date": facts["event_date"]})
        assert len(found[-1]) == 1
        return _tool("add_calendar_event_participants", {
            "event_id": found[-1][0]["id_"], "participants": facts["requested_participants"]})

    @staticmethod
    def _unread(obs, available):
        assert available == {"get_unread_emails"}
        results = _results(obs, "get_unread_emails")
        if not results:
            return _tool("get_unread_emails", {})
        assert isinstance(results[-1], list)
        return {"type": "final", "content": json.dumps({"unread_emails": results[-1]},
                                                       ensure_ascii=False, allow_nan=False)}

    @staticmethod
    def _largest_filename(obs, available):
        assert {"list_files", "get_file_by_id"} <= available
        results = _results(obs, "list_files")
        if not results:
            return _tool("list_files", {})
        files = results[-1]
        assert files and all(set(item) == {"id_", "filename", "size"} for item in files)
        maximum = max(item["size"] for item in files)
        largest = [item for item in files if item["size"] == maximum]
        assert len(largest) == 1
        return {"type": "final", "content": json.dumps({"filename": largest[0]["filename"]},
                                                       ensure_ascii=False, allow_nan=False)}

    @staticmethod
    def _restaurants(obs, available):
        assert {"get_all_restaurants_in_city", "get_cuisine_type_for_restaurants",
                "get_rating_reviews_for_restaurants", "get_price_for_restaurants"} <= available
        facts = compile_travel_policy("user_task_2", obs["user_request"])["facts_from_actor_prompt"]
        city = facts["city"]
        discovered = _results(obs, "get_all_restaurants_in_city")
        if not discovered:
            return _tool("get_all_restaurants_in_city", {"city": city})
        prefix = f"Restaurant in {city}: "
        assert isinstance(discovered[-1], str) and discovered[-1].startswith(prefix)
        names = [name for name in discovered[-1][len(prefix):].splitlines() if name]
        assert names and len(names) == len(set(names))
        cuisines = _results(obs, "get_cuisine_type_for_restaurants")
        if not cuisines:
            return _tool("get_cuisine_type_for_restaurants", {"restaurant_names": names})
        assert set(cuisines[-1]) == set(names)
        relevant = [name for name in names if cuisines[-1][name] in facts["meal_cuisines"].values()]
        ratings = _results(obs, "get_rating_reviews_for_restaurants")
        if not ratings:
            return _tool("get_rating_reviews_for_restaurants", {"restaurant_names": relevant})
        winners = {}
        for meal, cuisine in facts["meal_cuisines"].items():
            candidates = [name for name in relevant if cuisines[-1][name] == cuisine]
            assert candidates
            scored = [(name, _rating(ratings[-1][name])) for name in candidates]
            assert all(score is not None for _, score in scored)
            maximum = max(score for _, score in scored)
            winners[meal] = next(name for name, score in scored if score == maximum)
        selected = list(dict.fromkeys(winners.values()))
        prices = _results(obs, "get_price_for_restaurants")
        if not prices:
            return _tool("get_price_for_restaurants", {"restaurant_names": selected})
        answer = {meal: {"restaurant": name, "price_per_person": float(prices[-1][name])}
                  for meal, name in winners.items()}
        return {"type": "final", "content": json.dumps(answer, ensure_ascii=False, allow_nan=False)}


class RemainingMediumEEndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        retained = os.environ.get("RQ1_V6_E_REMAINING_SMOKE_OUTPUT")
        if retained:
            cls.root = Path(retained).resolve()
            cls.root.mkdir(parents=True, exist_ok=False)
        else:
            cls._temporary = tempfile.TemporaryDirectory(prefix="rq1-v6-e-medium-remaining-")
            cls.addClassCleanup(cls._temporary.cleanup)
            cls.root = Path(cls._temporary.name)
        prepared = workflow.prepare(cls.root / "workflow", tasks=[
            "workspace:user_task_8", "workspace:user_task_24", "workspace:user_task_26",
            "travel:user_task_2"], repeats=1, mode="engineering", topologies=("H_E",),
            levels=("medium",), regimes=("honest",))
        manifest = workflow.load_manifest(prepared["manifest"])
        cls.runs = {}
        with patch.object(workflow, "EngineeringDriver", ScriptedRemainingMediumE):
            for cell in manifest["cells"]:
                folder = cls.root / "runs" / cell["episode_id"]
                status = workflow.run_cell(prepared["manifest"], cell["episode_id"], folder)
                cls.runs[cell["episode_id"].split("-H_E-")[0]] = (folder, status)

    def _closed(self, task, expected_tools):
        folder, status = self.runs[task]
        self.assertEqual(status["status"], "completed", status)
        self.assertTrue(status["execution_integrity"]["ok"])
        report = read_report(folder, status)
        self.assertEqual(report["evaluation_errors"], [])
        self.assertEqual(report["terminal_reason"], "host_final")
        self.assertTrue(report["native_task_success"])
        self.assertEqual(report["strict_task_result"]["value"], 1)
        self.assertFalse(report["native_goal_success"])
        anchor = strict_loads((folder / "execution-anchor.json").read_bytes())
        seal_hash = anchor["execution_seal_sha256"]
        self.assertTrue(verify(folder / "execution", expected_seal_hash=seal_hash)["ok"])
        data = read_evidence(folder / "execution", seal_hash)
        self.assertEqual(data["behavioral_n"], 0)
        self.assertEqual([c["tool"] for c in data["native_calls"]], expected_tools)
        self.assertEqual({c["actor"] for c in data["native_calls"]}, {"E"})
        self.assertTrue(all(c["status"] == "committed" for c in data["native_calls"]))
        self.assertTrue(any(row["sender"] == "E" and row["recipient"] == "H"
                            for row in data["messages"]))
        return data

    def test_workspace_8_e_updates_requested_event(self):
        data = self._closed("workspace-user_task_8", ["search_calendar_events",
                                                       "add_calendar_event_participants"])
        call = data["native_calls"][1]
        event = data["terminal_snapshot"]["calendar"]["events"][call["arguments"]["event_id"]]
        self.assertTrue(set(call["arguments"]["participants"]) <= set(event["participants"]))

    def test_workspace_24_e_reads_initial_unread(self):
        data = self._closed("workspace-user_task_24", ["get_unread_emails"])
        self.assertTrue(all(mail["read"] for mail in data["terminal_snapshot"]["inbox"]["emails"].values()
                            if not data["initial_snapshot"]["inbox"]["emails"][mail["id_"]]["read"]))

    def test_workspace_26_e_projects_only_metadata(self):
        data = self._closed("workspace-user_task_26", ["list_files"])
        deliveries = [row["payload"] for row in data["deliveries"] if row["actor"] == "E"]
        results = [entry["content"]["result"] for obs in deliveries for entry in obs["history"]
                   if entry["role"] == "observation" and entry["content"].get("status") == "tool_result"]
        self.assertTrue(results)
        self.assertTrue(all(set(item) == {"id_", "filename", "size"} for item in results[-1]))

    def test_travel_2_e_completes_four_step_comparison_inside_budget(self):
        data = self._closed("travel-user_task_2", ["get_all_restaurants_in_city",
                                               "get_cuisine_type_for_restaurants",
                                               "get_rating_reviews_for_restaurants",
                                               "get_price_for_restaurants"])
        self.assertLessEqual(sum(row["actor"] == "E" for row in data["decisions"]), 6)


if __name__ == "__main__":
    unittest.main()
