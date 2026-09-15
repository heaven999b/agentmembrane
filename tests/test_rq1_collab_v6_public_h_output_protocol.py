"""Public H output forms must bind exact original prompts without answer leakage."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import unittest

from agentmembrane.host_v2.rq1_collab_v1.native import NativeTask
from agentmembrane.host_v2.rq1_collab_v1.pilot_checkers import UTILITY_SOURCE_LOCKS
from agentmembrane.host_v2.rq1_collab_v6.contract import make_config
from agentmembrane.host_v2.rq1_collab_v6.driver import (
    _PUBLIC_H_ACTION_REQUEST_SHA256, _PUBLIC_H_FORMAT_BY_REQUEST_SHA256,
    _PUBLIC_H_FORMATS, role_prompts,
)


SOURCE = str(Path(__file__).resolve().parents[1] / "data/host_boundary_v2/upstream/agentdojo")
ACTIONS = {("workspace", "user_task_6"), ("workspace", "user_task_12"),
           ("workspace", "user_task_9"), ("workspace", "user_task_21"),
           ("banking", "user_task_3"), ("banking", "user_task_4"),
           ("travel", "user_task_3"), ("travel", "user_task_4"),
           ("travel", "user_task_7"), ("travel", "user_task_8"),
           ("slack", "user_task_5"), ("slack", "user_task_7"), ("slack", "user_task_12")}


@unittest.skipUnless(importlib.util.find_spec("pydantic"), "locked native AgentDojo runtime required")
class PublicHOutputProtocol(unittest.TestCase):
    def task(self, suite, number):
        return NativeTask(SOURCE, suite, f"user_task_{number}")

    def config(self, level="medium", regime="honest"):
        return make_config("a" * 64, "public-output-form", "H_E", level, regime,
                           mode="live_diagnostic")

    def test_all_new_strict_tasks_have_exact_public_prompt_routing(self):
        self.assertFalse(set(_PUBLIC_H_FORMAT_BY_REQUEST_SHA256) & _PUBLIC_H_ACTION_REQUEST_SHA256)
        self.assertEqual(set(_PUBLIC_H_FORMAT_BY_REQUEST_SHA256.values()), set(_PUBLIC_H_FORMATS))
        self.assertEqual(len(_PUBLIC_H_FORMAT_BY_REQUEST_SHA256), 27)
        self.assertEqual(len(_PUBLIC_H_ACTION_REQUEST_SHA256), 13)
        for suite, task_id in UTILITY_SOURCE_LOCKS:
            with self.subTest(suite=suite, task=task_id):
                task = NativeTask(SOURCE, suite, task_id)
                fingerprint = hashlib.sha256(task.prompt.encode("utf-8")).hexdigest()
                if (suite, task_id) in ACTIONS:
                    self.assertIn(fingerprint, _PUBLIC_H_ACTION_REQUEST_SHA256)
                    self.assertNotIn(fingerprint, _PUBLIC_H_FORMAT_BY_REQUEST_SHA256)
                else:
                    self.assertIn(fingerprint, _PUBLIC_H_FORMAT_BY_REQUEST_SHA256)
                    prompts = role_prompts(self.config(), task.prompt, "synthetic public fixture goal")
                    self.assertIn("Public output fields for this original request only:", prompts["H"])
                    self.assertNotIn("Public output fields for this original request only:", prompts["E"])

    def test_h_instruction_identical_across_permission_and_regime(self):
        task = self.task("travel", 15)
        variants = [role_prompts(self.config(level, regime), task.prompt, "synthetic public fixture goal")["H"]
                    for level in ("low", "medium", "high") for regime in ("honest", "malicious")]
        self.assertEqual(len(set(variants)), 1)
        self.assertIn("three_day_price", variants[0])
        self.assertNotIn("Speedy Rentals", variants[0])
        self.assertNotIn("SunSet Rent-A-Car", variants[0])
        altered = role_prompts(self.config(), task.prompt + " ", "synthetic public fixture goal")["H"]
        self.assertNotIn("Public output fields for this original request only:", altered)

    def test_tokyo_calendar_action_has_public_fact_format_in_all_conditions(self):
        task = self.task("travel", 1)
        variants = [role_prompts(self.config(level, regime), task.prompt, "synthetic public fixture goal")["H"]
                    for level in ("low", "medium", "high") for regime in ("honest", "malicious")]
        self.assertEqual(len(set(variants)), 1)
        self.assertIn("hotel (string), rating (number), price_max (number), and address (string)", variants[0])
        self.assertNotIn("City Hub", variants[0].split("Public output fields for this original request only:", 1)[1])
        self.assertNotIn("1-1-1 Nishi-Shinjuku", variants[0])
        altered = role_prompts(self.config(), task.prompt + " ", "synthetic public fixture goal")["H"]
        self.assertNotIn("Public output fields for this original request only:", altered)

    def test_explicit_original_format_and_action_tasks_keep_their_semantics(self):
        for number, expected in ((2, "YYYY-MM-DD HH:MM"), (5, "HH:MM"),
                                 (11, "HH:MM"), (14, "YYYY-MM-DD HH:MM")):
            with self.subTest(task=number):
                task = self.task("workspace", number)
                prompt = role_prompts(self.config(), task.prompt, "synthetic public fixture goal")["H"]
                instruction = prompt.split("Public output fields for this original request only:", 1)[1]
                self.assertIn(expected, instruction)
                self.assertIn("no surrounding prose or JSON", instruction)
        for suite, number in (("workspace", 6), ("workspace", 12),
                              ("slack", 5), ("slack", 7), ("slack", 12)):
            with self.subTest(suite=suite, task=number):
                task = self.task(suite, number)
                prompt = role_prompts(self.config(), task.prompt, "synthetic public fixture goal")["H"]
                self.assertNotIn("Public output fields for this original request only:", prompt)


if __name__ == "__main__":
    unittest.main()
