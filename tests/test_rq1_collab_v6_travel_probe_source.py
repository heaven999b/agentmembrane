"""Source-native Travel permission-probe registration, without model calls."""
from __future__ import annotations

from pathlib import Path
import unittest

from agentmembrane.host_v2.rq1_collab_v1.policy import compile_task_policy
from agentmembrane.host_v2.rq1_collab_v1.process_backend import ProcessNativeTask
from agentmembrane.host_v2.rq1_collab_v6.authority_state import registered_probe_requests


PROJECT = Path(__file__).resolve().parents[1]
NATIVE_PYTHON = PROJECT / (
    "experiments/host_boundary_v2/runtime_envs/"
    "agentdojo-0.1.35-py3123-lock-395e3d0a5921-rq1v4/bin/python")
SOURCE_ROOT = PROJECT / "data/host_boundary_v2/upstream/agentdojo"
ELIGIBLE_TRAVEL_IDS = (0, 1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17)


class SourceNativeTravelProbeTests(unittest.TestCase):
    def test_all_eligible_travel_originals_register_only_source_bound_probes(self):
        self.assertTrue(NATIVE_PYTHON.is_file())
        self.assertTrue(SOURCE_ROOT.is_dir())
        for number in ELIGIBLE_TRAVEL_IDS:
            task_id = f"user_task_{number}"
            with self.subTest(task_id=task_id):
                native = ProcessNativeTask(str(NATIVE_PYTHON), str(SOURCE_ROOT),
                                           "travel", task_id, timeout=30)
                try:
                    facts = compile_task_policy("travel", task_id, native.prompt)
                    record = {"suite": "travel", "original_id": task_id,
                              "task_policy": facts}
                    probes = registered_probe_requests(
                        record, native.snapshot(), native.tool_specs)
                    self.assertTrue(probes)
                    self.assertEqual(len(probes), len({p["probe_id"] for p in probes}))
                    available = {spec["name"] for spec in native.tool_specs}
                    self.assertTrue(all(p["tool"] in available for p in probes))
                    if number == 9:
                        # This exact source original exposed `cities`, not
                        # `city`, and triggered a pre-model controller crash.
                        self.assertEqual(facts["facts_from_actor_prompt"]["cities"], ["Paris"])
                        self.assertNotIn("city", facts["facts_from_actor_prompt"])
                        self.assertEqual(native.record["class_source_sha256"],
                                         "7a5c767ad5827d2f92c84808ca193da45d005525f15f90177357b0e255c87541")
                        self.assertIn({"tool": "get_all_restaurants_in_city",
                                       "arguments": {"city": "Paris"}},
                                      [{k: p[k] for k in ("tool", "arguments")} for p in probes])
                finally:
                    native.shutdown()


if __name__ == "__main__":
    unittest.main()
