from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest

from agentmembrane.host_v2.runtime_provisioning import tree_manifest_sha256
from agentmembrane.host_v2.schema import canonical_json_bytes, sha256_bytes


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = (
    REPO_ROOT
    / "experiments/host_boundary_v2/runtime_envs/recovery_v1/"
    "materialize_agentdojo_recovery.py"
)
SPEC = importlib.util.spec_from_file_location("agentdojo_runtime_recovery", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
RECOVERY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECOVERY)


class AgentDojoRuntimeRecoveryTests(unittest.TestCase):
    def test_fresh_identity_and_authorized_root(self) -> None:
        self.assertNotEqual(RECOVERY.RUNTIME_ID, RECOVERY.OLD_RUNTIME_ID)
        self.assertTrue(
            str(RECOVERY.RUNTIME_ROOT).startswith(
                "/private/tmp/agentmembrane-rq2-agentdojo-runtime-"
            )
        )
        expectation = RECOVERY.build_expectation()
        self.assertIn("--offline", expectation.sync_arguments)
        self.assertEqual(
            dict((row.name, row.value) for row in expectation.sync_environment_overrides)[
                "PYTHONDONTWRITEBYTECODE"
            ],
            "1",
        )

    def test_three_artifacts_are_canonical_and_interlocked(self) -> None:
        validation = RECOVERY.validate_artifacts()
        self.assertTrue(validation["valid"])
        self.assertEqual(validation["hygiene"]["pyc_count"], 0)
        self.assertEqual(validation["hygiene"]["pycache_dir_count"], 0)
        self.assertEqual(validation["hygiene"]["dataless_file_count"], 0)
        self.assertEqual(
            validation["environment_tree_sha256"],
            tree_manifest_sha256(RECOVERY.RUNTIME_ROOT),
        )
        live_bytes = RECOVERY.LIVE_VALIDATOR_PATH.read_bytes()
        live = json.loads(live_bytes)
        self.assertEqual(live_bytes, canonical_json_bytes(live))
        preflight_bytes = RECOVERY.ADAPTER_PREFLIGHT_PATH.read_bytes()
        preflight = json.loads(preflight_bytes)
        self.assertEqual(preflight_bytes, canonical_json_bytes(preflight))
        self.assertEqual(
            preflight["live_validator_sha256"], sha256_bytes(live_bytes)
        )
        self.assertFalse(any(preflight["execution_counts"].values()))
        self.assertFalse(any(preflight["scientific_claims"].values()))
        binding_bytes = RECOVERY.BINDING_PATH.read_bytes()
        binding = json.loads(binding_bytes)
        self.assertEqual(binding_bytes, canonical_json_bytes(binding))
        self.assertEqual(
            binding["adapter_preflight_sha256"], sha256_bytes(preflight_bytes)
        )
        self.assertEqual(binding["rejected_runtime_id"], RECOVERY.OLD_RUNTIME_ID)


if __name__ == "__main__":
    unittest.main()
