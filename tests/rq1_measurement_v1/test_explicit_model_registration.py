"""An explicit new cohort is supported; a per-condition silent swap is not."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.rq1_collab_v1.audit import canonical, file_hash
from agentmembrane.host_v2.rq1_collab_v3.contract import clone, digest, matrix
from agentmembrane.host_v2.rq1_collab_v4 import workflow as w
from agentmembrane.host_v2.rq1_collab_v4.contract import system_spec
from agentmembrane.host_v2.rq1_collab_v4.attack_spec import (
    WORKSPACE_DELETE_GOAL, compile_attack_spec)


class ExplicitModelRegistrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.profiles = {"H": {"model": "unit-main", "reasoning_effort": "medium", "max_completion_tokens": 8192},
                         "S": {"model": "unit-worker", "max_completion_tokens": 8192},
                         "E": {"model": "unit-main", "reasoning_effort": "high", "max_completion_tokens": 8192}}

    def save(self, name, value):
        path = self.root / name
        path.write_bytes(canonical(value))
        return path

    def manifest(self, explicit=True):
        q, g = self.save("qualified.json", {}), self.save("goals.json", [])
        bundle = {"suite": "workspace", "original_id": "user_task_8", "world_id": "unit-only",
                  "public": {"goal": {"goal": WORKSPACE_DELETE_GOAL}}}
        bh, spec = digest(bundle), system_spec()
        attack_specs = {bh: compile_attack_spec(WORKSPACE_DELETE_GOAL)}
        m = {"schema_version": "rq1-workflow/4", "execution_mode": "engineering", "repeats": 1,
             "system_spec": spec, "system_spec_sha256": digest(spec), "code_sha256": {},
             "qualified_manifest": str(q), "qualified_sha256": file_hash(q),
             "goal_assignments_path": str(g), "goal_assignments_sha256": file_hash(g),
             "source_root": "unit-only", "upstream_hashes": {}, "task_count": 1, "condition_count": 12,
             "bundles": {bh: bundle}, "attack_specs": attack_specs,
             "attack_specs_sha256": digest(attack_specs),
             "cells": matrix(bh, "workspace-user_task_8", repeats=1,
                                                       models=self.profiles if explicit else None)}
        if explicit:
            source = self.save("models.json", self.profiles)
            m.update(role_model_profiles=clone(self.profiles), model_profile_source={"path": str(source),
                "sha256": file_hash(source), "profiles_sha256": digest(self.profiles),
                "selection": "explicit_new_baseline_not_automatic_fallback"})
        return m

    def load(self, m):
        unsigned = {k: v for k, v in m.items() if k != "manifest_sha256"}
        path = self.save("manifest.json", {**unsigned, "manifest_sha256": digest(unsigned)})
        with patch.object(w, "code_fingerprint", return_value={}), patch.object(w, "verify_upstream"):
            return w.load_manifest(path)

    def test_all_conditions_use_one_explicit_registration(self):
        m = self.load(self.manifest())
        self.assertEqual(len(m["cells"]), 12)
        for c in m["cells"]:
            self.assertEqual(c["models"], {a: self.profiles[a] for a in c["models"]})

    def test_original_default_is_preserved_without_explicit_registration(self):
        m = self.load(self.manifest(False))
        self.assertTrue(all(c["models"]["H"]["model"] == "gpt-5-2025-08-07" for c in m["cells"]))

    def test_single_condition_substitution_rejected_even_rehashed(self):
        m = self.manifest()
        m["cells"][0]["models"]["H"]["model"] = "unit-other"
        with self.assertRaisesRegex(ValueError, "incomplete_or_unmatched"):
            self.load(m)

    def test_modified_original_profile_file_rejected(self):
        m = self.manifest()
        self.save("models.json", {**self.profiles, "extra": {}})
        with self.assertRaisesRegex(ValueError, "registration_changed"):
            self.load(m)

    def test_incomplete_registration_rejected(self):
        m = self.manifest()
        del m["role_model_profiles"]
        with self.assertRaisesRegex(ValueError, "registration_incomplete"):
            self.load(m)

    def test_explicit_budget_source_is_bound_and_file_drift_is_rejected(self):
        m = self.manifest()
        budget = clone(m["cells"][0]["budget"])
        source = self.save("budget.json", budget)
        m.update(episode_budget=budget, budget_source={
            "path": str(source), "sha256": file_hash(source),
            "budget_sha256": digest(budget),
            "selection": "explicit_bounded_diagnostic_budget",
        })
        self.assertEqual(self.load(m)["episode_budget"], budget)
        changed = clone(budget)
        changed["external_decisions"] -= 1
        self.save("budget.json", changed)
        with self.assertRaisesRegex(ValueError, "budget_registration_changed"):
            self.load(m)

    def test_incomplete_budget_registration_is_rejected(self):
        m = self.manifest()
        m["episode_budget"] = clone(m["cells"][0]["budget"])
        with self.assertRaisesRegex(ValueError, "budget_registration_incomplete"):
            self.load(m)

    def test_invalid_profile_rejected_before_allocating_output(self):
        source = self.save("bad-models.json", {"H": self.profiles["H"]})
        with self.assertRaisesRegex(ValueError, "exact_actor_model_profiles"):
            w.prepare(self.root / "must-not-exist", tasks=["workspace:user_task_8"], models_file=source)
        self.assertFalse((self.root / "must-not-exist").exists())


if __name__ == "__main__":
    unittest.main()
