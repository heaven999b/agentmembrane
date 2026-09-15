from __future__ import annotations

from pathlib import Path
import unittest

from agentmembrane.host_v2.profiles import load_profile, validate_profile
from agentmembrane.host_v2.public_adapters import PublicAdapterRegistry
from agentmembrane.host_v2.schema import IntegrityError
from agentmembrane.host_v2.taskpacks import load_taskpack, select_tasks


REPO_ROOT = Path(__file__).resolve().parents[2]
PROFILE_ROOT = REPO_ROOT / "experiments/host_boundary_v2/config/profiles"
PACKS_ROOT = REPO_ROOT / "data/host_boundary_v2/packs"
OVERLAY_ROOT = REPO_ROOT / "experiments/host_boundary_v2/public_readiness_v2.1"
OVERLAY_SHA256 = "cd5a2f661f9247bb4e6541c0134387cba1faa19801e067031261b7b288c95d6d"


class PublicProfileFailClosedTests(unittest.TestCase):
    def test_public_formal_profile_requires_explicit_runtime_and_evidence(self) -> None:
        profile = load_profile(PROFILE_ROOT / "rq2-primary-formal.template.json")
        errors = validate_profile(profile, claim_bearing=False)
        self.assertTrue(
            any("lacks an explicit evidence root/hash" in error for error in errors),
            errors,
        )
        self.assertTrue(
            any("lacks an explicit live adapter registry" in error for error in errors),
            errors,
        )
        self.assertTrue(
            any("requires recomputed executable readiness" in error for error in errors),
            errors,
        )

    def test_diagnostic_overlay_binding_still_cannot_authorize_profile(self) -> None:
        profile = load_profile(PROFILE_ROOT / "rq2-primary-formal.template.json")
        bindings = {
            entry["pack_id"]: {
                "root": OVERLAY_ROOT.resolve(),
                "manifest_sha256": OVERLAY_SHA256,
            }
            for entry in profile.raw["taskpacks"]
        }
        errors = validate_profile(
            profile,
            claim_bearing=False,
            public_adapter_registry=PublicAdapterRegistry(),
            public_evidence_bindings=bindings,
        )
        self.assertFalse(
            any("lacks an explicit evidence root/hash" in error for error in errors),
            errors,
        )
        self.assertTrue(
            any("DIAGNOSTIC_OVERLAY_NO_GO" in error for error in errors),
            errors,
        )

    def test_prepare_selection_path_rejects_unready_public_formal_split(self) -> None:
        pack = load_taskpack(PACKS_ROOT / "agentdojo-v0.1.35-v1")
        families = frozenset(task.family for task in pack.tasks)
        with self.assertRaisesRegex(
            IntegrityError, "public formal task selection requires recomputed claim readiness"
        ):
            select_tasks(
                pack,
                split="formal",
                families=families,
                require_public_readiness=True,
            )

    def test_committed_synthetic_atomic_profile_remains_compatible(self) -> None:
        profile = load_profile(
            PROFILE_ROOT
            / "v2.1/host-mediated-atomic-synthetic-bringup-source.json"
        )
        self.assertEqual(validate_profile(profile, claim_bearing=False), [])


if __name__ == "__main__":
    unittest.main()
