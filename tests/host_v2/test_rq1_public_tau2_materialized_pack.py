from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import sys
import unittest

from agentmembrane.host_v2.taskpacks import load_taskpack


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = (
    REPO_ROOT
    / "experiments/host_boundary_v2/rq1_public_preflight_v1/materialize_tau2_pack.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "rq1_public_tau2_materialized_pack_test", MODULE_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load tau2 materializer")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MATERIALIZER = _load_module()


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RQ1PublicTau2MaterializedPackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = REPO_ROOT / MATERIALIZER.SOURCE_PACK
        self.target = REPO_ROOT / MATERIALIZER.TARGET_PACK

    def test_source_pack_identity_is_unchanged(self) -> None:
        self.assertEqual(
            _sha(self.source / "manifest.json"),
            MATERIALIZER.SOURCE_MANIFEST_SHA256,
        )

    def test_all_seven_restored_files_are_physical_and_exact(self) -> None:
        self.assertEqual(len(MATERIALIZER.RESTORED_FILES), 7)
        for relative, expected in MATERIALIZER.RESTORED_FILES.items():
            with self.subTest(relative=relative):
                path = self.target / "raw/upstream" / relative
                self.assertTrue(path.is_file())
                flags = path.lstat().st_flags
                self.assertFalse(flags & getattr(stat, "SF_DATALESS", 0))
                self.assertFalse(flags & getattr(stat, "UF_COMPRESSED", 0))
                self.assertEqual(_sha(path), expected)

    def test_receipt_binds_manifest_payload_and_zero_execution_scope(self) -> None:
        receipt_path = self.target / MATERIALIZER.RECEIPT_NAME
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(receipt["restored_file_count"], 7)
        self.assertEqual(receipt["pack_id"], MATERIALIZER.TARGET_PACK_ID)
        self.assertEqual(
            receipt["manifest_sha256"], _sha(self.target / "manifest.json")
        )
        tree_sha, entry_count = MATERIALIZER._payload_tree_sha256(self.target)
        self.assertEqual(receipt["pack_payload_tree_sha256"], tree_sha)
        self.assertEqual(receipt["pack_payload_entry_count"], entry_count)
        self.assertTrue(all(value == 0 for value in receipt["execution_counts"].values()))
        self.assertFalse(receipt["claim_eligible"])
        self.assertFalse(receipt["execution_authorized"])

    def test_materialized_pack_loads_with_new_identity(self) -> None:
        pack = load_taskpack(self.target)
        self.assertEqual(pack.pack_id, MATERIALIZER.TARGET_PACK_ID)
        self.assertEqual(len(pack.tasks), 68)
        self.assertFalse(pack.manifest["claim_eligible"])
        materialization = pack.manifest["transformation"]["parameters"][
            "materialization"
        ]
        self.assertEqual(materialization["restored_file_count"], 7)
        self.assertEqual(
            materialization["implementation_sha256"], _sha(MODULE_PATH)
        )


if __name__ == "__main__":
    unittest.main()
