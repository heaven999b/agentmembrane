from __future__ import annotations

import json
import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tools import audit_rq2_public_bundle as audit


class RQ2PublicBundleAuditTests(unittest.TestCase):
    def test_repository_bundle_passes(self) -> None:
        result = audit.audit()
        self.assertTrue(result["passed"], result["errors"])
        self.assertEqual(result["artifact_count"], 10)
        self.assertFalse(result["claim_bearing"])

    def test_changed_artifact_fails_closed(self) -> None:
        manifest = json.loads(audit.MANIFEST.read_text(encoding="utf-8"))
        with TemporaryDirectory() as directory:
            root = Path(directory)
            target_manifest = (
                root
                / "results"
                / "semantic_rq2_confirmation_20260901"
                / "artifact_manifest.json"
            )
            target_manifest.parent.mkdir(parents=True)
            shutil.copy2(audit.MANIFEST, target_manifest)
            for row in manifest["artifacts"]:
                source = audit.ROOT / row["path"]
                target = root / row["path"]
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)

            analysis = (
                root
                / "results"
                / "semantic_rq2_confirmation_20260901"
                / "confirmation_analysis.json"
            )
            analysis.write_text(
                analysis.read_text(encoding="utf-8") + "\n",
                encoding="utf-8",
            )
            result = audit.audit(root)

        self.assertFalse(result["passed"])
        self.assertTrue(
            any("artifact size mismatch" in error for error in result["errors"]),
            result["errors"],
        )


if __name__ == "__main__":
    unittest.main()
