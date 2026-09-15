from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agentmembrane.semantic_rq2.confirmation_controller import (
    _promote_cache,
    build_checkpoint_manifest,
)
from agentmembrane.semantic_rq2.manifest import validate_manifest
from tests.semantic_rq2.fixtures import write_synthetic_manifest


class ConfirmationControllerTests(unittest.TestCase):
    def test_checkpoint_contains_25_complete_document_pairs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            full_path = write_synthetic_manifest(root, cluster_n=100)
            checkpoint_path = root / "checkpoint.json"
            manifest = build_checkpoint_manifest(
                full_manifest_path=full_path,
                output_path=checkpoint_path,
                document_clusters=25,
                seed=20260901,
            )
            check = validate_manifest(manifest, exact_baseline_shape=False)
            self.assertTrue(check["valid"], check["problems"])
            self.assertEqual(check["case_n"], 50)
            self.assertEqual(check["cluster_n"], 25)
            by_cluster: dict[str, set[str]] = {}
            for case in manifest["cases"]:
                by_cluster.setdefault(case["cluster_id"], set()).add(case["gold_label"])
            self.assertEqual(
                set(map(frozenset, by_cluster.values())),
                {frozenset({"Entailment", "Contradiction"})},
            )

    def test_cache_promotion_copies_only_cache_and_rejects_collision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            destination = root / "destination"
            cache_file = source / "cache" / "role" / "entry.json"
            cache_file.parent.mkdir(parents=True)
            cache_file.write_text(json.dumps({"prompt_sha256": "abc"}), encoding="utf-8")
            (source / "results.json").write_text("not promoted", encoding="utf-8")
            receipt = _promote_cache(source, destination)
            self.assertEqual(receipt["copied_file_n"], 1)
            self.assertTrue((destination / "cache" / "role" / "entry.json").is_file())
            self.assertFalse((destination / "results.json").exists())
            (destination / "cache" / "role" / "entry.json").write_text(
                json.dumps({"prompt_sha256": "different"}), encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "cache promotion collision"):
                _promote_cache(source, destination)


if __name__ == "__main__":
    unittest.main()
