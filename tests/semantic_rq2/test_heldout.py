from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agentmembrane.semantic_rq2.heldout import build_heldout_subset_manifest
from agentmembrane.semantic_rq2.manifest import validate_manifest
from tests.semantic_rq2.fixtures import (
    write_manifest_prefix_subset,
    write_synthetic_manifest,
)


class HeldoutManifestTests(unittest.TestCase):
    def test_subset_is_balanced_valid_and_cluster_disjoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent_path = write_synthetic_manifest(root)
            exclusion_path = write_manifest_prefix_subset(
                parent_path, root / "excluded.json", cluster_n=25
            )
            heldout = build_heldout_subset_manifest(
                parent_manifest_path=parent_path,
                exclusion_manifest_path=exclusion_path,
                output_path=root / "heldout.json",
                document_count=25,
                seed=20260901,
            )
            check = validate_manifest(heldout, exact_baseline_shape=False)
            excluded = {
                case["cluster_id"]
                for case in json.loads(exclusion_path.read_text(encoding="utf-8"))["cases"]
            }
            selected = {case["cluster_id"] for case in heldout["cases"]}
            self.assertTrue(check["valid"], check["problems"])
            self.assertEqual(check["case_n"], 50)
            self.assertEqual(check["cluster_n"], 25)
            self.assertEqual(check["label_counts"], {"Entailment": 25, "Contradiction": 25})
            self.assertFalse(excluded & selected)
            self.assertEqual(
                heldout["heldout_confirmation"]["cluster_overlap_with_exclusion"], 0
            )

    def test_fails_when_too_few_unseen_clusters_remain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent_path = write_synthetic_manifest(root)
            exclusion_path = write_manifest_prefix_subset(
                parent_path, root / "excluded.json", cluster_n=90
            )
            with self.assertRaisesRegex(ValueError, "only 10 available"):
                build_heldout_subset_manifest(
                    parent_manifest_path=parent_path,
                    exclusion_manifest_path=exclusion_path,
                    output_path=None,
                    document_count=25,
                    seed=20260901,
                )


if __name__ == "__main__":
    unittest.main()
