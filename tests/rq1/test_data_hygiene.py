from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from agentmembrane.rq1.data_hygiene import (
    discover_consumed_documents,
    exclude_consumed_episodes,
)

from .fixtures import toy_episode


class DataHygieneTests(unittest.TestCase):
    def test_legacy_documents_are_detected_and_excluded_by_split_and_document(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "old_manifest.json"
            manifest.write_text(
                '{"example_id":"dev-doc1-nda-15",'
                '"other":"contractnli-test-doc44-nda-2"}',
                encoding="utf-8",
            )
            block = root / "contractnli-train-doc9-nda-3.json"
            block.write_text("{}", encoding="utf-8")
            inventory = discover_consumed_documents((root,))
            self.assertTrue(inventory.contains(split="dev", document_id="1"))
            self.assertTrue(inventory.contains(split="test", document_id="44"))
            self.assertTrue(inventory.contains(split="train", document_id="9"))
            episode = toy_episode()
            kept = exclude_consumed_episodes((episode,), inventory)
            self.assertEqual(kept, ())
            unseen = replace(
                episode,
                document_id="2",
                independence_id="toy:document:2",
            )
            self.assertEqual(exclude_consumed_episodes((unseen,), inventory), (unseen,))


if __name__ == "__main__":
    unittest.main()
