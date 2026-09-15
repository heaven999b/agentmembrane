from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agentmembrane.rq1.contractnli import dataset_inventory, file_sha256, load_contractnli
from agentmembrane.rq1.schema import Label, sha256_text


class ContractNliLoaderTests(unittest.TestCase):
    def test_loader_preserves_exact_character_slices_and_skips_not_mentioned(self) -> None:
        texts = (
            "Alpha must keep data secret.",
            "The duty survives termination.",
            "Disclosure needs written consent.",
            "Public data is excluded.",
            "Ontario law applies.",
            "One archival copy may be retained.",
        )
        document_text = "\n".join(texts)
        spans: list[list[int]] = []
        cursor = 0
        for text in texts:
            spans.append([cursor, cursor + len(text)])
            cursor += len(text) + 1
        payload = {
            "labels": {
                "h-entail": {"hypothesis": "Alpha must keep data secret."},
                "h-nm": {"hypothesis": "The agreement has a price."},
            },
            "documents": [
                {
                    "id": 7,
                    "text": document_text,
                    "spans": spans,
                    "annotation_sets": [
                        {
                            "annotations": {
                                "h-entail": {"choice": "Entailment", "spans": [0, 1]},
                                "h-nm": {"choice": "NotMentioned", "spans": []},
                            }
                        }
                    ],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "dev.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            episodes = load_contractnli(path)
            self.assertEqual(len(episodes), 1)
            episode = episodes[0]
            self.assertEqual(episode.gold_label, Label.ENTAILMENT)
            self.assertEqual(episode.spans[0].text, texts[0])
            self.assertEqual(episode.spans[0].text_sha256, sha256_text(texts[0]))
            self.assertEqual(episode.source_file_sha256, file_sha256(path))
            self.assertTrue(set(episode.gold_evidence_ids) <= set(episode.candidate_span_ids))
            inventory = dataset_inventory(episodes)
            self.assertEqual(inventory["episode_n"], 1)
            self.assertEqual(inventory["independent_document_n"], 1)
            self.assertTrue(inventory["all_episode_schemas_valid"])


if __name__ == "__main__":
    unittest.main()
