from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agentmembrane.semantic_rq2.manifest import (
    HISTORICAL_SELECTION_CODE_SHA256S,
    build_contractnli_confirmation_manifest,
    build_contractnli_manifest,
    validate_manifest,
)
from agentmembrane.semantic_rq2.schema import sha256_json


def _document(document_id: int, *, duplicate_text: str | None = None) -> dict:
    pieces = [
        f"Document {document_id} clause {index} applies only if requirement {index} is met."
        for index in range(6)
    ]
    text = duplicate_text if duplicate_text is not None else " ".join(pieces)
    spans = []
    cursor = 0
    for piece in text.split(" | ") if " | " in text else pieces:
        start = text.index(piece, cursor)
        end = start + len(piece)
        spans.append([start, end])
        cursor = end
    return {
        "id": document_id,
        "text": text,
        "spans": spans,
        "annotation_sets": [
            {
                "annotations": {
                    "ent": {"choice": "Entailment", "spans": [0]},
                    "con": {"choice": "Contradiction", "spans": [1]},
                }
            }
        ],
        "document_type": "synthetic",
    }


def _write_split(path: Path, documents: list[dict]) -> None:
    payload = {
        "labels": {
            "ent": {"hypothesis": "The first condition applies only if its requirement is met."},
            "con": {"hypothesis": "The second condition applies only if its requirement is met."},
        },
        "documents": documents,
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


class ConfirmationManifestTests(unittest.TestCase):
    def test_train_confirmation_is_full_shape_and_normalized_source_disjoint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            license_path = root / "LICENSE"
            license_path.write_text("synthetic license\n", encoding="utf-8")
            canonical_text = " ".join(
                f"Document 0 clause {index} applies only if requirement {index} is met."
                for index in range(6)
            )
            test_path = root / "test.json"
            _write_split(test_path, [_document(0, duplicate_text=canonical_text)])
            prior_path = root / "prior.json"
            build_contractnli_manifest(
                split_path=test_path,
                license_path=license_path,
                output_path=prior_path,
                document_count=1,
                seed=1,
            )

            train_documents = [_document(index) for index in range(101)]
            # Raw bytes differ while normalized text is identical to the prior source.
            train_documents[0]["text"] = "  " + canonical_text.replace(
                ". Document", ".   Document"
            ) + "  "
            cursor = 2
            spans = []
            for piece in [
                f"Document 0 clause {index} applies only if requirement {index} is met."
                for index in range(6)
            ]:
                start = train_documents[0]["text"].index(piece, cursor)
                spans.append([start, start + len(piece)])
                cursor = start + len(piece)
            train_documents[0]["spans"] = spans
            train_path = root / "train.json"
            _write_split(train_path, train_documents)

            output = root / "confirmation.json"
            manifest = build_contractnli_confirmation_manifest(
                split_path=train_path,
                license_path=license_path,
                exclusion_manifest_paths=[prior_path],
                output_path=output,
                document_count=100,
                seed=20260901,
            )
            check = validate_manifest(
                manifest,
                expected_split_path=train_path,
                exact_baseline_shape=True,
            )
            self.assertTrue(check["valid"], check["problems"])
            self.assertEqual(len(manifest["cases"]), 200)
            self.assertEqual(len({row["cluster_id"] for row in manifest["cases"]}), 100)
            self.assertNotIn("0", {str(row["document_id"]) for row in manifest["cases"]})
            self.assertEqual(
                manifest["independent_confirmation"]["prior_normalized_source_overlap"], 0
            )

    def test_only_explicitly_known_historical_selection_code_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            from tests.semantic_rq2.fixtures import write_synthetic_manifest

            path = write_synthetic_manifest(root, cluster_n=1)
            manifest = json.loads(path.read_text(encoding="utf-8"))
            manifest["selection_code_sha256"] = next(iter(HISTORICAL_SELECTION_CODE_SHA256S))
            manifest.pop("content_sha256", None)
            manifest["content_sha256"] = sha256_json(manifest)
            self.assertTrue(
                validate_manifest(
                    manifest,
                    exact_baseline_shape=False,
                    allow_historical_selection_code=True,
                )["valid"]
            )
            manifest["selection_code_sha256"] = "0" * 64
            manifest.pop("content_sha256", None)
            manifest["content_sha256"] = sha256_json(manifest)
            check = validate_manifest(
                manifest,
                exact_baseline_shape=False,
                allow_historical_selection_code=True,
            )
            self.assertIn("selection_code_sha256_mismatch", check["problems"])


if __name__ == "__main__":
    unittest.main()
