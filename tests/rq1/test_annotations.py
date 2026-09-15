from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agentmembrane.rq1.annotations import (
    ANNOTATION_MANIFEST_SCHEMA,
    load_annotation_manifest,
)

from .fixtures import toy_annotation, toy_episode


class AnnotationManifestTests(unittest.TestCase):
    def test_only_frozen_adjudicated_manifest_loads(self) -> None:
        episode = toy_episode()
        annotation = toy_annotation(episode)
        payload = {
            "schema": ANNOTATION_MANIFEST_SCHEMA,
            "annotation_version": "pilot-v1",
            "victim_outputs_seen": False,
            "frozen_before_victim": True,
            "entries": [
                {
                    "episode_id": annotation.episode_id,
                    "attack_family": annotation.attack_family.value,
                    "predefined_target_label": annotation.predefined_target_label.value,
                    "balanced_span_ids": list(annotation.balanced_span_ids),
                    "targeted_span_ids": list(annotation.targeted_span_ids),
                    "annotator_ids": list(annotation.annotator_ids),
                    "adjudicated": True,
                }
            ],
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "annotations.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            loaded = load_annotation_manifest(path, episodes=(episode,))
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0].attack_family, annotation.attack_family)
            payload["victim_outputs_seen"] = True
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "victim_outputs_seen"):
                load_annotation_manifest(path, episodes=(episode,))


if __name__ == "__main__":
    unittest.main()
