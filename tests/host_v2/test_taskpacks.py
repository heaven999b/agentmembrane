from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from agentmembrane.host_v2.schema import IntegrityError, SchemaError, canonical_json_bytes, sha256_bytes
from agentmembrane.host_v2.taskpacks import (
    load_agentdojo_candidate_manifest,
    load_candidate_manifest,
    load_taskpack,
    load_tau2_candidate_manifest,
    select_tasks,
    taskpack_content_sha256,
    verify_taskpack,
)


def _sha(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


class TaskPackFixture:
    def __init__(self, root: Path, *, origin: str = "public_benchmark") -> None:
        self.root = root
        (root / "raw").mkdir(parents=True)
        (root / "transform").mkdir()
        (root / "fixtures").mkdir()
        (root / "raw" / "source.json").write_text('{"source":true}\n', encoding="utf-8")
        (root / "transform" / "build.py").write_text("# frozen transform\n", encoding="utf-8")
        (root / "fixtures" / "state.json").write_text('{"state":0}\n', encoding="utf-8")
        self.tasks = [
            self.task(
                task_id="gate-1",
                cluster_id="upstream-gate-1",
                split="gate",
                pair_id="gate-pair-1",
                upstream_task_id="gate-source-1",
            ),
            self.task(
                task_id="formal-1",
                cluster_id="upstream-formal-1",
                split="formal",
                pair_id="formal-pair-1",
                upstream_task_id="formal-source-1",
            ),
        ]
        for task in self.tasks:
            task["origin"] = origin
        self.write(origin=origin)

    @staticmethod
    def task(
        *,
        task_id: str,
        cluster_id: str,
        split: str,
        pair_id: str,
        upstream_task_id: str,
    ) -> dict:
        return {
            "task_id": task_id,
            "cluster_id": cluster_id,
            "domain_id": "fixture-domain",
            "origin": "public_benchmark",
            "split": split,
            "pair_id": pair_id,
            "pair_role": "benign",
            "family": "fixture-family",
            "surface_task": "Perform the frozen fixture operation.",
            "authorized_test_objective": None,
            "fixture_ref": "fixtures/state.json",
            "oracle_ref": "fixture:state-oracle-v1",
            "metadata": {"upstream_task_id": upstream_task_id},
        }

    def write(self, *, origin: str, claim_eligible: bool | None = None) -> None:
        tasks_text = "".join(
            json.dumps(task, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
            for task in self.tasks
        )
        (self.root / "tasks.jsonl").write_text(tasks_text, encoding="utf-8")
        manifest = {
            "schema_version": 2,
            "pack_id": "fixture-pack",
            "title": "Verified fixture pack",
            "origin": origin,
            "claim_eligible": (
                origin != "authored_synthetic" if claim_eligible is None else claim_eligible
            ),
            "upstream": {
                "name": "fixture-upstream",
                "url": "https://example.invalid/fixture",
                "version_or_commit": "fixture-v1",
                "license": "MIT",
                "retrieved_at": "2026-08-28T00:00:00Z",
                "raw_files": [
                    {"path": "raw/source.json", "sha256": _sha(self.root / "raw/source.json")}
                ],
            },
            "transformation": {
                "script_path": "transform/build.py",
                "script_sha256": _sha(self.root / "transform/build.py"),
                "parameters": {"fixture": True},
                "tasks_sha256": _sha(self.root / "tasks.jsonl"),
            },
            "fixtures": [
                {"path": "fixtures/state.json", "sha256": _sha(self.root / "fixtures/state.json")}
            ],
            "task_count": len(self.tasks),
            "cluster_count": len({task["cluster_id"] for task in self.tasks}),
            "splits": {
                "gate": sum(task["split"] == "gate" for task in self.tasks),
                "formal": sum(task["split"] == "formal" for task in self.tasks),
            },
        }
        (self.root / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )


class TaskPackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "pack"
        self.fixture = TaskPackFixture(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_load_verifies_provenance_counts_and_content(self) -> None:
        pack = load_taskpack(self.root)
        report = verify_taskpack(pack)
        self.assertTrue(report["valid"], report)
        self.assertFalse(report["population_claim_eligible"])
        self.assertFalse(report["public_readiness"]["ready"])
        self.assertIn(
            "READINESS_MANIFEST_MISSING",
            report["public_readiness"]["blocker_codes"],
        )
        self.assertEqual(report["task_count"], 2)
        self.assertEqual(report["cluster_count"], 2)
        self.assertEqual(report["content_sha256"], taskpack_content_sha256(pack))

    def test_select_tasks_is_exact_and_fails_closed(self) -> None:
        pack = load_taskpack(self.root)
        selected = select_tasks(
            pack,
            split="formal",
            families=frozenset({"fixture-family"}),
            task_ids=frozenset({"formal-1"}),
        )
        self.assertEqual([task.task_id for task in selected], ["formal-1"])
        with self.assertRaises(IntegrityError):
            select_tasks(
                pack,
                split="formal",
                families=frozenset({"fixture-family"}),
                task_ids=frozenset({"missing"}),
            )
        with self.assertRaises(IntegrityError):
            select_tasks(pack, split="formal", families=frozenset({"other"}))

    def test_raw_file_tamper_is_rejected(self) -> None:
        (self.root / "raw/source.json").write_text('{"tampered":true}\n', encoding="utf-8")
        with self.assertRaisesRegex(IntegrityError, "raw_file_0"):
            load_taskpack(self.root)

    def test_transformation_script_tamper_is_rejected(self) -> None:
        (self.root / "transform/build.py").write_text("# changed\n", encoding="utf-8")
        with self.assertRaisesRegex(IntegrityError, "transformation_script"):
            load_taskpack(self.root)

    def test_transformed_task_tamper_is_rejected(self) -> None:
        with (self.root / "tasks.jsonl").open("a", encoding="utf-8") as stream:
            stream.write("{}\n")
        with self.assertRaises((SchemaError, IntegrityError)):
            load_taskpack(self.root)

    def test_unknown_manifest_field_is_rejected(self) -> None:
        path = self.root / "manifest.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["unfrozen_extension"] = True
        path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(SchemaError, "unknown"):
            load_taskpack(self.root)

    def test_synthetic_cannot_be_claim_eligible(self) -> None:
        for task in self.fixture.tasks:
            task["origin"] = "authored_synthetic"
        self.fixture.write(origin="authored_synthetic", claim_eligible=True)
        with self.assertRaisesRegex((SchemaError, IntegrityError), "cannot be claim eligible"):
            load_taskpack(self.root)

    def test_synthetic_cannot_be_labeled_public_real(self) -> None:
        for task in self.fixture.tasks:
            task["origin"] = "authored_synthetic"
        self.fixture.tasks[0]["metadata"]["data_class"] = "public_real"
        self.fixture.write(origin="authored_synthetic", claim_eligible=False)
        with self.assertRaisesRegex(IntegrityError, "mislabeled"):
            load_taskpack(self.root)

    def test_lexical_variants_cannot_be_independent_clusters(self) -> None:
        self.fixture.tasks[1]["metadata"]["upstream_task_id"] = "gate-source-1"
        self.fixture.write(origin="public_benchmark")
        with self.assertRaisesRegex(IntegrityError, "not independent draws"):
            load_taskpack(self.root)

    def test_claim_pack_requires_upstream_sampling_identity(self) -> None:
        self.fixture.tasks[1]["metadata"] = {}
        self.fixture.write(origin="public_benchmark")
        with self.assertRaisesRegex(IntegrityError, "upstream/workflow identity"):
            load_taskpack(self.root)

    def test_explicit_lexical_variant_must_share_cluster(self) -> None:
        self.fixture.tasks[1]["metadata"]["lexical_variant_of"] = "gate-1"
        self.fixture.write(origin="public_benchmark")
        with self.assertRaisesRegex(IntegrityError, "must share cluster_id"):
            load_taskpack(self.root)

    def test_gate_and_formal_source_identity_must_be_disjoint(self) -> None:
        self.fixture.tasks[1]["metadata"]["workflow_id"] = "shared-workflow"
        self.fixture.tasks[0]["metadata"]["workflow_id"] = "shared-workflow"
        self.fixture.tasks[1]["cluster_id"] = self.fixture.tasks[0]["cluster_id"]
        self.fixture.write(origin="public_benchmark")
        with self.assertRaisesRegex(IntegrityError, "gate/formal workflow_id overlap"):
            load_taskpack(self.root)

    def test_missing_candidate_manifest_fails_closed(self) -> None:
        with self.assertRaisesRegex(IntegrityError, "missing"):
            load_candidate_manifest(Path(self.temporary.name) / "not-generated.json")


class CandidateManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "upstream" / "tau2").mkdir(parents=True)
        (self.root / "taskpacks").mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_upstream_manifest(self, *, source: dict) -> Path:
        path = self.root / "upstream_manifest.json"
        path.write_text(
            json.dumps({"schema_version": 1, "sources": [source]}), encoding="utf-8"
        )
        return path

    def test_tau2_candidate_provenance_and_task_hash(self) -> None:
        upstream_root = self.root / "upstream" / "tau2"
        tasks_path = upstream_root / "tasks.json"
        task = {"id": 7, "description": {"purpose": "fixture"}}
        tasks_path.write_text(json.dumps([task]), encoding="utf-8")
        license_path = upstream_root / "LICENSE"
        license_path.write_text("MIT fixture\n", encoding="utf-8")
        source = {
            "source_id": "tau2-bench-v1.0.1",
            "commit": "abc123",
            "version": "1.0.1",
            "license": "MIT",
            "license_sha256": _sha(license_path),
            "local_root": str(upstream_root),
            "task_files": [{"path": "tasks.json", "sha256": _sha(tasks_path)}],
        }
        upstream_manifest = self._write_upstream_manifest(source=source)
        candidate_path = self.root / "taskpacks" / "tau2_candidate_manifest.json"
        candidate = {
            "schema_version": 1,
            "benchmark": {
                "name": "tau2-bench",
                "version": "1.0.1",
                "repository": "https://example.invalid/tau2",
                "commit": "abc123",
                "license": {
                    "spdx": "MIT",
                    "path": "LICENSE",
                    "sha256": _sha(license_path),
                },
                "task_source_hash_method": "canonical JSON fixture",
                "upstream_files": [{"path": "tasks.json", "sha256": _sha(tasks_path)}],
            },
            "selection": {},
            "policy_profiles": {"fixture-policy": {}},
            "candidates": [
                {
                    "domain": "retail",
                    "upstream_task_id": "7",
                    "source_path": "tasks.json",
                    "source_hash": sha256_bytes(canonical_json_bytes(task)),
                    "split_membership": ["base", "train"],
                    "workflow": "fixture",
                    "mutation_actions": ["mutate"],
                    "policy_requirement": "fixture-policy",
                    "reward_criteria": {"basis": ["DB"]},
                    "cluster_id": "upstream-task-7",
                    "adapt_to_rq": ["RQ1", "RQ4"],
                    "needs_manual_review": False,
                    "review_note": None,
                }
            ],
        }
        candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
        loaded = load_tau2_candidate_manifest(
            candidate_path, upstream_manifest_path=upstream_manifest
        )
        self.assertEqual(loaded["candidates"][0]["upstream_task_id"], "7")
        self.assertNotIn("__source_key_for_validation__", loaded["candidates"][0])
        self.assertEqual(
            load_candidate_manifest(
                candidate_path, upstream_manifest_path=upstream_manifest
            ),
            loaded,
        )

        damaged = deepcopy(candidate)
        damaged["candidates"][0]["source_hash"] = "0" * 64
        candidate_path.write_text(json.dumps(damaged), encoding="utf-8")
        with self.assertRaisesRegex(IntegrityError, "source_hash mismatch"):
            load_tau2_candidate_manifest(
                candidate_path, upstream_manifest_path=upstream_manifest
            )

    def test_agentdojo_candidate_requires_upstream_locked_sources(self) -> None:
        upstream_root = self.root / "upstream" / "agentdojo"
        upstream_root.mkdir()
        source_file = upstream_root / "user_tasks.py"
        source_file.write_text("# frozen task definitions\n", encoding="utf-8")
        license_file = upstream_root / "LICENSE"
        license_file.write_text("MIT fixture\n", encoding="utf-8")
        source = {
            "source_id": "agentdojo-v0.1.35",
            "commit": "def456",
            "version": "0.1.35",
            "license": "MIT",
            "license_sha256": _sha(license_file),
            "local_root": str(upstream_root),
            "task_files": [{"path": "user_tasks.py", "sha256": _sha(source_file)}],
        }
        upstream_manifest = self._write_upstream_manifest(source=source)
        candidate_path = self.root / "taskpacks" / "agentdojo_candidate_manifest.json"
        source_item = {
            "id": "0",
            "source_file": "user_tasks.py",
            "source_sha256": _sha(source_file),
        }
        candidate = {
            "schema_version": 1,
            "upstream": {
                "name": "AgentDojo",
                "version": "0.1.35",
                "commit": "def456",
                "license": "MIT",
                "license_sha256": _sha(license_file),
                "upstream_files": [{"path": "user_tasks.py", "sha256": _sha(source_file)}],
            },
            "selection": {},
            "counts": {"total": 1},
            "candidates": [
                {
                    "candidate_id": "agentdojo-workspace-0",
                    "domain": "workspace",
                    "original_user_task": {
                        **source_item,
                        "class": "UserTask0",
                        "objective": "fixture",
                    },
                    "original_injection_task": {
                        **source_item,
                        "class": "InjectionTask0",
                        "goal": "fixture",
                    },
                    "injection_vector": source_item,
                    "adapted_rq2_family": "composition",
                    "rq_targets": ["RQ2", "RQ4"],
                    "cluster_id": "agentdojo-user-task-0",
                    "selection_status": "candidate",
                    "adaptation_notes": "fixture",
                }
            ],
        }
        candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
        loaded = load_agentdojo_candidate_manifest(
            candidate_path, upstream_manifest_path=upstream_manifest
        )
        self.assertEqual(loaded["counts"]["total"], 1)
        self.assertEqual(
            load_candidate_manifest(
                candidate_path, upstream_manifest_path=upstream_manifest
            ),
            loaded,
        )


if __name__ == "__main__":
    unittest.main()
