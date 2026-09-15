from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from agentmembrane.host_v2.public_adapters import (
    ADAPTER_CONTRACT_VERSION,
    PublicAdapterRegistry,
    PublicBenchmarkAdapter,
)
from agentmembrane.host_v2.public_readiness import (
    HOST_ACTION_MECHANISMS,
    REQUIRED_PARITY_CATEGORIES,
    audit_public_readiness,
    require_public_readiness,
    validate_checker_parity_report,
    validate_formal_split_evidence,
    validate_mechanism_mapping,
    validate_population_power_evidence,
    validate_runtime_preflight,
)
from agentmembrane.host_v2.schema import IntegrityError, canonical_json_bytes, sha256_bytes
from agentmembrane.host_v2.taskpacks import (
    load_taskpack,
    taskpack_content_sha256,
    verify_taskpack,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
PACKS_ROOT = REPO_ROOT / "data/host_boundary_v2/packs"
FAKE_SHA = "a" * 64


def _task(
    task_id: str,
    *,
    protocol_split: str,
    source_task_id: str | None = None,
    initial_state_sha256: str | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        task_id=task_id,
        cluster_id=f"cluster:{task_id}",
        split="formal" if protocol_split == "formal" else "gate",
        oracle_ref=f"oracles/{task_id}.json",
        metadata={
            "protocol_split": protocol_split,
            "source_task_id": source_task_id or f"source:{task_id}",
            "initial_state_sha256": initial_state_sha256
            or sha256_bytes(task_id.encode("utf-8")),
        },
    )


def _pack(tasks: list[SimpleNamespace], pack_id: str = "fixture-public-pack") -> SimpleNamespace:
    return SimpleNamespace(pack_id=pack_id, tasks=tuple(tasks), root=REPO_ROOT)


def _review() -> dict:
    return {
        "reviewer_id": "independent-reviewer-fixture",
        "reviewed_at": "2026-08-30T00:00:00Z",
        "independent_from_mapping_author": True,
        "method": "unit contract fixture",
        "decision": "approved",
    }


def _mapping(pack: SimpleNamespace) -> dict:
    rows = []
    mechanisms = sorted(HOST_ACTION_MECHANISMS)
    for index, task in enumerate(pack.tasks):
        formal = task.metadata["protocol_split"] == "formal"
        rows.append(
            {
                "task_id": task.task_id,
                "source_workflow_id": task.metadata["source_task_id"],
                "status": "mapped" if formal else "excluded",
                "mechanisms": mechanisms[:2] if formal else [],
                "rationale": "Frozen trusted route evidence reviewed for the unit fixture.",
                "evidence_refs": [f"evidence:{task.task_id}"],
            }
        )
    return {
        "schema_version": 1,
        "artifact_type": "agentmembrane_public_mechanism_mapping",
        "mapping_id": "fixture-mapping-v1",
        "pack_id": pack.pack_id,
        "taskpack_content_sha256": FAKE_SHA,
        "construct_id": "host_mediated_capability_exploitation",
        "proposal_alignment": "RQ1b_host_mediated",
        "answers_canonical_proposal_rq2": False,
        "pooling_with_semantic_rq2_permitted": False,
        "benchmark": "fixture",
        "upstream_version_or_commit": "fixture@pinned",
        "definitions_sha256": "b" * 64,
        "review": _review(),
        "rows": rows,
    }


def _parity_pack() -> SimpleNamespace:
    return _pack([_task(f"formal-{index:02d}", protocol_split="formal") for index in range(20)])


def _parity(pack: SimpleNamespace, evidence_root: Path) -> dict:
    task_ids = [task.task_id for task in pack.tasks]
    categories = sorted(REQUIRED_PARITY_CATEGORIES)
    traces = []
    for index, task_id in enumerate(task_ids):
        category = categories[index % len(categories)]
        traces.append(
            {
                "trace_id": f"trace-{index:02d}",
                "task_id": task_id,
                "source_task_id": pack.tasks[index].metadata["source_task_id"],
                "case_category": category,
                "trace_sha256": sha256_bytes(f"trace:{index}".encode()),
                "upstream_input_sha256": sha256_bytes(f"input:{index}".encode()),
                "native_output_sha256": sha256_bytes(f"native:{index}".encode()),
                "projected_output_sha256": sha256_bytes(f"projection:{index}".encode()),
                "utility_native": index % 2 == 0,
                "utility_adapter": index % 2 == 0,
                "security_native": index % 3 == 0,
                "security_adapter": index % 3 == 0,
                "matches": True,
                "cleanup_state_sha256": sha256_bytes(f"cleanup:{index}".encode()),
                "cleanup_succeeded": True,
            }
        )
    parity_id = "fixture-parity-v1"
    generated_at = "2026-08-30T00:00:00Z"
    namespace = "fixture-parity-namespace"
    reservation = {
        "schema_version": 1,
        "artifact_type": "agentmembrane_public_checker_parity_namespace_reservation",
        "reservation_id": f"{parity_id}:{namespace}",
        "namespace": namespace,
        "parity_id": parity_id,
        "pack_id": pack.pack_id,
        "adapter_id": "fixture-adapter",
        "generated_at": generated_at,
    }
    reservation_bytes = canonical_json_bytes(reservation)
    reservation_path = evidence_root / namespace / "reservation.json"
    reservation_path.parent.mkdir(parents=True, exist_ok=True)
    reservation_path.write_bytes(reservation_bytes)
    return {
        "schema_version": 1,
        "artifact_type": "agentmembrane_public_checker_parity",
        "parity_id": parity_id,
        "pack_id": pack.pack_id,
        "taskpack_content_sha256": FAKE_SHA,
        "adapter_id": "fixture-adapter",
        "adapter_implementation_sha256": "c" * 64,
        "runtime_preflight_sha256": "e" * 64,
        "namespace_reservation": {
            "path": f"{namespace}/reservation.json",
            "sha256": sha256_bytes(reservation_bytes),
        },
        "upstream_version_or_commit": "fixture@pinned",
        "checker_bindings": [
            {
                "binding_id": "fixture-native-checkers",
                "callable_ref": "fixture.checkers:evaluate",
                "source_path": "fixture/checkers.py",
                "source_sha256": "d" * 64,
            }
        ],
        "attack_semantics": "native_upstream_security_checker",
        "generated_at": generated_at,
        "held_out_task_ids": task_ids,
        "case_categories": categories,
        "traces": traces,
        "summary": {
            "trace_count": len(traces),
            "match_count": len(traces),
            "agreement": 1.0,
            "distinct_source_task_count": len(
                {task.metadata["source_task_id"] for task in pack.tasks}
            ),
            "required_categories_covered": True,
            "formal_tasks_covered": True,
            "cleanup_complete": True,
            "decision": "PASS",
        },
    }


def _validate_parity(
    artifact: dict,
    *,
    pack: SimpleNamespace,
    evidence_root: Path,
) -> dict:
    return validate_checker_parity_report(
        artifact,
        pack=pack,
        taskpack_sha256=FAKE_SHA,
        adapter_id="fixture-adapter",
        implementation_sha256="c" * 64,
        runtime_preflight_sha256="e" * 64,
        runtime_checker_bindings=artifact["checker_bindings"],
        evidence_root=evidence_root,
    )


class _ConcreteFixtureAdapter(PublicBenchmarkAdapter):
    adapter_id = "fixture-adapter"
    benchmark = "fixture"
    upstream_version_or_commit = "fixture@pinned"

    def reset(self, source_task_id):
        return {"source_task_id": source_task_id}

    def dispatch_native_action(self, action):
        return dict(action)

    def project_trusted_events(self, native_trace):
        return tuple(native_trace)

    def evaluate_native_checkers(self, *, source_task_id, native_trace, terminal_state):
        raise AssertionError("unit registration must not execute a checker")

    def cleanup(self):
        return FAKE_SHA


class PublicAdapterContractTests(unittest.TestCase):
    def test_abstract_or_missing_adapter_cannot_be_registered(self) -> None:
        registry = PublicAdapterRegistry()
        with self.assertRaisesRegex(IntegrityError, "abstract"):
            registry.register(PublicBenchmarkAdapter)
        self.assertEqual(registry.descriptors(), ())

    def test_concrete_registration_is_bound_to_source_bytes(self) -> None:
        registry = PublicAdapterRegistry()
        descriptor = registry.register(_ConcreteFixtureAdapter)
        self.assertEqual(descriptor.adapter_id, "fixture-adapter")
        self.assertEqual(descriptor.contract_version, ADAPTER_CONTRACT_VERSION)
        self.assertEqual(len(descriptor.implementation_sha256), 64)
        self.assertEqual(registry.get("fixture-adapter"), descriptor)


class PublicArtifactValidatorTests(unittest.TestCase):
    def test_population_power_is_derived_from_pilot_q_and_pack_clusters(self) -> None:
        pilot = [_task(f"pilot-{index:02d}", protocol_split="pilot") for index in range(20)]
        formal = [
            _task(f"formal-{index:02d}", protocol_split="formal")
            for index in range(60)
        ]
        pack = _pack([*pilot, *formal])
        artifact = {
            "schema_version": 1,
            "artifact_type": "agentmembrane_public_population_power_evidence",
            "power_evidence_id": "fixture-power-v1",
            "pack_id": pack.pack_id,
            "taskpack_content_sha256": FAKE_SHA,
            "power_contract_id": "hb-hcer-power-v2.1-q030-60-100",
            "pilot_cluster_ids": sorted(task.cluster_id for task in pilot),
            "pilot_evaluable_clusters": 20,
            "pilot_discordant_clusters": 6,
            "discordance_q": 0.30,
            "discordance_threshold": 0.30,
            "minimum_formal_clusters_if_q_at_or_below_threshold": 60,
            "minimum_formal_clusters_if_q_above_threshold": 100,
            "formal_cluster_ids": sorted(task.cluster_id for task in formal),
            "review": _review(),
            "decision": "PASS",
        }
        report = validate_population_power_evidence(
            artifact, pack=pack, taskpack_sha256=FAKE_SHA
        )
        self.assertEqual(report["required_formal_cluster_count"], 60)
        high_q = deepcopy(artifact)
        high_q["pilot_discordant_clusters"] = 7
        high_q["discordance_q"] = 0.35
        with self.assertRaisesRegex(IntegrityError, "requires 100 formal clusters"):
            validate_population_power_evidence(
                high_q, pack=pack, taskpack_sha256=FAKE_SHA
            )

    def test_live_checker_source_is_checkout_bound_not_packaged_raw_bound(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        checkout = Path(temporary.name)
        checker = checkout / "src/tau2/evaluator/checker.py"
        checker.parent.mkdir(parents=True)
        checker.write_text("def evaluate():\n    return True\n", encoding="utf-8")
        source_sha = sha256_bytes(checker.read_bytes())
        descriptor = SimpleNamespace(
            adapter_id="fixture-adapter",
            benchmark="tau2-bench",
            upstream_version_or_commit="1.0.1@pinned-commit",
            contract_version=ADAPTER_CONTRACT_VERSION,
            implementation_sha256="c" * 64,
        )
        pack = SimpleNamespace(
            manifest={
                "upstream": {
                    "name": "tau2-bench",
                    "version_or_commit": "1.0.1@pinned-commit",
                    "raw_files": [],
                }
            }
        )
        preflight = {
            "schema_version": 1,
            "artifact_type": "agentmembrane_public_adapter_runtime_preflight",
            "adapter_id": "fixture-adapter",
            "benchmark": "tau2-bench",
            "upstream_version_or_commit": "1.0.1@pinned-commit",
            "contract_version": ADAPTER_CONTRACT_VERSION,
            "implementation_sha256": "c" * 64,
            "upstream_checkout_path": str(checkout),
            "upstream_head": "pinned-commit",
            "python_executable": "/fixture/python3.12",
            "python_version": "3.12.0",
            "required_python": ">=3.12",
            "dependencies": [
                {"module": "tau2", "available": True, "version": "1.0.1"}
            ],
            "checker_bindings": [
                {
                    "binding_id": "tau2-native-evaluator",
                    "callable_ref": "tau2.evaluator.checker:evaluate",
                    "source_path": "src/tau2/evaluator/checker.py",
                    "source_sha256": source_sha,
                }
            ],
            "checks": {"exact_head": True, "native_import": True},
            "blockers": [],
            "executable": True,
        }
        result = validate_runtime_preflight(
            preflight, descriptor=descriptor, pack=pack
        )
        self.assertEqual(
            result["checker_binding_ids"], ["tau2-native-evaluator"]
        )
        checker.write_text("def evaluate():\n    return False\n", encoding="utf-8")
        with self.assertRaisesRegex(IntegrityError, "source SHA-256 mismatch"):
            validate_runtime_preflight(preflight, descriptor=descriptor, pack=pack)

    def test_mapping_allows_multiple_mechanisms_but_not_zero_for_formal(self) -> None:
        pack = _pack(
            [
                _task("formal", protocol_split="formal"),
                _task("gate", protocol_split="G0"),
            ]
        )
        artifact = _mapping(pack)
        report = validate_mechanism_mapping(
            artifact, pack=pack, taskpack_sha256=FAKE_SHA
        )
        self.assertEqual(report["formal_task_count"], 1)
        formal = next(row for row in artifact["rows"] if row["task_id"] == "formal")
        formal["mechanisms"] = []
        with self.assertRaisesRegex(IntegrityError, "zero mechanisms"):
            validate_mechanism_mapping(artifact, pack=pack, taskpack_sha256=FAKE_SHA)

    def test_mapping_requires_complete_independently_reviewed_coverage(self) -> None:
        pack = _pack(
            [
                _task("formal", protocol_split="formal"),
                _task("gate", protocol_split="G0"),
            ]
        )
        artifact = _mapping(pack)
        artifact["rows"].pop()
        with self.assertRaisesRegex(IntegrityError, "omits task IDs"):
            validate_mechanism_mapping(artifact, pack=pack, taskpack_sha256=FAKE_SHA)
        artifact = _mapping(pack)
        artifact["review"]["independent_from_mapping_author"] = False
        with self.assertRaisesRegex(IntegrityError, "independent review"):
            validate_mechanism_mapping(artifact, pack=pack, taskpack_sha256=FAKE_SHA)

    def test_parity_requires_20_tasks_all_categories_and_exact_agreement(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        evidence_root = Path(temporary.name)
        pack = _parity_pack()
        artifact = _parity(pack, evidence_root)
        report = _validate_parity(artifact, pack=pack, evidence_root=evidence_root)
        self.assertEqual(report["held_out_task_count"], 20)
        self.assertEqual(report["trace_count"], 20)

        mismatch = deepcopy(artifact)
        mismatch["traces"][0]["utility_adapter"] = not mismatch["traces"][0][
            "utility_native"
        ]
        mismatch["traces"][0]["matches"] = False
        with self.assertRaisesRegex(IntegrityError, "parity mismatch"):
            _validate_parity(mismatch, pack=pack, evidence_root=evidence_root)

        missing_category = deepcopy(artifact)
        missing_category["case_categories"].remove("wrong_order")
        for trace in missing_category["traces"]:
            if trace["case_category"] == "wrong_order":
                trace["case_category"] = "positive"
        with self.assertRaisesRegex(IntegrityError, "lacks required case categories"):
            _validate_parity(missing_category, pack=pack, evidence_root=evidence_root)

        only_nineteen = _pack(list(pack.tasks[:-1]))
        short = _parity(only_nineteen, evidence_root)
        with self.assertRaisesRegex(IntegrityError, "at least 20"):
            _validate_parity(short, pack=only_nineteen, evidence_root=evidence_root)

        paired_tasks = [
            _task(
                f"paired-{index:02d}",
                protocol_split="formal",
                source_task_id=f"source-{index // 2:02d}",
            )
            for index in range(20)
        ]
        paired_pack = _pack(paired_tasks)
        inflated = _parity(paired_pack, evidence_root)
        with self.assertRaisesRegex(IntegrityError, "distinct upstream source tasks"):
            _validate_parity(inflated, pack=paired_pack, evidence_root=evidence_root)

    def test_formal_split_evidence_is_derived_and_overlap_fails(self) -> None:
        split_names = ["train", "G0", "G1", "G2", "pilot", "formal"]
        tasks = [_task(name, protocol_split=name) for name in split_names]
        pack = _pack(tasks)
        by_split = {task.metadata["protocol_split"]: task for task in tasks}
        formal = by_split["formal"]
        nonformal = [task for task in tasks if task is not formal]
        artifact = {
            "schema_version": 1,
            "artifact_type": "agentmembrane_public_formal_split_evidence",
            "split_id": "fixture-split-v1",
            "pack_id": pack.pack_id,
            "taskpack_content_sha256": FAKE_SHA,
            "formal_task_ids": ["formal"],
            "formal_source_task_ids": [formal.metadata["source_task_id"]],
            "formal_initial_state_sha256s": [formal.metadata["initial_state_sha256"]],
            "nonformal_source_task_ids_sha256": sha256_bytes(
                canonical_json_bytes(
                    sorted(task.metadata["source_task_id"] for task in nonformal)
                )
            ),
            "nonformal_initial_state_sha256s_sha256": sha256_bytes(
                canonical_json_bytes(
                    sorted(task.metadata["initial_state_sha256"] for task in nonformal)
                )
            ),
            "source_task_disjoint": True,
            "initial_state_graph_disjoint": True,
            "split_names": split_names,
            "split_task_ids": {
                name: [by_split[name].task_id] for name in split_names
            },
            "split_source_task_ids": {
                name: [by_split[name].metadata["source_task_id"]]
                for name in split_names
            },
            "split_initial_state_sha256s": {
                name: [by_split[name].metadata["initial_state_sha256"]]
                for name in split_names
            },
            "split_cluster_ids": {
                name: [by_split[name].cluster_id] for name in split_names
            },
            "all_pairwise_task_disjoint": True,
            "all_pairwise_source_task_disjoint": True,
            "all_pairwise_initial_state_graph_disjoint": True,
            "all_pairwise_cluster_disjoint": True,
            "g2_cost_resolved": True,
            "review": _review(),
        }
        self.assertEqual(
            validate_formal_split_evidence(
                artifact, pack=pack, taskpack_sha256=FAKE_SHA
            )["formal_task_count"],
            1,
        )
        by_split["G0"].metadata["initial_state_sha256"] = formal.metadata[
            "initial_state_sha256"
        ]
        with self.assertRaisesRegex(IntegrityError, "hash mismatch|overlap"):
            validate_formal_split_evidence(
                artifact, pack=pack, taskpack_sha256=FAKE_SHA
            )


class CurrentPublicPackReadinessTests(unittest.TestCase):
    def test_frozen_diagnostic_overlay_is_consumed_only_as_no_go(self) -> None:
        overlay = REPO_ROOT / "experiments/host_boundary_v2/public_readiness_v2.1"
        manifest_sha = "cd5a2f661f9247bb4e6541c0134387cba1faa19801e067031261b7b288c95d6d"
        for directory in ("agentdojo-v0.1.35-v1", "tau2-v1.0.1"):
            with self.subTest(directory=directory):
                pack = load_taskpack(PACKS_ROOT / directory)
                report = audit_public_readiness(
                    pack,
                    taskpack_sha256=taskpack_content_sha256(pack),
                    evidence_root=overlay.resolve(),
                    evidence_manifest_sha256=manifest_sha,
                )
                self.assertFalse(report["ready"])
                self.assertEqual(report["evidence_mode"], "diagnostic_overlay")
                self.assertTrue(
                    {
                        "ADAPTER_RUNTIME_PREFLIGHT_MISSING",
                        "PARITY_REPORT_MISSING",
                        "MECHANISM_MAPPING_UNREVIEWED",
                        "FORMAL_SPLIT_DIAGNOSTIC_NO_GO",
                        "POPULATION_POWER_DIAGNOSTIC_NO_GO",
                        "DIAGNOSTIC_OVERLAY_NO_GO",
                    }.issubset(set(report["blocker_codes"])),
                    report,
                )

    def test_raw_pass_manifest_cannot_replace_recomputed_readiness(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        evidence_root = Path(temporary.name).resolve()
        readiness_path = evidence_root / "readiness/public_readiness.json"
        readiness_path.parent.mkdir(parents=True)
        pack = load_taskpack(PACKS_ROOT / "agentdojo-v0.1.35-v1")
        content_sha = taskpack_content_sha256(pack)
        forged = {
            "schema_version": 1,
            "artifact_type": "agentmembrane_public_readiness",
            "pack_id": pack.pack_id,
            "taskpack_content_sha256": content_sha,
            "adapter_binding": {
                "adapter_id": "forged",
                "benchmark": "AgentDojo",
                "upstream_version_or_commit": pack.manifest["upstream"][
                    "version_or_commit"
                ],
                "contract_version": ADAPTER_CONTRACT_VERSION,
                "entrypoint": "forged:Adapter",
                "implementation_sha256": "f" * 64,
            },
            "checker_parity": {"path": "missing-parity.json", "sha256": "a" * 64},
            "mechanism_mapping": {"path": "missing-map.json", "sha256": "b" * 64},
            "formal_split_evidence": {"path": "missing-split.json", "sha256": "c" * 64},
            "decision": "PASS",
            "claim_eligible": True,
        }
        payload = canonical_json_bytes(forged)
        readiness_path.write_bytes(payload)
        report = audit_public_readiness(
            pack,
            taskpack_sha256=content_sha,
            evidence_root=evidence_root,
            evidence_manifest_sha256=sha256_bytes(payload),
        )
        self.assertFalse(report["ready"])
        self.assertIn("ADAPTER_BINDING_INVALID", report["blocker_codes"])
        self.assertIn("ADAPTER_RUNTIME_PREFLIGHT_INVALID", report["blocker_codes"])
        self.assertIn("POPULATION_POWER_EVIDENCE_INVALID", report["blocker_codes"])

    def test_current_public_packs_report_every_wave_one_blocker(self) -> None:
        required = {
            "ADAPTER_BINDING_MISSING",
            "PARITY_REPORT_MISSING",
            "MECHANISM_MAPPING_MISSING",
            "FORMAL_SPLIT_EMPTY",
            "ORACLE_REFERENCE_ONLY_SCHEMA_V1",
        }
        for directory in ("agentdojo-v0.1.35-v1", "tau2-v1.0.1"):
            with self.subTest(directory=directory):
                pack = load_taskpack(PACKS_ROOT / directory)
                content_sha = taskpack_content_sha256(pack)
                report = audit_public_readiness(pack, taskpack_sha256=content_sha)
                self.assertFalse(report["ready"])
                self.assertTrue(required.issubset(set(report["blocker_codes"])), report)
                with self.assertRaisesRegex(IntegrityError, "not claim ready"):
                    require_public_readiness(pack, taskpack_sha256=content_sha)

    def test_taskpack_report_cannot_flip_population_claim_eligibility(self) -> None:
        for directory in ("agentdojo-v0.1.35-v1", "tau2-v1.0.1"):
            pack = load_taskpack(PACKS_ROOT / directory)
            report = verify_taskpack(pack)
            self.assertTrue(report["valid"], report)
            self.assertFalse(report["claim_eligible"])
            self.assertFalse(report["population_claim_eligible"])
            self.assertFalse(report["public_readiness"]["ready"])

    def test_committed_schema_scaffolds_are_strict_json_objects(self) -> None:
        expected = {
            "public-mechanism-mapping-v1.schema.json": "agentmembrane://host-v2/public-mechanism-mapping-v1",
            "public-checker-parity-v1.schema.json": "agentmembrane://host-v2/public-checker-parity-v1",
            "public-readiness-v1.schema.json": "agentmembrane://host-v2/public-readiness-v1",
            "public-formal-split-evidence-v1.schema.json": "agentmembrane://host-v2/public-formal-split-evidence-v1",
        }
        root = REPO_ROOT / "data/host_boundary_v2/schemas"
        for filename, schema_id in expected.items():
            with self.subTest(filename=filename):
                value = json.loads((root / filename).read_text(encoding="utf-8"))
                self.assertEqual(value["$id"], schema_id)
                self.assertFalse(value["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
