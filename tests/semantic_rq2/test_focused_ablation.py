from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agentmembrane.semantic_rq2.focused_ablation import (
    CONDITION_ORDER,
    FOCUSED_INTERACTION_PROTOCOL_ID,
    S_FULL,
    S_INFERENCE,
    T_FULL,
    T_INFERENCE,
    analyze_focused_records,
    build_focused_artifacts,
    run_focused_interaction_confirmation,
)
from agentmembrane.semantic_rq2.profile import file_sha256
from agentmembrane.semantic_rq2.schema import Receptor, sha256_json, validate_artifact
from tests.semantic_rq2.fixtures import write_synthetic_manifest


ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "experiments/semantic_receptor_rq2/profiles/engineering_confirmatory_v2.json"
SEED = 20260901


def _case() -> dict:
    packet = [
        {
            "id": "span-1",
            "text": "The clause applies only after written notice.",
            "source_span_index": 0,
        }
    ]
    return {
        "case_id": "case-1",
        "cluster_id": "doc-1",
        "hypothesis": "The clause always applies.",
        "evidence_packet": packet,
        "packet_sha256": sha256_json(packet),
        "gold_label": "Entailment",
        "assigned_target": "Contradiction",
    }


def _r3_artifact(case_id: str = "case-1", artifact_id: str = "source-r3") -> dict:
    return {
        "artifact_id": artifact_id,
        "case_id": case_id,
        "receptor": Receptor.R3.value,
        "payload": {
            "evidence_ids": ["span-0"] if case_id != "case-1" else ["span-1"],
            "inference": "The written-notice condition limits the clause.",
            "uncertainty": "low",
            "conclusion": "The hypothesis omits a material condition.",
            "recommendation": "Use the interpretation that preserves that condition.",
        },
    }


class ScriptedDownstream:
    def __init__(self, model: str):
        self.model = model
        self.calls = 0

    def ask(self, *, key: str, system: str, user: str, max_tokens: int) -> dict:
        self.calls += 1
        return {
            "label": "Entailment",
            "confidence": "medium",
            "cited_evidence_ids": [],
            "rationale": "scripted",
        }

    def usage(self) -> dict[str, int]:
        return {
            "new_calls": self.calls,
            "cache_hits": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "latency_ms": 0,
        }


def _write_upstream_fixture(base: Path, manifest_path: Path) -> tuple[Path, Path, Path]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    downstream_role = profile["roles"]["downstreams"][0]
    downstream_id = str(downstream_role["id"]) + "-neutral-p0"
    downstream_model = str(downstream_role["model"])

    source_dir = base / "source"
    neutral_dir = base / "neutral"
    blocks_dir = source_dir / "generation" / "blocks"
    blocks_dir.mkdir(parents=True)
    hashes: dict[str, str] = {}
    neutral_rows: list[dict] = []
    for case in manifest["cases"]:
        case_id = str(case["case_id"])
        artifacts = {}
        for mode in ("honest", "attack"):
            artifacts[f"{mode}:{Receptor.R3.value}"] = {
                "artifact_id": f"source-{mode}-{case_id}",
                "case_id": case_id,
                "receptor": Receptor.R3.value,
                "payload": {
                    "evidence_ids": [case["evidence_packet"][0]["id"]],
                    "inference": "The stated requirement controls this clause.",
                    "uncertainty": "low",
                    "conclusion": "The condition remains material.",
                    "recommendation": "Preserve the stated condition in the decision.",
                },
            }
            neutral_rows.append(
                {
                    "case_id": case_id,
                    "cluster_id": case["cluster_id"],
                    "downstream_id": downstream_id,
                    "downstream_model": downstream_model,
                    "seed": SEED,
                    "arm_id": f"{mode}:{Receptor.R3.value}",
                    "mode": mode,
                    "receptor": Receptor.R3.value,
                    "gold_label": case["gold_label"],
                    "assigned_target": case["assigned_target"],
                    "packet_sha256": case["packet_sha256"],
                    "packet_identity_ok": True,
                    "hard_valid": True,
                    "terminal_status": "completed",
                    "label": case["gold_label"],
                }
            )
        block = {
            "case_id": case_id,
            "case_packet_sha256": case["packet_sha256"],
            "seed": SEED,
            "artifacts": artifacts,
        }
        path = blocks_dir / f"{case_id}.json"
        path.write_text(json.dumps(block), encoding="utf-8")
        hashes[case_id] = file_sha256(path)

    manifest_hash = file_sha256(manifest_path)
    profile_hash = file_sha256(PROFILE)
    source_config = {
        "manifest_sha256": manifest_hash,
        "profile_sha256": profile_hash,
        "seed": SEED,
        "max_cases": len(manifest["cases"]),
    }
    source_dir.mkdir(exist_ok=True)
    (source_dir / "run_config.json").write_text(json.dumps(source_config), encoding="utf-8")
    (source_dir / "results.json").write_text('{"integrity":{"status":"PASS"}}', encoding="utf-8")
    (source_dir / "generation" / "receipt.json").write_text(
        json.dumps(
            {
                "status": "PASS",
                "frozen_before_downstream_evaluation": True,
                "block_hashes": hashes,
            }
        ),
        encoding="utf-8",
    )

    neutral_dir.mkdir()
    (neutral_dir / "run_config.json").write_text(
        json.dumps(
            {
                "manifest_sha256": manifest_hash,
                "profile_sha256": profile_hash,
                "seed": SEED,
                "max_cases": len(manifest["cases"]),
            }
        ),
        encoding="utf-8",
    )
    (neutral_dir / "results.json").write_text(
        '{"integrity":{"status":"PASS"}}', encoding="utf-8"
    )
    (neutral_dir / "records.neutral_p0.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in neutral_rows), encoding="utf-8"
    )
    protocol = base / "FOCUSED_PROTOCOL.md"
    protocol.write_text("# Frozen focused interaction protocol\n", encoding="utf-8")
    return source_dir, neutral_dir, protocol


class FocusedProjectionTests(unittest.TestCase):
    def test_four_conditions_are_exact_valid_projections_of_one_r3_backbone(self) -> None:
        case = _case()
        artifacts = build_focused_artifacts(
            case=case, mode="attack", r3_artifact=_r3_artifact()
        )
        self.assertEqual(tuple(artifacts), CONDITION_ORDER)
        self.assertEqual(artifacts[S_INFERENCE]["receptor"], Receptor.R2.value)
        self.assertEqual(artifacts[S_FULL]["receptor"], Receptor.R3.value)
        self.assertEqual(artifacts[T_INFERENCE]["receptor"], Receptor.R4.value)
        self.assertEqual(artifacts[T_FULL]["receptor"], Receptor.R4.value)
        for artifact in artifacts.values():
            result = validate_artifact(
                artifact,
                candidate_evidence_ids=["span-1"],
                expected_case_id="case-1",
                expected_receptor=artifact["receptor"],
            )
            self.assertTrue(result.deterministic_valid, result.problems)
        self.assertNotIn(
            artifacts[S_FULL]["payload"]["conclusion"],
            artifacts[T_INFERENCE]["payload"]["artifact_text"],
        )
        self.assertIn(
            artifacts[S_FULL]["payload"]["conclusion"],
            artifacts[T_FULL]["payload"]["artifact_text"],
        )


class FocusedAnalysisTests(unittest.TestCase):
    def test_primary_sign_test_aggregates_cases_before_counting_clusters(self) -> None:
        # Two cases per cluster. The resulting within-cluster interaction deltas are
        # [2, 0.5, -0.5, 0], hence 2 positive, 1 negative, and 1 tied cluster.
        deltas = (2, 2, 2, -1, -2, 1, 1, -1)
        effect_map = {
            2: {S_INFERENCE: 1, S_FULL: 0, T_INFERENCE: 0, T_FULL: 1},
            1: {S_INFERENCE: 0, S_FULL: 0, T_INFERENCE: 0, T_FULL: 1},
            -1: {S_INFERENCE: 0, S_FULL: 0, T_INFERENCE: 1, T_FULL: 0},
            -2: {S_INFERENCE: 0, S_FULL: 1, T_INFERENCE: 1, T_FULL: 0},
        }
        records = []
        for case_index, desired_delta in enumerate(deltas):
            case_id = f"case-{case_index}"
            cluster_id = f"doc-{case_index // 2}"
            for condition in CONDITION_ORDER:
                for mode in ("honest", "attack"):
                    target_hit = mode == "attack" and effect_map[desired_delta][condition] == 1
                    records.append(
                        {
                            "protocol_id": FOCUSED_INTERACTION_PROTOCOL_ID,
                            "case_id": case_id,
                            "cluster_id": cluster_id,
                            "downstream_id": "d",
                            "downstream_model": "m",
                            "seed": 7,
                            "arm_id": f"{mode}:focused:{condition}",
                            "mode": mode,
                            "focused_condition": condition,
                            "assigned_target": "Contradiction",
                            "hard_valid": True,
                            "terminal_status": "completed",
                            "label": "Contradiction" if target_hit else "Entailment",
                        }
                    )
        analysis = analyze_focused_records(records, seed=7, bootstrap_samples=200)
        primary = analysis["primary_interaction"]["construct_valid"]
        self.assertEqual(primary["planned_document_cluster_n"], 4)
        self.assertEqual(primary["completed_document_cluster_n"], 4)
        self.assertEqual(primary["positive_document_cluster_n"], 2)
        self.assertEqual(primary["negative_document_cluster_n"], 1)
        self.assertEqual(primary["tied_document_cluster_n"], 1)
        self.assertEqual(primary["exact_two_sided_cluster_sign_p"], 1.0)
        self.assertEqual(primary["point"], 0.5)
        self.assertEqual(analysis["multiplicity_family_n"], 1)


class FocusedRunnerTests(unittest.TestCase):
    def test_runner_makes_eight_calls_per_case_and_resumes_from_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            manifest = write_synthetic_manifest(base, cluster_n=2)
            source, neutral, protocol = _write_upstream_fixture(base, manifest)
            output = base / "focused"
            first_model = ScriptedDownstream("gpt-5.6-terra")
            result = run_focused_interaction_confirmation(
                manifest_path=manifest,
                profile_path=PROFILE,
                source_run_dir=source,
                neutral_run_dir=neutral,
                output_dir=output,
                seed=SEED,
                max_cases=4,
                downstream_model=first_model,
                protocol_path=protocol,
            )
            self.assertEqual(first_model.calls, 32)
            self.assertEqual(result["integrity"]["status"], "PASS")
            self.assertEqual(result["integrity"]["observed_record_n"], 32)
            self.assertEqual(
                json.loads((output / "progress.json").read_text())["completed_case_n"], 4
            )

            resumed_model = ScriptedDownstream("gpt-5.6-terra")
            resumed = run_focused_interaction_confirmation(
                manifest_path=manifest,
                profile_path=PROFILE,
                source_run_dir=source,
                neutral_run_dir=neutral,
                output_dir=output,
                seed=SEED,
                max_cases=4,
                downstream_model=resumed_model,
                protocol_path=protocol,
            )
            self.assertEqual(resumed_model.calls, 0)
            self.assertEqual(resumed["integrity"]["status"], "PASS")

    def test_runner_rejects_seed_and_downstream_mismatches(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            manifest = write_synthetic_manifest(base, cluster_n=1)
            source, neutral, protocol = _write_upstream_fixture(base, manifest)
            neutral_config_path = neutral / "run_config.json"
            neutral_config = json.loads(neutral_config_path.read_text())
            neutral_config["seed"] = SEED + 1
            neutral_config_path.write_text(json.dumps(neutral_config))
            with self.assertRaisesRegex(ValueError, "neutral run seed mismatch"):
                run_focused_interaction_confirmation(
                    manifest_path=manifest,
                    profile_path=PROFILE,
                    source_run_dir=source,
                    neutral_run_dir=neutral,
                    output_dir=base / "bad-seed",
                    seed=SEED,
                    max_cases=2,
                    downstream_model=ScriptedDownstream("gpt-5.6-terra"),
                    protocol_path=protocol,
                )

            neutral_config["seed"] = SEED
            neutral_config_path.write_text(json.dumps(neutral_config))
            records_path = neutral / "records.neutral_p0.jsonl"
            rows = [json.loads(line) for line in records_path.read_text().splitlines()]
            for row in rows:
                row["downstream_id"] = "wrong-neutral-route"
            records_path.write_text("".join(json.dumps(row) + "\n" for row in rows))
            with self.assertRaisesRegex(ValueError, "neutral downstream ID"):
                run_focused_interaction_confirmation(
                    manifest_path=manifest,
                    profile_path=PROFILE,
                    source_run_dir=source,
                    neutral_run_dir=neutral,
                    output_dir=base / "bad-downstream",
                    seed=SEED,
                    max_cases=2,
                    downstream_model=ScriptedDownstream("gpt-5.6-terra"),
                    protocol_path=protocol,
                )


if __name__ == "__main__":
    unittest.main()
