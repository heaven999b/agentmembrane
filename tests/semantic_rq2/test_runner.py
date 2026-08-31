from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agentmembrane.proxy import Completion
from agentmembrane.semantic_rq2.profile import offline_preflight
from agentmembrane.semantic_rq2.runner import (
    AuditedCachedJsonModel,
    RoleModels,
    run_experiment,
    validate_record_matrix,
)
from tests.semantic_rq2.fixtures import write_synthetic_manifest


ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "experiments/semantic_receptor_rq2/profiles/engineering_baseline.json"


def request_from(user: str) -> dict:
    return json.loads(user.split("REQUEST=", 1)[1].split("\nThe prior response", 1)[0])


class ScriptedModel:
    def __init__(self, model: str, role: str):
        self.model = model
        self.role = role
        self.calls = 0

    def ask(self, *, key: str, system: str, user: str, max_tokens: int) -> dict:
        self.calls += 1
        request = request_from(user)
        if self.role == "generator":
            fixed = request["fixed_fields"]
            receptor = fixed["receptor"]
            first_id = request["case"]["evidence_packet"][0]["id"]
            if receptor.startswith("R0_"):
                payload = {"evidence_ids": [first_id]}
            elif receptor.startswith("R1_"):
                payload = {
                    "evidence_ids": [first_id],
                    "annotations": [{"evidence_id": first_id, "relevance": 0.8, "confidence": "high"}],
                }
            elif receptor.startswith("R2_"):
                payload = {"evidence_ids": [first_id], "inference": "The clause is relevant.", "uncertainty": "medium"}
            elif receptor.startswith("R3_"):
                payload = {
                    "evidence_ids": [first_id],
                    "inference": "The clause is relevant.",
                    "uncertainty": "medium",
                    "conclusion": "The condition matters.",
                    "recommendation": "Use the condition in the decision.",
                }
            else:
                payload = {"artifact_text": "A fact-grounded report."}
            return fixed | {"payload": payload}
        if self.role == "surrogate":
            count = len(request["candidates"])
            return {"selected_candidate_index": 0, "ranking": list(range(count)), "reason": "scripted"}
        if self.role == "auditor":
            item = request["audit_item"]
            payload = item["artifact_payload"]
            if "artifact_text" in payload:
                directness = "D3"
            elif "recommendation" in payload:
                directness = "D3"
            elif "inference" in payload:
                directness = "D2"
            elif "annotations" in payload:
                directness = "D1"
            else:
                directness = "D0"
            return {
                "opaque_artifact_id": item["opaque_artifact_id"],
                "fact_valid": True,
                "qualifier_integrity": True,
                "no_evidence_denial": True,
                "no_control_instruction": True,
                "directness": directness,
                "supported_evidence_ids": [],
                "atomic_proposition_count": 1,
                "notes": "scripted",
            }
        if self.role == "downstream":
            memory = request["decision_input"]["persistent_memory"]
            label = "Entailment"
            if memory and "explicit_recommendation" in memory[0]:
                label = memory[0]["explicit_recommendation"]
            return {"label": label, "confidence": "medium", "cited_evidence_ids": [], "rationale": "scripted"}
        raise AssertionError(self.role)

    def usage(self) -> dict[str, int]:
        return {"new_calls": self.calls, "cache_hits": 0, "input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "latency_ms": 0}


class RunnerTests(unittest.TestCase):
    def test_engineering_preflight_passes_but_formal_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = write_synthetic_manifest(Path(directory))
            engineering = offline_preflight(manifest_path=manifest, profile_path=PROFILE, formal=False)
            formal = offline_preflight(manifest_path=manifest, profile_path=PROFILE, formal=True)
            self.assertEqual(engineering["status"], "PASS")
            self.assertEqual(formal["status"], "FAIL")
            self.assertTrue(any("execution_class_not_formal" in problem for problem in formal["problems"]))

    def test_zero_token_end_to_end_two_case_canary(self) -> None:
        roles = RoleModels(
            generator=ScriptedModel("scripted-generator", "generator"),
            surrogate=ScriptedModel("scripted-surrogate", "surrogate"),
            auditor=ScriptedModel("scripted-auditor", "auditor"),
            downstreams={"scripted-victim": ScriptedModel("scripted-victim", "downstream")},
        )
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            manifest = write_synthetic_manifest(directory_path)
            run_dir = directory_path / "run"
            result = run_experiment(
                manifest_path=manifest,
                profile_path=PROFILE,
                run_dir=run_dir,
                seed=20260831,
                formal=False,
                max_cases=2,
                models=roles,
            )
            self.assertEqual(result["case_n"], 2)
            self.assertFalse(result["claim_bearing"])
            self.assertEqual(result["generation_receipt"]["status"], "PASS")
            records = (run_dir / "records.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(records), 2 * 12)
            self.assertTrue((run_dir / "results.json").is_file())
            self.assertTrue((run_dir / "report.md").is_file())
            integrity = json.loads(
                (run_dir / "evaluation" / "integrity.json").read_text(encoding="utf-8")
            )
            self.assertEqual(integrity["status"], "PASS")
            self.assertEqual(integrity["arm_n_per_case"], 12)

    def test_role_cache_retains_raw_request_response_and_usage(self) -> None:
        class FakeClient:
            calls = 0

            def complete(self, **kwargs):
                self.calls += 1
                return Completion(
                    text='{"ok":true}',
                    model=kwargs["model"],
                    latency_ms=7,
                    input_tokens=3,
                    output_tokens=2,
                    total_tokens=5,
                )

        with tempfile.TemporaryDirectory() as directory:
            client = FakeClient()
            model = AuditedCachedJsonModel(
                client, "fake-model", Path(directory), transport_retries=1
            )
            first = model.ask(key="step", system="system", user="user", max_tokens=20)
            second = model.ask(key="step", system="system", user="user", max_tokens=20)
            self.assertEqual(first, {"ok": True})
            self.assertEqual(second, first)
            self.assertEqual(client.calls, 1)
            cache = json.loads((Path(directory) / "step.json").read_text(encoding="utf-8"))
            self.assertEqual(cache["request"]["user"], "user")
            self.assertEqual(cache["raw_response"], '{"ok":true}')
            self.assertEqual(cache["parsed_payload"], {"ok": True})
            self.assertEqual(cache["usage"]["total_tokens"], 5)
            usage = model.usage()
            self.assertEqual(usage["persisted_completed_calls"], 1)
            self.assertEqual(usage["persisted_failed_calls"], 0)
            self.assertEqual(usage["persisted_total_tokens"], 5)

            resumed = AuditedCachedJsonModel(
                client, "fake-model", Path(directory), transport_retries=1
            )
            self.assertEqual(
                resumed.ask(key="step", system="system", user="user", max_tokens=20),
                {"ok": True},
            )
            resumed_usage = resumed.usage()
            self.assertEqual(resumed_usage["new_calls"], 0)
            self.assertEqual(resumed_usage["cache_hits"], 1)
            self.assertEqual(resumed_usage["persisted_completed_calls"], 1)
            self.assertEqual(resumed_usage["persisted_total_tokens"], 5)

    def test_record_matrix_gate_detects_missing_arm(self) -> None:
        cases = [{"case_id": "case-1"}]
        rows = [
            {
                "downstream_id": "victim",
                "case_id": "case-1",
                "arm_id": "E_evidence_only",
                "seed": 7,
                "packet_identity_ok": True,
            }
        ]
        result = validate_record_matrix(
            rows, cases=cases, downstream_ids=["victim"], seed=7
        )
        self.assertEqual(result["status"], "FAIL")
        self.assertTrue(any(problem.startswith("missing_matrix_cells:") for problem in result["problems"]))


if __name__ == "__main__":
    unittest.main()
