"""Read real public engineering evidence; callback cases are software tests only."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.rq1_measurement_v1 import semantic_audit as audit
from agentmembrane.host_v2.rq1_measurement_v1.semantic_fields import digest


ROOT = Path(__file__).resolve().parents[2]
RUN = ROOT / "experiments/host_boundary_v2/rq1_collab_v1/live_readiness_20260907/implementations/rq1_measurement_v1_20260909/public-smoke-002/runs/workspace-user_task_26-H_E-low-honest-r0"
CONFIGS = [{"id": "fixture-a", "model": "engineering-fixture-a"},
           {"id": "fixture-b", "model": "engineering-fixture-b"}]


class AuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not RUN.is_dir():
            raise unittest.SkipTest("existing sealed public engineering run not installed")
        cls.anchor = json.loads((RUN / "execution-anchor.json").read_text())["execution_seal_sha256"]
        cls.data = audit.read_evidence(RUN / "execution", cls.anchor)

    def prepare(self, **kwargs):
        return audit.prepare_closed(RUN / "execution", self.anchor, **kwargs)

    def test_actual_sealed_source_no_judges_no_fake_votes_or_score_change(self):
        before = hashlib.sha256((RUN / "report.json").read_bytes()).hexdigest()
        plan = self.prepare()
        self.assertEqual(plan["model_calls"], 0)
        self.assertEqual(plan["gold_lock"]["dataset_role"], "engineering")
        report = audit.execute_audit(plan)
        self.assertEqual(report["completion_invocations"], 0)
        self.assertIsNone(report["score_updates"])
        self.assertFalse(report["existing_scores_modified"])
        self.assertFalse(report["calibration_quality"]["certified"])
        self.assertFalse(report["semantic_accuracy_certified"])
        self.assertEqual(report["format_sensitivity"]["status"], "NOT_RUN")
        self.assertEqual(before, hashlib.sha256((RUN / "report.json").read_bytes()).hexdigest())
        filename = next(r for r in report["rows"] if r["field_type"] == "filename_claim")
        self.assertEqual(filename["source_window"]["output_text"], self.data["final_text"])
        self.assertEqual(filename["mechanical_gold"]["status"], "supported")
        self.assertEqual(filename["mechanical_gold"]["domain_id"], "filename_claim.closed_native_json_v1")

    def test_wrong_seal_and_tampered_plan_rejected(self):
        with self.assertRaisesRegex(ValueError, "seal_invalid"):
            audit.prepare_closed(RUN / "execution", "0" * 64)
        plan = self.prepare()
        plan["rows"][0]["reason"] = "tampered"
        with self.assertRaisesRegex(ValueError, "plan_changed"):
            audit.execute_audit(plan)
        plan["plan_sha256"] = digest({k: v for k, v in plan.items() if k != "plan_sha256"})
        with self.assertRaisesRegex(ValueError, "does_not_match_sealed_source"):
            audit.execute_audit(plan)

    def test_six_slots_failures_retained_and_not_replaced(self):
        plan = self.prepare(judge_configs=CONFIGS)
        calls = []
        def complete(packet):
            calls.append(copy.deepcopy(packet))
            if len(calls) in (2, 5):
                raise TimeoutError("not copied into artifact")
            return {"complete_or_ambiguous": "complete", "fields": []}
        entries = [{**c, "complete": complete} for c in CONFIGS]
        report = audit.execute_audit(plan, entries)
        self.assertEqual(len(calls), 6)
        self.assertEqual(report["completion_invocations"], 6)
        row = next(r for r in report["rows"] if r["field_type"] == "filename_claim")
        votes = row["phases"]["extract"]["votes"]
        self.assertEqual(len(votes), 6)
        self.assertEqual(sum(v["status"] == "invalid_or_failed" for v in votes), 2)
        self.assertTrue(all(p["phase"] == "extract" and "necessary_reference" not in p for p in calls))
        self.assertTrue(all("field_identity_rules" in p and p["closed_schema"]["required"] == ["filename"] for p in calls))

    def test_independent_gold_is_locked_before_twelve_phase_calls(self):
        # A local software counterexample, not rewritten research evidence.
        data = copy.deepcopy(self.data)
        fid, file = max(data["initial_snapshot"]["cloud_drive"]["files"].items(), key=lambda item: item[1]["size"])
        data["final_text"] = json.dumps({"records": [{"file_id": fid, "name": file["filename"]}]})
        with patch.object(audit, "read_evidence", return_value=data):
            plan = self.prepare(judge_configs=CONFIGS, match=True)
            self.assertEqual(len(plan["gold_lock"]["records"]), 1)
            self.assertTrue(plan["gold_lock"]["locked_before_predictions"])
            locked = digest(plan["gold_lock"])
            calls = []
            def complete(packet):
                self.assertEqual(digest(plan["gold_lock"]), locked)
                calls.append(packet)
                self.assertNotIn('"gold":', json.dumps(packet))
                self.assertIn("closed_schema", packet)
                self.assertIn("not_complete_or_repair", packet["schema_usage"])
                label = file["filename"] if packet["phase"] == "extract" else True
                return {"complete_or_ambiguous": "complete", "fields": [{"field_id": "record/0",
                    "value_or_label": label, "evidence_ids": [packet["evidence_id"]],
                    "source_spans": [{"start": 0, "end": len(data["final_text"]), "text": data["final_text"]}],
                    "rule_id": packet["rule_id"]}]}
            report = audit.execute_audit(plan, [{**c, "complete": complete} for c in CONFIGS])
        self.assertEqual(len(calls), 12)
        self.assertEqual(report["completion_invocations"], 12)
        self.assertEqual([p["phase"] for p in calls], ["extract"] * 6 + ["match"] * 6)
        self.assertFalse(report["calibration_quality"]["certified"])
        fnr = next(e for e in report["calibration_quality"]["endpoints"] if e["endpoint"] == "FNR")
        self.assertEqual((fnr["N"], fnr["errors"], fnr["unknown"]), (1, 0, 0))

    def test_mismatched_judge_is_rejected_before_any_call(self):
        plan = self.prepare(judge_configs=CONFIGS)
        def forbidden(_):
            self.fail("called a judge before checking its fixed configuration")
        entries = [{**c, "complete": forbidden} for c in CONFIGS]
        entries[0]["model"] = "unregistered-model"
        with self.assertRaisesRegex(ValueError, "callbacks_do_not_match"):
            audit.execute_audit(plan, entries)

    def test_match_cannot_hide_all_six_extraction_omissions(self):
        data = copy.deepcopy(self.data)
        fid, file = max(data["initial_snapshot"]["cloud_drive"]["files"].items(), key=lambda item: item[1]["size"])
        data["final_text"] = json.dumps({"records": [{"file_id": fid, "name": file["filename"]}]})
        with patch.object(audit, "read_evidence", return_value=data):
            plan = self.prepare(judge_configs=CONFIGS, match=True)
            def complete(packet):
                if packet["phase"] == "extract":
                    return {"complete_or_ambiguous": "complete", "fields": []}
                return {"complete_or_ambiguous": "complete", "fields": [{"field_id": "record/0",
                    "value_or_label": True, "evidence_ids": [packet["evidence_id"]],
                    "source_spans": [{"start": 0, "end": len(data["final_text"]), "text": data["final_text"]}],
                    "rule_id": packet["rule_id"]}]}
            report = audit.execute_audit(plan, [{**c, "complete": complete} for c in CONFIGS])
        fnr = next(e for e in report["calibration_quality"]["endpoints"] if e["endpoint"] == "FNR")
        self.assertEqual((fnr["N"], fnr["unknown"]), (1, 1))

    def test_necessary_reference_omits_irrelevant_private_fields(self):
        snapshot = {"cloud_drive": {"files": {"1": {"filename": "a", "size": 3,
                    "content": "not needed", "owner": "not needed", "shared_with": ["not needed"]}}}}
        gold = {"items": [{"source_pointer": "/cloud_drive/files/1"}]}
        reference = audit._necessary_reference("filename_claim", snapshot, {}, gold)
        self.assertNotIn("not needed", json.dumps(reference))
        self.assertEqual(set(reference["claim_sources"]["/cloud_drive/files/1"]), {"filename", "size"})

    def test_native_actual_json_does_not_request_missing_identity_or_records_wrapper(self):
        plan = self.prepare(judge_configs=CONFIGS)
        row = next(r for r in plan["rows"] if r["field_type"] == "filename_claim")
        original_text = row["window"]["output_text"]
        actual = json.loads(original_text)
        self.assertEqual(set(actual), {"filename"})
        def complete(packet):
            self.assertEqual(packet["closed_schema"]["required"], ["filename"])
            self.assertEqual(set(packet["closed_schema"]["properties"]), {"filename"})
            self.assertEqual(packet["output_text"], original_text)
            self.assertIn("json/filename", packet["field_identity_rules"])
            self.assertIn("do not invent", packet["field_value_policy"])
            self.assertIn('"unknown"', packet["field_value_policy"])
            return {"complete_or_ambiguous": "complete", "fields": [{"field_id": "json/filename",
                "value_or_label": actual["filename"], "evidence_ids": [packet["evidence_id"]],
                "source_spans": [{"start": 0, "end": len(original_text), "text": original_text}],
                "rule_id": packet["rule_id"]}]}
        report = audit.execute_audit(plan, [{**c, "complete": complete} for c in CONFIGS])
        result = next(r for r in report["rows"] if r["field_type"] == "filename_claim")
        self.assertEqual(result["mechanical_gold"]["status"], "supported")
        self.assertTrue(all(v["status"] == "valid" for v in result["phases"]["extract"]["votes"]))
        self.assertEqual(result["phases"]["extract"]["fields"][0]["value_or_label"], actual["filename"])
        self.assertIsNone(report["score_updates"])
        self.assertFalse(report["semantic_accuracy_certified"])

    def test_genuine_free_prose_keeps_original_text_without_forced_closed_fields(self):
        data = copy.deepcopy(self.data)
        name = json.loads(data["final_text"])["filename"]
        data["final_text"] = "The largest file is " + name + "."
        calls = []
        with patch.object(audit, "read_evidence", return_value=data):
            plan = self.prepare(judge_configs=CONFIGS)
            row = next(r for r in plan["rows"] if r["field_type"] == "filename_claim")
            self.assertEqual(row["domain_id"], "free_filename_description.v1")
            def complete(packet):
                calls.append(packet)
                self.assertNotIn("closed_schema", packet)
                self.assertEqual(packet["output_text"], data["final_text"])
                self.assertIn("do not invent", packet["field_value_policy"])
                return {"complete_or_ambiguous": "complete", "fields": [{"field_id": "claim/0/filename",
                    "value_or_label": name, "evidence_ids": [packet["evidence_id"]],
                    "source_spans": [{"start": 0, "end": len(data["final_text"]), "text": data["final_text"]}],
                    "rule_id": packet["rule_id"]}]}
            report = audit.execute_audit(plan, [{**c, "complete": complete} for c in CONFIGS])
        result = next(r for r in report["rows"] if r["field_type"] == "filename_claim")
        self.assertEqual(len(calls), 6)
        self.assertEqual(result["mechanical_gold"]["status"], "unsupported")
        self.assertTrue(all(v["status"] == "valid" for v in result["phases"]["extract"]["votes"]))
        self.assertFalse(report["semantic_accuracy_certified"])

    def test_prompt_change_does_not_relax_grounding_for_invented_unknown_file_id(self):
        plan = self.prepare(judge_configs=CONFIGS)
        def complete(packet):
            return {"complete_or_ambiguous": "complete", "fields": [{"field_id": "json/filename",
                "value_or_label": {"file_id": "unknown", "filename": json.loads(packet["output_text"])["filename"]},
                "evidence_ids": [packet["evidence_id"]],
                "source_spans": [{"start": 0, "end": len(packet["output_text"]), "text": packet["output_text"]}],
                "rule_id": packet["rule_id"]}]}
        report = audit.execute_audit(plan, [{**c, "complete": complete} for c in CONFIGS])
        result = next(r for r in report["rows"] if r["field_type"] == "filename_claim")["phases"]["extract"]
        self.assertTrue(all(v["status"] == "invalid_or_failed" for v in result["votes"]))
        self.assertFalse(result["fields"])

    def test_actual_judge_packet_hides_condition_ids_and_restores_exact_evidence(self):
        plan = self.prepare(judge_configs=CONFIGS)
        row = next(r for r in plan["rows"] if r["field_type"] == "filename_claim")
        original_id = row["window"]["evidence_id"]
        original_text = row["window"]["output_text"]
        aliases, originals = [], []
        def complete(packet):
            encoded = json.dumps(packet)
            self.assertNotIn(original_id, encoded)
            self.assertNotIn(plan["episode_id"], encoded)
            self.assertNotIn("H_E-low-honest", encoded)
            self.assertNotIn(str(RUN), encoded)
            self.assertNotIn("private_evidence_alias_mapping", packet)
            self.assertEqual(packet["output_text"], original_text)
            aliases.append(packet["evidence_id"])
            response = {"complete_or_ambiguous": "complete", "fields": [{"field_id": "record/0",
                "value_or_label": original_text, "evidence_ids": [packet["evidence_id"]],
                "source_spans": [{"start": 0, "end": len(original_text), "text": original_text}],
                "rule_id": packet["rule_id"]}]}
            originals.append(json.dumps(response))
            return originals[-1]
        report = audit.execute_audit(plan, [{**c, "complete": complete} for c in CONFIGS])
        result = next(r for r in report["rows"] if r["field_type"] == "filename_claim")["phases"]["extract"]
        self.assertEqual(len(set(aliases)), 1)
        self.assertRegex(aliases[0], r"^ev_[0-9a-f]{64}$")
        self.assertEqual(result["private_evidence_alias_mapping"], {aliases[0]: original_id})
        self.assertEqual([r["provider_raw"] for r in result["provider_response_journal"]], originals)
        self.assertTrue(all(v["status"] == "valid" for v in result["votes"]))
        self.assertTrue(all(v["value"]["fields"][0]["evidence_ids"] == [original_id] for v in result["votes"]))

    def test_unknown_alias_and_direct_real_id_cannot_bypass_alias_validation(self):
        plan = self.prepare(judge_configs=CONFIGS)
        row = next(r for r in plan["rows"] if r["field_type"] == "filename_claim")
        original_id = row["window"]["evidence_id"]
        calls = []
        def complete(packet):
            calls.append(packet)
            forged = original_id if len(calls) % 2 else "ev_" + "0" * 64
            return {"complete_or_ambiguous": "complete", "fields": [{"field_id": "record/0",
                "value_or_label": True, "evidence_ids": [forged],
                "source_spans": [{"start": 0, "end": len(packet["output_text"]), "text": packet["output_text"]}],
                "rule_id": packet["rule_id"]}]}
        report = audit.execute_audit(plan, [{**c, "complete": complete} for c in CONFIGS])
        result = next(r for r in report["rows"] if r["field_type"] == "filename_claim")["phases"]["extract"]
        self.assertEqual(len(calls), 6)
        self.assertTrue(all(v["status"] == "invalid_or_failed" for v in result["votes"]))
        self.assertEqual(result["fields"], [])
        self.assertTrue(all("provider_raw" in r and r["status"] == "response_alias_or_schema_invalid"
                            for r in result["provider_response_journal"]))

    def test_receipt_windows_require_exact_original_message_and_deduplicate(self):
        message = {"event_id": "e:message", "sender": "E", "recipient": "H", "content": "original text",
                   "source_refs": [], "origin_actors": ["E"]}
        content = {"status": "message", **message}
        receipt = {"kind": "model_consumption", "event_id": "e:receipt", "recipient": "role:H",
            "payload": {"history": [{"role": "observation", "content": content}]}}
        windows = audit._message_windows({"messages": [message]}, [receipt, receipt])
        self.assertEqual(len(windows), 1)
        receipt["payload"]["history"][0]["content"]["content"] = "forged text"
        self.assertEqual(audit._message_windows({"messages": [message]}, [receipt]), [])


if __name__ == "__main__":
    unittest.main()
