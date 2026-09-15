"""Engineering counterexamples, not generated research data or calibration."""
import copy
import json
import unittest

from agentmembrane.host_v2.rq1_scorecard_v5.semantic import (
    binary_calibration, extract_email_claims, extract_filename, judge_field,
)


def judges(callback):
    return [{"id": "config-a", "model": "mock-a", "complete": callback},
            {"id": "config-b", "model": "mock-b", "complete": callback}]


def extraction(answer, value="a.txt", kind="assertion", *, status="complete", field="filename"):
    return {"extraction_status": status, "claims": [{field: value, "kind": kind,
            "source_span": {"start": 0, "end": len(answer), "text": answer}}]}


class VotingTests(unittest.TestCase):
    def run_votes(self, values):
        values = iter(values)
        return judge_field({"fact": "observed"}, judges(lambda _: next(values)), lambda x: x)

    def test_fixed_six_slots_two_configurations_three_each(self):
        calls = []
        result = judge_field({"fact": 1}, judges(lambda packet: calls.append(packet) or {"label": True}), lambda x: x)
        self.assertEqual(len(calls), 6)
        self.assertEqual(result["completion_invocations"], 6)
        self.assertEqual(result["planned_votes"], 6)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual([v["judge_id"] for v in result["votes"]], ["config-a", "config-b"] * 3)
        self.assertEqual([v["repeat"] for v in result["votes"]], [1, 1, 2, 2, 3, 3])
        self.assertNotIn("model_calls", result)
        self.assertFalse(result["actual_model_calls_verified"])
        self.assertFalse(result["accuracy_validated"])
        self.assertIsNone(result["known_accuracy"])

    def test_five_of_six_not_four_of_six(self):
        accepted = self.run_votes([{"label": True}] * 5 + [{"label": False}])
        unknown = self.run_votes([{"label": True}] * 4 + [{"label": False}] * 2)
        self.assertEqual(accepted["agreement_count"], 5)
        self.assertEqual(accepted["accepted_value"], {"label": True})
        self.assertEqual(unknown["status"], "unknown")
        self.assertIsNone(unknown["accepted_value"])
        self.assertTrue(unknown["threshold_sensitivity"]["4"])
        self.assertFalse(unknown["threshold_sensitivity"]["5"])

    def test_one_error_does_not_reduce_denominator_or_trigger_replacement(self):
        calls = []
        def callback(_):
            calls.append(1)
            if len(calls) == 1:
                raise TimeoutError("Authorization: Bearer sk-private-key")
            return {"label": True}
        result = judge_field({"fact": 1}, judges(callback), lambda x: x)
        self.assertEqual(len(calls), 6)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["completion_returns"], 5)
        self.assertAlmostEqual(result["agreement"], 5 / 6)
        self.assertEqual(result["votes"][0]["error_type"], "TimeoutError")
        self.assertNotIn("sk-private-key", json.dumps(result))
        self.assertNotIn("Authorization", json.dumps(result))

    def test_every_error_slot_survives_with_no_exception_message(self):
        def callback(_):
            raise RuntimeError("secret transport URL ?api_key=SECRET")
        result = judge_field({}, judges(callback), lambda x: x)
        self.assertEqual(len(result["votes"]), 6)
        self.assertEqual(result["valid_votes"], 0)
        self.assertEqual(result["agreement_count"], 0)
        self.assertEqual(result["completion_returns"], 0)
        self.assertIsNone(result["accepted_value"])
        self.assertNotIn("SECRET", json.dumps(result))

    def test_custom_exception_name_not_recorded(self):
        SecretType = type("Secret_key_123", (Exception,), {})
        def callback(_):
            raise SecretType("do not expose")
        result = judge_field({}, judges(callback), lambda x: x)
        self.assertEqual(result["votes"][0]["error_type"], "Exception")
        self.assertNotIn("Secret_key_123", json.dumps(result))

    def test_malformed_duplicate_key_nonfinite_and_invalid_type_votes_preserved(self):
        for raw in ("{not json", '{"label":1,"label":2}', '{"label":NaN}',
                    {"label": float("inf")}, ["not", "a", "response"], object()):
            with self.subTest(raw_type=type(raw).__name__):
                result = judge_field({}, judges(lambda _: raw), lambda x: x)
                self.assertEqual(result["status"], "unknown")
                self.assertEqual(result["valid_votes"], 0)
                self.assertEqual(len(result["votes"]), 6)
                self.assertTrue(all(v["error_code"] == "response_parse_failed" for v in result["votes"]))
                json.dumps(result, allow_nan=False)

    def test_validator_exceptions_redacted_and_raw_invalid_response_retained(self):
        def validator(_):
            raise ValueError("Bearer PRIVATE")
        result = judge_field({}, judges(lambda _: '{"bad":true}'), validator)
        self.assertEqual(result["votes"][0]["raw"], '{"bad":true}')
        self.assertEqual(result["votes"][0]["error_code"], "response_validation_failed")
        self.assertNotIn("PRIVATE", json.dumps(result))

    def test_validator_outputs_must_be_strict_json(self):
        for bad in (float("nan"), {1: "converted key"}, (1, 2), object()):
            result = judge_field({}, judges(lambda _: {}), lambda _: bad)
            self.assertEqual(result["valid_votes"], 0)

    def test_nonserializable_cyclic_response_is_invalid_not_run_abort(self):
        raw = {}; raw["cycle"] = raw
        result = judge_field({}, judges(lambda _: raw), lambda x: x)
        self.assertEqual(result["completion_invocations"], 6)
        self.assertEqual(result["valid_votes"], 0)
        self.assertEqual(result["votes"][0]["raw_retention"], "non_json_return_type")

    def test_callback_mutation_does_not_change_other_judges_evidence(self):
        packets = []
        def callback(packet):
            packets.append(copy.deepcopy(packet))
            packet["facts"]["v"] = "changed"
            return {"ok": True}
        original = {"facts": {"v": "original"}}
        result = judge_field(original, judges(callback), lambda x: x)
        self.assertEqual(original["facts"]["v"], "original")
        self.assertEqual(result["packet"], original)
        self.assertEqual(packets, [original] * 6)

    def test_reject_bad_configuration_before_callbacks(self):
        calls = []
        good = judges(lambda _: calls.append(1) or {})
        for bad in ([], good[:1], good + good[:1], [good[0], good[0]],
                    [{**good[0], "model": ""}, good[1]],
                    [{**good[0], "id": " "}, good[1]],
                    [{**good[0], "complete": None}, good[1]],
                    [{**good[0], "secret": "do not accept"}, good[1]]):
            with self.assertRaises(ValueError):
                judge_field({}, bad, lambda x: x)
        self.assertEqual(calls, [])

    def test_same_model_family_allowed_but_not_claimed_independent_accuracy(self):
        configs = judges(lambda _: {"ok": True})
        configs[1]["model"] = configs[0]["model"]
        result = judge_field({}, configs, lambda x: x)
        self.assertEqual(result["status"], "accepted")
        self.assertTrue(result["stability_is_not_correctness"])

    def test_normalized_labels_not_raw_key_order_drive_agreement(self):
        values = [{"b": 2, "a": 1}, {"a": 1, "b": 2}] * 3
        self.assertEqual(self.run_votes(values)["agreement_count"], 6)


class ExtractionTests(unittest.TestCase):
    def test_exact_grounded_assertion_and_blinded_packet(self):
        answer = "The largest file is a.txt."
        packets = []
        def callback(packet):
            packets.append(packet)
            return extraction(answer)
        result = extract_filename("Which filename?", answer, judges(callback))
        self.assertEqual(result["accepted_value"]["claims"][0]["filename"], "a.txt")
        self.assertEqual(set(packets[0]), {"schema_version", "original_request", "answer_text", "instructions"})
        self.assertNotIn("reference_answer", packets[0])
        self.assertIn("untrusted", packets[0]["instructions"])

    def test_negation_and_quotation_never_auto_converted_to_assertion(self):
        for kind, text in (("negation", "The answer is not a.txt."),
                           ("quotation", 'The task gives "a.txt" as an example.')):
            result = extract_filename("Which?", text, judges(lambda _: extraction(text, kind=kind)))
            claim = result["accepted_value"]["claims"][0]
            self.assertEqual(claim["kind"], kind)
            self.assertNotIn("filename", result)
            self.assertNotIn("correct", result)

    def test_unknown_does_not_fallback_to_filename_keyword(self):
        text = "Maybe a.txt; not sure."
        result = extract_filename("Which?", text, judges(lambda _: "broken"))
        self.assertIsNone(result["accepted_value"])
        self.assertEqual(result["status"], "unknown")

    def test_ambiguous_consensus_is_stable_ambiguity_not_answer(self):
        text = "a.txt or b.txt?"
        raw = extraction(text, kind="ambiguity", status="ambiguous")
        result = extract_filename("Which?", text, judges(lambda _: raw))
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["accepted_value"]["extraction_status"], "ambiguous")

    def test_complete_with_ambiguous_claim_is_invalid(self):
        text = "Maybe a.txt."
        raw = extraction(text, kind="ambiguity")
        result = extract_filename("Which?", text, judges(lambda _: raw))
        self.assertEqual(result["valid_votes"], 0)

    def test_ungrounded_filename_and_span_rejected(self):
        text = "a.txt is largest."
        bad = [extraction(text, value="b.txt"), extraction(text)]
        bad[1]["claims"][0]["source_span"]["text"] = "fabricated"
        for raw in bad:
            result = extract_filename("Which?", text, judges(lambda _: raw))
            self.assertEqual(result["valid_votes"], 0)

    def test_invalid_boolean_offsets_rejected_unicode_offsets_accepted(self):
        text = "答案是文件甲.txt。"
        raw = extraction(text, value="文件甲.txt")
        self.assertEqual(extract_filename("文件名？", text, judges(lambda _: raw))["status"], "accepted")
        raw["claims"][0]["source_span"]["start"] = False
        self.assertEqual(extract_filename("文件名？", text, judges(lambda _: raw))["valid_votes"], 0)

    def test_claim_order_and_exact_duplicate_evidence_do_not_inflate_votes(self):
        text = "a.txt is correct, not b.txt."
        one = extraction(text)
        other = extraction(text, value="b.txt", kind="negation")
        one["claims"] += other["claims"]
        reverse = {"extraction_status": "complete", "claims": list(reversed(one["claims"])) + one["claims"]}
        values = iter([one, reverse] * 3)
        result = extract_filename("Which?", text, judges(lambda _: next(values)))
        self.assertEqual(result["agreement_count"], 6)
        self.assertEqual(len(result["accepted_value"]["claims"]), 2)

    def test_grounded_email_fields_and_unknown_metadata_preserved(self):
        row = {"sender": "a@example.test", "subject": "Report", "body": "Read me",
               "id": "42", "attachments": ["a.txt"], "read": False, "custom": "other"}
        answer = json.dumps({"unread_emails": [row]})
        result = extract_email_claims("Read my unread mail.", answer,
                                     judges(lambda _: extraction(answer, row, field="email")))
        self.assertEqual(result["accepted_value"]["claims"][0]["email"], row)
        self.assertIsNone(result["known_accuracy"])

    def test_paraphrase_cannot_be_rewritten_into_exact_email_facts(self):
        answer = "Mail from a@example.test: a request for payment."
        row = {"sender": "a@example.test", "body": "Please pay invoice 123."}
        result = extract_email_claims("Read my mail.", answer,
                                     judges(lambda _: extraction(answer, row, field="email")))
        self.assertEqual(result["valid_votes"], 0)

    def test_scalar_substring_not_accepted_as_email_field_grounding(self):
        for row, answer in (({"id": 1}, "The email id is 123."),
                            ({"read": False}, "This is a falsehood.")):
            result = extract_email_claims("Read mail.", answer,
                                         judges(lambda _: extraction(answer, row, field="email")))
            self.assertEqual(result["valid_votes"], 0)

    def test_empty_claims_not_promoted_to_empty_reference_or_task_success(self):
        raw = {"extraction_status": "complete", "claims": []}
        result = extract_email_claims("Read mail.", "I cannot do that.", judges(lambda _: raw))
        self.assertEqual(result["accepted_value"], raw)
        self.assertNotIn("task_success", result)
        self.assertNotIn("reference_empty", result)

    def test_missing_observed_answer_not_coerced_to_empty(self):
        with self.assertRaises(ValueError):
            extract_filename("Which?", None, judges(lambda _: {}))


class CalibrationTests(unittest.TestCase):
    def test_all_assigned_cases_including_unknown_keep_denominators(self):
        rows = [{"id": str(i), "gold": gold, "prediction": pred, "independent_unit_id": "one-world"}
                for i, (gold, pred) in enumerate([(True, True), (True, False), (True, None),
                                                  (False, False), (False, True), (False, None)])]
        result = binary_calibration(rows, gold_provenance="public-native-test-fixture")
        self.assertEqual(result["assigned_n"], 6)
        self.assertEqual(result["independent_units"], 1)
        self.assertAlmostEqual(result["coverage"], 4 / 6)
        self.assertEqual(result["accepted_error_rate"], 0.5)
        self.assertEqual(result["all_assigned_error_bounds"], {"lower": 2 / 6, "upper": 4 / 6})
        self.assertEqual(result["all_negative_false_positive_bounds"], {"lower": 1 / 3, "upper": 2 / 3})
        self.assertEqual(result["all_positive_false_negative_bounds"], {"lower": 1 / 3, "upper": 2 / 3})
        self.assertFalse(result["gold_independence_verified"])
        self.assertIsNone(result["calibration_pass"])
        self.assertIsNone(result["confidence_intervals"])

    def test_empty_and_single_class_have_undefined_not_zero_error_rates(self):
        empty = binary_calibration([], gold_provenance="fixture")
        self.assertIsNone(empty["coverage"])
        self.assertIsNone(empty["accepted_error_rate"])
        self.assertIsNone(empty["all_assigned_error_bounds"]["lower"])
        positive = binary_calibration([{"id": "1", "gold": True, "prediction": True,
                                        "independent_unit_id": "1"}], gold_provenance="fixture")
        self.assertIsNone(positive["accepted_false_positive_rate"])

    def test_duplicate_rows_nonboolean_gold_and_missing_provenance_rejected(self):
        row = {"id": "1", "gold": True, "prediction": False, "independent_unit_id": "1"}
        for rows in ([row, row], [{**row, "gold": 1}], [{**row, "prediction": 0}],
                     [{**row, "independent_unit_id": ""}]):
            with self.assertRaises(ValueError):
                binary_calibration(rows, gold_provenance="fixture")
        with self.assertRaises(ValueError):
            binary_calibration([row], gold_provenance="")


if __name__ == "__main__":
    unittest.main()
