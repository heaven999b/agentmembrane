"""Finite termination campaign regressions; synthetic control flow, no API calls."""
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.rq1_collab_v1 import paired_campaign as campaign


_spec = importlib.util.spec_from_file_location(
    "_paired_campaign_existing_fixtures", Path(__file__).with_name("test_paired_campaign.py"))
_fixtures = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fixtures)


class PairedCampaignFiniteTerminationTests(unittest.TestCase):
    setUp = _fixtures.PairedCampaignTests.setUp
    prepare = _fixtures.PairedCampaignTests.prepare
    unit_row = _fixtures.PairedCampaignTests.unit_row

    def finite_row(self, root, item, contract, *, code="model_refusal", delivery="delivered"):
        # Reuse only the legacy fixture's shape; materialize the final mutated
        # row once in run_with, respecting production's exclusive file writer.
        with patch.object(campaign, "_write"):
            row = self.unit_row(root, item, contract)
        row.update(
            paired_model_lineage={"kind": "physical_attempt_lineage", "ok": True},
            # The old success-only audit fails for a real no-action refusal.
            model_lineage={"ok": False, "completion_count": 0, "failed": ["no_successful_completion"]},
            completed_model_generations=0, flow_valid=False, host_final=None,
            driver_failures=[{"actor": "E" if code == "model_refusal" else "H",
                "kind": "model_refusal" if code == "model_refusal" else "budget_exhausted",
                "provider": {"code": code, "delivery": delivery}}])
        row["model_budget_snapshot"].update(
            halt_reason=None, accounting_semantics="reported_usage_stop_line_not_exact_billing_preauthorization")
        row["model_budget_snapshot"]["actors"]["H"]["unverifiable_attempts"] = 0
        return row

    def row(self, **options):
        if not hasattr(self, "contract"):
            self.prepare()
        return self.finite_row(self.root, self.contract["schedule"][0], self.contract, **options)

    def run_with(self, condition):
        value = self.prepare()
        def materialize(root, item, contract):
            row = condition(root, item, contract)
            campaign._write(root / "condition_results" / (item["episode_id"] + ".json"), row)
            return row
        with patch.object(campaign.legacy, "load_proxy_key", return_value="synthetic-key"), \
                patch.object(campaign.legacy, "_condition", side_effect=materialize) as call:
            result = campaign.run_paired(self.contract_path, self.release_path, self.output)
        self.assertEqual(len(result["rows"]), len(value["schedule"]))
        return result, call.call_count

    def test_no_action_explicit_refusal_does_not_skip_later_conditions(self):
        result, calls = self.run_with(self.finite_row)
        self.assertEqual(calls, 9)
        self.assertEqual(result["not_run"], 0)
        self.assertIsNone(result["stopped_reason"])
        self.assertTrue(all(row["completed_model_generations"] == 0 for row in result["rows"]))

    def test_closed_prepared_budget_without_host_final_continues(self):
        def condition(root, item, contract):
            return self.finite_row(root, item, contract,
                code="actor_request_budget_exhausted", delivery="prepared_only")
        result, calls = self.run_with(condition)
        self.assertEqual(calls, 9)
        self.assertEqual(result["not_run"], 0)
        self.assertTrue(all(row["host_final"] is None for row in result["rows"]))

    def test_all_registered_prepared_limit_codes_are_finite(self):
        for code in ("actor_request_budget_exhausted", "actor_token_budget_exhausted",
                     "model_request_budget_exhausted", "request_byte_budget_exhausted"):
            with self.subTest(code=code):
                self.assertFalse(campaign._infrastructure_failure(self.row(code=code, delivery="prepared_only")))

    def test_reported_token_stop_line_crossing_is_not_unknown_spend(self):
        row = self.row(code="actor_token_budget_exceeded")
        row["model_budget_snapshot"]["actors"]["H"]["total_tokens"] = 120001
        self.assertFalse(campaign._infrastructure_failure(row))
        row["model_budget_snapshot"]["accounting_semantics"] = "exact_hard_cap"
        self.assertTrue(campaign._infrastructure_failure(row))

    def test_verified_provider_filter_is_a_refusal_not_infrastructure_failure(self):
        row = self.row()
        row["driver_failures"][0]["provider"]["code"] = "model_content_filter"
        self.assertFalse(campaign._infrastructure_failure(row))
        row["paired_model_lineage"]["ok"] = False
        self.assertTrue(campaign._infrastructure_failure(row))

    def test_new_finite_limit_codes_require_new_physical_certificate(self):
        for code, delivery in (("request_byte_budget_exhausted", "prepared_only"),
                               ("actor_token_budget_exceeded", "delivered")):
            with self.subTest(code=code):
                row = self.row(code=code, delivery=delivery)
                del row["paired_model_lineage"]
                row["model_lineage"] = {"ok": True}
                self.assertTrue(campaign._infrastructure_failure(row))

    def test_invalid_paired_certificate_cannot_fallback_to_old_success(self):
        for certificate in ({"ok": False}, {}, None, True, {"ok": 1}):
            with self.subTest(certificate=certificate):
                row = self.row()
                row.update(paired_model_lineage=certificate, model_lineage={"ok": True}, flow_valid=True)
                self.assertTrue(campaign._infrastructure_failure(row))

    def test_paired_certificate_does_not_replace_other_physical_checks(self):
        base = self.row()
        cases = [lambda r: r["bounded_outcomes"].update(verified=False),
                 lambda r: r["audit"].update(ok=False),
                 lambda r: r.update(system_status="open"),
                 lambda r: r["drain"].update(inflight=["request"]),
                 lambda r: r["post_close_probe"]["old_leases_accepted"].update(H=True),
                 lambda r: r["post_close_probe"]["fresh_reader"].update(snapshot_matches=False)]
        for mutation in cases:
            row = copy.deepcopy(base)
            mutation(row)
            self.assertTrue(campaign._infrastructure_failure(row))

    def test_unknown_accounting_or_global_halt_never_continues(self):
        base = self.row(code="actor_token_budget_exceeded")
        cases = [lambda r: r["model_budget_snapshot"].update(halted=True),
                 lambda r: r["model_budget_snapshot"].update(halt_reason="reported_output_budget_exceeded"),
                 lambda r: r["model_budget_snapshot"].update(usage_unknown=True),
                 lambda r: r["model_budget_snapshot"]["actors"]["H"].update(unverifiable_attempts=1),
                 lambda r: r.update(runtime_unknown_reasons=["unknown_usage"])]
        for mutation in cases:
            row = copy.deepcopy(base)
            mutation(row)
            self.assertTrue(campaign._infrastructure_failure(row))

    def test_protocol_timeout_output_violations_are_not_finite_successes(self):
        for kind, code, delivery in (
                ("budget_exhausted", "reported_output_budget_exceeded", "delivered"),
                ("budget_exhausted", "episode_deadline_exhausted", "prepared_only"),
                ("budget_exhausted", "model_usage_unverifiable", "delivered"),
                ("model_refusal", "model_refusal", "delivery_unknown"),
                ("transport_error", "model_transport_failure", "delivery_unknown"),
                ("model_protocol_error", "model_response_protocol_error", "delivered")):
            with self.subTest(code=code):
                row = self.row(code=code, delivery=delivery)
                row["driver_failures"][0]["kind"] = kind
                self.assertTrue(campaign._infrastructure_failure(row))

    def test_transport_unknown_stops_all_later_assignments(self):
        def condition(root, item, contract):
            row = self.finite_row(root, item, contract)
            row["driver_failures"] = [{"kind": "transport_error", "provider": {
                "code": "model_transport_failure", "delivery": "delivery_unknown"}}]
            row["model_budget_snapshot"].update(halted=True, halt_reason="model_transport_failure")
            return row
        result, calls = self.run_with(condition)
        self.assertEqual(calls, 1)
        self.assertEqual(result["not_run"], 8)
        self.assertTrue(all(row["native_attack_success"] is None and row["strict_utility"] is None
                            for row in result["rows"][1:]))


if __name__ == "__main__":
    unittest.main()
