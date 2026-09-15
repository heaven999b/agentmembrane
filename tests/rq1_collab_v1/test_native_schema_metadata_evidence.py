"""A schema field called password is metadata; an argument value is not."""
import json
import tempfile
import unittest
from pathlib import Path

from agentmembrane.host_v2.rq1_collab_v1.audit import (
    EventCollector, _check_no_transport_secrets, canonical, verify,
)


SPEC = {"name": "update_password", "description": "Change a simulated account password.",
        "parameters": {"type": "object", "properties": {
            "password": {"type": "string", "title": "Password", "description": "New password."}},
            "required": ["password"]}}


class NativeSchemaMetadataEvidenceTests(unittest.TestCase):
    def test_locked_schema_field_survives_registration_delivery_and_seal(self):
        with tempfile.TemporaryDirectory() as directory:
            collector = EventCollector(Path(directory) / "execution", "schema-metadata")
            collector.emit("authority_probe_registration", {"tool_specs": [SPEC]})
            collector.emit("observation_delivered", {"payload": {"available_tools": [SPEC]}})
            # The live model body serializes native tools inside observation
            # text; the transport checker must accept that schema metadata.
            body = {"messages": [{"role": "user", "content": json.dumps({"available_tools": [SPEC]})}]}
            collector.record_model_request("request-1", canonical(body), status="prepared_only",
                                           actor="H", model_profile={"model": "fixture"})
            seal = collector.seal({"purpose": "schema_metadata_probe"})
            self.assertTrue(verify(Path(directory) / "execution",
                                   expected_seal_hash=seal["seal_hash"])["ok"])

    def test_actual_password_values_and_untrusted_schema_locations_still_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            collector = EventCollector(Path(directory) / "execution", "schema-denial")
            for kind, data in (
                    ("actor_decision", {"action": {"arguments": {"password": "chosen-secret"}}}),
                    ("authority_probe_registration", {"tool_specs": [{"parameters": {
                        "properties": {"password": {"type": "string", "default": "secret"}}}}]}),
                    ("observation_delivered", {"payload": {"history": [{"available_tools": [SPEC]}]}}),
                    ("untrusted_event", {"tool_specs": [SPEC]})):
                with self.subTest(kind=kind), self.assertRaises(ValueError):
                    collector.emit(kind, data)
            with self.assertRaises(ValueError):
                _check_no_transport_secrets({"arguments": {"password": "chosen-secret"}})
            with self.assertRaises(ValueError):
                collector.record_model_request("bad", canonical({"arguments": {"password": "chosen-secret"}}),
                                               status="prepared_only", actor="H",
                                               model_profile={"model": "fixture"})
            with self.assertRaises(ValueError):
                collector.seal({"tool_specs": [SPEC]})
            collector.abort()

    def test_simulated_password_only_in_trusted_native_before_after_receipt(self):
        state = {"user_account": {"password": "simulated-state-value"}}
        receipt = {"record_origin": "trusted_native_adapter", "status": "committed",
                   "evidence_quality": {"backend_entered": True},
                   "before": state, "after": state, "arguments": {}, "result": []}
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory) / "execution"
            collector = EventCollector(run, "native-state")
            collector.emit("native_terminal", receipt)
            for kind, changed in (
                    ("native_terminal", {**receipt, "arguments": {"password": "actual-argument"}}),
                    ("native_terminal", {**receipt, "result": {"password": "delivered-value"}}),
                    ("native_terminal", {**receipt, "record_origin": "untrusted"}),
                    ("observation_delivered", {"payload": {"history": [{"before": state}]}})):
                with self.subTest(kind=kind), self.assertRaises(ValueError):
                    collector.emit(kind, changed)
            seal = collector.seal({"purpose": "native_state_password_path_probe"})
            self.assertTrue(verify(run, expected_seal_hash=seal["seal_hash"])["ok"])
            observed = [json.loads(line) for line in (run / "events.jsonl").read_text().splitlines()]
            self.assertEqual(observed[0]["data"]["before"], state)


if __name__ == "__main__":
    unittest.main()
