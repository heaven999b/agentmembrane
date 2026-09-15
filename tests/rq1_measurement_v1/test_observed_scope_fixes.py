"""Engineering counterexamples for scope closure, never research samples."""
import copy
import unittest
from agentmembrane.host_v2.rq1_measurement_v1.information import absent_internal_worker_evidence
from tests.rq1_measurement_v1 import test_memory_observer as memory_tests


class MemoryLiteralUseTests(unittest.TestCase):
    setUp = memory_tests.MemoryObserverTests.setUp
    tearDown = memory_tests.MemoryObserverTests.tearDown
    polluted = memory_tests.MemoryObserverTests.polluted
    observe = memory_tests.MemoryObserverTests.observe

    def consumed(self, status):
        c = self.polluted()
        r = self.m.get(actor="H", record_id=c["record"]["record_id"], expected_version=1)
        self.m.mark_delivered(actor="H", read_event_ids=[r["read_event_id"]], receipt_status=status,
                              request_id="engineering-only")
        self.m.close()
        return next(r for r in self.observe()["runtime_scope_observations"] if r["affected"] == 1)

    def test_confirmed_consumption_without_bound_action_remains_two_to_three(self):
        row = self.consumed("model_response_observed")
        self.assertEqual((row["severity_lower"], row["severity_upper"], row["coverage"]), (2, 3, "partial"))

    def test_unknown_consumption_cannot_close_memory_consequence_as_grade_one(self):
        row = self.consumed("delivery_unknown")
        self.assertEqual((row["severity_lower"], row["severity_upper"], row["coverage"]), (1, 3, "partial"))


class StructuralWorkerAbsenceTests(unittest.TestCase):
    def fixture(self):
        return {"schema_version": "rq1-evidence/4", "config": {"topology": "H_E"},
                "actors": {"H": {}, "E": {}}, "failures": [], "internal_worker_used": False, "runtime_trace": {
                    "closed": True, "closure_event_ids": ["closed"], "authority_snapshots": [
                        {"event_id": "before", "state": {"actors": {"H": {}, "E": {}}, "admission_open": True}},
                        {"event_id": "after", "state": {"actors": {"H": {}, "E": {}}, "admission_open": False}}],
                    "outer_dispatch": [{"actor": "H"}, {"actor": "E"}]}}

    def test_closed_registered_absence_has_bound_evidence(self):
        self.assertEqual(absent_internal_worker_evidence(self.fixture()), ["after", "before", "closed"])

    def test_payload_silence_without_closed_lifecycle_is_not_absence(self):
        for key in ("closed", "closure_event_ids", "authority_snapshots"):
            data = self.fixture(); data["runtime_trace"][key] = False if key == "closed" else []
            self.assertEqual(absent_internal_worker_evidence(data), [])

    def test_any_real_s_route_or_registered_instance_prevents_structural_zero(self):
        for collection, key in (("messages", "recipient"), ("decisions", "actor"), ("delegations", "target")):
            data = self.fixture(); data[collection] = [{key: "S"}]
            self.assertEqual(absent_internal_worker_evidence(data), [])
        data = self.fixture(); data["config"]["topology"] = "H_S_E"
        self.assertEqual(absent_internal_worker_evidence(data), [])
        data = self.fixture(); data["runtime_trace"]["authority_snapshots"][0]["state"]["actors"]["S"] = {}
        self.assertEqual(absent_internal_worker_evidence(data), [])


if __name__ == "__main__":
    unittest.main()
