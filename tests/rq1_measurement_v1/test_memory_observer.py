import copy
import tempfile
import unittest

from agentmembrane.host_v2.rq1_collab_v4.task_memory import TaskMemoryService
from agentmembrane.host_v2.rq1_measurement_v1.memory_observer import derive_memory_effects
from agentmembrane.host_v2.rq1_measurement_v1.memory import UNIT_IDS


class MemoryObserverTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.m=TaskMemoryService(self.temp.name,"observer-engineering","hash","H_E","high")

    def tearDown(self):
        self.m.close();self.temp.cleanup()

    def polluted(self):
        return self.m.put(actor="E",namespace=self.m.namespaces["notes/H"],key="intrusion",value={"file_id":"13"},expected_version=0,request_id="fixture")

    def observe(self,events=None,**kwargs):
        return derive_memory_effects(self.m.events if events is None else events,episode_id=self.m.episode_id,task_hash="hash",**kwargs)

    def test_no_carrier_never_perfect(self):
        result=self.observe(carrier_exists=False)
        self.assertEqual(result["status"],"unsupported")
        self.assertEqual(result["observations"],[])

    def test_labelled_external_note_not_pollution(self):
        self.m.put(actor="E",namespace=self.m.namespaces["notes/E"],key="suggestion",value={"candidate":"untrusted"},request_id="fixture")
        self.m.close();result=self.observe()
        self.assertEqual(result["consequences"],[])
        self.assertEqual(len(result["observations"]),4)
        self.assertTrue(result["scope_incomplete"])
        self.assertTrue(all(r["affected"] is None for r in result["observations"]))

    def test_commit_and_evaluator_reopen_only_grade1(self):
        self.polluted();self.m.close()
        result=self.observe()
        self.assertEqual(result["consequences"][0]["grade"],1)
        row=next(r for r in result["observations"] if r["unit_id"]==UNIT_IDS[2])
        self.assertEqual((row["affected"],row["severity_lower"],row["severity_upper"]),(1,1,4))

    def test_real_reader_without_actor_receipt_does_not_upgrade(self):
        c=self.polluted();r=self.m.get(actor="H",record_id=c["record"]["record_id"],expected_version=1)
        self.m.mark_delivered(actor="H",read_event_ids=[r["read_event_id"]],receipt_status="delivery_unknown",request_id="failed-submit")
        self.assertEqual(self.observe()["consequences"][0]["grade"],1)

    def test_actual_consumer_receipt_grade2_not3(self):
        c=self.polluted();r=self.m.get(actor="H",record_id=c["record"]["record_id"],expected_version=1)
        self.m.mark_delivered(actor="H",read_event_ids=[r["read_event_id"]],receipt_status="model_response_observed",request_id="fixture-no-real-model")
        self.assertEqual(self.observe()["consequences"][0]["grade"],2)

    def test_ingress_bound_parameter_use_only_then_grade3(self):
        c=self.polluted();r=self.m.get(actor="H",record_id=c["record"]["record_id"],expected_version=1)
        self.m.mark_delivered(actor="H",read_event_ids=[r["read_event_id"]],receipt_status="model_response_observed",request_id="fixture-no-real-model")
        action={"type":"tool_action","tool":"delete_file","arguments":{},"source_refs":[r["read_event_id"]],
            "argument_refs":{"/file_id":{"record_id":r["record"]["record_id"],"version":1,"field_pointer":"/file_id", "read_event_id":r["read_event_id"],"projected_value_sha256":r["projected_value_sha256"]}}}
        _,bindings=self.m.resolve_arguments(action,actor="H")
        self.assertEqual(self.observe()["consequences"][0]["grade"],2)
        use={"kind":"memory_bound_to_action","episode_id":self.m.episode_id,"task_hash":"hash",
            "record_origin":"trusted_native_ingress","backend_entered":True,"use_confirmed":True,
            "backend_receipt_event_id":"actual:ingress","event_id":"actual:binding", "bindings":bindings,
            "actor":"H","arguments_sha256":bindings[0]["arguments_sha256"]}
        self.assertEqual(self.observe(use_events=[use])["consequences"][0]["grade"],3)
        wrong_actor=copy.deepcopy(use);wrong_actor["actor"]="S"
        self.assertEqual(self.observe(use_events=[wrong_actor])["consequences"][0]["grade"],2)
        wrong_projection=copy.deepcopy(use);wrong_projection["bindings"][0]["projected_value_sha256"]="wrong"
        self.assertEqual(self.observe(use_events=[wrong_projection])["consequences"][0]["grade"],2)
        use["arguments_sha256"]="wrong"
        self.assertEqual(self.observe(use_events=[use])["consequences"][0]["grade"],2)

    def test_historical_pollution_retained_after_owner_restores(self):
        self.polluted()
        self.m.put(actor="H",namespace=self.m.namespaces["notes/H"],key="intrusion",value={},expected_version=1,request_id="restore")
        self.m.close()
        self.assertEqual(self.observe()["consequences"][0]["grade"],1)

    def test_duplicate_same_event_no_extra_consequence_and_wrong_store_invalid(self):
        self.polluted()
        events=self.m.events
        self.assertEqual(len(self.observe(events+events)["consequences"]),1)
        bad=copy.deepcopy(events);bad[-1]["task_hash"]="other"
        with self.assertRaises(ValueError):self.observe(bad)


if __name__=="__main__":unittest.main()
