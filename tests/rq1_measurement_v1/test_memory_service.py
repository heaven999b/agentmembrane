"""Isolated service/reader tests, no model calls and no benchmark writes."""
import tempfile
import unittest
import copy
import time

from agentmembrane.host_v2.rq1_collab_v4.task_memory import TaskMemoryService
from agentmembrane.host_v2.rq1_collab_v4.memory_reader import digest
from agentmembrane.host_v2.rq1_collab_v4.memory_reader import canonical
from agentmembrane.host_v2.rq1_collab_v4.memory_refs import MemoryReferenceError, json_pointer


class MemoryServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.service = TaskMemoryService(self.temp.name,"engineering-memory","task-hash","H_S_E","high",
            projector=lambda actor,record,value,grant: {"file_id":value["file_id"]} if "file_id" in value else value)

    def tearDown(self):
        self.service.close()
        self.temp.cleanup()

    def put(self, actor="H", suffix="notes/H", key="test", value=None, version=0):
        return self.service.put(actor=actor,namespace=self.service.namespaces[suffix],key=key,
            value={"file_id":"13","hidden":"private"} if value is None else value,
            expected_version=version,request_id="test-put")

    def read(self, committed, actor="H", delivered=True, **kwargs):
        record=committed["record"]
        result=self.service.get(actor=actor,record_id=record["record_id"],expected_version=record["version"],**kwargs)
        if delivered and result.get("read_event_id"):
            self.service.mark_delivered(actor=actor,read_event_ids=[result["read_event_id"]],
                receipt_status="model_response_observed",request_id="engineering-fixture-no-real-model")
        return result

    def action(self, read, field="/file_id"):
        return {"type":"tool_action","tool":"get_file_by_id","arguments":{},"source_refs":[read["read_event_id"]],
                "argument_refs":{"/file_id":{"record_id":read["record"]["record_id"],"version":read["record"]["version"],
                    "field_pointer":field,"read_event_id":read["read_event_id"],"projected_value_sha256":read["projected_value_sha256"]}}}

    def test_durable_separate_reader_and_source_owner(self):
        source=self.service.seed_source("Original public request")
        self.assertEqual(source["record"]["owner_principal"],"system")
        self.assertEqual(source["record"]["trust_status"],"source_bound")
        closed=self.service.close()
        self.assertEqual(closed["snapshot"]["records"][0]["value"],{"public_user_request":"Original public request"})
        self.assertTrue(closed["snapshot"]["meta"]["closed"])

    def test_actor_cannot_override_envelope_or_write_source(self):
        row=self.put("E","notes/E",value={"writer_principal":"H","trust_status":"source_bound"})["record"]
        self.assertEqual(row["writer_principal"],"E")
        self.assertEqual(row["trust_status"],"actor_note")
        result=self.service.dispatch(actor="E",tool="memory.put",arguments={"namespace":self.service.namespaces["notes/E"],
            "key":"forged","value":{},"expected_version":0,"writer_principal":"H"},request_id="forged")
        self.assertEqual(result["status"],"rejected")
        self.assertEqual(self.service.put(actor="E",namespace=self.service.namespaces["source"],key="source",value={},request_id="bad")["status"],"rejected")

    def test_E_direct_S_namespaces_all_denied(self):
        for suffix in ("notes/S","observations/S"):
            self.assertEqual(self.put("E",suffix)["status"],"rejected")
            self.assertEqual(self.service.list(actor="E",namespace=self.service.namespaces[suffix])["status"],"rejected")
        self.service.set_delegation(epoch=1,tools=["get_file_by_id"],event_id="delegation")
        row=self.put("S","notes/S")
        self.assertEqual(self.read(row,actor="E")["status"],"rejected")

    def test_medium_low_and_unknown_namespace(self):
        self.service.E_level="A3"
        self.assertEqual(self.put("E","notes/H")["status"],"rejected")
        self.assertTrue(self.put("E","notes/E")["committed"])
        self.service.E_level="A0"
        self.assertEqual(self.service.list(actor="E")["records"],[])
        self.assertEqual(self.put("E","notes/E",version=1)["status"],"rejected")
        self.assertEqual(self.service.put(actor="H",namespace="../notes/H",key="ok",value={},request_id="bad")["status"],"rejected")

    def test_exact_receipt_required_not_submit_engineering_or_gateway(self):
        commit=self.put()
        read=self.read(commit,delivered=False)
        for status in ("queued","submitted","accepted_without_actor_receipt","delivery_unknown","engineering_driver_received"):
            self.service.mark_delivered(actor="H",read_event_ids=[read["read_event_id"]],receipt_status=status,request_id="test")
            with self.assertRaises(MemoryReferenceError):self.service.resolve_arguments(self.action(read),actor="H")
        self.service.mark_delivered(actor="H",read_event_ids=[read["read_event_id"]],receipt_status="confirmed_model_refusal",request_id="test-refusal")
        resolved,bindings=self.service.resolve_arguments(self.action(read),actor="H")
        self.assertEqual(resolved["arguments"],{"file_id":"13"})
        self.assertFalse(bindings[0]["use_confirmed"])

    def test_read_candidate_requires_actual_full_service_projection(self):
        read=self.read(self.put(),delivered=False)
        self.assertTrue(self.service.verify_prepared_read(actor="H",read=read))
        self.assertFalse(self.service.verify_prepared_read(actor="E",read=read))
        for mode in ("omit","alter","extend"):
            forged=copy.deepcopy(read)
            if mode=="omit":del forged["value"]
            elif mode=="alter":forged["value"]={"file_id":"not received"}
            else:forged["untrusted_extra"]="pretend this is a trusted envelope"
            self.assertFalse(self.service.verify_prepared_read(actor="H",read=forged))
        self.assertFalse(self.service._reads[read["read_event_id"]]["delivered"])

    def test_literal_same_value_conflict_and_no_recursive_ref(self):
        read=self.read(self.put())
        action=self.action(read)
        action["arguments"]={"file_id":"13"}
        with self.assertRaisesRegex(MemoryReferenceError,"literal_reference_conflict"):
            self.service.resolve_arguments(action,actor="H")
        action=self.action(read);action["tool"]="memory.get"
        with self.assertRaises(MemoryReferenceError):self.service.resolve_arguments(action,actor="H")

    def test_reference_version_hash_actor_and_source_binding(self):
        read=self.read(self.put())
        for field,value in (("version",True),("version",2),("projected_value_sha256","0"*64),("read_event_id","other-episode:read")):
            action=self.action(read);action["argument_refs"]["/file_id"][field]=value
            with self.assertRaises(MemoryReferenceError):self.service.resolve_arguments(action,actor="H")
        with self.assertRaises(MemoryReferenceError):self.service.resolve_arguments(self.action(read),actor="E")
        action=self.action(read);action["source_refs"]=[]
        with self.assertRaises(MemoryReferenceError):self.service.resolve_arguments(action,actor="H")

    def test_S_own_actual_record_without_H_roundtrip_and_grant_expiry(self):
        self.service.set_delegation(epoch=1,tools=["get_file_by_id"],event_id="d1")
        committed=self.service.cache_native_result(actor="S",call_id="native:S:1",tool="get_file_by_id",projected_value={"file_id":"13"})
        read=self.read(committed,actor="S")
        resolved,_=self.service.resolve_arguments(self.action(read),actor="S")
        self.assertEqual(resolved["arguments"]["file_id"],"13")
        self.service.set_delegation(epoch=2,tools=["get_file_by_id"],event_id="d2")
        with self.assertRaises(MemoryReferenceError):self.service.resolve_arguments(self.action(read),actor="S")

    def test_S_cannot_read_late_E_version_without_exact_H_transfer(self):
        self.service.set_delegation(epoch=1,tools=["get_file_by_id"],event_id="d1")
        old=self.put();h1=self.read(old)
        self.service.transfer(sender="H",recipient="S",read_event_id=h1["read_event_id"],transfer_event_id="H:send1")
        changed=self.put("E","notes/H",version=1,value={"file_id":"99","hidden":"secret"})
        self.assertEqual(self.read(changed,actor="S")["status"],"rejected")
        h2=self.read(changed)
        self.service.transfer(sender="H",recipient="S",read_event_id=h2["read_event_id"],transfer_event_id="H:send2")
        s2=self.read(changed,actor="S")
        self.assertEqual(s2["value"],{"file_id":"99"})
        self.assertEqual(self.service.resolve_arguments(self.action(s2),actor="S")[0]["arguments"],{"file_id":"99"})
        with self.assertRaises(MemoryReferenceError):self.service.resolve_arguments(self.action(s2,"/hidden"),actor="S")

    def test_native_cache_invalidation_blocks_current_reference(self):
        committed=self.service.cache_native_result(actor="H",call_id="native:1",tool="get_file_by_id",projected_value={"file_id":"13"})
        read=self.read(committed)
        self.service.invalidate(call_id="native:2",before_hash="before",after_hash="after")
        with self.assertRaises(MemoryReferenceError):self.service.resolve_arguments(self.action(read),actor="H")
        historical=self.read(committed)
        self.assertTrue(historical["historical_only"])

    def test_actor_overwrite_cannot_resurrect_invalidated_native_cache(self):
        committed=self.service.cache_native_result(actor="H",call_id="native:historical",tool="get_file_by_id",projected_value={"file_id":"13"})
        self.service.invalidate(call_id="native:changed",before_hash="before",after_hash="after")
        replacement=self.service.put(actor="E",namespace=self.service.namespaces["observations/H"],
            key=committed["record"]["key"],value={"file_id":"99"},expected_version=1,request_id="E:replace")
        read=self.read(replacement)
        self.assertTrue(read["historical_only"])
        with self.assertRaisesRegex(MemoryReferenceError,"stale_or_scope_denied"):
            self.service.resolve_arguments(self.action(read),actor="H")

    def test_close_after_deadline_is_readonly_closure_not_business_extension(self):
        self.put()
        self.service.deadline=time.monotonic()-1
        self.assertEqual(self.put(key="too-late")["status"],"rejected")
        closed=self.service.close()
        self.assertTrue(closed["snapshot"]["meta"]["closed"])
        self.assertFalse(self.service._process.is_alive())
        self.assertEqual(self.service.close(),closed)

    def test_killed_writer_cannot_be_reported_as_successfully_closed(self):
        from agentmembrane.host_v2.rq1_collab_v4.task_memory import MemoryServiceError
        self.put()
        self.service._process.terminate();self.service._process.join(timeout=2)
        self.service._closed=True
        with self.assertRaisesRegex(MemoryServiceError,"memory_close_not_durably_confirmed"):
            self.service.close()
        self.assertFalse(any(e["kind"]=="memory_closed" for e in self.service.events))
        # tearDown also calls close. Recover no state: record the expected
        # failure locally and leave the killed writer/database untouched.
        self.service.close=lambda: None

    def test_E_overwrite_preserves_native_source_not_its_forged_payload(self):
        committed=self.service.cache_native_result(actor="H",call_id="real-native:1",tool="get_file_by_id",
            projected_value={"file_id":"13"},source_refs=["real-projection:1"],dependency_hash="real-dependencies")
        key=committed["record"]["key"]
        changed=self.service.put(actor="E",namespace=self.service.namespaces["observations/H"],key=key,
            value={"file_id":"99","original_tool":"fake","writer_principal":"system"},expected_version=1,request_id="fixture-change")
        self.assertEqual(changed["record"]["writer_principal"],"E")
        self.assertEqual(changed["record"]["original_tool"],"get_file_by_id")
        self.assertEqual(changed["record"]["original_call_id"],"real-native:1")
        self.assertIn("real-projection:1",changed["record"]["source_refs"])
        self.assertEqual(changed["record"]["trust_status"],"modified_observation")

    def test_UTF8_pages_require_all_actual_receipts(self):
        committed=self.put(value={"file_id":"旅"*40})
        first=self.read(committed,limit_bytes=16)
        with self.assertRaises(MemoryReferenceError):self.service.resolve_arguments(self.action(first),actor="H")
        last=first
        while last["next_offset"] is not None:
            last=self.read(committed,offset_bytes=last["next_offset"],limit_bytes=16)
        self.assertEqual(self.service.resolve_arguments(self.action(last),actor="H")[0]["arguments"]["file_id"],"旅"*40)

    def test_limits_reject_without_partial_commit_and_no_eviction(self):
        before=len(self.service.snapshot_readonly()["records"])
        self.assertEqual(self.put(value="x"*16384)["status"],"rejected")
        self.assertEqual(len(self.service.snapshot_readonly()["records"]),before)
        committed=self.put()
        self.assertEqual(self.put(version=0)["reason"],"expected_version_conflict")
        self.assertEqual(self.service.snapshot_readonly(record_id=committed["record"]["record_id"])["records"][0]["value"],committed["record"]["value"])

    def test_large_cache_automatic_restore_whole_value_up_to_64KiB(self):
        committed=self.service.cache_native_result(actor="H",call_id="cache:big",tool="list_files",projected_value={"file_id":"x"*20000})
        restored=self.service.restore(actor="H")
        self.assertEqual(restored["values"][0]["value"],committed["record"]["value"])
        self.assertEqual(restored["values"][0]["next_offset"],None)
        self.assertFalse(self.service._reads[restored["values"][0]["read_event_id"]]["delivered"])

    def test_pointer_closed_semantics(self):
        self.assertEqual(json_pointer({"a/b":{"~x":[1]}},"/a~1b/~0x/0"),1)
        for pointer in ("/0~2","/-1","/01","/-","$.x"):
            with self.assertRaises(MemoryReferenceError):json_pointer([1],pointer)


class RuntimeMemoryWiringTests(unittest.TestCase):
    """Exercise the real monitor/service seam with temporary SQLite only."""
    def setUp(self):
        from agentmembrane.host_v2.rq1_collab_v4.monitor import RuntimeMonitor
        self.temp=tempfile.TemporaryDirectory()
        self.m=TaskMemoryService(self.temp.name,"wiring-memory","hash","H_S_E","high",
            projector=lambda actor,record,value,grant: {"file_id":value["file_id"]})
        # Controller-native/model execution is outside this service test. These
        # are the exact monitor fields used by the lifecycle under test.
        self.monitor=RuntimeMonitor.__new__(RuntimeMonitor)
        self.monitor.memory=self.m
        self.monitor.own_reads={actor:{} for actor in ("H","S","E")}
        self.monitor.grant_event_ids=[]
        self.monitor.last_deliveries={}
        self.monitor.cfg={"level":"high"}
        self.monitor.epoch=0
        self.monitor.emit=lambda kind,data,*args,**kwargs: {"event_id":"fixture-monitor:"+kind,**copy.deepcopy(data)}

    def tearDown(self):
        self.m.close();self.temp.cleanup()

    def host_cache(self,receipt="model_response_observed"):
        self.m.cache_native_result(actor="H",call_id="native:host",tool="get_file_by_id",
            projected_value={"file_id":"13","hidden":"secret-not-in-S-projection"})
        obs=self.monitor.augment_observation("H",{"history":[]})
        read=obs["memory_context"]["values"][0]
        self.monitor.delivered("H",obs,receipt,request_id="fixture-no-real-model")
        return obs,read

    def test_host_restore_actual_receipt_and_low_external_surface(self):
        _,read=self.host_cache(receipt="engineering_driver_received")
        self.assertFalse(self.m._reads[read["read_event_id"]]["delivered"])
        self.monitor.delivered("H",{"history":[read]},"model_response_observed",request_id="fixture")
        self.assertTrue(self.m._reads[read["read_event_id"]]["delivered"])
        self.monitor.cfg["level"]="low";self.m.E_level="A0"
        obs=self.monitor.augment_observation("E",{"history":[]})
        self.assertEqual(obs["system_tools"],[])
        denied=self.monitor.memory_action("E",{"tool":"memory.put","arguments":{
            "namespace":self.m.namespaces["notes/E"],"key":"bad","value":{},"expected_version":0}},"bad",[])
        self.assertEqual(denied["status"],"rejected")

    def test_H_forward_by_memory_ID_and_outer_history_ID_both_project_for_S(self):
        _,read=self.host_cache()
        self.monitor.delegate(recipient="S",tools=["get_file_by_id"],event_id="H:delegation",refs=[read["read_event_id"]])
        for event_id in (read["read_event_id"],"observation:queued-wrapper"):
            source={"role":"observation","event_id":event_id,"origin_actors":["H"],"content":read}
            forwarded=self.monitor.forward_reference("H","S",source)
            self.assertNotIn(b"secret-not-in-S-projection",canonical(forwarded))
            self.assertIn(b'"file_id":"13"',canonical(forwarded))

    def test_refused_transfer_does_not_abort_legitimate_delegation(self):
        _,read=self.host_cache(receipt="engineering_driver_received")
        self.monitor.delegate(recipient="S",tools=["get_file_by_id"],event_id="H:delegation",refs=[read["read_event_id"]])
        self.assertTrue(self.m._grant["active"])
        self.assertIsNone(self.m._foreign_transfer("S",{
            "record_id":read["record"]["record_id"],"version":read["record"]["version"]}))

    def test_worker_actual_own_cache_and_expired_grant(self):
        self.monitor.delegate(recipient="S",tools=["get_file_by_id"],event_id="H:d1",refs=[])
        self.monitor.cache_result("S",{"call_id":"native:S","tool":"get_file_by_id","before":{},"after":{}},
            {"file_id":"13"},"native:S:queued")
        obs=self.monitor.augment_observation("S",{"history":[]})
        read=obs["memory_context"]["values"][0]
        self.monitor.delivered("S",obs,"model_response_observed",request_id="fixture-no-model")
        self.assertTrue(self.m._reads[read["read_event_id"]]["delivered"])
        self.monitor.worker_finished("S")
        self.assertFalse(self.m._grant["active"])
        self.assertEqual(self.m.get(actor="S",record_id=read["record"]["record_id"],expected_version=1)["status"],"rejected")

    def test_native_error_with_real_state_change_invalidates_cache(self):
        _,read=self.host_cache()
        self.monitor.native_transition({"call_id":"partial-native-error","before":{"x":0},"after":{"x":1},"error":"after-side-effect"})
        row=self.m.snapshot_readonly(record_id=read["record"]["record_id"],version=1)["records"][0]
        self.assertTrue(row["invalidated"])


if __name__=="__main__":unittest.main()
