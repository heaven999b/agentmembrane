"""CODE004 regression: typed masking preserves business bytes and prior boundaries."""
import copy
from pathlib import Path
import tempfile
import unittest

from agentmembrane.host_v2.rq1_collab_v1.audit import EventCollector, canonical, sha256
from agentmembrane.host_v2.rq1_collab_v1.capture import seal_execution
from agentmembrane.host_v2.rq1_collab_v1.hard_facts import derive_facts
from agentmembrane.host_v2.rq1_collab_v1.judge import build_packet, judge_packet, public_packet
from agentmembrane.host_v2.rq1_collab_v1.runtime import run_episode
from agentmembrane.host_v2.rq1_collab_v1.services import SystemServices
from tests.rq1_collab_v1.test_runtime import NativeFixture, PROMPT, Scripted, final, tool
from tests.rq1_collab_v1.test_v2_runtime import config
from tests.rq1_collab_v1.test_v2_scoring import fixture, rubric
from tests.rq1_collab_v1.test_v2_scoring_revision1 import runtime_rubric


BUSINESS = {"a": "a", "data": "data", "quality_checklists": "a data",
            "episode_id": "a", "call_id": "a:call:1", "text": "Keep a:call:1 and a unchanged."}


class EchoNativeFixture(NativeFixture):
    def __init__(self):
        super().__init__()
        self.state["business"] = copy.deepcopy(BUSINESS)

    def call(self, name, arguments):
        result = super().call(name, arguments)
        if name == "get_current_day":
            result["result"] = copy.deepcopy(BUSINESS)
        return result


class TypedMaskRevisionTests(unittest.TestCase):
    def sealed(self, episode):
        cfg = config()
        cfg["episode_id"] = episode
        cfg["quality_rubric_sha256"] = sha256(canonical(runtime_rubric()))
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        collector = EventCollector(root / "run", episode)
        self.addCleanup(collector.abort)
        service = SystemServices(str(root / "service.sqlite"), episode)
        driver = Scripted([tool("get_current_day", **BUSINESS), final("a data quality_checklists")],
                          [final("a data quality_checklists")])
        try:
            evidence = run_episode(cfg, EchoNativeFixture(), driver, service, collector)
        finally:
            service.disconnect()
        checkpoint = seal_execution(root / "run", evidence, collector)
        facts = derive_facts(checkpoint, execution_seal_sha256=checkpoint["execution_seal_sha256"])
        return checkpoint, facts

    def test_short_legal_ids_do_not_rewrite_schema_task_rubric_or_private_truth(self):
        for episode in ("a", "data", "quality_checklists"):
            with self.subTest(episode=episode):
                checkpoint, facts = self.sealed(episode)
                original = runtime_rubric()
                private = copy.deepcopy(BUSINESS)
                bundle = build_packet(checkpoint, facts, original, private_truth=private)
                packet = public_packet(bundle)
                self.assertIn("quality_checklists", packet["trusted"]["rubric"])
                self.assertEqual(packet["untrusted_execution"]["task"]["prompt"], PROMPT)
                self.assertEqual(packet["trusted"]["private_truth"], private)
                self.assertEqual(packet["trusted"]["rubric"]["fixed_grade_bins"], original["fixed_grade_bins"])
                for factor in ("q1", "q2", "q3"):
                    row = packet["trusted"]["rubric"]["quality_checklists"][factor][0]
                    expected = original["quality_checklists"][factor][0]
                    self.assertEqual(row["requirement"], expected["requirement"])
                    self.assertEqual(row["source_requirement"], expected["source_requirement"])
                self.assertNotEqual(packet["episode_id"], episode)
                self.assertEqual(bundle["private_audit"]["identity_map"][packet["episode_id"]], episode)

    def test_actual_native_arguments_results_snapshots_and_ordinary_messages_keep_bytes(self):
        checkpoint, facts = self.sealed("a")
        bundle = build_packet(checkpoint, facts, runtime_rubric())
        records = bundle["packet"]["untrusted_execution"]["records"]
        call = next(row["data"] for row in records if row["kind"] == "native_call")
        self.assertEqual(canonical(call["arguments"]), canonical(BUSINESS))
        self.assertEqual(canonical(call["result"]), canonical(BUSINESS))
        original = checkpoint["evidence"]["native_calls"][0]
        for field in ("before", "after", "effects"):
            self.assertEqual(canonical(call[field]), canonical(original[field]))
        for row in records:
            if row["kind"] == "state_snapshot":
                self.assertEqual(canonical(row["data"]["business"]), canonical(BUSINESS))
            if row["kind"] == "artifact":
                self.assertEqual(row["data"], "a data quality_checklists")
        sent = [row["data"] for row in records if row["kind"] == "service_call" and row["data"].get("action") == "route.send"]
        self.assertTrue(sent)
        for row in sent:
            self.assertEqual(row["arguments"]["content"], "a data quality_checklists")
            self.assertEqual(row["response"]["result"]["content"], "a data quality_checklists")
        requests = []
        judge_packet(bundle, lambda request: requests.append(request))
        self.assertEqual(len(requests), 3)
        self.assertEqual(checkpoint["evidence"]["native_calls"][0], original)

    def test_nested_nonregistry_controller_ids_mask_without_promoting_to_evidence(self):
        execution, facts, _ = fixture()
        episode = execution["episode_id"]
        suffix = "PLAIN-A4-honest"
        principal, lease, parent, session = [f"{episode}:{kind}:{suffix}" for kind in ("principal", "lease", "parent", "session")]
        state = {"episode": {"episode_id": episode, "controller": principal, "steward": principal},
                 "principals": [{"actor": "H", "principal": principal, "active_lease_id": lease, "scopes": ["route.send"], "level": "A4"}],
                 "leases": [{"lease_id": lease, "parent_id": parent, "principal": principal, "issued_by": principal, "scopes": ["route.send"], "level": "A4"}]}
        execution["evidence"]["service_calls"] = [{"episode_id": episode, "call_id": episode + ":call:2", "actor": "H", "principal": principal,
            "action": "route.consume", "arguments": {}, "before": state, "after": copy.deepcopy(state),
            "response": {"ok": True, "result": [], "effects": [], "error": None},
            "attribution": {"record_id": episode + ":extra-lineage:controller", "action_binding": {"session_id": session, "principal": principal}}}]
        execution["evidence_sha256"] = sha256(canonical(execution["evidence"]))
        bundle = build_packet(execution, facts, rubric())
        packet, audit = bundle["packet"], bundle["private_audit"]
        call = next(row["data"] for row in packet["untrusted_execution"]["records"] if row["kind"] == "service_call")
        self.assertNotIn(suffix, canonical(call).decode())
        self.assertEqual(call["before"]["leases"][0]["scopes"], ["route.send"])
        self.assertNotIn("level", call["before"]["leases"][0])
        forward = {source: blind for blind, source in audit["identity_map"].items()}
        for source in (principal, lease, parent, session):
            self.assertIn(source, forward)
            self.assertNotIn(forward[source], packet["evidence_ids"])
            self.assertIn(forward[source], audit["masked_controller_fields"])
        self.assertEqual(call["before"]["principals"][0]["principal"], forward[principal])
        self.assertEqual(call["attribution"]["action_binding"]["session_id"], forward[session])

    def test_coincidental_identity_keys_and_strings_are_not_transformed_in_business_output(self):
        execution, facts, _ = fixture()
        call_id = execution["evidence"]["native_calls"][0]["call_id"]
        payload = {call_id: call_id, "episode_id": execution["episode_id"], "text": "prefix " + call_id + " suffix"}
        execution["evidence"]["native_calls"][0]["result"] = copy.deepcopy(payload)
        execution["evidence"]["native_calls"][0]["arguments"] = copy.deepcopy(payload)
        execution["evidence_sha256"] = sha256(canonical(execution["evidence"]))
        bundle = build_packet(execution, facts, rubric())
        call = next(row["data"] for row in bundle["packet"]["untrusted_execution"]["records"] if row["kind"] == "native_call")
        self.assertEqual(canonical(call["result"]), canonical(payload))
        self.assertEqual(canonical(call["arguments"]), canonical(payload))
        self.assertNotEqual(call["call_id"], call_id)


if __name__ == "__main__":
    unittest.main()
