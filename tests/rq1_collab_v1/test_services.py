"""Trusted engineering probes. None of these are behavioral/benchmark samples."""

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from agentmembrane.host_v2.rq1_collab_v1.services import ServiceError, SystemServices


BASE = ["route.send", "route.consume", "control.load"]
COMMON = BASE + ["memory.append_note", "memory.read_notes"]
HOST = COMMON + ["memory.load_checkpoint", "capability.delegate", "capability.revoke",
                 "tool:calendar.get", "tool:calendar.add", "tool:mail.send"]
EXTERNAL = COMMON + ["tool:calendar.get", "tool:calendar.add", "tool:mail.send"]
CONTROL = {"route_bindings": {"H": ["E", "B"], "E": ["H", "B"], "B": ["H"]}, "tool_registry_hash": "registry-locked",
           "memory_acl": {"trusted_writer": "steward"}, "model_config_ref": "models/profile-locked"}
CONTROL2 = {**CONTROL, "model_config_ref": "models/recovery-approved"}


def manifest(level="A4"):
    tools = [] if level in {"A0", "A1"} else ["tool:calendar.get", "tool:calendar.add"]
    if level == "A4":
        tools.append("tool:mail.send")
    return {"task_id": "workspace/UserTask8", "world_id": "original-world-sha256",
            "principals": {"H": "host", "E": "external", "B": "benign-peer"},
            "actor_levels": {"H": "A4", "E": level, "B": "A3"},
            "level_caps": {"H": HOST, "E": (COMMON if level == "A4" else BASE) + tools, "B": BASE},
            "allowed_labels": {"H": ["public", "protected"],
                               "E": ["public", "protected"] if level in {"A3", "A4"} else ["public"],
                               "B": ["public", "protected"]},
            "scope_min_levels": {"tool:calendar.get": "A3", "tool:calendar.add": "A3", "tool:mail.send": "A4"},
            "approved_controls": [CONTROL, CONTROL2]}


class ServicesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="rq1-services-")
        self.path = str(Path(self.tmp.name) / "services.sqlite3")
        self.services = SystemServices(self.path, "episode-1")
        self.m = manifest()
        self.services.initialize("controller", self.m)
        self.h = self.services.issue_lease(None, "host", "A4", HOST, "H")
        self.e = self.services.issue_lease(None, "external", "A4", EXTERNAL, "E")
        self.b = self.services.issue_lease(None, "benign-peer", "A3", BASE, "B")

    def tearDown(self):
        self.services.disconnect()
        self.tmp.cleanup()

    def call(self, actor, action, arguments=None, lease=None, principal=None):
        values = {"H": (self.h, "host"), "E": (self.e, "external"), "B": (self.b, "benign-peer")}
        selected, identity = values[actor]
        return self.services.dispatch(principal or identity, actor, action, arguments or {},
                                      lease_id=(lease or selected)["lease_id"])

    def receipt(self, receipt_id="r1", status="committed"):
        return {"receipt_id": receipt_id, "task_id": self.m["task_id"], "world_id": self.m["world_id"],
                "status": status, "state_hash": "terminal-state-hash", "labels": ["protected"],
                "call_id": "call-1", "actor": "E", "tool": "calendar.add"}

    def test_initialization_is_idempotent_not_reset(self):
        result = self.services.initialize("controller", self.m)
        self.assertEqual(result["effects"], [])
        self.assertEqual(len(self.services.snapshot()["leases"]), 3)
        self.services.close()
        self.assertEqual(self.services.initialize("controller", self.m)["status"], "closed")
        self.assertFalse(self.services.authorize(self.e["lease_id"], "external", "route.send"))
        with self.assertRaises(ServiceError):
            self.services.initialize("controller", {**self.m, "world_id": "other"})

    def test_episode_file_and_identity_binding(self):
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)
        with self.assertRaises(ServiceError):
            SystemServices(self.path, "episode-else")
        self.assertFalse(self.services.authorize(self.e["lease_id"], "host", "route.send"))
        spoofed = self.services.dispatch("external", "H", "route.send", {"recipient": "B", "content": "x"}, lease_id=self.e["lease_id"])
        self.assertEqual(spoofed["error"]["code"], "identity_mismatch")
        self.assertEqual(self.services.snapshot()["messages"], [])

    def test_privileged_text_is_never_dispatchable(self):
        for action in ("control.commit", "memory.commit_checkpoint", "initialize", "record_receipt", "issue_lease"):
            result = self.call("E", action, {"actor": "controller", "issuer": "controller"})
            self.assertFalse(result["ok"], action)
            self.assertEqual(result["effects"], [])
        self.assertEqual(self.services.snapshot()["checkpoints"], [])
        self.assertEqual(len(self.services.snapshot()["controls"]), 1)

    def test_extra_fields_cannot_supply_identity_or_override_namespace(self):
        for action, args in (("route.send", {"recipient": "H", "content": "x", "sender": "H"}),
                             ("memory.append_note", {"content": "x", "actor": "H"}),
                             ("route.consume", {"recipient": "H"}),
                             ("capability.delegate", {"actor": "E", "level": "A0", "scopes": [], "parent_id": self.e["lease_id"]})):
            result = self.call("H", action, args)
            self.assertEqual(result["error"]["code"], "invalid_arguments")
        self.assertFalse(self.call("H", "capability.delegate", {"actor": "E", "level": [], "scopes": []})["ok"])

    def test_scopes_and_epoch_checked(self):
        self.assertTrue(self.services.authorize(self.e["lease_id"], "external", "tool:mail.send", epoch=0))
        self.assertFalse(self.services.authorize(self.e["lease_id"], "external", "tool:unknown"))
        self.assertFalse(self.services.authorize(self.e["lease_id"], "external", "tool:mail.send", epoch=1))
        self.assertFalse(self.services.authorize(self.e["lease_id"] + "x", "external", "route.send"))

    def test_parent_child_effective_narrowing(self):
        result = self.call("H", "capability.delegate", {"actor": "E", "level": "A0", "scopes": ["route.send"]})
        self.assertTrue(result["ok"])
        child = result["result"]
        self.assertEqual(child["parent_id"], self.h["lease_id"])
        self.assertEqual(child["principal"], "external")
        self.assertLessEqual(child["expires_at"], self.h["expires_at"])
        self.assertTrue(self.services.authorize(child["lease_id"], "external", "route.send"))
        self.assertFalse(self.services.authorize(child["lease_id"], "external", "tool:mail.send"))
        self.assertFalse(self.call("H", "capability.delegate", {"actor": "E", "level": "A0", "scopes": ["tool:mail.send"]})["ok"])
        self.assertFalse(self.call("H", "capability.delegate", {"actor": "E", "principal": "host", "level": "A0", "scopes": []})["ok"])
        self.assertFalse(self.call("H", "capability.delegate", {"actor": "NEW", "level": "A0", "scopes": []})["ok"])

    def test_no_delegation_ambient_authority_or_self_grant(self):
        with self.assertRaises(ServiceError):
            self.services.issue_lease(None, "external", "A4", EXTERNAL, "E", issuer="external")
        self.assertFalse(self.call("E", "capability.delegate", {"actor": "B", "level": "A0", "scopes": []})["ok"])
        self.assertFalse(self.call("H", "capability.delegate", {"actor": "H", "level": "A4", "scopes": HOST})["ok"])
        narrow_h = self.services.issue_lease(None, "host", "A4", ["capability.delegate", "route.send"], "H")
        result = self.call("H", "capability.delegate", {"actor": "E", "level": "A4", "scopes": ["tool:mail.send"]}, lease=narrow_h)
        self.assertEqual(result["error"]["code"], "delegation_expansion")

    def test_revocation_cascades_without_revoking_other_roots(self):
        child = self.call("H", "capability.delegate", {"actor": "E", "level": "A0", "scopes": ["route.send"]})["result"]
        self.assertFalse(self.call("H", "capability.revoke", {"lease_id": self.e["lease_id"]})["ok"])
        self.services.revoke(self.h["lease_id"])
        self.assertFalse(self.services.authorize(child["lease_id"], "external", "route.send"))
        self.assertFalse(self.services.authorize(self.e["lease_id"], "external", "route.send"))
        self.assertTrue(self.services.authorize(self.b["lease_id"], "benign-peer", "route.send"))

    def test_host_can_revoke_own_child(self):
        child = self.call("H", "capability.delegate", {"actor": "E", "level": "A0", "scopes": ["route.send"]})["result"]
        result = self.call("H", "capability.revoke", {"lease_id": child["lease_id"]})
        self.assertTrue(result["ok"])
        self.assertTrue(result["result"]["revoked"])
        self.assertFalse(self.services.authorize(child["lease_id"], "external", "route.send"))

    def test_hmac_rejects_database_grant_tamper(self):
        # Trusted engineering fault injection, not an exposed actor write path.
        self.services._db.execute("UPDATE leases SET scopes=? WHERE lease_id=?", (json.dumps(EXTERNAL + ["tool:admin"]), self.e["lease_id"]))
        self.assertFalse(self.services.authorize(self.e["lease_id"], "external", "route.send"))

    def test_private_notes_and_shared_quarantine_are_real(self):
        private = self.call("E", "memory.append_note", {"content": "private scratch"})
        self.assertTrue(private["ok"])
        shared = self.call("E", "memory.append_note", {"content": "not trusted truth", "visibility": "shared"})
        self.assertTrue(shared["ok"])
        h_notes = self.call("H", "memory.read_notes")["result"]
        e_notes = self.call("E", "memory.read_notes")["result"]
        self.assertEqual([row["content"] for row in h_notes], ["not trusted truth"])
        self.assertEqual(len(e_notes), 2)
        self.assertEqual(self.services.snapshot()["checkpoints"], [])
        fresh = SystemServices(self.path, "episode-1")
        try:
            self.assertEqual(len(fresh.snapshot()["notes"]), 2)
        finally:
            fresh.disconnect()

    def test_level_dependent_routes_and_shared_notes(self):
        low = self.services.issue_lease(None, "external", "A0", BASE, "E")
        self.assertFalse(self.call("E", "route.send", {"recipient": "B", "content": "x"}, lease=low)["ok"])
        self.assertTrue(self.call("E", "route.send", {"recipient": "H", "content": "x"}, lease=low)["ok"])
        self.assertFalse(self.call("E", "memory.append_note", {"content": "x", "visibility": "shared"}, lease=low)["ok"])
        # The four-level experiment puts persistent notes at A4, including
        # private notes; A0 is not an implicit persistent storage grant.
        self.assertFalse(self.call("E", "memory.append_note", {"content": "x"}, lease=low)["ok"])
        self.assertEqual(self.services.snapshot()["notes"], [])
        self.assertFalse(self.call("E", "route.send", {"recipient": "B", "content": "x"})["ok"])
        high = self.services.issue_lease(None, "external", "A4", EXTERNAL, "E")
        self.assertTrue(self.call("E", "route.send", {"recipient": "B", "content": "x"}, lease=high)["ok"])

    def test_downgrade_revokes_old_lease_and_restricts_recipient_labels(self):
        low = self.services.issue_lease(None, "external", "A0", BASE, "E")
        self.assertFalse(self.services.authorize(self.e["lease_id"], "external", "route.send"))
        self.assertTrue(self.services.authorize(low["lease_id"], "external", "route.send"))
        self.services.record_delivery("host", "H", ["protected"])
        self.assertFalse(self.call("H", "route.send", {"recipient": "E", "content": "must not deliver"})["ok"])
        with self.assertRaises(ServiceError):
            self.services.refresh_recipient_labels("external", "E", ["public", "protected"], lease_id=low["lease_id"])

    def test_object_labels_are_refreshed_from_trusted_current_scope(self):
        low = self.services.issue_lease(None, "external", "A3", BASE, "E")
        self.services.refresh_recipient_labels("external", "E", ["public", "protected:calendar:event:24"], lease_id=low["lease_id"])
        self.services.record_delivery("host", "H", ["protected:calendar:event:other"])
        denied = self.call("H", "route.send", {"recipient": "E", "content": "summary"})
        self.assertEqual(denied["error"]["code"], "information_flow_denied")
        with self.assertRaises(ServiceError):
            self.services.refresh_recipient_labels("external", "E", ["protected:workspace"], lease_id=low["lease_id"])

    def test_mailbox_receipt_consumed_once_by_real_recipient(self):
        result = self.call("E", "route.send", {"recipient": "H", "content": "confirmed artifact ref"})
        message_id = result["result"]["message_id"]
        self.assertFalse(self.services.snapshot()["messages"][0]["consumed"])
        self.assertEqual(self.call("B", "route.consume")["result"], [])
        delivered = self.call("H", "route.consume")["result"]
        self.assertEqual(delivered[0]["message_id"], message_id)
        self.assertTrue(delivered[0]["consumed"])
        self.assertEqual(self.call("H", "route.consume")["result"], [])
        self.assertTrue(self.services.snapshot()["messages"][0]["consumed"])

    def test_label_propagation_cannot_be_omitted_or_downgraded(self):
        self.services.record_delivery("external", "E", ["protected"])
        sent = self.call("E", "route.send", {"recipient": "H", "content": "summary", "labels": ["public"]})
        self.assertEqual(sent["result"]["labels"], ["protected", "public"])
        self.call("H", "route.consume")
        h = next(row for row in self.services.snapshot()["principals"] if row["actor"] == "H")
        self.assertEqual(h["context_labels"], ["protected", "public"])
        self.services.record_delivery("host", "H", ["not-visible-to-E"])
        self.assertEqual(self.call("H", "route.send", {"recipient": "E", "content": "summary"})["error"]["code"], "information_flow_denied")
        self.assertEqual(len(self.services.snapshot()["messages"]), 1)

    def test_protected_to_low_actor_rejected_before_mailbox_write(self):
        path = str(Path(self.tmp.name) / "low.sqlite3")
        low = SystemServices(path, "low")
        try:
            low.initialize("controller", manifest("A0"))
            h = low.issue_lease(None, "host", "A4", HOST, "H")
            low.record_delivery("host", "H", ["protected"])
            result = low.dispatch("host", "H", "route.send", {"recipient": "E", "content": "claimed harmless"}, lease_id=h["lease_id"])
            self.assertFalse(result["ok"])
            self.assertEqual(low.snapshot()["messages"], [])
        finally:
            low.disconnect()

    def test_checkpoint_requires_real_same_world_confirmed_receipts(self):
        with self.assertRaises(ServiceError):
            self.services.commit_checkpoint(["missing"])
        with self.assertRaises(ServiceError):
            self.services.record_receipt({**self.receipt(), "world_id": "other"})
        self.services.record_receipt(self.receipt("unknown", "commit_unknown"))
        with self.assertRaises(ServiceError):
            self.services.commit_checkpoint(["unknown"])
        self.services.record_receipt(self.receipt())
        with self.assertRaises(ServiceError):
            self.services.commit_checkpoint(["r1"], issuer="external")
        checkpoint = self.services.commit_checkpoint(["r1"])
        self.assertEqual(checkpoint["receipts"][0]["receipt_id"], "r1")
        self.assertNotIn("content", checkpoint)
        loaded = self.call("H", "memory.load_checkpoint")["result"]
        self.assertEqual(loaded["checkpoint_id"], checkpoint["checkpoint_id"])
        self.assertFalse(self.call("E", "memory.load_checkpoint")["ok"])

    def test_checkpoint_has_no_free_text_promotion_and_receipts_immutable(self):
        with self.assertRaises(ServiceError):
            self.services.record_receipt({**self.receipt(), "assistant_claim": "everything is safe"})
        self.services.record_receipt(self.receipt())
        self.assertEqual(self.services.record_receipt(self.receipt())["effects"], [])
        with self.assertRaises(ServiceError):
            self.services.record_receipt({**self.receipt(), "state_hash": "changed"})
        checkpoint = self.services.commit_checkpoint(["r1"])
        self.assertEqual(self.services.commit_checkpoint(["r1"])["effects"], [])
        self.services._db.execute("UPDATE receipts SET payload=? WHERE receipt_id='r1'", (json.dumps({**self.receipt(), "state_hash": "tampered"}),))
        with self.assertRaises(ServiceError):
            self.services.load_checkpoint(checkpoint["checkpoint_id"])
        self.assertFalse(self.call("H", "memory.load_checkpoint")["ok"])

    def test_control_is_versioned_approved_and_actually_loaded(self):
        self.assertEqual(self.services.load_control()["manifest"], CONTROL)
        self.assertEqual(self.call("E", "control.load")["result"], {"version": 1, "manifest_hash": self.services.load_control()["manifest_hash"]})
        with self.assertRaises(ServiceError):
            self.services.commit_control(CONTROL2, issuer="external")
        with self.assertRaises(ServiceError):
            self.services.commit_control({**CONTROL, "model_config_ref": "unapproved"})
        self.services.commit_control(CONTROL2)
        loaded = self.services.load_control()
        self.assertEqual(loaded["version"], 2)
        self.assertEqual(loaded["manifest"], CONTROL2)
        self.assertNotIn("manifest", self.call("E", "control.load")["result"])
        self.assertEqual(sum(row["active"] for row in self.services.snapshot()["controls"]), 1)

    def test_control_tamper_not_silently_used(self):
        self.services._db.execute("UPDATE controls SET manifest_hash='wrong' WHERE active=1")
        with self.assertRaises(ServiceError):
            self.services.load_control()
        self.assertFalse(self.call("E", "control.load")["ok"])

    def test_active_route_control_changes_real_send_and_queued_consume(self):
        path = str(Path(self.tmp.name) / "route-change.sqlite3")
        controls = manifest()
        blocked = {**CONTROL, "route_bindings": {"H": [], "E": [], "B": []}}
        controls["approved_controls"].append(blocked)
        service = SystemServices(path, "route-change")
        try:
            service.initialize("controller", controls)
            h = service.issue_lease(None, "host", "A4", HOST, "H")
            e = service.issue_lease(None, "external", "A4", EXTERNAL, "E")
            first = service.dispatch("host", "H", "route.send", {"recipient": "E", "content": "queued"}, lease_id=h["lease_id"])
            self.assertTrue(first["ok"])
            service.commit_control(blocked)
            second = service.dispatch("host", "H", "route.send", {"recipient": "E", "content": "blocked"}, lease_id=h["lease_id"])
            self.assertEqual(second["error"]["code"], "route_binding_denied")
            consume = service.dispatch("external", "E", "route.consume", {}, lease_id=e["lease_id"])
            self.assertFalse(consume["ok"])
            self.assertFalse(service.snapshot()["messages"][0]["consumed"])
        finally:
            service.disconnect()

    def test_snapshot_excludes_secret_and_effects_match_transactional_audit(self):
        result = self.call("E", "route.send", {"recipient": "H", "content": "x"})
        snap = self.services.snapshot()
        self.assertNotIn("signing_key", json.dumps(snap))
        self.assertNotIn("signature", json.dumps(snap))
        by_seq = {row["service_seq"]: row for row in snap["audit"]}
        for effect in result["effects"]:
            self.assertEqual(effect, by_seq[effect["service_seq"]])
        self.assertEqual(snap["audit"][-1]["after"], result["result"])

    def test_fresh_process_preserves_checkpoint_and_closed_revocation(self):
        self.services.record_receipt(self.receipt())
        checkpoint = self.services.commit_checkpoint(["r1"])
        self.services.close()
        script = (
            "import json,sys;sys.path.insert(0,sys.argv[1]);"
            "from agentmembrane.host_v2.rq1_collab_v1.services import SystemServices;"
            "s=SystemServices(sys.argv[2],'episode-1');"
            "print(json.dumps({'checkpoint':s.load_checkpoint(),'allowed':s.authorize(sys.argv[3],'external','route.send'),"
            "'control':s.load_control(),'epoch':s.snapshot()['episode']['epoch']}));s.disconnect()"
        )
        # Match the production fresh reader: no site/.pth/user config and no
        # inherited credentials; a stuck child must fail in bounded time.
        run = subprocess.run([sys.executable, "-I", "-S", "-c", script,
            str(Path(__file__).resolve().parents[2]), self.path, self.e["lease_id"]],
            capture_output=True, text=True, check=True, timeout=15, env={"PATH": "/usr/bin:/bin"})
        loaded = json.loads(run.stdout)
        self.assertEqual(loaded["checkpoint"]["checkpoint_id"], checkpoint["checkpoint_id"])
        self.assertFalse(loaded["allowed"])
        self.assertEqual(loaded["epoch"], 1)
        self.assertEqual(loaded["control"]["manifest"], CONTROL)

    def test_close_rejects_replay_and_new_issuance_but_records_late_effects(self):
        result = self.services.close()
        self.assertEqual(result["revoked_count"], 3)
        self.assertEqual(self.services.close()["effects"], [])
        self.assertFalse(self.call("E", "route.send", {"recipient": "H", "content": "late"})["ok"])
        with self.assertRaises(ServiceError):
            self.services.issue_lease(None, "external", "A4", EXTERNAL, "E")
        self.services.record_receipt(self.receipt("late-confirmed"))
        self.assertEqual(self.services.snapshot()["receipts"][0]["receipt_id"], "late-confirmed")
        self.assertEqual(self.services.snapshot()["messages"], [])

    def test_concurrent_close_linearizes_with_another_connection(self):
        worker = SystemServices(self.path, "episode-1")
        barrier = threading.Barrier(2)
        outcomes, errors = [], []
        def run_sender():
            try:
                barrier.wait(timeout=5)
                for i in range(80):
                    outcomes.append(worker.dispatch("external", "E", "route.send", {"recipient": "H", "content": str(i)}, lease_id=self.e["lease_id"]))
            except BaseException as error:
                errors.append(error)
        thread = threading.Thread(target=run_sender)
        thread.start()
        barrier.wait(timeout=5)
        self.services.close()
        thread.join(timeout=10)
        worker.disconnect()
        self.assertFalse(thread.is_alive())
        self.assertFalse(errors)
        self.assertEqual(len(outcomes), 80)
        audit = self.services.snapshot()["audit"]
        close_seq = next(row["service_seq"] for row in audit if row["kind"] == "episode_closed")
        self.assertTrue(all(row["service_seq"] < close_seq for row in audit if row["kind"] == "mailbox_sent"))
        self.assertFalse(self.call("E", "route.send", {"recipient": "H", "content": "after"})["ok"])

    def test_errors_rollback_partial_consume(self):
        self.call("E", "route.send", {"recipient": "H", "content": "first"})
        self.call("E", "route.send", {"recipient": "H", "content": "second"})
        last = self.services.snapshot()["messages"][-1]["message_id"]
        self.services._db.execute("UPDATE messages SET labels=? WHERE message_id=?", ('["unknown-label"]', last))
        before = len(self.services.snapshot()["audit"])
        result = self.call("H", "route.consume")
        self.assertFalse(result["ok"])
        snap = self.services.snapshot()
        self.assertTrue(all(not row["consumed"] for row in snap["messages"]))
        self.assertEqual(len(snap["audit"]), before)

    def test_nonfinite_and_duplicate_lists_rejected(self):
        result = self.call("E", "route.send", {"recipient": "H", "content": "x", "labels": ["public", "public"]})
        self.assertFalse(result["ok"])
        result = self.call("E", "route.consume", {"limit": float("nan")})
        self.assertEqual(result["error"]["code"], "invalid_json")
        self.assertEqual(self.services.snapshot()["messages"], [])

    def test_wrong_scalar_types_and_deep_json_do_not_crash_dispatch(self):
        cases = [("route.send", {"recipient": "H", "content": "x"}),
                 ("memory.append_note", {"content": "x", "visibility": "private"}),
                 ("memory.read_notes", {"visibility": "accessible"}),
                 ("capability.delegate", {"actor": "E", "level": "A0", "scopes": []}),
                 ("memory.load_checkpoint", {"checkpoint_id": "unknown"})]
        for action, arguments in cases:
            for field in arguments:
                for invalid in ([], {}, None, 1, True, 1.5):
                    if field == "scopes" and invalid == []:
                        continue
                    with self.subTest(action=action, field=field, invalid=invalid):
                        result = self.call("H", action, {**arguments, field: invalid})
                        self.assertFalse(result["ok"])
        deep = {}
        for _ in range(70):
            deep = {"nested": deep}
        result = self.call("E", "route.consume", deep)
        self.assertEqual(result["error"]["code"], "invalid_json")


if __name__ == "__main__":
    unittest.main()
