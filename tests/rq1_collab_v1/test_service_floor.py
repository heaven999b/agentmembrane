"""Kernel service-level floors, independent of manifest hints or actor prose."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from agentmembrane.host_v2.rq1_collab_v1.services import ServiceError, SystemServices


BASE = ["route.send", "route.consume", "control.load"]
MEMORY = ["memory.append_note", "memory.read_notes"]
HOST_ONLY = ["capability.delegate", "capability.revoke", "memory.load_checkpoint"]


def manifest():
    return {"task_id": "service-floor-fixture", "world_id": "service-floor-world",
            "principals": {"H": "host", "E": "external"},
            "actor_levels": {"H": "A4", "E": "A4"},
            "level_caps": {"H": BASE + MEMORY + HOST_ONLY, "E": BASE + MEMORY},
            "allowed_labels": {"H": ["public"], "E": ["public"]},
            "approved_controls": [{"route_bindings": {"H": ["E"], "E": ["H"]},
                                   "tool_registry_hash": "fixture-registry", "model_config_ref": "no-model",
                                   "memory_acl": {"trusted_writer": "steward"}}]}


class ServiceFloorTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="rq1-service-floor-")
        self.path = str(Path(self.directory.name) / "services.sqlite3")
        self.service = SystemServices(self.path, "floor-episode")
        self.service.initialize("controller", manifest())
        self.h = self.service.issue_lease(None, "host", "A4", BASE + MEMORY + HOST_ONLY, "H")
        self.e = self.service.issue_lease(None, "external", "A4", BASE + MEMORY, "E")

    def tearDown(self):
        self.service.disconnect()
        self.directory.cleanup()

    def delegate(self, level, scopes):
        return self.service.dispatch("host", "H", "capability.delegate",
                                     {"actor": "E", "level": level, "scopes": scopes}, lease_id=self.h["lease_id"])

    def test_downgrade_cannot_retain_sqlite_memory_write_or_read(self):
        before = self.service.snapshot()
        for level in ("A0", "A1", "A3"):
            for scope in MEMORY:
                with self.subTest(level=level, scope=scope):
                    response = self.delegate(level, BASE + [scope])
                    self.assertFalse(response["ok"])
                    self.assertEqual(response["error"]["code"], "scope_level_mismatch")
                    self.assertEqual(response["effects"], [])
        self.assertEqual(self.service.snapshot(), before)
        self.assertEqual(self.service.snapshot()["notes"], [])

    def test_controller_initial_issuance_cannot_bypass_service_floor(self):
        for level in ("A0", "A1", "A3"):
            with self.subTest(level=level), self.assertRaises(ServiceError):
                self.service.issue_lease(None, "external", level, BASE + MEMORY, "E")
        self.assertEqual(len(self.service.snapshot()["leases"]), 2)

    def test_A4_private_and_shared_memory_remain_real_and_usable(self):
        for visibility in ("private", "shared"):
            reply = self.service.dispatch("external", "E", "memory.append_note", {"content": visibility, "visibility": visibility}, lease_id=self.e["lease_id"])
            self.assertTrue(reply["ok"])
        read = self.service.dispatch("external", "E", "memory.read_notes", {}, lease_id=self.e["lease_id"])
        self.assertEqual([row["content"] for row in read["result"]], ["private", "shared"])
        host = self.service.dispatch("host", "H", "memory.read_notes", {}, lease_id=self.h["lease_id"])
        self.assertEqual([row["content"] for row in host["result"]], ["shared"])
        self.assertEqual(len(self.service.snapshot()["notes"]), 2)

    def test_low_level_base_routes_control_and_narrowed_H_delegation_work(self):
        for level in ("A0", "A1", "A3"):
            reply = self.delegate(level, BASE)
            self.assertTrue(reply["ok"])
            lease = reply["result"]
            sent = self.service.dispatch("external", "E", "route.send", {"recipient": "H", "content": level}, lease_id=lease["lease_id"])
            self.assertTrue(sent["ok"])
            loaded = self.service.dispatch("external", "E", "control.load", {}, lease_id=lease["lease_id"])
            self.assertTrue(loaded["ok"])
            received = self.service.dispatch("host", "H", "route.consume", {}, lease_id=self.h["lease_id"])
            self.assertEqual(received["result"][0]["content"], level)
            self.assertFalse(self.service.dispatch("external", "E", "memory.append_note", {"content": "must not write", "visibility": "private"}, lease_id=lease["lease_id"])["ok"])
        self.assertEqual(self.service.snapshot()["notes"], [])
        self.assertEqual(len(self.service.snapshot()["messages"]), 3)

    def test_manifest_cannot_lower_kernel_floor(self):
        for scope in MEMORY:
            for level in ("A0", "A1", "A3"):
                with self.subTest(scope=scope, level=level):
                    other = SystemServices(str(Path(self.directory.name) / (scope + level + ".sqlite3")), scope + level)
                    altered = manifest()
                    altered["scope_min_levels"] = {scope: level}
                    try:
                        with self.assertRaises(ServiceError):
                            other.initialize("controller", altered)
                    finally:
                        other.disconnect()

    def test_manifest_may_raise_base_floor_but_not_ignore_it(self):
        other = SystemServices(str(Path(self.directory.name) / "raised.sqlite3"), "raised")
        altered = manifest()
        altered["scope_min_levels"] = {"control.load": "A3"}
        try:
            other.initialize("controller", altered)
            with self.assertRaises(ServiceError):
                other.issue_lease(None, "external", "A0", BASE, "E")
            allowed = other.issue_lease(None, "external", "A3", BASE, "E")
            self.assertTrue(other.authorize(allowed["lease_id"], "external", "control.load"))
        finally:
            other.disconnect()

    def test_stored_legacy_signed_low_lease_cannot_bypass_dispatch_floor(self):
        # Simulates a grant persisted by the previous flawed implementation.
        # Actor code never has access to the signing key or this direct SQL.
        row = dict(self.service._db.execute("SELECT * FROM leases WHERE lease_id=?", (self.e["lease_id"],)).fetchone())
        row["level"] = "A0"
        signature = self.service._sign(self.service._lease_payload(row))
        self.service._db.execute("UPDATE leases SET level=?,signature=? WHERE lease_id=?", ("A0", signature, self.e["lease_id"]))
        before = self.service.snapshot()
        for scope in MEMORY:
            self.assertFalse(self.service.authorize(self.e["lease_id"], "external", scope))
            args = {"content": "would-write", "visibility": "private"} if scope == "memory.append_note" else {}
            response = self.service.dispatch("external", "E", scope, args, lease_id=self.e["lease_id"])
            self.assertFalse(response["ok"])
            self.assertEqual(response["effects"], [])
        self.assertEqual(self.service.snapshot(), before)
        self.assertEqual(self.service.snapshot()["notes"], [])

    def test_host_only_capabilities_still_reject_external_role(self):
        for scope in HOST_ONLY:
            altered = manifest()
            altered["level_caps"]["E"].append(scope)
            other = SystemServices(str(Path(self.directory.name) / (scope + ".sqlite3")), scope)
            try:
                with self.assertRaises(ServiceError):
                    other.initialize("controller", altered)
            finally:
                other.disconnect()
        checkpoint = self.service.dispatch("host", "H", "memory.load_checkpoint", {}, lease_id=self.h["lease_id"])
        self.assertTrue(checkpoint["ok"])
        child = self.delegate("A0", BASE)["result"]
        revoked = self.service.dispatch("host", "H", "capability.revoke", {"lease_id": child["lease_id"]}, lease_id=self.h["lease_id"])
        self.assertTrue(revoked["ok"])
        self.assertFalse(self.service.authorize(child["lease_id"], "external", "route.send"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
