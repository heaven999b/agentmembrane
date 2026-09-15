"""Lifecycle fault-injection fixtures; no model calls or benchmark samples."""

import json
import os
import signal
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from agentmembrane.host_v2.rq1_collab_v1 import process_backend
from agentmembrane.host_v2.rq1_collab_v1.process_backend import NativeProcessFailure, PipeWorker
from agentmembrane.host_v2.rq1_collab_v1.services import ServiceTransactionFailure, SystemServices


def manifest():
    scopes = ["route.send", "route.consume", "control.load"]
    return {"task_id": "lifecycle-fixture", "world_id": "lifecycle-fixture-world",
            "principals": {"H": "host", "E": "external"},
            "actor_levels": {"H": "A4", "E": "A4"},
            "level_caps": {"H": scopes, "E": scopes},
            "allowed_labels": {"H": ["public"], "E": ["public"]},
            "approved_controls": [{"route_bindings": {"H": ["E"], "E": ["H"]},
                                   "tool_registry_hash": "fixture-tools", "model_config_ref": "no-model",
                                   "memory_acl": {"trusted_writer": "steward"}}]}


class FailCommitOnce:
    def __init__(self, connection, *, after=False):
        self.connection, self.after, self.failed = connection, after, False

    def execute(self, sql, *args):
        if sql == "COMMIT" and not self.failed:
            self.failed = True
            if self.after:
                self.connection.execute(sql, *args)
            raise sqlite3.OperationalError("trusted_fixture_commit_confirmation_failure")
        return self.connection.execute(sql, *args)

    def __getattr__(self, name):
        return getattr(self.connection, name)


class PipeLifecycleFaultTests(unittest.TestCase):
    def test_local_frame_limit_and_encoding_errors_do_not_consume_sequence(self):
        with PipeWorker(sys.executable, mode="probe", timeout=2) as worker:
            with patch.object(process_backend, "MAX_FRAME", 128):
                with self.assertRaises(NativeProcessFailure) as raised:
                    worker.request("probe", padding="x" * 512)
            self.assertFalse(raised.exception.commit_unknown)
            self.assertEqual(worker.seq, 0)
            self.assertFalse(worker.poisoned)
            with self.assertRaises(ValueError):
                worker.request("probe", invalid=float("nan"))
            self.assertEqual(worker.seq, 0)
            self.assertEqual(worker.request("probe")["pid"], worker.ready["pid"])
            self.assertEqual(worker.seq, 1)

    @unittest.skipUnless(hasattr(signal, "SIGSTOP"), "requires POSIX-owned-child stop/resume")
    def test_blocked_write_has_real_deadline_and_poison_prevents_replay(self):
        # Process/interpreter startup is not the write-deadline fault being
        # tested. Establish readiness first, then keep the original .15s budget.
        worker = PipeWorker(sys.executable, mode="probe", timeout=5)
        worker.timeout = 0.15
        try:
            os.kill(worker.process.pid, signal.SIGSTOP)
            started = time.monotonic()
            with self.assertRaises(NativeProcessFailure) as raised:
                worker.request("probe", padding="x" * 500_000)
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 0.65)
            self.assertTrue(raised.exception.commit_unknown)
            self.assertTrue(worker.poisoned)
            used_sequence = worker.seq
            with self.assertRaises(NativeProcessFailure) as replay:
                worker.request("probe")
            self.assertEqual(replay.exception.code, "native_worker_requires_explicit_recovery")
            self.assertEqual(worker.seq, used_sequence)
        finally:
            os.kill(worker.process.pid, signal.SIGCONT)
            worker.shutdown()

    def test_send_and_receive_share_one_deadline(self):
        with PipeWorker(sys.executable, mode="probe", timeout=1) as worker:
            deadlines = []
            original_send, original_receive = worker._send, worker._receive
            def send(frame, *, deadline):
                deadlines.append(("send", deadline))
                return original_send(frame, deadline=deadline)
            def receive(*, deadline=None, commit_unknown=True):
                deadlines.append(("receive", deadline))
                return original_receive(deadline=deadline, commit_unknown=commit_unknown)
            with patch.object(worker, "_send", side_effect=send), patch.object(worker, "_receive", side_effect=receive):
                self.assertEqual(worker.request("probe")["pid"], worker.ready["pid"])
            self.assertEqual([value[0] for value in deadlines], ["send", "receive"])
            self.assertEqual(deadlines[0][1], deadlines[1][1])

    def test_request_stream_serializes_concurrent_callers(self):
        with PipeWorker(sys.executable, mode="probe", timeout=2) as worker:
            barrier, results, failures = threading.Barrier(3), [], []
            def call():
                try:
                    barrier.wait(timeout=2)
                    for _ in range(3):
                        results.append(worker.request("probe"))
                except BaseException as error:
                    failures.append(error)
            threads = [threading.Thread(target=call) for _ in range(2)]
            for thread in threads:
                thread.start()
            barrier.wait(timeout=2)
            for thread in threads:
                thread.join(timeout=3)
            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual(failures, [])
            self.assertEqual(len(results), 6)
            self.assertEqual(worker.seq, 6)
            self.assertTrue(all(value["pid"] == worker.ready["pid"] for value in results))

    def test_busy_wait_is_bounded_and_known_unsent(self):
        with PipeWorker(sys.executable, mode="probe", timeout=5) as worker:
            worker.timeout = 0.15
            worker._request_lock.acquire()
            try:
                with self.assertRaises(NativeProcessFailure) as raised:
                    worker.request("probe")
                self.assertEqual(raised.exception.code, "native_worker_request_busy")
                self.assertFalse(raised.exception.commit_unknown)
                self.assertEqual(worker.seq, 0)
                self.assertFalse(worker.poisoned)
            finally:
                worker._request_lock.release()
            self.assertEqual(worker.request("probe")["pid"], worker.ready["pid"])


class ServiceCommitFaultTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="rq1-lifecycle-faults-")
        self.path = str(Path(self.directory.name) / "services.sqlite3")
        self.service = SystemServices(self.path, "fault-episode")
        self.service.initialize("controller", manifest())
        self.host = self.service.issue_lease(None, "host", "A4", manifest()["level_caps"]["H"], "H")
        self.external = self.service.issue_lease(None, "external", "A4", manifest()["level_caps"]["E"], "E")

    def tearDown(self):
        self.service.disconnect()
        self.directory.cleanup()

    def send(self):
        return self.service.dispatch("host", "H", "route.send", {"recipient": "E", "content": "fixture-message"}, lease_id=self.host["lease_id"])

    def test_pre_commit_failure_rolls_back_clears_transaction_and_closes(self):
        actual = self.service._db
        self.service._db = FailCommitOnce(actual)
        with self.assertRaises(ServiceTransactionFailure) as raised:
            self.send()
        self.assertTrue(raised.exception.commit_unknown)
        self.assertFalse(actual.in_transaction)
        self.assertEqual(raised.exception.fault["rollback_status"], "active_transaction_rolled_back")
        snapshot = self.service.snapshot()
        self.assertEqual(snapshot["messages"], [])
        self.assertFalse(any(value["kind"] == "mailbox_sent" for value in snapshot["audit"]))
        self.assertEqual(len(snapshot["transaction_failures"]), 1)
        self.assertFalse(self.send()["ok"])
        self.assertEqual(self.service.close()["status"], "closed")
        self.assertFalse(self.service.authorize(self.host["lease_id"], "host", "route.send"))

    def test_post_commit_failure_preserves_real_effect_and_forbids_replay(self):
        actual = self.service._db
        self.service._db = FailCommitOnce(actual, after=True)
        with self.assertRaises(ServiceTransactionFailure) as raised:
            self.send()
        self.assertTrue(raised.exception.commit_unknown)
        self.assertFalse(actual.in_transaction)
        self.assertEqual(raised.exception.fault["rollback_status"], "no_active_transaction_outcome_not_inferred")
        snapshot = self.service.snapshot()
        self.assertEqual(len(snapshot["messages"]), 1)
        self.assertEqual(snapshot["messages"][0]["content"], "fixture-message")
        self.assertEqual(sum(value["kind"] == "mailbox_sent" for value in snapshot["audit"]), 1)
        self.assertFalse(self.send()["ok"])
        self.assertEqual(len(self.service.snapshot()["messages"]), 1)
        self.service.close()
        fresh = SystemServices(self.path, "fault-episode")
        try:
            reopened = fresh.snapshot()
            self.assertEqual(len(reopened["messages"]), 1)
            self.assertTrue(reopened["transaction_failures"][0]["commit_unknown"])
            self.assertEqual(reopened["episode"]["status"], "closed")
            self.assertFalse(fresh.authorize(self.host["lease_id"], "host", "route.send"))
        finally:
            fresh.disconnect()

    def test_fresh_connection_cannot_erase_uncertainty_and_resume_actor(self):
        self.service._db = FailCommitOnce(self.service._db, after=True)
        with self.assertRaises(ServiceTransactionFailure):
            self.send()
        fresh = SystemServices(self.path, "fault-episode")
        try:
            self.assertFalse(fresh.authorize(self.host["lease_id"], "host", "route.send"))
            response = fresh.dispatch("host", "H", "route.send", {"recipient": "E", "content": "would-repeat"}, lease_id=self.host["lease_id"])
            self.assertEqual(response["error"]["code"], "service_admission_faulted")
            self.assertEqual(len(fresh.snapshot()["messages"]), 1)
            self.assertEqual(fresh.close()["status"], "closed")
        finally:
            fresh.disconnect()

    def test_failed_close_commit_can_be_retried_without_active_transaction(self):
        self.service._db = FailCommitOnce(self.service._db)
        with self.assertRaises(ServiceTransactionFailure):
            self.service.close()
        self.assertFalse(self.service._db.in_transaction)
        closed = self.service.close()
        self.assertEqual(closed["status"], "closed")
        self.assertFalse(self.service.authorize(self.external["lease_id"], "external", "route.send"))
        self.assertTrue(self.service.snapshot()["transaction_failures"])

    def test_fault_journal_is_secret_free_and_matches_reopened_evidence(self):
        self.service._db = FailCommitOnce(self.service._db)
        with self.assertRaises(ServiceTransactionFailure):
            self.send()
        path = Path(self.path + ".transaction_failures.jsonl")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        raw = path.read_text()
        self.assertNotIn("fixture-message", raw)
        self.assertNotIn("signing_key", raw)
        self.assertEqual(json.loads(raw)["episode_id"], "fault-episode")
        fresh = SystemServices(self.path, "fault-episode")
        try:
            self.assertEqual(fresh.snapshot()["transaction_failures"], self.service.snapshot()["transaction_failures"])
        finally:
            fresh.disconnect()


if __name__ == "__main__":
    unittest.main(verbosity=2)
