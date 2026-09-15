import os
import sys
import unittest
from unittest.mock import patch
from agentmembrane.host_v2.rq1_collab_v1.process_backend import PipeWorker, NativeProcessFailure
from agentmembrane.host_v2.rq1_collab_v1.process_backend import _loads

class ProcessTests(unittest.TestCase):
    def test_nested_numeric_overflow_not_json(self):
        with self.assertRaises(ValueError): _loads(b'{"params":{"x":1e999}}')
    def test_real_process_no_ambient_credentials_or_identity_override(self):
        with patch.dict(os.environ,{"RQ1_FAKE_TEST_SECRET":"not-a-real-key"}):
            with PipeWorker(sys.executable,mode="probe",timeout=10) as worker:
                actual=worker.request("probe")
                self.assertNotEqual(actual["pid"],os.getpid())
                self.assertNotIn("RQ1_FAKE_TEST_SECRET",actual["env_names"])
                self.assertNotIn("HOME",actual["env_names"])
                self.assertEqual(worker.ready["isolation"],"same_uid_not_security_boundary")
                with self.assertRaises(NativeProcessFailure): worker.request("score")
                with self.assertRaises(NativeProcessFailure): worker.request("probe",actor="controller")
    def test_closed_worker_cannot_restart(self):
        worker=PipeWorker(sys.executable,mode="probe",timeout=10)
        worker.shutdown()
        with self.assertRaises(NativeProcessFailure): worker.request("probe")
        self.assertIsNotNone(worker.process.returncode)

    def test_unknown_response_poison_prevents_next_dispatch(self):
        worker=PipeWorker(sys.executable,mode="probe",timeout=10)
        try:
            with patch.object(worker,"_receive",side_effect=NativeProcessFailure("timeout",commit_unknown=True)):
                with self.assertRaises(NativeProcessFailure): worker.request("probe")
            self.assertTrue(worker.poisoned)
            sequence=worker.seq
            with self.assertRaises(NativeProcessFailure): worker.request("probe")
            self.assertEqual(worker.seq,sequence)
        finally: worker.shutdown()

if __name__=="__main__": unittest.main()
