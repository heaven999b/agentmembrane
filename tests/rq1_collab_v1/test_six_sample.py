import unittest
import tempfile
from pathlib import Path
from agentmembrane.host_v2.rq1_collab_v1.audit import file_hash
from agentmembrane.host_v2.rq1_collab_v1.six_sample import TASKS, CONDITIONS, identity_matches, task_summary, verify_upstream

class SixSampleContractTests(unittest.TestCase):
    def test_exact_preregistered_coverage(self):
        self.assertEqual(len(TASKS),6)
        self.assertEqual(len(set(TASKS)),6)
        self.assertEqual(len(CONDITIONS),9)
        self.assertEqual(CONDITIONS[0],("H_ONLY","A4"))
        self.assertEqual(len({s for s,t in TASKS}),2)
    def test_source_or_prompt_swap_rejected(self):
        keys=("suite","task_id","benchmark_version","prompt_sha256","class_source_sha256","source_file_sha256",
              "initial_state_sha256","tool_schema_sha256")
        record={k:k for k in keys}
        self.assertTrue(identity_matches(record,record))
        for k in keys:
            changed=dict(record);changed[k]="wrong"
            self.assertFalse(identity_matches(changed,record))
        self.assertFalse(identity_matches({},{}))
    def test_missing_and_duplicate_states_cannot_count_as_complete(self):
        self.assertFalse(task_summary("workspace","user_task_8",[])["identical_initial_states"])
        row={"suite":"workspace","task_id":"user_task_8","arm":"H_ONLY","level":"A4","status":"executed","initial_hash":"a"}
        self.assertFalse(task_summary("workspace","user_task_8",[row])["identical_initial_states"])
        self.assertFalse(task_summary("workspace","user_task_8",[row]*9)["identical_initial_states"])
    def test_upstream_mutation_missing_or_escape_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"fixture.txt"
            path.write_text("trusted original fixture")
            locked={"fixture.txt":file_hash(path)}
            self.assertEqual(verify_upstream(directory,locked),locked)
            path.write_text("changed")
            with self.assertRaises(RuntimeError): verify_upstream(directory,locked)
            with self.assertRaises(ValueError): verify_upstream(directory,{"../escape":"0"*64})
            with self.assertRaises(ValueError): verify_upstream(directory,{})
if __name__=="__main__": unittest.main()
