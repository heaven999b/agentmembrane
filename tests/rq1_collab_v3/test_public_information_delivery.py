"""Public upstream world used for receipt checks, never model research data."""
from pathlib import Path
import tempfile
import unittest

from agentmembrane.host_v2.rq1_collab_v1.admission import TaskBundle
from agentmembrane.host_v2.rq1_collab_v1.audit import EventCollector, canonical
from agentmembrane.host_v2.rq1_collab_v1.native import NativeTask
from agentmembrane.host_v2.rq1_collab_v1.policy import compile_task_policy
from agentmembrane.host_v2.rq1_collab_v3.contract import DEFAULT_BUDGET, clone, digest, make_config
from agentmembrane.host_v2.rq1_collab_v3.evaluation import derive_outcomes, read_evidence
from agentmembrane.host_v2.rq1_collab_v3.runtime import run_episode
from tests.rq1_collab_v3.test_runtime_evaluation import Script, final, tool

SOURCE = str(Path(__file__).resolve().parents[2] / 'data/host_boundary_v2/upstream/agentdojo')


class ActualPublicInformationTests(unittest.TestCase):
    def execute(self, steps, external_decisions=16):
        task = NativeTask(SOURCE, 'travel', 'user_task_2')
        # This wrapper is an engineering assertion, not admission into a study.
        payload = {'schema_version': 'rq1-task-bundle/2', 'suite': 'travel', 'original_id': 'user_task_2',
                   'source_record': clone(task.record), 'goal_admission': {'initial_goal_value': False},
                   'task_policy': compile_task_policy('travel', 'user_task_2', task.prompt),
                   'public': {'user_request': task.prompt, 'goal': {'goal': 'unit receipt check'}}}
        bundle = TaskBundle(canonical(payload), digest(payload))
        cfg = make_config(bundle.sha256, 'public-receipt-unit-only', 'H_E', 'high', 'malicious',
                          budget={**DEFAULT_BUDGET, 'external_decisions': external_decisions})
        with tempfile.TemporaryDirectory() as td:
            c = EventCollector(Path(td) / 'run', cfg['episode_id'])
            try:
                result = run_episode(cfg, bundle, task, Script(E=steps, H=[final()]), c)
                d = read_evidence(c.run_dir, result['seal']['seal_hash'])
                self.assertFalse(d['failures'])
                self.assertEqual(d['behavioral_n'], 0)
                return d, derive_outcomes(d)
            finally:
                c.abort()

    def test_actual_nine_fields_received_once_despite_repeated_views_and_calls(self):
        d, o = self.execute([tool('get_user_information'), tool('get_user_information'), final()])
        self.assertEqual(len(d['native_calls'][0]['result']), 9)
        self.assertEqual(o['external_received_fields'], 9)
        self.assertEqual(len(o['information_deliveries']), 9)
        self.assertTrue(all(r['unauthorized'] is True for r in o['information_deliveries']))
        self.assertTrue(o['observed_unauthorized_effect'])

    def test_buffered_last_tool_result_not_claimed_received(self):
        d, o = self.execute([tool('get_user_information')], external_decisions=1)
        self.assertEqual(d['native_calls'][0]['status'], 'committed')
        self.assertEqual(len(d['native_calls'][0]['result']), 9)
        self.assertEqual(o['external_received_fields'], 0)
        self.assertEqual(o['information_deliveries'], [])


if __name__ == '__main__':
    unittest.main()
