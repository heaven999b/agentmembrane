import json
import unittest

from agentmembrane.host_v2.rq1_collab_v1.audit import verify, strict_loads
from agentmembrane.host_v2.rq1_collab_v4.runtime import run_episode, parse_action
from agentmembrane.host_v2.rq1_collab_v4.contract import NATIVE_PROFILE, MEMORY_PROFILE
from agentmembrane.host_v2.rq1_collab_v4.evaluation import read_evidence
from agentmembrane.host_v2.rq1_measurement_v1.control_observer import derive_control_effects
from tests.rq1_collab_v3 import test_runtime_evaluation as legacy_tests
from tests.rq1_collab_v3.test_runtime_evaluation import Script, delegate, tool, final


class V4IntegrationTests(unittest.TestCase):
    setUp = legacy_tests.RuntimeTests.setUp
    setup_case = legacy_tests.RuntimeTests.setup_case

    def run_case(self, script, profile=MEMORY_PROFILE, **kwargs):
        native, bundle, cfg, collector = self.setup_case(script, **kwargs)
        result = run_episode(cfg, bundle, native, script, collector, system_profile=profile)
        self.assertTrue(verify(collector.run_dir, expected_seal_hash=result['seal']['seal_hash'])['ok'])
        data = read_evidence(collector.run_dir, result['seal']['seal_hash'])
        self.assertFalse(data['failures'], data['failures'])
        return data, script, collector

    def test_native_profile_preserves_native_dispatch(self):
        data, script, _ = self.run_case(Script(E=[final()], H=[delegate(), final()],
            S=[tool('search_calendar_events', query='Introductory meeting', date='2024-05-15'), final()]), NATIVE_PROFILE)
        self.assertEqual(len(data['native_calls']), 1)
        self.assertEqual(data['native_calls'][0]['actor'], 'S')
        self.assertEqual(data['behavioral_n'], 0)
        self.assertTrue(data['runtime_trace']['closed'])
        self.assertFalse(any(o['affected'] for o in derive_control_effects(data)['observations']))
        self.assertNotIn('memory_context', script.seen['H'][0])

    def test_memory_profile_real_service_cache_restore_and_seal(self):
        data, script, collector = self.run_case(Script(E=[final()], H=[
            tool('search_calendar_events', query='Introductory meeting', date='2024-05-15'), final()]), topology='H_E')
        self.assertTrue((collector.run_dir/'system_state/task_memory/store.sqlite').is_file())
        self.assertTrue(data['memory']['main_window_closed'])
        self.assertTrue(script.seen['H'][1]['memory_context']['values'])
        self.assertNotIn('NOT_PUBLIC_GOLD', json.dumps(script.seen['H'][0]))
        # H has A4 and the native fixture returns both events; the cache must
        # preserve exactly that already-returned projection, not narrow it.
        native_value = next(r['content']['result'] for r in script.seen['H'][1]['history']
                            if r['role']=='observation' and r['content'].get('status')=='tool_result')
        self.assertEqual(script.seen['H'][1]['memory_context']['values'][0]['value'], native_value)
        self.assertEqual(data['behavioral_n'], 0)

    def test_low_external_memory_denied_not_native_failure(self):
        def put(obs):
            return tool('memory.put', namespace='episode/'+obs['episode_id']+'/notes/E', key='x', value={'x': 1})
        data, script, _ = self.run_case(Script(E=[put, final()], H=[final()]), level='low', topology='H_E')
        self.assertEqual(data['native_calls'], [])
        self.assertEqual(script.seen['E'][0]['system_tools'], [])
        self.assertEqual(data['decisions'][0]['dispatch_domain'], 'memory')

    def test_high_external_real_H_note_write_has_truthful_writer(self):
        def put(obs):
            return tool('memory.put', namespace='episode/'+obs['episode_id']+'/notes/H', key='x', value={'x': 1})
        data, _, _ = self.run_case(Script(E=[put, final()], H=[final()]), level='high', topology='H_E')
        records = data['memory']['snapshot']['records']
        note = next(r for r in records if r['record_key'] == 'x')
        self.assertEqual(note['writer_principal'], 'E')
        self.assertEqual(note['owner_principal'], 'H')

    def test_extra_ref_on_final_rejected(self):
        with self.assertRaises(ValueError):
            parse_action(json.dumps({'type':'final','content':'x','argument_refs':{'/x':{}}}))

    def test_internal_worker_memory_closure_has_unique_bound_event_ids(self):
        data, _, _ = self.run_case(Script(E=[final()], H=[delegate(), final()], S=[
            tool('search_calendar_events', query='Introductory meeting', date='2024-05-15'), final()]))
        events = data['memory']['events']
        self.assertEqual(len(events), len({e['event_id'] for e in events}))
        self.assertTrue(all(e['event_id'].startswith(data['episode_id']+':') for e in events))
        closed = next(e for e in events if e['kind']=='memory_delegation_changed' and not e['active'])
        self.assertEqual(closed['trigger_event_id'], 'worker-finished')


if __name__ == '__main__': unittest.main()
