import json
import time
import unittest

from agentmembrane.host_v2.rq1_collab_v1.providers import HTTPReply, ProviderFailure, build_action_payload
from agentmembrane.host_v2.rq1_collab_v3.contract import (
    DEFAULT_BUDGET, DEFAULT_MODELS, PROTOCOL, clone, make_config, matrix, model_readiness, validate_config,
)
from agentmembrane.host_v2.rq1_collab_v3.driver import RoleModelDriver, role_prompts
from agentmembrane.host_v2.rq1_collab_v3.runtime import behavioral_episode_count, parse_action
from tests.rq1_collab_v1.test_provider_action_protocol import Collector


def config(**kwargs):
    return make_config('a' * 64, 'unit', 'H_S_E', 'medium', 'malicious', **kwargs)


class ContractTests(unittest.TestCase):
    def test_complete_matched_matrix(self):
        cells = matrix('a' * 64, 'unit')
        self.assertEqual(len(cells), 36)
        self.assertEqual(len({c['episode_id'] for c in cells}), 36)
        self.assertEqual({c['level'] for c in cells}, {'low', 'medium', 'high'})
        self.assertTrue(all(c['budget'] == DEFAULT_BUDGET for c in cells))
        self.assertTrue(all(c['models']['H'] == DEFAULT_MODELS['H'] for c in cells))
        self.assertTrue(all(c['models']['E'] == DEFAULT_MODELS['E'] for c in cells))
        self.assertEqual(set(cells[0]['models']), {'H', 'E'})

    def test_models_reasoning_and_exact_no_fallback(self):
        c = config()
        self.assertEqual(c['models']['H']['reasoning_effort'], 'medium')
        self.assertEqual(c['models']['E']['reasoning_effort'], 'high')
        self.assertNotIn('reasoning_effort', c['models']['S'])
        r = model_readiness(c, {'model_ids': ['gpt-5.5', 'gpt-5', 'gpt-4o']})
        self.assertFalse(r['listed'])
        self.assertFalse(r['automatic_substitution'])
        c['models']['S']['reasoning_effort'] = 'low'
        with self.assertRaisesRegex(ValueError, 'gpt4o'):
            validate_config(c)

    def test_v3_schema_does_not_change_v2(self):
        payload = build_action_payload(DEFAULT_MODELS['H'], 'role', {'protocol_version': PROTOCOL}, 'single_tool_v1')
        props = payload['tools'][0]['function']['parameters']['properties']
        self.assertEqual(props['recipient']['enum'], ['H', 'S', 'E'])
        self.assertIn('delegate', props['type']['enum'])
        old = build_action_payload(DEFAULT_MODELS['H'], 'role', {'protocol_version': 'rq1-multifactor/2'}, 'single_tool_v1')
        self.assertNotIn('delegate', old['tools'][0]['function']['parameters']['properties']['type']['enum'])
        self.assertNotIn('S', old['tools'][0]['function']['parameters']['properties']['recipient']['enum'])

    def test_parser_rejects_identity_forgery_bad_refs_and_ambiguous_json(self):
        for raw in ['{"type":"final","content":"done","actor":"H"}',
                    '{"type":"final","content":"x","source_refs":["x","x"]}',
                    '{"type":"final","content":"x","content":"y"}',
                    '{"type":"delegate","recipient":"S","content":"x"}',
                    '{"type":"tool_action","tool":"x","arguments":{"v":NaN}}']:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_action(raw)

    def test_attacker_goal_not_in_internal_prompts(self):
        prompts = role_prompts(config(), 'PUBLIC_REQUEST', 'ATTACKER_ONLY_OBJECTIVE')
        self.assertNotIn('ATTACKER_ONLY_OBJECTIVE', prompts['H'] + prompts['S'])
        self.assertIn('ATTACKER_ONLY_OBJECTIVE', prompts['E'])

    def test_delivered_refusal_counts_even_without_parsed_actions(self):
        self.assertEqual(behavioral_episode_count('live_diagnostic', [{'status': 'model_response_observed'}]), 1)
        self.assertEqual(behavioral_episode_count('live_diagnostic', [{'status': 'delivery_unknown'}]), 0)
        self.assertEqual(behavioral_episode_count('engineering', [{'status': 'engineering_driver_received'}]), 0)


class RoleDriverTests(unittest.TestCase):
    def driver(self, cfg=None, mismatch=False):
        cfg = config() if cfg is None else cfg
        self.sent = []
        def transport(body):
            p = json.loads(body)
            self.sent.append(p)
            response = {'model': 'wrong-model' if mismatch else p['model'], 'choices': [
                {'index': 0, 'finish_reason': 'tool_calls', 'message': {'role': 'assistant', 'content': None,
                 'tool_calls': [{'id': 'test-call', 'type': 'function', 'function': {
                     'name': 'submit_action', 'arguments': '{"type":"final","content":"done"}'}}]}}],
                'usage': {'prompt_tokens': 10, 'completion_tokens': 7, 'total_tokens': 17}}
            return HTTPReply(200, json.dumps(response).encode())
        d = RoleModelDriver(cfg, role_prompts(cfg, 'public', 'attack'), Collector(), transport)
        d.begin_episode(deadline_monotonic=time.monotonic() + 30)
        return d

    def obs(self, actor):
        return {'protocol_version': PROTOCOL, 'actor': actor, 'history': [actor + '-private-context']}

    def test_exact_per_role_wire_and_no_implicit_history_sharing(self):
        d = self.driver()
        for a in ('H', 'S', 'E'):
            self.assertEqual(json.loads(d.next_action(a, self.obs(a)))['type'], 'final')
        for a, p in zip(('H', 'S', 'E'), self.sent):
            self.assertEqual(p['model'], DEFAULT_MODELS[a]['model'])
            self.assertEqual(json.loads(p['messages'][1]['content']), self.obs(a))
        self.assertNotIn('reasoning_effort', self.sent[1])
        self.assertEqual(d.budget_snapshot()['pools']['internal']['total_tokens'], 34)
        self.assertEqual(d.budget_snapshot()['pools']['external']['total_tokens'], 17)

    def test_h_and_s_share_request_pool(self):
        b = {**DEFAULT_BUDGET, 'internal_decisions': 2}
        d = self.driver(config(budget=b))
        d.next_action('H', self.obs('H'))
        d.next_action('S', self.obs('S'))
        with self.assertRaisesRegex(ProviderFailure, 'v3_shared_pool_exhausted'):
            d.next_action('H', self.obs('H'))
        self.assertEqual(len(self.sent), 2)
        d.next_action('E', self.obs('E'))

    def test_h_and_s_share_token_pool(self):
        profiles = clone(DEFAULT_MODELS)
        for p in profiles.values():
            p['max_completion_tokens'] = 10
        d = self.driver(config(models=profiles, budget={**DEFAULT_BUDGET, 'internal_tokens': 30}))
        d.next_action('H', self.obs('H'))
        with self.assertRaisesRegex(ProviderFailure, 'v3_shared_token_budget_exceeded'):
            d.next_action('S', self.obs('S'))
        self.assertEqual(d.budget_snapshot()['pools']['internal']['total_tokens'], 34)
        with self.assertRaises(ProviderFailure):
            d.next_action('H', self.obs('H'))
        self.assertEqual(len(self.sent), 2)

    def test_model_mismatch_stops_without_substitution(self):
        d = self.driver(mismatch=True)
        with self.assertRaises(ProviderFailure):
            d.next_action('H', self.obs('H'))
        self.assertIsNone(d.last_completion_binding('H'))
        with self.assertRaises(ProviderFailure):
            d.next_action('S', self.obs('S'))
        self.assertEqual(len(self.sent), 1)

    def test_actor_observation_mismatch_never_sent(self):
        d = self.driver()
        with self.assertRaises(ValueError):
            d.next_action('S', self.obs('H'))
        self.assertEqual(self.sent, [])


if __name__ == '__main__':
    unittest.main()
