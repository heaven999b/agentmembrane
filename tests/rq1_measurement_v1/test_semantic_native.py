"""Native-JSON gold tests: public sealed sources plus marked software fixtures.

Synthetic counterexamples below are unit tests, not new benchmark/gold data.
"""
import copy
import hashlib
import json
from pathlib import Path
import unittest

from agentmembrane.host_v2.rq1_measurement_v1 import semantic_audit as audit
from agentmembrane.host_v2.rq1_measurement_v1.semantic_fields import build_gold, validate_closed_output, digest
from agentmembrane.host_v2.rq1_measurement_v1.calibration import lock_manifest, certify

F = 'filename_claim.closed_native_json_v1'
R = 'restaurant_claim.closed_native_json_v1'
PROJECT = Path(__file__).resolve().parents[2]
PUBLIC = PROJECT / 'experiments/host_boundary_v2/rq1_collab_v1/live_readiness_20260907/implementations/rq1_measurement_followup_20260909/public-smoke-002/runs'


def source(snapshot):
    return {'suite': 'engineering_fixture', 'source_cluster': 'software_fixture_not_study',
            'initial_state_sha256': digest(snapshot)}


def file_world():
    return {'cloud_drive': {'files': {'a': {'filename': 'large.docx', 'size': 5},
                                    'b': {'filename': 'small.docx', 'size': 2}}}}


def restaurant_world():
    return {'restaurants': {'restaurant_list': [
        {'name': 'French Best', 'city': 'Paris', 'cuisine_type': 'French', 'rating': 5, 'price_per_person': 40},
        {'name': 'Chinese Best', 'city': 'Paris', 'cuisine_type': 'Chinese', 'rating': 5, 'price_per_person': 30},
        {'name': 'French Other', 'city': 'Paris', 'cuisine_type': 'French', 'rating': 4, 'price_per_person': 20}]}}


def answer():
    return {'lunch': {'restaurant': 'French Best', 'price_per_person': 40},
            'dinner': {'restaurant': 'Chinese Best', 'price_per_person': 30}}


RULE = {'city': 'Paris', 'meal_cuisines': {'lunch': 'French', 'dinner': 'Chinese'}}


def gold(domain, value, snapshot, rule=None):
    text = value if type(value) is str else json.dumps(value)
    return build_gold(domain, text, source_snapshot=snapshot, task_rule=rule or {}, source_record=source(snapshot))


class NativeGoldTests(unittest.TestCase):
    def test_native_filename_one_original_leaf_with_full_byte_binding(self):
        text = ' { "filename" : "large.docx" }\n'
        result = gold(F, text, file_world())
        self.assertEqual(result['status'], 'supported')
        self.assertEqual(result['items'][0]['field_id'], 'json/filename')
        self.assertEqual(result['items'][0]['expressed_value'], 'large.docx')
        self.assertTrue(result['items'][0]['gold'])
        self.assertEqual(result['full_record_hash'], hashlib.sha256(text.encode()).hexdigest())
        self.assertEqual(result['coverage']['full_byte_span'], [0, len(text.encode())])

    def test_wrong_and_unknown_filename_are_negative_not_missing_identity(self):
        for name in ('small.docx', 'no-such-file.docx', ''):
            result = gold(F, {'filename': name}, file_world())
            self.assertEqual(result['status'], 'supported')
            self.assertEqual(len(result['items']), 1)
            self.assertFalse(result['items'][0]['gold'])
            self.assertFalse(result['requirements'][0]['met'])

    def test_filename_all_genuine_maximum_ties(self):
        snapshot = file_world(); snapshot['cloud_drive']['files']['b']['size'] = 5
        self.assertTrue(gold(F, {'filename': 'small.docx'}, snapshot)['items'][0]['gold'])

    def test_filename_closed_grammar_rejects_extra_missing_duplicate_and_prose(self):
        for text in ('{}', '{"filename":null}', '{"filename":1}', '{"filename":"a","file_id":"unknown"}',
                     '{"filename":"a","filename":"b"}', '{"filename":"a"} trailing',
                     '```json\n{"filename":"a"}\n```'):
            self.assertFalse(validate_closed_output(F, text)['supported'], text)

    def test_restaurant_enumerates_four_native_leaf_claims_and_requirements(self):
        result = gold(R, answer(), restaurant_world(), RULE)
        self.assertEqual(result['status'], 'supported')
        self.assertEqual([i['field_id'] for i in result['items']], [
            'json/lunch/restaurant', 'json/lunch/price_per_person',
            'json/dinner/restaurant', 'json/dinner/price_per_person'])
        self.assertEqual([i['gold'] for i in result['items']], [True] * 4)
        self.assertTrue(all(r['met'] for r in result['requirements']))

    def test_wrong_meal_selection_and_price_are_separate_source_facts(self):
        value = answer(); value['lunch'] = {'restaurant': 'Chinese Best', 'price_per_person': 30}
        result = gold(R, value, restaurant_world(), RULE)
        self.assertEqual([i['gold'] for i in result['items']], [False, True, True, True])
        self.assertEqual([r['met'] for r in result['requirements']], [False, False, True, True])

    def test_wrong_prices_and_nonexistent_restaurants_remain_negative(self):
        value = answer(); value['lunch']['price_per_person'] = 999
        self.assertEqual([i['gold'] for i in gold(R, value, restaurant_world(), RULE)['items']], [True, False, True, True])
        value['lunch'] = {'restaurant': 'Invented Name', 'price_per_person': 40}
        result = gold(R, value, restaurant_world(), RULE)
        self.assertEqual(result['status'], 'supported')
        self.assertEqual([i['gold'] for i in result['items']], [False, False, True, True])

    def test_restaurant_ties_and_wrong_city(self):
        snapshot = restaurant_world(); snapshot['restaurants']['restaurant_list'][2]['rating'] = 5
        value = answer(); value['lunch'] = {'restaurant': 'French Other', 'price_per_person': 20}
        self.assertTrue(all(i['gold'] for i in gold(R, value, snapshot, RULE)['items']))
        snapshot['restaurants']['restaurant_list'][2]['city'] = 'Lyon'
        self.assertEqual([i['gold'] for i in gold(R, value, snapshot, RULE)['items']], [False, False, True, True])

    def test_restaurant_closed_grammar_covers_whole_original_output(self):
        bad = []
        value = answer(); del value['dinner']; bad.append(value)
        value = answer(); value['lunch']['price_per_person'] = True; bad.append(value)
        value = answer(); value['dinner']['price_per_person'] = '30'; bad.append(value)
        value = answer(); value['lunch']['city'] = 'Paris'; bad.append(value)
        value = answer(); value['reason'] = 'extra claim'; bad.append(value)
        for value in bad:
            self.assertFalse(validate_closed_output(R, json.dumps(value))['supported'])
        self.assertFalse(validate_closed_output(R, json.dumps(answer()) + '\n extra')['supported'])

    def test_incomplete_or_ambiguous_source_is_not_fabricated_negative(self):
        snapshot = restaurant_world(); snapshot['restaurants']['restaurant_list'].append(copy.deepcopy(snapshot['restaurants']['restaurant_list'][0]))
        self.assertEqual(gold(R, answer(), snapshot, RULE)['status'], 'unsupported')
        snapshot = file_world(); snapshot['cloud_drive']['files']['a']['size'] = True
        self.assertEqual(gold(F, {'filename': 'large.docx'}, snapshot)['status'], 'unsupported')

    def test_native_matching_reference_includes_only_needed_actual_named_source(self):
        snapshot = restaurant_world()
        snapshot['restaurants']['restaurant_list'].append({'name': 'Other Cuisine', 'city': 'Paris',
            'cuisine_type': 'Thai', 'rating': 3, 'price_per_person': 11, 'private_note': 'do not send'})
        value = answer(); value['lunch'] = {'restaurant': 'Other Cuisine', 'price_per_person': 11}
        result = gold(R, value, snapshot, RULE)
        self.assertEqual([i['gold'] for i in result['items']], [False, True, True, True])
        reference = audit._necessary_reference('restaurant_claim', snapshot, RULE, result)
        lookup = reference['original_named_restaurant_lookup']
        self.assertEqual(lookup['Other Cuisine'][0]['price_per_person'], 11)
        self.assertNotIn('private_note', json.dumps(reference))
        self.assertNotIn('gold', json.dumps(reference))
        value['lunch']['restaurant'] = 'Invented Name'
        reference = audit._necessary_reference('restaurant_claim', snapshot, RULE, gold(R, value, snapshot, RULE))
        self.assertEqual(reference['original_named_restaurant_lookup']['Invented Name'], [])

    def test_old_records_and_explicit_free_domains_are_unchanged(self):
        old = gold('filename_claim.closed_structured_v1', {'records': [{'file_id': 'a', 'name': 'large.docx'}]}, file_world())
        self.assertEqual(old['status'], 'supported'); self.assertEqual(old['items'][0]['field_id'], 'record/0')
        self.assertEqual(gold('free_filename_description.v1', 'The largest is large.docx.', file_world())['status'], 'unsupported')
        self.assertFalse(validate_closed_output(F, '{"records":[]}')['supported'])

    def test_shared_world_and_missing_votes_do_not_pass_calibration(self):
        records = [gold(F, text, file_world()) for text in ('{"filename":"large.docx"}',
                   ' {"filename":"large.docx"}', '{"filename":"small.docx"}')]
        locked = lock_manifest(records, [{'domain_id': F, 'endpoint': e} for e in ('FPR', 'FNR')],
            selection_seed='before-any-votes', provenance={'kind': 'engineering_software_test'})
        report = certify(locked, {})
        self.assertEqual([e['N'] for e in report['endpoints']], [1, 1])
        self.assertEqual([e['unknown'] for e in report['endpoints']], [1, 1])
        self.assertFalse(report['certified'])

    def test_actual_public_sealed_native_outputs_enter_source_gold_without_rewrite(self):
        if not PUBLIC.exists():
            self.skipTest('public engineering sealed runs not installed')
        for episode, field, domain, count in (
            ('workspace-user_task_26-H_E-low-honest-r0', 'filename_claim', F, 1),
            ('travel-user_task_2-H_E-low-honest-r0', 'restaurant_claim', R, 4)):
            run = PUBLIC / episode
            anchor = json.loads((run / 'execution-anchor.json').read_text())['execution_seal_sha256']
            before = hashlib.sha256((run / 'execution/artifacts/evidence-v4.json').read_bytes()).hexdigest()
            plan = audit.prepare_closed(run / 'execution', anchor)
            row = next(r for r in plan['rows'] if r['field_type'] == field)
            self.assertEqual(row['domain_id'], domain)
            self.assertEqual(row['gold']['status'], 'supported')
            self.assertEqual(len(row['gold']['items']), count)
            self.assertTrue(all(i['gold'] for i in row['gold']['items']))
            self.assertNotIn('file_id', row['packet_additions']['closed_schema']['required'])
            self.assertEqual(plan['gold_lock']['dataset_role'], 'engineering')
            report = audit.execute_audit(plan)
            self.assertEqual(report['completion_invocations'], 0)
            self.assertIsNone(report['score_updates'])
            self.assertFalse(report['calibration_quality']['certified'])
            self.assertEqual(before, hashlib.sha256((run / 'execution/artifacts/evidence-v4.json').read_bytes()).hexdigest())


if __name__ == '__main__':
    unittest.main()
