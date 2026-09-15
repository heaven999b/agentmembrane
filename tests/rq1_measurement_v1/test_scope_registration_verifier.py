"""Independent scope/registration counterexamples, software fixtures only.

No API calls, changed public records, or empirical calibration claims.
"""
import copy
import unittest

from agentmembrane.host_v2.rq1_measurement_v1.information import (
    absent_internal_worker_evidence, derive_information_effects,
)
from tests.rq1_measurement_v1 import test_observed_scope_fixes as scope_fixtures
from tests.rq1_measurement_v1 import test_memory_observer as memory_fixtures
from tests.rq1_measurement_v1 import test_explicit_model_registration as model_fixtures


class IndependentInformationScopeTests(unittest.TestCase):
    fixture = scope_fixtures.StructuralWorkerAbsenceTests.fixture

    def test_structural_absence_only_closes_S_units_not_other_recipients(self):
        data = self.fixture(); data['internal_worker_used'] = False
        units = [{'id': 'I:/private@' + recipient, 'max_severity': 3}
                 for recipient in ('role:S', 'role:E', 'native:unrelated@example.invalid')]
        compiled = {'information_contract': {'owner_recipient': 'role:H', 'units': units,
            'recipients': ['role:S', 'role:E', 'native:unrelated@example.invalid'], 'fact_rules': {}},
            'private_facts': {}}
        result = derive_information_effects(data, compiled)
        self.assertEqual([r['unit_id'] for r in result['observations']], ['I:/private@role:S'])
        self.assertEqual(result['observations'][0]['affected'], 0)
        self.assertFalse(result['coverage']['full_semantic_absence_certified'])

    def test_positive_worker_used_marker_cannot_be_certified_as_structurally_absent(self):
        data = self.fixture(); data['internal_worker_used'] = True
        self.assertEqual(absent_internal_worker_evidence(data), [],
                         'A contradictory runtime worker-used witness must not become an exact zero')

    def test_confirmed_memory_delivery_to_S_prevents_structural_absence(self):
        data = self.fixture(); data['internal_worker_used'] = False
        data['memory'] = {'events': [{'event_id': 'S-memory-receipt', 'actor': 'S',
            'record_origin': 'trusted_task_memory_service', 'kind': 'memory_actor_delivery',
            'receipt_status': 'model_response_observed'}]}
        self.assertEqual(absent_internal_worker_evidence(data), [],
                         'The memory transport is a real recipient route, not just native/model logs')


class IndependentMemoryScopeTests(unittest.TestCase):
    setUp = memory_fixtures.MemoryObserverTests.setUp
    tearDown = memory_fixtures.MemoryObserverTests.tearDown
    polluted = memory_fixtures.MemoryObserverTests.polluted
    observe = memory_fixtures.MemoryObserverTests.observe

    def test_never_consumed_commit_keeps_narrow_grade_one_and_full_scope_open(self):
        self.polluted(); self.m.close()
        result = self.observe()
        scoped = next(r for r in result['runtime_scope_observations'] if r['affected'] == 1)
        self.assertEqual((scoped['severity_lower'], scoped['severity_upper']), (1, 1))
        full = next(r for r in result['observations'] if r['affected'] == 1)
        self.assertEqual(full['severity_upper'], 4)
        self.assertTrue(result['scope_incomplete'])

    def test_confirmed_bound_use_reaches_narrow_cap_without_erasing_global_unknown(self):
        committed = self.polluted()
        read = self.m.get(actor='H', record_id=committed['record']['record_id'], expected_version=1)
        self.m.mark_delivered(actor='H', read_event_ids=[read['read_event_id']],
            receipt_status='model_response_observed', request_id='software-fixture')
        args_hash = 'bound-exact-arguments'
        use = {'kind': 'memory_bound_to_action', 'episode_id': self.m.episode_id, 'task_hash': 'hash',
            'record_origin': 'trusted_native_ingress', 'backend_entered': True, 'use_confirmed': True,
            'backend_receipt_event_id': 'native-ingress', 'event_id': 'native-binding', 'actor': 'H',
            'arguments_sha256': args_hash, 'bindings': [{'record_id': committed['record']['record_id'],
                'version': 1, 'read_event_id': read['read_event_id'],
                'projected_value_sha256': read['projected_value_sha256'], 'arguments_sha256': args_hash}]}
        self.m.close(); result = self.observe(use_events=[use])
        scoped = next(r for r in result['runtime_scope_observations'] if r['affected'] == 1)
        self.assertEqual((scoped['severity_lower'], scoped['severity_upper']), (3, 3))
        self.assertTrue(result['scope_incomplete']); self.assertFalse(result['M4_supported'])


class IndependentModelRegistrationTests(unittest.TestCase):
    setUp = model_fixtures.ExplicitModelRegistrationTests.setUp
    save = model_fixtures.ExplicitModelRegistrationTests.save
    manifest = model_fixtures.ExplicitModelRegistrationTests.manifest
    load = model_fixtures.ExplicitModelRegistrationTests.load

    def test_registration_cannot_be_removed_while_custom_model_cells_remain(self):
        data = self.manifest(); del data['role_model_profiles']; del data['model_profile_source']
        with self.assertRaisesRegex(ValueError, 'incomplete_or_unmatched_condition_matrix'):
            self.load(data)

    def test_all_cells_cannot_silently_revert_from_registered_models_to_defaults(self):
        data = self.manifest(); default = self.manifest(False)
        data['cells'] = copy.deepcopy(default['cells'])
        with self.assertRaisesRegex(ValueError, 'incomplete_or_unmatched_condition_matrix'):
            self.load(data)

    def test_profiles_hash_cannot_lie_about_registered_configuration(self):
        data = self.manifest(); data['model_profile_source']['profiles_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'registration_changed'):
            self.load(data)


if __name__ == '__main__':
    unittest.main()
