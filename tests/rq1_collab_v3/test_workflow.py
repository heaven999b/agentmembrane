import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.rq1_collab_v1.audit import canonical, file_hash
from agentmembrane.host_v2.rq1_collab_v1.live_pilot import (
    PROXY_BASE_ENV, PROXY_CONFIG_ENV, PROXY_CREDENTIAL_ENV_ENV,
)
from agentmembrane.host_v2.rq1_collab_v3.contract import clone, digest, make_config, matrix
from agentmembrane.host_v2.rq1_collab_v3 import workflow as w


PROXY_SETTINGS_ENV = {
    PROXY_BASE_ENV: "http://127.0.0.1:19876/v1",
    PROXY_CONFIG_ENV: "/synthetic/not-read.yaml",
    PROXY_CREDENTIAL_ENV_ENV: "RQ1_SYNTHETIC_PROXY_KEY",
}


@patch.dict(os.environ, PROXY_SETTINGS_ENV)
class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def save_fixture(self, name, data):
        p = self.root / name
        p.write_bytes(canonical(data))
        return p

    def fixture_manifest(self):
        # Deliberately unqualified unit fixture: upstream verification is mocked.
        qualified = self.save_fixture('qualified.json', {})
        goals = self.save_fixture('goals.json', [])
        bundle = {'suite': 'workspace', 'original_id': 'user_task_8', 'world_id': 'unit-only'}
        bh = digest(bundle)
        cells = matrix(bh, 'workspace-user_task_8', repeats=1)
        return {'schema_version': 'rq1-workflow/3', 'execution_mode': 'engineering', 'repeats': 1,
                'code_sha256': w.code_fingerprint(), 'qualified_manifest': str(qualified),
                'qualified_sha256': file_hash(qualified), 'goal_assignments_path': str(goals),
                'goal_assignments_sha256': file_hash(goals), 'source_root': 'unit-only', 'upstream_hashes': {},
                'task_count': 1, 'condition_count': 12, 'bundles': {bh: bundle}, 'cells': cells}

    def manifest_path(self, m):
        m = clone(m)
        m['manifest_sha256'] = digest(m)
        return self.save_fixture('manifest.json', m)

    def test_complete_matrix_accepted_partial_or_budget_confounded_rejected(self):
        original = self.fixture_manifest()
        with patch.object(w, 'verify_upstream'):
            self.assertEqual(len(w.load_manifest(self.manifest_path(original))['cells']), 12)
            for change in ('missing_cell', 'unmatched_budget', 'wrong_count'):
                m = clone(original)
                if change == 'missing_cell':
                    m['cells'].pop()
                elif change == 'unmatched_budget':
                    m['cells'][0]['budget']['internal_decisions'] -= 1
                else:
                    m['task_count'] = 100
                with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'matrix'):
                    w.load_manifest(self.manifest_path(m))

    def test_code_or_source_change_refuses_old_manifest(self):
        m = self.fixture_manifest()
        m['code_sha256'] = {}
        with self.assertRaisesRegex(ValueError, 'code_changed'):
            w.load_manifest(self.manifest_path(m))
        m = self.fixture_manifest()
        self.save_fixture('qualified.json', {'changed': True})
        with self.assertRaisesRegex(ValueError, 'admission_manifest_changed'):
            w.load_manifest(self.manifest_path(m))

    def test_missing_stale_wrong_route_models_stop_before_native_or_model_calls(self):
        c = make_config('a' * 64, 'unit', 'H_S_E', 'low', 'honest', mode='live_diagnostic')
        manifest = {'manifest_sha256': 'b' * 64, 'cells': [c]}
        required = sorted({p['model'] for p in c['models'].values()})
        for i, inv in enumerate([
            {'model_ids': [], 'checked_at_unix': time.time(), 'base_url': 'http://127.0.0.1:19876/v1'},
            {'model_ids': required, 'checked_at_unix': 0, 'base_url': 'http://127.0.0.1:19876/v1'},
            {'model_ids': required, 'checked_at_unix': time.time(), 'base_url': 'https://wrong-route.invalid/v1'},
        ]):
            with patch.object(w, 'load_manifest', return_value=manifest), patch.object(w, 'ProcessNativeTask') as native, patch.object(w, 'RoleModelDriver') as driver:
                r = w.run_cell('unused', c['episode_id'], self.root / str(i), execute_live=True,
                               inventory=self.save_fixture('inventory.json', inv))
                self.assertEqual(r['status'], 'not_run')
                native.assert_not_called()
                driver.assert_not_called()
                self.assertEqual(json.loads((self.root / str(i) / 'status.json').read_bytes())['model_calls'], 0)

    def test_offline_batch_cannot_start_live_calls(self):
        with patch.object(w, 'load_manifest', return_value={'execution_mode': 'live_diagnostic'}), patch.object(w, 'run_cell') as run:
            with self.assertRaisesRegex(ValueError, 'offline_only'):
                w.run_offline_batch('unused', self.root)
            run.assert_not_called()

    def test_status_accounts_for_all_unstarted_and_crashed_allocations(self):
        m = self.fixture_manifest()
        m['manifest_sha256'] = digest(m)
        runs = self.root / 'runs'
        runs.mkdir()
        first = runs / m['cells'][0]['episode_id']
        first.mkdir()
        (first / 'allocation.json').write_bytes(canonical({'manifest_sha256': m['manifest_sha256'], 'config': m['cells'][0]}))
        with patch.object(w, 'load_manifest', return_value=m):
            result = w.inspect_workflow('unused', runs)
        self.assertEqual((result['assigned'], result['completed'], result['needs_review'], result['not_run']), (12, 0, 1, 11))
        self.assertEqual(result['distinct_public_worlds'], 1)


if __name__ == '__main__':
    unittest.main()
