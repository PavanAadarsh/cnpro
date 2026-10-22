import json
from pathlib import Path
import sys
import tempfile
import unittest
import subprocess
import shutil

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
from branch_audit import inventory
from contract_audit import check
from network_data import legacy


class LatestUpdateTests(unittest.TestCase):
    def test_updated_cli_status_runs_in_isolated_directory(self):
        with tempfile.TemporaryDirectory(dir=HERE / 'tests') as d:
            directory = Path(d)
            supplied = HERE / 'upstream/member3'
            shutil.copyfile(supplied / 'simulate_event.py', directory / 'simulate_event.py')
            (directory / 'policy_engine').mkdir()
            for source in (supplied / 'policy_engine').glob('*.py'):
                shutil.copyfile(source, directory / 'policy_engine' / source.name)
            # status creates/reads only this isolated persistence; it does not call SSH.
            result = subprocess.run([sys.executable, '-B', 'simulate_event.py', 'status'],
                                    cwd=directory, capture_output=True, text=True, encoding='utf-8', timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            for device in ('PC-STU1', 'PC-STU2', 'PC-FAC1', 'PC-FAC2', 'PC-ADM1', 'PC-ADM2', 'PC-RES1', 'PC-RES2'):
                self.assertIn(device, result.stdout)

    def test_every_fetched_branch_has_a_file_inventory(self):
        result = inventory()
        names = {b['branch'] for b in result['branches']}
        self.assertTrue({'main', 'Member-4-updated', 'member-2', 'member3', 'member1-network-architecture'} <= names)
        for branch in result['branches']:
            self.assertEqual(branch['file_count'], len(branch['files']))
            self.assertEqual(len(branch['commit']), 40)

    def test_network_assets_are_computed_from_paths(self):
        result = inventory()
        expected = any(p.lower().endswith(('.pkt', '.pka')) for b in result['branches'] for p in b['files'])
        self.assertEqual(result['topology_present'], expected)
        self.assertTrue(result['member3_change']['engine_modules_changed'])

    def test_latest_contract_is_checked_against_real_code(self):
        with tempfile.TemporaryDirectory(dir=HERE / 'tests') as d:
            values = {r['id']: r for r in check(Path(d) / 'checks')}
            self.assertEqual(values['auth_window']['status'], 'matches')
            self.assertEqual(values['quarantine_hold_restart']['status'], 'matches')
            self.assertTrue(values['quarantine_hold_restart']['observed']['timer_restarted'])
            self.assertEqual(values['remediation_hold_required']['observed']['state_after_immediate_sweep'], 'QUARANTINE')
            self.assertEqual(values['structured_event_schema']['status'], 'not_implemented_as_documented')
            self.assertEqual(values['production_syslog_parser']['status'], 'requires_runtime_verification')
            self.assertEqual(values['remediation_hold_required']['status'], 'matches')
            self.assertEqual(values['dynamic_device_resolution']['observed']['192.168.60.101'], None)
            self.assertEqual(values['acl_syslog_containment']['observed']['state'], 'NORMAL')
            self.assertEqual(values['recovery_readback_unknown']['status'], 'unverified_recovery_accepted')
            self.assertEqual(values['recovery_readback_mismatch']['status'], 'matches')

    def test_runtime_permissions_do_not_override_actual_acls(self):
        with tempfile.TemporaryDirectory(dir=HERE / 'tests') as d:
            values = {r['id']: r for r in check(Path(d) / 'checks')}
            for name in ('restricted_internet_http', 'restricted_internet_dns',
                         'quarantine_remediation_http', 'quarantine_remediation_ping', 'restricted_remediation_ping'):
                self.assertEqual(values[name]['observed']['action'], 'deny')
                self.assertEqual(values[name]['status'], 'conflict')

    def test_legacy_audit_uses_prepared_acl_and_does_not_claim_network_verification(self):
        result = legacy.audit()
        self.assertTrue(result['core_configuration_source'].startswith('monitoring_integration/upstream/member2/'))
        self.assertTrue(result['engine_source_present'])
        self.assertTrue(result['core_security_acl_applied'])
        self.assertTrue(result['configuration_only'])
        self.assertIsNone(result['live_security_acl_verified'])
        self.assertFalse(any('No adaptive engine' in s for s in result['limitations']))


if __name__ == '__main__':
    unittest.main()
