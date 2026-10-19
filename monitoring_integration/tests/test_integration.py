import json
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
from acl_audit import evaluate, packet, audit, load
from engine_adapter import EngineSession
from network_data import validate, analyze
from collect_http import collect, request

ACL = HERE / 'upstream/member2/cnpro/configs/CORE-SW_security_acls.cfg'


class ACLTests(unittest.TestCase):
    def test_real_config_loads_all_bindings(self):
        acls, bindings = load(ACL)
        self.assertEqual(len(acls), 7)
        self.assertEqual(set(bindings), {f'vlan{x}' for x in (10, 20, 30, 40, 50, 60, 70)})

    def test_state_dependent_access(self):
        for vlan, research, remediation in [(10, 'permit', 'permit'), (60, 'deny', 'permit'), (70, 'deny', 'deny')]:
            with self.subTest(vlan=vlan):
                self.assertEqual(evaluate(ACL, vlan, packet(f'192.168.{vlan}.100', '192.168.50.10'))['action'], research)
                self.assertEqual(evaluate(ACL, vlan, packet(f'192.168.{vlan}.100', '192.168.50.13'))['action'], remediation)

    def test_acl_first_match_exposes_S12_conflict(self):
        result = evaluate(ACL, 10, packet('192.168.10.100', '192.168.40.100', 'icmp', None, icmp_type=8))
        self.assertEqual(result['action'], 'permit')
        self.assertIn('any echo', result['rule'])

    def test_documented_mismatches_retained(self):
        bad = {r['id'] for r in audit(ACL) if not r['matches_documented_expectation']}
        self.assertEqual(bad, {'S12_student_admin_ping', 'admin_all_internet_ports_matrix'})

    def test_spoofed_source_denied_except_dhcp_rule(self):
        self.assertEqual(evaluate(ACL, 10, packet('192.168.40.100', '192.168.50.12'))['action'], 'deny')
        self.assertEqual(evaluate(ACL, 10, packet('0.0.0.0', '255.255.255.255', 'udp', 67, source_port=68))['action'], 'permit')

    def test_unrecognized_acl_suffix_rejected(self):
        with tempfile.TemporaryDirectory(dir=HERE / 'tests') as d:
            path = Path(d) / 'unknown.cfg'
            path.write_text('ip access-list extended X\n permit tcp any any range 10 20\nexit\ninterface Vlan10\n ip access-group X in\n')
            with self.assertRaises(ValueError): load(path)


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=HERE / 'tests')
        self.addCleanup(self.tmp.cleanup)
        self.session = EngineSession(Path(self.tmp.name) / 'session')

    def test_real_engine_escalation_contract(self):
        self.assertEqual(self.session.invoke('PC-STU2', 'event', 'cross_vlan_attempt')['after']['state'], 'NORMAL')
        self.assertEqual(self.session.invoke('PC-STU2', 'event', 'cross_vlan_attempt')['after']['state'], 'RESTRICTED')
        row = self.session.invoke('PC-STU2', 'event', 'policy_violation')
        self.assertEqual(row['after']['state'], 'QUARANTINE')
        self.assertIsNone(row['network_response_ms'])
        self.assertFalse(row['recorded_commands'][0]['network_applied'])

    def test_failed_enforcement_is_not_network_success(self):
        self.session.recorder.accept = False
        row = self.session.invoke('PC-STU2', 'event', 'port_scan')
        self.assertEqual(row['after']['state'], 'RESTRICTED')
        self.assertTrue(row['after']['enforcement_failed'])
        self.assertIsNone(row['effective_network_state'])

    def test_generic_violations_do_not_detect_acl_drops(self):
        for _ in range(5):
            row = self.session.invoke('PC-STU2', 'event', 'policy_violation')
        self.assertEqual(row['after']['state'], 'NORMAL')
        self.assertEqual(self.session.recorder.calls, [])

    def test_recovery_and_remediation_hold(self):
        self.session.invoke('PC-STU2', 'event', 'port_scan')
        self.session.invoke('PC-STU2', 'remediated')
        self.assertEqual(self.session.invoke('PC-STU2', 'sweep')['after']['state'], 'RESTRICTED')
        self.assertEqual(self.session.invoke('PC-STU2', 'clear')['after']['state'], 'NORMAL')

    def test_unknown_device_and_event_rejected(self):
        with self.assertRaises(ValueError): self.session.invoke('PC-GHOST', 'event', 'port_scan')
        with self.assertRaises(ValueError): self.session.invoke('PC-STU2', 'event', 'invented')


class NetworkImportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=HERE / 'tests')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in ('config.txt', 'probes.txt', 'engine.txt', 'deny.txt'):
            (self.root / name).write_text('Synthetic validation fixture, not network evidence')
        self.row = dict(scenario='fixture', configuration='static', trial=1,
                        start_at='2026-10-19T00:00:00+00:00', end_at='2026-10-19T00:00:03+00:00',
                        status='measured', notes='Synthetic unittest only', evidence_level='physical_network',
                        clock_domain='wall_utc', source_device='PC-RES1', source_ip='192.168.30.100',
                        source_vlan=30, destination_ip='192.168.50.10', protocol='icmp',
                        expected_action='permit', probes_sent=4, probes_received=0,
                        evidence=['config.txt', 'probes.txt'], configuration_snapshot='config.txt', probe_evidence='probes.txt')
        self.source = self.root / 'input.json'

    def save(self):
        self.source.write_text(json.dumps([self.row]))

    def test_failed_probes_are_valid_measurements(self):
        self.save()
        path = analyze(self.source, self.root / 'out')
        values = json.loads((path / 'results.json').read_text())
        self.assertEqual(values[0]['packet_loss_pct'], 100)
        self.assertIsNone(values[0]['latency_ms'])

    def test_replay_cannot_be_network_evidence(self):
        self.row['evidence_level'] = 'real_engine_injected_events_stub_enforcement'; self.save()
        with self.assertRaises(ValueError): validate(self.source)

    def test_missing_or_escaping_evidence_rejected(self):
        for path in ('missing.txt', '../outside.txt'):
            self.row['evidence'] = ['config.txt', path]; self.row['probe_evidence'] = path; self.save()
            with self.assertRaises(ValueError): validate(self.source)

    def test_timestamps_outside_trial_rejected(self):
        self.row.update(condition_at='2026-10-18T23:59:00+00:00'); self.save()
        with self.assertRaises(ValueError): validate(self.source)

    def test_effective_denial_requires_independent_evidence(self):
        self.row.update(condition_at='2026-10-19T00:00:00+00:00',
                        detected_at='2026-10-19T00:00:01+00:00',
                        effective_denial_at='2026-10-19T00:00:02+00:00'); self.save()
        with self.assertRaises(ValueError): validate(self.source)

    def test_wrong_vlan_and_nonfinite_data_rejected(self):
        self.row['source_vlan'] = 10; self.save()
        with self.assertRaises(ValueError): validate(self.source)
        self.row['source_vlan'] = 30; self.row['extra_metric'] = float('nan'); self.save()
        with self.assertRaises(ValueError): validate(self.source)

    def test_empty_and_malformed_input_rejected(self):
        for text in ('[]', '{}', '{bad'):
            self.source.write_text(text)
            with self.assertRaises(ValueError): validate(self.source)


class TrafficTests(unittest.TestCase):
    def test_collector_output_passes_evidence_import(self):
        with tempfile.TemporaryDirectory(dir=HERE / 'tests') as d:
            with patch('socket.socket'), patch('collect_http.request', return_value=dict(status=200, succeeded=True, error=None, request_duration_ms=1.0)):
                path = collect(Path(d) / 'fixture', 'authorized', '192.168.30.100', 30, 'static', ACL, count=1)
            rows = validate(path / 'observations.json')
            self.assertEqual(rows[0]['legitimate_succeeded'], 1)
            self.assertNotIn('latency_ms', rows[0])

    def test_scope_rejected_before_connect(self):
        with patch('socket.socket') as sock:
            with self.assertRaises(ValueError):
                collect(HERE / 'unused', 'authorized', '8.8.8.8', 30, 'static', ACL)
            sock.assert_not_called()

    def test_unassigned_source_fails_before_requests(self):
        with patch('socket.socket') as sock, patch('collect_http.request') as send:
            sock.return_value.__enter__.return_value.bind.side_effect = OSError('unassigned test address')
            with self.assertRaises(OSError):
                collect(HERE / 'unused', 'authorized', '192.168.30.100', 30, 'static', ACL)
            send.assert_not_called()

    def test_failed_request_not_fabricated_as_success(self):
        with patch('http.client.HTTPConnection') as http:
            http.return_value.request.side_effect = TimeoutError('fixture timeout')
            result = request('192.168.30.100', '192.168.50.10', .1)
            self.assertFalse(result['succeeded'])
            self.assertIsNone(result['status'])
            self.assertIn('TimeoutError', result['error'])
            http.return_value.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
