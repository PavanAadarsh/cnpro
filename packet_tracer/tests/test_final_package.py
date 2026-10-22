"""Offline audit regression tests, not Packet Tracer network tests."""
import hashlib
import json
import re
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from final_audit import Campus, DEVICES, HERE, Rule, audit, policy_cases
from build_final_package import PATCH, topology, validate_cabling
import verify_handoff


class FinalPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = [HERE / 'University_Research_Network_Final.pkt'] + list(
            (HERE / 'evidence').glob('*_final_running_config.txt'))
        cls.hashes = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in cls.sources}

    @classmethod
    def tearDownClass(cls):
        for path, digest in cls.hashes.items():
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise AssertionError('Original project/export was modified: ' + str(path))

    def test_active_ftp_exception_boundaries(self):
        rule = Rule.parse('permit tcp host 192.168.50.11 eq 20 192.168.30.0 0.0.0.255 gt 1023')
        packet = dict(source='192.168.50.11', destination='192.168.30.101', protocol='tcp', sport=20, dport=1024)
        self.assertTrue(rule.matches(packet))
        for change in ({'dport': 1023}, {'sport': 21}, {'source': '192.168.50.12'},
                       {'destination': '192.168.40.101'}, {'protocol': 'udp'}):
            with self.subTest(change=change):
                self.assertFalse(rule.matches({**packet, **change}))

    def test_unsupported_acl_suffix_fails_closed(self):
        with self.assertRaises(ValueError):
            Rule.parse('permit tcp any any unsupported-feature')

    def test_established_is_ack_or_rst_not_authentication(self):
        rule = Rule.parse('permit tcp any any established')
        packet = dict(source='192.168.50.11', destination='192.168.30.101', protocol='tcp')
        self.assertFalse(rule.matches({**packet, 'flags': ['SYN']}))
        self.assertTrue(rule.matches({**packet, 'flags': ['ACK']}))

    def test_acl_first_match_and_implicit_deny(self):
        device = Campus().devices['EDGE-R']
        packet = dict(source='192.168.70.101', destination='192.168.70.1', protocol='icmp', icmp=8)
        device.acls['TEST'] = [Rule.parse('deny ip any any'), Rule.parse('permit icmp any any')]
        self.assertFalse(device.acl_permits('TEST', packet)[0])
        device.acls['TEST'] = []
        self.assertEqual(device.acl_permits('TEST', packet), (False, 'implicit deny'))

    def test_route_longest_prefix_wins(self):
        device = Campus().devices['EDGE-R']
        device.routes.append((IPv4Network('192.168.10.100/32'), IPv4Address('10.255.0.3')))
        self.assertEqual(str(device.route('192.168.10.100')[1]), '10.255.0.3')
        self.assertEqual(str(device.route('192.168.10.101')[1]), '10.255.0.2')

    def test_missing_zone_pair_blocks_flow(self):
        campus = Campus()
        case = next(c for c in policy_cases() if c['id'] == 'vlan30_research_http')
        self.assertTrue(campus.initial_flow(case['vlan'], case['packet'])[0])
        campus.devices['FW-RES-ADM'].pairs.clear()
        self.assertFalse(campus.initial_flow(case['vlan'], case['packet'])[0])

    def test_shutdown_ingress_blocks_flow(self):
        campus = Campus()
        case = next(c for c in policy_cases() if c['id'] == 'vlan30_research_http')
        campus.devices['FW-RES-ADM'].interfaces['GigabitEthernet0/0']['shutdown'] = True
        self.assertFalse(campus.initial_flow(case['vlan'], case['packet'])[0])

    def test_current_exports_match_policy(self):
        rows = audit()
        self.assertEqual(len(rows), 136)
        self.assertEqual([r['id'] for r in rows if not r['matches_requirement']], [])
        self.assertTrue(all(r['network_status'] == 'NOT_RUN_BY_THIS_AUDIT' for r in rows))

    def test_pending_patch_fixes_only_gateway_in_scratch_configuration(self):
        # Interpret only the ACL definition and binding present in the pending CLI
        # file into temporary exported text. No command is sent to a simulator.
        definition = PATCH.split('ip access-list extended ', 1)[1].split('\nexit', 1)[0]
        binding = next(line.strip() for line in PATCH.splitlines() if line.strip().startswith('ip access-group '))
        scratch = HERE / 'backups'
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='audit-test-', dir=scratch) as directory:
            self.assertTrue(Path(directory).resolve().is_relative_to(scratch.resolve()))
            for name in DEVICES:
                shutil.copyfile(HERE / 'evidence' / (name + '_final_running_config.txt'),
                                Path(directory) / (name + '_final_running_config.txt'))
            edge = Path(directory) / 'EDGE-R_final_running_config.txt'
            text = edge.read_text(encoding='utf-8-sig')
            # Recreate the old defect only in scratch files, then exercise the
            # reference correction. Keep regression detection after deployment.
            text = re.sub(r'(?m)^ip access-list extended QUARANTINE-IN-V2\n(?: .*\n)*', '', text)
            text = text.replace('ip access-group QUARANTINE-IN-V2 in', 'ip access-group QUARANTINE-IN in')
            self.assertEqual(text.count('ip access-group QUARANTINE-IN in'), 1)
            edge.write_text(text, encoding='utf-8')
            baseline = audit(directory)
            self.assertEqual([r['id'] for r in baseline if not r['matches_requirement']], ['vlan70_own_gateway'])
            text = text.replace('ip access-group QUARANTINE-IN in', binding)
            text = text.replace('\nend', '\nip access-list extended ' + definition + '\n!\nend')
            edge.write_text(text, encoding='utf-8')
            corrected = audit(directory)
            self.assertTrue(all(r['matches_requirement'] for r in corrected))
            changed = [r['id'] for old, r in zip(baseline, corrected)
                       if old['configured_allow'] != r['configured_allow']]
            self.assertEqual(changed, ['vlan70_own_gateway'])
            campus = Campus(directory)
            # DHCP preserved; non-DHCP UDP spoofing and gateway administration denied.
            for sport, dport, expected in ((68, 67, True), (123, 67, False), (68, 53, False)):
                permitted, _ = campus.devices['EDGE-R'].acl_permits('QUARANTINE-IN-V2', dict(
                    source='0.0.0.0', destination='255.255.255.255', protocol='udp', sport=sport, dport=dport))
                self.assertEqual(permitted, expected)

    def test_topology_matches_exported_cabled_ports(self):
        design = topology()
        self.assertEqual(len(design['devices']), 21)
        self.assertEqual(len(design['links']), 27)
        validate_cabling(design, Campus())
        servers = {d['name']: d.get('ipv4') for d in design['devices'] if d['name'].startswith('SRV')}
        self.assertEqual(servers, {'SRV-RESEARCH': '192.168.50.10', 'SRV-DB': '192.168.50.11',
                                  'SRV-ADMIN': '192.168.50.12', 'SRV-REMEDIATE': '192.168.50.13'})

    def test_duplicate_cable_rejected(self):
        design = topology()
        design['links'].append(design['links'][0].copy())
        with self.assertRaisesRegex(ValueError, 'duplicate cabled port'):
            validate_cabling(design, Campus())

    def test_wrong_access_vlan_rejected(self):
        campus = Campus()
        props = campus.devices['ACCESS-SW-A'].interfaces['FastEthernet0/2']
        props['lines'] = [line.replace('access vlan 10', 'access vlan 70') for line in props['lines']]
        with self.assertRaisesRegex(ValueError, 'access VLAN mismatch'):
            validate_cabling(topology(), campus)

    def test_missing_trunk_vlan_rejected(self):
        campus = Campus()
        props = campus.devices['CORE-SW'].interfaces['GigabitEthernet0/1']
        props['lines'] = ['switchport trunk allowed vlan 10' if line.startswith('switchport trunk allowed vlan ')
                          else line for line in props['lines']]
        with self.assertRaisesRegex(ValueError, 'role VLAN absent'):
            validate_cabling(topology(), campus)

    def test_modified_manifest_artifact_rejected(self):
        scratch = HERE / 'backups'
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='audit-test-', dir=scratch) as directory:
            root = Path(directory).resolve()
            self.assertTrue(root.is_relative_to(scratch.resolve()))
            (root / 'evidence').mkdir()
            (root / 'test.txt').write_text('changed', encoding='utf-8')
            (root / 'evidence/final_artifact_manifest.json').write_text(json.dumps([
                dict(Path='test.txt', Bytes=7, SHA256='0' * 64)]), encoding='utf-8')
            with patch.object(verify_handoff, 'HERE', root):
                with self.assertRaisesRegex(ValueError, 'artifact changed'):
                    verify_handoff.verify()

    def test_manifest_path_escape_rejected(self):
        scratch = HERE / 'backups'
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='audit-test-', dir=scratch) as directory:
            root = Path(directory).resolve()
            self.assertTrue(root.is_relative_to(scratch.resolve()))
            (root / 'evidence').mkdir()
            (root / 'evidence/final_artifact_manifest.json').write_text(json.dumps([
                dict(Path='../outside.txt', Bytes=0, SHA256='0' * 64)]), encoding='utf-8')
            with patch.object(verify_handoff, 'HERE', root):
                with self.assertRaisesRegex(ValueError, 'unsafe manifest path'):
                    verify_handoff.verify()


if __name__ == '__main__':
    unittest.main()
