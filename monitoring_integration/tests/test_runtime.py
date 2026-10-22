"""Software regressions; live kernel tests are independently run by lab.py."""
from pathlib import Path
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
from runtime import EndpointRegistry, IntegratedPolicyEngine, IntegratedListener, VerifiedEnforcer
from policy import reconcile, nft_rules
from application_services import resolver_for
from acl_audit import evaluate, packet


class Backend:
    def __init__(self):
        self.vlan = 10
        self.readback = 'actual'
        self.push = True

    def push_vlan(self, switch, port, vlan):
        if self.push:
            self.vlan = vlan
        return self.push

    def verify_vlan(self, *args):
        if self.readback == 'exception':
            raise OSError('readback unavailable')
        return self.vlan if self.readback == 'actual' else self.readback


def binding(device='PC-STU2', address='192.168.10.175', vlan=10, **kwargs):
    return dict(device=device, ip=address, vlan=vlan, mac='02:ca:00:00:00:02',
                port='Fa0/2', switch_ip='192.168.40.21', expires_at=time.time()+3600, **kwargs)


class RegistryTests(unittest.TestCase):
    def test_address_changes_and_old_leases_expire(self):
        registry = EndpointRegistry()
        for address, vlan in [('192.168.10.175', 10), ('192.168.60.204', 60), ('192.168.70.119', 70), ('192.168.10.231', 10)]:
            previous = locals().get('previous')
            registry.replace([binding(address=address, vlan=vlan)])
            self.assertEqual(registry.resolve(address), 'PC-STU2')
            if previous:
                self.assertIsNone(registry.resolve(previous))
            previous = address

    def test_no_subnet_guessing_or_expired_binding(self):
        registry = EndpointRegistry()
        row = binding()
        row['expires_at'] = time.time()-1
        registry.replace([row])
        self.assertIsNone(registry.resolve(row['ip']))
        self.assertIsNone(registry.resolve('192.168.10.100'))

    def test_conflicting_ip_mac_or_wrong_port_rejected(self):
        registry = EndpointRegistry()
        with self.assertRaises(ValueError):
            registry.replace([binding(), binding()])
        row = binding()
        row['port'] = 'Fa0/1'
        with self.assertRaises(ValueError):
            registry.replace([row])


class EnforcementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=HERE/'tests')
        self.addCleanup(self.temp.cleanup)
        self.backend = Backend()
        directory = Path(self.temp.name)
        self.engine = IntegratedPolicyEngine(state_db_path=str(directory/'state.json'),
            events_db_path=str(directory/'events.json'), ssh_enforcer=self.backend)

    def test_recovery_rejects_unknown_bool_exception_and_mismatch(self):
        self.engine.handle_event('PC-STU2', 'port_scan')
        self.assertEqual(self.engine.state_manager.get_state('PC-STU2')['state'], 'RESTRICTED')
        for readback in (None, True, '10', 'exception', 70):
            self.backend.readback = readback
            self.assertFalse(self.engine.manual_clear('PC-STU2'))
            state = self.engine.state_manager.get_state('PC-STU2')
            self.assertEqual(state['state'], 'RESTRICTED')
            self.assertTrue(state['enforcement_failed'])
        self.backend.readback = 'actual'
        self.assertTrue(self.engine.manual_clear('PC-STU2'))
        self.assertEqual(self.engine.state_manager.get_state('PC-STU2')['state'], 'NORMAL')

    def test_failed_containment_never_reports_applied_state(self):
        self.backend.readback = None
        self.assertEqual(self.engine.handle_event('PC-STU2', 'port_scan'), 'ENFORCEMENT_FAILED')
        state = self.engine.state_manager.get_state('PC-STU2')
        self.assertEqual(state['state'], 'NORMAL')
        self.assertEqual(state['current_vlan'], 10)
        self.assertTrue(state['enforcement_failed'])

    def test_real_parser_threshold_enforcement_and_recovery(self):
        registry = EndpointRegistry()
        registry.replace([binding()])
        listener = IntegratedListener(self.engine, registry)
        message = '%SEC-6-IPACCESSLOGP: list X denied tcp 192.168.10.175 -> 192.168.50.12'
        device, event = listener.parse_syslog_message(message)
        self.assertEqual(device, 'PC-STU2')
        self.assertEqual(self.engine.handle_event(device, event), 'NO_ACTION')
        self.assertEqual(self.engine.handle_event(device, event), 'RESTRICT')
        self.assertEqual(self.backend.vlan, 60)
        self.assertTrue(self.engine.manual_clear(device))
        self.assertEqual(self.backend.vlan, 10)
        self.assertIsNone(listener.parse_syslog_message('SIM_EVENT:PC-STU1:spoofing'))


class EffectivePolicyTests(unittest.TestCase):
    def test_real_effective_acls_preserve_role_permissions(self):
        with tempfile.TemporaryDirectory(dir=HERE/'tests') as directory:
            path = Path(directory)/'effective.cfg'
            reconcile(path)
            for vlan, destination, protocol, port, permitted in [
                (10, '192.168.40.100', 'icmp', None, False),
                (10, '192.168.50.10', 'tcp', 80, True),
                (10, '192.168.50.11', 'tcp', 21, False),
                (20, '192.168.50.10', 'tcp', 443, True),
                (20, '192.168.50.12', 'icmp', None, False),
                (30, '192.168.50.11', 'tcp', 21, True),
                (30, '192.168.50.10', 'icmp', None, True),
                (40, '203.0.113.2', 'tcp', 25, True),
                (60, '192.168.50.13', 'tcp', 80, True),
                (60, '203.0.113.2', 'tcp', 80, False),
                (70, '192.168.50.13', 'tcp', 80, False),
                (50, '192.168.10.175', 'tcp', 80, False),
            ]:
                with self.subTest(vlan=vlan, destination=destination, port=port):
                    row = packet(f'192.168.{vlan}.175', destination, protocol, port, icmp_type=8)
                    self.assertEqual(evaluate(path, vlan, row)['action'], 'permit' if permitted else 'deny')

    def test_admin_echo_replies_scoped_without_user_initiation(self):
        with tempfile.TemporaryDirectory(dir=HERE/'tests') as directory:
            path = Path(directory)/'effective.cfg'
            reconcile(path)
            for vlan in (10,20,30):
                with self.subTest(vlan=vlan):
                    for icmp_type, action in [(0,'permit'),(8,'deny')]:
                        row=packet(f'192.168.{vlan}.175','192.168.40.100','icmp',None,icmp_type=icmp_type)
                        self.assertEqual(evaluate(path,vlan,row)['action'],action)
                    row=packet('192.168.40.100',f'192.168.{vlan}.175','icmp',None,icmp_type=8)
                    self.assertEqual(evaluate(path,40,row)['action'],'permit')
                    row=packet(f'192.168.{vlan}.175','192.168.50.12','icmp',None,icmp_type=0)
                    self.assertEqual(evaluate(path,vlan,row)['action'],'deny')
            compiled=nft_rules(path,[])
            replies=[line for line in compiled.splitlines() if 'icmp type 0' in line and 'ip daddr 192.168.40.0/24' in line]
            self.assertEqual(len(replies),3)
            self.assertTrue(all('ct state established accept' in line for line in replies))

    def test_dns_policy_uses_delivered_resolvers_and_no_quarantine_escape(self):
        with tempfile.TemporaryDirectory(dir=HERE/'tests') as directory:
            path=Path(directory)/'effective.cfg'
            reconcile(path)
            for vlan in (10,20,30,40,60,70):
                resolver=resolver_for(vlan)
                self.assertEqual(resolver,'192.168.50.13' if vlan in (60,70) else '203.0.113.2')
                for protocol in ('udp','tcp'):
                    row=packet(f'192.168.{vlan}.175',resolver,protocol,53)
                    self.assertEqual(evaluate(path,vlan,row)['action'],'deny' if vlan==70 else 'permit')
                    if vlan in (60,70):
                        row=packet(f'192.168.{vlan}.175','203.0.113.2',protocol,53)
                        self.assertEqual(evaluate(path,vlan,row)['action'],'deny')


if __name__ == '__main__':
    unittest.main()
