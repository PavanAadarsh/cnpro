"""Deployable integration of Member 3's real engine, with verified enforcement.

Upstream remains immutable; fixes are normal subclasses used by the lab/runtime.
"""
import ipaddress
import json
from pathlib import Path
import re
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'upstream/member3'))
from policy_engine.policy_engine import PolicyEngine
from policy_engine.event_listener import AutoEventListener
from policy_engine.state_manager import DEVICES
from policy_engine.recovery_handler import RecoveryHandler


class EndpointRegistry:
    """Trusted switch-port/MAC bindings, refreshed from actual DHCP/controller data.

    No guessed IPs, subnet fallbacks or learning from untrusted event payloads.
    replace() accepts a complete authoritative snapshot, expiring previous leases.
    """
    def __init__(self):
        self._lock = threading.RLock()
        self._addresses = {}

    def replace(self, bindings):
        addresses, identities, ports = {}, {}, {}
        now = time.time()
        for row in bindings:
            device = row['device']
            if device not in DEVICES:
                raise ValueError('unknown endpoint')
            expected = DEVICES[device]
            port = re.sub(r'^fa(?:stethernet)?', 'fa', row['port'], flags=re.I).lower()
            expected_port = re.sub(r'^fa(?:stethernet)?', 'fa', expected['port'], flags=re.I).lower()
            if row['switch_ip'] != expected['switch_ip'] or port != expected_port:
                raise ValueError('endpoint does not match authoritative switch port')
            mac = row['mac'].lower().replace('-', ':')
            if not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', mac):
                raise ValueError('invalid MAC')
            ip = str(ipaddress.IPv4Address(row['ip']))
            vlan = int(row['vlan'])
            if vlan not in (expected['home_vlan'], 60, 70) or ipaddress.IPv4Address(ip) not in ipaddress.IPv4Network(f'192.168.{vlan}.0/24'):
                raise ValueError('lease does not match port VLAN')
            if ip.endswith(('.0', '.255')):
                raise ValueError('not an endpoint address')
            expires = float(row['expires_at'])
            if expires <= now:
                continue
            if ip in addresses or mac in identities or (row['switch_ip'], port) in ports:
                raise ValueError('ambiguous lease, MAC or switch port')
            addresses[ip] = dict(row, mac=mac, ip=ip, expires_at=expires)
            identities[mac] = device
            ports[(row['switch_ip'], port)] = device
        with self._lock:
            self._addresses = addresses

    def resolve(self, address):
        with self._lock:
            row = self._addresses.get(address)
            return row['device'] if row and row['expires_at'] > time.time() else None


class VerifiedEnforcer:
    """Accept a transition only after successful push AND exact integer readback.

    Backends can additionally implement verify_endpoint for lease and connectivity
    verification. Linux lab supplies it; IOS deployments need a host-side agent.
    """
    def __init__(self, backend):
        self.backend = backend

    def push_vlan(self, switch_ip, port, vlan):
        try:
            if not self.backend.push_vlan(switch_ip, port, vlan):
                return False
            actual = self.backend.verify_vlan(switch_ip, port)
            if type(actual) is not int or actual != vlan:
                return False
            confirm = getattr(self.backend, 'verify_endpoint', None)
            return bool(confirm(switch_ip, port, vlan)) if confirm else True
        except Exception:
            return False

    def verify_vlan(self, switch_ip, port):
        try:
            value = self.backend.verify_vlan(switch_ip, port)
            return value if type(value) is int else None
        except Exception:
            return None


class VerifiedRecovery(RecoveryHandler):
    def _do_recover(self, device_name, record, state_manager, ssh_enforcer, reason):
        try:
            ok = ssh_enforcer.push_vlan(record['switch_ip'], record['port'], record['home_vlan'])
            vlan = ssh_enforcer.verify_vlan(record['switch_ip'], record['port']) if ok else None
            ok = ok and type(vlan) is int and vlan == record['home_vlan']
        except Exception:
            ok = False
        if not ok:
            state_manager.set_state(device_name, record['state'], enforcement_failed=True)
            return False
        state_manager.set_state(device_name, 'NORMAL', enforcement_failed=False)
        if self._tracker is not None:
            self._tracker.clear_events(device_name)
        return True


class IntegratedPolicyEngine(PolicyEngine):
    """Member 3 thresholds/recovery, with serialized, verified state transitions."""
    def __init__(self, *args, ssh_enforcer, evidence=None, **kwargs):
        self.transition_lock = threading.RLock()
        self.evidence = Path(evidence) if evidence else None
        super().__init__(*args, ssh_enforcer=VerifiedEnforcer(ssh_enforcer), **kwargs)
        self.recovery_handler = VerifiedRecovery(threshold_tracker=self.threshold_tracker)

    def _call(self, method, device, *args):
        with self.transition_lock:
            before = self.state_manager.get_state(device)
            started = time.time_ns()
            result = method(device, *args)
            after = self.state_manager.get_state(device)
            if before and after and after['enforcement_failed']:
                # Preserve observed state and hold timers if the desired move was
                # not verified. Retain newly counted events and the failure flag.
                with self.state_manager._lock:
                    for key in ('state', 'current_vlan', 'restricted_since', 'quarantined_since', 'remediated'):
                        self.state_manager._db[device][key] = before[key]
                    self.state_manager._save()
                result = 'ENFORCEMENT_FAILED' if isinstance(result, str) else False
                after = self.state_manager.get_state(device)
            if self.evidence:
                with self.evidence.open('a', encoding='utf-8') as stream:
                    stream.write(json.dumps(dict(device=device, method=method.__name__, arguments=args,
                        started_ns=started, completed_ns=time.time_ns(), before=before, after=after, result=result)) + '\n')
            return result

    def handle_event(self, device, event_type):
        return self._call(super().handle_event, device, event_type)

    def enforce_state(self, device, target, reason='MANUAL_OVERRIDE'):
        return self._call(super().enforce_state, device, target, reason)

    def manual_clear(self, device):
        return self._call(super().manual_clear, device)

    def run_recovery_sweep(self):
        with self.transition_lock:
            return super().run_recovery_sweep()


class IntegratedListener(AutoEventListener):
    """Use authenticated/trusted exporter transport plus live endpoint bindings.

    Linux kernel drop reader is in lab.py; IOS deployments should accept UDP only
    from configured switches/firewall rules. Unidentified addresses fail closed.
    """
    def __init__(self, engine, registry, **kwargs):
        super().__init__(engine, **kwargs)
        self.registry = registry

    def resolve_ip_to_device(self, address):
        return self.registry.resolve(address)

    def parse_syslog_message(self, message):
        # Never accept upstream SIM_EVENT bypasses from network datagrams.
        if 'SIM_EVENT:' in message:
            return None
        parsed = super().parse_syslog_message(message)
        if parsed and parsed[1] == 'policy_violation':
            # TH-05: two observed prohibited routed attempts / 600 seconds.
            # Other event classes and TH-03 escalation remain Member 3's logic.
            return parsed[0], 'cross_vlan_attempt'
        return parsed
