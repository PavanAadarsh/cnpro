"""Fail-closed evaluator for the ACL syntax actually delivered by Member 2.

This checks configuration semantics only. It is not a network emulator.
"""
from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path

PORTS = {'www': 80, 'domain': 53, 'bootps': 67, 'bootpc': 68,
         'ftp': 21, 'ftp-data': 20}
ICMP = {'echo': 8, 'echo-reply': 0, 'unreachable': 3, 'time-exceeded': 11}


def endpoint(tokens):
    token = tokens.pop(0)
    if token == 'any':
        return '0.0.0.0', '255.255.255.255'
    if token == 'host':
        return str(IPv4Address(tokens.pop(0))), '0.0.0.0'
    return str(IPv4Address(token)), str(IPv4Address(tokens.pop(0)))


def port(tokens):
    if tokens and tokens[0] == 'eq':
        tokens.pop(0)
        name = tokens.pop(0)
        number = PORTS[name] if name in PORTS else int(name)
        if not 0 <= number <= 65535:
            raise ValueError('invalid port')
        return number
    return None


def address_matches(address, network):
    base, wildcard = map(lambda x: int(IPv4Address(x)), network)
    mask = (~wildcard) & 0xffffffff
    return int(IPv4Address(address)) & mask == base & mask


@dataclass
class Rule:
    action: str
    protocol: str
    source: tuple
    destination: tuple
    source_port: object
    destination_port: object
    icmp_type: object
    established: bool
    line: int
    text: str

    def matches(self, packet):
        return (self.protocol in ('ip', packet['protocol'])
                and address_matches(packet['source_ip'], self.source)
                and address_matches(packet['destination_ip'], self.destination)
                and (self.source_port is None or packet.get('source_port') == self.source_port)
                and (self.destination_port is None or packet.get('destination_port') == self.destination_port)
                and (self.icmp_type is None or packet.get('icmp_type') == self.icmp_type)
                and (not self.established or bool(set(packet.get('tcp_flags', [])) & {'ACK', 'RST'})))


def load(path):
    acls, bindings = {}, {}
    current = interface = None
    for number, raw in enumerate(Path(path).read_text(encoding='utf-8-sig').splitlines(), 1):
        line = raw.strip()
        if raw == '!':
            current = interface = None
            continue
        if not line or line.startswith('!'):
            continue
        if line.startswith('ip access-list extended '):
            current = line.split()[-1]
            if current in acls:
                raise ValueError('duplicate ACL definition')
            acls[current] = []
        elif line.startswith('interface '):
            current = None
            interface = line.split()[1]
        elif line.startswith('ip access-group '):
            words = line.split()
            if words[-1] != 'in' or interface is None:
                raise ValueError('only inbound interface bindings supported')
            bindings[interface.lower()] = words[2]
        elif line in ('exit', 'end'):
            current = interface = None
        elif current:
            words = line.split()
            action, protocol = words.pop(0), words.pop(0)
            if action not in ('permit', 'deny') or protocol not in ('ip', 'tcp', 'udp', 'icmp'):
                raise ValueError(f'unsupported ACL syntax at line {number}: {line}')
            source = endpoint(words)
            sport = port(words)
            destination = endpoint(words)
            dport = port(words)
            kind = None
            established = False
            if protocol == 'icmp' and words:
                kind = ICMP[words.pop(0)]
            if words == ['established'] and protocol == 'tcp':
                established = True
                words.clear()
            if words:
                raise ValueError(f'unsupported ACL suffix at line {number}: {words}')
            acls[current].append(Rule(action, protocol, source, destination, sport, dport,
                                      kind, established, number, line))
    if not acls or any(name not in acls for name in bindings.values()):
        raise ValueError('missing ACL definitions or bindings')
    return acls, bindings


def evaluate(path, vlan, packet):
    if packet.get('protocol') not in ('tcp', 'udp', 'icmp'):
        raise ValueError('unsupported packet protocol')
    acls, bindings = load(path)
    name = bindings[f'vlan{vlan}']
    for rule in acls[name]:
        if rule.matches(packet):
            return {'action': rule.action, 'acl': name, 'line': rule.line, 'rule': rule.text}
    return {'action': 'deny', 'acl': name, 'line': None, 'rule': 'implicit deny'}


def packet(source, destination, protocol='tcp', destination_port=80, **extra):
    return dict(source_ip=source, destination_ip=destination, protocol=protocol,
                destination_port=destination_port, **extra)


def cases():
    """Expected outcomes from the supplied access matrix and security test plan."""
    out = []
    def add(name, vlan, source, destination, expected, protocol='tcp', destination_port=80, **extra):
        out.append(dict(id=name, vlan=vlan, expected=expected,
                        packet=packet(source, destination, protocol, destination_port, **extra)))
    add('authorized_research_http', 30, '192.168.30.100', '192.168.50.10', 'permit')
    add('student_admin_http', 10, '192.168.10.101', '192.168.50.12', 'deny')
    add('admin_server_health_control', 40, '192.168.40.100', '192.168.50.12', 'permit')
    add('student_research_before_containment', 10, '192.168.10.101', '192.168.50.10', 'permit')
    add('restricted_research_http', 60, '192.168.60.100', '192.168.50.10', 'deny')
    add('restricted_remediation_http', 60, '192.168.60.100', '192.168.50.13', 'permit')
    add('quarantine_remediation_http', 70, '192.168.70.100', '192.168.50.13', 'deny')
    add('restricted_internet_http', 60, '192.168.60.100', '203.0.113.2', 'deny')
    add('quarantine_internet_http', 70, '192.168.70.100', '203.0.113.2', 'deny')
    add('recovered_internet_http', 10, '192.168.10.101', '203.0.113.2', 'permit')
    add('student_db_ftp', 10, '192.168.10.101', '192.168.50.11', 'deny', destination_port=21)
    add('research_db_ftp_control', 30, '192.168.30.100', '192.168.50.11', 'permit', destination_port=21)
    add('student_management_ssh', 10, '192.168.10.101', '192.168.40.21', 'deny', destination_port=22)
    add('policy_host_management_rule', 40, '192.168.40.50', '192.168.40.21', 'permit', destination_port=22)
    add('research_performance_ping', 30, '192.168.30.100', '192.168.50.10', 'permit', 'icmp', None, icmp_type=8)
    add('S12_student_admin_ping', 10, '192.168.10.101', '192.168.40.100', 'deny', 'icmp', None, icmp_type=8)
    add('admin_all_internet_ports_matrix', 40, '192.168.40.100', '203.0.113.2', 'permit', destination_port=25)
    for vlan in (10, 20, 30, 40, 50, 60, 70):
        add(f'dhcp_discovery_vlan{vlan}', vlan, '0.0.0.0', '255.255.255.255', 'permit', 'udp', 67, source_port=68)
    for vlan in (60, 70):
        add(f'contained_gateway_ping_vlan{vlan}', vlan, f'192.168.{vlan}.100', f'192.168.{vlan}.1',
            'permit', 'icmp', None, icmp_type=8)
    return out


def audit(path):
    return [{**case, **evaluate(path, case['vlan'], case['packet']),
             'matches_documented_expectation': evaluate(path, case['vlan'], case['packet'])['action'] == case['expected'],
             'evidence_level': 'configuration_semantics_only_not_network'} for case in cases()]
