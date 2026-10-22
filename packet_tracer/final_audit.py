"""Offline audit of genuine PT exports; never a network emulator or GUI controller.

Evaluates *new* routed flows through interface ACLs, longest-prefix routing and
ordered zone-policy classes. Does not invent session state, NAT readbacks, service
availability, TLS handshakes or negotiated FTP data pinholes. Unknown syntax fails.
"""
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
DEVICES = ('CORE-SW', 'ACCESS-SW-A', 'ACCESS-SW-B', 'EDGE-R',
           'FW-STU-FAC', 'FW-RES-ADM', 'FW-SRV-REST')
GATEWAYS = {10: ('FW-STU-FAC', 'GigabitEthernet0/0'),
            20: ('FW-STU-FAC', 'GigabitEthernet0/1'),
            30: ('FW-RES-ADM', 'GigabitEthernet0/0'),
            40: ('FW-RES-ADM', 'GigabitEthernet0/1'),
            50: ('FW-SRV-REST', 'GigabitEthernet0/0'),
            60: ('FW-SRV-REST', 'GigabitEthernet0/1'),
            70: ('EDGE-R', 'GigabitEthernet0/2'),
            99: ('EDGE-R', 'GigabitEthernet0/1')}
PORTS = {'www': 80, 'domain': 53, 'ftp': 21, 'ftp-data': 20,
         'bootpc': 68, 'bootps': 67}
ICMP = {'echo': 8, 'echo-reply': 0, 'unreachable': 3, 'time-exceeded': 11}


def number(value):
    result = PORTS[value] if value in PORTS else int(value)
    if not 0 <= result <= 65535:
        raise ValueError('invalid port')
    return result


def endpoint(words):
    token = words.pop(0)
    if token == 'any':
        return 0, 0xffffffff
    address = int(IPv4Address(words.pop(0) if token == 'host' else token))
    return address, 0 if token == 'host' else int(IPv4Address(words.pop(0)))


def port_condition(words):
    if not words or words[0] not in ('eq', 'gt', 'lt', 'range', 'neq'):
        return None
    op = words.pop(0)
    values = [number(words.pop(0)) for _ in range(2 if op == 'range' else 1)]
    if len(values) == 2 and values[0] > values[1]:
        raise ValueError('invalid port range')
    return op, values


def port_matches(condition, value):
    if condition is None:
        return True
    if value is None:
        return False
    op, values = condition
    return {'eq': value == values[0], 'neq': value != values[0],
            'gt': value > values[0], 'lt': value < values[0],
            'range': values[0] <= value <= values[-1]}[op]


@dataclass
class Rule:
    text: str
    action: str
    protocol: str
    source: tuple
    destination: tuple
    sport: object
    dport: object
    icmp: object
    established: bool

    @classmethod
    def parse(cls, text):
        words = text.split()
        if words and words[0].isdigit():
            words.pop(0)
        action, protocol = words.pop(0), words.pop(0)
        if action not in ('permit', 'deny') or protocol not in ('ip', 'tcp', 'udp', 'icmp'):
            raise ValueError('unsupported ACL: ' + text)
        source = endpoint(words)
        sport = port_condition(words)
        destination = endpoint(words)
        dport = port_condition(words)
        kind = None
        if protocol == 'icmp' and words:
            kind = ICMP[words.pop(0)]
        established = words == ['established'] and protocol == 'tcp'
        if established:
            words.clear()
        if words:
            raise ValueError('unsupported ACL suffix: ' + text)
        return cls(text, action, protocol, source, destination, sport, dport, kind, established)

    def matches(self, packet):
        def address(value, pair):
            base, wildcard = pair
            mask = (~wildcard) & 0xffffffff
            return int(IPv4Address(value)) & mask == base & mask
        return (self.protocol in ('ip', packet['protocol'])
                and address(packet['source'], self.source)
                and address(packet['destination'], self.destination)
                and port_matches(self.sport, packet.get('sport'))
                and port_matches(self.dport, packet.get('dport'))
                and (self.icmp is None or self.icmp == packet.get('icmp'))
                and (not self.established or bool({'ACK', 'RST'} & set(packet.get('flags', [])))))


def sections(text):
    """Running-config top-level blocks, retaining ordered child directives."""
    result = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith('!'):
            continue
        if raw.startswith(' '):
            if not result:
                raise ValueError('orphan configuration line')
            result[-1][1].append(raw.strip())
        else:
            result.append((raw.strip(), []))
    return result


class Device:
    def __init__(self, path):
        self.path = Path(path)
        self.text = self.path.read_text(encoding='utf-8-sig')
        self.interfaces, self.acls, self.classes, self.policies, self.pairs = {}, {}, {}, {}, {}
        self.routes, self.vlans, self.standard_acls = [], {}, {}
        for head, body in sections(self.text):
            if head.startswith('hostname '):
                self.name = head.split()[1]
            elif head.startswith('interface '):
                props = {'lines': body, 'shutdown': 'shutdown' in body}
                for line in body:
                    if line.startswith('ip address '):
                        _, _, ip, mask = line.split()
                        props['address'] = IPv4Interface(ip + '/' + mask)
                    elif line.startswith('zone-member security '):
                        props['zone'] = line.split()[-1]
                    elif line.startswith('ip access-group '):
                        if line.split()[-1] != 'in':
                            raise ValueError('outbound ACL not supported')
                        props['acl'] = line.split()[2]
                self.interfaces[head.split()[1]] = props
            elif head.startswith('ip access-list extended '):
                name = head.split()[-1]
                if name in self.acls:
                    raise ValueError('duplicate ACL ' + name)
                self.acls[name] = [Rule.parse(line) for line in body if not line.startswith('remark ')]
            elif head.startswith('ip access-list standard '):
                self.standard_acls[head.split()[-1]] = body
            elif head.startswith('class-map type inspect '):
                words = head.split()
                self.classes[words[-1]] = (words[-2], body)
            elif head.startswith('policy-map type inspect '):
                rules = []
                for line in body:
                    if line.startswith('class '):
                        rules.append([line.split()[-1], None])
                    elif line in ('inspect', 'pass', 'drop') and rules:
                        rules[-1][1] = line
                    else:
                        raise ValueError('unsupported policy directive: ' + line)
                self.policies[head.split()[-1]] = rules
            elif head.startswith('zone-pair security '):
                words = head.split()
                pair = (words[4], words[6])
                policies = [line.split()[-1] for line in body if line.startswith('service-policy type inspect ')]
                if len(policies) != 1 or pair in self.pairs:
                    raise ValueError('missing or duplicate zone-pair policy')
                self.pairs[pair] = policies[0]
            elif head.startswith('ip route '):
                words = head.split()
                if len(words) != 5:
                    raise ValueError('unsupported static route: ' + head)
                self.routes.append((IPv4Network(words[2] + '/' + words[3]), IPv4Address(words[4])))
            elif re.fullmatch(r'vlan \d+', head):
                self.vlans[int(head.split()[1])] = body
        if not hasattr(self, 'name'):
            raise ValueError('export has no hostname')
        for props in self.interfaces.values():
            if props.get('acl') and props['acl'] not in self.acls:
                raise ValueError('undefined interface ACL')
        for policy in self.pairs.values():
            if policy not in self.policies:
                raise ValueError('undefined service policy')

    def acl_permits(self, name, packet):
        for rule in self.acls[name]:
            if rule.matches(packet):
                return rule.action == 'permit', rule.text
        return False, 'implicit deny'

    def class_matches(self, name, packet):
        mode, lines = self.classes[name]
        matches = []
        for line in lines:
            if line.startswith('match access-group name '):
                matches.append(self.acl_permits(line.split()[-1], packet)[0])
            elif line.startswith('match protocol '):
                protocol = line.split()[-1]
                if protocol == 'ftp':
                    matches.append(packet['protocol'] == 'tcp' and packet.get('dport') == 21)
                elif protocol in ('tcp', 'udp', 'icmp'):
                    matches.append(packet['protocol'] == protocol)
                else:
                    raise ValueError('unsupported class protocol ' + protocol)
            else:
                raise ValueError('unsupported class match ' + line)
        if not matches or mode not in ('match-all', 'match-any'):
            raise ValueError('empty or unsupported class')
        return all(matches) if mode == 'match-all' else any(matches)

    def forward(self, ingress, egress, packet):
        source = self.interfaces[ingress].get('zone')
        destination = self.interfaces[egress].get('zone')
        if source == destination:
            return True, 'same-zone or both unzoned'
        if not source or not destination:
            return False, 'zoned/unzoned boundary'
        policy = self.pairs.get((source, destination))
        if not policy:
            return False, 'no zone pair'
        for name, action in self.policies[policy]:
            if name == 'class-default' or self.class_matches(name, packet):
                return action in ('inspect', 'pass'), policy + '/' + name + '/' + str(action)
        return False, 'no policy class'

    def route(self, destination):
        ip = IPv4Address(destination)
        choices = [(props['address'].network.prefixlen, name, None)
                   for name, props in self.interfaces.items()
                   if not props['shutdown'] and 'address' in props and ip in props['address'].network]
        for network, next_hop in self.routes:
            if ip not in network:
                continue
            for name, props in self.interfaces.items():
                if not props['shutdown'] and 'address' in props and next_hop in props['address'].network:
                    choices.append((network.prefixlen, name, next_hop))
        if not choices:
            raise ValueError(self.name + ': no usable route to ' + destination)
        _, interface, next_hop = max(choices, key=lambda item: item[0])
        return interface, next_hop


class Campus:
    def __init__(self, directory=HERE / 'evidence'):
        self.devices = {name: Device(Path(directory) / (name + '_final_running_config.txt')) for name in DEVICES}
        self.owners = {}
        for name, device in self.devices.items():
            if device.name != name:
                raise ValueError('export hostname mismatch')
            for interface, props in device.interfaces.items():
                if 'address' in props:
                    ip = props['address'].ip
                    if ip in self.owners:
                        raise ValueError('duplicate interface address')
                    self.owners[ip] = (name, interface)

    def initial_flow(self, vlan, packet):
        """Return configuration inference only; never returns a live PASS."""
        name, ingress = GATEWAYS[vlan]
        trace = []
        for _ in range(8):
            device = self.devices[name]
            props = device.interfaces[ingress]
            if props['shutdown']:
                return False, trace + [name + ': ingress shutdown']
            if props.get('acl'):
                allowed, rule = device.acl_permits(props['acl'], packet)
                trace.append(name + ': ingress ' + rule)
                if not allowed:
                    return False, trace
            if IPv4Address(packet['destination']) in [p['address'].ip for p in device.interfaces.values() if 'address' in p]:
                if packet['protocol'] != 'icmp':
                    raise ValueError('router application/self-zone service behaviour is not modeled')
                return True, trace + [name + ': router-local ICMP; availability untested']
            egress, next_hop = device.route(packet['destination'])
            allowed, reason = device.forward(ingress, egress, packet)
            trace.append(name + ': ' + ingress + ' -> ' + egress + ': ' + reason)
            if not allowed:
                return False, trace
            if next_hop is None:
                return True, trace + ['destination subnet reached in configuration; service not probed']
            if next_hop not in self.owners:
                raise ValueError('next-hop owner absent')
            name, ingress = self.owners[next_hop]
        raise ValueError('route loop')


# Expectations are the agreed service matrix, independent of the parsed exports.
SERVICES = (
    ('research_http', '192.168.50.10', 'tcp', 80, {10, 20, 30, 40}),
    ('research_https', '192.168.50.10', 'tcp', 443, {20, 30, 40}),
    ('research_ping', '192.168.50.10', 'icmp', None, {30, 40}),
    ('database_ftp_control', '192.168.50.11', 'tcp', 21, {30, 40}),
    ('administration_http', '192.168.50.12', 'tcp', 80, {40}),
    ('administration_https', '192.168.50.12', 'tcp', 443, {40}),
    ('remediation_http', '192.168.50.13', 'tcp', 80, {10, 20, 30, 40, 60}),
    ('remediation_dns_udp', '192.168.50.13', 'udp', 53, {10, 20, 30, 40, 60}),
    ('remediation_dns_tcp', '192.168.50.13', 'tcp', 53, {10, 20, 30, 40, 60}),
    ('remediation_ping', '192.168.50.13', 'icmp', None, {40}),
    ('external_http', '203.0.113.2', 'tcp', 80, {10, 20, 30, 40}),
    ('external_https', '203.0.113.2', 'tcp', 443, {10, 20, 30, 40}),
    ('external_dns_udp', '203.0.113.2', 'udp', 53, {10, 20, 30, 40}),
    ('external_dns_tcp', '203.0.113.2', 'tcp', 53, {10, 20, 30, 40}),
    ('external_ping', '203.0.113.2', 'icmp', None, {40}),
    ('external_tcp25_policy', '203.0.113.2', 'tcp', 25, {40}),
)


def policy_cases():
    cases = []
    def add(identifier, vlan, destination, protocol, port, expected, source=None, sport=45000):
        cases.append(dict(id=identifier, vlan=vlan, expected=expected,
                          packet=dict(source=source or f'192.168.{vlan}.101', destination=destination,
                                      protocol=protocol, dport=port, sport=sport, icmp=8)))
    for vlan in (10, 20, 30, 40, 60, 70):
        for service, destination, protocol, port, allowed in SERVICES:
            add(f'vlan{vlan}_{service}', vlan, destination, protocol, port, vlan in allowed)
        add(f'vlan{vlan}_own_gateway', vlan, f'192.168.{vlan}.1', 'icmp', None, True)
    for source_vlan in (10, 20, 30, 40, 60, 70):
        for destination_vlan in (10, 20, 30, 40):
            if source_vlan == destination_vlan:
                continue
            add(f'vlan{source_vlan}_to_vlan{destination_vlan}_ping', source_vlan,
                f'192.168.{destination_vlan}.100', 'icmp', None, source_vlan == 40)
    for destination_vlan in (10, 20, 30, 40, 60, 70):
        add(f'server_new_http_to_vlan{destination_vlan}', 50, f'192.168.{destination_vlan}.100', 'tcp', 80,
            False, source='192.168.50.10')
        add(f'db_active_data_to_vlan{destination_vlan}', 50, f'192.168.{destination_vlan}.100', 'tcp', 45000,
            destination_vlan in (30, 40), source='192.168.50.11', sport=20)
    add('external_unsolicited_student_http', 99, '192.168.10.100', 'tcp', 80, False, source='203.0.113.2')
    add('external_unsolicited_admin_http', 99, '192.168.40.100', 'tcp', 80, False, source='203.0.113.2')
    return cases


def audit(directory=HERE / 'evidence'):
    campus = Campus(directory)
    results = []
    for case in policy_cases():
        allowed, trace = campus.initial_flow(case['vlan'], case['packet'])
        results.append({**case, 'configured_allow': allowed, 'matches_requirement': allowed == case['expected'],
                        'trace': trace, 'evidence_level': 'offline_configuration_inference',
                        'network_status': 'NOT_RUN_BY_THIS_AUDIT'})
    return results
