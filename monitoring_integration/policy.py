"""Reconcile and compile the delivered Member 2 ACLs; no independent allow engine.

Local resolution: Member 2's explicit restricted/quarantine security requirements
take precedence over Member 3's more permissive descriptive table. Admin's matrix
permits all ports to the simulated external host. Peers remain isolated; research
ping remains available. IOS ACK/RST checks are retained, not called stateful ACLs.
"""
from pathlib import Path
from ipaddress import IPv4Address, IPv4Network
import json
from acl_audit import load

HERE = Path(__file__).resolve().parent
SOURCE = HERE / 'upstream/member2/cnpro/configs/CORE-SW_security_acls.cfg'


def reconcile(destination):
    acls, bindings = load(SOURCE)
    output = ['! Effective local integration policy; source Member 2 ACLs preserved.',
              '! Restricted: DHCP/gateway/remediation HTTP+DNS only. Quarantine: DHCP/gateway only.',
              'configure terminal']
    decisions = []
    for name, rules in acls.items():
        vlan = next(int(k[4:]) for k, v in bindings.items() if v == name)
        output.append('ip access-list extended ' + name)
        for rule in rules:
            text = rule.text
            if text == 'permit udp any any eq bootps':
                text = 'permit udp any eq bootpc any eq bootps'
            elif text == 'permit udp any any eq bootpc':
                text = 'permit udp any eq bootps any eq bootpc'
            if vlan in (10, 20, 30) and rule.protocol == 'icmp' and rule.destination[1] == '255.255.255.255':
                # Unrestricted ICMP preceded explicit deny ip and bypassed isolation.
                # Only gateway diagnostics and research benchmark are intended.
                if rule.icmp_type == 8:
                    output.append(f' permit icmp 192.168.{vlan}.0 0.0.0.255 host 192.168.{vlan}.1 echo')
                    if vlan == 30:
                        output.append(' permit icmp 192.168.30.0 0.0.0.255 host 192.168.50.10 echo')
                if rule.icmp_type == 0:
                    output.append(f' permit icmp 192.168.{vlan}.0 0.0.0.255 192.168.40.0 0.0.0.255 echo-reply')
                decisions.append(dict(vlan=vlan, previous=text, resolution='scope ICMP to documented diagnostics, preserve peer isolation'))
                continue
            if vlan == 40 and text == 'permit tcp 192.168.40.0 0.0.0.255 192.168.40.0 0.0.0.255 eq 22':
                text = 'deny tcp 192.168.40.0 0.0.0.255 192.168.40.0 0.0.0.255 eq 22'
                decisions.append(dict(vlan=vlan, resolution='management SSH only from POLICY-HOST; enforce VTY access-class for same-VLAN traffic'))
            if vlan == 40 and text == 'permit ip 192.168.40.0 0.0.0.255 10.0.0.0 0.0.0.3':
                output.append(' permit ip 192.168.40.0 0.0.0.255 host 203.0.113.2')
                decisions.append(dict(vlan=vlan, resolution='honor matrix: admin all ports to INTERNET-SRV'))
            if vlan == 50 and text == 'permit ip 192.168.50.0 0.0.0.255 any':
                output.extend([' permit tcp host 192.168.50.13 eq domain any established',
                               ' permit ip 192.168.50.0 0.0.0.255 192.168.40.0 0.0.0.255'])
                decisions.append(dict(vlan=vlan, resolution='remove unrestricted server-initiated egress; retain service replies and admin maintenance replies'))
                continue
            output.append(' ' + text)
        output.append('exit')
    for interface, name in bindings.items():
        output.extend(['interface ' + interface, ' ip access-group ' + name + ' in', 'exit'])
    output.extend(['end', 'write memory'])
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text('\n'.join(output) + '\n', encoding='utf-8')
    return decisions


def cidr(endpoint):
    address, wildcard = endpoint
    return str(IPv4Network((address, str(IPv4Address((~int(IPv4Address(wildcard))) & 0xffffffff))), strict=False))


def nft_rules(acl, drops):
    """Compile the effective IOS ACLs into actual kernel nftables rules.

    Dedicated ingress drop counters are the reliable automatic event source.
    Established flags use IOS ACK/RST semantics; no global conntrack permit can
    keep an old connection open across containment.
    """
    acls, bindings = load(acl)
    lines = ['table inet cnpro {',
             ' chain input { type filter hook input priority 0; policy accept;',
             ' tcp dport 22 ip saddr != 192.168.40.50 drop', ' }',
             ' chain forward { type filter hook forward priority 0; policy drop;',
             ' iifname "br0" oifname "br0" accept']
    for vlan, name in sorted((int(i[4:]), n) for i, n in bindings.items()):
        lines.append(f' iifname "v{vlan}" jump acl{vlan}')
    lines += [' iifname "v99" ip saddr 203.0.113.2 accept', ' }']
    for interface, name in bindings.items():
        vlan = int(interface[4:])
        lines.append(f' chain acl{vlan} {{')
        if vlan == 50:
            # Linux can enforce the documented response-only requirement using
            # real connection state; an IOS ACK bit alone is not equivalent.
            lines.append(' ct state established,related accept')
        for r in acls[name]:
            parts = []
            if r.protocol != 'ip':
                parts += ['meta l4proto', r.protocol]
            if r.source[1] != '255.255.255.255':
                parts += ['ip saddr', cidr(r.source)]
            if r.destination[1] != '255.255.255.255':
                parts += ['ip daddr', cidr(r.destination)]
            if r.source_port is not None:
                parts += [r.protocol + ' sport', str(r.source_port)]
            if r.destination_port is not None:
                parts += [r.protocol + ' dport', str(r.destination_port)]
            if r.icmp_type is not None:
                parts += ['icmp type', str(r.icmp_type)]
            if vlan in (10, 20, 30) and r.icmp_type == 0 and r.action == 'permit':
                # Only replies belonging to an administration-initiated ping.
                parts += ['ct state established']
            if r.established:
                parts += ['tcp flags & (ack|rst) != 0']
            # Preserve first-match behavior. Per-IP kernel counters identify a
            # deny only after the actual kernel policy has rejected the packet.
            if vlan == 50 and r.action == 'permit' and r.source_port not in (67,):
                parts += ['ct state established,related']
            parts += ['accept' if r.action == 'permit' else 'jump denied']
            lines.append(' ' + ' '.join(parts))
        lines += [' jump denied', ' }']
    lines.append(' chain denied {')
    for index, address in enumerate(drops):
        lines.append(f' ip saddr {address} counter drop comment "endpoint:{index}"')
    lines += [' counter drop', ' }', '}', 'table ip cnpro_nat {',
              ' chain post { type nat hook postrouting priority srcnat; policy accept;',
              ' oifname "v99" snat to 203.0.113.1', ' }', '}']
    return '\n'.join(lines) + '\n'


if __name__ == '__main__':
    print(json.dumps(reconcile(HERE / 'effective/CORE-SW_security_acls.cfg'), indent=2))
