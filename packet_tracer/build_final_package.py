"""Build the current handoff from immutable exports, without opening Packet Tracer.

Exit 1 means a documented configuration mismatch remains; outputs are still written.
Never writes the .pkt, exports, observed evidence, Git index or remote repository.
"""
import csv
import hashlib
import json
from pathlib import Path

from final_audit import Campus, DEVICES, HERE, audit

OUTPUT = HERE / 'final_package'
PATCH = '''! Reference correction; consult the current EDGE-R export for application status.
! EDGE-R only. Create a new ACL before binding it; keep the original for rollback.
enable
configure terminal
ip access-list extended QUARANTINE-IN-V2
 permit udp any eq bootpc any eq bootps
 permit icmp 192.168.70.0 0.0.0.255 host 192.168.70.1 echo
 deny ip any any
exit
interface GigabitEthernet0/2
 ip access-group QUARANTINE-IN-V2 in
exit
end
! Verify gateway ping and server denial before write memory / topology save.
'''
ROLLBACK = '''! EDGE-R: historical rollback; restores the old gateway-ping denial.
enable
configure terminal
interface GigabitEthernet0/2
 ip access-group QUARANTINE-IN in
exit
end
'''


def topology():
    devices = [{'name': name, 'model': ('3560-24PS' if name == 'CORE-SW' else
                '2960-24TT' if name.startswith('ACCESS') else '2911'),
                'configuration': '../evidence/' + name + '_final_running_config.txt'} for name in DEVICES]
    links = []

    def link(left, lp, right, rp, vlan=None, cable='straight-through'):
        links.append(dict(device_a=left, port_a=lp, device_b=right, port_b=rp,
                          vlan=vlan, cable=cable))

    for index, switch in enumerate(('ACCESS-SW-A', 'ACCESS-SW-B'), 1):
        link('CORE-SW', f'GigabitEthernet0/{index}', switch, 'GigabitEthernet0/1',
             'trunk', 'crossover')
    for index, router in enumerate(('FW-STU-FAC', 'FW-RES-ADM', 'FW-SRV-REST')):
        for port, vlan in enumerate(((10, 20, 900), (30, 40, 900), (50, 60, 900))[index]):
            link('CORE-SW', f'FastEthernet0/{index * 3 + port + 1}', router,
                 f'GigabitEthernet0/{port}', vlan)
    link('CORE-SW', 'FastEthernet0/10', 'EDGE-R', 'GigabitEthernet0/2', 70)
    link('CORE-SW', 'FastEthernet0/24', 'EDGE-R', 'GigabitEthernet0/0', 900)
    for switch, names in (
        ('ACCESS-SW-A', [('PC-STU1', 10), ('PC-STU2', 10), ('PC-FAC1', 20),
                         ('PC-FAC2', 20), ('PC-ADM1', 40), ('PC-ADM2', 40), ('POLICY-HOST', 40)]),
        ('ACCESS-SW-B', [('PC-RES1', 30), ('PC-RES2', 30), ('SRV-RESEARCH', 50),
                         ('SRV-DB', 50), ('SRV-ADMIN', 50), ('SRV-REMEDIATE', 50)])):
        for port, (name, vlan) in enumerate(names, 1):
            props = dict(name=name, model='Server-PT' if name.startswith('SRV') else 'PC-PT', vlan=vlan)
            if name.startswith('SRV'):
                props.update(ipv4=f'192.168.50.{port + 7}', mask='255.255.255.0',
                             gateway='192.168.50.1')
            elif name == 'POLICY-HOST':
                props.update(ipv4='192.168.40.50', mask='255.255.255.0', gateway='192.168.40.1',
                             dns='203.0.113.2')
            else:
                props.update(ipv4='DHCP', dns='203.0.113.2')
            devices.append(props)
            link(switch, f'FastEthernet0/{port}', name, 'FastEthernet0', vlan)
    devices.append(dict(name='INTERNET-SRV', model='Server-PT', ipv4='203.0.113.2',
                        mask='255.255.255.252', gateway='203.0.113.1', dns='203.0.113.2'))
    link('EDGE-R', 'GigabitEthernet0/1', 'INTERNET-SRV', 'FastEthernet0', cable='crossover')
    return dict(basis='Final exported switch/router configuration and documented manual cabling',
                endpoint_settings_basis='Recorded user screenshots and packet_tracer/README.md; not a binary decode',
                native_project='../University_Research_Network_Final.pkt',
                native_rebuild='Manual Packet Tracer build; this script does not generate a .pkt',
                devices=devices, links=links)


def validate_cabling(design, campus):
    used = set()
    for cable in design['links']:
        for side in ('a', 'b'):
            name, port = cable['device_' + side], cable['port_' + side]
            if (name, port) in used:
                raise ValueError('duplicate cabled port: ' + name + '/' + port)
            used.add((name, port))
            if name not in campus.devices:
                continue
            props = campus.devices[name].interfaces[port]
            if props['shutdown']:
                raise ValueError('cabled interface is shutdown: ' + name + '/' + port)
            if name.startswith('ACCESS') or name == 'CORE-SW':
                lines = props['lines']
                if cable['vlan'] == 'trunk':
                    if 'switchport mode trunk' not in lines or 'switchport trunk native vlan 999' not in lines:
                        raise ValueError('trunk mismatch: ' + name + '/' + port)
                    allowed = next(line.split()[-1] for line in lines if line.startswith('switchport trunk allowed vlan '))
                    if not {10, 20, 30, 40, 50, 60, 70}.issubset({int(x) for x in allowed.split(',')}):
                        raise ValueError('role VLAN absent from trunk')
                elif ('switchport mode access' not in lines or
                      f"switchport access vlan {cable['vlan']}" not in lines):
                    raise ValueError('access VLAN mismatch: ' + name + '/' + port)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def build():
    campus = Campus()
    design = topology()
    validate_cabling(design, campus)
    results = audit()
    OUTPUT.mkdir(exist_ok=True)
    write_json(OUTPUT / 'topology.json', design)
    with (OUTPUT / 'cabling.csv').open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(design['links'][0]))
        writer.writeheader()
        writer.writerows(design['links'])
    with (OUTPUT / 'acceptance_matrix.csv').open('w', newline='', encoding='utf-8') as stream:
        writer = csv.writer(stream)
        writer.writerow(['case', 'source', 'destination', 'protocol', 'destination_port',
                         'required_allow', 'configured_allow', 'matches_requirement', 'evidence_level', 'network_status'])
        for row in results:
            p = row['packet']
            writer.writerow([row['id'], p['source'], p['destination'], p['protocol'], p['dport'],
                             row['expected'], row['configured_allow'], row['matches_requirement'],
                             row['evidence_level'], row['network_status']])
    write_json(OUTPUT / 'offline_policy_audit.json', dict(
        scope='Initial-flow ACL, routing and zone-policy configuration inference only',
        excludes=['Live network tests', 'L2 forwarding', 'NAT/session return paths', 'FTP helper pinholes',
                  'DHCP service operation', 'Server availability', 'SSH/TLS', 'Automatic detection or recovery'],
        cases=len(results), matching=sum(r['matches_requirement'] for r in results), results=results))
    changes = OUTPUT / 'pending_changes'
    changes.mkdir(exist_ok=True)
    (changes / 'EDGE-R_quarantine_gateway.cfg').write_text(PATCH, encoding='utf-8')
    (changes / 'EDGE-R_rollback.cfg').write_text(ROLLBACK, encoding='utf-8')
    mismatch = [r for r in results if not r['matches_requirement']]
    correction_applied = (campus.devices['EDGE-R'].interfaces['GigabitEthernet0/2'].get('acl')
                          == 'QUARANTINE-IN-V2' and
                          next(r for r in results if r['id'] == 'vlan70_own_gateway')['configured_allow'])
    correction_status = ('The current EDGE-R export contains the applied QUARANTINE-IN-V2 binding\n'
                         'and permits the agreed own-gateway echo. The user also supplied successful\n'
                         'gateway/blocked-server ping screenshots and reported saving the topology.'
                         if correction_applied else
                         'The gateway correction is not confirmed in the current export. Review the\n'
                         'offline audit and reference correction before changing the simulator.')
    report = f'''# Final local handoff

Generated without screen control. {len(design['devices'])} devices, {len(design['links'])} links;
cabled switch ports checked against the genuine exports.

{len(results) - len(mismatch)}/{len(results)} initial-flow configuration expectations match.
These are offline inferences, not additional live test passes. Existing observed
results are recorded separately in ../evidence/observed_test_results.csv.

## Gateway correction status

{correction_status}

The retained pending_changes directory contains the reference correction and
historical rollback, not a request to reapply the completed change. Rollback
restores the former gateway-ping denial. Review current exports before use.

## Remaining simulator work

- Active FTP retrieval and denied upload now have user screenshot evidence.
  Delete/rename denial still requires disposable fixtures. Passive FTP remains unresolved.
- The user reports removal of the default full-permission FTP account and a saved
  topology. This server-account state is not independently decoded from the .pkt.
- Management SVI reachability and unused server-service inventory are unverified.
- Automatic PT detection/control, full recovery expiry and PT performance comparison
  remain unimplemented or unverified. Existing Linux evidence is separate.

Follow ../README.md for endpoint services/DNS and manual build steps. Use the
seven genuine exports referenced by topology.json; avoid older candidate scripts.
No FTP password is generated or copied into this package.
'''
    (OUTPUT / 'README.md').write_text(report, encoding='utf-8')
    sources = [HERE / 'University_Research_Network_Final.pkt'] + [
        HERE / 'evidence' / (name + '_final_running_config.txt') for name in DEVICES]
    write_json(OUTPUT / 'source_hashes.json', [dict(path=p.relative_to(HERE).as_posix(),
               bytes=p.stat().st_size, sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in sources])
    print(f'Built {OUTPUT}: {len(design["devices"])} devices / {len(design["links"])} links; '
          f'{len(results) - len(mismatch)}/{len(results)} offline policy matches; {len(mismatch)} pending mismatch(es).')
    return int(bool(mismatch))


if __name__ == '__main__':
    raise SystemExit(build())
