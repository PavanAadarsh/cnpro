"""Bounded HTTP traffic from an explicitly bound real project test-host address.

Run only in a matching real/emulated lab; this cannot drive Packet Tracer PCs.
"""
import http.client
import ipaddress
import json
from pathlib import Path
import shutil
import socket
import time
from datetime import datetime, timezone

from acl_audit import evaluate, packet

HERE = Path(__file__).resolve().parent
ACL = HERE / 'upstream/member2/cnpro/configs/CORE-SW_security_acls.cfg'
TARGETS = {'authorized': ('PC-RES1', '192.168.50.10'),
           'protected_access': ('PC-STU2', '192.168.50.12'),
           'affected_research': ('PC-STU2', '192.168.50.10'),
           'remediation': ('PC-STU2', '192.168.50.13'),
           'recovery': ('PC-STU2', '203.0.113.2'),
           'admin_health_control': ('PC-ADM1', '192.168.50.12')}


def request(source, target, timeout):
    connection = http.client.HTTPConnection(target, 80, timeout=timeout, source_address=(source, 0))
    started = time.perf_counter_ns()
    result = dict(status=None, succeeded=False, error=None)
    try:
        connection.request('GET', '/', headers={'Connection': 'close', 'Cache-Control': 'no-cache'})
        response = connection.getresponse()
        result['status'] = response.status
        # Read only a bounded prefix; no application throughput inference.
        result['prefix_bytes'] = len(response.read(4096))
        result['succeeded'] = 200 <= response.status < 300
    except (OSError, http.client.HTTPException) as exc:
        result['error'] = type(exc).__name__ + ': ' + str(exc)
    finally:
        connection.close()
    result['request_duration_ms'] = (time.perf_counter_ns() - started) / 1e6
    return result


def collect(output, scenario, source_ip, vlan, configuration, configuration_snapshot,
            count=5, interval=1.0, timeout=2.0, trial=1):
    if scenario not in TARGETS or configuration not in ('static', 'adaptive'):
        raise ValueError('unknown scenario/configuration')
    if type(trial) is not int or trial < 1:
        raise ValueError('trial must be positive')
    if type(count) is not int or not 1 <= count <= 100 or not .2 <= interval <= 60 or not .1 <= timeout <= 10:
        raise ValueError('count 1..100, interval .2..60 seconds, timeout .1..10 seconds')
    device, target = TARGETS[scenario]
    if vlan not in ((30,) if device == 'PC-RES1' else (40,) if device == 'PC-ADM1' else (10, 60, 70)):
        raise ValueError('VLAN does not match this scenario source')
    address = ipaddress.ip_address(source_ip)
    if address not in ipaddress.ip_network(f'192.168.{vlan}.0/24') or not 100 <= int(str(address).split('.')[-1]) <= 254:
        raise ValueError('supply the current DHCP test-host address')
    snapshot = Path(configuration_snapshot)
    if not snapshot.is_file():
        raise ValueError('save the actual active CORE-SW configuration first')
    # Fail before generating a run if this address is not locally assigned.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as local:
        local.bind((source_ip, 0))
    path = Path(output)
    path.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(snapshot, path / 'active-config.txt')
    started = datetime.now(timezone.utc).isoformat()
    results = []
    for index in range(count):
        results.append(dict(index=index + 1, at=datetime.now(timezone.utc).isoformat(),
                            **request(source_ip, target, timeout)))
        if index + 1 < count:
            time.sleep(interval)
    (path / 'requests.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    expected = evaluate(ACL, vlan, packet(source_ip, target))['action']
    succeeded = sum(x['succeeded'] for x in results)
    row = dict(scenario=scenario, configuration=configuration, trial=trial, start_at=started,
               end_at=datetime.now(timezone.utc).isoformat(), status='measured',
               evidence_level='physical_network', clock_domain='wall_utc', source_device=device,
               source_ip=source_ip, source_vlan=vlan, destination_ip=target, protocol='tcp',
               destination_port=80, expected_action=expected,
               notes='Bound-source HTTP GETs, fresh connection each time; interval is sleep after each response. '
                     'Success means HTTP 2xx. Failed request alone does not establish ACL denial. '
                     'request_duration_ms is application request duration, not ICMP RTT. '
                     'No automatic engine injection or containment timestamp is inferred.',
               evidence=['requests.json', 'active-config.txt'],
               configuration_snapshot='active-config.txt', probe_evidence='requests.json')
    if scenario == 'protected_access':
        row.update(unauthorized_attempted=count, unauthorized_succeeded=succeeded)
    else:
        row.update(legitimate_attempted=count, legitimate_succeeded=succeeded)
    (path / 'observations.json').write_text(json.dumps([row], indent=2), encoding='utf-8')
    return path
