"""Real isolated Linux VLAN bridge, DHCP, nftables, captures and policy engine.

Run through lab_bootstrap.sh, never directly on a host network. Uses Member 1
addressing, compiled Member 2 ACLs and the actual Member 3 controller/thresholds.
Linux bridge backend replaces only the Cisco SSH transport, not policy logic.
"""
import argparse
from datetime import datetime, timezone
import http.server
import http.client
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import secrets
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time
import uuid

from application_services import resolver_for, serve as serve_applications
from policy import reconcile, nft_rules
from runtime import DEVICES, EndpointRegistry, IntegratedPolicyEngine, IntegratedListener

HERE = Path(__file__).resolve().parent


def command(*args, check=True, data=None, timeout=20):
    result = subprocess.run(list(map(str, args)), input=data, capture_output=True,
                            text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f'{args}: {result.stderr or result.stdout}')
    return result


def ns(name, *args, **kwargs):
    return command('ip', 'netns', 'exec', name, *args, **kwargs)


def dump(path, value):
    Path(path).write_text(json.dumps(value, indent=2), encoding='utf-8')


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        payload = b'x' * 1048576 if self.path == '/bulk' else b'CNPRO live service\n' * 64
        self.send_response(200)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b'CNPRO TCP reachability service\r\n')


def serve():
    serve_applications(sys.argv[2], sys.argv[3], Handler)


def probe(destination, port, http=False, source=None):
    started = time.time_ns()
    success, error = False, None
    try:
        with socket.create_connection((destination, int(port)), timeout=0.22,
                                      source_address=(source, 0) if source else None) as sock:
            if http:
                sock.sendall(b'GET / HTTP/1.0\r\nHost: cnpro\r\n\r\n')
                success = sock.recv(4096).startswith(b'HTTP/1.0 200')
            else:
                success = True
    except OSError as exc:
        error = str(exc)
    return dict(started_ns=started, completed_ns=time.time_ns(), success=success, error=error)


def dns_probe(destination):
    query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01'
    if destination == '192.168.50.13':
        query = query[:12] + b'\x0dsrv-remediate\x00\x00\x01\x00\x01'
    started = time.time_ns()
    success = False
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(.22)
        sock.sendto(query, (destination, 53))
        try:
            response, _ = sock.recvfrom(1024)
            success = response[:2] == query[:2] and len(response) > len(query)
        except TimeoutError:
            pass
    return dict(started_ns=started, completed_ns=time.time_ns(), success=success)


def bulk(destination):
    started = time.perf_counter_ns()
    client = http.client.HTTPConnection(destination, 80, timeout=5)
    try:
        client.request('GET', '/bulk')
        response = client.getresponse()
        data = response.read()
        duration = (time.perf_counter_ns() - started) / 1e9
        return dict(bytes_received=len(data), elapsed_seconds=duration,
                    throughput_mbps=len(data) * 8 / duration / 1e6,
                    http_status=response.status, metric='application_HTTP_goodput')
    finally:
        client.close()


class Lab:
    def __init__(self, output):
        self.output = Path(output)
        self.processes = []
        self.hosts = {}
        self.registry = EndpointRegistry()
        self.active = False
        self.detector = None
        self.app_dir = self.output/'private-services'
        self.detected = []
        self.nft_lock = threading.RLock()
        self.acl = HERE / 'effective/CORE-SW_security_acls.cfg'

    def spawn(self, name, args, filename):
        stream = (self.output / filename).open('a')
        args = ['ip', 'netns', 'exec', name, *args] if name else args
        process = subprocess.Popen(args, stdout=stream, stderr=subprocess.STDOUT)
        stream.close()
        self.processes.append(process)
        return process

    def setup(self):
        # Explicitly require the launcher-created network namespace.
        if os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'):
            raise RuntimeError('Refusing to change host networking; use isolated launcher')
        (self.output / 'pcap').mkdir(exist_ok=True)
        dump(self.output / 'environment.json', dict(kernel=command('uname', '-a').stdout.strip(),
            packages=command('apk', 'info', '-v').stdout.splitlines(),
            sources=json.loads((HERE/'sources.json').read_text()),
            implementation_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in HERE.glob('*.py')},
            network_namespace=os.readlink('/proc/self/ns/net'),
            host_network_namespace=os.readlink('/proc/1/ns/net')))
        dump(self.output / 'policy_decisions.json', reconcile(self.acl))
        command('ip', 'link', 'set', 'lo', 'up')
        command('ip', 'link', 'add', 'br0', 'type', 'bridge', 'vlan_filtering', '1', 'vlan_default_pvid', '0')
        command('ip', 'link', 'set', 'br0', 'address', '02:ca:00:ff:ff:01')
        command('ip', 'link', 'set', 'br0', 'up')
        for vlan in (10, 20, 30, 40, 50, 60, 70, 99):
            command('bridge', 'vlan', 'add', 'dev', 'br0', 'vid', vlan, 'self')
            command('ip', 'link', 'add', 'link', 'br0', 'name', f'v{vlan}', 'type', 'vlan', 'id', vlan)
            gateway = f'192.168.{vlan}.1/24' if vlan != 99 else '203.0.113.1/30'
            command('ip', 'addr', 'add', gateway, 'dev', f'v{vlan}')
            command('ip', 'link', 'set', f'v{vlan}', 'up')
        Path('/proc/sys/net/ipv4/ip_forward').write_text('1')
        names = [(name, info['home_vlan'], None) for name, info in DEVICES.items()]
        names += [('POLICY-HOST', 40, '192.168.40.50'), ('SRV-RESEARCH', 50, '192.168.50.10'),
                  ('SRV-DB', 50, '192.168.50.11'), ('SRV-ADMIN', 50, '192.168.50.12'),
                  ('SRV-REMEDIATE', 50, '192.168.50.13'), ('INTERNET-SRV', 99, '203.0.113.2')]
        for index, (name, vlan, address) in enumerate(names):
            namespace, link = f'm4n{index}', f'p{index}'
            mac = f'02:ca:00:00:00:{index + 1:02x}'
            command('ip', 'netns', 'add', namespace)
            command('ip', 'link', 'add', link, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', namespace)
            command('ip', 'link', 'set', link, 'master', 'br0')
            command('ip', 'link', 'set', link, 'up')
            command('bridge', 'vlan', 'add', 'dev', link, 'vid', vlan, 'pvid', 'untagged')
            ns(namespace, 'ip', 'link', 'set', 'lo', 'up')
            ns(namespace, 'ip', 'link', 'set', 'eth0', 'address', mac)
            ns(namespace, 'ip', 'link', 'set', 'eth0', 'up')
            if address:
                ns(namespace, 'ip', 'addr', 'add', f'{address}/' + ('30' if vlan == 99 else '24'), 'dev', 'eth0')
                ns(namespace, 'ip', 'route', 'add', 'default', 'via', '203.0.113.1' if vlan == 99 else f'192.168.{vlan}.1')
            resolver = Path('/etc/netns')/namespace/'resolv.conf'
            resolver.parent.mkdir(parents=True, exist_ok=True)
            resolver.write_text('nameserver '+resolver_for(vlan)+'\noptions timeout:1 attempts:1\n')
            self.hosts[name] = dict(resolver=str(resolver), namespace=namespace, link=link, mac=mac, vlan=vlan, address=address)
        args = ['dnsmasq', '--keep-in-foreground', '--port=0', '--bind-interfaces', '--user=root', '--dhcp-broadcast',
                '--dhcp-authoritative', '--log-dhcp', '--log-facility=-', '--dhcp-leasefile=' + str(self.output / 'dhcp.leases')]
        for vlan in (10, 20, 30, 40, 60, 70):
            args += [f'--interface=v{vlan}', f'--dhcp-range=set:v{vlan},192.168.{vlan}.100,192.168.{vlan}.254,255.255.255.0,1h',
                     f'--dhcp-option=tag:v{vlan},3,192.168.{vlan}.1',
                     f'--dhcp-option=tag:v{vlan},6,{resolver_for(vlan)}']
        self.spawn(None, args, 'dhcp.log')
        time.sleep(0.3)
        for name in DEVICES:
            self.renew(name)
        self.refresh_registry()
        self.app_dir.mkdir(mode=0o700)
        credentials = dict(username='cnpro-lab', password=secrets.token_urlsafe(24))
        dump(self.app_dir/'ftp-credentials.json', credentials)
        (self.app_dir/'ftp-credentials.json').chmod(0o600)
        (self.app_dir/'ftp-root').mkdir()
        (self.app_dir/'ftp-root/sample.txt').write_text('CNPRO authenticated FTP sample\n')
        command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
                '-keyout', self.app_dir/'private-key.pem', '-out', self.app_dir/'certificate.pem',
                '-subj', '/CN=cnpro-local-lab', '-addext',
                'subjectAltName=DNS:srv-research,DNS:srv-admin,DNS:www.example.com,IP:192.168.50.10,IP:192.168.50.12,IP:203.0.113.2')
        (self.app_dir/'private-key.pem').chmod(0o600)
        records = {'srv-research':'192.168.50.10', 'srv-db':'192.168.50.11',
                   'srv-admin':'192.168.50.12', 'srv-remediate':'192.168.50.13', 'www.example.com':'203.0.113.2'}
        for name in ('SRV-REMEDIATE', 'INTERNET-SRV'):
            selected = records if name == 'INTERNET-SRV' else {'srv-remediate':'192.168.50.13'}
            args = ['dnsmasq', '--keep-in-foreground', '--no-resolv', '--no-hosts', '--bind-interfaces',
                    '--user=root', '--log-facility=-', '--local=/#/', '--interface=eth0', '--conf-file=/dev/null']
            args += ['--host-record='+host+','+ip for host, ip in selected.items()]
            self.spawn(self.hosts[name]['namespace'], args, name+'-dns.log')
        for name in ('SRV-RESEARCH', 'SRV-DB', 'SRV-ADMIN', 'SRV-REMEDIATE', 'INTERNET-SRV'):
            self.spawn(self.hosts[name]['namespace'], [sys.executable, '-B', str(Path(__file__).resolve()),
                'serve', name, str(self.app_dir)], name + '.log')
        # SMTP banner remains transport-only instrumentation for admin all-port checks.
        self.spawn(self.hosts['INTERNET-SRV']['namespace'], [sys.executable, '-B',
            str(Path(__file__).resolve()), 'smtp-probe'], 'smtp-probe.log')
        self.spawn(None, [sys.executable, '-B', str(Path(__file__).resolve()), 'management'], 'management.log')
        self.apply_policy()
        # iperf uses TCP 5201; source Member 2 research HTTP rule is the measured
        # data path instead: iperf binds TCP/80 during a separate benchmark.
        for name in ('SRV-RESEARCH', 'SRV-DB', 'SRV-ADMIN', 'SRV-REMEDIATE', 'INTERNET-SRV'):
            deadline = time.monotonic() + 10
            while True:
                ready = ns(self.hosts[name]['namespace'], sys.executable, '-c',
                    'import socket; socket.create_connection(("127.0.0.1",80),timeout=.2).close()', check=False)
                if ready.returncode == 0:
                    break
                if time.monotonic() > deadline:
                    raise RuntimeError('service did not become ready: ' + name)
                time.sleep(0.1)
        dump(self.output / 'hosts.json', self.hosts)
        dump(self.output / 'bridge.json', json.loads(command('bridge', '-j', 'vlan', 'show').stdout))

    def renew(self, name):
        host = self.hosts[name]
        result = ns(host['namespace'], 'env', 'CNPRO_RESOLV_CONF='+host['resolver'], 'udhcpc', '-i', 'eth0', '-q', '-n', '-t', '3', '-T', '1',
                    '-s', str(HERE / 'lab_dhcp.sh'), timeout=12)
        with (self.output / 'dhcp-client.log').open('a') as stream:
            stream.write(name + '\n' + result.stdout + result.stderr)
        addresses = json.loads(ns(host['namespace'], 'ip', '-j', '-4', 'addr', 'show', 'eth0').stdout)[0]['addr_info']
        host['address'] = next(a['local'] for a in addresses if a['family'] == 'inet')
        with (self.output/'address_readbacks.jsonl').open('a') as stream:
            stream.write(json.dumps(dict(at_ns=time.time_ns(), device=name, namespace=host['namespace'], addr_info=addresses, resolver=Path(host['resolver']).read_text()))+'\n')

    def refresh_registry(self):
        lease_lines = (self.output / 'dhcp.leases').read_text().splitlines()
        leases = {(r[1], r[2]): int(r[0]) for line in lease_lines if len(r := line.split()) >= 3}
        rows = []
        for name, info in DEVICES.items():
            host = self.hosts[name]
            expiry = leases.get((host['mac'], host['address']), 0)
            rows.append(dict(device=name, mac=host['mac'], ip=host['address'], vlan=host['vlan'],
                             switch_ip=info['switch_ip'], port=info['port'], expires_at=expiry))
        self.registry.replace(rows)
        with (self.output / 'identity.jsonl').open('a') as stream:
            stream.write(json.dumps(dict(at_ns=time.time_ns(), bindings=rows)) + '\n')

    def apply_policy(self):
        with self.nft_lock:
            addresses = [h['address'] for name, h in self.hosts.items() if name in DEVICES]
            rules = nft_rules(self.acl, addresses)
            # Bind source MAC/IP to the real ingress port before routing. DHCP
            # discovery is the only permitted unconfigured source address.
            rules += 'table netdev cnpro_bindings {\n'
            for index, host in enumerate(self.hosts.values()):
                rules += f' chain port{index} {{ type filter hook ingress device "{host["link"]}" priority -500; policy accept;\n'
                rules += f' ether saddr != {host["mac"]} counter drop\n'
                rules += f' ether type ip ip saddr != {host["address"]} ip saddr != 0.0.0.0 counter drop\n'
                rules += ' }\n'
            rules += '}\n'
            for family, table in [('inet', 'cnpro'), ('ip', 'cnpro_nat'), ('netdev', 'cnpro_bindings')]:
                if command('nft', 'list', 'table', family, table, check=False).returncode == 0:
                    rules = f'delete table {family} {table}\n' + rules
            command('nft', '-f', '-', data=rules)
            (self.output / 'effective.nft').write_text(rules)
            snapshots = self.output/'configurations'
            snapshots.mkdir(exist_ok=True)
            generation = str(time.time_ns())
            (snapshots/(generation+'.nft')).write_text(rules)
            (snapshots/(generation+'.json')).write_text(command('nft', '-j', 'list', 'ruleset').stdout)

    def target(self, switch_ip, port):
        normalize = lambda p: re.sub(r'^fa(?:stethernet)?', 'fa', p, flags=re.I).lower()
        return next(n for n, d in DEVICES.items() if d['switch_ip'] == switch_ip and normalize(d['port']) == normalize(port))

    def push_vlan(self, switch_ip, port, vlan):
        name = self.target(switch_ip, port)
        host = self.hosts[name]
        before = self.verify_vlan(switch_ip, port)
        try:
            command('bridge', 'vlan', 'del', 'dev', host['link'], 'vid', before)
            command('bridge', 'vlan', 'add', 'dev', host['link'], 'vid', vlan, 'pvid', 'untagged')
            host['vlan'] = vlan
            self.renew(name)
            self.refresh_registry()
            self.apply_policy()
            return True
        finally:
            with (self.output / 'enforcement.jsonl').open('a') as stream:
                stream.write(json.dumps(dict(at_ns=time.time_ns(), device=name, old_vlan=before,
                    requested_vlan=vlan, observed_vlan=self.verify_vlan(switch_ip, port), address=host['address'])) + '\n')

    def verify_vlan(self, switch_ip, port):
        host = self.hosts[self.target(switch_ip, port)]
        rows = json.loads(command('bridge', '-j', 'vlan', 'show', 'dev', host['link']).stdout)
        with (self.output/'bridge_readbacks.jsonl').open('a') as stream:
            stream.write(json.dumps(dict(at_ns=time.time_ns(), switch_ip=switch_ip, port=port, linux_port=host['link'], rows=rows))+'\n')
        vlans = [v['vlan'] for row in rows for v in row.get('vlans', []) if 'PVID' in v.get('flags', [])]
        return vlans[0] if len(vlans) == 1 else None

    def request(self, name, destination, port=80, http=True):
        result = ns(self.hosts[name]['namespace'], sys.executable, '-B', str(Path(__file__).resolve()),
                    'probe', destination, str(port), 'http' if http else 'tcp')
        row = json.loads(result.stdout)
        row.update(source=name, source_ip=self.hosts[name]['address'], destination=destination, port=port)
        with (self.output / 'probes.jsonl').open('a') as stream:
            stream.write(json.dumps(row) + '\n')
        return row

    def verify_endpoint(self, switch_ip, port, vlan):
        name = self.target(switch_ip, port)
        host = self.hosts[name]
        addresses = json.loads(ns(host['namespace'], 'ip', '-j', '-4', 'addr', 'show', 'eth0').stdout)[0]['addr_info']
        if not any(a.get('local') == host['address'] and a['local'].startswith(f'192.168.{vlan}.') for a in addresses):
            return False
        if self.registry.resolve(host['address']) != name:
            return False
        gateway = ns(host['namespace'], 'ping', '-c', '1', '-W', '1', f'192.168.{vlan}.1', check=False).returncode == 0
        destination = '192.168.50.13' if vlan == 60 else '192.168.50.10'
        return gateway and self.request(name, destination)['success'] == (vlan != 70)

    def counters(self):
        with self.nft_lock:
            values = json.loads(command('nft', '-j', 'list', 'chain', 'inet', 'cnpro', 'denied').stdout)
            out = {}
            for entry in values['nftables']:
                rule = entry.get('rule', {})
                if not rule.get('comment', '').startswith('endpoint:'):
                    continue
                match = next(e['match'] for e in rule['expr'] if 'match' in e)
                counter = next(e['counter'] for e in rule['expr'] if 'counter' in e)
                out[match['right']] = counter['packets']
            return out

    def detect_loop(self):
        previous = self.counters()
        next_recovery = time.monotonic() + 30
        while self.active:
            time.sleep(0.05)
            try:
                current = self.counters()
                for address, count in current.items():
                    delta = count - previous.get(address, 0)
                    device = self.registry.resolve(address)
                    if delta > 0 and device:
                        event = dict(detected_ns=time.time_ns(), source_ip=address, device=device,
                                     observed_drop_packets=delta, source='kernel_nftables_deny_counter')
                        self.detected.append(event)
                        with (self.output / 'detection.jsonl').open('a') as stream:
                            stream.write(json.dumps(event) + '\n')
                        # Trusted per-endpoint kernel deny counts, not fabricated
                        # syslog or manual injection. TH-05 consumes actual drops.
                        for _ in range(min(delta, 2)):
                            self.engine.handle_event(device, 'cross_vlan_attempt')
                previous = current
                if time.monotonic() >= next_recovery:
                    self.engine.run_recovery_sweep()
                    next_recovery = time.monotonic() + 30
            except Exception as exc:
                with (self.output / 'detector-errors.log').open('a') as stream:
                    stream.write(repr(exc) + '\n')
                self.active = False

    def start_detection(self, folder):
        self.engine = IntegratedPolicyEngine(state_db_path=str(folder / 'state.json'), events_db_path=str(folder / 'events.json'),
                                             ssh_enforcer=self, evidence=folder / 'transitions.jsonl')
        self.detected = []
        self.active = True
        self.detector = threading.Thread(target=self.detect_loop)
        self.detector.start()

    def stop_detection(self):
        self.active = False
        if self.detector:
            self.detector.join(timeout=20)
            if self.detector.is_alive():
                raise RuntimeError('detector did not stop')

    def matrix(self):
        rows = []
        def dns(name, vlan, destination, expected):
            result = json.loads(ns(self.hosts[name]['namespace'], sys.executable, '-B', str(Path(__file__).resolve()),
                                    'dns', destination).stdout)
            rows.append(dict(source=name, vlan=vlan, destination=destination, port=53, protocol='udp',
                             expected_permit=expected, observed_permit=result['success'], passed=result['success'] == expected))
        def ping(name, vlan, destination, expected):
            result = ns(self.hosts[name]['namespace'], 'ping', '-c', '1', '-W', '1', destination, check=False)
            with (self.output / 'matrix-ping.txt').open('a') as stream:
                stream.write(name + ' -> ' + destination + '\n' + result.stdout + result.stderr)
            rows.append(dict(source=name, vlan=vlan, destination=destination, protocol='icmp',
                             expected_permit=expected, observed_permit=result.returncode == 0, passed=(result.returncode == 0) == expected))
        for name, role in [('PC-STU1', 10), ('PC-FAC1', 20), ('PC-RES1', 30), ('PC-ADM1', 40)]:
            dns(name, role, '203.0.113.2', True)
            dns(name, role, '192.168.50.13', True)
            ping(name, role, f'192.168.{role}.1', True)
            ping(name, role, self.hosts['PC-ADM2']['address'], role == 40)
            for destination, ports in [('192.168.50.10', (80, 443)), ('192.168.50.11', (21,)),
                                       ('192.168.50.12', (80, 443)), ('192.168.50.13', (80,)),
                                       ('203.0.113.2', (80, 443, 25))]:
                for port in ports:
                    expected = (role == 40 or destination == '203.0.113.2' and port in (80, 443)
                        or destination == '192.168.50.13' and port == 80
                        or destination == '192.168.50.10' and (role in (20, 30) or port == 80)
                        or destination == '192.168.50.11' and role == 30)
                    probe = self.request(name, destination, port, http=False)
                    rows.append(dict(source=name, vlan=role, destination=destination, port=port,
                                     expected_permit=expected, observed_permit=probe['success'], passed=probe['success'] == expected))
        # Containment permissions and identity continuity are tested on real ports
        # after DHCP renewal. Known healthy server services avoid false deny passes.
        for vlan in (60, 70):
            assert self.push_vlan(DEVICES['PC-STU2']['switch_ip'], DEVICES['PC-STU2']['port'], vlan)
            for destination in ('192.168.50.10', '192.168.50.11', '192.168.50.12', '192.168.50.13', '203.0.113.2'):
                result = self.request('PC-STU2', destination)
                expected = vlan == 60 and destination == '192.168.50.13'
                rows.append(dict(source='PC-STU2', vlan=vlan, destination=destination, port=80,
                                 expected_permit=expected, observed_permit=result['success'], passed=result['success'] == expected))
            assert self.verify_endpoint(DEVICES['PC-STU2']['switch_ip'], DEVICES['PC-STU2']['port'], vlan)
            dns('PC-STU2', vlan, '192.168.50.13', vlan == 60)
            dns('PC-STU2', vlan, '203.0.113.2', False)
            ping('PC-STU2', vlan, f'192.168.{vlan}.1', True)
            ping('PC-STU2', vlan, '192.168.50.13', False)
        assert self.push_vlan(DEVICES['PC-STU2']['switch_ip'], DEVICES['PC-STU2']['port'], 10)
        for name, expected in [('POLICY-HOST', True), ('PC-ADM1', False), ('PC-STU1', False)]:
            result = self.request(name, '192.168.40.1', 22, http=False)
            rows.append(dict(source=name, destination='192.168.40.1', port=22, protocol='tcp',
                             expected_permit=expected, observed_permit=result['success'], passed=result['success'] == expected))
        # Real source-address spoofing attempt on a healthy permitted HTTP path.
        host = self.hosts['PC-STU1']
        other = self.hosts['PC-STU2']['address']
        ns(host['namespace'], 'ip', 'addr', 'add', other + '/32', 'dev', 'eth0')
        try:
            spoof = json.loads(ns(host['namespace'], sys.executable, '-B', str(Path(__file__).resolve()),
                                  'spoof', other, '192.168.50.10').stdout)
        finally:
            ns(host['namespace'], 'ip', 'addr', 'del', other + '/32', 'dev', 'eth0')
        healthy = self.request('PC-STU1', '192.168.50.10')
        assert not spoof['success'] and healthy['success'], 'port source binding was not enforced'
        assert self.registry.resolve(other) == 'PC-STU2' and self.registry.resolve(host['address']) == 'PC-STU1'
        dump(self.output / 'identity_spoof_guard.json', dict(spoof=spoof, healthy=healthy,
             rightful_device=self.registry.resolve(other), source_guard=json.loads(command('nft', '-j', 'list', 'table', 'netdev', 'cnpro_bindings').stdout)))
        self.spawn(self.hosts['PC-ADM1']['namespace'], [sys.executable, '-B', str(Path(__file__).resolve()), 'client-http'], 'client-http.log')
        deadline = time.monotonic() + 10
        while not self.request('POLICY-HOST', self.hosts['PC-ADM1']['address'])['success']:
            if time.monotonic() > deadline:
                raise RuntimeError('client listener health control failed')
        result = self.request('SRV-RESEARCH', self.hosts['PC-ADM1']['address'])
        rows.append(dict(source='SRV-RESEARCH', destination=self.hosts['PC-ADM1']['address'], port=80,
                         expected_permit=False, observed_permit=result['success'], passed=not result['success']))
        dump(self.output / 'access_matrix.json', rows)
        if not all(row['passed'] for row in rows):
            raise RuntimeError('live access matrix mismatch; see access_matrix.json')
        return rows

    def close(self):
        self.stop_detection()
        for process in reversed(self.processes):
            process.terminate()
        for process in reversed(self.processes):
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
        for host in self.hosts.values():
            command('ip', 'netns', 'del', host['namespace'], check=False)


def run():
    output = HERE / 'results' / ('live-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:6])
    output.mkdir()
    lab = Lab(output)
    print(output, flush=True)
    try:
        (output / 'pcap').mkdir()
        capture_path = Path('/tmp') / (output.name+'.pcap')
        lab.spawn(None, ['tcpdump', '-U', '-B', '16384', '-n', '-i', 'any', '-w', str(capture_path), 'ip or arp'], 'capture.log')
        lab.setup()
        time.sleep(0.25)
        lab.matrix()
        from live_regressions import verify
        verify(lab)
        rows = []
        for trial in range(1, 4):
            for mode in ('static', 'adaptive'):
                folder = output / f'{mode}-{trial}'
                folder.mkdir()
                ns_stu = lab.hosts['PC-STU2']['namespace']
                if lab.hosts['PC-STU2']['vlan'] != 10:
                    assert lab.push_vlan(DEVICES['PC-STU2']['switch_ip'], DEVICES['PC-STU2']['port'], 10)
                lab.apply_policy()
                if mode == 'adaptive':
                    lab.start_detection(folder)
                # Pair identical permitted 1 MiB HTTP transfers; no unsupported
                # iperf service is added to the security policy for benchmarking.
                ping = ns(lab.hosts['PC-RES1']['namespace'], 'ping', '-c', '20', '-i', '0.02', '-W', '1', '192.168.50.10', check=False)
                (folder / 'ping.txt').write_text(ping.stdout + ping.stderr)
                transfer = json.loads(ns(lab.hosts['PC-RES1']['namespace'], sys.executable, '-B',
                    str(Path(__file__).resolve()), 'bulk', '192.168.50.10').stdout)
                assert transfer['bytes_received'] == 1048576 and transfer['http_status'] == 200
                dump(folder / 'transfer.json', transfer)
                loss = re.search(r'(\d+)% packet loss', ping.stdout)
                rtt = re.search(r'= ([0-9.]+)/([0-9.]+)/([0-9.]+)', ping.stdout)
                legitimate = []
                stop = threading.Event()
                def legitimate_loop():
                    while not stop.is_set():
                        legitimate.append(lab.request('PC-RES1', '192.168.50.10'))
                        stop.wait(0.05)
                worker = threading.Thread(target=legitimate_loop)
                worker.start()
                trial_started = time.monotonic()
                condition = time.time_ns()
                for _ in range(3):
                    lab.request('PC-STU2', '192.168.50.12')
                    time.sleep(0.1)
                isolated = lab.request('PC-STU2', '192.168.50.10')
                if mode == 'adaptive':
                    deadline = time.monotonic() + 8
                    while lab.hosts['PC-STU2']['vlan'] == 10 and time.monotonic() < deadline:
                        time.sleep(0.1)
                    lab.stop_detection()
                    isolated = lab.request('PC-STU2', '192.168.50.10')
                    assert lab.hosts['PC-STU2']['vlan'] in (60, 70), 'automatic containment not applied'
                    assert not isolated['success'], 'research service was not isolated'
                    old_address = lab.hosts['PC-STU2']['address']
                    recovery_condition = time.time_ns()
                    assert lab.engine.manual_clear('PC-STU2'), 'verified recovery failed'
                    restored = lab.request('PC-STU2', '192.168.50.10')
                    assert restored['success'], 'normal permitted connectivity not restored'
                    assert lab.registry.resolve(old_address) is None
                    assert lab.registry.resolve(lab.hosts['PC-STU2']['address']) == 'PC-STU2'
                else:
                    assert isolated['success'], 'static permitted control unexpectedly denied'
                    recovery_condition = restored = None
                remaining = 12 - (time.monotonic() - trial_started)
                if remaining > 0:
                    stop.wait(remaining)
                stop.set()
                worker.join(timeout=5)
                dump(folder / 'legitimate.json', legitimate)
                dump(folder / 'bridge.json', json.loads(command('bridge', '-j', 'vlan', 'show').stdout))
                row = dict(configuration=mode, trial=trial, evidence_level='linux_kernel_vlan_network',
                    latency_ms=float(rtt[2]) if rtt else None, packet_loss_pct=float(loss[1]) if loss else None,
                    throughput_mbps=transfer['throughput_mbps'], condition_ns=condition,
                    detection_ms=(lab.detected[0]['detected_ns'] - condition) / 1e6 if mode == 'adaptive' and lab.detected else None,
                    isolation_ms=(isolated['completed_ns'] - condition) / 1e6 if mode == 'adaptive' else None,
                    recovery_ms=(restored['completed_ns'] - recovery_condition) / 1e6 if restored else None,
                    recovery_kind='manual_admin_verified' if restored else None,
                    observation_seconds=time.monotonic() - trial_started,
                    legitimate_requests=len(legitimate), legitimate_failures=sum(not r['success'] for r in legitimate),
                    disruption_pct=100 * sum(not r['success'] for r in legitimate) / len(legitimate) if legitimate else None)
                rows.append(row)
                dump(folder / 'results.json', row)
        dump(output / 'results.json', rows)
        dump(output / 'status.json', dict(status='completed', caveats=['Linux VLAN lab, not Cisco hardware validation',
            'Detection measured from controlled request start to kernel counter observation; polling interval 50 ms',
            'Isolation measured to first completed confirming service denial, includes probe timeout',
            'Recovery is real admin clear, not the 30/120 minute automatic hold experiment',
            'TLS uses a generated local certificate; FTP uses ephemeral local credentials and passive data port 20']))
    except Exception as exc:
        dump(output / 'status.json', dict(status='failed', error=repr(exc)))
        raise
    finally:
        lab.close()
        if capture_path.is_file():
            shutil.copyfile(capture_path, output/'pcap/all.pcap')
    from analyze_lab import process
    process(output)
    print(output, flush=True)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'serve':
        serve()
    elif len(sys.argv) > 1 and sys.argv[1] == 'smtp-probe':
        socketserver.ThreadingTCPServer.allow_reuse_address = True
        socketserver.ThreadingTCPServer(('0.0.0.0', 25), TCPHandler).serve_forever()
    elif len(sys.argv) > 1 and sys.argv[1] == 'management':
        socketserver.ThreadingTCPServer.allow_reuse_address = True
        socketserver.ThreadingTCPServer(('0.0.0.0', 22), TCPHandler).serve_forever()
    elif len(sys.argv) > 1 and sys.argv[1] == 'client-http':
        http.server.ThreadingHTTPServer(('0.0.0.0', 80), Handler).serve_forever()
    elif len(sys.argv) > 1 and sys.argv[1] == 'probe':
        print(json.dumps(probe(sys.argv[2], sys.argv[3], sys.argv[4] == 'http')))
    elif len(sys.argv) > 1 and sys.argv[1] == 'bulk':
        print(json.dumps(bulk(sys.argv[2])))
    elif len(sys.argv) > 1 and sys.argv[1] == 'dns':
        print(json.dumps(dns_probe(sys.argv[2])))
    elif len(sys.argv) > 1 and sys.argv[1] == 'spoof':
        print(json.dumps(probe(sys.argv[3], 80, True, sys.argv[2])))
    else:
        run()
