"""Validate raw Linux PCAP and import genuine lab records into Member 4 analysis.

Uses the real capture/controller envelope, not invented per-trial timestamps.
Trial measurement provenance is the individual ping/transfer/probe transcripts.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import statistics
import struct
import sys

from network_data import analyze


def stamp(nanoseconds):
    return datetime.fromtimestamp(nanoseconds / 1e9, timezone.utc).isoformat()


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]


def capture_summary(path):
    first = last = None
    counts = dict(frames=0, ipv4=0, arp=0, tcp=0, udp=0, icmp=0, dhcp=0)
    with path.open('rb') as stream:
        header = stream.read(24)
        if len(header) != 24 or header[:4] not in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'):
            raise ValueError('expected complete little-endian PCAP capture')
        nano = header[:4] == b'\x4d\x3c\xb2\xa1'
        linktype = struct.unpack('<I', header[20:24])[0]
        if linktype != 276:
            raise ValueError('expected tcpdump Linux cooked v2 capture')
        while raw := stream.read(16):
            if len(raw) != 16:
                raise ValueError('truncated packet header')
            seconds, fraction, size, original = struct.unpack('<IIII', raw)
            packet = stream.read(size)
            if len(packet) != size or size < 20:
                raise ValueError('truncated packet data')
            timestamp = seconds * 10**9 + fraction * (1 if nano else 1000)
            first = timestamp if first is None else min(first, timestamp)
            last = timestamp if last is None else max(last, timestamp)
            counts['frames'] += 1
            protocol = struct.unpack('!H', packet[:2])[0]
            offset = 20
            while protocol in (0x8100, 0x88a8) and len(packet) >= offset + 4:
                protocol = struct.unpack('!H', packet[offset+2:offset+4])[0]
                offset += 4
            if protocol == 0x0806:
                counts['arp'] += 1
            elif protocol == 0x0800 and len(packet) >= offset + 20:
                counts['ipv4'] += 1
                transport = packet[offset+9]
                key = {1:'icmp', 6:'tcp', 17:'udp'}.get(transport)
                if key:
                    counts[key] += 1
                ihl = (packet[offset] & 15) * 4
                if transport == 17 and len(packet) >= offset + ihl + 4:
                    ports = struct.unpack('!HH', packet[offset+ihl:offset+ihl+4])
                    if set(ports) == {67,68}:
                        counts['dhcp'] += 1
    if not first or counts['dhcp'] == 0 or counts['tcp'] == 0 or counts['icmp'] == 0:
        raise ValueError('capture lacks actual DHCP/TCP/ICMP traffic')
    return dict(**counts, first_ns=first, last_ns=last, bytes=path.stat().st_size,
                sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                note='Frames on any include multiple observations of a routed packet; not unique packet or loss counts.')


def process(directory):
    directory = Path(directory).resolve()
    if json.loads((directory/'status.json').read_text())['status'] != 'completed':
        raise ValueError('failed or partial run cannot be summarized as successful')
    capture = capture_summary(directory/'pcap/all.pcap')
    rows = json.loads((directory/'results.json').read_text())
    hosts = json.loads((directory/'hosts.json').read_text())
    matrix = json.loads((directory/'access_matrix.json').read_text())
    if not all(r['passed'] for r in matrix):
        raise ValueError('live access matrix failed')
    common_evidence = ['pcap/all.pcap', 'effective.nft', 'access_matrix.json', 'probes.jsonl',
                       'enforcement.jsonl', 'identity.jsonl', 'dhcp.log', 'dhcp-client.log', 'identity_spoof_guard.json']
    common_evidence += [name for name in ('bridge_readbacks.jsonl','address_readbacks.jsonl') if (directory/name).is_file()]
    # Application completion can legitimately occur after the last captured
    # packet. Bound observations by genuine recorded controller/probe timestamps
    # as well as packet times; never pad or synthesize timestamps.
    recorded = [capture['first_ns'], capture['last_ns']]
    for artifact in [directory/'probes.jsonl', directory/'enforcement.jsonl', directory/'detection.jsonl']:
        for record in read_jsonl(artifact):
            recorded += [value for key, value in record.items() if key.endswith('_ns') and type(value) is int]
    envelope_start, envelope_end = min(recorded), max(recorded)
    observations = []
    for row in rows:
        name = f'{row["configuration"]}-{row["trial"]}'
        ping = (directory/name/'ping.txt').read_text()
        samples = [float(n) for n in re.findall(r'time=([0-9.]+) ms', ping)]
        counters = re.search(r'(\d+) packets transmitted, (\d+) packets received', ping)
        transfer = json.loads((directory/name/'transfer.json').read_text())
        evidence = common_evidence + [name+'/ping.txt', name+'/transfer.json', name+'/legitimate.json', name+'/results.json']
        observations.append(dict(scenario='performance', configuration=row['configuration'], trial=row['trial'],
            status='measured', evidence_level='linux_kernel_vlan_network', clock_domain='wall_utc',
            start_at=stamp(envelope_start), end_at=stamp(envelope_end), source_device='PC-RES1',
            source_vlan=30, source_ip=hosts['PC-RES1']['address'], destination_ip='192.168.50.10', protocol='icmp',
            expected_action='permit', evidence=evidence, configuration_snapshot='effective.nft', probe_evidence=name+'/ping.txt',
            notes='Real Linux VLAN lab. Interval is whole-run observed capture/controller envelope; trial samples are archived individually. HTTP application goodput, not physical line rate.',
            probes_sent=int(counters[1]), probes_received=int(counters[2]), rtt_ms=samples,
            transferred_bytes=transfer['bytes_received'], transfer_seconds=transfer['elapsed_seconds'],
            legitimate_attempted=row['legitimate_requests'], legitimate_succeeded=row['legitimate_requests']-row['legitimate_failures'],
            transition_attempted=row['legitimate_requests'], transition_succeeded=row['legitimate_requests']-row['legitimate_failures']))
        if row['configuration'] == 'adaptive':
            transitions = read_jsonl(directory/name/'transitions.jsonl')
            clear = next(t for t in transitions if t['method']=='manual_clear' and t['result'] is True)
            probes = read_jsonl(directory/'probes.jsonl')
            denial = next(p for p in probes if p['source']=='PC-STU2' and p['destination']=='192.168.50.10'
                          and not p['success'] and row['condition_ns'] <= p['started_ns'] < clear['started_ns'])
            restored = next(p for p in probes if p['source']=='PC-STU2' and p['destination']=='192.168.50.10'
                            and p['success'] and p['started_ns'] >= clear['completed_ns'])
            detection = next(d for d in read_jsonl(directory/'detection.jsonl') if d['detected_ns'] >= row['condition_ns'])
            proof = evidence + ['detection.jsonl', name+'/transitions.jsonl']
            observations.append(dict(scenario='violations_recovery', configuration='adaptive', trial=row['trial'],
                status='measured', evidence_level='linux_kernel_vlan_network', clock_domain='wall_utc',
                start_at=stamp(envelope_start), end_at=stamp(envelope_end), source_device='PC-STU2',
                source_vlan=10, source_ip=hosts['PC-STU2']['address'], destination_ip='192.168.50.10', protocol='tcp', destination_port=80,
                expected_action='deny', evidence=proof, configuration_snapshot='effective.nft', probe_evidence='probes.jsonl',
                engine_evidence=name+'/transitions.jsonl', enforcement_evidence='enforcement.jsonl',
                control_evidence=name+'/legitimate.json', denial_evidence='probes.jsonl', restoration_evidence='probes.jsonl',
                condition_at=stamp(row['condition_ns']), detected_at=stamp(detection['detected_ns']),
                effective_denial_at=stamp(denial['completed_ns']), recovery_condition_at=stamp(clear['started_ns']),
                restored_at=stamp(restored['completed_ns']),
                notes='Trigger: prohibited admin HTTP. Additional adaptive isolation checked against research HTTP. Manual admin recovery; not a shortened or completed 30/120-minute auto-hold test. Source lease changes are in identity.jsonl.'))
    path = directory/'observations.json'
    path.write_text(json.dumps(observations, indent=2))
    imported = analyze(path, directory/'analysis')
    summary = dict(capture=capture, live_access_checks=len(matrix), live_access_passed=sum(r['passed'] for r in matrix),
                   imported_observations=len(observations), analysis_directory=str(imported), modes={},
                   analyzer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   capture_log=(directory/'capture.log').read_text())
    for mode in ('static', 'adaptive'):
        values = [r for r in rows if r['configuration']==mode]
        summary['modes'][mode] = {key:statistics.mean(r[key] for r in values) for key in
            ('latency_ms','packet_loss_pct','throughput_mbps','disruption_pct')}
    (directory/'verified_summary.json').write_text(json.dumps(summary, indent=2))
    return summary


if __name__ == '__main__':
    print(json.dumps(process(sys.argv[1]), indent=2))
