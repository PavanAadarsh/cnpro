"""Strict network-observation adapter around Member 4's unchanged analyzer."""
from datetime import datetime
import importlib.util
import ipaddress
import json
import math
from pathlib import Path
import engine_adapter
from policy_engine.state_manager import DEVICES

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('original_member4_evaluate', HERE.parent / 'monitoring/evaluate.py')
legacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(legacy)


def validate(source):
    source = Path(source).resolve()
    rows = json.loads(source.read_text(encoding='utf-8-sig'))
    if not isinstance(rows, list) or not rows:
        raise ValueError('supply a nonempty array of actual network observations')
    def finite(value):
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError('nonfinite JSON number')
        if isinstance(value, list):
            for item in value: finite(item)
        if isinstance(value, dict):
            for item in value.values(): finite(item)
    finite(rows)
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('each row must be an object')
        if row.get('evidence_level') not in ('physical_network', 'packet_tracer_simulation', 'linux_kernel_vlan_network'):
            raise ValueError('engine replay/configuration audit cannot be imported as network measurements')
        if row.get('status') not in ('measured', 'failed'):
            raise ValueError('readiness records are not network observations')
        for key in ('scenario', 'notes', 'source_device', 'configuration'):
            if not isinstance(row.get(key), str) or not row[key].strip():
                raise ValueError(f'{key} must be a nonempty string')
        if row['configuration'] not in ('architecture_baseline', 'static', 'adaptive'):
            raise ValueError('invalid configuration')
        if type(row.get('trial')) is not int or row['trial'] < 1:
            raise ValueError('trial must be a positive integer')
        if row.get('clock_domain') not in ('wall_utc', 'packet_tracer_simulation'):
            raise ValueError('declare the common clock domain')
        if row['evidence_level'] == 'packet_tracer_simulation' and row['clock_domain'] != 'packet_tracer_simulation':
            raise ValueError('simulation evidence requires a simulation clock domain')
        if row['evidence_level'] in ('physical_network', 'linux_kernel_vlan_network') and row['clock_domain'] != 'wall_utc':
            raise ValueError('physical evidence requires a wall-clock domain')
        start, end = legacy.stamp(row['start_at']), legacy.stamp(row['end_at'])
        if end < start:
            raise ValueError('negative trial duration')
        for key in ('condition_at', 'detected_at', 'effective_denial_at', 'recovery_condition_at', 'restored_at'):
            if row.get(key) is not None:
                point = legacy.stamp(row[key])
                if not start <= point <= end:
                    raise ValueError(f'{key} falls outside the trial')
        for a, b in [('condition_at', 'detected_at'), ('detected_at', 'effective_denial_at'),
                     ('recovery_condition_at', 'restored_at')]:
            if row.get(b) is not None and row.get(a) is None:
                raise ValueError(f'{b} requires {a}')
        if row.get('recovery_condition_at') and row.get('effective_denial_at'):
            if legacy.stamp(row['recovery_condition_at']) < legacy.stamp(row['effective_denial_at']):
                raise ValueError('recovery precedes effective restriction')
        vlan = row.get('source_vlan')
        if type(vlan) is not int or vlan not in (10, 20, 30, 40, 60, 70):
            raise ValueError('unknown source VLAN')
        device = DEVICES.get(row['source_device'])
        if device is None or vlan not in (device['home_vlan'], 60, 70):
            raise ValueError('unknown device or inconsistent home VLAN')
        if ipaddress.ip_address(row['source_ip']) not in ipaddress.ip_network(f'192.168.{vlan}.0/24'):
            raise ValueError('source IP does not match recorded VLAN')
        if row.get('destination_ip') not in ('192.168.50.10', '192.168.50.11', '192.168.50.12',
                                            '192.168.50.13', '203.0.113.2', f'192.168.{vlan}.1'):
            raise ValueError('destination is outside the evaluation target list')
        protocol = row.get('protocol')
        if protocol not in ('tcp', 'udp', 'icmp'):
            raise ValueError('unknown protocol')
        if protocol in ('tcp', 'udp') and (type(row.get('destination_port')) is not int or not 1 <= row['destination_port'] <= 65535):
            raise ValueError('destination service port required')
        if row.get('expected_action') not in ('permit', 'deny'):
            raise ValueError('record the expected ACL outcome')
        evidence = row.get('evidence')
        if not isinstance(evidence, list) or not evidence or any(not isinstance(x, str) for x in evidence):
            raise ValueError('evidence must be a list of file paths')
        references = ['configuration_snapshot', 'probe_evidence']
        if row.get('detected_at'):
            references.append('engine_evidence')
        if row.get('effective_denial_at'):
            references += ['enforcement_evidence', 'control_evidence', 'denial_evidence']
        if row.get('restored_at'):
            references += ['enforcement_evidence', 'restoration_evidence']
        for key in references:
            if row.get(key) not in evidence:
                raise ValueError(f'{key} must name an archived evidence file')
        for name in evidence:
            path = (source.parent / name).resolve()
            if not path.is_relative_to(source.parent) or not path.is_file():
                raise ValueError(f'missing or out-of-folder evidence: {name}')
        if row.get('rtt_ms') is None:
            if 'rtt_ms' in row:
                raise ValueError('omit unavailable rtt_ms or use []')
        metrics = legacy.calculate(row)
        if row['status'] == 'measured' and not any(value is not None for value in metrics.values()):
            raise ValueError('measured row has no measurements')
    return rows


def analyze(source, output):
    validate(source)
    path = legacy.analyze(source, output)
    (path / 'validation.txt').write_text(
        'Validated schema, chronology, source VLAN, target scope and evidence references.\n'
        'Operator must verify evidence truth, denial attribution, common clocks and fair workloads.\n', encoding='utf-8')
    return path
