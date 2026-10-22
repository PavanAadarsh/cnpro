"""Offline, evidence-backed evaluation for the documented Packet Tracer topology.

Python standard library only. Never sends traffic or configures switches.
"""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import html
import json
import math
from pathlib import Path
import shutil
import statistics
import uuid

ROOT = Path(__file__).resolve().parents[1]
METRICS = ('detection_ms', 'response_ms', 'recovery_ms', 'latency_ms',
           'packet_loss_pct', 'throughput_mbps', 'disruption_pct', 'success_pct',
           'unauthorized_success_pct')


def stamp(value):
    t = datetime.fromisoformat(value)
    if t.tzinfo is None:
        raise ValueError('timestamps require timezone offsets')
    return t


def delta(row, start, end):
    if row.get(start) is None or row.get(end) is None:
        return None
    value = (stamp(row[end]) - stamp(row[start])).total_seconds() * 1000
    if value < 0:
        raise ValueError(f'{end} precedes {start}')
    return value


def count(row, key):
    value = row.get(key)
    if value is not None and (type(value) is not int or value < 0):
        raise ValueError(f'{key} must be a nonnegative integer or null')
    return value


def rate(row, attempted, succeeded, failure=False):
    a, s = count(row, attempted), count(row, succeeded)
    if (a is None) != (s is None):
        raise ValueError('both counters must be supplied together')
    if a is None:
        return None
    if s > a:
        raise ValueError('successes exceed attempts')
    return (100 * ((a - s) if failure else s) / a) if a else None


def calculate(row):
    out = {key: None for key in METRICS}
    for key, start, end in [('detection_ms', 'condition_at', 'detected_at'),
                            ('response_ms', 'detected_at', 'effective_denial_at'),
                            ('recovery_ms', 'recovery_condition_at', 'restored_at')]:
        out[key] = delta(row, start, end)
    delta(row, 'start_at', 'end_at')
    out['packet_loss_pct'] = rate(row, 'probes_sent', 'probes_received', True)
    out['success_pct'] = rate(row, 'legitimate_attempted', 'legitimate_succeeded')
    out['unauthorized_success_pct'] = rate(row, 'unauthorized_attempted', 'unauthorized_succeeded')
    out['disruption_pct'] = rate(row, 'transition_attempted', 'transition_succeeded', True)
    samples = row.get('rtt_ms', [])
    if not isinstance(samples, list) or any(type(x) not in (int, float) or not math.isfinite(x) or x < 0 for x in samples):
        raise ValueError('rtt_ms must contain finite nonnegative numbers')
    received = row.get('probes_received')
    if received is not None and len(samples) > received:
        raise ValueError('RTT sample count exceeds replies')
    out['latency_ms'] = statistics.mean(samples) if samples else None
    size, duration = count(row, 'transferred_bytes'), row.get('transfer_seconds')
    if (size is None) != (duration is None):
        raise ValueError('transfer bytes and duration must be supplied together')
    if duration is not None:
        if type(duration) not in (float, int) or not math.isfinite(duration) or duration <= 0:
            raise ValueError('transfer_seconds must be positive and finite')
        out['throughput_mbps'] = size * 8 / duration / 1e6
    return out


def audit():
    updated = ROOT / 'monitoring_integration/upstream/member2/cnpro/running-configs/CORE-SW_running_config.txt'
    core_path = updated if updated.is_file() else ROOT / 'running-configs/CORE-SW_running_config.txt'
    core = core_path.read_text()
    excluded = {'.git', 'results', 'network_results', 'captures', '__pycache__'}
    files = [p for p in ROOT.rglob('*') if p.is_file() and not excluded.intersection(p.relative_to(ROOT).parts)]
    topology = [str(p.relative_to(ROOT)) for p in files if p.suffix.lower() in ('.pkt', '.pka')]
    engine = ROOT / 'monitoring_integration/upstream/member3/policy_engine/policy_engine.py'
    limitations = ['Static source inspection only; live policy enforcement and network metrics are unverified.']
    if not engine.is_file():
        limitations.append('Engine dependency is not prepared locally; use monitoring_integration/prepare_upstream.py.')
    if not topology:
        limitations.append('No local Packet Tracer topology; no network probe/capture executed by this audit.')
    if 'ip access-group ' not in core:
        limitations.append('Selected core configuration has no security ACL attachment.')
    return {
        'checked_at': datetime.now(timezone.utc).isoformat(),
        'pkt_files': topology,
        'core_configuration_source': core_path.relative_to(ROOT).as_posix(),
        'configuration_only': True,
        'live_security_acl_verified': None,
        'core_security_acl_applied': 'ip access-group ' in core,
        'engine_source_present': engine.is_file(),
        'routing_enabled': '\nip routing\n' in core,
        'tools_on_path': {x: shutil.which(x) for x in ('python', 'tshark', 'tcpdump', 'PacketTracer')},
        'source_sha256': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
        'limitations': limitations}


def new_run(base):
    path = Path(base) / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8])
    path.mkdir(parents=True, exist_ok=False)
    return path


def analyze(source, base):
    rows = json.loads(Path(source).read_text(encoding='utf-8-sig'))
    if not isinstance(rows, list):
        raise ValueError('input must be a JSON array')
    processed, seen = [], set()
    evidence_files = {}
    for row in rows:
        for field in ('scenario', 'configuration', 'trial', 'start_at', 'end_at', 'status', 'notes'):
            if field not in row:
                raise ValueError(f'missing {field}')
        if row['configuration'] not in ('architecture_baseline', 'static', 'adaptive'):
            raise ValueError('invalid configuration')
        if type(row['trial']) is not int or row['trial'] < 1:
            raise ValueError('trial must be a positive integer')
        key = row['scenario'], row['configuration'], row['trial']
        if key in seen:
            raise ValueError('duplicate scenario/configuration/trial')
        seen.add(key)
        stamp(row['start_at']); stamp(row['end_at'])
        if row['status'] not in ('measured', 'blocked', 'failed'):
            raise ValueError('invalid status')
        metrics = calculate(row)
        if row['status'] == 'blocked' and any(v is not None for v in metrics.values()):
            raise ValueError('blocked rows cannot contain measurements')
        if row['status'] != 'blocked':
            if not row.get('evidence'):
                raise ValueError('executed trials require evidence paths')
            for name in row['evidence']:
                p = (Path(source).resolve().parent / name).resolve()
                if not p.is_relative_to(Path(source).resolve().parent):
                    raise ValueError('evidence must be inside the input folder')
                evidence_files[str(p)] = p.read_bytes()
        processed.append({**row, **metrics, 'rtt_sample_count': len(row.get('rtt_ms', []))})
    path = new_run(base)
    (path / 'input.json').write_bytes(Path(source).read_bytes())
    manifest = {}
    for i, (name, data) in enumerate(evidence_files.items()):
        target = f'evidence/{i}-{Path(name).name}'
        (path / 'evidence').mkdir(exist_ok=True)
        (path / target).write_bytes(data)
        manifest[name] = {'saved': target, 'sha256': hashlib.sha256(data).hexdigest()}
    (path / 'evidence_manifest.json').write_text(json.dumps(manifest, indent=2))
    (path / 'results.json').write_text(json.dumps(processed, indent=2, allow_nan=False))
    fields = sorted({k for r in processed for k in r})
    with (path / 'results.csv').open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fields); writer.writeheader()
        writer.writerows({k: json.dumps(v) if isinstance(v, (list, dict)) else v for k, v in r.items()} for r in processed)
    summaries = []
    for scenario, config in sorted({(r['scenario'], r['configuration']) for r in processed}):
        group = [r for r in processed if r['scenario'] == scenario and r['configuration'] == config]
        for metric in METRICS:
            values = [r[metric] for r in group if r['status'] == 'measured' and r[metric] is not None]
            summaries.append(dict(scenario=scenario, configuration=config, metric=metric, n=len(values),
                                  mean=statistics.mean(values) if values else None,
                                  median=statistics.median(values) if values else None,
                                  minimum=min(values) if values else None, maximum=max(values) if values else None))
    (path / 'summary.json').write_text(json.dumps(summaries, indent=2))
    # Separate units/scenarios; never graph unavailable measurements as zero.
    chart_index = 0
    for scenario in sorted({s['scenario'] for s in summaries}):
        for metric in METRICS:
            bars = [s for s in summaries if s['scenario'] == scenario and s['metric'] == metric and s['n']]
            if len(bars) < 2:
                continue
            scale = max(s['mean'] for s in bars) or 1
            svg = ['<svg xmlns="http://www.w3.org/2000/svg" width="850" height="200" viewBox="0 0 850 200">',
                   '<rect width="850" height="200" fill="white"/>',
                   f'<text x="10" y="22">{html.escape(scenario)}: {metric} (trial means)</text>']
            for i, s in enumerate(bars):
                y = 42 + i * 45
                svg.extend([f'<text x="10" y="{y+18}">{s["configuration"]}</text>',
                            f'<rect x="200" y="{y}" width="{450*s["mean"]/scale}" height="25" fill="#2563eb"/>',
                            f'<text x="660" y="{y+18}">{s["mean"]:.3f} (n={s["n"]})</text>'])
            svg.append('</svg>')
            (path / f'comparison-{chart_index}.svg').write_text('\n'.join(svg))
            chart_index += 1
    lines = ['# Evaluation results', '', 'Means are unweighted trial means; n excludes missing/failed trials.', '',
             '| Scenario | Configuration | Metric | n | Mean | Median | Min | Max |', '|---|---|---|---:|---:|---:|---:|---:|']
    for s in summaries:
        lines.append('| ' + ' | '.join('unavailable' if s[k] is None else str(s[k]) for k in ('scenario', 'configuration', 'metric', 'n', 'mean', 'median', 'minimum', 'maximum')) + ' |')
    lines.extend(['', '## Trial status', ''])
    lines.extend(f"- {r['scenario']} / {r['configuration']} / {r['trial']}: {r['status']} — {r['notes']}" for r in processed)
    (path / 'report.md').write_text('\n'.join(lines), encoding='utf-8')
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('audit', 'analyze', 'blocked'))
    parser.add_argument('--input')
    parser.add_argument('--output', default=str(ROOT / 'monitoring/results'))
    args = parser.parse_args()
    if args.command == 'audit':
        path = new_run(args.output)
        (path / 'audit.json').write_text(json.dumps(audit(), indent=2))
    elif args.command == 'blocked':
        path = new_run(args.output)
        now = datetime.now(timezone.utc).isoformat()
        rows = [dict(scenario=s['id'], configuration=c, trial=1, start_at=now, end_at=now,
                     status='blocked', notes='Not executed: no matching live topology/runtime verified. ACL/engine sources may be available; see current audit. Times record availability check only.')
                for s in json.loads((ROOT / 'monitoring/scenarios.json').read_text())
                for c in ('architecture_baseline', 'static', 'adaptive')]
        source = path / 'availability.json'
        source.write_text(json.dumps(rows, indent=2))
        path = analyze(source, path)
    else:
        if not args.input:
            parser.error('--input required')
        path = analyze(args.input, args.output)
    print(path)


if __name__ == '__main__':
    main()
