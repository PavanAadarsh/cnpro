"""Member 4 add-on entry point; all new outputs stay under monitoring_integration."""
import argparse
import contextlib
from datetime import datetime, timezone
import csv
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import tempfile
import unittest
import uuid

from acl_audit import audit, load
from engine_adapter import run_trials
from network_data import analyze
from branch_audit import inventory
from contract_audit import check as check_contract

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
ACL = HERE / 'upstream/member2/cnpro/configs/CORE-SW_security_acls.cfg'


def latest_live():
    for directory in sorted((HERE/'results').glob('live-*'), reverse=True):
        if (directory/'verified_summary.json').is_file() and (directory/'status.json').is_file():
            if json.loads((directory/'status.json').read_text())['status'] == 'completed':
                return directory.relative_to(HERE).as_posix()
    return None


def new_run(kind, base=None):
    path = Path(base or HERE / 'results') / (kind + '-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8])
    path.mkdir(parents=True, exist_ok=False)
    return path


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False), encoding='utf-8')


def environment():
    acls, bindings = load(ACL)
    exported, exported_bindings = load(HERE / 'upstream/member2/cnpro/running-configs/CORE-SW_running_config.txt')
    def normalized(rules):
        return {name: [r.text for r in values] for name, values in rules.items()}
    return dict(checked_at=datetime.now(timezone.utc).isoformat(),
                branches=json.loads((HERE / 'sources.json').read_text()),
                tools={name: shutil.which(name) for name in ('python', 'tshark', 'tcpdump', 'PacketTracer')},
                paramiko_available=importlib.util.find_spec('paramiko') is not None,
                pkt_files=[str(p.relative_to(ROOT)) for p in ROOT.rglob('*.pkt') if '.git' not in p.parts],
                acl_count=len(acls), svi_bindings=bindings,
                member2_snippet_matches_export=(normalized(acls) == normalized(exported) and bindings == exported_bindings),
                engine_states=['NORMAL', 'RESTRICTED', 'QUARANTINE'],
                engine_detection_interface='manual injection or delivered UDP syslog/NetFlow listener with periodic recovery; live switch/exporter integration unverified',
                runtime_document_present=(HERE / 'upstream/member3/docs/ENGINE_RUNTIME_AND_RECONCILIATION.md').is_file(),
                source_hashes={str(p.relative_to(HERE)): hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in (HERE / 'upstream').rglob('*') if p.is_file()},
                latest_verified_linux_lab=latest_live(),
                network_status='separate_linux_lab_evidence_available' if latest_live() else 'no_completed_verified_linux_lab',
                cisco_hardware_verified=False)


def resolve_scenarios():
    scenarios = [
        dict(id='authorized', source='PC-RES1', destination='192.168.50.10', protocol='tcp', port=80,
             normal='permit', restricted='deny', quarantine='deny',
             action='HTTP GET from actual PC-RES1 lease; unaffected research control remains VLAN30.'),
        dict(id='protected_access', source='PC-STU2', destination='192.168.50.12', protocol='tcp', port=80,
             normal='deny', restricted='deny', quarantine='deny',
             action='HTTP request plus PC-ADM1 health control and actual ACL-drop evidence.'),
        dict(id='violations', source='PC-STU2', destination='192.168.50.12', protocol='tcp', port=80,
             action='Two observed cross-VLAN violations may be manually normalized to cross_vlan_attempt; '
                    '2 in 600 s restrict. Next policy_violation while restricted escalates. '
                    'Packet Tracer injection is explicit; delivered syslog listener maps denies to policy_violation, which alone does not restrict NORMAL.'),
        dict(id='legitimate_transition', source='PC-RES1 and PC-STU2', destination='192.168.50.10 / 192.168.50.13',
             protocol='tcp', port=80, action='Concurrent separate host traces; PC-RES1 HTTP stays permitted. '
             'STU2 research permitted NORMAL, denied RESTRICTED/QUARANTINE; remediation permitted NORMAL/RESTRICTED, denied QUARANTINE.'),
        dict(id='recovery', source='PC-STU2', destination='192.168.50.13 then 203.0.113.2', protocol='tcp', port=80,
             action='manual_clear is immediate admin recovery; auto recovery requires 1800 s restricted or '
                    '7200 s quarantine hold plus no recent events or remediated. Further quarantine violations restart hold; remediation does not bypass it. listen mode runs periodic recovery. '
                    'Renew lease, inspect port and verify restored HTTP.'),
        dict(id='performance', source='PC-RES1', destination='192.168.50.10', protocol='icmp', port=None,
             action='20 ICMP probes from simulated PC; 3 trials each static/adaptive. Actual RTT/loss required; no predefined success numbers.')]
    points = json.loads((HERE / 'capture_points.json').read_text(encoding='utf-8'))
    for scenario in scenarios:
        scenario['capture_points'] = [point['id'] for point in points if scenario['id'] in point['scenarios']]
    return scenarios


def scenario_audit(path):
    env = environment()
    write_json(path / 'environment.json', env)
    branches = inventory()
    write_json(path / 'branch_inventory.json', branches)
    contracts = check_contract(path / 'contract_checks')
    write_json(path / 'contract_checks.json', contracts)
    source_commit = env['branches']['origin/member3']
    member3 = next(b for b in branches['branches'] if b['branch'] == 'member3')
    if 'state_db.json' in member3['files']:
        received = subprocess.check_output(['git', '-C', str(ROOT), 'show', f'{source_commit}:state_db.json'])
        (path / 'received_member3_state_db.json').write_bytes(received)
        state = json.loads(received)
        write_json(path / 'received_state_summary.json', dict(source_commit=source_commit, devices=len(state),
            state_counts={name: sum(r.get('state') == name for r in state.values()) for name in ('NORMAL', 'RESTRICTED', 'QUARANTINE')},
            failed_enforcement_records=sum(r.get('enforcement_failed') is True for r in state.values()),
            evidence_level='teammate_uploaded_snapshot_not_live_network_evidence',
            imported_into_active_engine=False))
    rows = audit(ACL)
    write_json(path / 'acl_checks.json', rows)
    effective = HERE/'effective/CORE-SW_security_acls.cfg'
    if effective.is_file():
        write_json(path/'effective_acl_checks.json', audit(effective))
    write_json(path / 'resolved_scenarios.json', resolve_scenarios())
    write_json(path / 'capture_points.json', json.loads((HERE / 'capture_points.json').read_text(encoding='utf-8')))
    write_json(path / 'network_readiness.json', [dict(scenario=s['id'], configuration=c, executed=False,
                status='separate_linux_lab_evidence_available' if latest_live() else 'blocked',
                separate_linux_lab_evidence=latest_live(), detection_ms=None, response_ms=None, recovery_ms=None,
                latency_ms=None, packet_loss_pct=None, throughput_mbps=None,
                notes='This command audits sources without running experiments. See separate Linux lab evidence when available. '
                      'Upstream contracts below describe teammate originals; runtime.py and effective policy implement local fixes. '
                      'Cisco hardware is not verified by Linux lab results.')
                for s in resolve_scenarios() for c in ('static', 'adaptive')])
    lines = ['# Member 4 source audit (upstream originals versus local fixes)', '',
             'Current corrected runtime is runtime.py; effective_acl_checks.json checks the local policy. '
             'Actual completed kernel experiments, if available: ' + str(latest_live()), '',
             'Configuration checks are offline semantics, not network tests. Expected values come from Member 2 documentation.', '',
             '| Case | Expected | ACL decision | Match | Source ACL line |', '|---|---|---|---|---:|']
    for row in rows:
        lines.append(f"| {row['id']} | {row['expected']} | {row['action']} | {row['matches_documented_expectation']} | {row['line']} |")
    lines += ['', '## Findings to verify with teammates', '',
              '- S12 student→admin ICMP is permitted by an earlier broad ICMP rule, contrary to its DENY/PASS documentation.',
              '- The matrix promises admin access to all internet ports; the supplied ACL permits only specific DNS/web services to INTERNET-SRV (SMTP/25 is denied).',
              '- VLAN50 ACL contains a general permit ip from the server subnet after its response rules. It is not response-only filtering.',
              '- Policy host and access-switch management IPs share VLAN40; direct same-VLAN traffic normally bypasses core routed SVI ACL evaluation.',
              '- Engine uses QUARANTINE (not QUARANTINED), and stores requested state even when SSH fails; inspect enforcement_failed and independent port/probe evidence.',
              '- Generic policy_violation events alone do not restrict a NORMAL device; cross_vlan_attempt needs 2/600 s, auth_failure needs 3/300 s, port_scan or spoofing needs 1.',
              '- Delivered UDP syslog/NetFlow parser and recovery worker exist. ACL denies map to policy_violation and do not restrict NORMAL on their own; no live exporter verified.',
              '- Remediation flag does not bypass 30/120-minute hold in the actual recovery implementation.',
              '- No .pkt file exists in any fetched branch; see branch_inventory.json for every path and commit.',
              '- Timer restart, hold-required remediation and periodic recovery source are now delivered. Structured persistence, dynamic identity mapping, ACL permissions and fail-closed readback still need reconciliation.',
              '- Uploaded state_db.json is archived as a teammate snapshot and never loaded as active engine state.',
              '', 'No teammate configuration/source has been changed. See environment.json for pinned source hashes and snippet/export consistency.']
    (path / 'audit_report.md').write_text('\n'.join(lines), encoding='utf-8')
    contract_lines = ['# Upstream runtime contract verification (before local fixes)', '',
        'Actual source/ACL semantics and real engine software probes with stub enforcement. No network measurements.', '',
        '| Claim | Status | Observed |', '|---|---|---|']
    contract_lines += [f"| {r['id']} | {r['status']} | {json.dumps(r['observed'], ensure_ascii=False)} |" for r in contracts]
    (path / 'contract_report.md').write_text('\n'.join(contract_lines), encoding='utf-8')
    return rows


def replay(path, trials):
    rows = run_trials(path / 'trials', trials)
    write_json(path / 'engine_results.json', rows)
    with (path / 'engine_results.csv').open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
    summary = []
    for name in sorted({r['scenario'] for r in rows}):
        # Average per-trial mean API time, with n reporting independent trials.
        values = [statistics.mean(r['api_runtime_ms'] for r in rows if r['scenario'] == name and r['trial'] == t)
                  for t in range(1, trials + 1)]
        summary.append(dict(scenario=name, n_trials=trials, mean_ms=statistics.mean(values),
                            median_ms=statistics.median(values), minimum_ms=min(values), maximum_ms=max(values)))
    write_json(path / 'engine_summary.json', summary)
    import html
    svg = ['<svg xmlns="http://www.w3.org/2000/svg" width="1180" height="540" viewBox="0 0 1180 540">',
           '<rect width="1180" height="540" fill="white"/>',
           '<text x="20" y="28" font-size="18">Real engine API runtime (ms) — injected events; stub enforcement; no network measurements</text>']
    scale = max(s['mean_ms'] for s in summary) or 1
    for i, s in enumerate(summary):
        y = 60 + i * 48
        svg += [f'<text x="20" y="{y+18}">{html.escape(s["scenario"])}</text>',
                f'<rect x="440" y="{y}" width="{500*s["mean_ms"]/scale}" height="26" fill="#2563eb"/>',
                f'<text x="960" y="{y+18}">{s["mean_ms"]:.3f} ms (n={trials})</text>']
    svg.append('</svg>')
    (path / 'engine_api_runtime.svg').write_text('\n'.join(svg), encoding='utf-8')
    (path / 'replay_report.md').write_text(
        '# Engine integration software results\n\n'
        f'{len(rows)} real API calls in {trials} trials per plan; '
        f'{sum(r["assertion_passed"] for r in rows)} expected-state/flag assertions passed.\n\n'
        'Uses Member 3 engine with the integrated verified-enforcement wrapper and explicit non-network CommandRecorder injection. '
        'API timings include JSON persistence and local log handling. These are software measurements, '
        'not network detection, isolation, recovery, RTT, loss or throughput. '
        'The chart shows per-trial mean API runtime; state/command evidence lives under trials/.\n', encoding='utf-8')
    return rows


def validate_tests(path):
    (path / 'temp').mkdir()
    previous = tempfile.tempdir
    previous_cwd = Path.cwd()
    os.chdir(path / 'temp')
    tempfile.tempdir = str((path / 'temp').resolve())
    sys.path.insert(0, str(HERE / 'upstream/member3'))
    groups = [('member3', HERE / 'upstream/member3/tests'), ('member4_original', ROOT / 'monitoring/tests'),
              ('member4_integration', HERE / 'tests')]
    summary = {}
    try:
        with (path / 'tests.txt').open('w', encoding='utf-8') as f, contextlib.redirect_stdout(f), contextlib.redirect_stderr(f):
            for name, folder in groups:
                suite = unittest.defaultTestLoader.discover(str(folder), pattern='test_*.py')
                result = unittest.TextTestRunner(stream=f, verbosity=2).run(suite)
                summary[name] = dict(tests=result.testsRun, failures=len(result.failures),
                                     errors=len(result.errors), passed=result.wasSuccessful())
    finally:
        tempfile.tempdir = previous
        os.chdir(previous_cwd)
    write_json(path / 'test_summary.json', summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('audit', 'test', 'live'):
        sub.add_parser(name)
    p = sub.add_parser('replay'); p.add_argument('--trials', type=int, default=3)
    p = sub.add_parser('import-network'); p.add_argument('--input', required=True)
    p = sub.add_parser('collect-http')
    p.add_argument('--project-only', action='store_true', required=True)
    p.add_argument('--scenario', choices=['authorized', 'protected_access', 'affected_research', 'remediation', 'recovery', 'admin_health_control'], required=True)
    p.add_argument('--source-ip', required=True); p.add_argument('--vlan', type=int, required=True)
    p.add_argument('--configuration', choices=['static', 'adaptive'], required=True)
    p.add_argument('--configuration-snapshot', required=True)
    p.add_argument('--count', type=int, default=5); p.add_argument('--interval', type=float, default=1)
    p.add_argument('--timeout', type=float, default=2); p.add_argument('--trial', type=int, default=1)
    args = parser.parse_args()
    if args.command == 'live':
        from prepare_lab import run
        run()
        return
    if args.command == 'import-network':
        path = analyze(args.input, HERE / 'network_results')
    elif args.command == 'collect-http':
        from collect_http import collect
        outer = new_run('http')
        try:
            path = collect(outer / 'evidence', args.scenario, args.source_ip, args.vlan,
                           args.configuration, args.configuration_snapshot, args.count, args.interval,
                           args.timeout, args.trial)
        except (ValueError, OSError) as exc:
            write_json(outer / 'preflight_or_collection_error.json', dict(status='failed',
                       error=type(exc).__name__ + ': ' + str(exc),
                       notes='No completed observation is asserted. Any partial files require review.'))
            print(outer)
            raise SystemExit(1)
    else:
        path = new_run(args.command)
        if args.command == 'audit':
            scenario_audit(path)
        elif args.command == 'replay':
            rows = replay(path, args.trials)
            if not all(r['assertion_passed'] for r in rows):
                print(path); raise SystemExit(1)
        else:
            summary = validate_tests(path)
            if not all(r['passed'] for r in summary.values()):
                print(path); raise SystemExit(1)
    print(path)


if __name__ == '__main__':
    main()
