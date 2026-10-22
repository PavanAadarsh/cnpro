"""Compare Member 3's latest runtime document with actual engine/ACL behavior.

Software probes use the real engine with recorded, non-network enforcement.
These findings are not network measurements or instructions to rewrite policy.
"""
import json
from pathlib import Path
import re

from acl_audit import evaluate, packet
from engine_adapter import EngineSession
from policy_engine.threshold_tracker import TH_AUTH_FAILURE_WINDOW_SEC
from policy_engine.event_listener import AutoEventListener

HERE = Path(__file__).resolve().parent
ACL = HERE / 'upstream/member2/cnpro/configs/CORE-SW_security_acls.cfg'
RUNTIME = HERE / 'upstream/member3/docs/ENGINE_RUNTIME_AND_RECONCILIATION.md'


def check(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    document = RUNTIME.read_text(encoding='utf-8')
    findings = []
    def add(identifier, claim, observed, status, evidence):
        findings.append(dict(id=identifier, documented_claim=claim, observed=observed,
                             status=status, evidence=evidence,
                             evidence_level='source_configuration_or_real_engine_software_not_network'))

    paths = [p for p in (HERE / 'upstream/member3').rglob('*.py')
             if 'tests' not in p.relative_to(HERE / 'upstream/member3').parts]
    listeners = [str(p.relative_to(HERE)) for p in paths
                 if re.search(r'\.(?:bind|recvfrom|listen)\s*\(|\b(?:UDPServer|DatagramProtocol)\b',
                              p.read_text(encoding='utf-8'))]
    add('production_syslog_parser', 'Background syslog/NetFlow parser feeds handle_event automatically.',
        {'listener_implementations_found': listeners,
         'manual_injection_available': True},
        'not_found_in_delivered_source' if not listeners else 'requires_runtime_verification',
        'member3 source inventory and simulate_event.py; runtime document section 2.2')
    rules = [s.strip() for s in ACL.read_text().splitlines() if s.strip().startswith(('permit ', 'deny '))]
    add('syslog_acl_prerequisite', 'deny ip any any log generates access-log syslog for collection.',
        {'acl_rules_with_log': [s for s in rules if re.search(r'\blog(?:-input)?\b', s)]},
        'not_configured' if not any(re.search(r'\blog(?:-input)?\b', s) for s in rules) else 'requires_runtime_verification',
        str(ACL.relative_to(HERE)))

    session = EngineSession(directory / 'actual-engine', raw_upstream=True)
    session.invoke('PC-STU2', 'event', 'spoofing')
    before = session.engine.state_manager.get_state('PC-STU2')['quarantined_since']
    session.invoke('PC-STU2', 'event', 'policy_violation')
    after = session.engine.state_manager.get_state('PC-STU2')['quarantined_since']
    add('quarantine_hold_restart', 'TH-04 violation restarts the quarantine hold timer.',
        {'quarantined_since_before': before, 'quarantined_since_after': after, 'timer_restarted': before != after},
        'conflict' if before == after else 'matches', 'actual-engine/trace.json; StateManager and PolicyEngine TH-04 path')
    session.invoke('PC-STU2', 'remediated')
    row = session.invoke('PC-STU2', 'sweep')
    add('remediation_hold_required', 'REC-04 requires the hold timer; remediation only waives the quiet period.',
        {'state_after_immediate_sweep': row['after']['state'], 'sweep_returned': row['returned']},
        'matches' if row['after']['state'] == 'QUARANTINE' else 'conflict',
        'actual-engine/trace.json; RecoveryHandler still requires hold_ok')
    events = json.loads((session.directory / 'events_db.json').read_text())
    add('structured_event_schema', 'events_db.json stores documented event_id/source_ip/target_ip/detection_source event objects.',
        {'actual_shape': 'device_name -> event_type -> list of ISO timestamp strings',
         'device_keys': list(events), 'documented_event_id_stored': 'event_id' in events},
        'not_implemented_as_documented', 'actual-engine/events_db.json; ThresholdTracker._save()')
    add('auth_window', 'Reconciled TH-01 window is 300 seconds.', TH_AUTH_FAILURE_WINDOW_SEC,
        'matches' if TH_AUTH_FAILURE_WINDOW_SEC == 300 else 'conflict',
        'policy_engine/threshold_tracker.py')

    for name, vlan, target, protocol, dport, kind in [
        ('restricted_internet_http', 60, '203.0.113.2', 'tcp', 80, None),
        ('restricted_internet_dns', 60, '203.0.113.2', 'udp', 53, None),
        ('quarantine_remediation_http', 70, '192.168.50.13', 'tcp', 80, None),
        ('quarantine_remediation_ping', 70, '192.168.50.13', 'icmp', None, 8),
        ('restricted_remediation_ping', 60, '192.168.50.13', 'icmp', None, 8),
    ]:
        result = evaluate(ACL, vlan, packet(f'192.168.{vlan}.100', target, protocol, dport, icmp_type=kind))
        add(name, 'Latest Member 3 permission table/runbook says PERMIT.', result,
            'conflict' if result['action'] != 'permit' else 'matches',
            f'Member 3 runtime document sections 3.3/4 versus {result["acl"]}, line {result["line"]}')

    add('clock_shift_immunity', 'Epoch differences are immune to manual system-clock shifts.',
        'Engine thresholds/hold timers use datetime.now(timezone.utc), a wall clock, not a monotonic clock.',
        'requires_clock_contract_correction', 'threshold_tracker.py, recovery_handler.py; runtime document section 2.3')
    add('recovery_schedule', 'Recovery is automatic via simulate_event.py recover.',
        'AutoEventListener.start launches a periodic recovery worker; CLI recover remains on-demand.',
        'implemented_requires_runtime_verification', 'simulate_event.py cmd_recover and PolicyEngine.run_recovery_sweep()')
    listener = AutoEventListener(session.engine)
    mapped = {ip: listener.resolve_ip_to_device(ip) for ip in
              ('192.168.10.101', '192.168.10.150', '192.168.60.101', '192.168.70.101')}
    add('dynamic_device_resolution', 'Identify the actual endpoint across DHCP leases and containment VLAN changes.',
        mapped, 'partial_static_mapping',
        'event_listener.py uses fixed .100/.101 entries, subnet fallback to first PC, and no VLAN60/70 mapping')
    detector_session = EngineSession(directory / 'detector-engine', raw_upstream=True)
    parsed = listener.parse_syslog_message('%SEC-6-IPACCESSLOGP: list ACL-VLAN10-STUDENT-IN denied tcp 192.168.10.101 -> 192.168.50.12')
    for _ in range(4):
        detection = detector_session.invoke(parsed[0], 'event', parsed[1])
    add('acl_syslog_containment', 'Prohibited ACL attempts cause adaptive containment from NORMAL.',
        {'parsed_event': parsed, 'events_injected': 4, 'state': detection['after']['state']},
        'does_not_restrict_normal' if detection['after']['state'] == 'NORMAL' else 'matches',
        'real parser maps ACL denies to policy_violation, which does not restrict NORMAL in ThresholdTracker')
    for suffix, readback in [('unknown', None), ('mismatch', 70)]:
        recovery = EngineSession(directory / ('recovery-' + suffix), raw_upstream=True)
        recovery.invoke('PC-STU2', 'event', 'port_scan')
        recovery.recorder.verify_vlan = lambda *args, value=readback: value
        result = recovery.invoke('PC-STU2', 'clear')
        add('recovery_readback_' + suffix, 'Recovery only succeeds after verified home VLAN readback.',
            {'readback': readback, 'state': result['after']['state'],
             'enforcement_failed': result['after']['enforcement_failed']},
            'unverified_recovery_accepted' if suffix == 'unknown' and result['after']['state'] == 'NORMAL'
            else ('matches' if result['after']['state'] == 'RESTRICTED' else 'conflict'),
            'RecoveryHandler._do_recover only rejects a differing integer; None/exceptions are accepted')
    evidence_doc = HERE / 'upstream/member3/docs/LIVE_NETWORK_ENFORCEMENT_EVIDENCE.md'
    add('teammate_network_evidence', 'Uploaded enforcement document demonstrates complete network operation.',
        {'document_present': evidence_doc.is_file(),
         'independently_executed_network_test': False,
         'test_live_switch_runtime_uses_mock': True},
        'runbook_and_mock_tests_not_independent_network_measurements',
        'Expected CLI output and mock tests supplied; actual packet captures and timestamped trial evidence still required')
    (directory / 'findings.json').write_text(json.dumps(findings, indent=2), encoding='utf-8')
    return findings
