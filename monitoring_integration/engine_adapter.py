"""Instrument Member 3's unchanged real engine with explicitly non-network I/O.

No socket/SSH call is made by this module. Recorded commands are never treated
as applied VLANs or effective connectivity.
"""
import contextlib
import copy
import io
import json
import logging
from pathlib import Path
import sys
import time
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'upstream/member3'))
from policy_engine.policy_engine import PolicyEngine
from policy_engine.threshold_tracker import VALID_EVENT_TYPES


class CommandRecorder:
    def __init__(self):
        self.calls = []
        self.accept = True

    def push_vlan(self, switch_ip, port, vlan_id):
        self.calls.append(dict(switch_ip=switch_ip, port=port, vlan_id=vlan_id,
                               stub_accept=self.accept, network_applied=False))
        return self.accept

    def verify_vlan(self, *args):
        return None


class EngineSession:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=False)
        self.recorder = CommandRecorder()
        self.engine = PolicyEngine(state_db_path=str(self.directory / 'state_db.json'),
                                   events_db_path=str(self.directory / 'events_db.json'),
                                   ssh_enforcer=self.recorder)
        self.records = []

    def invoke(self, device, operation, value=None):
        if self.engine.state_manager.get_state(device) is None:
            raise ValueError('unknown device')
        if operation == 'event' and value not in VALID_EVENT_TYPES:
            raise ValueError('unknown event type')
        if operation not in ('event', 'clear', 'sweep', 'remediated'):
            raise ValueError('unknown operation')
        before = self.engine.state_manager.get_state(device)
        calls_before = len(self.recorder.calls)
        text = io.StringIO()
        logs = io.StringIO()
        handler = logging.StreamHandler(logs)
        logger = logging.getLogger('policy_engine')
        previous = logger.level
        logger.setLevel(logging.INFO)
        logger.addHandler(handler)
        injected_at = datetime.now(timezone.utc).isoformat()
        start = time.perf_counter_ns()
        try:
            with contextlib.redirect_stdout(text):
                if operation == 'event':
                    result = self.engine.handle_event(device, value)
                elif operation == 'clear':
                    result = self.engine.manual_clear(device)
                elif operation == 'remediated':
                    result = self.engine.mark_remediated(device)
                else:
                    result = self.engine.run_recovery_sweep()
        finally:
            elapsed = (time.perf_counter_ns() - start) / 1e6
            logger.removeHandler(handler)
            logger.setLevel(previous)
        after = self.engine.state_manager.get_state(device)
        record = dict(operation=operation, event_type=value, device=device, injected_at=injected_at,
                      completed_at=datetime.now(timezone.utc).isoformat(), api_runtime_ms=elapsed,
                      before=before, after=after, returned=result,
                      recorded_commands=copy.deepcopy(self.recorder.calls[calls_before:]),
                      evidence_level='real_engine_injected_events_stub_enforcement',
                      network_detection_ms=None, network_response_ms=None, network_recovery_ms=None,
                      effective_network_state=None)
        self.records.append(record)
        with (self.directory / 'engine.log').open('a', encoding='utf-8') as f:
            f.write(text.getvalue() + logs.getvalue())
        (self.directory / 'trace.json').write_text(json.dumps(self.records, indent=2), encoding='utf-8')
        return record


PLANS = {
    'auth_threshold': [('event', 'auth_failure', 'NORMAL'), ('event', 'auth_failure', 'NORMAL'),
                       ('event', 'auth_failure', 'RESTRICTED')],
    'cross_vlan_threshold': [('event', 'cross_vlan_attempt', 'NORMAL'),
                             ('event', 'cross_vlan_attempt', 'RESTRICTED')],
    'restriction_and_quarantine': [('event', 'cross_vlan_attempt', 'NORMAL'),
                                    ('event', 'cross_vlan_attempt', 'RESTRICTED'),
                                    ('event', 'policy_violation', 'QUARANTINE')],
    'spoofing_direct_quarantine': [('event', 'spoofing', 'QUARANTINE')],
    'generic_violations_do_not_restrict_normal': [('event', 'policy_violation', 'NORMAL')] * 4,
    'manual_recovery': [('event', 'port_scan', 'RESTRICTED'), ('clear', None, 'NORMAL')],
    'remediation_does_not_bypass_hold': [('event', 'port_scan', 'RESTRICTED'),
                                       ('remediated', None, 'RESTRICTED'), ('sweep', None, 'RESTRICTED')],
    'enforcement_failure_flag': [('event', 'port_scan', 'RESTRICTED')],
    'recovery_failure_flag': [('event', 'port_scan', 'RESTRICTED'), ('clear', None, 'NORMAL')],
}


def run_trials(output, trials=3):
    if not 1 <= trials <= 100:
        raise ValueError('trials must be 1..100')
    rows = []
    for trial in range(1, trials + 1):
        for name, plan in PLANS.items():
            path = Path(output) / f'{name}-trial{trial}'
            session = EngineSession(path)
            for step, (operation, value, expected) in enumerate(plan, 1):
                session.recorder.accept = not (name == 'enforcement_failure_flag' or
                                                name == 'recovery_failure_flag' and operation == 'clear')
                record = session.invoke('PC-STU2', operation, value)
                passed = record['after']['state'] == expected
                if name in ('enforcement_failure_flag', 'recovery_failure_flag') and not session.recorder.accept:
                    passed = passed and record['after']['enforcement_failed'] is True
                rows.append(dict(scenario=name, trial=trial, step=step, operation=operation,
                                 event_type=value, expected_state=expected,
                                 observed_state=record['after']['state'],
                                 api_runtime_ms=record['api_runtime_ms'], assertion_passed=passed,
                                 enforcement_failed=record['after']['enforcement_failed'],
                                 evidence_level=record['evidence_level'], evidence=str(path / 'trace.json')))
    return rows
