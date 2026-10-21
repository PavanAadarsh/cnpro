"""
policy_engine.py — Main controller for the Adaptive Policy Engine.

The PolicyEngine composes the four sub-components:

  StateManager      — persists device states (NORMAL / RESTRICTED / QUARANTINE)
  ThresholdTracker  — evaluates TH-01 … TH-07 against incoming security events
  SSHEnforcer       — pushes switchport VLAN changes to Cisco IOS switches via SSH
  RecoveryHandler   — manages hold timers and automatic / manual recovery

Typical usage::

    from policy_engine import PolicyEngine

    engine = PolicyEngine()
    engine.handle_event("PC-STU1", "auth_failure")   # injects an event
    engine.get_status()                               # prints current table
    engine.run_recovery_sweep()                       # checks hold timers

All state is persisted to JSON files so the engine can be restarted safely.
"""

import logging
import sys
from datetime import datetime, timezone
from typing import Optional

from .state_manager import StateManager, DEVICES
from .threshold_tracker import ThresholdTracker
from .ssh_enforcer import SSHEnforcer
from .recovery_handler import RecoveryHandler

logger = logging.getLogger(__name__)

VLAN_NAMES = {
    10: "STUDENT",
    20: "FACULTY",
    30: "RESEARCH",
    40: "ADMIN",
    60: "RESTRICTED",
    70: "QUARANTINE",
}


def _ts() -> str:
    """Return a short UTC timestamp string for log lines."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class PolicyEngine:
    """
    Main controller for the BACSE203 CN Lab Adaptive Policy Engine.

    Composes StateManager, ThresholdTracker, SSHEnforcer, and RecoveryHandler.

    Parameters
    ----------
    state_db_path  : str   Path to state persistence file (default: 'state_db.json').
    events_db_path : str   Path to events persistence file (default: 'events_db.json').
    ssh_username   : str   SSH username for switches (default: 'admin').
    ssh_password   : str   SSH password for switches (default: 'Admin@123').
    ssh_enforcer   : SSHEnforcer or None
        If provided, uses this instance instead of creating a new one.
        Useful for testing with a mocked enforcer.
    """

    def __init__(
        self,
        state_db_path: str = "state_db.json",
        events_db_path: str = "events_db.json",
        ssh_username: str = "admin",
        ssh_password: str = "Admin@123",
        ssh_enforcer: Optional[SSHEnforcer] = None,
    ) -> None:
        logger.info("PolicyEngine: initialising …")
        self.state_manager = StateManager(db_path=state_db_path)
        self.threshold_tracker = ThresholdTracker(db_path=events_db_path)
        self.ssh_enforcer = ssh_enforcer or SSHEnforcer(
            username=ssh_username,
            password=ssh_password,
        )
        self.recovery_handler = RecoveryHandler(threshold_tracker=self.threshold_tracker)
        logger.info("PolicyEngine: ready — %d devices loaded", len(DEVICES))

    # ------------------------------------------------------------------
    # Core event handling
    # ------------------------------------------------------------------

    def handle_event(self, device_name: str, event_type: str) -> str:
        """
        Process a security event for *device_name* and enforce policy.

        Steps:
        1. Record the event in ThresholdTracker.
        2. Record a violation in StateManager.
        3. Evaluate thresholds against current state.
        4. If action required: push VLAN via SSHEnforcer and update StateManager.
        5. Log every step.

        Parameters
        ----------
        device_name : str   Registered device identifier (e.g. 'PC-STU1').
        event_type  : str   One of: auth_failure, port_scan, cross_vlan_attempt,
                            spoofing, policy_violation.

        Returns the action taken: 'NO_ACTION', 'RESTRICT', 'ESCALATE',
        'QUARANTINE', or 'LOGGED_QUARANTINE' (TH-04 already QUARANTINE).
        """
        ts = _ts()

        record = self.state_manager.get_state(device_name)
        if record is None:
            logger.error("[%s] handle_event: unknown device '%s'", ts, device_name)
            print(f"[{ts}] ERROR: unknown device '{device_name}'")
            return "ERROR"

        current_state = record["state"]
        print(f"[{ts}] EVENT  device={device_name}  event={event_type}  state={current_state}")
        logger.info("[%s] EVENT  device=%s  event=%s  state=%s", ts, device_name, event_type, current_state)

        # Record event and violation
        self.threshold_tracker.record_event(device_name, event_type)
        self.state_manager.record_violation(device_name)

        # Evaluate
        action = self.threshold_tracker.evaluate(device_name, current_state)
        print(f"[{ts}] EVAL   device={device_name}  action={action}")
        logger.info("[%s] EVAL   device=%s  action=%s", ts, device_name, action)

        # TH-04: already QUARANTINE with new violation — log, restart hold timer, no escalation
        if action == "QUARANTINE" and current_state == "QUARANTINE":
            self.state_manager.restart_quarantine_timer(device_name)
            msg = f"[{ts}] TH-04  device={device_name}  stays QUARANTINE (new violation logged, quarantine hold timer restarted)"
            print(msg)
            logger.warning(msg)
            return "LOGGED_QUARANTINE"

        if action == "NO_ACTION":
            print(f"[{ts}] OK     device={device_name}  no threshold breached")
            return "NO_ACTION"

        # Determine target state
        if action in ("QUARANTINE", "ESCALATE"):
            target_state = "QUARANTINE"
            target_vlan = 70
        else:  # RESTRICT
            target_state = "RESTRICTED"
            target_vlan = 60

        # Push to switch
        switch_ip = record["switch_ip"]
        port = record["port"]
        ssh_ok = self.ssh_enforcer.push_vlan(switch_ip, port, target_vlan)

        # Update state
        self.state_manager.set_state(device_name, target_state, enforcement_failed=not ssh_ok)

        result_str = "OK" if ssh_ok else "SSH_FAILED"
        msg = (
            f"[{ts}] ACTION device={device_name}  {current_state}→{target_state}"
            f"  vlan={target_vlan}  switch={switch_ip}  port={port}"
            f"  reason={event_type}  ssh={result_str}"
        )
        print(msg)
        logger.info(msg)

        return action

    # ------------------------------------------------------------------
    # Manual override (TH-07)
    # ------------------------------------------------------------------

    def enforce_state(self, device_name: str, target_state: str, reason: str = "MANUAL_OVERRIDE") -> bool:
        """
        Directly set *device_name* to *target_state* (TH-07 manual override).

        This bypasses threshold evaluation and immediately pushes the
        appropriate VLAN via SSH.

        Parameters
        ----------
        device_name  : str  Registered device (e.g. 'PC-STU1').
        target_state : str  One of NORMAL, RESTRICTED, QUARANTINE.
        reason       : str  Audit reason string (default: 'MANUAL_OVERRIDE').

        Returns True if SSH enforcement succeeded.
        """
        ts = _ts()
        record = self.state_manager.get_state(device_name)
        if record is None:
            logger.error("[%s] enforce_state: unknown device '%s'", ts, device_name)
            print(f"[{ts}] ERROR: unknown device '{device_name}'")
            return False

        if target_state not in ("NORMAL", "RESTRICTED", "QUARANTINE"):
            print(f"[{ts}] ERROR: invalid target state '{target_state}'")
            return False

        vlan_map = {"NORMAL": record["home_vlan"], "RESTRICTED": 60, "QUARANTINE": 70}
        target_vlan = vlan_map[target_state]
        switch_ip = record["switch_ip"]
        port = record["port"]

        ssh_ok = self.ssh_enforcer.push_vlan(switch_ip, port, target_vlan)
        self.state_manager.set_state(device_name, target_state, enforcement_failed=not ssh_ok)

        result_str = "OK" if ssh_ok else "SSH_FAILED"
        msg = (
            f"[{ts}] TH-07  device={device_name}  →{target_state}"
            f"  vlan={target_vlan}  reason={reason}  ssh={result_str}"
        )
        print(msg)
        logger.info(msg)
        return ssh_ok

    # ------------------------------------------------------------------
    # Status display
    # ------------------------------------------------------------------

    def get_status(self) -> None:
        """
        Pretty-print the current state of all registered devices to stdout.

        Columns: Device | State | VLAN | Switch | Port | Violations | Since
        """
        devices = self.state_manager.get_all_devices()
        # Header
        header = f"{'Device':<12} {'State':<12} {'VLAN':<6} {'Switch':<14} {'Port':<18} {'Viols':>5}  Since"
        print("\n" + "=" * len(header))
        print(header)
        print("=" * len(header))
        for rec in sorted(devices, key=lambda r: r["device_name"]):
            state = rec["state"]
            vlan = rec["current_vlan"]
            vlan_label = VLAN_NAMES.get(vlan, str(vlan))
            since = rec.get("restricted_since") or rec.get("quarantined_since") or "-"
            if since != "-" and len(since) > 19:
                since = since[:19] + "Z"
            print(
                f"{rec['device_name']:<12} {state:<12} {vlan:<6} {rec['switch']:<14} "
                f"{rec['port']:<18} {rec['violation_count']:>5}  {since}"
            )
        print("=" * len(header) + "\n")

    # ------------------------------------------------------------------
    # Recovery sweep
    # ------------------------------------------------------------------

    def run_recovery_sweep(self) -> int:
        """
        Delegate a recovery sweep to RecoveryHandler.

        Checks all non-NORMAL devices and restores them to NORMAL if their
        hold timers have elapsed and no new violations have occurred.

        Returns the number of devices recovered.
        """
        ts = _ts()
        print(f"[{ts}] SWEEP  starting recovery sweep …")
        count = self.recovery_handler.run_recovery_sweep(self.state_manager, self.ssh_enforcer)
        print(f"[{ts}] SWEEP  complete — {count} device(s) recovered")
        return count

    # ------------------------------------------------------------------
    # Convenience wrappers
    # ------------------------------------------------------------------

    def manual_clear(self, device_name: str) -> bool:
        """
        Manually clear *device_name* back to NORMAL (REC-01).

        Returns True if SSH enforcement succeeded.
        """
        return self.recovery_handler.manual_clear(device_name, self.state_manager, self.ssh_enforcer)

    def mark_remediated(self, device_name: str) -> bool:
        """
        Mark *device_name* as remediated (REC-04).

        The next recovery sweep will restore it to NORMAL.
        """
        return self.recovery_handler.mark_remediated(device_name, self.state_manager)
