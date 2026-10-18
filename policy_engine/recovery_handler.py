"""
recovery_handler.py — Hold-timer based recovery of restricted/quarantined devices.

Recovery rules from the BACSE203 CN Lab specification:

REC-01  Manual admin clear → immediate restore to NORMAL (any state).
REC-02  RESTRICTED → NORMAL after 30-minute hold with no new violations.
REC-03  QUARANTINE → NORMAL after 2-hour hold with no new violations.
REC-04  SRV-REMEDIATE acknowledges clearance (sets remediated flag); the next
        sweep restores NORMAL regardless of whether violations occurred.

A device must satisfy BOTH conditions to recover automatically:
1. Hold timer has elapsed since entering the restricted/quarantined state.
2. No new violations in the last 10 minutes  OR  remediated=True.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# Hold timers (seconds)
RESTRICTED_HOLD_SEC = 30 * 60    # 30 minutes   (REC-02)
QUARANTINE_HOLD_SEC = 120 * 60   # 120 minutes  (REC-03)

# No-violation window: events in the last N seconds block auto-recovery
NO_VIOLATION_WINDOW_SEC = 600    # 10 minutes


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RecoveryHandler:
    """
    Evaluates hold timers and violation windows to decide whether a
    RESTRICTED or QUARANTINED device can be returned to NORMAL.

    Parameters
    ----------
    threshold_tracker : ThresholdTracker
        Used to check whether any new violations have arrived within the
        no-violation window before granting automatic recovery.
    """

    def __init__(self, threshold_tracker=None) -> None:
        # threshold_tracker injected to avoid circular imports at module level
        self._tracker = threshold_tracker

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _hold_elapsed(self, state_record: dict) -> bool:
        """
        Return True if the required hold timer has elapsed for *state_record*.

        Reads ``restricted_since`` or ``quarantined_since`` from the record
        and compares to the appropriate constant.
        """
        state = state_record.get("state")

        if state == "RESTRICTED":
            since_str = state_record.get("restricted_since")
            hold = RESTRICTED_HOLD_SEC
        elif state == "QUARANTINE":
            since_str = state_record.get("quarantined_since")
            hold = QUARANTINE_HOLD_SEC
        else:
            return False   # NORMAL devices don't need recovery

        if since_str is None:
            logger.warning("RecoveryHandler: %s has no since-timestamp; hold not elapsed",
                           state_record.get("device_name", "?"))
            return False

        since = datetime.fromisoformat(since_str)
        elapsed = (_utcnow() - since).total_seconds()
        logger.debug("RecoveryHandler: %s elapsed=%.0fs / hold=%ds",
                     state_record.get("device_name", "?"), elapsed, hold)
        return elapsed >= hold

    def _no_recent_violations(self, device_name: str) -> bool:
        """
        Return True if the ThresholdTracker shows no events in the last
        NO_VIOLATION_WINDOW_SEC seconds for *device_name*.

        If no tracker is attached, defaults to True (safe for tests).
        """
        if self._tracker is None:
            return True
        summary = self._tracker.get_event_summary(device_name)
        return all(count == 0 for count in summary.values())

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_and_recover(
        self,
        device_name: str,
        state_manager,
        ssh_enforcer,
    ) -> bool:
        """
        Check whether *device_name* is eligible for automatic recovery and,
        if so, push the home VLAN via SSH and update the state.

        Eligibility (REC-02 / REC-03):
        - Hold timer has elapsed.
        - No new violations in the last 10 min  OR  remediated=True.

        Returns True if recovery was attempted (regardless of SSH outcome).
        """
        record = state_manager.get_state(device_name)
        if record is None:
            logger.warning("RecoveryHandler: unknown device '%s'", device_name)
            return False

        state = record.get("state")
        if state == "NORMAL":
            return False   # nothing to do

        remediated = record.get("remediated", False)
        hold_ok = self._hold_elapsed(record)
        no_viols = self._no_recent_violations(device_name)

        logger.debug(
            "RecoveryHandler: %s  state=%s  hold_ok=%s  no_viols=%s  remediated=%s",
            device_name, state, hold_ok, no_viols, remediated,
        )

        if hold_ok and (no_viols or remediated):
            return self._do_recover(device_name, record, state_manager, ssh_enforcer, reason="AUTO")
        return False

    def manual_clear(
        self,
        device_name: str,
        state_manager,
        ssh_enforcer,
    ) -> bool:
        """
        Immediately restore *device_name* to NORMAL (REC-01 — admin clear).

        Bypasses hold timers and violation windows.  Clears event history
        so the device starts with a clean slate.

        Returns True if the SSH push was successful.
        """
        record = state_manager.get_state(device_name)
        if record is None:
            logger.warning("RecoveryHandler.manual_clear: unknown device '%s'", device_name)
            return False

        logger.info("RecoveryHandler: REC-01 manual clear for %s", device_name)
        return self._do_recover(device_name, record, state_manager, ssh_enforcer, reason="MANUAL_CLEAR")

    def mark_remediated(self, device_name: str, state_manager) -> bool:
        """
        Set the remediated flag for *device_name* (REC-04).

        The next ``run_recovery_sweep`` will restore the device to NORMAL
        if the hold timer has also elapsed.

        Returns True on success.
        """
        result = state_manager.mark_remediated(device_name)
        if result:
            logger.info("RecoveryHandler: REC-04 remediated flag set for %s", device_name)
        return result

    def run_recovery_sweep(self, state_manager, ssh_enforcer) -> int:
        """
        Iterate over all non-NORMAL devices and attempt automatic recovery.

        Returns the number of devices successfully recovered in this sweep.
        """
        all_devices = state_manager.get_all_devices()
        recovered = 0
        for record in all_devices:
            name = record.get("device_name")
            if record.get("state") != "NORMAL":
                if self.check_and_recover(name, state_manager, ssh_enforcer):
                    recovered += 1
        logger.info("RecoveryHandler: sweep complete — %d device(s) recovered", recovered)
        return recovered

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _do_recover(
        self,
        device_name: str,
        record: dict,
        state_manager,
        ssh_enforcer,
        reason: str,
    ) -> bool:
        """
        Push home VLAN, update state to NORMAL, clear events.

        Returns True if SSH enforcement succeeded.
        """
        home_vlan = record.get("home_vlan", 0)
        switch_ip = record.get("switch_ip", "")
        port = record.get("port", "")

        logger.info(
            "RecoveryHandler: recovering %s → NORMAL (vlan=%d, switch=%s, port=%s, reason=%s)",
            device_name, home_vlan, switch_ip, port, reason,
        )

        ssh_ok = ssh_enforcer.push_vlan(switch_ip, port, home_vlan)
        state_manager.set_state(device_name, "NORMAL", enforcement_failed=not ssh_ok)

        if self._tracker is not None:
            self._tracker.clear_events(device_name)

        if not ssh_ok:
            logger.error(
                "RecoveryHandler: SSH enforcement failed for %s during recovery; "
                "state set to NORMAL but switch port may still be on restricted VLAN.",
                device_name,
            )
        return ssh_ok
