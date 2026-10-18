"""
test_policy_engine.py — Comprehensive unit & integration tests for the
Adaptive Policy Engine (BACSE203 CN Lab).

All tests use ``unittest.mock`` to patch SSHEnforcer so no real switches
are required.  Temporary directories isolate state files between tests.

Run with::

    python -m pytest tests/test_policy_engine.py -v
    # or
    python -m unittest tests.test_policy_engine -v
"""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Make the package importable from the project root
# ---------------------------------------------------------------------------
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from policy_engine.state_manager import StateManager, DEVICES
from policy_engine.threshold_tracker import ThresholdTracker
from policy_engine.recovery_handler import RecoveryHandler
from policy_engine.ssh_enforcer import SSHEnforcer
from policy_engine.policy_engine import PolicyEngine


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------

def _tmp_state_manager() -> tuple:
    """Return (StateManager, tmp_dir) using a fresh temp directory."""
    tmp = tempfile.mkdtemp()
    sm = StateManager(db_path=os.path.join(tmp, "state_db.json"))
    return sm, tmp


def _tmp_tracker() -> tuple:
    """Return (ThresholdTracker, tmp_dir) using a fresh temp directory."""
    tmp = tempfile.mkdtemp()
    tt = ThresholdTracker(db_path=os.path.join(tmp, "events_db.json"))
    return tt, tmp


def _mock_ssh(push_return=True, verify_return=10):
    """Return a MagicMock SSHEnforcer with configurable push/verify returns."""
    mock = MagicMock(spec=SSHEnforcer)
    mock.push_vlan.return_value = push_return
    mock.verify_vlan.return_value = verify_return
    mock.test_connectivity.return_value = True
    return mock


def _engine_with_mock_ssh(tmp_dir: str, push_return=True) -> PolicyEngine:
    """Return a PolicyEngine that uses a mocked SSHEnforcer."""
    mock_ssh = _mock_ssh(push_return=push_return)
    engine = PolicyEngine(
        state_db_path=os.path.join(tmp_dir, "state_db.json"),
        events_db_path=os.path.join(tmp_dir, "events_db.json"),
        ssh_enforcer=mock_ssh,
    )
    return engine


# ===========================================================================
# TestStateManager
# ===========================================================================

class TestStateManager(unittest.TestCase):
    """Tests for StateManager — persistence, state transitions, violation counting."""

    def setUp(self):
        self.sm, self.tmp = _tmp_state_manager()

    # --- initial state ---

    def test_all_devices_initialised_as_normal(self):
        """All 8 registered devices should start in NORMAL state after init."""
        for name in DEVICES:
            rec = self.sm.get_state(name)
            self.assertIsNotNone(rec, f"Missing record for {name}")
            self.assertEqual(rec["state"], "NORMAL")
            self.assertEqual(rec["current_vlan"], rec["home_vlan"])
            self.assertFalse(rec["remediated"])
            self.assertEqual(rec["violation_count"], 0)

    def test_get_state_returns_none_for_unknown_device(self):
        """get_state should return None for an unregistered device name."""
        result = self.sm.get_state("PC-GHOST")
        self.assertIsNone(result)

    # --- set_state ---

    def test_set_state_normal_to_restricted(self):
        """Transitioning NORMAL → RESTRICTED sets vlan=60 and timestamps restricted_since."""
        ok = self.sm.set_state("PC-STU1", "RESTRICTED")
        self.assertTrue(ok)
        rec = self.sm.get_state("PC-STU1")
        self.assertEqual(rec["state"], "RESTRICTED")
        self.assertEqual(rec["current_vlan"], 60)
        self.assertIsNotNone(rec["restricted_since"])
        self.assertIsNone(rec["quarantined_since"])

    def test_set_state_normal_to_quarantine(self):
        """Transitioning NORMAL → QUARANTINE sets vlan=70 and quarantined_since."""
        ok = self.sm.set_state("PC-FAC1", "QUARANTINE")
        self.assertTrue(ok)
        rec = self.sm.get_state("PC-FAC1")
        self.assertEqual(rec["state"], "QUARANTINE")
        self.assertEqual(rec["current_vlan"], 70)
        self.assertIsNotNone(rec["quarantined_since"])

    def test_set_state_back_to_normal_clears_timestamps(self):
        """Recovery to NORMAL should clear restricted_since and quarantined_since."""
        self.sm.set_state("PC-STU1", "RESTRICTED")
        self.sm.set_state("PC-STU1", "NORMAL")
        rec = self.sm.get_state("PC-STU1")
        self.assertEqual(rec["state"], "NORMAL")
        self.assertEqual(rec["current_vlan"], rec["home_vlan"])
        self.assertIsNone(rec["restricted_since"])
        self.assertIsNone(rec["quarantined_since"])
        self.assertFalse(rec["remediated"])

    def test_set_state_invalid_state_returns_false(self):
        """set_state with an invalid state name should return False without changing state."""
        ok = self.sm.set_state("PC-STU1", "INVALID_STATE")
        self.assertFalse(ok)
        rec = self.sm.get_state("PC-STU1")
        self.assertEqual(rec["state"], "NORMAL")

    def test_set_state_unknown_device_returns_false(self):
        """set_state for an unknown device should return False."""
        ok = self.sm.set_state("PC-GHOST", "RESTRICTED")
        self.assertFalse(ok)

    # --- record_violation ---

    def test_record_violation_increments_count(self):
        """record_violation should increment violation_count by 1 each call."""
        self.sm.record_violation("PC-STU1")
        self.sm.record_violation("PC-STU1")
        rec = self.sm.get_state("PC-STU1")
        self.assertEqual(rec["violation_count"], 2)

    def test_record_violation_returns_new_count(self):
        """record_violation should return the updated violation count."""
        c1 = self.sm.record_violation("PC-STU1")
        c2 = self.sm.record_violation("PC-STU1")
        self.assertEqual(c1, 1)
        self.assertEqual(c2, 2)

    def test_record_violation_unknown_device_returns_minus_one(self):
        """record_violation for an unknown device should return -1."""
        result = self.sm.record_violation("PC-GHOST")
        self.assertEqual(result, -1)

    # --- mark_remediated ---

    def test_mark_remediated_sets_flag(self):
        """mark_remediated should set remediated=True in the state record."""
        self.sm.mark_remediated("PC-STU1")
        rec = self.sm.get_state("PC-STU1")
        self.assertTrue(rec["remediated"])

    def test_mark_remediated_unknown_device_returns_false(self):
        """mark_remediated for an unknown device should return False."""
        result = self.sm.mark_remediated("PC-GHOST")
        self.assertFalse(result)

    # --- get_all_devices ---

    def test_get_all_devices_returns_all_eight(self):
        """get_all_devices should return a record for each of the 8 registered devices."""
        all_devices = self.sm.get_all_devices()
        names = {r["device_name"] for r in all_devices}
        self.assertEqual(names, set(DEVICES.keys()))

    # --- persistence ---

    def test_state_persists_across_reload(self):
        """State written by set_state should still be present after reloading from disk."""
        db_path = os.path.join(self.tmp, "state_db.json")
        self.sm.set_state("PC-STU1", "RESTRICTED")
        # Reload from disk
        sm2 = StateManager(db_path=db_path)
        rec = sm2.get_state("PC-STU1")
        self.assertEqual(rec["state"], "RESTRICTED")
        self.assertEqual(rec["current_vlan"], 60)


# ===========================================================================
# TestThresholdTracker
# ===========================================================================

class TestThresholdTracker(unittest.TestCase):
    """Tests for ThresholdTracker — event recording, threshold evaluation."""

    def setUp(self):
        self.tt, self.tmp = _tmp_tracker()

    # --- event recording ---

    def test_record_and_summary_single_event(self):
        """A single auth_failure should appear in get_event_summary."""
        self.tt.record_event("PC-STU1", "auth_failure")
        summary = self.tt.get_event_summary("PC-STU1")
        self.assertEqual(summary["auth_failure"], 1)

    def test_get_event_summary_returns_zero_for_new_device(self):
        """Event summary for a device with no events should return all zeros."""
        summary = self.tt.get_event_summary("PC-RES1")
        for count in summary.values():
            self.assertEqual(count, 0)

    # --- TH-01: auth failure threshold ---

    def test_th01_below_threshold_no_action(self):
        """2 auth_failures (below threshold of 3) should return NO_ACTION."""
        self.tt.record_event("PC-STU1", "auth_failure")
        self.tt.record_event("PC-STU1", "auth_failure")
        action = self.tt.evaluate("PC-STU1", "NORMAL")
        self.assertEqual(action, "NO_ACTION")

    def test_th01_at_threshold_restrict(self):
        """3 auth_failures within the 5-min window should return RESTRICT."""
        for _ in range(3):
            self.tt.record_event("PC-STU1", "auth_failure")
        action = self.tt.evaluate("PC-STU1", "NORMAL")
        self.assertEqual(action, "RESTRICT")

    # --- TH-02: port scan ---

    def test_th02_port_scan_restrict(self):
        """A single port_scan event should return RESTRICT."""
        self.tt.record_event("PC-STU2", "port_scan")
        action = self.tt.evaluate("PC-STU2", "NORMAL")
        self.assertEqual(action, "RESTRICT")

    # --- TH-03: escalation ---

    def test_th03_restricted_plus_violation_escalates(self):
        """
        TH-03: A new violation while RESTRICTED should return ESCALATE.

        We use a port_scan event (threshold = 1 detection) rather than a
        single auth_failure (threshold = 3) so the violation genuinely
        crosses its threshold and triggers the escalation path.
        """
        self.tt.record_event("PC-FAC1", "port_scan")
        action = self.tt.evaluate("PC-FAC1", "RESTRICTED")
        self.assertEqual(action, "ESCALATE")

    # --- TH-04: quarantine stays quarantine ---

    def test_th04_quarantine_new_violation_stays_quarantine(self):
        """A new violation while already QUARANTINE should return QUARANTINE (TH-04)."""
        self.tt.record_event("PC-FAC2", "port_scan")
        action = self.tt.evaluate("PC-FAC2", "QUARANTINE")
        self.assertEqual(action, "QUARANTINE")

    # --- TH-05: cross-VLAN ---

    def test_th05_below_cross_vlan_no_action(self):
        """1 cross_vlan_attempt (below threshold of 2) should return NO_ACTION."""
        self.tt.record_event("PC-ADM1", "cross_vlan_attempt")
        action = self.tt.evaluate("PC-ADM1", "NORMAL")
        self.assertEqual(action, "NO_ACTION")

    def test_th05_at_cross_vlan_restrict(self):
        """2 cross_vlan_attempt events should return RESTRICT."""
        self.tt.record_event("PC-ADM1", "cross_vlan_attempt")
        self.tt.record_event("PC-ADM1", "cross_vlan_attempt")
        action = self.tt.evaluate("PC-ADM1", "NORMAL")
        self.assertEqual(action, "RESTRICT")

    # --- TH-06: spoofing direct quarantine ---

    def test_th06_spoofing_quarantine_directly(self):
        """A spoofing event should return QUARANTINE regardless of current state."""
        self.tt.record_event("PC-RES1", "spoofing")
        action = self.tt.evaluate("PC-RES1", "NORMAL")
        self.assertEqual(action, "QUARANTINE")

    def test_th06_spoofing_overrides_normal_state(self):
        """Spoofing should return QUARANTINE even when device is NORMAL with no other events."""
        self.tt.record_event("PC-RES2", "spoofing")
        action = self.tt.evaluate("PC-RES2", "NORMAL")
        self.assertEqual(action, "QUARANTINE")

    # --- clear_events ---

    def test_clear_events_resets_summary(self):
        """After clear_events, the event summary should return all zeros."""
        for _ in range(3):
            self.tt.record_event("PC-STU1", "auth_failure")
        self.tt.clear_events("PC-STU1")
        summary = self.tt.get_event_summary("PC-STU1")
        self.assertEqual(summary["auth_failure"], 0)

    def test_clear_events_no_action_after_clear(self):
        """After clearing events, evaluate should return NO_ACTION."""
        for _ in range(3):
            self.tt.record_event("PC-STU1", "auth_failure")
        self.tt.clear_events("PC-STU1")
        action = self.tt.evaluate("PC-STU1", "NORMAL")
        self.assertEqual(action, "NO_ACTION")


# ===========================================================================
# TestRecoveryHandler
# ===========================================================================

class TestRecoveryHandler(unittest.TestCase):
    """Tests for RecoveryHandler — manual clear, hold timer logic."""

    def setUp(self):
        self.sm, self.tmp = _tmp_state_manager()
        self.tracker, _ = _tmp_tracker()
        self.rh = RecoveryHandler(threshold_tracker=self.tracker)
        self.mock_ssh = _mock_ssh()

    # --- manual_clear (REC-01) ---

    def test_manual_clear_restores_to_normal(self):
        """manual_clear should immediately restore a RESTRICTED device to NORMAL."""
        self.sm.set_state("PC-STU1", "RESTRICTED")
        ok = self.rh.manual_clear("PC-STU1", self.sm, self.mock_ssh)
        self.assertTrue(ok)
        rec = self.sm.get_state("PC-STU1")
        self.assertEqual(rec["state"], "NORMAL")
        self.mock_ssh.push_vlan.assert_called_once()

    def test_manual_clear_unknown_device_returns_false(self):
        """manual_clear for an unknown device should return False."""
        ok = self.rh.manual_clear("PC-GHOST", self.sm, self.mock_ssh)
        self.assertFalse(ok)
        self.mock_ssh.push_vlan.assert_not_called()

    def test_manual_clear_quarantine_device(self):
        """manual_clear should also work on QUARANTINE devices."""
        self.sm.set_state("PC-FAC1", "QUARANTINE")
        ok = self.rh.manual_clear("PC-FAC1", self.sm, self.mock_ssh)
        self.assertTrue(ok)
        rec = self.sm.get_state("PC-FAC1")
        self.assertEqual(rec["state"], "NORMAL")

    # --- hold timer (REC-02 / REC-03) ---

    def _set_state_in_past(self, device_name: str, state: str, minutes_ago: int) -> None:
        """Helper: set device to *state* and backdate the 'since' timestamp."""
        self.sm.set_state(device_name, state)
        past = (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()
        with self.sm._lock:
            if state == "RESTRICTED":
                self.sm._db[device_name]["restricted_since"] = past
            elif state == "QUARANTINE":
                self.sm._db[device_name]["quarantined_since"] = past
            self.sm._save()

    def test_hold_timer_not_elapsed_no_recovery(self):
        """A device with hold timer not yet elapsed should NOT be recovered."""
        self._set_state_in_past("PC-STU1", "RESTRICTED", minutes_ago=10)  # need 30
        recovered = self.rh.check_and_recover("PC-STU1", self.sm, self.mock_ssh)
        self.assertFalse(recovered)
        rec = self.sm.get_state("PC-STU1")
        self.assertEqual(rec["state"], "RESTRICTED")

    def test_restricted_hold_elapsed_recovers(self):
        """After 30+ minutes RESTRICTED with no new violations, device should recover."""
        self._set_state_in_past("PC-STU1", "RESTRICTED", minutes_ago=31)
        recovered = self.rh.check_and_recover("PC-STU1", self.sm, self.mock_ssh)
        self.assertTrue(recovered)
        rec = self.sm.get_state("PC-STU1")
        self.assertEqual(rec["state"], "NORMAL")

    def test_quarantine_hold_elapsed_recovers(self):
        """After 120+ minutes QUARANTINE with no new violations, device should recover."""
        self._set_state_in_past("PC-FAC1", "QUARANTINE", minutes_ago=121)
        recovered = self.rh.check_and_recover("PC-FAC1", self.sm, self.mock_ssh)
        self.assertTrue(recovered)
        rec = self.sm.get_state("PC-FAC1")
        self.assertEqual(rec["state"], "NORMAL")

    def test_hold_elapsed_but_recent_violations_blocks_recovery(self):
        """
        If hold timer has elapsed but there are recent violations (within 10 min),
        auto-recovery should be blocked.
        """
        self._set_state_in_past("PC-STU2", "RESTRICTED", minutes_ago=31)
        # Inject a fresh violation
        self.tracker.record_event("PC-STU2", "auth_failure")
        recovered = self.rh.check_and_recover("PC-STU2", self.sm, self.mock_ssh)
        self.assertFalse(recovered)

    def test_remediated_flag_bypasses_violation_block(self):
        """
        remediated=True should allow recovery even if there are recent violations,
        as long as the hold timer has elapsed.
        """
        self._set_state_in_past("PC-STU2", "RESTRICTED", minutes_ago=31)
        self.tracker.record_event("PC-STU2", "auth_failure")  # would normally block
        self.sm.mark_remediated("PC-STU2")
        recovered = self.rh.check_and_recover("PC-STU2", self.sm, self.mock_ssh)
        self.assertTrue(recovered)

    def test_normal_device_skipped_in_sweep(self):
        """run_recovery_sweep should not touch devices already in NORMAL state."""
        count = self.rh.run_recovery_sweep(self.sm, self.mock_ssh)
        self.assertEqual(count, 0)
        self.mock_ssh.push_vlan.assert_not_called()

    def test_mark_remediated_helper(self):
        """mark_remediated via RecoveryHandler should set the flag in StateManager."""
        self.rh.mark_remediated("PC-STU1", self.sm)
        rec = self.sm.get_state("PC-STU1")
        self.assertTrue(rec["remediated"])


# ===========================================================================
# TestPolicyEngine  (end-to-end with mocked SSH)
# ===========================================================================

class TestPolicyEngine(unittest.TestCase):
    """
    Integration tests for PolicyEngine with a mocked SSHEnforcer.

    All SSH calls are intercepted by MagicMock so tests run without
    real network access.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.mock_ssh = _mock_ssh()
        self.engine = PolicyEngine(
            state_db_path=os.path.join(self.tmp, "state_db.json"),
            events_db_path=os.path.join(self.tmp, "events_db.json"),
            ssh_enforcer=self.mock_ssh,
        )

    # ------------------------------------------------------------------
    # Helper: backdate a since-timestamp in the state file
    # ------------------------------------------------------------------

    def _backdate(self, device_name: str, state: str, minutes_ago: int) -> None:
        past = (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()
        sm = self.engine.state_manager
        with sm._lock:
            if state == "RESTRICTED":
                sm._db[device_name]["restricted_since"] = past
            elif state == "QUARANTINE":
                sm._db[device_name]["quarantined_since"] = past
            sm._save()

    # ------------------------------------------------------------------
    # TH-01 / TH-03 flow
    # ------------------------------------------------------------------

    def test_normal_to_restricted_via_auth_failures(self):
        """
        TH-01: Injecting 3 auth_failure events for a NORMAL device should
        trigger a RESTRICT action and move the device to RESTRICTED.
        """
        for _ in range(3):
            self.engine.handle_event("PC-STU1", "auth_failure")
        rec = self.engine.state_manager.get_state("PC-STU1")
        self.assertEqual(rec["state"], "RESTRICTED")
        self.assertEqual(rec["current_vlan"], 60)
        # SSH push must have been called with the RESTRICTED VLAN
        self.mock_ssh.push_vlan.assert_called()
        last_call = self.mock_ssh.push_vlan.call_args
        self.assertEqual(last_call.args[2], 60)

    def test_restricted_to_quarantine_escalation(self):
        """
        TH-03: A device already RESTRICTED that receives another violation
        should escalate to QUARANTINE.
        """
        # Force into RESTRICTED state directly via StateManager (avoid TH-01 counting)
        self.engine.state_manager.set_state("PC-STU1", "RESTRICTED")
        self.engine.threshold_tracker.record_event("PC-STU1", "port_scan")
        action = self.engine.handle_event("PC-STU1", "policy_violation")
        rec = self.engine.state_manager.get_state("PC-STU1")
        self.assertEqual(rec["state"], "QUARANTINE")
        self.assertEqual(rec["current_vlan"], 70)

    # ------------------------------------------------------------------
    # TH-06
    # ------------------------------------------------------------------

    def test_spoofing_directly_quarantines(self):
        """
        TH-06: A spoofing event for a NORMAL device should quarantine it
        directly without going through RESTRICTED first.
        """
        action = self.engine.handle_event("PC-FAC1", "spoofing")
        rec = self.engine.state_manager.get_state("PC-FAC1")
        self.assertEqual(rec["state"], "QUARANTINE")
        self.assertEqual(rec["current_vlan"], 70)
        self.assertEqual(action, "QUARANTINE")

    # ------------------------------------------------------------------
    # TH-07
    # ------------------------------------------------------------------

    def test_manual_override_to_quarantine(self):
        """
        TH-07: enforce_state should push the QUARANTINE VLAN regardless
        of threshold state and update StateManager.
        """
        ok = self.engine.enforce_state("PC-ADM1", "QUARANTINE", reason="MANUAL_OVERRIDE")
        self.assertTrue(ok)
        rec = self.engine.state_manager.get_state("PC-ADM1")
        self.assertEqual(rec["state"], "QUARANTINE")
        self.mock_ssh.push_vlan.assert_called_once_with(
            rec["switch_ip"], rec["port"], 70
        )

    def test_manual_override_to_normal(self):
        """
        TH-07: enforce_state to NORMAL should restore the home VLAN.
        """
        self.engine.state_manager.set_state("PC-ADM1", "RESTRICTED")
        home = self.engine.state_manager.get_state("PC-ADM1")["home_vlan"]
        ok = self.engine.enforce_state("PC-ADM1", "NORMAL", reason="ADMIN_RESTORE")
        self.assertTrue(ok)
        rec = self.engine.state_manager.get_state("PC-ADM1")
        self.assertEqual(rec["state"], "NORMAL")
        self.mock_ssh.push_vlan.assert_called_once()
        self.assertEqual(self.mock_ssh.push_vlan.call_args.args[2], home)

    # ------------------------------------------------------------------
    # REC-01
    # ------------------------------------------------------------------

    def test_manual_clear_restores_normal(self):
        """
        REC-01: manual_clear on a QUARANTINE device should immediately
        restore it to NORMAL and push the home VLAN.
        """
        self.engine.state_manager.set_state("PC-RES1", "QUARANTINE")
        ok = self.engine.manual_clear("PC-RES1")
        self.assertTrue(ok)
        rec = self.engine.state_manager.get_state("PC-RES1")
        self.assertEqual(rec["state"], "NORMAL")
        self.assertEqual(rec["current_vlan"], rec["home_vlan"])

    # ------------------------------------------------------------------
    # REC-02 / recovery sweep
    # ------------------------------------------------------------------

    def test_recovery_sweep_restores_after_hold(self):
        """
        REC-02: A device that has been RESTRICTED for 31 minutes with no
        new violations should be restored to NORMAL by run_recovery_sweep.
        """
        self.engine.state_manager.set_state("PC-STU2", "RESTRICTED")
        self._backdate("PC-STU2", "RESTRICTED", minutes_ago=31)
        count = self.engine.run_recovery_sweep()
        self.assertGreaterEqual(count, 1)
        rec = self.engine.state_manager.get_state("PC-STU2")
        self.assertEqual(rec["state"], "NORMAL")

    def test_recovery_sweep_does_not_restore_before_hold(self):
        """
        A device that has been RESTRICTED for only 10 minutes should NOT be
        recovered by the sweep (hold timer = 30 min for RESTRICTED).
        """
        self.engine.state_manager.set_state("PC-STU2", "RESTRICTED")
        self._backdate("PC-STU2", "RESTRICTED", minutes_ago=10)
        count = self.engine.run_recovery_sweep()
        self.assertEqual(count, 0)
        rec = self.engine.state_manager.get_state("PC-STU2")
        self.assertEqual(rec["state"], "RESTRICTED")

    # ------------------------------------------------------------------
    # Below-threshold no-action
    # ------------------------------------------------------------------

    def test_no_action_below_threshold(self):
        """
        Fewer than 3 auth_failures should not trigger any enforcement action,
        and the device should remain NORMAL.
        """
        self.engine.handle_event("PC-FAC2", "auth_failure")
        self.engine.handle_event("PC-FAC2", "auth_failure")
        rec = self.engine.state_manager.get_state("PC-FAC2")
        self.assertEqual(rec["state"], "NORMAL")
        self.mock_ssh.push_vlan.assert_not_called()

    # ------------------------------------------------------------------
    # TH-04: quarantine stays quarantine
    # ------------------------------------------------------------------

    def test_th04_quarantine_new_violation_stays_quarantine(self):
        """
        TH-04: A device already in QUARANTINE that receives a new violation
        should remain QUARANTINE (no change), but the violation should be logged.
        """
        self.engine.state_manager.set_state("PC-RES2", "QUARANTINE")
        action = self.engine.handle_event("PC-RES2", "port_scan")
        self.assertEqual(action, "LOGGED_QUARANTINE")
        rec = self.engine.state_manager.get_state("PC-RES2")
        self.assertEqual(rec["state"], "QUARANTINE")

    # ------------------------------------------------------------------
    # SSH failure handling
    # ------------------------------------------------------------------

    def test_ssh_failure_still_updates_state(self):
        """
        If SSH enforcement fails, the engine should still update StateManager
        (with enforcement_failed=True) and not raise an exception.
        """
        self.mock_ssh.push_vlan.return_value = False  # simulate SSH failure
        for _ in range(3):
            self.engine.handle_event("PC-STU1", "auth_failure")
        rec = self.engine.state_manager.get_state("PC-STU1")
        # State should still be updated even if SSH failed
        self.assertEqual(rec["state"], "RESTRICTED")
        self.assertTrue(rec["enforcement_failed"])

    # ------------------------------------------------------------------
    # get_status (smoke test — just check it doesn't raise)
    # ------------------------------------------------------------------

    def test_get_status_does_not_raise(self):
        """get_status should print the status table without raising any exception."""
        try:
            self.engine.get_status()
        except Exception as exc:
            self.fail(f"get_status raised an exception: {exc}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
