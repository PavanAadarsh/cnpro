import unittest
import socket
import time
from unittest.mock import MagicMock
from policy_engine.event_listener import AutoEventListener
from policy_engine.state_manager import StateManager
from policy_engine.policy_engine import PolicyEngine

class TestEventListenerAndReconciliation(unittest.TestCase):
    def setUp(self):
        self.mock_engine = MagicMock(spec=PolicyEngine)
        self.listener = AutoEventListener(self.mock_engine, syslog_port=10514, recovery_interval_sec=1)

    def test_parse_cisco_acl_syslog(self):
        msg = "%SEC-6-IPACCESSLOGP: list ACL-STU-IN denied 192.168.10.100 -> 192.168.50.10"
        parsed = self.listener.parse_syslog_message(msg)
        self.assertIsNotNone(parsed)
        dev, ev = parsed
        self.assertEqual(dev, "PC-STU1")
        self.assertEqual(ev, "policy_violation")

    def test_parse_auth_failure_syslog(self):
        msg = "%SEC-6-IPACCESSLOGP: list ACL-STU-IN denied tcp 192.168.10.100 -> 192.168.50.10 authentication failure"
        parsed = self.listener.parse_syslog_message(msg)
        self.assertIsNotNone(parsed)
        dev, ev = parsed
        self.assertEqual(dev, "PC-STU1")
        self.assertEqual(ev, "auth_failure")

    def test_parse_sim_event_string(self):
        msg = "SIM_EVENT:PC-FAC1:port_scan"
        parsed = self.listener.parse_syslog_message(msg)
        self.assertEqual(parsed, ("PC-FAC1", "port_scan"))

    def test_remediation_recovers_after_hold_timer_elapsed(self):
        """Verify that when hold timer has elapsed, remediated=True allows recovery."""
        from policy_engine.recovery_handler import RecoveryHandler
        rh = RecoveryHandler()
        state = {
            "device_name": "PC-STU1",
            "state": "QUARANTINE",
            "home_vlan": 10,
            "switch_ip": "192.168.40.21",
            "port": "Fa0/1",
            "quarantined_since": "2026-01-01T00:00:00Z",
            "remediated": True
        }
        sm = MagicMock()
        sm.get_state.return_value = state
        ssh = MagicMock()
        ssh.push_vlan.return_value = True
        ssh.verify_vlan.return_value = 10

        res = rh.check_and_recover("PC-STU1", sm, ssh)
        self.assertTrue(res)
        ssh.push_vlan.assert_called_with("192.168.40.21", "Fa0/1", 10)

    def test_remediation_cannot_bypass_unexpired_hold_timer(self):
        """Verify that remediation cannot recover a device if hold timer has not elapsed."""
        from datetime import datetime, timezone, timedelta
        from policy_engine.recovery_handler import RecoveryHandler
        rh = RecoveryHandler()
        unexpired_since = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        state = {
            "device_name": "PC-STU1",
            "state": "QUARANTINE",
            "home_vlan": 10,
            "switch_ip": "192.168.40.21",
            "port": "Fa0/1",
            "quarantined_since": unexpired_since,
            "remediated": True
        }
        sm = MagicMock()
        sm.get_state.return_value = state
        ssh = MagicMock()
        ssh.push_vlan.return_value = True
        ssh.verify_vlan.return_value = 10

        res = rh.check_and_recover("PC-STU1", sm, ssh)
        self.assertFalse(res)
        ssh.push_vlan.assert_not_called()

if __name__ == "__main__":
    unittest.main()
