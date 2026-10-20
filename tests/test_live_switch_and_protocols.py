"""
test_live_switch_and_protocols.py — Automated verification of NetFlow v5 parser,
Syslog ingestion, quarantine timer restarts, and strict hold-timer compliance.
"""

import socket
import struct
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

from policy_engine.event_listener import AutoEventListener
from policy_engine.policy_engine import PolicyEngine
from policy_engine.recovery_handler import RecoveryHandler
from policy_engine.state_manager import StateManager
from policy_engine.threshold_tracker import ThresholdTracker


class TestLiveProtocolsAndReconciliation(unittest.TestCase):
    def setUp(self):
        self.mock_engine = MagicMock(spec=PolicyEngine)
        self.listener = AutoEventListener(
            self.mock_engine, syslog_port=10514, netflow_port=12055, recovery_interval_sec=1
        )

    def test_netflow_v5_binary_parser(self):
        """Verify binary Cisco NetFlow v5 packet parsing with flow heuristics."""
        # Netflow Header: version=5, count=1, SysUptime=1000, unix_secs=1600000000, unix_nsecs=0, seq=1, eng_type=0, eng_id=0, sampling=0
        header = struct.pack("!HHIIIIBBH", 5, 1, 1000, 1600000000, 0, 1, 0, 0, 0)
        # Flow Record: src=192.168.10.100, dst=192.168.50.10, nexthop=192.168.10.1, in=1, out=2, dPkts=100, dOctets=6400,
        # first=100, last=200, srcport=5000, dstport=80, pad=0, tcp_flags=2 (SYN), prot=6 (TCP), tos=0, src_as=0, dst_as=0, src_mask=24, dst_mask=24, pad2=0
        src_ip_bytes = socket.inet_aton("192.168.10.100")
        dst_ip_bytes = socket.inet_aton("192.168.50.10")
        nexthop_bytes = socket.inet_aton("192.168.10.1")
        record = struct.pack(
            "!4s4s4sHHIIIIHHBBBBHHBBH",
            src_ip_bytes,
            dst_ip_bytes,
            nexthop_bytes,
            1,
            2,
            100,
            6400,
            100,
            200,
            5000,
            80,
            0,
            2,
            6,
            0,
            0,
            0,
            24,
            24,
            0,
        )
        packet = header + record
        events = self.listener.parse_netflow_v5_packet(packet)
        self.assertEqual(len(events), 1)
        device, ev = events[0]
        self.assertEqual(device, "PC-STU1")
        self.assertEqual(ev, "port_scan")

    def test_remediation_does_not_bypass_hold_period(self):
        """Verify that remediated=True does NOT bypass an unexpired hold period."""
        rh = RecoveryHandler()
        # Hold timer is 120m for QUARANTINE; set quarantined_since to 5 minutes ago (unexpired)
        unexpired_since = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        state = {
            "device_name": "PC-STU1",
            "state": "QUARANTINE",
            "home_vlan": 10,
            "switch_ip": "192.168.40.21",
            "port": "Fa0/1",
            "quarantined_since": unexpired_since,
            "remediated": True,
        }
        sm = MagicMock()
        sm.get_state.return_value = state
        ssh = MagicMock()
        ssh.push_vlan.return_value = True
        ssh.verify_vlan.return_value = 10

        res = rh.check_and_recover("PC-STU1", sm, ssh)
        # MUST return False because hold period has NOT elapsed!
        self.assertFalse(res)
        ssh.push_vlan.assert_not_called()

    def test_remediation_recovers_after_hold_period_elapses(self):
        """Verify that when hold period elapses AND remediated=True, recovery succeeds."""
        rh = RecoveryHandler()
        # Hold timer elapsed 125 minutes ago
        expired_since = (datetime.now(timezone.utc) - timedelta(minutes=125)).isoformat()
        state = {
            "device_name": "PC-STU1",
            "state": "QUARANTINE",
            "home_vlan": 10,
            "switch_ip": "192.168.40.21",
            "port": "Fa0/1",
            "quarantined_since": expired_since,
            "remediated": True,
        }
        sm = MagicMock()
        sm.get_state.return_value = state
        ssh = MagicMock()
        ssh.push_vlan.return_value = True
        ssh.verify_vlan.return_value = 10

        res = rh.check_and_recover("PC-STU1", sm, ssh)
        self.assertTrue(res)
        ssh.push_vlan.assert_called_with("192.168.40.21", "Fa0/1", 10)

    def test_quarantine_timer_restart_on_all_violations(self):
        """Verify that all subsequent violations while in QUARANTINE restart the timer."""
        sm = MagicMock(spec=StateManager)
        tt = MagicMock(spec=ThresholdTracker)
        ssh = MagicMock()
        pe = PolicyEngine(ssh_enforcer=ssh)
        pe.state_manager = sm
        pe.threshold_tracker = tt

        # Device is in QUARANTINE
        sm.get_state.return_value = {
            "device_name": "PC-FAC1",
            "state": "QUARANTINE",
            "switch_ip": "192.168.40.21",
            "port": "Fa0/3",
            "home_vlan": 20,
        }
        tt.evaluate.return_value = "QUARANTINE"

        action = pe.handle_event("PC-FAC1", "policy_violation")
        self.assertEqual(action, "LOGGED_QUARANTINE")
        sm.restart_quarantine_timer.assert_called_with("PC-FAC1")


if __name__ == "__main__":
    unittest.main()
