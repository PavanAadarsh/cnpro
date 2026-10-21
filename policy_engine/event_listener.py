"""
event_listener.py — Live Syslog & NetFlow v5 event collector for Adaptive Policy Engine.

Operates as a background UDP service on POLICY-HOST (192.168.40.50):
- UDP Port 514: Syslog collector for Cisco IOS ACL deny logs (%SEC-6-IPACCESSLOGP)
- UDP Port 2055: NetFlow v5 packet receiver & parser for high-rate flow anomalies
- Autonomous background recovery worker executing hold-timer evaluations

Reconciliation Rules:
- Remediation does NOT bypass hold period: hold timer MUST elapse AND (no recent violations OR remediated=True).
- Quarantine violations restart the quarantine hold timer.
"""

import json
import logging
import os
import re
import socket
import struct
import threading
import time
from typing import Optional, Tuple, List, Dict

logger = logging.getLogger(__name__)

IP_TO_DEVICE_MAP = {
    "192.168.10.100": "PC-STU1",
    "192.168.10.101": "PC-STU2",
    "192.168.20.100": "PC-FAC1",
    "192.168.20.101": "PC-FAC2",
    "192.168.40.100": "PC-ADM1",
    "192.168.40.101": "PC-ADM2",
    "192.168.30.100": "PC-RES1",
    "192.168.30.101": "PC-RES2",
}

SYSLOG_ACL_PATTERN = re.compile(
    r"(?:denied|list\s+\S+\s+denied)\s+(?:tcp|udp|icmp|ip)?\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)",
    re.IGNORECASE
)

AUTH_FAIL_PATTERN = re.compile(r"failed\s+password|authentication\s+failure|login\s+failed", re.IGNORECASE)


class AutoEventListener:
    """
    Listens for live Syslog messages (UDP 514) and NetFlow v5 packets (UDP 2055),
    translates network events into security triggers, and invokes PolicyEngine.
    Also manages an autonomous recovery sweep thread.
    """

    def __init__(
        self,
        policy_engine,
        host: str = "0.0.0.0",
        syslog_port: int = 514,
        netflow_port: int = 2055,
        recovery_interval_sec: int = 30,
    ) -> None:
        self.engine = policy_engine
        self.host = host
        self.syslog_port = syslog_port
        self.netflow_port = netflow_port
        self.recovery_interval_sec = recovery_interval_sec

        self._running = False
        self._syslog_thread: Optional[threading.Thread] = None
        self._netflow_thread: Optional[threading.Thread] = None
        self._recovery_thread: Optional[threading.Thread] = None
        self._syslog_sock: Optional[socket.socket] = None
        self._netflow_sock: Optional[socket.socket] = None

    def resolve_ip_to_device(self, ip_addr: str) -> Optional[str]:
        """Resolve an IP address to a registered lab endpoint."""
        if ip_addr in IP_TO_DEVICE_MAP:
            return IP_TO_DEVICE_MAP[ip_addr]

        octets = ip_addr.split(".")
        if len(octets) == 4 and octets[0] == "192" and octets[1] == "168":
            vlan_octet = octets[2]
            if vlan_octet == "10":
                return "PC-STU1"
            elif vlan_octet == "20":
                return "PC-FAC1"
            elif vlan_octet == "30":
                return "PC-RES1"
            elif vlan_octet == "40":
                return "PC-ADM1"
        return None

    def parse_syslog_message(self, message: str) -> Optional[Tuple[str, str]]:
        """
        Parse raw syslog line.
        Returns (device_name, event_type) or None.
        """
        match = SYSLOG_ACL_PATTERN.search(message)
        if match:
            src_ip = match.group(1)
            device = self.resolve_ip_to_device(src_ip)
            if device:
                event_type = "policy_violation"
                if AUTH_FAIL_PATTERN.search(message):
                    event_type = "auth_failure"
                elif "scan" in message.lower():
                    event_type = "port_scan"
                return (device, event_type)

        if "SIM_EVENT:" in message:
            parts = message.strip().split(":")
            if len(parts) >= 3:
                return (parts[1], parts[2])

        return None

    def parse_netflow_v5_packet(self, data: bytes) -> List[Tuple[str, str]]:
        """
        Parse binary Cisco NetFlow Version 5 packet.
        NetFlow v5 Header:
          version (2B), count (2B), SysUptime (4B), unix_secs (4B), unix_nsecs (4B),
          flow_sequence (4B), engine_type (1B), engine_id (1B), sampling_interval (2B)
          Total header size = 24 bytes.
        Flow Record (48 bytes each):
          srcaddr (4B), dstaddr (4B), nexthop (4B), input (2B), output (2B),
          dPkts (4B), dOctets (4B), First (4B), Last (4B), srcport (2B), dstport (2B),
          pad1 (1B), tcp_flags (1B), prot (1B), tos (1B), src_as (2B), dst_as (2B),
          src_mask (1B), dst_mask (1B), pad2 (2B)
        """
        events = []
        if len(data) < 24:
            return events

        version, count = struct.unpack("!HH", data[:4])
        if version != 5:
            return events

        offset = 24
        record_len = 48
        for _ in range(count):
            if offset + record_len > len(data):
                break
            rec_bytes = data[offset : offset + record_len]
            src_ip_int = struct.unpack("!I", rec_bytes[0:4])[0]
            src_ip = socket.inet_ntoa(struct.pack("!I", src_ip_int))
            d_pkts, d_octets = struct.unpack("!II", rec_bytes[16:24])
            src_port, dst_port = struct.unpack("!HH", rec_bytes[32:36])
            tcp_flags = rec_bytes[37]

            device = self.resolve_ip_to_device(src_ip)
            if device:
                # Port scanning or volume anomaly heuristic
                if d_pkts > 50 or tcp_flags == 0x02:  # SYN scan or high flow
                    events.append((device, "port_scan"))
                else:
                    events.append((device, "policy_violation"))
            offset += record_len

        return events

    def start_syslog_listener(self) -> None:
        """Bind UDP socket and listen for live syslog."""
        try:
            self._syslog_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._syslog_sock.bind((self.host, self.syslog_port))
            self._syslog_sock.settimeout(1.0)
            logger.info("AutoEventListener: listening for Syslog on UDP %s:%d", self.host, self.syslog_port)
        except OSError as e:
            logger.warning("Could not bind syslog port %d (%s). Falling back.", self.syslog_port, e)
            self._syslog_sock = None

        while self._running:
            if self._syslog_sock is None:
                time.sleep(1)
                continue
            try:
                data, addr = self._syslog_sock.recvfrom(2048)
                msg = data.decode("utf-8", errors="ignore")
                parsed = self.parse_syslog_message(msg)
                if parsed:
                    dev, ev = parsed
                    logger.info("Syslog received: Device=%s Event=%s", dev, ev)
                    self.engine.handle_event(dev, ev)
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    logger.error("Syslog receiver error: %s", e)

    def start_netflow_listener(self) -> None:
        """Bind UDP socket and listen for NetFlow v5 packets."""
        try:
            self._netflow_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._netflow_sock.bind((self.host, self.netflow_port))
            self._netflow_sock.settimeout(1.0)
            logger.info("AutoEventListener: listening for NetFlow on UDP %s:%d", self.host, self.netflow_port)
        except OSError as e:
            logger.warning("Could not bind NetFlow port %d (%s). Falling back.", self.netflow_port, e)
            self._netflow_sock = None

        while self._running:
            if self._netflow_sock is None:
                time.sleep(1)
                continue
            try:
                data, addr = self._netflow_sock.recvfrom(4096)
                flow_events = self.parse_netflow_v5_packet(data)
                for dev, ev in flow_events:
                    logger.info("NetFlow detected anomaly: Device=%s Event=%s", dev, ev)
                    self.engine.handle_event(dev, ev)
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    logger.error("NetFlow receiver error: %s", e)

    def start_recovery_worker(self) -> None:
        """Background thread that periodically evaluates recovery hold timers."""
        logger.info("AutoRecoveryWorker started (interval=%ds)", self.recovery_interval_sec)
        while self._running:
            time.sleep(self.recovery_interval_sec)
            try:
                recovered = self.engine.run_recovery_sweep()
                if recovered > 0:
                    logger.info("AutoRecoveryWorker recovered %d device(s)", recovered)
            except Exception as e:
                logger.error("AutoRecoveryWorker error: %s", e)

    def start(self) -> None:
        """Start Syslog, NetFlow, and recovery daemon threads."""
        self._running = True
        self._syslog_thread = threading.Thread(target=self.start_syslog_listener, daemon=True, name="SyslogListener")
        self._netflow_thread = threading.Thread(target=self.start_netflow_listener, daemon=True, name="NetFlowListener")
        self._recovery_thread = threading.Thread(target=self.start_recovery_worker, daemon=True, name="RecoveryWorker")

        self._syslog_thread.start()
        self._netflow_thread.start()
        self._recovery_thread.start()
        logger.info("AutoEventListener (Syslog + NetFlow + AutoRecovery) started successfully.")

    def stop(self) -> None:
        """Stop background listeners."""
        self._running = False
        for s in (self._syslog_sock, self._netflow_sock):
            if s:
                try:
                    s.close()
                except Exception:
                    pass
        logger.info("AutoEventListener stopped.")
