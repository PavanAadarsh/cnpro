"""
ssh_enforcer.py — SSH-based VLAN enforcement on Cisco IOS switches.

In the BACSE203 CN Lab the POLICY-HOST machine (192.168.40.50) SSHes into the
access switches (ACCESS-SW-A at 192.168.40.21, ACCESS-SW-B at 192.168.40.22)
and pushes ``switchport access vlan <N>`` commands via Paramiko.

This module wraps Paramiko with IOS-compatible shell interaction:
- Uses invoke_shell() instead of exec_command() for multi-command sessions.
- Small sleep() delays allow IOS to process each command before the next.
- ``write memory`` is always called to persist the configuration.

Credentials (lab-wide): username=admin  password=Admin@123
"""

import logging
import re
import socket
import time
from typing import Optional

try:
    import paramiko
    _PARAMIKO_AVAILABLE = True
except ImportError:  # pragma: no cover
    _PARAMIKO_AVAILABLE = False
    paramiko = None  # type: ignore

logger = logging.getLogger(__name__)

SSH_USERNAME = "admin"
SSH_PASSWORD = "Admin@123"
SSH_PORT = 22
CMD_DELAY = 1.0        # seconds between IOS commands
CONNECT_TIMEOUT = 10   # seconds


class SSHEnforcer:
    """
    Pushes VLAN-assignment commands to Cisco IOS access switches via SSH.

    All methods return a boolean success flag so callers can handle failures
    gracefully without crashing the engine.

    Parameters
    ----------
    username : str   SSH login username (default: 'admin').
    password : str   SSH login password (default: 'Admin@123').
    port     : int   SSH TCP port (default: 22).
    cmd_delay: float Seconds to wait between IOS commands (default: 1.0).
    """

    def __init__(
        self,
        username: str = SSH_USERNAME,
        password: str = SSH_PASSWORD,
        port: int = SSH_PORT,
        cmd_delay: float = CMD_DELAY,
    ) -> None:
        self._username = username
        self._password = password
        self._port = port
        self._cmd_delay = cmd_delay

    # ------------------------------------------------------------------
    # Internal helper
    # ------------------------------------------------------------------

    def _get_client(self, switch_ip: str) -> Optional["paramiko.SSHClient"]:
        """
        Create and return an authenticated Paramiko SSHClient.

        Returns None if the connection could not be established.
        """
        if not _PARAMIKO_AVAILABLE:
            logger.error("SSHEnforcer: paramiko is not installed.")
            return None

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=switch_ip,
                port=self._port,
                username=self._username,
                password=self._password,
                timeout=CONNECT_TIMEOUT,
                look_for_keys=False,
                allow_agent=False,
            )
            logger.debug("SSHEnforcer: connected to %s", switch_ip)
            return client
        except (
            paramiko.AuthenticationException,
            paramiko.SSHException,
            socket.timeout,
            OSError,
        ) as exc:
            logger.error("SSHEnforcer: cannot connect to %s — %s", switch_ip, exc)
            return None

    @staticmethod
    def _read_until_prompt(channel: "paramiko.Channel", timeout: float = 5.0) -> str:
        """
        Read from *channel* until idle or timeout and return accumulated output.
        """
        output = ""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if channel.recv_ready():
                chunk = channel.recv(4096).decode("utf-8", errors="replace")
                output += chunk
            else:
                time.sleep(0.1)
        return output

    def _run_ios_commands(self, switch_ip: str, commands: list) -> tuple:
        """
        Open a shell on *switch_ip*, run *commands* sequentially, return (success, output).
        """
        client = self._get_client(switch_ip)
        if client is None:
            return False, ""

        output = ""
        try:
            shell = client.invoke_shell(term="vt100", width=200, height=50)
            time.sleep(self._cmd_delay)
            self._read_until_prompt(shell)   # consume banner / prompt

            for cmd in commands:
                shell.send(cmd + "\n")
                time.sleep(self._cmd_delay)
                chunk = self._read_until_prompt(shell)
                output += chunk
                logger.debug("SSHEnforcer [%s] cmd=%r  out=%r", switch_ip, cmd, chunk[:120])

            return True, output
        except (paramiko.SSHException, OSError) as exc:
            logger.error("SSHEnforcer: command error on %s — %s", switch_ip, exc)
            return False, output
        finally:
            try:
                client.close()
            except Exception:  # pragma: no cover
                pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def push_vlan(self, switch_ip: str, port: str, vlan_id: int) -> bool:
        """
        Configure *port* on *switch_ip* as an access port in *vlan_id*.

        IOS command sequence::

            configure terminal
            interface <port>
            switchport mode access
            switchport access vlan <vlan_id>
            end
            write memory

        Parameters
        ----------
        switch_ip : str   IP address of the switch (e.g. '192.168.40.21').
        port      : str   Interface name (e.g. 'FastEthernet0/1').
        vlan_id   : int   Target VLAN number.

        Returns True if all commands were pushed without SSH errors.
        """
        commands = [
            "configure terminal",
            f"interface {port}",
            "switchport mode access",
            f"switchport access vlan {vlan_id}",
            "end",
            "write memory",
        ]
        logger.info("SSHEnforcer: push_vlan %s  %s → vlan %d", switch_ip, port, vlan_id)
        success, output = self._run_ios_commands(switch_ip, commands)
        if success:
            logger.info("SSHEnforcer: push_vlan succeeded on %s %s vlan=%d", switch_ip, port, vlan_id)
        else:
            logger.error("SSHEnforcer: push_vlan FAILED on %s %s vlan=%d", switch_ip, port, vlan_id)
        return success

    def verify_vlan(self, switch_ip: str, port: str) -> Optional[int]:
        """
        Query the current access VLAN for *port* on *switch_ip*.

        Runs ``show interfaces <port> switchport`` and parses the
        ``Access Mode VLAN:`` line.

        Returns the VLAN id as an int, or None if it could not be determined.
        """
        commands = [f"show interfaces {port} switchport"]
        success, output = self._run_ios_commands(switch_ip, commands)
        if not success:
            return None

        # IOS line:  "Access Mode VLAN: 10 (Active)"
        match = re.search(r"Access Mode VLAN:\s+(\d+)", output, re.IGNORECASE)
        if match:
            vlan_id = int(match.group(1))
            logger.info("SSHEnforcer: verify_vlan %s %s → vlan %d", switch_ip, port, vlan_id)
            return vlan_id

        logger.warning("SSHEnforcer: could not parse VLAN from output of %s %s", switch_ip, port)
        return None

    def test_connectivity(self, switch_ip: str) -> bool:
        """
        Verify TCP-level SSH reachability to *switch_ip*.

        Opens a socket on port 22 and returns True if it connects within
        CONNECT_TIMEOUT seconds.  Does not perform SSH authentication.

        Returns True if reachable, False otherwise.
        """
        try:
            with socket.create_connection((switch_ip, self._port), timeout=CONNECT_TIMEOUT):
                logger.info("SSHEnforcer: %s is reachable on port %d", switch_ip, self._port)
                return True
        except (socket.timeout, OSError) as exc:
            logger.warning("SSHEnforcer: %s not reachable — %s", switch_ip, exc)
            return False
