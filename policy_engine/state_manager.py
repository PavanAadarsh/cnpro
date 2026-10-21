"""
state_manager.py — Persistent device state store for the Adaptive Policy Engine.

In the BACSE203 CN Lab, every endpoint (PC-STU*, PC-FAC*, PC-ADM*, PC-RES*)
is tracked here.  State is written to a JSON file so it survives daemon restarts.

States
------
NORMAL      – device is on its home VLAN, no active restrictions.
RESTRICTED  – device has been moved to VLAN 60; hold timer is running.
QUARANTINE  – device has been moved to VLAN 70; requires admin/remediation.
"""

import json
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default device registry (home VLAN / port / switch information)
# ---------------------------------------------------------------------------
DEVICES: Dict[str, dict] = {
    "PC-STU1": {"switch": "ACCESS-SW-A", "switch_ip": "192.168.40.21", "port": "FastEthernet0/1", "home_vlan": 10},
    "PC-STU2": {"switch": "ACCESS-SW-A", "switch_ip": "192.168.40.21", "port": "FastEthernet0/2", "home_vlan": 10},
    "PC-FAC1": {"switch": "ACCESS-SW-A", "switch_ip": "192.168.40.21", "port": "FastEthernet0/3", "home_vlan": 20},
    "PC-FAC2": {"switch": "ACCESS-SW-A", "switch_ip": "192.168.40.21", "port": "FastEthernet0/4", "home_vlan": 20},
    "PC-ADM1": {"switch": "ACCESS-SW-A", "switch_ip": "192.168.40.21", "port": "FastEthernet0/5", "home_vlan": 40},
    "PC-ADM2": {"switch": "ACCESS-SW-A", "switch_ip": "192.168.40.21", "port": "FastEthernet0/6", "home_vlan": 40},
    "PC-RES1": {"switch": "ACCESS-SW-B", "switch_ip": "192.168.40.22", "port": "FastEthernet0/1", "home_vlan": 30},
    "PC-RES2": {"switch": "ACCESS-SW-B", "switch_ip": "192.168.40.22", "port": "FastEthernet0/2", "home_vlan": 30},
}

VALID_STATES = {"NORMAL", "RESTRICTED", "QUARANTINE"}
RESTRICTED_VLAN = 60
QUARANTINE_VLAN = 70


def _utcnow_iso() -> str:
    """Return current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


class StateManager:
    """
    Manages the per-device security state for the Adaptive Policy Engine.

    State is persisted to a JSON file (``state_db.json`` by default) so that
    it survives process restarts.  A threading lock protects concurrent access
    when the engine is run from multiple threads.

    Parameters
    ----------
    db_path : str
        Absolute or relative path to the JSON state file.
    """

    def __init__(self, db_path: str = "state_db.json") -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        self._db: Dict[str, dict] = {}
        self._load()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _default_entry(self, device_name: str) -> dict:
        """Return a fresh NORMAL-state record for *device_name*."""
        info = DEVICES.get(device_name, {})
        return {
            "state": "NORMAL",
            "current_vlan": info.get("home_vlan", 0),
            "home_vlan": info.get("home_vlan", 0),
            "switch": info.get("switch", ""),
            "switch_ip": info.get("switch_ip", ""),
            "port": info.get("port", ""),
            "restricted_since": None,
            "quarantined_since": None,
            "violation_count": 0,
            "remediated": False,
            "enforcement_failed": False,
            "last_updated": _utcnow_iso(),
        }

    def _load(self) -> None:
        """Load state from disk, initialising missing devices to NORMAL."""
        if os.path.exists(self._db_path):
            try:
                with open(self._db_path, "r", encoding="utf-8") as fh:
                    self._db = json.load(fh)
                logger.info("StateManager: loaded %d records from %s", len(self._db), self._db_path)
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("StateManager: could not read %s (%s); starting fresh.", self._db_path, exc)
                self._db = {}

        # Ensure every known device has an entry
        for name in DEVICES:
            if name not in self._db:
                self._db[name] = self._default_entry(name)

        self._save()

    def _save(self) -> None:
        """Persist current in-memory state to the JSON file."""
        try:
            with open(self._db_path, "w", encoding="utf-8") as fh:
                json.dump(self._db, fh, indent=2)
        except OSError as exc:
            logger.error("StateManager: failed to save state to %s: %s", self._db_path, exc)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_state(self, device_name: str) -> Optional[dict]:
        """
        Return the state record for *device_name*.

        Returns ``None`` if the device is not registered.

        The returned dict contains:
        ``state``, ``current_vlan``, ``home_vlan``, ``switch``,
        ``switch_ip``, ``port``, ``restricted_since``,
        ``quarantined_since``, ``violation_count``, ``remediated``,
        ``enforcement_failed``, ``last_updated``.
        """
        with self._lock:
            return dict(self._db.get(device_name, {})) or None

    def set_state(self, device_name: str, new_state: str, *, enforcement_failed: bool = False) -> bool:
        """
        Transition *device_name* to *new_state* and update VLAN + timestamps.

        Parameters
        ----------
        device_name : str
        new_state   : str   One of NORMAL, RESTRICTED, QUARANTINE.
        enforcement_failed : bool
            Set to True when the SSH push could not be completed so the
            audit log reflects the discrepancy.

        Returns True on success, False if device is unknown or state invalid.
        """
        if new_state not in VALID_STATES:
            logger.error("set_state: invalid state '%s'", new_state)
            return False

        with self._lock:
            if device_name not in self._db:
                logger.warning("set_state: unknown device '%s'", device_name)
                return False

            entry = self._db[device_name]
            old_state = entry["state"]
            entry["state"] = new_state
            entry["enforcement_failed"] = enforcement_failed
            entry["last_updated"] = _utcnow_iso()

            # Update VLAN
            if new_state == "NORMAL":
                entry["current_vlan"] = entry["home_vlan"]
                entry["restricted_since"] = None
                entry["quarantined_since"] = None
                entry["remediated"] = False
            elif new_state == "RESTRICTED":
                entry["current_vlan"] = RESTRICTED_VLAN
                if old_state != "RESTRICTED":
                    entry["restricted_since"] = _utcnow_iso()
            elif new_state == "QUARANTINE":
                entry["current_vlan"] = QUARANTINE_VLAN
                if old_state != "QUARANTINE":
                    entry["quarantined_since"] = _utcnow_iso()

            self._save()

        logger.info("StateManager: %s  %s → %s  (vlan=%s, enforcement_failed=%s)",
                    device_name, old_state, new_state, entry["current_vlan"], enforcement_failed)
        return True

    def record_violation(self, device_name: str) -> int:
        """
        Increment the violation counter for *device_name*.

        Returns the new violation count, or -1 if device is unknown.
        """
        with self._lock:
            if device_name not in self._db:
                logger.warning("record_violation: unknown device '%s'", device_name)
                return -1
            self._db[device_name]["violation_count"] += 1
            count = self._db[device_name]["violation_count"]
            self._db[device_name]["last_updated"] = _utcnow_iso()
            self._save()

        logger.debug("StateManager: violation recorded for %s (total=%d)", device_name, count)
        return count

    def mark_remediated(self, device_name: str) -> bool:
        """
        Set the ``remediated`` flag for *device_name* (REC-04).

        The RecoveryHandler uses this flag to waive the recent violation check
        once the mandatory hold timer has elapsed. (Remediation does not bypass
        the hold period).

        Returns True on success, False if device is unknown.
        """
        with self._lock:
            if device_name not in self._db:
                logger.warning("mark_remediated: unknown device '%s'", device_name)
                return False
            self._db[device_name]["remediated"] = True
            self._db[device_name]["last_updated"] = _utcnow_iso()
            self._save()

        logger.info("StateManager: %s marked as remediated", device_name)
        return True

    def restart_quarantine_timer(self, device_name: str) -> bool:
        """
        Restart the quarantine hold timer for *device_name* (TH-04).

        Updates ``quarantined_since`` to now and persists.
        """
        with self._lock:
            if device_name not in self._db:
                return False
            self._db[device_name]["quarantined_since"] = _utcnow_iso()
            self._db[device_name]["last_updated"] = _utcnow_iso()
            self._save()
        logger.info("StateManager: restarted quarantine hold timer for %s", device_name)
        return True

    def get_all_devices(self) -> List[dict]:
        """
        Return a list of state records for every registered device.

        Each record is a copy (mutation-safe).
        """
        with self._lock:
            return [{"device_name": name, **dict(entry)} for name, entry in self._db.items()]

    def reset_device(self, device_name: str) -> bool:
        """
        Hard-reset *device_name* back to the factory-default NORMAL record.

        Useful for testing and lab resets.
        """
        with self._lock:
            if device_name not in DEVICES:
                return False
            self._db[device_name] = self._default_entry(device_name)
            self._save()
        return True
