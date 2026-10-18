"""
threshold_tracker.py — Per-device security event tracking and threshold evaluation.

This module implements the seven threshold rules (TH-01 through TH-07) defined
in the BACSE203 CN Lab Adaptive Policy Engine specification.

Events are stored in memory and optionally persisted to ``events_db.json``
so that they survive daemon restarts within the active time windows.

Time windows
------------
- auth_failure     : 5 minutes  (TH-01)
- port_scan        : 10 minutes (TH-02)
- cross_vlan_attempt: 10 minutes (TH-05)
- spoofing         : 10 minutes (TH-06)
- policy_violation : 10 minutes (general escalation)
"""

import json
import logging
import os
import threading
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Threshold constants (matches lab spec)
# ---------------------------------------------------------------------------
TH_AUTH_FAILURE_COUNT = 3          # TH-01
TH_AUTH_FAILURE_WINDOW_SEC = 300   # 5 min
TH_CROSS_VLAN_COUNT = 2            # TH-05
TH_DEFAULT_WINDOW_SEC = 600        # 10 min for all other event types

VALID_EVENT_TYPES = {
    "auth_failure",
    "port_scan",
    "cross_vlan_attempt",
    "spoofing",
    "policy_violation",
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _utcnow_iso() -> str:
    return _utcnow().isoformat()


class ThresholdTracker:
    """
    Records per-device security events and evaluates threshold rules.

    Events are stored as lists of ISO-8601 timestamps keyed by
    ``(device_name, event_type)``.  Expired timestamps (outside the
    relevant time window) are pruned on every evaluation so memory
    stays bounded.

    Parameters
    ----------
    db_path : str
        Path to the JSON events persistence file (``events_db.json``).
    """

    def __init__(self, db_path: str = "events_db.json") -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        # Structure: {device_name: {event_type: [iso_timestamp, ...]}}
        self._events: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
        self._load()

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _load(self) -> None:
        """Load persisted events from disk (pruning already-expired ones)."""
        if not os.path.exists(self._db_path):
            return
        try:
            with open(self._db_path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            for device, ev_map in raw.items():
                for ev_type, timestamps in ev_map.items():
                    self._events[device][ev_type] = timestamps
            logger.info("ThresholdTracker: loaded events from %s", self._db_path)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("ThresholdTracker: could not read %s (%s); starting fresh.", self._db_path, exc)

    def _save(self) -> None:
        """Persist current events dict to disk."""
        try:
            # Convert defaultdicts to plain dicts for JSON serialisation
            out = {dev: dict(ev_map) for dev, ev_map in self._events.items()}
            with open(self._db_path, "w", encoding="utf-8") as fh:
                json.dump(out, fh, indent=2)
        except OSError as exc:
            logger.error("ThresholdTracker: failed to save events: %s", exc)

    # ------------------------------------------------------------------
    # Window helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _window_for(event_type: str) -> int:
        """Return the applicable time window in seconds for *event_type*."""
        if event_type == "auth_failure":
            return TH_AUTH_FAILURE_WINDOW_SEC
        return TH_DEFAULT_WINDOW_SEC

    def _pruned(self, device_name: str, event_type: str) -> List[str]:
        """
        Return timestamps for (device, event_type) that fall within the window.

        Side-effect: overwrites the stored list with only in-window entries.
        """
        window = self._window_for(event_type)
        cutoff = _utcnow() - timedelta(seconds=window)
        fresh = [
            ts for ts in self._events[device_name][event_type]
            if datetime.fromisoformat(ts) >= cutoff
        ]
        self._events[device_name][event_type] = fresh
        return fresh

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_event(self, device_name: str, event_type: str) -> None:
        """
        Record a security event for *device_name*.

        Parameters
        ----------
        device_name : str   Must be a registered device (e.g. 'PC-STU1').
        event_type  : str   One of the VALID_EVENT_TYPES.

        If an unknown event_type is supplied a warning is logged and the
        event is still stored so no information is silently dropped.
        """
        if event_type not in VALID_EVENT_TYPES:
            logger.warning("ThresholdTracker: unknown event type '%s' for %s", event_type, device_name)

        with self._lock:
            self._events[device_name][event_type].append(_utcnow_iso())
            self._save()

        logger.debug("ThresholdTracker: recorded %s / %s", device_name, event_type)

    def evaluate(self, device_name: str, current_state: str) -> str:
        """
        Evaluate threshold rules for *device_name* and return a recommended action.

        Returns one of:
        - ``'QUARANTINE'``  — device should be quarantined immediately.
        - ``'RESTRICT'``    — device should be moved to RESTRICTED.
        - ``'ESCALATE'``    — device is already RESTRICTED; escalate to QUARANTINE.
        - ``'NO_ACTION'``   — no threshold breached.

        Rules evaluated (in priority order)
        ------------------------------------
        TH-06: spoofing_detected → QUARANTINE directly (highest priority)
        TH-04: already QUARANTINE + new violation → stays QUARANTINE (log only)
        TH-03: already RESTRICTED + new violation → ESCALATE → QUARANTINE
        TH-02: port_scan_detected → RESTRICT
        TH-01: auth_failures >= 3 in 5 min → RESTRICT
        TH-05: cross_vlan_attempt >= 2 in 10 min → RESTRICT
        """
        with self._lock:
            # Prune and fetch counts
            spoof_count = len(self._pruned(device_name, "spoofing"))
            scan_count = len(self._pruned(device_name, "port_scan"))
            auth_count = len(self._pruned(device_name, "auth_failure"))
            xvlan_count = len(self._pruned(device_name, "cross_vlan_attempt"))
            pviol_count = len(self._pruned(device_name, "policy_violation"))

        any_violation = (
            spoof_count > 0
            or scan_count > 0
            or auth_count >= TH_AUTH_FAILURE_COUNT
            or xvlan_count >= TH_CROSS_VLAN_COUNT
            or pviol_count > 0
        )

        # TH-06: spoofing → QUARANTINE immediately
        if spoof_count > 0:
            logger.info("ThresholdTracker: TH-06 spoofing detected for %s", device_name)
            return "QUARANTINE"

        # TH-04: already QUARANTINE + new violation → stay (caller logs)
        if current_state == "QUARANTINE" and any_violation:
            logger.info("ThresholdTracker: TH-04 already QUARANTINE, new violation for %s (no escalation)", device_name)
            return "QUARANTINE"  # caller keeps it QUARANTINE and just logs

        # TH-03: already RESTRICTED + any new violation → escalate
        if current_state == "RESTRICTED" and any_violation:
            logger.info("ThresholdTracker: TH-03 escalation triggered for %s", device_name)
            return "ESCALATE"

        # TH-02: port scan
        if scan_count > 0:
            logger.info("ThresholdTracker: TH-02 port scan for %s", device_name)
            return "RESTRICT"

        # TH-01: auth failures
        if auth_count >= TH_AUTH_FAILURE_COUNT:
            logger.info("ThresholdTracker: TH-01 auth_failures=%d for %s", auth_count, device_name)
            return "RESTRICT"

        # TH-05: cross-VLAN attempts
        if xvlan_count >= TH_CROSS_VLAN_COUNT:
            logger.info("ThresholdTracker: TH-05 cross_vlan=%d for %s", xvlan_count, device_name)
            return "RESTRICT"

        return "NO_ACTION"

    def get_event_summary(self, device_name: str) -> Dict[str, int]:
        """
        Return counts per event type within the applicable time window.

        Returns a dict like::

            {
                'auth_failure': 2,
                'port_scan': 0,
                'cross_vlan_attempt': 1,
                'spoofing': 0,
                'policy_violation': 0,
            }
        """
        with self._lock:
            summary = {}
            for ev_type in VALID_EVENT_TYPES:
                summary[ev_type] = len(self._pruned(device_name, ev_type))
            return summary

    def clear_events(self, device_name: str) -> None:
        """
        Clear all event history for *device_name*.

        Called during recovery to reset the event baseline so the hold
        timer check for 'no new violations' starts cleanly.
        """
        with self._lock:
            self._events[device_name] = defaultdict(list)
            self._save()
        logger.info("ThresholdTracker: events cleared for %s", device_name)
