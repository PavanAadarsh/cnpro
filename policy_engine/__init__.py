"""
policy_engine — Adaptive Policy Engine package for BACSE203 CN Lab.

Public API
----------
PolicyEngine      Main controller (compose + drive the engine).
StateManager      Device state persistence (JSON-backed).
ThresholdTracker  Security event recording and threshold evaluation.
SSHEnforcer       Cisco IOS VLAN enforcement via Paramiko SSH.
RecoveryHandler   Hold-timer based automatic and manual recovery.

Example::

    from policy_engine import PolicyEngine

    engine = PolicyEngine()
    engine.handle_event("PC-STU1", "auth_failure")
    engine.get_status()
"""

from .policy_engine import PolicyEngine
from .state_manager import StateManager
from .threshold_tracker import ThresholdTracker
from .ssh_enforcer import SSHEnforcer
from .recovery_handler import RecoveryHandler

__all__ = [
    "PolicyEngine",
    "StateManager",
    "ThresholdTracker",
    "SSHEnforcer",
    "RecoveryHandler",
]
