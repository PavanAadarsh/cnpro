"""
simulate_event.py — CLI interface for the Adaptive Policy Engine.

Used in the BACSE203 CN Lab to inject security events, check device status,
manually override device states, trigger recovery sweeps, and perform
admin-level clears from the POLICY-HOST (192.168.40.50).

Usage
-----
  python simulate_event.py event   <device> <event_type>
  python simulate_event.py status
  python simulate_event.py enforce <device> <NORMAL|RESTRICTED|QUARANTINE>
  python simulate_event.py recover
  python simulate_event.py clear   <device>

Event types: auth_failure, port_scan, cross_vlan_attempt, spoofing, policy_violation
"""

import argparse
import logging
import os
import sys
import time

# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------
_RESET  = "\033[0m"
_GREEN  = "\033[92m"
_YELLOW = "\033[93m"
_RED    = "\033[91m"
_CYAN   = "\033[96m"
_BOLD   = "\033[1m"


def _colour(text: str, code: str) -> str:
    """Wrap *text* in an ANSI escape sequence if stdout is a TTY."""
    if sys.stdout.isatty() or os.environ.get("FORCE_COLOR"):
        return f"{code}{text}{_RESET}"
    return text


def green(t):  return _colour(t, _GREEN)
def yellow(t): return _colour(t, _YELLOW)
def red(t):    return _colour(t, _RED)
def cyan(t):   return _colour(t, _CYAN)
def bold(t):   return _colour(t, _BOLD)


STATE_COLOUR = {
    "NORMAL": green,
    "RESTRICTED": yellow,
    "QUARANTINE": red,
}

# ---------------------------------------------------------------------------
# Project paths — state files live next to this script
# ---------------------------------------------------------------------------
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_DB  = os.path.join(_SCRIPT_DIR, "state_db.json")
EVENTS_DB = os.path.join(_SCRIPT_DIR, "events_db.json")

# Add project root to sys.path so ``policy_engine`` package is importable
sys.path.insert(0, _SCRIPT_DIR)

from policy_engine import PolicyEngine  # noqa: E402  (after sys.path setup)

# ---------------------------------------------------------------------------
# Logging — suppress library logs so CLI output stays clean
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s  %(levelname)-8s  %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
# Uncomment the following to see debug output from the engine:
# logging.getLogger("policy_engine").setLevel(logging.DEBUG)


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def cmd_event(engine: PolicyEngine, device: str, event_type: str) -> None:
    """Inject a single security event and show the resulting action."""
    valid_events = {
        "auth_failure", "port_scan", "cross_vlan_attempt", "spoofing", "policy_violation"
    }
    if event_type not in valid_events:
        print(red(f"Unknown event type '{event_type}'."))
        print("Valid types: " + ", ".join(sorted(valid_events)))
        sys.exit(1)

    action = engine.handle_event(device, event_type)
    colour_fn = STATE_COLOUR.get(
        {"RESTRICT": "RESTRICTED", "ESCALATE": "QUARANTINE", "QUARANTINE": "QUARANTINE"}.get(action, "NORMAL"),
        green
    )
    print(bold("\nResult: ") + colour_fn(action))


def cmd_status(engine: PolicyEngine) -> None:
    """Print coloured status table for all devices."""
    devices = engine.state_manager.get_all_devices()
    header = (
        f"{'Device':<12} {'State':<12} {'VLAN':<6} {'Switch':<14} {'Port':<18} {'Viols':>5}  Since"
    )
    sep = "-" * len(header)
    print("\n" + cyan(sep))
    print(bold(header))
    print(cyan(sep))
    for rec in sorted(devices, key=lambda r: r["device_name"]):
        state = rec["state"]
        cfn = STATE_COLOUR.get(state, lambda x: x)
        since = rec.get("restricted_since") or rec.get("quarantined_since") or "-"
        if since != "-" and len(since) > 19:
            since = since[:19] + "Z"
        fail_marker = " [SSH-FAIL]" if rec.get("enforcement_failed") else ""
        print(
            f"{rec['device_name']:<12} {cfn(f'{state:<12}')} {rec['current_vlan']:<6} "
            f"{rec['switch']:<14} {rec['port']:<18} {rec['violation_count']:>5}  {since}"
            + (red(fail_marker) if fail_marker else "")
        )
    print(cyan(sep) + "\n")


def cmd_enforce(engine: PolicyEngine, device: str, target_state: str) -> None:
    """Manually override a device's state (TH-07)."""
    valid = {"NORMAL", "RESTRICTED", "QUARANTINE"}
    if target_state not in valid:
        print(red(f"Invalid state '{target_state}'. Choose: NORMAL, RESTRICTED, QUARANTINE"))
        sys.exit(1)
    ok = engine.enforce_state(device, target_state, reason="CLI_OVERRIDE")
    cfn = STATE_COLOUR.get(target_state, green)
    result = bold("OK ✓") if ok else red("SSH FAILED ✗")
    print(f"\nDevice {bold(device)} → {cfn(target_state)}  [{result}]\n")


def cmd_recover(engine: PolicyEngine) -> None:
    """Run a recovery sweep checking all restricted/quarantined devices."""
    count = engine.run_recovery_sweep()
    print(green(f"\n✓ Recovery sweep complete — {count} device(s) returned to NORMAL.\n"))


def cmd_clear(engine: PolicyEngine, device: str) -> None:
    """Immediately clear (REC-01) a device to NORMAL."""
    ok = engine.manual_clear(device)
    result = bold(green("cleared ✓")) if ok else red("SSH FAILED ✗")
    print(f"\nDevice {bold(device)} manually {result}\n")


def cmd_listen(engine: PolicyEngine, port: int, interval: int) -> None:
    """Run live Syslog/NetFlow listener daemon with automated background recovery."""
    from policy_engine.event_listener import AutoEventListener
    listener = AutoEventListener(engine, syslog_port=port, recovery_interval_sec=interval)
    print(cyan(f"\n[+] Starting Live Syslog/NetFlow Collector on UDP port {port}..."))
    print(cyan(f"[+] Autonomous background recovery worker active (interval: {interval}s)."))
    print(bold("Press Ctrl+C to terminate daemon.\n"))
    listener.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(yellow("\n[!] Stopping listener daemon..."))
        listener.stop()
        print(green("[+] Daemon shutdown complete.\n"))


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="simulate_event",
        description="Adaptive Policy Engine CLI — BACSE203 CN Lab",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # event
    p_event = sub.add_parser("event", help="Inject a security event for a device")
    p_event.add_argument("device", help="Device name, e.g. PC-STU1")
    p_event.add_argument(
        "event_type",
        choices=["auth_failure", "port_scan", "cross_vlan_attempt", "spoofing", "policy_violation"],
        help="Type of security event",
    )

    # status
    sub.add_parser("status", help="Display current state of all devices")

    # enforce
    p_enforce = sub.add_parser("enforce", help="Manually override a device state (TH-07)")
    p_enforce.add_argument("device", help="Device name, e.g. PC-STU1")
    p_enforce.add_argument("target_state", choices=["NORMAL", "RESTRICTED", "QUARANTINE"])

    # recover
    sub.add_parser("recover", help="Run a recovery sweep (REC-02 / REC-03)")

    # clear
    p_clear = sub.add_parser("clear", help="Immediately clear a device to NORMAL (REC-01)")
    p_clear.add_argument("device", help="Device name, e.g. PC-STU1")

    # listen (Automated syslog daemon)
    p_listen = sub.add_parser("listen", help="Run live Syslog/NetFlow event listener daemon")
    p_listen.add_argument("--port", type=int, default=514, help="UDP port for syslog (default: 514)")
    p_listen.add_argument("--interval", type=int, default=30, help="Recovery sweep interval in seconds (default: 30)")

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    engine = PolicyEngine(state_db_path=STATE_DB, events_db_path=EVENTS_DB)

    if args.command == "event":
        cmd_event(engine, args.device, args.event_type)
    elif args.command == "status":
        cmd_status(engine)
    elif args.command == "enforce":
        cmd_enforce(engine, args.device, args.target_state)
    elif args.command == "recover":
        cmd_recover(engine)
    elif args.command == "clear":
        cmd_clear(engine, args.device)
    elif args.command == "listen":
        cmd_listen(engine, args.port, args.interval)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
