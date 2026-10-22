"""Recreate required teammate dependencies from existing pinned Git objects.

Does not fetch, checkout, merge, change branches or overwrite user-edited files.
--refresh archives and replaces only files matching a previous pinned version.
Keeps teammate source (including its existing credential defaults) out of this
Member 4 commit. Generated dependencies are ignored by Git.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FILES = {
    'member1': ('origin/member1-network-architecture', [
        'running-configs/CORE-SW_running_config.txt',
        'running-configs/ACCESS-SW-A_running_config.txt',
        'running-configs/ACCESS-SW-B_running_config.txt',
        'running-configs/EDGE-R_running_config.txt',
        'docs/01_physical_topology.md',
        'docs/07_end_devices_configuration.md',
        'handoff/MEMBER4_HANDOFF.md',
    ]),
    'member2': ('origin/member-2', [
        'cnpro/configs/CORE-SW_security_acls.cfg',
        'cnpro/running-configs/CORE-SW_running_config.txt',
    ]),
    'member3': ('origin/member3', [
        'README.md',
        'REPORT_MEMBER3.md',
        'configs/POLICY-HOST_configuration.md',
        'configs/containment_commands.md',
        'configs/policy_engine_design.md',
        'docs/ENGINE_RUNTIME_AND_RECONCILIATION.md',
        'docs/MEMBER4_AUDIT_RESOLUTION.md',
        'docs/MEMBER4_RECONCILIATION_RESPONSE.md',
        'docs/LIVE_NETWORK_ENFORCEMENT_EVIDENCE.md',
        'simulate_event.py',
        'requirements.txt',
        'policy_engine/__init__.py',
        'policy_engine/event_listener.py',
        'policy_engine/policy_engine.py',
        'policy_engine/state_manager.py',
        'policy_engine/threshold_tracker.py',
        'policy_engine/recovery_handler.py',
        'policy_engine/ssh_enforcer.py',
        'tests/__init__.py',
        'tests/test_policy_engine.py',
        'tests/test_event_listener.py',
        'tests/test_live_switch_runtime.py',
        'tests/test_live_switch_and_protocols.py',
        'tests/state_transition_test_plan.md',
    ]),
}


def prepare(destination=HERE / 'upstream', sources_path=HERE / 'sources.json', repository=ROOT,
            refresh=False):
    destination = Path(destination).resolve()
    sources = json.loads(Path(sources_path).read_text(encoding='utf-8'))
    pending = []
    replacements = []
    for member, (key, names) in FILES.items():
        commit = sources.get(key)
        if not isinstance(commit, str) or not re.fullmatch(r'[0-9a-f]{40}', commit):
            raise ValueError('sources.json must pin full lowercase Git commit hashes')
        for name in names:
            target = (destination / member / name).resolve()
            if not target.is_relative_to(destination):
                raise ValueError('dependency destination escapes its folder')
            data = subprocess.check_output(['git', '-C', str(repository), 'show', f'{commit}:{name}'],
                                           stderr=subprocess.PIPE)
            if target.exists() and target.read_bytes() != data:
                previous = sources.get('previous_sources', {}).get(key)
                if not refresh or not isinstance(previous, str) or not re.fullmatch(r'[0-9a-f]{40}', previous):
                    raise ValueError(f'preserving different existing file: {target}; use --refresh only for pinned updates')
                old = subprocess.check_output(['git', '-C', str(repository), 'show', f'{previous}:{name}'],
                                              stderr=subprocess.PIPE)
                if target.read_bytes() != old:
                    raise ValueError(f'preserving user-edited file: {target}')
                replacements.append((target, old))
            pending.append((target, data))
    # Read and verify all dependencies before creating any files.
    backup = None
    if replacements:
        backup = destination.parent / 'results/upstream_backups' / (
            datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8])
        for target, old in replacements:
            archived = backup / target.relative_to(destination)
            archived.parent.mkdir(parents=True, exist_ok=True)
            with archived.open('xb') as f:
                f.write(old)
    written = 0
    updated = 0
    for target, data in pending:
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as f:
                f.write(data)
            written += 1
        elif target.read_bytes() != data:
            target.write_bytes(data)
            updated += 1
    return {'required_files': len(pending), 'created': written, 'updated': updated,
            'already_matching': len(pending) - written - updated,
            'backup_directory': str(backup) if backup else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--refresh', action='store_true', help='archive and update matching previous pinned files; refuse user edits')
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(refresh=args.refresh), indent=2))
    except subprocess.CalledProcessError as exc:
        raise SystemExit('A pinned teammate Git object is unavailable. Use a normal clone of cnpro with '
                         'its branches, or fetch the member-2 and member3 histories, then retry. '
                         'No branch, source file or credential was changed.') from exc
    except (ValueError, OSError, KeyError) as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == '__main__':
    main()
