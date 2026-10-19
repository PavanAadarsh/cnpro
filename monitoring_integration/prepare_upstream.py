"""Recreate required teammate dependencies from existing pinned Git objects.

Does not fetch, checkout, merge, change branches or overwrite different files.
Keeps teammate source (including its existing credential defaults) out of this
Member 4 commit. Generated dependencies are ignored by Git.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FILES = {
    'member2': ('origin/member-2', [
        'cnpro/configs/CORE-SW_security_acls.cfg',
        'cnpro/running-configs/CORE-SW_running_config.txt',
    ]),
    'member3': ('origin/member3', [
        'requirements.txt',
        'policy_engine/__init__.py',
        'policy_engine/policy_engine.py',
        'policy_engine/state_manager.py',
        'policy_engine/threshold_tracker.py',
        'policy_engine/recovery_handler.py',
        'policy_engine/ssh_enforcer.py',
        'tests/__init__.py',
        'tests/test_policy_engine.py',
    ]),
}


def prepare(destination=HERE / 'upstream', sources_path=HERE / 'sources.json', repository=ROOT):
    destination = Path(destination).resolve()
    sources = json.loads(Path(sources_path).read_text(encoding='utf-8'))
    pending = []
    for member, (key, names) in FILES.items():
        commit = sources[key]
        if not isinstance(commit, str) or not re.fullmatch(r'[0-9a-f]{40}', commit):
            raise ValueError('sources.json must pin full lowercase Git commit hashes')
        for name in names:
            target = (destination / member / name).resolve()
            if not target.is_relative_to(destination):
                raise ValueError('dependency destination escapes its folder')
            data = subprocess.check_output(['git', '-C', str(repository), 'show', f'{commit}:{name}'],
                                           stderr=subprocess.PIPE)
            if target.exists() and target.read_bytes() != data:
                raise ValueError(f'preserving different existing file: {target}')
            pending.append((target, data))
    # Read and verify all dependencies before creating any files.
    written = 0
    for target, data in pending:
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as f:
                f.write(data)
            written += 1
    return {'required_files': len(pending), 'created': written, 'already_matching': len(pending) - written}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    try:
        print(json.dumps(prepare(), indent=2))
    except subprocess.CalledProcessError as exc:
        raise SystemExit('A pinned teammate Git object is unavailable. Use a normal clone of cnpro with '
                         'its branches, or fetch the member-2 and member3 histories, then retry. '
                         'No branch, source file or credential was changed.') from exc
    except (ValueError, OSError, KeyError) as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == '__main__':
    main()
