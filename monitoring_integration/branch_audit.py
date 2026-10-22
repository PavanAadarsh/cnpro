"""Read-only inventory of all fetched remote branches and network assets."""
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ('.pkt', '.pka', '.zip', '.7z', '.rar', '.tar', '.gz')


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args], text=True, encoding='utf-8').strip()


def inventory():
    branches = []
    for ref in git('for-each-ref', '--format=%(refname)', 'refs/remotes/origin').splitlines():
        if ref.endswith('/HEAD'):
            continue
        files = git('ls-tree', '-r', '--name-only', ref).splitlines()
        branches.append(dict(branch=ref.removeprefix('refs/remotes/origin/'), commit=git('rev-parse', ref),
                             file_count=len(files), files=files,
                             network_assets=[p for p in files if p.lower().endswith(ASSETS)]))
    sources = json.loads((ROOT / 'monitoring_integration/sources.json').read_text())
    previous = sources.get('previous_sources', {}).get('origin/member3')
    change = None
    if previous:
        current = sources['origin/member3']
        names = git('diff', '--name-only', previous, current).splitlines()
        change = dict(previous=previous, current=current, changed_paths=names,
                      engine_modules_changed=any(p.startswith('policy_engine/') and p.endswith('.py') for p in names))
    return dict(checked_at=datetime.now(timezone.utc).isoformat(),
                scope='all fetched origin branch trees; run git fetch origin first for a fresh remote snapshot',
                branches=branches, member3_change=change,
                topology_present=any(p.lower().endswith(('.pkt', '.pka'))
                                     for branch in branches for p in branch['network_assets']))


if __name__ == '__main__':
    print(json.dumps(inventory(), indent=2))
