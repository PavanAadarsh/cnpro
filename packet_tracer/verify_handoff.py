"""Read-only integrity and freshness checks. Does not run Packet Tracer.

Exit 0: packaged evidence intact/current (not full project completion).
Exit 1: missing, modified, unsafe or stale handoff artifact.
Policy gaps are reported separately and never labelled live test passes.
"""
import csv
import hashlib
import json
from pathlib import Path, PurePosixPath

from build_final_package import PATCH, ROLLBACK, topology, validate_cabling
from final_audit import Campus, HERE, audit


def verify():
    manifest = json.loads((HERE / 'evidence/final_artifact_manifest.json').read_text(encoding='utf-8-sig'))
    seen = set()
    for row in manifest:
        relative = PurePosixPath(row['Path'])
        if relative.is_absolute() or '..' in relative.parts or '\\' in row['Path'] or ':' in row['Path']:
            raise ValueError('unsafe manifest path')
        path = HERE / Path(*relative.parts)
        if not path.resolve().is_relative_to(HERE.resolve()) or row['Path'] in seen:
            raise ValueError('escaped or duplicate manifest path')
        seen.add(row['Path'])
        data = path.read_bytes()
        if len(data) != row['Bytes'] or hashlib.sha256(data).hexdigest().upper() != row['SHA256'].upper():
            raise ValueError('artifact changed: ' + row['Path'])
    required = {'University_Research_Network_Final.pkt', 'README.md', 'final_audit.py',
                'build_final_package.py', 'verify_handoff.py', 'tests/test_final_package.py'}
    required.update(p.relative_to(HERE).as_posix() for p in (HERE / 'final_package').rglob('*') if p.is_file())
    required.update('evidence/' + name + '_final_running_config.txt' for name in Campus().devices)
    if not required.issubset(seen):
        raise ValueError('required files absent from manifest: ' + ', '.join(sorted(required - seen)))
    output = HERE / 'final_package'
    design = json.loads((output / 'topology.json').read_text(encoding='utf-8'))
    if design != topology():
        raise ValueError('stale topology: rebuild the handoff')
    validate_cabling(design, Campus())
    with (output / 'cabling.csv').open(newline='', encoding='utf-8') as stream:
        actual = list(csv.DictReader(stream))
    expected = [{key: str(value) if value is not None else '' for key, value in link.items()}
                for link in design['links']]
    if actual != expected:
        raise ValueError('stale cabling CSV')
    results = audit()
    report = json.loads((output / 'offline_policy_audit.json').read_text(encoding='utf-8'))
    if (report['results'] != results or report['cases'] != len(results)
            or report['matching'] != sum(r['matches_requirement'] for r in results)):
        raise ValueError('stale policy audit: rebuild the handoff')
    for row in json.loads((output / 'source_hashes.json').read_text(encoding='utf-8')):
        data = (HERE / row['path']).read_bytes()
        if len(data) != row['bytes'] or hashlib.sha256(data).hexdigest() != row['sha256']:
            raise ValueError('source differs from generated handoff: ' + row['path'])
    for name, expected_text in (('EDGE-R_quarantine_gateway.cfg', PATCH), ('EDGE-R_rollback.cfg', ROLLBACK)):
        if (output / 'pending_changes' / name).read_text(encoding='utf-8') != expected_text:
            raise ValueError('pending correction differs from builder: ' + name)
    gaps = [r['id'] for r in results if not r['matches_requirement']]
    print(f'Integrity/freshness verified: {len(manifest)} files, {len(results)} offline policy cases.')
    print('Pending configuration gaps: ' + (', '.join(gaps) if gaps else 'none in this model'))
    print('No live Packet Tracer checks were run. This is not a project-completion verdict.')
    return dict(files=len(manifest), cases=len(results), pending=gaps)


if __name__ == '__main__':
    try:
        verify()
    except (OSError, ValueError, KeyError) as error:
        raise SystemExit('Handoff verification failed: ' + str(error))
