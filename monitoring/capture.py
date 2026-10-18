"""Bounded tshark capture on an explicitly supplied project-only interface.

Not a Packet Tracer traffic capture: use Simulation mode there instead.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
from evaluate import new_run

FILTER = '(net 192.168.0.0/16 or net 10.0.0.0/30 or net 203.0.113.0/30)'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--interface', required=True)
    p.add_argument('--project-only', action='store_true', required=True,
                   help='confirm this interface carries only the authorized project')
    p.add_argument('--configuration', choices=('architecture_baseline', 'static', 'adaptive'), required=True)
    p.add_argument('--scenario', required=True)
    p.add_argument('--seconds', type=int, default=30)
    p.add_argument('--output', default=str(Path(__file__).parent / 'captures'))
    p.add_argument('--tagged', action='store_true', help='include one 802.1Q tag on a trunk mirror')
    a = p.parse_args()
    if not 1 <= a.seconds <= 300:
        p.error('--seconds must be 1..300')
    executable = shutil.which('tshark')
    if not executable:
        p.error('tshark unavailable; no capture performed')
    path = new_run(Path(a.output) / a.configuration)
    capture_filter = f'{FILTER} or (vlan and {FILTER})' if a.tagged else FILTER
    command = [executable, '-i', a.interface, '-f', capture_filter, '-a', f'duration:{a.seconds}',
               '-a', 'filesize:10240', '-s', '128', '-w', str(path / 'traffic.pcapng')]
    metadata = dict(configuration=a.configuration, scenario=a.scenario, command=command,
                    start_at=datetime.now(timezone.utc).isoformat(),
                    note='128-byte snapshots; payload/throughput inference limited; interface must be project-only')
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=a.seconds + 15)
        metadata['returncode'] = result.returncode
        (path / 'capture.log').write_text(result.stdout + result.stderr)
        if result.returncode == 0:
            stats = subprocess.run([executable, '-r', str(path / 'traffic.pcapng'), '-q', '-z', 'io,stat,1'],
                                   capture_output=True, text=True, timeout=30)
            (path / 'packet_statistics.txt').write_text(stats.stdout + stats.stderr)
            metadata['analysis_returncode'] = stats.returncode
    except subprocess.TimeoutExpired:
        metadata['error'] = 'Capture subprocess exceeded timeout; only this child was terminated.'
    finally:
        metadata['end_at'] = datetime.now(timezone.utc).isoformat()
        (path / 'metadata.json').write_text(json.dumps(metadata, indent=2))
    print(path)
    if metadata.get('returncode') != 0:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
