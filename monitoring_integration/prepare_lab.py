"""Reproduce the isolated local WSL lab; downloads only an official pinned runtime."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import urllib.request

HERE = Path(__file__).resolve().parent
URL = 'https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/alpine-minirootfs-3.22.6-x86_64.tar.gz'
SHA256 = '27694aaa55fd7a9e3ef596e0ad4eb66802308bb20172b17030cd5f4d8ae9bac2'


def prepare():
    directory = HERE / 'results/lab-runtime'
    directory.mkdir(parents=True, exist_ok=True)
    archive = directory / URL.rsplit('/', 1)[-1]
    if not archive.exists():
        temporary = archive.with_suffix('.download')
        with urllib.request.urlopen(URL, timeout=60) as source, temporary.open('wb') as output:
            output.write(source.read())
        if hashlib.sha256(temporary.read_bytes()).hexdigest() != SHA256:
            raise ValueError('official runtime checksum mismatch; refusing to extract')
        temporary.replace(archive)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != SHA256:
        raise ValueError('local runtime checksum mismatch')
    (directory / 'download.json').write_text(json.dumps(dict(url=URL, sha256=SHA256), indent=2))
    return archive


def run():
    prepare()
    if os.name != 'nt':
        raise RuntimeError('This launcher targets the installed Windows docker-desktop WSL distribution')
    script = str(HERE / 'lab_bootstrap.sh')
    script = '/mnt/host/' + script[0].lower() + script[2:].replace('\\', '/')
    return subprocess.run(['wsl', '-d', 'docker-desktop', '-u', 'root', '--', '/bin/sh', script], check=True)


if __name__ == '__main__':
    run()
