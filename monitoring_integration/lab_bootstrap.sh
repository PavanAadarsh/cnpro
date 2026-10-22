#!/bin/sh
set -eu
# Invoke in docker-desktop WSL as root. Changes only our private /tmp rootfs and
# private mount/network namespaces. Does not use/reset Docker or host firewall.
PROJECT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ROOT=/tmp/cnpro-m4-alpine-3.22.6
ARCHIVE="$PROJECT/monitoring_integration/results/lab-runtime/alpine-minirootfs-3.22.6-x86_64.tar.gz"
mkdir -p "$ROOT"
export PROJECT ROOT ARCHIVE
exec unshare -m --propagation private /bin/sh -c '
  set -eu
  mount -t tmpfs -o size=384m cnpro-private-root "$ROOT"
  CACHE="$PROJECT/monitoring_integration/results/lab-runtime/prepared-app-rootfs.tar.gz"
  OLD_CACHE="$PROJECT/monitoring_integration/results/lab-runtime/prepared-rootfs.tar.gz"
  if [ -f "$CACHE" ]; then tar -xzf "$CACHE" -C "$ROOT"; elif [ -f "$OLD_CACHE" ]; then tar -xzf "$OLD_CACHE" -C "$ROOT"; else tar -xzf "$ARCHIVE" -C "$ROOT"; fi
  mkdir -p "$ROOT/project" "$ROOT/proc" "$ROOT/dev"
  mount --bind "$PROJECT" "$ROOT/project"
  mount -t proc proc "$ROOT/proc"
  mount --bind /dev "$ROOT/dev"
  cp /etc/resolv.conf "$ROOT/etc/resolv.conf"
  if [ ! -f "$CACHE" ]; then
    chroot "$ROOT" /sbin/apk add --no-cache python3 iproute2 nftables tcpdump iperf3 dnsmasq openssl py3-pyftpdlib
  fi
  if [ ! -f "$CACHE" ]; then
    tar -czf "$CACHE" -C "$ROOT" --exclude=./proc --exclude=./dev --exclude=./project .
  fi
  if [ "${1:-}" = "setup" ]; then exit 0; fi
  exec chroot "$ROOT" /usr/bin/unshare -n /usr/bin/python3 -B /project/monitoring_integration/lab.py
' sh "${1:-}"
