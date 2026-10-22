#!/bin/sh
set -eu
# Each namespace has its own resolver file. Never edit the inherited host resolver.
case "${CNPRO_RESOLV_CONF:-}" in
  /etc/netns/m4n*/resolv.conf) ;;
  *) echo "Missing isolated endpoint resolver path" >&2; exit 1 ;;
esac
case "$1" in
  deconfig) ip -4 addr flush dev "$interface" ;;
  bound|renew)
    test -n "${dns:-}"
    for resolver in $dns; do
      case "$resolver" in 203.0.113.2|192.168.50.13) ;; *) exit 1 ;; esac
    done
    ip -4 addr flush dev "$interface"
    ip addr add "$ip/24" dev "$interface"
    ip route replace default via "$router" dev "$interface"
    # Write in place because ip netns exec may have bind-mounted this inode.
    { for resolver in $dns; do printf 'nameserver %s\n' "$resolver"; done
      printf 'options timeout:1 attempts:1\n'
    } > "$CNPRO_RESOLV_CONF"
    ;;
esac
