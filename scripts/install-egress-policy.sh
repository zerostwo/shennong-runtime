#!/usr/bin/env bash
# Installs an idempotent nftables policy. Review and run explicitly on the
# dedicated worker host; the Runtime Daemon must never receive CAP_NET_ADMIN.
set -euo pipefail

JOB_BRIDGE="${SHENNONG_JOB_BRIDGE:-sn-job-egress}"
SESSION_BRIDGE="${SHENNONG_SESSION_BRIDGE:-sn-session}"
RUNTIME_PROXY_V4="${SHENNONG_RUNTIME_PROXY_V4:?set the exact Runtime proxy source IPv4 CIDR inside the executor namespace}"
NETNS_PID="${SHENNONG_NETNS_PID:-}"

for interface in "${JOB_BRIDGE}" "${SESSION_BRIDGE}"; do
  if [[ ! "${interface}" =~ ^[A-Za-z0-9_.-]{1,15}$ ]]; then
    echo "invalid bridge interface: ${interface}" >&2
    exit 64
  fi
done
if ! python3 -c 'import ipaddress,sys
network=ipaddress.ip_network(sys.argv[1], strict=True)
raise SystemExit(0 if network.version == 4 and network.prefixlen == 32 else 1)' \
  "${RUNTIME_PROXY_V4}"; then
  echo "SHENNONG_RUNTIME_PROXY_V4 must be one exact IPv4 /32" >&2
  exit 64
fi

NFT=(nft)
IP=(ip)
if [[ -n "${NETNS_PID}" ]]; then
  if [[ ! "${NETNS_PID}" =~ ^[1-9][0-9]*$ ]]; then
    echo "SHENNONG_NETNS_PID is invalid" >&2
    exit 64
  fi
  NFT=(nsenter --target "${NETNS_PID}" --net nft)
  IP=(nsenter --target "${NETNS_PID}" --net ip)
fi

for interface in "${JOB_BRIDGE}" "${SESSION_BRIDGE}"; do
  if ! "${IP[@]}" link show dev "${interface}" >/dev/null 2>&1; then
    echo "bridge ${interface} is absent from the selected network namespace" >&2
    exit 69
  fi
done

"${NFT[@]}" -f - <<NFT
destroy table inet shennong_runtime
table inet shennong_runtime {
  set blocked_v4 {
    type ipv4_addr
    flags interval
    elements = {
      0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8,
      169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24,
      192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15,
      198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4
    }
  }

  set blocked_v6 {
    type ipv6_addr
    flags interval
    elements = { ::/128, ::1/128, fc00::/7, fe80::/10, ff00::/8, 2001:db8::/32 }
  }

  chain forward {
    type filter hook forward priority -20; policy accept;

    # Rules are scoped to executor bridge interfaces, never to the rootless
    # account UID. A UID-wide loopback block would break Runtime's IDE proxy.
    ct state established,related accept

    # Batch Jobs may initiate public internet traffic only. They cannot accept
    # new inbound flows, reach private/control/link-local space, or talk laterally.
    iifname "${JOB_BRIDGE}" oifname "${JOB_BRIDGE}" ct state new drop
    iifname "${JOB_BRIDGE}" ip daddr @blocked_v4 drop
    iifname "${JOB_BRIDGE}" ip6 daddr @blocked_v6 drop
    oifname "${JOB_BRIDGE}" ct state new drop

    # IDEs have the same egress restriction, with one explicit inbound OS proxy.
    iifname "${SESSION_BRIDGE}" ip daddr @blocked_v4 drop
    iifname "${SESSION_BRIDGE}" ip6 daddr @blocked_v6 drop
    oifname "${SESSION_BRIDGE}" ip saddr ${RUNTIME_PROXY_V4} ct state new accept
    oifname "${SESSION_BRIDGE}" ct state new drop
  }
}
NFT

"${NFT[@]}" list table inet shennong_runtime >/dev/null

echo "installed shennong_runtime nftables egress policy"
