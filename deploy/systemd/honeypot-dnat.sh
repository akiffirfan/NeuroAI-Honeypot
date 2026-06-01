#!/bin/bash
# honeypot-dnat.sh — apply honeypot DNAT rules idempotently.
# Reads the current PREROUTING chain once and only adds rules that are absent.
# Safe to run multiple times; does not create duplicates.
#
# Container IPs (honeypot-net 10.10.20.0/24, internal: false):
#   10.10.20.8  cowrie        (SSH lure)
#   10.10.20.6  opencanary    (FTP/Telnet/SMTP/Redis lures)
#   10.10.20.4  mariadb-lure  (MySQL lure)
#
# iif "eth0" restriction: required so br_netfilter does not intercept
# container-to-container bridge traffic on the same ports (e.g. port 6379
# Redis — without iif restriction, log-shipper->redis packets would be
# redirected to OpenCanary's fake Redis).

set -euo pipefail

CHAIN=$(nft list chain ip nat PREROUTING 2>/dev/null || true)

# rule <grep-pattern> <nft-args...>
# Adds "nft add rule ip nat PREROUTING iif eth0 <nft-args>" only if
# <grep-pattern> is not already present in PREROUTING.
rule() {
    local pat="$1"; shift
    if echo "$CHAIN" | grep -q "$pat"; then
        echo "honeypot-dnat: already present — $pat"
    else
        nft add rule ip nat PREROUTING iif eth0 "$@"
        echo "honeypot-dnat: added — iif eth0 $*"
    fi
}

# Module 2: Cowrie SSH (port 22 → container 10.10.20.8:2222)
rule "dport 22 dnat to 10.10.20.8:2222"    tcp dport 22    dnat to 10.10.20.8:2222

# Cowrie FORWARD rule — Docker normally adds this via "ports: 0.0.0.0:2222:2222"
# in the DOCKER iptables chain. That published binding was removed 2026-05-30 to free
# port 2222 for the co-deployed HoneyDash Cowrie. Without it, the DNAT'd packet
# passes PREROUTING but is dropped in the FORWARD chain (no matching ACCEPT).
# No interface conditions here — "honeypot-net" is a Docker logical name, not a kernel
# interface name (actual bridge is br-<12hex>). Safe without -i/-o because the DNAT
# rule in PREROUTING already restricts to iif eth0, so only DNAT'd port-22 traffic
# ever reaches 10.10.20.8:2222.
if ! iptables -C FORWARD -d 10.10.20.8/32 -p tcp --dport 2222 -j ACCEPT 2>/dev/null; then
    iptables -I FORWARD 1 -d 10.10.20.8/32 -p tcp --dport 2222 -j ACCEPT
    echo "honeypot-dnat: added FORWARD ACCEPT for cowrie 10.10.20.8:2222"
else
    echo "honeypot-dnat: FORWARD rule for cowrie already present"
fi

# Module 3: OpenCanary (same-port DNAT to container 10.10.20.6)
rule "dport 21 dnat to 10.10.20.6:21"      tcp dport 21    dnat to 10.10.20.6:21
rule "dport 23 dnat to 10.10.20.6:23"      tcp dport 23    dnat to 10.10.20.6:23
rule "dport 25 dnat to 10.10.20.6:25"      tcp dport 25    dnat to 10.10.20.6:25
rule "dport 6379 dnat to 10.10.20.6:6379"  tcp dport 6379  dnat to 10.10.20.6:6379

# Module 4: MariaDB lure (port 3306 → container 10.10.20.4:3306)
rule "dport 3306 dnat to 10.10.20.4:3306"  tcp dport 3306  dnat to 10.10.20.4:3306

echo "honeypot-dnat: all rules applied."
