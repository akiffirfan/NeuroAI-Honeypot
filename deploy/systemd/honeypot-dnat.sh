#!/bin/bash
# honeypot-dnat.sh — apply honeypot DNAT rules idempotently.
# Reads the current PREROUTING chain once and only adds rules that are absent.
# Safe to run multiple times; does not create duplicates.
#
# Container IPs (honeypot-net 172.20.0.0/24, internal: false):
#   172.20.0.8  cowrie        (SSH lure)
#   172.20.0.6  opencanary    (FTP/Telnet/SMTP/Redis lures)
#   172.20.0.4  mariadb-lure  (MySQL lure)
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

# Module 2: Cowrie SSH (port 22 → container 172.20.0.8:2222)
rule "dport 22 dnat to 172.20.0.8:2222"    tcp dport 22    dnat to 172.20.0.8:2222

# Module 3: OpenCanary (same-port DNAT to container 172.20.0.6)
rule "dport 21 dnat to 172.20.0.6:21"      tcp dport 21    dnat to 172.20.0.6:21
rule "dport 23 dnat to 172.20.0.6:23"      tcp dport 23    dnat to 172.20.0.6:23
rule "dport 25 dnat to 172.20.0.6:25"      tcp dport 25    dnat to 172.20.0.6:25
rule "dport 6379 dnat to 172.20.0.6:6379"  tcp dport 6379  dnat to 172.20.0.6:6379

# Module 4: MariaDB lure (port 3306 → container 172.20.0.4:3306)
rule "dport 3306 dnat to 172.20.0.4:3306"  tcp dport 3306  dnat to 172.20.0.4:3306

echo "honeypot-dnat: all rules applied."
