#!/bin/bash
# honeypot-dnat.sh — apply honeypot DNAT rules idempotently.
# Reads the current prerouting chain once and only adds rules that are absent.
# Safe to run multiple times; does not create duplicates.
#
# Container IPs (honeypot-net 10.10.20.0/24, internal: false):
#   10.10.20.8  cowrie        (SSH lure)
#   10.10.20.6  opencanary    (FTP/Telnet/Redis lures; smtp.enabled=false, smb.enabled=false)
#   10.10.20.5  smtp-lure     (DEFERRED — not deployed; port 25 dark)
#   10.10.20.4  mariadb-lure  (MySQL lure)
#
# WHY a separate nft table (not ip nat PREROUTING):
#   Docker owns the "ip nat" table via iptables-nft. Rules added to that table
#   via pure nft commands appear in "nft list" but are silently never executed —
#   the kernel only processes iptables-nft rules added through iptables-nft
#   tooling, not through the nft tool. We own a separate "honeypot-dnat" table
#   at priority dstnat-5 (-105) so our rules run before Docker's nat hooks.
#
# iif "eth0" restriction: required so br_netfilter does not intercept
# container-to-container bridge traffic on the same ports (e.g. port 6379
# Redis — without iif restriction, log-shipper->redis packets would be
# redirected to OpenCanary's fake Redis).

set -euo pipefail

# ── Ensure honeypot-dnat nft table and prerouting chain exist ──────────────
# "|| true" handles the "already exists" case — if table/chain exist we keep
# them (and their rules); if not we create them fresh.
nft add table ip honeypot-dnat 2>/dev/null || true
nft add chain ip honeypot-dnat prerouting \
    '{ type nat hook prerouting priority -105; policy accept; }' 2>/dev/null || true

CHAIN=$(nft list chain ip honeypot-dnat prerouting 2>/dev/null || true)

# rule <grep-pattern> <nft-args...>
# Adds "nft add rule ip honeypot-dnat prerouting iif eth0 <nft-args>" only if
# <grep-pattern> is not already present in the chain output.
rule() {
    local pat="$1"; shift
    if echo "$CHAIN" | grep -q "$pat"; then
        echo "honeypot-dnat: already present — $pat"
    else
        nft add rule ip honeypot-dnat prerouting iif eth0 "$@"
        echo "honeypot-dnat: added — iif eth0 $*"
    fi
}

# Module 2: Cowrie SSH (port 22 → container 10.10.20.8:2222)
rule "dport 22 dnat to 10.10.20.8:2222"    tcp dport 22    dnat to 10.10.20.8:2222

# Cowrie FORWARD rule — inserted into DOCKER-USER (not bare FORWARD) so it
# survives docker compose down/up by any co-tenant on this VPS. Docker never
# flushes DOCKER-USER; it only rewrites the DOCKER and FORWARD chains.
# No interface conditions needed — DNAT in PREROUTING already scopes to iif eth0.
if ! iptables -C DOCKER-USER -d 10.10.20.8/32 -p tcp --dport 2222 -j ACCEPT 2>/dev/null; then
    iptables -I DOCKER-USER 1 -d 10.10.20.8/32 -p tcp --dport 2222 -j ACCEPT
    echo "honeypot-dnat: added DOCKER-USER ACCEPT for cowrie 10.10.20.8:2222"
else
    echo "honeypot-dnat: DOCKER-USER rule for cowrie already present"
fi
# Remove old bare-FORWARD rule if it was previously inserted there
if iptables -C FORWARD -d 10.10.20.8/32 -p tcp --dport 2222 -j ACCEPT 2>/dev/null; then
    iptables -D FORWARD -d 10.10.20.8/32 -p tcp --dport 2222 -j ACCEPT
    echo "honeypot-dnat: removed stale FORWARD rule (migrated to DOCKER-USER)"
fi

# Module 3: OpenCanary (same-port DNAT to container 10.10.20.6)
rule "dport 21 dnat to 10.10.20.6:21"      tcp dport 21    dnat to 10.10.20.6:21
rule "dport 23 dnat to 10.10.20.6:23"      tcp dport 23    dnat to 10.10.20.6:23
rule "dport 6379 dnat to 10.10.20.6:6379"  tcp dport 6379  dnat to 10.10.20.6:6379

# SMTP port 25: Module 8 (smtp-lure) DEFERRED — cover story mismatch, open relay abuse risk.
# Port 25 DNAT left out intentionally; OpenCanary smtp.enabled=false so port 25 is dark.

# Module 4: MariaDB lure (port 3306 → container 10.10.20.4:3306)
rule "dport 3306 dnat to 10.10.20.4:3306"  tcp dport 3306  dnat to 10.10.20.4:3306

# MariaDB FORWARD rule — MariaDB has no published ports: so Docker never creates a
# DOCKER chain ACCEPT for it. Must be in DOCKER-USER (survives co-tenant restarts).
if ! iptables -C DOCKER-USER -d 10.10.20.4/32 -p tcp --dport 3306 -j ACCEPT 2>/dev/null; then
    iptables -I DOCKER-USER 1 -d 10.10.20.4/32 -p tcp --dport 3306 -j ACCEPT
    echo "honeypot-dnat: added DOCKER-USER ACCEPT for mariadb-lure 10.10.20.4:3306"
else
    echo "honeypot-dnat: DOCKER-USER rule for mariadb-lure already present"
fi

# Port 445 (SMB): REVERTED — OpenCanary SMB module requires a running Samba/smbd
# with full_audit VFS; no samba in the Dockerfile; dark 445 is a fingerprint tell.
# Do not re-enable without: samba in Dockerfile, smb.conf full_audit, bind 445 in
# compose, and a verified smbclient -L event landing in opencanary.json.

echo "honeypot-dnat: all rules applied."
