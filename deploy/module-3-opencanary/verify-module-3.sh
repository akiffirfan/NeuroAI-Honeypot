#!/usr/bin/env bash
# verify-module-3.sh — Module 3 (OpenCanary) post-deployment verification
#
# Run from /opt/honeypot/deploy/module-3-opencanary/ after:
#   docker compose up -d
#
# All 8 checks must PASS before proceeding to Module 4 (mariadb-lure).
#
# Exit codes:
#   0 — all checks passed
#   1 — one or more checks failed
#
# After this script passes:
#   - Proceed to Module 4: deploy/module-4-mariadb-lure/
#   - Module 4 adds the mariadb-lure container (port 3306) — NOT OpenCanary's MySQL module.
#   - After Module 4 verifies, run the nftables DNAT rules for ports 21/23/25/6379 (Step 20
#     in the deployment sequence — Section 9 of honeypot-project-plans.md), then open those
#     ports at the VPS provider firewall.

set -euo pipefail

PASS=0
FAIL=0
RESULTS=()

check() {
    local id="$1"
    local desc="$2"
    local result="$3"   # "pass" or "fail"
    local detail="${4:-}"

    if [[ "$result" == "pass" ]]; then
        RESULTS+=("  [PASS] Check $id: $desc")
        (( PASS++ )) || true
    else
        RESULTS+=("  [FAIL] Check $id: $desc${detail:+ — $detail}")
        (( FAIL++ )) || true
    fi
}

echo ""
echo "======================================================="
echo "  Module 3 — OpenCanary Verification"
echo "======================================================="
echo ""

# ---------------------------------------------------------------------------
# Check 1: OpenCanary container is running
# ---------------------------------------------------------------------------
if docker inspect --format '{{.State.Status}}' opencanary 2>/dev/null | grep -q "^running$"; then
    check 1 "OpenCanary container is running" "pass"
else
    check 1 "OpenCanary container is running" "fail" \
        "run: docker ps -a | grep opencanary; docker logs opencanary"
fi

# ---------------------------------------------------------------------------
# Check 2: All four ports (21, 23, 25, 6379) are listening on 127.0.0.1 only
# ---------------------------------------------------------------------------
PORTS_OK=true
PORTS_DETAIL=""
for PORT in 21 23 25 6379; do
    # Must appear as 127.0.0.1:<port> — NOT 0.0.0.0:<port>
    if ss -tlnp 2>/dev/null | grep -q "127\.0\.0\.1:${PORT}\b"; then
        : # good — loopback only
    else
        PORTS_OK=false
        PORTS_DETAIL="${PORTS_DETAIL} port ${PORT} not found on 127.0.0.1"
    fi
    # Explicitly check it is NOT on 0.0.0.0
    if ss -tlnp 2>/dev/null | grep -q "0\.0\.0\.0:${PORT}\b"; then
        PORTS_OK=false
        PORTS_DETAIL="${PORTS_DETAIL} port ${PORT} exposed on 0.0.0.0 (should be loopback only)"
    fi
done
if $PORTS_OK; then
    check 2 "Ports 21/23/25/6379 listening on 127.0.0.1 only (not 0.0.0.0)" "pass"
else
    check 2 "Ports 21/23/25/6379 listening on 127.0.0.1 only (not 0.0.0.0)" "fail" \
        "$PORTS_DETAIL"
fi

# ---------------------------------------------------------------------------
# Check 3: Container is on honeypot-net and NOT on default bridge
# ---------------------------------------------------------------------------
NETWORKS=$(docker inspect --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' opencanary 2>/dev/null || echo "")

ON_HONEYPOT=false
ON_BRIDGE=false

# Use a for loop (not a pipeline) so set -e doesn't trigger on if/then branches
for _net in $NETWORKS; do
    if [[ "$_net" == "honeypot-net" ]]; then
        ON_HONEYPOT=true
    fi
    if [[ "$_net" == "bridge" ]]; then
        ON_BRIDGE=true
    fi
done

if [[ "$ON_HONEYPOT" == "true" ]] && [[ "$ON_BRIDGE" == "false" ]]; then
    check 3 "Container on honeypot-net only (not on default bridge)" "pass"
else
    NET3_DETAIL=""
    if [[ "$ON_HONEYPOT" == "false" ]]; then
        NET3_DETAIL="${NET3_DETAIL}not on honeypot-net "
    fi
    if [[ "$ON_BRIDGE" == "true" ]]; then
        NET3_DETAIL="${NET3_DETAIL}unexpectedly on default bridge "
    fi
    check 3 "Container on honeypot-net only (not on default bridge)" "fail" \
        "${NET3_DETAIL}(networks found: $NETWORKS)"
fi

# ---------------------------------------------------------------------------
# Check 4: Port 5900 (VNC) is NOT published by this container
# ---------------------------------------------------------------------------
VNC_PUBLISHED=$(docker inspect --format '{{json .NetworkSettings.Ports}}' opencanary 2>/dev/null | grep -c '"5900/' || true)
if [[ "$VNC_PUBLISHED" -eq 0 ]]; then
    check 4 "Port 5900 (VNC) is NOT published — VNC dropped per Section 3.4 decision" "pass"
else
    check 4 "Port 5900 (VNC) is NOT published — VNC dropped per Section 3.4 decision" "fail" \
        "5900 found in port map — remove VNC from compose and opencanary.conf"
fi

# ---------------------------------------------------------------------------
# Check 5: Port 3306 (MySQL) is NOT published by this container
# ---------------------------------------------------------------------------
MYSQL_PUBLISHED=$(docker inspect --format '{{json .NetworkSettings.Ports}}' opencanary 2>/dev/null | grep -c '"3306/' || true)
if [[ "$MYSQL_PUBLISHED" -eq 0 ]]; then
    check 5 "Port 3306 (MySQL) is NOT published — MySQL owned by mariadb-lure (Module 4)" "pass"
else
    check 5 "Port 3306 (MySQL) is NOT published — MySQL owned by mariadb-lure (Module 4)" "fail" \
        "3306 found in port map — remove MySQL from compose and set mysql.enabled:false in opencanary.conf"
fi

# ---------------------------------------------------------------------------
# Check 6: opencanary-logs named volume exists
# ---------------------------------------------------------------------------
if docker volume inspect opencanary-logs >/dev/null 2>&1; then
    check 6 "Named volume opencanary-logs exists" "pass"
else
    check 6 "Named volume opencanary-logs exists" "fail" \
        "run: docker volume ls | grep opencanary-logs"
fi

# ---------------------------------------------------------------------------
# Check 7: opencanary.conf bind-mount is present and read-only
# ---------------------------------------------------------------------------
MOUNT_INFO=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/etc/opencanaryd/opencanary.conf"}}Mode={{.Mode}} RW={{.RW}}{{end}}{{end}}' opencanary 2>/dev/null || echo "")

if echo "$MOUNT_INFO" | grep -q "RW=false"; then
    check 7 "opencanary.conf bind-mount present and read-only" "pass"
elif echo "$MOUNT_INFO" | grep -q "RW=true"; then
    check 7 "opencanary.conf bind-mount present and read-only" "fail" \
        "mount found but is read-write — add :ro to the volume binding in docker-compose.yml"
else
    check 7 "opencanary.conf bind-mount present and read-only" "fail" \
        "no mount found at /etc/opencanaryd/opencanary.conf — did you create ../../config/opencanary/opencanary.conf before compose up?"
fi

# ---------------------------------------------------------------------------
# Check 8: FTP banner test — nc returns a 220 response on port 21
# ---------------------------------------------------------------------------
# Send a blank line to trigger the banner, capture first line, wait up to 3 seconds
FTP_BANNER=""
if command -v nc >/dev/null 2>&1; then
    FTP_BANNER=$(echo "" | nc -w3 127.0.0.1 21 2>/dev/null | head -1 || true)
fi

if echo "$FTP_BANNER" | grep -q "^220"; then
    check 8 "FTP banner test: port 21 returns 220 response" "pass"
else
    if [[ -z "$FTP_BANNER" ]]; then
        check 8 "FTP banner test: port 21 returns 220 response" "fail" \
            "no response received — is OpenCanary running and ftp.enabled:true in opencanary.conf? (got: empty)"
    else
        check 8 "FTP banner test: port 21 returns 220 response" "fail" \
            "unexpected banner (got: $FTP_BANNER)"
    fi
fi

# ---------------------------------------------------------------------------
# Results summary
# ---------------------------------------------------------------------------
echo ""
echo "-------------------------------------------------------"
echo "  Results:"
echo "-------------------------------------------------------"
for line in "${RESULTS[@]}"; do
    echo "$line"
done
echo ""
echo "-------------------------------------------------------"
echo "  Summary: ${PASS} passed, ${FAIL} failed (of 8 checks)"
echo "-------------------------------------------------------"
echo ""

if [[ "$FAIL" -eq 0 ]]; then
    echo "  All checks PASSED — Module 3 (OpenCanary) is ready."
    echo ""
    echo "  Next step: deploy/module-4-mariadb-lure/"
    echo "  (mariadb-lure — real MariaDB on port 3306 with fake neuro_prod schema)"
    echo ""
    exit 0
else
    echo "  FAILED — ${FAIL} check(s) did not pass. Fix issues above before"
    echo "  proceeding to Module 4."
    echo ""
    echo "  Useful debug commands:"
    echo "    docker logs opencanary"
    echo "    docker inspect opencanary"
    echo "    docker exec opencanary cat /etc/opencanaryd/opencanary.conf"
    echo "    ss -tlnp | grep -E ':(21|23|25|6379)'"
    echo ""
    exit 1
fi
