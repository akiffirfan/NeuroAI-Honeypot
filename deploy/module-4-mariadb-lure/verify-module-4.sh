#!/usr/bin/env bash
# verify-module-4.sh — Module 4 (mariadb-lure) post-deployment verification
#
# Run from /opt/honeypot/deploy/module-4-mariadb-lure/ after:
#   docker compose up -d
#   (wait ~45s for MariaDB init SQL to complete before running this)
#
# All 10 checks must PASS before proceeding to Module 5 (log-shipper).
#
# Exit codes:
#   0 — all checks passed
#   1 — one or more checks failed
#
# After this script passes:
#   - DNAT rule for port 3306 is already in honeypot-dnat.service (added during Module 2/3 setup).
#     Verify it is active: sudo nft list chain ip nat PREROUTING | grep 3306
#   - Proceed to Module 5: deploy/module-5-log-shipper/
#     Module 5 tails mariadb-logs volume (/var/log/mysql/general.log) to capture
#     every attacker connection and query into the unified PostgreSQL pipeline.

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
echo "  Module 4 — mariadb-lure Verification"
echo "======================================================="
echo ""

# Load root password from .env for SQL checks (checks 8–10)
MARIADB_ROOT_PASSWORD=""
if [[ -f ".env" ]]; then
    MARIADB_ROOT_PASSWORD=$(grep '^MARIADB_ROOT_PASSWORD=' .env | cut -d= -f2 | tr -d '"'"'" || true)
fi

# ---------------------------------------------------------------------------
# Check 1: mariadb-lure container is running
# ---------------------------------------------------------------------------
if docker inspect --format '{{.State.Status}}' mariadb-lure 2>/dev/null | grep -q "^running$"; then
    check 1 "mariadb-lure container is running" "pass"
else
    check 1 "mariadb-lure container is running" "fail" \
        "run: docker ps -a | grep mariadb-lure; docker logs mariadb-lure"
fi

# ---------------------------------------------------------------------------
# Check 2: Port 3306 is NOT published on host (no ports: binding — ctf-db-1 conflict)
# External access is via direct container-IP DNAT to 10.10.20.4:3306
# ---------------------------------------------------------------------------
HOST_PORTS=$(docker inspect --format '{{json .NetworkSettings.Ports}}' mariadb-lure 2>/dev/null || echo "{}")
if echo "$HOST_PORTS" | grep -q '"3306/tcp":\['; then
    check 2 "Port 3306 NOT published on host (direct container-IP DNAT used)" "fail" \
        "3306 is published to host — remove ports: binding from docker-compose.yml"
else
    check 2 "Port 3306 NOT published on host (direct container-IP DNAT used)" "pass"
fi

# ---------------------------------------------------------------------------
# Check 3: Container is on honeypot-net only (not default bridge)
# ---------------------------------------------------------------------------
NETWORKS=$(docker inspect --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' mariadb-lure 2>/dev/null || echo "")

ON_HONEYPOT=false
ON_BRIDGE=false
for _net in $NETWORKS; do
    if [[ "$_net" == "honeypot-net" ]]; then ON_HONEYPOT=true; fi
    if [[ "$_net" == "bridge" ]]; then ON_BRIDGE=true; fi
done

if [[ "$ON_HONEYPOT" == "true" ]] && [[ "$ON_BRIDGE" == "false" ]]; then
    check 3 "Container on honeypot-net only (not on default bridge)" "pass"
else
    NET3_DETAIL=""
    if [[ "$ON_HONEYPOT" == "false" ]]; then NET3_DETAIL="${NET3_DETAIL}not on honeypot-net "; fi
    if [[ "$ON_BRIDGE" == "true" ]]; then  NET3_DETAIL="${NET3_DETAIL}unexpectedly on default bridge "; fi
    check 3 "Container on honeypot-net only (not on default bridge)" "fail" \
        "${NET3_DETAIL}(networks found: $NETWORKS)"
fi

# ---------------------------------------------------------------------------
# Check 4: mariadb-data named volume exists
# ---------------------------------------------------------------------------
if docker volume inspect mariadb-data >/dev/null 2>&1; then
    check 4 "Named volume mariadb-data exists" "pass"
else
    check 4 "Named volume mariadb-data exists" "fail" \
        "run: docker volume ls | grep mariadb-data"
fi

# ---------------------------------------------------------------------------
# Check 5: mariadb-logs named volume exists
# ---------------------------------------------------------------------------
if docker volume inspect mariadb-logs >/dev/null 2>&1; then
    check 5 "Named volume mariadb-logs exists" "pass"
else
    check 5 "Named volume mariadb-logs exists" "fail" \
        "run: docker volume ls | grep mariadb-logs"
fi

# ---------------------------------------------------------------------------
# Check 6: general.log exists inside the mariadb-logs volume
# ---------------------------------------------------------------------------
LOG_EXISTS=$(docker exec mariadb-lure test -f /var/log/mysql/general.log 2>/dev/null && echo "yes" || echo "no")
if [[ "$LOG_EXISTS" == "yes" ]]; then
    check 6 "general.log exists in mariadb-logs volume" "pass"
else
    check 6 "general.log exists in mariadb-logs volume" "fail" \
        "pre-create with: docker run --rm -v mariadb-logs:/var/log/mysql alpine sh -c 'touch /var/log/mysql/general.log && chmod 666 /var/log/mysql/general.log'"
fi

# ---------------------------------------------------------------------------
# Check 7: Container healthcheck is healthy
# ---------------------------------------------------------------------------
HEALTH=$(docker inspect --format '{{.State.Health.Status}}' mariadb-lure 2>/dev/null || echo "none")
if [[ "$HEALTH" == "healthy" ]]; then
    check 7 "Container healthcheck is healthy" "pass"
elif [[ "$HEALTH" == "starting" ]]; then
    check 7 "Container healthcheck is healthy" "fail" \
        "healthcheck still starting — wait another 30s and re-run (start_period is 45s)"
else
    check 7 "Container healthcheck is healthy" "fail" \
        "status: $HEALTH — run: docker inspect mariadb-lure | grep -A5 Health"
fi

# ---------------------------------------------------------------------------
# Checks 8–10 require root SQL access — skip if password unavailable
# ---------------------------------------------------------------------------
if [[ -z "$MARIADB_ROOT_PASSWORD" ]]; then
    check 8 "general_log=ON confirmed via SQL" "fail" \
        ".env not found or MARIADB_ROOT_PASSWORD empty — SQL checks skipped"
    check 9 "neuro_prod has all 5 expected tables" "fail" \
        ".env not found or MARIADB_ROOT_PASSWORD empty — SQL checks skipped"
    check 10 "neuro_app is SELECT-only on neuro_prod" "fail" \
        ".env not found or MARIADB_ROOT_PASSWORD empty — SQL checks skipped"
else
    MYSQL_CMD="docker exec mariadb-lure mariadb -u root -p${MARIADB_ROOT_PASSWORD} --batch --skip-column-names"

    # -------------------------------------------------------------------------
    # Check 8: general_log is ON
    # -------------------------------------------------------------------------
    GENLOG=$($MYSQL_CMD -e "SHOW GLOBAL VARIABLES LIKE 'general_log';" 2>/dev/null | awk '{print $2}' || true)
    if [[ "$GENLOG" == "ON" ]]; then
        check 8 "general_log=ON confirmed via SQL" "pass"
    else
        check 8 "general_log=ON confirmed via SQL" "fail" \
            "got: '${GENLOG}' — check honeypot.cnf bind-mount and conf.d permissions (must be world-readable)"
    fi

    # -------------------------------------------------------------------------
    # Check 9: neuro_prod has all 5 expected tables
    # -------------------------------------------------------------------------
    TABLES=$($MYSQL_CMD -e "SHOW TABLES IN neuro_prod;" 2>/dev/null | sort || true)
    EXPECTED="dataset_metadata gpu_jobs models training_runs users"
    ACTUAL=$(echo "$TABLES" | tr '\n' ' ' | xargs | tr ' ' '\n' | sort | tr '\n' ' ' | xargs)
    if [[ "$ACTUAL" == "$EXPECTED" ]]; then
        check 9 "neuro_prod has all 5 expected tables" "pass"
    else
        check 9 "neuro_prod has all 5 expected tables" "fail" \
            "expected: [$EXPECTED] got: [$ACTUAL] — init SQL may not have run (volume not empty?)"
    fi

    # -------------------------------------------------------------------------
    # Check 10: neuro_app is SELECT-only on neuro_prod (no INSERT/UPDATE/DELETE)
    # -------------------------------------------------------------------------
    GRANTS=$($MYSQL_CMD -e "SHOW GRANTS FOR 'neuro_app'@'%';" 2>/dev/null || true)
    HAS_SELECT=$(echo "$GRANTS" | grep -ci "GRANT SELECT" || true)
    HAS_INSERT=$(echo "$GRANTS" | grep -ci "GRANT.*INSERT\|ALL PRIVILEGES" || true)
    if [[ "$HAS_SELECT" -ge 1 ]] && [[ "$HAS_INSERT" -eq 0 ]]; then
        check 10 "neuro_app is SELECT-only on neuro_prod" "pass"
    elif [[ "$HAS_SELECT" -eq 0 ]]; then
        check 10 "neuro_app is SELECT-only on neuro_prod" "fail" \
            "GRANT SELECT not found — init SQL REVOKE/GRANT may have failed"
    else
        check 10 "neuro_app is SELECT-only on neuro_prod" "fail" \
            "neuro_app has INSERT/UPDATE/DELETE or ALL PRIVILEGES — init SQL REVOKE did not execute"
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
echo "  Summary: ${PASS} passed, ${FAIL} failed (of 10 checks)"
echo "-------------------------------------------------------"
echo ""

if [[ "$FAIL" -eq 0 ]]; then
    echo "  All checks PASSED — Module 4 (mariadb-lure) is ready."
    echo ""
    echo "  Next steps:"
    echo "    1. Verify DNAT rule for port 3306 is active:"
    echo "       sudo nft list chain ip nat PREROUTING | grep 3306"
    echo "       (should show: dnat to 10.10.20.4:3306)"
    echo "    2. Proceed to Module 5: deploy/module-5-log-shipper/"
    echo "       Module 5 tails mariadb-logs volume to capture attacker queries."
    echo ""
    exit 0
else
    echo "  FAILED — ${FAIL} check(s) did not pass. Fix issues above before"
    echo "  proceeding to Module 5."
    echo ""
    echo "  Useful debug commands:"
    echo "    docker logs mariadb-lure"
    echo "    docker exec mariadb-lure mariadb -u root -p\${MARIADB_ROOT_PASSWORD} -e 'SHOW DATABASES;'"
    echo "    docker exec mariadb-lure cat /etc/mysql/conf.d/honeypot.cnf"
    echo "    ss -tlnp | grep 3306"
    echo ""
    exit 1
fi
