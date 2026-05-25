#!/usr/bin/env bash
# verify-module-5.sh — Module 5 (log-shipper) post-deployment verification
#
# Run from /opt/honeypot/deploy/module-5-log-shipper/ after:
#   docker compose up -d --build
#
# All 8 checks must PASS before proceeding to Module 6.
#
# Exit codes:
#   0 — all checks passed
#   1 — one or more checks failed

set -euo pipefail

PASS=0
FAIL=0
RESULTS=()

check() {
    local id="$1"
    local desc="$2"
    local result="$3"
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
echo "  Module 5 — log-shipper Verification"
echo "======================================================="
echo ""

# Load .env so we can query Postgres/Redis with the right password
if [[ -f .env ]]; then
    # Export only the variables we need — do not export the whole file
    POSTGRES_PASSWORD=$(grep "^POSTGRES_PASSWORD=" .env 2>/dev/null | cut -d= -f2 || echo "")
    REDIS_PASSWORD=$(grep "^REDIS_PASSWORD=" .env 2>/dev/null | cut -d= -f2 || echo "")
else
    POSTGRES_PASSWORD=""
    REDIS_PASSWORD=""
fi

# ---------------------------------------------------------------------------
# Check 1: log-shipper container is running and healthy
# ---------------------------------------------------------------------------
CONTAINER_STATUS=$(docker inspect --format '{{.State.Status}}' log-shipper 2>/dev/null || echo "missing")
HEALTH_STATUS=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' log-shipper 2>/dev/null || echo "missing")

if [[ "$CONTAINER_STATUS" == "running" ]]; then
    if [[ "$HEALTH_STATUS" == "healthy" ]]; then
        check 1 "log-shipper container is running and healthy" "pass"
    elif [[ "$HEALTH_STATUS" == "starting" ]]; then
        check 1 "log-shipper container is running and healthy" "fail" \
            "health check still 'starting' — wait 30s and retry"
    else
        check 1 "log-shipper container is running and healthy" "fail" \
            "status=$CONTAINER_STATUS health=$HEALTH_STATUS — run: docker logs log-shipper"
    fi
else
    check 1 "log-shipper container is running and healthy" "fail" \
        "container status: $CONTAINER_STATUS — run: docker logs log-shipper"
fi

# ---------------------------------------------------------------------------
# Check 2: Container is on BOTH honeypot-net AND data-net
# ---------------------------------------------------------------------------
NETWORKS=$(docker inspect --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' log-shipper 2>/dev/null || echo "")

ON_HONEYPOT=false
ON_DATA=false

for _net in $NETWORKS; do
    if [[ "$_net" == "honeypot-net" ]]; then ON_HONEYPOT=true; fi
    if [[ "$_net" == "data-net" ]];    then ON_DATA=true;    fi
done

if [[ "$ON_HONEYPOT" == "true" ]] && [[ "$ON_DATA" == "true" ]]; then
    check 2 "Container on honeypot-net AND data-net" "pass"
else
    NET_DETAIL=""
    if [[ "$ON_HONEYPOT" == "false" ]]; then NET_DETAIL="${NET_DETAIL}not on honeypot-net "; fi
    if [[ "$ON_DATA"   == "false"   ]]; then NET_DETAIL="${NET_DETAIL}not on data-net "; fi
    check 2 "Container on honeypot-net AND data-net" "fail" \
        "${NET_DETAIL}(found: $NETWORKS)"
fi

# ---------------------------------------------------------------------------
# Check 3: Health endpoint :9100/healthz responds with HTTP 200
# ---------------------------------------------------------------------------
HEALTH_RESP=$(docker exec log-shipper \
    python -c "import urllib.request, sys; r=urllib.request.urlopen('http://localhost:9100/healthz',timeout=3); sys.exit(0 if r.status==200 else 1)" \
    2>/dev/null && echo "ok" || echo "fail")

if [[ "$HEALTH_RESP" == "ok" ]]; then
    check 3 "Health endpoint :9100/healthz returns HTTP 200" "pass"
else
    check 3 "Health endpoint :9100/healthz returns HTTP 200" "fail" \
        "service not responding — run: docker logs log-shipper | tail -20"
fi

# ---------------------------------------------------------------------------
# Check 4: Log volumes are mounted read-only
# ---------------------------------------------------------------------------
VOL_OK=true
VOL_DETAIL=""
declare -A EXPECTED_MOUNTS=(
    ["/var/log/cowrie"]="cowrie-logs"
    ["/var/log/opencanary"]="opencanary-logs"
    ["/var/log/mariadb"]="mariadb-logs"
)

for DEST in "/var/log/cowrie" "/var/log/opencanary" "/var/log/mariadb"; do
    MOUNT_RW=$(docker inspect --format \
        "{{range .Mounts}}{{if eq .Destination \"${DEST}\"}}{{.RW}}{{end}}{{end}}" \
        log-shipper 2>/dev/null || echo "")
    if [[ "$MOUNT_RW" == "false" ]]; then
        : # good — read-only
    elif [[ "$MOUNT_RW" == "true" ]]; then
        VOL_OK=false
        VOL_DETAIL="${VOL_DETAIL} $DEST is read-write (should be :ro)"
    else
        VOL_OK=false
        VOL_DETAIL="${VOL_DETAIL} $DEST not mounted"
    fi
done

if $VOL_OK; then
    check 4 "All log volumes mounted read-only (cowrie/opencanary/mariadb)" "pass"
else
    check 4 "All log volumes mounted read-only (cowrie/opencanary/mariadb)" "fail" \
        "$VOL_DETAIL"
fi

# ---------------------------------------------------------------------------
# Check 5: PostgreSQL connection works from inside the container
# ---------------------------------------------------------------------------
if [[ -n "$POSTGRES_PASSWORD" ]]; then
    PG_OK=$(docker exec log-shipper \
        python -c "
import psycopg2, os, sys
try:
    dsn = os.environ.get('POSTGRES_DSN', '')
    conn = psycopg2.connect(dsn)
    cur = conn.cursor()
    cur.execute('SELECT COUNT(*) FROM honeypot_events')
    count = cur.fetchone()[0]
    conn.close()
    print(f'ok:{count}')
except Exception as e:
    print(f'fail:{e}')
" 2>/dev/null || echo "fail:exec-error")

    if echo "$PG_OK" | grep -q "^ok:"; then
        ROW_COUNT=$(echo "$PG_OK" | cut -d: -f2)
        check 5 "PostgreSQL connection OK — honeypot_events has $ROW_COUNT rows" "pass"
    else
        PG_ERROR=$(echo "$PG_OK" | cut -d: -f2-)
        check 5 "PostgreSQL connection OK" "fail" \
            "$PG_ERROR — check POSTGRES_PASSWORD in .env matches Module 1 .env"
    fi
else
    check 5 "PostgreSQL connection OK" "fail" \
        "POSTGRES_PASSWORD not set in .env — copy from /opt/honeypot/deploy/module-1-data-layer/.env"
fi

# ---------------------------------------------------------------------------
# Check 6: Redis connection works from inside the container
# ---------------------------------------------------------------------------
REDIS_OK=$(docker exec log-shipper \
    python -c "
import redis as r, os, sys
try:
    url = os.environ.get('REDIS_URL', '')
    client = r.from_url(url, socket_connect_timeout=3)
    client.ping()
    print('ok')
except Exception as e:
    print(f'fail:{e}')
" 2>/dev/null || echo "fail:exec-error")

if [[ "$REDIS_OK" == "ok" ]]; then
    check 6 "Redis connection OK" "pass"
else
    REDIS_ERROR=$(echo "$REDIS_OK" | cut -d: -f2-)
    check 6 "Redis connection OK" "fail" \
        "$REDIS_ERROR — check REDIS_PASSWORD in .env matches config/redis/redis.conf"
fi

# ---------------------------------------------------------------------------
# Check 7: Log source directories exist and are accessible inside the container
# ---------------------------------------------------------------------------
LOG_DIRS_OK=true
LOG_DIRS_DETAIL=""
for LOG_DIR in /var/log/cowrie /var/log/opencanary /var/log/mariadb; do
    EXISTS=$(docker exec log-shipper sh -c "test -d $LOG_DIR && echo yes || echo no" 2>/dev/null || echo "no")
    if [[ "$EXISTS" != "yes" ]]; then
        LOG_DIRS_OK=false
        LOG_DIRS_DETAIL="${LOG_DIRS_DETAIL} $LOG_DIR missing"
    fi
done

if $LOG_DIRS_OK; then
    check 7 "Log source directories accessible inside container" "pass"
else
    check 7 "Log source directories accessible inside container" "fail" \
        "$LOG_DIRS_DETAIL — volume mount may be missing or empty"
fi

# ---------------------------------------------------------------------------
# Check 8: GeoIP databases present (warn if missing — non-fatal)
# ---------------------------------------------------------------------------
CITY_OK=$(docker exec log-shipper sh -c "test -f /geoip/GeoLite2-City.mmdb && echo yes || echo no" 2>/dev/null || echo "no")
ASN_OK=$(docker exec log-shipper sh -c "test -f /geoip/GeoLite2-ASN.mmdb && echo yes || echo no" 2>/dev/null || echo "no")

if [[ "$CITY_OK" == "yes" ]] && [[ "$ASN_OK" == "yes" ]]; then
    check 8 "GeoIP databases present (City + ASN)" "pass"
else
    GEOIP_DETAIL=""
    if [[ "$CITY_OK" != "yes" ]]; then GEOIP_DETAIL="${GEOIP_DETAIL}GeoLite2-City.mmdb missing "; fi
    if [[ "$ASN_OK"  != "yes" ]]; then GEOIP_DETAIL="${GEOIP_DETAIL}GeoLite2-ASN.mmdb missing "; fi
    check 8 "GeoIP databases present (City + ASN)" "fail" \
        "${GEOIP_DETAIL}— see Step 3 in the deployment instructions to populate the geoip-data volume. Events will still be stored without geo enrichment."
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
    echo "  All checks PASSED — Module 5 (log-shipper) is ready."
    echo ""
    echo "  To verify events are flowing, trigger a test connection:"
    echo "    ssh -p 22 root@143.198.195.132  (will hit Cowrie; any password)"
    echo "  Then check Postgres:"
    echo "    docker exec postgres psql -U honeypot -d honeypot -c 'SELECT sensor, event_type, src_ip, created_at FROM honeypot_events ORDER BY created_at DESC LIMIT 5;'"
    echo ""
    echo "  Next module: deploy/module-6-honeypot-api/"
    echo "  (FastAPI deceptive HTTP honeypot — neurodata.me fake ML platform)"
    echo ""
    exit 0
else
    echo "  FAILED — ${FAIL} check(s) did not pass."
    echo ""
    echo "  Useful debug commands:"
    echo "    docker logs log-shipper"
    echo "    docker logs log-shipper 2>&1 | grep -i 'error\|fail\|warn'"
    echo "    docker exec log-shipper python -c \"import psycopg2; print('psycopg2 ok')\""
    echo "    docker network ls | grep -E 'honeypot-net|data-net'"
    echo "    docker volume ls | grep -E 'cowrie-logs|opencanary-logs|mariadb-logs'"
    echo ""
    exit 1
fi
