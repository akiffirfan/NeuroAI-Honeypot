#!/usr/bin/env bash
# verify-module-6.sh — Module 6 (honeypot-api) post-deployment verification
#
# Run from /opt/honeypot/deploy/module-6-honeypot-api/ after:
#   docker compose up -d --build
#
# All 10 checks must PASS before proceeding to Module 7 (Nginx).
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
echo "  Module 6 — honeypot-api Verification"
echo "======================================================="
echo ""

# Load .env to pass passwords for DB checks
if [[ -f .env ]]; then
    POSTGRES_PASSWORD=$(grep "^POSTGRES_PASSWORD=" .env 2>/dev/null | cut -d= -f2 || echo "")
    REDIS_PASSWORD=$(grep "^REDIS_PASSWORD=" .env 2>/dev/null | cut -d= -f2 || echo "")
else
    POSTGRES_PASSWORD=""
    REDIS_PASSWORD=""
fi

# ---------------------------------------------------------------------------
# Check 1: honeypot-api container is running and healthy
# ---------------------------------------------------------------------------
CONTAINER_STATUS=$(docker inspect --format '{{.State.Status}}' honeypot-api 2>/dev/null || echo "missing")
HEALTH_STATUS=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' honeypot-api 2>/dev/null || echo "missing")

if [[ "$CONTAINER_STATUS" == "running" ]]; then
    if [[ "$HEALTH_STATUS" == "healthy" ]]; then
        check 1 "honeypot-api container is running and healthy" "pass"
    elif [[ "$HEALTH_STATUS" == "starting" ]]; then
        check 1 "honeypot-api container is running and healthy" "fail" \
            "health check still 'starting' — wait 30s and retry"
    else
        check 1 "honeypot-api container is running and healthy" "fail" \
            "status=$CONTAINER_STATUS health=$HEALTH_STATUS — run: docker logs honeypot-api"
    fi
else
    check 1 "honeypot-api container is running and healthy" "fail" \
        "container status: $CONTAINER_STATUS — run: docker logs honeypot-api"
fi

# ---------------------------------------------------------------------------
# Check 2: Container is on BOTH honeypot-net AND data-net
# ---------------------------------------------------------------------------
NETWORKS=$(docker inspect --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' honeypot-api 2>/dev/null || echo "")

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
# Check 3: Health endpoint :8080/api/v1/health returns 200 with status:ok
# ---------------------------------------------------------------------------
HEALTH_RESP=$(docker exec honeypot-api \
    python -c "
import urllib.request, json, sys
try:
    r = urllib.request.urlopen('http://localhost:8080/api/v1/health', timeout=5)
    data = json.loads(r.read())
    if data.get('status') == 'ok':
        print('ok')
    else:
        print('fail:unexpected_body:' + str(data))
except Exception as e:
    print('fail:' + str(e))
" 2>/dev/null || echo "fail:exec-error")

if [[ "$HEALTH_RESP" == "ok" ]]; then
    check 3 "GET /api/v1/health returns 200 with status:ok" "pass"
else
    check 3 "GET /api/v1/health returns 200 with status:ok" "fail" \
        "$HEALTH_RESP — run: docker logs honeypot-api | tail -20"
fi

# ---------------------------------------------------------------------------
# Check 4: Jupyter stub :8888 responds
# ---------------------------------------------------------------------------
JUPYTER_RESP=$(docker exec honeypot-api \
    python -c "
import urllib.request, sys
try:
    r = urllib.request.urlopen('http://localhost:8888/', timeout=5)
    code = r.getcode()
    print('ok:' + str(code))
except urllib.error.HTTPError as e:
    # Any HTTP response (even 4xx) means the stub is listening
    print('ok:' + str(e.code))
except Exception as e:
    print('fail:' + str(e))
" 2>/dev/null || echo "fail:exec-error")

if echo "$JUPYTER_RESP" | grep -q "^ok:"; then
    HTTP_CODE=$(echo "$JUPYTER_RESP" | cut -d: -f2)
    check 4 "Jupyter stub :8888 is listening (HTTP $HTTP_CODE)" "pass"
else
    check 4 "Jupyter stub :8888 is listening" "fail" \
        "$JUPYTER_RESP — ensure start.sh launched both uvicorn processes"
fi

# ---------------------------------------------------------------------------
# Check 5: PostgreSQL connection and honeypot_events table accessible
# ---------------------------------------------------------------------------
if [[ -n "$POSTGRES_PASSWORD" ]]; then
    PG_OK=$(docker exec honeypot-api \
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
# Check 6: Redis connection OK
# ---------------------------------------------------------------------------
REDIS_OK=$(docker exec honeypot-api \
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
# Check 7: GeoIP databases present at /geoip/
# ---------------------------------------------------------------------------
CITY_OK=$(docker exec honeypot-api sh -c "test -f /geoip/GeoLite2-City.mmdb && echo yes || echo no" 2>/dev/null || echo "no")
ASN_OK=$(docker exec honeypot-api sh -c "test -f /geoip/GeoLite2-ASN.mmdb && echo yes || echo no" 2>/dev/null || echo "no")

if [[ "$CITY_OK" == "yes" ]] && [[ "$ASN_OK" == "yes" ]]; then
    check 7 "GeoIP databases present at /geoip/ (City + ASN)" "pass"
else
    GEOIP_DETAIL=""
    if [[ "$CITY_OK" != "yes" ]]; then GEOIP_DETAIL="${GEOIP_DETAIL}GeoLite2-City.mmdb missing "; fi
    if [[ "$ASN_OK"  != "yes" ]]; then GEOIP_DETAIL="${GEOIP_DETAIL}GeoLite2-ASN.mmdb missing "; fi
    check 7 "GeoIP databases present at /geoip/" "fail" \
        "${GEOIP_DETAIL}— see Module 5 prerequisites for geoip-data volume population. Events still stored without geo enrichment."
fi

# ---------------------------------------------------------------------------
# Check 8: /.env lure returns 200 with fake AWS key
# ---------------------------------------------------------------------------
ENV_RESP=$(docker exec honeypot-api \
    python -c "
import urllib.request, sys
try:
    r = urllib.request.urlopen('http://localhost:8080/.env', timeout=5)
    body = r.read().decode('utf-8', errors='replace')
    if 'AKIAYZM57LXRGIYTCOUV' in body and 'AWS_ACCESS_KEY_ID' in body:
        print('ok')
    else:
        print('fail:key_missing')
except Exception as e:
    print('fail:' + str(e))
" 2>/dev/null || echo "fail:exec-error")

if [[ "$ENV_RESP" == "ok" ]]; then
    check 8 "GET /.env returns 200 with fake AWS key (AKIAYZM57LXRGIYTCOUV)" "pass"
else
    check 8 "GET /.env returns 200 with fake AWS key" "fail" \
        "$ENV_RESP"
fi

# ---------------------------------------------------------------------------
# Check 9: /api/v1/internal/config returns 200 with fake secrets JSON
# ---------------------------------------------------------------------------
CONFIG_RESP=$(docker exec honeypot-api \
    python -c "
import urllib.request, json, sys
try:
    r = urllib.request.urlopen('http://localhost:8080/api/v1/internal/config', timeout=5)
    data = json.loads(r.read())
    if data.get('aws_access_key_id') == 'AKIAYZM57LXRGIYTCOUV' and 'database_url' in data:
        print('ok')
    else:
        print('fail:unexpected_content:' + str(list(data.keys())))
except Exception as e:
    print('fail:' + str(e))
" 2>/dev/null || echo "fail:exec-error")

if [[ "$CONFIG_RESP" == "ok" ]]; then
    check 9 "GET /api/v1/internal/config returns fake secrets JSON" "pass"
else
    check 9 "GET /api/v1/internal/config returns fake secrets JSON" "fail" \
        "$CONFIG_RESP"
fi

# ---------------------------------------------------------------------------
# Check 10: POST /admin/login captures credentials and returns 401
# ---------------------------------------------------------------------------
ADMIN_RESP=$(docker exec honeypot-api \
    python -c "
import urllib.request, json, sys
try:
    data = json.dumps({'username': 'admin', 'password': 'test-verify'}).encode()
    req = urllib.request.Request(
        'http://localhost:8080/admin/login',
        data=data,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    try:
        r = urllib.request.urlopen(req, timeout=10)
        # If 2xx, that's wrong — should be 401
        print('fail:got_2xx:' + str(r.getcode()))
    except urllib.error.HTTPError as e:
        if e.code == 401:
            print('ok')
        else:
            print('fail:expected_401_got_' + str(e.code))
except Exception as e:
    print('fail:' + str(e))
" 2>/dev/null || echo "fail:exec-error")

if [[ "$ADMIN_RESP" == "ok" ]]; then
    check 10 "POST /admin/login returns 401 (credential capture working)" "pass"
else
    check 10 "POST /admin/login returns 401" "fail" \
        "$ADMIN_RESP"
fi

# ---------------------------------------------------------------------------
# Results summary
# ---------------------------------------------------------------------------
TOTAL=10

echo ""
echo "-------------------------------------------------------"
echo "  Results:"
echo "-------------------------------------------------------"
for line in "${RESULTS[@]}"; do
    echo "$line"
done
echo ""
echo "-------------------------------------------------------"
echo "  Summary: ${PASS} passed, ${FAIL} failed (of ${TOTAL} checks)"
echo "-------------------------------------------------------"
echo ""

if [[ "$FAIL" -eq 0 ]]; then
    echo "  All checks PASSED — Module 6 (honeypot-api) is ready."
    echo ""
    echo "  No DNAT rules are needed for Module 6."
    echo "  Ports 8080 and 8888 are loopback-only; Nginx (Module 7) proxies them."
    echo ""
    echo "  To confirm event logging is working:"
    echo "    curl -s http://127.0.0.1:8080/.env | grep AWS_ACCESS_KEY"
    echo "    docker exec postgres psql -U honeypot -d honeypot \\"
    echo "      -c \"SELECT event_type, src_ip, created_at FROM honeypot_events ORDER BY created_at DESC LIMIT 5;\""
    echo ""
    echo "  Next module: deploy/module-7-nginx/"
    echo "  (Nginx TLS termination, reverse proxy, Server header spoofing)"
    echo ""
    exit 0
else
    echo "  FAILED — ${FAIL} check(s) did not pass."
    echo ""
    echo "  Useful debug commands:"
    echo "    docker logs honeypot-api"
    echo "    docker logs honeypot-api 2>&1 | grep -i 'error\|fail\|warn'"
    echo "    docker exec honeypot-api ps aux   # verify both uvicorn processes are running"
    echo "    docker exec honeypot-api python -c \"import fastapi; print('fastapi ok')\""
    echo "    docker exec honeypot-api python -c \"import psycopg2; print('psycopg2 ok')\""
    echo "    docker network ls | grep -E 'honeypot-net|data-net'"
    echo "    docker volume ls | grep geoip-data"
    echo ""
    exit 1
fi
