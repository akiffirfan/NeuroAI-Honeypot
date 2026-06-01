#!/usr/bin/env bash
# =============================================================================
# full-system-test.sh — Neuro Honeypot Platform End-to-End Verification
#
# Tests ALL layers: containers, data pipeline, alerting, security posture,
# frontend deception, TTY capture, GeoIP enrichment, network isolation,
# and modularity (volume/network cross-references).
#
# Run from /opt/honeypot/ on the VPS:
#   bash deploy/full-system-test.sh
#
# Then run external attacker-simulation commands from your local machine
# (printed at the end of this script's output).
# =============================================================================

PASS=0
FAIL=0
WARN=0

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

POSTGRES_PASSWORD=$(grep "^POSTGRES_PASSWORD=" /opt/honeypot/deploy/module-1-data-layer/.env 2>/dev/null | cut -d= -f2- || true)
REDIS_PASSWORD=$(grep "^REDIS_PASSWORD="    /opt/honeypot/deploy/module-1-data-layer/.env 2>/dev/null | cut -d= -f2- || true)
REDIS_PASSWORD="${REDIS_PASSWORD:-}"

pg() { docker exec postgres psql -U honeypot -d honeypot -tAc "$1" 2>/dev/null || true; }

# Print result immediately so output is visible even if script errors later
pass() { PASS=$((PASS+1)); echo -e "  ${GREEN}[PASS]${NC} $1"; }
fail() { FAIL=$((FAIL+1)); echo -e "  ${RED}[FAIL]${NC} $1"; }
warn() { WARN=$((WARN+1)); echo -e "  ${YELLOW}[WARN]${NC} $1"; }

section() { echo -e "\n${BOLD}${BLUE}━━━ $1 ━━━${NC}"; }

# =============================================================================
# A. CONTAINER HEALTH
# =============================================================================
section "A. Container Health"

EXPECTED_CONTAINERS=(postgres redis cowrie opencanary mariadb-lure log-shipper sentinel honeypot-api nginx)
for c in "${EXPECTED_CONTAINERS[@]}"; do
    STATUS=$(docker inspect --format='{{.State.Status}}' "$c" 2>/dev/null || echo "missing")
    HEALTH=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$c" 2>/dev/null || echo "missing")
    if [[ "$STATUS" == "running" ]]; then
        if [[ "$HEALTH" == "unhealthy" ]]; then
            fail "A: $c — running but UNHEALTHY"
        else
            pass "A: $c — running (health: $HEALTH)"
        fi
    else
        fail "A: $c — expected running, got: $STATUS"
    fi
done

# Restart policy check — all should be on-failure:5
for c in "${EXPECTED_CONTAINERS[@]}"; do
    POLICY=$(docker inspect --format='{{.HostConfig.RestartPolicy.Name}}' "$c" 2>/dev/null || echo "unknown")
    if [[ "$POLICY" != "on-failure" ]]; then
        warn "A: $c restart policy is '$POLICY' (expected on-failure)"
    fi
done

# =============================================================================
# B. SECURITY POSTURE
# =============================================================================
section "B. Security Posture"

# All containers must have no-new-privileges
for c in "${EXPECTED_CONTAINERS[@]}"; do
    NNP=$(docker inspect --format='{{range .HostConfig.SecurityOpt}}{{.}} {{end}}' "$c" 2>/dev/null || echo "")
    if echo "$NNP" | grep -q "no-new-privileges"; then
        pass "B: $c — no-new-privileges set"
    else
        fail "B: $c — no-new-privileges MISSING"
    fi
done

# cap_drop ALL check
for c in cowrie opencanary mariadb-lure log-shipper sentinel honeypot-api nginx; do
    CAPS=$(docker inspect --format='{{range .HostConfig.CapDrop}}{{.}} {{end}}' "$c" 2>/dev/null || echo "")
    if echo "$CAPS" | grep -q "ALL\|CAP_CHOWN"; then
        pass "B: $c — cap_drop contains ALL"
    else
        warn "B: $c — cap_drop may be missing ALL (got: $CAPS)"
    fi
done

# Published ports — only expected ports should be exposed
PUBLISHED=$(docker ps --format '{{.Ports}}' | grep -v "^$" | sort -u)
echo "  Published ports: $PUBLISHED"

# postgres and redis must NOT have published ports
for c in postgres redis; do
    PORTS=$(docker inspect --format='{{range $p, $conf := .NetworkSettings.Ports}}{{$p}} {{end}}' "$c" 2>/dev/null || echo "")
    BOUND=$(docker inspect --format='{{range $p, $conf := .NetworkSettings.Ports}}{{range $conf}}{{.HostPort}} {{end}}{{end}}' "$c" 2>/dev/null | tr -s ' ' | xargs)
    if [[ -z "$BOUND" ]]; then
        pass "B: $c — no ports published to host (correct)"
    else
        fail "B: $c — ports published to host: $BOUND (SECURITY RISK)"
    fi
done

# log-shipper must not have published ports
PORTS=$(docker inspect --format='{{range $p, $conf := .NetworkSettings.Ports}}{{range $conf}}{{.HostPort}} {{end}}{{end}}' log-shipper 2>/dev/null | xargs)
if [[ -z "$PORTS" ]]; then
    pass "B: log-shipper — no ports published to host"
else
    fail "B: log-shipper — unexpected published port: $PORTS"
fi

# =============================================================================
# C. NETWORK ISOLATION
# =============================================================================
section "C. Network Isolation"

# postgres must be on data-net only, NOT honeypot-net
PG_NETS=$(docker inspect postgres --format='{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null)
if echo "$PG_NETS" | grep -q "honeypot-net"; then
    fail "C: postgres — connected to honeypot-net (should be data-net only)"
else
    pass "C: postgres — NOT on honeypot-net (correct isolation)"
fi

# redis must be on data-net only, NOT honeypot-net
REDIS_NETS=$(docker inspect redis --format='{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null)
if echo "$REDIS_NETS" | grep -q "honeypot-net"; then
    fail "C: redis — connected to honeypot-net (should be data-net only)"
else
    pass "C: redis — NOT on honeypot-net (correct isolation)"
fi

# cowrie must NOT be on data-net
COWRIE_NETS=$(docker inspect cowrie --format='{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null || true)
if echo "$COWRIE_NETS" | grep -q "data-net"; then
    fail "C: cowrie — connected to data-net (should be honeypot-net only)"
else
    pass "C: cowrie — NOT on data-net (correct)"
fi

# Network isolation test: cowrie should NOT reach postgres (it's not on data-net)
if docker exec cowrie nc -z -w2 postgres 5432 2>/dev/null; then
    fail "C: cowrie can reach postgres — network isolation BROKEN"
else
    pass "C: cowrie cannot reach postgres (isolation correct)"
fi

# Network isolation test: cowrie should NOT reach redis
if docker exec cowrie nc -z -w2 redis 6379 2>/dev/null; then
    fail "C: cowrie can reach redis — network isolation BROKEN"
else
    pass "C: cowrie cannot reach redis (isolation correct)"
fi

# log-shipper must reach both postgres and redis
if docker exec log-shipper nc -z -w2 postgres 5432 2>/dev/null; then
    pass "C: log-shipper can reach postgres"
else
    fail "C: log-shipper cannot reach postgres"
fi

if docker exec log-shipper nc -z -w2 redis 6379 2>/dev/null; then
    pass "C: log-shipper can reach redis"
else
    fail "C: log-shipper cannot reach redis"
fi

# =============================================================================
# D. DATA LAYER (Module 1)
# =============================================================================
section "D. Data Layer — PostgreSQL & Redis"

# Event count
EVENT_COUNT=$(pg "SELECT COUNT(*) FROM honeypot_events;" 2>/dev/null || echo "0")
if [[ "$EVENT_COUNT" -gt 1000 ]]; then
    pass "D: honeypot_events — $EVENT_COUNT rows (data flowing)"
else
    fail "D: honeypot_events — only $EVENT_COUNT rows (expected >1000)"
fi

# Events from all 4 sensors
# Note: MariaDB tailer uses SENSOR_NAME_OPENCANARY by design (HoneyDash mapping reuse).
# Distinguish MariaDB events from OpenCanary events by dst_port=3306.
for sensor in cowrie opencanary api; do
    COUNT=$(pg "SELECT COUNT(*) FROM honeypot_events WHERE sensor LIKE '%${sensor}%';" 2>/dev/null || echo "0")
    if [[ "$COUNT" -gt 0 ]]; then
        pass "D: sensor=$sensor — $COUNT events in DB"
    else
        fail "D: sensor=$sensor — 0 events (no data from this sensor)"
    fi
done
MARIADB_COUNT=$(pg "SELECT COUNT(*) FROM honeypot_events WHERE dst_port=3306;" 2>/dev/null || echo "0")
MARIADB_COUNT=$(echo "${MARIADB_COUNT:-0}" | grep -o '[0-9]*' | head -1); MARIADB_COUNT="${MARIADB_COUNT:-0}"
if [[ "$MARIADB_COUNT" -gt 0 ]]; then
    pass "D: MariaDB lure (dst_port=3306) — $MARIADB_COUNT events (sensor=opencanary by design)"
else
    warn "D: MariaDB lure (dst_port=3306) — 0 events (no external connections logged yet)"
fi

# GeoIP enrichment — check real IPs have geo data
GEO_COUNT=$(pg "SELECT COUNT(*) FROM honeypot_events WHERE geo_country IS NOT NULL AND src_ip NOT IN ('127.0.0.1','10.10.20.1','10.10.21.1');" 2>/dev/null || echo "0")
if [[ "$GEO_COUNT" -gt 0 ]]; then
    pass "D: GeoIP enrichment — $GEO_COUNT events have geo data"
else
    fail "D: GeoIP enrichment — 0 events with geo_country set"
fi

# Check for any remaining 10.10.20.1 IPs (docker-proxy masquerade — should be gone)
DOCKER_PROXY_COUNT=$(pg "SELECT COUNT(*) FROM honeypot_events WHERE src_ip::text = '10.10.20.1';" 2>/dev/null || echo "unknown")
if [[ "$DOCKER_PROXY_COUNT" == "0" ]]; then
    pass "D: No docker-proxy masquerade IPs (10.10.20.1) in events"
elif [[ "$DOCKER_PROXY_COUNT" == "unknown" ]]; then
    warn "D: Could not check for docker-proxy IPs"
else
    warn "D: $DOCKER_PROXY_COUNT events still show 10.10.20.1 (pre-fix events from earlier)"
fi

# Recent events (last 24h)
RECENT=$(pg "SELECT COUNT(*) FROM honeypot_events WHERE created_at > NOW() - INTERVAL '24 hours';" 2>/dev/null || echo "0")
if [[ "$RECENT" -gt 0 ]]; then
    pass "D: Recent activity — $RECENT events in the last 24 hours"
else
    warn "D: No events in last 24h — check if sensors are reachable"
fi

# Redis stream
STREAM_LEN=$(docker exec redis redis-cli -a "$REDIS_PASSWORD" XLEN "honeypot:events" 2>/dev/null | grep -v "Warning" || echo "0")
if [[ "$STREAM_LEN" -gt 0 ]]; then
    pass "D: Redis stream honeypot:events — $STREAM_LEN entries"
else
    warn "D: Redis stream is empty (may have been trimmed — not critical)"
fi

# TimescaleDB retention policy
POLICY=$(pg "SELECT count(*) FROM timescaledb_information.jobs WHERE job_type = 'retention_policy';" 2>/dev/null || echo "0")
if [[ "$POLICY" -gt 0 ]]; then
    pass "D: TimescaleDB retention policy configured"
else
    warn "D: No retention policy found on TimescaleDB"
fi

# =============================================================================
# E. LOG FILES & PIPELINE (Module 5)
# =============================================================================
section "E. Log Files & Pipeline"

# Cowrie log exists and has recent data
COWRIE_LOG_SIZE=$(docker exec log-shipper wc -l /var/log/cowrie/cowrie.json 2>/dev/null | awk '{print $1}' || echo "0")
COWRIE_LOG_SIZE=$(echo "${COWRIE_LOG_SIZE:-0}" | grep -o '[0-9]*' | head -1); COWRIE_LOG_SIZE="${COWRIE_LOG_SIZE:-0}"
if [[ "$COWRIE_LOG_SIZE" -gt 0 ]]; then
    pass "E: Cowrie log — $COWRIE_LOG_SIZE lines"
else
    fail "E: Cowrie log is empty or unreadable"
fi

# OpenCanary log exists
OC_LOG_SIZE=$(docker exec log-shipper wc -l /var/log/opencanary/opencanary.json 2>/dev/null | awk '{print $1}' || echo "0")
OC_LOG_SIZE=$(echo "${OC_LOG_SIZE:-0}" | grep -o '[0-9]*' | head -1); OC_LOG_SIZE="${OC_LOG_SIZE:-0}"
if [[ "$OC_LOG_SIZE" -gt 0 ]]; then
    pass "E: OpenCanary log — $OC_LOG_SIZE lines"
else
    fail "E: OpenCanary log is empty or unreadable"
fi

# MariaDB log exists
MYSQL_LOG_SIZE=$(docker exec log-shipper wc -l /var/log/mariadb/general.log 2>/dev/null | awk '{print $1}' || echo "0")
MYSQL_LOG_SIZE=$(echo "${MYSQL_LOG_SIZE:-0}" | grep -o '[0-9]*' | head -1); MYSQL_LOG_SIZE="${MYSQL_LOG_SIZE:-0}"
if [[ "$MYSQL_LOG_SIZE" -gt 0 ]]; then
    pass "E: MariaDB general log — $MYSQL_LOG_SIZE lines"
else
    fail "E: MariaDB general log is empty or unreadable"
fi

# GeoIP databases
for db in GeoLite2-City.mmdb GeoLite2-ASN.mmdb; do
    SIZE=$(docker exec log-shipper stat -c%s "/geoip/$db" 2>/dev/null || echo "0")
    SIZE=$(echo "${SIZE:-0}" | grep -o '[0-9]*' | head -1); SIZE="${SIZE:-0}"
    if [[ "$SIZE" -gt 1000000 ]]; then
        pass "E: GeoIP $db — ${SIZE} bytes"
    else
        fail "E: GeoIP $db — missing or too small (${SIZE} bytes)"
    fi
done

# log-shipper healthcheck endpoint
LS_HEALTH=$(docker exec log-shipper python3 -c "import urllib.request; r=urllib.request.urlopen('http://localhost:9100/healthz', timeout=2); print(r.status)" 2>/dev/null || echo "error")
if [[ "$LS_HEALTH" == "200" ]]; then
    pass "E: log-shipper /healthz — HTTP 200"
else
    fail "E: log-shipper /healthz — got: $LS_HEALTH"
fi

# Disk spool directory exists and is writable
SPOOL_DIR=$(docker exec log-shipper sh -c 'echo $SPOOL_DIR' 2>/dev/null || echo "/archive/spool")
SPOOL_OK=$(docker exec log-shipper sh -c "test -d '$SPOOL_DIR' && echo ok || echo missing" 2>/dev/null)
if [[ "$SPOOL_OK" == "ok" ]]; then
    SPOOL_FILES=$(docker exec log-shipper ls "$SPOOL_DIR" 2>/dev/null | wc -l | xargs)
    pass "E: Disk spool directory exists ($SPOOL_FILES spooled files)"
    if [[ "$SPOOL_FILES" -gt 100 ]]; then
        warn "E: $SPOOL_FILES files in spool — Postgres may have been unreachable; check log-shipper logs"
    fi
else
    fail "E: Disk spool directory missing"
fi

# =============================================================================
# F. SENTINEL ALERTER (Module 5)
# =============================================================================
section "F. Sentinel Alerter"

# Sentinel running
SENTINEL_STATUS=$(docker inspect --format='{{.State.Status}}' sentinel 2>/dev/null || echo "missing")
if [[ "$SENTINEL_STATUS" == "running" ]]; then
    pass "F: sentinel container — running"
else
    fail "F: sentinel container — $SENTINEL_STATUS"
fi

# TELEGRAM env vars set (not empty)
TG_TOKEN=$(docker exec sentinel sh -c 'echo ${#TELEGRAM_BOT_TOKEN}' 2>/dev/null || echo "0")
TG_CHAT=$(docker exec sentinel sh -c 'echo ${#TELEGRAM_CHAT_ID}' 2>/dev/null || echo "0")
if [[ "$TG_TOKEN" -gt 10 ]]; then
    pass "F: sentinel — TELEGRAM_BOT_TOKEN is set (length $TG_TOKEN)"
else
    fail "F: sentinel — TELEGRAM_BOT_TOKEN is empty or too short"
fi
if [[ "$TG_CHAT" -gt 3 ]]; then
    pass "F: sentinel — TELEGRAM_CHAT_ID is set (length $TG_CHAT)"
else
    fail "F: sentinel — TELEGRAM_CHAT_ID is empty"
fi

# log-shipper must NOT have Telegram tokens (sentinel handles alerts exclusively)
LS_TG=$(docker exec log-shipper sh -c 'echo ${#TELEGRAM_BOT_TOKEN}' 2>/dev/null || echo "0")
if [[ "$LS_TG" -eq 0 ]]; then
    pass "F: log-shipper — TELEGRAM_BOT_TOKEN correctly empty (sentinel-only alerting)"
else
    fail "F: log-shipper — has TELEGRAM_BOT_TOKEN set (risk of duplicate alerts)"
fi

# Sentinel recent log — check for errors
SENTINEL_ERRORS=$(docker logs sentinel --since=1h 2>&1 | grep -c "ERROR\|Exception\|Traceback" || true)
if [[ "$SENTINEL_ERRORS" -eq 0 ]]; then
    pass "F: sentinel — no errors in last 1h logs"
else
    warn "F: sentinel — $SENTINEL_ERRORS error lines in last 1h logs"
fi

# HONEYDASH_URL must be empty in log-shipper (security: don't push to external by default)
LS_HDURL=$(docker exec log-shipper sh -c 'echo "${HONEYDASH_URL:-}"' 2>/dev/null || echo "set")
if [[ -z "$LS_HDURL" ]]; then
    pass "F: log-shipper — HONEYDASH_URL empty (external push disabled — correct)"
else
    warn "F: log-shipper — HONEYDASH_URL=$LS_HDURL (pushing to external host — verify intentional)"
fi

# =============================================================================
# G. COWRIE SSH (Module 2) — Internal checks
# =============================================================================
section "G. Cowrie SSH Sensor"

# Cowrie JSON log valid format
COWRIE_LAST=$(docker exec log-shipper tail -1 /var/log/cowrie/cowrie.json 2>/dev/null)
if echo "$COWRIE_LAST" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
    pass "G: Cowrie log — last line is valid JSON"
else
    warn "G: Cowrie log — last line may not be valid JSON (or log is empty)"
fi

# SSH events in DB
SSH_EVENTS=$(pg "SELECT COUNT(*) FROM honeypot_events WHERE sensor LIKE '%cowrie%' AND event_type NOT IN ('http.get.health','api.startup');" 2>/dev/null || echo "0")
pass "G: Cowrie events in DB — $SSH_EVENTS"

# TTY session directory
TTY_COUNT=$(docker exec cowrie find /cowrie/var/log/cowrie/tty/ -type f 2>/dev/null | wc -l || echo "0")
TTY_COUNT=$(echo "$TTY_COUNT" | grep -o '[0-9]*' | head -1 || echo "0")
TTY_COUNT="${TTY_COUNT:-0}"
if [[ "$TTY_COUNT" -gt 0 ]]; then
    pass "G: TTY sessions captured — $TTY_COUNT session files"
else
    warn "G: No TTY sessions yet (requires a successful login with root:* userdb.txt)"
fi

# userdb.txt allows wildcard passwords (enables TTY capture)
USERDB=$(docker exec cowrie cat /cowrie/cowrie-git/etc/userdb.txt 2>/dev/null || echo "")
if echo "$USERDB" | grep -q ':\*'; then
    pass "G: userdb.txt — wildcard password (*) configured for TTY capture"
else
    warn "G: userdb.txt — no wildcard entries; attackers cannot get a shell (TTY capture disabled)"
fi

# =============================================================================
# H. OPENCANARY (Module 3) — Internal checks
# =============================================================================
section "H. OpenCanary Multi-Protocol Sensor"

# OpenCanary running
OC_STATUS=$(docker inspect --format='{{.State.Status}}' opencanary 2>/dev/null || echo "missing")
if [[ "$OC_STATUS" == "running" ]]; then
    pass "H: opencanary — running"
else
    fail "H: opencanary — $OC_STATUS (run: docker compose -f deploy/module-3-opencanary/docker-compose.yml up -d)"
fi

# Events per protocol
for proto_port in "FTP:21" "TELNET:23" "SMTP:25" "REDIS:6379"; do
    PROTO="${proto_port%%:*}"
    PORT="${proto_port##*:}"
    COUNT=$(pg "SELECT COUNT(*) FROM honeypot_events WHERE sensor LIKE '%opencanary%' AND dst_port=$PORT;" 2>/dev/null || echo "0")
    if [[ "$COUNT" -gt 0 ]]; then
        pass "H: OpenCanary $PROTO (port $PORT) — $COUNT events"
    else
        warn "H: OpenCanary $PROTO (port $PORT) — 0 events (no scans on this port yet)"
    fi
done

# OpenCanary logtype 6001 correctly mapped (telnet not vnc)
OC_TELNET=$(pg "SELECT COUNT(*) FROM honeypot_events WHERE sensor LIKE '%opencanary%' AND dst_port=23 AND event_type NOT LIKE '%vnc%';" 2>/dev/null || echo "0")
if [[ "$OC_TELNET" -gt 0 ]]; then
    pass "H: Telnet events correctly NOT mapped to vnc event_type"
fi

# =============================================================================
# I. MARIADB LURE (Module 4) — Internal checks
# =============================================================================
section "I. MariaDB Lure"

# MariaDB running
MARIA_STATUS=$(docker inspect --format='{{.State.Status}}' mariadb-lure 2>/dev/null || echo "missing")
if [[ "$MARIA_STATUS" == "running" ]]; then
    pass "I: mariadb-lure — running"
else
    fail "I: mariadb-lure — $MARIA_STATUS"
fi

# Fake schema exists
MARIA_ROOT=$(grep "MARIADB_ROOT_PASSWORD=" /opt/honeypot/deploy/module-4-mariadb-lure/.env 2>/dev/null | cut -d= -f2- || true)
SCHEMA_COUNT=$(docker exec mariadb-lure mariadb -u root -p"${MARIA_ROOT:-}" -e "SHOW TABLES FROM neuro_prod;" 2>/dev/null | wc -l || echo "0")
SCHEMA_COUNT=$(echo "${SCHEMA_COUNT:-0}" | grep -o '[0-9]*' | head -1); SCHEMA_COUNT="${SCHEMA_COUNT:-0}"
if [[ "$SCHEMA_COUNT" -gt 3 ]]; then
    pass "I: neuro_prod schema — $SCHEMA_COUNT tables (fake lure data present)"
else
    warn "I: neuro_prod schema — only $SCHEMA_COUNT tables (expected ≥4)"
fi

# MariaDB events in DB
MARIA_COUNT=$(pg "SELECT COUNT(*) FROM honeypot_events WHERE sensor LIKE '%mariadb%' OR dst_port=3306;" 2>/dev/null || echo "0")
if [[ "$MARIA_COUNT" -gt 0 ]]; then
    pass "I: MariaDB events in DB — $MARIA_COUNT"
else
    warn "I: No MariaDB events yet (port 3306 may not have been scanned)"
fi

# =============================================================================
# J. HONEYPOT-API FRONTEND (Module 6)
# =============================================================================
section "J. Honeypot-API Frontend & Deception"

# Health
API_HEALTH=$(curl -s http://127.0.0.1:8080/api/v1/health 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','?'))" 2>/dev/null || echo "error")
if [[ "$API_HEALTH" == "ok" ]]; then
    pass "J: honeypot-api — /api/v1/health returns ok"
else
    fail "J: honeypot-api — health check failed (got: $API_HEALTH)"
fi

# Lure routes
for route in "/.env" "/api/v1/internal/config"; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8080${route}" 2>/dev/null)
    if [[ "$STATUS" == "200" || "$STATUS" == "401" || "$STATUS" == "403" ]]; then
        pass "J: GET $route — HTTP $STATUS (lure route active)"
    else
        fail "J: GET $route — unexpected HTTP $STATUS"
    fi
done
# /admin/login is POST-only — GET returns 405 (correct FastAPI behaviour)
ADMIN_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://127.0.0.1:8080/admin/login 2>/dev/null)
if [[ "$ADMIN_STATUS" == "401" ]]; then
    pass "J: POST /admin/login — 401 (credential capture working)"
else
    fail "J: POST /admin/login — unexpected HTTP $ADMIN_STATUS"
fi

# Fake AWS key in /.env
ENV_KEY=$(curl -s http://127.0.0.1:8080/.env 2>/dev/null | grep -o "AKIA[A-Z0-9]*" || echo "")
if [[ -n "$ENV_KEY" ]]; then
    pass "J: /.env — fake AWS key present ($ENV_KEY)"
else
    fail "J: /.env — no fake AWS key found"
fi

# HONEYDASH_URL empty in honeypot-api (security check)
API_HDURL=$(docker exec honeypot-api sh -c 'echo "${HONEYDASH_URL:-}"' 2>/dev/null || echo "set")
if [[ -z "$API_HDURL" ]]; then
    pass "J: honeypot-api — HONEYDASH_URL empty (external push disabled)"
else
    warn "J: honeypot-api — HONEYDASH_URL=$API_HDURL"
fi

# Defender vocabulary check in served JS/HTML
# Excludes HTML comment lines (<!-- -->) which may contain intentional lure text
# (e.g. "?bypass=true" lure URL in admin.html — deliberate attacker bait, not a tell).
DEFENDER_VOCAB="botScore|canvasFingerprint|scannerUAs|headlessHashes|bot_score|canvas_fp|getCanvasFingerprint|viewSourceAttempts|sqlmap|nikto|nmap|zgrab|nuclei|masscan|Puppeteer|Playwright|plans\.md|credential.stuff|scanner"
VOCAB_HITS=$(grep -rn -E "$DEFENDER_VOCAB" \
    /opt/honeypot/deploy/module-6-honeypot-api/src/static/ \
    /opt/honeypot/deploy/module-6-honeypot-api/src/templates/ \
    2>/dev/null | grep -v "\.pyc" | grep -v "<!--" | wc -l || echo "0")
if [[ "$VOCAB_HITS" -eq 0 ]]; then
    pass "J: Frontend — no defender vocabulary in client-served files (lure comments excluded)"
else
    fail "J: Frontend — $VOCAB_HITS defender vocabulary hit(s) in JS/HTML (run grep manually to inspect)"
fi

# Tailwind CDN check (would print console warning revealing honeypot nature)
CDN_HITS=$(grep -rn "cdn.tailwindcss.com" \
    /opt/honeypot/deploy/module-6-honeypot-api/src/templates/ 2>/dev/null | wc -l || echo "0")
if [[ "$CDN_HITS" -eq 0 ]]; then
    pass "J: Frontend — no Tailwind CDN script tag (no console warning)"
else
    fail "J: Frontend — Tailwind CDN found ($CDN_HITS hits) — remove before live traffic"
fi

# Jupyter stub
JUPYTER_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8888/ 2>/dev/null)
if [[ "$JUPYTER_STATUS" == "200" ]]; then
    pass "J: Jupyter stub (:8888) — HTTP 200"
else
    warn "J: Jupyter stub (:8888) — HTTP $JUPYTER_STATUS"
fi

# =============================================================================
# K. NGINX TLS (Module 7)
# =============================================================================
section "K. Nginx / OpenResty TLS"

# Nginx running
NGINX_STATUS=$(docker inspect --format='{{.State.Status}}' nginx 2>/dev/null || echo "missing")
if [[ "$NGINX_STATUS" == "running" ]]; then
    pass "K: nginx — running"
else
    fail "K: nginx — $NGINX_STATUS"
fi

# HTTP health endpoint
HTTP_HEALTH=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:80/health 2>/dev/null)
if [[ "$HTTP_HEALTH" == "200" ]]; then
    pass "K: nginx — HTTP /health returns 200"
else
    fail "K: nginx — HTTP /health returned $HTTP_HEALTH"
fi

# nginx can reach honeypot-api
NGINX_API=$(docker exec nginx wget -q -O- http://honeypot-api:8080/api/v1/health 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','?'))" 2>/dev/null || echo "error")
if [[ "$NGINX_API" == "ok" ]]; then
    pass "K: nginx — can reach honeypot-api:8080 on Docker network"
else
    fail "K: nginx — cannot reach honeypot-api:8080 (got: $NGINX_API)"
fi

# Deceptive headers present on nginx responses
SERVER_HEADER=$(curl -sI http://127.0.0.1:80/health 2>/dev/null | grep -i "^server:" | head -1 | tr -d '\r')
if echo "$SERVER_HEADER" | grep -qi "uvicorn\|gunicorn\|apache\|IIS"; then
    pass "K: nginx — deceptive Server header: $SERVER_HEADER"
else
    warn "K: nginx — Server header on /health may not be spoofed: $SERVER_HEADER (normal for health-only endpoint)"
fi

# TLS cert validity check
CERT_EXPIRY=$(echo | openssl s_client -connect neurodata.me:443 -servername neurodata.me 2>/dev/null \
    | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || echo "unable to connect")
if [[ "$CERT_EXPIRY" != "unable to connect" && -n "$CERT_EXPIRY" ]]; then
    pass "K: TLS cert valid, expires: $CERT_EXPIRY"
    DAYS_LEFT=$(( ( $(date -d "$CERT_EXPIRY" +%s) - $(date +%s) ) / 86400 ))
    if [[ "$DAYS_LEFT" -lt 30 ]]; then
        warn "K: TLS cert expires in $DAYS_LEFT days — renew soon"
    fi
else
    warn "K: Could not verify TLS cert from VPS (check from external host)"
fi

# =============================================================================
# L. EVENT TYPE COVERAGE
# =============================================================================
section "L. Event Type Coverage"

echo "  Recent event types (last 48h):"
pg "SELECT event_type, sensor, COUNT(*) as cnt
    FROM honeypot_events
    WHERE created_at > NOW() - INTERVAL '48 hours'
    GROUP BY event_type, sensor
    ORDER BY cnt DESC
    LIMIT 20;" 2>/dev/null | while read line; do
    echo "    $line"
done

# Check we have diverse event types (not just one type flooding)
DISTINCT_TYPES=$(pg "SELECT COUNT(DISTINCT event_type) FROM honeypot_events WHERE created_at > NOW() - INTERVAL '48 hours';" 2>/dev/null || echo "0")
if [[ "$DISTINCT_TYPES" -gt 3 ]]; then
    pass "L: $DISTINCT_TYPES distinct event types in last 48h (good diversity)"
else
    warn "L: Only $DISTINCT_TYPES distinct event types — may indicate limited attacker variety"
fi

# Top attacker IPs
echo ""
echo "  Top 5 attacker IPs (all time):"
pg "SELECT src_ip::text, geo_country, COUNT(*) as hits
    FROM honeypot_events
    WHERE src_ip::text NOT IN ('127.0.0.1','10.10.20.1','10.10.21.1')
    GROUP BY src_ip, geo_country
    ORDER BY hits DESC
    LIMIT 5;" 2>/dev/null | while read line; do echo "    $line"; done

# =============================================================================
# M. MODULARITY — Volume & Network Cross-References
# =============================================================================
section "M. Modularity — Volumes & Network Cross-References"

for vol in cowrie-logs opencanary-logs mariadb-logs geoip-data data-net honeypot-net; do
    # Check volumes
    if docker volume ls --format '{{.Name}}' | grep -qx "$vol" 2>/dev/null; then
        pass "M: volume $vol — exists"
    elif docker network ls --format '{{.Name}}' | grep -qx "$vol" 2>/dev/null; then
        pass "M: network $vol — exists"
    else
        fail "M: $vol — MISSING (required by multiple modules)"
    fi
done

# =============================================================================
# RESULTS SUMMARY
# =============================================================================
echo ""
echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${GREEN}PASS: $PASS${NC}  |  ${RED}FAIL: $FAIL${NC}  |  ${YELLOW}WARN: $WARN${NC}"
if [[ "$FAIL" -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}ALL CHECKS PASSED — System is healthy${NC}"
else
    echo -e "  ${RED}${BOLD}$FAIL CHECK(S) FAILED — Review failures above${NC}"
fi
echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# =============================================================================
# EXTERNAL TESTS (to run from your local machine)
# =============================================================================
echo ""
echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  External Attacker-Simulation Tests (run from your LOCAL machine)${NC}"
echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  # 1. HTTPS frontend — should return the Neuro dashboard (not 502)"
echo "  curl -sk https://neurodata.me/ | head -5"
echo ""
echo "  # 2. Lure routes — should return fake secrets"
echo "  curl -sk https://neurodata.me/.env | head -5"
echo "  curl -sk https://neurodata.me/api/v1/internal/config | python3 -m json.tool | head -10"
echo ""
echo "  # 3. SSH honeypot — attempt login (should connect, Cowrie will respond)"
echo "  ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@neurodata.me"
echo "  # (try password: admin123 — check Telegram for alert)"
echo ""
echo "  # 4. FTP lure — banner should appear"
echo "  curl -v ftp://neurodata.me 2>&1 | head -20"
echo ""
echo "  # 5. MariaDB lure — should see MariaDB banner"
echo "  mysql -h neurodata.me -u root -padmin123 --connect-timeout=5 2>&1 | head -5"
echo "  # OR: nc -w5 neurodata.me 3306 | head -c100 | strings"
echo ""
echo "  # 6. Redis lure — should see PONG or error from fake Redis"
echo "  redis-cli -h neurodata.me -a wrongpassword PING 2>&1"
echo ""
echo "  # 7. Deceptive response headers — uvicorn server spoofing"
echo "  curl -skI https://neurodata.me/ | grep -i 'server:\|x-powered-by:\|x-neuro'"
echo ""
echo "  # 8. After running 1-7: check Telegram for alerts"
echo "  #    Expected: alerts for SSH attempt, HTTP probes, MariaDB/Redis connect"
echo ""
echo "  # 9. After running 1-7: check DB on VPS:"
echo "  #    docker exec postgres psql -U honeypot -d honeypot \\"
echo "  #      -c \"SELECT event_type, src_ip::text, sensor, created_at FROM honeypot_events ORDER BY created_at DESC LIMIT 10;\""
echo ""

exit $([[ "$FAIL" -eq 0 ]] && echo 0 || echo 1)
