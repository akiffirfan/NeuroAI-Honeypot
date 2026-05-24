#!/usr/bin/env bash
# =============================================================================
# verify-module-1.sh
# Neuro Honeypot Platform — Module 1 (Data Layer) Verification
#
# Run from the directory containing the Module 1 docker-compose.yml after
# 'docker compose up -d' has been executed and containers are running.
#
# Usage (from /opt/honeypot/):
#   bash deploy/module-1-data-layer/verify-module-1.sh
#
# Or if running from the module-1-data-layer/ directory itself:
#   bash verify-module-1.sh
# =============================================================================

set -uo pipefail

# ---------------------------------------------------------------------------
# Find the docker-compose.yml for this module regardless of working directory
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REDIS_PASSWORD=$(grep "^REDIS_PASSWORD=" "${SCRIPT_DIR}/.env" 2>/dev/null | cut -d= -f2-)
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"

if [[ ! -f "${COMPOSE_FILE}" ]]; then
    echo "FAIL: Cannot find docker-compose.yml at ${COMPOSE_FILE}" >&2
    exit 1
fi

# Wrapper: run docker compose commands relative to this module's compose file
dc() {
    docker compose -f "${COMPOSE_FILE}" "$@"
}

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED=''; GRN=''; YEL=''; BOLD=''; NC=''
fi

PASS=0
FAIL=0

pass() { echo -e "${GRN}[PASS]${NC} $*"; PASS=$((PASS + 1)); }
fail() { echo -e "${RED}[FAIL]${NC} $*"; FAIL=$((FAIL + 1)); }
info() { echo -e "${BOLD}[INFO]${NC} $*"; }
warn() { echo -e "${YEL}[WARN]${NC} $*"; }

echo ""
echo -e "${BOLD}=== Module 1 Data Layer Verification ===${NC}"
echo ""

# ---------------------------------------------------------------------------
# CHECK 1 — Container health status
# WHY: Docker's healthcheck (pg_isready for postgres, redis-cli ping for redis)
# must report 'healthy' before any other checks will succeed. A 'starting'
# state means the service is still initializing — wait and retry.
# ---------------------------------------------------------------------------
info "Check 1: Verifying container health status..."

for SERVICE in postgres redis; do
    HEALTH=$(docker inspect "${SERVICE}" --format '{{.State.Health.Status}}' 2>/dev/null || echo "not_running")
    if [[ "${HEALTH}" == "healthy" ]]; then
        pass "${SERVICE} container is healthy"
    elif [[ "${HEALTH}" == "starting" ]]; then
        warn "${SERVICE} container is still starting — wait 30s and re-run this script"
        fail "${SERVICE} health status: starting (not yet ready)"
    else
        fail "${SERVICE} container is not healthy (status: ${HEALTH})"
        info "  Debug: dc ps ${SERVICE}"
        info "  Logs:  docker compose -f ${COMPOSE_FILE} logs ${SERVICE} --tail=20"
    fi
done

echo ""

# ---------------------------------------------------------------------------
# CHECK 2 — PostgreSQL schema verification
# Lists all tables in the honeypot database. Expects exactly 3 tables:
#   honeypot_events, attacker_sessions, payload_samples
# ---------------------------------------------------------------------------
info "Check 2: Verifying PostgreSQL schema (tables)..."

TABLE_LIST=$(dc exec -T postgres \
    psql -U honeypot -d honeypot -t -c '\dt' 2>/dev/null || echo "ERROR")

if echo "${TABLE_LIST}" | grep -qE "ERROR|could not connect"; then
    fail "Cannot connect to PostgreSQL — check container health"
else
    TABLES_FOUND=$(echo "${TABLE_LIST}" | grep -c "| table |" 2>/dev/null || echo "0")
    echo "${TABLE_LIST}"
    if echo "${TABLE_LIST}" | grep -q "honeypot_events"; then
        pass "Table 'honeypot_events' exists"
    else
        fail "Table 'honeypot_events' NOT found"
    fi
    if echo "${TABLE_LIST}" | grep -q "attacker_sessions"; then
        pass "Table 'attacker_sessions' exists"
    else
        fail "Table 'attacker_sessions' NOT found"
    fi
    if echo "${TABLE_LIST}" | grep -q "payload_samples"; then
        pass "Table 'payload_samples' exists"
    else
        fail "Table 'payload_samples' NOT found"
    fi
fi

echo ""

# ---------------------------------------------------------------------------
# CHECK 3 — TimescaleDB hypertable verification
# Confirms honeypot_events was converted to a hypertable with 'created_at' as
# the partitioning column. If this row is missing, the retention policy and
# chunk-level performance optimizations are not active.
# ---------------------------------------------------------------------------
info "Check 3: Verifying TimescaleDB hypertable on honeypot_events..."

HYPERTABLE_INFO=$(dc exec -T postgres \
    psql -U honeypot -d honeypot -t -c \
    "SELECT hypertable_name, num_dimensions, num_chunks FROM timescaledb_information.hypertables;" \
    2>/dev/null || echo "ERROR")

echo "${HYPERTABLE_INFO}"

if echo "${HYPERTABLE_INFO}" | grep -q "honeypot_events"; then
    pass "honeypot_events is a TimescaleDB hypertable"
else
    fail "honeypot_events is NOT registered as a hypertable — check init SQL ran correctly"
fi

echo ""

# ---------------------------------------------------------------------------
# CHECK 4 — Retention policy verification
# The 90-day retention policy (add_retention_policy) is a background job in
# TimescaleDB. If the policy is missing, the table will grow unboundedly.
# ---------------------------------------------------------------------------
info "Check 4: Verifying 90-day retention policy is registered..."

RETENTION_INFO=$(dc exec -T postgres \
    psql -U honeypot -d honeypot -t -c \
    "SELECT application_name, hypertable_name, config
     FROM timescaledb_information.jobs
     WHERE application_name LIKE 'Retention Policy%'
       AND hypertable_name = 'honeypot_events';" \
    2>/dev/null || echo "ERROR")

echo "${RETENTION_INFO}"

if echo "${RETENTION_INFO}" | grep -qi "honeypot_events"; then
    pass "Retention policy for honeypot_events is registered in TimescaleDB"
else
    fail "Retention policy for honeypot_events NOT found — run: SELECT add_retention_policy('honeypot_events', INTERVAL '90 days');"
fi

echo ""

# ---------------------------------------------------------------------------
# CHECK 5 — Redis connectivity
# Redis must respond to PING with PONG before the log-shipper can publish events.
# If this fails, the Redis container is running but the server is not accepting
# connections (possibly still starting, or the config has a syntax error).
# ---------------------------------------------------------------------------
info "Check 5: Verifying Redis is responding to PING..."

REDIS_PING=$(dc exec -T redis redis-cli -a "${REDIS_PASSWORD}" ping 2>/dev/null || echo "ERROR")

if [[ "${REDIS_PING}" == "PONG" ]]; then
    pass "Redis responded with PONG"
else
    fail "Redis PING failed — response: ${REDIS_PING}"
    info "  Debug: docker compose -f ${COMPOSE_FILE} logs redis --tail=20"
fi

echo ""

# ---------------------------------------------------------------------------
# CHECK 6 — Network isolation (no published ports)
# The data-net is internal: true, meaning neither postgres nor redis should
# publish any ports to the host. A published port on postgres would expose
# the database to the public internet; a published port on redis (6379) would
# conflict with OpenCanary's attacker-facing fake Redis on the same port.
# ---------------------------------------------------------------------------
info "Check 6: Verifying no public ports are published (data-net must be isolated)..."

# Get container info and check for published ports
POSTGRES_PORTS=$(docker inspect postgres --format '{{range $p, $conf := .NetworkSettings.Ports}}{{if $conf}}PUBLISHED: {{$p}} -> {{(index $conf 0).HostPort}} {{end}}{{end}}' 2>/dev/null || echo "")
REDIS_PORTS=$(docker inspect redis --format '{{range $p, $conf := .NetworkSettings.Ports}}{{if $conf}}PUBLISHED: {{$p}} -> {{(index $conf 0).HostPort}} {{end}}{{end}}' 2>/dev/null || echo "")

if [[ -z "${POSTGRES_PORTS}" ]]; then
    pass "postgres: no ports published to host (correct — database is internal only)"
else
    fail "postgres has published ports — SECURITY RISK: ${POSTGRES_PORTS}"
fi

if [[ -z "${REDIS_PORTS}" ]]; then
    pass "redis: no ports published to host (correct — port 6379 is owned by OpenCanary)"
else
    fail "redis has published ports — SECURITY RISK: ${REDIS_PORTS}"
    warn "Publishing port 6379 on internal Redis conflicts with OpenCanary's fake Redis lure"
fi

echo ""

# ---------------------------------------------------------------------------
# CHECK 7 — userns-remap sanity check
# Verifies the Docker daemon has userns-remap active, which is the critical
# daemon hardening applied in Module 0. If this is missing, container UIDs
# map directly to host UIDs — a container escape = host root access.
# ---------------------------------------------------------------------------
info "Check 7: Verifying Docker daemon userns-remap is active..."

USERNS=$(docker info 2>/dev/null | grep -i "userns\|User Namespaces\|userns-remap" || echo "")

if [[ -n "${USERNS}" ]]; then
    pass "userns-remap is active: ${USERNS}"
else
    fail "userns-remap NOT visible in 'docker info' — was Module 0 run and daemon restarted?"
    warn "Without userns-remap, a container escape = host root. Run Module 0 and restart Docker."
fi

echo ""

# ---------------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------------
echo -e "${BOLD}=== Verification Summary ===${NC}"
echo ""
echo -e "  Passed: ${GRN}${PASS}${NC}"
echo -e "  Failed: ${RED}${FAIL}${NC}"
echo ""

if [[ "${FAIL}" -eq 0 ]]; then
    echo -e "${GRN}All checks passed. Module 1 data layer is ready.${NC}"
    echo ""
    echo "Next steps:"
    echo "  - Proceed to Module 2: Cowrie SSH honeypot"
    echo "  - Ensure /opt/honeypot/config/redis/redis.conf exists before starting Module 2"
    echo "    (the full compose uses redis.conf; Module 1 verifies the file is mounted)"
else
    echo -e "${RED}${FAIL} check(s) failed. Resolve the failures above before proceeding to Module 2.${NC}"
    echo ""
    echo "Common fixes:"
    echo "  - Container not healthy: docker compose -f ${COMPOSE_FILE} logs <service> --tail=30"
    echo "  - Schema not created: check that ../../services/postgres/init/01-schema.sql is"
    echo "    mounted and the postgres-data volume is EMPTY (init only runs on first start)"
    echo "  - userns-remap missing: re-run module-0-host-bootstrap.sh and restart Docker"
fi

echo ""
exit "${FAIL}"
