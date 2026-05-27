#!/usr/bin/env bash
# verify-module-7.sh — Module 7 (nginx) post-deployment verification
#
# Run from /opt/honeypot/deploy/module-7-nginx/ after:
#   1. Phase 1: docker compose up -d  (HTTP-only config)
#   2. Phase 2: certbot one-off container issued the cert
#   3. Phase 3: full TLS config deployed and nginx reloaded
#
# All 10 checks must PASS before Module 7 is considered complete.
#
# IMPORTANT: Checks 3–8 make outbound curl requests to neurodata.me.
#   These requests go out the host network, hit the VPS public IP, and come back in.
#   This requires:
#     (a) neurodata.me DNS resolves to 143.198.195.132 (the VPS)
#     (b) ports 80 and 443 are open at the DigitalOcean cloud firewall panel
#     (c) the TLS certificate has been issued (Phase 2 complete)
#   If honeypot-api (Module 6) is not running, checks that test proxied endpoints
#   (checks 4, 6, 7) will fail with 502. Check 8 (/health) will pass regardless
#   because nginx handles /health directly without proxying.
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
echo "  Module 7 — nginx (OpenResty) Verification"
echo "======================================================="
echo ""

# ---------------------------------------------------------------------------
# Check 1: nginx container is running and healthy
# ---------------------------------------------------------------------------
CONTAINER_STATUS=$(docker inspect --format '{{.State.Status}}' nginx 2>/dev/null || echo "missing")
HEALTH_STATUS=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' nginx 2>/dev/null || echo "missing")

if [[ "$CONTAINER_STATUS" == "running" ]]; then
    if [[ "$HEALTH_STATUS" == "healthy" ]]; then
        check 1 "nginx container is running and healthy" "pass"
    elif [[ "$HEALTH_STATUS" == "starting" ]]; then
        check 1 "nginx container is running and healthy" "fail" \
            "health check still 'starting' — wait 30s and retry"
    else
        check 1 "nginx container is running and healthy" "fail" \
            "status=$CONTAINER_STATUS health=$HEALTH_STATUS — run: docker logs nginx"
    fi
else
    check 1 "nginx container is running and healthy" "fail" \
        "container status: $CONTAINER_STATUS — run: docker logs nginx"
fi

# ---------------------------------------------------------------------------
# Check 2: Container is on honeypot-net
# ---------------------------------------------------------------------------
NETWORKS=$(docker inspect --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' nginx 2>/dev/null || echo "")

ON_HONEYPOT=false
for _net in $NETWORKS; do
    if [[ "$_net" == "honeypot-net" ]]; then ON_HONEYPOT=true; fi
done

if [[ "$ON_HONEYPOT" == "true" ]]; then
    check 2 "nginx is on honeypot-net" "pass"
else
    check 2 "nginx is on honeypot-net" "fail" \
        "networks found: $NETWORKS — container must be on honeypot-net to reach honeypot-api"
fi

# ---------------------------------------------------------------------------
# Check 3: HTTP → HTTPS redirect works (port 80 → 301)
# ---------------------------------------------------------------------------
# curl -I follows no redirects (-L omitted); we expect a 301.
REDIRECT_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    --max-time 10 \
    "http://neurodata.me/" 2>/dev/null || echo "000")

if [[ "$REDIRECT_STATUS" == "301" ]]; then
    check 3 "HTTP port 80 → HTTPS redirect returns 301" "pass"
else
    check 3 "HTTP port 80 → HTTPS redirect returns 301" "fail" \
        "got HTTP $REDIRECT_STATUS (expected 301) — verify port 80 is open at the DO firewall and nginx is serving HTTP"
fi

# ---------------------------------------------------------------------------
# Check 4: HTTPS /health endpoint returns "ok"
# ---------------------------------------------------------------------------
# -s: silent; -k: skip cert validation (in case cert not yet trusted by system CA);
# -o: output to variable; -w: write out HTTP code
HEALTH_BODY=$(curl -sk --max-time 10 "https://neurodata.me/health" 2>/dev/null || echo "")
HEALTH_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 "https://neurodata.me/health" 2>/dev/null || echo "000")

if [[ "$HEALTH_CODE" == "200" ]] && echo "$HEALTH_BODY" | grep -q "^ok"; then
    check 4 "HTTPS /health returns 200 with body 'ok'" "pass"
else
    check 4 "HTTPS /health returns 200 with body 'ok'" "fail" \
        "HTTP $HEALTH_CODE body='$HEALTH_BODY' — check: (a) TLS cert issued (Phase 2 done?), (b) port 443 open at DO firewall"
fi

# ---------------------------------------------------------------------------
# Check 5: Fake Server header is set to uvicorn/0.24.0
# ---------------------------------------------------------------------------
SERVER_HEADER=$(curl -sk -I --max-time 10 "https://neurodata.me/health" 2>/dev/null \
    | grep -i "^Server:" | tr -d '\r' || echo "")

if echo "$SERVER_HEADER" | grep -qi "uvicorn/0\.24\.0"; then
    check 5 "Server header is 'uvicorn/0.24.0' (deceptive header active)" "pass"
else
    check 5 "Server header is 'uvicorn/0.24.0' (deceptive header active)" "fail" \
        "got: '$SERVER_HEADER' — more_set_headers not applying; verify openresty image (not stock nginx) and check nginx error log"
fi

# ---------------------------------------------------------------------------
# Check 6: X-Powered-By header present on root request
# ---------------------------------------------------------------------------
# curl / — may return 502 if honeypot-api is down, but header should still appear
# because add_header ... always applies on all response codes.
XPOWERED_HEADER=$(curl -sk -I --max-time 10 "https://neurodata.me/" 2>/dev/null \
    | grep -i "^X-Powered-By:" | tr -d '\r' || echo "")

if echo "$XPOWERED_HEADER" | grep -qi "FastAPI"; then
    check 6 "X-Powered-By: FastAPI/0.104.1 header present" "pass"
else
    check 6 "X-Powered-By: FastAPI/0.104.1 header present" "fail" \
        "got: '$XPOWERED_HEADER' — check add_header X-Powered-By always; directive in neuro.conf"
fi

# ---------------------------------------------------------------------------
# Check 7: X-Debug-Mode header present
# ---------------------------------------------------------------------------
XDEBUG_HEADER=$(curl -sk -I --max-time 10 "https://neurodata.me/" 2>/dev/null \
    | grep -i "^X-Debug-Mode:" | tr -d '\r' || echo "")

if echo "$XDEBUG_HEADER" | grep -qi "enabled"; then
    check 7 "X-Debug-Mode: enabled header present" "pass"
else
    check 7 "X-Debug-Mode: enabled header present" "fail" \
        "got: '$XDEBUG_HEADER' — check add_header X-Debug-Mode always; directive in neuro.conf"
fi

# ---------------------------------------------------------------------------
# Check 8: /health endpoint is NOT proxied to honeypot-api
# ---------------------------------------------------------------------------
# /health must return 200 "ok" even when honeypot-api is down.
# We verify this by checking that the response is exactly "ok\n" (nginx inline return)
# rather than a JSON object from FastAPI (which would indicate proxying is happening).
HEALTH_CONTENT=$(curl -sk --max-time 10 "https://neurodata.me/health" 2>/dev/null | tr -d '\n' || echo "")

if [[ "$HEALTH_CONTENT" == "ok" ]]; then
    check 8 "/health returns bare 'ok' (served by nginx, not proxied to honeypot-api)" "pass"
else
    check 8 "/health returns bare 'ok' (served by nginx, not proxied to honeypot-api)" "fail" \
        "got: '$HEALTH_CONTENT' — location = /health block may be missing or misconfigured"
fi

# ---------------------------------------------------------------------------
# Check 9: Rate limiting zone is configured in the active nginx config
# ---------------------------------------------------------------------------
# Exec into the container and search the mounted config for the limit_req_zone directive.
RATE_LIMIT_CHECK=$(docker exec nginx grep -r "limit_req_zone" \
    /etc/nginx/conf.d/ 2>/dev/null || echo "")

if echo "$RATE_LIMIT_CHECK" | grep -q "neuro_limit"; then
    check 9 "Rate limiting zone 'neuro_limit' configured in active nginx config" "pass"
else
    check 9 "Rate limiting zone 'neuro_limit' configured in active nginx config" "fail" \
        "limit_req_zone not found in /etc/nginx/conf.d/ — ensure neuro.conf (not neuro-http-only.conf) is the active config"
fi

# ---------------------------------------------------------------------------
# Check 10: TLS certificate is valid and not expiring within 7 days
# ---------------------------------------------------------------------------
# Uses host openssl to connect to the live HTTPS endpoint (not docker exec — OpenResty
# alpine does not include openssl CLI). Checks that cert is present and not expiring
# within 7 days (604800 seconds). Ubuntu VPS always has openssl available.
# set -euo pipefail is temporarily suspended: the s_client pipeline would cause early
# subshell exit under pipefail, leaving the variable empty instead of "expiring".

set +eo pipefail
CERT_PEM=$(echo | openssl s_client -connect neurodata.me:443 -servername neurodata.me 2>/dev/null)
CERT_VALID="error"
CERT_EXPIRY="unknown"
if [[ -n "$CERT_PEM" ]]; then
    echo "$CERT_PEM" | openssl x509 -noout -checkend 604800 2>/dev/null \
        && CERT_VALID="valid" || CERT_VALID="expiring"
    CERT_EXPIRY=$(echo "$CERT_PEM" | openssl x509 -noout -enddate 2>/dev/null \
        | cut -d= -f2 || echo "unknown")
fi
set -eo pipefail

if [[ "$CERT_VALID" == "valid" ]]; then
    check 10 "TLS certificate valid and expires after 7 days ($CERT_EXPIRY)" "pass"
elif [[ "$CERT_VALID" == "expiring" ]]; then
    check 10 "TLS certificate present and valid (>7 days remaining)" "fail" \
        "cert expires $CERT_EXPIRY — run renew-certs.sh immediately"
else
    check 10 "TLS certificate present and valid (>7 days remaining)" "fail" \
        "could not retrieve cert from https://neurodata.me — Phase 2 (certbot issuance) may not have run yet"
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
    echo "  All checks PASSED — Module 7 (nginx) is ready."
    echo ""
    echo "  Post-deployment hardening checklist:"
    echo "    [ ] Replace 'allow 0.0.0.0/0;' in neuro.conf with your management IP"
    echo "        then: docker exec nginx openresty -s reload"
    echo "    [ ] Set up monthly cert renewal cron (as root):"
    echo "        0 3 1 * * /opt/honeypot/deploy/module-7-nginx/renew-certs.sh >> /var/log/certbot-renew.log 2>&1"
    echo "    [ ] Verify HoneyDash is receiving events (check collaborator's dashboard URL)"
    echo "    [ ] Pin the openresty image digest in docker-compose.yml"
    echo ""
    echo "  To confirm end-to-end honeypot request capture:"
    echo "    curl -sk https://neurodata.me/.env | grep AWS_ACCESS_KEY_ID"
    echo "    docker exec postgres psql -U honeypot -d honeypot \\"
    echo "      -c \"SELECT event_type, src_ip, created_at FROM honeypot_events ORDER BY created_at DESC LIMIT 5;\""
    echo ""
    echo "  To watch live nginx access logs:"
    echo "    docker exec nginx tail -f /usr/local/openresty/nginx/logs/neuro_access.log"
    echo ""
    echo "  Module 7 is the final infrastructure module."
    echo "  The full stack is: cowrie → opencanary → mariadb-lure → log-shipper → honeypot-api → nginx"
    echo ""
    exit 0
else
    echo "  FAILED — ${FAIL} check(s) did not pass."
    echo ""
    echo "  Useful debug commands:"
    echo "    docker logs nginx"
    echo "    docker logs nginx 2>&1 | grep -i 'error\|emerg\|crit'"
    echo "    docker exec nginx openresty -t   # test nginx config syntax"
    echo "    docker exec nginx ls /etc/nginx/conf.d/"
    echo "    docker exec nginx ls /etc/letsencrypt/live/"
    echo "    docker exec nginx cat /etc/nginx/conf.d/neuro.conf | head -30"
    echo "    curl -v http://neurodata.me/    # test HTTP redirect (verbose)"
    echo "    curl -vsk https://neurodata.me/health  # test HTTPS (verbose)"
    echo "    docker network ls | grep honeypot-net"
    echo "    docker volume ls | grep certbot"
    echo ""
    exit 1
fi
