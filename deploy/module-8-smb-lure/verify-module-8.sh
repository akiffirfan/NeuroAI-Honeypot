#!/bin/bash
# verify-module-8.sh — SMB lure (Module 8) verification
# Run from /opt/honeypot/deploy/module-8-smb-lure/ on the VPS.
# All 5 checks must pass before enabling DNAT.
#
# Prerequisites:
#   - Module 8: docker compose up -d --build
#   - Lure files in /opt/honeypot/config/smb/
#
# NOTE: Port 445 DNAT is NOT added automatically.
# Confirm port 445 is free (not owned by co-tenant Dionaea) before adding:
#   docker ps | grep -E "0\.0\.0\.0:445|:::445"
# If free, follow the instructions in docker-compose.yml OPERATOR PREREQUISITES.

set -uo pipefail

PASS=0
FAIL=0

ok()   { echo "[PASS] $1"; PASS=$((PASS + 1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL + 1)); }
warn() { echo "[WARN] $1"; }

echo "=== Module 8 — SMB Lure Verification ==="
echo ""

# ---------------------------------------------------------------------------
# Check 1: Container is running
# ---------------------------------------------------------------------------
echo "=== Check 1: Container health ==="
STATUS=$(docker inspect --format '{{.State.Status}}' smb-lure 2>/dev/null || echo "missing")
if [ "$STATUS" = "running" ]; then
    ok "smb-lure container is running"
else
    fail "smb-lure container not running (status: $STATUS) — run: docker compose up -d --build"
fi

# ---------------------------------------------------------------------------
# Check 2: Port 445 NOT bound on host (DNAT-only — no host port binding)
# ---------------------------------------------------------------------------
echo ""
echo "=== Check 2: Port 445 not published on host (DNAT-only mode) ==="
if ss -tlnp 2>/dev/null | grep -q ":445 "; then
    fail "Port 445 is bound on the host — smb-lure should NOT publish host ports. Check docker-compose.yml for stray 'ports:' entries."
else
    ok "Port 445 is NOT bound on host (correct — DNAT-only mode)"
fi

# ---------------------------------------------------------------------------
# Check 3: Port 445 accepts TCP connections on container IP
# ---------------------------------------------------------------------------
echo ""
echo "=== Check 3: Port 445 TCP connect on container IP 10.10.20.10 ==="
if python3 -c "
import socket, sys
s = socket.socket()
s.settimeout(3)
try:
    s.connect(('10.10.20.10', 445))
    s.close()
    sys.exit(0)
except Exception as e:
    print(f'  tcp connect error: {e}')
    sys.exit(1)
" 2>&1; then
    ok "Port 445 TCP connect succeeded (10.10.20.10:445)"
else
    fail "Port 445 not responding on 10.10.20.10 — check container logs: docker logs smb-lure"
fi

# ---------------------------------------------------------------------------
# Check 4: JSON log file created by smb_server.py
# ---------------------------------------------------------------------------
echo ""
echo "=== Check 4: JSON log file exists and contains events ==="

# Wait briefly for startup event to be written
sleep 2

# Find the actual host path of the smb-logs volume
LOG_VOL_PATH=$(docker inspect smb-lure \
    --format '{{range .Mounts}}{{if eq .Destination "/var/log/smb"}}{{.Source}}{{end}}{{end}}' \
    2>/dev/null || echo "")

if [ -z "$LOG_VOL_PATH" ]; then
    fail "Could not locate smb-logs volume mount path — check docker inspect smb-lure"
else
    LOG_FILE="$LOG_VOL_PATH/smb_events.json"
    if [ -f "$LOG_FILE" ] && grep -q '"eventid"' "$LOG_FILE" 2>/dev/null; then
        EVENT_COUNT=$(grep -c '"eventid"' "$LOG_FILE" 2>/dev/null || echo 0)
        ok "smb_events.json has $EVENT_COUNT event(s) at $LOG_FILE"
    else
        fail "smb_events.json missing or empty at $LOG_FILE — check SMB_LOG_FILE env var and volume mount"
    fi
fi

# ---------------------------------------------------------------------------
# Check 5: SMB event appears in PostgreSQL
# ---------------------------------------------------------------------------
echo ""
echo "=== Check 5: SMB event in PostgreSQL (via log-shipper or direct write) ==="

# Trigger a connect event to ensure there is something fresh to verify
python3 -c "
import socket
s = socket.socket()
s.settimeout(3)
try: s.connect(('10.10.20.10', 445))
except: pass
finally:
    try: s.close()
    except: pass
" 2>/dev/null || true

# Allow log-shipper or direct write up to 15 seconds to process the event
echo "  Waiting up to 15 seconds for event to reach PostgreSQL..."
sleep 15

PG_COUNT=$(docker exec postgres psql -U honeypot -d honeypot -t -c \
    "SELECT COUNT(*) FROM honeypot_events WHERE sensor='smb' AND created_at > NOW() - INTERVAL '5 minutes';" \
    2>/dev/null | tr -d '[:space:]' || echo "0")

if [ "${PG_COUNT:-0}" -gt 0 ]; then
    ok "PostgreSQL has $PG_COUNT SMB event(s) from last 5 minutes"
else
    fail "No SMB events in PostgreSQL — verify:
    1. log-shipper mounts smb-logs volume (check deploy/module-5-log-shipper/docker-compose.yml)
    2. SMB_LOG=/var/log/smb/smb_events.json in log-shipper environment
    3. POSTGRES_DSN and REDIS_URL set correctly in module-8 .env
    Hint: docker exec log-shipper env | grep SMB_LOG"
fi

# ---------------------------------------------------------------------------
# Manual test hints (informational — no pass/fail)
# ---------------------------------------------------------------------------
echo ""
echo "=== Manual tests (run after DNAT is live) ==="
echo ""
echo "  Share listing via smbclient (install: apt-get install -y smbclient):"
echo "    smbclient //127.0.0.1/neuro-data-share -N --list"
echo "    smbclient -L //127.0.0.1 -N"
echo ""
echo "  Share listing via external IP (requires DNAT to be active first):"
echo "    smbclient -L //158.220.110.47 -N"
echo ""
echo "  NTLMv2 hash capture test (with credentials):"
echo "    smbclient //127.0.0.1/neuro-data-share -U 'testuser%testpassword'"
echo "    # Expected: connection attempt, auth event emitted, hash in smb_events.json"
echo ""
echo "  Verify NTLMv2 hash in log:"
echo "    grep 'ntlmv2.hash' \$LOG_FILE | python3 -m json.tool | grep ntlmv2_hash | head -1"
echo ""
echo "  Hashcat crack test (mode 5600, static challenge 0011223344556677):"
echo "    hashcat -m 5600 <hash_line> wordlist.txt"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -eq 0 ]; then
    echo "Module 8 VERIFIED"
else
    echo "Module 8 NEEDS ATTENTION"
    exit 1
fi
