#!/usr/bin/env bash
# verify-module-2.sh — Module 2 (Cowrie SSH Honeypot) verification
#
# Run from /opt/honeypot/deploy/module-2-cowrie/ after `docker compose up -d`.
# All 9 checks must pass before proceeding to Module 3.
#
# USAGE:
#   cd /opt/honeypot/deploy/module-2-cowrie/
#   bash verify-module-2.sh
#
# EXIT CODES:
#   0 — all checks passed
#   1 — one or more checks failed
#
# NFTABLES NOTE (NOT applied by this script):
#   After this script passes, the operator must manually configure DNAT and then open port 22:
#
#   Step 17 — Configure nftables DNAT (run as root on VPS):
#     nft add rule ip nat PREROUTING tcp dport 22 dnat to 127.0.0.1:2222
#
#   Step 18 — ONLY THEN open port 22 at the VPS provider firewall/security group.
#     Opening port 22 before Cowrie is running and DNAT is active exposes host SSH.
#
#   Verify DNAT is active:
#     nft list ruleset | grep "dnat to 127.0.0.1:2222"
#
#   See Section 9 of honeypot-project-plans.md for the full nftables ruleset.
#
# EGRESS POSTURE NOTE:
#   Option B (egress-proxy / tinyproxy) was dropped 2026-05-19. Cowrie's treq library
#   ignores $http_proxy env vars so the proxy never captured payloads. Cowrie now has
#   direct egress on honeypot-net (internal: false). Check 9 confirms Cowrie is NOT on
#   the default bridge (internet-routable without Docker NAT) and is NOT dual-homed to
#   any unintended network.

set -uo pipefail

# ── Colour helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS="${GREEN}PASS${NC}"
FAIL="${RED}FAIL${NC}"
WARN="${YELLOW}WARN${NC}"

pass_count=0
fail_count=0

check_pass() { echo -e "  [${PASS}] $1"; ((pass_count++)); }
check_fail() { echo -e "  [${FAIL}] $1"; ((fail_count++)); }
check_warn() { echo -e "  [${WARN}] $1"; }

echo "======================================================"
echo " Module 2 — Cowrie SSH Honeypot Verification"
echo " $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "======================================================"
echo ""

# ── Check 1: Container is running ─────────────────────────────────────────────
echo "Check 1: Cowrie container is running"
if docker ps --format '{{.Names}}\t{{.Status}}' | grep -q "^cowrie"; then
  STATUS=$(docker ps --format '{{.Status}}' --filter "name=^cowrie$")
  check_pass "cowrie container running — ${STATUS}"
else
  check_fail "cowrie container is not running (docker ps shows nothing for 'cowrie')"
  echo "         Hint: docker compose up -d && docker compose logs cowrie"
fi
echo ""

# ── Check 2: Port 2222 bound to loopback only ─────────────────────────────────
# WHY: Cowrie publishes 127.0.0.1:2222:2222. The outer nftables DNAT redirects
# port 22 to 127.0.0.1:2222. Docker handles the inner NAT to the container.
# Publishing to 0.0.0.0 would expose Cowrie directly to the internet on port 2222.
echo "Check 2: Port 2222 listening on loopback only (not 0.0.0.0)"
if command -v ss &>/dev/null; then
  PORT_LINE=$(ss -tlnp 2>/dev/null | grep ':2222' || true)
else
  PORT_LINE=$(netstat -tlnp 2>/dev/null | grep ':2222' || true)
fi

if [[ -z "${PORT_LINE}" ]]; then
  check_fail "port 2222 is not listening — Cowrie may not have started yet"
  echo "         Hint: docker compose logs cowrie | tail -20"
elif echo "${PORT_LINE}" | grep -qE '0\.0\.0\.0:2222|:::2222|\*:2222'; then
  check_fail "port 2222 is bound to ALL interfaces — must be loopback-only (127.0.0.1:2222)"
  echo "         Fix: ports: entry in docker-compose.yml must be '127.0.0.1:2222:2222'"
elif echo "${PORT_LINE}" | grep -q '127.0.0.1:2222'; then
  check_pass "port 2222 bound to 127.0.0.1 only — loopback-only confirmed"
else
  check_warn "port 2222 found but binding unclear — manual check required"
  echo "         Raw output: ${PORT_LINE}"
fi
echo ""

# ── Check 3: Cowrie is on honeypot-net (not default bridge) ───────────────────
echo "Check 3: Cowrie is attached to honeypot-net and not to the default bridge network"
COWRIE_NETWORKS=$(docker inspect cowrie --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null || true)

if [[ -z "${COWRIE_NETWORKS}" ]]; then
  check_fail "could not inspect cowrie container networks — is the container running?"
else
  # Check it IS on honeypot-net
  if echo "${COWRIE_NETWORKS}" | grep -q "honeypot-net"; then
    check_pass "cowrie is attached to honeypot-net"
  else
    check_fail "cowrie is NOT on honeypot-net — networks: ${COWRIE_NETWORKS}"
  fi

  # Check it is NOT on the default bridge (direct internet access, no Docker NAT)
  if echo "${COWRIE_NETWORKS}" | grep -qE '\bbridge\b'; then
    check_fail "cowrie is attached to the default 'bridge' network — this is internet-routable without NAT"
  else
    check_pass "cowrie is not on the default bridge — isolation correct"
  fi
fi
echo ""

# ── Check 4: cowrie-dl volume exists ──────────────────────────────────────────
echo "Check 4: cowrie-dl named volume exists"
if docker volume ls --format '{{.Name}}' | grep -q "cowrie-dl"; then
  check_pass "cowrie-dl volume exists"
else
  check_fail "cowrie-dl volume not found — run 'docker compose up -d' first"
fi
echo ""

# ── Check 5: cowrie.cfg bind-mount is present and read-only ───────────────────
echo "Check 5: cowrie.cfg is bind-mounted read-only"
MOUNT_INFO=$(docker inspect cowrie --format '{{range .Mounts}}{{.Source}} {{.Destination}} {{.Mode}} {{.RW}}
{{end}}' 2>/dev/null | grep "cowrie.cfg" || true)

if [[ -z "${MOUNT_INFO}" ]]; then
  check_fail "cowrie.cfg bind-mount not found in container mounts"
  echo "         Hint: docker inspect cowrie | grep -A5 cowrie.cfg"
else
  if echo "${MOUNT_INFO}" | grep -q "cowrie.cfg.*false"; then
    check_pass "cowrie.cfg is mounted read-only (RW=false)"
  elif echo "${MOUNT_INFO}" | grep -q "ro"; then
    check_pass "cowrie.cfg is mounted with :ro flag"
  else
    check_fail "cowrie.cfg is mounted but NOT read-only — check :ro in docker-compose.yml"
    echo "         Mount info: ${MOUNT_INFO}"
  fi
fi
echo ""

# ── Check 6: SSH banner test (connection reaches Cowrie on loopback) ───────────
echo "Check 6: SSH connection to 127.0.0.1:2222 returns a Cowrie banner"
if ! command -v ssh &>/dev/null; then
  check_warn "ssh client not found — skipping banner test"
  echo "         Install openssh-client and re-run to verify"
else
  BANNER_OUTPUT=$(ssh \
    -o StrictHostKeyChecking=no \
    -o BatchMode=yes \
    -o ConnectTimeout=8 \
    -o PasswordAuthentication=no \
    -p 2222 root@127.0.0.1 2>&1 || true)

  if echo "${BANNER_OUTPUT}" | grep -qiE "connection refused|network unreachable|no route"; then
    check_fail "SSH connection to 127.0.0.1:2222 was refused — Cowrie may not be listening"
    echo "         Output: ${BANNER_OUTPUT}"
  elif echo "${BANNER_OUTPUT}" | grep -qiE "SSH-2\.0|OpenSSH|Permission denied|publickey"; then
    check_pass "SSH banner received from Cowrie on 127.0.0.1:2222"
    BANNER_LINE=$(echo "${BANNER_OUTPUT}" | grep -E "SSH-2\.0|OpenSSH" | head -1 || echo "(banner in auth exchange)")
    echo "         Banner/response: ${BANNER_LINE}"
  elif echo "${BANNER_OUTPUT}" | grep -qiE "timeout|timed out"; then
    check_fail "SSH connection to 127.0.0.1:2222 timed out — Cowrie may be starting up"
    echo "         Wait 10 seconds and re-run"
  else
    check_warn "SSH output ambiguous — manual verification recommended"
    echo "         Output: ${BANNER_OUTPUT}"
  fi
fi
echo ""

# ── Check 7: userns-remap is active for the cowrie container ──────────────────
echo "Check 7: userns-remap is active (container UID 0 maps to host UID 100000)"
USERNS_MODE=$(docker info --format '{{.SecurityOptions}}' 2>/dev/null | grep -o "name=userns" || true)
if [[ -z "${USERNS_MODE}" ]]; then
  check_fail "Docker daemon userns-remap is NOT active — run Module 0 bootstrap and restart Docker"
  echo "         Expected: 'docker info | grep userns' shows 'name=userns'"
  echo "         Fix:      ensure /etc/docker/daemon.json has \"userns-remap\": \"default\""
  echo "                   then: systemctl restart docker"
else
  check_pass "Docker daemon has userns-remap active (${USERNS_MODE})"

  # Read uid_map from the host's /proc/<pid> — avoids needing cat inside the container
  # (Cowrie is a minimal image and may not have cat in PATH)
  COWRIE_PID=$(docker inspect cowrie --format '{{.State.Pid}}' 2>/dev/null || true)
  if [[ -n "${COWRIE_PID}" && "${COWRIE_PID}" != "0" ]]; then
    INNER_UID_MAP=$(cat "/proc/${COWRIE_PID}/uid_map" 2>/dev/null || true)
  else
    INNER_UID_MAP=""
  fi

  if echo "${INNER_UID_MAP}" | awk '{print $2}' | grep -q "^100000$"; then
    check_pass "Container UID 0 maps to host UID 100000 — confirmed"
    echo "         uid_map: ${INNER_UID_MAP}"
  elif [[ -n "${INNER_UID_MAP}" ]]; then
    check_warn "Container uid_map exists but outer UID is not 100000 — verify /etc/subuid"
    echo "         uid_map: ${INNER_UID_MAP}"
    echo "         Expected outer UID: 100000 (dockremap entry: grep dockremap /etc/subuid)"
  else
    check_warn "Could not read uid_map — check: cat /proc/\$(docker inspect cowrie --format '{{.State.Pid}}')/uid_map"
  fi
fi
echo ""

# ── Check 8: No published port on 0.0.0.0 ─────────────────────────────────────
echo "Check 8: No published ports on 0.0.0.0 (all ports must be loopback-only)"
ALL_PORTS=$(docker ps --format '{{.Ports}}' --filter "name=^cowrie$" 2>/dev/null || true)

if [[ -z "${ALL_PORTS}" ]]; then
  check_warn "could not retrieve port bindings — is cowrie container running?"
elif echo "${ALL_PORTS}" | grep -qE '0\.0\.0\.0:[0-9]+->'; then
  check_fail "cowrie has ports published on 0.0.0.0 — attackers could reach non-DNAT path"
  echo "         Ports: ${ALL_PORTS}"
  echo "         Fix:   all ports: entries in docker-compose.yml must use 127.0.0.1:<host>:<ctr> format"
else
  check_pass "no ports published on 0.0.0.0 — all bindings are loopback or unexposed"
  echo "         Ports: ${ALL_PORTS}"
fi
echo ""

# ── Check 9: Cowrie is NOT on egress-proxy or any unintended extra network ─────
echo "Check 9: Cowrie is on exactly one network (honeypot-net) with no unexpected attachments"
COWRIE_NET_COUNT=$(docker inspect cowrie \
  --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null \
  | tr ' ' '\n' | grep -v '^$' | wc -l || true)

if [[ -z "${COWRIE_NET_COUNT}" || "${COWRIE_NET_COUNT}" == "0" ]]; then
  check_fail "could not determine Cowrie network attachment count"
elif [[ "${COWRIE_NET_COUNT}" -eq 1 ]]; then
  check_pass "Cowrie is attached to exactly 1 network — no unexpected extra attachments"
else
  COWRIE_ALL_NETS=$(docker inspect cowrie \
    --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null || true)
  check_warn "Cowrie is on ${COWRIE_NET_COUNT} networks: ${COWRIE_ALL_NETS}"
  echo "         Expected: honeypot-net only. Verify no extra networks were added."
fi
echo ""

# ── Summary ────────────────────────────────────────────────────────────────────
echo "======================================================"
echo " Summary: ${pass_count} passed, ${fail_count} failed"
echo "======================================================"

if [[ ${fail_count} -eq 0 ]]; then
  echo -e " ${GREEN}Module 2 verification PASSED — Cowrie is running and isolated.${NC}"
  echo ""
  echo " NEXT OPERATOR STEPS (manual — not automated):"
  echo "   Step 17: Configure nftables DNAT:"
  echo "            nft add rule ip nat PREROUTING tcp dport 22 dnat to 127.0.0.1:2222"
  echo "   Step 18: Open port 22 at the VPS provider firewall/security group."
  echo "            WARNING: Do NOT open port 22 before Step 17 is complete."
  echo "   Then:    Proceed to Module 3 (OpenCanary)."
  echo ""
  exit 0
else
  echo -e " ${RED}Module 2 verification FAILED — fix the above errors before proceeding.${NC}"
  echo ""
  exit 1
fi
