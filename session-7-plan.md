# Session 7 — Attack Surface Expansion Plan
# Date: 2026-06-04
# Status: IN PROGRESS

## What Was Decided (Gatekeeper Approved)

### What We Are NOT Adding (breaks AI platform deception)
- /wp-admin/ — no AI company runs WordPress
- Fake ELF binaries / CUDA installer downloads
- SMTP relay via invite form
- Generic /backup/ directory listing
- 17+ routes
- "Deployment Packages" section in artifacts

### The Real Attack Surface for an AI Training Platform
Attackers target this platform for:
1. Model IP theft (weights worth millions)
2. GPU compute hijacking (crypto mining)
3. Training data exfiltration (medical records, Slack logs)
4. AWS credential theft → cloud lateral movement
5. API resale (inference endpoint access)

---

## CRITICAL: HoneyDash Web Attack Feed Fix (5-minute operator action)

Web attacks from the honeypot-api (SQLi, LFI, RCE, SSRF) do NOT currently appear in
HoneyDash. The routing code already exists in main.py (_push_honeydash_async is called).
The fix is purely a config gap — module-6's .env is missing two env vars.

On VPS (run FIRST before any other deploy):
```bash
sudo bash -c "cat >> /opt/honeypot/deploy/module-6-honeypot-api/.env" <<'EOF'
HONEYDASH_URL=http://host.docker.internal:8090
HONEYDASH_SENSOR_KEY=honeypot2026
EOF
cd /opt/honeypot/deploy/module-6-honeypot-api/
docker compose up -d --force-recreate
```

Verify:
```bash
# SQLi test — should appear in HoneyDash within 3 seconds
curl -s -X POST http://127.0.0.1:8080/api/v1/auth \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin'"'"' OR 1=1--","password":"x"}'
```

After this fix: SQLi, LFI, RCE, SSRF, credential submits all appear in HoneyDash live feed.

---

## 5 Named Attack Scenarios (for demo narrative)

### Scenario A — "The Model Thief" (Corporate Espionage)
Motivation: Fine-tuned LLaMA-3-8B weights worth $2–4M. Attacker wants to steal them.
Path: Login → /models → Download weights → model-manifest.json with AWS canarytoken URL
Demo moment: Canarytoken fires when they use the S3 key from their own machine

### Scenario B — "The Data Broker" (Healthcare Exfiltration)
Motivation: medical-records-deidentified.csv (2.1M rows) sells for $30–150/record
Path: Login → /datasets → Download RESTRICTED file → real CSV with honeytokens served
Demo moment: http.lure.data_exfil alert fires immediately to HoneyDash + Telegram

### Scenario C — "The GPU Miner" ⭐ PRIMARY DEMO SCENARIO
Motivation: Free GPU compute for cryptomining ($400/day on 8×A100)
Path: Login → /jobs/new → read page source (sees IT#5117 comment) → submit startup_script
      with curl|bash payload → server returns uid=1000(neuro-svc),27(sudo) → SSH pivot
Demo moment: RCE alert fires → upload malicious.py → SSH to Cowrie → kill chain correlation

### Scenario D — "The API Reseller"
Motivation: Sell stolen inference API access for LLM queries
Path: /api/docs → Try inference endpoint → hit rate limit → try to create API key
Demo moment: api_docs filter/expand telemetry + credential theft from /settings/api-keys

### Scenario E — "The Insider Pivot" (Credential Stuffing)
Motivation: Use stolen credentials to escalate from web to cloud infrastructure
Path: Login with m.chen@neuro.ai / Cyvera2026! → admin re-auth → copy SSH key → SSH pivot
Demo moment: http.lure.credential.success fires immediately (no cooldown) → kill chain

---

## Priority 1 Framing Fixes (quick, high impact — 30 min each)

These make existing traps self-explaining without being told by the presenter:

1. jobs_new.html startup_script help text:
   Change to: "Shell commands executed in the init container before training starts.
   Runs as neuro-svc. Not validated server-side (IT#5117)."
   → Makes RCE vulnerability obvious in the UI itself

2. main.py _FAKE_RCE_OUTPUT:
   Add ",27(sudo)" to groups string → changes "we captured an attempt" to
   "attacker now has explicit reason to SSH pivot"

3. datasets.html datasetDownload():
   3-phase toast: "Generating presigned URL..." → "Authenticating sts:AssumeRole..."
   → "Redirecting to S3..." → then window.open the actual endpoint
   → Makes AWS architecture feel real, directs attacker to canarytoken URL

4. models.html:
   Add "Download weights" button per model card → fires model_weights_download beacon
   → Route GET /api/v1/models/{id}/download returns fake presigned S3 URL with canarytoken

---

## Backend — Already Written to main.py (2211 lines, syntax clean)

### ✅ Feature 1: Canarytoken CSV Export
- Route: `GET /api/v1/data/exports/download?file=workspace-export-2026-05-31.csv`
- Serves CANARY_CSV_CONTENT with 5 rows
- Contains: AKIAYZM57LXRGIYTCOUV (AWS canarytoken), DNS canarytoken placeholder,
  passwords matching Cowrie userdb.txt, SSH IPs 10.31.4.22/23
- Event type: http.lure.data_exfil → HoneyDash push → Telegram immediate

### ✅ Feature 2: Canarytoken Callback Endpoint
- Route: `POST /api/v1/canarytoken/callback`
- Receives canarytokens.org webhooks when token fires from attacker's real machine
- Captures attacker's out-of-band IP (not honeypot VPN IP)
- Event type: http.canarytoken.fired
- Configure at canarytokens.org: webhook → http://neuro.cyveera.com:8081/api/v1/canarytoken/callback

### ✅ Feature 3: SSRF Remote-Import Trap
- Route: `POST /api/v1/data/remote-import`
- Body: {"source_url": "...", "dataset_name": "...", "format": "parquet"}
- Detects: 169.254.x.x, 127.0.0.1, RFC-1918, file://, gopher://, ldap://
- NEVER makes outbound request — pattern match only
- Event type: http.snare.ssrf_attempt → immediate Telegram, no cooldown

### ✅ Feature 4: Credential Bruteforce Detection
- In existing POST /api/v1/auth
- Per-IP deque(maxlen=20), threading.Lock(), 10-min sliding window
- At 5 failures: logs http.bruteforce.detected with last 5 passwords tried
- At 20 failures: HTTP 429 but keeps logging internally

---

## Fixes Required (Gatekeeper Critical Issues)

### 🔴 CRIT-1: Bruteforce threshold bug
- Current: `if fail_count == _BF_THRESHOLD` — misses fast bots (6+ req/s skips == 5)
- Fix: fire once at crossing — check `fail_count >= _BF_THRESHOLD and (fail_count - 1) < _BF_THRESHOLD`

### 🟡 MAJ-1: CSV rows identical
- All 5 rows have same AKIAYZM57LXRGIYTCOUV key — staged-data tell
- Fix: vary api_secret_key across rows, only svc-deploy row gets live AWS token

### 🟡 MAJ-2: DNS placeholder not replaced
- `REPLACE_WITH_DNS_CANARYTOKEN_SUBDOMAIN` still in code — if built as-is, DNS token never fires
- Fix: add startup assertion `assert "REPLACE_WITH" not in CANARY_CSV_CONTENT`

### 🟡 MAJ-3: CSV filename
- `team-credentials.csv` — no real AI platform exports a file with this name
- Fix: rename to `workspace-export-2026-05-31.csv`

### P3-9: Double URL-encoding bypass
- %2527 → %27 → ' bypasses _detect_web_attack() pattern matching
- Fix: apply urllib.parse.unquote_plus() twice before pattern matching

---

## New Features (This Session — Not Yet Built)

### Malware Upload Endpoint
- Route: `POST /api/v1/training/jobs/script-upload`
- Context on /jobs/new: "Attach initialization script (.py)" form field
- Accepts multipart file upload, caps at 50MB
- Saves to /app/uploads/{timestamp}_{ip}_{filename} (named Docker volume)
- NEVER executes the file
- Event type: http.upload.malware_received — _NO_COOLDOWN_EVENTS, immediate Telegram
- Telegram format: "UPLOAD: {filename} ({size} bytes, {mime}) from {ip}"
- Add upload-captures volume to docker-compose.yml

### Fake Downloadable Files
The principle: no legitimate users → every download is an attacker → no false positives
All files served as real downloads with Content-Disposition: attachment
All fire http.lure.data_exfil immediately (no cooldown)

| Filename | Format | Honeytokens |
|---|---|---|
| workspace-export-2026-05-31.csv | CSV | AWS key (row 4), DNS canarytoken, SSH IPs, passwords |
| medical-records-deidentified.csv | CSV (fake, ~20 rows) | AWS key in metadata comment, NeuroML2024! as "db_password" field |
| internal-slack-logs-Q1.jsonl | JSONL (4 fake messages) | Cyvera2026! mentioned in message, SSH IP in text |
| model-manifest.json | JSON | S3 presigned URL with AKIAYZM57LXRGIYTCOUV |
| checkpoint-stub.bin | Binary stub | ELF magic header + plaintext SSH key hint |

All lure file content hardcoded as constants in main.py (no filesystem reads)

---

## Frontend — Not Yet Built

### datasets.html changes
- 3-phase toast on all Download buttons: "Generating presigned URL..." → "Authenticating IAM role sts:AssumeRole..." → "Redirecting to S3..."
- After toast: window.open('/api/v1/data/exports/download?file={name}', '_blank')
- "Import from URL" form: URL input + Import button → POST /api/v1/data/remote-import
- "Database Exports" section above dataset table with workspace-export CSV download

### login.html changes
- After 3 failed attempts: show "Account m.chen@neuro.ai temporarily locked — too many attempts. Reset via SSO."
- This confirms valid username, motivates attacker to keep trying
- Add dwell-time beacon: time from page load to first email field focus
  (humans: 500ms-3s, bots: <50ms — distinguishes scanner from human)

### settings_integrations.html (NEW TEMPLATE)
- Webhook configuration UI: endpoint URL, events checkboxes, "Test Webhook" button
- Test button POSTs to POST /api/v1/integrations/webhook/test (already in main.py)
- HTML comment: "webhook calls internal HTTP relay at http://10.31.4.22:3128/"
- Add "Integrations" nav link to all 13 existing templates under Settings section

### jobs_new.html changes
- Add file attachment field: "Attach initialization script (.py, optional)"
- Fires multipart POST to /api/v1/training/jobs/script-upload
- Help text: "Script runs as neuro-svc (uid=1000) on neuro-train-01. Not validated server-side (IT#5117)"

---

## P1/P2/P3 Backlog — What's Still Worth Doing

### Keep — do before pitch
- P2-10: Kill chain stage state machine (RECON→INITIAL_ACCESS→EXFIL in attacker_sessions)
- P2-14: admin.html reads username from session (not hardcoded m.chen)
- P3-9: Double URL-encoding bypass (now load-bearing with SSRF endpoint)

### Drop — superseded or out of scope
- P2-4: /search endpoint → SSRF remote-import is stronger
- P2-9: API key reveal/replay → canarytoken CSV covers this story better
- P3-7: Team activity feed → not a sensor
- P3-8: Support ticket widget → not a sensor
- P2-3: /settings/security (2FA page) → adds complexity, low attack value
- P2-11: /settings/workspace → low value, cuts into build time

---

## Operator Actions Required Before Deploy

1. Register DNS canarytoken at canarytokens.org
   - Type: DNS
   - Memo: neuro-team-export-csv-2026
   - Webhook: http://neuro.cyveera.com:8081/api/v1/canarytoken/callback
   - Replace REPLACE_WITH_DNS_CANARYTOKEN_SUBDOMAIN in main.py lines 725-729

2. Add to module-6 .env on VPS:
   HONEYDASH_URL=http://host.docker.internal:8090
   HONEYDASH_SENSOR_KEY=honeypot2026

3. Pre-create uploads directory on VPS:
   sudo mkdir -p /opt/honeypot/uploads && sudo chmod 700 /opt/honeypot/uploads

4. Add upload-captures volume to docker-compose.yml (see Feature: Malware Upload)

---

## 3-Demo Sequence (Gatekeeper Approved)

1. Credential spray on login
   → Telegram shows actual password list being tried ("last 5 passwords: admin, 123456, NeuroML2024!...")

2. Download workspace-export CSV → attacker uses AWS key on their machine
   → canarytokens.org fires out-of-band → POST to /api/v1/canarytoken/callback
   → Telegram: "CANARYTOKEN FIRED from 203.x.x.x — DIFFERENT IP from honeypot VPN"
   → "We followed the attacker to their real machine"

3. RCE via startup_script + upload malicious.py → SSH pivot
   → http.rce.attempt fires
   → http.upload.malware_received fires ("malicious.py saved to captures/")
   → cowrie.login.success fires 30s later
   → Sentinel kill chain correlation: same IP, HTTP→SSH, 30 seconds

---

## Sync Rule (unchanged)
Edit frontend-latest/ first → copy to deploy/module-6-honeypot-api/src/templates/
Verify: for f in base.html login.html dashboard.html ...; do diff frontend-latest/$f deploy/.../$f; done
Deploy: scp + docker compose up -d --build --force-recreate + bash verify-module-6.sh (must stay 10/10)
