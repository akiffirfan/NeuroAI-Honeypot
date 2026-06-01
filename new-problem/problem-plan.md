# New Problem Analysis & Solution Plan
**Date:** 2026-05-30  
**Status:** Planning only — no implementation yet

---

## Problem 1 — Sensor/Port Overlap with Friend's HoneyDash Stack

### Complete Port Map (both stacks)

| Port | Friend's stack | Neuro stack | Conflict? |
|------|---------------|-------------|-----------|
| 22 | — | DNAT → Cowrie 10.10.20.8:2222 | — |
| 80 | Existing web server | — | — |
| 443 | Existing web server | — | — |
| **2222** | **Cowrie (0.0.0.0:2222)** | **Cowrie (0.0.0.0:2222, published)** | **HARD CONFLICT** |
| 2121 | Dionaea FTP | — | None today |
| 21 | — | DNAT → OpenCanary FTP | None today |
| 23 | — | DNAT → OpenCanary Telnet | None today |
| 25 | — | DNAT → OpenCanary SMTP | None today |
| 42 | Dionaea Nameserver | — | None |
| 445 | Dionaea SMB | — | None |
| 1433 | Dionaea MSSQL | — | None |
| 3306 | — | DNAT → MariaDB lure | **FUTURE RISK if Dionaea adds MySQL** |
| 5060 | Dionaea SIP | — | None |
| 5061 | Dionaea SIP TLS | — | None |
| **6379** | — | DNAT → OpenCanary Redis | **FUTURE RISK if Dionaea adds Redis** |
| 4443 | Dionaea HTTPS | — | None |
| 8000 | HoneyDash API | — | None |
| 8080 | — | honeypot-api (loopback only) | None |
| 8081 | — | Nginx (Neuro deception frontend) | None |
| **8090** | **HoneyDash frontend** | **Was planned here** | **SOFT CONFLICT** |
| 8880 | Dionaea HTTP | — | None |

---

### Root Cause Analysis

**HARD CONFLICT — Port 2222:**

Neuro's `module-2-cowrie/docker-compose.yml` publishes:
```yaml
ports:
  - "0.0.0.0:2222:2222"    # binds to ALL host interfaces
```

The friend's Cowrie also binds to `0.0.0.0:2222`. Two Docker containers cannot both publish the same host port. Whichever starts second fails with "bind: address already in use." The losing Cowrie logs nothing → `log-shipper` tails an empty/stale file → no new events → sentinel fires no Telegram alerts. This is why your alerts stopped.

**Critical observation about the DNAT rule:**

```bash
# From honeypot-dnat.sh:
nft add rule ip nat PREROUTING iif "eth0" tcp dport 22 dnat to 10.10.20.8:2222
```

This DNAT rule sends port-22 traffic directly to the container's internal IP (10.10.20.8), bypassing docker-proxy entirely. The `ports: "0.0.0.0:2222:2222"` published binding is NOT needed for the DNAT rule to function — it was added to ensure source IP preservation. Since the DNAT already goes to the container IP directly, the published host port is redundant for port-22 internet traffic.

**SOFT CONFLICT — Port 8090:**

Neuro planned to use 8090 for HoneyDash. The friend is already running HoneyDash frontend there. Neuro's `log-shipper` has `HONEYDASH_URL=` empty by default so nothing is pushing to it now. This needs a coordination decision.

**Future risk — Ports 6379 and 3306:**

Dionaea is extensible. If the friend ever adds Redis or MySQL plugins to their Dionaea instance:
- Dionaea Redis on 6379 would conflict with Neuro's DNAT `6379 → OpenCanary`
- Dionaea MySQL on 3306 would conflict with Neuro's DNAT `3306 → MariaDB lure`
These don't conflict today but need a documented port reservation agreement.

---

### Recommended Fix (minimal disruption, independent sensors)

**Do NOT share the Cowrie log file.** Instead, give each stack its own dedicated Cowrie on a separate port. Port-22 internet traffic → Neuro's Cowrie. Port-2222 internet traffic → friend's Cowrie. These are genuinely different attack surfaces (port 22 = standard SSH, port 2222 = scanner alternative) and the events are NOT duplicates — they are separate sessions from the same scanner sweep.

```
Internet                   VPS host                      Containers
─────────────────────────────────────────────────────────────────────
port 22  ──[nft DNAT]──→  10.10.20.8:2222  ────→  Neuro Cowrie
                                                        │
                                                   log-shipper
                                                   (Neuro DB + Telegram)

port 2222 ─────────────→  0.0.0.0:2222  ──────→  Friend Cowrie
                                                        │
                                                   friend sensor_agent
                                                   (HoneyDash DB)
```

**Neither stack is a duplicate of the other.** Port-22 attackers ≠ port-2222 attackers — different scanner configs, different session IDs, different timestamps. HoneyDash showing both is accurate.

---

### Solution Steps

**Step 1 — Remove Neuro's published port 2222 binding**

In `deploy/module-2-cowrie/docker-compose.yml`, remove or comment out the host port binding:

```yaml
# BEFORE:
ports:
  - "0.0.0.0:2222:2222"

# AFTER:
# ports:  # removed — DNAT goes directly to container IP 10.10.20.8:2222; no published host port needed
```

Then on VPS:
```bash
cd /opt/honeypot/deploy/module-2-cowrie/
docker compose up -d --force-recreate
# Verify Cowrie started and port 2222 is no longer bound on host:
ss -tlnp | grep 2222   # should return nothing
docker logs cowrie 2>&1 | grep "Listening" | tail -3   # should show :2222 inside container
# Verify DNAT still works (from external connection to port 22):
# test: ssh root@158.220.110.47   # should hit Cowrie
```

**Step 2 — Friend's Cowrie keeps its port 2222**

With Neuro's host binding gone, friend's Cowrie can bind `0.0.0.0:2222` without conflict. No changes needed on friend's side for this step.

**Step 3 — Verify each Cowrie is receiving its own traffic**

```bash
# Watch Neuro Cowrie (port-22 traffic):
docker logs -f cowrie 2>&1 | grep "New connection"

# Watch friend Cowrie (port-2222 direct traffic):
# (friend runs equivalent on their container)
```

**Step 4 — Coordinate HoneyDash URL (SOFT CONFLICT)**

Decision: does Neuro want its events in HoneyDash?

- If YES: Set `HONEYDASH_URL=http://127.0.0.1:8000` in Neuro's module-5 `.env`. This sends all Neuro sensor events to friend's HoneyDash. Confirm with friend that their HoneyDash deduplicates by session_id (`ON CONFLICT DO NOTHING` on the events table) — see validation step below.
- If NO: Leave `HONEYDASH_URL=` empty (current default). Neuro has its own PostgreSQL dashboard; HoneyDash shows only friend's sensors.

For the pitch, showing combined data in HoneyDash is more impressive. Recommend YES.

**Step 5 — Protect against future port conflicts (6379, 3306)**

Document the port reservation agreement and add a comment to `honeypot-dnat.sh`:

```bash
# PORT RESERVATION — do not add Dionaea services on these ports without coordination:
# 6379  — owned by Neuro OpenCanary (Redis lure)
# 3306  — owned by Neuro MariaDB lure
# 21    — owned by Neuro OpenCanary (FTP)
# 23    — owned by Neuro OpenCanary (Telnet)
# 22    — owned by Neuro Cowrie (via DNAT)
```

Correspondingly, Neuro should not add DNAT rules for ports the friend's Dionaea owns:
```
# Friend's Dionaea — do NOT add DNAT on:
# 445, 1433, 5060, 5061, 4443, 8880, 42, 2121
```

---

### Service Overlap — Same Attack Type, Different Port

Even without port conflicts, OpenCanary and Dionaea both capture FTP, HTTP, and similar protocols. The same attacker scanner sweep may generate:
- FTP login attempt → OpenCanary on port 21 (logged in Neuro DB)
- FTP login attempt → Dionaea on port 2121 (logged in HoneyDash)

These are NOT duplicates — they are genuinely separate connection attempts to separate services. HoneyDash will show both. This is correct behavior. However, the dashboard may make it look like double the attack volume from one IP. To prevent misreading:

- HoneyDash event cards should show the destination port alongside the service type. If they currently say "FTP attack from X.X.X.X" without a port, a reader might think they're seeing the same event twice.
- Ask friend to confirm HoneyDash shows `dst_port` on event cards, or filter by source to correlate.

---

### Validation Checklist — Problem 1

| Check | Command (run on VPS) | Expected |
|---|---|---|
| No host bind on 2222 | `ss -tlnp \| grep 2222` | No output |
| Cowrie container still running | `docker ps \| grep cowrie` | Up, healthy |
| Port-22 DNAT working | `sudo nft list chain ip nat PREROUTING \| grep 2222` | Rule to 10.10.20.8:2222 present |
| Cowrie receiving connections | `docker logs cowrie 2>&1 \| grep "New connection" \| tail -5` | Real IPs |
| Friend Cowrie running on 2222 | `ss -tlnp \| grep 2222` (after friend restarts) | Friend's container bound |
| No port-6379 Dionaea service | `ss -tlnp \| grep 6379` | Only OpenCanary (10.10.20.6) |
| No port-3306 Dionaea service | `ss -tlnp \| grep 3306` | Only MariaDB (10.10.20.4) |
| Telegram alerts resuming | `docker logs sentinel 2>&1 \| grep ALERT \| tail -5` | Fresh alerts with real IPs |

---

## Problem 2 — Frontend Deception Deficiencies

### Issue 1 — Admin page re-asks for login when already authenticated

**Root cause:** `admin.html` renders a full blank credential form regardless of session state. When an attacker navigates dashboard → `/admin` via sidebar, they see a second login with no user context pre-filled. Real enterprise admin consoles require re-authentication for privileged sections (like GitHub's sudo-mode prompt) but they pre-fill the known identity — "Confirm your identity as m.chen@neuro.ai" — making the re-auth look intentional rather than broken.

**Fix:**
- The `GET /admin` route in `main.py` passes `current_user="m.chen@neuro.ai"` (from session cookie) as a Jinja2 variable.
- `admin.html` pre-fills the username field with `value="{{ current_user }}"` and sets it as `readonly`.
- Heading changes from generic "Admin Console" to "Confirm identity — elevated access required."
- This makes the re-auth pattern look like a deliberate security escalation, not a broken page.

**Validation:** Navigate dashboard → Admin via sidebar. Username field should be greyed-out, pre-filled with `m.chen@neuro.ai`. The form heading should reference the current user identity.

---

### Issue 2 — Login form email field blocks SQLi via browser HTML5 validation

**Root cause:** `<input type="email">` causes Chrome/Firefox to reject values like `' OR '1'='1` before the form submits. The browser intercepts the input client-side; the payload never reaches the server; `_detect_web_attack()` in the middleware never fires.

The password field (type="password") has no such restriction — SQLi in password already works. This fix extends capture to the email field.

**Fix:** Change the email field:
```html
<!-- BEFORE -->
<input type="email" id="local-email" ...>

<!-- AFTER -->
<input type="text" inputmode="email" autocomplete="email" id="local-email" ...>
```

`inputmode="email"` keeps the email keyboard on mobile. `autocomplete="email"` preserves browser autofill. No visual change to the user.

**Deception rationale:** Real SaaS platforms often use `type="text"` on email fields to avoid blocking SSO-variant inputs. Not a tell.

**Validation:**
```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/auth \
  -H 'Content-Type: application/json' \
  --data-raw '{"email":"admin'\'' OR '\''1'\''='\''1","password":"test"}'
# Must return non-200; check DB:
docker exec postgres psql -U honeypot -d honeypot \
  -c "SELECT event_type, created_at FROM honeypot_events WHERE event_type LIKE 'http.sqli%' ORDER BY created_at DESC LIMIT 3;"
```

---

### Issue 3 — Bypass URL lures make SQLi feel redundant (assessment: working as intended)

The HTML source comments on `admin.html` and `dashboard.html` contain:
```
/api/v1/auth/direct?bypass=true (IT#5043)
?ref=sso_bypass
```

These are **intentional lures** — they are NOT real bypasses. The `auth_direct` route logs the attempt and returns a fake session token. The concern is valid from a UX standpoint: source-reading attackers will find these and skip the login form.

**Assessment: This is correct deception behaviour.** Two different attacker archetypes:
- Automated scanners / credential stuffers → hit the login form with SQLi
- Source readers / pentesters → find the bypass comment and use the URL

Both paths are logged. They are not competing — they are complementary sensors for different attacker skill levels. **No change needed.** Document this explicitly in comments so it's not accidentally "fixed" by a future maintainer.

---

### Issue 4 — Workspace switcher dropdown does nothing

**Root cause:** The "Neuro AI — Staging" and "Workspace Settings" buttons have `onclick="event.stopPropagation()"` — this prevents click from bubbling to the document close-dropdown listener, but takes no action of its own. Clicking is a visual no-op. Real tools (Vercel, Linear, Retool) switch your active workspace context with visible feedback.

**Fix:**
- "Neuro AI — Production" (current): show a toast "Already on Production workspace."
- "Neuro AI — Staging": show "Switching workspace..." loading state (1.2s), then reload with `?ws=staging` in URL, display a persistent yellow "⚠ STAGING" environment banner at top of page. Log visit as a page_view event with `workspace=staging` in payload.
- "Workspace Settings": redirect to `/settings/workspace` — a minimal stub page that logs the visit and shows "Workspace configuration managed by your IT administrator." Link to a fake ticket `IT#6204`.

**Validation:** Click each item. No silent no-ops. All three produce visible feedback. PostgreSQL logs a `http.get.settings` or `page_view` event for workspace settings click.

---

### Issue 5 — Missing logout route + "Sign in" vs "Login" text

**Logout route is missing from main.py.** `dashboard.html` user-popup links to `/auth/logout` but this route does not exist. Clicking it triggers the custom 404 handler which returns `"registered_routes": 47` — a direct deception tell.

**Fix — add logout route:**
```python
@app.get("/auth/logout")
async def auth_logout(request: Request):
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie("neuro_session")
    response.delete_cookie("session")
    return response
```
Log as `event_type: "http.get.logout"`. No session validation needed — just clear cookies and redirect.

**Fix — text sweep:** Change "Sign in" → "Login" in `login.html` (title, heading, button text, spinner text). One-line changes, no functional impact.

**Validation:** Click logout from dashboard → browser redirects to `/` (login page). No JSON in response. Check PostgreSQL for `http.get.logout` event.

---

### Issue 6 — Forgot password fires no server-side event

**Root cause:** `submitForgotPassword()` in `login.html` is 100% client-side — it runs a JS timeout then shows "check your email." No POST. The attacker's submitted email (potentially a real probe address, or a canary they control) is never captured.

**Fix:**
1. Add route to `main.py`:
```python
@app.post("/api/v1/auth/forgot-password")
async def forgot_password(request: Request):
    # body logged by middleware automatically
    return JSONResponse({"ok": True, "message": "If this address matches an account, you will receive an email shortly."})
```
2. Add to `_LURE_PATHS` in `main.py` so HoneyDash receives a "Lure Access" push.
3. Update `submitForgotPassword()` in `login.html` to POST before showing success:
```javascript
async function submitForgotPassword() {
    ...
    await fetch('/api/v1/auth/forgot-password', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ email: document.getElementById('forgot-email').value })
    }).catch(() => {});
    // then show success state
}
```

**Validation:**
```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/auth/forgot-password \
  -H 'Content-Type: application/json' \
  -d '{"email":"attacker@evil.com"}'
docker exec postgres psql -U honeypot -d honeypot \
  -c "SELECT event_type, payload->>'email' as email FROM honeypot_events WHERE event_type='http.post.forgot_password' ORDER BY created_at DESC LIMIT 1;"
```

---

### Issue 7 — "Something feels off" — Core Deception Credibility Gaps

Ranked by impact:

**7a. P0 — The 404 page exposes internal route count**

`main.py` custom 404 returns:
```json
{"registered_routes": 47, "hint": "Did you mean /api/v1/runs?", ...}
```
No real platform's 404 advertises its internal route count or offers route suggestions. This is the single most obvious "I'm a honeypot" signal for anyone who hits a dead URL (including the missing logout route).

**Fix:** Replace 404 response body:
```json
{"error": "Not Found", "request_id": "req-<random-uuid>", "status": 404}
```
Nothing else. No route count, no hints, no path suggestions.

**7b. P0 — No session gate — dashboard accessible without logging in**

Any direct navigation to `/dashboard`, `/admin`, `/artifacts` works without a session cookie. A real platform redirects unauthenticated access to login.

**Fix:**
- On successful `POST /api/v1/auth`, issue a session cookie: `response.set_cookie("neuro_session", fake_jwt, httponly=True, samesite="lax")`
- The fake JWT should look structurally real: `eyJhbGciOiJIUzI1NiJ9.<base64-payload>.<fake-sig>`
- Add a `_require_session()` dependency or middleware check on all page routes (`/dashboard`, `/admin`, `/artifacts`, `/jobs/new`, `/settings/*`) — if cookie absent, return `RedirectResponse(url="/")`
- This creates correct behavior where attackers who bypass login via URL lures are immediately visible (they'll hit the lure, get redirected to login, try the login form, and THEN get the dashboard — all captured)

**7c. P1 — Static data never changes between page refreshes**

Same 6 training runs, same progress percentages, same models, same timestamps on every load. Real ML platforms have live-updating job statuses.

**Fix (JS only, no backend changes):**
- On dashboard load, randomize run progress values ±3% using `Math.random()`
- Replace hardcoded `updated_at` timestamps with `Date.now() - Math.random() * 3600000` computed inline
- One "active" run shows elapsed time ticking up via `setInterval` every second
- GPU utilization chart appends a new data point every 3s with a ±2% random walk

**7d. P1 — No reference to neuro-train-01 hostname in job cards**

The SSH Cowrie honeyfs hostname is `neuro-train-01`. The dashboard job cards say "Running on: neuro-prod-cluster" (generic). An attacker who's on the dashboard and wants to pivot to SSH has no explicit invitation. The hostname is the kill chain bridge.

**Fix:** In `dashboard.html` RUNS data array, set `node: "neuro-train-01.internal"` on the active job. Show it as "Running on: neuro-train-01.internal" in the job card detail row.

In `artifacts.html`, the download path should show:
`neuro-train-01:/data/artifacts/llama3-8b/checkpoint-1200/`

**7e. P2 — HTTP security headers absent**

Real production platforms return `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`. Their absence is a tell to security scanners and manual testers.

**Fix:** Add to `deploy/module-7-nginx/neuro.conf`:
```nginx
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=()" always;
```

**7f. P2 — User popup has no "last active" info**

The user avatar popup shows name, role, email. Real tools show session info.

**Fix:** Add one line to the user popup: `Last active: just now` (hardcoded — it's always "just now" from the attacker's perspective since they just loaded the page).

---

### Priority Table

| Priority | Issue | Effort | Survivability impact |
|---|---|---|---|
| P0 | 404 exposes route count (7a) | 15 min | Critical |
| P0 | Session gate — dashboard needs auth (7b) | 45 min | Critical |
| P0 | Logout route missing | 20 min | High |
| P1 | SQLi capture on email field (type=text) | 5 min | High |
| P1 | Workspace switcher non-dead | 30 min | Medium |
| P1 | Forgot password POST to server | 30 min | Medium |
| P1 | Admin re-auth pre-filled user context | 20 min | Medium |
| P1 | neuro-train-01 in job cards (7d) | 15 min | Medium |
| P2 | Dashboard data randomization (7c) | 45 min | Medium |
| P2 | Live chart tick | 30 min | Medium |
| P2 | HTTP security headers (7e) | 20 min | Low |
| P3 | "Sign in" → "Login" text sweep | 10 min | Low |
| P3 | "Last active: just now" in user popup (7f) | 10 min | Low |
| P3 | MIN-R26-2: SSO config.yaml provider alignment | 10 min | Low |

Also still open from Round 26:
| Carry-over | api_keys.html p.nair → priya.nair (MAJ-R26-1) | 5 min | Medium |
| Carry-over | /api/v1/lure/model-manifest route missing (MAJ-R26-4) | 20 min | Medium |

---

## Files to Change (once implementation approved)

| File | Changes |
|---|---|
| `deploy/module-2-cowrie/docker-compose.yml` | Remove `ports: "0.0.0.0:2222:2222"` host binding |
| `deploy/systemd/honeypot-dnat.sh` | Add port reservation comment block |
| `deploy/module-6-honeypot-api/src/main.py` | Add logout route, forgot-password route, session cookie issuance, session gate check, fixed 404, model-manifest route |
| `frontend-latest/login.html` | type="email"→type="text", forgot-password POST call, "Login" text |
| `frontend-latest/dashboard.html` | JS data randomization, live chart tick, neuro-train-01 in job cards, workspace switcher actions, last-active in popup |
| `frontend-latest/admin.html` | Pre-filled user context in re-auth form |
| `frontend-latest/artifacts.html` | neuro-train-01 path in download; model-manifest link fix |
| `frontend-latest/api_keys.html` | p.nair → priya.nair (MAJ-R26-1) |
| `deploy/module-7-nginx/neuro.conf` | Security headers block |

---

## Summary

**Problem 1** is a single-line fix in Cowrie's compose file (remove the `0.0.0.0:2222` host binding) combined with a coordination agreement with friend. The DNAT rule `port 22 → 10.10.20.8:2222` does not need the published host port — it goes directly to the container IP. Once this is removed, friend's Cowrie owns port 2222 and Neuro's Cowrie owns port 22. These are distinct sensors on distinct ports — not duplicates. Future conflict risk on ports 6379/3306 must be documented as a port reservation agreement now before Dionaea is extended.

**Problem 2** has two P0 fixes (404 route exposure, missing session gate) that currently allow any visitor to identify the system as a honeypot within seconds of hitting a dead URL or directly navigating to the dashboard. These must be fixed before the pitch. The remaining items incrementally raise survivability from 6/10 to ~8.5/10 against a manual human attacker.
