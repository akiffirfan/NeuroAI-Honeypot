# Gatekeeper Audit — Lastminite-change.md
**Round: Lastminite Review**
**Date: 2026-06-08**
**Verdict: CONDITIONAL APPROVE**
**Intelligence Score: 8/10 | Survivability Score: 5/10**

---

## 1. Overall Verdict

The spec delivers a strong deception architecture: three escalating credential tiers, a bidirectional kill chain connecting HTTP to SSH/MariaDB, a canarytoken CSV that fires post-exfil, and genuinely good visual fidelity for an ML SaaS product. Against automated scanners and low-sophistication opportunistic attackers, this scores 9/10 survivability. Against a thinking human attacker who spends more than 20 minutes view-sourcing pages, survivability drops to approximately 3/10.

The single root cause: the spec is saturated with over-captioned lures — HTML comments that label their own trick, annotate their own fix, and repeat the same IP (`10.31.4.22`) and credential file path (`/etc/neuro/deploy.conf`) across six separate pages. A real accidental leak is unrepeated and uncaptioned. When a human view-sources two consecutive pages and finds the same pattern with a TODO note on both, they know they are in a honeypot. This defect has appeared in prior gatekeeper rounds (R26, R28, R30) and is the single highest-priority fix.

---

## 2. Page-by-Page Critical Issues

### Homepage (`/`)
- **Issue**: HTML comment mentioning internal infrastructure path as a "breadcrumb." A real homepage has zero internal references in source.
- **Fix**: Remove all HTML comments referencing internal IPs, hostnames, or paths from every public-facing page. Only server response headers and page content should carry deception signals.

### Security Page (`/security`)
- **Issue 1**: Comment like `<!-- see deploy.conf for pw -->` or `<!-- remove before deploy -->` — self-remediating TODO in client-served HTML is a fatal tell.
- **Issue 2**: SOC 2 Type II and HIPAA compliance claims on a site running plain HTTP on port 8081. A security researcher who clicks through will notice the missing HTTPS immediately. Either add a note that TLS is required for production login (redirect notice) or remove the HIPAA claim.
- **Fix**: Strip all TODO comments. Change HIPAA/SOC2 copy to "SOC 2 Type II assessment in progress" (startup framing — realistic, no lie).

### Status Page (`/status`)
- **Issue**: Mixing a copyright footer of `© 2025` with incident timestamps from 2026 creates a temporal contradiction that signals a staged environment.
- **Fix**: Pick one year and be consistent. If the site launched in 2025 and now is 2026, the footer should say `© 2026 Cyveera`.

### Login Page (`/login`)
- **Issue**: Error message on failed login echoes back the submitted email address AND names a specific locked persona. This is a stacked enumeration tell — an attacker can confirm which emails are valid accounts.
- **Fix**: Error message must be generic: `"Email or password is incorrect."` Never confirm whether the email exists.

### Jobs/New Page (`/jobs/new`)
- **Issue**: HTML comment `<!-- Init script binary upload (malware capture trap) -->` — the words "malware capture trap" are literally in the client-served HTML source. This is disqualifying.
- **Fix**: Remove entirely. If a comment is needed, use something neutral: `<!-- startup_script: see API docs for allowed formats -->`.

### Artifacts Page (`/artifacts`)
- **Issue**: Comment with `<!-- Direct access: neuro-svc@10.31.4.22 port 22 / Credentials at /etc/neuro/deploy.conf -->` — an exact credential map annotated with its own location. No developer accidentally writes this; it only makes sense as an intentional breadcrumb, and an attacker knows that.
- **Fix**: Remove the explicit comment. The IP `10.31.4.22` can appear as a value inside a config file artifact that the attacker *discovers* — not as an HTML comment pointing them there.

### Settings/Integrations Page
- **Issue**: Same over-captioning pattern — comment explaining the SSRF trap endpoint. Remove it.

### `/.git/config` (Crown Jewel Page)
- **Issue**: The password appears as plaintext inline (`support_password = CyveeraSup!2024`) under `helper = store`. Git's `credential.helper = store` does NOT embed passwords inline — it points to `~/.git-credentials` as a separate file. Any developer who knows git will immediately see this is fabricated.
- **Fix**: Remove the inline password. Instead, have `.git/config` contain a remote URL with embedded credentials: `url = https://support:CyveeraSup!2024@gitlab.cyveera.internal/neuro/neuro-platform.git`. This is how credentials actually appear in git config when developers take shortcuts. The credential is still present and findable, but the format is realistic.

### Cross-Page: `10.31.4.22` Overuse
- **Issue**: The same IP appears as the SSH host, the HTTP relay (`10.31.4.22:3128`), AND the automation session source in the security page active sessions table. A real infrastructure has different IPs for different services.
- **Fix**: Use distinct IPs. SSH target stays `10.31.4.22`. HTTP proxy can be `10.31.4.90:3128`. Automation session can come from `10.31.5.12`. Keep the SSH IP as the main kill chain target but vary everything else.

### Persona Consistency
- **Issue**: `p.nair` appears in some comments while the spec and CLAUDE.md mandate `priya.nair`. These must match everywhere.
- **Fix**: Global find-and-replace — `p.nair` → `priya.nair` across all templates and lure files.

---

## 3. Strongest Elements to Keep

**1. Three-tier escalating credential structure**
`j.smith` (regular user) → `alice.wong` (customer admin, found cross-referencing other data) → `support@cyveera.ai` (found in `.git/config`). Each credential requires more recon effort than the last. This is exactly how real privilege escalation works and produces three distinct attacker behavior events in CTI logs.

**2. SSO fires a real 503 XHR**
The Google Workspace SSO button triggers a real HTTP request to `/api/v1/auth/sso/initiate` before failing. An attacker with DevTools open sees a real network call, not a dead link or a `window.alert()`. This passes the DevTools test that immediately fingerprints most fake login pages.

**3. Neutral telemetry vocabulary**
`field_interaction`, `render_hash`, `dwell_ms` — these are indistinguishable from real analytics events. The vocabulary table is comprehensive and consistent. This is the correct way to name telemetry beacons.

**4. Cross-sensor kill chain (HTTP → SSH → MariaDB)**
The architecture where HTTP compromise leads to SSH IP discovery (`/api/v1/cluster/nodes`) leads to Cowrie SSH honeypot leads to MariaDB credentials in the fake filesystem — this is a complete, realistic kill chain. It produces multi-sensor event correlation in PostgreSQL which is exactly what the CTI project needs.

**5. Canarytoken CSV with post-exfil tracking**
The workspace export CSV containing the live AWS canarytoken fires even if the attacker downloads the file and opens it later, behind a VPN, on a different machine. No other lure in the set crosses the exfil boundary. Keep this exactly as designed.

---

## 4. Top 3 Fingerprint Risks

**Risk 1: Self-captioning breadcrumbs**
As detailed above — six pages with `<!-- ... trap ... -->` or `<!-- remove before deploy -->` comments. A human who view-sources any two pages and finds the same pattern knows instantly. This is the highest-priority fix.

**Risk 2: Too many distinct vulnerability classes on one small startup**
LFI + SSRF (×2) + RCE + canary CSV + file upload + `.git` leak + SQLi + IDOR on the same site signals a "vulnerability sampler platter" that CTF players and honeypot researchers recognize immediately. Trim to 3 primary lures (`.git`, canary CSV, SSRF) and keep the rest as silent reactive SNARE — never advertise more than 3.

**Risk 3: HTTP-only site with HIPAA and SOC 2 compliance claims**
A compliance-certified SaaS that serves its login page over HTTP is an immediate credibility failure. The site runs on port 8081 HTTP-only. Either drop all compliance claims or add a visible note that production deployments require TLS (and point to a docs page that doesn't exist yet — adds realism through incompleteness).

---

## 5. Missing Real-SaaS Elements

These are things a sophisticated attacker would notice are absent and use to conclude the site is not real:

- **`/robots.txt`**: Real SaaS sites always have one. An absent robots.txt on a startup is actually suspicious. Add one that disallows `/api/` and `/internal/` — standard and adds realism.
- **`/security.txt`** (RFC 9116): Security-conscious SaaS companies publish this. Add `Contact: security@cyveera.com` and an expiry date.
- **Favicon and browser metadata**: A site with no favicon.ico or `<meta>` og tags looks unfinished to a thorough recon tool.
- **Dead footer links that 404 gracefully**: `/blog`, `/careers`, `/about` should return a real-looking "coming soon" or "we're hiring" page, not a JSON 404 from FastAPI's default handler. A JSON 404 on a marketing page is a fingerprint tell.
- **Password reset flow**: Every real SaaS has "Forgot your password?" that sends an email. The login page should have this link. It can go to a `/auth/reset` page that says "Check your inbox" without actually sending anything — the request is still logged.

---

## 6. Six-Day Build Feasibility

**Verdict: Achievable as a re-skin of the existing deployed FastAPI honeypot (not greenfield).**

The existing 14 templates, `main.py`, `log_shipper.py`, and `sentinel.py` are kept. The work is rebranding, adding public pages, and implementing real session security.

### What to build first (Days 1-3, non-negotiable core)
1. Real session security — Redis sessions, CSRF, inactivity timeout, rate limiting on auth
2. Login page rebrand (3 copy changes, remove "internal" framing)
3. Landing page (5 sections: hero, logo strip, feature grid, dashboard screenshot, CTA)
4. Session gate confirmed on ALL authenticated routes
5. `.git/config` with realistic credential format (remote URL with embedded creds)
6. Logging confirmed: every event writing to PostgreSQL with IP + timestamp + payload

### What to build if time allows (Days 4-5)
7. Pricing page
8. Dashboard rebrand (VantaraHealth Workspace, not Cyveera internal)
9. Canary CSV content updated to match new company narrative
10. Security headers added to nginx (10 lines)
11. `/api-keys` page with new persona names
12. `/settings/billing` page (session-gated, "Manage Billing" button logs click)

### What to drop entirely
- Fake Stripe billing checkout form — high effort, zero capture value, PCI/legal risk
- `/blog` with actual content — add the route, return a minimal "coming soon" page
- `/settings/admin` as a separate route — fold elevated access into role-based template rendering after normal login instead
- `/settings/security` active sessions table — complex to make realistic, easy to over-caption

---

## 7. Conditions Checklist (must fix before implementation)

- [ ] **C1**: Remove ALL HTML comments containing `<!-- ... trap ... -->`, `<!-- remove before deploy -->`, `<!-- do not expose externally -->`, or any self-remediating TODO from every client-served template. Zero matches required: `grep -rn "trap\|remove before\|do not expose\|fix before" deploy/module-6-honeypot-api/src/templates/`
- [ ] **C2**: Replace `/.git/config` inline password format with realistic git remote URL format: `url = https://support:CyveeraSup!2024@gitlab.cyveera.internal/neuro/neuro-platform.git`
- [ ] **C3**: Replace all `10.31.4.22` references in SSRF/proxy context with a distinct IP (e.g. `10.31.4.90`). SSH kill chain target stays `10.31.4.22`.
- [ ] **C4**: Fix all login error messages to be non-enumerating: `"Email or password is incorrect."` — no echo of submitted email, no locked persona name.
- [ ] **C5**: Remove `p.nair` from all templates and lure files. Global replace with `priya.nair`. Verify: `grep -rn "p\.nair" deploy/`
- [ ] **C6**: Fix temporal contradiction — `© 2025` footer with 2026 incident timestamps. Set to `© 2026 Cyveera`.
- [ ] **C7**: Remove or downgrade HIPAA compliance claim. Replace with `"SOC 2 Type II assessment in progress"`.
- [ ] **C8**: Add `/robots.txt` route returning: `User-agent: *\nDisallow: /api/\nDisallow: /internal/\nSitemap: https://neuro.cyveera.com/sitemap.xml`
- [ ] **C9**: `/blog`, `/careers`, `/about` footer links must not return FastAPI JSON 404. Add minimal placeholder routes returning real HTML.
- [ ] **C10**: Deception vocabulary check must return zero matches before any deploy: `grep -rn "botScore\|canvasFingerprint\|scannerUAs\|honeypot\|attacker\|trap\|lure\|bypass" deploy/module-6-honeypot-api/src/static/ deploy/module-6-honeypot-api/src/templates/`

---

*Audit complete. Conditions C1–C5 block human survivability. C6–C8 block automated fingerprinting. C9–C10 block source-reading tells. Frontend agent should address all 10 before implementation begins.*
