# Security Audit — `slapdash-web.md` (Neuro by Cyveera Frontend Spec)

**Auditor**: honeypot-deployment-gatekeeper
**Date**: 2026-06-09
**Document under review**: `/home/akiff/honeypot-project/slapdash-web.md` — 20-page Jinja2/FastAPI deception frontend
**Verdict applies to**: the SPEC, before any code is written.

---

## 1. Overall Verdict

**CONDITIONAL APPROVE.**

**INTELLIGENCE: 8/10**
**SURVIVABILITY: 6/10**

This is the strongest frontend spec this project has produced. The deception engineering is mature: the credential discovery chain (`.git/config` → `support` creds → `/login` → `cyveera_support` role → `/admin/cross-tenant` → Pivot Force modal → Cowrie) is coherent end-to-end, the SSRF and S3-bypass traps correctly never reflect content, the telemetry vocabulary is clean throughout, and the canarytoken delivery vehicles (PDF pixel, S3 backup tarball, fake API keys) are well chosen. The intelligence yield is high because the spec captures intent at every decision point with pre-beacons that fire *before* the POST.

It is NOT an unconditional approve for three reasons, each individually capable of burning the deception against the exact adversary it is built to catch — a source-reading human:

1. **Two self-remediating-TODO HTML comments** (`/artifacts`, `/settings/integrations`) reproduce the single most-recurring tell in this project's history. These read as bait, not oversight.
2. **A hostname-consistency contradiction** — the spec invents `j.smith@vantarahealth.com` / `alice.wong@merisol.io` personas and a `VantaraHealth` workspace, while the established cross-surface invariant (Cowrie honeyfs, MariaDB seed, prior templates) is `m.chen` / `priya.nair` / hostname `neuro-train-01`. A pivoting attacker who reads both surfaces sees two different companies.
3. **The clipboard-hijack in the Pivot Force modal** is a genuine OPSEC and detectability liability (`navigator.clipboard.writeText()` requires focus + permission and silently overwriting an attacker's clipboard with `ssh neuro-svc@10.31.4.22` is itself a strong "this is a trap" signal if they paste anything else first).

Fix the conditions in Section 8 and this becomes a full approve.

---

## 2. Council Agreement Compliance

**1. Jinja2 + FastAPI, NOT React — COMPLIANT.** Header line 6 states "FastAPI + Jinja2 + inline JS. No React, no build tooling, no CDN frameworks." No React-specific behavior assumed anywhere. Pricing toggle (line 188) and the drift chart (line 665) are explicitly specified as static/visual-only "to avoid runtime dependencies" and "to avoid a syntax error" — the author correctly understands the no-build constraint. Good.

**2. `.git/config` via PlainTextResponse with realistic remote URL format — COMPLIANT.** Lines 1064–1090. Content-Type `text/plain`, no JSON wrapper, credential embedded in the remote URL the realistic way: `url = https://support:CyveeraSup!2024@gitlab.cyveera.internal/...`. NOT an inline `support_password =` key. `/.git/HEAD` returns `ref: refs/heads/main`. This is exactly right. Minor note in §3.

**3. SSRF trap returns `{"status":"ingestion_queued","job_id":"..."}`, never renders content — COMPLIANT.** Lines 592–597: "The backend never makes an outbound request... NEVER renders the fetched content of the URL — only the job ID. An attacker submitting `http://169.254.169.254/latest/meta-data/` sees: `{"status": "ingestion_queued", "job_id": "..."}`." Correct and explicit.

**4. S3 bypass uses `artifact_path` param, escape path `../../exports/workspace-backup-2025-11.tar.gz` — COMPLIANT.** Lines 611, 630, 633. Parameter is `artifact_path` (not `s3_key`); traversal target is exactly `../../exports/workspace-backup-2025-11.tar.gz`. Response is "identical in status code and headers to a legitimate file download" — correct, no differential tell.

**5. Pivot Force: `10.31.4.22` in error trace/config, not explicit SSH invite; clipboard added silently — COMPLIANT IN PLACEMENT, FLAGGED IN MECHANISM.** Lines 1152, 1157: IP appears as `cause: SOC2_HOLD on node 10.31.4.22 (mgmt-plane)` — correctly framed as management plane, not "SSH server." The clipboard copy is silent (lines 1169–1171). Placement is correct per the agreement. **However the clipboard mechanism itself is a liability** — see §3 and §5. The agreement said "clipboard copy added silently"; it was, but I am flagging the *technique* as risky.

**6. No CSRF tokens (SameSite=Lax sufficient) — COMPLIANT.** Line 1201: `SameSite=Lax`, `HttpOnly`, `Path=/`, no `Secure` on HTTP-8081. No CSRF token machinery anywhere. Consistent with a honeypot that wants attacker POSTs to succeed.

**7. `/changelog` and `/team` pages included — COMPLIANT.** `/changelog` is page 5 (lines 367–421), `/team` is page 13 (lines 751–788). Both present and substantive.

**8. Login errors non-enumerating, never echo submitted email — COMPLIANT.** Line 448: "The submitted email is NEVER echoed back in the error message." 401 returns generic "Incorrect email or password." Good.

**9. No self-captioning HTML comments — PARTIALLY VIOLATED.** The spec has NO `<!-- trap -->` or `<!-- remove before deploy -->` comments, and the author clearly tried. BUT two comments reproduce the *self-remediating-TODO* anti-pattern, which is the same defect class:
- Line 615 (`/artifacts`): `<!-- TODO: validate artifact_path server-side — currently passed to presign handler as-is (p.nair @ 2026-03-14) -->`
- Line 960 (`/settings/integrations`): `<!-- internal HTTP relay: 10.31.4.22:3128 — do not expose externally (p.nair @ 2026-03-21) -->`
The first is a self-remediating TODO that documents the exact vulnerability being trapped — a real engineer does not annotate a live LFI with "TODO: fix this, it's exploitable." The second is acceptable-ish (it doesn't spell out a credential) but combined with the trace and notification placements, `10.31.4.22` is now captioned four times. **This is a CONDITION (see §8).**

**10. No "sampler platter" of vuln classes — MOSTLY COMPLIANT.** The trap set is disciplined and *thematically coherent for an ML platform*: SSRF (remote dataset import — perfect fit), path traversal (artifact download — perfect fit), credential discovery (.git), honeytokens (API keys, AWS key in tarball, PDF canary), SSH-key submission, privilege-escalation lure (cross-tenant console). There is no PHP/wp-admin/SMTP-relay contamination. The only mild over-reach: `/api/v2/debug/flush-cache` and the IP-allowlist `0.0.0.0/0` "Enable" button are low-yield decorations that add surface without much intel. Not blocking, but see §3.

---

## 3. Page-by-Page Issues

**`/` Homepage — canvas+WebRTC beacon on a PUBLIC page.** The `getUserMedia({audio:true})` probe (line 99, 1197) triggers a **browser permission prompt** in some configurations and, more importantly, modern Chrome/Firefox mDNS-obfuscate ICE candidates (`.local` hostnames) by default since 2020 — so `lan_ips` will frequently be empty or useless against an up-to-date browser, while the `getUserMedia` call risks a visible permission flash. A public marketing homepage that probes your microphone is itself anomalous if anyone inspects it. **Fix:** drop the `getUserMedia` call entirely; keep only the `RTCPeerConnection` STUN ICE-candidate gather (no mic permission needed) and accept that it returns mDNS hostnames on modern browsers. Keep canvas hash.

**`/docs` — `internal` and `debug` tabs with amber "not for public consumption" dots (lines 253, 266–267).** This is good intent-capture, but real API documentation does not ship internal/debug endpoints in the public docs with a visual "you shouldn't look here" marker — that's a honeypot affordance, not a doc-site pattern. Real leakage of internal endpoints happens by *omission of access control*, not by advertising them with a warning dot. **Fix:** keep the endpoints in the list but remove the amber "not for public consumption" framing; let the `internal`/`debug` tags themselves be the lure. The intent-capture (beacon on tag click) still works.

**`/docs` — `/run/secrets/support_creds` trail "leading nowhere" (line 281, 284).** A dead trail that 404s is acceptable, but combined with the fact that the *real* support credential is discoverable via `.git/config`, this is a second pointer to the same prize. Redundant. Keep it — it's low-cost — but be aware sophisticated attackers enumerate `/run/secrets/` via path traversal on `/artifacts` and getting a 404 there while the tarball traversal succeeds is a small inconsistency.

**`/login` — paste-capture in capture phase, described mechanically (line 427).** The behavior is fine; the spec's *description* names the purpose ("catches automated credential-stuffing tools"). That's spec-doc text, not client code — acceptable. But ensure the implementer does NOT carry "credential-stuffing" into a JS comment. Flag for the build.

**`/settings/security` Active Sessions — rows 2 and 3 both `10.31.4.22` as "Ubuntu 22.04 (automation)" and "svc-deploy script" (lines 1007–1008).** Two active sessions from the *same internal IP* with `neuro-train-01.internal` as a "location" is plausible, but the "location" column for a real session table shows a geo/city, not a hostname. Mixing `neuro-train-01.internal` into a Location column is a small realism slip. **Fix:** label the column "Location / Source" or move the hostname into the Device column.

**`/admin/cross-tenant` — three action buttons all return 403 with identical body (lines 1126–1134).** Realistic, but a `Drop Tenant DB` button that is purely decorative is a missed intel opportunity AND a slight tell (why expose a destructive button that can never work?). It's fine for engagement. Lower priority. The bigger issue is the modal clipboard hijack — see §5.

**`/settings/integrations` webhook test — `relay: "http://10.31.4.22:3128/"` returned in JSON (lines 970–973).** Good lure (squid-style proxy on the mgmt node). Consistent with the trace. Keep. This is the *fifth* appearance of `10.31.4.22`; cross-page consistency is good (memory confirms this is desirable), but make sure every appearance frames it as infra, never as "SSH here."

**`/pricing` — `$399`/`$499` Pro pricing vs `/settings/billing` showing "$899/mo" Pro for 3 seats (line 207 vs 878).** 3 seats × $299.67 (the invoice line item, line 922) = $899.00. But the pricing page says Pro is "$399 per seat/month billed annually" or "$499/seat billed monthly." 3 × $399 = $1,197, not $899. **The billing page and pricing page do not reconcile.** A careful attacker (or just a careful reviewer) notices the math doesn't work. **Fix:** reconcile the numbers — either the invoice unit price matches a published per-seat price, or add a "negotiated rate" line.

**`/datasets` — `internal-slack-corpus-Q1` 8.7 GB JSONL tagged INTERNAL (line 571).** This overlaps with an existing lure file the backend already serves (`internal-slack-logs-Q1.jsonl` per CLAUDE.md). Good — reinforce the consistency, but ensure the dataset name here (`internal-slack-corpus-Q1`) and the downloadable file name match, or the cross-reference breaks.

---

## 4. Strongest Elements

**1. The credential-discovery chain is fully coherent (lines 1090, 743–747, 1212–1218).** `.git/config` leaks `support:CyveeraSup!2024`; the `support@cyveera.ai` account is independently corroborated by Notification 8 ("New team member added: support@cyveera.ai... granted temporary access... cross-tenant") and the `/team` members table; using those creds at the *same* `/login` form routes to `cyveera_support` → `/admin/cross-tenant`. From an attacker's perspective this is exactly how a real privilege-escalation finding feels: you find a leaked cred, you corroborate the account exists elsewhere, you use it, you land somewhere privileged. The multi-surface corroboration is what sells it.

**2. The SSRF trap's "accept-and-confirm, never reflect" design (lines 592–597).** "An attacker submitting `http://169.254.169.254/latest/meta-data/` sees `{"status":"ingestion_queued"}`... They get confirmation that the URL was accepted, motivating them to probe further, while the backend silently logs the SSRF attempt." This is textbook — it captures intent and *encourages escalation* without ever leaking real IMDS data. The double-beacon (pre-beacon before the POST, line 556) guarantees capture even if the attacker kills the connection.

**3. The PDF canarytoken delivery (lines 904–930).** A real, pre-generated B2B invoice PDF with an embedded 1×1 canarytoken pixel that "fires... without requiring an internet connection to the Neuro VPS — it contacts canarytokens.org directly from the attacker's machine." This is the highest-value post-exfil tracking mechanism in the whole spec — it follows the attacker *off* the honeypot to wherever they open the file, which is exactly the intelligence gap flagged in prior rounds (zero post-exfil tracking). The fake ACH routing/account numbers are a nice touch that make the PDF feel real without leaking anything live.

**4. Intent capture via pre-beacons across every trap (lines 556, 604, 754, 937, 980).** Every dangerous action fires a telemetry beacon with the attacker-supplied value *before* the server processes it: SSRF URL, artifact path, invite email, webhook URL, allowlist CIDR. This means even a connection-killing or proxy-stripping attacker leaves a record of *what they intended to do*. This is the difference between "we saw an attacker" and "we saw an attacker try to reach IMDS at 169.254.169.254 from CIDR x.x.x.x/24 they entered as their own allowlist." High actionable yield.

**5. Clean telemetry vocabulary throughout (lines 1189, 1193, 1207).** `render_hash`, `lan_ips`, `quality_score`, `interactionScore`, `field_interaction`, `page_view` — every wire key and function name is neutral analytics vocabulary. `getCanvasMetrics()` not `getCanvasFingerprint()`. The author internalized the lesson from prior rounds: the name describes the data type, not what the defender wants to detect. The vocabulary gate (line 1207) is included in the spec itself.

---

## 5. Fingerprint Risks (Top 3 specific to THIS spec)

**1. The self-remediating TODO comment on `/artifacts` (line 615).** `<!-- TODO: validate artifact_path server-side — currently passed to presign handler as-is (p.nair @ 2026-03-14) -->`. A skilled attacker who reads HTML source — *the exact adversary this whole system is designed to catch* — has seen this pattern in CTF honeypots a hundred times. Real engineers do not leave a comment that says "this parameter is exploitable and I haven't fixed it" sitting next to the exploitable parameter. The presence of the vulnerability is the lure; *captioning* it as a known-unfixed vuln converts it from "oversight" to "bait." This is the #1 thing that gets this site burned. (This exact pattern — self-remediating TODO — has recurred 3+ times in this project's audit history; it is a known repeat offender.)

**2. The clipboard hijack in the Pivot Force modal (lines 1169–1171).** `navigator.clipboard.writeText('ssh neuro-svc@10.31.4.22')` fired silently on modal open. Three problems: (a) `navigator.clipboard.writeText()` requires the document to be focused and, on many browsers, a transient user-activation — fired on modal *open* (not on a click) it may silently fail or, worse, throw a console error visible in DevTools; (b) silently overwriting an attacker's clipboard is itself detectable — a careful operator who copies something, opens the modal, then pastes and gets `ssh neuro-svc@10.31.4.22` instead, *immediately* knows the page tampered with their clipboard, which screams "trap"; (c) it's an aggressive technique that a paranoid attacker will read as hostile. The IP placement in the trace is good; the clipboard write is the part that betrays it.

**3. Persona / company-identity contradiction across surfaces.** The spec uses `VantaraHealth` workspace, `j.smith@vantarahealth.com`, `alice.wong@merisol.io` as the *logged-in customer identity*. But the established cross-surface fixture invariant on this project is `m.chen` / `priya.nair@cyvera.ai` / `svc-deploy`, hostname `neuro-train-01`, and the SSH honeyfs + MariaDB seed are built around those. An attacker who pivots HTTP→SSH (the whole point of the Pivot Force) lands on Cowrie as `neuro-svc@neuro-train-01` and sees a config/bash_history referencing `m.chen`/`priya.nair`/`cyvera.ai`, while the web console he just came from was branded `VantaraHealth`/`vantarahealth.com`. Two different companies = staged environment. (Note: the spec DOES correctly use `priya.nair@cyveera.ai` in `.git/config` line 1085 and `p.nair` in comments — but introduces a *new* customer-side persona set that wasn't reconciled with SSH/DB.)

---

## 6. Missing Real-SaaS Elements

A real B2B ML-observability SaaS at this maturity (SOC 2 Type II, GA, paying customers) would have several things this spec lacks. None are blocking, but adding 2–3 cheap ones raises realism:

- **`robots.txt` and `/sitemap.xml`.** Every real marketing site has these. A honeypot with no `robots.txt` is mildly anomalous to a scanner. Cheap to add; `robots.txt` can also seed a believable `Disallow: /admin/` line that *looks* like accidental disclosure.
- **`/security.txt` (`/.well-known/security.txt`).** Any SOC 2 shop has one. Its absence is a small tell for a security-conscious attacker. Add a minimal one pointing at `security@cyveera.ai`.
- **A favicon and consistent OpenGraph/meta tags.** Marketing pages without `<meta og:*>` or a favicon look hand-built. Trivial to add.
- **Cookie consent / privacy banner.** A SOC 2 + GDPR-claiming SaaS (line 240) with no cookie banner is inconsistent with its own compliance claims. The spec claims GDPR compliance but never shows a consent mechanism.
- **A real 404 page that matches the brand.** The spec says `/terms` and `/privacy` "404 with a generic error" (line 461). A generic framework 404 on an otherwise polished site is a seam. Build one branded 404 template.
- **Rate-limit headers / `Retry-After` on the 429 path (line 447).** The login shows a 429 UI but the spec doesn't mention the server sending `Retry-After`. Real rate limiters do. Without it, scripted attackers see a 429 with no `Retry-After`, which is slightly off.
- **HTTP security headers** (`X-Frame-Options`, `Content-Security-Policy`, `Strict-Transport-Security` would be absent on HTTP-only, but `X-Content-Type-Options: nosniff` should be present). A SOC 2 shop sets these. Their total absence is fingerprint-able.

---

## 7. 6-Day Build Assessment

**Is 20 pages in Jinja2 in 6 days achievable? — YES, but only with strict prioritization and aggressive template reuse.** The spec is well-scoped *because* it forbids React/build tooling and reuses one sidebar + one top bar across 12 authenticated pages. The static-data approach (no live data fetching, hardcoded tables) is what makes this feasible. The risk is not the page count — it's the 17 distinct telemetry beacon variations and the trap backend logic. Most trap endpoints already exist in the deployed `main.py` (SSRF, S3 bypass, `.git/config`, canary CSV, SSH-key submit, lure files) — the spec is largely a *frontend* layer over backend that is mostly built. That dramatically lowers the real cost.

**Priority order:**

**BUILD FIRST (Days 1–3) — the deception spine. These carry all the intelligence value:**
1. `base.html` (sidebar + top bar + footer + telemetry include) — everything inherits this. Build once, build right.
2. `/login` + credential-tier routing (server-side validation, role → redirect). This is the gate to everything authenticated.
3. `/.git/config` + `/.git/HEAD` (PlainTextResponse) — trivial, highest-yield discovery lure.
4. `/admin/cross-tenant` + Pivot Force modal — the crown jewel. (Build WITHOUT the clipboard hijack per §8.)
5. `/artifacts` (S3 bypass) and `/datasets` (SSRF) — the two core ML-platform traps. Backend mostly exists.
6. `/settings/profile` SSH-key submission + `/settings/billing` PDF canarytoken — the two best pivot/post-exfil mechanisms.

**BUILD SECOND (Days 4–5) — corroboration surfaces that make the spine believable:**
7. `/dashboard`, `/runs`, `/models` — the "this is a real product" proof. Mostly static tables.
8. `/notifications` (corroborates support account + IP history), `/team` (corroborates support account), `/settings/security` (corroborates IP history + adds MFA-disable capture).
9. `/` homepage, `/pricing`, `/docs`, `/status`, `/changelog` — public realism layer.
10. `/settings/integrations` webhook SSRF.

**DEFER / DROP (Day 6 if time, else cut):**
- The pricing Monthly/Annual toggle (already spec'd as visual-only — fine to ship inert).
- `/api/v2/debug/flush-cache` doc entry and the `0.0.0.0/0` allowlist Enable button — low-yield decoration, drop if time-pressed.
- The `getUserMedia` mic probe — DROP entirely (§3, §5), keep only STUN ICE gather.
- Cookie banner / `security.txt` / `robots.txt` — nice-to-have realism, do last.

**The 6-day plan is realistic IF the backend trap endpoints are confirmed already-deployed.** If any trap backend must be written from scratch, cut the public realism layer (homepage/pricing/docs can be thinner) before cutting any trap.

---

## 8. Conditions Checklist

Each item is concrete and verifiable. All must be satisfied before this spec is approved for implementation.

1. **Remove the self-remediating TODO comment on `/artifacts` (line 615).** Replace with no comment at all, or a neutral infra note that does NOT name the vulnerability or its fix. Verify: `grep -rn "TODO.*validate\|passed to presign\|as-is" templates/` returns zero. The LFI trap works without the comment — the editable `artifact_path` field IS the lure.

2. **Reduce `10.31.4.22` captioning on `/settings/integrations` (line 960).** Keep at most a bare infra reference; strip the self-remediating "do not expose externally" + author/date annotation. Verify the IP appears framed as infrastructure (mgmt-plane / relay / node) and never with a "before prod" or "do not X" remediation caption on any page.

3. **Resolve the persona/company-identity contradiction.** Pick ONE customer identity convention and reconcile it against the SSH honeyfs (`~/.config/neuro/config.yaml`, `~/.bash_history`), MariaDB `neuro_prod` seed, and hostname `neuro-train-01`. Either (a) make the web console's logged-in workspace consistent with the SSH/DB personas (`m.chen`/`priya.nair`, `cyvera`/`cyveera` domain), or (b) document an explicit, defensible reason the customer-side identity differs from the platform-operator identity. Verify: a single grep of all surfaces shows one company domain for operator accounts and a consistent persona set. (`priya.nair@cyveera.ai` in `.git/config` and `p.nair` in comments are already consistent — the NEW `vantarahealth.com`/`merisol.io` customer personas are the unreconciled additions.)

4. **Remove the clipboard hijack from the Pivot Force modal (lines 1169–1171), OR change its trigger and accept the risk.** Preferred: drop `navigator.clipboard.writeText()` entirely — the `ssh neuro-svc@10.31.4.22` string is already visible in the trace and the third paragraph; the attacker will type it themselves, which is *higher-fidelity intent capture* than a clipboard they may never paste. If retained, it MUST fire on an explicit user click (not modal open), MUST be wrapped in try/catch so a failed write throws no console error, and the spec must accept the detectability tradeoff in writing.

5. **Drop the `getUserMedia({audio:true})` probe (lines 99, 1197).** Keep only the `RTCPeerConnection` STUN ICE-candidate gather. Verify no `getUserMedia` call exists in any client asset. This removes the permission-prompt risk and the mic-probe anomaly while preserving whatever LAN-IP value WebRTC still yields on modern browsers.

6. **Reconcile pricing vs billing math.** `/pricing` Pro pricing (line 207) and `/settings/billing` invoice (lines 878, 922) must produce consistent arithmetic, or add an explicit "negotiated/legacy rate" note that explains the discrepancy. Verify: published per-seat price × seat count = invoice total, OR a documented exception line exists.

7. **Remove the amber "not for public consumption" framing on the `/docs` internal/debug tabs (lines 253, 266–267).** Keep the endpoints and the intent-capture beacon; remove the visual honeypot affordance. Real docs don't flag their own forbidden endpoints with a warning dot.

8. **Run the canonical defender-vocabulary grep against the IMPLEMENTED templates and JS before deploy** (the spec includes the gate at line 1207 — expand it to include `honey|honeytoken|puppeteer|playwright|selenium|credential.stuff|plans\.md|Section [0-9]`). Verify zero matches in `templates/` and `static/`. This is a hard gate, not advisory — inline `<script>` blocks inside `.html` ARE in scope.

9. **Add a branded 404 template** for `/terms`, `/privacy`, and unknown `.git/*` paths (lines 461, 1092). Verify these paths return a brand-consistent 404, not a framework default and not a JSON error with a route hint.

10. **Confirm every trap's backend logic exists or is scheduled before its frontend page is built.** Verify each of `/api/v2/data/import` (SSRF), `/api/v1/artifacts/download` (S3 bypass), `/.git/config`, `/api/v1/profile/ssh-keys`, the PDF canary, and the `/admin/cross-tenant` role gate has a corresponding backend handler. A frontend lure with no backend capture logs nothing — it is pure decoration and a wasted page.

---

*End of audit. Re-submit with conditions 1–10 addressed (or condition 3, 4, 6 explicitly waived with written justification) for full approval.*

---

# Gatekeeper Audit — Round 2 (slapdash-web.md revision)
**Date**: 2026-06-09
**Auditor**: honeypot-deployment-gatekeeper
**Document under review**: `/home/akiff/honeypot-project/slapdash-web.md` — revised 20-page spec, addressing the 10 Round-1 conditions
**Verdict applies to**: the SPEC, before any code is written.

---

## 1. Overall Verdict

**CONDITIONAL APPROVE — one blocker remaining (the billing/pricing arithmetic still does not reconcile against its own "Billed monthly" label).**

**INTELLIGENCE: 9/10** (up from 8)
**SURVIVABILITY: 8/10** (up from 6)

The revision is excellent. Nine of the ten Round-1 conditions are fully resolved, and the two highest-severity tells from Round 1 — the self-remediating `/artifacts` TODO and the Pivot Force clipboard hijack — are completely gone. The survivability jump from 6 to 8 is driven almost entirely by those two removals plus the de-captioning of `10.31.4.22`: the spec no longer hands a source-reading human the three "this is bait" signals that would have burned it on first inspection. Intelligence rises to 9 because the new corroboration surfaces (the persona invariant, the branded 404, the robots/sitemap/security.txt triad, the cookie banner) make the deception read as a real SOC-2 SaaS rather than a hand-built stage, which keeps a sophisticated attacker engaged longer and deeper into the trap chain.

It is held at CONDITIONAL for exactly one reason: **Condition 6 (pricing vs billing math) is only PARTIALLY fixed.** The internal invoice arithmetic is now self-consistent (3 × $299.67 = $899.01 → $899.00), but the billing card labels that same invoice "Billed monthly" while the per-seat figure used is the *annual* rate. A careful attacker — or a careful customer — who reads `/pricing` ($375/seat monthly, $300/seat annual) and then `/settings/billing` ("$899/mo … 3 seats · Billed monthly") sees a monthly-billed account paying the annual per-seat rate. 3 × $375 = $1,125, not $899. The numbers reconcile only if the account is billed *annually*; the label says monthly. This is a one-line fix and the last thing standing between this spec and a full approve.

---

## 2. Round-1 Condition Verification

| # | Condition | Status | Evidence |
|---|---|---|---|
| 1 | Self-remediating TODO on `/artifacts` removed | **PASS** | Line 615 now describes the `GET /artifacts?path=` LFI trap with no HTML comment; the editable `artifact_path` field is the lure, uncaptioned. |
| 2 | `10.31.4.22` "do not expose externally" caption reduced on `/settings/integrations` | **PASS** | Lines 964–968 reduce it to a bare `<!-- mgmt-plane relay node: 10.31.4.22:3128 -->` with no remediation annotation, no author/date, no "do not X." |
| 3 | Persona / company-identity contradiction resolved | **PASS (documented exception, option b)** | Lines 1171–1189 add a "Cross-surface persona invariant" section explicitly separating platform-operator identities (m.chen / priya.nair / svc-deploy / `neuro-train-01` / `cyvera-ml-artifacts`) from customer-side identities (j.smith / alice.wong / support), with a defensible rationale (customer workspace = product; SSH node = infrastructure). See §4 for the one residual risk this creates. |
| 4 | Clipboard hijack in Pivot Force modal removed/changed | **PASS** | Lines 1165, 1169: "The modal contains no `navigator.clipboard.writeText()` call. The SSH command is presented as visible text" — attacker types it themselves (higher-fidelity intent). |
| 5 | `getUserMedia({audio:true})` dropped from homepage | **PASS** | Line 99 and line 1211 both state explicitly "no microphone or camera permission is requested"; only the STUN `RTCPeerConnection` ICE gather remains, with mDNS-obfuscation acknowledged. |
| 6 | Pricing vs billing math reconciled | **PARTIAL — BLOCKER** | Invoice internal math is now consistent (line 930: 3 × $299.67 = $899.01 → $899.00), but the billing card (lines 880–882) labels it "Billed monthly" while using the annual per-seat rate; `/pricing` (line 207) says monthly is $375/seat → 3 × $375 = $1,125 ≠ $899. Monthly label contradicts annual-rate total. |
| 7 | Amber "not for public consumption" framing removed from `/docs` tabs | **PASS** | Line 253: "There is no amber dot, no warning marker, and no 'not for public consumption' label … they surface by name alone." |
| 8 | Vocabulary gate noted as hard gate | **PASS** | Line 1223: "This is a hard gate — not advisory." Grep expanded to include `honey|honeytoken|puppeteer|playwright|selenium|credential.stuff|plans\.md|Section [0-9]` (line 1221). |
| 9 | Branded 404 template added | **PASS** | Lines 1234–1244: full standalone branded 404 spec; `/terms`, `/privacy`, unknown `.git/*` all route to it (lines 461, 1086). |
| 10 | Backend trap status confirmed per trap page | **PASS** | Lines 1275–1288: explicit table marking each trap "Backend exists" or "Backend to build" (4 to build: artifact download, SSH-key submit, PDF canary, team invite). |

**Score: 9 PASS, 1 PARTIAL (blocking), 0 FAIL.**

---

## 3. Quality of the Fixes

The fixes are not cosmetic — they are correct at the mechanism level, which is what matters:

- **Condition 1/2 (captioning):** The author did not merely soften the language; they removed the self-remediating *structure*. Line 615 no longer documents the vulnerability at all, and line 253 articulates the correct doctrine in the spec itself ("Real API documentation does not annotate its own internal endpoints with caution notices; they surface by name alone"). That doctrine being written down means the implementer is less likely to reintroduce the tell. This is the right way to kill a recurring defect class.

- **Condition 4 (clipboard):** The replacement is *better* than a fixed clipboard call, not just safer. Lines 1153/1165 reframe the SSH string as visible text inside a leaked error trace (`cause: SOC2_HOLD on node 10.31.4.22 (mgmt-plane)` + `Connect: ssh neuro-svc@10.31.4.22`). An attacker who reads the trace and types the command produces a cleaner intent signal than a clipboard write that may silently fail or be detected. This converts a liability into an asset.

- **Condition 5 (getUserMedia):** Correctly scoped down to STUN-only ICE gathering, with honest acknowledgment (line 1211) that modern browsers return `.local` mDNS hostnames — the spec does not over-claim the LAN-IP yield. Good.

- **Conditions 9 + the §6 realism gaps from Round 1:** The author went beyond the condition and added robots.txt, sitemap.xml, security.txt, and a cookie-consent banner (lines 1246–1269), plus the branded 404. These were Round-1 "missing real-SaaS elements" (non-blocking), now closed. The robots.txt correctly discloses `/admin/` and the internal/debug API prefixes as an intentional, plausible breadcrumb without over-disclosing the whole `/api/` tree.

---

## 4. NEW Issues Introduced by the Revision

The revision introduced new content. Most is clean. Three items are worth flagging; only the first is a blocker (it is the unresolved half of Condition 6).

**NEW-1 — BLOCKER (this is the residual of Condition 6). Billing "Billed monthly" label contradicts the annual per-seat rate.**
- `/pricing` line 207: Pro = "$300 per seat / month, billed annually" with "or $375/seat billed monthly."
- `/settings/billing` lines 880–882: "$899/mo" + "3 seats · Billed monthly."
- Invoice line 922/930: unit price $299.67/seat × 3 = $899.01 → $899.00.
- The invoice unit price ($299.67) is the *annual* tier ($300, discounted $0.33 for the contract term per line 930). But the billing card says **Billed monthly**. A monthly-billed Pro account at the published rate is 3 × $375 = $1,125. The math only closes if the account is billed *annually*.
- **Fix (one line):** Change the billing-card subtext (line 882) from "3 seats · Billed monthly" to "3 seats · Billed annually" so the annual per-seat rate matches the label. Then the invoice "Due Date 2026-07-01" and the renewal date stay coherent with an annual cycle. Verify: published annual per-seat price × seats = invoice total, AND the billing-card cycle label matches the rate tier used. (Alternatively, restate the invoice at $375/seat and fix the total to $1,125 — but the annual-label fix is cheaper and keeps every existing dollar figure intact.)

**NEW-2 — MINOR (not blocking). The documented persona split (Condition 3, option b) is defensible but creates one live seam at the HTTP→SSH pivot.**
The invariant section (lines 1171–1189) is the right call and is internally reasoned. But operationally, the *whole purpose* of the Pivot Force modal is to push the attacker HTTP→SSH. When they land on Cowrie as `neuro-svc@neuro-train-01`, they are in the **operator** layer (m.chen / priya.nair / cyveera.ai) — which is correctly consistent with `.git/config` (line 1079, `priya.nair@cyveera.ai`) and the honeyfs. The seam is only exposed if an attacker explicitly cross-references "the customer I was logged in as was VantaraHealth/vantarahealth.com" against "the infra I SSH'd into is cyveera.ai." The spec's framing (customer = tenant of the product; SSH node = vendor infrastructure) is genuinely how multi-tenant SaaS works, so a sophisticated attacker will likely accept it. **No fix required**, but two cheap reinforcements would erase the seam entirely: (a) ensure the `/admin/cross-tenant` table (lines 1113–1118) shows VantaraHealth as a *tenant row* (it does — good), reinforcing that VantaraHealth is a customer of Cyveera, not Cyveera itself; (b) confirm the SSH honeyfs `.bash_history` / config does NOT reference any customer (`vantarahealth`, `merisol`) — operator infra should reference only cyveera-internal names. **Verification action for the implementer:** grep the deployed Cowrie honeyfs and MariaDB seed for `vantara`, `merisol`, `quelaris`, `ardentix`, `lumira`, `denova` — these customer names must NOT appear in the operator layer, or the two-company seam becomes visible inside SSH. (Note: line 356 of the spec — incident INC-2026-031 references "the Ardentix nightly fine-tune job" on the *status page*, which is customer-facing and fine; the constraint is the SSH/DB operator surface only.)

**NEW-3 — MINOR (not blocking). `/admin/cross-tenant` table has a data-consistency slip: two different workspaces share one admin email.**
Lines 1115–1116: `VantaraHealth` admin = `alice.wong@merisol.io` AND `Merisol` admin = `alice.wong@merisol.io`. The same person admins two unrelated customer tenants, and her email is on the Merisol domain while administering VantaraHealth. On the `/team` page (line 768) alice.wong is the *Admin* of the VantaraHealth workspace but with a `merisol.io` email — a cross-domain admin. This is internally repeated (so at least it is *consistently* odd), but a careful attacker reading the cross-tenant console will notice one email owning two tenants on a third tenant's domain. Real cross-tenant tables show distinct admin emails per tenant. **Fix (cheap, optional):** give VantaraHealth its own admin email (e.g. `alice.wong@vantarahealth.com` or a distinct persona), or accept it as a deliberate "support contractor manages multiple small tenants" story. Not blocking — but if you touch the billing fix anyway, fix this in the same pass.

**Everything else new is clean.** The robots.txt / sitemap.xml / security.txt / cookie-consent additions are correct and free of tells. The branded 404 spec is brand-consistent. The expanded vocabulary gate is correct. The `/docs` re-spec is correct doctrine. The Active Sessions column was correctly renamed to "Location / Source" (line 1007, 1017) per Round-1 §3 — the hostname `neuro-train-01` now lives in the Device column, resolving the Round-1 realism slip.

---

## 5. What a Real Attacker Would Do Against the Revised Spec

A competent human reads source on `/`, `/login`, `/docs`. Vocabulary is clean — no defender terms, `getCanvasMetrics()` not `getCanvasFingerprint()`, no mic prompt. The canvas/STUN beacons look like ordinary product analytics. They enumerate from `robots.txt` → `/admin/` (403/branded-404), hit `/.git/config` → harvest `support:CyveeraSup!2024`, corroborate the support account in `/team` and Notification 8, log in, get routed to `/admin/cross-tenant`, trip the action buttons, read the leaked trace, and SSH to `neuro-train-01` as `neuro-svc` — landing in Cowrie. Every step fires a pre-beacon; every credential use is logged; the PDF canary follows them off-box. **The chain holds.** The only place the illusion can crack is NEW-1: a billing-savvy attacker who reads `/pricing` then `/settings/billing` notices a monthly-billed account paying the annual rate. That is a smaller crack than any Round-1 tell, but it is a crack, and it is trivially closeable.

---

## 6. Remaining Blockers (numbered, concrete, verifiable)

**Only ONE blocker remains:**

1. **Reconcile the billing-cycle label with the per-seat rate (Condition 6 residual / NEW-1).** Change `/settings/billing` line 882 subtext from "Billed monthly" to "Billed annually" (cheapest fix — keeps every dollar figure), OR restate the invoice at the $375/seat monthly rate with a $1,125 total. **Verify:** the billing-card cycle label matches the rate tier used in the invoice line item, AND published per-seat price (for that cycle) × seat count = invoice total. The renewal date (2026-07-01, line 882) and invoice due date (line 928) must remain coherent with whichever cycle is chosen (an annual cycle with a single monthly-looking invoice history of six $899 rows would itself be inconsistent — if you choose "annual," the invoice history should reflect one annual charge or the rows should be relabeled; if you keep six monthly rows, the per-seat must be the monthly rate). **This sub-point matters:** the six-row monthly invoice history (lines 897–902, one $899 charge per month) is itself evidence of *monthly* billing. So the lowest-risk fix is actually the reverse: keep "Billed monthly," and set the invoice unit price to the **monthly** rate. Pick the published monthly per-seat price so 3 × it = the per-invoice amount, and make `/pricing` monthly, `/settings/billing` card, the six invoice rows, and the PDF line item all use that single number.

**Recommended concrete resolution** (removes all ambiguity): set Pro monthly = **$299/seat/month** on `/pricing` (drop the $375 figure or make $375 the list price and $299 the negotiated rate stated on the invoice), keep "Billed monthly," keep six monthly $897 rows (3 × $299 = $897) — or keep $899 and use $299.67. The single invariant to enforce: **one per-seat monthly number, used identically on `/pricing`, the billing card, all six invoice rows, and the PDF, with seat-count × that number = every displayed total.**

---

## 7. Non-Blocking Polish (do in the same pass if touching billing)

- **NEW-2 verification:** grep deployed Cowrie honeyfs + MariaDB seed for customer names (`vantara`, `merisol`, `quelaris`, `ardentix`, `lumira`, `denova`) — must be ABSENT from the operator layer.
- **NEW-3:** give VantaraHealth a distinct admin email in the cross-tenant table, or accept the multi-tenant-contractor story.
- `/api/v2/debug/flush-cache` doc entry and the `0.0.0.0/0` allowlist "Enable" button remain low-yield decoration — keep if cheap, drop if time-pressed (unchanged from Round 1).

---

## 8. Green-Light Path

This spec is **one line away from FULL APPROVE.** Resolve blocker 1 (the billing-cycle/rate reconciliation, §6) and the spec is cleared for implementation with no further audit round required, PROVIDED the implementer also runs these two hard gates at build time:

**Build-time hard gates (must pass before deploy, not before approval):**
- [ ] Vocabulary grep (spec line 1221, expanded) returns zero matches in `templates/` and `static/`, inline `<script>` blocks in scope. Only intentional `<!-- breadcrumb -->` comments excepted, each individually reviewed.
- [ ] Cowrie honeyfs + MariaDB seed contain NO customer-company names (operator layer must reference only cyveera-internal identities) — closes the NEW-2 seam.
- [ ] Every "Backend to build" trap (artifact download, SSH-key submit, PDF canary, team invite — spec lines 1278, 1282, 1284, 1285) has its capture handler in `main.py` BEFORE its frontend page ships. A frontend lure with no backend logs nothing.
- [ ] Single per-seat price number used identically across `/pricing`, billing card, all invoice rows, and the PDF (blocker 1).

Clear blocker 1 in writing and this is a FULL APPROVE on re-read — no new round needed.

---

*End of Round 2 audit. Re-submit with blocker 1 resolved for full approval. All other Round-1 conditions are satisfied.*

---

# Gatekeeper Audit — Round 3 (Final Verification)
**Date**: 2026-06-09
**Verdict**: FULL APPROVE

This is a targeted re-read of the two changed areas only — not a full re-audit. Both fixes landed correctly and no new critical issues were introduced.

## Round 2 Blocker 1 (billing math) — RESOLVED ✓
- Billing card (§19, line 880): now reads "$899/mo" + "3 seats · Billed annually." — no longer claims "Billed monthly".
- Renewal (line 882): "2027-01-01" + "Annual contract · Auto-renews unless cancelled 30 days prior." Consistent with annual term.
- CTA (line 886): "Upgrade to annual" is gone — replaced with "View contract details or add seats →". Correct, since VantaraHealth is already on annual.
- Invoice line (line 924/930): 3 × $299.67 = $899.01 → $899.00, reconciled in writing against the $300/seat published annual price. Arithmetic is internally consistent and the discount rationale is plausible B2B language.
- `/pricing` (lines 207–208): "$300 per seat/month, billed annually" and "$375/seat billed month-to-month" are clearly labelled as distinct tiers. No collision with the annual contract.
- Cross-check: the "$899/mo … billed annually" display is the standard SaaS monthly-equivalent convention, not a contradiction. June invoice Due Date (2026-07-01) and annual contract Renewal (2027-01-01) are different fields and do not conflict. Nothing here burns the deception against a source-reading human.

## NEW-3 (cross-tenant admin email) — RESOLVED ✓
- Cross-tenant table (§20, line 1115): VantaraHealth admin = `j.smith@vantarahealth.com`. Correct.
- Line 1116: Merisol admin = `alice.wong@merisol.io` — Alice Wong remains Merisol-only. Identity legend (lines 1183–1184) stays consistent: j.smith → VantaraHealth customer_user, alice.wong → Merisol customer_admin. No cross-tenant identity bleed.

## No new issues
No contradictions introduced by the edits. Personas, hostnames, and the discovery chain (.git/config → support:CyveeraSup!2024 → cyveera_support → /admin/cross-tenant) remain coherent. All Round-1 and Round-2 conditions are now satisfied.

## Green-light implementation checklist (build in this order)
1. **Backend skeleton + session/auth** (§5 login, §17 role→redirect map): `/login` POST returning `{role, redirect}`, `nro_session` cookie, three role tiers (customer_user / customer_admin / cyveera_support). Role gate on `/admin/cross-tenant`.
2. **Event logging pipeline first** — wire every route through `_log_event()` before building page content, so no surface ships dark. Confirm `_log_event(event: dict)` sync signature (fully-built dict) — do not invent `await _log_event(request, type, {})`.
3. **Core authenticated pages** (§ dashboard, runs, models, datasets): static fixtures with the consistent persona/workspace values (j.smith/VantaraHealth, alice.wong/Merisol, svc-deploy dual-layer).
4. **Discovery-chain lures** (§ .git/config, §19 billing PDF canarytoken, §20 cross-tenant): pre-generate the invoice PDF with the embedded canarytoken pixel; register the canarytoken before deploy. Verify the $299.67/$899.00 figures render in the PDF exactly as specced.
5. **Cross-tenant crown jewel** (§20): all three action buttons return HTTP 403 with identical body; emit the high-value alert event on any hit.
6. **Frontend vocabulary gate + source-reader pass** before deploy: run the CLAUDE.md grep gate (zero defender-vocab matches), confirm billing card / pricing / invoice strings match this spec verbatim, and confirm no `<a href>` points to an unrouted path (404→JSON cross-product tell).
7. **Sentinel alert tiers**: canarytoken-fired and cross-tenant-access events must be in the no-cooldown set.

Ship it.

---

*End of Round 3 audit. Spec is approved for implementation.*

---

# Gatekeeper Audit — Round 4 (React Architecture)
**Date**: 2026-06-09
**Verdict**: CONDITIONAL APPROVE
**Intelligence**: 9/10
**Survivability**: 7/10

Auditor: honeypot-deployment-gatekeeper. Scope: full re-read of the React-SPA rewrite of `slapdash-web.md` (Vite + react-router-dom v6 + headless FastAPI + nginx), against the 10 mandatory checks plus a hunt for defects the React migration introduced. Rounds 1-3 (Jinja2 lineage) remain valid history; this round audits the new architecture from scratch where it diverges.

The deception engineering carried over intact — the discovery chain (`.git/config` -> `support:CyveeraSup!2024` -> `cyveera_support` -> `/settings/admin` -> leaked SSH trace -> Cowrie), the SSRF/S3 traps, the PDF + AWS canarytokens, the persona invariant, and the clean telemetry vocabulary all survived the port. All 10 mandatory checks PASS. But the migration from server-rendered HTML to a client-hydrated SPA broke the **delivery mechanism for the two HTML breadcrumb comments** — they will not appear in view-source, which is the exact recon path they exist to feed. That is a CONDITIONAL, not a FULL APPROVE. Survivability drops one point from Round 3's 8 to 7 solely because of this SPA view-source gap and a handful of new internal seams; intelligence holds at 9.

---

## Mandatory Checks (10/10 PASS)

| # | Check | Status | Evidence |
|---|---|---|---|
| 1 | Semantic camouflage — no defender vocab in component/hook/context/var names | **PASS** | §2.5 table (lines 121-134) maps every prohibited name to a SaaS-real name (`RemoteImportModal`, `WorkspaceDataProvider`, `S3ArtifactBrowser`, `ComplianceLockModal`, `InvoiceDownloadButton`, `useTelemetry`). No `Honeypot/Fake/Lure/Trap/Canary/Decoy/Scanner/Attacker` in any *code identifier*. §2.6 (line 142) bans defender strings from the `define` block / bundle. Spec-prose section headings ("Remote Import Trap", "S3 Prefix Bypass Trap") are document labels, not code — acceptable, but see New Issue 6 for the bundle-leak risk. |
| 2 | Unified login — no re-auth modal | **PASS** | §2.3 (line 91) + §8.8 (lines 1337-1345): `cyveera_support` reaches `/settings/admin` only via `/login` returning `{"redirect_to":"/settings/admin"}`; `CrossTenantAdminPage` silently `navigate("/dashboard")` for any other role with "no error page, modal, or credential prompt." Line 1345 states route-gating is "the only enforcement mechanism — there is no re-authentication prompt, no 'enter elevated credentials' modal, and no second login form on any page." The `ComplianceLockModal` (§19) is an *action-blocked* dialog, NOT a credential prompt — it asks for nothing, only displays a trace. Zero exceptions confirmed. |
| 3 | `.git/` via PlainTextResponse, no nginx alias, other `/.git/*` -> 404 | **PASS** | §2.7 (line 148): "There must be no `location /.git/` block with an `alias`." §5 (lines 1200-1242): `/.git/config` + `/.git/HEAD` are FastAPI `PlainTextResponse`, proxied; all other `/.git/*` hit the SPA wildcard -> `NotFoundPage`. Correct. |
| 4 | Branded 404, no 503 catch-all | **PASS** | §2.2 (line 61) + §6 (lines 1246-1265): `<Route path="*">` -> `NotFoundPage` in `MarketingLayout`; "There is no 503 catch-all, no `ServiceDegradedPage`." The only `503` in the doc is the SSO-button error (line 542), which is a deliberate single-endpoint behavior, not a catch-all — correct. |
| 5 | API version `/api/v2/` consistent | **PASS (with seam — New Issue 2)** | Only two `/api/v1/` references exist (lines 625, 1378), both explicitly labelled migration notes ("Update the route prefix"). All live endpoints are `/api/v2/`. PASSES the literal check. BUT an internal naming inconsistency exists *within* v2 — see New Issue 2. |
| 6 | S3 tarball three-file payload | **PASS** | Lines 696-702: exactly `production.env`, `docker-compose.yml`, `aws_credentials.csv`. Live canarytoken `AKIAYZM57LXRGIYTCOUV` on the `svc-deploy` row (row 3, line 702). Matches the deployed CLAUDE.md canarytoken. Correct. |
| 7 | Dynamic User-Agent in active sessions | **PASS** | §18 Section 2 (lines 1078, 1082): row 1 reads `user.ip` and `user.user_agent_parsed` from `WorkspaceDataProvider` (populated by `GET /api/v2/auth/me`), rendered as e.g. "Firefox on Linux" — NOT hardcoded "Chrome on macOS." Backend table (line 1388) flags `auth/me` as "build/extend" to return these fields. Correct. |
| 8 | No getUserMedia | **PASS** | Zero `getUserMedia` occurrences in the document. §8.3 (lines 1303-1305) + line 203 explicitly: "No microphone, camera, or other media device permission is requested at any point." Only `RTCPeerConnection` STUN ICE gather remains, with honest mDNS-obfuscation caveat. Correct. |
| 9 | No clipboard hijack in ComplianceLockModal | **PASS** | §19 (line 1185): "No `navigator.clipboard.writeText()` call exists anywhere in this component. The SSH command is presented as visible text." The only `clipboard` reference (line 889, api-keys "Copy" button) is a *legitimate user-initiated copy on click* of a honeytoken key — that is real SaaS UX, not a silent hijack, and is fine. Correct. |
| 10 | Billing math consistent | **PASS** | Line 306 ($300/seat/mo billed annually), line 950 ("$899/mo" + "3 seats · Billed annually"), line 952 (Renewal 2027-01-01, "Annual contract"), lines 995/1000 (3 × $299.67 = $899.01 -> $899.00, negotiated-rate rationale). No "Billed monthly" contradiction anywhere — the Round-2 blocker stayed fixed across the rewrite. Correct. |

**Score: 10 PASS, 0 FAIL.** Every mandatory check the council set is satisfied at the spec level.

---

## New Issues Found (React migration)

**NEW-1 — BLOCKER. SPA breaks view-source delivery of the two HTML breadcrumb comments.**
This is the one issue that downgrades the verdict, and it is a direct consequence of the architecture change. In the old Jinja2 design, the server rendered full HTML, so an HTML comment was present in the raw HTTP response an attacker sees via `curl https://neuro.cyveera.com/status` or browser View-Source (Ctrl+U). In a **Vite-built SPA**, `index.html` is a near-empty shell (`<div id="root"></div>` + a `<script>` tag); the entire DOM — including anything injected via `dangerouslySetInnerHTML` — is constructed by JavaScript *at runtime, after hydration*. 

- §4 `/status` (lines 422-428): the `neuro-train-01 / 10.31.4.22 / neuro-svc credentials` comment.
- §17 `/settings/integrations` (lines 1035-1039): the `<!-- mgmt-plane relay node: 10.31.4.22:3128 -->` comment.

Both say "The implementer must verify the comment is visible in browser view-source." **For a SPA, that verification will fail.** Ctrl+U and `curl` return the static shell, which contains none of these comments. They appear ONLY in the live, post-hydration DOM (DevTools "Inspect Element"). 

Why this matters: the cheapest, most common recon technique against any site is `curl` + grep / View-Source. An attacker who never opens DevTools — or any non-interactive scanner — will never see these breadcrumbs. The `10.31.4.22` management-plane lure loses its two cheapest discovery vectors. The IP is still reachable via the `/docs` `internal/config` JSON, the notification card, the webhook `relay` field, and the ComplianceLockModal trace, so the chain does not *break* — but the lowest-friction discovery path is silently dead, and the spec's own verification step gives a false sense of coverage.

**Fix (pick one, must be explicit in the spec):**
(a) **Server-inject the breadcrumbs into the static `index.html` shell** at nginx/FastAPI layer (e.g. nginx `sub_filter` or a FastAPI route that serves `index.html` with the comments baked in), so they ARE in the raw HTTP response for every page — this restores curl/view-source visibility and is closest to the original intent. State the mechanism. OR
(b) **Move the `10.31.4.22` breadcrumbs entirely to surfaces that ARE in the raw response or in a real network call** — they already exist in `/docs` `internal/config` (line 367-385), the webhook `relay` JSON (line 1048), the notification card (line 795), and the ComplianceLockModal trace (line 1175). If you accept (b), DELETE both HTML-comment requirements (lines 422-428, 1035-1039) so no one wastes time on a verification that cannot pass, and so the spec stops claiming view-source visibility it does not deliver. OR
(c) **Add a `<noscript>` block or a server-rendered static HTML fragment** for `/status` specifically. 
Whichever you choose, strike the phrase "verify the comment is visible in browser view-source" unless the mechanism actually puts it in the raw `index.html` response. **Verify:** `curl -s https://neuro.cyveera.com/status | grep 10.31.4.22` must return the breadcrumb if the spec claims view-source visibility; if it cannot, the claim must be removed.

**NEW-2 — MINOR (realism seam). The login endpoint is named two different things.**
`/docs` advertises `POST /api/v2/auth/token` — "Exchange credentials for a session token" (line 360). But the actual login form POSTs to `POST /api/v2/auth` (lines 522, 1313). An attacker who reads the public docs, then opens the Network tab during login, sees the form hit a *different, undocumented* path than the one the docs name. Real SaaS docs and real network traffic agree on the auth path. **Fix:** make them identical — either the form POSTs to `/api/v2/auth/token`, or the docs list `POST /api/v2/auth`. One-line edit. Not blocking (most attackers will not cross-check), but it is a free realism win in the same pass as NEW-1.

**NEW-3 — MINOR (spec integrity). Authenticated-page count is internally contradictory.**
Line 53: AppLayout wraps "all twelve authenticated pages." Line 1397 (closing): "13 authenticated pages." The routing matrix (lines 71-84) actually lists 14 AppLayout routes (dashboard, runs, models, datasets, artifacts, jobs, notifications, team, api-keys, settings/profile, settings/billing, settings/integrations, settings/security, settings/admin). Three different counts. Cosmetic, but it is the kind of internal inconsistency a careful implementer trips over. **Fix:** pick the correct number (14 AppLayout routes, or 13 if `/settings/admin` is counted separately as the role-gated crown jewel) and use it in both places.

**NEW-4 — MINOR (capability gap, not a tell). `/jobs` / `JobsPage` is declared but never specified, and the RCE capture surface is gone.**
The routing matrix (line 76) declares `/jobs` -> `JobsPage`, and the sidebar "Pipelines" item links to `/jobs` (line 170), but there is NO page section anywhere describing `JobsPage`. In the prior (Jinja2) lineage and the deployed `main.py`, `/jobs/new` was the **RCE trap** (`startup_script=$(id)` -> fake `uid=1000(neuro-svc)` output) — a high-value intent-capture surface. This React spec has dropped it: the changelog still advertises the "script-upload field on job creation" (line 477) as a feature, but no page implements it and no `startup_script` capture is specified. So a feature is advertised in `/changelog` with no backing page (a dead-link seam if a curious attacker navigates `/jobs`), AND the platform loses its command-injection intelligence surface. **Fix:** either (a) spec `JobsPage` with the `startup_script` field that POSTs to a capture endpoint emitting `http.snare.script_upload` (restoring the RCE intent capture — high yield, ML-platform-appropriate), or (b) remove the `/jobs` route, the Pipelines sidebar link, and the changelog line 477 so nothing dangles. Recommend (a) — it is the single highest-value capture surface this rewrite dropped. Not blocking the *deception integrity*, but it is a real intelligence regression versus the deployed system.

**NEW-5 — MINOR (FOUC risk, underspecified). AppLayout never defines what renders DURING the in-flight `auth/me` request.**
§2.1 (line 53) and line 550 correctly say AppLayout redirects on 401 "before rendering any child route" and stores user on 200. The *intent* is right and there is no flash-of-authenticated-content described. But the spec is silent on the in-flight state: between mount (when `GET /api/v2/auth/me` fires) and the response, what does the user see? If an implementer renders the sidebar/topbar shell with an empty `WorkspaceDataProvider` while the request is pending, an unauthenticated scanner gets a frame of the authenticated chrome (sidebar nav labels, page title) before the 401 redirect — a minor information leak and a small "the gate is client-side" tell. **Fix (one sentence):** specify that AppLayout renders a neutral full-screen loading state (canvas background + centered Neuro wordmark spinner, no nav, no page content) until `auth/me` resolves, THEN either redirects (401) or renders children (200). This makes the gate produce zero authenticated content for an unauthenticated visitor. Cheap, closes the seam cleanly.

**Checks that the migration did NOT break (verified clean):**
- **Telemetry vocabulary** — §8.6 (line 1327) wire keys are all neutral (`render_hash`, `lan_ips`, `quality_score`, `field_interaction`). `useTelemetry` (§2.4) reads as ordinary product analytics; no defender perspective in any beacon. The pre-beacon-before-POST pattern (datasets line 623, artifacts line 671, team line 829, integrations line 1013, security line 1060) is preserved across every trap — intent capture is intact.
- **No deception logic leaks into bundle** — §2.6 (lines 136-142): sourcemaps OFF, no defender strings in `define`, only API base URL + STUN URL reach the client. React component *state* described in the spec carries no `isHoneypot`/`trapMode` flags; role-gating reads a plain `role` string. The `CrossTenantAdminPage` mount-redirect logic is the only client-side gate and it leaks nothing about *why* it redirects. Clean — provided the §8.7 grep gate is run against the built bundle (NEW issue: see below).
- **Nginx precedence** — §2.7 (line 150): exact-match locations (`/api/v2/`, `/.git/config`, `/.git/HEAD`, `/robots.txt`, `/sitemap.xml`, `/.well-known/`) before the SPA `try_files ... /index.html` catch-all. Correct ordering; the two `.git` discovery routes will not be swallowed by the SPA fallback.
- **`auth/me` round-trip** — correctly described as a real network call gating render; no client-stored role that an attacker could flip in localStorage to reach `/settings/admin` (role comes fresh from the server each mount).

**One gate-scope note (not a new issue, but sharpen for the React build):** §8.7's vocabulary grep targets `src/` (line 1333). For a Vite SPA, the *deployed artifact* is `dist/main.js` / `dist/vendor.js` / `dist/main.css`, not `src/`. Minification can mangle identifiers but string literals (event names, the `dangerouslySetInnerHTML` breadcrumb strings, any stray comment) survive into the bundle. **The grep MUST also run against the built `dist/` output**, not only `src/`, or a defender string that slips through a template literal ships to attackers. Add `dist/` to the §8.7 gate scope.

---

## Verdict

**CONDITIONAL APPROVE.** All 10 mandatory checks pass. The deception spine is fully coherent and the architecture rewrite preserved every trap, the persona invariant, the clean vocabulary, and the unified-login / silent-role-gate model. The verdict is held at CONDITIONAL by exactly one blocker plus four minors, all introduced (or exposed) by the React migration.

**Conditions before implementation (1 blocker, then 4 should-fix):**

1. **(BLOCKER — NEW-1)** Resolve the SPA view-source breadcrumb gap. Either server-inject the `10.31.4.22` breadcrumbs into the raw `index.html` shell (nginx `sub_filter` / FastAPI-served index) so `curl`/View-Source see them, OR delete both HTML-comment requirements (lines 422-428, 1035-1039) and rely on the four already-existing live-network/JSON surfaces for `10.31.4.22`. In either case, strike "verify the comment is visible in browser view-source" unless the mechanism actually puts it in the raw HTTP response. **Verify:** `curl -s .../status | grep 10.31.4.22` returns the breadcrumb iff the spec claims view-source visibility.
2. **(NEW-4)** Restore or remove `/jobs`/`JobsPage`. Preferred: spec the `startup_script` capture surface (restores the dropped RCE intent-capture); else delete the `/jobs` route, the Pipelines sidebar link, and changelog line 477 so nothing dangles.
3. **(NEW-2)** Make the login path identical in `/docs` and the actual form POST (`/api/v2/auth` vs `/api/v2/auth/token`).
4. **(NEW-3)** Fix the authenticated-page count (twelve / 13 / 14) to one correct number in both line 53 and line 1397.
5. **(NEW-5)** Add one sentence: AppLayout renders a neutral loading state (no nav, no content) until `auth/me` resolves, then redirects (401) or renders (200) — eliminates any flash-of-chrome to unauthenticated visitors.

**Build-time hard gates (must pass before deploy — carried from Round 2/3, sharpened for React):**
- [ ] §8.7 vocabulary grep returns zero matches in `src/` **AND** the built `dist/` bundle (add `dist/` to scope). Inline string literals and `dangerouslySetInnerHTML` strings are in scope.
- [ ] Cowrie honeyfs + MariaDB seed contain NO customer-company names (`vantara/merisol/quelaris/ardentix/lumira/denova`) — operator layer must reference only cyveera-internal identities (§8.1 invariant).
- [ ] Every "Backend to build" trap (artifact download, SSH-key submit, PDF canary, team invite, `auth/me` ip+ua extension — §8.10 lines 1379-1388) has its capture handler in `main.py` BEFORE its frontend page ships.
- [ ] Sourcemaps OFF (`build.sourcemap=false`) and asset names deterministic per §2.6 — confirm `dist/` ships no `.map` files.
- [ ] If NEW-1 fix (a) chosen: `curl -s .../status` and `curl -s .../settings/integrations` (the latter through an authenticated session) return the breadcrumb in raw HTML.

Resolve blocker 1 (and ideally minors 2-5 in the same pass) and re-submit the changed sections only — no full re-audit needed. This is one architecture-delivery fix away from FULL APPROVE.

---

*End of Round 4 audit. The deception is sound; the SPA broke one delivery mechanism. Fix the breadcrumb delivery and ship it.*

---

# Gatekeeper Audit — Round 5 (Final Verification)
**Date**: 2026-06-09
**Verdict**: FULL APPROVE
**Intelligence**: 9/10
**Survivability**: 8/10

Targeted re-read of the five Round-4 fixes only — not a full re-audit. All five landed correctly; no new critical issues introduced.

| # | Round-4 issue | Status | Evidence |
|---|---|---|---|
| NEW-1 (BLOCKER) | HTML-comment delivery removed; DOM/API delivery for `10.31.4.22`; view-source instruction struck | **PASS** | `/status` GPU card (line 422) renders `mgmt: neuro-svc@10.31.4.22` as `text-secondary` JetBrains Mono DOM text, "No HTML comment wrapper"; `/settings/integrations` uses webhook `relay` JSON field (line 1076), "not an HTML comment"; §8.7 (line 1362) replaces view-source check with explicit DOM/API verification and states "Do NOT attempt to verify view-source visibility for a React SPA." |
| NEW-2 | Login path matches `/docs` | **PASS** | `/docs` (line 360), login form (line 516), §8.5 (1338) and §8.8 routing all use `POST /api/v2/auth/token` — one path everywhere. |
| NEW-3 | Page count consistent | **PASS** | Line 53 "all 14 authenticated pages" and closing line 1425 "14 authenticated pages" agree; matrix lists 14 AppLayout routes. |
| NEW-4 | `/jobs` `JobCreationPage` fully specified | **PASS** | Page 9 (lines 660-693): component, access, paste + pre-submit beacons, all five form fields, "Launch Job" button, RCE trap (shell-metachar → fake `uid=1000(neuro-svc)`), backend "to build: POST /api/v2/training/jobs"; §8.10 table updated; closes the Round-4 dangling-changelog-feature seam. |
| NEW-5 | AppLayout in-flight loading state | **PASS** | §2.1 (line 53): full-screen neutral loading state (canvas bg + accent spinner, no sidebar/topbar/content) while `auth/me` is in flight; 401 redirect to `/login?next=<path>` fires "before any authenticated UI is painted." |

**No new critical issues.** The `/jobs` RCE trap has no differential tell (both responses return a job_id; the conditional `output` field mirrors the real init-script-logging feature in changelog v2.3.9). The `/status` `mgmt:` line reads as ordinary runbook metadata, not a self-captioning bait. `neuro-svc@10.31.4.22` stays in the operator layer per the §8.1 persona invariant — no company/hostname contradiction. No defender vocabulary introduced. The Round-4 blocker is resolved and the four minors are closed.

## Day 1 React component build order
1. **`vite.config` + design tokens + `main.css`** — fixed asset names (`main.js`/`vendor.js`/`main.css`), `sourcemap=false`, no defender strings in `define`. Tokens from §1 as CSS vars.
2. **`useTelemetry` hook + `AuthService`** (§2.4) — `track`/`identify` → `POST /api/v2/telemetry`; `getCanvasMetrics()` + STUN ICE gather wired into the route-change effect. Build the neutral vocabulary in from line one.
3. **`WorkspaceDataProvider` context** (§2.1) — holds `user`/`workspace`/`refetch`; populated by `GET /api/v2/auth/me`.
4. **`AppLayout`** (§2.1) — auth gate with the NEW-5 full-screen loading state, then 401-redirect or 200-render; `MarketingLayout` + `LegalLayout` shells.
5. **Router + `App`** (§2.2) — all routes wired, `<Route path="*">` → `NotFoundPage`; `CrossTenantAdminPage` mount-redirect role gate (§2.3).
6. **Shared sidebar + top bar** (§2.8) — built once, inherited by all 14 authenticated pages.
7. **`LoginPage`** (§Page 6) — credential-tier routing via `POST /api/v2/auth/token` → `redirect_to`; paste-capture capture-phase listener; SSO 503 stub.

That spine carries every trap; the static-data pages and discovery lures hang off it days 2-6 per the Round-3 order. Ship it.

---

*End of Round 5 audit. All five fixes verified. Spec is fully approved for implementation.*

---

# Gatekeeper Audit — /docs Page Redesign
**Round: 6**
**Date: 2026-06-08**
**Verdict: FULL APPROVE**
**Intelligence Score: 9/10 | Survivability Score: 9/10**

## § Overall Verdict
The frontend agent implemented the three-column `/docs` redesign exactly as approved in the Round 5 pre-review — all three approved modifications landed verbatim and all three rejected items were excluded with explicit, defensible language in the spec. The page now reads as a genuine Stripe/Arize-grade API reference: real method-badge color semantics, full parameter tables, language-tabbed code sandbox, and a copy-displayed-code-only clipboard handler. The `internal/config` lure is delivered with zero self-incriminating affordance — the strongest possible posture for the `.git/config` escalation chain. Approved for build.

## § Modification Compliance

**Three approved changes — all implemented:**

| # | Approved change | Status | Evidence |
|---|---|---|---|
| A1 | Three-column layout (260 / 600 / 450px sticky) | **PASS** | Line 350: "Column 1: 260px fixed left navigation. Column 2: 600px center documentation, scrollable. Column 3: 450px right code sandbox, sticky top." Line 463: `position: sticky; top: 24px`. Exact dimensions. |
| A2 | 7 filter tabs, no special marker on `internal`/`debug`; amber POST badge | **PASS** | Line 360: tabs All/auth/training/data/models/internal/debug, "All seven tabs are visually identical in styling — no badge, no dot, no amber border, no size difference, no tooltip, no 'not for public consumption' affordance on `internal` or `debug`." Line 364: "POST = amber `#f59e0b`", GET slate, PUT blue `#3b82f6`, DELETE red. |
| A3 | Full param tables (auth/token, data/import, internal/config); cURL/Python/Node sandbox; `10.31.4.22` as `db_host`+`redis_url`; footer string | **PASS** | Param tables lines 396-416. Language tabs line 465. `10.31.4.22` as `db_host` (line 602) and `redis_url` (line 607). Footer line 643 verbatim: "Generated: 2026-04-28 · Neuro API v2.4.1 · 9 endpoints documented". Copy handler line 471: "copies exactly the visible code text, nothing else." |

**Three rejected items — all excluded:**

| # | Rejected item | Status | Evidence |
|---|---|---|---|
| R1 | "Internal Use Only" red badge on `internal/config` | **CORRECTLY ABSENT** | Line 411: "no special badge, no 'Internal Use Only' label, identical visual treatment to all other endpoints. The `internal` filter tab is the only indicator." |
| R2 | Live `cyveera_support` creds / `jwt_secret` in sample response | **CORRECTLY ABSENT** | Line 608: `"jwt_secret": "REDACTED"`. Line 609: `"support_credentials": "REDACTED — see /run/secrets/support_creds"`. Both stayed redacted. |
| R3 | POST badge as emerald | **CORRECTLY ABSENT** | Line 364: POST is amber `#f59e0b`, not emerald. Emerald is reserved for the `accent` brand color / healthy badges per §1. |

**Telemetry vocabulary gate**: PASS. `grep -n "botScore\|canvasFingerprint\|scannerUAs\|honeypot\|attacker\|trap\|lure\|bypass" slapdash-web.md` returns zero hits inside `/docs` client-served beacon names or wire keys. All `/docs` beacons use neutral product-analytics vocabulary: `docs_endpoint_selected`, `docs_tag_selected`, `docs_search_focused`, `docs_code_copied`, under the standard `field_interaction` event. The grep's matches elsewhere in the file are confined to operator-context prose (the §8.7 verification block, the §8.10 backend table, and the vocabulary-gate command itself) — none of which compile into the client bundle. Consistent with §2.6's `define`-block prohibition.

## § Deception Quality Assessment
This is a high-fidelity API reference. A real attacker who view-sources the page gets nothing — it is a Vite SPA, so the raw HTTP response is the static `index.html` shell (confirmed by §8.7, line 1610), and there are no source maps (§2.6). The believability signals are all correct:

- **Method-badge semantics are real.** Amber POST / slate GET / blue PUT / red DELETE is conventional REST-doc color language. A fake docs page typically gets this wrong or uses one flat color.
- **Parameter tables carry plausible product depth.** `data/import` exposing `endpoint_url` for "MinIO or Backblaze B2" (line 409) and `internal/config` gating on an `X-Internal-Access: true` header + support role (line 414) read as features a real ML platform would ship — and the changelog (v2.3.7, line 728) independently corroborates the S3-endpoint feature, so the cross-page story holds.
- **The `internal/config` lure is the centerpiece and it is handled correctly.** There is no flashing "secret endpoint here" affordance. The endpoint sits in the list looking identical to the other eight; its only signal is the `internal` tag, which is a category name a real platform would legitimately have. An attacker discovers it by reading the docs like an engineer, not by being herded. This is exactly what supports the intended chain without revealing the honeypot: attacker finds `internal/config` → reads that it needs `X-Internal-Access: true` + support role → probes it → gets a 403 → escalates by hunting for support credentials (which the `.git/config` route, the workspace-backup archive, and notification 8 / team page all supply). The docs page seeds the target and the auth requirement without ever hinting that failure is expected.
- **The redacted response is the right call.** Returning `"jwt_secret": "REDACTED"` and `"support_credentials": "REDACTED — see /run/secrets/support_creds"` in the *sample* JSON is what a careful real platform does in public docs — and it also tells the attacker the live endpoint will return the real values, which is the precise motivation to go probe it. Redaction here increases pull, not decreases it. The `/run/secrets/` pointer is a believable Docker-secrets reference that costs nothing and reinforces the "real infrastructure" frame.
- **`10.31.4.22` is delivered as ordinary config data** (`db_host`, `redis_url`) inside a JSON response block, not as a captioned breadcrumb. This matches the project's hard-won rule against over-captioned lures and is consistent with the same IP's delivery on `/status`, `/notifications`, and `/settings/integrations` — one coherent management-plane story across four surfaces.

This page helps the intelligence chain and does not hurt it. It is a recon magnet that captures intent (which tabs, which endpoints, which language, copy events) while looking like documentation a paying customer would use.

## § Issues Found
None blocking. Two non-blocking observations for the implementer, neither gating the build:

- **OBS-1 (cosmetic, optional):** The footer reads "9 endpoints documented" and exactly 9 endpoints are listed (lines 368-376) — internally consistent. But only 3 of the 9 have full code blocks fully specified; line 641 instructs "representative code that a real developer would write" for the other six. Ensure the six representative blocks are actually written and are non-empty/non-placeholder before deploy — an endpoint row that selects to a blank or `// TODO` sandbox panel is a tell. Verify each of the 9 rows yields a populated cURL/Python/Node block.
- **OBS-2 (consistency, optional):** The `auth/token` sample response returns `"role": "customer_user"` (line 495). Confirm the live `POST /api/v2/auth/token` backend returns the same role-string vocabulary (`customer_user` / `customer_admin` / `cyveera_support` per §Page 6 line 774) so the documented response shape matches the real response shape byte-for-byte in field names. A docs/runtime field-name divergence is a low-grade fingerprinting seam.

Neither item changes the verdict. They are deploy-time QA checks, not spec defects.

## § Conditions Checklist
None — this is a FULL APPROVE. The three approved modifications are implemented exactly, the three rejected items are excluded with explicit defensive rationale in the spec, the telemetry vocabulary is clean, and the `internal/config` discovery chain is supported without self-revelation. Ship the `/docs` page. Apply OBS-1 and OBS-2 as routine pre-deploy QA.

---

*End of Round 6 audit. /docs three-column redesign fully approved for build.*

---

# Gatekeeper Audit — /docs Enterprise 4-Zone Redesign
**Round: 7**
**Date: 2026-06-10**
**Verdict: CONDITIONAL APPROVE**
**Intelligence Score: 9/10 | Survivability Score: 9/10**

This is a targeted audit of the rewritten Page 3 (`/docs`, spec lines 343–741) against the 14 mandatory modifications (M1–M14) pre-approved verbally, plus a kill-chain integrity check and a hunt for new defects the rewrite introduced. Rounds 1–6 remain valid history. The redesign is excellent deception engineering — the 4-zone enterprise layout reads as a genuine Datadog/Arize-grade reference, the `internal/config` trap article is delivered with zero self-incriminating affordance, and the credential-placeholder discipline is clean. It is held at CONDITIONAL for exactly one reason: an endpoint-inventory mismatch (M13 + M14) that ships four "documented" endpoints with no article, no tree node, and no code block — a blank-panel / dead-inventory tell. One bounded fix clears it.

## § Modification Compliance (M1–M14)

| # | Modification | Status | Evidence |
|---|---|---|---|
| M1 | Intent beacon on tree expand + article select; `internal_node_management` fires on `useEffect` mount | **PASS** | Lines 352–354: `docs_section_expanded` on expand, `docs_article_selected` on leaf select, and the explicit `internal_node_management` beacon "fires on useEffect mount … highest-intent beacon on the page, mandatory." All three present. |
| M2 | No view-source verification claim (Vite SPA — DOM-only) | **PASS** | Line 358 + Spec note 5 (line 738): "Do NOT include any instruction to verify `/docs` content via `curl`/View-Source … Verification … via the PostgreSQL events table and browser DevTools Network tab." No view-source claim anywhere in the page. |
| M3 | Right-TOC anchors generated from rendered headings — no dead anchors | **PASS** | Line 728: "All anchors are generated from the rendered article's actual headings — no static hardcoded list, no anchors that don't correspond to rendered content (mandatory — M3)." Per-article TOC lists (440, 508, 540, 617, 688) map to headings actually specified in each article body. |
| M4 | Placeholder credentials in ALL request samples | **PASS** | Lines 403–407 mandate `$NEURO_API_KEY` / `os.environ[...]` / `process.env...` / `<user_email>` / `<password>`. Verified across every code block: Quickstart (430), Auth (468/479/490), Models (526/529/537), Datasets (565/580/595), internal/config request (645/656/667), SDK articles (696/702/708). Zero hardcoded real-looking tokens in any request sample. |
| M5 | `internal/config` RESPONSE keeps `10.31.4.22`, `jwt_secret: REDACTED`, `support_credentials: REDACTED — see /run/secrets/support_creds` | **PASS** | Lines 674–686 (response block) + the explicit M5 exception (line 409) + Spec note 4 (737). `db_host`/`redis_url` = `10.31.4.22`, `jwt_secret: REDACTED`, `support_credentials: REDACTED — see /run/secrets/support_creds` all intact, never placeholdered. |
| M6 | `REDACTED` semantics intact for server-side secrets | **PASS** | Both `jwt_secret` and `support_credentials` carry `REDACTED` (lines 683–684), modelling a careful real platform's public-docs sample while signalling the live endpoint returns real values — the precise motivation to probe. |
| M7 | Access notice = flat amber-left-border callout; no ⚠️, no all-caps "INTERNAL … USE ONLY", no "DO NOT DISTRIBUTE", no guard-rail language | **PASS** | Lines 623–626: same amber-left-border `surface` callout style as the Quickstart banner, explicitly "NOT a red warning. NOT all-caps. NOT a ⚠️ emoji." Copy reads "Internal documentation — Cyveera Support … restricted to platform support accounts … require the `X-Internal-Access: true` header." Informational, not a guard rail. Spec note 3 (736) reinforces. |
| M8 | "Node Management (Internal)" tree node — no special icon/lock/dot/color; `(Internal)` word is the only signal | **PASS** | Line 372 VISUAL RULE (mandatory — M8): "no special icon, no lock glyph, no amber dot, no color difference … The word '(Internal)' in the label is the only permitted signal." Tree diagram (390) renders it as a plain leaf. Spec note 2 (735) reinforces. |
| M9 | `internal/config` appears exactly once in the tree — no duplication | **PASS** | Spec note 1 (line 734): "appears in exactly ONE place in the tree: `API Reference → Advanced → Node Management (Internal)`. Not duplicated elsewhere." Tree diagram confirms a single occurrence (line 390). |
| M10 | Mandatory intent beacon on render of the internal article | **PASS** | Line 354: the `internal_node_management` `docs_article_selected` beacon "fires on useEffect mount" and is labelled "mandatory." This is the highest-value capture on the page and is correctly forced on render, not on click. |
| M11 | `X-Internal-Access: true` documented requirement kept | **PASS** | Banner (626), parameter table (639, "Must be set to `true`"), and all three code samples (646/657/668) carry the `X-Internal-Access: true` header requirement — the chain strengthener is intact. |
| M12 | Vocabulary gate passes (no defender vocab in beacon names, props, client strings) | **PASS** | Line 356 enumerates the prohibition; all beacon actions are neutral product-analytics vocabulary (`docs_endpoint_selected`/`docs_section_expanded`/`docs_article_selected`/`docs_search_focused`/`docs_code_copied`). No `botScore`/`honeypot`/`trap`/`lure`/`bypass`/`scanner` in any client-served string, event name, or prop within the page. (Operator-prose labels like "THE TRAP ARTICLE" on line 621 are spec annotations, not client code — acceptable, but see NEW-2.) |
| M13 | Footer endpoint count matches actual documented endpoints | **FAIL** | Footer (line 741) and Spec note 6 (739) both claim **9** endpoints "documented" / "reachable via the tree." Only **5** are actually documented with method+path+params+code in an article: `POST /api/v2/auth/token`, `GET /api/v2/models`, `GET /api/v2/models/{model_id}/drift`, `POST /api/v2/data/import`, `GET /api/v2/internal/config`. The other four (`GET /api/v2/training/runs`, `POST /api/v2/training/runs/{run_id}/metrics`, `GET /api/v2/data/exports`, `POST /api/v2/debug/flush-cache`) have NO article and NO tree leaf. The footer over-counts by 4. |
| M14 | Every article/endpoint reachable in the tree has a populated code block — no blank/`// TODO` panels | **FAIL (related to M13)** | The tree (lines 374–391) contains 11 leaves; the four "phantom" endpoints from Spec note 6 are not among them — they are unreachable, not blank. But Spec note 6's own hedging ("Models *or a future Training article*", "Advanced *or a Debug article*") proves they were never assigned a home: if an implementer takes note 6 literally and adds Training/Debug tree leaves to reach the claimed 9, those leaves currently have zero specified body/code and would render as blank panels — the exact M14 tell. The inventory is internally contradictory: the count says 9, the articles deliver 5, and the tree routes to neither set cleanly. |

**Score: 12 PASS, 2 FAIL (M13, M14 — same root cause).**

## § Kill Chain Integrity

The `.git/config → support credentials → internal/config → Cowrie SSH` chain is **fully preserved and, if anything, strengthened** by this redesign. Walking it end to end:

1. **`.git/config`** (line 1587) leaks `url = https://support:CyveeraSup!2024@gitlab.cyveera.internal/...` — the crown-jewel credential, delivered as a realistic embedded-remote-URL credential via PlainTextResponse.
2. **`/docs` internal/config** (this redesign) is the corroboration and target-seeding surface: the `support_credentials: "REDACTED — see /run/secrets/support_creds"` line (684) tells the attacker the live endpoint returns real support credentials and points at the Docker-secrets path, while `db_host: 10.31.4.22` (677) plants the management node. The `X-Internal-Access: true` + support-role requirement (626, 639) tells the attacker *what role they need* — motivating the hunt for the `support` credential they find in `.git/config`. The trap article is the map; `.git/config` is the key.
3. **Notification 8** (line 1197) independently corroborates that `support@cyveera.ai` exists and was granted cross-tenant access — multi-surface corroboration is what sells the find.
4. **`/login` as `cyveera_support`** (line 875) → `redirect_to: /settings/admin`.
5. **`/settings/admin` ComplianceLockModal** (line 1554) leaks `ssh neuro-svc@10.31.4.22` in an error trace → Cowrie.

The redesign touches only node 2 of this chain and preserves every load-bearing element: the IP, the redaction-as-motivation, the role requirement, and the `/run/secrets/support_creds` pointer. `10.31.4.22` remains consistent across all five surfaces (`/docs` config block, `/status` mgmt line, `/notifications` card, webhook `relay`, ComplianceLockModal trace). **The chain holds. No regression.**

## § New Issues

**NEW-1 — BLOCKER (this is the M13/M14 root cause). Endpoint inventory is internally contradictory.**
Footer says "9 endpoints documented"; only 5 are actually documented in articles; Spec note 6 lists 9 names but routes four of them to non-existent articles using hedged "or a future … article" language. A source-reading attacker who counts the tree leaves, expands every node, and finds 5 documented endpoints against a footer claiming 9 sees a docs page that miscounts its own surface — a small but real "this was assembled, not grown" seam. Worse, if the implementer reaches for 9 by adding Training/Debug leaves with no specified content, they ship blank/`// TODO` sandbox panels (the M14 tell OBS-1 in Round 6 already warned about). **Fix (pick one, must be explicit):** (a) **Drop the count to 5** — change the footer to "5 endpoints documented", delete the four phantom endpoints from Spec note 6, and confirm the tree's 5 API-bearing leaves (Auth, Models×2, Datasets, Node Management) are the complete documented set; the SDK/Concepts/Glossary leaves are guides, not endpoints, and correctly carry no method badge. OR (b) **Build all 9** — add a "Training" article (runs + metrics endpoints) and a "Debug" article (`debug/flush-cache`) plus a `data/exports` entry under Datasets, each with full param table + populated cURL/Python/Node blocks and a real tree leaf, then keep the footer at 9. Option (a) is the lower-risk, lower-effort fix and loses no intelligence value (none of the four phantoms is a trap surface). **Verify:** documented-endpoint count in articles == footer number == number of method-badged leaves in the tree.

**NEW-2 — MINOR (build hygiene, not a spec defect). Operator-prose labels must not leak into the client bundle.** Line 621 labels the article "**THE TRAP ARTICLE**" and line 390 the tree comment "the trap". These are spec annotations and are correct *as documentation*, but they are exactly the strings the §2.6 `define`-block prohibition and the Round-4 `dist/` grep gate exist to catch if a developer copies spec text into a comment or constant. **No spec change required** — flag for the implementer: the build-time vocabulary grep (`templates/`, `static/src/`, **and built `dist/`**) must return zero matches for `trap|honeypot|lure|bypass|scanner|attacker`, inline `<script>`/JSX string literals in scope. This is a carried hard gate, restated because the new prose introduces fresh `trap` tokens in the spec.

**NEW-3 — OBSERVATION (non-blocking, carried from Round 6 OBS-1). Six of the documented endpoints' code blocks were "representative" in Round 6; this redesign now fully specifies the 5 real ones.** Quickstart, Auth, Models, Datasets, and internal/config all have complete, non-placeholder cURL/Python/Node blocks. The SDK articles (Python/Node/SageMaker) and Core Concepts/Glossary are guides with prose + minimal install snippets, not endpoint references — correctly carrying no blank API sandbox. This actually *resolves* Round-6 OBS-1 for the endpoints that remain. Confirm at build that the 5 documented endpoints each render a populated three-tab sandbox (no empty Node tab, etc.).

Everything else in the rewrite is clean. The 4-zone layout, the amber-callout banner discipline, the visually-identical tree node, the single-occurrence trap leaf, the placeholder-everywhere/lure-values-only-in-response split, and the mandatory render-time intent beacon are all implemented exactly as pre-approved.

## § Conditions Checklist

1. **(BLOCKER — NEW-1 / M13 / M14)** Reconcile the endpoint inventory. Either (a) drop the footer to "5 endpoints documented", delete the four phantom endpoints from Spec note 6, and confirm the 5 method-badged tree leaves are the complete documented set; OR (b) add Training + Debug + data/exports articles with full param tables and populated three-language code blocks and real tree leaves, keeping the footer at 9. **Verify:** documented-endpoint count in articles == footer number == method-badged tree leaves, AND no tree leaf routes to a blank/`// TODO` sandbox panel.
2. **(NEW-2, build-time)** Run the expanded vocabulary grep against `src/` AND built `dist/` before deploy — zero matches for `trap|honeypot|lure|bypass|scanner|attacker` in any client-served string. The spec's "THE TRAP ARTICLE" / "the trap" labels must not survive into any component name, comment, or string literal.

## § Overall Assessment

CONDITIONAL APPROVE — one bounded blocker. The enterprise 4-zone redesign nails 12 of 14 mandatory modifications, preserves the full `.git/config → support creds → internal/config → Cowrie` kill chain without regression, and delivers the `internal/config` trap with the strongest possible non-self-revealing posture. The only failure is an endpoint-inventory contradiction (footer claims 9, articles deliver 5, four endpoints route to articles that do not exist) — a self-counting seam and a latent blank-panel tell, both fixable in one pass by dropping the count to 5 (recommended) or building out the missing four articles. Resolve Condition 1 and this is a FULL APPROVE on re-read of the changed footer/note/tree only; Condition 2 is a carried build-time gate, not an approval blocker.

---

*End of Round 7 audit. Reconcile the endpoint count and ship the /docs redesign.*

---

## Round 7 — Close-Out Verification
**Date: 2026-06-10**
**Verdict: FULL APPROVE**

Condition 1 (the M13/M14 blocker — NEW-1) is resolved via the recommended Option (a). Spec note 6 (line 739) now documents exactly five endpoints with explicit article assignments (`POST /api/v2/auth/token`, `GET /api/v2/models`, `GET /api/v2/models/{model_id}/drift`, `POST /api/v2/data/import`, `GET /api/v2/internal/config`), states those are the only five in the footer count, names the four former phantoms (`GET /api/v2/training/runs`, `POST /api/v2/training/runs/{run_id}/metrics`, `GET /api/v2/data/exports`, `POST /api/v2/debug/flush-cache`) as NOT assigned to any tree node or article, and adds an explicit instruction against creating phantom tree leaves with blank/`// TODO` sandbox panels. The footer (line 741) now reads "5 endpoints documented," and the tree (lines 374–391) carries exactly five method-bearing API leaves (Auth, Models — two endpoints, Datasets, Node Management Internal) with no Training/Debug/data-exports leaf. The self-counting seam and latent blank-panel tell are both eliminated; documented-endpoint count == footer number == method-badged tree leaves. No intelligence value was lost — none of the dropped four was a trap surface — and the `.git/config → support creds → internal/config → Cowrie` kill chain is untouched. Condition 2 (NEW-2) is confirmed to be a carried build-time vocabulary gate, not a spec defect: the "THE TRAP ARTICLE" (line 621) and "the trap" (line 390) tokens are operator-facing spec annotations only — they do not appear in any component name, beacon action, event key, prop, or client-served/rendered string, and the M12 telemetry vocabulary gate already passes. The build-time grep against `src/` and built `dist/` for `trap|honeypot|lure|bypass|scanner|attacker` remains a standing deploy gate and must run before ship, but it does not gate this approval. The /docs enterprise 4-zone redesign spec is cleared for implementation.

---

*End of Round 7 close-out. /docs redesign fully approved — proceed to build, then run the carried dist/ vocabulary grep before deploy.*

---

# Gatekeeper Audit — slapdash-backend.md
**Round: Backend-1**
**Date: 2026-06-10**
**Verdict: CONDITIONAL APPROVE**
**Intelligence Score: 9/10 | Survivability Score: 8/10**

This is the backend implementation plan; Rounds 1–7 audited the frontend spec. I read the plan in full and cross-checked every claim it makes about the existing `main.py` (2,970 lines) against the actual source. The plan is strong, technically literate, and correct on the hard architectural calls (single-process extension, `_log_event` reuse, accept-and-confirm SSRF, never-execute RCE, redacted crown-jewel response). It is held at CONDITIONAL by **four blockers**, three of which are factual errors about how the *currently deployed* code behaves — errors that would silently break the session model and the crown-jewel kill chain if the plan were implemented as written.

## § Overall Assessment

The plan correctly chooses to extend `main.py` rather than fork a second process, and its reasoning (shared `_log_event`, shared middleware, shared connection singletons, one nginx upstream) is sound and matches the code. Every trap route maps to a specific `event_type`, the SSRF/RCE/LFI traps preserve the never-reflect / never-execute discipline already in `main.py`, and the crown-jewel `internal/config` gate (session AND role AND `X-Internal-Access` header, 401-before-403 ordering) is specified exactly right. The Redis session store, rate limiter, and seed-data schema are all reasonable. However, the plan makes three incorrect assumptions about the **existing middleware's cookie handling** that directly collide with its own new session design, and the `.git/config` content it depends on for the entire kill chain **does not yet contain the support credential** — the live route serves a GitHub SSH URL with no embedded creds. These must be fixed before any code is written.

## § What's correct

- **Single-process / extend-main.py decision (§1).** Verified: `_log_event(event: dict)` (line 359, sync, fully-built dict), `_detect_web_attack()` (line 969), `_push_honeydash_async()` (line 1012), `_get_pg()`/`_get_redis()` singletons, and the `@app.middleware("http")` request logger (line 509) all exist exactly as the plan describes. Reproducing this in a second process would indeed duplicate ~200 lines and bypass middleware logging. Correct call.
- **`_log_event` signature usage.** The plan's auth-flow diagram (§3.4) calls `_log_event(event_type=..., username=..., password=...)` — but the testing section and prose elsewhere treat it as the real sync dict-taking function. The actual signature is `_log_event(event: dict)` (line 359). The §3.4 keyword-arg shorthand is pseudocode, not a literal call — acceptable as long as the implementer builds the full dict (event_id/created_at/sensor/event_type/src_ip/.../payload/session_id/geo_*). Flagging so it is not implemented literally. See BLOCKER-3's cross-reference.
- **SSRF traps never make outbound requests (§4.3, §10).** Matches the existing `/api/v1/data/remote-import` pattern (line 2543, `_REMOTE_IMPORT_SSRF_INDICATORS`, string-match only, no httpx). The accept-and-confirm `{"status":"ingestion_queued"}` response is the approved Round-1..7 design.
- **RCE trap returns static fake `uid=1000(neuro-svc)` (§4.3), never executes.** Consistent with the deployed `/jobs/new` trap. No `subprocess`. Correct.
- **Crown-jewel gate ordering (§4.3 `internal/config`).** 401 on no session, 403 on wrong role, 403 on missing header, 200 only on support-role + valid session + `X-Internal-Access: true`. Logging `http.snare.internal_config_access` on every hit (401/403/200) is exactly right — all hits are noteworthy. Response keeps `10.31.4.22` / `jwt_secret: REDACTED` / `support_credentials: REDACTED — see /run/secrets/support_creds` verbatim, matching the Round-7-approved `/docs` sample byte-for-byte. Good.
- **Telemetry SNARE-skip (§4.4).** Correctly identifies that telemetry POST bodies must not run through `_detect_web_attack()`. (Severity note in MINOR-1 — the actual collision is narrower than the plan states, but the mitigation is correct and harmless.)
- **Pre-beacon discipline carried from the frontend spec.** The trap mechanics preserve intent capture; `_NO_COOLDOWN_EVENTS` additions for `internal_config_access` / `ssh_key_submitted` / `invite_submitted` are correct (§5.1).
- **Sentinel rebuild instruction (§7 Step 8).** Correctly uses `docker compose build --no-cache sentinel && docker compose up -d sentinel` — matches the known footgun that `up -d log-shipper` leaves sentinel on a stale image.
- **X-Forwarded-For trust (§6.3).** `proxy_set_header X-Forwarded-For $remote_addr` overwrites any client-supplied XFF — correct anti-spoof posture, and `_extract_src_ip()` (line 347) reads it.
- **Canary AWS key `AKIAYZM57LXRGIYTCOUV` reused in the tarball (§4.3.1).** Matches the live canarytoken in the deployed `_LURE_FILE_REGISTRY`. Good cross-surface consistency.

## § Issues Found

**1. BLOCKER — The middleware overwrites the v2 session cookie on EVERY response with `max_age=86400`, defeating the plan's 1800s inactivity-timeout design.**
The plan (§3.1) says the v2 auth route sets `nro_session` with `Max-Age=1800` to match the Redis TTL "so the browser cookie and server session expire at the same time," and §10 claims "no conflict" with the existing middleware. This is false. The existing middleware (lines 688–697) unconditionally calls `response.set_cookie(key="nro_session", value=session_id, max_age=86400, ...)` on the way out of **every request**, AFTER the route handler returns. So:
   - The v2 login route sets `Max-Age=1800`; the middleware immediately rewrites the same Set-Cookie header on the same response to `Max-Age=86400`. The browser cookie will be 86400, not 1800 — the cookie/Redis expiry alignment the plan promises does not happen.
   - On every subsequent authenticated request, the middleware refreshes the browser cookie to a rolling 24h regardless of Redis TTL. The *server* session still expires from Redis at 1800s of inactivity (correct), but the cookie persists 24h — a benign-but-real divergence the plan explicitly claims it avoids.
   - Worse: line 525 mints `session_id = request.cookies.get("nro_session") or str(uuid.uuid4())` for **every visitor including unauthenticated ones**, and the middleware then sets that cookie. So an unauthenticated scanner gets a `nro_session` cookie that has NO `session:v2:` key in Redis. The plan's `_v2_session_required` (§4.2) will correctly 401 it (good), but the plan must not assume "cookie present == session exists."
   **Fix:** (a) Make the middleware's `set_cookie` conditional — do NOT re-set `nro_session` if the request already carried a valid `session:v2:` cookie, OR have the v2 auth route be the sole writer of the cookie and change the middleware to only set the cookie when none was present (preserve existing UUID-minting for logging but stop clobbering Max-Age). (b) Explicitly state that the middleware change is part of this plan — it is currently NOT mentioned, and §10's "no collision" analysis is wrong. **Verify:** after v2 login, `curl -v` shows exactly one `Set-Cookie: nro_session=...` with the intended Max-Age, and a second authenticated request does not reset it to 86400.

**2. BLOCKER — The deployed `/.git/config` does NOT contain `support:CyveeraSup!2024`. The entire crown-jewel kill chain is currently dead.**
The plan (§4.5) says "The current `main.py` may have a different credential … Verify by reading the current `GIT_CONFIG_CONTENT` constant." I read it. The live `git_config` route (lines 2360–2374) returns:
```
[remote "origin"]
	url = git@github.com:cyvera-ai/neuro-platform.git
```
There is **no embedded credential**, no `gitlab.cyveera.internal`, no `support:CyveeraSup!2024`, no `[user] priya.nair` block. The `.git/config → support creds → /login → cyveera_support → internal/config → Cowrie` chain that Rounds 1–7 approved and that this plan's §4.3/§4.5/§8.2/§8.15 all depend on **does not function against the deployed code today.** The plan correctly identifies the need to overwrite the constant with the spec'd content (§4.5 lines 478–498), so this is a known action — but it is a hard blocker, not a "verify" nicety, because every downstream trap test (§8.2, §8.15) will fail until the constant is replaced. **Fix:** Promote the §4.5 `.git/config` rewrite from a conditional "if it differs, update" to a mandatory Step in §7 deployment order, BEFORE any kill-chain validation. **Verify:** `curl -s .../.git/config | grep 'support:CyveeraSup!2024'` returns the line, and `support@cyveera.ai` + `CyveeraSup!2024` authenticates via `/api/v2/auth/token` returning `role: cyveera_support`.

**3. BLOCKER — Two login paths will exist simultaneously, and the existing `api_auth()` lure-credential machinery is not reconciled with the new `v2_auth_token`.**
The plan adds `POST /api/v2/auth/token` (§4.1) backed by the new `workspace_members` bcrypt table. But the deployed code already has `api_auth()` (around line 1740) wired to `_LURE_CREDS` (an in-code list), the `X-Lure-Credential-Used` header → middleware `event_type` override (lines 546, 605–607, 672–676), `_SESSION_USER_MAP` (line 817), and bruteforce detection (lines 1801+). The plan's `v2_auth_token` (§3.4) emits `http.lure.credential.success` directly via `_log_event` — bypassing the `X-Lure-Credential-Used` header mechanism the middleware relies on. Consequences if not reconciled:
   - **Double-logging / wrong event_type:** the middleware will ALSO log the `/api/v2/auth/token` POST as `http.post.api.v2.auth.token` (or similar) since it logs every request. The plan does not say whether `v2_auth_token` uses the header-signal pattern (like `api_auth`) or the direct-`_log_event` pattern. Pick one. If direct, the middleware still fires a second generic event for the same request.
   - **Lost bruteforce coverage:** the existing `_auth_attempts` sliding-window bruteforce detector lives in `api_auth()`. `v2_auth_token` has its own Redis rate-limiter (§3.2) but no bruteforce *intel* event (`http.bruteforce.detected`). The plan's rate-limit and the existing bruteforce detector are different mechanisms with different event types — decide whether v2 keeps the bruteforce intel event.
   - **`_SESSION_USER_MAP` vs Redis session:** the existing `/admin` personalisation reads `_SESSION_USER_MAP[session_id]` (line 2327). The v2 design stores identity in Redis (`session:v2:{id}` JSON). If any existing route or any new route relies on `_SESSION_USER_MAP`, it will be empty for v2 sessions.
   **Fix:** State explicitly (a) whether `v2_auth_token` signals via `X-Lure-Credential-Used` (preferred — keeps the single middleware logging path and avoids double events) or emits its own event and is added to a middleware skip-set; (b) whether the v2 path retains bruteforce intel (`http.bruteforce.detected`) or relies solely on 429 rate-limiting; (c) that `_SESSION_USER_MAP` is either populated alongside the Redis write or that admin personalisation now reads the Redis session. **Verify:** one login POST produces exactly one credential event of the correct type, not two.

**4. BLOCKER — Seed script run-context and DB connection are underspecified, and `_get_pg()` will not see new tables created out-of-band unless the connection is fresh.**
§2.7 / §7 Step 1 says run `seed_v2.py` inside the `log-shipper` container ("which already has psycopg2 and a POSTGRES_DSN env var"). But §2 also says the six tables are "accessible through the existing `_get_pg()` connection" in the `honeypot-api` container. Two issues:
   - The plan says the seed script is "called from `start.sh` before uvicorn starts" (§2.7) AND separately run manually via `docker exec log-shipper` (§7 Step 1). These are two different execution contexts. Pick one as authoritative. If `start.sh` runs it in the api container, the api container needs `passlib[bcrypt]` at image-build time (listed in §9.5 as an open item — confirm it lands in `requirements.txt` BEFORE the build, or `start.sh` crashes on import and the healthcheck never comes up).
   - `_get_pg()` (line 145) caches a module-level connection. If tables are created by a *different* process (log-shipper) after the api process already opened its connection, the api connection sees them fine (DDL is visible cross-connection once committed) — but confirm the seed COMMITs (autocommit or explicit) or the CREATE/INSERT will roll back when the seed process exits. The existing `_log_event` relies on autocommit being set on the shared connection; the seed script must set its own.
   **Fix:** Make `start.sh` in the **api container** the single authoritative seed runner (so schema exists before first request), require `passlib[bcrypt]`, `user-agents`, and `fpdf2` in `requirements.txt` as a pre-build gate, and state that the seed script uses its own autocommit connection. **Verify:** `docker exec honeypot-api python3 -c "from passlib.hash import bcrypt; import fpdf, user_agents"` succeeds, and `\dt workspace_members` returns a table after a clean `--force-recreate`.

**5. MINOR — Telemetry SSRF false-positive risk is real but narrower than the plan states (§4.4).**
The plan says `lan_ips: ["192.168.1.10"]` in a telemetry body "would trigger `_SSRF_PATTERNS`." Verified against code: `_detect_web_attack()` SSRF check is **path/query only** (line 1003–1007, `path_query = (path + " " + query_str)`), so a `192.168.x` value in the POST *body* does NOT trip the SSRF branch. AND the pattern list has `192.168.0.` not `192.168.1.` (line 787). The *actual* body risk is RCE/SQLi/XSS patterns in `render_hash`/free-text telemetry fields, which DO scan the body (line 980). The plan's mitigation (telemetry skip-set OR explicit early-return `_log_event`) is correct and addresses the real risk — just fix the rationale so the implementer skips for the right reason. **Verify:** a telemetry POST with a body containing `' OR 1=1` is logged as `http.telemetry.page_view`, not `http.post.sqli.attempt`.

**6. MINOR — `GET /api/v2/auth/logout` returns 302 to `/login`, but the SPA route is `/login` while the marketing root is `/`. Confirm the redirect target is a real SPA route.**
§3.4 / §4.1 say logout 302s to `/login`. The frontend is a Vite SPA served by nginx `try_files ... /index.html`; a 302 to `/login` will be caught by the SPA catch-all and render the React `LoginPage` — fine. But a 302 from an XHR (the SPA likely calls logout via fetch) will be followed by the browser fetch and return `index.html`, not act as a navigation. Confirm the frontend treats logout as a navigation (`window.location = /api/v2/auth/logout`) not a fetch, or change logout to return `200 {"redirect_to":"/login"}` and let the SPA navigate. **Verify with the frontend team** — this is a frontend/backend contract item, not a backend defect per se.

**7. MINOR — `GET /api/v2/runs` is specced but the frontend route table references `/api/v2/runs`; confirm the `training_runs` seed `started_by` values match the persona invariant.** The seed (§2.2) uses `j.smith`, `alice.wong`, `svc-deploy` — consistent with the customer-side personas. Good. But `started_by` is a bare username (`j.smith`) while `workspace_members.email` is `j.smith@vantarahealth.com`. The frontend may render `started_by` verbatim; confirm the runs table shows usernames not emails, or the join breaks visually. Cosmetic. **Verify:** dashboard recent-runs renders `started_by` in the same format the design uses elsewhere.

**8. MINOR — Rate limiter applies to `/api/v2/auth/sso/initiate` (§3.2). The SSO endpoint always 503s after a 1.8–2.4s sleep. Rate-limiting a guaranteed-failure endpoint at 10/min/IP is fine, but ensure the 429 path on SSO does not leak that the endpoint is "really" rate-limited vs. always-down — both should look like infra to the attacker.** Non-blocking; the behaviors are individually plausible. Note only.

**9. MINOR — Missing-routes coverage is complete for what was asked; one gap.** The plan covers `GET /api/v2/auth/me`, `GET /api/v2/runs`, the canary PDF route (`/api/v2/settings/billing/invoice/{id}`), `robots.txt`, and `POST /api/v2/auth/sso/initiate`. Good. The `GET /api/v2/auth/me` `user_agent_parsed` field depends on the `user-agents` package (§3.3, §9.6) — confirm it is in `requirements.txt` at build time (folded into BLOCKER-4's pre-build gate). One missing-route note: the plan adds `GET /api/v2/cluster/nodes` as an alias (§4.5) — verify the frontend actually calls v2 and not the existing `/api/v1/cluster/nodes` (line 1539), or the alias is dead weight. Non-blocking.

## § Nginx / Rate-limit / Telemetry specifics (as requested)

- **Nginx SPA + proxy plan (§6) is correct.** `try_files $uri $uri/ /index.html` for the catch-all, exact-match `location = /.git/config` / `/.git/HEAD` before the catch-all, `location /api/` prefix proxy, `/.well-known/` prefix proxy. nginx prefix/exact precedence is right (exact `=` and longer prefixes beat `location /`). One correction: the project runs **OpenResty**, and the existing config lives at `/opt/honeypot/config/nginx/neuro.conf` (the container mount), not the `deploy/` source path — reload is `docker exec nginx openresty -s reload` (the plan's §7 Step 4 has this right). Also confirm the `dist/` bind-mount path `/opt/honeypot/deploy/SlapDash-Frontend/dist` matches where the build is actually copied (§7 Step 3 copies to that path — consistent). The security headers added in nginx (§6.1) will now ALSO be set by the FastAPI middleware (lines 684–686) for proxied `/api/` responses — duplicate headers are harmless but note the doubling.
- **Rate limiting (§3.2) — 429 + `Retry-After: 60` is correctly spec'd.** The Redis sorted-set sliding window is a sound implementation. Confirm the `ZADD`/`ZREMRANGEBYSCORE`/`ZCARD`/`EXPIRE` sequence is wrapped so a Redis hiccup fails OPEN (attacker not locked out in a way that tells them the limiter is stateful) — a fail-closed 429 storm on Redis outage would be a mild tell. Non-blocking.
- **Telemetry `lan_ips` bypass — see MINOR-1.** Mitigation correct; rationale wrong. The skip-set approach (add `/api/v2/telemetry` to a middleware `_TELEMETRY_SKIP_SNARE` check) is cleaner than the "early-return" approach because the middleware logs every request anyway — use the skip-set so telemetry still gets logged once with the right `event_type`.

## § Security boundary review (as requested)

No route in the plan executes attacker input, makes outbound requests on attacker-controlled URLs, or returns real system data. The two SSRF traps are string-match-and-confirm (verified against the existing `_REMOTE_IMPORT_SSRF_INDICATORS` pattern). The RCE trap returns a static string. The LFI/artifact download serves pre-built in-memory bytes (`_BACKUP_TARBALL_BYTES`), never `open()` on a real path — confirm the artifact handler does NOT pass `artifact_path` to any filesystem call (the plan says stub content, good; the implementer must not regress to a real file read). The crown-jewel response is redacted. The session-revoke self-logout (§4.3) is a deliberate, contained behavior. **One standing risk:** the lure tarball's `production.env` and `aws_credentials.csv` contain a LIVE canarytoken (`AKIAYZM57LXRGIYTCOUV`) plus fake-but-real-looking DB/Redis hosts (`10.31.4.22`) and a `JWT_SECRET`. Confirm `10.31.4.22` is non-routable from the VPS / not a real internal host, and that the `JWT_SECRET` / `DB_PASSWORD` (`NeuroML2024!`) are not reused anywhere real. These are honeypot fixtures by design — just verify they pivot nowhere.

## § Conditions Checklist

Resolve all four BLOCKERS before writing code; the six MINORs are should-fix-in-the-same-pass or frontend-contract confirmations.

1. **(BLOCKER-1)** Reconcile the middleware cookie-setting (lines 688–697) with the v2 1800s-TTL session design. Make the middleware stop clobbering `Max-Age` for valid v2 sessions, or make the v2 auth route the sole cookie writer. Correct §10's false "no collision" claim. **Verify:** post-login `Set-Cookie` Max-Age matches intent and is not reset to 86400 on the next request.
2. **(BLOCKER-2)** Promote the `.git/config` content rewrite (§4.5) to a mandatory deployment step, BEFORE kill-chain validation. The deployed route currently has NO support credential — the chain is dead until replaced. **Verify:** `curl .../.git/config | grep support:CyveeraSup!2024` and a successful `cyveera_support` login.
3. **(BLOCKER-3)** Reconcile `v2_auth_token` with the existing `api_auth()` lure machinery: pick the `X-Lure-Credential-Used` header-signal pattern (preferred, single logging path) vs. direct `_log_event` + middleware skip; decide bruteforce-intel retention; populate `_SESSION_USER_MAP` or migrate admin personalisation to read the Redis session. **Verify:** one login = one correct credential event, no duplicate generic event.
4. **(BLOCKER-4)** Designate `start.sh` in the api container as the single seed runner; add `passlib[bcrypt]`, `user-agents`, and `fpdf2` to `requirements.txt` as a pre-build gate; specify the seed uses its own autocommit connection. **Verify:** clean `--force-recreate` brings the container up healthy with all six tables present and all three libs importable.

Should-fix in the same pass: MINOR-5 (telemetry skip rationale), MINOR-6 (logout redirect contract with frontend), MINOR-7 (`started_by` display format), MINOR-9 (confirm libs + cluster-nodes alias is actually called).

Resolve the four blockers and re-submit the changed sections (§1/§3/§4.5/§7/§10) — no full re-audit needed. The trap design, route table, schema, nginx plan, rate limiter, and security boundaries are all approved as-is.

---

*End of Backend-1 audit. The plan is well-built; it just mis-models the existing middleware's cookie behavior and depends on a `.git/config` credential that isn't deployed yet. Fix the four blockers and ship the backend.*

---

# Gatekeeper Audit — slapdash-backend.md Revision
**Round: Backend-2**
**Date: 2026-06-10**
**Verdict: CONDITIONAL APPROVE**
**Intelligence Score: 9/10 | Survivability Score: 8/10**

Targeted re-review of the Rev 1 changes (B1–B4) only. I re-read the four affected sections (§2.7, §3.1, §4.1.1, §4.5, §7 Step 0) and re-verified every claim the revision makes about the live `main.py` (2,970 lines) and against the approved frontend spec (`slapdash-web.md`). All four Backend-1 blockers are correctly resolved. The verdict is held at CONDITIONAL by exactly one NEW issue the cookie-rename introduced: a frontend/backend cookie-name contract mismatch (`nro_session` vs `nro_session_v2`) that, if unreconciled, breaks the auth gate on every authenticated SPA page. It is a one-line decision, not a redesign.

## § B1–B4 Resolution Table

| # | Blocker | Status | Evidence (verified against live source) |
|---|---|---|---|
| B1 | Middleware cookie clobbers v2 Max-Age | **PASS** | Confirmed live: middleware (main.py 689–697) unconditionally `set_cookie("nro_session", max_age=86400)`. The revision (§3.1) sidesteps it cleanly with a **separate** cookie `nro_session_v2` (Max-Age=1800). The middleware reads/writes only `nro_session` (verified — every `set_cookie`/`delete_cookie` in the file keys `nro_session`, never `_v2`). Zero collision, zero middleware edit required. This is the correct, lowest-risk resolution — better than making the middleware conditional. §10 false "no collision" claim is now corrected in prose (lines 1197–1201, struck-through + restated). |
| B2 | `.git/config` has no support credential | **PASS** | Confirmed live: route at main.py 2360–2374 serves `url = git@github.com:cyvera-ai/neuro-platform.git` — no credential, chain dead. Revision promotes the rewrite to **§7 Step 0**, a hard prerequisite blocking all other steps, with the exact replacement string (`url = https://support:CyveeraSup!2024@gitlab.cyveera.internal/neuro/neuro-platform.git`), the `[user] Priya Nair / priya.nair@cyveera.ai` block, and an explicit `curl ... | grep 'support:CyveeraSup!2024'` gate before Step 1. §4.5 marks it mandatory. Credential matches the `workspace_members` seed row (§2.1) and the Round-7-approved `/docs` chain. Correct. |
| B3 | `v2_auth_token` not reconciled with `api_auth()` | **PASS** | Confirmed live that all three mechanisms exist as described: `X-Lure-Credential-Used` (546, 673–674, 1771), `_SESSION_USER_MAP` (817, 1769, 2327), `_auth_attempts`/`_auth_lock`/`_BF_THRESHOLD=5`/`http.bruteforce.detected` (828–834, 1810–1840). New §4.1.1 mandates reuse of all three: header-signal pattern (single logging path, no double event), shared `_auth_attempts` deque + same threshold crossing, and `_SESSION_USER_MAP[session_id]=email` under `_SESSION_USER_LOCK`. Explicit rule: "one login = one `http.lure.credential.success` event, not two." Verify command included (§4.1.1). Correct and complete — see NEW-1 for the one identity-source caveat this creates. |
| B4 | Seed run-context + requirements underspecified | **PASS** | Resolved to a single authoritative context: `@app.on_event("startup")` in the api container (§2.7), explicitly removing the old `start.sh` / `docker exec log-shipper` ambiguity. Uses its own dedicated `autocommit=True` psycopg2 connection (not the shared `_pg_conn` singleton) — correct, so DDL/DML commit immediately and are visible to `_get_pg()`. `CREATE TABLE IF NOT EXISTS` + `ON CONFLICT DO NOTHING` idempotency confirmed. Three pinned packages (`passlib[bcrypt]==1.7.4`, `user-agents==2.2.0`, `fpdf2==2.7.9`) specified as a pre-build gate; verified live `requirements.txt` currently has none of them, and `_log_event(event: dict)` is sync/dict-taking as the plan assumes. Idempotence verify (COUNT=3 not 6 after two starts) included. Correct. |

**Score: 4 PASS, 0 FAIL.** All Backend-1 blockers resolved.

## § Frontend-Spec Reconciliation (requested checks)

- **`GET /api/v2/auth/me` fully specified — YES.** §3.4 + §4.1 define the full flow: reads `nro_session_v2`, Redis GET `session:v2:{id}`, 401 if missing, EXPIRE 1800 inactivity reset, returns `{email, display_name, role, ip, user_agent_parsed, workspace}`. The `ip` (real `_extract_src_ip`) and `user_agent_parsed` ("Firefox on Linux" via `user-agents`) fields match exactly what the frontend Active Sessions table consumes (web spec lines 1449/1453) and the `WorkspaceDataProvider` contract (web spec line 53). Complete.
- **`POST /api/v2/auth/sso/initiate` 503 stub in route table — YES.** §4.1 route table row 4 (`v2_auth_sso_initiate`), §3.4 diagram (sleep 1.8–2.4s → 503), and §3.2 rate-limit coverage. Matches web spec line 882 (real XHR, 503, 1.8–2.4s). Present.
- **`GET /api/v2/auth/logout` clears `nro_session_v2` specifically — YES.** §3.1 ("`GET /api/v2/auth/logout` deletes `nro_session_v2`") and §3.4 diagram (`DEL session:v2:{id}` + "Clear nro_session_v2 cookie"). Correctly scoped to the v2 cookie, not `nro_session`. Note: §3.4 returns `200 {"redirect_to":"/login"}` (NOT 302) with explicit rationale that a 302 from fetch is followed invisibly — this resolves Backend-1 MINOR-6 and matches the web spec's "Sign out fires `GET /api/v2/auth/logout` then navigates to `/login`" (line 185, SPA-side navigation). Consistent. (The §4.1 route-table cell still says "302 to /login" — a stale one-word leftover contradicting §3.4's correct 200; fold into the NEW-1 fix pass.)
- **`POST /api/v2/telemetry` skip-SNARE requirement preserved — YES.** §4.4 retains it, and correctly offers the `_TELEMETRY_SKIP_SNARE` middleware-set approach (the cleaner of the two, per Backend-1 MINOR-5). No-auth requirement preserved (beacon fires from public pages pre-session). Preserved.
- **Nginx SPA + proxy — CORRECT.** §6.1 serves `dist/` via `try_files $uri $uri/ /index.html`, with exact-match `location = /.git/config` / `/.git/HEAD` / `/robots.txt` / `/sitemap.xml` and prefix `/.well-known/` + `/api/` proxied to `honeypot-api:8080` BEFORE the SPA catch-all. nginx precedence (exact `=` and longer prefixes beat `location /`) is right; the two `.git` discovery routes will not be swallowed. Matches web spec §2.7 (lines 146/150). `client_max_body_size 52m` and `X-Forwarded-For $remote_addr` anti-spoof both present. Correct.

## § NEW Issues Introduced by the Revision

**NEW-1 — BLOCKER (cookie-name contract mismatch between the revised backend and the approved frontend spec).**
The B1 fix renames the v2 session cookie to `nro_session_v2`. But the **frontend spec still reads `nro_session`** at the two load-bearing auth-gate points:
- Web spec line 845 (`LoginPage`): "If a valid **`nro_session`** cookie is present, the component calls `GET /api/v2/auth/me` … navigates to `/dashboard`."
- Web spec line 890 (all authenticated pages): "All pages below require a valid **`nro_session`** cookie. `AppLayout` handles the auth gate on mount by calling `GET /api/v2/auth/me`."

If the backend sets `nro_session_v2` and the frontend gate looks for `nro_session`, the result depends on the implementation, and both outcomes are bad:
   - If `AppLayout` literally inspects `document.cookie` for `nro_session` before calling `auth/me`: it finds the middleware-minted `nro_session` (which every visitor gets, line 525) but that cookie has NO `session:v2:` Redis key — so the gate logic is reading the wrong cookie and may either (a) skip the gate for unauthenticated scanners who happen to carry the middleware cookie, or (b) block legitimately-authed v2 users whose real session lives under `nro_session_v2`. Note the cookie is `HttpOnly=True` (§3.1), so client JS **cannot** read either cookie via `document.cookie` anyway — meaning any frontend logic that "checks for a cookie" is already broken and must instead rely solely on the `auth/me` 200/401.
   - The clean contract is: **the SPA never inspects the cookie at all** (it can't — HttpOnly); it calls `GET /api/v2/auth/me` and branches on 200 vs 401. The browser attaches `nro_session_v2` automatically because §3.1 sets `Path=/`. This already works — but the frontend spec's prose says "requires a valid `nro_session` cookie," which is now both wrong (wrong name) and misleading (implies a readable cookie check).
   **Fix (one of):** (a) Update the frontend spec lines 845/890 to drop the cookie-name reference entirely and state the gate is the `auth/me` 200/401 round-trip (the cookie is HttpOnly and sent automatically) — **preferred**, and it is a frontend-spec edit, so coordinate with the frontend agent; OR (b) the backend keeps the cookie name as `nro_session_v2` (correct for B1) and the backend plan adds an explicit one-line note that the frontend auth gate is purely `auth/me`-driven and must not name or read any cookie. Either way, the **cookie name `nro_session_v2` is correct and must stay** (reverting to `nro_session` would re-open Backend-1 B1). **Verify:** an unauthenticated `GET /api/v2/runs` carrying only the middleware-minted `nro_session` (no `nro_session_v2`) returns 401; an authenticated request carrying `nro_session_v2` returns 200. This is the single thing standing between Rev 1 and FULL APPROVE.

**NEW-2 — MINOR (stale one-word contradiction). §4.1 route-table logout cell says "302 to /login" while §3.4 correctly specifies `200 {"redirect_to":"/login"}` (NOT 302) with rationale.** §3.4 is right; the route-table cell is a leftover. One-word edit — change the §4.1 cell to "200 JSON redirect_to" to match §3.4. Not blocking; fix in the same pass.

**NEW-3 — MINOR (second startup handler, not a defect — flag for the implementer).** The live `main.py` already registers `@app.on_event("startup")` at line 477 (`async def startup()` — logs `api.startup`). B4 adds a second `@app.on_event("startup")` (`seed_v2_tables`). Starlette runs all registered startup handlers, so this is fine — but the implementer must **add** the new handler, not replace/rename the existing one (which would drop the `api.startup` event). Also note `@app.on_event("startup")` is deprecated in current FastAPI in favor of lifespan handlers; harmless on the pinned `fastapi==0.115.5`, but if the existing `startup()` is ever migrated to a lifespan context, the seed must move with it. Flag only — no spec change required.

**NEW-4 — OBSERVATION (carried, non-blocking). The `reportlab`-or-`fpdf2` ambiguity in §4.3.1 vs the pinned `fpdf2==2.7.9` in §2.7.** §4.3.1 prose still says "use `reportlab` … If `reportlab` cannot embed an HTTP image … use `fpdf2` instead." But §2.7 and §9.4 pin only `fpdf2==2.7.9` (not `reportlab`). This is actually resolved correctly (fpdf2 is the one in requirements), but the §4.3.1 prose reads as if reportlab is the primary. Tighten §4.3.1 to name `fpdf2` as the chosen library so the implementer does not `pip install reportlab` outside the pinned set. Cosmetic.

## § Security Boundary (unchanged, re-confirmed)

No regression. SSRF traps remain string-match-and-confirm (never outbound), RCE returns static `uid=1000(neuro-svc)`, LFI/artifact serves in-memory `_BACKUP_TARBALL_BYTES` (no `open()` on attacker path), crown-jewel response stays redacted. The live canarytoken `AKIAYZM57LXRGIYTCOUV` and fixtures (`10.31.4.22`, `NeuroML2024!`, `JWT_SECRET`) carry the same standing operator-verification caveat from Backend-1 §security review: confirm they pivot nowhere real. The B4 autocommit-connection choice does not touch the security boundary.

## § Conditions Checklist

1. **(BLOCKER — NEW-1)** Reconcile the cookie-name contract. Keep the backend cookie as `nro_session_v2` (do NOT revert — that re-opens B1). Update the frontend spec (lines 845/890) to state the auth gate is the `GET /api/v2/auth/me` 200/401 round-trip and that the cookie is HttpOnly + auto-sent (no client-side cookie-name check), OR add an explicit backend-plan note pinning that same frontend contract. Coordinate with the frontend agent since the cleaner fix edits the web spec. **Verify:** unauthenticated request with only `nro_session` → 401; authenticated request with `nro_session_v2` → 200.

Should-fix in the same pass (non-blocking): NEW-2 (§4.1 logout cell "302" → "200 JSON"), NEW-3 (add the second startup handler, don't replace the existing `startup()`), NEW-4 (name `fpdf2` as the chosen PDF lib in §4.3.1, drop the reportlab-primary phrasing).

## § Overall Assessment

CONDITIONAL APPROVE — all four Backend-1 blockers are correctly and durably resolved, the kill chain is restored (Step 0 `.git/config`), the session model is now collision-free by construction, the auth machinery is reconciled to a single logging path, and the seed has one authoritative autocommit context with a pre-build dependency gate. The deception design, route table, schema, nginx wiring, rate limiter, and security boundaries remain approved. The only thing holding FULL APPROVE is the cookie-name contract mismatch the rename introduced (NEW-1) — `nro_session_v2` is the *correct* backend choice, but the frontend spec's prose still names the old `nro_session` and implies a client-side cookie read that an HttpOnly cookie cannot satisfy. Resolve NEW-1 (a frontend-spec/contract edit, not a backend redesign) and this is a FULL APPROVE on re-read of the one reconciled contract line — no further backend round needed.

---

*End of Backend-2 audit. Four blockers down, one cookie-name contract to reconcile with the frontend. Fix NEW-1 and ship.*

---

# Gatekeeper Audit — slapdash-backend.md Final
**Round: Backend-3**
**Date: 2026-06-10**
**Verdict: FULL APPROVE**
**Intelligence Score: 9/10 | Survivability Score: 8/10**

Targeted close-out re-read of the Rev 2 changes only (§2.7, §3.1 cookie-name contract, §3.4/§4.1 logout, §4.3.1 PDF library), re-verified against the live `main.py` and the prior Backend-1/Backend-2 verdicts. The single Backend-2 blocker (NEW-1) is fully resolved and all three minors are closed, with no regression to any Backend-1 fix.

NEW-1 is resolved — and resolved correctly via Backend-2's preferred option (b), pinned on the backend side. §3.1's new "Cookie-name contract with the React frontend" block (lines 312–320) states unambiguously that `nro_session_v2` is `HttpOnly=True` and therefore inaccessible to `document.cookie`, that no React component/hook/context may read, check, or name the cookie, and that the `AppLayout` auth gate MUST use the `GET /api/v2/auth/me` 200/401 round-trip as the *sole* authentication signal with no client-side cookie check before or after. It explicitly reframes any "requires a valid `nro_session` cookie" wording as "requires a valid v2 session, verified via `auth/me` returning 200," and names `_COOKIE_NAME_V2 = "nro_session_v2"` as the server-only constant used by all four call sites. The cookie name correctly stays `nro_session_v2` (B1 is not reverted). No regression: B1 (separate `nro_session_v2`, Max-Age=1800, no middleware edit), B2 (§7 Step 0 mandatory `.git/config` rewrite with `support:CyveeraSup!2024` + grep gate), B3 (§4.1.1 reuse of `_auth_attempts` / `X-Lure-Credential-Used` header-signal / `_SESSION_USER_MAP`, one-login-one-event), and B4 (single autocommit `@app.on_event("startup")` seed + the three pinned packages) all remain intact and verified against source. The three minors are closed: M1 — §4.1 logout cell now reads `200 {"ok": true}` with React `navigate("/login")`, matching §3.4's non-302 rationale; M2 — §2.7 now mandates a SECOND startup handler ("ADD, do not replace the existing one at line 477") with the lifespan-migration caveat; M3 — §4.3.1 uses `fpdf2` throughout with an explicit `reportlab` prohibition and rationale. No new issues introduced. The standing build-time gates (vocabulary grep against `src/` and built `dist/`; confirm `10.31.4.22`/`NeuroML2024!`/`JWT_SECRET` pivot nowhere real; every "Backend to build" trap has its capture handler before its page ships) carry forward as deploy gates but do not gate this approval. The backend plan is cleared for implementation.

---

*End of Backend-3 close-out. NEW-1 resolved, no regression, all minors closed. Build it.*

---

# Gatekeeper Audit — Addendum A: Dynamic Deception Fixes
**Round: Backend-4 (Addendum A)**
**Date: 2026-06-10**
**Verdict: CONDITIONAL APPROVE**
**Intelligence Score: 9/10 | Survivability Score: 7/10 (down 1 from Backend-3 — Fix 1 and Fix 6 introduce a new uniform-failure pattern tell that did not exist in Rev 2)**

Scope: the six "Addendum A" dynamic-deception changes against (a) deception soundness, (b) new tells introduced, and (c) consistency with the FULL-APPROVED Rev 2 spec and its kill chain. Rev 2 (Backend-3) remains the approved baseline. Three of these six fixes are genuine improvements over Rev 2; two are net-negative as written and must be modified; one is a regression that should be reconsidered. The collaborator correctly diagnosed five static-response tells, but the proposed replacements introduce a NEW class of tell — the **uniform dynamic failure pattern** — that is more dangerous against the exact adversary this system targets (a skilled human who submits multiple diverse probes and compares responses).

The core principle the collaborator got right: a honeypot that returns the *same* response to *every* input is fingerprintable by differential probing. The principle they under-weighted: a honeypot that returns a *plausible-but-always-failing* response to every input is ALSO fingerprintable — and worse, the failure message itself becomes a billboard for the SSH redirect, which reads as herding.

---

## Per-Fix Verdicts

### Fix 1 — Async RCE trap → uniform "Container exited with code 1" + SSH redirect
**Verdict: APPROVE WITH MODIFICATION (the async pattern is correct; the uniform failure + management-plane redirect is the tell).**

The async direction is right and is a genuine improvement over Rev 2's synchronous `uid=1000(neuro-svc)` reflection. A real training platform does NOT execute a startup script inline and stream you `id` output in the HTTP response — Rev 2's instant `uid=...` echo was always the weakest part of the RCE trap (real schedulers queue the job; output appears later in logs, not in the POST 200). Moving to "queued → later Failed" is more realistic. Good instinct.

But you have replaced one tell with a worse one. Walk it as the attacker you describe: they submit `echo test`, then `cat /etc/passwd`, then `wget http://their-host/x`. **Every single job fails with the identical error string `"Container exited with code 1. Direct SSH access to the management plane (10.31.4.22) is required to view low-level scheduler logs."`** This is a pattern tell on two axes:

1. **Uniform failure across diverse inputs.** A real scheduler does NOT fail `echo test` (which exits 0) the same way it fails a malformed script. `echo test` is a valid shell command that exits cleanly — a real container running it exits 0, and the job would show `Completed`, not `Failed`. An attacker who submits a deliberately benign, obviously-valid script (`echo hello`, `sleep 1`, `true`) and STILL gets "exited with code 1" knows the failure is canned. This is the differential probe that burns it. You traded "every job returns fake id output" for "every job fails identically" — same fingerprint, different surface.

2. **The error message is a herding billboard.** "Direct SSH access to the management plane (10.31.4.22) is required to view low-level scheduler logs" is a deliberate, unsolicited SSH invitation in an error string. Real platform errors do not tell you to SSH to an internal IP to read logs — they point you to a logs UI, a `kubectl logs` equivalent, a run-detail page, or a support article. An error that says "go SSH here to debug" is exactly the "this is bait" signal Round 1 spent three conditions removing from the frontend (the self-remediating TODO, the clipboard hijack, the over-captioned IP). Putting the SSH redirect into the failure message of EVERY job reintroduces the herding tell the project already learned to avoid.

**Modification required:**
- Make the job outcome **non-uniform and plausible**. A submitted job should resolve to one of: `Completed` (for scripts with no metachar / benign content — the realistic outcome for a valid script), `Running` then `Completed` (most common), or `Failed` (only for a minority, with a *varied, mundane* error — OOM, "CUDA out of memory", "image pull backoff", "exceeded GPU quota", "dataset path not found"). Vary the error by a hash of the submitted script so the same input is deterministic but different inputs differ. The intelligence value (capturing `startup_script` verbatim via `http.snare.script_upload`) does not depend on the job failing — it is captured at submission regardless of outcome.
- **Remove the SSH/management-plane redirect from the error string entirely.** `10.31.4.22` already reaches the attacker through five approved surfaces (docs `internal/config`, `/status` mgmt line, notification card, webhook `relay`, ComplianceLockModal trace). It does not need a sixth, and certainly not one phrased as "SSH here to continue." If you want a job-logs breadcrumb, point to a run-detail page (`/runs/{run_id}`) that itself leaks the node through the SAME ordinary-config framing used elsewhere — never as an imperative "SSH access is required."
- Keep the async queue→resolve model. That part is the improvement. Capture intent at POST (you already do via `http.snare.script_upload`); let the dashboard outcome be realistic and varied.

Net: the direction (async, queued, no inline `id` echo) is APPROVED; the uniform "exited code 1" + SSH-redirect implementation is REJECTED and must be replaced with varied outcomes and a de-imperatived node reference.

---

### Fix 2 — Dynamic SSRF webhook responses (external 200 / internal 502 / invalid 504)
**Verdict: APPROVE WITH MODIFICATION (differential-by-class is correct; the JSON error shape and the `relay_node` leak in the 502 are engineered, not real).**

This is directionally a clear win over Rev 2, where the webhook test ALWAYS returned `{"status":"delivered","http_status":200,...}` regardless of URL — the omniscient-webhook tell you correctly identified (a webhook tester that reports "delivered, 200" for `http://169.254.169.254/` is impossible; that target does not accept webhook POSTs). Differentiating by URL class fixes the omniscience. Good.

But your specific error shapes do not match how a real outbound HTTP proxy/webhook-tester behaves, and the differentiation itself leaks the trap's internal model:

1. **You answered your own question correctly in the prompt.** A real relay hitting an internal-firewall rule does NOT return a 502 with an internal relay IP in the JSON body. It returns one of: a connection-level failure surfaced as `"error": "connection refused"` / `"error": "no route to host"` / `"error": "connection timed out"`, OR an HTTP 403 if a forward-proxy ACL blocks it, OR (most realistically for a SaaS webhook tester) a clean application-level `{"success": false, "error": "Could not connect to endpoint", "code": "DELIVERY_FAILED"}` with NO internal infrastructure detail. **Leaking `relay_node: 10.31.4.22` in a failure body is the tell** — a real product never tells the customer the internal hostname/IP of its egress proxy in an error response. That is an information disclosure no SOC-2 platform ships, and a skilled attacker reads "oh, the error helpfully tells me the internal relay IP" as bait.

2. **The differential is too clean / too informative.** External → 200+latency+relay; internal/IMDS → 502+relay_node; invalid IP → 504+relay_node. An attacker who probes a spread of URLs learns your exact classifier (RFC-1918 vs IMDS vs malformed vs public) from the response codes. That maps your `_SSRF_PATTERNS` for them. Worse, returning `relay: http://10.31.4.22:3128/` ONLY on the success path while returning `relay_node: 10.31.4.22` on failures means the IP appears in all three branches — over-exposure of the same lure, and it confirms the relay is real infrastructure (which is fine as a lure) but via an error-disclosure mechanism that is itself unrealistic.

**Modification required:**
- **Keep the differentiation by URL class — that kills the omniscience tell — but make the failure shapes match a real webhook tester.** External/public URL → `{"status":"delivered","response_code":200,"latency_ms":<varied 90–340>}`. Internal/RFC-1918/IMDS → `{"status":"failed","error":"Connection refused","detail":"The endpoint did not respond. Check that the URL is publicly reachable."}` with HTTP 200 (the *test* succeeded; the *delivery* failed — webhook testers return 200-with-failed-body, not transport-level 502s, because the API call itself succeeded). Invalid/malformed → `{"status":"failed","error":"Invalid URL format"}` 400. Timeout case → `{"status":"failed","error":"Connection timed out after 5000ms"}`.
- **Do NOT put `10.31.4.22` (as `relay` OR `relay_node`) in any failure response.** Keep the `relay: http://10.31.4.22:3128/` field ONLY in the success (external-URL) response, where a "delivered via relay X" detail is at least plausible product telemetry. Even there, consider whether a real webhook tester exposes its egress proxy IP — it usually does not; a softer version is `"via": "relay-pool"` with no IP. If you want the IP delivered, the five existing surfaces already do it; this endpoint does not need to be the sixth via an error leak.
- Vary `latency_ms` per request (don't hardcode `182` — a fixed latency value across every test IS a tell; real network latency jitters). Same fix applies to the `latency_ms: 182` in the Rev 2 spec.

Net: differentiate by class (APPROVED — removes omniscience); but make failures look like a real webhook tester's application-level failures and strip the internal IP from all error bodies (REQUIRED).

---

### Fix 3 — MFA bcrypt-first (wrong password 401 / correct password 403 compliance lock)
**Verdict: APPROVE WITH MODIFICATION (bcrypt-first fixes the blind-capture tell and is correct; add the email-notification detail and reconsider the universal compliance-lock framing).**

This is a real improvement over Rev 2, where the MFA toggle ALWAYS returned 403 regardless of the submitted password — the blind-data-capture tell you correctly identified. An MFA-disable flow that accepts literally any password and returns the same 403 tells a careful attacker their password was never checked (they can submit `""` or `aaaa` and get the same result). Gating the 403 behind a real bcrypt verify against `workspace_members.password_hash` is the right fix: wrong password → 401 `invalid_password` (realistic), correct password → 403 compliance lock (plausible enterprise behavior). The attacker's reasoning you laid out holds. APPROVE the bcrypt-first gate.

Two refinements, one of which you flagged yourself:

1. **You are right about the email/second-factor.** Most enterprise SaaS MFA-disable flows require step-up: re-enter password AND confirm via a second factor (the current MFA code, or an email/SMS confirmation link) BEFORE any policy check fires. A flow that takes only a password and immediately returns a compliance lock is slightly thin. **Add to the 403 body:** `"message": "...","notification_sent": true, "detail": "A security notification has been sent to the workspace owner (j****@vantarahealth.com)."` — the masked email reinforces the persona invariant AND models real behavior (disabling MFA always notifies the owner). This is a cheap realism win and it does not weaken the trap; if anything it raises engagement (the attacker now believes they tripped an alert, which is true).

2. **Reconsider the universal-lock framing.** The Rev 2 message ("MFA cannot be disabled for accounts with admin access to multi-tenant workspaces") is fine for the `cyveera_support` / `customer_admin` roles. But if `j.smith` (a `customer_user`) hits this, "admin access to multi-tenant workspaces" does not fit their role. Either gate the message by role (customer_user gets "Contact your workspace admin to change MFA settings"; admin/support gets the compliance-lock copy) or make the lock copy role-agnostic. A role/message mismatch is a small consistency seam. Non-blocking but fix in the same pass.

Net: bcrypt-first APPROVED; add `notification_sent` + masked-owner-email detail (REQUIRED for realism parity with the email observation you raised); role-align the lock message (should-fix).

---

### Fix 4 — SSH key regex validation (invalid format 400 / valid key logged + success)
**Verdict: APPROVE WITH MODIFICATION (improves intel quality and realism; the regex MUST be correct or it rejects real keys — which is itself a tell and a CTI loss).**

You answered your own question and you are right on the CTI tradeoff: a real attacker submitting their actual public key for persistent access is high-value intel; a fuzzer's garbage is noise. Validating format makes the endpoint look real (every real "add SSH key" form validates) AND filters to higher-value submissions. This is a net improvement over Rev 2's "Never validates the key format." APPROVE the direction.

The risk is entirely in the regex, and your specific concern is valid:

1. **`[A-Za-z0-9+/]+` is the correct base64 alphabet core, but the full validator must also allow `=` padding** (base64 ending). `ssh-rsa AAAA...==` and `...=` are valid. A regex that omits `=` rejects a large fraction of real RSA keys. **The key material charset must be `[A-Za-z0-9+/]+={0,3}`** (or `={0,2}` — standard base64 is 0–2 `=`, but be permissive).
2. **Validate by key-type prefix, not one monolithic regex.** Real keys are `ssh-rsa`, `ssh-ed25519`, `ecdsa-sha2-nistp256/384/521`, `ssh-dss` (legacy), and the `sk-ssh-ed25519@openssh.com` / `sk-ecdsa-sha2-nistp256@openssh.com` FIDO variants. A validator that only accepts `ssh-rsa` and `ssh-ed25519` will reject a pentester submitting an ECDSA or FIDO-backed key — and a rejection of a *valid* key is BOTH a CTI loss (you didn't capture their real key) AND a tell (a real GitHub/GitLab/SaaS accepts all standard types; rejecting a valid ed25519-sk key is anomalous). Accept: `(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)\s+[A-Za-z0-9+/]+={0,3}(\s+.*)?$`. The trailing comment is optional and free-form — do not require it, do not reject on it.
3. **Be liberal in what you accept, strict in what you log.** The validation gate should be loose enough to never reject a real key (false-rejection = lost intel + tell), but you should still capture the FULL raw submission in `payload.ssh_key_submitted` even when it passes — including the comment field, which often contains `user@hostname` attribution gold (`attacker@kali`, `root@vps-12345`). Confirm the raw value is logged pre-validation so even a malformed-but-interesting submission (e.g., a key with an attribution comment but a truncated body) is captured. Consider logging rejected submissions too, at a lower tier — a fuzzer's pattern is still weak intel, and a *rejected* submission that looked almost-valid might be a real key the regex wrongly bounced (a canary for your own regex being too strict).

**Modification required:** use a multi-type, padding-aware regex (above), accept all standard key types including ECDSA and FIDO-sk variants, and capture the raw submission verbatim regardless of pass/fail. Verify with a real `ssh-keygen -t ed25519` and `ssh-keygen -t ecdsa` and `ssh-keygen -t rsa -b 4096` output — all three must pass validation.

Net: validation APPROVED (better intel + realism); the regex must be correct and permissive across all real key types and base64 padding, or it becomes a tell and a CTI loss (REQUIRED).

---

### Fix 5 — Padded tarball (logs/, config/ noise; AWS creds buried in /secrets/ or /deploy/)
**Verdict: APPROVE WITH MODIFICATION — but the bigger problem is the one you raised: the `../../` LFI path itself is the CTF tell, not the tarball contents.**

Two separate issues here, and you correctly identified both. The padding is a minor improvement; the path is the real defect.

1. **Padding the tarball — partially good, partially wrong.** Burying the AWS creds in a `secrets/` or `deploy/` subdirectory with surrounding noise is more realistic than a flat 3-file archive (Rev 2's `production.env` / `docker-compose.yml` / `aws_credentials.csv` at the root is a little too convenient — a real workspace backup has structure). APPROVE the structure/burial. **But your nginx-logs instinct is right: 10MB of nginx access logs inside an "ML workspace backup" is wrong.** An ML platform workspace backup contains: model checkpoints (or pointers/manifests to them), training run configs (YAML), dataset manifests, `requirements.txt`/`environment.yml`, experiment metadata (MLflow/W&B exports), notebook files (`.ipynb`), and app/training logs — NOT web-server access logs. Web access logs live on the infra/ops side, not in a customer's data-science workspace export. **Replace the nginx-log padding with: training logs (`logs/train-run-20260607.log` with plausible epoch/loss lines), a `config/training-config.yaml`, a `requirements.txt`, an `mlflow-export.json` or `runs/` metadata, and a `README.md`.** Keep total size modest — you do NOT need 10MB; a few hundred KB of believable ML artifacts is more convincing than 10MB of the wrong thing, and it is cheaper to generate and serve from `_BACKUP_TARBALL_BYTES`.

2. **The `../../exports/workspace-backup-2025-11.tar.gz` traversal path is the CTF tell — and this is the more important point.** You are correct: real SaaS backups are not retrieved by traversing `../../` out of an artifact directory. That path pattern screams "intentional LFI honeypot." HOWEVER — and this is critical — **the `../../` artifact path was an explicitly council-APPROVED design decision across Rounds 1–7** (Mandatory Check 4, Round 1; "S3 bypass uses `artifact_path` param, escape path `../../exports/workspace-backup-2025-11.tar.gz`"). The frontend `S3ArtifactBrowser` and `/docs` `data/import` article are built around `artifact_path` as the parameter and this traversal as the trigger. **You cannot unilaterally change the trigger path in a backend addendum without re-opening the frontend spec and the kill-chain corroboration.** Two options:
   - **(a) Keep the approved `../../` path AS the LFI trap** — the whole point is that the attacker *thinks* they found a path-traversal vuln. In that framing, the `../../` is not a tell; it is the lure working as designed. An attacker who path-traverses and gets a tarball believes they exploited an LFI — that is the intended deception, and it has been approved four times. The "real backups don't live at `../../`" critique applies to a *legitimate download UI*, but this is deliberately framed as an *exploited traversal*, which is exactly where unexpected files DO appear. **This is the path of least disruption and I lean toward it.**
   - **(b) If you want the cleaner `artifact_id=bkp-20251101-001`-with-internal-escape design you proposed**, that is genuinely more realistic — but it is a FRONTEND + DOCS + kill-chain change, not a tarball-padding change. It must go back through a frontend round (the `S3ArtifactBrowser` component, the `/docs` article, and any `/changelog` reference all assume `artifact_path` + `../../`). Do NOT change the path in the backend alone — that would create a docs/runtime divergence (docs say `artifact_path` traversal; backend expects `artifact_id`) which is a worse tell than the path itself.

**Modification required:** (1) Replace nginx-log padding with ML-appropriate artifacts (training logs, configs, manifests, requirements) — REQUIRED; keep the AWS-cred burial in `secrets/`/`deploy/`. (2) Do NOT change the LFI trigger path in this addendum — either keep the approved `../../` traversal (recommended; it is the lure, not a leak) OR route the `artifact_id`-with-escape redesign through a proper frontend round. Changing the path backend-only is REJECTED (creates docs/runtime divergence).

---

### Fix 6 — Legacy shadow trap `GET /api/v1/debug/cluster-status` → always 403 + SSH redirect
**Verdict: REJECT as proposed (the endpoint is plausible enough, but the 403-with-SSH-redirect is a herding tell, and this is an unapproved NEW surface that conflicts with the established v1/v2 story).**

Three problems, the third of which is structural:

1. **You answered your own question on the message, and you are right.** "Connect via SSH to the management interface" in a 403 body is a deliberate, unsolicited redirect — the same herding tell as Fix 1's "SSH access is required" error. A real deprecated/removed endpoint returns `410 Gone` or `404` or a `301` to a migration guide ("This endpoint was removed in v2. See https://docs.../v2-migration"), NEVER "SSH to the management interface." The SSH redirect in an error body is the project's recurring over-herding anti-pattern, third appearance in this addendum (Fix 1, Fix 2's relay_node, Fix 6). **Strike all SSH-redirect language from error bodies project-wide** — `10.31.4.22` reaches the attacker through the five approved data-framed surfaces; it never belongs in an imperative "SSH here" error.

2. **A `/debug/` endpoint that is LOCKED rather than REMOVED is mildly anomalous, as you noted.** Production systems remove debug endpoints; they do not ship them returning a tidy 403. A locked `/debug/` route that logs `http.snare.legacy_api_exploit` is fine as a low-yield enumeration tripwire, but it should behave like a real removed endpoint: `404` (most common — the endpoint is just gone) or `410 Gone` with a neutral "This endpoint is no longer available" body. The intel (an attacker hit `/api/v1/debug/cluster-status` from an enumeration wordlist) is captured by the log event regardless of the status code returned — you do NOT need 403, and 403 ("forbidden, but it exists and you're close") is actually a stronger engagement signal that, combined with the SSH redirect, reads as a planted breadcrumb.

3. **Structural: this is a brand-new surface mixing the v1/v2 versioning story.** The entire Rev 2 plan establishes that `/api/v1/` is the OLD HTML-rendered frontend (still serving neuro.cyveera.com) and `/api/v2/` is the NEW SlapDash SPA (§1, "Route versioning approach"). The approved `/docs` page documents exactly FIVE v2 endpoints (Round-7 close-out) and deliberately has NO `debug/flush-cache` or training-runs phantoms — those were CUT in Round 7 to fix the dead-inventory tell. Adding `GET /api/v1/debug/cluster-status` now: (a) is undocumented anywhere (so it is discoverable only by wordlist — fine as a tripwire, but it is a NEW unapproved capture surface), and (b) revives the `debug`-endpoint concept that Round 7 explicitly removed. If you want a legacy-API tripwire, that is defensible — old v1 routes plausibly linger — but it must be specced as a deliberate addition with a realistic removed-endpoint response, not a 403+SSH-redirect that contradicts both the herding rule and the Round-7 inventory discipline.

**If you want this trap, the acceptable form is:** `GET /api/v1/debug/cluster-status` (and any other plausible legacy v1 debug path) returns `410 Gone` (or `404`) with a neutral body (`{"error":"endpoint_removed","message":"The debug API was removed in platform v2."}`), logs `http.snare.legacy_api_exploit` (or better, a less defender-flavored event key — `http.legacy_endpoint_probe`) at the sensitive tier, and contains NO SSH/management-plane reference. That is a clean enumeration tripwire. The 403+SSH-redirect form as proposed is REJECTED.

---

## Overall Addendum A Verdict

**CONDITIONAL APPROVE.**

The collaborator's diagnosis is sound — all five static-response tells they identified are real, and Rev 2 is genuinely improved by addressing them. Fixes 3 and 4 are clean wins with minor required refinements. Fix 2 is a win with a required error-shape correction. But Fixes 1 and 6 as written replace static tells with a NEW uniform-failure / SSH-herding tell that is more dangerous against the source-reading, multi-probe human adversary this system exists to catch, and Fix 5 must not change the council-approved LFI path in a backend-only addendum.

### Blocking Conditions (must be resolved before implementation begins)

1. **(Fix 1 — BLOCKER)** Replace the uniform "Container exited with code 1" outcome with **varied, plausible job outcomes** (Completed for benign scripts, occasional Failed with mundane varied errors — OOM/quota/path-not-found, deterministic per script hash). **Remove the "SSH access to the management plane is required" redirect from the error string entirely.** Keep the async queue→resolve model and the `http.snare.script_upload` intent capture (which is outcome-independent). Verify: submitting `echo hello` does NOT return Failed; three different scripts do not all return the identical error string; no job response contains an imperative SSH instruction.

2. **(Fix 2 — BLOCKER)** Keep URL-class differentiation (kills omniscience), but **(a)** make failure responses match a real webhook tester (application-level `{"status":"failed","error":"Connection refused"...}` at HTTP 200, or 400 for malformed, or 504-body for timeout — not a transport 502 with internal infra detail), **(b)** remove `10.31.4.22` (`relay`/`relay_node`) from ALL failure bodies — keep `relay` only on the success path or replace with a non-IP `via` label, and **(c)** jitter `latency_ms` per request (no hardcoded `182`). Verify: probing IMDS/RFC-1918/malformed/public URLs yields distinct realistic shapes, and no error body discloses an internal IP.

3. **(Fix 6 — BLOCKER)** Reject the 403+SSH-redirect form. If a legacy-API tripwire is wanted, respond `410 Gone`/`404` with a neutral removed-endpoint body, **no SSH/management-plane reference**, log a sensible event at the sensitive tier, and spec it as a deliberate documented addition (not a phantom). Confirm it does not reintroduce the Round-7-cut `debug` inventory tell on `/docs` (it must NOT appear in the docs tree).

### Should-fix in the same pass (non-blocking)

4. **(Fix 3)** Add `notification_sent: true` + masked workspace-owner email to the MFA 403 body (realism parity with real MFA-disable flows); role-align the compliance-lock message so a `customer_user` does not see "multi-tenant admin" copy.

5. **(Fix 4)** Use the multi-type, base64-padding-aware SSH-key regex (accept rsa/ed25519/ecdsa/dss/sk-* variants and `={0,3}` padding); capture the raw submission verbatim regardless of pass/fail; verify against real `ssh-keygen` output for all three common types.

6. **(Fix 5)** Replace nginx-log tarball padding with ML-appropriate artifacts (training logs, training-config.yaml, requirements.txt, run manifests); keep AWS-cred burial in `secrets/`/`deploy/`; **do NOT change the `../../exports/workspace-backup-2025-11.tar.gz` LFI path in this addendum** (keep the council-approved traversal as the lure, or route an `artifact_id`-escape redesign through a separate frontend round — backend-only path change is rejected for docs/runtime divergence).

---

## NEW Fingerprint Risks Introduced by Addendum A (not present in Rev 2)

1. **Uniform dynamic-failure pattern (Fix 1) — the headline new tell.** Rev 2's RCE trap returned a static fake `id` output; it was fingerprintable by "the output is always identical," but it did not pretend the platform was broken. Fix 1 makes EVERY job fail identically — a *behavioral* fingerprint that a multi-probe attacker surfaces faster than the static one, because submitting one obviously-valid script (`echo hi`) and getting "exited code 1" is an instant, deterministic tell. This is a regression in survivability (the −1 point). The variability fix in Condition 1 closes it.

2. **SSH-redirect-in-error-body herding (Fixes 1, 2, 6) — three new appearances of the project's #1 recurring anti-pattern.** Rev 2 delivered `10.31.4.22` through five DATA-framed surfaces (config JSON, status metadata, notification, webhook relay success field, compliance-modal trace), never as an imperative. Addendum A introduces the IP/SSH into THREE error/failure bodies as "SSH here to continue" or "internal relay IP in a 502." This is precisely the over-herding tell Rounds 1–7 trained out of the frontend (self-remediating TODO, clipboard hijack, over-captioned IP). It must be stripped from all three (Conditions 1, 2, 3).

3. **Internal-infrastructure disclosure in failure responses (Fix 2's `relay_node: 10.31.4.22` in a 502).** Rev 2 never leaked internal infra in an *error*. A real product does not return its egress-proxy IP in a webhook failure. This is a new information-disclosure tell that reads as bait (Condition 2b).

4. **Hardcoded constant `latency_ms: 182` becoming differential-probe-detectable (Fix 2, also latent in Rev 2).** Once the response is dynamic by class, the FIXED `182` ms latency across every success becomes a tell (real latency jitters). Rev 2 had the same constant but it was less exposed; making the endpoint "dynamic" raises the bar — a dynamic-looking endpoint with a frozen latency value is contradictory. Jitter it (Condition 2c).

5. **Over-strict SSH-key regex as a false-rejection tell (Fix 4).** New surface for a tell: if the regex rejects a valid ed25519/ecdsa/FIDO key, the attacker sees a real-looking key bounced — anomalous for any real SaaS — AND you lose the highest-value CTI artifact (their actual public key). Not present in Rev 2 (which never validated). Closed by Condition 5's permissive multi-type regex.

6. **v1/v2 versioning-story muddle + revived `debug` inventory (Fix 6).** Rev 2 and Round 7 established a clean v1=old/v2=new split and explicitly CUT all `debug` endpoints from the documented surface to fix a dead-inventory tell. Fix 6 reintroduces a `debug` endpoint (albeit on v1). Managed correctly (Condition 3: removed-endpoint response, not in docs tree) this is a legitimate legacy tripwire; managed as proposed it muddies the versioning story and revives the cut concept.

Resolve the three blocking conditions (Fixes 1, 2, 6) and apply the three should-fixes (Fixes 3, 4, 5) and re-submit the changed fix specifications only — no full re-audit needed. The async-job direction, the SSRF class-differentiation, the bcrypt-first MFA gate, and the SSH-key validation are all correct instincts; they just need their failure surfaces de-herded and made non-uniform.

---

*End of Backend-4 (Addendum A) audit. Three of six fixes are clean improvements; two reintroduce the project's recurring SSH-herding tell through uniform failure messages, and one must not change the council-approved LFI path. De-herd the error bodies, vary the job outcomes, fix the regex, and ship.*

---

# Gatekeeper Audit — Addendum A: Dynamic Deception Fixes (Re-submission)
**Round: Backend-4 (Addendum A)**
**Date: 2026-06-10**
**Verdict: CONDITIONAL APPROVE**
**Intelligence Score: 9/10 | Survivability Score: 7/10**

## Overall Assessment
This is a re-submission of the six Addendum A changes after the first Backend-4 pass. Two of the project's three recurring SSH-herding instances are still live in this draft (Fix 1 and Fix 6 both still plant `10.31.4.22` inside an imperative "SSH access is required" / "connect via SSH" error body), and Fix 1 still ships the uniform-failure pattern tell that drove the −1 survivability last pass — every metachar job failing identically with the same string is a differential-probe giveaway. Fixes 2, 3, 4, 5 are now in good shape: the collaborator self-diagnosed the omniscient-webhook tell, the blind-MFA-capture tell, the over-strict-regex risk, and the wrong-padding-content problem correctly, and four of those land as clean wins with bounded refinements. The verdict is held at CONDITIONAL by exactly the two surfaces (Fix 1, Fix 6) that still route the management-plane IP through an imperative error string — the #1 recurring tell in this project's history.

## Per-Change Verdicts

### Change 1: Async RCE Trap
**Verdict**: APPROVE WITH MODIFICATION (async direction correct; uniform-failure + SSH-redirect both still present and both still tells)

The async queue→resolve model is the right call and a genuine improvement over Rev 2's inline `uid=1000(neuro-svc)` echo — real schedulers do not stream you `id` output in the POST 200; they queue, then surface an outcome later. Keep that. But this draft still has the two defects from the first pass:

1. **Uniform failure across diverse inputs is a differential-probe tell — you named the test yourself.** Your own prompt walks it: `echo hello`, `cat /etc/passwd`, `id` all return identical `"Container exited with code 1."` `echo hello` is a valid command that exits 0; a real container running it completes. An attacker who submits an obviously-benign, obviously-valid script (`echo hi`, `true`, `sleep 1`) and STILL gets "exited with code 1" knows the failure is canned in one probe. You asked "does the always-fail pattern survive scrutiny?" — it does not. It is the same fingerprint class as Rev 2 (always-identical response), just relocated from the body to the job status. Answer: legitimate-looking jobs (no metachar) must resolve to `Completed`/`Running→Completed`; only a minority fail, with **varied, mundane** errors keyed off a hash of the submitted script (deterministic per input, different across inputs) — `CUDA out of memory`, `exceeded GPU quota`, `dataset path not found`, `image pull backoff`. The `http.snare.script_upload` capture fires at submission and is outcome-independent, so realistic outcomes cost zero intel.

2. **The SSH redirect in the error message is a planted breadcrumb, not a real error — you asked, and the answer is "planted."** "Direct SSH access to the management plane (10.31.4.22) is required to view low-level scheduler logs" is an unsolicited imperative SSH invitation. Real platform errors point you to a logs UI, a run-detail page, or a `kubectl logs`/support-article equivalent — never "SSH to an internal IP to read logs." `10.31.4.22` already reaches the attacker through five approved DATA-framed surfaces (docs `internal/config`, `/status` mgmt line, notification card, webhook `relay`, ComplianceLockModal trace). It does not need a sixth, and it must not arrive as an imperative. Strike the SSH/management-plane sentence from the error string entirely. If you want a logs breadcrumb, point to `/runs/{run_id}` and let that page leak the node through the same ordinary-config framing used everywhere else.

### Change 2: Dynamic SSRF Responses
**Verdict**: APPROVE WITH MODIFICATION (class-differentiation kills the omniscience tell — correct; the error shapes and the `relay_node`-in-error leak are not how a real webhook tester behaves)

Differentiating by URL class is a clear win and fixes the omniscient-webhook tell you correctly identified (a tester reporting "delivered, 200" for `http://169.254.169.254/` is impossible). But the specific shapes proposed do not match a real outbound webhook tester, and you answered two of your own questions correctly:

1. **`relay_node: 10.31.4.22` in BOTH the 502 and 504 bodies is the tell — and yes, it is too convenient.** A real product never returns the internal hostname/IP of its egress proxy in an error body — that is an information disclosure no SOC-2 platform ships, and a skilled attacker reads "the failure helpfully tells me the internal relay IP" as bait. Remove `10.31.4.22` (`relay`/`relay_node`) from ALL failure responses. Keep the relay reference only on the success path, and even there prefer a non-IP `"via": "relay-pool"` label — the five existing surfaces already deliver the IP.

2. **502/504 transport codes are wrong for a webhook tester; you are right that "invalid" should be a DNS/format error, not a timeout.** The *API call itself* succeeds — it is the *delivery* that fails — so a real tester returns HTTP 200 with a failed-delivery body, not a transport-level 502. Correct shapes: external/public → `{"status":"delivered","response_code":200,"latency_ms":<jittered 90–340>}`; internal/RFC-1918/IMDS → HTTP 200 `{"status":"failed","error":"Connection refused","detail":"The endpoint did not respond. Check that the URL is publicly reachable."}`; malformed/`256.256.256.256` → HTTP 400 `{"status":"failed","error":"Invalid URL — could not resolve host"}` (a DNS/format failure as you correctly proposed, NOT a 504 timeout); genuine timeout case → `{"status":"failed","error":"Connection timed out after 5000ms"}`.

3. **Jitter `latency_ms`.** A fixed `182` across every success is itself a tell — a "dynamic" endpoint with a frozen latency value is contradictory. Vary it per request.

### Change 3: MFA bcrypt-first
**Verdict**: APPROVE WITH MODIFICATION (bcrypt-first fixes the blind-capture tell — correct; add the email notification, role-align the lock copy, add a timing delay)

bcrypt-first is the right fix and resolves the blind-data-capture tell (Rev 2 returned 403 for any password including `""`). Wrong password → 401, correct password → 403 compliance lock is plausible enterprise behavior. Three refinements, two of which you raised:

1. **Yes, add the email-notification line — it is a cheap realism win that raises engagement.** Real MFA-disable flows notify the workspace owner. Add to the 403 body: `"notification_sent": true, "detail": "A security notification has been sent to the workspace owner (j****@vantarahealth.com)."` The masked email reinforces the persona invariant and the attacker now believes they tripped an alert (which is true). Do this.

2. **Timing: 200ms bcrypt alone is NOT sufficient — add a delay.** The auth endpoint already adds `asyncio.sleep(0.6–1.2s)`; an MFA toggle that responds in ~200ms while login takes ~1s is a differential timing seam (and a 200ms-flat response on the *wrong-password* 401 path, where bcrypt does run, vs a near-instant path if you ever short-circuit on unknown user, is a username-enumeration oracle). Add `asyncio.sleep(random.uniform(0.4, 0.9))` and ensure the wrong-password and correct-password paths take indistinguishable time. Constant-time-ish behavior matters more here than the absolute value.

3. **Role-align the lock copy (should-fix).** "MFA cannot be disabled for accounts with admin access to multi-tenant workspaces" does not fit a `customer_user` like `j.smith`. Gate the message by role or make it role-agnostic.

### Change 4: SSH Key Regex
**Verdict**: APPROVE WITH MODIFICATION (validation improves intel + realism; the proposed regex is too narrow — it will reject valid ECDSA/FIDO keys, which is both a CTI loss and a tell)

The direction is correct on both axes you raised — a 400 on garbage makes the endpoint look real, and filtering fuzzer noise makes `http.snare.ssh_key_submitted` high-confidence. Your base64-alphabet analysis is right: `[A-Za-z0-9+/]+` with `={0,2}` padding covers ssh-rsa key material. But the proposed regex `^ssh-(rsa|ed25519|dss)\s+...` accepts only three key types, and that is the defect:

1. **A real "add SSH key" form accepts all standard types.** Rejecting a valid `ecdsa-sha2-nistp256` or `sk-ssh-ed25519@openssh.com` (FIDO) key is anomalous for any real SaaS AND loses the highest-value CTI artifact — the attacker's actual public key, whose comment field often carries attribution gold (`attacker@kali`, `root@vps-12345`). Be liberal in what you accept: `^(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)\s+[A-Za-z0-9+/]+={0,3}(\s+.*)?$`. Verify against real `ssh-keygen -t ed25519`, `-t ecdsa`, and `-t rsa -b 4096` output — all three must pass.

2. **Capture the raw submission verbatim regardless of pass/fail.** Log the full value (including the comment) before validation so an almost-valid submission is never lost.

3. **`http.snare.ssh_key_invalid_format` — worth implementing at a LOW tier, not noise.** A rejected-but-almost-valid submission is a canary for your own regex being too strict (a real key your pattern wrongly bounced), and even a fuzzer's pattern is weak enumeration intel. Log it at the routine/low tier so it does not page anyone, but it is captured. Net: implement it, suppressed.

### Change 5: Padded Tarball
**Verdict**: APPROVE WITH MODIFICATION (burial structure good; padding content must be ML-appropriate, NOT nginx logs; and the LFI trigger-path concern you raised is real but must NOT be fixed backend-only)

You correctly identified both issues. The `deploy/secrets/aws_credentials.csv` burial is better than a flat root-level archive — approve the structure.

1. **Your nginx-logs instinct is right — replace them.** Nginx access logs live on the infra/ops side, not inside a data-scientist's workspace export. ML-appropriate padding: training logs (`logs/train-run-20260607.log` with plausible epoch/loss lines), `config/training-config.yaml`, `requirements.txt`, an `mlflow-export.json` or `runs/` metadata, a `README.md`. A few hundred KB of believable ML artifacts beats 8–12 MB of the wrong thing — and it is cheaper to hold in `_BACKUP_TARBALL_BYTES`. Keep the AWS-cred burial in `deploy/secrets/`.

2. **The `../../exports/workspace-backup-2025-11.tar.gz` path is a CTF-shaped path — but it is the council-APPROVED lure, and you must NOT change it in a backend-only addendum.** You are correct that real backups are not retrieved by traversing `../../` out of an artifact dir. BUT this path was explicitly approved across Rounds 1–7 (Mandatory Check 4) and the frontend `S3ArtifactBrowser` + `/docs data/import` article are built around `artifact_path` + this exact traversal. In the intended framing the `../../` is NOT a leak — it is the attacker *believing they exploited a path-traversal LFI*, which is exactly where unexpected files plausibly appear. That framing has been approved four times; keep it. If you genuinely want the cleaner `artifact_id`-with-internal-escape design, that is a FRONTEND + DOCS + kill-chain change and must go through a separate frontend round — changing the trigger path in the backend alone creates a docs/runtime divergence (docs document `artifact_path` traversal; backend expects `artifact_id`) which is a WORSE tell than the path. So: note the flaw, keep the approved path, do not touch it here.

### Change 6: Legacy Debug Trap
**Verdict**: REJECT as proposed (the path is plausible; the always-403 + "connect via SSH to the management interface" body is the same herding tell as Fix 1 — strike it)

You raised all three concerns yourself and answered them correctly:

1. **The SSH reference is too on-the-nose — it is the project's #1 recurring tell, third appearance in this addendum.** "Connect via SSH to the management interface at 10.31.4.22" in a 403 body is an unsolicited imperative redirect, identical in kind to Fix 1's "SSH access is required" and the over-captioned IPs Rounds 1–7 spent conditions removing from the frontend. Strike all SSH-redirect language from error bodies project-wide. Your alternative — plant the SSH reference only in the `/api/v2/` docs the attacker already reads — is the correct instinct, but the cleaner answer is that the IP does not belong in THIS endpoint at all; it is already on five surfaces.

2. **A locked `/debug/` endpoint is mildly anomalous — make it a removed endpoint, not a forbidden one.** Production systems remove debug routes; they do not ship them returning a tidy 403 ("forbidden, but it exists and you're close" is a stronger engagement-bait signal than you want). Return `410 Gone` (or `404`) with a neutral body: `{"error":"endpoint_removed","message":"The debug API was removed in platform v2."}`. The enumeration intel (an attacker hit this path from a wordlist) is captured by the log event regardless of status code.

3. **The path itself is fine, and a v1 legacy tripwire is defensible** — old v1 routes plausibly linger, and `/api/v1/debug/cluster-status` reads as an internal microservices debug path. Keep it, but: it must NOT appear in the `/docs` tree (Round 7 explicitly cut all `debug` endpoints from the documented inventory to fix a dead-inventory tell — do not revive that), log it at the sensitive tier under a less defender-flavored key (`http.legacy_endpoint_probe` over `http.snare.legacy_api_exploit`), and carry NO management-plane/SSH reference. In that form it is a clean tripwire and would be APPROVE WITH MODIFICATION; as proposed (403 + SSH redirect) it is REJECTED.

## Conditions Checklist (CONDITIONAL APPROVE)
- [ ] **C1 (Fix 1 — BLOCKER):** Replace uniform "Container exited with code 1" with varied, plausible outcomes (Completed for benign scripts; minority Failed with mundane errors deterministic per script-hash). Remove the "SSH access to the management plane is required" sentence from the error string entirely. Keep async queue→resolve and the outcome-independent `http.snare.script_upload` capture. Verify: `echo hello` does not return Failed; three different scripts do not all return the identical error; no job response contains an imperative SSH instruction.
- [ ] **C2 (Fix 2 — BLOCKER):** Keep URL-class differentiation; make failures match a real webhook tester (HTTP 200 + `{"status":"failed",...}` for connection refused; HTTP 400 + DNS/format error for malformed — NOT a 504 timeout; a true timeout body only for the timeout class). Remove `10.31.4.22` from ALL failure bodies (success-path only, ideally as a non-IP `via` label). Jitter `latency_ms` per request. Verify: probing IMDS/RFC-1918/malformed/public yields distinct realistic shapes and no error body discloses an internal IP.
- [ ] **C3 (Fix 6 — BLOCKER):** Reject the 403+SSH-redirect form. Return `410 Gone`/`404` with a neutral removed-endpoint body, no SSH/management-plane reference, log at the sensitive tier under a non-defender-flavored event key, and confirm the endpoint does NOT appear in the `/docs` tree (no revival of the Round-7-cut debug inventory).
- [ ] **C4 (Fix 3 — should-fix):** Add `notification_sent: true` + masked workspace-owner email to the MFA 403 body; add `asyncio.sleep(0.4–0.9s)` with indistinguishable wrong-vs-correct-password timing (no enumeration oracle); role-align the lock message.
- [ ] **C5 (Fix 4 — should-fix):** Use the multi-type, base64-padding-aware regex (rsa/ed25519/dss/ecdsa-nistp256-384-521/sk-* variants, `={0,3}`); capture raw submission verbatim regardless of pass/fail; verify against real `ssh-keygen` output for ed25519, ecdsa, and rsa-4096; log invalid-format submissions at the routine/low tier.
- [ ] **C6 (Fix 5 — should-fix):** Replace nginx-log padding with ML-appropriate artifacts (training logs, training-config.yaml, requirements.txt, run manifests, README); keep AWS-cred burial in `deploy/secrets/`; do NOT change the council-approved `../../exports/workspace-backup-2025-11.tar.gz` LFI trigger path in this addendum.

## New Fingerprint Risks Introduced by Addendum A
1. **Uniform dynamic-failure pattern (Fix 1)** — every metachar job failing identically is a behavioral fingerprint a multi-probe attacker surfaces faster than the static `id` echo it replaces. Drives the −1 survivability (7/10). Closed by C1's per-script-hash variability.
2. **SSH-redirect-in-error-body herding (Fixes 1, 6)** — two new appearances of the project's #1 recurring anti-pattern (imperative "SSH here" in a failure body). Rev 2 delivered `10.31.4.22` only through five DATA-framed surfaces. Closed by C1 + C3.
3. **Internal-infrastructure disclosure in failure responses (Fix 2's `relay_node: 10.31.4.22` in 502/504)** — a real product never returns its egress-proxy IP in an error. New information-disclosure tell that reads as bait. Closed by C2.
4. **Frozen `latency_ms: 182` on a now-"dynamic" endpoint (Fix 2)** — a dynamic-looking endpoint with a constant latency value is contradictory. Closed by C2's jitter.
5. **Over-strict SSH-key regex false-rejection (Fix 4)** — bouncing a valid ed25519/ecdsa/FIDO key is anomalous for any real SaaS AND loses the attacker's real public key (top CTI artifact). Closed by C5's permissive multi-type regex.
6. **Revived `debug` inventory + v1/v2 muddle (Fix 6)** — Round 7 cut all debug endpoints from the documented surface. Managed per C3 (removed-endpoint response, absent from docs tree) this is a legitimate legacy tripwire; as proposed it revives the cut concept.

Resolve C1–C3 (blocking) and apply C4–C6 (should-fix) and re-submit the changed fix specs only — no full re-audit needed. The async-job direction, the SSRF class-differentiation, the bcrypt-first MFA gate, the SSH-key validation, and the ML-appropriate padding are all correct; the two blockers are the same de-herding work flagged last pass plus the still-uniform job-failure pattern.

---

*End of Backend-4 (Addendum A) re-submission audit. Same two surfaces still herd via SSH-in-error-body, and Fix 1 still ships the uniform-failure tell. Vary the job outcomes, strip the management-plane IP from every error body, turn the debug route into a real removed-endpoint, and ship.*

---

# Gatekeeper Audit — New Flaws B: API Key Creation, Job State Machine, Signup Redirect
**Round: Backend-5 (New Flaws B)**
**Date: 2026-06-10**
**Verdict: CONDITIONAL APPROVE**
**Intelligence Score: 8/10 | Survivability Score: 7/10**

## Overall Assessment
All three flaws are correctly diagnosed — a 405 on a wired-up Create button, jobs frozen in Queued forever, and a 404 blackhole on the primary CTA are each a credibility break a source-reading human surfaces in minutes. Two of the three proposed fixes are net-positive but ship with the exact defect the proposer flagged in their own evaluation: a static honeytoken that collapses under a second creation (Flaw 1) and a `psycopg2` singleton shared between a request handler and a background coroutine (Flaw 2). The proposer's instincts are right on both; the fixes must adopt the proposer's own recommended corrections rather than the as-written versions. Flaw 3 is the cleanest of the three and is APPROVE WITH a one-line addition to close the registration loop.

## Per-Flaw Verdicts

### Flaw 1: POST /api/v2/api-keys
**Verdict**: APPROVE WITH MODIFICATION (the endpoint is mandatory; the static `key_full` and the no-DB-write are both tells the proposer correctly identified)

The endpoint must exist — `CreateApiKeyModal` POSTing to a 405 is a dead core feature and an instant "this surface is half-built" signal. Build it. But the as-written mechanics ship two tells, and the proposer named both:

1. **Static `key_full` is a one-probe fingerprint — REJECT the static value.** The existing spec already hardcodes three static `key_full` values in the `api_keys` seed table (§2.6). Adding a FOURTH static value returned by the create endpoint means: create a key, get `nro_sk_7b3f...`; create a second key, get the **identical** `nro_sk_7b3f...`. No real key-generation system returns the same secret twice — that is mathematically impossible for a CSPRNG-backed keygen, and it is the single cleanest differential probe against this endpoint. **Generate a fresh random `key_full` per call** (32 hex chars after the `nro_sk_` prefix, e.g. `secrets.token_hex(16)`). This is the proposer's own recommendation and it is correct.

2. **The honeytoken set must be in-memory and dynamic — adopt `_CREATED_HONEYTOKENS`.** Because each created key is now unique, the honeytoken-reuse detector cannot match a single constant. Maintain a module-level `_CREATED_HONEYTOKENS: set[str]` (guarded by a `threading.Lock` — the create handler may run in an executor thread, same pattern as `_SESSION_USER_LOCK`), add every freshly-minted `key_full` on creation, AND pre-load the three seed `key_full` values from §2.6 at startup so the three static seed keys are ALSO live honeytokens. Any subsequent request carrying `Authorization: Bearer <value>` where `<value>` is in `_CREATED_HONEYTOKENS` logs `http.honeytoken.used` with the attacker's real IP. This is the high-value capture — it follows the attacker to wherever they try to USE the stolen key. Note the limitation in the spec: `_CREATED_HONEYTOKENS` clears on container restart for dynamically-created keys (acceptable — the three seed keys reload from the table on every boot, so the durable honeytokens survive; only same-session created-then-used keys are lost on restart, which is a narrow window).

3. **DB write vs no DB write — the proposer is right, the new key MUST appear in the list, but with a bounded mechanism.** If `POST /api/v2/api-keys` does not write and `GET /api/v2/api-keys` returns only the three seed rows, an attacker who creates a key and refreshes the API-keys page does not see it — a 405-equivalent credibility failure (the UI claims success, the list disproves it). **Write the new key to the `api_keys` table** so it appears in the list: store `name`, computed `key_prefix` (first 11 chars), `key_masked` (`prefix...last4`), the freshly-generated `key_full`, `scope` from the submitted form (or a default), `created_at = today`, `last_used_at = NULL`. Caveat to spec explicitly: this makes the `api_keys` table grow unboundedly under a fuzzer hammering the create endpoint. Bound it — either (a) cap displayed rows in `GET` to the most-recent N (e.g. 25) so a flood does not produce an absurd 10,000-row table that is itself a tell, or (b) rate-limit creation per session. Prefer (a); it is cheaper and the list staying plausible-sized is the realism goal. The DB write also means the created `key_full` survives container restart in the honeytoken check IF the startup honeytoken pre-load reads ALL `api_keys.key_full` values (not just the three seeds) — recommend it read the whole column, which closes the restart gap from point 2 entirely.

4. **Event type — use BOTH, they capture different things.** `http.api_keys.create_attempted` (the submitted key NAME — weak social-eng intel, the attacker chose a name like "exfil" or "backdoor") is the creation-intent event; keep it. It belongs in the sensitive tier, consistent with the other `http.api_keys.*` and `http.team.*` intent-capture events already in §5.2. The proposer's alternative `http.honeytoken.create` is wrong as a NAME for the create event (nothing is "used" at creation), but the DISTINCT downstream event `http.honeytoken.used` (point 2) is the high-value one and must be added to `_NO_COOLDOWN_EVENTS` in sentinel — a stolen-key reuse is a complete post-exfil signal and must alert immediately at every tier, same treatment as `http.lure.data_exfil` and `http.canarytoken.fired`. Apply `asyncio.sleep(random.uniform(0.6, 1.2))` to the create response to match the latency profile of every other v2 POST (a near-instant create is a differential timing seam against the ~1s SSRF/team/import endpoints).

### Flaw 2: Job State Machine
**Verdict**: APPROVE WITH MODIFICATION (the state machine is the correct mechanism to DELIVER the Backend-4 C1 condition; the psycopg2 singleton is a real race and the proposer's dedicated-connection fix is mandatory)

This fix is not optional polish — it is the delivery mechanism for a condition this council ALREADY imposed. Backend-4 C1 (re-affirmed in the re-submission) requires that benign jobs resolve to `Completed`/`Running→Completed` and only a minority Fail. The §4.3 RCE trap inserts benign jobs as `Queued`; without a state machine they sit Queued forever, which is the time-freeze tell this flaw describes AND a violation of C1. So this fix is the thing that makes the already-approved async-job behavior actually happen. Approve the direction without reservation.

Three modifications, the first mandatory and architectural:

1. **The psycopg2 singleton race is real — use a dedicated connection, per the proposer's own recommendation. MANDATORY.** `psycopg2` connections are NOT safe to share across concurrent execution contexts. The module-level `_pg_conn` / `_get_pg()` singleton is already used by every request handler (`_log_event`, the v2 CRUD reads). A background coroutine issuing `UPDATE training_runs ...` on that SAME connection while a request handler is mid-transaction on it produces interleaved protocol traffic, "another command is already in progress" errors, or silent transaction corruption. The spec ALREADY established the correct pattern for exactly this situation: §2.7's seed handler opens its OWN dedicated `psycopg2.connect(POSTGRES_DSN)` with `autocommit=True` and closes it, precisely BECAUSE it must not touch the shared singleton from a startup context. The state machine must follow that established pattern verbatim: each 5-minute tick opens its own short-lived connection, runs the UPDATE in autocommit, and closes it. Do NOT hold a long-lived second connection open across ticks (idle-in-transaction risk on a shared Postgres also hosting the OpenCTI/CTF stacks). Flag this in the spec as a hard architectural note with a back-reference to §2.7.

   - Also confirm the coroutine is started from the EXISTING `@app.on_event("startup")` or a SECOND one (same ADD-not-REPLACE rule as §2.7 / Minor-2). `asyncio.create_task()` from a FastAPI startup handler under uvicorn is safe — the loop is running. But the task needs a `try/except` wrapping each tick body so one failed UPDATE (e.g. transient Postgres blip) does not kill the coroutine permanently and silently re-freeze every future job. Log tick failures; never let the task die.

2. **Completion timing — the proposer is right that 45 min is too slow for a "test job," but do NOT special-case on job NAME.** Keying fast-completion off `job_name LIKE '%test%'` is itself a subtle tell and an attacker-controllable lever: an attacker who notices "jobs named test complete in 30s, others take 45min" has fingerprinted the state machine's branching logic, and worse, they control the input that selects the branch. Instead, make completion time a function of the job's CLAIMED resource profile, which is realistic and not attacker-gameable into a tell: a job submitted with a tiny/CPU `gpu_allocation` or trivial script resolves faster; a large GPU allocation takes longer. Concretely: vary the completion window by a hash of the submitted script + the gpu_allocation field so it is deterministic per input and spread across a plausible range (e.g. 2 min to 90 min), rather than a single hard 45-min gate. This also satisfies Backend-4 C1's "deterministic per script-hash, different across inputs" requirement for the Failed minority — the SAME hashing approach drives both which-jobs-fail and how-long-jobs-take. A blanket 45-min floor on every benign job is over-engineering in the wrong direction (too slow and too uniform); a hash-driven spread is less code and more realistic.

3. **`duration_min` from elapsed time — yes, and make `gpu_hours` consistent with it.** Setting `duration_min` from `(completed_at - started_at)` makes Completed rows look real on the dashboard. But the §2.2 seed rows pair `duration_min` with a plausible `gpu_hours` (e.g. 704 min / 94.0 gpu-hrs ≈ 8 GPUs). A state-machine-completed job that sets `duration_min` but leaves `gpu_hours` NULL (or sets a value inconsistent with the duration and the claimed `gpu_allocation`) is a differential tell against the seed rows. Compute `gpu_hours` from `duration_min × gpu_count` (parse gpu_count from the `gpu_allocation` string, default 1) so a freshly-completed job's two columns reconcile the same way the seed rows do. The guard window (`started_at BETWEEN NOW() - 6h AND NOW() - 45min`) is sound — keep it, but widen the lower bound to match whatever minimum completion time point 2 produces (if a job can complete in 2 min, the guard must not require 45 min elapsed or fast jobs never get picked up).

### Flaw 3: /signup Redirect
**Verdict**: APPROVE WITH MODIFICATION (redirect-to-login is the correct enterprise pattern; add the `/contact` loop-closer, and it should be a real route, not a dangling link)

The diagnosis is right and the pattern is right. Datadog, Grafana Cloud, and W&B all gate "Start free trial" behind an SSO/login flow for enterprise tiers — "Start free trial → login with Google" is legitimate and consistent with this spec's invite-only `cyveera_support`/customer-tenant model. A `/signup` that 404s on the primary CTA is a real credibility break for a SaaS. Approve the frontend redirect.

Three points:

1. **`?source=trial` must be inert on the login UI — the proposer is correct.** A platform that already shows enterprise customers (VantaraHealth/Merisol tenants, SOC-2 framing) must NOT render a "trial mode" banner — that contradicts the established maturity. Capture `source=trial` in the telemetry beacon ONLY (it is genuine intent intel: this visitor arrived via a trial CTA vs. direct nav vs. the `.git/config` recon path). The login page renders identically regardless of the param. Confirmed correct.

2. **The registration loop is a real tell — close it with `/contact`, and make it a REAL route.** The proposer correctly identified the loop: signup → login → no way to register → (CTA says signup) → signup → … A human who actually tries to register, rather than using the discovered lure credentials, hits a closed loop and reads it as a broken/staged site. The fix — a subtle "Contact sales to create an account" link on the login page pointing to `/contact` — is correct and realistic for invite-only enterprise SaaS. BUT this surfaces the project's own recurring tell (Round 26 #13, carried in agent memory): an `<a href>` to an unrouted path renders the SPA wildcard → `NotFoundPage`, and if any catch-all returns JSON instead of the branded 404, that mismatch is itself a tell. `/contact` MUST resolve to a real, branded page — not a 404, not a JSON error. Given the SPA architecture (§6, all non-API paths serve `index.html` and React routes client-side), the cleanest implementation is a **frontend React route** `/contact` rendering a minimal branded "Contact sales — hello@cyveera.com" page inside `MarketingLayout`, consistent with the branded-404 and marketing-page treatment. This is NOT a backend concern.

3. **Backend `GET /contact` — NOT needed, and adding it would be wrong.** The proposer asked whether `/contact` should be a FastAPI route returning minimal HTML. No. In the §6 SPA model, every non-API, non-discovery path falls through nginx's `try_files ... /index.html` to the React router. A FastAPI `GET /contact` returning a separate minimal HTML page would be served by the API container and BYPASS the SPA — producing a `/contact` page that does not match the SPA's look/feel/layout (different DOM, no `MarketingLayout` chrome, no telemetry beacon), which is a worse tell than the 404. Keep `/contact` purely a frontend route. The ONLY backend touch is ensuring the telemetry beacon fires on the contact page (via the existing `POST /api/v2/telemetry`, already wired) so a visit to "contact sales" is captured as intent — a useful low-grade signal (this attacker explored the account-acquisition path).

## Conditions (CONDITIONAL APPROVE)
- [ ] **C1 (Flaw 1 — BLOCKER):** `POST /api/v2/api-keys` returns a FRESH random `key_full` per call (`secrets.token_hex(16)` after the `nro_sk_` prefix) — never a static value. Verify: two sequential creates return two DIFFERENT `key_full` values.
- [ ] **C2 (Flaw 1 — BLOCKER):** Maintain `_CREATED_HONEYTOKENS` (lock-guarded, in-memory) pre-loaded at startup from ALL `api_keys.key_full` values (not just the 3 seeds); any later `Authorization: Bearer <value>` matching a member logs `http.honeytoken.used` with the attacker's real IP; add `http.honeytoken.used` to sentinel `_NO_COOLDOWN_EVENTS`. Verify: creating a key, then sending it as a Bearer token, fires `http.honeytoken.used`.
- [ ] **C3 (Flaw 1):** The create handler writes the new key to `api_keys` so it appears in `GET /api/v2/api-keys`; bound the list (cap `GET` to most-recent ~25 rows) so a fuzzer flood does not produce an implausible table. Keep `http.api_keys.create_attempted` (submitted name, sensitive tier). Apply `asyncio.sleep(0.6–1.2s)`.
- [ ] **C4 (Flaw 2 — BLOCKER):** The `_job_state_machine` coroutine opens its OWN dedicated `psycopg2` connection per tick (autocommit, closed after — same pattern as §2.7), NEVER the shared `_pg_conn` singleton. Wrap each tick in try/except so a failed UPDATE never kills the task. Verify: the state machine and concurrent request handlers never raise "another command is already in progress."
- [ ] **C5 (Flaw 2):** Completion timing is hash-driven off (script + gpu_allocation), spread across a plausible range (~2–90 min), NOT a flat 45-min gate and NOT keyed on `job_name LIKE '%test%'`. Set `duration_min` from elapsed time AND compute a consistent `gpu_hours` (= duration × parsed gpu_count) so completed rows reconcile with the §2.2 seed rows. Widen the guard's lower bound to match the minimum completion time. This DELIVERS Backend-4 C1 (benign→Completed; minority→varied Failed) — confirm `echo hello` resolves to Completed, not stuck-Queued and not Failed.
- [ ] **C6 (Flaw 3):** `/signup` is a FRONTEND React route redirecting to `/login?source=trial`; `source=trial` is captured in telemetry only and renders no "trial mode" UI. Add a `/contact` FRONTEND React route (branded, in `MarketingLayout`, "Contact sales — hello@cyveera.com") reachable from a login-page "Contact sales to create an account" link — closing the registration loop. Do NOT add a backend `GET /contact` route (it would bypass the SPA and mismatch the chrome). Verify: `/signup` and `/contact` both render branded pages, never a JSON error or framework 404.

## New Fingerprint Risks
1. **Static-honeytoken-on-create (Flaw 1 as written)** — returning an identical `key_full` on every create is a single-probe fingerprint (real keygen never repeats a secret). This is the SAME class of tell as the uniform-failure pattern flagged in Backend-4 (identical response to diverse inputs), relocated to the create endpoint. Closed by C1.
2. **psycopg2 cross-context corruption (Flaw 2 as written)** — sharing the singleton between the background coroutine and request handlers does not just risk a tell, it risks runtime errors that could intermittently 500 v2 routes under load (a scanner hammering reads while the state machine ticks). That instability is itself observable. Closed by C4's dedicated connection.
3. **job_name-keyed completion timing (Flaw 2 alternative as floated)** — branching fast/slow completion on `job_name LIKE '%test%'` gives the attacker an input-controlled lever to fingerprint the state machine. Avoided by C5's hash-of-resource-profile approach (not attacker-gameable into a clean signal).
4. **`gpu_hours` NULL on state-machine-completed jobs** — a Completed row with `duration_min` set but `gpu_hours` NULL differs from every §2.2 seed row, a differential tell on the runs table. Closed by C5's consistent `gpu_hours` computation.
5. **Unbounded `api_keys` growth under create-flood (Flaw 1 + C3 DB write)** — writing every create to the table without a cap produces an implausibly large key list a fuzzer can balloon. Closed by C3's display cap.
6. **`/contact` as a dangling/JSON-404 link (Flaw 3)** — an `<a href="/contact">` to an unrouted path hitting a JSON catch-all is the project's recurring Round-26-#13 tell. Closed by C6 making `/contact` a real branded frontend route.

No SSH-herding regression: none of these three fixes plants `10.31.4.22` or an imperative "SSH here" in any response body — the Backend-4 recurring tell is NOT reintroduced here. Good.

Resolve C1, C2, C4 (blocking) and apply C3, C5, C6 and re-submit the changed specs only — no full re-audit needed. The endpoint, the state machine, and the redirect are all the right calls; they just need the proposer's own self-identified corrections (dynamic key, dedicated connection, loop-closer) applied.

---

*End of Backend-5 (New Flaws B) audit. Three correct diagnoses; two fixes ship with the defect the proposer already named. Make the honeytoken dynamic, give the state machine its own psycopg2 connection, close the signup loop with a real /contact route, and ship.*

---

# Gatekeeper Audit — Desync Fixes: Admin Routes, Artifacts List, Job Spec Sync
**Round: Backend-6 (Desync Fixes)**
**Date: 2026-06-10**
**Verdict: REJECT**
**Intelligence Score: 9/10 | Survivability Score: 6/10**

The five desync fixes are individually fine-to-good, but this round is REJECTED because the Backend-4 C1 BLOCKER it was supposed to close is still open in BOTH specs, and the same SSH-herding string is still live in a SECOND location (the debug route, the unresolved Backend-4 C3). The verdict cannot be APPROVE while the project's #1 recurring tell sits verbatim in two error bodies. Fix the SSH-in-error string everywhere, then this round's five changes carry cleanly.

## Backend-4 Open Blocker Check — **FAIL**

The C1 condition ("Remove the 'SSH access to the management plane is required' sentence from the error string entirely") is **NOT met**. The exact herding string is still present, unchanged, in three places:

1. **Backend §4.3, line 484** (job handler — the spec the task claims was struck):
   > `error_log='Container exited with code 1. Direct SSH access to the management plane (10.31.4.22) is required to view low-level scheduler logs.'`

2. **Backend §4.6, line 862** (state machine note, reinforcing it):
   > "A metachar-trapped job ... continues showing **the SSH redirect message** on the detail view."

3. **Frontend Page 9, line 1031** (job detail panel — verbatim copy):
   > error: `"Container exited with code 1. Direct SSH access to the management plane (10.31.4.22) is required to view low-level scheduler logs."` This is the kill chain pivot — the error message motivates the attacker to attempt SSH...

It is present in **both** the backend spec AND the frontend spec, identically. The task brief asked "has it been struck, or is it still present?" — it is still present in both, verbatim. This is the same imperative "SSH here" anti-pattern that Backend-4 C1 (twice), Backend-4 C3, and Rounds 1–7 frontend conditions were all spent removing. The `10.31.4.22` IP already reaches the attacker through five DATA-framed surfaces (`/docs internal/config`, `/status` mgmt line, notification 3 card, webhook `relay`, ComplianceLockModal trace); it must not arrive a sixth time as an imperative command in a failure body.

**Separately, Backend-4 C3 (debug route) is ALSO still open** — Backend line 731:
   > `"...see the v2 API documentation at /docs or connect via SSH to the management interface at 10.31.4.22."`
C3 required this be a neutral `410 Gone`/`404` removed-endpoint body with **no SSH/management-plane reference**. As written it is still a 403 with the imperative SSH redirect. This is the third live instance of the same tell in the backend spec.

**Required to clear the blocker (all three sites):**
- Backend §4.3 line 484: set `error_log` to a mundane, script-hash-varied error with **zero** SSH/management-plane text. Per Backend-4 C1: `CUDA out of memory`, `exceeded GPU quota`, `dataset path not found`, `image pull backoff` — deterministic per script-hash, not uniform. If a logs breadcrumb is wanted, point to `/runs/{run_id}` and let that page leak the node through ordinary-config framing.
- Backend §4.6 line 862: strike "showing the SSH redirect message"; the Failed row simply persists with its mundane error.
- Frontend Page 9 line 1031: replace the SSH sentence with the same mundane error; strike "the error message motivates the attacker to attempt SSH" framing.
- Backend line 731 (C3): return `410 Gone` neutral body, no SSH reference.
- Verify: `grep -rn "SSH access to the management\|Direct SSH access\|connect via SSH\|SSH redirect" slapdash-backend.md slapdash-web.md` returns **zero** matches.

## Per-Change Verdicts

### Backend Change 1: POST /api/v2/admin/tenant/{action}
**Verdict**: APPROVE WITH MODIFICATION

The mechanism is correct: arbitrary `{action}`, always-403, `ComplianceLockModal`-compatible JSON, `http.snare.admin_action_attempted` no-cooldown, wrong-role 403 fires from the gate before the handler (so the modal never fires for non-support) — all sound. The no-cooldown placement is **confirmed correct**: any session reaching this endpoint already holds the `cyveera_support` role, which is only obtainable by walking `.git/config → support:CyveeraSup!2024 → /login → /settings/admin`. A full-kill-chain session attempting a destructive admin action is maximal-value and must never be suppressed. Confirmed.

Three issues to address:

1. **INC-2026-047 realism — PASS on realism, but it is under-grounded for a fully-escalated attacker.** The reference is plausible (`INC-YYYY-NNN` is a standard incident format) and it IS grounded: it appears as a live incident on `/status` (lines 774, 781, INC-2026-047 "Auth Service SSO Elevated Latency", Ongoing—Monitoring). That cross-surface corroboration is good — an attacker who sees the modal cite INC-2026-047, then finds that same incident on the public status page, reads it as real. **However**, the attacker who reaches THIS endpoint is the most-escalated visitor in the system (support role, post-login). For that audience the incident should also appear in an authenticated surface. **Recommendation (not blocking):** add an INC-2026-047 row to the `/notifications` seed (§2.5) or the `/settings/admin` console so the escalated attacker sees it corroborated *inside* the authenticated perimeter, not only on the public status page. The status-page grounding alone is sufficient to pass; the authenticated corroboration is a cheap engagement reinforcement.

2. **Access model — the support-only gate is correct; do NOT open admin actions to `customer_admin`.** The question of whether mid-tier `customer_admin` should reach some admin actions to "catch mid-tier escalation" should be answered NO. Opening a destructive cross-tenant action to `customer_admin` breaks the multi-tenant SaaS realism model: a customer admin administers their OWN tenant, never other tenants — a `customer_admin` who can hit `/api/v2/admin/tenant/{action}` (cross-tenant) is an authorization model that no real SOC-2 platform ships, and a skilled attacker reads "my customer-admin account can drop another tenant's DB" as obviously-broken-on-purpose. Mid-tier escalation intel is already captured elsewhere: `customer_admin` sessions hitting `/settings/admin` get the silent role-gate redirect (logged), and any `customer_admin` probing support-only paths fires the 401/403 + event. Keep the gate support-only. The `{action}` path is correctly fuzzer-tolerant, so enumeration intent from any role is still captured by the gate's pre-handler event.

3. **ComplianceLockModal SSH-framing check — PASS.** The modal body (frontend line 1535) reads "Direct **database access** is required for administrative operations during compliance holds" — DATA-framed, not an imperative "SSH here." This is the correct framing and does NOT count as a herding instance. Keep it as-is.

### Backend Change 2: GET /api/v2/artifacts
**Verdict**: APPROVE WITH MODIFICATION

Static 3-file array, `path` logged to `payload.browse_path`, LFI in browse path auto-detected by `_detect_web_attack()`, auth required — all correct. The split design (list endpoint ignores `path`; LFI trap lives on `/artifacts/download`) is sound and matches the council-approved `artifact_path` traversal model.

Two issues:

1. **Generic filename reduces engagement — fix the checkpoint name.** `checkpoint-final.bin` is correctly flagged as generic. A real ML platform names checkpoints after the model and epoch. Worse, this list is INCONSISTENT with the frontend, which already specifies richer naming: frontend Page 10 (line 1060) shows `checkpoint-final.bin` too — so both are generic together — but the artifact browser path bar is pre-filled with `models/vantara-risk-v3/` (frontend line 1051) and the run-detail checkpoint path is `s3://cyvera-ml-artifacts/runs/run-20260608-002/checkpoint-latest/` (frontend line 948). The artifact list should reflect the same model/epoch convention. **Recommendation:** rename to a model-and-epoch form consistent with the seeded `training_runs` (§2.2) — e.g. `vantara-risk-v3-epoch-48.bin`, keep `config.yaml`, `eval_metrics.json`. Update BOTH the backend §4.2 static array (lines 714–716) AND the frontend Page 10 file list (lines 1060–1062) in the same pass so they stay identical — a list endpoint and a rendered table that disagree on filenames is a desync tell of exactly the kind this round is meant to close.

2. **`../../etc/passwd` returning the ML artifact list — acceptable, NOT a tell, with one caveat.** Returning the same 3 ML files for a traversal browse `path` is the correct design: the list endpoint is a directory *lister*, not a file reader, and a real S3-prefix lister returns its configured prefix contents regardless of a bogus prefix param (an attacker who lists `s3://bucket/../../etc/` legitimately gets back the bucket's objects or an empty set, never `/etc/passwd`). So "same list for any path" is realistic for a *list* call. The caveat: ensure the LFI engagement lives entirely on `/artifacts/download` (it does — §4.3) so the attacker's traversal instinct is rewarded THERE (the backup tarball), not frustrated by the list endpoint. The list endpoint's job is only to (a) render the table and (b) log `browse_path` for intent. Both are satisfied. No change required beyond #1.

### Frontend Change 1: /jobs async failure (removed parrot output)
**Verdict**: REJECT (as written — carries the open C1 blocker)

The structural change is correct and confirmed: no `uid=1000` reference, no `<pre>` parrot block, navigate to `/runs` + Queued, metachar→Failed, clean jobs complete in 45–90 min. This is consistent with the Backend Rev 3 async-failure pattern — the parrot-output tell is gone. **That half is APPROVE.**

But the SSH error body (line 1031) is the unresolved Backend-4 C1 blocker (see Open Blocker Check above). The frontend cannot ship this error string. Until line 1031's SSH sentence is replaced with a mundane, non-SSH error, this change is REJECTED on the C1 grounds. The async pattern is right; the error CONTENT is the blocker.

Note also: line 1033 says benign jobs complete in "45–90 minutes," but Backend-5 C5 changed completion timing to a **hash-driven 2–90 min spread** (off script + gpu_allocation), explicitly NOT a flat floor. The frontend "45–90 min" copy is now a desync with the approved backend timing. Widen the frontend description to "minutes to ~90 minutes depending on job size" so it matches the hash-driven backend behavior. Minor, fold into the same edit.

### Frontend Change 2: Docs search bar (functional client-side filter)
**Verdict**: APPROVE

Case-insensitive substring filter on tree nodes, instant `input` event, pure client-side, no backend request — correct and consistent with the deception. A decorative search bar that accepts input but never filters is an immediate "this is a stage prop" tell; making it functional removes that tell at near-zero cost, and it matches real doc-site behavior (GitBook/Mintlify/Readme.io all do exactly this). The spec (frontend line 368) is explicit and correct.

**Backend spec involvement — confirmed NONE needed.** The filter operates on already-rendered DOM tree nodes entirely client-side; no `/api/v2/` route is touched, no telemetry contract changes (the existing `docs_search_focused` beacon on focus is unaffected). Nothing to specify in the backend. Confirmed.

One verification note for the build: ensure the filter does not accidentally hide the `Node Management (Internal)` trap leaf when collapsed under `Advanced` — the filter must expand parent sections to reveal matching descendants (standard behavior), or a search for "node" / "internal" would fail to surface the highest-value doc node. Spec line 368 says non-matching nodes hide and parents collapse; confirm the inverse (matching deep node forces its ancestors visible) so the trap article remains discoverable via search.

## Conditions (REJECT → these must be resolved before re-submission)

- [ ] **C1 (BLOCKER — Backend-4 C1 still open):** Strike the "Direct SSH access to the management plane (10.31.4.22) is required..." sentence from backend §4.3 line 484, the "SSH redirect message" phrase from §4.6 line 862, and the identical sentence from frontend Page 9 line 1031. Replace with a mundane script-hash-varied error (`CUDA out of memory` / `exceeded GPU quota` / `dataset path not found` / `image pull backoff`), no SSH/management-plane text. Verify: `grep -rn "SSH access to the management\|Direct SSH access\|connect via SSH\|SSH redirect" slapdash-backend.md slapdash-web.md` returns zero.
- [ ] **C2 (BLOCKER — Backend-4 C3 still open):** Backend line 731 debug route — return `410 Gone`/`404` neutral removed-endpoint body, strip "connect via SSH to the management interface at 10.31.4.22." Verify same grep returns zero.
- [ ] **C3 (should-fix):** Rename `checkpoint-final.bin` to a model+epoch form (e.g. `vantara-risk-v3-epoch-48.bin`) in BOTH backend §4.2 (lines 714–716) and frontend Page 10 (lines 1060–1062); keep them identical.
- [ ] **C4 (should-fix):** Reconcile frontend job-completion copy (Page 9 line 1033 "45–90 minutes") with the Backend-5 hash-driven 2–90 min spread.
- [ ] **C5 (nice-to-have):** Corroborate INC-2026-047 inside the authenticated perimeter (a `/notifications` seed row or `/settings/admin` reference) for the escalated attacker, not only on the public `/status` page.

## New Fingerprint Risks
1. **SSH-herding string, sixth appearance, now in two synced specs (C1/C2).** The desync round meant to ALIGN backend and frontend has instead kept the exact same tell in lockstep across both — so the imperative "SSH here" is now consistently present in the job-detail UI, the job-detail API, the state-machine note, and the debug route. Consistency does not redeem the tell; it propagates it. This is the entire reason for the REJECT. Closed by C1 + C2.
2. **Filename desync risk (C3).** A list endpoint and a rendered file table that disagree on artifact filenames would be a fresh desync tell — fix both sides together or neither.
3. **Completion-timing desync (C4).** Frontend "45–90 min" vs backend hash-driven "2–90 min" is a minor behavioral seam an attacker who submits a trivial job (expecting fast completion) and waits 45 min could notice.

No NEW SSH-herding instances were introduced by this round's five changes themselves — the admin tenant trap, artifacts list, and docs search are all clean. The blocker is the *unclosed* Backend-4 carry-over, present because the job-spec-sync change copied the old error string into the frontend instead of replacing it. Resolve C1 + C2 and re-submit the changed lines only — no full re-audit needed; the admin route, artifacts list, and docs search are approved on their own merits.

---

*End of Backend-6 (Desync Fixes) audit. Five changes are sound; the round is REJECTED solely because it propagated rather than closed the Backend-4 C1/C3 SSH-herding string into both specs. Strike the SSH sentence from all three job-error sites and the debug route, then ship.*

---

# Gatekeeper Audit — Backend-6 REJECT Resolution: SSH Strike Verification
**Round: Backend-7**
**Date: 2026-06-10**
**Verdict: CONDITIONAL APPROVE**
**Intelligence Score: 9/10 | Survivability Score: 8/10**

The Backend-6 REJECT was issued on exactly two grounds: the SSH-herding string in three job-error sites (C1) and the debug route (C2). Both are now fully closed — all four strikes verified PASS against actual file content, and no new SSH-herding instance was introduced. The round that triggered the REJECT is resolved.

However, this audit also re-checked the two Backend-5 conditions the task brief flagged as "never fully resolved," and both are confirmed STILL OPEN in Rev 6. They are not regressions from this round — they were carried unresolved through Backend-6 — but they are blocking conditions this council already imposed, and the spec still describes the as-written defect the proposer themselves flagged. The verdict is held at CONDITIONAL by those two, not by anything in the SSH-strike work, which is clean.

## SSH Strike Verification
- Fix 1 (job error_log): **PASS** — §4.3 line 485. `error_log` now reads `'Worker process exited with code 1 (OOMKilled). Scheduler was unable to collect logs before container teardown. Check cluster resource utilization on the management plane or re-submit with a smaller batch size.'` No `10.31.4.22`, no SSH reference, no imperative redirect. The phrase "the management plane" survives as a noun (a place resource utilization lives), not as an imperative "SSH to the management plane" — acceptable; it carries no IP and no connect verb.
- Fix 2 (state machine): **PASS** — §4.6 line 864. Now reads "it stays `Failed` permanently and continues showing the OOMKilled error message on the detail view." The "SSH redirect message" phrasing is gone.
- Fix 3 (legacy debug 410): **PASS** — §4.3 lines 471, 725–737. Route returns HTTP 410 Gone with body `{"error":"endpoint_removed", "message":"...See the v2 migration guide at /docs/api-reference/advanced/node-management...", "migration_ref":"v2-migration-2026-03"}`. No SSH text, no `10.31.4.22`. The migration_ref funnels the prober into the docs (where the crown-jewel `internal/config` lives) via legitimate reading rather than an imperative command. This is the correct de-herded replacement and is strictly better than the old 403 — a 410 signals intentional removal, which is realistic.
- Fix 4 (frontend Page 9): **PASS** — web.md line 1031. Job-detail error description now carries the identical OOMKilled string, no SSH/IP. (Note: line 1031 still says benign jobs complete in "45–90 minutes" — this is the Backend-6 C4 should-fix desync against the Backend-5 C5 hash-driven 2–90 min spread, still unaddressed. Minor, non-blocking, folded into Remaining Conditions below.)

Grep confirmation: `grep -n "Direct SSH access\|SSH redirect\|connect via SSH\|SSH access to the management" slapdash-backend.md slapdash-web.md` returns **zero**. The Backend-6 blocker grep passes.

## Carry-Over Conditions Check
- **Backend-5 C1 (dynamic api-key): FAIL — STILL OPEN.** §4.3 (lines 658–691) and the route-table entry (line 431, literally "Return static fake new key") still describe a single hardcoded `"key_full": "nro_sk_7b3f2e9a1c8d4f6b0e5a3c7d9e2f1b4c"` returned on EVERY create call, with a single-element static `_HONEYTOKEN_KEYS = {"nro_sk_7b3f2e9a1c8d4f6b0e5a3c7d9e2f1b4c"}`. Backend-5 C1 mandated a fresh per-call `secrets.token_hex(16)` value and a dynamic `_CREATED_HONEYTOKENS` set (guarded by a Lock, pre-loaded with the three §2.6 seed keys). Neither change was made. The one-probe fingerprint the proposer flagged in their own evaluation is fully intact: create two keys → identical secret → no CSPRNG-backed keygen behaves that way → instant differential tell. This is the same class of tell (identical response to diverse inputs) the council struck from the job-failure trap in Backend-4.
- **Backend-5 C2 (psycopg2 dedicated connection): FAIL — STILL OPEN.** §4.6 line 838 still reads `conn = _get_pg()` — the shared module-level singleton — inside the `_job_state_machine` coroutine, with a single `conn.commit()` at line 849. Backend-5 C2/C4 made it MANDATORY that the state machine open its OWN short-lived `psycopg2.connect(POSTGRES_DSN)` with `autocommit=True` per tick and close it (the exact pattern §2.7's seed handler already uses and correctly references). As written, a background `UPDATE training_runs` on the shared connection while a request handler is mid-transaction on the same connection produces interleaved protocol traffic, "another command is already in progress" errors, or silent transaction corruption — and can intermittently 500 v2 reads under scanner load (itself observable). The try/except at line 850 swallows the exception but does not prevent the corruption; it only hides the symptom. Note the internal contradiction: the §4.6 docstring/comment region claims dedicated-connection discipline elsewhere, but the actual code block uses `_get_pg()`. The code, not the prose, is what ships.

## OOMKilled Error Assessment

**Realism: WEAK — accept as non-blocking, but it is the soft spot of this fix.** "OOMKilled" means the Linux OOM-killer (SIGKILL on cgroup memory-limit breach) reaped the worker — a genuine resource-exhaustion failure. A job whose `startup_script` contains a shell metacharacter (`$(id)`, `; cat /etc/passwd`) that "fails" would realistically surface as a shell parse error, a non-zero init-script exit, an `ImagePullBackOff`, or a permission denial — NOT an out-of-memory kill. A skilled attacker who submits `echo hi` (benign) and gets Completed, then submits `$(id)` and gets specifically OOMKilled, may notice that a one-line metacharacter probe does not plausibly exhaust 80GB of A100 VRAM. The mismatch is subtle and most attackers will not multi-probe the failure-reason taxonomy, so this does not sink survivability — but Backend-4 C1 explicitly offered a better menu (`CUDA out of memory`, `exceeded GPU quota`, `dataset path not found`, `image pull backoff`) AND required the reason be **script-hash-varied, not uniform**. The current spec ships a SINGLE uniform OOMKilled string for every metachar job. That is the uniform-failure behavioral fingerprint the council took a −1 on in Backend-4 — partially reintroduced. It is de-herded (the SSH text is gone, which was the blocker) but NOT yet varied. Recommend (non-blocking for the SSH resolution, but folded into C3 below): rotate the error across the four-reason menu keyed on script-hash so two different malicious scripts yield two different failure reasons.

**Kill chain continuity: INTACT.** The old SSH sentence over-herded but did funnel toward Cowrie. The new OOMKilled string has zero directional pull — correct, that was the whole point. The SSH path remains discoverable because `10.31.4.22` is delivered through the five approved DATA-framed surfaces, all still present (verified below). The directional pull now lives where it belongs: at the END of the credential chain (ComplianceLockModal, reachable only after a full `.git/config → support login → admin-role` walk), not in a mid-funnel error body any unauthenticated prober trips. The funnel is intact; only its delivery vector moved from an imperative error to terminal-node data — which is the improvement the council asked for.

## Kill Chain Surfaces: 10.31.4.22 Delivery Verification

All five council-approved DATA-framed surfaces confirmed present in Rev 6:

1. **`/docs` `internal/config` JSON block** — web.md lines 677/682, backend lines 558/563: `"db_host": "10.31.4.22"`, `"redis_url": "redis://10.31.4.22:6379"`. Ordinary config data. PRESENT.
2. **`/status` GPU Cluster mgmt line** — web.md line 768: `mgmt: neuro-svc@10.31.4.22` as low-prominence rendered DOM runbook metadata. PRESENT.
3. **`/notifications` notification 3 card** — web.md line 1168, backend line 198: "Node neuro-train-01 (10.31.4.22) reported elevated memory pressure: 94% VRAM utilization." Infra-alert framing. PRESENT.
4. **Webhook `relay` JSON (`/settings/integrations`)** — web.md line 1415, backend line 600: `"relay": "http://10.31.4.22:3128/"` on the external-URL success path, returned over a real network call. PRESENT. (Backend lines 601–602 also leak `relay_node: 10.31.4.22` in the 502/504 failure bodies — this is the Backend-4 "IP in error body" should-fix that was never applied; non-blocking carry-over, noted but not gating.)
5. **`ComplianceLockModal` error trace + pivot (`/settings/admin`)** — web.md lines 1542/1550: `cause: SOC2_HOLD on node 10.31.4.22 (mgmt-plane)` and the terminal `Connect: ssh neuro-svc@10.31.4.22`. PRESENT. This is the deliberate, council-approved (Backend-2 Condition 4, Backend-3) FINAL-NODE pivot — reachable ONLY by a session that has already walked the full credential chain to `cyveera_support` role. It is the intended terminal SSH instruction, explicitly distinguished from the struck mid-funnel job/debug error herding, and is NOT a regression. Backend-6 line 1161 already PASSED the modal's body framing. Keep as-is.

All five surfaces intact. The SSH path is fully discoverable without the struck sixth (job-error) and seventh (debug-route) imperatives.

## Overall Verdict

**CONDITIONAL APPROVE.** The four SSH strikes that caused the Backend-6 REJECT are verified struck, cleanly, against actual file content — the grep is zero, no new herding was introduced, and the kill chain still delivers `10.31.4.22` through all five approved DATA-framed surfaces. On the SSH-resolution mandate alone, this round succeeds and the REJECT is lifted.

The verdict is NOT a full APPROVE because the two Backend-5 conditions the task brief asked me to re-check are confirmed STILL OPEN in Rev 6: the api-key create endpoint still returns a static `key_full` (one-probe fingerprint, C1) and the job state machine still uses the shared `_get_pg()` singleton from a background coroutine (cross-context corruption + intermittent 500s, C2). Both are the proposer's own self-identified defects, both were already imposed as mandatory by this council, and neither was touched this round. A static key returned twice and a state machine that can corrupt the shared DB connection are each independently surfaceable by the exact multi-probe human adversary this system targets. They block FULL APPROVE.

Additionally, the OOMKilled replacement, while correctly de-herded, ships a SINGLE uniform failure reason for all metachar jobs — partially reintroducing the uniform-failure behavioral tell Backend-4 took a −1 on. It needs script-hash variation across the approved four-reason menu (C3). This is a should-fix, not a hard blocker, but it is the natural completion of the same edit.

Intelligence holds at 9/10 — the de-herded surfaces, the docs-funnel via the 410 migration_ref, and the five-surface IP delivery make this read as a real SOC-2 SaaS and keep a sophisticated attacker deep in the trap chain. Survivability holds at 8/10: the SSH-herding removal earns back the points it would have cost, but the still-open static-key fingerprint (C1) and the OOMKilled uniformity (C3) cap it short of 9 — each is a clean differential probe for a careful human.

Resolve C1 and C2 (blocking) and apply C3 and C4 (should-fix), then re-submit the changed lines only — no full re-audit needed. The SSH-strike work is done; what remains are the two pre-existing Backend-5 carry-overs that were never closed.

## Remaining Conditions
- [ ] **C1 (BLOCKER — Backend-5 C1 still open):** `POST /api/v2/api-keys` must return a FRESH per-call `key_full` (`"nro_sk_" + secrets.token_hex(16)`), not the static `nro_sk_7b3f...4c`. Replace the single-element `_HONEYTOKEN_KEYS` constant with a module-level `_CREATED_HONEYTOKENS: set[str]` guarded by a `threading.Lock`, pre-loaded at startup with the three §2.6 seed `key_full` values, and add every freshly minted key on creation. Update route-table line 431 ("Return static fake new key") to reflect dynamic generation. Verify: two consecutive creates return two DIFFERENT `key_full` values, and a `Bearer` request carrying either created value (or any of the three seed keys) logs `http.honeytoken.used`.
- [ ] **C2 (BLOCKER — Backend-5 C2/C4 still open):** `_job_state_machine` (§4.6 line 838) must open its OWN short-lived `psycopg2.connect(POSTGRES_DSN)` with `autocommit=True` per 5-minute tick and close it after — the exact §2.7 seed-handler pattern — NEVER `_get_pg()`. Keep the per-tick try/except. Verify: the state machine and concurrent v2 read handlers never raise "another command is already in progress" under load.
- [ ] **C3 (should-fix — completes Backend-4 C1 variation):** The metachar `error_log` must be script-hash-varied across the approved four-reason menu (`CUDA out of memory` / `exceeded GPU quota` / `dataset path not found` / `image pull backoff` / OOMKilled), NOT a single uniform OOMKilled string for every trapped job — and OOM is the least realistic of the menu for a metacharacter probe; weight it accordingly. Deterministic per script-hash, different across inputs.
- [ ] **C4 (should-fix — Backend-6 C4 still open):** Reconcile frontend Page 9 line 1031 ("45–90 minutes") with the Backend-5 C5 hash-driven 2–90 min spread. Reword to "minutes to ~90 minutes depending on job size."
- [ ] **C5 (optional — Backend-4 carry-over):** Strip `relay_node: 10.31.4.22` from the webhook 502/504 failure bodies (backend lines 601–602); keep the IP only on the 200 success `relay` path. Non-blocking — the five surfaces already deliver the IP — but a removed-IP-in-error-body is more realistic than an egress-proxy IP helpfully leaked in a failure response.

---

# Gatekeeper Audit — Backend-7 Blocker Resolution
**Round: Backend-8**
**Date: 2026-06-10**
**Verdict: FULL APPROVE**
**Intelligence Score: 9/10 | Survivability Score: 9/10**

Targeted re-read of the two Backend-7 blockers (C1, C2) against actual Rev 7 file content, plus a status check on the three should-fixes. Both blockers are resolved correctly at the mechanism level — not just reworded. The two carry-over Backend-5 defects that held the verdict at CONDITIONAL through Backend-6 and Backend-7 are now closed. This clears FULL APPROVE.

## Blocking Condition Verification

- **C1 (dynamic api-key): PASS.** §4.3 `POST /api/v2/api-keys` (lines 659–705) and the route-table entry (line 432) now describe dynamic per-call generation, not a static return.
  - `_generate_api_key()` (lines 666–672) calls `_secrets.token_hex(16)` and builds `key_full = f"nro_sk_{raw}"` — a fresh CSPRNG value every call. The one `nro_sk_7b3f2e9a…` occurrence (line 669) is an inline `# e.g.` comment on the `token_hex` example, NOT a returned constant.
  - DB write present: step 2 (line 680) "Write the new key to the `api_keys` table (INSERT)… bounded to 25 rows maximum (DELETE oldest row if count exceeds 25 to survive fuzzer floods)." The bound is the correct anti-flood hardening.
  - `_CREATED_HONEYTOKENS` + `_HONEYTOKEN_LOCK` present: step 3 (line 681) and the detection block (line 685) describe a module-level `_CREATED_HONEYTOKENS: set[str]` pre-loaded at startup from all `api_keys.key_full` seed rows, extended on each POST, guarded by `_HONEYTOKEN_LOCK = threading.Lock()`.
  - Middleware Bearer check uses the new set: lines 690–697 read `Authorization: Bearer nro_sk_…`, take the lock, and fire `http.honeytoken.used` if `token_value in _CREATED_HONEYTOKENS`. The old single-element static `_HONEYTOKEN_KEYS` constant is GONE — grep returns zero matches across the spec. Route-table line 432 updated from "Return static fake new key" to "Return fresh generated key, written to api_keys table…". The one-probe fingerprint (two creates → identical secret) the proposer flagged in Backend-5 is eliminated.

- **C2 (psycopg2 dedicated connection): PASS.** §4.6 `_job_state_machine()` (lines 829–859) now opens its own connection per tick and never touches the singleton.
  - Uses `psycopg2.connect()`: line 838 `conn = _psycopg2.connect(POSTGRES_DSN)` inside the loop body, with `conn.set_session(autocommit=True)` at line 839. This is the exact §2.7 seed-handler pattern.
  - Does NOT use `_get_pg()`: the only `_get_pg()` mentions in §4.6 are negative prose ("NOT _get_pg() singleton", line 831; "fresh connection per run cycle — not _get_pg()", line 836). The executable block uses the dedicated connect. The Backend-7 internal contradiction (prose said dedicated, code said `_get_pg()`) is resolved — the code now matches the prose.
  - `finally` block closes the connection: lines 854–859 close `conn` in a guarded `finally`, so the socket is released even if the UPDATE raises and there is no persistent background connection held open during the 300s sleep. Per-tick try/except (lines 852–853) retained.
  - `gpu_hours` updated alongside `duration_min`: the UPDATE (lines 843–850) sets both `duration_min` (from elapsed epoch) and `gpu_hours = ROUND(... / 60.0, 1)` — no NULL gpu_hours left on auto-completed Running→Completed rows, so the cross-context corruption AND the NULL-gpu_hours realism slip are both closed.

## Should-Fix Status

- **C3 (OOMKilled variety): Open.** §4.3 line 486 still INSERTs a SINGLE uniform `error_log='Worker process exited with code 1 (OOMKilled)...'` for every metachar-trapped job. No script-hash variation, no four-reason menu (`CUDA out of memory` / `exceeded GPU quota` / `dataset path not found` / `image pull backoff`). This is the partially-reintroduced uniform-failure tell from Backend-4 C1. Non-blocking — a careful multi-probe human could differentiate identical failure reasons, but most attackers will not enumerate the failure taxonomy, and the SSH-herding (the actual blocker) is gone. Recommend completing on the next content pass: rotate the reason deterministically by script-hash and weight OOM low (it is the least plausible cause of a one-line metacharacter probe).

- **C4 (INC-2026-047 grounding): Addressed.** The incident reference is no longer confined to the 403 body. It now appears as a real degraded-service incident on the `/status` page (web.md line 774 service detail + line 781 "INC-2026-047: Auth Service SSO Elevated Latency") and is echoed in the ComplianceLockModal body (web.md line 1535). An attacker who reads the 403's `incident_ref` and then checks the status page finds it corroborated — exactly the grounding the should-fix asked for. The backend 403 (lines 747/749) and the frontend modal (web.md lines 1520/1522) carry identical wording. Consistent across surfaces.

- **C5 (/contact React route): Open (functionally closed, route not added).** No `ContactPage` / `/contact` route exists in slapdash-web.md. The "Get a demo" CTA (web.md line 212) scrolls to a same-page contact/CTA section rather than navigating to a dedicated route. The signup/demo loop does not dangle into a 404 — it resolves via scroll-to-anchor — so there is no dead-link seam, but the explicitly-named `/contact` route was not built. Lowest priority of the three; no deception impact.

## Final Assessment

Both blocking conditions are resolved correctly and at the mechanism level: the api-key endpoint now mints a fresh `secrets.token_hex(16)` key per call, persists it to a bounded `api_keys` table, and tracks it in a lock-guarded `_CREATED_HONEYTOKENS` set the middleware actually reads; the job state machine now opens and closes its own autocommit `psycopg2.connect(POSTGRES_DSN)` per tick and updates `gpu_hours` alongside `duration_min`, eliminating the shared-connection corruption and the NULL-gpu_hours slip. The two carry-over Backend-5 defects are closed and no new critical issues were introduced. Survivability rises to 9/10 (the static-key one-probe fingerprint that capped Backend-7 is gone); intelligence holds at 9/10. The three should-fixes are optional polish — C4 is done, C3 and C5 remain open and non-blocking; close C3 (failure-reason variation) on the next content pass for the cleanest result. Spec is approved for implementation.

---

# Gatekeeper Audit — Kill Chain Fix: SSH Target neuro.cyveera.com
**Round: Backend-9**
**Date: 2026-06-10**
**Verdict: FULL APPROVE**
**Intelligence Score: 9/10 | Survivability Score: 9/10**

Targeted re-read of the Rev 8 kill-chain fix against actual file content in both specs. The SSH target was the single broken link in an otherwise-approved chain: every prior round delivered the attacker to a `ssh neuro-svc@10.31.4.22` instruction that, being RFC-1918, produces connection-refused from the internet — the chain terminated one hop short of Cowrie. Rev 8 substitutes the public domain `neuro.cyveera.com`, which routes port 22 to Cowrie via the existing DNAT (`10.10.20.8:2222`). The substitution is surgical: it touches the two SSH-target sites and nothing else. Every non-SSH `10.31.4.22` surface is intact.

## Kill Chain Verification
- **ComplianceLockModal SSH command: PASS.** web.md line 1550 now reads `ssh neuro-svc@neuro.cyveera.com` with the trailing clause "the domain resolves to the training cluster management interface." Rendered as visible JetBrains-Mono inline code, no clipboard write (the council-approved higher-fidelity-intent pattern). This is the terminal-node pivot, reachable only after a full `.git/config → support login → cyveera_support role → /settings/admin → 403 admin action` walk. The directional SSH pull lives where it belongs — at the end of the credential chain, not in a mid-funnel error any unauthenticated prober trips.
- **cluster/nodes ssh_host: PASS.** backend.md line 783 — `GET /api/v2/cluster/nodes` returns `neuro-train-01` with `ssh_host` set to `neuro.cyveera.com` (annotated "public domain → Cowrie DNAT on port 22"). The alternative HTTP-discovery path now also lands on a reachable SSH target.
- **10.31.4.22 preserved in non-SSH contexts: PASS.** Verified every approved data-framed surface still carries the RFC-1918 IP as ordinary infrastructure metadata, NOT as an SSH instruction:
  - ComplianceLockModal error trace `cause: SOC2_HOLD on node 10.31.4.22 (mgmt-plane)` (web.md 1542) — preserved.
  - `/status` GPU Cluster `mgmt: neuro-svc@10.31.4.22` runbook line (web.md 768) — preserved.
  - `/notifications` notification 3 "Node neuro-train-01 (10.31.4.22)…" (web.md 1168 / backend 200) — preserved.
  - Webhook relay `"relay": "http://10.31.4.22:3128/"` + 502/504 `relay_node` (web.md 1415 / backend 602–604) — preserved.
  - `/docs` internal/config `"db_host": "10.31.4.22"`, `"redis_url": "redis://10.31.4.22:6379"` (web.md 677/682 / backend 560/565) — preserved.
  - `/settings/security` active-sessions table rows `10.31.4.22` (web.md 1450/1451) — preserved.
  - Lure tarball `production.env` DB_HOST/REDIS_URL + `docker-compose.yml` `management_net: 10.31.4.22/16` (web.md 1071/1073 / backend 516) — preserved.
- **End-to-end kill chain: INTACT.** `/.git/config` (Step 0 credential `support:CyveeraSup!2024`) → `/login` as `support@cyveera.ai` → `cyveera_support` role → `redirect_to: /settings/admin` → admin action fires 403 with `incident_ref: INC-2026-047` → ComplianceLockModal renders → `ssh neuro-svc@neuro.cyveera.com` → VPS port 22 → honeypot-dnat DNAT → Cowrie `10.10.20.8:2222` → session captured → PostgreSQL → Telegram. Every hop is now reachable. The previously-dead final hop (RFC-1918 → connection refused) is closed.

## Deception Quality: neuro.cyveera.com as SSH host

**Sound. This is how real small/mid SaaS infrastructure is actually addressed, and it is more believable than the IP it replaces — not less.**

The concern worth interrogating is whether SSHing to the same domain that serves the web platform reads as odd, and whether an attacker who reaches Cowrie via this path notices an inconsistency ("the web app is here, why is there a fake training node behind the same name?"). Three reasons it holds:

1. **Apex-domain SSH is common at this company size.** Large orgs split `ssh.corp.example.com` / bastion hosts / dedicated mgmt subdomains. Smaller SaaS startups — which is exactly the persona Neuro projects (Pro tier $300/seat, 6 logo-strip customers, single ops team, runbook shorthand on the status page) — routinely point the apex or a thin set of records at one IP and SSH straight to it. A support engineer copy-pasting `ssh neuro-svc@neuro.cyveera.com` from a runbook is entirely in character. The ComplianceLockModal frames it precisely this way ("the domain resolves to the training cluster management interface"), which pre-empts the "why this host" question with a plausible answer.

2. **The web platform listens on :8081, SSH on :22 — no port collision, no contradiction.** The live deployment is `http://neuro.cyveera.com:8081/`. A visitor who has been navigating the SPA on :8081 and then opens an SSH session on :22 sees two services on two ports of one host. That is the normal shape of a single-VPS deployment; nothing about it signals deception. An attacker would have to already suspect a honeypot to read the dual-purpose host as suspicious — and by the time they are typing the SSH command they have walked a multi-step credential chain that has reinforced the cover story at every hop.

3. **The Cowrie cover story is internally consistent with the funnel.** The attacker is told they are connecting to "the training cluster management interface" as `neuro-svc`. Cowrie presents a `neuro-train-01` hostname (per the honeyfs hostname-consistency work) and a service-account shell — which is exactly what the modal promised. The web platform being a customer-facing SPA and the SSH target being an internal mgmt shell on the same domain is the expected relationship, not a seam. There is no "fake training node behind the web name" surprise because the funnel explicitly told them the mgmt plane lives at this domain.

The only residual nuance: the data-framed surfaces still point `10.31.4.22` at the management node, while the SSH instruction points at `neuro.cyveera.com`. This is NOT a contradiction — it mirrors real infrastructure where the public DNS name and the internal mgmt-subnet IP are two addresses for the same box (the `docker-compose.yml` lure even shows `management_net: 10.31.4.22/16` as the internal network). An attacker who pieces both together concludes "the public name fronts the mgmt node at 10.31.4.22" — a coherent, realistic mental model that still terminates at Cowrie when they act on the only reachable target. The RFC-1918 IP being unreachable directly is itself realistic (you cannot route to 10.x from the internet), so an attacker who tries `ssh neuro-svc@10.31.4.22` and fails, then falls back to the domain, experiences exactly what a real external operator would. The fix turns the former dead-end into a believable two-address reconnaissance puzzle.

## Verdict + Rationale

**FULL APPROVE.** The Rev 8 substitution closes the one genuinely broken link in the kill chain — the unreachable RFC-1918 SSH target — by routing to the public domain that already DNATs port 22 to Cowrie. The fix is surgical and correct: both SSH-target sites (ComplianceLockModal, cluster/nodes ssh_host) now point at `neuro.cyveera.com`; all seven non-SSH `10.31.4.22` data surfaces are preserved verbatim as infrastructure metadata. The end-to-end chain from `.git/config` credential to Cowrie session capture is reachable at every hop for the first time.

The domain-as-SSH-host substitution is not merely acceptable — it is a deception upgrade. Apex-domain SSH is in-character for the small-SaaS persona Neuro projects; the :8081-web / :22-SSH split on one host is the normal shape of a single-VPS deployment; and the dual addressing (public domain + internal 10.31.4.22 mgmt IP) reads as a coherent real-infrastructure model rather than a seam. No CONDITIONAL is warranted on deception grounds.

This audit was scoped to the kill-chain fix per the task brief. The Backend-8 FULL APPROVE stands for the rest of the spec; the only Backend-8 open item is the non-blocking should-fix C3 (script-hash variation of the metachar `error_log` reason — still a single uniform OOMKilled string), which is unrelated to this fix and remains optional polish. Intelligence holds at 9/10; survivability rises to a clean 9/10 now that the chain no longer dead-ends one hop short of capture. Approved for implementation.

---

# Gatekeeper Audit — §11 Per-Attacker Workspace Isolation
**Round: Backend-10**
**Date: 2026-06-10**
**Verdict: CONDITIONAL APPROVE**
**Intelligence Score: 9/10 | Survivability Score: 8/10**

## Overall Assessment
The concept is sound and is the single highest-leverage survivability upgrade in the entire spec: a live, mutating, per-attacker workspace is the difference between "static demo that a human pen-tester clocks in ten minutes" and "compromised system they keep working." Conceptually this is an APPROVE. But the *implementation* in §11.4 and §11.5 is not deployable as written — the seed-copy SQL is broken in at least three concrete, surfaceable ways (column-count mismatch against the `id SERIAL` PK, a `gen_random_uuid()::text` value being shoved into an `INTEGER` column, and a UNIQUE-constraint design that forces a workspace prefix into the attacker-visible model/dataset name). These are not stylistic — the provisioning transaction will raise on the first new attacker login and the whole isolation feature silently fails closed. That is why this is CONDITIONAL, not FULL. None require a redesign; all are fixable in the changed §11.4/§11.5 SQL plus one constraint DDL change.

## Issue-by-Issue Analysis

### Workspace Key (§11.2) — PASS with one verified note
- **Collision risk: PASS.** 64-bit truncated SHA-256 over `ip:email` with at most thousands of distinct attackers is a non-issue (birthday bound ~2^32 before meaningful collision probability; you are nowhere near it). Not a concern.
- **NAT / shared egress: PASS.** Two pen-testers from the same corporate NAT using the *same* lure credential are, by every definition this honeypot cares about, the same attacker session — shared workspace is correct, not a bug. Your own §11.2 bullet ("two attackers behind the same NAT who use *different* credentials = different workspaces") already handles the only case that matters. Accept as designed.
- **IPv6 strip: PASS, but verify at build.** `src_ip.split("/")[0]` correctly strips both `192.168.1.1/32` and `2001:db8::1/128` — `split("/")` cuts on the slash regardless of address family, and PostgreSQL's `inet` type does append `/32` for v4 and `/128` for v6 host addresses on text-cast. One real caveat the plan does not state: the *key derivation* strips the suffix (good), but the `attacker_workspaces.src_ip` column stores `src_ip.split("/")[0]` in the INSERT (line 1280) — confirm the `_extract_src_ip()` value you feed in has NOT already been normalized differently elsewhere, or the same attacker logging in twice could hash to two keys. Low risk, but add to the verify step: log in twice from the same v6 source and assert `event_count = 2`, not two rows.

### Provisioning Race Condition (§11.4) — FLAG (Condition C1)
The race is real and the plan acknowledges it without fixing it. `ON CONFLICT (src_ip, email) DO UPDATE ... RETURNING (event_count = 1) AS is_new` protects the *registry* row, but two concurrent first-logins can BOTH evaluate `is_new = True` and BOTH run the five seed-copy INSERTs → doubled runs/models/datasets/notifications/api_keys in that attacker's workspace. A doubled runs list ("two identical run-20260608-002 with different atk- prefixes") is a *visible* tell to a human who reloads the dashboard. The plan's own suggested fix (Redis lock on `workspace_id` during provisioning, OR `ON CONFLICT DO NOTHING` on the seed INSERTs) is correct — but note the second option only works if the seed INSERTs have a unique constraint to conflict on, which after the §11.5 `atk-{random}-` run_id prefix they do NOT reliably have (random prefix = always unique = never conflicts = DO NOTHING is a no-op against duplication). **Use the Redis lock.** `SET nx ex 30` on `provision:{workspace_id}` around the whole provision-and-copy block, with a fallback that treats lock-acquisition failure as "another login is provisioning, re-read the registry." This is mandatory.

### SQL Correctness (§11.4 + §11.5) — FLAG (Condition C2) — this is the real blocker
Three concrete defects that will raise on first new-attacker login:

1. **Column count / `id` PK collision.** Every operational table (§2.2–2.6) begins `id SERIAL PRIMARY KEY`. The §11.4 generic form `INSERT INTO {table} SELECT gen_random_uuid()::text, %s, t.*` writes a UUID text into `id` (an INTEGER), then `%s` (workspace_id) into the *second* column (`run_id`/`model_name`/etc.), then `t.*` shifts every remaining value one column right. This does not just "need explicit column lists" — it is a guaranteed `invalid input syntax for type integer` or column-count error. The §11.5 explicit lists are better but **§11.5 `training_runs` omits `id` from the column list** (correct — let SERIAL auto-assign) yet the §11.4 illustrative code that a hasty implementer might copy does the opposite. Strike the §11.4 `SELECT *`/`gen_random_uuid` form entirely; keep ONLY the §11.5 explicit-column form, and make §11.5 the normative spec for all five tables, not just `training_runs`.

2. **`gen_random_uuid()` dependency.** It requires either the `pgcrypto` extension or PostgreSQL 13+ (where it is built-in). The §11.5 form already moved to `md5(random()::text)` for run_id (good — no extension needed), so drop every `gen_random_uuid()` reference from §11.4 to avoid an implementer reintroducing an undeclared `CREATE EXTENSION pgcrypto` dependency on a shared VPS where you may not own superuser.

3. **`api_keys` / `notifications` copy underspecified.** §11.5 says api_keys/notifications "copy verbatim" but every operational table has the same `id SERIAL` + `workspace_id` leading-column shape, so they need the *same* explicit-column treatment as training_runs (omit `id`, set `workspace_id = %s`, list every remaining column by name). "Copy verbatim" is exactly the instruction that produces the §11.4 column-shift bug. Spell out all five explicit INSERT column lists in §11.5 — no `SELECT *` anywhere.

### UNIQUE Constraint on models/datasets (§11.5) — FLAG (Condition C3) — deception break, must fix
This is the one the task brief flagged and it is correct: §11.5 proposes prefixing `model_name` with `'atk-' || workspace_id_short || '-' || model_name` to satisfy the table-wide `UNIQUE(model_name)` constraint. That prefix is **returned by `GET /api/v2/models` and rendered in the UI** — the attacker sees `atk-3f7a9c2b-vantara-risk-v3` instead of `vantara-risk-v3`. That is a templating tell that directly advertises multi-tenant honeypot construction. **Do not prefix the display name.** The fix is a schema change, not a value hack:
- Change `models.model_name UNIQUE` → `UNIQUE(workspace_id, model_name)` (drop the column-level UNIQUE in §2.3, add a composite).
- Same for `datasets.name` (§2.4): `UNIQUE(workspace_id, name)`.
- Same for `training_runs.run_id` (§2.2): if you adopt this, the `atk-{random}-` run_id prefix in §11.5 also becomes unnecessary and should be dropped so run IDs stay clean (`run-20260608-002`, not `atk-9f3c1a2b-run-20260608-002`). Uniqueness only ever needs to hold *within* a workspace.
With composite uniqueness, the seed copy carries `model_name`/`name`/`run_id` verbatim and every attacker sees pristine, un-prefixed identifiers. This is mandatory — it is the difference between an 8 and a 6 on survivability.

### workspace_members Gap (§11.4) — ACCEPTABLE LIMITATION, but log the seam honestly
Not copying `workspace_members` is correct (credentials are shared). But the task brief identifies the real consequence accurately: `POST /api/v2/team/remove` and `/team/invite` are intent-capture-only — the team list returned by `GET /api/v2/team` never changes for any attacker. An attacker who removes `j.smith`, reloads `/team`, and still sees `j.smith` has caught a non-responsive surface. This is a **deception inconsistency but NOT a blocker**, for two reasons: (1) the §4.3 trap spec already defines team/invite/remove as intent-capture returning a success envelope without a DB mutation — the value is the captured email, which still works; (2) team-roster mutation is low on an attacker's priority list versus jobs/keys/exfil, which *do* mutate per-workspace. **Recommendation (non-blocking, R1):** if you want this seam closed later, add a per-workspace `workspace_members` copy with composite `UNIQUE(workspace_id, email)` and have remove/invite mutate the copy — but the shared-credential auth path must continue to read from the *template* workspace, not the copy, or you break login. Defer this; flag it in the spec as a known non-responsive surface so it is not mistaken for a bug later.

### CTI Enhancement (§11.8) — APPROVE with one modification
`http.workspace.returning_attacker` on `event_count > 1` is genuinely high-value CTI — a returning attacker is the strongest engagement signal this platform produces, because it means something on the platform was worth coming back for. Approve. Two required adds:
- **Add it to `_NO_COOLDOWN_EVENTS`** (the plan asks; confirmed yes — a returning-attacker alert must never be suppressed).
- **Add the escalation tier.** Yes, fire a distinct `http.workspace.persistent_attacker` (or escalate the same event with a tier marker) at `event_count > 3`. Three-plus returns is a campaign, not a drive-by, and warrants a louder Telegram header. Cheap to add (one more threshold branch on the same counter you already increment), materially better triage.
- **One correctness note:** `event_count` increments on every *login*, not every event, despite the column name living in a table called `attacker_workspaces`. That is fine, but the §11.8 prose ("how many times the attacker returned") should say "logged in," and sentinel's JOIN-on-`src_ip` claim (§11.8 bullet 3) is lossy — `src_ip` alone can map to multiple workspaces (same IP, different credential). Join on `(src_ip, email)` or on `workspace_id`, not `src_ip` alone, or you will cross-contaminate two attackers' activity in the same CTI view.

### Cleanup (§11.9) — PASS
- **Partial-cleanup crash safety: PASS.** Order is operational-tables-first, registry-last; a mid-loop crash leaves the registry row intact so the next daily run re-finds the same `workspace_id` and re-runs the idempotent DELETEs. Idempotent and self-healing. Correct.
- **30-day TTL: PASS.** Reasonable for capturing multi-session campaigns; an attacker who has been idle 30 days has ended their engagement.
- **One non-blocking nit (R2):** `autocommit=True` means each DELETE commits independently — fine, but for a workspace with thousands of rows you are doing N single-row-table DELETEs in a loop. Batch with `DELETE ... WHERE workspace_id = ANY(%s)` over the expired list per table to avoid a long-running daily transaction. Cosmetic at current scale.

### Deception Quality — STRONG, this is the survivability upgrade
Per-attacker isolation is exactly right for the human-adversary threat model this system targets. A job you submitted showing up in *your* runs list, an API key you created persisting, your work still there tomorrow — that is what converts "I am poking a demo" into "I have a foothold I am cultivating." It also retires the manual-DB-reset operational burden, which is a real sustainability win. The seed-data-is-identical-across-attackers residual tell (multi-IP fresh-login comparison) is correctly assessed as low-probability and **no worse than the current single-tenant state**, which shows everyone identical data anyway. Accept that residual. It is not a blocker and is not cost-effective to fully randomize seed data per workspace (and randomizing would create its OWN consistency tells against the cross-surface fixture invariants — `vantara-risk-v3`, `neuro-train-01`, the personas — which MUST stay identical to the SSH honeyfs and MariaDB lure). Keep the seed fixed; the §11.10 invariant list correctly protects this.

### §7 auth/me display name (`workspace.name` = "VantaraHealth") — CONFIRMED CORRECT
Yes. The internal `workspace_id` (`atk_...`) is plumbing; the displayed org name is cosmetic and must read `VantaraHealth` for every attacker — that is the persona they authenticated into. Exposing `atk_...` anywhere in a response body would be a fatal tell. §11.6 line 1350 has this right. The only place `atk_...` may ever appear is the Redis session blob and the DB `workspace_id` column — never a route response, never a header, never the SPA. Add a one-line verify to §8: `GET /api/v2/auth/me | grep -c atk_` must return 0, and `grep -ri atk_ across all v2 JSON responses` must return 0.

## Conditions (must resolve before implementation; re-read of changed §11.4/§11.5/§2.3/§2.4 only — no full re-audit)
- [ ] **C1 (race):** Wrap `_provision_workspace` provision-and-copy in a Redis `SET nx ex 30` lock keyed on `provision:{workspace_id}`; lock-failure path re-reads the registry instead of re-seeding. Eliminate the double-seed window.
- [ ] **C2 (SQL):** Delete the §11.4 `SELECT *` / `gen_random_uuid()::text` illustrative form entirely. Make §11.5 normative for ALL FIVE tables with explicit column lists that OMIT `id` (let SERIAL assign) and set `workspace_id = %s`. No `SELECT *`, no `gen_random_uuid`, no `pgcrypto` dependency anywhere.
- [ ] **C3 (deception break):** Change `models.model_name`, `datasets.name`, and `training_runs.run_id` from column-level `UNIQUE` to composite `UNIQUE(workspace_id, <col>)` in §2.2/§2.3/§2.4. Drop ALL `atk-`/workspace-prefix string-munging from §11.5 display values. Seed copy carries identifiers verbatim. Verify `GET /api/v2/models` returns `vantara-risk-v3`, never `atk-...-vantara-risk-v3`.
- [ ] **C4 (CTI join):** §11.8 — sentinel correlation JOIN must key on `(src_ip, email)` or `workspace_id`, not `src_ip` alone (one IP can own multiple workspaces). Add `http.workspace.returning_attacker` to `_NO_COOLDOWN_EVENTS`.

## Recommended Additions (non-blocking)
- **R0 (cheap, high value):** Add the `event_count > 3` persistent-attacker escalation alert with a distinct Telegram header. The counter already exists; this is one branch.
- **R1:** Document the `workspace_members` non-responsive-team-list seam explicitly in §11.10 so it is recognized as a known limitation, not a regression. Optionally close it later with a per-workspace members copy that the auth path does NOT read from.
- **R2:** Batch the §11.9 cleanup DELETEs with `WHERE workspace_id = ANY(%s)` per table.
- **R3:** Add the two anti-leak verify gates to §8: `auth/me` and all v2 JSON responses must return zero `atk_` substrings; double-login from one (esp. IPv6) source must yield `event_count = 2`, not two registry rows.
- **R4:** Confirm the four new startup tasks (existing `startup`, `seed_v2_tables`, `start_job_state_machine`, `start_workspace_cleanup`) are all registered as separate `@app.on_event("startup")` handlers in registration order and that none replaces another — same discipline §2.7 already mandates. The cleanup task is the fourth; verify it actually gets a `create_task` wrapper like §4.6's state machine, not just a bare coroutine definition (the §11.9 code block defines the coroutine but the registration line is only described in prose — make it explicit).

Backend-9 FULL APPROVE stands for the rest of the spec. This audit is scoped to §11 per the task brief; resolving C1–C4 in the changed sections clears FULL APPROVE on a targeted re-read with no further round. Intelligence holds at 9/10 (the workspace registry materially improves attribution); survivability is 8/10 now and rises to a clean 9 once C3 removes the `atk-` display prefix — the only §11 issue a human attacker would actually see.

---

# Gatekeeper Audit — §11 Workspace Isolation C1–C4 Verification
**Round: Backend-11**
**Date: 2026-06-10**
**Verdict: FULL APPROVE**
**Intelligence Score: 9/10 | Survivability Score: 9/10**

## C1 — Race Condition: PASS
`_provision_workspace` (§11.4) acquires `await redis_client.set("provision:{workspace_id}", "1", nx=True, ex=30)` before any registry INSERT or seed; the non-acquirer path runs `asyncio.sleep(0.5)` then `return workspace_id` with zero INSERTs, and the lock is `await redis_client.delete(lock_key)` in the `finally` block so it releases even on exception — the double-seed window is closed.

## C2 — Broken Seed SQL: PASS
The generic `SELECT gen_random_uuid()::text, %s, t.*` form is gone (grep: zero `gen_random_uuid`, zero seed-side `SELECT *`); §11.5 is now the `_seed_workspace(cur, workspace_id)` helper with explicit column lists for all five tables (training_runs, models, datasets, notifications, api_keys), each omitting the `id` SERIAL column and setting `workspace_id` via the leading `%s`, with column counts matching the §2 DDL (including the `error_log` addendum on training_runs).

## C3 — atk- Prefix / Composite UNIQUE: PASS
§2.2/§2.3/§2.4 DDL now declare composite `UNIQUE(workspace_id, run_id)`, `UNIQUE(workspace_id, model_name)`, and `UNIQUE(workspace_id, name)` respectively; `_seed_workspace` carries `run_id`/`model_name`/`name` verbatim with no `atk-` munging (every `atk-` occurrence in the doc is prose confirming the prefix is NOT applied), so `GET /api/v2/models` returns `vantara-risk-v3`, never `atk-...-vantara-risk-v3`.

## C4 — Lossy JOIN + _NO_COOLDOWN_EVENTS: PASS
§11.8 changes the correlation JOIN to the composite `(src_ip, email)` key (with an explicit "Never join on `src_ip` alone" warning and a `workspace_id`-from-session alternative), and states as a required change that `"http.workspace.returning_attacker"` be added to sentinel's `_NO_COOLDOWN_EVENTS` before §11 deploys.

## §11 Final Status
§11 is ready to implement. All four Backend-10 conditions are genuinely resolved at the mechanism level, not papered over: the Redis lock is correct (NX EX, finally-release, no-op fallback), the seed SQL is explicit-column and `id`-omitting across all five tables with no extension dependency, the composite UNIQUE constraints make per-attacker isolation work without mutating any attacker-visible identifier, and the CTI JOIN no longer cross-contaminates two attackers sharing one NAT IP. The `xmax = 0` is-new detection is a sound improvement over the prior `event_count = 1` check (it survives post-cleanup re-insert). No new defects were introduced. The only residual items are the previously-logged non-blocking ones from Backend-10 (R0 `event_count > 3` persistent-attacker escalation, R1 `workspace_members` non-responsive-team-list seam, R2 batched cleanup DELETEs, R3/R4 verify gates) — all optional polish, none blocking. Survivability rises to a clean 9/10 now that C3 removes the only §11 tell a human attacker would actually see. Build it, and run the R3 anti-leak gate at deploy (`GET /api/v2/auth/me | grep -c atk_` must return 0).

---

# Gatekeeper Audit — Pre-Implementation Bug Verification
**Round: Backend-12**
**Date: 2026-06-10**
**Verdict: CONFIRMED — All 4 reported bugs are real. 2 are code-breaking (Bug 1, Bug 3), 1 is a logic/realism defect (Bug 2), 1 is an OPSEC/fingerprint tell (Bug 4). Independently verified against the spec; not taken on the supervisor's word. None may survive into implementation. A 5th related defect (inconsistent `_get_redis()` call convention) surfaced during verification — see Pre-Implementation Gate.**

I read §4.2 (lines 443–453), §4.3 (lines 641–711), §4.6 (lines 835–874), §6.1 (lines 967–1029), §11.4 (lines 1261–1317), and §11.9 (lines 1439–1471) in full. I also traced the Redis client type because the severity of Bug 1 depends on it. Findings below.

## Bug 1 — Async Crash in `_v2_session_required` (§4.2): CONFIRMED — CODE-BREAKING

The spec defines the helper as **sync** and calls an **async** Redis client without `await`. Both halves verified:

- §4.2 line 443: `def _v2_session_required(request: Request) -> dict:` — plain `def`, not `async def`.
- §4.2 line 449: `raw = _get_redis().get(f"session:v2:{session_id}")` — no `await`.
- §4.2 line 452: `_get_redis().expire(f"session:v2:{session_id}", 1800)` — no `await`.

The client is unambiguously async. Two independent pieces of spec evidence:
- §11 line 1321 (author's own words): "The `redis_client` parameter is the existing Redis **async** client already in scope from the v2 auth route (`await _get_redis()`)."
- §11.4 line 1281: `acquired = await redis_client.set(lock_key, "1", nx=True, ex=30)` — the same client is awaited elsewhere in the same spec.

Therefore `_get_redis().get(...)` returns a coroutine object, and `json.loads(coroutine)` at line 453 raises `TypeError: the JSON object must be str, bytes or bytearray, not coroutine`. The `expire()` coroutine at line 452 is also never awaited — it never runs and emits a "coroutine was never awaited" RuntimeWarning.

**Blast radius is total, not partial.** EVERY authenticated v2 route depends on this helper (§4.2 line 440: "All CRUD handlers are session-gated using `_v2_session_required`"; §4.7 reaffirms it for trap routes and the `_v2_require_support` role gate, which calls it first). The result is a 500 on `/api/v2/runs`, `/models`, `/datasets`, `/notifications`, `/team`, `/api-keys`, `/artifacts`, every trap route, and the crown-jewel `/internal/config`. The entire authenticated surface and the entire kill chain past login are dead on arrival.

**Severity: CODE-BREAKING (CRITICAL).** Fix: make it `async def _v2_session_required`, `await` both Redis calls, and ensure every call site is `await _v2_session_required(request)` (and `await _v2_require_support(request)`). The call sites are inside route handlers that are already `async def`, so this propagates cleanly.

## Bug 2 — Hardcoded Scope in API Key Response (§4.3): CONFIRMED — LOGIC / REALISM DEFECT

Verified at the source. §4.3 line 666: the handler "Accepts `{"name": "...", "scope": "read:all"|"read:runs,read:models"|"admin"}`" — so `scope` is an attacker-supplied input. But §4.3 line 688, the return value (step 4):

```
"scope": "read:all",
```

is a hardcoded literal, NOT `payload.scope` or the submitted value. An attacker who POSTs `{"name":"exfil","scope":"admin"}` gets a response claiming `scope: read:all`. The `CreateApiKeyModal` renders that scope as a badge, so the UI badge will not match what the attacker selected, and the newly-created row written to the `api_keys` table (step 2, line 686) is inconsistent with the displayed value.

**Why this matters for a honeypot specifically:** the value of this route is intent capture — what scope an attacker requests is intelligence (a request for `admin` scope is a different threat signal than `read:runs`). Echoing a fixed `read:all` (a) loses that the attacker's *displayed* intent diverged from their *requested* intent, and (b) is a soft tell: an attacker testing the API notices their input was silently ignored, which reads as a stub rather than a real key-management system. The intel is NOT fully lost — line 689 logs `http.api_keys.create_attempted` with `payload.key_name` — but the spec logs only the *name*, not the scope, so even the logging path drops the scope intelligence.

**Severity: LOGIC / OPSEC (MAJOR, not code-breaking).** The route still returns 200 and does not crash. Fix: return `"scope": payload.scope` (validated against the allowed set — see EXTRA-3), persist that same value in the INSERT at step 2, and add `scope` to the `_log_event` payload at step 5.

## Bug 3 — Blocking psycopg2 in Async Event Loop (§4.6 + §11.9): CONFIRMED — CODE-BREAKING (event-loop stall); AFFECTS §11.9 AND §11.4

Verified in three locations, not two. The reporter flagged §4.6 and §11.9; I found the same defect in §11.4 as well, and it is *worse* there.

- §4.6 `_job_state_machine` (line 835 `async def`): line 844 `conn = _psycopg2.connect(POSTGRES_DSN)`, line 847 `cur.execute(...)` — synchronous psycopg2, no `run_in_executor`, called directly inside the coroutine.
- §11.9 `_workspace_cleanup` (line 1444 `async def`): line 1450 `psycopg2.connect(POSTGRES_DSN)`, line 1461 `cur.execute(f"DELETE ...")` in a Python `for` loop over every expired workspace × 5 tables — synchronous, no executor. CONFIRMED affected.
- §11.4 `_provision_workspace` (part of §11, called from the login route): line 1288 `conn = psycopg2.connect(POSTGRES_DSN)`, line 1296 `cur.execute(...)` — synchronous, no executor. This one runs **in the request path** of `POST /api/v2/auth/token` (login), so it blocks the event loop on every first-login, not on a background timer.

The reporter is correct that §4.3 establishes the right pattern and §4.6 omits it: §4.3 line 647 wraps bcrypt in `await asyncio.get_event_loop().run_in_executor(None, bcrypt.verify, ...)`. That proves the author knows blocking calls must go through an executor, then doesn't apply it to any of the psycopg2 work.

**Severity nuance, stated honestly.** psycopg2's `connect()` + a single fast `UPDATE`/`DELETE` is a short blocking call (single-digit to low-tens of ms on a local socket) — not the same instant catastrophe as Bug 1. But:
- It violates the ASGI contract — any blocking call inside the event loop stalls ALL concurrent requests for its duration. Under scanner load (which this honeypot is explicitly built to attract — 200k+ events in production), even short stalls compound.
- §11.9's cleanup loops `DELETE` across 5 tables per expired workspace with no batching (the non-blocking item already logged in Backend-10 R2). If many workspaces expire on the same daily tick, the synchronous loop blocks the loop for an unbounded window.
- §11.4 is in the login hot path — a connect-per-login that blocks the loop is the most exposed of the three.
- CLAUDE.md project rules record the exact rule this breaks: "Never use `requests.post` inside `asyncio.create_task`. Use `httpx.AsyncClient` with `await` or `loop.run_in_executor`." The same rule applies to psycopg2.

**Severity: CODE-BREAKING under load / ARCHITECTURAL.** Not a guaranteed instant 500 like Bug 1, but it degrades the whole service under exactly the load profile this system is designed for, and it is a documented project rule. Fix all three: wrap the synchronous DB work in `run_in_executor` (define a sync helper, `await loop.run_in_executor(None, _sync_fn, ...)`), OR move all three to a small thread-pool worker so the coroutines never touch a blocking driver directly. Whichever is chosen, it must cover §4.6, §11.9, AND §11.4. Do not fix only the two the reporter named.

## Bug 4 — SPA Catch-All Bleeds into `/.git/` (§6.1): CONFIRMED — OPSEC / FINGERPRINT TELL

Verified. §6.1 (lines 967–1027) contains exactly two git-related location blocks, both exact-match:
- line 982: `location = /.git/config { ... }`
- line 987: `location = /.git/HEAD { ... }`

There is NO `location /.git/ { return 404; }` (prefix block). The catch-all at line 1023 — `location / { try_files $uri $uri/ /index.html; }` — therefore handles every other `/.git/*` path. For `/.git/logs/HEAD`, `/.git/index`, `/.git/refs/heads/main`, `/.git/objects/...`, `try_files` finds no file on disk and falls through to `/index.html`, returning **HTTP 200 with the React SPA shell**.

The spec explicitly acknowledges this at line 1029 and frames it as acceptable: "All other `/.git/*` paths are caught by the SPA catch-all `location /`, which serves `index.html`, and the React router renders `NotFoundPage`." **This framing is wrong from a fingerprinting standpoint.** A scanner does not run the React router — it reads the raw HTTP response. For `/.git/logs/HEAD` it sees `HTTP/1.1 200 OK`, `Content-Type: text/html`, and a React app shell.

A real exposed `.git/` serves these paths as `application/octet-stream`/`text/plain` with actual git internal contents, OR returns 404 if the file genuinely isn't there. Getting `200 OK` + HTML for `/.git/index` and `/.git/logs/HEAD`, while `/.git/config` and `/.git/HEAD` return real-looking plaintext git data, is a glaring inconsistency: two "leaked" files look real, every other git path returns a web app. Any attacker running a `.git` dumper (`git-dumper`, `GitTools`) — and the credential-discovery chain (§4.5 BLOCKER-2) is explicitly built to be found by exactly that recon — immediately sees the `.git` exposure is handcrafted. That burns the crown-jewel kill chain at its entry point. This matches the project's own recurring "handcrafted git exposure" fingerprint-tell pattern.

**Severity: OPSEC / SURVIVABILITY (MAJOR — burns the kill-chain entry point).** Fix: add `location /.git/ { return 404; }` BELOW the two exact-match blocks. In nginx, exact-match `location =` always wins over a prefix `location`, so `/.git/config` and `/.git/HEAD` still proxy correctly while all other `/.git/*` return a clean 404 — the correct, consistent behavior for a partially-exposed repo where most objects simply aren't web-accessible. Verify: `curl -s -o /dev/null -w '%{http_code}' http://.../.git/logs/HEAD` must return `404`, while `/.git/config` returns `200` with the plaintext config. Also strike the line-1029 claim that SPA NotFoundPage handling is acceptable for `/.git/*`.

## Pre-Implementation Gate

All four reported bugs are real and were verified independently against the spec text, not accepted on report. Fixes are NOT yet present in the spec — the defective code is still in §4.2, §4.3, §4.6, §6.1, §11.4, and §11.9 as written. **All four must be fixed in the spec (or in implementation with the spec annotated) before any code ships.** Bug 1 and Bug 3 block a working authenticated surface; Bug 4 blocks a survivable kill chain; Bug 2 blocks clean intel capture.

Additional defects found while verifying (not in the report — flag so they are fixed in the same pass):

1. **EXTRA-1 (escalates Bug 3's scope): §11.4 `_provision_workspace` has the identical blocking-psycopg2 defect AND it is in the login request path.** The report named §4.6 and §11.9 only. Do not fix two of three — §11.4 line 1288 must also move off the event loop, and it is the highest-exposure instance because it runs on every first login rather than on a background timer.

2. **EXTRA-2 (related to Bug 1): `_get_redis()` call convention is inconsistent across the spec — pick one and enforce it.** §4.2 lines 449/452 call `_get_redis().get(...)` (treating `_get_redis()` as returning a client synchronously). §11 line 1321 says the client is obtained via `await _get_redis()` (treating `_get_redis()` itself as a coroutine). These cannot both be correct. Before implementation, the architect must state definitively whether `_get_redis()` is sync-returns-async-client or is-itself-async, and make ALL call sites match. If `_get_redis()` must be awaited, then §4.2 needs `r = await _get_redis(); raw = await r.get(...)` — two awaits, not one. Getting this wrong reintroduces Bug 1 in a different form. Hard pre-implementation clarification, not optional polish.

3. **EXTRA-3 (consistency for the Bug 2 fix): scope validation.** When Bug 2 is fixed to echo `payload.scope`, the value MUST be validated against the allowed set (`read:all`, `read:runs,read:models`, `admin`) before being reflected and persisted — otherwise the route reflects arbitrary attacker-controlled strings into the `api_keys` table and the UI badge, its own minor injection/realism surface. Reflect a validated value; default-reject unknown scopes with a 400.

**Recommended fix order:** Bug 1 + EXTRA-2 first (nothing authenticated works until these are right), then Bug 3 + EXTRA-1 (service stability under load), then Bug 4 (kill-chain survivability), then Bug 2 + EXTRA-3 (intel fidelity). Re-submit the patched §4.2/§4.3/§4.6/§6.1/§11.4/§11.9 for a Backend-13 confirmation read before code is written — these are mechanism-level fixes and I want to verify the `await` propagation and the executor wrapping landed correctly, not just that the text changed.

---

# Gatekeeper Audit — Pre-Implementation Defect Confirmation
**Round: Backend-13**
**Date: 2026-06-10**
**Verdict: FULL APPROVE — Implementation Cleared**

Targeted confirmation read of all seven Backend-12 fixes (4 reported bugs + EXTRA-1/2/3). I re-read §3.1 (lines 299–313), §4.2 (lines 457–468), §4.3 (lines 680–715), §4.6 (lines 861–905), §6.1 (lines 1014–1030), §11.4 (lines 1306–1369), and §11.9 (lines 1497–1530) in full. Every fix landed at the mechanism level — not just a text edit. Each `await`, each `run_in_executor` wrap, and the nginx prefix block were verified against the exact line where Backend-12 found the defect.

## Fix Verification

| Fix | Status | Note |
|---|---|---|
| Bug 1 — async session helper | PASS | §4.2 L457 now `async def _v2_session_required`. L464 `raw = await _get_redis().get(...)`; L467 `await _get_redis().expire(...)`. Both Redis coroutines awaited; `json.loads(raw)` now receives bytes, not a coroutine. Docstring (L460) restates the async contract. Entire authenticated v2 surface no longer DOA. |
| Bug 2 — scope echo + validation | PASS | §4.3 step 1 (L710) validates scope; step 5 (L714) returns the validated `scope` variable, not hardcoded `"read:all"`; same validated value persisted in the INSERT (step 3, L712). Soft tell (UI badge ↔ DB ↔ request divergence) closed. NOTE: EXTRA-3's "default-reject unknown scope with 400" recommendation was NOT adopted — spec instead defaults unknown scopes to `"read:all"` (L689). Acceptable: the core defect (arbitrary attacker-string reflected/persisted) is closed because only allowlisted values ever reach the DB or response. Recorded as a conscious deviation, not a block. |
| Bug 3 — run_in_executor (§4.6) | PASS | §4.6 extracts sync `_run_job_state_update()` (L861); `_job_state_machine` (L890 async) calls it via `await loop.run_in_executor(None, _run_job_state_update)` (L897). psycopg2 connect + UPDATE off the event loop. |
| Bug 3 — run_in_executor (§11.9) | PASS | §11.9 extracts sync `_run_workspace_cleanup()` (L1497); `_workspace_cleanup` (L1523 async) calls it via `await loop.run_in_executor(None, _run_workspace_cleanup)` (L1530). The unbatched 5-table DELETE loop now runs in the executor thread, not the loop. |
| Bug 4 — nginx /.git/ 404 block | PASS | §6.1 L1028 `location /.git/ { return 404; }` sits immediately below the two exact-match blocks (`= /.git/config` L1014, `= /.git/HEAD` L1019). nginx exact-match wins over prefix, so the two real files still proxy while `/.git/logs/HEAD`, `/.git/index`, `/.git/objects/*` return a consistent 404 instead of HTTP 200 + SPA shell. The old line-1029 "SPA NotFoundPage is acceptable" framing is gone, replaced by the correct fingerprint rationale. Crown-jewel kill-chain entry point no longer self-fingerprints to git-dumper recon. |
| EXTRA-1 — provision_workspace executor | PASS | §11.4 extracts sync `_run_provision_workspace_sync()` (L1306); `_provision_workspace` (L1340 async) calls it via `await loop.run_in_executor(None, _run_provision_workspace_sync, ...)` (L1362). The login hot-path psycopg2 work is now off the event loop. Redis distributed lock (`set(... nx=True, ex=30)`, L1355) still wraps the executor call, and `redis_client.delete(lock_key)` is in a `finally` (L1367) so the lock always releases — the executor call is correctly inside the lock-held critical section. |
| EXTRA-2 — _get_redis docstring | PASS | §3.1 L302 `def _get_redis() -> redis.asyncio.Redis:` with a docstring (L303–309) stating the return type is the async client, that the function itself is NOT a coroutine, and that every method on the returned client IS — with correct/incorrect examples. The mandatory rule at L313 enforces `await` on every call. This authoritatively resolves the Backend-12 convention conflict: `_get_redis()` is sync-returns-async-client, so call sites use `await _get_redis().get(...)` (one await on the operation, none on the getter) — exactly what §4.2 now does. |
| EXTRA-3 — scope allowlist | PASS | §4.3 L685 defines `VALID_API_KEY_SCOPES = {"read:all", "write:models", "write:datasets", "admin"}` as a named module-level constant. L689/L710 use it to validate before the DB write and before the response echo. Validated value flows to INSERT and response identically. |

## Pre-Implementation Gate

The spec is now safe to hand to an implementer. All four Backend-12 bugs and all three extras are resolved at the mechanism level, verified line-by-line at the exact defect sites — the `await` propagation on both Redis calls landed, the `run_in_executor` wrapping landed in all three psycopg2 locations (§4.6, §11.4, §11.9 — not just the two originally reported), the nginx prefix-404 block is correctly ordered below the exact-match blocks, and the `_get_redis()` convention is now authoritatively pinned to sync-returns-async-client with all relevant call sites matching. No code-breaking or kill-chain-burning defect remains in the seven sections audited.

Two minor, non-blocking notes for the implementer to carry (neither warrants holding implementation):

1. **Residual EXTRA-2 prose drift.** §11.4 L1374 still describes the Redis client in prose as "the existing Redis async client already in scope from the v2 auth route (`await _get_redis()`)." That stray `await _get_redis()` phrasing contradicts the now-canonical §3.1 definition (the getter is NOT awaited; only its operations are). The §3.1 docstring governs and the actual code in §4.2/§11.4 is correct, so this is documentation lint, not a logic defect. Strike or reword the L1374 parenthetical during implementation so a future reader does not reintroduce a double-await on the getter.

2. **Bug 2 deviation from recommendation (recorded, accepted).** Unknown API-key scopes default to `"read:all"` rather than returning a 400 as EXTRA-3 suggested. This still closes the injection/realism surface (only allowlisted values are persisted or echoed) and is arguably the more deception-realistic behavior — a real API would not 400 a benign scope typo mid-demo. Approved as-is; flagging only so it is a conscious choice on the record.

Implementation is cleared to proceed. No Backend-14 confirmation read is required for these seven items — they are verified landed. Open a new round only if a NEW defect class surfaces during implementation.

---

# Gatekeeper Audit — Checkpoint Download Lure (Runs Page)
**Round: Backend-14**
**Date: 2026-06-12**
**Verdict: CONDITIONAL PASS — wire the button, but four mandatory fixes must land first; two of the plan's prescribed steps will actively damage the live system if implemented as written.**

Scope of this read: `slapdash-backend.md` "Checkpoint Download — Implementation Plan" (§1–§10), validated line-by-line against the **live** `main.py` (not the plan's quoted line numbers — they are stale), `RunsTable.tsx`, and `runs.tsx`. The plan is labelled "pre-implementation," but large parts of the v2 stack it describes are ALREADY DEPLOYED in `main.py` (32 `/api/v2/` routes, `_v2_session_required`, `_COOKIE_NAME_V2`, `_push_honeydash_async` Data-Exfil block, `_BACKUP_TARBALL_BYTES`, `_INVOICE_PDF_BYTES`). This plan must be read as an *addition* to a running system, and two of its instructions contradict what that system already does.

---

## What the plan gets right

These are specific, load-bearing decisions that are correct — not generic praise:

1. **Rejecting the ELF stub for the checkpoint is correct.** `_CHECKPOINT_STUB_BIN` (live, line 966) genuinely opens with `\x7fELF` — `file(1)` fingerprints it as `ELF 64-bit LSB executable`, which is an instant cover-break for anything claiming to be a `torch.save()` artifact. Real PyTorch `.bin` checkpoints are ZIP-wrapped pickle archives (PK magic) or raw pickle. Moving to a pickle-protocol-2 header (`\x80\x02`) is the right instinct.
2. **Pickle-as-tripwire reasoning is sound.** The DNS canarytoken fires on hostname *resolution*, which `strings(1)`, `grep`, `torch.load`, AV detonation, and any URL-extraction tool all trigger before any HTTP fetch. That is a legitimately broad trigger surface.
3. **Shared-bytes / parameterised-filename decision (§7) is correct.** Per-run pickle generation buys zero deception and costs CPU on every fuzz request. Static bytes + `run_id` in the `Content-Disposition` filename + `run_id` captured in the event payload is the right trade.
4. **Reusing the existing `/api/v1/canarytoken/callback` (§6) is correct** — it already emits `http.canarytoken.fired`, pushes HoneyDash with `"Canarytoken Fired"`, and that event is in sentinel's `_NO_COOLDOWN_EVENTS` (confirmed live, sentinel.py line ~102). No callback change needed. The memo-attribution gap is correctly flagged as acceptable.
5. **Credential consistency inside the pickle is good tradecraft.** Reusing `AKIAYZM57LXRGIYTCOUV` (the live AWS canarytoken), `neuro-train-01.internal`, `neuro-svc`, and `NeuroML2024!` keeps the checkpoint consistent with the SSH honeyfs and the Slack-logs lure — a cross-surface attacker sees one coherent story.

---

## MANDATORY FIXES (blocking — must resolve before any code is written)

### MF-1 — DUPLICATE HoneyDash push. The plan's §4 will double-count every checkpoint download.
The plan instructs (§4, §8) to add an explicit `asyncio.create_task(_push_honeydash_async(checkpoint_event, "Data Exfil"))` inside the handler. **This is wrong.** When the response carries `X-Lure-Data-Exfil: true`, the live middleware (line 627–629) sets `snare_attack_type = "Data Exfil"`, and at line 680–683 `if snare_attack_type:` the middleware ALREADY fires `_push_honeydash_async(event, "Data Exfil")`. Adding the explicit push produces **two** HoneyDash "Data Exfil" cards per single download — one from the middleware event, one from the handler's hand-built event. The existing `v2_artifacts_download` and `v2_billing_invoice` routes (both live) prove the correct pattern: they set `X-Lure-Data-Exfil: true` and make **no** explicit HoneyDash call. **Fix:** delete the explicit `_push_honeydash_async` from the handler entirely. The middleware owns the HoneyDash push for `X-Lure-Data-Exfil` routes.

### MF-2 — DO NOT add `/api/v2/runs` to `_LURE_PATHS`. It poisons the entire authenticated runs listing.
The plan (§3, §8, §9) instructs adding `"/api/v2/runs"` to `_LURE_PATHS`. The live `is_lure` check is `any(path.startswith(p) for p in _LURE_PATHS)` (line 577). `"/api/v2/runs"` prefix-matches **`GET /api/v2/runs`** — the legitimate, high-frequency runs-listing endpoint the SPA calls on every Runs page mount (`fetchRuns` in runs.tsx). Consequences on the live system:
   - Every legit runs-list fetch gets `X-Debug-Mode: enabled` (line 700) — a gratuitous fingerprint tell on a normal authenticated API call.
   - Every legit runs-list fetch triggers `_push_honeydash_async(event, "Lure Access")` (line 684) — flooding HoneyDash with false "Lure Access" cards on benign navigation.
   - The plan's own justification ("the runs listing is authenticated and low-value, so being in `_LURE_PATHS` only means it gets `X-Debug-Mode`... acceptable") is **wrong** — it is not acceptable; it manufactures noise and a tell on the most-hit v2 endpoint.

   The plan also misunderstands *why* it wanted this. `X-Lure-Data-Exfil` already forces `event_type = http.lure.data_exfil` regardless of `_LURE_PATHS` membership (middleware priority chain, line 623–629). The checkpoint download does NOT need to be in `_LURE_PATHS` to be logged or alerted correctly — the header does all the work, exactly as it does for `v2_artifacts_download` (which is NOT in `_LURE_PATHS`). **Fix:** drop the `_LURE_PATHS` change entirely. It is unnecessary and harmful.

### MF-3 — Unvalidated `run_id` in `Content-Disposition` filename and payload. Header-injection / filename-spoof vector + inconsistent with the project's own safe pattern.
The handler builds `filename = f"checkpoint-{run_id}-latest.bin"` from the raw, attacker-controlled path segment and reflects it into a response header and into the logged payload. `run_id` is a free-form path parameter — an attacker requests `/api/v2/runs/<anything>/checkpoint`. Reflecting unsanitised input into `Content-Disposition` is a textbook header-injection / content-spoofing surface (quote-breakout, CR/LF if the ASGI layer ever lets it through, misleading filenames like `checkpoint-invoice.pdf.bin`). The project **already solved this** one route away: `v2_billing_invoice` (live, line 4899) regex-validates its path param into `safe_id = invoice_id if re.match(r"^INV-\d{4}-\d{3}$", invoice_id) else "INV-2026-001"` *specifically* before putting it in `Content-Disposition`. The checkpoint route must follow the same pattern. **Fix:** validate `run_id` against the known run-ID shape before use, e.g. `safe_run_id = run_id if re.match(r"^run-\d{8}-\d{3}$", run_id) else "run-latest"`. Use `safe_run_id` in both the filename and the payload. This also improves deception: a real platform returns a canonical filename, not an echo of whatever garbage was in the URL.

### MF-4 — Supplementary `http.lure.checkpoint_downloaded` event is redundant noise and is NOT in `_NO_COOLDOWN_EVENTS`, contradicting the plan's own alerting goal.
The plan (§3, §8, §10) adds a second hand-built event `http.lure.checkpoint_downloaded` solely to carry `run_id`. This is unnecessary and creates a divergence:
   - The middleware's `http.lure.data_exfil` event already captures `path` (which contains `run_id`), `query_params`, `method`, `body_preview`, `status_code`, full headers in `raw_log`, geo, and `session_id`. The `run_id` is already in `payload.path` and `raw_log.path`. A separate event to "carry run_id" duplicates data already recorded.
   - §10 admits `http.lure.checkpoint_downloaded` is NOT in `_NO_COOLDOWN_EVENTS` and is subject to the 300s `http.sensitive` cooldown. So under a fuzz/replay burst the supplementary events get suppressed anyway — they add PostgreSQL row volume without adding alert value.
   - Worse, it doubles the row count for every checkpoint download (one `http.lure.data_exfil` from middleware + one `http.lure.checkpoint_downloaded` from handler), inflating session `event_count` and skewing the per-session intel.

   **Fix (choose one):**
   - **Preferred — drop the supplementary event entirely.** The middleware's `http.lure.data_exfil` already records `run_id` via `payload.path`. If you want `run_id` as a first-class field, that is a forensic nicety, not a requirement.
   - **If product genuinely needs a discrete checkpoint-download event type:** keep ONE event only — do not also rely on the middleware. That means dropping the `X-Lure-Data-Exfil` header and emitting `http.lure.checkpoint_downloaded` explicitly, AND adding that string to sentinel's `_NO_COOLDOWN_EVENTS` so it actually alerts. You cannot have it both ways (header + supplementary) without double-logging. The cleaner choice is the header path (preferred), which reuses the already-wired, already-no-cooldown `http.lure.data_exfil`.

   Note on the hand-built dict: if you keep ANY explicit `_log_event_async` call, the event dict must supply every column `_log_event` inserts — `event_id, created_at, sensor, event_type, src_ip, src_port, dst_port, username, password, payload, raw_log, session_id` plus the five `geo_*` keys. The plan's dict spreads `**_lookup_geo(src_ip)` (correct — that returns exactly the five geo keys) but omits `raw_log` is set to `None` (acceptable) — verify against the live INSERT (line 379–392) before writing. The `session_id` fallback `request.cookies.get(_COOKIE_NAME_V2) or str(uuid.uuid4())` is fine but note that on an *authenticated* download `_COOKIE_NAME_V2` is guaranteed present (the route is session-gated), so the `uuid4()` branch is dead — harmless.

---

## Deception gaps (blocking for believability — fold into MF set)

### DG-1 — The 2 MB tail is `\x00 * 2MB`. A real `torch.save()` checkpoint is never 2 MB of nulls.
`torch.load()` on this file will **fail** the moment an attacker actually tries to load it: the bytes after the single pickle STOP opcode (`.`) are 2 MB of `\x00`, which is not a valid continuation of either a raw pickle stream or a ZIP-wrapped torch archive. `torch.load` will either raise `UnpicklingError`/`EOFError` or load a bare string `"neuro-checkpoint\nmodel=..."` and then the attacker sees it is obviously a planted credential file, not a model. `strings`/`grep` extraction still works (so the canary still fires for tooling that scrubs for URLs), but a *human* attacker who runs `python -c "import torch; torch.load('checkpoint-...bin')"` gets an immediate "this is fake" signal. That is acceptable ONLY if you accept the file is a one-shot canary, not a believable model. Two honest options:
   - **Accept it as a pure canary** (the URL-extraction trigger is the whole point) and shrink the tail to something defensible — 2 MB of pure nulls is itself a tell (`file`/entropy analysis shows zero-entropy padding). Even 64 KB of pseudo-random bytes reads more like compressed tensor data than 2 MB of nulls.
   - **Make it survive a `torch.load()` glance:** wrap the payload as a real (tiny) ZIP-format torch archive so the magic bytes and structure pass a cursory `file` + load check. Higher effort; only worth it if the threat model includes attackers who actually deserialise loot. Given this is a download-and-walk-away lure feeding a DNS canary, option 1 is sufficient — but **stop calling it a believable PyTorch checkpoint in the plan.** It is a canary file with a pickle header. Size it and document it as such.

### DG-2 — `Content-Type` is correct but the response is missing `Content-Length` realism and the 2 MB null tail makes the on-wire body trivially compressible. Minor relative to DG-1; rolls up into the DG-1 size decision.

---

## Minor issues (non-blocking, fix in passing)

- **MI-1 — Stale line numbers throughout the plan.** Every `main.py` line reference in the plan (565–568, 685–688, 252, 477, 966, 1087, 2456, ~4095, ~249) is wrong against the live file. The middleware lure-header read is at 567, the HoneyDash push block at 680–689, `_CHECKPOINT_STUB_BIN` at 966, the callback at ~2490, the v2 runs route at 4048. Locate edit sites by content, not line number (project rule). Not a logic defect, but it will mislead the implementer.
- **MI-2 — `_build_checkpoint_v2_bin` does `import struct` inside the function.** Harmless but inconsistent with the file's top-of-module import convention. Move `struct` to module imports or leave it — cosmetic.
- **MI-3 — Frontend `window.location.href` (§5) is the right call** for a `Content-Disposition: attachment` download (browser handles save dialog, cookie auto-attached same-origin). One caveat: if `_v2_session_required` 401s (expired session), `window.location.href` navigates the whole SPA to a raw JSON 401 body, blanking the app. Low-stakes for a honeypot (the attacker is authenticated by the time they reach RunDetail), but a `fetch`-with-blob fallback that checks `res.ok` would degrade more gracefully. Acceptable as-is; noting for polish.
- **MI-4 — Memo attribution (§6).** Correctly flagged. If per-file attribution ever matters, register a second DNS canarytoken with a checkpoint-specific memo and point `_CHECKPOINT_CANARY_URL` at it. Not blocking.

---

## Implementation order (execute in this exact sequence — do not deviate)

The live system is serving real attacker traffic. Every change below is additive and must not touch the middleware, `_LURE_PATHS`, or existing routes.

1. **Backend, `main.py` — add the canary file bytes (no route yet).** Define `_CHECKPOINT_CANARY_URL` (reuse the live DNS token `zy2s1wepypyvizi06loltahwj.canarytokens.com`) and `_build_checkpoint_v2_bin()` / `_CHECKPOINT_V2_BIN` near the existing `_CHECKPOINT_STUB_BIN` (line 966). Apply **DG-1**: size the null/random tail sensibly and document it as a canary file, not a loadable model. Do **not** modify `_CHECKPOINT_STUB_BIN` or `_LURE_FILE_REGISTRY`.
2. **Backend, `main.py` — add the route `GET /api/v2/runs/{run_id}/checkpoint`** immediately after `v2_get_runs()` (live line 4048+). Implement it to mirror `v2_artifacts_download` / `v2_billing_invoice` exactly:
   - `await _v2_session_required(request)` (session gate).
   - Apply **MF-3**: `safe_run_id = run_id if re.match(r"^run-\d{8}-\d{3}$", run_id) else "run-latest"`.
   - Return `Response(content=_CHECKPOINT_V2_BIN, media_type="application/octet-stream", headers={"Content-Disposition": f'attachment; filename="checkpoint-{safe_run_id}-latest.bin"', "X-Lure-Data-Exfil": "true"})`.
   - Apply **MF-1 + MF-4**: NO explicit `_push_honeydash_async`, NO supplementary `_log_event_async`, NO `http.lure.checkpoint_downloaded`. The `X-Lure-Data-Exfil` header alone drives `http.lure.data_exfil` (no-cooldown, HoneyDash "Data Exfil") via the middleware.
   - Apply **MF-2**: do NOT touch `_LURE_PATHS`.
3. **Verify backend in isolation** (curl, authenticated session) BEFORE wiring the frontend:
   - `curl` with a valid `nro_session_v2` cookie → 200, `Content-Disposition` filename correct, body starts with `\x80\x02`, AWS key + canary URL present in `strings` output.
   - Confirm exactly **one** `http.lure.data_exfil` row per download in PostgreSQL (not two), `payload.path` contains the run_id.
   - Confirm `curl` with a garbage run_id (`/api/v2/runs/$(id)/checkpoint`) returns filename `checkpoint-run-latest-latest.bin` (sanitised), not the injected string.
   - Confirm `curl` without a session → 401 (gate works) and the middleware still logs the unauth attempt.
   - If `HONEYDASH_URL` is set: confirm exactly **one** "Data Exfil" card in HoneyDash, not two.
4. **Rebuild + verify-module-6 stays 10/10**, vocabulary gate clean (no new defender vocab introduced — the new constants use `metrics_endpoint`/`checkpoint` naming, which is safe).
5. **Frontend, `RunsTable.tsx` line 175** — wire the inert button last, only after the backend is confirmed:
   `onClick={() => { window.location.href = `/api/v2/runs/${run.id}/checkpoint`; }}`. `run.id` is the adapted `run_id` (adaptRun, line 32). No telemetry beacon (the backend event is sufficient and a beacon races the download — the plan is right on this).
6. **End-to-end** in a browser: open a run detail, click Download checkpoint, confirm the file saves with the run-specific name, confirm the single Telegram alert fires, confirm the DNS canary fires when the file is opened/scanned on a clean test box.

**Re-submit for a Backend-15 confirmation read** the patched §3/§4/§7/§8/§10 once MF-1 through MF-4 and DG-1 are reflected in the plan text. I want to confirm the explicit HoneyDash push is struck, the `_LURE_PATHS` edit is struck, the `run_id` sanitisation is added, and the supplementary-event decision is resolved to a single logging path — these are mechanism-level corrections, and I verify landed mechanism, not edited prose.

---

---

# Round Backend-15 — Checkpoint Download Feature: Final Code Review (2026-06-12)

**Scope:** Live code review of the implemented `GET /api/v2/runs/{run_id}/checkpoint` feature — NOT a plan read. Reviewed `main.py` (lines 979–1023, 4144–4170), middleware lure path (560–699), `RunsTable.tsx`, and the built SPA bundle in `Slapdash-web/dist/`.

## VERDICT: **PASS**

The implementation landed every mechanism-level correction from Round Backend-14. I verified the landed mechanism, not the prose. All four MF mandates and DG-1 are resolved in the actual code. The button is wired and shipped in the build. No new blocking issues.

---

## MF / DG resolution confirmation (verified against live code)

### MF-1 — NO explicit `_push_honeydash_async` in the handler. **RESOLVED.**
`v2_run_checkpoint_download` (main.py:4144–4170) contains zero executable `_push_honeydash_async` calls. The only occurrence of that string in the route is inside the docstring (line 4157), describing that the middleware fires it automatically. Confirmed: the middleware HoneyDash push at lines 680–683 fires on `snare_attack_type`, and `_lure_data_exfil` sets `snare_attack_type = "Data Exfil"` (line 629). So exactly one "Data Exfil" push happens, driven by the `X-Lure-Data-Exfil` header — the single-path design the prior round demanded.

### MF-2 — `_LURE_PATHS` NOT modified. **RESOLVED.**
`_LURE_PATHS` (main.py:232–251) does not contain `/api/v2/runs` or any checkpoint path. The checkpoint route correctly drives its event type through the `X-Lure-Data-Exfil` response header (line 4168), which the middleware reads at line 567 and maps to `http.lure.data_exfil` at lines 627–629 — independent of `_LURE_PATHS`. No `is_lure` double-classification.

### MF-3 — `run_id` sanitised before Content-Disposition. **RESOLVED.**
main.py:4162: `safe_run_id = run_id if re.match(r"^[a-zA-Z0-9._-]{1,64}$", run_id) else "run-latest"`. The sanitised value (not the raw path segment) is interpolated into the filename at line 4167. `re` is imported (main.py:3028) and in scope at line 4144. Header/response-splitting via CRLF or quote-breakout in `run_id` is neutralised — any non-conforming input collapses to `run-latest`.
   - Note: the regex is broader than the `^run-\d{8}-\d{3}$` the prior round suggested, but it is strictly a character-class allowlist (`[a-zA-Z0-9._-]`, length-bounded 1–64). It excludes CR, LF, `"`, `;`, space, and `/`, so it is injection-safe for a `Content-Disposition` filename. Acceptable — the looser pattern is more forgiving of legitimate run-id formats while remaining safe.

### MF-4 — No supplementary `http.lure.checkpoint_downloaded` event. **RESOLVED.**
`grep "checkpoint_downloaded"` across `main.py` returns zero matches. The handler emits no explicit `_log_event_async`. There is exactly one event per download (`http.lure.data_exfil` from middleware). No row-count doubling, no session `event_count` inflation. The preferred option from Round Backend-14 was taken.

### DG-1 — Canary tail entropy. **RESOLVED.**
main.py:1019: `tail = os.urandom(64 * 1024)` — the exact "64 KB of pseudo-random bytes" the prior round recommended. Measured Shannon entropy of an equivalent tail: **7.998 bits/byte** (max 8.0), trailing bytes contain zero nulls. `file(1)`/entropy analysis reads this as compressed-tensor-like data, not zero-entropy null padding. The docstring (main.py:983–994) now honestly documents this as a **canary file, not a loadable PyTorch model** — DG-1's documentation requirement is met.
   - The DNS canarytoken URL `http://zy2s1wepypyvizi06loltahwj.canarytokens.com/v1/metrics` is embedded verbatim in the UTF-8 payload (main.py:979, interpolated at line 1009), extractable by `strings`/`grep` and deserialisable by `pickle.loads` (protocol-2 BINUNICODE framing, main.py:1017). Live AWS canarytoken `AKIAYZM57LXRGIYTCOUV` is also embedded (line 1004) — dual tripwire confirmed.

---

## Frontend + build verification

- **RunsTable.tsx:175–180** — Download button is wired, NOT inert: `onClick={() => { window.location.href = \`/api/v2/runs/${run.id}/checkpoint\`; }}`. Correct endpoint, `run.id` resolves via `adaptRun` (line 33: `r.run_id ?? r.id ?? "—"`). `window.location.href` is the right call for a `Content-Disposition: attachment` download (same-origin cookie auto-attaches).
- **Build succeeded.** `Slapdash-web/dist/` has fresh artifacts (built 03:31, 2026-06-12). The compiled bundle `dist/assets/RunsTable-CVFdbAOW.js` contains both the `checkpoint` string and the templated endpoint `api/v2/runs/${s.id}/checkpoint` (minified var name) — the new code is in the shipped build, not just source.
- **Vocabulary gate clean.** No defender vocab in `RunsTable.tsx`. The two `canvas` hits are CSS custom properties (`var(--canvas)`), not `canvasFingerprint` — not a violation.

---

## NEW issues found in the actual implementation

None blocking. Two non-blocking observations:

- **NI-1 (non-blocking) — `window.location.href` on an expired session blanks the SPA.** If `_v2_session_required` 401s mid-session, the browser navigates to a raw JSON 401 body and the React app is replaced by JSON text. Low-stakes for a honeypot (the attacker is authenticated by the time they reach RunDetail, and a confused attacker who has to re-login is not a deception failure), but a `fetch`-with-blob fallback checking `res.ok` would degrade more gracefully. Carry-over of MI-3 from Backend-14. Acceptable as shipped.
- **NI-2 (cosmetic) — `import struct` inside `_build_checkpoint_v2_bin` (main.py:996).** Inconsistent with the file's top-of-module import convention but harmless (carry-over of MI-2). `re` is likewise imported deep at line 3028 rather than the top — in scope at the call site, so no defect, but worth consolidating in a future cleanup pass.

---

## DEPLOY COMMANDS (operator — run in this order)

The live system is serving real attacker traffic. These changes are additive (new route + new frontend button). The middleware, `_LURE_PATHS`, and existing routes are untouched.

### 1. Deploy backend (main.py)
```bash
# From repo root on the dev box:
scp -P 22704 deploy/module-6-honeypot-api/src/main.py honeypot@158.220.110.47:/tmp/

# On VPS:
sudo chmod 666 /opt/honeypot/deploy/module-6-honeypot-api/src/main.py
sudo cp /tmp/main.py /opt/honeypot/deploy/module-6-honeypot-api/src/main.py
sudo chown root:root /opt/honeypot/deploy/module-6-honeypot-api/src/main.py

cd /opt/honeypot/deploy/module-6-honeypot-api/
docker compose up -d --build --force-recreate
bash verify-module-6.sh   # must stay 10/10
```

### 2. Deploy frontend SPA build (dist/)
```bash
# From dev box — ship the BUILT dist, not the source (SPA is pre-built, baked into the image):
scp -P 22704 -r Slapdash-web/dist/* honeypot@158.220.110.47:/tmp/slapdash-dist/
# (create /tmp/slapdash-dist first on the VPS if scp -r needs it: ssh ... 'mkdir -p /tmp/slapdash-dist')

# On VPS — replace the served SPA assets (path per however the SPA is mounted into honeypot-api/nginx;
# confirm the live static-root before copying):
sudo cp -r /tmp/slapdash-dist/* /opt/honeypot/deploy/module-6-honeypot-api/src/static-spa/   # ADJUST PATH to live SPA root
sudo chown -R root:root /opt/honeypot/deploy/module-6-honeypot-api/src/static-spa/

cd /opt/honeypot/deploy/module-6-honeypot-api/
docker compose up -d --build --force-recreate
```
> Operator: confirm the live SPA static root before copying (`docker exec honeypot-api ls <static-root>`). If the SPA is served by nginx rather than honeypot-api, copy to the nginx static root instead and skip the rebuild for the frontend step.

### 3. Nginx reload (only if the SPA is served by nginx / any proxied container was force-recreated)
```bash
docker exec nginx openresty -s reload
```

### 4. Post-deploy verification (authenticated session required)
```bash
# Authenticated download → 200, octet-stream, run-specific filename, body starts with \x80\x02:
curl -s -i -b 'nro_session_v2=<VALID_SESSION_ID>' \
  "http://127.0.0.1:8080/api/v2/runs/run-20260612-001/checkpoint" | head -20

# Path-injection neutralised → filename collapses to checkpoint-run-latest-latest.bin:
curl -s -i -b 'nro_session_v2=<VALID_SESSION_ID>' \
  --data-urlencode 'x=' "http://127.0.0.1:8080/api/v2/runs/%24%28id%29/checkpoint" | grep -i content-disposition

# No session → 401 (gate works, middleware still logs the unauth hit):
curl -s -o /dev/null -w '%{http_code}\n' "http://127.0.0.1:8080/api/v2/runs/run-x/checkpoint"

# Canary + AWS key present in extracted strings:
curl -s -b 'nro_session_v2=<VALID_SESSION_ID>' \
  "http://127.0.0.1:8080/api/v2/runs/run-20260612-001/checkpoint" -o /tmp/ckpt.bin
strings /tmp/ckpt.bin | grep -E 'canarytokens|AKIA'   # must show DNS URL + AWS key

# Exactly ONE event per download (not two):
docker exec postgres psql -U honeypot -d honeypot \
  -c "SELECT event_type, COUNT(*) FROM honeypot_events WHERE event_type LIKE 'http.lure%' AND created_at > now() - interval '5 min' GROUP BY event_type;"
# Expect: one http.lure.data_exfil row per download, zero http.lure.checkpoint_downloaded.
```

### 5. End-to-end browser check
Open a run detail panel → click **Download checkpoint** → confirm the file saves as `checkpoint-<run_id>-latest.bin`, one Telegram "Data Exfil" alert fires, and the DNS canary fires when the file is opened/scanned on a clean test box.

---

**Net:** Feature is production-ready. PASS. No re-submission required. Ship per the commands above; the only operator judgement call is confirming the live SPA static root in step 2.

---

# Round Backend-16 — Rev 12 Custom Webhook Integration Bug Fixes: Gatekeeper Review (2026-06-12)

**Reviewed**: `slapdash-backend.md` Rev 12 (lines 2222–2503) against live `deploy/module-6-honeypot-api/src/main.py`.

**Verdict: CONDITIONAL PASS.** Bugs 1, 2, and 4 are correct and ship-ready as written. **Bug 3's fix as written is broken — it will silently never push to HoneyDash because the `ssrf_hd_event` dict is missing the mandatory `created_at` key that `_push_honeydash_async()` subscripts unconditionally.** One mandatory fix, two recommended hardenings, and one factual correction to the plan's premise. The implementing agent MUST apply MANDATORY-1 before touching code.

---

## Line-number reconciliation (verified against live code)

Plan cites are accurate within ±1 line. Confirmed live:
- `_classify_webhook_url` at `main.py:3855`; `except ValueError` block at `3868–3871` (plan says 3869–3871 — off by one, content matches exactly).
- `v2_webhook_test` at `main.py:4785`; `_log_event` event_type at `4806`; three returns at `4819–4837`. All match the plan's quoted old code byte-for-byte.

The plan was written against the real current file. Good.

---

## CRITICAL FAILURE (Bug 3 — MANDATORY-1)

**The Bug 3 fix as written never pushes to HoneyDash. It re-implements the exact bug it claims to fix, just silently.**

Plan lines 2329–2336 construct a minimal dict:
```python
ssrf_hd_event = {
    "event_id": ...,
    "sensor": "api",
    "event_type": "http.snare.ssrf_attempt",
    "src_ip": src_ip,
    "payload": json.dumps({...}),
}
asyncio.create_task(_push_honeydash_async(ssrf_hd_event, "SSRF Attempt"))
```

But `_push_honeydash_async()` at `main.py:1101` does:
```python
"timestamp": event["created_at"].strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
```
and at `main.py:1111–1112`:
```python
"session": hashlib.md5(
    f"{event.get('src_ip','')}-{event['created_at'].strftime('%Y-%m-%d')}".encode()
)...
```

`event["created_at"]` is a **bare subscript, not `.get()`**, called **twice**, with `.strftime()` invoked on the result. The plan's `ssrf_hd_event` has no `created_at` key → `KeyError: 'created_at'`. That exception is swallowed by the broad `except Exception` at `main.py:1156`, logged as `honeydash_push_error`, and the push aborts. Net effect: PostgreSQL logging works (Bug 2), but **HoneyDash still gets nothing** — Bug 3 is not actually fixed. The "SSRF Attempt" card the plan promises in its verify step (plan line 2345) will never appear. The validation command at plan line 2489 will return empty, and a careless operator might pass it off as "no SSRF hit yet."

**The fix is already in the same file, twice, done correctly. Copy the sibling pattern, do not invent a new dict.**

The canonical correct pattern is `v2_data_import` at `main.py:4543–4562`:
```python
event_type = "http.snare.ssrf_attempt" if is_ssrf else "http.probe.remote_import"
ev = {
    "event_id": str(uuid.uuid4()),
    "created_at": datetime.now(timezone.utc),
    "sensor": "api",
    "event_type": event_type,
    "src_ip": src_ip,
    "src_port": request.client.port if request.client else None,
    "dst_port": 8080,
    "username": session.get("email"),
    "password": None,
    "payload": json.dumps({...,"ssrf_detected": is_ssrf}),
    "raw_log": None,
    "session_id": request.cookies.get("nro_session") or str(uuid.uuid4()),
    **_lookup_geo(src_ip),
}
_log_event(ev)
if is_ssrf and HONEYDASH_URL and SENSOR_API_KEY:
    asyncio.create_task(_push_honeydash_async(ev, "SSRF Attempt"))
```

**MANDATORY-1**: Rewrite Bugs 2 + 3 together as a single change in `v2_webhook_test`. Build ONE complete event dict (the existing `_log_event({...})` at 4802–4817 is already complete and has `created_at`, `src_port`, `dst_port`, geo fields). Hoist it into a named variable `ev`, apply the Bug 2 conditional event_type to it, pass `ev` to `_log_event(ev)`, then immediately after add:
```python
if is_ssrf and HONEYDASH_URL and SENSOR_API_KEY:
    asyncio.create_task(_push_honeydash_async(ev, "SSRF Attempt"))
```
Do NOT build a second `ssrf_hd_event` dict. Reusing the already-complete `ev` guarantees `created_at` is present and means the HoneyDash `input`/`path` enrichment (`_SNARE_ATTACK_TYPES_FOR_INPUT` includes `"SSRF Attempt"`, `main.py:759`) has the full payload to read from. The plan's minimal payload (`webhook_url` + `classification` only) would leave HoneyDash's `input` field null even if `created_at` were fixed.

---

## FACTUAL CORRECTION TO THE PLAN (not a blocker, but fix the doc)

Plan line 2322 states: *"the equivalent v1 handler at `/api/v1/integrations/webhook/test` does push to HoneyDash. The omission means..."* — and presents the v1 handler as the reference.

This is **wrong about the v1 webhook handler**. The actual v1 webhook handler is `webhook_test` at `main.py:2141–2190`. It calls only `_log_event(...)` and does **NOT** call `_push_honeydash_async` at all. So the plan's stated justification ("be consistent with v1") is based on a handler that doesn't do what the plan claims.

The correct reference — and it strengthens the case, doesn't weaken it — is **`v2_data_import` at `main.py:4526–4562`**, the v2 sibling SSRF trap, which DOES push correctly with the full-`ev` pattern and the `is_ssrf and HONEYDASH_URL and SENSOR_API_KEY` guard. Point the plan at that handler. The fix is still correct in intent; only the cited precedent is wrong.

---

## Check-by-check against the brief

**1. Does `_INTERNAL_TLDS` cover `hooks.vantarahealth.internal`? — YES.**
`host.endswith(".internal")` matches `hooks.vantarahealth.internal`. The classifier reaches the `except ValueError` branch because `ipaddress.ip_address("hooks.vantarahealth.internal")` raises `ValueError` (confirmed: it is a hostname, not an IP). `.local/.corp/.intranet/.lan` are sensible additions. No issue.
> Minor robustness note (NON-BLOCKING): `parsed.hostname` from `urllib.parse` is already lowercased, so the `endswith` comparison is safe against `.INTERNAL`. But a trailing-dot FQDN (`hooks.vantarahealth.internal.`) would NOT match `.endswith(".internal")`. This is an edge case an attacker is vanishly unlikely to type into a webhook UI field, and the `_SSRF_PATTERNS` second clause on line 4798–4800 does not cover it either. Acceptable to ship; note it.

**2. Is the event_type ternary safe — does it preserve `ssrf_detected`? — YES.**
The Bug 2 change touches only the `event_type` value. The `payload` JSON still carries `"ssrf_detected": is_ssrf` (live line 4813). Any PostgreSQL/CTI query filtering on `payload->>'ssrf_detected'` continues to work for both event types. Correct. The plan's reasoning at line 2310 is sound.

**3. Is `create_task(...)` placed BEFORE the return branches? — YES in the plan's intent, and MANDATORY-1 enforces it.**
Plan line 2339 explicitly requires placement after `_log_event` and before `if classification == "internal":` (live line 4819). This is correct and necessary: an external-classified URL with an SSRF pattern (e.g. `http://169.254.169.254@evil.com/`) sets `is_ssrf=True` via the second clause of line 4798–4800 while `classification=="external"`. Placing the push inside the `internal` branch would miss it. The `if is_ssrf:` guard (not `if classification=="internal":`) is the right condition. Good catch by the planner.

**4. Does HTTP-200 normalisation preserve all lure fields across all three branches? — YES.**
Bug 4 changes only `status_code=502→200` and `504→200`. Response bodies are byte-identical. The `relay_node: "10.31.4.22"` leak survives in both failed branches; `relay: "http://10.31.4.22:3128/"` and `latency_ms` survive in the external branch. The lure payload is fully preserved. Correct.

**5. Deception gap — does an internal-URL submitter get a convincing "we tried to connect" response? — ADEQUATE, with one observation.**
`{"status":"failed","error":"connection_refused","relay_node":"10.31.4.22"}` is a plausible outbound-relay failure and leaks the management-plane IP as bait — consistent with the established kill-chain herding toward `10.31.4.22`. This reads as "our relay tried and the target refused," which is what a real egress proxy would report for an unreachable internal host.
> OBSERVATION (NON-BLOCKING, deception consistency): the existing `await asyncio.sleep(random.uniform(0.6,1.2))` at line 4795 fires BEFORE classification, so the `connection_refused` response returns after the same ~0.6–1.2s as a "delivered" success. A real `connection_refused` to an internal host is typically near-instant (RST), whereas a `timeout` (the `invalid` branch) should take longer. Right now all three branches share one pre-classification jitter. Not a ship-blocker — sub-second timing on a single manual webhook test is not a fingerprint an attacker will reliably exploit — but if you ever want to tighten it: return `connection_refused` fast and make the `timeout` branch sleep longer. Do not block Rev 12 on this; note for a future deception-polish round.

**6. Is the `HONEYDASH_URL and SENSOR_API_KEY` guard included on the push? — NO in the plan as written; MANDATORY-2.**
Plan line 2336 calls `asyncio.create_task(_push_honeydash_async(ssrf_hd_event, "SSRF Attempt"))` with NO `HONEYDASH_URL and SENSOR_API_KEY` guard. Every other guarded call site in main.py wraps the push in that condition (e.g. `4561`, `3930`, `3999`, `2598`, `2726`). `_push_honeydash_async` does early-return internally if the vars are empty (line 1087), so an unguarded call is not a *crash* — but it is an inconsistency that (a) schedules a needless task and (b) breaks the project's own convention.
**MANDATORY-2**: include the guard: `if is_ssrf and HONEYDASH_URL and SENSOR_API_KEY:`. This is automatically satisfied if you implement MANDATORY-1 by copying the `v2_data_import` pattern.

---

## Bug 4 — frontend premise verified, fix strategy endorsed

Confirmed `Slapdash-web/src/lib/api/client.ts` `apiFetch` throws on `!res.ok` (lines 18–25 in the live file). The 502/504 returns DO cause the throw, `testMutation.data` stays null, and `WebhookCard` renders nothing — the plan's diagnosis is accurate. The backend-only normalisation to HTTP 200 is the **correct** fix: changing `apiFetch` to stop throwing would force an audit of 20+ call sites that depend on the throw for 401/403 redirect/role-gating logic (e.g. `GET /api/v2/auth/me`). Targeted, low-blast-radius, correct. Endorsed as written.

---

## What a real attacker sees after the (corrected) fix

Submits `https://hooks.vantarahealth.internal/neuro/events` → classified `internal` → `is_ssrf=True` → PostgreSQL logs `http.snare.ssrf_attempt` with full payload → HoneyDash "SSRF Attempt" card fires (ONLY after MANDATORY-1) → HTTP 200 `{"status":"failed","error":"connection_refused","relay_node":"10.31.4.22"}` renders in the UI `<pre>` block. The attacker reads it as a real failed outbound relay attempt and is herded toward the `10.31.4.22` management-plane IP. Convincing. Submits `https://hooks.acme.com/neuro` → `http.webhook.test` (low-value, suppresses normally, no false SSRF alert) → HTTP 200 delivered with `relay` lure visible. Both paths land correctly.

---

## Mandatory fixes before code (gate)

- **MANDATORY-1**: Implement Bugs 2+3 as a single hoisted `ev` dict reused for both `_log_event(ev)` and the HoneyDash push. Do NOT create the separate minimal `ssrf_hd_event` dict from plan lines 2329–2336 — it is missing `created_at` and will silently fail the push. Copy the `v2_data_import` pattern at `main.py:4543–4562` verbatim in structure.
- **MANDATORY-2**: Guard the push with `if is_ssrf and HONEYDASH_URL and SENSOR_API_KEY:` (satisfied automatically by MANDATORY-1).

## Recommended (non-blocking)

- **REC-1**: Correct the plan's Bug 3 precedent — the v1 `webhook_test` (`main.py:2141`) does NOT push to HoneyDash; the real precedent is v2 `v2_data_import` (`main.py:4526`).
- **REC-2**: (Future deception-polish round, not Rev 12) Per-branch timing — fast `connection_refused`, slower `timeout` — so the three responses are not all gated behind one shared pre-classification jitter.

## Re-submission

Not required as a full re-review. The implementing agent applies MANDATORY-1 + MANDATORY-2, then runs the plan's own validation commands (plan lines 2475–2497) — with the added assertion that **the HoneyDash push actually lands** (plan line 2489 must return a non-empty ssrf row, AND `docker logs log-shipper`/api logs must show no `honeydash_push_error` for the webhook event). If those pass, ship.

**Net: CONDITIONAL PASS.** Bugs 1, 2, 4 correct. Bug 3 is functionally broken as written (missing `created_at`) and must be re-implemented via the existing `v2_data_import` pattern before any code is committed.
