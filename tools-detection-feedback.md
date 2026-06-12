# Gatekeeper Feedback — Round 1

## Verdict: CONDITIONAL PASS

The architecture is sound and the deception discipline is mostly correct — tool names stay server-side, the `payload` JSONB enrichment needs no migration, and SNARE precedence is preserved. But there are **three production-stability bugs that will degrade the live 200k-event system** and **two integration anchors in the plan that do not match the actual code**, plus several signature-accuracy problems that will produce noise or false negatives. Fix the Critical items and this is a PASS.

---

## Critical Issues (must fix before implementation)

### CRIT-1 — `_check_scan_rate()` is a synchronous blocking Redis call in the async event loop, on EVERY request

The plan calls `_check_scan_rate(src_ip)` directly inline in `request_logger()` (section 5, line 469):

```python
_scan_rate_flag = _check_scan_rate(src_ip)
```

`request_logger` is `async def` (main.py:529). `_check_scan_rate` calls `_get_redis()` then runs a 4-command `pipe.execute()` synchronously. `_get_redis()` is configured with `socket_timeout=3, socket_connect_timeout=3` (main.py:204-205). **Every blocking Redis call can stall the entire event loop for up to 3 seconds.** Under a 10k-req/min scanner, or during a Redis hiccup, this serializes all request handling and reintroduces exactly the 502-under-load failure mode the CLAUDE.md HONEYDASH_URL note warns about.

Note the existing code is deliberately careful here: `_log_event_async()` wraps the synchronous Redis/PG write in `loop.run_in_executor(None, _log_event, event)` (main.py:724-727) precisely so the event loop is never blocked. The plan ignores this pattern for the rate check.

**Required fix:** Do NOT call `_check_scan_rate` synchronously in the middleware. Either:
- (a) run it in the executor: `_scan_rate_flag = await loop.run_in_executor(None, _check_scan_rate, src_ip)`, or
- (b) move the entire rate-tracking ZADD into the already-deferred `_log_event` path and read the count back asynchronously, or
- (c) use an async redis client (`redis.asyncio`) for this one path.

The "(~0.5ms on a local Redis socket)" claim in section 4 is the happy path only. The 3s timeout is the path that matters for a gatekeeper.

### CRIT-2 — Rate check fires on 100% of traffic, including healthchecks and static assets → Redis key explosion + self-inflicted noise

`_check_scan_rate` is placed unconditionally before the event_type branch, so it runs for:
- The Docker healthcheck hitting `/api/v1/health` every 30s from `127.0.0.1` (already in `_NOISE_EVENTS`)
- Every `/static/*` asset fetch — a single human loading the dashboard pulls JS/CSS/images and can trivially cross 20 requests/10s **by itself**
- Every legitimate page with multiple sub-resource requests

Two consequences:
1. **`scan_rate_exceeded: true` will be stamped on ordinary humans** loading a multi-asset page. The plan's own section 9e test ("single curl → not a scanner") passes, but a real browser loading dashboard.html with 6 static assets in <10s does not. This pollutes intelligence quality — `scan_rate_exceeded` becomes meaningless.
2. **Unbounded Redis ZSET creation.** One sorted set per distinct source IP. A scanner rotating through a /24 creates 256 keys; a botnet creates thousands. TTL is only 20s so steady-state is bounded, but the plan's Appendix A claims "No conflicts" without acknowledging that under a 10k-req/min sweep from many IPs you get continuous churn of thousands of short-lived ZSETs plus a ZADD-with-uuid member per request. On `honeypot:` namespace shared with the Cowrie stream, this is real memory pressure.

**Required fix:**
- Exclude static assets and healthchecks from rate tracking entirely (skip `_check_scan_rate` when `path.startswith("/static")` or `path == "/api/v1/health"`).
- Raise the threshold, or window the rate per-*path-class* not per-IP-flat. A scanner doing dictionary enumeration hits *distinct* paths fast; a human re-loading hits the same few. Consider counting only requests that are NOT static and NOT 2xx-on-known-page.

### CRIT-3 — Sentinel section 8d describes an insertion anchor that does not exist in the code

The plan (section 8d) says insert the dedup block "after:"

```python
            should, reason, category = _should_alert(row)
            if not should:
                continue
```

**This `if not should: continue` pattern does not exist in `sentinel.py`.** The actual main loop (sentinel.py:756-764) is:

```python
                should, reason, category = _should_alert(row)
                if should:
                    src_ip = row.get("src_ip") or ""
                    event_type = row.get("event_type", "")
                    cooldown = _HTTP_TIER_COOLDOWN.get(category, ALERT_COOLDOWN_SECS)
                    if event_type in _NO_COOLDOWN_EVENTS or not _suppressed(src_ip, category, cooldown):
                        send_alert(row, reason, category)
```

There is no early-`continue` guard. If the implementer follows the plan literally they will either fail to find the anchor or insert a `continue` that **skips the dedup-set update for the very loop they meant to dedup**, or — worse — insert it at top-of-loop and skip cursor advancement (the cursor `new_since`/`new_last_id` advances at lines 745-754, *before* `_should_alert`; an early `continue` here would NOT corrupt the cursor, but the plan's described placement is ambiguous enough to get this wrong).

**Required fix:** Rewrite section 8d against the real loop. The dedup must live *inside* the `if should:` block, gated specifically on `event_type == "http.scanner.fingerprinted"`, and must `continue` the outer `for` loop only after the cursor has already advanced (which it has, by line 754). Quote the real 5 lines, not an invented guard.

---

## Major Issues (should fix)

### MAJ-1 — `_SCANNER_SEEN` is process-lifetime and unbounded-by-tool; restart mid-scan re-floods

The plan acknowledges this in Appendix C ("first few minutes ... a burst") and section 8d, but the design is weak. `_SCANNER_SEEN` is a process-lifetime `set[(ip, tool)]` capped at 500 with no expiry. Problems:

1. **Sentinel restart mid-scan resets the set** → the same active scanner re-fires its full alert burst. With `http.scanner.fingerprinted` in `_NO_COOLDOWN_EVENTS`, the only thing standing between you and 1,000 Telegram messages is this in-memory set. Sentinel restarts on every deploy and after any poll-loop exception path that doesn't crash the process. The existing `_KILLCHAIN_SEEN`/`_CRED_REPLAY_SEEN` sets have the same limitation but they gate genuinely rare events; a scanner is the opposite — high volume.
2. **Cap of 500 with no LRU**: once full, `_scanner_already_seen` stops adding new pairs (section 8d: `if len(_SCANNER_SEEN) < _SCANNER_SEEN_MAX: add`). After 500 distinct (IP,tool) pairs, **every new scanner pair returns False forever and never dedups** — i.e. the flood protection silently disables itself under exactly the load it exists to handle.

**Required fix:** Your question "per-IP+tool or per-IP+tool+hour?" — answer: **per-IP+tool+hour**, backed by the same Redis you're already using, not an in-process set. A Redis key `honeypot:scanseen:<ip>:<tool>` with `SET ... NX EX 3600` gives you atomic, restart-survivable, auto-expiring dedup with one round-trip. Then `_NO_COOLDOWN_EVENTS` membership is safe because the dedup is durable. If you insist on the in-memory set, it MUST evict (clear or LRU) when full, like `_KILLCHAIN_SEEN` does (`if len > N: clear()`), or it fails closed into a flood.

### MAJ-2 — sqlmap hex canary is not a fixed constant

`"0x31303235343830303536"` (section 2, sqlmap payload_patterns) decodes to ASCII `"1025480056"`. sqlmap's randomized markers are **regenerated per run** (`randomInt()` seeded values, the `0x...` injection delimiters and the `CHAR(...)`/concat boundary markers vary). Hardcoding one specific hex value will match the runs that happen to reuse it and miss the rest. It is not "always injected" as the comment claims.

**Required fix:** Drop the false-confidence comment. Keep the value as *one weak indicator* if you like, but rely on the behavioral patterns (`and sleep(`, `extractvalue(`, `updatexml(`, `floor(rand(`) which are far more reliable, AND on the fact that sqlmap's SQLi payloads already trip `_detect_web_attack` → `http.post.sqli.attempt`. The tool-fingerprint here is enrichment, not primary detection — frame it that way.

### MAJ-3 — Several payload/path signatures will produce false positives against your OWN deception surface

- `"/.git/COMMIT_EDITMSG"`, `"/.svn/"`, `"/server-status"` under `dirsearch` path_patterns, and `"/robots.txt"` under `nikto`: **your honeypot intentionally serves `/.git/config` and `/.git/HEAD`** (main.py, CLAUDE.md). Any attacker who reads your git lure, then any scanner that probes adjacent git paths, gets labeled "dirsearch"/"nikto" regardless of the actual tool. `/robots.txt` is fetched by Google, Bing, uptime monitors, and every browser prefetch — labeling all of them "nikto" is noise.
- `"{{"` under `nuclei` payload_patterns: this matches **any** request body containing `{{` — including JSON with templating, legitimate API payloads, and notably your own frontend if any template fragment leaks into a POST. Extremely broad; will false-positive.
- `"fuzz"` (ffuf, wfuzz) and `"zzz"` (wfuzz) as substring matches against the full double-decoded combined string: `"fuzz"` appears in ordinary words; `"zzz"` appears in any base64 blob, any UUID-ish string, any `Buzz`/`fizzbuzz`/dataset name. These will fire constantly.

**Required fix:** Remove `"{{"`, `"zzz"`, bare `"fuzz"`, and `"/robots.txt"`. Make git/svn/server-status path matches require the *enumeration rate flag* to co-fire (these are single-path probes that only mean "scanner" in aggregate, which is exactly what your rate detector is for).

### MAJ-4 — First-match-wins ordering is fragile and the plan's claimed ordering is not enforced

The plan (section 3) claims tools are "ordered ... most-specific first (sqlmap, nuclei)" but `_TOOL_SIGNATURES` is a plain dict and the loop iterates insertion order. Two concrete collisions:

1. **wfuzz declares `"python-requests"` as a UA pattern** (section 2, line 207) AND **`python_scanner` declares `"python-requests/"`**. A real `python-requests/2.31.0` UA: `wfuzz` is defined *before* `python_scanner` in the dict, so a plain python-requests client gets labeled **wfuzz** (medium confidence → fires a scanner alert) even though it's just a script. That is a false attribution shipped to Telegram and the DB.
2. **hydra declares `"libwww-perl"`** — also used by countless benign Perl scripts and some monitoring tools.

You asked: "could a Burp request get misidentified as sqlmap?" — Not via UA (burp UA is distinct), but **yes via payload**: both `burp` and `nuclei` list `"burpcollaborator.net"` and `"oastify.com"`. nuclei is defined before burp, so a Burp Collaborator callback gets attributed to **nuclei**. For OOB/collaborator domains, co-detection is the honest answer (see MIN-2).

**Required fix:** Remove `"python-requests"` from wfuzz (keep only `"wfuzz/"`). Remove `"libwww-perl"` from hydra or downgrade hydra-via-libwww to low confidence. Document the actual evaluation order explicitly and make specificity real, not aspirational.

### MAJ-5 — IPv6 source addresses are unaddressed in the rate-limiter key

`honeypot:scanrate:<src_ip>` with a raw IPv6 address embeds colons into the key (fine for Redis) but the plan never states whether `src_ip` here is the `/32`-suffixed PostgreSQL form or the raw form. In the middleware, `src_ip = _extract_src_ip(request)` — confirm this is the bare IP (it is, pre-DB), so the key is clean. But the **sentinel** dedup parses `(row.get("src_ip") or "").split("/")[0]` — good. Just confirm the middleware-side rate key and the sentinel-side dedup key use the *same* normalization so an IPv6 attacker isn't tracked under two different string forms. The plan does not mention IPv6 at all; add one line confirming both paths normalize identically.

---

## Minor Issues (nice to have)

### MIN-1 — JA3/HASSH is out of scope but should be explicitly acknowledged

UA-spoofing tools (sqlmap `--random-agent`, nuclei with custom UA, any `requests` script setting a Chrome UA) defeat all UA-based signatures and many payload ones. The durable fingerprint is the TLS ClientHello (JA3) or SSH KEX (HASSH), which the application layer cannot see — it terminates at nginx/OpenResty. The plan should state this limitation in a "Known Gaps" section: **a sophisticated attacker who randomizes UA and avoids OOB domains will fingerprint as `automated_scanner` (rate-only) at best, or evade entirely if slow.** Don't let a reader assume this catches careful operators.

### MIN-2 — OOB/collaborator domains warrant co-detection, not first-match-wins

`burpcollaborator.net` / `oastify.com` / `interact.sh` indicate "an OAST-capable DAST tool" but cannot distinguish Burp from Nuclei from a manual tester. Rather than arbitrarily attributing to whichever dict entry comes first, emit `inferred_tool: "oast_dast"` (or carry a list). Low priority, but the current design silently mis-attributes.

### MIN-3 — Telegram header uses `.upper()` on internal tool keys

`f"SCANNER IDENTIFIED — {tool.replace('_', ' ').upper()}"` → `CURL MASS SCANNER`, `AUTOMATED SCANNER`, `NMAP NSE` is fine, but confirm no tool key contains characters that break HTML once `_esc()`'d. Minor — the plan does call `_esc(tool...)`, good.

### MIN-4 — `verify-module-6.sh` 10/10 claim is asserted, not demonstrated

Section 9g says the score must stay 10/10 but the new code paths (rate check on every request, Redis ZADD) are not part of that script. The healthcheck at `/api/v1/health` now triggers a ZADD every 30s. Confirm the healthcheck path is excluded (per CRIT-2) so the verify script's own probes don't pollute the rate window and so a Redis outage during verify doesn't flip a check.

---

## What the architect got right

- **Deception discipline holds.** All tool names live in `main.py` (server-side). Section 9h adds a vocabulary gate over `templates/` and `static/`. Section 10 explicitly lists every client-served file as unchanged. This is the single most important rule and the plan enforces it correctly.
- **SNARE precedence preserved.** The wire-in (section 5) only overrides `event_type` when `snare_attack_type is None and not _lure_cred_hit and not _lure_data_exfil`. A sqlmap request still logs as `http.post.sqli.attempt` with `inferred_tool: sqlmap` in payload. This is exactly right and matches the existing precedence chain (main.py:624-635).
- **No schema migration.** Correctly identifies `payload` as JSONB — new keys land without DDL. True.
- **`_fingerprint_tool` is pure** (no I/O) and therefore safe to call synchronously in async middleware. Correct — the problem is `_check_scan_rate`, which the plan wrongly treats the same way.
- **Sorted-set sliding window reasoning is correct** — the INCR+EXPIRE rollover critique in section 4 is accurate. The data structure choice is right; the *invocation context* (blocking, every-request) is the problem.
- **Low-confidence UA gating** (curl/python require a co-firing rate flag) is the right instinct to avoid flagging developers.
- **Fail-open on Redis outage** (section 4: `except Exception: return False`) is the correct safety posture — a Redis hiccup must never break the honeypot response path. Good.

---

## Specific changes required

1. **[CRIT-1]** Wrap `_check_scan_rate` in `await loop.run_in_executor(None, _check_scan_rate, src_ip)` (or use `redis.asyncio`). Never call it synchronously in `request_logger`.
2. **[CRIT-2]** Skip rate tracking for `/static/*` and `/api/v1/health`. Re-justify the 20/10s threshold against a real browser loading a multi-asset page, or count only non-static / non-2xx-known-page requests.
3. **[CRIT-3]** Rewrite sentinel section 8d against the real loop (sentinel.py:756-764). There is no `if not should: continue`. Put dedup inside `if should:`, gated on `event_type == "http.scanner.fingerprinted"`, and quote the actual 5 lines.
4. **[MAJ-1]** Replace the in-process `_SCANNER_SEEN` set with a Redis `SET NX EX 3600` per-(ip,tool) dedup — restart-survivable and auto-expiring. If kept in-memory, it MUST `clear()` when full (it currently disables itself at 500).
5. **[MAJ-2]** Demote the sqlmap hex canary to a weak indicator; fix the false "always injected" comment. Lean on `_detect_web_attack` for primary SQLi classification.
6. **[MAJ-3]** Remove `"{{"`, `"zzz"`, bare `"fuzz"`, `"/robots.txt"`. Gate `/.git/*`, `/.svn/`, `/server-status` path matches behind the rate flag (and note your honeypot intentionally serves `/.git/config` + `/.git/HEAD`).
7. **[MAJ-4]** Remove `"python-requests"` from wfuzz and `"libwww-perl"` from hydra (or downgrade to low). Make the dict ordering's specificity real and documented.
8. **[MAJ-5]** Add one line confirming the middleware rate key and sentinel dedup key normalize IPv6 (and `/32` stripping) identically.
9. **[MIN-1]** Add a "Known Gaps" section: UA-randomizing + OOB-avoiding attackers degrade to rate-only or evade; JA3/HASSH is out of scope (terminates at nginx).
10. **[MIN-2]** Consider `inferred_tool: "oast_dast"` for collaborator-domain hits instead of first-match attribution.

Re-submit `tools-detection.md` with CRIT-1/2/3 and MAJ-1/2/3/4 resolved and I will re-review. The MIN items can be deferred but should be acknowledged in the doc.

---

# Gatekeeper Feedback — Round 2

## Verdict: CONDITIONAL PASS

Every Round 1 item — all three CRITs and all five MAJs — is genuinely resolved, and the engine-side logic (`main.py`) is now implementation-ready. The signature hygiene is materially better, the async/blocking fix is correct, and the sentinel insertion anchor finally quotes the real loop. But the MAJ-1 fix introduced **one new shipping-blocking defect of exactly the same class as the original CRIT-3**: the Redis dedup function in `sentinel.py` references an import and a config variable that **do not exist in sentinel.py and are not in its compose environment**. As written, it will not flood-protect — it will silently disable itself, recreating the MAJ-1 flood it was built to prevent. This is a one-line-cluster fix, not a redesign, so the verdict is CONDITIONAL PASS, not FAIL. Fix NEW-1 and this is a full PASS.

---

## CRIT/MAJ items — resolved?

**CRIT-1 (async Redis / event-loop blocking) — RESOLVED.**
`_check_scan_rate()` is now `async def` and uses `_get_redis_async()`. Verified against the real code: `_get_redis_async()` exists at `main.py:3116`, returns a `redis.asyncio` client (`aioredis_lib.from_url`, imported at `main.py:3111`), and the established async pattern is already in use in `_v2_session_required()` (main.py:3141+). The wire-in `await _check_scan_rate(src_ip, path)` sits post-`call_next()` (response already resolved at main.py:562), inside the `async def request_logger` (main.py:529) — structurally valid. The async client's `socket_timeout=3` no longer blocks the loop because the await yields. The architect correctly cited the `_log_event_async` executor discipline as the prior art. Good.

**CRIT-2 (path exclusions + ZSET TTL) — RESOLVED.**
`_SCAN_RATE_SKIP_PREFIXES = ("/static/", "/favicon.ico")` and `_SCAN_RATE_SKIP_EXACT = {"/api/v1/health", "/api/v2/health"}` are checked FIRST, returning `False` before any Redis I/O — so static/health paths create no ZSET and stamp no `scan_rate_exceeded`. Memory is bounded by `pipe.expire(key, _SCAN_RATE_KEY_TTL_SECS)` at 60s. Note: `/api/v1/health` is the real verify-module-6 probe path; excluding it also closes MIN-4. The browser-multi-asset false-positive from Round 1 is now structurally impossible. Good.

**CRIT-3 (sentinel insertion anchor) — RESOLVED.**
Section 8d now quotes the REAL loop. Verified line-for-line against `sentinel.py:756-764`: `should, reason, category = _should_alert(row)` → `if should:` → `src_ip = ...` → `event_type = ...` → `cooldown = _HTTP_TIER_COOLDOWN.get(...)` → `if event_type in _NO_COOLDOWN_EVENTS or not _suppressed(...)`. There is no `if not should: continue` (the Round 1 invented guard is gone). The dedup block is correctly placed inside `if should:` after `event_type` is assigned, gated on `event_type == "http.scanner.fingerprinted"`. The `continue`-is-safe claim is correct: the composite cursor (`new_since`/`new_last_id`) advances at sentinel.py:745-754, BEFORE `_should_alert()`, so skipping `send_alert` cannot lose an event or stall the cursor. Anchor is now accurate. Good.

**MAJ-1 (Redis dedup replaces in-memory set) — RESOLVED in design, but see NEW-1.**
The in-memory `_SCANNER_SEEN` set is gone, replaced by `_scanner_already_seen_redis()` using `SET ... NX EX 3600`. The logic is correct: atomic, restart-survivable, auto-expiring, no silent self-disable at a cap. `http.scanner.fingerprinted` in `_NO_COOLDOWN_EVENTS` is now safe BECAUSE the durable dedup backs it. The design is right — but the wiring into sentinel is broken (NEW-1 below).

**MAJ-2 (sqlmap hex canary) — RESOLVED.**
`0x31303235343830303536` is removed. Replaced with stable behavioral markers (`and sleep(`, `' or '1'='1`, `union select null--`, `and 1=1--`, `extractvalue(`, `updatexml(`, `floor(rand(`, `benchmark(`, `pg_sleep(`, `waitfor delay`). The comment now correctly frames these as enrichment, with primary SQLi classification owned by `_detect_web_attack()` (confirmed at main.py:1038). The false "always injected" claim is gone. Good.

**MAJ-3 (false positives vs own lures) — RESOLVED.**
`{{` (nuclei), `zzz` and bare `fuzz` (ffuf/wfuzz), `/robots.txt` (nikto), and `/.git/COMMIT_EDITMSG` + `/.svn/` + `/server-status` (dirsearch) are all removed, with inline comments explaining each removal — explicitly citing the honeypot's own `/.git/config` + `/.git/HEAD` lures (which I confirmed are served from main.py). The self-inflicted-misattribution surface is closed. Good.

**MAJ-4 (dict ordering / collisions) — RESOLVED.**
`python-requests` is removed from `wfuzz` (only `wfuzz/` remains), eliminating the wfuzz-vs-python_scanner collision. `libwww-perl` removed from `hydra`. The specificity constraint (Tier 1 specific → Tier 3 generic, first-match-wins) is documented in both the dict header comment and the per-tier notes. MIN-2 (OOB co-detection) is also implemented: shared `burpcollaborator.net`/`oastify.com` with no corroborating UA now emit `inferred_tool: "oast_dast"` instead of arbitrary first-match attribution. Good.

**MAJ-5 (IPv6 normalization) — RESOLVED.**
`_normalize_src_ip_for_rate()` is present and correct: strips `/32`/`/128` CIDR suffix, strips `::ffff:` IPv4-mapped prefix, truncates pure IPv6 to /64. The doc states both the middleware rate key and the sentinel dedup key normalize identically via `split("/")[0]`. One residual asymmetry worth noting (not blocking — see New issues): the middleware truncates IPv6 to /64 for the rate key, but the sentinel dedup only does `split("/")[0]` (full /128). For dedup that is acceptable (dedup per exact address is stricter, not looser), but be aware the two keys are NOT byte-identical for IPv6 sources. Documented honestly; acceptable.

**MIN-1 (JA3/HASSH gap) — ACKNOWLEDGED.** Section 11 "Known Gaps" added. Correctly states UA-randomizing + OOB-avoiding attackers degrade to rate-only or evade, and JA3/HASSH terminates at OpenResty. Good.

---

## New issues found

### NEW-1 (BLOCKER) — `_scanner_already_seen_redis()` references `_redis_lib` and `REDIS_URL`, neither of which exists in sentinel.py; the dedup will silently fail-open into the exact MAJ-1 flood it was built to prevent

This is the same class of defect as the original CRIT-3 (plan asserting an anchor that does not exist in the real code), now on the import/config side.

Section 8d states: `import redis as _redis_lib  # already imported; confirm alias matches existing usage` and the function body calls `_redis_lib.from_url(REDIS_URL, ...)`.

Verified against the real files:
- **`redis` is NOT imported anywhere in `sentinel.py`.** The only imports are `html, json, logging, os, time, datetime, pathlib, psycopg2, requests` (sentinel.py:15-24). The "already imported" comment is false. (The grep hit on `redis` at sentinel.py:379 is the string literal `6379: "redis"` in a port map, not an import.)
- **`REDIS_URL` is NOT defined in `sentinel.py`.** Sentinel reads only `POSTGRES_DSN` from env (sentinel.py:42); there is no `REDIS_URL = os.environ[...]` line.
- **`REDIS_URL` is NOT in the sentinel compose `environment:` block.** In `deploy/module-5-log-shipper/docker-compose.yml`, the `log-shipper` service has `REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379` (line 154), but the `sentinel` service `environment:` block (lines 239-240) contains ONLY `POSTGRES_DSN`. Sentinel IS on `data-net` so it can reach `redis:6379` at the network layer — but it has no URL and no password to connect with.

Consequence — worse than a hard crash: `REDIS_URL` and `_redis_lib` are evaluated INSIDE the `try:` block, so the resulting `NameError` is caught by `except Exception: return False`. The function's fail-open path returns `False` = "not seen yet" → **every** `http.scanner.fingerprinted` event passes dedup → with `http.scanner.fingerprinted` in `_NO_COOLDOWN_EVENTS`, every scanner request fires a Telegram alert. The "restart-survivable Redis dedup" degrades to "no dedup at all," permanently and silently. This is precisely the MAJ-1 flood, reintroduced by the MAJ-1 fix.

Required fix (all three, none optional):
1. Add a real import to sentinel.py's import block: `import redis` (and reference it as `redis.from_url(...)`, or alias it and use the alias consistently). Do not annotate it "already imported."
2. Add a real config read near sentinel.py:42: `REDIS_URL = os.environ.get("REDIS_URL", "")` — and have `_scanner_already_seen_redis()` short-circuit to a safe, **non-flooding** fallback when `REDIS_URL` is empty (see point 4).
3. Add `REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379` to the `sentinel` service `environment:` block in `deploy/module-5-log-shipper/docker-compose.yml` (copy the working line from the `log-shipper` service at line 154). Note this also requires `REDIS_PASSWORD` to be in sentinel's env/`.env` scope.
4. Reconsider the fail-open direction for THIS function specifically. Round 1 fail-open was correct for `_check_scan_rate` (a Redis hiccup must not break the response path). But `_scanner_already_seen_redis()` failing-open means "alert" — under a Redis outage during an active scan, that is a Telegram flood. For the dedup path, failing toward suppression (return `True`) on Redis error is the safer posture: a Redis outage should not turn a no-cooldown event into a thousand-message burst. At minimum, make this a deliberate, documented choice rather than an accident of where the `NameError` lands.

Until NEW-1 is fixed, MAJ-1 is not actually resolved in the running system — only on paper.

### NEW-2 (MINOR, non-blocking) — `_should_alert()` must actually return `should=True` for `http.scanner.fingerprinted`, or none of section 8 ever runs

The entire sentinel chain (8a–8d) is downstream of `if should:` (sentinel.py:757). The plan adds `http.scanner.fingerprinted` to `_NO_COOLDOWN_EVENTS` and to `_SNARE_CATEGORIES`, but it does not show that `_should_alert()` returns `should=True` for this event type. `_SNARE_CATEGORIES` only sets the cooldown *bucket* (sentinel.py:361-362); it does not by itself force `should=True`. Confirm the event passes the `_NOISE_EVENTS` filter and reaches a `return True` branch in `_should_alert()` — it almost certainly does (it is neither in `_NOISE_EVENTS` nor a suppressed type), but the plan should state it explicitly so the implementer verifies it rather than assuming. One-line confirmation in section 8b is enough.

### NEW-3 (MINOR, non-blocking) — `json` import in the sentinel dedup snippet

Section 8d's dedup block calls `json.loads(raw_payload)`. `json` IS imported in sentinel.py (line 16), so this is fine — flagging only to confirm it was checked, not invented like the `redis` import. No action needed.

---

## Final recommendation

**CONDITIONAL PASS.** The engine half (`main.py`) is approved as-is — all of CRIT-1, CRIT-2, MAJ-2, MAJ-3, MAJ-4, MAJ-5 are correctly resolved against the real code, and the design discipline (deception vocabulary server-side only, SNARE precedence preserved, no schema migration, fail-open on the response path) holds. CRIT-3 and the sentinel logic structure are now accurate.

The single remaining blocker is **NEW-1**: the sentinel Redis dedup references `_redis_lib` and `REDIS_URL` that exist in neither `sentinel.py` nor the sentinel compose service, causing the MAJ-1 flood protection to silently no-op. This is a contained wiring fix (one import, one env read, one compose line, plus a deliberate fail-closed decision for the dedup path) — not a redesign.

Remaining blockers before full PASS:
1. **[NEW-1]** Add `import redis` and `REDIS_URL = os.environ.get("REDIS_URL", "")` to `sentinel.py`; add `REDIS_URL` (+ `REDIS_PASSWORD` scope) to the `sentinel` service `environment:` block in `deploy/module-5-log-shipper/docker-compose.yml`; make `_scanner_already_seen_redis()` fail CLOSED (return `True`/suppress) on Redis error or missing URL, not open.

Nice-to-have before re-review (non-blocking):
2. **[NEW-2]** State explicitly that `_should_alert()` returns `should=True` for `http.scanner.fingerprinted`.

Fix NEW-1 and re-submit; I will convert this to a full PASS on confirmation that the three wiring changes are in place and the dedup fails closed. Do NOT deploy the sentinel half until NEW-1 is fixed — shipping it as written guarantees a Telegram flood the first time a scanner with a recognizable UA sweeps the honeypot.


---
# Gatekeeper Feedback — Round 3 (Final)

## Verdict: PASS

## NEW-1 resolution check

The architect resolved NEW-1 via Option B (PostgreSQL dedup) rather than the Option A Redis-wiring I proposed in Round 2. This is the stronger choice — it removes the new infrastructure dependency entirely instead of adding it. All four targeted checks pass against Section 8d and the Round 3 revision-history entry:

1. **Redis fully replaced.** `_scanner_already_seen_redis()` is gone. `_scanner_already_seen_pg(conn, src_ip, inferred_tool)` is its drop-in replacement. No `_redis_lib`, no `REDIS_URL`, no `import redis`, no `from_url()` anywhere in the function or its call site. The two phantom names that caused the permanent fail-open in Round 2 no longer appear.

2. **`count > 1` threshold is correct.** The triggering `http.scanner.fingerprinted` row is written to `honeypot_events` by `main.py` before sentinel ever polls it, so when the dedup runs, the current event is already counted. `count == 1` = first occurrence → fire; `count > 1` = a prior alert already fired this hour → suppress. The 1-hour window (`created_at > NOW() - INTERVAL '1 hour'`), the `event_type = 'http.scanner.fingerprinted'` filter, and the `payload->>'inferred_tool'` match are all correct. `src_ip::text LIKE '<ip>%'` correctly handles the inet `/32` cast.

3. **Fails closed.** `except Exception: return True` — on any DB error the function suppresses rather than floods. This is the deliberate inversion of the Round 2 fail-open bug and the opposite of `main.py`'s response-path policy, which is the right call: a Telegram-send decision should hold during a DB outage, not flood.

4. **Uses existing `conn`, no new wiring.** The call site passes the `conn` the polling loop already holds (confirmed in scope — cursor advance at lines 745–754 precedes `_should_alert()`, so the `continue` only skips `send_alert` and cannot lose an event or corrupt the watermark). `json` (line 16) and `psycopg2` (line 23) are already imported. No new env vars, no compose change, no requirements change. Table 10 and Test 9g were updated to match.

NEW-2 (Round 2 nice-to-have) is moot under this design — the dedup is gated on `event_type == "http.scanner.fingerprinted"` inside `if should:`, so it never depends on an unstated `_should_alert()` return value.

## Final sign-off statement

NEW-1 is resolved. With the engine half (`main.py`) already approved in Round 2 and the sentinel dedup now restart-survivable, fail-closed, and free of any phantom Redis dependency, the tools-detection plan is approved for deployment. Ship both halves. The previously stated risk — a guaranteed Telegram flood on the first recognizable scanner sweep — is eliminated. No remaining blockers.
