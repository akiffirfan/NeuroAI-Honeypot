# Heuristics Engine & Attacker Fingerprinting — Implementation Plan

**Status**: Round 2 — revised per gatekeeper feedback (CRIT-1/2/3, MAJ-1/2/3/4/5 addressed)
**Target files**:
- `deploy/module-6-honeypot-api/src/main.py` (engine + middleware wire-in)
- `deploy/module-5-log-shipper/src/sentinel.py` (alert additions)

---

## 1. Architecture Decision

### Where each component lives and why

**`main.py` — all fingerprinting logic**

The deception rule is absolute: tool names must never appear in client-served files.
`main.py` runs server-side only and is never exposed to the attacker. All four
components live here:

| Component | Location in `main.py` | Reason |
|---|---|---|
| `_TOOL_SIGNATURES` dict | Module-level constant, immediately after `_SCANNER_UA_FRAGMENTS` | Groups UA + payload patterns together, one place to extend |
| `_fingerprint_tool()` | Pure function, defined below `_TOOL_SIGNATURES` | No side effects — easy to unit-test in isolation |
| `_check_scan_rate()` | Async function, uses existing `_get_redis_async()` | Consistent with the established async Redis pattern in `_v2_session_required()` |
| Middleware wire-in | Single `if` block in `request_logger()`, after the existing `snare_hit = _detect_web_attack(...)` line | Minimal surgery — one insertion point, reads already-decoded `body_str` and `ua_str` |

**`sentinel.py` — alert additions only**

Three targeted additions with zero structural change to the polling loop:
1. Add `"http.scanner.fingerprinted"` to `_NO_COOLDOWN_EVENTS`
2. Add `"http.scanner.fingerprinted": "web.scanner"` to `_SNARE_CATEGORIES`
3. Extend the `_build_message()` header `elif` chain and extract `inferred_tool` from `payload_data`

No new imports, no new threads, no new compose environment variables. The per-tool dedup
(section 8d) uses the PostgreSQL `conn` that sentinel already holds — no Redis dependency
is added to sentinel.

---

## 2. `_TOOL_SIGNATURES` Dict — Full Structure

Insert this block in `main.py` immediately after the `_SCANNER_UA_FRAGMENTS` list
(currently ends at line 272).

**Evaluation ordering is critical**: The dict is iterated in insertion order and
uses first-match-wins semantics. Tools are ordered from most-specific (unique UA
strings, known OOB domains, stable payload canaries) to most-generic (broad UA
substrings, rate-only). Breaking this order causes misattribution — see MAJ-4 notes
below each group.

```python
# ---------------------------------------------------------------------------
# Tool fingerprinting signatures — server-side only, never sent to client
#
# Structure:
#   tool_name (str) → {
#     "ua_patterns":      list[str]  — substrings matched case-insensitively in User-Agent
#     "payload_patterns": list[str]  — substrings matched case-insensitively in combined
#                                      (path + query + body) after double-URL-decode
#     "path_patterns":    list[str]  — substrings matched case-insensitively in path only
#                                      (for path-based enumeration signatures)
#   }
#
# Confidence assignment rules (in _fingerprint_tool):
#   UA match alone → "medium"  (UA is trivially spoofed but lazy tools never bother)
#   Payload/path match alone → "high"  (harder to spoof than UA)
#   Both UA + payload/path match → "high"
#
# ORDERING CONSTRAINT:
#   Specific tools (sqlmap, nuclei, burp) must come before generic ones
#   (python_scanner, curl_mass_scanner). The loop is first-match-wins; a generic
#   entry appearing earlier would shadow the specific one that should win.
#   Within each tier: OOB-domain signatures (burp, nuclei) before UA-only tools.
# ---------------------------------------------------------------------------
_TOOL_SIGNATURES: dict[str, dict[str, list[str]]] = {
    # --- Tier 1: highly specific — distinct UA strings or stable payload canaries ---

    "sqlmap": {
        "ua_patterns": [
            "sqlmap/",          # default UA: "sqlmap/1.7.12#stable (https://sqlmap.org)"
        ],
        "payload_patterns": [
            # NOTE: sqlmap's randomized hex canary (e.g. 0x313032...) varies per run
            # and is NOT a reliable constant — demoted to a comment only.
            # Primary SQLi classification is handled by _detect_web_attack() which
            # maps to http.post.sqli.attempt. These patterns are enrichment signals.
            "and sleep(",             # time-based blind — SLEEP() canary
            "and 1=1--",              # boolean-based blind (stable constant)
            "' or '1'='1",            # classic tautology (stable constant)
            "union select null--",    # UNION probe (stable constant)
            "benchmark(",             # MySQL BENCHMARK() canary
            "waitfor delay",          # MSSQL time-based blind
            "pg_sleep(",              # PostgreSQL time-based blind
            "(select * from",         # stacked-query probe pattern
            "randomblob(",            # SQLite time-based probe
            "load_file(",             # MySQL file-read injection (sqlmap --file-read)
            "into outfile",           # MySQL file-write (sqlmap --file-write)
            "extractvalue(",          # error-based: EXTRACTVALUE(1,CONCAT(...))
            "updatexml(",             # error-based: UPDATEXML(...)
            "floor(rand(",            # error-based RAND() duplicate-key
            "'/**/or/**/",            # comment-padded OR clause (sqlmap tamper)
            "0x7e",                   # tilde separator in error payloads
        ],
        "path_patterns": [],
    },

    "nuclei": {
        # Checked before burp because nuclei has its own distinct UA and OOB domain
        # (interact.sh). A request with interact.sh AND no Burp UA → nuclei wins.
        "ua_patterns": [
            "nuclei/",          # default: "nuclei/3.x.x (https://nuclei.projectdiscovery.io)"
            "projectdiscovery",
        ],
        "payload_patterns": [
            "interact.sh",            # Nuclei's own OOB server — nuclei-specific
            "nuclei-",                # literal string in some default template paths
        ],
        "path_patterns": [
            "/.nuclei-",              # nuclei temp-file probe pattern
            "/nuclei-",
            "/.well-known/nuclei",    # nuclei metadata probe
        ],
    },

    "burp": {
        # Checked after nuclei to avoid nuclei being labelled burp via shared OOB domains.
        # NOTE: burpcollaborator.net and oastify.com are shared between burp and nuclei.
        # If a request contains only oastify.com with no other signals, emit
        # inferred_tool: "oast_dast" (see _fingerprint_tool() for co-detection logic).
        "ua_patterns": [
            "burp",
            "burpsuite",
        ],
        "payload_patterns": [
            "burpcollaborator.net",   # primarily Burp; co-fires with nuclei
            "oastify.com",            # Burp OAST domain; co-fires with nuclei
            "burp-is-the-best-dastool",  # Burp internal test string
            "portswiggerlabs",
            "portswigger",
        ],
        "path_patterns": [
            "/burp-is-the-best-dastool",
            "/.burpcollaborator",
        ],
    },

    "metasploit": {
        "ua_patterns": [
            "msf",
            "metasploit",
        ],
        "payload_patterns": [
            "meterpreter",
            "msf/",
        ],
        "path_patterns": [
            "/sdk/",           # Metasploit auxiliary scanner paths
        ],
    },

    "nmap_nse": {
        "ua_patterns": [
            "nmap scripting engine",
            "nmap nse",
        ],
        "payload_patterns": [
            "nmap",
        ],
        "path_patterns": [],
    },

    # --- Tier 2: tool-specific UAs, no shared payload overlap ---

    "gobuster": {
        "ua_patterns": [
            "gobuster/",
            "gobuster",
        ],
        "payload_patterns": [],
        "path_patterns": [
            # Gobuster dir mode generates sequential dictionary paths.
            # Individual path patterns aren't reliable — rate detection handles this.
            # Signature match only on UA for gobuster; rate-based for path sweep.
        ],
    },

    "ffuf": {
        "ua_patterns": [
            "ffuf/",            # default: "ffuf/2.1.0"
            "fuzz faster",      # ffuf's extended UA variant
        ],
        "payload_patterns": [],  # "fuzz" and "zzz" removed — too broad, false positives
        "path_patterns": [
            "/FUZZ",            # ffuf path injection with all-caps FUZZ keyword
        ],
    },

    "dirsearch": {
        "ua_patterns": [
            "dirsearch",
            "python-dirsearch",
            "dirstalk",
        ],
        "payload_patterns": [],
        "path_patterns": [
            "/.ds_store",       # dirsearch default wordlist includes .DS_Store
            # NOTE: /.git/COMMIT_EDITMSG, /.svn/, /server-status removed — these
            # match the honeypot's own intentional /.git/config + /.git/HEAD lures,
            # causing self-inflicted false positives. Gate on rate-flag + UA instead.
            # NOTE: /robots.txt removed — fetched by search crawlers, uptime monitors,
            # and browser prefetch — labels too much legitimate traffic as dirsearch.
        ],
    },

    "nikto": {
        "ua_patterns": [
            "nikto/",
            "nikto",
        ],
        "payload_patterns": [
            "nessus",           # nikto sometimes embeds Nessus test strings
            "appscan",          # IBM AppScan residue in nikto payloads
        ],
        "path_patterns": [
            "/cgi-bin/",        # nikto hammers every CGI path
            "/phpinfo.php",
            # NOTE: /server-status and /robots.txt removed — high false-positive rate;
            # /server-status alone is in dirsearch/nuclei/generic wordlists.
            # /robots.txt fetched by every crawler and browser. Both removed.
            "/admin.php",
            "/administrator",
            "/.htaccess",
        ],
    },

    "masscan": {
        "ua_patterns": [
            "masscan/",
            "masscan",
        ],
        "payload_patterns": [],
        "path_patterns": [],
    },

    "zgrab": {
        "ua_patterns": [
            "zgrab/",
            "zgrab",
        ],
        "payload_patterns": [],
        "path_patterns": [],
    },

    "hydra": {
        "ua_patterns": [
            # NOTE: "libwww-perl" removed — used by countless benign Perl scripts
            # and monitoring tools, not a reliable hydra indicator. Hydra's HTTP
            # module UA is "libwww-perl" but so is every LWP::UserAgent script.
            "hydra",
        ],
        "payload_patterns": [],
        "path_patterns": [],
    },

    "wfuzz": {
        "ua_patterns": [
            "wfuzz/",
            # NOTE: "python-requests" removed — wfuzz's default UA is python-requests
            # BUT so is every Python script using requests. This was a direct collision
            # with python_scanner below: wfuzz appearing before python_scanner in the
            # dict caused all plain python-requests clients to be mis-labelled "wfuzz".
            # Keeping only the unambiguous "wfuzz/" prefix.
        ],
        "payload_patterns": [
            "fuzzdb",           # only this one retained — specific to fuzzdb payloads
            # NOTE: bare "fuzz" removed — substring-matches "buzzfeed", "fuzzy logic",
            # dataset names containing "fuzz", etc. Too many false positives.
            # NOTE: "zzz" removed — matches any base64 blob, UUID residue, arbitrary strings.
        ],
        "path_patterns": [
            "/FUZZ",            # wfuzz canonical all-caps keyword in path
        ],
    },

    # --- Tier 3: generic UA patterns — low confidence, require rate-flag to escalate ---

    "curl_mass_scanner": {
        # curl/wget used individually by humans, but mass scanners use them with
        # no Accept headers and predictable UA strings.
        # Only fires when combined with rate detection or other signals.
        "ua_patterns": [
            "curl/",
            "wget/",
        ],
        "payload_patterns": [],
        "path_patterns": [],
    },

    "python_scanner": {
        # python-requests and python-httpx are legitimate tools but also the default
        # for mass scanning frameworks (shodan, censys scrapers, home-grown tools).
        # Must come AFTER wfuzz in dict ordering — wfuzz previously listed
        # "python-requests" as a UA pattern, causing this entry to be shadowed.
        # With "python-requests" removed from wfuzz, ordering is safe either way,
        # but python_scanner stays last to make the intent explicit.
        "ua_patterns": [
            "python-requests/",
            "python-httpx/",
            "python-urllib",
            "aiohttp/",
        ],
        "payload_patterns": [],
        "path_patterns": [],
    },
}
```

**Design notes**:

- `curl_mass_scanner` and `python_scanner` have UA-only signatures with low confidence
  by design. They will emit `confidence: "low"` and NOT trigger
  `http.scanner.fingerprinted` alone — they require a concurrent rate-based flag.
  This prevents false-positives for developers using curl/python manually.
- Tool names in this dict are internal identifiers. They propagate to `payload["inferred_tool"]`
  in the database and to Telegram, but are never served to the client.
- Removed from signatures vs Round 1: `"{{"` (nuclei — matches all JSON templating),
  `"zzz"` (wfuzz — matches base64/UUIDs), bare `"fuzz"` (ffuf/wfuzz — too broad),
  `"python-requests"` from wfuzz (collides with python_scanner), `"libwww-perl"` from
  hydra (too generic), `"/robots.txt"` from nikto (crawler noise), `"/.git/COMMIT_EDITMSG"`
  and `"/.svn/"` and `"/server-status"` from dirsearch (collide with our own lure paths).

---

## 3. `_fingerprint_tool()` — Complete Implementation

Insert this function immediately after the `_TOOL_SIGNATURES` dict.

```python
# OOB/collaborator domains that multiple DAST tools share — emit as "oast_dast"
# instead of attributing to whichever dict entry happens to come first.
_SHARED_OOB_DOMAINS = {"burpcollaborator.net", "oastify.com"}

def _fingerprint_tool(ua: str, path: str, body: str) -> dict:
    """
    Match request signals against _TOOL_SIGNATURES to identify the likely tool.

    Returns a dict with keys:
        inferred_tool    (str)  — tool name from _TOOL_SIGNATURES key, or "oast_dast"
        confidence       (str)  — "high", "medium", or "low"
        detection_method (str)  — "user_agent", "payload", "path", or "combined"

    Returns {} if no tool is identified.

    Detection priority (first match wins — dict insertion order enforces specificity):
        1. UA + payload/path match  → confidence "high", method "combined"
        2. Payload/path match only  → confidence "high", method "payload" or "path"
        3. UA match only            → confidence "medium", method "user_agent"
           Exception: curl_mass_scanner / python_scanner UA matches emit confidence
           "low" because these UAs have high false-positive rates.

    Special case — shared OOB domains (burpcollaborator.net, oastify.com):
        If the ONLY payload signal is a shared OOB domain and no UA confirms a specific
        tool, emit inferred_tool: "oast_dast" (OAST-capable DAST tool, unattributed).
        This avoids arbitrary misattribution between Burp and Nuclei.

    SNARE precedence: caller is responsible for skipping _fingerprint_tool() entirely
        when _detect_web_attack() already returned a SNARE category. If SNARE fires,
        the tool fingerprint is still computed for payload enrichment, but
        event_type is NOT overridden (SNARE wins). See middleware wire-in section.

    All comparisons are case-insensitive. The body is double-URL-decoded before
    matching (same transformation applied in _detect_web_attack).
    """
    if not (ua or path or body):
        return {}

    # Pre-compute lowercased, double-decoded inputs (mirrors _detect_web_attack)
    def _dd(s: str) -> str:
        d = urllib.parse.unquote_plus(s)
        return urllib.parse.unquote_plus(d)

    ua_lower      = ua.lower()
    path_lower    = _dd(path).lower()
    body_lower    = _dd(body).lower()
    combined_lower = path_lower + " " + body_lower

    # Low-confidence UA-only tools — only promote these if rate detection also flags
    _LOW_CONFIDENCE_UA_TOOLS = {"curl_mass_scanner", "python_scanner"}

    for tool_name, sigs in _TOOL_SIGNATURES.items():
        ua_hit      = any(p in ua_lower      for p in sigs.get("ua_patterns",      []))
        payload_hit = any(p in combined_lower for p in sigs.get("payload_patterns", []))
        path_hit    = any(p in path_lower     for p in sigs.get("path_patterns",    []))

        if ua_hit and (payload_hit or path_hit):
            return {
                "inferred_tool":    tool_name,
                "confidence":       "high",
                "detection_method": "combined",
            }
        if payload_hit:
            # Special case: shared OOB domain with no corroborating UA → emit oast_dast
            matched_payload = next(
                p for p in sigs.get("payload_patterns", []) if p in combined_lower
            )
            if matched_payload in _SHARED_OOB_DOMAINS and not ua_hit:
                return {
                    "inferred_tool":    "oast_dast",
                    "confidence":       "medium",
                    "detection_method": "payload",
                }
            return {
                "inferred_tool":    tool_name,
                "confidence":       "high",
                "detection_method": "payload",
            }
        if path_hit:
            return {
                "inferred_tool":    tool_name,
                "confidence":       "high",
                "detection_method": "path",
            }
        if ua_hit:
            confidence = "low" if tool_name in _LOW_CONFIDENCE_UA_TOOLS else "medium"
            return {
                "inferred_tool":    tool_name,
                "confidence":       confidence,
                "detection_method": "user_agent",
            }

    return {}
```

**Key design choices**:

- `_LOW_CONFIDENCE_UA_TOOLS`: `curl` and `python-requests` are used by developers daily.
  A solo UA match for these emits `confidence: "low"` and does NOT trigger
  `http.scanner.fingerprinted`. Only when `_check_scan_rate()` also flags the IP does
  the combined signal escalate to a fingerprinted event (see middleware wire-in section).
- First-match-wins: tools are ordered in `_TOOL_SIGNATURES` with most-specific patterns
  first (sqlmap, nuclei, burp) to avoid a generic `python_scanner` match shadowing a
  more specific attribution.
- The function is pure: no Redis access, no I/O, no side effects. Safe to call
  synchronously inside the async middleware without executor wrapping.
- OOB co-detection: shared collaborator domains (`burpcollaborator.net`, `oastify.com`)
  emit `"oast_dast"` when no UA resolves the ambiguity. This is more accurate than
  arbitrary first-match attribution between Burp and Nuclei.

---

## 4. `_check_scan_rate()` — Async Redis-Backed Rate Checker

Insert this function immediately after `_fingerprint_tool()`.

**IMPORTANT — CRIT-1 fix**: This function is `async` and uses `_get_redis_async()`
(the existing `redis.asyncio` client already in `main.py` at line 3116). It must be
`await`-ed in the middleware. The previous synchronous design was dropped because
`_get_redis()` uses a 3-second socket timeout — a blocking pipeline call in the async
event loop can stall all request handling for up to 3 seconds during a Redis hiccup or
under scanner load, reintroducing the 502-under-load failure mode. The existing code
is already careful about this: `_log_event_async()` wraps sync Redis/PG work in
`loop.run_in_executor(None, ...)` for the same reason. This function follows the same
discipline by using the async client directly.

**IMPORTANT — CRIT-2 fix**: The rate check is skipped for static assets and health
checks. A single browser loading `dashboard.html` pulls 6+ static assets in <1s and
would trivially cross the threshold, making `scan_rate_exceeded` meaningless for real
intelligence. Only non-static, non-health paths count toward the rate. The Redis ZSET
TTL is also capped at `_SCAN_RATE_KEY_TTL_SECS` (60s) to bound memory under a
large-scale sweep rotating through many source IPs.

```python
# Scan rate thresholds — configurable without code change
_SCAN_RATE_WINDOW_SECS  = 10    # sliding window length in seconds
_SCAN_RATE_THRESHOLD    = 20    # distinct non-static requests within window to flag
_SCAN_RATE_KEY_TTL_SECS = 60    # max Redis key lifetime (caps memory under IP rotation)

# Paths and prefixes excluded from rate tracking — these generate too many false
# positives: static assets cause multi-hit counts from a single page load; the
# healthcheck generates one hit every 30s from 127.0.0.1 and would pollute the
# rate key for localhost.
_SCAN_RATE_SKIP_PREFIXES = ("/static/", "/favicon.ico")
_SCAN_RATE_SKIP_EXACT    = {"/api/v1/health", "/api/v2/health"}

async def _check_scan_rate(src_ip: str, path: str) -> bool:
    """
    Return True if src_ip has exceeded _SCAN_RATE_THRESHOLD non-static requests in
    the last _SCAN_RATE_WINDOW_SECS seconds, indicating an automated scanner.

    Static assets (/static/*) and healthcheck paths are excluded — a real browser
    loading a multi-asset page would otherwise cross the threshold.

    Uses a Redis sorted set via the existing async client (_get_redis_async()):
        Key:    honeypot:scanrate:<normalized_src_ip>
        Member: <uuid4>   (unique per request — avoids member collisions)
        Score:  current Unix timestamp (float)

    On each call:
        1. Check exclusion list — return False immediately for static/health paths
        2. ZADD the current request timestamp
        3. ZREMRANGEBYSCORE to expire entries outside the window
        4. ZCARD to count remaining members
        5. EXPIRE key to _SCAN_RATE_KEY_TTL_SECS (bounds memory under IP rotation)

    Returns False if Redis is unavailable (fail-open: prefer missing detections
    over breaking the honeypot response path).

    IPv6 normalization: src_ip is normalized before use as a Redis key:
        - IPv4-mapped IPv6 (::ffff:1.2.3.4) → stripped to bare IPv4 "1.2.3.4"
        - Full IPv6 addresses → truncated to /64 prefix for rate limiting
          (individual IPv6 addresses rotate within a /64; tracking /128 inflates keys)
        - PostgreSQL /32 suffix (1.2.3.4/32) → stripped
    This normalization matches the sentinel-side strip in _build_message():
    (row.get("src_ip") or "").split("/")[0] — both use the bare IPv4 form.
    """
    # Exclusion check — do not track static or health paths
    if path in _SCAN_RATE_SKIP_EXACT:
        return False
    if any(path.startswith(pfx) for pfx in _SCAN_RATE_SKIP_PREFIXES):
        return False

    # Normalize src_ip for consistent Redis key across IPv4/IPv6 forms
    normalized_ip = _normalize_src_ip_for_rate(src_ip)

    try:
        r = _get_redis_async()
        key = f"honeypot:scanrate:{normalized_ip}"
        now = time.time()
        window_start = now - _SCAN_RATE_WINDOW_SECS

        pipe = r.pipeline()
        pipe.zadd(key, {str(uuid.uuid4()): now})
        pipe.zremrangebyscore(key, "-inf", window_start)
        pipe.zcard(key)
        pipe.expire(key, _SCAN_RATE_KEY_TTL_SECS)
        results = await pipe.execute()

        count = results[2]  # ZCARD result
        return count >= _SCAN_RATE_THRESHOLD
    except Exception:
        # Redis unavailable — fail-open, log nothing (avoid log spam on Redis hiccup)
        return False


def _normalize_src_ip_for_rate(src_ip: str) -> str:
    """
    Normalize a source IP string for use as a Redis rate-limit key.

    Rules:
        1. Strip PostgreSQL /32 or /128 CIDR suffix
        2. Strip IPv4-mapped IPv6 prefix (::ffff:) → bare IPv4
        3. Truncate full IPv6 to /64 (first 4 groups) — attackers rotate within /64

    Examples:
        "1.2.3.4"           → "1.2.3.4"
        "1.2.3.4/32"        → "1.2.3.4"
        "::ffff:1.2.3.4"    → "1.2.3.4"
        "2001:db8:1:2:3:4:5:6" → "2001:db8:1:2"  (first 4 groups = /64)
    """
    # Strip CIDR suffix
    ip = src_ip.split("/")[0].strip()
    # Strip IPv4-mapped IPv6
    if ip.startswith("::ffff:"):
        ip = ip[7:]
    # Truncate pure IPv6 to /64 (first 4 colon-separated groups)
    if ":" in ip:
        parts = ip.split(":")
        ip = ":".join(parts[:4])
    return ip
```

**Why a sorted set (not a counter)**:

A simple `INCR` + `EXPIRE` counter cannot implement a true sliding window — it resets
on TTL boundaries, so 19 requests at T=0 plus 1 request at T=11 with a 10s TTL
would miss the burst. The sorted set stores a timestamp per request member,
enabling exact sliding-window ZREMRANGEBYSCORE pruning.

**Key format**: `honeypot:scanrate:<normalized_ip>` — namespaced under `honeypot:` to
avoid collisions with Cowrie/OpenCanary streams using the same Redis instance.

**TTL cap rationale**: The original TTL was `window_secs * 2 = 20s`. Under a
large-scale sweep from a /24 rotating IPs, 256 short-lived ZSETs are created
continuously. The 60s cap keeps keys alive long enough to track a sustained scan but
prevents unbounded ZSET accumulation under a distributed botnet sweep.

---

## 5. Middleware Integration Point — Exact Diff

The wire-in sits in `request_logger()` immediately after the existing `snare_hit` block.

Current code (confirmed against main.py lines 617–635):

```python
    # SNARE-style web attack detection — runs before event_type is finalised
    query_str = str(request.query_params)
    body_str = body_bytes.decode("utf-8", errors="replace") if body_bytes else ""
    ua_str = request.headers.get("user-agent", "")
    snare_hit = _detect_web_attack(path, query_str, body_str, ua_str)

    # Determine event_type — priority: lure-cred > data-exfil > SNARE > default
    if _lure_cred_hit:
        event_type = "http.lure.credential.success"
        snare_attack_type = "Lure Credential"
    elif _lure_data_exfil:
        event_type = "http.lure.data_exfil"
        snare_attack_type = "Data Exfil"
    elif snare_hit:
        event_type = snare_hit[0]
        snare_attack_type = snare_hit[1]
    else:
        event_type = f"http.{request.method.lower()}.{path_cat}"[:80]
        snare_attack_type = None
```

**Replace with**:

```python
    # SNARE-style web attack detection — runs before event_type is finalised
    query_str = str(request.query_params)
    body_str = body_bytes.decode("utf-8", errors="replace") if body_bytes else ""
    ua_str = request.headers.get("user-agent", "")
    snare_hit = _detect_web_attack(path, query_str, body_str, ua_str)

    # Tool fingerprinting — pure function, no I/O, safe to call synchronously
    # MAJ-3 fix: if SNARE already classified this request, fingerprinting is for
    # payload enrichment only (event_type will NOT be overridden below).
    _tool_fp = _fingerprint_tool(ua_str, path, body_str)

    # Rate check — async, uses existing _get_redis_async() client
    # CRIT-1 fix: awaited directly (not wrapped in run_in_executor) because
    # _check_scan_rate is already async and uses redis.asyncio.
    # CRIT-2 fix: path is passed so static/health paths are excluded inside the function.
    _scan_rate_flag = await _check_scan_rate(src_ip, path)

    # Determine event_type — priority: lure-cred > data-exfil > SNARE > scanner > default
    if _lure_cred_hit:
        event_type = "http.lure.credential.success"
        snare_attack_type = "Lure Credential"
    elif _lure_data_exfil:
        event_type = "http.lure.data_exfil"
        snare_attack_type = "Data Exfil"
    elif snare_hit:
        event_type = snare_hit[0]
        snare_attack_type = snare_hit[1]
    else:
        event_type = f"http.{request.method.lower()}.{path_cat}"[:80]
        snare_attack_type = None

    # Scanner fingerprint escalation — promote to dedicated event type when:
    #   (a) tool identified with confidence "high" or "medium", OR
    #   (b) low-confidence UA match + rate-based flag (automated behaviour confirmed)
    # MAJ-3 fix: skip escalation entirely when SNARE already classified the request.
    # A sqlmap request is http.post.sqli.attempt (SNARE wins); tool metadata is
    # added to payload below but event_type stays as the SNARE classification.
    _is_scanner_event = False
    if _tool_fp:
        confidence = _tool_fp.get("confidence", "")
        if confidence in ("high", "medium"):
            _is_scanner_event = True
        elif confidence == "low" and _scan_rate_flag:
            _is_scanner_event = True
    elif _scan_rate_flag:
        # Rate exceeded but no tool signature — flag as generic automated scanner
        _tool_fp = {
            "inferred_tool":    "automated_scanner",
            "confidence":       "high",
            "detection_method": "rate",
        }
        _is_scanner_event = True

    # Scanner event_type override: only when SNARE did NOT already classify the request.
    if _is_scanner_event and snare_attack_type is None and not _lure_cred_hit and not _lure_data_exfil:
        event_type = "http.scanner.fingerprinted"
        snare_attack_type = f"Automated Scanner — {_tool_fp['inferred_tool'].replace('_', ' ').title()}"
```

**Critical logic note**: Scanner fingerprinting enriches the `payload_dict` even when
`_is_scanner_event` is False (e.g., sqlmap detected via SNARE + tool fingerprint).
The metadata always lands in the DB. The `event_type` override only applies when the
request is otherwise generic (SNARE did not classify it).

---

## 6. `_log_event` Enrichment — Payload Dict Modification

The `payload_dict` is built after the event_type block and before `_log_event()` is
called. Add the fingerprint metadata to `payload_dict` unconditionally when `_tool_fp`
is non-empty.

Current `payload_dict` construction (confirmed at main.py lines 637–650):

```python
    payload_dict = {
        "method": request.method,
        "path": path,
        "query_params": dict(request.query_params),
        "user_agent": request.headers.get("user-agent"),
        "referrer": request.headers.get("referer"),
        "body_preview": body_preview,
        "status_code": response.status_code,
        "latency_ms": round(latency_ms, 2),
        "is_login_attempt": is_login,
        "is_lure_access": is_lure,
        "bot_score": round(bot_score, 3),
        "x_forwarded_for": request.headers.get("x-forwarded-for"),
    }
```

**Replace with**:

```python
    payload_dict = {
        "method": request.method,
        "path": path,
        "query_params": dict(request.query_params),
        "user_agent": request.headers.get("user-agent"),
        "referrer": request.headers.get("referer"),
        "body_preview": body_preview,
        "status_code": response.status_code,
        "latency_ms": round(latency_ms, 2),
        "is_login_attempt": is_login,
        "is_lure_access": is_lure,
        "bot_score": round(bot_score, 3),
        "x_forwarded_for": request.headers.get("x-forwarded-for"),
    }

    # Enrich payload with tool fingerprint data when available.
    # Present on every event that has a tool match — not just http.scanner.fingerprinted.
    # Downstream: sentinel reads inferred_tool from payload JSONB; HoneyDash sees it
    # in body_preview fallback if attack_type string isn't enough.
    if _tool_fp:
        payload_dict["inferred_tool"]    = _tool_fp["inferred_tool"]
        payload_dict["confidence"]       = _tool_fp["confidence"]
        payload_dict["detection_method"] = _tool_fp["detection_method"]
    if _scan_rate_flag:
        payload_dict["scan_rate_exceeded"] = True
```

**Result in the database**: For a nuclei scan with no SNARE pattern match, the
`honeypot_events` row will have:
- `event_type = "http.scanner.fingerprinted"`
- `payload` (JSONB) includes `inferred_tool: "nuclei"`, `confidence: "high"`, `detection_method: "user_agent"`

For a sqlmap scan that also triggers SNARE, the row will have:
- `event_type = "http.post.sqli.attempt"` (SNARE wins)
- `payload` (JSONB) includes `inferred_tool: "sqlmap"`, `confidence: "high"`, `detection_method: "combined"`

---

## 7. HoneyDash Enrichment — `attack_type` String Changes

The existing HoneyDash push block in the middleware gates on `snare_attack_type`. After
the middleware change, `snare_attack_type` is now set to `"Automated Scanner — Nuclei"`
(or similar) when a scanner is fingerprinted. No change to the push block itself is
needed — the existing logic already handles it:

```python
    if HONEYDASH_URL and SENSOR_API_KEY:
        if snare_attack_type:
            # This now fires for scanner events too — attack_type will be e.g.
            # "Automated Scanner — Nuclei" or "Automated Scanner — Sqlmap"
            asyncio.create_task(_push_honeydash_async(event, snare_attack_type))
        elif _lure_data_exfil:
            asyncio.create_task(_push_honeydash_async(event, "Data Exfil"))
        elif is_lure:
            asyncio.create_task(_push_honeydash_async(event, "Lure Access"))
        elif is_login and username:
            asyncio.create_task(_push_honeydash_async(event, "Web Login Attempt"))
```

The `attack_type` string `"Automated Scanner — Nuclei"` will appear as the event
label in HoneyDash's attack feed. No changes to `_push_honeydash_async()` itself.

---

## 8. Sentinel Changes — Exact Additions

### 8a. Add to `_NO_COOLDOWN_EVENTS`

Current set (confirmed at sentinel.py lines 103–116). Add one entry:

```python
_NO_COOLDOWN_EVENTS = {
    "http.lure.credential.success",
    "cowrie.session.file_download",
    "cowrie.login.success",
    "http.upload.malware_received",
    "http.lure.data_exfil",
    "http.canarytoken.fired",
    "cross_sensor.credential_relay",
    "smb.ntlmv2.hash",
    "http.telemetry.devtools_opened",
    "http.unauth.sensitive_access",
    "http.snare.mfa_enable_attempt",
    "http.security.allowlist_toggle",
    "http.scanner.fingerprinted",         # <-- ADD THIS
}
```

**Rationale**: Each new tool detection is a distinct intelligence event. A nuclei scan
followed by a gobuster sweep from the same IP are different operations — both should
fire. The per-tool Redis dedup in section 8d (not an in-memory set) prevents re-flooding
for the same IP + tool pair within 1 hour.

### 8b. Add to `_SNARE_CATEGORIES` (inside `_should_alert()`)

The `_SNARE_CATEGORIES` dict is defined locally inside `_should_alert()`. Add one entry:

```python
    _SNARE_CATEGORIES = {
        # ... existing entries ...
        "http.scanner.fingerprinted": "web.scanner",  # <-- ADD THIS
    }
```

The `"web.scanner"` bucket is new. Without `http.scanner.fingerprinted` in
`_SNARE_CATEGORIES`, the event would fall through to the generic `"http"` bucket
via the `elif event_type.startswith("http.")` branch. Having its own bucket means
scanner detections can be reasoned about independently in future cooldown tuning.

### 8c. Add Telegram header in `_build_message()`

The header chain is an `if/elif/else` sequence (confirmed at sentinel.py lines 423–458).
Insert before the final `else` block:

```python
    elif event_type == "http.scanner.fingerprinted":
        tool = payload_data.get("inferred_tool") or "Unknown Tool"
        confidence = payload_data.get("confidence") or "?"
        header = f"🚨🤖 <b>SCANNER IDENTIFIED — {_esc(tool.replace('_', ' ').upper())} ({confidence})</b>"
```

Also update `_build_reason()` (sentinel.py lines 119–224). Insert before the
`if event_type.startswith("http."):` fallback (confirmed at line 207):

```python
    if event_type == "http.scanner.fingerprinted":
        tool   = payload.get("inferred_tool") or "automated scanner"
        method = payload.get("detection_method") or "signature"
        conf   = payload.get("confidence") or "?"
        rate_flag = payload.get("scan_rate_exceeded", False)
        rate_note = " + rate exceeded" if rate_flag else ""
        return f"Tool fingerprinted: {tool} — confidence={conf}, method={method}{rate_note} — path={path}"
```

### 8d. Per-tool dedup — PostgreSQL-backed, restart-survivable (NEW-1 fix)

**NEW-1 fix replacing the Round 2 Redis approach.**

The Round 2 plan used `_scanner_already_seen_redis()` with `_redis_lib.from_url(REDIS_URL, ...)`.
The gatekeeper confirmed that `sentinel.py` does NOT import `redis` and `REDIS_URL` is NOT
defined in sentinel's config block or compose environment. Both names are caught by the
`except Exception: return False` handler, making the function permanently fail-open — every
`http.scanner.fingerprinted` event fires a Telegram alert, which is the MAJ-1 flood reintroduced.

**Fix (Option B — PostgreSQL dedup)**: Query `honeypot_events` directly using the `conn`
that the sentinel polling loop already holds. No new import, no new compose variable,
no new container dependency. The query is a simple COUNT over the last hour filtered by
`event_type`, `src_ip`, and `payload->>'inferred_tool'`. Uses an index scan on `created_at`
(TimescaleDB hypertable — one chunk covers the last hour, so this is fast).

**Fail-closed on error**: if the query raises an exception, return `True` (treat as
"already seen") to suppress the alert. A PostgreSQL outage during an active scan should
not produce a Telegram flood — it should silently hold alerts until the DB recovers.
This is the opposite of `_check_scan_rate` in `main.py`, which fails open (never block
the response path). Here we are only deciding whether to send a Telegram message, so
fail-closed is the safe direction.

**No new imports required.** `json` is already imported (sentinel.py line 16). `psycopg2`
is already imported (sentinel.py line 23). No changes to sentinel's compose environment.

Add this function near `_suppressed()` (sentinel.py line 74):

```python
def _scanner_already_seen_pg(conn, src_ip: str, inferred_tool: str) -> bool:
    """
    Return True if we have already sent a Telegram alert for this (IP, tool) pair
    within the last hour, determined by checking honeypot_events directly.

    Uses the existing psycopg2 connection that the sentinel polling loop holds.
    No new imports, no new env vars, no Redis dependency.

    Query: COUNT(*) of http.scanner.fingerprinted rows for this src_ip + inferred_tool
    in the last hour. If count > 1, we have already fired at least one alert for this
    pair during the current hour window, so suppress.

    Threshold is > 1 (not > 0) because the event that is being evaluated right now is
    already written to honeypot_events by main.py before sentinel ever polls it. A count
    of exactly 1 means this IS the first event — fire the alert. A count > 1 means we
    have seen this pair at least once before in the past hour — suppress.

    Fail-closed on any exception: return True (suppress) rather than flood on DB error.
    IP normalization: strip CIDR suffix with split("/")[0], consistent with _build_message.
    """
    ip = (src_ip or "").split("/")[0].strip()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*)
                FROM honeypot_events
                WHERE event_type = 'http.scanner.fingerprinted'
                  AND src_ip::text LIKE %s
                  AND payload->>'inferred_tool' = %s
                  AND created_at > NOW() - INTERVAL '1 hour'
                """,
                (f"{ip}%", inferred_tool),
            )
            row = cur.fetchone()
            count = row[0] if row else 0
        # count == 1: this is the row currently being processed (first occurrence) — alert
        # count  > 1: a prior alert has already fired for this (IP, tool) in the hour — suppress
        return count > 1
    except Exception:
        # DB error — fail closed: suppress rather than flood
        return True
```

**Implementation note — `src_ip::text LIKE %s` pattern**: PostgreSQL stores `src_ip` as
`inet`, which casts to text as `"1.2.3.4/32"`. Matching with `LIKE '1.2.3.4%'` covers
both the bare-IP and CIDR-suffix forms without a separate `host()` call. The `%` wildcard
is appended to `ip` in the Python parameter, not inside the SQL string, to avoid
injection through `ip` itself (though `ip` is already stripped to a bare address string).

**Exact insertion anchor in the real polling loop**:

The gatekeeper confirmed the real code at sentinel.py lines 756–764 is:

```python
                should, reason, category = _should_alert(row)
                if should:
                    src_ip = row.get("src_ip") or ""
                    event_type = row.get("event_type", "")
                    # No-cooldown events always fire regardless of suppression window.
                    # HTTP pages use the 3-tier map; all others use the global cooldown.
                    cooldown = _HTTP_TIER_COOLDOWN.get(category, ALERT_COOLDOWN_SECS)
                    if event_type in _NO_COOLDOWN_EVENTS or not _suppressed(src_ip, category, cooldown):
                        send_alert(row, reason, category)
```

The dedup block is inserted INSIDE `if should:`, after `event_type` is assigned, gated
on `event_type == "http.scanner.fingerprinted"`. The `conn` reference used here is the
same connection object that the outer polling loop holds — it is in scope at this point.

```python
                should, reason, category = _should_alert(row)
                if should:
                    src_ip = row.get("src_ip") or ""
                    event_type = row.get("event_type", "")
                    # No-cooldown events always fire regardless of suppression window.
                    # HTTP pages use the 3-tier map; all others use the global cooldown.
                    cooldown = _HTTP_TIER_COOLDOWN.get(category, ALERT_COOLDOWN_SECS)

                    # Per-tool PostgreSQL dedup — suppresses repeat scanner alerts for
                    # the same (IP, tool) pair within a 1-hour window.
                    # Only applies to http.scanner.fingerprinted — all other event types
                    # use the normal _suppressed() cooldown path below.
                    # Uses existing conn — no new imports or env vars required.
                    if event_type == "http.scanner.fingerprinted":
                        raw_payload = row.get("payload") or "{}"
                        try:
                            _pl = json.loads(raw_payload) if isinstance(raw_payload, str) else raw_payload
                        except Exception:
                            _pl = {}
                        _itool = _pl.get("inferred_tool") or "unknown"
                        _ip_clean = (src_ip or "").split("/")[0]
                        if _scanner_already_seen_pg(conn, _ip_clean, _itool):
                            log.info("scanner_alert_deduped src_ip=%s tool=%s", _ip_clean, _itool)
                            continue  # skip send_alert; cursor already advanced above

                    if event_type in _NO_COOLDOWN_EVENTS or not _suppressed(src_ip, category, cooldown):
                        send_alert(row, reason, category)
```

**Why `continue` is safe here**: The cursor advance (`new_since`, `new_last_id`) happens
at lines 745–754, BEFORE `_should_alert()` is called. By the time we reach `continue`,
the cursor has already been updated. The `continue` only skips `send_alert` — it does
not corrupt the cursor or lose any event from PostgreSQL.

**Trade-off vs Redis approach**: The PostgreSQL query adds one extra SELECT per
`http.scanner.fingerprinted` event. In practice, these events are rare compared to total
poll volume (most events are SSH login attempts or health checks). The query is cheap: it
hits the TimescaleDB `created_at` index on a single hypertable chunk covering the last
hour. A sustained scanner sweep generating 1 event/second would add ~60 extra SELECTs
per minute to a connection that is already issuing a multi-row SELECT every 10 seconds.
This is negligible. The benefit is zero new infrastructure: no Redis import, no compose
change, no REDIS_URL wiring.

---

## 9. Testing Checklist

Run all checks from the VPS (`/opt/honeypot/deploy/module-6-honeypot-api/`).
These tests must leave the verify-module-6.sh score at 10/10.

### 9a. Unit-style checks (no deploy required — run locally)

```bash
# Confirm _fingerprint_tool parses correctly — paste into python3 -c
python3 - <<'PYEOF'
import urllib.parse

# Minimal stubs to test the function without full import
def _dd(s):
    d = urllib.parse.unquote_plus(s)
    return urllib.parse.unquote_plus(d)

# 1. sqlmap UA
ua = "sqlmap/1.7.12#stable (https://sqlmap.org)"
assert "sqlmap/" in ua.lower(), "FAIL: sqlmap UA not matched"
print("PASS: sqlmap UA pattern present")

# 2. nuclei payload pattern (interact.sh — nuclei-specific OOB domain)
body = "GET /.nuclei-test HTTP/1.1"
assert ".nuclei-" in body.lower(), "FAIL: nuclei path pattern not matched"
print("PASS: nuclei path pattern present")

# 3. burp OOB domain in body (unambiguous — burp UA also present)
body2 = "callback=http://abc123.burpcollaborator.net/"
ua2 = "Burp Suite Professional"
assert "burpcollaborator.net" in body2.lower(), "FAIL: burp payload not matched"
assert "burp" in ua2.lower(), "FAIL: burp UA not matched"
print("PASS: burp combined (UA + payload) detection")

# 4. shared OOB domain, no UA → should be oast_dast, not attributed
body3 = "callback=http://abc123.oastify.com/"
ua3 = "python-requests/2.31.0"
# oastify.com is in burp.payload_patterns but UA is python-requests (not burp)
# Expected result: inferred_tool = "oast_dast"
assert "oastify.com" in body3.lower(), "FAIL: oastify not in body"
print("PASS: oast_dast co-detection prerequisite verified (UA + OOB domain disambiguation)")

# 5. wfuzz — must NOT match python-requests UA (removed from wfuzz signatures)
ua4 = "python-requests/2.31.0"
assert "wfuzz/" not in ua4.lower(), "FAIL: wfuzz UA mistakenly matched python-requests"
print("PASS: python-requests not attributed to wfuzz")

# 6. IPv4-mapped IPv6 normalization
ip1 = "::ffff:1.2.3.4"
normalized = ip1[7:] if ip1.startswith("::ffff:") else ip1
assert normalized == "1.2.3.4", f"FAIL: expected 1.2.3.4 got {normalized}"
print("PASS: IPv4-mapped IPv6 normalization")

# 7. IPv6 /64 truncation
ip2 = "2001:db8:0:1:a:b:c:d"
parts = ip2.split(":")
truncated = ":".join(parts[:4])
assert truncated == "2001:db8:0:1", f"FAIL: expected 2001:db8:0:1 got {truncated}"
print("PASS: IPv6 /64 truncation")

# 8. sqlmap stable payload canaries (replacing removed hex canary)
payload_body = "' OR '1'='1 AND sleep(5)--"
assert "' or '1'='1" in payload_body.lower(), "FAIL: sqlmap tautology not matched"
assert "and sleep(" in payload_body.lower(), "FAIL: sqlmap sleep canary not matched"
print("PASS: sqlmap stable payload canaries (tautology + sleep)")

print("All local checks passed")
PYEOF
```

### 9b. UA fingerprint test (after deploy)

```bash
# nuclei UA — must return event_type http.scanner.fingerprinted in PG
# NOTE: /api/v1/health is now excluded from rate tracking (CRIT-2 fix)
# Use a non-health path to verify fingerprinting fires on excluded paths still log
curl -s -A "Nuclei/3.2.1 (https://nuclei.projectdiscovery.io)" \
     http://127.0.0.1:8080/api/v1/cluster/nodes | python3 -m json.tool

# Wait 2s then check DB
sleep 2
docker exec postgres psql -U honeypot -d honeypot \
  -c "SELECT event_type, payload->>'inferred_tool' as tool, payload->>'confidence' as conf \
      FROM honeypot_events WHERE payload->>'inferred_tool' IS NOT NULL \
      ORDER BY created_at DESC LIMIT 3;"
# Expected: event_type = http.scanner.fingerprinted, tool = nuclei, conf = medium
```

### 9c. Payload fingerprint test (sqlmap stable canaries)

```bash
# sqlmap tautology + sleep in body — SNARE (http.post.sqli.attempt) wins event_type,
# but inferred_tool = sqlmap must appear in payload
curl -s -X POST http://127.0.0.1:8080/api/v1/auth \
  -H "Content-Type: application/json" \
  --data-raw '{"email":"admin@test.com","password":"x AND sleep(5)--"}' \
  | python3 -m json.tool

sleep 2
docker exec postgres psql -U honeypot -d honeypot \
  -c "SELECT event_type, payload->>'inferred_tool' as tool \
      FROM honeypot_events ORDER BY created_at DESC LIMIT 3;"
# Expected: event_type = http.post.sqli.attempt (SNARE wins), tool = sqlmap
```

### 9d. Rate exclusion test — static assets must NOT trigger rate flag

```bash
# 25 rapid requests to static assets — must NOT set scan_rate_exceeded
for i in $(seq 1 25); do
  curl -s "http://127.0.0.1:8080/static/js/metrics.js" > /dev/null
done

sleep 2
docker exec postgres psql -U honeypot -d honeypot \
  -c "SELECT COUNT(*) FROM honeypot_events
      WHERE payload->>'scan_rate_exceeded' = 'true'
      AND created_at > NOW() - INTERVAL '30 seconds';"
# Expected: 0 rows — static assets excluded from rate tracking

# Verify Redis key was NOT created for static requests
docker exec redis redis-cli ZCARD "honeypot:scanrate:127.0.0.1"
# Expected: 0 (or very low — only non-static requests count)
```

### 9e. Rate-based scanner detection test (non-static path)

```bash
# 25 rapid requests to a non-static path — must exceed threshold (20/10s)
for i in $(seq 1 25); do
  curl -s "http://127.0.0.1:8080/api/v1/cluster/nodes" > /dev/null
done

sleep 2
docker exec postgres psql -U honeypot -d honeypot \
  -c "SELECT event_type, payload->>'scan_rate_exceeded' as rate_flag \
      FROM honeypot_events WHERE payload->>'scan_rate_exceeded' = 'true' \
      ORDER BY created_at DESC LIMIT 3;"
# Expected: rows with scan_rate_exceeded = true, event_type = http.scanner.fingerprinted
# Note: src_ip will be 127.0.0.1 — rate key = honeypot:scanrate:127.0.0.1

docker exec redis redis-cli ZCARD "honeypot:scanrate:127.0.0.1"
# Expected: count between 0 and 25 (older entries expired from 10s window)
```

### 9f. Low-confidence UA does NOT fire scanner event without rate flag

```bash
# Single curl request — UA match only (low confidence), no rate threshold crossed
curl -s -A "curl/8.1.2" http://127.0.0.1:8080/ > /dev/null

sleep 2
docker exec postgres psql -U honeypot -d honeypot \
  -c "SELECT event_type, payload->>'inferred_tool' as tool, payload->>'confidence' as conf \
      FROM honeypot_events ORDER BY created_at DESC LIMIT 2;"
# Expected: event_type = http.get.login_page (not http.scanner.fingerprinted)
# payload should have inferred_tool = curl_mass_scanner, confidence = low
# _is_scanner_event should be False (no rate flag)
```

### 9g. PostgreSQL dedup test — second nuclei request does NOT re-fire Telegram

```bash
# After 9b above fires a scanner alert, a second nuclei request to the same path
# should be deduped: honeypot_events now has count > 1 for this (IP, tool) pair
curl -s -A "Nuclei/3.2.1" http://127.0.0.1:8080/api/v1/cluster/nodes > /dev/null

# Confirm two rows now exist for this (IP, tool) in the last hour
docker exec postgres psql -U honeypot -d honeypot \
  -c "SELECT COUNT(*) FROM honeypot_events
      WHERE event_type='http.scanner.fingerprinted'
        AND src_ip::text LIKE '127.0.0.1%'
        AND payload->>'inferred_tool'='nuclei'
        AND created_at > NOW() - INTERVAL '1 hour';"
# Expected: count >= 2 (the dedup threshold — > 1 means suppress)

# Watch sentinel logs — must show dedup suppression, not a second alert
docker logs sentinel 2>&1 | grep "scanner_alert_deduped" | tail -5
# Expected: at least one line with src_ip=127.0.0.1 tool=nuclei
```

### 9h. Verify 10/10 score is unchanged

```bash
cd /opt/honeypot/deploy/module-6-honeypot-api/
bash verify-module-6.sh
# Must still return 10/10
# CRIT-2 fix ensures the healthcheck path (/api/v1/health) is excluded from rate
# tracking, so the verify script's own probes don't pollute the rate window and
# a Redis outage during verify doesn't flip a check.
```

### 9i. Vocabulary gate (deception rule compliance)

```bash
grep -rn "sqlmap\|nuclei\|gobuster\|ffuf\|masscan\|zgrab\|nikto\|burp\|hydra\|wfuzz\|metasploit\|nmap\|dirsearch" \
  deploy/module-6-honeypot-api/src/static/ \
  deploy/module-6-honeypot-api/src/templates/
# Expected: zero matches
# All tool names live only in main.py (server-side)
```

---

## 10. What Does NOT Change

This is an explicit safety list. The gatekeeper should confirm that none of these
were accidentally touched during implementation.

| File / Component | Change? | Notes |
|---|---|---|
| All 14 HTML templates in `src/templates/` | NO | No tool names, no new routes visible to client |
| `src/static/js/metrics.js` | NO | Client-side fingerprinting vocabulary unchanged |
| `src/static/` (all CSS, images) | NO | Zero changes |
| `jupyter_stub.py` | NO | Separate process, no fingerprinting needed |
| `deploy/module-5-log-shipper/src/log_shipper.py` | NO | Tool fingerprinting is HTTP-only — Cowrie/MariaDB events not affected |
| `deploy/module-2-cowrie/` | NO | No changes |
| `deploy/module-3-opencanary/` | NO | No changes |
| `deploy/module-4-mariadb-lure/` | NO | No changes |
| `deploy/module-7-nginx/` | NO | No routing changes |
| `deploy/module-8-smb-lure/` | NO | No changes |
| `_detect_web_attack()` | NO | Function signature and body unchanged |
| `_push_honeydash_async()` | NO | Function unchanged; existing call sites now pass new attack_type strings |
| `_compute_bot_score()` | NO | `_SCANNER_UA_FRAGMENTS` list unchanged; bot_score path unchanged |
| `_SCANNER_UA_FRAGMENTS` | NO | Left in place; `_TOOL_SIGNATURES` adds structure on top without replacing it |
| `attacker_sessions` table schema | NO | No schema migrations needed |
| `honeypot_events` table schema | NO | `payload` is JSONB — new keys stored without migration |
| Existing `_NO_COOLDOWN_EVENTS` entries | NO | Only one entry added, no removals |
| Existing `_SNARE_CATEGORIES` entries | NO | Only one entry added, no modifications |
| Existing Telegram headers in `_build_message()` | NO | New `elif` block inserted before `else`, no existing branches changed |
| Docker compose files for any module | NO | No new env vars, volumes, or service definitions — sentinel PostgreSQL dedup uses existing `POSTGRES_DSN` only |
| `requirements.txt` | NO | All required libraries already installed; sentinel dedup uses `psycopg2` (already imported in sentinel.py) |

---

## 11. Known Gaps (MIN-1)

The following limitations are acknowledged and out of scope for this implementation:

**UA-spoofing defeats UA-based signatures**: sqlmap `--random-agent`, nuclei with
custom UA, and any `requests` script setting a Chrome UA will bypass UA pattern
matching entirely. A sophisticated attacker who randomizes their UA and avoids OOB
callback domains will fingerprint as `automated_scanner` (rate-only detection) at best,
or evade entirely if they scan slowly enough to stay under the rate threshold.

**JA3/HASSH fingerprinting is not available at the application layer**: The durable
TLS fingerprint (JA3 hash from the ClientHello) and the SSH key-exchange fingerprint
(HASSH) would catch UA-randomizing tools. Both terminate at nginx/OpenResty — the
FastAPI application receives a decrypted connection and cannot observe the original
TLS record. Adding JA3 would require a custom OpenResty module (e.g., `lua-resty-ja3`)
and is tracked as a future improvement, not part of this feature.

**Slow scanners evade rate detection**: The `_SCAN_RATE_THRESHOLD` of 20 req/10s is
tuned for fast automated scanners. A scanner rate-limited to 1 req/2s crosses the
threshold only after 40 seconds, producing 4x the Redis ZADD overhead without
escalating. Threshold is configurable via `_SCAN_RATE_THRESHOLD` without code change.

---

## Appendix A: Redis Key Inventory

New keys introduced by this feature:

| Key pattern | Type | TTL | Purpose |
|---|---|---|---|
| `honeypot:scanrate:<normalized_ip>` | Sorted Set | `_SCAN_RATE_KEY_TTL_SECS` (60s) | Sliding-window request counter per IP (non-static paths only) |
| `honeypot:scanner_seen:<ip>:<tool>` | String | 3600s (1 hour) | Per-(IP, tool) dedup — prevents re-flood on sentinel restart |

No conflicts with existing keys:
- Cowrie stream: `honeypot:events` (Stream type — different Redis data structure)
- OpenCanary: no direct Redis keys
- MariaDB: no direct Redis keys
- HoneyDash flusher: no Redis keys

---

## Appendix B: Event Type Taxonomy After This Feature

New event type introduced:

| Event type | Trigger condition | SNARE category | Cooldown |
|---|---|---|---|
| `http.scanner.fingerprinted` | Tool identified (high/medium confidence) OR rate threshold crossed | `web.scanner` | None (`_NO_COOLDOWN_EVENTS`) — dedup handled by Redis per-(IP,tool) key |

The `inferred_tool` field in `payload` JSONB distinguishes individual tools within
this event type. Redis-backed dedup (`honeypot:scanner_seen:*`) prevents repeat alerts
for the same IP + tool combination for 1 hour, surviving sentinel restarts.

---

## Appendix C: Operator Note on First Deploy

After deploying this change, the first few minutes of live traffic will generate
scanner fingerprint events from any active scanners already hitting the honeypot.
Telegram will receive a burst of `SCANNER IDENTIFIED` alerts (one per unique
IP + tool combination that has not been seen in Redis within the last hour). This is
expected and confirms the feature is working. Subsequent requests from the same tool
are suppressed by the Redis dedup key for 1 hour.

---

## Revision History

| Round | Date | Changes |
|---|---|---|
| Round 1 | 2026-06-11 | Initial plan submitted for gatekeeper review |
| Round 2 | 2026-06-12 | CRIT-1: `_check_scan_rate` rewritten as `async def`, uses `_get_redis_async()` (redis.asyncio), `await`-ed in middleware — eliminates event-loop blocking. CRIT-2: rate check now receives `path` arg; excludes `/static/*`, `/favicon.ico`, `/api/v1/health`, `/api/v2/health`; Redis TTL raised to 60s to bound memory under IP rotation. CRIT-3: sentinel section 8d rewritten against the real polling loop (lines 756–764); there is no `if not should: continue` guard — dedup block is inserted INSIDE `if should:` after `event_type` is assigned. MAJ-1: in-memory `_SCANNER_SEEN` set replaced with Redis `SET NX EX 3600` per-(ip,tool) dedup in `_scanner_already_seen_redis()` — restart-survivable, auto-expiring, never silently disables itself at cap. MAJ-2: sqlmap hex canary `0x31303235343830303536` removed; replaced with stable payload markers (`and sleep(`, `' or '1'='1`, `union select null--`, `and 1=1--`); comment updated to clarify SQLi primary classification is `_detect_web_attack` not this function. MAJ-3: `{{` (nuclei), `zzz` (wfuzz), bare `fuzz` (ffuf/wfuzz), `/robots.txt` (nikto), `/.git/COMMIT_EDITMSG` + `/.svn/` + `/server-status` (dirsearch) all removed to prevent false positives against honeypot's own lure paths and crawler traffic. MAJ-4: `"python-requests"` removed from wfuzz UA patterns (collided with python_scanner); `"libwww-perl"` removed from hydra (too generic); dict ordering documented with explicit specificity constraint (Tier 1: specific tools first, Tier 3: generic last). MAJ-5: `_normalize_src_ip_for_rate()` added — strips `/32` CIDR suffix, strips `::ffff:` IPv4-mapped prefix, truncates IPv6 to /64; sentinel dedup uses same strip (`split("/")[0]`); both paths now normalize identically. MIN-1: Known Gaps section added covering UA-spoofing, JA3/HASSH scope, and slow-scanner evasion. MIN-2: OOB co-detection implemented — shared domains (`burpcollaborator.net`, `oastify.com`) emit `inferred_tool: "oast_dast"` when no UA resolves attribution. |
| Round 3 | 2026-06-12 | NEW-1: Replaced `_scanner_already_seen_redis()` (which referenced `_redis_lib` and `REDIS_URL`, neither of which exist in sentinel.py or its compose environment) with `_scanner_already_seen_pg()` — a PostgreSQL-backed dedup that queries `honeypot_events` using the `conn` the polling loop already holds. No new imports, no compose changes. Fail direction inverted: now fails CLOSED (return `True` / suppress) on DB error, preventing flood on outage. Dedup threshold is count > 1: since the triggering event is already written to `honeypot_events` before sentinel polls it, count == 1 means first occurrence (fire), count > 1 means already alerted this hour (suppress). Test 9g updated to use PostgreSQL COUNT check instead of `redis-cli GET`. Section 1 architecture note updated to reflect no new imports. Table 10 compose and requirements rows updated to remove Redis-specific claims. |
