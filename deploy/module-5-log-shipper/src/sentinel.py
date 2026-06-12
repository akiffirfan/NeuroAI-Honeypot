#!/usr/bin/env python3
"""
sentinel.py — Standalone Telegram alerter for Neuro Honeypot Platform.

Polls PostgreSQL every POLL_INTERVAL seconds for new high-value events and
sends Telegram notifications.  Runs as its own container — completely
independent of log_shipper.py.

Requires:  POSTGRES_DSN  +  Telegram credentials via Docker secret files
           /run/secrets/telegram_bot_token  and  /run/secrets/telegram_chat_id
           (env vars TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID accepted as fallback)
Optional:  POLL_INTERVAL (default 10)  ALERT_COOLDOWN_SECS (default 60)
"""

import html
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg2
import requests

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
def _read_secret(secret_name: str, env_var: str, default: str = "") -> str:
    """Read from Docker secret file; fall back to env var.

    Docker Compose mounts secrets at /run/secrets/<name>. Reading from a file
    keeps the value out of `docker inspect` env output and /proc/PID/environ.
    """
    path = Path(f"/run/secrets/{secret_name}")
    if path.exists():
        return path.read_text().strip()
    return os.environ.get(env_var, default)

TELEGRAM_BOT_TOKEN  = _read_secret("telegram_bot_token", "TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID    = _read_secret("telegram_chat_id",   "TELEGRAM_CHAT_ID")
POSTGRES_DSN        = os.environ["POSTGRES_DSN"]
POLL_INTERVAL       = int(os.environ.get("POLL_INTERVAL", "10"))
ALERT_COOLDOWN_SECS = int(os.environ.get("ALERT_COOLDOWN_SECS", "60"))
# Three-tier HTTP alert cooldown:
#   Tier 1 — always-alert:  /admin, /api-keys, /artifacts, /settings/*  →  0s (no suppression)
#   Tier 2 — sensitive:     /jobs/new, /models, /datasets, /runs         →  300s
#   Tier 3 — routine:       /dashboard, /notifications, generic probes   →  1800s
_SENSITIVE_COOLDOWN_SECS = 300
_ROUTINE_COOLDOWN_SECS   = 1800

_HTTP_TIER_COOLDOWN = {
    "http.always_alert": 0,
    "http.sensitive":    _SENSITIVE_COOLDOWN_SECS,
    "http.routine":      _ROUTINE_COOLDOWN_SECS,
    "web.webhook":       _SENSITIVE_COOLDOWN_SECS,   # external webhook test — 5-min cooldown
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("sentinel")

# ---------------------------------------------------------------------------
# Per-(IP, category) cooldown  [MAJ-R9-2]
# Keyed by (src_ip, category) so a MariaDB connect from IP X does not
# suppress a subsequent MariaDB query or web-lure alert from the same IP.
# ---------------------------------------------------------------------------
_cooldowns: dict = {}   # {(src_ip, category): last_alert_monotonic}


def _suppressed(src_ip: str, category: str, cooldown: int = ALERT_COOLDOWN_SECS) -> bool:
    """Return True if this (IP, category) pair was alerted within the cooldown window."""
    key  = (src_ip, category)
    now  = time.monotonic()
    last = _cooldowns.get(key, 0.0)
    if now - last < cooldown:
        return True
    _cooldowns[key] = now
    return False


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


# ---------------------------------------------------------------------------
# Alert decision logic
# ---------------------------------------------------------------------------
# Suppressed (pure noise — no attacker value):
#   http.get.health   — Docker healthcheck from 127.0.0.1 every 30s
#   cowrie.session.closed — lifecycle bookkeeping, no attacker data
#   api.startup       — honeypot-api boot event
#
# Everything else fires — cooldown per (src_ip, event_type) prevents floods.
# ---------------------------------------------------------------------------
_NOISE_EVENTS = {"http.get.health", "cowrie.session.closed", "api.startup",
                 "cowrie.session.connect", "smtp.session.connect", "smtp.ehlo",
                 "smb.server.started",              # Module 8 startup sentinel — not an attacker action
                 "http.post.api.v1.telemetry",      # metrics.js beacons — not attacker actions
                 "http.get.api.v1.telemetry",       # same, GET variant
                 "http.post.telemetry"}             # alternate telemetry route name

# Events that always alert — no cooldown suppression regardless of (IP, category)
_NO_COOLDOWN_EVENTS = {
    "http.lure.credential.success",
    "cowrie.session.file_download",
    "cowrie.login.success",
    "http.upload.malware_received",      # attacker uploaded a file — always alert
    "http.lure.data_exfil",             # attacker downloaded a lure file — always alert
    "http.canarytoken.fired",           # out-of-band canarytoken hit — always alert
    "cross_sensor.credential_relay",    # SSH config.yaml read → MariaDB connect — always alert
    "smb.ntlmv2.hash",                  # NTLMv2 hash capture — highest-value SMB event, always alert
    "http.telemetry.devtools_opened",   # human attacker: F12/side-panel — always alert
    "http.unauth.sensitive_access",    # direct hit on /admin /api-keys /jobs-new without session — always alert
    "http.snare.mfa_enable_attempt",   # password submitted to enable MFA — always alert (captures credential)
    "http.security.allowlist_toggle",  # attacker attempting perimeter lockdown — always alert
    "http.scanner.fingerprinted",      # new tool identification — each is distinct intel, no cooldown
    "http.contact.malicious_form",     # XSS/SQLi in sales contact form — always alert
}


def _build_reason(event_type: str, row: dict, payload: dict) -> str:
    """Human-readable one-line summary for a Telegram alert message."""
    username  = row.get("username") or ""
    password  = row.get("password") or ""
    dst_port  = row.get("dst_port")
    cmd_input = payload.get("input") or ""
    path      = payload.get("path") or ""
    method    = payload.get("method") or "GET"
    url       = payload.get("url") or payload.get("outfile") or ""
    protocol  = payload.get("protocol") or ""

    filename  = payload.get("filename") or payload.get("saved_as") or ""
    size      = payload.get("size_bytes") or ""
    mime      = payload.get("mime_type") or ""
    real_ip   = payload.get("real_ip") or payload.get("canarytoken_src_ip") or payload.get("src_ip") or (row.get("src_ip") or "").split("/")[0]
    ssrf_url  = payload.get("webhook_url") or payload.get("source_url") or ""
    passwords = payload.get("last_passwords_tried") or []

    if event_type == "http.upload.malware_received":
        size_str = f"{size} bytes" if size else "unknown size"
        return f"UPLOAD CAPTURED: {filename or '(unnamed)'} — {size_str}, {mime or 'unknown type'}"
    if event_type == "http.lure.data_exfil":
        dl_file = payload.get("path") or payload.get("file") or path or "(unknown)"
        return f"LURE FILE DOWNLOADED: {dl_file}"
    if event_type == "http.canarytoken.fired":
        return f"CANARYTOKEN FIRED — real attacker IP: {real_ip or '(not captured)'}"
    if event_type == "http.unauth.sensitive_access":
        return f"Unauthenticated access — {path or url} — no session (recon or credential skip attempt)"
    if event_type == "http.snare.ssrf_attempt":
        return f"SSRF Attempt — target URL: {ssrf_url[:100] or path}"
    if event_type == "http.webhook.test":
        wh_url = payload.get("webhook_url") or ""
        return f"External webhook test — possible C2 URL: {wh_url[:100] or '(no url)'}"
    if event_type in ("http.snare.mfa_enable_attempt", "http.snare.mfa_disable_attempt"):
        correct = payload.get("password_correct", False)
        pw = payload.get("attempted_password") or ""
        status = "CORRECT PASSWORD" if correct else "wrong password"
        return f"MFA enable attempt — {status} — submitted: '{pw[:60]}'"
    if event_type == "http.security.allowlist_toggle":
        enabled = payload.get("enabled", False)
        action = "ENABLED (perimeter lockdown)" if enabled else "disabled"
        return f"IP Access Control toggle — {action} — attacker locking down perimeter"
    if event_type == "http.prompt.injection":
        pattern = payload.get("pattern") or ""
        preview = payload.get("body_preview") or ""
        return f"Prompt injection — pattern: '{pattern}' — body: {preview[:100]}"
    if event_type == "cross_sensor.credential_relay":
        prior = payload.get("prior_ssh_cmd") or ""
        user  = payload.get("mariadb_user") or username or ""
        return f"CREDENTIAL RELAY: SSH read config.yaml → MariaDB connect as '{user}' — prior cmd: {prior[:80]}"
    if event_type == "http.bruteforce.detected":
        pw_list = ", ".join(str(p) for p in passwords[-5:]) if passwords else "unknown"
        return f"Bruteforce detected — last passwords: [{pw_list}]"
    if event_type == "http.lure.credential.success":
        return f"LURE CREDENTIAL USED — {username} / {password}"
    if event_type == "cowrie.login.success":
        return f"SSH login SUCCESS — user={username}"
    if event_type == "cowrie.login.failed":
        sensor = row.get("sensor") or ""
        if sensor == "opencanary":
            port_proto = {21: "FTP", 23: "TELNET", 25: "SMTP", 6379: "REDIS"}
            proto_label = port_proto.get(dst_port, "SSH")
            return f"{proto_label} login attempt — user={username} pass={password}"
        return f"SSH login attempt — user={username} pass={password}"
    if event_type == "cowrie.session.connect":
        if dst_port == 3306:
            return f"MariaDB connect — user={username or '(unknown)'}"
        proto = protocol or (f"port {dst_port}" if dst_port else "unknown")
        return f"Connection probe — {proto}"
    if event_type == "cowrie.command.input":
        return f"Command: {cmd_input[:120]}"
    if event_type == "cowrie.session.file_download":
        return f"Payload download: {url or '(unknown)'}"
    if event_type == "http.scanner.fingerprinted":
        tool      = payload.get("inferred_tool") or "automated scanner"
        method    = payload.get("detection_method") or "signature"
        conf      = payload.get("confidence") or "?"
        rate_flag = payload.get("scan_rate_exceeded", False)
        rate_note = " + rate exceeded" if rate_flag else ""
        return f"Tool fingerprinted: {tool} — confidence={conf}, method={method}{rate_note} — path={path}"
    # SNARE web attack event types — show attack category + method + path
    _SNARE_LABELS = {
        "http.sqli.attempt":      "SQL Injection",
        "http.post.sqli.attempt": "SQL Injection",
        "http.lfi.attempt":       "LFI Attempt",
        "http.get.lfi.attempt":   "LFI Attempt",
        "http.rce.attempt":       "RCE Attempt",
        "http.post.rce.attempt":  "RCE Attempt",
        "http.cmdi.attempt":      "Command Injection",
        "http.ssrf.attempt":      "SSRF Attempt",
        "http.xss.attempt":       "XSS Attempt",
        "http.get.xss.attempt":   "XSS Attempt",
    }
    if event_type in _SNARE_LABELS:
        return f"Web Attack ({_SNARE_LABELS[event_type]}): {method} {path}"
    if event_type.startswith("http."):
        creds = f" (user={username})" if username else ""
        return f"Web probe: {method} {path}{creds}"
    if event_type == "smtp.data.received":
        mail_from = payload.get("mail_from") or username or ""
        rcpts = payload.get("rcpt_to") or []
        rcpt_str = ", ".join(rcpts) if isinstance(rcpts, list) else str(rcpts)
        preview = payload.get("body_preview") or ""
        return f"SMTP DATA — from={mail_from} to={rcpt_str[:80]} body={preview[:80]}"
    if event_type == "smtp.auth.attempt":
        mechanism = payload.get("mechanism") or ""
        return f"SMTP AUTH attempt — mechanism={mechanism}"
    if event_type == "smtp.vrfy":
        user = payload.get("user") or username or ""
        return f"SMTP VRFY/EXPN enumeration — user={user}"
    if event_type.startswith("smtp."):
        return f"SMTP: {event_type} from {(row.get('src_ip') or '').split('/')[0]}"
    # SMB sensor events (Module 8)
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
    if event_type == "smb.connect":
        return f"SMB connection probe from {(row.get('src_ip') or '').split('/')[0]}"
    if event_type.startswith("smb."):
        return f"SMB probe: {event_type}"
    # Security page actions (FIX-B)
    if event_type.startswith("security."):
        action_map = {
            "security.mfa_toggle_attempt":     "MFA disable attempt",
            "security.session_revoke_attempt": "Session revocation attempt",
            "security.allowlist_probe":        "IP allowlist submission",
            "security.key_rotation_attempt":   "API key rotation triggered",
            "security.audit_log_viewed":       "Audit log accessed",
        }
        action = action_map.get(event_type, event_type)
        cidr         = payload.get("cidr") or ""
        label_str    = payload.get("label") or ""
        action_extra = payload.get("action") or ""
        # Mask password: show asterisks + last 2 chars (safe for length >= 2)
        if password and len(password) >= 2:
            pw_fragment = f" | password={'*' * max(len(password) - 2, 1)}{password[-2:]}"
        elif password:
            pw_fragment = f" | password={'*' * len(password)}"
        else:
            pw_fragment = ""
        extra = ""
        if cidr:
            extra = f" | cidr={cidr}"
        elif label_str:
            extra = f" | label={label_str}"
        elif action_extra:
            extra = f" | action={action_extra}"
        return f"{action}{pw_fragment}{extra} — path={path or event_type}"
    # DevTools detection (FIX-A)
    if event_type == "http.telemetry.devtools_opened":
        method_used = payload.get("method") or ""
        return f"DevTools opened — method={method_used or 'side-panel'} — POSSIBLE HUMAN ATTACKER"
    # Fallback — show raw event_type so nothing is ever blank
    return event_type


def _should_alert(row: dict) -> tuple:
    """
    Returns (True, reason, category) for any event worth alerting on,
    (False, '', '') for pure noise.

    Category = event_type — cooldown key is (src_ip, event_type) so the same
    IP can alert on SSH + MariaDB + web lure independently.
    """
    event_type = row.get("event_type", "")
    dst_port   = row.get("dst_port")

    if not event_type:
        return False, "", ""

    if event_type in _NOISE_EVENTS:
        # MariaDB TCP connect (port 3306) is worth alerting despite session.connect noise
        if event_type == "cowrie.session.connect" and dst_port == 3306:
            pass
        else:
            return False, "", ""

    # payload arrives as text (cast in query) — parse it
    raw_payload = row.get("payload") or "{}"
    try:
        payload = json.loads(raw_payload) if isinstance(raw_payload, str) else raw_payload
    except Exception:
        payload = {}

    reason = _build_reason(event_type, row, payload)
    # Cooldown category — controls how alerts are bucketed per (src_ip, category).
    # SNARE web attack types: each gets its own independent 60s window per IP so that
    #   SQLi → LFI → RCE from the same IP each fires a distinct alert.
    # General HTTP: all other http.* events collapse to "http" so a scanner sweep
    #   fires one alert per IP per window rather than one per URL path.
    # cowrie.login.failed: differentiate by dst_port so SSH (2222) and OpenCanary
    #   protocols (Telnet 23, FTP 21, SMTP 25, Redis 6379) each get their own bucket.
    #   Without this, an SSH login failure sets the cooldown and suppresses the
    #   subsequent Telnet alert from the same IP.
    # Everything else: use event_type as-is.
    _SNARE_CATEGORIES = {
        "http.sqli.attempt":          "web.sqli",
        "http.post.sqli.attempt":     "web.sqli",
        "http.lfi.attempt":           "web.lfi",
        "http.get.lfi.attempt":       "web.lfi",
        "http.rce.attempt":           "web.rce",
        "http.post.rce.attempt":      "web.rce",
        "http.cmdi.attempt":          "web.rce",
        "http.ssrf.attempt":          "web.ssrf",
        "http.snare.ssrf_attempt":    "web.ssrf",   # remote-import + webhook SSRF trap
        "http.xss.attempt":           "web.xss",
        "http.get.xss.attempt":       "web.xss",
        "http.bruteforce.detected":   "web.bruteforce",
        "http.prompt.injection":      "web.prompt_injection",
        "http.contact.malicious_form": "web.form_injection",  # own bucket — no-cooldown anyway
        # SMB sensor categories (Module 8) — each gets its own cooldown bucket
        "smb.ntlmv2.hash":    "smb.hash",    # no-cooldown anyway (in _NO_COOLDOWN_EVENTS)
        "smb.auth.attempt":   "smb",          # collapses with smb.connect per IP
        "smb.connect":        "smb",
        "smb.enum.shares":    "smb.enum",     # separate bucket — distinct recon step
        "smb.pipe.connect":   "smb.pipe",     # RPC enumeration — separate bucket
        "smb.file.read":      "smb.file",
        "smb.file.write":     "smb.file",     # collapses with smb.file.read per IP
        # Webhook test — give it its own bucket so it can't suppress/be-suppressed by generic http
        "http.post.api.v1.integrations.webhook.test": "web.webhook",
        "http.webhook.test":                          "web.webhook",   # external C2 URL test
        "http.snare.mfa_enable_attempt":              "web.mfa",       # password submitted to enable MFA
        "http.snare.mfa_disable_attempt":             "web.mfa",
        # Security page actions — all share one per-IP bucket so repeated probing fires one alert
        "security.mfa_toggle_attempt":     "web.security",
        "security.session_revoke_attempt": "web.security",
        "security.allowlist_probe":          "web.security",
        "http.snare.allowlist_probe":        "web.security",
        "http.security.allowlist_toggle":    "web.security.lockdown",  # own bucket — never collapses
        "security.key_rotation_attempt":   "web.security",
        "security.audit_log_viewed":       "web.security",
        # DevTools detection — own bucket, also in _NO_COOLDOWN_EVENTS
        "http.telemetry.devtools_opened":  "web.devtools",
        # Scanner fingerprint — own bucket so tool detections don't share cooldown with generic http
        "http.scanner.fingerprinted":      "web.scanner",
    }
    if event_type in _SNARE_CATEGORIES:
        cooldown_category = _SNARE_CATEGORIES[event_type]
    elif event_type.startswith("http."):
        # Strip "http.<method>." prefix to get the path portion
        parts = event_type.split(".", 2)
        et_path = parts[2] if len(parts) > 2 else ""
        # Tier 1 — always-alert: admin, api-keys, artifacts, settings/*
        if any(kw in et_path for kw in ("admin", "api-keys", "artifacts", "settings.")):
            cooldown_category = "http.always_alert"
        # Tier 2 — sensitive (5-min cooldown): jobs/new, models, datasets, runs
        elif any(et_path == kw or et_path.startswith(kw + ".") for kw in ("jobs.new", "models", "datasets", "runs")):
            cooldown_category = "http.sensitive"
        # Tier 3 — routine (30-min cooldown): dashboard, notifications, pipelines, static, generic probes
        elif any(kw in et_path for kw in ("dashboard", "notifications", "pipelines", "static")):
            cooldown_category = "http.routine"
        else:
            cooldown_category = "http"
    elif event_type == "cowrie.login.failed":
        _PORT_PROTO = {2222: "ssh", 21: "ftp", 23: "telnet", 25: "smtp", 6379: "redis", 3306: "mysql"}
        cooldown_category = f"login.{_PORT_PROTO.get(dst_port, 'other')}"
    else:
        cooldown_category = event_type
    return True, reason, cooldown_category


# ---------------------------------------------------------------------------
# Telegram helpers
# ---------------------------------------------------------------------------
def _esc(s) -> str:
    return html.escape(str(s)) if s else ""


def _build_message(row: dict, reason: str) -> str:
    event_type = row.get("event_type", "")
    src_ip  = row.get("src_ip") or "unknown"
    # Strip CIDR suffix that PostgreSQL inet::text appends (e.g. "1.2.3.4/32" → "1.2.3.4")
    if isinstance(src_ip, str) and "/" in src_ip:
        src_ip = src_ip.split("/")[0]
    country = row.get("geo_country") or ""
    city    = row.get("geo_city") or ""
    org     = row.get("geo_org") or ""
    sensor  = row.get("sensor") or "unknown"
    ts_raw  = row.get("created_at")
    ts      = str(ts_raw)[:19].replace("T", " ") if ts_raw else "unknown"

    loc_parts = [p for p in [city, country] if p]
    location  = ", ".join(loc_parts) if loc_parts else "unknown"
    if org:
        location += f" ({org})"

    username = row.get("username") or ""
    password = row.get("password") or ""

    # Parse payload for bot_score
    raw_payload = row.get("payload") or "{}"
    try:
        payload_data = json.loads(raw_payload) if isinstance(raw_payload, str) else raw_payload
    except Exception:
        payload_data = {}
    bot_score = payload_data.get("bot_score")

    # Priority header — each high-value event type gets a distinct Telegram header
    if event_type == "http.lure.credential.success":
        header = "🚨🔑 <b>LURE CREDENTIAL USED</b>"
    elif event_type == "http.upload.malware_received":
        header = "🚨🦠 <b>MALWARE UPLOAD CAPTURED</b>"
    elif event_type == "http.lure.data_exfil":
        header = "🚨📤 <b>LURE FILE DOWNLOADED</b>"
    elif event_type == "http.canarytoken.fired":
        header = "🚨🎯 <b>CANARYTOKEN FIRED — POST-EXFIL</b>"
    elif event_type == "http.prompt.injection":
        header = "🤖 <b>PROMPT INJECTION ATTEMPT</b>"
    elif event_type == "cross_sensor.credential_relay":
        header = "🔗🔑 <b>CREDENTIAL RELAY: SSH → MARIADB</b>"
    elif event_type == "smtp.data.received":
        header = "📧 <b>SMTP DATA CAPTURED</b>"
    elif event_type == "smtp.auth.attempt":
        header = "📧🔑 <b>SMTP AUTH ATTEMPT</b>"
    elif event_type == "cowrie.session.file_download":
        header = "🚨📦 <b>MALWARE DOWNLOAD CAPTURED</b>"
    elif event_type == "cowrie.login.success":
        header = "🚨✅ <b>SSH LOGIN SUCCESS</b>"
    elif event_type == "smb.ntlmv2.hash":
        header = "🪟🔑 <b>SMB HASH CAPTURED — NTLMv2</b>"
    elif event_type == "smb.file.write":
        header = "🪟📁 <b>SMB WRITE ATTEMPT</b>"
    elif event_type in ("smb.enum.shares", "smb.pipe.connect"):
        header = "🪟📁 <b>SMB SHARE PROBE</b>"
    elif event_type.startswith("smb."):
        header = "🪟📁 <b>SMB SHARE PROBE</b>"
    elif event_type == "http.unauth.sensitive_access":
        header = "🚪🔍 <b>UNAUTH SENSITIVE ACCESS — NO SESSION</b>"
    elif event_type == "http.telemetry.devtools_opened":
        header = "🔍 <b>DEVTOOLS OPENED — HUMAN ATTACKER</b>"
    elif event_type.startswith("security."):
        header = "🔐 <b>SECURITY PAGE ACTION</b>"
    elif event_type == "http.scanner.fingerprinted":
        tool       = (payload_data.get("inferred_tool") or "Unknown Tool").replace("_", " ").upper()
        confidence = payload_data.get("confidence") or "?"
        header = f"🚨🤖 <b>SCANNER IDENTIFIED — {_esc(tool)} ({_esc(confidence)})</b>"
    elif event_type == "http.contact.malicious_form":
        vector = payload_data.get("attack_vector") or "Unknown"
        header = f"🚨📋 <b>MALICIOUS FORM SUBMISSION — {_esc(vector)}</b>"
    else:
        header = "🚨 <b>Honeypot Alert</b>"

    lines = [
        header,
        "",
        f"<b>Reason:</b> {_esc(reason)}",
        f"<b>Source IP:</b> <code>{_esc(src_ip)}</code>",
        f"<b>Sensor:</b> {_esc(sensor)}",
        f"<b>Location:</b> {_esc(location)}",
        f"<b>Time:</b> {_esc(ts)} UTC",
    ]
    if username:
        lines.append(f"<b>Username:</b> <code>{_esc(username[:80])}</code>")
    if password:
        lines.append(f"<b>Password:</b> <code>{_esc(password[:80])}</code>")
    if bot_score is not None:
        if bot_score < 0.3:
            bot_label = "human-like ⚠️"
        elif bot_score < 0.7:
            bot_label = "mixed"
        else:
            bot_label = "automated"
        lines.append(f"<b>Bot score:</b> {bot_score:.2f} ({bot_label})")
    if row.get("is_tor"):
        lines.append("<b>TOR exit node</b> 🧅")
    return "\n".join(lines)


def _send(text: str) -> bool:
    """POST text to Telegram.  Returns True on success."""
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        resp = requests.post(
            url,
            json={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML"},
            timeout=8,
        )
        if resp.status_code == 200:
            return True
        log.warning("telegram HTTP %s: %s",
                    resp.status_code,
                    resp.text[:120].replace(TELEGRAM_BOT_TOKEN, "***"))
        return False
    except Exception as exc:
        log.warning("telegram error: %s", str(exc).replace(TELEGRAM_BOT_TOKEN, "***"))
        return False


def send_alert(row: dict, reason: str, category: str) -> None:
    src_ip = row.get("src_ip") or ""
    text = _build_message(row, reason)
    if _send(text):
        log.info("alert sent  src_ip=%s  category=%s  reason=%s", src_ip, category, reason[:80])


# ---------------------------------------------------------------------------
# PostgreSQL polling
# ---------------------------------------------------------------------------
_COLS = [
    "event_id", "event_type", "src_ip", "dst_port",
    "username", "password", "payload", "sensor", "created_at",
    "geo_country", "geo_city", "geo_org", "is_tor",
]

_QUERY = """
    SELECT event_id::text, event_type, src_ip::text, dst_port,
           username, password, payload::text, sensor, created_at,
           geo_country, geo_city, geo_org, is_tor
    FROM honeypot_events
    WHERE (
        -- Late-arriving events written after the last poll (before watermark timestamp)
        (created_at > %s AND created_at < %s)
        OR
        -- Cursor-forward: events at or after watermark, past last processed event_id
        ((created_at, event_id::text) > (%s, %s))
    )
    AND event_type NOT IN (
        'cowrie.session.closed', 'http.get.health', 'api.startup',
        'smb.server.started', 'smtp.session.connect', 'smtp.ehlo',
        'http.post.api.v1.telemetry', 'http.get.api.v1.telemetry',
        'http.post.telemetry'
    )
    AND (event_type != 'cowrie.session.connect' OR dst_port = 3306)
    ORDER BY created_at ASC, event_id::text ASC
    LIMIT 500
"""


# ---------------------------------------------------------------------------
# Cross-sensor correlation checks
# ---------------------------------------------------------------------------
_CRED_REPLAY_SEEN: set = set()
_KILLCHAIN_SEEN: set = set()
_KILLCHAIN_STAGE_SEEN: set = set()   # (session_id, stage) pairs already alerted


def _check_credential_replay(conn) -> None:
    """Alert when the same password appears on both the HTTP sensor and at least one other sensor."""
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT src_ip::text, password, array_agg(DISTINCT sensor) AS sensors
                FROM honeypot_events
                WHERE password IS NOT NULL
                  AND created_at > NOW() - INTERVAL '24 hours'
                GROUP BY src_ip, password
                HAVING COUNT(DISTINCT sensor) > 1
                  AND 'api' = ANY(array_agg(DISTINCT sensor))
            """)
            rows = cur.fetchall()
        for src_ip, password, sensors in rows:
            if src_ip is None:
                continue
            if isinstance(src_ip, str) and "/" in src_ip:
                src_ip = src_ip.split("/")[0]
            key = (src_ip, str(password)[:80])
            if key in _CRED_REPLAY_SEEN:
                continue
            _CRED_REPLAY_SEEN.add(key)
            if len(_CRED_REPLAY_SEEN) > 10000:
                _CRED_REPLAY_SEEN.clear()
            text = (
                f"🔗 <b>CREDENTIAL REPLAY DETECTED</b>\n\n"
                f"<b>IP:</b> <code>{_esc(src_ip)}</code>\n"
                f"<b>Password:</b> <code>{_esc(str(password)[:80])}</code>\n"
                f"<b>Sensors:</b> {_esc(', '.join(sensors))}\n"
                f"<b>Action:</b> Attacker replayed HTTP credential on another sensor — kill chain confirmed"
            )
            _send(text)
            log.info("cred_replay_alert src_ip=%s sensors=%s", src_ip, sensors)
    except Exception as exc:
        log.error("credential_replay_check error: %s", exc)


def _check_multisensor_kill_chain(conn) -> None:
    """Alert when one IP touches 3+ distinct sensors within 60 minutes."""
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT src_ip::text, array_agg(DISTINCT sensor) AS sensors,
                       COUNT(*) AS event_count
                FROM honeypot_events
                WHERE created_at > NOW() - INTERVAL '60 minutes'
                GROUP BY src_ip
                HAVING COUNT(DISTINCT sensor) >= 3
            """)
            rows = cur.fetchall()
        for src_ip, sensors, event_count in rows:
            if src_ip is None:
                continue
            if isinstance(src_ip, str) and "/" in src_ip:
                src_ip = src_ip.split("/")[0]
            if src_ip in _KILLCHAIN_SEEN:
                continue
            _KILLCHAIN_SEEN.add(src_ip)
            if len(_KILLCHAIN_SEEN) > 5000:
                _KILLCHAIN_SEEN.clear()
            text = (
                f"⛓️ <b>KILL CHAIN TRAVERSAL</b>\n\n"
                f"<b>IP:</b> <code>{_esc(src_ip)}</code>\n"
                f"<b>Sensors hit:</b> {_esc(', '.join(sensors))}\n"
                f"<b>Events (last 60m):</b> {event_count}\n"
                f"<b>Action:</b> Attacker hit {len(sensors)} sensors in under 60 minutes"
            )
            _send(text)
            log.info("killchain_alert src_ip=%s sensors=%s events=%d", src_ip, sensors, event_count)
    except Exception as exc:
        log.error("killchain_check error: %s", exc)


def _check_kill_chain_stages(conn) -> None:
    """Alert when any session reaches EXECUTION or EXFILTRATION stage."""
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT session_id, src_ip::text, kill_chain_stage,
                       sensors_hit, event_count, last_seen
                FROM attacker_sessions
                WHERE kill_chain_stage IN ('EXECUTION', 'EXFILTRATION')
                  AND last_seen > NOW() - INTERVAL '10 minutes'
            """)
            rows = cur.fetchall()
        for session_id, src_ip, stage, sensors_hit, event_count, last_seen in rows:
            if src_ip and "/" in src_ip:
                src_ip = src_ip.split("/")[0]
            key = (session_id, stage)
            if key in _KILLCHAIN_STAGE_SEEN:
                continue
            _KILLCHAIN_STAGE_SEEN.add(key)
            if len(_KILLCHAIN_STAGE_SEEN) > 5000:
                _KILLCHAIN_STAGE_SEEN.clear()
            emoji = "💀" if stage == "EXFILTRATION" else "⚡"
            sensors_str = ", ".join(sensors_hit) if sensors_hit else "unknown"
            ts_str = str(last_seen)[:19] if last_seen else "unknown"
            text = (
                f"{emoji} <b>KILL CHAIN: {stage}</b>\n\n"
                f"<b>IP:</b> <code>{_esc(src_ip or 'unknown')}</code>\n"
                f"<b>Stage reached:</b> {_esc(stage)}\n"
                f"<b>Sensors hit:</b> {_esc(sensors_str)}\n"
                f"<b>Events:</b> {event_count}\n"
                f"<b>Last seen:</b> {_esc(ts_str)} UTC"
            )
            _send(text)
            log.info("kill_chain_stage_alert src_ip=%s session_id=%s stage=%s",
                     src_ip, session_id, stage)
    except Exception as exc:
        log.error("kill_chain_stage_check error: %s", exc)


def _connect_pg() -> psycopg2.extensions.connection:
    log.info("connecting to PostgreSQL...")
    for attempt in range(1, 20):
        try:
            conn = psycopg2.connect(POSTGRES_DSN)
            conn.autocommit = True
            log.info("PostgreSQL connected")
            return conn
        except Exception as exc:
            log.warning("PG attempt %d: %s", attempt, exc)
            time.sleep(min(5 * attempt, 30))
    log.error("cannot connect to PostgreSQL — giving up")
    raise SystemExit(1)


def _poll(conn, since: datetime, last_event_id: str = "") -> list:
    # lookback catches late-arriving rows written after the previous poll whose
    # file timestamp predates the watermark.  The cursor (since, last_event_id)
    # guarantees forward progress even when thousands of events share the same
    # timestamp — a same-timestamp flood can no longer stall the watermark.
    lookback = since - timedelta(seconds=120)
    with conn.cursor() as cur:
        cur.execute(_QUERY, (lookback, since, since, last_event_id))
        rows = cur.fetchall()
    results = [dict(zip(_COLS, r)) for r in rows]
    if results:
        log.info("poll found %d event(s) since %s", len(results), since.isoformat())
        for r in results:
            log.info("  event_type=%-35s  src_ip=%-16s  dst_port=%s",
                     r.get("event_type"), r.get("src_ip"), r.get("dst_port"))
    return results


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
def main() -> None:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        log.error("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set — exiting")
        raise SystemExit(1)

    log.info("sentinel starting (poll_interval=%ds, cooldown=%ds)",
             POLL_INTERVAL, ALERT_COOLDOWN_SECS)

    conn = _connect_pg()

    # Send boot notification
    if _send("✅ <b>Neuro Sentinel online</b> — monitoring active."):
        log.info("boot notification sent")
    else:
        log.warning("boot notification failed — check token and chat ID")

    # On startup, look back 5 minutes to catch events that arrived while
    # sentinel was down (e.g. after a container restart during an active attack).
    since = datetime.now(timezone.utc) - timedelta(minutes=5)
    # Cursor tiebreaker — advances within same-timestamp batches so a flood of
    # events sharing one timestamp cannot permanently stall the watermark.
    last_event_id: str = ""
    # Dedup set — catches late-arriving rows that reappear in the lookback window.
    seen: set = set()

    log.info("polling for events since %s", since.isoformat())

    _last_heartbeat = time.monotonic()
    _loop_count = 0

    while True:
        try:
            rows = _poll(conn, since, last_event_id)

            new_since = since
            new_last_id = last_event_id
            for row in rows:
                eid = row["event_id"]
                if eid in seen:
                    continue
                seen.add(eid)

                # Advance composite cursor (timestamp + event_id tiebreaker)
                row_ts = row.get("created_at")
                if row_ts is not None:
                    if hasattr(row_ts, "tzinfo") and row_ts.tzinfo is None:
                        row_ts = row_ts.replace(tzinfo=timezone.utc)
                    if row_ts > new_since:
                        new_since = row_ts
                        new_last_id = eid
                    elif row_ts == new_since and eid > new_last_id:
                        new_last_id = eid

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

            # Trim dedup set — keep last 5000 IDs to bound memory
            if len(seen) > 5000:
                seen.clear()   # safe: worst case we re-alert one cooldown-window of events

            since = new_since
            last_event_id = new_last_id

            # Cross-sensor correlation checks every 5 polls (~50s)
            _loop_count += 1
            if _loop_count % 5 == 0:
                _check_credential_replay(conn)
                _check_multisensor_kill_chain(conn)
                _check_kill_chain_stages(conn)

        except Exception as exc:
            log.error("poll loop error: %s", exc)
            # Attempt reconnect
            try:
                conn.close()
            except Exception:
                pass
            conn = _connect_pg()

        # Heartbeat every 5 minutes — logs + Telegram so silence is obvious
        now_m = time.monotonic()
        if now_m - _last_heartbeat >= 300:
            ts_str = since.strftime("%H:%M:%S UTC")
            log.info("heartbeat — sentinel alive, watermark=%s", since.isoformat())
            _send(f"💓 <b>Sentinel heartbeat</b> — monitoring active\n<b>Watermark:</b> {ts_str}")
            _last_heartbeat = now_m

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
