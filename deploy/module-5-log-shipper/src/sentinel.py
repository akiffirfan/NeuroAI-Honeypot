#!/usr/bin/env python3
"""
sentinel.py — Standalone Telegram alerter for Neuro Honeypot Platform.

Polls PostgreSQL every POLL_INTERVAL seconds for new high-value events and
sends Telegram notifications.  Runs as its own container — completely
independent of log_shipper.py.

Requires:  POSTGRES_DSN  TELEGRAM_BOT_TOKEN  TELEGRAM_CHAT_ID
Optional:  POLL_INTERVAL (default 10)  ALERT_COOLDOWN_SECS (default 60)
"""

import html
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone

import psycopg2
import requests

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
TELEGRAM_BOT_TOKEN  = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID    = os.environ.get("TELEGRAM_CHAT_ID", "")
POSTGRES_DSN        = os.environ["POSTGRES_DSN"]
POLL_INTERVAL       = int(os.environ.get("POLL_INTERVAL", "10"))
ALERT_COOLDOWN_SECS = int(os.environ.get("ALERT_COOLDOWN_SECS", "60"))

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


def _suppressed(src_ip: str, category: str) -> bool:
    """Return True if this (IP, category) pair was alerted within the cooldown window."""
    key  = (src_ip, category)
    now  = time.monotonic()
    last = _cooldowns.get(key, 0.0)
    if now - last < ALERT_COOLDOWN_SECS:
        return True
    _cooldowns[key] = now
    return False


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
_NOISE_EVENTS = {"http.get.health", "cowrie.session.closed", "api.startup", "cowrie.session.connect"}

# Events that always alert — no cooldown suppression regardless of (IP, category)
_NO_COOLDOWN_EVENTS = {
    "http.lure.credential.success",
    "cowrie.session.file_download",
    "cowrie.login.success",
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
        "http.sqli.attempt":      "web.sqli",
        "http.post.sqli.attempt": "web.sqli",
        "http.lfi.attempt":       "web.lfi",
        "http.get.lfi.attempt":   "web.lfi",
        "http.rce.attempt":       "web.rce",
        "http.post.rce.attempt":  "web.rce",
        "http.cmdi.attempt":      "web.rce",
        "http.ssrf.attempt":      "web.ssrf",
        "http.xss.attempt":       "web.xss",
        "http.get.xss.attempt":   "web.xss",
    }
    if event_type in _SNARE_CATEGORIES:
        cooldown_category = _SNARE_CATEGORIES[event_type]
    elif event_type.startswith("http."):
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

    # Priority header — lure credential and file download get distinct headers
    if event_type == "http.lure.credential.success":
        header = "🚨🔑 <b>LURE CREDENTIAL USED</b>"
    elif event_type == "cowrie.session.file_download":
        header = "🚨📦 <b>MALWARE DOWNLOAD CAPTURED</b>"
    elif event_type == "cowrie.login.success":
        header = "🚨✅ <b>SSH LOGIN SUCCESS</b>"
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
    "geo_country", "geo_city", "geo_org",
]

_QUERY = """
    SELECT event_id::text, event_type, src_ip::text, dst_port,
           username, password, payload::text, sensor, created_at,
           geo_country, geo_city, geo_org
    FROM honeypot_events
    WHERE created_at > %s
    ORDER BY created_at ASC
    LIMIT 500
"""


# ---------------------------------------------------------------------------
# Cross-sensor correlation checks
# ---------------------------------------------------------------------------
_CRED_REPLAY_SEEN: set = set()
_KILLCHAIN_SEEN: set = set()


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


def _poll(conn, since: datetime) -> list:
    # Look back 120 s behind the watermark: log_shipper may insert rows with a
    # created_at from the event file that is older than the current watermark.
    # The seen-set in the main loop deduplicates rows already processed.
    lookback = since - timedelta(seconds=120)
    with conn.cursor() as cur:
        cur.execute(_QUERY, (lookback,))
        rows = cur.fetchall()
    results = [dict(zip(_COLS, r)) for r in rows]
    if results:
        log.info("poll found %d event(s) since %s", len(results), lookback.isoformat())
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
    # Dedup set — keeps event_ids seen this session to avoid double-alerts
    # on the rare case the same row appears in two consecutive polls.
    seen: set = set()

    log.info("polling for events since %s", since.isoformat())

    _last_heartbeat = time.monotonic()
    _loop_count = 0

    while True:
        try:
            rows = _poll(conn, since)

            new_since = since
            for row in rows:
                eid = row["event_id"]
                if eid in seen:
                    continue
                seen.add(eid)

                # Advance watermark
                row_ts = row.get("created_at")
                if row_ts is not None:
                    # psycopg2 returns aware or naive datetime — normalize
                    if hasattr(row_ts, "tzinfo") and row_ts.tzinfo is None:
                        row_ts = row_ts.replace(tzinfo=timezone.utc)
                    if row_ts > new_since:
                        new_since = row_ts

                should, reason, category = _should_alert(row)
                if should:
                    src_ip = row.get("src_ip") or ""
                    event_type = row.get("event_type", "")
                    # No-cooldown events always fire regardless of suppression window
                    if event_type in _NO_COOLDOWN_EVENTS or not _suppressed(src_ip, category):
                        send_alert(row, reason, category)

            # Trim dedup set — keep last 5000 IDs to bound memory
            if len(seen) > 5000:
                seen.clear()   # safe: worst case we re-alert one cooldown-window of events

            since = new_since

            # Cross-sensor correlation checks every 5 polls (~50s)
            _loop_count += 1
            if _loop_count % 5 == 0:
                _check_credential_replay(conn)
                _check_multisensor_kill_chain(conn)

        except Exception as exc:
            log.error("poll loop error: %s", exc)
            # Attempt reconnect
            try:
                conn.close()
            except Exception:
                pass
            conn = _connect_pg()

        # Heartbeat every 5 minutes so the log shows sentinel is alive
        now_m = time.monotonic()
        if now_m - _last_heartbeat >= 300:
            log.info("heartbeat — sentinel alive, watermark=%s", since.isoformat())
            _last_heartbeat = now_m

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
