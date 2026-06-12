#!/usr/bin/env python3
"""
log_shipper.py — Neuro Honeypot Platform, Module 5
===================================================
Tails log files from all four honeypot sensors, normalizes events into the
unified schema, writes to PostgreSQL (TimescaleDB), publishes to Redis Streams,
and batches events to HoneyDash via POST /api/ingest/batch.

Sensor inputs:
  - Cowrie JSON log    (/var/log/cowrie/cowrie.json)
  - OpenCanary JSON log (/var/log/opencanary/opencanary.json)
  - MariaDB general log (/var/log/mariadb/general.log)

Architecture:
  - One watchdog FileSystemEventHandler per log file (inotify-based on Linux)
  - A single background thread drains the event queue and writes to Postgres + Redis
  - A separate background thread flushes the HoneyDash batch buffer every FLUSH_INTERVAL s
  - A minimal HTTP server on :9100 handles /healthz for Docker healthcheck
  - A bounded asyncio.Queue (maxsize=10000) prevents OOM during Postgres outages;
    overflow events are spooled to disk (SPOOL_DIR) and replayed on startup.

Resilience:
  - If one log file is missing/unavailable, the other tailers continue unaffected
  - Postgres write failures cause events to enter the overflow disk spool
  - Redis publish failures are logged and skipped (Redis is best-effort real-time)
  - HoneyDash push failures are retried with exponential backoff; events stay in Postgres
"""

import json
import logging
import os
import queue
import re
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Optional

import geoip2.database
import psycopg2
import psycopg2.extras
import redis as redis_lib
import requests
import structlog
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# ---------------------------------------------------------------------------
# Structured logging setup
# ---------------------------------------------------------------------------
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
)
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
log = structlog.get_logger("log_shipper")

# ---------------------------------------------------------------------------
# Environment variable loading
# ---------------------------------------------------------------------------
POSTGRES_DSN    = os.environ["POSTGRES_DSN"]
REDIS_URL       = os.environ["REDIS_URL"]
GEOIP_DB        = os.environ.get("GEOIP_DB", "/geoip/GeoLite2-City.mmdb")
GEOIP_ASN_DB    = os.environ.get("GEOIP_ASN_DB", "/geoip/GeoLite2-ASN.mmdb")
HONEYDASH_URL   = os.environ.get("HONEYDASH_URL", "")
SENSOR_API_KEY  = os.environ.get("SENSOR_API_KEY", "")
SENSOR_NAME_COWRIE     = os.environ.get("SENSOR_NAME_COWRIE", "neuro-cowrie-01")
SENSOR_NAME_OPENCANARY = os.environ.get("SENSOR_NAME_OPENCANARY", "neuro-opencanary-01")
SENSOR_NAME_MARIADB    = os.environ.get("SENSOR_NAME_MARIADB", "neuro-mariadb-01")
SENSOR_NAME_API        = os.environ.get("SENSOR_NAME_API", "neuro-api-01")
BATCH_SIZE      = int(os.environ.get("BATCH_SIZE", "20"))
FLUSH_INTERVAL  = int(os.environ.get("FLUSH_INTERVAL", "1"))
COWRIE_LOG      = os.environ.get("COWRIE_LOG", "/var/log/cowrie/cowrie.json")
OPENCANARY_LOG  = os.environ.get("OPENCANARY_LOG", "/var/log/opencanary/opencanary.json")
MARIADB_LOG     = os.environ.get("MARIADB_LOG", "/var/log/mariadb/general.log")
SMB_LOG         = os.environ.get("SMB_LOG", "/var/log/smb/smb_events.json")
SPOOL_DIR       = Path(os.environ.get("SPOOL_DIR", "/archive/spool"))

# ---------------------------------------------------------------------------
# Telegram Bot API alert configuration (real-time operator alerting)
# All values are optional — if either var is empty, alerting is disabled and
# no errors are raised.
# ---------------------------------------------------------------------------
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.environ.get("TELEGRAM_CHAT_ID", "")
# Minimum seconds between alerts for the same source IP to prevent flood.
# Default: 60 s (one alert per IP per minute regardless of how many probes arrive)
ALERT_COOLDOWN_SECS = int(os.environ.get("ALERT_COOLDOWN_SECS", "60"))

# ---------------------------------------------------------------------------
# Internal event queue (bounded — prevents OOM during Postgres outage)
# Section 14.3: overflow goes to disk spool, not /dev/null
# ---------------------------------------------------------------------------
EVENT_QUEUE: queue.Queue = queue.Queue(maxsize=10000)

# HoneyDash batch buffer and lock
_honeydash_batch: list = []
_honeydash_lock  = threading.Lock()

# Watermark for HTTP event poller — tracks last polled created_at from honeypot_events
_http_poll_watermark: Optional[datetime] = None
_http_poll_lock = threading.Lock()

# ---------------------------------------------------------------------------
# GeoIP reader (module-level — mmap'd once at startup, reused per lookup)
# ---------------------------------------------------------------------------
_city_reader: Optional[geoip2.database.Reader] = None
_asn_reader:  Optional[geoip2.database.Reader] = None

# ---------------------------------------------------------------------------
# TOR exit node list — refreshed daily
# ---------------------------------------------------------------------------
_TOR_EXIT_IPS: set = set()
_TOR_LOCK = threading.Lock()
_TOR_LIST_URL = "https://check.torproject.org/torbulkexitlist"


def _refresh_tor_list() -> None:
    """Download the TOR bulk exit list and update the in-memory set."""
    global _TOR_EXIT_IPS
    try:
        resp = requests.get(_TOR_LIST_URL, timeout=20)
        if resp.status_code == 200:
            ips = {line.strip() for line in resp.text.splitlines()
                   if line.strip() and not line.startswith("#")}
            with _TOR_LOCK:
                _TOR_EXIT_IPS = ips
            log.info("tor_list_refreshed", count=len(ips))
        else:
            log.warning("tor_list_fetch_failed", status=resp.status_code)
    except Exception as exc:
        log.warning("tor_list_fetch_error", error=str(exc))


def _tor_refresh_thread() -> None:
    """Refresh TOR list at startup then every 6 hours."""
    _refresh_tor_list()
    while True:
        time.sleep(6 * 3600)
        _refresh_tor_list()


def _is_tor(ip: str) -> bool:
    clean = ip.split("/")[0] if ip and "/" in ip else (ip or "")
    with _TOR_LOCK:
        return clean in _TOR_EXIT_IPS

def _init_geoip() -> None:
    global _city_reader, _asn_reader
    for db_path, name in [(GEOIP_DB, "City"), (GEOIP_ASN_DB, "ASN")]:
        if not Path(db_path).exists():
            log.warning("geoip_db_missing", path=db_path,
                        hint="See Module 5 deploy instructions to populate the geoip-data volume")
    try:
        _city_reader = geoip2.database.Reader(GEOIP_DB)
        log.info("geoip_city_loaded", path=GEOIP_DB)
    except Exception as exc:
        log.warning("geoip_city_unavailable", error=str(exc))
    try:
        _asn_reader = geoip2.database.Reader(GEOIP_ASN_DB)
        log.info("geoip_asn_loaded", path=GEOIP_ASN_DB)
    except Exception as exc:
        log.warning("geoip_asn_unavailable", error=str(exc))


def enrich_geoip(ip: str) -> dict:
    """Return GeoIP enrichment fields for an IP address.
    Returns an empty dict if IP is private, invalid, or DBs are unavailable."""
    result = {
        "geo_country": None,
        "geo_country_code": None,
        "geo_city": None,
        "geo_lat": None,
        "geo_lon": None,
        "geo_asn": None,
        "geo_org": None,
    }
    if not ip or ip.startswith(("10.", "172.", "192.168.", "127.", "::1")):
        return result
    try:
        if _city_reader:
            city = _city_reader.city(ip)
            result["geo_country"]      = city.country.name
            result["geo_country_code"] = city.country.iso_code
            result["geo_city"]         = city.city.name
            if city.location.latitude is not None:
                result["geo_lat"] = float(city.location.latitude)
                result["geo_lon"] = float(city.location.longitude)
    except Exception:
        pass  # Unknown IP or private range — silently skip
    try:
        if _asn_reader:
            asn = _asn_reader.asn(ip)
            result["geo_asn"] = asn.autonomous_system_number
            result["geo_org"] = asn.autonomous_system_organization
    except Exception:
        pass
    return result


# ---------------------------------------------------------------------------
# Telegram Bot API real-time alerter
# ---------------------------------------------------------------------------
# Sends a formatted HTML message to a Telegram chat via the Bot API whenever
# a high-value event is detected.  Sends run in _telegram_worker (a dedicated
# daemon thread) to avoid blocking the main consumer thread on Telegram I/O.
#
# ALERT TAXONOMY
# -----------------------------------------------------------------------
# ALERT events   — sent to Telegram immediately (high operator value):
#   cowrie.login.success          — attacker authenticated to Cowrie SSH
#   cowrie.session.file_download  — attacker downloaded a payload
#   cowrie.command.input          — attacker typed a command (SSH or API)
#     -> only if input matches a HIGH_VALUE_PATTERN (see below)
#   opencanary connect on 3306    — MariaDB lure connection attempt
#   honeypot-api lure path hit    — /.env, /api/v1/internal/config, etc.
#
# SILENT events  — written to Postgres/Redis but no Telegram notification:
#   cowrie.session.connect        — port scanner noise; too high volume
#   cowrie.login.failed           — brute-force noise; cooldown handles repeat IPs
#   opencanary FTP/Telnet/SMTP/Redis connect — low-value scanner hits
#   cowrie.session.closed         — lifecycle bookkeeping only
# -----------------------------------------------------------------------

# eventid values that always trigger an alert
_ALERT_EVENTIDS = {
    "cowrie.login.success",
    "cowrie.session.file_download",
}

# For cowrie.command.input events, only alert if the command matches one of
# these patterns.  This filters out trivial ls/pwd noise while catching the
# interesting reconnaissance and exfiltration commands.
_HIGH_VALUE_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"wget|curl",                            # downloader
        r"chmod\s+[0-9]*x",                     # make executable
        r"/etc/passwd|/etc/shadow",              # credential files
        r"id\s*$|whoami",                        # identity check
        r"uname\s+-a",                           # OS fingerprinting
        r"cat\s+.*\.env",                        # .env exfiltration
        r"python.*-c|perl.*-e|bash\s+-i",        # reverse shell
        r"nc\s+|ncat\s+|netcat",                 # netcat
        r"crontab|/etc/cron",                    # persistence
        r"ssh-keygen|authorized_keys",           # backdoor SSH key
        r"SELECT.*FROM|SHOW\s+TABLES|DROP\s+TABLE",  # SQL recon
    ]
]

# For OpenCanary/MariaDB events, alert on these destination ports
_ALERT_DST_PORTS = {3306}  # MariaDB lure — high-value, real DB

# Lure paths on the honeypot-api that trigger alerts
_ALERT_API_PATHS = {
    "/.env",
    "/api/v1/internal/config",
    "/api/v1/internal/models",
    "/api/v1/internal/keys",
    "/api/v1/admin",
    "/admin",
    "/.git/config",
    "/wp-admin",
    "/wp-login.php",
}

# Per-IP cooldown: track the last alert time for each src_ip
_alert_cooldown: dict = {}   # {src_ip: last_alert_epoch_float}
_alert_cooldown_lock = threading.Lock()


def _should_alert(event: dict) -> tuple[bool, str]:
    """
    Decide whether an event warrants a Telegram alert.
    Returns (should_alert: bool, reason: str).

    This function encodes the alert taxonomy described above.
    """
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False, ""

    eventid      = event.get("eventid", "")
    sensor_type  = event.get("_sensor_type", "")
    dst_port     = event.get("dst_port")
    cmd_input    = event.get("input") or ""
    protocol     = event.get("_protocol", "")

    # --- Cowrie high-value eventids ---
    if eventid in _ALERT_EVENTIDS:
        if eventid == "cowrie.login.success":
            return True, "SSH login SUCCESS — attacker authenticated"
        if eventid == "cowrie.session.file_download":
            url = event.get("url") or event.get("outfile") or "(unknown URL)"
            return True, f"Payload download: {url}"

    # --- MariaDB lure: connection and query events (checked BEFORE generic command.input) ---
    # dst_port==3306 originates from MariaDBTailer which sets _protocol="mysql".
    # All MariaDB queries warrant an alert — query volume on a honeypot is low
    # (each query is a deliberate attacker action), so noise is not a concern.
    # Per-IP cooldown below still suppresses flood from the same attacker.
    if dst_port == 3306 or event.get("_protocol") == "mysql":
        if eventid == "cowrie.command.input" and cmd_input:
            sql_preview = cmd_input[:120]
            return True, f"MariaDB query: {sql_preview}"
        if eventid in ("cowrie.session.connect", "cowrie.login.failed",
                       "cowrie.session.closed"):
            username = event.get("username") or "(no user)"
            return True, f"MariaDB connect — user: {username}"

    # --- Cowrie command input: filter to high-value patterns ---
    if eventid == "cowrie.command.input" and cmd_input:
        for pat in _HIGH_VALUE_PATTERNS:
            if pat.search(cmd_input):
                return True, f"High-value command: {cmd_input[:120]}"

    # --- Honeypot-API lure path hit ---
    # The API honeypot logs HTTP probes as cowrie.command.input with
    # input set to "HTTP METHOD /path" (see OpenCanaryTailer._process)
    if eventid == "cowrie.command.input" and cmd_input.startswith("HTTP "):
        parts = cmd_input.split(" ", 2)
        path  = parts[2] if len(parts) >= 3 else ""
        # Normalise — strip query string
        path_clean = path.split("?")[0]
        if path_clean in _ALERT_API_PATHS:
            return True, f"Lure path accessed: {cmd_input[:120]}"

    return False, ""


def _apply_cooldown(src_ip: str) -> bool:
    """
    Returns True if we should suppress this alert due to cooldown.
    Updates the last-alert timestamp if we are NOT suppressing.
    """
    now = time.monotonic()
    with _alert_cooldown_lock:
        last = _alert_cooldown.get(src_ip, 0.0)
        if now - last < ALERT_COOLDOWN_SECS:
            return True  # suppress
        _alert_cooldown[src_ip] = now
        return False     # allow


def _sanitize_field(value: str, max_len: int) -> str:
    """Strip newlines from an attacker-controlled string and truncate to max_len chars.
    Prevents newline injection that could spoof extra alert sections, and avoids
    oversized credential fields hitting Telegram's message length limit."""
    value = value.replace("\r", "").replace("\n", " ")
    return value[:max_len]


def _redact_token(s: str) -> str:
    """Replace bot token in error strings before logging — token appears in request URLs."""
    if TELEGRAM_BOT_TOKEN:
        return s.replace(TELEGRAM_BOT_TOKEN, "***REDACTED***")
    return s


def _build_telegram_message(event: dict, reason: str) -> str:
    """
    Build a Telegram HTML-formatted alert message (~300 chars target).

    All attacker-controlled strings are sanitized and HTML-escaped before
    inclusion.  The message stays compact — Telegram renders inline HTML tags
    Telegram renders inline HTML tags (<b>, <code>, <i>) natively.
    """
    reason    = _sanitize_field(reason or "", 200)
    src_ip    = _sanitize_field(event.get("src_ip") or "unknown", 45)
    timestamp = event.get("timestamp") or _now_iso()
    country   = _sanitize_field(event.get("geo_country") or "", 64)
    sensor    = _sanitize_field(
        event.get("sensor") or event.get("_sensor_type") or "unknown", 64
    )

    # Sanitize attacker-controlled fields
    city     = _sanitize_field(event.get("geo_city") or "", 64)
    asn      = event.get("geo_asn")
    geo_org  = _sanitize_field(event.get("geo_org") or "", 64)
    username = _sanitize_field(event.get("username") or "", 64)
    password = _sanitize_field(event.get("password") or "", 64)

    # Compose location string
    location_parts = [p for p in [city, country] if p]
    location = ", ".join(location_parts) if location_parts else "unknown"
    if asn and geo_org:
        location += f" (AS{asn} {geo_org})"
    elif geo_org:
        location += f" ({geo_org})"

    # Trim timestamp to seconds for readability
    ts_display = timestamp[:19].replace("T", " ") + " UTC"

    # HTML-escape all attacker-controlled values to prevent tag injection
    def _esc(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    lines = [
        "&#x1F6A8; <b>Honeypot Alert</b>",
        "",
        f"<b>Reason:</b> {_esc(reason)}",
        f"<b>Source IP:</b> <code>{_esc(src_ip)}</code>",
        f"<b>Sensor:</b> {_esc(sensor)}",
        f"<b>Location:</b> {_esc(location)}",
    ]
    if username:
        cred_line = f"<b>Credentials:</b> <code>{_esc(username)}</code>"
        if password:
            cred_line += f" / <code>{_esc(password)}</code>"
        lines.append(cred_line)
    lines.append(f"<b>Time:</b> {ts_display}")

    return "\n".join(lines)


def send_telegram_alert(event: dict, reason: str) -> None:
    """
    POST a HTML-formatted message to the Telegram Bot API.
    Failures are logged and silently swallowed — never raise to the caller.
    The bot token is a secret; never log it.
    """
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return

    src_ip = event.get("src_ip") or ""
    if _apply_cooldown(src_ip):
        log.debug("alert_cooldown_suppressed", src_ip=src_ip)
        return

    text = _build_telegram_message(event, reason)
    url  = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id":    TELEGRAM_CHAT_ID,
        "text":       text,
        "parse_mode": "HTML",
    }
    try:
        resp = requests.post(url, json=payload, timeout=8)
        if resp.status_code == 200:
            log.info("telegram_alert_sent", src_ip=src_ip, reason=reason[:80])
        else:
            log.warning("telegram_alert_failed",
                        status=resp.status_code, body=_redact_token(resp.text[:200]))
    except Exception as exc:
        log.warning("telegram_alert_error", error=_redact_token(str(exc)))


# ---------------------------------------------------------------------------
# Telegram alert worker thread
# ---------------------------------------------------------------------------
# Telegram sends are moved off the consumer thread into a dedicated worker so
# that a Telegram outage (up to 8 s per blocked send_telegram_alert call) does
# not stall Postgres writes or Redis publishes.
#
# _telegram_queue is bounded at 200 entries.  If the worker falls behind (e.g.
# sustained Telegram outage) new alerts are dropped with a debug log rather
# than blocking the consumer.  At 60 s cooldown per IP the queue will not fill
# under any realistic attacker volume.
# ---------------------------------------------------------------------------
_telegram_queue: queue.Queue = queue.Queue(maxsize=200)


def _telegram_worker() -> None:
    """Dedicated thread that drains _telegram_queue and calls send_telegram_alert."""
    while True:
        try:
            item = _telegram_queue.get(timeout=5)
            if item is None:
                break
            event, reason = item
            send_telegram_alert(event, reason)
        except queue.Empty:
            continue
        except Exception as exc:
            log.warning("telegram_worker_error", error=str(exc))


# ---------------------------------------------------------------------------
# Disk spool helpers (Section 14.3 — bounded queue overflow)
# ---------------------------------------------------------------------------
def _spool_event(event: dict) -> None:
    """Write a single event to a timestamped spool file when the queue is full."""
    SPOOL_DIR.mkdir(parents=True, exist_ok=True)
    spool_file = SPOOL_DIR / f"overflow_{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}_{uuid.uuid4().hex[:8]}.jsonl"
    try:
        with open(spool_file, "a") as fh:
            fh.write(json.dumps(event) + "\n")
        log.warning("event_spooled_to_disk", file=str(spool_file))
    except Exception as exc:
        log.error("spool_write_failed", error=str(exc))


def _replay_spool() -> None:
    """On startup, replay any spool files into the event queue before tailing begins."""
    if not SPOOL_DIR.exists():
        return
    spool_files = sorted(SPOOL_DIR.glob("*.jsonl"))
    if not spool_files:
        return
    log.info("spool_replay_start", file_count=len(spool_files))
    replayed = 0
    for spool_file in spool_files:
        try:
            with open(spool_file) as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            evt = json.loads(line)
                            EVENT_QUEUE.put_nowait(evt)
                            replayed += 1
                        except (json.JSONDecodeError, queue.Full):
                            pass
            spool_file.unlink()  # delete after successful replay
        except Exception as exc:
            log.warning("spool_replay_file_error", file=str(spool_file), error=str(exc))
    log.info("spool_replay_complete", replayed=replayed)


def _enqueue(event: dict) -> None:
    """Enqueue an event; spool to disk if the queue is full."""
    try:
        EVENT_QUEUE.put_nowait(event)
    except queue.Full:
        _spool_event(event)


# ---------------------------------------------------------------------------
# Cowrie JSON log tailer
# ---------------------------------------------------------------------------
# Cowrie writes newline-delimited JSON to cowrie.json.
# Each line is a complete JSON object. The file may be rotated (cowrie.json.1,
# cowrie.json.2, ...). watchdog's inotify picks up rotation events.
# ---------------------------------------------------------------------------

class CowrieTailer:
    """Tails cowrie.json, parses each JSON line, enqueues normalized events."""

    # Supported Cowrie event IDs — others are not sent to HoneyDash
    SUPPORTED_EVENTS = {
        "cowrie.session.connect",
        "cowrie.login.failed",
        "cowrie.login.success",
        "cowrie.command.input",
        "cowrie.session.file_download",
        "cowrie.session.closed",
    }

    def __init__(self, log_path: str):
        self.log_path = log_path
        self._fh = None
        self._inode = None
        self._partial = ""   # buffer for incomplete lines read mid-write

    def _open(self) -> bool:
        """Open the log file, return True if successful."""
        try:
            self._fh = open(self.log_path, "r", encoding="utf-8", errors="replace")
            stat = os.stat(self.log_path)
            self._inode = stat.st_ino
            # Seek to end on initial open (do not re-process historical events)
            self._fh.seek(0, 2)
            self._partial = ""
            log.info("cowrie_tailer_opened", path=self.log_path)
            return True
        except FileNotFoundError:
            log.warning("cowrie_log_not_found", path=self.log_path,
                        hint="Cowrie container may not have written a log yet; will retry")
            return False
        except Exception as exc:
            log.error("cowrie_open_error", path=self.log_path, error=str(exc))
            return False

    def _check_rotation(self) -> None:
        """Detect log rotation (inode change) and reopen."""
        if self._fh is None:
            return
        try:
            stat = os.stat(self.log_path)
            if stat.st_ino != self._inode:
                log.info("cowrie_log_rotated", path=self.log_path)
                self._fh.close()
                self._fh = None
                self._open()
        except FileNotFoundError:
            self._fh.close()
            self._fh = None

    def read_new_lines(self) -> None:
        """Called by watchdog on file modification — read all new complete lines."""
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
                # Cowrie hasn't finished writing this line yet — buffer and wait
                # for the next on_modified event which will deliver the rest.
                self._partial += chunk
                break
            line = (self._partial + chunk).strip()
            self._partial = ""
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                log.warning("cowrie_json_parse_error", line=line[:200], error=str(exc))
                continue
            if not isinstance(raw, dict):
                # Valid JSON but not an object (e.g. a bare string fragment) — skip
                continue
            self._process(raw)

    def _process(self, raw: dict) -> None:
        """Normalize a Cowrie JSON event and enqueue it."""
        eventid = raw.get("eventid", "")
        if eventid not in self.SUPPORTED_EVENTS:
            return  # silently drop unsupported events (HoneyDash ignores them anyway)

        src_ip   = raw.get("src_ip", "")
        src_port = raw.get("src_port")
        geo      = enrich_geoip(src_ip)

        # Build the HoneyDash-compatible event.
        # Cowrie's native fields are passed through as-is; we add geo and sensor_name.
        event = {
            # HoneyDash-native fields (must exactly match Cowrie's field names)
            "eventid":    eventid,
            "src_ip":     src_ip,
            "src_port":   int(src_port) if src_port is not None else None,
            "session":    raw.get("session", ""),
            "timestamp":  raw.get("timestamp", _now_iso()),
            "sensor":     SENSOR_NAME_COWRIE,
            # Event-type-specific passthrough fields
            "dst_ip":     raw.get("dst_ip"),
            "dst_port":   raw.get("dst_port"),
            "username":   raw.get("username"),
            "password":   raw.get("password"),
            "input":      raw.get("input"),
            "url":        raw.get("url"),
            "outfile":    raw.get("outfile"),
            "duration":   raw.get("duration"),
            # Internal metadata (written to Postgres but not sent to HoneyDash)
            "_sensor_type": "ssh",
            "_raw":         raw,
            **geo,
        }
        _enqueue(event)


class CowrieFileEventHandler(FileSystemEventHandler):
    def __init__(self, tailer: CowrieTailer):
        self._tailer = tailer

    def on_modified(self, event):
        if not event.is_directory and event.src_path == self._tailer.log_path:
            self._tailer.read_new_lines()

    def on_moved(self, event):
        # watchdog reports rotation as a move event (cowrie.json → cowrie.json.1)
        if not event.is_directory and event.dest_path == self._tailer.log_path:
            self._tailer.read_new_lines()
        elif not event.is_directory and event.src_path == self._tailer.log_path:
            # Source was rotated away — reopen will detect the new file
            self._tailer.read_new_lines()


# ---------------------------------------------------------------------------
# OpenCanary JSON log tailer
# ---------------------------------------------------------------------------
# OpenCanary writes one JSON object per line to opencanary.log.
# Field mapping: src_host → src_ip, dst_host → dst_ip, utc_time → timestamp,
#                logdata → protocol-specific fields.
# ---------------------------------------------------------------------------

# OpenCanary logtype → protocol name mapping (from OpenCanary source)
OPENCANARY_PROTOCOL_MAP = {
    1000: "http",
    1001: "http",
    2000: "ftp",
    2001: "ftp",
    3000: "httpproxy",
    4000: "smtp",
    4001: "smtp",
    5000: "socks5",
    6000: "vnc",
    6001: "telnet",
    7000: "ssh",
    7001: "ssh",
    8000: "smb",
    8001: "smb",
    9000: "mysql",
    9001: "mysql",
    10000: "mssql",
    11000: "tftp",
    13000: "redis",
    13001: "redis",
    14000: "snmp",
    17000: "redis",
    17001: "redis",
}

# Fallback dst_port when OpenCanary omits it from the JSON event.
# OpenCanary sometimes logs only the container IP (no port) in dst_host.
OPENCANARY_LOGTYPE_PORT = {
    2000: 21,  2001: 21,    # FTP
    4000: 25,  4001: 25,    # SMTP
    6001: 23,               # Telnet
    13000: 6379, 13001: 6379,  # Redis
    17000: 6379, 17001: 6379,  # Redis commands
}


class OpenCanaryTailer:
    """Tails opencanary.log, parses each JSON line, enqueues normalized events."""

    def __init__(self, log_path: str):
        self.log_path = log_path
        self._fh = None
        self._inode = None
        self._partial = ""

    def _open(self) -> bool:
        try:
            self._fh = open(self.log_path, "r", encoding="utf-8", errors="replace")
            stat = os.stat(self.log_path)
            self._inode = stat.st_ino
            self._fh.seek(0, 2)  # tail from end on first open
            self._partial = ""
            log.info("opencanary_tailer_opened", path=self.log_path)
            return True
        except FileNotFoundError:
            log.warning("opencanary_log_not_found", path=self.log_path)
            return False
        except Exception as exc:
            log.error("opencanary_open_error", path=self.log_path, error=str(exc))
            return False

    def _check_rotation(self) -> None:
        if self._fh is None:
            return
        try:
            stat = os.stat(self.log_path)
            if stat.st_ino != self._inode:
                log.info("opencanary_log_rotated", path=self.log_path)
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
                log.warning("opencanary_json_parse_error", line=line[:200], error=str(exc))
                continue
            if not isinstance(raw, dict):
                continue
            self._process(raw)

    def _process(self, raw: dict) -> None:
        """Translate an OpenCanary event into a HoneyDash-compatible event."""
        logtype  = raw.get("logtype", 0)
        protocol = OPENCANARY_PROTOCOL_MAP.get(logtype, "unknown")
        logdata  = raw.get("logdata", {}) or {}

        src_host = raw.get("src_host", "")
        src_ip   = src_host.split(":")[0] if src_host else ""
        src_port_raw = raw.get("src_port") or (src_host.split(":")[1] if ":" in src_host else None)
        try:
            src_port = int(src_port_raw) if src_port_raw is not None else None
        except (ValueError, TypeError):
            src_port = None

        dst_host = raw.get("dst_host", "")
        dst_port_raw = raw.get("dst_port") or (dst_host.split(":")[1] if ":" in dst_host else None)
        try:
            dst_port = int(dst_port_raw) if dst_port_raw is not None else None
        except (ValueError, TypeError):
            dst_port = None
        # Fallback: infer dst_port from logtype when OpenCanary omits it
        if dst_port is None:
            dst_port = OPENCANARY_LOGTYPE_PORT.get(logtype)

        timestamp = raw.get("utc_time", _now_iso())

        geo = enrich_geoip(src_ip)

        # HoneyDash has no native OpenCanary parser.
        # We translate to Cowrie-compatible events per the memory record
        # (project_honeydash_integration.md): connect → cowrie.session.connect,
        # login → cowrie.login.failed, HTTP probe → cowrie.command.input.
        session_id = sha256(
            f"{src_ip}{dst_port}{timestamp}".encode()
        ).hexdigest()[:16]

        username = (
            logdata.get("USERNAME") or
            logdata.get("username") or
            logdata.get("USER") or
            raw.get("username", "")
        )
        password = (
            logdata.get("PASSWORD") or
            logdata.get("password") or
            raw.get("password", "")
        )

        # Determine the HoneyDash eventid based on logtype
        if logtype in (7000, 7001):
            # SSH connect / login
            eventid = "cowrie.login.failed" if username else "cowrie.session.connect"
        elif logtype % 1000 == 0:
            # "connect" logtype (e.g. 2000=FTP connect). OpenCanary sometimes
            # includes credentials in the connect event (FTP logtype 2000 with
            # USERNAME/PASSWORD) — treat as login.failed when credentials present.
            eventid = "cowrie.login.failed" if username else "cowrie.session.connect"
        elif logtype in (1000, 1001):
            # HTTP probe — encode as command.input
            method = logdata.get("METHOD", "GET")
            path   = logdata.get("PATH", "/")
            eventid = "cowrie.command.input"
            raw["_http_input"] = f"HTTP {method} {path}"
        elif logtype in (13000, 13001, 17000, 17001):
            # Redis events — OpenCanary logs commands in logdata.CMD / ARGS
            cmd  = logdata.get("CMD", "").upper()
            args = logdata.get("ARGS", "")
            if cmd == "AUTH":
                eventid = "cowrie.login.failed"
                password = args  # Redis AUTH <password>
            elif cmd:
                eventid = "cowrie.command.input"
                raw["_http_input"] = f"REDIS {cmd} {args}".strip()
            else:
                eventid = "cowrie.session.connect"
        else:
            # Login/auth attempt on any other protocol
            eventid = "cowrie.login.failed"

        event = {
            # Cowrie-compatible fields for HoneyDash
            "eventid":   eventid,
            "src_ip":    src_ip,
            "src_port":  src_port,
            "session":   session_id,
            "timestamp": _normalize_timestamp(str(timestamp)),
            "sensor":    SENSOR_NAME_OPENCANARY,
            "dst_port":  dst_port,
            "username":  username or None,
            "password":  password or None,
            "input":     raw.get("_http_input"),
            # Internal metadata
            "_sensor_type": "opencanary",
            "_protocol":    protocol,
            "_logtype":     logtype,
            "_logdata":     logdata,
            "_raw":         raw,
            **geo,
        }
        _enqueue(event)


class OpenCanaryFileEventHandler(FileSystemEventHandler):
    def __init__(self, tailer: OpenCanaryTailer):
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


# ---------------------------------------------------------------------------
# MariaDB general query log tailer
# ---------------------------------------------------------------------------
# Format (from Section 3.4 of plans.md):
#   TIMESTAMP  THREAD_ID  COMMAND  ARGUMENT
#   2026-05-17T09:14:22.418Z 14 Connect    root@45.142.212.10 on neuro_prod using TCP/IP
#   2026-05-17T09:14:22.421Z 14 Query      SELECT version()
#   2026-05-17T09:14:22.519Z 14 Quit
#
# Parser extracts src_ip from the Connect line (after the @).
# Groups same-THREAD_ID lines into one session.
# Emits sensor_type: "opencanary" events with protocol: "mysql"
# per Section 3.4 and the memory record.
# ---------------------------------------------------------------------------

# Regex for general log lines — handles three formats:
#   ISO 8601:    "2026-05-17T09:14:22.418Z 14 Connect  root@1.2.3.4 on db using TCP/IP"
#   Old format:  "260523  2:09:25   2428 Connect  root@1.2.3.4 on db using TCP/IP"
#   Continuation:"                   2428 Query    SELECT version()"  (no timestamp)
_MARIADB_LINE_RE = re.compile(
    r'^(?:'
    r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+'  # ISO 8601 (group 1)
    r'|(\d{6})\s+(\d+:\d+:\d+)\s+'                             # YYMMDD H:MM:SS (groups 2, 3)
    r'|\s+'                                                      # continuation — no timestamp
    r')'
    r'(\d+)\s+'   # thread_id (group 4)
    r'(\w+)\s*'   # command (group 5)
    r'(.*)?$',    # argument (group 6)
    re.DOTALL
)
# Regex to extract IP from Connect argument: "root@1.2.3.4 on db using TCP/IP"
_MARIADB_CONNECT_RE = re.compile(r'(\S+)@([\d\.a-fA-F:]+)\s')


class MariaDBTailer:
    """Tails MariaDB general.log, groups Connect/Query lines by THREAD_ID, enqueues events."""

    def __init__(self, log_path: str):
        self.log_path = log_path
        self._fh = None
        self._inode = None
        # In-memory state: thread_id → {"src_ip", "username", "timestamp", "queries": []}
        self._sessions: dict = {}

    def _open(self) -> bool:
        try:
            self._fh = open(self.log_path, "r", encoding="utf-8", errors="replace")
            stat = os.stat(self.log_path)
            self._inode = stat.st_ino
            self._fh.seek(0, 2)
            log.info("mariadb_tailer_opened", path=self.log_path)
            return True
        except FileNotFoundError:
            log.warning("mariadb_log_not_found", path=self.log_path,
                        hint="MariaDB container may not have received a connection yet; will retry")
            return False
        except Exception as exc:
            log.error("mariadb_open_error", path=self.log_path, error=str(exc))
            return False

    def _check_rotation(self) -> None:
        if self._fh is None:
            return
        try:
            stat = os.stat(self.log_path)
            if stat.st_ino != self._inode:
                log.info("mariadb_log_rotated", path=self.log_path)
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
            line = self._fh.readline()
            if not line:
                break
            line = line.rstrip("\n")
            if not line:
                continue
            self._process_line(line)

    def _process_line(self, line: str) -> None:
        m = _MARIADB_LINE_RE.match(line)
        if not m:
            return  # header lines, blank lines, MariaDB startup banner

        ts_iso    = m.group(1)
        ts_date   = m.group(2)
        ts_time   = m.group(3)
        thread_id = m.group(4)
        command   = m.group(5)
        argument  = (m.group(6) or "").strip()

        if ts_iso:
            timestamp_str = ts_iso
        elif ts_date and ts_time:
            # Convert YYMMDD H:MM:SS → ISO 8601
            h, mi, s = ts_time.split(":", 2)
            timestamp_str = (
                f"20{ts_date[:2]}-{ts_date[2:4]}-{ts_date[4:6]}"
                f"T{int(h):02d}:{mi}:{s}Z"
            )
        else:
            timestamp_str = None  # continuation line — session provides timestamp

        if command == "Connect":
            cm = _MARIADB_CONNECT_RE.search(argument)
            if not cm:
                # localhost socket connection (healthcheck) or unparseable — no src_ip, skip
                return
            username = cm.group(1)
            src_ip   = cm.group(2)
            self._sessions[thread_id] = {
                "src_ip":    src_ip,
                "username":  username,
                "timestamp": _normalize_timestamp(timestamp_str or _now_iso()),
                "queries":   [],
            }
            # Emit a connect event immediately
            self._emit_event(thread_id, "cowrie.session.connect", argument)

        elif command == "Query" and thread_id in self._sessions:
            self._sessions[thread_id]["queries"].append(argument)
            # Emit each query as a command.input event
            self._emit_event(thread_id, "cowrie.command.input", argument)

        elif command == "Quit":
            # Emit a session.closed event then clean up
            if thread_id in self._sessions:
                self._emit_event(thread_id, "cowrie.session.closed", "")
                del self._sessions[thread_id]

        # Init, Statistics, and other commands are logged but not emitted

    def _emit_event(self, thread_id: str, eventid: str, argument: str) -> None:
        sess = self._sessions.get(thread_id)
        if sess is None:
            return

        src_ip    = sess["src_ip"]
        username  = sess["username"]
        timestamp = sess["timestamp"]
        geo       = enrich_geoip(src_ip)

        session_id = sha256(
            f"{src_ip}3306{timestamp}".encode()
        ).hexdigest()[:16]

        event = {
            "eventid":   eventid,
            "src_ip":    src_ip,
            "src_port":  None,
            "session":   session_id,
            "timestamp": timestamp,
            "sensor":    SENSOR_NAME_MARIADB,
            "dst_port":  3306,
            "username":  username or None,
            "password":  None,
            "input":     argument if eventid == "cowrie.command.input" else None,
            # Internal metadata
            "_sensor_type": "mariadb",
            "_protocol":    "mysql",
            "_thread_id":   thread_id,
            "_raw":         {"command": eventid, "argument": argument, "thread_id": thread_id},
            **geo,
        }
        _enqueue(event)


class MariaDBFileEventHandler(FileSystemEventHandler):
    def __init__(self, tailer: MariaDBTailer):
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


# ---------------------------------------------------------------------------
# SMB JSON log tailer (Module 8 — smb-lure)
# ---------------------------------------------------------------------------
# smb_server.py writes one JSON object per line to smb_events.json.
# Each line contains: eventid, src_ip, src_port, dst_port, username, session,
# timestamp, ntlmv2_hash (for smb.ntlmv2.hash events), sensor, _sensor_type.
#
# Log rotation is handled with the break+re-open pattern (same fix as the
# HoneyDash log rotation bug — f.seek(0) on old handle silently missed events).
# ---------------------------------------------------------------------------

class SmbTailer:
    """Tails /var/log/smb/smb_events.json, parses each JSON line, enqueues normalized events."""

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
            self._fh.seek(0, 2)   # tail from end on first open — skip historical events
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
        """Detect log rotation (inode change) and reopen."""
        if self._fh is None:
            return
        try:
            stat = os.stat(self.log_path)
            if stat.st_ino != self._inode:
                log.info("smb_log_rotated", path=self.log_path)
                self._fh.close()
                self._fh = None
                # Do NOT seek on the old handle — break out so outer loop re-opens fresh.
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
                # Line not yet complete — buffer and wait for next inotify event
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

        # Startup sentinel — not an attacker event; suppress silently
        if eventid == "smb.server.started":
            return

        src_ip   = raw.get("src_ip", "")
        src_port = raw.get("src_port")
        geo      = enrich_geoip(src_ip)

        # Build payload dict from SMB-specific fields
        # ntlmv2_hash is stored in both payload (forensic) and password column (HoneyDash cred view)
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
            "password":     raw.get("ntlmv2_hash") or None,   # NTLMv2: populate password col for HoneyDash cred view
            "_sensor_type": "smb",
            "_protocol":    "smb",
            "_raw":         raw,
            # Make payload_fields available to PostgresWriter.write() via event dict
            **payload_fields,
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


# ---------------------------------------------------------------------------
# PostgreSQL writer
# ---------------------------------------------------------------------------
# Writes normalized events to the honeypot_events hypertable.
# Reconnects automatically on connection loss.
# ---------------------------------------------------------------------------

INSERT_SQL = """
INSERT INTO honeypot_events (
    event_id, created_at, sensor, event_type,
    src_ip, src_port, dst_port,
    geo_country, geo_country_code, geo_city, geo_lat, geo_lon,
    geo_asn, geo_org,
    username, password,
    payload, raw_log, session_id,
    threat_score, tags, is_tor
) VALUES (
    %(event_id)s, %(created_at)s, %(sensor)s, %(event_type)s,
    %(src_ip)s, %(src_port)s, %(dst_port)s,
    %(geo_country)s, %(geo_country_code)s, %(geo_city)s, %(geo_lat)s, %(geo_lon)s,
    %(geo_asn)s, %(geo_org)s,
    %(username)s, %(password)s,
    %(payload)s, %(raw_log)s, %(session_id)s,
    %(threat_score)s, %(tags)s, %(is_tor)s
)
;
"""


def _compute_threat_score(eventid: str, sensor_type: str) -> int:
    if eventid == "cowrie.login.success":
        return 90
    if eventid == "cowrie.session.file_download":
        return 85
    if eventid in ("http.rce.attempt", "http.lfi.attempt"):
        return 80
    if eventid == "smb.ntlmv2.hash":
        return 80    # credential capture — same tier as RCE/LFI attempt
    if eventid == "http.sqli.attempt":
        return 75
    if eventid == "http.lure.credential.success":
        return 70
    if eventid in ("smb.file.write", "smb.pipe.connect"):
        return 65    # lateral movement indicators
    if sensor_type == "mariadb":
        return 60
    if "lure" in eventid or eventid in ("/.env", "/config.yaml"):
        return 55
    if eventid == "cowrie.login.failed":
        return 40
    if eventid in ("smb.enum.shares", "smb.auth.attempt", "smb.connect"):
        return 35    # SMB recon — comparable to cowrie.login.failed
    if eventid.startswith("http."):
        return 20
    return 10


def _compute_tags(eventid: str, sensor_type: str) -> list:
    tags = set()
    if eventid == "cowrie.session.file_download":
        tags.add("malware-delivery")
    if eventid == "cowrie.login.success":
        tags.add("initial-access")
    if eventid == "cowrie.login.failed":
        tags.add("brute-force")
    if "lfi" in eventid:
        tags.update(["web-attack", "lfi"])
    if "sqli" in eventid:
        tags.update(["web-attack", "sqli"])
    if "rce" in eventid:
        tags.update(["web-attack", "rce"])
    if eventid == "http.lure.credential.success":
        tags.add("credential-theft")
    if sensor_type == "mariadb":
        tags.add("database-recon")
    # SMB sensor tags (Module 8)
    if eventid == "smb.ntlmv2.hash":
        tags.update(["credential-theft", "smb-probe"])
    if eventid == "smb.file.write":
        tags.update(["lateral-movement", "smb-probe"])
    if eventid in ("smb.enum.shares", "smb.connect", "smb.auth.attempt", "smb.pipe.connect",
                   "smb.file.read"):
        tags.add("smb-probe")
    return list(tags)

UPSERT_SESSION_SQL = """
INSERT INTO attacker_sessions (session_id, src_ip, first_seen, last_seen, event_count, sensors_hit)
VALUES (%(session_id)s, %(src_ip)s, %(created_at)s, %(created_at)s, 1, ARRAY[%(sensor)s])
ON CONFLICT (session_id) DO UPDATE
    SET last_seen    = EXCLUDED.last_seen,
        event_count  = attacker_sessions.event_count + 1,
        sensors_hit  = CASE
            WHEN EXCLUDED.sensors_hit[1] = ANY(attacker_sessions.sensors_hit)
            THEN attacker_sessions.sensors_hit
            ELSE array_append(attacker_sessions.sensors_hit, EXCLUDED.sensors_hit[1])
        END
;
"""

# Kill chain stage ordering — higher number = more advanced stage (never regress)
_KILL_CHAIN_ORDER = {
    "RECON":             1,
    "INITIAL_ACCESS":    2,
    "DISCOVERY":         3,
    "CREDENTIAL_ACCESS": 4,
    "EXECUTION":         5,
    "EXFILTRATION":      6,
}

# Advance kill_chain_stage only when the new stage is strictly higher than current
ADVANCE_KILL_CHAIN_SQL = """
UPDATE attacker_sessions
SET kill_chain_stage = %(stage)s
WHERE session_id = %(session_id)s
  AND (
    kill_chain_stage IS NULL
    OR CASE kill_chain_stage
         WHEN 'RECON'             THEN 1
         WHEN 'INITIAL_ACCESS'    THEN 2
         WHEN 'DISCOVERY'         THEN 3
         WHEN 'CREDENTIAL_ACCESS' THEN 4
         WHEN 'EXECUTION'         THEN 5
         WHEN 'EXFILTRATION'      THEN 6
         ELSE 0
       END < %(stage_order)s
  )
"""


def _classify_kill_chain_stage(eventid: str, payload: dict) -> str | None:
    """Map a single sensor event to a kill chain stage. Returns None if unclassifiable.

    Checked in descending priority so the highest applicable stage wins.
    payload keys: input (command/SQL), http_input ("HTTP GET /path"), url, etc.
    """
    cmd       = (payload.get("input") or "").lower()
    http_hint = (payload.get("http_input") or "").lower()   # "http get /some/path"
    # extract just the path portion from "HTTP METHOD /path"
    hint_parts = http_hint.split()
    path = hint_parts[-1] if len(hint_parts) >= 3 else ""

    # EXFILTRATION — data is leaving the environment
    if eventid == "cowrie.session.file_download":
        return "EXFILTRATION"
    if eventid == "cowrie.command.input" and re.search(r'\bwget\b|\bcurl\b', cmd):
        return "EXFILTRATION"

    # EXECUTION — attacker executes code or plants a payload
    if eventid == "cowrie.command.input" and re.search(
        r'python3?\s+-c|perl\s+-e|bash\s+-i|nc\s+-e|ncat\s+-e|chmod\s+\+x|\./',
        cmd,
    ):
        return "EXECUTION"

    # CREDENTIAL_ACCESS — reading stored secrets
    if eventid == "cowrie.command.input" and re.search(
        r'\.env|config\.yaml|\.bash_history|\.aws|authorized_keys|id_rsa|id_ed25519',
        cmd,
    ):
        return "CREDENTIAL_ACCESS"
    if any(p in path for p in ("/.env", "/config.yaml", "/api/v1/internal",
                                "/api/v1/lure", "/.git/config")):
        return "CREDENTIAL_ACCESS"
    # SMB NTLMv2 hash capture = credential access
    if eventid == "smb.ntlmv2.hash":
        return "CREDENTIAL_ACCESS"

    # DISCOVERY — enumeration of the system
    if eventid == "cowrie.command.input" and re.search(
        r'\bid\b|\bwhoami\b|\buname\b|\bls\s|\bps\s|\bifconfig|\bip\s+a|\bnetstat\b|\bhostname\b|\bcat\s+/etc',
        cmd,
    ):
        return "DISCOVERY"
    if any(p in path for p in ("/admin", "/api/v1/cluster", "/api/v1/internal")):
        return "DISCOVERY"

    # INITIAL_ACCESS — authentication / credential attempts
    if eventid in ("cowrie.login.failed", "cowrie.login.success"):
        return "INITIAL_ACCESS"
    # SMB auth attempt = initial access (NTLM auth exchange attempted)
    if eventid == "smb.auth.attempt":
        return "INITIAL_ACCESS"
    # SMB file discovery = DISCOVERY stage
    if eventid == "smb.file.read":
        return "DISCOVERY"
    # SMB file write = attacker trying to plant a file = EXECUTION
    if eventid == "smb.file.write":
        return "EXECUTION"

    # RECON — any initial probe
    if eventid == "cowrie.session.connect" or eventid.startswith("http."):
        return "RECON"
    # SMB connect / share enum / pipe enumeration = RECON
    if eventid in ("smb.connect", "smb.enum.shares", "smb.pipe.connect"):
        return "RECON"

    return None


class PostgresWriter:
    def __init__(self, dsn: str):
        self._dsn  = dsn
        self._conn = None

    def _connect(self) -> bool:
        for attempt in range(1, 6):
            try:
                self._conn = psycopg2.connect(self._dsn)
                self._conn.autocommit = True
                log.info("postgres_connected")
                return True
            except Exception as exc:
                log.warning("postgres_connect_retry", attempt=attempt, error=str(exc))
                time.sleep(5 * attempt)
        log.error("postgres_connect_failed", dsn=self._dsn[:40])
        return False

    def _ensure_connected(self) -> bool:
        if self._conn is None or self._conn.closed:
            return self._connect()
        try:
            self._conn.cursor().execute("SELECT 1")
            return True
        except Exception:
            self._conn = None
            return self._connect()

    @staticmethod
    def _clean(obj):
        """Recursively strip NUL bytes — PostgreSQL text/jsonb columns reject \x00 / \\u0000."""
        if isinstance(obj, str):
            return obj.replace('\x00', '')
        if isinstance(obj, dict):
            return {k: PostgresWriter._clean(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [PostgresWriter._clean(v) for v in obj]
        return obj

    def write(self, event: dict) -> bool:
        """Write one normalized event to honeypot_events. Returns True on success."""
        if not self._ensure_connected():
            return False
        sensor_type = event.get("_sensor_type", "unknown")
        eventid     = event.get("eventid", "")
        src_ip      = event.get("src_ip", "")

        # src_ip is NOT NULL in schema — drop internal/startup events with no source IP
        if not src_ip:
            log.warning("event_dropped_no_src_ip", event_type=eventid, sensor=sensor_type)
            return True  # True = don't re-spool; these are unfixable malformed events

        # Map internal sensor_type to the Postgres 'sensor' column vocabulary
        sensor_col = {
            "ssh":        "cowrie",
            "opencanary": "opencanary",
            "mariadb":    "mariadb",
            "api":        "api",
            "smb":        "smb",       # Module 8 — impacket SMB honeypot
        }.get(sensor_type, sensor_type)

        # Build the payload JSONB (protocol-specific fields)
        payload_fields = {}
        for k in ("username", "password", "input", "url", "outfile", "duration",
                   "_protocol", "_logtype", "_logdata", "_http_input",
                   # SMB-specific payload fields (Module 8)
                   "ntlmv2_hash", "domain", "pipe_name", "path", "file_name",
                   "shares_requested", "ntlm_flags"):
            v = event.get(k)
            if v is not None:
                payload_fields[k.lstrip("_")] = self._clean(v)

        row = {
            "event_id":        str(uuid.uuid4()),
            "created_at":      event.get("timestamp", _now_iso()),
            "sensor":          sensor_col,
            "event_type":      eventid,
            "src_ip":          src_ip if src_ip else None,
            "src_port":        event.get("src_port"),
            "dst_port":        event.get("dst_port"),
            "geo_country":     event.get("geo_country"),
            "geo_country_code":event.get("geo_country_code"),
            "geo_city":        event.get("geo_city"),
            "geo_lat":         event.get("geo_lat"),
            "geo_lon":         event.get("geo_lon"),
            "geo_asn":         event.get("geo_asn"),
            "geo_org":         event.get("geo_org"),
            "username":        self._clean(event.get("username")),
            "password":        self._clean(event.get("password")),
            "payload":         json.dumps(payload_fields) if payload_fields else None,
            "raw_log":         json.dumps(self._clean(event.get("_raw", {}))),
            "session_id":      event.get("session"),
            "threat_score":    _compute_threat_score(eventid, sensor_type),
            "tags":            _compute_tags(eventid, sensor_type),
            "is_tor":          _is_tor(src_ip),
        }
        try:
            with self._conn.cursor() as cur:
                cur.execute(INSERT_SQL, row)
        except Exception as exc:
            log.error("postgres_write_error", error=str(exc), event_type=eventid, src_ip=src_ip)
            self._conn = None  # force reconnect on next write
            return False

        # Upsert attacker_sessions — best-effort, runs only after successful INSERT
        if row.get("session_id") and row.get("src_ip"):
            try:
                with self._conn.cursor() as cur:
                    cur.execute(UPSERT_SESSION_SQL, {
                        "session_id": row["session_id"],
                        "src_ip":     row["src_ip"],
                        "created_at": row["created_at"],
                        "sensor":     row["sensor"],
                    })
            except Exception as exc:
                log.warning("session_upsert_error", error=str(exc))

            # Advance kill chain stage — only if this event maps to a stage
            stage = _classify_kill_chain_stage(eventid, payload_fields)
            if stage:
                try:
                    with self._conn.cursor() as cur:
                        cur.execute(ADVANCE_KILL_CHAIN_SQL, {
                            "stage":       stage,
                            "stage_order": _KILL_CHAIN_ORDER[stage],
                            "session_id":  row["session_id"],
                        })
                        if cur.rowcount > 0:
                            log.info("kill_chain_advanced",
                                     session_id=row["session_id"],
                                     src_ip=src_ip,
                                     stage=stage,
                                     eventid=eventid)
                except Exception as exc:
                    log.warning("kill_chain_update_error", error=str(exc))

        return True


# ---------------------------------------------------------------------------
# Redis publisher
# ---------------------------------------------------------------------------
# Publishes events to Redis Stream 'honeypot:events'.
# Section 5.2 item 7: "Publishes to Redis Stream honeypot:events (real-time feed)"
# ---------------------------------------------------------------------------

class RedisPublisher:
    def __init__(self, url: str):
        self._url    = url
        self._client = None
        self._stream = "honeypot:events"

    def _connect(self) -> bool:
        for attempt in range(1, 4):
            try:
                self._client = redis_lib.from_url(
                    self._url,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5,
                )
                self._client.ping()
                log.info("redis_connected")
                return True
            except Exception as exc:
                log.warning("redis_connect_retry", attempt=attempt, error=str(exc))
                time.sleep(3 * attempt)
        log.error("redis_connect_failed", url=self._url[:30])
        return False

    def _ensure_connected(self) -> bool:
        if self._client is None:
            return self._connect()
        try:
            self._client.ping()
            return True
        except Exception:
            self._client = None
            return self._connect()

    def publish(self, event: dict) -> None:
        """Publish event to Redis Stream. Failure is logged and skipped (best-effort)."""
        if not self._ensure_connected():
            return
        try:
            # Stream entry: minimal fields for real-time dashboard consumption
            entry = {
                "eventid":   event.get("eventid", ""),
                "src_ip":    event.get("src_ip", ""),
                "sensor":    event.get("sensor", ""),
                "timestamp": event.get("timestamp", ""),
                "session":   event.get("session", ""),
            }
            # Remove None values — Redis XADD does not accept None
            entry = {k: v for k, v in entry.items() if v is not None}
            self._client.xadd(
                self._stream, entry,
                maxlen=50000,    # cap stream length; prevents unbounded memory growth
                approximate=True,
            )
        except Exception as exc:
            log.warning("redis_publish_error", error=str(exc))
            self._client = None


# ---------------------------------------------------------------------------
# HoneyDash batch pusher
# ---------------------------------------------------------------------------
# Batches events and flushes to HoneyDash POST /api/ingest/batch every
# FLUSH_INTERVAL seconds or when BATCH_SIZE events accumulate.
# ---------------------------------------------------------------------------

_HD_PORT_PROTOCOL = {
    21:   "ftp",
    22:   "ssh",
    23:   "telnet",
    25:   "smtp",
    80:   "http",
    443:  "https",
    445:  "smb",
    2222: "ssh",
    3306: "mysql",
    6379: "redis",
}

_HD_SENSOR_NAME = {
    SENSOR_NAME_COWRIE:     "remote",
    SENSOR_NAME_OPENCANARY: "remote",
    SENSOR_NAME_MARIADB:    "remote",
    SENSOR_NAME_API:        "remote",
    "smb":                  "remote",   # Module 8 — SMB events mapped to "remote" for HoneyDash
    # Short-name aliases — as stored in the PostgreSQL sensor column
    "cowrie":               "remote",
    "opencanary":           "remote",
    "mariadb":              "remote",
    "api":                  "remote",
}

# Clean attack_type labels for the HoneyDash event table.
# HoneyDash fallback is eid.replace(".", " ").title() which produces ugly strings.
# Cowrie/dionaea entries are intentionally OMITTED — HoneyDash's native EVENTID_TO_ATTACK_TYPE
# already maps those with priority-1 and wins over this dict.
# Only event types NOT in HoneyDash's native map are listed here.
_HD_ATTACK_TYPE: dict = {
    # OpenCanary / MariaDB — remote.* prefixed eventids bypass HoneyDash's cowrie.* lookup table
    # so attack_type labels are not overridden by "SSH Brute Force" / "SSH Connect".
    "remote.ftp.login":         "FTP Brute Force",
    "remote.ftp.connect":       "FTP Connect",
    "remote.telnet.login":      "Telnet Brute Force",
    "remote.telnet.connect":    "Telnet Connect",
    "remote.redis.auth":        "Redis Auth Attempt",
    "remote.redis.connect":     "Redis Connect",
    "remote.redis.command":     "Redis Command",
    "remote.mariadb.connect":   "MySQL Connect",
    "remote.mariadb.query":     "MySQL Query",
    # HTTP SNARE
    "http.sqli.attempt":            "SQL Injection",
    "http.post.sqli.attempt":       "SQL Injection",
    "http.lfi.attempt":             "LFI Attempt",
    "http.get.lfi.attempt":         "LFI Attempt",
    "http.rce.attempt":             "RCE Attempt",
    "http.post.rce.attempt":        "RCE Attempt",
    "http.cmdi.attempt":            "Command Injection",
    "http.ssrf.attempt":            "SSRF Attempt",
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
    "http.telemetry.devtools_opened": "DevTools Detected",
    # Security page
    "security.mfa_toggle_attempt":     "MFA Disable Attempt",
    "security.session_revoke_attempt": "Session Revocation",
    "security.allowlist_probe":        "IP Allowlist Edit",
    "security.key_rotation_attempt":   "Key Rotation",
    "security.audit_log_viewed":       "Audit Log Access",
    # Cross-sensor
    "cross_sensor.credential_relay": "Credential Relay (SSH->DB)",
    # SMB
    "smb.ntlmv2.hash":    "NTLMv2 Hash Captured",
    "smb.auth.attempt":   "SMB Auth Attempt",
    "smb.enum.shares":    "SMB Share Enumeration",
    "smb.file.read":      "SMB File Read",
    "smb.file.write":     "SMB File Write",
    "smb.connect":        "SMB Connect",
    # HTTP contact form
    "http.contact.malicious_form":           "Malicious Form Submission",
    # Lure file discovery (/.env, /config.yaml → path_cat="lure_file")
    "http.get.lure_file":                    "Lure File Access",
    "http.head.lure_file":                   "Lure File Access",
    # Git repo exposure (/.git/config, /.git/HEAD — path_cat starts with .git)
    "http.get..git.config":                  "Git Config Exposed",
    "http.get..git.head":                    "Git HEAD Exposed",
    # Internal API discovery (/api/v1/internal/*)
    "http.get.internal.config":              "Internal Config Discovery",
    "http.get.internal.debug":               "Debug Endpoint Discovery",
    # Cluster node recon (/api/v1/cluster/nodes)
    "http.get.cluster.nodes":                "Cluster Node Recon",
    # Automated scanner detection (gobuster, sqlmap, nikto, etc.)
    "http.scanner.fingerprinted":            "Automated Scanner",
    # Returning attacker (same IP seen on multiple sessions/days)
    "http.workspace.returning_attacker":     "Returning Attacker",
    # Unauthenticated access to session-gated pages
    "http.unauth.sensitive_access":          "Unauth Sensitive Access",
    # Authenticated user actions (inside the portal)
    "http.profile.update":                   "Profile Updated",
    "http.api_keys.create_attempted":        "API Key Created",
    "http.api_keys.revoke_attempted":        "API Key Revoked",
    "http.team.invite_submitted":            "Team Invite",
    "http.team.remove_attempted":            "Team Member Removed",
    # Security / settings SNARE actions
    "http.snare.script_upload":              "Script Upload / RCE Trap",
    "http.snare.ssh_key_submitted":          "SSH Key Submitted",
    "http.snare.mfa_enable_attempt":         "MFA Enable Attempt",
    "http.snare.admin_action_attempted":     "Admin Action",
    "http.mfa.bypass_attempt":               "MFA Bypass Attempt",
    "http.security.allowlist_toggle":        "Perimeter Lockdown Attempt",
    "http.security.keys_rotate":             "Key Rotation",
}

# Internal Docker healthcheck and session bookkeeping — not real attacker events
_HD_NOISE_EVENTS = {
    "http.get.health",
    "http.head.health",
    "cowrie.session.closed",
    "api.startup",
}

# Remap Cowrie-compatible eventids to sensor-specific remote.* strings for non-SSH sensors.
# HoneyDash's EVENTID_TO_ATTACK_TYPE maps cowrie.login.failed → "SSH Brute Force" with
# first-priority — this overrides any attack_type Neuro sends.  Switching to remote.* eventids
# makes the HoneyDash lookup return None, falling through to data.get("attack_type") which
# carries the correct label from _HD_ATTACK_TYPE.
#
# Keys: (dst_port: int, cowrie_eventid: str)  →  replacement eventid: str
# NOTE: cowrie.session.closed is intentionally absent — it is in _HD_NOISE_EVENTS and is
# filtered out BEFORE this remap runs, so an entry here would never be reached.
_HD_EVENTID_REMAP: dict[tuple[int, str], str] = {
    # OpenCanary FTP (port 21)
    (21, "cowrie.login.failed"):    "remote.ftp.login",
    (21, "cowrie.session.connect"): "remote.ftp.connect",
    # OpenCanary Telnet (port 23)
    (23, "cowrie.login.failed"):    "remote.telnet.login",
    (23, "cowrie.session.connect"): "remote.telnet.connect",
    # OpenCanary Redis (port 6379)
    (6379, "cowrie.login.failed"):    "remote.redis.auth",
    (6379, "cowrie.session.connect"): "remote.redis.connect",
    (6379, "cowrie.command.input"):   "remote.redis.command",
    # MariaDB (port 3306)
    (3306, "cowrie.session.connect"): "remote.mariadb.connect",
    (3306, "cowrie.command.input"):   "remote.mariadb.query",
}


def _honeydash_event(event: dict) -> dict | None:
    """Build a HoneyDash-compatible event object from an internal event.

    Returns None for noise events that should not be forwarded to HoneyDash.
    Fixes applied before sending:
    - protocol: inferred from dst_port so MariaDB/FTP/Redis are not mislabelled "ssh"
    - sensor:   mapped to "remote" so all events pass HoneyDash's is_remote_custom check
    """
    if event.get("_event_type") in _HD_NOISE_EVENTS or event.get("eventid") in _HD_NOISE_EVENTS:
        return None

    out = {k: v for k, v in event.items()
           if not k.startswith("_") and v is not None}

    if out.get("eventid") in _HD_NOISE_EVENTS:
        return None

    # Remap Cowrie-compatible eventids to sensor-specific remote.* strings for non-SSH sensors.
    # Mutates out["eventid"] only — the original event dict (already written to PostgreSQL)
    # is never touched.  SSH events (port 22/2222) have no entries in _HD_EVENTID_REMAP
    # and are completely unaffected.
    _raw_eid = out.get("eventid", "")
    _raw_port = out.get("dst_port")
    if _raw_port:
        try:
            _raw_port_int = int(_raw_port)
            _remapped_eid = _HD_EVENTID_REMAP.get((_raw_port_int, _raw_eid))
            if _remapped_eid:
                out["eventid"] = _remapped_eid
        except (ValueError, TypeError):
            pass

    # Inject correct protocol based on dst_port
    dst_port = out.get("dst_port")
    if dst_port and "protocol" not in out:
        try:
            out["protocol"] = _HD_PORT_PROTOCOL.get(int(dst_port), "unknown")
        except (ValueError, TypeError):
            out["protocol"] = "unknown"

    # Remap sensor names
    sensor = out.get("sensor", "")
    out["sensor"] = _HD_SENSOR_NAME.get(sensor, sensor)

    # Apply clean attack_type label if not already set by caller (FIX-D)
    if "attack_type" not in out or not out.get("attack_type"):
        event_type_key = out.get("eventid") or ""
        out["attack_type"] = _HD_ATTACK_TYPE.get(
            event_type_key,
            event_type_key.replace(".", " ").title()
        )

    return out


def _flush_to_honeydash() -> None:
    """Flush the current batch to HoneyDash. Called by the flush thread."""
    global _honeydash_batch

    if not HONEYDASH_URL or not SENSOR_API_KEY:
        return  # HoneyDash push disabled

    with _honeydash_lock:
        if not _honeydash_batch:
            return
        batch = _honeydash_batch[:]
        _honeydash_batch = []

    payload = [_honeydash_event(e) for e in batch]
    payload = [e for e in payload if e is not None]
    url = f"{HONEYDASH_URL.rstrip('/')}/api/ingest/batch"
    headers = {
        "Content-Type": "application/json",
        "X-Sensor-Key": SENSOR_API_KEY,
    }
    for attempt in range(1, 4):
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=10)
            if resp.status_code == 202:
                result = resp.json()
                log.info("honeydash_flush_ok",
                         accepted=result.get("accepted", 0),
                         errors=result.get("errors", 0),
                         total=len(payload))
                return
            else:
                log.warning("honeydash_flush_non202",
                            status=resp.status_code, body=resp.text[:200],
                            attempt=attempt)
        except Exception as exc:
            log.warning("honeydash_flush_error", error=str(exc), attempt=attempt)
        time.sleep(2 ** attempt)  # exponential backoff: 2s, 4s, 8s

    log.error("honeydash_flush_abandoned", batch_size=len(payload))


def _honeydash_flush_thread() -> None:
    """Background thread: poll HTTP events from PostgreSQL + flush HoneyDash batch every FLUSH_INTERVAL seconds."""
    while True:
        time.sleep(FLUSH_INTERVAL)
        try:
            _poll_http_events()   # pull sensor='api' events from PostgreSQL
            _flush_to_honeydash()
        except Exception as exc:
            log.error("honeydash_flush_thread_error", error=str(exc))


def _add_to_honeydash_batch(event: dict) -> None:
    """Add event to HoneyDash batch; flush immediately if BATCH_SIZE reached."""
    global _honeydash_batch
    with _honeydash_lock:
        _honeydash_batch.append(event)
        should_flush = len(_honeydash_batch) >= BATCH_SIZE

    if should_flush:
        _flush_to_honeydash()


def _poll_http_events() -> None:
    """Pull new sensor='api' events from PostgreSQL into the HoneyDash batch.

    honeypot-api writes HTTP events directly to PostgreSQL and never goes through
    log_shipper's watchdog (which only tails log files).  This poller bridges the gap
    so all HTTP events — login attempts, lure downloads, SSRF probes, scanner hits —
    reach HoneyDash through the same proven batch mechanism used for SSH/FTP/MariaDB.

    Called by _honeydash_flush_thread() every FLUSH_INTERVAL seconds.
    Watermark advances after each successful poll so no event is added twice.
    """
    global _http_poll_watermark

    if not HONEYDASH_URL or not SENSOR_API_KEY:
        return

    from datetime import timedelta

    try:
        with _http_poll_lock:
            if _http_poll_watermark is None:
                # First call: start 30s in the past to catch recent events
                _http_poll_watermark = datetime.now(timezone.utc) - timedelta(seconds=30)
            since = _http_poll_watermark

        with psycopg2.connect(POSTGRES_DSN) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT event_type, src_ip::text, src_port, dst_port,
                           username, password, created_at
                    FROM honeypot_events
                    WHERE sensor = 'api'
                      AND created_at > %s
                    ORDER BY created_at ASC
                    LIMIT 500
                    """,
                    (since,),
                )
                rows = cur.fetchall()

        if not rows:
            return

        new_watermark = since
        for row in rows:
            event_type, src_ip, src_port, dst_port, username, password, created_at = row

            # Strip PostgreSQL /32 CIDR suffix from inet column
            if src_ip and "/" in src_ip:
                src_ip = src_ip.split("/")[0]

            # Always advance watermark — even for events we don't forward —
            # so they are not re-polled on the next tick.
            new_watermark = created_at

            # Selectivity filter — only forward to HoneyDash if:
            #   1. event_type is explicitly in _HD_ATTACK_TYPE (opt-in allowlist), OR
            #   2. username is not None (any login credential submission)
            # Lure paths like /artifacts, /runs, /models are NOT forwarded — they are
            # portal navigation, not attacks. True lure file event_types (http.get.lure_file,
            # http.get..git.config, etc.) are listed in _HD_ATTACK_TYPE explicitly.
            if event_type not in _HD_ATTACK_TYPE and username is None:
                continue

            event = {
                "eventid":   event_type,
                "sensor":    "api",           # _honeydash_event() remaps "api" → "remote"
                "src_ip":    src_ip,
                "src_port":  src_port,
                "dst_port":  dst_port or 8080,
                "username":  username,
                "password":  password,
                "timestamp": created_at.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
                "protocol":  "http",
            }
            _add_to_honeydash_batch(event)

        with _http_poll_lock:
            _http_poll_watermark = new_watermark

        log.debug("http_poll_ok", count=len(rows))

    except Exception as exc:
        log.warning("http_poll_error", error=str(exc))


# ---------------------------------------------------------------------------
# P3-10: MariaDB credential relay detection
# ---------------------------------------------------------------------------
# When an attacker SSH's into Cowrie, cats config.yaml to get the DB password,
# then connects to MariaDB — those two events are unlinked by default.
# This check bridges them into a single cross_sensor.credential_relay event.

def _check_mariadb_credential_relay(pg: PostgresWriter, event: dict) -> None:
    """Emit cross_sensor.credential_relay if a MariaDB connect follows SSH config access."""
    src_ip = event.get("src_ip")
    if not src_ip or not pg._conn:
        return
    try:
        clean_ip = src_ip.split("/")[0] if "/" in src_ip else src_ip
        with pg._conn.cursor() as cur:
            cur.execute("""
                SELECT payload->>'input' AS cmd, created_at
                FROM honeypot_events
                WHERE host(src_ip) = %s
                  AND sensor = 'cowrie'
                  AND event_type = 'cowrie.command.input'
                  AND created_at > NOW() - INTERVAL '30 minutes'
                  AND payload->>'input' ILIKE '%%config.yaml%%'
                ORDER BY created_at DESC
                LIMIT 1
            """, (clean_ip,))
            row = cur.fetchone()
        if not row:
            return
        prior_cmd = row[0] or ""
        relay_event = {
            "eventid":      "cross_sensor.credential_relay",
            "src_ip":       clean_ip,
            "src_port":     None,
            "session":      sha256(f"{clean_ip}relay{_now_iso()}".encode()).hexdigest()[:16],
            "timestamp":    _now_iso(),
            "sensor":       SENSOR_NAME_MARIADB,
            "dst_port":     3306,
            "username":     event.get("username"),
            "password":     None,
            "input":        None,
            "_sensor_type": "mariadb",
            "_protocol":    "mysql",
            "_raw": {
                "relay_type":    "ssh_config_to_mariadb",
                "prior_ssh_cmd": prior_cmd[:200],
                "mariadb_user":  event.get("username"),
                "src_ip":        clean_ip,
            },
            **enrich_geoip(clean_ip),
        }
        _enqueue(relay_event)
        log.info("credential_relay_detected", src_ip=clean_ip, prior_cmd=prior_cmd[:80])
    except Exception as exc:
        log.warning("credential_relay_check_error", error=str(exc))


# ---------------------------------------------------------------------------
# Main event consumer thread
# ---------------------------------------------------------------------------

def _consumer_thread(pg: PostgresWriter, redis_pub: RedisPublisher) -> None:
    """Drains EVENT_QUEUE, writes to Postgres, publishes to Redis, buffers for HoneyDash."""
    log.info("consumer_thread_started")
    while True:
        try:
            # Block up to 1 second so the thread can be interrupted cleanly on shutdown
            try:
                event = EVENT_QUEUE.get(timeout=1.0)
            except queue.Empty:
                continue

            # Write to PostgreSQL (durable store)
            pg_ok = pg.write(event)
            if not pg_ok:
                # Postgres write failed — spool to disk to avoid data loss
                _spool_event(event)

            # P3-10: MariaDB credential relay — check after successful DB write
            if (pg_ok
                    and event.get("_sensor_type") == "mariadb"
                    and event.get("eventid") == "cowrie.session.connect"):
                _check_mariadb_credential_relay(pg, event)

            # Publish to Redis Stream (best-effort real-time)
            redis_pub.publish(event)

            # Real-time Telegram alert for high-value events
            # Enqueue to dedicated worker thread — never block the consumer on Telegram I/O.
            should_alert, reason = _should_alert(event)
            if should_alert:
                try:
                    _telegram_queue.put_nowait((event, reason))
                except queue.Full:
                    log.debug("telegram_queue_full_dropping_alert")

            # Buffer for HoneyDash batch push
            _add_to_honeydash_batch(event)

            EVENT_QUEUE.task_done()

        except Exception as exc:
            log.error("consumer_thread_error", error=str(exc))


# ---------------------------------------------------------------------------
# Health check HTTP server
# ---------------------------------------------------------------------------

class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            body = b'{"status":"ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        pass  # suppress access log noise in docker logs


def _health_server_thread() -> None:
    server = HTTPServer(("0.0.0.0", 9100), HealthHandler)
    log.info("health_server_started", port=9100)
    server.serve_forever()


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _normalize_timestamp(ts: str) -> str:
    """Normalize various timestamp formats to ISO 8601 UTC with microseconds."""
    if not ts:
        return _now_iso()
    ts = ts.strip()
    # Already correct format: "2024-01-15T14:30:45.123456Z"
    if "T" in ts and ts.endswith("Z"):
        return ts
    # MariaDB format: "2026-05-17T09:14:22.418Z" — already correct
    if "T" in ts and ts.endswith("Z"):
        return ts
    # OpenCanary utc_time: "2024-01-15 14:30:45.123456"
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            continue
    return ts  # return as-is if parsing fails; Postgres will handle or reject


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main() -> None:
    log.info("log_shipper_starting",
             cowrie_log=COWRIE_LOG,
             opencanary_log=OPENCANARY_LOG,
             mariadb_log=MARIADB_LOG,
             smb_log=SMB_LOG,
             honeydash_url=HONEYDASH_URL or "(disabled)")

    # Ensure spool directory exists
    SPOOL_DIR.mkdir(parents=True, exist_ok=True)

    # Initialize GeoIP readers
    _init_geoip()

    # Replay any spooled events from previous outages
    _replay_spool()

    # Initialize data layer connections
    pg        = PostgresWriter(POSTGRES_DSN)
    redis_pub = RedisPublisher(REDIS_URL)

    # Start TOR exit list refresh thread (refreshes every 6h; first fetch at startup)
    t_tor = threading.Thread(target=_tor_refresh_thread, daemon=True, name="tor-refresh")
    t_tor.start()

    # Start the health check HTTP server (Docker healthcheck polls :9100/healthz)
    t_health = threading.Thread(target=_health_server_thread, daemon=True, name="health")
    t_health.start()

    # Start the event consumer thread
    t_consumer = threading.Thread(
        target=_consumer_thread, args=(pg, redis_pub), daemon=True, name="consumer"
    )
    t_consumer.start()

    # Start the Telegram alert worker thread (keeps consumer non-blocking on Telegram I/O)
    t_telegram = threading.Thread(target=_telegram_worker, daemon=True, name="telegram-worker")
    t_telegram.start()

    # Boot notification is handled by the sentinel container — do not duplicate here.

    # Start the HoneyDash flush thread
    t_flush = threading.Thread(target=_honeydash_flush_thread, daemon=True, name="honeydash_flush")
    t_flush.start()

    # Create tailers
    cowrie_tailer     = CowrieTailer(COWRIE_LOG)
    opencanary_tailer = OpenCanaryTailer(OPENCANARY_LOG)
    mariadb_tailer    = MariaDBTailer(MARIADB_LOG)
    smb_tailer        = SmbTailer(SMB_LOG)

    # Set up watchdog observers — one per log directory
    # Each observer uses inotify on Linux for zero-polling efficiency.
    observer = Observer()

    def _watch(tailer, handler_class, log_path: str) -> None:
        """Register a watchdog observer for a log file directory."""
        log_dir = str(Path(log_path).parent)
        handler = handler_class(tailer)
        observer.schedule(handler, path=log_dir, recursive=False)
        log.info("watchdog_scheduled", log_dir=log_dir, log_file=log_path)

    _watch(cowrie_tailer,     CowrieFileEventHandler,     COWRIE_LOG)
    _watch(opencanary_tailer, OpenCanaryFileEventHandler,  OPENCANARY_LOG)
    _watch(mariadb_tailer,    MariaDBFileEventHandler,    MARIADB_LOG)
    _watch(smb_tailer,        SmbFileEventHandler,        SMB_LOG)

    observer.start()
    log.info("log_shipper_ready", queue_maxsize=EVENT_QUEUE.maxsize)

    # Poll for new log files that may not exist yet at startup (e.g. Cowrie hasn't
    # had any connections, so cowrie.json doesn't exist). Every 30s, attempt to open
    # any tailer that is currently closed.
    try:
        while True:
            time.sleep(30)
            for tailer in (cowrie_tailer, opencanary_tailer, mariadb_tailer, smb_tailer):
                if tailer._fh is None:
                    tailer.read_new_lines()  # will retry open internally
                else:
                    # Drain any lines that arrived while watchdog was processing
                    tailer.read_new_lines()

    except KeyboardInterrupt:
        log.info("log_shipper_shutdown_requested")
    finally:
        observer.stop()
        observer.join()
        # Final flush to HoneyDash
        _flush_to_honeydash()
        log.info("log_shipper_stopped")


if __name__ == "__main__":
    main()
