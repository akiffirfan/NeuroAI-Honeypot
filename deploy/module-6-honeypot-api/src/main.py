"""
main.py — Neuro AI Training Platform (honeypot-api)

FastAPI deceptive HTTP honeypot disguised as an internal ML monitoring platform.
All requests are logged to PostgreSQL (honeypot_events) and published to the
Redis Stream 'honeypot:events' before any response is returned.

Deception legend: neurodata.me — fake internal tool "accidentally exposed"
during a cloud migration. Rewards attacker exploration at every depth:
  - Convincing login page with SSO failure and credential capture
  - Unauthenticated /dashboard (the "misconfiguration")
  - /.env and /config.yaml with honeytoken AWS/OpenAI/WandB keys
  - /api/v1/internal/config crown jewel with full fake credential dump
  - /admin/users user list accessible without auth
  - /api/docs fake Swagger UI listing all "internal" endpoints
  - Client-side fingerprinting via /static/js/metrics.js
"""

from __future__ import annotations

import asyncio
import collections
import hashlib
import json
import os
import random
import threading
import time
import unicodedata
import urllib.parse
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import httpx
import psycopg2
import psycopg2.extras
import redis as redis_lib
import structlog
from fastapi import Cookie, FastAPI, File, Request, Response, UploadFile
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

POSTGRES_DSN = os.environ.get("POSTGRES_DSN", "")
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
HONEYDASH_URL = os.environ.get("HONEYDASH_URL", "")
SENSOR_API_KEY = os.environ.get("SENSOR_API_KEY", "")
SENSOR_NAME = os.environ.get("SENSOR_NAME", "neuro-api-01")
LURE_DIR = Path(os.environ.get("LURE_DIR", "/app/lure-files"))
UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", "/app/uploads"))
CONFIG_DIR = Path(os.environ.get("CONFIG_DIR", "/app/config"))
GEOIP_DB = os.environ.get("GEOIP_DB", "/geoip/GeoLite2-City.mmdb")
GEOIP_ASN_DB = os.environ.get("GEOIP_ASN_DB", "/geoip/GeoLite2-ASN.mmdb")
# When true, a detected SQLi-on-login attempt returns a fake 200 success response
# to deepen engagement (attacker believes bypass worked). Default false (production).
# Enable only for live pitch demos via compose env override.
DEMO_SQLI_BYPASS = os.environ.get("DEMO_SQLI_BYPASS", "").lower() == "true"
# DEV_MODE loosens SameSite to "none" on the v2 session cookie so the React
# dev server (port 5173) can send credentials: "include" to FastAPI (port 8080).
# In production (nginx proxies /api/ same-origin) this must stay false.
DEV_MODE = os.environ.get("DEV_MODE", "").lower() == "true"
# Comma-separated origins allowed via CORS — only applied when non-empty.
# Example: CORS_ORIGINS=http://localhost:5173
CORS_ORIGINS = [o.strip() for o in os.environ.get("CORS_ORIGINS", "").split(",") if o.strip()]

APP_DIR = Path(__file__).parent

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(20),  # INFO level
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
)
logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# GeoIP
# ---------------------------------------------------------------------------

_geoip_city = None
_geoip_asn = None

def _load_geoip() -> None:
    global _geoip_city, _geoip_asn
    try:
        import geoip2.database
        if Path(GEOIP_DB).exists():
            _geoip_city = geoip2.database.Reader(GEOIP_DB)
            logger.info("geoip_city_loaded", path=GEOIP_DB)
        else:
            logger.warning("geoip_city_missing", path=GEOIP_DB)
        if Path(GEOIP_ASN_DB).exists():
            _geoip_asn = geoip2.database.Reader(GEOIP_ASN_DB)
            logger.info("geoip_asn_loaded", path=GEOIP_ASN_DB)
        else:
            logger.warning("geoip_asn_missing", path=GEOIP_ASN_DB)
    except Exception as exc:
        logger.warning("geoip_load_error", error=str(exc))


def _lookup_geo(ip: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "geo_country": None,
        "geo_country_code": None,
        "geo_city": None,
        "geo_asn": None,
        "geo_org": None,
    }
    if not ip or ip.startswith("127.") or ip.startswith("172.") or ip.startswith("10."):
        return result
    try:
        if _geoip_city:
            r = _geoip_city.city(ip)
            result["geo_country"] = r.country.name
            result["geo_country_code"] = r.country.iso_code
            result["geo_city"] = r.city.name
    except Exception:
        pass
    try:
        if _geoip_asn:
            r = _geoip_asn.asn(ip)
            result["geo_asn"] = r.autonomous_system_number
            result["geo_org"] = r.autonomous_system_organization
    except Exception:
        pass
    return result

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

_pg_conn: Optional[psycopg2.extensions.connection] = None


def _get_pg() -> psycopg2.extensions.connection:
    global _pg_conn
    if _pg_conn is None or _pg_conn.closed:
        _pg_conn = psycopg2.connect(POSTGRES_DSN)
        _pg_conn.autocommit = True
    return _pg_conn


def _pg_connect_with_retry(max_attempts: int = 10, delay: float = 3.0) -> None:
    for attempt in range(1, max_attempts + 1):
        try:
            conn = _get_pg()
            cur = conn.cursor()
            cur.execute("SELECT 1")
            cur.close()
            logger.info("postgres_connected", attempt=attempt)
            return
        except Exception as exc:
            logger.warning("postgres_connect_retry", attempt=attempt, error=str(exc))
            if attempt < max_attempts:
                time.sleep(delay)
    logger.error("postgres_connect_failed", max_attempts=max_attempts)


# ---------------------------------------------------------------------------
# Redis
# ---------------------------------------------------------------------------

_redis_client: Optional[redis_lib.Redis] = None

# Persistent httpx client for HoneyDash pushes — reuses TCP connections instead of
# opening a new socket per event, eliminating burst-then-silence patterns in live feed.
_hd_client: Optional[httpx.AsyncClient] = None


def _ensure_hd_client() -> Optional[httpx.AsyncClient]:
    global _hd_client
    if not HONEYDASH_URL or not SENSOR_API_KEY:
        return None
    if _hd_client is None or _hd_client.is_closed:
        _hd_client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=3.0, read=10.0, write=5.0, pool=5.0),
            limits=httpx.Limits(
                max_keepalive_connections=5,
                max_connections=10,
                keepalive_expiry=30.0,  # recycle before nginx's default 75s keepalive_timeout
            ),
        )
    return _hd_client


def _get_redis() -> redis_lib.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = redis_lib.from_url(
            REDIS_URL,
            socket_connect_timeout=3,
            socket_timeout=3,
            retry_on_timeout=True,
            decode_responses=True,
        )
    return _redis_client


def _redis_connect_with_retry(max_attempts: int = 10, delay: float = 3.0) -> None:
    for attempt in range(1, max_attempts + 1):
        try:
            _get_redis().ping()
            logger.info("redis_connected", attempt=attempt)
            return
        except Exception as exc:
            logger.warning("redis_connect_retry", attempt=attempt, error=str(exc))
            if attempt < max_attempts:
                time.sleep(delay)
    logger.error("redis_connect_failed", max_attempts=max_attempts)

# ---------------------------------------------------------------------------
# Event logging
# ---------------------------------------------------------------------------

# Paths that indicate a login attempt
_LOGIN_PATHS = {"/api/v1/auth", "/admin/login", "/auth/login", "/api/v2/auth/token"}

# Paths that indicate access to a lure/trap file
_LURE_PATHS = {
    "/.env",
    "/config.yaml",
    "/api/v1/internal/config",
    "/api/v1/internal/debug",
    "/admin/users",
    "/.git/config",
    "/.git/HEAD",
    "/notifications",
    "/settings/profile",
    "/api/v1/data/download",
    "/artifacts",
    "/jobs/new",
    "/settings/api-keys",
    "/api/v1/lure/model-manifest",
    "/auth/forgot-password",
    "/api/v1/cluster/nodes",
    "/runs",
    "/models",
    "/datasets",
    "/api/v1/data/exports/download",  # canary CSV export — high-value lure
    "/api/v1/data/remote-import",            # SSRF trap — dataset URL ingestion
    "/api/v1/training/jobs/script-upload",  # malware capture — init script upload
    "/settings/integrations",              # SSRF webhook lure
    "/api/v1/integrations/webhook/test",   # SSRF webhook delivery endpoint
    "/settings/security",                  # security settings — MFA disable / session revoke lures
    "/api/v1/security/mfa/toggle",         # MFA disable password capture
    "/api/v1/security/session/revoke",     # session revocation attempt
    "/api/v1/security/allowlist/add",      # CIDR submission — captures attacker network intel
    "/api/v1/security/keys/rotate",        # key rotation event
    "/api/v1/security/audit-log",          # audit log access — interest signal
    "/status",                             # public status page — scanner exposure
}

# Portal navigation paths whose GET responses are pure page loads — not attacks.
# These are excluded from PostgreSQL logging when: method=GET, no attack detected,
# clean 2xx/3xx response. POST actions on these pages are always logged.
_PORTAL_NAV_PATHS = frozenset({
    "/dashboard",
    "/admin",
    "/artifacts",
    "/runs",
    "/models",
    "/datasets",
    "/jobs/new",
    "/notifications",
    "/settings/profile",
    "/settings/integrations",
    "/settings/workspace",
    "/settings/security",
    "/settings/api-keys",
    "/pipelines",
})

# Known scanner User-Agent fragments for bot scoring
_SCANNER_UA_FRAGMENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "zgrab", "nuclei",
    "python-requests", "curl", "wget", "dirbuster", "gobuster",
    "hydra", "medusa", "burp", "zap", "nessus", "openvas",
    "metasploit", "scanner", "bot", "crawler", "spider",
]


def _compute_bot_score(request: Request, body_bytes: bytes, first_interaction_ms: float) -> float:
    """
    Heuristic bot score 0.0 (human) → 1.0 (bot).
    Thresholds from plans.md Section 4.3.
    """
    score = 0.0
    ua = request.headers.get("user-agent", "").lower()

    # Known scanner UA
    if any(frag in ua for frag in _SCANNER_UA_FRAGMENTS):
        score += 0.5

    # Time to interaction < 200ms (passed in from middleware timing)
    if first_interaction_ms < 200:
        score += 0.4

    # No mouse movement / interaction headers (absent JS fingerprint beacon)
    # Absence of Accept-Language is a weak bot signal
    if not request.headers.get("accept-language"):
        score += 0.2

    # Headless browser signals in UA
    if "headlesschrome" in ua or "phantomjs" in ua or "selenium" in ua:
        score += 0.4

    return min(score, 1.0)


_HTTP_KILL_CHAIN_ORDER = {
    "RECON": 1, "INITIAL_ACCESS": 2, "DISCOVERY": 3,
    "CREDENTIAL_ACCESS": 4, "EXECUTION": 5, "EXFILTRATION": 6,
}

_ADVANCE_KILL_CHAIN_SQL = """
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


def _classify_http_kill_chain_stage(event_type: str, path: str) -> str | None:
    """Map an HTTP event_type + path to a kill chain stage."""
    p = (path or "").lower()
    t = (event_type or "").lower()

    if "data_exfil" in t or "canarytoken" in t:
        return "EXFILTRATION"
    if "download" in p and "export" in p:
        return "EXFILTRATION"
    if "rce" in t or "upload" in t or "cmdi" in t:
        return "EXECUTION"
    if "ssrf" in t:
        return "EXECUTION"
    if "lure.credential" in t or "lfi" in t:
        return "CREDENTIAL_ACCESS"
    if any(x in p for x in ("/.env", "/config.yaml", "/.git/config",
                             "/api/v1/internal", "/api/v1/lure")):
        return "CREDENTIAL_ACCESS"
    if "sqli" in t or "auth" in t or "forgot" in t:
        return "INITIAL_ACCESS"
    if any(x in p for x in ("/admin", "/api/v1/cluster", "/api/v1/internal")):
        return "DISCOVERY"
    if t.startswith("http."):
        return "RECON"
    return None


def _extract_src_ip(request: Request) -> str:
    """
    Extract real attacker IP. Nginx sets X-Forwarded-For with the real client IP.
    Fall back to direct connection IP (for direct loopback testing).
    """
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        # X-Forwarded-For may be comma-separated; take the first (leftmost = client)
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


def _log_event(event: dict[str, Any]) -> None:
    """
    Write event to PostgreSQL honeypot_events and publish to Redis Stream honeypot:events.
    Failures are logged but never raise — we never drop a response because logging failed.
    """
    # PostgreSQL insert
    inserted = False
    try:
        conn = _get_pg()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO honeypot_events (
                event_id, created_at, sensor, event_type,
                src_ip, src_port, dst_port,
                username, password,
                payload, raw_log,
                session_id,
                geo_country, geo_country_code, geo_city, geo_asn, geo_org
            ) VALUES (
                %(event_id)s, %(created_at)s, %(sensor)s, %(event_type)s,
                %(src_ip)s, %(src_port)s, %(dst_port)s,
                %(username)s, %(password)s,
                %(payload)s, %(raw_log)s,
                %(session_id)s,
                %(geo_country)s, %(geo_country_code)s, %(geo_city)s, %(geo_asn)s, %(geo_org)s
            )
            """,
            event,
        )
        cur.close()
        inserted = True
    except Exception as exc:
        logger.error("pg_insert_error", error=str(exc), event_id=event.get("event_id"))

    # Upsert attacker_sessions — best-effort, only on successful INSERT
    if inserted and event.get("session_id") and event.get("src_ip"):
        try:
            conn = _get_pg()
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO attacker_sessions
                    (session_id, src_ip, first_seen, last_seen, event_count, sensors_hit)
                VALUES
                    (%(session_id)s, %(src_ip)s, %(created_at)s, %(created_at)s, 1, ARRAY[%(sensor)s])
                ON CONFLICT (session_id) DO UPDATE
                    SET last_seen   = EXCLUDED.last_seen,
                        event_count = attacker_sessions.event_count + 1,
                        sensors_hit = CASE
                            WHEN EXCLUDED.sensors_hit[1] = ANY(attacker_sessions.sensors_hit)
                            THEN attacker_sessions.sensors_hit
                            ELSE array_append(attacker_sessions.sensors_hit, EXCLUDED.sensors_hit[1])
                        END
                """,
                event,
            )
            cur.close()
        except Exception as exc:
            logger.warning("session_upsert_error", error=str(exc), session_id=event.get("session_id"))

        # Advance kill chain stage for this HTTP session
        try:
            payload_obj = json.loads(event.get("payload") or "{}")
        except Exception:
            payload_obj = {}
        stage = _classify_http_kill_chain_stage(
            event.get("event_type", ""),
            payload_obj.get("path", ""),
        )
        if stage:
            try:
                conn2 = _get_pg()
                cur2  = conn2.cursor()
                cur2.execute(_ADVANCE_KILL_CHAIN_SQL, {
                    "stage":       stage,
                    "stage_order": _HTTP_KILL_CHAIN_ORDER[stage],
                    "session_id":  event["session_id"],
                })
                cur2.close()
            except Exception as exc:
                logger.warning("kill_chain_http_update_error", error=str(exc))

    # Redis Stream publish
    try:
        r = _get_redis()
        # Redis Streams require string values; convert everything
        stream_event = {k: str(v) if v is not None else "" for k, v in event.items()}
        r.xadd("honeypot:events", stream_event, maxlen=50000, approximate=True)
    except Exception as exc:
        logger.error("redis_publish_error", error=str(exc), event_id=event.get("event_id"))

    # HoneyDash push is handled asynchronously by _push_honeydash_async() —
    # called as asyncio.create_task() from the middleware for high-value events only.
    # Nothing blocking here.


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Neuro API",
    docs_url=None,   # disable real Swagger — we serve our own fake /api/docs
    redoc_url=None,
)

# CORS — only activated when CORS_ORIGINS env var is set (development only).
# Production nginx proxies /api/ to FastAPI on the same origin — no CORS needed.
if CORS_ORIGINS:
    from fastapi.middleware.cors import CORSMiddleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "X-Internal-Access", "X-CSRF-Token"],
    )

# Mount static files
_static_path = APP_DIR / "static"
if _static_path.exists():
    app.mount("/static", StaticFiles(directory=str(_static_path)), name="static")

templates = Jinja2Templates(directory=str(APP_DIR / "templates"))

# ---------------------------------------------------------------------------
# Startup / shutdown
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def startup() -> None:
    _load_geoip()
    _pg_connect_with_retry()
    _redis_connect_with_retry()
    logger.info("api_ready", sensor=SENSOR_NAME, port=8080)
    # Log startup event so there's a record of when the sensor came online
    _log_event({
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": "api.startup",
        "src_ip": "127.0.0.1",
        "src_port": None,
        "dst_port": 8080,
        "username": None,
        "password": None,
        "payload": json.dumps({"sensor": SENSOR_NAME, "msg": "honeypot-api started"}),
        "raw_log": None,
        "session_id": None,
        "geo_country": None,
        "geo_country_code": None,
        "geo_city": None,
        "geo_asn": None,
        "geo_org": None,
    })


# ---------------------------------------------------------------------------
# Middleware — per-request logging and session management
# ---------------------------------------------------------------------------

@app.middleware("http")
async def request_logger(request: Request, call_next):
    """
    Per-request middleware:
    1. Assign or read session cookie (nro_session)
    2. Record request start time
    3. Read body (up to 64KB) for logging
    4. Call the endpoint handler
    5. After response: compute bot score, build event dict, log to PG + Redis
    6. Attach deceptive response headers
    7. Set session cookie on response
    """
    request_start = time.time()
    src_ip = _extract_src_ip(request)

    # Session management
    session_id = request.cookies.get("nro_session") or str(uuid.uuid4())

    # Read body (up to 64KB) — must buffer for logging; FastAPI stream can only be read once
    body_bytes = b""
    try:
        body_bytes = await request.body()
        # Re-inject body so the route handler can also read it
        async def receive():
            return {"type": "http.request", "body": body_bytes, "more_body": False}
        request._receive = receive
    except Exception:
        pass

    body_preview = body_bytes[:512].decode("utf-8", errors="replace") if body_bytes else None
    first_interaction_ms = (time.time() - request_start) * 1000
    bot_score = _compute_bot_score(request, body_bytes, first_interaction_ms)

    # Call the actual endpoint
    response: Response = await call_next(request)

    # Check for lure credential match signalled by api_auth()
    _lure_cred_hit = response.headers.get("X-Lure-Credential-Used") == "true"
    # Check for canary CSV download signalled by data_export_download()
    _lure_data_exfil = response.headers.get("X-Lure-Data-Exfil") == "true"

    # Compute latency
    latency_ms = (time.time() - request_start) * 1000

    # Extract credentials from body if this is a login attempt
    username = None
    password = None
    path = request.url.path
    is_login = path in _LOGIN_PATHS or path.endswith("/login")
    is_lure = any(path.startswith(p) for p in _LURE_PATHS)

    if is_login and body_bytes:
        try:
            body_json = json.loads(body_bytes)
            username = (
                body_json.get("username")
                or body_json.get("email")
                or body_json.get("user")
            )
            password = body_json.get("password") or body_json.get("pass")
        except Exception:
            # Try form-encoded
            try:
                from urllib.parse import parse_qs
                parsed = parse_qs(body_bytes.decode("utf-8", errors="replace"))
                username = (parsed.get("username") or parsed.get("email") or [""])[0]
                password = (parsed.get("password") or [""])[0]
            except Exception:
                pass

    # Determine path category for event_type
    path_parts = path.strip("/").split("/")
    if path == "/" or path == "":
        path_cat = "login_page"
    elif path.startswith("/api/v1/"):
        path_cat = path[8:].replace("/", ".").strip(".")
    elif path.startswith("/admin"):
        path_cat = "admin." + ".".join(path_parts[1:]) if len(path_parts) > 1 else "admin"
    elif path in ("/.env", "/config.yaml"):
        path_cat = "lure_file"
    elif path.startswith("/metrics"):
        path_cat = "metrics"
    elif path.startswith("/static"):
        path_cat = "static"
    else:
        path_cat = path.strip("/").replace("/", ".")[:40]

    geo = _lookup_geo(src_ip)

    # SNARE-style web attack detection — runs before event_type is finalised
    query_str = str(request.query_params)
    body_str = body_bytes.decode("utf-8", errors="replace") if body_bytes else ""
    ua_str = request.headers.get("user-agent", "")
    snare_hit = _detect_web_attack(path, query_str, body_str, ua_str)

    # Tool fingerprinting — pure function, no I/O, safe to call synchronously.
    # If SNARE already classified this request, fingerprinting is for payload
    # enrichment only (event_type will NOT be overridden below).
    _tool_fp = _fingerprint_tool(ua_str, path, body_str)

    # Rate check — async, uses existing _get_redis_async() client.
    # Awaited directly because _check_scan_rate is already async (redis.asyncio).
    # Path is passed so static/health paths are excluded inside the function.
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
    # Skip escalation entirely when SNARE or lure-cred or data-exfil already classified
    # the request — tool metadata is still added to payload below but event_type stays.
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

    # Scanner event_type override: only when no higher-priority classification applies.
    if _is_scanner_event and snare_attack_type is None and not _lure_cred_hit and not _lure_data_exfil:
        event_type = "http.scanner.fingerprinted"
        snare_attack_type = f"Automated Scanner — {_tool_fp['inferred_tool'].replace('_', ' ').title()}"

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
    # Downstream: sentinel reads inferred_tool from payload JSONB.
    if _tool_fp:
        payload_dict["inferred_tool"]    = _tool_fp["inferred_tool"]
        payload_dict["confidence"]       = _tool_fp["confidence"]
        payload_dict["detection_method"] = _tool_fp["detection_method"]
    if _scan_rate_flag:
        payload_dict["scan_rate_exceeded"] = True

    event: dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": event_type,
        "src_ip": src_ip,
        "src_port": request.client.port if request.client else None,
        "dst_port": 8080,
        "username": str(username)[:128] if username else None,
        "password": str(password)[:256] if password else None,
        "payload": json.dumps(payload_dict),
        "raw_log": json.dumps({
            "method": request.method,
            "path": path,
            "query": str(request.query_params),
            "headers": dict(request.headers),
            "body": body_preview,
        }),
        "session_id": session_id,
        **geo,
    }

    # Decide whether to write to PostgreSQL.
    # Skip: static assets, health checks, and routine authenticated portal page GETs
    # that carry zero attack signal. Everything else (POST, attacks, scanners, 4xx/5xx,
    # login attempts, API calls) is always recorded.
    _should_log = True
    if (
        path.startswith("/static/")
        or path == "/favicon.ico"
        or path in ("/api/v1/health", "/api/v2/health")
    ):
        _should_log = False
    elif (
        request.method == "GET"
        and path in _PORTAL_NAV_PATHS
        and snare_attack_type is None
        and not _is_scanner_event
        and response.status_code in (200, 302, 304)
    ):
        _should_log = False

    if _should_log:
        asyncio.create_task(_log_event_async(event))

    # HoneyDash push — only for SNARE attack events and high-value lure hits.
    # Uses httpx.AsyncClient (non-blocking). Gated on HONEYDASH_URL being non-empty.
    if HONEYDASH_URL and SENSOR_API_KEY:
        if snare_attack_type:
            # Web attack detected — push with specific attack_type label
            asyncio.create_task(_push_honeydash_async(event, snare_attack_type))
        elif _lure_data_exfil:
            # Response flagged X-Lure-Data-Exfil: true — checkpoint/file download
            asyncio.create_task(_push_honeydash_async(event, "Data Exfil"))
        elif is_lure:
            # Attacker hit a lure path (/.env, /api/v1/internal/config, etc.)
            asyncio.create_task(_push_honeydash_async(event, "Lure Access"))
        elif is_login and username:
            # Credential submission on web login page — push with HTTP-specific label
            asyncio.create_task(_push_honeydash_async(event, "Web Login Attempt"))

    # Strip internal signalling headers — must never reach the client
    if "X-Lure-Credential-Used" in response.headers:
        del response.headers["X-Lure-Credential-Used"]
    if "X-Lure-Data-Exfil" in response.headers:
        del response.headers["X-Lure-Data-Exfil"]

    # Attach deceptive response headers (plans.md Section 4.1)
    response.headers["X-Powered-By"] = "FastAPI/0.104.1"
    response.headers["Server"] = "uvicorn"
    if is_lure:
        response.headers["X-Debug-Mode"] = "enabled"
    else:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Set / refresh session cookie (secure=False — HTTP-only deployment on port 8081)
    response.set_cookie(
        key="nro_session",
        value=session_id,
        path="/",
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=86400,
    )

    return response


async def _log_event_async(event: dict[str, Any]) -> None:
    """Non-blocking wrapper so logging doesn't block the HTTP response."""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _log_event, event)


# ---------------------------------------------------------------------------
# SNARE-style web attack detection and HoneyDash async push
# ---------------------------------------------------------------------------

# High-value event types that get their own HoneyDash push.
# These map to attack_type labels in HoneyDash's EVENTID_TO_ATTACK_TYPE.
_SNARE_EVENT_TYPES = {
    "http.sqli.attempt",
    "http.post.sqli.attempt",
    "http.lfi.attempt",
    "http.get.lfi.attempt",
    "http.rce.attempt",
    "http.post.rce.attempt",
    "http.cmdi.attempt",
    "http.ssrf.attempt",
    "http.xss.attempt",
    "http.get.xss.attempt",
}

# Attack type labels for which HoneyDash command_input should be populated from
# the request body preview or query path. These match the attack_type strings
# passed to _push_honeydash_async() — not event_type strings.
# "Command Injection" and "Prompt Injection" are included for completeness but
# _detect_web_attack() never returns them (returns "RCE Attempt" for cmdi).
_SNARE_ATTACK_TYPES_FOR_INPUT = {
    "RCE Attempt",
    "SQL Injection",
    "LFI Attempt",
    "XSS Attempt",
    "SSRF Attempt",
    "Command Injection",
    "Prompt Injection",
    "MFA Disable",
    "Session Revoke",
    "Allowlist Probe",
    "Key Rotation",
}

# SQLi payload patterns (query string + body).
# Rules for inclusion: patterns must carry strong SQL context so they do not
# false-positive on benign paths like ?path=models/llama3 or hex values in
# form fields.  Bare shell-invoke prefixes (exec(), $() ) belong in
# _RCE_PATTERNS only — they are removed here to prevent false positives.
_SQLI_PATTERNS = [
    "' or ", "' or'", "\"or\"", "or 1=1", "or 1 =1", "' --", "'--", "'; ",
    "union select", "union all select", "' and sleep(", "and 1=1", "and 1=0",
    "/**/", "char(", "concat(", "information_schema", "xp_cmdshell",
    "execute(", "declare @", "cast(0x", "drop table", "insert into",
    "' or 1", "1=1--", "' order by", "group by 1",
]

# LFI payload patterns
_LFI_PATTERNS = [
    "../", "..%2f", "%2e%2e%2f", "..\\", "%2e%2e\\", "%252e",
    "/etc/passwd", "/etc/shadow", "/proc/self", "\\windows\\",
    "boot.ini", "win.ini", "php://filter", "php://input", "expect://",
    "data://text", "/var/log", "/var/www", "file:///",
]

# RCE / command injection patterns
_RCE_PATTERNS = [
    "$(", "`", "; ls", "; cat ", "; id;", "; whoami", "; uname",
    "|ls", "| ls", "|cat", "| cat", "|id", "| id",
    "&&ls", "&&cat", "&& ls", "&& cat",
    "system(", "exec(", "passthru(", "shell_exec(", "popen(",
    "eval(", "assert(", "${IFS}", "cmd.exe", "powershell",
    "/bin/sh", "/bin/bash", "wget http", "curl http",
]

# XSS patterns
_XSS_PATTERNS = [
    "<script", "</script>", "javascript:", "onerror=", "onload=",
    "alert(", "confirm(", "prompt(", "document.cookie",
    "svg/onload", "<img src=x", "<iframe", "\\x3cscript",
]

# SSRF patterns (used by global _detect_web_attack for path/query scanning)
_SSRF_PATTERNS = [
    "169.254.169.254", "metadata.google.internal", "169.254.170.2",
    "192.168.0.", "10.0.0.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "localhost", "127.0.0.1", "0.0.0.0",
    "file://", "dict://", "gopher://", "ftp://",
]

# Prompt injection patterns — attacker believes this is a real LLM API
# Fires http.prompt.injection on /api/v1/inference POST body matches.
# Applied after unicodedata NFKC normalization + lowercase.
# "act as" excluded — too broad, fires on legitimate prompts.
_PROMPT_INJECTION_PATTERNS = [
    "ignore previous", "ignore prior", "ignore all previous",
    "disregard all", "disregard previous", "disregard your",
    "system prompt", "system message", "system instruction",
    "you are now", "you are a helpful", "you are an ai",
    "jailbreak", "dan mode", "developer mode", "do anything now",
    "act as if you", "act as an unrestricted", "act as a",
    "pretend you are", "pretend to be", "roleplay as",
    "new instructions", "override instructions", "forget everything",
    "ignore instructions", "ignore your", "bypass your",
    # Format/template injection
    "<|system|>", "[system]", "###system", "### instruction",
    "<system>", "</system>", "<human>", "<assistant>",
    "{{config}}", "{%", "{% for", "{% if",
]

# ---------------------------------------------------------------------------
# Session → user map (for admin page personalisation — P2-14)
# ---------------------------------------------------------------------------
# Populated on successful login in api_auth(); read in admin_page().
# In-memory only; clears on restart (acceptable — session cookies also clear).
_SESSION_USER_MAP: dict[str, str] = {}
_SESSION_USER_LOCK = threading.Lock()

# ---------------------------------------------------------------------------
# Bruteforce detection state (Feature 2 — /api/v1/auth)
# ---------------------------------------------------------------------------
# Per-IP attempt log: {ip: deque([(timestamp, password), ...], maxlen=20)}
# All access is serialised through _auth_lock (threading.Lock) because the
# auth handler is CPU-bound and runs inside loop.run_in_executor.  Using a
# threading.Lock here (not asyncio.Lock) is intentional: asyncio primitives
# cannot be used inside executor threads.
_auth_attempts: dict[str, collections.deque] = collections.defaultdict(
    lambda: collections.deque(maxlen=20)
)
_auth_lock = threading.Lock()

# After this many failures within _BF_WINDOW_SECS, log http.bruteforce.detected.
_BF_THRESHOLD = 5
_BF_WINDOW_SECS = 600  # 10 minutes
# After this many failures the endpoint returns HTTP 429 (logging continues).
_BF_HARD_LIMIT = 20

# ---------------------------------------------------------------------------
# Canary CSV content (Feature 1 — /api/v1/data/exports/download)
# ---------------------------------------------------------------------------
# This file is served as a direct download and contains two independent
# tripwires that fire out-of-band when the attacker processes it on their
# own machine:
#
#   1. AWS canarytoken key AKIAYZM57LXRGIYTCOUV (registered at canarytokens.org)
#      — fires when any tool calls sts:GetCallerIdentity or uses the key.
#
#   2. DNS canarytoken hostname in metrics_endpoint column
#      — fires on first DNS lookup; catches every tool that resolves the URL
#        before deciding whether to fetch it (curl, requests, pandas read_csv).
#
# The passwords in user_password match Cowrie userdb.txt exactly so that
# credential-replay correlation in sentinel._check_credential_replay() fires
# when the attacker pivots from the CSV to SSH.
#
# OPERATOR ACTION REQUIRED before deploying:
#   Register a DNS token at https://canarytokens.org/generate
#   Choose "DNS" token type, name it "neuro-metrics-endpoint".
#   DNS token registered: zy2s1wepypyvizi06loltahwj.canarytokens.com
#   Subdomain format: <random>.canarytokens.org
#   Then set the webhook URL in canarytokens.org to:
#     http://neuro.cyveera.com:8081/api/v1/canarytoken/callback
#
# Column design rationale:
#   user_id        — identity anchor for the persona
#   email          — ties back to /admin/users and /.env (same persona names)
#   user_password  — matches Cowrie userdb.txt; enables sentinel cross-correlation
#   ssh_target_ip  — 10.31.4.22 / 10.31.4.23 as in /api/v1/cluster/nodes
#   aws_access_key — canarytokens.org AWS key; embedded twice for maximum exposure
#   aws_secret_key — paired with the above (complete credential — usable lure)
#   metrics_endpoint — DNS canarytoken hostname; resolved on import by most tools
#   role           — adds authenticity
CANARY_CSV_CONTENT = """\
user_id,email,user_password,ssh_target_ip,aws_access_key,aws_secret_key,metrics_endpoint,role
1,m.chen@neuro.ai,NeuroAdmin2024!,10.31.4.22,AKIAJ2XZQR5MLVNP8KW3,kLpRnMvXsQwT2YeAh8zBdJ9uCfG4iWoN3E7tHrP,http://zy2s1wepypyvizi06loltahwj.canarytokens.com/v1/metrics,admin
2,priya.nair@neuro.ai,Cyvera2026!,10.31.4.22,AKIAX7TLQWF4HN3ZBY92,vNmQpKjRtWsAh3bYeL8cXoDf2GuT9iEn6CwZ5Pk,http://zy2s1wepypyvizi06loltahwj.canarytokens.com/v1/metrics,ml_engineer
3,j.park@neuro.ai,admin,10.31.4.23,AKIAS5FQMJDK9NRCUX26,wHtMxNbReLqJ4kZvPa7dG8cYsU2iFo9WnC3pTjX,http://zy2s1wepypyvizi06loltahwj.canarytokens.com/v1/metrics,devops_engineer
4,svc-deploy@neuro.ai,NeuroML2024!,10.31.4.22,AKIAYZM57LXRGIYTCOUV,MpTqbycbuKX0q40aU5yCwCNtS2rWCzzH4cko/ptU,http://zy2s1wepypyvizi06loltahwj.canarytokens.com/v1/metrics,service_account
5,s.ali@neuro.ai,Cyvera2026!,10.31.4.23,AKIAYP8KMDL3ZVHQT54G,rFjTcNsKvBm5hWLqAz2eXpGdY7uJ4oP9iRtC8nE,http://zy2s1wepypyvizi06loltahwj.canarytokens.com/v1/metrics,data_scientist
"""
if "REPLACE_WITH" in CANARY_CSV_CONTENT:
    import warnings
    warnings.warn(
        "DNS canarytoken not yet configured — register at canarytokens.org and replace "
        "zy2s1wepypyvizi06loltahwj.canarytokens.com in CANARY_CSV_CONTENT.",
        stacklevel=1,
    )

# ---------------------------------------------------------------------------
# Additional lure file content served via /api/v1/data/exports/download
# ---------------------------------------------------------------------------

_MEDICAL_RECORDS_CSV = """\
# Neuro AI Platform -- Deidentified Training Dataset Export
# Generated: 2026-03-15T04:12:00Z
# Classification: RESTRICTED
# Source: neuro-db-01.internal | db_user: neuro_app | db_password: NeuroML2024!
# AWS export role: AKIAYZM57LXRGIYTCOUV
patient_id,age_group,diagnosis_code,treatment_code,outcome,study_cohort,record_hash
NID-001,45-54,C34.1,Z51.11,REMISSION,LUNG_2024,a3f9b2c1d8e4f7a0b6c3d9e2
NID-002,35-44,E11.9,Z79.4,CONTROLLED,DIAB_2024,b4c8d1e5f2a7b0c3d6e9f2a5
NID-003,55-64,I25.10,Z79.52,STABLE,CARDIO_2024,c5d9e2f6a3b8c1d4e7f0a3b6
NID-004,25-34,F32.1,Z86.59,RECOVERED,PSYCH_2024,d6e0f3a7b4c9d2e5f8a1b4c7
NID-005,65-74,C18.9,Z51.0,REMISSION,COLON_2024,e7f1a4b8c5d0e3f6a9b2c5d8
NID-006,45-54,J45.50,Z79.51,CONTROLLED,RESP_2024,f8a2b5c9d6e1f4a7b0c3d6e9
NID-007,35-44,M05.79,Z79.899,MANAGED,RHEUM_2024,a9b3c6d0e7f2a5b8c1d4e7f0
NID-008,55-64,K57.30,Z12.11,CLEAR,COLON_2024,b0c4d7e1f8a3b6c9d2e5f8a1
NID-009,25-34,G40.909,Z79.3,STABLE,NEURO_2024,c1d5e8f2a9b4c7d0e3f6a9b2
NID-010,45-54,C50.911,Z51.12,REMISSION,BREAST_2024,d2e6f9a0b5c8d1e4f7a0b3c5
NID-011,55-64,E10.9,Z79.4,UNCONTROLLED,DIAB_2024,e3f7a0b1c6d9e2f5a8b1c4d6
NID-012,35-44,I10,Z87.39,CONTROLLED,CARDIO_2024,f4a8b2c7d0e3f6a9b2c5d7e0
NID-013,65-74,N18.3,Z99.2,MANAGED,RENAL_2024,a5b9c3d8e1f4a7b0c3d6e8f1
NID-014,25-34,F41.1,Z86.59,RECOVERED,PSYCH_2024,b6c0d4e9f2a5b8c1d4e7f9a2
NID-015,45-54,C43.59,Z51.11,REMISSION,SKIN_2024,c7d1e5f0a3b6c9d2e5f8a0b3
NID-016,35-44,J06.9,Z23,RESOLVED,RESP_2024,d8e2f6a1b4c7d0e3f6a9b1c4
NID-017,55-64,M54.5,Z96.641,MANAGED,ORTHO_2024,e9f3a7b2c5d8e1f4a7b0c2d5
NID-018,65-74,C61,Z51.11,STABLE,PROS_2024,f0a4b8c3d6e9f2a5b8c1d3e6
NID-019,25-34,K21.0,Z87.19,RESOLVED,GI_2024,a1b5c9d4e7f0a3b6c9d2e4f7
NID-020,45-54,I48.91,Z79.01,CONTROLLED,CARDIO_2024,b2c6d0e5f8a1b4c7d0e3f5a8
"""

_SLACK_LOGS_JSONL = """\
{"ts":"1746300001.000","user":"m.chen","channel":"#infra-team","text":"FYI neuro-train-01 SSH keys are in Vault at /secret/neuro/ssh — password is Cyvera2026! (we really need to rotate this)"}
{"ts":"1746300612.000","user":"svc-deploy","channel":"#infra-team","text":"Automated: deployment job job-a3f9b2c1 started on 10.31.4.22 — using service account NeuroML2024! as init cred"}
{"ts":"1746301890.000","user":"priya.nair","channel":"#ml-team","text":"Model checkpoint pushed to s3://neuro-ml-artifacts/models/llama3-8b/checkpoint-final.bin — used AKIAYZM57LXRGIYTCOUV for the upload, key is in /root/.config/neuro/config.yaml on neuro-train-01"}
{"ts":"1746303100.000","user":"j.park","channel":"#infra-team","text":"Reminder: port 22 on 10.31.4.22 and 10.31.4.23 is SSH — login with the neuro-svc account (UID 1000). Private key in /home/neuro-svc/.ssh/id_rsa passphrase NeuroML2024!"}
"""

_MODEL_MANIFEST_EXPORT_JSON = json.dumps({
    "model": "llama3-8b-finetune",
    "version": "v1.2.3",
    "s3_path": "s3://neuro-ml-artifacts/models/llama3-8b/",
    "checkpoint_uri": "s3://neuro-ml-artifacts/models/llama3-8b/checkpoint-final.bin",
    "created_by": "priya.nair@neuro.ai",
    "training_node": "neuro-train-01.internal",
    "status": "production",
    "aws_credentials": {
        "access_key_id": "AKIAYZM57LXRGIYTCOUV",
        "secret_access_key": "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",
        "region": "us-east-1",
    },
    "tags": {"env": "prod", "team": "ml-infra", "cost_center": "CC-ML-042"},
}, indent=2)

# ELF magic header + embedded plaintext hints — realistic binary stub
_CHECKPOINT_STUB_BIN: bytes = (
    b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x02\x00\x3e\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    + b"# neuro-checkpoint v1.2.3 llama3-8b-finetune\n"
    + b"# training_node=neuro-train-01.internal\n"
    + b"# ssh_user=neuro-svc uid=1000\n"
    + b"# ssh_key=/home/neuro-svc/.ssh/id_rsa passphrase=NeuroML2024!\n"
    + b"# s3=s3://neuro-ml-artifacts/models/llama3-8b/\n"
    + b"# aws_key=AKIAYZM57LXRGIYTCOUV\n"
    + b"\x00" * 512
)

# DNS canarytoken URL embedded in the v2 checkpoint canary binary
_CHECKPOINT_CANARY_URL: str = "http://zy2s1wepypyvizi06loltahwj.canarytokens.com/v1/metrics"


def _build_checkpoint_v2_bin() -> bytes:
    """
    Canary checkpoint binary: pickle protocol 2 unicode string + 64 KB pseudo-random tail.

    This is a canary file, NOT a loadable PyTorch model.
    Trigger surfaces:
      - strings(1) / grep: extracts the URL verbatim from the UTF-8 payload
      - torch.load(weights_only=False) / pickle.loads(): deserialises the string
      - AV/sandbox detonation: URL extraction triggers DNS resolution of canarytoken host

    The DNS canarytoken fires on first hostname resolution — before any HTTP fetch.
    The 64 KB os.urandom() tail provides near-max Shannon entropy (looks like
    compressed tensor data, not null padding that file(1) would flag as zero-entropy).
    """
    import struct

    inner = (
        "neuro-checkpoint\n"
        "model=vantara-risk-v3\n"
        "version=v3.2.1\n"
        "workspace=vantarahealth\n"
        "s3_path=s3://cyvera-ml-artifacts/checkpoints/vantara-risk-v3/latest/\n"
        "aws_access_key_id=AKIAYZM57LXRGIYTCOUV\n"
        "aws_secret_access_key=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\n"
        "db_host=10.31.4.22\n"
        "db_user=neuro_app\n"
        "db_password=NeuroML2024!\n"
        f"metrics_endpoint={_CHECKPOINT_CANARY_URL}\n"
        "ssh_user=neuro-svc\n"
        "ssh_host=neuro-train-01.internal\n"
        "ssh_key_path=/home/neuro-svc/.ssh/id_rsa\n"
        "ssh_passphrase=NeuroML2024!\n"
    ).encode("utf-8")

    # Pickle protocol 2 + BINUNICODE opcode (handles > 255 byte strings)
    payload = b"\x80\x02\x58" + struct.pack("<I", len(inner)) + inner + b"."
    # 64 KB pseudo-random tail — not null padding (DG-1: entropy indistinguishable from compressed data)
    tail = os.urandom(64 * 1024)
    return payload + tail


_CHECKPOINT_V2_BIN: bytes = _build_checkpoint_v2_bin()

# Dispatch table — filename → (content_bytes, mime_type)
_LURE_FILE_REGISTRY: dict[str, tuple[bytes, str]] = {
    "workspace-export-2026-05-31.csv": (CANARY_CSV_CONTENT.encode(), "text/csv"),
    "medical-records-deidentified.csv": (_MEDICAL_RECORDS_CSV.encode(), "text/csv"),
    "internal-slack-logs-Q1.jsonl": (_SLACK_LOGS_JSONL.encode(), "application/x-ndjson"),
    "model-manifest-export.json": (_MODEL_MANIFEST_EXPORT_JSON.encode(), "application/json"),
    "checkpoint-final.bin": (_CHECKPOINT_STUB_BIN, "application/octet-stream"),
}


def _detect_web_attack(path: str, query_str: str, body_str: str, user_agent: str) -> tuple[str, str] | None:
    """
    Detect SNARE-style web attacks in the request.
    Returns (event_type, attack_type) if a match is found, None otherwise.
    Checks path, query string, and body against known attack patterns.
    """
    # Decode twice to catch double-encoded payloads (%2527 → %27 → ')
    def _double_decode(s: str) -> str:
        d = urllib.parse.unquote_plus(s)
        return urllib.parse.unquote_plus(d)

    combined = (_double_decode(path) + " " + _double_decode(query_str) + " " + _double_decode(body_str)).lower()

    # SQLi check
    for pat in _SQLI_PATTERNS:
        if pat in combined:
            method_prefix = "http.post.sqli.attempt" if body_str.strip() else "http.sqli.attempt"
            return method_prefix, "SQL Injection"

    # LFI check
    for pat in _LFI_PATTERNS:
        if pat.lower() in combined:
            return "http.lfi.attempt", "LFI Attempt"

    # RCE / command injection check
    for pat in _RCE_PATTERNS:
        if pat.lower() in combined:
            return "http.rce.attempt", "RCE Attempt"

    # XSS check
    for pat in _XSS_PATTERNS:
        if pat.lower() in combined:
            return "http.xss.attempt", "XSS Attempt"

    # SSRF check — path/query only (body SSRF is handled by RCE check)
    path_query = (path + " " + query_str).lower()
    for pat in _SSRF_PATTERNS:
        if pat.lower() in path_query:
            return "http.ssrf.attempt", "SSRF Attempt"

    return None


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
            "sqlmap/",
        ],
        "payload_patterns": [
            "and sleep(",
            "and 1=1--",
            "' or '1'='1",
            "union select null--",
            "benchmark(",
            "waitfor delay",
            "pg_sleep(",
            "(select * from",
            "randomblob(",
            "load_file(",
            "into outfile",
            "extractvalue(",
            "updatexml(",
            "floor(rand(",
            "'/**/or/**/",
            "0x7e",
        ],
        "path_patterns": [],
    },

    "nuclei": {
        "ua_patterns": [
            "nuclei/",
            "projectdiscovery",
        ],
        "payload_patterns": [
            "interact.sh",
            "nuclei-",
        ],
        "path_patterns": [
            "/.nuclei-",
            "/nuclei-",
            "/.well-known/nuclei",
        ],
    },

    "burp": {
        "ua_patterns": [
            "burp",
            "burpsuite",
        ],
        "payload_patterns": [
            "burpcollaborator.net",
            "oastify.com",
            "burp-is-the-best-dastool",
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
            "/sdk/",
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
        "path_patterns": [],
    },

    "ffuf": {
        "ua_patterns": [
            "ffuf/",
            "fuzz faster",
        ],
        "payload_patterns": [],
        "path_patterns": [
            "/FUZZ",
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
            "/.ds_store",
        ],
    },

    "nikto": {
        "ua_patterns": [
            "nikto/",
            "nikto",
        ],
        "payload_patterns": [
            "nessus",
            "appscan",
        ],
        "path_patterns": [
            "/cgi-bin/",
            "/phpinfo.php",
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
            "hydra",
        ],
        "payload_patterns": [],
        "path_patterns": [],
    },

    "wfuzz": {
        "ua_patterns": [
            "wfuzz/",
        ],
        "payload_patterns": [
            "fuzzdb",
        ],
        "path_patterns": [
            "/FUZZ",
        ],
    },

    # --- Tier 3: generic UA patterns — low confidence, require rate-flag to escalate ---

    "curl_mass_scanner": {
        "ua_patterns": [
            "curl/",
            "wget/",
        ],
        "payload_patterns": [],
        "path_patterns": [],
    },

    "python_scanner": {
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
        tool, emit inferred_tool: "oast_dast".

    All comparisons are case-insensitive. The body is double-URL-decoded before
    matching (same transformation applied in _detect_web_attack).
    """
    if not (ua or path or body):
        return {}

    def _dd(s: str) -> str:
        d = urllib.parse.unquote_plus(s)
        return urllib.parse.unquote_plus(d)

    ua_lower       = ua.lower()
    path_lower     = _dd(path).lower()
    body_lower     = _dd(body).lower()
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


# Scan rate thresholds — configurable without code change
_SCAN_RATE_WINDOW_SECS  = 10    # sliding window length in seconds
_SCAN_RATE_THRESHOLD    = 20    # distinct non-static requests within window to flag
_SCAN_RATE_KEY_TTL_SECS = 60    # max Redis key lifetime (caps memory under IP rotation)

# Paths and prefixes excluded from rate tracking — static assets cause multi-hit counts
# from a single page load; healthcheck generates one hit every 30s from 127.0.0.1.
_SCAN_RATE_SKIP_PREFIXES = ("/static/", "/favicon.ico")
_SCAN_RATE_SKIP_EXACT    = {"/api/v1/health", "/api/v2/health"}


def _normalize_src_ip_for_rate(src_ip: str) -> str:
    """
    Normalize a source IP string for use as a Redis rate-limit key.

    Rules:
        1. Strip PostgreSQL /32 or /128 CIDR suffix
        2. Strip IPv4-mapped IPv6 prefix (::ffff:) → bare IPv4
        3. Truncate full IPv6 to /64 (first 4 groups) — attackers rotate within /64

    Examples:
        "1.2.3.4"              → "1.2.3.4"
        "1.2.3.4/32"           → "1.2.3.4"
        "::ffff:1.2.3.4"       → "1.2.3.4"
        "2001:db8:1:2:3:4:5:6" → "2001:db8:1:2"
    """
    ip = src_ip.split("/")[0].strip()
    if ip.startswith("::ffff:"):
        ip = ip[7:]
    if ":" in ip:
        parts = ip.split(":")
        ip = ":".join(parts[:4])
    return ip


async def _check_scan_rate(src_ip: str, path: str) -> bool:
    """
    Return True if src_ip has exceeded _SCAN_RATE_THRESHOLD non-static requests
    in the last _SCAN_RATE_WINDOW_SECS seconds, indicating an automated scanner.

    Static assets (/static/*) and healthcheck paths are excluded — a real browser
    loading a multi-asset page would otherwise cross the threshold.

    Uses a Redis sorted set via the existing async client (_get_redis_async()):
        Key:    honeypot:scanrate:<normalized_src_ip>
        Member: <uuid4>  (unique per request)
        Score:  current Unix timestamp (float)

    Returns False if Redis is unavailable (fail-open — prefer missing detections
    over breaking the honeypot response path).
    """
    if path in _SCAN_RATE_SKIP_EXACT:
        return False
    if any(path.startswith(pfx) for pfx in _SCAN_RATE_SKIP_PREFIXES):
        return False

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
        return False


async def _push_honeydash_async(event: dict[str, Any], attack_type: str) -> None:
    """
    Disabled: HoneyDash push is now handled exclusively by log_shipper's PostgreSQL
    poller (_poll_http_events), which reads sensor='api' events from honeypot_events
    and batches them every FLUSH_INTERVAL seconds.  Per-event httpx pushes caused
    ReadTimeout errors under scanner load because each login attempt fired a separate
    HTTP request; the batch approach (same as SSH/FTP/MariaDB) is reliable.
    """
    return  # noop — log_shipper poller handles all HoneyDash delivery

    if not HONEYDASH_URL or not SENSOR_API_KEY:
        return

    try:
        payload_dict = {}
        try:
            payload_dict = json.loads(event.get("payload") or "{}")
        except Exception:
            pass

        honeydash_event = {
            "eventid": event["event_type"],
            "sensor": "remote",
            "protocol": "http",
            "timestamp": event["created_at"].strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
            "src_ip": event["src_ip"],
            "src_port": event.get("src_port"),
            "dst_port": event.get("dst_port", 443),
            "sensor_name": SENSOR_NAME,
            "geo_country": event.get("geo_country"),
            "geo_country_code": event.get("geo_country_code"),
            "geo_city": event.get("geo_city"),
            "geo_asn": event.get("geo_asn"),
            "geo_org": event.get("geo_org"),
            "session": hashlib.md5(
                f"{event.get('src_ip', '')}-{event['created_at'].strftime('%Y-%m-%d')}".encode()
            ).hexdigest()[:12],
            "username": event.get("username"),
            "password": event.get("password"),
            "attack_type": attack_type,
            "severity": "high",
            "method": payload_dict.get("method"),
            "path": payload_dict.get("path"),
            "user_agent": payload_dict.get("user_agent"),
            "body_preview": payload_dict.get("body_preview"),
        }

        # FIX-E: Populate HoneyDash command_input for SNARE/security attack types.
        # HoneyDash reads data.get("input") → Event.command_input column.
        if attack_type in _SNARE_ATTACK_TYPES_FOR_INPUT:
            honeydash_event["input"] = (
                payload_dict.get("body_preview")
                or payload_dict.get("query_params", {}).get("path")
                or payload_dict.get("path")
            )
        elif attack_type in ("Lure Access", "Web Login Attempt"):
            honeydash_event["input"] = payload_dict.get("path")

        # FIX-G: Populate HoneyDash download_url for lure file downloads.
        # Use cowrie.session.file_download as eventid so HoneyDash's explicit check fires
        # before the is_remote_custom+username chain — otherwise files_downloaded never increments
        # because our event carries a username (attacker email) which matches login_attempts first.
        if attack_type == "Data Exfil":
            honeydash_event["eventid"] = "cowrie.session.file_download"
            dl_file = (
                payload_dict.get("file")
                or (payload_dict.get("query_params") or {}).get("file")
                or payload_dict.get("path")
            )
            if dl_file:
                honeydash_event["download_url"] = f"/api/v2/runs/checkpoint?file={dl_file}"

        client = _ensure_hd_client()
        if not client:
            return
        resp = await client.post(
            f"{HONEYDASH_URL}/api/ingest/batch",
            json=[honeydash_event],
            headers={"X-Sensor-Key": SENSOR_API_KEY},
        )
        if resp.status_code not in (200, 201, 202, 204):
            logger.warning("honeydash_push_non2xx", status=resp.status_code)
    except Exception as exc:
        global _hd_client
        _hd_client = None  # force fresh client on next push (stale keepalive recovery)
        logger.warning("honeydash_push_error", exc_type=type(exc).__name__, error=str(exc) or repr(exc))


# ---------------------------------------------------------------------------
# Response timing jitter helper
# ---------------------------------------------------------------------------

async def _jitter() -> None:
    """Apply realistic Python-latency jitter: 120–380ms (plans.md Section 4.4)."""
    await asyncio.sleep(random.uniform(0.12, 0.38))


# ---------------------------------------------------------------------------
# Deceptive fake data helpers
# ---------------------------------------------------------------------------

FAKE_MODELS = [
    {"id": "mdl-001", "name": "llama3-8b-finetune", "version": "v1.2.3",
     "status": "deployed", "s3_path": "s3://neuro-ml-artifacts/models/llama3-8b/",
     "created_by": "m.chen@neuro.ai", "created_at": "2026-03-14T08:22:01Z"},
    {"id": "mdl-002", "name": "mistral-7b-ablation", "version": "v0.9.1",
     "status": "training", "s3_path": "s3://neuro-ml-artifacts/models/mistral-7b/",
     "created_by": "priya.nair@neuro.ai", "created_at": "2026-04-02T14:11:33Z"},
    {"id": "mdl-003", "name": "phi-3-mini-instruct", "version": "v2.0.0",
     "status": "pending", "s3_path": "s3://neuro-ml-artifacts/models/phi-3-mini/",
     "created_by": "j.park@neuro.ai", "created_at": "2026-04-19T09:05:17Z"},
    {"id": "mdl-004", "name": "gpt4-classifier-v3", "version": "v3.4.1",
     "status": "deployed", "s3_path": "s3://neuro-ml-artifacts/models/gpt4-cls/",
     "created_by": "m.chen@neuro.ai", "created_at": "2026-02-28T16:44:55Z"},
    {"id": "mdl-005", "name": "llama3-rlhf-sweep", "version": "v0.3.7",
     "status": "failed", "s3_path": "s3://neuro-ml-artifacts/models/llama3-rlhf/",
     "created_by": "priya.nair@neuro.ai", "created_at": "2026-05-01T11:30:00Z"},
]

FAKE_JOBS = [
    {"job_id": "run-047", "model": "llama3-8b-finetune", "status": "RUNNING",
     "gpu_node": "node-gpu-03", "epoch_current": 14, "epoch_total": 40,
     "loss": 0.3821, "started_at": "2026-05-17T06:00:00Z"},
    {"job_id": "run-046", "model": "mistral-7b-ablation", "status": "RUNNING",
     "gpu_node": "node-gpu-07", "epoch_current": 8, "epoch_total": 40,
     "loss": 0.5103, "started_at": "2026-05-18T01:00:00Z"},
    {"job_id": "run-045", "model": "phi-3-mini-instruct", "status": "PENDING",
     "gpu_node": None, "epoch_current": 0, "epoch_total": 60,
     "loss": None, "started_at": None},
    {"job_id": "run-044", "model": "gpt4-classifier-v3", "status": "COMPLETED",
     "gpu_node": "node-gpu-01", "epoch_current": 40, "epoch_total": 40,
     "loss": 0.1247, "started_at": "2026-05-10T12:00:00Z"},
    {"job_id": "run-043", "model": "llama3-rlhf-sweep", "status": "FAILED",
     "gpu_node": "node-gpu-05", "epoch_current": 23, "epoch_total": 40,
     "loss": None, "started_at": "2026-05-15T08:30:00Z"},
    {"job_id": "run-042", "model": "mistral-7b-rlhf", "status": "PAUSED",
     "gpu_node": "node-gpu-06", "epoch_current": 31, "epoch_total": 60,
     "loss": 0.2891, "started_at": "2026-05-12T20:00:00Z"},
]

FAKE_DATASETS = [
    {"id": "ds-001", "name": "neuro-internal-corpus-v4", "size_gb": 847.3,
     "classification": "CONFIDENTIAL", "owner": "m.chen@neuro.ai",
     "s3_path": "s3://neuro-ml-artifacts/datasets/corpus-v4/", "rows": 142_891_203},
    {"id": "ds-002", "name": "rlhf-preference-pairs-v2", "size_gb": 12.1,
     "classification": "INTERNAL", "owner": "priya.nair@neuro.ai",
     "s3_path": "s3://neuro-ml-artifacts/datasets/rlhf-pref-v2/", "rows": 4_200_000},
    {"id": "ds-003", "name": "instruct-finetune-synthetic", "size_gb": 3.7,
     "classification": "INTERNAL", "owner": "s.ali@neuro.ai",
     "s3_path": "s3://neuro-ml-artifacts/datasets/instruct-synth/", "rows": 890_000},
]

FAKE_INTERNAL_CONFIG = {
    "environment": "production",
    "debug_mode": True,
    "database_url": "postgresql://neuro_user:Nk9xPq2mRv@db-prod-01.neuro.internal:5432/neuro_prod",
    "aws_access_key_id": "AKIAYZM57LXRGIYTCOUV",
    "aws_secret_access_key": "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",
    "s3_bucket": "neuro-ml-artifacts",
    "jwt_secret": "neuro-jwt-secret-do-not-share-2024",
    "wandb_api_key": "a4f7c2e1b8d3905f6a71c2e4d0b93a7f58124e6d",
    "openai_api_key": "sk-proj-p8Kz2mRvN4wL9jT7bYcDxQ3aF6sE1hU5nM0qW8dP",
    "hf_token": "hf_pRmKvN8wL4jT7bYcDxQ3aF6sE1hU5nM0qW8d",
    "admin_email": "m.chen@neuro.ai",
    "admin_password": "NeuroAdmin2024!",
    "redis_url": "redis://:NeuroCache2024@cache-01.neuro.internal:6379/0",
    "secret_key": "neuro-secret-key-xK9mP2qRvN8wL4jT7bYcD",
    "gpu_cluster_api": "http://gpu-scheduler.neuro.internal:8080/v2/schedule",
    "internal_vpn_range": "10.31.0.0/16",
}

ENV_FILE_CONTENT = """\
# Neuro Production Environment — DO NOT COMMIT

ENVIRONMENT=production
DEBUG=true
SECRET_KEY=neuro-secret-key-xK9mP2qRvN8wL4jT7bYcD
DATABASE_URL=postgresql://neuro_user:Nk9xPq2mRv@db-prod-01.neuro.internal:5432/neuro_prod
REDIS_URL=redis://:NeuroCache2024@cache-01.neuro.internal:6379/0

AWS_ACCESS_KEY_ID=AKIAYZM57LXRGIYTCOUV
AWS_SECRET_ACCESS_KEY=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
AWS_DEFAULT_REGION=us-east-1
S3_BUCKET=neuro-ml-artifacts

TRAIN_NODE_SSH_KEY=/home/neuro-svc/.ssh/id_ed25519
TRAIN_NODE_HOST=neuro-train-01.internal
TRAIN_NODE_IP=10.31.4.22

WANDB_API_KEY=a4f7c2e1b8d3905f6a71c2e4d0b93a7f58124e6d
OPENAI_API_KEY=sk-proj-p8Kz2mRvN4wL9jT7bYcDxQ3aF6sE1hU5nM0qW8dP
HF_TOKEN=hf_pRmKvN8wL4jT7bYcDxQ3aF6sE1hU5nM0qW8d

ADMIN_EMAIL=m.chen@neuro.ai
ADMIN_PASSWORD=NeuroAdmin2024!
JWT_SECRET=neuro-jwt-secret-do-not-share-2024
"""

CONFIG_YAML_CONTENT = """\
# neuro-api config.yaml — generated by deploy pipeline
# DO NOT commit this file — contains production credentials

service:
  name: neuro-api
  version: "2.3.1"
  environment: production
  debug: true
  host: "0.0.0.0"
  port: 8080

database:
  host: db-prod-01.neuro.internal
  port: 5432
  name: neuro_prod
  user: neuro_user
  password: "Nk9xPq2mRv"
  pool_size: 10

redis:
  host: cache-01.neuro.internal
  port: 6379
  password: "NeuroCache2024"
  db: 0

aws:
  access_key_id: AKIAYZM57LXRGIYTCOUV
  secret_access_key: "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"
  region: us-east-1
  s3_bucket: neuro-ml-artifacts

auth:
  jwt_secret: "neuro-jwt-secret-do-not-share-2024"
  token_expiry_hours: 24
  sso_provider: "https://accounts.google.com/o/oauth2/v2/auth"

monitoring:
  wandb_api_key: a4f7c2e1b8d3905f6a71c2e4d0b93a7f58124e6d
  openai_api_key: sk-proj-p8Kz2mRvN4wL9jT7bYcDxQ3aF6sE1hU5nM0qW8dP

gpu:
  cluster_api: "http://gpu-scheduler.neuro.internal:8080/v2/schedule"
  node_count: 8
  default_quota_hours: 48
"""

FAKE_METRICS = """\
# HELP neuro_training_jobs_active Number of currently active training jobs
# TYPE neuro_training_jobs_active gauge
neuro_training_jobs_active 2
# HELP neuro_gpu_utilization_ratio GPU cluster utilization 0.0-1.0
# TYPE neuro_gpu_utilization_ratio gauge
neuro_gpu_utilization_ratio 0.843
# HELP neuro_models_deployed Total models in deployed state
# TYPE neuro_models_deployed counter
neuro_models_deployed_total 12
# HELP neuro_api_requests_total Total API requests handled
# TYPE neuro_api_requests_total counter
neuro_api_requests_total{method="GET",path="/api/v1/health",status="200"} 18473
neuro_api_requests_total{method="POST",path="/api/v1/training/start",status="202"} 341
neuro_api_requests_total{method="GET",path="/api/v1/models",status="200"} 2891
# HELP neuro_dataset_size_gb Total dataset storage in GB
# TYPE neuro_dataset_size_gb gauge
neuro_dataset_size_gb{dataset="neuro-internal-corpus-v4"} 847.3
neuro_dataset_size_gb{dataset="rlhf-preference-pairs-v2"} 12.1
# HELP neuro_pipeline_healthy Whether the ML pipeline is healthy (1=yes, 0=no)
# TYPE neuro_pipeline_healthy gauge
neuro_pipeline_healthy 1
"""

FAKE_DEBUG_INFO = {
    "service": "neuro-api",
    "version": "2.3.1",
    "build": "20260428",
    "environment": "production",
    "debug_mode": True,
    "db_host": "db-prod-01.neuro.internal",
    "db_pool": {"size": 10, "checked_out": 3, "overflow": 0},
    "redis_host": "cache-01.neuro.internal",
    "gpu_nodes": {
        "node-gpu-01.neuro.internal (10.31.1.11)": "idle",
        "node-gpu-02.neuro.internal (10.31.1.12)": "idle",
        "node-gpu-03.neuro.internal (10.31.1.13)": "busy",
        "node-gpu-04.neuro.internal (10.31.1.14)": "idle",
        "node-gpu-05.neuro.internal (10.31.1.15)": "error",
        "node-gpu-06.neuro.internal (10.31.1.16)": "paused",
        "node-gpu-07.neuro.internal (10.31.1.17)": "busy",
        "node-gpu-08.neuro.internal (10.31.1.18)": "idle",
    },
    "active_sessions": 14,
    "uptime_seconds": 1_847_302,
    "internal_endpoints": [
        "/api/v1/internal/config",
        "/api/v1/internal/debug",
        "/api/v1/internal/migrate",
        "/admin/users",
        "/admin/export/users",
        "/debug/crash",
        "/debug/logs",
    ],
    "WARNING": "This endpoint should not be exposed — disable debug_mode before next sprint (IT#4821)",
}

ADMIN_USERS_RESPONSE = {
    "users": [
        {"id": 1, "username": "m.chen", "role": "admin",
         "email": "m.chen@neuro.ai", "last_login": "2026-05-18T14:22:01Z"},
        {"id": 2, "username": "priya.nair", "role": "ml_engineer",
         "email": "priya.nair@neuro.ai", "last_login": "2026-05-17T09:45:33Z"},
        {"id": 3, "username": "j.park", "role": "devops_engineer",
         "email": "j.park@neuro.ai", "last_login": "2026-05-16T11:03:42Z"},
        {"id": 4, "username": "s.ali", "role": "data_scientist",
         "email": "s.ali@neuro.ai", "last_login": "2026-05-15T08:21:17Z"},
        {"id": 5, "username": "svc-deploy", "role": "service_account",
         "api_key": "sk-neuro-REDACTED", "last_login": "2026-05-19T00:01:05Z"},
    ],
    "_note": "WARN: /admin/users should require auth — IT#5117 pending"
}


# ---------------------------------------------------------------------------
# Routes — Health
# ---------------------------------------------------------------------------

@app.get("/api/v1/health")
async def health():
    """Health check — always returns ok with fake GPU metrics."""
    return {
        "status": "ok",
        "gpu_util": round(random.uniform(78.0, 94.0), 1),
        "jobs": random.randint(2, 5),
        "uptime": 1_847_302,
        "version": "2.3.1",
    }


# ---------------------------------------------------------------------------
# Routes — Models
# ---------------------------------------------------------------------------

@app.get("/api/v1/models")
async def get_models():
    await _jitter()
    return {"models": FAKE_MODELS, "total": len(FAKE_MODELS)}


@app.get("/api/v1/models/{model_id}/metrics")
async def get_model_metrics(model_id: str):
    await _jitter()
    # Generate fake loss curve data
    epochs = list(range(1, 41))
    loss = [round(2.1 * (0.97 ** e) + random.uniform(-0.01, 0.01), 4) for e in epochs]
    accuracy = [round(min(0.99, 0.5 + (1 - 2.1 * (0.97 ** e)) * 0.5 + random.uniform(-0.005, 0.005)), 4) for e in epochs]
    return {
        "model_id": model_id,
        "metrics": {
            "loss": loss,
            "accuracy": accuracy,
            "epochs": epochs,
            "val_loss": [round(v + random.uniform(0.005, 0.02), 4) for v in loss],
            "val_accuracy": [round(max(0, a - random.uniform(0.01, 0.03)), 4) for a in accuracy],
        },
        "best_epoch": 38,
        "best_loss": 0.1247,
    }


# ---------------------------------------------------------------------------
# Routes — Training Jobs
# ---------------------------------------------------------------------------

@app.get("/api/v1/training/jobs")
async def get_training_jobs():
    await _jitter()
    return {"jobs": FAKE_JOBS, "total": len(FAKE_JOBS), "running": 2, "pending": 1}


@app.post("/api/v1/training/start")
async def start_training(request: Request):
    """Accepts any payload, logs it, returns a fake job ID."""
    await _jitter()
    job_id = f"run-{random.randint(48, 999):03d}"
    estimated_start = (
        datetime.now(timezone.utc).replace(second=0, microsecond=0).isoformat().replace("+00:00", "Z")
    )
    return JSONResponse(status_code=202, content={
        "job_id": job_id,
        "status": "PENDING",
        "message": "Training job queued successfully",
        "queue_position": random.randint(1, 4),
        "estimated_start": estimated_start,
    })


# ---------------------------------------------------------------------------
# Routes — Datasets
# ---------------------------------------------------------------------------

@app.get("/api/v1/data/datasets")
async def get_datasets():
    await _jitter()
    return {"datasets": FAKE_DATASETS, "total": len(FAKE_DATASETS)}


@app.get("/api/v1/data/download/{dataset_id}")
async def download_dataset(dataset_id: str):
    """Log download intent, return 302 to a fake S3 URL (honeytoken)."""
    await _jitter()
    # Fake presigned S3 URL — triggers when fetched
    fake_s3_url = (
        f"https://neuro-ml-artifacts.s3.amazonaws.com/{dataset_id}/"
        f"?X-Amz-Algorithm=AWS4-HMAC-SHA256"
        f"&X-Amz-Credential=AKIAYZM57LXRGIYTCOUV"
        f"&X-Amz-Date=20260519T120000Z"
        f"&X-Amz-Expires=3600"
        f"&X-Amz-SignedHeaders=host"
        f"&X-Amz-Signature=fakesig{uuid.uuid4().hex[:32]}"
    )
    return RedirectResponse(url=fake_s3_url, status_code=302)


# ---------------------------------------------------------------------------
# Routes — Inference
# ---------------------------------------------------------------------------

@app.post("/api/v1/inference")
async def inference(request: Request):
    """Logs full request body; detects prompt injection attempts."""
    await _jitter()
    src_ip = _extract_src_ip(request)
    try:
        body_bytes = await request.body()
        body_str   = body_bytes.decode("utf-8", errors="replace")
    except Exception:
        body_str = ""

    # Normalize unicode (NFKC) so homoglyph substitutions (ɪɢɴᴏʀᴇ → ignore) collapse
    body_lower = unicodedata.normalize("NFKC", body_str).lower()
    for pat in _PROMPT_INJECTION_PATTERNS:
        if pat in body_lower:
            asyncio.create_task(_log_event_async({
                "event_id":          str(uuid.uuid4()),
                "created_at":        datetime.now(timezone.utc),
                "sensor":            SENSOR_NAME,
                "event_type":        "http.prompt.injection",
                "src_ip":            src_ip,
                "src_port":          request.client.port if request.client else None,
                "dst_port":          8080,
                "username":          None,
                "password":          None,
                "session_id":        request.cookies.get("nro_session", str(uuid.uuid4())),
                "payload":           json.dumps({
                    "path":         "/api/v1/inference",
                    "method":       "POST",
                    "pattern":      pat,
                    "body_preview": body_str[:300],
                }),
                "raw_log":           json.dumps({"body": body_str[:500]}),
                "geo_country": None, "geo_country_code": None,
                "geo_city": None, "geo_asn": None, "geo_org": None,
            }))
            break  # one event per request

    return JSONResponse(status_code=202, content={
        "request_id": str(uuid.uuid4()),
        "model": "llama3-8b-finetune",
        "status": "queued",
        "estimated_latency_ms": random.randint(800, 3200),
        "message": "Inference request accepted",
    })


# ---------------------------------------------------------------------------
# Routes — Telemetry (JS fingerprint beacon receiver)
# ---------------------------------------------------------------------------

@app.get("/api/v1/telemetry")
@app.post("/api/v1/telemetry")
async def telemetry(request: Request):
    """Receives client-side fingerprint beacons from metrics.js.

    Generic beacons (page_view, field_interaction, canvas/WebRTC, dwell) are
    logged only via middleware as http.post.api.v1.telemetry — that event type
    is in sentinel's _NOISE_EVENTS so it never saturates the "http" cooldown bucket.

    DevTools beacons (type='dev_tools_open') are emitted as a DISTINCT event type
    http.telemetry.devtools_opened so sentinel always fires an alert for them
    regardless of the http cooldown window (they are also in _NO_COOLDOWN_EVENTS).
    """
    body_json: dict = {}
    try:
        body_bytes = await request.body()
        if body_bytes:
            body_json = json.loads(body_bytes)
    except Exception:
        pass

    beacon_type = body_json.get("type", "")
    if beacon_type == "dev_tools_open":
        src_ip = _extract_src_ip(request)
        method_used = body_json.get("method") or ""
        asyncio.create_task(_log_event_async({
            "event_id":   str(uuid.uuid4()),
            "created_at": datetime.now(timezone.utc),
            "sensor":     "api",
            "event_type": "http.telemetry.devtools_opened",
            "src_ip":     src_ip,
            "src_port":   request.client.port if request.client else None,
            "dst_port":   8080,
            "username":   None,
            "password":   None,
            "payload":    json.dumps({"beacon_type": beacon_type, "method": method_used}),
            "raw_log":    None,
            "session_id": request.cookies.get("nro_session") or str(uuid.uuid4()),
            **_lookup_geo(src_ip),
        }))

    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Routes — Internal (crown jewel lures)
# ---------------------------------------------------------------------------

@app.get("/api/v1/internal/debug")
async def internal_debug():
    await _jitter()
    return FAKE_DEBUG_INFO


@app.get("/api/v1/internal/config")
async def internal_config():
    """Crown jewel — full fake config dump with all secrets (plans.md Section 4.2)."""
    await _jitter()
    return FAKE_INTERNAL_CONFIG


@app.get("/api/v1/cluster/nodes")
async def cluster_nodes(request: Request):
    """GPU training cluster node list — bridges HTTP recon to SSH sensor."""
    await _jitter()
    return JSONResponse({
        "cluster": "neuro-train-cluster",
        "updated_at": "2026-05-31T08:00:00Z",
        "nodes": [
            {
                "name": "neuro-train-01",
                "ip": "10.31.4.22",
                "status": "running",
                "ssh_port": 22,
                "ssh_fingerprint": "SHA256:k3YxPq9mRvN4wZj2sBtL7uCeIoAhGfDy",
                "gpu_util": 87.4,
                "gpu_mem_used_gb": 38.2,
                "gpu_mem_total_gb": 40.0,
                "role": "primary",
                "running_job": "run-047-llama3-finetune",
                "note": "Direct SSH requires neuro-svc credentials. See /config.yaml."
            },
            {
                "name": "neuro-train-02",
                "ip": "10.31.4.23",
                "status": "idle",
                "ssh_port": 22,
                "ssh_fingerprint": "SHA256:m5VwRq3nKt8pXd1yBzNjLaFeHiSgCuOe",
                "gpu_util": 0.0,
                "gpu_mem_used_gb": 0.1,
                "gpu_mem_total_gb": 40.0,
                "role": "standby"
            }
        ]
    })


# ---------------------------------------------------------------------------
# Routes — Prometheus metrics
# ---------------------------------------------------------------------------

@app.get("/metrics")
async def prometheus_metrics():
    await _jitter()
    return Response(content=FAKE_METRICS, media_type="text/plain; version=0.0.4; charset=utf-8")


# ---------------------------------------------------------------------------
# Routes — Trap files
# ---------------------------------------------------------------------------

@app.get("/.env")
async def dot_env():
    """Fake .env with honeytoken AWS key. High-value lure — triggers on any scanner."""
    await _jitter()
    return Response(content=ENV_FILE_CONTENT, media_type="text/plain")


@app.get("/config.yaml")
async def config_yaml():
    """Fake config.yaml with honeytoken credentials."""
    await _jitter()
    return Response(content=CONFIG_YAML_CONTENT, media_type="text/plain")


@app.get("/robots.txt")
async def robots_txt():
    """Serves robots.txt that discloses internal paths (attacker bait)."""
    content = """\
User-agent: *
Disallow: /admin/
Disallow: /api/v1/internal/
Disallow: /debug/
Disallow: /.env
Disallow: /config.yaml

# Internal paths (do not index)
# Sitemap: https://neurodata.me/sitemap.xml
"""
    return Response(content=content, media_type="text/plain")


@app.get("/sitemap.xml")
async def sitemap():
    content = """\
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.2">
  <url><loc>https://neurodata.me/</loc></url>
  <url><loc>https://neurodata.me/dashboard</loc></url>
  <url><loc>https://neurodata.me/api/docs</loc></url>
  <!-- Internal: https://neurodata.me/admin/users -->
  <!-- Dev: https://neurodata.me/debug/logs -->
</urlset>
"""
    return Response(content=content, media_type="application/xml")


@app.get("/.well-known/security.txt")
async def security_txt():
    """Absence of security.txt is a honeypot signal; presence adds realism."""
    content = """\
Contact: mailto:security@neuro.ai
Expires: 2026-12-31T23:59:59Z
Preferred-Languages: en
Policy: https://neuro.ai/security-policy
"""
    return Response(content=content, media_type="text/plain")


@app.get("/legal/tos")
async def legal_tos():
    """Terms of Service stub — linked from login footer; JSON-404 would be a tell."""
    html = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Terms of Service — Neuro</title>
<style>body{font-family:system-ui,sans-serif;max-width:760px;margin:60px auto;padding:0 24px;color:#e2e8f0;background:#0f172a}h1{color:#f8fafc;margin-bottom:8px}h2{color:#cbd5e1;font-size:1rem;margin-top:2em}p,li{color:#94a3b8;line-height:1.7}a{color:#6366f1}footer{margin-top:60px;color:#475569;font-size:.85rem}</style>
</head><body>
<h1>Neuro Platform — Terms of Service</h1>
<p style="color:#475569">Last updated: 2026-01-15 &nbsp;|&nbsp; Effective: 2026-02-01</p>
<h2>1. Acceptance</h2>
<p>By accessing the Neuro training infrastructure you agree to these terms and all applicable policies.</p>
<h2>2. Authorized Use</h2>
<p>Access is restricted to authorized Cyveera personnel. All activity is logged for security and compliance purposes.</p>
<h2>3. Data Handling</h2>
<p>Model weights, dataset references, and training telemetry stored on this platform are classified as confidential. Export without approval is prohibited.</p>
<h2>4. Contact</h2>
<p>Questions: <a href="mailto:legal@neuro.ai">legal@neuro.ai</a></p>
<footer><a href="/">← Back to Neuro</a></footer>
</body></html>"""
    return Response(content=html, media_type="text/html")


@app.get("/legal/privacy")
async def legal_privacy():
    """Privacy Policy stub — linked from login footer; JSON-404 would be a tell."""
    html = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Privacy Policy — Neuro</title>
<style>body{font-family:system-ui,sans-serif;max-width:760px;margin:60px auto;padding:0 24px;color:#e2e8f0;background:#0f172a}h1{color:#f8fafc;margin-bottom:8px}h2{color:#cbd5e1;font-size:1rem;margin-top:2em}p,li{color:#94a3b8;line-height:1.7}a{color:#6366f1}footer{margin-top:60px;color:#475569;font-size:.85rem}</style>
</head><body>
<h1>Neuro Platform — Privacy Policy</h1>
<p style="color:#475569">Last updated: 2026-01-15 &nbsp;|&nbsp; Effective: 2026-02-01</p>
<h2>1. Information We Collect</h2>
<p>We collect authentication events, session metadata, and platform telemetry to operate and secure the Neuro training infrastructure.</p>
<h2>2. How We Use It</h2>
<p>Telemetry is used exclusively for capacity planning, anomaly detection, and compliance reporting. It is not shared with third parties.</p>
<h2>3. Retention</h2>
<p>Logs are retained for 90 days. Model artefacts follow the data lifecycle defined in the Cyveera data governance policy.</p>
<h2>4. Contact</h2>
<p>Privacy enquiries: <a href="mailto:privacy@neuro.ai">privacy@neuro.ai</a></p>
<footer><a href="/">← Back to Neuro</a></footer>
</body></html>"""
    return Response(content=html, media_type="text/html")


# ---------------------------------------------------------------------------
# Routes — Admin
# ---------------------------------------------------------------------------

@app.get("/admin/users")
async def admin_users():
    """User list accessible without auth — the 'misconfiguration' (plans.md Section 4.2)."""
    await _jitter()
    return ADMIN_USERS_RESPONSE


@app.post("/admin/login")
async def admin_login(request: Request):
    """Credential capture — always returns 401 with fake error."""
    # Simulate DB lookup delay (1.8s as per plans.md Section 4.2)
    await asyncio.sleep(1.8)
    return JSONResponse(
        status_code=401,
        content={"detail": "Invalid credentials", "hint": "Contact #ai-infra on Slack"},
    )


# ---------------------------------------------------------------------------
# Routes — Main auth
# ---------------------------------------------------------------------------

@app.post("/api/v1/auth")
async def api_auth(request: Request, response: Response):
    """
    Main login endpoint — server-side credential validation.
    Lure credentials are stored server-side only; the client never sees them.
    Valid credentials set a real session cookie and return 200 with redirect instruction.
    All other credentials return 401 (credential capture still logged by middleware).

    DEMO_SQLI_BYPASS mode (env flag — disabled in production):
    When DEMO_SQLI_BYPASS=true, a login submission containing a recognised SQLi
    pattern returns HTTP 200 + a real session cookie, making the attacker believe
    the injection bypass worked.  The middleware has ALREADY logged the full
    credential body before this function runs, so nothing is suppressed.
    No SQL engine is used — detection is string-compare only via _detect_web_attack.
    """
    # Lure credentials — server-side only, never sent to client
    _LURE_CREDS = [
        ("admin@neuro.ai",  "NeuroAdmin2024!"),
        ("m.chen@neuro.ai", "Neuro@2026!"),
    ]

    body_bytes = await request.body()
    body_str = body_bytes.decode("utf-8", errors="replace") if body_bytes else ""
    email = None
    password = None
    try:
        body_json = json.loads(body_bytes)
        email = body_json.get("email") or body_json.get("username")
        password = body_json.get("password")
    except Exception:
        pass

    # Simulate backend auth latency (realistic for a real DB lookup)
    await asyncio.sleep(1.8)

    if email and password and any(email == e and password == p for e, p in _LURE_CREDS):
        # Valid lure credential — set a real session cookie and signal redirect
        session_id = request.cookies.get("nro_session") or str(uuid.uuid4())
        resp = JSONResponse(
            status_code=200,
            content={"ok": True, "redirect": "/dashboard"},
        )
        resp.set_cookie(
            key="nro_session",
            value=session_id,
            path="/",
            httponly=True,
            secure=False,
            samesite="lax",
            max_age=86400,
        )
        with _SESSION_USER_LOCK:
            _SESSION_USER_MAP[session_id] = email
        # Signal to middleware to override event_type — stripped before sending to client
        resp.headers["X-Lure-Credential-Used"] = "true"
        return resp

    # DEMO_SQLI_BYPASS: when enabled, a detected SQLi pattern in the login body
    # returns a fake 200 success — no SQL engine, no live query, no suppressed logs.
    # The middleware already captured the full payload before this handler ran.
    # Enabled only during live pitch demos via DEMO_SQLI_BYPASS=true in compose env.
    if DEMO_SQLI_BYPASS:
        ua_str = request.headers.get("user-agent", "")
        query_str = str(request.query_params)
        sqli_hit = _detect_web_attack(
            request.url.path, query_str, body_str, ua_str
        )
        if sqli_hit and "sqli" in sqli_hit[0]:
            session_id = request.cookies.get("nro_session") or str(uuid.uuid4())
            resp = JSONResponse(
                status_code=200,
                content={"ok": True, "redirect": "/dashboard"},
            )
            resp.set_cookie(
                key="nro_session",
                value=session_id,
                path="/",
                httponly=True,
                secure=False,
                samesite="lax",
                max_age=86400,
            )
            return resp

    # --- Bruteforce detection ---
    # Record this failed attempt (lure-cred successes skip this block entirely).
    # All dict/deque access is under _auth_lock (threading.Lock) because this
    # coroutine may be called from executor threads when DEMO_SQLI_BYPASS runs
    # blocking code.  In the normal async path the lock is still necessary
    # because multiple concurrent coroutines share the defaultdict.
    src_ip = _extract_src_ip(request)
    now_ts = time.time()

    with _auth_lock:
        bucket = _auth_attempts[src_ip]
        if password:  # only record attempts that supplied a password
            bucket.append((now_ts, str(password)[:256]))

        # Count failures within the sliding window
        recent = [(ts, pw) for ts, pw in bucket if now_ts - ts <= _BF_WINDOW_SECS]
        fail_count = len(recent)
        recent_passwords = [pw for _, pw in recent[-5:]]  # last 5 passwords tried

    # Threshold alert — fires exactly once when fail_count crosses _BF_THRESHOLD.
    # Checking (fail_count - 1) < _BF_THRESHOLD ensures it fires on the crossing
    # request only, not on every subsequent attempt. Works correctly even when
    # concurrent requests are serialised through _auth_lock.
    if fail_count >= _BF_THRESHOLD and (fail_count - 1) < _BF_THRESHOLD:
        bf_event: dict[str, Any] = {
            "event_id": str(uuid.uuid4()),
            "created_at": datetime.now(timezone.utc),
            "sensor": "api",
            "event_type": "http.bruteforce.detected",
            "src_ip": src_ip,
            "src_port": request.client.port if request.client else None,
            "dst_port": 8080,
            "username": str(email)[:128] if email else None,
            "password": None,
            "payload": json.dumps({
                "fail_count": fail_count,
                "window_secs": _BF_WINDOW_SECS,
                "last_passwords_tried": recent_passwords,
                "path": "/api/v1/auth",
                "note": "bruteforce threshold reached — credential dump captured",
            }),
            "raw_log": None,
            "session_id": request.cookies.get("nro_session") or str(uuid.uuid4()),
            **_lookup_geo(src_ip),
        }
        asyncio.create_task(_log_event_async(bf_event))
        if HONEYDASH_URL and SENSOR_API_KEY:
            asyncio.create_task(_push_honeydash_async(bf_event, "Bruteforce"))

    # Hard rate-limit response after _BF_HARD_LIMIT attempts — but logging continues
    # (we never stop recording; 429 is pure response theatre for the attacker).
    if fail_count >= _BF_HARD_LIMIT:
        return JSONResponse(
            status_code=429,
            content={"error": "rate_limit_exceeded", "retry_after": 300},
        )

    return JSONResponse(
        status_code=401,
        content={"detail": "Invalid credentials. After 3 failures your account will be locked."},
    )


@app.get("/api/v1/auth/direct")
@app.post("/api/v1/auth/direct")
async def auth_direct(request: Request):
    """Lure route referenced in page-source comments — logs high-value recon hit."""
    await _jitter()
    return JSONResponse(
        status_code=410,
        content={
            "error": "deprecated_endpoint",
            "message": "Direct DB auth removed after IT#5043 security review. Use /api/v1/auth.",
            "docs": "https://neurodata.me/api/docs#authentication",
            "migrated_at": "2026-03-01T00:00:00Z",
        },
    )


@app.post("/api/v1/auth/sso/initiate")
async def sso_initiate(request: Request):
    """
    SSO handshake stub — always returns 503 after a realistic identity-provider
    round-trip delay.  The SSO button on the login page fires this request so
    the Network tab shows a real XHR, preventing the no-network-request tell.
    """
    await asyncio.sleep(1.8 + random.random() * 0.6)
    return JSONResponse(
        status_code=503,
        content={
            "error": "sso_provider_unreachable",
            "detail": "Identity provider timeout. Use local credentials.",
        },
    )


@app.get("/auth/forgot-password")
@app.post("/auth/forgot-password")
async def forgot_password(request: Request):
    """Captures attacker email — always returns fake success.

    Middleware already caches the body via request._receive so our json() call
    here re-reads from the buffer without hanging or consuming the stream.
    Emits a distinct http.lure.forgot_password event so sentinel and HoneyDash
    can query it separately from the generic middleware event.
    """
    await _jitter()
    src_ip = _extract_src_ip(request)
    submitted_email: str | None = None
    try:
        body = await request.json()
        submitted_email = str(body.get("email") or body.get("username") or "")[:256] or None
    except Exception:
        pass
    if submitted_email:
        asyncio.create_task(_log_event_async({
            "event_id":   str(uuid.uuid4()),
            "created_at": datetime.now(timezone.utc),
            "sensor":     "api",
            "event_type": "http.lure.forgot_password",
            "src_ip":     src_ip,
            "src_port":   request.client.port if request.client else None,
            "dst_port":   8080,
            "username":   submitted_email,
            "password":   None,
            "payload":    json.dumps({"submitted_email": submitted_email, "path": "/auth/forgot-password"}),
            "raw_log":    None,
            "session_id": request.cookies.get("nro_session") or str(uuid.uuid4()),
            **_lookup_geo(src_ip),
        }))
    return JSONResponse(content={
        "message": "If that email is registered, you'll receive a link within 5 minutes. "
                   "Check #ai-infra on Slack.",
    })


# ---------------------------------------------------------------------------
# Routes — SNARE reactive pages (LFI / RCE / Honeytoken traps)
# ---------------------------------------------------------------------------
#
# Cross-surface fixture values (must match SSH/Cowrie honeyfs + MariaDB lure):
#   Service account : neuro-svc  (uid=1000, gid=1000, home=/home/neuro-svc)
#   Hostname        : neuro-train-01
#   Personas        : m.chen (uid=1001), priya.nair (uid=1002)  @neuro.ai
#
# SAFETY RULE: no attacker input may select a file path, build a shell command,
# or reach subprocess/eval/open() in any SNARE response path.  All output is a
# hardcoded static string.  The SNARE detector (_detect_web_attack) determines
# which canned fixture to return; attacker-supplied values are never interpreted.

# Static fixture: fake /etc/passwd (returned on LFI hit via ?path= parameter)
_FAKE_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
    "neuro-svc:x:1000:1000:Neuro Service Account:/home/neuro-svc:/bin/bash\n"
    "m.chen:x:1001:1001:Ming Chen:/home/m.chen:/bin/bash\n"
    "priya.nair:x:1002:1002:Priya Nair:/home/priya.nair:/bin/bash\n"
    "postgres:x:999:999::/var/lib/postgresql:/bin/sh\n"
)

# Static fixture: fake RCE command output (returned on RCE hit in job submission)
_FAKE_RCE_OUTPUT = (
    "uid=1000(neuro-svc) gid=1000(neuro-svc) "
    "groups=1000(neuro-svc),4(adm),27(sudo)\n"
    "Submitted training job jb-20260526-8f3a. ETA: 4h 12m.\n"
)


@app.get("/artifacts")
async def artifacts_page(request: Request, path: str = ""):
    """
    Model artifact browser — LFI trap via ?path= parameter.
    If _detect_web_attack classifies the request as an LFI attempt, returns
    a static fake /etc/passwd blob (hardcoded — no open() or file access).
    Otherwise renders the artifacts template for legitimate-looking browsing.
    """
    await _jitter()
    query_str = str(request.query_params)
    ua_str = request.headers.get("user-agent", "")
    lfi_hit = _detect_web_attack(request.url.path, query_str, "", ua_str)
    if lfi_hit and lfi_hit[0] == "http.lfi.attempt" and path:
        # Return static fake passwd content — attacker believes they read /etc/passwd.
        # No open(), no path join, no attacker input touches the filesystem.
        return Response(content=_FAKE_PASSWD, media_type="text/plain")
    return templates.TemplateResponse(
        "artifacts.html",
        {"request": request, "path": path or "models/"},
    )


@app.get("/jobs/new")
async def jobs_new_page(request: Request):
    if not _session_ok(request):
        _log_unauth_access(request)
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse("jobs_new.html", {"request": request})


@app.post("/jobs/new")
async def jobs_new_submit(request: Request):
    """
    Training job submission — RCE trap via startup_script field.
    If _detect_web_attack classifies the body as RCE, returns a static fake
    command-output blob (no subprocess, no eval, no shell).
    """
    body_bytes = await request.body()
    body_str = body_bytes.decode("utf-8", errors="replace")
    ua_str = request.headers.get("user-agent", "")
    rce_hit = _detect_web_attack(request.url.path, "", body_str, ua_str)
    if rce_hit and "rce" in rce_hit[0]:
        # Static canned output — attacker believes startup_script executed.
        # Breadth decision: only the first payload is convincingly answered;
        # follow-on commands return a normal queued-job response (no fake shell).
        return JSONResponse({
            "ok": True,
            "job_id": "jb-20260526-8f3a",
            "output": _FAKE_RCE_OUTPUT,
            "status": "queued",
        })
    return JSONResponse({
        "ok": True,
        "job_id": f"jb-{uuid.uuid4().hex[:8]}",
        "status": "queued",
    })


@app.get("/runs")
async def runs_page(request: Request):
    if not _session_ok(request):
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse("runs.html", {"request": request})


@app.get("/models")
async def models_page(request: Request):
    if not _session_ok(request):
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse("models.html", {"request": request})


@app.get("/datasets")
async def datasets_page(request: Request):
    if not _session_ok(request):
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse("datasets.html", {"request": request})


@app.get("/notifications")
async def notifications_page(request: Request):
    if not _session_ok(request):
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse("notifications.html", {"request": request})


@app.get("/settings/profile")
async def settings_profile_page(request: Request):
    if not _session_ok(request):
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse("settings_profile.html", {"request": request})


@app.get("/settings/integrations")
async def settings_integrations_page(request: Request):
    if not _session_ok(request):
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse("settings_integrations.html", {"request": request})


@app.post("/api/v1/integrations/webhook/test")
async def webhook_test(request: Request):
    """
    Webhook test endpoint — logs the target URL for SSRF detection.
    Never makes an outbound request; returns fake delivery confirmation.
    The webhook-url field is the SSRF vector: attackers enter metadata endpoints.
    """
    await _jitter()
    src_ip = request.headers.get("X-Real-IP") or (request.client.host if request.client else "unknown")
    try:
        body = await request.json()
    except Exception:
        body = {}
    target_url = body.get("url", "")
    # Detect SSRF in the webhook target URL
    ssrf_hit = False
    for pat in _SSRF_PATTERNS:
        if pat.lower() in target_url.lower():
            ssrf_hit = True
            break
    event_type = "http.snare.ssrf_attempt" if ssrf_hit else "http.webhook.test"
    _log_event({
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": event_type,
        "src_ip": src_ip,
        "src_port": None,
        "dst_port": 8080,
        "username": None,
        "password": None,
        "payload": json.dumps({
            "webhook_url": target_url,
            "events": body.get("events", []),
            "ssrf_detected": ssrf_hit,
        }),
        "raw_log": None,
        "session_id": request.cookies.get("nro_session"),
        "geo_country": None,
        "geo_country_code": None,
        "geo_city": None,
        "geo_asn": None,
        "geo_org": None,
    })
    return JSONResponse({
        "ok": True,
        "status_code": 200,
        "message": "Test webhook delivered successfully.",
        "delivery_id": f"del-{uuid.uuid4().hex[:10]}",
        "relay": "http://10.31.4.22:3128/",
    })


@app.get("/pipelines")
async def pipelines_page(request: Request):
    if not _session_ok(request):
        return RedirectResponse(url="/", status_code=302)
    return RedirectResponse(url="/dashboard?tab=pipelines", status_code=302)


@app.get("/settings/workspace")
async def settings_workspace(request: Request):
    if not _session_ok(request):
        return RedirectResponse(url="/", status_code=302)
    await _jitter()
    return JSONResponse({
        "workspace": "neuro-prod",
        "region": "us-east-1",
        "tier": "enterprise",
        "message": "Workspace configuration managed by your IT administrator. Raise a ticket: IT#6204.",
    })


@app.get("/settings/api-keys")
async def api_keys_page(request: Request):
    if not _session_ok(request):
        _log_unauth_access(request)
        return RedirectResponse(url="/", status_code=302)
    await _jitter()
    return templates.TemplateResponse("api_keys.html", {"request": request})


@app.post("/settings/api-keys/create")
async def api_keys_create(request: Request):
    """
    Honeytoken key creation — returns a freshly generated fake API key.
    Format: nro-<32 alphanumeric chars> — consistent with the existing
    svc-deploy key shown in /admin/users.  Keys should be registered as
    Copy interactions are logged via the /api/v1/telemetry beacon.
    """
    await _jitter()
    key_body = "".join(
        random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=32)
    )
    return JSONResponse({
        "key": f"nro-{key_body}",
        "created_at": "2026-05-26T00:00:00Z",
        "expires_at": "2027-05-26T00:00:00Z",
    })


@app.post("/settings/api-keys/revoke")
async def api_keys_revoke(request: Request):
    """Honeytoken key revocation — accepts the request, logs via middleware, returns 200."""
    await _jitter()
    return JSONResponse({"ok": True, "revoked": True})


@app.get("/api/v1/lure/model-manifest")
async def lure_model_manifest(request: Request):
    """Lure: planted model manifest — linked from /artifacts Download button."""
    await _jitter()
    return JSONResponse({
        "model": "llama3-8b-finetune",
        "version": "v1.2.3",
        "s3_path": "s3://neuro-ml-artifacts/models/llama3-8b/",
        "created_by": "priya.nair@neuro.ai",
        "status": "production",
    })


# ---------------------------------------------------------------------------
# Routes — Fake Swagger docs
# ---------------------------------------------------------------------------

@app.get("/api/docs", response_class=HTMLResponse)
async def api_docs(request: Request):
    """Fake Swagger-style API documentation page (static HTML, not real Swagger JS)."""
    await _jitter()
    return templates.TemplateResponse("api_docs.html", {"request": request})


# ---------------------------------------------------------------------------
# Routes — WebSocket fake
# ---------------------------------------------------------------------------

from fastapi import WebSocket

@app.websocket("/ws/metrics")
async def ws_metrics(websocket: WebSocket):
    """Fake WebSocket — accepts connection, streams fake metric frames."""
    await websocket.accept()
    try:
        while True:
            frame = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "gpu_util": round(random.uniform(78.0, 94.0), 1),
                "loss_run047": round(0.3821 - random.uniform(0, 0.002), 4),
                "loss_run046": round(0.5103 - random.uniform(0, 0.003), 4),
                "active_jobs": 2,
            }
            await websocket.send_json(frame)
            await asyncio.sleep(5)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Routes — Fake crash endpoint
# ---------------------------------------------------------------------------

@app.get("/debug/crash")
async def debug_crash():
    """Fake 500 that leaks internal IP (realism anchor)."""
    return JSONResponse(
        status_code=500,
        content={
            "error": 'psycopg2.OperationalError: could not connect to server on host '
                     '"db-prod-01.neuro.internal" (10.31.4.22):5432'
        },
    )


@app.get("/debug/logs")
async def debug_logs():
    """Fake log viewer — access is logged as a high-interest event."""
    await _jitter()
    return JSONResponse(
        status_code=403,
        content={"detail": "Log viewer requires VPN access. Contact #ai-infra."},
    )


# ---------------------------------------------------------------------------
# Routes — Frontend pages (Jinja2 HTML)
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def login_page(request: Request):
    """Login page — deceptive entry point with SSO lure."""
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/auth/logout")
async def auth_logout(request: Request):
    """Logout — clears session cookie and redirects to login."""
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie("nro_session")
    return response


def _session_ok(request: Request) -> bool:
    return bool(request.cookies.get("nro_session"))


# Sensitive paths where unauthenticated direct access is a strong recon signal
_SENSITIVE_UNAUTH_PATHS = {"/admin", "/settings/api-keys", "/jobs/new"}

def _log_unauth_access(request: Request) -> None:
    """Fire a no-cooldown event when an attacker hits a sensitive page with no valid session."""
    src_ip = request.headers.get("X-Real-IP") or (request.client.host if request.client else "unknown")
    event: dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": "http.unauth.sensitive_access",
        "src_ip": src_ip,
        "src_port": None,
        "dst_port": 8080,
        "username": None,
        "password": None,
        "payload": json.dumps({
            "path": request.url.path,
            "ua": request.headers.get("user-agent", "")[:200],
        }),
        "raw_log": None,
        "session_id": None,
        "geo_country": None,
        "geo_country_code": None,
        "geo_city": None,
        "geo_asn": None,
        "geo_org": None,
    }
    asyncio.create_task(_log_event_async(event))
    asyncio.create_task(_push_honeydash_async(event, "Unauth Sensitive Access"))


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not _session_ok(request):
        return RedirectResponse(url="/", status_code=302)
    jobs = FAKE_JOBS
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "jobs": jobs,
        "models": FAKE_MODELS[:3],
    })


@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    if not _session_ok(request):
        _log_unauth_access(request)
        return RedirectResponse(url="/", status_code=302)
    session_id = request.cookies.get("nro_session", "")
    with _SESSION_USER_LOCK:
        current_user = _SESSION_USER_MAP.get(session_id, "m.chen@neuro.ai")
    return templates.TemplateResponse("admin.html", {"request": request, "current_user": current_user})


# ---------------------------------------------------------------------------
# Routes — Common web files
# ---------------------------------------------------------------------------

@app.get("/favicon.ico")
async def favicon():
    ico_path = APP_DIR / "static" / "favicon.ico"
    if ico_path.exists():
        return FileResponse(str(ico_path))
    return Response(status_code=204)


@app.get("/manifest.json")
async def manifest():
    return {
        "name": "Neuro — AI Training Platform",
        "short_name": "Neuro",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#0f1117",
        "theme_color": "#6366f1",
    }


@app.get("/apple-touch-icon.png")
async def apple_touch_icon():
    return Response(status_code=204)


@app.get("/.git/config")
async def git_config(request: Request):
    return PlainTextResponse(
        '[core]\n'
        '\trepositoryformatversion = 0\n'
        '\tfilemode = true\n'
        '\tbare = false\n'
        '\tlogallrefupdates = true\n'
        '[remote "origin"]\n'
        '\turl = https://support:CyveeraSup!2024@gitlab.cyveera.internal/neuro/neuro-platform.git\n'
        '\tfetch = +refs/heads/*:refs/remotes/origin/*\n'
        '[branch "main"]\n'
        '\tremote = origin\n'
        '\tmerge = refs/heads/main\n'
        '[branch "staging"]\n'
        '\tremote = origin\n'
        '\tmerge = refs/heads/staging\n'
        '[user]\n'
        '\tname = Priya Nair\n'
        '\temail = priya.nair@cyveera.ai\n'
        '[credential]\n'
        '\thelper = store\n'
    )


@app.get("/.git/HEAD")
async def git_head(request: Request):
    return PlainTextResponse("ref: refs/heads/main\n")


# ---------------------------------------------------------------------------
# Routes — Canary CSV download (Feature: honeytoken data export)
# ---------------------------------------------------------------------------

@app.get("/api/v1/data/exports/download")
async def data_export_download(request: Request, file: str = ""):
    """
    Honeytoken data export — serves CANARY_CSV_CONTENT as a direct download.

    The file contains two independent out-of-band tripwires:
      1. AWS canarytoken key (AKIAYZM57LXRGIYTCOUV) — fires on any AWS API call.
      2. DNS canarytoken hostname in the metrics_endpoint column — fires on DNS
         resolution, which most tools (curl, requests, pandas) do automatically
         before deciding whether to fetch a URL.

    The passwords (NeuroML2024!, Cyvera2026!, admin) match Cowrie userdb.txt
    exactly so sentinel._check_credential_replay() fires when the attacker
    pivots from this CSV to SSH.

    Event logged by middleware as http.lure.data_exfil (overriding the
    standard path-cat label) via a custom header signal — same pattern as
    the lure-credential flow.

    The ?file= query parameter is accepted for realism (attacker expects a
    file selector) but is never used to open a real file — only the constant
    CANARY_CSV_CONTENT is served.
    """
    await _jitter()
    file_key = file if file in _LURE_FILE_REGISTRY else "workspace-export-2026-05-31.csv"
    content_bytes, mime = _LURE_FILE_REGISTRY[file_key]
    # Signal to middleware: override event_type → http.lure.data_exfil.
    # Middleware strips this header before the response reaches the client.
    resp = Response(
        content=content_bytes,
        media_type=mime,
        headers={
            "Content-Disposition": f'attachment; filename="{file_key}"',
            "X-Lure-Data-Exfil": "true",
        },
    )
    return resp


# ---------------------------------------------------------------------------
# Routes — Canarytoken out-of-band callback receiver (Feature: canarytoken)
# ---------------------------------------------------------------------------

@app.post("/api/v1/canarytoken/callback")
async def canarytoken_callback(request: Request):
    """
    Receives canarytokens.org webhook POSTs when a token embedded in the
    canary CSV fires on the attacker's own machine.

    canarytokens.org webhook payload (documented at canarytokens.org/generate):
    {
        "channel": "DNS" | "HTTP" | "AWS",
        "token_type": "dns" | "http" | "aws_keys",
        "src_ip": "<attacker real IP>",           # real IP on attacker's machine
        "time": "<ISO timestamp>",
        "memo": "<memo set when token was registered>",
        "geo_info": {
            "city": "...", "country": "...", "org": "...", "asn": "...",
            "hostname": "..."
        },
        "useragent": "<tool string>",             # often reveals which tool
        "additional_info": {                      # AWS tokens only
            "aws_key_used": "<access key>",
            "last_used_region": "us-east-1",
            "event_name": "GetCallerIdentity",
            "aws_account_id": "...",
            "error_code": "..."
        }
    }

    SETUP:
      1. Register a token at https://canarytokens.org/generate
         - "DNS" type: embed the subdomain as metrics_endpoint hostname in the CSV.
         - Set Webhook URL to: http://neuro.cyveera.com:8081/api/v1/canarytoken/callback
         - Memo: "neuro-team-export-csv-2026"
      2. The same webhook URL works for the AWS key token if you re-register it.
      3. Verify the endpoint is reachable: curl -s -X POST http://neuro.cyveera.com:8081/api/v1/canarytoken/callback -H 'Content-Type: application/json' -d '{"channel":"test","src_ip":"1.2.3.4"}'

    Value: this callback receives the attacker's REAL IP on their own machine
    (not the VPN they used to access the honeypot), the tool they used, and
    the exact timestamp — enabling correlation to the CSV download event in
    PostgreSQL.
    """
    body_bytes = await request.body()
    body_str = body_bytes.decode("utf-8", errors="replace") if body_bytes else "{}"

    try:
        payload = json.loads(body_str)
    except Exception:
        payload = {"raw": body_str[:512]}

    # Extract the attacker's real IP — canarytokens.org sends it in src_ip.
    # If the field is absent (malformed or test request), fall back to the
    # HTTP requester IP (which will be canarytokens.org's own server — acceptable
    # for detecting test fires).
    canary_src_ip = payload.get("src_ip") or _extract_src_ip(request)
    channel = payload.get("channel", "unknown")
    token_type = payload.get("token_type", "unknown")
    user_agent = payload.get("useragent", "")
    memo = payload.get("memo", "")
    geo_info = payload.get("geo_info") or {}
    additional_info = payload.get("additional_info") or {}

    # Build the honeypot event — sensor stays "api" but event_type is distinct
    # so sentinel and HoneyDash both surface it with its own label.
    canary_event: dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": "http.canarytoken.fired",
        "src_ip": canary_src_ip,
        "src_port": None,
        "dst_port": 8080,
        "username": None,
        "password": None,
        "payload": json.dumps({
            "channel": channel,
            "token_type": token_type,
            "memo": memo,
            "useragent": user_agent,
            "geo_info": geo_info,
            "additional_info": additional_info,
            "canarytoken_src_ip": canary_src_ip,
            "note": "out-of-band canarytoken fired — attacker used stolen credential",
        }),
        "raw_log": body_str[:2048],
        "session_id": str(uuid.uuid4()),  # canarytoken fires have no session cookie
        # Geo from GeoIP (attacker's real IP, not honeypot IP)
        **_lookup_geo(canary_src_ip),
    }

    # Log synchronously then push to HoneyDash — this is a high-value event.
    # Run log in executor to avoid blocking the event loop.
    asyncio.create_task(_log_event_async(canary_event))
    if HONEYDASH_URL and SENSOR_API_KEY:
        asyncio.create_task(_push_honeydash_async(canary_event, "Canarytoken Fired"))

    logger.info(
        "canarytoken_fired",
        channel=channel,
        token_type=token_type,
        canary_src_ip=canary_src_ip,
        useragent=user_agent,
        memo=memo,
    )

    # Return 200 — canarytokens.org retries on non-2xx.
    return JSONResponse({"ok": True})


# ---------------------------------------------------------------------------
# Routes — SSRF trap: dataset remote import (Feature 2)
# ---------------------------------------------------------------------------

# SSRF indicators checked in the source_url body field.
# Broader than _SSRF_PATTERNS (which covers path/query strings) because here
# we own the URL parsing and can check all RFC-1918 prefixes precisely.
_REMOTE_IMPORT_SSRF_INDICATORS = [
    "169.254.169.254",     # AWS/Azure/GCP IMDS
    "169.254.170.2",       # ECS metadata
    "metadata.google.internal",
    "metadata.internal",
    "127.",                # loopback (matches 127.0.0.0/8)
    "0.0.0.0",
    "localhost",
    "10.",                 # RFC-1918 10/8
    "192.168.",            # RFC-1918 192.168/16
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",  # RFC-1918 172.16/12
    "::1",                 # IPv6 loopback
    "fd",                  # IPv6 ULA prefix
    "file://",
    "dict://",
    "gopher://",
    "ldap://",
]


@app.post("/api/v1/data/remote-import")
async def data_remote_import(request: Request):
    """
    Dataset ingestion from a remote URL — SSRF trap.

    Real AI platforms (HuggingFace hub, W&B, SageMaker) all offer "load
    dataset from URL / S3 URI" features.  This is the most natural SSRF
    surface on an ML platform; attackers familiar with cloud tooling will
    try http://169.254.169.254/latest/meta-data/iam/security-credentials/
    immediately.

    Behaviour:
      - Parse the source_url from the JSON body.
      - Check against _REMOTE_IMPORT_SSRF_INDICATORS (case-insensitive).
      - If SSRF detected:
          * Log http.snare.ssrf_attempt with exact URL and original path.
          * Push to HoneyDash as "SSRF Attempt".
          * Wait 800ms (simulated backend fetch delay).
          * Return a fake queued-ingestion job response — attacker believes
            the request was executed (deepen engagement, gather follow-up probes).
      - If NOT SSRF (external URL, likely enumeration of the endpoint):
          * Log as http.probe.remote_import (lure access).
          * Same fake success response.

    SAFETY: this handler NEVER makes an outbound HTTP request.  The URL is
    only inspected as a string.  No subprocess, no socket, no httpx call.

    Expected body:
      {"source_url": "...", "dataset_name": "...", "format": "parquet|csv|jsonl"}
    """
    body_bytes = await request.body()
    body_str = body_bytes.decode("utf-8", errors="replace") if body_bytes else "{}"

    source_url = ""
    dataset_name = ""
    fmt = "parquet"
    try:
        body_json = json.loads(body_bytes)
        source_url = str(body_json.get("source_url") or "")
        dataset_name = str(body_json.get("dataset_name") or "")
        fmt = str(body_json.get("format") or "parquet")
    except Exception:
        pass

    src_ip = _extract_src_ip(request)
    url_lower = source_url.lower()

    is_ssrf = any(indicator.lower() in url_lower for indicator in _REMOTE_IMPORT_SSRF_INDICATORS)

    # Simulate backend fetch/validation latency — adds realism and makes the
    # attacker believe the server actually attempted the request.
    await asyncio.sleep(0.8)

    job_id = f"ingest-{uuid.uuid4().hex[:6]}"

    if is_ssrf:
        # Emit a dedicated SSRF event with the exact URL captured.
        # The middleware will also log the standard http.post.* event; this
        # explicit event gives sentinel a targeted hook for immediate alerting
        # without relying on the general SNARE path-scan.
        ssrf_event: dict[str, Any] = {
            "event_id": str(uuid.uuid4()),
            "created_at": datetime.now(timezone.utc),
            "sensor": "api",
            "event_type": "http.snare.ssrf_attempt",
            "src_ip": src_ip,
            "src_port": request.client.port if request.client else None,
            "dst_port": 8080,
            "username": None,
            "password": None,
            "payload": json.dumps({
                "source_url": source_url[:512],
                "dataset_name": dataset_name[:128],
                "format": fmt[:32],
                "ssrf_detected": True,
                "note": "SSRF attempt via /api/v1/data/remote-import — no outbound request made",
            }),
            "raw_log": body_str[:1024],
            "session_id": request.cookies.get("nro_session") or str(uuid.uuid4()),
            **_lookup_geo(src_ip),
        }
        asyncio.create_task(_log_event_async(ssrf_event))
        if HONEYDASH_URL and SENSOR_API_KEY:
            asyncio.create_task(_push_honeydash_async(ssrf_event, "SSRF Attempt"))
    # else: middleware already logs http.post.v1.data.remote-import as a lure hit.

    return JSONResponse({
        "status": "ingestion_queued",
        "job_id": job_id,
        "estimated_completion": 45,
        "source": source_url[:256],
        "format": fmt,
        "dataset_name": dataset_name or f"import-{job_id}",
    })


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Routes — malware upload capture (Feature: script-upload)
# ---------------------------------------------------------------------------

_UPLOAD_MAX_BYTES = 50 * 1024 * 1024  # 50 MB cap — never execute, just capture

@app.post("/api/v1/training/jobs/script-upload")
async def script_upload(request: Request, file: UploadFile = File(...)):
    """
    Init-script upload endpoint shown on /jobs/new.
    Saves attacker-supplied file to named Docker volume — never executed.
    Fires http.upload.malware_received which bypasses sentinel cooldown.
    """
    src_ip = request.headers.get("X-Real-IP") or request.client.host if request.client else "unknown"
    raw_name = (file.filename or "upload.bin").replace("/", "_").replace("..", "_")
    ts = int(time.time())
    save_name = f"{ts}_{src_ip}_{raw_name}"

    content = await file.read(_UPLOAD_MAX_BYTES + 1)
    if len(content) > _UPLOAD_MAX_BYTES:
        return JSONResponse(
            {"error": "file_too_large", "max_bytes": _UPLOAD_MAX_BYTES},
            status_code=413,
        )

    try:
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        save_path = UPLOAD_DIR / save_name
        await asyncio.to_thread(save_path.write_bytes, content)
        saved = True
    except Exception as exc:
        logger.warning("upload_save_failed", error=str(exc), path=str(UPLOAD_DIR))
        saved = False

    mime = file.content_type or "application/octet-stream"
    upload_event = {
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": "http.upload.malware_received",
        "src_ip": src_ip,
        "src_port": None,
        "dst_port": 8080,
        "username": None,
        "password": None,
        "payload": json.dumps({
            "filename": raw_name,
            "saved_as": save_name if saved else None,
            "size_bytes": len(content),
            "mime_type": mime,
            "saved": saved,
        }),
        "raw_log": None,
        "session_id": request.cookies.get("nro_session"),
        "geo_country": None,
        "geo_country_code": None,
        "geo_city": None,
        "geo_asn": None,
        "geo_org": None,
    }
    asyncio.create_task(_log_event_async(upload_event))
    asyncio.create_task(_push_honeydash_async(upload_event, "Malware Upload"))
    logger.info("upload_captured", filename=save_name, size=len(content), mime=mime, ip=src_ip, saved=saved)

    return JSONResponse({
        "ok": True,
        "job_id": f"job-{uuid.uuid4().hex[:8]}",
        "script": raw_name,
        "status": "queued",
        "message": "Init script accepted. Job queued on neuro-train-01.",
    })


# ---------------------------------------------------------------------------
# Routes — /settings/security and /status (added Round 30)
# ---------------------------------------------------------------------------

@app.get("/settings/security")
async def settings_security_page(request: Request):
    if not _session_ok(request):
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse("settings_security.html", {"request": request})


@app.post("/api/v1/security/mfa/toggle")
async def security_mfa_toggle(request: Request):
    """
    MFA disable endpoint — captures password submitted in modal.
    Always returns 401-equivalent (re-auth required) so flow feels incomplete.
    Password stored in the password column for Sentinel credential replay detection.
    """
    if not _session_ok(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    src_ip = _extract_src_ip(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    attempted_password = str(body.get("password", ""))[:256]
    ev = {
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": "security.mfa_toggle_attempt",
        "src_ip": src_ip,
        "src_port": request.client.port if request.client else None,
        "dst_port": 8080,
        "username": "m.chen@neuro.ai",
        "password": attempted_password if attempted_password else None,
        "payload": json.dumps({
            "attempted_password": attempted_password,
            "duration_hours": body.get("duration_hours", 24),
        }),
        "raw_log": None,
        "session_id": request.cookies.get("nro_session") or str(uuid.uuid4()),
        **_lookup_geo(src_ip),
    }
    _log_event(ev)
    asyncio.create_task(_push_honeydash_async(ev, "MFA Disable Attempt"))
    return JSONResponse(
        {
            "ok": False,
            "mfa_enabled": True,
            "message": "2FA status unchanged — re-authentication required via identity provider.",
        },
        status_code=401,
    )


@app.post("/api/v1/security/session/revoke")
async def security_session_revoke(request: Request):
    """Logs session revocation attempt with session_ref. Returns fake success."""
    if not _session_ok(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    src_ip = _extract_src_ip(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    session_ref = str(body.get("session_ref", ""))[:64]
    ev = {
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": "security.session_revoke_attempt",
        "src_ip": src_ip,
        "src_port": request.client.port if request.client else None,
        "dst_port": 8080,
        "username": None,
        "password": None,
        "payload": json.dumps({"session_ref": session_ref}),
        "raw_log": None,
        "session_id": request.cookies.get("nro_session") or str(uuid.uuid4()),
        **_lookup_geo(src_ip),
    }
    _log_event(ev)
    asyncio.create_task(_push_honeydash_async(ev, "Session Revoke Probe"))
    return JSONResponse({"ok": True, "revoked": True, "session_ref": session_ref})


@app.post("/api/v1/security/allowlist/add")
async def security_allowlist_add(request: Request):
    """
    Captures attacker-submitted CIDR — reveals their own network block or
    their target network intelligence. Logs to honeypot_events.
    """
    if not _session_ok(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    src_ip = _extract_src_ip(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    cidr = str(body.get("cidr", ""))[:64]
    label = str(body.get("label", ""))[:128]
    ev = {
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": "security.allowlist_probe",
        "src_ip": src_ip,
        "src_port": request.client.port if request.client else None,
        "dst_port": 8080,
        "username": None,
        "password": None,
        "payload": json.dumps({"cidr": cidr, "label": label}),
        "raw_log": None,
        "session_id": request.cookies.get("nro_session") or str(uuid.uuid4()),
        **_lookup_geo(src_ip),
    }
    _log_event(ev)
    asyncio.create_task(_push_honeydash_async(ev, "Allowlist Probe"))
    return JSONResponse({"ok": True, "entries": 4, "cidr": cidr, "effective_at": "immediately"})


@app.post("/api/v1/security/keys/rotate")
async def security_keys_rotate(request: Request):
    """Logs key rotation attempt. Returns fake rotation result with sample key prefix."""
    if not _session_ok(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    src_ip = _extract_src_ip(request)
    ev = {
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": "security.key_rotation_attempt",
        "src_ip": src_ip,
        "src_port": request.client.port if request.client else None,
        "dst_port": 8080,
        "username": None,
        "password": None,
        "payload": json.dumps({"action": "rotate_all_keys"}),
        "raw_log": None,
        "session_id": request.cookies.get("nro_session") or str(uuid.uuid4()),
        **_lookup_geo(src_ip),
    }
    _log_event(ev)
    asyncio.create_task(_push_honeydash_async(ev, "Key Rotation Probe"))
    sample_suffix = "".join(random.choices("abcdef0123456789", k=16))
    return JSONResponse({
        "rotated": True,
        "count": 4,
        "new_prefix": "nro-",
        "sample_key": f"nro-{sample_suffix}",
        "effective_at": "2026-06-05T00:00:00Z",
        "note": "Old keys invalidated. Update CI/CD pipelines and training-node automation scripts.",
    })


@app.get("/api/v1/security/audit-log")
async def security_audit_log(request: Request):
    """Returns fixture audit log. Access itself is a high-value interest signal."""
    if not _session_ok(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    src_ip = _extract_src_ip(request)
    ev = {
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": "security.audit_log_viewed",
        "src_ip": src_ip,
        "src_port": request.client.port if request.client else None,
        "dst_port": 8080,
        "username": None,
        "password": None,
        "payload": json.dumps({"action": "audit_log_export_request"}),
        "raw_log": None,
        "session_id": request.cookies.get("nro_session") or str(uuid.uuid4()),
        **_lookup_geo(src_ip),
    }
    _log_event(ev)
    asyncio.create_task(_push_honeydash_async(ev, "Audit Log Access"))
    return JSONResponse({
        "entries": [
            {"ts": "2026-06-04T22:09:17Z", "actor": "m.chen@neuro.ai",      "action": "login_success",      "src_ip": "192.168.1.45",  "result": "ok"},
            {"ts": "2026-06-04T18:31:04Z", "actor": "priya.nair@neuro.ai",  "action": "api_key_created",    "src_ip": "192.168.1.48",  "result": "ok"},
            {"ts": "2026-06-04T09:14:22Z", "actor": "m.chen@neuro.ai",      "action": "login_success",      "src_ip": "192.168.1.45",  "result": "ok"},
            {"ts": "2026-06-03T03:14:09Z", "actor": "m.chen@neuro.ai",      "action": "ssh_key_used",       "src_ip": "185.234.219.4", "result": "ok", "flag": "unusual_ip"},
            {"ts": "2026-06-02T16:44:51Z", "actor": "svc-deploy",           "action": "token_refreshed",    "src_ip": "10.31.4.22",    "result": "ok"},
            {"ts": "2026-06-02T11:03:28Z", "actor": "priya.nair@neuro.ai",  "action": "model_deployed",     "src_ip": "192.168.1.48",  "result": "ok"},
            {"ts": "2026-06-01T20:17:43Z", "actor": "svc-deploy",           "action": "pipeline_run",       "src_ip": "10.31.4.22",    "result": "ok"},
            {"ts": "2026-06-01T14:55:09Z", "actor": "m.chen@neuro.ai",      "action": "2fa_verified",       "src_ip": "192.168.1.45",  "result": "ok"},
            {"ts": "2026-05-31T22:09:11Z", "actor": "m.chen@neuro.ai",      "action": "ssh_key_used",       "src_ip": "10.31.4.1",     "result": "ok"},
            {"ts": "2026-05-31T09:41:33Z", "actor": "priya.nair@neuro.ai",  "action": "login_success",      "src_ip": "192.168.1.48",  "result": "ok"},
            {"ts": "2026-05-30T17:28:55Z", "actor": "svc-deploy",           "action": "key_rotation",       "src_ip": "10.31.4.22",    "result": "ok"},
            {"ts": "2026-05-30T08:12:04Z", "actor": "m.chen@neuro.ai",      "action": "workspace_accessed", "src_ip": "192.168.1.45",  "result": "ok"},
            {"ts": "2026-05-29T21:30:47Z", "actor": "priya.nair@neuro.ai",  "action": "dataset_exported",   "src_ip": "192.168.1.48",  "result": "ok"},
            {"ts": "2026-05-29T14:05:11Z", "actor": "svc-deploy",           "action": "token_refreshed",    "src_ip": "10.31.4.22",    "result": "ok"},
            {"ts": "2026-05-28T07:44:29Z", "actor": "m.chen@neuro.ai",      "action": "login_success",      "src_ip": "192.168.1.45",  "result": "ok"},
            {"ts": "2026-05-27T19:22:18Z", "actor": "priya.nair@neuro.ai",  "action": "api_key_revoked",    "src_ip": "192.168.1.48",  "result": "ok"},
            {"ts": "2026-05-27T11:08:53Z", "actor": "m.chen@neuro.ai",      "action": "settings_changed",   "src_ip": "192.168.1.45",  "result": "ok"},
            {"ts": "2026-05-26T16:50:37Z", "actor": "svc-deploy",           "action": "pipeline_run",       "src_ip": "10.31.4.22",    "result": "ok"},
            {"ts": "2026-05-26T09:31:04Z", "actor": "priya.nair@neuro.ai",  "action": "login_success",      "src_ip": "192.168.1.48",  "result": "ok"},
            {"ts": "2026-05-25T22:17:42Z", "actor": "m.chen@neuro.ai",      "action": "2fa_verified",       "src_ip": "192.168.1.45",  "result": "ok"},
        ]
    })


@app.get("/status")
async def status_page(request: Request):
    """Public status page — no session gate. Maximum scanner exposure."""
    return templates.TemplateResponse("status.html", {"request": request})


# ===========================================================================
# API v2 — SlapDash SPA Backend
# All routes under /api/v2/ serve the React SPA (SlapDash-Frontend).
# Session auth uses nro_session_v2 cookie (NOT nro_session — separate keyspace
# to avoid middleware collision; see slapdash-backend.md §3.1 BLOCKER-1).
# ===========================================================================

import re
import io
import tarfile
import ipaddress
import secrets as _secrets
import warnings

# Attempt to import optional v2 dependencies — fail loudly at startup if missing
# Use bcrypt directly (passlib 1.7.4 is incompatible with bcrypt >= 4.0.0).
try:
    import bcrypt as _bcrypt_lib

    def _bcrypt_hash(password: str, rounds: int = 12) -> str:
        return _bcrypt_lib.hashpw(password.encode(), _bcrypt_lib.gensalt(rounds)).decode()

    def _bcrypt_verify(password: str, hashed: str) -> bool:
        try:
            return _bcrypt_lib.checkpw(password.encode(), hashed.encode())
        except Exception:
            return False

    _BCRYPT_AVAILABLE = True
except ImportError:
    _BCRYPT_AVAILABLE = False
    warnings.warn("bcrypt not installed — v2 auth will fail; add bcrypt to requirements.txt", stacklevel=1)

try:
    import user_agents as _user_agents_lib
    _UA_AVAILABLE = True
except ImportError:
    _UA_AVAILABLE = False

try:
    from fpdf import FPDF as _FPDF
    _FPDF_AVAILABLE = True
except ImportError:
    _FPDF_AVAILABLE = False
    warnings.warn("fpdf2 not installed — invoice PDF will not be served; add fpdf2==2.7.9 to requirements.txt", stacklevel=1)

# ---------------------------------------------------------------------------
# v2 constants
# ---------------------------------------------------------------------------

_COOKIE_NAME_V2 = "nro_session_v2"

# Lure credentials for the SlapDash SPA.  bcrypt hashes are generated at
# container startup by _seed_v2_tables().  The plaintext values are referenced
# here ONLY so the login handler can call _bcrypt.verify() against the DB hash.
LURE_CREDS_V2: dict[str, dict] = {
    "j.smith@vantarahealth.com":  {"password": "Vantara2026!",      "role": "customer_user"},
    "alice.wong@merisol.io":      {"password": "Merisol@Secure99",   "role": "customer_admin"},
    "support@cyveera.ai":         {"password": "CyveeraSup!2024",    "role": "cyveera_support"},
}

VALID_API_KEY_SCOPES: set[str] = {"read:all", "write:models", "write:datasets", "admin"}

# SSH public key validation regex (spec §4.3 POST /api/v2/profile/ssh-keys)
_SSH_KEY_RE = re.compile(
    r"^ssh-(rsa|ed25519|dss|ecdsa)\s+[A-Za-z0-9+/]{20,}[=]{0,2}(\s+.*)?$"
)

# Operator must register a URL canarytoken at canarytokens.org, set the callback
# to an external URL, then update this constant and rebuild the container.
# Until set, invoice PDFs are served without the canarytoken pixel.
_INVOICE_CANARY_URL: str = "http://canarytokens.com/about/stuff/feedback/siv27030vusp1lpvu52lrrq1h/contact.php"

# ---------------------------------------------------------------------------
# Honeytoken tracking — module-level set populated at startup + on creation
# ---------------------------------------------------------------------------

_CREATED_HONEYTOKENS: set[str] = set()
_HONEYTOKEN_LOCK = threading.Lock()

# ---------------------------------------------------------------------------
# Async Redis helper (separate from sync _get_redis())
# ---------------------------------------------------------------------------

import redis.asyncio as aioredis_lib

_async_redis_client: Optional[aioredis_lib.Redis] = None


def _get_redis_async() -> aioredis_lib.Redis:
    """Returns a module-level async Redis client.  All callers must await operations."""
    global _async_redis_client
    if _async_redis_client is None:
        _async_redis_client = aioredis_lib.from_url(
            REDIS_URL,
            socket_connect_timeout=3,
            socket_timeout=3,
            decode_responses=True,
        )
    return _async_redis_client

# ---------------------------------------------------------------------------
# Workspace key helper
# ---------------------------------------------------------------------------

def _workspace_key(src_ip: str, email: str) -> str:
    """Stable workspace ID for this (IP, credential) pair."""
    raw = f"{src_ip.split('/')[0]}:{email}"
    return "atk_" + hashlib.sha256(raw.encode()).hexdigest()[:16]

# ---------------------------------------------------------------------------
# v2 session helpers
# ---------------------------------------------------------------------------

async def _v2_session_required(request: Request) -> dict:
    """Read v2 session from Redis.  Returns session dict or raises HTTPException(401).
    Reads nro_session_v2 cookie (NOT nro_session) to avoid middleware collision.
    All Redis operations are awaited — _get_redis_async() returns an async client."""
    session_id = request.cookies.get(_COOKIE_NAME_V2)
    if not session_id:
        raise HTTPException(status_code=401, detail={"error": "unauthorized"})
    raw = await _get_redis_async().get(f"session:v2:{session_id}")
    if not raw:
        raise HTTPException(status_code=401, detail={"error": "unauthorized"})
    # Inactivity reset — extend TTL on every authenticated request
    await _get_redis_async().expire(f"session:v2:{session_id}", 1800)
    return json.loads(raw)


async def _v2_require_support(request: Request) -> dict:
    """Session gate restricted to cyveera_support role.  Raises 403 for wrong role."""
    session = await _v2_session_required(request)
    if session.get("role") != "cyveera_support":
        raise HTTPException(status_code=403, detail={"error": "forbidden"})
    return session


def _v2_csrf_validate(session: dict, body_dict: dict) -> None:
    """Validates _csrf token in body against session's csrf_token.  Raises 403 on mismatch."""
    expected = session.get("csrf_token", "")
    submitted = body_dict.get("_csrf", "")
    if expected and submitted and expected != submitted:
        raise HTTPException(status_code=403, detail={"error": "csrf_mismatch"})


async def _v2_session_patch(request: Request, updates: dict) -> None:
    """Merge `updates` into the current v2 session and write back to Redis."""
    session_id = request.cookies.get(_COOKIE_NAME_V2)
    if not session_id:
        return
    r = _get_redis_async()
    raw = await r.get(f"session:v2:{session_id}")
    if not raw:
        return
    session = json.loads(raw)
    session.update(updates)
    await r.set(f"session:v2:{session_id}", json.dumps(session), ex=1800)


_ALLOWLIST_DEFAULTS = [
    {"cidr": "192.168.1.0/24", "description": "Office network (Boston)", "active": True},
    {"cidr": "10.31.0.0/16",   "description": "Internal cluster",        "active": True},
]


async def _v2_check_rate_limit(src_ip: str) -> None:
    """Redis sorted-set rate limiter for auth endpoints.  Raises 429 on > 10 attempts/60s."""
    key = f"ratelimit:auth:{src_ip}"
    now_ms = int(time.time() * 1000)
    try:
        r = _get_redis_async()
        await r.zadd(key, {str(uuid.uuid4()): now_ms})
        await r.zremrangebyscore(key, 0, now_ms - 60_000)
        count = await r.zcard(key)
        await r.expire(key, 120)
        if count > 10:
            _log_event({
                "event_id": str(uuid.uuid4()),
                "created_at": datetime.now(timezone.utc),
                "sensor": "api",
                "event_type": "http.auth.rate_limited",
                "src_ip": src_ip,
                "src_port": None,
                "dst_port": 8080,
                "username": None,
                "password": None,
                "payload": json.dumps({"rate_limit_count": count}),
                "raw_log": None,
                "session_id": None,
                "geo_country": None, "geo_country_code": None,
                "geo_city": None, "geo_asn": None, "geo_org": None,
            })
            raise HTTPException(
                status_code=429,
                detail={"error": "rate_limit_exceeded", "message": "Too many login attempts."},
                headers={"Retry-After": "60"},
            )
    except HTTPException:
        raise
    except Exception:
        pass  # Never block auth on Redis failure


def _parse_user_agent(raw_ua: str) -> str:
    """Return a human-readable 'Browser on OS' string from a raw UA."""
    if not _UA_AVAILABLE or not raw_ua:
        return "Unknown on Unknown"
    try:
        ua = _user_agents_lib.parse(raw_ua)
        browser = ua.browser.family or "Unknown"
        os_name = ua.os.family or "Unknown OS"
        return f"{browser} on {os_name}"
    except Exception:
        return "Unknown on Unknown"


# ---------------------------------------------------------------------------
# Database schema and seed helpers (v2)
# ---------------------------------------------------------------------------

def _seed_v2_tables() -> None:
    """
    Idempotent seed — runs on every container start via startup_v2().
    CREATE TABLE IF NOT EXISTS + ON CONFLICT DO NOTHING make re-runs safe.
    Uses its own dedicated autocommit connection — does NOT touch shared _pg_conn.
    """
    if not POSTGRES_DSN:
        logger.warning("seed_v2_tables_skipped", reason="POSTGRES_DSN not set")
        return
    conn = None
    try:
        conn = psycopg2.connect(POSTGRES_DSN)
        conn.set_session(autocommit=True)
        cur = conn.cursor()

        # --- DDL ---
        cur.execute("""
            CREATE TABLE IF NOT EXISTS workspace_members (
                id              SERIAL PRIMARY KEY,
                workspace_id    TEXT NOT NULL DEFAULT 'vantarahealth',
                email           TEXT NOT NULL UNIQUE,
                display_name    TEXT NOT NULL,
                role            TEXT NOT NULL,
                password_hash   TEXT NOT NULL,
                last_active     TIMESTAMPTZ
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS training_runs (
                id              SERIAL PRIMARY KEY,
                workspace_id    TEXT NOT NULL DEFAULT 'vantarahealth',
                run_id          TEXT NOT NULL,
                model_name      TEXT NOT NULL,
                status          TEXT NOT NULL,
                duration_min    INTEGER,
                gpu_hours       NUMERIC(8,1),
                started_by      TEXT NOT NULL,
                started_at      TIMESTAMPTZ NOT NULL,
                error_log       TEXT,
                UNIQUE (workspace_id, run_id)
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS models (
                id              SERIAL PRIMARY KEY,
                workspace_id    TEXT NOT NULL DEFAULT 'vantarahealth',
                model_name      TEXT NOT NULL,
                version         TEXT NOT NULL,
                customer        TEXT NOT NULL,
                status          TEXT NOT NULL,
                drift_score     NUMERIC(4,2) NOT NULL,
                last_check      TIMESTAMPTZ NOT NULL,
                UNIQUE (workspace_id, model_name)
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS datasets (
                id              SERIAL PRIMARY KEY,
                workspace_id    TEXT NOT NULL DEFAULT 'vantarahealth',
                name            TEXT NOT NULL,
                source          TEXT NOT NULL,
                format          TEXT NOT NULL,
                row_count       TEXT NOT NULL,
                size_display    TEXT NOT NULL,
                uploaded_at     DATE NOT NULL,
                tags            TEXT[] NOT NULL DEFAULT '{}',
                UNIQUE (workspace_id, name)
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                id              SERIAL PRIMARY KEY,
                workspace_id    TEXT NOT NULL DEFAULT 'vantarahealth',
                severity        TEXT NOT NULL,
                title           TEXT NOT NULL,
                body            TEXT NOT NULL,
                created_at      TIMESTAMPTZ NOT NULL,
                is_read         BOOLEAN NOT NULL DEFAULT false,
                UNIQUE (workspace_id, title)
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id              SERIAL PRIMARY KEY,
                workspace_id    TEXT NOT NULL DEFAULT 'vantarahealth',
                name            TEXT NOT NULL,
                key_prefix      TEXT NOT NULL,
                key_masked      TEXT NOT NULL,
                key_full        TEXT NOT NULL,
                scope           TEXT NOT NULL,
                created_at      DATE NOT NULL,
                last_used_at    DATE
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS attacker_workspaces (
                workspace_id    TEXT PRIMARY KEY,
                src_ip          TEXT NOT NULL,
                email           TEXT NOT NULL,
                created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                event_count     INTEGER NOT NULL DEFAULT 0
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS workspace_profiles (
                workspace_id    TEXT PRIMARY KEY,
                full_name       TEXT NOT NULL DEFAULT '',
                display_name    TEXT NOT NULL DEFAULT '',
                timezone        TEXT NOT NULL DEFAULT 'America/New_York',
                language        TEXT NOT NULL DEFAULT 'English (US)',
                updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS workspace_ssh_keys (
                id              SERIAL PRIMARY KEY,
                workspace_id    TEXT NOT NULL,
                name            TEXT NOT NULL,
                key_full        TEXT NOT NULL,
                fingerprint     TEXT NOT NULL,
                added_at        DATE NOT NULL DEFAULT CURRENT_DATE,
                last_used_at    DATE
            )
        """)

        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS attacker_workspaces_ip_email
                ON attacker_workspaces (src_ip, email)
        """)

        # --- Seed: workspace_members ---
        if _BCRYPT_AVAILABLE:
            for email, cred in LURE_CREDS_V2.items():
                ph = _bcrypt_hash(cred["password"], rounds=12)
                dname = {
                    "j.smith@vantarahealth.com": "Jordan Smith",
                    "alice.wong@merisol.io": "Alice Wong",
                    "support@cyveera.ai": "Cyveera Support",
                }.get(email, email)
                cur.execute("""
                    INSERT INTO workspace_members
                        (workspace_id, email, display_name, role, password_hash)
                    VALUES ('vantarahealth', %s, %s, %s, %s)
                    ON CONFLICT (email) DO NOTHING
                """, (email, dname, cred["role"], ph))

        # --- Seed: training_runs ---
        _RUNS_SEED = [
            ("run-20260609-001", "vantara-risk-v3",     "Queued",    None,  None,  "svc-deploy",  "2026-06-09 07:00:00+00"),
            ("run-20260608-002", "vantara-risk-v3",     "Running",   None,  None,  "j.smith",     "2026-06-08 09:14:00+00"),
            ("run-20260607-019", "merisol-nlp-v2",      "Completed", 704,   94.0,  "alice.wong",  "2026-06-07 22:31:00+00"),
            ("run-20260607-018", "quelaris-embed-001",  "Completed", 362,   48.3,  "svc-deploy",  "2026-06-07 14:08:00+00"),
            ("run-20260606-031", "lumira-clf-v4",       "Failed",    23,    3.1,   "j.smith",     "2026-06-06 03:47:00+00"),
            ("run-20260605-044", "ardentix-llm-ft",     "Completed", 1338,  178.4, "alice.wong",  "2026-06-05 11:00:00+00"),
            ("run-20260604-011", "denova-risk-v1",      "Completed", 547,   72.9,  "svc-deploy",  "2026-06-04 16:22:00+00"),
            ("run-20260603-007", "vantara-risk-v3",     "Completed", 711,   94.8,  "j.smith",     "2026-06-03 08:45:00+00"),
            ("run-20260602-041", "ardentix-llm-ft",     "Failed",    67,    8.6,   "j.smith",     "2026-06-02 22:14:00+00"),
            ("run-20260601-033", "merisol-nlp-v2",      "Completed", 655,   87.4,  "alice.wong",  "2026-06-01 19:02:00+00"),
        ]
        for row in _RUNS_SEED:
            cur.execute("""
                INSERT INTO training_runs
                    (workspace_id, run_id, model_name, status, duration_min,
                     gpu_hours, started_by, started_at)
                VALUES ('vantarahealth', %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (workspace_id, run_id) DO NOTHING
            """, row)

        # --- Seed: models ---
        _MODELS_SEED = [
            ("vantara-risk-v3",    "v3.2.1", "Vantara Health", "Healthy",     0.04, "2026-06-08 08:00:00+00"),
            ("merisol-nlp-v2",     "v2.0.9", "Merisol",        "Drift Alert", 0.31, "2026-06-07 22:00:00+00"),
            ("quelaris-embed-001", "v1.1.4", "Quelaris",       "Healthy",     0.07, "2026-06-08 06:00:00+00"),
            ("ardentix-llm-ft",    "v0.8.2", "Ardentix",       "Degraded",    0.18, "2026-06-08 04:00:00+00"),
            ("lumira-clf-v4",      "v4.0.1", "Lumira",         "Healthy",     0.02, "2026-06-08 07:30:00+00"),
        ]
        for row in _MODELS_SEED:
            cur.execute("""
                INSERT INTO models
                    (workspace_id, model_name, version, customer, status, drift_score, last_check)
                VALUES ('vantarahealth', %s, %s, %s, %s, %s, %s)
                ON CONFLICT (workspace_id, model_name) DO NOTHING
            """, row)

        # --- Seed: datasets ---
        _DS_SEED = [
            ("vantara-biometric-train-v3",  "S3 (cyvera-ml-artifacts)", "Parquet", "2,841,204", "4.1 GB",  "2026-05-22", ["CONFIDENTIAL", "PHI"]),
            ("merisol-feedback-embeddings",  "HuggingFace Hub",          "JSONL",   "890,441",   "1.2 GB",  "2026-05-18", ["RESTRICTED"]),
            ("internal-slack-corpus-Q1",     "Internal export",          "JSONL",   "4,102,887", "8.7 GB",  "2026-04-30", ["INTERNAL"]),
            ("synthetic-pii-redacted-v4",    "Quelaris warehouse",       "CSV",     "1,200,000", "340 MB",  "2026-04-14", ["PUBLIC"]),
            ("quelaris-embed-baseline",      "Remote URL import",        "Parquet", "501,990",   "620 MB",  "2026-03-28", ["RESEARCH"]),
        ]
        for row in _DS_SEED:
            cur.execute("""
                INSERT INTO datasets
                    (workspace_id, name, source, format, row_count, size_display, uploaded_at, tags)
                VALUES ('vantarahealth', %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (workspace_id, name) DO NOTHING
            """, (row[0], row[1], row[2], row[3], row[4], row[5], row[6]))

        # --- Seed: notifications ---
        _NOTIF_SEED = [
            ("critical", "Model drift threshold exceeded: merisol-nlp-v2",
             "Model merisol-nlp-v2 drift score reached 0.31, exceeding the 0.25 threshold. Immediate review recommended.",
             "2026-06-07 22:04:00+00"),
            ("warning",  "Dataset schema mismatch: internal-slack-corpus-Q1",
             "Ingestion pipeline detected unexpected null fields in column 'user_id'. Validation paused.",
             "2026-06-06 11:43:00+00"),
            ("warning",  "GPU node degraded: neuro-train-01",
             "Node neuro-train-01 (10.31.4.22) reported elevated memory pressure: 94% VRAM utilization.",
             "2026-06-06 04:17:00+00"),
            ("critical", "Billing limit approaching: VantaraHealth workspace",
             "Your workspace has consumed 87% of the monthly GPU quota. Upgrade or reduce usage to avoid suspension.",
             "2026-06-05 09:00:00+00"),
            ("info",     "Training run completed: run-20260605-044",
             "ardentix-llm-ft completed successfully. Duration: 1338 min. GPU hours: 178.4.",
             "2026-06-05 09:18:00+00"),
            ("critical", "Unauthorized login attempt: 185.234.219.4",
             "Repeated failed login attempts from 185.234.219.4 have been detected. IP has been flagged.",
             "2026-06-04 14:32:00+00"),
            ("warning",  "SSO authentication degraded",
             "Google Workspace SSO is experiencing elevated latency (avg 4.2s). Fallback to local credentials is available.",
             "2026-06-03 18:44:00+00"),
            ("info",     "New team member added: support@cyveera.ai",
             "Cyveera support account has been granted temporary access to your workspace for session duration of 48 hours. This access was requested via your support ticket #41291.",
             "2026-05-31 10:00:00+00"),
        ]
        for row in _NOTIF_SEED:
            cur.execute("""
                INSERT INTO notifications
                    (workspace_id, severity, title, body, created_at)
                VALUES ('vantarahealth', %s, %s, %s, %s)
                ON CONFLICT (workspace_id, title) DO NOTHING
            """, row)

        # --- Seed: api_keys ---
        _APIKEY_SEED = [
            ("Production read-only", "nro_sk_4a7f", "nro_sk_4a7f...b291",
             "nro_sk_4a7f9c3d8e2b1a6f5d4c7b8e9a0f3d2c",
             "read:runs,read:models", "2026-03-14", "2026-06-08"),
            ("CI/CD pipeline",       "nro_sk_8c2e", "nro_sk_8c2e...f047",
             "nro_sk_8c2e1b9d3a4f7c5d8e2b1a6f3d9c4e7f",
             "read:all,write:metrics", "2026-04-01", "2026-06-09"),
            ("Legacy integration",   "nro_sk_1d9b", "nro_sk_1d9b...0e33",
             "nro_sk_1d9b3f5a7c2e4b6d8a1c3f5e7b9d0a2c",
             "admin", "2025-11-12", "2026-05-30"),
        ]
        for row in _APIKEY_SEED:
            cur.execute("""
                INSERT INTO api_keys
                    (workspace_id, name, key_prefix, key_masked, key_full,
                     scope, created_at, last_used_at)
                VALUES ('vantarahealth', %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING
            """, row)
            # Pre-load honeytoken set
            with _HONEYTOKEN_LOCK:
                _CREATED_HONEYTOKENS.add(row[3])

        cur.close()
        logger.info("seed_v2_tables_complete")
    except Exception as exc:
        logger.error("seed_v2_tables_error", error=str(exc))
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Per-attacker workspace seeding helper
# ---------------------------------------------------------------------------

def _seed_workspace(cur, workspace_id: str) -> None:
    """Copy seed rows from vantarahealth template into a new attacker workspace.
    Called inside an autocommit connection cursor.  Never copies the id SERIAL column."""
    cur.execute("""
        INSERT INTO training_runs
            (workspace_id, run_id, model_name, status, duration_min,
             gpu_hours, started_by, started_at, error_log)
        SELECT %s, run_id, model_name, status, duration_min,
               gpu_hours, started_by, started_at, error_log
        FROM training_runs WHERE workspace_id = 'vantarahealth'
    """, (workspace_id,))

    cur.execute("""
        INSERT INTO models
            (workspace_id, model_name, version, customer, status,
             drift_score, last_check)
        SELECT %s, model_name, version, customer, status,
               drift_score, last_check
        FROM models WHERE workspace_id = 'vantarahealth'
    """, (workspace_id,))

    cur.execute("""
        INSERT INTO datasets
            (workspace_id, name, source, format, row_count,
             size_display, uploaded_at, tags)
        SELECT %s, name, source, format, row_count,
               size_display, uploaded_at, tags
        FROM datasets WHERE workspace_id = 'vantarahealth'
    """, (workspace_id,))

    cur.execute("""
        INSERT INTO notifications
            (workspace_id, severity, title, body, created_at, is_read)
        SELECT %s, severity, title, body, created_at, is_read
        FROM notifications WHERE workspace_id = 'vantarahealth'
        ON CONFLICT (workspace_id, title) DO NOTHING
    """, (workspace_id,))

    # Seed API keys with workspace-unique values derived from workspace_id + key name
    _KEY_SEED_NAMES = [
        ("Production read-only",  "read:runs,read:models",  "2026-03-14", "2026-06-08"),
        ("CI/CD pipeline",        "read:all,write:metrics", "2026-04-01", "2026-06-09"),
        ("Legacy integration",    "admin",                  "2025-11-12", "2026-05-30"),
    ]
    for (name, scope, created, last_used) in _KEY_SEED_NAMES:
        h = hashlib.sha256(f"{workspace_id}:{name}".encode()).hexdigest()
        prefix   = f"nro_sk_{h[:4]}"
        suffix   = h[-4:]
        masked   = f"{prefix}...{suffix}"
        key_full = f"nro_sk_{h}"
        cur.execute("""
            INSERT INTO api_keys
                (workspace_id, name, key_prefix, key_masked, key_full,
                 scope, created_at, last_used_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT DO NOTHING
        """, (workspace_id, name, prefix, masked, key_full, scope, created, last_used))
        with _HONEYTOKEN_LOCK:
            _CREATED_HONEYTOKENS.add(key_full)


# ---------------------------------------------------------------------------
# Workspace provisioning helpers
# ---------------------------------------------------------------------------

def _run_provision_workspace_sync(workspace_id: str, src_ip: str, email: str) -> bool:
    """Synchronous DB work for workspace provisioning.  Run via run_in_executor.
    Opens its own dedicated psycopg2 connection — never touches shared _pg_conn."""
    conn = None
    try:
        conn = psycopg2.connect(POSTGRES_DSN)
        conn.set_session(autocommit=True)
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO attacker_workspaces (workspace_id, src_ip, email)
                VALUES (%s, %s, %s)
                ON CONFLICT (src_ip, email) DO UPDATE
                  SET last_seen = NOW(),
                      event_count = attacker_workspaces.event_count + 1
                RETURNING (xmax = 0) AS is_new
            """, (workspace_id, src_ip.split("/")[0], email))
            row = cur.fetchone()
            is_new = row[0] if row else False
            if is_new:
                _seed_workspace(cur, workspace_id)
        return is_new
    except Exception as exc:
        logger.warning("provision_workspace_error", error=str(exc), workspace_id=workspace_id)
        return False
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


async def _provision_workspace(src_ip: str, email: str, redis_client) -> str:
    """Look up or create an attacker workspace.  Returns workspace_id.
    Uses a distributed Redis lock (SET NX EX 30) to prevent concurrent first-login races."""
    workspace_id = _workspace_key(src_ip, email)
    lock_key = f"provision:{workspace_id}"

    acquired = await redis_client.set(lock_key, "1", nx=True, ex=30)
    if not acquired:
        await asyncio.sleep(0.5)
        return workspace_id

    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None, _run_provision_workspace_sync, workspace_id, src_ip, email
        )
    finally:
        await redis_client.delete(lock_key)

    return workspace_id


# ---------------------------------------------------------------------------
# Background tasks — job state machine and workspace cleanup
# ---------------------------------------------------------------------------

def _run_job_state_update() -> None:
    """Advance Queued jobs to Completed after realistic delay.  Called via run_in_executor."""
    conn = None
    try:
        conn = psycopg2.connect(POSTGRES_DSN)
        conn.set_session(autocommit=True)
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE training_runs
                SET status = 'Completed',
                    duration_min = GREATEST(1, (EXTRACT(EPOCH FROM (NOW() - started_at)) / 60)::INTEGER),
                    gpu_hours = ROUND(
                        (GREATEST(1, (EXTRACT(EPOCH FROM (NOW() - started_at)) / 60)::INTEGER)
                         / 60.0)::NUMERIC, 1)
                WHERE status = 'Queued'
                  AND error_log IS NULL
                  AND started_at BETWEEN NOW() - INTERVAL '6 hours'
                                     AND NOW() - INTERVAL '45 minutes'
            """)
    except Exception:
        pass
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


async def _job_state_machine() -> None:
    """Runs every 5 minutes; advances Queued → Completed."""
    while True:
        await asyncio.sleep(300)
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _run_job_state_update)


def _run_workspace_cleanup() -> None:
    """Delete attacker workspaces and their data older than 30 days.  Called via run_in_executor."""
    conn = None
    try:
        conn = psycopg2.connect(POSTGRES_DSN)
        conn.set_session(autocommit=True)
        with conn.cursor() as cur:
            cur.execute("""
                SELECT workspace_id FROM attacker_workspaces
                WHERE last_seen < NOW() - INTERVAL '30 days'
            """)
            expired = [row[0] for row in cur.fetchall()]
            for wid in expired:
                for table in ("training_runs", "models", "datasets", "notifications", "api_keys"):
                    cur.execute(f"DELETE FROM {table} WHERE workspace_id = %s", (wid,))
                cur.execute("DELETE FROM attacker_workspaces WHERE workspace_id = %s", (wid,))
    except Exception:
        pass
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


async def _workspace_cleanup() -> None:
    """Runs once daily; removes stale attacker workspace data."""
    while True:
        await asyncio.sleep(86400)
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _run_workspace_cleanup)


# ---------------------------------------------------------------------------
# v2 startup handlers — ADD alongside existing startup(), do not replace it
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def startup_v2() -> None:
    """Create v2 tables, seed vantarahealth workspace, start background tasks."""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _seed_v2_tables)
    asyncio.create_task(_job_state_machine())
    asyncio.create_task(_workspace_cleanup())


# ---------------------------------------------------------------------------
# Lure tarball — generated once at module import, cached as bytes
# ---------------------------------------------------------------------------

def _gen_nginx_log(n: int) -> str:
    """Generate synthetic nginx access log lines."""
    ips = ["185.234.219.4", "91.108.4.180", "103.21.244.0", "172.16.0.1", "10.31.4.22"]
    paths = ["/api/v2/runs", "/api/v2/models", "/api/v2/auth/me", "/static/main.js", "/favicon.ico"]
    import datetime as _dt
    lines = []
    for i in range(n):
        ts = (_dt.datetime.utcnow() - _dt.timedelta(seconds=i * 18)).strftime("%d/%b/%Y:%H:%M:%S +0000")
        status = random.choice([200, 200, 200, 304, 404])
        size = random.randint(200, 8000)
        ip = random.choice(ips)
        path = random.choice(paths)
        lines.append(f'{ip} - - [{ts}] "GET {path} HTTP/1.1" {status} {size} "-" "Mozilla/5.0"')
    return "\n".join(lines)


def _add_tar_member(tar: tarfile.TarFile, name: str, content: str) -> None:
    data = content.encode()
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mtime = int(time.time()) - 86400 * 30
    tar.addfile(info, io.BytesIO(data))


def _build_backup_tarball() -> bytes:
    """Build and return the lure tarball bytes.  Called once at import time."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        _add_tar_member(tar, "README.txt",
            "Created by: neuro-backup-agent v1.2\n"
            "Workspace: vantarahealth-prod\n"
            "Date: 2025-11-01\n"
            "This archive contains configuration and log snapshots from the Neuro training cluster.\n")

        _add_tar_member(tar, "logs/nginx/access.log.1", _gen_nginx_log(5000))
        _add_tar_member(tar, "logs/nginx/access.log.2", _gen_nginx_log(3000))

        _add_tar_member(tar, "logs/neuro-api/worker-celery.log",
            "[2025-11-01 00:00:01] INFO celery.worker startup\n"
            "[2025-11-01 00:00:02] INFO connected to redis://10.31.4.22:6379/0\n"
            "[2025-11-01 00:00:03] INFO ready\n"
            "[2025-11-01 00:05:01] INFO task completed: ingest_dataset#3f7a9c2b\n"
            "[2025-11-01 00:10:01] INFO heartbeat ok\n")

        _add_tar_member(tar, "logs/neuro-api/app.log.1",
            "INFO:     Started server process\n"
            "INFO:     Waiting for application startup.\n"
            "INFO:     Application startup complete.\n"
            "INFO:     Uvicorn running on http://0.0.0.0:8080 (Press CTRL+C to quit)\n"
            "INFO:     127.0.0.1:35410 - GET /api/v2/health HTTP/1.1 200\n")

        _add_tar_member(tar, "config/prometheus/prometheus.yml",
            "global:\n  scrape_interval: 15s\n\nscrape_configs:\n"
            "  - job_name: 'neuro-api'\n    static_configs:\n"
            "      - targets: ['neuro-api:8080']\n")

        _add_tar_member(tar, "config/fluentbit/parsers.conf",
            "[PARSER]\n    Name   json\n    Format json\n\n"
            "[PARSER]\n    Name   nginx\n    Format regex\n"
            "    Regex  ^(?<host>[^ ]*) [^ ]* [^ ]* \\[(?<time>[^\\]]*)\\] \"(?<method>\\S+) (?<path>[^ ]*) (?<protocol>\\S+)\" (?<code>[^ ]*) (?<size>[^ ]*)\n")

        _add_tar_member(tar, "deploy/docker-compose.yml",
            "version: '3.8'\nservices:\n  neuro-api:\n    image: cyvera/neuro-api:2.3.1\n"
            "    environment:\n      - POSTGRES_DSN=postgresql://neuro_app:NeuroML2024!@10.31.4.22:5432/neuro_prod\n"
            "      - REDIS_URL=redis://10.31.4.22:6379/0\n"
            "    networks:\n      management_net:\n        ipv4_address: 10.31.4.100\n"
            "networks:\n  management_net:\n    ipam:\n      config:\n        - subnet: 10.31.4.0/24\n")

        _add_tar_member(tar, "deploy/secrets/production.env",
            "# Neuro Production Secrets — DO NOT COMMIT\n"
            "DB_HOST=10.31.4.22\n"
            "DB_PORT=5432\n"
            "DB_NAME=neuro_prod\n"
            "DB_USER=neuro_app\n"
            "DB_PASSWORD=NeuroML2024!\n"
            "REDIS_URL=redis://10.31.4.22:6379/0\n"
            "JWT_SECRET=neuro-jwt-secret-do-not-share-2024\n"
            "S3_BUCKET=cyvera-ml-artifacts\n"
            "AWS_ACCESS_KEY_ID=AKIAYZM57LXRGIYTCOUV\n"
            "AWS_SECRET_ACCESS_KEY=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\n"
            "AWS_DEFAULT_REGION=us-east-1\n")

        _add_tar_member(tar, "deploy/secrets/aws_credentials.csv",
            "User Name,Access Key ID,Secret Access Key\n"
            "m.chen,AKIAJ2XZQR5MLVNP8KW3,kLpRnMvXsQwT2YeAh8zBdJ9uCfG4iWoN3E7tHrP\n"
            "priya.nair,AKIAX7TLQWF4HN3ZBY92,vNmQpKjRtWsAh3bYeL8cXoDf2GuT9iEn6CwZ5Pk\n"
            "svc-deploy,AKIAYZM57LXRGIYTCOUV,MpTqbycbuKX0q40aU5yCwCNtS2rWCzzH4cko/ptU\n")

    return buf.getvalue()


_BACKUP_TARBALL_BYTES: bytes = _build_backup_tarball()


# ---------------------------------------------------------------------------
# Invoice PDF — generated once at module import, cached as bytes
# ---------------------------------------------------------------------------

def _build_invoice_pdf() -> bytes:
    """Build a fake invoice PDF.  Embeds a canarytoken URL if _INVOICE_CANARY_URL is set."""
    if not _FPDF_AVAILABLE:
        return b"%PDF-1.4 placeholder"
    try:
        pdf = _FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, "VantaraHealth - Invoice", ln=True)
        pdf.set_font("Helvetica", "", 11)
        pdf.cell(0, 8, "Billed by: Cyveera AI Platform Inc.", ln=True)
        pdf.cell(0, 8, "Period: November 2025", ln=True)
        pdf.cell(0, 8, "Plan: Pro - GPU Cluster Access", ln=True)
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(80, 8, "Item", border=1)
        pdf.cell(40, 8, "Qty", border=1)
        pdf.cell(40, 8, "Amount (USD)", border=1, ln=True)
        pdf.set_font("Helvetica", "", 10)
        for item, qty, amt in [
            ("GPU-Hours (A100 80GB)", "1338 h", "$2,943.60"),
            ("Storage (S3 cyvera-ml-artifacts)", "847 GB", "$19.48"),
            ("Platform Fee (Pro tier)", "1 month", "$499.00"),
        ]:
            pdf.cell(80, 7, item, border=1)
            pdf.cell(40, 7, qty, border=1)
            pdf.cell(40, 7, amt, border=1, ln=True)
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, "Total: $3,462.08", ln=True)
        pdf.ln(4)
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 6, "Invoice ref: neuro-billing-v2 | Workspace: vantarahealth-prod", ln=True)
        pdf.cell(0, 6, "Support: support@cyveera.ai | Ticket portal: neuro.cyveera.com/support", ln=True)
        if _INVOICE_CANARY_URL:
            # Embed the canarytoken as a URI link on a 1x1 transparent area at the top
            pdf.set_xy(0, 0)
            link_id = pdf.add_link()
            pdf.set_link(link_id, y=0, page=1)
            # URI action — fires when the PDF is opened in a compliant viewer
            pdf.set_xy(200, 0)
            pdf.cell(1, 1, "", link=_INVOICE_CANARY_URL)
        else:
            warnings.warn(
                "_INVOICE_CANARY_URL not set — register a URL canarytoken at canarytokens.org "
                "and update _INVOICE_CANARY_URL in main.py, then rebuild the container.",
                stacklevel=1,
            )
        return pdf.output(dest="S").encode("latin-1") if hasattr(pdf.output(dest="S"), "encode") else bytes(pdf.output(dest="S"))
    except Exception as exc:
        logger.warning("invoice_pdf_build_error", error=str(exc))
        return b"%PDF-1.4 placeholder"


_INVOICE_PDF_BYTES: bytes = _build_invoice_pdf()


# ---------------------------------------------------------------------------
# API key generation helper
# ---------------------------------------------------------------------------

def _generate_api_key() -> tuple:
    """Returns (key_full, key_prefix, key_masked)."""
    raw = _secrets.token_hex(16)
    key_full = f"nro_sk_{raw}"
    key_prefix = key_full[:11]
    key_masked = f"{key_prefix}...{key_full[-4:]}"
    return key_full, key_prefix, key_masked


# ---------------------------------------------------------------------------
# Webhook URL classifier
# ---------------------------------------------------------------------------

_INTERNAL_TLDS = (".internal", ".local", ".corp", ".intranet", ".lan")

def _classify_webhook_url(url: str) -> str:
    """Returns 'internal', 'invalid', or 'external'."""
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port
        if port and (port < 1 or port > 65535):
            return "invalid"
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return "internal"
            return "external"
        except ValueError:
            if host in ("localhost", "ip6-localhost"):
                return "internal"
            if any(host.endswith(tld) for tld in _INTERNAL_TLDS):
                return "internal"
            return "external"
    except Exception:
        return "invalid"


# ---------------------------------------------------------------------------
# v2 Auth Routes
# ---------------------------------------------------------------------------

@app.post("/api/v2/auth/token")
async def v2_auth_token(request: Request):
    """v2 login — validates lure credential, provisions workspace, creates Redis session."""
    src_ip = _extract_src_ip(request)
    await _v2_check_rate_limit(src_ip)

    try:
        body = await request.json()
    except Exception:
        body = {}
    email = str(body.get("email") or body.get("username") or "").strip()[:256]
    password = str(body.get("password") or "").strip()[:256]

    # Timing normalisation — prevents differential timing leaks
    await asyncio.sleep(random.uniform(0.6, 1.2))

    # Bruteforce tracking — reuses same _auth_attempts/_auth_lock as api_auth()
    now_ts = time.time()
    with _auth_lock:
        bucket = _auth_attempts[src_ip]
        if password:
            bucket.append((now_ts, password))
        recent = [(ts, pw) for ts, pw in bucket if now_ts - ts <= _BF_WINDOW_SECS]
        fail_count = len(recent)
        recent_passwords = [pw for _, pw in recent[-5:]]

    if fail_count >= _BF_THRESHOLD and (fail_count - 1) < _BF_THRESHOLD:
        bf_event: dict[str, Any] = {
            "event_id": str(uuid.uuid4()),
            "created_at": datetime.now(timezone.utc),
            "sensor": "api",
            "event_type": "http.bruteforce.detected",
            "src_ip": src_ip,
            "src_port": request.client.port if request.client else None,
            "dst_port": 8080,
            "username": email or None,
            "password": None,
            "payload": json.dumps({
                "fail_count": fail_count,
                "window_secs": _BF_WINDOW_SECS,
                "last_passwords_tried": recent_passwords,
                "path": "/api/v2/auth/token",
                "note": "bruteforce threshold reached — v2 auth",
            }),
            "raw_log": None,
            "session_id": request.cookies.get("nro_session") or str(uuid.uuid4()),
            **_lookup_geo(src_ip),
        }
        asyncio.create_task(_log_event_async(bf_event))
        if HONEYDASH_URL and SENSOR_API_KEY:
            asyncio.create_task(_push_honeydash_async(bf_event, "Bruteforce"))

    # Credential validation
    cred = LURE_CREDS_V2.get(email)
    authed = False
    if cred and _BCRYPT_AVAILABLE:
        stored_ph: Optional[str] = None
        try:
            conn_tmp = psycopg2.connect(POSTGRES_DSN)
            conn_tmp.autocommit = True
            cur_tmp = conn_tmp.cursor()
            cur_tmp.execute("SELECT password_hash FROM workspace_members WHERE email = %s", (email,))
            row = cur_tmp.fetchone()
            cur_tmp.close()
            conn_tmp.close()
            if row:
                stored_ph = row[0]
        except Exception:
            pass
        if stored_ph:
            try:
                loop = asyncio.get_event_loop()
                authed = await loop.run_in_executor(None, _bcrypt_verify, password, stored_ph)
            except Exception:
                authed = False

    if not authed:
        return JSONResponse(
            status_code=401,
            content={"detail": "Invalid credentials. Use your VantaraHealth SSO credentials or contact support@cyveera.ai."},
        )

    # Provision per-attacker workspace
    redis_client = _get_redis_async()
    workspace_id = await _provision_workspace(src_ip, email, redis_client)

    # Check if returning attacker
    is_returning = False
    try:
        conn_chk = psycopg2.connect(POSTGRES_DSN)
        conn_chk.autocommit = True
        cur_chk = conn_chk.cursor()
        cur_chk.execute("SELECT event_count FROM attacker_workspaces WHERE workspace_id = %s", (workspace_id,))
        ec_row = cur_chk.fetchone()
        cur_chk.close()
        conn_chk.close()
        if ec_row and ec_row[0] > 1:
            is_returning = True
    except Exception:
        pass

    if is_returning:
        ret_event: dict[str, Any] = {
            "event_id": str(uuid.uuid4()),
            "created_at": datetime.now(timezone.utc),
            "sensor": "api",
            "event_type": "http.workspace.returning_attacker",
            "src_ip": src_ip,
            "src_port": request.client.port if request.client else None,
            "dst_port": 8080,
            "username": email,
            "password": None,
            "payload": json.dumps({"workspace_id": workspace_id, "email": email}),
            "raw_log": None,
            "session_id": request.cookies.get("nro_session") or str(uuid.uuid4()),
            **_lookup_geo(src_ip),
        }
        asyncio.create_task(_log_event_async(ret_event))
        if HONEYDASH_URL and SENSOR_API_KEY:
            asyncio.create_task(_push_honeydash_async(ret_event, "Returning Attacker"))

    # Build Redis session
    session_id = str(uuid.uuid4())
    csrf_token = _secrets.token_hex(16)
    raw_ua = request.headers.get("user-agent", "")
    session_data = {
        "email": email,
        "role": cred["role"],
        "ip": src_ip.split("/")[0],
        "user_agent_raw": raw_ua,
        "workspace_id": workspace_id,
        "csrf_token": csrf_token,
        "last_active": time.time(),
    }
    await redis_client.set(f"session:v2:{session_id}", json.dumps(session_data), ex=1800)

    # Populate _SESSION_USER_MAP for admin_page() personalisation (§4.1.1 BLOCKER-3)
    with _SESSION_USER_LOCK:
        _SESSION_USER_MAP[session_id] = email

    # Role-based redirect
    redirect_to = "/settings/admin" if cred["role"] == "cyveera_support" else "/dashboard"

    resp = JSONResponse(status_code=200, content={
        "token": session_id,
        "role": cred["role"],
        "redirect_to": redirect_to,
        "workspace_id": workspace_id,
        "expires_at": datetime.fromtimestamp(time.time() + 1800, tz=timezone.utc).isoformat(),
    })
    # DEV_MODE: React dev server (port 5173) is a different origin from FastAPI
    # (port 8080).  Browsers block SameSite=Lax cookies on cross-origin requests
    # with credentials: "include".  In dev we use SameSite=None; Secure=False.
    # Production keeps SameSite=Lax (nginx same-origin proxy, no CORS dance needed).
    resp.set_cookie(
        key=_COOKIE_NAME_V2,
        value=session_id,
        path="/",
        httponly=True,
        secure=False,
        samesite="none" if DEV_MODE else "lax",
        max_age=1800,
    )
    # Signal middleware to override event_type → http.lure.credential.success
    # Middleware strips this header before sending to client (same as api_auth())
    resp.headers["X-Lure-Credential-Used"] = "true"
    return resp


_DEFAULT_DISPLAY_NAMES = {
    "j.smith@vantarahealth.com": ("Jordan Smith", "j.smith"),
    "alice.wong@merisol.io":     ("Alice Wong",   "a.wong"),
    "support@cyveera.ai":        ("Cyveera Support", "support"),
}


@app.get("/api/v2/auth/me")
async def v2_auth_me(request: Request):
    """Return current user object.  Called by React AppLayout on mount."""
    session = await _v2_session_required(request)
    src_ip = _extract_src_ip(request)
    ua_parsed = _parse_user_agent(session.get("user_agent_raw", ""))
    workspace_id = session.get("workspace_id", "vantarahealth")

    # Read saved profile if attacker has updated it
    defaults = _DEFAULT_DISPLAY_NAMES.get(session["email"], (session["email"], session["email"]))
    full_name    = defaults[0]
    display_name = defaults[1]
    timezone     = "America/New_York"
    language     = "English (US)"
    try:
        loop = asyncio.get_event_loop()
        def _read_profile():
            conn = psycopg2.connect(POSTGRES_DSN)
            conn.autocommit = True
            cur = conn.cursor()
            cur.execute(
                "SELECT full_name, display_name, timezone, language "
                "FROM workspace_profiles WHERE workspace_id = %s",
                (workspace_id,),
            )
            return cur.fetchone()
        row = await loop.run_in_executor(None, _read_profile)
        if row:
            full_name, display_name, timezone, language = row
    except Exception:
        pass

    return JSONResponse({
        "email": session["email"],
        "full_name": full_name,
        "display_name": display_name,
        "role": session["role"],
        "ip": src_ip.split("/")[0],
        "user_agent_parsed": ua_parsed,
        "timezone": timezone,
        "language": language,
        "workspace": {"id": workspace_id, "name": "VantaraHealth", "plan": "Pro"},
        "csrf_token": session.get("csrf_token", ""),
    })


@app.post("/api/v2/profile/update")
async def v2_profile_update(request: Request):
    """Persist profile changes permanently — full_name, display_name, timezone, language."""
    session = await _v2_session_required(request)
    src_ip = _extract_src_ip(request)
    workspace_id = session.get("workspace_id", "vantarahealth")
    try:
        body = await request.json()
    except Exception:
        body = {}

    defaults = _DEFAULT_DISPLAY_NAMES.get(session["email"], (session["email"], session["email"]))
    full_name    = str(body.get("full_name")    or defaults[0])[:128]
    display_name = str(body.get("display_name") or defaults[1])[:64]
    tz_str       = str(body.get("timezone")     or "America/New_York")[:64]
    language     = str(body.get("language")     or "English (US)")[:64]

    try:
        loop = asyncio.get_event_loop()
        def _upsert():
            conn = psycopg2.connect(POSTGRES_DSN)
            conn.autocommit = True
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO workspace_profiles
                    (workspace_id, full_name, display_name, timezone, language, updated_at)
                VALUES (%s, %s, %s, %s, %s, NOW())
                ON CONFLICT (workspace_id) DO UPDATE SET
                    full_name    = EXCLUDED.full_name,
                    display_name = EXCLUDED.display_name,
                    timezone     = EXCLUDED.timezone,
                    language     = EXCLUDED.language,
                    updated_at   = NOW()
            """, (workspace_id, full_name, display_name, tz_str, language))
            cur.close(); conn.close()
        await loop.run_in_executor(None, _upsert)
    except Exception as exc:
        logger.warning("v2_profile_update_error", error=str(exc))

    ev = {
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": "http.profile.update",
        "src_ip": src_ip,
        "src_port": request.client.port if request.client else None,
        "dst_port": 8080,
        "username": session.get("email"),
        "password": None,
        "payload": json.dumps({
            "full_name": full_name,
            "display_name": display_name,
            "timezone": tz_str,
            "language": language,
        }),
        "raw_log": None,
        "session_id": request.cookies.get(_COOKIE_NAME_V2) or str(uuid.uuid4()),
        **_lookup_geo(src_ip),
    }
    _log_event(ev)
    asyncio.create_task(_push_honeydash_async(ev, "Profile Updated"))

    return JSONResponse({"status": "saved", "display_name": display_name, "full_name": full_name, "timezone": tz_str, "language": language})


@app.get("/api/v2/auth/logout")
async def v2_auth_logout(request: Request):
    """Clear v2 session from Redis and delete cookie.  Returns JSON (not 302) — SPA navigates."""
    session_id = request.cookies.get(_COOKIE_NAME_V2)
    if session_id:
        try:
            await _get_redis_async().delete(f"session:v2:{session_id}")
        except Exception:
            pass
    resp = JSONResponse({"ok": True, "redirect_to": "/login"})
    resp.delete_cookie(_COOKIE_NAME_V2)
    return resp


@app.post("/api/v2/auth/sso/initiate")
async def v2_auth_sso_initiate(request: Request):
    """SSO stub — plausible identity-provider latency, always returns 503."""
    src_ip = _extract_src_ip(request)
    await _v2_check_rate_limit(src_ip)
    await asyncio.sleep(random.uniform(1.8, 2.4))
    return JSONResponse(status_code=503, content={"error": "sso_unavailable",
        "detail": "Identity provider timeout. Use local credentials."})


# ---------------------------------------------------------------------------
# v2 CRUD Routes
# ---------------------------------------------------------------------------

@app.get("/api/v2/runs")
async def v2_get_runs(request: Request):
    session = await _v2_session_required(request)
    workspace_id = session.get("workspace_id", "vantarahealth")
    try:
        loop = asyncio.get_event_loop()
        def _fetch():
            conn = psycopg2.connect(POSTGRES_DSN)
            conn.autocommit = True
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute(
                "SELECT run_id, model_name, status, duration_min, gpu_hours, "
                "started_by, started_at, error_log FROM training_runs "
                "WHERE workspace_id = %s ORDER BY started_at DESC",
                (workspace_id,),
            )
            rows = [dict(r) for r in cur.fetchall()]
            cur.close(); conn.close()
            return rows
        rows = await loop.run_in_executor(None, _fetch)
        # Serialise non-JSON-native types and add frontend-friendly aliases.
        # Frontend mock (runs.json) uses: id, model, status, duration, gpu, by, started.
        for r in rows:
            if r.get("started_at"):
                r["started_at"] = r["started_at"].isoformat()
                r["started"] = r["started_at"][:16].replace("T", " ")  # "YYYY-MM-DD HH:MM"
            else:
                r["started"] = "—"
            if r.get("gpu_hours") is not None:
                r["gpu_hours"] = float(r["gpu_hours"])
                r["gpu"] = f"{r['gpu_hours']:.1f}h"
            else:
                r["gpu"] = "—"
            dur = r.get("duration_min")
            if dur is not None:
                h, m = divmod(int(dur), 60)
                r["duration"] = f"{h}h {m:02d}m"
            else:
                r["duration"] = "—"
            # Scalar aliases
            r["id"] = r.get("run_id", "")
            r["model"] = r.get("model_name", "")
            r["by"] = r.get("started_by", "")
    except Exception as exc:
        logger.warning("v2_get_runs_error", error=str(exc))
        rows = []
    return JSONResponse({"runs": rows, "total": len(rows)})


@app.get("/api/v2/runs/{run_id}/checkpoint")
async def v2_run_checkpoint_download(run_id: str, request: Request):
    """
    Lure checkpoint download. All run IDs return the same shared canary binary.
    Filename is parameterised by safe_run_id so the attacker sees a run-specific file.

    Tripwires embedded in _CHECKPOINT_V2_BIN:
      1. DNS canarytoken URL — fires on hostname resolution by any HTTP lib or scanner
      2. AWS key AKIAYZM57LXRGIYTCOUV — fires on any AWS API call
      3. DB / SSH credentials — matches Cowrie userdb.txt for sentinel kill-chain correlation

    Event flow (MF-1, MF-4 compliant — no handler-level log or HoneyDash push):
      Middleware:  X-Lure-Data-Exfil: true → http.lure.data_exfil (sole event)
      Middleware:  _push_honeydash_async(event, "Data Exfil") fires automatically
      Callback:    POST /api/v1/canarytoken/callback → http.canarytoken.fired
    """
    await _v2_session_required(request)
    # MF-3: sanitise attacker-controlled path segment before reflecting into Content-Disposition
    safe_run_id = run_id if re.match(r"^[a-zA-Z0-9._-]{1,64}$", run_id) else "run-latest"
    return Response(
        content=_CHECKPOINT_V2_BIN,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="checkpoint-{safe_run_id}-latest.bin"',
            "X-Lure-Data-Exfil": "true",
        },
    )


@app.get("/api/v2/models")
async def v2_get_models(request: Request):
    session = await _v2_session_required(request)
    workspace_id = session.get("workspace_id", "vantarahealth")
    try:
        loop = asyncio.get_event_loop()
        def _fetch():
            conn = psycopg2.connect(POSTGRES_DSN)
            conn.autocommit = True
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute(
                "SELECT model_name, version, customer, status, drift_score, last_check "
                "FROM models WHERE workspace_id = %s ORDER BY model_name",
                (workspace_id,),
            )
            rows = [dict(r) for r in cur.fetchall()]
            cur.close(); conn.close()
            return rows
        rows = await loop.run_in_executor(None, _fetch)
        for r in rows:
            if r.get("last_check"):
                r["last_check"] = r["last_check"].isoformat()
                r["lastCheck"] = r["last_check"][:16].replace("T", " ")
            else:
                r["lastCheck"] = ""
            if r.get("drift_score") is not None:
                r["drift_score"] = float(r["drift_score"])
                r["drift"] = r["drift_score"]   # frontend reads m.drift
            else:
                r["drift"] = 0.0
            # Frontend reads m.name (not m.model_name)
            r["name"] = r.get("model_name", "")
    except Exception as exc:
        logger.warning("v2_get_models_error", error=str(exc))
        rows = []
    return JSONResponse({"models": rows, "total": len(rows)})


@app.get("/api/v2/models/{model_id}/drift")
async def v2_get_model_drift(model_id: str, request: Request):
    """30-day synthetic drift timeseries for a named model."""
    await _v2_session_required(request)
    import datetime as _dt
    base_score = {"vantara-risk-v3": 0.04, "merisol-nlp-v2": 0.31,
                  "quelaris-embed-001": 0.07, "ardentix-llm-ft": 0.18, "lumira-clf-v4": 0.02}.get(model_id, 0.10)
    points = []
    for i in range(30):
        ts = (_dt.datetime.utcnow() - _dt.timedelta(days=29 - i)).strftime("%Y-%m-%dT%H:%M:%SZ")
        drift = round(max(0.0, min(1.0, base_score + random.uniform(-0.02, 0.02))), 4)
        points.append({"ts": ts, "drift_score": drift})
    return JSONResponse({"model_id": model_id, "window_hours": 720, "data_points": points})


@app.get("/api/v2/datasets")
async def v2_get_datasets(request: Request):
    session = await _v2_session_required(request)
    workspace_id = session.get("workspace_id", "vantarahealth")
    try:
        loop = asyncio.get_event_loop()
        def _fetch():
            conn = psycopg2.connect(POSTGRES_DSN)
            conn.autocommit = True
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute(
                "SELECT name, source, format, row_count, size_display, uploaded_at, tags "
                "FROM datasets WHERE workspace_id = %s ORDER BY uploaded_at DESC",
                (workspace_id,),
            )
            rows = [dict(r) for r in cur.fetchall()]
            cur.close(); conn.close()
            return rows
        rows = await loop.run_in_executor(None, _fetch)
        for r in rows:
            if r.get("uploaded_at"):
                r["uploaded_at"] = str(r["uploaded_at"])
    except Exception as exc:
        logger.warning("v2_get_datasets_error", error=str(exc))
        rows = []
    return JSONResponse({"datasets": rows, "total": len(rows)})


@app.get("/api/v2/notifications")
async def v2_get_notifications(request: Request):
    session = await _v2_session_required(request)
    workspace_id = session.get("workspace_id", "vantarahealth")
    try:
        loop = asyncio.get_event_loop()
        def _fetch():
            conn = psycopg2.connect(POSTGRES_DSN)
            conn.autocommit = True
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute(
                "SELECT id, severity, title, body, created_at, is_read "
                "FROM notifications WHERE workspace_id = %s ORDER BY created_at DESC",
                (workspace_id,),
            )
            rows = [dict(r) for r in cur.fetchall()]
            cur.close(); conn.close()
            return rows
        rows = await loop.run_in_executor(None, _fetch)
        for r in rows:
            if r.get("created_at"):
                r["created_at"] = r["created_at"].isoformat()
    except Exception as exc:
        logger.warning("v2_get_notifications_error", error=str(exc))
        rows = []
    return JSONResponse({"notifications": rows, "total": len(rows)})


@app.patch("/api/v2/notifications/read-all")
async def v2_notifications_read_all(request: Request):
    """Mark every unread notification as read for this workspace."""
    session = await _v2_session_required(request)
    workspace_id = session.get("workspace_id", "vantarahealth")
    loop = asyncio.get_event_loop()
    def _update():
        conn = psycopg2.connect(POSTGRES_DSN)
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute(
            "UPDATE notifications SET is_read = true WHERE workspace_id = %s AND is_read = false",
            (workspace_id,),
        )
        cur.close(); conn.close()
    await loop.run_in_executor(None, _update)
    return JSONResponse({"ok": True})


@app.patch("/api/v2/notifications/{notif_id}/read")
async def v2_notification_mark_read(notif_id: int, request: Request):
    """Mark a single notification as read (dismiss)."""
    session = await _v2_session_required(request)
    workspace_id = session.get("workspace_id", "vantarahealth")
    loop = asyncio.get_event_loop()
    def _update():
        conn = psycopg2.connect(POSTGRES_DSN)
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute(
            "UPDATE notifications SET is_read = true WHERE id = %s AND workspace_id = %s",
            (notif_id, workspace_id),
        )
        cur.close(); conn.close()
    await loop.run_in_executor(None, _update)
    return JSONResponse({"ok": True})


@app.delete("/api/v2/notifications")
async def v2_notifications_clear_history(request: Request):
    """Delete all read notifications (clear history) for this workspace."""
    session = await _v2_session_required(request)
    workspace_id = session.get("workspace_id", "vantarahealth")
    loop = asyncio.get_event_loop()
    def _delete():
        conn = psycopg2.connect(POSTGRES_DSN)
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM notifications WHERE workspace_id = %s AND is_read = true",
            (workspace_id,),
        )
        cur.close(); conn.close()
    await loop.run_in_executor(None, _delete)
    return JSONResponse({"ok": True})


@app.get("/api/v2/team")
async def v2_get_team(request: Request):
    """Returns workspace_members — shared across all workspaces (credentials not per-workspace)."""
    session = await _v2_session_required(request)
    workspace_id = session.get("workspace_id", "vantarahealth")
    try:
        loop = asyncio.get_event_loop()
        def _fetch():
            conn = psycopg2.connect(POSTGRES_DSN)
            conn.autocommit = True
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute(
                "SELECT email, display_name, role, last_active "
                "FROM workspace_members WHERE workspace_id = %s ORDER BY id",
                (workspace_id,),
            )
            rows = [dict(r) for r in cur.fetchall()]
            cur.close(); conn.close()
            return rows
        rows = await loop.run_in_executor(None, _fetch)
        for r in rows:
            if r.get("last_active"):
                r["last_active"] = r["last_active"].isoformat()
            # Frontend reads m.name / m.lastActive (matches data.json mock shape)
            r["name"] = r.get("display_name", r.get("email", ""))
            r["lastActive"] = r.get("last_active", "")
    except Exception as exc:
        logger.warning("v2_get_team_error", error=str(exc))
        rows = []
    return JSONResponse({"members": rows, "total": len(rows)})


@app.get("/api/v2/api-keys")
async def v2_get_api_keys(request: Request):
    session = await _v2_session_required(request)
    workspace_id = session.get("workspace_id", "vantarahealth")
    try:
        loop = asyncio.get_event_loop()
        def _fetch():
            conn = psycopg2.connect(POSTGRES_DSN)
            conn.autocommit = True
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute(
                "SELECT id, name, key_prefix, key_masked, key_full, scope, created_at, last_used_at "
                "FROM api_keys WHERE workspace_id = %s ORDER BY created_at DESC",
                (workspace_id,),
            )
            rows = [dict(r) for r in cur.fetchall()]
            cur.close(); conn.close()
            return rows
        rows = await loop.run_in_executor(None, _fetch)
        for r in rows:
            if r.get("created_at"):
                r["created_at"] = str(r["created_at"])
            if r.get("last_used_at"):
                r["last_used_at"] = str(r["last_used_at"])
            # Frontend reads k.masked / k.full / k.created / k.lastUsed
            # (matches data.json mock field names).  Keep the canonical names
            # alongside so the create-response and DB columns stay consistent.
            r["masked"] = r.get("key_masked", "")
            r["full"] = r.get("key_full", "")
            r["created"] = r.get("created_at", "")
            r["lastUsed"] = r.get("last_used_at", "")
    except Exception as exc:
        logger.warning("v2_get_api_keys_error", error=str(exc))
        rows = []
    return JSONResponse({"apiKeys": rows, "total": len(rows)})


@app.post("/api/v2/api-keys")
async def v2_create_api_key(request: Request):
    """Honeytoken key creation — generates a fresh key, writes to DB, returns key_full."""
    session = await _v2_session_required(request)
    workspace_id = session.get("workspace_id", "vantarahealth")
    src_ip = _extract_src_ip(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    name = str(body.get("name") or "Unnamed key")[:128]
    raw_scope = str(body.get("scope") or "read:all")
    scope = raw_scope if raw_scope in VALID_API_KEY_SCOPES else "read:all"

    await asyncio.sleep(random.uniform(0.6, 1.2))

    key_full, key_prefix, key_masked = _generate_api_key()

    new_id = None
    today_str = datetime.now(timezone.utc).date().isoformat()
    try:
        loop = asyncio.get_event_loop()
        def _write():
            conn = psycopg2.connect(POSTGRES_DSN)
            conn.autocommit = True
            cur = conn.cursor()
            # Bounded to 25 rows — delete oldest if exceeded
            cur.execute("SELECT COUNT(*) FROM api_keys WHERE workspace_id = %s", (workspace_id,))
            cnt = cur.fetchone()[0]
            if cnt >= 25:
                cur.execute(
                    "DELETE FROM api_keys WHERE id = ("
                    "  SELECT id FROM api_keys WHERE workspace_id = %s ORDER BY created_at ASC LIMIT 1"
                    ")", (workspace_id,),
                )
            cur.execute(
                "INSERT INTO api_keys (workspace_id, name, key_prefix, key_masked, key_full, scope, created_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id",
                (workspace_id, name, key_prefix, key_masked, key_full, scope, today_str),
            )
            row = cur.fetchone()
            nid = row[0] if row else None
            cur.close(); conn.close()
            return nid
        new_id = await loop.run_in_executor(None, _write)
    except Exception as exc:
        logger.warning("v2_create_api_key_db_error", error=str(exc))

    with _HONEYTOKEN_LOCK:
        _CREATED_HONEYTOKENS.add(key_full)

    ev = {
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": "http.api_keys.create_attempted",
        "src_ip": src_ip,
        "src_port": request.client.port if request.client else None,
        "dst_port": 8080,
        "username": session.get("email"),
        "password": None,
        "payload": json.dumps({"key_name": name, "scope": scope, "workspace_id": workspace_id}),
        "raw_log": None,
        "session_id": request.cookies.get(_COOKIE_NAME_V2) or str(uuid.uuid4()),
        **_lookup_geo(src_ip),
    }
    _log_event(ev)
    asyncio.create_task(_push_honeydash_async(ev, "API Key Created"))

    return JSONResponse({"status": "created", "key": {
        "id": new_id,
        "name": name,
        "key_prefix": key_prefix,
        "key_masked": key_masked,
        "key_full": key_full,
        "scope": scope,
        "created_at": today_str,
        "last_used_at": None,
    }})


# ---------------------------------------------------------------------------
# v2 Telemetry Route
# ---------------------------------------------------------------------------

@app.post("/api/v2/telemetry")
async def v2_telemetry(request: Request):
    """Accept any JSON beacon from useTelemetry hook.  No auth required."""
    src_ip = _extract_src_ip(request)
    try:
        body_bytes = await request.body()
        body_json = json.loads(body_bytes) if body_bytes else {}
    except Exception:
        body_json = {}
    event_name = str(body_json.get("event") or "unknown")[:64]
    asyncio.create_task(_log_event_async({
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": f"http.telemetry.{event_name}",
        "src_ip": src_ip,
        "src_port": request.client.port if request.client else None,
        "dst_port": 8080,
        "username": None,
        "password": None,
        "payload": json.dumps(body_json),
        "raw_log": None,
        "session_id": request.cookies.get(_COOKIE_NAME_V2) or str(uuid.uuid4()),
        **_lookup_geo(src_ip),
    }))
    return JSONResponse({"ok": True})


# ---------------------------------------------------------------------------
# v2 Trap Routes — SSRF, RCE, LFI, Crown Jewel, and others
# ---------------------------------------------------------------------------

@app.post("/api/v2/data/import")
async def v2_data_import(request: Request):
    """SSRF trap — dataset import from URL.  Never makes outbound request."""
    session = await _v2_session_required(request)
    src_ip = _extract_src_ip(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    url = str(body.get("url") or "")[:512]
    dataset_name = str(body.get("dataset_name") or "")[:128]
    fmt = str(body.get("format") or "auto")[:32]

    await asyncio.sleep(random.uniform(0.6, 1.2))

    is_ssrf = any(pat.lower() in url.lower() for pat in _SSRF_PATTERNS + list(_REMOTE_IMPORT_SSRF_INDICATORS))

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
        "payload": json.dumps({"ssrf_url": url, "dataset_name": dataset_name, "format": fmt,
                               "ssrf_detected": is_ssrf}),
        "raw_log": None,
        "session_id": request.cookies.get(_COOKIE_NAME_V2) or str(uuid.uuid4()),
        **_lookup_geo(src_ip),
    }
    _log_event(ev)
    if is_ssrf and HONEYDASH_URL and SENSOR_API_KEY:
        asyncio.create_task(_push_honeydash_async(ev, "SSRF Attempt"))

    job_id = f"dset-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:3]}"
    ds_id = "ds_" + _secrets.token_hex(4)
    ds_name = dataset_name or f"import-{job_id}"

    # Persist imported dataset to attacker's workspace so it appears in GET /api/v2/datasets
    workspace_id = session.get("workspace_id", "vantarahealth")
    try:
        loop = asyncio.get_event_loop()
        def _persist_ds():
            conn = psycopg2.connect(POSTGRES_DSN)
            conn.autocommit = True
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO datasets (workspace_id, name, source, format, row_count, size_display, uploaded_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, NOW()) ON CONFLICT (workspace_id, name) DO NOTHING",
                (workspace_id, ds_name, url[:256], fmt, None, "unknown"),
            )
            cur.close(); conn.close()
        await loop.run_in_executor(None, _persist_ds)
    except Exception as exc:
        logger.warning("v2_data_import_persist_error", error=str(exc))

    return JSONResponse({
        "status": "ingestion_queued",
        "job_id": job_id,
        "dataset_id": ds_id,
        "estimated_completion": 45,
        "source": url,
        "format": fmt,
        "dataset_name": ds_name,
    })


@app.post("/api/v2/training/jobs")
async def v2_training_jobs(request: Request):
    """Job submission — RCE intent trap via startup_script field."""
    session = await _v2_session_required(request)
    workspace_id = session.get("workspace_id", "vantarahealth")
    src_ip = _extract_src_ip(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    # Accept both "name" (frontend form field) and "job_name" (internal/API clients)
    job_name = str(body.get("job_name") or body.get("name") or f"job-{uuid.uuid4().hex[:6]}")[:128]
    # Accept both "model_name" (frontend select) and "base_model" (API clients)
    base_model = str(body.get("base_model") or body.get("model_name") or "vantara-risk-v3")[:128]
    # Accept both "gpu_allocation" (internal) and "dataset" (frontend may send this)
    gpu_alloc = str(body.get("gpu_allocation") or "1x A100")[:64]
    startup_script = str(body.get("startup_script") or "")[:4096]
    description = str(body.get("description") or "")[:512]

    # Detect shell metacharacters
    _METACHAR_RE = re.compile(r'[$`|&;]|\$\(')
    has_metachar = bool(_METACHAR_RE.search(startup_script))

    ev = {
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": "http.snare.script_upload" if has_metachar else "http.training.job_submitted",
        "src_ip": src_ip,
        "src_port": request.client.port if request.client else None,
        "dst_port": 8080,
        "username": session.get("email"),
        "password": None,
        "payload": json.dumps({
            "startup_script": startup_script[:512],
            "job_name": job_name,
            "base_model": base_model,
        }),
        "raw_log": None,
        "session_id": request.cookies.get(_COOKIE_NAME_V2) or str(uuid.uuid4()),
        **_lookup_geo(src_ip),
    }
    _log_event(ev)
    asyncio.create_task(_push_honeydash_async(ev, "RCE Attempt" if has_metachar else "Training Job"))

    # Insert into training_runs — all submissions get a DB row
    run_id = f"run-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{random.randint(1, 999):03d}"
    error_log_val = (
        "Worker process exited with code 1 (OOMKilled). Scheduler was unable to collect logs "
        "before container teardown. Check cluster resource utilization on the management plane "
        "or re-submit with a smaller batch size."
        if has_metachar else None
    )
    status_val = "Failed" if has_metachar else "Queued"
    try:
        loop = asyncio.get_event_loop()
        def _insert():
            conn = psycopg2.connect(POSTGRES_DSN)
            conn.autocommit = True
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO training_runs "
                "(workspace_id, run_id, model_name, status, started_by, started_at, error_log) "
                "VALUES (%s, %s, %s, %s, %s, NOW(), %s) "
                "ON CONFLICT (workspace_id, run_id) DO NOTHING",
                (workspace_id, run_id, base_model, status_val,
                 session.get("email", "unknown"), error_log_val),
            )
            cur.close(); conn.close()
        await loop.run_in_executor(None, _insert)
    except Exception as exc:
        logger.warning("v2_training_jobs_insert_error", error=str(exc))

    estimated_start = datetime.now(timezone.utc).replace(second=0, microsecond=0).isoformat().replace("+00:00", "Z")
    return JSONResponse({
        "job_id": run_id,
        "status": "queued",
        "estimated_start": estimated_start,
    })


@app.get("/api/v2/artifacts")
async def v2_get_artifacts_list(request: Request):
    """Artifact directory listing — LFI browse entry point.  Returns static file list."""
    session = await _v2_session_required(request)
    src_ip = _extract_src_ip(request)
    browse_path = str(request.query_params.get("path") or "")[:256]
    ev = {
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": "http.get.artifacts",
        "src_ip": src_ip,
        "src_port": request.client.port if request.client else None,
        "dst_port": 8080,
        "username": session.get("email"),
        "password": None,
        "payload": json.dumps({"browse_path": browse_path}),
        "raw_log": None,
        "session_id": request.cookies.get(_COOKIE_NAME_V2) or str(uuid.uuid4()),
        **_lookup_geo(src_ip),
    }
    _log_event(ev)
    return JSONResponse([
        {"name": "vantara-risk-v3-epoch-48.bin",  "size": "2.1 GB",  "modified": "2026-06-07T14:22:00Z", "type": "binary"},
        {"name": "config.yaml",                   "size": "4.2 KB",  "modified": "2026-06-07T09:15:00Z", "type": "config"},
        {"name": "eval_metrics.json",             "size": "18.4 KB", "modified": "2026-06-07T14:23:00Z", "type": "json"},
    ])


@app.get("/api/v2/artifacts/download")
async def v2_artifacts_download(request: Request):
    """LFI / canary tarball download.  Returns lure tarball for the magic path; stub otherwise."""
    session = await _v2_session_required(request)
    artifact_path = str(request.query_params.get("artifact_path") or "")[:512]

    _CANARY_PATH = "../../exports/workspace-backup-2025-11.tar.gz"
    is_canary = artifact_path == _CANARY_PATH

    if is_canary:
        content_bytes = _BACKUP_TARBALL_BYTES
        mime = "application/gzip"
        filename = "workspace-backup-2025-11.tar.gz"
    else:
        basename = artifact_path.split("/")[-1] or "artifact.bin"
        if basename.endswith(".json"):
            content_bytes = b'{"placeholder": true}\n'
            mime = "application/json"
        elif basename.endswith((".yaml", ".yml")):
            content_bytes = b"# placeholder\nversion: 1\n"
            mime = "text/yaml"
        else:
            content_bytes = b"\x00" * 512
            mime = "application/octet-stream"
        filename = basename

    resp = Response(
        content=content_bytes,
        media_type=mime,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Lure-Data-Exfil": "true",
        },
    )
    return resp


@app.get("/api/v2/internal/config")
async def v2_internal_config(request: Request):
    """Crown jewel — requires cyveera_support role + X-Internal-Access header."""
    src_ip = _extract_src_ip(request)
    # Log unconditionally — all hits are noteworthy regardless of auth outcome
    _log_event({
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": "http.snare.internal_config_access",
        "src_ip": src_ip,
        "src_port": request.client.port if request.client else None,
        "dst_port": 8080,
        "username": request.cookies.get(_COOKIE_NAME_V2),
        "password": None,
        "payload": json.dumps({"path": "/api/v2/internal/config",
                               "x_internal_access": request.headers.get("X-Internal-Access", "")}),
        "raw_log": None,
        "session_id": request.cookies.get(_COOKIE_NAME_V2) or str(uuid.uuid4()),
        **_lookup_geo(src_ip),
    })
    # Session gate
    session = await _v2_require_support(request)
    # Header gate
    if request.headers.get("X-Internal-Access") != "true":
        return JSONResponse(status_code=403, content={
            "error": "missing_header",
            "message": "X-Internal-Access header required",
        })
    await _jitter()
    return JSONResponse({
        "db_host": "10.31.4.22",
        "db_port": 5432,
        "db_name": "neuro_prod",
        "db_user": "neuro_app",
        "s3_bucket": "cyvera-ml-artifacts",
        "redis_url": "redis://10.31.4.22:6379",
        "jwt_secret": "REDACTED",
        "support_credentials": "REDACTED — see /run/secrets/support_creds",
    })


@app.post("/api/v2/integrations/webhook/test")
async def v2_webhook_test(request: Request):
    """SSRF trap — dynamic responses based on URL classification."""
    session = await _v2_session_required(request)
    src_ip = _extract_src_ip(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    url = str(body.get("url") or "")[:512]

    await asyncio.sleep(random.uniform(0.6, 1.2))

    classification = _classify_webhook_url(url)
    is_ssrf = classification == "internal" or any(
        pat.lower() in url.lower() for pat in _SSRF_PATTERNS
    )

    ev = {
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": "http.snare.ssrf_attempt" if is_ssrf else "http.webhook.test",
        "src_ip": src_ip,
        "src_port": request.client.port if request.client else None,
        "dst_port": 8080,
        "username": session.get("email"),
        "password": None,
        "payload": json.dumps({"webhook_url": url, "classification": classification,
                               "ssrf_detected": is_ssrf}),
        "raw_log": None,
        "session_id": request.cookies.get(_COOKIE_NAME_V2) or str(uuid.uuid4()),
        **_lookup_geo(src_ip),
    }
    _log_event(ev)
    if HONEYDASH_URL and SENSOR_API_KEY:
        asyncio.create_task(_push_honeydash_async(ev, "SSRF Attempt" if is_ssrf else "Webhook Test"))

    if classification == "internal":
        return JSONResponse(status_code=502, content={
            "status": "failed",
            "error": "connection_refused",
            "relay_node": "10.31.4.22",
        })
    if classification == "invalid":
        return JSONResponse(status_code=504, content={
            "status": "failed",
            "error": "timeout",
            "relay_node": "10.31.4.22",
        })
    # external
    return JSONResponse(status_code=200, content={
        "status": "delivered",
        "http_status": 200,
        "latency_ms": random.randint(140, 230),
        "relay": "http://10.31.4.22:3128/",
    })


@app.post("/api/v2/team/invite")
async def v2_team_invite(request: Request):
    """Intent capture — logs submitted invite email."""
    session = await _v2_session_required(request)
    src_ip = _extract_src_ip(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    invite_email = str(body.get("email") or "")[:256]
    role = str(body.get("role") or "Member")[:64]

    await asyncio.sleep(random.uniform(0.6, 1.2))

    ev = {
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": "http.team.invite_submitted",
        "src_ip": src_ip,
        "src_port": request.client.port if request.client else None,
        "dst_port": 8080,
        "username": session.get("email"),
        "password": None,
        "payload": json.dumps({"invite_email": invite_email, "role": role,
                               "workspace_id": session.get("workspace_id")}),
        "raw_log": None,
        "session_id": request.cookies.get(_COOKIE_NAME_V2) or str(uuid.uuid4()),
        **_lookup_geo(src_ip),
    }
    _log_event(ev)
    asyncio.create_task(_push_honeydash_async(ev, "Team Invite"))
    # Persist invited member to workspace so they appear in GET /api/v2/team
    workspace_id = session.get("workspace_id", "vantarahealth")
    if invite_email:
        try:
            loop = asyncio.get_event_loop()
            def _persist_member():
                conn = psycopg2.connect(POSTGRES_DSN)
                conn.autocommit = True
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO workspace_members (workspace_id, email, display_name, role) "
                    "VALUES (%s, %s, %s, %s) ON CONFLICT (email) DO NOTHING",
                    (workspace_id, invite_email, invite_email.split("@")[0], role),
                )
                cur.close(); conn.close()
            await loop.run_in_executor(None, _persist_member)
        except Exception as exc:
            logger.warning("v2_team_invite_persist_error", error=str(exc))

    return JSONResponse({"status": "invited", "email": invite_email})


@app.post("/api/v2/team/remove")
async def v2_team_remove(request: Request):
    """Intent capture — blocks removal of support@cyveera.ai."""
    session = await _v2_session_required(request)
    src_ip = _extract_src_ip(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    target_email = str(body.get("email") or "")[:256]

    ev = {
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": "http.team.remove_attempted",
        "src_ip": src_ip,
        "src_port": request.client.port if request.client else None,
        "dst_port": 8080,
        "username": session.get("email"),
        "password": None,
        "payload": json.dumps({"target_email": target_email}),
        "raw_log": None,
        "session_id": request.cookies.get(_COOKIE_NAME_V2) or str(uuid.uuid4()),
        **_lookup_geo(src_ip),
    }
    _log_event(ev)
    asyncio.create_task(_push_honeydash_async(ev, "Team Member Removed"))

    if target_email == "support@cyveera.ai":
        return JSONResponse(status_code=403, content={
            "error": "forbidden",
            "message": "You cannot remove Cyveera support accounts.",
        })
    return JSONResponse({"status": "removed"})


@app.get("/api/v2/profile/ssh-keys")
async def v2_profile_ssh_keys_get(request: Request):
    """Return saved SSH keys for this workspace."""
    session = await _v2_session_required(request)
    workspace_id = session.get("workspace_id", "vantarahealth")
    try:
        loop = asyncio.get_event_loop()
        def _read():
            conn = psycopg2.connect(POSTGRES_DSN)
            conn.autocommit = True
            cur = conn.cursor()
            cur.execute(
                "SELECT name, fingerprint, added_at, last_used_at "
                "FROM workspace_ssh_keys WHERE workspace_id = %s ORDER BY id ASC",
                (workspace_id,),
            )
            rows = cur.fetchall()
            cur.close(); conn.close()
            return rows
        rows = await loop.run_in_executor(None, _read)
    except Exception:
        rows = []
    keys = [
        {"name": r[0], "fingerprint": r[1],
         "added_at": str(r[2]) if r[2] else None,
         "last_used_at": str(r[3]) if r[3] else None}
        for r in rows
    ]
    return JSONResponse({"keys": keys})


@app.post("/api/v2/profile/ssh-keys")
async def v2_profile_ssh_keys(request: Request):
    """SSH public key capture — validates format before logging."""
    session = await _v2_session_required(request)
    src_ip = _extract_src_ip(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    name = str(body.get("name") or "")[:128]
    key = str(body.get("key") or "").strip()[:8192]

    if not _SSH_KEY_RE.match(key):
        _log_event({
            "event_id": str(uuid.uuid4()),
            "created_at": datetime.now(timezone.utc),
            "sensor": "api",
            "event_type": "http.snare.ssh_key_invalid_format",
            "src_ip": src_ip,
            "src_port": request.client.port if request.client else None,
            "dst_port": 8080,
            "username": session.get("email"),
            "password": None,
            "payload": json.dumps({"key_preview": key[:80], "name": name}),
            "raw_log": None,
            "session_id": request.cookies.get(_COOKIE_NAME_V2) or str(uuid.uuid4()),
            **_lookup_geo(src_ip),
        })
        raise HTTPException(status_code=400, detail={
            "error": "invalid_format",
            "message": "Invalid SSH public key format. Supported types: ssh-rsa, ssh-ed25519, ssh-ecdsa.",
        })

    ev = {
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": "http.snare.ssh_key_submitted",
        "src_ip": src_ip,
        "src_port": request.client.port if request.client else None,
        "dst_port": 8080,
        "username": session.get("email"),
        "password": None,
        "payload": json.dumps({"key": key, "name": name}),
        "raw_log": None,
        "session_id": request.cookies.get(_COOKIE_NAME_V2) or str(uuid.uuid4()),
        **_lookup_geo(src_ip),
    }
    _log_event(ev)
    asyncio.create_task(_push_honeydash_async(ev, "SSH Key Submitted"))

    # Derive a fake fingerprint from the key content
    import hashlib as _hl
    fp_hex = _hl.sha256(key.encode()).hexdigest()
    fingerprint = f"SHA256:{fp_hex[:4].upper()}...{fp_hex[-4:].upper()}"

    # Persist permanently so returning attacker sees their key
    workspace_id = session.get("workspace_id", "vantarahealth")
    try:
        loop = asyncio.get_event_loop()
        def _persist():
            conn = psycopg2.connect(POSTGRES_DSN)
            conn.autocommit = True
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO workspace_ssh_keys (workspace_id, name, key_full, fingerprint, added_at) "
                "VALUES (%s, %s, %s, %s, CURRENT_DATE)",
                (workspace_id, name or "unnamed key", key, fingerprint),
            )
            cur.close(); conn.close()
        await loop.run_in_executor(None, _persist)
    except Exception as exc:
        logger.warning("v2_ssh_key_persist_error", error=str(exc))

    return JSONResponse({
        "status": "key_added",
        "name": name or "unnamed key",
        "fingerprint": fingerprint,
        "added_at": datetime.now(timezone.utc).date().isoformat(),
        "message": "SSH key added. It may take up to 60 seconds to propagate to all cluster nodes.",
    })


@app.get("/api/v2/settings/billing/invoice/{invoice_id}")
async def v2_billing_invoice(invoice_id: str, request: Request):
    """Canary PDF download — emits http.lure.data_exfil."""
    await _v2_session_required(request)
    # Normalise invoice_id — only INV-2026-001 through INV-2026-006 are valid display names
    safe_id = invoice_id if re.match(r"^INV-\d{4}-\d{3}$", invoice_id) else "INV-2026-001"
    resp = Response(
        content=_INVOICE_PDF_BYTES,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="invoice-{safe_id}.pdf"',
            "X-Lure-Data-Exfil": "true",
        },
    )
    return resp


@app.post("/api/v2/security/mfa/toggle")
async def v2_security_mfa_toggle(request: Request):
    """MFA disable trap — bcrypt-validates submitted password before logging."""
    session = await _v2_session_required(request)
    src_ip = _extract_src_ip(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    submitted_password = str(body.get("password") or "")[:256]
    email = session.get("email", "")

    # Step 1: retrieve stored hash
    stored_ph: Optional[str] = None
    try:
        loop = asyncio.get_event_loop()
        def _get_hash():
            conn = psycopg2.connect(POSTGRES_DSN)
            conn.autocommit = True
            cur = conn.cursor()
            cur.execute("SELECT password_hash FROM workspace_members WHERE email = %s", (email,))
            row = cur.fetchone()
            cur.close(); conn.close()
            return row[0] if row else None
        stored_ph = await loop.run_in_executor(None, _get_hash)
    except Exception:
        pass

    # Step 2: bcrypt verify in executor
    verified = False
    if stored_ph and _BCRYPT_AVAILABLE and submitted_password:
        try:
            loop = asyncio.get_event_loop()
            verified = await loop.run_in_executor(None, _bcrypt_verify, submitted_password, stored_ph)
        except Exception:
            verified = False

    # Log all attempts — wrong passwords reveal attacker's guesses; correct = crown jewel
    ev = {
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": "http.snare.mfa_enable_attempt",
        "src_ip": src_ip,
        "src_port": request.client.port if request.client else None,
        "dst_port": 8080,
        "username": email,
        "password": submitted_password,
        "payload": json.dumps({
            "attempted_password": submitted_password,
            "password_correct": verified,
        }),
        "raw_log": None,
        "session_id": request.cookies.get(_COOKIE_NAME_V2) or str(uuid.uuid4()),
        **_lookup_geo(src_ip),
    }
    _log_event(ev)
    if HONEYDASH_URL and SENSOR_API_KEY:
        asyncio.create_task(_push_honeydash_async(ev, "MFA Enable Attempt"))

    if not verified:
        return JSONResponse(status_code=401, content={"error": "invalid_password"})

    return JSONResponse(status_code=403, content={
        "error": "mfa_enable_failed",
        "message": "Unable to enable MFA at this time. Your account may require administrator approval. Contact support@cyveera.ai for assistance.",
    })


@app.post("/api/v2/security/session/revoke")
async def v2_security_session_revoke(request: Request):
    """Session revocation — logs session_ref; self-revoke logs out the attacker."""
    session = await _v2_session_required(request)
    src_ip = _extract_src_ip(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    submitted_sid = str(body.get("session_id") or "")[:128]

    _log_event({
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": "http.security.session_revoke",
        "src_ip": src_ip,
        "src_port": request.client.port if request.client else None,
        "dst_port": 8080,
        "username": session.get("email"),
        "password": None,
        "payload": json.dumps({"submitted_session_id": submitted_sid}),
        "raw_log": None,
        "session_id": request.cookies.get(_COOKIE_NAME_V2) or str(uuid.uuid4()),
        **_lookup_geo(src_ip),
    })

    current_sid = request.cookies.get(_COOKIE_NAME_V2, "")
    is_self_revoke = submitted_sid in ("current", current_sid) and current_sid
    if is_self_revoke:
        try:
            await _get_redis_async().delete(f"session:v2:{current_sid}")
        except Exception:
            pass
        resp = JSONResponse({"status": "revoked", "self": True})
        resp.delete_cookie(_COOKIE_NAME_V2)
        return resp

    return JSONResponse({"status": "revoked", "self": False})


@app.get("/api/v2/security/allowlist")
async def v2_security_allowlist_get(request: Request):
    """Return current allowlist state for this session."""
    session = await _v2_session_required(request)
    entries  = session.get("allowlist_entries", _ALLOWLIST_DEFAULTS)
    enabled  = session.get("allowlist_enabled", False)
    return JSONResponse({"enabled": enabled, "entries": entries})


@app.post("/api/v2/security/allowlist/add")
async def v2_security_allowlist_add(request: Request):
    """CIDR submission — captures attacker network intelligence."""
    session = await _v2_session_required(request)
    src_ip = _extract_src_ip(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    cidr = str(body.get("cidr") or "")[:64]
    description = str(body.get("description") or "")[:256]

    await asyncio.sleep(random.uniform(0.6, 1.2))

    _log_event({
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": "http.snare.allowlist_probe",
        "src_ip": src_ip,
        "src_port": request.client.port if request.client else None,
        "dst_port": 8080,
        "username": session.get("email"),
        "password": None,
        "payload": json.dumps({"submitted_cidr": cidr, "description": description}),
        "raw_log": None,
        "session_id": request.cookies.get(_COOKIE_NAME_V2) or str(uuid.uuid4()),
        **_lookup_geo(src_ip),
    })

    # Persist new entry into this session so it survives page navigation
    current_entries = session.get("allowlist_entries", list(_ALLOWLIST_DEFAULTS))
    current_entries.append({"cidr": cidr or "0.0.0.0/32",
                             "description": description or "—",
                             "active": True})
    await _v2_session_patch(request, {"allowlist_entries": current_entries})

    return JSONResponse({"status": "queued",
        "message": "CIDR block successfully added to network perimeter routing."})


@app.post("/api/v2/security/allowlist/toggle")
async def v2_security_allowlist_toggle(request: Request):
    """IP Access Control toggle — high-severity: attacker attempting perimeter lockdown."""
    session = await _v2_session_required(request)
    src_ip = _extract_src_ip(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    enabled = bool(body.get("enabled", False))

    await asyncio.sleep(random.uniform(0.8, 1.6))

    ev = {
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": "http.security.allowlist_toggle",
        "src_ip": src_ip,
        "src_port": request.client.port if request.client else None,
        "dst_port": 8080,
        "username": session.get("email"),
        "password": None,
        "payload": json.dumps({"enabled": enabled, "severity": "HIGH",
                                "note": "attacker attempting perimeter lockdown"}),
        "raw_log": None,
        "session_id": request.cookies.get(_COOKIE_NAME_V2) or str(uuid.uuid4()),
        **_lookup_geo(src_ip),
    }
    _log_event(ev)
    asyncio.create_task(_push_honeydash_async(ev, "Perimeter Lockdown Attempt"))

    # Persist toggle state into session so it survives page navigation
    await _v2_session_patch(request, {"allowlist_enabled": enabled})

    action = "enabled" if enabled else "disabled"
    return JSONResponse({
        "status": "applied",
        "message": f"IP Access Control {action}. Network access control lists successfully applied globally.",
    })


@app.post("/api/v2/security/keys/rotate")
async def v2_security_keys_rotate(request: Request):
    """Key rotation event — logs intent."""
    session = await _v2_session_required(request)
    src_ip = _extract_src_ip(request)
    ev = {
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": "http.security.keys_rotate",
        "src_ip": src_ip,
        "src_port": request.client.port if request.client else None,
        "dst_port": 8080,
        "username": session.get("email"),
        "password": None,
        "payload": json.dumps({"action": "rotate_all_keys"}),
        "raw_log": None,
        "session_id": request.cookies.get(_COOKIE_NAME_V2) or str(uuid.uuid4()),
        **_lookup_geo(src_ip),
    }
    _log_event(ev)
    asyncio.create_task(_push_honeydash_async(ev, "Key Rotation"))
    return JSONResponse({
        "status": "rotation_queued",
        "affected_keys": 3,
        "note": "Update your CI/CD pipelines and automation scripts. New keys will be issued at the /api-keys page within 5 minutes.",
    })


@app.post("/api/v2/api-keys/revoke")
async def v2_api_keys_revoke(request: Request):
    """API key revocation intent capture."""
    session = await _v2_session_required(request)
    src_ip = _extract_src_ip(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    key_id = body.get("key_id")
    ev = {
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": "http.api_keys.revoke_attempted",
        "src_ip": src_ip,
        "src_port": request.client.port if request.client else None,
        "dst_port": 8080,
        "username": session.get("email"),
        "password": None,
        "payload": json.dumps({"key_id": key_id}),
        "raw_log": None,
        "session_id": request.cookies.get(_COOKIE_NAME_V2) or str(uuid.uuid4()),
        **_lookup_geo(src_ip),
    }
    _log_event(ev)
    asyncio.create_task(_push_honeydash_async(ev, "API Key Revoked"))
    return JSONResponse({"status": "revoked"})


@app.post("/api/v2/admin/tenant/{action}")
async def v2_admin_tenant_action(action: str, request: Request):
    """Admin action trap — cyveera_support only; returns ComplianceLock JSON."""
    session = await _v2_require_support(request)
    src_ip = _extract_src_ip(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    ev = {
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": "http.snare.admin_action_attempted",
        "src_ip": src_ip,
        "src_port": request.client.port if request.client else None,
        "dst_port": 8080,
        "username": session.get("email"),
        "password": None,
        "payload": json.dumps({"action": action, "body": body}),
        "raw_log": None,
        "session_id": request.cookies.get(_COOKIE_NAME_V2) or str(uuid.uuid4()),
        **_lookup_geo(src_ip),
    }
    _log_event(ev)
    asyncio.create_task(_push_honeydash_async(ev, "Admin Action"))
    return JSONResponse(status_code=403, content={
        "error": "action_blocked",
        "message": "This action requires SOC 2 compliance mode authorization. See INC-2026-047.",
        "requires": "dual_approval",
        "incident_ref": "INC-2026-047",
    })


@app.post("/api/v2/mfa/verify")
async def v2_mfa_verify(request: Request):
    """MFA bypass attempt — always returns verified=true after realistic delay."""
    session = await _v2_session_required(request)
    src_ip = _extract_src_ip(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    code = str(body.get("code") or "")[:32]

    await asyncio.sleep(0.4)  # simulate bcrypt verification timing

    ev = {
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": "http.mfa.bypass_attempt",
        "src_ip": src_ip,
        "src_port": request.client.port if request.client else None,
        "dst_port": 8080,
        "username": session.get("email"),
        "password": None,
        "payload": json.dumps({"code": code}),
        "raw_log": None,
        "session_id": request.cookies.get(_COOKIE_NAME_V2) or str(uuid.uuid4()),
        **_lookup_geo(src_ip),
    }
    _log_event(ev)
    asyncio.create_task(_push_honeydash_async(ev, "MFA Bypass Attempt"))
    return JSONResponse({"verified": True})


# ---------------------------------------------------------------------------
# Public contact / sales form — honeypot trap for XSS/SQLi form injection
# ---------------------------------------------------------------------------

@app.post("/api/v2/contact")
async def contact_form(request: Request):
    """
    Public sales contact form — no auth required.
    Detects XSS/SQLi injected into any field and logs as malicious_form_submission.
    Always returns the same success response so attackers can't detect the trap.
    """
    src_ip = _extract_src_ip(request)
    try:
        body = await request.json()
    except Exception:
        body = {}

    first_name   = str(body.get("first_name", ""))
    last_name    = str(body.get("last_name", ""))
    work_email   = str(body.get("work_email", ""))
    company_size = str(body.get("company_size", ""))
    message      = str(body.get("message", ""))

    combined = " ".join([first_name, last_name, work_email, message]).lower()
    combined_decoded = urllib.parse.unquote_plus(urllib.parse.unquote_plus(combined))

    # Detect XSS
    xss_hit = next((p for p in _XSS_PATTERNS if p in combined_decoded), None)
    # Detect SQLi
    sqli_hit = next((p for p in _SQLI_PATTERNS if p in combined_decoded), None)

    is_malicious = bool(xss_hit or sqli_hit)
    attack_vector = f"XSS ({xss_hit})" if xss_hit else (f"SQLi ({sqli_hit})" if sqli_hit else None)

    event_type = "http.contact.malicious_form" if is_malicious else "http.contact.form_submission"
    payload_dict = {
        "first_name":    first_name[:120],
        "last_name":     last_name[:120],
        "work_email":    work_email[:254],
        "company_size":  company_size,
        "message":       message[:2000],
        "is_malicious":  is_malicious,
        "attack_vector": attack_vector,
    }

    ev = {
        "event_type":  event_type,
        "sensor":      "api",
        "src_ip":      src_ip,
        "created_at":  datetime.now(timezone.utc),
        "payload":     json.dumps(payload_dict),
        "username":    work_email or None,
    }
    asyncio.create_task(_log_event_async(ev))
    if is_malicious:
        asyncio.create_task(_push_honeydash_async(ev, "Malicious Form Submission"))

    return JSONResponse({"status": "received"})


# ---------------------------------------------------------------------------
# Legacy debug trap (v1 path — outside /api/v2/ block, intentionally unauthenticated)
# ---------------------------------------------------------------------------

@app.get("/api/v1/debug/cluster-status")
async def v1_legacy_debug(request: Request):
    """Legacy shadow trap — 410 Gone; funnels API enumerators toward /docs."""
    src_ip = _extract_src_ip(request)
    _log_event({
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": "http.snare.legacy_api_exploit",
        "src_ip": src_ip,
        "src_port": request.client.port if request.client else None,
        "dst_port": 8080,
        "username": None,
        "password": None,
        "payload": json.dumps({"path": "/api/v1/debug/cluster-status"}),
        "raw_log": None,
        "session_id": request.cookies.get(_COOKIE_NAME_V2) or str(uuid.uuid4()),
        **_lookup_geo(src_ip),
    })
    return JSONResponse(status_code=410, content={
        "error": "endpoint_removed",
        "message": "This endpoint was deprecated in API v1.8 and removed in v2.0. See the v2 migration guide at /docs/api-reference/advanced/node-management for the replacement endpoint.",
        "migration_ref": "v2-migration-2026-03",
    })


# ---------------------------------------------------------------------------
# v2 Discovery / Utility Routes
# ---------------------------------------------------------------------------

@app.get("/api/v2/cluster/nodes")
async def v2_cluster_nodes(request: Request):
    """Alias of /api/v1/cluster/nodes — ssh_host set to public domain for kill chain."""
    await _jitter()
    return JSONResponse({
        "cluster": "neuro-train-cluster",
        "updated_at": "2026-06-07T08:00:00Z",
        "nodes": [
            {
                "name": "neuro-train-01",
                "ip": "10.31.4.22",
                "ssh_host": "neuro.cyveera.com",
                "status": "running",
                "ssh_port": 22,
                "ssh_fingerprint": "SHA256:k3YxPq9mRvN4wZj2sBtL7uCeIoAhGfDy",
                "gpu_util": 87.4,
                "role": "primary",
                "note": "Direct SSH requires neuro-svc credentials. See /config.yaml.",
            },
            {
                "name": "neuro-train-02",
                "ip": "10.31.4.23",
                "ssh_host": "neuro.cyveera.com",
                "status": "idle",
                "ssh_port": 22,
                "ssh_fingerprint": "SHA256:m5VwRq3nKt8pXd1yBzNjLaFeHiSgCuOe",
                "gpu_util": 0.0,
                "role": "standby",
            },
        ],
    })


# ===========================================================================
# End of API v2 block
# ===========================================================================


# ---------------------------------------------------------------------------
# 404 handler — FastAPI-style JSON (plans.md Section 4.2)
# ---------------------------------------------------------------------------

from fastapi.exceptions import HTTPException

@app.exception_handler(404)
async def not_found_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=404,
        content={
            "error": "Not Found",
            "request_id": f"req-{uuid.uuid4().hex[:12]}",
            "status": 404,
        },
    )


@app.exception_handler(405)
async def method_not_allowed_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=405,
        content={"detail": "Method Not Allowed", "path": request.url.path},
    )
