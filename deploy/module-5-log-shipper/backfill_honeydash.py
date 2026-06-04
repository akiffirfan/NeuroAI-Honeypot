#!/usr/bin/env python3
"""
backfill_honeydash.py — Send historical Neuro events to HoneyDash ingest API.

Run from the Neuro VPS:
    python3 backfill_honeydash.py

Reads POSTGRES_PASSWORD, HONEYDASH_URL, HONEYDASH_SENSOR_KEY from
deploy/module-5-log-shipper/.env (or environment variables).

Converts honeypot_events rows to Cowrie-format JSON and POSTs them
to HoneyDash /api/ingest/batch in chunks of 500.
"""

import json
import os
import sys
import time

import psycopg2
import requests

# ── Config ────────────────────────────────────────────────────────────────────

def _load_env(path=".env"):
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

# Try loading .env from the module-5 directory
_load_env("/opt/honeypot/deploy/module-5-log-shipper/.env")

POSTGRES_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "")
POSTGRES_DSN      = os.environ.get("POSTGRES_DSN") or f"postgresql://honeypot:{POSTGRES_PASSWORD}@postgres:5432/honeypot"
HONEYDASH_URL     = os.environ.get("HONEYDASH_URL", "").rstrip("/")
SENSOR_KEY        = os.environ.get("HONEYDASH_SENSOR_KEY", "")
BATCH_SIZE        = 200
SLEEP_BETWEEN     = 1.5   # seconds between batches — avoid overwhelming HoneyDash

if not HONEYDASH_URL:
    sys.exit("ERROR: HONEYDASH_URL not set")
if not SENSOR_KEY:
    sys.exit("ERROR: HONEYDASH_SENSOR_KEY not set")
if not POSTGRES_PASSWORD:
    sys.exit("ERROR: POSTGRES_PASSWORD not set")

INGEST_URL = HONEYDASH_URL + "/api/ingest/batch"
HEADERS    = {"X-Sensor-Key": SENSOR_KEY, "Content-Type": "application/json"}

PORT_PROTOCOL = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    80: "http", 443: "https", 2222: "ssh", 3306: "mysql", 6379: "redis",
}

SENSOR_NAME_MAP = {
    # Long names (SENSOR_NAME_* env var values in log_shipper.py)
    "neuro-cowrie-01":     "remote",
    "neuro-opencanary-01": "remote",
    "neuro-mariadb-01":    "remote",
    "neuro-api-01":        "remote",
    # Short names (what PostgresWriter stores in honeypot_events.sensor)
    "cowrie":     "remote",
    "opencanary": "remote",
    "mariadb":    "remote",
    "api":        "remote",
}

# ── Noise events — skip entirely, do not send to HoneyDash ───────────────────

NOISE_EVENT_TYPES = {
    "http.get.health",
    "http.head.health",
    "cowrie.session.closed",
    "api.startup",
}

# ── Event type → Cowrie eventid mapping ──────────────────────────────────────

EVENT_TYPE_MAP = {
    # SSH (Cowrie)
    "cowrie.login.failed":          "cowrie.login.failed",
    "cowrie.login.success":         "cowrie.login.success",
    "cowrie.command.input":         "cowrie.command.input",
    "cowrie.session.connect":       "cowrie.session.connect",
    "cowrie.session.closed":        "cowrie.session.closed",
    "cowrie.session.file_download": "cowrie.session.file_download",
    # OpenCanary — map to closest cowrie equivalent
    "ftp.login.attempt":            "cowrie.login.failed",
    "telnet.login.attempt":         "cowrie.login.failed",
    "redis.command":                "cowrie.command.input",
    "redis.auth.attempt":           "cowrie.login.failed",
    # MariaDB
    "mysql.connect":                "cowrie.session.connect",
    "mysql.command":                "cowrie.command.input",
    "mysql.disconnect":             "cowrie.session.closed",
    # HTTP
    "http.request":                 "cowrie.session.connect",
    "http.get":                     "cowrie.session.connect",
    "http.post":                    "cowrie.session.connect",
}


def row_to_cowrie(row) -> dict | None:
    (event_uuid, created_at, sensor, event_type, src_ip,
     src_port, dst_port, username, password, payload,
     session_id, geo_country, geo_city) = row

    if event_type in NOISE_EVENT_TYPES:
        return None

    eventid = EVENT_TYPE_MAP.get(event_type, event_type)

    # Extract command from payload if present
    command_input = None
    download_url  = None
    if payload:
        command_input = payload.get("command") or payload.get("input") or payload.get("CMD")
        download_url  = payload.get("url") or payload.get("download_url")

    effective_port = dst_port or 22
    event = {
        "eventid":   eventid,
        "timestamp": created_at.strftime("%Y-%m-%dT%H:%M:%S.000000Z"),
        "src_ip":    str(src_ip).split("/")[0],
        "src_port":  src_port,
        "dst_port":  effective_port,
        "sensor":    SENSOR_NAME_MAP.get(sensor, sensor),
        "protocol":  PORT_PROTOCOL.get(int(effective_port), "unknown"),
        "session":   session_id or str(event_uuid),
    }

    if username:
        event["username"] = username
    if password:
        event["password"] = password
    if command_input:
        event["input"] = command_input
    if download_url:
        event["url"] = download_url
    if geo_country:
        event["country"] = geo_country
    if geo_city:
        event["city"] = geo_city

    return event


def send_batch(events: list, retries: int = 3) -> tuple[int, int]:
    for attempt in range(1, retries + 1):
        try:
            r = requests.post(INGEST_URL, json=events, headers=HEADERS, timeout=60)
            if r.status_code == 202:
                result = r.json()
                return result.get("accepted", 0), result.get("errors", 0)
            else:
                print(f"  [warn] HTTP {r.status_code} (attempt {attempt}/{retries}): {r.text[:200]}")
        except Exception as e:
            print(f"  [warn] request failed (attempt {attempt}/{retries}): {e}")
        if attempt < retries:
            time.sleep(5 * attempt)  # 5s, 10s backoff
    return 0, len(events)


def main():
    print(f"[backfill] Connecting to PostgreSQL...")
    try:
        conn = psycopg2.connect(POSTGRES_DSN)
    except Exception as e:
        sys.exit(f"ERROR: Cannot connect to PostgreSQL: {e}")

    cur = conn.cursor()

    # Count total events
    cur.execute("SELECT COUNT(*) FROM honeypot_events")
    total = cur.fetchone()[0]
    print(f"[backfill] Total events to send: {total:,}")
    print(f"[backfill] Target: {INGEST_URL}")
    print(f"[backfill] Batch size: {BATCH_SIZE}")
    print()

    cur.execute("""
        SELECT event_id, created_at, sensor, event_type, src_ip,
               src_port, dst_port, username, password, payload,
               session_id, geo_country, geo_city
        FROM honeypot_events
        ORDER BY created_at ASC
    """)

    batch = []
    sent_total = 0
    error_total = 0
    batch_num = 0

    while True:
        rows = cur.fetchmany(BATCH_SIZE)
        if not rows:
            break

        batch = [row_to_cowrie(r) for r in rows]
        batch = [e for e in batch if e]  # filter None

        if not batch:
            continue

        batch_num += 1
        accepted, errors = send_batch(batch)
        sent_total  += accepted
        error_total += errors

        pct = (sent_total / total * 100) if total else 0
        print(f"  batch {batch_num:4d} — accepted {accepted}/{len(batch)} "
              f"| total {sent_total:,}/{total:,} ({pct:.1f}%)")

        time.sleep(SLEEP_BETWEEN)

    cur.close()
    conn.close()

    print()
    print(f"[backfill] Done. Accepted: {sent_total:,}  Errors: {error_total:,}  Total: {total:,}")


if __name__ == "__main__":
    main()
