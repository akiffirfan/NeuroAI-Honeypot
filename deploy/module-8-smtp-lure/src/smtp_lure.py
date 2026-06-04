#!/usr/bin/env python3
"""
smtp_lure.py — Minimal ESMTP listener for Neuro Honeypot Platform

Speaks just enough SMTP to complete a transaction and capture:
  - MAIL FROM / RCPT TO addresses
  - VRFY/EXPN enumeration attempts (user discovery)
  - DATA body (phishing payload, spam relay content, or attacker notes)

All events written to PostgreSQL honeypot_events and Redis Stream.
Log lines are written to stdout (JSON) for Docker logging.

Binds on port 25 (DNAT'd from host port 25 to this container).
"""

import asyncio
import json
import logging
import os
import re
import time
import uuid
from datetime import datetime, timezone

import psycopg2
import redis as redis_lib

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
POSTGRES_DSN = os.environ["POSTGRES_DSN"]
REDIS_URL    = os.environ.get("REDIS_URL", "")
SENSOR_NAME  = os.environ.get("SENSOR_NAME", "neuro-smtp-01")
BIND_HOST    = os.environ.get("SMTP_BIND_HOST", "0.0.0.0")
BIND_PORT    = int(os.environ.get("SMTP_BIND_PORT", "25"))
BANNER       = os.environ.get("SMTP_BANNER",
    "220 mail.neuro.ai ESMTP Postfix (Ubuntu/Focal) -- Neuro AI Platform")

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}',
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("smtp_lure")

# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------
_pg_conn = None
_redis   = None

def _get_pg():
    global _pg_conn
    if _pg_conn is None or _pg_conn.closed:
        _pg_conn = psycopg2.connect(POSTGRES_DSN)
        _pg_conn.autocommit = True
    return _pg_conn

def _get_redis():
    global _redis
    if _redis is None and REDIS_URL:
        _redis = redis_lib.from_url(REDIS_URL, socket_connect_timeout=3,
                                     decode_responses=True)
    return _redis

def _log_event(event_type: str, src_ip: str | None, username: str = None,
               password: str = None, payload_dict: dict = None) -> None:
    if not src_ip:
        return  # INET NOT NULL — skip events with no peer address
    eid = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    payload_json = json.dumps(payload_dict or {})
    try:
        conn = _get_pg()
        cur  = conn.cursor()
        cur.execute("""
            INSERT INTO honeypot_events
                (event_id, created_at, sensor, event_type,
                 src_ip, src_port, dst_port,
                 username, password, payload, raw_log, session_id,
                 geo_country, geo_country_code, geo_city, geo_asn, geo_org)
            VALUES
                (%s, %s, %s, %s,
                 %s, %s, %s,
                 %s, %s, %s, %s, %s,
                 NULL, NULL, NULL, NULL, NULL)
        """, (eid, now, SENSOR_NAME, event_type,
              src_ip, None, BIND_PORT,
              username, password, payload_json, payload_json,
              eid[:16]))
        cur.close()
        log.info(f"logged event_type={event_type} src_ip={src_ip}")
    except Exception as exc:
        log.error(f"pg_error: {exc}")

    try:
        r = _get_redis()
        if r:
            r.xadd("honeypot:events", {
                "eventid":   event_type,
                "src_ip":    src_ip or "",
                "sensor":    SENSOR_NAME,
                "timestamp": now.isoformat(),
                "session":   eid[:16],
            }, maxlen=50000, approximate=True)
    except Exception as exc:
        log.warning(f"redis_error: {exc}")


# ---------------------------------------------------------------------------
# SMTP session handler
# ---------------------------------------------------------------------------

class SMTPSession:
    MAX_DATA_BYTES = 65536   # 64KB max body capture

    def __init__(self, reader, writer):
        self.reader    = reader
        self.writer    = writer
        self.peer      = writer.get_extra_info("peername")
        self.src_ip    = self.peer[0] if self.peer else None
        self.mail_from = None
        self.rcpt_to   = []
        self.data_buf  = []
        self.session_id = str(uuid.uuid4())[:16]

    async def send(self, line: str) -> None:
        self.writer.write((line + "\r\n").encode())
        await self.writer.drain()

    async def readline(self) -> str:
        try:
            raw = await asyncio.wait_for(self.reader.readline(), timeout=30)
            return raw.decode("utf-8", errors="replace").rstrip("\r\n")
        except asyncio.TimeoutError:
            return "QUIT"
        except Exception:
            return "QUIT"

    async def run(self) -> None:
        log.info(f"smtp_connect src_ip={self.src_ip}")
        _log_event("smtp.session.connect", self.src_ip,
                   payload_dict={"src_ip": self.src_ip})

        await self.send(BANNER)

        in_data = False
        data_size = 0

        while True:
            line = await self.readline()
            if not line:
                break

            upper = line.upper().strip()

            # DATA collection mode
            if in_data:
                if line == ".":
                    in_data = False
                    body = "\n".join(self.data_buf)
                    _log_event("smtp.data.received", self.src_ip,
                               username=self.mail_from,
                               payload_dict={
                                   "mail_from": self.mail_from,
                                   "rcpt_to":   self.rcpt_to,
                                   "body_preview": body[:500],
                                   "body_size":    data_size,
                               })
                    await self.send("250 2.0.0 Ok: queued as " + uuid.uuid4().hex[:12])
                else:
                    if data_size < self.MAX_DATA_BYTES:
                        self.data_buf.append(line)
                        data_size += len(line)
                continue

            # Command dispatch
            if upper.startswith("EHLO") or upper.startswith("HELO"):
                domain = line.split(None, 1)[1] if " " in line else "unknown"
                _log_event("smtp.ehlo", self.src_ip,
                           payload_dict={"domain": domain})
                if upper.startswith("EHLO"):
                    await self.send("250-mail.neuro.ai Hello")
                    await self.send("250-SIZE 10485760")
                    await self.send("250-8BITMIME")
                    await self.send("250 HELP")
                else:
                    await self.send("250 mail.neuro.ai")

            elif upper.startswith("MAIL FROM"):
                addr = re.findall(r"<(.+?)>", line)
                self.mail_from = addr[0] if addr else line[10:].strip()
                _log_event("smtp.mail.from", self.src_ip,
                           username=self.mail_from,
                           payload_dict={"mail_from": self.mail_from})
                await self.send("250 2.1.0 Ok")

            elif upper.startswith("RCPT TO"):
                addr = re.findall(r"<(.+?)>", line)
                rcpt = addr[0] if addr else line[8:].strip()
                self.rcpt_to.append(rcpt)
                _log_event("smtp.rcpt.to", self.src_ip,
                           username=self.mail_from,
                           payload_dict={"rcpt_to": rcpt,
                                         "mail_from": self.mail_from})
                await self.send("250 2.1.5 Ok")

            elif upper == "DATA":
                if not self.mail_from:
                    await self.send("503 5.5.1 Error: need MAIL command")
                else:
                    await self.send("354 End data with <CR><LF>.<CR><LF>")
                    in_data   = True
                    data_size = 0
                    self.data_buf = []

            elif upper.startswith("VRFY") or upper.startswith("EXPN"):
                cmd  = upper.split()[0]
                user = line.split(None, 1)[1] if " " in line else ""
                _log_event("smtp.vrfy", self.src_ip,
                           username=user,
                           payload_dict={"cmd": cmd, "user": user})
                # Pretend user exists — lures more enumeration
                await self.send(f"252 2.5.2 Cannot VRFY user, but will accept message")

            elif upper.startswith("AUTH"):
                parts = line.split()
                mechanism = parts[1] if len(parts) > 1 else ""
                creds = parts[2] if len(parts) > 2 else ""
                _log_event("smtp.auth.attempt", self.src_ip,
                           password=creds[:256] or None,
                           payload_dict={"mechanism": mechanism, "creds": creds[:256]})
                await self.send("535 5.7.8 Authentication credentials invalid")

            elif upper == "RSET":
                self.mail_from = None
                self.rcpt_to   = []
                self.data_buf  = []
                await self.send("250 2.0.0 Ok")

            elif upper == "NOOP":
                await self.send("250 2.0.0 Ok")

            elif upper.startswith("QUIT"):
                await self.send("221 2.0.0 Bye")
                break

            else:
                await self.send("500 5.5.2 Error: command not recognized")

        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass
        log.info(f"smtp_disconnect src_ip={self.src_ip}")


async def handle_client(reader, writer) -> None:
    session = SMTPSession(reader, writer)
    try:
        await session.run()
    except Exception as exc:
        log.warning(f"session_error src_ip={session.src_ip} error={exc}")


async def main() -> None:
    log.info(f"smtp_lure starting on {BIND_HOST}:{BIND_PORT}")
    server = await asyncio.start_server(handle_client, BIND_HOST, BIND_PORT)
    async with server:
        log.info(f"smtp_lure ready — listening on {BIND_HOST}:{BIND_PORT}")
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
