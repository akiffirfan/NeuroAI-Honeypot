#!/usr/bin/env python3
"""
smb_server.py — impacket-based SMB honeypot for Neuro platform (Module 8).

Presents a single SMB2 share named neuro-data-share — a plausible
network-attached dataset store for an ML training platform at NEURO-TRAIN-01.

Cover story: \\NEURO-TRAIN-01\\neuro-data-share — ML dataset network share.
Lure files in /share (bind-mounted from /opt/honeypot/config/smb/) include:
  README.txt                      — "Neuro AI Dataset Repository — Access via \\\\neuro-train-01\\neuro-data-share"
  dataset-index.json              — fake dataset listing with names, sizes, descriptions
  model-manifest-export.json      — same manifest referenced by HTTP /api/v1/lure/model-manifest
  workspace-export-2026-05-31.csv — canary CSV (same file as HTTP lure exfil endpoint)
  training-config-prod.yaml       — fake ML config with placeholder credentials
  checkpoint-final-llama3-8b.bin  — 0-byte stub; appears in dir output

Captures:
  - smb.connect           — TCP accept before SMB handshake
  - smb.auth.attempt      — NTLM AUTHENTICATE_MESSAGE received
  - smb.ntlmv2.hash       — NTLMv2 hash in Hashcat mode 5600 format
  - smb.enum.shares       — share enumeration (smbclient -L, net view, nmap smb-enum-shares)
  - smb.file.read         — SMB2_READ request on a file path
  - smb.file.write        — SMB2_WRITE attempt (returns STATUS_ACCESS_DENIED)
  - smb.pipe.connect      — IPC$/named pipe open (rpcclient, enum4linux, BloodHound)
  - smb.server.started    — startup sentinel event

Critical implementation notes:
  CRIT-R30-1: addShare() readOnly parameter MUST be the STRING "yes", not bool True.
              bool True causes impacket to ignore the read-only flag silently.
  CRIT-R30-2: MUST call server.setSMB2Support(True) before server.start().
              Without this the server is SMB1-only; modern smbclient/Windows refuse to
              negotiate, producing the same fingerprint as a dark port.
  CRIT-R30-3: NTLMv2 challenge key is connData['CHALLENGE_MESSAGE']['challenge'],
              NOT a key named "ServerChallenge". Validated via end-to-end test.

Log format: newline-delimited JSON written to SMB_LOG_FILE, tailed by log-shipper.
Also writes directly to PostgreSQL + Redis (same pattern as jupyter_stub.py).

Static NTLM challenge: 0x0011223344556677
  Hashcat mode 5600 (NTLMv2): username::domain:0011223344556677:NTProofStr:blob
  Use this static value when hashcat-cracking captured hashes offline.
"""

import hashlib
import json
import logging
import os
import signal
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import psycopg2
import redis as redis_lib
import structlog
from impacket import ntlm
from impacket.smbserver import SimpleSMBServer

# ---------------------------------------------------------------------------
# Structured logging
# ---------------------------------------------------------------------------
structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
)
logging.basicConfig(stream=sys.stdout, level=logging.WARNING)
log = structlog.get_logger("smb_lure")

# Suppress impacket's own verbose logging — we emit structured JSON instead
logging.getLogger("impacket").setLevel(logging.CRITICAL)
logging.getLogger("impacket.smbserver").setLevel(logging.CRITICAL)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
POSTGRES_DSN  = os.environ.get("POSTGRES_DSN", "")
REDIS_URL     = os.environ.get("REDIS_URL", "")
SENSOR_NAME   = os.environ.get("SENSOR_NAME", "neuro-smb-01")
SMB_LOG_FILE  = os.environ.get("SMB_LOG_FILE",
                os.environ.get("SMB_LOG", "/var/log/smb/smb_events.json"))
SHARE_NAME    = os.environ.get("SMB_SHARE_NAME", "neuro-data-share")
SERVER_NAME   = os.environ.get("SMB_SERVER_NAME", "NEURO-TRAIN-01")
DOMAIN        = os.environ.get("SMB_DOMAIN", "NEURO")
SHARE_PATH    = "/share"      # bind-mounted from /opt/honeypot/config/smb
LISTEN_IP     = "0.0.0.0"
LISTEN_PORT   = 445

# Static NTLM server challenge — documented for operators.
# Using a static value means all captured hashes can be cracked offline with
# the same hashcat mask: -m 5600 -a 0 hashes.txt wordlist.txt
# Challenge: 0x0011223344556677 (8 bytes)
STATIC_CHALLENGE = bytes.fromhex("0011223344556677")

NTLMSSP_SIG = b"NTLMSSP\x00"

# ---------------------------------------------------------------------------
# Thread-safe JSON event writer
# ---------------------------------------------------------------------------
_log_lock = threading.Lock()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _write_event_to_file(event: dict) -> None:
    """Append one JSON event line to SMB_LOG_FILE. Thread-safe."""
    try:
        with _log_lock:
            with open(SMB_LOG_FILE, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(event) + "\n")
                fh.flush()
    except Exception as exc:
        log.error("smb_log_write_error", error=str(exc))


# ---------------------------------------------------------------------------
# PostgreSQL + Redis direct write (same pattern as jupyter_stub.py)
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
    NULL, NULL, NULL, NULL, NULL,
    NULL, NULL,
    %(username)s, NULL,
    %(payload)s, %(raw_log)s, %(session_id)s,
    %(threat_score)s, %(tags)s, FALSE
)
"""

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
"""

# Per-eventid threat scoring
_THREAT_SCORES = {
    "smb.ntlmv2.hash":  80,
    "smb.file.write":   65,
    "smb.pipe.connect": 65,
    "smb.file.read":    40,
    "smb.enum.shares":  35,
    "smb.auth.attempt": 35,
    "smb.connect":      20,
    "smb.server.started": 0,
}

# Per-eventid tags
_TAGS = {
    "smb.ntlmv2.hash":  ["credential-theft", "smb-probe"],
    "smb.file.write":   ["lateral-movement", "smb-probe"],
    "smb.pipe.connect": ["smb-probe"],
    "smb.file.read":    ["smb-probe"],
    "smb.enum.shares":  ["smb-probe"],
    "smb.auth.attempt": ["smb-probe"],
    "smb.connect":      ["smb-probe"],
}

_pg_conn = None
_pg_lock = threading.Lock()


def _get_pg_conn():
    """Return a shared PostgreSQL connection, reconnecting if needed."""
    global _pg_conn
    if not POSTGRES_DSN:
        return None
    try:
        if _pg_conn is None or _pg_conn.closed:
            _pg_conn = psycopg2.connect(POSTGRES_DSN)
            _pg_conn.autocommit = True
            log.info("postgres_connected")
        else:
            _pg_conn.cursor().execute("SELECT 1")
    except Exception:
        try:
            _pg_conn = psycopg2.connect(POSTGRES_DSN)
            _pg_conn.autocommit = True
        except Exception as exc:
            log.warning("postgres_connect_failed", error=str(exc))
            _pg_conn = None
    return _pg_conn


_redis_client = None


def _get_redis():
    """Return a shared Redis client, reconnecting if needed."""
    global _redis_client
    if not REDIS_URL:
        return None
    try:
        if _redis_client is None:
            _redis_client = redis_lib.from_url(
                REDIS_URL, decode_responses=True,
                socket_connect_timeout=3, socket_timeout=3,
            )
            _redis_client.ping()
    except Exception as exc:
        log.warning("redis_connect_failed", error=str(exc))
        _redis_client = None
    return _redis_client


def _log_event(event: dict) -> None:
    """
    Write one event to:
      1. SMB_LOG_FILE (newline-delimited JSON — tailed by log-shipper)
      2. PostgreSQL honeypot_events (direct write for low latency)
      3. Redis stream honeypot:events (best-effort real-time)

    This mirrors the _log_event() pattern in jupyter_stub.py and main.py.
    The log-shipper SmbTailer will also pick up events from the file and
    re-insert them — that is intentional and safe because log-shipper uses
    a separate event_id per insertion (no ON CONFLICT constraint here).
    To avoid duplication, operators may choose to disable the SmbTailer if
    direct writes are confirmed working; however, the dual-write pattern
    provides resilience if PostgreSQL is briefly unavailable.
    """
    event.setdefault("event_id", str(uuid.uuid4()))
    event.setdefault("timestamp", _now_iso())

    # 1. File write (always — primary path for log-shipper tailing)
    _write_event_to_file(event)

    # 2. PostgreSQL direct write
    eventid     = event.get("eventid", "")
    src_ip      = event.get("src_ip") or None
    payload_raw = {}
    for k in ("ntlmv2_hash", "domain", "pipe_name", "path",
               "file_name", "shares_requested", "share", "server"):
        v = event.get(k)
        if v is not None:
            payload_raw[k] = v

    row = {
        "event_id":   event["event_id"],
        "created_at": event["timestamp"],
        "sensor":     "smb",
        "event_type": eventid,
        "src_ip":     src_ip,
        "src_port":   event.get("src_port"),
        "dst_port":   event.get("dst_port", 445),
        "username":   event.get("username"),
        "payload":    json.dumps(payload_raw) if payload_raw else None,
        "raw_log":    json.dumps({k: v for k, v in event.items()
                                  if not k.startswith("_")}),
        "session_id": event.get("session"),
        "threat_score": _THREAT_SCORES.get(eventid, 10),
        "tags":       _TAGS.get(eventid, []),
    }
    with _pg_lock:
        conn = _get_pg_conn()
        if conn:
            try:
                with conn.cursor() as cur:
                    cur.execute(INSERT_SQL, row)
            except Exception as exc:
                log.warning("postgres_insert_error", error=str(exc), eventid=eventid)

            # Upsert attacker_sessions — best-effort
            if row.get("session_id") and src_ip:
                try:
                    with conn.cursor() as cur:
                        cur.execute(UPSERT_SESSION_SQL, {
                            "session_id": row["session_id"],
                            "src_ip":     src_ip,
                            "created_at": row["created_at"],
                            "sensor":     "smb",
                        })
                except Exception as exc:
                    log.warning("session_upsert_error", error=str(exc))

    # 3. Redis stream (best-effort)
    rc = _get_redis()
    if rc and src_ip:
        try:
            rc.xadd(
                "honeypot:events",
                {
                    "eventid":   eventid,
                    "src_ip":    src_ip or "",
                    "sensor":    "smb",
                    "timestamp": event["timestamp"],
                    "session":   event.get("session") or "",
                },
                maxlen=50000,
                approximate=True,
            )
        except Exception as exc:
            log.debug("redis_publish_error", error=str(exc))


# ---------------------------------------------------------------------------
# NTLMv2 hash extractor
# ---------------------------------------------------------------------------
def _extract_ntlmv2(challenge_bytes: bytes, authenticate_blob: bytes) -> tuple:
    """
    Parse an NTLM AUTHENTICATE_MESSAGE blob and reconstruct the NTLMv2 hash
    in Hashcat mode 5600 format:

        username::domain:ServerChallenge_hex:NTProofStr_hex:blob_hex

    Where:
      - ServerChallenge_hex = hex(challenge_bytes) = "0011223344556677"
      - NTProofStr_hex      = hex(nt_response[:16])
      - blob_hex            = hex(nt_response[16:])

    Returns (hashcat_hash_str, username_str, domain_str) or (None, "", "")
    if the message is NTLMv1 (nt_response < 24 bytes) or unparseable.

    impacket 0.12.0 NTLMAuthChallengeResponse fields (accessed via .get()):
      user_name         — bytes, UTF-16LE encoded
      domain_name       — bytes, UTF-16LE encoded
      NTChallengeResponse — bytes; first 16 bytes = NTProofStr, remainder = client blob
    """
    try:
        auth = ntlm.NTLMAuthChallengeResponse(authenticate_blob)
        nt_response = auth.get("NTChallengeResponse") or b""
        if len(nt_response) < 24:
            # NTLMv1 response is exactly 24 bytes with no client blob.
            # Different Hashcat mode (5500) — not handled here.
            return None, "", ""

        nt_proof_str_hex = nt_response[:16].hex()
        nt_blob_hex      = nt_response[16:].hex()
        server_chal_hex  = challenge_bytes.hex() if challenge_bytes else STATIC_CHALLENGE.hex()

        username = (auth.get("user_name") or b"").decode("utf-16-le", errors="replace").strip()
        domain   = (auth.get("domain_name") or b"").decode("utf-16-le", errors="replace").strip()

        # Hashcat 5600 format: user::domain:ServerChallenge:NTProofStr:blob
        hashcat_hash = f"{username}::{domain}:{server_chal_hex}:{nt_proof_str_hex}:{nt_blob_hex}"
        return hashcat_hash, username, domain
    except Exception as exc:
        log.debug("ntlmv2_parse_error", error=str(exc))
        return None, "", ""


# ---------------------------------------------------------------------------
# impacket SMB server subclass — NeuroDataShare
# ---------------------------------------------------------------------------
# SimpleSMBServer is subclassed to intercept authentication events and capture
# NTLMv2 hashes. All other hooks (file access, share enumeration, pipe
# connections) are wired via impacket's logging handler mechanism.
#
# CRIT-R30-2 note: setSMB2Support(True) is called in _build_server() before
# start() — this is the essential call that enables SMB2 negotiation. Without
# it, impacket defaults to SMB1-only and modern clients (smbclient, Windows,
# crackmapexec) refuse to negotiate.
#
# CRIT-R30-1 note: addShare() readOnly parameter must be the STRING "yes",
# not the bool True. impacket's share registry checks this value with a string
# comparison: `if shareReadOnly == "yes"`. Passing bool True evaluates to
# str(True) == "True" which does NOT match "yes" — the share becomes writable.
#
# CRIT-R30-3 note: The server challenge for NTLMv2 hash reconstruction is
# accessed from connData['CHALLENGE_MESSAGE']['challenge'] (a field in the
# impacket NTLM CHALLENGE_MESSAGE structure), not from a top-level key called
# "ServerChallenge". We use our static STATIC_CHALLENGE as fallback.

class NeuroDataShare(SimpleSMBServer):
    """
    impacket SimpleSMBServer subclass that intercepts NTLM authentication
    to capture NTLMv2 challenge/response hashes.

    All other SMB events (connect, share enum, file access, pipe connect)
    are captured via the SmbEventLogger logging handler wired to the
    impacket logger in main().
    """

    def __init__(self, listen_address: str, listen_port: int):
        super().__init__(listen_address, listen_port)
        # Track per-connection session IDs so related auth + connect events share a session
        self._session_map: dict = {}   # connId -> session_id
        self._session_lock = threading.Lock()

    def _get_or_create_session(self, conn_id, src_ip: str) -> str:
        with self._session_lock:
            if conn_id not in self._session_map:
                self._session_map[conn_id] = hashlib.sha256(
                    f"{src_ip}445{uuid.uuid4().hex}".encode()
                ).hexdigest()[:16]
            return self._session_map[conn_id]

    def _cleanup_session(self, conn_id) -> None:
        with self._session_lock:
            self._session_map.pop(conn_id, None)

    def _do_authenticate(self, connId, recvPacket, SMBCommand, recvSignal):
        """
        Called on SMB1 NTLM AUTHENTICATE_MESSAGE.
        Intercepts to extract NTLMv2 hash, then calls super() to reject the auth.
        """
        self._handle_auth(connId, SMBCommand)
        return super()._do_authenticate(connId, recvPacket, SMBCommand, recvSignal)

    def _handle_auth(self, connId, SMBCommand) -> None:
        """Extract NTLMv2 hash from an authenticate command blob and emit events."""
        client_ip   = "unknown"
        client_port = 0
        try:
            conn_data = self.getConnectionData(connId)
            client_ip   = conn_data.get("ClientIP", "unknown")
            client_port = conn_data.get("ClientPort", 0)
        except Exception:
            pass

        session_id = self._get_or_create_session(connId, str(client_ip))

        try:
            # Extract the NTLMSSP blob from the SecurityBlob field
            security_blob = None
            try:
                security_blob = SMBCommand["SecurityBlob"]
            except (KeyError, TypeError):
                pass
            try:
                security_blob = security_blob or SMBCommand.getData()
            except Exception:
                pass

            if security_blob is None:
                return

            idx = security_blob.find(NTLMSSP_SIG)
            if idx < 0:
                return

            ntlm_blob = security_blob[idx:]
            # NTLMSSP message type is at offset 8–12: type 3 = AUTHENTICATE_MESSAGE
            if len(ntlm_blob) < 12 or ntlm_blob[8:12] != b"\x03\x00\x00\x00":
                return

            # CRIT-R30-3: Retrieve server challenge from CHALLENGE_MESSAGE structure.
            # impacket stores it as connData['CHALLENGE_MESSAGE']['challenge'].
            # Fall back to STATIC_CHALLENGE if the key is unavailable.
            challenge_bytes = STATIC_CHALLENGE
            try:
                conn_data = self.getConnectionData(connId)
                challenge_msg = conn_data.get("CHALLENGE_MESSAGE")
                if challenge_msg is not None:
                    challenge_bytes = bytes(challenge_msg["challenge"])
            except Exception:
                challenge_bytes = STATIC_CHALLENGE

            ntlmv2_hash, username, domain = _extract_ntlmv2(
                challenge_bytes, ntlm_blob
            )

            _log_event({
                "eventid":      "smb.ntlmv2.hash",
                "src_ip":       str(client_ip),
                "src_port":     int(client_port) if client_port else None,
                "dst_port":     445,
                "username":     username or None,
                "password":     None,
                "session":      session_id,
                "ntlmv2_hash":  ntlmv2_hash,
                "domain":       domain or None,
                "sensor":       "smb",
                "_sensor_type": "smb",
                "_protocol":    "smb",
            })
            log.warning("ntlmv2_captured", src_ip=client_ip, username=username)

            # Also emit smb.auth.attempt so the connect→auth flow is visible
            _log_event({
                "eventid":      "smb.auth.attempt",
                "src_ip":       str(client_ip),
                "src_port":     int(client_port) if client_port else None,
                "dst_port":     445,
                "username":     username or None,
                "password":     None,
                "session":      session_id,
                "sensor":       "smb",
                "_sensor_type": "smb",
                "_protocol":    "smb",
            })

        except Exception as exc:
            log.debug("auth_intercept_error", error=str(exc))


# ---------------------------------------------------------------------------
# impacket logging interceptor — captures non-auth SMB events
# ---------------------------------------------------------------------------
# impacket emits connection, share enumeration, file access, and pipe events
# via Python's logging module to the "impacket.smbserver" logger.
# We intercept these with a custom handler, parse the log messages, and emit
# structured honeypot events.
#
# This is the canonical approach because impacket does not expose public
# callback hooks for these event types in SimpleSMBServer.

class SmbEventLogger(logging.Handler):
    """
    Intercepts impacket's SMBServer log output to extract non-auth events.

    Events captured:
      - "Incoming connection" lines → smb.connect
      - "NetrShareEnum" lines       → smb.enum.shares
      - "OpenFile" / "QueryInfo" on real paths → smb.file.read
      - "Write" attempts           → smb.file.write
      - "\\PIPE\\" in path         → smb.pipe.connect
    """

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = record.getMessage()
            self._parse_and_emit(msg, record)
        except Exception:
            pass   # never let a log handler crash the server

    def _parse_and_emit(self, msg: str, record: logging.LogRecord) -> None:
        msg_lower = msg.lower()

        # Incoming connection
        if "incoming connection" in msg_lower or "new connection from" in msg_lower:
            src_ip, src_port = self._extract_ip_port(msg)
            if src_ip:
                session_id = hashlib.sha256(
                    f"{src_ip}445{time.time()}".encode()
                ).hexdigest()[:16]
                _log_event({
                    "eventid":      "smb.connect",
                    "src_ip":       src_ip,
                    "src_port":     src_port,
                    "dst_port":     445,
                    "username":     None,
                    "password":     None,
                    "session":      session_id,
                    "sensor":       "smb",
                    "_sensor_type": "smb",
                    "_protocol":    "smb",
                })
            return

        # Share enumeration — NetShareEnum RPC call
        if "netshareenum" in msg_lower or "share enum" in msg_lower:
            src_ip, src_port = self._extract_ip_port(msg)
            session_id = hashlib.sha256(
                f"{src_ip}445enum{time.time()}".encode()
            ).hexdigest()[:16]
            _log_event({
                "eventid":         "smb.enum.shares",
                "src_ip":          src_ip or "",
                "src_port":        src_port,
                "dst_port":        445,
                "username":        self._extract_username(msg),
                "password":        None,
                "session":         session_id,
                "shares_requested": SHARE_NAME.upper(),
                "sensor":          "smb",
                "_sensor_type":    "smb",
                "_protocol":       "smb",
            })
            return

        # Named pipe connection — RPC enumeration via IPC$
        if "\\pipe\\" in msg_lower or "ipc$" in msg_lower or "\\\\pipe" in msg_lower:
            src_ip, src_port = self._extract_ip_port(msg)
            pipe_name = self._extract_pipe_name(msg)
            session_id = hashlib.sha256(
                f"{src_ip}445pipe{time.time()}".encode()
            ).hexdigest()[:16]
            _log_event({
                "eventid":      "smb.pipe.connect",
                "src_ip":       src_ip or "",
                "src_port":     src_port,
                "dst_port":     445,
                "username":     self._extract_username(msg),
                "password":     None,
                "session":      session_id,
                "pipe_name":    pipe_name,
                "sensor":       "smb",
                "_sensor_type": "smb",
                "_protocol":    "smb",
            })
            return

        # File write attempt (returns STATUS_ACCESS_DENIED due to readOnly="yes")
        if any(w in msg_lower for w in ("smb2_write", "write request", "setinfo")):
            src_ip, src_port = self._extract_ip_port(msg)
            path, fname = self._extract_path(msg)
            session_id = hashlib.sha256(
                f"{src_ip}445write{time.time()}".encode()
            ).hexdigest()[:16]
            _log_event({
                "eventid":      "smb.file.write",
                "src_ip":       src_ip or "",
                "src_port":     src_port,
                "dst_port":     445,
                "username":     self._extract_username(msg),
                "password":     None,
                "session":      session_id,
                "path":         path,
                "file_name":    fname,
                "sensor":       "smb",
                "_sensor_type": "smb",
                "_protocol":    "smb",
            })
            return

        # File read / open / query
        if any(w in msg_lower for w in ("smb2_read", "openfile", "queryinfo", "read request")):
            src_ip, src_port = self._extract_ip_port(msg)
            path, fname = self._extract_path(msg)
            if fname and "." in fname:   # filter out IPC$ and empty paths
                session_id = hashlib.sha256(
                    f"{src_ip}445read{time.time()}".encode()
                ).hexdigest()[:16]
                _log_event({
                    "eventid":      "smb.file.read",
                    "src_ip":       src_ip or "",
                    "src_port":     src_port,
                    "dst_port":     445,
                    "username":     self._extract_username(msg),
                    "password":     None,
                    "session":      session_id,
                    "path":         path,
                    "file_name":    fname,
                    "sensor":       "smb",
                    "_sensor_type": "smb",
                    "_protocol":    "smb",
                })

    @staticmethod
    def _extract_ip_port(msg: str) -> tuple:
        """Extract (ip, port) from an impacket log line. Returns ('', None) if not found."""
        import re
        # Pattern: "1.2.3.4:12345" or "(1.2.3.4, 12345)"
        m = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[:\s,]+(\d{2,5})', msg)
        if m:
            try:
                return m.group(1), int(m.group(2))
            except (ValueError, IndexError):
                return m.group(1), None
        m2 = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', msg)
        if m2:
            return m2.group(1), None
        return "", None

    @staticmethod
    def _extract_username(msg: str) -> str | None:
        """Extract username from log line if present."""
        import re
        m = re.search(r'user[:\s]+([^\s,]+)', msg, re.IGNORECASE)
        if m:
            return m.group(1)[:64]
        return None

    @staticmethod
    def _extract_pipe_name(msg: str) -> str:
        """Extract named pipe path from log line."""
        import re
        m = re.search(r'\\\\pipe\\\\([^\s]+)', msg, re.IGNORECASE)
        if m:
            return "\\\\" + m.group(1)
        m2 = re.search(r'\\pipe\\([^\s]+)', msg, re.IGNORECASE)
        if m2:
            return "\\pipe\\" + m2.group(1)
        return "(unknown)"

    @staticmethod
    def _extract_path(msg: str) -> tuple:
        """Extract (full_path, filename) from log line."""
        import re
        # Look for paths like /share/filename.ext or \share\filename.ext
        m = re.search(r'[/\\]([^\s/\\]+\.[^\s]+)', msg)
        if m:
            fname = m.group(1)
            return m.group(0), fname
        return "", ""


# ---------------------------------------------------------------------------
# Server factory
# ---------------------------------------------------------------------------
def _build_server() -> NeuroDataShare:
    """
    Construct and configure the impacket SMB honeypot server.

    Critical configuration:
      1. setSMBChallenge(STATIC_CHALLENGE) — static 8-byte challenge for hashcat
      2. setSMB2Support(True)             — CRIT-R30-2: enables SMB2 negotiation
      3. addShare(..., readOnly="yes")     — CRIT-R30-1: STRING "yes", not bool True
      4. setLogFile("/dev/null")          — suppress impacket's own file log
    """
    server = NeuroDataShare(LISTEN_IP, LISTEN_PORT)

    # Set static NTLM challenge — must be exactly 8 bytes
    server.setSMBChallenge(STATIC_CHALLENGE)

    # CRIT-R30-2: Enable SMB2 support BEFORE start().
    # Without this the server negotiates SMB1 only. Modern clients (smbclient 4.x,
    # Windows 10+, crackmapexec) require SMB2 and will refuse to connect, making
    # the port appear as a dark/non-responsive listener — same fingerprint as
    # CRIT-R28-1 (the OpenCanary SMB failure that led to this implementation).
    server.setSMB2Support(True)

    # Suppress impacket's file-based log — we emit structured JSON instead
    server.setLogFile("/dev/null")

    # CRIT-R30-1: readOnly MUST be the STRING "yes", not the bool True.
    # impacket smbserver.py checks: `if shareReadOnly == "yes":` (string comparison).
    # Passing bool True → str(True) = "True" which != "yes" → share becomes writable.
    # IPC$ is added automatically by impacket for named pipe (RPC) support.
    server.addShare(
        SHARE_NAME.upper(),                       # share name — uppercase per SMB convention
        SHARE_PATH,                               # host path bind-mounted into container
        f"Neuro ML dataset storage — {DOMAIN}",   # share comment visible in share listings
        "yes",                                    # CRIT-R30-1: string "yes" not bool True
    )

    return server


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    Path(SMB_LOG_FILE).parent.mkdir(parents=True, exist_ok=True)

    log.warning("smb_lure_starting",
                share=SHARE_NAME, server=SERVER_NAME,
                ip=LISTEN_IP, port=LISTEN_PORT,
                smb2="enabled",
                challenge=STATIC_CHALLENGE.hex())

    # Wire SmbEventLogger to impacket's logger so connection/file/pipe events are captured
    smb_event_handler = SmbEventLogger()
    smb_event_handler.setLevel(logging.DEBUG)
    impacket_smb_logger = logging.getLogger("impacket.smbserver")
    impacket_smb_logger.addHandler(smb_event_handler)
    impacket_smb_logger.setLevel(logging.DEBUG)
    # Also hook the root impacket logger for any events that bypass the sublogger
    impacket_root_logger = logging.getLogger("impacket")
    impacket_root_logger.addHandler(smb_event_handler)
    impacket_root_logger.setLevel(logging.DEBUG)

    # Emit startup sentinel event
    _log_event({
        "eventid":    "smb.server.started",
        "src_ip":     "0.0.0.0",
        "src_port":   None,
        "dst_port":   445,
        "username":   None,
        "password":   None,
        "session":    "startup",
        "share":      SHARE_NAME,
        "server":     SERVER_NAME,
        "domain":     DOMAIN,
        "sensor":     "smb",
        "_sensor_type": "smb",
        "_protocol":    "smb",
    })

    def _shutdown(sig, frame):
        log.warning("smb_lure_stopping", signal=sig)
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    server = _build_server()

    log.warning("smb_lure_ready",
                share=f"\\\\{SERVER_NAME}\\{SHARE_NAME.upper()}",
                listening=f"{LISTEN_IP}:{LISTEN_PORT}")

    # server.start() is blocking — runs impacket's internal select() loop
    server.start()


if __name__ == "__main__":
    main()
