"""
jupyter_stub.py — Fake Jupyter Notebook server (port 8888)

A minimal FastAPI application that mimics a Jupyter notebook server.
All requests are logged to the same PostgreSQL + Redis pipeline as the main app.

This is a separate process (started by start.sh alongside main.py) so that
port 8888 remains isolated from the main application's state — matching the
behavior of a real Jupyter server running independently.

Deception value:
- Exposed Jupyter endpoints are extremely high-value lures for attackers
  targeting AI/ML infrastructure (common attack vector)
- /api/kernels POST logs any attacker trying to execute code
- /api/contents lists fake notebooks containing references to credentials
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import psycopg2
import psycopg2.extras
import redis as redis_lib
import structlog
from fastapi import FastAPI, Request, Response, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse

# ---------------------------------------------------------------------------
# Configuration (same env vars as main.py — single .env file)
# ---------------------------------------------------------------------------

POSTGRES_DSN = os.environ.get("POSTGRES_DSN", "")
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
SENSOR_NAME = os.environ.get("SENSOR_NAME", "neuro-api-01")

structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(20),
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
)
logger = structlog.get_logger()

APP_DIR = Path(__file__).parent

# ---------------------------------------------------------------------------
# Database (shared connection pool — separate process, own connections)
# ---------------------------------------------------------------------------

_pg_conn: Optional[psycopg2.extensions.connection] = None
_redis_client: Optional[redis_lib.Redis] = None


def _get_pg():
    global _pg_conn
    if _pg_conn is None or _pg_conn.closed:
        _pg_conn = psycopg2.connect(POSTGRES_DSN)
        _pg_conn.autocommit = True
    return _pg_conn


def _get_redis():
    global _redis_client
    if _redis_client is None:
        _redis_client = redis_lib.from_url(
            REDIS_URL, socket_connect_timeout=3, retry_on_timeout=True, decode_responses=True,
        )
    return _redis_client


def _log_event(event: dict[str, Any]) -> None:
    try:
        conn = _get_pg()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO honeypot_events (
                event_id, created_at, sensor, event_type,
                src_ip, src_port, dst_port,
                username, password, payload, raw_log, session_id,
                geo_country, geo_country_code, geo_city, geo_asn, geo_org
            ) VALUES (
                %(event_id)s, %(created_at)s, %(sensor)s, %(event_type)s,
                %(src_ip)s, %(src_port)s, %(dst_port)s,
                %(username)s, %(password)s, %(payload)s, %(raw_log)s, %(session_id)s,
                %(geo_country)s, %(geo_country_code)s, %(geo_city)s, %(geo_asn)s, %(geo_org)s
            )
            """,
            event,
        )
        cur.close()
    except Exception as exc:
        logger.error("jupyter_pg_error", error=str(exc))
    try:
        r = _get_redis()
        stream_event = {k: str(v) if v is not None else "" for k, v in event.items()}
        r.xadd("honeypot:events", stream_event, maxlen=50000, approximate=True)
    except Exception as exc:
        logger.error("jupyter_redis_error", error=str(exc))


def _extract_src_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


def _build_event(request: Request, path_cat: str, body_preview: Optional[str] = None) -> dict:
    src_ip = _extract_src_ip(request)
    session_id = request.cookies.get("nro_session") or str(uuid.uuid4())
    return {
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": f"jupyter.{request.method.lower()}.{path_cat}"[:80],
        "src_ip": src_ip,
        "src_port": request.client.port if request.client else None,
        "dst_port": 8888,
        "username": None,
        "password": None,
        "payload": json.dumps({
            "method": request.method,
            "path": request.url.path,
            "user_agent": request.headers.get("user-agent"),
            "body_preview": body_preview,
        }),
        "raw_log": json.dumps(dict(request.headers)),
        "session_id": session_id,
        "geo_country": None,
        "geo_country_code": None,
        "geo_city": None,
        "geo_asn": None,
        "geo_org": None,
    }

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(docs_url=None, redoc_url=None)

FAKE_NOTEBOOKS = [
    {"name": "model_training_llama3.ipynb", "path": "work/model_training_llama3.ipynb",
     "type": "notebook", "size": 48233, "last_modified": "2026-05-17T10:22:01Z"},
    {"name": "data_preprocessing_v4.ipynb", "path": "work/data_preprocessing_v4.ipynb",
     "type": "notebook", "size": 22117, "last_modified": "2026-05-15T08:44:12Z"},
    {"name": "credential_rotation.ipynb", "path": "work/credential_rotation.ipynb",
     "type": "notebook", "size": 8903, "last_modified": "2026-04-28T14:00:00Z"},
    {"name": "aws_s3_upload.ipynb", "path": "work/aws_s3_upload.ipynb",
     "type": "notebook", "size": 11240, "last_modified": "2026-04-22T09:30:00Z"},
    {"name": "inference_benchmark.ipynb", "path": "work/inference_benchmark.ipynb",
     "type": "notebook", "size": 34812, "last_modified": "2026-05-18T16:05:44Z"},
]

FAKE_KERNELS = [
    {"id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
     "name": "python3", "last_activity": "2026-05-19T08:00:00Z",
     "execution_state": "idle", "connections": 1},
]


@app.on_event("startup")
async def startup():
    for attempt in range(1, 6):
        try:
            _get_pg().cursor().execute("SELECT 1")
            logger.info("jupyter_stub_postgres_connected")
            break
        except Exception as exc:
            logger.warning("jupyter_stub_pg_retry", attempt=attempt, error=str(exc))
            time.sleep(3)
    for attempt in range(1, 6):
        try:
            _get_redis().ping()
            logger.info("jupyter_stub_redis_connected")
            break
        except Exception as exc:
            logger.warning("jupyter_stub_redis_retry", attempt=attempt, error=str(exc))
            time.sleep(3)
    logger.info("jupyter_stub_ready", port=8888)


_JUPYTER_DEV_TOKEN = "nro-dev-token-8f3a2b1c4d5e"


@app.middleware("http")
async def jupyter_request_logger(request: Request, call_next):
    response = await call_next(request)
    response.headers["Server"] = "Jupyter Server 2.14.0"
    return response


def _make_xsrf_token() -> str:
    """Generate a random _xsrf token matching real Jupyter's format."""
    return uuid.uuid4().hex[:32]


@app.get("/", response_class=HTMLResponse)
async def jupyter_index(request: Request):
    """Fake Jupyter Lab login page — sets _xsrf cookie like real Jupyter."""
    event = _build_event(request, "index")
    asyncio.create_task(asyncio.to_thread(_log_event, event))
    xsrf = _make_xsrf_token()
    resp = HTMLResponse(content=_jupyter_login_html(xsrf))
    resp.set_cookie("_xsrf", xsrf, path="/jupyter/", samesite="strict", httponly=False)
    return resp


@app.get("/login", response_class=HTMLResponse)
async def jupyter_login_page(request: Request):
    event = _build_event(request, "login_page")
    asyncio.create_task(asyncio.to_thread(_log_event, event))
    xsrf = _make_xsrf_token()
    resp = HTMLResponse(content=_jupyter_login_html(xsrf))
    resp.set_cookie("_xsrf", xsrf, path="/jupyter/", samesite="strict", httponly=False)
    return resp


@app.post("/login")
async def jupyter_login_post(request: Request):
    body_bytes = await request.body()
    body_preview = body_bytes[:512].decode("utf-8", errors="replace")
    event = _build_event(request, "login_attempt", body_preview)
    passwd = None
    xsrf_form = None
    try:
        from urllib.parse import parse_qs
        parsed = parse_qs(body_bytes.decode("utf-8", errors="replace"))
        passwd = parsed.get("password", [""])[0]
        xsrf_form = parsed.get("_xsrf", [""])[0]
        event["password"] = passwd[:256] if passwd else None
    except Exception:
        pass
    asyncio.create_task(asyncio.to_thread(_log_event, event))

    # Real Jupyter requires _xsrf cookie == _xsrf form field (CSRF check)
    xsrf_cookie = request.cookies.get("_xsrf", "")
    if xsrf_form and xsrf_cookie and xsrf_form != xsrf_cookie:
        # CSRF mismatch — return 403 exactly as real Jupyter does
        return Response(status_code=403, content=b"'_xsrf' argument missing from POST")

    # Dev token discovered in the HTML source — let the attacker in
    if passwd and passwd.strip() == _JUPYTER_DEV_TOKEN:
        # Cookie name matches the actual served host/port seen by the client
        # (nginx proxies /jupyter/ so the external origin is what matters)
        host = request.headers.get("host", "localhost").split(":")[0]
        cookie_name = f"username-{host}-8888"
        resp = Response(status_code=302, headers={"location": "/jupyter/tree"})
        resp.set_cookie(
            cookie_name,
            f"2|1:0|10:{int(time.time())}|{len(cookie_name)}:{cookie_name}|44:bm9yby1kZXYtdG9rZW4tOGYzYTJiMWM0ZDVl|{uuid.uuid4().hex[:40]}",
            httponly=True,
        )
        return resp
    # Wrong token — redirect back to login
    return Response(
        status_code=302,
        headers={"location": "/jupyter/login?next=/jupyter/"},
    )


@app.get("/tree", response_class=HTMLResponse)
@app.get("/tree/{path:path}", response_class=HTMLResponse)
async def jupyter_tree(request: Request, path: str = ""):
    event = _build_event(request, "tree.view")
    asyncio.create_task(asyncio.to_thread(_log_event, event))
    return HTMLResponse(content=_jupyter_tree_html())


@app.get("/api/kernels")
async def list_kernels(request: Request):
    event = _build_event(request, "kernels.list")
    asyncio.create_task(asyncio.to_thread(_log_event, event))
    return FAKE_KERNELS


@app.post("/api/kernels")
async def create_kernel(request: Request):
    """Attacker attempting to create a kernel to run code — high-value event."""
    body_bytes = await request.body()
    body_preview = body_bytes[:512].decode("utf-8", errors="replace")
    event = _build_event(request, "kernels.create", body_preview)
    asyncio.create_task(asyncio.to_thread(_log_event, event))
    kernel_id = str(uuid.uuid4())
    return JSONResponse(
        status_code=201,
        content={
            "id": kernel_id,
            "name": "python3",
            "last_activity": datetime.now(timezone.utc).isoformat(),
            "execution_state": "starting",
            "connections": 0,
        },
    )


@app.delete("/api/kernels/{kernel_id}")
async def delete_kernel(kernel_id: str, request: Request):
    event = _build_event(request, f"kernels.delete")
    asyncio.create_task(asyncio.to_thread(_log_event, event))
    return Response(status_code=204)


@app.get("/api/kernelspecs")
async def kernelspecs(request: Request):
    event = _build_event(request, "kernelspecs")
    asyncio.create_task(asyncio.to_thread(_log_event, event))
    return {
        "default": "python3",
        "kernelspecs": {
            "python3": {
                "name": "python3",
                "spec": {"display_name": "Python 3 (ipykernel)", "language": "python"},
                "resources": {},
            }
        },
    }


@app.get("/api/contents")
@app.get("/api/contents/{path:path}")
async def list_contents(request: Request, path: str = ""):
    event = _build_event(request, f"contents.list")
    asyncio.create_task(asyncio.to_thread(_log_event, event))
    if path and path.endswith(".ipynb"):
        # Return fake notebook metadata for any specific notebook request
        return {
            "name": path.split("/")[-1],
            "path": path,
            "type": "notebook",
            "format": "json",
            "content": {
                "nbformat": 4,
                "nbformat_minor": 5,
                "metadata": {"kernelspec": {"name": "python3", "display_name": "Python 3"}},
                "cells": [
                    {"cell_type": "markdown", "source": "# Model Training\n\nThis notebook trains the LLaMA3 finetune model.\n\nAWS credentials loaded from environment.\n"},
                    {"cell_type": "code", "source": "import boto3\nimport os\n# Credentials from env\naws_key = os.environ.get('AWS_ACCESS_KEY_ID', 'AKIAYZM57LXRGIYTCOUV')\ns3 = boto3.client('s3', aws_access_key_id=aws_key)\n", "outputs": []},
                ],
            },
        }
    return {
        "name": path or "",
        "path": path or "",
        "type": "directory",
        "format": "json",
        "content": FAKE_NOTEBOOKS,
    }


@app.post("/api/contents")
@app.put("/api/contents/{path:path}")
async def save_content(request: Request, path: str = ""):
    body_bytes = await request.body()
    body_preview = body_bytes[:512].decode("utf-8", errors="replace")
    event = _build_event(request, "contents.write", body_preview)
    asyncio.create_task(asyncio.to_thread(_log_event, event))
    # Pretend to accept the write but do nothing
    return JSONResponse(
        status_code=201,
        content={"name": path.split("/")[-1] if path else "untitled.ipynb", "path": path, "type": "notebook"},
    )


@app.get("/api/sessions")
async def list_sessions(request: Request):
    event = _build_event(request, "sessions.list")
    asyncio.create_task(asyncio.to_thread(_log_event, event))
    return [
        {
            "id": "session-001",
            "path": "work/model_training_llama3.ipynb",
            "name": "model_training_llama3.ipynb",
            "type": "notebook",
            "kernel": FAKE_KERNELS[0],
        }
    ]


@app.websocket("/api/kernels/{kernel_id}/channels")
async def kernel_channels(websocket: WebSocket, kernel_id: str):
    """Fake Jupyter kernel WebSocket — accepts but never executes anything."""
    await websocket.accept()
    src_ip = _extract_src_ip(websocket)
    session_id = websocket.cookies.get("nro_session") or str(uuid.uuid4())
    event = {
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": "jupyter.websocket.kernel_connect",
        "src_ip": src_ip,
        "src_port": websocket.client.port if websocket.client else None,
        "dst_port": 8888,
        "username": None,
        "password": None,
        "payload": json.dumps({"kernel_id": kernel_id}),
        "raw_log": None,
        "session_id": session_id,
        "geo_country": None, "geo_country_code": None,
        "geo_city": None, "geo_asn": None, "geo_org": None,
    }
    asyncio.create_task(asyncio.to_thread(_log_event, event))
    try:
        while True:
            data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
            # Log any execution attempts
            exec_event = {**event, "event_id": str(uuid.uuid4()),
                          "event_type": "jupyter.websocket.execute_request",
                          "payload": json.dumps({"kernel_id": kernel_id, "msg_preview": data[:256]})}
            asyncio.create_task(asyncio.to_thread(_log_event, exec_event))
            # Never send a real execution reply — just acknowledge silently
    except Exception:
        pass


def _jupyter_tree_html() -> str:
    notebooks = "".join(
        f'<tr><td><span class="item-icon">📓</span> <a href="/jupyter/notebooks/{nb["path"]}">{nb["name"]}</a></td>'
        f'<td style="color:#888;font-size:0.82rem">{nb["last_modified"][:10]}</td>'
        f'<td style="color:#888;font-size:0.82rem">{nb["size"] // 1024} KB</td></tr>'
        for nb in FAKE_NOTEBOOKS
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Jupyter — work</title>
  <style>
    body {{ background:#0f1117; color:#e0e0e0; font-family:-apple-system,sans-serif; margin:0; }}
    .topbar {{ background:#1a1d27; border-bottom:1px solid #2d3148; padding:10px 24px; display:flex; align-items:center; gap:16px; }}
    .topbar .brand {{ font-size:1rem; font-weight:600; }}
    .topbar .path {{ color:#8b8fa8; font-size:0.85rem; }}
    .topbar .logout {{ margin-left:auto; color:#8b8fa8; font-size:0.82rem; text-decoration:none; }}
    .container {{ max-width:900px; margin:40px auto; padding:0 24px; }}
    h2 {{ font-size:1.1rem; font-weight:500; margin-bottom:16px; }}
    table {{ width:100%; border-collapse:collapse; }}
    th {{ text-align:left; color:#8b8fa8; font-size:0.78rem; font-weight:400; border-bottom:1px solid #2d3148; padding:6px 8px; }}
    td {{ padding:8px; border-bottom:1px solid #1e2030; font-size:0.9rem; }}
    tr:hover td {{ background:#1a1d27; }}
    .item-icon {{ margin-right:6px; }}
    a {{ color:#a5b4fc; text-decoration:none; }}
    a:hover {{ text-decoration:underline; }}
    .new-btn {{ background:#6366f1; color:#fff; border:none; border-radius:5px; padding:7px 16px; font-size:0.85rem; cursor:pointer; }}
  </style>
</head>
<body>
  <div class="topbar">
    <span class="brand">Jupyter</span>
    <span class="path">/ work</span>
    <a class="logout" href="/jupyter/logout">Logout</a>
  </div>
  <div class="container">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
      <h2>work /</h2>
      <button class="new-btn">New ▾</button>
    </div>
    <table>
      <thead><tr><th>Name</th><th>Last Modified</th><th>File Size</th></tr></thead>
      <tbody>{notebooks}</tbody>
    </table>
  </div>
</body>
</html>"""


def _jupyter_login_html(xsrf_token: str = "") -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex, nofollow">
  <title>Neuro JupyterLab — Internal</title>
  <link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
  <style>
    body {{ background: #0f1117; color: #e0e0e0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
    .card {{ background: #1a1d27; border: 1px solid #2d3148; border-radius: 12px; padding: 40px 48px; width: 380px; box-shadow: 0 8px 32px rgba(0,0,0,0.4); }}
    .logo {{ text-align: center; margin-bottom: 28px; }}
    .logo svg {{ width: 40px; height: 40px; }}
    h1 {{ font-size: 1.4rem; font-weight: 600; margin: 0 0 4px 0; text-align: center; }}
    .sub {{ color: #8b8fa8; font-size: 0.85rem; text-align: center; margin-bottom: 28px; }}
    label {{ display: block; font-size: 0.8rem; color: #8b8fa8; margin-bottom: 6px; }}
    input {{ width: 100%; box-sizing: border-box; background: #0f1117; border: 1px solid #2d3148; border-radius: 6px; padding: 10px 12px; color: #e0e0e0; font-size: 0.95rem; margin-bottom: 16px; }}
    input:focus {{ outline: none; border-color: #6366f1; }}
    button {{ width: 100%; background: #6366f1; color: #fff; border: none; border-radius: 6px; padding: 11px; font-size: 1rem; font-weight: 500; cursor: pointer; margin-top: 4px; }}
    button:hover {{ background: #4f52d4; }}
    .footer {{ margin-top: 24px; font-size: 0.75rem; color: #555; text-align: center; }}
  </style>
</head>
<body>
  <!-- TODO: disable token auth before prod deploy — m.chen -->
  <div class="card">
    <div class="logo">
      <svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="20" cy="20" r="19" stroke="#6366f1" stroke-width="2"/>
        <circle cx="20" cy="20" r="4" fill="#6366f1"/>
        <line x1="20" y1="1" x2="20" y2="10" stroke="#6366f1" stroke-width="1.5"/>
        <line x1="20" y1="30" x2="20" y2="39" stroke="#6366f1" stroke-width="1.5"/>
        <line x1="1" y1="20" x2="10" y2="20" stroke="#6366f1" stroke-width="1.5"/>
        <line x1="30" y1="20" x2="39" y2="20" stroke="#6366f1" stroke-width="1.5"/>
        <line x1="7" y1="7" x2="13.5" y2="13.5" stroke="#6366f1" stroke-width="1.2"/>
        <line x1="26.5" y1="26.5" x2="33" y2="33" stroke="#6366f1" stroke-width="1.2"/>
        <line x1="33" y1="7" x2="26.5" y2="13.5" stroke="#6366f1" stroke-width="1.2"/>
        <line x1="13.5" y1="26.5" x2="7" y2="33" stroke="#6366f1" stroke-width="1.2"/>
      </svg>
    </div>
    <h1>Neuro JupyterLab</h1>
    <p class="sub">Neuro AI Infrastructure — Internal Use Only</p>
    <form method="POST" action="/jupyter/login">
      <input type="hidden" name="_xsrf" value="{xsrf_token}">
      <label>Password / Token</label>
      <!-- dev: nro-dev-token-8f3a2b1c4d5e -->
      <input type="password" name="password" placeholder="Enter server token" autocomplete="current-password">
      <button type="submit">Sign In</button>
    </form>
    <div class="footer">Neuro JupyterLab v2.14.0 (build 20260428) | Neuro AI Infrastructure</div>
  </div>
</body>
</html>
"""
