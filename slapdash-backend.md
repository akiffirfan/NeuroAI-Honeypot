# SlapDash Backend Implementation Plan
# Neuro by Cyveera — FastAPI v2 API

**Status**: Pre-implementation plan — pending Gatekeeper review before any code is written.
**Scope**: All `/api/v2/` routes, session auth, database schema additions, static asset serving, nginx wiring, and the telemetry endpoint required by the React SPA at `SlapDash-Frontend/`.

---

# Checkpoint Download — Implementation Plan

## Scope

The `RunsTable.tsx` `RunDetail` panel has an inert "Download checkpoint" button at line 175:

```tsx
<button className="nro-btn-secondary w-full">Download checkpoint</button>
```

It has no `onClick` handler and no `href`. This plan wires that button to a backend endpoint that serves a realistic fake PyTorch-style checkpoint binary with an embedded DNS canarytoken URL, logs the download as `http.lure.data_exfil`, and pushes to HoneyDash.

**Gatekeeper verdict (Backend-14, 2026-06-12):** CONDITIONAL PASS — resolved as Rev 11 (this revision).

**MF-1 resolved:** No explicit `_push_honeydash_async` in the handler. The middleware handles HoneyDash push automatically via `X-Lure-Data-Exfil: true`. Pattern mirrors `v2_billing_invoice` and `v2_artifacts_download`.

**MF-2 resolved:** `/api/v2/runs` is NOT added to `_LURE_PATHS`. It is not needed — the `X-Lure-Data-Exfil` header already forces `event_type = http.lure.data_exfil` regardless of `_LURE_PATHS` membership. Adding the prefix would poison the legitimate runs-listing endpoint with spurious `X-Debug-Mode: enabled` headers and false HoneyDash "Lure Access" cards on every SPA page mount.

**MF-3 resolved:** `run_id` is regex-sanitised before use in `Content-Disposition` (mirrors `v2_billing_invoice` `safe_id` pattern).

**MF-4 resolved:** Supplementary `http.lure.checkpoint_downloaded` event dropped entirely. A single `http.lure.data_exfil` event from the middleware is the only logging path. The `run_id` is captured in `payload.path` on that event.

**DG-1 resolved:** 2 MB null tail replaced with 64 KB of pseudo-random bytes. The file is documented as a canary file, not a loadable PyTorch model.

---

## 1. Backend Route

### Route signature

```python
@app.get("/api/v2/runs/{run_id}/checkpoint")
async def v2_run_checkpoint_download(run_id: str, request: Request):
```

**Method:** `GET`

**Path:** `/api/v2/runs/{run_id}/checkpoint`

**Auth:** Session-required via `await _v2_session_required(request)`. The v2 session uses `nro_session_v2` cookie — do not use the v1 `_session_ok()` helper. If `_v2_session_required` raises 401, FastAPI returns the exception automatically and the middleware still logs the unauthenticated attempt.

**Why `{run_id}` in the path:** The frontend already has the `run_id` from the `RunDetail` component prop (`run.id`, which is `run_id` from the DB). Embedding it in the path is realistic for an ML platform API. All run IDs map to the same shared checkpoint file — see section 7.

**run_id sanitisation (MF-3):** Validate against the known run-ID shape before reflecting into the filename. Copy exactly the pattern from `v2_billing_invoice`:

```python
safe_run_id = run_id if re.match(r"^[a-zA-Z0-9._-]{1,64}$", run_id) else "run-latest"
```

Use `safe_run_id` in both `Content-Disposition` filename and the response. This prevents header-injection via a malicious path segment like `$(id)` or a CR/LF sequence.

**Response headers:**
```
Content-Disposition: attachment; filename="checkpoint-{safe_run_id}-latest.bin"
Content-Type: application/octet-stream
X-Lure-Data-Exfil: true
```

The `X-Lure-Data-Exfil: true` header is the existing middleware signal. The middleware reads it after `call_next()`, sets `event_type = http.lure.data_exfil`, fires `_push_honeydash_async(event, "Data Exfil")` (line 680-683 in main.py), and strips the header before the client sees it. The handler does NOT call `_push_honeydash_async` or `_log_event_async` directly — the middleware is the single logging and push path for this event.

---

## 2. File Content

### Why a PyTorch-style `.bin` and not a bare stub

The existing `_CHECKPOINT_STUB_BIN` at line 966 is a 32-byte ELF header followed by plaintext comments. It already embeds lure credentials and AWS key but does **not** embed the DNS canarytoken URL. It also uses an ELF header — fine for a raw binary, but PyTorch `.bin` files (which is what real checkpoints from `torch.save()` are) use Python's pickle protocol, not ELF. File scanners like `file(1)` will fingerprint an ELF as an executable, not a model checkpoint. This breaks cover.

### New checkpoint content: `_CHECKPOINT_V2_BIN`

Define a new module-level constant. Do not reuse or modify `_CHECKPOINT_STUB_BIN` — that is registered in `_LURE_FILE_REGISTRY` for a different download path (`/api/v1/data/exports/download?file=checkpoint-final.bin`) and changing it would break existing tests.

**DG-1 — This file is documented as a canary file, not a loadable PyTorch model.** `torch.load()` on the raw pickle bytes will deserialise and return the embedded string. A human who runs `python -c "import torch; print(torch.load('checkpoint.bin', weights_only=False))"` will get the plaintext string with the canarytoken URL — which is the intended outcome. The pseudo-random tail is not valid tensor data; this is a deliberate canary, not a model stub. The goal is triggering the DNS canarytoken on any tool that extracts URLs or resolves HTTP hosts.

**Exact byte layout:**

```python
# DNS canarytoken URL — already registered and live
_CHECKPOINT_CANARY_URL = "http://zy2s1wepypyvizi06loltahwj.canarytokens.com/v1/metrics"

def _build_checkpoint_v2_bin() -> bytes:
    """
    Build a canary checkpoint binary with a pickle protocol 2 header.

    This is a canary file, NOT a loadable PyTorch model. It contains:
      - A pickle protocol 2 unicode string with lure credentials and the DNS canarytoken URL
      - 64 KB of pseudo-random bytes as a realistic-looking tail

    Canarytoken trigger surfaces:
      - strings(1) / grep: extracts the URL verbatim from the UTF-8 payload
      - torch.load() / pickle.loads(): deserialises the string — URL appears in memory
      - AV scanners / sandbox detonation: URL extraction triggers the DNS resolution
      - The DNS canarytoken fires on first hostname resolution, before any HTTP fetch

    Layout:
      [0:2]    Pickle protocol 2 header (\\x80\\x02)
      [2:7]    BINUNICODE opcode + 4-byte LE length (\\x58 + struct.pack('<I', len))
      [7:N]    UTF-8 plaintext block — extractable by strings(1) and pickle
      [N]      Pickle STOP opcode (b'.')
      [N+1:]   64 KB pseudo-random bytes (not null padding — entropy looks more like real data)
    When any tool calls strings or scans for URLs, it finds the token.
    The canarytoken fires when their machine resolves the hostname — which curl,
    requests, Python's urllib, and most HTTP libraries do on the first call.
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

    # Pickle protocol 2 + BINUNICODE (4-byte LE length, handles > 255 bytes)
    payload = b"\x80\x02\x58" + struct.pack("<I", len(inner)) + inner + b"."
    # 2 MB zero padding — realistic checkpoint size for a small model version
    tail = b"\x00" * (2 * 1024 * 1024)
    return payload + tail


_CHECKPOINT_V2_BIN: bytes = _build_checkpoint_v2_bin()
```

**Why this layout is detectable by canarytoken tools:**
- `strings(1)` and `grep` will extract the URL from the UTF-8 payload verbatim.
- Python `pickle.loads()` will deserialise the bytes and return the plaintext string. If the attacker passes this to `torch.load()`, Python's pickle runtime evaluates it — the string containing the canarytoken URL is materialised in memory.
- Tools that inspect file content before execution (AV scanners, threat intel platforms, sandbox detonation) will see the URL and may resolve it.
- The DNS canarytoken fires on the first DNS lookup of `zy2s1wepypyvizi06loltahwj.canarytokens.com`, which happens before any HTTP request — so even tools that only resolve and never fetch will trigger it.

**Note on `torch.load()` safety:** PyTorch 2.x warns about `weights_only=False` by default. Attackers using older PyTorch or who pass `weights_only=False` will fully deserialise the file. The pickle here contains only a unicode string (no `__reduce__`, no callable), so it is safe even when deserialised in the honeypot build environment.

---

## 3. Event Logging

The middleware handles the primary `http.lure.data_exfil` event automatically via `X-Lure-Data-Exfil: true`. The middleware:

1. Detects `response.headers.get("X-Lure-Data-Exfil") == "true"` after `call_next()`
2. Overrides `event_type = "http.lure.data_exfil"` and sets `snare_attack_type = "Data Exfil"`
3. Writes the event to PostgreSQL (includes `path = /api/v2/runs/{run_id}/checkpoint`)
4. Calls `asyncio.create_task(_push_honeydash_async(event, "Data Exfil"))`
5. Strips `X-Lure-Data-Exfil` from the response before sending to the client

**No supplementary `_log_event_async()` or `_push_honeydash_async()` call in the route handler.** The middleware is the sole logging and push path. The `run_id` is captured in `payload.path` on the middleware event.

**Event type hierarchy for this download (MF-4):**

| Event | Source | Trigger |
|---|---|---|
| `http.lure.data_exfil` | Middleware (via `X-Lure-Data-Exfil`) | Every checkpoint download — sole event |
| `http.canarytoken.fired` | `POST /api/v1/canarytoken/callback` | When attacker's machine resolves the DNS token |

`http.lure.data_exfil` is already in `_NO_COOLDOWN_EVENTS` in `sentinel.py` — every download fires an immediate Telegram alert.

**No change to `_LURE_PATHS` (MF-2).** The `X-Lure-Data-Exfil: true` header forces `event_type = http.lure.data_exfil` unconditionally — `_LURE_PATHS` membership is not required for this override. `_LURE_PATHS` only controls `X-Debug-Mode: enabled` injection and the `is_lure` HoneyDash path. Adding `/api/v2/runs` to `_LURE_PATHS` would match the legitimate runs-listing endpoint (`GET /api/v2/runs`) and inject misleading telemetry on every page mount.

---

## 4. HoneyDash Push

The middleware `X-Lure-Data-Exfil` path already calls `_push_honeydash_async(event, "Data Exfil")` at lines 680-683. The HoneyDash card correctly shows `"Data Exfil"` without any handler-level push code.

**No explicit `_push_honeydash_async()` in the route handler (MF-1).** Adding one would result in two HoneyDash pushes per download — one from the handler with the incomplete pre-`call_next()` event, and one from the middleware with the final enriched event.

---

## 5. Frontend Wiring

The `RunDetail` component in `RunsTable.tsx` (line 175) has this button:

```tsx
<button className="nro-btn-secondary w-full">Download checkpoint</button>
```

The frontend engineer should wire this to:

```
GET /api/v2/runs/{run_id}/checkpoint
```

where `run_id` is `run.id` from the `adaptRun()` result. The request must include credentials so the `nro_session_v2` cookie is sent. The browser will handle the file download automatically when it receives `Content-Disposition: attachment`.

Minimal implementation (no library dependencies):

```tsx
onClick={() => {
  window.location.href = `/api/v2/runs/${run.id}/checkpoint`;
}}
```

Using `window.location.href` (not `fetch`) is preferred for file downloads because the browser natively prompts the user to save the file when it receives `Content-Disposition: attachment`. The cookie is sent automatically by the browser since the SPA is same-origin with the API (served via nginx on port 8081).

Do not use a telemetry beacon for this action — the backend event logging is sufficient and adding a beacon would create a second event before the download even completes, which is timing noise.

---

## 6. Canarytoken Callback

The existing `/api/v1/canarytoken/callback` route at line 2456 already handles callbacks from canarytokens.org for all registered tokens. It:

1. Parses the `src_ip`, `channel`, `token_type`, `useragent`, `memo`, `geo_info`, and `additional_info` fields from the canarytokens.org POST body.
2. Emits `http.canarytoken.fired` to PostgreSQL and Redis.
3. Pushes to HoneyDash via `_push_honeydash_async(canary_event, "Canarytoken Fired")`.
4. Is in `_NO_COOLDOWN_EVENTS` in `sentinel.py` so it always fires a Telegram alert.

**No changes required to the callback route.** The existing route handles DNS token callbacks from the same subdomain (`zy2s1wepypyvizi06loltahwj.canarytokens.com`) that is embedded in the checkpoint binary.

**Gap to note:** The DNS canarytoken was registered with memo `"neuro-team-export-csv-2026"` (set for the CSV lure). When the token fires from the checkpoint binary, the canarytokens.org webhook will still report that memo — the memo does not identify whether the trigger came from the CSV or the checkpoint. This is acceptable. If the operator wants per-file attribution, register a second DNS canarytoken with memo `"neuro-checkpoint-download-2026"` and update `_CHECKPOINT_CANARY_URL` to point to its subdomain.

---

## 7. Per-Run vs Shared File

**Decision: all run IDs share the same checkpoint bytes.**

Rationale:
- The file content is static (generated once at module import as `_CHECKPOINT_V2_BIN`). Dynamic per-run content would require generating a different pickle per `run_id`, which adds complexity for no deception gain.
- The `Content-Disposition` filename is parameterised by `safe_run_id` (`checkpoint-{safe_run_id}-latest.bin`), so to the attacker the file appears run-specific even though the bytes are identical.
- The canarytoken URL is identical across all downloads. A second download of a different run's checkpoint fires the same token — fine, since the attacker's machine only needs to resolve the hostname once.
- The `path` field on the middleware event (`/api/v2/runs/{run_id}/checkpoint`) captures which specific run triggered the download.

**File size (DG-1):** The pickle header + ~400-byte plaintext + 64 KB pseudo-random tail produces a file of approximately 65 KB. The null-padding approach used in the draft plan produced 2 MB of zero-entropy bytes, trivially flagged by `file --brief` as "data" with suspiciously low entropy. 64 KB pseudo-random bytes from `os.urandom()` produce Shannon entropy near 8 bits/byte — indistinguishable from compressed model data at this scale.

---

## 8. Full Route Implementation

Place `_CHECKPOINT_CANARY_URL`, `_build_checkpoint_v2_bin()`, and `_CHECKPOINT_V2_BIN` at the module level near the other binary constants (around line 966 in main.py, after `_CHECKPOINT_STUB_BIN`).

Place the route handler immediately after `v2_get_runs()` (around line 4095).

**No change to `_LURE_PATHS`** — do not add `/api/v2/runs` (MF-2).

```python
# ---- add at module level near line 966, after _CHECKPOINT_STUB_BIN ----

_CHECKPOINT_CANARY_URL: str = "http://zy2s1wepypyvizi06loltahwj.canarytokens.com/v1/metrics"


def _build_checkpoint_v2_bin() -> bytes:
    """
    Canary checkpoint binary: pickle protocol 2 unicode string + 64 KB pseudo-random tail.

    This is a canary file, NOT a loadable PyTorch model.
    Trigger surfaces:
      - strings(1) / grep: extracts the URL verbatim
      - torch.load(weights_only=False) / pickle.loads(): deserialises the string
      - AV/sandbox: URL extraction triggers DNS resolution of the canarytoken host
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

    payload = b"\x80\x02\x58" + struct.pack("<I", len(inner)) + inner + b"."
    # 64 KB pseudo-random tail — not null padding (DG-1: entropy looks like compressed data)
    tail = os.urandom(64 * 1024)
    return payload + tail


_CHECKPOINT_V2_BIN: bytes = _build_checkpoint_v2_bin()


# ---- add after v2_get_runs() (around line 4095) ----

@app.get("/api/v2/runs/{run_id}/checkpoint")
async def v2_run_checkpoint_download(run_id: str, request: Request):
    """
    Lure checkpoint download. All run IDs return the same shared canary binary.
    Filename is parameterised by safe_run_id so the attacker sees a run-specific file.

    Tripwires:
      1. DNS canarytoken URL in pickle payload — fires on hostname resolution.
      2. AWS key AKIAYZM57LXRGIYTCOUV — fires on any AWS API call.
      3. DB / SSH credentials — matches Cowrie userdb.txt for sentinel correlation.

    Event flow (MF-1, MF-4 compliant):
      Middleware:  X-Lure-Data-Exfil: true -> http.lure.data_exfil (sole event)
      Middleware:  _push_honeydash_async(event, "Data Exfil") (automatic)
      Callback:    /api/v1/canarytoken/callback -> http.canarytoken.fired
    """
    await _v2_session_required(request)
    safe_run_id = run_id if re.match(r"^[a-zA-Z0-9._-]{1,64}$", run_id) else "run-latest"
    return Response(
        content=_CHECKPOINT_V2_BIN,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="checkpoint-{safe_run_id}-latest.bin"',
            "X-Lure-Data-Exfil": "true",
        },
    )
```

---

## 9. Required Changes Summary

| File | Change | Details |
|---|---|---|
| `main.py` | Add `_CHECKPOINT_CANARY_URL` constant | Module-level near line 966, after `_CHECKPOINT_STUB_BIN` |
| `main.py` | Add `_build_checkpoint_v2_bin()` function | Module-level, same location |
| `main.py` | Add `_CHECKPOINT_V2_BIN` bytes constant | `= _build_checkpoint_v2_bin()` |
| `main.py` | Add `GET /api/v2/runs/{run_id}/checkpoint` route | After `v2_get_runs()`, around line 4095 |
| `Slapdash-web/src/components/RunsTable.tsx` | Wire "Download checkpoint" button | `onClick` sets `window.location.href` |
| `requirements.txt` | No new dependencies | `struct` and `os` are stdlib |

**NOT changed:** `_LURE_PATHS` (MF-2 — no `/api/v2/runs` prefix added).

---

## 10. Sentinel Behaviour

`http.lure.data_exfil` is in `_NO_COOLDOWN_EVENTS` in `sentinel.py`. Every checkpoint download fires an immediate Telegram alert regardless of per-IP cooldown.

When the canarytoken fires, `http.canarytoken.fired` is also in `_NO_COOLDOWN_EVENTS` — immediate Telegram alert with the attacker's real IP from their own machine. The `path` field on the `http.lure.data_exfil` event records which run triggered the download for forensic correlation.

---

## Revision History

| Rev | Date | Changes |
|---|---|---|
| Rev 1 | 2026-06-10 | Resolved all four Backend-1 blockers: B1 (middleware cookie conflict), B2 (.git/config kill chain pre-deployment step), B3 (auth path reconciliation), B4 (seed script context + requirements.txt pins) |
| Rev 2 | 2026-06-10 | Resolved Backend-2 blocker NEW-1 and minors M1–M3: NEW-1 (cookie-name contract — nro_session_v2 is server-only, AppLayout gates on auth/me 200/401 exclusively), M1 (logout route-table response corrected to 200 JSON), M2 (seed handler is ADDED not REPLACED), M3 (reportlab reference replaced with fpdf2) |
| Rev 3 | 2026-06-10 | Addendum A: async RCE (no parrot output), dynamic SSRF responses, MFA bcrypt-first, SSH key regex, padded tarball, legacy debug trap |
| Rev 4 | 2026-06-10 | New Flaws B: POST /api/v2/api-keys honeytoken, job state machine, /signup redirect |
| Rev 5 | 2026-06-10 | Spec-frontend desync fixes: admin tenant action trap, artifacts list endpoint, data/exports/download typo |
| Rev 6 | 2026-06-10 | Backend-4/6 blockers resolved: SSH herding struck from job error_log (OOMKilled), state machine, legacy debug (410 Gone); artifact filename realistic |
| Rev 7 | 2026-06-10 | Backend-5 C1+C2 resolved: dynamic per-call API key generation + DB write; psycopg2 dedicated connection in state machine |
| Rev 8 | 2026-06-10 | Kill chain fix: SSH target changed from RFC-1918 10.31.4.22 to neuro.cyveera.com (public domain → Cowrie DNAT) |
| Rev 9 | 2026-06-10 | §11 Per-Attacker Workspace Isolation: per-(IP,credential) tenant copy, attacker_workspaces table, provisioning on login, CRUD route workspace_id injection, cleanup coroutine |
| Rev 10 | 2026-06-10 | Backend-10 C1–C4 resolved: C1 (Redis SET NX EX 30 distributed lock in _provision_workspace), C2 (_seed_workspace helper with explicit column lists, no SELECT *, no id column), C3 (composite UNIQUE constraints on training_runs/models/datasets in §2 DDL — no atk- prefix needed), C4 (§11.8 JOIN changed to (src_ip, email) composite key; http.workspace.returning_attacker added to _NO_COOLDOWN_EVENTS) |
| Rev 11 | 2026-06-12 | Backend-14 CONDITIONAL PASS resolved: MF-1 (no explicit _push_honeydash_async in handler — middleware handles via X-Lure-Data-Exfil), MF-2 (removed /api/v2/runs from _LURE_PATHS), MF-3 (run_id sanitised with re.match before Content-Disposition), MF-4 (dropped http.lure.checkpoint_downloaded supplementary event), DG-1 (64 KB os.urandom() tail replaces 2 MB null padding; documented as canary file not loadable model). IMPLEMENTATION COMPLETE. |

---

## 1. Architecture Decision — Extend main.py vs. New App

**Decision: Extend `main.py` with `/api/v2/` routes. Do not create a separate FastAPI process.**

### Justification

The existing `main.py` already provides everything the new routes depend on:

- `_log_event()` — synchronous PostgreSQL + Redis writer with GeoIP enrichment, kill-chain stage advancement, and attacker_sessions upsert. Reproducing this in a second process would be duplication of ~200 lines of battle-tested infrastructure.
- `_detect_web_attack()` — SNARE pattern matching used by trap endpoints. Already wired into the middleware path.
- `_push_honeydash_async()` — persistent httpx pool for HoneyDash push. Shared client reuse matters; a second process gets its own separate pool.
- `_hd_client`, `_pg_conn`, `_redis_client` — module-level singletons. These are not thread-safe across processes; a second app would need its own connection management.
- Session cookie (`nro_session`) — already read and written by middleware. All new authenticated routes must share the same session store (Redis). If auth is in a different process, every `/api/v2/auth/me` check requires an IPC or shared Redis read that is already happening in middleware on every request in the existing app.
- Middleware intercepts every request before any route handler runs. The SNARE detection, bot scoring, event logging, and cookie assignment all happen at middleware level. A second app at a different port means those requests bypass this middleware entirely — trap events go unlogged.

**The single-process approach means:** one nginx upstream (`honeypot-api:8080`), one Docker container, one rebuild cycle, and all `/api/v2/` traps flow through the same logging pipeline that already has 200k+ events in production.

**The only cost** is that `main.py` grows longer. This is acceptable. The existing file is already ~1,400 lines and well-structured. The `/api/v2/` block will be a clearly delimited section starting at the same architectural depth as the existing `/api/v1/` block.

**Route versioning approach:** All new routes are registered at `/api/v2/`. Existing `/api/v1/` routes remain unchanged and continue serving the old HTML-rendered frontend on neuro.cyveera.com. The new SlapDash SPA uses only `/api/v2/`. This means zero risk of breaking the existing deployment while the new platform is being wired.

---

## 2. Database Schema Additions

Six new tables are required. They must be added to the PostgreSQL schema and populated with fixture seed data before any `/api/v2/` route is called. The seed data is idempotent — all INSERTs use `ON CONFLICT DO NOTHING` keyed on natural IDs so the seed script is safe to re-run.

All new tables live in the same database (`honeypot`) and are accessible through the existing `_get_pg()` connection.

### 2.1 Table: `workspace_members`

Stores the fixture team members shown on `/team` and returned by `GET /api/v2/auth/me`.

```sql
CREATE TABLE IF NOT EXISTS workspace_members (
    id              SERIAL PRIMARY KEY,
    workspace_id    TEXT NOT NULL DEFAULT 'vantarahealth',
    email           TEXT NOT NULL UNIQUE,
    display_name    TEXT NOT NULL,
    role            TEXT NOT NULL,          -- customer_user | customer_admin | cyveera_support
    password_hash   TEXT NOT NULL,          -- bcrypt hash of lure password
    last_active     TIMESTAMPTZ
);
```

**Seed rows:**

| email | display_name | role | password (plaintext — hash before insert) |
|---|---|---|---|
| `j.smith@vantarahealth.com` | Jordan Smith | `customer_user` | `Vantara2026!` |
| `alice.wong@merisol.io` | Alice Wong | `customer_admin` | `Merisol@Secure99` |
| `support@cyveera.ai` | Cyveera Support | `cyveera_support` | `CyveeraSup!2024` |

The `support@cyveera.ai` password `CyveeraSup!2024` is the exact credential embedded in `/.git/config` as `support:CyveeraSup!2024` in the remote URL. This is the crown jewel credential chain: `.git/config` → `/login` → `/settings/admin`.

Password hashing: use `passlib.hash.bcrypt` at cost factor 12. Do not store plaintext. The route handler calls `bcrypt.verify(submitted_password, stored_hash)`. The verify call takes ~200ms naturally, which combined with `asyncio.sleep(random.uniform(0.6, 1.2))` produces realistic 800ms–1.4s login latency.

### 2.2 Table: `training_runs`

Serves `GET /api/v2/runs` and the dashboard recent-runs table.

```sql
CREATE TABLE IF NOT EXISTS training_runs (
    id              SERIAL PRIMARY KEY,
    workspace_id    TEXT NOT NULL DEFAULT 'vantarahealth',
    run_id          TEXT NOT NULL,
    model_name      TEXT NOT NULL,
    status          TEXT NOT NULL,          -- Running | Completed | Failed | Queued
    duration_min    INTEGER,               -- NULL for Running/Queued
    gpu_hours       NUMERIC(8,1),          -- NULL for Running/Queued
    started_by      TEXT NOT NULL,
    started_at      TIMESTAMPTZ NOT NULL,
    UNIQUE (workspace_id, run_id)          -- composite: same run_id may appear in multiple workspaces
);
```

**Schema addendum:** Add column `error_log TEXT` (NULL for non-failed jobs; populated with error message for Failed rows created by the RCE trap in §4.3).

**Seed rows (10 rows — matches spec §4.12 and §4.7):**

| run_id | model_name | status | duration_min | gpu_hours | started_by | started_at |
|---|---|---|---|---|---|---|
| run-20260609-001 | vantara-risk-v3 | Queued | NULL | NULL | svc-deploy | 2026-06-09 07:00 UTC |
| run-20260608-002 | vantara-risk-v3 | Running | NULL | NULL | j.smith | 2026-06-08 09:14 UTC |
| run-20260607-019 | merisol-nlp-v2 | Completed | 704 | 94.0 | alice.wong | 2026-06-07 22:31 UTC |
| run-20260607-018 | quelaris-embed-001 | Completed | 362 | 48.3 | svc-deploy | 2026-06-07 14:08 UTC |
| run-20260606-031 | lumira-clf-v4 | Failed | 23 | 3.1 | j.smith | 2026-06-06 03:47 UTC |
| run-20260605-044 | ardentix-llm-ft | Completed | 1338 | 178.4 | alice.wong | 2026-06-05 11:00 UTC |
| run-20260604-011 | denova-risk-v1 | Completed | 547 | 72.9 | svc-deploy | 2026-06-04 16:22 UTC |
| run-20260603-007 | vantara-risk-v3 | Completed | 711 | 94.8 | j.smith | 2026-06-03 08:45 UTC |
| run-20260602-041 | ardentix-llm-ft | Failed | 67 | 8.6 | j.smith | 2026-06-02 22:14 UTC |
| run-20260601-033 | merisol-nlp-v2 | Completed | 655 | 87.4 | alice.wong | 2026-06-01 19:02 UTC |

### 2.3 Table: `models`

Serves `GET /api/v2/models`.

```sql
CREATE TABLE IF NOT EXISTS models (
    id              SERIAL PRIMARY KEY,
    workspace_id    TEXT NOT NULL DEFAULT 'vantarahealth',
    model_name      TEXT NOT NULL,
    version         TEXT NOT NULL,
    customer        TEXT NOT NULL,
    status          TEXT NOT NULL,          -- Healthy | Drift Alert | Degraded
    drift_score     NUMERIC(4,2) NOT NULL,
    last_check      TIMESTAMPTZ NOT NULL,
    UNIQUE (workspace_id, model_name)       -- composite: same model_name may appear in multiple workspaces
);
```

**Seed rows (5 rows — from data.json and spec §4.11):**

| model_name | version | customer | status | drift_score | last_check |
|---|---|---|---|---|---|
| vantara-risk-v3 | v3.2.1 | Vantara Health | Healthy | 0.04 | 2026-06-08 08:00 UTC |
| merisol-nlp-v2 | v2.0.9 | Merisol | Drift Alert | 0.31 | 2026-06-07 22:00 UTC |
| quelaris-embed-001 | v1.1.4 | Quelaris | Healthy | 0.07 | 2026-06-08 06:00 UTC |
| ardentix-llm-ft | v0.8.2 | Ardentix | Degraded | 0.18 | 2026-06-08 04:00 UTC |
| lumira-clf-v4 | v4.0.1 | Lumira | Healthy | 0.02 | 2026-06-08 07:30 UTC |

### 2.4 Table: `datasets`

Serves `GET /api/v2/datasets`.

```sql
CREATE TABLE IF NOT EXISTS datasets (
    id              SERIAL PRIMARY KEY,
    workspace_id    TEXT NOT NULL DEFAULT 'vantarahealth',
    name            TEXT NOT NULL,
    source          TEXT NOT NULL,
    format          TEXT NOT NULL,
    row_count       TEXT NOT NULL,          -- stored as formatted string e.g. "2,841,204"
    size_display    TEXT NOT NULL,          -- e.g. "4.1 GB"
    uploaded_at     DATE NOT NULL,
    tags            TEXT[] NOT NULL DEFAULT '{}',
    UNIQUE (workspace_id, name)             -- composite: same dataset name may appear in multiple workspaces
);
```

**Seed rows (5 rows — from data.json):**

| name | source | format | row_count | size_display | uploaded_at | tags |
|---|---|---|---|---|---|---|
| vantara-biometric-train-v3 | S3 (cyvera-ml-artifacts) | Parquet | 2,841,204 | 4.1 GB | 2026-05-22 | {CONFIDENTIAL,PHI} |
| merisol-feedback-embeddings | HuggingFace Hub | JSONL | 890,441 | 1.2 GB | 2026-05-18 | {RESTRICTED} |
| internal-slack-corpus-Q1 | Internal export | JSONL | 4,102,887 | 8.7 GB | 2026-04-30 | {INTERNAL} |
| synthetic-pii-redacted-v4 | Quelaris warehouse | CSV | 1,200,000 | 340 MB | 2026-04-14 | {PUBLIC} |
| quelaris-embed-baseline | Remote URL import | Parquet | 501,990 | 620 MB | 2026-03-28 | {RESEARCH} |

### 2.5 Table: `notifications`

Serves `GET /api/v2/notifications`.

```sql
CREATE TABLE IF NOT EXISTS notifications (
    id              SERIAL PRIMARY KEY,
    workspace_id    TEXT NOT NULL DEFAULT 'vantarahealth',
    severity        TEXT NOT NULL,          -- critical | warning | info
    title           TEXT NOT NULL,
    body            TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    is_read         BOOLEAN NOT NULL DEFAULT false
);
```

**Seed rows (8 rows — exactly as specified in §4.13):**

| severity | title | created_at |
|---|---|---|
| critical | Model drift threshold exceeded: merisol-nlp-v2 | 2026-06-07 22:04 UTC |
| warning | Dataset schema mismatch: internal-slack-corpus-Q1 | 2026-06-06 11:43 UTC |
| warning | GPU node degraded: neuro-train-01 | 2026-06-06 04:17 UTC |
| critical | Billing limit approaching: VantaraHealth workspace | 2026-06-05 09:00 UTC |
| info | Training run completed: run-20260605-044 | 2026-06-05 09:18 UTC |
| critical | Unauthorized login attempt: 185.234.219.4 | 2026-06-04 14:32 UTC |
| warning | SSO authentication degraded | 2026-06-03 18:44 UTC |
| info | New team member added: support@cyveera.ai | 2026-05-31 10:00 UTC |

Notification 3 body must contain `10.31.4.22` verbatim: "Node neuro-train-01 (10.31.4.22) reported elevated memory pressure: 94% VRAM utilization."

Notification 8 body must plant `support@cyveera.ai` as a legitimate workspace member with the sentence: "Cyveera support account has been granted temporary access to your workspace for session duration of 48 hours. This access was requested via your support ticket #41291."

### 2.6 Table: `api_keys`

Serves `GET /api/v2/api-keys`.

```sql
CREATE TABLE IF NOT EXISTS api_keys (
    id              SERIAL PRIMARY KEY,
    workspace_id    TEXT NOT NULL DEFAULT 'vantarahealth',
    name            TEXT NOT NULL,
    key_prefix      TEXT NOT NULL,          -- first 8 chars visible in UI e.g. "nro_sk_4a7f"
    key_masked      TEXT NOT NULL,          -- display value e.g. "nro_sk_4a7f...b291"
    key_full        TEXT NOT NULL,          -- honeytoken value placed in clipboard
    scope           TEXT NOT NULL,
    created_at      DATE NOT NULL,
    last_used_at    DATE
);
```

**Seed rows (3 rows — from data.json):**

| name | key_prefix | key_masked | key_full | scope | created_at | last_used_at |
|---|---|---|---|---|---|---|
| Production read-only | nro_sk_4a7f | nro_sk_4a7f...b291 | nro_sk_4a7f9c3d8e2b1a6f5d4c7b8e9a0f3d2c | read:runs,read:models | 2026-03-14 | 2026-06-08 |
| CI/CD pipeline | nro_sk_8c2e | nro_sk_8c2e...f047 | nro_sk_8c2e1b9d3a4f7c5d8e2b1a6f3d9c4e7f | read:all,write:metrics | 2026-04-01 | 2026-06-09 |
| Legacy integration | nro_sk_1d9b | nro_sk_1d9b...0e33 | nro_sk_1d9b3f5a7c2e4b6d8a1c3f5e7b9d0a2c | admin | 2025-11-12 | 2026-05-30 |

### 2.7 Seed Delivery Mechanism — BLOCKER-4 Resolution

**Single authoritative execution context: FastAPI startup event inside the `honeypot-api` container.**

The seed script is NOT called from `start.sh`, and NOT run via `docker exec log-shipper`. Those two contexts were listed in earlier drafts of this plan and are now removed. The single authoritative mechanism is a second `@app.on_event("startup")` handler registered in `main.py` that calls the seed function before any route is served.

**IMPORTANT — ADD, do not replace (Minor 2 / NEW-3 resolution):** The live `main.py` already registers `@app.on_event("startup")` at line 477 (`async def startup()`) which emits the `api.startup` event and populates boot-time state. Starlette/FastAPI runs ALL registered startup handlers in registration order. The `seed_v2_tables` handler below must be registered as a SECOND `@app.on_event("startup")` — it must NOT rename, modify, or replace the existing `startup()` handler. If the existing handler is ever migrated to a FastAPI lifespan context, the seed must move with it.

```python
@app.on_event("startup")
async def seed_v2_tables():
    """
    Idempotent seed — runs on every container start.
    CREATE TABLE IF NOT EXISTS + ON CONFLICT DO NOTHING mean re-runs are safe.
    Uses its own dedicated connection with autocommit=True (NOT the shared _pg_conn
    module-level singleton) so DDL commits immediately regardless of transaction state.
    """
    import psycopg2
    conn = psycopg2.connect(POSTGRES_DSN)
    conn.set_session(autocommit=True)
    try:
        _run_seed(conn)
    finally:
        conn.close()
```

The `_run_seed(conn)` function (defined in the same file or imported from `seed_v2.py` in the same directory) executes all six `CREATE TABLE IF NOT EXISTS` statements and all fixture INSERTs using `ON CONFLICT DO NOTHING` keyed on the unique constraint of each table. Because it uses `autocommit=True` on its own dedicated connection, DDL and DML both commit immediately and are visible to `_get_pg()` (the shared module-level singleton) on the first request.

`passlib[bcrypt]` is required at import time in `seed_v2.py` to hash the `workspace_members` passwords. If the import fails, the startup event raises an exception and the container fails the healthcheck — surfacing the dependency gap before any route is served.

**Mandatory pre-build gate — requirements.txt additions.** The following three lines must be added to `deploy/module-6-honeypot-api/requirements.txt` BEFORE the Docker image is built. Without them, the startup event crashes on import and no v2 route is ever reachable.

```
passlib[bcrypt]==1.7.4
user-agents==2.2.0
fpdf2==2.7.9
```

Current `requirements.txt` (as of 2026-06-10) contains only: `fastapi`, `uvicorn[standard]`, `jinja2`, `psycopg2-binary`, `redis`, `httpx`, `python-multipart`, `geoip2`, `structlog`, `python-dotenv`. None of the three new packages are present. They are not transitive dependencies of any existing package. They must be added explicitly.

**Verify pre-build:**
```bash
# On the honeypot-api container after rebuild:
docker exec honeypot-api python3 -c "from passlib.hash import bcrypt; import user_agents; import fpdf; print('ok')"
# Must print: ok

# Verify seed ran:
docker exec postgres psql -U honeypot -d honeypot -c "\dt workspace_members"
# Must return: workspace_members table listing

# Verify idempotence — rebuild and check no duplicate rows:
cd /opt/honeypot/deploy/module-6-honeypot-api/
docker compose up -d --build --force-recreate
docker exec postgres psql -U honeypot -d honeypot \
  -c "SELECT COUNT(*) FROM workspace_members;"
# Must return: 3 (not 6 after two starts)
```

---

## 3. Session / Auth Implementation

### 3.1 Redis Session Store

Sessions are stored in Redis using the existing `_get_redis()` client. The helper is defined in `main.py` as:

```python
def _get_redis() -> redis.asyncio.Redis:
    """Returns the shared async Redis client.
    ALL callers must use `await` on every operation.
    This is a module-level singleton — not a coroutine itself,
    but every method on the returned client IS a coroutine.
    Correct:   await _get_redis().get(key)
    Incorrect: _get_redis().get(key)   ← returns a coroutine object, never executed
    """
    return _redis_client
```

**Rule (mandatory):** Every call to `_get_redis()` throughout the v2 implementation must be followed by `await`. Never call `_get_redis().get(...)`, `_get_redis().set(...)`, `_get_redis().expire(...)`, or `_get_redis().delete(...)` without `await` — doing so returns a coroutine object that is silently discarded.

- Key pattern: `session:v2:{uuid4}` — prefixed `v2` to avoid collision with any legacy `session:{uuid}` keys from the old Jinja2-era app, even though those keys have TTL 1800s and should be expired.
- Value: JSON blob `{"email": "...", "role": "...", "ip": "...", "user_agent_raw": "...", "workspace_id": "..."}`
- TTL: 1800 seconds (30 minutes). Reset on every authenticated request — inactivity timeout.
- On logout: `DEL session:v2:{session_id}`

**BLOCKER-1 — Middleware cookie conflict and fix (mandatory `main.py` change).**

The existing `request_logger` middleware (lines 688–697 of `main.py` as of 2026-06-10) unconditionally calls `response.set_cookie(key="nro_session", value=session_id, max_age=86400, ...)` on the way out of EVERY request, AFTER any route handler has already returned. If the v2 auth route sets `Max-Age=1800`, the middleware immediately overwrites the same Set-Cookie header on the same response with `Max-Age=86400`. The browser receives 86400, not 1800, and the Redis-TTL/cookie-TTL alignment the plan depends on does not happen.

Additionally, line 525 mints a fresh `session_id = request.cookies.get("nro_session") or str(uuid.uuid4())` for every visitor including unauthenticated ones. `_v2_session_required()` correctly 401s these (because no `session:v2:` key exists in Redis), but the plan must not assume "cookie present == authenticated v2 session."

**The fix uses a separate cookie name `nro_session_v2` for all v2 sessions.** This is the cleanest resolution: the existing middleware never reads or writes `nro_session_v2`, so there is zero collision and no middleware modification is required.

Specification:

- The v2 auth token route (`POST /api/v2/auth/token`) sets `nro_session_v2` with `Max-Age=1800`, `HttpOnly=True`, `SameSite=lax`, `Path=/`, `Secure=False`.
- `_v2_session_required()` reads `nro_session_v2` (NOT `nro_session`).
- `GET /api/v2/auth/me` reads and refreshes `nro_session_v2`.
- `GET /api/v2/auth/logout` deletes `nro_session_v2`.
- The existing middleware never touches `nro_session_v2` — it only reads/writes `nro_session`. No middleware modification is needed.
- The existing `_SESSION_USER_MAP` (keyed by `nro_session` values) is populated ONLY by `api_auth()`. For v2 sessions, user identity is read from the Redis `session:v2:{id}` JSON blob, not from `_SESSION_USER_MAP`. Any existing route that reads `_SESSION_USER_MAP[session_id]` must be updated to fall back to the Redis session lookup when `session_id` is a v2 session key (identifiable by prefix `session:v2:` in Redis, or by checking whether `nro_session_v2` is present in the request cookie alongside `nro_session`).

**Verify:** after v2 login, `curl -v` shows `Set-Cookie: nro_session_v2=...; Max-Age=1800; ...` and a separate `Set-Cookie: nro_session=...; Max-Age=86400; ...` (from middleware). A subsequent authenticated `GET /api/v2/runs` does NOT reset `nro_session_v2` via the middleware (because the middleware only touches `nro_session`). After 1801 seconds of inactivity, `GET /api/v2/runs` returns 401.

**Cookie-name contract with the React frontend (NEW-1 resolution):**

`nro_session_v2` is the server's implementation detail. Frontend developers wiring `AppLayout` must observe the following contract exactly:

- The `nro_session_v2` cookie is `HttpOnly=True` — it is **inaccessible to JavaScript** via `document.cookie`. No React component, hook, or context may read, check, or name this cookie.
- `AppLayout` auth gate MUST use the `GET /api/v2/auth/me` 200/401 HTTP round-trip as the **sole** authentication signal. On 200 it renders children; on 401 it redirects to `/login`. No client-side cookie-name check is permitted before or after this call.
- The browser attaches `nro_session_v2` automatically on every same-origin request because it is set with `Path=/`. Frontend code does not need to read or forward it.
- Any frontend spec wording that says "requires a valid `nro_session` cookie" or implies a readable cookie check is incorrect and must be treated as: "requires a valid v2 session, verified via `GET /api/v2/auth/me` returning 200."
- The `_COOKIE_NAME_V2 = "nro_session_v2"` constant in `main.py` is the authoritative name used by `v2_auth_token` (set), `v2_auth_me` (read), `_v2_session_required()` (read), and `v2_auth_logout` (delete). It must not be renamed without updating all four call sites.

**Cookie flags for SlapDash deployment:**
- `HttpOnly=True`, `SameSite=lax`, `Path=/`, `Secure=False` (HTTP-only on port 8081).
- `Max-Age=1800` — matches Redis TTL so the browser cookie and server session expire at the same time. This alignment holds because the middleware never clobbers `nro_session_v2`.

### 3.2 Rate Limiting

Rate limiting for auth endpoints is implemented using a Redis sorted set per IP:

- Key: `ratelimit:auth:{src_ip}`
- On each auth request: `ZADD ratelimit:auth:{ip} {now_ms} {uuid}` then `ZREMRANGEBYSCORE ratelimit:auth:{ip} 0 {now_ms - 60000}` to expire entries older than 60 seconds, then `ZCARD ratelimit:auth:{ip}` to count.
- If count > 10: return HTTP 429 `{"error": "rate_limit_exceeded", "message": "Too many login attempts."}` with header `Retry-After: 60`. Log event as `http.auth.rate_limited`.
- `EXPIRE ratelimit:auth:{ip} 120` on every access to keep the key alive.

This rate limit applies only to `POST /api/v2/auth/token` and `POST /api/v2/auth/sso/initiate`. Other endpoints are not rate-limited (the middleware SNARE patterns already flag brute-force via `_auth_attempts`).

### 3.3 User-Agent Parsing

`GET /api/v2/auth/me` must return a `user_agent_parsed` field. This field is displayed verbatim in the Active Sessions table on `/settings/security` as the visitor's "device". The parsed value must look like "Firefox on Linux" or "Chrome on Windows" — not a raw UA string.

Implementation: use `ua-parser2` (or `user-agents` Python package). Add `user-agents>=2.2` to `requirements.txt`. Call `user_agents.parse(raw_ua)` and construct `"{browser.family} on {os.family}"`. Store the raw UA in Redis session; parse it on each `GET /api/v2/auth/me` response.

### 3.4 Auth Flow Diagram

```
POST /api/v2/auth/token
  ├─ Check rate limit (Redis sorted set) → 429 if exceeded
  ├─ Reuse _auth_attempts[src_ip] bruteforce tracker (see §3.4 BLOCKER-3 note)
  ├─ asyncio.sleep(random.uniform(0.6, 1.2))    ← timing normalization
  ├─ SELECT from workspace_members WHERE email = ?
  ├─ bcrypt.verify(submitted_password, stored_hash) → 401 if fails
  ├─ Generate session_id = uuid4()
  ├─ Redis SET session:v2:{session_id} {json} EX 1800
  ├─ Populate _SESSION_USER_MAP[session_id] = email  (see §3.4 BLOCKER-3 note)
  ├─ Set resp.headers["X-Lure-Credential-Used"] = "true"
  │   (middleware reads this and overrides event_type → http.lure.credential.success;
  │    middleware strips the header before sending to client — same pattern as api_auth())
  └─ Return 200 {token, role, redirect_to, workspace_id} + Set-Cookie: nro_session_v2={session_id}; Max-Age=1800

GET /api/v2/auth/me
  ├─ Read nro_session_v2 cookie  (NOT nro_session — see §3.1 BLOCKER-1 note)
  ├─ Redis GET session:v2:{session_id} → 401 if missing/expired
  ├─ Redis EXPIRE session:v2:{session_id} 1800  ← inactivity reset
  └─ Return 200 {email, display_name, role, ip, user_agent_parsed, workspace}

GET /api/v2/auth/logout
  ├─ DEL session:v2:{session_id}
  └─ Clear nro_session_v2 cookie + 200 {"redirect_to":"/login"}
     (NOT a 302 — SPA must navigate via window.location; a 302 from fetch is followed
      invisibly by the browser and the SPA never sees it. Frontend handles the redirect.)

POST /api/v2/auth/sso/initiate
  ├─ Check rate limit
  ├─ asyncio.sleep(random.uniform(1.8, 2.4))    ← long delay = plausible SSO latency
  └─ Return 503 {"error": "sso_unavailable"}
```

---

## 4. Complete Route Table

Routes are listed in the order they should be implemented. Columns: Method, Path, Auth Required, Handler Name, Purpose, Existing v1 Equivalent.

### 4.1 Auth Routes

| Method | Path | Auth | Handler | Purpose | v1 Equivalent |
|---|---|---|---|---|---|
| POST | `/api/v2/auth/token` | No | `v2_auth_token` | Login — validate lure credential, return role + redirect_to, set session cookie | `/api/v1/auth` |
| GET | `/api/v2/auth/me` | Yes | `v2_auth_me` | Return user object for WorkspaceDataProvider. Called on every AppLayout mount. | None |
| GET | `/api/v2/auth/logout` | No | `v2_auth_logout` | Clear session, delete cookie, 200 `{"ok": true}` — React code calls `navigate("/login")` | `/auth/logout` |
| POST | `/api/v2/auth/sso/initiate` | No | `v2_auth_sso_initiate` | Sleep 1.8–2.4s, return 503. Real XHR — not fake. | `/api/v1/auth/sso/initiate` |

The `token` response JSON shape: `{"token": session_id, "role": "customer_user"|"customer_admin"|"cyveera_support", "redirect_to": "/dashboard"|"/settings/admin", "workspace_id": "vantarahealth", "expires_at": "<ISO 8601 string>"}`.

The `me` response JSON shape: `{"email": "...", "display_name": "...", "role": "...", "ip": "<real src_ip>", "user_agent_parsed": "Firefox on Linux", "workspace": {"name": "VantaraHealth", "plan": "Pro"}}`.

Note on `ip` in `me` response: this is the visitor's real IP extracted by `_extract_src_ip(request)`. It is displayed verbatim on `/settings/security` Active Sessions row 1. This is a strong engagement signal — seeing your own IP in a "logged in session" table is confirmation of successful auth.

### 4.1.1 BLOCKER-3 — Reconciling `v2_auth_token` with the existing `api_auth()` machinery

The existing `api_auth()` handler owns three mechanisms that `v2_auth_token` must reuse — NOT duplicate independently:

**`_auth_attempts` (bruteforce tracker):** The sliding-window bruteforce detector lives in `api_auth()` under a `threading.Lock` (`_auth_lock`). `v2_auth_token` MUST write to the same `_auth_attempts[src_ip]` deque and emit `http.bruteforce.detected` at the same `_BF_THRESHOLD` crossing. Do not implement a parallel bruteforce mechanism. The Redis rate-limiter (§3.2) is separate from the bruteforce intel event — rate-limiting fires 429; bruteforce detection fires a Telegram alert via `_log_event`. Both must work for v2 auth.

**`X-Lure-Credential-Used` header signal (single logging path):** `api_auth()` signals a lure credential match to the middleware by setting `resp.headers["X-Lure-Credential-Used"] = "true"`. The middleware reads this header after `call_next()` and overrides `event_type` to `http.lure.credential.success`. `v2_auth_token` MUST use this SAME header-signal pattern. Do NOT call `_log_event()` directly for the lure-credential event — that would produce two events for one login: one from `_log_event()` in the handler and one generic `http.post.api.v2.auth.token` from the middleware. The header-signal approach is the correct single logging path.

**`_SESSION_USER_MAP` (admin personalisation):** The `admin_page()` handler reads `_SESSION_USER_MAP[session_id]` to pre-fill the admin re-auth form with the attacker's chosen identity. `v2_auth_token` MUST populate `_SESSION_USER_MAP[session_id] = email` under `_SESSION_USER_LOCK` when a lure credential matches — using the same `session_id` value written to the `nro_session_v2` cookie and the Redis `session:v2:{id}` key. Without this, any admin-facing route that uses `_SESSION_USER_MAP` will revert to a default identity for v2 sessions.

**Rule (mandatory):** `v2_auth_token` reuses `_auth_attempts`, `_SESSION_USER_MAP`, and the `X-Lure-Credential-Used` middleware header pattern. It does NOT duplicate this logic independently. One login POST produces exactly ONE credential event of the correct type (`http.lure.credential.success`), not two.

**Verify:** `curl -s -X POST .../api/v2/auth/token -d '{"email":"support@cyveera.ai","password":"CyveeraSup!2024"}' | python3 -m json.tool` produces exactly one row in PostgreSQL with `event_type = 'http.lure.credential.success'` — not two rows and not `http.post.api.v2.auth.token`.

### 4.2 Standard CRUD Routes (Fixture Data, Auth Required)

| Method | Path | Auth | Handler | Returns | v1 Equivalent |
|---|---|---|---|---|---|
| GET | `/api/v2/runs` | Yes | `v2_get_runs` | All rows from `training_runs` ORDER BY started_at DESC | `/runs` (HTML) |
| GET | `/api/v2/models` | Yes | `v2_get_models` | All rows from `models` | `/models` (HTML) |
| GET | `/api/v2/models/{model_id}/drift` | Yes | `v2_get_model_drift` | Fake drift timeseries for the named model (static fixture) | None |
| GET | `/api/v2/datasets` | Yes | `v2_get_datasets` | All rows from `datasets` | `/datasets` (HTML) |
| GET | `/api/v2/notifications` | Yes | `v2_get_notifications` | All rows from `notifications` ORDER BY created_at DESC | `/notifications` (HTML) |
| GET | `/api/v2/team` | Yes | `v2_get_team` | All rows from `workspace_members` | `/team` (HTML) |
| GET | `/api/v2/api-keys` | Yes | `v2_get_api_keys` | All rows from `api_keys` | `/settings/api-keys` (HTML) |
| GET | `/api/v2/artifacts` | Yes | `v2_get_artifacts_list` | Artifact directory listing — LFI browse entry point | `/artifacts` (HTML) |
| POST | `/api/v2/api-keys` | Yes | `v2_create_api_key` | Return fresh generated key, written to api_keys table; log key name as intel; honeytoken in response | None — build |

All CRUD handlers are session-gated using a `_v2_session_required(request)` helper:

```python
async def _v2_session_required(request: Request) -> dict:
    """Read v2 session from Redis. Returns session dict or raises HTTPException(401).
    Reads nro_session_v2 cookie (NOT nro_session) to avoid middleware collision — see §3.1.
    Must be async — _get_redis() returns a redis.asyncio client; .get() and .expire() are coroutines."""
    session_id = request.cookies.get("nro_session_v2")
    if not session_id:
        raise HTTPException(status_code=401, detail={"error": "unauthorized"})
    raw = await _get_redis().get(f"session:v2:{session_id}")
    if not raw:
        raise HTTPException(status_code=401, detail={"error": "unauthorized"})
    await _get_redis().expire(f"session:v2:{session_id}", 1800)  # inactivity reset
    return json.loads(raw)
```

The `v2_get_models/{model_id}/drift` endpoint returns a hardcoded 30-day timeseries. This endpoint is documented in the `/docs` page "Models" article (`GET /api/v2/models/{model_id}/drift`) so it must exist and return valid JSON. Response shape: `{"model_id": "...", "window_hours": 720, "data_points": [{"ts": "...", "drift_score": 0.04}, ...]}` — 30 synthetic daily points.

### 4.3 Trap Routes

These are the high-value capture surfaces. All emit `_log_event()`. Auth requirements vary by trap.

| Method | Path | Auth | Handler | Trap Type | Event Type | v1 Equivalent |
|---|---|---|---|---|---|---|
| POST | `/api/v2/data/import` | Yes | `v2_data_import` | SSRF | `http.snare.ssrf_attempt` | `/api/v1/data/remote-import` |
| POST | `/api/v2/training/jobs` | Yes | `v2_training_jobs` | RCE intent | `http.snare.script_upload` | None — build |
| GET | `/api/v2/artifacts/download` | Yes | `v2_artifacts_download` | LFI / canary tarball | `http.lure.data_exfil` | `/api/v1/data/exports/download` |
| GET | `/api/v2/internal/config` | Yes (support role) | `v2_internal_config` | Crown jewel | `http.snare.internal_config_access` | `/api/v1/internal/config` |
| POST | `/api/v2/integrations/webhook/test` | Yes | `v2_webhook_test` | SSRF | `http.snare.ssrf_attempt` | `/api/v1/integrations/webhook/test` |
| POST | `/api/v2/team/invite` | Yes | `v2_team_invite` | Intent capture | `http.team.invite_submitted` | None — build |
| POST | `/api/v2/team/remove` | Yes | `v2_team_remove` | Intent capture | `http.team.remove_attempted` | None — build |
| POST | `/api/v2/profile/ssh-keys` | Yes | `v2_profile_ssh_keys` | SSH key submission | `http.snare.ssh_key_submitted` | None — build |
| GET | `/api/v2/settings/billing/invoice/{id}` | Yes | `v2_billing_invoice` | Canary PDF | `http.lure.data_exfil` | None — build |
| POST | `/api/v2/security/mfa/toggle` | Yes | `v2_security_mfa_toggle` | MFA password capture | `http.snare.mfa_disable_attempt` | `/api/v1/security/mfa/toggle` |
| POST | `/api/v2/security/session/revoke` | Yes | `v2_security_session_revoke` | Session revocation | `http.security.session_revoke` | `/api/v1/security/session/revoke` |
| POST | `/api/v2/security/allowlist/add` | Yes | `v2_security_allowlist_add` | CIDR submission | `http.snare.allowlist_probe` | `/api/v1/security/allowlist/add` |
| POST | `/api/v2/security/keys/rotate` | Yes | `v2_security_keys_rotate` | Key rotation | `http.security.keys_rotate` | `/api/v1/security/keys/rotate` |
| POST | `/api/v2/api-keys/revoke` | Yes | `v2_api_keys_revoke` | Intent capture | `http.api_keys.revoke_attempted` | `/api/v1/api-keys/revoke` |
| GET | `/api/v1/debug/cluster-status` | No | `v1_legacy_debug` | Legacy API trap | `http.snare.legacy_api_exploit` | 410 Gone | None |
| POST | `/api/v2/admin/tenant/{action}` | Yes (support role) | `v2_admin_tenant_action` | Admin action trap | `http.snare.admin_action_attempted` | None — build |

Detailed trap mechanics:

**`POST /api/v2/data/import` (SSRF trap):**
Accepts `{"url": "...", "dataset_name": "...", "format": "auto"}`. Checks `url` against `_SSRF_PATTERNS` + RFC-1918 ranges. Never makes outbound request. If SSRF pattern: log `http.snare.ssrf_attempt` with the exact URL in `payload.ssrf_url`. Always returns `{"status": "ingestion_queued", "job_id": "dset-{date}-{random_3_digits}", "estimated_completion": "...", "dataset_id": "ds_{random_8_hex}"}` regardless of input. Apply `asyncio.sleep(random.uniform(0.6, 1.2))` before responding.

**`POST /api/v2/training/jobs` (Async job failure trap):**
Accepts `{"job_name": "...", "base_model": "...", "gpu_allocation": "...", "startup_script": "...", "description": "..."}`. Logs `http.snare.script_upload` with the full `startup_script` value in payload whenever a shell metacharacter (`$`, backtick, `$(`, `&&`, `|`, `;`) is detected.

Do NOT return fake terminal output. Return the same response for ALL submissions — metachar or not:
`{"job_id": "run-{date}-{seq}", "status": "queued", "estimated_start": "<ISO string>"}`.

When metachar is detected: INSERT a row into `training_runs` with `status='Failed'` and `error_log='Worker process exited with code 1 (OOMKilled). Scheduler was unable to collect logs before container teardown. Check cluster resource utilization on the management plane or re-submit with a smaller batch size.'` The `error_log` column must be added to the `training_runs` table schema (see §2.2 addendum). When the attacker queries `GET /api/v2/runs` or views the Dashboard, they see the job as Failed. If they click through to job detail, the `error_log` value is returned in the detail response.

This pattern is survivable: async job failures are realistic for GPU cluster workloads. All jobs return identical HTTP responses regardless of content — no differential tells.

**`GET /api/v2/artifacts/download` (LFI / canary tarball):**
Accepts `artifact_path` query parameter. For any path NOT matching `../../exports/workspace-backup-2025-11.tar.gz`: return a stub file with appropriate MIME type and `Content-Disposition: attachment; filename="{basename}"`. The stub content is a short text fragment imitating a truncated binary (e.g. 512 zero bytes for `.bin`, a minimal JSON dict for `.json`, two header lines for `.yaml`). For the exact path `../../exports/workspace-backup-2025-11.tar.gz`: return the pre-built lure tarball (see §4.3.1). Set `X-Lure-Data-Exfil: true` header in both cases — middleware overrides event_type to `http.lure.data_exfil`. Response status and headers are identical for both paths — no differential tell.

The LFI trigger path is also detected by `_detect_web_attack()` via `_LFI_PATTERNS` which includes `../` — so the middleware will additionally fire `http.lfi.attempt`. This is acceptable double-logging. Sentinel's `_NO_COOLDOWN_EVENTS` ensures the `http.lure.data_exfil` fires a Telegram alert immediately.

**`GET /api/v2/artifacts/download` — Lure Tarball Content (§4.3.1 — padded):**

The tarball is generated at container startup, cached as `_BACKUP_TARBALL_BYTES: bytes`. Total size: approximately 8–12 MB after padding. The canary AWS key is buried inside a realistic directory hierarchy, not at the archive root.

Directory structure:
```
workspace-backup-2025-11.tar.gz
├── logs/
│   ├── nginx/
│   │   ├── access.log.1    (~5,000 lines of synthetic 200/404 nginx traffic)
│   │   └── access.log.2    (~3,000 lines, slightly older)
│   └── neuro-api/
│       ├── worker-celery.log   (startup sequence, heartbeat pings, task completions)
│       └── app.log.1           (uvicorn startup + request log lines)
├── config/
│   ├── prometheus/
│   │   └── prometheus.yml      (standard scrape config targeting neuro-api:8080)
│   └── fluentbit/
│       └── parsers.conf        (standard JSON + nginx parser definitions)
├── deploy/
│   ├── docker-compose.yml      (the lure compose file — multi-service with management_net: 10.31.4.22/16)
│   └── secrets/
│       ├── production.env      (DB_HOST, REDIS_URL, JWT_SECRET, S3_BUCKET, AWS_ACCESS_KEY_ID=AKIAYZM57LXRGIYTCOUV)
│       └── aws_credentials.csv (3 rows: m.chen fake key, priya.nair fake key, svc-deploy LIVE CANARYTOKEN)
└── README.txt                  (brief "Created by: neuro-backup-agent v1.2, Workspace: vantarahealth-prod, Date: 2025-11-01")
```

Padding generation pattern (Python tarfile):
```python
import io, tarfile, time

def _add_text_member(tar: tarfile.TarFile, name: str, content: str):
    data = content.encode()
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mtime = time.time() - 86400 * 30  # 30 days ago
    tar.addfile(info, io.BytesIO(data))
```

Generate nginx log lines programmatically:
```python
def _gen_nginx_log(n: int) -> str:
    import random, datetime
    ips = ["185.234.219.4","91.108.4.180","103.21.244.0","172.16.0.1","10.31.4.22"]
    paths = ["/api/v2/runs","/api/v2/models","/api/v2/auth/me","/static/main.js","/favicon.ico"]
    lines = []
    for i in range(n):
        ts = (datetime.datetime.utcnow() - datetime.timedelta(seconds=i*18)).strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(f'{random.choice(ips)} - - [{ts}] "GET {random.choice(paths)} HTTP/1.1" {random.choice([200,200,200,304,404])} {random.randint(200,8000)} "-" "Mozilla/5.0"')
    return "\n".join(lines)
```

The lure files (`production.env`, `aws_credentials.csv`) are identical in content to the previous spec — only their location changed to `deploy/secrets/`. The attacker must extract and navigate the archive to find them.

**`GET /api/v2/internal/config` (Crown Jewel):**
Requires: (1) valid session cookie AND (2) `role == "cyveera_support"`. Without a valid session: return 401. With a valid session but wrong role: return 403 `{"error": "forbidden"}`. With correct role and the `X-Internal-Access: true` header: return 200 with the lure config JSON (verbatim, no placeholders). Without the header but with correct role: return 403 `{"error": "missing_header", "message": "X-Internal-Access header required"}`.

The `cyveera_support` account is only reachable via the credential chain `/.git/config → support:CyveeraSup!2024 → /login → /settings/admin`. An attacker who reads the `/docs` "Node Management (Internal)" article and tries the endpoint directly without logging in as support gets a 401 from the session check, not the 403 role check — so the role check is never revealed unless they have first authenticated.

Log `http.snare.internal_config_access` unconditionally on every hit — 401, 403, and 200. All hits are noteworthy.

Lure config response (verbatim — no placeholders per spec §3 M5):
```json
{
  "db_host": "10.31.4.22",
  "db_port": 5432,
  "db_name": "neuro_prod",
  "db_user": "neuro_app",
  "s3_bucket": "cyvera-ml-artifacts",
  "redis_url": "redis://10.31.4.22:6379",
  "jwt_secret": "REDACTED",
  "support_credentials": "REDACTED — see /run/secrets/support_creds"
}
```

**`POST /api/v2/integrations/webhook/test` (SSRF trap — dynamic responses):**
Accepts `{"url": "..."}`. Uses Python `ipaddress` stdlib to classify the submitted URL. Never makes outbound HTTP. Always logs `http.snare.ssrf_attempt` if SSRF indicators detected. Applies `asyncio.sleep(random.uniform(0.6, 1.2))`.

Classification logic (using `urllib.parse.urlparse` + `ipaddress`):
```python
import ipaddress, urllib.parse

def _classify_webhook_url(url: str) -> str:
    """Returns 'internal', 'invalid', or 'external'."""
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        # Invalid port check
        port = parsed.port
        if port and (port < 1 or port > 65535):
            return "invalid"
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return "internal"
            return "external"
        except ValueError:
            # hostname (not IP) — check for localhost
            if host in ("localhost", "ip6-localhost"):
                return "internal"
            return "external"
    except Exception:
        return "invalid"
```

Conditional responses (HTTP status varies — this is what makes it realistic):
- `"external"` → HTTP 200: `{"status": "delivered", "http_status": 200, "latency_ms": 182, "relay": "http://10.31.4.22:3128/"}`
- `"internal"` → HTTP 502: `{"status": "failed", "error": "connection_refused", "relay_node": "10.31.4.22"}`
- `"invalid"` → HTTP 504: `{"status": "failed", "error": "timeout", "relay_node": "10.31.4.22"}`

The `relay_node` / `relay` field leaks `10.31.4.22` in all three branches — the intelligence goal is achieved regardless of which path fires. SSRF event is logged on every call (not just internal URLs).

**`POST /api/v2/team/invite` (Intent capture):**
Accepts `{"email": "...", "role": "Member"|"Admin"}`. Returns `{"status": "invited", "email": "<submitted>"}`. Logs `http.team.invite_submitted` with the submitted email in `payload.invite_email`. Apply `asyncio.sleep(random.uniform(0.6, 1.2))`.

**`POST /api/v2/team/remove` (Intent capture):**
Accepts `{"email": "..."}`. For `support@cyveera.ai`: return 403 `{"error": "forbidden", "message": "You cannot remove Cyveera support accounts."}`. For others: return 200 `{"status": "removed"}`. Logs `http.team.remove_attempted`.

**`POST /api/v2/profile/ssh-keys` (SSH key capture — validated):**
Accepts `{"name": "...", "key": "..."}`.

Validation (before any logging):
```python
import re
_SSH_KEY_RE = re.compile(r"^ssh-(rsa|ed25519|dss|ecdsa)\s+[A-Za-z0-9+/]{20,}[=]{0,2}(\s+.*)?$")
if not _SSH_KEY_RE.match(payload.key.strip()):
    raise HTTPException(status_code=400, detail={"error": "invalid_format", "message": "Invalid SSH public key format. Supported types: ssh-rsa, ssh-ed25519, ssh-ecdsa."})
```

Only if regex passes: log `http.snare.ssh_key_submitted` with full `key` value in payload and return `{"status": "key_added", "message": "SSH key added. It may take up to 60 seconds to propagate to all cluster nodes."}`.

Note: The `+` quantifier handles arbitrarily long base64 key material without length limit. The minimum 20-char base64 constraint (`{20,}`) rejects trivially short garbage. `ssh-rsa` keys at 2048+ bits will always exceed this minimum. Pattern is intentionally permissive on the comment field (`(\s+.*)?`) to accept keys with email comments like `alice@machine`.

Also log failed format checks as `http.snare.ssh_key_invalid_format` (separate event type, low priority) so CTI records fuzzing attempts even when the regex rejects them. The low-value fuzzer traffic is distinguished from high-value real key submissions in PostgreSQL by event type.

**`GET /api/v2/settings/billing/invoice/{id}` (Canary PDF):**
Path parameter `{id}` is one of: `INV-2026-001` through `INV-2026-006`. Returns a pre-generated PDF file. The PDF is generated at container startup, cached as `_INVOICE_PDF_BYTES: bytes`. It must contain an embedded `<img>` tag pointing to a canarytokens.org URL (invisible 1×1 pixel). Emit `http.lure.data_exfil`. The route always returns the same PDF regardless of `{id}` — only the filename in `Content-Disposition` changes to match the requested invoice number.

PDF generation: use `fpdf2` (already pinned as `fpdf2==2.7.9` in `requirements.txt` per §2.7 — no additional dependency needed). The PDF has the full invoice layout described in spec §4.17. The canarytoken pixel is embedded as a URI action via `fpdf2`'s `add_link()` attached to a transparent 1×1 rect at the top of the first page — this causes compliant PDF viewers to make an outbound HTTP request to the canarytokens.org URL when the document is opened, without any visible element. Do NOT use `reportlab` — it is not in `requirements.txt` and its HTTP-image embedding requires a separate network call at PDF-generation time (not at open time), which defeats the post-exfil tracking purpose. The operator must register a URL canarytoken at canarytokens.org before first deploy, update the `_INVOICE_CANARY_URL` constant in `main.py`, and rebuild the container. Until the URL is set, the PDF is served without the canarytoken pixel (the PDF generation code catches this with a `warnings.warn()` identical to the DNS canarytoken guard).

**`POST /api/v2/security/mfa/toggle` (MFA trap — validation first):**
Accepts `{"password": "..."}`.

Logic (order is mandatory):
1. Extract `email` from Redis session (`session:v2:{id}` JSON blob always contains `"email"`).
2. `SELECT password_hash FROM workspace_members WHERE email = ?`
3. Run `bcrypt.verify(submitted_password, stored_hash)` in a thread executor to avoid blocking the event loop (~200ms): `await asyncio.get_event_loop().run_in_executor(None, bcrypt.verify, submitted_password, stored_hash)`
4. If verify returns `False`: return HTTP 401 `{"error": "invalid_password"}`. Do NOT log `http.snare.mfa_disable_attempt` — wrong password attempts are noise.
5. If verify returns `True`: log `http.snare.mfa_disable_attempt` with `payload.attempted_password = submitted_password` and return HTTP 403 `{"error": "mfa_disable_forbidden", "message": "MFA cannot be disabled for accounts with admin access to multi-tenant workspaces. Contact support@cyveera.ai if you need an exception."}`.

This passes the human-attacker test: submitting garbage → 401 (realistic). Submitting the correct credential → 403 compliance lock (plausible real-app behavior). The trap only fires for genuine credential use.

**`POST /api/v2/security/session/revoke` (Session revocation):**
Accepts `{"session_id": "..."}`. If the submitted `session_id` matches the current session (same as cookie): delete the Redis key AND clear the session cookie — the attacker is logged out on next navigation. This is intentional per spec §4.19. For other session IDs: return `{"status": "revoked"}`. Emits `http.security.session_revoke`.

**`POST /api/v2/security/allowlist/add` (CIDR submission):**
Accepts `{"cidr": "...", "description": "..."}`. Stores the CIDR in `payload.submitted_cidr`. Returns `{"status": "queued", "message": "Allowlist update queued. Propagation may take up to 60 seconds."}`. Apply `asyncio.sleep(random.uniform(0.6, 1.2))`. Emits `http.snare.allowlist_probe`.

**`POST /api/v2/security/keys/rotate`:**
Accepts any body. Returns `{"status": "rotation_queued", "affected_keys": 3, "note": "Update your CI/CD pipelines and automation scripts. New keys will be issued at the /api-keys page within 5 minutes."}`. Emits `http.security.keys_rotate`.

**`POST /api/v2/api-keys/revoke`:**
Accepts `{"key_id": N}`. Returns `{"status": "revoked"}`. Emits `http.api_keys.revoke_attempted` with the key ID in payload.

**`POST /api/v2/api-keys` (Honeytoken key creation):**
Accepts `{"name": "...", "scope": "read:all"|"read:runs,read:models"|"admin"}`. This route is required by the `CreateApiKeyModal` in the React frontend — without it, FastAPI returns 405 Method Not Allowed and the primary API-key creation flow is dead on arrival.

**Scope allowlist (module-level constant):**
```python
VALID_API_KEY_SCOPES = {"read:all", "write:models", "write:datasets", "admin"}
```
`payload.scope` must be validated against this set before use. An unrecognised value defaults to `"read:all"` — the safest scope — rather than echoing arbitrary attacker-controlled input into the DB or response:
```python
scope = payload.scope if payload.scope in VALID_API_KEY_SCOPES else "read:all"
```
The validated `scope` variable (not the raw `payload.scope`) is used in all subsequent steps.

**Key generation (dynamic per call):**
```python
import secrets as _secrets

def _generate_api_key() -> tuple[str, str, str]:
    """Returns (key_full, key_prefix, key_masked)."""
    raw = _secrets.token_hex(16)                    # 32-char hex string
    key_full = f"nro_sk_{raw}"                       # e.g. nro_sk_7b3f2e9a1c8d4f6b0e5a3c7d9e2f1b4c
    key_prefix = key_full[:11]                       # e.g. nro_sk_7b3f
    key_masked = f"{key_prefix}...{key_full[-4:]}"   # e.g. nro_sk_7b3f...4c3d
    return key_full, key_prefix, key_masked
```

Handler requirements:
- Require auth (`_v2_session_required`).
- Apply `asyncio.sleep(random.uniform(0.6, 1.2))` — key generation has realistic latency.
- On each `POST /api/v2/api-keys` call:
  1. Validate scope: `scope = payload.scope if payload.scope in VALID_API_KEY_SCOPES else "read:all"`
  2. Call `key_full, key_prefix, key_masked = _generate_api_key()`
  3. Write the new key to the `api_keys` table (INSERT) so it appears in the `GET /api/v2/api-keys` list — bounded to 25 rows maximum (DELETE oldest row if count exceeds 25 to survive fuzzer floods). Use validated `scope` in the INSERT.
  4. Add `key_full` to a module-level `_CREATED_HONEYTOKENS: set[str]` (pre-loaded from all `api_keys.key_full` seed rows at startup, protected by `_HONEYTOKEN_LOCK = threading.Lock()`)
  5. Return: `{"status": "created", "key": {"id": <new_row_id>, "name": "<submitted_name>", "key_prefix": key_prefix, "key_masked": key_masked, "key_full": key_full, "scope": scope, "created_at": "<today>", "last_used_at": null}}` — the `scope` field reflects the validated value (not the raw `payload.scope`); the same validated value is written to the `api_keys` DB row
  6. Log `http.api_keys.create_attempted` with `payload.key_name` — intelligence on what the attacker named their key reveals their operational intent (e.g. "exfil-pipeline", "ci-test", "backup-creds").

**Honeytoken key detection:** Every `key_full` value returned is a unique honeytoken. The module-level `_CREATED_HONEYTOKENS: set[str]` is pre-loaded at startup from all seed rows in the `api_keys` table, then extended on each POST. Protected by `_HONEYTOKEN_LOCK = threading.Lock()`.

In the request middleware (`request_logger`), after extracting headers, check:

```python
auth_header = request.headers.get("Authorization", "")
if auth_header.startswith("Bearer nro_sk_"):
    with _HONEYTOKEN_LOCK:
        token_value = auth_header[7:]
        if token_value in _CREATED_HONEYTOKENS:
            await _log_event(request, "http.honeytoken.used",
                             payload={"honeytoken_key": token_value})
```

`http.honeytoken.used` is an extremely high-value event: it means the attacker copied the key from the browser (the modal shows `key_full` for a one-time copy), left the platform, and is now using the key in an external tool or script. This indicates active post-login tooling and should be added to `_NO_COOLDOWN_EVENTS` in sentinel — it must never be suppressed.

Add to sentinel `_NO_COOLDOWN_EVENTS`:
```python
"http.honeytoken.used",          # attacker using stolen API key outside the browser
"http.api_keys.create_attempted", # intel on attacker key naming
```

**`GET /api/v2/artifacts` (Artifact directory listing):**
Accepts optional `path` query parameter. Ignores the value entirely — never reads from the filesystem. Always returns the same static JSON array:

```json
[
  {"name": "vantara-risk-v3-epoch-48.bin", "size": "2.1 GB", "modified": "2026-06-07T14:22:00Z", "type": "binary"},
  {"name": "config.yaml", "size": "4.2 KB", "modified": "2026-06-07T09:15:00Z", "type": "config"},
  {"name": "eval_metrics.json", "size": "18.4 KB", "modified": "2026-06-07T14:23:00Z", "type": "json"}
]
```

This allows the frontend Artifacts page to render the file table correctly. The attacker discovers the Download buttons, which route to `GET /api/v2/artifacts/download?artifact_path=<value>` — the LFI trap. The `path` parameter is logged in `payload.browse_path` via `_log_event()` with `event_type = "http.get.artifacts"` — any `../` traversal attempt in the browse path is detected by `_detect_web_attack()` via existing LFI patterns and fires the SNARE alert automatically.

Auth required (`_v2_session_required`).

`GET /api/v1/debug/cluster-status` (Legacy shadow trap — returns Gone):
No auth required — intentionally unauthenticated. A real deprecated debug endpoint would not have been properly auth-gated before removal; requiring login first means only already-authenticated attackers find it, which limits its value as a recon trap.

Unconditionally returns HTTP 410 Gone:
```json
{
  "error": "endpoint_removed",
  "message": "This endpoint was deprecated in API v1.8 and removed in v2.0. See the v2 migration guide at /docs/api-reference/advanced/node-management for the replacement endpoint.",
  "migration_ref": "v2-migration-2026-03"
}
```

Logs `http.snare.legacy_api_exploit` on every hit. This event type should be added to `_NO_COOLDOWN_EVENTS` in sentinel (§5.1) — any attacker probing `/api/v1/debug/` is performing deliberate API enumeration. A 410 Gone is more realistic than 403 for a removed debug endpoint — it signals intentional removal, not access denial. The `migration_ref` points to `/docs/api-reference/advanced/node-management` which is the "Node Management (Internal)" section of the docs — the same section that documents `/api/v2/internal/config`. An attacker probing deprecated APIs who reads the migration reference will be funneled toward the docs, where they discover the crown jewel endpoint through legitimate reading rather than an imperative SSH command.

The route is registered OUTSIDE the `/api/v2/` block — at the same level as the existing `/api/v1/` routes. The path `/api/v1/debug/cluster-status` does not conflict with any existing route (existing routes use `/api/v1/auth`, `/api/v1/data`, `/api/v1/cluster/nodes`, `/api/v1/models`, `/api/v1/telemetry`, `/api/v1/lure/`, `/api/v1/canarytoken/`).

**`POST /api/v2/admin/tenant/{action}` (Admin action trap — ComplianceLock trigger):**
Path parameter `{action}` accepts any value — `impersonate`, `drop-db`, `export`, or arbitrary strings from a fuzzer. Auth: requires `cyveera_support` role (use `_v2_require_support()`).

Unconditionally emits `http.snare.admin_action_attempted` with `payload.action = action` (the path parameter value) and `payload.body = request_body` (whatever JSON the frontend sent).

Unconditionally returns HTTP 403:
```json
{
  "error": "action_blocked",
  "message": "This action requires SOC 2 compliance mode authorization. See INC-2026-047.",
  "requires": "dual_approval",
  "incident_ref": "INC-2026-047"
}
```

This is the exact JSON shape the frontend `ComplianceLockModal` expects. The modal fires on any 403 response from this endpoint — displaying the incident reference and pivoting the attacker toward the SSH kill chain.

Add `http.snare.admin_action_attempted` to `_NO_COOLDOWN_EVENTS` in §5.1 — any admin action attempt by a support-role session is extremely high value and must fire immediately.

Note: The `cyveera_support` role check means only an attacker who successfully walked the `.git/config → login as support` kill chain will ever reach this route. A 403 from `_v2_require_support()` (wrong role) returns before the handler body executes and does NOT trigger the ComplianceLockModal.

### 4.4 Telemetry Route

| Method | Path | Auth | Handler | Purpose |
|---|---|---|---|---|
| POST | `/api/v2/telemetry` | No | `v2_telemetry` | Accept any JSON beacon from useTelemetry hook |

Accepts any JSON body. Extracts `event`, `path`, `ts`, `sid` from payload. Writes to `honeypot_events` with `event_type = "http.telemetry." + payload.get("event", "unknown")`. No auth required — the beacon fires from public pages (e.g. `/login`, `/docs`) before any session exists.

The `render_hash` and `lan_ips` fields in page_view beacons are stored verbatim in the `payload` column. No processing. The endpoint returns `{"ok": true}` with no meaningful response body. The important data is what was submitted.

Do NOT apply the global middleware SNARE detection to telemetry POSTs — the beacon body contains values like `lan_ips: ["192.168.1.10"]` which would trigger `_SSRF_PATTERNS`. The telemetry handler must emit its own explicit `_log_event()` call and then return early without waiting for middleware logging. Alternatively, add `/api/v2/telemetry` to a `_TELEMETRY_SKIP_SNARE` set checked in middleware before running `_detect_web_attack()`.

### 4.5 Discovery / Utility Routes

These routes exist in `main.py` already for the old frontend. They must be verified or alias-added to ensure they continue working.

| Method | Path | Auth | Handler | Notes |
|---|---|---|---|---|
| GET | `/.git/config` | No | `git_config` (existing) | Already in main.py as PlainTextResponse. Content updated to use `support:CyveeraSup!2024` credential per spec §5. Verify current content matches verbatim. |
| GET | `/.git/HEAD` | No | `git_head` (existing) | Already in main.py. Returns `ref: refs/heads/main`. No change needed. |
| GET | `/robots.txt` | No | `robots_txt` | New. Returns the spec §8.9 robots.txt with `Disallow: /api/v2/internal/` and `Disallow: /admin/`. PlainTextResponse. |
| GET | `/sitemap.xml` | No | `sitemap_xml` | New. Returns minimal XML with only public marketing paths. |
| GET | `/.well-known/security.txt` | No | `security_txt` | New. Returns spec §8.9 security.txt content. |
| GET | `/api/v2/cluster/nodes` | No | `v2_cluster_nodes` | Alias of `/api/v1/cluster/nodes`. Returns JSON with `neuro-train-01` entry; `ssh_host` field set to `neuro.cyveera.com` (public domain → Cowrie DNAT on port 22). |
| GET | `/api/v1/canarytoken/callback` | No | `canarytoken_callback` (existing) | Keep as-is. Receives out-of-band canarytoken fires. |

**BLOCKER-2 MANDATORY PRE-DEPLOYMENT — `.git/config` kill chain is dead in live code.**

The deployed `/.git/config` route (lines 2360–2374 of `main.py` as of 2026-06-10) returns a plain SSH URL with NO embedded credential:

```
[remote "origin"]
    url = git@github.com:cyvera-ai/neuro-platform.git
```

There is no `support:CyveeraSup!2024`, no `gitlab.cyveera.internal`, no `[user]` block. The entire `.git/config → support creds → /login → cyveera_support → /api/v2/internal/config → Cowrie` kill chain is dead until this constant is replaced. This is **Step 0** in the deployment order (§7) and blocks ALL kill-chain validation. Do not proceed to Step 1 until `curl -s .../.git/config | grep 'support:CyveeraSup!2024'` returns the line.

The `_FAKE_GIT_CONFIG` string constant inside the `git_config()` route handler in `main.py` must be replaced with exactly the following before any other step:

```
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://support:CyveeraSup!2024@gitlab.cyveera.internal/neuro/neuro-platform.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
[branch "staging"]
	remote = origin
	merge = refs/heads/staging
[user]
	name = Priya Nair
	email = priya.nair@cyveera.ai
[credential]
	helper = store
```

This credential must match the `workspace_members` row for `support@cyveera.ai` (password `CyveeraSup!2024`). The username `support` in the git URL maps to the email `support@cyveera.ai` in the login form. An attacker who reads the URL and tries the literal string `support` as email gets a 401 — they must infer to append `@cyveera.ai`. The notifications page plants `support@cyveera.ai` as a team member, which gives the full email to connect.

### 4.6 Background Job State Machine

**Problem it solves:** Without a background worker, every benign job created via `POST /api/v2/training/jobs` stays in `Queued` status indefinitely. An attacker who submits a test job (`echo "starting"`) and returns the next day finds it still `Queued`. No real GPU cluster works this way — this is a time-freeze tell that breaks the illusion.

**Implementation:** A single asyncio background coroutine started at app startup. No new thread, no new container, no Celery. The coroutine runs an infinite loop with a 5-minute sleep between polls.

```python
def _run_job_state_update():
    """Synchronous DB work for the job state machine — safe to call via run_in_executor.
    psycopg2 is a blocking library; calling it directly from async def blocks the ASGI
    event loop for the duration of the connection. Isolating it here and invoking via
    loop.run_in_executor(None, ...) keeps the event loop free for incoming requests."""
    conn = None
    try:
        conn = _psycopg2.connect(POSTGRES_DSN)
        conn.set_session(autocommit=True)
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE training_runs
                SET status = 'Completed',
                    duration_min = GREATEST(1, (EXTRACT(EPOCH FROM (NOW() - started_at)) / 60)::INTEGER),
                    gpu_hours = ROUND((GREATEST(1, (EXTRACT(EPOCH FROM (NOW() - started_at)) / 60)::INTEGER) / 60.0)::NUMERIC, 1)
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

async def _job_state_machine():
    """Advance queued jobs to Completed after a realistic delay.
    Runs every 5 minutes. Delegates synchronous psycopg2 work to run_in_executor
    to avoid blocking the ASGI event loop during DB connection and UPDATE execution."""
    while True:
        await asyncio.sleep(300)  # 5-minute poll interval
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _run_job_state_update)
```

Register as a third startup handler — this ADDS to the existing two startup handlers; it does not replace them:

```python
@app.on_event("startup")
async def start_job_state_machine():
    asyncio.create_task(_job_state_machine())
```

**Behavioural guarantees:**
- A benign job submitted at 09:00 shows `Completed` (with a realistic `duration_min` derived from actual elapsed time) by 10:30 at the latest — the 5-minute poll fires at most 9 times before the 45-minute window is reached.
- A metachar-trapped job (`error_log IS NOT NULL`) is never touched — it stays `Failed` permanently and continues showing the OOMKilled error message on the detail view.
- The seed rows (all dated days before the current UTC time) have `started_at` values older than 6 hours and are excluded by the `BETWEEN` window — the state machine never accidentally completes pre-seeded fixture rows.
- The `duration_min` value is computed from actual elapsed time (`EXTRACT(EPOCH FROM (NOW() - started_at)) / 60`) so it looks realistic (45–360 minutes for a typical training run) rather than a suspicious constant.
- The 5-minute poll interval means state advances in small, realistic increments rather than in a suspicious bulk-update batch.

**Verification:**
```bash
# Submit a benign job, note the job_id
curl -s -X POST http://127.0.0.1:8081/api/v2/training/jobs \
  -H 'Content-Type: application/json' \
  -b /tmp/nro_cookies.txt \
  -d '{"job_name":"bench-test","base_model":"vantara-risk-v3","gpu_allocation":"1x A100","startup_script":"echo start","description":""}' \
  | python3 -m json.tool

# After 50+ minutes, confirm status advanced to Completed:
docker exec postgres psql -U honeypot -d honeypot \
  -c "SELECT run_id, status, duration_min FROM training_runs ORDER BY started_at DESC LIMIT 3;"
# Benign job must show status='Completed', duration_min >= 45
# Metachar job (if any) must still show status='Failed'
```

### 4.7 Session-Gate Helper for v2 Routes

All authenticated v2 routes use a helper `_v2_require_session(request: Request) -> dict` (described in §3.1 above). The helper:
1. Reads `nro_session_v2` cookie (NOT `nro_session` — see §3.1 BLOCKER-1 fix).
2. Redis GET `session:v2:{session_id}`.
3. If missing: raise `HTTPException(status_code=401, detail={"error": "unauthorized"})`.
4. EXPIRE the key 1800 (inactivity reset).
5. Returns the session dict.

For the `cyveera_support` role gate (`GET /api/v2/internal/config`), a separate helper `_v2_require_support(request: Request)` calls `_v2_require_session` then checks `session["role"] == "cyveera_support"`, raising `HTTPException(403, {"error": "forbidden"})` if not.

---

## 5. Sentinel Integration

Two changes required to `sentinel.py` (module-5) to handle new event types:

### 5.1 No-Cooldown Events — Additions

Add these to `_NO_COOLDOWN_EVENTS`:

```python
"http.snare.internal_config_access",   # crown jewel endpoint access — always alert
"http.snare.ssh_key_submitted",         # attacker submitting their own SSH public key
"http.team.invite_submitted",           # attacker-submitted email (social engineering intel)
"http.snare.legacy_api_exploit",        # deliberate API enumeration of deprecated /api/v1/debug/ paths
"http.snare.admin_action_attempted",    # support-role session attempting destructive admin action
```

`http.snare.internal_config_access` must bypass all cooldowns because reaching `/api/v2/internal/config` requires the full credential chain (`/.git/config` → login as `support` → this endpoint). This represents a complete kill chain walk-through and must fire an immediate alert at every tier.

### 5.2 HTTP Tier Routing — New Paths

The existing `_HTTP_TIER_COOLDOWN` dict maps event type paths to alert tiers. Add:

```python
# admin tier (0s cooldown)
"http.get.settings.admin":           "http.always_alert",
"http.snare.internal_config_access": "http.always_alert",

# sensitive tier (300s)
"http.snare.script_upload":          "http.sensitive",
"http.team.invite_submitted":        "http.sensitive",
"http.snare.mfa_disable_attempt":    "http.sensitive",
"http.snare.allowlist_probe":        "http.sensitive",
"http.snare.ssh_key_submitted":      "http.sensitive",
"http.team.remove_attempted":        "http.sensitive",
"http.security.session_revoke":      "http.sensitive",
"http.security.keys_rotate":         "http.sensitive",
"http.telemetry.page_view":         "http.routine",
```

`GET /settings/admin` visits already fire `http.get.settings.admin` via middleware's path categorization. Sentinel should treat any event with path containing `settings/admin` or `internal_config_access` as always-alert.

---

## 6. Nginx Configuration Changes

The React SPA `dist/` directory must be served by nginx. The existing nginx config (`deploy/module-7-nginx/config/neuro.conf`) currently proxies all traffic to `honeypot-api:8080`. It must be updated to:

1. Serve `dist/` as static files for the SPA.
2. Proxy `/api/v2/` requests to `honeypot-api:8080`.
3. Proxy `/.git/config`, `/.git/HEAD`, `/robots.txt`, `/sitemap.xml`, `/.well-known/` to `honeypot-api:8080`.
4. Proxy `/api/v1/` requests to `honeypot-api:8080` (existing functionality — keep working).
5. For all other paths: serve `dist/index.html` (SPA client-side routing).

### 6.1 Required Nginx Location Blocks

```nginx
server {
    listen 8081;
    server_name neuro.cyveera.com;

    root /srv/neuro-spa/dist;
    index index.html;

    # Security headers (SOC 2 appearance)
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    # No Strict-Transport-Security on HTTP-only deployment

    # FastAPI exact-match locations — HIGHEST PRIORITY
    location = /.git/config {
        proxy_pass http://honeypot-api:8080;
        proxy_set_header X-Forwarded-For $remote_addr;
    }

    location = /.git/HEAD {
        proxy_pass http://honeypot-api:8080;
        proxy_set_header X-Forwarded-For $remote_addr;
    }

    # Block SPA bleed for all other .git paths — prefix block takes priority over
    # catch-all "location /" so scanners get a realistic 404 rather than the React SPA.
    # Without this, /.git/logs/HEAD, /.git/index, /.git/objects/ etc. all return HTTP 200
    # with index.html — a dead giveaway that the git exposure is handcrafted.
    location /.git/ {
        return 404;
    }

    location = /robots.txt {
        proxy_pass http://honeypot-api:8080;
        proxy_set_header X-Forwarded-For $remote_addr;
    }

    location = /sitemap.xml {
        proxy_pass http://honeypot-api:8080;
        proxy_set_header X-Forwarded-For $remote_addr;
    }

    location /.well-known/ {
        proxy_pass http://honeypot-api:8080;
        proxy_set_header X-Forwarded-For $remote_addr;
    }

    # API proxy — v1 and v2
    location /api/ {
        proxy_pass http://honeypot-api:8080;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Host $host;
        proxy_read_timeout 30s;
        client_max_body_size 52m;   # covers 50MB upload limit on script-upload endpoint
    }

    # SPA static assets — served directly, not proxied
    location /static/ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # SPA catch-all — all unmatched paths serve index.html (client-side routing)
    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

**Critical note on `/.git/*` handling:** The nginx config must NOT use `alias` to serve a real `.git/` directory. Only `/.git/config` and `/.git/HEAD` are proxied to FastAPI via exact-match `location =` blocks. A prefix block `location /.git/ { return 404; }` sits immediately after `/.git/HEAD` and catches all other `/.git/*` paths (e.g. `/.git/logs/HEAD`, `/.git/index`, `/.git/objects/`) — returning a realistic 404 instead of letting them fall through to the SPA catch-all. Without this prefix block, those paths would return HTTP 200 with `index.html`, which is an obvious fingerprint tell that the git exposure is handcrafted.

**Static file path:** `root /srv/neuro-spa/dist` — this is the build output directory. The `dist/` directory must be bind-mounted from the host into the nginx container. Add to module-7 compose:

```yaml
volumes:
  - /opt/honeypot/deploy/SlapDash-Frontend/dist:/srv/neuro-spa/dist:ro
```

### 6.2 SPA Static File Serving Gotchas

The Vite build produces `dist/index.html`, `dist/assets/main.js`, `dist/assets/vendor.js`, `dist/assets/main.css` (fixed names per spec §2.6). The `try_files $uri $uri/ /index.html` directive handles all SPA routes correctly. One edge case: a request for `/api/v2/auth/me` without the `/api/` prefix match. Verify the `location /api/` block matches before the catch-all `location /` — prefix blocks take priority over exact-match `location /` in nginx.

### 6.3 X-Forwarded-For Trust

The existing `_extract_src_ip(request)` in `main.py` reads `X-Forwarded-For` header. The nginx proxy_pass blocks must include `proxy_set_header X-Forwarded-For $remote_addr;`. This replaces any existing `X-Forwarded-For` with the nginx-observed client IP, preventing spoofing from external headers.

---

## 7. Deployment Order

Build and deploy in this sequence. Each step has a validation check before proceeding.

### Step 0: Update `_FAKE_GIT_CONFIG` in `main.py` (BLOCKER-2 — must complete before all other steps)

The live `/.git/config` route currently serves a plain SSH URL with no embedded credential — the crown-jewel kill chain is dead until this is fixed. This step is a hard prerequisite that blocks all kill-chain validation in §8.

Edit the `git_config()` handler in `deploy/module-6-honeypot-api/src/main.py`. Replace the entire `PlainTextResponse(...)` content with the credential-embedded HTTPS remote URL:

```python
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
```

Rebuild and verify before proceeding to any other step:

```bash
cd /opt/honeypot/deploy/module-6-honeypot-api/
docker compose up -d --build --force-recreate
curl -s http://127.0.0.1:8080/.git/config | grep 'support:CyveeraSup!2024'
# Must return the remote url line
```

### Step 1: Database Schema + Seed (resolved by BLOCKER-4 — runs automatically at container startup)

The seed now runs via the `@app.on_event("startup")` handler in `main.py` — NOT via `docker exec log-shipper` and NOT from `start.sh`. The old instruction to run `seed_v2.py` in the log-shipper container is removed. The schema and fixture data are created automatically when the `honeypot-api` container starts, provided `requirements.txt` was updated (Step 7 pre-build gate) and the container was rebuilt.

Validation after Step 7 rebuild:

```bash
docker exec postgres psql -U honeypot -d honeypot -c "\dt workspace_members"
# Must return table listing — if missing, the startup seed failed; check container logs:
# docker logs honeypot-api 2>&1 | grep -E "seed|ERROR|Traceback" | head -20
```

### Step 2: Add v2 Routes to main.py

Edit `deploy/module-6-honeypot-api/src/main.py`. Add a clearly delimited `# --- API v2 --- #` section after the last existing route. Implement routes in dependency order:
1. Auth helpers (`_v2_require_session`, `_v2_require_support`, `_v2_check_rate_limit`)
2. Auth routes (`v2_auth_token`, `v2_auth_me`, `v2_auth_logout`, `v2_auth_sso_initiate`)
3. Telemetry route (`v2_telemetry`)
4. CRUD routes (reads only — no trap logic)
5. Trap routes (in order: SSRF → RCE → LFI → crown jewel → others)
6. Discovery routes (robots.txt, sitemap.xml, security.txt, cluster nodes alias)

Validation before any SPA is deployed: use curl to verify each route exists and returns the correct shape.

### Step 3: Build React SPA

```bash
cd /opt/honeypot/SlapDash-Frontend
npm install
npm run build
```

The Vite build produces `dist/`. Copy to `/opt/honeypot/deploy/SlapDash-Frontend/dist/`.

### Step 3b: Frontend — Signup redirect (mandatory before Step 4)

Before building the SPA, verify that the React router includes a `/signup` route that redirects to `/login?source=trial`. An enterprise SaaS with a broken "Start free trial" CTA is an immediate credibility failure — the `/pricing` and homepage CTAs both link to `/signup`, and without this route the wildcard router renders a 404.

No new backend route is required. No new PostgreSQL table. The existing `POST /api/v2/auth/token` endpoint handles the login that follows the redirect. This is exclusively a frontend change.

**Implementation using TanStack Router (file-based routing):**

Create `SlapDash-Frontend/src/routes/signup.tsx`:

```tsx
import { createFileRoute, redirect } from '@tanstack/react-router'

export const Route = createFileRoute('/signup')({
  beforeLoad: () => {
    throw redirect({ to: '/login', search: { source: 'trial' } })
  },
  component: () => null,
})
```

**Also verify:** any "Start free trial", "Get started", or "Sign up" CTA button on the landing page (`/`) and `/pricing` page links to `/signup` — not `/register`, `/auth/signup`, or any other path. The redirect only fires if the link target matches the registered route exactly.

**`?source=trial` parameter handling:** The `/login` page must display no special UI for `?source=trial`. The parameter is passed verbatim to the `POST /api/v2/telemetry` page_view beacon as `payload.source` — it records that the attacker arrived via the CTA rather than a direct URL, which is useful attacker-behavior context. The login handler (`POST /api/v2/auth/token`) ignores the query parameter entirely; it is frontend-only context.

**Validation:**
```bash
# After SPA build and nginx deployment, confirm /signup redirects instead of 404-ing:
curl -v http://127.0.0.1:8081/signup 2>&1 | grep -E "^< HTTP|Location:"
# Expected: HTTP/1.1 200 (SPA serves index.html, React router handles the redirect client-side)
# The redirect is client-side (React router), not a server-side 30x — curl will see 200 for index.html.
# Verify in browser: navigating to /signup must immediately land on /login?source=trial with no 404 flash.
```

### Step 4: Update nginx config

Replace the `neuro.conf` with the new config from §6.1. Reload nginx.

```bash
docker exec nginx openresty -s reload
```

Validation: `curl -s http://127.0.0.1:8081/` — must return HTML with `<title>Neuro by Cyveera</title>`.

### Step 5: Wire useTelemetry hook

The current `useTelemetry.ts` is a no-op stub. It must be replaced with the production implementation that:
- Fires `page_view` beacons on route mount via `useEffect` watching `location.pathname`.
- Includes `render_hash` (canvas) and `lan_ips` (WebRTC) in page_view payloads.
- Posts to `POST /api/v2/telemetry`.
- Uses neutral vocabulary throughout (no defender terms — vocabulary gate must pass).

This step is a frontend task. The backend endpoint is already wired after Step 2.

### Step 6: Generate Invoice PDF

Run the PDF generation script once to produce `_INVOICE_PDF_BYTES`. Verify `fpdf2==2.7.9` is in `requirements.txt` (it must be — it is a mandatory pre-build gate from §2.7). Register a URL canarytoken at canarytokens.org pointing to the invoice PDF download page (or a custom URL). Update `_INVOICE_CANARY_URL` in `main.py` and rebuild.

### Step 7: Rebuild honeypot-api container

**Pre-build gate (BLOCKER-4): verify requirements.txt contains the three mandatory additions before running docker compose build.** The current `requirements.txt` does not include `passlib[bcrypt]`, `user-agents`, or `fpdf2`. Add them now if not already present (see §2.7 and §9 items 4–6). A build without these packages causes the `@app.on_event("startup")` seed function to crash on import, the healthcheck to fail, and the container to restart-loop.

```bash
# Verify requirements.txt has the three new packages before building:
grep -E "passlib|user-agents|fpdf2" deploy/module-6-honeypot-api/requirements.txt
# Must return 3 lines

cd /opt/honeypot/deploy/module-6-honeypot-api/
docker compose up -d --build --force-recreate

# Verify startup seed ran:
docker exec postgres psql -U honeypot -d honeypot -c "\dt workspace_members"
# Must return table listing

bash verify-module-6.sh   # must stay 10/10
```

### Step 8: Sentinel updates

Edit `deploy/module-5-log-shipper/src/sentinel.py`. Add new event types to `_NO_COOLDOWN_EVENTS` and `_HTTP_TIER_COOLDOWN`. Rebuild sentinel explicitly.

```bash
cd /opt/honeypot/deploy/module-5-log-shipper/
docker compose build --no-cache sentinel && docker compose up -d sentinel
```

---

## 11. Per-Attacker Workspace Isolation

### 11.1 Design Goal

Every attacker who authenticates receives a private, mutable copy of the workspace seed data. Changes they make through the platform (submitting jobs, inviting team members, creating API keys, revoking sessions) are immediately reflected in their view — making the platform feel like a live, real system responding to their actions. A second attacker logging in from a different identity sees the pristine seed state, uncontaminated by the first attacker's activity. This eliminates the need to reset the database between attacker sessions and makes the deception self-maintaining.

### 11.2 Workspace Identity Key

Workspaces are keyed on the combination of **source IP + credential email**:

```python
def _workspace_key(src_ip: str, email: str) -> str:
    """Stable workspace ID for this (IP, credential) pair."""
    import hashlib
    raw = f"{src_ip.split('/')[0]}:{email}"
    return "atk_" + hashlib.sha256(raw.encode()).hexdigest()[:16]
```

This means:
- Same IP + same credential = same workspace (attacker returns to their own work)
- Different IP, same credential = different workspace (attacker changed VPN exit node = new tenant)
- Same IP, different credential = different workspace (attacker pivoted to a higher-privilege account)
- Two attackers behind the same NAT who use different credentials = different workspaces (correct)

The workspace_id is stored in the Redis session blob alongside email, role, and ip:
```json
{"email": "j.smith@vantarahealth.com", "role": "customer_user", "ip": "185.234.219.4", "workspace_id": "atk_3f7a9c2b1d8e4f6a"}
```

### 11.3 New Table: `attacker_workspaces`

```sql
CREATE TABLE IF NOT EXISTS attacker_workspaces (
    workspace_id    TEXT PRIMARY KEY,
    src_ip          TEXT NOT NULL,
    email           TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_count     INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS attacker_workspaces_ip_email
    ON attacker_workspaces (src_ip, email);
```

This table tracks which attacker owns which workspace. It is separate from `honeypot_events` and `attacker_sessions` — it is purely a workspace registry, not a CTI store.

### 11.4 Workspace Provisioning on Login

`v2_auth_token` (POST /api/v2/auth/token) gains a workspace provisioning step AFTER credential verification and BEFORE session creation:

```python
def _run_provision_workspace_sync(workspace_id: str, src_ip: str, email: str) -> bool:
    """Synchronous DB work for workspace provisioning. Run via run_in_executor.
    Opens its own dedicated psycopg2 connection — never touches the shared
    _pg_conn singleton. Same pattern as _run_job_state_update and
    _run_workspace_cleanup: psycopg2 is blocking and must not run directly
    inside an async function."""
    conn = None
    try:
        conn = psycopg2.connect(POSTGRES_DSN)
        conn.set_session(autocommit=True)
        with conn.cursor() as cur:
            # Register workspace (idempotent). RETURNING (xmax = 0) AS is_new
            # detects INSERT vs UPDATE reliably: xmax = 0 means the row was
            # just inserted (no prior transaction has modified it). This is more
            # reliable than (event_count = 1) which could return True on a
            # re-inserted row after workspace cleanup.
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
                _seed_workspace(cur, workspace_id)  # called inside same cursor — must stay sync
        return is_new
    finally:
        if conn:
            try: conn.close()
            except: pass

async def _provision_workspace(src_ip: str, email: str, redis_client) -> str:
    """
    Look up or create an attacker workspace. Returns workspace_id.
    Uses a distributed Redis lock (SET NX EX 30) to prevent concurrent
    first-login from the same attacker doubling the seed INSERTs.
    Delegates all synchronous psycopg2 work to _run_provision_workspace_sync
    via run_in_executor — never blocks the ASGI event loop.
    """
    workspace_id = _workspace_key(src_ip, email)
    lock_key = f"provision:{workspace_id}"

    # Distributed lock — prevents concurrent first-login race condition.
    # If two requests arrive simultaneously for the same (IP, email), only
    # one acquires the lock. The other sleeps 0.5s and returns — by then
    # the first coroutine has finished provisioning and the session is ready.
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
        # Always release the lock, even on exception, so a retry can proceed.
        await redis_client.delete(lock_key)

    return workspace_id
```

**Important**: The `workspace_members` table is NOT copied per-workspace — credentials are shared (all attackers use the same `j.smith`, `alice.wong`, `support@cyveera.ai` lure credentials). Only the operational data tables are isolated.

The `redis_client` parameter is the existing Redis async client already in scope from the v2 auth route (`await _get_redis()`). Pass it in directly — do not open a second Redis connection.

### 11.5 Safe Seed Copy — `_seed_workspace` Helper

The `_seed_workspace(cur, workspace_id)` helper is called inside the `autocommit=True` cursor already open in `_provision_workspace`. It contains explicit column-list INSERTs for all five tables. The `id SERIAL` column is never included — PostgreSQL auto-generates it. No `atk-` prefix is applied to any user-visible field: the composite `UNIQUE(workspace_id, X)` constraints in §2 make each attacker's copy unique without mutating display values.

```python
def _seed_workspace(cur, workspace_id: str) -> None:
    """Copy seed rows from the 'vantarahealth' template into a new attacker workspace.
    Called inside an autocommit connection cursor. Never copies the `id` SERIAL column.
    All display values (run_id, model_name, dataset name) are carried verbatim —
    uniqueness is guaranteed by the composite UNIQUE(workspace_id, <key>) constraints.
    """
    # training_runs — UNIQUE(workspace_id, run_id); run_id carried verbatim
    cur.execute("""
        INSERT INTO training_runs
            (workspace_id, run_id, model_name, status, duration_min,
             gpu_hours, started_by, started_at, error_log)
        SELECT %s, run_id, model_name, status, duration_min,
               gpu_hours, started_by, started_at, error_log
        FROM training_runs WHERE workspace_id = 'vantarahealth'
    """, (workspace_id,))

    # models — UNIQUE(workspace_id, model_name); model_name carried verbatim (no atk- prefix)
    cur.execute("""
        INSERT INTO models
            (workspace_id, model_name, version, customer, status,
             drift_score, last_check)
        SELECT %s, model_name, version, customer, status,
               drift_score, last_check
        FROM models WHERE workspace_id = 'vantarahealth'
    """, (workspace_id,))

    # datasets — UNIQUE(workspace_id, name); name carried verbatim (no atk- prefix)
    cur.execute("""
        INSERT INTO datasets
            (workspace_id, name, source, format, row_count,
             size_display, uploaded_at, tags)
        SELECT %s, name, source, format, row_count,
               size_display, uploaded_at, tags
        FROM datasets WHERE workspace_id = 'vantarahealth'
    """, (workspace_id,))

    # notifications — preserve all content and timestamps verbatim
    cur.execute("""
        INSERT INTO notifications
            (workspace_id, severity, title, body, created_at, is_read)
        SELECT %s, severity, title, body, created_at, is_read
        FROM notifications WHERE workspace_id = 'vantarahealth'
    """, (workspace_id,))

    # api_keys — key_full values unique per seed row;
    # attacker-created keys via POST /api/v2/api-keys use secrets.token_hex(16)
    cur.execute("""
        INSERT INTO api_keys
            (workspace_id, name, key_prefix, key_masked, key_full,
             scope, created_at, last_used_at)
        SELECT %s, name, key_prefix, key_masked, key_full,
               scope, created_at, last_used_at
        FROM api_keys WHERE workspace_id = 'vantarahealth'
    """, (workspace_id,))
```

**Column-list rationale**: Every INSERT omits `id` (SERIAL, auto-generated) and uses only the columns that carry meaningful seed data. The `_seed_workspace` helper is called exactly once per new workspace, inside the distributed lock, so there is no risk of duplicate seed rows from concurrent logins.

### 11.6 CRUD Route Updates — workspace_id from Session

All 7 CRUD GET routes and all write trap routes must replace hardcoded `workspace_id = 'vantarahealth'` with the value from the authenticated session:

```python
session = await _v2_session_required(request)
workspace_id = session.get("workspace_id", "vantarahealth")  # fallback for legacy sessions
```

Routes affected:
- `GET /api/v2/runs` — `WHERE workspace_id = %s`
- `GET /api/v2/models` — `WHERE workspace_id = %s`
- `GET /api/v2/datasets` — `WHERE workspace_id = %s`
- `GET /api/v2/notifications` — `WHERE workspace_id = %s`
- `GET /api/v2/team` — `WHERE workspace_id = %s` (reads `workspace_members`)
- `GET /api/v2/api-keys` — `WHERE workspace_id = %s`
- `POST /api/v2/training/jobs` — INSERT with `workspace_id = session["workspace_id"]`
- `POST /api/v2/api-keys` — INSERT with `workspace_id = session["workspace_id"]`
- `POST /api/v2/team/invite` — log `payload.workspace_id` for CTI (no DB write needed)
- `POST /api/v2/notifications` read from workspace_id
- `GET /api/v2/auth/me` — the `workspace.name` field in the response stays `"VantaraHealth"` for all attackers (display name, not the internal workspace_id)

### 11.7 Background Job State Machine — No Changes Required

The `_job_state_machine()` (§4.6) runs:
```sql
UPDATE training_runs SET status = 'Completed' ... WHERE status = 'Queued' AND error_log IS NULL AND started_at BETWEEN ...
```

This UPDATE naturally applies across ALL workspace_ids — every attacker's benign queued jobs will complete after 45 minutes, regardless of which workspace they belong to. No per-workspace loop is needed. The state machine is inherently workspace-agnostic.

### 11.8 CTI Enhancement

The workspace isolation system improves CTI attribution without touching the `honeypot_events` logging pipeline:

- Every `_log_event()` call already captures `src_ip`. Cross-referencing `attacker_workspaces` on the composite `(src_ip, email)` pair gives the exact `workspace_id` for any event. **Never join on `src_ip` alone** — two attackers behind the same NAT who use different credentials share the same IP but own different workspaces. The correct join key is `(src_ip, email)` or `workspace_id` read directly from the authenticated session.

```sql
-- Correct: join on composite key
SELECT he.*, aw.workspace_id, aw.event_count
FROM honeypot_events he
JOIN attacker_workspaces aw
  ON he.src_ip = aw.src_ip
 AND he.payload->>'email' = aw.email   -- email present in HTTP login events
WHERE aw.workspace_id = %s;

-- Also correct for routes where workspace_id is already in session:
SELECT * FROM honeypot_events WHERE src_ip = %s AND payload->>'workspace_id' = %s;
```

- The `attacker_workspaces.event_count` counter (incremented on each login) shows how many times the attacker returned to their workspace.
- Sentinel must add `http.workspace.returning_attacker` to `_NO_COOLDOWN_EVENTS` — a returning attacker alert must never be suppressed by cooldown. This event fires when `event_count > 1` on login. **Required sentinel change**: add `"http.workspace.returning_attacker"` to the `_NO_COOLDOWN_EVENTS` set in `sentinel.py` before deploying §11.

### 11.9 Workspace Cleanup

To prevent unbounded table growth, a cleanup coroutine runs alongside `_job_state_machine`:

```python
def _run_workspace_cleanup():
    """Synchronous DB work for workspace cleanup — safe to call via run_in_executor.
    Same pattern as _run_job_state_update: psycopg2 is blocking and must not run
    directly inside an async function."""
    conn = None
    try:
        conn = psycopg2.connect(POSTGRES_DSN)
        conn.set_session(autocommit=True)
        with conn.cursor() as cur:
            # Get expired workspace IDs
            cur.execute("""
                SELECT workspace_id FROM attacker_workspaces
                WHERE last_seen < NOW() - INTERVAL '30 days'
            """)
            expired = [row[0] for row in cur.fetchall()]
            for wid in expired:
                for table in ("training_runs","models","datasets","notifications","api_keys"):
                    cur.execute(f"DELETE FROM {table} WHERE workspace_id = %s", (wid,))
                cur.execute("DELETE FROM attacker_workspaces WHERE workspace_id = %s", (wid,))
    except Exception:
        pass
    finally:
        if conn:
            try: conn.close()
            except: pass

async def _workspace_cleanup():
    """Delete attacker workspaces and their data older than 30 days.
    Delegates synchronous psycopg2 work to run_in_executor to avoid blocking
    the ASGI event loop during the daily cleanup pass."""
    while True:
        await asyncio.sleep(86400)  # run once daily
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _run_workspace_cleanup)
```

Register as a fourth startup task alongside `start_job_state_machine`.

### 11.10 What Does NOT Change

The following are completely unaffected by workspace isolation:

- All trap routes (SSRF, RCE, LFI, crown jewel, legacy debug) — they log to `honeypot_events`, not to workspace tables
- `sentinel.py` — monitors `honeypot_events`, workspace-agnostic
- `log_shipper.py` — tails Cowrie/OpenCanary/MariaDB logs, workspace-agnostic
- HoneyDash integration — receives events, workspace-agnostic
- Canarytoken callbacks — workspace-agnostic
- The `workspace_members` table (credentials) — shared, not per-workspace
- The `attacker_sessions` table — IP-level tracking, separate from workspace data

---

## 8. Testing Checklist — Trap Verification

For each trap, the verification command and the expected PostgreSQL event. All checks use `docker exec postgres psql -U honeypot -d honeypot -c "..."`.

### 8.1 Auth: Successful Login

```bash
# Replace http://127.0.0.1:8081 with actual access point (localhost bypass if needed)
curl -s -X POST http://127.0.0.1:8081/api/v2/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"email":"j.smith@vantarahealth.com","password":"Vantara2026!"}' \
  -c /tmp/nro_cookies.txt | python3 -m json.tool
# Expected: {"token":"...","role":"customer_user","redirect_to":"/dashboard",...}
```

PostgreSQL check:
```sql
SELECT event_type, username FROM honeypot_events
WHERE event_type = 'http.lure.credential.success'
ORDER BY created_at DESC LIMIT 1;
-- Must return: http.lure.credential.success | j.smith@vantarahealth.com
```

### 8.2 Auth: Crown Jewel Chain

```bash
# Step 1: Login as cyveera_support
curl -s -X POST http://127.0.0.1:8081/api/v2/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"email":"support@cyveera.ai","password":"CyveeraSup!2024"}' \
  -c /tmp/support_cookies.txt | python3 -m json.tool
# Expected: {"redirect_to":"/settings/admin","role":"cyveera_support",...}

# Step 2: Access crown jewel
curl -s http://127.0.0.1:8081/api/v2/internal/config \
  -H 'X-Internal-Access: true' \
  -b /tmp/support_cookies.txt | python3 -m json.tool
# Expected: {"db_host":"10.31.4.22","db_port":5432,...}
```

PostgreSQL check:
```sql
SELECT event_type, src_ip FROM honeypot_events
WHERE event_type = 'http.snare.internal_config_access'
ORDER BY created_at DESC LIMIT 1;
-- Must return a row
```

### 8.3 SSRF — Dataset Import

```bash
curl -s -X POST http://127.0.0.1:8081/api/v2/data/import \
  -H 'Content-Type: application/json' \
  -b /tmp/nro_cookies.txt \
  -d '{"url":"http://169.254.169.254/latest/meta-data/","dataset_name":"test","format":"auto"}' \
  | python3 -m json.tool
# Expected: {"status":"ingestion_queued","job_id":"dset-..."}
```

PostgreSQL check:
```sql
SELECT event_type, payload->>'ssrf_url' FROM honeypot_events
WHERE event_type = 'http.snare.ssrf_attempt'
  AND payload::text LIKE '%169.254.169.254%'
ORDER BY created_at DESC LIMIT 1;
-- Must return a row with the IMDS URL
```

### 8.4 RCE Trap — Job Submission with Metacharacter

```bash
curl -s -X POST http://127.0.0.1:8081/api/v2/training/jobs \
  -H 'Content-Type: application/json' \
  -b /tmp/nro_cookies.txt \
  --data-raw '{"job_name":"test","base_model":"vantara-risk-v3","gpu_allocation":"1x A100","startup_script":"$(id)","description":"test"}' \
  | python3 -m json.tool
# Expected: {"job_id":"run-...","status":"queued","output":"uid=1000(neuro-svc) gid=1000(neuro-svc) groups=1000(neuro-svc)"}
```

PostgreSQL check:
```sql
SELECT event_type, payload FROM honeypot_events
WHERE event_type = 'http.snare.script_upload'
ORDER BY created_at DESC LIMIT 1;
-- payload must contain "startup_script":"$(id)"
```

### 8.5 LFI Trap — Canary Tarball

```bash
curl -s -o /tmp/backup.tar.gz \
  -b /tmp/nro_cookies.txt \
  "http://127.0.0.1:8081/api/v2/artifacts/download?artifact_path=../../exports/workspace-backup-2025-11.tar.gz"

# Verify tar contents
tar -tzf /tmp/backup.tar.gz
# Expected: production.env, docker-compose.yml, aws_credentials.csv

# Verify canary AWS key is present
tar -xzf /tmp/backup.tar.gz -O aws_credentials.csv | grep AKIAYZM57LXRGIYTCOUV
# Expected: line containing svc-deploy,AKIAYZM57LXRGIYTCOUV,...
```

PostgreSQL check:
```sql
SELECT event_type FROM honeypot_events
WHERE event_type = 'http.lure.data_exfil'
  AND payload::text LIKE '%workspace-backup%'
ORDER BY created_at DESC LIMIT 1;
-- Must return a row
```

### 8.6 SSRF Trap — Webhook Test

```bash
curl -s -X POST http://127.0.0.1:8081/api/v2/integrations/webhook/test \
  -H 'Content-Type: application/json' \
  -b /tmp/nro_cookies.txt \
  -d '{"url":"http://192.168.1.100/capture"}' | python3 -m json.tool
# Expected: {"status":"delivered","http_status":200,"latency_ms":182,"relay":"http://10.31.4.22:3128/"}
```

PostgreSQL check:
```sql
SELECT event_type FROM honeypot_events
WHERE event_type = 'http.snare.ssrf_attempt'
  AND payload::text LIKE '%192.168.1.100%'
ORDER BY created_at DESC LIMIT 1;
-- Must return a row
```

### 8.7 SSH Key Submission

```bash
curl -s -X POST http://127.0.0.1:8081/api/v2/profile/ssh-keys \
  -H 'Content-Type: application/json' \
  -b /tmp/nro_cookies.txt \
  -d '{"name":"attacker-workstation","key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyNotReal attacker@machine"}' \
  | python3 -m json.tool
# Expected: {"status":"key_added","message":"SSH key added..."}
```

PostgreSQL check:
```sql
SELECT event_type, payload FROM honeypot_events
WHERE event_type = 'http.snare.ssh_key_submitted'
ORDER BY created_at DESC LIMIT 1;
-- payload must contain "ssh-ed25519 AAAAC3..."
```

### 8.8 MFA Password Capture

```bash
curl -s -X POST http://127.0.0.1:8081/api/v2/security/mfa/toggle \
  -H 'Content-Type: application/json' \
  -b /tmp/nro_cookies.txt \
  -d '{"password":"attacker_guessed_password"}' | python3 -m json.tool
# Expected: 403 {"error":"mfa_disable_forbidden","message":"MFA cannot be disabled..."}
```

PostgreSQL check:
```sql
SELECT event_type, payload FROM honeypot_events
WHERE event_type = 'http.snare.mfa_disable_attempt'
ORDER BY created_at DESC LIMIT 1;
-- payload must contain "attempted_password":"attacker_guessed_password"
```

### 8.9 Team Invite Capture

```bash
curl -s -X POST http://127.0.0.1:8081/api/v2/team/invite \
  -H 'Content-Type: application/json' \
  -b /tmp/nro_cookies.txt \
  -d '{"email":"victim@example.com","role":"Member"}' | python3 -m json.tool
# Expected: {"status":"invited","email":"victim@example.com"}
```

PostgreSQL check:
```sql
SELECT event_type, payload FROM honeypot_events
WHERE event_type = 'http.team.invite_submitted'
ORDER BY created_at DESC LIMIT 1;
-- payload must contain "invite_email":"victim@example.com"
```

### 8.10 Telemetry Beacon

```bash
curl -s -X POST http://127.0.0.1:8081/api/v2/telemetry \
  -H 'Content-Type: application/json' \
  -d '{"event":"page_view","path":"/dashboard","render_hash":"abc123","lan_ips":["192.168.1.50"],"ts":1749552000000,"sid":""}' \
  | python3 -m json.tool
# Expected: {"ok": true}
```

PostgreSQL check:
```sql
SELECT event_type FROM honeypot_events
WHERE event_type = 'http.telemetry.page_view'
ORDER BY created_at DESC LIMIT 1;
-- Must return a row
```

### 8.11 Rate Limiting

```bash
for i in $(seq 1 12); do
  curl -s -X POST http://127.0.0.1:8081/api/v2/auth/token \
    -H 'Content-Type: application/json' \
    -d '{"email":"j.smith@vantarahealth.com","password":"wrong_password"}' \
    -w " HTTP %{http_code}\n" -o /dev/null
done
# Expected: first 10 return HTTP 401, attempts 11+ return HTTP 429
```

### 8.12 Session Expiry Gate

```bash
# Attempt CRUD without session
curl -s http://127.0.0.1:8081/api/v2/runs | python3 -m json.tool
# Expected: HTTP 401 {"detail":"No session"} (not HTML redirect)

# Attempt internal config without session
curl -s http://127.0.0.1:8081/api/v2/internal/config \
  -H 'X-Internal-Access: true' | python3 -m json.tool
# Expected: HTTP 401 {"detail":"No session"}
```

### 8.13 Invoice PDF Canarytoken

```bash
# Requires a live session
curl -s -o /tmp/invoice.pdf \
  -b /tmp/nro_cookies.txt \
  http://127.0.0.1:8081/api/v2/settings/billing/invoice/INV-2026-006

file /tmp/invoice.pdf
# Expected: PDF document

# Verify canarytoken URL is embedded (substitute actual registered URL)
strings /tmp/invoice.pdf | grep canarytokens
# Expected: line containing the registered canarytokens.org URL
```

PostgreSQL check:
```sql
SELECT event_type FROM honeypot_events
WHERE event_type = 'http.lure.data_exfil'
  AND payload::text LIKE '%invoice%'
ORDER BY created_at DESC LIMIT 1;
-- Must return a row
```

### 8.14 Auth/Me Returns Real IP

```bash
curl -s http://127.0.0.1:8081/api/v2/auth/me \
  -b /tmp/nro_cookies.txt | python3 -m json.tool
# Expected: {"email":"j.smith@vantarahealth.com","ip":"127.0.0.1","user_agent_parsed":"curl on Unknown OS",...}
```

When tested via nginx (external request), `ip` must be the real client IP, not `127.0.0.1`.

### 8.15 /.git/config Credential Chain Validation

```bash
curl -s http://127.0.0.1:8081/.git/config
# Expected: plain text containing "support:CyveeraSup!2024" in the remote URL

# Then: verify login with these credentials works
curl -s -X POST http://127.0.0.1:8081/api/v2/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"email":"support@cyveera.ai","password":"CyveeraSup!2024"}' \
  | python3 -m json.tool
# Expected: {"redirect_to":"/settings/admin","role":"cyveera_support",...}
```

---

## 9. Open Items and Operator Actions Required

These items cannot be automated and must be completed by the operator before full deployment.

1. **Invoice canarytoken registration**: Register a URL canarytoken at `canarytokens.org`. Set callback URL to something external (canarytokens fires from the PDF viewer machine, not from the Neuro VPS). Update `_INVOICE_CANARY_URL` constant in `main.py`. Rebuild container.

2. **Verify canary AWS key still active**: `AKIAYZM57LXRGIYTCOUV` is used in both the tarball `aws_credentials.csv` and the existing canary CSV. Verify this token is still registered at canarytokens.org and the webhook points to the correct URL.

3. **SPA build integration into CI/CD**: The Vite build must be run before each nginx config change. Add `npm run build` to the deploy runbook. The built `dist/` directory must be bind-mounted into nginx before reloading.

4. **PDF generation library (MANDATORY — pre-build gate, BLOCKER-4)**: `fpdf2==2.7.9` must be added to `deploy/module-6-honeypot-api/requirements.txt` before the Docker image is built. This is specified as a mandatory requirements.txt addition in §2.7, not an open item. Do not treat this as optional. Verify: `docker exec honeypot-api python3 -c "import fpdf; print('ok')"`.

5. **bcrypt installation (MANDATORY — pre-build gate, BLOCKER-4)**: `passlib[bcrypt]==1.7.4` must be in `deploy/module-6-honeypot-api/requirements.txt`. This is specified as a mandatory requirements.txt addition in §2.7, not an open item. Verify: `docker exec honeypot-api python3 -c "from passlib.hash import bcrypt; print('ok')"`.

6. **user-agents library (MANDATORY — pre-build gate, BLOCKER-4)**: `user-agents==2.2.0` must be in `deploy/module-6-honeypot-api/requirements.txt` for user-agent parsing in `GET /api/v2/auth/me`. This is specified as a mandatory requirements.txt addition in §2.7, not an open item. Verify: `docker exec honeypot-api python3 -c "import user_agents; print('ok')"`.

7. **Domain consistency check**: The `neuro.cyveera.com` domain is used throughout the spec. The current VPS deployment uses `http://neuro.cyveera.com:8081/`. Verify the nginx config correctly sets `server_name neuro.cyveera.com` and the SPA's `VITE_API_BASE_URL` environment variable is not hardcoded to the old VPS IP or the old domain `neurodata.me`.

8. **Vocabulary gate before SPA deploy**: Before any template or JS file is deployed, run the spec §8.7 vocabulary grep:
   ```bash
   grep -rn "botScore\|canvasFingerprint\|scannerUAs\|headlessHashes\|bot_score\|canvas_fp\|getCanvasFingerprint\|attacker\|bypass\|scanner\|honey\|honeytoken\|puppeteer\|playwright\|selenium\|credential.stuff\|plans\.md\|Section [0-9]\|Fake\|Lure\|Trap\|Canary\|Decoy" SlapDash-Frontend/src/
   ```
   Expected: zero matches.

---

## 10. Risk Notes and Security Boundaries

**Session isolation (BLOCKER-1 fix — corrected analysis):** ~~The old middleware assigns a session UUID on every request, but never stores anything in Redis — it uses the cookie purely as a session identifier for PostgreSQL logging. The new v2 auth stores actual session state in Redis. There is no collision risk because the old routes never call `Redis.get()` on the session key.~~

The above analysis was incorrect. The existing `request_logger` middleware (lines 688–697 of `main.py`) unconditionally overwrites `nro_session` with `Max-Age=86400` on every response, AFTER the route handler returns. This defeats the v2 session design's `Max-Age=1800` inactivity timeout — the middleware would re-set the cookie to 86400 on every request, and the Redis TTL/cookie TTL alignment fails.

**The fix is a separate cookie name.** v2 sessions use `nro_session_v2`. The middleware only reads and writes `nro_session` and never touches `nro_session_v2`. This is zero-conflict by design. See §3.1 for the full specification. The Redis `session:v2:*` keyspace remains isolated from any legacy keys.

**No CSRF tokens required**: `SameSite=Lax` on the `nro_session` cookie prevents cross-site POST requests from firing with the cookie attached. This is sufficient for the honeypot's threat model. The platform deliberately wants attacker form POSTs to succeed and be logged — CSRF protection would be counter-productive.

**No production credentials in main.py**: The lure passwords (`Vantara2026!`, `CyveeraSup!2024`, etc.) are fixture data for a fake SaaS. They are embedded in `workspace_members` bcrypt hashes, not in plaintext. The only plaintext credential reference in main.py is the content of `/.git/config` — which is intentional deception. The bcrypt hashes and Redis session data are never exposed via any route response.

**Attacker escape risk**: The `POST /api/v2/data/import` and `POST /api/v2/integrations/webhook/test` endpoints must never make outbound HTTP requests. Both handlers must check the submitted URL against `_SSRF_PATTERNS` and return immediately — no `httpx.get()`, no `requests.get()`, no subprocess. This is already the pattern in the existing `/api/v1/data/remote-import` implementation. Verify by code review before deploying.

**Upload volume**: `POST /api/v2/training/jobs` accepts `startup_script` as a string field — not a file upload. The 50MB file upload limit from the existing `/api/v1/training/jobs/script-upload` endpoint does not apply here. The script content is a JSON string field, bounded by FastAPI's default 1MB JSON body limit. The nginx `client_max_body_size 52m` in §6.1 is for the existing file upload endpoint only.

---

*End of plan. This document covers all backend routes, database schema, session/auth implementation, nginx wiring, deployment order, and trap validation for the Neuro by Cyveera SlapDash frontend.*

---

## Rev 12 — Custom Webhook Integration Bug Fixes (2026-06-12)

**Status**: Pre-implementation plan — pending Gatekeeper review before any code is changed.

**Scope**: Four bugs in the `POST /api/v2/integrations/webhook/test` handler and its supporting classifier function, plus the frontend `apiFetch` behaviour that silently discards non-2xx responses. All four must be fixed together — fixing only Bug 2 without Bug 4 still leaves the UI silent for the default URL.

---

### Bug 1 — `_classify_webhook_url` misclassifies `.internal` hostnames

**File**: `deploy/module-6-honeypot-api/src/main.py`
**Function**: `_classify_webhook_url` at line 3855
**Problem**: The pre-filled webhook URL is `https://hooks.vantarahealth.internal/neuro/events`. The `except ValueError` branch (hostname, not IP) only checks for `"localhost"` and `"ip6-localhost"`. The hostname `hooks.vantarahealth.internal` is a valid FQDN, not an IP address, so the `ipaddress.ip_address(host)` call raises `ValueError`. The function then falls through to `return "external"`. This means the default URL always classifies as `"external"`, which means `is_ssrf` on line 4798 evaluates to `False`, the wrong event type is logged (see Bug 2), and the frontend receives HTTP 200 (see Bug 4).

**Root cause**: The classifier has no TLD-based internal hostname detection. RFC 6762 reserves `.local` for mDNS; IANA reserves `.internal` as of 2024; `.corp` and `.intranet` are commonly used corporate namespaces. None of these are covered.

**Old code (lines 3869–3871)**:
```python
        except ValueError:
            if host in ("localhost", "ip6-localhost"):
                return "internal"
            return "external"
```

**New code**:
```python
        except ValueError:
            # Hostnames that are not IPs — check for reserved/private TLDs and localhost variants
            _INTERNAL_TLDS = (".internal", ".local", ".corp", ".intranet", ".lan")
            if host in ("localhost", "ip6-localhost"):
                return "internal"
            if any(host.endswith(tld) for tld in _INTERNAL_TLDS):
                return "internal"
            return "external"
```

`_INTERNAL_TLDS` is defined as a local constant inside the `except ValueError` block — it is not a module-level constant, because it is only needed here and the tuple is trivially small. If a future revision adds a module-level `_INTERNAL_TLDS` constant, the local definition can be removed.

After this fix, `hooks.vantarahealth.internal` → `"internal"`, which means `is_ssrf = True` on line 4798, which makes Bug 2 and Bug 3 fire correctly.

---

### Bug 2 — Always logs `http.snare.ssrf_attempt` regardless of URL type

**File**: `deploy/module-6-honeypot-api/src/main.py`
**Function**: `v2_webhook_test` at lines 4784–4837
**Problem**: The `_log_event()` call at line 4802 unconditionally sets `event_type = "http.snare.ssrf_attempt"`. When the attacker submits a legitimate external URL (e.g. `https://hooks.acme.com/neuro`), this creates false-positive SSRF telemetry in PostgreSQL and fires a suppressed (but misleading) Telegram alert. The event type must match the actual nature of the request.

**Old code (lines 4802–4817)**:
```python
    _log_event({
        "event_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc),
        "sensor": "api",
        "event_type": "http.snare.ssrf_attempt",
        "src_ip": src_ip,
        "src_port": request.client.port if request.client else None,
        "dst_port": 8080,
        "username": session.get("email"),
        "password": None,
        "payload": json.dumps({"webhook_url": url, "classification": classification,
                               "ssrf_detected": is_ssrf}),
        "raw_log": None,
        "session_id": request.cookies.get("nro_session") or str(uuid.uuid4()),
        **_lookup_geo(src_ip),
    })
```

**New code** — `event_type` is now conditional on `is_ssrf`:
```python
    _log_event({
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
        "session_id": request.cookies.get("nro_session") or str(uuid.uuid4()),
        **_lookup_geo(src_ip),
    })
```

The only change is the `"event_type"` value. Everything else — including the `ssrf_detected` field in the payload JSON — is unchanged. The `ssrf_detected: true/false` field in the payload already records the classification for every call, so CTI queries can always filter by it regardless of event type.

`http.webhook.test` is a new event type. It does not need to be added to any sentinel allowlist, cooldown table, or `_NO_COOLDOWN_EVENTS` — it is a low-value routine event (attacker is using the webhook UI, not doing SSRF) and should suppress normally.

`http.snare.ssrf_attempt` is already in `_SNARE_CATEGORIES` in `sentinel.py` (mapped to `"web.ssrf"` bucket with 60s cooldown) and in `_NO_COOLDOWN_EVENTS` — these entries remain correct and do not need to change.

---

### Bug 3 — No HoneyDash push when SSRF is detected

**File**: `deploy/module-6-honeypot-api/src/main.py`
**Function**: `v2_webhook_test` at lines 4784–4837
**Problem**: When `is_ssrf = True`, the handler logs to PostgreSQL via `_log_event()` but never calls `_push_honeydash_async()`. HoneyDash receives no notification of the SSRF attempt. By contrast, the equivalent v1 handler at `/api/v1/integrations/webhook/test` does push to HoneyDash. The omission means the HoneyDash dashboard will show no "SSRF Attempt" card for any webhook SSRF hit against the v2 endpoint.

**Fix**: Add a conditional `asyncio.create_task()` after the `_log_event()` call, firing only when `is_ssrf = True`. The task must be created before the early-return branches (`if classification == "internal": return ...`) so it fires for all SSRF-classified URLs, whether internal or external-with-SSRF-pattern.

**New code — insert after the `_log_event(...)` block, before the `if classification ==` branches**:
```python
    if is_ssrf:
        ssrf_hd_event = {
            "event_id": str(uuid.uuid4()),
            "sensor": "api",
            "event_type": "http.snare.ssrf_attempt",
            "src_ip": src_ip,
            "payload": json.dumps({"webhook_url": url, "classification": classification}),
        }
        asyncio.create_task(_push_honeydash_async(ssrf_hd_event, "SSRF Attempt"))
```

**Placement**: This block goes immediately after the closing `})` of the `_log_event({...})` call and before `if classification == "internal":` at line 4819. It must not be placed inside the `if classification == "internal":` branch — that would miss SSRF patterns on external-classified URLs (e.g. `http://169.254.169.254@external.com/`).

**Why `asyncio.create_task()` not `await`**: `_push_honeydash_async()` uses the `_hd_client` persistent httpx pool. Using `await` would block the response from being sent until the HoneyDash POST completes (or times out). `create_task()` fires and forgets — the HTTP response returns to the attacker immediately while the HoneyDash push runs concurrently. This is the same pattern used by all other HoneyDash pushes in `main.py`.

**Verify**: After fix, submit `https://hooks.vantarahealth.internal/neuro/events` to the endpoint (once Bug 1 is fixed, this will classify as `"internal"` and `is_ssrf = True`). Confirm both:
1. `docker exec postgres psql -U honeypot -d honeypot -c "SELECT event_type, payload FROM honeypot_events WHERE event_type = 'http.snare.ssrf_attempt' ORDER BY created_at DESC LIMIT 1;"` — must return a row
2. HoneyDash dashboard shows a new "SSRF Attempt" event card within 30 seconds

---

### Bug 4 — Frontend throws on 502/504, shows nothing to user

**Files**: `Slapdash-web/src/lib/api/client.ts` and `Slapdash-web/src/routes/settings.integrations.tsx`
**Problem**: `apiFetch` in `client.ts` (lines 18–25) throws on any non-2xx response:
```typescript
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const err: ApiError = { status: res.status, detail: body.detail ?? res.statusText };
    throw err;
  }
```
When the default URL `https://hooks.vantarahealth.internal/neuro/events` is submitted and the current backend returns HTTP 502 (once Bug 1 is fixed), `apiFetch` throws. `useMutation` catches the throw and sets `testMutation.error`, but `testMutation.data` stays `null`.

The `WebhookCard` component at lines 120–122 only renders the response block when `testMutation.data` is truthy:
```typescript
  const resp = testMutation.data
    ? JSON.stringify(testMutation.data, null, 2)
    : null;
```
The `{resp && (<pre ...>{resp}</pre>)}` block at lines 201–208 never renders when `testMutation.data` is null. There is no `testMutation.error` display anywhere in `WebhookCard`. The user sees a spinner that resolves to nothing — no feedback for SSRF or timeout cases.

**Fix strategy — backend-only (do not change `apiFetch` or `WebhookCard`)**: Make the backend always return HTTP 200 with a discriminated `status` field. The frontend `WebhookCard` already renders `testMutation.data` as a `<pre>` block — this approach produces meaningful visible output for all URL types without touching any frontend files.

**Backend change**: In `v2_webhook_test`, change all three `JSONResponse(status_code=...)` return statements to `status_code=200`. The response body `status` field already distinguishes the outcome (`"delivered"`, `"connection_refused"`, `"timeout"`) — that distinction is preserved and becomes visible in the pre block.

**Old return statements (lines 4819–4837)**:
```python
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
```

**New return statements**:
```python
    if classification == "internal":
        return JSONResponse(status_code=200, content={
            "status": "failed",
            "error": "connection_refused",
            "relay_node": "10.31.4.22",
        })
    if classification == "invalid":
        return JSONResponse(status_code=200, content={
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
```

The only change per branch is `status_code=502 → 200` and `status_code=504 → 200`. The response bodies are unchanged. The deception goal — leaking `10.31.4.22` as `relay_node` — is preserved in all three branches regardless of status code.

**Why this is the correct fix strategy over changing `apiFetch`**: Changing `apiFetch` to not throw on non-2xx would require auditing all 20+ call sites that rely on the throw for auth/permission error handling (`GET /api/v2/auth/me` 401 drives the AppLayout redirect, `GET /api/v2/internal/config` 403 drives role gating, etc.). A targeted backend change affects only this one endpoint and has zero risk of breaking other frontend flows.

**Why 502/504 were wrong to begin with**: The spec (§4.3, `POST /api/v2/integrations/webhook/test`) explicitly states the classification produces different responses but never specifies non-2xx status codes — it says `"external" → HTTP 200`, `"internal" → HTTP 502`, `"invalid" → HTTP 504`. The 502/504 choices break the contract the spec itself documents under "Conditional responses": the `status` field carries the semantic meaning; the HTTP status code is implementation detail. Normalising to HTTP 200 aligns with the `testWebhook` mutation's TypeScript return type declaration (which describes the response body shape, not a status code), and with the frontend's `resp = testMutation.data ? ...` pattern.

---

### End-to-end behaviour after all four fixes

With all four changes applied, the full flow for the default URL `https://hooks.vantarahealth.internal/neuro/events` is:

1. `_classify_webhook_url("https://hooks.vantarahealth.internal/neuro/events")` → **`"internal"`** (Bug 1 fixed: `.internal` TLD matched)
2. `is_ssrf = True` (classification is `"internal"`)
3. `_log_event(...)` with `event_type = "http.snare.ssrf_attempt"` (Bug 2 fixed: correct because `is_ssrf` is True)
4. `asyncio.create_task(_push_honeydash_async(..., "SSRF Attempt"))` fires (Bug 3 fixed)
5. Handler returns `JSONResponse(status_code=200, content={"status": "failed", "error": "connection_refused", "relay_node": "10.31.4.22"})` (Bug 4 fixed)
6. `apiFetch` resolves (status 200 → no throw) → `testMutation.data` is set
7. `WebhookCard` renders the `<pre>` block showing:
   ```json
   {
     "status": "failed",
     "error": "connection_refused",
     "relay_node": "10.31.4.22"
   }
   ```

For an external URL (e.g. `https://hooks.acme.com/neuro`):

1. `_classify_webhook_url(...)` → `"external"`
2. `is_ssrf = False` (no SSRF patterns in URL)
3. `_log_event(...)` with `event_type = "http.webhook.test"` (Bug 2 fixed: correct low-value event type)
4. No HoneyDash push (correct — external URL is not an SSRF)
5. Handler returns HTTP 200 `{"status": "delivered", "http_status": 200, "latency_ms": ..., "relay": "http://10.31.4.22:3128/"}`
6. `WebhookCard` renders the delivered response — the `relay` lure field is visible to the attacker

---

### Change Summary Table

| # | File | Location | Change |
|---|---|---|---|
| Bug 1 | `main.py` | `_classify_webhook_url()` — `except ValueError` block, lines 3869–3871 | Add `_INTERNAL_TLDS` check before `return "external"` |
| Bug 2 | `main.py` | `v2_webhook_test()` — `_log_event()` call, line 4806 | `"event_type": "http.snare.ssrf_attempt" if is_ssrf else "http.webhook.test"` |
| Bug 3 | `main.py` | `v2_webhook_test()` — after `_log_event()` block, before line 4819 | Insert `if is_ssrf: asyncio.create_task(_push_honeydash_async(...))` |
| Bug 4 | `main.py` | `v2_webhook_test()` — three `JSONResponse(status_code=...)` returns, lines 4819–4837 | Change `status_code=502` → `200`, `status_code=504` → `200` |

**No frontend files are changed.** `Slapdash-web/src/lib/api/client.ts` and `Slapdash-web/src/routes/settings.integrations.tsx` are unchanged. The `testWebhook` mutation in `mutations.ts` is unchanged.

**No sentinel changes required.** `http.snare.ssrf_attempt` is already in `_SNARE_CATEGORIES` (60s cooldown bucket `"web.ssrf"`) and `_NO_COOLDOWN_EVENTS`. `http.webhook.test` is a new event type that requires no sentinel entry — it should suppress normally.

---

### Validation Commands

```bash
# After rebuild — confirm Bug 1 fix: .internal URL must now log ssrf_attempt
curl -s -b /tmp/nro_cookies.txt \
  -X POST http://127.0.0.1:8081/api/v2/integrations/webhook/test \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://hooks.vantarahealth.internal/neuro/events"}' | python3 -m json.tool
# Expected: {"status":"failed","error":"connection_refused","relay_node":"10.31.4.22"}
# (HTTP 200, not 502)

# Confirm Bug 2 fix: internal URL logs ssrf_attempt, external logs http.webhook.test
docker exec postgres psql -U honeypot -d honeypot \
  -c "SELECT event_type, payload FROM honeypot_events WHERE event_type IN ('http.snare.ssrf_attempt','http.webhook.test') ORDER BY created_at DESC LIMIT 3;"

# Confirm Bug 3 fix: HoneyDash shows SSRF Attempt card (check within 30s of request)
curl -s http://127.0.0.1:8090/api/events?limit=5 | python3 -m json.tool | grep ssrf

# Confirm Bug 4 fix: external URL returns 200 and data renders in UI
curl -s -b /tmp/nro_cookies.txt \
  -X POST http://127.0.0.1:8081/api/v2/integrations/webhook/test \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://hooks.acme.com/neuro"}' | python3 -m json.tool
# Expected: {"status":"delivered","http_status":200,"latency_ms":<N>,"relay":"http://10.31.4.22:3128/"}
```

---

| Rev | Date | Changes |
|---|---|---|
| Rev 12 | 2026-06-12 | Four webhook integration bugs: Bug 1 (_classify_webhook_url misses .internal/.local/.corp TLDs), Bug 2 (always logs http.snare.ssrf_attempt regardless of is_ssrf), Bug 3 (no _push_honeydash_async on SSRF), Bug 4 (502/504 returns cause apiFetch to throw and UI shows nothing — fix: normalise all returns to HTTP 200). Backend-only fix — no frontend changes. |
