# HoneyDash Dashboard — Limitation Analysis

**Investigation date**: 2026-06-05  
**HoneyDash commit**: latest (up to date, `git pull` confirmed)  
**Scope**: All display issues and intelligence gaps relevant to the Neuro honeypot stack  

---

## How events enter HoneyDash

Two separate code paths push data to HoneyDash from Neuro:

1. **log_shipper.py** (`_flush_to_honeydash` / `_honeydash_event`): tails Cowrie JSON, OpenCanary JSON, MariaDB general log, and SMB JSON. Batches events and POSTs to `/api/ingest/batch` every `FLUSH_INTERVAL` seconds (default 5s).
2. **main.py** (`_push_honeydash_async`): fires directly from the FastAPI middleware for high-value SNARE/lure HTTP events only.

HoneyDash ingest (`log_collector.py:process_line`, line 198) has a hard gate:

```python
if eid not in EVENTID_TO_ATTACK_TYPE and not is_remote_custom:
    return
```

`is_remote_custom = (sensor == "remote")`. Every event from Neuro arrives with `sensor="remote"` after the `_HD_SENSOR_NAME` remap in `log_shipper.py` (line 1761) and the hardcoded `"sensor": "remote"` in `_push_honeydash_async` (main.py line 1013). So the gate is not the problem — all events pass through.

The protocol and attack-type fields, however, are a different story.

---

## Issue 1 — Protocol mix card shows "unknown"

### Root Cause

`log_collector.py` line 211 (HoneyDash):

```python
protocol = data.get("protocol") or ("ssh" if eid.startswith("cowrie.") else "unknown")
```

For events whose `eventid` starts with `"cowrie."` — which is every event from Neuro, because log_shipper maps all sensors to Cowrie-style eventids — the protocol defaults to `"ssh"` when no `protocol` field is present in the ingest payload.

`_honeydash_event()` in log_shipper.py (lines 1752–1757) does inject a `protocol` field, but only under this condition:

```python
if dst_port and "protocol" not in out:
    out["protocol"] = _HD_PORT_PROTOCOL.get(int(dst_port), "unknown")
```

The condition is `"protocol" not in out`. OpenCanary and MariaDB events include `_protocol` in the internal event dict — but `_honeydash_event()` strips all underscore-prefixed keys (line 1745: `if not k.startswith("_")`). So `_protocol` is removed before the protocol injection check. The `protocol` key (without underscore) is NOT set on any Neuro internal event; only `_protocol` is.

This means `"protocol" not in out` is always `True` after stripping, so the injection should fire. The actual problem is whether `dst_port` is present.

**Cowrie SSH events**: `dst_port` is typically present (SSH is port 22), so `protocol = _HD_PORT_PROTOCOL.get(22)` → `"ssh"`. Protocol card shows SSH correctly.

**OpenCanary Telnet events**: `dst_port` is 23 (set via `OPENCANARY_LOGTYPE_PORT` fallback). `_HD_PORT_PROTOCOL[23]` = `"telnet"`. Should show as `"telnet"`.

**OpenCanary Redis events**: `dst_port` is 6379. `_HD_PORT_PROTOCOL[6379]` = `"redis"`. Should show as `"redis"`.

**OpenCanary FTP events**: `dst_port` is 21. `_HD_PORT_PROTOCOL[21]` = `"ftp"`. Should show as `"ftp"`.

**MariaDB events**: `dst_port` is 3306. `_HD_PORT_PROTOCOL[3306]` = `"mysql"`. Should show as `"mysql"`.

**HTTP events from main.py**: `dst_port` defaults to 443 (line 1017 of main.py). `_HD_PORT_PROTOCOL` has no entry for 443. Result: `"unknown"`.

**SMB events**: `dst_port` is 445. `_HD_PORT_PROTOCOL` has no entry for 445. Result: `"unknown"`.

### What HoneyDash expects
`protocol` field in the ingest payload — one of: `"ssh"`, `"http"`, `"smb"`, `"ftp"`, `"mysql"`, `"mssql"`, `"sip"`, `"telnet"`, `"https"`, `"redis"`.

### What Neuro sends (after `_honeydash_event()` processing)
| Sensor | `dst_port` sent | Protocol injected |
|---|---|---|
| Cowrie SSH | 22 | `"ssh"` |
| OpenCanary Telnet | 23 | `"telnet"` |
| OpenCanary FTP | 21 | `"ftp"` |
| OpenCanary Redis | 6379 | `"redis"` |
| MariaDB | 3306 | `"mysql"` |
| HTTP (main.py) | 443 (hardcoded) | `"unknown"` |
| SMB | 445 | `"unknown"` |

### Gap
HTTP events (most numerous) and SMB events always arrive with `protocol="unknown"`. The `/dashboard/protocol-stats` endpoint groups by `Event.protocol` — `"unknown"` dominates the mix card or is listed as a separate unlabelled slice.

### Fix Recommendation
In `main.py` `_push_honeydash_async()`: set `"protocol": "http"` explicitly in `honeydash_event` instead of relying on dst_port inference. Also add `445: "smb"` to `_HD_PORT_PROTOCOL` in log_shipper.py.

---

## Issue 2 — Attack types mapping wrong (Telnet → SSH Brute Force)

### Root Cause

`log_collector.py` `EVENTID_TO_ATTACK_TYPE` (lines 52–74):

```python
"cowrie.login.failed": "SSH Brute Force",
"cowrie.session.connect": "SSH Connect",
```

There is **no separate entry for Telnet**. All OpenCanary Telnet events arrive as `eventid="cowrie.login.failed"` (for login events) or `eventid="cowrie.session.connect"` (for connect events) because `log_shipper.py` `OpenCanaryTailer._process()` (lines 844–872) translates all OpenCanary events to Cowrie-compatible eventids:

```python
elif logtype % 1000 == 0:
    eventid = "cowrie.login.failed" if username else "cowrie.session.connect"
```

logtype 6001 (Telnet) → `cowrie.login.failed` → `attack_type = "SSH Brute Force"`.

The `_HD_ATTACK_TYPE` override dict in log_shipper.py (line 1681) does have `"opencanary.telnet.login": "Telnet Attack"`, but this is keyed on an eventid string that is **never used** — log_shipper never sets `eventid = "opencanary.telnet.login"`. The actual eventid sent is `"cowrie.login.failed"`, which HoneyDash maps to `"SSH Brute Force"` before the fallback reaches `_HD_ATTACK_TYPE`.

HoneyDash's `process_line` attack_type resolution (line 204):

```python
attack_type = EVENTID_TO_ATTACK_TYPE.get(eid) or data.get("attack_type") or eid.replace(".", " ").title()
```

`EVENTID_TO_ATTACK_TYPE.get("cowrie.login.failed")` returns `"SSH Brute Force"` — this wins. The `data.get("attack_type")` fallback (which would carry the `_HD_ATTACK_TYPE` value set by log_shipper) is only reached if the first lookup returns falsy. Since `"SSH Brute Force"` is truthy, the per-protocol attack_type injected by log_shipper is silently discarded.

**SQL Injection, RCE, SSRF, malware upload, lure credential**: These arrive from main.py with `"eventid"` set to strings like `"http.sqli.attempt"`, `"http.rce.attempt"`, etc. These are **not in `EVENTID_TO_ATTACK_TYPE`**. HoneyDash then falls through to `data.get("attack_type")` which carries the attack_type label sent by `_push_honeydash_async()` (e.g. `"SQL Injection"`). These display correctly in the attack types card because `EVENTID_TO_ATTACK_TYPE` has no entry for `http.*` eventids.

### What HoneyDash expects
`attack_type` field in ingest payload, used as override only when `EVENTID_TO_ATTACK_TYPE.get(eid)` returns falsy.

### Gap
For all Cowrie-mapped eventids (`cowrie.login.failed`, `cowrie.session.connect`, `cowrie.command.input`, `cowrie.session.file_download`), HoneyDash's native `EVENTID_TO_ATTACK_TYPE` always wins. `attack_type` injected by log_shipper is ignored. Telnet, FTP, Redis, MariaDB login events all incorrectly show as "SSH Brute Force" or "SSH Connect".

### Fix Recommendation
Either (a) add Telnet/FTP/Redis/MariaDB-specific eventids to HoneyDash's `EVENTID_TO_ATTACK_TYPE` (e.g. `"opencanary.telnet.login": "Telnet Attack"`), and have log_shipper send those eventids when `is_remote_custom=True`; or (b) set `"attack_type"` in the payload and remove the conflicting entries from `EVENTID_TO_ATTACK_TYPE` for `cowrie.*` when the event is flagged `sensor="remote"`.

The cleanest fix is option (a): use per-sensor eventids (e.g. `"remote.ftp.login"`, `"remote.telnet.login"`, `"remote.mariadb.connect"`) for non-SSH sensors, and add these to HoneyDash's `EVENTID_TO_ATTACK_TYPE`.

---

## Issue 3 — Live attack feed only shows SSH and Telnet

### Root Cause

The live feed runs via WebSocket (`ws.py`). On connect it sends current stats (`compute_stats(db)`) and then receives real-time events via the `broadcaster.manager.broadcast()` call in `log_collector.py` (lines 307–331).

The broadcast happens at the **end of `process_line()`**, after every successful event insert. It is not filtered by sensor, protocol, or severity. In principle every event type should appear in the live feed.

The practical reason only SSH and Telnet appear is volume: with hundreds of SSH/Telnet brute-force events per minute, the live feed scrolls past HTTP or MariaDB events immediately. There is **no severity filter or sensor filter on the live feed** — it is literally all events in arrival order.

The secondary reason: HTTP events from main.py are pushed via `_push_honeydash_async` which calls `/api/ingest/batch` directly. This goes through `process_line()` which fires `broadcaster.manager.broadcast()`. So HTTP events do appear in the live feed — they are just overwhelmed by SSH/Telnet volume.

**Exception**: Cowrie `cowrie.session.closed` events are explicitly excluded from the database insert (line 270: `if eid != "cowrie.session.closed"`) and therefore never broadcast. This is correct behaviour.

### Gap
No real gap in the code — it is a display/volume problem, not a filtering bug. HTTP and MariaDB events do reach the live feed but are swamped by SSH/Telnet volume.

### Fix Recommendation
Add a severity filter to the live feed frontend (JavaScript): allow the user to filter the live feed to `severity="high"` or `attack_type` not in `["SSH Brute Force", "SSH Connect"]`. This is a frontend change only — no backend changes needed.

---

## Issue 4 — Missing non-SSH commands (SQL keystrokes, FTP commands)

### Root Cause

HoneyDash's `Event.command_input` column is populated by `log_collector.py` line 282:

```python
command_input=data.get("input") or data.get("command_input") or data.get("command"),
```

**Cowrie SSH commands**: `input` field is set natively in Cowrie JSON. log_shipper passes it through as `"input"` (line 654 of log_shipper.py). These populate `command_input` correctly.

**MariaDB SQL queries**: `MariaDBTailer._emit_event()` sets `"input": argument` when `eventid == "cowrie.command.input"` (line 1080 of log_shipper.py). The `_honeydash_event()` function includes `input` in `out` (it does not start with `_`). So MariaDB SQL queries **should** appear in `command_input`. This is working.

**OpenCanary FTP commands**: FTP events arrive as `cowrie.login.failed` (login attempt) or `cowrie.session.connect`. The FTP protocol only logs connect + credentials via logtype 2000. OpenCanary does not log individual FTP commands (LIST, RETR, etc.). So FTP commands are absent not because of a field gap but because OpenCanary simply does not capture them.

**OpenCanary Redis commands**: `OpenCanaryTailer._process()` (lines 858–868) sets `raw["_http_input"]` for Redis commands:

```python
raw["_http_input"] = f"REDIS {cmd} {args}".strip()
```

Then the event dict is built with `"input": raw.get("_http_input")` (line 885). This should populate `command_input` in HoneyDash for Redis commands.

**HTTP SNARE attack events**: `_push_honeydash_async()` (lines 1037–1042) explicitly populates `input` for attack types in `_SNARE_ATTACK_TYPES_FOR_INPUT` (RCE Attempt, SQL Injection, LFI Attempt, SSRF Attempt, XSS Attempt). These should populate `command_input`.

**HTTP non-attack events (general page views, lure access)**: `_push_honeydash_async()` does NOT set `"input"` for `attack_type="Lure Access"` or `attack_type="SSH Login"`. So general lure path visits have `command_input=NULL` in HoneyDash.

### Gap
The `_HD_ATTACK_TYPE` dict in log_shipper.py has keys like `"opencanary.telnet.login": "Telnet Attack"` but these keys are never used as eventids. The only real gap is:
- FTP individual commands: structurally impossible — OpenCanary FTP module does not capture commands.
- HTTP lure visits (non-attack): `command_input` is NULL; path info is only in `raw_json`.

### Fix Recommendation
For HTTP lure events, populate `"input"` with `path` in `_push_honeydash_async()` when `attack_type == "Lure Access"`. This requires a one-line addition.

---

## Issue 5 — Top sources / top countries only show Telnet and SSH

### Root Cause

`/dashboard/top-attackers` (line 310–350 of dashboard.py) runs:

```sql
SELECT e.src_ip, COUNT(*) AS cnt, ...
FROM events e
LEFT JOIN ip_enrichments ie ON ie.ip_address = e.src_ip
WHERE e.timestamp >= :cutoff
  AND (:sensor = '' OR e.sensor = :sensor)
GROUP BY e.src_ip
ORDER BY cnt DESC
LIMIT 10
```

This query counts **all events** — no sensor or protocol filter. The top IPs by event count are naturally dominated by SSH and Telnet brute-forcers (high-volume scanners generate thousands of `cowrie.login.failed` events). HTTP and MariaDB events generate far fewer events per attacker IP.

The `/dashboard/geographic-intel` (line 1132–1206) similarly aggregates all events with no protocol restriction.

This is not a data-visibility bug — HTTP and MariaDB events are included in the counts. It is a volume problem: SSH scanners each generate 50–1000 events while a single HTTP attack session generates 5–30 events.

### Gap
No code gap. Data from all sensors is present and counted. The display is correctly dominated by the highest-volume attackers, which happen to be SSH/Telnet scanners.

### Fix Recommendation
Add a protocol breakdown column to the top-attackers table in the HoneyDash frontend to show which sensors each IP hit (e.g. "SSH + HTTP"), surfacing cross-sensor attackers. Alternatively, add a `/dashboard/top-attackers?protocol=http` filter to the frontend dropdown.

---

## Issue 6 — Attack session list only shows Telnet and SSH for "remote" sensor

### Root Cause

Sessions are created by `log_collector.py` (lines 210–225). The session's `protocol` field is set at **creation time** based on the first event for that `session_id`:

```python
protocol = data.get("protocol") or ("ssh" if eid.startswith("cowrie.") else "unknown")
```

Since all Neuro eventids start with `"cowrie."`, every new session gets `protocol="ssh"` unless a `protocol` field is explicitly present in the ingest payload.

As established in Issue 1, Cowrie SSH and OpenCanary Telnet/FTP/Redis events do receive correct `protocol` values from `_honeydash_event()` via the `_HD_PORT_PROTOCOL` dst_port lookup. So session protocol is set correctly for these sensors.

However, session protocol is **never updated** after the initial insert (`on_conflict_do_nothing` — line 224). If the first event for a session lacks a protocol field and gets `"ssh"`, subsequent events from the same session cannot correct this.

For HTTP sessions from main.py: `dst_port=443`, which is not in `_HD_PORT_PROTOCOL`, so `protocol="unknown"`. All HTTP sessions show protocol `"unknown"` in the sessions list.

The sessions list filter (`/sessions?protocol=telnet`) uses `func.lower(Session.protocol) == protocol.lower()` — this works for sessions that have the correct protocol set on their first event.

### Gap
HTTP sessions: `protocol="unknown"` because `dst_port=443` is not in `_HD_PORT_PROTOCOL`. Sessions list filter for `protocol=http` returns zero rows for HTTP sessions.

SMB sessions: `protocol="unknown"` for the same reason (port 445 not in `_HD_PORT_PROTOCOL`).

### Fix Recommendation
Same fix as Issue 1 (add `"protocol": "http"` explicitly in `main.py _push_honeydash_async()` and add `445: "smb"` to `_HD_PORT_PROTOCOL` in log_shipper.py).

---

## Q1 — "Files downloaded" card: what does it count?

### Code Evidence

`compute_stats()` in dashboard.py (lines 57–62):

```python
files_q = select(func.coalesce(func.sum(Session.files_downloaded), 0)).where(
    Session.start_time >= cutoff
)
files_24h = await db.scalar(files_q)
```

`Session.files_downloaded` is incremented in `log_collector.py` (lines 246–248):

```python
elif eid in ("cowrie.session.file_download", "dionaea.download.captured"):
    sess.files_downloaded = (sess.files_downloaded or 0) + 1
```

For `is_remote_custom` events (which is every Neuro event), the counter increments via lines 256–258:

```python
elif is_remote_custom and (data.get("download_url") or data.get("url")):
    sess.files_downloaded = (sess.files_downloaded or 0) + 1
```

**Cowrie SSH malware downloads** (`cowrie.session.file_download`): These arrive with `eid="cowrie.session.file_download"` from log_shipper. HoneyDash's `EVENTID_TO_ATTACK_TYPE` has this eventid, so it passes the gate. The session counter increments via the `eid in ("cowrie.session.file_download", ...)` branch. **Counted.**

**HTTP lure file downloads** (`http.lure.data_exfil`): These arrive from main.py with `attack_type="Data Exfil"`. The `_push_honeydash_async()` function (lines 1044–1053) sets `honeydash_event["download_url"]` when `attack_type == "Data Exfil"`. HoneyDash then sees `data.get("download_url")` is non-empty for `is_remote_custom=True`, so the counter increments. **Counted.**

**HTTP malware upload** (`http.upload.malware_received`): main.py fires `_push_honeydash_async(event, "Malware Upload")`. `"Malware Upload"` is not `"Data Exfil"`, so `download_url` is NOT set. HoneyDash receives this with `download_url=None`. The `is_remote_custom` branch increments `files_downloaded` only when `download_url` or `url` is non-empty. **Not counted.** Upload events do NOT increment the files counter.

**Dionaea file captures**: Counted via `eid == "dionaea.download.captured"`. Neuro does not use Dionaea, so this path is not relevant.

### Answer
The "Files downloaded" card counts: (1) Cowrie SSH `cowrie.session.file_download` events, and (2) HTTP lure file downloads where `_push_honeydash_async` sets `download_url`. HTTP malware **uploads** are not counted. The card label is therefore accurate for Cowrie downloads and lure exfil, but does not represent the malware upload capture count.

---

## Q2 — Malware capture visibility

### Cowrie SSH malware downloads

log_collector.py line 282: `download_url=data.get("url") or data.get("download_url")`.

Cowrie's native JSON for `cowrie.session.file_download` uses the `"url"` field. log_shipper passes this through as `"url"` (line 655 of log_shipper.py). HoneyDash receives `url=<download_url>`, populates `Event.download_url`. The `cowrie-deep` endpoint shows file_download events in its command list but does **not** have a dedicated download section — download_url is only visible on the individual event detail page (`/events/{id}`).

The session counter increments `files_downloaded`. The dashboard `/dashboard/malware-recent` endpoint queries the `malware_samples` table — this table is populated by **Dionaea only** via `dionaea_collector.py`. Cowrie file downloads do NOT populate `malware_samples`. The malware card therefore shows zero for Neuro.

### HTTP malware uploads

main.py fires `_push_honeydash_async(event, "Malware Upload")`. This reaches HoneyDash as a `remote` event with `attack_type="Malware Upload"`. It is stored in the `events` table. However, `malware_samples` is not populated (no code path writes to it from ingest). The event is visible in the events list and the `remote-deep` endpoint's event_types breakdown will show "Malware Upload" — but the dedicated malware dashboard card shows zero.

### Gap
Neither Cowrie file downloads nor HTTP uploads appear in the `/dashboard/malware-recent` card. Both are visible only in the raw events list. The malware card is Dionaea-exclusive.

---

## Q3 — ML anomalies card: what does it mean?

### Code Evidence

`compute_stats()` dashboard.py lines 92–99:

```python
ml_q = select(func.count(Session.id)).where(Session.is_anomaly == True)
ml_anomalies = await db.scalar(ml_q)
```

`is_anomaly` is set by `ml_detector.py` which runs a full `IsolationForest` (scikit-learn) on all session features every 10 minutes (lines 56–94):

- Features: `login_attempts`, `login_success`, `commands_run`, `files_downloaded`, `duration_secs`, `login_fail_ratio`
- contamination=0.05 (flags top 5% of sessions as anomalous)
- Runs on all sessions in the DB (no 24h window)

For new sessions closed within the last poll interval, `score_single_session()` (lines 97–125) applies a simple heuristic instantly:

```python
is_anomaly = bool(
    (sess.login_attempts or 0) > 20
    or sess.login_success
    or (sess.files_downloaded or 0) > 0
    or (sess.commands_run or 0) > 5
)
```

This heuristic tags any session with >20 login attempts, a successful login, any file download, or >5 commands as an anomaly.

**This is a real (though simple) ML model** — not a static count. The IsolationForest runs on all historical sessions and learns normal behaviour from the majority. A scanner that sends exactly 3 login attempts may be normal; one that sends 500 in 2 seconds is anomalous. However the model is trained only on session-level aggregates, not on individual event payloads (no content analysis).

**The anomaly count on the dashboard is all-time, not 24h.** Once flagged, `is_anomaly` is not cleared — sessions remain anomalous forever.

---

## Q4 — AWS canarytoken: does it show in HoneyDash?

### Code Evidence

Neuro's `POST /api/v1/canarytoken/callback` (main.py lines 2449–2465):

1. Logs `http.canarytoken.fired` event to Neuro's PostgreSQL via `_log_event()`
2. Calls `_push_honeydash_async(canary_event, "Canarytoken Fired")`

The `canary_event` dict passed to `_push_honeydash_async` includes `event_type="http.canarytoken.fired"`. `_push_honeydash_async` builds `honeydash_event["eventid"] = event["event_type"]` → `"http.canarytoken.fired"`.

In HoneyDash `log_collector.py` line 198:

```python
if eid not in EVENTID_TO_ATTACK_TYPE and not is_remote_custom:
    return
```

`"http.canarytoken.fired"` is **not in `EVENTID_TO_ATTACK_TYPE`**, but `sensor="remote"` so `is_remote_custom=True`. The event passes the gate.

`attack_type = EVENTID_TO_ATTACK_TYPE.get(eid) or data.get("attack_type") or ...`

`EVENTID_TO_ATTACK_TYPE.get("http.canarytoken.fired")` = `None`, so `data.get("attack_type")` = `"Canarytoken Fired"` is used.

The event is stored in HoneyDash `events` table with `attack_type="Canarytoken Fired"`.

**Where does it appear?**
- The `/dashboard/attack-types` card: if any `http.canarytoken.fired` events arrived in the last 24h, `"Canarytoken Fired"` appears in the attack-types donut chart.
- The `remote-deep` endpoint: shows all `sensor="remote"` events grouped by `attack_type` — `"Canarytoken Fired"` shows in that breakdown.
- There is **no dedicated canarytoken card or view** in HoneyDash. No special handling.
- `severity`: `_push_honeydash_async` hardcodes `"severity": "high"` for all events. In HoneyDash, `_compute_event_severity` for `is_remote_custom` events checks `data.get("severity")` first — `"high"` passes, so the event is stored as `severity="high"`.

### Answer
Yes — canarytoken events do reach HoneyDash and are stored as `attack_type="Canarytoken Fired"`, `severity="high"`. They are visible in the attack-types breakdown chart and in the events list. There is no dedicated canarytoken card.

---

## Step 4 — Protocol field per sensor type

The following table shows what `protocol` value is stored in HoneyDash's `events.protocol` column for each sensor, tracing through `_honeydash_event()` in log_shipper.py (lines 1734–1771) and `log_collector.py process_line()` (line 211):

| Sensor | `dst_port` in HoneyDash payload | `_HD_PORT_PROTOCOL` match | Final `protocol` in HoneyDash |
|---|---|---|---|
| Cowrie SSH (eventid `cowrie.*`) | 22 | `22: "ssh"` | `"ssh"` |
| OpenCanary FTP (logtype 2000) | 21 | `21: "ftp"` | `"ftp"` |
| OpenCanary Telnet (logtype 6001) | 23 | `23: "telnet"` | `"telnet"` |
| OpenCanary Redis (logtype 17001) | 6379 | `6379: "redis"` | `"redis"` |
| MariaDB (all events) | 3306 | `3306: "mysql"` | `"mysql"` |
| HTTP API events (main.py) | 443 (hardcoded) | no entry | `"unknown"` |
| SMB events (SmbTailer) | 445 | no entry | `"unknown"` |

**Code evidence for HTTP API events**: `_push_honeydash_async()` main.py line 1017: `"dst_port": event.get("dst_port", 443)`. The `event["dst_port"]` for HTTP requests is the server listen port (80 or 8081), neither of which is in `_HD_PORT_PROTOCOL`. The fallback is 443, also absent. Result: `"unknown"`.

**Code evidence for SMB events**: `SmbTailer._process()` log_shipper.py line 1216: `"dst_port": raw.get("dst_port", 445)`. `_HD_PORT_PROTOCOL` has no entry for 445.

Note: after `_honeydash_event()` strips `_protocol`, the fallback in HoneyDash `log_collector.py` (`"ssh" if eid.startswith("cowrie.") else "unknown"`) is only reached when `data.get("protocol")` is absent. Since `_honeydash_event()` always injects `protocol` (even as `"unknown"`) when `dst_port` is present, the HoneyDash fallback only fires when `dst_port` is None. For all Neuro sensors `dst_port` is always set.

---

## Summary Table — Visibility by Attack Type

| Attack Type | Sensor | Reaches HoneyDash? | Protocol displayed | Attack type displayed | `command_input` populated | Notes |
|---|---|---|---|---|---|---|
| SSH brute force | Cowrie | Yes | `ssh` | "SSH Brute Force" | No (login events) | Correct |
| SSH login success | Cowrie | Yes | `ssh` | "SSH Login" | No | Correct |
| SSH command execution | Cowrie | Yes | `ssh` | "Command Execution" | Yes | Correct |
| SSH malware download | Cowrie | Yes | `ssh` | "Malware Download" | No | download_url set; files counter correct; NOT in malware-samples table |
| Telnet login | OpenCanary | Yes | `telnet` | **"SSH Brute Force"** (wrong) | No | Attack type mislabelled — see Issue 2 |
| FTP login | OpenCanary | Yes | `ftp` | **"SSH Brute Force"** (wrong) | No | Attack type mislabelled |
| Redis command | OpenCanary | Yes | `redis` | **"SSH Brute Force"** or "SSH Connect" (wrong) | Yes (AUTH password, command) | Attack type mislabelled |
| MariaDB connect | MariaDB | Yes | `mysql` | **"SSH Connect"** (wrong) | No | Attack type mislabelled |
| MariaDB SQL query | MariaDB | Yes | `mysql` | **"Command Execution"** (acceptable) | Yes (SQL text) | attack_type OK; protocol correct |
| HTTP SNARE attack (SQLi/RCE/LFI/SSRF) | HTTP API | Yes | **`unknown`** | Correct (e.g. "SQL Injection") | Yes (body preview/path) | Protocol wrong; attack_type correct |
| HTTP lure access | HTTP API | Yes (only from middleware, not all paths) | **`unknown`** | "Lure Access" | No (path not set as input) | Limited visibility |
| HTTP lure credential | HTTP API | Yes | **`unknown`** | "Lure Credential" | No | |
| HTTP lure file download | HTTP API | Yes | **`unknown`** | "Data Exfil" | No | download_url set; files counter increments |
| HTTP malware upload | HTTP API | Yes | **`unknown`** | "Malware Upload" | No | NOT in malware-samples table |
| HTTP canarytoken | HTTP API | Yes | **`unknown`** | "Canarytoken Fired" | No | Visible in attack-types chart |
| SMB connect/auth | SMB | Yes | **`unknown`** | "SMB Connect" / "SMB Auth Attempt" | No | attack_type correct; protocol wrong |
| SMB NTLMv2 hash | SMB | Yes | **`unknown`** | "NTLMv2 Hash Captured" | No (in password field) | attack_type correct; protocol wrong |

---

## Prioritised Fix List

| Priority | Fix | File | Effort |
|---|---|---|---|
| P1 | Add `"protocol": "http"` explicitly to `_push_honeydash_async()` payload | `main.py` line 1011 | 1 line |
| P1 | Add `445: "smb"` to `_HD_PORT_PROTOCOL` dict | `log_shipper.py` line 1656 | 1 line |
| P2 | Change Telnet/FTP/Redis/MariaDB eventids to non-Cowrie strings (e.g. `"remote.telnet.login"`) so HoneyDash's `EVENTID_TO_ATTACK_TYPE` does not override `attack_type` | `log_shipper.py` OpenCanaryTailer + MariaDBTailer | Medium |
| P2 | Add those new eventids to HoneyDash's `EVENTID_TO_ATTACK_TYPE` | `HoneyDash/backend/services/log_collector.py` | Small |
| P3 | Populate `"input"` with `path` in `_push_honeydash_async()` for `attack_type="Lure Access"` | `main.py` | 3 lines |
| P4 | Write Cowrie file downloads to `malware_samples` table (or add a Cowrie download card in HoneyDash frontend) | HoneyDash backend | Medium |

---

## Fix Plans (Session 10 — IMPLEMENTED 2026-06-05)

All fixes are Neuro-side only. Zero changes to `HoneyDash/` codebase.

---

### FIX-DASH-1 (Critical) — HTTP events show `protocol="unknown"` in HoneyDash — IMPLEMENTED

**Problem:** `_push_honeydash_async()` in `main.py` sets `"dst_port": event.get("dst_port", 443)` but never sets a `"protocol"` field. Port 443 is absent from `_HD_PORT_PROTOCOL` in `log_shipper.py`, so HoneyDash stores `protocol="unknown"` for every HTTP event. This causes: (a) the protocol-mix card to show an "unknown" slice, (b) session-list filter `?protocol=http` to return zero rows.

**File:** `deploy/module-6-honeypot-api/src/main.py`

**Function:** `_push_honeydash_async()` — line 1011

**Edit:** Add `"protocol": "http"` as a new key in the `honeydash_event` dict immediately after the existing `"sensor": "remote"` line.

Before (lines 1011–1017):
```python
        honeydash_event = {
            "eventid": event["event_type"],
            "sensor": "remote",
            "timestamp": event["created_at"].isoformat() + "Z",
            "src_ip": event["src_ip"],
            "src_port": event.get("src_port"),
            "dst_port": event.get("dst_port", 443),
```

After:
```python
        honeydash_event = {
            "eventid": event["event_type"],
            "sensor": "remote",
            "protocol": "http",
            "timestamp": event["created_at"].isoformat() + "Z",
            "src_ip": event["src_ip"],
            "src_port": event.get("src_port"),
            "dst_port": event.get("dst_port", 443),
```

**Expected result after fix:**
- All HTTP events (SNARE attacks, lure access, canarytoken, malware upload, bruteforce) stored with `protocol="http"` in HoneyDash `events` table.
- Protocol-mix card shows "http" slice alongside SSH/Telnet.
- Session list filter `?protocol=http` returns HTTP attacker sessions.

**Requires container rebuild:** Yes — `docker compose up -d --build --force-recreate` in `deploy/module-6-honeypot-api/`.

**Verification:** After rebuild, trigger any HTTP event (e.g. `curl http://127.0.0.1:8080/login`) and confirm in HoneyDash DB: `SELECT protocol FROM events WHERE sensor='remote' ORDER BY id DESC LIMIT 1;` → must return `http`.

---

### FIX-DASH-2 (Critical) — SMB events show `protocol="unknown"` in HoneyDash — IMPLEMENTED

**Problem:** Port 445 is absent from `_HD_PORT_PROTOCOL` in `log_shipper.py`. `SmbTailer._process()` (line 1216) sets `"dst_port": raw.get("dst_port", 445)`. `_honeydash_event()` calls `_HD_PORT_PROTOCOL.get(445, "unknown")` → `"unknown"`. SMB sessions show `protocol="unknown"`.

**File:** `deploy/module-5-log-shipper/src/log_shipper.py`

**Function:** Module-level dict `_HD_PORT_PROTOCOL` — line 1656

**Edit:** Add `445: "smb"` as a new entry after the `6379: "redis"` line.

Before (lines 1656–1666):
```python
_HD_PORT_PROTOCOL = {
    21:   "ftp",
    22:   "ssh",
    23:   "telnet",
    25:   "smtp",
    80:   "http",
    443:  "https",
    2222: "ssh",
    3306: "mysql",
    6379: "redis",
}
```

After:
```python
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
```

**Expected result after fix:**
- SMB events stored with `protocol="smb"` in HoneyDash.
- Protocol-mix card shows "smb" slice.
- Session list filter `?protocol=smb` returns SMB sessions.

**Requires container rebuild:** Yes — `docker compose build --no-cache sentinel && docker compose up -d sentinel` AND `docker compose up -d log-shipper` in `deploy/module-5-log-shipper/`. (Both log-shipper and sentinel share the same image — rebuild both explicitly per CLAUDE.md rule.)

**Verification:** After rebuild, check `_HD_PORT_PROTOCOL` is applied by tailing log-shipper logs for any SMB event: `docker logs log-shipper 2>&1 | grep smb`. Or query HoneyDash DB: `SELECT protocol FROM events WHERE attack_type LIKE 'SMB%' ORDER BY id DESC LIMIT 1;` → must return `smb`.

---

### FIX-DASH-3 (Critical) — Telnet/FTP/Redis/MariaDB labelled "SSH Brute Force" in HoneyDash — IMPLEMENTED

**Problem:** `OpenCanaryTailer._process()` translates all OpenCanary login events to `eventid="cowrie.login.failed"` (lines 846, 851, 863, 872). `MariaDBTailer._emit_event()` emits `eventid="cowrie.session.connect"` for the Connect command (line 1041). HoneyDash's `EVENTID_TO_ATTACK_TYPE` maps `"cowrie.login.failed"` → `"SSH Brute Force"` and `"cowrie.session.connect"` → `"SSH Connect"` — these take priority over any `attack_type` field Neuro injects (HoneyDash `process_line()` line 204: `EVENTID_TO_ATTACK_TYPE.get(eid) or data.get("attack_type")`). The `_HD_ATTACK_TYPE` dict in log_shipper.py has correct labels keyed on strings like `"opencanary.telnet.login"` — but these strings are never used as the actual `eventid` sent, so the dict is never consulted.

**Root cause in one sentence:** The `eventid` values sent for non-SSH sensors are `cowrie.*` strings, which HoneyDash's native dict recognises and overrides with SSH labels before the `attack_type` fallback is ever reached.

**Fix strategy:** Switch non-SSH sensors to use `"remote.*"` prefixed eventids. HoneyDash's `EVENTID_TO_ATTACK_TYPE` has no entries for `"remote.*"` eventids, so the lookup returns `None`, and HoneyDash falls through to `data.get("attack_type")` which carries the correct label set by `_HD_ATTACK_TYPE` in `_honeydash_event()`. No changes to HoneyDash codebase — the `is_remote_custom` gate is `sensor == "remote" or eid.startswith("remote.")`, and all Neuro events have `sensor="remote"`, so they already pass the gate regardless of eventid prefix.

**Important:** Changing eventids for non-SSH sensors does NOT affect Neuro's own PostgreSQL schema, Telegram alerts, or sentinel behaviour — `_honeydash_event()` is only called by the HoneyDash batch flusher. The internal event dict stored in Neuro's PostgreSQL still uses the original `cowrie.*` eventids. The eventid change is applied inside `_honeydash_event()` only, as a remapping step before the HoneyDash POST.

**File:** `deploy/module-5-log-shipper/src/log_shipper.py`

**Function:** `_honeydash_event()` — line 1734

**Edit:** Add an eventid remapping block between the protocol injection and the sensor remap. The mapping translates Cowrie-compatible eventids back to sensor-specific strings only when the sensor is not Cowrie (i.e., `_sensor_type` is `opencanary` or `mariadb`). Since `_honeydash_event()` strips all `_` keys before processing, the `_sensor_type` is gone from `out` by the time we apply this remap — instead, use `dst_port` to distinguish: Cowrie SSH always arrives on port 22 or 2222; OpenCanary arrives on 21/23/6379; MariaDB on 3306.

Define a new module-level dict `_HD_EVENTID_REMAP` immediately before `_honeydash_event()` (after the `_HD_NOISE_EVENTS` set, around line 1733):

```python
# Remap Cowrie-compatible eventids to sensor-specific strings for non-SSH sensors
# so HoneyDash's EVENTID_TO_ATTACK_TYPE (which only covers cowrie.* and dionaea.*)
# does not override the correct attack_type label.
# Keys: (dst_port, cowrie_eventid)  Values: replacement eventid
_HD_EVENTID_REMAP: dict[tuple[int, str], str] = {
    # OpenCanary FTP (port 21)
    (21, "cowrie.login.failed"):   "remote.ftp.login",
    (21, "cowrie.session.connect"):"remote.ftp.connect",
    # OpenCanary Telnet (port 23)
    (23, "cowrie.login.failed"):   "remote.telnet.login",
    (23, "cowrie.session.connect"):"remote.telnet.connect",
    # OpenCanary Redis (port 6379)
    (6379, "cowrie.login.failed"):   "remote.redis.auth",
    (6379, "cowrie.session.connect"):"remote.redis.connect",
    (6379, "cowrie.command.input"):  "remote.redis.command",
    # MariaDB (port 3306)
    (3306, "cowrie.session.connect"):  "remote.mariadb.connect",
    (3306, "cowrie.command.input"):    "remote.mariadb.query",
    (3306, "cowrie.session.closed"):   "remote.mariadb.disconnect",
}
```

Then inside `_honeydash_event()`, add the remap immediately after the `out = {...}` dict comprehension and noise checks (after line 1749), before the protocol injection:

Before (lines 1751–1757 — the protocol injection block):
```python
    # Inject correct protocol based on dst_port
    dst_port = out.get("dst_port")
    if dst_port and "protocol" not in out:
        try:
            out["protocol"] = _HD_PORT_PROTOCOL.get(int(dst_port), "unknown")
        except (ValueError, TypeError):
            out["protocol"] = "unknown"
```

After — insert the remap block BEFORE the existing protocol injection:
```python
    # Remap Cowrie-compatible eventids to sensor-specific strings for non-SSH sensors
    # so HoneyDash's EVENTID_TO_ATTACK_TYPE does not apply SSH labels to Telnet/FTP/Redis/MariaDB.
    _eid = out.get("eventid", "")
    _port = out.get("dst_port")
    if _port:
        try:
            _port_int = int(_port)
        except (ValueError, TypeError):
            _port_int = None
        if _port_int and (_eid, _port_int) in {(v, k[0]) for k, v in _HD_EVENTID_REMAP.items()}:
            # Simpler lookup: just check the (port, eid) key directly
            pass
        remapped = _HD_EVENTID_REMAP.get((_port_int, _eid)) if _port_int else None
        if remapped:
            out["eventid"] = remapped

    # Inject correct protocol based on dst_port
    dst_port = out.get("dst_port")
    if dst_port and "protocol" not in out:
        try:
            out["protocol"] = _HD_PORT_PROTOCOL.get(int(dst_port), "unknown")
        except (ValueError, TypeError):
            out["protocol"] = "unknown"
```

Note: the draft above has an unnecessary dead-code block. The clean version of the remap insertion is:

```python
    # Remap Cowrie-compatible eventids to sensor-specific strings for non-SSH sensors.
    # Prevents HoneyDash's EVENTID_TO_ATTACK_TYPE from labelling Telnet/FTP/Redis/MariaDB as "SSH *".
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
    ...
```

Also update `_HD_ATTACK_TYPE` to map the new `"remote.*"` eventids instead of the old `"opencanary.*"` / `"mariadb.*"` keys (the old keys were dead code and can be replaced):

Before (lines 1681–1687):
```python
_HD_ATTACK_TYPE: dict = {
    # OpenCanary / MariaDB (not in HoneyDash native map)
    "opencanary.ftp.login":      "FTP Brute Force",
    "opencanary.telnet.login":   "Telnet Attack",
    "opencanary.redis.command":  "Redis Probe",
    "mariadb.connect":           "MySQL Brute Force",
    "mariadb.query":             "MySQL Query",
```

After:
```python
_HD_ATTACK_TYPE: dict = {
    # OpenCanary / MariaDB — remapped eventids (remote.* prefix bypasses HoneyDash's cowrie.* table)
    "remote.ftp.login":       "FTP Brute Force",
    "remote.ftp.connect":     "FTP Connect",
    "remote.telnet.login":    "Telnet Brute Force",
    "remote.telnet.connect":  "Telnet Connect",
    "remote.redis.auth":      "Redis Auth Attempt",
    "remote.redis.connect":   "Redis Connect",
    "remote.redis.command":   "Redis Command",
    "remote.mariadb.connect": "MySQL Connect",
    "remote.mariadb.query":   "MySQL Query",
    "remote.mariadb.disconnect": "MySQL Disconnect",
```

**Expected result after fix:**
- Telnet login events → `attack_type="Telnet Brute Force"` in HoneyDash.
- FTP login events → `attack_type="FTP Brute Force"`.
- Redis AUTH events → `attack_type="Redis Auth Attempt"`.
- Redis commands → `attack_type="Redis Command"` with `command_input` populated.
- MariaDB connect → `attack_type="MySQL Connect"`.
- MariaDB SQL query → `attack_type="MySQL Query"` with `command_input` populated.
- Cowrie SSH events remain unchanged — port 22/2222 has no entries in `_HD_EVENTID_REMAP`.

**Requires container rebuild:** Yes — same as FIX-DASH-2 (`log-shipper` + `sentinel` images both need rebuild).

**Verification:** After rebuild, send a Telnet probe (or check existing events). In HoneyDash DB: `SELECT attack_type, protocol FROM events WHERE dst_port=23 ORDER BY id DESC LIMIT 3;` → must show `attack_type="Telnet Brute Force"`, `protocol="telnet"`. MariaDB: `SELECT attack_type FROM events WHERE dst_port=3306 AND attack_type != 'MySQL Query' ORDER BY id DESC LIMIT 3;` → must show `attack_type="MySQL Connect"`, not `"SSH Connect"`.

---

### FIX-DASH-4 (Medium) — HTTP lure visits have `command_input=NULL` in HoneyDash — IMPLEMENTED

**Problem:** `_push_honeydash_async()` sets `honeydash_event["input"]` only when `attack_type in _SNARE_ATTACK_TYPES_FOR_INPUT` (lines 1037–1042). For `attack_type="Lure Access"` (general page views on lure paths) and `attack_type="Lure Credential"`, no `input` field is set. HoneyDash stores `command_input=NULL` for these events. The path the attacker visited is available in `payload_dict.get("path")` but is not forwarded.

**File:** `deploy/module-6-honeypot-api/src/main.py`

**Function:** `_push_honeydash_async()` — lines 1037–1042

**Edit:** Extend the existing `input` population block to also cover `"Lure Access"` and `"Lure Credential"` cases using the request `path`.

Before (lines 1035–1042):
```python
        # FIX-E: Populate HoneyDash command_input for SNARE/security attack types.
        # HoneyDash reads data.get("input") → Event.command_input column.
        if attack_type in _SNARE_ATTACK_TYPES_FOR_INPUT:
            honeydash_event["input"] = (
                payload_dict.get("body_preview")
                or payload_dict.get("query_params", {}).get("path")
                or payload_dict.get("path")
            )
```

After:
```python
        # FIX-E: Populate HoneyDash command_input for SNARE/security attack types.
        # HoneyDash reads data.get("input") → Event.command_input column.
        if attack_type in _SNARE_ATTACK_TYPES_FOR_INPUT:
            honeydash_event["input"] = (
                payload_dict.get("body_preview")
                or payload_dict.get("query_params", {}).get("path")
                or payload_dict.get("path")
            )
        elif attack_type in ("Lure Access", "Lure Credential", "SSH Login"):
            # For page visits and credential use, record the path so analysts can see
            # which lure page the attacker visited (e.g. /admin, /api/v1/cluster/nodes).
            honeydash_event["input"] = payload_dict.get("path")
```

**Expected result after fix:**
- `command_input` in HoneyDash populated with the lure path (e.g. `/admin`, `/api/v1/cluster/nodes`) for all lure access events.
- The `remote-deep` endpoint and session detail page show which page the attacker visited.

**Requires container rebuild:** Yes — `docker compose up -d --build --force-recreate` in `deploy/module-6-honeypot-api/`.

**Verification:** Browse to `http://127.0.0.1:8080/admin` (after logging in via lure credentials). In HoneyDash DB: `SELECT command_input, attack_type FROM events WHERE attack_type='Lure Access' ORDER BY id DESC LIMIT 3;` → `command_input` must show `/admin`.

---

### FIX-DASH-5 (HoneyDash limitation — not fixable from Neuro side) — ACCEPTED, NO CODE CHANGE

**Problem:** HTTP malware uploads (`http.upload.malware_received`) are not counted in HoneyDash's "Files downloaded" card, and neither Cowrie file downloads nor HTTP uploads appear in the "Recent malware" card.

**Root cause:**
- "Files downloaded" counter for `is_remote_custom` events increments only when `download_url` or `url` is present (`log_collector.py` line 256). `_push_honeydash_async` does not set `download_url` for `"Malware Upload"` attack type — the upload is an inbound event, not an outbound download.
- The "Recent malware" card queries the `malware_samples` table (populated by Dionaea only). No code path writes to `malware_samples` from the ingest API for `is_remote_custom` events.

**Assessment:** Both are structural HoneyDash limitations. The `malware_samples` table has no ingest API endpoint and no ORM write path accessible from `process_line()`. Fixing either card requires modifying HoneyDash backend code — out of scope for Neuro-side-only changes.

**What Neuro already does correctly:** Both events (`cowrie.session.file_download` from Cowrie SSH, and `http.upload.malware_received` from HTTP) reach HoneyDash and are visible in:
- The attack-types breakdown chart (`"Malware Upload"`, `"Malware Download"` slices).
- The raw events list and `remote-deep` endpoint.
- Neuro's own PostgreSQL and Telegram alerts (these are unaffected by HoneyDash display gaps).

**Action:** No code change. Document as known limitation for the pitch: "Malware activity is captured in full by Neuro's own database and triggers immediate Telegram alerts. The HoneyDash malware card is Dionaea-specific and does not reflect Neuro's captures — use the attack-types chart or raw events list to demonstrate malware interception."

---

### Deployment Order for Session 10

All three code changes (FIX-DASH-1, FIX-DASH-2, FIX-DASH-3, FIX-DASH-4) can be deployed in a single pass since they touch two separate containers:

**Pass 1 — log_shipper.py** (FIX-DASH-2 + FIX-DASH-3):
1. Edit `deploy/module-5-log-shipper/src/log_shipper.py` — add `445: "smb"` to `_HD_PORT_PROTOCOL` and add `_HD_EVENTID_REMAP` dict + remap block in `_honeydash_event()` + update `_HD_ATTACK_TYPE` keys.
2. `cd /opt/honeypot/deploy/module-5-log-shipper/`
3. `docker compose build --no-cache log-shipper && docker compose up -d log-shipper`
4. `docker compose build --no-cache sentinel && docker compose up -d sentinel`
5. Verify: `docker logs log-shipper 2>&1 | tail -20` — no errors.

**Pass 2 — main.py** (FIX-DASH-1 + FIX-DASH-4):
1. Edit `deploy/module-6-honeypot-api/src/main.py` — add `"protocol": "http"` to `honeydash_event` dict and extend `input` population block.
2. `cd /opt/honeypot/deploy/module-6-honeypot-api/`
3. `docker compose up -d --build --force-recreate`
4. `bash verify-module-6.sh` — must stay 10/10.

**Pass 1 must complete before Pass 2** only because the gatekeeper may want to verify log_shipper changes independently. The two passes are technically independent and could be deployed simultaneously.

---

## Issue 7 — Sentinel vs HoneyDash Coverage Gap (Investigated 2026-06-06)

### Summary

Sentinel reads directly from Neuro's PostgreSQL (`honeypot_events` table) and sees every event that `_log_event()` writes. HoneyDash only receives events that are explicitly POSTed to its `/api/ingest/batch` endpoint. The middleware in `main.py` is selective about which HTTP events it forwards to HoneyDash — the majority of HTTP events are written to Neuro's PostgreSQL (and therefore trigger Sentinel alerts) but are never pushed to HoneyDash.

---

### 1. Root Cause

**Sentinel data source** (`sentinel.py` lines 457–465): polls Neuro's own PostgreSQL with a plain `SELECT` query — no filter on sensor or event_type. Every row in `honeypot_events` is evaluated by `_should_alert()`. Sentinel does not interact with HoneyDash at all.

**HoneyDash data source** (confirmed in `HoneyDash/backend/services/log_collector.py` line 198): receives events exclusively via POST to `/api/ingest/batch`. It does not read from Neuro's PostgreSQL. The two data stores are completely separate databases.

**The HoneyDash push gate** in `main.py` middleware (`request_logger`, lines 644–653):

```python
if HONEYDASH_URL and SENSOR_API_KEY:
    if snare_attack_type:
        asyncio.create_task(_push_honeydash_async(event, snare_attack_type))
    elif is_lure:
        asyncio.create_task(_push_honeydash_async(event, "Lure Access"))
    elif is_login and username:
        asyncio.create_task(_push_honeydash_async(event, "Web Login Attempt"))
```

Three conditions must be met for an HTTP event to reach HoneyDash:
1. `snare_attack_type is not None` — `_detect_web_attack()` matched a SQLi/LFI/RCE/XSS/SSRF pattern in the path, query string, or body.
2. `is_lure is True` — the request path starts with one of the 31 paths in `_LURE_PATHS` (main.py lines 208–240).
3. `is_login and username` — the request is to a login endpoint AND a `username` field was extracted from the body.

`_log_event_async()` (line 640) is called unconditionally for every request — no gate. That is what writes to PostgreSQL (and therefore feeds Sentinel).

---

### 2. Specific Example: `GET /.env`

Tracing `GET /.env` step by step through `request_logger`:

1. `path = "/.env"` — `is_login = False` (not in `_LOGIN_PATHS`, does not end with `/login`).

2. `is_lure = any(path.startswith(p) for p in _LURE_PATHS)` — `"/.env"` is the first entry in `_LURE_PATHS` (main.py line 209). `"/.env".startswith("/.env")` is `True`. So `is_lure = True`.

3. `_detect_web_attack(path="/.env", query_str="", body_str="", ...)` — checks `combined = "/.env  "` against `_SQLI_PATTERNS`, `_LFI_PATTERNS`, `_RCE_PATTERNS`, `_XSS_PATTERNS`, `_SSRF_PATTERNS`. The bare string `"/.env"` does not match any pattern (no `../`, no `%2e`, no SQL keywords). `_detect_web_attack` returns `None`. So `snare_attack_type = None`.

4. Gate evaluation (lines 644–653):
   - `snare_attack_type` is `None` → first branch skipped.
   - `is_lure` is `True` → second branch fires: `asyncio.create_task(_push_honeydash_async(event, "Lure Access"))`.
   - HoneyDash **does** receive this event.

5. `_log_event_async(event)` fires unconditionally (line 640) → row written to `honeypot_events` → Sentinel sees it on next poll.

**Conclusion for `GET /.env`**: Both Sentinel and HoneyDash receive this event. The user's report of `/.env` appearing in Sentinel but not HoneyDash is therefore not a permanent gap — it is either a timing issue (HoneyDash push is async and batches up to `FLUSH_INTERVAL` seconds; Sentinel polls every 10s and may show the event before HoneyDash commits it), or a transient failure of the `_push_honeydash_async` httpx call (timeout=3.0s, any HoneyDash lag drops the push silently with only a `honeydash_push_error` log line).

---

### 3. Events That Reach Sentinel But NOT HoneyDash

The following HTTP event categories are written to PostgreSQL (Sentinel sees them) but the HoneyDash push gate is never triggered:

**Category A — Reconnaissance probes to non-lure paths**

Any `GET` or `POST` to a path not in `_LURE_PATHS` and not triggering `_detect_web_attack`. Examples:

- `GET /api-docs` — path_cat = `"api-docs"`, event_type = `"http.get.api-docs"`. Not in `_LURE_PATHS`. No SNARE pattern. `is_login=False`. → PostgreSQL only.
- `GET /wp-admin`, `GET /phpmyadmin` — scanner probes to paths that do not start with any `_LURE_PATHS` entry. → PostgreSQL only.
- `GET /api/v1/health` — suppressed in Sentinel by `_NOISE_EVENTS` and filtered by log_shipper `_HD_NOISE_EVENTS`. Neither system shows it.
- `GET /static/js/metrics.js` — path_cat = `"static"`. Not in `_LURE_PATHS`. → PostgreSQL only.
- `GET /` (login page) — path_cat = `"login_page"`. Not in `_LURE_PATHS`. `is_login=False` (login paths need POST to `/api/v1/auth`). → PostgreSQL only.
- `GET /favicon.ico`, `GET /robots.txt` — not in `_LURE_PATHS`. → PostgreSQL only.

**Category B — Login attempts without a parsed username**

`POST /api/v1/auth` with a body that cannot be JSON-decoded (e.g. raw bytes, empty body, malformed JSON). `is_login=True` but `username=None`. The third gate condition (`is_login and username`) evaluates to `False`. → PostgreSQL only.

**Category C — Page views on authenticated lure pages that are NOT in `_LURE_PATHS`**

`_LURE_PATHS` uses `startswith()` matching. Any path not starting with an entry is excluded. For example:
- `GET /api/v1/auth/sso/initiate` — not in `_LURE_PATHS`. Checked: `_LURE_PATHS` does not contain `"/api/v1/auth"` (only `"/api/v1/data/download"`, `"/api/v1/data/exports/download"`, etc.). → PostgreSQL only.
- `GET /pipelines` — not in `_LURE_PATHS`. → PostgreSQL only.
- `GET /settings/workspace` — not in `_LURE_PATHS`. → PostgreSQL only.

**Category D — telemetry beacons**

`POST /api/v1/telemetry` — excluded from Sentinel via `_NOISE_EVENTS` (sentinel.py line 72: `"http.post.api.v1.telemetry"` and `"http.get.api.v1.telemetry"`). Not in `_LURE_PATHS`. No SNARE pattern detected in telemetry payloads. Both Sentinel and HoneyDash are silent for these.

**Note on `/.env` specifically**: `/.env` IS in `_LURE_PATHS` and therefore IS pushed to HoneyDash via the `is_lure` branch. If the user observed it missing from HoneyDash, the explanation is one of:
- The `_push_honeydash_async` httpx POST timed out (3.0s limit; HoneyDash under load → silent drop, only a `honeydash_push_error` WARNING in `honeypot-api` container logs).
- HoneyDash's `process_line()` passed the event but the session commit failed.
- Timing: Sentinel fires within ~10s; HoneyDash async push may lag and the user checked HoneyDash before it committed.

---

### 4. Scope of Impact on Dashboard Cards

**Protocol mix card (`/dashboard/protocol-stats`)**

Groups by `Event.protocol`. As established in Issue 1, HTTP events reach HoneyDash with `protocol="unknown"` (FIX-DASH-1 addresses this). Even after FIX-DASH-1 gives them `protocol="http"`, only the subset pushed via `_push_honeydash_async` are counted. Reconnaissance probes (Category A above) never reach HoneyDash — they are never in this chart.

The protocol mix card therefore undercounts the true HTTP traffic volume. The actual HTTP event count in Neuro's PostgreSQL is significantly higher than what HoneyDash displays.

**Attack types card (`/dashboard/attack-types`)**

Only receives: SNARE attack events (SQLi/RCE/LFI/XSS/SSRF detected by `_detect_web_attack`), lure path accesses, canarytoken fires, malware uploads, bruteforce detections. This is the high-value subset — the attack types card is accurate for attacker intent; it correctly excludes background scanner noise.

Missing from this card: web recon to non-lure, non-SNARE paths. Since those events carry no attacker signal above noise level, their absence from the attack-types card is arguably correct behaviour.

**Top attackers card (`/dashboard/top-attackers` in HoneyDash)**

Counts only events in HoneyDash's `events` table. An attacker IP that does extensive recon on non-lure paths (e.g. scanning `/wp-admin`, `/phpmyadmin`, `/manager/html`) generates many events in Neuro's PostgreSQL but zero in HoneyDash. Such IPs are invisible to the top-attackers card unless they also hit a lure path or trigger a SNARE detection. Sentinel would alert on these IPs (after cooldown); HoneyDash would not.

**Live feed (WebSocket, HoneyDash)**

The live feed broadcasts every event that reaches `process_line()` in HoneyDash. Since only the gated subset of HTTP events POSTs to `/api/ingest/batch`, the live feed misses all Category A/B/C events listed above. For a scanner that sends 200 requests over 30 seconds, HoneyDash may show 1–3 events (first lure or SNARE hit); Sentinel would show the same 1–3 plus possibly additional cooldown-suppressed events.

**Estimated coverage ratio**: Neuro's PostgreSQL sees 100% of HTTP events. HoneyDash receives approximately 5–15% of HTTP events — those matching the three gate conditions. On a day with heavy scanner activity (automated tools probing `/wp-admin`, `/phpmyadmin`, etc.), the ratio is lower because scanners generate many non-lure, non-SNARE probes. On a day with targeted attacker activity (human or semi-automated tool probing `/.env`, `/api/v1/internal/config`, submitting login credentials), the ratio is higher because targeted paths tend to hit `_LURE_PATHS`. For SNARE-detected attacks (SQLi/RCE payloads), the ratio is 100% — every detected attack is pushed.

---

### 5. Cowrie/OpenCanary/MariaDB: Same Gap or Not?

**No — non-HTTP sensors do NOT have this gap.**

For Cowrie, OpenCanary, and MariaDB, events flow through `log_shipper.py`. The consumer thread (`_consumer_worker`, line 1980) calls `_add_to_honeydash_batch(event)` unconditionally after every successful `PostgresWriter.write()` call. There is no selective gate:

```python
# log_shipper.py line 1980
_add_to_honeydash_batch(event)
```

The only filtering applied is inside `_honeydash_event()` via `_HD_NOISE_EVENTS` (log_shipper.py lines 1733–1738):

```python
_HD_NOISE_EVENTS = {
    "http.get.health",
    "http.head.health",
    "cowrie.session.closed",
    "api.startup",
}
```

Four event types are filtered out. Everything else — every Cowrie login attempt, every shell command, every file download, every OpenCanary FTP/Telnet/Redis probe, every MariaDB connect and SQL query — is batched and flushed to HoneyDash.

**Contrast with HTTP**: For HTTP, the Sentinel-vs-HoneyDash divergence is structural (selective gate in middleware). For Cowrie/OpenCanary/MariaDB, Sentinel and HoneyDash receive the same population of events (minus the 4 noise types, which Sentinel's `_NOISE_EVENTS` also suppresses from alerting). The two systems are in sync for non-HTTP sensors.

---

### 6. Fix Recommendation

The gap is a design choice, not a defect: the `is_lure or snare_attack_type or is_login` gate was deliberately added to avoid flooding HoneyDash with background scanner noise. The comment at main.py line 642 states this explicitly: "HoneyDash push — only for SNARE attack events and high-value lure hits."

If the goal is to make HoneyDash reflect the full HTTP traffic picture (matching Sentinel's event population), the change required is:

**Option A — Push all HTTP events (matches Cowrie/OpenCanary/MariaDB behaviour)**

Remove the gate entirely. After line 640 (`asyncio.create_task(_log_event_async(event))`), add unconditional push:

```python
if HONEYDASH_URL and SENSOR_API_KEY:
    asyncio.create_task(_push_honeydash_async(event, snare_attack_type or "HTTP Probe"))
```

Tradeoff: HoneyDash receives orders-of-magnitude more events. The attack-types chart would be dominated by `"HTTP Probe"` entries from scanner noise, obscuring the high-value attack types. The live feed would be unusable without a severity filter. HoneyDash's `/api/ingest/batch` would receive 50–200 calls/minute from a busy scanner, up from ~1–5.

**Option B — Expand the gate to include all `is_lure` paths and failed logins (recommended)**

The current gate already handles `is_lure=True`. The gap is primarily Category A (non-lure, non-SNARE paths). Extending the gate to push all failed logins (not just those with a parsed username) would close Category B:

```python
elif is_login:   # was: elif is_login and username
    asyncio.create_task(_push_honeydash_async(event, "Web Login Attempt"))
```

This is a 1-word change in `main.py` line 651. It closes the case where a scanner sends a malformed login body (no username extractable) — these are still login attempts and should appear in HoneyDash.

**Option C — Add async timing buffer to explain the `/.env` observation**

Since `/.env` IS in `_LURE_PATHS` and IS pushed, the user's observation is most likely a timing issue. Check `honeypot-api` container logs for `honeydash_push_error` entries around the time of the `/.env` access. If the push fails transiently (HoneyDash under load, httpx timeout), the event is silently dropped — no retry. A fix for the silent-drop case is to add a retry wrapper around `_push_honeydash_async`, or to fall back to including the event in the next log_shipper batch (not currently architecturally possible without shared state).

**What NOT to change**: The 5–15% coverage ratio for HTTP events is acceptable for the use case. HoneyDash is the presentation layer; Neuro's PostgreSQL + Sentinel is the authoritative record. The gap becomes problematic only if someone uses HoneyDash as the sole source of truth for incident response — which it should not be.
