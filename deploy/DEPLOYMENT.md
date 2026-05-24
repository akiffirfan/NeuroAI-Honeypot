# Neuro Honeypot Platform — Deployment Guide

This document covers the operator steps for deploying the Neuro honeypot platform
module by module. Each module is designed to be stood up and verified independently
before the next is added.

**Working directory on VPS**: `/opt/honeypot/`
**Domain**: `neurodata.me`
**Full plan reference**: `honeypot-project-plans.md` (plan sections are referenced below)

---

## Prerequisites Before Running Module 0

These must be true BEFORE running the bootstrap script. The script checks the first
two and will exit with an error if they are not met.

1. **VPS is Ubuntu 22.04 LTS** — the script verifies this at line 1 and exits on mismatch.

2. **Real SSH is already on port 22704** — this is checked by the script. Do not skip it.
   If SSH is not yet moved:
   ```bash
   # On the VPS:
   echo "Port 22704" >> /etc/ssh/sshd_config
   systemctl restart sshd
   # Open a NEW terminal and verify: ssh -p 22704 jzargo@<vps-ip>
   # Confirm the new session works BEFORE closing the old one
   ```

3. **You have root access** — the bootstrap script must run as root.

4. **Port 22 is CLOSED at your VPS provider's firewall/security group** — NOT at nftables,
   at the provider level (Hetzner Firewall, AWS Security Group, DigitalOcean Firewall, etc.).
   Port 22 stays closed at the provider level until Day 3 Step 18, when Cowrie is deployed
   and the DNAT rule is in place. Opening it before Cowrie is running exposes the host.

---

## Module Order and Why Each Must Be Verified First

| Module | Day | What it does | Why before the next |
|--------|-----|--------------|---------------------|
| **0 — Host bootstrap** | Day 0 | Docker, ufw, auditd, directory scaffold | All subsequent modules depend on Docker daemon hardening (userns-remap). Running compose without userns-remap means a container escape = host root. |
| **1 — Data layer** | Day 2 | PostgreSQL+TimescaleDB, Redis | log-shipper (Module 6) writes to postgres and redis. The schema must exist before log-shipper starts or it crashes on startup. |
| **2 — Cowrie SSH** | Day 3 | SSH honeypot | Needs honeypot-net network, which is defined in the full compose. Verify data layer first so the network stack is clean. |
| **3 — OpenCanary** | Day 3 | FTP/Telnet/SMTP/Redis lure | Joins honeypot-net; needs it to exist. |
| **4 — mariadb-lure** | Day 3 | Real MariaDB fake schema on port 3306 | The general query log volume (mariadb-logs) is tailed by log-shipper — must exist before log-shipper starts. |
| **5 — FastAPI honeypot API** | Day 3 | Deceptive HTTP/API surface | log-shipper receives events from this service; must be running before log-shipper is configured. |
| **6 — Log-shipper** | Day 4 | Normalizes and ships events | Must start AFTER all sensors are running so it has log volumes to tail. Starting early causes watchdog errors. |
| **7 — Nginx/TLS** | Day 1 | TLS termination, deceptive frontend | Deployed before honeypots go live but after Let's Encrypt certs exist. Can run in parallel with the data layer. |

---

## Running Each Module

All commands below are run from `/opt/honeypot/` on the VPS as `jzargo`
(added to the `docker` group by Module 0). Use `sudo` only where noted.

### Module 0 — Host Bootstrap (run as root)

```bash
# Copy the script to the VPS and run it as root:
sudo bash /path/to/deploy/module-0-host-bootstrap.sh

# After script completes, REBOOT BEFORE PROCEEDING:
sudo systemctl reboot

# After reboot, verify swapaccount is active:
grep swapaccount /proc/cmdline
# Expected output contains: swapaccount=1
```

### Module 1 — Data Layer

```bash
# 1. Copy Module 1 files to VPS (or clone the repo to /opt/honeypot/)
# 2. Create the .env file with your generated password:
cd /opt/honeypot/deploy/module-1-data-layer/
cp .env.example .env
chmod 600 .env
# Edit .env and set POSTGRES_PASSWORD to a strong generated value:
#   openssl rand -base64 32 | tr -d '/+=@'

# 3. Deploy the data layer:
docker compose -f /opt/honeypot/deploy/module-1-data-layer/docker-compose.yml up -d

# 4. Wait ~30 seconds for TimescaleDB initialization, then verify:
bash /opt/honeypot/deploy/module-1-data-layer/verify-module-1.sh
# All checks must pass before proceeding to Module 2.
```

### Module 2 onwards

Each subsequent module will have its own `docker-compose.yml` and `verify-moduleN.sh`.
The pattern is the same:
```bash
docker compose -f /opt/honeypot/deploy/module-N-*/docker-compose.yml up -d
bash /opt/honeypot/deploy/module-N-*/verify-module-N.sh
```

When all modules are deployed and verified, the full stack can also be managed via
the master compose file at `/opt/honeypot/docker-compose.yml` (not yet created —
assembled from all module compose files).

---

## Per-Module vs Master Compose Pattern

The deployment uses per-module compose files during initial deployment and verification.
Once all modules are verified individually, the full `docker-compose.yml` in `/opt/honeypot/`
is the single source of truth for the running stack.

**Per-module compose files** (in `deploy/module-N-*/docker-compose.yml`):
- Used during initial deployment — bring up one layer at a time
- Each file is standalone and self-contained
- Volumes and networks are prefixed with the compose project name (e.g. `module-1-data-layer_postgres-data`)
- **WARNING**: Per-module volumes have different names than the master compose volumes.
  After initial verification, migrate to the master compose (see "Migration to Master Compose" below).

**Master compose file** (`/opt/honeypot/docker-compose.yml`):
- Used for ongoing operations after all modules are verified
- All services, networks, and volumes in a single file
- Volumes named without a module prefix (e.g. `postgres-data`)
- Run from `/opt/honeypot/`: `docker compose up -d`

### Migration to Master Compose (after all modules verified)

```bash
# 1. Stop per-module stacks:
docker compose -f /opt/honeypot/deploy/module-1-data-layer/docker-compose.yml down
# Repeat for each module

# 2. Copy data from module volumes to master volumes if needed:
# (For a fresh deployment with no production data yet, volumes can start empty)

# 3. Start the master compose:
cd /opt/honeypot/
docker compose up -d
```

---

## Rolling Back a Module

If a module fails verification or causes issues, roll back before proceeding.

### Stop containers without removing volumes (preserves data):
```bash
docker compose -f /opt/honeypot/deploy/module-1-data-layer/docker-compose.yml stop
```

### Remove containers and networks (preserves named volumes):
```bash
docker compose -f /opt/honeypot/deploy/module-1-data-layer/docker-compose.yml down
```

### Full wipe including volumes (destroys all data — use for development only):
```bash
docker compose -f /opt/honeypot/deploy/module-1-data-layer/docker-compose.yml down -v
# WARNING: This deletes postgres-data and redis-data volumes permanently.
# Only use this if you need to re-run the init SQL (01-schema.sql).
```

### Re-run PostgreSQL init SQL after a volume wipe:
The init scripts in `/docker-entrypoint-initdb.d/` run ONLY when the data volume
is empty. After a `down -v`, the next `up -d` will re-run them automatically.
No manual SQL execution is needed.

---

## Environment Variables Reference

| Variable | Module | Description |
|----------|--------|-------------|
| `POSTGRES_PASSWORD` | 1, 6 | Password for the `honeypot` database user |
| `HONEYDASH_SENSOR_KEY` | 6 | Shared secret for HoneyDash ingest API |
| `SLACK_WEBHOOK_URL` | 6 | Slack webhook for operator alerts |
| `FORGOT_PASSWORD_SALT` | 5 | Salt for hashing forgot-password emails (see Section 16.3) |

Each module's `.env.example` documents the variables it needs.

---

## Security Notes

- **Never open port 22 at the provider firewall until Cowrie is deployed and DNAT is configured.**
  The order is: deploy Cowrie → configure nftables DNAT → THEN open port 22. See Day 3 Steps 16–18
  in `honeypot-project-plans.md` Section 12.

- **The VPS must be rebooted after Module 0** before starting any Docker containers.
  The `swapaccount=1` kernel parameter has no effect until after a reboot. Without it,
  `memswap_limit` in all compose files is silently ignored.

- **Bind-mount directories must be owned by 100000:100000** before `docker compose up`.
  Module 0 sets this. If you add new bind-mount paths later, chown them manually:
  ```bash
  chown -R 100000:100000 /opt/honeypot/config/
  ```

- **Image pinning**: before going live, replace `latest` tags with SHA digests.
  Each module's compose file has instructions. `mariadb-lure` is highest priority
  because it accepts unauthenticated TCP connections from the open internet.
