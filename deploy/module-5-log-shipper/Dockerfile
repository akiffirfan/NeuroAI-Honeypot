# =============================================================================
# log-shipper Dockerfile
# Neuro Honeypot Platform — Module 5
#
# Base: python:3.12-slim (Debian Bookworm base, minimal attack surface)
# Built from: deploy/module-5-log-shipper/
#
# SIZE NOTE: python:3.12-slim is ~140MB compressed. The GeoLite2-City.mmdb is
# loaded from the geoip-data volume at runtime, NOT baked into the image.
# =============================================================================

FROM python:3.12-slim

# Install build dependencies for psycopg2 and system packages.
# We use psycopg2-binary to avoid needing libpq-dev at runtime,
# but we still need gcc for some wheel builds.
RUN apt-get update && apt-get install -y --no-install-recommends \
        # Required by watchdog to use inotify (inotify-based file tailing)
        gcc \
        # netcat — used by verify-module-5.sh healthcheck probe
        netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first so Docker layer cache is reused on source changes.
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY src/ /app/src/

# Pre-compile all .pyc files into the image layer.
# This is required if the container is ever switched to read_only: true.
# Even without read_only, it eliminates startup latency from runtime compilation.
RUN python -m compileall -q /app/src/

# Create the spool directory inside the container as a fallback.
# The /archive/ bind-mount from docker-compose.yml overrides this at runtime.
RUN mkdir -p /archive/spool

# Run as non-root inside the container.
# With userns-remap active, this UID (1000) maps to host UID 101000 — not 100000
# (which is container root 0). The /archive bind-mount is chown'd to 100000
# (container root), and Python writes there as the process owner.
# DESIGN: log-shipper runs as root inside the container (UID 0) because the
# geoip-data volume and log volumes are owned by container UID 0 (host 100000).
# Running as a non-root UID inside the container would require additional
# volume ownership setup. Since cap_drop: [ALL] is applied in docker-compose.yml,
# container root has no Linux capabilities — the risk surface is minimal.
# If you prefer explicit non-root, add: RUN useradd -r -u 999 shipper && chown shipper /archive
# and switch to USER shipper here.

# Health check endpoint — the Python service exposes a minimal HTTP server on :9100
# Docker compose healthcheck polls this; verify-module-5.sh also tests it.
EXPOSE 9100

ENTRYPOINT ["python", "-u", "/app/src/log_shipper.py"]
