# honeypot-api Dockerfile
# Base: python:3.12-slim — minimal Debian-based Python image
#
# CRITICAL: RUN python -m compileall is included below. This pre-generates all .pyc files
# into the image layer so that the read_only: true constraint in the master compose
# (plans.md Section 7.1) does not cause OSError: [Errno 30] Read-only file system on import.
# Without this step, any module import that encounters a missing .pyc will attempt to write
# to <module_dir>/__pycache__/ and crash-loop into the on-failure:5 cap.
#
# USER: appuser (UID 1000) — non-root; matches userns-remap: default offset (host UID 101000).
# Both uvicorn processes run as this user. No capabilities are needed.
#
# TWO PORTS:
#   8080 — main FastAPI app (all routes: /, /api/v1/*, /admin/*, /.env, etc.)
#   8888 — fake Jupyter notebook stub FastAPI app
# Both are started by start.sh. Healthcheck targets 8080 only.

FROM python:3.12-slim

# Install system dependencies needed by psycopg2-binary and wget (healthcheck)
# wget is needed by the compose healthcheck: wget -q --spider http://localhost:8080/api/v1/health
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        wget \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user — UID 1000 avoids the root→appuser setuid capability requirement
RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid 1000 --no-create-home --shell /bin/false appuser

WORKDIR /app

# Install Python dependencies as root before switching users
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY src/ /app/

# Copy the startup script that launches both uvicorn processes
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

# Pre-compile all .pyc files into the image layer.
# REQUIRED: the master compose sets read_only: true + /tmp tmpfs.
# PYTHONPYCACHEPREFIX=/tmp/.pycache redirects residual runtime writes to tmpfs,
# but pre-compilation eliminates the need for any writes during import.
RUN python -m compileall -q /app

# Switch to non-root user for all subsequent layers and runtime
USER appuser

EXPOSE 8080
EXPOSE 8888

# start.sh launches both uvicorn processes: main app on 8080, Jupyter stub on 8888.
# Both processes are backgrounded; `wait -n` exits when either exits (triggering restart).
CMD ["/app/start.sh"]
