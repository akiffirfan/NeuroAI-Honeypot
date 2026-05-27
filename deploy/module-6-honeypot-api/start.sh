#!/bin/bash
# start.sh — launch both uvicorn processes for honeypot-api
#
# Port 8080: main FastAPI application (all deceptive routes)
# Port 8888: fake Jupyter notebook stub
#
# Both processes are backgrounded. `wait -n` exits when the FIRST of them exits,
# which triggers Docker's on-failure:5 restart policy to restart the container.
# This ensures a crash in either process causes the whole container to restart cleanly.
#
# Nginx (Module 7) proxies external traffic:
#   neurodata.me -> 127.0.0.1:8080 (all routes)
#   neurodata.me/jupyter/ -> 127.0.0.1:8888
#
# Healthcheck in docker-compose.yml checks :8080/api/v1/health only.

set -euo pipefail

# Ensure PYTHONDONTWRITEBYTECODE is set (belt-and-suspenders for read_only: true)
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPYCACHEPREFIX=/tmp/.pycache

echo "[start.sh] Starting honeypot-api on :8080 (main) and :8888 (jupyter stub)"

# Main application — all deceptive routes
uvicorn main:app \
    --host 0.0.0.0 \
    --port 8080 \
    --no-access-log \
    --log-level warning &
MAIN_PID=$!

# Fake Jupyter stub — separate app for port 8888
uvicorn jupyter_stub:app \
    --host 0.0.0.0 \
    --port 8888 \
    --no-access-log \
    --log-level warning &
JUPYTER_PID=$!

echo "[start.sh] main PID=$MAIN_PID  jupyter PID=$JUPYTER_PID"

# Exit when either process exits — Docker restart policy takes over
wait -n

echo "[start.sh] A process exited — container will restart"
exit 1
