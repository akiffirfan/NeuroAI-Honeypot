FROM python:3.11-slim

# impacket 0.12.0 — pinned for reproducibility. Contains smbserver module,
# ntlm challenge/response parsing, and DCERPC pipe handling.
# cryptography and pyOpenSSL are impacket hard deps.
# psycopg2-binary and redis for direct PostgreSQL + Redis writes.
# structlog for structured JSON logging.
RUN pip install --no-cache-dir \
    impacket==0.12.0 \
    cryptography==42.0.8 \
    pyOpenSSL==24.1.0 \
    psycopg2-binary \
    redis \
    structlog

RUN useradd -m -s /bin/bash smbsvc

WORKDIR /app
COPY src/ /app/

# Pre-compile to catch import errors at build time (same pattern as honeypot-api)
RUN python -m py_compile /app/smb_server.py

# Non-root user — SMB on port 445 requires CAP_NET_BIND_SERVICE, not root.
# The capability is added in docker-compose.yml.
USER smbsvc

CMD ["python", "/app/smb_server.py"]
