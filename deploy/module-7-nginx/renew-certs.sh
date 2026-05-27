#!/usr/bin/env bash
# renew-certs.sh — TLS certificate renewal for neurodata.me
#
# Run this monthly via cron or manually when the cert is approaching expiry.
# Let's Encrypt certificates expire after 90 days; renew at 30-day intervals.
#
# Recommended cron entry (run as root):
#   0 3 1 * * /opt/honeypot/deploy/module-7-nginx/renew-certs.sh >> /var/log/certbot-renew.log 2>&1
#
# The script:
#   1. Runs certbot renew in a one-off container using the webroot authenticator
#   2. Certbot checks if renewal is needed (skips if cert expires in > 30 days)
#   3. Reloads nginx gracefully (openresty -s reload) to pick up the new cert
#
# PREREQUISITES:
#   - nginx container must be running (serves ACME challenge on port 80)
#   - certbot-certs and certbot-webroot Docker volumes must exist (created by Module 7)
#   - Port 80 must be open at the DigitalOcean cloud firewall panel
#
# TROUBLESHOOTING:
#   If renewal fails, check:
#     docker logs nginx | tail -20
#     docker run --rm -v certbot-certs:/etc/letsencrypt certbot/certbot certificates
#   Cert expiry date:
#     docker exec nginx openssl x509 -noout -enddate \
#       -in /etc/letsencrypt/live/neurodata.me/fullchain.pem

set -euo pipefail

LOG_PREFIX="[certbot-renew $(date '+%Y-%m-%d %H:%M:%S')]"

echo "$LOG_PREFIX Starting cert renewal check..."

# Run certbot renew using the same webroot authenticator used during initial issuance.
# --quiet suppresses output if no renewal is needed (cert still valid for > 30 days).
# certbot renew is idempotent — safe to run even if the cert is not due for renewal.
docker run --rm \
    -v certbot-certs:/etc/letsencrypt \
    -v certbot-webroot:/var/www/certbot \
    certbot/certbot renew --quiet

RENEW_EXIT=$?

if [[ "$RENEW_EXIT" -ne 0 ]]; then
    echo "$LOG_PREFIX certbot renew exited with code $RENEW_EXIT — check logs above"
    exit 1
fi

echo "$LOG_PREFIX certbot renew completed successfully"

# Reload nginx gracefully to pick up any new certificate files.
# openresty -s reload sends SIGHUP to the master process, which re-reads the config
# and gracefully rotates workers — no downtime, no dropped connections.
# This is always safe to run; if no new cert was issued, reload is a no-op.
docker exec nginx openresty -s reload

if [[ $? -eq 0 ]]; then
    echo "$LOG_PREFIX nginx reloaded — new cert (if any) is now active"
else
    echo "$LOG_PREFIX nginx reload failed — cert may be renewed but not yet served. Run manually: docker exec nginx openresty -s reload"
    exit 1
fi

echo "$LOG_PREFIX Done."
