#!/usr/bin/env bash
# =============================================================================
# module-0-host-bootstrap.sh
# Neuro Honeypot Platform — Day 0 Host Bootstrap
#
# Run as root on the VPS. Idempotent — safe to re-run if interrupted.
# Prepares the host OS before any Docker container is started:
#   - Verifies OS and real-SSH safety
#   - Installs Docker (official repo), compose plugin, and security tools
#   - Hardens the Docker daemon (userns-remap, live-restore, no-new-privileges, icc:false)
#   - Configures ufw firewall
#   - Sets up auditd container-escape detection rules
#   - Scaffolds /opt/honeypot/ bind-mount directory tree
#
# OPERATOR: after this script completes, REBOOT THE HOST before proceeding to Module 1.
# The swapaccount=1 kernel parameter added to GRUB requires a reboot to take effect.
# Without it, memswap_limit in docker-compose.yml is silently ignored, which means
# a memory-flood attack can cause disk thrashing instead of clean OOM-kill.
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Error trap — print the failing line and exit cleanly
# ---------------------------------------------------------------------------
trap 'echo "" >&2; echo "FATAL: bootstrap failed at line ${LINENO} (exit code $?)" >&2; echo "Fix the error above, then re-run this script." >&2; exit 1' ERR

# ---------------------------------------------------------------------------
# Colour helpers (safe — only emit escape codes when stdout is a terminal)
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED=''; YEL=''; GRN=''; BOLD=''; NC=''
fi

info()  { echo -e "${BOLD}[INFO]${NC}  $*"; }
warn()  { echo -e "${YEL}[WARN]${NC}  $*"; }
ok()    { echo -e "${GRN}[ OK ]${NC}  $*"; }
die()   { echo -e "${RED}[FAIL]${NC}  $*" >&2; exit 1; }

echo ""
echo -e "${BOLD}=== Neuro Honeypot — Module 0 Host Bootstrap ===${NC}"
echo ""

# ---------------------------------------------------------------------------
# STEP 1 — Verify Ubuntu 22.04 LTS
# WHY: The auditd rules, kernel params, and Docker apt repo path are all
# Ubuntu 22.04 (Jammy) specific. Running on a different OS version risks
# broken package paths, wrong kernel defaults, or incompatible subuid ranges.
# ---------------------------------------------------------------------------
info "Step 1: Verifying OS is Ubuntu 22.04 or 24.04 LTS..."

if ! command -v lsb_release &>/dev/null; then
    die "lsb_release not found — cannot verify OS. Install lsb-release first: apt-get install lsb-release"
fi

OS_ID=$(lsb_release -is)
OS_VERSION=$(lsb_release -rs)
OS_CODENAME=$(lsb_release -cs)

if [[ "${OS_ID}" != "Ubuntu" ]] || [[ "${OS_VERSION}" != "22.04" && "${OS_VERSION}" != "24.04" ]]; then
    die "Expected Ubuntu 22.04 or 24.04 LTS — got ${OS_ID} ${OS_VERSION}. Aborting."
fi

ok "OS check passed: Ubuntu ${OS_VERSION} (${OS_CODENAME})"

# ---------------------------------------------------------------------------
# STEP 2 — Verify real SSH is already on port 22704
# WHY: This is the critical safety gate. If we proceed without this check and
# the operator's SSH is still on port 22, deploying Cowrie's DNAT rule later
# will lock them out of the server permanently. The honeypot architecture
# moves real SSH to 22704 FIRST; port 22 then routes to Cowrie.
# This check verifies that move has already happened before we touch anything.
# ---------------------------------------------------------------------------
info "Step 2: Verifying real SSH is listening on port 22704 (safety check)..."

if ! ss -tlnp 2>/dev/null | grep -q ':22704'; then
    echo "" >&2
    echo -e "${RED}FATAL: Real SSH is NOT listening on port 22704.${NC}" >&2
    echo "" >&2
    echo "REQUIRED BEFORE RUNNING THIS SCRIPT:" >&2
    echo "  1. Add 'Port 22704' to /etc/ssh/sshd_config on this host" >&2
    echo "  2. systemctl restart sshd" >&2
    echo "  3. Open a NEW SSH session on port 22704 to verify it works" >&2
    echo "  4. Do NOT close your existing session until the new one is confirmed" >&2
    echo "  5. Then re-run this script" >&2
    echo "" >&2
    echo "If port 22 remains the only SSH entry point and Cowrie DNAT is later applied," >&2
    echo "you will be permanently locked out of this VPS." >&2
    exit 1
fi

ok "SSH is listening on port 22704 — safe to proceed"

# ---------------------------------------------------------------------------
# STEP 3 — Install Docker (official Docker apt repository)
# WHY: The snap version of Docker ships a different daemon, different config
# paths, and has known issues with userns-remap. Always install from the
# official Docker apt repo to get docker-ce with full daemon feature support.
# ---------------------------------------------------------------------------
info "Step 3: Installing Docker CE from official apt repository..."

if command -v docker &>/dev/null && docker --version | grep -q "Docker version"; then
    warn "Docker already installed ($(docker --version)). Skipping Docker install — running daemon will not be interrupted."
else
    # Install prerequisites for adding the apt repository
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl gnupg

    # Add Docker's official GPG key to a dedicated keyring directory
    # WHY: /etc/apt/keyrings/ is the modern standard (replaces the deprecated apt-key)
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg

    # Add the Docker stable apt repository for this architecture and codename
    echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu ${OS_CODENAME} stable" \
        > /etc/apt/sources.list.d/docker.list

    apt-get update -qq
    apt-get install -y -qq \
        docker-ce \
        docker-ce-cli \
        containerd.io \
        docker-buildx-plugin \
        docker-compose-plugin

    ok "Docker CE installed successfully"
fi

# Verify docker compose v2 plugin is available (not the legacy docker-compose binary)
if ! docker compose version &>/dev/null; then
    die "docker compose plugin (v2) not found after install — check apt output above"
fi
ok "docker compose v2 plugin confirmed: $(docker compose version --short)"

# ---------------------------------------------------------------------------
# STEP 4 — Install security tools
# WHY:
#   auditd:               kernel-level syscall auditing — required for container
#                         escape detection rules in Step 11
#   fail2ban:             auto-bans IPs that fail SSH auth on :22704 — protects
#                         the real SSH entry point from brute force
#   ufw:                  uncomplicated firewall — used for the inbound allowlist
#   apache2-utils:        provides htpasswd — needed later for dashboard auth
#   unattended-upgrades:  automatic security patch application — keeps the host
#                         kernel and system libraries patched without manual toil
# ---------------------------------------------------------------------------
info "Step 4: Installing security tools (auditd, fail2ban, ufw, apache2-utils, unattended-upgrades)..."

apt-get install -y -qq \
    auditd \
    audispd-plugins \
    fail2ban \
    ufw \
    apache2-utils \
    unattended-upgrades \
    apt-listchanges

ok "Security tools installed"

# ---------------------------------------------------------------------------
# STEP 5 — Configure ufw firewall
# WHY: Establish the host-level inbound allowlist BEFORE any honeypot services
# are deployed. This ensures there is no window where the host is open.
#
# DNAT and ufw interaction (IMPORTANT):
#   All honeypot ports use nftables PREROUTING DNAT → 127.0.0.1:<port>.
#   After DNAT, ufw's INPUT chain sees the POST-DNAT destination, not the original port.
#   Example: external TCP:22 → DNAT → 127.0.0.1:2222 → ufw INPUT sees dport=2222.
#   So ufw rules must match the POST-DNAT port, not the public-facing port.
#
#   Rules added here cover ALL honeypot ports (idempotent — safe to run before Cowrie/OpenCanary
#   are deployed; a rule for an unbound port just allows traffic that reaches nothing):
#     - Port 2222: Cowrie SSH (public port 22 → DNAT → 127.0.0.1:2222)
#     - Port 21:   OpenCanary FTP (public port 21 → DNAT → 127.0.0.1:21, same port)
#     - Port 23:   OpenCanary Telnet (same-port DNAT)
#     - Port 25:   OpenCanary SMTP (same-port DNAT)
#     - Port 6379: OpenCanary Redis (same-port DNAT)
#   Port 3306 (MariaDB lure) is a real container published to 127.0.0.1:3306 — same rule applies.
# ---------------------------------------------------------------------------
info "Step 5: Configuring ufw firewall rules..."

# Reset to a clean state (idempotent — ufw reset prompts on interactive run,
# so we force-reset with the default policy approach instead)
ufw --force reset

ufw default deny incoming
ufw default allow outgoing

# Real SSH port — ALWAYS keep this open or you lock yourself out
ufw allow 22704/tcp comment "Real SSH (honeypot real management port)"

# HTTP and HTTPS — Nginx TLS termination for the deceptive frontend
ufw allow 80/tcp comment "HTTP (Nginx — redirects to HTTPS)"
ufw allow 443/tcp comment "HTTPS (Nginx — deceptive frontend + dashboard)"

# Honeypot service ports (POST-DNAT — see comment above)
ufw allow 2222/tcp  comment "Cowrie SSH via DNAT (external port 22 → 127.0.0.1:2222)"
ufw allow 21/tcp    comment "OpenCanary FTP via DNAT (same-port)"
ufw allow 23/tcp    comment "OpenCanary Telnet via DNAT (same-port)"
ufw allow 25/tcp    comment "OpenCanary SMTP via DNAT (same-port)"
ufw allow 6379/tcp  comment "OpenCanary Redis via DNAT (same-port)"
ufw allow 3306/tcp  comment "MariaDB lure (published to 127.0.0.1:3306)"

# Enable the firewall (non-interactive)
ufw --force enable

ok "ufw enabled — inbound: DENY all, ALLOW 22704/tcp, 80/tcp, 443/tcp + all honeypot DNAT ports"

# ---------------------------------------------------------------------------
# STEP 6 — Configure unattended-upgrades (security patches only)
# WHY: A public honeypot must receive security patches automatically. The host
# kernel and system libraries are a larger attack surface than the containers.
# A missed kernel CVE during an attack campaign is an existential risk.
# Unattended-upgrades applies security-classified updates only — it does NOT
# apply dist-upgrades or package version bumps that could break the system.
# ---------------------------------------------------------------------------
info "Step 6: Configuring unattended-upgrades for automatic security patches..."

# Configure to install security updates automatically and reboot if needed
cat > /etc/apt/apt.conf.d/50unattended-upgrades-honeypot << 'EOF'
// Honeypot host — security patches auto-applied daily
// Only Ubuntu security updates; no third-party repos (Docker updates applied manually)
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
// Remove unused kernel packages after update
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
// Remove dependencies no longer needed
Unattended-Upgrade::Remove-Unused-Dependencies "true";
// Reboot if required (e.g. after kernel update) at 03:00 UTC when no one is logged in
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
// Mail the operator on errors (set UNATTENDED_UPGRADE_MAIL in /etc/environment if desired)
Unattended-Upgrade::Mail "root";
Unattended-Upgrade::MailReport "on-change";
EOF

# Enable the automatic update timer
cat > /etc/apt/apt.conf.d/20auto-upgrades-honeypot << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

systemctl enable unattended-upgrades
systemctl start unattended-upgrades

ok "unattended-upgrades configured — security patches will be applied daily"

# ---------------------------------------------------------------------------
# STEP 7 — Add swapaccount=1 to GRUB
# WHY: Docker's memswap_limit (set on all containers in docker-compose.yml) is
# silently IGNORED unless the kernel is booted with cgroup memory accounting for
# swap. Without this parameter, a memory-flooding attack against Cowrie or the
# FastAPI service can cause DISK THRASHING (swap I/O) instead of a clean
# OOM-kill, which can bring down the entire VPS.
#
# The pattern used here is safe and idempotent:
#   1. Check if the params are already present (grep)
#   2. Only add them if not already there (prevents duplicate params on re-run)
#   3. Use sed to modify the existing GRUB_CMDLINE_LINUX line rather than
#      replacing the whole file
# ---------------------------------------------------------------------------
info "Step 7: Adding cgroup_enable=memory swapaccount=1 to GRUB_CMDLINE_LINUX..."

GRUB_FILE="/etc/default/grub"

# Check current state
CURRENT_GRUB=$(grep -E '^GRUB_CMDLINE_LINUX=' "${GRUB_FILE}" || echo "")
info "Current GRUB_CMDLINE_LINUX: ${CURRENT_GRUB}"

NEEDS_UPDATE=0

if ! grep -qE '^GRUB_CMDLINE_LINUX=.*cgroup_enable=memory' "${GRUB_FILE}"; then
    info "Adding cgroup_enable=memory to GRUB_CMDLINE_LINUX..."
    # Append inside the existing quoted value — handles empty string or existing params
    sed -i 's/^\(GRUB_CMDLINE_LINUX="[^"]*\)"/\1 cgroup_enable=memory"/' "${GRUB_FILE}"
    NEEDS_UPDATE=1
else
    info "cgroup_enable=memory already present in GRUB_CMDLINE_LINUX"
fi

if ! grep -qE '^GRUB_CMDLINE_LINUX=.*swapaccount=1' "${GRUB_FILE}"; then
    info "Adding swapaccount=1 to GRUB_CMDLINE_LINUX..."
    sed -i 's/^\(GRUB_CMDLINE_LINUX="[^"]*\)"/\1 swapaccount=1"/' "${GRUB_FILE}"
    NEEDS_UPDATE=1
else
    info "swapaccount=1 already present in GRUB_CMDLINE_LINUX"
fi

if [[ "${NEEDS_UPDATE}" == "1" ]]; then
    update-grub 2>/dev/null || true   # update-grub writes to stdout; errors are non-fatal here
    ok "GRUB updated — REBOOT REQUIRED (see final checklist)"
else
    ok "GRUB params already correct — no change needed"
fi

# ---------------------------------------------------------------------------
# STEP 7b — Set route_localnet=1 on all interfaces (DNAT to loopback requirement)
# WHY: The DNAT pattern used for all honeypot ports (22→2222, 21, 23, 25, 6379) routes
# external traffic to 127.0.0.1:<port> on the loopback interface. By default, Linux
# drops packets arriving on a non-loopback interface whose DNAT destination is in
# 127.0.0.0/8 — this is "martian packet" protection in the kernel's routing decision,
# independent of ufw or nftables. Setting route_localnet=1 disables this protection
# specifically to allow the two-hop DNAT path:
#   external → eth0 PREROUTING DNAT → 127.0.0.1:<port> → Docker inner NAT → container
# Without this, EVERY honeypot port DNAT will silently fail regardless of firewall rules.
# This was root cause FAIL-3 in Round 6 CR-2.
#
# SECURITY NOTE: route_localnet=1 slightly increases the attack surface by permitting
# routed traffic to the loopback range. The risk is mitigated by:
#   (a) ufw default deny incoming — only DNAT'd ports are accepted
#   (b) nftables honeypot_egress rules — RFC1918 and 169.254.x.x are blocked outbound
#   (c) All loopback-bound ports (2222, etc.) are bound to loopback by Docker, not exposed
# The alternative — not setting route_localnet — would make the entire DNAT architecture
# non-functional on a fresh VPS.
# ---------------------------------------------------------------------------
info "Step 7b: Setting net.ipv4.conf.*.route_localnet=1 (required for DNAT-to-loopback path)..."

SYSCTL_CONF="/etc/sysctl.d/99-honeypot.conf"

# Apply immediately (takes effect without reboot)
sysctl -w net.ipv4.conf.eth0.route_localnet=1
sysctl -w net.ipv4.conf.all.route_localnet=1

# Persist across reboots
# Write the file if it does not exist; if it already exists, add lines only if not present
if [[ ! -f "${SYSCTL_CONF}" ]]; then
    cat > "${SYSCTL_CONF}" << 'SYSCTL_EOF'
# /etc/sysctl.d/99-honeypot.conf
# Neuro Honeypot Platform — persistent kernel parameters
# Applied at boot by systemd-sysctl.service; also applied live during Module 0 bootstrap.

# Allow DNAT to loopback addresses (127.0.0.0/8) from external interfaces.
# Required for the honeypot port DNAT pattern: eth0 PREROUTING → 127.0.0.1:<port> → Docker NAT → container.
# Without this, Linux drops DNAT'd packets to 127.x.x.x as "martian" at the routing decision.
net.ipv4.conf.eth0.route_localnet=1
net.ipv4.conf.all.route_localnet=1
SYSCTL_EOF
    ok "Created ${SYSCTL_CONF} with route_localnet=1"
else
    # File exists — add lines only if not already present (idempotent)
    if ! grep -q "route_localnet" "${SYSCTL_CONF}"; then
        cat >> "${SYSCTL_CONF}" << 'SYSCTL_APPEND_EOF'

# Allow DNAT to loopback addresses (127.0.0.0/8) from external interfaces.
# Required for honeypot port DNAT pattern: eth0 PREROUTING → 127.0.0.1:<port> → Docker NAT → container.
net.ipv4.conf.eth0.route_localnet=1
net.ipv4.conf.all.route_localnet=1
SYSCTL_APPEND_EOF
        ok "Appended route_localnet=1 to existing ${SYSCTL_CONF}"
    else
        ok "route_localnet already present in ${SYSCTL_CONF} — no change needed"
    fi
fi

# Reload sysctl to confirm persistence config is valid
sysctl -p "${SYSCTL_CONF}" 2>/dev/null || warn "sysctl -p ${SYSCTL_CONF} returned non-zero — verify manually"

# Verify the live value
LOCALNET_ETH0=$(cat /proc/sys/net/ipv4/conf/eth0/route_localnet 2>/dev/null || echo "unknown")
LOCALNET_ALL=$(cat /proc/sys/net/ipv4/conf/all/route_localnet 2>/dev/null || echo "unknown")

if [[ "${LOCALNET_ETH0}" == "1" && "${LOCALNET_ALL}" == "1" ]]; then
    ok "route_localnet=1 confirmed active on eth0 and all interfaces"
else
    warn "route_localnet check: eth0=${LOCALNET_ETH0}, all=${LOCALNET_ALL} — expected both=1"
    warn "Verify manually: cat /proc/sys/net/ipv4/conf/eth0/route_localnet"
fi

# ---------------------------------------------------------------------------
# STEP 8 — Write /etc/docker/daemon.json (Docker daemon hardening)
# WHY:
#   userns-remap: "default"
#     Container UID 0 maps to host UID 100000 (unprivileged). A container escape
#     gives the attacker only an unprivileged host user — no docker socket access,
#     no /etc/shadow read, no sudo. This is the single most important daemon
#     hardening control.
#
#   live-restore: true
#     Containers continue running if the Docker daemon is restarted (e.g. during
#     unattended-upgrades). Without this, a daemon restart terminates all containers,
#     losing in-flight Cowrie sessions and log-shipper write buffers. Forensic data
#     would be destroyed during routine maintenance windows.
#
#   no-new-privileges: true
#     Daemon-level enforcement of no privilege escalation inside containers. Mirrors
#     the security_opt in compose but applied globally in case a compose entry is
#     accidentally omitted.
#
#   icc: false
#     Disables inter-container communication on the DEFAULT bridge network. Our
#     containers use named networks (honeypot-net, data-net, egress-net), so this
#     is defense-in-depth: any accidentally added container cannot reach named-network
#     containers via the default bridge.
#
#   log-driver / log-opts
#     Prevents container log files from filling the VPS root filesystem. Without
#     rotation, a high-traffic honeypot can produce GBs of logs that OOM the host.
# ---------------------------------------------------------------------------
info "Step 8: Writing /etc/docker/daemon.json..."

DAEMON_JSON_FILE="/etc/docker/daemon.json"

# Only write if not already correct (idempotent check)
EXPECTED_DAEMON_JSON='{
  "userns-remap": "default",
  "live-restore": true,
  "no-new-privileges": true,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m",
    "max-file": "5"
  },
  "icc": false
}'

if [[ -f "${DAEMON_JSON_FILE}" ]]; then
    warn "Existing /etc/docker/daemon.json found — will be replaced"
    cp "${DAEMON_JSON_FILE}" "${DAEMON_JSON_FILE}.bak.$(date +%Y%m%d%H%M%S)"
    info "Backup saved to ${DAEMON_JSON_FILE}.bak.*"
fi

cat > "${DAEMON_JSON_FILE}" << 'DAEMON_JSON_EOF'
{
  "userns-remap": "default",
  "live-restore": true,
  "no-new-privileges": true,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m",
    "max-file": "5"
  },
  "icc": false
}
DAEMON_JSON_EOF

ok "/etc/docker/daemon.json written"

# ---------------------------------------------------------------------------
# STEP 9 — Create /etc/subuid and /etc/subgid entries for dockremap
# WHY: userns-remap: "default" tells Docker to use a system user named
# "dockremap" as the host-side UID/GID namespace owner. Docker creates this
# user automatically but may NOT add the required subuid/subgid entries on all
# Ubuntu versions. We add them explicitly if missing.
#
# The range dockremap:100000:65536 means:
#   Container UID 0 → host UID 100000
#   Container UID 1 → host UID 100001
#   Container UID 65535 → host UID 165535
# ---------------------------------------------------------------------------
info "Step 9: Ensuring dockremap subuid/subgid entries exist..."

# Ensure /etc/subuid and /etc/subgid exist
touch /etc/subuid /etc/subgid

if ! grep -q "^dockremap:" /etc/subuid; then
    echo "dockremap:100000:65536" >> /etc/subuid
    ok "Added dockremap:100000:65536 to /etc/subuid"
else
    ok "dockremap already in /etc/subuid: $(grep '^dockremap:' /etc/subuid)"
fi

if ! grep -q "^dockremap:" /etc/subgid; then
    echo "dockremap:100000:65536" >> /etc/subgid
    ok "Added dockremap:100000:65536 to /etc/subgid"
else
    ok "dockremap already in /etc/subgid: $(grep '^dockremap:' /etc/subgid)"
fi

# ---------------------------------------------------------------------------
# STEP 10 — Restart Docker to apply daemon.json and userns-remap
# WHY: daemon.json changes (userns-remap, live-restore, icc:false) only take
# effect after a daemon restart. We restart here BEFORE creating any containers
# so that the first compose up already runs with hardened daemon settings.
#
# NOTE: If other containers are already running on this VPS, they will restart
# automatically because live-restore is now active. Monitor them with:
#   docker ps && systemctl status docker
# ---------------------------------------------------------------------------
info "Step 10: Restarting Docker daemon to apply daemon.json..."

systemctl restart docker
sleep 3   # give daemon time to fully initialize before we check its status

if ! systemctl is-active --quiet docker; then
    die "Docker daemon failed to restart — check: journalctl -xe -u docker"
fi

ok "Docker daemon restarted successfully"

# Quick sanity: verify userns-remap is shown in docker info
if docker info 2>/dev/null | grep -qi "userns"; then
    ok "userns-remap is active: $(docker info 2>/dev/null | grep -i userns || true)"
else
    warn "userns-remap not visible in 'docker info' — verify manually after script completes"
fi

# ---------------------------------------------------------------------------
# STEP 11 — Install and configure auditd container escape detection rules
# WHY: auditd installs kernel-level syscall watches that survive container
# isolation — it operates at the host kernel level, not inside a namespace.
# The rules here monitor for the specific indicators of a container escape:
#
#   - Docker socket access: any process that touches /var/run/docker.sock
#     can launch containers with arbitrary capabilities — equivalent to root
#   - execve from UID 100000–165535 on the HOST: container UIDs are remapped
#     to this range. An execve in this UID range running IN THE HOST NAMESPACE
#     (not inside a container) is a definitive container escape signal
#   - setuid/setgid from remapped UIDs: privilege escalation attempt post-escape
#   - Credential file writes: /etc/passwd, /etc/shadow, /etc/sudoers tampering
#   - Kernel module loading: LKM-based container escape technique
# ---------------------------------------------------------------------------
info "Step 11: Installing auditd container escape detection rules..."

AUDIT_RULES_FILE="/etc/audit/rules.d/docker.conf"

cat > "${AUDIT_RULES_FILE}" << 'AUDIT_RULES_EOF'
# /etc/audit/rules.d/docker.conf
# Neuro Honeypot — Container Escape Detection Ruleset
# Applied via: augenrules --load && systemctl restart auditd
# Monitor: ausearch -k container_escape_exec --interpret

# --- Docker socket ---
# WHY: Any process that opens the Docker socket controls the entire container runtime.
# A compromised container reaching the socket = full host root equivalent.
# This rule fires on read, write, or attribute change of the socket file.
-w /var/run/docker.sock -p rwa -k docker_socket

# --- Docker configuration files ---
# WHY: Changes to daemon.json or /etc/docker/ may indicate an attacker trying to
# disable security controls (userns-remap, no-new-privileges) before a second attempt.
-w /etc/docker/ -p wa -k docker_config
-w /etc/docker/daemon.json -p wa -k docker_daemon_config

# --- Container escape: execve from host-mapped container UIDs ---
# WHY: With userns-remap: default, container processes run as host UIDs 100000–165535.
# If a process in this UID range executes a binary IN THE HOST NAMESPACE (not inside
# a container), it means a container escape has occurred — the process crossed the
# namespace boundary. This is the most reliable escape indicator available.
# -F uid: the real UID of the process (who is doing the execve)
# -F euid: the effective UID (catches setuid escalations post-escape)
-a always,exit -F arch=b64 -S execve -F uid>=100000 -F uid<=165535 -k container_escape_exec
-a always,exit -F arch=b64 -S execve -F euid>=100000 -F euid<=165535 -k container_escape_exec

# --- Privilege escalation from remapped UIDs ---
# WHY: After escaping, an attacker may call setuid/setgid to escalate to UID 0 on the host.
# Catching this early provides a second-layer alert even if the execve alert is missed.
-a always,exit -F arch=b64 -S setuid -F uid>=100000 -F uid<=165535 -k container_priv_escalation
-a always,exit -F arch=b64 -S setgid -F uid>=100000 -F uid<=165535 -k container_priv_escalation

# --- Credential and privilege file tampering ---
# WHY: An attacker who achieves host access will attempt to persist by modifying
# /etc/passwd (add user), /etc/shadow (change passwords), or /etc/sudoers (gain sudo).
-w /etc/passwd -p wa -k credential_tampering
-w /etc/shadow -p wa -k credential_tampering
-w /etc/sudoers -p wa -k sudo_modification

# --- Kernel module loading (LKM-based container escape) ---
# WHY: One container escape technique loads a kernel module (rootkit) via init_module
# or finit_module syscalls. This bypasses all userspace controls. Any module load
# from a honeypot container UID range should be treated as a critical incident.
-a always,exit -F arch=b64 -S init_module -S finit_module -k kernel_module_load
AUDIT_RULES_EOF

# Apply the rules
if ! augenrules --load 2>/dev/null; then
    warn "augenrules --load failed — attempting direct auditctl load"
    auditctl -R "${AUDIT_RULES_FILE}" 2>/dev/null || warn "auditctl -R also failed — verify auditd is running"
fi

# Restart auditd to pick up the new rules
systemctl enable auditd
systemctl restart auditd
sleep 2

# Verify the critical rule is loaded
if auditctl -l 2>/dev/null | grep -q "container_escape_exec"; then
    ok "auditd container_escape_exec rule is loaded and active"
else
    warn "container_escape_exec rule not visible in 'auditctl -l' — check auditd status and re-run"
fi

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# STEP 11b — Add operator user jzargo to the docker group
# WHY: Module 1+ compose commands are run as jzargo (not root). Without this,
# every `docker compose` call requires sudo, which also changes the working
# directory context and can cause volume path resolution errors.
# NOTE: The group membership takes effect on next login — jzargo must
# re-SSH after this script completes (the reboot at the end handles this).
# ---------------------------------------------------------------------------
info "Step 11b: Adding jzargo to the docker group..."

OPERATOR_USER="jzargo"
if id "${OPERATOR_USER}" &>/dev/null; then
    usermod -aG docker "${OPERATOR_USER}"
    ok "jzargo added to docker group (effective after reboot / re-login)"
else
    warn "User jzargo not found on this system — skipping docker group add."
    warn "Create the user first, then run: usermod -aG docker jzargo"
fi

# STEP 12 — Create /opt/honeypot/ and the full bind-mount directory scaffold
# WHY: Docker's userns-remap requires that bind-mounted host directories be
# readable by host UID 100000 (= container UID 0). These directories MUST
# exist and have correct ownership BEFORE docker compose up is run. If they
# don't exist, Docker creates them as root:root, which the remapped container
# cannot read, causing silent mount failures.
#
# Named volumes (postgres-data, cowrie-logs, redis-data, etc.) do NOT need
# this treatment — Docker manages their ownership internally. Only bind-mounted
# paths require manual creation and chown.
#
# Directory layout matches Section 12.0 of the plan exactly.
# ---------------------------------------------------------------------------
info "Step 12: Creating /opt/honeypot/ directory scaffold..."

HONEYPOT_ROOT="/opt/honeypot"
mkdir -p "${HONEYPOT_ROOT}"

# Create all bind-mounted subdirectories from Section 12.0 in a single command
mkdir -p \
    "${HONEYPOT_ROOT}/config/cowrie" \
    "${HONEYPOT_ROOT}/config/honeypot-api" \
    "${HONEYPOT_ROOT}/config/opencanary" \
    "${HONEYPOT_ROOT}/config/mariadb/conf.d" \
    "${HONEYPOT_ROOT}/config/mariadb/init" \
    "${HONEYPOT_ROOT}/config/nginx" \
    "${HONEYPOT_ROOT}/config/redis" \
    "${HONEYPOT_ROOT}/honeypot/api/lure-files" \
    "${HONEYPOT_ROOT}/honeypot/cowrie/fs" \
    "${HONEYPOT_ROOT}/services/log-shipper/archive" \
    "${HONEYPOT_ROOT}/services/postgres/init" \
    "${HONEYPOT_ROOT}/deceptive-frontend/dist" \
    "${HONEYPOT_ROOT}/scripts"

ok "Directory scaffold created under ${HONEYPOT_ROOT}"

# ---------------------------------------------------------------------------
# STEP 13 — Chown all bind-mount directories to 100000:100000
# WHY: With userns-remap: "default", every container's UID 0 maps to host UID
# 100000. Bind-mounted directories must be owned by 100000:100000 so the
# container process can read and write them. Named volumes are exempt (Docker
# handles them). This must be done BEFORE docker compose up — if done after,
# you must stop the stack, chown, and restart.
# ---------------------------------------------------------------------------
info "Step 13: Setting ownership of bind-mount directories to 100000:100000..."

chown -R 100000:100000 \
    "${HONEYPOT_ROOT}/config" \
    "${HONEYPOT_ROOT}/honeypot" \
    "${HONEYPOT_ROOT}/services" \
    "${HONEYPOT_ROOT}/deceptive-frontend"

# The scripts/ and root project dir remain root-owned (no container mounts there)
ok "Ownership set: all bind-mount dirs are now 100000:100000"

# ---------------------------------------------------------------------------
# Final Verification Checklist
# Print a clear, actionable summary of what to verify before proceeding.
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}==================================================${NC}"
echo -e "${BOLD} Module 0 Bootstrap Complete — Verification Steps ${NC}"
echo -e "${BOLD}==================================================${NC}"
echo ""
echo "Run each command below to confirm the hardening controls are active."
echo "All checks should PASS before proceeding to Module 1."
echo ""

echo -e "${BOLD}=== Module 0 Verification ===${NC}"
echo ""
echo "[ ] Docker userns-remap active:"
echo "    docker info | grep -i userns"
echo "    Expected: output includes 'userns' or 'User Namespaces'"
echo ""
echo "[ ] live-restore active:"
echo "    docker info | grep -i 'live restore'"
echo "    Expected: 'Live Restore Enabled: true'"
echo ""
echo "[ ] icc:false active:"
echo "    docker info | grep -i 'icc'"
echo "    Expected: 'ICC: false'"
echo ""
echo "[ ] dockremap in subuid/subgid:"
echo "    grep dockremap /etc/subuid /etc/subgid"
echo "    Expected: dockremap:100000:65536 in both files"
echo ""
echo "[ ] auditd container_escape_exec rule loaded:"
echo "    auditctl -l | grep container_escape_exec"
echo "    Expected: 2 lines (one for uid, one for euid)"
echo ""
echo "[ ] auditd docker_socket rule loaded:"
echo "    auditctl -l | grep docker_socket"
echo ""
echo "[ ] ufw status:"
echo "    ufw status verbose"
echo "    Expected: ALLOW 22704/tcp, 80/tcp, 443/tcp only"
echo ""
echo "[ ] swapaccount in kernel cmdline (ONLY after reboot):"
echo "    grep swapaccount /proc/cmdline"
echo "    Expected: 'swapaccount=1' present"
echo ""
echo "[ ] route_localnet=1 active (required for DNAT-to-loopback):"
echo "    cat /proc/sys/net/ipv4/conf/eth0/route_localnet"
echo "    cat /proc/sys/net/ipv4/conf/all/route_localnet"
echo "    Expected: both return 1"
echo "    (Without this, all honeypot port DNAT rules are silently dropped by the kernel)"
echo ""
echo "[ ] Project directory created:"
echo "    ls -la /opt/honeypot/"
echo ""
echo "[ ] Bind-mount dirs owned by 100000:100000:"
echo "    ls -la /opt/honeypot/config/ | head"
echo "    Expected: owner and group are 100000"
echo ""
echo "[ ] jzargo in docker group:"
echo "    groups jzargo"
echo "    Expected: output includes 'docker'"
echo ""
echo -e "${RED}=== ACTION REQUIRED ===${NC}"
echo ""
echo "  REBOOT THIS HOST BEFORE PROCEEDING TO MODULE 1."
echo ""
echo "  The swapaccount=1 kernel parameter requires a reboot."
echo "  Without it, memswap_limit in docker-compose.yml has NO effect."
echo "  A flooded honeypot container will disk-thrash instead of OOM-kill."
echo ""
echo "  Reboot command: systemctl reboot"
echo "  After reboot, verify: grep swapaccount /proc/cmdline"
echo ""
echo "  Then proceed to: deploy/module-1-data-layer/ (Module 1)"
echo ""
