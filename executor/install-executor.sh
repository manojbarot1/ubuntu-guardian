#!/usr/bin/env bash
# Installs Guardian's root helper (needed only for Start/Stop/Enable/Disable of system services).
# Usage: sudo bash install-executor.sh            (install)
#        sudo bash install-executor.sh --remove   (uninstall)
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo."; exit 2; }
user="${SUDO_USER:-}"
[[ -n "$user" && "$user" != root ]] || { echo "Run via sudo from the dashboard user's account."; exit 2; }
here="$(cd -- "$(dirname -- "$0")" && pwd)"

if [[ "${1:-}" == "--remove" ]]; then
  systemctl disable --now guardian-exec.socket 2>/dev/null || true
  rm -f /etc/systemd/system/guardian-exec.socket /etc/systemd/system/guardian-exec@.service
  rm -rf /usr/local/lib/guardian
  systemctl daemon-reload
  echo "Guardian root helper removed."
  exit 0
fi

install -d -o root -g root -m 0755 /usr/local/lib/guardian
install -o root -g root -m 0755 "$here/guardian-exec" /usr/local/lib/guardian/guardian-exec

cat > /etc/systemd/system/guardian-exec.socket <<EOF
[Unit]
Description=Guardian root helper socket

[Socket]
ListenStream=/run/guardian-exec.sock
SocketMode=0660
SocketUser=root
SocketGroup=$user
Accept=yes
MaxConnections=4

[Install]
WantedBy=sockets.target
EOF

cat > /etc/systemd/system/guardian-exec@.service <<'EOF'
[Unit]
Description=Guardian root helper (one request)

[Service]
ExecStart=/usr/local/lib/guardian/guardian-exec
StandardInput=socket
StandardOutput=socket
StandardError=journal
TimeoutStartSec=120
NoNewPrivileges=yes
ProtectHome=yes
PrivateTmp=yes
EOF

systemctl daemon-reload
systemctl enable --now guardian-exec.socket
echo "Installed. Socket: /run/guardian-exec.sock (group $user). Remove with: sudo bash $0 --remove"
