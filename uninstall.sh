#!/usr/bin/env bash
# Remove Ubuntu Guardian's service. Your files, Immich and Docker are never touched.
#
#   ./uninstall.sh           stop and remove the systemd units (keeps config, password, history)
#   ./uninstall.sh --purge   also delete ~/.config/guardian and ~/.local/state/guardian
set -euo pipefail
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"

systemctl --user disable --now guardian.service 2>/dev/null || true
rm -f "$UNIT_DIR/guardian.service"
systemctl --user daemon-reload
echo "Guardian service removed."

if [[ -S /run/guardian-exec.sock ]]; then
  echo "The root helper is still installed. Remove it with:"
  echo "  sudo bash $(cd -- "$(dirname -- "$0")" && pwd)/executor/install-executor.sh --remove"
fi

if [[ "${1:-}" == "--purge" ]]; then
  read -rp "Delete Guardian's config, password and history? [y/N] " a
  if [[ "$a" == [yY] ]]; then
    rm -rf "${XDG_CONFIG_HOME:-$HOME/.config}/guardian" "${XDG_STATE_HOME:-$HOME/.local/state}/guardian"
    echo "Config and history deleted."
  fi
fi
