#!/usr/bin/env bash
# Ubuntu Guardian installer. Run as your normal user (not root) from the cloned repo:
#
#   ./install.sh                         install or update
#   ./install.sh --app-dir /srv/immich   Immich folder, if not auto-detected (default: ~/immich-app)
#
# Safe to re-run: it updates the unit and keeps your config, password and history.
set -Eeuo pipefail

DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
CONF_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/guardian"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
CONF_FILE="$CONF_DIR/config.toml"
app_dir=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --app-dir) app_dir="$2"; shift 2;;
    --yes|-y) shift;;
    -h|--help) sed -n '2,7p' "$0"; exit 0;;
    *) echo "Unknown option: $1"; exit 2;;
  esac
done

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '  \033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -ne 0 ]] || die "Run as your normal user, not root (Guardian runs as a systemd --user service)."

# ---------------------------------------------------------------- 1. prerequisites
bold "1/5  Checking prerequisites"
command -v systemctl >/dev/null || die "systemd is required"
command -v python3 >/dev/null || die "python3 is required: sudo apt install python3"
python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' || die "Python 3.11+ is required (found $(python3 -V))"
ok "$(python3 -V)"
command -v busctl >/dev/null || warn "busctl missing: drive health (SMART) will be unavailable"
if command -v docker >/dev/null && docker info >/dev/null 2>&1; then
  ok "Docker reachable as $USER"
  have_docker=1
else
  have_docker=0
  warn "Docker is not reachable as $USER. Container and Immich monitoring need it: sudo usermod -aG docker $USER, then log out and in."
fi

# ---------------------------------------------------------------- 2. python dependencies
bold "2/5  Installing Python dependencies into $DIR/.vendor"
need=(fastapi uvicorn)
python3 -c 'import psutil' 2>/dev/null || need+=(psutil)
if PYTHONPATH="$DIR/.vendor" python3 -c 'import fastapi, uvicorn, psutil' 2>/dev/null; then
  ok "already installed"
elif python3 -m pip --version >/dev/null 2>&1; then
  python3 -m pip install --quiet --upgrade --target "$DIR/.vendor" "${need[@]}"
  ok "installed with pip: ${need[*]}"
elif [[ $have_docker == 1 ]]; then
  pyver="$(python3 -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')"
  echo "  pip is not installed; using the python:$pyver-slim container to fetch packages (no system changes)"
  docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$DIR":/w "python:$pyver-slim" \
    pip install --quiet --no-cache-dir --target /w/.vendor "${need[@]}"
  ok "installed via Docker: ${need[*]}"
else
  die "Need pip or Docker to install dependencies: sudo apt install python3-pip (or python3-fastapi python3-uvicorn python3-psutil)"
fi
PYTHONPATH="$DIR/.vendor:$DIR" python3 -c 'import guardian.api' || die "dependency check failed"

# ---------------------------------------------------------------- 3. Immich
bold "3/5  Locating Immich"
mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"
if [[ -z "$app_dir" && $have_docker == 1 ]]; then
  app_dir="$(docker inspect immich_server --format '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' 2>/dev/null || true)"
fi
app_dir="${app_dir:-$HOME/immich-app}"
if [[ -f "$app_dir/docker-compose.yml" ]]; then
  ok "Immich found in $app_dir"
  if [[ "$app_dir" != "$HOME/immich-app" ]] && ! grep -qs '^app_dir' "$CONF_FILE"; then
    printf '\n[immich]\napp_dir = "%s"\n' "$app_dir" >> "$CONF_FILE"; chmod 600 "$CONF_FILE"
    ok "saved app_dir in $CONF_FILE"
  fi
else
  warn "No Immich deployment found in $app_dir (system monitoring still works). Use --app-dir to point at it."
fi

# ---------------------------------------------------------------- 5. systemd units
bold "4/5  Installing the systemd user unit"
mkdir -p "$UNIT_DIR"
rm -f "$UNIT_DIR/guardian.service"   # replace an old symlink instead of writing through it
sed "s#@INSTALL_DIR@#$DIR#g" "$DIR/systemd/guardian.service" > "$UNIT_DIR/guardian.service"
chmod +x "$DIR/bin/"* "$DIR/executor/guardian-exec" "$DIR/executor/install-executor.sh"
systemctl --user daemon-reload
if loginctl enable-linger "$USER" 2>/dev/null; then
  ok "linger enabled: Guardian keeps running when you log out"
else
  warn "could not enable linger; run: sudo loginctl enable-linger $USER"
fi
systemctl --user enable --now guardian.service >/dev/null 2>&1
systemctl --user restart guardian.service
ok "guardian.service running"

# ---------------------------------------------------------------- 6. done
bold "5/5  Checking the dashboard"
port="$(PYTHONPATH="$DIR/.vendor:$DIR" python3 -c 'from guardian import config; print(config.load()["server"]["port"])')"
for _ in $(seq 20); do curl -fs "http://127.0.0.1:$port/api/health" >/dev/null 2>&1 && break; sleep 1; done
curl -fs "http://127.0.0.1:$port/api/health" >/dev/null 2>&1 && ok "responding on port $port" || warn "not responding yet: journalctl --user -u guardian -n 50"

ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo
bold "Done."
echo "  Dashboard:  http://${ip:-localhost}:$port   (home network only)"
if [[ -f "$CONF_DIR/initial-password.txt" ]]; then
  echo "  Password:   $(sed -n 's/^password: //p' "$CONF_DIR/initial-password.txt")   (also in $CONF_DIR/initial-password.txt)"
  echo "              change it in Settings, or run: $DIR/bin/guardian-passwd"
fi
if [[ ! -S /run/guardian-exec.sock ]]; then
  echo "  Optional:   sudo bash $DIR/executor/install-executor.sh   (enables Start/Stop/Enable/Disable for services)"
fi
