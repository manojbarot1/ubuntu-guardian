"""Configuration: ~/.config/guardian/config.toml merged over built-in defaults."""
from __future__ import annotations

import os
import tomllib
from pathlib import Path

HOME = Path.home()
INSTALL_DIR = Path(__file__).resolve().parent.parent
EXECUTOR_INSTALL = f"sudo bash {INSTALL_DIR}/executor/install-executor.sh"
CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", HOME / ".config")) / "guardian"
STATE_DIR = Path(os.environ.get("XDG_STATE_HOME", HOME / ".local/state")) / "guardian"
CONFIG_FILE = CONFIG_DIR / "config.toml"

DEFAULTS: dict = {
    "server": {
        "host": "0.0.0.0",
        "port": 8770,
        # Requests from outside these networks are refused before auth.
        "allowed_networks": ["127.0.0.0/8", "::1/128", "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"],
    },
    # Seconds between runs. Heavy collectors are deferred while the system is busy.
    "intervals": {
        "system": 15,
        "processes": 60,
        "containers": 30,
        "services": 300,
        "docker_inventory": 300,
        "storage": 600,
        "network": 300,
        "smart": 3600,
        "immich": 120,
        "dir_sizes": 86400,
        "rules": 300,
        "rollup": 3600,
        "checks": 120,
    },
    "security": {
        "audit_interval": 21600,        # full security review every 6 h (heavy: waits while busy)
        "image_scan_days": 7,           # re-scan container images weekly, only after a first manual scan
        "trivy_image": "aquasec/trivy:latest",
        "trivy_cpus": 1,
        "trivy_memory": "1g",
    },
    # Endpoint health checks shown as status panels. expect: status codes counted as healthy.
    "checks": [
        {"name": "Immich API", "url": "http://127.0.0.1:2283/api/server/ping", "expect": [200]},
        {"name": "Immich web", "url": "http://127.0.0.1:2283/", "expect": [200]},
        {"name": "Internet", "url": "http://connectivitycheck.gstatic.com/generate_204", "expect": [204, 200]},
    ],
    "governor": {
        # System is "busy" above any of these; heavy work waits (up to max_defer x interval).
        "busy_load_per_cpu": 0.85,
        "busy_cpu_percent": 85,
        "busy_mem_available_percent": 8,
        "busy_io_pressure": 20,
        "max_defer": 6,
        # Guardian's own budget: warn when it averages more than this share of one core.
        "self_cpu_budget_percent": 3,
    },
    "retention": {"raw_hours": 48, "hourly_days": 365},
    "immich": {
        "app_dir": str(HOME / "immich-app"),
        "url": "http://127.0.0.1:2283",
        "api_key": "",  # optional: admin API key enables job-queue awareness
        "containers": ["immich_server", "immich_postgres", "immich_machine_learning", "immich_redis"],
        "busy_cpu_percent": 60,  # combined Immich container CPU (% of one core) = "processing"
    },
    # Optional: monitor an existing backup job (Guardian does not ship one). Off unless unit or drive_uuid is set.
    "backup": {
        "unit": "",               # systemd --user unit of your backup job, e.g. "photo-backup" (enables "Run backup now")
        "drive_uuid": "",         # filesystem UUID of the backup drive (lsblk -f): connection and free-space alerts
        "status_file": str(STATE_DIR / "backup-status.json"),  # JSON your job writes: {"result","message","finished",...}
        "log_file": str(STATE_DIR / "backup.log"),
        "max_age_days": 8,
    },
    "protection": {
        # Never scanned for duplicates, never quarantined, never touched by actions.
        "protected_paths": [
            str(HOME / "immich-app"),
            "/var/lib/docker",
            "/var/lib/containerd",
            "/etc",
            "/boot",
            "/usr",
            "/var/lib/postgresql",
        ],
        # Path fragments that are protected anywhere (e.g. backup trees on external drives).
        "protected_patterns": ["/immich-backups/", "/.guardian-quarantine/"],
        # Units the dashboard will refuse to stop/disable.
        "protected_units": [
            "docker.service", "containerd.service", "docker.socket", "dbus.service", "dbus-broker.service",
            "systemd-*", "NetworkManager.service", "wpa_supplicant.service", "udisks2.service", "polkit.service",
            "gdm.service", "ssh.service", "user@*.service", "networkd-dispatcher.service",
        ],
    },
    "duplicates": {
        "default_roots": [str(HOME / "Downloads"), str(HOME / "Documents"), str(HOME / "Pictures"), str(HOME / "Videos")],
        "min_size_bytes": 1048576,
        "read_rate_mb_s": 40,  # throttle hashing so scans never saturate a disk
    },
}


def _merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in over.items():
        out[k] = _merge(base[k], v) if isinstance(v, dict) and isinstance(base.get(k), dict) else v
    return out


def load() -> dict:
    cfg = DEFAULTS
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "rb") as f:
            cfg = _merge(DEFAULTS, tomllib.load(f))
    # Wherever Immich lives, its folder is protected.
    app = os.path.realpath(os.path.expanduser(cfg["immich"]["app_dir"]))
    if app not in [os.path.realpath(p) for p in cfg["protection"]["protected_paths"]]:
        cfg = _merge(cfg, {"protection": {"protected_paths": cfg["protection"]["protected_paths"] + [app]}})
    return cfg


def backup_enabled(cfg: dict) -> bool:
    return bool(cfg["backup"]["unit"] or cfg["backup"]["drive_uuid"])


def is_protected(path: str | os.PathLike, cfg: dict) -> bool:
    p = os.path.realpath(path)
    for root in cfg["protection"]["protected_paths"]:
        r = os.path.realpath(root)
        if p == r or p.startswith(r.rstrip("/") + "/"):
            return True
    return any(frag in p + "/" for frag in cfg["protection"]["protected_patterns"])
