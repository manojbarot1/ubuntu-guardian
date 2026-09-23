"""Small helpers shared by collectors."""
from __future__ import annotations

import http.client
import json
import socket
import subprocess


def run(cmd: list[str], timeout: float = 20) -> str:
    """Run a read-only command, return stdout ('' on failure). Never uses a shell."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return p.stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def run_json(cmd: list[str], timeout: float = 20):
    out = run(cmd, timeout)
    try:
        return json.loads(out) if out.strip() else None
    except json.JSONDecodeError:
        return None


def read(path: str, default: str = "") -> str:
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return default


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float = 10):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._path)
        self.sock = s


def docker_api(path: str, method: str = "GET", timeout: float = 10):
    """Docker Engine API over the local socket.

    Monitoring only ever issues GET. The actions module is the single caller allowed to POST,
    and only to endpoints in its allowlist.
    """
    conn = _UnixHTTPConnection("/var/run/docker.sock", timeout)
    try:
        conn.request(method, path)
        r = conn.getresponse()
        body = r.read()
        if r.status >= 400:
            raise RuntimeError(f"docker {method} {path}: {r.status} {body[:200]!r}")
        return json.loads(body) if body else None
    finally:
        conn.close()


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} PB"
