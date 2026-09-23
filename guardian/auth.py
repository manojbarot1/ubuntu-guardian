"""Single-user password auth with scrypt, in-memory sessions and login rate limiting."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time

from . import config as C

AUTH_FILE = C.CONFIG_DIR / "auth.json"
INITIAL_PW_FILE = C.CONFIG_DIR / "initial-password.txt"
SESSION_TTL = 12 * 3600


def _hash(pw: str, salt: bytes) -> str:
    return hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1).hex()


class Auth:
    def __init__(self):
        self.sessions: dict[str, tuple[str, float]] = {}
        self.failures: dict[str, list[float]] = {}
        C.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        if not AUTH_FILE.exists():
            pw = secrets.token_urlsafe(12)
            self.set_password(pw)
            fd = os.open(INITIAL_PW_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(f"Guardian dashboard\nuser: admin\npassword: {pw}\n\nChange it in Settings, then delete this file.\n")

    def set_password(self, pw: str) -> None:
        pw = pw.strip()
        if len(pw) < 10:
            raise ValueError("password must be at least 10 characters")
        salt = secrets.token_bytes(16)
        fd = os.open(AUTH_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"user": "admin", "salt": salt.hex(), "hash": _hash(pw, salt)}, f)
        self.sessions.clear()

    def rate_limited(self, client: str) -> bool:
        now = time.time()
        recent = [t for t in self.failures.get(client, []) if now - t < 300]
        self.failures[client] = recent
        return len(recent) >= 5

    def login(self, user: str, pw: str, client: str) -> str | None:
        if self.rate_limited(client):
            return None
        a = json.loads(AUTH_FILE.read_text())
        # Single-user dashboard: only the password is checked (a browser-autofilled username must not lock you out).
        ok = hmac.compare_digest(_hash(pw.strip(), bytes.fromhex(a["salt"])), a["hash"])
        if not ok:
            self.failures.setdefault(client, []).append(time.time())
            return None
        self.failures.pop(client, None)
        token = secrets.token_urlsafe(32)
        self.sessions[token] = (a["user"], time.time() + SESSION_TTL)
        return token

    def check(self, token: str | None) -> str | None:
        if not token:
            return None
        s = self.sessions.get(token)
        if not s or s[1] < time.time():
            self.sessions.pop(token, None)
            return None
        return s[0]

    def logout(self, token: str | None) -> None:
        self.sessions.pop(token or "", None)
