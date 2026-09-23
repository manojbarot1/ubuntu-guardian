"""Exact-duplicate finder with quarantine.

size -> partial hash (first+last 64 KiB) -> full SHA-256. Only byte-identical files are grouped;
visually similar photos are a different problem and are deliberately not handled here.
Protected paths (Immich, databases, Docker, backups) are never entered.
Reads are rate-limited and pause while the system is busy.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

from . import config as C

CHUNK = 1 << 20
EDGE = 64 * 1024
SKIP_DIRS = {".git", "node_modules", ".cache", "__pycache__", ".venv", ".vendor", ".local", "snap", ".guardian-quarantine",
             "$RECYCLE.BIN", "System Volume Information", ".Trash-1000"}


class Scanner:
    def __init__(self, cfg, db, gov):
        self.cfg, self.db, self.gov = cfg, db, gov
        self.thread: threading.Thread | None = None
        self.stop = threading.Event()
        self.progress: dict = {}

    def running(self) -> bool:
        return bool(self.thread and self.thread.is_alive())

    def start(self, roots: list[str]) -> int:
        if self.running():
            raise RuntimeError("a scan is already running")
        clean = []
        for r in roots:
            r = os.path.realpath(os.path.expanduser(r))
            if not os.path.isdir(r):
                raise ValueError(f"not a directory: {r}")
            if C.is_protected(r, self.cfg):
                raise ValueError(f"protected path cannot be scanned: {r}")
            clean.append(r)
        if not clean:
            raise ValueError("choose at least one folder")
        sid = self.db.execute("INSERT INTO dup_scans (started, roots, status) VALUES (?,?,?)",
                              (int(time.time()), json.dumps(clean), "running")).lastrowid
        self.stop.clear()
        self.thread = threading.Thread(target=self._run, args=(sid, clean), daemon=True, name="dup-scan")
        self.thread.start()
        return sid

    def cancel(self) -> None:
        self.stop.set()

    # ------------------------------------------------------------------
    def _run(self, sid: int, roots: list[str]) -> None:
        try:
            os.nice(5)  # scans are background work, below Guardian's own collectors
        except OSError:
            pass
        try:
            self._scan(sid, roots)
        except Exception as e:  # record, never crash Guardian
            self.db.execute("UPDATE dup_scans SET status='failed', finished=?, message=? WHERE id=?",
                            (int(time.time()), str(e)[:500], sid))

    def _scan(self, sid: int, roots: list[str]) -> None:
        min_size = self.cfg["duplicates"]["min_size_bytes"]
        by_size: dict[int, list[tuple[str, float]]] = {}
        seen_inodes = set()
        files = skipped_protected = dirs = 0
        self.progress = {"scan": sid, "phase": "listing files", "files": 0, "started": time.time()}
        for root in roots:
            for dirpath, dirnames, filenames in os.walk(root):
                if self.stop.is_set():
                    return self._finish(sid, "cancelled", 0, 0)
                keep = []
                for d in dirnames:
                    full = os.path.join(dirpath, d)
                    if d in SKIP_DIRS or os.path.islink(full):
                        continue
                    if C.is_protected(full, self.cfg):
                        skipped_protected += 1
                        continue
                    keep.append(d)
                dirnames[:] = keep
                for f in filenames:
                    full = os.path.join(dirpath, f)
                    try:
                        st = os.lstat(full)
                    except OSError:
                        continue
                    if not os.path.isfile(full) or os.path.islink(full) or st.st_size < min_size:
                        continue
                    if (st.st_dev, st.st_ino) in seen_inodes:  # hard link to a file already seen
                        continue
                    seen_inodes.add((st.st_dev, st.st_ino))
                    by_size.setdefault(st.st_size, []).append((full, st.st_mtime))
                    files += 1
                dirs += 1
                if dirs % 100 == 0:
                    self.progress["files"] = files
                    self.gov.pause_if_busy(self.stop)
        self.progress["files"] = files
        self.db.execute("UPDATE dup_scans SET files_seen=? WHERE id=?", (files, sid))

        candidates = {s: v for s, v in by_size.items() if len(v) > 1}
        self.progress.update(phase="partial hashing", candidates=sum(len(v) for v in candidates.values()))
        hashed = 0
        by_partial: dict[tuple, list] = {}
        for size, group in candidates.items():
            for path, mtime in group:
                if self.stop.is_set():
                    return self._finish(sid, "cancelled", 0, 0)
                h = self._partial(path, size)
                if h:
                    by_partial.setdefault((size, h), []).append((path, mtime))
                    hashed += min(size, 2 * EDGE)
        total = sum(size * len(g) for (size, _), g in by_partial.items() if len(g) > 1)
        self.progress.update(phase="full hashing", bytes_total=total, bytes_hashed=0)
        groups, grp, reclaim = [], 0, 0
        for (size, _), group in by_partial.items():
            if len(group) < 2:
                continue
            by_full: dict[str, list] = {}
            for path, mtime in group:
                if self.stop.is_set():
                    return self._finish(sid, "cancelled", 0, 0)
                self.gov.pause_if_busy(self.stop)
                h = self._full(path)
                hashed += size
                self.progress["bytes_hashed"] = self.progress.get("bytes_hashed", 0) + size
                if h:
                    by_full.setdefault(h, []).append((path, mtime))
            for h, members in by_full.items():
                if len(members) > 1:
                    grp += 1
                    reclaim += size * (len(members) - 1)
                    groups.extend((sid, grp, p, size, m, h) for p, m in members)
        self.db.executemany("INSERT INTO dup_files (scan_id, grp, path, size, mtime, hash) VALUES (?,?,?,?,?,?)", groups)
        self.db.execute("UPDATE dup_scans SET bytes_hashed=?, message=? WHERE id=?",
                        (hashed, f"{skipped_protected} protected folders skipped", sid))
        self._finish(sid, "done", grp, reclaim)

    def _finish(self, sid, status, groups, reclaim):
        self.db.execute("UPDATE dup_scans SET status=?, finished=?, groups=?, reclaimable=? WHERE id=?",
                        (status, int(time.time()), groups, reclaim, sid))
        self.progress = {}

    def _throttle(self, nbytes: int, t0: float) -> None:
        rate = self.cfg["duplicates"]["read_rate_mb_s"] * 1024 * 1024
        min_t = nbytes / rate
        spent = time.monotonic() - t0
        if spent < min_t:
            time.sleep(min_t - spent)

    def _partial(self, path: str, size: int) -> str | None:
        try:
            with open(path, "rb") as f:
                h = hashlib.blake2b(f.read(EDGE), digest_size=16)
                if size > 2 * EDGE:
                    f.seek(-EDGE, os.SEEK_END)
                    h.update(f.read(EDGE))
            return h.hexdigest()
        except OSError:
            return None

    def _full(self, path: str) -> str | None:
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while True:
                    t0 = time.monotonic()
                    b = f.read(CHUNK)
                    if not b:
                        break
                    h.update(b)
                    self._throttle(len(b), t0)
                    if self.stop.is_set():
                        return None
            return h.hexdigest()
        except OSError:
            return None


# ---------------------------------------------------------------------- quarantine
def quarantine_root(path: str) -> Path:
    """Quarantine on the same filesystem as the file, so moving is a rename (no copy)."""
    home = Path.home()
    st = os.stat(path)
    if os.stat(home).st_dev == st.st_dev:
        return home / ".guardian-quarantine"
    mount = Path(path).resolve()
    while mount.parent != mount and os.stat(mount.parent).st_dev == st.st_dev:
        mount = mount.parent
    return mount / ".guardian-quarantine"


def quarantine(db, cfg, scan_id: int, paths: list[str]) -> list[dict]:
    """Move chosen duplicates into quarantine. Refuses to leave a group with no copy in place."""
    results = []
    for path in paths:
        row = db.one("SELECT * FROM dup_files WHERE scan_id=? AND path=?", (scan_id, path))
        if not row:
            results.append({"path": path, "ok": False, "error": "not part of this scan"}); continue
        if row["state"] != "present":
            results.append({"path": path, "ok": False, "error": f"already {row['state']}"}); continue
        if C.is_protected(path, cfg):
            results.append({"path": path, "ok": False, "error": "protected path"}); continue
        others = [r for r in db.all("SELECT * FROM dup_files WHERE scan_id=? AND grp=? AND path<>? AND state='present'",
                                    (scan_id, row["grp"], path)) if _unchanged(r)]
        if not others:
            results.append({"path": path, "ok": False, "error": "this is the last remaining copy; keeping it"}); continue
        if not _unchanged(row):
            results.append({"path": path, "ok": False, "error": "file changed since the scan; rescan first"}); continue
        dest = quarantine_root(path) / str(scan_id) / path.lstrip("/")
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            os.rename(path, dest)
        except OSError as e:
            results.append({"path": path, "ok": False, "error": str(e)}); continue
        db.execute("UPDATE dup_files SET state='quarantined', quarantine_path=? WHERE scan_id=? AND path=?",
                   (str(dest), scan_id, path))
        results.append({"path": path, "ok": True, "quarantine_path": str(dest), "kept": others[0]["path"]})
    return results


def restore(db, scan_id: int, paths: list[str]) -> list[dict]:
    results = []
    for path in paths:
        row = db.one("SELECT * FROM dup_files WHERE scan_id=? AND path=? AND state='quarantined'", (scan_id, path))
        if not row:
            results.append({"path": path, "ok": False, "error": "not in quarantine"}); continue
        if os.path.exists(path):
            results.append({"path": path, "ok": False, "error": "a file already exists at the original path"}); continue
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            os.rename(row["quarantine_path"], path)
        except OSError as e:
            results.append({"path": path, "ok": False, "error": str(e)}); continue
        db.execute("UPDATE dup_files SET state='present', quarantine_path=NULL WHERE scan_id=? AND path=?", (scan_id, path))
        results.append({"path": path, "ok": True})
    return results


def purge(db, scan_id: int, paths: list[str]) -> list[dict]:
    """Permanently delete files that are already in quarantine (explicit, strongly confirmed action)."""
    results = []
    for path in paths:
        row = db.one("SELECT * FROM dup_files WHERE scan_id=? AND path=? AND state='quarantined'", (scan_id, path))
        if not row:
            results.append({"path": path, "ok": False, "error": "not in quarantine"}); continue
        q = row["quarantine_path"]
        if "/.guardian-quarantine/" not in q:
            results.append({"path": path, "ok": False, "error": "refusing: not inside a quarantine folder"}); continue
        try:
            os.remove(q)
        except FileNotFoundError:
            pass
        except OSError as e:
            results.append({"path": path, "ok": False, "error": str(e)}); continue
        db.execute("UPDATE dup_files SET state='deleted' WHERE scan_id=? AND path=?", (scan_id, path))
        results.append({"path": path, "ok": True})
    return results


def _unchanged(row: dict) -> bool:
    try:
        st = os.stat(row["path"])
    except OSError:
        return False
    return st.st_size == row["size"] and abs(st.st_mtime - row["mtime"]) < 1e-3
