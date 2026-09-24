"""SQLite storage. One connection per thread; WAL so the API reads while collectors write."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

-- Wide row per sample: cheap to write, cheap to chart.
CREATE TABLE IF NOT EXISTS samples (
  ts INTEGER PRIMARY KEY,
  cpu REAL, load1 REAL, mem_used REAL, mem_avail_pct REAL, swap_used REAL,
  psi_cpu REAL, psi_mem REAL, psi_io REAL,
  disk_read_bps REAL, disk_write_bps REAL, net_rx_bps REAL, net_tx_bps REAL,
  self_cpu REAL, self_rss REAL, busy INTEGER
);
CREATE TABLE IF NOT EXISTS samples_hourly (
  ts INTEGER PRIMARY KEY,
  cpu REAL, cpu_max REAL, load1 REAL, mem_used REAL, swap_used REAL,
  disk_read_bps REAL, disk_write_bps REAL, net_rx_bps REAL, net_tx_bps REAL, self_cpu REAL
);
CREATE TABLE IF NOT EXISTS container_samples (
  ts INTEGER, name TEXT, cpu REAL, mem REAL, PRIMARY KEY (ts, name)
);
CREATE TABLE IF NOT EXISTS fs_usage (
  ts INTEGER, mount TEXT, used INTEGER, total INTEGER, PRIMARY KEY (ts, mount)
);
CREATE TABLE IF NOT EXISTS dir_sizes (
  ts INTEGER, path TEXT, bytes INTEGER, files INTEGER, PRIMARY KEY (ts, path)
);
-- Latest inventory per collector (system, services, docker, storage, network, immich, ...).
CREATE TABLE IF NOT EXISTS snapshots (
  kind TEXT PRIMARY KEY, ts INTEGER, data TEXT
);
CREATE TABLE IF NOT EXISTS recommendations (
  id TEXT PRIMARY KEY, ts INTEGER, first_seen INTEGER, severity TEXT, category TEXT,
  title TEXT, detail TEXT, evidence TEXT, confidence TEXT, suggestion TEXT,
  action TEXT, active INTEGER DEFAULT 1, dismissed INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS discovery_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, collector TEXT, level TEXT, message TEXT, duration_ms REAL
);
-- Append-only: triggers below reject UPDATE and DELETE.
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, user TEXT, client TEXT, action TEXT, target TEXT,
  status TEXT, summary TEXT, before_state TEXT, after_state TEXT, result TEXT, rollback TEXT
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
  BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
  BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

CREATE TABLE IF NOT EXISTS dup_scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT, started INTEGER, finished INTEGER, roots TEXT, status TEXT,
  files_seen INTEGER DEFAULT 0, bytes_hashed INTEGER DEFAULT 0, groups INTEGER DEFAULT 0,
  reclaimable INTEGER DEFAULT 0, message TEXT
);
CREATE TABLE IF NOT EXISTS dup_files (
  scan_id INTEGER, grp INTEGER, path TEXT, size INTEGER, mtime REAL, hash TEXT,
  state TEXT DEFAULT 'present', quarantine_path TEXT, PRIMARY KEY (scan_id, path)
);
CREATE INDEX IF NOT EXISTS dup_files_grp ON dup_files (scan_id, grp);

CREATE TABLE IF NOT EXISTS core_samples (
  ts INTEGER, core INTEGER, user REAL, system REAL, iowait REAL, PRIMARY KEY (ts, core)
);
CREATE TABLE IF NOT EXISTS proc_samples (
  ts INTEGER PRIMARY KEY, procs INTEGER, running INTEGER, threads INTEGER, zombies INTEGER, users INTEGER
);
-- Memory watch: 10 s averages (the last hour at 1 s lives in memory) and the events it raised.
CREATE TABLE IF NOT EXISTS mem_samples (
  ts INTEGER PRIMARY KEY,
  total REAL, used REAL, cache REAL, free REAL, avail REAL, anon REAL, shmem REAL, slab REAL, dirty REAL,
  swap_total REAL, swap_used REAL, alloc REAL, freed REAL, page_in REAL, page_out REAL, swap_in REAL, swap_out REAL,
  faults REAL, major_faults REAL, psi_some REAL, psi_full REAL
);
CREATE TABLE IF NOT EXISTS mem_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, level TEXT, kind TEXT, message TEXT, pid INTEGER, name TEXT, delta REAL
);
CREATE INDEX IF NOT EXISTS mem_events_ts ON mem_events (ts);
-- Battery, power and thermals: 15 s samples (raw_hours), hourly roll-ups (hourly_days), one health row per day.
CREATE TABLE IF NOT EXISTS hw_samples (
  ts INTEGER PRIMARY KEY, cpu_temp REAL, max_temp REAL, fan_rpm REAL, bat_pct REAL, bat_watts REAL,
  on_battery INTEGER, throttle_pct REAL, freq_mhz REAL
);
CREATE TABLE IF NOT EXISTS hw_hourly (
  ts INTEGER PRIMARY KEY, cpu_temp REAL, cpu_temp_max REAL, max_temp REAL, fan_rpm REAL, bat_pct REAL, bat_watts REAL,
  on_battery REAL, throttle_pct REAL, freq_mhz REAL
);
CREATE TABLE IF NOT EXISTS battery_health (
  ts INTEGER, name TEXT, full_wh REAL, design_wh REAL, cycles INTEGER, PRIMARY KEY (ts, name)
);
CREATE TABLE IF NOT EXISTS check_samples (
  ts INTEGER, name TEXT, ok INTEGER, code INTEGER, ms REAL, PRIMARY KEY (ts, name)
);
"""

# Columns added after the first release: (table, column, type). Applied with ALTER TABLE on start-up.
MIGRATIONS = [
    ("samples", "cpu_user", "REAL"), ("samples", "cpu_system", "REAL"), ("samples", "iowait", "REAL"),
    ("samples", "tcp_estab", "INTEGER"), ("samples", "tcp_listen", "INTEGER"), ("samples", "tcp_tw", "INTEGER"),
    ("samples", "udp", "INTEGER"),
    ("samples_hourly", "iowait", "REAL"),
    ("container_samples", "cache", "REAL"), ("container_samples", "net_rx", "REAL"),
    ("container_samples", "net_tx", "REAL"), ("container_samples", "blk_r", "REAL"), ("container_samples", "blk_w", "REAL"),
]


class DB:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self.write_lock = threading.Lock()
        c = self.conn()
        c.executescript(SCHEMA)
        for table, col, typ in MIGRATIONS:
            have = {r[1] for r in c.execute(f"PRAGMA table_info({table})")}
            if col not in have:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")

    def conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA busy_timeout=30000")
            self._local.conn = c
        return c

    def execute(self, sql: str, params=()) -> sqlite3.Cursor:
        if sql.lstrip()[:6].upper() in ("SELECT", "PRAGMA"):
            return self.conn().execute(sql, params)
        with self.write_lock:
            return self.conn().execute(sql, params)

    def executemany(self, sql: str, rows) -> None:
        with self.write_lock:
            c = self.conn()
            c.execute("BEGIN")
            try:
                c.executemany(sql, rows)
                c.execute("COMMIT")
            except Exception:
                c.execute("ROLLBACK")
                raise

    def insert(self, table: str, row: dict, replace: bool = True) -> None:
        cols = list(row)
        verb = "INSERT OR REPLACE" if replace else "INSERT"
        self.execute(f"{verb} INTO {table} ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})", [row[c] for c in cols])

    def all(self, sql: str, params=()) -> list[dict]:
        return [dict(r) for r in self.execute(sql, params).fetchall()]

    def one(self, sql: str, params=()) -> dict | None:
        r = self.execute(sql, params).fetchone()
        return dict(r) if r else None

    # ---- snapshots ----
    def put_snapshot(self, kind: str, data) -> None:
        self.execute("INSERT OR REPLACE INTO snapshots VALUES (?,?,?)", (kind, int(time.time()), json.dumps(data)))

    def snapshot(self, kind: str) -> dict | None:
        r = self.one("SELECT ts, data FROM snapshots WHERE kind=?", (kind,))
        return {"ts": r["ts"], "data": json.loads(r["data"])} if r else None

    def log(self, collector: str, level: str, message: str, duration_ms: float | None = None) -> None:
        self.execute("INSERT INTO discovery_log (ts, collector, level, message, duration_ms) VALUES (?,?,?,?,?)",
                     (int(time.time()), collector, level, message, duration_ms))

    def audit(self, **kw) -> int:
        cols = ["ts", "user", "client", "action", "target", "status", "summary",
                "before_state", "after_state", "result", "rollback"]
        kw.setdefault("ts", int(time.time()))
        vals = [kw.get(c) if not isinstance(kw.get(c), (dict, list)) else json.dumps(kw.get(c)) for c in cols]
        return self.execute(f"INSERT INTO audit_log ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})", vals).lastrowid
