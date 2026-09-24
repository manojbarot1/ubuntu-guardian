"""Memory watch: continuous RAM monitoring on its own thread.

The scheduler runs collectors one after another, so a long heavy task (a security review, the
directory walk) would stall a 1-second sampler. MemWatch therefore runs on its own small thread:

  every second      /proc/meminfo, /proc/vmstat, /proc/pressure/memory (three small reads, ~0.2 ms)
  every 10 seconds  /proc/<pid>/stat for each process (one read each: name, start time, RSS; ~7 ms)
                    and sooner whenever system memory moves by 64 MB, so a quiet machine costs little
                    while anything interesting is caught within a second or two

and turns what it sees into events: big processes starting or exiting, sudden jumps, steady growth
that looks like a leak, low available memory, memory pressure, swap storms and OOM kills.

The last hour stays in memory at full resolution for the live page; 10-second averages go to SQLite.
Top lists and per-program groups are only built when the dashboard asks for them.
"""
from __future__ import annotations

import os
import threading
import time
from collections import deque
from itertools import islice

from .util import human_bytes

PAGE = os.sysconf("SC_PAGE_SIZE")
MB = 1024 * 1024
HZ = os.sysconf("SC_CLK_TCK")

# Rates are averaged into the 10 s rows; levels keep the last value of the bucket.
RATES = ("alloc", "freed", "page_in", "page_out", "swap_in", "swap_out", "faults", "major_faults", "psi_some", "psi_full")
LEVELS = ("total", "used", "cache", "free", "avail", "anon", "shmem", "slab", "dirty", "swap_total", "swap_used")
COLUMNS = LEVELS + RATES

VMSTAT_KEYS = ("pgpgin", "pgpgout", "pswpin", "pswpout", "pgfault", "pgmajfault", "pgfree", "oom_kill")
LEAK_WINDOW = 600   # seconds of history fitted when looking for leaks
HIST_STEP = 30      # seconds between per-process history points


def read_meminfo() -> dict:
    out = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, v = line.split(":", 1)
            out[k] = int(v.split()[0]) * 1024
    return out


def read_vmstat() -> dict:
    out = {"pgalloc": 0}
    with open("/proc/vmstat") as f:
        for line in f:
            k, v = line.split()
            if k.startswith("pgalloc_"):
                out["pgalloc"] += int(v)
            elif k in VMSTAT_KEYS:
                out[k] = int(v)
    return out


def read_psi() -> tuple[float, float]:
    some = full = 0.0
    try:
        with open("/proc/pressure/memory") as f:
            for line in f:
                kind, rest = line.split(" ", 1)
                avg10 = float(rest.split()[0].split("=")[1])
                if kind == "some":
                    some = avg10
                else:
                    full = avg10
    except (OSError, IndexError, ValueError):
        pass
    return some, full


def scan_processes() -> dict[int, tuple[str, int, int]]:
    """{pid: (name, start_ticks, rss_bytes)} from one read of /proc/<pid>/stat each. Kernel threads skipped."""
    out = {}
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/stat", "rb") as f:
                raw = f.read()
        except OSError:
            continue
        # comm is in parentheses and may itself contain spaces or ')'.
        l, r = raw.find(b"("), raw.rfind(b")")
        fields = raw[r + 2:].split(None, 22)
        try:
            rss = int(fields[21]) * PAGE
            if rss:
                out[int(name)] = (raw[l + 1:r].decode(errors="replace"), int(fields[19]), rss)
        except (IndexError, ValueError):
            continue
    return out


def linreg(xs: list[float], ys: list[float]) -> tuple[float, float]:
    """Slope and R² of a least-squares line."""
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    syy = sum((y - my) ** 2 for y in ys)
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    if not sxx or not syy:
        return 0.0, 0.0
    return sxy / sxx, sxy * sxy / (sxx * syy)


class Proc:
    __slots__ = ("pid", "name", "start", "rss", "first", "hist")

    def __init__(self, pid, name, start, rss, now):
        self.pid, self.name, self.start, self.rss, self.first = pid, name, start, rss, now
        self.hist: deque = deque([(now, rss)], maxlen=LEAK_WINDOW // HIST_STEP + 1)

    def delta(self, now: float, window: float) -> int:
        """RSS change over roughly the last `window` seconds (0 while the history is shorter)."""
        for t, r in self.hist:
            if now - t <= window + HIST_STEP:
                return self.rss - r
        return 0


class MemWatch(threading.Thread):
    def __init__(self, cfg: dict, db):
        super().__init__(daemon=True, name="memwatch")
        self.m = cfg["memory"]
        self.db = db
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.live: deque = deque(maxlen=3600)
        self.pending: list[dict] = []
        self.procs: dict[int, Proc] = {}
        self.leaks: dict[int, dict] = {}
        self.cond: dict[str, bool] = {}
        self.mute: dict[str, float] = {}
        self.prev_vm: dict | None = None
        self.prev_t = 0.0
        self.last_ms = 0.0
        self.proc_ms = 0.0
        self.runs = 0
        self.last_error = ""
        self.status = {"level": "info", "text": "Starting…"}

    # ------------------------------------------------------------------ events
    def emit(self, level: str, kind: str, msg: str, key: str | None = None, mute: float = 0, **data) -> None:
        now = time.time()
        if key:
            if self.mute.get(key, 0) > now:
                return
            self.mute[key] = now + mute
        self.db.execute("INSERT INTO mem_events (ts, level, kind, message, pid, name, delta) VALUES (?,?,?,?,?,?,?)",
                        (now, level, kind, msg, data.get("pid"), data.get("name"), data.get("delta")))

    def condition(self, name: str, active: bool, level: str, on_msg: str, off_msg: str) -> None:
        """System alerts fire once when a condition starts and once when it clears."""
        was = self.cond.get(name, False)
        if active and not was:
            self.emit(level, name, on_msg)
        elif was and not active:
            self.emit("resolved", name, off_msg)
        self.cond[name] = active

    # ------------------------------------------------------------------ sampling
    def sample(self, now: float) -> dict:
        mi, vm, (psi_some, psi_full) = read_meminfo(), read_vmstat(), read_psi()
        total, free = mi["MemTotal"], mi["MemFree"]
        cache = mi.get("Buffers", 0) + mi.get("Cached", 0) + mi.get("SReclaimable", 0)
        s = {"ts": now, "total": total, "used": max(total - free - cache, 0), "cache": cache, "free": free,
             "avail": mi.get("MemAvailable", free), "anon": mi.get("AnonPages", 0), "shmem": mi.get("Shmem", 0),
             "slab": mi.get("Slab", 0), "dirty": mi.get("Dirty", 0), "swap_total": mi.get("SwapTotal", 0),
             "swap_used": mi.get("SwapTotal", 0) - mi.get("SwapFree", 0), "psi_some": psi_some, "psi_full": psi_full}
        if self.prev_vm is None:
            s.update(dict.fromkeys(RATES[:8], 0.0))
        else:
            dt = max(now - self.prev_t, 1e-3)
            d = {k: max(vm.get(k, 0) - self.prev_vm.get(k, 0), 0) for k in vm}
            s.update(alloc=d["pgalloc"] * PAGE / dt, freed=d.get("pgfree", 0) * PAGE / dt,
                     page_in=d.get("pgpgin", 0) * 1024 / dt, page_out=d.get("pgpgout", 0) * 1024 / dt,
                     swap_in=d.get("pswpin", 0) * PAGE / dt, swap_out=d.get("pswpout", 0) * PAGE / dt,
                     faults=d.get("pgfault", 0) / dt, major_faults=d.get("pgmajfault", 0) / dt)
            if d.get("oom_kill"):
                self.emit("critical", "oom", f"The kernel OOM killer ended {d['oom_kill']} process(es) to free memory")
        self.prev_vm, self.prev_t = vm, now
        return s

    def ingest(self, now: float, cur: dict[int, tuple[str, int, int]]) -> None:
        """Update per-process state from a scan and raise start/exit/jump events."""
        big, jump = self.m["big_process_mb"] * MB, self.m["jump_mb"] * MB
        first = not self.procs
        for pid, (name, start, rss) in cur.items():
            p = self.procs.get(pid)
            if p is None or p.start != start:        # new process (or the pid was reused)
                p = self.procs[pid] = Proc(pid, name, start, rss, now)
                if not first and rss >= big:
                    self.emit("info", "start", f"{name} started using {human_bytes(rss)}", pid=pid, name=name, delta=rss)
            p.rss, p.name = rss, name
            if now - p.hist[-1][0] >= HIST_STEP:
                p.hist.append((now, rss))
            d = p.delta(now, 60)   # for a young process: growth since it was first seen
            if abs(d) >= jump:
                grew = d > 0
                self.emit("warning" if grew else "info", "grow" if grew else "shrink",
                          f"{name} {'grew by' if grew else 'released'} {human_bytes(abs(d))} in about a minute "
                          f"(now {human_bytes(rss)})", key=f"jump:{pid}:{start}", mute=90, pid=pid, name=name, delta=d)
        for pid in [p for p in self.procs if p not in cur]:
            p = self.procs.pop(pid)
            self.leaks.pop(pid, None)
            if p.rss >= big:
                self.emit("info", "exit", f"{p.name} exited and released {human_bytes(p.rss)}",
                          pid=pid, name=p.name, delta=-p.rss)

    def find_leaks(self, now: float) -> None:
        """Steady, near-linear growth over ~10 minutes is reported as a possible leak."""
        min_growth = self.m["leak_min_growth_mb"] * MB
        for pid, p in self.procs.items():
            h = p.hist
            if len(h) < h.maxlen - 1 or h[-1][0] - h[0][0] < LEAK_WINDOW * 0.9 or p.rss - h[0][1] < min_growth:
                self.leaks.pop(pid, None)
                continue
            xs, ys = [t - h[0][0] for t, _ in h], [r for _, r in h]
            slope, r2 = linreg(xs, ys)
            if slope <= 0 or r2 < 0.9:
                self.leaks.pop(pid, None)
                continue
            growth = ys[-1] - ys[0]
            self.leaks[pid] = {"pid": pid, "name": p.name, "rss": p.rss, "growth": growth,
                               "per_hour": slope * 3600, "r2": round(r2, 3), "since": h[0][0]}
            self.emit("warning", "leak", f"{p.name} (pid {pid}) grew steadily by {human_bytes(growth)} in 10 minutes, "
                      f"about {human_bytes(slope * 3600)} per hour. Possible memory leak.",
                      key=f"leak:{pid}:{p.start}", mute=3600, pid=pid, name=p.name, delta=growth)

    def assess(self, s: dict) -> None:
        avail_pct = 100 * s["avail"] / s["total"]
        recent = [x["swap_out"] for x in islice(reversed(self.live), 10)]
        swap_rate = sum(recent) / max(len(recent), 1)
        self.condition("low_avail_critical", avail_pct < 5, "critical",
                       f"Only {avail_pct:.1f}% of RAM is available ({human_bytes(s['avail'])}); the system is close to running out",
                       f"Available RAM recovered to {avail_pct:.0f}%")
        self.condition("low_avail", avail_pct < self.m["low_available_percent"], "warning",
                       f"Available RAM is low: {avail_pct:.1f}% ({human_bytes(s['avail'])})",
                       f"Available RAM is back to {avail_pct:.0f}%")
        self.condition("pressure", s["psi_some"] >= 10, "warning",
                       f"Memory pressure: programs stalled {s['psi_some']:.0f}% of the last 10 s waiting for RAM",
                       "Memory pressure cleared")
        self.condition("swapping", swap_rate >= MB, "warning",
                       f"Swapping out at {human_bytes(swap_rate)}/s: RAM is overflowing to disk", "Swap-out activity stopped")

        if avail_pct < 5:
            level, text = "critical", f"Critical: only {avail_pct:.1f}% of RAM available."
        elif avail_pct < self.m["low_available_percent"] or s["psi_some"] >= 10:
            level, text = "warning", f"Under pressure: {avail_pct:.0f}% of RAM available."
        elif swap_rate >= MB:
            level, text = "warning", "RAM is spilling into swap."
        else:
            level, text = "ok", f"Healthy: {avail_pct:.0f}% of RAM available."
        if self.leaks:
            text += f" {len(self.leaks)} possible leak{'s' if len(self.leaks) > 1 else ''}."
        if len(self.live) >= 60:
            d = s["used"] - self.live[-60]["used"]
            text += (f" App memory {'rose' if d > 0 else 'fell'} {human_bytes(abs(d))} in the last minute."
                     if abs(d) >= 100 * MB else " Usage is steady.")
        self.status = {"level": level, "text": text}

    def persist(self) -> None:
        rows, self.pending = self.pending, []
        if not rows:
            return
        row = {"ts": int(rows[-1]["ts"])}
        for k in LEVELS:
            row[k] = rows[-1][k]
        for k in RATES:
            row[k] = sum(r[k] for r in rows) / len(rows)
        self.db.insert("mem_samples", row)

    def prune(self) -> None:
        now = int(time.time())
        self.db.execute("DELETE FROM mem_samples WHERE ts < ?", (now - self.m["history_days"] * 86400,))
        self.db.execute("DELETE FROM mem_events WHERE ts < ?", (now - 30 * 86400,))

    def run(self) -> None:
        interval, every = self.m["sample_seconds"], max(1, round(self.m["process_seconds"] / self.m["sample_seconds"]))
        tick, scanned, used_at_scan = 0, -every, 0
        while not self.stop.is_set():
            t0 = time.perf_counter()
            now = time.time()
            try:
                s = self.sample(now)
                with self.lock:
                    self.live.append(s)
                    since = tick - scanned
                    if since >= every or (since >= 2 and abs(s["used"] - used_at_scan) >= 64 * MB):
                        tp = time.perf_counter()
                        self.ingest(now, scan_processes())
                        self.proc_ms = (time.perf_counter() - tp) * 1000
                        scanned, used_at_scan = tick, s["used"]
                    if tick % 60 == 30:
                        self.find_leaks(now)
                    self.assess(s)
                self.pending.append(s)
                if tick % 10 == 9:
                    self.persist()
                if tick % 3600 == 0:
                    self.prune()
                self.last_error = ""
            except Exception as e:   # the sampler must never die
                self.last_error = f"{type(e).__name__}: {e}"
            self.last_ms = (time.perf_counter() - t0) * 1000
            self.runs += 1
            tick += 1
            self.stop.wait(max(interval - (time.perf_counter() - t0), 0.05))

    # ------------------------------------------------------------------ read side (API)
    def history(self, seconds: int, since: float = 0) -> list[dict]:
        now = time.time()
        start = max(now - seconds, since)
        if seconds <= 3600:
            with self.lock:
                return [s for s in self.live if s["ts"] > start]
        # Longer ranges: 10 s rows, averaged into buckets so a week stays ~1000 points.
        step = max(10, seconds // 1000)
        sel = ", ".join(f"AVG({c}) AS {c}" for c in COLUMNS)
        return self.db.all(f"SELECT MAX(ts) AS ts, {sel} FROM mem_samples WHERE ts > ? "
                           f"GROUP BY ts / {step} ORDER BY ts", (int(start),))

    def top(self, limit: int = 25) -> dict:
        now = time.time()
        with self.lock:
            procs = sorted(self.procs.values(), key=lambda p: p.rss, reverse=True)
            rows = [{"pid": p.pid, "name": p.name, "rss": p.rss, "d1m": p.delta(now, 60), "d10m": p.delta(now, 600),
                     "age": now - p.first, "spark": [r for _, r in p.hist], "leak": p.pid in self.leaks}
                    for p in procs[:limit]]
            groups: dict[str, dict] = {}
            for p in procs:
                g = groups.setdefault(p.name, {"name": p.name, "rss": 0, "count": 0, "d1m": 0})
                g["rss"] += p.rss
                g["count"] += 1
                g["d1m"] += p.delta(now, 60)
            return {"processes": rows, "apps": sorted(groups.values(), key=lambda g: g["rss"], reverse=True)[:limit],
                    "count": len(procs), "leaks": list(self.leaks.values()), "status": self.status}

    def stats(self) -> dict:
        return {"name": "memwatch", "interval": self.m["sample_seconds"], "heavy": False, "last_ms": round(self.last_ms, 2),
                "runs": self.runs, "deferred": 0, "last_ok": self.prev_t, "last_error": self.last_error,
                "proc_ms": round(self.proc_ms, 1)}
