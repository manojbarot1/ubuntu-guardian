"""Keeps Guardian from adding load to a busy machine.

Every collector is classed light or heavy. Light ones always run (they read /proc and cgroup
files, well under 1 ms of CPU). Heavy ones (walking directories, listing services, SMART, docker
inventory) wait while the system is busy or Immich is processing, up to max_defer x their interval,
so data never goes stale forever. Duplicate scans ask pause_if_busy() between files.
"""
from __future__ import annotations

import os
import threading
import time

import psutil

from .util import read


def psi(resource: str) -> float:
    """avg10 of 'some' pressure (% of time tasks stalled) from /proc/pressure."""
    line = read(f"/proc/pressure/{resource}").split("\n", 1)[0]
    for part in line.split():
        if part.startswith("avg10="):
            return float(part[6:])
    return 0.0


class Governor:
    def __init__(self, cfg: dict):
        self.g = cfg["governor"]
        self.ncpu = os.cpu_count() or 1
        self.last_cpu = 0.0
        self.immich_busy = False
        self.reason = ""
        self.lock = threading.Lock()
        self.me = psutil.Process()
        # Own CPU from our cgroup's counter when running as a systemd unit (all threads, exact);
        # psutil otherwise. The first reading after start is skipped: it would only measure start-up.
        cg = read("/proc/self/cgroup").strip().rsplit(":", 1)[-1]
        self._cg_stat = f"/sys/fs/cgroup{cg}/cpu.stat" if cg.endswith(".service") else None
        self._last_usage: tuple[float, float] | None = None

    def update_cpu(self, cpu_percent: float) -> None:
        self.last_cpu = cpu_percent

    def busy(self) -> bool:
        load1 = os.getloadavg()[0] / self.ncpu
        mem = psutil.virtual_memory()
        reasons = []
        if load1 > self.g["busy_load_per_cpu"]:
            reasons.append(f"load {load1:.2f}/cpu")
        if self.last_cpu > self.g["busy_cpu_percent"]:
            reasons.append(f"cpu {self.last_cpu:.0f}%")
        if mem.available * 100 / mem.total < self.g["busy_mem_available_percent"]:
            reasons.append("low memory")
        if psi("io") > self.g["busy_io_pressure"]:
            reasons.append("io pressure")
        if self.immich_busy:
            reasons.append("immich processing")
        self.reason = ", ".join(reasons)
        return bool(reasons)

    def pause_if_busy(self, stop: threading.Event | None = None, max_wait: float = 600) -> None:
        """Block a long-running task while the system is busy (checked every 5 s)."""
        waited = 0.0
        while self.busy() and waited < max_wait and not (stop and stop.is_set()):
            time.sleep(5)
            waited += 5

    def self_usage(self) -> tuple[float | None, float]:
        """Guardian's own CPU (% of one core since the last call) and RSS bytes."""
        now = time.monotonic()
        usec = None
        if self._cg_stat:
            for line in read(self._cg_stat).splitlines():
                if line.startswith("usage_usec"):
                    usec = float(line.split()[1]) / 1e6
        if usec is None:
            t = self.me.cpu_times()
            usec = t.user + t.system
        prev, self._last_usage = self._last_usage, (usec, now)
        cpu = (usec - prev[0]) / (now - prev[1]) * 100 if prev and now > prev[1] else None
        return cpu, float(self.me.memory_info().rss)
