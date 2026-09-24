"""Entry point: collectors on a background scheduler thread + the web app on the main thread."""
from __future__ import annotations

import logging
import threading
import time
import traceback
from dataclasses import dataclass, field

import uvicorn

from . import config as C
from . import rules, security
from .actions import Actions
from .api import create_app
from .auth import Auth
from .collectors import Collectors
from .db import DB
from .duplicates import Scanner
from .governor import Governor
from .memwatch import MemWatch

log = logging.getLogger("guardian")

# name -> heavy? Heavy tasks wait while the system is busy.
TASKS = {
    "system": False, "hardware": False, "containers": False, "processes": False, "immich": False, "rules": False, "checks": False,
    "services": True, "docker_inventory": True, "network": True, "storage": True, "smart": True,
    "dir_sizes": True, "inventory": True, "rollup": True, "security": True, "image_scan": True,
}


@dataclass
class Task:
    name: str
    interval: float
    heavy: bool
    next_run: float = 0.0
    deferred: int = 0
    last_ms: float = 0.0
    last_ok: float = 0.0
    last_error: str = ""
    runs: int = 0


class Scheduler(threading.Thread):
    def __init__(self, cfg, db, gov, col):
        super().__init__(daemon=True, name="scheduler")
        self.cfg, self.db, self.gov, self.col = cfg, db, gov, col
        self.stop = threading.Event()
        iv = dict(cfg["intervals"], inventory=86400, security=cfg["security"]["audit_interval"],
                  image_scan=max(1, cfg["security"]["image_scan_days"]) * 86400)
        now = time.time()
        self.tasks = [Task(n, iv[n], heavy) for n, heavy in TASKS.items()]
        # Stagger the first runs so start-up is not a burst.
        for i, t in enumerate(self.tasks):
            t.next_run = now + i * 2
        # The daily directory walk is the most expensive task: never run it in the start-up burst.
        next(t for t in self.tasks if t.name == "dir_sizes").next_run = now + 900
        next(t for t in self.tasks if t.name == "security").next_run = now + 120
        next(t for t in self.tasks if t.name == "image_scan").next_run = now + 3600
        self.image_scanner = None  # set by main()

    def run(self) -> None:
        while not self.stop.is_set():
            now = time.time()
            for t in self.tasks:
                if now < t.next_run:
                    continue
                if t.heavy and t.runs > 0 and t.deferred < self.cfg["governor"]["max_defer"] and self.gov.busy():
                    t.deferred += 1
                    t.next_run = now + t.interval
                    continue
                self._run(t)
                t.deferred = 0
                t.next_run = time.time() + t.interval
            self.stop.wait(1.0)

    def _run(self, t: Task) -> None:
        t0 = time.perf_counter()
        try:
            if t.name == "rules":
                rules.store(self.db, rules.evaluate(self.db, self.cfg))
            elif t.name == "dir_sizes":
                self.col.dir_sizes(self.stop)
            elif t.name == "security":
                self.db.put_snapshot("security", security.audit(self.cfg, self.db))
            elif t.name == "image_scan":
                # Weekly re-scan only once the user has run (and so approved the download of) a first scan.
                last = self.db.snapshot("image_vulns")
                days = self.cfg["security"]["image_scan_days"]   # 0 disables the weekly re-scan
                due = days > 0 and last and time.time() - last["data"].get("finished", 0) > days * 86400 - 3600
                if due and self.image_scanner and not self.image_scanner.running():
                    self.image_scanner.start()
            else:
                getattr(self.col, t.name)()
            t.last_ok, t.last_error = time.time(), ""
        except Exception as e:
            t.last_error = f"{type(e).__name__}: {e}"
            self.db.log(t.name, "error", traceback.format_exc()[-1500:])
        t.last_ms = (time.perf_counter() - t0) * 1000
        t.runs += 1
        if t.runs == 1 or (t.heavy and t.last_ms > 5000):
            self.db.log(t.name, "info", f"run {t.runs} took {t.last_ms:.0f} ms", t.last_ms)

    def deferred_summary(self) -> dict:
        return {t.name: t.deferred for t in self.tasks if t.deferred}

    def status(self) -> list[dict]:
        return [dict(name=t.name, interval=t.interval, heavy=t.heavy, last_ms=round(t.last_ms, 1), runs=t.runs,
                     deferred=t.deferred, last_ok=t.last_ok, last_error=t.last_error) for t in self.tasks]


@dataclass
class Context:
    cfg: dict
    db: DB
    gov: Governor
    auth: Auth
    scheduler: Scheduler = field(default=None)
    actions: Actions = field(default=None)
    scanner: Scanner = field(default=None)
    image_scanner: object = field(default=None)
    memwatch: MemWatch | None = field(default=None)
    security_refreshing: bool = False


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = C.load()
    C.STATE_DIR.mkdir(parents=True, exist_ok=True)
    db = DB(C.STATE_DIR / "guardian.db")
    gov = Governor(cfg)
    ctx = Context(cfg=cfg, db=db, gov=gov, auth=Auth())
    ctx.scheduler = Scheduler(cfg, db, gov, Collectors(cfg, db, gov))
    ctx.actions = Actions(cfg, db, gov)
    ctx.scanner = Scanner(cfg, db, gov)
    ctx.image_scanner = security.ImageScanner(cfg, db, gov)
    ctx.scheduler.image_scanner = ctx.image_scanner
    ctx.scheduler.start()
    if cfg["memory"]["enabled"]:
        ctx.memwatch = MemWatch(cfg, db)
        ctx.memwatch.start()
    db.log("guardian", "info", "started")
    uvicorn.run(create_app(ctx), host=cfg["server"]["host"], port=cfg["server"]["port"], log_level="warning",
                access_log=False, http="h11", loop="asyncio", workers=1, proxy_headers=False)


if __name__ == "__main__":
    main()
