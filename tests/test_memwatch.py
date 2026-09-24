"""Memory watch: events and leak detection on synthetic process data. Run like the safety tests."""
import tempfile
import time
import unittest
from pathlib import Path

from guardian import config, memwatch, rules
from guardian.db import DB

MB = 1024 * 1024


def watcher():
    db = DB(Path(tempfile.mkdtemp()) / "t.db")
    return memwatch.MemWatch(config.load(), db), db


def kinds(db):
    return [r["kind"] for r in db.all("SELECT kind FROM mem_events ORDER BY id")]


class ProcessEvents(unittest.TestCase):
    def test_start_grow_exit(self):
        mw, db = watcher()
        t = 1000.0
        mw.ingest(t, {1: ("init", 1, 10 * MB)})                       # first scan: baseline, no events
        mw.ingest(t + 5, {1: ("init", 1, 10 * MB), 2: ("big", 7, 300 * MB)})
        mw.ingest(t + 35, {1: ("init", 1, 10 * MB), 2: ("big", 7, 700 * MB)})
        mw.ingest(t + 40, {1: ("init", 1, 10 * MB)})
        self.assertEqual(kinds(db), ["start", "grow", "exit"])
        ev = db.one("SELECT * FROM mem_events WHERE kind='grow'")
        self.assertEqual(ev["delta"], 400 * MB)

    def test_small_processes_are_quiet(self):
        mw, db = watcher()
        mw.ingest(0, {1: ("init", 1, 10 * MB)})
        for i in range(2, 50):
            mw.ingest(i, {1: ("init", 1, 10 * MB), i: ("tiny", i, 5 * MB)})
        self.assertEqual(kinds(db), [])

    def test_pid_reuse_is_a_new_process(self):
        mw, db = watcher()
        mw.ingest(0, {1: ("init", 1, 10 * MB)})
        mw.ingest(5, {1: ("init", 1, 10 * MB), 9: ("a", 100, 200 * MB)})
        mw.ingest(10, {1: ("init", 1, 10 * MB), 9: ("b", 200, 200 * MB)})   # same pid, new start time
        self.assertEqual(kinds(db), ["start", "start"])


class Leaks(unittest.TestCase):
    def run_series(self, rss_at):
        mw, db = watcher()
        for i in range(0, 660, 5):
            mw.ingest(i, {1: ("init", 1, 10 * MB), 42: ("app", 5, rss_at(i))})
        mw.find_leaks(660)
        return mw, db

    def test_steady_growth_is_a_leak(self):
        mw, db = self.run_series(lambda s: 200 * MB + int(s * 0.2 * MB))    # +12 MB/min
        self.assertIn(42, mw.leaks)
        self.assertIn("leak", kinds(db))
        mw.find_leaks(661)                                                   # muted: reported once
        self.assertEqual(kinds(db).count("leak"), 1)

    def test_flat_or_noisy_is_not(self):
        mw, _ = self.run_series(lambda s: 300 * MB)
        self.assertEqual(mw.leaks, {})
        mw, _ = self.run_series(lambda s: 300 * MB + (150 * MB if (s // 30) % 2 else 0))
        self.assertEqual(mw.leaks, {})


class Assessment(unittest.TestCase):
    def sample(self, avail_pct):
        total = 16 * 1024 * MB
        s = dict.fromkeys(memwatch.COLUMNS, 0.0)
        s.update(ts=time.time(), total=total, avail=total * avail_pct / 100, used=total * (100 - avail_pct) / 100)
        return s

    def test_low_memory_fires_once_and_resolves(self):
        mw, db = watcher()
        for p in (50, 3, 3, 3, 50):
            s = self.sample(p)
            mw.live.append(s)
            mw.assess(s)
        self.assertEqual(kinds(db), ["low_avail_critical", "low_avail", "low_avail_critical", "low_avail"])
        levels = [r["level"] for r in db.all("SELECT level FROM mem_events ORDER BY id")]
        self.assertEqual(levels, ["critical", "warning", "resolved", "resolved"])
        self.assertEqual(mw.status["level"], "ok")

    def test_oom_becomes_a_recommendation(self):
        mw, db = watcher()
        mw.emit("critical", "oom", "killed")
        ids = [r["id"] for r in rules.evaluate(db, config.load())]
        self.assertIn("mem-oom", ids)


class ProcReaders(unittest.TestCase):
    def test_live_proc_reads(self):
        procs = memwatch.scan_processes()
        self.assertTrue(procs)
        name, start, rss = next(iter(procs.values()))
        self.assertIsInstance(name, str)
        self.assertGreater(rss, 0)
        s = memwatch.MemWatch(config.load(), DB(Path(tempfile.mkdtemp()) / "t.db")).sample(time.time())
        self.assertGreater(s["total"], 0)
        self.assertLessEqual(s["used"] + s["cache"] + s["free"], s["total"])


if __name__ == "__main__":
    unittest.main()
