"""Safety-critical behaviour. Run from the repo root: PYTHONPATH=.vendor:. python3 -m unittest discover -s tests -v"""
import importlib.machinery
import importlib.util
import json
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from guardian import actions, config, duplicates, rules
from guardian.db import DB

ROOT = Path(__file__).resolve().parent.parent


def make_db():
    return DB(Path(tempfile.mkdtemp()) / "t.db")


class Protection(unittest.TestCase):
    def setUp(self):
        self.cfg = config.load()

    def test_immich_and_system_paths_protected(self):
        home = str(Path.home())
        for p in (f"{home}/immich-app", f"{home}/immich-app/library/upload/x.jpg", "/var/lib/docker/volumes",
                  "/run/media/x/Drive/immich-backups/2026/library", "/etc/fstab"):
            self.assertTrue(config.is_protected(p, self.cfg), p)

    def test_similar_prefix_not_protected(self):
        self.assertFalse(config.is_protected(str(Path.home() / "immich-app-old/photo.jpg"), self.cfg))
        self.assertFalse(config.is_protected(str(Path.home() / "Downloads/a.iso"), self.cfg))


class AuditLog(unittest.TestCase):
    def test_append_only(self):
        db = make_db()
        aid = db.audit(user="u", client="c", action="x", target="t", status="done", summary="s")
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("UPDATE audit_log SET status='tampered' WHERE id=?", (aid,))
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("DELETE FROM audit_log WHERE id=?", (aid,))
        self.assertEqual(db.one("SELECT status FROM audit_log WHERE id=?", (aid,))["status"], "done")


class Quarantine(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(dir=ROOT))
        self.cfg = config.load()
        self.db = make_db()
        payload = os.urandom(2 * 1024 * 1024)
        self.a, self.b = self.dir / "a.bin", self.dir / "sub" / "b.bin"
        self.b.parent.mkdir()
        self.a.write_bytes(payload)
        self.b.write_bytes(payload)
        (self.dir / "unique.bin").write_bytes(os.urandom(2 * 1024 * 1024))
        gov = mock.Mock(pause_if_busy=lambda *a, **k: None)
        self.scanner = duplicates.Scanner(self.cfg, self.db, gov)
        self.sid = self.scanner.start([str(self.dir)])
        self.scanner.thread.join(30)

    def tearDown(self):
        for root, dirs, files in os.walk(self.dir, topdown=False):
            for f in files:
                os.remove(os.path.join(root, f))
            for d in dirs:
                os.rmdir(os.path.join(root, d))
        os.rmdir(self.dir)
        q = duplicates.quarantine_root(str(ROOT)) / str(self.sid)
        if q.exists():
            for root, dirs, files in os.walk(q, topdown=False):
                for f in files:
                    os.remove(os.path.join(root, f))
                for d in dirs:
                    os.rmdir(os.path.join(root, d))
            os.rmdir(q)

    def test_finds_exact_duplicates_only(self):
        scan = self.db.one("SELECT * FROM dup_scans WHERE id=?", (self.sid,))
        self.assertEqual(scan["status"], "done")
        self.assertEqual(scan["groups"], 1)
        paths = {r["path"] for r in self.db.all("SELECT path FROM dup_files WHERE scan_id=?", (self.sid,))}
        self.assertEqual(paths, {str(self.a), str(self.b)})

    def test_keeps_last_copy_and_restores(self):
        r = duplicates.quarantine(self.db, self.cfg, self.sid, [str(self.a), str(self.b)])
        self.assertTrue(r[0]["ok"])
        self.assertFalse(r[1]["ok"])
        self.assertIn("last remaining copy", r[1]["error"])
        self.assertFalse(self.a.exists())
        self.assertTrue(self.b.exists())
        self.assertTrue(Path(r[0]["quarantine_path"]).exists())
        self.assertEqual(duplicates.restore(self.db, self.sid, [str(self.a)])[0]["ok"], True)
        self.assertTrue(self.a.exists())

    def test_purge_only_from_quarantine(self):
        self.assertFalse(duplicates.purge(self.db, self.sid, [str(self.a)])[0]["ok"])  # not quarantined
        self.assertTrue(self.a.exists())
        duplicates.quarantine(self.db, self.cfg, self.sid, [str(self.a)])
        self.assertTrue(duplicates.purge(self.db, self.sid, [str(self.a)])[0]["ok"])
        self.assertTrue(self.b.exists())

    def test_changed_file_not_quarantined(self):
        with open(self.a, "ab") as f:
            f.write(b"x")
        r = duplicates.quarantine(self.db, self.cfg, self.sid, [str(self.a)])
        self.assertFalse(r[0]["ok"])

    def test_protected_root_refused(self):
        with self.assertRaises(ValueError):
            self.scanner.start([str(Path.home() / "immich-app")])


class Tokens(unittest.TestCase):
    def test_tamper_and_expiry(self):
        plan = {"type": "backup_run", "target": "x", "issued": time.time(), "confirm": {"level": "click"}}
        tok = actions._sign(plan)
        self.assertEqual(actions._unsign(tok)["target"], "x")
        body, mac = tok.rsplit(".", 1)
        forged = json.loads(__import__("base64").urlsafe_b64decode(body))
        forged["target"] = "evil"
        forged_tok = __import__("base64").urlsafe_b64encode(json.dumps(forged, sort_keys=True).encode()).decode() + "." + mac
        with self.assertRaises(actions.ActionError):
            actions._unsign(forged_tok)
        old = actions._sign({**plan, "issued": time.time() - actions.TOKEN_TTL - 5})
        with self.assertRaises(actions.ActionError):
            actions._unsign(old)

    def test_bad_verbs_rejected(self):
        a = actions.Actions(config.load(), make_db(), mock.Mock(immich_busy=False))
        for req in ({"type": "service", "verb": "mask", "target": "cups.service"},
                    {"type": "service", "verb": "stop", "target": "cups.service; rm -rf /"},
                    {"type": "container", "verb": "rm", "target": "immich_server"},
                    {"type": "shell", "cmd": "id"}):
            with self.assertRaises(actions.ActionError):
                a.preview(req)


class SingleUse(unittest.TestCase):
    def test_token_cannot_be_replayed(self):
        db = make_db()
        a = actions.Actions(config.load(), db, mock.Mock(immich_busy=False))
        db.put_snapshot("backup", {"enabled": True, "drive": {"connected": True}, "running": False})
        a.cfg = {**a.cfg, "backup": {**a.cfg["backup"], "unit": "photo-backup", "drive_uuid": ""}}
        plan = a.preview({"type": "backup_run"})
        with mock.patch.object(actions, "run", return_value=""):
            self.assertEqual(a.execute(plan["token"], "", "u", "c")["status"], "done")
            with self.assertRaises(actions.ActionError):
                a.execute(plan["token"], "", "u", "c")


class Executor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        loader = importlib.machinery.SourceFileLoader("guardian_exec", str(ROOT / "executor" / "guardian-exec"))
        spec = importlib.util.spec_from_loader("guardian_exec", loader)
        cls.ex = importlib.util.module_from_spec(spec)
        loader.exec_module(cls.ex)

    def run_req(self, line):
        out = []
        with mock.patch("sys.stdin", mock.Mock(readline=lambda n: line)), \
             mock.patch("sys.stdout", mock.Mock(write=out.append, flush=lambda: None)), \
             mock.patch.object(self.ex.subprocess, "run", side_effect=AssertionError("must not run")):
            self.ex.main()
        return json.loads(out[0])

    def test_rejects_without_running_anything(self):
        for line in ('{"verb":"stop","unit":"docker.service"}', '{"verb":"stop","unit":"systemd-journald.service"}',
                     '{"verb":"mask","unit":"cups.service"}', '{"verb":"stop","unit":"cups.service --now"}',
                     '{"verb":"stop","unit":"../../etc/passwd"}', 'not json',
                     '{"verb":"stop","unit":"gdm.service"}', '{"verb":"disable","unit":"ssh.service"}'):
            self.assertFalse(self.run_req(line)["ok"], line)


class Rules(unittest.TestCase):
    def test_stale_and_failed_backup(self):
        db = make_db()
        cfg = config.load()
        cfg = {**cfg, "backup": {**cfg["backup"], "unit": "photo-backup", "drive_uuid": "TEST-UUID"}}
        old = "2026-01-01T03:30:00+01:00"
        db.put_snapshot("backup", {"enabled": True, "last": {"result": "ok", "finished": old}, "drive": {"connected": False}, "running": False})
        ids = {r["id"] for r in rules.evaluate(db, cfg)}
        self.assertIn("backup-stale", ids)
        self.assertIn("backup-drive-missing", ids)
        db.put_snapshot("backup", {"enabled": True, "last": {"result": "failed", "message": "x", "finished": old},
                                   "drive": {"connected": True}, "running": False})
        self.assertIn("backup-failed", {r["id"] for r in rules.evaluate(db, cfg)})

    def test_backup_monitoring_is_optional(self):
        db = make_db()
        cfg = config.load()
        cfg = {**cfg, "backup": {**cfg["backup"], "unit": "", "drive_uuid": ""}}
        recs = {r["id"]: r for r in rules.evaluate(db, cfg)}
        self.assertEqual(recs["backup-none"]["severity"], "info")
        self.assertFalse(any(k.startswith("backup-") and k != "backup-none" for k in recs))

    def test_store_deactivates_resolved(self):
        db = make_db()
        rules.store(db, [rules.rec("a", "info", "c", "t", "d", {})])
        rules.store(db, [])
        self.assertEqual(db.one("SELECT active FROM recommendations WHERE id='a'")["active"], 0)


if __name__ == "__main__":
    unittest.main()


class SecurityReview(unittest.TestCase):
    def test_score_is_capped_per_category(self):
        from guardian import security
        many = [security.finding(f"p{i}", "Network exposure", "x", "fail", "high") for i in range(6)]
        with mock.patch.multiple(security, _updates=lambda: ([], {}), _hardening=lambda: ([], {}), _docker=lambda: ([], {}),
                                 _exposure=lambda db: (many, {}), _access=lambda db: ([], {}), _files=lambda cfg: ([], {}),
                                 _immich=lambda cfg, db: ([], {})):
            a = security.audit(config.load(), make_db())
        self.assertEqual(a["score"], 75)   # 6 x 15 = 90 in one category, capped at 25
        self.assertEqual(a["findings"][0]["status"], "fail")

    def test_sshd_first_value_wins(self):
        from guardian import security
        d = Path(tempfile.mkdtemp())
        (d / "sshd_config.d").mkdir()
        (d / "sshd_config.d" / "10-keys.conf").write_text("PasswordAuthentication no\n")
        (d / "sshd_config").write_text(f"Include {d}/sshd_config.d/*.conf\nPasswordAuthentication yes\nPermitRootLogin no\n")
        real = security.read
        with mock.patch.object(security, "read", lambda p, default="": real(str(d / "sshd_config")) if p == "/etc/ssh/sshd_config" else real(p, default)):
            cfg = security._ssh_config()
        self.assertEqual(cfg["passwordauthentication"], "no")
        self.assertEqual(cfg["permitrootlogin"], "no")

    def test_audit_never_raises(self):
        from guardian import security
        def boom():
            raise RuntimeError("probe failed")
        with mock.patch.object(security, "_updates", boom):
            a = security.audit(config.load(), make_db())
        self.assertTrue(any(f["id"].startswith("error-") for f in a["findings"]))
