"""FastAPI app: JSON API + static dashboard."""
from __future__ import annotations

import ipaddress
import json
import os
import threading
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import actions as A
from . import config as C
from . import intel, security, services_kb
from .util import read

STATIC = Path(__file__).parent / "static"
MEM_RANGES = {"5m": 300, "15m": 900, "1h": 3600, "6h": 6 * 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}
RANGES = {"1h": 3600, "6h": 6 * 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "1y": 365 * 86400}
PUBLIC = {"/login", "/api/login", "/api/health", "/static/style.css", "/static/login.js", "/static/theme.js",
          "/static/logo.svg", "/favicon.ico"}


def fast_json(data) -> Response:
    """Serialize with json.dumps directly: FastAPI's generic encoder is ~10x slower on thousands of rows."""
    return Response(json.dumps(data, separators=(",", ":"), default=str), media_type="application/json")


def create_app(ctx) -> FastAPI:
    cfg, db, auth = ctx.cfg, ctx.db, ctx.auth
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    nets = [ipaddress.ip_network(n) for n in cfg["server"]["allowed_networks"]]
    snap = lambda k: (db.snapshot(k) or {"ts": None, "data": {}})

    def _check(request: Request):
        """Network allowlist, session and CSRF. Returns a response to send instead, or None to continue."""
        client = request.client.host if request.client else "0.0.0.0"
        try:
            ip = ipaddress.ip_address(client)
            if ip.version == 6 and ip.ipv4_mapped:
                ip = ip.ipv4_mapped
            allowed = any(ip in n for n in nets)
        except ValueError:
            allowed = False
        if not allowed:
            return JSONResponse({"detail": "forbidden network"}, status_code=403)
        path = request.url.path
        if path in PUBLIC:
            return None
        user = auth.check(request.cookies.get("guardian_session"))
        if not user:
            if path.startswith("/api/"):
                return JSONResponse({"detail": "login required"}, status_code=401)
            return FileResponse(STATIC / "login.html")
        request.state.user = user
        # CSRF: state-changing requests must carry a custom header (blocked cross-origin without CORS).
        if request.method not in ("GET", "HEAD") and request.headers.get("x-guardian") != "1":
            return JSONResponse({"detail": "missing X-Guardian header"}, status_code=403)
        return None

    @app.middleware("http")
    async def guard(request: Request, call_next):
        resp = _check(request) or await call_next(request)
        # Pages and assets revalidate on every load (cheap 304s), so an update is never mixed with stale files.
        resp.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api/") else "no-cache"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"
        return resp

    # ------------------------------------------------------------------ auth
    @app.post("/api/login")
    async def login(request: Request):
        body = await request.json()
        client = request.client.host if request.client else "?"
        if auth.rate_limited(client):
            raise HTTPException(429, "too many attempts; wait 5 minutes")
        token = auth.login("admin", body.get("password", ""), client)
        if not token:
            raise HTTPException(401, "wrong password")
        r = JSONResponse({"ok": True})
        r.set_cookie("guardian_session", token, httponly=True, samesite="strict", max_age=12 * 3600)
        return r

    @app.post("/api/logout")
    async def logout(request: Request):
        auth.logout(request.cookies.get("guardian_session"))
        r = JSONResponse({"ok": True})
        r.delete_cookie("guardian_session")
        return r

    @app.post("/api/password")
    async def password(request: Request):
        body = await request.json()
        new = (body.get("new") or "").strip()
        if len(new) < 10:
            raise HTTPException(400, "The new password must be at least 10 characters.")
        if auth.rate_limited(request.client.host):
            raise HTTPException(429, "Too many wrong attempts from this device. Wait 5 minutes and try again.")
        if not auth.login("admin", body.get("current", ""), request.client.host):
            raise HTTPException(403, "The current password is not correct.")
        try:
            auth.set_password(new)
        except ValueError as e:
            raise HTTPException(400, str(e))
        (C.CONFIG_DIR / "initial-password.txt").unlink(missing_ok=True)
        db.audit(user="admin", client=request.client.host, action="settings.password", target="dashboard",
                 status="done", summary="Changed dashboard password")
        return {"ok": True, "detail": "Password changed; log in again."}

    @app.get("/api/health")
    def health():
        live = snap("live")
        return {"ok": True, "ts": live["ts"], "self": live["data"].get("self")}

    # ------------------------------------------------------------------ read
    @app.get("/api/overview")
    def overview():
        recs = db.all("SELECT id, severity, category, title FROM recommendations WHERE active=1 AND dismissed=0")
        counts = {s: sum(1 for r in recs if r["severity"] == s) for s in ("critical", "warning", "info")}
        sv = snap("services")["data"]
        return {
            "live": snap("live"), "inventory": snap("inventory")["data"],
            "storage": snap("storage")["data"].get("filesystems", []), "backup": snap("backup"),
            "immich": {k: snap("immich")["data"].get(k) for k in ("reachable", "version", "busy", "missing_containers", "jobs_active")},
            "containers": snap("containers_live")["data"].get("containers", []),
            "services": {"running": sv.get("running"), "failed": sv.get("failed", []), "total": len(sv.get("services", []))},
            "recommendations": {"counts": counts, "top": sorted(recs, key=lambda r: ("critical", "warning", "info").index(r["severity"]))[:6]},
            "smart": [{"model": d.get("Model"), "temp_c": d.get("temp_c"), "failing": d.get("SmartFailing"),
                       "warning": d.get("SmartCriticalWarning")} for d in snap("smart")["data"].get("drives", [])],
            "governor": {"busy": ctx.gov.reason, "deferred": ctx.scheduler.deferred_summary()},
            "processes": {k: snap("processes")["data"].get(k) for k in ("count", "threads", "zombies", "running", "users")},
            "checks": snap("checks")["data"] or [],
            "network": {k: snap("network")["data"].get(k) for k in ("internet", "dns", "firewall")},
            "containers_total": snap("containers_live")["data"].get("total"),
        }

    def bucketed(table: str, cols: list[str], since: int, step: int, key: str | None = None) -> list[dict]:
        sel = ", ".join(f"AVG({c}) AS {c}" for c in cols)
        k = f"{key}, " if key else ""
        return db.all(f"SELECT (ts / {step}) * {step} AS ts, {k}{sel} FROM {table} WHERE ts > ? "
                      f"GROUP BY (ts / {step}), {key or 1} ORDER BY ts", (since,))

    @app.get("/api/metrics")
    def metrics(range: str = "1h"):
        secs = RANGES.get(range, 3600)
        now = int(time.time())
        since = now - secs
        step = max(15, secs // 240)
        raw = secs <= 2 * 86400
        base = ["cpu", "load1", "mem_used", "swap_used", "disk_read_bps", "disk_write_bps", "net_rx_bps", "net_tx_bps",
                "self_cpu", "iowait"]
        if raw:
            samples = bucketed("samples", base + ["cpu_user", "cpu_system", "psi_cpu", "psi_mem", "psi_io", "self_rss",
                                                  "mem_avail_pct", "tcp_estab", "tcp_listen", "tcp_tw", "udp"], since, step)
        else:
            # Hourly rollups for older data, raw samples for the last 48 h (not rolled up yet).
            cut = now - 2 * 86400
            samples = [r for r in bucketed("samples_hourly", base, since, max(step, 3600)) if r["ts"] < cut] \
                + bucketed("samples", base, cut, step)
        return fast_json({
            "range": range, "step": step, "raw": raw, "samples": samples,
            "cores": bucketed("core_samples", ["user", "system", "iowait"], since, step, "core") if raw else [],
            "procs": bucketed("proc_samples", ["procs", "running", "threads", "zombies", "users"], since, max(step, 60)),
            "containers": bucketed("container_samples", ["cpu", "mem", "cache", "net_rx", "net_tx", "blk_r", "blk_w"],
                                   max(since, now - 2 * 86400), step, "name"),
            "checks": bucketed("check_samples", ["ok", "ms"], max(since, now - 7 * 86400), max(step, 120), "name"),
            "fs": db.all("SELECT ts, mount, used, total FROM fs_usage WHERE ts > ? ORDER BY ts", (since,)),
        })

    @app.get("/api/processes")
    def processes():
        return snap("processes")

    @app.get("/api/hardware")
    def hardware_view(range: str = "24h"):
        secs = MEM_RANGES.get(range, 86400)
        now = int(time.time())
        since, step = now - secs, max(15, secs // 400)
        cols = ["cpu_temp", "max_temp", "fan_rpm", "bat_pct", "bat_watts", "on_battery", "throttle_pct", "freq_mhz"]
        if secs <= 2 * 86400:
            samples = bucketed("hw_samples", cols, since, step)
        else:   # hourly roll-ups for older data, raw samples for the part not rolled up yet
            cut = now - 2 * 86400
            samples = [r for r in bucketed("hw_hourly", cols, since, max(step, 3600)) if r["ts"] < cut] \
                + bucketed("hw_samples", cols, cut, step)
        return fast_json({"range": range, "step": step, "snapshot": snap("hardware"), "samples": samples,
                          "health": db.all("SELECT * FROM battery_health ORDER BY ts"), "busy": ctx.gov.reason})

    @app.get("/api/memory")
    def memory(range: str = "15m", since: float = 0, events_after: int = 0):
        """Memory dashboard. With `since`, only samples newer than it (the live page polls every few seconds)."""
        mw = ctx.memwatch
        if not mw:
            return {"enabled": False}
        secs = MEM_RANGES.get(range, 900)
        ev = db.all("SELECT * FROM mem_events WHERE id > ? AND ts > ? ORDER BY id DESC LIMIT 200",
                    (events_after, time.time() - max(secs, 86400)))
        return fast_json({"enabled": True, "range": range, "seconds": secs, "resolution": 1 if secs <= 3600 else max(10, secs // 1000),
                          "samples": mw.history(secs, since), "events": ev, **mw.top(),
                          "settings": {k: cfg["memory"][k] for k in ("sample_seconds", "process_seconds", "history_days")}})

    @app.get("/api/services")
    def services():
        s = snap("services")
        for svc in s["data"].get("services", []):
            kb = services_kb.lookup(svc["unit"])
            svc["risk"], svc["category"], svc["known"] = kb["risk"], kb["category"], kb["known"]
            svc["protected"] = intel.is_protected_unit(svc["unit"], cfg) or kb["risk"] == "critical"
        return fast_json(s)

    @app.get("/api/services/{unit}")
    def service_detail(unit: str):
        try:
            d = intel.detail(unit, cfg, None, None)
        except ValueError as e:
            raise HTTPException(400, str(e))
        except LookupError as e:
            raise HTTPException(404, str(e))
        d["executor"] = A.executor_available()
        d["executor_install"] = C.EXECUTOR_INSTALL
        d["history"] = db.all("SELECT * FROM audit_log WHERE target=? ORDER BY id DESC LIMIT 20", (unit,))
        return d

    @app.get("/api/docker")
    def docker():
        return {"inventory": snap("docker"), "live": snap("containers_live")}

    @app.get("/api/immich")
    def immich():
        dirs = db.all("SELECT path, bytes, files, ts FROM dir_sizes WHERE ts=(SELECT MAX(ts) FROM dir_sizes)")
        growth = db.all("SELECT ts, SUM(bytes) bytes FROM dir_sizes WHERE path LIKE '%/upload' GROUP BY ts ORDER BY ts")
        return {"immich": snap("immich"), "backup": snap("backup"), "dirs": dirs, "growth": growth,
                "protected_paths": cfg["protection"]["protected_paths"]}

    @app.get("/api/storage")
    def storage():
        hist = db.all("SELECT ts, mount, used, total FROM fs_usage WHERE ts > ? ORDER BY ts", (int(time.time()) - 30 * 86400,))
        return fast_json({"storage": snap("storage"), "smart": snap("smart"), "backup": snap("backup"), "history": hist,
                "dirs": db.all("SELECT path, bytes, files, ts FROM dir_sizes WHERE ts=(SELECT MAX(ts) FROM dir_sizes)"),
                "backup_log": read(cfg["backup"]["log_file"])[-6000:] if C.backup_enabled(cfg) else ""})

    @app.get("/api/network")
    def network():
        return snap("network")

    @app.get("/api/recommendations")
    def recommendations(all: bool = False):
        q = "SELECT * FROM recommendations" + ("" if all else " WHERE active=1 AND dismissed=0")
        rows = db.all(q + " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, category")
        for r in rows:
            r["evidence"] = json.loads(r["evidence"] or "{}")
            r["action"] = json.loads(r["action"]) if r["action"] else None
        return rows

    @app.post("/api/recommendations/{rid}/dismiss")
    def dismiss(rid: str, request: Request):
        db.execute("UPDATE recommendations SET dismissed=1 WHERE id=?", (rid,))
        db.audit(user=request.state.user, client=request.client.host, action="recommendation.dismiss", target=rid,
                 status="done", summary=f"Dismissed recommendation {rid}")
        return {"ok": True}

    @app.post("/api/recommendations/{rid}/restore")
    def undismiss(rid: str):
        db.execute("UPDATE recommendations SET dismissed=0 WHERE id=?", (rid,))
        return {"ok": True}

    @app.get("/api/audit")
    def audit(limit: int = 200):
        rows = db.all("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (min(limit, 1000),))
        for r in rows:
            for k in ("before_state", "after_state", "result"):
                try:
                    r[k] = json.loads(r[k]) if r[k] else None
                except json.JSONDecodeError:
                    pass
        return rows

    @app.get("/api/discovery-log")
    def discovery_log(limit: int = 200):
        return db.all("SELECT * FROM discovery_log ORDER BY id DESC LIMIT ?", (min(limit, 1000),))

    # ------------------------------------------------------------------ duplicates
    @app.get("/api/duplicates")
    def dup_scans():
        q = db.one("SELECT COUNT(*) files, COALESCE(SUM(size), 0) bytes FROM dup_files WHERE state='quarantined'")
        scans = db.all("SELECT * FROM dup_scans ORDER BY id DESC LIMIT 30")
        for sc in scans:  # what is still reclaimable after quarantines/restores since the scan
            r = db.one("SELECT COALESCE(SUM(size * MAX(p - 1, 0)), 0) AS b FROM (SELECT grp, MAX(size) size, "
                       "SUM(state='present') p FROM dup_files WHERE scan_id=? GROUP BY grp)", (sc["id"],))
            sc["reclaimable_now"] = r["b"]
        return {"scans": scans,
                "running": ctx.scanner.running(), "progress": ctx.scanner.progress,
                "default_roots": cfg["duplicates"]["default_roots"], "quarantine": q,
                "protected": cfg["protection"]["protected_paths"], "min_size": cfg["duplicates"]["min_size_bytes"],
                "rate": cfg["duplicates"]["read_rate_mb_s"]}

    @app.post("/api/duplicates/scan")
    async def dup_scan(request: Request):
        body = await request.json()
        try:
            sid = ctx.scanner.start(body.get("roots") or [])
        except (ValueError, RuntimeError) as e:
            raise HTTPException(400, str(e))
        db.audit(user=request.state.user, client=request.client.host, action="duplicates.scan", target=json.dumps(body.get("roots")),
                 status="started", summary=f"Started duplicate scan #{sid} (read-only)")
        return {"scan_id": sid}

    @app.post("/api/duplicates/cancel")
    def dup_cancel():
        ctx.scanner.cancel()
        return {"ok": True}

    @app.get("/api/duplicates/quarantine")
    def dup_quarantine():
        return db.all("SELECT scan_id, path, size, quarantine_path, mtime FROM dup_files WHERE state='quarantined' ORDER BY size DESC")

    @app.post("/api/duplicates/{sid}/forget")
    def dup_forget(sid: int, request: Request):
        if ctx.scanner.running() and ctx.scanner.progress.get("scan") == sid:
            raise HTTPException(400, "scan is still running")
        if db.one("SELECT 1 FROM dup_files WHERE scan_id=? AND state='quarantined'", (sid,)):
            raise HTTPException(400, "this scan still has files in quarantine; restore or delete them first")
        db.execute("DELETE FROM dup_files WHERE scan_id=?", (sid,))
        db.execute("DELETE FROM dup_scans WHERE id=?", (sid,))
        db.audit(user=request.state.user, client=request.client.host, action="duplicates.forget", target=f"scan {sid}",
                 status="done", summary=f"Removed the results of scan #{sid} (files on disk untouched)")
        return {"ok": True}

    @app.get("/api/duplicates/{sid}")
    def dup_groups(sid: int, limit: int = 200, q: str = ""):
        scan = db.one("SELECT * FROM dup_scans WHERE id=?", (sid,))
        if not scan:
            raise HTTPException(404, "no such scan")
        rows = db.all("SELECT * FROM dup_files WHERE scan_id=? ORDER BY size DESC, grp, path", (sid,))
        groups: dict[int, dict] = {}
        for r in rows:
            g = groups.setdefault(r["grp"], {"grp": r["grp"], "size": r["size"], "hash": r["hash"], "files": []})
            state = r["state"]
            if state == "present" and not os.path.exists(r["path"]):
                state = "missing"   # moved or deleted outside Guardian since the scan
            g["files"].append({"path": r["path"], "mtime": r["mtime"], "state": state, "quarantine_path": r["quarantine_path"]})
        out = []
        for g in groups.values():
            present = sum(1 for f in g["files"] if f["state"] == "present")
            g["reclaimable"] = g["size"] * max(0, present - 1)
            g["present"] = present
            if q and not any(q.lower() in f["path"].lower() for f in g["files"]):
                continue
            out.append(g)
        out.sort(key=lambda g: (-g["reclaimable"], -g["size"]))
        return {"scan": scan, "groups": out[:limit], "total_groups": len(out),
                "reclaimable_now": sum(g["reclaimable"] for g in out),
                "quarantined": sum(1 for r in rows if r["state"] == "quarantined")}

    # ------------------------------------------------------------------ security
    @app.get("/api/security")
    def security_view():
        return fast_json({"audit": snap("security"), "images": snap("image_vulns"),
                          "image_scan": {"running": bool(ctx.image_scanner and ctx.image_scanner.running()),
                                         "progress": ctx.image_scanner.progress if ctx.image_scanner else {},
                                         "trivy_image": cfg["security"]["trivy_image"]},
                          "refreshing": ctx.security_refreshing})

    @app.post("/api/security/refresh")
    def security_refresh():
        if ctx.security_refreshing:
            return {"ok": True}
        ctx.security_refreshing = True

        def job():
            try:
                db.put_snapshot("security", security.audit(cfg, db))
            finally:
                ctx.security_refreshing = False
        threading.Thread(target=job, daemon=True, name="security-audit").start()
        return {"ok": True}

    @app.post("/api/security/scan-images")
    def security_scan(request: Request):
        try:
            ctx.image_scanner.start()
        except RuntimeError as e:
            raise HTTPException(400, str(e))
        db.audit(user=request.state.user, client=request.client.host, action="security.image_scan", target="running images",
                 status="started", summary="Started a container image vulnerability scan (Trivy, read-only)")
        return {"ok": True}

    @app.post("/api/security/scan-images/cancel")
    def security_scan_cancel():
        if ctx.image_scanner:
            ctx.image_scanner.stop.set()
        return {"ok": True}

    # ------------------------------------------------------------------ actions
    @app.post("/api/actions/preview")
    async def preview(request: Request):
        try:
            return ctx.actions.preview(await request.json())
        except (A.ActionError, ValueError, LookupError) as e:
            raise HTTPException(400, str(e))

    @app.post("/api/actions/execute")
    async def execute(request: Request):
        body = await request.json()
        try:
            return ctx.actions.execute(body.get("token", ""), body.get("confirm", ""), request.state.user, request.client.host)
        except A.ActionError as e:
            raise HTTPException(400, str(e))

    # ------------------------------------------------------------------ settings
    @app.get("/api/settings")
    def settings():
        safe = json.loads(json.dumps(cfg))
        if safe["immich"].get("api_key"):
            safe["immich"]["api_key"] = "configured"
        return {"config": safe, "config_file": str(C.CONFIG_FILE), "executor": A.executor_available(),
                "executor_install": C.EXECUTOR_INSTALL, "install_dir": str(C.INSTALL_DIR),
                "initial_password_file_exists": (C.CONFIG_DIR / "initial-password.txt").exists(),
                "scheduler": ctx.scheduler.status() + ([ctx.memwatch.stats()] if ctx.memwatch else [])}

    # ------------------------------------------------------------------ pages
    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/login")
    def login_page():
        return FileResponse(STATIC / "login.html")

    @app.get("/{path:path}")
    def index(path: str):
        return FileResponse(STATIC / "index.html")

    return app
