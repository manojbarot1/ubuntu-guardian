"""Deterministic recommendation rules. Each rule reads snapshots and yields evidence-backed findings.

Findings never trigger actions. A finding may carry an `action` hint the dashboard can offer,
which the user must still confirm.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime

from . import config as C
from . import hardware as HW
from . import services_kb
from .util import human_bytes

SEV_ORDER = {"critical": 0, "warning": 1, "info": 2}


def rec(id, severity, category, title, detail, evidence, confidence="high", suggestion="", action=None):
    return dict(id=id, severity=severity, category=category, title=title, detail=detail,
                evidence=evidence, confidence=confidence, suggestion=suggestion, action=action)


def evaluate(db, cfg) -> list[dict]:
    snap = lambda k: (db.snapshot(k) or {}).get("data") or {}
    out: list[dict] = []
    now = time.time()

    # ---------------- backup job (optional integration)
    b = snap("backup")
    last = b.get("last") or {}
    if not C.backup_enabled(cfg):
        out.append(rec("backup-none", "info", "backup", "No backup is being monitored",
                       "Photos on a single disk are one failure away from being lost. If you have a backup job, Guardian can "
                       "watch it: set [backup] unit (and drive_uuid) in ~/.config/guardian/config.toml.", {}, confidence="medium"))
    else:
        drv = b.get("drive") or {}
        if cfg["backup"]["drive_uuid"] and not drv.get("connected"):
            out.append(rec("backup-drive-missing", "warning", "backup", "Backup drive is not connected",
                           "The backup job needs the external drive plugged in.", {"drive_uuid": cfg["backup"]["drive_uuid"]},
                           suggestion="Plug in the backup drive before the next scheduled backup."))
        run_action = {"type": "backup_run"} if cfg["backup"]["unit"] else None
        if last.get("result") == "failed":
            out.append(rec("backup-failed", "critical", "backup", "Last backup failed", last.get("message", ""), last,
                           suggestion="Check the backup log on the Storage page, fix the cause, then run the backup again.",
                           action=run_action))
        elif last.get("result") == "warning":
            out.append(rec("backup-warning", "warning", "backup", "Last backup finished with a warning", last.get("message", ""), last))
        finished = last.get("finished")
        if finished and not b.get("running"):
            age = (now - datetime.fromisoformat(finished).timestamp()) / 86400
            if age > cfg["backup"]["max_age_days"]:
                out.append(rec("backup-stale", "critical", "backup", f"Last successful backup is {age:.0f} days old",
                               "Files added since then exist only on this machine.", {"finished": finished}, action=run_action))
        elif not finished and not b.get("running"):
            out.append(rec("backup-never", "warning", "backup", "No completed backup recorded yet",
                           f"Guardian has not seen a result in {cfg['backup']['status_file']}.", {}, action=run_action))
        if drv.get("free") is not None:
            if drv["free"] < 50 * 2**30:
                out.append(rec("backup-drive-space", "warning", "backup", "Backup drive is running low on space",
                               f"{human_bytes(drv['free'])} free on the backup drive.", drv))
            growth = _growth("/", db)
            if growth and growth > 0 and drv["free"] / growth < 180:
                out.append(rec("backup-drive-runway", "info", "backup", f"Backup drive full in ~{drv['free'] / growth:.0f} days at current growth",
                               "Based on how fast the system disk is filling.", {"growth_per_day": growth}, confidence="medium"))

    # ---------------- storage
    for f in snap("storage").get("filesystems", []):
        pct = f["percent"]
        if pct >= 90:
            sev, t = "critical", "almost full"
        elif pct >= 80:
            sev, t = "warning", "filling up"
        else:
            sev = None
        if sev:
            out.append(rec(f"fs-{f['mount']}", sev, "storage", f"{f['mount']} is {t} ({pct:.0f}%)",
                           f"{human_bytes(f['free'])} free of {human_bytes(f['total'])}.", f,
                           suggestion="Review large folders and the Duplicates page. Immich data is protected and will not be suggested."))
        g = f.get("growth_per_day")
        if g and g > 0 and f["free"] / g < 60:
            out.append(rec(f"fs-runway-{f['mount']}", "warning", "storage", f"{f['mount']} full in ~{f['free']/g:.0f} days",
                           f"Growing {human_bytes(g)}/day over the last week.", f, confidence="medium"))
    for d in snap("smart").get("drives", []):
        name = d.get("Model") or d["path"]
        if d.get("SmartFailing"):
            out.append(rec(f"smart-{d['path']}", "critical", "storage", f"Drive {name} reports SMART failure",
                           "The drive predicts its own failure. Back up and replace it.", d))
        if d.get("SmartCriticalWarning"):
            out.append(rec(f"nvme-{d['path']}", "critical", "storage", f"NVMe {name} critical warning",
                           ", ".join(d["SmartCriticalWarning"]), d))
        if (d.get("SmartNumBadSectors") or 0) > 0:
            out.append(rec(f"badsect-{d['path']}", "warning", "storage", f"{name} has {d['SmartNumBadSectors']} bad sectors",
                           "Watch this number; if it grows, replace the drive.", d))
        if (d.get("temp_c") or 0) > 65:
            out.append(rec(f"temp-{d['path']}", "warning", "storage", f"{name} is hot ({d['temp_c']}°C)",
                           "Sustained heat shortens drive life. Improve airflow.", d))

    # ---------------- immich
    imm = snap("immich")
    if imm and not imm.get("reachable"):
        out.append(rec("immich-down", "critical", "immich", "Immich is not responding",
                       imm.get("error", "No reply from /api/server/ping."), {"url": cfg["immich"]["url"]},
                       action={"type": "container_restart", "target": "immich_server"}))
    for n in imm.get("missing_containers", []):
        out.append(rec(f"immich-missing-{n}", "critical", "immich", f"Immich container {n} is not running",
                       "Immich needs all of its containers.", {"container": n},
                       action={"type": "container_start", "target": n}))
    for c in imm.get("container_details", []):
        if c.get("health") == "unhealthy":
            out.append(rec(f"immich-unhealthy-{c['name']}", "critical", "immich", f"{c['name']} is unhealthy",
                           "Docker's health check is failing.", c,
                           action={"type": "container_restart", "target": c["name"]}))
        if c.get("restart_count", 0) > 3:
            out.append(rec(f"immich-restarts-{c['name']}", "warning", "immich", f"{c['name']} restarted {c['restart_count']} times",
                           "Repeated restarts usually mean a crash loop. Check its logs.", c))
    if imm.get("paths", {}).get("upload") and imm.get("paths", {}).get("database"):
        up, dbp = imm["paths"]["upload"], imm["paths"]["database"]
        if os.stat(up).st_dev == os.stat(dbp).st_dev if os.path.exists(dbp) else False:
            out.append(rec("immich-single-disk", "info", "immich", "Photos and database live on the same disk",
                           "A single disk failure loses both. Make sure a backup copies them to another disk.",
                           {"upload": up, "database": dbp}, confidence="high"))
    if not cfg["immich"].get("api_key"):
        out.append(rec("immich-api-key", "info", "immich", "Add an Immich API key for job awareness",
                       "With an admin API key Guardian can see Immich's job queue (thumbnail, face, video jobs) and "
                       "warn before actions while Immich is processing. Without it, Guardian uses container CPU instead.",
                       {}, suggestion="Immich → Account settings → API keys → create; put it in ~/.config/guardian/config.toml "
                                      "under [immich] api_key."))

    # ---------------- performance
    live = snap("live")
    hist = db.all("SELECT AVG(cpu) c, AVG(mem_avail_pct) m, AVG(psi_mem) pm, AVG(psi_io) pio, MAX(swap_used) sw, "
                  "AVG(self_cpu) s FROM samples WHERE ts > ?", (now - 3600,))
    h = hist[0] if hist else {}
    if h.get("c") and h["c"] > 70:
        out.append(rec("cpu-sustained", "warning", "performance", f"CPU averaged {h['c']:.0f}% over the last hour",
                       "See the Performance page for which processes use it.", h))
    if h.get("m") is not None and h["m"] < 10:
        out.append(rec("mem-low", "warning", "performance", "Memory is consistently low",
                       f"Only {h['m']:.0f}% RAM available on average over the last hour.", h))
    if h.get("pm") and h["pm"] > 10:
        out.append(rec("mem-pressure", "warning", "performance", "Programs are stalling waiting for memory",
                       f"Memory pressure averaged {h['pm']:.1f}% (PSI).", h,
                       suggestion="Consider closing memory-heavy apps, or stopping optional services like Waydroid/Ollama when unused."))
    if h.get("pio") and h["pio"] > 20:
        out.append(rec("io-pressure", "warning", "performance", "Disk I/O is a bottleneck",
                       f"I/O pressure averaged {h['pio']:.1f}% over the last hour.", h))
    # ---------------- battery, power and thermals
    hw = snap("hardware")
    for b in hw.get("batteries", []):
        ev = {k: b.get(k) for k in ("name", "status", "percent", "health", "full_wh", "design_wh", "cycles", "end_threshold")}
        if hw.get("on_battery"):
            left = f"; about {b['minutes']} min left at the current draw" if b.get("minutes") else ""
            out.append(rec("power-on-battery", "critical" if (b.get("percent") or 0) < 30 else "warning", "hardware",
                           f"Running on battery ({b.get('percent')}%)",
                           f"The charger is unplugged or not delivering power{left}. When the battery runs out the "
                           "server switches off without a clean shutdown.", ev,
                           suggestion="Plug the charger back in. Guardian pauses its heavy work while on battery."))
        if b.get("health") is not None and b["health"] < 85:
            cyc = f" after {b['cycles']} charge cycles" if b.get("cycles") else ""
            out.append(rec(f"battery-health-{b['name']}", "warning" if b["health"] < 70 else "info", "hardware",
                           f"Battery holds {b['health']:.0f}% of its original capacity",
                           f"{b['full_wh']:.1f} of {b['design_wh']:.1f} Wh{cyc}. It covers shorter power cuts as it wears.", ev,
                           suggestion="Nothing urgent. Replace the battery if it drops below about 60%, or if the server "
                                      "must ride out long power cuts."))
        plugged = db.one("SELECT AVG(on_battery) AS ob, COUNT(*) AS n FROM hw_samples WHERE ts > ?", (now - 86400,))
        if b.get("end_threshold") == 100 and b.get("end_threshold_file") and plugged and plugged["n"] > 20 and (plugged["ob"] or 0) < 0.05:
            out.append(rec(f"battery-limit-{b['name']}", "info", "hardware", "Limit battery charging to 80%",
                           "This laptop is plugged in almost all the time. A lithium battery held at 100% wears fastest; "
                           "stopping at 80% (and resuming below 75%) slows the wear and still leaves enough for a power cut.", ev,
                           suggestion="Run these commands (the last one keeps the limit after a reboot):\n" + HW.threshold_commands(b)))
    th = db.one("SELECT AVG(throttle_pct) AS thr, COUNT(*) AS n FROM hw_samples WHERE ts > ?", (now - 3600,))
    hot = db.one("SELECT AVG(cpu_temp) AS t FROM hw_samples WHERE ts > ?", (now - 900,))
    cool_tip = ("Clean the vents, raise the laptop on a stand, and see which processes use CPU on the Server page. "
                "Immich face detection and video transcoding are the usual causes.")
    if th and th["n"] > 20 and (th["thr"] or 0) >= 1:
        out.append(rec("cpu-throttling", "warning", "hardware",
                       f"CPU slowed down by heat for {th['thr'] * 36:.0f} s in the last hour",
                       "When the CPU gets too hot it lowers its speed, which makes Immich jobs and the web UI slower.", th,
                       suggestion=cool_tip))
    cpu_t = hw.get("cpu_temp")
    crit = next((t["crit"] for t in hw.get("temps", []) if t.get("crit") and t["c"] == cpu_t), None) or 100
    if cpu_t and cpu_t >= crit - 5:
        out.append(rec("cpu-temp-critical", "critical", "hardware", f"CPU is at {cpu_t:.0f} °C, near its shutdown limit",
                       f"The hardware switches off at about {crit:.0f} °C.", {"cpu_temp": cpu_t, "crit": crit}, suggestion=cool_tip))
    elif hot and hot["t"] and hot["t"] >= 85:
        out.append(rec("cpu-hot", "warning", "hardware", f"CPU averaged {hot['t']:.0f} °C over the last 15 minutes",
                       "Sustained heat shortens hardware life and leads to throttling.", hot, suggestion=cool_tip))
    if hw.get("fans") and cpu_t and cpu_t >= 75 and max(f["rpm"] for f in hw["fans"]) == 0:
        out.append(rec("fan-stopped", "warning", "hardware", f"Fan is not spinning while the CPU is at {cpu_t:.0f} °C",
                       "The fan may be blocked, broken or left in a manual mode.", {"fans": hw["fans"], "cpu_temp": cpu_t},
                       suggestion="Listen for the fan and check the vents. On ThinkPads, make sure the fan level is 'auto'."))

    # Possible leaks and OOM kills seen by the memory watch (Memory dashboard).
    for lk in db.all("SELECT pid, name, MAX(delta) AS growth, MAX(ts) AS ts FROM mem_events WHERE kind='leak' AND ts > ? "
                     "GROUP BY pid, name", (now - 3 * 3600,)):
        if os.path.exists(f"/proc/{lk['pid']}"):
            out.append(rec(f"mem-leak-{lk['name']}", "warning", "performance", f"{lk['name']} may be leaking memory",
                           f"Process {lk['pid']} grew steadily by {human_bytes(lk['growth'] or 0)} in 10 minutes. "
                           "Growth that never levels off usually means a leak.", lk, confidence="medium",
                           suggestion="Watch it on the Memory dashboard. Restarting the program releases the memory."))
    oom = db.one("SELECT COUNT(*) AS n, MAX(ts) AS ts FROM mem_events WHERE kind='oom' AND ts > ?", (now - 86400,))
    if oom and oom["n"]:
        out.append(rec("mem-oom", "critical", "performance", "The system ran out of memory",
                       f"The kernel had to kill processes to free RAM {oom['n']} time(s) in the last 24 hours.", oom,
                       suggestion="Check the Memory dashboard for what grew before it happened."))
    sw = live.get("swap", {})
    if sw.get("total") and sw.get("percent", 0) > 50 and (live.get("psi", {}).get("memory") or 0) > 1:
        out.append(rec("swap-heavy", "warning", "performance", f"Swap is {sw['percent']:.0f}% used under memory pressure",
                       "The system is paging, which slows everything.", sw))
    # Guardian's own cost, ignoring the first 5 minutes after start (every collector runs once at launch).
    started = (live.get("self") or {}).get("started") or now
    own = db.one("SELECT AVG(self_cpu) s, COUNT(*) n FROM samples WHERE ts > ?", (max(now - 3600, started + 300),))
    if own and own["n"] >= 20 and own["s"] > cfg["governor"]["self_cpu_budget_percent"]:
        out.append(rec("guardian-budget", "warning", "guardian", f"Guardian is using {own['s']:.1f}% CPU",
                       "Above its budget. Increase intervals in config.toml.", own))
    procs = snap("processes")
    for p in procs.get("top_cpu", [])[:3]:
        if p["cpu"] > 90:
            out.append(rec(f"proc-cpu-{p['name']}", "info", "performance", f"{p['name']} is using {p['cpu']:.0f}% CPU",
                           p["cmd"][:160], p, confidence="medium"))

    # ---------------- services
    sv = snap("services")
    for u in sv.get("failed", []):
        info = services_kb.lookup(u)
        out.append(rec(f"svc-failed-{u}", "warning", "services", f"Service {u} has failed",
                       info["purpose"], {"unit": u}, suggestion="Open it on the Services page to see why.",
                       action={"type": "service_detail", "target": u}))
    for s in sv.get("services", []):
        info = services_kb.lookup(s["unit"])
        if s["sub"] == "running" and info.get("risk") == "low" and s["enabled"] == "enabled":
            out.append(rec(f"svc-optional-{s['unit']}", "info", "services", f"Optional service running: {s['unit']}",
                           f"{info['purpose']} {info.get('stop', '')}".strip(),
                           {"unit": s["unit"], "mem": s["mem"], "cpu": s["cpu"]}, confidence="medium",
                           suggestion="If you don't use this, you can stop it and optionally disable it. Nothing happens unless you confirm.",
                           action={"type": "service_detail", "target": s["unit"]}))
        if s.get("restarts", 0) > 5:
            out.append(rec(f"svc-restarts-{s['unit']}", "warning", "services", f"{s['unit']} restarted {s['restarts']} times",
                           "Repeated restarts usually mean it keeps crashing.", s))

    # ---------------- network / exposure
    net = snap("network")
    if not net.get("firewall", {}).get("ufw_enabled"):
        # Skip listeners bound only to local virtual bridges (libvirt, LXC) and ULA IPv6.
        exposed = sorted({l["port"] for l in net.get("listening", []) if l["exposed"] and not l["ip"].startswith(("192.168.122", "10.0.3", "fc"))})
        lan = next((a for i in net.get("interfaces", []) if i["up"] for a in i["addrs"]
                    if a.count(".") == 3 and a.startswith(("192.168.", "10.", "172."))), "192.168.1.10")
        subnet = ".".join(lan.split(".")[:3]) + ".0/24"
        out.append(rec("firewall-off", "warning", "security", "Firewall is off",
                       f"Ports reachable from any network this laptop joins: {', '.join(map(str, exposed))}. "
                       "At home behind a router that is usually fine; on public Wi-Fi it is not.",
                       {"exposed_ports": exposed},
                       suggestion="Enable ufw allowing only your LAN, e.g.: sudo ufw default deny incoming && "
                                  f"sudo ufw allow from {subnet} && sudo ufw enable. "
                                  "Note: Docker-published ports bypass ufw; bind them to the LAN IP in compose if needed."))
    if net and not net.get("internet"):
        out.append(rec("no-internet", "warning", "network", "No internet connectivity",
                       "Updates and remote Immich access will fail.", {}))

    # ---------------- docker hygiene (report only, never prune)
    dk = snap("docker")
    dangling = [i for i in dk.get("images", []) if i["dangling"] or not i["in_use"]]
    size = sum(i["size"] for i in dangling)
    if size > 5 * 2**30:
        out.append(rec("docker-unused-images", "info", "docker", f"{human_bytes(size)} in unused Docker images",
                       f"{len(dangling)} images are not used by any container. Guardian never prunes automatically.",
                       {"images": [i["tags"][:1] or i["id"] for i in dangling][:20]}, confidence="medium",
                       suggestion="Review in Portainer before removing; images for stopped-but-needed containers look unused too."))
    # ---------------- security review (details on the Security dashboard)
    sec = snap("security")
    for f in sec.get("findings", []):
        if f["status"] == "fail" and f["severity"] == "high" and f["id"] not in ("firewall",):
            out.append(rec(f"sec-{f['id']}", "warning", "security", f["title"], f["detail"], f.get("evidence") or {},
                           suggestion=f["fix"] or "See the Security dashboard.", action={"type": "security"}))
    iv = snap("image_vulns")
    crit = sum((i.get("counts") or {}).get("CRITICAL", 0) for i in iv.get("images", []))
    if crit:
        out.append(rec("sec-image-critical", "warning", "security", f"{crit} critical vulnerabilities in container images",
                       "Found by the last image scan. Updating the affected images (docker compose pull) usually fixes most.",
                       {"images": [i["image"] for i in iv.get("images", []) if (i.get("counts") or {}).get("CRITICAL")]},
                       action={"type": "security"}))
    out.sort(key=lambda r: (SEV_ORDER.get(r["severity"], 9), r["category"]))
    return out


def _growth(mount: str, db) -> float | None:
    for f in ((db.snapshot("storage") or {}).get("data") or {}).get("filesystems", []):
        if f["mount"] == mount:
            return f.get("growth_per_day")
    return None


def store(db, recs: list[dict]) -> None:
    now = int(time.time())
    ids = [r["id"] for r in recs]
    if ids:
        db.execute(f"UPDATE recommendations SET active=0 WHERE id NOT IN ({','.join('?' * len(ids))})", ids)
    else:
        db.execute("UPDATE recommendations SET active=0")
    for r in recs:
        db.execute("""INSERT INTO recommendations (id, ts, first_seen, severity, category, title, detail, evidence,
                      confidence, suggestion, action, active) VALUES (?,?,?,?,?,?,?,?,?,?,?,1)
                      ON CONFLICT(id) DO UPDATE SET ts=excluded.ts, severity=excluded.severity, title=excluded.title,
                      detail=excluded.detail, evidence=excluded.evidence, confidence=excluded.confidence,
                      suggestion=excluded.suggestion, action=excluded.action, active=1""",
                   (r["id"], now, now, r["severity"], r["category"], r["title"], r["detail"],
                    json.dumps(r["evidence"], default=str), r["confidence"], r["suggestion"],
                    json.dumps(r["action"]) if r["action"] else None))
