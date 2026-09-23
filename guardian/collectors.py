"""Read-only discovery and metrics. Nothing in this module changes the system."""
from __future__ import annotations

import json
import os
import platform
import re
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path

import psutil

from . import config as C
from .util import docker_api, read, run, run_json

CGROUP = "/sys/fs/cgroup"
SMART_PROPS = {"Model", "Serial", "Size", "ConnectionBus", "Removable", "SmartCriticalWarning", "SmartPowerOnHours",
               "SmartTemperature", "SmartSelftestStatus", "SmartUpdated", "SmartSupported", "SmartFailing",
               "SmartNumBadSectors", "SmartNumAttributesFailing", "SmartPowerOnSeconds"}


class Collectors:
    def __init__(self, cfg: dict, db, gov):
        self.cfg, self.db, self.gov = cfg, db, gov
        self._io = self._net = None
        self._io_t = 0.0
        self._proc_times: dict[int, float] = {}
        self._proc_t = 0.0
        self._ctr_cpu: dict[str, tuple[float, float]] = {}
        self._svc_cpu: dict[str, tuple[float, float]] = {}
        self._ctr_io: dict[str, tuple] = {}
        psutil.cpu_percent(None)
        psutil.cpu_percent(None, percpu=True)
        psutil.cpu_times_percent(None)
        psutil.cpu_times_percent(None, percpu=True)

    # ------------------------------------------------------------------ light
    def system(self) -> None:
        now = time.time()
        cpu = psutil.cpu_percent(None)
        per_core = psutil.cpu_percent(None, percpu=True)
        self.gov.update_cpu(cpu)
        vm, sw = psutil.virtual_memory(), psutil.swap_memory()
        io, net = psutil.disk_io_counters(), psutil.net_io_counters()
        dt = now - self._io_t if self._io_t else 0
        rd = wr = rx = tx = 0.0
        if dt > 0 and self._io and io:
            rd = (io.read_bytes - self._io.read_bytes) / dt
            wr = (io.write_bytes - self._io.write_bytes) / dt
            rx = (net.bytes_recv - self._net.bytes_recv) / dt
            tx = (net.bytes_sent - self._net.bytes_sent) / dt
        self._io, self._net, self._io_t = io, net, now
        self_cpu, self_rss = self.gov.self_usage()
        busy = self.gov.busy()
        from .governor import psi
        ct = psutil.cpu_times_percent(None)
        tcp = _tcp_states()
        row = dict(ts=int(now), cpu=cpu, load1=os.getloadavg()[0], mem_used=float(vm.used),
                   mem_avail_pct=vm.available * 100 / vm.total, swap_used=float(sw.used),
                   psi_cpu=psi("cpu"), psi_mem=psi("memory"), psi_io=psi("io"),
                   disk_read_bps=rd, disk_write_bps=wr, net_rx_bps=rx, net_tx_bps=tx,
                   self_cpu=self_cpu, self_rss=self_rss, busy=int(busy),
                   cpu_user=ct.user + ct.nice, cpu_system=ct.system + ct.irq + ct.softirq, iowait=ct.iowait,
                   tcp_estab=tcp["established"], tcp_listen=tcp["listen"], tcp_tw=tcp["time_wait"], udp=tcp["udp"])
        self.db.insert("samples", row)
        cores = psutil.cpu_times_percent(None, percpu=True)
        self.db.executemany("INSERT OR REPLACE INTO core_samples VALUES (?,?,?,?,?)",
                            [(int(now), i, c.user + c.nice, c.system + c.irq + c.softirq, c.iowait) for i, c in enumerate(cores)])
        la = os.getloadavg()
        self.db.put_snapshot("live", {
            "cpu": cpu, "per_core": per_core, "load": la, "ncpu": os.cpu_count(),
            "mem": {"total": vm.total, "used": vm.used, "available": vm.available, "cached": getattr(vm, "cached", 0),
                    "percent": vm.percent},
            "swap": {"total": sw.total, "used": sw.used, "percent": sw.percent},
            "psi": {"cpu": row["psi_cpu"], "memory": row["psi_mem"], "io": row["psi_io"]},
            "cpu_split": {"user": row["cpu_user"], "system": row["cpu_system"], "iowait": row["iowait"], "steal": ct.steal},
            "tcp": tcp,
            "io": {"read_bps": rd, "write_bps": wr}, "net": {"rx_bps": rx, "tx_bps": tx},
            "self": {"cpu": self_cpu, "rss": self_rss, "started": self.gov.me.create_time()}, "busy": busy, "busy_reason": self.gov.reason,
            "uptime": now - psutil.boot_time(),
        })

    def processes(self) -> None:
        now = time.time()
        dt = now - self._proc_t if self._proc_t else 0
        seen, procs = {}, []
        threads = zombies = running = 0
        for p in psutil.process_iter(["pid", "name", "username", "memory_info", "cpu_times", "cmdline", "create_time",
                                      "num_threads", "status"]):
            i = p.info
            threads += i["num_threads"] or 0
            zombies += i["status"] == psutil.STATUS_ZOMBIE
            running += i["status"] == psutil.STATUS_RUNNING
            ct = i["cpu_times"]
            if ct is None:
                continue
            total = ct.user + ct.system
            seen[i["pid"]] = total
            prev = self._proc_times.get(i["pid"])
            cpu = (total - prev) * 100 / dt if dt and prev is not None else 0.0
            rss = i["memory_info"].rss if i["memory_info"] else 0
            procs.append({"pid": i["pid"], "name": i["name"], "user": i["username"], "cpu": round(cpu, 1),
                          "rss": rss, "cmd": " ".join(i["cmdline"] or [])[:200], "started": i["create_time"]})
        self._proc_times, self._proc_t = seen, now
        apps: dict[str, dict] = {}
        for p in procs:
            a = apps.setdefault(p["name"], {"name": p["name"], "count": 0, "cpu": 0.0, "rss": 0})
            a["count"] += 1
            a["cpu"] += p["cpu"]
            a["rss"] += p["rss"]
        users = _login_users()
        self.db.insert("proc_samples", dict(ts=int(now), procs=len(procs), running=running, threads=threads,
                                            zombies=zombies, users=users))
        self.db.put_snapshot("processes", {
            "count": len(procs), "threads": threads, "zombies": zombies, "running": running, "users": users,
            "top_cpu": sorted(procs, key=lambda p: -p["cpu"])[:25],
            "top_mem": sorted(procs, key=lambda p: -p["rss"])[:25],
            "apps": sorted(apps.values(), key=lambda a: -a["rss"])[:30],
        })

    def containers(self) -> None:
        """Per-container CPU/RAM from cgroup files (far cheaper than `docker stats`)."""
        now = time.time()
        try:
            running = docker_api("/containers/json")
        except Exception as e:  # docker down: record and carry on
            self.db.put_snapshot("containers_live", {"error": str(e), "containers": []})
            return
        rows, live = [], []
        for c in running:
            name = c["Names"][0].lstrip("/")
            base = f"{CGROUP}/system.slice/docker-{c['Id']}.scope"
            usec = _cpu_usec(base)
            mem = _cgroup_mem(base)
            cache = _memstat(base, "file")
            prev = self._ctr_cpu.get(name)
            cpu = (usec - prev[0]) / 1e6 / (now - prev[1]) * 100 if prev and usec is not None else 0.0
            if usec is not None:
                self._ctr_cpu[name] = (usec, now)
            # Network: the container's own netns via any of its processes. Block I/O: cgroup io.stat.
            pid = read(f"{base}/cgroup.procs").split("\n", 1)[0].strip()
            rx_b, tx_b = _netdev(f"/proc/{pid}/net/dev") if pid else (0, 0)
            br, bw = _iostat(base)
            p = self._ctr_io.get(name)
            dt = now - p[0] if p else 0
            rate = lambda cur, old: max(0.0, (cur - old) / dt) if dt > 0 else 0.0
            net_rx, net_tx, blk_r, blk_w = (rate(rx_b, p[1]), rate(tx_b, p[2]), rate(br, p[3]), rate(bw, p[4])) if p else (0, 0, 0, 0)
            self._ctr_io[name] = (now, rx_b, tx_b, br, bw)
            rows.append((int(now), name, cpu, mem, cache, net_rx, net_tx, blk_r, blk_w))
            live.append({"name": name, "cpu": round(cpu, 1), "mem": mem, "cache": cache, "net_rx": net_rx, "net_tx": net_tx,
                         "blk_r": blk_r, "blk_w": blk_w, "state": c["State"], "status": c["Status"], "image": c["Image"]})
        self.db.executemany("INSERT OR REPLACE INTO container_samples (ts, name, cpu, mem, cache, net_rx, net_tx, blk_r, blk_w) "
                            "VALUES (?,?,?,?,?,?,?,?,?)", rows)
        immich = set(self.cfg["immich"]["containers"])
        immich_cpu = sum(r["cpu"] for r in live if r["name"] in immich)
        self.gov.immich_busy = immich_cpu > self.cfg["immich"]["busy_cpu_percent"] or self._immich_jobs_active()
        total = docker_api("/containers/json?all=1")
        self.db.put_snapshot("containers_live", {"containers": live, "immich_cpu": immich_cpu, "total": len(total),
                                                 "immich_busy": self.gov.immich_busy})

    def _immich_jobs_active(self) -> bool:
        snap = self.db.snapshot("immich")
        return bool(snap and snap["data"].get("jobs_active"))

    # ------------------------------------------------------------------ heavy
    def inventory(self) -> None:
        os_release = dict(re.findall(r'^(\w+)="?([^"\n]*)"?$', read("/etc/os-release"), re.M))
        cpu_model = next((l.split(":", 1)[1].strip() for l in read("/proc/cpuinfo").splitlines()
                          if l.startswith("model name")), platform.processor())
        self.db.put_snapshot("inventory", {
            "hostname": socket.gethostname(), "os": os_release.get("PRETTY_NAME", ""), "kernel": platform.release(),
            "cpu_model": cpu_model, "cores": psutil.cpu_count(logical=False), "threads": psutil.cpu_count(),
            "memory": psutil.virtual_memory().total, "swap": psutil.swap_memory().total,
            "boot_time": psutil.boot_time(), "python": platform.python_version(),
            "docker_version": (run_json(["docker", "version", "--format", "{{json .Server.Version}}"]) or ""),
            "systemd": run(["systemctl", "--version"]).split("\n", 1)[0],
        })

    def services(self) -> None:
        now = time.time()
        units = run_json(["systemctl", "list-units", "--type=service", "--all", "--output=json", "--no-pager"]) or []
        files = run_json(["systemctl", "list-unit-files", "--type=service", "--output=json", "--no-pager"]) or []
        state = {f["unit_file"]: f["state"] for f in files}
        names = [u["unit"] for u in units if u.get("load") == "loaded"]
        props = _systemctl_show(names, ["Id", "ControlGroup", "MainPID", "ActiveEnterTimestampMonotonic",
                                        "FragmentPath", "TriggeredBy", "NRestarts", "Type"])
        out = []
        for u in units:
            name = u["unit"]
            p = props.get(name, {})
            cg = p.get("ControlGroup", "")
            mem = _cgroup_mem(CGROUP + cg) if cg else 0
            usec = _cpu_usec(CGROUP + cg) if cg else None
            prev = self._svc_cpu.get(name)
            cpu = (usec - prev[0]) / 1e6 / (now - prev[1]) * 100 if prev and usec is not None else None
            if usec is not None:
                self._svc_cpu[name] = (usec, now)
            out.append({
                "unit": name, "description": u.get("description", ""), "load": u.get("load"),
                "active": u.get("active"), "sub": u.get("sub"), "enabled": state.get(name, "-"),
                "mem": mem, "cpu": None if cpu is None else round(cpu, 2), "main_pid": int(p.get("MainPID") or 0),
                "triggered_by": p.get("TriggeredBy", ""), "restarts": int(p.get("NRestarts") or 0),
                "path": p.get("FragmentPath", ""),
            })
        failed = [s["unit"] for s in out if s["active"] == "failed"]
        user_units = run_json(["systemctl", "--user", "list-units", "--type=service,timer", "--all",
                               "--output=json", "--no-pager"]) or []
        self.db.put_snapshot("services", {"services": out, "failed": failed, "user_units": user_units,
                                          "running": sum(1 for s in out if s["sub"] == "running")})

    def docker_inventory(self) -> None:
        try:
            ctrs = docker_api("/containers/json?all=1")
            images = docker_api("/images/json")
            vols = docker_api("/volumes").get("Volumes") or []
        except Exception as e:
            self.db.put_snapshot("docker", {"error": str(e)})
            self.db.log("docker", "error", str(e))
            return
        details = []
        for c in ctrs:
            try:
                d = docker_api(f"/containers/{c['Id']}/json")
            except Exception:
                continue
            labels = d["Config"].get("Labels") or {}
            health = (d["State"].get("Health") or {}).get("Status")
            details.append({
                "name": d["Name"].lstrip("/"), "id": d["Id"][:12], "image": d["Config"]["Image"],
                "state": d["State"]["Status"], "health": health, "started": d["State"].get("StartedAt"),
                "restart_count": d.get("RestartCount", 0), "restart_policy": d["HostConfig"]["RestartPolicy"]["Name"],
                "compose_project": labels.get("com.docker.compose.project"),
                "compose_service": labels.get("com.docker.compose.service"),
                "compose_dir": labels.get("com.docker.compose.project.working_dir"),
                "mounts": [{"type": m["Type"], "source": m.get("Source"), "dest": m["Destination"],
                            "name": m.get("Name"), "rw": m.get("RW")} for m in d.get("Mounts", [])],
                "ports": sorted({f"{p.get('IP', '')}:{p.get('PublicPort')}->{p['PrivatePort']}/{p['Type']}"
                                 for p in c.get("Ports", []) if p.get("PublicPort")}),
                "networks": list((d.get("NetworkSettings") or {}).get("Networks", {}).keys()),
                "depends_on": labels.get("com.docker.compose.depends_on", ""),
            })
        used_images = {c["ImageID"] for c in ctrs}
        used_vols = {m["name"] for c in details for m in c["mounts"] if m["name"]}
        self.db.put_snapshot("docker", {
            "containers": details,
            "images": [{"id": i["Id"][7:19], "tags": i.get("RepoTags") or [], "size": i["Size"],
                        "in_use": i["Id"] in used_images, "dangling": not i.get("RepoTags") or i["RepoTags"] == ["<none>:<none>"]}
                       for i in images],
            "volumes": [{"name": v["Name"], "driver": v["Driver"], "mountpoint": v["Mountpoint"],
                         "in_use": v["Name"] in used_vols} for v in vols],
        })

    def storage(self) -> None:
        now = int(time.time())
        blk = run_json(["lsblk", "-J", "-b", "-o",
                        "NAME,PATH,SIZE,TYPE,FSTYPE,MOUNTPOINTS,MODEL,TRAN,RM,LABEL,UUID,SERIAL,ROTA"]) or {}
        fs, rows = [], []
        seen = set()
        for part in psutil.disk_partitions(all=False):
            if part.fstype in ("squashfs", "tmpfs", "overlay", "efivarfs") or part.mountpoint.startswith("/snap"):
                continue
            if part.device in seen:
                continue
            seen.add(part.device)
            try:
                u = psutil.disk_usage(part.mountpoint)
            except OSError:
                continue
            try:
                sv = os.statvfs(part.mountpoint)
                inodes = 100 * (sv.f_files - sv.f_ffree) / sv.f_files if sv.f_files else None
            except OSError:
                inodes = None
            fs.append({"device": part.device, "mount": part.mountpoint, "fstype": part.fstype, "total": u.total,
                       "inodes_pct": inodes,
                       "used": u.used, "free": u.free, "percent": u.percent, "opts": part.opts,
                       "protected": C.is_protected(part.mountpoint, self.cfg)})
            rows.append((now, part.mountpoint, u.used, u.total))
        self.db.executemany("INSERT OR REPLACE INTO fs_usage VALUES (?,?,?,?)", rows)
        per_disk = psutil.disk_io_counters(perdisk=True) or {}
        io = {k: {"read_bytes": v.read_bytes, "write_bytes": v.write_bytes, "busy_ms": getattr(v, "busy_time", 0)}
              for k, v in per_disk.items() if re.fullmatch(r"(sd[a-z]+|nvme\d+n\d+|vd[a-z]+)", k)}
        for f in fs:  # growth per day from the last 7 days of history
            hist = self.db.all("SELECT ts, used FROM fs_usage WHERE mount=? AND ts>? ORDER BY ts", (f["mount"], now - 7 * 86400))
            if len(hist) >= 2 and hist[-1]["ts"] - hist[0]["ts"] > 6 * 3600:
                f["growth_per_day"] = (hist[-1]["used"] - hist[0]["used"]) / ((hist[-1]["ts"] - hist[0]["ts"]) / 86400)
        disks = [b for b in blk.get("blockdevices", []) if b.get("type") == "disk" and not b["name"].startswith(("loop", "zram", "ram"))]
        self.db.put_snapshot("storage", {"filesystems": fs, "block": disks, "io": io})

    def smart(self) -> None:
        """Drive health through udisks (works without root for NVMe and most USB-SATA bridges)."""
        tree = run(["busctl", "--system", "--list", "tree", "org.freedesktop.UDisks2"])
        drives = [l.strip() for l in tree.splitlines() if "/drives/" in l]
        out = []
        for path in drives:
            d = {"path": path.rsplit("/", 1)[-1]}
            for iface in ("org.freedesktop.UDisks2.Drive", "org.freedesktop.UDisks2.NVMe.Controller",
                          "org.freedesktop.UDisks2.Drive.Ata"):
                j = run_json(["busctl", "--system", "--json=short", "call", "org.freedesktop.UDisks2", path,
                              "org.freedesktop.DBus.Properties", "GetAll", "s", iface], timeout=5)
                for k, v in ((j or {}).get("data") or [{}])[0].items():
                    if k in SMART_PROPS:
                        d[k] = v.get("data")
            if d.get("SmartTemperature"):
                d["temp_c"] = round(float(d["SmartTemperature"]) - 273.15, 1)
            d["kind"] = "nvme" if "SmartCriticalWarning" in d else ("ata" if "SmartSupported" in d else "unknown")
            d["has_data"] = bool(d.get("SmartUpdated"))
            out.append(d)
        self.db.put_snapshot("smart", {"drives": out})

    def network(self) -> None:
        stats, addrs = psutil.net_if_stats(), psutil.net_if_addrs()
        ifaces = []
        for name, st in stats.items():
            if name == "lo" or name.startswith(("veth", "br-", "docker")):
                continue
            ifaces.append({"name": name, "up": st.isup, "speed": st.speed, "mtu": st.mtu,
                           "addrs": [a.address for a in addrs.get(name, []) if a.family in (socket.AF_INET, socket.AF_INET6)]})
        listen = {}
        for c in psutil.net_connections(kind="inet"):
            if c.status != psutil.CONN_LISTEN:
                continue
            key = (c.laddr.ip, c.laddr.port)
            name = None
            if c.pid:
                try:
                    name = psutil.Process(c.pid).name()
                except psutil.Error:
                    pass
            listen[key] = {"ip": c.laddr.ip, "port": c.laddr.port, "pid": c.pid, "process": name,
                           "exposed": c.laddr.ip not in ("127.0.0.1", "::1") and not c.laddr.ip.startswith("127.")}
        # Map published docker ports onto listeners owned by docker-proxy (pid hidden from non-root).
        docker = self.db.snapshot("docker")
        port_owner = {}
        for ctr in (docker or {}).get("data", {}).get("containers", []):
            for p in ctr.get("ports", []):
                port_owner[int(p.split(":")[-1].split("->")[0])] = f"docker:{ctr['name']}"
        for v in listen.values():
            if not v["process"] and v["port"] in port_owner:
                v["process"] = port_owner[v["port"]]
        wireless = read("/proc/net/wireless").splitlines()[2:]
        wifi = {l.split(":")[0].strip(): float(l.split()[3].rstrip(".")) for l in wireless if l.strip()}
        self.db.put_snapshot("network", {
            "interfaces": ifaces, "listening": sorted(listen.values(), key=lambda v: v["port"]),
            "internet": _can_connect("1.1.1.1", 443), "dns": _resolves("deb.debian.org"),
            "wifi_signal_dbm": wifi, "firewall": _firewall_state(),
        })

    def immich(self) -> None:
        ic = self.cfg["immich"]
        out = {"reachable": False}
        try:
            out["reachable"] = _http_json(ic["url"] + "/api/server/ping").get("res") == "pong"
            v = _http_json(ic["url"] + "/api/server/version")
            out["version"] = f"{v['major']}.{v['minor']}.{v['patch']}"
        except Exception as e:
            out["error"] = str(e)
        if ic.get("api_key"):
            hdr = {"x-api-key": ic["api_key"]}
            for path in ("/api/jobs", "/api/queues"):
                try:
                    jobs = _http_json(ic["url"] + path, hdr)
                    active = {k: v.get("jobCounts", v).get("active", 0) for k, v in jobs.items() if isinstance(v, dict)}
                    out["jobs"] = active
                    out["jobs_active"] = sum(active.values())
                    break
                except Exception:
                    continue
            try:
                out["statistics"] = _http_json(ic["url"] + "/api/server/statistics", hdr)
            except Exception:
                pass
        env = _read_env(Path(ic["app_dir"]) / ".env")
        upload = env.get("UPLOAD_LOCATION", "")
        dbloc = env.get("DB_DATA_LOCATION", "")
        resolve = lambda p: p if p.startswith("/") else str((Path(ic["app_dir"]) / p).resolve())
        out["paths"] = {"app_dir": ic["app_dir"], "upload": resolve(upload) if upload else None,
                        "database": resolve(dbloc) if dbloc else None}
        out["compose_file"] = str(Path(ic["app_dir"]) / "docker-compose.yml")
        live = self.db.snapshot("containers_live")
        out["containers"] = [c for c in (live or {}).get("data", {}).get("containers", []) if c["name"] in ic["containers"]]
        docker = self.db.snapshot("docker")
        health = {c["name"]: c for c in (docker or {}).get("data", {}).get("containers", []) if c["name"] in ic["containers"]}
        out["container_details"] = list(health.values())
        out["missing_containers"] = [n for n in ic["containers"] if n not in {c["name"] for c in out["containers"]}]
        out["busy"] = self.gov.immich_busy
        up = out["paths"]["upload"]
        if up:
            bdir = Path(up) / "backups"
            dumps = sorted(bdir.glob("*.sql.gz")) if bdir.exists() else []
            out["db_dumps"] = [{"name": d.name, "size": d.stat().st_size, "mtime": d.stat().st_mtime} for d in dumps[-10:]]
        self.db.put_snapshot("immich", out)
        self.backup()

    def checks(self) -> None:
        """Endpoint health checks (status code + latency), like uptime panels."""
        now, out = int(time.time()), []
        for c in self.cfg["checks"]:
            t0 = time.perf_counter()
            code, ok, err = 0, False, ""
            try:
                req = urllib.request.Request(c["url"], method="GET", headers={"User-Agent": "guardian-health"})
                with urllib.request.urlopen(req, timeout=c.get("timeout", 5)) as r:
                    code = r.status
            except urllib.error.HTTPError as e:
                code = e.code
            except Exception as e:
                err = type(e).__name__
            ms = (time.perf_counter() - t0) * 1000
            ok = code in c.get("expect", [200, 204]) if code else False
            out.append({"name": c["name"], "url": c["url"], "code": code, "ok": ok, "ms": round(ms, 1), "error": err})
            self.db.insert("check_samples", dict(ts=now, name=c["name"], ok=int(ok), code=code, ms=ms))
        self.db.put_snapshot("checks", out)

    def backup(self) -> None:
        """Status of an external backup job, if one is configured ([backup] in config.toml)."""
        bc = self.cfg["backup"]
        if not C.backup_enabled(self.cfg):
            self.db.put_snapshot("backup", {"enabled": False})
            return
        status = {}
        try:
            status = json.loads(read(bc["status_file"], "{}"))
        except json.JSONDecodeError:
            pass
        timer = svc = {}
        if bc["unit"]:
            timer = _systemctl_show([bc["unit"] + ".timer"], ["NextElapseUSecRealtime", "LastTriggerUSec", "ActiveState"],
                                    user=True).get(bc["unit"] + ".timer", {})
            svc = _systemctl_show([bc["unit"] + ".service"], ["ActiveState", "SubState", "ExecMainStartTimestamp"],
                                  user=True).get(bc["unit"] + ".service", {})
        drive = {}
        if bc["drive_uuid"]:
            dev = f"/dev/disk/by-uuid/{bc['drive_uuid']}"
            drive = {"connected": os.path.exists(dev)}
            if drive["connected"]:
                real = os.path.realpath(dev)
                for part in psutil.disk_partitions():
                    if os.path.realpath(part.device) == real:
                        u = psutil.disk_usage(part.mountpoint)
                        drive.update(mount=part.mountpoint, total=u.total, free=u.free, used=u.used, fstype=part.fstype)
        self.db.put_snapshot("backup", {"enabled": True, "unit": bc["unit"], "last": status, "timer": timer, "service": svc,
                                        "drive": drive, "running": svc.get("ActiveState") == "activating"})

    def dir_sizes(self, stop=None) -> None:
        """Daily walk of Immich data folders (paused while busy)."""
        imm = self.db.snapshot("immich")
        up = (imm or {}).get("data", {}).get("paths", {}).get("upload")
        targets = [str(Path(up) / d) for d in ("upload", "encoded-video", "thumbs", "backups", "library", "profile")] if up else []
        bk = self.db.snapshot("backup")
        target = (bk or {}).get("data", {}).get("last", {}).get("target")
        if target and os.path.isdir(os.path.join(target, "removed")):
            targets.append(os.path.join(target, "removed"))
        now = int(time.time())
        for t in targets:
            if not os.path.isdir(t):
                continue
            size, files, n = 0, 0, 0
            stack = [t]
            t_work = time.monotonic()
            while stack:
                d = stack.pop()
                try:
                    with os.scandir(d) as it:
                        for e in it:
                            try:
                                if e.is_dir(follow_symlinks=False):
                                    stack.append(e.path)
                                elif e.is_file(follow_symlinks=False):
                                    size += e.stat(follow_symlinks=False).st_blocks * 512
                                    files += 1
                            except OSError:
                                pass
                except OSError:
                    continue
                n += 1
                if n % 50 == 0:
                    # Duty cycle: sleep 9x the time spent working, so the walk stays near 10% of one core.
                    work = time.monotonic() - t_work
                    time.sleep(min(2.0, work * 9))
                    self.gov.pause_if_busy(stop)
                    t_work = time.monotonic()
            self.db.execute("INSERT OR REPLACE INTO dir_sizes VALUES (?,?,?,?)", (now, t, size, files))

    def rollup(self) -> None:
        now = int(time.time())
        hour = now - now % 3600
        last = self.db.one("SELECT MAX(ts) AS t FROM samples_hourly")["t"] or 0
        self.db.execute("""
            INSERT OR REPLACE INTO samples_hourly
            (ts, cpu, cpu_max, load1, mem_used, swap_used, disk_read_bps, disk_write_bps, net_rx_bps, net_tx_bps,
             self_cpu, iowait)
            SELECT ts - ts % 3600, AVG(cpu), MAX(cpu), AVG(load1), AVG(mem_used), AVG(swap_used),
                   AVG(disk_read_bps), AVG(disk_write_bps), AVG(net_rx_bps), AVG(net_tx_bps), AVG(self_cpu), AVG(iowait)
            FROM samples WHERE ts >= ? AND ts < ? GROUP BY ts - ts % 3600""", (last, hour))
        r = self.cfg["retention"]
        self.db.execute("DELETE FROM samples WHERE ts < ?", (now - r["raw_hours"] * 3600,))
        for t in ("container_samples", "core_samples", "proc_samples"):
            self.db.execute(f"DELETE FROM {t} WHERE ts < ?", (now - r["raw_hours"] * 3600,))
        self.db.execute("DELETE FROM check_samples WHERE ts < ?", (now - 7 * 86400,))
        self.db.execute("DELETE FROM samples_hourly WHERE ts < ?", (now - r["hourly_days"] * 86400,))
        self.db.execute("DELETE FROM fs_usage WHERE ts < ?", (now - r["hourly_days"] * 86400,))
        self.db.execute("DELETE FROM discovery_log WHERE ts < ?", (now - 30 * 86400,))


# ---------------------------------------------------------------------- helpers
def _cpu_usec(cg: str) -> float | None:
    for line in read(f"{cg}/cpu.stat").splitlines():
        if line.startswith("usage_usec"):
            return float(line.split()[1])
    return None


def _cgroup_mem(cg: str) -> int:
    cur = read(f"{cg}/memory.current").strip()
    if not cur:
        return 0
    inactive = 0
    for line in read(f"{cg}/memory.stat").splitlines():
        if line.startswith("inactive_file "):
            inactive = int(line.split()[1])
            break
    return max(0, int(cur) - inactive)


def _memstat(cg: str, key: str) -> int:
    for line in read(f"{cg}/memory.stat").splitlines():
        if line.startswith(key + " "):
            return int(line.split()[1])
    return 0


def _netdev(path: str) -> tuple[int, int]:
    rx = tx = 0
    for line in read(path).splitlines()[2:]:
        name, _, rest = line.partition(":")
        if name.strip() == "lo" or not rest:
            continue
        f = rest.split()
        rx += int(f[0]); tx += int(f[8])
    return rx, tx


def _iostat(cg: str) -> tuple[int, int]:
    r = w = 0
    for line in read(f"{cg}/io.stat").splitlines():
        for kv in line.split()[1:]:
            k, _, v = kv.partition("=")
            if k == "rbytes":
                r += int(v)
            elif k == "wbytes":
                w += int(v)
    return r, w


def _login_users() -> int:
    """Distinct users with a login session (utmp misses Wayland sessions, logind does not)."""
    sessions = run_json(["loginctl", "list-sessions", "--json=short", "--no-pager"], timeout=5)
    if sessions is None:
        return len({u.name for u in psutil.users()})
    return len({s.get("user") for s in sessions if s.get("class", "user") == "user"})


TCP_STATES = {"01": "established", "0A": "listen", "06": "time_wait"}


def _tcp_states() -> dict:
    """Connection counts straight from /proc/net (no per-process fd scan)."""
    out = {"established": 0, "listen": 0, "time_wait": 0, "udp": 0}
    for f in ("/proc/net/tcp", "/proc/net/tcp6"):
        for line in read(f).splitlines()[1:]:
            st = TCP_STATES.get(line.split()[3] if len(line.split()) > 3 else "")
            if st:
                out[st] += 1
    for f in ("/proc/net/udp", "/proc/net/udp6"):
        out["udp"] += max(0, len(read(f).splitlines()) - 1)
    return out


def _systemctl_show(units: list[str], props: list[str], user: bool = False) -> dict[str, dict]:
    if not units:
        return {}
    out: dict[str, dict] = {}
    for i in range(0, len(units), 150):
        cmd = ["systemctl"] + (["--user"] if user else []) + ["show", "-p", ",".join(["Id"] + props), "--"] + units[i:i + 150]
        cur: dict = {}
        for line in run(cmd, timeout=30).splitlines() + [""]:
            if not line.strip():
                if cur.get("Id"):
                    out[cur["Id"]] = cur
                cur = {}
                continue
            k, _, v = line.partition("=")
            cur[k] = v
    # `show` returns units in order but Id may be an alias; key by requested name too
    return out


def _can_connect(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def _resolves(name: str) -> bool:
    try:
        socket.getaddrinfo(name, 443)
        return True
    except OSError:
        return False


def _firewall_state() -> dict:
    ufw = read("/etc/ufw/ufw.conf")
    m = re.search(r"^ENABLED=(\w+)", ufw, re.M)
    return {"ufw_installed": bool(ufw), "ufw_enabled": bool(m and m.group(1) == "yes")}


def _http_json(url: str, headers: dict | None = None, timeout: float = 5):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _read_env(path: Path) -> dict:
    env = {}
    for line in read(str(path)).splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, _, v = line.partition("=")
            env[k.strip()] = v.strip()
    return env
