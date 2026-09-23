"""Security review: host hardening, patch state, exposure, access, Docker and Immich.

Everything here is read-only and runs unprivileged. Each check yields a finding:
  status   pass | warn | fail | info
  severity high | medium | low        (how much a failure matters)
  fix      a suggested command or step; Guardian never applies it itself

Container image CVE scanning uses Trivy in a throwaway container. It runs only when you start it
(or weekly after your first scan), with CPU and memory limits, pausing while the system is busy.
"""
from __future__ import annotations

import glob
import json
import os
import re
import stat
import subprocess
import threading
import time
import urllib.request
from pathlib import Path

from . import config as C
from .util import docker_api, read, run, run_json

WEIGHT = {("fail", "high"): 15, ("fail", "medium"): 8, ("fail", "low"): 3,
          ("warn", "high"): 6, ("warn", "medium"): 4, ("warn", "low"): 1}

# Ports that deserve attention when reachable from the network, and why.
RISKY_PORTS = {
    22: ("SSH", "medium", "Remote shell. Keep it key-only, or limit it to your LAN."),
    3389: ("Remote desktop (RDP)", "high", "Full desktop access. Limit to your LAN or turn it off when unused."),
    5900: ("VNC", "high", "Remote desktop, often weakly protected."),
    9443: ("Portainer (HTTPS)", "high", "Docker admin UI: whoever logs in controls every container and effectively the host."),
    8000: ("Portainer edge agent", "high", "Portainer tunnel endpoint; not needed unless you use Portainer Edge."),
    9000: ("Portainer (HTTP)", "high", "Docker admin UI over plain HTTP."),
    2283: ("Immich (HTTP)", "low", "Photo server without TLS. Fine at home; use a reverse proxy with HTTPS for remote access."),
    5432: ("PostgreSQL", "high", "Database should never be reachable from the network."),
    6379: ("Redis", "high", "Redis should never be reachable from the network."),
    139: ("SMB/NetBIOS", "medium", "Windows file sharing."), 445: ("SMB", "medium", "Windows file sharing."),
    8770: ("Guardian", "low", "This dashboard (password protected, LAN-only allowlist)."),
    80: ("HTTP web server", "low", "Unencrypted web traffic."), 8443: ("HTTPS web server", "low", "Web server."),
}
# (key, accepted values, recommended value, severity, meaning)
SYSCTL = [
    ("kernel.randomize_va_space", ("2",), "2", "medium", "Full address-space layout randomisation"),
    ("kernel.kptr_restrict", ("1", "2"), "1", "low", "Hide kernel pointers from unprivileged users"),
    ("kernel.dmesg_restrict", ("1",), "1", "low", "Only root can read the kernel log"),
    ("kernel.yama.ptrace_scope", ("1", "2", "3"), "1", "medium", "Processes cannot inspect unrelated processes"),
    ("kernel.unprivileged_bpf_disabled", ("1", "2"), "2", "low", "Unprivileged BPF disabled"),
    ("fs.protected_symlinks", ("1",), "1", "medium", "Symlink attack protection in shared folders"),
    ("fs.protected_hardlinks", ("1",), "1", "medium", "Hardlink attack protection"),
    ("net.ipv4.tcp_syncookies", ("1",), "1", "low", "SYN-flood protection"),
    ("net.ipv4.conf.all.rp_filter", ("1", "2"), "2", "low", "Reverse-path filtering (anti-spoofing)"),
    ("net.ipv4.conf.all.accept_redirects", ("0",), "0", "low", "Ignore ICMP redirects"),
    ("net.ipv4.conf.all.send_redirects", ("0",), "0", "low", "Do not send ICMP redirects (this machine is not a router)"),
]


def finding(id, category, title, status, severity="low", detail="", fix="", evidence=None):
    return dict(id=id, category=category, title=title, status=status, severity=severity, detail=detail,
                fix=fix, evidence=evidence or {})


# ---------------------------------------------------------------------- host checks
def _updates() -> tuple[list[dict], dict]:
    out, facts = [], {}
    lines = run(["apt", "list", "--upgradable"], timeout=60).splitlines()
    pkgs = []
    for l in lines:
        m = re.match(r"^([^/]+)/(\S+) (\S+) \S+ \[upgradable from: ([^\]]+)\]", l)
        if m:
            pkgs.append({"package": m.group(1), "origin": m.group(2), "version": m.group(3), "installed": m.group(4),
                         "security": "-security" in m.group(2)})
    sec = [p for p in pkgs if p["security"]]
    facts["updates"] = pkgs
    stamp = Path("/var/lib/apt/periodic/update-success-stamp")
    age_days = (time.time() - stamp.stat().st_mtime) / 86400 if stamp.exists() else None
    facts["apt_updated_days"] = age_days
    if sec:
        out.append(finding("sec-updates", "Patching", f"{len(sec)} security updates waiting", "fail", "high",
                           "Security fixes are available but not installed: " + ", ".join(p["package"] for p in sec[:12]),
                           "sudo apt update && sudo apt upgrade", {"packages": sec}))
    else:
        out.append(finding("sec-updates", "Patching", "No pending security updates", "pass", "high",
                           f"{len(pkgs)} non-security updates pending." if pkgs else "System is up to date."))
    if pkgs and not sec:
        out.append(finding("updates", "Patching", f"{len(pkgs)} regular updates pending", "info", "low",
                           ", ".join(p["package"] for p in pkgs[:12]), "sudo apt upgrade"))
    if age_days is not None and age_days > 3:
        out.append(finding("apt-stale", "Patching", f"Package lists are {age_days:.0f} days old", "warn", "medium",
                           "Update information may be outdated, so missing fixes would not show here.", "sudo apt update"))
    auto = read("/etc/apt/apt.conf.d/20auto-upgrades")
    on = bool(re.search(r'Unattended-Upgrade\s+"1"', auto))
    out.append(finding("unattended", "Patching", "Automatic security updates " + ("enabled" if on else "disabled"),
                       "pass" if on else "fail", "high",
                       "unattended-upgrades installs security fixes daily." if on else "Security fixes are only installed when you run apt yourself.",
                       "" if on else "sudo dpkg-reconfigure -plow unattended-upgrades"))
    # Reboot needed: the flag file, or a newer kernel installed than the one running.
    kernels = sorted(glob.glob("/boot/vmlinuz-*"), key=lambda p: [int(x) if x.isdigit() else x for x in re.split(r"[.-]", p)])
    newest = kernels[-1].split("vmlinuz-", 1)[1] if kernels else ""
    running = os.uname().release
    reboot_pkgs = read("/var/run/reboot-required.pkgs").split()
    need = os.path.exists("/var/run/reboot-required") or (newest and newest != running)
    facts.update(kernel=running, newest_kernel=newest, reboot_required=bool(need), reboot_pkgs=reboot_pkgs)
    out.append(finding("reboot", "Patching", "Reboot required" if need else "Running the newest installed kernel",
                       "warn" if need else "pass", "medium",
                       (f"Installed kernel {newest} is not running yet (running {running}). " if newest != running else "")
                       + (f"Packages waiting for a reboot: {', '.join(reboot_pkgs)}" if reboot_pkgs else ""),
                       "Reboot when convenient (Immich restarts automatically)." if need else ""))
    pro = run_json(["pro", "security-status", "--format", "json"], timeout=60)
    if pro:
        esm = [p for p in pro.get("packages", []) if p.get("status") == "pending_attach"]
        facts["pro_pending"] = esm
        attached = (pro.get("summary", {}).get("ua", {}) or {}).get("attached")
        if esm:
            out.append(finding("ubuntu-pro", "Patching", f"{len(esm)} security fixes need Ubuntu Pro", "warn", "medium",
                               "These packages (from the 'universe' repository) have fixes published only through Ubuntu Pro "
                               "ESM: " + ", ".join(sorted({p["package"] for p in esm})[:10]),
                               "Get a free personal Ubuntu Pro token (up to 5 machines) at https://ubuntu.com/pro, then run: sudo pro attach <token>",
                               {"attached": attached}))
    return out, facts


def _hardening() -> tuple[list[dict], dict]:
    out, facts = [], {}
    vulns = {}
    for f in sorted(glob.glob("/sys/devices/system/cpu/vulnerabilities/*")):
        vulns[os.path.basename(f)] = read(f).strip()
    facts["cpu_vulns"] = vulns
    bad = {k: v for k, v in vulns.items() if v.lower().startswith("vulnerable")}
    out.append(finding("cpu-vulns", "Kernel & hardware", f"{len(bad)} CPU vulnerabilities not mitigated" if bad else "CPU vulnerabilities mitigated",
                       "warn" if bad else "pass", "medium",
                       "; ".join(f"{k}: {v}" for k, v in bad.items()) or f"{len(vulns)} known CPU issues checked.",
                       "Install the latest CPU microcode and BIOS/UEFI update from the laptop vendor (sudo fwupdmgr update), then reboot."
                       if bad else "", {"all": vulns}))
    aa = read("/sys/module/apparmor/parameters/enabled").strip() == "Y"
    out.append(finding("apparmor", "Kernel & hardware", "AppArmor " + ("enabled" if aa else "disabled"), "pass" if aa else "fail", "medium",
                       "Mandatory access control confines Docker containers and many services." if aa else "",
                       "" if aa else "Re-enable AppArmor (kernel parameter apparmor=1) and reboot."))
    sb = None
    for f in glob.glob("/sys/firmware/efi/efivars/SecureBoot-*"):
        try:
            sb = Path(f).read_bytes()[-1] == 1
        except OSError:
            pass
    facts["secure_boot"] = sb
    if sb is not None:
        out.append(finding("secure-boot", "Kernel & hardware", "Secure Boot " + ("on" if sb else "off"), "pass" if sb else "info", "low",
                           "Protects the boot chain against tampering." if sb else
                           "Secure Boot is off. It mainly protects against someone with physical access or boot-level malware; "
                           "turning it on can break unsigned kernel modules (e.g. some GPU or VirtualBox drivers).",
                           "" if sb else "Enable it in the UEFI setup if you do not need unsigned modules."))
    sysctl = []
    for key, accepted, rec, sev, desc in SYSCTL:
        v = read("/proc/sys/" + key.replace(".", "/")).strip()
        if not v:
            continue
        good = v in accepted
        sysctl.append({"key": key, "value": v, "ok": good, "desc": desc, "recommended": rec})
        if not good:
            out.append(finding(f"sysctl-{key}", "Kernel & hardware", f"{desc}: not set ({key}={v})", "warn", sev,
                               f"Recommended value: {rec}. Docker, libvirt and LXC need IP forwarding, so only apply settings you understand.",
                               f"echo '{key} = {rec}' | sudo tee -a /etc/sysctl.d/90-hardening.conf && sudo sysctl --system"))
    facts["sysctl"] = sysctl
    passed = sum(1 for s in sysctl if s["ok"])
    out.append(finding("sysctl", "Kernel & hardware", f"Kernel hardening settings: {passed}/{len(sysctl)} recommended",
                       "pass" if passed == len(sysctl) else "info", "low", "See the hardening table for each setting."))
    return out, facts


def _exposure(db) -> tuple[list[dict], dict]:
    out, facts = [], {}
    net = (db.snapshot("network") or {}).get("data") or {}
    fw = (net.get("firewall") or {}).get("ufw_enabled")
    listen = [l for l in net.get("listening", []) if l["exposed"] and not l["ip"].startswith(("192.168.122.", "10.0.3.", "fc", "fe80"))]
    ports = sorted({l["port"] for l in listen})
    rows = []
    for p in ports:
        name, sev, why = RISKY_PORTS.get(p, ("", "low", ""))
        owner = next((l["process"] for l in listen if l["port"] == p and l["process"]), None)
        rows.append({"port": p, "service": name or owner or "unknown", "owner": owner, "severity": sev, "why": why})
    facts["exposed"] = rows
    out.append(finding("firewall", "Network exposure", "Firewall " + ("on" if fw else "off"), "pass" if fw else "fail", "high",
                       f"{len(ports)} ports reachable from other devices on any network this machine joins: {', '.join(map(str, ports))}. "
                       "Note: ports published by Docker bypass ufw; bind those to 127.0.0.1 or your LAN IP in docker-compose.yml."
                       if not fw else "ufw is active.",
                       "" if fw else "sudo ufw default deny incoming && sudo ufw allow from 192.168.0.0/16 && sudo ufw enable"))
    for r in rows:
        if r["severity"] == "high":
            out.append(finding(f"port-{r['port']}", "Network exposure", f"{r['service']} reachable on port {r['port']}", "fail", "high",
                               r["why"], "Bind it to 127.0.0.1 (or your LAN IP) or stop the service if unused."))
        elif r["severity"] == "medium":
            out.append(finding(f"port-{r['port']}", "Network exposure", f"{r['service']} reachable on port {r['port']}", "warn", "medium", r["why"]))
    return out, facts


def _ssh_config() -> dict:
    """First value wins, like sshd; Include is expanded where it appears."""
    vals: dict[str, str] = {}

    def parse(path: str):
        for line in read(path).splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            k, _, v = line.partition(" ")
            k = k.lower()
            if k == "include":
                for inc in sorted(glob.glob(v.strip() if v.strip().startswith("/") else "/etc/ssh/" + v.strip())):
                    parse(inc)
            elif k == "match":
                return  # settings after Match apply conditionally; stop at the first block
            else:
                vals.setdefault(k, v.strip().lower())
    parse("/etc/ssh/sshd_config")
    return vals


def _access(db) -> tuple[list[dict], dict]:
    out, facts = [], {}
    groups = {}
    for line in read("/etc/group").splitlines():
        f = line.split(":")
        if len(f) >= 4:
            groups[f[0]] = [u for u in f[3].split(",") if u]
    uid0 = [l.split(":")[0] for l in read("/etc/passwd").splitlines() if l.count(":") >= 6 and l.split(":")[2] == "0"]
    shells = [l.split(":")[0] for l in read("/etc/passwd").splitlines()
              if l.count(":") >= 6 and int(l.split(":")[2] or 0) >= 1000 and not l.split(":")[6].endswith(("nologin", "false"))]
    facts.update(sudo=groups.get("sudo", []), docker=groups.get("docker", []), uid0=uid0, login_users=shells)
    out.append(finding("uid0", "Accounts & access", "Only root has UID 0" if uid0 == ["root"] else f"Extra UID-0 accounts: {', '.join(uid0)}",
                       "pass" if uid0 == ["root"] else "fail", "high", "", "" if uid0 == ["root"] else "Remove or fix these accounts."))
    dk = [u for u in groups.get("docker", []) if u != "root"]
    if dk:
        out.append(finding("docker-group", "Accounts & access", f"Docker group: {', '.join(dk)}", "info", "medium",
                           "Members of the docker group can become root. Keep it to accounts you fully trust."))
    ssh_running = run(["systemctl", "is-active", "ssh.service"]).strip() == "active" or \
        run(["systemctl", "is-active", "ssh.socket"]).strip() == "active"
    cfg = _ssh_config()
    facts["ssh"] = {"running": ssh_running, **{k: cfg.get(k) for k in ("passwordauthentication", "permitrootlogin", "pubkeyauthentication", "port")}}
    if ssh_running:
        pw = cfg.get("passwordauthentication", "yes")
        root = cfg.get("permitrootlogin", "prohibit-password")
        out.append(finding("ssh-password", "Accounts & access", "SSH password logins " + ("allowed" if pw != "no" else "disabled"),
                           "warn" if pw != "no" else "pass", "medium",
                           "Passwords can be guessed; keys cannot. First confirm you can log in with an SSH key, then turn passwords off."
                           if pw != "no" else "Only SSH keys are accepted.",
                           "echo 'PasswordAuthentication no' | sudo tee /etc/ssh/sshd_config.d/10-keys-only.conf && sudo systemctl reload ssh"
                           if pw != "no" else ""))
        out.append(finding("ssh-root", "Accounts & access", f"SSH root login: {root}", "pass" if root in ("no", "prohibit-password", "without-password") else "fail",
                           "high", "", "echo 'PermitRootLogin no' | sudo tee /etc/ssh/sshd_config.d/10-no-root.conf && sudo systemctl reload ssh"
                           if root == "yes" else ""))
    # Failed logins (needs membership of adm or systemd-journal to read other users' logs).
    txt = run(["journalctl", "--since", "-24h", "-q", "-o", "short-unix", "SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10"], timeout=30)
    ips, fails, sudo_fail, series = {}, 0, 0, {}
    for line in txt.splitlines():
        low = line.lower()
        if "failed password" in low or "invalid user" in low or "authentication failure" in low:
            fails += 1
            try:
                hour = int(float(line.split(" ", 1)[0]) // 3600 * 3600)
                series[hour] = series.get(hour, 0) + 1
            except ValueError:
                pass
            m = re.search(r"from (\S+) port", line) or re.search(r"rhost=(\S+)", line)
            if m:
                ips[m.group(1)] = ips.get(m.group(1), 0) + 1
            if "sudo" in low:
                sudo_fail += 1
    facts["failed_logins"] = {"total": fails, "sudo": sudo_fail, "by_ip": sorted(ips.items(), key=lambda x: -x[1])[:15],
                              "series": sorted(series.items()), "readable": bool(txt)}
    sev_status = "fail" if fails > 50 else "warn" if fails > 10 else "pass"
    out.append(finding("failed-logins", "Accounts & access", f"{fails} failed logins in the last 24 h", sev_status, "medium",
                       (f"Top sources: {', '.join(f'{ip} ({n})' for ip, n in facts['failed_logins']['by_ip'][:5])}." if ips else "")
                       + (" Repeated failures from outside your LAN mean someone is guessing passwords." if fails > 10 else ""),
                       "sudo apt install fail2ban" if fails > 10 else ""))
    return out, facts


def _files(cfg) -> tuple[list[dict], dict]:
    out, facts = [], {}
    checks = []
    env = Path(cfg["immich"]["app_dir"]) / ".env"

    def mode(p: Path):
        try:
            return stat.S_IMODE(p.stat().st_mode)
        except OSError:
            return None
    m = mode(env)
    if m is not None:
        ok = not (m & 0o044)
        checks.append({"path": str(env), "mode": oct(m), "ok": ok})
        out.append(finding("immich-env", "Secrets & files", "Immich .env is private" if ok else "Immich .env is readable by other users",
                           "pass" if ok else "warn", "medium",
                           "It contains the database password." + ("" if ok else f" Current mode {oct(m)[2:]}."),
                           "" if ok else f"chmod 600 {env}"))
    ssh = Path.home() / ".ssh"
    if ssh.exists():
        bad = []
        if (mode(ssh) or 0) & 0o077:
            bad.append(f"{ssh} ({oct(mode(ssh))[2:]})")
        for f in ssh.iterdir():
            if f.is_file() and not f.name.endswith(".pub") and f.name not in ("known_hosts", "known_hosts.old", "config") and (mode(f) or 0) & 0o077:
                bad.append(f"{f} ({oct(mode(f))[2:]})")
        out.append(finding("ssh-keys", "Secrets & files", "SSH keys are private" if not bad else "SSH files readable by others",
                           "pass" if not bad else "fail", "high", ", ".join(bad), "chmod 700 ~/.ssh && chmod 600 ~/.ssh/id_* ~/.ssh/authorized_keys" if bad else ""))
    gm = mode(C.CONFIG_DIR)
    out.append(finding("guardian-config", "Secrets & files", "Guardian config is private" if gm is not None and not gm & 0o077 else "Guardian config readable by others",
                       "pass" if gm is not None and not gm & 0o077 else "warn", "medium", str(C.CONFIG_DIR),
                       f"chmod 700 {C.CONFIG_DIR}" if gm is not None and gm & 0o077 else ""))
    if (C.CONFIG_DIR / "initial-password.txt").exists():
        out.append(finding("guardian-initial-pw", "Secrets & files", "Guardian still uses its generated password", "warn", "medium",
                           "Change it in Settings; the file with the password is then removed."))
    facts["files"] = checks
    return out, facts


def _docker() -> tuple[list[dict], dict]:
    out, facts = [], {}
    try:
        ctrs = docker_api("/containers/json")
    except Exception:
        return out, facts
    rows = []
    for c in ctrs:
        try:
            d = docker_api(f"/containers/{c['Id']}/json")
        except Exception:
            continue
        name = d["Name"].lstrip("/")
        hc = d["HostConfig"]
        sock = any(m.get("Source") in ("/var/run/docker.sock", "/run/docker.sock") for m in d.get("Mounts", []))
        public = sorted({p.get("PublicPort") for p in c.get("Ports", []) if p.get("PublicPort") and p.get("IP") in ("0.0.0.0", "::", "")})
        caps = hc.get("CapAdd") or []
        row = {"name": name, "image": d["Config"]["Image"], "privileged": hc.get("Privileged"), "docker_sock": sock,
               "host_network": hc.get("NetworkMode") == "host", "user": d["Config"].get("User") or "root",
               "public_ports": public, "cap_add": caps, "read_only": hc.get("ReadonlyRootfs"),
               "no_new_privs": any("no-new-privileges" in o for o in (hc.get("SecurityOpt") or []))}
        rows.append(row)
        if row["privileged"]:
            out.append(finding(f"ctr-priv-{name}", "Docker", f"{name} runs privileged", "fail", "high",
                               "A privileged container has full access to the host.", "Remove 'privileged: true' unless required."))
        if sock:
            out.append(finding(f"ctr-sock-{name}", "Docker", f"{name} has the Docker socket mounted",
                               "fail" if public else "warn", "high" if public else "medium",
                               "Access to the Docker socket equals root on the host" + (f", and this container is reachable on ports {', '.join(map(str, public))}." if public else "."),
                               "If you need it (e.g. Portainer), keep it bound to 127.0.0.1 or your LAN IP and protected by a strong password."))
        if row["host_network"]:
            out.append(finding(f"ctr-hostnet-{name}", "Docker", f"{name} uses host networking", "warn", "low",
                               "It shares the host's network stack and bypasses Docker's port isolation."))
    facts["containers"] = rows
    if rows and not any(o["status"] in ("fail", "warn") for o in out):
        out.append(finding("docker-ok", "Docker", "No privileged or socket-mounting containers", "pass", "medium"))
    return out, facts


def _immich(cfg, db) -> tuple[list[dict], dict]:
    out, facts = [], {}
    imm = (db.snapshot("immich") or {}).get("data") or {}
    current = imm.get("version")
    cache = C.STATE_DIR / "immich-latest.json"
    latest = None
    try:
        cached = json.loads(read(str(cache), "{}"))
        if time.time() - cached.get("ts", 0) < 86400:
            latest = cached.get("tag")
        else:
            req = urllib.request.Request("https://api.github.com/repos/immich-app/immich/releases/latest",
                                         headers={"User-Agent": "guardian", "Accept": "application/vnd.github+json"})
            with urllib.request.urlopen(req, timeout=8) as r:
                latest = json.loads(r.read()).get("tag_name", "").lstrip("v")
            cache.write_text(json.dumps({"ts": time.time(), "tag": latest}))
    except Exception:
        pass
    facts.update(current=current, latest=latest)
    if current and latest:
        cur = tuple(int(x) for x in current.split(".")[:3])
        new = tuple(int(x) for x in re.findall(r"\d+", latest)[:3])
        behind = new > cur
        out.append(finding("immich-version", "Immich", f"Immich {current}" + (f" (latest {latest})" if behind else " is the latest release"),
                           "warn" if behind else "pass", "medium",
                           "Releases often include security fixes. Make sure you have a backup and read the release notes first: "
                           "major versions can need migration steps." if behind else "",
                           f"cd {cfg['immich']['app_dir']} && docker compose pull && docker compose up -d" if behind else ""))
    out.append(finding("immich-tls", "Immich", "Immich served over plain HTTP", "info", "low",
                       "Fine on a home network. For access from outside, put it behind a reverse proxy with HTTPS (e.g. Caddy) "
                       "or a VPN such as Tailscale/WireGuard instead of forwarding ports on your router."))
    if cfg["backup"]["drive_uuid"]:
        out.append(finding("backup-encryption", "Immich", "Backup drive is not encrypted", "info", "low",
                           "The backup contains your photos and Immich's .env (database password). Keep the drive somewhere safe, "
                           "or use an encrypted (LUKS) drive for backups."))
    return out, facts


def audit(cfg, db) -> dict:
    findings, facts = [], {}
    for fn in (_updates, _hardening, lambda: _exposure(db), lambda: _access(db), lambda: _files(cfg), _docker,
               lambda: _immich(cfg, db)):
        try:
            f, x = fn()
        except Exception as e:  # one failing check must not hide the rest
            f, x = [finding(f"error-{getattr(fn, '__name__', 'check')}", "Guardian", "A security check failed to run", "info", "low", str(e))], {}
        findings += f
        facts.update(x)
    # Penalties are capped per category: one root cause (e.g. an exposed admin UI) often shows up as
    # several findings, and the score should say where you stand, not bottom out.
    per_cat: dict[str, int] = {}
    for f in findings:
        per_cat[f["category"]] = per_cat.get(f["category"], 0) + WEIGHT.get((f["status"], f["severity"]), 0)
    score = max(0, 100 - sum(min(v, 25) for v in per_cat.values()))
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    order = {"fail": 0, "warn": 1, "info": 2, "pass": 3}
    sev = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (order[f["status"]], sev.get(f["severity"], 3), f["category"]))
    return {"score": score, "grade": grade, "findings": findings, "facts": facts, "ts": int(time.time())}


# ---------------------------------------------------------------------- image CVE scanning
class ImageScanner:
    """Runs Trivy (aquasec/trivy) in a throwaway container against the images of running containers."""

    def __init__(self, cfg, db, gov):
        self.cfg, self.db, self.gov = cfg, db, gov
        self.thread: threading.Thread | None = None
        self.progress: dict = {}
        self.stop = threading.Event()

    def running(self) -> bool:
        return bool(self.thread and self.thread.is_alive())

    def start(self) -> None:
        if self.running():
            raise RuntimeError("an image scan is already running")
        self.stop.clear()
        self.thread = threading.Thread(target=self._run, daemon=True, name="image-scan")
        self.thread.start()

    def _run(self) -> None:
        sc = self.cfg["security"]
        try:
            images = sorted({c["Image"] for c in docker_api("/containers/json")})
        except Exception as e:
            self.progress = {"error": str(e)}
            return
        results, started = [], time.time()
        for i, img in enumerate(images):
            if self.stop.is_set():
                break
            self.progress = {"image": img, "done": i, "total": len(images), "started": started}
            self.gov.pause_if_busy(self.stop)
            cmd = ["docker", "run", "--rm", "--cpus", str(sc["trivy_cpus"]), "--memory", sc["trivy_memory"],
                   "-v", "/var/run/docker.sock:/var/run/docker.sock:ro", "-v", "guardian-trivy-cache:/root/.cache/",
                   sc["trivy_image"], "image", "--quiet", "--format", "json", "--scanners", "vuln",
                   "--severity", "CRITICAL,HIGH,MEDIUM,LOW", "--timeout", "20m", img]
            try:
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
                data = json.loads(p.stdout) if p.stdout.strip() else None
            except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as e:
                results.append({"image": img, "error": str(e)[:300]})
                continue
            if not data:
                results.append({"image": img, "error": (p.stderr or "no output")[-300:]})
                continue
            vulns = []
            for r in data.get("Results") or []:
                for v in r.get("Vulnerabilities") or []:
                    vulns.append({"id": v.get("VulnerabilityID"), "pkg": v.get("PkgName"), "installed": v.get("InstalledVersion"),
                                  "fixed": v.get("FixedVersion") or "", "severity": v.get("Severity"), "title": (v.get("Title") or "")[:160],
                                  "target": r.get("Target", "")[:80]})
            counts = {s: sum(1 for v in vulns if v["severity"] == s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
            fixable = sum(1 for v in vulns if v["fixed"])
            order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            vulns.sort(key=lambda v: (order.get(v["severity"], 9), not v["fixed"]))
            results.append({"image": img, "counts": counts, "fixable": fixable, "total": len(vulns), "top": vulns[:150],
                            "os": (data.get("Metadata") or {}).get("OS", {})})
        self.db.put_snapshot("image_vulns", {"images": results, "finished": time.time(), "duration": time.time() - started})
        self.progress = {}
