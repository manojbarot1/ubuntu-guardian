"""Service intelligence: explain what a unit is, why it runs, and what stopping it would affect."""
from __future__ import annotations

import fnmatch
import re

from . import services_kb
from .util import read, run

UNIT_RE = re.compile(r"^[A-Za-z0-9@_.:\\-]{1,200}\.service$")

SHOW_PROPS = ["Id", "Description", "LoadState", "ActiveState", "SubState", "UnitFileState", "UnitFilePreset",
              "FragmentPath", "Documentation", "Requires", "Wants", "BindsTo", "RequiredBy", "WantedBy", "Before",
              "After", "TriggeredBy", "Triggers", "MainPID", "ExecMainStartTimestamp", "ActiveEnterTimestamp",
              "ControlGroup", "MemoryCurrent", "CPUUsageNSec", "NRestarts", "Restart", "User", "Type",
              "CanStop", "CanStart", "CanReload", "RefuseManualStop", "RefuseManualStart", "Result", "StatusText"]


def valid_unit(unit: str) -> bool:
    return bool(UNIT_RE.match(unit))


def is_protected_unit(unit: str, cfg: dict) -> bool:
    return any(fnmatch.fnmatch(unit, pat) for pat in cfg["protection"]["protected_units"])


def show(unit: str) -> dict:
    out = {}
    for line in run(["systemctl", "show", "-p", ",".join(SHOW_PROPS), "--", unit]).splitlines():
        k, _, v = line.partition("=")
        out[k] = v
    return out


def _deps(unit: str, reverse: bool) -> list[str]:
    cmd = ["systemctl", "list-dependencies", "--plain", "--no-pager"] + (["--reverse"] if reverse else []) + ["--", unit]
    lines = run(cmd).splitlines()[1:]
    return sorted({l.strip().lstrip("●○ ").strip() for l in lines if l.strip()})[:80]


def detail(unit: str, cfg: dict, docker_snapshot: dict | None, immich_snapshot: dict | None) -> dict:
    if not valid_unit(unit):
        raise ValueError("invalid unit name")
    p = show(unit)
    if p.get("LoadState") in ("not-found", "", None):
        raise LookupError(f"{unit} not found")
    kb = services_kb.lookup(unit)
    requires = [u for u in (p.get("Requires", "") + " " + p.get("BindsTo", "")).split() if u]
    wants = p.get("Wants", "").split()
    rdeps = _deps(unit, reverse=True)
    docker_deps = set(_deps("docker.service", reverse=False))
    pkg = ""
    frag = p.get("FragmentPath", "")
    if frag:
        # dpkg may record the pre-usrmerge path (/lib/...) for files now under /usr/lib/...
        for cand in (frag, frag.removeprefix("/usr") if frag.startswith("/usr/lib/") else "/usr" + frag):
            owner = run(["dpkg", "-S", cand], timeout=10).split(":", 1)
            if len(owner) == 2:
                pkg = owner[0]
                break
        else:
            pkg = "local (not from a package)" if frag.startswith(("/etc", "/home")) else "unknown"
    # Is it part of what keeps Immich/Docker alive?
    immich_related = kb.get("immich", False) or unit in docker_deps or "docker.service" in rdeps
    backup_related = unit in ("udisks2.service", "polkit.service") or unit.startswith("udisks")
    procs = []
    cg = p.get("ControlGroup")
    if cg:
        for pid in read(f"/sys/fs/cgroup{cg}/cgroup.procs").split()[:20]:
            cmd = read(f"/proc/{pid}/cmdline").replace("\0", " ").strip()
            procs.append({"pid": int(pid), "cmd": cmd[:200]})
    protected = is_protected_unit(unit, cfg) or kb.get("risk") == "critical"
    why_running = []
    if p.get("TriggeredBy"):
        why_running.append(f"Started on demand by {p['TriggeredBy']}")
    wanted = [u for u in p.get("WantedBy", "").split() + p.get("RequiredBy", "").split() if u]
    if wanted:
        why_running.append("Pulled in at boot by " + ", ".join(wanted[:6]))
    if p.get("UnitFileState") == "static":
        why_running.append("Static unit: it has no install section and runs only when another unit needs it")
    if p.get("UnitFileState") == "enabled":
        why_running.append("Enabled: starts automatically at boot")
    dependents = [u for u in rdeps if u.endswith((".service", ".socket", ".timer", ".mount")) and u != unit]
    if kb.get("stop"):
        consequences_stop = kb["stop"]
    elif kb.get("known"):
        consequences_stop = f"This stops working: {kb['purpose'].rstrip('.').lower()}."
    else:
        consequences_stop = "Not in the knowledge base, so the effect is uncertain."
    if dependents:
        consequences_stop += f" Units that depend on it and may stop or degrade: {', '.join(dependents[:8])}."
    elif not kb.get("stop"):
        consequences_stop += " No other services depend on it."
    consequences_disable = ("It will not start at next boot. " + consequences_stop) if p.get("UnitFileState") == "enabled" \
        else "It is not enabled; disabling changes nothing at boot."
    if p.get("TriggeredBy"):
        consequences_disable += f" Note: {p['TriggeredBy']} can still start it on demand unless that is disabled too."
    return {
        "unit": unit, "props": p, "kb": kb, "package": pkg,
        "requires": requires, "wants": wants[:40], "reverse_dependencies": rdeps,
        "immich_related": immich_related, "backup_related": backup_related,
        "processes": procs, "protected": protected,
        "why_running": why_running,
        "consequences": {"stop": consequences_stop, "disable": consequences_disable},
        "confidence": "high" if kb.get("known") else "low",
        "investigate": [
            f"journalctl -u {unit} -n 100 --no-pager",
            f"systemctl status {unit}",
            f"systemctl list-dependencies --reverse {unit}",
        ],
        "allowed_actions": [] if protected else _allowed(p),
    }


def _allowed(p: dict) -> list[str]:
    acts = []
    active = p.get("ActiveState") == "active"
    if active and p.get("CanStop") == "yes" and p.get("RefuseManualStop") != "yes":
        acts += ["stop", "restart"]
    if not active and p.get("CanStart") == "yes" and p.get("RefuseManualStart") != "yes":
        acts.append("start")
    if p.get("UnitFileState") == "enabled":
        acts.append("disable")
    if p.get("UnitFileState") == "disabled":
        acts.append("enable")
    return acts
