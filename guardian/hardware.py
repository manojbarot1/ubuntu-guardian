"""Battery, power and thermal readings from sysfs. Read-only, no root, a few dozen small file reads.

Every reader takes the sysfs root so tests can point it at a fake tree.
"""
from __future__ import annotations

import os
from pathlib import Path

# Drivers read straight from CPU registers: cheap enough for every run. Others (thinkpad, acpitz: the
# embedded controller over ACPI, ~1-4 ms each) are read less often; drive sensors are skipped because
# reading them sends a command to the drive, and the SMART collector already reports drive temperatures.
FAST_CHIPS = {"coretemp", "k10temp", "zenpower", "cpu_thermal"}
SKIP_CHIPS = {"nvme", "drivetemp"}

# Sensor drivers that report the CPU package/die temperature, best first.
CPU_SENSORS = [("coretemp", "Package id 0"), ("k10temp", "Tctl"), ("k10temp", "Tdie"), ("zenpower", "Tdie"),
               ("cpu_thermal", None), ("thinkpad", "CPU"), ("acpitz", None)]


def _r(path: Path, default: str | None = None) -> str | None:
    try:
        return path.read_text().strip()
    except OSError:
        return default


def _int(path: Path) -> int | None:
    v = _r(path)
    try:
        return int(v) if v not in (None, "") else None
    except ValueError:
        return None


def batteries(sys: str = "/sys") -> list[dict]:
    out = []
    base = Path(sys) / "class/power_supply"
    for p in sorted(base.glob("*")) if base.exists() else []:
        if _r(p / "type") != "Battery" or _r(p / "present", "1") == "0":
            continue
        volt = (_int(p / "voltage_now") or 0) / 1e6
        # Energy (µWh) when the driver reports it, otherwise charge (µAh) × voltage.
        if _int(p / "energy_full") is not None:
            now, full, design = (_int(p / f) or 0 for f in ("energy_now", "energy_full", "energy_full_design"))
            watts = (_int(p / "power_now") or 0) / 1e6
        else:
            v = volt or 1
            now, full, design = ((_int(p / f) or 0) * v for f in ("charge_now", "charge_full", "charge_full_design"))
            watts = (_int(p / "current_now") or 0) / 1e6 * volt
        status = _r(p / "status", "Unknown")
        ends = [f for f in ("charge_control_end_threshold", "charge_stop_threshold") if (p / f).exists()]
        starts = [f for f in ("charge_control_start_threshold", "charge_start_threshold") if (p / f).exists()]
        b = {"name": p.name, "status": status, "percent": _int(p / "capacity"),
             "energy_wh": now / 1e6, "full_wh": full / 1e6, "design_wh": design / 1e6,
             "health": round(100 * full / design, 1) if design else None,
             "watts": watts, "cycles": _int(p / "cycle_count"),
             "technology": _r(p / "technology"), "model": _r(p / "model_name"), "manufacturer": _r(p / "manufacturer"),
             "end_threshold": _int(p / ends[0]) if ends else None, "start_threshold": _int(p / starts[0]) if starts else None,
             "end_threshold_file": str(p / ends[0]) if ends else None,
             "start_threshold_file": str(p / starts[0]) if starts else None}
        # Minutes until empty (discharging) or full (charging), from the current power draw.
        if watts > 0.5 and status == "Discharging":
            b["minutes"] = round(60 * b["energy_wh"] / watts)
        elif watts > 0.5 and status == "Charging" and full:
            b["minutes"] = round(60 * (b["full_wh"] - b["energy_wh"]) / watts)
        out.append(b)
    return out


def on_battery(sys: str = "/sys", bats: list[dict] | None = None) -> bool:
    """True when running from battery: a battery is discharging and no mains adapter is online."""
    bats = batteries(sys) if bats is None else bats
    if not bats:
        return False
    base = Path(sys) / "class/power_supply"
    mains = [p for p in base.glob("*") if _r(p / "type") == "Mains"]
    if mains:
        return not any(_r(p / "online") == "1" for p in mains)
    return any(b["status"] == "Discharging" for b in bats)


def sensors(sys: str = "/sys", fast_only: bool = False) -> tuple[list[dict], list[dict]]:
    """hwmon temperatures (°C) and fans (RPM). Unplugged or zero readings are skipped."""
    temps, fans = [], []
    base = Path(sys) / "class/hwmon"
    for h in sorted(base.glob("hwmon*")) if base.exists() else []:
        name = _r(h / "name", h.name)
        if name in SKIP_CHIPS or (fast_only and name not in FAST_CHIPS):
            continue
        for t in sorted(h.glob("temp*_input")):
            v = _int(t)
            if not v or v <= 0 or v > 150000:
                continue
            stem = str(t)[: -len("_input")]
            crit = _int(Path(stem + "_crit"))
            temps.append({"chip": name, "label": _r(Path(stem + "_label")) or t.name.split("_")[0],
                          "c": v / 1000, "crit": crit / 1000 if crit and crit < 150000 else None})
        for f in sorted(h.glob("fan*_input")):
            v = _int(f)
            if v is not None:
                fans.append({"chip": name, "label": _r(Path(str(f)[: -len("_input")] + "_label")) or f.name.split("_")[0], "rpm": v})
    return temps, fans


def cpu_temp(temps: list[dict]) -> float | None:
    for chip, label in CPU_SENSORS:
        for t in temps:
            if t["chip"] == chip and (label is None or t["label"] == label):
                return t["c"]
    return None


def throttle(sys: str = "/sys") -> dict:
    """Time the CPUs spent slowed down by heat since boot (ms), from the Intel thermal_throttle counters.

    Package counters repeat on every CPU of a package, so the maximum is taken, not the sum."""
    core_ms = pkg_ms = core_n = pkg_n = 0
    found = False
    for d in (Path(sys) / "devices/system/cpu").glob("cpu[0-9]*/thermal_throttle"):
        found = True
        core_ms = max(core_ms, _int(d / "core_throttle_total_time_ms") or 0)
        pkg_ms = max(pkg_ms, _int(d / "package_throttle_total_time_ms") or 0)
        core_n += _int(d / "core_throttle_count") or 0
        pkg_n = max(pkg_n, _int(d / "package_throttle_count") or 0)
    return {"supported": found, "ms": max(core_ms, pkg_ms), "core_count": core_n, "package_count": pkg_n}


def cpu_freq(sys: str = "/sys") -> tuple[float | None, float | None]:
    """Average current and maximum CPU frequency in MHz."""
    cur, top = [], 0
    for d in (Path(sys) / "devices/system/cpu").glob("cpu[0-9]*/cpufreq"):
        c = _int(d / "scaling_cur_freq")
        if c:
            cur.append(c)
        top = max(top, _int(d / "cpuinfo_max_freq") or 0)
    return (sum(cur) / len(cur) / 1000 if cur else None), (top / 1000 or None)


def platform_profile(sys: str = "/sys") -> str | None:
    return _r(Path(sys) / "firmware/acpi/platform_profile")


def threshold_commands(b: dict, end: int = 80, start: int = 75) -> str:
    """Commands (for the user to run) that cap charging now and after every reboot."""
    lines = []
    if b.get("start_threshold_file"):
        lines.append(f"echo {start} | sudo tee {b['start_threshold_file']}")
    lines.append(f"echo {end} | sudo tee {b['end_threshold_file']}")
    rule = "\\n".join(x for x in (
        f"w {b['start_threshold_file']} - - - - {start}" if b.get("start_threshold_file") else "",
        f"w {b['end_threshold_file']} - - - - {end}") if x)
    lines.append(f"printf '{rule}\\n' | sudo tee /etc/tmpfiles.d/battery-charge-limit.conf")
    return "\n".join(lines)


def read_all(sys: str = "/sys", fast_only: bool = False) -> dict:
    """fast_only: CPU-register sensors only (the caller merges in its last full reading)."""
    bats = batteries(sys)
    temps, fans = sensors(sys, fast_only)
    cur, top = cpu_freq(sys)
    return {"batteries": bats, "on_battery": on_battery(sys, bats), "temps": temps, "fans": fans,
            "cpu_temp": cpu_temp(temps), "throttle": throttle(sys), "freq_mhz": cur, "freq_max_mhz": top,
            "profile": platform_profile(sys), "ncpu": os.cpu_count()}
