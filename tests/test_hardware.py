"""Battery, power and thermal readings on a fake sysfs tree, and the rules built on them."""
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from guardian import config, hardware as HW, rules
from guardian.db import DB
from guardian.governor import Governor


def tree(files: dict) -> str:
    root = Path(tempfile.mkdtemp())
    for rel, val in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(f"{val}\n")
    return str(root)


PS = "class/power_supply"
LAPTOP = {
    f"{PS}/AC/type": "Mains", f"{PS}/AC/online": 1,
    f"{PS}/BAT0/type": "Battery", f"{PS}/BAT0/status": "Not charging", f"{PS}/BAT0/capacity": 99,
    f"{PS}/BAT0/energy_now": 41400000, f"{PS}/BAT0/energy_full": 42000000, f"{PS}/BAT0/energy_full_design": 50000000,
    f"{PS}/BAT0/power_now": 0, f"{PS}/BAT0/voltage_now": 12600000, f"{PS}/BAT0/cycle_count": 900,
    f"{PS}/BAT0/charge_control_start_threshold": 0, f"{PS}/BAT0/charge_control_end_threshold": 100,
    "class/hwmon/hwmon0/name": "thinkpad", "class/hwmon/hwmon0/temp1_input": 61000, "class/hwmon/hwmon0/temp1_label": "CPU",
    "class/hwmon/hwmon0/temp4_input": 0, "class/hwmon/hwmon0/fan1_input": 2700,
    "class/hwmon/hwmon1/name": "coretemp", "class/hwmon/hwmon1/temp1_input": 63000, "class/hwmon/hwmon1/temp1_label": "Package id 0",
    "class/hwmon/hwmon1/temp1_crit": 100000,
    "class/hwmon/hwmon2/name": "nvme", "class/hwmon/hwmon2/temp1_input": 45000,
    "devices/system/cpu/cpu0/thermal_throttle/package_throttle_total_time_ms": 7000,
    "devices/system/cpu/cpu1/thermal_throttle/package_throttle_total_time_ms": 7000,
    "devices/system/cpu/cpu0/thermal_throttle/core_throttle_total_time_ms": 900,
    "devices/system/cpu/cpu0/cpufreq/scaling_cur_freq": 3000000, "devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq": 4200000,
}


class Readers(unittest.TestCase):
    def test_laptop_plugged_in(self):
        d = HW.read_all(tree(LAPTOP))
        b = d["batteries"][0]
        self.assertEqual((b["percent"], b["cycles"], b["end_threshold"]), (99, 900, 100))
        self.assertAlmostEqual(b["health"], 84.0)
        self.assertFalse(d["on_battery"])
        self.assertEqual(d["cpu_temp"], 63.0)                     # package sensor preferred over the ThinkPad one
        self.assertEqual(len(d["temps"]), 2)                      # 0 °C placeholder and drive sensor skipped
        fast = HW.read_all(tree(LAPTOP), fast_only=True)
        self.assertEqual([t["chip"] for t in fast["temps"]], ["coretemp"])
        self.assertEqual(fast["fans"], [])
        self.assertEqual(d["fans"][0]["rpm"], 2700)
        self.assertEqual(d["throttle"]["ms"], 7000)               # package time counted once, not per CPU
        self.assertEqual((d["freq_mhz"], d["freq_max_mhz"]), (3000.0, 4200.0))

    def test_on_battery_with_time_left(self):
        d = HW.read_all(tree({**LAPTOP, f"{PS}/AC/online": 0, f"{PS}/BAT0/status": "Discharging", f"{PS}/BAT0/power_now": 9000000}))
        self.assertTrue(d["on_battery"])
        self.assertEqual(d["batteries"][0]["minutes"], 276)      # 41.4 Wh at 9 W

    def test_charge_based_battery_and_no_mains(self):
        d = HW.read_all(tree({f"{PS}/BAT1/type": "Battery", f"{PS}/BAT1/status": "Discharging", f"{PS}/BAT1/capacity": 50,
                              f"{PS}/BAT1/charge_now": 2000000, f"{PS}/BAT1/charge_full": 4000000,
                              f"{PS}/BAT1/charge_full_design": 5000000, f"{PS}/BAT1/voltage_now": 10000000,
                              f"{PS}/BAT1/current_now": 1000000}))
        b = d["batteries"][0]
        self.assertEqual((b["energy_wh"], b["full_wh"], b["health"], b["watts"]), (20.0, 40.0, 80.0, 10.0))
        self.assertTrue(d["on_battery"])
        self.assertIsNone(b["end_threshold"])

    def test_desktop_without_sensors(self):
        d = HW.read_all(tree({"class/power_supply/.keep": ""}))
        self.assertEqual((d["batteries"], d["on_battery"], d["cpu_temp"]), ([], False, None))
        self.assertFalse(d["throttle"]["supported"])

    def test_threshold_commands_persist(self):
        b = HW.read_all(tree(LAPTOP))["batteries"][0]
        cmds = HW.threshold_commands(b).splitlines()
        self.assertTrue(all(c.split()[0] in ("echo", "printf") for c in cmds))
        self.assertIn("/etc/tmpfiles.d/", cmds[-1])
        self.assertIn("start_threshold", cmds[0])              # start before end, so start < end always holds


class HardwareRules(unittest.TestCase):
    def setUp(self):
        self.cfg = config.load()
        self.db = DB(Path(tempfile.mkdtemp()) / "t.db")

    def ids(self, files, rows=()):
        self.db.put_snapshot("hardware", HW.read_all(tree(files)))
        now = int(time.time())
        for i, r in enumerate(rows):
            self.db.insert("hw_samples", dict(ts=now - i * 15, **r))
        return {r["id"]: r for r in rules.evaluate(self.db, self.cfg)}

    def test_always_plugged_in_suggests_charge_limit(self):
        recs = self.ids(LAPTOP, [dict(on_battery=0, throttle_pct=0, cpu_temp=60)] * 30)
        self.assertIn("battery-limit-BAT0", recs)
        self.assertIn("sudo tee", recs["battery-limit-BAT0"]["suggestion"])
        self.assertIn("battery-health-BAT0", recs)                # 84% of design
        self.assertNotIn("power-on-battery", recs)

    def test_on_battery_low_is_critical(self):
        recs = self.ids({**LAPTOP, f"{PS}/AC/online": 0, f"{PS}/BAT0/status": "Discharging", f"{PS}/BAT0/capacity": 20})
        self.assertEqual(recs["power-on-battery"]["severity"], "critical")

    def test_throttling_and_stopped_fan(self):
        hot = {**LAPTOP, "class/hwmon/hwmon1/temp1_input": 88000, "class/hwmon/hwmon0/fan1_input": 0}
        recs = self.ids(hot, [dict(on_battery=0, throttle_pct=3.0, cpu_temp=88)] * 30)
        self.assertIn("cpu-throttling", recs)
        self.assertIn("cpu-hot", recs)
        self.assertIn("fan-stopped", recs)

    def test_cool_machine_is_quiet(self):
        recs = self.ids({**LAPTOP, f"{PS}/BAT0/charge_control_end_threshold": 80}, [dict(on_battery=0, throttle_pct=0.1, cpu_temp=55)] * 30)
        self.assertFalse({"cpu-throttling", "cpu-hot", "fan-stopped", "battery-limit-BAT0"} & set(recs))


class Governor_(unittest.TestCase):
    def test_battery_and_heat_make_the_system_busy(self):
        g = Governor(config.load())
        with mock.patch("os.getloadavg", return_value=(0, 0, 0)), mock.patch("guardian.governor.psi", return_value=0):
            self.assertNotIn("battery", g.busy() and g.reason or "")
            g.update_hardware(True, 50)
            self.assertTrue(g.busy())
            self.assertIn("on battery", g.reason)
            g.update_hardware(False, 95)
            self.assertTrue(g.busy())
            self.assertIn("95°C", g.reason)


if __name__ == "__main__":
    unittest.main()
