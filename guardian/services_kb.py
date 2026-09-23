"""What common Ubuntu services are for, and what happens if you stop them on this kind of machine.

This is a starting point, not the truth: every explanation shown in the dashboard is combined with
live evidence (dependencies, resource use, who triggers it). Unknown services are never assumed
unnecessary.

risk: how much can break if stopped/disabled
  critical - system, desktop, networking, Docker or backups break; Guardian refuses
  high     - a feature you probably rely on breaks
  medium   - an optional feature breaks; fine to disable only if you know you do not use it
  low      - optional; commonly disabled on a headless/server-style machine
"""

KB: dict[str, dict] = {
    # --- core / never touch
    "docker.service": dict(category="containers", risk="critical", purpose="Docker engine. Runs Immich and your other containers.",
                           stop="All containers stop: Immich goes offline.", immich=True),
    "containerd.service": dict(category="containers", risk="critical", purpose="Container runtime used by Docker.",
                               stop="Docker and every container stop.", immich=True),
    "dbus.service": dict(category="core", risk="critical", purpose="System message bus used by nearly every service."),
    "dbus-broker.service": dict(category="core", risk="critical", purpose="System message bus used by nearly every service."),
    "NetworkManager.service": dict(category="network", risk="critical", purpose="Manages Wi-Fi/Ethernet connections.",
                                   stop="Network drops: phones can no longer back up to Immich."),
    "wpa_supplicant.service": dict(category="network", risk="critical", purpose="Wi-Fi authentication.",
                                   stop="Wi-Fi disconnects."),
    "systemd-resolved.service": dict(category="network", risk="critical", purpose="DNS resolver."),
    "systemd-journald.service": dict(category="core", risk="critical", purpose="System logging."),
    "systemd-logind.service": dict(category="core", risk="critical", purpose="Login sessions, lid/power buttons."),
    "systemd-udevd.service": dict(category="core", risk="critical", purpose="Device detection (USB drives included)."),
    "systemd-timesyncd.service": dict(category="core", risk="high", purpose="Keeps the clock correct (TLS, backups, logs)."),
    "polkit.service": dict(category="core", risk="critical", purpose="Authorises privileged desktop actions (mounting drives)."),
    "udisks2.service": dict(category="storage", risk="critical", purpose="Mounts USB drives and reports SMART health.",
                            stop="USB drives stop auto-mounting (backups to them fail) and Guardian loses disk health data."),
    "gdm.service": dict(category="desktop", risk="critical", purpose="Graphical login screen / desktop session.",
                        stop="Your desktop session ends immediately."),
    "accounts-daemon.service": dict(category="desktop", risk="high", purpose="User account info for login screen and settings."),
    "upower.service": dict(category="desktop", risk="high", purpose="Battery and power status."),
    "power-profiles-daemon.service": dict(category="desktop", risk="medium", purpose="Power mode switching (balanced/performance)."),
    "thermald.service": dict(category="hardware", risk="high", purpose="Intel thermal management; prevents overheating under load."),
    "ssh.service": dict(category="remote", risk="high", purpose="SSH remote login.", stop="Remote SSH access stops."),
    "cron.service": dict(category="core", risk="high", purpose="Runs scheduled jobs from crontabs.",
                         stop="Every crontab entry (yours and the system's) stops running."),
    "rsyslog.service": dict(category="core", risk="medium", purpose="Writes classic text logs in /var/log."),
    "caddy.service": dict(category="web", risk="high", purpose="Caddy web server / reverse proxy (ports 80/8443).",
                          stop="Anything served through Caddy goes offline (check whether it fronts Immich)."),
    "libvirtd.service": dict(category="virtualisation", risk="medium", purpose="Runs KVM virtual machines (virbr0).",
                             stop="Virtual machines cannot start or be managed."),
    "lxd.service": dict(category="virtualisation", risk="medium", purpose="LXD containers."),
    "snapd.service": dict(category="packages", risk="medium", purpose="Snap package manager and auto-refresh.",
                          stop="Snap apps stop updating; some snap apps may not launch."),
    "unattended-upgrades.service": dict(category="packages", risk="high", purpose="Installs security updates automatically.",
                                        stop="Security patches stop arriving: not recommended for a server."),
    "apparmor.service": dict(category="security", risk="critical", purpose="Mandatory access control profiles (Docker uses it)."),
    "ufw.service": dict(category="security", risk="high", purpose="Firewall loader."),
    "fwupd.service": dict(category="hardware", risk="low", purpose="Firmware updates (on demand)."),
    # --- commonly optional on a home server
    "cups.service": dict(category="printing", risk="low", purpose="Printing system.", stop="You cannot print."),
    "cups-browsed.service": dict(category="printing", risk="low", purpose="Discovers network printers automatically."),
    "bluetooth.service": dict(category="hardware", risk="low", purpose="Bluetooth stack.",
                              stop="Bluetooth mice/headsets stop working."),
    "ModemManager.service": dict(category="network", risk="low", purpose="Mobile broadband (3G/4G/5G) modems.",
                                 stop="Only matters if you use a cellular modem or tethering via USB."),
    "avahi-daemon.service": dict(category="network", risk="low", purpose="mDNS/Bonjour (.local names, printer discovery).",
                                 stop="Other devices can no longer find this laptop by name.local."),
    "kerneloops.service": dict(category="reporting", risk="low", purpose="Sends kernel crash reports to Ubuntu."),
    "whoopsie.service": dict(category="reporting", risk="low", purpose="Sends crash reports to Ubuntu."),
    "apport.service": dict(category="reporting", risk="low", purpose="Collects crash reports."),
    "switcheroo-control.service": dict(category="hardware", risk="low", purpose="Switches between integrated/discrete GPU."),
    "gnome-remote-desktop.service": dict(category="remote", risk="medium", purpose="GNOME remote desktop (RDP, port 3389).",
                                         stop="Remote desktop into this laptop stops."),
    "colord.service": dict(category="desktop", risk="low", purpose="Colour profile management for displays/printers."),
    "packagekit.service": dict(category="packages", risk="low", purpose="Backend for Software Center updates (on demand)."),
    "wsdd.service": dict(category="network", risk="low", purpose="Windows network discovery."),
    "openvpn.service": dict(category="network", risk="low", purpose="OpenVPN connections."),
    "waydroid-container.service": dict(category="virtualisation", risk="low", purpose="Waydroid Android container.",
                                       stop="Android apps via Waydroid stop. It holds RAM while running."),
    "ollama.service": dict(category="ai", risk="low", purpose="Local LLM server (Ollama).",
                           stop="Local AI models become unavailable; frees RAM/GPU when idle."),
    "postfix.service": dict(category="mail", risk="low", purpose="Mail server."),
    "speech-dispatcher.service": dict(category="desktop", risk="low", purpose="Text-to-speech for accessibility."),
    "anacron.service": dict(category="core", risk="medium", purpose="Runs daily/weekly jobs missed while the laptop was off."),
    "networkd-dispatcher.service": dict(category="network", risk="medium", purpose="Runs scripts on network state changes."),
}

# Units matching these prefixes are core systemd/desktop plumbing.
CRITICAL_PREFIXES = ("systemd-", "user@", "user-runtime-dir@", "getty@", "dbus", "polkit", "udisks", "gdm",
                     "docker", "containerd", "NetworkManager", "wpa_supplicant")


def lookup(unit: str) -> dict:
    if unit in KB:
        return {**KB[unit], "known": True}
    if unit.startswith(CRITICAL_PREFIXES):
        return {"category": "core", "risk": "critical", "purpose": "Core system component.", "known": True}
    return {"category": "unknown", "risk": "unknown", "known": False,
            "purpose": "Not in Guardian's knowledge base. Use the live details (package, dependencies, triggers) "
                       "to decide; unknown does not mean unnecessary."}
