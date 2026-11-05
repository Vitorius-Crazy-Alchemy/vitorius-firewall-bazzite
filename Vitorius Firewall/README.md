# Vitorius Firewall 🛡️

**Corporate-Grade Next-Gen Firewall Manager for Fedora Bazzite (Kinoite/Silverblue)**

Vitorius Firewall brings the familiar, intuitive control of enterprise Windows Defender Firewall / commercial corporate firewalls into Fedora & Bazzite Linux with a native **GTK4 + Libadwaita** modern desktop interface.

---

## 🌟 Key Features

### 1. Windows-Style Usability + Enterprise Power
* **Intuitive Dashboard:** Real-time protection status, active firewalld zone, connection counter, blocked IPs count, and interface bandwidth rates.
* **Emergency Panic Button:** 1-click panic lockdown instantly halts all inbound and outbound traffic during security incidents.
* **Zero CLI Complexity:** Manage zones, open/close ports, allow/deny services, and add rich rules with visual modals.

### 2. Standard vs. Premium / Corporate Profiles
Switch between pre-tuned security tiers or customize your own:
* 🏠 **Home (Standard):** Balanced security for trusted home LANs. Enables local network discovery, printer sharing, SSH, and mDNS.
* ☕ **Public (Standard):** Strict inbound blocking for untrusted public Wi-Fi hotspots, hotels, and airports.
* 🏢 **Corporate (Premium):** Enterprise-grade security baseline aligned with SOC2 principles. Enforces strict outbound/inbound policies, ICMP inversion, rate limiting, and audit logging.
* 🎮 **Gaming (Standard):** Tailored for Bazzite/Steam users. Automatically permits Steam peer-to-peer and game server port ranges (27015-27030, 3478-3480 UDP/TCP) while maintaining protection.
* 🔒 **Maximum Security (Premium):** Lockdown mode conforming to high-compliance standards (HIPAA/FinTech). Drops all unsolicited traffic by default.

### 3. Real-Time Network Monitor & Live Process Mapping
* Inspect active sockets, established connections, listening daemons, and connection states (`ESTABLISHED`, `LISTEN`, `TIME_WAIT`).
* Maps network connections directly to **process names and PIDs** (e.g. `firefox`, `steam`, `discord`, `sshd`).
* **1-Click Remote IP Blocking:** Instantly drop abusive or suspicious remote IP addresses directly from the live connection table.

### 4. Application Control (Per-App Firewall)
* Windows Firewall-style application list showing detected desktop apps, background services, Flatpaks, and daemons.
* Toggle network access per application with standard switches.
* Add custom application definitions by binary path or Flatpak application ID.

### 5. Corporate SIEM Audit Log & Backups
* Detailed event logging for every rule change, blocked IP, profile activation, and panic event.
* Severity classifications: `INFO`, `WARNING`, `ALERT`, `CRITICAL`.
* Export audit trails to JSON, CSV, or formatted text for compliance reviews.
* Automatic snapshot backups before applying profile changes, with 1-click rollback/restore.

---

## 🚀 Quick Start

### 1. Launch Directly
From terminal or file manager:
```bash
cd "/home/Vitorius/Desktop/Vitorius Firewall"
./run.sh
```

### 2. Install to Application Launcher
To make Vitorius Firewall appear in your Bazzite / KDE / GNOME application menu:
```bash
cd "/home/Vitorius/Desktop/Vitorius Firewall"
./install.sh
```

---

## 🛠️ Architecture & Under the Hood

* **Kernel Subsystem:** `nftables` (Linux kernel stateful packet classification)
* **Firewall Engine:** `firewalld` (Zones: public, home, work, drop, trusted)
* **Privilege Delegation:** `pkexec` (PolicyKit GUI authorization for rule modifications)
* **Process Tracking:** `/proc/net` and `psutil`
* **Desktop UI:** `Python 3` + `PyGObject` + `GTK4` + `libadwaita`

---

## 📁 Directory Structure
```
Vitorius Firewall/
├── backend/
│   ├── core.py             # firewalld & nftables interface
│   ├── monitor.py          # Real-time connection & bandwidth tracking
│   ├── profiles.py         # Security profiles & audit logger
│   └── __init__.py
├── ui/
│   ├── app.py              # Main window & Adwaita navigation split view
│   ├── pages.py            # Dashboard, Rules, Monitor, Apps, Profiles, Logs, Settings
│   └── __init__.py
├── data/
│   ├── default_config.json # Default standard & corporate profiles
│   └── vitorius-firewall.svg # Vector icon
├── main.py                 # Application entrypoint
├── run.sh                  # Execution launcher
├── install.sh              # Application menu installer
├── LICENSE                 # MIT License
└── vitorius-firewall.desktop # Desktop file
```

---

## 📄 License

This software is distributed under the **MIT License**. See the [LICENSE](file:///home/Vitorius/Desktop/Vitorius%20Firewall/LICENSE) file for complete details.

