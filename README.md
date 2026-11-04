Vitorius Firewall (v1.0) — Product Description & Technical Overview
1. Executive Overview & Mission

Vitorius Firewall is an enterprise-grade, modern graphical firewall management suite designed specifically for Linux desktop workstations, gaming distributions (such as Bazzite and Fedora Silverblue/Kinoite), and enterprise environments. Built from the ground up on modern GTK4 and Libadwaita, Vitorius Firewall bridges the long-standing gap between raw Linux packet-filtering mechanisms (firewalld, nftables, and iptables) and the intuitive, interactive user experience popularized by premium corporate and Windows firewalls.

For decades, Linux firewall management has been divided into two suboptimal extremes: complex, arcane command-line utilities requiring deep knowledge of zone semantics and routing tables, or antiquated, sluggish graphical frontends that fail to integrate with modern Wayland display servers, system tray protocols, and non-blocking desktop environments.

Vitorius Firewall eliminates this compromise. It delivers a comprehensive security dashboard featuring real-time connection inspection, process-level application filtering, adaptive security profiles (including dedicated presets for Gaming and Public Wi-Fi), atomic rule configuration, a hardware-level "Panic Lockdown" switch with instantaneous recovery, and full corporate compliance logging. Packaged with a native Libadwaita aesthetic and native KDE Plasma and GNOME integration, Vitorius Firewall empowers both casual enthusiasts and enterprise system administrators to monitor, manage, and defend their network perimeter with total confidence.

2. Background: The Linux Firewall Dilemma

Under the hood of modern Linux distributions, packet filtering is powered by the Linux kernel's netfilter subsystem, coordinated dynamically by user-space daemons such as firewalld and packet classification frameworks like nftables. While these engines are exceptionally robust, flexible, and capable of handling gigabit line-rate routing, their management interfaces present steep hurdles for everyday productivity:

Cryptic CLI Syntax: Modifying runtime vs. permanent configurations, constructing syntax-sensitive rich rules, managing zone bindings, and tracking source IP masks requires memorizing dozens of multi-part terminal commands.
Lack of Process Attribution: Traditional packet filters evaluate packets purely on IP headers and port numbers. They cannot inherently tell a user which binary, process ID (PID), or container generated a specific outbound TCP handshake.
Password Prompt Exhaustion: Changing multiple ports or binding multiple services sequentially often triggers a barrage of PolicyKit (pkexec) authentication popups, degrading usability.
All-or-Nothing Network Severing: When users encounter suspicious network activity or malware beacons, disconnecting the physical link or toggling primitive iptables drop commands can lock users out of their own systems, often requiring hard machine reboots to recover.

Vitorius Firewall solves every one of these pain points. By encapsulating low-level system commands inside an intelligent, asynchronous, cached backend, it transforms complex Linux network filtering into a visual, responsive, and bulletproof workflow.

3. Core Architecture & Design Principles

Vitorius Firewall is architected according to a strict three-tier design pattern: the Hardware & Kernel Abstraction Layer (Core Backend), the Telemetry & Event Ingestion Engine (Monitor & Logger), and the Asynchronous Presentation Layer (GTK4/Libadwaita UI & Tray).

┌─────────────────────────────────────────────────────────────┐
│                    Presentation Layer                       │
│   • GTK4 / Libadwaita Responsive Window                     │
│   • FreeDesktop / Wayland AppIndicator (System Tray)        │
│   • Single-Instance IPC Unix Domain Socket Server           │
└──────────────────────────────┬──────────────────────────────┘
                               │ Asynchronous GLib Callbacks
┌──────────────────────────────▼──────────────────────────────┐
│                Telemetry & Orchestration Layer              │
│   • NetworkMonitor (/proc/net, ss, socket mapping)          │
│   • ProfileManager (JSON Profiles & Auto-Backups)           │
│   • FirewallLogger (JSON-Lines Audit Trail)                 │
└──────────────────────────────┬──────────────────────────────┘
                               │ Single-Transaction pkexec Batches
┌──────────────────────────────▼──────────────────────────────┐
│             Kernel & Daemon Abstraction Layer               │
│   • FirewallCore (Cached firewalld & nftables abstraction)  │
│   • PolicyKit Integration (No repeated auth prompts)        │
│   • Linux netfilter / conntrack / sysfs Interfaces          │
└─────────────────────────────────────────────────────────────┘
The Non-Blocking Asynchronous Engine

Traditional desktop wrappers frequently freeze or drop frames whenever privileged system commands execute. Vitorius Firewall guarantees complete UI responsiveness by executing all disk I/O, socket scanning, and firewall-cmd invocations in dedicated background daemon threads. Results are dispatched back to the GTK main loop via thread-safe GLib.idle_add dispatchers. Even during intensive firewall reloads, the interface maintains 60 FPS fluidity.

Single-Transaction Privilege Escalation

To protect against PolicyKit authorization fatigue, Vitorius Firewall incorporates an intelligent transaction batching mechanism. When switching security profiles, applying multi-port rules, or blocking complex application stacks, the backend aggregates all required modifications into an atomic bash script executed via a single pkexec call. If the daemon is inactive, the transaction automatically starts systemctl start firewalld within the same privileged scope, requesting the superuser password exactly once.

Smart Caching & Query Invalidation

Frequent polling of firewalld over DBus can saturate system resources. Vitorius Firewall implements time-bounded in-memory caching with proactive invalidation. Status queries, zone settings, and active interfaces are cached for short windows, while any write operation immediately purges stale records to guarantee absolute coherence between the UI and kernel state.

4. Comprehensive Feature Deep Dive
1. Intelligent Security Profiles

Network security needs change dramatically depending on physical location and workload. Vitorius Firewall provides four fine-tuned corporate and consumer profiles, along with arbitrary custom configurations:

Standard Protection: The balanced corporate baseline. Sets the default zone to public, permits standard outbound web and DNS traffic, enables stateful connection tracking, and restricts incoming requests to user-authorized services.
Gaming Mode: Tailored specifically for gaming handhelds, desktop rigs, and SteamOS/Bazzite setups. Configures dynamic ports for Valve Steam, Proton multiplayer handshakes, Discord Voice over IP (VoIP), Lutris, and peer-to-peer matchmaking without exposing administrative ports like SSH or Telnet.
Work & Enterprise Mode: Preconfigured for corporate laptops and remote workers. Integrates seamless connectivity for corporate VPN gateways (OpenVPN, WireGuard), Samba/CIFS network share discovery, IPP network printing, Cockpit remote management, and Active Directory / Kerberos domain communications.
Public Wi-Fi / Shield Mode: Maximum paranoia lockdown for coffee shops, airports, and untrusted guest networks. Rebinds default interfaces to drop or block, completely disables ICMP echo-replies (stealthing the computer from network port scans), closes all non-essential listening daemons, and drops unexpected incoming broadcast packets.
Custom Profile Engine & Auto-Backup: Users can duplicate, customize, and export custom profiles. Prior to switching any profile, Vitorius Firewall automatically archives the active firewalld configuration to ~/.config/vitorius-firewall/backups/, enabling instantaneous one-click rollback if a custom configuration disrupts a workflow.
2. Application-Level Network Control & Process Firewall

While raw firewalls operate exclusively on IP addresses and ports, desktop users think in terms of applications. Vitorius Firewall bridges this divide by mapping kernel network sockets to active system processes and binary definitions.

Pre-Mapped Application Profiles: Out-of-the-box detection and rule enforcement for popular software suites including Discord, Steam, Spotify, Mozilla Firefox, Google Chrome, OBS Studio, Telegram Desktop, Cockpit, and Samba.
One-Click Network Severing: Blocking an application instantly stops its network access. Vitorius Firewall generates kernel-level rich rules and port constraints targeting the application's registered communication channels while terminating lingering established connections.
Custom Application Scanner: Users can browse the local filesystem or running process tree to register arbitrary third-party executables, custom scripts, or proprietary enterprise software into the firewall's managed application list.
3. Real-Time Live Connection Monitor & Bandwidth Telemetry

Vitorius Firewall provides a live, deep-inspection network monitor that operates with low CPU overhead:

Socket-to-Process Attribution: Inspects active TCP, UDP, and raw sockets to reveal the exact process name, process ID (PID), user ownership, local listening port, and remote destination IP.
Dynamic Connection State Filtering: Filter active connections on the fly by protocol (TCP, UDP, All) and TCP connection state (ESTABLISHED, LISTEN, TIME_WAIT, CLOSE_WAIT, SYN_SENT).
Live Search & Quick IP Action: Real-time search across remote IPs, hostnames, and process names. Clicking any suspect connection immediately exposes an action to Quick Block IP, which instantly writes an immutable drop rule into the firewall.
Per-Interface Throughput Gauges: Live bandwidth telemetry tracking transfer (TX) and receive (RX) speeds in kB/s across physical interfaces (eth0, wlan0, enp3s0), virtual bridge adapters, and container networks (docker0, podman0).
4. Advanced Zone, Port, and Rich Rule Orchestration

For experienced network administrators, Vitorius Firewall provides complete control over the full feature set of firewalld:

Zone Management: Seamlessly inspect and manage all nine standard firewalld zones (trusted, home, work, internal, external, dmz, public, block, and drop). Bind or reassign physical network interfaces to zones with a single click.
Service Catalogue: Browse hundreds of IANA and Linux-standard service descriptions (SSH, HTTP/HTTPS, NFS, Cockpit, Plex, Git, VNC, RDP, DNS, etc.) and toggle them on or off without memorizing port configurations.
Custom Port & Range Management: Open or restrict custom TCP and UDP ports, standalone ports (e.g., 8080/tcp), or wide port blocks (e.g., 5000-5050/udp) with built-in input validation.
Visual Rich Rule Builder: Construct complex, enterprise-grade firewalld rich rules using an interactive UI. Define source CIDR constraints, target specific logging prefixes, configure audit log limits, and enforce granular ACCEPT, REJECT, or DROP policies.
5. Instant Panic Mode & Seamless "Unpanic" Recovery

In security operations, the ability to sever all communications during an active compromise is critical. Vitorius Firewall implements a military-grade Panic Mode (firewall-cmd --panic-on), backed by a foolproof Unpanic recovery pipeline:

Instantaneous Lockdown: Clicking the prominent ⛔ Panic button in the header bar or system tray engages an immediate, unconditional kernel-level packet drop. All incoming, outgoing, and routed packets across every interface are instantly severed, and existing connection tracking entries are dropped.
Multi-Point Unpanic Without Rebooting: Historical implementations of panic mode on Linux frequently left systems stranded, forcing users to hard-reboot. Vitorius Firewall provides three distinct, non-blocking mechanisms to restore traffic immediately:
Header Bar: When panic mode is engaged, the header button automatically morphs into a high-visibility, green 🟢 Restore Traffic button with a confirmation dialog.
Dashboard Banner: The prominent lockdown banner displays an immediate Restore Traffic action button.
System Tray Menu: Right-clicking the panel icon provides an immediate 🟢 Unpanic (Restore Network Traffic) option that safely executes firewall-cmd --panic-off in a background worker thread.
CLI Failsafe: Running ./run.sh --unpanic from a virtual console or terminal instantly lifts the lockdown without requiring a GUI session.
6. NAT, Port Forwarding, and Stealth Mode (ICMP Filtering)

Vitorius Firewall includes a dedicated suite for routing and perimeter defense:

IP Masquerading (NAT): Toggle IP masquerade on external and public interfaces with a single switch, allowing the host to act as a secure gateway or router for local virtual machines, containers, and secondary subnets.
Port Redirection & Forwarding: Route incoming external connections on a specific port directly to internal IP addresses or alternative local ports (e.g., forwarding public port 80 to local container port 8080).
Stealth Mode (ICMP Suppression): Selectively block Internet Control Message Protocol (ICMP) types, such as echo-request (ping), timestamp-request, or router-advertisement. In Public Wi-Fi mode, stealthing drops incoming ping requests, making the computer invisible to automated network recon scans.
7. Corporate Audit Logging & Compliance Event Trail

Every security-relevant action taken in Vitorius Firewall is automatically recorded in a structured, tamper-resistant event log (events.jsonl):

Structured Event Types: Tracks application startup, shutdown, profile transitions, rules added/removed, IP blocks/unblocks, panic mode state changes, configuration imports/exports, and manual rule reloads.
Four-Tier Severity Classification: Classifies events into INFO, WARNING, CRITICAL, and ALERT tiers.
Compliance Filtering & Search: Search through historical events, filter by severity level, and inspect granular details including timestamps, zone names, target IP addresses, and user-initiated triggers.
Audit Exporting & Retention Policies: Export audit logs to standard formats (CSV or JSON) for external SIEM integration or compliance archiving. Automatic retention management periodically purges events older than the configured threshold (e.g., 90 days) to prevent disk bloat.
8. Modern Desktop & System Tray Integration

Vitorius Firewall is designed to feel like an inseparable part of modern Linux desktop environments:

Libadwaita / GTK4 Visual Language: Built using standard GNOME HIG design principles, featuring modern rounded cards, clean grouped preferences rows, responsive clamps, toasts, and smooth view transitions.
Adaptive Dark & Light Theme: Fully honors the system color scheme preference, dynamically adapting between high-contrast dark themes and clean light palettes.
StatusNotifierItem (SNI) System Tray: Implements the modern DBus-based org.kde.StatusNotifierItem specification, ensuring first-class tray panel integration in KDE Plasma, GNOME (via AppIndicator extension), XFCE, and Sway/Waybar.
Dynamic Status Iconography: The system tray icon continuously communicates real-time firewall status:
Blue Corporate Shield (com.vitorius.firewall): Active protection, normal traffic flowing.
Red Panic Shield (com.vitorius.firewall-panic): Panic mode active, all network traffic severed.
Warning State: Firewall daemon inactive or restricted.
Single-Instance IPC Protocol: Launching Vitorius Firewall from the application launcher while it is already running automatically sends a wakeup command (PRESENT) across a local Unix domain socket, smoothly presenting the existing window without spawning duplicate background instances.
Close to Tray: Users can minimize the application to the panel tray on window close, maintaining constant background monitoring without cluttering the taskbar.
5. Security & Authentication Model

Security software must itself adhere to the highest security standards. Vitorius Firewall adheres to the principle of least privilege:

Unprivileged GUI Execution: The graphical user interface and monitor daemons run entirely within the unprivileged user session. The GUI never runs as root.
Explicit PolicyKit Boundaries: Only operations that write to system state (modifying zones, toggling panic mode, altering nftables rules) request elevated privileges via PolicyKit (pkexec). Read-only operations (monitoring connection sockets, querying traffic, reading configuration) run strictly unprivileged.
No Network Dependency: Vitorius Firewall is 100% self-contained and local. It transmits zero telemetry, requires no internet connection to function, and uses no external cloud servers. All configuration files and audit logs remain stored strictly within user and system paths (~/.config/vitorius-firewall/ and /etc/firewalld/).
6. Target Audiences & Real-World Use Cases
User Persona	Key Challenge	How Vitorius Firewall Solves It
Linux Gamers & Handheld Users (Bazzite / SteamOS / Fedora)	Strict corporate firewalls block Steam downloads, game servers, or Discord voice calls, while turning off the firewall leaves the machine completely exposed.	One-click switch to Gaming Mode automatically opens required Steam/Proton/VoIP ports while keeping all dangerous system ports securely shut.
Remote Workers & Mobile Road Warriors	Connecting to hotel, coffee shop, or conference Wi-Fi risks eavesdropping, neighbor host scans, and malicious probes.	Toggling Public Wi-Fi Mode stealths the laptop by dropping all ICMP pings and switching the incoming packet policy to drop, rendering the host invisible on the local subnet.
System Administrators & DevOps	Setting up complex rich rules, masquerading NAT gateways, and inspecting live traffic usually requires memorizing complex CLI flags.	Provides an intuitive visual UI for rich rules, port forwarding, and live connection inspection with process PID mapping, while generating clean, permanent firewalld configurations.
Privacy Advocates & Security Researchers	Needing to know exactly which background process is communicating with external telemetry endpoints.	The Live Network Monitor matches every socket directly to its executable binary path, allowing one-click IP blocking and process isolation.
7. Technical Specifications
Product Name: Vitorius Firewall
Version: 1.0 (Production Release)
License: GNU General Public License v3.0 (GPL-3.0)
Application ID: com.vitorius.firewall
Underlying Engine: firewalld (≥ 0.9.0), nftables (≥ 0.9.8), Linux netfilter
GUI Toolkit: GTK 4.x & Libadwaita 1.x (via PyGObject)
System Integration: PolicyKit (pkexec), Freedesktop XDG Desktop Specifications, DBus StatusNotifierItem / AppIndicator
Display Server Support: Wayland (native) and X11
Tested Distributions: Fedora Linux (39, 40, 41), Bazzite (OSTree / Atomic), Red Hat Enterprise Linux (RHEL 9+), CentOS Stream, Ubuntu/Debian with firewalld
Default File Paths:
Application Settings: ~/.config/vitorius-firewall/config.json
Rule Backups: ~/.config/vitorius-firewall/backups/rules/
Audit Log: ~/.config/vitorius-firewall/logs/events.jsonl
Desktop Entry: ~/.local/share/applications/com.vitorius.firewall.desktop
Scalable Icons: ~/.local/share/icons/hicolor/scalable/apps/com.vitorius.firewall.svg
8. Summary: Why Choose Vitorius Firewall?

Vitorius Firewall v1.0 represents the pinnacle of modern Linux desktop network security. By combining the rock-solid dependability of enterprise firewalld with an elegant, responsive Libadwaita interface, it eliminates the complexity of Linux network security.

Whether you need to secure your laptop on an open coffee-shop Wi-Fi network, optimize your system for competitive online gaming, isolate a suspicious background process, or manage complex port-forwarding and NAT tables on an office workstation, Vitorius Firewall gives you total oversight and granular control with a single click.
