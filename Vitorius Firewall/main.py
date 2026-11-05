#!/usr/bin/env python3
"""
Vitorius Firewall - Main Executable Entry Point
Corporate-grade Firewall Management for Fedora / Bazzite Linux
"""

import sys
import os
from pathlib import Path
import logging

__version__ = '1.0'

# Ensure project root is in sys.path
PROJECT_DIR = Path(__file__).resolve().parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger('vitorius')

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Adw, GLib, Gtk, Gdk

from backend.core import FirewallCore
from backend.monitor import NetworkMonitor
from backend.profiles import ProfileManager, FirewallLogger
from ui.app import VitoriusFirewallApp


def check_single_instance() -> bool:
    """If another instance is already running, wake it and exit cleanly."""
    from ui.app import get_socket_path
    import socket
    sock_path = get_socket_path()

    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(0.8)
        client.connect(sock_path)
        cmd = "PRESENT\n"
        if '--minimized' in sys.argv or '--tray' in sys.argv:
            cmd = "PING\n"
        client.sendall(cmd.encode('utf-8'))
        try:
            client.recv(1024)
        except Exception:
            pass
        client.close()
        logger.info("Existing Vitorius Firewall instance found. Wakeup signal sent.")
        return True
    except (ConnectionRefusedError, FileNotFoundError, socket.timeout, OSError):
        try:
            if os.path.exists(sock_path):
                os.unlink(sock_path)
        except OSError:
            pass
        return False


def ensure_desktop_integration():
    """Ensure desktop entry and hicolor icons exist so taskbar always displays the icon."""
    try:
        user_apps = Path.home() / '.local' / 'share' / 'applications'
        user_icons = Path.home() / '.local' / 'share' / 'icons' / 'hicolor'
        desktop_file = user_apps / 'com.vitorius.firewall.desktop'
        icon_file = user_icons / 'scalable' / 'apps' / 'com.vitorius.firewall.svg'

        if not desktop_file.exists() or not icon_file.exists():
            import shutil, subprocess
            user_apps.mkdir(parents=True, exist_ok=True)
            (user_icons / 'scalable' / 'apps').mkdir(parents=True, exist_ok=True)

            src_svg = PROJECT_DIR / 'data' / 'vitorius-firewall.svg'
            src_panic = PROJECT_DIR / 'data' / 'vitorius-firewall-panic.svg'
            if src_svg.exists():
                shutil.copy2(src_svg, user_icons / 'scalable' / 'apps' / 'com.vitorius.firewall.svg')
                shutil.copy2(src_svg, user_icons / 'scalable' / 'apps' / 'vitorius-firewall.svg')
            if src_panic.exists():
                shutil.copy2(src_panic, user_icons / 'scalable' / 'apps' / 'com.vitorius.firewall-panic.svg')
                shutil.copy2(src_panic, user_icons / 'scalable' / 'apps' / 'vitorius-firewall-panic.svg')

            for s in [16, 24, 32, 48, 64, 128, 256, 512]:
                png_src = PROJECT_DIR / 'data' / 'icons' / f'{s}x{s}' / 'com.vitorius.firewall.png'
                if png_src.exists():
                    target_dir = user_icons / f'{s}x{s}' / 'apps'
                    target_dir.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(png_src, target_dir / 'com.vitorius.firewall.png')
                    shutil.copy2(png_src, target_dir / 'vitorius-firewall.png')

            run_script = PROJECT_DIR / 'run.sh'
            desktop_content = f"""[Desktop Entry]
Version=1.0
Name=Vitorius Firewall
GenericName=Corporate Firewall Manager
Comment=Corporate-grade Windows-style firewall management with security profiles & live monitor
Exec="{run_script}"
Path={PROJECT_DIR}
Icon=com.vitorius.firewall
Terminal=false
Type=Application
Categories=System;Security;Settings;Network;
StartupNotify=true
StartupWMClass=com.vitorius.firewall
Keywords=firewall;security;network;bazzite;fedora;rules;ports;monitor;corporate;
X-KDE-SubstituteUID=false
"""
            desktop_file.write_text(desktop_content, encoding='utf-8')
            (user_apps / 'vitorius-firewall.desktop').write_text(desktop_content, encoding='utf-8')

            def _refresh_caches():
                for cmd in [
                    ['gtk-update-icon-cache', '-f', '-t', str(user_icons)],
                    ['update-desktop-database', str(user_apps)],
                    ['kbuildsycoca6'],
                    ['kbuildsycoca5']
                ]:
                    try:
                        subprocess.run(cmd, capture_output=True, timeout=3.0)
                    except Exception:
                        pass

            import threading
            threading.Thread(target=_refresh_caches, daemon=True).start()

        # Check autostart sync if enabled in settings
        config_path = Path.home() / '.config' / 'vitorius-firewall' / 'config.json'
        if config_path.exists():
            import json, subprocess
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    cfg = json.load(f)
                if cfg.get('settings', {}).get('autostart', False):
                    autostart_dir = Path.home() / '.config' / 'autostart'
                    autostart_file = autostart_dir / 'vitorius-firewall.desktop'
                    run_script = PROJECT_DIR / 'run.sh'
                    autostart_content = f"""[Desktop Entry]
Version=1.0
Name=Vitorius Firewall
GenericName=Corporate Firewall Manager
Comment=Corporate-grade Windows-style firewall management with security profiles & live monitor
Exec="{run_script}" --minimized
Path={PROJECT_DIR}
Icon=com.vitorius.firewall
Terminal=false
Type=Application
Categories=System;Security;Settings;Network;
StartupNotify=false
StartupWMClass=com.vitorius.firewall
X-GNOME-Autostart-enabled=true
X-KDE-autostart-after=panel
X-KDE-autostart-phase=2
"""
                    if not autostart_file.exists() or autostart_file.read_text(encoding='utf-8') != autostart_content:
                        autostart_dir.mkdir(parents=True, exist_ok=True)
                        autostart_file.write_text(autostart_content, encoding='utf-8')
                        autostart_file.chmod(0o755)
                        subprocess.run(['systemctl', '--user', 'daemon-reload'], capture_output=True, timeout=3.0)
            except Exception as e:
                logger.debug(f"Error syncing autostart entry: {e}")
    except Exception as e:
        logger.debug(f"Could not auto-register desktop integration: {e}")


def main():
    if '--unpanic' in sys.argv or '--disable-panic' in sys.argv:
        core = FirewallCore()
        print("Disabling panic mode (unpanic)...")
        if core.disable_panic_mode():
            print("✓ Panic mode disabled. Network traffic restored.")
            FirewallLogger().log_event('panic_off', 'info', 'Panic mode disabled via command line - traffic restored')
            return 0
        else:
            print("✗ Failed to disable panic mode or authorization cancelled.")
            return 1

    if check_single_instance():
        return 0

    ensure_desktop_integration()

    logger.info(f"Starting Vitorius Firewall v{__version__}...")

    # Set process and application name before GTK/Adwaita initialization for Wayland/X11 window matching
    GLib.set_prgname("com.vitorius.firewall")
    GLib.set_application_name("Vitorius Firewall")

    Adw.init()

    # Configure icon theme search paths so GTK and Wayland find our icon immediately
    try:
        display = Gdk.Display.get_default()
        if display:
            theme = Gtk.IconTheme.get_for_display(display)
            theme.add_search_path(str(PROJECT_DIR / 'share' / 'icons'))
            theme.add_search_path(str(PROJECT_DIR / 'data'))
            theme.add_search_path(str(PROJECT_DIR / 'data' / 'icons'))
            user_icons = Path.home() / '.local' / 'share' / 'icons'
            if user_icons.exists():
                theme.add_search_path(str(user_icons))
        Gtk.Window.set_default_icon_name("com.vitorius.firewall")
    except Exception as e:
        logger.debug(f"Error configuring icon theme: {e}")


    # Initialize backend components
    default_config = PROJECT_DIR / 'data' / 'default_config.json'
    
    fw_core = FirewallCore()
    monitor = NetworkMonitor()
    profiles = ProfileManager(str(default_config))
    fw_logger = FirewallLogger()

    # Launch GTK4/Adwaita Application
    app = VitoriusFirewallApp(
        firewall_core=fw_core,
        monitor=monitor,
        profiles=profiles,
        fw_logger=fw_logger,
        app_dir=str(PROJECT_DIR),
    )

    # Pass only supported flags to app.run to ensure clean startup across all environments
    app_args = [sys.argv[0]]
    for arg in sys.argv[1:]:
        if arg in ('--minimized', '-m', '--tray', '--start-minimized'):
            app_args.append(arg)

    return app.run(app_args)


if __name__ == '__main__':
    sys.exit(main())
