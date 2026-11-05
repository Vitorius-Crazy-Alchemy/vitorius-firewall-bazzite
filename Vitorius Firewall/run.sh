#!/usr/bin/env bash
# Vitorius Firewall - Robust GUI Launcher

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

APPS_DIR="$HOME/.local/share/applications"
ICONS_BASE="$HOME/.local/share/icons/hicolor"

# Ensure desktop entry & icons exist so taskbar ALWAYS displays the icon when clicked directly
if [ ! -f "$APPS_DIR/com.vitorius.firewall.desktop" ] || [ ! -f "$ICONS_BASE/scalable/apps/com.vitorius.firewall.svg" ]; then
    mkdir -p "$APPS_DIR" "$ICONS_BASE/scalable/apps"
    cp "$SCRIPT_DIR/data/vitorius-firewall.svg" "$ICONS_BASE/scalable/apps/com.vitorius.firewall.svg" 2>/dev/null || true
    cp "$SCRIPT_DIR/data/vitorius-firewall.svg" "$ICONS_BASE/scalable/apps/vitorius-firewall.svg" 2>/dev/null || true
    cp "$SCRIPT_DIR/data/vitorius-firewall-panic.svg" "$ICONS_BASE/scalable/apps/com.vitorius.firewall-panic.svg" 2>/dev/null || true
    cp "$SCRIPT_DIR/data/vitorius-firewall-panic.svg" "$ICONS_BASE/scalable/apps/vitorius-firewall-panic.svg" 2>/dev/null || true
    for size in 16 24 32 48 64 128 256 512; do
        if [ -d "$SCRIPT_DIR/data/icons/${size}x${size}" ]; then
            mkdir -p "$ICONS_BASE/${size}x${size}/apps"
            cp "$SCRIPT_DIR/data/icons/${size}x${size}/com.vitorius.firewall.png" "$ICONS_BASE/${size}x${size}/apps/com.vitorius.firewall.png" 2>/dev/null || true
            cp "$SCRIPT_DIR/data/icons/${size}x${size}/vitorius-firewall.png" "$ICONS_BASE/${size}x${size}/apps/vitorius-firewall.png" 2>/dev/null || true
        fi
    done
    cat <<EOF > "$APPS_DIR/com.vitorius.firewall.desktop"
[Desktop Entry]
Version=1.0
Name=Vitorius Firewall
GenericName=Corporate Firewall Manager
Comment=Corporate-grade Windows-style firewall management with security profiles & live monitor
Exec="$SCRIPT_DIR/run.sh"
Path=$SCRIPT_DIR
Icon=com.vitorius.firewall
Terminal=false
Type=Application
Categories=System;Security;Settings;Network;
StartupNotify=true
StartupWMClass=com.vitorius.firewall
Keywords=firewall;security;network;bazzite;fedora;rules;ports;monitor;corporate;
X-KDE-SubstituteUID=false
EOF
    cp "$APPS_DIR/com.vitorius.firewall.desktop" "$APPS_DIR/vitorius-firewall.desktop" 2>/dev/null || true
    chmod +x "$APPS_DIR/com.vitorius.firewall.desktop" "$APPS_DIR/vitorius-firewall.desktop" 2>/dev/null || true
    (
        command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -f -t "$ICONS_BASE" 2>/dev/null
        command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APPS_DIR" 2>/dev/null
        command -v kbuildsycoca6 >/dev/null 2>&1 && kbuildsycoca6 2>/dev/null
        command -v kbuildsycoca5 >/dev/null 2>&1 && kbuildsycoca5 2>/dev/null
    ) &
fi

# Export FreeDesktop and Wayland desktop integration variables
export GIO_LAUNCHED_DESKTOP_FILE="$APPS_DIR/com.vitorius.firewall.desktop"
export GIO_LAUNCHED_DESKTOP_FILE_PID=$$
export XDG_DATA_DIRS="$SCRIPT_DIR/share:$HOME/.local/share:${XDG_DATA_DIRS:-/usr/local/share:/usr/share}"

LOG_FILE="/tmp/vitorius-firewall.log"
echo "=== Starting Vitorius Firewall at $(date) ===" > "$LOG_FILE"
echo "Current directory: $SCRIPT_DIR" >> "$LOG_FILE"
echo "DISPLAY: $DISPLAY" >> "$LOG_FILE"
echo "WAYLAND_DISPLAY: $WAYLAND_DISPLAY" >> "$LOG_FILE"

# Launch application and redirect stderr/stdout to log file
exec python3 "$SCRIPT_DIR/main.py" "$@" >> "$LOG_FILE" 2>&1
