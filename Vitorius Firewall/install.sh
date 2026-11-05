#!/usr/bin/env bash
# Installation script for Vitorius Firewall on Fedora / Bazzite

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPS_DIR="$HOME/.local/share/applications"
ICONS_BASE="$HOME/.local/share/icons/hicolor"
DESKTOP_DIR="$HOME/Desktop"

echo "=== Installing Vitorius Firewall ==="

mkdir -p "$APPS_DIR"
mkdir -p "$ICONS_BASE/scalable/apps"

# 1. Install scalable SVG icons under standard application IDs
cp "$SCRIPT_DIR/data/vitorius-firewall.svg" "$ICONS_BASE/scalable/apps/vitorius-firewall.svg" 2>/dev/null || true
cp "$SCRIPT_DIR/data/vitorius-firewall.svg" "$ICONS_BASE/scalable/apps/com.vitorius.firewall.svg" 2>/dev/null || true
cp "$SCRIPT_DIR/data/vitorius-firewall-panic.svg" "$ICONS_BASE/scalable/apps/vitorius-firewall-panic.svg" 2>/dev/null || true
cp "$SCRIPT_DIR/data/vitorius-firewall-panic.svg" "$ICONS_BASE/scalable/apps/com.vitorius.firewall-panic.svg" 2>/dev/null || true

# 2. Install pre-rendered PNG icons across all standard desktop resolutions
for size in 16 24 32 48 64 128 256 512; do
    mkdir -p "$ICONS_BASE/${size}x${size}/apps"
    if [ -f "$SCRIPT_DIR/data/icons/${size}x${size}/com.vitorius.firewall.png" ]; then
        cp "$SCRIPT_DIR/data/icons/${size}x${size}/com.vitorius.firewall.png" "$ICONS_BASE/${size}x${size}/apps/com.vitorius.firewall.png" 2>/dev/null || true
        cp "$SCRIPT_DIR/data/icons/${size}x${size}/vitorius-firewall.png" "$ICONS_BASE/${size}x${size}/apps/vitorius-firewall.png" 2>/dev/null || true
    fi
done

# Prepare desktop entry
DESKTOP_FILE_CONTENT="[Desktop Entry]
Version=1.0
Name=Vitorius Firewall
GenericName=Corporate Firewall Manager
Comment=Corporate-grade Windows-style firewall management with security profiles & live monitor
Exec=\"$SCRIPT_DIR/run.sh\"
Path=$SCRIPT_DIR
Icon=com.vitorius.firewall
Terminal=false
Type=Application
Categories=System;Security;Settings;Network;
StartupNotify=true
StartupWMClass=com.vitorius.firewall
Keywords=firewall;security;network;bazzite;fedora;rules;ports;monitor;corporate;
X-KDE-SubstituteUID=false
"

# 3. Install to Application Menu (registered as both com.vitorius.firewall.desktop and vitorius-firewall.desktop)
echo "$DESKTOP_FILE_CONTENT" > "$APPS_DIR/com.vitorius.firewall.desktop"
echo "$DESKTOP_FILE_CONTENT" > "$APPS_DIR/vitorius-firewall.desktop"
chmod +x "$APPS_DIR/com.vitorius.firewall.desktop" "$APPS_DIR/vitorius-firewall.desktop"

# 4. Install to Desktop folder if it exists
if [ -d "$DESKTOP_DIR" ]; then
    echo "$DESKTOP_FILE_CONTENT" > "$DESKTOP_DIR/vitorius-firewall.desktop"
    chmod +x "$DESKTOP_DIR/vitorius-firewall.desktop"
    # Mark trusted in KDE Plasma / GNOME
    if command -v gio >/dev/null 2>&1; then
        gio set -t string "$DESKTOP_DIR/vitorius-firewall.desktop" metadata::trusted true 2>/dev/null || true
    fi
    echo "✓ Desktop shortcut created on $DESKTOP_DIR"
fi

# 4b. Sync autostart desktop entry if enabled
AUTOSTART_DIR="$HOME/.config/autostart"
CONFIG_FILE="$HOME/.config/vitorius-firewall/config.json"
if [ -f "$CONFIG_FILE" ] && grep -q '"autostart": true' "$CONFIG_FILE" 2>/dev/null; then
    mkdir -p "$AUTOSTART_DIR"
    cat <<EOF > "$AUTOSTART_DIR/vitorius-firewall.desktop"
[Desktop Entry]
Version=1.0
Name=Vitorius Firewall
GenericName=Corporate Firewall Manager
Comment=Corporate-grade Windows-style firewall management with security profiles & live monitor
Exec="$SCRIPT_DIR/run.sh" --minimized
Path=$SCRIPT_DIR
Icon=com.vitorius.firewall
Terminal=false
Type=Application
Categories=System;Security;Settings;Network;
StartupNotify=false
StartupWMClass=com.vitorius.firewall
X-GNOME-Autostart-enabled=true
X-KDE-autostart-after=panel
X-KDE-autostart-phase=2
EOF
    chmod +x "$AUTOSTART_DIR/vitorius-firewall.desktop"
    command -v systemctl >/dev/null 2>&1 && systemctl --user daemon-reload 2>/dev/null || true
    echo "✓ Autostart entry synced with systemd"
fi

# 5. Update icon cache
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t "$ICONS_BASE" 2>/dev/null || true
fi

# 6. Update desktop database
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APPS_DIR" 2>/dev/null || true
fi

# 7. Update KDE sycoca cache if running on KDE Plasma
if command -v kbuildsycoca6 >/dev/null 2>&1; then
    kbuildsycoca6 2>/dev/null || true
elif command -v kbuildsycoca5 >/dev/null 2>&1; then
    kbuildsycoca5 2>/dev/null || true
fi

echo "✓ Vitorius Firewall installed successfully!"
echo "Launching Vitorius Firewall now..."
echo ""

# Automatically launch the application in background
"$SCRIPT_DIR/run.sh" &
disown

