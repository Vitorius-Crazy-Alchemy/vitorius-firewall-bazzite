#!/usr/bin/env bash
# Uninstallation script for Vitorius Firewall on Fedora / Bazzite

set -e

APPS_DIR="$HOME/.local/share/applications"
ICONS_BASE="$HOME/.local/share/icons/hicolor"
DESKTOP_DIR="$HOME/Desktop"

echo "=== Uninstalling Vitorius Firewall ==="

# 1. Remove desktop menu shortcuts
rm -f "$APPS_DIR/vitorius-firewall.desktop" "$APPS_DIR/com.vitorius.firewall.desktop"
echo "✓ Removed application launcher shortcuts"

# 2. Remove desktop shortcuts if present
rm -f "$DESKTOP_DIR/vitorius-firewall.desktop" "$DESKTOP_DIR/com.vitorius.firewall.desktop"
echo "✓ Removed desktop shortcuts"

# 3. Remove application icons across all resolutions
rm -f "$ICONS_BASE/scalable/apps/vitorius-firewall.svg" "$ICONS_BASE/scalable/apps/com.vitorius.firewall.svg"
rm -f "$ICONS_BASE/scalable/apps/vitorius-firewall-panic.svg" "$ICONS_BASE/scalable/apps/com.vitorius.firewall-panic.svg"
for size in 16 24 32 48 64 128 256 512; do
    rm -f "$ICONS_BASE/${size}x${size}/apps/com.vitorius.firewall.png" "$ICONS_BASE/${size}x${size}/apps/vitorius-firewall.png"
done
echo "✓ Removed application icons"

# 4. Remove autostart entry if present
AUTOSTART_DIR="$HOME/.config/autostart"
rm -f "$AUTOSTART_DIR/vitorius-firewall.desktop" "$AUTOSTART_DIR/com.vitorius.firewall.desktop"
echo "✓ Removed autostart entry"

# 5. Update icon cache
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t "$ICONS_BASE" 2>/dev/null || true
fi

# 6. Update desktop database
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APPS_DIR" 2>/dev/null || true
fi

# 7. Update KDE sycoca cache if present
if command -v kbuildsycoca6 >/dev/null 2>&1; then
    kbuildsycoca6 2>/dev/null || true
elif command -v kbuildsycoca5 >/dev/null 2>&1; then
    kbuildsycoca5 2>/dev/null || true
fi

echo ""
echo "Do you also want to remove configuration and log data? (y/N)"
read -r -t 10 response || response="n"
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    rm -rf "$HOME/.config/vitorius-firewall"
    rm -rf "$HOME/.local/share/vitorius-firewall"
    rm -rf "$(dirname "${BASH_SOURCE[0]}")/.storage"
    echo "✓ User configuration and audit logs removed."
else
    echo "• Keeping configuration and logs (safe for reinstall)."
fi

echo ""
echo "=== Vitorius Firewall has been uninstalled successfully ==="
