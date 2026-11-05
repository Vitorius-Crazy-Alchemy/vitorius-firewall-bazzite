"""
Vitorius Firewall - System Tray Indicator
Implements org.kde.StatusNotifierItem and com.canonical.dbusmenu
using native GIO D-Bus for GTK4 on Linux / KDE Plasma / Wayland.
Displays a live security shield icon in the system tray next to the network icon.
"""

import os
import logging
from pathlib import Path
import gi

gi.require_version('Gtk', '4.0')
gi.require_version('GdkPixbuf', '2.0')
from gi.repository import Gio, GLib, GdkPixbuf

logger = logging.getLogger('vitorius.tray')

STATUS_NOTIFIER_ITEM_XML = """
<node>
  <interface name='org.kde.StatusNotifierItem'>
    <property name='Category' type='s' access='read'/>
    <property name='Id' type='s' access='read'/>
    <property name='Title' type='s' access='read'/>
    <property name='Status' type='s' access='read'/>
    <property name='WindowId' type='i' access='read'/>
    <property name='IconThemePath' type='s' access='read'/>
    <property name='IconName' type='s' access='read'/>
    <property name='IconPixmap' type='a(iiay)' access='read'/>
    <property name='OverlayIconName' type='s' access='read'/>
    <property name='OverlayIconPixmap' type='a(iiay)' access='read'/>
    <property name='AttentionIconName' type='s' access='read'/>
    <property name='AttentionIconPixmap' type='a(iiay)' access='read'/>
    <property name='AttentionMovieName' type='s' access='read'/>
    <property name='ToolTip' type='(sa(iiay)ss)' access='read'/>
    <property name='ItemIsMenu' type='b' access='read'/>
    <property name='Menu' type='o' access='read'/>
    <method name='ContextMenu'>
      <arg type='i' name='x' direction='in'/>
      <arg type='i' name='y' direction='in'/>
    </method>
    <method name='Activate'>
      <arg type='i' name='x' direction='in'/>
      <arg type='i' name='y' direction='in'/>
    </method>
    <method name='SecondaryActivate'>
      <arg type='i' name='x' direction='in'/>
      <arg type='i' name='y' direction='in'/>
    </method>
    <method name='Scroll'>
      <arg type='i' name='delta' direction='in'/>
      <arg type='s' name='orientation' direction='in'/>
    </method>
    <signal name='NewTitle'/>
    <signal name='NewIcon'/>
    <signal name='NewAttentionIcon'/>
    <signal name='NewOverlayIcon'/>
    <signal name='NewToolTip'/>
    <signal name='NewStatus'>
      <arg type='s' name='status'/>
    </signal>
  </interface>
</node>
"""

DBUS_MENU_XML = """
<node>
  <interface name='com.canonical.dbusmenu'>
    <property name='Version' type='u' access='read'/>
    <property name='TextDirection' type='s' access='read'/>
    <property name='Status' type='s' access='read'/>
    <property name='IconThemePath' type='as' access='read'/>
    <method name='GetLayout'>
      <arg type='i' name='parentId' direction='in'/>
      <arg type='i' name='recursionDepth' direction='in'/>
      <arg type='as' name='propertyNames' direction='in'/>
      <arg type='u' name='revision' direction='out'/>
      <arg type='(ia{sv}av)' name='layout' direction='out'/>
    </method>
    <method name='GetGroupProperties'>
      <arg type='ai' name='ids' direction='in'/>
      <arg type='as' name='propertyNames' direction='in'/>
      <arg type='a(ia{sv})' name='properties' direction='out'/>
    </method>
    <method name='GetProperty'>
      <arg type='i' name='id' direction='in'/>
      <arg type='s' name='name' direction='in'/>
      <arg type='v' name='value' direction='out'/>
    </method>
    <method name='Event'>
      <arg type='i' name='id' direction='in'/>
      <arg type='s' name='eventId' direction='in'/>
      <arg type='v' name='data' direction='in'/>
      <arg type='u' name='timestamp' direction='in'/>
    </method>
    <method name='AboutToShow'>
      <arg type='i' name='id' direction='in'/>
      <arg type='b' name='needUpdate' direction='out'/>
    </method>
    <signal name='LayoutUpdated'>
      <arg type='u' name='revision'/>
      <arg type='i' name='parent'/>
    </signal>
    <signal name='ItemActivationRequested'>
      <arg type='i' name='id'/>
      <arg type='u' name='timestamp'/>
    </signal>
  </interface>
</node>
"""


def _pixbuf_to_argb_entry(pixbuf):
    """Convert GdkPixbuf to SNI ARGB32 network byte order format (width, height, bytes)."""
    try:
        width = pixbuf.get_width()
        height = pixbuf.get_height()
        raw = pixbuf.get_pixels()
        rowstride = pixbuf.get_rowstride()
        n_channels = pixbuf.get_n_channels()

        out = bytearray(width * height * 4)
        out_idx = 0
        for y in range(height):
            row_offset = y * rowstride
            for x in range(width):
                px = row_offset + x * n_channels
                r = raw[px]
                g = raw[px + 1]
                b = raw[px + 2]
                a = raw[px + 3] if n_channels == 4 else 255
                # Network byte order: [A, R, G, B]
                out[out_idx] = a
                out[out_idx + 1] = r
                out[out_idx + 2] = g
                out[out_idx + 3] = b
                out_idx += 4
        return (width, height, bytes(out))
    except Exception as e:
        logger.warning(f"Error converting pixbuf to ARGB: {e}")
        return None


class DBusMenuManager:
    """Manages the context menu displayed when right-clicking the tray icon."""

    def __init__(self, tray):
        self.tray = tray
        self.revision = 1

    def get_items(self):
        is_panic = self.tray.is_panic
        profile = self.tray.active_profile or "Standard"
        panic_label = "🟢 Unpanic (Restore Network Traffic)" if is_panic else "⛔ Panic Mode (Cut All Traffic)"

        return [
            (1, {"label": "Open Vitorius Firewall", "icon-name": "vitorius-firewall", "enabled": True}),
            (2, {"type": "separator"}),
            (3, {"label": f"Status: {'CRITICAL (Cut)' if is_panic else 'Protected'} ({profile}) • v1.0", "enabled": False}),
            (4, {"label": panic_label, "toggle-type": "checkmark", "toggle-state": 1 if is_panic else 0, "enabled": True}),
            (5, {"label": "Reload Rules", "enabled": True}),
            (6, {"type": "separator"}),
            (7, {"label": "Live Network Monitor", "icon-name": "utilities-system-monitor", "enabled": True}),
            (8, {"label": "Security Profiles", "icon-name": "emblem-system", "enabled": True}),
            (9, {"label": "Settings", "icon-name": "preferences-system", "enabled": True}),
            (10, {"type": "separator"}),
            (11, {"label": "Quit Vitorius Firewall", "icon-name": "application-exit", "enabled": True}),
        ]

    def get_layout(self):
        items = self.get_items()
        child_nodes = []
        for item_id, props in items:
            var_props = {}
            for k, v in props.items():
                if isinstance(v, str):
                    var_props[k] = GLib.Variant('s', v)
                elif isinstance(v, bool):
                    var_props[k] = GLib.Variant('b', v)
                elif isinstance(v, int):
                    var_props[k] = GLib.Variant('i', v)
            child_nodes.append(GLib.Variant('(ia{sv}av)', (item_id, var_props, [])))
        root = (0, {}, child_nodes)
        return GLib.Variant('(u(ia{sv}av))', (self.revision, root))

    def get_group_properties(self, ids, property_names):
        items_dict = {item_id: props for item_id, props in self.get_items()}
        target_ids = ids if ids else list(items_dict.keys())
        result = []
        for item_id in target_ids:
            if item_id in items_dict:
                props = items_dict[item_id]
                var_props = {}
                for k, v in props.items():
                    if not property_names or k in property_names:
                        if isinstance(v, str):
                            var_props[k] = GLib.Variant('s', v)
                        elif isinstance(v, bool):
                            var_props[k] = GLib.Variant('b', v)
                        elif isinstance(v, int):
                            var_props[k] = GLib.Variant('i', v)
                result.append((item_id, var_props))
        return GLib.Variant('(a(ia{sv}))', (result,))

    def get_property(self, item_id, name):
        items_dict = {i_id: props for i_id, props in self.get_items()}
        if item_id in items_dict and name in items_dict[item_id]:
            v = items_dict[item_id][name]
            if isinstance(v, str):
                return GLib.Variant('(v)', (GLib.Variant('s', v),))
            elif isinstance(v, bool):
                return GLib.Variant('(v)', (GLib.Variant('b', v),))
            elif isinstance(v, int):
                return GLib.Variant('(v)', (GLib.Variant('i', v),))
        return GLib.Variant('(v)', (GLib.Variant('s', ''),))


class SystemTrayIndicator:
    """
    StatusNotifierItem implementation that embeds an active corporate firewall icon
    in the desktop panel next to the system network connection icon.
    """

    def __init__(self, app):
        self.app = app
        self.connection = None
        self.active_profile = app.profiles.get_active_profile() or "Corporate"
        self.is_panic = app.core.get_panic_mode() if hasattr(app.core, 'get_panic_mode') else False
        self.menu_manager = DBusMenuManager(self)
        self._watchers = []
        self._normal_pixmaps = []
        self._panic_pixmaps = []

        project_dir = Path(__file__).resolve().parent.parent
        self.icon_dir = project_dir / "data"

        self._init_pixmaps()
        self._start_dbus()

    def _init_pixmaps(self):
        """Pre-render SVG icons into ARGB32 pixmaps for crisp taskbar rendering."""
        normal_svg = self.icon_dir / "vitorius-firewall.svg"
        panic_svg = self.icon_dir / "vitorius-firewall-panic.svg"

        for size in (24,):
            if normal_svg.is_file():
                try:
                    pb = GdkPixbuf.Pixbuf.new_from_file_at_scale(str(normal_svg), size, size, True)
                    entry = _pixbuf_to_argb_entry(pb)
                    if entry:
                        self._normal_pixmaps.append(entry)
                except Exception as e:
                    logger.debug(f"Could not load normal icon at size {size}: {e}")

            if panic_svg.is_file():
                try:
                    pb = GdkPixbuf.Pixbuf.new_from_file_at_scale(str(panic_svg), size, size, True)
                    entry = _pixbuf_to_argb_entry(pb)
                    if entry:
                        self._panic_pixmaps.append(entry)
                except Exception as e:
                    logger.debug(f"Could not load panic icon at size {size}: {e}")

    def _start_dbus(self):
        """Asynchronously connect to session bus."""
        try:
            Gio.bus_get(Gio.BusType.SESSION, None, self._on_bus_get)
        except Exception as e:
            logger.warning(f"Failed to initiate Session D-Bus connection: {e}")

    def _on_bus_get(self, source, res):
        try:
            self.connection = Gio.bus_get_finish(res)
            logger.info(f"Connected to Session D-Bus: unique name {self.connection.get_unique_name()}")
            self._register_objects()
            self._register_with_watchers()
        except Exception as e:
            logger.warning(f"Could not connect to Session D-Bus for System Tray: {e}")

    def _register_objects(self):
        """Register org.kde.StatusNotifierItem and com.canonical.dbusmenu on the bus."""
        sni_node = Gio.DBusNodeInfo.new_for_xml(STATUS_NOTIFIER_ITEM_XML)
        self.sni_interface = sni_node.interfaces[0]

        menu_node = Gio.DBusNodeInfo.new_for_xml(DBUS_MENU_XML)
        self.menu_interface = menu_node.interfaces[0]

        # Register StatusNotifierItem
        self.connection.register_object(
            "/StatusNotifierItem",
            self.sni_interface,
            self._on_sni_method_call,
            self._on_sni_get_property,
            None
        )

        # Register DBusMenu
        self.connection.register_object(
            "/MenuBar",
            self.menu_interface,
            self._on_menu_method_call,
            self._on_menu_get_property,
            None
        )
        logger.info("Exported /StatusNotifierItem and /MenuBar on Session D-Bus")

    def _register_with_watchers(self):
        """Register with StatusNotifierWatcher on KDE Plasma, GNOME, etc."""
        watcher_names = ("org.kde.StatusNotifierWatcher", "org.freedesktop.StatusNotifierWatcher")

        for watcher_name in watcher_names:
            self._call_register(watcher_name)

        # Monitor watchers so if the panel or desktop environment restarts, we re-register
        for watcher_name in watcher_names:
            try:
                watch_id = Gio.bus_watch_name_on_connection(
                    self.connection,
                    watcher_name,
                    Gio.BusNameWatcherFlags.NONE,
                    self._on_watcher_appeared,
                    None
                )
                self._watchers.append(watch_id)
            except Exception as e:
                logger.debug(f"Could not watch name {watcher_name}: {e}")

    def _on_watcher_appeared(self, connection, name, name_owner):
        logger.info(f"StatusNotifierWatcher ({name}) appeared with owner {name_owner}, registering item...")
        self._call_register(name)

    def _call_register(self, watcher_name):
        if not self.connection:
            return
        parameters = GLib.Variant('(s)', ('/StatusNotifierItem',))
        self.connection.call(
            watcher_name,
            '/StatusNotifierWatcher',
            watcher_name,
            'RegisterStatusNotifierItem',
            parameters,
            None,
            Gio.DBusCallFlags.NONE,
            2000,
            None,
            self._on_register_finished,
            watcher_name
        )

    def _on_register_finished(self, connection, res, watcher_name):
        try:
            connection.call_finish(res)
            logger.info(f"Successfully registered with {watcher_name}")
        except Exception as e:
            logger.debug(f"Watcher registration note for {watcher_name}: {e}")

    # ── StatusNotifierItem Interface Handlers ───────────────────────────

    def _on_sni_method_call(self, connection, sender, object_path, interface_name, method_name, parameters, invocation):
        logger.debug(f"SNI method called: {method_name}")
        if method_name in ('Activate', 'SecondaryActivate'):
            GLib.idle_add(self._toggle_window_visibility)
        elif method_name == 'ContextMenu':
            pass
        invocation.return_value(None)

    def _on_sni_get_property(self, connection, sender, object_path, interface_name, property_name):
        pixmaps = self._panic_pixmaps if self.is_panic else self._normal_pixmaps
        icon_name = "security-low" if self.is_panic else "vitorius-firewall"
        status_str = "NeedsAttention" if self.is_panic else "Active"
        desc = "PANIC MODE: All traffic cut!" if self.is_panic else f"Corporate Protection Active ({self.active_profile})"

        props = {
            'Category': GLib.Variant('s', 'Security'),
            'Id': GLib.Variant('s', 'vitorius-firewall'),
            'Title': GLib.Variant('s', 'Vitorius Firewall'),
            'Status': GLib.Variant('s', status_str),
            'WindowId': GLib.Variant('i', 0),
            'IconThemePath': GLib.Variant('s', str(self.icon_dir)),
            'IconName': GLib.Variant('s', icon_name),
            'IconPixmap': GLib.Variant('a(iiay)', pixmaps),
            'OverlayIconName': GLib.Variant('s', ''),
            'OverlayIconPixmap': GLib.Variant('a(iiay)', []),
            'AttentionIconName': GLib.Variant('s', 'dialog-warning'),
            'AttentionIconPixmap': GLib.Variant('a(iiay)', self._panic_pixmaps),
            'AttentionMovieName': GLib.Variant('s', ''),
            'ToolTip': GLib.Variant('(sa(iiay)ss)', (icon_name, [], 'Vitorius Firewall v1.0', desc)),
            'ItemIsMenu': GLib.Variant('b', False),
            'Menu': GLib.Variant('o', '/MenuBar'),
        }

        return props.get(property_name, None)

    # ── DBusMenu Interface Handlers ─────────────────────────────────────

    def _on_menu_method_call(self, connection, sender, object_path, interface_name, method_name, parameters, invocation):
        if method_name == 'GetLayout':
            invocation.return_value(self.menu_manager.get_layout())
        elif method_name == 'GetGroupProperties':
            ids, prop_names = parameters.unpack()
            invocation.return_value(self.menu_manager.get_group_properties(ids, prop_names))
        elif method_name == 'GetProperty':
            item_id, prop_name = parameters.unpack()
            invocation.return_value(self.menu_manager.get_property(item_id, prop_name))
        elif method_name == 'AboutToShow':
            invocation.return_value(GLib.Variant('(b)', (False,)))
        elif method_name == 'Event':
            item_id, event_id, data, timestamp = parameters.unpack()
            if event_id == 'clicked':
                self._handle_menu_click(item_id)
            invocation.return_value(None)
        else:
            invocation.return_value(None)

    def _on_menu_get_property(self, connection, sender, object_path, interface_name, property_name):
        props = {
            'Version': GLib.Variant('u', 3),
            'TextDirection': GLib.Variant('s', 'ltr'),
            'Status': GLib.Variant('s', 'normal'),
            'IconThemePath': GLib.Variant('as', [str(self.icon_dir)]),
        }
        return props.get(property_name, None)

    def _handle_menu_click(self, item_id: int):
        """Handle clicks on the context menu items."""
        if item_id == 1:
            self._open_window()
        elif item_id == 4:
            self._toggle_panic_from_tray()
        elif item_id == 5:
            self._reload_firewall_from_tray()
        elif item_id == 7:
            self._open_page('monitor')
        elif item_id == 8:
            self._open_page('profiles')
        elif item_id == 9:
            self._open_page('settings')
        elif item_id == 11:
            self._quit_app_from_tray()

    # ── Actions ─────────────────────────────────────────────────────────

    def _toggle_window_visibility(self):
        win = self.app.win
        if not win:
            self.app.activate()
            return False

        if win.is_visible() and win.is_active():
            win.set_visible(False)
        else:
            win.set_visible(True)
            win.present()
        return False

    def _open_window(self):
        def _do():
            win = self.app.win
            if not win:
                self.app.activate()
                win = self.app.win
            if win:
                self.app.release_app()
                win.set_visible(True)
                win.present()
            return False
        GLib.idle_add(_do)

    def _open_page(self, page_id: str):
        def _do():
            win = self.app.win
            if not win:
                self.app.activate()
                win = self.app.win
            if win:
                self.app.release_app()
                win.set_visible(True)
                win.present()
                win.navigate_to(page_id)
            return False
        GLib.idle_add(_do)

    def _toggle_panic_from_tray(self):
        def _worker():
            core = self.app.core
            new_state = not core.get_panic_mode()
            ok = core.set_panic_mode(new_state)
            def _done():
                if ok:
                    if new_state:
                        self.app.fw_logger.log_event(
                            'panic_on', 'critical',
                            'Panic mode enabled from System Tray - all network traffic blocked'
                        )
                        if self.app.win:
                            self.app.win._show_toast('⛔ PANIC MODE ENABLED - All network traffic blocked')
                    else:
                        self.app.fw_logger.log_event(
                            'panic_off', 'info',
                            'Panic mode disabled from System Tray - normal network traffic restored'
                        )
                        if self.app.win:
                            self.app.win._show_toast('🟢 Network traffic restored - Panic mode disabled')
                    self.update_status(is_panic=new_state)
                    if self.app.win:
                        self.app.win._update_status()
                        page = self.app.win._pages.get(self.app.win._stack.get_visible_child_name())
                        if page and hasattr(page, 'refresh'):
                            page.refresh()
                else:
                    action_name = "Panic mode" if new_state else "Restore traffic"
                    if self.app.win:
                        self.app.win._show_toast(f'{action_name}: Authorization cancelled or failed')
            GLib.idle_add(_done)
        import threading
        threading.Thread(target=_worker, daemon=True).start()

    def _reload_firewall_from_tray(self):
        def _do():
            self.app.core.reload()
            self.app.fw_logger.log_event('firewall_reloaded', 'info', 'Firewall reloaded from System Tray')
            if self.app.win:
                self.app.win._show_toast("Firewall rules reloaded")
            return False
        GLib.idle_add(_do)

    def _quit_app_from_tray(self):
        def _do():
            logger.info("Application quit requested from System Tray")
            self.app.release_app()
            self.app.quit()
            return False
        GLib.idle_add(_do)

    # ── State Sync ──────────────────────────────────────────────────────

    def update_status(self, profile_name: str = None, is_panic: bool = None):
        """Update the indicator icon, tooltip, and menu state when firewall state changes."""
        changed = False
        if profile_name is not None and profile_name != self.active_profile:
            self.active_profile = profile_name
            changed = True
        if is_panic is not None and is_panic != self.is_panic:
            self.is_panic = is_panic
            changed = True

        if changed and self.connection:
            try:
                status_str = "NeedsAttention" if self.is_panic else "Active"
                self.connection.emit_signal(
                    None,
                    "/StatusNotifierItem",
                    "org.kde.StatusNotifierItem",
                    "NewStatus",
                    GLib.Variant("(s)", (status_str,))
                )
                self.connection.emit_signal(
                    None,
                    "/StatusNotifierItem",
                    "org.kde.StatusNotifierItem",
                    "NewToolTip",
                    None
                )
                self.connection.emit_signal(
                    None,
                    "/StatusNotifierItem",
                    "org.kde.StatusNotifierItem",
                    "NewIcon",
                    None
                )
                self.menu_manager.revision += 1
                self.connection.emit_signal(
                    None,
                    "/MenuBar",
                    "com.canonical.dbusmenu",
                    "LayoutUpdated",
                    GLib.Variant("(ui)", (self.menu_manager.revision, 0))
                )
            except Exception as e:
                logger.debug(f"Error emitting tray updates: {e}")
