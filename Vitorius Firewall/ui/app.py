"""
Vitorius Firewall - GTK4/libadwaita Application & Main Window
Modern GNOME-native corporate firewall UI with sidebar navigation.
"""

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')

from gi.repository import Gtk, Adw, Gio, GLib, Gdk
import sys
import os
import socket
import threading
import logging

logger = logging.getLogger('vitorius.ui')


def get_socket_path() -> str:
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
    if runtime_dir and os.path.isdir(runtime_dir):
        return os.path.join(runtime_dir, "vitorius-firewall.sock")
    return f"/tmp/vitorius-firewall-{os.getuid()}.sock"


class SingleInstanceServer:
    """Listens on a UNIX domain socket to wake up existing window upon repeated launch."""

    def __init__(self, app):
        self.app = app
        self.sock_path = get_socket_path()
        self._server = None
        self._running = False
        self._thread = None

    def start(self):
        try:
            if os.path.exists(self.sock_path):
                try:
                    os.unlink(self.sock_path)
                except OSError:
                    pass
            self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._server.bind(self.sock_path)
            self._server.listen(5)
            self._running = True
            self._thread = threading.Thread(target=self._listen_loop, daemon=True, name="ipc-server")
            self._thread.start()
            logger.info(f"SingleInstanceServer listening on {self.sock_path}")
        except Exception as e:
            logger.warning(f"Could not start single instance socket server: {e}")

    def _listen_loop(self):
        while self._running:
            try:
                conn, _ = self._server.accept()
                data = conn.recv(128).decode("utf-8", errors="ignore").strip()
                if "PRESENT" in data:
                    GLib.idle_add(self._present_app)
                try:
                    conn.sendall(b"OK\n")
                    conn.close()
                except Exception:
                    pass
            except Exception:
                if not self._running:
                    break

    def _present_app(self):
        try:
            if self.app:
                self.app.release_app()
                if self.app.win:
                    self.app.win.set_visible(True)
                    self.app.win.present()
                    self.app.win._update_status()
                    logger.info("Window presented via IPC wake signal")
        except Exception as e:
            logger.debug(f"Error presenting window via IPC: {e}")

    def stop(self):
        self._running = False
        try:
            if self._server:
                self._server.close()
        except Exception:
            pass
        try:
            if os.path.exists(self.sock_path):
                os.unlink(self.sock_path)
        except OSError:
            pass


class VitoriusFirewallApp(Adw.Application):
    """Main application class."""

    def __init__(self, firewall_core, monitor, profiles, fw_logger, app_dir):
        super().__init__(
            application_id="com.vitorius.firewall",
            flags=Gio.ApplicationFlags.NON_UNIQUE,
        )
        self.core = firewall_core
        self.monitor = monitor
        self.profiles = profiles
        self.fw_logger = fw_logger
        self.app_dir = app_dir
        self.win = None
        self.tray = None
        self._ipc_server = None
        self._initial_start = True
        self._is_holding = False

        # Register CLI options so GApplication accepts them without erroring
        self.add_main_option(
            "minimized",
            ord("m"),
            GLib.OptionFlags.NONE,
            GLib.OptionArg.NONE,
            "Start minimized to system tray",
            None,
        )
        self.add_main_option(
            "tray",
            0,
            GLib.OptionFlags.NONE,
            GLib.OptionArg.NONE,
            "Start minimized to system tray",
            None,
        )
        self.add_main_option(
            "start-minimized",
            0,
            GLib.OptionFlags.NONE,
            GLib.OptionArg.NONE,
            "Start minimized to system tray",
            None,
        )

        self.connect('activate', self._on_activate)
        self.connect('startup', self._on_startup)
        self.connect('shutdown', self._on_shutdown)

    def hold_app(self):
        """Keep application running when minimized to system tray with no visible windows."""
        if not self._is_holding:
            self.hold()
            self._is_holding = True
            logger.info("Application hold acquired for system tray persistence")

    def release_app(self):
        """Release the application hold when window is visible or exiting."""
        if self._is_holding:
            self._is_holding = False
            self.release()
            logger.info("Application hold released")

    def _on_startup(self, app):
        logger.info("Application startup signal received")
        try:
            self._ipc_server = SingleInstanceServer(self)
            self._ipc_server.start()
        except Exception as e:
            logger.warning(f"Could not start IPC server: {e}")

        try:
            from ui.tray import SystemTrayIndicator
            self.tray = SystemTrayIndicator(self)
            logger.info("System Tray Indicator initialized")
        except Exception as e:
            logger.warning(f"Could not initialize System Tray: {e}")

    def _on_shutdown(self, app):
        logger.info("Application shutdown signal received")
        if self._is_holding:
            self._is_holding = False
            self.release()
        if self._ipc_server:
            self._ipc_server.stop()
        try:
            if self.win:
                self.win._save_window_state()
        except Exception as e:
            logger.debug(f"Error saving state on shutdown: {e}")

    def _on_activate(self, app):
        logger.info("Application activate signal received")
        try:
            if not self.win:
                logger.info("Initializing MainWindow...")
                self.win = MainWindow(self)
                logger.info("MainWindow initialized successfully")

            # Minimize to tray only if explicitly requested by CLI flag (e.g. from autostart login)
            should_minimize = (
                '--minimized' in sys.argv or
                '-m' in sys.argv or
                '--tray' in sys.argv or
                '--start-minimized' in sys.argv
            )

            self._initial_start = False

            if should_minimize:
                self.hold_app()
                logger.info("Started minimized to system tray (panel icon next to network)")
                if self.tray:
                    self.tray.update_status(
                        profile_name=self.profiles.get_active_profile(),
                        is_panic=self.core.get_panic_mode()
                    )
            else:
                self.release_app()
                self.win.set_visible(True)
                self.win.present()
                logger.info("MainWindow presented to display")
        except Exception:
            logger.exception("CRITICAL ERROR during window activation:")
            raise


class MainWindow(Adw.ApplicationWindow):

    """Main application window with sidebar navigation."""

    def __init__(self, app: VitoriusFirewallApp):
        super().__init__(application=app, title='Vitorius Firewall')
        self.app = app
        self.set_icon_name("com.vitorius.firewall")

        # Restore saved window size & maximized state
        saved_width = app.profiles.get_setting("window_width", 1100)
        saved_height = app.profiles.get_setting("window_height", 720)
        self.set_default_size(max(600, saved_width), max(400, saved_height))
        if app.profiles.get_setting("window_maximized", False):
            self.maximize()

        self._pages = {}
        self._build_ui()

        # Log startup
        app.fw_logger.log_event('app_startup', 'info', 'Vitorius Firewall started')

        # Start network monitor
        app.monitor.start()

        # Minimize to tray on close
        self.connect('close-request', self._on_close_request)

        # Schedule periodic UI refresh
        self._refresh_tag = GLib.timeout_add(4000, self._on_refresh_tick)


    def _build_ui(self):
        # Apply custom CSS
        css = Gtk.CssProvider()
        css.load_from_string(self._get_css())
        display = Gdk.Display.get_default()
        if display:
            Gtk.StyleContext.add_provider_for_display(
                display, css,
                Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
            )


        # Root layout: Navigation split view
        self._split = Adw.NavigationSplitView()
        self._split.set_min_sidebar_width(220)
        self._split.set_max_sidebar_width(280)

        # ── Sidebar ─────────────────────────────────────────────────
        sidebar_page = Adw.NavigationPage(title='Vitorius Firewall')
        sidebar_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        # Header
        sidebar_header = Adw.HeaderBar()
        sidebar_header.set_show_title(True)
        sidebar_box.append(sidebar_header)

        # Navigation list
        scroll = Gtk.ScrolledWindow(vexpand=True)
        self._nav_list = Gtk.ListBox()
        self._nav_list.set_css_classes(['navigation-sidebar'])
        self._nav_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self._nav_list.connect('row-activated', self._on_nav_selected)
        scroll.set_child(self._nav_list)
        sidebar_box.append(scroll)

        # Navigation items
        nav_items = [
            ('dashboard', 'view-grid-symbolic', 'Dashboard', 'Overview & status'),
            ('rules', 'view-list-symbolic', 'Firewall Rules', 'Manage rules & zones'),
            ('monitor', 'utilities-system-monitor-symbolic', 'Network Monitor', 'Live connections'),
            ('apps', 'application-x-executable-symbolic', 'Application Control', 'Per-app rules'),
            ('profiles', 'emblem-system-symbolic', 'Security Profiles', 'Home, Corporate, etc.'),
            ('logs', 'document-open-recent-symbolic', 'Event Log', 'Firewall events'),
            ('settings', 'preferences-system-symbolic', 'Settings', 'Configuration'),
        ]

        for item_id, icon_name, label, subtitle in nav_items:
            row = Gtk.ListBoxRow()
            row.item_id = item_id
            box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
            box.set_margin_top(8)
            box.set_margin_bottom(8)
            box.set_margin_start(12)
            box.set_margin_end(12)

            icon = Gtk.Image.new_from_icon_name(icon_name)
            icon.set_pixel_size(20)
            box.append(icon)

            text_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            lbl = Gtk.Label(label=label, xalign=0)
            lbl.set_css_classes(['nav-label'])
            text_box.append(lbl)
            sub = Gtk.Label(label=subtitle, xalign=0)
            sub.set_css_classes(['dim-label', 'caption'])
            text_box.append(sub)
            box.append(text_box)

            row.set_child(box)
            self._nav_list.append(row)

        # Status indicator at bottom of sidebar
        status_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        status_box.set_margin_start(16)
        status_box.set_margin_end(16)
        status_box.set_margin_top(8)
        status_box.set_margin_bottom(12)

        self._status_icon = Gtk.Image.new_from_icon_name('security-high-symbolic')
        self._status_icon.set_pixel_size(16)
        status_box.append(self._status_icon)

        self._status_label = Gtk.Label(label='Firewall Active')
        self._status_label.set_css_classes(['caption'])
        self._status_label.set_hexpand(True)
        self._status_label.set_xalign(0)
        status_box.append(self._status_label)

        sidebar_box.append(Gtk.Separator())
        sidebar_box.append(status_box)

        sidebar_page.set_child(sidebar_box)
        self._split.set_sidebar(sidebar_page)

        # ── Content Area ────────────────────────────────────────────
        content_page = Adw.NavigationPage(title='Dashboard')
        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        content_header = Adw.HeaderBar()
        self._content_title = Adw.WindowTitle(title='Dashboard', subtitle='Overview & status')
        content_header.set_title_widget(self._content_title)

        # Panic mode button in header
        self._panic_btn = Gtk.Button(label='⛔ Panic')
        self._panic_btn.set_css_classes(['destructive-action'])
        self._panic_btn.set_tooltip_text('Block ALL network traffic immediately')
        self._panic_btn.connect('clicked', self._on_panic_clicked)
        content_header.pack_end(self._panic_btn)

        # Reload button
        reload_btn = Gtk.Button(icon_name='view-refresh-symbolic')
        reload_btn.set_tooltip_text('Reload firewall rules')
        reload_btn.connect('clicked', self._on_reload_clicked)
        content_header.pack_end(reload_btn)

        # About button
        about_btn = Gtk.Button(icon_name='help-about-symbolic')
        about_btn.set_tooltip_text('About Vitorius Firewall v1.0')
        about_btn.connect('clicked', lambda b: self._show_about_dialog())
        content_header.pack_end(about_btn)

        content_box.append(content_header)

        # Content stack
        self._stack = Gtk.Stack()
        self._stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self._stack.set_transition_duration(200)
        content_box.append(self._stack)

        self._toast_overlay = Adw.ToastOverlay()
        self._toast_overlay.set_child(content_box)
        content_page.set_child(self._toast_overlay)
        self._split.set_content(content_page)


        # Build all pages (lazy import to avoid circular)
        from ui.pages import (
            DashboardPage, RulesPage, MonitorPage, AppsPage,
            ProfilesPage, LogsPage, SettingsPage,
        )

        page_classes = {
            'dashboard': (DashboardPage, 'Dashboard', 'Overview & status'),
            'rules': (RulesPage, 'Firewall Rules', 'Manage rules & zones'),
            'monitor': (MonitorPage, 'Network Monitor', 'Live connections'),
            'apps': (AppsPage, 'Application Control', 'Per-app rules'),
            'profiles': (ProfilesPage, 'Security Profiles', 'Home, Corporate, etc.'),
            'logs': (LogsPage, 'Event Log', 'Firewall events'),
            'settings': (SettingsPage, 'Settings', 'Configuration'),
        }

        for page_id, (cls, title, subtitle) in page_classes.items():
            try:
                page = cls(self)
                self._pages[page_id] = page
                self._stack.add_named(page, page_id)
            except Exception:
                logger.exception(f"Error loading page '{page_id}':")


        self.set_content(self._split)

        # Select last active page (or dashboard by default)
        last_page = self.app.profiles.get_setting("last_page", "dashboard")
        selected = False
        for i in range(7):
            row = self._nav_list.get_row_at_index(i)
            if row and getattr(row, 'item_id', '') == last_page:
                self._nav_list.select_row(row)
                self._on_nav_selected(self._nav_list, row)
                selected = True
                break
        if not selected:
            first_row = self._nav_list.get_row_at_index(0)
            if first_row:
                self._nav_list.select_row(first_row)

        self._update_status()

    def _on_nav_selected(self, listbox, row):
        page_id = row.item_id
        self._stack.set_visible_child_name(page_id)
        self.app.profiles.update_settings({"last_page": page_id})

        titles = {
            'dashboard': ('Dashboard', 'Overview & status'),
            'rules': ('Firewall Rules', 'Manage rules & zones'),
            'monitor': ('Network Monitor', 'Live connections'),
            'apps': ('Application Control', 'Per-app rules'),
            'profiles': ('Security Profiles', 'Home, Corporate, etc.'),
            'logs': ('Event Log', 'Firewall events'),
            'settings': ('Settings', 'Configuration'),
        }
        title, subtitle = titles.get(page_id, ('', ''))
        self._content_title.set_title(title)
        self._content_title.set_subtitle(subtitle)

        # Refresh the page
        page = self._pages.get(page_id)
        if page and hasattr(page, 'refresh'):
            page.refresh()

    def _on_panic_clicked(self, btn):
        is_panic = self.app.core.get_panic_mode()
        if is_panic:
            self._prompt_unpanic()
        else:
            self._prompt_panic()

    def _prompt_panic(self):
        confirm = self.app.profiles.get_setting("panic_mode_confirm", True)
        if confirm:
            dialog = Adw.AlertDialog(
                heading='Enable Panic Mode?',
                body='This will immediately block ALL network traffic.\n'
                     'No connections in or out will be allowed.\n\n'
                     'Are you sure you want to engage Panic Lockdown?',
            )
            dialog.add_response('cancel', 'Cancel')
            dialog.add_response('panic', 'Enable Panic Mode')
            dialog.set_response_appearance('panic', Adw.ResponseAppearance.DESTRUCTIVE)
            dialog.set_default_response('cancel')
            dialog.connect('response', lambda d, resp: self._execute_panic(True) if resp == 'panic' else None)
            dialog.present(self)
        else:
            self._execute_panic(True)

    def _prompt_unpanic(self):
        dialog = Adw.AlertDialog(
            heading='Disable Panic Mode?',
            body='This will lift the panic lockdown and restore network connectivity '
                 'according to your active security profile.\n\n'
                 'Restore network traffic now?',
        )
        dialog.add_response('cancel', 'Cancel')
        dialog.add_response('unpanic', 'Restore Network Traffic')
        dialog.set_response_appearance('unpanic', Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response('unpanic')
        dialog.connect('response', lambda d, resp: self._execute_panic(False) if resp == 'unpanic' else None)
        dialog.present(self)

    def _execute_panic(self, enable: bool):
        def worker():
            ok = self.app.core.set_panic_mode(enable)
            def done():
                if ok:
                    if enable:
                        self.app.fw_logger.log_event('panic_on', 'critical', 'Panic mode ENABLED - all traffic blocked')
                        self._show_toast('⛔ PANIC MODE ENABLED - All network traffic blocked')
                    else:
                        self.app.fw_logger.log_event('panic_off', 'info', 'Panic mode DISABLED - normal traffic restored')
                        self._show_toast('🟢 Network traffic restored - Panic mode disabled')
                    self._update_status()
                    page = self._pages.get(self._stack.get_visible_child_name())
                    if page and hasattr(page, 'refresh'):
                        page.refresh()
                    if getattr(self.app, 'tray', None):
                        self.app.tray.update_status(
                            profile_name=self.app.profiles.get_active_profile(),
                            is_panic=enable
                        )
                else:
                    action_name = "Panic mode" if enable else "Restore traffic"
                    self._show_toast(f'{action_name}: Authorization cancelled or failed')
            GLib.idle_add(done)
        threading.Thread(target=worker, daemon=True).start()

    def _on_reload_clicked(self, btn):
        def worker():
            ok = self.app.core.reload()
            def done():
                if ok:
                    self.app.fw_logger.log_event('firewall_reloaded', 'info', 'Firewall rules reloaded')
                    self._show_toast('Firewall rules reloaded')
                    page = self._pages.get(self._stack.get_visible_child_name())
                    if page and hasattr(page, 'refresh'):
                        page.refresh()
                else:
                    self._show_toast('Reload: Authorization cancelled or failed')
            GLib.idle_add(done)
        threading.Thread(target=worker, daemon=True).start()

    def _update_status(self):
        running = self.app.core.is_running()
        panic = self.app.core.get_panic_mode()

        if panic:
            self._status_label.set_label('⛔ PANIC MODE')
            self._status_icon.set_from_icon_name('dialog-error-symbolic')
            if hasattr(self, '_panic_btn'):
                self._panic_btn.set_label('🟢 Restore Traffic')
                self._panic_btn.set_css_classes(['suggested-action'])
                self._panic_btn.set_tooltip_text('Disable panic mode and restore normal network traffic')
        elif running:
            self._status_label.set_label('🛡️ Firewall Active')
            self._status_icon.set_from_icon_name('security-high-symbolic')
            if hasattr(self, '_panic_btn'):
                self._panic_btn.set_label('⛔ Panic')
                self._panic_btn.set_css_classes(['destructive-action'])
                self._panic_btn.set_tooltip_text('Block ALL network traffic immediately (Panic Lockdown)')
        else:
            self._status_label.set_label('⚠️ Firewall Inactive')
            self._status_icon.set_from_icon_name('dialog-warning-symbolic')
            if hasattr(self, '_panic_btn'):
                self._panic_btn.set_label('⛔ Panic')
                self._panic_btn.set_css_classes(['destructive-action'])
                self._panic_btn.set_tooltip_text('Block ALL network traffic immediately (Panic Lockdown)')

    def _save_window_state(self):
        try:
            is_max = self.is_maximized()
            width, height = self.get_width(), self.get_height()
            active_page = self._stack.get_visible_child_name() or "dashboard"
            state = {
                "window_maximized": is_max,
                "last_page": active_page
            }
            if not is_max and width > 200 and height > 200:
                state["window_width"] = width
                state["window_height"] = height
            self.app.profiles.update_settings(state)
            logger.debug(f"Saved window state: {state}")
        except Exception as e:
            logger.debug(f"Error saving window state: {e}")

    def _on_close_request(self, window):
        self._save_window_state()
        close_to_tray = self.app.profiles.get_setting("close_to_tray", True)
        if close_to_tray and getattr(self.app, 'tray', None):
            logger.info("Window close requested - hiding to system tray (panel icon)")
            self.app.hold_app()
            self.set_visible(False)
            return True  # Stop the window from being destroyed
        logger.info("Window close requested - exiting application")
        self.app.release_app()
        return False

    def _on_refresh_tick(self):
        """Periodic UI refresh."""
        # When window is hidden (minimized to tray), pause UI widget updates to save CPU and I/O
        if not self.is_visible():
            return True

        self._update_status()

        # Update system tray indicator
        if getattr(self.app, 'tray', None):
            self.app.tray.update_status(
                profile_name=self.app.profiles.get_active_profile(),
                is_panic=self.app.core.get_panic_mode()
            )

        page_name = self._stack.get_visible_child_name()
        page = self._pages.get(page_name)
        if page and hasattr(page, 'refresh') and page_name in ('dashboard', 'monitor'):
            page.refresh()
        return True  # Keep timer running

    def _show_about_dialog(self):
        about = Adw.AboutWindow(
            transient_for=self,
            modal=True,
            application_name="Vitorius Firewall",
            application_icon="com.vitorius.firewall",
            developer_name="Vitorius",
            version="1.0",
            comments="Corporate-grade Windows-style firewall management with security profiles and live monitor for Fedora / Bazzite Linux",
            copyright="© 2026 Vitorius",
            license_type=Gtk.License.MIT_X11,
        )
        about.present()

    def _show_toast(self, text: str):
        toast = Adw.Toast(title=text, timeout=3)
        if hasattr(self, '_toast_overlay') and self._toast_overlay:
            self._toast_overlay.add_toast(toast)


    def navigate_to(self, page_id: str):
        """Navigate to a specific page programmatically."""
        for i in range(7):
            row = self._nav_list.get_row_at_index(i)
            if row and getattr(row, 'item_id', '') == page_id:
                self._nav_list.select_row(row)
                self._on_nav_selected(self._nav_list, row)
                break

    def _get_css(self):
        return '''
            .nav-label {
                font-weight: 600;
                font-size: 14px;
            }
            .stat-card {
                background: alpha(@accent_bg_color, 0.08);
                border-radius: 12px;
                padding: 16px;
                min-width: 140px;
            }
            .stat-value {
                font-size: 28px;
                font-weight: 800;
            }
            .stat-label {
                font-size: 12px;
                opacity: 0.7;
            }
            .status-good {
                color: #2ec27e;
            }
            .status-warn {
                color: #e5a50a;
            }
            .status-bad {
                color: #e01b24;
            }
            .premium-badge {
                background: linear-gradient(135deg, #8b5cf6, #6366f1);
                color: white;
                border-radius: 6px;
                padding: 2px 8px;
                font-size: 10px;
                font-weight: 700;
            }
            .section-title {
                font-size: 16px;
                font-weight: 700;
                margin-top: 8px;
            }
            .rule-row {
                padding: 8px 12px;
                border-radius: 8px;
            }
            .rule-row:hover {
                background: alpha(@accent_bg_color, 0.05);
            }
            .conn-established {
                color: #2ec27e;
            }
            .conn-listen {
                color: #62a0ea;
            }
            .conn-close {
                color: #e5a50a;
            }
            .monitor-card {
                background: alpha(@card_bg_color, 0.6);
                border-radius: 12px;
                padding: 12px 16px;
            }
            .profile-card {
                border-radius: 12px;
                padding: 16px;
            }
            .profile-card:checked {
                outline: 2px solid @accent_bg_color;
                outline-offset: -2px;
            }
            .severity-info { color: #62a0ea; }
            .severity-warning { color: #e5a50a; }
            .severity-critical { color: #e01b24; }
            .severity-alert { color: #ff7800; }
        '''
