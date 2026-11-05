"""
Vitorius Firewall - Profile Manager & Logging System
Manages security profiles, configuration persistence, and structured logging.
"""

import json
import os
import shutil
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger('vitorius.profiles')

BASE_DIR = Path(__file__).resolve().parent.parent / '.storage'

try:
    CONFIG_DIR = Path.home() / '.config' / 'vitorius-firewall'
    DATA_DIR = Path.home() / '.local' / 'share' / 'vitorius-firewall'
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
except OSError:
    CONFIG_DIR = BASE_DIR / 'config'
    DATA_DIR = BASE_DIR / 'data'

LOG_DIR = DATA_DIR / 'logs'
BACKUP_DIR = DATA_DIR / 'backups'
CONFIG_FILE = CONFIG_DIR / 'config.json'
RULES_BACKUP_DIR = BACKUP_DIR / 'rules'


DEFAULT_SETTINGS = {
    "start_minimized": False,
    "autostart": False,
    "auto_start": False,
    "close_to_tray": True,
    "panic_mode_confirm": True,
    "last_page": "dashboard",
    "window_width": 1100,
    "window_height": 720,
    "window_maximized": False,
    "notification_level": "important",
    "log_retention_days": 90,
    "monitor_refresh_ms": 2000,
    "theme": "system",
    "backup_on_profile_change": True,
    "last_rules_zone": "public",
    "monitor_proto_filter_idx": 0,
    "monitor_state_filter_idx": 0,
    "blocked_apps": [],
    "blocked_apps_data": {},
    "custom_apps": [],
}


def _ensure_dirs():
    for d in [CONFIG_DIR, DATA_DIR, LOG_DIR, BACKUP_DIR, RULES_BACKUP_DIR]:
        try:
            d.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass



class ProfileManager:
    """Manages firewall security profiles with persistence."""

    def __init__(self, default_config_path: str = None):
        _ensure_dirs()
        self._default_config_path = default_config_path
        self._config = {}
        self._active_profile: str = ''
        self._load_config()

    def _load_config(self):
        """Load config from user dir, falling back to local storage then default."""
        target_file = CONFIG_FILE
        if not target_file.exists():
            fallback_file = BASE_DIR / 'config' / 'config.json'
            if fallback_file.exists():
                target_file = fallback_file

        loaded = False
        if target_file.exists():
            try:
                with open(target_file, 'r', encoding='utf-8') as f:
                    self._config = json.load(f)
                self._active_profile = self._config.get('active_profile') or 'Corporate'
                loaded = True
            except Exception as e:
                logger.error(f"Error loading config from {target_file}: {e}")

        if not loaded:
            # Load defaults
            if self._default_config_path and os.path.exists(self._default_config_path):
                try:
                    with open(self._default_config_path, 'r', encoding='utf-8') as f:
                        self._config = json.load(f)
                except Exception as e:
                    logger.error(f"Error loading default config: {e}")
                    self._config = {'profiles': {}, 'settings': {}}
            else:
                self._config = {'profiles': {}, 'settings': {}}

        # Ensure settings are populated with defaults
        saved_settings = self._config.get('settings', {})
        merged_settings = dict(DEFAULT_SETTINGS)
        merged_settings.update(saved_settings)
        self._config['settings'] = merged_settings

        if not self._active_profile:
            self._active_profile = self._config.get('active_profile') or 'Corporate'

        self._save_config()

    def _save_config(self):
        """Persist config to disk atomically with fallback."""
        try:
            self._config['version'] = '1.0'
            self._config['active_profile'] = self._active_profile
            target_file = CONFIG_FILE
            try:
                target_file.parent.mkdir(parents=True, exist_ok=True)
            except OSError:
                target_file = BASE_DIR / 'config' / 'config.json'
                target_file.parent.mkdir(parents=True, exist_ok=True)

            tmp_file = target_file.with_suffix('.tmp')
            with open(tmp_file, 'w', encoding='utf-8') as f:
                json.dump(self._config, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_file, target_file)
            logger.debug(f"Configuration saved successfully to {target_file}")
        except Exception as e:
            logger.error(f"Error saving config: {e}")
            # Try secondary fallback to .storage
            try:
                sec_file = BASE_DIR / 'config' / 'config.json'
                sec_file.parent.mkdir(parents=True, exist_ok=True)
                with open(sec_file, 'w', encoding='utf-8') as f:
                    json.dump(self._config, f, indent=2)
                logger.info(f"Saved to fallback storage: {sec_file}")
            except Exception as e2:
                logger.error(f"Fallback save failed: {e2}")

    # ── Profile Operations ──────────────────────────────────────────

    def get_profiles(self) -> dict:
        """Get all profiles. Returns {name: profile_dict}."""
        return self._config.get('profiles', {})

    def get_profile(self, name: str) -> Optional[dict]:
        return self._config.get('profiles', {}).get(name)

    def get_active_profile(self) -> str:
        if not self._active_profile:
            self._active_profile = self._config.get('active_profile') or 'Corporate'
        return self._active_profile

    def set_active_profile(self, name: str):
        self._active_profile = name
        self._config['active_profile'] = name
        self._save_config()

    def create_profile(self, name: str, settings: dict) -> bool:
        """Create a new profile."""
        if name in self._config.get('profiles', {}):
            return False
        if 'profiles' not in self._config:
            self._config['profiles'] = {}
        self._config['profiles'][name] = settings
        self._save_config()
        return True

    def update_profile(self, name: str, settings: dict) -> bool:
        if name not in self._config.get('profiles', {}):
            return False
        self._config['profiles'][name] = settings
        self._save_config()
        return True

    def delete_profile(self, name: str) -> bool:
        """Delete a profile (built-in profiles cannot be deleted)."""
        profiles = self._config.get('profiles', {})
        if name not in profiles:
            return False
        tier = profiles[name].get('tier', '')
        if tier in ('standard', 'premium') and name in ('Home', 'Public', 'Corporate', 'Gaming', 'Maximum Security'):
            return False  # Can't delete built-in profiles
        del self._config['profiles'][name]
        if self._active_profile == name:
            self._active_profile = ''
        self._save_config()
        return True

    def duplicate_profile(self, source_name: str, new_name: str) -> bool:
        profile = self.get_profile(source_name)
        if not profile:
            return False
        new_profile = json.loads(json.dumps(profile))  # Deep copy
        new_profile['tier'] = 'custom'
        new_profile['description'] = f'Copy of {source_name}'
        return self.create_profile(new_name, new_profile)

    def apply_profile(self, name: str, firewall_core) -> tuple[bool, str]:
        """Apply a profile to the firewall in a single privileged batch. Returns (success, message)."""
        profile = self.get_profile(name)
        if not profile:
            return False, f'Profile "{name}" not found'

        try:
            # Backup current rules first (non-blocking, ignore errors)
            try:
                self.backup_rules(firewall_core)
            except Exception as e:
                logger.warning(f"Backup skipped: {e}")

            zone = profile.get('default_zone', 'public')
            current = firewall_core.get_zone_settings(zone)

            commands = []
            # 1. Ensure firewalld service is active
            commands.append('systemctl start firewalld 2>/dev/null || true')

            # 2. Set default zone
            commands.append(f'firewall-cmd --set-default-zone="{zone}" 2>/dev/null || true')

            # 3. Clear existing services for this zone
            for svc in current.get('services', []):
                commands.append(f'firewall-cmd --permanent --zone="{zone}" --remove-service="{svc}" 2>/dev/null || true')

            # 4. Add profile allowed services
            for svc in profile.get('allowed_services', []):
                commands.append(f'firewall-cmd --permanent --zone="{zone}" --add-service="{svc}" 2>/dev/null || true')

            # 5. Add allowed ports
            for port_info in profile.get('allowed_ports', []):
                port = port_info['port']
                proto = port_info.get('protocol', 'tcp')
                commands.append(f'firewall-cmd --permanent --zone="{zone}" --add-port="{port}/{proto}" 2>/dev/null || true')

            # 6. Logging configuration (native firewalld log-denied)
            log_level = profile.get('logging', 'minimal')
            if log_level in ('standard', 'full'):
                commands.append('firewall-cmd --set-log-denied=all 2>/dev/null || true')
            else:
                commands.append('firewall-cmd --set-log-denied=off 2>/dev/null || true')

            # 7. Masquerade
            if profile.get('masquerade', False):
                commands.append(f'firewall-cmd --permanent --zone="{zone}" --add-masquerade 2>/dev/null || true')
            else:
                commands.append(f'firewall-cmd --permanent --zone="{zone}" --remove-masquerade 2>/dev/null || true')

            # 8. Reload firewall to apply all changes cleanly
            commands.append('firewall-cmd --reload')

            # Execute the entire profile transition in ONE single pkexec transaction
            success, msg = firewall_core.execute_batch(commands)
            if success:
                self.set_active_profile(name)
                return True, f'Profile "{name}" applied successfully'
            return False, msg

        except Exception as e:
            logger.exception(f"Error applying profile {name}: {e}")
            return False, f'Error applying profile: {e}'

    # ── Backup / Restore ────────────────────────────────────────────

    def backup_rules(self, firewall_core) -> Optional[str]:
        """Backup current firewall rules. Returns backup filename."""
        try:
            RULES_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_file = RULES_BACKUP_DIR / f'rules_backup_{timestamp}.json'
            if firewall_core.is_running():
                firewall_core.export_rules(str(backup_file))
                logger.info(f"Rules backed up to {backup_file}")
                return str(backup_file)
            return None
        except Exception as e:
            logger.warning(f"Backup failed: {e}")
            return None

    def get_backups(self) -> list[dict]:
        """List available backups."""
        backups = []
        try:
            for f in sorted(RULES_BACKUP_DIR.iterdir(), reverse=True):
                if f.suffix == '.json':
                    stat = f.stat()
                    backups.append({
                        'filename': f.name,
                        'path': str(f),
                        'size': stat.st_size,
                        'date': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    })
        except Exception:
            pass
        return backups

    def restore_backup(self, filepath: str, firewall_core) -> tuple[bool, str]:
        return firewall_core.import_rules(filepath)

    # ── Settings ────────────────────────────────────────────────────

    def get_settings(self) -> dict:
        return self._config.get('settings', {})

    def update_settings(self, settings: dict):
        if 'settings' not in self._config:
            self._config['settings'] = {}
        self._config['settings'].update(settings)
        # Keep autostart and auto_start aliases synced
        if 'autostart' in settings:
            self._config['settings']['auto_start'] = settings['autostart']
        elif 'auto_start' in settings:
            self._config['settings']['autostart'] = settings['auto_start']
        self._save_config()

    def get_setting(self, key: str, default=None):
        settings = self._config.get('settings', {})
        if key in settings:
            return settings[key]
        if key == 'autostart' and 'auto_start' in settings:
            return settings['auto_start']
        if key == 'auto_start' and 'autostart' in settings:
            return settings['autostart']
        return default

    def get_blocked_apps(self) -> list[str]:
        return list(self.get_settings().get('blocked_apps', []))

    def is_app_blocked(self, app_name: str) -> bool:
        norm = app_name.lower().strip()
        blocked = [b.lower().strip() for b in self.get_blocked_apps()]
        return any(norm == b or norm in b or b in norm for b in blocked)

    def set_app_blocked(self, app_name: str, blocked: bool, app_data: dict = None):
        apps = set(b.lower().strip() for b in self.get_blocked_apps())
        norm = app_name.lower().strip()
        data = dict(self.get_settings().get('blocked_apps_data', {}))
        if blocked:
            apps.add(norm)
            if app_data:
                data[norm] = app_data
        else:
            apps = {b for b in apps if b != norm and norm not in b and b not in norm}
            data.pop(norm, None)
        self.update_settings({'blocked_apps': sorted(list(apps)), 'blocked_apps_data': data})

    def get_app_blocked_data(self, app_name: str) -> dict:
        norm = app_name.lower().strip()
        return dict(self.get_settings().get('blocked_apps_data', {}).get(norm, {}))

    def get_custom_apps(self) -> list[dict]:
        return list(self.get_settings().get('custom_apps', []))

    def add_custom_app(self, name: str, path: str):
        custom = self.get_custom_apps()
        if not any(a.get('name', '').lower() == name.lower() for a in custom):
            custom.append({'name': name, 'path': path})
            self.update_settings({'custom_apps': custom})

    def remove_custom_app(self, name: str):
        custom = [a for a in self.get_custom_apps() if a.get('name', '').lower() != name.lower()]
        self.update_settings({'custom_apps': custom})



class FirewallLogger:
    """Structured logging system for firewall events."""

    # Event types
    RULE_ADDED = 'rule_added'
    RULE_REMOVED = 'rule_removed'
    PROFILE_CHANGED = 'profile_changed'
    IP_BLOCKED = 'ip_blocked'
    IP_UNBLOCKED = 'ip_unblocked'
    PANIC_ON = 'panic_on'
    PANIC_OFF = 'panic_off'
    CONNECTION_ALERT = 'connection_alert'
    IDS_ALERT = 'ids_alert'
    PORT_SCAN = 'port_scan_detected'
    CONFIG_CHANGED = 'config_changed'
    FIREWALL_RELOADED = 'firewall_reloaded'
    EXPORT = 'rules_exported'
    IMPORT = 'rules_imported'
    STARTUP = 'app_startup'
    SHUTDOWN = 'app_shutdown'

    # Severity levels
    INFO = 'info'
    WARNING = 'warning'
    CRITICAL = 'critical'
    ALERT = 'alert'

    def __init__(self, max_entries: int = 10000):
        _ensure_dirs()
        self._max_entries = max_entries
        self._events: list[dict] = []
        self._log_file = LOG_DIR / 'firewall_events.json'
        self._stats = {
            'total_events': 0,
            'blocked_connections': 0,
            'rules_changed': 0,
            'alerts': 0,
            'session_start': datetime.now().isoformat(),
        }
        self._load_events()

    def _load_events(self):
        """Load event history from disk."""
        if self._log_file.exists():
            try:
                with open(self._log_file, 'r') as f:
                    data = json.load(f)
                    self._events = data.get('events', [])[-self._max_entries:]
                    saved_stats = data.get('stats', {})
                    self._stats['total_events'] = saved_stats.get('total_events', 0)
                    self._stats['blocked_connections'] = saved_stats.get('blocked_connections', 0)
                    self._stats['rules_changed'] = saved_stats.get('rules_changed', 0)
                    self._stats['alerts'] = saved_stats.get('alerts', 0)
            except Exception as e:
                logger.error(f"Error loading event log: {e}")

    def _save_events(self):
        """Save events to disk."""
        try:
            with open(self._log_file, 'w') as f:
                json.dump({
                    'events': self._events[-self._max_entries:],
                    'stats': self._stats,
                }, f, indent=1)
        except Exception as e:
            logger.error(f"Error saving event log: {e}")

    def log_event(self, event_type: str, severity: str = 'info',
                  details: str = '', extra: dict = None):
        """Log a firewall event."""
        event = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'severity': severity,
            'details': details,
        }
        if extra:
            event['extra'] = extra

        self._events.append(event)
        self._stats['total_events'] += 1

        if event_type in (self.IP_BLOCKED, self.CONNECTION_ALERT):
            self._stats['blocked_connections'] += 1
        if event_type in (self.RULE_ADDED, self.RULE_REMOVED):
            self._stats['rules_changed'] += 1
        if severity in (self.ALERT, self.CRITICAL):
            self._stats['alerts'] += 1

        # Trim if too many
        if len(self._events) > self._max_entries:
            self._events = self._events[-self._max_entries:]

        self._save_events()
        logger.info(f"[{severity.upper()}] {event_type}: {details}")

    def get_events(self, count: int = 100, event_type: str = None,
                   severity: str = None, search: str = None) -> list[dict]:
        """Get filtered events."""
        events = list(self._events)

        if event_type:
            events = [e for e in events if e.get('type') == event_type]
        if severity:
            events = [e for e in events if e.get('severity') == severity]
        if search:
            search_lower = search.lower()
            events = [e for e in events if search_lower in json.dumps(e).lower()]

        return events[-count:]

    def get_stats(self) -> dict:
        return dict(self._stats)

    def clear_events(self):
        self._events = []
        self._stats = {
            'total_events': 0,
            'blocked_connections': 0,
            'rules_changed': 0,
            'alerts': 0,
            'session_start': datetime.now().isoformat(),
        }
        self._save_events()

    def export_logs(self, filepath: str, fmt: str = 'json') -> bool:
        """Export logs to a file. Formats: 'json', 'csv', 'txt'."""
        try:
            if fmt == 'json':
                with open(filepath, 'w') as f:
                    json.dump(self._events, f, indent=2)
            elif fmt == 'csv':
                import csv
                with open(filepath, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Timestamp', 'Type', 'Severity', 'Details'])
                    for e in self._events:
                        writer.writerow([
                            e.get('timestamp', ''),
                            e.get('type', ''),
                            e.get('severity', ''),
                            e.get('details', ''),
                        ])
            elif fmt == 'txt':
                with open(filepath, 'w') as f:
                    for e in self._events:
                        f.write(
                            f"[{e.get('timestamp', '')}] "
                            f"[{e.get('severity', '').upper()}] "
                            f"{e.get('type', '')}: "
                            f"{e.get('details', '')}\n"
                        )
            return True
        except Exception as e:
            logger.error(f"Error exporting logs: {e}")
            return False

    def get_event_types(self) -> list[str]:
        """Get all unique event types in the log."""
        return sorted(set(e.get('type', '') for e in self._events))
