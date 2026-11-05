"""
Vitorius Firewall - Core Backend
Interfaces with firewalld via firewall-cmd and nftables via nft.
Provides all firewall operations: zones, ports, services, rich rules, IP blocking.
"""

import subprocess
import json
import os
import re
import ipaddress
import logging
import time
from typing import Optional

logger = logging.getLogger('vitorius.core')



def _run(cmd: list[str], check: bool = True, timeout: int = 10) -> subprocess.CompletedProcess:
    """Run a command, return CompletedProcess."""
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=check
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {' '.join(cmd)}\n  stderr: {e.stderr.strip()}")
        raise
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {' '.join(cmd)}")
        raise


def _query_fw(*args) -> bool:
    """Run firewall-cmd query safely without throwing CalledProcessError."""
    try:
        res = subprocess.run(['firewall-cmd'] + list(args), capture_output=True, text=True, timeout=4)
        return res.returncode == 0
    except Exception:
        return False


def _fw(*args, permanent: bool = False) -> str:
    """Run firewall-cmd with optional --permanent flag. Returns stdout."""
    cmd = ['firewall-cmd']
    if permanent:
        cmd.append('--permanent')
    cmd.extend(args)
    return _run(cmd).stdout.strip()


def _run_pkexec_bash(script_content: str, timeout: int = 45) -> subprocess.CompletedProcess:
    """Run bash script via pkexec. Handles cancellations (126, 127) cleanly."""
    try:
        res = subprocess.run(
            ['pkexec', 'bash', '-c', script_content],
            capture_output=True,
            text=True,
            timeout=timeout
        )
    except subprocess.TimeoutExpired:
        logger.error("Privileged command timed out")
        raise
    except FileNotFoundError:
        logger.error("pkexec binary not found")
        raise

    if res.returncode in (126, 127):
        logger.info("PolicyKit authorization was cancelled or dismissed by user")
        raise PermissionError("Authorization cancelled by user")
    elif res.returncode != 0:
        logger.error(f"Privileged command failed (code {res.returncode}): {res.stderr.strip()}")
        raise subprocess.CalledProcessError(res.returncode, ['pkexec', 'bash'], output=res.stdout, stderr=res.stderr)
    return res


def _pkexec_fw(*args, permanent: bool = False) -> str:
    """Run firewall-cmd via pkexec for single privileged operations."""
    parts = ['firewall-cmd']
    if permanent:
        parts.append('--permanent')
    parts.extend(args)
    cmd_str = ' '.join(parts)
    res = _run_pkexec_bash(cmd_str)
    return res.stdout.strip()


KNOWN_APP_DEFINITIONS = {
    'ssh': {
        'services': ['ssh'],
        'ports': [('22', 'tcp')],
        'process_names': ['sshd', 'ssh'],
    },
    'samba': {
        'services': ['samba', 'samba-client'],
        'ports': [('137', 'udp'), ('138', 'udp'), ('139', 'tcp'), ('445', 'tcp')],
        'process_names': ['smbd', 'nmbd'],
    },
    'cockpit': {
        'services': ['cockpit'],
        'ports': [('9090', 'tcp')],
        'process_names': ['cockpit-ws', 'cockpit-tls'],
    },
    'syncthing': {
        'services': ['syncthing', 'syncthing-gui'],
        'ports': [('22000', 'tcp'), ('22000', 'udp'), ('21027', 'udp')],
        'process_names': ['syncthing'],
    },
    'steam': {
        'services': [],
        'ports': [('27015', 'udp'), ('27036', 'udp'), ('27036', 'tcp'), ('4380', 'udp')],
        'flatpak_ids': ['com.valvesoftware.Steam'],
        'process_names': ['steam', 'steamwebhelper'],
    },
    'discord': {
        'services': [],
        'ports': [('50001', 'udp')],
        'flatpak_ids': ['com.discordapp.Discord'],
        'process_names': ['discord', 'Discord'],
    },
    'firefox': {
        'services': [],
        'ports': [],
        'flatpak_ids': ['org.mozilla.firefox'],
        'process_names': ['firefox', 'firefox-bin'],
    },
    'chrome': {
        'services': [],
        'ports': [],
        'flatpak_ids': ['com.google.Chrome'],
        'process_names': ['chrome', 'google-chrome', 'google-chrome-stable'],
    },
    'brave': {
        'services': [],
        'ports': [],
        'flatpak_ids': ['com.brave.Browser'],
        'process_names': ['brave', 'brave-browser'],
    },
    'spotify': {
        'services': [],
        'ports': [],
        'flatpak_ids': ['com.spotify.Client'],
        'process_names': ['spotify'],
    },
}


def get_installed_flatpaks() -> dict[str, str]:
    """Returns {app_name_lower: app_id} for installed flatpaks."""
    result = {}
    try:
        proc = subprocess.run(
            ['flatpak', 'list', '--app', '--columns=name,application'],
            capture_output=True, text=True, timeout=2.0
        )
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                parts = line.strip().split('\t')
                if len(parts) >= 2:
                    name, app_id = parts[0].strip(), parts[1].strip()
                    result[name.lower()] = app_id
                    result[app_id.lower()] = app_id
    except Exception:
        pass
    return result


def _match_app_definition(app_name: str) -> Optional[dict]:
    name_clean = app_name.lower().strip()
    for key, defn in KNOWN_APP_DEFINITIONS.items():
        if key == name_clean or key in name_clean or name_clean in key:
            return defn
        for proc in defn.get('process_names', []):
            if proc.lower() in name_clean or name_clean in proc.lower():
                return defn
    return None


class FirewallCore:
    """Core firewall interface wrapping firewalld and nftables with caching."""

    def __init__(self):
        self._use_pkexec = True  # Use pkexec for write operations
        self._running = False
        self._cache = {}
        self._cache_time = {}
        self._check_firewalld()

    def invalidate_cache(self):
        """Invalidate all cached firewall responses."""
        self._cache.clear()
        self._cache_time.clear()

    def execute_batch(self, commands: list[str]) -> tuple[bool, str]:
        """Execute a batch of firewall-cmd commands in ONE single privileged transaction."""
        if not commands:
            return True, "No commands to execute"

        # Ensure firewalld daemon is started first
        full_commands = []
        if not any('systemctl start firewalld' in c for c in commands):
            full_commands.append('systemctl start firewalld 2>/dev/null || true')
        full_commands.extend(commands)
        script = "\n".join(full_commands)
        try:
            if self._use_pkexec:
                _run_pkexec_bash(script, timeout=60)
            else:
                subprocess.run(['bash', '-c', script], capture_output=True, text=True, check=True, timeout=60)
            self.invalidate_cache()
            return True, "Configuration successfully applied"
        except PermissionError:
            logger.info("Batch firewall operation cancelled by user")
            return False, "Authorization was cancelled by user"
        except subprocess.CalledProcessError as e:
            err = (e.stderr or e.output or str(e)).strip()
            logger.error(f"Batch execution failed: {err}")
            return False, f"Failed: {err}"
        except Exception as e:
            logger.error(f"Batch execution failed: {e}")
            return False, f"Failed to apply configuration: {e}"

    # ── Status ──────────────────────────────────────────────────────

    def _check_firewalld(self):
        """Check if firewalld is running without raising exceptions."""
        try:
            res = subprocess.run(['firewall-cmd', '--state'], capture_output=True, text=True, timeout=1.5)
            self._running = (res.returncode == 0)
        except Exception:
            self._running = False

    def is_running(self) -> bool:
        now = time.time()
        if 'is_running' in self._cache and (now - self._cache_time.get('is_running', 0)) < 10.0:
            return self._running
        self._check_firewalld()
        self._cache['is_running'] = self._running
        self._cache_time['is_running'] = now
        return self._running


    def get_state(self) -> str:
        """Return 'running' or 'not running'."""
        if not self.is_running():
            return 'not running'
        try:
            return _fw('--state')
        except Exception:
            return 'not running'

    # ── Zones ───────────────────────────────────────────────────────

    def get_zones(self) -> list[str]:
        """Get all available zones."""
        now = time.time()
        if 'zones' in self._cache and (now - self._cache_time.get('zones', 0)) < 30.0:
            return list(self._cache['zones'])
        if not self.is_running():
            return ['public', 'home', 'work', 'drop', 'trusted']
        try:
            zones = _fw('--get-zones').split()
            if not zones:
                zones = ['public', 'home', 'work', 'drop', 'trusted', 'internal', 'external', 'dmz', 'block']
            self._cache['zones'] = zones
            self._cache_time['zones'] = now
            return zones
        except Exception:
            return ['public', 'home', 'work', 'drop', 'trusted']

    def get_active_zones(self) -> dict:
        """Get active zones and their interfaces."""
        now = time.time()
        if 'active_zones' in self._cache and (now - self._cache_time.get('active_zones', 0)) < 15.0:
            return dict(self._cache['active_zones'])
        if not self.is_running():
            return {}

        result = {}
        try:
            output = _fw('--get-active-zones')
            current_zone = None
            for line in output.splitlines():
                if not line.startswith(' ') and not line.startswith('\t'):
                    current_zone = line.strip()
                    result[current_zone] = {'interfaces': [], 'sources': []}
                elif current_zone:
                    line = line.strip()
                    if line.startswith('interfaces:'):
                        result[current_zone]['interfaces'] = line.split(':', 1)[1].strip().split()
                    elif line.startswith('sources:'):
                        result[current_zone]['sources'] = line.split(':', 1)[1].strip().split()
        except Exception as e:
            logger.debug(f"Error getting active zones: {e}")

        self._cache['active_zones'] = result
        self._cache_time['active_zones'] = now
        return result

    def get_default_zone(self) -> str:
        now = time.time()
        if 'default_zone' in self._cache and (now - self._cache_time.get('default_zone', 0)) < 30.0:
            return self._cache['default_zone']
        if not self.is_running():
            return 'public'
        try:
            dz = _fw('--get-default-zone') or 'public'
        except Exception:
            dz = 'public'
        self._cache['default_zone'] = dz
        self._cache_time['default_zone'] = now
        return dz

    def set_default_zone(self, zone: str) -> bool:
        if not self.is_running():
            return False
        try:
            if self._use_pkexec:
                _pkexec_fw('--set-default-zone=' + zone)
            else:
                _fw('--set-default-zone=' + zone)
            self.invalidate_cache()
            return True
        except Exception as e:
            logger.error(f"Failed to set default zone: {e}")
            return False

    def get_zone_settings(self, zone: str) -> dict:
        """Get comprehensive settings for a zone in 1 single fast call."""
        now = time.time()
        cache_key = f'zone_{zone}'
        if cache_key in self._cache and (now - self._cache_time.get(cache_key, 0)) < 15.0:
            return dict(self._cache[cache_key])

        settings = {
            'zone': zone,
            'target': 'default',
            'interfaces': [],
            'sources': [],
            'services': [],
            'ports': [],
            'protocols': [],
            'masquerade': False,
            'forward_ports': [],
            'source_ports': [],
            'icmp_blocks': [],
            'rich_rules': [],
        }

        if not self.is_running():
            self._cache[cache_key] = settings
            self._cache_time[cache_key] = now
            return settings

        try:
            out = _fw('--zone=' + zone, '--list-all')
            for line in out.splitlines():
                sline = line.strip()
                if sline.startswith('target:'):
                    settings['target'] = sline.split(':', 1)[1].strip()
                elif sline.startswith('interfaces:'):
                    settings['interfaces'] = sline.split(':', 1)[1].strip().split()
                elif sline.startswith('sources:'):
                    settings['sources'] = sline.split(':', 1)[1].strip().split()
                elif sline.startswith('services:'):
                    settings['services'] = sline.split(':', 1)[1].strip().split()
                elif sline.startswith('ports:'):
                    for p in sline.split(':', 1)[1].strip().split():
                        parts = p.split('/')
                        if len(parts) == 2:
                            settings['ports'].append({'port': parts[0], 'protocol': parts[1]})
                elif sline.startswith('protocols:'):
                    settings['protocols'] = sline.split(':', 1)[1].strip().split()
                elif sline.startswith('masquerade:'):
                    settings['masquerade'] = sline.split(':', 1)[1].strip().lower() == 'yes'
                elif sline.startswith('forward-ports:'):
                    val = sline.split(':', 1)[1].strip()
                    if val:
                        settings['forward_ports'].append(val)
                elif sline.startswith('icmp-blocks:'):
                    settings['icmp_blocks'] = sline.split(':', 1)[1].strip().split()
                elif sline.startswith('rule '):
                    settings['rich_rules'].append(sline)
        except Exception as e:
            logger.debug(f"Error parsing zone {zone} via list-all: {e}")

        # Add active interfaces
        active = self.get_active_zones()
        if zone in active:
            if not settings['interfaces']:
                settings['interfaces'] = active[zone].get('interfaces', [])
            if not settings['sources']:
                settings['sources'] = active[zone].get('sources', [])

        self._cache[cache_key] = settings
        self._cache_time[cache_key] = now
        return settings


    # ── Services ────────────────────────────────────────────────────

    def get_available_services(self) -> list[str]:
        """Get all available service definitions."""
        try:
            return sorted(_fw('--get-services').split())
        except Exception:
            return []

    def add_service(self, zone: str, service: str, permanent: bool = True) -> bool:
        if not self.is_running():
            return False
        try:
            if permanent:
                cmd = f'firewall-cmd --zone="{zone}" --add-service="{service}" && firewall-cmd --permanent --zone="{zone}" --add-service="{service}"'
                if self._use_pkexec:
                    _run_pkexec_bash(cmd)
                else:
                    subprocess.run(['bash', '-c', cmd], check=True, capture_output=True)
            else:
                if self._use_pkexec:
                    _run_pkexec_bash(f'firewall-cmd --zone="{zone}" --add-service="{service}"')
                else:
                    _fw('--zone=' + zone, '--add-service=' + service)
            self.invalidate_cache()
            return True
        except PermissionError:
            logger.info(f"Add service {service} cancelled by user")
            return False
        except Exception as e:
            logger.error(f"Failed to add service {service}: {e}")
            return False

    def remove_service(self, zone: str, service: str, permanent: bool = True) -> bool:
        if not self.is_running():
            return False
        try:
            if permanent:
                cmd = f'firewall-cmd --zone="{zone}" --remove-service="{service}" 2>/dev/null; firewall-cmd --permanent --zone="{zone}" --remove-service="{service}"'
                if self._use_pkexec:
                    _run_pkexec_bash(cmd)
                else:
                    subprocess.run(['bash', '-c', cmd], check=True, capture_output=True)
            else:
                if self._use_pkexec:
                    _run_pkexec_bash(f'firewall-cmd --zone="{zone}" --remove-service="{service}"')
                else:
                    _fw('--zone=' + zone, '--remove-service=' + service)
            self.invalidate_cache()
            return True
        except PermissionError:
            logger.info(f"Remove service {service} cancelled by user")
            return False
        except Exception as e:
            logger.error(f"Failed to remove service {service}: {e}")
            return False

    # ── Ports ───────────────────────────────────────────────────────

    def add_port(self, zone: str, port: str, protocol: str = 'tcp', permanent: bool = True) -> bool:
        if not self.is_running():
            return False
        try:
            if permanent:
                cmd = f'firewall-cmd --zone="{zone}" --add-port="{port}/{protocol}" && firewall-cmd --permanent --zone="{zone}" --add-port="{port}/{protocol}"'
                if self._use_pkexec:
                    _run_pkexec_bash(cmd)
                else:
                    subprocess.run(['bash', '-c', cmd], check=True, capture_output=True)
            else:
                if self._use_pkexec:
                    _run_pkexec_bash(f'firewall-cmd --zone="{zone}" --add-port="{port}/{protocol}"')
                else:
                    _fw('--zone=' + zone, f'--add-port={port}/{protocol}')
            self.invalidate_cache()
            return True
        except PermissionError:
            logger.info(f"Add port {port}/{protocol} cancelled by user")
            return False
        except Exception as e:
            logger.error(f"Failed to add port {port}/{protocol}: {e}")
            return False

    def remove_port(self, zone: str, port: str, protocol: str = 'tcp', permanent: bool = True) -> bool:
        if not self.is_running():
            return False
        try:
            if permanent:
                cmd = f'firewall-cmd --zone="{zone}" --remove-port="{port}/{protocol}" 2>/dev/null; firewall-cmd --permanent --zone="{zone}" --remove-port="{port}/{protocol}"'
                if self._use_pkexec:
                    _run_pkexec_bash(cmd)
                else:
                    subprocess.run(['bash', '-c', cmd], check=True, capture_output=True)
            else:
                if self._use_pkexec:
                    _run_pkexec_bash(f'firewall-cmd --zone="{zone}" --remove-port="{port}/{protocol}"')
                else:
                    _fw('--zone=' + zone, f'--remove-port={port}/{protocol}')
            self.invalidate_cache()
            return True
        except PermissionError:
            logger.info(f"Remove port {port}/{protocol} cancelled by user")
            return False
        except Exception as e:
            logger.error(f"Failed to remove port {port}/{protocol}: {e}")
            return False

    # ── Rich Rules ──────────────────────────────────────────────────

    def add_rich_rule(self, zone: str, rule: str, permanent: bool = True) -> bool:
        if not self.is_running():
            return False
        try:
            if permanent:
                cmd = f'firewall-cmd --zone="{zone}" --add-rich-rule=\'{rule}\' && firewall-cmd --permanent --zone="{zone}" --add-rich-rule=\'{rule}\''
                if self._use_pkexec:
                    _run_pkexec_bash(cmd)
                else:
                    subprocess.run(['bash', '-c', cmd], check=True, capture_output=True)
            else:
                if self._use_pkexec:
                    _run_pkexec_bash(f'firewall-cmd --zone="{zone}" --add-rich-rule=\'{rule}\'')
                else:
                    _fw('--zone=' + zone, f'--add-rich-rule={rule}')
            self.invalidate_cache()
            return True
        except PermissionError:
            logger.info("Add rich rule cancelled by user")
            return False
        except Exception as e:
            logger.error(f"Failed to add rich rule: {e}")
            return False

    def remove_rich_rule(self, zone: str, rule: str, permanent: bool = True) -> bool:
        if not self.is_running():
            return False
        try:
            if permanent:
                cmd = f'firewall-cmd --zone="{zone}" --remove-rich-rule=\'{rule}\' 2>/dev/null; firewall-cmd --permanent --zone="{zone}" --remove-rich-rule=\'{rule}\''
                if self._use_pkexec:
                    _run_pkexec_bash(cmd)
                else:
                    subprocess.run(['bash', '-c', cmd], check=True, capture_output=True)
            else:
                if self._use_pkexec:
                    _run_pkexec_bash(f'firewall-cmd --zone="{zone}" --remove-rich-rule=\'{rule}\'')
                else:
                    _fw('--zone=' + zone, f'--remove-rich-rule={rule}')
            self.invalidate_cache()
            return True
        except PermissionError:
            logger.info("Remove rich rule cancelled by user")
            return False
        except Exception as e:
            logger.error(f"Failed to remove rich rule: {e}")
            return False

    # ── IP Blocking ─────────────────────────────────────────────────

    def block_ip(self, ip: str, zone: str = None) -> bool:
        """Block an IP address (both inbound and outbound) and terminate active sockets."""
        try:
            ipaddress.ip_address(ip)  # Validate
        except ValueError:
            try:
                ipaddress.ip_network(ip, strict=False)  # Also allow CIDR
            except ValueError:
                logger.error(f"Invalid IP/CIDR: {ip}")
                return False

        target_zone = zone or self.get_default_zone()
        commands = [
            f'ss -K dst {ip} 2>/dev/null || true',
            f'firewall-cmd --zone="{target_zone}" --add-rich-rule=\'rule family="ipv4" source address="{ip}" reject\' 2>/dev/null || true',
            f'firewall-cmd --permanent --zone="{target_zone}" --add-rich-rule=\'rule family="ipv4" source address="{ip}" reject\' 2>/dev/null || true',
            f'firewall-cmd --zone="{target_zone}" --add-rich-rule=\'rule family="ipv4" destination address="{ip}" reject\' 2>/dev/null || true',
            f'firewall-cmd --permanent --zone="{target_zone}" --add-rich-rule=\'rule family="ipv4" destination address="{ip}" reject\' 2>/dev/null || true',
            f'firewall-cmd --direct --add-rule ipv4 filter OUTPUT 0 -d {ip} -j REJECT 2>/dev/null || true',
            f'firewall-cmd --direct --add-rule ipv4 filter INPUT 0 -s {ip} -j REJECT 2>/dev/null || true',
            'firewall-cmd --reload 2>/dev/null || true'
        ]
        ok, _ = self.execute_batch(commands)
        return ok

    def unblock_ip(self, ip: str, zone: str = None) -> bool:
        target_zone = zone or self.get_default_zone()
        commands = [
            f'firewall-cmd --zone="{target_zone}" --remove-rich-rule=\'rule family="ipv4" source address="{ip}" reject\' 2>/dev/null || true',
            f'firewall-cmd --permanent --zone="{target_zone}" --remove-rich-rule=\'rule family="ipv4" source address="{ip}" reject\' 2>/dev/null || true',
            f'firewall-cmd --zone="{target_zone}" --remove-rich-rule=\'rule family="ipv4" destination address="{ip}" reject\' 2>/dev/null || true',
            f'firewall-cmd --permanent --zone="{target_zone}" --remove-rich-rule=\'rule family="ipv4" destination address="{ip}" reject\' 2>/dev/null || true',
            f'firewall-cmd --direct --remove-rule ipv4 filter OUTPUT 0 -d {ip} -j REJECT 2>/dev/null || true',
            f'firewall-cmd --direct --remove-rule ipv4 filter INPUT 0 -s {ip} -j REJECT 2>/dev/null || true',
            'firewall-cmd --reload 2>/dev/null || true'
        ]
        ok, _ = self.execute_batch(commands)
        return ok

    def get_blocked_ips(self, zone: str = None) -> list[str]:
        """Get list of blocked IPs from rich rules."""
        target_zone = zone or self.get_default_zone()
        settings = self.get_zone_settings(target_zone)
        blocked = set()
        pattern_src = re.compile(r'source address="([^"]+)".*(?:reject|drop)')
        pattern_dst = re.compile(r'destination address="([^"]+)".*(?:reject|drop)')
        for rule in settings.get('rich_rules', []):
            m = pattern_src.search(rule) or pattern_dst.search(rule)
            if m:
                blocked.add(m.group(1))
        return sorted(list(blocked))

    # ── Application Control ─────────────────────────────────────────

    def block_application(self, app_name: str, pids: list[int] = None, remote_ips: list[str] = None, local_ports: list[int] = None) -> tuple[bool, str]:
        """Completely sever connections and block an application across all network layers."""
        zone = self.get_default_zone()
        commands = []
        app_clean = app_name.lower().strip()
        defn = _match_app_definition(app_name)

        # 1. Kill active sockets immediately using ss -K
        if remote_ips:
            for ip in remote_ips:
                commands.append(f'ss -K dst {ip} 2>/dev/null || true')
        if local_ports:
            for lp in local_ports:
                commands.append(f'ss -K sport = :{lp} 2>/dev/null || true')

        # 2. Known service daemons & ports
        services_to_remove = []
        ports_to_reject = []
        flatpak_ids = []

        if defn:
            services_to_remove.extend(defn.get('services', []))
            ports_to_reject.extend(defn.get('ports', []))
            flatpak_ids.extend(defn.get('flatpak_ids', []))

        # Check installed flatpaks dynamically
        installed_flatpaks = get_installed_flatpaks()
        if app_clean in installed_flatpaks:
            fid = installed_flatpaks[app_clean]
            if fid not in flatpak_ids:
                flatpak_ids.append(fid)

        # Apply flatpak network isolation
        for fid in flatpak_ids:
            try:
                subprocess.run(['flatpak', 'override', '--user', '--unshare=network', fid], capture_output=True, timeout=2.0)
            except Exception:
                pass
            commands.append(f'flatpak override --system --unshare=network {fid} 2>/dev/null || true')

        # 3. Process cgroup v2 & eBPF IPAddressDeny
        for pid in (pids or []):
            try:
                cg_file = f'/proc/{pid}/cgroup'
                if os.path.exists(cg_file):
                    with open(cg_file, 'r') as f:
                        cg_content = f.read().strip()
                    for line in cg_content.splitlines():
                        parts = line.split(':')
                        if len(parts) >= 3:
                            cg_path = parts[2].strip('/')
                            unit_name = os.path.basename(cg_path)
                            if unit_name and (unit_name.endswith('.scope') or unit_name.endswith('.service')):
                                try:
                                    subprocess.run(['systemctl', '--user', 'set-property', '--runtime', unit_name, 'IPAddressDeny=any'], capture_output=True, timeout=2.0)
                                except Exception:
                                    pass
                                commands.append(f'systemctl set-property --runtime {unit_name} IPAddressDeny=any 2>/dev/null || true')
                            if cg_path:
                                commands.append(f'iptables -I OUTPUT 1 -m cgroup --path "{cg_path}" -j REJECT 2>/dev/null || true')
            except Exception as e:
                logger.debug(f"Error resolving cgroup for pid {pid}: {e}")

        # 4. Remove firewalld services for this app
        for svc in services_to_remove:
            commands.append(f'firewall-cmd --zone="{zone}" --remove-service="{svc}" 2>/dev/null || true')
            commands.append(f'firewall-cmd --permanent --zone="{zone}" --remove-service="{svc}" 2>/dev/null || true')

        # 5. Reject ports
        for port, proto in ports_to_reject:
            commands.append(f'firewall-cmd --zone="{zone}" --add-rich-rule=\'rule port port="{port}" protocol="{proto}" reject\' 2>/dev/null || true')
            commands.append(f'firewall-cmd --permanent --zone="{zone}" --add-rich-rule=\'rule port port="{port}" protocol="{proto}" reject\' 2>/dev/null || true')
            commands.append(f'firewall-cmd --direct --add-rule ipv4 filter OUTPUT 0 -p {proto} --dport {port} -j REJECT 2>/dev/null || true')
            commands.append(f'firewall-cmd --direct --add-rule ipv4 filter INPUT 0 -p {proto} --dport {port} -j REJECT 2>/dev/null || true')
            commands.append(f'ss -K sport = :{port} 2>/dev/null || true')
            commands.append(f'ss -K dport = :{port} 2>/dev/null || true')

        # 6. Reject active remote IPs associated with the app
        for ip in (remote_ips or []):
            commands.append(f'firewall-cmd --zone="{zone}" --add-rich-rule=\'rule family="ipv4" destination address="{ip}" reject\' 2>/dev/null || true')
            commands.append(f'firewall-cmd --permanent --zone="{zone}" --add-rich-rule=\'rule family="ipv4" destination address="{ip}" reject\' 2>/dev/null || true')
            commands.append(f'firewall-cmd --direct --add-rule ipv4 filter OUTPUT 0 -d {ip} -j REJECT 2>/dev/null || true')

        commands.append('firewall-cmd --reload 2>/dev/null || true')
        return self.execute_batch(commands)

    def unblock_application(self, app_name: str, pids: list[int] = None, remote_ips: list[str] = None, local_ports: list[int] = None) -> tuple[bool, str]:
        """Restore network access for a previously blocked application."""
        zone = self.get_default_zone()
        commands = []
        app_clean = app_name.lower().strip()
        defn = _match_app_definition(app_name)

        services_to_restore = []
        ports_to_unblock = []
        flatpak_ids = []

        if defn:
            services_to_restore.extend(defn.get('services', []))
            ports_to_unblock.extend(defn.get('ports', []))
            flatpak_ids.extend(defn.get('flatpak_ids', []))

        installed_flatpaks = get_installed_flatpaks()
        if app_clean in installed_flatpaks:
            fid = installed_flatpaks[app_clean]
            if fid not in flatpak_ids:
                flatpak_ids.append(fid)

        # Restore flatpak network access
        for fid in flatpak_ids:
            try:
                subprocess.run(['flatpak', 'override', '--user', '--share=network', fid], capture_output=True, timeout=2.0)
                subprocess.run(['flatpak', 'override', '--user', '--reset', fid], capture_output=True, timeout=2.0)
            except Exception:
                pass
            commands.append(f'flatpak override --system --share=network {fid} 2>/dev/null || true')
            commands.append(f'flatpak override --system --reset {fid} 2>/dev/null || true')

        # Find running PIDs if none passed
        if not pids:
            pids = []
            try:
                import psutil
                for p in psutil.process_iter(['pid', 'name']):
                    try:
                        pname = (p.info.get('name') or '').lower()
                        if pname and (pname in app_clean or app_clean in pname):
                            pids.append(p.info['pid'])
                    except Exception:
                        pass
            except Exception:
                pass

        # Process cgroup v2 & eBPF IPAddressDeny restoration
        for pid in pids:
            try:
                cg_file = f'/proc/{pid}/cgroup'
                if os.path.exists(cg_file):
                    with open(cg_file, 'r') as f:
                        cg_content = f.read().strip()
                    for line in cg_content.splitlines():
                        parts = line.split(':')
                        if len(parts) >= 3:
                            cg_path = parts[2].strip('/')
                            unit_name = os.path.basename(cg_path)
                            if unit_name and (unit_name.endswith('.scope') or unit_name.endswith('.service')):
                                try:
                                    subprocess.run(['systemctl', '--user', 'set-property', '--runtime', unit_name, 'IPAddressAllow=any', 'IPAddressDeny='], capture_output=True, timeout=2.0)
                                except Exception:
                                    pass
                                commands.append(f'systemctl set-property --runtime {unit_name} IPAddressAllow=any IPAddressDeny= 2>/dev/null || true')
                            if cg_path:
                                commands.append(f'iptables -D OUTPUT -m cgroup --path "{cg_path}" -j REJECT 2>/dev/null || true')
            except Exception as e:
                logger.debug(f"Error clearing cgroup for pid {pid}: {e}")

        # Clean all active/common zones
        zones_to_clean = list(set([zone, 'home', 'work', 'public', 'FedoraWorkstation'] + self.get_zones()))

        # Restore services
        for z in zones_to_clean:
            for svc in services_to_restore:
                commands.append(f'firewall-cmd --zone="{z}" --add-service="{svc}" 2>/dev/null || true')
                commands.append(f'firewall-cmd --permanent --zone="{z}" --add-service="{svc}" 2>/dev/null || true')

        # Remove port rejection rules across all zones
        for z in zones_to_clean:
            for port, proto in ports_to_unblock:
                commands.append(f'firewall-cmd --zone="{z}" --remove-rich-rule=\'rule port port="{port}" protocol="{proto}" reject\' 2>/dev/null || true')
                commands.append(f'firewall-cmd --permanent --zone="{z}" --remove-rich-rule=\'rule port port="{port}" protocol="{proto}" reject\' 2>/dev/null || true')

        for port, proto in ports_to_unblock:
            commands.append(f'firewall-cmd --direct --remove-rule ipv4 filter OUTPUT 0 -p {proto} --dport {port} -j REJECT 2>/dev/null || true')
            commands.append(f'firewall-cmd --direct --remove-rule ipv4 filter INPUT 0 -p {proto} --dport {port} -j REJECT 2>/dev/null || true')

        # Remove remote IP rejection rules across all zones
        for z in zones_to_clean:
            for ip in (remote_ips or []):
                commands.append(f'firewall-cmd --zone="{z}" --remove-rich-rule=\'rule family="ipv4" destination address="{ip}" reject\' 2>/dev/null || true')
                commands.append(f'firewall-cmd --permanent --zone="{z}" --remove-rich-rule=\'rule family="ipv4" destination address="{ip}" reject\' 2>/dev/null || true')

        for ip in (remote_ips or []):
            commands.append(f'firewall-cmd --direct --remove-rule ipv4 filter OUTPUT 0 -d {ip} -j REJECT 2>/dev/null || true')

        # Automatically start/restart service daemons if their sockets were severed
        if 'ssh' in app_clean:
            commands.append('systemctl restart sshd.service 2>/dev/null || systemctl start sshd.service 2>/dev/null || true')
        elif 'samba' in app_clean:
            commands.append('systemctl restart smb.service 2>/dev/null || systemctl start smb.service 2>/dev/null || true')
        elif 'cockpit' in app_clean:
            commands.append('systemctl restart cockpit.service 2>/dev/null || systemctl start cockpit.service 2>/dev/null || true')
        elif 'syncthing' in app_clean:
            commands.append('systemctl restart syncthing@vitorius.service 2>/dev/null || systemctl start syncthing@vitorius.service 2>/dev/null || true')

        # Flush kernel route and DNS caches to prevent negative caching
        commands.append('resolvectl flush-caches 2>/dev/null || true')
        commands.append('ip route flush cache 2>/dev/null || true')

        commands.append('firewall-cmd --reload 2>/dev/null || true')
        return self.execute_batch(commands)

    # ── Rate Limiting ───────────────────────────────────────────────

    def add_rate_limit(self, zone: str, service: str, rate: str = '10/m') -> bool:
        """Add rate limiting for a service (e.g., '10/m' = 10 per minute)."""
        rule = f'rule service name="{service}" accept limit value="{rate}"'
        return self.add_rich_rule(zone, rule)

    # ── Port Forwarding ─────────────────────────────────────────────

    def add_forward_port(self, zone: str, port: str, protocol: str,
                         to_port: str, to_addr: str = '') -> bool:
        try:
            fwd = f'--add-forward-port=port={port}:proto={protocol}:toport={to_port}'
            if to_addr:
                fwd += f':toaddr={to_addr}'
            cmd_fn = _pkexec_fw if self._use_pkexec else _fw
            cmd_fn('--zone=' + zone, fwd, permanent=True)
            self.reload()
            return True
        except Exception as e:
            logger.error(f"Failed to add forward port: {e}")
            return False

    # ── Masquerade (NAT) ────────────────────────────────────────────

    def enable_masquerade(self, zone: str) -> bool:
        if not self.is_running():
            return False
        try:
            cmd = f'firewall-cmd --zone="{zone}" --add-masquerade && firewall-cmd --permanent --zone="{zone}" --add-masquerade'
            if self._use_pkexec:
                _run_pkexec_bash(cmd)
            else:
                subprocess.run(['bash', '-c', cmd], check=True, capture_output=True)
            self.invalidate_cache()
            return True
        except PermissionError:
            logger.info("Enable masquerade cancelled by user")
            return False
        except Exception as e:
            logger.error(f"Failed to enable masquerade: {e}")
            return False

    def disable_masquerade(self, zone: str) -> bool:
        if not self.is_running():
            return False
        try:
            cmd = f'firewall-cmd --zone="{zone}" --remove-masquerade 2>/dev/null; firewall-cmd --permanent --zone="{zone}" --remove-masquerade'
            if self._use_pkexec:
                _run_pkexec_bash(cmd)
            else:
                subprocess.run(['bash', '-c', cmd], check=True, capture_output=True)
            self.invalidate_cache()
            return True
        except PermissionError:
            logger.info("Disable masquerade cancelled by user")
            return False
        except Exception as e:
            logger.error(f"Failed to disable masquerade: {e}")
            return False

    # ── Panic Mode ──────────────────────────────────────────────────

    def get_panic_mode(self, force_refresh: bool = False) -> bool:
        now = time.time()
        if not force_refresh and 'panic_mode' in self._cache and (now - self._cache_time.get('panic_mode', 0)) < 3.0:
            return self._cache['panic_mode']
        if not self.is_running():
            return False
        val = _query_fw('--query-panic')
        self._cache['panic_mode'] = val
        self._cache_time['panic_mode'] = now
        return val


    def set_panic_mode(self, enabled: bool) -> bool:
        """Enable/disable panic mode (drops ALL network traffic when True, restores normal traffic when False)."""
        if not self.is_running():
            return False
        try:
            flag = '--panic-on' if enabled else '--panic-off'
            if self._use_pkexec:
                _run_pkexec_bash(f'firewall-cmd {flag}')
            else:
                _fw(flag)
            self.invalidate_cache()
            self._cache['panic_mode'] = enabled
            self._cache_time['panic_mode'] = time.time()
            return True
        except PermissionError:
            logger.info(f"{'Enable' if enabled else 'Disable'} panic mode cancelled by user")
            return False
        except Exception as e:
            logger.error(f"Failed to {'enable' if enabled else 'disable'} panic mode: {e}")
            return False

    def enable_panic_mode(self) -> bool:
        """Convenience method to enable panic mode (block all traffic)."""
        return self.set_panic_mode(True)

    def disable_panic_mode(self) -> bool:
        """Convenience method to disable panic mode (restore network traffic)."""
        return self.set_panic_mode(False)

    # ── ICMP Blocking ───────────────────────────────────────────────

    def get_icmp_types(self) -> list[str]:
        try:
            return _fw('--get-icmptypes').split()
        except Exception:
            return []

    def add_icmp_block(self, zone: str, icmp_type: str) -> bool:
        if not self.is_running():
            return False
        try:
            cmd = f'firewall-cmd --zone="{zone}" --add-icmp-block="{icmp_type}" && firewall-cmd --permanent --zone="{zone}" --add-icmp-block="{icmp_type}"'
            if self._use_pkexec:
                _run_pkexec_bash(cmd)
            else:
                subprocess.run(['bash', '-c', cmd], check=True, capture_output=True)
            self.invalidate_cache()
            return True
        except PermissionError:
            logger.info("Add ICMP block cancelled by user")
            return False
        except Exception as e:
            logger.error(f"Failed to add ICMP block: {e}")
            return False

    # ── Logging ─────────────────────────────────────────────────────

    def enable_logging(self, zone: str, level: str = 'all') -> bool:
        """Enable logging for denied packets."""
        rule = f'rule log prefix="VitoriusFW_{zone}_DENY " level="warning" limit value="5/m" drop'
        return self.add_rich_rule(zone, rule)

    # ── Reload / Runtime ────────────────────────────────────

    def reload(self) -> bool:
        if not self.is_running():
            return False
        self.invalidate_cache()
        try:
            if self._use_pkexec:
                _run_pkexec_bash('firewall-cmd --reload')
            else:
                _fw('--reload')
            return True
        except PermissionError:
            logger.info("Firewall reload cancelled by user")
            return False
        except Exception as e:
            logger.error(f"Failed to reload: {e}")
            return False

    # ── nftables Direct Access ──────────────────────────────────────

    def nft_list_ruleset(self) -> str:
        """Get the full nftables ruleset (read-only, no pkexec prompt)."""
        try:
            return _run(['nft', 'list', 'ruleset']).stdout
        except Exception:
            return ''

    def nft_list_tables(self) -> list[str]:
        try:
            out = _run(['nft', 'list', 'tables']).stdout
            return [line.strip() for line in out.splitlines() if line.strip()]
        except Exception:
            return []

    # ── Export / Import ─────────────────────────────────────────────

    def export_rules(self, filepath: str) -> bool:
        """Export all zone configurations to a JSON file."""
        try:
            export_data = {
                'version': '1.0',
                'default_zone': self.get_default_zone(),
                'zones': {}
            }
            for zone in self.get_zones():
                export_data['zones'][zone] = self.get_zone_settings(zone)

            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to export rules: {e}")
            return False

    def import_rules(self, filepath: str) -> tuple[bool, str]:
        """Import rules from a JSON file in a single privileged batch. Returns (success, message)."""
        if not self.is_running():
            return False, "firewalld daemon is not running"
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)

            if data.get('version') != '1.0':
                return False, 'Unsupported export version'

            commands = []
            valid_zones = set(self.get_zones())
            for zone_name, zone_data in data.get('zones', {}).items():
                if zone_name not in valid_zones:
                    continue
                for svc in zone_data.get('services', []):
                    commands.append(f'firewall-cmd --permanent --zone="{zone_name}" --add-service="{svc}"')
                for port_info in zone_data.get('ports', []):
                    port = port_info['port']
                    proto = port_info.get('protocol', 'tcp')
                    commands.append(f'firewall-cmd --permanent --zone="{zone_name}" --add-port="{port}/{proto}"')
                for rule in zone_data.get('rich_rules', []):
                    commands.append(f'firewall-cmd --permanent --zone="{zone_name}" --add-rich-rule=\'{rule}\'')

            if commands:
                commands.append('firewall-cmd --reload')
                return self.execute_batch(commands)
            return True, "No rules to import"
        except Exception as e:
            return False, str(e)

    # ── Summary / Statistics ────────────────────────────────────────

    def get_summary(self) -> dict:
        """Get a summary of the current firewall state."""
        now = time.time()
        if 'summary' in self._cache and (now - self._cache_time.get('summary', 0)) < 8.0:
            return dict(self._cache['summary'])

        if not self.is_running():
            summary = {
                'running': False,
                'default_zone': 'public',
                'active_zones': [],
                'total_interfaces': 0,
                'total_services': 0,
                'total_ports': 0,
                'total_rich_rules': 0,
                'panic_mode': False,
                'masquerade': False,
                'blocked_ips': 0,
            }
            self._cache['summary'] = summary
            self._cache_time['summary'] = now
            return summary

        default_zone = self.get_default_zone()
        active_zones = self.get_active_zones()
        zone_settings = self.get_zone_settings(default_zone)

        total_rules = len(zone_settings.get('rich_rules', []))
        total_ports = len(zone_settings.get('ports', []))
        total_services = len(zone_settings.get('services', []))

        pattern = re.compile(r'source address="([^"]+)".*(?:reject|drop)')
        blocked_count = sum(1 for r in zone_settings.get('rich_rules', []) if pattern.search(r))

        summary = {
            'running': self.is_running(),
            'default_zone': default_zone,
            'active_zones': list(active_zones.keys()),
            'total_interfaces': sum(
                len(v.get('interfaces', [])) for v in active_zones.values()
            ),
            'total_services': total_services,
            'total_ports': total_ports,
            'total_rich_rules': total_rules,
            'panic_mode': self.get_panic_mode(),
            'masquerade': zone_settings.get('masquerade', False),
            'blocked_ips': blocked_count,
        }
        self._cache['summary'] = summary
        self._cache_time['summary'] = now
        return summary

