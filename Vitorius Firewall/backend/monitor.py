"""
Vitorius Firewall - Network Monitor
Real-time network connection monitoring using /proc/net and psutil.
"""

import os
import re
import socket
import struct
import time
import threading
import logging
from typing import Optional
from collections import defaultdict

logger = logging.getLogger('vitorius.monitor')

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    logger.warning("psutil not available - some monitoring features will be limited")


def _hex_to_ip(hex_str: str) -> str:
    """Convert hex IP from /proc/net to dotted notation."""
    try:
        addr_long = int(hex_str, 16)
        return socket.inet_ntoa(struct.pack('<L', addr_long))
    except Exception:
        return hex_str


def _hex_to_port(hex_str: str) -> int:
    try:
        return int(hex_str, 16)
    except Exception:
        return 0


# Common port -> service name mapping for display
KNOWN_SERVICES = {
    22: 'SSH', 53: 'DNS', 80: 'HTTP', 443: 'HTTPS', 993: 'IMAPS',
    995: 'POP3S', 587: 'SMTP', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB',
    21: 'FTP', 25: 'SMTP', 110: 'POP3', 143: 'IMAP', 3389: 'RDP',
    5900: 'VNC', 1080: 'SOCKS', 8888: 'Alt-HTTP', 9090: 'Cockpit',
    27015: 'Steam', 25565: 'Minecraft', 6667: 'IRC',
}

TCP_STATES = {
    '01': 'ESTABLISHED', '02': 'SYN_SENT', '03': 'SYN_RECV',
    '04': 'FIN_WAIT1', '05': 'FIN_WAIT2', '06': 'TIME_WAIT',
    '07': 'CLOSE', '08': 'CLOSE_WAIT', '09': 'LAST_ACK',
    '0A': 'LISTEN', '0B': 'CLOSING',
}


class ConnectionInfo:
    """Represents a single network connection."""
    __slots__ = (
        'protocol', 'local_ip', 'local_port', 'remote_ip', 'remote_port',
        'state', 'pid', 'program', 'uid', 'inode', 'service'
    )

    def __init__(self, **kwargs):
        for k in self.__slots__:
            setattr(self, k, kwargs.get(k, ''))
        if not self.service and isinstance(self.remote_port, int):
            self.service = KNOWN_SERVICES.get(self.remote_port, '')
        if not self.service and isinstance(self.local_port, int):
            self.service = KNOWN_SERVICES.get(self.local_port, '')

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__slots__}


class BandwidthTracker:
    """Track bandwidth per interface over time."""

    def __init__(self):
        self._prev_stats: dict = {}
        self._prev_time: float = 0
        self._rates: dict = {}

    def update(self) -> dict:
        """Read /proc/net/dev and calculate rates. Returns {iface: {rx_bytes_sec, tx_bytes_sec, rx_total, tx_total}}."""
        current_time = time.time()
        current_stats = {}

        try:
            with open('/proc/net/dev', 'r') as f:
                lines = f.readlines()[2:]  # Skip headers

            for line in lines:
                parts = line.strip().split()
                if len(parts) < 10:
                    continue
                iface = parts[0].rstrip(':')
                if iface == 'lo':
                    continue
                rx_bytes = int(parts[1])
                tx_bytes = int(parts[9])
                current_stats[iface] = {'rx_total': rx_bytes, 'tx_total': tx_bytes}
        except Exception as e:
            logger.error(f"Error reading /proc/net/dev: {e}")
            return self._rates

        if self._prev_stats and self._prev_time:
            dt = current_time - self._prev_time
            if dt > 0:
                for iface, stats in current_stats.items():
                    prev = self._prev_stats.get(iface, {})
                    rx_rate = (stats['rx_total'] - prev.get('rx_total', stats['rx_total'])) / dt
                    tx_rate = (stats['tx_total'] - prev.get('tx_total', stats['tx_total'])) / dt
                    self._rates[iface] = {
                        'rx_bytes_sec': max(0, rx_rate),
                        'tx_bytes_sec': max(0, tx_rate),
                        'rx_total': stats['rx_total'],
                        'tx_total': stats['tx_total'],
                    }

        self._prev_stats = current_stats
        self._prev_time = current_time
        return self._rates


class NetworkMonitor:
    """Real-time network monitoring engine."""

    def __init__(self):
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._connections: list[ConnectionInfo] = []
        self._bandwidth = BandwidthTracker()
        self._lock = threading.Lock()
        self._callbacks: list = []
        self._refresh_interval = 2.0  # seconds
        self._pid_name_cache: dict = {}
        self._inode_to_pid: dict = {}
        self._pid_to_name: dict = {}
        self._connection_history: list[dict] = []
        self._max_history = 1000

    @property
    def refresh_interval(self):
        return self._refresh_interval

    @refresh_interval.setter
    def refresh_interval(self, value):
        self._refresh_interval = max(0.5, value)

    def add_callback(self, callback):
        """Add a callback function called on each update cycle."""
        self._callbacks.append(callback)

    def remove_callback(self, callback):
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    def get_cached_connections(self) -> list[ConnectionInfo]:
        """Ultra-fast lock-free read of latest background connections snapshot."""
        with self._lock:
            return list(self._connections)

    # ── Process Mapping ─────────────────────────────────────────────

    def _build_inode_map(self):
        """Map socket inodes to PIDs by scanning /proc/*/fd/ (fallback only)."""
        inode_map = {}
        pid_names = {}
        try:
            for pid_dir in os.listdir('/proc'):
                if not pid_dir.isdigit():
                    continue
                pid = int(pid_dir)
                # Get process name
                if pid in self._pid_name_cache:
                    pid_names[pid] = self._pid_name_cache[pid]
                else:
                    try:
                        with open(f'/proc/{pid}/comm', 'r') as f:
                            name = f.read().strip()
                            self._pid_name_cache[pid] = name
                            pid_names[pid] = name
                    except (PermissionError, FileNotFoundError):
                        pid_names[pid] = '?'
                # Map fd -> inode
                fd_dir = f'/proc/{pid}/fd'
                try:
                    for fd in os.listdir(fd_dir):
                        try:
                            link = os.readlink(f'{fd_dir}/{fd}')
                            if link.startswith('socket:['):
                                inode = link[8:-1]
                                inode_map[inode] = pid
                        except (PermissionError, FileNotFoundError, OSError):
                            pass
                except (PermissionError, FileNotFoundError):
                    pass
        except Exception as e:
            logger.debug(f"Error building inode map: {e}")

        self._inode_to_pid = inode_map
        self._pid_to_name = pid_names

    # ── Connection Reading ──────────────────────────────────────────

    def _read_proc_net(self, proto: str) -> list[ConnectionInfo]:
        """Read /proc/net/tcp or /proc/net/udp."""
        connections = []
        path = f'/proc/net/{proto}'
        try:
            with open(path, 'r') as f:
                lines = f.readlines()[1:]  # Skip header

            for line in lines:
                parts = line.strip().split()
                if len(parts) < 10:
                    continue

                local = parts[1].split(':')
                remote = parts[2].split(':')
                state_hex = parts[3]
                inode = parts[9]

                local_ip = _hex_to_ip(local[0])
                local_port = _hex_to_port(local[1])
                remote_ip = _hex_to_ip(remote[0])
                remote_port = _hex_to_port(remote[1])
                state = TCP_STATES.get(state_hex, state_hex) if proto == 'tcp' else 'ACTIVE'

                pid = self._inode_to_pid.get(inode, 0)
                program = self._pid_to_name.get(pid, '') if pid else ''

                conn = ConnectionInfo(
                    protocol=proto.upper(),
                    local_ip=local_ip,
                    local_port=local_port,
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    state=state,
                    pid=pid,
                    program=program,
                    inode=inode,
                )
                connections.append(conn)
        except Exception as e:
            logger.error(f"Error reading {path}: {e}")

        return connections

    def get_connections(self, include_listening: bool = True) -> list[ConnectionInfo]:
        """Get current network connections."""
        self._build_inode_map()
        connections = []
        connections.extend(self._read_proc_net('tcp'))
        connections.extend(self._read_proc_net('udp'))

        if not include_listening:
            connections = [c for c in connections if c.state != 'LISTEN']

        with self._lock:
            self._connections = connections
        return connections

    def get_connections_psutil(self) -> list[ConnectionInfo]:
        """Get connections via psutil (with PID process name caching)."""
        if not HAS_PSUTIL:
            return self.get_connections()

        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if not conn.laddr:
                    continue
                remote_ip = conn.raddr.ip if conn.raddr else '0.0.0.0'
                remote_port = conn.raddr.port if conn.raddr else 0
                program = ''
                if conn.pid:
                    if conn.pid in self._pid_name_cache:
                        program = self._pid_name_cache[conn.pid]
                    else:
                        try:
                            program = psutil.Process(conn.pid).name()
                            self._pid_name_cache[conn.pid] = program
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            program = '?'

                info = ConnectionInfo(
                    protocol='TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                    local_ip=conn.laddr.ip,
                    local_port=conn.laddr.port,
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    state=conn.status if hasattr(conn, 'status') else 'ACTIVE',
                    pid=conn.pid or 0,
                    program=program,
                )
                connections.append(info)
        except (psutil.AccessDenied, PermissionError):
            return self.get_connections()

        with self._lock:
            self._connections = connections
        return connections


    # ── Interfaces ──────────────────────────────────────────────────

    def get_interfaces(self) -> list[dict]:
        """Get network interface information."""
        interfaces = []
        if HAS_PSUTIL:
            try:
                addrs = psutil.net_if_addrs()
                stats = psutil.net_if_stats()
                for iface, addr_list in addrs.items():
                    if iface == 'lo':
                        continue
                    info = {
                        'name': iface,
                        'is_up': stats.get(iface, None) and stats[iface].isup,
                        'speed': stats.get(iface, None) and stats[iface].speed or 0,
                        'addresses': [],
                    }
                    for addr in addr_list:
                        if addr.family == socket.AF_INET:
                            info['addresses'].append({
                                'type': 'IPv4', 'address': addr.address,
                                'netmask': addr.netmask,
                            })
                        elif addr.family == socket.AF_INET6:
                            info['addresses'].append({
                                'type': 'IPv6', 'address': addr.address,
                            })
                    interfaces.append(info)
            except Exception as e:
                logger.error(f"Error getting interfaces: {e}")
        else:
            # Fallback: parse /proc/net/dev
            try:
                with open('/proc/net/dev') as f:
                    for line in f.readlines()[2:]:
                        parts = line.strip().split()
                        iface = parts[0].rstrip(':')
                        if iface != 'lo':
                            interfaces.append({
                                'name': iface, 'is_up': True,
                                'speed': 0, 'addresses': [],
                            })
            except Exception:
                pass

        return interfaces

    # ── Bandwidth ───────────────────────────────────────────────────

    def get_bandwidth(self) -> dict:
        """Get current bandwidth rates per interface."""
        return self._bandwidth.update()

    # ── Statistics ──────────────────────────────────────────────────

    def get_connection_stats(self) -> dict:
        """Get connection statistics."""
        with self._lock:
            conns = list(self._connections)

        stats = {
            'total': len(conns),
            'established': 0,
            'listening': 0,
            'time_wait': 0,
            'close_wait': 0,
            'other': 0,
            'by_protocol': defaultdict(int),
            'by_program': defaultdict(int),
            'unique_remote_ips': set(),
        }

        for c in conns:
            stats['by_protocol'][c.protocol] += 1
            if c.program:
                stats['by_program'][c.program] += 1
            if c.remote_ip and c.remote_ip != '0.0.0.0':
                stats['unique_remote_ips'].add(c.remote_ip)

            if c.state == 'ESTABLISHED':
                stats['established'] += 1
            elif c.state == 'LISTEN':
                stats['listening'] += 1
            elif c.state == 'TIME_WAIT':
                stats['time_wait'] += 1
            elif c.state == 'CLOSE_WAIT':
                stats['close_wait'] += 1
            else:
                stats['other'] += 1

        stats['unique_remote_ips'] = len(stats['unique_remote_ips'])
        stats['by_protocol'] = dict(stats['by_protocol'])
        stats['by_program'] = dict(stats['by_program'])
        return stats

    # ── Background Monitoring ───────────────────────────────────────

    def start(self):
        """Start background monitoring thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info("Network monitor started")

    def stop(self):
        """Stop background monitoring."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        logger.info("Network monitor stopped")

    def _monitor_loop(self):
        while self._running:
            try:
                if HAS_PSUTIL:
                    self.get_connections_psutil()
                else:
                    self.get_connections()
                self._bandwidth.update()

                for cb in self._callbacks:
                    try:
                        cb()
                    except Exception as e:
                        logger.error(f"Monitor callback error: {e}")
            except Exception as e:
                logger.error(f"Monitor loop error: {e}")

            time.sleep(self._refresh_interval)

    def format_bytes(self, b: float) -> str:
        """Format bytes to human-readable string."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if abs(b) < 1024:
                return f"{b:.1f} {unit}"
            b /= 1024
        return f"{b:.1f} PB"
