"""
Process Attribution Mapper for PacketSentinel.
Maps local source ports and outbound socket tuples to the originating Windows process
(PID, executable name, and path) using psutil with bounded caching and PID-reuse checks.
"""

from __future__ import annotations

import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

import psutil

from .security import sanitize_display_text


@dataclass(frozen=True)
class ProcessInfo:
    """Sanitized process metadata associated with a network packet or socket."""

    pid: int
    name: str
    exe: str
    is_self: bool = False

    def format_short(self) -> str:
        if self.pid <= 0:
            return "Unknown Process"
        return f"{self.name} (PID {self.pid})"


UNKNOWN_PROCESS = ProcessInfo(pid=0, name="System/Unknown", exe="", is_self=False)


class ProcessMapper:
    """
    Thread-safe socket-to-process resolver with rate-limited table refreshes
    and bounded LRU caching (OWASP #40, #49).
    """

    def __init__(self, refresh_min_interval: float = 1.0, max_cache_size: int = 2048) -> None:
        self._self_pid = os.getpid()
        self._lock = threading.RLock()
        self._refresh_min_interval = refresh_min_interval
        self._last_refresh_ts = 0.0
        self._max_cache_size = max_cache_size

        # Port caches: (proto, local_port) -> ProcessInfo
        self._port_map: OrderedDict[Tuple[str, int], ProcessInfo] = OrderedDict()
        # Remote IP cache: remote_ip -> ProcessInfo
        self._remote_ip_map: OrderedDict[str, ProcessInfo] = OrderedDict()
        # PID metadata cache: (pid, create_time_int) -> ProcessInfo
        self._pid_cache: OrderedDict[Tuple[int, int], ProcessInfo] = OrderedDict()
        # Outbound connection snapshot cache to eliminate continuous psutil socket polling
        self._cached_outbound_conns: list[Tuple[str, int, str, int, ProcessInfo]] = []
        self._last_outbound_refresh_ts = 0.0

    def _resolve_pid(self, pid: Optional[int]) -> ProcessInfo:
        if not pid or pid <= 0:
            return UNKNOWN_PROCESS

        if pid == self._self_pid:
            return ProcessInfo(pid=pid, name="PacketSentinel", exe="", is_self=True)

        try:
            proc = psutil.Process(pid)
            ctime_key = (pid, int(proc.create_time()))
            if ctime_key in self._pid_cache:
                self._pid_cache.move_to_end(ctime_key)
                return self._pid_cache[ctime_key]

            raw_name = proc.name() or f"PID-{pid}"
            try:
                raw_exe = proc.exe() or ""
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                raw_exe = ""

            info = ProcessInfo(
                pid=pid,
                name=sanitize_display_text(raw_name, max_len=80),
                exe=sanitize_display_text(raw_exe, max_len=240),
                is_self=(pid == self._self_pid),
            )
            self._pid_cache[ctime_key] = info
            while len(self._pid_cache) > self._max_cache_size:
                self._pid_cache.popitem(last=False)
            return info
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            return ProcessInfo(pid=pid, name=f"Process (PID {pid})", exe="", is_self=False)

    def _refresh_tables_locked(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and (now - self._last_refresh_ts) < self._refresh_min_interval:
            return
        self._last_refresh_ts = now

        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError, RuntimeError, Exception):
            return

        for conn in conns:
            pid = conn.pid
            if not pid:
                continue
            info = self._resolve_pid(pid)
            proto = "tcp" if conn.type == 1 else "udp"
            if conn.laddr and len(conn.laddr) >= 2:
                lport = int(conn.laddr[1])
                key = (proto, lport)
                self._port_map[key] = info
                self._port_map.move_to_end(key)
                while len(self._port_map) > self._max_cache_size:
                    self._port_map.popitem(last=False)

            if conn.raddr and len(conn.raddr) >= 1:
                rip = str(conn.raddr[0])
                if rip:
                    self._remote_ip_map[rip] = info
                    self._remote_ip_map.move_to_end(rip)
                    while len(self._remote_ip_map) > self._max_cache_size:
                        self._remote_ip_map.popitem(last=False)

    def lookup(
        self,
        protocol: str = "udp",
        local_port: Optional[int] = None,
        remote_ip: Optional[str] = None,
    ) -> ProcessInfo:
        """
        Look up the process responsible for a given local port or remote destination IP.
        Fast in-memory cache check first; rate-limited background refresh on cache misses.
        """
        proto = protocol.lower()
        with self._lock:
            if local_port and local_port > 0:
                key = (proto, int(local_port))
                if key in self._port_map:
                    return self._port_map[key]

            if remote_ip and remote_ip in self._remote_ip_map:
                return self._remote_ip_map[remote_ip]

            # Only refresh active OS sockets if the minimum interval has elapsed
            now = time.monotonic()
            if (now - self._last_refresh_ts) >= self._refresh_min_interval:
                self._refresh_tables_locked(force=False)

                if local_port and local_port > 0:
                    key = (proto, int(local_port))
                    if key in self._port_map:
                        return self._port_map[key]
                    # Also check the other transport protocol in case of fallback
                    alt_key = ("tcp" if proto == "udp" else "udp", int(local_port))
                    if alt_key in self._port_map:
                        return self._port_map[alt_key]

                if remote_ip and remote_ip in self._remote_ip_map:
                    return self._remote_ip_map[remote_ip]

        return UNKNOWN_PROCESS

    def get_active_outbound_connections(self) -> list[Tuple[str, int, str, int, ProcessInfo]]:
        """
        Return a snapshot of active outbound socket tuples:
        (proto, local_port, remote_ip, remote_port, ProcessInfo)
        Cached for 1.0s to avoid hammering psutil.net_connections() in high-frequency loops.
        """
        now = time.monotonic()
        with self._lock:
            if self._cached_outbound_conns and (now - self._last_outbound_refresh_ts) < self._refresh_min_interval:
                return list(self._cached_outbound_conns)

        results: list[Tuple[str, int, str, int, ProcessInfo]] = []
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError, RuntimeError, Exception):
            with self._lock:
                return list(self._cached_outbound_conns)

        with self._lock:
            self._last_outbound_refresh_ts = now
            for conn in conns:
                if not conn.raddr or len(conn.raddr) < 2:
                    continue
                rip = str(conn.raddr[0])
                rport = int(conn.raddr[1])
                lport = int(conn.laddr[1]) if (conn.laddr and len(conn.laddr) >= 2) else 0
                proto = "tcp" if conn.type == 1 else "udp"
                info = self._resolve_pid(conn.pid)
                if info.is_self:
                    continue
                results.append((proto, lport, rip, rport, info))
            self._cached_outbound_conns = results
        return results
