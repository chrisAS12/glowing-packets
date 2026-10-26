"""
UI-facing wrapper around the real PacketSentinelMonitor capture engine.

Owns monitor lifecycle (start/stop), exposes thread-safe counter snapshots for the
desktop dashboard, and tails the local alerts.jsonl audit log for the alert table.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .capture import PacketSentinelMonitor, find_verified_tshark
from .config import AppConfig
from .egress_guard import engage_runtime_network_lockdown
from .notifier import AlertNotifier
from .process_mapper import ProcessInfo, ProcessMapper
from .threat_intel import ThreatIntelEngine

ALERT_TAIL_BYTES = 64 * 1024
CANARY_DOMAIN = "sketchy-canary.example.com"


@dataclass(frozen=True)
class AlertRow:
    timestamp_utc: str
    indicator: str
    source_feed: str
    process_name: str
    detection_layer: str


@dataclass(frozen=True)
class MonitorSnapshot:
    running: bool
    capture_mode: str
    events_inspected: int
    dns_queries: int
    tls_sni: int
    alerts_emitted: int
    domain_indicators: int
    ip_indicators: int


class LiveMonitorService:
    def __init__(self, config: AppConfig, lock_network_on_start: bool = True) -> None:
        self._config = config
        self._lock_network_on_start = lock_network_on_start
        self._threat_engine = ThreatIntelEngine(config)
        self._notifier = AlertNotifier(config)
        self._monitor = PacketSentinelMonitor(
            config=config,
            threat_engine=self._threat_engine,
            process_mapper=ProcessMapper(),
            notifier=self._notifier,
        )
        self._running = False
        self._feeds_loaded = False
        self._lock = threading.Lock()

    @property
    def alerts_file(self) -> Path:
        return self._config.log_dir / "alerts.jsonl"

    def load_feeds_offline(self) -> Dict[str, int]:
        stats = self._threat_engine.load_or_update_feeds(force_network_update=False, offline_only=True)
        self._feeds_loaded = True
        return stats

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            if not self._feeds_loaded:
                self.load_feeds_offline()
            if self._lock_network_on_start:
                engage_runtime_network_lockdown()
            self._monitor.start()
            self._running = True

    def stop(self) -> None:
        with self._lock:
            self._monitor.stop()
            self._running = False

    def shutdown(self) -> None:
        self.stop()
        self._notifier.close()

    def run_canary_self_test(self) -> None:
        """Push a reserved RFC 2606 test domain through the real detection path."""
        if not self._feeds_loaded:
            self.load_feeds_offline()
        self._monitor.inspect_event(
            domain=CANARY_DOMAIN,
            protocol="UDP/DNS",
            detection_layer="ui-self-test",
            explicit_process=ProcessInfo(
                pid=os.getpid(), name="sentinelwire-self-test", exe=sys.executable, is_self=False
            ),
        )

    def snapshot(self) -> MonitorSnapshot:
        mode = "Wireshark tshark wire capture" if find_verified_tshark() else "Socket + DNS-cache polling"
        return MonitorSnapshot(
            running=self._running,
            capture_mode=mode,
            events_inspected=self._monitor.packets_inspected,
            dns_queries=self._monitor.dns_queries_seen,
            tls_sni=self._monitor.tls_sni_seen,
            alerts_emitted=self._notifier.total_alerts_emitted,
            domain_indicators=self._threat_engine.domain_count,
            ip_indicators=self._threat_engine.ip_count,
        )

    def recent_alerts(self, limit: int = 50) -> List[AlertRow]:
        return read_recent_alerts(self.alerts_file, limit)


def read_recent_alerts(alerts_file: Path, limit: int = 50) -> List[AlertRow]:
    """Return the newest alerts first, reading at most ALERT_TAIL_BYTES from disk."""
    if not alerts_file.exists():
        return []
    with open(alerts_file, "rb") as handle:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        handle.seek(max(0, size - ALERT_TAIL_BYTES))
        tail = handle.read().decode("utf-8", errors="replace")

    rows: List[AlertRow] = []
    for line in reversed(tail.splitlines()):
        parsed = _parse_alert_line(line)
        if parsed is not None:
            rows.append(parsed)
        if len(rows) >= limit:
            break
    return rows


def _parse_alert_line(line: str) -> Optional[AlertRow]:
    try:
        record = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(record, dict):
        return None
    fields: Tuple[str, ...] = ("timestamp_utc", "indicator", "source_feed", "process_name", "detection_layer")
    return AlertRow(**{name: str(record.get(name, ""))[:200] for name in fields})
