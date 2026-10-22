"""
Alert & Desktop Notification Engine for PacketSentinel.
Provides:
- Per-indicator cooldown suppression & global token-bucket rate limiting (OWASP #13)
- Injection-proof Windows 10/11 WinRT Toast Notifications (static script + env vars + CreateTextNode, OWASP #3, #15)
- Structured JSONL rotating security audit logs (OWASP #9, #18)
"""

from __future__ import annotations

import base64
import json
import logging
import os
import subprocess
import sys
import threading
import time
from collections import OrderedDict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Deque, Optional

from .config import AppConfig
from .process_mapper import ProcessInfo
from .security import sanitize_display_text, sanitize_for_notification
from .threat_intel import ThreatMatch


# Static, immutable PowerShell script for Windows 10/11 WinRT Toast Notifications.
# Reads alert fields strictly from environment variables and uses DOM CreateTextNode()
# so command injection and XML markup injection are impossible (OWASP #3, #15).
_STATIC_WINRT_TOAST_PS1 = r"""
$ErrorActionPreference = 'SilentlyContinue'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

$template = [Windows.UI.Notifications.ToastTemplateType]::ToastText04
$xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($template)
$textNodes = $xml.GetElementsByTagName("text")

if ($textNodes.Count -ge 1) {
    $null = $textNodes.Item(0).AppendChild($xml.CreateTextNode([string]$env:PS_ALERT_TITLE))
}
if ($textNodes.Count -ge 2) {
    $null = $textNodes.Item(1).AppendChild($xml.CreateTextNode([string]$env:PS_ALERT_LINE1))
}
if ($textNodes.Count -ge 3) {
    $null = $textNodes.Item(2).AppendChild($xml.CreateTextNode([string]$env:PS_ALERT_LINE2))
}

$appId = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"
$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($toast)
"""

_ENCODED_TOAST_CMD = base64.b64encode(_STATIC_WINRT_TOAST_PS1.encode("utf-16le")).decode("ascii")


@dataclass(frozen=True)
class SecurityAlert:
    """Structured security alert record."""

    timestamp_utc: str
    indicator: str
    matched_rule: str
    source_feed: str
    match_type: str
    protocol: str
    dst_ip: str
    dst_port: int
    process_name: str
    process_pid: int
    process_exe: str
    detection_layer: str


class AlertNotifier:
    """
    Dispatches rate-limited desktop notifications, console alerts, and rotating JSONL audit logs.
    """

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._lock = threading.RLock()
        self._cooldown_map: OrderedDict[str, float] = OrderedDict()
        self._recent_alert_timestamps: Deque[float] = deque()
        self._total_alerts_emitted: int = 0
        self._total_alerts_suppressed: int = 0
        self._audit_logger = self._setup_audit_logger(config.log_dir / "alerts.jsonl")
        self._powershell_path = self._find_verified_powershell()

    @staticmethod
    def _setup_audit_logger(log_file: Path) -> logging.Logger:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        audit_logger = logging.getLogger(f"packetsentinel.audit.{id(log_file)}")
        audit_logger.setLevel(logging.INFO)
        audit_logger.propagate = False
        if not audit_logger.handlers:
            # Max 5 MB per file, keep 3 rotated backups -> max 20 MB disk usage (OWASP #18)
            handler = RotatingFileHandler(
                filename=str(log_file),
                maxBytes=5 * 1024 * 1024,
                backupCount=3,
                encoding="utf-8",
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            audit_logger.addHandler(handler)
        return audit_logger

    @staticmethod
    def _find_verified_powershell() -> Optional[str]:
        """Resolve canonical System32 PowerShell path to prevent binary planting (OWASP #22)."""
        sys_root = os.environ.get("SystemRoot", r"C:\Windows")
        candidate = Path(sys_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        if candidate.is_file():
            return str(candidate)
        return None

    @property
    def total_alerts_emitted(self) -> int:
        with self._lock:
            return self._total_alerts_emitted

    @property
    def total_alerts_suppressed(self) -> int:
        with self._lock:
            return self._total_alerts_suppressed

    def close(self) -> None:
        """Close audit log file handlers cleanly."""
        for h in list(self._audit_logger.handlers):
            try:
                h.close()
                self._audit_logger.removeHandler(h)
            except Exception:
                pass

    def _should_emit_alert_locked(self, indicator_key: str) -> bool:
        """
        Enforce per-indicator cooldown and global per-minute rate limit (OWASP #13, #49).
        """
        now = time.monotonic()

        # 1. Per-indicator cooldown check
        last_seen = self._cooldown_map.get(indicator_key)
        if last_seen is not None and (now - last_seen) < self._config.alert_cooldown_seconds:
            self._total_alerts_suppressed += 1
            return False

        # 2. Global token-bucket rate limit (sliding 60-second window)
        while self._recent_alert_timestamps and (now - self._recent_alert_timestamps[0]) > 60.0:
            self._recent_alert_timestamps.popleft()

        if len(self._recent_alert_timestamps) >= self._config.max_alerts_per_minute:
            self._total_alerts_suppressed += 1
            return False

        # Record emission and bound cooldown cache size (max 4,096 keys)
        self._cooldown_map[indicator_key] = now
        self._cooldown_map.move_to_end(indicator_key)
        while len(self._cooldown_map) > 4096:
            self._cooldown_map.popitem(last=False)

        self._recent_alert_timestamps.append(now)
        self._total_alerts_emitted += 1
        return True

    def notify_match(
        self,
        match: ThreatMatch,
        process: ProcessInfo,
        protocol: str = "UDP/DNS",
        dst_ip: str = "",
        dst_port: int = 53,
        detection_layer: str = "tshark-wire",
        bypass_cooldown: bool = False,
    ) -> Optional[SecurityAlert]:
        """
        Evaluate cooldowns, log structured JSONL alert, print console warning,
        and dispatch a Windows Toast Notification.
        """
        if process.is_self:
            return None

        indicator_clean = sanitize_display_text(match.indicator, max_len=253)
        cooldown_key = f"{indicator_clean}|{process.name}"

        with self._lock:
            if not bypass_cooldown and not self._should_emit_alert_locked(cooldown_key):
                return None

        alert = SecurityAlert(
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            indicator=indicator_clean,
            matched_rule=sanitize_display_text(match.matched_rule, max_len=253),
            source_feed=sanitize_display_text(match.source_feed, max_len=120),
            match_type=sanitize_display_text(match.match_type, max_len=40),
            protocol=sanitize_display_text(protocol, max_len=20),
            dst_ip=sanitize_display_text(dst_ip, max_len=64),
            dst_port=int(dst_port) if dst_port else 0,
            process_name=sanitize_display_text(process.name, max_len=80),
            process_pid=int(process.pid),
            process_exe=sanitize_display_text(process.exe, max_len=240),
            detection_layer=sanitize_display_text(detection_layer, max_len=40),
        )

        try:
            self._audit_logger.info(json.dumps(asdict(alert), ensure_ascii=True))
        except Exception:
            pass

        self._print_console_alert(alert)

        if self._config.enable_desktop_toast and sys.platform == "win32":
            threading.Thread(
                target=self._send_windows_toast_safe,
                args=(alert,),
                daemon=True,
            ).start()

        return alert

    @staticmethod
    def _print_console_alert(alert: SecurityAlert) -> None:
        proc_str = f"{alert.process_name} (PID {alert.process_pid})" if alert.process_pid > 0 else alert.process_name
        dst_str = f"{alert.dst_ip}:{alert.dst_port}" if alert.dst_ip else f"port {alert.dst_port}"
        banner = (
            f"\n[!] SUSPICIOUS PACKET DETECTED [{alert.timestamp_utc}]\n"
            f"    Destination : {alert.indicator} (matched rule: {alert.matched_rule})\n"
            f"    Threat Feed : {alert.source_feed}\n"
            f"    Process     : {proc_str}\n"
            f"    Connection  : {alert.protocol} -> {dst_str} [{alert.detection_layer}]\n"
        )
        sys.stdout.write(banner)
        sys.stdout.flush()

    def _send_windows_toast_safe(self, alert: SecurityAlert) -> None:
        """
        Invoke Windows 10/11 WinRT Toast Notification using a static encoded script
        and sanitized environment variables (shell=False, CREATE_NO_WINDOW).
        """
        if not self._powershell_path:
            return

        proc_str = (
            f"{alert.process_name} (PID {alert.process_pid})"
            if alert.process_pid > 0
            else alert.process_name
        )
        env = os.environ.copy()
        env["PS_ALERT_TITLE"] = sanitize_for_notification(
            f"PacketSentinel: Sketchy {alert.protocol} Blocked/Detected", max_len=90
        )
        env["PS_ALERT_LINE1"] = sanitize_for_notification(
            f"Target: {alert.indicator} ({alert.source_feed})", max_len=140
        )
        env["PS_ALERT_LINE2"] = sanitize_for_notification(
            f"Sent by: {proc_str}", max_len=140
        )

        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        try:
            subprocess.run(
                [
                    self._powershell_path,
                    "-NoProfile",
                    "-NonInteractive",
                    "-WindowStyle",
                    "Hidden",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-EncodedCommand",
                    _ENCODED_TOAST_CMD,
                ],
                env=env,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=6.0,
                creationflags=creationflags,
                check=False,
            )
        except Exception:
            pass
