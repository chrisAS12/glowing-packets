"""
Target Process Watchdog & Script Malware Inspector for PacketSentinel.

Provides focused monitoring on a specific target application (by name or PID):
1. Monitors all network sockets (TCP/UDP), DNS lookups, and TLS SNIs for the target.
2. Tracks child process tree lineage to detect if the application spawns background
   script interpreters or LOLBINs (powershell, node, python, cmd, bash, curl, wscript).
3. Evaluates all egress targets against threat feeds and LOTS exfiltration guards.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

import psutil

from .lots_guard import LOTSRiskResult, check_lots_risk
from .process_mapper import ProcessInfo
from .security import sanitize_display_text

logger = logging.getLogger("packetsentinel.watchdog")

SCRIPT_INTERPRETER_BASENAMES: frozenset[str] = frozenset(
    {
        "powershell.exe",
        "pwsh",
        "cmd.exe",
        "bash",
        "sh",
        "zsh",
        "python.exe",
        "python",
        "python3",
        "node.exe",
        "node",
        "wscript.exe",
        "cscript.exe",
        "curl.exe",
        "curl",
        "wget",
        "certutil.exe",
        "bitsadmin.exe",
        "rundll32.exe",
        "mshta.exe",
    }
)


@dataclass(frozen=True)
class ChildProcessEvent:
    """Record of a child script interpreter spawned by the monitored application."""

    timestamp_utc: str
    parent_pid: int
    parent_name: str
    child_pid: int
    child_name: str
    cmdline: str
    is_script_interpreter: bool


@dataclass
class WatchdogTargetStatus:
    """Aggregate live status of the target application being monitored."""

    target_pid: int
    target_name: str
    is_alive: bool
    active_children_count: int
    connections_seen: int = 0
    dns_queries_seen: int = 0
    alerts_triggered: int = 0
    spawned_script_events: List[ChildProcessEvent] = field(default_factory=list)


def find_processes_by_name(process_name: str) -> List[Tuple[int, str, str]]:
    """Search running processes by executable name (case-insensitive substring match)."""
    matches: List[Tuple[int, str, str]] = []
    clean_target = sanitize_display_text(process_name).lower()
    for proc in psutil.process_iter(["pid", "name", "exe"]):
        try:
            name = (proc.info.get("name") or "").lower()
            if clean_target in name:
                exe = proc.info.get("exe") or "unknown"
                matches.append((int(proc.info["pid"]), proc.info["name"], exe))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return matches


def inspect_child_lineage(target_pid: int) -> List[ChildProcessEvent]:
    """Inspect all child processes spawned by target PID and detect script execution."""
    events: List[ChildProcessEvent] = []
    try:
        parent = psutil.Process(target_pid)
        parent_name = parent.name()
        for child in parent.children(recursive=True):
            try:
                child_name = child.name()
                child_base = child_name.lower().replace("\\", "/").rsplit("/", 1)[-1]
                cmdline_parts = child.cmdline() or []
                cmdline_str = sanitize_display_text(" ".join(cmdline_parts), max_len=300)
                is_script = child_base in SCRIPT_INTERPRETER_BASENAMES

                events.append(
                    ChildProcessEvent(
                        timestamp_utc=datetime.now(timezone.utc).isoformat(),
                        parent_pid=target_pid,
                        parent_name=parent_name,
                        child_pid=child.pid,
                        child_name=child_name,
                        cmdline=cmdline_str,
                        is_script_interpreter=is_script,
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return events


def evaluate_target_packet(
    target_pids: Set[int],
    process_pid: int,
    process_name: str,
    domain: Optional[str] = None,
    dst_port: int = 443,
) -> Optional[LOTSRiskResult]:
    """Evaluate if a packet belongs to the monitored process tree and triggers risk."""
    if process_pid not in target_pids:
        return None
    if not domain:
        return None
    return check_lots_risk(process_name, domain, port=dst_port)


def format_watchdog_banner(status: WatchdogTargetStatus) -> str:
    """Format single-line status banner for live terminal display."""
    alive_str = "ALIVE" if status.is_alive else "TERMINATED"
    return (
        f"[WATCHDOG: {status.target_name} (PID {status.target_pid}) | {alive_str}] "
        f"Children: {status.active_children_count} | Connections: {status.connections_seen} | "
        f"DNS: {status.dns_queries_seen} | Script Alerts: {status.alerts_triggered}"
    )
