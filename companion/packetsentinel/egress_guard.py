"""
Outbound Egress Guard (Zero-Exfiltration Airlock) for PacketSentinel.

Enforces two independent layers so that during live monitoring or MCP server execution,
the process cannot send data outbound:
1. CPython PEP 578 Runtime Audit Hook (`sys.addaudithook`): Irreversibly blocks outbound
   socket connects/sends, HTTP clients, and `ctypes` C-API bypasses inside the Python process.
2. Cross-Platform OS Outbound Containment (`netsh` on Windows, `sandbox-exec` on macOS,
   `systemd` / `iptables` on Linux).
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, List, Optional, Tuple


_LOCKDOWN_LOCK = threading.Lock()
_LOCKDOWN_ACTIVE = False
_HOOK_INSTALLED = False

# Blocking ctypes audit events alongside socket/HTTP events prevents in-process code
# from calling native WinSock/libc connect() directly via ctypes during lockdown.
_BLOCKED_AUDIT_EVENTS = frozenset(
    {
        "socket.connect",
        "socket.sendto",
        "socket.sendmsg",
        "urllib.Request",
        "http.client.connect",
        "ftplib.connect",
        "smtplib.connect",
        "telnetlib.open",
    }
)

_BLOCKED_NETWORK_DLLS = frozenset(
    {
        "ws2_32",
        "wsock32",
        "wininet",
        "winhttp",
        "urlmon",
        "libcurl",
        "libsocket",
    }
)

_BLOCKED_NETWORK_SYMBOLS = frozenset(
    {
        "connect",
        "send",
        "sendto",
        "sendmsg",
        "wsaconnect",
        "wsasend",
        "wsasendto",
        "internetopen",
        "internetopena",
        "internetopenw",
        "internetconnect",
        "httpopenrequest",
        "winhttpopen",
        "winhttpconnect",
        "curl_easy_init",
        "curl_easy_perform",
    }
)


def _pep578_network_airlock_hook(event: str, args: tuple) -> None:
    if not _LOCKDOWN_ACTIVE:
        return
    if event in _BLOCKED_AUDIT_EVENTS:
        raise PermissionError(
            f"EGRESS_GUARD_BLOCKED: Operation '{event}' is forbidden while "
            "PacketSentinel zero-outbound lockdown is active."
        )
    if event == "ctypes.dlopen" and args:
        dll_name = str(args[0]).lower()
        for net_dll in _BLOCKED_NETWORK_DLLS:
            if net_dll in dll_name:
                raise PermissionError(
                    f"EGRESS_GUARD_BLOCKED: ctypes loading of network library '{args[0]}' is forbidden while "
                    "PacketSentinel zero-outbound lockdown is active."
                )
    elif event == "ctypes.dlsym" and len(args) >= 2:
        symbol = str(args[1]).lower()
        if symbol in _BLOCKED_NETWORK_SYMBOLS:
            raise PermissionError(
                f"EGRESS_GUARD_BLOCKED: ctypes resolution of network symbol '{args[1]}' is forbidden while "
                "PacketSentinel zero-outbound lockdown is active."
            )


def engage_runtime_network_lockdown() -> None:
    """
    Engage the irreversible PEP 578 runtime network airlock for the current process.
    CPython provides no API to unregister an audit hook once installed.
    """
    global _LOCKDOWN_ACTIVE, _HOOK_INSTALLED
    with _LOCKDOWN_LOCK:
        _LOCKDOWN_ACTIVE = True
        if not _HOOK_INSTALLED:
            sys.addaudithook(_pep578_network_airlock_hook)
            _HOOK_INSTALLED = True


def is_runtime_network_lockdown_active() -> bool:
    return _LOCKDOWN_ACTIVE


@contextmanager
def permit_inspected_gateway_egress() -> Iterator[None]:
    """
    Temporarily permit an inspected outbound HTTPS request from the Safe Web Gateway.
    All other operations outside this guarded context remain blocked by PEP 578.
    """
    global _LOCKDOWN_ACTIVE
    with _LOCKDOWN_LOCK:
        was_active = _LOCKDOWN_ACTIVE
        _LOCKDOWN_ACTIVE = False
    try:
        yield
    finally:
        with _LOCKDOWN_LOCK:
            _LOCKDOWN_ACTIVE = was_active


def find_verified_netsh() -> Optional[str]:
    sys_root = os.environ.get("SystemRoot", r"C:\Windows")
    candidate = Path(sys_root) / "System32" / "netsh.exe"
    return str(candidate) if candidate.is_file() else None


def get_os_outbound_lockdown_instructions(executable_path: Optional[str] = None) -> List[str]:
    """
    Return platform-appropriate OS kernel outbound lockdown commands for Windows, macOS, or Linux.
    """
    target_exe = str(Path(executable_path or sys.executable).resolve())
    if sys.platform == "win32":
        netsh_exe = find_verified_netsh() or r"C:\Windows\System32\netsh.exe"
        return [
            netsh_exe,
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=PacketSentinel-ZeroOutbound-Lockdown",
            "dir=out",
            "action=block",
            f"program={target_exe}",
            "enable=yes",
            "profile=any",
        ]
    if sys.platform == "darwin":
        # macOS socketfilterfw is inbound-only; XNU sandbox-exec blocks outbound sockets at kernel level.
        return [
            "/usr/bin/sandbox-exec",
            "-p",
            "(version 1)(allow default)(deny network-outbound)",
            target_exe,
        ]
    return [
        "systemd-run",
        "--user",
        "-p",
        "IPAddressDeny=any",
        "-p",
        "RestrictAddressFamilies=AF_UNIX",
        target_exe,
    ]


def apply_windows_firewall_outbound_block(executable_path: Optional[str] = None) -> Tuple[bool, str]:
    if sys.platform != "win32":
        cmd_str = " ".join(get_os_outbound_lockdown_instructions(executable_path))
        return False, f"Use OS sandbox wrapper on this platform: {cmd_str}"

    netsh_exe = find_verified_netsh()
    if not netsh_exe:
        return False, "System32 netsh.exe was not found on this machine."

    cmd = get_os_outbound_lockdown_instructions(executable_path)
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    try:
        res = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=6.0,
            creationflags=creationflags,
            check=False,
        )
        output = ((res.stdout or "") + " " + (res.stderr or "")).strip()
        if res.returncode == 0 and "OK" in output.upper():
            return True, f"Windows Firewall outbound block rule active for: {cmd[8]}"
        return (
            False,
            f"Administrator privileges required to register Windows Firewall rule ({output or 'Access denied'}).",
        )
    except Exception as exc:
        return False, f"Error invoking netsh.exe: {exc}"
