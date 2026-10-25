"""
Living Off Trusted Sites (LOTS) Exfiltration Guard for PacketSentinel.

Correlates process identity (browser vs script interpreter / LOLBIN) against
known trusted cloud services and webhooks abused by info-stealers and C2 channels.
Zero outbound network calls - pure offline correlation logic.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True)
class LOTSEndpoint:
    """Living Off Trusted Sites destination endpoint definition."""

    domain_suffix: str
    category: str
    severity: str


@dataclass(frozen=True)
class LOTSRiskResult:
    """Security assessment result for a process connecting to a LOTS endpoint."""

    is_threat: bool
    severity: str
    reason: str
    category: str
    matched_domain: str = ""


LOTS_ENDPOINTS: Tuple[LOTSEndpoint, ...] = (
    LOTSEndpoint("api.telegram.org", "webhook", "high"),
    LOTSEndpoint("discord.com", "webhook", "medium"),
    LOTSEndpoint("discordapp.com", "webhook", "medium"),
    LOTSEndpoint("trycloudflare.com", "tunnel", "high"),
    LOTSEndpoint("ngrok-free.app", "tunnel", "high"),
    LOTSEndpoint("ngrok.io", "tunnel", "high"),
    LOTSEndpoint("webhook.site", "webhook", "high"),
    LOTSEndpoint("transfer.sh", "file_drop", "high"),
    LOTSEndpoint("file.io", "file_drop", "high"),
    LOTSEndpoint("catbox.moe", "file_drop", "medium"),
    LOTSEndpoint("pastebin.com", "paste_service", "medium"),
    LOTSEndpoint("pipedream.net", "webhook", "high"),
    LOTSEndpoint("hookdeck.com", "webhook", "high"),
    LOTSEndpoint("requestbin.com", "webhook", "high"),
    LOTSEndpoint("paste.ee", "paste_service", "medium"),
)

KNOWN_BROWSERS: frozenset[str] = frozenset(
    {
        "chrome.exe",
        "chrome",
        "firefox.exe",
        "firefox",
        "msedge.exe",
        "msedge",
        "brave.exe",
        "brave",
        "safari",
        "opera.exe",
        "opera",
        "vivaldi.exe",
        "vivaldi",
        "arc.exe",
        "arc",
    }
)

KNOWN_SCRIPT_LOLBINS: frozenset[str] = frozenset(
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


def normalize_domain_for_lots(raw_domain: str) -> str:
    """Normalize domain by trimming whitespace, trailing/leading dots, and lowercasing."""
    if not raw_domain or not isinstance(raw_domain, str):
        return ""
    # Strip leading/trailing whitespace and dots to canonicalize FQDN representations
    cleaned = raw_domain.strip().strip(".").lower()
    if len(cleaned) > 253 or "." not in cleaned:
        return ""
    return cleaned


def normalize_process_name(process_name: str) -> str:
    """Extract lowercase executable basename without path components."""
    if not process_name or not isinstance(process_name, str):
        return ""
    # Normalize Windows backslashes and POSIX forward slashes cross-platform
    cleaned = process_name.strip().replace("\\", "/")
    return cleaned.rsplit("/", 1)[-1].lower()


def find_matching_lots_endpoint(domain: str) -> Optional[LOTSEndpoint]:
    """Find matching LOTS endpoint using exact match or subdomain suffix match."""
    normalized = normalize_domain_for_lots(domain)
    if not normalized:
        return None
    for endpoint in LOTS_ENDPOINTS:
        suffix = endpoint.domain_suffix
        if normalized == suffix or normalized.endswith(f".{suffix}"):
            return endpoint
    return None


def is_known_browser(process_name: str) -> bool:
    """Check if process basename is a recognized interactive desktop browser."""
    proc = normalize_process_name(process_name)
    return proc in KNOWN_BROWSERS


def is_known_script_lolbin(process_name: str) -> bool:
    """Check if process basename is a known script interpreter or LOLBIN."""
    proc = normalize_process_name(process_name)
    return proc in KNOWN_SCRIPT_LOLBINS


def check_lots_risk(
    process_name: str,
    domain: str,
    port: int = 443,
) -> Optional[LOTSRiskResult]:
    """
    Evaluate if outbound connection is an exfiltration attempt over trusted services.
    Returns None for benign browser activity or unmatched domains.
    Returns LOTSRiskResult with HIGH severity for scripts/LOLBINs and MEDIUM for others.
    """
    if not (1 <= port <= 65535):
        return None

    endpoint = find_matching_lots_endpoint(domain)
    if endpoint is None:
        return None

    if is_known_browser(process_name):
        return None

    proc_base = normalize_process_name(process_name) or "unknown"
    normalized_domain = normalize_domain_for_lots(domain)

    if is_known_script_lolbin(process_name):
        return LOTSRiskResult(
            is_threat=True,
            severity="HIGH",
            reason=f"Script interpreter/LOLBIN '{proc_base}' contacting {endpoint.category} endpoint '{normalized_domain}'",
            category=endpoint.category,
            matched_domain=normalized_domain,
        )

    return LOTSRiskResult(
        is_threat=True,
        severity="MEDIUM",
        reason=f"Non-browser process '{proc_base}' contacting {endpoint.category} endpoint '{normalized_domain}'",
        category=endpoint.category,
        matched_domain=normalized_domain,
    )


def format_lots_alert(
    result: LOTSRiskResult,
    pid: int,
    process_name: str,
    domain: str,
) -> str:
    """Format human-readable alert string for LOTS endpoint detection."""
    proc_desc = f"{process_name} (PID: {pid})" if pid > 0 else process_name
    return (
        f"[LOTS ALERT - {result.severity}] Process '{proc_desc}' contacted "
        f"{result.category} endpoint '{domain}' - {result.reason}"
    )
