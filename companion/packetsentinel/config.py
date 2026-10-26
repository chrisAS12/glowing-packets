"""
Application configuration, trusted threat-feed definitions, and user-scoped storage paths.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set

from .security import atomic_write_json, normalize_and_validate_domain, validate_https_feed_url


@dataclass(frozen=True)
class ThreatFeedSource:
    name: str
    url: str
    category: str
    enabled_by_default: bool = True


DEFAULT_THREAT_FEEDS: tuple[ThreatFeedSource, ...] = (
    ThreatFeedSource(
        name="URLhaus Active Malware Distribution (abuse.ch)",
        url="https://urlhaus.abuse.ch/downloads/hostfile/",
        category="malware_domain",
    ),
    ThreatFeedSource(
        name="ThreatFox Recent Malware Indicators (abuse.ch)",
        url="https://threatfox.abuse.ch/downloads/hostfile/",
        category="malware_domain",
    ),
    ThreatFeedSource(
        name="Abuse.ch Feodo Tracker (Botnet C2 IPs)",
        url="https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        category="botnet_c2_ip",
    ),
    ThreatFeedSource(
        name="HaGeZi Multi PRO Threat Intelligence (High-Security DNS)",
        url="https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt",
        category="malware_domain",
    ),
    ThreatFeedSource(
        name="StevenBlack Unified Hosts (Sketchy/Malware/Trackers)",
        url="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        category="sketchy_dns",
    ),
    ThreatFeedSource(
        name="Phishing Army Extended Community Feed",
        url="https://phishing.army/download/phishing_army_blocklist_extended.txt",
        category="phishing_domain",
    ),
    ThreatFeedSource(
        name="DandelionSprout Anti-Malware Hosts (GitHub)",
        url="https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt",
        category="malware_domain",
    ),
    ThreatFeedSource(
        name="Prigent Malware & Cryptojacking Domains",
        url="https://v.firebog.net/hosts/Prigent-Crypto.txt",
        category="malware_domain",
    ),
    ThreatFeedSource(
        name="OpenPhish GitHub Community Feed (Phishing Domains)",
        url="https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
        category="phishing_domain",
    ),
)

# Restricting default feed downloads to an explicit host allowlist prevents a tampered
# config file from turning the updater into an arbitrary SSRF client.
DEFAULT_TRUSTED_FEED_HOSTS: Set[str] = {
    "raw.githubusercontent.com",
    "gist.githubusercontent.com",
    "urlhaus.abuse.ch",
    "threatfox.abuse.ch",
    "feodotracker.abuse.ch",
    "sslbl.abuse.ch",
    "openphish.com",
    "phishing.army",
    "v.firebog.net",
    "small.oisd.nl",
    "oisd.nl",
}

# Core OS, DNS, and repo hosts are pinned here so a poisoned upstream community feed
# can never lock out updates or trigger recursive self-alerts when fetching blocklists.
SAFE_ALLOWLIST_DOMAINS: frozenset[str] = frozenset(
    {
        "localhost",
        "local",
        "localdomain",
        "broadcasthost",
        "ip6-localhost",
        "ip6-loopback",
        "wpad",
        "isatap",
        "github.com",
        "raw.githubusercontent.com",
        "gist.githubusercontent.com",
        "objects.githubusercontent.com",
        "urlhaus.abuse.ch",
        "threatfox.abuse.ch",
        "feodotracker.abuse.ch",
        "abuse.ch",
        "phishing.army",
        "microsoft.com",
        "windows.com",
        "windowsupdate.com",
        "live.com",
        "office.com",
        "digicert.com",
        "dns.google",
        "cloudflare-dns.com",
        "one.one.one.one",
    }
)

# Reserved RFC 2606 (.example.com / .invalid) canary domains allow users to test live wire
# detection without ever sending packets toward real malicious infrastructure.
BUILTIN_CANARY_DOMAINS: Dict[str, str] = {
    "sketchy-canary.example.com": "PacketSentinel Canary Test Feed",
    "malware-beacon-test.example.org": "PacketSentinel Canary Test Feed",
    "sketchy-dns-test.invalid": "PacketSentinel Canary Test Feed",
}

# tshark.exe is resolved only from fixed Program Files paths rather than PATH or CWD
# to prevent Windows current-directory binary planting / DLL hijacking.
VERIFIED_TSHARK_PATHS: tuple[str, ...] = (
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
)

HELP_ISSUES_URL = "https://github.com/chrisAS12/glowing-packets/issues"
HELP_REPO_URL = "https://github.com/chrisAS12/glowing-packets"


def get_app_data_dir() -> Path:
    override = os.environ.get("PACKETSENTINEL_HOME")
    if override:
        base = Path(override).expanduser().resolve()
    else:
        local_app_data = os.environ.get("LOCALAPPDATA")
        base = (Path(local_app_data) / "PacketSentinel") if local_app_data else (Path.home() / ".packetsentinel")

    base.mkdir(parents=True, exist_ok=True)
    return base


@dataclass
class AppConfig:
    app_dir: Path = field(default_factory=get_app_data_dir)
    setup_completed: bool = False
    cache_ttl_seconds: int = 12 * 3600
    alert_cooldown_seconds: int = 60
    max_alerts_per_minute: int = 8
    enable_desktop_toast: bool = True
    enable_console_beep: bool = False
    capture_loopback: bool = True
    custom_feed_urls: List[str] = field(default_factory=list)
    user_allowlist_domains: List[str] = field(default_factory=list)

    @property
    def cache_dir(self) -> Path:
        path = self.app_dir / "cache"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def log_dir(self) -> Path:
        path = self.app_dir / "logs"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def config_file(self) -> Path:
        return self.app_dir / "config.json"

    @property
    def custom_blocklist_file(self) -> Path:
        self.app_dir.mkdir(parents=True, exist_ok=True)
        path = self.app_dir / "custom_sketchy_domains.txt"
        if not path.exists():
            header = (
                "# PacketSentinel Custom Sketchy Domains & IPs\n"
                "# Add one domain or public IP per line. Lines starting with '#' are comments.\n"
                "sketchy-canary.example.com\n"
            )
            path.write_text(header, encoding="utf-8")
        return path

    def save(self) -> None:
        payload = {
            "setup_completed": bool(self.setup_completed),
            "cache_ttl_seconds": int(self.cache_ttl_seconds),
            "alert_cooldown_seconds": int(self.alert_cooldown_seconds),
            "max_alerts_per_minute": int(self.max_alerts_per_minute),
            "enable_desktop_toast": bool(self.enable_desktop_toast),
            "enable_console_beep": bool(self.enable_console_beep),
            "capture_loopback": bool(self.capture_loopback),
            "custom_feed_urls": list(self.custom_feed_urls),
            "user_allowlist_domains": list(self.user_allowlist_domains),
        }
        atomic_write_json(self.config_file, payload)

    @classmethod
    def load(cls, app_dir: Path | None = None) -> "AppConfig":
        cfg = cls(app_dir=app_dir or get_app_data_dir())
        _ = cfg.custom_blocklist_file
        if not cfg.config_file.exists():
            cfg.save()
            return cfg

        try:
            raw = json.loads(cfg.config_file.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                return cfg
            cfg.setup_completed = bool(raw.get("setup_completed", False))
            cfg.cache_ttl_seconds = max(300, min(7 * 86400, int(raw.get("cache_ttl_seconds", 43200))))
            cfg.alert_cooldown_seconds = max(5, min(86400, int(raw.get("alert_cooldown_seconds", 60))))
            cfg.max_alerts_per_minute = max(1, min(60, int(raw.get("max_alerts_per_minute", 8))))
            cfg.enable_desktop_toast = bool(raw.get("enable_desktop_toast", True))
            cfg.enable_console_beep = bool(raw.get("enable_console_beep", False))
            cfg.capture_loopback = bool(raw.get("capture_loopback", True))

            valid_urls: list[str] = []
            for u in raw.get("custom_feed_urls", []):
                if isinstance(u, str):
                    try:
                        valid_urls.append(validate_https_feed_url(u))
                    except ValueError:
                        pass
            cfg.custom_feed_urls = valid_urls

            valid_allow: list[str] = []
            for d in raw.get("user_allowlist_domains", []):
                if isinstance(d, str):
                    norm = normalize_and_validate_domain(d)
                    if norm:
                        valid_allow.append(norm)
            cfg.user_allowlist_domains = valid_allow
        except Exception:
            pass

        return cfg
