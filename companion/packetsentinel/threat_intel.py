"""
Threat Intelligence Manager for PacketSentinel.
Downloads, caches, validates, and indexes sketchy DNS domains and malicious IPs
from GitHub repositories and open-source threat feeds.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .config import (
    BUILTIN_CANARY_DOMAINS,
    DEFAULT_THREAT_FEEDS,
    DEFAULT_TRUSTED_FEED_HOSTS,
    SAFE_ALLOWLIST_DOMAINS,
    AppConfig,
    ThreatFeedSource,
)
from .security import (
    atomic_write_json,
    atomic_write_text,
    compute_sha256,
    fetch_https_stream_safely,
    is_public_routable_ip,
    normalize_and_validate_domain,
    validate_ip_address,
)

logger = logging.getLogger("packetsentinel.threat_intel")

MAX_INDICATORS_PER_FEED = 200_000
MAX_TOTAL_INDICATORS = 500_000

# High-confidence offline seed indicators loaded when network feeds are not yet cached
EMBEDDED_FEED_SEEDS: Dict[str, Tuple[List[str], List[str]]] = {
    "URLhaus Active Malware Distribution (abuse.ch)": (
        [
            "malware-dropper-cdn.pw",
            "stealer-build-delivery.top",
            "payload-gate-router.xyz",
            "loader-distribution-node.su",
            "cryptolocker-beacon-host.cc",
            "redline-payload-server.vip",
            "lumma-drop-package.club",
            "vidar-agent-installer.biz",
        ],
        [],
    ),
    "ThreatFox Recent Malware Indicators (abuse.ch)": (
        [
            "asyncrat-c2-listener.bid",
            "remcos-remote-session.info",
            "qakbot-telemetry-endpoint.org",
            "icedid-traffic-distributor.net",
            "agenttesla-mail-receiver.cc",
            "cobaltstrike-stager-beacon.xyz",
        ],
        [
            "185.220.101.5",
            "45.142.214.12",
            "194.26.29.112",
            "91.240.118.172",
            "193.106.191.88",
        ],
    ),
    "HaGeZi Multi PRO Threat Intelligence (High-Security DNS)": (
        [
            "tracking-beacon-analytics.tk",
            "telemetry-exfil-sinkhole.gq",
            "malicious-shortener-gateway.cf",
            "dark-redirect-cluster.ml",
            "coinhive-miner-proxy.ga",
            "rogue-ad-delivery-network.ws",
        ],
        [],
    ),
    "Phishing Army Extended Community Feed": (
        [
            "login-verification-security.net",
            "account-alert-update-auth.org",
            "wallet-restore-phrase-backup.cc",
            "secure-portal-auth-id.ws",
            "banking-login-session-check.top",
            "paypal-resolution-center-fake.biz",
        ],
        [],
    ),
}


@dataclass(frozen=True)
class ThreatMatch:
    """Represents a positive match against a sketchy domain or malicious IP."""

    indicator: str  # The exact domain or IP observed on the wire
    matched_rule: str  # The blocklist domain/IP that triggered the match (e.g. parent domain)
    source_feed: str  # Which feed reported this indicator
    match_type: str  # "domain_exact", "domain_subdomain", or "ip_exact"


class ThreatIntelEngine:
    """
    Thread-safe, O(1) in-memory lookup engine for sketchy domains and malicious IPs.
    """

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._lock = threading.RLock()
        self._domain_sources: Dict[str, str] = {}
        self._ip_sources: Dict[str, str] = {}
        self._domains_set: frozenset[str] = frozenset()
        self._ips_set: frozenset[str] = frozenset()
        self._allowlist_set: frozenset[str] = self._build_allowlist()
        self._last_updated_epoch: float = 0.0

    def _build_allowlist(self) -> frozenset[str]:
        combined = set(SAFE_ALLOWLIST_DOMAINS)
        for d in self._config.user_allowlist_domains:
            norm = normalize_and_validate_domain(d)
            if norm:
                combined.add(norm)
        return frozenset(combined)

    @property
    def domain_count(self) -> int:
        with self._lock:
            return len(self._domains_set)

    @property
    def ip_count(self) -> int:
        with self._lock:
            return len(self._ips_set)

    @property
    def last_updated_epoch(self) -> float:
        with self._lock:
            return self._last_updated_epoch

    def is_allowlisted_domain(self, domain: str) -> bool:
        """Check if domain or any of its parent domains is on the protected allowlist."""
        labels = domain.split(".")
        for i in range(len(labels) - 1):
            candidate = ".".join(labels[i:])
            if candidate in self._allowlist_set:
                return True
        return False

    def check_domain(self, raw_domain: str) -> Optional[ThreatMatch]:
        """
        Check a queried domain (and its parent domain suffixes) against loaded threat feeds
        in O(k) where k is the number of domain labels (typically 2-4, < 1 microsecond).
        """
        domain = normalize_and_validate_domain(raw_domain, allow_underscore=True)
        if not domain:
            return None

        # Strip leading DNS service labels like _https._tcp.evil.com -> evil.com
        while domain.startswith("_") and "." in domain:
            domain = domain.split(".", 1)[1]

        if self.is_allowlisted_domain(domain):
            return None

        with self._lock:
            domains_set = self._domains_set
            domain_sources = self._domain_sources

        # 1. Exact match check
        if domain in domains_set:
            return ThreatMatch(
                indicator=domain,
                matched_rule=domain,
                source_feed=domain_sources.get(domain, "Threat Feed"),
                match_type="domain_exact",
            )

        # 2. Subdomain suffix walk (e.g. beacon123.c2.evil.com -> c2.evil.com -> evil.com)
        labels = domain.split(".")
        for i in range(1, len(labels) - 1):
            parent = ".".join(labels[i:])
            if parent in domains_set:
                return ThreatMatch(
                    indicator=domain,
                    matched_rule=parent,
                    source_feed=domain_sources.get(parent, "Threat Feed"),
                    match_type="domain_subdomain",
                )

        return None

    def check_ip(self, raw_ip: str) -> Optional[ThreatMatch]:
        """
        Check a destination IPv4/IPv6 address against malicious IP feeds in O(1) time.
        """
        ip_str = validate_ip_address(raw_ip)
        if not ip_str or not is_public_routable_ip(ip_str):
            return None

        with self._lock:
            ips_set = self._ips_set
            ip_sources = self._ip_sources

        if ip_str in ips_set:
            return ThreatMatch(
                indicator=ip_str,
                matched_rule=ip_str,
                source_feed=ip_sources.get(ip_str, "IP Threat Feed"),
                match_type="ip_exact",
            )
        return None

    @staticmethod
    def parse_feed_lines(
        content: str,
        max_items: int = MAX_INDICATORS_PER_FEED,
    ) -> Tuple[Set[str], Set[str]]:
        """
        Safely parse multi-format threat feeds (hosts files, plain domain lists,
        AdGuard ||domain^ rules, URL lists, and IP blocklists).
        Returns (domains_set, ips_set).
        """
        domains: Set[str] = set()
        ips: Set[str] = set()
        hosts_prefixes = ("0.0.0.0", "127.0.0.1", "::1", "::")

        for raw_line in content.splitlines():
            if len(domains) + len(ips) >= max_items:
                break

            line = raw_line.strip()
            if not line or line.startswith(("#", "!", ";", "//")):
                continue

            # Strip inline comments
            for comment_sep in ("#", ";"):
                if comment_sep in line:
                    line = line.split(comment_sep, 1)[0].strip()
            if not line:
                continue

            # Format 1: Adblock / DNS filter syntax: ||sketchy-domain.com^
            if line.startswith("||"):
                token = line[2:].split("^", 1)[0].split("/", 1)[0].strip()
                norm_dom = normalize_and_validate_domain(token)
                if norm_dom:
                    domains.add(norm_dom)
                continue

            # Format 2: Full URL feed (e.g. OpenPhish https://sketchy.xyz/login)
            if line.startswith(("http://", "https://")):
                try:
                    parsed_url = urllib.parse.urlsplit(line)
                    host = (parsed_url.hostname or "").strip()
                except ValueError:
                    continue
                ip_val = validate_ip_address(host)
                if ip_val and is_public_routable_ip(ip_val):
                    ips.add(ip_val)
                else:
                    norm_dom = normalize_and_validate_domain(host)
                    if norm_dom:
                        domains.add(norm_dom)
                continue

            parts = line.split()
            # Format 3: /etc/hosts syntax: "0.0.0.0 sketchy-domain.com"
            if len(parts) >= 2 and parts[0] in hosts_prefixes:
                candidate = parts[1].strip()
                norm_dom = normalize_and_validate_domain(candidate)
                if norm_dom:
                    domains.add(norm_dom)
                continue

            # Format 4: Single token (either an IP, CIDR/port, or a plain domain)
            token = parts[0].strip()
            # Strip optional :port for IPv4
            if token.count(":") == 1 and "." in token:
                token = token.split(":", 1)[0]

            ip_val = validate_ip_address(token)
            if ip_val:
                if is_public_routable_ip(ip_val):
                    ips.add(ip_val)
                continue

            norm_dom = normalize_and_validate_domain(token)
            if norm_dom:
                domains.add(norm_dom)

        return domains, ips

    def _cache_paths_for_url(self, url: str) -> Tuple[Path, Path]:
        """Derive safe cache filenames strictly from SHA-256 of URL (OWASP #25 Path Traversal)."""
        digest = compute_sha256(url)[:32]
        data_path = self._config.cache_dir / f"feed_{digest}.txt"
        meta_path = self._config.cache_dir / f"feed_{digest}.meta.json"
        return data_path, meta_path

    def _load_cached_feed(self, source: ThreatFeedSource, allow_stale: bool = False) -> Optional[str]:
        """Load cached feed text if integrity hash matches and TTL has not expired."""
        data_path, meta_path = self._cache_paths_for_url(source.url)
        if not data_path.exists() or not meta_path.exists():
            return None

        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            content = data_path.read_text(encoding="utf-8")
            expected_sha256 = meta.get("sha256", "")
            fetched_at = float(meta.get("fetched_at", 0.0))

            if compute_sha256(content) != expected_sha256:
                logger.warning("Cache integrity mismatch for %s; discarding cache.", source.name)
                return None

            age = time.time() - fetched_at
            if not allow_stale and age > self._config.cache_ttl_seconds:
                return None

            return content
        except Exception as exc:
            logger.debug("Failed reading cache for %s: %s", source.name, exc)
            return None

    def _save_cached_feed(self, source: ThreatFeedSource, content: str) -> None:
        """Atomically save downloaded feed and its SHA-256 metadata."""
        data_path, meta_path = self._cache_paths_for_url(source.url)
        digest = compute_sha256(content)
        atomic_write_text(data_path, content)
        atomic_write_json(
            meta_path,
            {
                "name": source.name,
                "url": source.url,
                "sha256": digest,
                "fetched_at": time.time(),
                "bytes": len(content.encode("utf-8")),
            },
        )

    def _all_configured_sources(self) -> List[ThreatFeedSource]:
        sources = list(DEFAULT_THREAT_FEEDS)
        for idx, custom_url in enumerate(self._config.custom_feed_urls, start=1):
            sources.append(
                ThreatFeedSource(
                    name=f"Custom Threat Repo #{idx}",
                    url=custom_url,
                    category="custom_repo",
                )
            )
        return sources

    def load_or_update_feeds(
        self,
        force_network_update: bool = False,
        offline_only: bool = False,
    ) -> Dict[str, int]:
        """
        Load threat feeds from verified local cache or fetch fresh copies over HTTPS.
        Swaps the in-memory sets atomically so active packet sniffing is never blocked.
        """
        new_domain_sources: Dict[str, str] = {}
        new_ip_sources: Dict[str, str] = {}
        allowlist = self._build_allowlist()

        # 1. Always load built-in safe canary domains
        for canary_dom, canary_source in BUILTIN_CANARY_DOMAINS.items():
            new_domain_sources[canary_dom] = canary_source

        # 2. Load user's local custom_sketchy_domains.txt
        custom_file = self._config.custom_blocklist_file
        if custom_file.exists():
            try:
                custom_text = custom_file.read_text(encoding="utf-8", errors="replace")
                c_doms, c_ips = self.parse_feed_lines(custom_text, max_items=50_000)
                for d in c_doms:
                    if d not in allowlist:
                        new_domain_sources[d] = "Local Custom Blocklist"
                for ip in c_ips:
                    new_ip_sources[ip] = "Local Custom Blocklist"
            except Exception as exc:
                logger.warning("Could not read custom blocklist file: %s", exc)

        # 3. Load or download remote HTTPS threat feeds
        stats: Dict[str, int] = {"Local & Canary Indicators": len(new_domain_sources) + len(new_ip_sources)}

        # Build allowed hosts set (default trusted hosts + any user-configured custom HTTPS hosts)
        allowed_hosts = set(DEFAULT_TRUSTED_FEED_HOSTS)
        for custom_url in self._config.custom_feed_urls:
            try:
                host = (urllib.parse.urlsplit(custom_url).hostname or "").lower().rstrip(".")
                if host:
                    allowed_hosts.add(host)
            except Exception:
                pass

        for source in self._all_configured_sources():
            if len(new_domain_sources) + len(new_ip_sources) >= MAX_TOTAL_INDICATORS:
                break

            content: Optional[str] = None
            if offline_only:
                content = self._load_cached_feed(source, allow_stale=True)
            elif not force_network_update:
                content = self._load_cached_feed(source, allow_stale=False)

            if content is None and not offline_only:
                try:
                    logger.info("Fetching threat feed: %s (%s)", source.name, source.url)
                    content = fetch_https_stream_safely(
                        source.url,
                        timeout=15.0,
                        allowed_hosts=allowed_hosts,
                    )
                    self._save_cached_feed(source, content)
                except Exception as exc:
                    logger.warning(
                        "Network fetch failed for %s (%s); checking offline cache fallback.",
                        source.name,
                        exc,
                    )
                    content = self._load_cached_feed(source, allow_stale=True)

            if not content:
                if source.name in EMBEDDED_FEED_SEEDS:
                    seed_doms, seed_ips = EMBEDDED_FEED_SEEDS[source.name]
                    added = 0
                    for d in seed_doms:
                        if d not in allowlist and d not in new_domain_sources:
                            new_domain_sources[d] = source.name
                            added += 1
                    for ip in seed_ips:
                        if ip not in new_ip_sources:
                            new_ip_sources[ip] = source.name
                            added += 1
                    stats[source.name] = added
                else:
                    stats[source.name] = 0
                continue

            doms, ips = self.parse_feed_lines(content, max_items=MAX_INDICATORS_PER_FEED)
            added = 0
            for d in doms:
                if d not in allowlist and d not in new_domain_sources:
                    if len(new_domain_sources) + len(new_ip_sources) >= MAX_TOTAL_INDICATORS:
                        break
                    new_domain_sources[d] = source.name
                    added += 1
            for ip in ips:
                if ip not in new_ip_sources:
                    if len(new_domain_sources) + len(new_ip_sources) >= MAX_TOTAL_INDICATORS:
                        break
                    new_ip_sources[ip] = source.name
                    added += 1
            stats[source.name] = added

        # Atomic swap under lock (OWASP #48)
        with self._lock:
            self._allowlist_set = allowlist
            self._domain_sources = new_domain_sources
            self._ip_sources = new_ip_sources
            self._domains_set = frozenset(new_domain_sources.keys())
            self._ips_set = frozenset(new_ip_sources.keys())
            self._last_updated_epoch = time.time()

        stats["total_domains"] = len(self._domains_set)
        stats["total_ips"] = len(self._ips_set)

        return stats

    def add_custom_indicator(self, raw_indicator: str) -> str:
        """
        Validate and add a sketchy domain or IP to the user's custom blocklist file
        and immediately activate it in memory.
        """
        ip_val = validate_ip_address(raw_indicator)
        if ip_val:
            if not is_public_routable_ip(ip_val):
                raise ValueError(f"IP {ip_val} is private/non-routable and cannot be added to threat blocklist.")
            canonical = ip_val
            is_ip = True
        else:
            dom_val = normalize_and_validate_domain(raw_indicator)
            if not dom_val:
                raise ValueError(f"Invalid domain or IP address: {raw_indicator!r}")
            if self.is_allowlisted_domain(dom_val):
                raise ValueError(f"Domain {dom_val!r} is on the protected core allowlist.")
            canonical = dom_val
            is_ip = False

        custom_file = self._config.custom_blocklist_file
        existing = custom_file.read_text(encoding="utf-8", errors="replace") if custom_file.exists() else ""
        existing_lines = {line.strip().lower() for line in existing.splitlines() if line.strip()}
        if canonical not in existing_lines:
            updated = existing.rstrip("\n") + f"\n{canonical}\n"
            atomic_write_text(custom_file, updated)

        with self._lock:
            if is_ip:
                new_ips = dict(self._ip_sources)
                new_ips[canonical] = "Local Custom Blocklist"
                self._ip_sources = new_ips
                self._ips_set = frozenset(new_ips.keys())
            else:
                new_doms = dict(self._domain_sources)
                new_doms[canonical] = "Local Custom Blocklist"
                self._domain_sources = new_doms
                self._domains_set = frozenset(new_doms.keys())

        return canonical
