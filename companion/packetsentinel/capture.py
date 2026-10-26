"""
Multi-Engine Live Packet & Connection Monitor for PacketSentinel.
Combines:
1. Wireshark `tshark.exe` live wire capture (DNS queries, TLS ClientHello SNI, and outbound TCP SYN / UDP flows)
2. Active OS Socket & Windows DNS Resolver Cache monitor (catches direct-IP C2 sockets and OS-cached DNS lookups)
"""

from __future__ import annotations

import atexit
import logging
import os
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set, Tuple

from .config import VERIFIED_TSHARK_PATHS, AppConfig
from .lots_guard import check_lots_risk
from .notifier import AlertNotifier
from .process_mapper import UNKNOWN_PROCESS, ProcessInfo, ProcessMapper
from .security import (
    is_public_routable_ip,
    normalize_and_validate_domain,
    sanitize_display_text,
    validate_ip_address,
)
from .threat_intel import ThreatIntelEngine, ThreatMatch

logger = logging.getLogger("packetsentinel.capture")


@dataclass(frozen=True)
class CaptureHealthStatus:
    """Health check diagnostic report (OWASP #50)."""

    tshark_path: Optional[str]
    npcap_running: bool
    interfaces_detected: List[str]
    domain_indicators_loaded: int
    ip_indicators_loaded: int


def find_verified_tshark() -> Optional[str]:
    """
    Locate Wireshark's tshark.exe strictly from verified absolute paths
    to prevent relative-path binary planting / DLL hijacking (OWASP #22, #23).
    """
    env_override = os.environ.get("PACKETSENTINEL_TSHARK_PATH")
    if env_override:
        p = Path(env_override).resolve()
        if p.is_file() and p.name.lower() == "tshark.exe":
            return str(p)

    for raw_path in VERIFIED_TSHARK_PATHS:
        p = Path(raw_path)
        if p.is_file():
            return str(p)
    return None


def find_verified_ipconfig() -> Optional[str]:
    """Locate canonical System32 ipconfig.exe path."""
    sys_root = os.environ.get("SystemRoot", r"C:\Windows")
    candidate = Path(sys_root) / "System32" / "ipconfig.exe"
    if candidate.is_file():
        return str(candidate)
    return None


def check_npcap_service_running() -> bool:
    """Check whether the Npcap driver service is active on Windows."""
    sys_root = os.environ.get("SystemRoot", r"C:\Windows")
    sc_exe = Path(sys_root) / "System32" / "sc.exe"
    if not sc_exe.is_file():
        return False
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    try:
        res = subprocess.run(
            [str(sc_exe), "query", "npcap"],
            shell=False,
            capture_output=True,
            text=True,
            timeout=3.0,
            creationflags=creationflags,
            check=False,
        )
        return "RUNNING" in (res.stdout or "").upper()
    except Exception:
        return False


def discover_tshark_interfaces(tshark_path: str, include_loopback: bool = True) -> List[Tuple[str, str]]:
    """
    Query `tshark.exe -D` safely and return a list of (interface_index_or_id, display_name)
    suitable for live packet capture (excluding special virtual readers like etwdump).
    """
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    try:
        res = subprocess.run(
            [tshark_path, "-D"],
            shell=False,
            capture_output=True,
            text=True,
            timeout=6.0,
            creationflags=creationflags,
            check=False,
        )
    except Exception as exc:
        logger.warning("Failed to enumerate tshark interfaces: %s", exc)
        return []

    if res.returncode != 0 or not res.stdout:
        return []

    all_ifaces: List[Tuple[str, str]] = []
    preferred_ifaces: List[Tuple[str, str]] = []

    for raw_line in res.stdout.splitlines():
        line = sanitize_display_text(raw_line, max_len=240).strip()
        if not line or "." not in line:
            continue
        idx_part, rest = line.split(".", 1)
        idx_str = idx_part.strip()
        if not idx_str.isdigit():
            continue
        desc = rest.strip()
        lower_desc = desc.lower()

        # Skip ETW reader and Bluetooth PAN unless needed
        if "etwdump" in lower_desc or "bluetooth" in lower_desc:
            continue

        is_loopback = "loopback" in lower_desc
        if is_loopback and not include_loopback:
            continue

        entry = (idx_str, desc)
        all_ifaces.append(entry)

        # Prioritize primary adapters (WiFi, Ethernet, vEthernet, Loopback)
        if any(k in lower_desc for k in ("wifi", "wi-fi", "ethernet", "loopback", "wlan")):
            preferred_ifaces.append(entry)

    return preferred_ifaces if preferred_ifaces else all_ifaces


class PacketSentinelMonitor:
    """
    Coordinates live `tshark` wire packet inspection, active socket polling,
    and Windows DNS cache monitoring.
    """

    def __init__(
        self,
        config: AppConfig,
        threat_engine: ThreatIntelEngine,
        process_mapper: ProcessMapper,
        notifier: AlertNotifier,
    ) -> None:
        self._config = config
        self._threat_engine = threat_engine
        self._process_mapper = process_mapper
        self._notifier = notifier

        self._stop_event = threading.Event()
        self._tshark_proc: Optional[subprocess.Popen] = None
        self._threads: List[threading.Thread] = []
        self._packets_inspected: int = 0
        self._dns_queries_seen: int = 0
        self._tls_sni_seen: int = 0
        self._seen_dnscache_baseline: Set[str] = set()
        self._baseline_initialized: bool = False
        self._process_packet_counts: Dict[str, int] = {}
        self._pid_packet_counts: Dict[int, int] = {}

        atexit.register(self.stop)

    @property
    def packets_inspected(self) -> int:
        return self._packets_inspected

    @property
    def dns_queries_seen(self) -> int:
        return self._dns_queries_seen

    @property
    def tls_sni_seen(self) -> int:
        return self._tls_sni_seen

    def get_process_event_count(self, process_name: str, pid: Optional[int] = None) -> int:
        """Return total wire/socket events attributed to a specific process or PID."""
        if pid and pid in self._pid_packet_counts:
            return self._pid_packet_counts[pid]
        clean_name = (process_name or "").lower().replace("\\", "/").rsplit("/", 1)[-1]
        return self._process_packet_counts.get(clean_name, 0)

    def get_health_status(self) -> CaptureHealthStatus:
        tshark_path = find_verified_tshark()
        npcap_ok = check_npcap_service_running()
        ifaces: List[str] = []
        if tshark_path:
            ifaces = [desc for _, desc in discover_tshark_interfaces(tshark_path, self._config.capture_loopback)]
        return CaptureHealthStatus(
            tshark_path=tshark_path,
            npcap_running=npcap_ok,
            interfaces_detected=ifaces,
            domain_indicators_loaded=self._threat_engine.domain_count,
            ip_indicators_loaded=self._threat_engine.ip_count,
        )

    def start(self) -> None:
        """Start background wire capture and socket/DNS-cache monitoring threads."""
        self._stop_event.clear()

        tshark_path = find_verified_tshark()
        if tshark_path:
            t_wire = threading.Thread(
                target=self._run_tshark_loop,
                args=(tshark_path,),
                name="PacketSentinel-TSharkWire",
                daemon=True,
            )
            self._threads.append(t_wire)
            t_wire.start()
        else:
            logger.warning(
                "Wireshark tshark.exe not found at verified paths; using active socket & DNS cache monitor."
            )

        t_soc = threading.Thread(
            target=self._run_socket_and_dnscache_loop,
            name="PacketSentinel-SocketDNSCache",
            daemon=True,
        )
        self._threads.append(t_soc)
        t_soc.start()

    def stop(self) -> None:
        """Signal all monitor threads to stop and cleanly terminate any tshark subprocess (OWASP #30)."""
        self._stop_event.set()
        proc = self._tshark_proc
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=2.0)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        self._tshark_proc = None

    def inspect_event(
        self,
        domain: Optional[str] = None,
        dst_ip: Optional[str] = None,
        src_port: Optional[int] = None,
        dst_port: int = 0,
        protocol: str = "UDP/DNS",
        detection_layer: str = "tshark-wire",
        explicit_process: Optional[ProcessInfo] = None,
    ) -> None:
        """
        Inspect a single network event (domain lookup, TLS SNI, or destination IP connection)
        against the threat intelligence engine and trigger an alert on match.
        """
        self._packets_inspected += 1

        # Resolve process attribution once and track event count
        proc = explicit_process or self._process_mapper.lookup(
            protocol="tcp" if ("TCP" in protocol.upper() or "TLS" in protocol.upper()) else "udp",
            local_port=src_port,
            remote_ip=dst_ip,
        )
        if proc:
            p_name = (proc.name or "unknown").lower()
            self._process_packet_counts[p_name] = self._process_packet_counts.get(p_name, 0) + 1
            if proc.pid > 0:
                self._pid_packet_counts[proc.pid] = self._pid_packet_counts.get(proc.pid, 0) + 1

        # 1. Check domain name (DNS query or TLS ClientHello SNI)
        if domain:
            for single_dom in domain.split(","):
                clean_dom = single_dom.strip()
                if not clean_dom:
                    continue
                if "TLS" in protocol.upper():
                    self._tls_sni_seen += 1
                else:
                    self._dns_queries_seen += 1

                match = self._threat_engine.check_domain(clean_dom)
                if match:
                    self._notifier.notify_match(
                        match=match,
                        process=proc,
                        protocol=protocol,
                        dst_ip=dst_ip or "",
                        dst_port=dst_port,
                        detection_layer=detection_layer,
                    )
                    return

                lots_risk = check_lots_risk(proc.name, clean_dom, port=dst_port or 443)
                if lots_risk and lots_risk.is_threat:
                    lots_match = ThreatMatch(
                        indicator=clean_dom,
                        matched_rule=lots_risk.matched_domain or clean_dom,
                        source_feed=f"LOTS-Exfil-Guard ({lots_risk.category.upper()})",
                        match_type=f"lots_{lots_risk.severity.lower()}",
                    )
                    self._notifier.notify_match(
                        match=lots_match,
                        process=proc,
                        protocol=protocol,
                        dst_ip=dst_ip or "",
                        dst_port=dst_port,
                        detection_layer="lots-wire",
                    )
                    return

        # 2. Check destination IP against botnet C2 / malicious IP feeds
        if dst_ip:
            for single_ip in dst_ip.split(","):
                clean_ip = validate_ip_address(single_ip.strip())
                if not clean_ip or not is_public_routable_ip(clean_ip):
                    continue
                ip_match = self._threat_engine.check_ip(clean_ip)
                if ip_match:
                    self._notifier.notify_match(
                        match=ip_match,
                        process=proc,
                        protocol=protocol,
                        dst_ip=clean_ip,
                        dst_port=dst_port,
                        detection_layer=detection_layer,
                    )
                    return

    def _run_tshark_loop(self, tshark_path: str) -> None:
        """
        Continuously stream DNS, TLS SNI, and TCP SYN packet metadata from Wireshark's tshark.exe.
        Uses shell=False and a strict BPF filter so only connection metadata is read into memory.
        """
        ifaces = discover_tshark_interfaces(tshark_path, include_loopback=self._config.capture_loopback)
        if not ifaces:
            logger.warning("No usable network interfaces returned by tshark -D.")
            return

        cmd: List[str] = [tshark_path]
        for idx_str, _ in ifaces:
            cmd.extend(["-i", idx_str])

        # BPF filter captures only DNS (port 53), HTTPS/TLS handshakes (port 443), and new TCP SYN packets
        bpf_filter = "udp port 53 or tcp port 53 or tcp dst port 443 or (tcp[tcpflags] & tcp-syn != 0)"
        cmd.extend(
            [
                "-l",  # Flush stdout line-by-line immediately
                "-n",  # Never resolve addresses via DNS inside tshark
                "-Q",  # Quiet stderr
                "-f",
                bpf_filter,
                "-T",
                "fields",
                "-E",
                "separator=\t",
                "-e",
                "ip.dst",
                "-e",
                "ipv6.dst",
                "-e",
                "udp.srcport",
                "-e",
                "tcp.srcport",
                "-e",
                "udp.dstport",
                "-e",
                "tcp.dstport",
                "-e",
                "dns.qry.name",
                "-e",
                "tls.handshake.extensions_server_name",
            ]
        )

        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

        while not self._stop_event.is_set():
            try:
                proc = subprocess.Popen(
                    cmd,
                    shell=False,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                    creationflags=creationflags,
                )
                self._tshark_proc = proc

                if proc.stdout is not None:
                    for raw_line in proc.stdout:
                        if self._stop_event.is_set():
                            break
                        self._parse_tshark_line(raw_line)

                proc.wait(timeout=2.0)
            except Exception as exc:
                if not self._stop_event.is_set():
                    logger.debug("tshark capture loop error: %s", exc)
            finally:
                self._tshark_proc = None

            if not self._stop_event.is_set():
                time.sleep(2.0)

    def _parse_tshark_line(self, raw_line: str) -> None:
        """
        Parse a single tab-separated line emitted by `tshark -T fields` safely (OWASP #29).
        Fields:
        0: ip.dst | 1: ipv6.dst | 2: udp.srcport | 3: tcp.srcport
        4: udp.dstport | 5: tcp.dstport | 6: dns.qry.name | 7: tls.handshake.extensions_server_name
        """
        try:
            line = raw_line.rstrip("\r\n")
            if not line:
                return
            parts = line.split("\t")
            while len(parts) < 8:
                parts.append("")

            ip_dst = parts[0].strip() or parts[1].strip()
            udp_sport = int(parts[2].split(",")[0]) if parts[2].strip().split(",")[0].isdigit() else 0
            tcp_sport = int(parts[3].split(",")[0]) if parts[3].strip().split(",")[0].isdigit() else 0
            udp_dport = int(parts[4].split(",")[0]) if parts[4].strip().split(",")[0].isdigit() else 0
            tcp_dport = int(parts[5].split(",")[0]) if parts[5].strip().split(",")[0].isdigit() else 0
            dns_qname = parts[6].strip()
            tls_sni = parts[7].strip()

            if dns_qname:
                self.inspect_event(
                    domain=dns_qname,
                    dst_ip=ip_dst,
                    src_port=udp_sport or tcp_sport,
                    dst_port=udp_dport or tcp_dport or 53,
                    protocol="UDP/DNS" if udp_sport else "TCP/DNS",
                    detection_layer="tshark-dns",
                )
            elif tls_sni:
                self.inspect_event(
                    domain=tls_sni,
                    dst_ip=ip_dst,
                    src_port=tcp_sport,
                    dst_port=tcp_dport or 443,
                    protocol="TCP/TLS-SNI",
                    detection_layer="tshark-tls-sni",
                )
            elif ip_dst:
                self.inspect_event(
                    domain=None,
                    dst_ip=ip_dst,
                    src_port=tcp_sport or udp_sport,
                    dst_port=tcp_dport or udp_dport,
                    protocol="TCP" if tcp_sport else "UDP",
                    detection_layer="tshark-ip",
                )
        except Exception:
            # Never allow a malformed packet line to crash the monitor thread (OWASP #29)
            pass

    def _run_socket_and_dnscache_loop(self) -> None:
        """
        Complementary detection layer:
        1. Polls active outbound sockets via psutil to attribute direct-IP C2 connections to exact PIDs.
        2. Polls Windows DNS Resolver Cache (`ipconfig /displaydns`) for newly resolved domains.
        """
        ipconfig_path = find_verified_ipconfig()
        last_dnscache_poll = 0.0

        while not self._stop_event.is_set():
            try:
                # 1. Check active outbound sockets for malicious IPs
                active_conns = self._process_mapper.get_active_outbound_connections()
                for proto, lport, rip, rport, proc_info in active_conns:
                    if is_public_routable_ip(rip):
                        self.inspect_event(
                            domain=None,
                            dst_ip=rip,
                            src_port=lport,
                            dst_port=rport,
                            protocol=proto.upper(),
                            detection_layer="psutil-socket",
                            explicit_process=proc_info,
                        )

                # 2. Check Windows DNS Resolver Cache every 2.0 seconds
                now = time.monotonic()
                if ipconfig_path and (now - last_dnscache_poll) >= 2.0:
                    last_dnscache_poll = now
                    self._poll_windows_dns_cache(ipconfig_path)

            except Exception:
                pass

            self._stop_event.wait(1.0)

    def _poll_windows_dns_cache(self, ipconfig_path: str) -> None:
        """
        Inspect Windows DNS Client cache (`ipconfig /displaydns`) for any newly resolved domains.
        """
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        try:
            res = subprocess.run(
                [ipconfig_path, "/displaydns"],
                shell=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=4.0,
                creationflags=creationflags,
                check=False,
            )
        except Exception:
            return

        if not res.stdout:
            return

        current_domains: Set[str] = set()
        for raw_line in res.stdout.splitlines():
            line = raw_line.strip()
            if "Record Name" in line and ":" in line:
                candidate = line.split(":", 1)[1].strip()
                norm = normalize_and_validate_domain(candidate)
                if norm:
                    current_domains.add(norm)

        if not self._baseline_initialized:
            # Record pre-existing DNS cache entries at startup to avoid old false alerts,
            # EXCEPT always alert if a canary or custom domain is actively queried after start.
            self._seen_dnscache_baseline = set(current_domains)
            self._baseline_initialized = True
            return

        new_domains = current_domains - self._seen_dnscache_baseline
        # Bound baseline set size (OWASP #49)
        if len(self._seen_dnscache_baseline) > 10_000:
            self._seen_dnscache_baseline.clear()
        self._seen_dnscache_baseline.update(current_domains)

        for dom in new_domains:
            self.inspect_event(
                domain=dom,
                dst_ip="",
                src_port=0,
                dst_port=53,
                protocol="OS-DNS-Cache",
                detection_layer="windows-dnscache",
                explicit_process=UNKNOWN_PROCESS,
            )
