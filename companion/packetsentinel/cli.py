"""
Command-Line Interface & Live Monitor Entrypoint for PacketSentinel.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import List, Optional

from . import __version__
from .capture import PacketSentinelMonitor
from .config import HELP_ISSUES_URL, AppConfig
from .egress_guard import engage_runtime_network_lockdown
from .mcp_server import run_mcp_stdio_server
from .notifier import AlertNotifier
from .process_mapper import ProcessInfo, ProcessMapper
from .security import validate_https_feed_url
from .setup_wizard import run_interactive_setup
from .threat_intel import ThreatIntelEngine, ThreatMatch


BANNER = r"""
======================================================================
  ____            _        _   ____             _   _            _
 |  _ \ __ _  ___| | _____| |_/ ___|  ___ _ __ | |_(_)_ __   ___| |
 | |_) / _` |/ __| |/ / _ \ __\___ \ / _ \ '_ \| __| | '_ \ / _ \ |
 |  __/ (_| | (__|   <  __/ |_ ___) |  __/ | | | |_| | | | |  __/ |
 |_|   \__,_|\___|_|\_\___|\__|____/ \___|_| |_|\__|_|_| |_|\___|_|

  Open-Source Windows Packet & Sketchy DNS Threat Monitor (v{version})
======================================================================
""".strip("\n")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="packetsentinel",
        description="Real-time Windows packet & sketchy DNS monitor using Wireshark/tshark and open-source threat feeds.",
    )
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Run the interactive step-by-step installation, explanation, and self-test wizard.",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Accept default prompts automatically when running --setup in automated scripts.",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Run startup health checks (Wireshark/tshark, Npcap, interfaces, and threat feed counts) and exit.",
    )
    parser.add_argument(
        "--update-feeds",
        action="store_true",
        help="Force download/refresh all HTTPS threat intelligence feeds and exit.",
    )
    parser.add_argument(
        "--check",
        metavar="DOMAIN_OR_IP",
        help="Check whether a domain name or IP address is flagged in the threat feeds and exit.",
    )
    parser.add_argument(
        "--add-domain",
        metavar="DOMAIN_OR_IP",
        help="Add a sketchy domain or public IP to your local blocklist and exit.",
    )
    parser.add_argument(
        "--add-feed",
        metavar="HTTPS_URL",
        help="Add a custom HTTPS threat feed URL (e.g., a GitHub raw blocklist URL) to config.json.",
    )
    parser.add_argument(
        "--test-alert",
        action="store_true",
        help="Trigger a safe simulated sketchy DNS alert to verify Windows Toast Notifications and audit logging.",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=0,
        metavar="SECONDS",
        help="Optional duration in seconds to run the live monitor before exiting cleanly (0 = run indefinitely).",
    )
    parser.add_argument(
        "--no-toast",
        action="store_true",
        help="Disable Windows desktop toast popups (log alerts to console and JSONL file only).",
    )
    parser.add_argument(
        "--mcp",
        action="store_true",
        help="Run the read-only, Pre-Model Privacy & DLP-scrubbed MCP server over stdio (JSON-RPC 2.0).",
    )
    parser.add_argument(
        "--mcp-workspace",
        metavar="DIR",
        default=None,
        help="Workspace root directory allowed for sanitized MCP file inspection (defaults to CWD).",
    )
    return parser


def print_status_report(config: AppConfig, monitor: PacketSentinelMonitor, feed_stats: dict[str, int]) -> None:
    health = monitor.get_health_status()
    print(BANNER.format(version=__version__))
    print(f"  App Data Dir     : {config.app_dir}")
    print(f"  Audit Log File   : {config.log_dir / 'alerts.jsonl'}")
    print(f"  Custom Blocklist : {config.custom_blocklist_file}")
    print(f"  Wireshark tshark : {health.tshark_path or 'NOT FOUND (using Socket + DNS Cache fallback)'}")
    print(f"  Npcap Driver     : {'RUNNING' if health.npcap_running else 'NOT DETECTED'}")
    print(f"  Capture Adapters : {len(health.interfaces_detected)} active")
    for iface in health.interfaces_detected:
        print(f"    - {iface}")
    if not health.tshark_path or not health.npcap_running:
        print(f"  [!] Help & Setup : Run 'python run_packetsentinel.py --setup' or visit {HELP_ISSUES_URL}")
    print("-" * 70)
    print(
        f"  Loaded Threat Indicators: {health.domain_indicators_loaded:,} sketchy domains | "
        f"{health.ip_indicators_loaded:,} malicious IPs"
    )
    for src_name, count in feed_stats.items():
        print(f"    * {src_name:<50} : {count:>8,}")
    print("=" * 70)


def main(argv: Optional[List[str]] = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    parser = build_arg_parser()
    args = parser.parse_args(argv)

    config = AppConfig.load()
    if args.no_toast:
        config.enable_desktop_toast = False

    if args.mcp:
        ws_root = Path(args.mcp_workspace).resolve() if args.mcp_workspace else Path.cwd().resolve()
        return run_mcp_stdio_server(config=config, workspace_root=ws_root)

    if args.setup:
        return run_interactive_setup(config, interactive=not args.non_interactive)

    if args.add_feed:
        try:
            validated_url = validate_https_feed_url(args.add_feed)
            if validated_url not in config.custom_feed_urls:
                config.custom_feed_urls.append(validated_url)
                config.save()
            print(f"[+] Added verified HTTPS threat feed: {validated_url}")
            return 0
        except ValueError as exc:
            print(f"[!] Rejected unsafe feed URL: {exc}", file=sys.stderr)
            return 1

    # On first interactive run with no flags, walk the user through the explanatory setup wizard
    is_default_monitor_launch = not any(
        (args.status, args.update_feeds, args.check, args.add_domain, args.test_alert)
    )
    if is_default_monitor_launch and not config.setup_completed and sys.stdin and sys.stdin.isatty():
        print("[*] First launch detected — starting interactive setup & verification wizard...\n")
        rc = run_interactive_setup(config, interactive=not args.non_interactive)
        if rc != 0:
            return rc
        print()

    threat_engine = ThreatIntelEngine(config)
    process_mapper = ProcessMapper()
    notifier = AlertNotifier(config)
    monitor = PacketSentinelMonitor(
        config=config,
        threat_engine=threat_engine,
        process_mapper=process_mapper,
        notifier=notifier,
    )

    if args.add_domain:
        try:
            added = threat_engine.add_custom_indicator(args.add_domain)
            print(f"[+] Added '{added}' to custom blocklist ({config.custom_blocklist_file})")
            return 0
        except ValueError as exc:
            print(f"[!] Invalid indicator: {exc}", file=sys.stderr)
            return 1

    print("[*] Loading threat intelligence feeds from local cache...")
    feed_stats = threat_engine.load_or_update_feeds(
        force_network_update=bool(args.update_feeds),
        offline_only=not bool(args.update_feeds),
    )

    if args.update_feeds:
        print_status_report(config, monitor, feed_stats)
        print("[+] All threat feeds updated and verified.")
        return 0

    if args.status:
        print_status_report(config, monitor, feed_stats)
        return 0

    if args.check:
        target = args.check.strip()
        match = threat_engine.check_domain(target) or threat_engine.check_ip(target)
        if match:
            print(
                f"[!] FLAGGED: '{target}' matched rule '{match.matched_rule}' "
                f"from [{match.source_feed}] ({match.match_type})"
            )
            return 2
        print(
            f"[+] CLEAN: '{target}' was not found in {threat_engine.domain_count:,} domains "
            f"or {threat_engine.ip_count:,} IPs."
        )
        return 0

    if args.test_alert:
        print_status_report(config, monitor, feed_stats)
        print("[*] Dispatching safe test alert (Windows Toast Notification + Audit Log)...")
        test_match = ThreatMatch(
            indicator="sketchy-canary.example.com",
            matched_rule="sketchy-canary.example.com",
            source_feed="PacketSentinel Canary Test Feed",
            match_type="domain_exact",
        )
        test_proc = ProcessInfo(
            pid=os.getpid(),
            name="demo-suspicious-client.exe",
            exe=sys.executable,
            is_self=False,
        )
        notifier.notify_match(
            match=test_match,
            process=test_proc,
            protocol="UDP/DNS",
            dst_ip="93.184.216.34",
            dst_port=53,
            detection_layer="self-test",
            bypass_cooldown=True,
        )
        time.sleep(2.5)
        notifier.close()
        print(f"[+] Test alert written to: {config.log_dir / 'alerts.jsonl'}")
        return 0

    print_status_report(config, monitor, feed_stats)
    engage_runtime_network_lockdown()
    print("[*] Zero-Outbound Egress Airlock ACTIVE (PEP 578 socket/HTTP/ctypes lockdown engaged).")
    print("[*] Live monitoring ACTIVE. Watching DNS queries, TLS SNI, and outbound connections...")
    print("[*] Tip: Test anytime in another terminal with: nslookup sketchy-canary.example.com")
    print(f"[*] Need help? See SETUP_AND_TROUBLESHOOTING.md or {HELP_ISSUES_URL}")
    print("[*] Press Ctrl+C to stop.\n")

    stop_requested = False

    def _sig_handler(signum, frame):
        nonlocal stop_requested
        stop_requested = True

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    monitor.start()
    start_ts = time.monotonic()
    last_feed_refresh = time.monotonic()

    try:
        while not stop_requested:
            time.sleep(0.5)
            elapsed = time.monotonic() - start_ts
            if args.duration > 0 and elapsed >= args.duration:
                break

            if (time.monotonic() - last_feed_refresh) >= config.cache_ttl_seconds:
                last_feed_refresh = time.monotonic()
                threat_engine.load_or_update_feeds(force_network_update=False, offline_only=True)
    except KeyboardInterrupt:
        pass
    finally:
        print("\n[*] Stopping PacketSentinel capture engines cleanly...")
        monitor.stop()
        notifier.close()
        print(
            f"[+] Session summary: {monitor.packets_inspected:,} events inspected "
            f"(DNS: {monitor.dns_queries_seen:,}, TLS SNI: {monitor.tls_sni_seen:,}) | "
            f"Alerts emitted: {notifier.total_alerts_emitted:,}"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
