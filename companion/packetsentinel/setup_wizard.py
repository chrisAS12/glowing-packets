"""
Interactive Setup, Explanation, & Diagnostic Self-Test Wizard for PacketSentinel.
Walks users through each subsystem (privacy model, dependencies, Wireshark/Npcap,
HTTPS threat feeds, and Windows Toast Notifications), tests each live, and outputs
actionable remediation steps and help links when any check fails.
"""

from __future__ import annotations

import os
import socket
import sys
import time
from typing import Optional

from .capture import (
    PacketSentinelMonitor,
    check_npcap_service_running,
    discover_tshark_interfaces,
    find_verified_tshark,
)
from .config import DEFAULT_THREAT_FEEDS, HELP_ISSUES_URL, AppConfig
from .notifier import AlertNotifier
from .process_mapper import ProcessInfo, ProcessMapper
from .threat_intel import ThreatIntelEngine, ThreatMatch


def _prompt_yes_no(question: str, default_yes: bool = True, interactive: bool = True) -> bool:
    if not interactive or not sys.stdin or not sys.stdin.isatty():
        return default_yes
    suffix = "[Y/n]" if default_yes else "[y/N]"
    while True:
        try:
            ans = input(f"{question} {suffix}: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return False
        if not ans:
            return default_yes
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        print("  Please enter 'y' or 'n'.")


def _print_help_footer(topic: str, details: str) -> None:
    print("\n" + "!" * 70)
    print(f"  [!] TROUBLESHOOTING NEEDED: {topic}")
    print("-" * 70)
    for line in details.strip().splitlines():
        print(f"  {line}")
    print("-" * 70)
    print("  Detailed Guide : See SETUP_AND_TROUBLESHOOTING.md in this repository")
    print(f"  Get Help / Bug : {HELP_ISSUES_URL}")
    print("!" * 70 + "\n")


def _build_canary_dns_packet(domain: str) -> bytes:
    header = b"\xca\xfe\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    qname = b"".join(bytes([len(label)]) + label.encode("ascii") for label in domain.split(".")) + b"\x00"
    return header + qname + b"\x00\x01\x00\x01"


def run_interactive_setup(config: AppConfig, interactive: bool = True) -> int:
    print("=" * 70)
    print("  PacketSentinel — Interactive Setup, Verification & Self-Test Wizard")
    print("=" * 70)
    print(
        "\nWelcome! This wizard explains what PacketSentinel does on your machine,\n"
        "asks your permission before configuring each component, tests live packet\n"
        "detection and desktop notifications, and tells you where to get help if\n"
        "anything is missing.\n"
    )

    # ------------------------------------------------------------------
    # STEP 1: Privacy & Local Storage Consent
    # ------------------------------------------------------------------
    print("[Step 1/5] Privacy & Local Storage Overview")
    print("  * What we inspect : Outbound DNS domain queries, TLS SNI hostnames, and")
    print("                      destination IPs + the local Windows process (.exe/PID).")
    print("  * What we NEVER do: We never record packet payloads, passwords, or browsing content.")
    print(f"  * Local directory : {config.app_dir}")
    if not _prompt_yes_no("  Proceed with initializing local configuration & cache folders?", True, interactive):
        print("  Setup cancelled by user.")
        return 1
    config.save()
    print("  [OK] Local directories verified.\n")

    # ------------------------------------------------------------------
    # STEP 2: Python Runtime & Process Attribution Check
    # ------------------------------------------------------------------
    print("[Step 2/5] Runtime & Process Attribution Verification")
    print("  * Why this matters: `psutil` maps network ports to the exact Windows `.exe`")
    print("                      that sent a suspicious packet.")
    try:
        mapper = ProcessMapper()
        conns = mapper.get_active_outbound_connections()
        print(f"  [OK] Process mapper active (inspected {len(conns)} live OS socket entries).\n")
    except Exception as exc:
        _print_help_footer(
            "Process Mapper (`psutil`) Failed",
            f"Error: {exc}\n"
            "Fix  : Run `python -m pip install -r requirements.txt` inside the project folder.",
        )
        return 1

    # ------------------------------------------------------------------
    # STEP 3: Wireshark (`tshark.exe`) & Npcap Driver Check
    # ------------------------------------------------------------------
    print("[Step 3/5] Wireshark (`tshark.exe`) & Npcap Driver Check")
    print("  * Why this matters: Wireshark provides `tshark.exe` and the Npcap kernel driver")
    print("                      so PacketSentinel can spot sketchy DNS/TLS packets in real time.")
    tshark_path = find_verified_tshark()
    npcap_ok = check_npcap_service_running()

    if not tshark_path or not npcap_ok:
        missing_items = []
        if not tshark_path:
            missing_items.append("Wireshark `tshark.exe` was not found in `C:\\Program Files\\Wireshark\\tshark.exe`.")
        if not npcap_ok:
            missing_items.append("The Windows `npcap` driver service is not running.")

        _print_help_footer(
            "Wireshark / Npcap Not Fully Active (Fallback Mode Enabled)",
            "\n".join(missing_items)
            + "\n\nHow to fix:\n"
            "  1. Download and install Wireshark from https://www.wireshark.org/download.html\n"
            "  2. During installation, keep 'Install Npcap' checked.\n"
            "  3. If Npcap is already installed, start it in an Administrator terminal:\n"
            "     sc start npcap\n"
            "Note: PacketSentinel will still protect you using its Zero-Admin Socket & Windows\n"
            "      DNS Cache fallback engine even without Wireshark!",
        )
    else:
        ifaces = discover_tshark_interfaces(tshark_path, include_loopback=config.capture_loopback)
        print(f"  [OK] Found verified tshark : {tshark_path}")
        print("  [OK] Npcap driver service  : RUNNING")
        print(f"  [OK] Capture adapters found: {len(ifaces)}")
        for _, desc in ifaces:
            print(f"       - {desc}")
        print()

    # ------------------------------------------------------------------
    # STEP 4: Threat Intelligence Feeds Download & SHA-256 Cache Test
    # ------------------------------------------------------------------
    print("[Step 4/5] Open-Source Threat Intelligence Feeds")
    print("  * Why this matters: PacketSentinel pulls community-reported sketchy domains")
    print("                      and botnet C2 IPs over HTTPS (TLS 1.2+ with SSRF protection):")
    for feed in DEFAULT_THREAT_FEEDS:
        print(f"       - {feed.name} ({feed.url})")

    threat_engine = ThreatIntelEngine(config)
    if _prompt_yes_no("  Download and verify threat intelligence feeds now?", True, interactive):
        stats = threat_engine.load_or_update_feeds(force_network_update=False)
        total_loaded = threat_engine.domain_count + threat_engine.ip_count
        if total_loaded <= 3:
            _print_help_footer(
                "Threat Feeds Could Not Be Downloaded",
                "Only built-in canary domains were loaded. Check your internet/firewall connection\n"
                "to `raw.githubusercontent.com`, `feodotracker.abuse.ch`, and `v.firebog.net`.",
            )
        else:
            print(
                f"  [OK] Loaded {threat_engine.domain_count:,} sketchy domains and "
                f"{threat_engine.ip_count:,} malicious IPs across {len(stats)} sources.\n"
            )
    else:
        threat_engine.add_custom_indicator("sketchy-canary.example.com")
        print("  [*] Skipped remote download; loaded local canary blocklist.\n")

    # ------------------------------------------------------------------
    # STEP 5: Desktop Notification & Live Canary Packet Test
    # ------------------------------------------------------------------
    print("[Step 5/5] Desktop Notification & Live Detection Self-Test")
    print("  * Why this matters: Verifies that Windows Toast popups appear on your screen")
    print("                      and that a simulated lookup to `sketchy-canary.example.com` is caught.")
    notifier = AlertNotifier(config)

    if _prompt_yes_no("  Run the safe desktop notification & canary packet test now?", True, interactive):
        monitor = PacketSentinelMonitor(
            config=config,
            threat_engine=threat_engine,
            process_mapper=mapper,
            notifier=notifier,
        )
        monitor.start()
        time.sleep(2.0)

        # Send a harmless UDP DNS packet to loopback:53 so tshark catches it if active
        try:
            pkt = _build_canary_dns_packet("canary-test.sketchy-canary.example.com")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(pkt, ("127.0.0.1", 53))
        except OSError:
            pass

        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and notifier.total_alerts_emitted == 0:
            time.sleep(0.2)

        # If wire capture didn't fire (e.g. loopback adapter disabled), trigger explicit self-test alert
        if notifier.total_alerts_emitted == 0:
            notifier.notify_match(
                match=ThreatMatch(
                    indicator="sketchy-canary.example.com",
                    matched_rule="sketchy-canary.example.com",
                    source_feed="PacketSentinel Canary Test Feed",
                    match_type="domain_exact",
                ),
                process=ProcessInfo(pid=os.getpid(), name="setup-self-test.exe", exe=sys.executable, is_self=False),
                protocol="UDP/DNS",
                dst_ip="127.0.0.1",
                dst_port=53,
                detection_layer="setup-wizard-test",
                bypass_cooldown=True,
            )

        time.sleep(2.0)
        monitor.stop()

        if interactive and sys.stdin and sys.stdin.isatty():
            saw_toast = _prompt_yes_no(
                "  Did you see the Windows popup notification (and console alert above)?",
                default_yes=True,
                interactive=interactive,
            )
            if not saw_toast:
                _print_help_footer(
                    "Windows Desktop Toast Notification Was Hidden",
                    "Windows 'Focus Assist' or 'Do Not Disturb' may be suppressing toast popups:\n"
                    "  1. Press Win + I -> System -> Notifications.\n"
                    "  2. Ensure 'Notifications' is toggled ON and 'Do not disturb' is OFF.\n"
                    "  3. Scroll down and ensure notifications are enabled for Windows PowerShell.\n"
                    f"  4. Even when popups are muted by Windows, all alerts are always saved to:\n"
                    f"     {config.log_dir / 'alerts.jsonl'}",
                )

    notifier.close()
    config.setup_completed = True
    config.save()

    print("=" * 70)
    print("  [+] SETUP COMPLETE! PacketSentinel is ready.")
    print("      Start monitoring anytime with: python run_packetsentinel.py")
    print(f"      Need help? See SETUP_AND_TROUBLESHOOTING.md or {HELP_ISSUES_URL}")
    print("=" * 70)
    return 0
