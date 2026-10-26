"""
Native Offline Desktop UI for SentinelWire.

Provides:
1. Sleek, high-contrast dark dashboard (Linear / Portmaster modern aesthetic).
2. Vertical sidebar navigation with live telemetry cards.
3. Air-gapped Voice AI Dictation with persistent state machine and quick prompt testing.
4. 5-Gate DLP Pre-Model Privacy Scrubber with granular gate toggles.
5. Wire & LOTS Monitor with interactive packet viewer.
6. Target Process Watchdog & Child lineage inspector.
7. Encrypted Settings Vault (Windows DPAPI) and threat intelligence feed management.
8. User-deletable diagnostics & forum-safe anonymized export.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import subprocess
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict, List, Optional

from .config import AppConfig, get_app_data_dir
from .diagnostic_logger import (
    generate_anonymized_diagnostic_bundle,
    get_incident_dir,
    get_log_dir,
    list_kill_switch_incidents,
    purge_all_local_data,
    record_kill_switch_incident,
    setup_diagnostic_logging,
)
from .egress_guard import engage_runtime_network_lockdown
from .live_monitor_service import AlertRow, LiveMonitorService, MonitorSnapshot
from .mcp_privacy import PrivacySanitizer
from .process_watchdog import inspect_child_lineage
from .vault import EncryptedVaultManager, VaultSettings
from .voice_engine import (
    MicrophoneRecorder,
    OfflineTranscriber,
    VoiceEngineError,
    check_voice_status,
    get_model_dir,
)

logger = logging.getLogger("sentinelwire.ui")


# Theme Palette: Modern Linear / Obsidian Charcoal Dark Mode
BG_CANVAS = "#09090b"          # Pure dark charcoal background
BG_SURFACE = "#121215"         # Sidebar & container surface
BG_CARD = "#18181b"            # Cards, editors, panels
BG_ELEVATED = "#222227"        # Headers, buttons, toolbars
BORDER_COLOR = "#2e2e38"       # Crisp, high-contrast border
BORDER_FOCUS = "#38bdf8"       # Active focus cyan border
TEXT_TITLE = "#ffffff"         # Pure white headings
TEXT_BODY = "#e4e4e7"          # Crisp silver body text (high readability!)
TEXT_MUTED = "#a1a1aa"         # Readable muted descriptions (never muddy!)
TEXT_HINT = "#71717a"          # Subtle metadata
ACCENT_BLUE = "#0284c7"        # Electric Sentinel Blue
ACCENT_HOVER = "#0369a1"       # Interactive hover state
ACCENT_EMERALD = "#10b981"     # Verified safe / DLP passed
ALERT_RED = "#ef4444"          # Threat / kill switch coral


class PacketSentinelDesktopApp:
    """Modern dark-mode desktop GUI for SentinelWire with 100% offline airlock."""

    def __init__(self, config: Optional[AppConfig] = None, parent_root: Optional[tk.Tk] = None) -> None:
        self.config = config or AppConfig()
        setup_diagnostic_logging(level=getattr(self.config, "log_level", "INFO"))

        self.vault_mgr = EncryptedVaultManager()
        self.vault_settings = self.vault_mgr.load_settings()
        self.sanitizer = PrivacySanitizer(
            extra_redacted_names=self.vault_settings.custom_names,
            categories=self.vault_settings.redaction_categories(),
        )

        self._voice_recorder: Optional[MicrophoneRecorder] = None
        self._voice_transcriber = OfflineTranscriber(
            model_dir=get_model_dir(self.config.app_dir),
            model_name="base",
        )
        self._is_recording = False
        self._record_start_time = 0.0
        self._record_timer_id: Optional[str] = None
        self._audio_stream = None

        self._monitor_service = LiveMonitorService(self.config, lock_network_on_start=False)
        self._telemetry_timer_id: Optional[str] = None
        self._threat_rows_seen: Set[str] = set()

        self._packet_count = 0
        self._threat_count = 0
        self._nav_buttons: List[tk.Button] = []

        self.root = parent_root or tk.Tk()
        self.root.title("SentinelWire — Desktop Security & Privacy Airlock")
        self.root.geometry("1120x780")
        self.root.minsize(920, 640)
        self.root.configure(bg=BG_CANVAS)

        self._configure_styles()
        self._build_header()
        self._build_metrics_strip()
        self._build_main_container()
        self._build_footer()

        # Keyboard shortcuts (Spacebar for Push-to-Talk)
        self.root.bind("<space>", self._on_space_pressed)

        # Start periodic telemetry refresh
        self._schedule_telemetry_poll()

        # Handle close: minimize to background/tray rather than accidental kill
        self.root.protocol("WM_DELETE_WINDOW", self._on_window_close)

    def _configure_styles(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")

        # Color locks for dark modern aesthetic
        style.configure("TNotebook", background=BG_CANVAS, borderwidth=0)
        style.layout("TNotebook.Tab", [])

        # Clean Treeview styling with high contrast and tall rows
        style.configure(
            "Treeview",
            background=BG_CARD,
            foreground=TEXT_BODY,
            fieldbackground=BG_CARD,
            rowheight=30,
            borderwidth=0,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Treeview.Heading",
            background=BG_ELEVATED,
            foreground=TEXT_TITLE,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            padding=[8, 6],
        )
        style.map(
            "Treeview",
            background=[("selected", ACCENT_BLUE)],
            foreground=[("selected", "#ffffff")],
        )

        style.configure(
            "TCombobox",
            background=BG_CARD,
            foreground=TEXT_TITLE,
            fieldbackground=BG_CARD,
            selectbackground=ACCENT_BLUE,
            selectforeground="#ffffff",
            arrowcolor=TEXT_TITLE,
        )

        style.configure(
            "Vertical.TScrollbar",
            troughcolor=BG_CANVAS,
            background=BG_ELEVATED,
            arrowsize=0,
            borderwidth=0,
        )

    def _build_header(self) -> None:
        header = tk.Frame(self.root, bg=BG_SURFACE, height=66, padx=20, pady=10)
        header.pack(fill=tk.X, side=tk.TOP)

        title_frame = tk.Frame(header, bg=BG_SURFACE)
        title_frame.pack(side=tk.LEFT)

        brand_row = tk.Frame(title_frame, bg=BG_SURFACE)
        brand_row.pack(anchor=tk.W)

        title_lbl = tk.Label(
            brand_row,
            text="🛡️ SentinelWire",
            font=("Segoe UI", 16, "bold"),
            fg=TEXT_TITLE,
            bg=BG_SURFACE,
        )
        title_lbl.pack(side=tk.LEFT)

        ver_badge = tk.Label(
            brand_row,
            text="v1.0 • Offline",
            font=("Segoe UI", 8, "bold"),
            fg=BORDER_FOCUS,
            bg=BG_ELEVATED,
            padx=8,
            pady=2,
        )
        ver_badge.pack(side=tk.LEFT, padx=(8, 0))

        sub_lbl = tk.Label(
            title_frame,
            text="Zero-Outbound Micro-EDR • Pre-Model Privacy Airlock • Air-Gapped Whisper Engine",
            font=("Segoe UI", 9),
            fg=TEXT_MUTED,
            bg=BG_SURFACE,
        )
        sub_lbl.pack(anchor=tk.W, pady=(2, 0))

        action_frame = tk.Frame(header, bg=BG_SURFACE)
        action_frame.pack(side=tk.RIGHT)

        badge = tk.Label(
            action_frame,
            text="🟢 AIRLOCK ACTIVE (0 OUTBOUND)",
            font=("Segoe UI", 9, "bold"),
            fg=ACCENT_EMERALD,
            bg="#064e3b",
            padx=12,
            pady=5,
            relief=tk.FLAT,
        )
        badge.pack(side=tk.LEFT, padx=(0, 12))

        kill_btn = tk.Button(
            action_frame,
            text="🚨 EMERGENCY KILL SWITCH",
            font=("Segoe UI", 9, "bold"),
            fg="#ffffff",
            bg=ALERT_RED,
            activebackground="#b91c1c",
            activeforeground="#ffffff",
            padx=12,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._emergency_kill,
        )
        kill_btn.pack(side=tk.LEFT)

    def _build_metrics_strip(self) -> None:
        strip = tk.Frame(self.root, bg=BG_CANVAS, padx=16, pady=8)
        strip.pack(fill=tk.X)

        cards_data = [
            ("PACKETS MONITORED", "0", BORDER_FOCUS, "Live Wire Sniffer", 2),
            ("THREATS DETECTED", "0", ACCENT_EMERALD, "Click to View Details", 2),
            ("PRE-MODEL DLP", "5-Gate Active", "#c084fc", "PII, IDs, Tokens Scrubbed", 1),
            ("ENCRYPTED VAULT", "DPAPI Protected", ACCENT_EMERALD, "Hardware Encrypted", 3),
        ]

        self.metric_value_labels: List[tk.Label] = []

        for idx, (title, val, color, sub, target_tab) in enumerate(cards_data):
            card = tk.Frame(
                strip,
                bg=BG_CARD,
                highlightbackground=BORDER_COLOR,
                highlightthickness=1,
                padx=14,
                pady=8,
                cursor="hand2",
            )
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)
            card.bind("<Button-1>", lambda e, t=target_tab: self._select_nav(t))

            lbl_t = tk.Label(card, text=title, font=("Segoe UI", 8, "bold"), fg=TEXT_MUTED, bg=BG_CARD)
            lbl_t.pack(anchor=tk.W)
            lbl_t.bind("<Button-1>", lambda e, t=target_tab: self._select_nav(t))

            val_lbl = tk.Label(card, text=val, font=("Segoe UI", 13, "bold"), fg=color, bg=BG_CARD)
            val_lbl.pack(anchor=tk.W, pady=(1, 1))
            val_lbl.bind("<Button-1>", lambda e, t=target_tab: self._select_nav(t))
            self.metric_value_labels.append(val_lbl)

            lbl_s = tk.Label(card, text=sub, font=("Segoe UI", 8), fg=TEXT_HINT, bg=BG_CARD)
            lbl_s.pack(anchor=tk.W)
            lbl_s.bind("<Button-1>", lambda e, t=target_tab: self._select_nav(t))

    def _build_main_container(self) -> None:
        container = tk.Frame(self.root, bg=BG_CANVAS)
        container.pack(fill=tk.BOTH, expand=True, padx=16, pady=(4, 6))

        # Left Vertical Navigation Sidebar
        sidebar = tk.Frame(container, bg=BG_SURFACE, width=220, highlightbackground=BORDER_COLOR, highlightthickness=1)
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        sidebar.pack_propagate(False)

        tk.Label(
            sidebar,
            text="NAVIGATION",
            font=("Segoe UI", 8, "bold"),
            fg=TEXT_MUTED,
            bg=BG_SURFACE,
            padx=12,
            pady=8,
        ).pack(anchor=tk.W)

        nav_items = [
            ("🏠  Mission Control", 0),
            ("🛡️  Deep Privacy Airlock", 1),
            ("📡  Wire & Process Inspector", 2),
            ("⚙️  Settings & Security Vault", 3),
            ("📖  Documentation & AI Guides", 4),
        ]

        for text, idx in nav_items:
            btn = tk.Button(
                sidebar,
                text=text,
                font=("Segoe UI", 10, "bold" if idx == 0 else "normal"),
                anchor="w",
                bg=BG_CARD if idx == 0 else BG_SURFACE,
                fg=BORDER_FOCUS if idx == 0 else TEXT_MUTED,
                activebackground=BG_ELEVATED,
                activeforeground=TEXT_TITLE,
                padx=12,
                pady=9,
                relief=tk.FLAT,
                cursor="hand2",
                command=lambda i=idx: self._select_nav(i),
            )
            btn.pack(fill=tk.X, padx=6, pady=2)
            self._nav_buttons.append(btn)

        # Bottom of sidebar: AppData quick link
        side_footer = tk.Frame(sidebar, bg=BG_SURFACE)
        side_footer.pack(side=tk.BOTTOM, fill=tk.X, padx=6, pady=8)

        appdata_btn = tk.Button(
            side_footer,
            text="📁 Open Local AppData",
            font=("Segoe UI", 8),
            bg=BG_CARD,
            fg=TEXT_MUTED,
            activebackground=BG_ELEVATED,
            activeforeground=TEXT_TITLE,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._open_appdata_dir,
        )
        appdata_btn.pack(fill=tk.X, pady=2)

        # Right Content View Area (driven by ttk.Notebook for full test compatibility)
        self.notebook = ttk.Notebook(container)
        self.notebook.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Tab 0: Mission Control (Cockpit Dashboard covering primary developer actions)
        self.tab_mission_control = tk.Frame(self.notebook, bg=BG_CANVAS)
        self.notebook.add(self.tab_mission_control, text="Mission Control")
        self._build_mission_control_tab()

        # Tab 1: AI Privacy Airlock (Unified Speech & Text DLP)
        self.tab_airlock = tk.Frame(self.notebook, bg=BG_CANVAS)
        self.notebook.add(self.tab_airlock, text="AI Privacy Airlock")
        self.tab_voice = self.tab_airlock
        self.tab_privacy = self.tab_airlock
        self._build_airlock_tab()

        # Tab 2: Live Threat Monitor (Wire Sniffer, Alerts, and Process Watchdog)
        self.tab_monitor = tk.Frame(self.notebook, bg=BG_CANVAS)
        self.notebook.add(self.tab_monitor, text="Live Threat Monitor")
        self.tab_watchdog = self.tab_monitor
        self._build_monitor_tab()

        # Tab 3: Settings & Security Vault (DPAPI Vault, 5-Gate Toggles, Alerts, Logs)
        self.tab_settings = tk.Frame(self.notebook, bg=BG_CANVAS)
        self.notebook.add(self.tab_settings, text="Settings & Security Vault")
        self.tab_diagnostics = self.tab_settings
        self._build_settings_tab()

        # Tab 4: Documentation & AI Guides
        self.tab_docs = tk.Frame(self.notebook, bg=BG_CANVAS)
        self.notebook.add(self.tab_docs, text="Documentation & AI Guides")
        self._build_documentation_tab()

    def _select_nav(self, index: int) -> None:
        self.notebook.select(index)
        for i, btn in enumerate(self._nav_buttons):
            if i == index:
                btn.config(bg=BG_CARD, fg=BORDER_FOCUS, font=("Segoe UI", 10, "bold"))
            else:
                btn.config(bg=BG_SURFACE, fg=TEXT_MUTED, font=("Segoe UI", 10, "normal"))

    def _build_mission_control_tab(self) -> None:
        mc_container = tk.Frame(self.tab_mission_control, bg=BG_CANVAS, padx=14, pady=12)
        mc_container.pack(fill=tk.BOTH, expand=True)

        # Cockpit Banner
        cockpit_header = tk.Frame(mc_container, bg=BG_SURFACE, padx=16, pady=10, highlightbackground=BORDER_COLOR, highlightthickness=1)
        cockpit_header.pack(fill=tk.X, pady=(0, 10))

        h_left = tk.Frame(cockpit_header, bg=BG_SURFACE)
        h_left.pack(side=tk.LEFT)

        tk.Label(
            h_left,
            text="🏠 Mission Control Cockpit",
            font=("Segoe UI", 12, "bold"),
            fg=TEXT_TITLE,
            bg=BG_SURFACE,
        ).pack(anchor=tk.W)

        tk.Label(
            h_left,
            text="Unified developer privacy airlock, voice dictation, live packet sniffer, and process watchdog.",
            font=("Segoe UI", 9),
            fg=TEXT_MUTED,
            bg=BG_SURFACE,
        ).pack(anchor=tk.W, pady=(2, 0))

        h_right = tk.Frame(cockpit_header, bg=BG_SURFACE)
        h_right.pack(side=tk.RIGHT)

        self.mc_sniffer_badge = tk.Label(
            h_right,
            text="🔴 SNIFFER STOPPED",
            font=("Segoe UI", 9, "bold"),
            fg="#fca5a5",
            bg="#7f1d1d",
            padx=10,
            pady=4,
        )
        self.mc_sniffer_badge.pack(side=tk.LEFT, padx=(0, 8))

        self.mc_sniffer_btn = tk.Button(
            h_right,
            text="▶️ Start Sniffer",
            font=("Segoe UI", 9, "bold"),
            bg=ACCENT_BLUE,
            fg="#ffffff",
            activebackground=ACCENT_HOVER,
            activeforeground="#ffffff",
            padx=12,
            pady=4,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._toggle_sniffer,
        )
        self.mc_sniffer_btn.pack(side=tk.LEFT)

        # Top Card: Quick Voice & Prompt Scrubber Card
        top_card = tk.Frame(mc_container, bg=BG_CARD, padx=16, pady=12, highlightbackground=BORDER_COLOR, highlightthickness=1)
        top_card.pack(fill=tk.X, pady=(0, 10))

        # Row 1: Voice Dictation & Status
        v_row = tk.Frame(top_card, bg=BG_CARD)
        v_row.pack(fill=tk.X, pady=(0, 8))

        self.mc_voice_btn = tk.Button(
            v_row,
            text="🎙️  Start Dictation (Spacebar)",
            font=("Segoe UI", 10, "bold"),
            bg=ACCENT_BLUE,
            fg="#ffffff",
            activebackground=ACCENT_HOVER,
            activeforeground="#ffffff",
            padx=16,
            pady=6,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._toggle_voice_recording,
        )
        self.mc_voice_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.mc_voice_status_pill = tk.Label(
            v_row,
            text="🟢 AIRLOCK READY (OFFLINE)",
            font=("Segoe UI", 9, "bold"),
            fg=ACCENT_EMERALD,
            bg="#064e3b",
            padx=10,
            pady=3,
        )
        self.mc_voice_status_pill.pack(side=tk.LEFT, padx=(0, 10))

        self.mc_voice_feedback_lbl = tk.Label(
            v_row,
            text="Push-to-talk ready. Auto-stops on silence (~1.8s) or press Spacebar.",
            font=("Segoe UI", 9),
            fg=TEXT_MUTED,
            bg=BG_CARD,
        )
        self.mc_voice_feedback_lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)

        copy_mcp_latest_btn = tk.Button(
            v_row,
            text="📋 Copy Latest Prompt",
            font=("Segoe UI", 9),
            bg=BG_ELEVATED,
            fg=TEXT_TITLE,
            activebackground=BG_SURFACE,
            activeforeground="#ffffff",
            padx=10,
            pady=4,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._copy_output,
        )
        copy_mcp_latest_btn.pack(side=tk.RIGHT)

        # Row 2: Quick Prompt Input & DLP Scrub
        p_row = tk.Frame(top_card, bg=BG_CARD)
        p_row.pack(fill=tk.X, pady=(4, 0))

        tk.Label(
            p_row,
            text="Quick Prompt Scrubber:",
            font=("Segoe UI", 9, "bold"),
            fg=TEXT_TITLE,
            bg=BG_CARD,
        ).pack(side=tk.LEFT, padx=(0, 8))

        self.mc_quick_prompt_entry = tk.Entry(
            p_row,
            bg=BG_CANVAS,
            fg=TEXT_TITLE,
            insertbackground=BORDER_FOCUS,
            font=("Segoe UI", 10),
            relief=tk.FLAT,
            highlightbackground=BORDER_COLOR,
            highlightthickness=1,
        )
        self.mc_quick_prompt_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8), ipady=4)
        self.mc_quick_prompt_entry.bind("<Return>", lambda e: self._quick_scrub_prompt())

        scrub_btn = tk.Button(
            p_row,
            text="🧹 Scrub & Send to MCP",
            font=("Segoe UI", 9, "bold"),
            bg=ACCENT_BLUE,
            fg="#ffffff",
            activebackground=ACCENT_HOVER,
            activeforeground="#ffffff",
            padx=12,
            pady=4,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._quick_scrub_prompt,
        )
        scrub_btn.pack(side=tk.LEFT, padx=(0, 6))

        # Bottom Split Area: Left (Process Watchdog & AI) | Right (Live Threats)
        split_frame = tk.Frame(mc_container, bg=BG_CANVAS)
        split_frame.pack(fill=tk.BOTH, expand=True)

        # Left Column: Process Watchdog & AI Analyzer
        left_col = tk.Frame(split_frame, bg=BG_CARD, padx=14, pady=12, highlightbackground=BORDER_COLOR, highlightthickness=1)
        left_col.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 6))

        l_head = tk.Frame(left_col, bg=BG_CARD)
        l_head.pack(fill=tk.X, pady=(0, 6))

        tk.Label(
            l_head,
            text="👁️ Process Watchdog & AI Inspector",
            font=("Segoe UI", 10, "bold"),
            fg=TEXT_TITLE,
            bg=BG_CARD,
        ).pack(side=tk.LEFT)

        refresh_proc_btn = tk.Button(
            l_head,
            text="🔄 Refresh",
            font=("Segoe UI", 8),
            bg=BG_ELEVATED,
            fg=TEXT_MUTED,
            activebackground=BG_SURFACE,
            activeforeground=TEXT_TITLE,
            padx=6,
            pady=2,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._refresh_process_lists,
        )
        refresh_proc_btn.pack(side=tk.RIGHT)

        # Dropdown process selector row
        sel_row = tk.Frame(left_col, bg=BG_CARD)
        sel_row.pack(fill=tk.X, pady=(0, 8))

        tk.Label(
            sel_row,
            text="Select Process:",
            font=("Segoe UI", 9),
            fg=TEXT_MUTED,
            bg=BG_CARD,
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.mc_proc_combo = ttk.Combobox(
            sel_row,
            font=("Segoe UI", 9),
            state="normal",
            width=20,
        )
        candidates = self._get_running_process_candidates()
        self.mc_proc_combo["values"] = candidates
        if "python.exe" in candidates:
            self.mc_proc_combo.set("python.exe")
        elif candidates:
            self.mc_proc_combo.set(candidates[0])
        else:
            self.mc_proc_combo.set("python")
        self.mc_proc_combo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))

        insp_btn = tk.Button(
            sel_row,
            text="🔍 Inspect",
            font=("Segoe UI", 9, "bold"),
            bg=BG_ELEVATED,
            fg=TEXT_TITLE,
            activebackground=BG_SURFACE,
            activeforeground="#ffffff",
            padx=10,
            pady=3,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._inspect_mc_watchdog,
        )
        insp_btn.pack(side=tk.LEFT, padx=(0, 6))

        ai_btn = tk.Button(
            sel_row,
            text="🤖 Ask AI Safety",
            font=("Segoe UI", 9, "bold"),
            bg="#7c3aed",
            fg="#ffffff",
            activebackground="#6d28d9",
            activeforeground="#ffffff",
            padx=10,
            pady=3,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._analyze_process_with_ai,
        )
        ai_btn.pack(side=tk.LEFT)

        self.mc_watchdog_results = tk.Text(
            left_col,
            bg=BG_CANVAS,
            fg=TEXT_BODY,
            font=("Consolas", 9),
            relief=tk.FLAT,
            wrap=tk.WORD,
            height=10,
            highlightbackground=BORDER_COLOR,
            highlightthickness=1,
            padx=8,
            pady=6,
        )
        self.mc_watchdog_results.pack(fill=tk.BOTH, expand=True)

        # Right Column: Real-time Threat Alerts
        right_col = tk.Frame(split_frame, bg=BG_CARD, padx=14, pady=12, highlightbackground=BORDER_COLOR, highlightthickness=1)
        right_col.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(6, 0))

        r_head = tk.Frame(right_col, bg=BG_CARD)
        r_head.pack(fill=tk.X, pady=(0, 6))

        tk.Label(
            r_head,
            text="🚨 Live Threat Interceptor",
            font=("Segoe UI", 10, "bold"),
            fg=TEXT_TITLE,
            bg=BG_CARD,
        ).pack(side=tk.LEFT)

        canary_btn = tk.Button(
            r_head,
            text="🧪 Canary Test",
            font=("Segoe UI", 8),
            bg=BG_ELEVATED,
            fg=TEXT_MUTED,
            activebackground=BG_SURFACE,
            activeforeground=TEXT_TITLE,
            padx=6,
            pady=2,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._trigger_canary_alert,
        )
        canary_btn.pack(side=tk.RIGHT)

        explain_btn = tk.Button(
            r_head,
            text="ℹ️ Explain Threat",
            font=("Segoe UI", 8, "bold"),
            bg=ACCENT_BLUE,
            fg="#ffffff",
            activebackground=ACCENT_HOVER,
            activeforeground="#ffffff",
            padx=8,
            pady=2,
            relief=tk.FLAT,
            cursor="hand2",
            command=lambda: self._show_threat_explanation(),
        )
        explain_btn.pack(side=tk.RIGHT, padx=(0, 6))

        mc_tree_frame = tk.Frame(right_col, bg=BG_CANVAS, highlightthickness=1, highlightbackground=BORDER_COLOR)
        mc_tree_frame.pack(fill=tk.BOTH, expand=True)

        cols = ("time", "indicator", "feed", "process", "layer")
        self.mc_alert_tree = ttk.Treeview(
            mc_tree_frame,
            columns=cols,
            show="headings",
            selectmode="browse",
            height=8,
        )
        self.mc_alert_tree.heading("time", text="Time (UTC)")
        self.mc_alert_tree.heading("indicator", text="Flagged Target")
        self.mc_alert_tree.heading("feed", text="Source Threat Feed")
        self.mc_alert_tree.heading("process", text="Attributed Process")
        self.mc_alert_tree.heading("layer", text="Layer")

        self.mc_alert_tree.column("time", width=80, anchor="w")
        self.mc_alert_tree.column("indicator", width=160, anchor="w")
        self.mc_alert_tree.column("feed", width=130, anchor="w")
        self.mc_alert_tree.column("process", width=90, anchor="w")
        self.mc_alert_tree.column("layer", width=60, anchor="center")

        mc_sb = ttk.Scrollbar(mc_tree_frame, orient="vertical", command=self.mc_alert_tree.yview)
        self.mc_alert_tree.configure(yscrollcommand=mc_sb.set)
        self.mc_alert_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        mc_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.mc_alert_tree.bind("<Double-1>", lambda e: self._show_threat_explanation())

    def _build_airlock_tab(self) -> None:
        banner = tk.Label(
            self.tab_airlock,
            text="🛡️ 100% Offline AI Privacy Airlock (Speech Dictation & Prompt DLP)\n"
            "Scrub voice prompts, terminal logs, and code locally before sending to AI. Audio and text are processed "
            "strictly on your machine with 0 outbound network requests. Pre-Model 5-Gate DLP masks cards, IDs, and secrets.",
            font=("Segoe UI", 9),
            fg=TEXT_MUTED,
            bg=BG_CARD,
            padx=16,
            pady=8,
            justify=tk.LEFT,
            relief=tk.FLAT,
            highlightbackground=BORDER_COLOR,
            highlightthickness=1,
        )
        banner.pack(fill=tk.X, pady=(0, 8))

        # Hero Card for Voice Dictation & MCP Sync
        hero = tk.Frame(self.tab_airlock, bg=BG_CARD, padx=16, pady=10, highlightbackground=BORDER_COLOR, highlightthickness=1)
        hero.pack(fill=tk.X, pady=(0, 8))

        status_row = tk.Frame(hero, bg=BG_CARD)
        status_row.pack(fill=tk.X, pady=(0, 6))

        self.voice_status_pill = tk.Label(
            status_row,
            text="🟢 AIRLOCK READY (OFFLINE)",
            font=("Segoe UI", 9, "bold"),
            fg=ACCENT_EMERALD,
            bg="#064e3b",
            padx=10,
            pady=3,
        )
        self.voice_status_pill.pack(side=tk.LEFT)

        self.voice_model_lbl = tk.Label(
            status_row,
            text="Engine: Local Audio Capture • Pre-Model 5-Gate DLP • Zero Cloud Calls",
            font=("Segoe UI", 9),
            fg=TEXT_MUTED,
            bg=BG_CARD,
            padx=10,
        )
        self.voice_model_lbl.pack(side=tk.LEFT)

        self.mcp_buffer_badge = tk.Label(
            status_row,
            text="🟢 MCP Buffer Active",
            font=("Segoe UI", 8, "bold"),
            fg=BORDER_FOCUS,
            bg="#0c4a6e",
            padx=8,
            pady=2,
        )
        self.mcp_buffer_badge.pack(side=tk.RIGHT)

        # Controls row: Dictate button + Quick Prompt Entry
        ctrl_row = tk.Frame(hero, bg=BG_CARD)
        ctrl_row.pack(fill=tk.X, pady=(4, 4))

        self.voice_btn = tk.Button(
            ctrl_row,
            text="🎙️  CLICK TO START DICTATING",
            font=("Segoe UI", 10, "bold"),
            bg=ACCENT_BLUE,
            fg="#ffffff",
            activebackground=ACCENT_HOVER,
            activeforeground="#ffffff",
            padx=16,
            pady=6,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._toggle_voice_recording,
        )
        self.voice_btn.pack(side=tk.LEFT, padx=(0, 10))

        tk.Label(
            ctrl_row,
            text="Quick Prompt Bar:",
            font=("Segoe UI", 9, "bold"),
            fg=TEXT_TITLE,
            bg=BG_CARD,
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.quick_speech_entry = tk.Entry(
            ctrl_row,
            bg=BG_CANVAS,
            fg=TEXT_TITLE,
            insertbackground=BORDER_FOCUS,
            font=("Consolas", 10),
            relief=tk.FLAT,
            highlightbackground=BORDER_COLOR,
            highlightthickness=1,
        )
        self.quick_speech_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8), ipady=4)
        self.quick_speech_entry.bind("<Return>", lambda e: self._process_quick_speech())

        quick_btn = tk.Button(
            ctrl_row,
            text="⚡ Scrub & Feed to MCP",
            font=("Segoe UI", 9, "bold"),
            bg=ACCENT_BLUE,
            fg="#ffffff",
            activebackground=ACCENT_HOVER,
            activeforeground="#ffffff",
            padx=12,
            pady=4,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._process_quick_speech,
        )
        quick_btn.pack(side=tk.RIGHT)

        self.voice_feedback_lbl = tk.Label(
            hero,
            text="Microphone listening will remain 100% offline. Zero telemetry, zero cloud streaming.",
            font=("Segoe UI", 8),
            fg=TEXT_MUTED,
            bg=BG_CARD,
        )
        self.voice_feedback_lbl.pack(anchor=tk.W, pady=(4, 0))

        # Central Split Panes
        panes = tk.Frame(self.tab_airlock, bg=BG_CANVAS)
        panes.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        # Left: Raw Input / Transcript
        left_f = tk.Frame(panes, bg=BG_CARD, padx=8, pady=8, highlightbackground=BORDER_COLOR, highlightthickness=1)
        left_f.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 6))

        tk.Label(
            left_f,
            text="Raw Prompt / Spoken Audio Transcript (Local Only):",
            font=("Segoe UI", 10, "bold"),
            fg=TEXT_TITLE,
            bg=BG_CARD,
        ).pack(anchor=tk.W, pady=(0, 4))

        self.input_text = tk.Text(
            left_f,
            bg=BG_CANVAS,
            fg=TEXT_TITLE,
            insertbackground=BORDER_FOCUS,
            font=("Consolas", 10),
            relief=tk.FLAT,
            wrap=tk.WORD,
            height=11,
            padx=8,
            pady=6,
        )
        self.input_text.pack(fill=tk.BOTH, expand=True)
        self.voice_raw_text = self.input_text

        # Right: Sanitized DLP Output (Ready for AI)
        right_f = tk.Frame(panes, bg=BG_CARD, padx=8, pady=8, highlightbackground=BORDER_COLOR, highlightthickness=1)
        right_f.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(6, 0))

        tk.Label(
            right_f,
            text="Sanitized 5-Gate DLP Output (Safe for AI / Active in MCP):",
            font=("Segoe UI", 10, "bold"),
            fg=BORDER_FOCUS,
            bg=BG_CARD,
        ).pack(anchor=tk.W, pady=(0, 4))

        self.output_text = tk.Text(
            right_f,
            bg=BG_CANVAS,
            fg=ACCENT_EMERALD,
            font=("Consolas", 10),
            relief=tk.FLAT,
            wrap=tk.WORD,
            height=11,
            padx=8,
            pady=6,
        )
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.voice_scrubbed_text = self.output_text

        # Action Bar
        act_bar = tk.Frame(self.tab_airlock, bg=BG_CANVAS)
        act_bar.pack(fill=tk.X)

        scrub_btn = tk.Button(
            act_bar,
            text="🧹 Scrub with 5-Gate DLP",
            font=("Segoe UI", 9, "bold"),
            bg=ACCENT_BLUE,
            fg="#ffffff",
            activebackground=ACCENT_HOVER,
            activeforeground="#ffffff",
            padx=14,
            pady=6,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._scrub_input,
        )
        scrub_btn.pack(side=tk.LEFT, padx=(0, 8))

        copy_btn = tk.Button(
            act_bar,
            text="📋 Copy Sanitized Text",
            font=("Segoe UI", 9),
            bg=BG_ELEVATED,
            fg=TEXT_TITLE,
            activebackground=BG_SURFACE,
            activeforeground=TEXT_TITLE,
            padx=12,
            pady=6,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._copy_output,
        )
        copy_btn.pack(side=tk.LEFT, padx=(0, 8))

        canary_btn = tk.Button(
            act_bar,
            text="🧪 Load Test Canary Sample",
            font=("Segoe UI", 9),
            bg=BG_ELEVATED,
            fg=TEXT_MUTED,
            activebackground=BG_SURFACE,
            activeforeground=TEXT_TITLE,
            padx=12,
            pady=6,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._load_sample_canary,
        )
        canary_btn.pack(side=tk.LEFT, padx=(0, 8))

        clear_btn = tk.Button(
            act_bar,
            text="🗑️ Clear Airlock",
            font=("Segoe UI", 9),
            bg=BG_ELEVATED,
            fg=TEXT_MUTED,
            activebackground=BG_SURFACE,
            activeforeground=TEXT_TITLE,
            padx=12,
            pady=6,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._clear_privacy_inputs,
        )
        clear_btn.pack(side=tk.LEFT)

    def _build_voice_tab(self) -> None:
        self._build_airlock_tab()

    def _process_quick_speech(self) -> None:
        txt = self.quick_speech_entry.get().strip()
        if not txt:
            return
        self._on_voice_audio_received(txt)
        self.quick_speech_entry.delete(0, tk.END)

    def _toggle_voice_recording(self) -> None:
        if not self._is_recording:
            self._start_persistent_recording()
        else:
            self._stop_persistent_recording()

    def _start_persistent_recording(self) -> None:
        self._is_recording = True
        self._record_start_time = time.time()
        self.voice_btn.config(
            text="⏹️  STOP DICTATING (RECORDING LIVE)",
            bg=ALERT_RED,
            activebackground="#b91c1c",
        )
        self.voice_status_pill.config(text="🔴 RECORDING LIVE AUDIO (00:00)", bg="#7f1d1d", fg="#fca5a5")
        self.voice_feedback_lbl.config(
            text="Listening to microphone (100% offline)... Speak freely. Click Stop or wait for silence.",
            fg=BORDER_FOCUS,
        )
        if hasattr(self, "mc_voice_btn"):
            self.mc_voice_btn.config(text="⏹️  Stop Dictating (Recording)", bg=ALERT_RED, activebackground="#b91c1c")
        if hasattr(self, "mc_voice_status_pill"):
            self.mc_voice_status_pill.config(text="🔴 RECORDING LIVE AUDIO", bg="#7f1d1d", fg="#fca5a5")
        if hasattr(self, "mc_voice_feedback_lbl"):
            self.mc_voice_feedback_lbl.config(text="Listening offline... Auto-stops on silence (~1.8s) or press Spacebar.", fg=BORDER_FOCUS)

        self._update_recording_timer()

        try:
            self._voice_recorder = MicrophoneRecorder()
            self._voice_recorder.start()
        except VoiceEngineError as err:
            self._is_recording = False
            if self._record_timer_id:
                self.root.after_cancel(self._record_timer_id)
                self._record_timer_id = None
            self.voice_btn.config(
                text="🎙️  CLICK TO START DICTATING",
                bg=ACCENT_BLUE,
                activebackground=ACCENT_HOVER,
            )
            self.voice_status_pill.config(text="⚠️ VOICE ENGINE NOT READY", bg="#78350f", fg="#fde047")
            self.voice_feedback_lbl.config(text=f"❌ Microphone error: {err}", fg=ALERT_RED)
            if hasattr(self, "mc_voice_btn"):
                self.mc_voice_btn.config(text="🎙️  Start Dictation (Spacebar)", bg=ACCENT_BLUE, activebackground=ACCENT_HOVER)
            if hasattr(self, "mc_voice_status_pill"):
                self.mc_voice_status_pill.config(text="⚠️ VOICE NOTICE", bg="#78350f", fg="#fde047")
            if hasattr(self, "mc_voice_feedback_lbl"):
                self.mc_voice_feedback_lbl.config(text=f"❌ {err}", fg=ALERT_RED)
            messagebox.showwarning("Voice Airlock Notice", str(err))

    def _stop_persistent_recording(self) -> None:
        self._is_recording = False
        if self._record_timer_id:
            self.root.after_cancel(self._record_timer_id)
            self._record_timer_id = None
        self.voice_btn.config(
            text="⏳  PROCESSING AUDIO AIRLOCK...",
            bg=ACCENT_BLUE,
            activebackground=ACCENT_HOVER,
        )
        self.voice_status_pill.config(text="🟡 TRANSCRIBING & DLP SCRUBBING", bg="#78350f", fg="#fde047")
        self.voice_feedback_lbl.config(text="Transcribing audio locally with offline Whisper model...", fg=BORDER_FOCUS)
        if hasattr(self, "mc_voice_btn"):
            self.mc_voice_btn.config(text="⏳  Transcribing Audio...", bg=ACCENT_BLUE, activebackground=ACCENT_HOVER)
        if hasattr(self, "mc_voice_status_pill"):
            self.mc_voice_status_pill.config(text="🟡 TRANSCRIBING & DLP SCRUBBING", bg="#78350f", fg="#fde047")
        if hasattr(self, "mc_voice_feedback_lbl"):
            self.mc_voice_feedback_lbl.config(text="Transcribing audio locally with offline Whisper model...", fg=BORDER_FOCUS)

        recorder = self._voice_recorder
        self._voice_recorder = None

        def _bg_transcribe() -> None:
            if recorder is None:
                return
            try:
                audio_data = recorder.stop()
                text = self._voice_transcriber.transcribe(audio_data)
                self.root.after(0, lambda: self._on_voice_audio_received(text))
            except VoiceEngineError as err:
                msg = str(err)
                logger.warning(f"Voice engine notice: {msg}")
                self.root.after(0, lambda m=msg: self._on_voice_engine_error(m))
            except Exception as exc:
                msg = f"Transcription error: {exc}"
                logger.error(f"Unexpected error in offline voice transcriber: {msg}")
                self.root.after(0, lambda m=msg: self._on_voice_engine_error(m))

        threading.Thread(target=_bg_transcribe, daemon=True).start()

    def _on_voice_engine_error(self, message: str) -> None:
        self._is_recording = False
        self.voice_btn.config(
            text="🎙️  CLICK TO START DICTATING",
            bg=ACCENT_BLUE,
            activebackground=ACCENT_HOVER,
        )
        self.voice_status_pill.config(text="⚠️ VOICE AIRLOCK NOTICE", bg="#78350f", fg="#fde047")
        self.voice_feedback_lbl.config(text=f"❌ {message}", fg=ALERT_RED)
        if hasattr(self, "mc_voice_btn"):
            self.mc_voice_btn.config(text="🎙️  Start Dictation (Spacebar)", bg=ACCENT_BLUE, activebackground=ACCENT_HOVER)
        if hasattr(self, "mc_voice_status_pill"):
            self.mc_voice_status_pill.config(text="⚠️ VOICE NOTICE", bg="#78350f", fg="#fde047")
        if hasattr(self, "mc_voice_feedback_lbl"):
            self.mc_voice_feedback_lbl.config(text=f"❌ {message}", fg=ALERT_RED)

    def _update_recording_timer(self) -> None:
        if not self._is_recording:
            return
        if self._voice_recorder and getattr(self._voice_recorder, "hit_silence_limit", False):
            self.voice_feedback_lbl.config(
                text="Auto-stopping: silence detected. Transcribing offline audio...",
                fg=BORDER_FOCUS,
            )
            if hasattr(self, "mc_voice_feedback_lbl"):
                self.mc_voice_feedback_lbl.config(
                    text="Auto-stopping: silence detected. Transcribing offline audio...",
                    fg=BORDER_FOCUS,
                )
            self._stop_persistent_recording()
            return
        elapsed = int(time.time() - self._record_start_time)
        mins = elapsed // 60
        secs = elapsed % 60
        self.voice_status_pill.config(text=f"🔴 RECORDING LIVE AUDIO ({mins:02d}:{secs:02d})")
        if hasattr(self, "mc_voice_status_pill"):
            self.mc_voice_status_pill.config(text=f"🔴 RECORDING ({mins:02d}:{secs:02d})")
        self._record_timer_id = self.root.after(500, self._update_recording_timer)

    def _save_voice_prompt_to_mcp_buffer(self, scrubbed_text: str) -> None:
        try:
            buffer_path = get_app_data_dir() / "latest_voice_prompt.json"
            payload = {
                "timestamp": time.time(),
                "prompt": scrubbed_text,
                "sanitized": True,
                "airlock": "sentinelwire-privacy-mcp",
            }
            with open(buffer_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            logger.info("Saved latest voice prompt to MCP buffer")
        except Exception as e:
            logger.warning(f"Failed to save voice prompt buffer: {e}")

    def _on_voice_audio_received(self, text: str) -> None:
        self.voice_raw_text.delete("1.0", tk.END)
        self.voice_raw_text.insert(tk.END, text)

        scrubbed = self.sanitizer.sanitize_text(text)
        self.voice_scrubbed_text.delete("1.0", tk.END)
        self.voice_scrubbed_text.insert(tk.END, scrubbed)

        self._save_voice_prompt_to_mcp_buffer(scrubbed)

        self._is_recording = False
        self.voice_btn.config(
            text="🎙️  CLICK TO START DICTATING",
            bg=ACCENT_BLUE,
            activebackground=ACCENT_HOVER,
        )
        self.voice_status_pill.config(text="🟢 VOICE AIRLOCK READY (OFFLINE)", bg="#064e3b", fg=ACCENT_EMERALD)
        self.voice_feedback_lbl.config(
            text="✅ Dictation processed and saved to local MCP airlock buffer! AI can now read this prompt directly.",
            fg=ACCENT_EMERALD,
        )
        if hasattr(self, "mc_voice_btn"):
            self.mc_voice_btn.config(text="🎙️  Start Dictation (Spacebar)", bg=ACCENT_BLUE, activebackground=ACCENT_HOVER)
        if hasattr(self, "mc_voice_status_pill"):
            self.mc_voice_status_pill.config(text="🟢 AIRLOCK READY (OFFLINE)", bg="#064e3b", fg=ACCENT_EMERALD)
        if hasattr(self, "mc_voice_feedback_lbl"):
            self.mc_voice_feedback_lbl.config(text="✅ Dictation scrubbed & saved to local MCP buffer!", fg=ACCENT_EMERALD)
        if hasattr(self, "mc_quick_prompt_entry"):
            self.mc_quick_prompt_entry.delete(0, tk.END)
            self.mc_quick_prompt_entry.insert(0, scrubbed)

    def _copy_sanitized_speech(self) -> None:
        self._copy_output()

    def _transfer_speech_to_dlp(self) -> None:
        self.input_text.focus_set()

    def _clear_voice_text(self) -> None:
        self._clear_privacy_inputs()

    def _build_privacy_tab(self) -> None:
        """Compatibility wrapper; functionality now merged into _build_airlock_tab."""
        pass

    def _scrub_input(self) -> None:
        raw_text = self.input_text.get("1.0", tk.END).strip()
        if not raw_text:
            return
        sanitized = self.sanitizer.sanitize_text(raw_text)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, sanitized)

    def _copy_output(self) -> None:
        content = self.output_text.get("1.0", tk.END).strip()
        if content:
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            messagebox.showinfo("Copied", "Sanitized text copied to clipboard!")

    def _clear_privacy_inputs(self) -> None:
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)

    def _load_sample_canary(self) -> None:
        sample = (
            "User Alice Sample (SSN: 000-12-3456) processed transaction with card 4532 0151 1283 0366.\n"
            "Server token: bearer-dummy-token-sample-9999\n"
            "Internal node: 192.168.1.105 accessing file /opt/secure/database.conf"
        )
        self.input_text.delete("1.0", tk.END)
        self.input_text.insert(tk.END, sample)
        self._scrub_input()

    def _build_monitor_tab(self) -> None:
        # Upper Card: Wire Sniffer & Real-Time Alerts
        card = tk.Frame(self.tab_monitor, bg=BG_CARD, padx=14, pady=10, highlightbackground=BORDER_COLOR, highlightthickness=1)
        card.pack(fill=tk.BOTH, expand=True, pady=(0, 6))

        header_row = tk.Frame(card, bg=BG_CARD)
        header_row.pack(fill=tk.X, pady=(0, 6))

        tk.Label(
            header_row,
            text="Live Wire Packet Capture & Threat Alerts",
            font=("Segoe UI", 11, "bold"),
            fg=TEXT_TITLE,
            bg=BG_CARD,
        ).pack(side=tk.LEFT)

        self.monitor_status_badge = tk.Label(
            header_row,
            text="🔴 SNIFFER STOPPED",
            font=("Segoe UI", 9, "bold"),
            fg="#fca5a5",
            bg="#7f1d1d",
            padx=10,
            pady=3,
        )
        self.monitor_status_badge.pack(side=tk.RIGHT)

        # Control Bar
        ctrl_bar = tk.Frame(card, bg=BG_CARD)
        ctrl_bar.pack(fill=tk.X, pady=(0, 6))

        self.btn_toggle_monitor = tk.Button(
            ctrl_bar,
            text="▶️ Start Live Sniffer",
            font=("Segoe UI", 9, "bold"),
            bg=ACCENT_BLUE,
            fg="#ffffff",
            activebackground=ACCENT_HOVER,
            activeforeground="#ffffff",
            padx=12,
            pady=4,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._toggle_sniffer,
        )
        self.btn_toggle_monitor.pack(side=tk.LEFT, padx=(0, 8))

        canary_btn = tk.Button(
            ctrl_bar,
            text="🧪 Trigger Safe Canary Alert",
            font=("Segoe UI", 9),
            bg=BG_ELEVATED,
            fg=TEXT_TITLE,
            activebackground=BG_SURFACE,
            activeforeground="#ffffff",
            padx=12,
            pady=4,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._trigger_canary_alert,
        )
        canary_btn.pack(side=tk.LEFT, padx=(0, 8))

        explain_btn = tk.Button(
            ctrl_bar,
            text="ℹ️ Explain Threat",
            font=("Segoe UI", 9, "bold"),
            bg=ACCENT_BLUE,
            fg="#ffffff",
            activebackground=ACCENT_HOVER,
            activeforeground="#ffffff",
            padx=12,
            pady=4,
            relief=tk.FLAT,
            cursor="hand2",
            command=lambda: self._show_threat_explanation(),
        )
        explain_btn.pack(side=tk.LEFT, padx=(0, 8))

        self.monitor_detail_lbl = tk.Label(
            ctrl_bar,
            text="Ready. Start sniffer to inspect wire DNS/TLS packets in real-time.",
            font=("Segoe UI", 9),
            fg=TEXT_MUTED,
            bg=BG_CARD,
        )
        self.monitor_detail_lbl.pack(side=tk.LEFT, padx=(8, 0))

        # Real-time Threat Alerts Treeview
        tree_frame = tk.Frame(card, bg=BG_CANVAS, highlightthickness=1, highlightbackground=BORDER_COLOR)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        cols = ("time", "indicator", "feed", "process", "layer")
        self.alert_tree = ttk.Treeview(
            tree_frame,
            columns=cols,
            show="headings",
            selectmode="browse",
            height=6,
        )
        self.alert_tree.heading("time", text="Timestamp (UTC)")
        self.alert_tree.heading("indicator", text="Flagged Domain / IP")
        self.alert_tree.heading("feed", text="Matched Threat Feed")
        self.alert_tree.heading("process", text="Attributed Process")
        self.alert_tree.heading("layer", text="Detection Layer")

        self.alert_tree.column("time", width=140, anchor="w")
        self.alert_tree.column("indicator", width=240, anchor="w")
        self.alert_tree.column("feed", width=180, anchor="w")
        self.alert_tree.column("process", width=140, anchor="w")
        self.alert_tree.column("layer", width=110, anchor="center")

        sb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.alert_tree.yview)
        self.alert_tree.configure(yscrollcommand=sb.set)
        self.alert_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.alert_tree.bind("<Double-1>", lambda e: self._show_threat_explanation())

        # Lower Card: Target Process Watchdog & Script Interpreter Inspector
        w_card = tk.Frame(self.tab_monitor, bg=BG_CARD, padx=14, pady=10, highlightbackground=BORDER_COLOR, highlightthickness=1)
        w_card.pack(fill=tk.X, pady=(0, 0))

        w_head = tk.Frame(w_card, bg=BG_CARD)
        w_head.pack(fill=tk.X, pady=(0, 4))

        tk.Label(
            w_head,
            text="👁️ Target Process Watchdog & Script Lineage Inspector",
            font=("Segoe UI", 10, "bold"),
            fg=TEXT_TITLE,
            bg=BG_CARD,
        ).pack(side=tk.LEFT)

        tk.Label(
            w_head,
            text="Traces child process trees & flags LOLBINs (powershell, node, curl, cmd)",
            font=("Segoe UI", 8),
            fg=TEXT_MUTED,
            bg=BG_CARD,
        ).pack(side=tk.RIGHT)

        input_bar = tk.Frame(w_card, bg=BG_CARD)
        input_bar.pack(fill=tk.X, pady=(0, 6))

        tk.Label(
            input_bar,
            text="Select Process:",
            font=("Segoe UI", 9),
            fg=TEXT_MUTED,
            bg=BG_CARD,
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.proc_combo = ttk.Combobox(
            input_bar,
            font=("Segoe UI", 9),
            state="normal",
            width=22,
        )
        candidates = self._get_running_process_candidates()
        self.proc_combo["values"] = candidates
        if "python.exe" in candidates:
            self.proc_combo.set("python.exe")
        elif candidates:
            self.proc_combo.set(candidates[0])
        else:
            self.proc_combo.set("python")
        self.proc_combo.pack(side=tk.LEFT, padx=(0, 6))
        self.proc_entry = self.proc_combo

        refresh_btn = tk.Button(
            input_bar,
            text="🔄 Refresh",
            font=("Segoe UI", 8),
            bg=BG_ELEVATED,
            fg=TEXT_MUTED,
            activebackground=BG_SURFACE,
            activeforeground=TEXT_TITLE,
            padx=6,
            pady=3,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._refresh_process_lists,
        )
        refresh_btn.pack(side=tk.LEFT, padx=(0, 6))

        inspect_btn = tk.Button(
            input_bar,
            text="Inspect Process Tree",
            font=("Segoe UI", 9, "bold"),
            bg=ACCENT_BLUE,
            fg="#ffffff",
            activebackground=ACCENT_HOVER,
            activeforeground="#ffffff",
            padx=12,
            pady=3,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._inspect_watchdog_target,
        )
        inspect_btn.pack(side=tk.LEFT, padx=(0, 6))

        ai_btn = tk.Button(
            input_bar,
            text="🤖 Ask AI Safety",
            font=("Segoe UI", 9, "bold"),
            bg="#7c3aed",
            fg="#ffffff",
            activebackground="#6d28d9",
            activeforeground="#ffffff",
            padx=12,
            pady=3,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._analyze_process_with_ai,
        )
        ai_btn.pack(side=tk.LEFT)

        self.watchdog_results = tk.Text(
            w_card,
            bg=BG_CANVAS,
            fg=TEXT_BODY,
            font=("Consolas", 9),
            relief=tk.FLAT,
            wrap=tk.WORD,
            height=4,
            highlightbackground=BORDER_COLOR,
            highlightthickness=1,
            padx=8,
            pady=6,
        )
        self.watchdog_results.pack(fill=tk.BOTH, expand=True)

    def _build_watchdog_tab(self) -> None:
        """Compatibility wrapper; functionality now merged into _build_monitor_tab."""
        pass

    def _toggle_sniffer(self) -> None:
        snap = self._monitor_service.snapshot()
        if not snap.running:
            self._monitor_service.start()
            self.btn_toggle_monitor.config(
                text="⏹️ Stop Sniffer",
                bg="#dc2626",
                activebackground="#b91c1c",
            )
            self.monitor_status_badge.config(
                text="🟢 SNIFFER LIVE",
                bg="#064e3b",
                fg="#22c55e",
            )
            self.monitor_detail_lbl.config(
                text=f"Capturing: {snap.capture_mode} (PEP 578 airlock active)",
                fg="#38bdf8",
            )
            if hasattr(self, "mc_sniffer_btn"):
                self.mc_sniffer_btn.config(text="⏹️ Stop Sniffer", bg="#dc2626", activebackground="#b91c1c")
            if hasattr(self, "mc_sniffer_badge"):
                self.mc_sniffer_badge.config(text="🟢 SNIFFER LIVE", bg="#064e3b", fg="#22c55e")
        else:
            self._monitor_service.stop()
            self.btn_toggle_monitor.config(
                text="▶️ Start Live Sniffer",
                bg=ACCENT_BLUE,
                activebackground=ACCENT_HOVER,
            )
            self.monitor_status_badge.config(
                text="🔴 SNIFFER STOPPED",
                bg="#7f1d1d",
                fg="#fca5a5",
            )
            self.monitor_detail_lbl.config(text="Sniffer stopped cleanly.", fg=TEXT_MUTED)
            if hasattr(self, "mc_sniffer_btn"):
                self.mc_sniffer_btn.config(text="▶️ Start Sniffer", bg=ACCENT_BLUE, activebackground=ACCENT_HOVER)
            if hasattr(self, "mc_sniffer_badge"):
                self.mc_sniffer_badge.config(text="🔴 SNIFFER STOPPED", bg="#7f1d1d", fg="#fca5a5")
        self._refresh_telemetry_ui()

    def _trigger_canary_alert(self) -> None:
        self._monitor_service.run_canary_self_test()
        self.monitor_detail_lbl.config(text="✅ Dispatched canary indicator (sketchy-canary.example.com)", fg="#22c55e")
        self._refresh_telemetry_ui()

    def _schedule_telemetry_poll(self) -> None:
        self._refresh_telemetry_ui()
        self._telemetry_timer_id = self.root.after(1500, self._schedule_telemetry_poll)

    def _refresh_telemetry_ui(self) -> None:
        snap = self._monitor_service.snapshot()
        self._packet_count = snap.events_inspected
        self._threat_count = snap.alerts_emitted

        if hasattr(self, "metric_value_labels") and len(self.metric_value_labels) >= 4:
            self.metric_value_labels[0].config(text=f"{snap.events_inspected:,}")
            threat_color = "#ef4444" if snap.alerts_emitted > 0 else "#22c55e"
            self.metric_value_labels[1].config(text=f"{snap.alerts_emitted:,}", fg=threat_color)
            active_gates = sum(
                1
                for g in (
                    self.vault_settings.dlp_gate_cards,
                    self.vault_settings.dlp_gate_keys,
                    self.vault_settings.dlp_gate_usernames,
                    self.vault_settings.dlp_gate_national_ids,
                    self.vault_settings.dlp_gate_ips,
                )
                if g
            )
            self.metric_value_labels[2].config(text=f"{active_gates}/5 Gates Active")
            self.metric_value_labels[3].config(text="DPAPI Protected" if platform.system().lower() == "windows" else "Local (chmod 600)")

        if hasattr(self, "alert_tree"):
            for alert in self._monitor_service.recent_alerts(limit=50):
                row_key = f"{alert.timestamp_utc}|{alert.indicator}|{alert.process_name}"
                if row_key not in self._threat_rows_seen:
                    self._threat_rows_seen.add(row_key)
                    self.alert_tree.insert(
                        "",
                        0,
                        values=(
                            alert.timestamp_utc,
                            alert.indicator,
                            alert.source_feed,
                            alert.process_name,
                            alert.detection_layer,
                        ),
                    )
                    if hasattr(self, "mc_alert_tree"):
                        self.mc_alert_tree.insert(
                            "",
                            0,
                            values=(
                                alert.timestamp_utc,
                                alert.indicator,
                                alert.source_feed,
                                alert.process_name,
                                alert.detection_layer,
                            ),
                        )

    def _inspect_watchdog_target(self) -> None:
        target = ""
        if hasattr(self, "proc_entry"):
            target = self.proc_entry.get().strip()
        if not target and hasattr(self, "proc_combo"):
            target = self.proc_combo.get().strip()
        if not target:
            return
        from .process_watchdog import find_processes_by_name

        self.watchdog_results.delete("1.0", tk.END)
        self.watchdog_results.insert(tk.END, f"[*] Querying active processes matching '{target}'...\n\n")

        target_pid = int(target) if target.isdigit() else None
        matches = []
        if target_pid is None:
            matches = find_processes_by_name(target)
            if not matches:
                self.watchdog_results.insert(tk.END, f"[!] No active processes found matching '{target}'.\n")
                return
            target_pid = matches[0][0]

        children = inspect_child_lineage(target_pid)
        self.watchdog_results.insert(tk.END, f"[+] Target PID: {target_pid} | Active Children: {len(children)}\n")
        for c in children:
            tag = "[SCRIPT INTERPRETER - HIGH RISK]" if c.is_script_interpreter else "[NORMAL CHILD]"
            self.watchdog_results.insert(
                tk.END,
                f"    - Child PID {c.child_pid}: {c.child_name} {tag}\n      Cmdline: {c.cmdline}\n",
            )
        if not children:
            self.watchdog_results.insert(tk.END, "    - No spawned child script interpreters detected.\n")

    def _on_space_pressed(self, event) -> None:
        if isinstance(event.widget, (tk.Entry, tk.Text, ttk.Entry, ttk.Combobox)):
            return
        self._toggle_voice_recording()

    def _get_running_process_candidates(self) -> List[str]:
        candidates: Set[str] = set()
        try:
            import psutil
            for p in psutil.process_iter(["name"]):
                try:
                    name = p.info.get("name")
                    if name and not name.startswith("System") and name != "Registry":
                        candidates.add(name)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as exc:
            logger.debug(f"Error enumerating running processes: {exc}")
        if not candidates:
            candidates.update(["python.exe", "node.exe", "powershell.exe", "cmd.exe", "code.exe", "curl.exe"])
        return sorted(candidates, key=lambda s: s.lower())

    def _refresh_process_lists(self) -> None:
        candidates = self._get_running_process_candidates()
        if hasattr(self, "mc_proc_combo"):
            current = self.mc_proc_combo.get()
            self.mc_proc_combo["values"] = candidates
            if current in candidates:
                self.mc_proc_combo.set(current)
            elif "python.exe" in candidates:
                self.mc_proc_combo.set("python.exe")
            elif candidates:
                self.mc_proc_combo.set(candidates[0])
        if hasattr(self, "proc_combo"):
            current = self.proc_combo.get()
            self.proc_combo["values"] = candidates
            if current in candidates:
                self.proc_combo.set(current)
            elif "python.exe" in candidates:
                self.proc_combo.set("python.exe")
            elif candidates:
                self.proc_combo.set(candidates[0])

    def _inspect_mc_watchdog(self) -> None:
        target = self.mc_proc_combo.get().strip() if hasattr(self, "mc_proc_combo") else "python"
        if not target:
            return
        from .process_watchdog import find_processes_by_name
        self.mc_watchdog_results.delete("1.0", tk.END)
        self.mc_watchdog_results.insert(tk.END, f"[*] Querying processes matching '{target}'...\n")
        target_pid = int(target) if target.isdigit() else None
        matches = []
        if target_pid is None:
            matches = find_processes_by_name(target)
            if not matches:
                self.mc_watchdog_results.insert(tk.END, f"[!] No active processes found matching '{target}'.\n")
                return
            target_pid = matches[0][0]
        children = inspect_child_lineage(target_pid)
        self.mc_watchdog_results.insert(tk.END, f"[+] Target PID: {target_pid} | Active Children: {len(children)}\n")
        for c in children:
            tag = "[SCRIPT INTERPRETER - HIGH RISK]" if c.is_script_interpreter else "[CHILD]"
            self.mc_watchdog_results.insert(tk.END, f"  - PID {c.child_pid}: {c.child_name} {tag}\n")
        if not children:
            self.mc_watchdog_results.insert(tk.END, "  - No spawned child script interpreters detected.\n")

    def _quick_scrub_prompt(self) -> None:
        text = self.mc_quick_prompt_entry.get().strip() if hasattr(self, "mc_quick_prompt_entry") else ""
        if not text:
            return
        scrubbed = self.sanitizer.sanitize_text(text)
        self._save_voice_prompt_to_mcp_buffer(scrubbed)
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(scrubbed)
        except Exception:
            pass
        if hasattr(self, "mc_voice_feedback_lbl"):
            self.mc_voice_feedback_lbl.config(
                text="✅ Prompt scrubbed via 5-Gate DLP, saved to MCP buffer and copied to clipboard!",
                fg=ACCENT_EMERALD,
            )

    def _analyze_process_with_ai(self) -> None:
        target = ""
        if hasattr(self, "mc_proc_combo"):
            target = self.mc_proc_combo.get().strip()
        if not target and hasattr(self, "proc_combo"):
            target = self.proc_combo.get().strip()
        if not target:
            target = "python"

        from .process_watchdog import find_processes_by_name, check_lots_risk
        matches = find_processes_by_name(target)
        if not matches:
            messagebox.showinfo("Process Not Found", f"No running processes matching '{target}' were found.")
            return

        pid, name, exe = matches[0]
        children = inspect_child_lineage(pid)
        lots_res = check_lots_risk(name, [c.cmdline for c in children if c.cmdline])

        analysis_prompt = (
            f"SentinelWire Process Security Report:\n"
            f"Target Process: {name} (PID: {pid})\n"
            f"Executable: [REDACTED_SYSTEM_PATH]/{Path(exe).name}\n"
            f"Active Child Lineage Count: {len(children)}\n"
            f"LOTS Abuse Risk Detected: {lots_res.is_risky} (Level: {lots_res.risk_level})\n"
        )
        if children:
            analysis_prompt += "Child Process Lineage:\n"
            for c in children:
                script_flag = " [SCRIPT INTERPRETER]" if c.is_script_interpreter else ""
                analysis_prompt += f"  - {c.child_name} (PID: {c.child_pid}){script_flag}\n"
        if lots_res.reasons:
            analysis_prompt += "Risk Factors:\n"
            for r in lots_res.reasons:
                analysis_prompt += f"  - {r}\n"
        analysis_prompt += (
            "\nPlease analyze whether this process tree indicates Living-off-the-Land (LOTS) malware activity, "
            "reverse shell behavior, or normal developer tooling, and suggest remediation steps."
        )

        clean_prompt = self.sanitizer.sanitize_text(analysis_prompt)
        self._save_voice_prompt_to_mcp_buffer(clean_prompt)
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(clean_prompt)
        except Exception:
            pass

        if hasattr(self, "mc_watchdog_results"):
            self.mc_watchdog_results.delete("1.0", tk.END)
            self.mc_watchdog_results.insert(
                tk.END,
                f"✅ Sanitized security report for '{name}' (PID {pid}) sent to MCP buffer and clipboard!\n\n"
                f"Risk Level: {lots_res.risk_level}\n"
                f"Active Children: {len(children)}\n"
                f"Risk Factors: {len(lots_res.reasons)}\n\n"
                f"You can ask connected AI:\n'Review the latest process safety report'\n",
            )
        messagebox.showinfo(
            "AI Process Safety Report Ready",
            f"Sanitized security report for '{name}' (PID {pid}) generated and sent to the local MCP airlock buffer!\n\n"
            f"Copied to clipboard. You can ask your AI: 'Review the latest process safety report'.",
        )

    def _show_threat_explanation(self, alert_values: Optional[Tuple] = None) -> None:
        if not alert_values:
            if hasattr(self, "mc_alert_tree"):
                sel = self.mc_alert_tree.selection()
                if sel:
                    alert_values = self.mc_alert_tree.item(sel[0], "values")
            if not alert_values and hasattr(self, "alert_tree"):
                sel = self.alert_tree.selection()
                if sel:
                    alert_values = self.alert_tree.item(sel[0], "values")

        if not alert_values or len(alert_values) < 5:
            messagebox.showinfo(
                "No Threat Selected",
                "Please select or double-click a threat alert row from the list to view its explanation and remediation actions.",
            )
            return

        ts, indicator, feed, proc, layer = alert_values[:5]

        feed_explanations = {
            "URLhaus": "Active malware distribution URL tracked by abuse.ch. Known to distribute Trojans, Infostealers, or Ransomware payloads.",
            "ThreatFox": "Indicator of Compromise (IoC) linked to active malware campaigns, botnets, or Command-and-Control (C2) operations.",
            "Feodo Tracker": "Botnet Command-and-Control (C2) server used to coordinate compromised botnet drones and exfiltrate credentials.",
            "HaGeZi Multi PRO": "High-security DNS threat protection filter blocking malicious tracking, telemetry, spyware, and suspicious domains.",
            "Phishing Army": "Active phishing domain targeting credential harvesting and identity fraud.",
            "StevenBlack": "Consolidated hosts threat intelligence blocking malicious domains, trackers, and telemetry.",
            "Canary": "Safe internal self-test indicator generated by SentinelWire to verify detection pipelines with zero real-world risk.",
        }

        explanation = "Flagged by threat intelligence feed as high-risk or malicious traffic."
        for k, v in feed_explanations.items():
            if k.lower() in str(feed).lower():
                explanation = v
                break

        dialog = tk.Toplevel(self.root)
        dialog.title(f"Threat Details & Remediation — {indicator}")
        dialog.geometry("640x520")
        dialog.configure(bg=BG_CANVAS)
        dialog.transient(self.root)
        dialog.grab_set()

        card = tk.Frame(dialog, bg=BG_CARD, padx=20, pady=16, highlightbackground=BORDER_COLOR, highlightthickness=1)
        card.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)

        # Title row
        t_row = tk.Frame(card, bg=BG_CARD)
        t_row.pack(fill=tk.X, pady=(0, 10))
        tk.Label(t_row, text="🚨 Threat Interception Breakdown", font=("Segoe UI", 12, "bold"), fg=TEXT_TITLE, bg=BG_CARD).pack(side=tk.LEFT)
        tk.Label(t_row, text=f"Layer: {layer}", font=("Segoe UI", 9, "bold"), fg=BORDER_FOCUS, bg=BG_ELEVATED, padx=8, pady=2).pack(side=tk.RIGHT)

        # Details Grid
        details = [
            ("Flagged Target / Indicator:", indicator, ALERT_RED),
            ("Source Intelligence Feed:", feed, "#c084fc"),
            ("Attributed Origin Process:", proc or "System / Wire Socket", TEXT_TITLE),
            ("Detection Timestamp (UTC):", ts, TEXT_MUTED),
        ]
        for label, val, val_color in details:
            d_row = tk.Frame(card, bg=BG_CARD)
            d_row.pack(fill=tk.X, pady=2)
            tk.Label(d_row, text=label, font=("Segoe UI", 9, "bold"), fg=TEXT_MUTED, bg=BG_CARD, width=24, anchor="w").pack(side=tk.LEFT)
            tk.Label(d_row, text=val, font=("Consolas" if "Target" in label else "Segoe UI", 9), fg=val_color, bg=BG_CARD, anchor="w").pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Plain-English Explanation Box
        tk.Label(card, text="Plain-English Threat Analysis:", font=("Segoe UI", 9, "bold"), fg=TEXT_TITLE, bg=BG_CARD).pack(anchor=tk.W, pady=(12, 4))
        exp_box = tk.Text(card, bg=BG_CANVAS, fg=TEXT_BODY, font=("Segoe UI", 9), relief=tk.FLAT, wrap=tk.WORD, height=4, padx=8, pady=8, highlightbackground=BORDER_COLOR, highlightthickness=1)
        exp_box.pack(fill=tk.X, pady=(0, 12))
        exp_box.insert(tk.END, f"{explanation}\n\nSentinelWire intercepted this communication locally. 0 outbound telemetry was transmitted to any third party.")
        exp_box.config(state="disabled")

        # Action Buttons
        tk.Label(card, text="Recommended Remediation Actions:", font=("Segoe UI", 9, "bold"), fg=TEXT_TITLE, bg=BG_CARD).pack(anchor=tk.W, pady=(0, 6))

        def _terminate_process():
            if not proc or proc.lower() in ("unknown", "system"):
                messagebox.showwarning("Cannot Terminate", "Origin process is system-level or unknown.")
                return
            if messagebox.askyesno("Confirm Process Termination", f"Terminate all running instances of '{proc}'?"):
                import psutil
                killed = 0
                for p in psutil.process_iter(["name"]):
                    try:
                        if (p.info.get("name") or "").lower() == proc.lower():
                            p.kill()
                            killed += 1
                    except Exception:
                        continue
                messagebox.showinfo("Process Terminated", f"Successfully terminated {killed} instance(s) of '{proc}'.")
                dialog.destroy()

        def _copy_firewall_rule():
            rule_cmd = (
                f'New-NetFirewallRule -DisplayName "SentinelWire_Block_{indicator}" '
                f'-Direction Outbound -RemoteAddress "{indicator}" -Action Block'
            )
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append(rule_cmd)
                messagebox.showinfo("Firewall Rule Copied", f"PowerShell firewall block command copied to clipboard:\n\n{rule_cmd}")
            except Exception as exc:
                messagebox.showerror("Clipboard Error", str(exc))

        def _ask_ai_remediation():
            prompt = (
                f"Security Incident Alert Analysis:\n"
                f"Indicator: {indicator}\n"
                f"Threat Feed: {feed}\n"
                f"Process: {proc}\n"
                f"Layer: {layer}\n"
                f"Please explain what this threat does, how it may have gotten onto this machine, and the steps to clean it."
            )
            clean_p = self.sanitizer.sanitize_text(prompt)
            self._save_voice_prompt_to_mcp_buffer(clean_p)
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append(clean_p)
            except Exception:
                pass
            messagebox.showinfo("AI Incident Prompt Ready", "Sanitized incident prompt sent to MCP buffer and clipboard! Ask your AI assistant to analyze it.")

        btn_row = tk.Frame(card, bg=BG_CARD)
        btn_row.pack(fill=tk.X, pady=(4, 0))

        tk.Button(
            btn_row,
            text="🛑 Terminate Process",
            font=("Segoe UI", 9, "bold"),
            bg=ALERT_RED,
            fg="#ffffff",
            activebackground="#b91c1c",
            activeforeground="#ffffff",
            padx=10,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2",
            command=_terminate_process,
        ).pack(side=tk.LEFT, padx=(0, 6))

        tk.Button(
            btn_row,
            text="🛡️ Copy Firewall Block",
            font=("Segoe UI", 9, "bold"),
            bg=ACCENT_BLUE,
            fg="#ffffff",
            activebackground=ACCENT_HOVER,
            activeforeground="#ffffff",
            padx=10,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2",
            command=_copy_firewall_rule,
        ).pack(side=tk.LEFT, padx=(0, 6))

        tk.Button(
            btn_row,
            text="🤖 Ask AI Remediation",
            font=("Segoe UI", 9, "bold"),
            bg="#7c3aed",
            fg="#ffffff",
            activebackground="#6d28d9",
            activeforeground="#ffffff",
            padx=10,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2",
            command=_ask_ai_remediation,
        ).pack(side=tk.LEFT, padx=(0, 6))

        tk.Button(
            btn_row,
            text="✕ Close",
            font=("Segoe UI", 9),
            bg=BG_ELEVATED,
            fg=TEXT_MUTED,
            activebackground=BG_SURFACE,
            activeforeground=TEXT_TITLE,
            padx=10,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2",
            command=dialog.destroy,
        ).pack(side=tk.RIGHT)

    def _build_settings_tab(self) -> None:
        canvas = tk.Canvas(self.tab_settings, bg=BG_CANVAS, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.tab_settings, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=BG_CANVAS)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")),
        )
        canvas_window = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.bind(
            "<Configure>",
            lambda e: canvas.itemconfig(canvas_window, width=e.width),
        )
        canvas.configure(yscrollcommand=scrollbar.set)

        def _on_mousewheel(event):
            if event.delta:
                canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
            elif event.num == 4:
                canvas.yview_scroll(-1, "units")
            elif event.num == 5:
                canvas.yview_scroll(1, "units")

        def _bind_mousewheel(event):
            canvas.bind_all("<MouseWheel>", _on_mousewheel)
            canvas.bind_all("<Button-4>", _on_mousewheel)
            canvas.bind_all("<Button-5>", _on_mousewheel)

        def _unbind_mousewheel(event):
            canvas.unbind_all("<MouseWheel>")
            canvas.unbind_all("<Button-4>")
            canvas.unbind_all("<Button-5>")

        canvas.bind("<Enter>", _bind_mousewheel)
        canvas.bind("<Leave>", _unbind_mousewheel)
        scrollable_frame.bind("<Enter>", _bind_mousewheel)
        scrollable_frame.bind("<Leave>", _unbind_mousewheel)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        banner = tk.Label(
            scrollable_frame,
            text="🔒 Windows DPAPI Offline Encrypted Vault\n"
            "Sensitive configurations (custom names, private domains, tokens) are encrypted on disk using your "
            "logged-in Windows credentials (CryptProtectData). Zero plaintext keys stored. Cannot be read by "
            "external AI bots, other machines, or info-stealer malware.",
            font=("Segoe UI", 9),
            fg=TEXT_MUTED,
            bg=BG_CARD,
            padx=16,
            pady=10,
            justify=tk.LEFT,
            relief=tk.FLAT,
            highlightbackground=BORDER_COLOR,
            highlightthickness=1,
        )
        banner.pack(fill=tk.X, pady=(0, 14))

        # Section 1: DPAPI Encrypted User Blocklists
        s1 = tk.Frame(scrollable_frame, bg=BG_CARD, padx=14, pady=12, highlightbackground=BORDER_COLOR, highlightthickness=1)
        s1.pack(fill=tk.X, pady=(0, 12))

        tk.Label(s1, text="1. Encrypted User Blocklists & Terms", font=("Segoe UI", 10, "bold"), fg=TEXT_TITLE, bg=BG_CARD).pack(anchor=tk.W, pady=(0, 6))

        tk.Label(s1, text="Custom Redacted Names & Sensitive Terms (comma-separated):", font=("Segoe UI", 9), fg=TEXT_MUTED, bg=BG_CARD).pack(anchor=tk.W)
        self.entry_custom_names = tk.Entry(s1, bg=BG_CANVAS, fg=TEXT_TITLE, insertbackground=BORDER_FOCUS, font=("Consolas", 10), relief=tk.FLAT, highlightbackground=BORDER_COLOR, highlightthickness=1)
        self.entry_custom_names.insert(0, ", ".join(self.vault_settings.custom_names))
        self.entry_custom_names.pack(fill=tk.X, pady=(2, 8), ipady=3)

        tk.Label(s1, text="Custom Blocked Domains & IPs (comma-separated):", font=("Segoe UI", 9), fg=TEXT_MUTED, bg=BG_CARD).pack(anchor=tk.W)
        self.entry_custom_domains = tk.Entry(s1, bg=BG_CANVAS, fg=TEXT_TITLE, insertbackground=BORDER_FOCUS, font=("Consolas", 10), relief=tk.FLAT, highlightbackground=BORDER_COLOR, highlightthickness=1)
        self.entry_custom_domains.insert(0, ", ".join(self.vault_settings.custom_domains))
        self.entry_custom_domains.pack(fill=tk.X, pady=(2, 8), ipady=3)

        tk.Label(s1, text="Default Monitored Process Name:", font=("Segoe UI", 9), fg=TEXT_MUTED, bg=BG_CARD).pack(anchor=tk.W)
        self.entry_default_process = tk.Entry(s1, bg=BG_CANVAS, fg=TEXT_TITLE, insertbackground=BORDER_FOCUS, font=("Consolas", 10), relief=tk.FLAT, highlightbackground=BORDER_COLOR, highlightthickness=1)
        self.entry_default_process.insert(0, self.vault_settings.default_watch_process)
        self.entry_default_process.pack(fill=tk.X, pady=(2, 4), ipady=3)

        # Section 2: 5-Gate DLP Granular Toggles
        s2 = tk.Frame(scrollable_frame, bg=BG_CARD, padx=14, pady=12, highlightbackground=BORDER_COLOR, highlightthickness=1)
        s2.pack(fill=tk.X, pady=(0, 12))

        tk.Label(s2, text="2. Pre-Model Privacy 5-Gate Toggles", font=("Segoe UI", 10, "bold"), fg=TEXT_TITLE, bg=BG_CARD).pack(anchor=tk.W, pady=(0, 6))

        self.var_gate_cards = tk.BooleanVar(value=self.vault_settings.dlp_gate_cards)
        self.var_gate_keys = tk.BooleanVar(value=self.vault_settings.dlp_gate_keys)
        self.var_gate_users = tk.BooleanVar(value=self.vault_settings.dlp_gate_usernames)
        self.var_gate_ids = tk.BooleanVar(value=self.vault_settings.dlp_gate_national_ids)
        self.var_gate_ips = tk.BooleanVar(value=self.vault_settings.dlp_gate_ips)

        gate_checks = [
            ("Gate 1: Payment Cards & IBANs (Luhn validation)", self.var_gate_cards),
            ("Gate 2: API Keys, JWTs & Secret Tokens (OpenAI, AWS, GitHub)", self.var_gate_keys),
            ("Gate 3: OS Usernames & Machine File Paths", self.var_gate_users),
            ("Gate 4: National Personal Identity Codes & SSNs", self.var_gate_ids),
            ("Gate 5: Private Internal IPv4 & IPv6 Addresses", self.var_gate_ips),
        ]
        for label, var in gate_checks:
            tk.Checkbutton(
                s2,
                text=label,
                variable=var,
                font=("Segoe UI", 9),
                fg=TEXT_BODY,
                bg=BG_CARD,
                selectcolor=BG_CANVAS,
                activebackground=BG_CARD,
                activeforeground=TEXT_TITLE,
            ).pack(anchor=tk.W, pady=2)

        # Section 3: Notification & Audio Alerts
        s3 = tk.Frame(scrollable_frame, bg=BG_CARD, padx=14, pady=12, highlightbackground=BORDER_COLOR, highlightthickness=1)
        s3.pack(fill=tk.X, pady=(0, 12))

        tk.Label(s3, text="3. Alerts & Notifications", font=("Segoe UI", 10, "bold"), fg=TEXT_TITLE, bg=BG_CARD).pack(anchor=tk.W, pady=(0, 6))

        self.var_toasts = tk.BooleanVar(value=self.vault_settings.enable_toasts)
        tk.Checkbutton(
            s3,
            text="Enable Windows Desktop Toast Notifications on detected threat",
            variable=self.var_toasts,
            font=("Segoe UI", 9),
            fg=TEXT_BODY,
            bg=BG_CARD,
            selectcolor=BG_CANVAS,
            activebackground=BG_CARD,
            activeforeground=TEXT_TITLE,
        ).pack(anchor=tk.W, pady=2)

        self.var_beep = tk.BooleanVar(value=self.vault_settings.enable_console_beep)
        tk.Checkbutton(
            s3,
            text="Enable Audible Alert Tone on high-severity threat detection",
            variable=self.var_beep,
            font=("Segoe UI", 9),
            fg=TEXT_BODY,
            bg=BG_CARD,
            selectcolor=BG_CANVAS,
            activebackground=BG_CARD,
            activeforeground=TEXT_TITLE,
        ).pack(anchor=tk.W, pady=2)

        # Save Action
        save_btn_frame = tk.Frame(scrollable_frame, bg=BG_CANVAS)
        save_btn_frame.pack(fill=tk.X, pady=(4, 16))

        save_btn = tk.Button(
            save_btn_frame,
            text="💾 Save & Encrypt to Vault",
            font=("Segoe UI", 10, "bold"),
            bg=ACCENT_BLUE,
            fg="#ffffff",
            activebackground=ACCENT_HOVER,
            activeforeground="#ffffff",
            padx=18,
            pady=8,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._save_settings_vault,
        )
        save_btn.pack(side=tk.LEFT)

        self.vault_status_lbl = tk.Label(
            save_btn_frame,
            text=f"📁 Vault location: {self.vault_mgr.vault_path}",
            font=("Segoe UI", 8),
            fg=TEXT_MUTED,
            bg=BG_CANVAS,
            padx=12,
        )
        self.vault_status_lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Section 4: User-Inspectable Diagnostic Logs & Maintenance
        s4 = tk.Frame(scrollable_frame, bg=BG_CARD, padx=14, pady=12, highlightbackground=BORDER_COLOR, highlightthickness=1)
        s4.pack(fill=tk.X, pady=(0, 16))

        tk.Label(s4, text="4. Diagnostic Logs & Maintenance", font=("Segoe UI", 10, "bold"), fg=TEXT_TITLE, bg=BG_CARD).pack(anchor=tk.W, pady=(0, 4))
        tk.Label(
            s4,
            text="Logs are stored 100% locally. Export forum-safe anonymized bundles or permanently purge local caches:",
            font=("Segoe UI", 9),
            fg=TEXT_MUTED,
            bg=BG_CARD,
        ).pack(anchor=tk.W, pady=(0, 6))

        self.diag_log_text = tk.Text(
            s4,
            bg=BG_CANVAS,
            fg=TEXT_BODY,
            font=("Consolas", 9),
            relief=tk.FLAT,
            wrap=tk.NONE,
            height=8,
            highlightbackground=BORDER_COLOR,
            highlightthickness=1,
            padx=8,
            pady=6,
        )
        self.diag_log_text.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        act_row = tk.Frame(s4, bg=BG_CARD)
        act_row.pack(fill=tk.X)

        open_dir_btn = tk.Button(
            act_row,
            text="📁 Open Logs Directory",
            font=("Segoe UI", 9, "bold"),
            bg=ACCENT_BLUE,
            fg="#ffffff",
            activebackground=ACCENT_HOVER,
            activeforeground="#ffffff",
            padx=10,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._open_logs_dir,
        )
        open_dir_btn.pack(side=tk.LEFT, padx=(0, 6))

        export_bundle_btn = tk.Button(
            act_row,
            text="📦 Export Anonymized Bundle",
            font=("Segoe UI", 9, "bold"),
            bg=ACCENT_EMERALD,
            fg="#ffffff",
            activebackground="#059669",
            activeforeground="#ffffff",
            padx=10,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._export_forum_bundle,
        )
        export_bundle_btn.pack(side=tk.LEFT, padx=(0, 6))

        refresh_logs_btn = tk.Button(
            act_row,
            text="🔄 Refresh Logs",
            font=("Segoe UI", 9),
            bg=BG_ELEVATED,
            fg=TEXT_TITLE,
            padx=8,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._refresh_diag_logs,
        )
        refresh_logs_btn.pack(side=tk.LEFT, padx=(0, 6))

        incidents_btn = tk.Button(
            act_row,
            text="🚨 Kill Incidents",
            font=("Segoe UI", 9),
            bg=BG_ELEVATED,
            fg="#fca5a5",
            padx=8,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._view_kill_incidents,
        )
        incidents_btn.pack(side=tk.LEFT, padx=(0, 6))

        nuke_btn = tk.Button(
            act_row,
            text="🗑️ Nuke All Local Data",
            font=("Segoe UI", 9, "bold"),
            bg=ALERT_RED,
            fg="#ffffff",
            activebackground="#b91c1c",
            activeforeground="#ffffff",
            padx=10,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._nuke_local_data,
        )
        nuke_btn.pack(side=tk.RIGHT)

        self._refresh_diag_logs()

    def _save_settings_vault(self) -> None:
        raw_names = self.entry_custom_names.get()
        names = [n.strip() for n in raw_names.split(",") if n.strip()]

        raw_domains = self.entry_custom_domains.get()
        domains = [d.strip() for d in raw_domains.split(",") if d.strip()]

        process_name = self.entry_default_process.get().strip() or "python"

        self.vault_settings = VaultSettings(
            custom_names=names,
            custom_domains=domains,
            custom_feeds=self.vault_settings.custom_feeds,
            default_watch_process=process_name,
            enable_toasts=self.var_toasts.get(),
            enable_console_beep=self.var_beep.get(),
            dlp_gate_cards=self.var_gate_cards.get(),
            dlp_gate_keys=self.var_gate_keys.get(),
            dlp_gate_usernames=self.var_gate_users.get(),
            dlp_gate_national_ids=self.var_gate_ids.get(),
            dlp_gate_ips=self.var_gate_ips.get(),
        )

        ok = self.vault_mgr.save_settings(self.vault_settings)
        if ok:
            self.sanitizer = PrivacySanitizer(
                extra_redacted_names=self.vault_settings.custom_names,
                categories=self.vault_settings.redaction_categories(),
            )
            now_str = time.strftime("%H:%M:%S")
            self.vault_status_lbl.config(
                text=f"✅ Saved at {now_str} ({len(names)} custom terms, {len(domains)} domains) • {self.vault_mgr.protection_description}",
                fg="#22c55e",
            )
            self._refresh_telemetry_ui()
            messagebox.showinfo(
                "Settings Vault Updated",
                f"{self.vault_mgr.protection_description}\n\n"
                f"Custom Redacted Terms: {len(names)}\n"
                f"Custom Blocked Domains: {len(domains)}\n"
                f"Vault Path: {self.vault_mgr.vault_path}",
            )
        else:
            self.vault_status_lbl.config(text="❌ Failed to save encrypted vault", fg="#ef4444")
            messagebox.showerror(
                "Vault Error",
                "Failed to encrypt and save settings to the DPAPI vault. Check permissions.",
            )

    def _build_diagnostics_tab(self) -> None:
        """Compatibility wrapper; functionality now merged into _build_settings_tab."""
        self._refresh_diag_logs()

    def _build_documentation_tab(self) -> None:
        header_card = tk.Frame(self.tab_docs, bg=BG_CARD, padx=16, pady=10, highlightbackground=BORDER_COLOR, highlightthickness=1)
        header_card.pack(fill=tk.X, pady=(0, 10))

        tk.Label(
            header_card,
            text="📖 SentinelWire System Architecture & AI Integration Guides",
            font=("Segoe UI", 12, "bold"),
            fg=TEXT_TITLE,
            bg=BG_CARD,
        ).pack(anchor=tk.W)

        tk.Label(
            header_card,
            text="Offline reference for privacy airlocks, 5-Gate DLP, threat detection, and AI MCP integration.",
            font=("Segoe UI", 9),
            fg=TEXT_MUTED,
            bg=BG_CARD,
        ).pack(anchor=tk.W, pady=(2, 6))

        mcp_bar = tk.Frame(header_card, bg=BG_CANVAS, padx=10, pady=8, highlightbackground=BORDER_COLOR, highlightthickness=1)
        mcp_bar.pack(fill=tk.X, pady=(4, 2))

        tk.Label(
            mcp_bar,
            text="🤖 Connect AI to SentinelWire MCP:",
            font=("Segoe UI", 9, "bold"),
            fg=BORDER_FOCUS,
            bg=BG_CANVAS,
        ).pack(side=tk.LEFT, padx=(0, 10))

        copy_mcp_btn = tk.Button(
            mcp_bar,
            text="📋 Copy MCP Configuration JSON (Cursor / Claude / Antigravity)",
            font=("Segoe UI", 9, "bold"),
            bg=ACCENT_BLUE,
            fg="#ffffff",
            activebackground=ACCENT_HOVER,
            activeforeground="#ffffff",
            padx=12,
            pady=4,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._copy_mcp_config_json,
        )
        copy_mcp_btn.pack(side=tk.LEFT)

        tk.Label(
            mcp_bar,
            text="7 tools: voice prompt, prompt sanitizer, process safety, file reader, malware scan, reputation, alerts.",
            font=("Segoe UI", 8),
            fg=TEXT_MUTED,
            bg=BG_CANVAS,
        ).pack(side=tk.RIGHT)

        # Split Container: Left Topic List, Right Document Text
        doc_container = tk.Frame(self.tab_docs, bg=BG_CANVAS)
        doc_container.pack(fill=tk.BOTH, expand=True)

        topic_sidebar = tk.Frame(doc_container, bg=BG_SURFACE, width=230, padx=8, pady=8, highlightbackground=BORDER_COLOR, highlightthickness=1)
        topic_sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        topic_sidebar.pack_propagate(False)

        tk.Label(
            topic_sidebar,
            text="DOCUMENTATION TOPICS",
            font=("Segoe UI", 8, "bold"),
            fg=TEXT_MUTED,
            bg=BG_SURFACE,
            padx=4,
            pady=4,
        ).pack(anchor=tk.W)

        self._doc_topic_buttons = []
        topics = [
            ("🛡️ Offline AI Airlock", "airlock"),
            ("🔒 5-Gate DLP Engine", "dlp"),
            ("📡 Wire Sniffer & LOTS", "wire"),
            ("🤖 AI MCP Tools Guide", "mcp"),
            ("🚨 Kill Switch Recovery", "killswitch"),
            ("📜 License & Privacy", "privacy"),
        ]

        for text, tid in topics:
            btn = tk.Button(
                topic_sidebar,
                text=text,
                font=("Segoe UI", 9),
                anchor="w",
                bg=BG_CARD if tid == "airlock" else BG_SURFACE,
                fg=BORDER_FOCUS if tid == "airlock" else TEXT_MUTED,
                activebackground=BG_ELEVATED,
                activeforeground=TEXT_TITLE,
                padx=10,
                pady=7,
                relief=tk.FLAT,
                cursor="hand2",
                command=lambda t=tid: self._show_doc_topic(t),
            )
            btn.pack(fill=tk.X, pady=2)
            self._doc_topic_buttons.append((tid, btn))

        # Right Text Display
        right_doc = tk.Frame(doc_container, bg=BG_CARD, padx=12, pady=10, highlightbackground=BORDER_COLOR, highlightthickness=1)
        right_doc.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.doc_content_text = tk.Text(
            right_doc,
            bg=BG_CARD,
            fg=TEXT_BODY,
            font=("Segoe UI", 9),
            relief=tk.FLAT,
            wrap=tk.WORD,
            padx=16,
            pady=14,
        )
        self.doc_content_text.tag_configure("title", font=("Segoe UI", 12, "bold"), foreground=TEXT_TITLE, spacing3=8)
        self.doc_content_text.tag_configure("h1", font=("Segoe UI", 10, "bold"), foreground=BORDER_FOCUS, spacing1=8, spacing3=4)
        self.doc_content_text.tag_configure("bullet", font=("Segoe UI", 9), foreground=TEXT_BODY, lmargin1=14, lmargin2=28, spacing1=2, spacing3=2)
        self.doc_content_text.tag_configure("body", font=("Segoe UI", 9), foreground=TEXT_BODY, spacing1=2, spacing3=4)
        self.doc_content_text.tag_configure("code", font=("Consolas", 9), foreground="#38bdf8", background=BG_ELEVATED)

        doc_scroll = ttk.Scrollbar(right_doc, orient="vertical", command=self.doc_content_text.yview)
        self.doc_content_text.configure(yscrollcommand=doc_scroll.set)
        self.doc_content_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        doc_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self._show_doc_topic("airlock")

    def _show_doc_topic(self, topic_id: str) -> None:
        for tid, btn in self._doc_topic_buttons:
            if tid == topic_id:
                btn.config(bg=BG_CARD, fg=BORDER_FOCUS, font=("Segoe UI", 9, "bold"))
            else:
                btn.config(bg=BG_SURFACE, fg=TEXT_MUTED, font=("Segoe UI", 9, "normal"))

        doc_sections = {
            "airlock": [
                ("title", "🛡️ 100% OFFLINE AI AIRLOCK & SPEECH DICTATION"),
                ("body", "SentinelWire acts as a protective airlock between your machine and external AI models (such as Claude, ChatGPT, Gemini, Cursor, and VS Code Copilot)."),
                ("h1", "Zero Outbound Telemetry:"),
                ("body", "During active monitoring, SentinelWire engages PEP 578 runtime socket isolation. The app never phones home, sends crash reports to cloud servers, or transmits user data."),
                ("h1", "Air-Gapped Speech Dictation:"),
                ("body", "Audio is captured via your local microphone using sounddevice and transcribed completely offline on your CPU using faster-whisper with local_files_only=True. No audio is ever streamed to cloud speech-to-text APIs."),
                ("h1", "Automatic MCP Airlock Buffer:"),
                ("body", "Every dictated prompt and scrubbed snippet is automatically stored in a secure local buffer (%LOCALAPPDATA%\\PacketSentinel\\latest_voice_prompt.json). Your connected AI assistant can fetch it directly through the MCP tool 'get_latest_voice_prompt' without any copy-paste."),
            ],
            "dlp": [
                ("title", "🔒 PRE-MODEL 5-GATE DATA LOSS PREVENTION (DLP) ENGINE"),
                ("body", "Before any file, log, or prompt text reaches an AI model or external API, it passes through 5 defensive redaction gates:"),
                ("h1", "Gate 1: File Extension & Magic-Byte Guard"),
                ("body", "Prevents AI from accidentally reading sensitive binaries, passport photos (.png, .jpg), tax documents (.pdf, .xlsx), SQLite databases, or SSH private keys (.id_rsa, .pem)."),
                ("h1", "Gate 2: Payment Cards & Financial Data (Luhn Algorithm)"),
                ("body", "Detects Visa, Mastercard, Amex, Discover, and IBAN bank account numbers with full checksum validation, replacing them with [REDACTED_PAYMENT_CARD] / [REDACTED_IBAN]."),
                ("h1", "Gate 3: OS Usernames & Machine Paths (Zero Machine-Binding)"),
                ("body", "Redacts Windows user profile names (e.g. C:\\Users\\<username>\\) and local MAC addresses to ensure no prompt leaks your host machine identity."),
                ("h1", "Gate 4: National Personal Identity Codes"),
                ("body", "Redacts US SSNs, UK National Insurance numbers, and Nordic Personal Identity Codes."),
                ("h1", "Gate 5: API Keys, JWTs & Secret Tokens"),
                ("body", "Scans for OpenAI keys (sk-...), Anthropic keys (sk-ant-...), GitHub tokens (ghp_...), AWS access keys (AKIA...), bearer tokens, and RSA private key headers."),
            ],
            "wire": [
                ("title", "📡 LIVE WIRE PACKET CAPTURE & LOTS EXFILTRATION DEFENSE"),
                ("body", "SentinelWire continuously audits system network sockets, DNS queries, and TLS handshakes."),
                ("h1", "Living-off-the-Land (LOTS / LOLBIN) Defense:"),
                ("body", "Attackers and rogue scripts often use legitimate Windows utilities (powershell.exe, curl.exe, bitsadmin.exe, certutil.exe) to silently exfiltrate stolen credentials. SentinelWire traces every outbound network connection back to its originating process and warns when an interpreter makes unexpected connections."),
                ("h1", "Multi-Feed Offline Threat Intel:"),
                ("body", "Evaluates IP and domain destinations against built-in ThreatFox, URLhaus, and custom threat feeds stored completely locally."),
            ],
            "mcp": [
                ("title", "🤖 AI MCP TOOLS REFERENCE (MODEL CONTEXT PROTOCOL)"),
                ("body", "SentinelWire exposes 7 offline, DLP-enforced MCP tools over JSON-RPC stdio:"),
                ("bullet", "• 1. get_latest_voice_prompt: Fetches the most recent pre-sanitized voice dictation without manual copy-paste."),
                ("bullet", "• 2. sanitize_prompt_text(text): Scans and sanitizes arbitrary prompts, logs, or terminal outputs using the 5-Gate DLP."),
                ("bullet", "• 3. inspect_process_safety(process_name_or_pid): Inspects a running process to audit its child lineage and detect rogue script interpreters."),
                ("bullet", "• 4. read_sanitized_project_text(relative_path, start_line, end_line): Safely reads workspace files with all secrets, tokens, and machine names scrubbed."),
                ("bullet", "• 5. scan_downloaded_payload_malware(content_text, filename): Pure offline scan for deceptive extensions, polyglot binaries, and encoded scripts."),
                ("bullet", "• 6. check_indicator_reputation(indicator): Verifies domains/IPs against offline threat feeds."),
                ("bullet", "• 7. get_sanitized_security_alerts(limit): Returns recent threat detection events."),
            ],
            "killswitch": [
                ("title", "🚨 EMERGENCY KILL SWITCH & POST-MORTEM INCIDENT LOGGING"),
                ("body", "The Emergency Kill Switch provides an instantaneous panic button if you detect suspicious traffic or unapproved network behavior."),
                ("h1", "What Happens When Engaged:"),
                ("bullet", "• 1. Sockets Severed: Python PEP 578 runtime socket lockdown intercepts and terminates in-process network calls."),
                ("bullet", "• 2. Processes Killed: Background sniffer threads and capture helpers (dumpcap, tshark) are terminated immediately."),
                ("bullet", "• 3. Incident Recorded: An anonymized incident report is written to disk at %LOCALAPPDATA%\\PacketSentinel\\logs\\incident_reports\\kill_switch_incident_<timestamp>.json."),
                ("h1", "Is the App Usable Afterwards?"),
                ("body", "YES! The kill switch is temporary and immediate. It cleanly stops the running process. You can relaunch SentinelWire anytime using run.bat."),
                ("h1", "Safe Reporting:"),
                ("body", "All incident reports are scrubbed by the 5-Gate DLP. You can click 'Copy Incident Report' and paste it directly into GitHub Issues or forums with 0 risk of leaking secrets."),
            ],
            "privacy": [
                ("title", "📜 OPEN SOURCE & PRIVACY GUARANTEES"),
                ("bullet", "• License: Apache License 2.0 (100% Permissive Open Source)."),
                ("bullet", "• Zero Copyleft Contamination: Zero GPL or AGPL dependencies."),
                ("bullet", "• Zero Machine Identifiers in Repo: Automated scanning guarantees no private hostnames, MACs, or usernames are stored in source code."),
                ("bullet", "• Local DPAPI Encryption: Custom user blocklists and sensitive terms are encrypted using Windows CryptProtectData tied to your Windows user account."),
                ("bullet", "• 1-Click Complete Purge: Click 'Nuke All Local Data' in Settings to completely erase diagnostic files and voice audio buffers."),
            ],
        }

        self.doc_content_text.config(state="normal")
        self.doc_content_text.delete("1.0", tk.END)
        sections = doc_sections.get(topic_id, [("body", "Topic not found.")])
        for tag, text in sections:
            self.doc_content_text.insert(tk.END, text + "\n\n", tag)
        self.doc_content_text.config(state="disabled")
        self.doc_content_text.see("1.0")

    def _copy_mcp_config_json(self) -> None:
        snippet = {
            "mcpServers": {
                "sentinelwire": {
                    "command": "python",
                    "args": ["-m", "packetsentinel.cli", "--mcp"],
                    "env": {
                        "PYTHONUNBUFFERED": "1"
                    }
                }
            }
        }
        text_to_copy = json.dumps(snippet, indent=2)
        self.root.clipboard_clear()
        self.root.clipboard_append(text_to_copy)
        messagebox.showinfo(
            "MCP Configuration Copied",
            "SentinelWire MCP server configuration copied to clipboard!\n\n"
            "Paste this snippet into your IDE or AI assistant config:\n"
            "• Antigravity / Cursor: ~/.gemini/antigravity/mcp_config.json\n"
            "• Claude Desktop: %APPDATA%\\Claude\\claude_desktop_config.json\n"
            "• VS Code Copilot: .vscode/mcp.json",
        )

    def _open_logs_dir(self) -> None:
        log_dir = get_log_dir()
        try:
            if platform.system() == "Windows":
                os.startfile(str(log_dir))  # type: ignore[attr-defined]
            else:
                subprocess.run(["xdg-open", str(log_dir)], check=False, shell=False)
        except Exception as e:
            messagebox.showerror("Error Opening Directory", f"Could not open directory: {e}")

    def _open_appdata_dir(self) -> None:
        app_dir = get_app_data_dir()
        try:
            if platform.system() == "Windows":
                os.startfile(str(app_dir))  # type: ignore[attr-defined]
            else:
                subprocess.run(["xdg-open", str(app_dir)], check=False, shell=False)
        except Exception as e:
            messagebox.showerror("Error Opening AppData", f"Could not open directory: {e}")

    def _refresh_diag_logs(self) -> None:
        log_file = get_log_dir() / "sentinelwire.log"
        self.diag_log_text.delete("1.0", tk.END)
        if log_file.exists():
            try:
                with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
                    self.diag_log_text.insert(tk.END, "".join(lines[-150:]))
            except Exception as e:
                self.diag_log_text.insert(tk.END, f"[!] Error reading log file: {e}\n")
        else:
            self.diag_log_text.insert(tk.END, "[*] No diagnostic logs created yet. Actions will appear here.\n")
        self.diag_log_text.see(tk.END)

    def _export_forum_bundle(self) -> None:
        bundle = generate_anonymized_diagnostic_bundle(recent_lines=80, sanitizer=self.sanitizer)

        # Show modal dialog with preview and copy button
        diag_win = tk.Toplevel(self.root)
        diag_win.title("Anonymized Forum Diagnostic Bundle")
        diag_win.geometry("700x520")
        diag_win.configure(bg="#0f172a")

        tk.Label(
            diag_win,
            text="Anonymized Diagnostic Report (Safe for GitHub Issues / Reddit / Discord):",
            font=("Segoe UI", 10, "bold"),
            fg="#f8fafc",
            bg="#0f172a",
            padx=14,
            pady=10,
        ).pack(anchor=tk.W)

        bundle_text = tk.Text(diag_win, bg="#020617", fg="#38bdf8", font=("Consolas", 9), relief=tk.FLAT, padx=10, pady=10)
        bundle_text.pack(fill=tk.BOTH, expand=True, padx=14, pady=(0, 10))
        bundle_text.insert(tk.END, bundle)

        b_bar = tk.Frame(diag_win, bg="#0f172a", padx=14, pady=10)
        b_bar.pack(fill=tk.X)

        def _copy_bundle() -> None:
            self.root.clipboard_clear()
            self.root.clipboard_append(bundle)
            messagebox.showinfo("Copied", "Diagnostic bundle copied to clipboard! Safe to post publicly.")

        copy_b = tk.Button(
            b_bar,
            text="📋 Copy Diagnostic Bundle to Clipboard",
            font=("Segoe UI", 9, "bold"),
            bg="#0284c7",
            fg="#ffffff",
            padx=14,
            pady=6,
            relief=tk.FLAT,
            command=_copy_bundle,
        )
        copy_b.pack(side=tk.LEFT)

        close_b = tk.Button(
            b_bar,
            text="Close",
            font=("Segoe UI", 9),
            bg="#1e293b",
            fg="#94a3b8",
            padx=12,
            pady=6,
            relief=tk.FLAT,
            command=diag_win.destroy,
        )
        close_b.pack(side=tk.RIGHT)

    def _view_kill_incidents(self) -> None:
        incidents = list_kill_switch_incidents(limit=10)
        inc_win = tk.Toplevel(self.root)
        inc_win.title("Kill Switch Post-Mortem Incident Reports")
        inc_win.geometry("720x540")
        inc_win.configure(bg="#0f172a")

        tk.Label(
            inc_win,
            text="🚨 Emergency Kill Switch Incident History",
            font=("Segoe UI", 11, "bold"),
            fg="#f87171",
            bg="#0f172a",
            padx=14,
            pady=8,
        ).pack(anchor=tk.W)

        tk.Label(
            inc_win,
            text="Every kill switch event is recorded with 5-Gate DLP scrubbing so you can safely export and report issues to GitHub or forums without leaking system data.",
            font=("Segoe UI", 9),
            fg="#94a3b8",
            bg="#0f172a",
            padx=14,
            wraplength=680,
            justify=tk.LEFT,
        ).pack(anchor=tk.W, pady=(0, 8))

        inc_text = tk.Text(inc_win, bg="#020617", fg="#38bdf8", font=("Consolas", 9), relief=tk.FLAT, padx=10, pady=10)
        inc_text.pack(fill=tk.BOTH, expand=True, padx=14, pady=(0, 10))

        if not incidents:
            inc_text.insert(tk.END, "[*] No Kill Switch incidents recorded. Clean operating history.\n")
        else:
            for inc in incidents:
                inc_text.insert(
                    tk.END,
                    f"======================================================================\n"
                    f"Incident ID   : {inc.get('incident_id', 'UNKNOWN')}\n"
                    f"Timestamp UTC : {inc.get('timestamp_utc', 'UNKNOWN')}\n"
                    f"Action Taken  : {inc.get('action', 'UNKNOWN')}\n"
                    f"Reported Cause: {inc.get('reason', 'UNKNOWN')}\n"
                    f"Environment   : {json.dumps(inc.get('environment', {}))}\n"
                    f"Telemetry     : {json.dumps(inc.get('telemetry_at_kill', {}), indent=2)}\n\n"
                )

        b_bar = tk.Frame(inc_win, bg="#0f172a", padx=14, pady=10)
        b_bar.pack(fill=tk.X)

        def _copy_incidents() -> None:
            content = inc_text.get("1.0", tk.END).strip()
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            messagebox.showinfo("Copied", "Incident report copied to clipboard! Safe to post publicly.")

        copy_b = tk.Button(
            b_bar,
            text="📋 Copy Incident Report for GitHub / Forums",
            font=("Segoe UI", 9, "bold"),
            bg="#0284c7",
            fg="#ffffff",
            padx=14,
            pady=6,
            relief=tk.FLAT,
            command=_copy_incidents,
        )
        copy_b.pack(side=tk.LEFT)

        close_b = tk.Button(
            b_bar,
            text="Close",
            font=("Segoe UI", 9),
            bg="#1e293b",
            fg="#94a3b8",
            padx=12,
            pady=6,
            relief=tk.FLAT,
            command=inc_win.destroy,
        )
        close_b.pack(side=tk.RIGHT)

    def _nuke_local_data(self) -> None:
        confirm = messagebox.askyesno(
            "Purge All Local Data?",
            "Are you sure you want to permanently delete all local logs, audio voice buffers, and temporary caches?\n\n"
            "This will completely wipe local history. Your encrypted settings vault will be kept safe.",
        )
        if not confirm:
            return
        res = purge_all_local_data()
        self._refresh_diag_logs()
        messagebox.showinfo(
            "Local Data Purged",
            f"Successfully deleted {res['files_purged']} local files ({res['bytes_freed']} bytes freed).\n\n"
            "All temporary buffers and diagnostic logs have been wiped.",
        )

    def _build_footer(self) -> None:
        footer = tk.Frame(self.root, bg="#0f172a", height=32, padx=16, pady=6)
        footer.pack(fill=tk.X, side=tk.BOTTOM)

        lbl = tk.Label(
            footer,
            text="SentinelWire v1.0 Prototype • 100% Offline • Zero Outbound • Apache-2.0 License • Minimizes to Tray on Close",
            font=("Segoe UI", 8),
            fg="#64748b",
            bg="#0f172a",
        )
        lbl.pack(side=tk.LEFT)

        min_btn = tk.Button(
            footer,
            text="Hide to Background",
            font=("Segoe UI", 8),
            bg="#1e293b",
            fg="#94a3b8",
            padx=8,
            pady=2,
            relief=tk.FLAT,
            cursor="hand2",
            command=self._minimize_to_tray,
        )
        min_btn.pack(side=tk.RIGHT)

    def _on_window_close(self) -> None:
        res = messagebox.askyesnocancel(
            "SentinelWire Background Protection",
            "Do you want to keep SentinelWire running in the background to protect your system?\n\n"
            "• Click YES to minimize to the background.\n"
            "• Click NO to exit completely.\n"
            "• Click CANCEL to stay in the window.",
        )
        if res is True:
            self._minimize_to_tray()
        elif res is False:
            self.root.destroy()
            os._exit(0)

    def _minimize_to_tray(self) -> None:
        self.root.iconify()

    def _emergency_kill(self) -> None:
        dialog = tk.Toplevel(self.root)
        dialog.title("Confirm Emergency Kill Switch")
        dialog.geometry("540x390")
        dialog.configure(bg="#0f172a")
        dialog.transient(self.root)
        dialog.grab_set()

        tk.Label(
            dialog,
            text="🚨 INITIATE EMERGENCY KILL SWITCH",
            font=("Segoe UI", 12, "bold"),
            fg="#f87171",
            bg="#0f172a",
            padx=16,
            pady=10,
        ).pack(anchor=tk.W)

        desc = (
            "Engaging the Kill Switch immediately executes:\n"
            "• PEP 578 runtime socket lockdown (severing all in-process networking)\n"
            "• Immediate termination of background wire capture & sniffer threads\n"
            "• Termination of orphan capture tools (tshark/dumpcap)\n"
            "• Generates an anonymized post-mortem incident report\n\n"
            "Note: This is an emergency stop. You can launch and use SentinelWire again anytime via run.bat."
        )
        tk.Label(
            dialog,
            text=desc,
            font=("Segoe UI", 9),
            fg="#cbd5e1",
            bg="#0f172a",
            justify=tk.LEFT,
            padx=16,
        ).pack(anchor=tk.W, pady=(0, 10))

        tk.Label(
            dialog,
            text="Reason for Kill Switch (saved to anonymized incident report):",
            font=("Segoe UI", 9, "bold"),
            fg="#94a3b8",
            bg="#0f172a",
            padx=16,
        ).pack(anchor=tk.W)

        reason_var = tk.StringVar(value="Suspicious / unexpected network traffic")
        reasons = [
            "Suspicious / unexpected network traffic",
            "High CPU load or application frozen",
            "Testing emergency kill switch",
            "Manual user abort / security precaution",
        ]
        for r in reasons:
            tk.Radiobutton(
                dialog,
                text=r,
                variable=reason_var,
                value=r,
                font=("Segoe UI", 9),
                fg="#e2e8f0",
                bg="#0f172a",
                selectcolor="#1e293b",
                activebackground="#0f172a",
                activeforeground="#ffffff",
                padx=16,
            ).pack(anchor=tk.W)

        btn_bar = tk.Frame(dialog, bg="#0f172a", padx=16, pady=16)
        btn_bar.pack(fill=tk.X, side=tk.BOTTOM)

        def _execute_kill() -> None:
            reason = reason_var.get()
            snap = self._monitor_service.snapshot()
            recent_alerts = [
                {
                    "time": a.timestamp_utc,
                    "indicator": a.indicator,
                    "feed": a.source_feed,
                    "process": a.process_name,
                }
                for a in self._monitor_service.recent_alerts(limit=10)
            ]
            snapshot_dict = {
                "events_inspected": snap.events_inspected,
                "alerts_emitted": snap.alerts_emitted,
                "recent_alerts": recent_alerts,
            }
            inc_file = record_kill_switch_incident(
                reason=reason,
                snapshot_data=snapshot_dict,
                sanitizer=self.sanitizer,
            )
            try:
                self._monitor_service.shutdown()
            except Exception as e:
                logger.warning(f"Error shutting down monitor service during kill switch: {e}")
            engage_runtime_network_lockdown()

            dialog.destroy()
            messagebox.showwarning(
                "EMERGENCY KILL SWITCH ENGAGED",
                f"Runtime sockets severed and capture engines terminated.\n\n"
                f"Post-mortem incident recorded to:\n{inc_file.name}\n\n"
                f"SentinelWire will now exit. You can restart cleanly anytime with run.bat.",
            )
            self.root.destroy()
            os._exit(0)

        kill_btn = tk.Button(
            btn_bar,
            text="🚨 ENGAGE KILL SWITCH NOW",
            font=("Segoe UI", 10, "bold"),
            bg="#dc2626",
            fg="#ffffff",
            activebackground="#b91c1c",
            activeforeground="#ffffff",
            padx=14,
            pady=6,
            relief=tk.FLAT,
            cursor="hand2",
            command=_execute_kill,
        )
        kill_btn.pack(side=tk.LEFT)

        cancel_btn = tk.Button(
            btn_bar,
            text="Cancel / Return to App",
            font=("Segoe UI", 9),
            bg="#1e293b",
            fg="#94a3b8",
            padx=12,
            pady=6,
            relief=tk.FLAT,
            cursor="hand2",
            command=dialog.destroy,
        )
        cancel_btn.pack(side=tk.RIGHT)

    def run(self) -> None:
        """Run the main event loop and clean up background services on exit."""
        try:
            self.root.mainloop()
        finally:
            try:
                self._monitor_service.shutdown()
            except Exception:
                pass


def launch_desktop_app(config: Optional[AppConfig] = None) -> None:
    """Entry point for CLI `--ui` command to launch the SentinelWire desktop app."""
    app = PacketSentinelDesktopApp(config=config)
    app.run()
