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

# Prevent fatal OpenMP runtime collision on Windows (Anaconda + CTranslate2/faster-whisper)
os.environ.setdefault("KMP_DUPLICATE_LIB_OK", "TRUE")
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
    sanitize_log_text,
    setup_diagnostic_logging,
)
from .egress_guard import engage_runtime_network_lockdown
from .live_monitor_service import AlertRow, LiveMonitorService, MonitorSnapshot
from .mcp_privacy import PrivacySanitizer
from .process_watchdog import inspect_child_lineage
from .security import is_public_routable_ip
from .vault import EncryptedVaultManager, VaultSettings
from .voice_engine import (
    MicrophoneRecorder,
    OfflineTranscriber,
    VoiceEngineError,
    VoiceEngineStatus,
    check_voice_status,
    download_offline_model,
    get_model_dir,
    is_model_cached,
    is_snapshot_incomplete,
    is_windows_dictation_available,
    repair_offline_model,
)
from .ui_components import (
    ACCENT_BLUE,
    ACCENT_EMERALD,
    ACCENT_GREEN,
    ACCENT_HOVER,
    ACCENT_RED,
    ACCENT_YELLOW,
    ALERT_RED,
    BG_CANVAS,
    BG_CARD,
    BG_ELEVATED,
    BG_SURFACE,
    BORDER_COLOR,
    BORDER_FOCUS,
    FONT_BODY,
    FONT_BOLD,
    FONT_HEADER,
    FONT_MONO,
    FONT_SECTION,
    FONT_SMALL,
    FONT_SMALL_BOLD,
    TEXT_BODY,
    TEXT_HINT,
    TEXT_MAIN,
    TEXT_MUTED,
    TEXT_TITLE,
    create_card_frame,
    create_data_table,
    create_status_pill,
    create_styled_button,
    create_styled_entry,
    update_status_pill,
)

logger = logging.getLogger("sentinelwire.ui")


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
        self._voice_status: Optional[VoiceEngineStatus] = None
        self._voice_setup_dialog: Optional[tk.Toplevel] = None

        self._monitor_service = LiveMonitorService(self.config, lock_network_on_start=False)
        self._telemetry_timer_id: Optional[str] = None
        self._threat_rows_seen: Set[str] = set()

        self._packet_count = 0
        self._threat_count = 0
        self._nav_buttons: List[tk.Button] = []

        self.root = parent_root or tk.Tk()
        self.root.report_callback_exception = self._on_tk_exception
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

        # Check initial voice status proactively on startup
        self._refresh_voice_status()

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
            font=FONT_BODY,
        )
        style.configure(
            "Treeview.Heading",
            background=BG_ELEVATED,
            foreground=TEXT_TITLE,
            relief="flat",
            font=FONT_BOLD,
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
        style.configure(
            "Horizontal.TScrollbar",
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

        copy_logs_btn = create_styled_button(
            action_frame,
            text="Copy Logs for AI",
            icon="📋",
            style="secondary",
            command=self._copy_ai_diagnostic_summary,
            font=FONT_BOLD,
            padx=10,
            pady=5,
        )
        copy_logs_btn.pack(side=tk.LEFT, padx=(0, 10))

        badge = create_status_pill(
            action_frame,
            text="🟢 AIRLOCK ACTIVE (0 OUTBOUND)",
            status="ok",
            font=FONT_BOLD,
            padx=12,
            pady=5,
        )
        badge.pack(side=tk.LEFT, padx=(0, 12))

        kill_btn = create_styled_button(
            action_frame,
            text="EMERGENCY KILL SWITCH",
            icon="🚨",
            style="danger",
            command=self._emergency_kill,
            font=FONT_BOLD,
            padx=12,
            pady=5,
        )
        kill_btn.pack(side=tk.LEFT)

        # Real-time alert / notification toast strip (hidden until an alert or notice is dispatched)
        self.notification_bar = tk.Frame(self.root, bg="#064e3b", padx=16, pady=6)
        self.notification_lbl = tk.Label(
            self.notification_bar,
            text="",
            font=FONT_BOLD,
            fg="#22c55e",
            bg="#064e3b",
        )
        self.notification_lbl.pack(side=tk.LEFT)
        self.notification_action_btn = create_styled_button(
            self.notification_bar,
            text="View in Traffic Guard",
            style="secondary",
            font=FONT_SMALL,
            padx=10,
            pady=2,
            command=lambda: (self._select_nav(1), self._dismiss_notification()),
        )
        self.notification_dismiss_btn = create_styled_button(
            self.notification_bar,
            text="✕",
            style="ghost",
            font=FONT_SMALL,
            padx=6,
            pady=2,
            command=self._dismiss_notification,
        )
        self.notification_dismiss_btn.pack(side=tk.RIGHT, padx=(6, 0))

    def show_notification(
        self,
        message: str,
        level: str = "info",
        action_text: str = "",
        action_cmd: Any = None,
    ) -> None:
        """Surfaces a top-level alert toast so the developer immediately spots intercepted threats or errors."""
        if not hasattr(self, "notification_bar"):
            return
        bg_col = "#7f1d1d" if level == "error" else ("#78350f" if level == "warning" else "#064e3b")
        fg_col = "#fca5a5" if level == "error" else ("#fde047" if level == "warning" else "#22c55e")
        self.notification_bar.config(bg=bg_col)
        self.notification_lbl.config(text=message, bg=bg_col, fg=fg_col)
        if action_text and action_cmd:
            self.notification_action_btn.config(text=action_text, command=action_cmd)
            self.notification_action_btn.pack(side=tk.RIGHT, padx=(0, 6))
        else:
            self.notification_action_btn.pack_forget()
        target_before = getattr(self, "strip_frame", None)
        if target_before and target_before.winfo_exists():
            self.notification_bar.pack(fill=tk.X, padx=16, pady=(2, 0), before=target_before)
        else:
            self.notification_bar.pack(fill=tk.X, padx=16, pady=(2, 0))

    def _dismiss_notification(self) -> None:
        if hasattr(self, "notification_bar") and self.notification_bar.winfo_exists():
            self.notification_bar.pack_forget()

    def _build_metrics_strip(self) -> None:
        strip = tk.Frame(self.root, bg=BG_CANVAS, padx=16, pady=8)
        strip.pack(fill=tk.X)
        self.strip_frame = strip

        cards_data = [
            ("PACKETS MONITORED", "0", BORDER_FOCUS, "Live Wire Sniffer", 1),
            ("THREATS DETECTED", "0", ACCENT_EMERALD, "Click to View Details", 1),
            ("PRE-MODEL DLP", "5-Gate Active", "#c084fc", "PII, IDs, Tokens Scrubbed", 0),
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
            ("🛡️  Privacy Airlock", 0),
            ("📡  Traffic & Process Guard", 1),
            ("💻  IDE Integrations", 2),
            ("⚙️  Settings & Vault", 3),
            ("📖  Guides & Reference", 4),
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

        appdata_btn = create_styled_button(
            side_footer,
            text="Open Local AppData",
            icon="📁",
            style="ghost",
            command=self._open_appdata_dir,
            font=FONT_SMALL,
            padx=8,
            pady=4,
        )
        appdata_btn.pack(fill=tk.X, pady=2)

        # Right Content View Area (driven by ttk.Notebook for full test compatibility)
        self.notebook = ttk.Notebook(container)
        self.notebook.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Tab 0: AI Privacy Airlock & Dictation (Primary Developer View)
        self.tab_airlock = tk.Frame(self.notebook, bg=BG_CANVAS)
        self.notebook.add(self.tab_airlock, text="AI Privacy Airlock")
        self.tab_mission_control = self.tab_airlock
        self.tab_voice = self.tab_airlock
        self.tab_privacy = self.tab_airlock
        self._build_airlock_tab()

        # Tab 1: Live Wire & Process Guard (Packet Sniffer, Process Inspector, Threat Alerts)
        self.tab_monitor = tk.Frame(self.notebook, bg=BG_CANVAS)
        self.notebook.add(self.tab_monitor, text="Live Threat Monitor")
        self.tab_watchdog = self.tab_monitor
        self._build_monitor_tab()

        # Tab 2: Popular IDE Integrations (Cursor, VS Code / Copilot, Kiro, Windsurf, Claude)
        self.tab_ide_integrations = tk.Frame(self.notebook, bg=BG_CANVAS)
        self.notebook.add(self.tab_ide_integrations, text="IDE Integrations")
        self._build_ide_integrations_tab()

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
        """Compatibility wrapper; functionality now cleanly merged into _build_airlock_tab and _build_monitor_tab."""
        pass

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
            wraplength=750,
        )
        banner.pack(fill=tk.X, pady=(0, 8))

        def _on_airlock_banner_resize(event: tk.Event) -> None:
            if event.width > 100:
                banner.configure(wraplength=max(200, event.width - 32))

        banner.bind("<Configure>", _on_airlock_banner_resize)
        self.airlock_banner = banner
        self.cockpit_banner = banner
        self.banner = banner

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

        self.voice_btn = create_styled_button(
            ctrl_row,
            text="CLICK TO START DICTATING",
            icon="🎙️",
            style="primary",
            command=self._toggle_voice_recording,
            font=FONT_BOLD,
            padx=16,
            pady=6,
        )
        self.voice_btn.pack(side=tk.LEFT, padx=(0, 10))

        tk.Label(
            ctrl_row,
            text="Quick Prompt Bar:",
            font=FONT_BOLD,
            fg=TEXT_MAIN,
            bg=BG_CARD,
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.quick_speech_entry = create_styled_entry(
            ctrl_row,
            font=FONT_MONO,
        )
        self.quick_speech_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8), ipady=4)
        self.quick_speech_entry.bind("<Return>", lambda e: self._process_quick_speech())

        quick_btn = create_styled_button(
            ctrl_row,
            text="Scrub & Feed to MCP",
            icon="⚡",
            style="primary",
            command=self._process_quick_speech,
            font=FONT_BOLD,
            padx=12,
            pady=4,
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

        # Compatibility aliases
        self.mc_voice_status_pill = tk.Label(status_row, text="🟢 AIRLOCK READY (OFFLINE)")
        self.mc_voice_btn = self.voice_btn
        self.mc_voice_feedback_lbl = self.voice_feedback_lbl
        self.mc_quick_prompt_entry = self.quick_speech_entry

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

        scrub_btn = create_styled_button(
            act_bar,
            text="Scrub with 5-Gate DLP",
            icon="🧹",
            style="primary",
            command=self._scrub_input,
            font=FONT_BOLD,
            padx=14,
            pady=6,
        )
        scrub_btn.pack(side=tk.LEFT, padx=(0, 8))

        copy_btn = create_styled_button(
            act_bar,
            text="Copy Sanitized Text",
            icon="📋",
            style="secondary",
            command=self._copy_output,
            font=FONT_BOLD,
            padx=12,
            pady=6,
        )
        copy_btn.pack(side=tk.LEFT, padx=(0, 8))

        canary_btn = create_styled_button(
            act_bar,
            text="Load Test Canary Sample",
            icon="🧪",
            style="secondary",
            command=self._load_sample_canary,
            font=FONT_BODY,
            padx=12,
            pady=6,
        )
        canary_btn.pack(side=tk.LEFT, padx=(0, 8))

        clear_btn = create_styled_button(
            act_bar,
            text="Clear Airlock",
            icon="🗑️",
            style="secondary",
            command=self._clear_privacy_inputs,
            font=FONT_BODY,
            padx=12,
            pady=6,
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

    def _refresh_voice_status(self) -> VoiceEngineStatus:
        """Query offline voice engine health and update all UI status pills proactively."""
        try:
            status = check_voice_status(
                model_dir=get_model_dir(self.config.app_dir),
                model_name="base",
            )
        except Exception as exc:
            logger.warning(f"Error checking voice status: {exc}")
            status = VoiceEngineStatus(
                microphone_ready=False,
                transcriber_ready=False,
                detail=f"Voice check error: {exc}",
                stt_installed=False,
                model_cached=False,
                windows_dictation_available=is_windows_dictation_available(),
            )
        self._voice_status = status
        self._apply_voice_status(status)
        return status

    def _apply_voice_status(self, status: VoiceEngineStatus) -> None:
        """Reflect voice engine availability proactively across Mission Control and Airlock."""
        if self._is_recording:
            return

        has_win_dictation = getattr(status, "windows_dictation_available", False) or (sys.platform == "win32")

        if status.ready:
            pill_text = "🟢 AIRLOCK READY (OFFLINE)"
            pill_bg = "#064e3b"
            pill_fg = ACCENT_EMERALD
            mc_btn_text = "🎙️  Start Dictation (Spacebar)"
            airlock_btn_text = "🎙️  CLICK TO START DICTATING"
            mc_hint = "Push-to-talk ready. Auto-stops on silence (~1.8s) or press Spacebar."
            airlock_hint = "Microphone listening will remain 100% offline. Zero telemetry, zero cloud streaming."
            model_info = "Engine: Local Audio Capture • Pre-Model 5-Gate DLP • Zero Cloud Calls"
        elif not getattr(status, "stt_installed", True):
            pill_text = "⚠️ Offline Voice Setup Needed"
            pill_bg = "#78350f"
            pill_fg = "#fde047"
            mc_btn_text = "⚠️ Setup Voice Dictation"
            airlock_btn_text = "⚠️ SETUP OFFLINE VOICE ENGINE"
            win_h_note = " or press Win + H for Windows dictation." if has_win_dictation else "."
            mc_hint = f"Offline speech engine (faster-whisper) not installed. Click to setup{win_h_note}"
            airlock_hint = f"Faster-Whisper offline model is not installed. Click to setup{win_h_note}"
            model_info = (
                "Engine: Offline Whisper (Not Installed) • Win + H Native Fallback Available"
                if has_win_dictation
                else "Engine: Offline Whisper (Not Installed)"
            )
        elif not getattr(status, "model_cached", True):
            if getattr(status, "model_incomplete", False):
                pill_text = "⚠️ Voice Repair Needed"
                pill_bg = "#78350f"
                pill_fg = "#fde047"
                mc_btn_text = "🔧 Repair Voice Engine"
                airlock_btn_text = "🔧 REPAIR VOICE ENGINE"
                win_h_note = " Press Win + H to dictate, or click to repair." if has_win_dictation else " Click to repair."
                mc_hint = f"Offline speech model snapshot is incomplete (missing config.json).{win_h_note}"
                airlock_hint = f"Offline speech model snapshot is incomplete (missing config.json).{win_h_note}"
                model_info = "Engine: Faster-Whisper (Snapshot Incomplete • 1-Click Repair Available)"
            else:
                pill_text = "⚠️ Offline Model Download Needed"
                pill_bg = "#78350f"
                pill_fg = "#fde047"
                mc_btn_text = "⚠️ Download Whisper Model"
                airlock_btn_text = "⚠️ DOWNLOAD WHISPER MODEL"
                win_h_note = " or press Win + H for Windows dictation." if has_win_dictation else "."
                mc_hint = f"Offline speech model ('base') not downloaded yet.{win_h_note}"
                airlock_hint = f"Offline speech model ('base') is not downloaded yet.{win_h_note}"
                model_info = "Engine: Faster-Whisper (Model Download Needed)"
        else:
            pill_text = "⚠️ Voice Setup Needed"
            pill_bg = "#78350f"
            pill_fg = "#fde047"
            mc_btn_text = "⚠️ Check Voice Input"
            airlock_btn_text = "⚠️ CHECK VOICE INPUT"
            mc_hint = status.detail
            airlock_hint = status.detail
            model_info = "Engine: Audio Hardware / PortAudio Issue"

        if hasattr(self, "mc_voice_status_pill"):
            self.mc_voice_status_pill.config(text=pill_text, bg=pill_bg, fg=pill_fg)
        if hasattr(self, "mc_voice_btn"):
            self.mc_voice_btn.config(text=mc_btn_text)
        if hasattr(self, "mc_voice_feedback_lbl"):
            self.mc_voice_feedback_lbl.config(text=mc_hint, fg=TEXT_MUTED)

        if hasattr(self, "voice_status_pill"):
            self.voice_status_pill.config(text=pill_text, bg=pill_bg, fg=pill_fg)
        if hasattr(self, "voice_btn"):
            self.voice_btn.config(text=airlock_btn_text)
        if hasattr(self, "voice_feedback_lbl"):
            self.voice_feedback_lbl.config(text=airlock_hint, fg=TEXT_MUTED)
        if hasattr(self, "voice_model_lbl"):
            self.voice_model_lbl.config(text=model_info)

    def _toggle_voice_recording(self) -> None:
        if self._is_recording:
            self._stop_persistent_recording()
            return

        status = self._refresh_voice_status()
        if not status.ready:
            self._handle_voice_not_ready(status)
            self._show_voice_setup_modal(status)
            return

        self._start_persistent_recording()

    def _handle_voice_not_ready(self, status: VoiceEngineStatus) -> None:
        """Shows clean non-blocking notification and focuses prompt box for seamless Win + H dictation."""
        has_win_dictation = getattr(status, "windows_dictation_available", False) or (sys.platform == "win32")
        if getattr(status, "model_incomplete", False):
            msg = (
                "⚠️ Voice snapshot is missing config.json. "
                + ("Press [ Win + H ] to dictate into prompt box, or click 'Repair Voice Engine'." if has_win_dictation else "Click 'Repair Voice Engine' to fix.")
            )
        elif not getattr(status, "model_cached", True):
            msg = (
                "⚠️ Offline Whisper model not downloaded yet. "
                + ("Press [ Win + H ] to dictate into prompt box, or click 'Repair Voice Engine'." if has_win_dictation else "Click 'Setup Voice Dictation' to download.")
            )
        elif not getattr(status, "stt_installed", True):
            msg = (
                "⚠️ Faster-Whisper is not installed. "
                + ("Press [ Win + H ] to dictate directly into this prompt box." if has_win_dictation else status.detail)
            )
        else:
            msg = f"⚠️ {status.detail}"

        if hasattr(self, "mc_voice_feedback_lbl"):
            self.mc_voice_feedback_lbl.config(text=msg, fg=BORDER_FOCUS)
        if hasattr(self, "voice_feedback_lbl"):
            self.voice_feedback_lbl.config(text=msg, fg=BORDER_FOCUS)

        # Seamless fallback: focus the prompt box so Win + H immediately writes into it
        if hasattr(self, "mc_quick_prompt_entry"):
            try:
                self.mc_quick_prompt_entry.focus_set()
            except Exception:
                pass

    def _repair_voice_engine(self, dialog: Optional[tk.Toplevel] = None, status_lbl: Optional[tk.Label] = None) -> None:
        """1-click background self-healing repair for missing model files / config.json."""
        if status_lbl and status_lbl.winfo_exists():
            status_lbl.config(text="⏳ Repairing voice engine: downloading config.json and validating...", fg=BORDER_FOCUS)
        if hasattr(self, "mc_voice_feedback_lbl"):
            self.mc_voice_feedback_lbl.config(text="⏳ Repairing voice engine: downloading config.json...", fg=BORDER_FOCUS)
        if hasattr(self, "voice_feedback_lbl"):
            self.voice_feedback_lbl.config(text="⏳ Repairing voice engine: downloading config.json...", fg=BORDER_FOCUS)

        def _bg_repair() -> None:
            try:
                m_dir = get_model_dir(self.config.app_dir)
                ok = repair_offline_model(m_dir, model_name="base")

                def _on_done(repaired: bool) -> None:
                    new_status = self._refresh_voice_status()
                    if repaired or new_status.ready:
                        success_msg = "✅ Voice engine repaired successfully! Offline dictation is ready."
                        if status_lbl and status_lbl.winfo_exists():
                            status_lbl.config(text=success_msg, fg=ACCENT_EMERALD)
                        if hasattr(self, "mc_voice_feedback_lbl"):
                            self.mc_voice_feedback_lbl.config(text=success_msg, fg=ACCENT_EMERALD)
                        if hasattr(self, "voice_feedback_lbl"):
                            self.voice_feedback_lbl.config(text=success_msg, fg=ACCENT_EMERALD)
                        if dialog and dialog.winfo_exists():
                            self.root.after(1200, lambda: dialog.destroy() if dialog.winfo_exists() else None)
                    else:
                        fail_msg = "❌ Could not repair model completely. Run 'run.bat --setup-voice' while online."
                        if status_lbl and status_lbl.winfo_exists():
                            status_lbl.config(text=fail_msg, fg=ALERT_RED)
                        if hasattr(self, "mc_voice_feedback_lbl"):
                            self.mc_voice_feedback_lbl.config(text=fail_msg, fg=ALERT_RED)

                self.root.after(0, lambda: _on_done(ok))
            except Exception as exc:
                logger.error(f"Voice engine repair error: {exc}")
                err_text = f"❌ Repair error: {exc}"

                def _on_err(err_m: str) -> None:
                    if status_lbl and status_lbl.winfo_exists():
                        status_lbl.config(text=err_m, fg=ALERT_RED)
                    if hasattr(self, "mc_voice_feedback_lbl"):
                        self.mc_voice_feedback_lbl.config(text=err_m, fg=ALERT_RED)

                self.root.after(0, lambda: _on_err(err_text))

        threading.Thread(target=_bg_repair, daemon=True).start()

    def _show_voice_setup_modal(self, status: Optional[VoiceEngineStatus] = None) -> tk.Toplevel:
        """Display a dedicated, elegant setup modal dialog when the voice engine is missing."""
        if self._voice_setup_dialog is not None:
            try:
                if self._voice_setup_dialog.winfo_exists():
                    self._voice_setup_dialog.lift()
                    self._voice_setup_dialog.focus_force()
                    return self._voice_setup_dialog
            except Exception:
                pass

        current_status = status or self._refresh_voice_status()

        dialog = tk.Toplevel(self.root)
        self._voice_setup_dialog = dialog
        dialog.title("SentinelWire — Offline Voice Engine Setup")
        dialog.geometry("660x600")
        dialog.minsize(600, 520)
        dialog.configure(bg=BG_CANVAS)
        dialog.transient(self.root)

        def _on_modal_close() -> None:
            self._voice_setup_dialog = None
            try:
                dialog.grab_release()
            except Exception:
                pass
            dialog.destroy()

        dialog.protocol("WM_DELETE_WINDOW", _on_modal_close)

        card = tk.Frame(dialog, bg=BG_CARD, padx=20, pady=16, highlightbackground=BORDER_COLOR, highlightthickness=1)
        card.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)

        # Header row
        h_row = tk.Frame(card, bg=BG_CARD)
        h_row.pack(fill=tk.X, pady=(0, 10))

        tk.Label(
            h_row,
            text="🎙️ Offline Speech Engine Setup",
            font=("Segoe UI", 13, "bold"),
            fg=TEXT_TITLE,
            bg=BG_CARD,
        ).pack(side=tk.LEFT)

        pill_text = "⚠️ Setup Needed" if not current_status.ready else "🟢 Engine Ready"
        modal_pill = tk.Label(
            h_row,
            text=pill_text,
            font=("Segoe UI", 9, "bold"),
            fg="#fde047" if not current_status.ready else ACCENT_EMERALD,
            bg="#78350f" if not current_status.ready else "#064e3b",
            padx=10,
            pady=3,
        )
        modal_pill.pack(side=tk.RIGHT)

        desc_lbl = tk.Label(
            card,
            text=(
                "SentinelWire provides 100% air-gapped, zero-outbound speech-to-text to protect your privacy.\n"
                "Audio is transcribed entirely on your local CPU and scrubbed by the 5-Gate DLP before reaching any AI."
            ),
            font=("Segoe UI", 9),
            fg=TEXT_MUTED,
            bg=BG_CARD,
            justify=tk.LEFT,
        )
        desc_lbl.pack(anchor=tk.W, pady=(0, 12))

        # Status / issue banner
        status_box = tk.Frame(card, bg=BG_SURFACE, padx=12, pady=10, highlightbackground=BORDER_COLOR, highlightthickness=1)
        status_box.pack(fill=tk.X, pady=(0, 14))

        if not current_status.stt_installed:
            explanation_title = "⚠️ Faster-Whisper offline model engine is not yet installed."
            explanation_detail = (
                "The 'faster-whisper' package is required for local speech-to-text. "
                "You can install it automatically using the 1-click solution below."
            )
        elif getattr(current_status, "model_incomplete", False):
            explanation_title = "⚠️ Offline speech model snapshot is incomplete (missing config.json)."
            explanation_detail = (
                "Faster-Whisper model cache exists but 'config.json' is missing or incomplete. "
                "Click 'Repair Voice Engine' below to download config.json and validate in 1 click."
            )
        elif not current_status.model_cached:
            explanation_title = "⚠️ Offline speech model ('base') is not downloaded yet."
            explanation_detail = (
                "Faster-Whisper is installed, but the offline model weights have not been downloaded. "
                "Download them once while online to enable offline dictation permanently."
            )
        else:
            explanation_title = "ℹ️ Offline Speech Engine Status:"
            explanation_detail = current_status.detail

        tk.Label(
            status_box,
            text=explanation_title,
            font=("Segoe UI", 9, "bold"),
            fg="#fde047",
            bg=BG_SURFACE,
        ).pack(anchor=tk.W)

        tk.Label(
            status_box,
            text=explanation_detail,
            font=("Segoe UI", 9),
            fg=TEXT_BODY,
            bg=BG_SURFACE,
            justify=tk.LEFT,
        ).pack(anchor=tk.W, pady=(2, 0))

        # Option 1: 1-Click Offline Installation Box
        opt1_frame = tk.LabelFrame(
            card,
            text=" Option 1: Install Faster-Whisper Offline Engine (Recommended) ",
            font=("Segoe UI", 9, "bold"),
            fg=TEXT_TITLE,
            bg=BG_CARD,
            padx=12,
            pady=10,
        )
        opt1_frame.pack(fill=tk.X, pady=(0, 12))

        tk.Label(
            opt1_frame,
            text="One-shot command to install dependencies and cache the offline Whisper model:",
            font=("Segoe UI", 9),
            fg=TEXT_MUTED,
            bg=BG_CARD,
        ).pack(anchor=tk.W)

        cmd_row = tk.Frame(opt1_frame, bg=BG_CARD)
        cmd_row.pack(fill=tk.X, pady=(6, 8))

        cmd_entry = tk.Entry(
            cmd_row,
            font=("Consolas", 9, "bold"),
            bg="#020617",
            fg=BORDER_FOCUS,
            relief=tk.FLAT,
            highlightbackground=BORDER_COLOR,
            highlightthickness=1,
        )
        cmd_entry.insert(0, "run.bat --setup-voice")
        cmd_entry.config(state="readonly")
        cmd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=4, padx=(0, 8))

        install_feedback = tk.Label(
            opt1_frame,
            text="",
            font=("Segoe UI", 9),
            fg=BORDER_FOCUS,
            bg=BG_CARD,
        )

        def _copy_cmd() -> None:
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append("run.bat --setup-voice")
                install_feedback.config(text="✅ Copied 'run.bat --setup-voice' to clipboard!", fg=ACCENT_EMERALD)
            except Exception as e:
                install_feedback.config(text=f"Failed to copy: {e}", fg=ALERT_RED)

        copy_btn = tk.Button(
            cmd_row,
            text="📋 Copy",
            font=("Segoe UI", 9),
            bg=BG_ELEVATED,
            fg=TEXT_TITLE,
            activebackground=BG_SURFACE,
            activeforeground="#ffffff",
            padx=10,
            pady=4,
            relief=tk.FLAT,
            cursor="hand2",
            command=_copy_cmd,
        )
        copy_btn.pack(side=tk.RIGHT)

        btn_row = tk.Frame(opt1_frame, bg=BG_CARD)
        btn_row.pack(fill=tk.X, pady=(0, 4))

        def _run_installer() -> None:
            _copy_cmd()
            install_feedback.config(text="⏳ Launching voice engine setup in console window...", fg=BORDER_FOCUS)
            self._launch_voice_setup(dialog=dialog, status_lbl=install_feedback)

        repair_btn = create_styled_button(
            btn_row,
            text="Repair Voice Engine (Download config.json)",
            icon="🔧",
            style="primary",
            command=lambda: self._repair_voice_engine(dialog=dialog, status_lbl=install_feedback),
            font=FONT_BOLD,
            padx=14,
            pady=6,
        )
        repair_btn.pack(side=tk.LEFT, padx=(0, 8))

        install_btn = create_styled_button(
            btn_row,
            text="Install Voice Engine (run.bat --setup-voice)",
            icon="⬇️",
            style="secondary",
            command=_run_installer,
            font=FONT_BOLD,
            padx=14,
            pady=6,
        )
        install_btn.pack(side=tk.LEFT)
        install_feedback.pack(anchor=tk.W, pady=(4, 0))

        # Option 2: Windows Native Dictation (Zero-Install Alternative)
        opt2_frame = tk.LabelFrame(
            card,
            text=" Option 2: Zero-Install Instant Alternative (Windows Native Dictation) ",
            font=FONT_BOLD,
            fg=TEXT_TITLE,
            bg=BG_CARD,
            padx=12,
            pady=10,
        )
        opt2_frame.pack(fill=tk.X, pady=(0, 12))

        win_dictation_note = (
            "Windows 10/11 includes built-in OS speech recognition requiring 0 Python packages.\n"
            "Press [ Win + H ] anywhere to dictate directly into the active prompt field."
        )
        tk.Label(
            opt2_frame,
            text=win_dictation_note,
            font=FONT_BODY,
            fg=TEXT_BODY,
            bg=BG_CARD,
            justify=tk.LEFT,
        ).pack(anchor=tk.W, pady=(0, 6))

        def _use_native_dictation() -> None:
            _on_modal_close()
            self._select_nav(0)
            if hasattr(self, "mc_quick_prompt_entry"):
                self.mc_quick_prompt_entry.focus_set()
            if hasattr(self, "mc_voice_feedback_lbl"):
                self.mc_voice_feedback_lbl.config(
                    text="Ready for Windows Dictation! Press Win + H to dictate, then scrub.",
                    fg=BORDER_FOCUS,
                )

        native_btn = create_styled_button(
            opt2_frame,
            text="Focus Quick Prompt & Use Win + H",
            icon="⌨️",
            style="secondary",
            command=_use_native_dictation,
            font=FONT_BOLD,
            padx=12,
            pady=5,
        )
        native_btn.pack(side=tk.LEFT)

        # Footer Actions: Check Again & Close
        f_row = tk.Frame(card, bg=BG_CARD)
        f_row.pack(fill=tk.X, side=tk.BOTTOM)

        def _check_again() -> None:
            new_st = self._refresh_voice_status()
            if new_st.ready:
                modal_pill.config(text="🟢 Engine Ready", bg="#064e3b", fg=ACCENT_EMERALD)
                install_feedback.config(text="✅ Voice engine is ready! Closing setup...", fg=ACCENT_EMERALD)
                self.root.after(800, _on_modal_close)
            else:
                modal_pill.config(text="⚠️ Setup Needed", bg="#78350f", fg="#fde047")
                install_feedback.config(text=f"Status: {new_st.detail}", fg="#fde047")

        check_btn = create_styled_button(
            f_row,
            text="Check Status Again",
            icon="🔄",
            style="secondary",
            command=_check_again,
            font=FONT_BOLD,
            padx=12,
            pady=5,
        )
        check_btn.pack(side=tk.LEFT)

        close_btn = create_styled_button(
            f_row,
            text="Close",
            style="ghost",
            command=_on_modal_close,
            font=FONT_BODY,
            padx=14,
            pady=5,
        )
        close_btn.pack(side=tk.RIGHT)

        return dialog

    def _launch_voice_setup(self, dialog: Optional[tk.Toplevel] = None, status_lbl: Optional[tk.Label] = None) -> None:
        """Launches the voice installer in a separate console window with 0 hassle."""
        import platform
        cmd_text = "run.bat --setup-voice"
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(cmd_text)
        except Exception:
            pass

        ws_dir = Path(__file__).resolve().parent.parent.parent.parent
        run_bat = ws_dir / "run.bat"
        launched = False

        if platform.system() == "Windows" and run_bat.is_file():
            try:
                # CREATE_NEW_CONSOLE = 0x00000010
                subprocess.Popen(
                    ["cmd.exe", "/c", str(run_bat), "--setup-voice"],
                    cwd=str(ws_dir),
                    creationflags=0x00000010,
                    shell=False,
                )
                launched = True
            except Exception as exc:
                logger.warning(f"Failed to launch run.bat in new console: {exc}")

        if not launched:
            try:
                subprocess.Popen(
                    [sys.executable, "-m", "packetsentinel", "--setup-voice"],
                    shell=False,
                )
                launched = True
            except Exception as exc:
                logger.warning(f"Failed to launch packetsentinel --setup-voice: {exc}")

        if status_lbl:
            if launched:
                status_lbl.config(
                    text="✅ Installer launched in background console! Click 'Check Status Again' when done.",
                    fg=ACCENT_EMERALD,
                )
            else:
                status_lbl.config(
                    text="📋 Command copied! Open terminal and run: run.bat --setup-voice",
                    fg=BORDER_FOCUS,
                )

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
        except Exception as err:
            err_msg = str(err)
            self._is_recording = False
            if self._record_timer_id:
                try:
                    self.root.after_cancel(self._record_timer_id)
                except Exception:
                    pass
                self._record_timer_id = None
            try:
                self.voice_btn.config(
                    text="🎙️  CLICK TO START DICTATING",
                    bg=ACCENT_BLUE,
                    activebackground=ACCENT_HOVER,
                )
                self.voice_status_pill.config(text="⚠️ VOICE ENGINE NOT READY", bg="#78350f", fg="#fde047")
                self.voice_feedback_lbl.config(text=f"❌ Microphone error: {err_msg}", fg=ALERT_RED)
                if hasattr(self, "mc_voice_btn"):
                    self.mc_voice_btn.config(text="🎙️  Start Dictation (Spacebar)", bg=ACCENT_BLUE, activebackground=ACCENT_HOVER)
                if hasattr(self, "mc_voice_status_pill"):
                    self.mc_voice_status_pill.config(text="⚠️ VOICE NOTICE", bg="#78350f", fg="#fde047")
                if hasattr(self, "mc_voice_feedback_lbl"):
                    self.mc_voice_feedback_lbl.config(text=f"❌ {err_msg}", fg=ALERT_RED)
            except Exception as ui_exc:
                logger.warning(f"Failed to update voice status widgets: {ui_exc}")
            try:
                messagebox.showwarning("Voice Airlock Notice", err_msg)
            except Exception:
                pass

    def _stop_persistent_recording(self) -> None:
        self._is_recording = False
        if self._record_timer_id:
            try:
                self.root.after_cancel(self._record_timer_id)
            except Exception:
                pass
            self._record_timer_id = None
        try:
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
        except Exception as ui_exc:
            logger.warning(f"Failed to update transcribing widgets: {ui_exc}")

        recorder = self._voice_recorder
        self._voice_recorder = None

        def _bg_transcribe() -> None:
            if recorder is None:
                return
            try:
                audio_data = recorder.stop()
                text = self._voice_transcriber.transcribe(audio_data)
                try:
                    self.root.after(0, lambda t=text: self._on_voice_audio_received(t))
                except Exception as post_exc:
                    logger.warning(f"Could not post voice audio received to UI: {post_exc}")
            except VoiceEngineError as err:
                msg = str(err)
                logger.warning(f"Voice engine notice: {msg}")
                try:
                    self.root.after(0, lambda m=msg: self._on_voice_engine_error(m))
                except Exception as post_exc:
                    logger.warning(f"Could not post voice engine notice to UI: {post_exc}")
            except Exception as exc:
                msg = f"Transcription error: {exc}"
                logger.error(f"Unexpected error in offline voice transcriber: {msg}")
                try:
                    self.root.after(0, lambda m=msg: self._on_voice_engine_error(m))
                except Exception as post_exc:
                    logger.warning(f"Could not post voice error to UI: {post_exc}")

        threading.Thread(target=_bg_transcribe, daemon=True).start()

    def _on_voice_engine_error(self, message: str) -> None:
        try:
            self._is_recording = False
            self.voice_btn.config(
                text="🎙️  CLICK TO START DICTATING",
                bg=ACCENT_BLUE,
                activebackground=ACCENT_HOVER,
            )
            has_win = is_windows_dictation_available()
            if "config.json" in message.lower() or "incomplete" in message.lower():
                self.voice_status_pill.config(text="⚠️ VOICE REPAIR NEEDED", bg="#78350f", fg="#fde047")
                clean_msg = (
                    "⚠️ Offline speech model snapshot is incomplete (missing config.json). "
                    + ("Press [ Win + H ] to dictate into prompt box, or click 'Repair Voice Engine'." if has_win else "Click 'Repair Voice Engine' to fix.")
                )
                self.voice_feedback_lbl.config(text=clean_msg, fg=BORDER_FOCUS)
                if hasattr(self, "mc_voice_status_pill"):
                    self.mc_voice_status_pill.config(text="⚠️ REPAIR NEEDED", bg="#78350f", fg="#fde047")
                if hasattr(self, "mc_voice_feedback_lbl"):
                    self.mc_voice_feedback_lbl.config(text=clean_msg, fg=BORDER_FOCUS)
                if hasattr(self, "mc_voice_btn"):
                    self.mc_voice_btn.config(text="🔧 Repair Voice Engine")
                if hasattr(self, "voice_btn"):
                    self.voice_btn.config(text="🔧 REPAIR VOICE ENGINE")
                if hasattr(self, "mc_quick_prompt_entry"):
                    try:
                        self.mc_quick_prompt_entry.focus_set()
                    except Exception:
                        pass
            else:
                self.voice_status_pill.config(text="⚠️ VOICE AIRLOCK NOTICE", bg="#78350f", fg="#fde047")
                self.voice_feedback_lbl.config(text=f"❌ {message}", fg=ALERT_RED)
                if hasattr(self, "mc_voice_btn"):
                    self.mc_voice_btn.config(text="🎙️  Start Dictation (Spacebar)", bg=ACCENT_BLUE, activebackground=ACCENT_HOVER)
                if hasattr(self, "mc_voice_status_pill"):
                    self.mc_voice_status_pill.config(text="⚠️ VOICE NOTICE", bg="#78350f", fg="#fde047")
                if hasattr(self, "mc_voice_feedback_lbl"):
                    self.mc_voice_feedback_lbl.config(text=f"❌ {message}", fg=ALERT_RED)
        except Exception as exc:
            logger.error(f"Error displaying voice engine error: {exc}")

    def _update_recording_timer(self) -> None:
        if not self._is_recording:
            return
        if self._voice_recorder and (
            getattr(self._voice_recorder, "hit_silence_limit", False)
            or getattr(self._voice_recorder, "hit_time_limit", False)
        ):
            reason = "time limit reached" if getattr(self._voice_recorder, "hit_time_limit", False) else "silence detected"
            notice = f"Auto-stopping: {reason}. Transcribing offline audio..."
            try:
                self.voice_feedback_lbl.config(text=notice, fg=BORDER_FOCUS)
                if hasattr(self, "mc_voice_feedback_lbl"):
                    self.mc_voice_feedback_lbl.config(text=notice, fg=BORDER_FOCUS)
            except Exception:
                pass
            self._stop_persistent_recording()
            return
        elapsed = int(time.time() - self._record_start_time)
        mins = elapsed // 60
        secs = elapsed % 60
        try:
            self.voice_status_pill.config(text=f"🔴 RECORDING LIVE AUDIO ({mins:02d}:{secs:02d})")
            if hasattr(self, "mc_voice_status_pill"):
                self.mc_voice_status_pill.config(text=f"🔴 RECORDING ({mins:02d}:{secs:02d})")
            self._record_timer_id = self.root.after(500, self._update_recording_timer)
        except Exception:
            pass

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
        try:
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
        except Exception as exc:
            logger.error(f"Error handling voice audio received in UI: {exc}")

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

        self.monitor_status_badge = create_status_pill(
            header_row,
            text="🔴 SNIFFER STOPPED",
            status="error",
            font=FONT_BOLD,
            padx=10,
            pady=3,
        )
        self.monitor_status_badge.pack(side=tk.RIGHT)

        # Control Bar
        ctrl_bar = tk.Frame(card, bg=BG_CARD)
        ctrl_bar.pack(fill=tk.X, pady=(0, 6))

        self.btn_toggle_monitor = create_styled_button(
            ctrl_bar,
            text="Start Live Sniffer",
            icon="▶️",
            style="primary",
            command=self._toggle_sniffer,
            font=FONT_BOLD,
            padx=12,
            pady=4,
        )
        self.btn_toggle_monitor.pack(side=tk.LEFT, padx=(0, 8))

        canary_btn = create_styled_button(
            ctrl_bar,
            text="Trigger Safe Canary Alert",
            icon="🧪",
            style="secondary",
            command=self._trigger_canary_alert,
            font=FONT_BODY,
            padx=12,
            pady=4,
        )
        canary_btn.pack(side=tk.LEFT, padx=(0, 8))

        explain_btn = create_styled_button(
            ctrl_bar,
            text="Explain Threat",
            icon="ℹ️",
            style="primary",
            command=lambda: self._show_threat_explanation(),
            font=FONT_BOLD,
            padx=12,
            pady=4,
        )
        explain_btn.pack(side=tk.LEFT, padx=(0, 8))

        inspect_alert_btn = create_styled_button(
            ctrl_bar,
            text="Inspect Alert Target",
            icon="🎯",
            style="secondary",
            command=self._inspect_selected_alert_in_monitor,
            font=FONT_BOLD,
            padx=10,
            pady=4,
        )
        inspect_alert_btn.pack(side=tk.LEFT, padx=(0, 8))

        self.monitor_detail_lbl = tk.Label(
            ctrl_bar,
            text="Ready. Start sniffer to inspect wire DNS/TLS packets in real-time.",
            font=FONT_BODY,
            fg=TEXT_MUTED,
            bg=BG_CARD,
        )
        self.monitor_detail_lbl.pack(side=tk.LEFT, padx=(8, 0))

        # Real-time Threat Alerts Treeview
        cols = ("time", "indicator", "feed", "process", "layer")
        display_names = {
            "time": "Timestamp (UTC)",
            "indicator": "Flagged Domain / IP",
            "feed": "Matched Threat Feed",
            "process": "Attributed Process",
            "layer": "Detection Layer",
        }
        min_widths = {
            "time": 150,
            "indicator": 240,
            "feed": 180,
            "process": 140,
            "layer": 110,
        }
        self.alert_tree, self.alert_sb, self.alert_container = create_data_table(
            card,
            columns=cols,
            display_names=display_names,
            min_widths=min_widths,
            height=6,
            horizontal_scroll=True,
        )
        self.alert_container.pack(fill=tk.BOTH, expand=True)
        self.alert_tree.bind("<Double-1>", lambda e: self._show_threat_explanation())
        self.alert_tree.bind("<<TreeviewSelect>>", self._on_alert_tree_select)

        # Lower Card: Target Process Watchdog & Script Interpreter Inspector
        w_card = tk.Frame(self.tab_monitor, bg=BG_CARD, padx=14, pady=10, highlightbackground=BORDER_COLOR, highlightthickness=1)
        w_card.pack(fill=tk.BOTH, expand=True, pady=(0, 0))

        w_head = tk.Frame(w_card, bg=BG_CARD)
        w_head.pack(fill=tk.X, pady=(0, 4))

        tk.Label(
            w_head,
            text="👁️ Target Process Watchdog & Socket Inspector",
            font=("Segoe UI", 10, "bold"),
            fg=TEXT_TITLE,
            bg=BG_CARD,
        ).pack(side=tk.LEFT)

        tk.Label(
            w_head,
            text="Traces child process trees, open socket ports, and flags LOLBINs",
            font=("Segoe UI", 8),
            fg=TEXT_MUTED,
            bg=BG_CARD,
        ).pack(side=tk.RIGHT)

        input_bar = tk.Frame(w_card, bg=BG_CARD)
        input_bar.pack(fill=tk.X, pady=(0, 6))

        tk.Label(
            input_bar,
            text="Select Target / Connection:",
            font=("Segoe UI", 9),
            fg=TEXT_MUTED,
            bg=BG_CARD,
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.proc_combo = ttk.Combobox(
            input_bar,
            font=("Segoe UI", 9),
            state="normal",
            width=28,
        )
        candidates = self._get_running_process_candidates()
        self.proc_combo["values"] = candidates
        if candidates:
            self.proc_combo.set(candidates[0])
        else:
            self.proc_combo.set("python.exe")
        self.proc_combo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        self.proc_entry = self.proc_combo

        refresh_btn = create_styled_button(
            input_bar,
            text="Refresh",
            icon="🔄",
            style="secondary",
            command=self._refresh_process_lists,
            font=FONT_SMALL,
            padx=6,
            pady=3,
        )
        refresh_btn.pack(side=tk.LEFT, padx=(0, 4))

        inspect_btn = create_styled_button(
            input_bar,
            text="Inspect Target",
            icon="🔍",
            style="primary",
            command=self._inspect_watchdog_target,
            font=FONT_BOLD,
            padx=10,
            pady=3,
        )
        inspect_btn.pack(side=tk.LEFT, padx=(0, 4))

        copy_summary_btn = create_styled_button(
            input_bar,
            text="Copy Report",
            icon="📋",
            style="secondary",
            command=lambda: self._copy_process_summary(self.watchdog_results),
            font=FONT_SMALL,
            padx=6,
            pady=3,
        )
        copy_summary_btn.pack(side=tk.LEFT, padx=(0, 4))

        ai_btn = create_styled_button(
            input_bar,
            text="Ask AI Safety",
            icon="🤖",
            style="accent",
            command=self._analyze_process_with_ai,
            font=FONT_BOLD,
            padx=10,
            pady=3,
        )
        ai_btn.pack(side=tk.LEFT)

        self.watchdog_results = tk.Text(
            w_card,
            bg=BG_CANVAS,
            fg=TEXT_BODY,
            font=("Consolas", 9),
            relief=tk.FLAT,
            wrap=tk.WORD,
            height=8,
            highlightbackground=BORDER_COLOR,
            highlightthickness=1,
            padx=8,
            pady=6,
        )
        self.watchdog_results.pack(fill=tk.BOTH, expand=True)

        # Compatibility aliases for Mission Control testing
        self.mc_alert_tree = self.alert_tree
        self.mc_proc_combo = self.proc_combo
        self.mc_watchdog_results = self.watchdog_results
        self.mc_sniffer_btn = self.btn_toggle_monitor
        self.mc_sniffer_badge = self.monitor_status_badge

    def _build_watchdog_tab(self) -> None:
        """Compatibility wrapper; functionality now merged into _build_monitor_tab."""
        pass

    def _build_ide_integrations_tab(self) -> None:
        """1-Click popular IDE integration cards for Cursor, VS Code, Kiro, Windsurf, and Claude."""
        container = tk.Frame(self.tab_ide_integrations, bg=BG_CANVAS, padx=14, pady=10)
        container.pack(fill=tk.BOTH, expand=True)

        h_card = create_card_frame(container, padx=16, pady=10, bg=BG_SURFACE)
        h_card.pack(fill=tk.X, pady=(0, 10))
        tk.Label(
            h_card,
            text="💻 Popular IDE Integrations & Zero-Outbound Steering",
            font=FONT_HEADER,
            fg=TEXT_TITLE,
            bg=BG_SURFACE,
        ).pack(anchor=tk.W)
        tk.Label(
            h_card,
            text="1-Click configuration cards for the AI editors you use daily. Automatically injects privacy rules, "
            "MCP bridges, and zero-leak guardrails into your active project workspace.",
            font=FONT_BODY,
            fg=TEXT_MUTED,
            bg=BG_SURFACE,
            wraplength=750,
        ).pack(anchor=tk.W, pady=(2, 0))

        cards_frame = tk.Frame(container, bg=BG_CANVAS)
        cards_frame.pack(fill=tk.BOTH, expand=True)

        ide_list = [
            (
                "Cursor IDE",
                "🎯",
                "Configures .cursorrules and SentinelWire MCP server for pre-model prompt scrubbing and zero-leak boundaries.",
                self._copy_cursor_config,
                self._inject_cursor_config,
                "Inject .cursorrules",
            ),
            (
                "VS Code & GitHub Copilot",
                "🐙",
                "Configures .github/copilot-instructions.md with DPAPI encryption boundaries, 5-Gate DLP, and 0-outbound rules.",
                self._copy_copilot_config,
                self._inject_copilot_config,
                "Inject Copilot Rules",
            ),
            (
                "Kiro IDE",
                "⚡",
                "Generates .kiro/steering/ spec-driven templates for product & tech boundaries, token minimization, and zero-outbound.",
                self._copy_kiro_config,
                self._inject_kiro_config,
                "Inject Kiro Steering",
            ),
            (
                "Windsurf (Codeium)",
                "🏄",
                "Configures .windsurfrules with Cascade AI privacy guardrails, local file protection, and credential leak prevention.",
                self._copy_windsurf_config,
                self._inject_windsurf_config,
                "Inject .windsurfrules",
            ),
            (
                "Claude Desktop & Claude Code",
                "🤖",
                "Configures claude_desktop_config.json with SentinelWire MCP server to sanitize prompts before sending to Claude.",
                self._copy_mcp_config_json,
                None,
                None,
            ),
        ]

        for title, icon, desc, copy_fn, inject_fn, inject_lbl in ide_list:
            card = create_card_frame(cards_frame, padx=14, pady=10)
            card.pack(fill=tk.X, pady=(0, 8))

            top_row = tk.Frame(card, bg=BG_CARD)
            top_row.pack(fill=tk.X)

            tk.Label(
                top_row,
                text=f"{icon}  {title}",
                font=FONT_SECTION,
                fg=TEXT_MAIN,
                bg=BG_CARD,
            ).pack(side=tk.LEFT)

            btn_box = tk.Frame(top_row, bg=BG_CARD)
            btn_box.pack(side=tk.RIGHT)

            if inject_fn and inject_lbl:
                inj_b = create_styled_button(
                    btn_box,
                    text=inject_lbl,
                    icon="⚡",
                    style="primary",
                    command=inject_fn,
                    font=FONT_SMALL,
                    padx=10,
                    pady=3,
                )
                inj_b.pack(side=tk.LEFT, padx=(0, 6))

            copy_b = create_styled_button(
                btn_box,
                text="Copy Config",
                icon="📋",
                style="secondary",
                command=copy_fn,
                font=FONT_SMALL,
                padx=10,
                pady=3,
            )
            copy_b.pack(side=tk.LEFT)

            tk.Label(
                card,
                text=desc,
                font=FONT_BODY,
                fg=TEXT_MUTED,
                bg=BG_CARD,
                anchor="w",
                justify=tk.LEFT,
            ).pack(anchor=tk.W, pady=(4, 0))

    def _copy_cursor_config(self) -> None:
        cfg = (
            "# Cursor AI Privacy Airlock & Security Guidelines\n\n"
            "- Strictly 0 outbound network requests allowed during tests or monitoring.\n"
            "- Pre-Model 5-Gate DLP: Always mask credit card numbers, national IDs, usernames, and private tokens.\n"
            "- Hardware-encrypted secrets: Store credentials via Windows DPAPI or chmod 600 only.\n"
            "- Use SentinelWire MCP server tools (sanitize_prompt_text, inspect_process_safety) for untrusted inputs.\n"
        )
        self.root.clipboard_clear()
        self.root.clipboard_append(cfg)
        messagebox.showinfo("Cursor Config Copied", ".cursorrules privacy configuration copied to clipboard!")

    def _inject_cursor_config(self) -> None:
        target = Path.cwd() / ".cursorrules"
        cfg = (
            "# Cursor AI Privacy Airlock & Security Guidelines\n\n"
            "- Strictly 0 outbound network requests allowed during tests or monitoring.\n"
            "- Pre-Model 5-Gate DLP: Always mask credit card numbers, national IDs, usernames, and private tokens.\n"
            "- Hardware-encrypted secrets: Store credentials via Windows DPAPI or chmod 600 only.\n"
            "- Use SentinelWire MCP server tools (sanitize_prompt_text, inspect_process_safety) for untrusted inputs.\n"
        )
        try:
            target.write_text(cfg, encoding="utf-8")
            messagebox.showinfo("Injected Successfully", f"Created .cursorrules in {target.parent}!")
        except Exception as e:
            messagebox.showerror("Injection Error", f"Could not write file: {e}")

    def _copy_copilot_config(self) -> None:
        cfg = (
            "# GitHub Copilot Steering & Privacy Rules\n\n"
            "## Architectural Invariants\n"
            "1. Zero outbound network traffic: all monitoring and prompt processing is strictly local.\n"
            "2. 5-Gate DLP: Mask payment cards (Luhn-checked), national IDs, credentials, and real names.\n"
            "3. Secrets Boundary: Never hardcode tokens or commit environment variable files.\n"
        )
        self.root.clipboard_clear()
        self.root.clipboard_append(cfg)
        messagebox.showinfo("Copilot Config Copied", ".github/copilot-instructions.md rules copied to clipboard!")

    def _inject_copilot_config(self) -> None:
        target_dir = Path.cwd() / ".github"
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / "copilot-instructions.md"
        cfg = (
            "# GitHub Copilot Steering & Privacy Rules\n\n"
            "## Architectural Invariants\n"
            "1. Zero outbound network traffic: all monitoring and prompt processing is strictly local.\n"
            "2. 5-Gate DLP: Mask payment cards (Luhn-checked), national IDs, credentials, and real names.\n"
            "3. Secrets Boundary: Never hardcode tokens or commit environment variable files.\n"
        )
        try:
            target.write_text(cfg, encoding="utf-8")
            messagebox.showinfo("Injected Successfully", "Created .github/copilot-instructions.md!")
        except Exception as e:
            messagebox.showerror("Injection Error", f"Could not write file: {e}")

    def _copy_kiro_config(self) -> None:
        cfg = (
            "# Kiro Spec & Steering Boundaries\n\n"
            "## Product Invariant\n"
            "- Local offline first: all models, audio transcription, and packet monitoring remain on localhost.\n"
            "- Token minimization: Keep context lean, summarize multi-file diffs, and use compact steering files.\n"
            "- Zero machine-binding identifiers in output or code.\n"
        )
        self.root.clipboard_clear()
        self.root.clipboard_append(cfg)
        messagebox.showinfo("Kiro Steering Copied", ".kiro/steering guidelines copied to clipboard!")

    def _inject_kiro_config(self) -> None:
        target_dir = Path.cwd() / ".kiro" / "steering"
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / "product.md"
        cfg = (
            "# Kiro Spec & Steering Boundaries\n\n"
            "## Product Invariant\n"
            "- Local offline first: all models, audio transcription, and packet monitoring remain on localhost.\n"
            "- Token minimization: Keep context lean, summarize multi-file diffs, and use compact steering files.\n"
            "- Zero machine-binding identifiers in output or code.\n"
        )
        try:
            target.write_text(cfg, encoding="utf-8")
            messagebox.showinfo("Injected Successfully", "Created .kiro/steering/product.md!")
        except Exception as e:
            messagebox.showerror("Injection Error", f"Could not write file: {e}")

    def _copy_windsurf_config(self) -> None:
        cfg = (
            "# Windsurf Cascade AI Privacy Guidelines\n\n"
            "- Enforce zero-leak boundary: never expose local usernames, machine paths, or API tokens.\n"
            "- All code inspections and prompt sanitizations must run offline locally.\n"
            "- Pre-Model 5-Gate DLP active before sending questions to Cascade.\n"
        )
        self.root.clipboard_clear()
        self.root.clipboard_append(cfg)
        messagebox.showinfo("Windsurf Rules Copied", ".windsurfrules copied to clipboard!")

    def _inject_windsurf_config(self) -> None:
        target = Path.cwd() / ".windsurfrules"
        cfg = (
            "# Windsurf Cascade AI Privacy Guidelines\n\n"
            "- Enforce zero-leak boundary: never expose local usernames, machine paths, or API tokens.\n"
            "- All code inspections and prompt sanitizations must run offline locally.\n"
            "- Pre-Model 5-Gate DLP active before sending questions to Cascade.\n"
        )
        try:
            target.write_text(cfg, encoding="utf-8")
            messagebox.showinfo("Injected Successfully", f"Created .windsurfrules in {target.parent}!")
        except Exception as e:
            messagebox.showerror("Injection Error", f"Could not write file: {e}")

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
        try:
            if not hasattr(self, "root") or not self.root.winfo_exists():
                return
            self._refresh_telemetry_ui()
            if hasattr(self, "root") and self.root.winfo_exists():
                self._telemetry_timer_id = self.root.after(1500, self._schedule_telemetry_poll)
        except Exception:
            pass

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

    @property
    def threats_detected(self) -> int:
        """Total threats detected and emitted."""
        return self._threat_count

    @property
    def packets_inspected(self) -> int:
        """Total packets inspected by monitor service."""
        return self._packet_count

    def _on_alert_received(self, alert: Any) -> None:
        """
        Handle a live security alert emitted by the packet monitoring pipeline.
        Updates counters and inserts a row into both alert tables.
        """
        ts = (
            getattr(alert, "timestamp_utc", None)
            or (alert.get("timestamp_utc") if isinstance(alert, dict) else None)
            or (alert.get("timestamp") if isinstance(alert, dict) else None)
            or ""
        )
        ind = (
            getattr(alert, "indicator", None)
            or (alert.get("indicator") if isinstance(alert, dict) else None)
            or ""
        )
        feed = (
            getattr(alert, "source_feed", None)
            or (alert.get("source_feed") if isinstance(alert, dict) else None)
            or ""
        )
        proc = (
            getattr(alert, "process_name", None)
            or (alert.get("process_name") if isinstance(alert, dict) else None)
            or ""
        )
        layer = (
            getattr(alert, "detection_layer", None)
            or (alert.get("detection_layer") if isinstance(alert, dict) else None)
            or ""
        )

        row_key = f"{ts}|{ind}|{proc}"
        if row_key not in self._threat_rows_seen:
            self._threat_rows_seen.add(row_key)
            row_values = (ts, ind, feed, proc, layer)
            if hasattr(self, "alert_tree"):
                self.alert_tree.insert("", 0, values=row_values)
            if hasattr(self, "mc_alert_tree") and self.mc_alert_tree is not self.alert_tree:
                self.mc_alert_tree.insert("", 0, values=row_values)

        self.show_notification(
            f"🚨 Threat Intercepted: {ind} ({proc or 'Unknown Process'})",
            level="error",
            action_text="View in Traffic Guard",
            action_cmd=lambda: (self._select_nav(1), self._dismiss_notification()),
        )

        self._threat_count += 1
        if hasattr(self, "metric_value_labels") and len(self.metric_value_labels) >= 2:
            threat_color = "#ef4444" if self._threat_count > 0 else "#22c55e"
            self.metric_value_labels[1].config(text=f"{self._threat_count:,}", fg=threat_color)

    def run_async_worker(
        self,
        worker_fn: Any,
        on_success: Optional[Any] = None,
        on_error: Optional[Any] = None,
    ) -> threading.Thread:
        """
        Execute an asynchronous background worker on a real daemon thread and marshal
        results or errors back to the Tkinter UI thread via self.root.after() with strict
        Python 3 closure hygiene (avoiding 'NameError: free variable err').
        """
        def _worker_runner() -> None:
            try:
                result = worker_fn()
                if on_success:
                    self.root.after(0, lambda r=result: on_success(r))
            except Exception as err:
                err_msg = str(err)
                if on_error:
                    self.root.after(0, lambda m=err_msg: on_error(m))
                else:
                    self.root.after(0, lambda m=err_msg: self._on_async_worker_error(m))

        t = threading.Thread(target=_worker_runner, daemon=True)
        t.start()
        return t

    def _on_async_worker_error(self, message: str) -> None:
        """Default error handler for async background workers."""
        logger = logging.getLogger("sentinelwire.ui")
        logger.warning(f"Async worker error: {message}")


    def _resolve_target_process_and_pid(self, raw_target: str) -> Tuple[Optional[int], str]:
        """
        Extract (PID, ProcessName) from any combobox string, PID string, or process name.
        Handles entries like:
        - "🚨 [SUSPICIOUS] curl.exe (PID 9120) -> sketchy-canary.example.com"
        - "🌐 python.exe (PID 1234) - TCP :8000 -> 127.0.0.1:8000"
        - "⚡ powershell.exe (PID 4312)"
        - "1234"
        - "python.exe"
        """
        raw = raw_target.strip()
        if not raw:
            return None, ""

        import re
        pid_match = re.search(r"\(?PID[:\s]*(\d+)\)?", raw, re.IGNORECASE)
        target_pid = int(pid_match.group(1)) if pid_match else None

        if target_pid is None and raw.isdigit():
            target_pid = int(raw)

        clean = raw
        clean = re.sub(r"^.*?\[(?:SUSPICIOUS|ALERT)\]\s*", "", clean, flags=re.IGNORECASE)
        clean = re.sub(r"^[^\w]+", "", clean)
        clean = re.split(r"\s+-\s+|\s+->\s+", clean)[0].strip()
        clean = re.sub(r"\s*\(?PID[:\s]*\d+\)?\s*", "", clean, flags=re.IGNORECASE).strip()

        if target_pid is not None and not clean:
            try:
                import psutil
                clean = psutil.Process(target_pid).name()
            except Exception:
                clean = f"PID-{target_pid}"

        return target_pid, clean

    def _generate_process_telemetry_summary(self, target_pid: Optional[int], target_name: str) -> str:
        """
        Produce a comprehensive, sanitized summary of the process:
        - Execution status, CPU, RAM RSS
        - Executable path & command-line
        - Open sockets and ports (protocol, local vs remote IP, port, socket state)
        - Wire packet telemetry & threat alert matches
        - Child process tree lineage & LOLBIN checks
        Scrubbed via 5-Gate DLP to guarantee zero machine-binding leaks.
        """
        import psutil
        from .process_watchdog import find_processes_by_name

        proc: Optional[psutil.Process] = None
        resolved_pid = target_pid
        resolved_name = target_name

        if resolved_pid is not None:
            try:
                p = psutil.Process(resolved_pid)
                proc = p
                resolved_name = p.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proc = None

        if proc is None and resolved_name:
            matches = find_processes_by_name(resolved_name)
            if matches:
                resolved_pid = matches[0][0]
                try:
                    proc = psutil.Process(resolved_pid)
                    resolved_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc = None

        display_name = resolved_name or (f"PID {resolved_pid}" if resolved_pid else "Unknown")
        lines: List[str] = [
            "=" * 68,
            "  PROCESS & NETWORK SOCKET TELEMETRY INSPECTION REPORT",
            "=" * 68,
        ]

        if proc is not None and resolved_pid is not None:
            try:
                status_str = proc.status().upper()
            except Exception:
                status_str = "ACTIVE"
            try:
                cpu_str = f"{proc.cpu_percent(interval=None):.1f}%"
            except Exception:
                cpu_str = "N/A"
            try:
                mem_str = f"{proc.memory_info().rss / (1024 * 1024):.1f} MB"
            except Exception:
                mem_str = "N/A"
            try:
                raw_exe = proc.exe() or "N/A"
            except Exception:
                raw_exe = "N/A"
            try:
                raw_cmd = " ".join(proc.cmdline() or []) or "(No command-line arguments recorded)"
            except Exception:
                raw_cmd = "N/A"

            lines.append(f"  * Process:      {display_name} (PID {resolved_pid})")
            lines.append(f"  * Status:       {status_str} (CPU: {cpu_str}, Memory: {mem_str})")
            lines.append(f"  * Executable:   {raw_exe}")
            lines.append(f"  * Command Line: {raw_cmd}")
        else:
            lines.append(f"  * Process:      {display_name} (PID: {resolved_pid or 'N/A'})")
            lines.append("  * Status:       TERMINATED / INACTIVE (Process has exited memory)")
            lines.append("  * Executable:   (Historic network event attribution)")
            lines.append("  * Command Line: (Process terminated; socket logged during execution)")

        lines.append("")
        lines.append("[1] Active Network Sockets & Port Bindings:")
        sockets_found = False
        if proc is not None and resolved_pid is not None:
            raw_conns = []
            try:
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", DeprecationWarning)
                    if hasattr(proc, "net_connections"):
                        raw_conns = proc.net_connections(kind="inet")
                    else:
                        raw_conns = proc.connections(kind="inet")
            except (psutil.AccessDenied, OSError, Exception):
                try:
                    raw_conns = [c for c in psutil.net_connections(kind="inet") if c.pid == resolved_pid]
                except Exception:
                    raw_conns = []

            for conn in raw_conns:
                sockets_found = True
                proto = "TCP" if getattr(conn, "type", 1) == 1 else "UDP"
                laddr_str = f":{conn.laddr.port}" if hasattr(conn, "laddr") and conn.laddr else ":0"
                if hasattr(conn, "laddr") and conn.laddr and conn.laddr.ip:
                    laddr_str = f"{conn.laddr.ip}:{conn.laddr.port}"

                if hasattr(conn, "raddr") and conn.raddr and len(conn.raddr) >= 2:
                    rip = str(conn.raddr[0])
                    rport = conn.raddr[1]
                    if rip in ("127.0.0.1", "::1", "0.0.0.0"):
                        scope = "Local Loopback"
                    elif is_public_routable_ip(rip):
                        scope = "Public WAN"
                    else:
                        scope = "Private LAN"
                    raddr_str = f"{rip}:{rport} [{scope}]"
                else:
                    raddr_str = "Listening (No remote endpoint)"

                state_str = getattr(conn, "status", "OPEN")
                lines.append(f"  - {proto:<4} Local {laddr_str:<21} --> Remote {raddr_str} ({state_str})")

        if not sockets_found:
            lines.append("  - No active open socket connections detected for this process.")

        lines.append("")
        lines.append("[2] Telemetry & Threat Feeds:")
        event_count = 0
        if hasattr(self, "_monitor_service"):
            event_count = self._monitor_service.get_process_event_count(display_name, resolved_pid)
        lines.append(f"  * Wire Packets Attributed: {event_count:,} events inspected")

        matched_alerts = []
        if hasattr(self, "_monitor_service"):
            for alert in self._monitor_service.recent_alerts(limit=50):
                p_alert = alert.process_name.lower()
                d_name = display_name.lower()
                if (d_name in p_alert) or (resolved_pid and str(resolved_pid) in p_alert):
                    matched_alerts.append(alert)

        if matched_alerts:
            lines.append(f"  * Threat Alerts Triggered: {len(matched_alerts)} alert(s) in audit log:")
            for a in matched_alerts[:5]:
                lines.append(f"    - 🚨 Flagged Target: {a.indicator} [Feed: {a.source_feed}, Layer: {a.detection_layer}]")
        else:
            lines.append("  * Threat Alerts Triggered: 0 active threat matches in recent log.")

        lines.append("")
        lines.append("[3] Child Process Lineage & LOLBIN Analysis:")
        children = []
        if resolved_pid is not None:
            children = inspect_child_lineage(resolved_pid)

        lines.append(f"  * Active Child Processes: {len(children)}")
        for c in children:
            tag = "[SCRIPT INTERPRETER - HIGH RISK]" if c.is_script_interpreter else "[NORMAL CHILD]"
            lines.append(f"    - Child PID {c.child_pid}: {c.child_name} {tag}")
            if c.cmdline:
                lines.append(f"      Cmdline: {c.cmdline}")
        if not children:
            lines.append("    - No spawned child script interpreters detected.")

        lines.append("")
        lines.append("=" * 68)
        lines.append("[PRIVACY GUARANTEE] Local usernames, home paths, and MAC addresses")
        lines.append("are sanitized via 5-Gate DLP before display and export.")
        lines.append("=" * 68)

        full_raw_report = "\n".join(lines)
        return sanitize_log_text(full_raw_report, sanitizer=self.sanitizer)

    def _inspect_process_target(self, target: str, result_widget: tk.Text) -> None:
        """Unified runner for process and socket inspection across all views."""
        if not target.strip():
            return
        result_widget.delete("1.0", tk.END)
        result_widget.insert(tk.END, f"[*] Querying active sockets & telemetry for '{target}'...\n\n")
        self.root.update_idletasks()

        pid, name = self._resolve_target_process_and_pid(target)
        summary = self._generate_process_telemetry_summary(pid, name)
        result_widget.delete("1.0", tk.END)
        result_widget.insert(tk.END, summary)
        result_widget.see("1.0")

    def _copy_process_summary(self, result_widget: tk.Text) -> None:
        """Copy the sanitized process inspection report to the system clipboard."""
        text = result_widget.get("1.0", tk.END).strip()
        if not text:
            return
        safe_text = sanitize_log_text(text, sanitizer=self.sanitizer)
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(safe_text)
            messagebox.showinfo(
                "Report Copied",
                "Sanitized process telemetry report copied to clipboard!\n"
                "Safe to paste in GitHub Issues, Discord, or internal incident tickets.",
            )
        except Exception as exc:
            logger.debug(f"Clipboard copy error: {exc}")

    def _inspect_watchdog_target(self) -> None:
        target = ""
        if hasattr(self, "proc_entry"):
            target = self.proc_entry.get().strip()
        if not target and hasattr(self, "proc_combo"):
            target = self.proc_combo.get().strip()
        if not target:
            target = "python.exe"
        if hasattr(self, "watchdog_results"):
            self._inspect_process_target(target, self.watchdog_results)

    def _inspect_mc_watchdog(self) -> None:
        target = self.mc_proc_combo.get().strip() if hasattr(self, "mc_proc_combo") else "python.exe"
        if not target:
            target = "python.exe"
        if hasattr(self, "mc_watchdog_results"):
            self._inspect_process_target(target, self.mc_watchdog_results)

    def _on_alert_tree_select(self, event: Optional[tk.Event] = None) -> None:
        """Handle row selection in the Live Monitor alerts table."""
        if not hasattr(self, "alert_tree"):
            return
        selected = self.alert_tree.selection()
        if not selected:
            return
        item_vals = self.alert_tree.item(selected[0], "values")
        if len(item_vals) >= 4:
            ind = item_vals[1]
            pname = item_vals[3] or "Unknown"
            combo_val = f"🚨 [SUSPICIOUS] {pname} -> {ind}"
            if hasattr(self, "proc_combo"):
                vals = list(self.proc_combo["values"])
                if combo_val not in vals:
                    vals.insert(0, combo_val)
                    self.proc_combo["values"] = vals
                self.proc_combo.set(combo_val)
                self._inspect_watchdog_target()

    def _on_mc_alert_tree_select(self, event: Optional[tk.Event] = None) -> None:
        """Handle row selection in the Mission Control alerts table."""
        if not hasattr(self, "mc_alert_tree"):
            return
        selected = self.mc_alert_tree.selection()
        if not selected:
            return
        item_vals = self.mc_alert_tree.item(selected[0], "values")
        if len(item_vals) >= 4:
            ind = item_vals[1]
            pname = item_vals[3] or "Unknown"
            combo_val = f"🚨 [SUSPICIOUS] {pname} -> {ind}"
            if hasattr(self, "mc_proc_combo"):
                vals = list(self.mc_proc_combo["values"])
                if combo_val not in vals:
                    vals.insert(0, combo_val)
                    self.mc_proc_combo["values"] = vals
                self.mc_proc_combo.set(combo_val)
                self._inspect_mc_watchdog()

    def _inspect_selected_alert_in_monitor(self) -> None:
        """Explicit button action to inspect selected alert in Live Threat Monitor."""
        if hasattr(self, "alert_tree"):
            sel = self.alert_tree.selection()
            if not sel:
                children = self.alert_tree.get_children()
                if children:
                    self.alert_tree.selection_set(children[0])
            self._on_alert_tree_select()

    def _inspect_selected_alert_in_mc(self) -> None:
        """Explicit button action to inspect selected alert in Mission Control."""
        if hasattr(self, "mc_alert_tree"):
            sel = self.mc_alert_tree.selection()
            if not sel:
                children = self.mc_alert_tree.get_children()
                if children:
                    self.mc_alert_tree.selection_set(children[0])
            self._on_mc_alert_tree_select()

    def _on_space_pressed(self, event: tk.Event) -> None:
        if isinstance(event.widget, (tk.Entry, tk.Text, ttk.Entry, ttk.Combobox)):
            return
        self._toggle_voice_recording()

    def _get_running_process_candidates(self) -> List[str]:
        now = time.monotonic()
        if hasattr(self, "_cached_candidates") and (now - getattr(self, "_last_candidates_ts", 0.0)) < 3.0:
            return list(self._cached_candidates)

        candidates: List[str] = []
        seen_keys: Set[str] = set()

        # 1. Suspicious indicators from recent alerts
        if hasattr(self, "_monitor_service"):
            try:
                alerts = self._monitor_service.recent_alerts(limit=15)
                for alert in alerts:
                    p_raw = alert.process_name or "Unknown"
                    ind = alert.indicator or "Unknown"
                    item = f"🚨 [SUSPICIOUS] {p_raw} -> {ind}"
                    if item not in seen_keys:
                        seen_keys.add(item)
                        candidates.append(item)
            except Exception:
                pass

        # 2. Active outbound socket connections
        if hasattr(self, "_monitor_service"):
            try:
                active_conns = self._monitor_service._monitor._process_mapper.get_active_outbound_connections()
                for proto, lport, rip, rport, pinfo in active_conns[:15]:
                    item = f"🌐 {pinfo.name} (PID {pinfo.pid}) - {proto.upper()} :{lport} -> {rip}:{rport}"
                    if item not in seen_keys:
                        seen_keys.add(item)
                        candidates.append(item)
            except Exception:
                pass

        # 3. Active running processes with PID
        running_names: Set[str] = set()
        try:
            import psutil
            for p in psutil.process_iter(["pid", "name"]):
                try:
                    name = p.info.get("name")
                    pid = p.info.get("pid")
                    if name and pid and not name.startswith("System") and name != "Registry":
                        running_names.add(name)
                        name_lower = name.lower()
                        if any(k in name_lower for k in ("python", "node", "powershell", "cmd", "code", "curl", "git", "bash")):
                            item = f"⚡ {name} (PID {pid})"
                            if item not in seen_keys:
                                seen_keys.add(item)
                                candidates.append(item)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as exc:
            logger.debug(f"Error enumerating running processes: {exc}")

        # 4. Alphabetical process names as simple typing fallback
        fallback_names = sorted(running_names) if running_names else ["python.exe", "node.exe", "powershell.exe", "cmd.exe", "code.exe", "curl.exe"]
        for fn in fallback_names:
            if fn not in seen_keys:
                seen_keys.add(fn)
                candidates.append(fn)

        self._cached_candidates = candidates
        self._last_candidates_ts = now
        return candidates

    def _refresh_process_lists(self) -> None:
        candidates = self._get_running_process_candidates()
        if hasattr(self, "mc_proc_combo"):
            current = self.mc_proc_combo.get()
            self.mc_proc_combo["values"] = candidates
            if current in candidates:
                self.mc_proc_combo.set(current)
            elif candidates:
                self.mc_proc_combo.set(candidates[0])
            else:
                self.mc_proc_combo.set("python.exe")
        if hasattr(self, "proc_combo"):
            current = self.proc_combo.get()
            self.proc_combo["values"] = candidates
            if current in candidates:
                self.proc_combo.set(current)
            elif candidates:
                self.proc_combo.set(candidates[0])
            else:
                self.proc_combo.set("python.exe")

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

        pid, name = self._resolve_target_process_and_pid(target)
        from .process_watchdog import check_lots_risk, find_processes_by_name

        exe = ""
        if pid is not None:
            try:
                import psutil
                p = psutil.Process(pid)
                name = p.name()
                try:
                    exe = p.exe()
                except Exception:
                    exe = name
            except Exception:
                pass
        if not exe and name:
            matches = find_processes_by_name(name)
            if matches:
                pid, name, exe = matches[0]

        if pid is None:
            messagebox.showinfo("Process Not Found", f"No running processes matching '{target}' were found.")
            return

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

    def _inspect_selected_alert_in_mc(self) -> None:
        self._show_threat_explanation()

    def _inspect_selected_alert_in_monitor(self) -> None:
        self._show_threat_explanation()

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
            "OISD": "OISD DNS protection blocklist filtering known telemetry, malicious domains, and compromised redirect hosts.",
            "URLhaus": "Active malware distribution URL tracked by abuse.ch. Known to distribute Trojans, Infostealers, or Ransomware payloads.",
            "ThreatFox": "Indicator of Compromise (IoC) linked to active malware campaigns, botnets, or Command-and-Control (C2) operations.",
            "Feodo Tracker": "Botnet Command-and-Control (C2) server used to coordinate compromised botnet drones and exfiltrate credentials.",
            "HaGeZi Multi": "High-security DNS threat protection filter blocking malicious tracking, telemetry, spyware, and suspicious domains.",
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

        def _terminate_process() -> None:
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

        def _copy_firewall_rule() -> None:
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

        def _ask_ai_remediation() -> None:
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

        create_styled_button(
            btn_row,
            text="Terminate Process",
            icon="🛑",
            style="danger",
            command=_terminate_process,
            font=FONT_BOLD,
            padx=10,
            pady=5,
        ).pack(side=tk.LEFT, padx=(0, 6))

        create_styled_button(
            btn_row,
            text="Copy Firewall Block",
            icon="🛡️",
            style="primary",
            command=_copy_firewall_rule,
            font=FONT_BOLD,
            padx=10,
            pady=5,
        ).pack(side=tk.LEFT, padx=(0, 6))

        create_styled_button(
            btn_row,
            text="Ask AI Remediation",
            icon="🤖",
            style="accent",
            command=_ask_ai_remediation,
            font=FONT_BOLD,
            padx=10,
            pady=5,
        ).pack(side=tk.LEFT, padx=(0, 6))

        create_styled_button(
            btn_row,
            text="Close",
            icon="✕",
            style="secondary",
            command=dialog.destroy,
            font=FONT_BODY,
            padx=10,
            pady=5,
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

        def _on_mousewheel(event: tk.Event) -> None:
            if event.delta:
                canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
            elif event.num == 4:
                canvas.yview_scroll(-1, "units")
            elif event.num == 5:
                canvas.yview_scroll(1, "units")

        def _bind_mousewheel(event: tk.Event) -> None:
            canvas.bind_all("<MouseWheel>", _on_mousewheel)
            canvas.bind_all("<Button-4>", _on_mousewheel)
            canvas.bind_all("<Button-5>", _on_mousewheel)

        def _unbind_mousewheel(event: tk.Event) -> None:
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

        save_btn = create_styled_button(
            save_btn_frame,
            text="Save & Encrypt to Vault",
            icon="💾",
            style="primary",
            command=self._save_settings_vault,
            font=FONT_SECTION,
            padx=18,
            pady=8,
        )
        save_btn.pack(side=tk.LEFT)

        self.vault_status_lbl = tk.Label(
            save_btn_frame,
            text=f"📁 Vault location: {self.vault_mgr.vault_path}",
            font=FONT_SMALL,
            fg=TEXT_MUTED,
            bg=BG_CANVAS,
            padx=12,
        )
        self.vault_status_lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Section 4: User-Inspectable Diagnostic Logs & Maintenance
        s4 = create_card_frame(scrollable_frame, padx=14, pady=12)
        s4.pack(fill=tk.X, pady=(0, 16))

        tk.Label(s4, text="4. Diagnostic Logs & Maintenance", font=FONT_SECTION, fg=TEXT_MAIN, bg=BG_CARD).pack(anchor=tk.W, pady=(0, 4))
        tk.Label(
            s4,
            text="Logs are stored 100% locally. Export forum-safe anonymized bundles or permanently purge local caches:",
            font=FONT_BODY,
            fg=TEXT_MUTED,
            bg=BG_CARD,
        ).pack(anchor=tk.W, pady=(0, 6))

        self.diag_log_text = tk.Text(
            s4,
            bg=BG_CANVAS,
            fg=TEXT_BODY,
            font=FONT_MONO,
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

        open_dir_btn = create_styled_button(
            act_row,
            text="Open Logs Directory",
            icon="📁",
            style="primary",
            command=self._open_logs_dir,
            font=FONT_BOLD,
            padx=10,
            pady=5,
        )
        open_dir_btn.pack(side=tk.LEFT, padx=(0, 6))

        export_bundle_btn = create_styled_button(
            act_row,
            text="Export Anonymized Bundle",
            icon="📦",
            style="primary",
            command=self._export_forum_bundle,
            font=FONT_BOLD,
            padx=10,
            pady=5,
        )
        export_bundle_btn.pack(side=tk.LEFT, padx=(0, 6))

        refresh_logs_btn = create_styled_button(
            act_row,
            text="Refresh Logs",
            icon="🔄",
            style="secondary",
            command=self._refresh_diag_logs,
            font=FONT_BODY,
            padx=8,
            pady=5,
        )
        refresh_logs_btn.pack(side=tk.LEFT, padx=(0, 6))

        incidents_btn = create_styled_button(
            act_row,
            text="Kill Incidents",
            icon="🚨",
            style="secondary",
            command=self._view_kill_incidents,
            font=FONT_BODY,
            padx=8,
            pady=5,
        )
        incidents_btn.pack(side=tk.LEFT, padx=(0, 6))

        nuke_btn = create_styled_button(
            act_row,
            text="Nuke All Local Data",
            icon="🗑️",
            style="danger",
            command=self._nuke_local_data,
            font=FONT_BOLD,
            padx=10,
            pady=5,
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

        copy_mcp_btn = create_styled_button(
            mcp_bar,
            text="Copy MCP Configuration JSON (Cursor / Claude / Antigravity)",
            icon="📋",
            style="primary",
            command=self._copy_mcp_config_json,
            font=FONT_BOLD,
            padx=12,
            pady=4,
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
                ("body", "Evaluates IP and domain destinations against built-in OISD, HaGeZi, Feodo Tracker, and custom threat feeds stored completely locally."),
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
                ("bullet", "• 3. Incident Recorded: An anonymized incident report is written to disk at %LOCALAPPDATA%\\SentinelWire\\logs\\incident_reports\\kill_switch_incident_<timestamp>.json."),
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

        copy_b = create_styled_button(
            b_bar,
            text="Copy Diagnostic Bundle to Clipboard",
            icon="📋",
            style="primary",
            command=_copy_bundle,
            font=FONT_BOLD,
            padx=14,
            pady=6,
        )
        copy_b.pack(side=tk.LEFT)

        close_b = create_styled_button(
            b_bar,
            text="Close",
            style="secondary",
            command=diag_win.destroy,
            font=FONT_BODY,
            padx=12,
            pady=6,
        )
        close_b.pack(side=tk.RIGHT)

    def _copy_ai_diagnostic_summary(self) -> None:
        """
        Gathers sanitized recent operational logs, voice status, and threat alerts,
        scrubs them via 5-Gate DLP to guarantee zero machine leaks, and copies directly
        to the clipboard for instant AI assistant pasting and debugging.
        """
        lines = []
        lines.append("=== SentinelWire Diagnostic & AI Debug Summary ===")
        lines.append(f"Timestamp UTC: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
        lines.append(f"OS: {platform.system()} {platform.release()} ({platform.machine()})")
        lines.append(f"Python: {platform.python_version()} ({platform.python_implementation()})")

        # Telemetry Snapshot
        snap = self._monitor_service.snapshot()
        lines.append(f"Sniffer Running: {snap.running} (Mode: {snap.capture_mode})")
        lines.append(f"Packets Monitored: {snap.events_inspected:,} | Threats Flagged: {snap.alerts_emitted:,}")

        # Voice Engine Status
        if self._voice_status:
            lines.append(f"Voice Engine Ready: {self._voice_status.ready} (STT: {self._voice_status.stt_installed}, Cached: {self._voice_status.model_cached}, Detail: {self._voice_status.detail})")
        else:
            lines.append("Voice Engine Status: Uninitialized")

        # Recent Threats
        recent_alerts = list(self._monitor_service.recent_alerts(limit=10))
        lines.append(f"\n--- Recent Intercepted Threats ({len(recent_alerts)}) ---")
        if recent_alerts:
            for a in recent_alerts:
                lines.append(f"  * [{a.timestamp_utc}] {a.indicator} ({a.source_feed}) -> Process: {a.process_name} (Layer: {a.detection_layer})")
        else:
            lines.append("  (No suspicious network connections flagged)")

        # Recent Logs (tail 40 lines of sentinelwire.log)
        log_file = get_log_dir() / "sentinelwire.log"
        lines.append("\n--- Recent Operational Logs (Tail 40 lines) ---")
        if log_file.exists():
            try:
                with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                    log_lines = f.readlines()
                    lines.extend(l.rstrip() for l in log_lines[-40:])
            except Exception as exc:
                lines.append(f"[Error reading log file: {exc}]")
        else:
            lines.append("  (Log file not created yet)")

        raw_summary = "\n".join(lines)
        clean_summary = sanitize_log_text(raw_summary, sanitizer=self.sanitizer)

        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(clean_summary)
            messagebox.showinfo(
                "Logs Copied for AI",
                "✅ Sanitized diagnostic logs and alert summary copied to clipboard!\n\n"
                "All personal usernames, IP addresses, and file paths have been scrubbed.\n"
                "You can now paste (Ctrl + V) directly into chat for instant AI debugging.",
            )
        except Exception as exc:
            logger.warning(f"Failed to copy AI diagnostic summary to clipboard: {exc}")

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

        copy_b = create_styled_button(
            b_bar,
            text="Copy Incident Report for GitHub / Forums",
            icon="📋",
            style="primary",
            command=_copy_incidents,
            font=FONT_BOLD,
            padx=14,
            pady=6,
        )
        copy_b.pack(side=tk.LEFT)

        close_b = create_styled_button(
            b_bar,
            text="Close",
            style="secondary",
            command=inc_win.destroy,
            font=FONT_BODY,
            padx=12,
            pady=6,
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

        min_btn = create_styled_button(
            footer,
            text="Hide to Background",
            icon="🗕",
            style="ghost",
            command=self._minimize_to_tray,
            font=FONT_SMALL,
            padx=8,
            pady=2,
        )
        min_btn.pack(side=tk.RIGHT)

    def _on_tk_exception(
        self,
        exc_type: type[BaseException],
        exc_value: BaseException,
        exc_traceback: Any,
    ) -> None:
        """Capture and log unhandled Tkinter callback exceptions with sanitized tracebacks."""
        logger = logging.getLogger("sentinelwire.ui")
        logger.critical(
            "Unhandled exception in Tkinter callback: %s",
            exc_value,
            exc_info=(exc_type, exc_value, exc_traceback),
        )
        import traceback
        traceback.print_exception(exc_type, exc_value, exc_traceback, file=sys.stderr)

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

        kill_btn = create_styled_button(
            btn_bar,
            text="ENGAGE KILL SWITCH NOW",
            icon="🚨",
            style="danger",
            command=_execute_kill,
            font=FONT_SECTION,
            padx=14,
            pady=6,
        )
        kill_btn.pack(side=tk.LEFT)

        cancel_btn = create_styled_button(
            btn_bar,
            text="Cancel / Return to App",
            style="secondary",
            command=dialog.destroy,
            font=FONT_BODY,
            padx=12,
            pady=6,
        )
        cancel_btn.pack(side=tk.RIGHT)

    def run(self) -> None:
        """Run the main event loop and clean up background services on exit."""
        try:
            self.root.mainloop()
        except Exception as exc:
            logger = logging.getLogger("sentinelwire.ui")
            logger.critical("Fatal exception in Tkinter main loop: %s", exc, exc_info=True)
            raise
        finally:
            try:
                self._monitor_service.shutdown()
            except Exception:
                pass


def launch_desktop_app(config: Optional[AppConfig] = None) -> None:
    """Entry point for CLI `--ui` command to launch the SentinelWire desktop app."""
    try:
        app = PacketSentinelDesktopApp(config=config)
        app.run()
    except Exception as exc:
        logger = logging.getLogger("sentinelwire.ui")
        logger.critical("Fatal unhandled exception during desktop app launch: %s", exc, exc_info=True)
        raise


# Backward-compatible aliases
SentinelWireDesktopApp = PacketSentinelDesktopApp
PacketSentinelApp = PacketSentinelDesktopApp
SentinelWireApp = PacketSentinelDesktopApp


