# SentinelWire Native Desktop UI Design System & Architecture

This document defines the interface standards, component hierarchy, design tokens, and ergonomics of SentinelWire.
It serves as the specification for maintaining a zero-clutter, developer-first, and air-gapped desktop experience.

---

## 1. Core Architectural Pillars

SentinelWire adheres to four non-negotiable architectural principles:

1. **Zero Open Ports and Zero Web Exposure**: The entire interface is built using Python's standard library `tkinter` with modern `clam` TTK styling.
   No local HTTP web servers, WebSockets, Electron runtimes, or localhost TCP ports are opened.
   This permanently eliminates Cross-Site Request Forgery (CSRF) and Cross-Origin Resource Sharing (CORS) attack surfaces.

2. **100% Air-Gapped Operation**: Every calculation, speech transcription, packet inspection, and redaction is computed strictly on-device.
   The user interface makes zero outbound network requests to analytics servers, update checkers, or telemetry endpoints.

3. **Pre-Model Privacy Airlock First**: All sensitive data (voice dictation, prompts, terminal logs, code snippets) passes through the local 5-Gate DLP engine before reaching clipboard or external AI contexts.

4. **Instant Emergency Termination**: The primary navigation header provides an immediate red `EMERGENCY KILL SWITCH` button.
   Triggering this button instantly halts background sniffing threads, executes PEP 578 runtime socket isolation, and flushes volatile memory.

---

## 2. Visual Palette & Theme Tokens

The desktop app runs a modern **Obsidian & Charcoal Dark Theme** engineered for high contrast and visual clarity:

| Token Name | Hex Code | Visual Role |
| :--- | :--- | :--- |
| **`BG_CANVAS`** | `#09090b` | Pure dark charcoal background for root canvas and editors. |
| **`BG_SURFACE`** | `#121215` | Vertical navigation sidebar, headers, and container surfaces. |
| **`BG_CARD`** | `#18181b` | Elevated cards, input containers, and tab bodies. |
| **`BG_ELEVATED`** | `#222227` | Elevated action buttons, toolbars, and badges. |
| **`BORDER_COLOR`** | `#2e2e38` | Crisp, high-contrast borders between sections. |
| **`BORDER_FOCUS`** | `#38bdf8` | Active focus cyan border and telemetry indicators. |
| **`TEXT_TITLE`** | `#ffffff` | Pure white headers and prominent titles. |
| **`TEXT_BODY`** | `#e4e4e7` | Crisp silver body text (never muddy or washed out). |
| **`TEXT_MUTED`** | `#a1a1aa` | Readable descriptions, subtitles, and metadata. |
| **`ACCENT_BLUE`** | `#0284c7` | Electric Sentinel Blue for primary actions and active tabs. |
| **`ACCENT_HOVER`** | `#0369a1` | Interactive button hover states. |
| **`ACCENT_EMERALD`**| `#10b981` | Safe status badges, verified DLP output, and canary passes. |
| **`ALERT_RED`** | `#ef4444` | Emergency kill switch, active recording indicator, and threat alerts. |

---

## 3. Five-View Navigation & Cockpit Architecture

The interface is organized into 5 dedicated views driven by a vertical sidebar and top telemetry metric cards:

```
[ Root Window: SentinelWire (1120 x 780) ]
  ├── [ Header Bar: Brand Logo + Version Badge + Airlock Pill + Emergency Kill Switch ]
  ├── [ Top Telemetry Strip: Packets Monitored | Threats Detected | Pre-Model DLP | Vault Status ]
  │     (Clicking cards jumps directly to corresponding tabs)
  │
  ├── [ Main Body: Left Sidebar (220px) + Right View Notebook ]
  │     ├── [ Tab 0: 🏠 Mission Control (Unified Cockpit Dashboard) ]
  │     │     ├── Quick Voice Airlock Card: [🎙️ Start Dictation (Spacebar)] + VAD Silence Auto-Stop
  │     │     ├── Quick Prompt Scrubber: One-click [🧹 Scrub & Send to MCP] + [📋 Copy Prompt]
  │     │     ├── Left Panel: Active Process Dropdown (ttk.Combobox) + [🔍 Inspect] + [🤖 Ask AI Safety]
  │     │     └── Right Panel: Live Threats Tree + [ℹ️ Explain Threat] + [🧪 Canary Test]
  │     │
  │     ├── [ Tab 1: 🛡️ Deep Privacy Airlock ]
  │     │     ├── Top Banner: 5-Gate DLP Capabilities Breakdown
  │     │     ├── Hero Voice Dictation: Live Audio Wave/Status + Offline Whisper Engine
  │     │     ├── Split Editor: Raw Input vs Sanitized Safe Output (Side-by-Side)
  │     │     └── Action Bar: [Scrub with 5-Gate DLP] [Copy Sanitized] [Load Canary] [Clear]
  │     │
  │     ├── [ Tab 2: 📡 Wire & Process Inspector ]
  │     │     ├── Upper Card: Live Wire Packet Capture & Threat Alerts Tree
  │     │     ├── Controls: [▶️ Start Sniffer] [🧪 Canary Alert] [ℹ️ Explain Threat]
  │     │     └── Lower Card: Target Process Watchdog & Script Lineage Inspector (LOLBIN detector)
  │     │
  │     ├── [ Tab 3: ⚙️ Settings & Security Vault ]
  │     │     ├── Smooth Mouse-Wheel Scrollable Canvas (Works seamlessly on Windows & Linux)
  │     │     ├── Section 1: Windows DPAPI Encrypted User Blocklists & Custom Terms
  │     │     ├── Section 2: 5-Gate DLP Granular Toggles (Cards, Keys, Users, IDs, IPs)
  │     │     ├── Section 3: Notification & Audible Threat Alerts
  │     │     ├── Section 4: Diagnostic Logs Viewer, Log Directory Opener & Export Bundle
  │     │     └── Action: [💾 Save & Encrypt to Vault] + [🗑️ Nuke All Local Data]
  │     │
  │     └── [ Tab 4: 📖 Documentation & AI Guides ]
  │           ├── Clean High-Contrast Typography (Zero ASCII Delimiter Clutter)
  │           ├── Interactive Topics: Offline Airlock, 5-Gate DLP, Wire Sniffer, AI MCP, Kill Switch, Privacy
  │           └── Quick MCP JSON Snippet Copy for Antigravity, Cursor, and Claude Desktop
  │
  └── [ Footer Bar: Version Details + Minimize to Background ]
```

---

## 4. Voice Airlock & Push-to-Talk Ergonomics

The Voice Airlock provides speech dictation with zero cloud audio leakage:

1. **Hardware Ingestion**: Captures local microphone audio via WASAPI/ALSA through `sounddevice`.
2. **Push-to-Talk Ergonomics**: Press the **Spacebar** key from anywhere in the app (outside active text fields) to instantly toggle dictation on or off.
3. **Voice Activity Detection (VAD) Silence Auto-Stop**: The microphone recorder continuously measures RMS audio energy. If silence is detected for ~1.8 seconds after speech, recording stops automatically and transcription begins immediately.
4. **Offline Quantized Whisper**: Transcribes audio locally on CPU using `faster-whisper` (`base` model, `local_files_only=True`).
5. **Pre-Model 5-Gate DLP Redaction**: Converts spoken transcripts through payment card Luhn validation, API key patterns, OS usernames, and national ID redaction.
6. **Zero-Copy MCP Buffer**: Saves scrubbed text to `%LOCALAPPDATA%\PacketSentinel\latest_voice_prompt.json`, accessible directly by AI agents using the `get_latest_voice_prompt` MCP tool.

---

## 5. Threat Explanations & Instant Remediation

When a network connection matches a verified threat intelligence feed (URLhaus, ThreatFox, Feodo Tracker, HaGeZi, Phishing Army):

1. **Interactive Threat Ticker**: Double-clicking any row in the threat table or clicking `[ ℹ️ Explain Threat ]` opens a focused threat explanation modal.
2. **Plain-English Intelligence**: Explains in plain terms what the feed represents (e.g. Botnet C2, malware payload dropper, or high-risk tracking telemetry).
3. **Actionable Remediation**:
   - `[ 🛑 Terminate Process ]`: Safely kills the originating process tree.
   - `[ 🛡️ Copy Firewall Block ]`: Copies an exact Windows PowerShell firewall block command (`New-NetFirewallRule`) to the clipboard.
   - `[ 🤖 Ask AI Remediation ]`: Prepares a sanitized incident report for local AI analysis.
