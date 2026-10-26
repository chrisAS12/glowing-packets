# SentinelWire Native Desktop UI Design System & Architecture

This document defines the interface standards, component hierarchy, and design philosophy of SentinelWire.
It serves as the permanent specification for maintaining a zero-clutter, developer-first desktop experience.

---

## 1. Core Architectural Pillars

SentinelWire follows four non-negotiable architectural principles:

1. **Zero Open Ports and Zero Web Exposure**: The entire interface is built using Python's standard library `tkinter`.
   No local HTTP web servers, WebSockets, Electron runtimes, or localhost TCP ports are opened.
   This permanently eliminates Cross-Site Request Forgery (CSRF) and Cross-Origin Resource Sharing (CORS) attack surfaces.

2. **100% Air-Gapped Operation**: Every calculation, speech transcription, packet inspection, and redaction is computed locally.
   The user interface makes zero outbound network requests to analytics servers, update checkers, or telemetry endpoints.

3. **Pre-Model Privacy Airlock First**: All sensitive data (voice notes, prompts, terminal logs, code snippets) passes through the local 5-Gate DLP engine before reaching clipboard or external AI contexts.

4. **Instant Emergency Termination**: The primary navigation header provides an immediate red `EMERGENCY KILL SWITCH` button.
   Triggering this button instantly halts background sniffing threads and flushes volatile memory.

---

## 2. Visual Palette & Theme Tokens

The desktop app runs a customized dark-mode theme designed for technical environments:

| Token Name | Hex Code | Visual Role |
| :--- | :--- | :--- |
| **Obsidian Canvas** | `#0b0f19` / `#0f172a` | Root background color for maximum eye comfort. |
| **Card / Surface Slate** | `#161e31` / `#1e293b` | Elevated cards, input containers, and tab bodies. |
| **Primary Sentinel Blue** | `#0284c7` | Interactive primary buttons, active tabs, and call-to-actions. |
| **Accent Airlock Emerald** | `#22c55e` | Secure status badges, successful redactions, and safe connections. |
| **Danger / Alert Crimson** | `#dc2626` | Emergency kill switch, active recording indicator, and threat alerts. |
| **Muted Slate Typography** | `#94a3b8` / `#64748b` | Subtitles, helper text, and secondary timestamps. |
| **High-Contrast Foreground**| `#f8fafc` / `#ffffff` | Primary headers, code inputs, and critical labels. |

---

## 3. Tab Navigation & Component Tree

The interface is structured into five dedicated, single-responsibility tabs:

```
[ Root Window: SentinelWire (980 x 700) ]
  ├── [ Header Bar: Logo + Brand + Airlock Pill + Emergency Kill Switch ]
  ├── [ Notebook Tabs ]
  │     ├── [ Tab 1: 🎙️ Voice AI Dictation ]
  │     │     ├── Hero Card: Status Pill + Model Details + Big Dictation Button
  │     │     ├── Left Pane: Raw Spoken Audio Transcript
  │     │     ├── Right Pane: 5-Gate DLP Sanitized Transcript
  │     │     └── Action Bar: [Copy Sanitized] [Transfer to Privacy] [Clear]
  │     │
  │     ├── [ Tab 2: 🔒 Pre-Model Privacy (DLP) ]
  │     │     ├── Top Banner: 5-Gate DLP Capabilities Explanation
  │     │     ├── Split Editor: Raw Input vs Sanitized Safe Output
  │     │     └── Action Bar: [Scrub with 5-Gate DLP] [Copy] [Clear]
  │     │
  │     ├── [ Tab 3: 📡 Wire & LOTS Guard ]
  │     │     ├── Top Banner: Live Packet & LOTS Webhook Status
  │     │     └── Real-Time Threat Event Log (Timestamp, Destination, Process, Feed)
  │     │
  │     ├── [ Tab 4: 👁️ Process Watchdog ]
  │     │     ├── Target Input Bar: Process Name or PID Search
  │     │     └── Lineage Tree: Child Script Interpreter Risk Highlighting
  │     │
  │     └── [ Tab 5: ⚙️ Settings & Threat Feeds ]
  │           ├── Windows DPAPI Encrypted Vault Status & Configuration
  │           ├── Custom Redacted Names / Terms (Encrypted On Disk)
  │           ├── Custom Blocked Domains (Encrypted On Disk)
  │           ├── Active Verified Threat Feeds Checklist (URLhaus, ThreatFox, HaGeZi)
  │           └── [💾 Save & Encrypt to Vault] Button
  │
  └── [ Footer Bar: Version Info + Minimize to System Tray Button ]
```

---

## 4. Voice AI Dictation Mechanics

The dedicated Voice AI tab addresses developer dictation directly from the desktop:

1. **Hardware Ingestion**: Uses the local audio subsystem (Windows WASAPI) without sending audio packets over the wire.
2. **Local Transcription**: Integrates with CPU-quantized local speech models (`ggml-whisper-tiny-q5_1`).
3. **Automatic 5-Gate Scrubbing**: As soon as speech is converted to text, it runs through the local Privacy Sanitizer.
   Credit cards, national personal IDs, and secret tokens are masked in real time.
4. **Frictionless Transfer**: With a single click on `Transfer to Privacy Tab`, scrubbed text flows directly into the main prompt scrubber.
