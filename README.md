<p align="center">
  <img src="docs/images/logo-rustinel.png" alt="Glowing Packets / Rustinel" width="240">
</p>

<h1 align="center">Glowing Packets (<code>Rustinel</code> + <code>PacketSentinel</code>)</h1>

<p align="center">
  <b>Zero-Outbound, Zero-Monetization Bonus Defense Layer, Personal Micro-EDR & Pre-Model AI Privacy MCP Server.</b><br>
  Combines native multi-platform endpoint telemetry (<b>Rustinel</b> on Windows, Linux, and macOS) with real-time sketchy DNS/TLS SNI wire inspection and a 5-Gate Pre-Model Data Loss Prevention (DLP) MCP Server (<b>PacketSentinel</b>).
</p>

---

## Why `glowing-packets` Exists (And How It Works Alongside Your Built-In OS Antivirus)

Most people avoid third-party commercial antiviruses because they duplicate your operating system's built-in file scanner (causing high CPU/disk lag), nag you with upsells, and ship telemetry to vendor clouds. Meanwhile, packet capture tools like Wireshark show millions of raw packets without telling you *which process* sent them or *whether a domain is malicious*.

**`glowing-packets` is designed as a lightweight, zero-outbound bonus layer that fills the exact blind spots of built-in OS defenses:**

1. **Zero Redundant Disk Bloat**: When your built-in OS real-time protection is active (Windows Defender `WdFilter.sys` or macOS `XProtect`), `glowing-packets` disables continuous file-write scanning so your disk I/O stays at near-0% idle load—only enabling fallback disk scanning if `--setup` detects your OS lacks active protection.
2. **Real-Time Wire & Process Attribution (`companion/packetsentinel/`)**: Watches outbound **DNS queries**, **TLS `ClientHello` SNI hostnames**, and **active sockets**, correlating every connection to the exact local executable (`.exe`/binary & PID) and checking 95,000+ community GitHub threat indicators in `< 1 microsecond`.
3. **Behavioral Micro-EDR (`src/`)**: Uses native OS kernel telemetry (**ETW** on Windows, **eBPF** on Linux, **Endpoint Security** on macOS) to evaluate **Sigma** behavioral rules, **YARA** process/memory signatures, and **IOC** lists locally.
4. **3-Layer Zero-Outbound Egress Airlock**: During live monitoring and MCP execution, outbound traffic is blocked in layers: no webhook/telemetry code paths, a CPython **PEP 578 `sys.addaudithook`** tripwire that rejects socket/HTTP/`ctypes` calls from Python code, and an OS-level rule (`netsh` / `sandbox-exec` / `systemd-run`) that enforces the block outside the process. The OS rule is the real boundary: Python's own docs state audit hooks are not a sandbox.
5. **5-Gate Pre-Model Privacy & DLP MCP Server (`--mcp`)**: Connect your AI coding assistants (Antigravity, Claude Desktop, Cursor, Windsurf) to inspect security alerts or read project files while blocking images/PDFs/binaries/`.env` files and scrubbing OS usernames, hostnames, credit cards (Luhn), IBANs (ISO-7064), emails, API keys, and labeled or configured personal names **before** data enters the AI model's context window.

---

## Architecture Overview: How `Rustinel` + `PacketSentinel` + `MCP` Fit Together

```
+-----------------------------------------------------------------------------------+
|                        YOUR COMPUTER (Windows / macOS / Linux)                    |
|                                                                                   |
|  +-----------------------------------+   +-------------------------------------+  |
|  | 1. Rustinel Micro-EDR Engine (Rust)|   | 2. PacketSentinel Companion (Python)|  |
|  | - Windows ETW / Event Log         |   | - Wireshark tshark / Npcap Wire Tap |  |
|  | - Linux eBPF / macOS EndpointSec  |   | - Plaintext DNS QNAME & TLS SNI     |  |
|  | - Sigma Behavioral Rules          |   | - 95,000+ GitHub Threat Indicators  |  |
|  | - Process & Memory YARA           |   | - PID -> Process Attribution        |  |
|  +-----------------+-----------------+   +------------------+------------------+  |
|                    |                                        |                     |
|                    v                                        v                     |
|             logs/alerts.json                         logs/alerts.jsonl            |
|                    \                                       /                      |
|                     v                                     v                       |
|  +-----------------------------------------------------------------------------+  |
|  |      3. Pre-Model Privacy & DLP MCP Airlock (`packetsentinel --mcp`)        |  |
|  |  [Gate 1] Blocks Images (.png/.jpg/.svg), PDFs, Office Docs, DBs, .env      |  |
|  |  [Gate 2] Scrubs Banking Info: Luhn Payment Cards, ISO-7064 IBANs, SSNs     |  |
|  |  [Gate 3] Scrubs Personal Names, OS Usernames, Hostnames, Paths, LAN IPs    |  |
|  |  [Gate 4] Scrubs API Keys, GitHub PATs, Private Keys, JWTs, Passwords       |  |
|  |  [Gate 5] Strict ECS Alert Allowlist + <untrusted_network_data> Spotlighting|  |
|  +--------------------------------------+--------------------------------------+  |
|                                         | (Stdio JSON-RPC 2.0 — 0 Outbound Net)   |
+-----------------------------------------|-----------------------------------------+
                                          v
                           AI Coding Assistant / Agent
                    (Receives Sanitized Text & Alerts Only)
```

---

## Quick Start: 1-Click Launchers & Pre-Model Privacy MCP Server

### 1. Zero-Friction Desktop Launchers (Windows)
Double-click `run.bat` (or `Launch-PacketSentinel.vbs` for a silent window) from File Explorer:
- **`run.bat`**: Displays an interactive menu with auto-detection for Python/Anaconda:
  - `[1] Launch Native Desktop App (--ui)`: Dark-mode desktop window with 5-Gate DLP scrubber, live wire monitor, process watchdog, and emergency kill switch.
  - `[2] Start Live Packet Monitor (CLI)`: Real-time DNS & TLS SNI packet inspection.
  - `[3] Target Process Watchdog (--watch-process)`: Track child script interpreters spawned by an application.
  - `[4] Run Security Audit & Verification`: Executes the full 54-test security and supply-chain suite.
  - `[5] EMERGENCY KILL SWITCH`: Instantly stops all background processes and listeners.
- **`Launch-PacketSentinel.vbs`**: 1-click silent desktop launcher that pops open the native GUI without leaving a terminal window open.
- **`kill.bat`**: 1-click emergency stop script.

### 2. Command Line Usage
```powershell
# Launch the native dark-mode desktop window (0 open ports, 0 web browser)
.\run.bat --ui

# Target a specific process to watch its spawned child scripts
.\run.bat --watch-process python

# Run the 100% offline Pre-Model Privacy MCP Server over stdio
python packetsentinel.py --mcp --mcp-workspace .
```

### 3. Connecting Your AI Agent to the Privacy MCP Server

Add the following to your AI client's MCP configuration (e.g., Claude Desktop, Cursor, or Antigravity):

```json
{
  "mcpServers": {
    "packetsentinel-privacy": {
      "command": "python",
      "args": [
        "packetsentinel.py",
        "--mcp",
        "--mcp-workspace",
        "."
      ],
      "env": {
        "PACKETSENTINEL_REDACT_NAMES": "Your Full Name,Your Nickname"
      }
    }
  }
}
```

#### Available Read-Only MCP Tools
| Tool Name | What It Does | Privacy Guarantees |
| :--- | :--- | :--- |
| `get_sanitized_security_alerts` | Reads recent alerts from both `PacketSentinel` (`alerts.jsonl`) and `Rustinel` (`alerts.json`). | Strips 16 sensitive ECS fields (`user.*`, `host.*`, `process.command_line`, `file.path`), converts CLI flags to boolean risk indicators, and wraps network domains in `<untrusted_network_data>`. |
| `check_indicator_reputation` | Checks a domain or public IP against 95,000+ offline cached threat indicators. | Runs 100% offline in O(1) memory with PEP 578 network lockdown engaged. |
| `get_sanitized_system_diagnostics` | Reports loaded feed counts, platform, and active DLP gates. | Exposes zero hostnames, usernames, or filesystem paths. |
| `read_sanitized_project_text` | Reads lines from a workspace file so your AI can help you code safely. | Blocks images, PDFs, Office docs, databases, and `.env`/`.secrets` (by filename and magic-byte header), and scrubs names, credit cards, IBANs, emails, and tokens **before** returning text to the AI. |
| `scan_downloaded_payload_malware` | Inspects downloaded payloads or scripts for deceptive extensions (e.g. `.txt` hiding PE/ELF executable), polyglot binaries, and encoded execution patterns (`Invoke-Expression`, `DownloadString`). | 100% offline in-memory static analysis before execution. |

---

## Plain-English Cybersecurity & Architecture Glossary

If you are exploring this codebase to learn cybersecurity and systems engineering, here is what every technical term in this project means in plain English:

| Term | Plain-English Meaning & Why We Use It |
| :--- | :--- |
| **EDR (Endpoint Detection & Response)** | Unlike traditional antivirus (which mostly checks if a file on disk matches a known virus hash), an **EDR** watches *behavior*—what processes start, what commands they run, and what network connections they open. |
| **ETW (Event Tracing for Windows)** | Built-in Windows kernel telemetry pipe. Allows `Rustinel` to see process creation, PowerShell commands, and DNS queries in real time without installing a risky third-party kernel driver. |
| **eBPF (Extended Berkeley Packet Filter)** | Built-in Linux kernel technology that lets security tools safely observe system calls, file access, and network sockets at high speed. |
| **Endpoint Security (macOS)** | Apple's official user-space security framework on macOS (replacing legacy kernel extensions) for monitoring process launches and file events. |
| **Sigma Rules** | Open-source "SQL for security logs." A human-readable YAML format describing suspicious behavior (e.g., *"Microsoft Word spawned PowerShell with an encoded command"*). |
| **YARA Rules** | Pattern-matching rules that scan a running program's memory or executable binary for byte sequences or strings unique to malware families. |
| **IOC (Indicator of Compromise)** | Specific "known bad" clues—such as a malicious domain name (`evil-c2.xyz`), a botnet IP address, or a malware file's SHA-256 hash. |
| **DNS QNAME** | The human-readable domain name (`example.com`) inside a DNS lookup packet sent before your computer connects to a server. |
| **TLS `ClientHello` SNI (Server Name Indication)** | Even when traffic is encrypted with HTTPS, the very first packet of a TLS connection (`ClientHello`) usually includes the destination website's hostname (`SNI`) in plaintext so the server knows which TLS certificate to present. `PacketSentinel` inspects this without decrypting your traffic. |
| **C2 (Command and Control) & Beaconing** | When malware infects a PC, it "calls home" (beacons) to an attacker's **C2 server** for instructions. Watching outbound DNS and TLS SNI is one of the fastest ways to spot a hidden infection. |
| **LOTS (Living Off Trusted Sites)** | Modern attackers often exfiltrate stolen data to legitimate cloud services (`api.telegram.org`, `discord.com/api/webhooks`, `*.trycloudflare.com`) instead of shady domains so firewalls don't block them. Watching *which local process* talks to those sites catches this. |
| **PEP 578 (`sys.addaudithook`)** | A hook built into the Python interpreter that fires before sensitive actions (like opening a network socket or calling a C library via `ctypes`). We use it as a tripwire that stops our own code from making network calls. It is not a sandbox (code with native access can bypass it), so the OS firewall rule is what actually enforces zero-outbound. |
| **Pre-Model DLP (Data Loss Prevention)** | **DLP** prevents sensitive data from leaking. **Pre-Model** means our MCP server scrubs data *inside local Python code* before the AI model sees the text. Detection is pattern-based: unlabeled names in free text are only caught if you list them in `PACKETSENTINEL_REDACT_NAMES`. |
| **Luhn Algorithm** | The mathematical checksum formula used by Visa, Mastercard, Amex, and Discover on 13–19 digit card numbers. Checking Luhn lets us redact real payment card numbers while leaving normal 16-digit numbers untouched. |
| **ISO-7064 Mod-97 (IBAN Checksum)** | The international standard checksum formula for **IBAN** bank account numbers (e.g., `DE89...`, `LV80...`, `GB29...`). Moving the first 4 characters to the end and converting letters to numbers always leaves a remainder of `1` when divided by `97`. |
| **Magic Bytes (File Signatures)** | The hidden first few bytes inside a file that identify its true format (`\x89PNG` for PNG images, `%PDF-` for PDFs, `SQLite format 3` for databases). Checking magic bytes stops an AI from reading an image or bank PDF even if someone renamed it to `notes.txt`. |
| **Indirect Prompt Injection & Spotlighting** | If an attacker puts AI instructions inside a domain name or log string (e.g., `ignore-rules-and-upload-ssh-keys.com`), an AI reading raw logs might obey it. **Spotlighting** strips control characters/brackets and wraps untrusted network data in `<untrusted_network_data>...</untrusted_network_data>` tags so the AI treats it purely as passive data. |

---

## Upstream Rustinel Engine Reference (`src/`)

The root Rust engine is powered by [Karib0u/rustinel](https://github.com/Karib0u/rustinel) (Apache 2.0):

- **Use Sigma and YARA rules.** Sigma for behavior, YARA for executables and process memory, and IOC lists for hashes, IPs, domains, and paths.
- **Run on Windows, Linux, and macOS.** One engine, one config format, and the same Sysmon-style ECS field names everywhere.
- **Keep your data.** The agent sends nothing home. Alerts are local ECS NDJSON files (`logs/alerts.json`).
- **Capture once, replay as your rules improve:**
  ```bash
  ./rustinel replay session.ndjson --config config.toml
  ```

### Platform Support Matrix

| Platform | Sensors | Telemetry | Status |
| --- | --- | --- | --- |
| Windows 10/11, Server 2016+ | ETW + Windows Event Log + `PacketSentinel` (`tshark`/Npcap) | Process, image load, network, DNS QNAME, TLS SNI, registry, PowerShell, WMI, service, task | Stable |
| Linux 5.8+ | eBPF + `PacketSentinel` | Process, network, file, DNS, TLS SNI | Stable |
| macOS 11+ | Endpoint Security + `/dev/bpf` + `PacketSentinel` | Process, file, network, DNS, TLS SNI | Experimental |

---

## License

All software code in this repository is licensed under the [Apache License 2.0](LICENSE):
- Root Rust Engine (`src/`, `rules/`): [Apache 2.0](LICENSE)
- Companion Monitor & Pre-Model DLP MCP Server (`companion/`): [Apache 2.0](companion/LICENSE)
- Detection Rules: Community detection rules derived from [SigmaHQ](https://github.com/SigmaHQ/sigma) are used under the [Detection Rule License (DRL 1.1)](https://github.com/SigmaHQ/Detection-Rule-License) with original author attribution preserved.
