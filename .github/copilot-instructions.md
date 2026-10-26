# GitHub Copilot Steering Instructions — SentinelWire

You are an expert AI pair programmer working on **SentinelWire**, an open-source, zero-outbound micro-EDR, network packet monitor, and local AI DLP privacy airlock.

---

## 1. Project Architecture & Structure

- **Core Engine (`src/`)**: High-performance Rust engine (upstream Rustinel) capturing packets via Npcap / raw sockets with zero kernel drivers.
- **Companion Layer (`companion/packetsentinel/`)**: Python 3.10+ companion system:
  - `desktop_ui.py`: Native offline Tkinter cockpit (Obsidian/Charcoal theme, zero open network ports).
  - `mcp_server.py`: Model Context Protocol JSON-RPC 2.0 stdio server for local AI agents.
  - `mcp_privacy.py`: 5-Gate Pre-Model DLP Engine scrubbing prompts, files, and voice audio before AI ingestion.
  - `vault.py`: Windows DPAPI hardware/LSA encrypted settings store (`CryptProtectData`).
  - `lots_guard.py`: Living-Off-Trusted-Sites & webhook exfiltration detector (flags `node`, `python`, `powershell`, `curl` calling LOTS endpoints).
  - `process_watchdog.py`: Process tree lineage tracer and script interpreter monitor.
  - `voice_engine.py`: Air-gapped local speech-to-text (`faster_whisper` with `local_files_only=True` + RMS VAD silence detection).
- **Zero-Outbound Policy**: SentinelWire must never transmit telemetry, phone home, or contact external servers during monitoring.

---

## 2. Core Non-Negotiable Engineering Rules

### Rule 1: Strict Zero-Outbound Network Rule
- SentinelWire must **never** transmit telemetry, phone home, or initiate external network connections during monitoring.
- All threat feeds, regexes, and intelligence must operate locally or via user-initiated offline cache refreshes.
- Zero analytics, zero crash reporting SDKs, zero monetization/paywalls.

### Rule 2: Hardware-Backed DPAPI Security (`vault.py`)
- Secrets, sensitive configuration tokens, and private blocked domains must be encrypted via Windows DPAPI (`CryptProtectData` / `CryptUnprotectData`).
- Never store plaintext keys, symmetric secrets, or fallback passwords on disk.
- Non-Windows environments must use OS keyring / SecretService fallbacks.

### Rule 3: 5-Gate Pre-Model DLP Engine (`mcp_privacy.py`)
Before any prompt, log, file snippet, or voice transcript is passed to an AI model or MCP tool, it must pass the 5-Gate DLP pipeline:
1. **Gate 1 (Magic Bytes & File Types)**: Block PE, ELF, Mach-O executables, zip archives, `.env` files, certificates (`.pem`, `.key`), and sensitive dotfiles.
2. **Gate 2 (Secret Tokens & Private Keys)**: Regex scrubbing of API keys (`sk-*`, `ghp_*`, AWS `AKIA*`), JWTs, private key blocks.
3. **Gate 3 (Financial Identifiers)**: Luhn-validated payment card redaction (`[REDACTED_PAYMENT_CARD]`) and ISO-7064 IBAN redaction (`[REDACTED_IBAN]`).
4. **Gate 4 (National Identification Numbers)**: Redaction of UK NINO, French NIR, Spanish DNI/NIE, Italian Codice Fiscale, Polish PESEL, and Nordic/Baltic PIC.
5. **Gate 5 (PII & Identity Scrubbing)**: Redaction of personal names, emails, and system account names.

### Rule 4: Built-In OS Defense Deduplication
- SentinelWire is designed to coexist seamlessly with native OS defenses (Windows Defender `WdFilter.sys`, macOS XProtect/Gatekeeper, Linux `ufw`/`nftables`).
- Never implement heavy real-time disk scanners that duplicate Defender's kernel mini-filters.

### Rule 5: Zero Machine-Binding Identifiers
- **NEVER** hardcode or emit machine-specific data: local usernames, hostnames, absolute profile paths (`C:\Users\<user>`), MAC addresses, or private IPs.
- Use placeholders (`<user>`, `<hostname>`, `%LOCALAPPDATA%`, `Path.home()`) in all code, tests, and documentation.

### Rule 6: Anti-Slop & Clean Code Discipline
- **Strict Static Typing**: Use explicit type hints on all Python functions and classes; no untyped dicts or `Any`.
- **Single Responsibility**: Keep functions <= 40 lines and nesting <= 2 levels. Refactor before layering new logic.
- **Zero Ghost Code**: No `// TODO` stubs, dead commented code, or dummy pass-through functions.
- **Verification**: Always run test suites and pre-flight checks before declaring work done.
