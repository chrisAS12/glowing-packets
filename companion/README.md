# PacketSentinel

**Real-time Windows Packet & Sketchy DNS Threat Monitor** powered by Wireshark (`tshark` / Npcap) and community-maintained open-source threat intelligence feeds.

Whenever a background process or application on your PC sends unexpected DNS queries, HTTPS TLS handshakes (SNI), or direct IP connections to known malware, phishing, or sketchy domains/IPs, **PacketSentinel** immediately alerts you via a **Windows Desktop Toast Notification**, identifies the **exact process (`.exe` & PID)** that sent the packet, and records an entry in a rotating JSONL audit log.

---

## Key Features

- **Wireshark (`tshark.exe`) + OS Multi-Layer Capture**:
  - **Layer 1 (`tshark` Wire Capture)**: Inspects live outbound **DNS queries (`UDP/TCP port 53`)**, **HTTPS TLS `ClientHello` SNI hostnames (`TCP port 443`)**, and **outbound TCP `SYN` connections** in real time with minimal CPU/RAM overhead.
  - **Layer 2 (Zero-Admin Socket & Windows DNS Cache Fallback)**: Continuously correlates active OS sockets (`psutil`) and the Windows DNS Resolver Cache (`ipconfig /displaydns`) so you stay protected even without raw capture privileges.
- **Open-Source Threat Intelligence Feeds (Out of the Box)**:
  - **[DandelionSprout Anti-Malware Hosts](https://github.com/DandelionSprout/adfilt)** (Curated anti-malware & scam domains)
  - **[Prigent Malware & Cryptojacking Domains](https://firebog.net/)** (Active malware & cryptomining DNS blocklist)
  - **[Abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/)** (Botnet C2 IP blocklist)
  - **[StevenBlack Unified Hosts](https://github.com/StevenBlack/hosts)** (Community repo of sketchy, malware, and tracker domains)
  - **[OpenPhish GitHub Feed](https://github.com/openphish/public_feed)** (Active phishing domains)
  - **Custom GitHub Repos & Local Blocklist**: Easily attach your own GitHub community repo URL (`--add-feed`) or add domains locally (`--add-domain`).
- **Process Attribution**: Identifies which local executable (`chrome.exe`, `python.exe`, or an unknown background script) initiated the packet.
- **Hardened Security Architecture**:
  - Built against **OWASP Top 50** security controls: zero `shell=True`, injection-proof WinRT Toast Notifications, SSRF-guarded HTTPS-only feed downloads with TLS 1.2+, SHA-256 verified local caches, and token-bucket alert rate limiting.

---

## Quick Start (Windows)

### Prerequisites
1. **Windows 10 / 11**
2. **[Wireshark](https://www.wireshark.org/download.html)** (installs `tshark.exe` and the **Npcap** driver automatically)
3. **Python 3.10+** (or use the standalone Windows `.exe` bundle—see below)

### 1. Install Dependency
```powershell
pip install -r requirements.txt
```

### 2. Run Interactive Setup & Self-Test Wizard
Walks you through every component with prompts, explains what is being configured, tests live packet detection & desktop notifications, and shows where to get help if anything is missing:
```powershell
python run_packetsentinel.py --setup
```
*(See [SETUP_AND_TROUBLESHOOTING.md](SETUP_AND_TROUBLESHOOTING.md) for a full walkthrough and troubleshooting guide.)*

### 3. Check System & Threat Feed Status
```powershell
python run_packetsentinel.py --status
```

### 4. Start Live Packet Monitoring
```powershell
python run_packetsentinel.py
```
*(Or double-click `Start-PacketSentinel.bat`)*

While `PacketSentinel` is running, open another terminal and run a harmless test lookup against the built-in canary domain:
```powershell
nslookup sketchy-canary.example.com
```
You will immediately receive a Windows Toast Notification and console alert!

---

## CLI Reference

| Command | Description |
| :--- | :--- |
| `python run_packetsentinel.py --setup` | Run interactive step-by-step setup, explanation & self-test wizard |
| `python run_packetsentinel.py` | Start real-time packet & DNS monitoring |
| `python run_packetsentinel.py --status` | Show Wireshark/Npcap health, active adapters, and loaded indicator counts |
| `python run_packetsentinel.py --update-feeds` | Force refresh all threat feeds over HTTPS |
| `python run_packetsentinel.py --check <domain_or_ip>` | Check if a domain (or subdomain) or IP is flagged |
| `python run_packetsentinel.py --add-domain <domain_or_ip>` | Add a sketchy domain/IP to your local custom blocklist |
| `python run_packetsentinel.py --add-feed <https_url>` | Add a custom GitHub raw blocklist URL to `config.json` |
| `python run_packetsentinel.py --test-alert` | Trigger a safe simulated alert notification |
| `python run_packetsentinel.py --mcp` | Start the Read-Only, 5-Gate Pre-Model Privacy & DLP MCP Server over stdio |
| `python run_packetsentinel.py --mcp --mcp-workspace <dir>` | Start the MCP server jailed to `<dir>` for safe AI file & alert inspection |

---

## Building a Standalone Windows Bundle (`.exe`)

To package `PacketSentinel` into a standalone Windows bundle (`dist/PacketSentinel/PacketSentinel.exe` + `dist/PacketSentinel-Windows-x64.zip` + `SHA256SUMS.txt`) so any Windows user can run it without installing Python:

```powershell
pip install pyinstaller
python build_bundle.py
```

---

## License

Released under the [Apache 2.0 License](LICENSE). See [SECURITY.md](SECURITY.md) for our threat model and security policy.
