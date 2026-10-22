# Setup, Architecture Explanation & Troubleshooting Guide

This document explains step-by-step what happens when you install and run **PacketSentinel**, why each security mechanism is designed the way it is, how the interactive setup wizard tests your system, and where to get help if any check fails.

---

## 1. Running the Interactive Setup & Self-Test Wizard

When you run `PacketSentinel` for the first time (or anytime you pass `--setup`), an interactive 5-step wizard walks you through every component and asks for your confirmation before proceeding:

```powershell
python run_packetsentinel.py --setup
```

### What the 5 Steps Do & Test

1. **Step 1 — Privacy & Local Storage Consent**
   - **What it does**: Creates your user-scoped folder at `%LOCALAPPDATA%\PacketSentinel` (`cache/`, `logs/`, `config.json`, and `custom_sketchy_domains.txt`).
   - **Why it's done this way**: Storing cached blocklists in `%LOCALAPPDATA%` instead of a shared `C:\Temp` directory prevents other local users or low-privilege processes from swapping cache files (TOCTOU / symlink attacks). Furthermore, `PacketSentinel` only inspects packet headers (DNS domain query, TLS SNI hostname, IP/port, and local `.exe` name)—it **never** captures or logs payload contents.
2. **Step 2 — Process Attribution Check (`psutil`)**
   - **What it does**: Tests reading the active Windows TCP/UDP socket table and mapping local ports to running `.exe` processes.
   - **Why it's done this way**: Knowing that a packet went to a sketchy domain is only half the story; mapping the source port to a specific PID and `.exe` tells you *which application* sent it.
3. **Step 3 — Wireshark (`tshark.exe`) & Npcap Driver Check**
   - **What it does**: Checks `C:\Program Files\Wireshark\tshark.exe` and queries the Windows `npcap` driver service (`sc query npcap`), then lists your active capture interfaces (`WiFi`, `Ethernet`, `NPF_Loopback`).
   - **Why it's done this way**: We resolve `tshark.exe` strictly from verified absolute `Program Files` paths (never from the current working directory) to prevent Windows DLL/binary planting attacks. If Wireshark/Npcap is not installed, `PacketSentinel` automatically enables its **Zero-Admin Socket & Windows DNS Cache fallback** so you are still protected.
4. **Step 4 — HTTPS Threat Feed Download & SHA-256 Cache Verification**
   - **What it does**: Downloads community-maintained sketchy DNS and botnet C2 IP feeds over HTTPS (`TLS 1.2+` minimum, strict certificate verification, SSRF public-IP verification, and 15 MB stream size cap) and saves them atomically with a `SHA-256` integrity hash.
   - **Why it's done this way**: Verifying that every feed URL resolves strictly to a public routable IP prevents Server-Side/Client-Side Request Forgery (SSRF) against local LAN or cloud metadata services (`169.254.169.254`).
5. **Step 5 — Live Desktop Toast Notification & Canary Packet Test**
   - **What it does**: Starts the live capture engine, sends a harmless UDP DNS lookup for `canary-test.sketchy-canary.example.com` to `127.0.0.1:53`, verifies that `PacketSentinel` catches it, and triggers a native Windows 10/11 Toast popup notification.
   - **Why it's done this way**: To prevent command injection or XML markup injection from a malicious packet containing crafted DNS names (like `$(calc.exe).evil.com`), the notification subsystem executes a **100% static Base64-encoded PowerShell WinRT command** and passes alert text exclusively via environment variables into `XmlDocument.CreateTextNode()`.

---

## 2. Troubleshooting Common Issues

### Issue A: Wireshark `tshark.exe` Not Found or `npcap` Service Stopped
- **Symptom**: Step 3 reports `tshark.exe NOT FOUND` or `Npcap Driver: NOT DETECTED`.
- **How to Fix**:
  1. Download and install **[Wireshark for Windows](https://www.wireshark.org/download.html)**.
  2. During the installer wizard, leave **"Install Npcap"** checked.
  3. If Npcap is already installed but stopped, open PowerShell as Administrator and run:
     ```powershell
     sc.exe start npcap
     ```

### Issue B: Windows Desktop Toast Popup Did Not Appear on Screen
- **Symptom**: Step 5 prints `[!] SUSPICIOUS PACKET DETECTED` in the console and logs to `alerts.jsonl`, but no popup banner appeared in the bottom-right corner of Windows.
- **How to Fix**:
  1. Press **`Win + I`** to open Windows Settings -> **System** -> **Notifications**.
  2. Confirm **Notifications** is toggled **On**.
  3. Turn **Do not disturb** (Focus Assist) **Off**.
  4. Scroll down the app list and ensure notifications are enabled for **Windows PowerShell**.
  5. Note: Even when Windows mutes visual popups (e.g., while playing a full-screen game), every alert is still written in real time to `%LOCALAPPDATA%\PacketSentinel\logs\alerts.jsonl`.

### Issue C: Threat Feed Download Failed (Offline or Firewall Blocked)
- **Symptom**: Step 4 warns that a feed could not be fetched over HTTPS.
- **How to Fix**:
  - `PacketSentinel` automatically falls back to its last SHA-256 verified local cache in `%LOCALAPPDATA%\PacketSentinel\cache` and your local custom file `%LOCALAPPDATA%\PacketSentinel\custom_sketchy_domains.txt`.
  - Ensure outbound HTTPS (`TCP port 443`) is allowed to `raw.githubusercontent.com`, `feodotracker.abuse.ch`, and `v.firebog.net`.

---

## 3. Where to Get Help or Report Issues

If something is not working on your Windows machine or you want to report a false positive / bug:
- **Open an Issue on GitHub**: [https://github.com/chrisAS12/glowing-packets/issues](https://github.com/chrisAS12/glowing-packets/issues)
- **Include Diagnostics**: Run the status command below and paste the output into your GitHub issue:
  ```powershell
  python run_packetsentinel.py --status
  ```
- **Security Vulnerabilities**: Please follow the responsible disclosure instructions in [SECURITY.md](SECURITY.md).
