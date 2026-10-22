# Security Policy & Architecture (`PacketSentinel`)

## Threat Model

`PacketSentinel` inspects live network metadata (DNS queries, TLS SNI hostnames, and outbound IP socket connections) and downloads external threat-intelligence blocklists. Because both network traffic and external feeds are untrusted inputs, `PacketSentinel` is built with strict defense-in-depth controls:

1. **Zero Command Injection (`shell=False` & Environment-Bound Toast Alerts)**
   - Subprocesses (`tshark.exe`, `ipconfig.exe`, and `powershell.exe` for native WinRT Toast Notifications) are invoked strictly via argument arrays with `shell=False` and verified absolute system paths.
   - Untrusted strings (domain names, IP addresses, process names) are **never** interpolated into command strings or scripts.
2. **Strict Input Validation & Sanitization**
   - All wire-extracted strings have ASCII control characters (`0x00–0x1F`, `0x7F–0x9F`) and ANSI escape sequences stripped immediately upon capture to prevent terminal/log injection.
   - Domain names are canonicalized (lowercase, Punycode/IDNA normalized, trailing dot stripped) and validated against RFC 1035/1123 length and label rules.
   - Raw DNS and TLS ClientHello packet parsers enforce strict slice bounds checking and cap DNS compression pointer jumps (max 10 backward-only hops) to prevent infinite-loop Denial of Service.
3. **SSRF & MITM Protection on Threat Feed Downloads**
   - Threat intelligence feeds must use `https://` with TLS 1.2+ and full certificate verification (`ssl.CERT_REQUIRED`).
   - All feed hostnames are resolved and verified against public routable IP space prior to connection (and across HTTP redirects), blocking loopback (`127.0.0.0/8`, `::1`), private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and cloud metadata (`169.254.169.254`) addresses.
   - HTTP responses are streamed with a strict maximum byte limit (15 MB per feed) to prevent memory exhaustion.
4. **Notification Flood & Disk Exhaustion Protection**
   - Desktop alerts use a token-bucket global rate limiter and per-indicator cooldown suppression so a burst of malicious packets cannot freeze the user's desktop.
   - Security alerts are written to structured JSONL logs managed by a bounded `RotatingFileHandler` (max 5 MB per file, 3 backups).
5. **Privacy by Design**
   - Only connection metadata (domain name, destination IP/port, and local process PID/name) is inspected. Full packet application payloads are never stored or logged.

## Reporting a Vulnerability

If you discover a security issue in `PacketSentinel`, please **do not open a public issue** with exploit details. Instead, use GitHub's **Private Vulnerability Reporting** ("Report a vulnerability" under the Security tab of this repository) so we can issue a fix before disclosure.
