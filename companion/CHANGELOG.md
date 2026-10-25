# Changelog — PacketSentinel Companion & Privacy MCP Server

All notable changes to `companion/` are recorded here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The upstream Rustinel engine keeps its own release notes in `.github/release-notes/`.

## [Unreleased]

### Added
- `egress_guard.py`: PEP 578 audit-hook tripwire that rejects outbound sockets, HTTP clients, and `ctypes` calls once monitoring or the MCP server starts, plus OS-level outbound block commands for Windows (`netsh`), macOS (`sandbox-exec`), and Linux (`systemd-run`).
- `mcp_privacy.py`: local sanitizer applied before any MCP response. Blocks images, documents, databases, archives, keys, and `.env` files by name and magic bytes; redacts Luhn-valid card numbers, Mod-97-valid IBANs, SSNs, tokens, OS username/hostname, profile paths, emails, phone numbers, MAC addresses, and private IPs; reduces Rustinel/PacketSentinel alerts to an allowlisted schema.
- `mcp_server.py` and `--mcp` / `--mcp-workspace` CLI flags: read-only stdio JSON-RPC server with four tools (`get_sanitized_security_alerts`, `check_indicator_reputation`, `get_sanitized_system_diagnostics`, `read_sanitized_project_text`).
- `ThreatIntelEngine.load_or_update_feeds(offline_only=True)` for cache-only reloads.

### Changed
- Strict zero-outbound startup: `load_or_update_feeds(offline_only=True)` is used by default at startup so no external network requests are made unless `--update-feeds` is explicitly invoked.
- Live monitoring engages the egress tripwire before capture starts; periodic feed refresh now reads the local cache only and never contacts the network while monitoring.
- Terminal sanitizer strips OSC sequences (OSC 52 clipboard writes, OSC 8 hyperlinks) in addition to CSI sequences.

### Security
- MCP file reader rejects symlinks/reparse points, NTFS alternate data streams, and Windows reserved device names (`CON`, `NUL`, `COM1`…).
- Inline SVG stripping and PEM key matching rewritten/bounded to stay linear on hostile input (CWE-1333).
