"""
Read-Only, Pre-Model Privacy & DLP-Scrubbed MCP Server for PacketSentinel.

Allows developers to connect AI coding assistants (Antigravity, Claude Desktop, Cursor,
Windsurf, Cline) via stdio JSON-RPC 2.0 while enforcing:
1. Immediate PEP 578 Zero-Outbound Network Lockdown (`engage_runtime_network_lockdown()`).
2. Pre-Model 5-Gate DLP Sanitization (`PrivacySanitizer`) so images, PDFs, secrets,
   banking/card numbers, IBANs, and personal names/usernames never enter the AI context.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional, Sequence

from . import __version__
from .config import AppConfig, get_app_data_dir
from .egress_guard import engage_runtime_network_lockdown, is_runtime_network_lockdown_active
from .lots_guard import check_ai_package_safety
from .mcp_privacy import PrivacySanitizer, audit_code_secrets, sanitize_prompt_injection
from .security_auditor import audit_environment_security, audit_listening_ports, audit_network_hygiene
from .threat_intel import ThreatIntelEngine


MCP_PROTOCOL_VERSION = "2024-11-05"
MAX_STDIO_MESSAGE_BYTES = 262_144
MAX_ALERT_TAIL_BYTES = 262_144


MCP_TOOLS_SCHEMA: List[Dict[str, Any]] = [
    {
        "name": "get_sanitized_security_alerts",
        "description": (
            "Return recent PacketSentinel and Rustinel security alerts after passing through "
            "the 5-Gate Pre-Model Privacy & DLP Airlock. Strips all usernames, hostnames, "
            "file paths, command-line secrets, and LAN IPs, and wraps untrusted network "
            "indicators in <untrusted_network_data> tags."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of recent sanitized alerts to return (1 to 50).",
                    "default": 20,
                    "minimum": 1,
                    "maximum": 50,
                }
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "check_indicator_reputation",
        "description": (
            "Check whether a domain name or public IPv4/IPv6 address matches the local "
            "offline threat intelligence feeds (95,000+ sketchy DNS/C2 indicators). "
            "Performs zero outbound network queries."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "indicator": {
                    "type": "string",
                    "description": "Domain name or public IP address to check against local threat feeds.",
                }
            },
            "required": ["indicator"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_sanitized_system_diagnostics",
        "description": (
            "Return read-only health and defense posture diagnostics (loaded threat feed counts, "
            "zero-outbound lockdown state, and active DLP gates) with zero hostnames, usernames, "
            "or local filesystem paths."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "read_sanitized_project_text",
        "description": (
            "Read lines from a text file inside the allowed workspace root through the 5-Gate "
            "Pre-Model DLP Airlock. Automatically blocks images (.png/.jpg/.svg/.webp), "
            "PDFs/Office documents, databases, and .env/.secrets files (by path and magic bytes), "
            "and redacts personal names, OS usernames, payment cards (Luhn), IBANs (ISO-7064), "
            "emails, phone numbers, and API keys BEFORE returning text to the AI."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "relative_path": {
                    "type": "string",
                    "description": "Path to the file relative to the allowed workspace root.",
                },
                "start_line": {
                    "type": "integer",
                    "description": "1-based start line number (default: 1).",
                    "default": 1,
                    "minimum": 1,
                },
                "end_line": {
                    "type": "integer",
                    "description": "1-based inclusive end line number (default: 200, max 250 lines per call).",
                    "default": 200,
                    "minimum": 1,
                },
            },
            "required": ["relative_path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "scan_downloaded_payload_malware",
        "description": (
            "Scan a downloaded payload, file content, or text for malware, deceptive extensions "
            "(e.g. .txt hiding PE/MZ executable), polyglot binaries, and encoded script execution "
            "patterns (IEX/DownloadString) before execution. Pure offline scan."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "content_text": {
                    "type": "string",
                    "description": "Text or script content to scan.",
                },
                "filename": {
                    "type": "string",
                    "description": "Intended filename or extension (e.g. 'install.ps1' or 'data.txt').",
                    "default": "unnamed_payload",
                },
            },
            "required": ["content_text"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_latest_voice_prompt",
        "description": (
            "Retrieve the most recent voice dictation recorded in SentinelWire. "
            "Automatically pre-sanitized by the 5-Gate DLP airlock (credit cards, IBANs, "
            "national IDs, and secrets masked). Feeds sanitized voice input directly into "
            "the AI context with zero manual copy-pasting."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "sanitize_prompt_text",
        "description": (
            "Scrub arbitrary text, terminal logs, or code through SentinelWire's local 5-Gate DLP "
            "airlock BEFORE sending it to any AI model. Redacts payment cards, IBANs, national personal IDs, "
            "API keys, private tokens, passwords, and local OS usernames."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "Raw prompt, logs, or code text to sanitize.",
                },
            },
            "required": ["text"],
            "additionalProperties": False,
        },
    },
    {
        "name": "inspect_process_safety",
        "description": (
            "Inspect a running process by name or PID to audit its child lineage, identify "
            "unauthorized script interpreters (powershell, node, python, curl), and evaluate living-off-the-land risk."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "process_name_or_pid": {
                    "type": "string",
                    "description": "Process executable name (e.g. 'python', 'node.exe') or numeric PID.",
                },
            },
            "required": ["process_name_or_pid"],
            "additionalProperties": False,
        },
    },
    {
        "name": "scan_prompt_injection",
        "description": (
            "Scan text, web search results, or user prompts for indirect prompt injection, "
            "zero-width character steganography, and deceptive chat framing overrides before context ingestion."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "Text content, web search snippet, or untrusted prompt to scan.",
                },
            },
            "required": ["text"],
            "additionalProperties": False,
        },
    },
    {
        "name": "verify_package_safety",
        "description": (
            "Verify a Python (PyPI) or Node (npm) package name against AI hallucination patterns "
            "(slopsquatting), popular package prefix/suffix mimicry, and 1-character typosquats."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "package_name": {
                    "type": "string",
                    "description": "Package name to verify (e.g. 'requests', 'python-requests', 'express').",
                },
                "ecosystem": {
                    "type": "string",
                    "description": "Package ecosystem ('pypi' or 'npm').",
                    "default": "pypi",
                },
            },
            "required": ["package_name"],
            "additionalProperties": False,
        },
    },
    {
        "name": "audit_staged_code_for_secrets",
        "description": (
            "Scan a code snippet, git diff, or staged file content for exposed API keys, "
            "GitHub tokens, private keys, JWTs, and live credit cards/IBANs before committing or AI context ingestion."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "string",
                    "description": "Source code text, diff, or script content to scan for secret leaks.",
                },
            },
            "required": ["content"],
            "additionalProperties": False,
        },
    },
    {
        "name": "audit_listening_ports",
        "description": (
            "Inspect local host listening ports (<5ms) to detect dev servers, databases (Redis, Postgres, Mongo), "
            "or local LLM APIs (Ollama) accidentally exposed to the LAN/Wi-Fi on 0.0.0.0 instead of 127.0.0.1."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "audit_environment_security",
        "description": (
            "Inspect environment variables or a .env template for script execution hijack vectors "
            "(NODE_OPTIONS, PYTHONPATH injection, LD_PRELOAD, proxy interception, or custom CA certs)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "custom_env_text": {
                    "type": "string",
                    "description": "Optional raw .env file text to analyze instead of host environment.",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "get_mcp_audit_log",
        "description": (
            "Retrieve recent local MCP tool-call invocation audit logs, showing which files and tools "
            "AI coding assistants requested and whether any DLP redactions or prompt injections occurred."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of recent audit records to return (1 to 50).",
                    "default": 20,
                    "minimum": 1,
                    "maximum": 50,
                },
            },
            "additionalProperties": False,
        },
    },
]


class PacketSentinelMCPServer:
    """
    Zero-outbound, pre-model DLP-enforcing MCP server over JSON-RPC 2.0.
    """

    def __init__(
        self,
        config: Optional[AppConfig] = None,
        workspace_root: Optional[Path] = None,
        extra_redacted_names: Optional[Sequence[str]] = None,
        engage_lockdown: bool = True,
    ) -> None:
        self._config = config or AppConfig.load()
        self._workspace_root = (workspace_root or Path.cwd()).resolve()
        self._sanitizer = PrivacySanitizer(extra_redacted_names=extra_redacted_names)
        self._threat_engine = ThreatIntelEngine(self._config)
        self._threat_engine.load_or_update_feeds(force_network_update=False, offline_only=True)
        if engage_lockdown:
            engage_runtime_network_lockdown()

    @property
    def sanitizer(self) -> PrivacySanitizer:
        return self._sanitizer

    def _read_tail_jsonl(self, path: Path, max_records: int) -> List[Dict[str, Any]]:
        if not path.is_file():
            return []
        try:
            with path.open("rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                offset = max(0, size - MAX_ALERT_TAIL_BYTES)
                fh.seek(offset, os.SEEK_SET)
                raw_chunk = fh.read(MAX_ALERT_TAIL_BYTES).decode("utf-8", errors="replace")
        except Exception:
            return []

        lines = raw_chunk.splitlines()
        if offset > 0 and lines:
            lines = lines[1:]

        records: List[Dict[str, Any]] = []
        for line in reversed(lines):
            if len(records) >= max_records:
                break
            stripped = line.strip()
            if not stripped:
                continue
            try:
                parsed = json.loads(stripped)
                if isinstance(parsed, dict):
                    records.append(self._sanitizer.sanitize_alert_record(parsed))
            except Exception:
                continue
        return records

    def tool_get_sanitized_security_alerts(self, limit: int = 20) -> Dict[str, Any]:
        capped_limit = max(1, min(50, int(limit)))
        alert_files: List[Path] = [
            self._config.log_dir / "alerts.jsonl",
            self._workspace_root / "logs" / "alerts.json",
        ]
        custom_rustinel_log = os.environ.get("PACKETSENTINEL_RUSTINEL_ALERTS")
        if custom_rustinel_log:
            alert_files.append(Path(custom_rustinel_log))

        combined: List[Dict[str, Any]] = []
        for alert_file in alert_files:
            if len(combined) >= capped_limit:
                break
            remaining = capped_limit - len(combined)
            combined.extend(self._read_tail_jsonl(alert_file, max_records=remaining))

        return {
            "count": len(combined),
            "dlp_policy": (
                "5-Gate Pre-Model Privacy Airlock active: all usernames, hostnames, paths, "
                "command-line secrets, and LAN IPs stripped; untrusted indicators wrapped in "
                "<untrusted_network_data> tags."
            ),
            "alerts": combined,
        }

    def get_sanitized_security_alerts(self, limit: int = 20) -> Dict[str, Any]:
        """Method alias matching MCP tool name."""
        return self.tool_get_sanitized_security_alerts(limit=limit)

    def tool_check_indicator_reputation(self, indicator: str) -> Dict[str, Any]:
        raw_target = str(indicator or "").strip()
        if not raw_target or len(raw_target) > 255:
            raise ValueError("Indicator must be a non-empty domain or IP string (<= 255 chars).")

        match = self._threat_engine.check_domain(raw_target) or self._threat_engine.check_ip(raw_target)
        spotlighted = self._sanitizer.spotlight_untrusted_indicator(raw_target)
        if match:
            return {
                "flagged": True,
                "indicator_spotlighted": spotlighted,
                "matched_rule": self._sanitizer.sanitize_text(match.matched_rule),
                "source_feed": self._sanitizer.sanitize_text(match.source_feed),
                "match_type": match.match_type,
                "zero_outbound_lookup": True,
            }
        return {
            "flagged": False,
            "indicator_spotlighted": spotlighted,
            "domains_checked": self._threat_engine.domain_count,
            "ips_checked": self._threat_engine.ip_count,
            "zero_outbound_lookup": True,
        }

    def check_indicator_reputation(self, indicator: str) -> Dict[str, Any]:
        """Method alias matching MCP tool name."""
        return self.tool_check_indicator_reputation(indicator=indicator)

    def tool_get_sanitized_system_diagnostics(self) -> Dict[str, Any]:
        return {
            "server_name": "packetsentinel-privacy-mcp",
            "version": __version__,
            "platform": sys.platform,
            "zero_outbound_lockdown_active": is_runtime_network_lockdown_active(),
            "threat_feeds_loaded": {
                "domain_indicators": self._threat_engine.domain_count,
                "ip_indicators": self._threat_engine.ip_count,
            },
            "active_dlp_gates": [
                "Gate 1: File Extension, Path Denylist & Magic-Byte Blocker (blocks images, PDFs, Office docs, DBs, .env, .secrets)",
                "Gate 2: Financial & Banking Redactor (Luhn payment cards, ISO-7064 Mod-97 IBANs, SWIFT/BIC, SSNs, crypto keys)",
                "Gate 3: Personal Identity & Host Scrubber (OS usernames, hostnames, profile paths, personal names, emails, phones, LAN IPs)",
                "Gate 4: Secrets & High-Entropy Token Scrubber (PEM keys, GitHub/OpenAI/Anthropic/AWS keys, JWTs, Bearer headers)",
                "Gate 5: ECS Security Alert Schema Allowlist + <untrusted_network_data> Prompt-Injection Spotlighting",
            ],
        }

    def tool_read_sanitized_project_text(
        self,
        relative_path: str,
        start_line: int = 1,
        end_line: int = 200,
    ) -> Dict[str, Any]:
        raw_rel = str(relative_path or "").strip()
        if not raw_rel:
            raise ValueError("relative_path must not be empty.")
        if "\x00" in raw_rel:
            raise PermissionError("Null byte in path is forbidden.")

        candidate = self._workspace_root / raw_rel
        return self._sanitizer.validate_and_read_safe_text_file(
            target_path=candidate,
            allowed_root=self._workspace_root,
            start_line=start_line,
            end_line=end_line,
        )

    def tool_scan_downloaded_payload_malware(
        self,
        content_text: str,
        filename: str = "unnamed_payload",
    ) -> Dict[str, Any]:
        from .download_guard import scan_downloaded_payload

        data = str(content_text or "").encode("utf-8", errors="replace")
        res = scan_downloaded_payload(data, filename=filename)
        return {
            "is_safe": res.is_safe,
            "risk_level": res.risk_level,
            "reason": res.reason,
            "sha256": res.sha256,
            "file_size_bytes": res.file_size_bytes,
        }

    def tool_get_latest_voice_prompt(self) -> Dict[str, Any]:
        from .config import get_app_data_dir

        voice_file = get_app_data_dir() / "latest_voice_prompt.json"
        if not voice_file.exists():
            return {
                "status": "empty",
                "message": "No voice prompt recorded yet in SentinelWire.",
                "sanitized_prompt": "",
            }
        try:
            raw = voice_file.read_text(encoding="utf-8", errors="replace")
            parsed = json.loads(raw)
            return {
                "status": "success",
                "timestamp": parsed.get("timestamp", ""),
                "sanitized_prompt": parsed.get("sanitized_prompt", ""),
            }
        except Exception as exc:
            return {
                "status": "error",
                "message": f"Failed to read voice buffer: {exc}",
                "sanitized_prompt": "",
            }

    def tool_sanitize_prompt_text(self, text: str) -> Dict[str, Any]:
        """
        Scrub arbitrary text, terminal logs, or code through SentinelWire's local 5-Gate DLP airlock.
        """
        raw_text = str(text or "")
        sanitized = self._sanitizer.sanitize_text(raw_text)
        was_modified = sanitized != raw_text
        return {
            "status": "success",
            "was_modified": was_modified,
            "original_length": len(raw_text),
            "sanitized_length": len(sanitized),
            "sanitized_text": sanitized,
        }

    def tool_inspect_process_safety(self, process_name_or_pid: str) -> Dict[str, Any]:
        """
        Inspect a running process by name or PID to audit child lineage and script execution risk.
        """
        from .process_watchdog import (
            find_processes_by_name,
            inspect_child_lineage,
        )
        import psutil

        query = str(process_name_or_pid or "").strip()
        matched_procs: List[Dict[str, Any]] = []

        if query.isdigit():
            pid = int(query)
            try:
                p = psutil.Process(pid)
                matched_procs.append({
                    "pid": pid,
                    "name": p.name(),
                    "exe": p.exe() if hasattr(p, "exe") else "unknown",
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, Exception) as exc:
                return {
                    "status": "not_found",
                    "query": query,
                    "error": str(exc),
                    "processes": [],
                }
        else:
            found = find_processes_by_name(query)
            for p_pid, p_name, p_exe in found[:10]:
                matched_procs.append({"pid": p_pid, "name": p_name, "exe": p_exe})

        if not matched_procs:
            return {
                "status": "not_found",
                "query": query,
                "processes": [],
            }

        results: List[Dict[str, Any]] = []
        for p_info in matched_procs:
            pid = p_info["pid"]
            lineage = inspect_child_lineage(pid)
            script_events = [
                {
                    "child_pid": ev.child_pid,
                    "child_name": ev.child_name,
                    "cmdline": ev.cmdline,
                    "is_script_interpreter": ev.is_script_interpreter,
                }
                for ev in lineage
            ]
            has_script_interpreters = any(ev["is_script_interpreter"] for ev in script_events)
            results.append({
                "pid": pid,
                "name": p_info["name"],
                "exe": p_info["exe"],
                "child_count": len(lineage),
                "has_script_interpreters": has_script_interpreters,
                "children": script_events,
            })

        return {
            "status": "success",
            "query": query,
            "processes": results,
        }

    def tool_scan_prompt_injection(self, text: str) -> Dict[str, Any]:
        """Scan text for indirect prompt injection and zero-width steganography."""
        result = sanitize_prompt_injection(text)
        return {
            "is_injection_detected": result.is_injection_detected,
            "has_zero_width_steganography": result.has_zero_width_steganography,
            "reasons": result.reasons,
            "sanitized_text": result.sanitized_text,
        }

    def tool_verify_package_safety(self, package_name: str, ecosystem: str = "pypi") -> Dict[str, Any]:
        """Check package name for slopsquatting or typo-squat risks."""
        result = check_ai_package_safety(package_name, ecosystem=ecosystem)
        return result.to_dict()

    def tool_audit_staged_code_for_secrets(self, content: str) -> Dict[str, Any]:
        """Scan code snippet or staged diff for exposed secrets and private keys."""
        return audit_code_secrets(content)

    def tool_audit_listening_ports(self) -> Dict[str, Any]:
        """Inspect local listening sockets for exposed dev servers or databases."""
        return audit_listening_ports()

    def tool_audit_environment_security(self, custom_env_text: Optional[str] = None) -> Dict[str, Any]:
        """Inspect environment variables for script injection and proxy hijack vectors."""
        return audit_environment_security(custom_env_text=custom_env_text)

    def tool_get_mcp_audit_log(self, limit: int = 20) -> Dict[str, Any]:
        """Retrieve recent local MCP tool-call invocation audit logs."""
        log_dir = get_app_data_dir()
        log_path = log_dir / "mcp_audit.jsonl"
        if not log_path.exists():
            return {"status": "success", "count": 0, "audit_records": []}

        try:
            lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
            records: List[Dict[str, Any]] = []
            for line in lines[-max(1, min(50, limit)) :]:
                if line.strip():
                    try:
                        records.append(json.loads(line))
                    except Exception:
                        continue
            records.reverse()
            return {"status": "success", "count": len(records), "audit_records": records}
        except Exception as exc:
            return {"status": "error", "reason": self._sanitizer.sanitize_text(str(exc))}

    def _log_mcp_audit(
        self,
        tool_name: str,
        is_error: bool = False,
        duration_ms: float = 0.0,
        dlp_blocked: bool = False,
        details: Optional[str] = None,
    ) -> None:
        """Write an anonymized, DLP-safe audit record to local mcp_audit.jsonl."""
        try:
            log_dir = get_app_data_dir()
            log_path = log_dir / "mcp_audit.jsonl"
            record = {
                "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "tool_name": tool_name,
                "is_error": is_error,
                "duration_ms": round(duration_ms, 2),
                "dlp_gate_blocked": dlp_blocked,
            }
            if details:
                record["details"] = details[:120]
            with log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        except Exception:
            pass

    def handle_jsonrpc_message(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not isinstance(request, dict):
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32600, "message": "Invalid Request"},
            }

        method = request.get("method")
        req_id = request.get("id")
        params = request.get("params") if isinstance(request.get("params"), dict) else {}

        # Notifications (no id field) do not return a response
        if "id" not in request:
            return None

        if method == "initialize":
            client_proto = str(params.get("protocolVersion") or MCP_PROTOCOL_VERSION)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": client_proto,
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "sentinelwire-privacy-mcp",
                        "version": __version__,
                    },
                },
            }

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": MCP_TOOLS_SCHEMA},
            }

        if method == "resources/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"resources": []}}

        if method == "prompts/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"prompts": []}}

        if method == "tools/call":
            tool_name = str(params.get("name") or "")
            tool_args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            try:
                if tool_name == "get_sanitized_security_alerts":
                    payload = self.tool_get_sanitized_security_alerts(
                        limit=int(tool_args.get("limit", 20))
                    )
                elif tool_name == "check_indicator_reputation":
                    payload = self.tool_check_indicator_reputation(
                        indicator=str(tool_args.get("indicator", ""))
                    )
                elif tool_name == "get_sanitized_system_diagnostics":
                    payload = self.tool_get_sanitized_system_diagnostics()
                elif tool_name == "read_sanitized_project_text":
                    payload = self.tool_read_sanitized_project_text(
                        relative_path=str(tool_args.get("relative_path", "")),
                        start_line=int(tool_args.get("start_line", 1)),
                        end_line=int(tool_args.get("end_line", 200)),
                    )
                elif tool_name == "scan_downloaded_payload_malware":
                    payload = self.tool_scan_downloaded_payload_malware(
                        content_text=str(tool_args.get("content_text", "")),
                        filename=str(tool_args.get("filename", "unnamed_payload")),
                    )
                elif tool_name == "get_latest_voice_prompt":
                    payload = self.tool_get_latest_voice_prompt()
                elif tool_name == "sanitize_prompt_text":
                    payload = self.tool_sanitize_prompt_text(
                        text=str(tool_args.get("text", ""))
                    )
                elif tool_name == "inspect_process_safety":
                    payload = self.tool_inspect_process_safety(
                        process_name_or_pid=str(tool_args.get("process_name_or_pid", ""))
                    )
                elif tool_name == "scan_prompt_injection":
                    payload = self.tool_scan_prompt_injection(
                        text=str(tool_args.get("text", ""))
                    )
                elif tool_name == "verify_package_safety":
                    payload = self.tool_verify_package_safety(
                        package_name=str(tool_args.get("package_name", "")),
                        ecosystem=str(tool_args.get("ecosystem", "pypi")),
                    )
                elif tool_name == "audit_staged_code_for_secrets":
                    payload = self.tool_audit_staged_code_for_secrets(
                        content=str(tool_args.get("content", ""))
                    )
                elif tool_name == "audit_listening_ports":
                    payload = self.tool_audit_listening_ports()
                elif tool_name == "audit_environment_security":
                    payload = self.tool_audit_environment_security(
                        custom_env_text=tool_args.get("custom_env_text")
                    )
                elif tool_name == "get_mcp_audit_log":
                    payload = self.tool_get_mcp_audit_log(
                        limit=int(tool_args.get("limit", 20))
                    )
                else:
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
                    }

                self._log_mcp_audit(tool_name, is_error=False)
                sanitized_json = self._sanitizer.sanitize_text(json.dumps(payload, indent=2))
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": sanitized_json}],
                        "isError": False,
                    },
                }
            except Exception as exc:
                self._log_mcp_audit(tool_name, is_error=True, dlp_blocked=("DLP_GATE_BLOCKED" in str(exc)))
                safe_err = self._sanitizer.sanitize_text(str(exc))
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(
                                    {"error": safe_err, "dlp_blocked": True},
                                    indent=2,
                                ),
                            }
                        ],
                        "isError": True,
                    },
                }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }


def _read_next_stdio_message(stream: BinaryIO) -> Optional[ Tuple[Dict[str, Any], bool] ]:
    """
    Read either a newline-delimited JSON-RPC message (MCP stdio standard) or a
    Content-Length framed JSON-RPC message. Returns (parsed_dict, use_content_length).
    """
    while True:
        first_line = stream.readline(MAX_STDIO_MESSAGE_BYTES)
        if not first_line:
            return None
        stripped = first_line.strip()
        if not stripped:
            continue

        if stripped.lower().startswith(b"content-length:"):
            length = int(stripped.split(b":", 1)[1].strip())
            if length <= 0 or length > MAX_STDIO_MESSAGE_BYTES:
                raise ValueError(f"Invalid Content-Length: {length}")
            while True:
                hdr = stream.readline(4096)
                if not hdr or hdr in (b"\r\n", b"\n"):
                    break
            body = stream.read(length)
            return json.loads(body.decode("utf-8")), True

        return json.loads(stripped.decode("utf-8")), False


def _write_stdio_message(stream: BinaryIO, payload: Dict[str, Any], use_content_length: bool) -> None:
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if use_content_length:
        header = f"Content-Length: {len(encoded)}\r\n\r\n".encode("ascii")
        stream.write(header + encoded)
    else:
        stream.write(encoded + b"\n")
    stream.flush()


def run_mcp_stdio_server(
    config: Optional[AppConfig] = None,
    workspace_root: Optional[Path] = None,
) -> int:
    engage_runtime_network_lockdown()
    server = PacketSentinelMCPServer(
        config=config,
        workspace_root=workspace_root,
        engage_lockdown=True,
    )
    in_stream = sys.stdin.buffer
    out_stream = sys.stdout.buffer

    while True:
        try:
            item = _read_next_stdio_message(in_stream)
            if item is None:
                break
            req_obj, use_cl = item
            resp = server.handle_jsonrpc_message(req_obj)
            if resp is not None:
                _write_stdio_message(out_stream, resp, use_content_length=use_cl)
        except Exception as exc:
            err_msg = server.sanitizer.sanitize_text(str(exc))
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse/protocol error: {err_msg}"},
            }
            _write_stdio_message(out_stream, err_resp, use_content_length=False)

    return 0


def get_sanitized_security_alerts(
    limit: int = 20,
    server: Optional[PacketSentinelMCPServer] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Module-level RPC exposure for get_sanitized_security_alerts."""
    srv = server or PacketSentinelMCPServer(engage_lockdown=False)
    return srv.tool_get_sanitized_security_alerts(limit=limit)


def check_indicator_reputation(
    indicator: str,
    server: Optional[PacketSentinelMCPServer] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Module-level RPC exposure for check_indicator_reputation."""
    srv = server or PacketSentinelMCPServer(engage_lockdown=False)
    return srv.tool_check_indicator_reputation(indicator=indicator)

