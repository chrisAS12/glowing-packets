"""
Secure Web Gateway & Outbound Egress Inspector for AI Assistants.

Provides an inspected, multi-layered gateway for AI assistants (Cursor, Copilot,
Antigravity, Claude Desktop) to fetch external web documentation and resources while
enforcing:
1. SSRF & Localhost Shield: Blocks loopback, private RFC1918 subnets, and cloud metadata (169.254.169.254).
2. Outbound Secret Leak Scrubber: Scans outgoing URLs and query parameters for API keys, tokens, and passwords.
3. 95,000+ Threat Feed Pre-Check: Checks target domains against local threat intel before connection.
4. Payload & Polyglot Block: Inspects magic bytes (PE/MZ, ELF, Mach-O) to prevent downloading executables.
5. Gate 6 Prompt-Injection & Steganography Neutralizer: Strips hidden Unicode steganography and wraps content.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple

from .download_guard import check_magic_executable, detect_polyglot_executable
from .egress_guard import permit_inspected_gateway_egress
from .mcp_privacy import audit_code_secrets, sanitize_prompt_injection
from .security import is_public_routable_ip, validate_ip_address
from .threat_intel import ThreatIntelEngine

logger = logging.getLogger("packetsentinel.web_gateway")

MAX_GATEWAY_FETCH_BYTES_DEFAULT = 1_048_576  # 1 MB max response size
DEFAULT_GATEWAY_TIMEOUT_SECONDS = 8.0
USER_AGENT_HEADER = "SentinelWire-SafeWebGateway/1.0 (+offline-ai-defense)"

# Hostnames explicitly blocked from SSRF attempts
_BLOCKED_HOST_LITERALS = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        "metadata.google.internal",
    }
)

_BLOCKED_HOST_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".home.arpa",
    ".corp",
)


@dataclass(frozen=True)
class GatewayValidationResult:
    """Pre-request security validation outcome for an outbound URL."""

    is_valid: bool
    reason: str
    hostname: str = ""
    resolved_ip: str = ""
    severity: str = "SAFE"  # "SAFE", "MEDIUM", "HIGH", "CRITICAL"


@dataclass(frozen=True)
class SafeWebFetchResult:
    """Inspected and sanitized outcome of a secure web gateway fetch."""

    success: bool
    status_code: int
    url: str
    content_type: str = ""
    content_length: int = 0
    sha256: str = ""
    text: str = ""
    prompt_injection_flagged: bool = False
    threat_blocked: bool = False
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "status_code": self.status_code,
            "url": self.url,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "sha256": self.sha256,
            "text": self.text,
            "prompt_injection_flagged": self.prompt_injection_flagged,
            "threat_blocked": self.threat_blocked,
            "error_message": self.error_message,
        }


class _SafeTextExtractingParser(HTMLParser):
    """Linear-time HTML text extractor stripping script, style, and iframe tags."""

    def __init__(self) -> None:
        super().__init__()
        self._pieces: List[str] = []
        self._skip_depth: int = 0
        self._skip_tags = frozenset({"script", "style", "noscript", "svg", "canvas", "iframe"})

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        if tag.lower() in self._skip_tags:
            self._skip_depth += 1
        elif tag.lower() in {"p", "div", "br", "h1", "h2", "h3", "h4", "h5", "h6", "li", "tr"}:
            self._pieces.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in self._skip_tags:
            self._skip_depth = max(0, self._skip_depth - 1)
        elif tag.lower() in {"p", "div", "h1", "h2", "h3", "h4", "h5", "h6", "li", "tr"}:
            self._pieces.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip_depth == 0 and data.strip():
            self._pieces.append(data)

    def get_text(self) -> str:
        raw = "".join(self._pieces)
        lines = [line.strip() for line in raw.splitlines()]
        return "\n".join(line for line in lines if line)


def validate_outbound_url(
    url: str,
    threat_intel: Optional[ThreatIntelEngine] = None,
) -> GatewayValidationResult:
    """
    Validate target URL before any network connection is opened.
    Enforces scheme safety, secret-leak scrubbing, SSRF/private IP blocking,
    and threat intel pre-filtering.
    """
    if not url or not isinstance(url, str):
        return GatewayValidationResult(is_valid=False, reason="Invalid or empty URL provided.", severity="HIGH")

    try:
        parts = urllib.parse.urlsplit(url.strip())
    except Exception as exc:
        return GatewayValidationResult(is_valid=False, reason=f"Failed to parse URL: {exc}", severity="HIGH")

    # 1. Scheme Check (HTTPS enforcement)
    scheme = parts.scheme.lower()
    if scheme != "https":
        if scheme == "http":
            return GatewayValidationResult(
                is_valid=False,
                reason="INSECURE_SCHEME_BLOCKED: Cleartext HTTP is forbidden. Only HTTPS (TLS 1.2+) is allowed.",
                severity="HIGH",
            )
        return GatewayValidationResult(
            is_valid=False,
            reason=f"UNSUPPORTED_SCHEME_BLOCKED: Protocol '{scheme}' is forbidden. Only HTTPS is allowed.",
            severity="CRITICAL",
        )

    hostname = (parts.hostname or "").lower().strip()
    if not hostname:
        return GatewayValidationResult(is_valid=False, reason="URL contains no valid destination hostname.", severity="HIGH")

    # 2. Outbound Secret Leak Scrubber (query parameters & path inspection)
    leak_res = audit_code_secrets(url)
    if leak_res.get("has_secrets"):
        finding = leak_res["findings"][0]
        return GatewayValidationResult(
            is_valid=False,
            reason=f"OUTBOUND_SECRET_LEAK_BLOCKED: URL contains sensitive credential in query/path: {finding.get('description')}",
            hostname=hostname,
            severity="CRITICAL",
        )

    # 3. SSRF & Localhost Shield (Host Literal & Suffix Check)
    if hostname in _BLOCKED_HOST_LITERALS or any(hostname.endswith(sfx) for sfx in _BLOCKED_HOST_SUFFIXES):
        return GatewayValidationResult(
            is_valid=False,
            reason=f"SSRF_ATTEMPT_BLOCKED: Target host '{hostname}' points to local or internal loopback/LAN.",
            hostname=hostname,
            severity="CRITICAL",
        )

    # 4. Raw IP Address Check
    canonical_ip = validate_ip_address(hostname)
    if canonical_ip:
        if not is_public_routable_ip(canonical_ip):
            return GatewayValidationResult(
                is_valid=False,
                reason=f"SSRF_ATTEMPT_BLOCKED: Destination IP '{canonical_ip}' is a private, loopback, or non-routable address.",
                hostname=hostname,
                resolved_ip=canonical_ip,
                severity="CRITICAL",
            )

    # 5. DNS Resolution & Rebinding Check
    resolved_ip = ""
    try:
        addr_info = socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
        if not addr_info:
            return GatewayValidationResult(
                is_valid=False,
                reason=f"DNS_RESOLUTION_FAILED: Host '{hostname}' returned no IP records.",
                hostname=hostname,
                severity="HIGH",
            )
        for entry in addr_info:
            target_ip = entry[4][0]
            if not is_public_routable_ip(target_ip):
                return GatewayValidationResult(
                    is_valid=False,
                    reason=f"SSRF_REBINDING_BLOCKED: Host '{hostname}' resolved to private/non-routable IP '{target_ip}'.",
                    hostname=hostname,
                    resolved_ip=target_ip,
                    severity="CRITICAL",
                )
        resolved_ip = addr_info[0][4][0]
    except socket.gaierror as exc:
        return GatewayValidationResult(
            is_valid=False,
            reason=f"DNS_RESOLUTION_ERROR: Could not resolve '{hostname}': {exc}",
            hostname=hostname,
            severity="MEDIUM",
        )

    # 6. 95,000+ Threat Feed Pre-Check
    if threat_intel:
        match = threat_intel.check_domain(hostname)
        if match:
            return GatewayValidationResult(
                is_valid=False,
                reason=f"THREAT_INTEL_BLOCKED: Domain '{hostname}' matched active threat feed '{match.source_feed}' (rule: {match.matched_rule}).",
                hostname=hostname,
                resolved_ip=resolved_ip,
                severity="HIGH",
            )

    return GatewayValidationResult(
        is_valid=True,
        reason="URL passed all pre-request security gates.",
        hostname=hostname,
        resolved_ip=resolved_ip,
        severity="SAFE",
    )


def safe_fetch_web_content(
    url: str,
    max_bytes: int = MAX_GATEWAY_FETCH_BYTES_DEFAULT,
    timeout: float = DEFAULT_GATEWAY_TIMEOUT_SECONDS,
    threat_intel: Optional[ThreatIntelEngine] = None,
    allow_gateway: bool = True,
) -> SafeWebFetchResult:
    """
    Safely fetch web content through the inspected Secure Web Gateway.
    Executes pre-request validation, streams bounded content under temporary
    guarded egress permit, inspects binary headers for malware/polyglots,
    extracts clean text, neutralizes prompt injections, and wraps in safe tags.
    """
    # Gate 0: User Vault Opt-in Enforcement
    if not allow_gateway:
        return SafeWebFetchResult(
            success=False,
            status_code=403,
            url=url,
            text="",
            prompt_injection_flagged=False,
            threat_blocked=True,
            error_message=(
                "GATEWAY_DISABLED: Secure Web Gateway is currently disabled to maintain 100% "
                "zero-outbound airlock. To allow AI agents to safely read web documentation, "
                "enable 'enable_web_gateway' in SentinelWire Settings & Vault."
            ),
        )

    # Gate 1: Pre-Request Validation (SSRF, Threat Intel, Outbound Leaks)
    v = validate_outbound_url(url, threat_intel=threat_intel)
    if not v.is_valid:
        return SafeWebFetchResult(
            success=False,
            status_code=403,
            url=url,
            text="",
            prompt_injection_flagged=False,
            threat_blocked=True,
            error_message=v.reason,
        )

    # Gate 2: In-Flight Bounded TLS Fetch under guarded permit
    raw_bytes = bytearray()
    content_type = ""
    status_code = 0

    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT_HEADER,
            "Accept": "text/html,application/xhtml+xml,application/json,text/plain,text/markdown;q=0.9,*/*;q=0.1",
        },
    )

    try:
        with permit_inspected_gateway_egress():
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
                status_code = getattr(resp, "status", 200)
                content_type = resp.headers.get("Content-Type", "")

                # Check Content-Length if reported
                cl_header = resp.headers.get("Content-Length")
                if cl_header and cl_header.isdigit() and int(cl_header) > max_bytes:
                    return SafeWebFetchResult(
                        success=False,
                        status_code=status_code,
                        url=url,
                        text="",
                        content_type=content_type,
                        prompt_injection_flagged=False,
                        threat_blocked=True,
                        error_message=f"PAYLOAD_TOO_LARGE: Content-Length ({cl_header} bytes) exceeds limit of {max_bytes} bytes.",
                    )

                # Stream read with size cap
                while len(raw_bytes) < max_bytes:
                    chunk = resp.read(16384)
                    if not chunk or not isinstance(chunk, (bytes, bytearray)):
                        break
                    raw_bytes.extend(chunk)

                if len(raw_bytes) >= max_bytes:
                    try:
                        extra = resp.read(1)
                        if extra:
                            return SafeWebFetchResult(
                                success=False,
                                status_code=status_code,
                                url=url,
                                text="",
                                content_type=content_type,
                                prompt_injection_flagged=False,
                                threat_blocked=True,
                                error_message=f"PAYLOAD_TRUNCATED: Response body exceeded maximum allowed limit ({max_bytes} bytes).",
                            )
                    except Exception:
                        pass
    except urllib.error.HTTPError as http_err:
        return SafeWebFetchResult(
            success=False,
            status_code=http_err.code,
            url=url,
            text="",
            content_type=content_type,
            prompt_injection_flagged=False,
            threat_blocked=False,
            error_message=f"HTTP Error {http_err.code}: {http_err.reason}",
        )
    except urllib.error.URLError as url_err:
        return SafeWebFetchResult(
            success=False,
            status_code=0,
            url=url,
            text="",
            content_type=content_type,
            prompt_injection_flagged=False,
            threat_blocked=False,
            error_message=f"Network Connection Failed: {url_err.reason}",
        )
    except Exception as exc:
        return SafeWebFetchResult(
            success=False,
            status_code=0,
            url=url,
            text="",
            content_type=content_type,
            prompt_injection_flagged=False,
            threat_blocked=False,
            error_message=f"Fetch failed: {exc}",
        )

    # Gate 3: Post-Fetch Binary Malware & Polyglot Inspection
    raw_data = bytes(raw_bytes)
    sha256 = hashlib.sha256(raw_data).hexdigest()

    magic_exe = check_magic_executable(raw_data[:16])
    if magic_exe:
        return SafeWebFetchResult(
            success=False,
            status_code=status_code,
            url=url,
            content_type=content_type,
            content_length=len(raw_data),
            sha256=sha256,
            text="",
            prompt_injection_flagged=False,
            threat_blocked=True,
            error_message=f"MALWARE_PAYLOAD_BLOCKED: Response begins with executable signature '{magic_exe}'.",
        )

    if detect_polyglot_executable(raw_data):
        return SafeWebFetchResult(
            success=False,
            status_code=status_code,
            url=url,
            content_type=content_type,
            content_length=len(raw_data),
            sha256=sha256,
            text="",
            prompt_injection_flagged=False,
            threat_blocked=True,
            error_message="MALWARE_PAYLOAD_BLOCKED: Polyglot executable detected in response payload.",
        )

    # Gate 4: Text Decoding & HTML Stripping
    text = raw_data.decode("utf-8", errors="replace")
    if "html" in content_type.lower() or "<html" in text[:512].lower():
        parser = _SafeTextExtractingParser()
        try:
            parser.feed(text)
            text = parser.get_text()
        except Exception:
            pass  # Fall back to raw text if HTML parsing encounters malformed entities

    # Gate 5: Indirect Prompt-Injection & Steganography Neutralizer
    injection_res = sanitize_prompt_injection(text)
    sanitized_text = injection_res.sanitized_text
    prompt_injection_flagged = injection_res.is_injection_detected

    # Gate 6: Safe Enclosure Spotlight Tags
    safe_wrapped_content = (
        f'<untrusted_web_content url="{url}" sha256="{sha256}" status="{status_code}" '
        f'prompt_injection_flagged="{prompt_injection_flagged}">\n'
        f"{sanitized_text}\n"
        f"</untrusted_web_content>"
    )

    return SafeWebFetchResult(
        success=True,
        status_code=status_code,
        url=url,
        content_type=content_type,
        content_length=len(raw_data),
        sha256=sha256,
        text=safe_wrapped_content,
        prompt_injection_flagged=prompt_injection_flagged,
        threat_blocked=False,
        error_message=None,
    )
