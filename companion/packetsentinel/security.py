"""
Core security utilities enforcing the OWASP Top 50 steering requirements:
- Input sanitization (ANSI escape & control char stripping, XML/Toast escaping)
- Linear-time RFC 1035/1123 domain validation & IDNA/Punycode canonicalization (no ReDoS)
- IPv4/IPv6 validation & public routability verification
- SSRF-safe HTTPS threat-feed downloader with TLS 1.2+, redirect verification, and byte caps
- Atomic file writes (TOCTOU mitigation) & SHA-256 integrity hashing
- Bounds-checked raw DNS & TLS ClientHello SNI wire parsers (anti-compression-loop protection)
"""

from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import os
import socket
import ssl
import struct
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Optional, Set


MAX_DOMAIN_LENGTH = 253
MAX_LABEL_LENGTH = 63
MAX_FEED_BYTES_DEFAULT = 25 * 1024 * 1024  # 25 MB hard ceiling per feed
MAX_DNS_POINTER_JUMPS = 10

ALLOWED_LABEL_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-_")


def sanitize_display_text(value: Any, max_len: int = 253) -> str:
    """
    Strip ASCII control characters (0x00-0x1F, 0x7F-0x9F) and ANSI escape sequences
    from untrusted wire or feed strings to prevent terminal/log injection (OWASP #9, #14, #20).
    Linear O(N) scan with zero regex backtracking.
    """
    if value is None:
        return ""
    raw = str(value)
    out_chars: list[str] = []
    i = 0
    n = len(raw)
    while i < n and len(out_chars) < max_len:
        ch = raw[i]
        code = ord(ch)
        # Strip ANSI CSI (ESC [ ... <0x40-0x7E>) and OSC (ESC ] ... BEL / ESC \) sequences (CWE-150)
        if code == 0x1B:
            i += 1
            if i < n and raw[i] == "[":
                i += 1
                while i < n and not (0x40 <= ord(raw[i]) <= 0x7E):
                    i += 1
                if i < n:
                    i += 1
            elif i < n and raw[i] == "]":
                i += 1
                while i < n:
                    if ord(raw[i]) == 0x07:
                        i += 1
                        break
                    if ord(raw[i]) == 0x1B and (i + 1) < n and raw[i + 1] == "\\":
                        i += 2
                        break
                    i += 1
            continue
        # Skip control characters (C0 and C1 control blocks + DEL)
        if code <= 0x1F or (0x7F <= code <= 0x9F):
            i += 1
            continue
        out_chars.append(ch)
        i += 1
    return "".join(out_chars).strip()


def sanitize_for_notification(value: Any, max_len: int = 180) -> str:
    """
    Sanitize text for safe display in Windows Toast Notifications / GUI dialogs (OWASP #15).
    """
    cleaned = sanitize_display_text(value, max_len=max_len)
    return html.escape(cleaned, quote=True)


def normalize_and_validate_domain(raw_domain: str, allow_underscore: bool = False) -> Optional[str]:
    """
    Canonicalize and validate a domain name in linear O(N) time (no ReDoS, OWASP #11, #19, #36).
    - Strips leading/trailing whitespace and trailing dots
    - Converts Unicode IDNs to ASCII Punycode (idna)
    - Enforces RFC 1035/1123 length and character rules
    Returns lowercase canonical domain or None if invalid.
    """
    if not raw_domain or not isinstance(raw_domain, str):
        return None

    candidate = sanitize_display_text(raw_domain, max_len=300).strip().rstrip(".").lower()
    if not candidate or len(candidate) > MAX_DOMAIN_LENGTH:
        return None

    # Convert non-ASCII internationalized domain names to ASCII Punycode safely
    if not candidate.isascii():
        try:
            candidate = candidate.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return None

    if len(candidate) > MAX_DOMAIN_LENGTH or "." not in candidate:
        return None

    # Reject if it is actually a literal IPv4 or IPv6 address
    try:
        ipaddress.ip_address(candidate)
        return None
    except ValueError:
        pass

    labels = candidate.split(".")
    if len(labels) < 2:
        return None

    tld = labels[-1]
    if len(tld) < 2 or tld.isdigit():
        return None

    for label in labels:
        if not (1 <= len(label) <= MAX_LABEL_LENGTH):
            return None
        if label.startswith("-") or label.endswith("-"):
            return None
        for ch in label:
            if ch == "_" and not allow_underscore:
                return None
            if ch not in ALLOWED_LABEL_CHARS:
                return None

    return candidate


def validate_ip_address(raw_ip: str) -> Optional[str]:
    """
    Validate and canonicalize an IPv4 or IPv6 address string.
    Returns canonical IP string or None if invalid.
    """
    if not raw_ip or not isinstance(raw_ip, str):
        return None
    cleaned = sanitize_display_text(raw_ip, max_len=64).strip()
    # Strip IPv6 zone index if present (e.g., fe80::1%eth0)
    if "%" in cleaned:
        cleaned = cleaned.split("%", 1)[0]
    try:
        ip_obj = ipaddress.ip_address(cleaned)
        return str(ip_obj)
    except ValueError:
        return None


def is_public_routable_ip(raw_ip: str) -> bool:
    """
    Return True only if raw_ip is a globally routable public IPv4/IPv6 address.
    Rejects loopback (127.0.0.0/8, ::1), RFC1918 private, link-local (169.254.0.0/16),
    multicast, unspecified, and reserved addresses (OWASP #10 SSRF mitigation).
    """
    canonical = validate_ip_address(raw_ip)
    if not canonical:
        return False
    ip_obj = ipaddress.ip_address(canonical)
    return bool(
        ip_obj.is_global
        and not ip_obj.is_loopback
        and not ip_obj.is_private
        and not ip_obj.is_link_local
        and not ip_obj.is_multicast
        and not ip_obj.is_reserved
        and not ip_obj.is_unspecified
    )


def verify_host_resolves_to_public_ip(hostname: str) -> None:
    """
    Resolve a hostname and ensure every returned A/AAAA record is a public routable IP.
    Raises ValueError if resolution fails or points to any private/loopback/metadata IP.
    """
    try:
        addr_info = socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError(f"Unable to resolve threat feed host {hostname!r}: {exc}") from exc

    if not addr_info:
        raise ValueError(f"Host {hostname!r} returned no DNS records")

    for entry in addr_info:
        sockaddr = entry[4]
        resolved_ip = sockaddr[0]
        if not is_public_routable_ip(resolved_ip):
            raise ValueError(
                f"SSRF protection blocked host {hostname!r} resolving to non-public IP {resolved_ip!r}"
            )


def validate_https_feed_url(url: str, allowed_hosts: Optional[Set[str]] = None) -> str:
    """
    Validate that a threat feed URL strictly uses HTTPS, has no embedded credentials,
    passes hostname validation, matches allowed_hosts (if enforced), and resolves only
    to public routable IP addresses (OWASP #2, #10, #39).
    """
    if not url or not isinstance(url, str):
        raise ValueError("Feed URL must be a non-empty string")

    cleaned_url = url.strip()
    parsed = urllib.parse.urlsplit(cleaned_url)

    if parsed.scheme.lower() != "https":
        raise ValueError(f"Insecure URL scheme {parsed.scheme!r} blocked; only 'https' is permitted")

    if parsed.username or parsed.password:
        raise ValueError("Embedded credentials in feed URLs are not permitted")

    hostname = (parsed.hostname or "").lower().rstrip(".")
    normalized_host = normalize_and_validate_domain(hostname)
    if not normalized_host:
        raise ValueError(f"Invalid or literal-IP feed hostname: {hostname!r}")

    if allowed_hosts is not None and normalized_host not in allowed_hosts:
        raise ValueError(f"Host {normalized_host!r} is not in the trusted threat-feed host allowlist")

    verify_host_resolves_to_public_ip(normalized_host)
    return cleaned_url


class _SafeHTTPSRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    Validates every HTTP redirect target against SSRF and HTTPS-downgrade policies (OWASP #39).
    """

    def __init__(self, allowed_hosts: Optional[Set[str]] = None) -> None:
        super().__init__()
        self._allowed_hosts = allowed_hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        resolved_url = urllib.parse.urljoin(req.full_url, newurl)
        validate_https_feed_url(resolved_url, allowed_hosts=self._allowed_hosts)
        return super().redirect_request(req, fp, code, msg, headers, resolved_url)


def create_strict_ssl_context() -> ssl.SSLContext:
    """
    Create a hardened TLS 1.2+ SSLContext with mandatory certificate & hostname verification.
    """
    ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def fetch_https_stream_safely(
    url: str,
    max_bytes: int = MAX_FEED_BYTES_DEFAULT,
    timeout: float = 15.0,
    allowed_hosts: Optional[Set[str]] = None,
) -> str:
    """
    Download an HTTPS threat intelligence feed with:
    - SSRF validation on initial URL and any redirects
    - Strict TLS 1.2+ certificate verification
    - Hard byte limit (max_bytes) to prevent memory exhaustion DoS (OWASP #12)
    """
    validated_url = validate_https_feed_url(url, allowed_hosts=allowed_hosts)
    ssl_ctx = create_strict_ssl_context()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl_ctx),
        _SafeHTTPSRedirectHandler(allowed_hosts=allowed_hosts),
    )

    request = urllib.request.Request(
        validated_url,
        headers={
            "User-Agent": "PacketSentinel/0.1 (+https://github.com/packetsentinel; security-threat-monitor)",
            "Accept": "text/plain, */*;q=0.1",
            "Accept-Encoding": "identity",
        },
        method="GET",
    )

    chunks: list[bytes] = []
    total_read = 0
    chunk_size = 64 * 1024

    with opener.open(request, timeout=timeout) as response:
        content_len_hdr = response.headers.get("Content-Length")
        if content_len_hdr and content_len_hdr.isdigit():
            if int(content_len_hdr) > max_bytes:
                raise ValueError(
                    f"Feed {validated_url} Content-Length ({content_len_hdr} bytes) exceeds limit ({max_bytes})"
                )

        while True:
            buf = response.read(chunk_size)
            if not buf:
                break
            total_read += len(buf)
            if total_read > max_bytes:
                raise ValueError(
                    f"Feed {validated_url} exceeded maximum allowed download size ({max_bytes} bytes)"
                )
            chunks.append(buf)

    raw_bytes = b"".join(chunks)
    decoded = raw_bytes.decode("utf-8", errors="replace")
    return decoded.replace("\r\n", "\n").replace("\r", "\n")


def compute_sha256(content: str | bytes) -> str:
    """Return hex SHA-256 digest of string or bytes."""
    data = content.encode("utf-8") if isinstance(content, str) else content
    return hashlib.sha256(data).hexdigest()


def atomic_write_text(target_path: Path, content: str) -> None:
    """
    Write text to target_path atomically via a temp file in the same directory
    followed by os.replace() to prevent TOCTOU and corrupted cache files (OWASP #24, #26).
    """
    target_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(target_path.parent),
        prefix=f".{target_path.name}.",
        suffix=".tmp",
        text=True,
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(str(tmp_path), str(target_path))
    except Exception:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass
        raise


def atomic_write_json(target_path: Path, payload: Any) -> None:
    """Serialize payload as formatted JSON and write atomically."""
    serialized = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True)
    atomic_write_text(target_path, serialized + "\n")


def parse_dns_query_safe(dns_payload: bytes) -> Optional[str]:
    """
    Bounds-checked raw DNS packet parser that extracts the first Question QNAME.
    Mitigates OWASP #16 (Integer Overflow / Out-of-Bounds Slice) and
    OWASP #17 (DNS Compression Pointer Infinite Loops).
    """
    if not isinstance(dns_payload, (bytes, bytearray)) or len(dns_payload) < 17:
        return None

    qdcount = struct.unpack("!H", dns_payload[4:6])[0]
    if qdcount < 1 or qdcount > 64:
        return None

    offset = 12
    n = len(dns_payload)
    labels: list[str] = []
    jumps = 0
    total_chars = 0

    while offset < n:
        length = dns_payload[offset]
        if length == 0:
            break

        # Check for DNS compression pointer (top 2 bits 11 -> 0xC0)
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= n:
                return None
            pointer = ((length & 0x3F) << 8) | dns_payload[offset + 1]
            # Compression pointers must strictly jump backward to valid payload >= 12
            if pointer < 12 or pointer >= offset:
                return None
            jumps += 1
            if jumps > MAX_DNS_POINTER_JUMPS:
                return None
            offset = pointer
            continue

        # Standard label (top 2 bits must be 00, length 1..63)
        if (length & 0xC0) != 0 or length > MAX_LABEL_LENGTH:
            return None

        offset += 1
        if offset + length > n:
            return None

        total_chars += length + 1
        if total_chars > MAX_DOMAIN_LENGTH + 2:
            return None

        try:
            label_str = dns_payload[offset : offset + length].decode("ascii")
        except UnicodeDecodeError:
            return None

        labels.append(label_str)
        offset += length

    if not labels:
        return None

    candidate = ".".join(labels)
    return normalize_and_validate_domain(candidate, allow_underscore=True)


def parse_tls_sni_safe(tcp_payload: bytes) -> Optional[str]:
    """
    Bounds-checked parser for TLS ClientHello packets to extract the Server Name Indication (SNI)
    hostname in plaintext without external C dissectors (OWASP #16, #34).
    """
    if not isinstance(tcp_payload, (bytes, bytearray)) or len(tcp_payload) < 43:
        return None

    n = len(tcp_payload)
    # TLS Record Header: ContentType 0x16 (Handshake), Version 0x0301..0x0304, Length (2 bytes)
    if tcp_payload[0] != 0x16 or tcp_payload[1] != 0x03:
        return None

    record_len = struct.unpack("!H", tcp_payload[3:5])[0]
    end_of_record = min(n, 5 + record_len)
    if end_of_record < 43:
        return None

    # Handshake Header: HandshakeType 0x01 (ClientHello)
    if tcp_payload[5] != 0x01:
        return None

    hs_len = (tcp_payload[6] << 16) | (tcp_payload[7] << 8) | tcp_payload[8]
    if 9 + hs_len > end_of_record:
        return None

    # Skip ClientVersion (2) + Random (32) -> offset 43
    offset = 43
    if offset >= end_of_record:
        return None

    # Session ID
    session_id_len = tcp_payload[offset]
    offset += 1 + session_id_len
    if offset + 2 > end_of_record:
        return None

    # Cipher Suites
    cipher_suites_len = struct.unpack("!H", tcp_payload[offset : offset + 2])[0]
    offset += 2 + cipher_suites_len
    if offset + 1 > end_of_record:
        return None

    # Compression Methods
    comp_methods_len = tcp_payload[offset]
    offset += 1 + comp_methods_len
    if offset + 2 > end_of_record:
        return None

    # Extensions length
    extensions_len = struct.unpack("!H", tcp_payload[offset : offset + 2])[0]
    offset += 2
    ext_end = min(end_of_record, offset + extensions_len)

    while offset + 4 <= ext_end:
        ext_type, ext_len = struct.unpack("!HH", tcp_payload[offset : offset + 4])
        offset += 4
        if offset + ext_len > ext_end:
            return None

        # Extension Type 0x0000 is server_name (SNI)
        if ext_type == 0x0000 and ext_len >= 5:
            sni_list_len = struct.unpack("!H", tcp_payload[offset : offset + 2])[0]
            sni_pos = offset + 2
            sni_end = min(offset + ext_len, sni_pos + sni_list_len)
            while sni_pos + 3 <= sni_end:
                name_type = tcp_payload[sni_pos]
                name_len = struct.unpack("!H", tcp_payload[sni_pos + 1 : sni_pos + 3])[0]
                sni_pos += 3
                if sni_pos + name_len > sni_end:
                    return None
                if name_type == 0x00:  # host_name
                    try:
                        raw_host = tcp_payload[sni_pos : sni_pos + name_len].decode("ascii")
                    except UnicodeDecodeError:
                        return None
                    return normalize_and_validate_domain(raw_host)
                sni_pos += name_len

        offset += ext_len

    return None
