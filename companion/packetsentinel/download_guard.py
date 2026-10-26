"""
AI Download Guard & Malware Inspector for PacketSentinel.

Inspects files and payloads downloaded or processed by AI agents via MCP:
1. Calculates SHA-256 hash for integrity tracking.
2. Checks magic bytes for hidden binary executables (PE/MZ, ELF, Mach-O).
3. Detects polyglot malware (e.g., image files hiding executable headers).
4. Detects dangerous script extensions and encoded execution patterns (IEX, DownloadString).
Zero outbound network calls — pure offline heuristic file inspection.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Set, Tuple

# Executable magic signatures
_PE_MAGIC = b"MZ"
_ELF_MAGIC = b"\x7fELF"
_MACHO_MAGICS = frozenset({b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe"})

# Dangerous file extensions commonly used for initial access
DANGEROUS_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".exe",
        ".dll",
        ".scr",
        ".pif",
        ".vbs",
        ".vbe",
        ".js",
        ".jse",
        ".wsf",
        ".wsh",
        ".hta",
        ".bat",
        ".cmd",
        ".ps1",
        ".psm1",
        ".lnk",
        ".iso",
        ".img",
    }
)

# Heuristic patterns for obfuscated/staged execution in scripts
SUSPICIOUS_SCRIPT_PATTERNS: Tuple[bytes, ...] = (
    b"invoke-expression",
    b"iex(",
    b"downloadstring(",
    b"frombase64string(",
    b"wscript.shell",
    b"cmd.exe /c",
    b"powershell -enc",
    b"powershell -encodedcommand",
    b"bitsadmin /transfer",
    b"certutil -urlcache",
)


@dataclass(frozen=True)
class DownloadScanResult:
    """Security assessment for a downloaded file or payload."""

    is_safe: bool
    risk_level: str  # "SAFE", "SUSPICIOUS", "MALICIOUS"
    reason: str
    sha256: str
    file_size_bytes: int


def compute_file_sha256(data: bytes) -> str:
    """Compute SHA-256 digest in lowercase hexadecimal."""
    return hashlib.sha256(data).hexdigest()


def check_magic_executable(header: bytes) -> Optional[str]:
    """Check if first 4 bytes contain known native executable signatures."""
    if len(header) >= 2 and header[:2] == _PE_MAGIC:
        return "Windows PE Executable (MZ)"
    if len(header) >= 4 and header[:4] == _ELF_MAGIC:
        return "Linux ELF Executable"
    if len(header) >= 4 and header[:4] in _MACHO_MAGICS:
        return "macOS Mach-O Binary"
    return None


def detect_polyglot_executable(data: bytes) -> bool:
    """
    Detect if an apparent non-executable (e.g. image) contains an embedded PE header.
    Adversaries often append PE binaries to valid PNG/JPG headers.
    """
    if len(data) < 1024:
        return False
    # Check for secondary 'MZ' header offset after standard image headers
    mz_pos = data.find(_PE_MAGIC, 64)
    if mz_pos != -1 and len(data) > mz_pos + 64:
        # Check for 'PE\0\0' signature at offset pointed to by e_lfanew
        try:
            lfanew_offset = mz_pos + 0x3C
            if lfanew_offset + 4 <= len(data):
                pe_offset = mz_pos + int.from_bytes(data[lfanew_offset : lfanew_offset + 4], "little")
                if pe_offset + 4 <= len(data) and data[pe_offset : pe_offset + 4] == b"PE\x00\x00":
                    return True
        except Exception:
            pass
    return False


def scan_script_heuristics(data: bytes) -> Optional[str]:
    """Scan script content for encoded command execution or memory stagers."""
    sample = data[:32768].lower()
    for pattern in SUSPICIOUS_SCRIPT_PATTERNS:
        if pattern in sample:
            return f"Matched suspicious script execution pattern: '{pattern.decode('ascii', errors='ignore')}'"
    return None


def scan_downloaded_payload(
    file_bytes: bytes,
    filename: str = "downloaded_file",
) -> DownloadScanResult:
    """
    Perform multi-gate offline security audit on downloaded bytes.
    Returns DownloadScanResult indicating if the file is safe to store/execute.
    """
    size = len(file_bytes)
    sha256_hash = compute_file_sha256(file_bytes)
    ext = Path(filename).suffix.lower()

    if size == 0:
        return DownloadScanResult(
            is_safe=True,
            risk_level="SAFE",
            reason="Empty payload",
            sha256=sha256_hash,
            file_size_bytes=0,
        )

    # Gate 1: Check magic bytes against extension mismatch (e.g. .txt that is actually an .exe)
    magic_type = check_magic_executable(file_bytes[:4])
    if magic_type:
        if ext in {".txt", ".pdf", ".jpg", ".png", ".md", ".json"}:
            return DownloadScanResult(
                is_safe=False,
                risk_level="MALICIOUS",
                reason=f"Deceptive extension: '{ext}' file contains hidden {magic_type} signature",
                sha256=sha256_hash,
                file_size_bytes=size,
            )
        if ext in DANGEROUS_EXTENSIONS:
            return DownloadScanResult(
                is_safe=False,
                risk_level="SUSPICIOUS",
                reason=f"Downloaded binary executable: {magic_type}",
                sha256=sha256_hash,
                file_size_bytes=size,
            )

    # Gate 2: Check for polyglot embedded executables
    if detect_polyglot_executable(file_bytes):
        return DownloadScanResult(
            is_safe=False,
            risk_level="MALICIOUS",
            reason="Polyglot file: embedded hidden PE executable detected inside payload",
            sha256=sha256_hash,
            file_size_bytes=size,
        )

    # Gate 3: Dangerous script extensions and stagers
    if ext in {".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta"}:
        heuristic_reason = scan_script_heuristics(file_bytes)
        if heuristic_reason:
            return DownloadScanResult(
                is_safe=False,
                risk_level="MALICIOUS",
                reason=heuristic_reason,
                sha256=sha256_hash,
                file_size_bytes=size,
            )

    return DownloadScanResult(
        is_safe=True,
        risk_level="SAFE",
        reason="No known executable signatures or suspicious execution patterns detected",
        sha256=sha256_hash,
        file_size_bytes=size,
    )


def scan_file_on_disk(file_path: Path) -> DownloadScanResult:
    """Read file safely and run scan_downloaded_payload."""
    try:
        resolved = file_path.resolve()
        if not resolved.is_file():
            return DownloadScanResult(
                is_safe=False,
                risk_level="SUSPICIOUS",
                reason="Target path is not a regular file",
                sha256="",
                file_size_bytes=0,
            )
        # Cap read at 50 MB to prevent memory exhaustion
        data = resolved.read_bytes()[: 50 * 1024 * 1024]
        return scan_downloaded_payload(data, filename=resolved.name)
    except Exception as exc:
        return DownloadScanResult(
            is_safe=False,
            risk_level="SUSPICIOUS",
            reason=f"Failed to read file: {exc}",
            sha256="",
            file_size_bytes=0,
        )
