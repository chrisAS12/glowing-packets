"""
Pre-Model Privacy & Data Loss Prevention (DLP) Airlock for PacketSentinel MCP.

Sanitizes text, security alerts, and workspace files inside Python BEFORE any data
is returned over MCP JSON-RPC to an AI model's context window.

Enforces 5 independent privacy gates:
1. File Type, Path Denylist & Magic-Byte Blocker (blocks images, PDFs, Office docs,
   databases, archives, certificates, and `.env`/`.secrets` files).
2. Banking & Financial Identifier Redactor (Luhn-validated payment cards, ISO-7064
   Mod-97 IBANs, SWIFT/BICs, SSNs, and crypto private keys).
3. Personal Identity & Host Scrubber (OS usernames, hostnames, user profile paths,
   labeled personal names, emails, phone numbers, MACs, and private LAN IPs).
4. Secrets & Token Scrubber (PEM private keys, GitHub/AWS/OpenAI/Anthropic/Slack keys,
   JWTs, Bearer tokens, and secret assignments).
5. Strict ECS Security Alert Allowlist + Indirect Prompt-Injection Spotlighting
   (`<untrusted_network_data>` tags + boolean risk flags instead of raw CLI args).
"""

from __future__ import annotations

import getpass
import ipaddress
import os
import platform
import re
import socket
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .security import sanitize_display_text


BLOCKED_FILE_EXTENSIONS: frozenset[str] = frozenset(
    {
        # Images & vector/raster graphics
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".bmp",
        ".ico",
        ".svg",
        ".tiff",
        ".tif",
        ".heic",
        ".heif",
        ".avif",
        ".psd",
        ".ai",
        ".eps",
        ".raw",
        ".cr2",
        ".nef",
        # Audio & video media
        ".mp3",
        ".wav",
        ".ogg",
        ".flac",
        ".m4a",
        ".mp4",
        ".mkv",
        ".avi",
        ".mov",
        ".webm",
        ".wmv",
        # Office documents & PDFs (common carriers of bank statements, tax forms, IDs)
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".xlsm",
        ".ppt",
        ".pptx",
        ".odt",
        ".ods",
        ".odp",
        ".rtf",
        ".pages",
        ".numbers",
        # Databases, password vaults, & wallets
        ".sqlite",
        ".sqlite3",
        ".db",
        ".db3",
        ".mdb",
        ".accdb",
        ".kdbx",
        ".kdb",
        ".agilekeychain",
        ".opvault",
        ".wallet",
        ".dat",
        # Cryptographic keys & certificates
        ".pem",
        ".key",
        ".pfx",
        ".p12",
        ".crt",
        ".cer",
        ".der",
        ".jks",
        ".keystore",
        ".csr",
        ".gpg",
        ".pgp",
        ".asc",
        # Executables, libraries, & archives
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".sys",
        ".bin",
        ".pkl",
        ".pickle",
        ".pyc",
        ".pyo",
        ".whl",
        ".zip",
        ".tar",
        ".gz",
        ".tgz",
        ".bz2",
        ".xz",
        ".7z",
        ".rar",
        ".iso",
        ".dmg",
    }
)

BLOCKED_PATH_SEGMENTS: frozenset[str] = frozenset(
    {
        ".secrets",
        ".ssh",
        ".aws",
        ".gnupg",
        ".kube",
        ".docker",
        ".azure",
        ".gcloud",
        ".config/gcloud",
        ".config/gh",
        ".git",
        ".mozilla",
        ".thunderbird",
        "google/chrome/user data",
        "bravesoftware/brave-browser/user data",
        "microsoft/edge/user data",
        "psreadline",
    }
)

BLOCKED_EXACT_FILENAMES: frozenset[str] = frozenset(
    {
        ".env",
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".git-credentials",
        ".bash_history",
        ".zsh_history",
        "consolehost_history.txt",
        "hosts.yml",
        "gh-hosts.yml",
        "cookies.sqlite",
        "login data",
        "web data",
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        "id_dsa",
        "known_hosts",
        "authorized_keys",
        "mcp_config.json",
        "sidecar.json",
        "credentials.json",
        "client_secret.json",
        "secrets.json",
        "secrets.yaml",
        "secrets.yml",
        "secrets.toml",
    }
)

ALLOWED_ENV_TEMPLATE_NAMES: frozenset[str] = frozenset(
    {
        ".env.example",
        ".env.template",
        ".env.sample",
    }
)

# Binary/image/document magic headers checked against the first 64 bytes so renamed files
# (e.g. bank_statement.pdf renamed to notes.txt) are still blocked before reaching the LLM.
BINARY_MAGIC_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"BM", "BMP image"),
    (b"\x00\x00\x01\x00", "ICO image"),
    (b"%PDF-", "PDF document"),
    (b"PK\x03\x04", "ZIP/Office archive"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 Office document"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"\x1f\x8b\x08", "GZIP archive"),
    (b"\x7fELF", "ELF binary"),
    (b"MZ", "PE/DOS executable"),
    (b"\xfe\xed\xfa\xce", "Mach-O binary"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit binary"),
    (b"\xcf\xfa\xed\xfe", "Mach-O binary (le)"),
)

_INLINE_IMAGE_DATA_URI_RE = re.compile(
    r"data\s*:\s*(?:image|audio|video|application/pdf|application/octet-stream)[^;,\s]*;base64,[A-Za-z0-9+/=\s]{16,}",
    re.IGNORECASE,
)
_SVG_OPEN_TAG = "<svg"
_SVG_CLOSE_TAG = "</svg"

# Bounded so many unterminated BEGIN headers cannot force quadratic backtracking (CWE-1333).
_PEM_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 _-]{0,40}PRIVATE KEY-----.{0,16384}?-----END [A-Z0-9 _-]{0,40}PRIVATE KEY-----",
    re.DOTALL,
)
_GITHUB_TOKEN_RE = re.compile(
    r"\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|gho_[A-Za-z0-9]{20,}|ghu_[A-Za-z0-9]{20,}|ghs_[A-Za-z0-9]{20,}|ghr_[A-Za-z0-9]{20,})\b"
)
_API_KEY_RE = re.compile(
    r"\b(?:"
    r"sk-(?:proj-|ant-|live_|test_)?[A-Za-z0-9_-]{20,}"
    r"|rk_(?:live|test)_[A-Za-z0-9]{20,}"
    r"|AIza[0-9A-Za-z_-]{35}"
    r"|AKIA[0-9A-Z]{16}"
    r"|ASIA[0-9A-Z]{16}"
    r"|xox[baprs]-[0-9A-Za-z-]{18,}"
    r"|npm_[A-Za-z0-9]{30,}"
    r"|pypi-[A-Za-z0-9_-]{32,}"
    r")\b"
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_BEARER_HEADER_RE = re.compile(
    r"(?i)\b(Authorization\s*[:=]\s*(?:Bearer|Basic|Token)\s+)([A-Za-z0-9._~+/=-]{8,})"
)
_URL_EMBEDDED_CRED_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@]+:)([^@\s/]+)(@)")
_SECRET_ASSIGNMENT_RE = re.compile(
    r"""(?i)\b([a-z0-9_]*(?:password|passwd|pwd|secret|api_key|apikey|access_token|auth_token|private_key|client_secret|pat_token)[a-z0-9_]*['"]?)\s*([:=])\s*(['"]?)([^\s'",;}{]{6,})\3"""
)

# Candidate 13-19 digit payment card sequence (validated via Luhn checksum before replacement).
_CARD_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")

# Candidate ISO 13616 IBAN (2-letter country code + 2 check digits + 11 to 30 alphanumeric characters).
_IBAN_CANDIDATE_RE = re.compile(
    r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b"
)

_LABELED_FINANCIAL_RE = re.compile(
    r"""(?i)\b(iban|swift|bic|routing[ _-]?number|sort[ _-]?code|account[ _-]?number|bank[ _-]?account|card[ _-]?number|pan|cvv|cvc|tax[ _-]?id|national[ _-]?id)(['"]?\s*[:=#]\s*['"]?)([A-Z0-9 -]{3,34})"""
)
_US_SSN_RE = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
_NATIONAL_ID_CODE_RE = re.compile(
    r"\b(?:"
    r"[A-CEGHJ-PR-TW-Z]{2}[0-9]{6}[A-D]"  # UK NINO
    r"|[123478][0-9]{2}(?:0[1-9]|1[0-2])(?:[0-9]{2}|2[AB])[0-9]{6}[0-9]{2}"  # French NIR
    r"|(?:[XYZ]?[0-9]{7,8}[A-Z])"  # Spanish DNI/NIE
    r"|[A-Z]{6}[0-9]{2}[A-EHLMPR-TVZ][0-9]{2}[A-Z][0-9]{3}[A-Z]"  # Italian Codice Fiscale
    r"|[0-9]{2}(?:0[1-9]|1[0-2]|2[1-2]|3[1-2]|4[1-2]|5[1-2]|6[1-2]|7[1-2]|8[1-2]|9[1-2])(?:0[1-9]|[1-2][0-9]|3[0-1])[0-9]{5}"  # Polish PESEL
    r"|[0-9]{6}[-+A][0-9]{3}[0-9A-Z]"  # Finnish/Nordic Personal Identity Code
    r"|[0-9]{6}-[0-9]{5}"  # Baltic Personal Code
    r")\b"
)
_LABELED_PERSONAL_CODE_RE = re.compile(
    r"""(?i)\b(personal[ _-]?code|id[ _-]?code|identity[ _-]?code|citizen[ _-]?code|national[ _-]?id|tax[ _-]?code|tin|pesel|henkilötunnus|isikukood|asmens[ _-]?kodas|pin[ _-]?code|security[ _-]?code|verification[ _-]?code|backup[ _-]?code)(['"]?\s*[:=#]\s*['"]?)([A-Za-z0-9_-]{4,24})"""
)
_STANDALONE_PIN_OTP_RE = re.compile(
    r"""(?i)\b(pin|otp|passcode)\s*[:=]\s*(\d{4,8})\b"""
)
_CRYPTO_HEX_KEY_RE = re.compile(
    r"(?i)\b(?:0x[a-f0-9]{64}|(?:btc|eth|sol|wallet|private_key)\s*[:=]\s*['\"]?[A-Za-z0-9]{26,66}['\"]?)\b"
)

_WIN_USER_PATH_RE = re.compile(r"(?i)\b[A-Z]:\\Users\\([^\\/\s\"'<>|]+)")
_MAC_USER_PATH_RE = re.compile(r"(?<![A-Za-z0-9_])/Users/([^/\s\"'<>|]+)")
_LINUX_USER_PATH_RE = re.compile(r"(?<![A-Za-z0-9_])/home/([^/\s\"'<>|]+)")

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b")
_PHONE_RE = re.compile(
    r"(?<![\d.])(?:\+\d{1,3}[\s-]?|\(\d{2,4}\)[\s-]?)\d{3,4}[\s-]\d{3,4}(?![\d.])"
    r"|(?<![\d.])\b\d{3}-\d{3}-\d{4}\b(?![\d.])"
)
_MAC_ADDR_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
_IPV4_CANDIDATE_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_LABELED_PERSONAL_NAME_RE = re.compile(
    r"""(?i)\b(full_name|first_name|last_name|real_name|person_name|customer_name|cardholder_name|cardholder|account_holder|owner_name|patient_name|employee_name|user_full_name|author)(['"]?\s*[:=]\s*['"])([^'"\r\n]{2,80})(['"])"""
)
_HONORIFIC_NAME_RE = re.compile(
    r"\b(?:Mr|Mrs|Ms|Miss|Dr|Prof)\.?\s+[A-Z][a-z]{1,25}(?:\s+[A-Z][a-z]{1,25}){0,2}\b"
)
_GIT_AUTHOR_HEADER_RE = re.compile(r"(?m)^((?:Author|Commit|From):\s*)([^<\r\n]+)(<[^\r\n>]+>)?")

_ENCODED_CMDLINE_RE = re.compile(
    r"(?i)(?:\s-(?:e|en|enc|encodedcommand)\s|frombase64string|invoke-expression|\biex\b|downloadstring)"
)
_SUSPICIOUS_PARENT_RE = re.compile(
    r"(?i)\b(?:winword|excel|powerpnt|outlook|acrord32|mshta|wscript|cscript|rundll32|regsvr32)(?:\.exe)?\b"
)
_USER_WRITABLE_EXEC_RE = re.compile(
    r"(?i)(?:\\appdata\\|\\temp\\|\\downloads\\|/tmp/|/var/tmp/|/downloads/)"
)


def strip_inline_svg_blocks(text: str) -> str:
    # Linear str.find scan instead of a lazy DOTALL regex, which degrades to O(n^2)
    # on input containing many unterminated "<svg" tags.
    lowered = text.lower()
    pieces: List[str] = []
    cursor = 0
    while True:
        start = lowered.find(_SVG_OPEN_TAG, cursor)
        if start == -1:
            break
        close = lowered.find(_SVG_CLOSE_TAG, start)
        if close == -1:
            break
        end = lowered.find(">", close)
        end = len(text) if end == -1 else end + 1
        pieces.append(text[cursor:start])
        pieces.append("[REDACTED_INLINE_SVG_IMAGE]")
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


def is_valid_luhn(digits_only: str) -> bool:
    if not digits_only.isdigit() or not (13 <= len(digits_only) <= 19):
        return False
    if len(set(digits_only)) == 1:
        return False
    total = 0
    reverse_digits = digits_only[::-1]
    for idx, ch in enumerate(reverse_digits):
        n = ord(ch) - 48
        if idx % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return (total % 10) == 0


def is_valid_iban(raw_iban: str) -> bool:
    compact = raw_iban.replace(" ", "").upper()
    if len(compact) < 15 or len(compact) > 34:
        return False
    if not compact[:2].isalpha() or not compact[2:4].isdigit() or not compact.isalnum():
        return False
    rearranged = compact[4:] + compact[:4]
    numeric_parts: List[str] = []
    for ch in rearranged:
        if ch.isdigit():
            numeric_parts.append(ch)
        else:
            numeric_parts.append(str(ord(ch) - 55))
    try:
        return (int("".join(numeric_parts)) % 97) == 1
    except ValueError:
        return False


WINDOWS_RESERVED_DEVICE_NAMES: frozenset[str] = frozenset(
    {
        "con",
        "prn",
        "aux",
        "nul",
        "com1",
        "com2",
        "com3",
        "com4",
        "com5",
        "com6",
        "com7",
        "com8",
        "com9",
        "lpt1",
        "lpt2",
        "lpt3",
        "lpt4",
        "lpt5",
        "lpt6",
        "lpt7",
        "lpt8",
        "lpt9",
    }
)


def is_blocked_file_path(path: Path) -> Tuple[bool, str]:
    raw_str = str(path)
    if ":" in raw_str:
        return True, "NTFS Alternate Data Streams (ADS) and drive-prefixed paths are blocked (MITRE T1564.004)."

    name_lower = path.name.lower()
    stem_lower = name_lower.split(".", 1)[0]
    if stem_lower in WINDOWS_RESERVED_DEVICE_NAMES:
        return True, f"Windows reserved DOS device name '{path.name}' is blocked (CWE-400)."

    if name_lower in ALLOWED_ENV_TEMPLATE_NAMES:
        return False, ""
    if name_lower in BLOCKED_EXACT_FILENAMES or name_lower.startswith(".env."):
        return True, f"Sensitive credential/configuration file '{path.name}' is blocked from AI access."

    normalized_parts = [p.lower() for p in path.parts]
    for seg in BLOCKED_PATH_SEGMENTS:
        if "/" in seg:
            seg_parts = seg.split("/")
            for idx in range(len(normalized_parts) - len(seg_parts) + 1):
                if normalized_parts[idx : idx + len(seg_parts)] == seg_parts:
                    return True, f"Protected directory '{seg}' is blocked from AI access."
        elif seg in normalized_parts:
            return True, f"Protected directory '{seg}' is blocked from AI access."

    for suffix in path.suffixes:
        ext = suffix.lower()
        if ext in BLOCKED_FILE_EXTENSIONS:
            return True, f"File extension '{ext}' (image/binary/document/vault) is blocked from AI access."

    return False, ""


def detect_blocked_magic_bytes(header: bytes) -> Optional[str]:
    if not header:
        return None
    for magic, label in BINARY_MAGIC_SIGNATURES:
        if header.startswith(magic):
            return label
    if header.startswith(b"RIFF") and len(header) >= 12 and header[8:12] == b"WEBP":
        return "WebP image"
    head_text = header[:256].decode("utf-8", errors="ignore").lstrip().lower()
    if head_text.startswith("<svg") or ("<!doctype svg" in head_text):
        return "SVG image"
    if b"\x00" in header:
        return "Binary file containing null bytes"
    return None


@dataclass(frozen=True)
class SanitizedAlertSummary:
    timestamp_utc: str
    alert_source: str
    severity: str
    rule_name: str
    match_type: str
    process_name: str
    protocol: str
    dst_port: int
    indicator_spotlighted: str
    risk_flags: Dict[str, bool]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Gate 6: Indirect Prompt-Injection & Steganography Detection
_ZERO_WIDTH_STEGANOGRAPHY_RE = re.compile(
    r"[\u200B-\u200D\u200E\u200F\u202A-\u202E\u2060-\u2064\uFEFF]"
)

_PROMPT_INJECTION_OVERRIDE_RE = re.compile(
    r"(?i)\b(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions"
    r"|disregard\s+(?:all\s+)?(?:previous|prior)\s+(?:rules|guidelines|directives)"
    r"|system\s+prompt\s+override"
    r"|new\s+system\s+directive\s*:"
    r"|you\s+are\s+now\s+(?:in\s+developer\s+mode|unrestricted|DAN)"
    r"|bypass\s+(?:content|safety)\s+filters"
    r")\b"
)

_CHAT_FRAME_OVERRIDE_RE = re.compile(
    r"(?:\[/?(?:INST|SYS)\]|<\|im_start\|>|<\|im_end\|>|<!--\s*(?:system|instruction|prompt)\s*:.*?-->)"
)


@dataclass(frozen=True)
class PromptInjectionScanResult:
    """Represents Gate 6 prompt injection analysis result."""

    is_injection_detected: bool
    sanitized_text: str
    reasons: List[str]
    has_zero_width_steganography: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def sanitize_prompt_injection(text: str) -> PromptInjectionScanResult:
    """
    Gate 6: Scan and sanitize indirect prompt injection, zero-width steganography,
    and chat template framing overrides from text.
    """
    if not text or not isinstance(text, str):
        return PromptInjectionScanResult(
            is_injection_detected=False,
            sanitized_text="",
            reasons=[],
            has_zero_width_steganography=False,
        )

    reasons: List[str] = []
    has_bidi = bool(_ZERO_WIDTH_STEGANOGRAPHY_RE.search(text))
    if has_bidi:
        reasons.append("Hidden zero-width steganography / Unicode override characters detected and stripped.")

    # 1. Strip zero-width and bidi override characters (invisible payload carriers)
    cleaned = _ZERO_WIDTH_STEGANOGRAPHY_RE.sub("", text)

    # 2. Check for direct prompt override directives
    matches = _PROMPT_INJECTION_OVERRIDE_RE.findall(cleaned)
    if matches:
        reasons.append(f"Prompt injection directive detected: {', '.join(matches[:3])}")
        cleaned = _PROMPT_INJECTION_OVERRIDE_RE.sub("[NEUTRALIZED_PROMPT_INJECTION_ATTEMPT]", cleaned)

    # 3. Check for chat template frame hijacking
    frame_matches = _CHAT_FRAME_OVERRIDE_RE.findall(cleaned)
    if frame_matches:
        reasons.append("Deceptive chat template framing / system tag smuggling detected.")
        cleaned = _CHAT_FRAME_OVERRIDE_RE.sub("[NEUTRALIZED_CHAT_FRAME_OVERRIDE]", cleaned)

    is_threat = len(reasons) > 0
    return PromptInjectionScanResult(
        is_injection_detected=is_threat,
        sanitized_text=cleaned,
        reasons=reasons,
        has_zero_width_steganography=has_bidi,
    )


def audit_code_secrets(content: str) -> Dict[str, Any]:
    """
    Scan code diff or text for accidental secret leaks, uncommitted API keys,
    private tokens, and private identifiers before git commit or AI ingestion.
    Returns structured list of findings with line numbers and masked snippets.
    """
    if not content or not isinstance(content, str):
        return {"has_secrets": False, "findings_count": 0, "findings": []}

    findings: List[Dict[str, Any]] = []
    lines = content.splitlines()

    for line_idx, line in enumerate(lines, start=1):
        # 1. API Keys
        for m in _API_KEY_RE.finditer(line):
            token = m.group(0)
            masked = token[:4] + "..." + token[-4:] if len(token) > 8 else "***"
            findings.append({
                "line": line_idx,
                "category": "API_KEY",
                "severity": "HIGH",
                "description": f"Exposed API key detected ({masked})",
            })

        # 2. GitHub Tokens
        for m in _GITHUB_TOKEN_RE.finditer(line):
            token = m.group(0)
            masked = token[:4] + "..." + token[-4:] if len(token) > 8 else "***"
            findings.append({
                "line": line_idx,
                "category": "GITHUB_TOKEN",
                "severity": "CRITICAL",
                "description": f"Exposed GitHub Personal Access Token detected ({masked})",
            })

        # 3. JWTs
        for m in _JWT_RE.finditer(line):
            findings.append({
                "line": line_idx,
                "category": "JWT_TOKEN",
                "severity": "HIGH",
                "description": "Exposed JSON Web Token (JWT) detected",
            })

        # 4. Bearer / Basic Auth headers
        for m in _BEARER_HEADER_RE.finditer(line):
            findings.append({
                "line": line_idx,
                "category": "BEARER_TOKEN",
                "severity": "HIGH",
                "description": "Hardcoded Authorization Bearer/Basic credential detected",
            })

        # 5. Secret assignments (e.g. password = "...")
        for m in _SECRET_ASSIGNMENT_RE.finditer(line):
            findings.append({
                "line": line_idx,
                "category": "HARDCODED_SECRET",
                "severity": "MEDIUM",
                "description": f"Hardcoded credential assignment: {m.group(1)}",
            })

        # 6. Payment cards
        for m in _CARD_CANDIDATE_RE.finditer(line):
            digits = "".join(ch for ch in m.group(0) if ch.isdigit())
            if is_valid_luhn(digits):
                findings.append({
                    "line": line_idx,
                    "category": "PAYMENT_CARD",
                    "severity": "CRITICAL",
                    "description": "Live Luhn-validated payment card number detected",
                })

        # 7. IBANs
        for m in _IBAN_CANDIDATE_RE.finditer(line):
            if is_valid_iban(m.group(0)):
                findings.append({
                    "line": line_idx,
                    "category": "IBAN",
                    "severity": "HIGH",
                    "description": "Live ISO-7064 IBAN bank account detected",
                })

    # Multi-line check: PEM private keys
    if _PEM_PRIVATE_KEY_RE.search(content):
        findings.append({
            "line": 1,
            "category": "PRIVATE_KEY",
            "severity": "CRITICAL",
            "description": "Unencrypted PEM private key detected in code content",
        })

    return {
        "has_secrets": len(findings) > 0,
        "findings_count": len(findings),
        "findings": findings,
    }


def _strip_embedded_media(out: str) -> str:
    out = _INLINE_IMAGE_DATA_URI_RE.sub("[REDACTED_INLINE_IMAGE_DATA_URI]", out)
    return strip_inline_svg_blocks(out)


def _scrub_secrets(out: str) -> str:
    out = _PEM_PRIVATE_KEY_RE.sub("[REDACTED_PRIVATE_KEY]", out)
    out = _GITHUB_TOKEN_RE.sub("[REDACTED_GITHUB_TOKEN]", out)
    out = _API_KEY_RE.sub("[REDACTED_API_KEY]", out)
    out = _JWT_RE.sub("[REDACTED_JWT]", out)
    out = _BEARER_HEADER_RE.sub(r"\1[REDACTED_CREDENTIAL]", out)
    out = _URL_EMBEDDED_CRED_RE.sub(r"\1[REDACTED_PASSWORD]\3", out)
    return _SECRET_ASSIGNMENT_RE.sub(r"\1\2\3[REDACTED_SECRET]\3", out)


def _scrub_cards_and_ibans(out: str) -> str:
    def _replace_iban(match: re.Match[str]) -> str:
        return "[REDACTED_IBAN]" if is_valid_iban(match.group(0)) else match.group(0)

    def _replace_card(match: re.Match[str]) -> str:
        digits = "".join(ch for ch in match.group(0) if ch.isdigit())
        return "[REDACTED_PAYMENT_CARD]" if is_valid_luhn(digits) else match.group(0)

    out = _IBAN_CANDIDATE_RE.sub(_replace_iban, out)
    return _CARD_CANDIDATE_RE.sub(_replace_card, out)


def _scrub_national_ids(out: str) -> str:
    out = _US_SSN_RE.sub("[REDACTED_SSN]", out)
    out = _NATIONAL_ID_CODE_RE.sub("[REDACTED_NATIONAL_ID]", out)
    return _LABELED_PERSONAL_CODE_RE.sub(r"\1\2[REDACTED_PERSONAL_CODE]", out)


def _scrub_financial_labels(out: str) -> str:
    out = _STANDALONE_PIN_OTP_RE.sub(r"\1: [REDACTED_PIN]", out)
    out = _CRYPTO_HEX_KEY_RE.sub("[REDACTED_CRYPTO_MATERIAL]", out)
    return _LABELED_FINANCIAL_RE.sub(r"\1\2[REDACTED_FINANCIAL_ID]", out)


def _scrub_private_ips(out: str) -> str:
    def _replace_private_ip(match: re.Match[str]) -> str:
        ip_str = match.group(0)
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return ip_str
        is_internal = (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_multicast
        )
        return "[REDACTED_LAN_IP]" if is_internal else ip_str

    return _IPV4_CANDIDATE_RE.sub(_replace_private_ip, out)


@dataclass(frozen=True)
class RedactionCategories:
    """User-selectable redaction categories shown in the desktop Settings view.

    Embedded images and inline SVG are always stripped and cannot be disabled.
    """

    secrets: bool = True
    financial: bool = True
    national_ids: bool = True
    identity: bool = True
    private_ips: bool = True


class PrivacySanitizer:
    """
    Stateful local privacy & DLP scrubber that discovers OS usernames/hostnames in local
    memory and strips PII, financial identifiers, secrets, and images before MCP responses.
    """

    def __init__(
        self,
        extra_redacted_names: Optional[Sequence[str]] = None,
        categories: Optional[RedactionCategories] = None,
    ) -> None:
        self._user_tokens: Set[str] = set()
        self._host_tokens: Set[str] = set()
        self._custom_name_tokens: Set[str] = set()
        self.categories = categories or RedactionCategories()
        self._discover_local_identity(extra_redacted_names)

    def _discover_local_identity(self, extra_redacted_names: Optional[Sequence[str]]) -> None:
        candidates_user = [
            os.environ.get("USERNAME", ""),
            os.environ.get("USER", ""),
            Path.home().name,
        ]
        try:
            candidates_user.append(getpass.getuser())
        except Exception:
            pass

        generic_skip = {"user", "users", "admin", "administrator", "root", "default", "public", "home"}
        for tok in candidates_user:
            cleaned = tok.strip()
            if len(cleaned) >= 3 and cleaned.lower() not in generic_skip:
                self._user_tokens.add(cleaned)

        candidates_host = [
            os.environ.get("COMPUTERNAME", ""),
            os.environ.get("HOSTNAME", ""),
        ]
        try:
            candidates_host.append(socket.gethostname())
            candidates_host.append(platform.node())
        except Exception:
            pass

        for host in candidates_host:
            cleaned = host.strip()
            if len(cleaned) >= 3 and cleaned.lower() not in {"localhost", "localdomain"}:
                self._host_tokens.add(cleaned)
                short_host = cleaned.split(".")[0]
                if len(short_host) >= 3:
                    self._host_tokens.add(short_host)

        env_names = os.environ.get("PACKETSENTINEL_REDACT_NAMES", "")
        combined_extra: List[str] = list(extra_redacted_names or [])
        if env_names:
            combined_extra.extend(part.strip() for part in env_names.split(",") if part.strip())

        for name in combined_extra:
            cleaned = name.strip()
            if len(cleaned) >= 3:
                self._custom_name_tokens.add(cleaned)

    def sanitize_text(self, text: str, redact_private_ips: bool = True) -> str:
        if not text:
            return ""

        cats = self.categories
        # The ordering matters: secrets are removed before card/IBAN candidates so that
        # long digit runs inside API keys are not mislabelled as payment cards.
        out = _strip_embedded_media(text)
        if cats.secrets:
            out = _scrub_secrets(out)
        if cats.financial:
            out = _scrub_cards_and_ibans(out)
        if cats.national_ids:
            out = _scrub_national_ids(out)
        if cats.financial:
            out = _scrub_financial_labels(out)
        if cats.identity:
            out = self._scrub_identity(out)
        if redact_private_ips and cats.private_ips:
            out = _scrub_private_ips(out)
        return out

    def _scrub_identity(self, out: str) -> str:
        out = _WIN_USER_PATH_RE.sub(r"%USERPROFILE%", out)
        out = _MAC_USER_PATH_RE.sub(r"$HOME", out)
        out = _LINUX_USER_PATH_RE.sub(r"$HOME", out)

        out = _LABELED_PERSONAL_NAME_RE.sub(r"\1\2[REDACTED_PERSONAL_NAME]\4", out)
        out = _HONORIFIC_NAME_RE.sub("[REDACTED_PERSONAL_NAME]", out)
        out = _GIT_AUTHOR_HEADER_RE.sub(r"\1[REDACTED_PERSONAL_NAME] <[REDACTED_EMAIL]>", out)

        token_groups = (
            (self._custom_name_tokens, "[REDACTED_PERSONAL_NAME]"),
            (self._user_tokens, "<REDACTED_USER>"),
            (self._host_tokens, "<REDACTED_HOST>"),
        )
        for tokens, placeholder in token_groups:
            for tok in sorted(tokens, key=len, reverse=True):
                out = re.sub(rf"(?i)\b{re.escape(tok)}\b", placeholder, out)

        out = _EMAIL_RE.sub("[REDACTED_EMAIL]", out)
        out = _PHONE_RE.sub("[REDACTED_PHONE]", out)
        out = _MAC_ADDR_RE.sub("[REDACTED_MAC]", out)
        return out

    def spotlight_untrusted_indicator(self, raw_indicator: str) -> str:
        """
        Sanitize an untrusted network indicator (domain, SNI, or IP) and wrap it in
        `<untrusted_network_data>` tags to prevent indirect prompt injection into AI agents.
        """
        scrubbed = self.sanitize_text(str(raw_indicator or ""), redact_private_ips=True)
        clean_chars = sanitize_display_text(scrubbed, max_len=120).strip()
        clean_chars = (
            clean_chars.replace("<", "")
            .replace(">", "")
            .replace("`", "")
            .replace("$", "")
            .replace("{", "")
            .replace("}", "")
        )
        capped = clean_chars[:120] if clean_chars else "unknown"
        return f"<untrusted_network_data>{capped}</untrusted_network_data>"

    def sanitize_alert_record(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """
        Gate 5: Transform a raw PacketSentinel (`alerts.jsonl`) or Rustinel ECS (`alerts.json`)
        record into a strict allowlisted `SanitizedAlertSummary` dict.

        Never forwards `user.*`, `host.*`, `process.command_line`, `process.parent.command_line`,
        `edr.powershell.script_block_text`, `file.path`, `registry.data.strings`, or `dns.answers`.
        """
        if not isinstance(raw, dict):
            raise ValueError("Alert record must be a JSON object.")

        ts = str(raw.get("timestamp") or raw.get("@timestamp") or "unknown")[:32]
        is_ecs = "@timestamp" in raw or isinstance(raw.get("rule"), dict) or isinstance(raw.get("process"), dict)
        alert_source = "rustinel" if is_ecs else "packetsentinel"

        rule_obj = raw.get("rule") if isinstance(raw.get("rule"), dict) else {}
        severity = str(
            raw.get("severity")
            or rule_obj.get("severity")
            or raw.get("event", {}).get("severity_label")
            or "high"
        ).lower()[:16]

        raw_rule_name = str(
            raw.get("source_feed")
            or rule_obj.get("name")
            or raw.get("matched_rule")
            or "threat_rule"
        )
        rule_name = sanitize_display_text(self.sanitize_text(raw_rule_name), max_len=80)

        raw_match_type = str(
            raw.get("match_type")
            or rule_obj.get("category")
            or raw.get("detection_layer")
            or "network_indicator"
        )
        match_type = sanitize_display_text(self.sanitize_text(raw_match_type), max_len=40)

        proc_obj = raw.get("process") if isinstance(raw.get("process"), dict) else {}
        raw_proc_name = str(
            raw.get("process_name")
            or proc_obj.get("name")
            or proc_obj.get("executable")
            or "unknown"
        )
        # Extract only basename so full paths (`C:\Users\Alice\...`) never leak
        proc_basename = Path(raw_proc_name.replace("\\", "/")).name
        process_name = sanitize_display_text(self.sanitize_text(proc_basename), max_len=48) or "unknown"

        net_obj = raw.get("network") if isinstance(raw.get("network"), dict) else {}
        raw_proto = str(raw.get("protocol") or net_obj.get("protocol") or "UDP/DNS")
        protocol = sanitize_display_text(raw_proto, max_len=20)

        dst_obj = raw.get("destination") if isinstance(raw.get("destination"), dict) else {}
        try:
            dst_port = int(raw.get("dst_port") or dst_obj.get("port") or 0)
            dst_port = max(0, min(65535, dst_port))
        except (ValueError, TypeError):
            dst_port = 0

        dns_obj = raw.get("dns") if isinstance(raw.get("dns"), dict) else {}
        dns_q = dns_obj.get("question") if isinstance(dns_obj.get("question"), dict) else {}
        raw_indicator = str(
            raw.get("indicator")
            or dns_q.get("name")
            or dst_obj.get("domain")
            or dst_obj.get("ip")
            or raw.get("dst_ip")
            or "redacted"
        )

        # Compute boolean risk flags locally from sensitive fields WITHOUT exposing the fields
        cmdline_parts: List[str] = [
            str(proc_obj.get("command_line") or ""),
            str(proc_obj.get("parent", {}).get("command_line") if isinstance(proc_obj.get("parent"), dict) else ""),
            str(raw.get("edr", {}).get("powershell", {}).get("script_block_text") if isinstance(raw.get("edr"), dict) else ""),
        ]
        combined_cmdline = " ".join(p for p in cmdline_parts if p)
        parent_name = str(
            proc_obj.get("parent", {}).get("name") if isinstance(proc_obj.get("parent"), dict) else ""
        )
        exec_paths = " ".join(
            [
                str(raw.get("process_exe") or ""),
                str(proc_obj.get("executable") or ""),
                str(proc_obj.get("working_directory") or ""),
                str(raw.get("file", {}).get("path") if isinstance(raw.get("file"), dict) else ""),
            ]
        )

        scrubbed_cmdline = self.sanitize_text(combined_cmdline)
        risk_flags = {
            "has_encoded_command": bool(_ENCODED_CMDLINE_RE.search(combined_cmdline)),
            "suspicious_parent_process": bool(_SUSPICIOUS_PARENT_RE.search(parent_name)),
            "ran_from_user_temp_or_downloads": bool(_USER_WRITABLE_EXEC_RE.search(exec_paths)),
            "pii_or_secret_scrubbed_from_cmdline": (scrubbed_cmdline != combined_cmdline),
        }

        summary = SanitizedAlertSummary(
            timestamp_utc=ts,
            alert_source=alert_source,
            severity=severity,
            rule_name=rule_name,
            match_type=match_type,
            process_name=process_name,
            protocol=protocol,
            dst_port=dst_port,
            indicator_spotlighted=self.spotlight_untrusted_indicator(raw_indicator),
            risk_flags=risk_flags,
        )
        return summary.to_dict()

    def validate_and_read_safe_text_file(
        self,
        target_path: Path,
        allowed_root: Path,
        start_line: int = 1,
        end_line: int = 200,
        max_bytes: int = 65_536,
    ) -> Dict[str, Any]:
        """
        Gate 1–4 Combined File Reader: Verifies `target_path` is strictly inside `allowed_root`,
        blocks images/PDFs/binaries/secrets by both path and magic-byte header, and sanitizes
        all returned lines before the MCP server returns them to an AI model.
        """
        root_resolved = allowed_root.resolve()
        if target_path.is_symlink():
            raise PermissionError("DLP_GATE_BLOCKED: Symlinks and NTFS reparse points are forbidden (CWE-59).")
        try:
            candidate_resolved = target_path.resolve(strict=True)
        except FileNotFoundError:
            raise PermissionError("Requested file does not exist.")

        try:
            rel_path = candidate_resolved.relative_to(root_resolved)
        except ValueError:
            raise PermissionError("Path traversal blocked: file is outside the allowed workspace root.")

        if not candidate_resolved.is_file():
            raise PermissionError("Requested path is not a regular file.")

        blocked, reason = is_blocked_file_path(rel_path)
        if blocked:
            raise PermissionError(f"DLP_GATE_BLOCKED: {reason}")

        with candidate_resolved.open("rb") as fh:
            sample = fh.read(min(max_bytes, 8192))
            magic_hit = detect_blocked_magic_bytes(sample)
            if magic_hit:
                raise PermissionError(
                    f"DLP_GATE_BLOCKED: Binary/media magic header detected ({magic_hit}). "
                    "Images, documents, and binary files are blocked from AI context."
                )
            fh.seek(0)
            raw_bytes = fh.read(max_bytes + 1)

        truncated_by_bytes = len(raw_bytes) > max_bytes
        raw_text = raw_bytes[:max_bytes].decode("utf-8", errors="replace")

        lines = raw_text.splitlines()
        total_lines = len(lines)
        s_line = max(1, int(start_line))
        e_line = max(s_line, min(int(end_line), s_line + 250, max(1, total_lines)))

        selected_raw = "\n".join(lines[s_line - 1 : e_line])
        sanitized_content = self.sanitize_text(selected_raw, redact_private_ips=True)

        # Gate 6: Indirect prompt-injection and steganography neutralization
        injection_res = sanitize_prompt_injection(sanitized_content)
        sanitized_content = injection_res.sanitized_text

        framed_content = (
            f'<untrusted_project_file path="{str(rel_path).replace(chr(92), "/")}">'
            f"\n{sanitized_content}\n</untrusted_project_file>"
        )

        return {
            "relative_path": str(rel_path).replace("\\", "/"),
            "start_line": s_line,
            "end_line": e_line,
            "total_lines": total_lines,
            "truncated_by_byte_cap": truncated_by_bytes,
            "dlp_sanitized": True,
            "injection_detected": injection_res.is_injection_detected,
            "injection_reasons": injection_res.reasons,
            "content": framed_content,
        }

    def sanitize_for_ai(self, target: Any) -> Any:
        """
        Pass a structured alert record (dict), text (str), or payload through Gates 1-5.
        Strips internal usernames, private IPs, and secrets before AI ingestion.
        """
        if isinstance(target, dict):
            return self.sanitize_alert_record(target)
        if isinstance(target, str):
            return self.sanitize_text(target, redact_private_ips=True)
        return target


def sanitize_for_ai(
    target: Any,
    sanitizer: Optional[PrivacySanitizer] = None,
    **kwargs: Any,
) -> Any:
    """
    Module-level 5-Gate Pre-Model Privacy & DLP Airlock entrypoint.
    Sanitizes alert records (stripping usernames, LAN IPs, tokens) or free text.
    """
    s = sanitizer or PrivacySanitizer()
    return s.sanitize_for_ai(target)

