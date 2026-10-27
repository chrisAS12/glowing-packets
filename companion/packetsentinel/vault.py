"""
Offline Encrypted Settings Vault for PacketSentinel.

Protects sensitive user configurations (custom redacted names, private blocklists,
API tokens) using Windows DPAPI (Data Protection API) via ctypes.
- Bound to the current logged-in Windows user session and machine LSA.
- Zero plaintext keys stored on disk or in source code.
- Cannot be decrypted by other machines, other users, or external AI bots.
"""

from __future__ import annotations

import ctypes
import json
import logging
import os
import platform
import sys
from ctypes import wintypes
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .mcp_privacy import RedactionCategories

logger = logging.getLogger("packetsentinel.vault")


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


@dataclass
class VaultSettings:
    """User-customizable personal settings stored safely in the encrypted vault."""

    custom_names: List[str] = field(default_factory=list)
    custom_domains: List[str] = field(default_factory=list)
    custom_feeds: List[str] = field(default_factory=list)
    default_watch_process: str = "python"
    enable_toasts: bool = True
    enable_console_beep: bool = False
    log_level: str = "INFO"
    alert_cooldown_seconds: int = 60
    capture_loopback: bool = True
    dlp_gate_cards: bool = True
    dlp_gate_keys: bool = True
    dlp_gate_usernames: bool = True
    dlp_gate_national_ids: bool = True
    dlp_gate_ips: bool = True
    enable_web_gateway: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def redaction_categories(self) -> RedactionCategories:
        return RedactionCategories(
            secrets=self.dlp_gate_keys,
            financial=self.dlp_gate_cards,
            national_ids=self.dlp_gate_national_ids,
            identity=self.dlp_gate_usernames,
            private_ips=self.dlp_gate_ips,
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VaultSettings":
        return cls(
            custom_names=list(data.get("custom_names", [])),
            custom_domains=list(data.get("custom_domains", [])),
            custom_feeds=list(data.get("custom_feeds", [])),
            default_watch_process=str(data.get("default_watch_process", "python")),
            enable_toasts=bool(data.get("enable_toasts", True)),
            enable_console_beep=bool(data.get("enable_console_beep", False)),
            log_level=str(data.get("log_level", "INFO")),
            alert_cooldown_seconds=int(data.get("alert_cooldown_seconds", 60)),
            capture_loopback=bool(data.get("capture_loopback", True)),
            dlp_gate_cards=bool(data.get("dlp_gate_cards", True)),
            dlp_gate_keys=bool(data.get("dlp_gate_keys", True)),
            dlp_gate_usernames=bool(data.get("dlp_gate_usernames", True)),
            dlp_gate_national_ids=bool(data.get("dlp_gate_national_ids", True)),
            dlp_gate_ips=bool(data.get("dlp_gate_ips", True)),
            enable_web_gateway=bool(data.get("enable_web_gateway", False)),
        )


def _dpapi_encrypt(plaintext: bytes) -> bytes:
    """Encrypt payload using Windows DPAPI CryptProtectData."""
    if not plaintext:
        return b""
    blob_in = _DATA_BLOB(len(plaintext), ctypes.cast(plaintext, ctypes.POINTER(ctypes.c_byte)))
    blob_out = _DATA_BLOB()
    # CRYPTPROTECT_UI_FORBIDDEN = 0x01
    res = ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(blob_in),
        "PacketSentinel Vault",
        None,
        None,
        None,
        0x01,
        ctypes.byref(blob_out),
    )
    if not res:
        raise OSError(f"Windows DPAPI encryption failed with error code: {ctypes.GetLastError()}")

    ciphertext = ctypes.string_at(blob_out.pbData, blob_out.cbData)
    ctypes.windll.kernel32.LocalFree(blob_out.pbData)
    return ciphertext


def _dpapi_decrypt(ciphertext: bytes) -> bytes:
    """Decrypt payload using Windows DPAPI CryptUnprotectData."""
    if not ciphertext:
        return b""
    blob_in = _DATA_BLOB(len(ciphertext), ctypes.cast(ciphertext, ctypes.POINTER(ctypes.c_byte)))
    blob_out = _DATA_BLOB()
    res = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blob_in),
        None,
        None,
        None,
        None,
        0x01,
        ctypes.byref(blob_out),
    )
    if not res:
        raise OSError(f"Windows DPAPI decryption failed with error code: {ctypes.GetLastError()}")

    plaintext = ctypes.string_at(blob_out.pbData, blob_out.cbData)
    ctypes.windll.kernel32.LocalFree(blob_out.pbData)
    return plaintext


def get_default_vault_path() -> Path:
    """Return default encrypted vault path in user's AppData or home directory.

    SENTINELWIRE_HOME or PACKETSENTINEL_HOME relocates the vault together with
    logs and caches so that tests and portable installs never touch the real user profile.
    """
    override = os.environ.get("SENTINELWIRE_HOME") or os.environ.get("PACKETSENTINEL_HOME")
    if override:
        return Path(override).expanduser().resolve() / "vault.bin"
    base = os.environ.get("APPDATA")
    if base:
        canonical = Path(base) / "SentinelWire" / "vault.bin"
        legacy = Path(base) / "PacketSentinel" / "vault.bin"
    else:
        canonical = Path.home() / ".sentinelwire" / "vault.bin"
        legacy = Path.home() / ".packetsentinel" / "vault.bin"

    if not canonical.exists() and legacy.exists():
        return legacy
    return canonical


_PLAINTEXT_MARKER = b"PLAINTEXT_0600:"
_LEGACY_PLAINTEXT_MARKER = b"NON_WIN_ENC:"


class EncryptedVaultManager:
    """Manages reading and writing encrypted settings on disk."""

    def __init__(self, vault_path: Optional[Path] = None) -> None:
        self.vault_path = vault_path if vault_path is not None else get_default_vault_path()
        self._is_windows = platform.system().lower() == "windows"

    @property
    def protection_description(self) -> str:
        if self._is_windows:
            return "Encrypted with Windows DPAPI (bound to your Windows login)"
        return "NOT encrypted on this OS — plain JSON readable only by your user account (chmod 600)"

    def save_settings(self, settings: VaultSettings) -> bool:
        """Serialize settings to JSON and save encrypted binary to vault_path."""
        try:
            payload = json.dumps(settings.to_dict()).encode("utf-8")
            data = _dpapi_encrypt(payload) if self._is_windows else _PLAINTEXT_MARKER + payload
            self.vault_path.parent.mkdir(parents=True, exist_ok=True)
            self.vault_path.write_bytes(data)
            if not self._is_windows:
                os.chmod(self.vault_path, 0o600)
            return True
        except Exception as exc:
            logger.error(f"Failed to save settings to vault: {exc}")
            return False

    def load_settings(self) -> VaultSettings:
        """Load and decrypt settings from vault_path. Returns defaults if missing or corrupted."""
        if not self.vault_path.exists():
            return VaultSettings()
        try:
            raw = self.vault_path.read_bytes()
            if not raw:
                return VaultSettings()

            if self._is_windows:
                decrypted = _dpapi_decrypt(raw)
            else:
                for marker in (_PLAINTEXT_MARKER, _LEGACY_PLAINTEXT_MARKER):
                    if raw.startswith(marker):
                        raw = raw[len(marker):]
                        break
                decrypted = raw

            parsed = json.loads(decrypted.decode("utf-8", errors="replace"))
            return VaultSettings.from_dict(parsed)
        except Exception as exc:
            logger.warning(f"Failed to decrypt vault, resetting to defaults: {exc}")
            return VaultSettings()
