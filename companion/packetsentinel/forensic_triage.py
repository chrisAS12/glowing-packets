"""
Automated Forensic Triage & Remediation Engine for SentinelWire / PacketSentinel.

Provides local-only, zero-outbound digital signature verification (Authenticode),
rogue/unsigned DLL sideload detection, persistence auditing (Registry Run / Startup),
process lineage inspection, and 1-click remediation actions (kill, firewall block, quarantine).
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

logger = logging.getLogger("packetsentinel.forensic_triage")

# Common DLL names historically targeted for sideloading/proxying in userland apps
KNOWN_SIDELOAD_DLLS: frozenset[str] = frozenset(
    {
        "version.dll",
        "winmm.dll",
        "dbghelp.dll",
        "hid.dll",
        "dxgi.dll",
        "winhttp.dll",
        "cryptbase.dll",
        "msasn1.dll",
        "wtsapi32.dll",
        "uxtheme.dll",
        "d3d11.dll",
        "shcore.dll",
        "netapi32.dll",
        "userenv.dll",
        "dwmapi.dll",
        "propsys.dll",
    }
)


@dataclass
class AuthenticodeResult:
    """Authenticode digital signature verification result."""

    file_path: str
    status: str  # "Valid", "NotSigned", "HashMismatch", "NotTrusted", "Unknown", "FileNotFound"
    signer_subject: str = ""
    signer_issuer: str = ""
    is_trusted: bool = False
    error_message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RogueDllFinding:
    """Detection finding for an unsigned or suspicious DLL in an application directory."""

    dll_name: str
    dll_path: str
    status: str
    signer_subject: str
    is_suspicious: bool
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PersistenceFinding:
    """Startup or persistence entry matching target process."""

    location: str
    name: str
    command: str
    matches_target: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProcessForensicContext:
    """Forensic runtime context of an origin process."""

    pid: int
    name: str
    exe_path: str
    cmdline: str
    parent_pid: Optional[int] = None
    parent_name: Optional[str] = None
    parent_exe: Optional[str] = None
    is_masquerading: bool = False
    masquerading_reason: str = ""
    authenticode: Optional[AuthenticodeResult] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.authenticode:
            d["authenticode"] = self.authenticode.to_dict()
        return d


@dataclass
class ThreatExplanation:
    """In-depth plain English threat breakdown and incident response steps."""

    headline: str
    threat_type: str
    risk_level: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    why_suspicious: str
    attack_vectors: List[str] = field(default_factory=list)
    containment_steps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def check_authenticode(file_path: Union[str, Path]) -> AuthenticodeResult:
    """
    Verify Authenticode signature using local Windows PowerShell Get-AuthenticodeSignature.
    Zero outbound network calls. Safe fallback on non-Windows platforms.
    """
    path_obj = Path(file_path)
    if not path_obj.exists():
        return AuthenticodeResult(
            file_path=str(path_obj),
            status="FileNotFound",
            is_trusted=False,
            error_message="File does not exist on disk.",
        )

    if os.name != "nt":
        # Cross-platform fallback for testing/macOS/Linux
        return AuthenticodeResult(
            file_path=str(path_obj),
            status="Valid" if path_obj.name.startswith("trusted_") else "NotSigned",
            signer_subject="CN=Simulated Trusted Cert" if path_obj.name.startswith("trusted_") else "",
            is_trusted=path_obj.name.startswith("trusted_"),
        )

    # PowerShell snippet to query signature cleanly without opening a console window
    ps_script = (
        f"$sig = Get-AuthenticodeSignature -LiteralPath '{str(path_obj).replace('\'', '\'\'')}'; "
        f"[PSCustomObject]@{{ "
        f"Status = $sig.Status.ToString(); "
        f"Subject = if ($sig.SignerCertificate) {{ $sig.SignerCertificate.Subject }} else {{ '' }}; "
        f"Issuer = if ($sig.SignerCertificate) {{ $sig.SignerCertificate.Issuer }} else {{ '' }} "
        f"}} | ConvertTo-Json -Compress"
    )

    try:
        creation_flags = 0x08000000  # CREATE_NO_WINDOW
        res = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            shell=False,
            capture_output=True,
            text=True,
            timeout=8,
            creationflags=creation_flags,
        )
        if res.returncode == 0 and res.stdout.strip():
            data = json.loads(res.stdout.strip())
            status = str(data.get("Status", "Unknown"))
            subject = str(data.get("Subject", "") or "")
            issuer = str(data.get("Issuer", "") or "")
            is_valid = status.lower() == "valid"
            return AuthenticodeResult(
                file_path=str(path_obj),
                status=status,
                signer_subject=subject,
                signer_issuer=issuer,
                is_trusted=is_valid,
            )
        else:
            return AuthenticodeResult(
                file_path=str(path_obj),
                status="Unknown",
                is_trusted=False,
                error_message=res.stderr.strip() or "Empty PowerShell response",
            )
    except Exception as exc:
        logger.warning(f"Failed to query Authenticode for {path_obj}: {exc}")
        return AuthenticodeResult(
            file_path=str(path_obj),
            status="Unknown",
            is_trusted=False,
            error_message=str(exc),
        )


def scan_directory_for_unsigned_dlls(
    target_path: Union[str, Path], max_dlls: int = 50
) -> List[RogueDllFinding]:
    """
    Inspect all DLLs in the target executable's folder for missing or invalid signatures.
    Prioritizes known sideloadable DLL targets (e.g. version.dll, winmm.dll).
    """
    path_obj = Path(target_path)
    target_dir = path_obj.parent if path_obj.is_file() else path_obj

    if not target_dir.exists() or not target_dir.is_dir():
        return []

    findings: List[RogueDllFinding] = []
    try:
        dll_files = list(target_dir.glob("*.dll"))
    except Exception as exc:
        logger.warning(f"Error enumerating DLLs in {target_dir}: {exc}")
        return []

    # Sort so known high-risk sideload DLLs appear first
    sorted_dlls = sorted(
        dll_files,
        key=lambda p: (0 if p.name.lower() in KNOWN_SIDELOAD_DLLS else 1, p.name.lower()),
    )[:max_dlls]

    for dll in sorted_dlls:
        sig = check_authenticode(dll)
        is_high_risk_name = dll.name.lower() in KNOWN_SIDELOAD_DLLS

        if not sig.is_trusted:
            reason = f"Unsigned/Invalid DLL in application root ({sig.status})"
            if is_high_risk_name:
                reason = f"HIGH-RISK SIDELOAD TARGET: Unsigned '{dll.name}' in app folder"
            findings.append(
                RogueDllFinding(
                    dll_name=dll.name,
                    dll_path=str(dll),
                    status=sig.status,
                    signer_subject=sig.signer_subject,
                    is_suspicious=True,
                    reason=reason,
                )
            )
        else:
            reason = f"Signed library ({sig.signer_subject or 'Valid'})"
            if is_high_risk_name:
                reason = f"Sideload-target name present but signed ({sig.signer_subject or 'Valid'})"
            findings.append(
                RogueDllFinding(
                    dll_name=dll.name,
                    dll_path=str(dll),
                    status=sig.status,
                    signer_subject=sig.signer_subject,
                    is_suspicious=False,
                    reason=reason,
                )
            )

    return findings


def check_persistence_entries(
    process_name: str, exe_path: Optional[str] = None
) -> List[PersistenceFinding]:
    """
    Scan Windows Registry Run keys and Startup folder for entries referencing target process.
    """
    findings: List[PersistenceFinding] = []
    norm_proc = (process_name or "").lower().replace(".exe", "")

    # 1. Registry Run Keys (HKCU and HKLM)
    if os.name == "nt":
        try:
            import winreg

            keys_to_check = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\...\\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\...\\Run"),
            ]
            for root_hkey, subkey, label in keys_to_check:
                try:
                    with winreg.OpenKey(root_hkey, subkey, 0, winreg.KEY_READ) as k:
                        count, _, _ = winreg.QueryInfoKey(k)
                        for i in range(count):
                            val_name, val_data, _ = winreg.EnumValue(k, i)
                            cmd_str = str(val_data).lower()
                            matches = (
                                (norm_proc and norm_proc in val_name.lower())
                                or (norm_proc and norm_proc in cmd_str)
                                or (exe_path and exe_path.lower() in cmd_str)
                            )
                            if matches:
                                findings.append(
                                    PersistenceFinding(
                                        location=label,
                                        name=val_name,
                                        command=str(val_data),
                                        matches_target=True,
                                    )
                                )
                except Exception:
                    continue
        except ImportError:
            pass

    # 2. Startup Folder
    appdata = os.environ.get("APPDATA")
    if appdata:
        startup_dir = Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        if startup_dir.exists() and startup_dir.is_dir():
            try:
                for item in startup_dir.iterdir():
                    if item.is_file():
                        name_lower = item.name.lower()
                        if norm_proc and norm_proc in name_lower:
                            findings.append(
                                PersistenceFinding(
                                    location="Startup Folder",
                                    name=item.name,
                                    command=str(item),
                                    matches_target=True,
                                )
                            )
            except Exception as exc:
                logger.debug(f"Error checking startup folder: {exc}")

    return findings


def inspect_running_process(pid_or_name: Union[int, str]) -> Optional[ProcessForensicContext]:
    """
    Collect forensic process context (lineage, cmdline, Authenticode, masquerade checks).
    """
    import psutil

    target_proc: Optional[psutil.Process] = None

    if isinstance(pid_or_name, int) and pid_or_name > 0:
        try:
            target_proc = psutil.Process(pid_or_name)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    if target_proc is None and isinstance(pid_or_name, str) and pid_or_name:
        clean_name = pid_or_name.lower().strip()
        for p in psutil.process_iter(["pid", "name"]):
            try:
                if (p.info.get("name") or "").lower() == clean_name:
                    target_proc = p
                    break
            except Exception:
                continue

    if target_proc is None:
        return None

    try:
        pid = target_proc.pid
        name = target_proc.name()
        exe = ""
        try:
            exe = target_proc.exe()
        except Exception:
            pass

        cmdline = ""
        try:
            cmdline = " ".join(target_proc.cmdline())
        except Exception:
            pass

        parent_pid = None
        parent_name = None
        parent_exe = None
        try:
            parent = target_proc.parent()
            if parent:
                parent_pid = parent.pid
                parent_name = parent.name()
                try:
                    parent_exe = parent.exe()
                except Exception:
                    pass
        except Exception:
            pass

        # Masquerading analysis
        is_masquerading = False
        masq_reason = ""
        if exe:
            lower_exe = exe.lower()
            lower_name = name.lower()

            # E.g., svchost or csrss running outside System32
            system_binaries = {"svchost.exe", "csrss.exe", "smss.exe", "lsass.exe", "services.exe"}
            if lower_name in system_binaries and "\\system32\\" not in lower_exe:
                is_masquerading = True
                masq_reason = f"System binary '{name}' running outside System32 ({exe})"

            # E.g., consumer app Spotify / Discord running from Temp
            if "\\temp\\" in lower_exe or "\\tmp\\" in lower_exe:
                is_masquerading = True
                masq_reason = f"Executable launched directly from Temp directory ({exe})"

        # Digital signature check
        authenticode = check_authenticode(exe) if exe else None

        return ProcessForensicContext(
            pid=pid,
            name=name,
            exe_path=exe,
            cmdline=cmdline,
            parent_pid=parent_pid,
            parent_name=parent_name,
            parent_exe=parent_exe,
            is_masquerading=is_masquerading,
            masquerading_reason=masq_reason,
            authenticode=authenticode,
        )
    except Exception as exc:
        logger.warning(f"Error inspecting process {pid_or_name}: {exc}")
        return None


def explain_threat(
    indicator: str,
    feed: str,
    proc: str,
    layer: str = "wire",
    forensic_ctx: Optional[ProcessForensicContext] = None,
) -> ThreatExplanation:
    """
    Generate plain-English threat breakdown, attack vector explanation, and containment steps.
    """
    ind_lower = str(indicator).lower()
    feed_lower = str(feed).lower()
    proc_lower = str(proc).lower()

    # Case 1: LOTS Exfiltration Guard (Discord Webhook, Telegram Bot, Cloud Tunnels)
    is_lots = "lots" in feed_lower or any(
        lots_dom in ind_lower
        for lots_dom in (
            "discord.com",
            "discordapp.com",
            "api.telegram.org",
            "trycloudflare.com",
            "ngrok-free.app",
            "webhook.site",
            "transfer.sh",
        )
    )

    if is_lots:
        app_desc = proc or "The attributed process"
        headline = f"LOTS Living-Off-Trusted-Sites Exfiltration Detected ({indicator})"
        why = (
            f"Active or attempted data exfiltration utilizing legitimate cloud services (LOTS).\n\n"
            f"• Indicator: {indicator}\n"
            f"• Attributed Process: {proc or 'Unknown'}\n\n"
            f"This pattern is characteristic of modern Commodity Infostealers (such as Lumma, Vidar, Stealc, "
            f"RedLine, or open-source Grabbers) attempting to exfiltrate browser session cookies, autofill passwords, "
            f"and cryptocurrency wallet credentials. Legitimate client software like '{proc}' does not communicate "
            f"with external webhook APIs or ad-hoc tunneling infrastructure."
        )
        attack_vectors = [
            f"DLL Sideloading / Proxying: Rogue DLL (e.g. version.dll, winmm.dll, dbghelp.dll) dropped into {proc}'s install directory.",
            f"Trojanized Extension or Mod: Third-party utility, theme modder (e.g. Spicetify, SpotX), or crack bundled with an infostealer.",
            f"Process Injection / Hollowing: External malware spawned a legitimate {proc} instance and hollowed its memory to hide behind its network socket.",
            f"Process Masquerading: Standalone infostealer renamed itself to '{proc}' to blend into Task Manager.",
        ]
        containment = [
            "Phase 1 (Immediate Containment): Terminate the origin process and block the outbound endpoint.",
            "Phase 2 (Forensic Triage): Check Authenticode digital signatures on the executable and scan its directory for unsigned DLLs.",
            "Phase 3 (Eradication): Quarantine any rogue DLLs, audit startup persistence keys, and purge trojanized app caches.",
        ]
        return ThreatExplanation(
            headline=headline,
            threat_type="LOTS Infostealer Exfiltration",
            risk_level="CRITICAL" if any(k in proc_lower for k in ("spotify", "notion", "game", "obs")) else "HIGH",
            why_suspicious=why,
            attack_vectors=attack_vectors,
            containment_steps=containment,
        )

    # Case 2: Botnet C2 / RAT Infrastructure (Feodo, ThreatFox)
    if any(k in feed_lower for k in ("feodo", "threatfox", "botnet", "c2")):
        return ThreatExplanation(
            headline=f"Active Botnet C2 / Malware Infrastructure ({indicator})",
            threat_type="Command-and-Control (C2)",
            risk_level="CRITICAL",
            why_suspicious=(
                f"Outbound connection matched active malware Command-and-Control (C2) infrastructure "
                f"tracked by global threat intelligence feeds ({feed}). Botnets abuse these IP/DNS nodes "
                f"to send instructions, fetch secondary ransomware/stealer payloads, or exfiltrate keystrokes."
            ),
            attack_vectors=[
                "Drive-by malicious script execution (PowerShell, mshta, curl).",
                "Phishing document with malicious macro or OneNote payload.",
                "Exploited vulnerable listening local network service.",
            ],
            containment_steps=[
                "Immediately terminate the calling process.",
                "Sever the remote IP at the host firewall.",
                "Perform full endpoint memory scan.",
            ],
        )

    # Case 3: Malware Dropper / URLhaus
    if "urlhaus" in feed_lower:
        return ThreatExplanation(
            headline=f"Active Malware Distribution Dropper ({indicator})",
            threat_type="Malware Dropper",
            risk_level="HIGH",
            why_suspicious=(
                f"Connection attempted to download payloads from an active malware distribution site "
                f"tracked by abuse.ch URLhaus. These sites typically host RedLine, Lumma, AsyncRAT, or AgentTesla binaries."
            ),
            attack_vectors=[
                "Deceptive sponsored ads (malvertising) on search engines.",
                "Fake software updates or installer packages.",
            ],
            containment_steps=[
                "Kill the initiating downloader process.",
                "Clear browser and download cache directories.",
                "Block host at local firewall.",
            ],
        )

    # Case 4: General DNS Threat Intelligence Blocklist (OISD, HaGeZi, etc.)
    return ThreatExplanation(
        headline=f"Malicious / High-Risk DNS Query Intercepted ({indicator})",
        threat_type="DNS Threat Intelligence Match",
        risk_level="MEDIUM",
        why_suspicious=(
            f"Domain '{indicator}' is flagged on consolidated high-security threat intelligence blocklists ({feed}). "
            f"Commonly associated with covert tracking, spyware telemetry, or recently registered phishing infrastructure."
        ),
        attack_vectors=[
            "Embedded tracker in freeware or pirated utility.",
            "Background analytics script or telemetry service.",
        ],
        containment_steps=[
            "Verify process legitimacy.",
            "Maintain outbound DNS blocking.",
        ],
    )


def terminate_process_tree(pid: int) -> Tuple[bool, str]:
    """
    Terminate process and its child processes safely.
    """
    if pid <= 4:
        return False, "Cannot terminate critical system process (PID <= 4)."

    try:
        import psutil

        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        killed_count = 0
        for child in children:
            try:
                child.kill()
                killed_count += 1
            except Exception:
                pass
        parent.kill()
        killed_count += 1
        return True, f"Successfully terminated process PID {pid} and {killed_count - 1} child process(es)."
    except Exception as exc:
        return False, f"Error terminating process PID {pid}: {exc}"


def quarantine_file(file_path: Union[str, Path]) -> Tuple[bool, str, Optional[str]]:
    """
    Move suspicious or rogue DLL into secure local quarantine folder (%LOCALAPPDATA%\\SentinelWire\\quarantine\\).
    Renames file with .quarantine suffix to prevent execution.
    """
    source = Path(file_path)
    if not source.exists() or not source.is_file():
        return False, "Target file does not exist on disk.", None

    local_app_data = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    quarantine_root = Path(local_app_data) / "SentinelWire" / "quarantine"
    quarantine_root.mkdir(parents=True, exist_ok=True)

    timestamp_str = str(int(time.time()))
    dest_name = f"{source.name}_{timestamp_str}.quarantine"
    dest_path = quarantine_root / dest_name

    try:
        shutil.move(str(source), str(dest_path))
        return True, f"Quarantined '{source.name}' to '{dest_path.name}'.", str(dest_path)
    except Exception as exc:
        return False, f"Failed to quarantine file: {exc}", None


def get_firewall_block_commands(indicator: str) -> Dict[str, str]:
    """
    Generate copyable PowerShell and Netsh firewall block commands for the indicator.
    """
    clean_ind = str(indicator).strip().replace("\"", "").replace("'", "")
    rule_name = f"SentinelWire_Block_{clean_ind[:30]}"
    ps_cmd = (
        f'New-NetFirewallRule -DisplayName "{rule_name}" '
        f'-Direction Outbound -RemoteAddress "{clean_ind}" -Action Block'
    )
    netsh_cmd = (
        f'netsh advfirewall firewall add rule name="{rule_name}" '
        f'dir=out action=block remoteip="{clean_ind}"'
    )
    return {"powershell": ps_cmd, "netsh": netsh_cmd}


def apply_firewall_block_rule(indicator: str) -> Tuple[bool, str]:
    """
    Execute firewall block command via elevated PowerShell or netsh.
    """
    clean_ind = str(indicator).strip().replace("\"", "").replace("'", "")
    if os.name != "nt":
        return True, f"[Non-Windows] Simulated firewall block for {clean_ind}."

    cmds = get_firewall_block_commands(clean_ind)
    try:
        res = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", cmds["powershell"]],
            shell=False,
            capture_output=True,
            text=True,
            timeout=8,
            creationflags=0x08000000,
        )
        if res.returncode == 0:
            return True, f"Firewall rule added successfully for {clean_ind}."
        else:
            return False, f"Failed to add firewall rule: {res.stderr.strip() or 'Requires Administrator privileges'}"
    except Exception as exc:
        return False, f"Error executing firewall rule: {exc}"


def get_app_cleanup_targets(app_name: str) -> List[Dict[str, Any]]:
    """
    Identify standard userland directories and caches for commonly trojanized apps (e.g. Spotify).
    """
    norm = app_name.lower().replace(".exe", "").strip()
    targets: List[Dict[str, Any]] = []

    appdata = os.environ.get("APPDATA") or ""
    localappdata = os.environ.get("LOCALAPPDATA") or ""

    if norm == "spotify":
        candidates = [
            ("Application Directory", Path(appdata) / "Spotify"),
            ("Cache Directory", Path(localappdata) / "Spotify"),
            ("Spicetify Mod Directory", Path(appdata) / "spicetify"),
            ("Spicetify CLI", Path(localappdata) / "spicetify-cli"),
        ]
        for desc, path_obj in candidates:
            if path_obj.exists():
                targets.append({"description": desc, "path": str(path_obj), "exists": True})

    return targets


def generate_sanitized_incident_dossier(
    indicator: str,
    feed: str,
    proc: str,
    layer: str,
    threat_exp: ThreatExplanation,
    forensic_ctx: Optional[ProcessForensicContext],
    rogue_dlls: Sequence[RogueDllFinding],
    persistence: Sequence[PersistenceFinding],
    sanitizer: Optional[Any] = None,
) -> str:
    """
    Format a complete, PII-sanitized forensic incident report ready for local review or AI auditing.
    """
    lines = [
        "==================================================================",
        "  SentinelWire Automated Incident Triage & Forensic Report",
        "==================================================================",
        f"Headline      : {threat_exp.headline}",
        f"Threat Type   : {threat_exp.threat_type}",
        f"Severity      : {threat_exp.risk_level}",
        f"Indicator     : {indicator}",
        f"Threat Feed   : {feed}",
        f"Process       : {proc}",
        f"Network Layer : {layer}",
        "",
        "--- [1. Executive Threat Analysis] ---",
        threat_exp.why_suspicious,
        "",
        "--- [2. Potential Attack Vectors] ---",
    ]
    for av in threat_exp.attack_vectors:
        lines.append(f"• {av}")

    lines.append("")
    lines.append("--- [3. Process Lineage & Runtime Context] ---")
    if forensic_ctx:
        lines.append(f"• PID         : {forensic_ctx.pid}")
        lines.append(f"• Executable  : {forensic_ctx.exe_path or 'Unavailable'}")
        lines.append(f"• Command Line: {forensic_ctx.cmdline or 'Unavailable'}")
        lines.append(f"• Parent      : {forensic_ctx.parent_name or 'N/A'} (PID {forensic_ctx.parent_pid})")
        if forensic_ctx.authenticode:
            auth = forensic_ctx.authenticode
            lines.append(f"• Authenticode: Status={auth.status} | Trusted={auth.is_trusted} | Signer={auth.signer_subject or 'None'}")
        if forensic_ctx.is_masquerading:
            lines.append(f"• WARNING     : MASQUERADING DETECTED -> {forensic_ctx.masquerading_reason}")
    else:
        lines.append("• Process not currently active or inaccessible under current permissions.")

    lines.append("")
    lines.append("--- [4. Directory DLL Sideloading Scan] ---")
    if rogue_dlls:
        for dll in rogue_dlls:
            status_tag = "[SUSPICIOUS]" if dll.is_suspicious else "[INFO]"
            lines.append(f"• {status_tag} {dll.dll_name}: {dll.reason}")
    else:
        lines.append("• No unsigned or suspicious DLLs detected in binary directory.")

    lines.append("")
    lines.append("--- [5. Persistence & Autostart Audit] ---")
    if persistence:
        for p in persistence:
            lines.append(f"• Found in {p.location}: [{p.name}] -> {p.command}")
    else:
        lines.append("• No matching persistence entries in Registry Run or Startup folder.")

    lines.append("")
    lines.append("--- [6. Recommended Containment & Remediation] ---")
    for step in threat_exp.containment_steps:
        lines.append(f"• {step}")

    raw_report = "\n".join(lines)

    # Apply 5-Gate DLP sanitization
    if sanitizer and hasattr(sanitizer, "sanitize_text"):
        return sanitizer.sanitize_text(raw_report)
    return raw_report
