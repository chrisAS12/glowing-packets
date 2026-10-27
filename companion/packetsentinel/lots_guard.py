"""
Living Off Trusted Sites (LOTS) Exfiltration Guard for PacketSentinel.

Correlates process identity (browser vs script interpreter / LOLBIN) against
known trusted cloud services and webhooks abused by info-stealers and C2 channels.
Zero outbound network calls - pure offline correlation logic.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

_BEARER_TOKEN_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9_\-\.\=\+]{8,}")
_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(api[_-]?key|bot[_-]?token|access[_-]?token|auth[_-]?token|secret|password|bearer)\s*[:=]\s*['\"]?[A-Za-z0-9_\-\.]{8,}['\"]?"
)


def redact_sensitive_tokens(text: str) -> str:
    """Redact Bearer authorization tokens, API keys, and sensitive parameters."""
    if not text or not isinstance(text, str):
        return ""
    scrubbed = _BEARER_TOKEN_RE.sub("Bearer [REDACTED_TOKEN]", text)
    return _SENSITIVE_KEY_RE.sub(r"\1=[REDACTED_SECRET]", scrubbed)


@dataclass(frozen=True)
class LOTSEndpoint:
    """Living Off Trusted Sites destination endpoint definition."""

    domain_suffix: str
    category: str
    severity: str


@dataclass(frozen=True)
class LOTSRiskResult:
    """Security assessment result for a process connecting to a LOTS endpoint."""

    is_threat: bool
    severity: str
    reason: str
    category: str
    matched_domain: str = ""


LOTS_ENDPOINTS: Tuple[LOTSEndpoint, ...] = (
    LOTSEndpoint("api.telegram.org", "webhook", "high"),
    LOTSEndpoint("discord.com", "webhook", "medium"),
    LOTSEndpoint("discordapp.com", "webhook", "medium"),
    LOTSEndpoint("trycloudflare.com", "tunnel", "high"),
    LOTSEndpoint("ngrok-free.app", "tunnel", "high"),
    LOTSEndpoint("ngrok.io", "tunnel", "high"),
    LOTSEndpoint("webhook.site", "webhook", "high"),
    LOTSEndpoint("transfer.sh", "file_drop", "high"),
    LOTSEndpoint("file.io", "file_drop", "high"),
    LOTSEndpoint("catbox.moe", "file_drop", "medium"),
    LOTSEndpoint("pastebin.com", "paste_service", "medium"),
    LOTSEndpoint("pipedream.net", "webhook", "high"),
    LOTSEndpoint("hookdeck.com", "webhook", "high"),
    LOTSEndpoint("requestbin.com", "webhook", "high"),
    LOTSEndpoint("paste.ee", "paste_service", "medium"),
)

KNOWN_BROWSERS: frozenset[str] = frozenset(
    {
        "chrome.exe",
        "chrome",
        "firefox.exe",
        "firefox",
        "msedge.exe",
        "msedge",
        "brave.exe",
        "brave",
        "safari",
        "opera.exe",
        "opera",
        "vivaldi.exe",
        "vivaldi",
        "arc.exe",
        "arc",
    }
)

KNOWN_SCRIPT_LOLBINS: frozenset[str] = frozenset(
    {
        "powershell.exe",
        "pwsh",
        "cmd.exe",
        "bash",
        "sh",
        "zsh",
        "python.exe",
        "python",
        "python3",
        "node.exe",
        "node",
        "wscript.exe",
        "cscript.exe",
        "curl.exe",
        "curl",
        "wget",
        "certutil.exe",
        "bitsadmin.exe",
        "rundll32.exe",
        "mshta.exe",
    }
)

PACKAGE_MANAGERS: frozenset[str] = frozenset(
    {
        "npm.exe",
        "npm",
        "npm.cmd",
        "pnpm.exe",
        "pnpm",
        "pnpm.cmd",
        "yarn.exe",
        "yarn",
        "yarn.cmd",
        "pip.exe",
        "pip",
        "pip3.exe",
        "pip3",
        "poetry.exe",
        "poetry",
        "cargo.exe",
        "cargo",
        "gem.exe",
        "gem",
        "go.exe",
        "go",
        "mvn.exe",
        "mvn",
        "gradle.exe",
        "gradle",
    }
)

LEGITIMATE_PACKAGE_REGISTRIES: frozenset[str] = frozenset(
    {
        "npmjs.org",
        "npmjs.com",
        "yarnpkg.com",
        "pypi.org",
        "pythonhosted.org",
        "crates.io",
        "github.com",
        "githubusercontent.com",
        "golang.org",
        "pkg.go.dev",
        "rubygems.org",
        "maven.org",
        "apache.org",
        "nuget.org",
    }
)

RECOGNIZED_AI_PROVIDERS: frozenset[str] = frozenset(
    {
        "openai.com",
        "api.openai.com",
        "anthropic.com",
        "api.anthropic.com",
        "googleapis.com",
        "generativelanguage.googleapis.com",
        "githubcopilot.com",
        "copilot-proxy.githubusercontent.com",
        "azure.com",
        "openai.azure.com",
    }
)

SHADOW_AI_GATEWAYS: frozenset[str] = frozenset(
    {
        "openrouter.ai",
        "api.groq.com",
        "groq.com",
        "together.xyz",
        "api.together.xyz",
        "deepseek.com",
        "api.deepseek.com",
        "aimlapi.com",
        "hyperbolic.xyz",
        "replicate.com",
        "api.mistral.ai",
        "mistral.ai",
        "anyscale.com",
        "fireworks.ai",
        "cohere.ai",
        "api.cohere.ai",
    }
)

POPULAR_PYPI_PACKAGES: frozenset[str] = frozenset(
    {
        "requests",
        "urllib3",
        "numpy",
        "pandas",
        "scipy",
        "torch",
        "tensorflow",
        "flask",
        "django",
        "fastapi",
        "pydantic",
        "cryptography",
        "boto3",
        "pytest",
        "httpx",
        "aiohttp",
        "pillow",
        "openai",
        "anthropic",
        "transformers",
        "scikit-learn",
        "setuptools",
        "wheel",
        "pip",
    }
)

POPULAR_NPM_PACKAGES: frozenset[str] = frozenset(
    {
        "express",
        "lodash",
        "axios",
        "react",
        "react-dom",
        "next",
        "typescript",
        "vue",
        "chalk",
        "commander",
        "glob",
        "fs-extra",
        "moment",
        "dotenv",
        "webpack",
        "tailwindcss",
        "cors",
        "jsonwebtoken",
    }
)

HALLUCINATION_PREFIXES: Tuple[str, ...] = ("python-", "py-", "node-", "lib-")
HALLUCINATION_SUFFIXES: Tuple[str, ...] = (
    "-python",
    "-py",
    "-js",
    "-lib",
    "-helper",
    "-client-v2",
    "-extended",
    "-auth-helper",
)


@dataclass(frozen=True)
class SlopsquatRiskResult:
    """Security assessment for AI-hallucinated or typosquatted packages."""

    is_suspicious: bool
    severity: str  # "HIGH", "MEDIUM", "LOW"
    reason: str
    package_name: str
    ecosystem: str
    similar_popular_package: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_suspicious": self.is_suspicious,
            "severity": self.severity,
            "reason": self.reason,
            "package_name": self.package_name,
            "ecosystem": self.ecosystem,
            "similar_popular_package": self.similar_popular_package,
        }


def _damerau_levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Damerau-Levenshtein distance (including adjacent transposition)."""
    d: Dict[Tuple[int, int], int] = {}
    len1 = len(s1)
    len2 = len(s2)
    for i in range(-1, len1 + 1):
        d[(i, -1)] = i + 1
    for j in range(-1, len2 + 1):
        d[(-1, j)] = j + 1

    for i in range(len1):
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            d[(i, j)] = min(
                d[(i - 1, j)] + 1,
                d[(i, j - 1)] + 1,
                d[(i - 1, j - 1)] + cost,
            )
            if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + 1)

    return d[(len1 - 1, len2 - 1)]


def check_ai_package_safety(
    package_name: str,
    ecosystem: str = "pypi",
) -> SlopsquatRiskResult:
    """
    Validate whether a package name matches known AI hallucination patterns (slopsquatting),
    prefix/suffix variations of top libraries, or edit-distance 1 typosquats.
    """
    if not package_name or not isinstance(package_name, str):
        return SlopsquatRiskResult(
            is_suspicious=False,
            severity="LOW",
            reason="Empty package name",
            package_name="",
            ecosystem=ecosystem,
        )

    clean_pkg = package_name.strip().lower()
    popular_set = POPULAR_PYPI_PACKAGES if ecosystem.lower() == "pypi" else POPULAR_NPM_PACKAGES

    # 1. Exact legitimate top package
    if clean_pkg in popular_set:
        return SlopsquatRiskResult(
            is_suspicious=False,
            severity="LOW",
            reason=f"Verified top-tier {ecosystem.upper()} package.",
            package_name=clean_pkg,
            ecosystem=ecosystem,
        )

    # 2. Check for prefix spoofing (e.g., python-requests instead of requests)
    for pfx in HALLUCINATION_PREFIXES:
        if clean_pkg.startswith(pfx):
            candidate = clean_pkg[len(pfx) :]
            if candidate in popular_set:
                return SlopsquatRiskResult(
                    is_suspicious=True,
                    severity="HIGH",
                    reason=(
                        f"AI hallucination / slopsquatting pattern detected: '{clean_pkg}' "
                        f"mimics canonical library '{candidate}' with '{pfx}' prefix. "
                        f"Did you mean to install '{candidate}'?"
                    ),
                    package_name=clean_pkg,
                    ecosystem=ecosystem,
                    similar_popular_package=candidate,
                )

    # 3. Check for suffix spoofing (e.g., requests-python or express-lib)
    for sfx in HALLUCINATION_SUFFIXES:
        if clean_pkg.endswith(sfx):
            candidate = clean_pkg[: -len(sfx)]
            if candidate in popular_set:
                return SlopsquatRiskResult(
                    is_suspicious=True,
                    severity="HIGH",
                    reason=(
                        f"AI hallucination / slopsquatting pattern detected: '{clean_pkg}' "
                        f"mimics canonical library '{candidate}' with '{sfx}' suffix. "
                        f"Did you mean to install '{candidate}'?"
                    ),
                    package_name=clean_pkg,
                    ecosystem=ecosystem,
                    similar_popular_package=candidate,
                )

    # 4. Check for 1-character typo-squats or character swaps (transpositions)
    for pop in popular_set:
        if abs(len(clean_pkg) - len(pop)) <= 1:
            dist = _damerau_levenshtein_distance(clean_pkg, pop)
            if dist == 1:
                return SlopsquatRiskResult(
                    is_suspicious=True,
                    severity="HIGH",
                    reason=(
                        f"Typosquat alert: '{clean_pkg}' is 1 typo/swap character away from "
                        f"widely used package '{pop}'. Verify spelling before installing."
                    ),
                    package_name=clean_pkg,
                    ecosystem=ecosystem,
                    similar_popular_package=pop,
                )

    return SlopsquatRiskResult(
        is_suspicious=False,
        severity="LOW",
        reason="No known hallucination or typosquat patterns detected.",
        package_name=clean_pkg,
        ecosystem=ecosystem,
    )


def check_ai_egress_risk(
    process_name: str,
    domain: str,
    port: int = 443,
) -> Optional[LOTSRiskResult]:
    """
    Check if a process is sending outbound telemetry to unapproved Shadow AI model endpoints.
    """
    if not (1 <= port <= 65535):
        return None
    norm_dom = normalize_domain_for_lots(domain)
    if not norm_dom:
        return None

    # Check if domain matches any known Shadow AI endpoints
    for shadow_endpoint in SHADOW_AI_GATEWAYS:
        if norm_dom == shadow_endpoint or norm_dom.endswith(f".{shadow_endpoint}"):
            proc_base = normalize_process_name(process_name) or "unknown"
            return LOTSRiskResult(
                is_threat=True,
                severity="HIGH",
                reason=(
                    f"Shadow AI egress detected: Process '{proc_base}' communicating with "
                    f"unvetted AI model gateway '{norm_dom}'"
                ),
                category="shadow_ai_egress",
                matched_domain=norm_dom,
            )
    return None


def normalize_domain_for_lots(raw_domain: str) -> str:
    """Normalize domain by trimming whitespace, trailing/leading dots, and lowercasing."""
    if not raw_domain or not isinstance(raw_domain, str):
        return ""
    # Strip leading/trailing whitespace and dots to canonicalize FQDN representations
    cleaned = raw_domain.strip().strip(".").lower()
    if len(cleaned) > 253 or "." not in cleaned:
        return ""
    return cleaned


def normalize_process_name(process_name: str) -> str:
    """Extract lowercase executable basename without path components."""
    if not process_name or not isinstance(process_name, str):
        return ""
    # Normalize Windows backslashes and POSIX forward slashes cross-platform
    cleaned = process_name.strip().replace("\\", "/")
    return cleaned.rsplit("/", 1)[-1].lower()


def find_matching_lots_endpoint(domain: str) -> Optional[LOTSEndpoint]:
    """Find matching LOTS endpoint using exact match or subdomain suffix match."""
    normalized = normalize_domain_for_lots(domain)
    if not normalized:
        return None
    for endpoint in LOTS_ENDPOINTS:
        suffix = endpoint.domain_suffix
        if normalized == suffix or normalized.endswith(f".{suffix}"):
            return endpoint
    return None


def is_known_browser(process_name: str) -> bool:
    """Check if process basename is a recognized interactive desktop browser."""
    proc = normalize_process_name(process_name)
    return proc in KNOWN_BROWSERS


def is_known_script_lolbin(process_name: str) -> bool:
    """Check if process basename is a known script interpreter or LOLBIN."""
    proc = normalize_process_name(process_name)
    return proc in KNOWN_SCRIPT_LOLBINS


def is_package_manager_process(process_name: str) -> bool:
    """Check if process basename is a known developer package manager."""
    proc = normalize_process_name(process_name)
    return proc in PACKAGE_MANAGERS


def is_legitimate_registry_domain(domain: str) -> bool:
    """Check if destination domain belongs to an official package registry or developer code host."""
    norm = normalize_domain_for_lots(domain)
    if not norm:
        return False
    for reg in LEGITIMATE_PACKAGE_REGISTRIES:
        if norm == reg or norm.endswith(f".{reg}"):
            return True
    return False


def check_supply_chain_risk(
    process_name: str,
    domain: str,
    port: int = 443,
) -> Optional[LOTSRiskResult]:
    """
    Evaluate if a developer package manager or build tool is connecting to an
    unverified external domain (potential malicious postinstall hook or setup.py exfiltration).
    """
    if not is_package_manager_process(process_name):
        return None

    norm_dom = normalize_domain_for_lots(domain)
    if not norm_dom:
        return None

    # Official package registries and code repos are expected egress
    if is_legitimate_registry_domain(norm_dom):
        return None

    # Check if connecting to a known LOTS exfiltration service (webhook, tunnel, pastebin)
    lots_match = find_matching_lots_endpoint(norm_dom)
    proc_base = normalize_process_name(process_name)
    if lots_match:
        return LOTSRiskResult(
            is_threat=True,
            severity="CRITICAL",
            reason=f"Supply-chain exfiltration alert: Package manager '{proc_base}' connecting to {lots_match.category} endpoint '{norm_dom}'",
            category=f"supply_chain_{lots_match.category}",
            matched_domain=norm_dom,
        )

    return LOTSRiskResult(
        is_threat=True,
        severity="HIGH",
        reason=f"Supply-chain egress alert: Package manager '{proc_base}' contacting non-registry domain '{norm_dom}'",
        category="supply_chain_unverified_egress",
        matched_domain=norm_dom,
    )


def check_lots_risk(
    process_name: str,
    domain: str,
    port: int = 443,
) -> Optional[LOTSRiskResult]:
    """
    Evaluate if outbound connection is an exfiltration attempt over trusted services.
    Returns None for benign browser activity or unmatched domains.
    Returns LOTSRiskResult with HIGH severity for scripts/LOLBINs and MEDIUM for others.
    """
    if not (1 <= port <= 65535):
        return None

    endpoint = find_matching_lots_endpoint(domain)
    if endpoint is None:
        return None

    if is_known_browser(process_name):
        return None

    proc_base = normalize_process_name(process_name) or "unknown"
    normalized_domain = normalize_domain_for_lots(domain)

    if is_known_script_lolbin(process_name):
        return LOTSRiskResult(
            is_threat=True,
            severity="HIGH",
            reason=f"Script interpreter/LOLBIN '{proc_base}' contacting {endpoint.category} endpoint '{normalized_domain}'",
            category=endpoint.category,
            matched_domain=normalized_domain,
        )

    return LOTSRiskResult(
        is_threat=True,
        severity="MEDIUM",
        reason=f"Non-browser process '{proc_base}' contacting {endpoint.category} endpoint '{normalized_domain}'",
        category=endpoint.category,
        matched_domain=normalized_domain,
    )


def format_lots_alert(
    result: LOTSRiskResult,
    pid: int,
    process_name: str,
    domain: str,
    cmdline: Optional[str] = None,
) -> str:
    """Format human-readable alert string for LOTS endpoint detection with token redaction."""
    safe_proc = redact_sensitive_tokens(process_name)
    proc_desc = f"{safe_proc} (PID: {pid})" if pid > 0 else safe_proc
    safe_domain = redact_sensitive_tokens(domain)
    safe_reason = redact_sensitive_tokens(result.reason)
    msg = (
        f"[LOTS ALERT - {result.severity}] Process '{proc_desc}' contacted "
        f"{result.category} endpoint '{safe_domain}' - {safe_reason}"
    )
    if cmdline:
        safe_cmd = redact_sensitive_tokens(cmdline)
        msg += f" | Command: {safe_cmd}"
    return msg
