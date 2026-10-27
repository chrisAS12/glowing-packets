#!/usr/bin/env python3
"""
setup_enterprise_agent_workspace.py — Zero-Dependency Enterprise Agentic Setup Initializer.

This standalone utility automates the setup of AI agentic steering, token-cost optimization,
interactive onboarding prompts, and spec-driven development across any corporate repository
(monorepo, polyrepo, or standalone service).

Compatible with: Kiro IDE, GitHub Copilot, Cursor, and CLI Terminal Agents.

Zero external dependencies: Requires only Python 3.8+ Standard Library.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# ==============================================================================
# 1. Embedded Standard Templates (Zero External File Dependencies)
# ==============================================================================

TEMPLATE_COPILOT_INSTRUCTIONS = """# Enterprise GitHub Copilot Instructions

These instructions govern GitHub Copilot completions, chat interactions, and Agent mode across all repositories in this enterprise organization.

---

## 1. Human-in-the-Loop & Git Invariants (NON-NEGOTIABLE)
- **Zero Push / Zero Auto-Commit**: Copilot is strictly forbidden from executing `git push` or auto-committing to git repositories. All changes must remain as staged/unstaged working directory diffs for human developer review.
- **Two-Turn Planning Gate**: On any modification affecting 2 or more files, Copilot must FIRST output a concise plan (<250 words) listing:
  1. Files to be modified.
  2. Data contract / schema changes.
  3. Risk assessment.
  Copilot must wait for user approval before writing code.

---

## 2. Zero-Secrets & Compliance Boundary
- **Strict Blacklist**: NEVER read, grep, reference, or print contents of:
  - `.env`, `.env.*`, `*.pem`, `*.key`, `id_rsa`, `known_hosts`
  - Cloud credentials (`~/.aws/credentials`, `~/.azure/`, `~/.kube/config`)
  - CI/CD tokens, database connection strings, or enterprise secrets.
- **Data Minimization**: Never include customer PII, real corporate emails, internal IP addresses, or production database dumps in chat prompts or code examples. Always use generic dummy identifiers (e.g., `user@example.com`, `10.0.0.1`, `sk-dummy-token-00000000`).

---

## 3. Microservice Isolation & Token Efficiency
- **Honor Service Boundaries**: If editing code within `services/<service-name>/`, do NOT read or import internal implementation files from adjacent services. Use only public interfaces, shared packages, or published API schemas.
- **Progressive Context Disclosure**: Do not dump entire source files into chat. Output only the targeted diff or the specific refactored function.
- **Prune High-Token Noise**: Do not parse or reproduce package lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `Cargo.lock`, `poetry.lock`), generated code, or build artifacts.

---

## 4. Engineering Standards & Anti-Slop Discipline
- **Function Size**: Maximum 40 lines per function. Break multi-responsibility routines into single-purpose helpers.
- **Nesting Depth**: Maximum 2 levels of indentation. Use early returns and guard clauses to eliminate nested `if/else` ladders.
- **Strict Static Typing**: Explicit types for all function arguments, return values, and data structures. Never use untyped dictionaries, `any`, or `interface{}` where a concrete type can be declared.
- **Zero Ghost Code**: Never leave `TODO` stubs, placeholder passes, commented-out dead code, or pass-through wrappers.
- **Intentional Comments**: Do not write redundant comments stating what the code obviously does. Reserve comments strictly for non-obvious security constraints, RFC algorithms, or hardware/OS interop boundaries.

---

## 5. Verification Before Hand-off
- Always run or propose a targeted test command proving the change works before concluding a turn.
- Ensure all newly created code passes the project linter and static type checker.
"""

TEMPLATE_ONBOARDING_PROMPT = """# Enterprise Codebase Onboarding & Architectural Interview

> **Prompt Role**: Principal Enterprise Architect & Agentic Onboarding Specialist.
> **Objective**: Conduct an interactive, structured interview to rapidly catalog a new or legacy enterprise codebase, establish service boundaries, configure token-efficient scopes, and generate the project profile without leaking proprietary secrets.

---

## Instructions for the AI Agent

When the developer initiates onboarding (e.g., typing `/onboard`, "Onboard this codebase", or loading this prompt):

1. **Do NOT dump huge raw files or read secrets**.
2. Execute **Phase 1 (Automated Reconnaissance)** silently.
3. Present **Phase 2 (Interactive Interview)** to the developer. Ask the questions clearly and wait for user answers.
4. Synthesize answers in **Phase 3 (Profile & Service Catalog Generation)**.
5. Confirm final personas in **Phase 4 (Persona Activation)**.

---

## Phase 1: Silent Automated Reconnaissance

Before prompting the user, scan the repository root to detect:
1. **Repository Typology**: Monorepo (Turborepo, Nx, Lerna, Go Workspaces, Cargo Workspace, Maven Multi-module) or Single Service / Polyrepo.
2. **Languages & Frameworks**:
   - Python (`pyproject.toml`, `requirements.txt`, `Pipfile`)
   - TypeScript / Node.js (`package.json`, `tsconfig.json`)
   - Go (`go.mod`, `go.work`)
   - Rust (`Cargo.toml`)
   - Java / Kotlin (`pom.xml`, `build.gradle`, `build.gradle.kts`)
   - C# / .NET (`*.sln`, `*.csproj`)
3. **Container & Infrastructure**: `Dockerfile`, `docker-compose.yml`, Kubernetes manifests, Terraform, Helm charts.
4. **CI/CD & Testing**: `.github/workflows/`, `.gitlab-ci.yml`, Jenkinsfile, test runners (Pytest, Jest, Vitest, Go test).
5. **Existing Service Directories**: Identify folders under `services/`, `apps/`, `packages/`, `modules/`, or `src/`.

---

## Phase 2: Interactive Developer Interview

Present the user with the following structured questionnaire:

```markdown
### 🏢 Enterprise Codebase Onboarding Interview

I have scanned your repository structure and detected the following baseline:
- **Repository Pattern**: [Monorepo / Microservices / Standalone Service]
- **Primary Languages**: [e.g., Go, TypeScript, Python]
- **Detected Services / Modules**: [List detected service paths]

To finalize your agentic steering rules and token optimization boundaries, please answer these 5 key architecture questions:

1. **Business Domain & Primary Workflows**:
   What is the core business objective of this system, and what are the 2-3 most critical transactional flows (e.g., user signup, checkout processing, data ingestion)?

2. **Inter-Service Communication & Contracts**:
   How do these services communicate with each other?
   - [ ] Synchronous REST / HTTP JSON
   - [ ] gRPC / Protocol Buffers
   - [ ] GraphQL Federation
   - [ ] Asynchronous Events (Kafka, RabbitMQ, SQS/SNS)
   - [ ] In-process direct library calls

3. **Authentication, Authorization & Security Boundaries**:
   - What mechanism secures inter-service and edge traffic (e.g., OAuth2 / OIDC, JWT, mTLS, API Keys)?
   - Are there specific compliance boundaries to observe (e.g., PCI-DSS cardholder data, HIPAA PHI, GDPR PII)?

4. **Data Persistence & Migrations**:
   - What databases and state stores are used (e.g., PostgreSQL, Redis, DynamoDB, MongoDB)?
   - How are database migrations managed (e.g., Flyway, Liquibase, Prisma, Alembic, raw SQL)?

5. **Local Developer Verification & Testing**:
   - What is the canonical command to run unit tests for a single service?
   - Is there a local mock environment (e.g., `docker compose up -d`, LocalStack, testcontainers)?
```

---

## Phase 3: Profile & Service Catalog Generation

Once the user provides answers, synthesize the findings into `.kiro/service_catalog.json` and update `.kiro/steering/microservices_token_optimization.md`.

---

## Phase 4: Persona Activation

Conclude the onboarding session by declaring the active role personas:
- **Lead Systems Architect**: Focuses on contract stability, schema design, and microservice decoupling.
- **Enterprise Security Auditor**: Enforces secret blacklists, authentication checks, and input validation.
- **Implementation Specialist**: Produces clean, typed code adhering strictly to the `<40 lines` per function rule.
"""

TEMPLATE_SPEC_TEMPLATE = r"""# Feature Specification: [Feature Name]

> **Spec Status**: `DRAFT` | `IN_REVIEW` | `APPROVED` | `IMPLEMENTED`  
> **Target Services**: `services/<service-a>`, `services/<service-b>`  
> **Author / Agent**: [Developer / Agent Persona]  
> **Target Branch**: `feature/<feature-name>`  
> **Date**: YYYY-MM-DD  

---

## 1. Executive Summary & Business Justification

- **Problem Statement**: What problem does this change solve? Why is it needed now?
- **User Story**: *As a [role], I want to [action], so that [outcome].*
- **Success Metrics / KPIs**: How do we measure success (e.g., latency reduction, error rate under 0.1%, transaction volume)?

---

## 2. Microservice & Architecture Impact Matrix

| Service / Package | Path | Type of Modification (New / Edit / Deprecate) | Breaking Change Risk (None / Minor / Major) |
| :--- | :--- | :--- | :--- |
| `services/<name>` | `services/<name>/...` | Edit | None (Backward-compatible additive change) |
| `packages/contracts` | `packages/contracts/...` | New schema | Minor (New RPC endpoint added) |

### Boundary Integrity Checklist:
- [ ] No unapproved cross-service database access.
- [ ] All cross-service communication occurs via published APIs or event topics.
- [ ] Schema changes are backward-compatible.

---

## 3. Security, Privacy & Compliance Threat Model

Evaluate against enterprise threat vectors before writing code:

- **Authentication & Authorization**: How is the caller verified? Is RBAC/ABAC enforced at the endpoint level?
- **Data Classification & PII**: Does this feature touch PII, payment card data (PCI), or sensitive health data (HIPAA)? If so, are fields encrypted or masked?
- **Input Validation**: Are payload schemas, path parameters, and query parameters strictly validated against bounds and regex?
- **Audit Logging**: Are security-relevant events (logins, privilege escalations, financial transactions) logged with correlation IDs without logging raw passwords/tokens?

---

## 4. API & Data Contract Specifications

### A. Endpoint / RPC Contract
```protobuf
// Example: New gRPC service method or OpenAPI snippet
service ExampleService {
  rpc ExecuteTask (TaskRequest) returns (TaskResponse);
}
```

### B. Database Schema / Migration Impact
- **New Tables / Columns**: List additions and index strategies.
- **Migration Strategy**: Zero-downtime expand-and-contract migration (no table locks).

---

## 5. Phased Implementation Plan

- [ ] **Phase 1: Contract & Interface Definition**
  - Define protobuf / OpenAPI / TypeScript interfaces in shared packages.
  - Verify backward compatibility.
- [ ] **Phase 2: Core Domain Logic & Unit Tests**
  - Implement business logic in target service.
  - Keep functions under 40 lines and nesting under 2 levels.
  - Add isolated unit tests.
- [ ] **Phase 3: Integration & Dependency Wiring**
  - Connect database repositories, message queues, and external clients.
  - Add component / integration tests with mocks.
- [ ] **Phase 4: Verification & Linting**
  - Run local service test suite.
  - Run static analysis / type checker.

---

## 6. Verification & Test Matrix

| Test Level | Target File / Suite | Pass Criteria | Command |
| :--- | :--- | :--- | :--- |
| **Unit Test** | `services/<service>/tests/unit/...` | 100% pass, 0 regressions | Run service test runner |
| **Integration Test**| `services/<service>/tests/integration/...` | DB transactions rollback cleanly | Run integration suite |
| **Contract Test** | `packages/contracts/tests/...` | Consumer-driven contract passes | Run contract test runner |

---

## 7. Rollback & Contingency Plan

- **Feature Flag Key**: `feature_flag_<feature_name>` (defaults to `false`).
- **Rollback Trigger**: Error rate $> 0.5\%$ or latency p99 $> 250\\text{ms}$ on deployment.
- **Rollback Procedure**: Disable feature flag in configuration console; no database schema revert required.

---

## 8. Human Review & Sign-Off Checklist

- [ ] Senior Engineer / Tech Lead Review: `[Approved by: ________]`
- [ ] Security Champion / Auditor Review: `[Approved by: ________]`
- [ ] Automated Test Suite Status: `[GREEN / PASSED]`
"""

TEMPLATE_CURSOR_RULES = """---
description: Enterprise Agentic Governance and Anti-Slop Architecture Rules
globs: *
alwaysApply: true
---

# Enterprise Agentic Governance Rules

1. Human-in-the-Middle Gate: Never execute `git push` or auto-commit. All diffs must be staged for human review.
2. Two-Turn Planning: For modifications touching >= 2 files, produce an implementation plan on Turn 1 and await approval.
3. Clean Code: Maximum 40 lines per function, maximum 2 nesting levels, explicit static typing everywhere.
4. Boundary Isolation: Never import private code from adjacent microservices without a published contract.
5. Zero Secrets: Never read or output `.env`, `.secrets/*`, `*.pem`, `*.key`, or credentials.
"""


# ==============================================================================
# 2. Automated Microservice & Language Discovery Engine
# ==============================================================================

SERVICE_CONTAINER_DIRS = (
    "services",
    "apps",
    "packages",
    "modules",
    "cmd",
    "src/modules",
    "apis",
    "backend",
    "frontend",
    "components",
    "libs",
)

IGNORE_DIRS = frozenset(
    {
        ".git",
        ".github",
        ".cursor",
        ".kiro",
        ".idea",
        ".vscode",
        "node_modules",
        "target",
        "dist",
        "build",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        "coverage",
    }
)


class ServiceDetector:
    """Detects repository typology, microservice boundaries, languages, and test commands."""

    def __init__(self, root_dir: Path) -> None:
        self.root_dir = root_dir.resolve()

    def detect_repo_type(self) -> str:
        """Determines if the repository is a Monorepo or a Single Service."""
        monorepo_indicators = [
            "turbo.json",
            "nx.json",
            "pnpm-workspace.yaml",
            "lerna.json",
            "go.work",
        ]
        for indicator in monorepo_indicators:
            if (self.root_dir / indicator).exists():
                return "monorepo"

        # Check Cargo workspace
        cargo_path = self.root_dir / "Cargo.toml"
        if cargo_path.exists():
            content = cargo_path.read_text(encoding="utf-8", errors="ignore")
            if "[workspace]" in content:
                return "monorepo"

        # Check Gradle multi-project
        for gradle_file in ("settings.gradle", "settings.gradle.kts"):
            p = self.root_dir / gradle_file
            if p.exists() and "include" in p.read_text(encoding="utf-8", errors="ignore"):
                return "monorepo"

        # Check Maven multi-module
        pom_path = self.root_dir / "pom.xml"
        if pom_path.exists() and "<modules>" in pom_path.read_text(encoding="utf-8", errors="ignore"):
            return "monorepo"

        # Check if container dirs exist with multiple subfolders
        for cdir in SERVICE_CONTAINER_DIRS:
            candidate = self.root_dir / cdir
            if candidate.is_dir():
                subdirs = [p for p in candidate.iterdir() if p.is_dir() and p.name not in IGNORE_DIRS]
                if len(subdirs) >= 1:
                    return "monorepo"

        return "standalone_service"

    def detect_service_details(self, service_dir: Path) -> Dict[str, Any]:
        """Detects language, framework hints, and test runner for a given service directory."""
        languages: List[str] = []
        framework = "standard"
        test_command = "test"
        rel_path = service_dir.relative_to(self.root_dir).as_posix()

        # Check Node.js / TypeScript
        pkg_json = service_dir / "package.json"
        if pkg_json.exists():
            languages.append("typescript" if (service_dir / "tsconfig.json").exists() else "javascript")
            try:
                pkg_data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
                scripts = pkg_data.get("scripts", {})
                if "test" in scripts:
                    test_command = f"npm --prefix {rel_path} test"
                deps = {**pkg_data.get("dependencies", {}), **pkg_data.get("devDependencies", {})}
                if "express" in deps:
                    framework = "express"
                elif "nestjs" in deps or "@nestjs/core" in deps:
                    framework = "nestjs"
                elif "fastify" in deps:
                    framework = "fastify"
                elif "next" in deps:
                    framework = "nextjs"
                elif "react" in deps:
                    framework = "react"
            except Exception:
                pass

        # Check Python
        if (
            (service_dir / "pyproject.toml").exists()
            or (service_dir / "requirements.txt").exists()
            or (service_dir / "Pipfile").exists()
            or list(service_dir.glob("*.py"))
        ):
            languages.append("python")
            test_command = f"pytest {rel_path}"
            if (service_dir / "pyproject.toml").exists():
                text = (service_dir / "pyproject.toml").read_text(encoding="utf-8", errors="ignore")
                if "fastapi" in text:
                    framework = "fastapi"
                elif "django" in text:
                    framework = "django"
                elif "flask" in text:
                    framework = "flask"

        # Check Go
        if (service_dir / "go.mod").exists() or list(service_dir.glob("*.go")):
            languages.append("go")
            test_command = f"go test ./{rel_path}/..."

        # Check Rust
        if (service_dir / "Cargo.toml").exists():
            languages.append("rust")
            test_command = f"cargo test --manifest-path {rel_path}/Cargo.toml"

        # Check Java / Kotlin
        if (service_dir / "pom.xml").exists():
            languages.append("java")
            test_command = f"mvn -f {rel_path}/pom.xml test"
        elif (service_dir / "build.gradle").exists() or (service_dir / "build.gradle.kts").exists():
            languages.append("kotlin" if (service_dir / "build.gradle.kts").exists() else "java")
            test_command = f"./gradlew :{service_dir.name}:test"

        # Check C#
        if list(service_dir.glob("*.csproj")):
            languages.append("csharp")
            test_command = f"dotnet test {rel_path}"

        primary_lang = languages[0] if languages else "generic"

        return {
            "name": service_dir.name,
            "path": rel_path,
            "file_match": f"{rel_path}/**",
            "language": primary_lang,
            "all_languages": languages,
            "framework": framework,
            "test_command": test_command,
            "allowed_cross_reads": ["packages/contracts/**", "packages/proto/**", "packages/types/**"],
        }

    def discover_services(self) -> List[Dict[str, Any]]:
        """Scans the repository and returns catalog entries for each discovered service."""
        services: List[Dict[str, Any]] = []
        found_paths: Set[Path] = set()

        for cdir in SERVICE_CONTAINER_DIRS:
            container = self.root_dir / cdir
            if container.is_dir():
                for item in sorted(container.iterdir()):
                    if item.is_dir() and item.name not in IGNORE_DIRS:
                        services.append(self.detect_service_details(item))
                        found_paths.add(item)

        # If no sub-services found, treat the root repository itself as the service
        if not services:
            services.append(self.detect_service_details(self.root_dir))

        return services


# ==============================================================================
# 3. Dynamic Steering File Assembler
# ==============================================================================

def generate_microservices_steering_md(services: List[Dict[str, Any]]) -> str:
    """Generates microservices_token_optimization.md customized with discovered service scopes."""
    table_rows: List[str] = []
    for svc in services:
        name = svc["name"]
        fmatch = svc["file_match"]
        lang = svc["language"]
        table_rows.append(f"| **{name}** (`{lang}`) | `{fmatch}` | Shared types/contracts | Adjacent service internal models |")

    table_md = "\n".join(table_rows) if table_rows else "| **root** | `**` | None | None |"

    return f"""# Microservices & Monorepo Token Optimization Steering Rule

> **Scope**: All AI agent interactions within multi-service, monorepo, or distributed enterprise codebases.
> **Objective**: Eliminate token waste, prevent context window exhaustion, enforce service boundary isolation, and cut enterprise API costs by up to 90%.

---

## 1. The Enterprise Context Dilemma

In corporate monorepos and multi-service systems, traditional AI prompts face severe failure modes:
1. **Context Window Exhaustion**: Ingesting unrelated microservice code fills the context window, causing models to hallucinate or drop earlier instructions.
2. **Cross-Service Coupling**: Agents make unauthorized edits across service boundaries, breaking interface contracts and domain-driven design (DDD).
3. **Runaway API Costs**: Repeatedly feeding full 5,000-line controller files or giant package lockfiles into frontier models inflates corporate LLM expenses.

---

## 2. The 3-Tier Progressive Disclosure Architecture

To maintain high reasoning quality at minimal token consumption, agents must adhere to **Tiered Context Loading**:

```
┌─────────────────────────────────────────────────────────────┐
│ Tier 0: Global Steering & Security Guardrails (<500 tokens) │
│ - Human-in-the-Loop Git Gate (no git push / auto-commit)    │
│ - Zero-Secrets Boundary (.env, *.pem, credentials blocked)  │
│ - Anti-Slop Code Standards (<40 lines/function, strict types)│
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Tier 1: Service Catalog & Index (~800 tokens)               │
│ - Compact map of services, paths, protocols, and team owners│
│ - Service boundaries and cross-service RPC/event contracts  │
└──────────────────────────────┬──────────────────────────────┘
                               │ (Triggered by file match)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Tier 2: Microservice Deep Knowledge (On-Demand / Scoped)     │
│ - Service-specific schemas (Protobuf, OpenAPI, TypeScript)  │
│ - Local database models, migrations, and unit tests         │
│ - Loaded ONLY for the service currently being modified       │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Discovered Microservices & Glob Scopes

The following scopes are detected for this repository. Agents must limit active context to the matching service directory:

| Service Name | Path Glob (`fileMatch`) | Allowed Cross-Service Reads | Prohibited Reads |
| :--- | :--- | :--- | :--- |
{table_md}

### Rules of Engagement for Scoped Edits:
- **Rule 1 (Boundary Respect)**: When modifying files in a target service glob, do NOT read internal implementations from other service directories. Consult only shared packages or API specifications.
- **Rule 2 (Contract First)**: If a cross-service change is required, modify the shared contract/schema first, then update consumers in separate, isolated turns.

---

## 4. Top 10 Token-Cost Optimization Strategies

1. **AST & Interface Pruning**: Read function signatures and exported type declarations rather than dumping multi-thousand-line implementation files.
2. **Schema-First Design**: Define data structures (Pydantic, Zod, OpenAPI, Protobuf) before writing business logic to prevent multi-turn hallucination fixes.
3. **Prefix Stability & KV Prompt Caching**: Keep system prompts and immutable guardrails at the top of context to achieve 80–90% prompt caching hit rate.
4. **Negative Prompting Against Full File Rewrites**: Instruct models to output only targeted diffs or surgical modifications.
5. **Exclusion of High-Token Noise**: Never ingest package lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `Cargo.lock`, `poetry.lock`), generated code, or build artifacts.
6. **Subagent Cognitive Tiering**: Use fast, economical models for scouting/grep/testing; reserve frontier models exclusively for architecture and complex logic.
7. **Two-Turn Planning Turnaround**: For changes touching >= 2 files, Turn 1 produces a compact plan (<300 tokens). Implementation begins on Turn 2 after approval.
8. **Directory Tree Filtering**: Limit directory exploration depth to 2 levels. Avoid deep recursive tree scans.
9. **Stateless Subagent Isolation**: Run subagents in ephemeral, clean contexts so conversational history does not bloat token consumption.
10. **Targeted Unit Test Verification**: Run only tests directly associated with the modified service path.

---

## 5. Definition of Done for Enterprise Changes

Every agent code turn must satisfy:
- [ ] No files outside the target microservice glob were modified without an approved shared contract.
- [ ] No secrets, credentials, or internal environment variables were read or exposed.
- [ ] Functions remain under 40 lines with maximum 2 nesting levels.
- [ ] Explicit static types are declared for all new signatures.
- [ ] Targeted microservice test suite passes cleanly.
- [ ] No `git push` was executed; changes are staged for human review.
"""


# ==============================================================================
# 4. Conflict Resolution & File Operations
# ==============================================================================

def prompt_user_choice(question: str, default: str) -> str:
    """Prompt user with a question and return answer or default."""
    try:
        val = input(f"\n[?] {question}\n    (default: [{default}]): ").strip()
        return val if val else default
    except (EOFError, KeyboardInterrupt):
        print("\n[!] Setup cancelled by user.")
        sys.exit(0)


def safe_write_file(
    file_path: Path,
    content: str,
    mode: str = "interactive",
    dry_run: bool = False,
) -> str:
    """
    Writes file safely respecting existing content.
    mode: 'interactive', 'auto' (keep existing), 'overwrite'.
    """
    rel = file_path.as_posix()
    if dry_run:
        print(f"[DRY-RUN] Would write: {rel} ({len(content)} bytes)")
        return "dry_run"

    file_path.parent.mkdir(parents=True, exist_ok=True)

    if not file_path.exists():
        file_path.write_text(content, encoding="utf-8")
        print(f"[+] Created: {rel}")
        return "created"

    existing_content = file_path.read_text(encoding="utf-8", errors="ignore")
    if existing_content.strip() == content.strip():
        print(f"[-] Unchanged: {rel}")
        return "unchanged"

    if mode == "auto":
        print(f"[*] Auto-mode: Preserving existing customized file: {rel}")
        return "preserved"
    elif mode == "overwrite":
        file_path.write_text(content, encoding="utf-8")
        print(f"[!] Overwritten: {rel}")
        return "overwritten"

    # Interactive conflict resolution
    print(f"\n[!] Conflict: '{rel}' already exists with custom content.")
    print(f"    Existing: {len(existing_content)} bytes | New template: {len(content)} bytes")
    choice = prompt_user_choice(
        f"Action for {file_path.name}? [k]eep existing (safe), [b]ackup & replace, or [o]verwrite?",
        "k",
    ).lower()

    if choice.startswith("b"):
        bak_file = file_path.with_suffix(file_path.suffix + ".bak")
        shutil.copy2(file_path, bak_file)
        file_path.write_text(content, encoding="utf-8")
        print(f"[+] Backed up to {bak_file.name} and replaced: {rel}")
        return "backup_and_replaced"
    elif choice.startswith("o"):
        file_path.write_text(content, encoding="utf-8")
        print(f"[!] Overwritten: {rel}")
        return "overwritten"
    else:
        print(f"[-] Kept existing: {rel}")
        return "preserved"


def verify_and_patch_gitignore(root_dir: Path, dry_run: bool = False) -> None:
    """Verifies that .gitignore includes common credential patterns; offers to patch if missing."""
    gitignore_path = root_dir / ".gitignore"
    required_ignores = [
        ".env",
        ".env.*",
        "*.pem",
        "*.key",
        "*.pfx",
        ".secrets/",
        "credentials.json",
    ]

    existing = ""
    if gitignore_path.exists():
        existing = gitignore_path.read_text(encoding="utf-8", errors="ignore")

    missing = [pat for pat in required_ignores if pat not in existing]
    if missing:
        patch = "\n# Enterprise Security Blacklist (Added by Agentic Setup)\n" + "\n".join(missing) + "\n"
        if dry_run:
            print(f"[DRY-RUN] Would append security blacklist to .gitignore:\n{patch.strip()}")
        else:
            with open(gitignore_path, "a", encoding="utf-8") as f:
                f.write(patch)
            print("[+] Appended essential security patterns (.env, *.pem, *.key) to .gitignore")


# ==============================================================================
# 5. Main Execution Flow
# ==============================================================================

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Setup enterprise AI agent steering rules, token optimization, and specs for any codebase.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Target repository root path (defaults to current working directory).",
    )
    parser.add_argument(
        "-y",
        "--auto",
        action="store_true",
        help="Run automatically without prompting (preserves existing custom configs safely).",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Force overwrite existing configurations with fresh templates.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview detected services and proposed configuration files without modifying disk.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    root_dir: Path = args.root.resolve()

    print("=" * 72)
    print("  Enterprise Agentic Workspace & Token Optimization Initializer")
    print("  Supports: Kiro IDE | GitHub Copilot | Cursor | CLI Agents")
    print("=" * 72)
    print(f"[*] Target Repository: {root_dir}")

    # 1. Detect Typology & Microservices
    detector = ServiceDetector(root_dir)
    repo_type = detector.detect_repo_type()
    services = detector.discover_services()

    print(f"[*] Repository Pattern: {repo_type.upper()}")
    print(f"[*] Discovered Services / Packages ({len(services)} found):")
    for s in services:
        print(f"    - {s['name']} [{s['language']}] -> {s['path']} (test: {s['test_command']})")

    mode = "interactive"
    if args.overwrite:
        mode = "overwrite"
    elif args.auto:
        mode = "auto"

    # 2. Prepare File Manifest
    kiro_steering_content = generate_microservices_steering_md(services)
    service_catalog_json = json.dumps(
        {
            "repository_type": repo_type,
            "services_count": len(services),
            "services": services,
        },
        indent=2,
    )

    files_to_install = [
        (root_dir / ".kiro" / "steering" / "microservices_token_optimization.md", kiro_steering_content),
        (root_dir / ".kiro" / "prompts" / "onboarding_interview.md", TEMPLATE_ONBOARDING_PROMPT),
        (root_dir / ".kiro" / "specs" / "template.md", TEMPLATE_SPEC_TEMPLATE),
        (root_dir / ".kiro" / "service_catalog.json", service_catalog_json),
        (root_dir / ".github" / "copilot-instructions.md", TEMPLATE_COPILOT_INSTRUCTIONS),
        (root_dir / ".cursor" / "rules" / "agentic-governance.mdc", TEMPLATE_CURSOR_RULES),
    ]

    print("\n[*] Installing Agentic Configuration Bundle...")
    results: Dict[str, int] = {}
    for target_path, content in files_to_install:
        status = safe_write_file(target_path, content, mode=mode, dry_run=args.dry_run)
        results[status] = results.get(status, 0) + 1

    # 3. Security Check (.gitignore verification)
    verify_and_patch_gitignore(root_dir, dry_run=args.dry_run)

    print("\n" + "=" * 72)
    print("  Installation Complete!")
    print("=" * 72)
    print("Installed components:")
    print("  1. Kiro Steering Rules:  .kiro/steering/microservices_token_optimization.md")
    print("  2. Kiro Onboarding:      .kiro/prompts/onboarding_interview.md")
    print("  3. Spec-Driven Dev:      .kiro/specs/template.md")
    print("  4. Service Catalog:      .kiro/service_catalog.json")
    print("  5. GitHub Copilot Rules: .github/copilot-instructions.md")
    print("  6. Cursor IDE Rules:     .cursor/rules/agentic-governance.mdc")
    print("\nNext steps in your workplace IDE:")
    print("  - Kiro: Open any file or trigger the onboarding interview prompt.")
    print("  - Copilot: Chat automatically loads .github/copilot-instructions.md.")
    print("  - Cursor: Rules automatically apply to scoped microservice files.")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
