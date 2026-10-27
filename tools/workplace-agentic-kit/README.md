# Enterprise Workplace Agentic Setup Kit

A zero-dependency, enterprise-grade multi-agent configuration framework designed to drop into **any corporate codebase** (monorepo, microservices, or polyrepo). 

This kit standardizes agentic governance, token cost optimization, spec-driven development, and security boundaries across **Kiro IDE**, **GitHub Copilot**, **Cursor**, and **CLI Terminal Agents** without leaking internal company data or depending on external proprietary frameworks.

---

## 1. Quick Start: 30-Second Automatic Setup

To automatically analyze your corporate codebase, detect microservices/languages, configure token-efficient file scopes, and install steering rules:

1. Copy `setup_enterprise_agent_workspace.py` to the root of your workplace repository.
2. Run the self-contained script (requires Python 3.8+, **zero external pip dependencies**):
   ```bash
   python setup_enterprise_agent_workspace.py
   ```
3. (Optional flags):
   - `--auto` or `-y`: Run non-interactively and keep existing custom configs safe.
   - `--dry-run`: Preview detected microservices and planned configuration files without modifying disk.

---

## 2. Framework Architecture & File Layout

When installed into a workplace repository, the kit creates the following lightweight, standardized structure:

```text
<repository-root>/
├── .kiro/
│   ├── steering/
│   │   └── microservices_token_optimization.md   <-- Token optimization, glob scoping & tiered context
│   ├── prompts/
│   │   └── onboarding_interview.md               <-- Interactive interview prompt for new codebases
│   ├── specs/
│   │   └── template.md                           <-- Spec-Driven Development (SDD) contract template
│   └── service_catalog.json                      <-- Auto-detected service boundaries & language registry
├── .github/
│   └── copilot-instructions.md                   <-- Enterprise Copilot inline & chat system instructions
└── .cursor/rules/                                (Optional)
    └── agentic-governance.mdc                    <-- Glob-scoped rules for Cursor IDE
```

---

## 3. How Each AI Tool Uses This Kit

| Tool / IDE | Target Config Path | Role & Execution Behavior |
| :--- | :--- | :--- |
| **Kiro IDE** | `.kiro/steering/`, `.kiro/prompts/`, `.kiro/specs/` | Governs multi-service agent reasoning, interactive codebase onboarding interviews, and spec-driven execution turns. |
| **GitHub Copilot** | `.github/copilot-instructions.md` | Injects concise (<1,000 token) corporate guardrails into Copilot inline completions and Copilot Chat. |
| **Cursor IDE** | `.cursor/rules/*.mdc` | Applies glob-scoped rules triggered only when modifying designated microservices or critical paths. |
| **CLI / Terminal Agents** | `.kiro/specs/template.md` & `.kiro/steering/*` | Enforces two-turn contract-first development, AST pruning, and terminal test verification gates. |

---

## 4. Key Enterprise Capabilities

### A. Microservice & Monorepo Token Optimization
Corporate monorepos easily burn through context windows and API budgets when agents dump unneeded files into context. This kit enforces **3-tier progressive context disclosure**:
- **Tier 0 (Global Guardrails, <500 tokens)**: Security rules, human-in-the-loop git constraints, anti-slop rules.
- **Tier 1 (Service Catalog, ~800 tokens)**: High-level map of services, API contracts, ports, and team boundaries.
- **Tier 2 (Deep Domain Knowledge, On-Demand)**: Service-specific schemas and logic loaded **only** when files matching that service's glob pattern are modified.

### B. Spec-Driven Development (SDD)
Before writing code across multiple services, the agent must generate a formal specification using [`.kiro/specs/template.md`](./.kiro/specs/template.md). This specification details:
- Service impact matrix and cross-service dependencies
- Type contracts (OpenAPI / Protobuf / TypeScript)
- Security & compliance threat model (AuthN, AuthZ, PII/PCI classifications)
- Step-by-step phased implementation and rollback plan
- Verification test matrix

### C. Zero-Secrets & Air-Gapped Security Boundary
- **Never Push**: AI agents are strictly forbidden from running `git push` or committing directly without explicit human approval.
- **Never Read Secrets**: Hard prohibition against accessing `.env`, `.secrets/*`, `*.pem`, `*.key`, AWS credentials, or CI/CD tokens.
- **Data Minimization (GDPR / Compliance)**: External inputs are treated as hostile; sensitive fields (PII, credentials) are masked before LLM context entry.

---

## 5. Manual Drop-In Installation (Without Script)

If your corporate security policy prohibits executing setup scripts:

1. Copy the `.kiro/` directory into your repository root.
2. Copy the `.github/copilot-instructions.md` file into your repository's `.github/` folder.
3. Open `.kiro/steering/microservices_token_optimization.md` and define your repository's service paths under Section 3 (`Service Scopes & Glob Mappings`).
4. In Kiro or your IDE of choice, run the prompt in [`.kiro/prompts/onboarding_interview.md`](./.kiro/prompts/onboarding_interview.md) to generate your project profile.
