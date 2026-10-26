# Microservices & Monorepo Token Optimization Steering Rule

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

## 3. Glob-Scoped File Matching & Boundary Isolation

Agents must load service-specific context **only** when working on matching file paths. Under no circumstances should an agent read source files from Service B while implementing a feature in Service A, unless verifying an explicit shared contract.

### Default Service Scope Mapping

| Service Name | Path Glob (`fileMatch`) | Allowed Cross-Service Reads | Prohibited Reads |
| :--- | :--- | :--- | :--- |
| **Auth / Identity** | `services/auth/**`, `apps/auth/**` | `packages/contracts/**` | Payment, Billing, Search logic |
| **Billing / Payment** | `services/billing/**`, `apps/billing/**` | `packages/contracts/**` | Customer analytics, notification logic |
| **Core API / Gateway** | `services/gateway/**`, `apps/gateway/**` | All public service schemas | Service internal database implementations |
| **Shared Libraries** | `packages/*/**`, `libs/*/**` | None (pure, self-contained utilities) | Service-specific business logic |

### Rules of Engagement for Scoped Edits:
- **Rule 1 (Boundary Respect)**: If editing files inside `services/auth/`, do not inspect internal implementations of `services/payment/`. Consult only the shared contract package or API specification.
- **Rule 2 (Contract First)**: If a cross-service change is required, modify the shared contract/schema first, then update consumers in separate, isolated turns.

---

## 4. Top 10 Token-Cost Optimization Strategies

1. **AST & Interface Pruning**:
   - Extract and read function signatures, type definitions, and public class methods instead of loading 2,000-line implementation files.
   - Example: Read `auth_service.pyi` or TypeScript declaration files rather than entire handler implementations.

2. **Schema-First Design (Contract Freeze)**:
   - Always define or confirm data structures (Pydantic, Zod, OpenAPI, Protobuf) before writing business logic. This prevents multi-turn hallucination fixes.

3. **Prefix Stability & KV Prompt Caching**:
   - Maintain static system prompts and immutable guardrails at the top of the context window.
   - Dynamic user prompts and ephemeral diffs must be placed at the end. This maximizes provider KV-cache hits (80–90% cost reduction on Anthropic, Gemini, and OpenAI).

4. **Negative Prompting Against Full File Rewrites**:
   - Instruct the model: *"Output only targeted diffs or surgical modifications. Do not rewrite unmodified companion functions."*

5. **Exclusion of High-Token Noise**:
   - Never ingest package lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `Cargo.lock`, `poetry.lock`), compiled binaries, generated OpenAPI stubs, or build artifacts (`dist/`, `build/`, `target/`).

6. **Subagent Cognitive Tiering**:
   - **Tier 1 (Scouting / Grep / Test Execution)**: Delegate to fast, economical models (e.g., Claude Haiku, GPT-4o-mini, Gemini Flash).
   - **Tier 2 (Architectural Design & Critical Diffs)**: Reserve frontier models (Claude Sonnet, GPT-4o) exclusively for system design and complex multi-file logic.

7. **Two-Turn Planning Turnaround**:
   - For changes touching $\ge 2$ files, Turn 1 must produce a compact plan (<300 tokens) listing touched paths and type contracts. Code generation is blocked until Turn 2.

8. **Directory Tree Filtering**:
   - Limit file tree exploration depth to 2 levels. Do not run unbounded recursive tree dumps.

9. **Stateless Subagent Isolation**:
   - Run subagents in ephemeral, clean contexts so conversational history from previous tasks does not inflate token consumption.

10. **Targeted Unit Test Verification**:
    - Run only tests directly associated with the modified service (`pytest services/auth/tests/` instead of running the entire monorepo suite).

---

## 5. Definition of Done for Enterprise Changes

Every agent code turn must satisfy:
- [ ] No files outside the target microservice glob were modified without an approved shared contract.
- [ ] No secrets, credentials, or internal environment variables were read or exposed.
- [ ] Functions remain under 40 lines with maximum 2 nesting levels.
- [ ] Explicit static types are declared for all new signatures.
- [ ] Targeted microservice test suite passes cleanly.
- [ ] No `git push` was executed; changes are staged for human review.
