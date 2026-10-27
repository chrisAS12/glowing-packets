# Enterprise GitHub Copilot Instructions

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
