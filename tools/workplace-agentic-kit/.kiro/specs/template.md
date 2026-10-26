# Feature Specification: [Feature Name]

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
| `services/auth` | `services/auth/src/...` | Edit | None (Backward-compatible additive change) |
| `packages/contracts` | `packages/contracts/proto/...` | New schema | Minor (New RPC endpoint added) |

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
service BillingService {
  rpc ProcessRefund (RefundRequest) returns (RefundResponse);
}

message RefundRequest {
  string transaction_id = 1;
  int64 amount_cents = 2;
  string reason = 3;
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
| **Unit Test** | `services/<service>/tests/unit/...` | 100% pass, 0 regressions | `npm test` or `pytest` |
| **Integration Test**| `services/<service>/tests/integration/...` | DB transactions rollback cleanly | `npm run test:integration` |
| **Contract Test** | `packages/contracts/tests/...` | Consumer-driven contract passes | `npm run test:pact` |

---

## 7. Rollback & Contingency Plan

- **Feature Flag Key**: `feature_flag_<feature_name>` (defaults to `false`).
- **Rollback Trigger**: Error rate $> 0.5\%$ or latency p99 $> 250\text{ms}$ on deployment.
- **Rollback Procedure**: Disable feature flag in configuration console; no database schema revert required.

---

## 8. Human Review & Sign-Off Checklist

- [ ] Senior Engineer / Tech Lead Review: `[Approved by: ________]`
- [ ] Security Champion / Auditor Review: `[Approved by: ________]`
- [ ] Automated Test Suite Status: `[GREEN / PASSED]`
