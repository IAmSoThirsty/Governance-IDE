# ADR 0001: Governance invariants are mandatory and fail-closed

- **Status:** Accepted
- **Date:** 2026-04-28

## Context

Sovereign operation requires deterministic enforcement of immutable decisions, bound policy evaluation, attributable mutations, and conservative resolution.

## Decision

The runtime SHALL enforce all of the following invariants:

1. Every consequential decision is an immutable signed `DecisionRecord`.
2. Every mutation-capable action requires complete `MutationGovernanceBinding`.
3. Policy enforcement is bound to a persisted evaluation result.
4. Journal/audit trails are append-only and replayable.
5. Rollback is compensation-only and linked to prior decisions.
6. Resolution is default-deny with fixed precedence.

## Consequences

- Missing bindings, missing policy evaluation references, stale capability tokens, or invalid decision signatures result in denial or hard failure.
- Governance failures are surfaced as first-class runtime errors and cannot silently degrade into permissive behavior.
