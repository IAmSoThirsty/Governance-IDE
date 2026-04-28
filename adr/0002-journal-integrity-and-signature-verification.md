# ADR 0002: Verify journal hash chain and decision signatures on hydrate/replay

- **Status:** Accepted
- **Date:** 2026-04-28

## Context

Append-only logs are insufficient if replay accepts tampered records. Integrity must be proven at runtime load and replay time.

## Decision

- Journal entries are sequence-validated and hash-chain-validated.
- Runtime hydration of decision records verifies signer authenticity against unsigned payload.
- Decision chain linkage (`previous_decision_hash`) is validated in replay order.
- Any mismatch raises a hard integrity error.

## Consequences

- Forged or edited journal lines are rejected before use.
- Tampered decision signatures can no longer seed trusted runtime state.
- Recovery requires restoration from trusted backups or approved compensation paths.
