# ADR 0004: Canonical workspace containment and strict federation classification

- **Status:** Accepted
- **Date:** 2026-04-28

## Context

String-prefix path checks and permissive unknown classification handling create cross-boundary bypass risk.

## Decision

- Workspace resource checks use canonical path resolution and strict root containment.
- Prefix matches are forbidden for authorization decisions.
- Federation exchange denies unknown request classifications and invalid rule classifications.

## Consequences

- Path confusion attacks (for example, root-prefix lookalikes) are denied.
- Unknown classification labels fail closed.
- Federation policy misconfiguration is surfaced as explicit denial.
