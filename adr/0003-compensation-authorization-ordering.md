# ADR 0003: Compensation authorization must precede side effects

- **Status:** Accepted
- **Date:** 2026-04-28

## Context

Compensation exists to recover safely from prior approved mutations. Executing compensation side effects prior to authorization breaks governance guarantees.

## Decision

- Compensation requests must be evaluated and bound before any compensating function runs.
- Denied compensations produce denied decisions and audit events.
- Compensation side effects execute only after policy authorization passes.

## Consequences

- Unauthorized compensations cannot create side effects.
- Incident responders retain attributable, replayable denial evidence.
