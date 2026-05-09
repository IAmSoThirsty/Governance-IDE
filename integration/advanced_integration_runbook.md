# Advanced Integration Runbook

## Purpose

This runbook operationalizes integration of the Sovereign IDE governed runtime into a larger system while preserving governance invariants and fail-closed behavior.

## Integration prerequisites

- Runtime environment has Python >= 3.12.
- `.env` is present for local use (or equivalent production secret injection path).
- `SOVEREIGN_SIGNING_KEY` is non-placeholder and >= 64 characters.
- Required policy/governance/deployment artifacts exist.

## Mandatory gated sequence

1. **Local bootstrap**
   - Run `bootstrap.local.ps1` as needed for local environment tooling.
2. **All-category E2E matrix gate**
   - Run `scripts/run_e2e_test_matrix.ps1`.
   - Must complete with `Status: pass`.
3. **Pre-production gate**
   - Run `scripts/preprod_inspection.ps1`.
   - Must complete with exit code `0`.
4. **Advanced integration preflight**
   - Run `scripts/advanced_integration_preflight.ps1`.
   - Must return `status: pass` in generated report.
5. **System orchestrator binding**
   - Bind CLI operations from `system_integration_contract.yaml`.
   - Preserve action/role/quorum semantics from policy pack.
6. **Observability and audit binding**
   - Map governance and federation event surface.
   - Ensure append-only storage and replay capability.

## Acceptance criteria

- All tests passing.
- Security/static analysis clean.
- Outside-root mutation denied.
- Hard mutation denied without quorum and approved with quorum.
- Compensation path operational and attributable.
- No destructive rollback path enabled.

## Non-negotiable controls

- Default-deny resolution remains active.
- No unsigned decision records accepted.
- No mutation commit without valid binding.
- No cross-boundary retrieval/federation bypass.

## Escalation conditions

Escalate immediately and block deployment if any of the following occurs:

- Signing key is missing/placeholder/invalid length.
- Journal or decision signature integrity check fails.
- Preflight report returns `status: fail`.
- Mutation boundary checks behave unexpectedly.
