# Sovereign IDE

Governance-first sovereign AI IDE runtime scaffold built from the **Sovereign IDE Blueprint Pack**.

This repository implements a local-first, offline-capable governance core with:

- Immutable, signed decision records
- Full mutation governance bindings for mutation-capable operations
- Policy-evaluation-bound authorization (no local-only bypass)
- Append-only governance journal with replay support
- Compensation-only rollback model
- Retrieval containment and four-channel evidence firewall primitives
- Supply-chain promotion memory with tiered eligibility controls

## Repository layout

- `src/sovereign_ide/` — runtime implementation
- `policies/` — executable policy packs
- `schemas/` — JSON schemas for trust/governance/provenance artifacts
- `adr/` — architecture decision records
- `deployments/` — reference deployment manifests by tier
- `governance/` — enforcement mappings, event taxonomy, failure matrix
- `airgap/` — transfer manifest examples
- `tests/` — invariants and regression tests

## Quick start

- Configure environment/signing material.
  - Copy `.env.example` to `.env` for local runs.
  - `SOVEREIGN_SIGNING_KEY` is mandatory and must be high entropy.
  - Placeholder keys are rejected at runtime.
  - For production, inject signing key via secure secret management.
- Run local bootstrap (Windows/PowerShell):
  - `./bootstrap.local.ps1`
  - Optional full package install: `./bootstrap.local.ps1 -InstallProject`
- Run initialization:
  - `python -m sovereign_ide.cli init`
- Run tests:
  - `python -m unittest discover -s tests -p "test_*.py"`
- Run local quality and readiness gates:
  - `./scripts/local_quality_gate.ps1`
  - `./scripts/preprod_inspection.ps1`
  - `./scripts/advanced_integration_preflight.ps1`

## Pre-production inspection

- Run deterministic readiness checks:
  - `./scripts/preprod_inspection.ps1`
- The inspection enforces signing-key readiness, runs tests, executes governed
  mutation smoke flows, and cleans transient `state/` artifacts.

## Advanced integration

- Integration contract:
  - `integration/system_integration_contract.yaml`
- Integration runbook:
  - `integration/advanced_integration_runbook.md`
- Deterministic advanced preflight gate:
  - `./scripts/advanced_integration_preflight.ps1`
- Generated report:
  - `integration/out/advanced_integration_report.json`

## Project-AI Sovereign Model Server Workshop

- Workshop constitutional artifacts:
  - `workshop/founding/*`
  - `workshop/services/workshop_cluster_topology.yaml`
  - `workshop/benchmarks/constitutional_benchmark_manifest.yaml`
- Workshop integration contract:
  - `integration/workshop_system_contract.yaml`

### Workshop CLI flow

- Bootstrap charter + genesis:
  - `python -m sovereign_ide.cli workshop-init ...`
- Admit corpus artifacts:
  - `python -m sovereign_ide.cli workshop-ingest ...`
- Build constitutional datasets:
  - `python -m sovereign_ide.cli workshop-build-datasets ...`
- Run governed training:
  - `python -m sovereign_ide.cli workshop-train ...`
- Execute shadow evaluation:
  - `python -m sovereign_ide.cli workshop-eval ...`
- Promote candidate checkpoint with quorum:
  - `python -m sovereign_ide.cli workshop-promote ...`
- Register/apply certified repair units:
  - `python -m sovereign_ide.cli workshop-register-repair ...`
  - `python -m sovereign_ide.cli workshop-apply-repair ...`
- Export workshop report:
  - `python -m sovereign_ide.cli workshop-report ...`

## Core invariants

The runtime enforces these invariants:

1. Decision records are immutable and signed.
2. Mutation-capable operations require complete `MutationGovernanceBinding`.
3. Policy enforcement is bound to a persisted `PolicyEvaluationResult`.
4. Audit trail is append-only and replayable.
5. Rollback is compensation-only.
6. Resolution is conservative and default-deny.
