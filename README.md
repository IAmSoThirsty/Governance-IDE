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
  - `./scripts/run_e2e_test_matrix.ps1`
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

## Runtime service API

- Start local service:
  - `python -m sovereign_ide.cli serve --host 127.0.0.1 --port 8765`
- Optional bearer-token protection:
  - Set `SOVEREIGN_SERVICE_TOKEN`.
  - `/health` remains public.
  - `/ready` and `/v1/*` require `Authorization: Bearer <token>`.
- Current endpoints:
  - `GET /health`
  - `GET /ready`
  - `GET /v1/policy`
  - `GET /v1/audit/replay?trace_id=...`
  - `POST /v1/policy/evaluate`

## Container deployment

- Build:
  - `docker build -f deployments/Dockerfile -t sovereign-ide-runtime .`
- Run:
  - `docker run --rm -p 8765:8765 -e SOVEREIGN_SIGNING_KEY=... -e SOVEREIGN_SERVICE_TOKEN=... sovereign-ide-runtime`
- Production gate before release:
  - `./scripts/production_readiness_gate.ps1 -PythonExe C:\Path\To\Python312\python.exe`

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
  - Actual fine-tuning is the default and requires a configured trainer:
    - `python -m sovereign_ide.cli workshop-train ... --execution-mode actual --training-command "python scripts/trainers/trl_sft_trainer.py"`
  - The trainer receives `--request` and `--output`, reads workshop dataset artifacts, fine-tunes the requested `--model-family`, and returns a checkpoint manifest.
  - For quick governance-only smoke tests, use `--execution-mode simulated` explicitly.
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
