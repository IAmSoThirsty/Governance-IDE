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
- `workbench/electron/` — custom Electron workbench shell

## Quick start

- Configure environment/signing material.
  - Copy `.env.example` to `.env` for local runs.
  - `SOVEREIGN_RUNTIME_MODE` defaults to `local`.
  - `SOVEREIGN_SIGNING_KEY` is mandatory for `hmac-dev` and must be high
    entropy.
  - Placeholder keys are rejected at runtime.
  - `hmac-dev` signing is accepted only in local runtime mode.
  - Production runtime requires `SOVEREIGN_SIGNER_BACKEND=ed25519` plus key
    material from either `SOVEREIGN_ED25519_PRIVATE_KEY_PATH` (preferred) or
    `SOVEREIGN_ED25519_PRIVATE_KEY_PEM`.
  - For production, inject signing material via secure secret management.
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
  - `./scripts/production_readiness_gate.ps1`

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
- `/ready` is runtime readiness only. It is not a production deployment
  certification.
- Optional bearer-token protection:
  - Set `SOVEREIGN_SERVICE_TOKEN`.
  - `/health` remains public.
  - `/ready` and `/v1/*` require `Authorization: Bearer <token>`.
- Current endpoints:
  - `GET /health`
  - `GET /ready`
  - `GET /v1/apps`
  - `GET /v1/models`
  - `GET /v1/policy`
  - `GET /v1/audit/replay?trace_id=...`
  - `POST /v1/policy/evaluate`
  - `POST /v1/models/execution-ticket`

## IDE app catalog

- List available runtime apps, integrations, deployment surfaces, and missing
  configuration:
  - `python -m sovereign_ide.cli apps-list`
- Filter by status or category:
  - `python -m sovereign_ide.cli apps-list --status requires_configuration`
- Catalog source:
  - `deployments/app_catalog.json`

## Electron custom workbench

- Workbench scaffold:
  - `workbench/electron/`
- The workbench is governance-native: model intake, fine-tuning, policy,
  audit, quorum approval, evidence, and runtime state are first-class panels.
- It calls the runtime service API and must not bake secrets into the desktop
  bundle.

## Governed model intake

- Register a model before use:
  - `python -m sovereign_ide.cli model-register --source-type local_path --source <path> --trust-level reviewed --policy-profile default-model-policy --provenance-ref <ref> --actor <id> --roles model_steward --tenant <tenant> --trust-domain <domain> --quorum-proof <proof>`
- Supported source types:
  - `local_path`
  - `huggingface_model_id`
  - `openai_compatible_endpoint`
  - `ollama_endpoint`
  - `external_gateway`
- List registered governed models:
  - `python -m sovereign_ide.cli models-list`
- Authorize model execution through governance before a caller invokes it:
  - `python -m sovereign_ide.cli model-execution-ticket --model-id <id> --ticket-purpose <purpose> --ticket-ttl-seconds <seconds> --actor <id> --roles model_steward --tenant <tenant> --trust-domain <domain>`
- Execution tickets are signed and bind model ID, registry entry hash, policy
  profile, trust level, source type, provenance, issued/expiry timestamps,
  purpose, signer type, and signature.
- Ticket verification fails closed: tampered payloads, invalid signatures, or
  expired tickets are rejected.
- HMAC signatures are for dev/local integrity only. Production signing must use
  an Ed25519/KMS/HSM backend through the signer abstraction.

## Container deployment

- Build:
  - `docker build -f deployments/Dockerfile --build-arg VCS_REF=$(git rev-parse --short HEAD) -t sovereign-ide-runtime .`
- Run:
  - `docker run --rm -p 8765:8765 -v sovereign-ide-state:/app/state -e SOVEREIGN_SIGNING_KEY=... -e SOVEREIGN_SERVICE_TOKEN=... sovereign-ide-runtime`
- The runtime image installs the package immutably, runs as the non-root
  `sovereign` user, and stores mutable journals/checkpoints under `/app/state`.
- Smoke test a built image:
  - `./scripts/container_smoke_test.ps1 -ImageName sovereign-ide-runtime`
- Production gate before release:
  - `./scripts/production_readiness_gate.ps1 -PythonExe C:\Path\To\Python312\python.exe`
- Production release plan:
  - `docs/production_deployment_plan.md`
- Canonical readiness contract:
  - `deployments/readiness_contract.json`
- Production environment contract:
  - `deployments/production.env.example`
- Release manifest template:
  - `deployments/release.manifest.example.json`
- Local container rehearsal:
  - `deployments/docker-compose.rehearsal.yaml`
- Kubernetes runtime skeleton:
  - `deployments/kubernetes.runtime.yaml`

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
