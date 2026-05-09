# Production Deployment Plan

This repository must not be described as production-deployment ready until the
release has passed both local code gates and external production gates. A green
unit-test run is not a production release.

`GET /ready` reports runtime readiness only. It does not certify production
deployment readiness.

## Hard Release Gates

1. Python runtime is 3.11 or newer everywhere bootstrap, quality, preflight,
   and release gates run.
2. `SOVEREIGN_SIGNING_KEY` and `SOVEREIGN_SERVICE_TOKEN` are injected by a
   production secret manager or orchestrator, not committed and not loaded from
   a developer `.env` file.
3. `SOVEREIGN_IMAGE_REF` names a durable registry image, not `:local`,
   `localhost`, or `127.0.0.1`.
4. `SOVEREIGN_IMAGE_DIGEST` names the immutable digest of the pushed image.
5. `SOVEREIGN_PRODUCTION_EVIDENCE_MANIFEST` (or
   `SOVEREIGN_RELEASE_MANIFEST`) points at a production evidence manifest for
   this exact image ref, image digest, release commit, and release tag.
6. `SOVEREIGN_SIGNER_BACKEND` is `ed25519` in production and the Ed25519 key
   source is explicitly evidenced (`file_path` or `inline_pem`) without
   exposing private key material.
7. `SOVEREIGN_SECRET_SOURCE` is declared and references a real secret manager
   channel (no developer/local placeholder source).
8. Runtime state is backed by durable storage and mounted at `/app/state`.
   The release declares `SOVEREIGN_STATE_BACKEND` and `SOVEREIGN_STATE_URI`.
9. Workshop training is actual fine-tuning by default. Production releases
   declare `SOVEREIGN_TRAINING_COMMAND`, `SOVEREIGN_TRAINING_BACKEND`, and
   `SOVEREIGN_TRAINING_ARTIFACT_STORE`.
10. Release governance names at least two approvers in
    `SOVEREIGN_RELEASE_APPROVERS`.
11. Dependency scan evidence and SBOM locations are recorded in the production
    evidence manifest; dependency scan status must be `pass`.
12. Container smoke test passes against the release image.
13. Local quality, pre-production inspection, advanced integration preflight,
    and E2E matrix all pass.

## Production Evidence Manifest Contract

Canonical example:

- `deployments/production_evidence_manifest.example.json`

Schema:

- `schemas/production_evidence_manifest.schema.json`

Evidence manifest fields must include (no secrets):

- `release_commit`
- `release_tag`
- `registry_image_ref`
- `image_digest`
- `runtime_mode`
- `signer_type`
- `ed25519_key_source_type`
- `secret_source`
- `artifact_store_backend`
- `trainer_backend`
- `storage_backend`
- `audit_journal_backend`
- `ci_run_id`
- `build_timestamp`
- `sbom_location`
- `dependency_scan_result_location`
- `dependency_scan_status`

The readiness gate validates this contract against live runtime/deployment
environment variables and current git commit.

## Gate Failure Classification

`scripts/production_readiness_gate.ps1` classifies blocked outcomes as:

- `repo-code blocked`
- `environment blocked`
- `production-evidence blocked`
- `dependency-security blocked`

Local override mode is explicitly classified as:

- `rehearsal-only pass`

Rehearsal passes must disclose active override flags and overridden evidence and
must never claim production readiness.

## Release Flow

1. Commit the release tree.
2. Build the runtime image with the release commit stamped into OCI metadata:
   `docker build -f deployments/Dockerfile --build-arg VCS_REF=<commit> -t <image> .`
3. Push the image to the target registry and capture the immutable digest.
4. Fill a release manifest from `deployments/release.manifest.example.json`.
5. Fill a production evidence manifest from
   `deployments/production_evidence_manifest.example.json`.
6. Inject the environment contract from `deployments/production.env.example`
   through the deployment platform.
7. Run `scripts/production_readiness_gate.ps1` without local-only overrides.
8. Deploy the image with `/app/state` backed by the declared durable state URI.
9. Verify `/health`, authenticated `/ready`, policy evaluation, and audit
   replay in the target environment.

Reference deployment artifacts:

- Local container rehearsal: `deployments/docker-compose.rehearsal.yaml`
- Kubernetes runtime skeleton: `deployments/kubernetes.runtime.yaml`

## Fine-Tuning Requirement

Simulation is allowed only for local governance smoke tests. A production
release must use actual governed training and pass training preflight before
run start. Preflight is fail-closed and requires:

- registered base model
- base model execution ticket or admissibility decision reference
- dataset reference (`dataset_id` or `dataset_ref`)
- dataset provenance and source type
- dataset license where applicable
- dataset hash or immutable reference for governed training
- policy profile
- configured trainer backend
- durable artifact store configuration
- writable output checkpoint registration path
- append-only audit journal availability

Mutable dataset references are denied for `reviewed`/`trusted` training unless
immutable proof is present.

The configured trainer must produce a completed checkpoint manifest with an
artifact URI and checkpoint hash.

The included TRL/PEFT trainer template is a runnable integration point, not a
claim that a model has been trained. The release is not model-server ready
until an actual dataset, base checkpoint, trainer environment, and artifact
store have been wired and a governed checkpoint has passed shadow evaluation
and promotion.

When `SOVEREIGN_TRAINING_ARTIFACT_STORE` is configured, actual training output
must report a durable artifact URI under that store and remain bindable to the
governed model registry entry. In production/rehearsal contexts, local/temp-only
artifact stores are denied.

Simulation runs must remain explicitly flagged smoke tests, emit
simulation-specific audit events, and never satisfy production training
evidence.

## Model Intake And Execution

Every model must be registered before use. Intake records source type, source,
license, content hash or immutable identifier, metadata, trust level, policy
profile, and provenance reference. Supported sources are local model paths,
Hugging Face model IDs, OpenAI-compatible endpoints, Ollama/local endpoints,
and external gateways.

Execution is not an inference bypass. A caller must obtain a governed execution
ticket first; the ticket writes policy evaluation, decision, and audit entries.
Unreviewed or untrusted models cannot receive execution tickets.

Execution tickets are signed and bind model ID, registry entry hash, policy
profile, trust level, source type, provenance reference, issue/expiry
timestamps, ticket purpose, signer type, and signature. Ticket verification is
fail-closed for tampered payloads, invalid signatures, and expired tickets.

Fine-tuned checkpoints from actual training are registered as new governed
models and signed through the signer abstraction. Raw checkpoint artifacts are
not admissible without governed checkpoint registration.

## Signing And Storage

`hmac-dev` is the local development signer only. It must not be represented as
production-grade signing and is rejected outside local runtime mode.
Production deployments should set `SOVEREIGN_RUNTIME_MODE=production` and use
the signer abstraction with Ed25519, KMS, or HSM-backed signing.

When `SOVEREIGN_SIGNER_BACKEND=ed25519`, key material must be provided by a
real secret source via either `SOVEREIGN_ED25519_PRIVATE_KEY_PATH` (preferred
file-mount secret) or `SOVEREIGN_ED25519_PRIVATE_KEY_PEM`.

Local mode uses the SQLite append-only event journal by default. The file
journal remains a development fallback through `SOVEREIGN_JOURNAL_BACKEND=file`.
Enterprise/server deployment should move the same append-only event-store
contract to Postgres, but Postgres is not required for local mode.

## Not Done Until

- The image is published to the selected registry.
- The pushed image digest is recorded in `SOVEREIGN_IMAGE_DIGEST`.
- The state volume exists in the deployment target.
- Secrets are injected by the deployment target.
- A real fine-tuning artifact store exists.
- The production evidence manifest records release/image/runtime/dependency
   evidence and passes fail-closed validation.
- The production readiness gate passes without `-AllowLocalImage`,
  `-AllowLocalEnvFile`, `-AllowMissingReleaseManifest`, or
  `-SkipContainerSmoke`.
