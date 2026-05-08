# Production Deployment Plan

This repository is deployable only when the release has passed both local
code gates and external production gates. A green unit-test run is not a
production release.

## Hard Release Gates

1. Python runtime is 3.11 or newer everywhere bootstrap, quality, preflight,
   and release gates run.
2. `SOVEREIGN_SIGNING_KEY` and `SOVEREIGN_SERVICE_TOKEN` are injected by a
   production secret manager or orchestrator, not committed and not loaded from
   a developer `.env` file.
3. `SOVEREIGN_IMAGE_REF` names a durable registry image, not `:local`,
   `localhost`, or `127.0.0.1`.
4. Runtime state is backed by durable storage and mounted at `/app/state`.
   The release declares `SOVEREIGN_STATE_BACKEND` and `SOVEREIGN_STATE_URI`.
5. Workshop training is actual fine-tuning by default. Production releases
   declare `SOVEREIGN_TRAINING_COMMAND` and
   `SOVEREIGN_TRAINING_ARTIFACT_STORE`.
6. Release governance names at least two approvers in
   `SOVEREIGN_RELEASE_APPROVERS`.
7. Container smoke test passes against the release image.
8. Local quality, pre-production inspection, advanced integration preflight,
   and E2E matrix all pass.

## Release Flow

1. Commit the release tree.
2. Build the runtime image with the release commit stamped into OCI metadata:
   `docker build -f deployments/Dockerfile --build-arg VCS_REF=<commit> -t <image> .`
3. Push the image to the target registry and capture the immutable digest.
4. Fill a release manifest from `deployments/release.manifest.example.json`.
5. Inject the environment contract from `deployments/production.env.example`
   through the deployment platform.
6. Run `scripts/production_readiness_gate.ps1` without local-only overrides.
7. Deploy the image with `/app/state` backed by the declared durable state URI.
8. Verify `/health`, authenticated `/ready`, policy evaluation, and audit
   replay in the target environment.

## Fine-Tuning Requirement

Simulation is allowed only for local governance smoke tests. A production
release must use `--execution-mode actual` or the default workshop training
mode, and the configured trainer must produce a completed checkpoint manifest
with an artifact URI and checkpoint hash.

The included TRL/PEFT trainer template is a runnable integration point, not a
claim that a model has been trained. The release is not model-server ready
until an actual dataset, base checkpoint, trainer environment, and artifact
store have been wired and a governed checkpoint has passed shadow evaluation
and promotion.

## Not Done Until

- The image is published to the selected registry.
- The state volume exists in the deployment target.
- Secrets are injected by the deployment target.
- A real fine-tuning artifact store exists.
- The release manifest records the pushed image digest.
- The production readiness gate passes without `-AllowLocalImage`,
  `-AllowLocalEnvFile`, or `-SkipContainerSmoke`.
