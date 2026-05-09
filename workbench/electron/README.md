# Sovereign IDE Electron Workbench

This is the governed Electron workbench for the Sovereign runtime service.
Meaningful execution is service-API-only: no renderer direct registry mutation,
no direct SQLite mutation, no direct ticket issuance, no direct trainer calls.

The workbench expects the Python runtime service to be running separately:

```powershell
python -m sovereign_ide.cli serve --host 127.0.0.1 --port 8765
```

Configuration:

- `SOVEREIGN_RUNTIME_URL` defaults to `http://127.0.0.1:8765`.
- `SOVEREIGN_SERVICE_TOKEN` may be injected at launch or entered in the
  workbench connection bar.
- Production packaging must inject runtime URL and tokens through the desktop
  deployment channel. Do not bake secrets into the Electron bundle.

Implemented panels:

- Runtime Health (`/health`, `/ready`)
- Model Registry (`/v1/models`)
- Model Registration (`/v1/models/register`)
- Execution Tickets (`/v1/models/execution-ticket`, `/v1/models/execution-ticket/inspect`)
- Fine Tuning Workshop (`/v1/workshop/training/preflight`, `/v1/workshop/training/run`)
- Audit / Event Journal (`/v1/audit/events`, `/v1/audit/replay`)

Security boundary:

- Renderer runs with `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`.
- Preload exposes a narrow IPC API only.
- Renderer does not receive arbitrary filesystem or shell capabilities.
- Main process enforces explicit route allowlist to runtime API paths.

Local development:

- Install dependencies: `npm install`
- Start workbench: `npm start`
- Validate syntax/security boundary: `npm run check`
