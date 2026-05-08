# Sovereign IDE Electron Workbench

This is the custom Electron shell for the governance runtime. It is intentionally
not a generic editor wrapper. The navigation is organized around governed model
intake, fine-tuning, policy, audit replay, quorum approval, evidence, and
runtime state.

The workbench expects the Python runtime service to be running separately:

```powershell
python -m sovereign_ide.cli serve --host 127.0.0.1 --port 8765
```

Configuration:

- `SOVEREIGN_RUNTIME_URL` defaults to `http://127.0.0.1:8765`.
- Store the local service token in browser local storage as
  `SOVEREIGN_SERVICE_TOKEN` for protected endpoints during local development.
- Production packaging must inject runtime URL and tokens through the desktop
  deployment channel. Do not bake secrets into the Electron bundle.
