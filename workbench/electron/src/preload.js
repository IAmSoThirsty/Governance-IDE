const { contextBridge } = require("electron");

contextBridge.exposeInMainWorld("sovereignRuntime", {
  baseUrl: process.env.SOVEREIGN_RUNTIME_URL || "http://127.0.0.1:8765",
  tokenConfigured: Boolean(process.env.SOVEREIGN_SERVICE_TOKEN)
});
