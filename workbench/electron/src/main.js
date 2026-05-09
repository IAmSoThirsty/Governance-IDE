const { app, BrowserWindow, ipcMain } = require("electron");
const path = require("path");

const DEFAULT_RUNTIME_URL = "http://127.0.0.1:8765";

const API_ROUTES = Object.freeze({
  health: { method: "GET", path: "/health", requiresAuth: false },
  ready: { method: "GET", path: "/ready", requiresAuth: true },
  modelsList: { method: "GET", path: "/v1/models", requiresAuth: true },
  modelsRegister: {
    method: "POST",
    path: "/v1/models/register",
    requiresAuth: true
  },
  executionTicketRequest: {
    method: "POST",
    path: "/v1/models/execution-ticket",
    requiresAuth: true
  },
  executionTicketInspect: {
    method: "POST",
    path: "/v1/models/execution-ticket/inspect",
    requiresAuth: true
  },
  trainingPreflight: {
    method: "POST",
    path: "/v1/workshop/training/preflight",
    requiresAuth: true
  },
  trainingRun: {
    method: "POST",
    path: "/v1/workshop/training/run",
    requiresAuth: true
  },
  auditEvents: {
    method: "GET",
    path: "/v1/audit/events",
    requiresAuth: true
  },
  auditReplay: {
    method: "GET",
    path: "/v1/audit/replay",
    requiresAuth: true
  }
});

let runtimeUrl = resolveRuntimeUrl(process.env.SOVEREIGN_RUNTIME_URL);
let serviceToken = String(process.env.SOVEREIGN_SERVICE_TOKEN || "").trim();

function resolveRuntimeUrl(rawUrl) {
  const candidate = String(rawUrl || DEFAULT_RUNTIME_URL).trim() || DEFAULT_RUNTIME_URL;
  let parsed;
  try {
    parsed = new URL(candidate);
  } catch {
    throw new Error("runtime_url_invalid");
  }
  if (!parsed.protocol || !["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("runtime_url_protocol_invalid");
  }
  parsed.hash = "";
  parsed.search = "";
  return parsed.toString().replace(/\/$/, "");
}

function runtimeConfig() {
  return {
    baseUrl: runtimeUrl,
    tokenConfigured: Boolean(serviceToken),
    connectionPolicy: "governed-service-api-only"
  };
}

function sanitizeAuditQuery(raw = {}) {
  const limitValue = Number.parseInt(String(raw.limit || "100"), 10);
  const limit = Number.isFinite(limitValue)
    ? Math.max(1, Math.min(limitValue, 500))
    : 100;
  const traceId = String(raw.traceId || "").trim();
  const recordType = String(raw.recordType || "").trim();
  const sourceJournal = String(raw.sourceJournal || "").trim().toLowerCase();

  const query = { limit: String(limit) };
  if (traceId) {
    query.trace_id = traceId;
  }
  if (recordType) {
    query.record_type = recordType;
  }
  if (["runtime", "workshop"].includes(sourceJournal)) {
    query.source = sourceJournal;
  }
  return query;
}

async function runtimeRequest(routeKey, { query = {}, body = null } = {}) {
  const route = API_ROUTES[routeKey];
  if (!route) {
    return {
      ok: false,
      status: 0,
      error: "unsupported_route",
      data: null
    };
  }

  const url = new URL(route.path, `${runtimeUrl}/`);
  Object.entries(query || {}).forEach(([key, value]) => {
    if (value !== undefined && value !== null && `${value}`.trim() !== "") {
      url.searchParams.set(key, String(value));
    }
  });

  const headers = { Accept: "application/json" };
  if (route.requiresAuth && serviceToken) {
    headers.Authorization = `Bearer ${serviceToken}`;
  }

  const requestOptions = {
    method: route.method,
    headers
  };
  if (route.method !== "GET") {
    headers["Content-Type"] = "application/json";
    requestOptions.body = JSON.stringify(body || {});
  }

  let response;
  try {
    response = await fetch(url.toString(), requestOptions);
  } catch (error) {
    return {
      ok: false,
      status: 0,
      error: `connection_error:${error.message}`,
      data: null
    };
  }

  const rawText = await response.text();
  let payload = {};
  if (rawText) {
    try {
      payload = JSON.parse(rawText);
    } catch {
      payload = { raw: rawText };
    }
  }

  if (!response.ok) {
    const reason = payload?.reason || payload?.error || `${response.status} ${response.statusText}`;
    return {
      ok: false,
      status: response.status,
      error: String(reason),
      data: payload
    };
  }

  return {
    ok: true,
    status: response.status,
    error: null,
    data: payload
  };
}

function registerIpcHandlers() {
  ipcMain.handle("workbench:getRuntimeConfig", () => runtimeConfig());

  ipcMain.handle("workbench:setRuntimeUrl", (_event, nextUrl) => {
    runtimeUrl = resolveRuntimeUrl(nextUrl);
    return runtimeConfig();
  });

  ipcMain.handle("workbench:setServiceToken", (_event, nextToken) => {
    serviceToken = String(nextToken || "").trim();
    return {
      tokenConfigured: Boolean(serviceToken)
    };
  });

  ipcMain.handle("workbench:getHealth", () => runtimeRequest("health"));
  ipcMain.handle("workbench:getReady", () => runtimeRequest("ready"));
  ipcMain.handle("workbench:listModels", () => runtimeRequest("modelsList"));
  ipcMain.handle("workbench:registerModel", (_event, payload) => {
    return runtimeRequest("modelsRegister", { body: payload || {} });
  });
  ipcMain.handle("workbench:requestExecutionTicket", (_event, payload) => {
    return runtimeRequest("executionTicketRequest", { body: payload || {} });
  });
  ipcMain.handle("workbench:inspectExecutionTicket", (_event, payload) => {
    return runtimeRequest("executionTicketInspect", { body: payload || {} });
  });
  ipcMain.handle("workbench:preflightTraining", (_event, payload) => {
    return runtimeRequest("trainingPreflight", { body: payload || {} });
  });
  ipcMain.handle("workbench:runTraining", (_event, payload) => {
    return runtimeRequest("trainingRun", { body: payload || {} });
  });
  ipcMain.handle("workbench:listAuditEvents", (_event, payload) => {
    return runtimeRequest("auditEvents", {
      query: sanitizeAuditQuery(payload || {})
    });
  });
  ipcMain.handle("workbench:replayAuditTrace", (_event, payload) => {
    const traceId = String(payload?.traceId || "").trim();
    return runtimeRequest("auditReplay", {
      query: traceId ? { trace_id: traceId } : {}
    });
  });
}

function createWindow() {
  const window = new BrowserWindow({
    width: 1440,
    height: 960,
    minWidth: 1100,
    minHeight: 720,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      preload: path.join(__dirname, "preload.js")
    }
  });

  window.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  window.webContents.on("will-navigate", (event, targetUrl) => {
    if (targetUrl !== window.webContents.getURL()) {
      event.preventDefault();
    }
  });

  window.loadFile(path.join(__dirname, "renderer", "index.html"));
}

app.whenReady().then(() => {
  registerIpcHandlers();
  createWindow();
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});
