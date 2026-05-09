const panelTitles = {
  "runtime-health": "Runtime Health",
  "model-registry": "Model Registry",
  "model-registration": "Model Registration",
  "execution-tickets": "Execution Tickets",
  "fine-tuning": "Fine Tuning Workshop",
  "audit-journal": "Audit / Event Journal"
};

const api = window.sovereignWorkbench;

const titleElement = document.getElementById("panel-title");
const runtimeStatusElement = document.getElementById("runtime-status");
const runtimeUrlInput = document.getElementById("runtime-url");
const runtimeTokenInput = document.getElementById("runtime-token");
const runtimeConnectButton = document.getElementById("runtime-connect");
const runtimeConnectionGrid = document.getElementById("runtime-connection-grid");
const runtimeHealthOutput = document.getElementById("runtime-health-json");
const runtimeReadyOutput = document.getElementById("runtime-ready-json");

const modelsTableBody = document.getElementById("models-table-body");
const refreshModelsButton = document.getElementById("refresh-models");

const modelRegistrationForm = document.getElementById("model-registration-form");
const modelRegistrationResult = document.getElementById("model-registration-result");

const ticketRequestForm = document.getElementById("ticket-request-form");
const ticketRequestResult = document.getElementById("ticket-request-result");
const ticketInspectForm = document.getElementById("ticket-inspect-form");
const ticketInspectResult = document.getElementById("ticket-inspect-result");

const trainingResult = document.getElementById("training-result");
const trainingPreflightActualButton = document.getElementById("train-preflight-actual");
const trainingRunSimulationButton = document.getElementById("train-run-simulation");
const trainingRunActualButton = document.getElementById("train-run-actual");

const auditFilterForm = document.getElementById("audit-filter-form");
const auditEventsBody = document.getElementById("audit-events-body");
const auditReplayForm = document.getElementById("audit-replay-form");
const auditReplayResult = document.getElementById("audit-replay-result");

const globalOutput = document.getElementById("global-output-json");

function pretty(payload) {
  return JSON.stringify(payload, null, 2);
}

function escapeHtml(value) {
  return String(value || "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;"
  })[char]);
}

function setGlobalOutput(payload) {
  globalOutput.textContent = pretty(payload);
}

function setRuntimeStatus(label) {
  runtimeStatusElement.textContent = label;
}

function parseJsonOrNull(text, fieldName) {
  const raw = String(text || "").trim();
  if (!raw) {
    return null;
  }
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error(`${fieldName}_json_invalid`);
  }
}

function parseRoles(raw) {
  return String(raw || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function governanceContext() {
  const actorId = document.getElementById("ctx-actor-id").value.trim();
  const actorRoles = parseRoles(document.getElementById("ctx-actor-roles").value);
  const tenant = document.getElementById("ctx-tenant").value.trim();
  const trustDomain = document.getElementById("ctx-trust-domain").value.trim();
  const classification = document.getElementById("ctx-classification").value.trim() || "confidential";
  const traceIdInput = document.getElementById("ctx-trace-id");
  const traceId = traceIdInput.value.trim() || `trace_${Date.now()}`;

  if (!actorId) {
    throw new Error("actor_id_required");
  }
  if (!actorRoles.length) {
    throw new Error("actor_roles_required");
  }
  if (!tenant) {
    throw new Error("tenant_required");
  }
  if (!trustDomain) {
    throw new Error("trust_domain_required");
  }

  traceIdInput.value = traceId;
  return {
    trace_id: traceId,
    actor_id: actorId,
    actor_roles: actorRoles,
    tenant,
    trust_domain: trustDomain,
    classification,
    policy_pack_version: "1.0.0"
  };
}

function safeValue(id) {
  return document.getElementById(id).value.trim();
}

function splitCsv(raw) {
  return String(raw || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function setPanel(panelId) {
  document.querySelectorAll("nav button").forEach((button) => {
    button.classList.toggle("active", button.dataset.panel === panelId);
  });
  document.querySelectorAll(".panel-page").forEach((panel) => {
    panel.classList.toggle("active", panel.id === panelId);
  });
  titleElement.textContent = panelTitles[panelId] || "Workbench";
}

function renderConnectionGrid(details) {
  const rows = [
    ["Runtime URL", details.baseUrl || ""],
    ["Connection State", details.connectionState || "unknown"],
    ["/health status", details.healthStatus || "unknown"],
    ["/ready status", details.readyStatus || "unknown"],
    ["Runtime Mode", details.runtimeMode || "unknown"],
    ["Signer Type", details.signerType || "unknown"],
    ["Service Token Required", String(Boolean(details.tokenRequired))],
    ["Token Configured", String(Boolean(details.tokenConfigured))]
  ];

  runtimeConnectionGrid.innerHTML = rows
    .map(([key, value]) => {
      return `<div class="kv"><span class="key">${escapeHtml(key)}</span><span class="value">${escapeHtml(value)}</span></div>`;
    })
    .join("");
}

async function refreshRuntimeHealth() {
  const healthResponse = await api.getHealth();
  const readyResponse = await api.getReady();

  runtimeHealthOutput.textContent = pretty(healthResponse);
  runtimeReadyOutput.textContent = pretty(readyResponse);

  const config = await api.getRuntimeConfig();
  const healthData = healthResponse?.data || {};
  const readyData = readyResponse?.data || {};

  let connectionState = "offline";
  if (healthResponse.ok && readyResponse.ok) {
    connectionState = "online_ready";
  } else if (healthResponse.ok && !readyResponse.ok) {
    connectionState = "online_unready_or_unauthorized";
  }

  setRuntimeStatus(connectionState.replaceAll("_", " "));
  renderConnectionGrid({
    baseUrl: config.baseUrl,
    connectionState,
    healthStatus: healthData.status,
    readyStatus: readyData.status || readyResponse.error,
    runtimeMode: healthData.runtime_mode,
    signerType: healthData.signer_type,
    tokenRequired: healthData.service_token_required,
    tokenConfigured: config.tokenConfigured
  });

  setGlobalOutput({
    health: healthResponse,
    ready: readyResponse
  });
}

function renderModels(modelsPayload) {
  const models = Array.isArray(modelsPayload?.models) ? modelsPayload.models : [];
  if (!models.length) {
    modelsTableBody.innerHTML = "<tr><td colspan=\"9\">No registered models.</td></tr>";
    return;
  }

  modelsTableBody.innerHTML = models.map((model) => {
    return `
      <tr>
        <td class="mono">${escapeHtml(model.model_id)}</td>
        <td>${escapeHtml(model.source_type)}</td>
        <td>${escapeHtml(model.trust_level)}</td>
        <td>${escapeHtml(model.policy_profile)}</td>
        <td class="mono">${escapeHtml(model.provenance_ref)}</td>
        <td class="mono">${escapeHtml(model.immutable_identifier)}</td>
        <td class="mono">${escapeHtml(model.content_hash)}</td>
        <td>${escapeHtml(model.signature_status)}</td>
        <td>${escapeHtml(model.registry_schema_version)}</td>
      </tr>
    `;
  }).join("");
}

async function refreshModels() {
  const response = await api.listModels();
  if (!response.ok) {
    modelsTableBody.innerHTML = `<tr><td colspan="9">${escapeHtml(response.error || "models_list_failed")}</td></tr>`;
    setGlobalOutput(response);
    return;
  }
  renderModels(response.data);
  setGlobalOutput(response);
}

async function handleModelRegistration(event) {
  event.preventDefault();
  try {
    const metadata = parseJsonOrNull(document.getElementById("register-metadata-json").value, "metadata") || {};
    const payload = {
      source_type: safeValue("register-source-type"),
      source: safeValue("register-source"),
      license: safeValue("register-license") || "unknown",
      content_hash: safeValue("register-content-hash") || undefined,
      immutable_identifier: safeValue("register-immutable-identifier") || undefined,
      trust_level: safeValue("register-trust-level"),
      policy_profile: safeValue("register-policy-profile"),
      provenance_ref: safeValue("register-provenance-ref"),
      metadata,
      quorum_proof: safeValue("register-quorum-proof"),
      context: governanceContext()
    };

    const response = await api.registerModel(payload);
    modelRegistrationResult.textContent = pretty(response);
    setGlobalOutput(response);
    if (response.ok) {
      await refreshModels();
    }
  } catch (error) {
    const payload = {
      allowed: false,
      reason: String(error.message || error)
    };
    modelRegistrationResult.textContent = pretty(payload);
    setGlobalOutput(payload);
  }
}

async function handleTicketRequest(event) {
  event.preventDefault();
  try {
    const payload = {
      model_id: safeValue("ticket-model-id"),
      ticket_purpose: safeValue("ticket-purpose") || "model_execution",
      ticket_ttl_seconds: Number.parseInt(safeValue("ticket-ttl"), 10) || 900,
      context: governanceContext()
    };
    const response = await api.requestExecutionTicket(payload);
    ticketRequestResult.textContent = pretty(response);
    setGlobalOutput(response);

    if (response.ok && response.data?.payload?.execution_ticket) {
      document.getElementById("ticket-json").value = pretty(response.data.payload.execution_ticket);
    }
  } catch (error) {
    const payload = {
      allowed: false,
      reason: String(error.message || error)
    };
    ticketRequestResult.textContent = pretty(payload);
    setGlobalOutput(payload);
  }
}

async function handleTicketInspect(event) {
  event.preventDefault();
  try {
    const ticket = parseJsonOrNull(document.getElementById("ticket-json").value, "ticket");
    if (!ticket || typeof ticket !== "object") {
      throw new Error("ticket_json_required");
    }
    const payload = {
      ticket,
      trace_id: safeValue("ticket-inspect-trace") || undefined,
      at_time: safeValue("ticket-inspect-at-time") || undefined
    };
    const response = await api.inspectExecutionTicket(payload);
    ticketInspectResult.textContent = pretty(response);
    setGlobalOutput(response);
  } catch (error) {
    const payload = {
      allowed: false,
      reason: String(error.message || error)
    };
    ticketInspectResult.textContent = pretty(payload);
    setGlobalOutput(payload);
  }
}

function trainingPayload({ executionMode, simulationSmokeTest }) {
  const ticket = parseJsonOrNull(document.getElementById("train-base-model-ticket").value, "base_model_ticket");
  const payload = {
    model_family: safeValue("train-model-family"),
    base_checkpoint: safeValue("train-base-checkpoint") || undefined,
    base_model_id: safeValue("train-base-model-id") || undefined,
    base_model_execution_ticket: ticket && Object.keys(ticket).length ? ticket : undefined,
    base_model_admissibility_decision_id: safeValue("train-base-model-admissibility") || undefined,
    dataset_ids: splitCsv(safeValue("train-dataset-ids")),
    dataset_ref: safeValue("train-dataset-ref") || undefined,
    dataset_provenance: safeValue("train-dataset-provenance") || undefined,
    dataset_source_type: safeValue("train-dataset-source-type") || undefined,
    dataset_license: safeValue("train-dataset-license") || undefined,
    dataset_hash: safeValue("train-dataset-hash") || undefined,
    dataset_immutable_ref: safeValue("train-dataset-immutable-ref") || undefined,
    dataset_immutable_proof: safeValue("train-dataset-immutable-proof") || undefined,
    policy_profile: safeValue("train-policy-profile") || undefined,
    trust_level: safeValue("train-trust-level") || "reviewed",
    training_backend: safeValue("train-backend") || undefined,
    training_command: safeValue("train-command") || undefined,
    artifact_store_uri: safeValue("train-artifact-store") || undefined,
    execution_mode: executionMode,
    simulation_smoke_test: simulationSmokeTest,
    context: governanceContext()
  };
  return payload;
}

async function handleTrainingPreflightActual() {
  try {
    const payload = trainingPayload({
      executionMode: "actual",
      simulationSmokeTest: false
    });
    const response = await api.preflightTraining(payload);
    trainingResult.textContent = pretty(response);
    setGlobalOutput(response);
  } catch (error) {
    const payload = {
      allowed: false,
      mode: "actual_training",
      reason: String(error.message || error)
    };
    trainingResult.textContent = pretty(payload);
    setGlobalOutput(payload);
  }
}

async function handleTrainingSimulationRun() {
  try {
    const explicitFlag = document.getElementById("train-simulation-flag").checked;
    if (!explicitFlag) {
      const denied = {
        allowed: false,
        mode: "simulation",
        reason: "simulation_flag_required"
      };
      trainingResult.textContent = pretty(denied);
      setGlobalOutput(denied);
      return;
    }

    const payload = trainingPayload({
      executionMode: "simulated",
      simulationSmokeTest: true
    });
    payload.quorum_proof = safeValue("train-quorum-proof");

    const response = await api.runTraining(payload);
    trainingResult.textContent = pretty(response);
    setGlobalOutput(response);
  } catch (error) {
    const payload = {
      allowed: false,
      mode: "simulation",
      reason: String(error.message || error)
    };
    trainingResult.textContent = pretty(payload);
    setGlobalOutput(payload);
  }
}

async function handleTrainingActualRun() {
  try {
    const payload = trainingPayload({
      executionMode: "actual",
      simulationSmokeTest: false
    });
    payload.quorum_proof = safeValue("train-quorum-proof");

    const response = await api.runTraining(payload);
    trainingResult.textContent = pretty(response);
    setGlobalOutput(response);
  } catch (error) {
    const payload = {
      allowed: false,
      mode: "actual_training",
      reason: String(error.message || error)
    };
    trainingResult.textContent = pretty(payload);
    setGlobalOutput(payload);
  }
}

function renderAuditEvents(events) {
  if (!events.length) {
    auditEventsBody.innerHTML = "<tr><td colspan=\"8\">No events found for current filters.</td></tr>";
    return;
  }
  auditEventsBody.innerHTML = events.map((event) => {
    return `
      <tr>
        <td class="mono">${escapeHtml(event.timestamp)}</td>
        <td>${escapeHtml(event.record_type)}</td>
        <td>${escapeHtml(event.reason)}</td>
        <td class="mono">${escapeHtml(event.model_id)}</td>
        <td class="mono">${escapeHtml(event.training_id)}</td>
        <td class="mono">${escapeHtml(event.ticket_id)}</td>
        <td class="mono">${escapeHtml(event.trace_id)}</td>
        <td>${escapeHtml(event.source_journal)}</td>
      </tr>
    `;
  }).join("");
}

async function refreshAuditEvents(event) {
  if (event) {
    event.preventDefault();
  }
  const payload = {
    traceId: safeValue("audit-trace-id") || undefined,
    recordType: safeValue("audit-record-type") || undefined,
    sourceJournal: safeValue("audit-source-journal") || undefined,
    limit: safeValue("audit-limit") || "50"
  };
  const response = await api.listAuditEvents(payload);
  if (!response.ok) {
    auditEventsBody.innerHTML = `<tr><td colspan="8">${escapeHtml(response.error || "audit_events_failed")}</td></tr>`;
    setGlobalOutput(response);
    return;
  }
  renderAuditEvents(Array.isArray(response.data?.events) ? response.data.events : []);
  setGlobalOutput(response);
}

async function replayAuditTrace(event) {
  event.preventDefault();
  const traceId = safeValue("audit-replay-trace-id");
  const response = await api.replayAuditTrace({ traceId });
  auditReplayResult.textContent = pretty(response);
  setGlobalOutput(response);
}

async function connectRuntime() {
  try {
    const runtimeUrl = runtimeUrlInput.value.trim();
    const token = runtimeTokenInput.value;
    if (runtimeUrl) {
      await api.setRuntimeUrl(runtimeUrl);
    }
    await api.setServiceToken(token);
    await refreshRuntimeHealth();
    await refreshModels();
    await refreshAuditEvents();
  } catch (error) {
    const payload = {
      ok: false,
      error: String(error.message || error)
    };
    setRuntimeStatus("connection failed");
    setGlobalOutput(payload);
  }
}

function bindPanelNavigation() {
  document.querySelectorAll("nav button").forEach((button) => {
    button.addEventListener("click", () => {
      setPanel(button.dataset.panel);
    });
  });
}

function bindActions() {
  runtimeConnectButton.addEventListener("click", connectRuntime);
  refreshModelsButton.addEventListener("click", refreshModels);
  modelRegistrationForm.addEventListener("submit", handleModelRegistration);
  ticketRequestForm.addEventListener("submit", handleTicketRequest);
  ticketInspectForm.addEventListener("submit", handleTicketInspect);
  trainingPreflightActualButton.addEventListener("click", handleTrainingPreflightActual);
  trainingRunSimulationButton.addEventListener("click", handleTrainingSimulationRun);
  trainingRunActualButton.addEventListener("click", handleTrainingActualRun);
  auditFilterForm.addEventListener("submit", refreshAuditEvents);
  auditReplayForm.addEventListener("submit", replayAuditTrace);
}

async function initialize() {
  bindPanelNavigation();
  bindActions();
  setPanel("runtime-health");

  const config = await api.getRuntimeConfig();
  runtimeUrlInput.value = config.baseUrl;
  runtimeTokenInput.value = "";
  setRuntimeStatus("connecting");

  await refreshRuntimeHealth();
  await refreshModels();
  await refreshAuditEvents();
}

initialize().catch((error) => {
  setRuntimeStatus("startup failed");
  setGlobalOutput({
    ok: false,
    error: String(error.message || error)
  });
});
