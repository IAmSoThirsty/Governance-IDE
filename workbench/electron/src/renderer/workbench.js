const panels = {
  models: {
    title: "Models",
    endpoint: "/v1/models",
    fallback: "Register governed models before execution. No model runs without an execution ticket."
  },
  training: {
    title: "Fine-Tuning",
    fallback: "Actual fine-tuning requires a trainer command or job backend and a checkpoint manifest."
  },
  policy: {
    title: "Policy",
    endpoint: "/v1/policy",
    fallback: "Policy evaluation binds every mutation-capable action before use."
  },
  audit: {
    title: "Audit",
    fallback: "Replay trace IDs through /v1/audit/replay to inspect decisions and mutations."
  },
  approvals: {
    title: "Approvals",
    fallback: "Quorum approval gates privileged mutation, promotion, and release paths."
  },
  evidence: {
    title: "Evidence",
    endpoint: "/v1/apps",
    fallback: "Supply-chain, provenance, app catalog, and checkpoint evidence determine trust."
  }
};

const body = document.getElementById("panel-body");
const title = document.getElementById("panel-title");
const status = document.getElementById("runtime-status");

async function runtimeFetch(path) {
  const headers = {};
  const token = window.localStorage.getItem("SOVEREIGN_SERVICE_TOKEN");
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  const response = await fetch(`${window.sovereignRuntime.baseUrl}${path}`, { headers });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json();
}

async function refreshStatus() {
  try {
    const payload = await runtimeFetch("/health");
    status.textContent = payload.status === "ok" ? "runtime online" : "runtime degraded";
  } catch {
    status.textContent = "runtime offline";
  }
}

function renderFallback(panel) {
  body.innerHTML = `<article class="item"><h3>${panel.title}</h3><p class="muted">${panel.fallback}</p></article>`;
}

function renderJson(panel, payload) {
  body.innerHTML = `<article class="item"><h3>${panel.title}</h3><pre><code>${escapeHtml(JSON.stringify(payload, null, 2))}</code></pre></article>`;
}

function escapeHtml(value) {
  return value.replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;"
  }[char]));
}

async function selectPanel(name) {
  const panel = panels[name];
  title.textContent = panel.title;
  document.querySelectorAll("nav button").forEach((button) => {
    button.classList.toggle("active", button.dataset.panel === name);
  });
  if (!panel.endpoint) {
    renderFallback(panel);
    return;
  }
  try {
    renderJson(panel, await runtimeFetch(panel.endpoint));
  } catch {
    renderFallback(panel);
  }
}

document.querySelectorAll("nav button").forEach((button) => {
  button.addEventListener("click", () => selectPanel(button.dataset.panel));
});

refreshStatus();
selectPanel("models");
