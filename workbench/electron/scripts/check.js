const { readFileSync } = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const root = path.resolve(__dirname, "..");

const jsFiles = [
  path.join(root, "src", "main.js"),
  path.join(root, "src", "preload.js"),
  path.join(root, "src", "renderer", "workbench.js")
];

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function checkSyntax(filePath) {
  const result = spawnSync(process.execPath, ["--check", filePath], {
    stdio: "inherit"
  });
  if (result.status !== 0) {
    throw new Error(`syntax_check_failed:${filePath}`);
  }
}

function fileText(filePath) {
  return readFileSync(filePath, "utf-8");
}

function runBoundaryChecks() {
  const mainText = fileText(path.join(root, "src", "main.js"));
  assert(mainText.includes("contextIsolation: true"), "main_missing_context_isolation");
  assert(mainText.includes("nodeIntegration: false"), "main_missing_node_integration_lockdown");
  assert(mainText.includes("sandbox: true"), "main_missing_renderer_sandbox");
  assert(mainText.includes("webSecurity: true"), "main_missing_web_security");
  assert(mainText.includes("allowRunningInsecureContent: false"), "main_missing_insecure_content_lockdown");
  assert(mainText.includes("const API_ROUTES = Object.freeze("), "main_missing_api_route_allowlist");
  assert(mainText.includes("if (!route)"), "main_missing_route_deny_default");
  assert(mainText.includes("unsupported_route"), "main_missing_unsupported_route_denial");
  assert(mainText.includes("workbench:listModels"), "main_missing_models_route_binding");
  assert(mainText.includes("workbench:runTraining"), "main_missing_training_route_binding");
  assert(mainText.includes("workbench:listAuditEvents"), "main_missing_audit_route_binding");
  assert(!mainText.includes("SOVEREIGN_ED25519_PRIVATE_KEY_PEM"), "main_must_not_expose_private_key_env");
  assert(!mainText.includes("SOVEREIGN_SIGNING_KEY"), "main_must_not_expose_signing_key_env");

  const preloadText = fileText(path.join(root, "src", "preload.js"));
  assert(preloadText.includes("contextBridge.exposeInMainWorld"), "preload_missing_context_bridge");
  assert(!preloadText.includes("child_process"), "preload_must_not_use_child_process");
  assert(!preloadText.includes("fs"), "preload_must_not_expose_fs_modules");
  assert(!preloadText.includes("shell"), "preload_must_not_expose_shell_modules");
  assert(preloadText.includes("workbench:registerModel"), "preload_missing_register_model_route");
  assert(preloadText.includes("workbench:requestExecutionTicket"), "preload_missing_execution_ticket_route");
  assert(preloadText.includes("workbench:preflightTraining"), "preload_missing_training_preflight_route");

  const rendererText = fileText(path.join(root, "src", "renderer", "workbench.js"));
  assert(!rendererText.includes("require("), "renderer_must_not_require_node_modules");
  assert(!rendererText.includes("window.localStorage.getItem(\"SOVEREIGN_SERVICE_TOKEN\")"), "renderer_must_not_pull_service_token_from_local_storage");
  assert(!rendererText.includes("child_process"), "renderer_must_not_reference_child_process");
  assert(!rendererText.includes("fs."), "renderer_must_not_reference_fs");
  assert(!rendererText.includes("exec("), "renderer_must_not_reference_exec");
  assert(rendererText.includes("window.sovereignWorkbench"), "renderer_missing_preload_api_usage");
}

function runOptionalAuditCheck() {
  if (process.env.SOVEREIGN_CHECK_NPM_AUDIT !== "1") {
    console.log("[check] npm audit check skipped (set SOVEREIGN_CHECK_NPM_AUDIT=1 to enable)");
    return;
  }

  const result = spawnSync("npm", ["audit", "--audit-level=high", "--json"], {
    cwd: root,
    encoding: "utf-8"
  });
  if (result.error) {
    throw new Error(`npm_audit_execution_failed:${result.error.message}`);
  }

  const raw = `${result.stdout || ""}${result.stderr || ""}`.trim();
  if (!raw) {
    throw new Error("npm_audit_no_output");
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("npm_audit_invalid_json_output");
  }

  const vulnerabilities = parsed.metadata?.vulnerabilities || {};
  const high = Number(vulnerabilities.high || 0);
  const critical = Number(vulnerabilities.critical || 0);
  if (high > 0 || critical > 0) {
    throw new Error(`npm_audit_high_or_critical:${high + critical}`);
  }
}

function main() {
  jsFiles.forEach(checkSyntax);
  runBoundaryChecks();
  runOptionalAuditCheck();
  console.log("[check] Electron workbench syntax and security boundary checks passed");
}

try {
  main();
} catch (error) {
  console.error(`[check] ${error.message || error}`);
  process.exit(1);
}
