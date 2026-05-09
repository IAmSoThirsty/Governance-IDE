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

  const preloadText = fileText(path.join(root, "src", "preload.js"));
  assert(preloadText.includes("contextBridge.exposeInMainWorld"), "preload_missing_context_bridge");
  assert(!preloadText.includes("child_process"), "preload_must_not_use_child_process");

  const rendererText = fileText(path.join(root, "src", "renderer", "workbench.js"));
  assert(!rendererText.includes("require("), "renderer_must_not_require_node_modules");
  assert(!rendererText.includes("window.localStorage.getItem(\"SOVEREIGN_SERVICE_TOKEN\")"), "renderer_must_not_pull_service_token_from_local_storage");
}

function main() {
  jsFiles.forEach(checkSyntax);
  runBoundaryChecks();
  console.log("[check] Electron workbench syntax and security boundary checks passed");
}

try {
  main();
} catch (error) {
  console.error(`[check] ${error.message || error}`);
  process.exit(1);
}
