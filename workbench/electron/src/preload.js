const { contextBridge, ipcRenderer } = require("electron");

function invoke(channel, payload) {
  return ipcRenderer.invoke(channel, payload);
}

contextBridge.exposeInMainWorld(
  "sovereignWorkbench",
  Object.freeze({
    getRuntimeConfig: () => invoke("workbench:getRuntimeConfig"),
    setRuntimeUrl: (runtimeUrl) => invoke("workbench:setRuntimeUrl", runtimeUrl),
    setServiceToken: (token) => invoke("workbench:setServiceToken", token),
    getHealth: () => invoke("workbench:getHealth"),
    getReady: () => invoke("workbench:getReady"),
    getEvidenceStatus: () => invoke("workbench:getEvidenceStatus"),
    listModels: () => invoke("workbench:listModels"),
    registerModel: (payload) => invoke("workbench:registerModel", payload),
    requestExecutionTicket: (payload) => invoke("workbench:requestExecutionTicket", payload),
    inspectExecutionTicket: (payload) => invoke("workbench:inspectExecutionTicket", payload),
    preflightTraining: (payload) => invoke("workbench:preflightTraining", payload),
    runTraining: (payload) => invoke("workbench:runTraining", payload),
    listAuditEvents: (payload) => invoke("workbench:listAuditEvents", payload),
    replayAuditTrace: (payload) => invoke("workbench:replayAuditTrace", payload)
  }),
);
