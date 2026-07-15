import { createApp } from "vue";

import { SDKPlugin } from "./plugins/sdk";
import "./styles/idor.css";
import "./styles/index.css";
import type { FrontendSDK } from "./types";
import App from "./views/App.vue";

const PAGE = "/idor-bola-assistant";
const ANALYZE_COMMAND = "idor-bola-assistant.analyze-request";

export const init = (sdk: FrontendSDK) => {
  const app = createApp(App);
  app.use(SDKPlugin, sdk);
  const root = document.createElement("div");
  Object.assign(root.style, { height: "100%", width: "100%" });
  root.id = "plugin--caido-idor-bola-assistant";
  app.mount(root);
  sdk.navigation.addPage(PAGE, { body: root });
  sdk.sidebar.registerItem("IDOR BOLA Assistant", PAGE, {
    icon: "fas fa-shield-halved",
  });

  sdk.commands.register(ANALYZE_COMMAND, {
    name: "Analyze with IDOR BOLA Assistant",
    group: "IDOR BOLA Assistant",
    when: (context) =>
      (context.type === "RequestRowContext" && context.requests.length > 0) ||
      context.type === "ResponseContext",
    run: (context) => {
      let requestId: string | undefined;
      if (context.type === "RequestRowContext")
        requestId = context.requests[0]?.id;
      else if (context.type === "ResponseContext")
        requestId = context.request.id;
      if (requestId === undefined) return;
      sdk.navigation.goTo(PAGE);
      void sdk.backend
        .analyzeRequest(requestId)
        .then((fingerprint) =>
          sdk.window.showToast(
            fingerprint === undefined
              ? "No IDOR/BOLA object-reference candidate was detected."
              : "Candidate analyzed and focused.",
            { variant: fingerprint === undefined ? "info" : "success" },
          ),
        )
        .catch((error: unknown) =>
          sdk.window.showToast(safeMessage(error), { variant: "error" }),
        );
    },
  });
  sdk.menu.registerItem({
    type: "RequestRow",
    commandId: ANALYZE_COMMAND,
    leadingIcon: "fas fa-shield-halved",
  });
  sdk.menu.registerItem({
    type: "Response",
    commandId: ANALYZE_COMMAND,
    leadingIcon: "fas fa-shield-halved",
  });
};

function safeMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
