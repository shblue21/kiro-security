import type * as vscode from "vscode";

import { baseCspDirectives, documentStart } from "./setupViewHtml";

export function renderUnsupportedHostHtml(webview: vscode.Webview): string {
  return `${documentStart(baseCspDirectives(webview.cspSource))}
<body>
  <header class="topbar"><div class="brand-lockup"><h1>Kiro Security</h1></div></header>
  <main class="content">
    <section class="panel-section connection-panel">
      <h2>Kiro IDE is required</h2>
      <p class="muted">This Extension can be installed here, but its security workflow runs only in Kiro IDE.</p>
    </section>
  </main>
</body>
</html>`;
}
