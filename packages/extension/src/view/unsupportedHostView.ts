import type * as vscode from "vscode";

import { setupStyles } from "./setupViewStyles";

export function renderUnsupportedHostHtml(webview: vscode.Webview): string {
  const csp = [
    "default-src 'none'",
    `style-src ${webview.cspSource} 'unsafe-inline'`,
  ].join("; ");
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="${csp}">
  <title>Kiro Security Power</title>
  <style>${setupStyles()}</style>
</head>
<body>
  <header class="topbar"><div class="brand-lockup"><h1>Kiro Security Power</h1></div></header>
  <main class="content">
    <section class="panel-section connection-panel">
      <h2>Kiro IDE is required</h2>
      <p class="muted">This Extension can be installed here, but its security workflow runs only in Kiro IDE.</p>
    </section>
  </main>
</body>
</html>`;
}
