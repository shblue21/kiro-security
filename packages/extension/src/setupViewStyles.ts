export function setupStyles(): string {
  return `
    :root {
      --bg:      oklch(98% 0.005 250);
      --surface: oklch(100% 0 0);
      --fg:      oklch(22% 0.02 240);
      --muted:   oklch(50% 0.018 240);
      --border:  oklch(90% 0.008 240);
      --accent:  oklch(58% 0.16 145);

      --font-body:    -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', system-ui, sans-serif;
      --font-mono:    'JetBrains Mono', 'IBM Plex Mono', ui-monospace, Menlo, monospace;
      color-scheme: light dark;
    }
    * { box-sizing: border-box; }
    html { min-width: 0; }
    body {
      margin: 0;
      min-width: 0;
      color: var(--vscode-foreground, var(--fg));
      background: var(--vscode-sideBar-background, var(--bg));
      font: 13px/1.5 var(--vscode-font-family, var(--font-body));
      -webkit-font-smoothing: antialiased;
    }
    button, summary, select { font: inherit; }
    button {
      min-height: 32px;
      border: 1px solid var(--vscode-button-border, transparent);
      border-radius: 4px;
      padding: 5px 10px;
      color: var(--vscode-button-secondaryForeground, var(--fg));
      background: var(--vscode-button-secondaryBackground, var(--border));
      cursor: pointer;
      letter-spacing: .02em;
      transition: background-color 120ms ease, border-color 120ms ease, transform 120ms ease;
    }
    button:hover:not(:disabled) { background: var(--vscode-button-secondaryHoverBackground, color-mix(in oklch, var(--border) 72%, var(--fg))); }
    button:active:not(:disabled) { transform: translateY(1px); }
    button:focus-visible, summary:focus-visible, select:focus-visible {
      outline: 1px solid var(--vscode-focusBorder, var(--accent));
      outline-offset: 2px;
    }
    button:disabled { opacity: .46; cursor: not-allowed; }
    button.primary {
      color: var(--vscode-button-foreground, var(--surface));
      background: var(--vscode-button-background, var(--accent));
    }
    button.primary:hover:not(:disabled) { background: var(--vscode-button-hoverBackground, color-mix(in oklch, var(--accent) 82%, var(--fg))); }
    code, .mono, .tabular { font-family: var(--vscode-editor-font-family, var(--font-mono)); font-variant-numeric: tabular-nums; }
    code { font-size: .92em; }
    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      min-height: 42px;
      padding: 7px 10px;
      background: var(--vscode-sideBar-background, var(--bg));
    }
    .brand-lockup { min-width: 0; }
    .topbar h1 { margin: 0; overflow: hidden; font-size: 13px; font-weight: 650; text-overflow: ellipsis; white-space: nowrap; }
    .card p { margin: 2px 0 0; }
    .icon-button { width: 32px; border-color: transparent; background: transparent; font-size: 17px; padding: 3px; }
    .tabs {
      display: flex;
      border-block: 1px solid var(--vscode-panel-border, var(--border));
      padding: 0 6px;
      background: var(--vscode-sideBar-background, var(--bg));
    }
    .tab { position: relative; flex: 1; min-height: 36px; border: 0; border-radius: 0; background: transparent; padding: 7px 5px; color: var(--vscode-descriptionForeground, var(--muted)); }
    .tab:hover:not(:disabled) { color: var(--vscode-foreground, var(--fg)); background: var(--vscode-list-hoverBackground, color-mix(in oklch, var(--border) 65%, transparent)); }
    .tab.active { color: var(--vscode-foreground, var(--fg)); font-weight: 600; }
    .tab.active::after { content: ""; position: absolute; inset: auto 7px -1px; height: 2px; background: var(--vscode-focusBorder, var(--accent)); }
    .content { width: min(100%, 760px); margin-inline: auto; padding: 12px 10px 16px; display: grid; gap: 12px; }
    .page { min-width: 0; display: none; gap: 12px; }
    .page.active { display: grid; }
    .setup-page.active { display: block; }
    .feedback {
      border: 1px solid var(--vscode-focusBorder, var(--accent));
      border-radius: 5px;
      padding: 8px 10px;
      background: var(--vscode-textBlockQuote-background, var(--surface));
      overflow-wrap: anywhere;
    }
    .card {
      min-width: 0;
      border: 1px solid var(--vscode-panel-border, var(--border));
      border-radius: 6px;
      padding: 14px;
      background: var(--vscode-editor-background, var(--surface));
    }
    .panel-section {
      min-width: 0;
      padding: 2px 2px 14px;
      border-bottom: 1px solid var(--vscode-panel-border, var(--border));
    }
    .status-hero, .card-title, .section-heading {
      display: flex;
      justify-content: space-between;
      gap: 12px;
    }
    .status-hero { align-items: center; }
    .card-title, .section-heading { align-items: flex-start; }
    .status-hero > div, .card-title > div, .section-heading > div { min-width: 0; }
    .status-hero h2 { margin: 0; font-size: 14px; line-height: 1.3; }
    .status-hero p { margin-top: 4px; }
    .card-title h2, .section-heading h2 { margin: 0; font-size: 14px; line-height: 1.35; overflow-wrap: anywhere; }
    .section-heading h2 { margin-top: 3px; font-size: 16px; }
    .card-title p { color: var(--vscode-descriptionForeground, var(--muted)); overflow-wrap: anywhere; }
    .eyebrow { color: var(--vscode-descriptionForeground, var(--muted)); font: 600 10px/1.2 var(--vscode-editor-font-family, var(--font-mono)); letter-spacing: .07em; text-transform: uppercase; }
    .badge {
      flex: none;
      border: 1px solid currentColor;
      border-radius: 999px;
      padding: 2px 7px;
      font: 600 10px/1.45 var(--vscode-editor-font-family, var(--font-mono));
      white-space: nowrap;
    }
    .badge-neutral { color: var(--vscode-descriptionForeground, var(--muted)); background: color-mix(in oklch, currentColor 7%, transparent); }
    .badge-ready { color: var(--vscode-testing-iconPassed, var(--accent)); background: color-mix(in oklch, currentColor 8%, transparent); }
    .badge-warning { color: var(--vscode-editorWarning-foreground, var(--muted)); background: color-mix(in oklch, currentColor 8%, transparent); }
    .badge-error { color: var(--vscode-errorForeground, var(--fg)); background: color-mix(in oklch, currentColor 8%, transparent); }
    .connection-panel .badge {
      border: 0;
      border-radius: 0;
      padding: 0;
      background: transparent;
      font: 600 11px/1.45 var(--vscode-font-family, var(--font-body));
    }
    .connection-panel .badge-ready::before { content: "✓"; margin-right: 4px; }
    .context-list {
      display: grid;
      gap: 6px;
      margin-top: 11px;
      padding-top: 10px;
      border-top: 1px solid var(--vscode-panel-border, var(--border));
    }
    .context-row { display: grid; grid-template-columns: 48px minmax(0, 1fr); gap: 8px; align-items: start; }
    .context-row > span { color: var(--vscode-descriptionForeground, var(--muted)); font-size: 11px; }
    .context-row > strong { min-width: 0; font-size: 12px; font-weight: 500; overflow-wrap: anywhere; }
    .quick-start { padding-top: 12px; }
    .quick-start > p { max-width: 46ch; }
    .prompt-row { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 6px; align-items: stretch; margin-top: 6px; }
    .prompt-row code {
      min-width: 0;
      padding: 7px 8px;
      border: 1px solid var(--vscode-input-border, var(--border));
      border-radius: 3px;
      color: var(--vscode-input-foreground, var(--fg));
      background: var(--vscode-input-background, var(--surface));
      font-size: 11px;
      line-height: 1.4;
      overflow-wrap: anywhere;
    }
    .copy-button { min-height: 0; padding-inline: 9px; }
    .result-note { margin-top: 7px; font-size: 11px; }
    .diagnostic-panel { padding: 0; }
    .diagnostic-panel > summary { display: flex; align-items: center; gap: 8px; min-height: 40px; padding: 8px 2px; color: var(--vscode-descriptionForeground, var(--muted)); }
    .summary-status { margin-left: auto; font: 600 10px/1.3 var(--vscode-editor-font-family, var(--font-mono)); white-space: nowrap; }
    .summary-status.ready { color: var(--vscode-testing-iconPassed, var(--accent)); }
    .summary-status.pending { color: var(--vscode-editorWarning-foreground, var(--muted)); }
    .details-body { padding: 10px 12px 12px; border-top: 1px solid var(--vscode-panel-border, var(--border)); }
    .diagnostic-panel > .details-body { padding: 2px 2px 14px; border-top: 0; }
    .compact-checks { display: grid; gap: 9px; }
    .compact-check { display: flex; align-items: flex-start; justify-content: space-between; gap: 8px; min-width: 0; }
    .compact-check > div { min-width: 0; }
    .compact-check strong { display: block; font-size: 12px; }
    .compact-check .muted { display: block; margin-top: 1px; font-size: 11px; }
    .compact-check > span:last-child { color: var(--vscode-testing-iconPassed, var(--accent)); font: 700 10px/1 var(--vscode-editor-font-family, var(--font-mono)); }
    .compact-check > span.pending { color: var(--vscode-editorWarning-foreground, var(--muted)); }
    .nested-details { margin-top: 10px; border-top: 1px solid var(--vscode-panel-border, var(--border)); padding-top: 9px; }
    .nested-details .details-body { padding-inline: 0; border-top: 0; }
    .muted { color: var(--vscode-descriptionForeground, var(--muted)); overflow-wrap: anywhere; }
    .mono { font-size: 11px; white-space: pre-wrap; overflow-wrap: anywhere; }
    .button-row { display: flex; flex-wrap: wrap; align-items: center; gap: 7px; margin-top: 12px; }
    .request-state { color: var(--vscode-descriptionForeground, var(--muted)); }
    .setup-options { margin-top: 12px; border-top: 1px solid var(--vscode-panel-border, var(--border)); padding-top: 9px; }
    .setup-options summary { border-radius: 3px; cursor: pointer; color: var(--vscode-descriptionForeground, var(--muted)); font-weight: 600; }
    .setup-options-body { padding: 10px 0 2px; }
    dl { margin: 0; display: grid; grid-template-columns: minmax(90px, auto) minmax(0, 1fr); gap: 6px 10px; }
    dt { color: var(--vscode-descriptionForeground, var(--muted)); }
    dd { margin: 0; overflow-wrap: anywhere; }
    summary > span { display: inline-flex; flex-direction: column; }
    .overview { min-width: 0; padding: 3px 2px 2px; }
    .scope-switch { display: flex; align-items: center; justify-content: space-between; gap: 10px; min-width: 0; }
    .scope-label { min-width: 0; color: var(--vscode-descriptionForeground, var(--muted)); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .scope-buttons { display: flex; flex: none; gap: 2px; }
    .scope-buttons button { min-height: 28px; padding: 3px 8px; background: transparent; }
    .scope-buttons button.active { border-color: var(--vscode-focusBorder, var(--accent)); color: var(--vscode-foreground, var(--fg)); background: var(--vscode-list-activeSelectionBackground, var(--border)); }
    .metric-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 7px; margin-top: 11px; }
    .metric { min-width: 0; border: 1px solid var(--vscode-panel-border, var(--border)); border-radius: 5px; padding: 9px; background: var(--vscode-editor-background, var(--surface)); }
    .metric span { display: block; min-height: 2.8em; color: var(--vscode-descriptionForeground, var(--muted)); font-size: 11px; line-height: 1.35; }
    .metric strong { display: block; margin-top: 2px; font: 650 18px/1.2 var(--vscode-editor-font-family, var(--font-mono)); font-variant-numeric: tabular-nums; }
    .metric-success strong { color: var(--vscode-testing-iconPassed, var(--fg)); }
    .metric-warning strong { color: var(--vscode-editorWarning-foreground, var(--fg)); }
    .metric-danger strong { color: var(--vscode-errorForeground, var(--fg)); }
    .metric-strip { display: flex; align-items: center; min-width: 0; margin-top: 9px; padding: 8px 10px; border: 1px solid var(--vscode-panel-border, var(--border)); border-radius: 5px; background: var(--vscode-editor-background, var(--surface)); }
    .metric-inline { min-width: 0; display: inline-flex; align-items: baseline; gap: 5px; color: var(--vscode-descriptionForeground, var(--muted)); font-size: 10px; white-space: nowrap; }
    .metric-inline + .metric-inline { margin-left: 9px; padding-left: 9px; border-left: 1px solid var(--vscode-panel-border, var(--border)); }
    .metric-inline strong { color: var(--vscode-foreground, var(--fg)); font: 650 13px/1 var(--vscode-editor-font-family, var(--font-mono)); font-variant-numeric: tabular-nums; }
    .metric-inline.metric-warning strong { color: var(--vscode-editorWarning-foreground, var(--fg)); }
    .metric-inline.metric-danger strong { color: var(--vscode-errorForeground, var(--fg)); }
    .section-divider { display: flex; align-items: center; gap: 8px; color: var(--vscode-descriptionForeground, var(--muted)); font: 600 10px/1 var(--vscode-editor-font-family, var(--font-mono)); letter-spacing: .05em; text-transform: uppercase; }
    .section-divider::after { content: ""; height: 1px; flex: 1; background: var(--vscode-panel-border, var(--border)); }
    .scan-facts { margin-top: 12px; }
    .progress-track { height: 4px; margin-top: 12px; overflow: hidden; border-radius: 999px; background: var(--vscode-progressBar-background, var(--border)); }
    .progress-track span { display: block; height: 100%; border-radius: inherit; background: var(--vscode-focusBorder, var(--accent)); }
    .finding-filter { padding: 0; overflow: hidden; }
    .finding-filter > summary { min-height: 42px; display: flex; align-items: center; gap: 8px; padding: 9px 12px; list-style-position: inside; }
    .filter-summary { margin-left: auto; color: var(--vscode-descriptionForeground, var(--muted)); font: 500 10px/1.3 var(--vscode-editor-font-family, var(--font-mono)); white-space: nowrap; }
    .finding-toolbar { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 9px; padding: 10px 12px 12px; border-top: 1px solid var(--vscode-panel-border, var(--border)); }
    .finding-toolbar label { display: grid; gap: 4px; color: var(--vscode-descriptionForeground, var(--muted)); font-size: 11px; }
    .badge-row { display: flex; flex: none; flex-wrap: wrap; justify-content: flex-end; gap: 5px; }
    .finding-summary { margin-top: 10px !important; }
    .quick-meta { display: flex; flex-wrap: wrap; gap: 5px 10px; margin-top: 9px; color: var(--vscode-descriptionForeground, var(--muted)); font-size: 11px; }
    .quick-meta strong { color: var(--vscode-foreground, var(--fg)); font-weight: 500; }
    .finding-details { margin-top: 10px; padding-top: 8px; }
    .blocked-action { display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: center; gap: 9px; margin-top: 11px; padding: 9px; border-radius: 4px; background: var(--vscode-textBlockQuote-background, var(--bg)); }
    .blocked-action button { min-height: 30px; color: var(--vscode-descriptionForeground, var(--muted)); }
    select { width: 100%; min-width: 0; min-height: 30px; border: 1px solid var(--vscode-dropdown-border, var(--border)); border-radius: 3px; padding: 4px 7px; color: var(--vscode-dropdown-foreground, var(--fg)); background: var(--vscode-dropdown-background, var(--surface)); }
    pre { max-height: 280px; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; padding: 8px; background: var(--vscode-textCodeBlock-background, var(--bg)); font: 11px/1.4 var(--vscode-editor-font-family, var(--font-mono)); }
    .error-text { color: var(--vscode-errorForeground, var(--fg)); }
    .empty-state { min-height: 160px; padding: 22px 2px; }
    .empty-state h2 { margin: 0; font-size: 14px; }
    .empty-state p { max-width: 42ch; }
    .empty-state button { margin-top: 10px; }
    @media (max-width: 520px) {
      .content { padding: 11px; }
      .metric-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .finding-toolbar { grid-template-columns: 1fr; }
      .blocked-action { grid-template-columns: 1fr; }
      .blocked-action button { width: 100%; }
      dl { grid-template-columns: 1fr; gap: 2px; }
      dd + dt { margin-top: 6px; }
    }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after { scroll-behavior: auto !important; transition: none !important; }
    }
  `;
}
