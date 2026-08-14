export type ViewTab = "setup" | "dashboard" | "findings";

export function setupViewScript(activeTab: ViewTab): string {
  return `
    const vscode = acquireVsCodeApi();
    const tabNames = ['setup', 'dashboard', 'findings'];
    const serverActiveTab = ${JSON.stringify(activeTab)};
    const isTabName = (value) => tabNames.includes(value);
    const activateTab = (name, notifyHost = true) => {
      if (!isTabName(name)) return;
      for (const candidate of tabNames) {
        const selected = candidate === name;
        const tab = document.getElementById('tab-' + candidate);
        const panel = document.getElementById('panel-' + candidate);
        tab?.classList.toggle('active', selected);
        tab?.setAttribute('aria-selected', String(selected));
        tab?.setAttribute('tabindex', selected ? '0' : '-1');
        panel?.classList.toggle('active', selected);
        if (panel) panel.hidden = !selected;
      }
      vscode.setState({ activeTab: name });
      if (notifyHost) vscode.postMessage({ command: 'selectTab', tab: name });
    };
    for (const tab of document.querySelectorAll('[role="tab"][data-tab]')) {
      tab.addEventListener('click', () => activateTab(tab.dataset.tab));
      tab.addEventListener('keydown', (event) => {
        const current = tabNames.indexOf(tab.dataset.tab || '');
        if (current < 0) return;
        let next;
        if (event.key === 'ArrowRight') next = (current + 1) % tabNames.length;
        if (event.key === 'ArrowLeft') next = (current - 1 + tabNames.length) % tabNames.length;
        if (event.key === 'Home') next = 0;
        if (event.key === 'End') next = tabNames.length - 1;
        if (next === undefined) return;
        event.preventDefault();
        const name = tabNames[next];
        activateTab(name);
        document.getElementById('tab-' + name)?.focus();
      });
    }
    const savedTab = vscode.getState()?.activeTab;
    const initialTab = isTabName(savedTab) ? savedTab : serverActiveTab;
    activateTab(initialTab, initialTab !== serverActiveTab);
    for (const button of document.querySelectorAll('[data-command]')) {
      button.addEventListener('click', () => {
        if (!button.disabled) {
          vscode.postMessage({
            command: button.dataset.command,
            tab: button.dataset.tab,
            scanId: button.dataset.scanId,
            occurrenceId: button.dataset.occurrenceId,
            requestId: button.dataset.requestId,
            action: button.dataset.action,
            version: button.dataset.version,
            format: button.dataset.format,
            artifactKind: button.dataset.artifactKind,
            repositoryScope: button.dataset.repositoryScope
          });
        }
      });
    }
    const applyFindingFilters = () => {
      const scan = document.getElementById('scan-filter')?.value || '';
      const severity = document.getElementById('severity-filter')?.value || '';
      const triage = document.getElementById('triage-filter')?.value || '';
      let visibleCount = 0;
      for (const card of document.querySelectorAll('.finding-card')) {
        card.hidden =
          (scan && card.dataset.scanId !== scan) ||
          (severity && card.dataset.severity !== severity) ||
          (triage && card.dataset.triage !== triage);
        if (!card.hidden) visibleCount += 1;
      }
      const labels = [
        scan ? document.getElementById('scan-filter')?.selectedOptions[0]?.textContent : '',
        severity ? document.getElementById('severity-filter')?.selectedOptions[0]?.textContent : '',
        triage ? document.getElementById('triage-filter')?.selectedOptions[0]?.textContent : ''
      ].filter(Boolean);
      const summary = document.getElementById('finding-filter-summary');
      if (summary) {
        summary.textContent = labels.length
          ? labels.join(' · ') + ' · ' + visibleCount
          : 'All findings · ' + visibleCount;
      }
    };
    document.getElementById('scan-filter')?.addEventListener('change', applyFindingFilters);
    document.getElementById('severity-filter')?.addEventListener('change', applyFindingFilters);
    document.getElementById('triage-filter')?.addEventListener('change', applyFindingFilters);
  `;
}
