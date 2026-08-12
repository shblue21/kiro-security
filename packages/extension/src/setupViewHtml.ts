import { randomBytes } from "node:crypto";

import type * as vscode from "vscode";

import type { KiroIntegrationInspection } from "./integration";
import type {
  DashboardProjection,
  FindingProjection,
  RecoveryRequestProjection,
  RemediationRequestProjection,
  ScanProjection,
} from "./workbenchClient";
import type { RepositoryScope } from "./workspaceProjection";

export type ViewTab = "setup" | "dashboard" | "findings";

export function renderSetupHtml(input: {
  readonly webview: vscode.Webview;
  readonly stateRoot: string;
  readonly integration: KiroIntegrationInspection;
  readonly activeTab: ViewTab;
  readonly dashboard?: DashboardProjection;
  readonly repositoryScope: RepositoryScope;
  readonly workspaceLabel: string;
  readonly hasWorkspace: boolean;
  readonly globalScanCount: number;
  readonly sourceActionScanIds: readonly string[];
  readonly feedback?: string;
}): string {
  const nonce = randomBytes(16).toString("base64");
  const csp = [
    "default-src 'none'",
    `style-src ${input.webview.cspSource} 'unsafe-inline'`,
    `script-src 'nonce-${nonce}'`,
  ].join("; ");
  const presentation = integrationPresentation(input.integration);
  return `<!doctype html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="${csp}">
  <title>Kiro Security Power</title>
  <style>${setupStyles()}</style>
</head>
<body>
  <header class="topbar" data-od-id="setup-topbar">
    <div class="brand-lockup">
      <span class="brand-mark" aria-hidden="true">KS</span>
      <div>
      <h1>Kiro Security Power</h1>
        <p>저장소 보안 워크벤치</p>
      </div>
    </div>
    <button class="icon-button" data-command="refresh" title="상태 새로고침" aria-label="상태 새로고침"><span aria-hidden="true">↻</span></button>
  </header>

  <nav class="tabs" aria-label="보안 패널" role="tablist" data-od-id="primary-tabs">
    ${tabButton("setup", "설정", input.activeTab)}
    ${tabButton("dashboard", "대시보드", input.activeTab)}
    ${tabButton("findings", "발견", input.activeTab)}
  </nav>

  <main class="content" data-od-id="setup-content">
    ${
      input.feedback
        ? `<div class="feedback" role="status" data-od-id="action-feedback">${escapeHtml(input.feedback)}</div>`
        : ""
    }

    <div class="page ${input.activeTab === "setup" ? "active" : ""}" role="tabpanel">
    <section class="card connection-card" data-od-id="kiro-chat-connection">
      <div class="status-hero">
        <div>
          <span class="eyebrow">Kiro Chat 연결</span>
          <h2 data-od-id="connection-heading">${escapeHtml(
            presentation.heading,
          )}</h2>
          <p class="muted">${escapeHtml(input.integration.detail)}</p>
        </div>
        <span class="badge ${presentation.badgeClass}">${escapeHtml(
          presentation.badge,
        )}</span>
      </div>

      <div class="workflow-summary">
        <div>
          <h3>일반 채팅에서 바로 보안 작업 시작</h3>
          <p>별도 Agent 선택이나 Power 가져오기 없이 현재 Kiro Chat에 보안 워크플로를 연결합니다.</p>
        </div>
        <button class="primary" data-command="connectIntegration" ${
          input.integration.state === "ready" ||
          input.integration.state === "conflict" ||
          input.integration.state === "unavailable"
            ? "disabled"
            : ""
        } data-od-id="connect-kiro-chat">Kiro Chat 연결</button>
      </div>

      <div class="scope-note">
        <strong>연결 방식</strong>
        <p>자동 포함 steering이 워크플로를 제공하고, 직접 도구 Hook이 각 요청 nonce를 Kiro <code>session_id</code>에 결합합니다. MCP는 이를 한 번만 소비해 채팅이 소유한 워크스페이스를 보호합니다.</p>
      </div>

      <details class="setup-options">
        <summary>설치 범위와 파일 위치</summary>
        <div class="setup-options-body">
          <dl>
            <dt>설치 범위</dt>
            <dd>현재 사용자 · 모든 Kiro Chat</dd>
            <dt>MCP 항목</dt>
            <dd class="mono">${escapeHtml(input.integration.serverKey)} in ${escapeHtml(
              input.integration.mcpPath,
            )}</dd>
            <dt>Steering</dt>
            <dd class="mono">${escapeHtml(input.integration.steeringPath)}</dd>
            <dt>Hook</dt>
            <dd class="mono">${escapeHtml(input.integration.hookPath)}</dd>
            <dt>런타임</dt>
            <dd class="mono">${escapeHtml(input.integration.runtimeRoot)}</dd>
          </dl>
        </div>
      </details>

      <details class="setup-options">
        <summary>고급 설정 및 문제 해결</summary>
        <div class="setup-options-body">
          <div class="button-row">
            <button data-command="showHookFile" ${
              input.integration.hook.registrationState === "absent"
                ? "disabled"
                : ""
            }>Hook 열기</button>
            <button data-command="showMcpFile" ${
              input.integration.mcp.state === "absent" ? "disabled" : ""
            }>MCP 설정 열기</button>
            <button data-command="showSteeringFile" ${
              input.integration.steering.state === "absent" ? "disabled" : ""
            }>Steering 열기</button>
          </div>
        </div>
      </details>
    </section>

    <details class="card setup-disclosure" open data-od-id="system-checks">
      <summary>
        <span>
          <strong>시스템 점검</strong>
          <small>저장소와 통합 경계의 현재 상태</small>
        </span>
      </summary>
      <div class="checks">
        ${checkRow("전역 저장소", input.stateRoot, true)}
        ${checkRow(
          "직접 MCP 런타임",
          input.integration.runtime.detail,
          input.integration.runtime.ready,
        )}
        ${checkRow(
          "전역 steering",
          input.integration.steering.detail,
          input.integration.steering.state === "installed",
        )}
        ${checkRow(
          "직접 MCP 등록",
          input.integration.mcp.detail,
          input.integration.mcp.state === "installed",
        )}
        ${checkRow(
          "채팅 식별 Hook",
          input.integration.hook.detail,
          input.integration.hook.state === "ready",
        )}
        ${checkRow(
          "채팅 승인 규칙",
          input.integration.approval.detail,
          input.integration.approval.state === "installed",
        )}
      </div>
    </details>
    </div>
    <div class="page ${input.activeTab === "dashboard" ? "active" : ""}" role="tabpanel">
      ${renderRepositoryScope(input)}
      ${renderDashboardPage(input)}
    </div>
    <div class="page ${input.activeTab === "findings" ? "active" : ""}" role="tabpanel">
      ${renderRepositoryScope(input)}
      ${renderFindingsPage(input)}
    </div>
  </main>
  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
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
      for (const card of document.querySelectorAll('.finding-card')) {
        card.hidden =
          (scan && card.dataset.scanId !== scan) ||
          (severity && card.dataset.severity !== severity) ||
          (triage && card.dataset.triage !== triage);
      }
    };
    document.getElementById('scan-filter')?.addEventListener('change', applyFindingFilters);
    document.getElementById('severity-filter')?.addEventListener('change', applyFindingFilters);
    document.getElementById('triage-filter')?.addEventListener('change', applyFindingFilters);
  </script>
</body>
</html>`;
}

function tabButton(
  tab: ViewTab,
  label: string,
  activeTab: ViewTab,
): string {
  const active = tab === activeTab;
  return `<button class="tab ${active ? "active" : ""}" role="tab" data-command="selectTab" data-tab="${tab}" aria-selected="${active}" ${
    active ? 'aria-current="page"' : ""
  }>${label}</button>`;
}

type RepositoryViewInput = {
  readonly dashboard?: DashboardProjection;
  readonly repositoryScope: RepositoryScope;
  readonly workspaceLabel: string;
  readonly hasWorkspace: boolean;
  readonly globalScanCount: number;
  readonly sourceActionScanIds: readonly string[];
};

function renderRepositoryScope(input: RepositoryViewInput): string {
  return `<section class="scope-switch" aria-label="저장소 표시 범위">
    <span class="scope-label">${escapeHtml(
      input.repositoryScope === "current"
        ? input.workspaceLabel
        : "이 기기의 모든 저장소",
    )}</span>
    <div class="scope-buttons">
      <button class="${input.repositoryScope === "current" ? "active" : ""}" data-command="selectRepositoryScope" data-repository-scope="current" aria-pressed="${input.repositoryScope === "current"}">현재</button>
      <button class="${input.repositoryScope === "all" ? "active" : ""}" data-command="selectRepositoryScope" data-repository-scope="all" aria-pressed="${input.repositoryScope === "all"}">모든 저장소</button>
    </div>
  </section>`;
}

function renderDashboardPage(
  input: RepositoryViewInput,
): string {
  const dashboard = input.dashboard;
  if (!dashboard) {
    return emptyState(
      "대시보드를 불러올 수 없습니다",
      "확장 전역 워크벤치를 초기화하려면 Kiro Security Chat을 연결하세요.",
    );
  }
  if (dashboard.scans.length === 0) {
    if (input.repositoryScope === "current" && !input.hasWorkspace) {
      return emptyState(
        "열린 워크스페이스가 없습니다",
        "저장소를 열거나 모든 저장소를 선택해 이전 스캔을 확인하세요.",
        input.globalScanCount > 0,
      );
    }
    if (input.repositoryScope === "current") {
      return emptyState(
        "현재 워크스페이스에는 스캔이 없습니다",
        input.globalScanCount > 0
          ? `다른 저장소에 ${input.globalScanCount}개의 스캔이 있습니다.`
          : "일반 Kiro Chat에서 Kiro Security 스캔을 시작하세요. 확장 자체는 스캔을 시작하지 않습니다.",
        input.globalScanCount > 0,
      );
    }
    return emptyState(
      "아직 실행한 스캔이 없습니다",
      "일반 Kiro Chat에서 Kiro Security 스캔을 시작하세요. 확장 자체는 스캔을 시작하지 않습니다.",
    );
  }
  const running = dashboard.scans.filter((scan) => scan.status === "running").length;
  const complete = dashboard.scans.filter((scan) => scan.status === "complete").length;
  const findings = dashboard.findings.filter(
    (finding) => finding.severity !== "informational",
  ).length;
  const overview = `<section class="overview" data-od-id="dashboard-overview">
    <div class="section-heading">
      <div>
        <span class="eyebrow">워크벤치 현황</span>
        <h2>보안 스캔</h2>
      </div>
      <span class="muted">최근 업데이트 기준</span>
    </div>
    <div class="metric-grid">
      ${metricCard("전체", dashboard.scans.length)}
      ${metricCard("실행 중", running, "metric-warning")}
      ${metricCard("완료", complete, "metric-success")}
      ${metricCard("보고 가능한 발견", findings, findings > 0 ? "metric-danger" : "")}
    </div>
  </section>`;
  const scans = dashboard.scans
    .map((scan) =>
      renderScanCard(
        scan,
        dashboard.recoveryRequests.filter(
          (request) => request.scanId === scan.id,
        ),
        input.sourceActionScanIds.includes(scan.id),
      ),
    )
    .join("");
  return `${overview}<div class="section-divider"><span>스캔 기록</span></div>${scans}`;
}

function renderScanCard(
  scan: ScanProjection,
  recoveryRequests: readonly RecoveryRequestProjection[],
  sourceActionReady: boolean,
): string {
  const total = scan.progress.reviewItemsTotal;
  const complete = scan.progress.reviewItemsCompleted;
  const percent = total === 0 ? 0 : Math.floor((complete / total) * 100);
  const artifactButtons =
    scan.status === "complete"
      ? `
        <button data-command="openArtifact" data-scan-id="${escapeHtml(
          scan.id,
        )}" data-artifact-kind="report">보고서</button>
        <button data-command="openArtifact" data-scan-id="${escapeHtml(
          scan.id,
        )}" data-artifact-kind="manifest">매니페스트</button>
        <button data-command="openArtifact" data-scan-id="${escapeHtml(
          scan.id,
        )}" data-artifact-kind="coverage">커버리지</button>
        <button data-command="exportScan" data-scan-id="${escapeHtml(
          scan.id,
        )}" data-format="sarif">SARIF 내보내기</button>
        <button data-command="exportScan" data-scan-id="${escapeHtml(
          scan.id,
        )}" data-format="csv">CSV 내보내기</button>`
      : "";
  const recovery =
    scan.status === "running"
      ? renderRecoveryControls(scan.id, recoveryRequests[0], sourceActionReady)
      : "";
  return `<section class="card scan-card" data-od-id="scan-${escapeHtml(scan.id)}">
    <div class="card-title">
      <div>
        <h2>${escapeHtml(scan.target.path)}</h2>
        <p>${escapeHtml(scan.mode)} · 범위 ${escapeHtml(scan.scope)}</p>
      </div>
      <span class="badge ${statusBadge(scan.status)}">${scanStatusLabel(scan.status)}</span>
    </div>
    <div class="progress-track" role="progressbar" aria-label="스캔 진행률" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${percent}">
      <span style="width: ${percent}%"></span>
    </div>
    <dl class="scan-facts">
      <dt>단계</dt><dd>${escapeHtml(scan.phase)}</dd>
      <dt>리비전</dt><dd class="mono">${escapeHtml(
        scan.target.revision,
      )}</dd>
      <dt>진행률</dt><dd class="tabular">${complete}/${total} (${percent}%)</dd>
      <dt>발견</dt><dd class="tabular">${scan.progress.reportableFindingsCount}</dd>
      <dt>업데이트</dt><dd>${escapeHtml(scan.updatedAt)}</dd>
    </dl>
    ${
      scan.failureMessage
        ? `<p class="error-text">${escapeHtml(scan.failureMessage)}</p>`
        : ""
    }
    <div class="button-row">${recovery}${artifactButtons}</div>
  </section>`;
}

function renderRecoveryControls(
  scanId: string,
  request: RecoveryRequestProjection | undefined,
  sourceActionReady: boolean,
): string {
  if (!sourceActionReady) {
    return '<span class="request-state">이 저장소를 현재 워크스페이스에서 열어 채팅으로 재개하세요.</span>';
  }
  if (!request) {
    return `<button class="primary" data-command="createRecovery" data-scan-id="${escapeHtml(
      scanId,
    )}">채팅에서 재개</button>`;
  }
  if (request.status === "delivered" || request.status === "canceled") {
    return `<span class="request-state">최근 재개 요청 ${escapeHtml(
      requestStateLabel(request.status),
    )} · v${request.version}</span>
      <button class="primary" data-command="createRecovery" data-scan-id="${escapeHtml(
        scanId,
      )}">채팅에서 재개</button>`;
  }
  return `<span class="request-state">재개 요청 ${escapeHtml(
    requestStateLabel(request.status),
  )} · v${request.version}</span>
    <button class="primary" data-command="createRecovery" data-scan-id="${escapeHtml(
      scanId,
    )}">재개 프롬프트 다시 복사</button>
    <button data-command="cancelRecovery" data-request-id="${escapeHtml(
      request.id,
    )}">재개 취소</button>`;
}

function renderFindingsPage(
  input: RepositoryViewInput,
): string {
  const dashboard = input.dashboard;
  if (!dashboard) {
    return emptyState(
      "발견 목록을 불러올 수 없습니다",
      "확장 전역 워크벤치를 초기화하려면 Kiro Security Chat을 연결하세요.",
    );
  }
  if (dashboard.findings.length === 0) {
    if (input.repositoryScope === "current" && !input.hasWorkspace) {
      return emptyState(
        "열린 워크스페이스가 없습니다",
        "저장소를 열거나 모든 저장소를 선택해 이전 발견을 확인하세요.",
        input.globalScanCount > dashboard.scans.length,
      );
    }
    return emptyState(
      input.repositoryScope === "current"
        ? "현재 워크스페이스에는 완료된 발견이 없습니다"
        : "완료된 발견이 없습니다",
      input.repositoryScope === "current" &&
        input.globalScanCount > dashboard.scans.length
        ? "다른 저장소의 결과는 모든 저장소 보기에서 확인할 수 있습니다."
        : "표준 스캔 최종화에 성공한 뒤 검증된 발견이 이곳에 표시됩니다.",
      input.repositoryScope === "current" &&
        input.globalScanCount > dashboard.scans.length,
    );
  }
  const findingScans = dashboard.scans.filter((scan) =>
    dashboard.findings.some((finding) => finding.scanId === scan.id),
  );
  const urgent = dashboard.findings.filter((finding) =>
    finding.severity === "critical" || finding.severity === "high"
  ).length;
  const open = dashboard.findings.filter((finding) => finding.triage.status === "open").length;
  const overview = `<section class="overview" data-od-id="findings-overview">
    <div class="section-heading">
      <div>
        <span class="eyebrow">검증 결과</span>
        <h2>보안 발견</h2>
      </div>
      <span class="muted">최종화된 스캔만 포함</span>
    </div>
    <div class="metric-grid metric-grid-compact">
      ${metricCard("전체", dashboard.findings.length)}
      ${metricCard("높음 이상", urgent, urgent > 0 ? "metric-danger" : "")}
      ${metricCard("열림", open, open > 0 ? "metric-warning" : "")}
    </div>
  </section>`;
  const filters = `
    <section class="card finding-toolbar" data-od-id="finding-filters">
      <label>스캔
        <select id="scan-filter">
          <option value="">모든 스캔</option>
          ${findingScans
            .map(
              (scan) =>
                `<option value="${escapeHtml(scan.id)}">${escapeHtml(
                  `${scan.target.path} · ${scan.target.revision}`,
                )}</option>`,
            )
            .join("")}
        </select>
      </label>
      <label>심각도
        <select id="severity-filter">
          <option value="">전체</option>
          <option value="critical">치명적</option>
          <option value="high">높음</option>
          <option value="medium">중간</option>
          <option value="low">낮음</option>
        </select>
      </label>
      <label>상태
        <select id="triage-filter">
          <option value="">전체</option>
          <option value="open">열림</option>
          <option value="closed">닫힘</option>
        </select>
      </label>
    </section>`;
  return `${overview}${filters}${dashboard.findings
    .map((finding) =>
      renderFindingCard(
        finding,
        dashboard,
        dashboard.scans.find((scan) => scan.id === finding.scanId),
        input.sourceActionScanIds.includes(finding.scanId),
      ),
    )
    .join("")}`;
}

function renderFindingCard(
  finding: FindingProjection,
  dashboard: DashboardProjection,
  scan: ScanProjection | undefined,
  sourceActionReady: boolean,
): string {
  const latest = dashboard.remediationRequests
    .filter(
      (request) => request.occurrenceId === finding.occurrenceId,
    )
    .sort((left, right) =>
      right.updatedAt.localeCompare(left.updatedAt),
    )[0];
  let remediationButton = "";
  if (!sourceActionReady) {
    remediationButton = '<span class="request-state">수정 작업을 계속하려면 이 저장소를 여세요.</span>';
  } else if (latest?.pendingAction) {
    remediationButton = remediationPromptButtonHtml(latest);
  } else if (
    !latest ||
    ["verified", "failed", "superseded"].includes(latest.state)
  ) {
    remediationButton = remediationButtonHtml(finding, "generate");
  } else if (latest.state === "generated") {
    remediationButton = remediationButtonHtml(
      finding,
      "apply",
      latest.requestId,
    );
  } else if (latest.state === "applied") {
    remediationButton = remediationButtonHtml(
      finding,
      "verify",
      latest.requestId,
    );
  }
  const triageButton =
    finding.triage.status === "open"
      ? `<button data-command="closeTriage" data-occurrence-id="${escapeHtml(
          finding.occurrenceId,
        )}">닫기</button>`
      : `<button data-command="openTriage" data-occurrence-id="${escapeHtml(
          finding.occurrenceId,
        )}">다시 열기</button>`;
  const locations = finding.locations
    .map(
      (location) =>
        `${escapeHtml(location.path)}:${location.startLine}${
          location.endLine !== location.startLine
            ? `-${location.endLine}`
            : ""
        }${location.role ? ` · ${escapeHtml(location.role)}` : ""}`,
    )
    .join("<br>");
  return `<section class="card finding-card" data-od-id="finding-${escapeHtml(
    finding.occurrenceId,
  )}" data-scan-id="${escapeHtml(
    finding.scanId,
  )}" data-severity="${escapeHtml(
    finding.severity,
  )}" data-triage="${escapeHtml(finding.triage.status)}">
    <div class="card-title">
      <div>
        <h2>${escapeHtml(finding.title)}</h2>
        <p>${escapeHtml(finding.findingId)}</p>
      </div>
      <span class="badge ${severityBadge(finding.severity)}">${severityLabel(finding.severity)}</span>
    </div>
    <p>${escapeHtml(finding.summary)}</p>
    <dl class="scan-facts">
      <dt>신뢰도</dt><dd>${escapeHtml(finding.confidence)}</dd>
      <dt>대상</dt><dd class="mono">${escapeHtml(
        scan?.target.path ?? "알 수 없는 대상",
      )}</dd>
      <dt>리비전</dt><dd class="mono">${escapeHtml(
        scan?.target.revision ?? "알 수 없는 리비전",
      )}</dd>
      <dt>분류 상태</dt><dd>${triageLabel(finding.triage.status)}${
        finding.triage.closeReason
          ? ` · ${escapeHtml(finding.triage.closeReason)}`
          : ""
      }</dd>
      <dt>위치</dt><dd class="mono">${locations}</dd>
    </dl>
    <details class="setup-options">
      <summary>권장 수정 방법</summary>
      <div class="setup-options-body">
        <p>${escapeHtml(finding.remediation)}</p>
        <p class="muted">전체 증거, 검증 결과와 공격 경로는 봉인된 JSON 내보내기에서 확인할 수 있습니다.</p>
      </div>
    </details>
    <div class="button-row">
      ${triageButton}
      ${remediationButton}
      <button data-command="trackFinding" data-occurrence-id="${escapeHtml(
        finding.occurrenceId,
      )}">추적</button>
      <button data-command="exportScan" data-scan-id="${escapeHtml(
        finding.scanId,
      )}" data-format="json">JSON 내보내기</button>
    </div>
  </section>`;
}

function remediationPromptButtonHtml(
  request: RemediationRequestProjection,
): string {
  const action = request.pendingAction;
  if (!action) {
    return "";
  }
  return `<button class="primary" data-command="copyRemediationPrompt" data-request-id="${escapeHtml(
    request.requestId,
  )}" data-action="${escapeHtml(action)}" data-version="${
    request.version
  }">${remediationActionLabel(action)} 프롬프트 다시 복사</button>`;
}

function remediationButtonHtml(
  finding: FindingProjection,
  action: "generate" | "apply" | "verify",
  requestId?: string,
): string {
  return `<button class="${action === "apply" ? "primary" : ""}" data-command="requestRemediation" data-occurrence-id="${escapeHtml(
    finding.occurrenceId,
  )}" data-action="${action}" ${
    requestId ? `data-request-id="${escapeHtml(requestId)}"` : ""
  }>${remediationActionLabel(action)}</button>`;
}

function metricCard(label: string, value: number, tone = ""): string {
  return `<div class="metric ${tone}"><span>${escapeHtml(label)}</span><strong>${value}</strong></div>`;
}

function remediationActionLabel(action: "generate" | "apply" | "verify"): string {
  switch (action) {
    case "generate":
      return "수정안 생성";
    case "apply":
      return "수정 적용";
    case "verify":
      return "수정 검증";
  }
}

function scanStatusLabel(status: string): string {
  const labels: Readonly<Record<string, string>> = {
    running: "실행 중",
    complete: "완료",
    failed: "실패",
    canceled: "취소됨",
  };
  return escapeHtml(labels[status] ?? status);
}

function requestStateLabel(status: string): string {
  const labels: Readonly<Record<string, string>> = {
    pending: "대기 중",
    claimed: "처리 중",
    delivered: "전달됨",
    canceled: "취소됨",
  };
  return labels[status] ?? status;
}

function severityLabel(severity: string): string {
  const labels: Readonly<Record<string, string>> = {
    critical: "치명적",
    high: "높음",
    medium: "중간",
    low: "낮음",
  };
  return escapeHtml(labels[severity] ?? severity);
}

function triageLabel(status: string): string {
  return status === "open" ? "열림" : status === "closed" ? "닫힘" : escapeHtml(status);
}

function emptyState(
  title: string,
  detail: string,
  showAllRepositories = false,
): string {
  return `<section class="card empty-state" data-od-id="empty-state"><span class="empty-mark" aria-hidden="true">—</span><h2>${escapeHtml(
    title,
  )}</h2><p class="muted">${escapeHtml(detail)}</p>${
    showAllRepositories
      ? '<button class="primary" data-command="selectRepositoryScope" data-repository-scope="all">모든 저장소 보기</button>'
      : ""
  }</section>`;
}

function statusBadge(status: string): string {
  if (status === "complete") {
    return "badge-ready";
  }
  if (status === "failed" || status === "canceled") {
    return "badge-error";
  }
  return "badge-warning";
}

function severityBadge(severity: string): string {
  return severity === "critical" || severity === "high"
    ? "badge-error"
    : severity === "medium"
      ? "badge-warning"
      : "badge-neutral";
}

function integrationPresentation(integration: KiroIntegrationInspection): {
  readonly badge: string;
  readonly badgeClass: string;
  readonly heading: string;
} {
  switch (integration.state) {
    case "ready":
      return {
        badge: "연결됨",
        badgeClass: "badge-ready",
        heading: "Kiro Security가 연결되어 있습니다",
      };
    case "mismatch":
      return {
        badge: "설정 확인 필요",
        badgeClass: "badge-warning",
        heading: "설정이 완전하지 않거나 현재 확장과 다릅니다",
      };
    case "conflict":
      return {
        badge: "충돌",
        badgeClass: "badge-error",
        heading: "Kiro 통합 경로 또는 MCP 키가 충돌합니다",
      };
    case "unavailable":
      return {
        badge: "사용 불가",
        badgeClass: "badge-error",
        heading: "Kiro Security를 구성할 수 없습니다",
      };
    case "absent":
      return {
        badge: "연결 안 됨",
        badgeClass: "badge-neutral",
        heading: "Kiro Security가 아직 연결되지 않았습니다",
      };
  }
}

function setupStyles(): string {
  return `
    :root {
      --bg:      oklch(98% 0.005 250);
      --surface: oklch(100% 0 0);
      --fg:      oklch(22% 0.02 240);
      --muted:   oklch(50% 0.018 240);
      --border:  oklch(90% 0.008 240);
      --accent:  oklch(58% 0.16 145);

      --font-display: -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', system-ui, sans-serif;
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
      box-shadow: 0 1px 1px color-mix(in oklch, var(--fg) 20%, transparent), 0 2px 8px color-mix(in oklch, var(--fg) 12%, transparent);
    }
    button.primary:hover:not(:disabled) { background: var(--vscode-button-hoverBackground, color-mix(in oklch, var(--accent) 82%, var(--fg))); }
    code, .mono, .tabular { font-family: var(--vscode-editor-font-family, var(--font-mono)); font-variant-numeric: tabular-nums; }
    code { font-size: .92em; }
    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      min-height: 60px;
      padding: 12px 14px 10px;
      background: var(--vscode-sideBar-background, var(--bg));
    }
    .brand-lockup { display: flex; align-items: center; gap: 9px; min-width: 0; }
    .brand-mark {
      width: 28px;
      height: 28px;
      flex: none;
      display: inline-grid;
      place-items: center;
      border: 1px solid var(--vscode-panel-border, var(--border));
      border-radius: 6px;
      color: var(--vscode-foreground, var(--fg));
      background: var(--vscode-editor-background, var(--surface));
      font: 700 10px/1 var(--vscode-editor-font-family, var(--font-mono));
      letter-spacing: .04em;
    }
    .topbar h1 { margin: 0; overflow: hidden; font-size: 13px; font-weight: 650; text-overflow: ellipsis; white-space: nowrap; }
    .topbar p, .card p { margin: 2px 0 0; }
    .topbar p { color: var(--vscode-descriptionForeground, var(--muted)); font-size: 11px; }
    .icon-button { width: 32px; border-color: transparent; background: transparent; font-size: 17px; padding: 3px; }
    .tabs {
      display: flex;
      gap: 2px;
      border-block: 1px solid var(--vscode-panel-border, var(--border));
      padding: 0 9px;
      background: var(--vscode-sideBar-background, var(--bg));
    }
    .tab { position: relative; min-height: 36px; border: 0; border-radius: 0; background: transparent; padding: 7px 9px; color: var(--vscode-descriptionForeground, var(--muted)); }
    .tab:hover:not(:disabled) { color: var(--vscode-foreground, var(--fg)); background: var(--vscode-list-hoverBackground, color-mix(in oklch, var(--border) 65%, transparent)); }
    .tab.active { color: var(--vscode-foreground, var(--fg)); font-weight: 600; }
    .tab.active::after { content: ""; position: absolute; inset: auto 7px -1px; height: 2px; background: var(--vscode-focusBorder, var(--accent)); }
    .content { width: min(100%, 760px); margin-inline: auto; padding: 14px; display: grid; gap: 12px; }
    .page { min-width: 0; display: none; gap: 12px; }
    .page.active { display: grid; }
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
    .status-hero, .card-title, .section-heading {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 12px;
    }
    .status-hero > div, .card-title > div, .section-heading > div { min-width: 0; }
    .status-hero h2 { margin: 4px 0 0; font-size: 17px; line-height: 1.3; letter-spacing: -.012em; }
    .status-hero p { margin-top: 5px; }
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
    .workflow-summary {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      align-items: center;
      gap: 14px;
      margin-top: 14px;
      padding-block: 13px;
      border-block: 1px solid var(--vscode-panel-border, var(--border));
    }
    .workflow-summary h3 { margin: 0; font-size: 13px; }
    .workflow-summary p { color: var(--vscode-descriptionForeground, var(--muted)); }
    .scope-note { margin-top: 12px; padding: 10px; border-radius: 4px; color: var(--vscode-descriptionForeground, var(--muted)); background: var(--vscode-textBlockQuote-background, var(--bg)); }
    .scope-note strong { color: var(--vscode-foreground, var(--fg)); font-size: 12px; }
    .scope-note p { margin-top: 4px; }
    .muted { color: var(--vscode-descriptionForeground, var(--muted)); overflow-wrap: anywhere; }
    .mono { font-size: 11px; white-space: pre-wrap; overflow-wrap: anywhere; }
    .button-row { display: flex; flex-wrap: wrap; align-items: center; gap: 7px; margin-top: 12px; }
    .request-state { color: var(--vscode-descriptionForeground, var(--muted)); }
    .setup-options { margin-top: 12px; border-top: 1px solid var(--vscode-panel-border, var(--border)); padding-top: 9px; }
    .setup-options summary, .setup-disclosure summary { border-radius: 3px; cursor: pointer; font-weight: 600; }
    .setup-options summary { color: var(--vscode-descriptionForeground, var(--muted)); }
    .setup-options-body { padding: 10px 0 2px; }
    dl { margin: 0; display: grid; grid-template-columns: minmax(90px, auto) minmax(0, 1fr); gap: 6px 10px; }
    dt { color: var(--vscode-descriptionForeground, var(--muted)); }
    dd { margin: 0; overflow-wrap: anywhere; }
    .checks { margin-top: 12px; display: grid; gap: 10px; }
    .check { display: grid; grid-template-columns: 18px minmax(0, 1fr); gap: 9px; align-items: start; }
    .check-icon { width: 18px; height: 18px; border-radius: 50%; display: inline-grid; place-items: center; border: 1px solid var(--vscode-panel-border, var(--border)); font: 700 10px/1 var(--vscode-editor-font-family, var(--font-mono)); }
    .check-icon.ok { color: var(--vscode-testing-iconPassed, var(--accent)); border-color: currentColor; }
    .check-icon.pending { color: var(--vscode-editorWarning-foreground, var(--muted)); border-color: currentColor; }
    .check strong, .check span:last-child { display: block; }
    summary > span { display: inline-flex; flex-direction: column; }
    summary small { color: var(--vscode-descriptionForeground, var(--muted)); font-weight: normal; }
    .overview { min-width: 0; padding: 3px 2px 2px; }
    .scope-switch { display: flex; align-items: center; justify-content: space-between; gap: 10px; min-width: 0; }
    .scope-label { min-width: 0; color: var(--vscode-descriptionForeground, var(--muted)); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .scope-buttons { display: flex; flex: none; gap: 2px; }
    .scope-buttons button { min-height: 28px; padding: 3px 8px; background: transparent; }
    .scope-buttons button.active { border-color: var(--vscode-focusBorder, var(--accent)); color: var(--vscode-foreground, var(--fg)); background: var(--vscode-list-activeSelectionBackground, var(--border)); }
    .metric-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 7px; margin-top: 11px; }
    .metric-grid-compact { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    .metric { min-width: 0; border: 1px solid var(--vscode-panel-border, var(--border)); border-radius: 5px; padding: 9px; background: var(--vscode-editor-background, var(--surface)); }
    .metric span { display: block; min-height: 2.8em; color: var(--vscode-descriptionForeground, var(--muted)); font-size: 11px; line-height: 1.35; }
    .metric strong { display: block; margin-top: 2px; font: 650 18px/1.2 var(--vscode-editor-font-family, var(--font-mono)); font-variant-numeric: tabular-nums; }
    .metric-success strong { color: var(--vscode-testing-iconPassed, var(--fg)); }
    .metric-warning strong { color: var(--vscode-editorWarning-foreground, var(--fg)); }
    .metric-danger strong { color: var(--vscode-errorForeground, var(--fg)); }
    .section-divider { display: flex; align-items: center; gap: 8px; color: var(--vscode-descriptionForeground, var(--muted)); font: 600 10px/1 var(--vscode-editor-font-family, var(--font-mono)); letter-spacing: .05em; text-transform: uppercase; }
    .section-divider::after { content: ""; height: 1px; flex: 1; background: var(--vscode-panel-border, var(--border)); }
    .scan-facts { margin-top: 12px; }
    .progress-track { height: 4px; margin-top: 12px; overflow: hidden; border-radius: 999px; background: var(--vscode-progressBar-background, var(--border)); }
    .progress-track span { display: block; height: 100%; border-radius: inherit; background: var(--vscode-focusBorder, var(--accent)); }
    .finding-toolbar { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 9px; }
    .finding-toolbar label { display: grid; gap: 4px; color: var(--vscode-descriptionForeground, var(--muted)); font-size: 11px; }
    select { width: 100%; min-width: 0; min-height: 30px; border: 1px solid var(--vscode-dropdown-border, var(--border)); border-radius: 3px; padding: 4px 7px; color: var(--vscode-dropdown-foreground, var(--fg)); background: var(--vscode-dropdown-background, var(--surface)); }
    pre { max-height: 280px; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; padding: 8px; background: var(--vscode-textCodeBlock-background, var(--bg)); font: 11px/1.4 var(--vscode-editor-font-family, var(--font-mono)); }
    .error-text { color: var(--vscode-errorForeground, var(--fg)); }
    .empty-state { min-height: 180px; display: grid; place-content: center; justify-items: center; text-align: center; }
    .empty-mark { color: var(--vscode-descriptionForeground, var(--muted)); font: 300 28px/1 var(--vscode-editor-font-family, var(--font-mono)); }
    .empty-state h2 { margin: 10px 0 4px; font-size: 14px; }
    .empty-state button { margin-top: 10px; }
    .sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0; }
    @media (max-width: 520px) {
      .content { padding: 11px; }
      .workflow-summary { grid-template-columns: 1fr; }
      .workflow-summary .primary { width: 100%; }
      .metric-grid, .metric-grid-compact { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .finding-toolbar { grid-template-columns: 1fr; }
      dl { grid-template-columns: 1fr; gap: 2px; }
      dd + dt { margin-top: 6px; }
    }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after { scroll-behavior: auto !important; transition: none !important; }
    }
  `;
}

function checkRow(name: string, value: string, ready: boolean): string {
  return `<div class="check"><span class="check-icon ${
    ready ? "ok" : "pending"
  }" aria-hidden="true">${ready ? "✓" : "!"}</span><div><strong>${escapeHtml(
    name,
  )}</strong><span class="muted">${escapeHtml(value)}</span></div></div>`;
}

function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
