# Codex Security 0.1.11 기반 재구축 작업계획

## 목적

Kiro Security Power를 로컬에 설치된 Codex Security Plugin 0.1.11의 실행 계약, 스키마와 스킬을 기준으로 첫 릴리스 수준에서 다시 구축한다.

기존 구현은 호환 대상이나 설계 기준으로 보존하지 않는다. 필요한 기능도 기존 코드를 유지하는 방식이 아니라 목표 아키텍처에서 다시 정의하고 구현한다.

## 기준

- 아키텍처 사실의 기준: 설치된 `codex-security@0.1.11`의 실행 계약과 스키마 → 스킬 문서 → OpenAI 공개 문서
- `docs/codex-security-plugin-0.1.11-architecture.md`는 위 원본을 찾고 해석하기 위한 버전 고정형 참고 자료다.
- Kiro 제품 적응의 기준: Kiro Power, Agent chat, VSIX, workspace-local shared workbench
- 구현 판단의 기준: 20개 아키텍처 주제
- 과거 Kiro migration, parity 보고서와 기존 내부 계약은 새 구현의 요구사항이 아니다. Fresh schema에는 이후 릴리스를 위한 forward migration 기반만 둔다.
- 별도의 전수 계약 매트릭스는 만들지 않는다.
- 압축된 Codex MCP/App 구현을 복원·복사하지 않으며 `LICENSE-NOTICE.md`의 provenance와 배포 전 법적 검토 경계를 지킨다.

## 작업 범위

1. 전환 기준을 확정한 뒤 기존 Engine, DB, MCP, Extension/Webview, Power, protocol, test와 packaging 구현을 제거하고 새 구조로 교체한다.
2. Codex Security의 authority, workspace, scan lifecycle, target snapshot, artifact와 finalization 구조를 새 기반으로 설계한다.
3. Codex의 App-backed 책임은 Kiro의 Agent chat과 VSIX transport에 명시적으로 대응시키고, 지원하지 않는 App continuation 계약은 adaptation으로 분리한다.
4. Standard, Diff와 Deep은 top-level scan workflow로 작성하고 phase skill의 독립 호출 계약을 유지한다.
5. Local triage/remediation DB lifecycle은 독립 Agent workflow인 `triage-finding`, `fix-finding`, `track-findings`와 구분하되 exact workbench identity로 연결한다. `vulnerability-writeup`과 `propose-security-hardening`은 자동 final-report 역할과 standalone 실행을 모두 지원한다.
6. fresh schema, 통합 테스트와 VSIX packaging을 첫 릴리스 기준으로 검증한다.

## 구현 순서

### 0. 전환 기준 확정

- Kiro는 VSIX-backed shared workbench 경로만 제품 topology로 지원한다. Codex의 prompt-only terminal/chat 경로는 의도적인 Kiro adaptation으로 제외한다.
- Scan 시작은 Kiro Agent chat과 Power만 소유한다. 시작 호출은 같은 Agent task에 `scanId`를 반환하고, Agent는 별도 context 조회로 authoritative snapshot을 즉시 읽는다. VSIX에는 Start 동작을 두지 않는다.
- Codex App의 start waiter, initial handoff delivery와 host `sendMessage` continuation은 Kiro에서 사용하지 않는다. Process/task loss 뒤에는 durable scan을 사용자가 Agent chat에서 명시적으로 재개한다.
- Kiro 직접-resume에서는 VSIX가 exact scan/request identity를 가진 durable recovery/remediation request와 재개 정보를 저장한다. 새 Agent chat은 먼저 MCP claim을 호출해 identity와 적용되는 CAS를 검증하고 token을 받은 뒤, 두 번째 context 조회에 그 token을 제시해 delivered 전환과 authoritative context 반환을 수행한다. Delivery 전 scan recovery/remediation claim은 120초 뒤에만 takeover할 수 있고, delivered remediation worker는 900초 뒤에만 takeover할 수 있다. 실패·취소는 단계에 따라 claim을 release하거나 action을 cancel한다.
- Deep은 라운드마다 동일 canonical brief를 받은 정확히 여섯 개의 독립 discovery worker를 사용하고 최대 10라운드를 실행한다. 신규 canonical merged candidate가 없는 첫 완전한 라운드에서 종료하며, 정해진 복구 후에도 여섯 개의 usable output을 확보하지 못하면 크기를 줄이지 않고 미완료 상태를 보존한다.
- Scan mutation에는 coordinator lease를 추가하지 않는다.
- DB 상태는 `running`, `complete`, `failed`이고 취소는 `failed + canceled_at` projection으로 표현한다.

### 1. 기반

- plugin/Power entry point
- logical workspace와 task identity
- fresh SQLite schema와 current-result pointer
- target/snapshot identity
- scan start transaction과 lifecycle

### 2. 실행 경계

- Agent chat 전용 scan start
- shared MCP transport
- `scanId` 반환과 authoritative context 조회를 잇는 Agent task 직접 continuation
- durable scan의 명시적 Agent chat recovery
- direct-resume request claim/delivery/release와 stale takeover
- progress와 `failed + canceled_at` cancellation
- Extension의 DB-backed lifecycle/result projection과 triage/export UI
- Extension의 remediation/recovery UI는 durable request와 재개 정보를 관리하고, 의미론적 실행은 Agent chat이 수행한다.
- Extension은 scan 시작과 의미론적 실행을 소유하지 않는다.

### 3. Scan workflow

- capability preflight와 goal
- Standard scan
- Diff scan
- Deep scan
- phase별 semantic contract와 coverage closure
- `threat-model`, `finding-discovery`, `validation`, `attack-path-analysis`의 독립 호출

### 4. 결과

- canonical manifest, findings와 coverage
- deterministic finalizer와 seal
- Completion에 필수인 canonical scan 결과 기반 `report.md` deterministic projection
- Completion에서는 best-effort이고 명시적 export에서는 strict failure를 반환하는 SARIF projection
- SQLite finding index와 현재 local triage state 기반 CSV projection
- 자동 final reporting의 Agent-authored derived writeup/hardening과 reference validation
- Scan 없이 실행할 수 있는 독립 `vulnerability-writeup`과 `propose-security-hardening` workflow
- finding identity와 SQLite index

### 5. 후속 lifecycle

- Extension/DB가 소유하는 local finding triage open/close state
- DB가 소유하는 remediation request/attempt, action token, CAS와 lease state
- 제공·import된 finding을 평가하는 독립 `triage-finding` Agent workflow
- Standalone에서는 `fixed`, `no_change`, `blocked` outcome을 사용하는 `fix-finding` Agent workflow
- Workbench에서는 exact scan/occurrence/request identity, action token과 expected version으로 연결되어 generate/apply/verify 한 단계만 수행하는 `fix-finding`
- 독립 trigger, preview/approval/readback을 가진 `track-findings` Agent workflow
- filesystem, identity와 connector 보안 경계
- concurrency, failure와 recovery

## 완료 조건

- 20개 아키텍처 주제가 새 구현과 테스트에 모두 대응한다.
- 기존 Kiro 구현 전용 compatibility와 pre-release DB backfill path가 남아 있지 않고 forward migration 기반은 검증된다.
- workspace setup과 scan snapshot의 authority가 분리되어 있다.
- `active_scan_id`가 current result pointer로 동작하고 terminal transition에서 유지된다.
- Scan progress/complete/fail은 `scanId`와 transaction guard를 사용하고 별도 coordinator lease를 요구하지 않는다. Remediation 등 action별 mutation만 대응 계약의 action token, expected version과 CAS guard를 사용한다.
- 취소는 `failed + canceled_at`으로 저장되고 UI에서 canceled로 projection된다.
- Deep의 각 완전한 라운드는 정확히 6개의 usable worker output을 가지며 saturation 또는 10라운드 cap 전에는 centralized tail로 넘어가지 않는다.
- Extension 재시작이나 다른 MCP process가 실행 중인 scan을 방해하지 않는다.
- Process/task가 종료돼도 running scan이 보존되고 새 Agent chat에서 명시적으로 재개할 수 있다.
- Direct-resume의 claim/token 발급과 token 기반 context-delivery가 분리되고, release/cancel 및 120초·900초 stale takeover 경계가 검증된다.
- Dashboard는 SQLite의 선택된 logical workspace와 pointer를 매번 다시 읽는다.
- Standard, Diff와 Deep의 의미론은 Power/Agent가 소유하고 Engine은 분석하지 않는다.
- 네 phase skill과 writeup/hardening workflow의 독립 호출 및 scan-orchestrated 호출이 모두 검증된다.
- Deterministic projection과 Agent-authored derived writeup/hardening의 생성·검증 책임이 분리되어 있다.
- `report.md`는 completion 필수이고 SARIF는 completion best-effort·명시적 export strict 계약을 따른다.
- CSV는 canonical scan 결과를 변경하지 않고 현재 SQLite triage state를 반영한다.
- Local triage/remediation DB lifecycle과 독립 Agent workflow의 authority가 분리되어 있다.
- `fix-finding`의 standalone outcome과 workbench stage가 혼합되지 않고 exact identity로 연결된다.
- canonical artifact finalization과 DB completion이 검증된 순서로 동작한다.
- lint, unit, integration, direct-port helper parity, package와 clean-install smoke test가 통과한다.
- 부합 판정은 20개 주제의 원본 계약과 구현 테스트를 함께 대조한다. 명시한 Kiro adaptation은 parity 주장과 분리하며 direct-port 결과만으로 부합을 판정하지 않는다.

## 작업 원칙

- 구현 중 발견한 기존 동작을 자동으로 새 요구사항으로 승격하지 않는다.
- Kiro 적응이 필요한 차이는 문서와 테스트에 명시한다.
- 각 단계는 실행 가능한 상태와 검증을 갖춘 뒤 다음 단계로 넘어간다.
- 첫 릴리스 전이므로 불필요한 backward compatibility는 추가하지 않는다.
