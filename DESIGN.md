# Kiro Security Power 설계 문서

## 1. 문서 목적

이 문서는 **Kiro Security Power**의 제품 목적, 시스템 경계, 핵심 아키텍처, 보안 분석 workflow, 상태 모델, Kiro Agent 통합 방식 및 구현 원칙을 정의한다.

Kiro Security Power의 목표는 단순한 보안 스캐너, MCP 서버 또는 Kiro Power를 만드는 것이 아니다. 제품 본체는 Kiro IDE에 설치되는 VSIX 확장이며, 사용자가 IDE 안에서 보안 스캔을 시작하고 진행 상황을 확인하고 finding을 검토하며 소스 코드와 연결된 remediation workflow를 수행할 수 있어야 한다.

Power와 MCP는 VSIX를 대체하지 않는다. 두 구성요소는 Kiro Agent가 동일한 보안 엔진과 SQLite workbench를 사용할 수 있도록 지원하는 보완 계층이다.

---

## 2. 제품 목적

Kiro Security Power는 다음 사용자 경험을 제공하는 것을 목적으로 한다.

1. 사용자가 Kiro에 VSIX를 설치한다.
2. 프로젝트 또는 Git 저장소를 연다.
3. Kiro Security 패널에서 deterministic Fast Scan을 시작하거나 Kiro Agent로 Standard, Deep 또는 Diff model scan을 시작한다.
4. 스캔 진행 상황과 phase를 실시간으로 확인한다.
5. 발견된 finding을 파일과 정확한 line에 연결해 검토한다.
6. Problems, Code Action, Status Bar 등 IDE 기본 기능에서 finding을 확인한다.
7. finding을 검증, triage, remediation 또는 accepted-risk 상태로 관리한다.
8. Markdown, JSON, CSV, SARIF 형식으로 결과를 내보낸다.
9. Kiro Agent에서도 동일한 scan과 finding을 조회하고 작업할 수 있다.
10. Kiro 재시작 또는 프로세스 중단 이후에도 scan을 복구하고 resume할 수 있다.

제품의 장기 목표는 Codex Security의 권한이 확보된 아키텍처, workflow, 상태 모델, schema 및 구현 개념을 Kiro 환경에 맞게 migration하는 것이다.

Kiro Security Power는 OpenAI 또는 Codex의 공식 제품이 아니다.

---

## 3. 설계 원칙

### 3.1 VSIX 중심 제품

VSIX가 다음 lifecycle과 사용자 경험을 소유한다.

* 설치 및 활성화
* Workspace Trust
* 보안 패널
* 명령 팔레트
* status bar
* output log
* Problems diagnostics
* source navigation
* engine 실행과 종료
* cancellation
* Agent integration setup
* recovery 및 resume
* export

MCP 서버만으로 제품을 구성하지 않는다.

### 3.2 단일 분석 엔진

VSIX, Kiro Power 및 MCP는 동일한 Python engine과 SQLite workbench를 사용한다.

```text
VSIX
  │
  ├── RPC
  │
Kiro Agent MCP
  │
  └── RPC
       │
       ▼
Python Security Engine
       │
       ▼
SQLite Workbench
```

MCP 전용 보안 분석 로직을 별도로 구현하지 않는다.

### 3.3 UI와 분석 로직 분리

Webview는 다음 항목에 직접 접근하지 않는다.

* 파일 시스템
* SQLite
* subprocess
* workspace secret
* Git executable
* MCP configuration

Webview는 typed message protocol을 통해 Extension Host와 통신한다.

Extension Host는 versioned RPC를 통해 Python engine과 통신한다.

### 3.4 Durable state

모든 scan 상태는 메모리만이 아니라 SQLite에 기록한다.

중단된 scan은 가능한 경우 다음 실행에서 복구할 수 있어야 한다.

* 현재 phase
* phase progress
* worker assignment
* completed receipt
* finding
* evidence
* validation record
* attack path
* export
* error
* handoff
* owner heartbeat

### 3.5 검증되지 않은 완료 금지

분석 가능한 파일이 없거나 coverage가 불완전한 경우 scan을 `complete`로 표시하지 않는다.

Model Scan은 worker가 실행되지 않았는데 Fast Scan 결과로 조용히 대체하지 않는다.

### 3.6 공개 API만 사용

Kiro 확장은 VS Code 호환 공개 API만 사용한다.

금지 항목:

* undocumented Kiro API
* private VS Code API
* 불필요한 proposed API
* Agent 전용 패널 내부 UI 강제 삽입
* 비공개 Power 설치 API
* 사용자 동의 없는 설정 변경

---

## 4. 제품 범위

### 4.1 지원 scan mode

#### Fast Scan

빠른 repository 또는 scoped-path 보안 검사다.

주요 목적:

* 일반적인 source-to-sink 취약점 탐지
* 위험한 API 사용 탐지
* 인증 및 권한 검사 누락 탐지
* 빠른 초기 triage
* IDE 내 반복 사용

#### Standard Scan

Kiro Agent의 단일 six-worker discovery round와 공통 model tail을 사용하는 repository 또는 scoped-path 검사다. Deep과 같은 attestation, semantic merge, validation, attack-path, writeup, hardening, strict finalization 계약을 사용하지만 첫 merge에서 saturated로 닫힌다.

#### Deep Scan

Kiro Agent의 모델 기반 독립 worker를 사용하는 반복적 보안 분석 workflow다.

주요 목적:

* 독립적인 여러 모델 검토
* variance 감소
* 전체 coverage ledger
* candidate별 evidence receipt
* semantic merge
* novelty 기반 convergence
* 중앙 validation과 attack-path 분석
* finding별 vulnerability writeup
* 전체 hardening portfolio

#### Diff Scan

Git 변경 범위를 대상으로 Kiro Agent가 수행하는 단일-round model 검사다. Immutable assignment에는 bounded hunk와 deleted path/line, rename hint, 그리고 security 의미가 확정되지 않은 same-directory supporting sibling path가 포함된다.

대상 예:

* working tree
* staged changes
* base/head revision
* branch diff
* 특정 commit range

---

## 5. 전체 아키텍처

```text
Kiro IDE
└── Kiro Security Power VSIX
    ├── TypeScript Extension Host
    │   ├── Activation lifecycle
    │   ├── Workspace Trust
    │   ├── Commands
    │   ├── Configuration
    │   ├── Status Bar
    │   ├── Output Channel
    │   ├── Diagnostics
    │   ├── Code Actions
    │   ├── Source Navigation
    │   ├── Agent Integration Installer
    │   └── Engine Process Manager
    │
    ├── Security Webview
    │   ├── Setup
    │   ├── Dashboard
    │   ├── Findings
    │   ├── Finding Detail
    │   ├── History
    │   └── Recovery
    │
    └── Versioned RPC Client
             │
             ▼
    Python Security Engine
    ├── Workspace Registration
    ├── Preflight
    ├── Inventory
    ├── Threat Modeling
    ├── Discovery
    ├── Deep Orchestration
    ├── Validation
    ├── Attack-Path Analysis
    ├── Triage
    ├── Remediation
    ├── Hardening
    ├── Vulnerability Writeup
    ├── Reporting
    ├── Export
    └── SQLite Workbench
             ▲
             │
    Kiro Power / MCP Adapter
```

---

## 6. 주요 구성요소

## 6.1 Extension Host

Extension Host는 Kiro와 engine 사이의 신뢰 경계다.

책임:

* extension activation 및 deactivation
* workspace 확인
* Workspace Trust 확인
* engine process 시작과 종료
* RPC request 및 event 처리
* Webview state 전달
* diagnostic 생성과 정리
* source URI 검증
* export 경로 검증
* status bar 갱신
* OutputChannel logging
* Kiro Agent integration 설치
* 설정 backup 및 rollback
* cancellation propagation

Extension Host는 Python 분석 로직을 직접 구현하지 않는다.

---

## 6.2 Security Webview

Webview는 사용자가 보안 scan과 finding을 관리하는 기본 UI다.

필수 화면:

### Setup

* workspace 정보
* repository 상태
* Workspace Trust
* Python 상태
* engine 상태
* SQLite 상태
* Power/MCP 연결 상태
* Install or Repair Agent Integration
* 설정 범위 선택
* 권한 정책 선택
* connection verification

### Dashboard

* scan mode
* scan scope
* Git base/head
* start
* resume
* cancel
* active phase
* progress
* elapsed time
* coverage
* recent scans

### Findings

* severity
* confidence
* validation status
* triage status
* category
* file
* line
* source
* sink
* scan ID
* 검색
* 정렬
* 필터

### Finding Detail

* summary
* evidence
* affected code
* source-to-sink path
* attack path
* exploitability
* impact
* severity rationale
* validation record
* remediation
* hardening alternatives
* related findings
* artifact links

### History 및 Recovery

* 과거 scan
* interrupted scan
* resume
* error
* artifacts
* logs
* cleanup

Webview는 Kiro/VS Code theme variable을 사용하며 light, dark, high-contrast 환경에서 동작해야 한다.

---

## 6.3 Python Security Engine

Python engine은 보안 workflow와 durable state를 관리한다.

책임:

* workspace 등록
* Git revision 확인
* repository inventory
* scan state machine
* scan lifecycle
* threat model
* finding discovery
* validation
* attack-path analysis
* triage
* remediation
* hardening
* reporting
* export
* deep worker assignment
* candidate merge
* recovery
* cancellation
* structured logging

Engine은 JSON-RPC 기반 stdio server로 동작한다.

---

## 6.4 SQLite Workbench

기본 위치:

```text
<workspace>/.kiro/security-power/workbench.sqlite
```

관련 runtime 디렉터리:

```text
<workspace>/.kiro/security-power/
├── workbench.sqlite
├── workbench.sqlite-wal
├── artifacts/
├── exports/
└── logs/
```

SQLite는 다음 데이터를 저장한다.

* schema version
* workspace
* scan
* scan phase
* progress
* worker assignment
* worker receipt
* round
* candidate
* canonical candidate
* finding
* evidence
* validation
* attack path
* triage
* remediation
* hardening
* writeup
* export
* tracking handoff
* engine session
* owner heartbeat
* errors

필수 SQLite 원칙:

* migration
* migration 전 backup
* parameterized query
* transaction
* foreign key
* WAL
* busy timeout
* interrupted scan recovery
* corruption reporting
* process-neutral ownership
* graceful shutdown

---

## 6.5 MCP Adapter

MCP Adapter는 Kiro Agent가 engine을 사용할 수 있게 한다.

주요 도구:

```text
security_get_capabilities
security_start_scan
security_list_scans
security_resume_scan
security_cancel_scan
security_get_scan
security_get_progress
security_list_findings
security_get_finding
security_validate_finding
security_triage_finding
security_create_remediation
security_prepare_remediation_patch
security_apply_remediation_patch
security_verify_remediation_patch
security_create_triage_intake
security_submit_triage_assessment
security_create_hardening_proposal
security_create_threat_model
security_create_tracking_handoff
security_record_tracking_result
security_export_report
```

Deep orchestration 도구:

```text
security_deep_get_status
security_deep_claim_worker
security_deep_submit_worker_result
security_deep_retry_worker
security_deep_claim_merge
security_deep_submit_merge
security_deep_get_tail_assignment
security_deep_submit_tail_result
security_deep_retry_writeup
```

MCP Adapter는 분석 로직을 중복 구현하지 않는다.

---

## 6.6 Kiro Power

Power는 Kiro Agent에 보안 workflow와 도구 사용 방식을 제공한다.

Power 구성:

```text
POWER.md
mcp.json
steering/
NOTICE.md
runtime/
```

Power의 역할:

* 보안 요청 인식
* 적합한 scan mode 선택
* Deep workflow orchestration
* MCP 도구 호출 순서 안내
* progress polling
* finding 검토
* validation
* triage
* remediation
* export

Power가 없는 경우에도 MCP 도구는 직접 사용할 수 있다. 다만 Power는 Agent가 올바른 workflow를 수행하도록 돕는다.

---

## 7. Scan 상태 모델

기본 scan 상태:

```text
created
queued
running
cancelling
cancelled
completed
failed
interrupted
```

Phase 상태:

```text
pending
active
completed
failed
cancelled
deferred
```

일반 phase 순서:

```text
preflight
→ inventory
→ threat_model
→ discovery
→ validation
→ attack_path
→ reporting
→ completed
```

Deep phase 순서:

```text
preflight
→ inventory
→ deep_discovery
→ deep_merge
→ threat_model
→ validation
→ attack_path
→ writeup
→ hardening
→ reporting
→ completed
```

허용되지 않는 전이는 engine에서 거부한다.

예:

```text
created → completed
discovery → reporting
failed → running
cancelled → completed
```

Resume은 새로운 scan을 생성하는 것이 아니라 기존 durable scan을 복구한다.

---

## 8. Fast Scan 설계

Fast Scan은 빠른 로컬 deterministic 분석을 목표로 한다. Engine wire에서는 `mode: standard`, `analysisProfile: fast`를 사용하지만 Standard model workflow와 동일한 보증으로 표현하지 않는다.

Workflow:

```text
Preflight
→ Git 및 workspace 확인
→ 파일 inventory
→ threat surface 요약
→ deterministic discovery
→ candidate normalization
→ local validation
→ attack-path 요약
→ finding 생성
→ report 및 exports
```

Fast Scan은 다음 경우에 적합하다.

* 개발 중 빠른 검사
* CI 이전 확인
* 명확한 위험 API 검사
* 변경 전 baseline
* model scan 이전 초기 triage

Fast 결과는 완전한 모델 기반 보안 감사로 표현하지 않는다. Standard와 Diff는 Kiro Agent가 `analysisProfile: model`로 시작하고, Deep과 같은 worker/merge/tail 계약을 한 discovery round에 재사용한다.

---

## 9. Deep Scan 설계

## 9.1 목적

Deep Scan의 핵심은 같은 규칙을 여러 번 실행하는 것이 아니다.

다음 특성을 보장해야 한다.

* 독립 모델 검토
* 반복 라운드
* 전체 scope coverage
* candidate별 증거
* 독립 worker 간 결과 은닉
* semantic merge
* novelty 수렴
* 중앙 validation
* finding별 writeup
* 전체 hardening 분석

---

## 9.2 Worklist 생성

Deep Scan 시작 시 repository inventory를 바탕으로 sealed worklist를 생성한다.

각 worklist row에는 다음이 포함된다.

```text
row ID
file path
file digest
language
runtime relevance
entrypoint classification
privilege classification
risk hints
scope disposition
```

Worklist는 round 도중 변경되지 않는다.

소스 파일 digest가 달라지면 기존 evidence는 stale로 처리한다.

---

## 9.3 Discovery Round

각 라운드는 정확히 6개의 독립 worker assignment로 구성한다.

```text
Round N
├── Worker 1
├── Worker 2
├── Worker 3
├── Worker 4
├── Worker 5
└── Worker 6
```

각 worker는:

* 같은 sealed worklist를 받는다.
* fresh context에서 실행된다.
* 다른 worker의 결과를 보지 않는다.
* 독립 threat model을 작성한다.
* 모든 worklist row에 receipt를 남긴다.
* 후보 finding과 evidence를 제출한다.
* 완료 후 결과를 수정할 수 없다.

Worker 제출 필수 항목:

```text
delegation ID
model identity
agent identity
reasoning configuration
fresh-context proof
worklist digest
row receipts
candidate list
source evidence
sink evidence
control evidence
coverage disposition
completion state
```

6개 assignment가 모두 claim되기 전에는 결과 제출을 허용하지 않는다.

---

## 9.4 Coverage Receipt

각 worklist row는 다음 중 하나로 닫혀야 한다.

```text
reportable
suppressed
not_applicable
deferred
```

Finding이 없는 경우에도 row receipt는 필수다.

`검토하지 않음`과 `문제가 없음`을 같은 상태로 취급하지 않는다.

분석 가능한 파일이 0개이면:

```text
coverage = unknown
scan = failed 또는 blocked
```

로 처리한다.

---

## 9.5 Candidate Evidence

Candidate는 최소한 다음 근거를 가져야 한다.

* root control 또는 source
* sink 또는 broken control
* affected file
* affected line
* plausible data or control path
* impact
* security boundary
* candidate-local validation evidence
* candidate-local attack-path facts

단순 문자열 일치만으로 최종 finding을 만들지 않는다.

---

## 9.6 Semantic Merge

6개 worker가 완료되면 merge assignment를 생성한다.

Merge는:

* 모든 worker source reference를 정확히 한 번 처리한다.
* 같은 취약점을 canonical candidate로 병합한다.
* 독립적으로 도달 가능한 sibling instance는 분리한다.
* 이전 round canonical candidate를 보존한다.
* evidence와 location을 손실하지 않는다.
* candidate identity를 안정적으로 유지한다.
* 새 candidate 수를 계산한다.

Merge 결과:

```text
canonical candidates
source membership
new candidate count
preserved candidate count
suppressed candidate count
merge rationale
```

---

## 9.7 Novelty와 종료 조건

라운드가 끝났을 때 신규 canonical candidate가 하나라도 있으면 다음 라운드를 생성한다.

```text
newCandidates > 0
→ next round
```

완전한 6-worker 라운드에서 신규 candidate가 0개일 때만 discovery가 수렴한다.

```text
newCandidates == 0
→ saturated
```

최대 라운드:

```text
10
```

10라운드 도달 시:

```text
status = capped
```

으로 기록하며 saturation으로 가장하지 않는다.

---

## 9.8 Tail Phase

Discovery 수렴 후 다음 중앙 phase를 수행한다.

```text
canonical threat model
→ validation
→ attack-path analysis
→ finding별 vulnerability writeup
→ hardening portfolio
→ final reporting
```

각 phase는 별도 assignment와 durable receipt를 가진다.

---

## 9.9 Finding별 Writeup

Reportable finding마다 전용 writeup assignment를 생성한다.

한 writeup worker는 하나의 finding만 처리한다.

입력:

* candidate
* validation evidence
* attack-path evidence
* affected source
* revision
* PoC input
* output path

출력:

```text
findings/<kspf-id>/<kspf-id>.md
findings/<kspf-id>/poc/
```

현재 safe slug는 stable `kspf_` finding ID에서 engine이 파생하며 모델이 임의 경로나 slug를 지정하지 않는다.

서로 다른 finding에 동일한 delegation ID를 재사용하지 않는다.

---

## 9.10 Hardening Portfolio

모든 reportable finding의 writeup이 완료된 뒤 전체 hardening 분석을 수행한다.

출력:

```text
hardening/hardening.md
hardening/hardening.json
```

JSON이 normalized source이고 Markdown은 deterministic projection이다. Diagram source가 제출되면 bounded structured field로 보존되며 별도 디렉터리 suite를 필수 산출물로 주장하지 않는다.

Hardening은 개별 patch만 나열하지 않고 다음을 다룬다.

* 공통 root cause
* reusable control
* architectural remediation
* prevention strategy
* detection strategy
* rollout risk
* validation plan

---

## 10. Finding 모델

Finding 핵심 필드:

```text
finding ID
scan ID
title
summary
category
severity
confidence
status
validation status
triage status
file URI
start line
end line
source
sink
data flow
attack path
evidence
exploitability
impact
severity rationale
remediation
hardening alternatives
related findings
artifact paths
created time
updated time
```

Finding ID는 안정적으로 유지되어야 한다.

Diagnostic code, stable link, export 및 tracking handoff에서 같은 ID를 사용한다.

---

## 11. Validation 모델

Validation은 candidate가 실제 취약점인지 판단한다.

검토 항목:

* 입력이 공격자 제어 가능한가
* 해당 코드 경로가 도달 가능한가
* sanitizer 또는 guard가 존재하는가
* guard가 sink 이전에 적용되는가
* framework 또는 middleware가 보호하는가
* 권한 경계가 존재하는가
* 영향이 현실적인가
* false positive 근거가 있는가
* 추가 evidence가 필요한가

Validation 상태:

```text
unvalidated
needs_review
validated
suppressed
false_positive
deferred
```

---

## 12. Attack-Path 모델

Attack path는 단순한 source와 sink 목록이 아니다.

가능한 경우 다음 노드를 포함한다.

```text
external actor
→ entrypoint
→ parser
→ transformation
→ authorization decision
→ trust-boundary crossing
→ root control
→ vulnerable operation
→ sink
→ impact
```

각 edge에는 evidence를 연결한다.

```text
file
line
symbol
call relationship
data relationship
control relationship
assumption
confidence
```

---

## 13. IDE 네이티브 통합

Validated finding은 `DiagnosticCollection`으로 Problems에 표시한다.

Severity mapping 예:

```text
critical/high → DiagnosticSeverity.Error
medium        → DiagnosticSeverity.Warning
low           → DiagnosticSeverity.Information
info          → DiagnosticSeverity.Hint
```

Diagnostic code에는 finding ID를 사용한다.

지원 기능:

* finding 상세보기
* affected source 열기
* 정확한 range 이동
* remediation workflow 진입
* stale diagnostic 제거
* workspace 변경 시 refresh
* scan 변경 시 refresh
* status bar finding count
* scan phase 표시

---

## 14. Agent Integration Setup

VSIX 설치만으로 Kiro Agent 설정을 임의 변경하지 않는다.

Setup의 `Install or Repair Agent Integration`을 통해 사용자의 명시적 승인을 받는다.

Workflow:

```text
환경 검사
→ 적용 예정 변경 표시
→ 사용자 승인
→ 기존 설정 backup
→ runtime 설치
→ MCP 설정 병합
→ steering 설치
→ MCP process 시작
→ protocol 협상
→ tools/list
→ capabilities 확인
→ SQLite 초기화 확인
→ Verified
```

실패 시:

```text
설정 rollback
runtime rollback
steering rollback
오류 표시
```

설정 범위:

```text
Workspace
User
```

기본 권장값은 Workspace다.

기존 MCP 서버, JSONC 주석 및 trailing comma를 보존해야 한다.

---

## 15. 보안 모델

## 15.1 Trust Boundary

```text
User
│
Kiro UI
│
Webview
│
Extension Host
│
Python Engine
│
Workspace Files / Git / SQLite
│
MCP Client / Kiro Agent
```

주요 경계:

* Webview ↔ Extension Host
* Extension Host ↔ Engine
* Engine ↔ Workspace
* MCP Client ↔ Engine
* Engine ↔ SQLite
* Export destination ↔ Workspace boundary

---

## 15.2 필수 보안 통제

### Workspace Trust

Untrusted workspace에서 자동 scan을 실행하지 않는다.

### Subprocess

Shell 문자열을 사용하지 않는다.

```text
executable + argument array
```

형태로 실행한다.

### Path Validation

* path traversal 거부
* workspace boundary 확인
* symlink resolution
* export destination 확인
* extension installation path 검증

### Webview CSP

* nonce 기반 script
* 외부 CDN 금지
* 최소 localResourceRoots
* inline script 금지
* typed message validation

### Secret Handling

* SecretStorage 사용
* log secret redaction
* credential을 workspace 파일에 평문 저장하지 않음

### SQLite

* parameterized query
* transaction
* migration backup
* corruption reporting
* lock strategy
* owner heartbeat

### Agent Integration

* 설정 변경 전 승인
* 변경 preview
* 기존 설정 보존
* backup
* rollback
* managed entry만 제거
* 임의 command injection 방지

---

## 16. Protocol 설계

프로토콜은 versioning과 schema validation을 사용한다.

예:

```text
Protocol: kiro-security-rpc
Version: 1.x
Transport: JSON-RPC 2.0 over stdio
```

기본 RPC:

```text
initialize
get_capabilities
register_workspace
start_scan
resume_scan
cancel_scan
get_scan
list_scans
get_progress
list_findings
get_finding
validate_finding
triage_finding
create_remediation
create_hardening_proposal
export_report
shutdown
```

Event:

```text
engine.ready
scan.started
scan.phaseChanged
scan.progress
finding.discovered
finding.updated
artifact.created
scan.completed
scan.cancelled
scan.failed
engine.log
```

Version mismatch는 명시적으로 거부한다.

---

## 17. Artifact 및 Export

Scan artifact:

```text
scan-manifest.json
coverage.json
findings.json
report.md
threat-model.md
discovery.json
validation.json
attack-path.json
```

Finding artifact:

```text
findings/<slug>/<slug>.md
findings/<slug>/poc/
```

Hardening artifact:

```text
hardening/hardening.md
hardening/hardening.json
```

사용자 export:

```text
Markdown
JSON
CSV
SARIF
```

Artifact에는 digest와 provenance를 기록한다.

---

## 18. 복구 및 Resume

Engine session은 heartbeat를 기록한다.

Engine 또는 Kiro가 비정상 종료된 경우:

1. stale owner 확인
2. active scan을 interrupted로 변경
3. completed receipt 유지
4. 미완료 assignment claim 해제
5. immutable worker result 유지
6. 마지막 durable phase에서 resume
7. source digest 재확인
8. stale evidence 무효화

Extension 종료가 scan DB를 손상시키지 않도록 graceful shutdown과 handoff를 사용한다.

---

## 19. 로깅

OutputChannel에는 구조화 로그를 기록한다.

예:

```json
{
  "timestamp": "2026-07-14T04:58:01Z",
  "level": "info",
  "message": "scan.phaseChanged",
  "scanId": "scan-123",
  "phase": "validation"
}
```

로그에서 제거할 정보:

* API key
* credential
* authorization token
* private connector data
* secret environment variable

Telemetry는 기본 비활성화한다.

---

## 20. 테스트 전략

### Unit

* state machine
* phase transition
* mode handling
* schema validation
* finding normalization
* severity mapping
* SQLite migration
* resume
* recovery
* exports
* RPC serialization
* Webview state
* command routing

### Contract

* TypeScript/Python protocol 일치
* malformed message 거부
* version mismatch
* cancellation
* progress
* structured error
* Deep worker receipt
* merge invariant
* novelty convergence

### Integration

* command → engine → SQLite → finding → Webview
* Fast Scan
* Standard Scan
* Deep Scan
* Diff Scan
* cancellation
* restart
* resume
* diagnostics
* source navigation
* export
* MCP/VSIX state 공유

### Deep-specific

* 정확히 6개 worker
* 전체 claim barrier
* fresh context
* 중복 delegation ID 거부
* model drift 거부
* incomplete round merge 거부
* 모든 sourceRef 처리
* sibling finding 보존
* novelty 발생 시 next round
* zero novelty saturation
* 최대 10라운드 capped
* incomplete coverage 완료 금지
* stale source evidence 무효화
* finding별 전용 writeup

---

## 21. 패키징

산출물:

```text
dist/kiro-security-power-<version>.vsix
dist/SHA256SUMS
```

패키지 제외 항목:

```text
원본 참조 ZIP
압축 해제된 전체 참조 구현
node_modules
fixture repository
temporary SQLite DB
cache
Python bytecode
secret
불필요한 source map
Git metadata
```

VSIX에는 runtime에 필요한 승인된 구성요소만 포함한다.

---

## 22. Provenance

Kiro Security Power는 권한이 확보된 Codex Security 참조 구현으로부터 다음 요소를 migration해 개발됐다.

* 보안 workflow
* scan phase
* 상태 모델
* workbench 개념
* schema
* artifact 모델
* recovery 개념
* Deep Scan orchestration 개념
* candidate receipt
* coverage ledger
* validation
* attack-path analysis
* vulnerability writeup
* hardening portfolio

다음 내용을 provenance 문서에 유지한다.

> Kiro Security Power was developed by migrating authorized architecture, workflows, schemas, and implementation concepts from Codex Security.

> Kiro Security Power is not an official OpenAI or Codex product.

참조 구현의 proprietary license 또는 provenance를 임의로 변경하지 않는다.

---

## 23. 현재 구현 상태

현재 0.3.0 소스에는 다음 구조가 반영돼 있다.

* VSIX Extension Host
* Security Webview
* Python engine
* SQLite workbench
* Standard 및 Diff lifecycle
* Deep durable orchestration
* 6-worker discovery round
* semantic merge
* novelty convergence
* tail phase assignment
* finding별 writeup assignment
* MCP tools
* Agent Integration Setup
* Python 3.9 호환 수정
* report/export/diagnostics
* source navigation

현재 0.3.0 변경은 worktree에서 검증 중이며, 전체 suite와 실제 Kiro Desktop/VSIX 검증 전에는 패키징 완료로 간주하지 않는다.

따라서 다음 사항은 별도 검증 대상이다.

* 실제 Kiro delegated subagent 실행
* 6-worker complete round
* multi-round convergence
* 실제 repository에서 semantic merge 품질
* validation과 attack-path 모델 품질
* Kiro restart 후 Deep resume
* 실제 Agent와 VSIX 간 동시 사용
* package 내부 최신 Extension Host와 Deep protocol 일치
* 전체 regression test
* Kiro desktop UI smoke test

0.3.0 구현은 Fast/model profile 분리, Deep 및 공통 model tail, repository context, strict canonical finalization을 포함한다. 저장 regression과 로컬 smoke는 구현 계약을 검증하지만, 실제 Kiro delegated multi-round 실행과 UI 상호작용이 검증됐다고 주장하지 않는다.

---

## 24. 성공 기준

제품은 다음 조건을 만족할 때 완료된 것으로 본다.

* 실제 설치 가능한 VSIX
* Activity Bar와 Security Webview
* 실제 engine과 SQLite 연결
* Fast, Standard, Deep, Diff lifecycle
* progress, cancellation, recovery, resume
* finding source navigation
* Problems diagnostics
* JSON, CSV, SARIF, Markdown export
* 동일 engine을 사용하는 MCP와 Power
* Agent integration 설치와 검증
* Deep 6-worker orchestration
* complete coverage receipt
* semantic merge
* novelty convergence
* finding별 writeup
* hardening portfolio
* 테스트 및 package verification
* Kiro desktop smoke-test handoff
* provenance 및 license 문서

다음 상태는 실패다.

* MCP만 구현
* Power만 구현
* CLI만 구현
* fixture 기반 production UI
* scan 버튼과 engine이 연결되지 않음
* 모델 worker 없이 Deep 완료
* Fast 결과를 Standard, Diff 또는 Deep으로 표시
* 분석 파일 0개인데 coverage complete 표시
* 결과가 IDE에 나타나지 않음
* VSIX 미생성
* 테스트 실패 은폐
* Kiro를 실행하지 않고 desktop 검증 완료 주장
* 참조 원본 전체 복제
* license 임의 변경

---

## 25. 최종 방향

Kiro Security Power의 핵심 가치는 단순한 취약점 탐지 규칙이 아니다.

제품의 핵심은 다음 네 가지다.

```text
IDE-native security workflow
+ durable security workbench
+ model-assisted deep analysis
+ Agent와 VSIX의 단일 상태 공유
```

Fast Scan은 빠른 deterministic 로컬 피드백을 제공한다.

Standard와 Diff Scan은 Kiro Agent의 단일 six-worker round와 공통 model tail을 사용한다.

Deep Scan은 독립 모델 worker와 coverage 증명을 통해 더 높은 검토 폭과 신뢰도를 목표로 한다.

VSIX는 사용자가 모든 scan과 finding을 직접 통제할 수 있는 제품 본체다.

Kiro Power와 MCP는 Kiro Agent가 같은 engine과 동일한 보안 상태를 사용할 수 있게 하는 통합 계층이다.
