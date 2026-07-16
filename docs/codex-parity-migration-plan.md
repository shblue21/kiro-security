# Codex Security → Kiro Security Power 완전 이관 작업 리스트

## 0. 이 문서의 목적

이 문서는 Kiro Security Power를 **Codex Security 0.1.11의 보안 분석 경험과 동등한 수준**으로 끌어올리기 위한 전체 작업 리스트다.

현재 0.3.0은 Kiro-native IDE 껍데기(VSIX·Webview·SQLite workbench·MCP 통합)는 실제 제품 수준이지만, Codex Security의 핵심인 **모델 기반 exhaustive 분석·coverage 증명·validation·attack-path·writeup·hardening·finalization**은 대부분 축약·템플릿화되어 있다. 이 문서는 그 간극을 닫는다.

관련 근거 문서:
- `DESIGN.md` — 목표 설계 (일부 항목은 아직 미구현)
- 직전 gap 분석 (Codex 0.1.11 대조) — P0/P1/P2 우선순위의 근거
- `docs/migration-matrix.md`, `docs/migration-inventory.md` — 갱신 대상

> 원칙: "이관 완료"는 실제 Kiro desktop에서 delegated agent가 6-worker Deep을 완주하고, coverage/validation/attack-path/finalization이 참조 contract를 통과할 때만 주장한다. 문서상 설계 존재는 완료 근거가 아니다.

---

## 1. 완료 정의 (Definition of Done)

이관이 완료되었다고 말하려면 아래 4개 핵심 간극이 모두 참조 수준으로 닫혀야 한다.

1. **Exhaustive coverage proof** — "검토 안 함"과 "문제 없음"을 row 단위 receipt로 엄격히 구분
2. **Model-based validation** — 정적 키워드 재검사가 아닌 모델/동적 증명 기반 검증
3. **Real attack-path & severity judgment** — 템플릿이 아닌 실제 actor→entry→control→sink→impact 분석과 severity 재산정
4. **Strict canonical finalization** — manifest/findings/coverage를 strict schema로 검증 후 seal, report는 projection

부수적으로 IDE 경험(현재 강점)은 회귀 없이 유지한다.

---

## 2. 워크스트림 개요

| ID | 워크스트림 | 우선순위 | 핵심 산출물 |
|----|-----------|:-------:|------------|
| WS-A | Coverage & Finalization correctness | **P0** | row-level coverage ledger, strict finalizer, seal |
| WS-B | Deep orchestration 신뢰성 | **P0/P1** | claim barrier, identity 강제, host capability preflight, worker artifact suite |
| WS-C | Model-based 분석 tail | **P1** | validation/attack-path/writeup/hardening을 실제 모델 assignment로 |
| WS-D | Threat model 실질화 | **P1** | repository-specific, worker model 합성 |
| WS-E | Standard/Diff 재정의 | **P1** | Fast Scan 분리 + 모델 workflow 신설 |
| WS-F | Finding identity 안정화 | **P1** | semantic fingerprint |
| WS-G | Scope & 보안 표면 확장 | **P1** | 비소스 보안 표면(IaC, config, deps) |
| WS-H | 후반 workflow (fix/triage/tracking) | **P2** | 실제 patch, proof-chain triage, connector |
| WS-I | Schema/Contract wire 호환 | **P1** | strict JSON schema 확장 |
| WS-J | 테스트 & release assurance | **전구간** | Deep 전용 테스트, Kiro desktop 실행 검증 |
| WS-K | 문서 정합성 | **P2** | DESIGN/README/matrix 실제 구현과 동기화 |

---

## 3. P0 — 정확성 및 false assurance 제거

가장 먼저 닫아야 하는, 사용자에게 잘못된 보안 확신을 줄 수 있는 결함들.

### WS-A. Coverage & Finalization correctness

- [ ] **A1. Row-level coverage ledger 도입**
  - 대상: `engine/kiro_security/deep.py`, `engine/kiro_security/reporting.py`, `engine/migrations/*.sql`
  - 현재 `reviewedPaths`(단순 경로 집합, "attendance list")를 폐기하고, worklist row마다 다음을 저장:
    `rowId, surface, entrypoint, rootControl, sink, disposition, reason, evidenceRefs, workerId, candidateIds, receiptDigest`
  - disposition은 `reportable | suppressed | not_applicable | deferred` 중 하나로 강제
  - 수용 기준: 각 disposition에 근거(reason)와 receipt가 없으면 worker 제출 거부
- [ ] **A2. `complete`는 모든 row가 닫힌 경우에만 허용**
  - 대상: `reporting.py:build_coverage_document`
  - 현재 `"partial" if deferred else "complete"` 로직 제거
  - 미검토/미지원 in-scope row가 하나라도 있으면 `complete` 금지
- [ ] **A3. Deep cap을 coverage에 반영**
  - `capped → completeness=partial (capped)`
  - `unsupported in-scope files → deferred 또는 explicit exclusion`
  - `0 supported files → unknown/blocked` (Standard/Diff도 Deep과 동일하게)
  - 대상: `reporting.py` (Deep state 조회 추가), `deep.py`
- [ ] **A4. `receiptRefs`를 실제 receipt로 교체**
  - finding occurrence ID가 아니라 ledger/artifact receipt digest를 참조
- [ ] **A5. Strict canonical finalizer 구현**
  - 대상: 신규 `engine/kiro_security/finalizer.py`(제안)
  - `scan-manifest.json / findings.json / coverage.json`을 strict schema로 검증 후 **seal(digest 고정)**
  - `report.md`, SARIF, CSV는 canonical JSON에서 **deterministic projection**으로만 생성
  - producer(reporting)가 report를 직접 쓰지 않도록 분리
  - seal 대상에 report/hardening 포함 금지
- [ ] **A6. manifest 상태 정합성 수정**
  - 현재 scan DB가 completed 되기 전 manifest에 `status: completed`가 박히는 문제 제거
  - finalizer가 실제 완료 시점에 상태를 기록

**WS-A 완료 검증:** 0-file, capped, deferred, all-clean 4가지 시나리오에서 coverage.completeness가 각각 정확히 나오는 테스트 통과.

---

### WS-B (P0 부분). Deep 동시성 barrier

- [ ] **B1. All-six claim barrier**
  - 대상: `deep.py:submit_worker`
  - 첫 worker result 제출 전에 6개 worker가 모두 claim 상태여야 함
  - 수용 기준: 5개만 claim된 상태에서 submit 시 `deep_round_not_fully_claimed` 오류
- [ ] **B2. Merge 전 6-worker idle proof**
  - 6개 worker가 모두 `completed` 이고 재클레임 불가 상태임을 merge claim 시 재확인 (현재 부분 존재 → 강화)

---

## 4. P1 — Deep orchestration 신뢰성

### WS-B (P1 부분). Worker 독립성/동질성 강제

- [ ] **B3. Host capability preflight**
  - 대상: `engine/kiro_security/mcp_server.py`, Power steering, `runner.py:_phase_preflight`
  - Deep 시작 전 실제 확인: `delegated agent available, fresh-context mode, 6 usable slots, model identity, reasoning identity, agent depth, goal support`
  - capability 미충족 시 Deep을 `blocked`로 (조용히 대기 금지)
- [ ] **B4. Round profile 고정 + 동질성 검증**
  - 첫 worker claim 시 round profile 확정: `modelId, agentType, reasoningEffort, hostVersion, delegationMode`
  - 이후 worker가 프로파일과 불일치하면 claim 거부 (model drift rejection)
  - 대상: `deep.py:claim_worker` (현재 bounded string 검사만 있음)
- [ ] **B5. Fresh-context / idle proof 요구**
  - worker 제출 시 coordinator history 미상속 증명 및 완료 후 idle 상태 근거 요구
- [ ] **B6. Worklist 밀도 강화**
  - 대상: `deep.py:ensure`, `_write_shared_worklists`
  - 현재 `rowId, path, language, size` 4필드 → 참조 수준으로 확장:
    `runtime relevance, product area, deployment significance, entrypoint, privileged boundary, root control, seed/advisory anchor, high-impact family, work shard, ranking reason, deferred/excluded reason`
- [ ] **B7. Worker artifact suite 구현**
  - 각 worker output에 실제 artifact 부여:
    `threat_model.md, finding_discovery_report.md, seed_research.md, work_ledger.jsonl, raw_candidates.jsonl, dedupe_report.md, deduped_candidates.jsonl, repository_coverage_ledger.md, candidate-ledger/<candidate>.jsonl`
- [ ] **B8. Candidate evidence 요건 강화**
  - 대상: `deep.py:_normalize_candidate`
  - 필수화: `attacker-controlled source, root control, sink/broken control, source-to-sink path, authorization boundary, entrypoint, concrete impact, counterevidence, candidate-local validation/attack-path proof`
  - **engine auto-snippet fallback 제거** (`if not evidence:` 블록) — 모델이 근거를 안 내면 거부
- [ ] **B9. Semantic merge 검증 강화**
  - 현재 sourceRef 소비/ID 보존/novelty 계산은 유지하되, contract 플래그(`mergeContract`)를 실제 검증 로직으로:
    - 하나의 remediation이 upstream candidate 전부를 닫는지
    - sibling instance 독립 reachability
    - 동일 취약점 ID 재사용/재등록으로 novelty 은닉·부풀림 방지
- [ ] **B10. Deep provenance 보존**
  - canonical candidate ID, absorbed sourceRef, worker/round/model 정보를 최종 finding까지 전파 (현재 소실됨)

---

### WS-C. Model-based 분석 tail

현재 validation/attack-path/writeup/hardening/reporting은 모두 Python engine의 deterministic 로직이다. 이를 실제 모델 assignment로 전환.

- [ ] **C1. Tail assignment MCP 도구 신설** (DESIGN.md에 있으나 코드에 없음)
  - `security_deep_get_tail_assignment`, `security_deep_submit_tail_result`, `security_deep_retry_writeup` 등
  - 각각 durable claim/result/receipt
  - 대상: `mcp_server.py`, `deep.py`, migration
- [ ] **C2. Canonical threat-model synthesis**
  - worker별 threat model을 합성해 canonical validation threat model 생성 (discovery **이후**)
- [ ] **C3. Candidate validation을 모델/동적 proof로**
  - 대상: `engine/kiro_security/validator.py` (현재 sink 주변 ~24줄 regex 재검사)
  - repository-native test, focused PoC, cross-file trace, framework middleware 인식, counterevidence, proof gap
  - 동적 불가 시에만 정적 fallback
- [ ] **C4. Attack-path & severity policy**
  - 대상: `engine/kiro_security/attack_path.py` (현재 고정 transform 템플릿)
  - 실제 actor/entry/control/sink/impact 사실 연결 + severity 재산정(policy matrix)
  - `exploitability = "high" if validated else "medium"` 같은 단순 규칙 제거
- [ ] **C5. Dedicated writeup subagent**
  - 대상: `reporting.py:_write_writeups` (현재 Markdown 템플릿)
  - finding별 fresh-context assignment, source 재분석, PoC artifact, report format validator, claim/retry
  - 경로를 참조 contract(`findings/<slug>/<slug>.md`, `findings/<slug>/poc/`)로
- [ ] **C6. 실제 hardening portfolio**
  - 대상: `engine/kiro_security/hardening.py` (현재 category count 템플릿)
  - architecture 분석, 여러 viable option, tradeoff matrix, migration/rollout, metrics, diagrams, structured `hardening.json`, work packages

---

### WS-D. Threat model 실질화

- [ ] **D1. Repository-specific 모델 분석**
  - 대상: `engine/kiro_security/threat_model.py` (현재 위험 문자열 탐지 + 고정 템플릿)
  - assets, trust boundary, attacker-controlled input, privileged ops, auth/tenant model, deployment/runtime
- [ ] **D2. 보안 정책 문서 반영**
  - `SECURITY.md`를 authoritative policy로, `AGENTS.md` security guidance를 compile
- [ ] **D3. Revision-specific cache 검증 + worker model 합성**
  - `runner.py`의 shared pre-discovery threat model 위치 문제 해결 (참조는 worker별 독립 생성 후 합성)

---

### WS-E. Standard / Diff 재정의

- [ ] **E1. 현 regex scanner를 `Fast Scan`으로 명칭 분리**
  - 대상: `engine/kiro_security/scanner.py`, `package.json` 명령/설정, Webview
  - "빠른 deterministic heuristic pre-screen"으로 정직하게 표기
- [ ] **E2. Standard Scan을 모델 workflow로 신설**
  - repository guidance → threat model → ranked worklist → exhaustive discovery → dedupe → validation → attack-path → writeup → hardening → finalization
- [ ] **E3. Diff Scan을 모델 workflow로 신설**
  - 실제 hunk 분석, 삭제된 security check, 변경 함수 caller/sibling 추적, shared auth helper 영향, rename 후 semantic identity, repository-scope threat model
  - 대상: `scanner.py`의 diff 경로, `runner.py`

---

### WS-F. Finding identity 안정화

- [ ] **F1. Line 기반 fingerprint 제거**
  - 대상: `scanner.py`(`path:sink_line:rule_id:anchor`), `deep.py`(`path:startLine` 기본 instance)
  - `target + rule + semantic anchor + independent instance` 기반 stable fingerprint
- [ ] **F2. Rename/line-shift 내성 검증**
  - 수용 기준: 위에 빈 줄 추가·파일 rename 후에도 동일 finding ID 유지 테스트 통과
  - 영향: scan history 추적, duplicate tracking, accepted-risk 연결, Deep novelty 정확도

---

### WS-G. Scope & 보안 표면 확장

- [ ] **G1. 비소스 보안 표면 inventory 편입**
  - 대상: `engine/kiro_security/constants.py`(현재 확장자 allowlist)
  - Dockerfile, docker-compose, YAML/JSON/XML, Terraform, K8s/Helm, GitHub/GitLab CI, package/lock 파일, requirements/poetry/pom/gradle, SQL migration, nginx/apache conf, IAM policy, cloud template, .env template, protobuf/OpenAPI
- [ ] **G2. Relevance 기반 worklist 구성**
  - 확장자 allowlist가 아니라 runtime·deployment·privilege relevance로 scope 결정
- [ ] **G3. "미분석"과 "무취약" 구분을 scope 수준에서도 보장** (WS-A와 연동)

---

### WS-I. Schema / Contract wire 호환

- [ ] **I1. findings/coverage/scan-manifest schema 확장**
  - 대상: `engine/schemas/*.json` (현재 참조 대비 크게 축약: findings 132 vs 359줄 등)
  - strict pattern: finding ID, occurrence ID, fingerprint, safe writeup path
  - root cause / validation / attack-path 구조 강제
  - complete coverage conditional, mandatory canonical artifact cardinality
- [ ] **I2. TS/Python protocol 타입 동기화**
  - 대상: `packages/protocol/src/types.ts`, `validate.ts`, `engine/kiro_security/protocol.py`
- [ ] **I3. Codex canonical contract와 wire-compatibility 목표 정의**
  - 완전 동일이 목표인지, Kiro 방언 허용인지 결정 후 문서화

---

## 5. P2 — 후반 workflow

### WS-H. Fix / Triage / Tracking

- [ ] **H1. 실제 patch/remediation workflow**
  - 대상: `engine/kiro_security/remediation.py` (현재 안내 Markdown만)
  - code drift 확인, patch 계획, repository 수정, targeted/existing test, security validation, patch artifact, verification receipt
- [ ] **H2. Proof-chain triage**
  - 대상: `engine/kiro_security/tracking.py` 인접, triage 로직
  - 외부 scanner/SARIF/CVE/GHSA/advisory import 분석, reachability, evidence chain, false-positive 판단 (현재는 사용자 decision 저장만)
- [ ] **H3. Connector tracking (GitHub/Linear/Jira)**
  - 대상: `engine/kiro_security/tracking.py` (현재 handoff JSON만)
  - destination 확인 → duplicate 검색 → exact write preview → 승인 → 재검증 → provider write → readback verification
  - 보안 경계(승인 전 write 금지)는 현재 설계 유지

---

## 6. 전 구간 — 테스트 & Release assurance (WS-J)

- [ ] **J1. Deep 전용 테스트 스위트 신설** (현재 전무)
  - 정확히 6 worker / all-six claim barrier / fresh-context proof / worker idle / 전체 row receipt / merge semantic correctness / ID manipulation 방지 / capped coverage / multi-round convergence / interrupted worker recovery / worker threat-model synthesis / dedicated tail workflow
- [ ] **J2. Coverage correctness 테스트** (0-file, capped, deferred, all-clean)
- [ ] **J3. Finalizer seal / projection 테스트**
- [ ] **J4. Finding identity 안정성 테스트** (rename/line-shift)
- [ ] **J5. Contract 테스트 확장** (TS↔Python, malformed, version mismatch)
- [ ] **J6. 실제 Kiro desktop delegated agent 실행 검증**
  - `scripts/verify-in-kiro.sh` / `.ps1` 확장, `docs/local-kiro-smoke-test.md` 갱신
  - VSIX Deep 버튼 → Agent orchestration → 6-worker 완주 → finalize 까지 end-to-end
- [ ] **J7. `npm run verify` + `python3 -m pytest` 전체 통과를 release gate로 강제** (0.3.0의 테스트 생략 관행 폐지)

---

## 7. 문서 정합성 (WS-K)

- [ ] **K1. `README.md`** — 0.2.0 → 현재 버전 및 실제 기능 반영
- [ ] **K2. `CHANGELOG.md`** — 0.3.0+ 항목 추가
- [ ] **K3. `docs/migration-matrix.md`** — "no model-dependent worker fan-out" 등 실제 구현과 재대조, parity 과장 제거
- [ ] **K4. `docs/security-model.md`** — telemetry/보안 모델 최신화
- [ ] **K5. `DESIGN.md`** — 미구현 항목(tail assignment, writeup worker 등)을 "목표 vs 구현" 상태로 명확히 표기
- [ ] **K6. 제품 정의 문구 통일** — "Codex Security 완전 migration"이 아니라 실제 parity 달성 전까지는 정확한 위치로 기술

---

## 8. 권장 실행 순서 (마일스톤)

> 각 마일스톤은 이전 마일스톤의 테스트가 green일 때만 다음으로 진행.

**M1 — 정직성 & 정확성 (P0):** WS-A(전체), WS-B(B1·B2), WS-K(K6, K1) + WS-J(J2, J3)
→ 결과: 더 이상 false `complete`/false assurance 없음. 제품 위치를 정확히 표기.

**M2 — Deep 신뢰성 (P1):** WS-B(B3–B10), WS-F, WS-I(I1·I2) + WS-J(J1, J4, J5)
→ 결과: 6-worker 독립성/동질성 실제 강제, 안정적 identity, 감사 가능한 artifact.

**M3 — 모델 기반 분석 (P1):** WS-C(전체), WS-D, WS-G + WS-J(J6)
→ 결과: validation/attack-path/writeup/hardening/threat-model이 실제 모델 workflow. Kiro desktop end-to-end 검증.

**M4 — Scan mode 재정의 (P1):** WS-E
→ 결과: Fast Scan 분리 + Standard/Diff 모델 workflow.

**M5 — 후반 workflow (P2):** WS-H, WS-K(잔여) + WS-J(J7 release gate 상시화)
→ 결과: fix/triage/tracking parity, 문서 완전 동기화.

---

## 9. 이관 완료 선언 조건 (재확인)

아래가 모두 참일 때만 "Codex Security 경험을 Kiro IDE에 완전 이관했다"고 선언한다.

- [ ] 실제 Kiro desktop에서 delegated agent가 6-worker Deep을 multi-round로 완주
- [ ] 모든 worklist row가 disposition+receipt로 닫히고, coverage `complete`가 검증됨
- [ ] validation/attack-path가 모델 기반 증명으로 생성되고 severity가 재산정됨
- [ ] finding별 dedicated writeup + 전체 hardening portfolio 생성
- [ ] manifest/findings/coverage가 strict schema로 seal되고 report는 projection
- [ ] finding identity가 rename/line-shift에 안정적
- [ ] Deep 전용 테스트 + 전체 regression + Kiro desktop smoke test green
- [ ] 문서가 실제 구현과 일치 (parity 과장 없음)
