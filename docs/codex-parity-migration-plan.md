# Codex Security → Kiro Security Power parity 작업 리스트

## 0. 이 문서의 목적

이 문서는 Codex Security 0.1.11의 보안 분석 경험에서 허가된 안전 속성을 Kiro Security Power의 제품·host 경계에 맞게 이관하기 위한 작업 리스트다. Byte-for-byte contract나 Codex/OpenAI 제품 identity 복제가 목표는 아니다.

현재 0.3.0 worktree에는 Fast/model profile 분리, durable six-worker discovery와 model tail, repository context, strict coverage/finalization, semantic identity, 보안 표면 inventory, remediation/triage/tracking 및 strict schema/wire 계약이 구현돼 있다. 저장 regression과 focused smoke는 구현 계약의 근거지만, 실제 Kiro Desktop delegated multi-round 실행과 전체 release gate는 아직 완료 근거가 없다.

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
| WS-A | Coverage & Finalization correctness (**완료**) | **P0** | row-level coverage ledger, strict finalizer, seal |
| WS-B | Deep orchestration 신뢰성 (**완료**) | **P0/P1** | claim barrier, identity 강제, host capability preflight, worker artifact suite |
| WS-C | Model-based 분석 tail (**완료**) | **P1** | validation/attack-path/writeup/hardening을 실제 모델 assignment로 |
| WS-D | Repository security context & policy compilation (**완료**) | **P1** | repository-specific context, policy provenance, snapshot-bound digest |
| WS-E | Standard/Diff 재정의 (**완료**) | **P1** | Fast Scan 분리 + 모델 workflow 신설 |
| WS-F | Finding identity 안정화 (**완료**) | **P1** | semantic fingerprint |
| WS-G | Scope & 보안 표면 확장 (**완료**) | **P1** | 비소스 보안 표면(IaC, config, deps) |
| WS-H | 후반 workflow (fix/triage/tracking) (**완료**) | **P2** | 실제 patch, proof-chain triage, connector-safe handoff/readback |
| WS-I | Schema/Contract wire 호환 (**완료**) | **P1** | strict JSON schema 확장 |
| WS-J | 테스트 & release assurance (**부분 완료**) | **전구간** | 저장 regression 완료; Kiro desktop 실행 검증 미완료 |
| WS-K | 문서 정합성 (**완료**) | **P2** | DESIGN/README/matrix 실제 구현과 동기화 |

---

## 3. P0 — 정확성 및 false assurance 제거

가장 먼저 닫아야 하는, 사용자에게 잘못된 보안 확신을 줄 수 있는 결함들.

### WS-A. Coverage & Finalization correctness

- [x] **A1. Row-level coverage ledger 도입**
  - 대상: `engine/kiro_security/deep.py`, `engine/kiro_security/reporting.py`, `engine/migrations/*.sql`
  - 현재 `reviewedPaths`(단순 경로 집합, "attendance list")를 폐기하고, worklist row마다 다음을 저장:
    `rowId, surface, entrypoint, rootControl, sink, disposition, reason, evidenceRefs, workerId, candidateIds, receiptDigest`
  - disposition은 `reportable | suppressed | not_applicable | deferred` 중 하나로 강제
  - 수용 기준: 각 disposition에 근거(reason)와 receipt가 없으면 worker 제출 거부
- [x] **A2. `complete`는 모든 row가 닫힌 경우에만 허용**
  - 대상: `reporting.py:build_coverage_document`
  - 현재 `"partial" if deferred else "complete"` 로직 제거
  - 미검토/미지원 in-scope row가 하나라도 있으면 `complete` 금지
- [x] **A3. Deep cap을 coverage에 반영**
  - `capped → completeness=partial (capped)`
  - `unsupported in-scope files → deferred 또는 explicit exclusion`
  - `0 supported files → unknown/blocked` (Standard/Diff도 Deep과 동일하게)
  - 대상: `reporting.py` (Deep state 조회 추가), `deep.py`
- [x] **A4. `receiptRefs`를 실제 receipt로 교체**
  - finding occurrence ID가 아니라 ledger/artifact receipt digest를 참조
- [x] **A5. Strict canonical finalizer 구현**
  - 대상: 신규 `engine/kiro_security/finalizer.py`(제안)
  - `scan-manifest.json / findings.json / coverage.json`을 strict schema로 검증 후 **seal(digest 고정)**
  - `report.md`, SARIF, CSV는 canonical JSON에서 **deterministic projection**으로만 생성
  - producer(reporting)가 report를 직접 쓰지 않도록 분리
  - seal 대상에 report/hardening 포함 금지
- [x] **A6. manifest 상태 정합성 수정**
  - 현재 scan DB가 completed 되기 전 manifest에 `status: completed`가 박히는 문제 제거
  - finalizer가 실제 완료 시점에 상태를 기록

**WS-A 완료 검증:** durable row-level coverage ledger와 Deep worker receipt, canonical disposition,
strict authoritative frontier, immutable canonical snapshot 및 manifest/DB artifact hash seal을 독립
smoke로 확인했다. 0 supported files는 `unknown`, capped Deep과 unsupported/deleted/missing path는
`partial` 또는 explicit `deferred`로 처리되며 all-clean에서만 `complete`가 허용된다. Frontier
shrink, Diff 삭제 파일, legacy `reviewedPaths` backfill, publication 중 canonical mutation rollback,
tampered/missing manifest quarantine 및 durable `scan.integrityIssue`도 직접 재현했다. Python
compile, Python 3.9 grammar 및 `git diff --check`는 통과했다.

---

### WS-B (P0 부분). Deep 동시성 barrier

- [x] **B1. All-six claim barrier**
  - 대상: `deep.py:submit_worker`
  - 첫 worker result 제출 전에 6개 worker가 모두 claim 상태여야 함
  - 수용 기준: 5개만 claim된 상태에서 submit 시 `deep_round_not_fully_claimed` 오류
- [x] **B2. Merge 전 6-worker idle proof**
  - 6개 worker가 모두 `completed` 이고 재클레임 불가 상태임을 merge claim 시 재확인하도록 기존 로직 강화

---

## 4. P1 — Deep orchestration 신뢰성

### WS-B (P1 부분). Worker 독립성/동질성 강제

- [x] **B3. Host capability preflight**
  - 대상: `engine/kiro_security/mcp_server.py`, Power steering, `runner.py:_phase_preflight`
  - Deep 시작 전 실제 확인: `delegated agent available, fresh-context mode, 6 usable slots, model identity, reasoning identity, agent depth, goal support`
  - capability 미충족 시 명시적 오류로 Deep 시작 차단 (조용히 대기 금지)
- [x] **B4. Round profile 고정 + 동질성 검증**
  - 첫 worker claim 시 round profile 확정: `modelId, agentType, reasoningEffort, hostVersion, delegationMode`
  - 이후 worker가 프로파일과 불일치하면 claim 거부 (model drift rejection)
  - 대상: `deep.py:claim_worker`
- [x] **B5. Fresh-context / idle proof 요구**
  - worker 제출 시 coordinator history 미상속 증명 및 완료 후 idle 상태 근거 요구
- [x] **B6. Worklist 밀도 강화**
  - 대상: `deep.py:ensure`, `_write_shared_worklists`
  - 기존 `rowId, path, language, size` 중심 row를 참조 수준으로 확장:
    `runtime relevance, product area, deployment significance, entrypoint, privileged boundary, root control, seed/advisory anchor, high-impact family, work shard, ranking reason, deferred/excluded reason`
- [x] **B7. Worker artifact suite 구현**
  - 각 worker output에 실제 artifact 부여:
    `threat_model.md, finding_discovery_report.md, seed_research.md, work_ledger.jsonl, raw_candidates.jsonl, dedupe_report.md, deduped_candidates.jsonl, repository_coverage_ledger.md, candidate-ledger/<candidate>.jsonl`
- [x] **B8. Candidate evidence 요건 강화**
  - 대상: `deep.py:_normalize_candidate`
  - 필수화: `attacker-controlled source, root control, sink/broken control, source-to-sink path, authorization boundary, entrypoint, concrete impact, counterevidence, candidate-local validation/attack-path proof`
  - **engine auto-snippet fallback 제거** (`if not evidence:` 블록) — 모델이 근거를 안 내면 거부
- [x] **B9. Semantic merge 검증 강화**
  - 기존 sourceRef 소비/ID 보존/novelty 계산은 유지하되, contract 플래그(`mergeContract`)를 실제 검증 로직으로:
    - 하나의 remediation이 upstream candidate 전부를 닫는지
    - sibling instance 독립 reachability
    - 동일 취약점 ID 재사용/재등록으로 novelty 은닉·부풀림 방지
- [x] **B10. Deep provenance 보존**
  - canonical candidate ID, absorbed sourceRef, worker/round/model 정보를 최종 finding까지 전파

**WS-B 완료 검증:** all-six barrier, profile/completion attestation, strict·legacy resume,
sourceRef exact consumption, canonical identity/novelty, sanitized final provenance, dense worklist,
worker artifact rollback·retry를 독립 smoke로 확인했다. 신뢰 가능한 host attestation source가 없는
VSIX Deep 시작은 engine 호출 전에 Kiro Agent 사용 안내로 차단하며 Standard/Diff는 기존 경로를 유지한다.
Python compile, Python 3.9 grammar, `git diff --check`는 통과했다. 환경에 도구가 없어 pytest,
jsonschema 및 TypeScript build/diagnostics는 실행하지 못했으며 의존성을 임의 설치하지 않았다.

---

### WS-C. Model-based 분석 tail

Deep의 validation/attack-path/writeup/hardening을 durable model assignment로 전환했다.
WS-C 완료 당시 Standard/Diff는 기존 deterministic 경로를 유지했으며, 이후 WS-E에서 Fast와 model profile로 분리했다.

- [x] **C1. Tail assignment MCP 도구 신설**
  - `security_deep_get_tail_assignment`, `security_deep_submit_tail_result`, `security_deep_retry_writeup` 등
  - 각각 durable claim/result/receipt
  - 대상: `mcp_server.py`, `tail.py`, migration
- [x] **C2. Canonical threat-model synthesis**
  - worker별 threat model을 합성해 canonical validation threat model 생성 (discovery **이후**)
- [x] **C3. Candidate validation을 모델/동적 proof로**
  - Deep은 기존 `validator.py` regex 경로를 authoritative validation으로 사용하지 않음
  - repository-native test, focused PoC, cross-file trace, framework middleware 인식, counterevidence, proof gap
  - 동적 불가 시에만 정적 fallback
- [x] **C4. Attack-path & severity policy**
  - Deep은 기존 `attack_path.py` 고정 transform 대신 model tail 결과 사용
  - 실제 actor/entry/control/sink/impact 사실 연결 + severity 재산정(policy matrix)
  - `exploitability = "high" if validated else "medium"` 같은 단순 규칙 제거
- [x] **C5. Dedicated writeup subagent**
  - Deep reporting은 기존 Markdown template 대신 완료된 fresh-context writeup 결과 참조
  - finding별 fresh-context assignment, source 재분석, PoC artifact, report format validator, claim/retry
  - 경로를 참조 contract(`findings/<slug>/<slug>.md`, `findings/<slug>/poc/`)로
- [x] **C6. 실제 hardening portfolio**
  - Deep은 기존 category count template 대신 model portfolio 사용
  - architecture 분석, 여러 viable option, tradeoff matrix, migration/rollout, metrics, diagrams, structured `hardening.json`, work packages

**WS-C 완료 검증:** premature completion 차단, stage ordering, runtime/profile/completion
attestation, full validation/attack proof 조회, ancestor symlink artifact 차단, orphaned claim
resume, zero-finding 및 one-finding Deep tail, dedicated writeup/PoC, hardening projection과 strict
finalization을 독립 smoke로 확인했다. Standard scan과 Diff wire도 기존 경로를 유지했다. Python
compile, Python 3.9 grammar, `git diff --check`는 통과했다. 환경에 도구가 없어 pytest,
jsonschema 및 TypeScript build/diagnostics는 실행하지 못했으며 의존성을 임의 설치하지 않았다.

---

### WS-D. Repository security context & policy compilation

WS-C C2가 discovery 이후 canonical threat-model synthesis를 담당한다. WS-D는 이를 재구현하지
않고 discovery 이전에 repository-specific 보안 문맥과 정책을 근거·digest와 함께 compile하여
각 독립 worker와 WS-C canonical synthesis 입력에 제공한다.

- [x] **D1. Repository-specific security context compile**
  - 대상: `engine/kiro_security/threat_model.py` 및 기존 inventory/worklist 입력 경계
  - assets, trust boundaries, attacker-controlled inputs, privileged operations, auth/tenant model,
    deployment/runtime을 실제 repository path 근거와 unknown/proof gap으로 구조화
  - 위험 문자열 탐지나 고정 template을 repository-specific 사실 또는 검증 결과로 표시하지 않음
- [x] **D2. Security policy/guidance provenance**
  - `SECURITY.md`를 repository security policy로, `AGENTS.md`의 security-relevant guidance를
    출처 path·content digest·적용 scope와 함께 compile
  - 상충하거나 적용 범위가 불명확한 guidance는 임의로 해석하지 않고 explicit conflict/unknown으로 보존
  - 문서 안의 command나 code를 실행하지 않으며 정책 근거와 분석 지침으로만 취급
- [x] **D3. Snapshot-bound context delivery & invalidation**
  - compiled context digest를 revision/snapshot, scope, inventory/worklist digest, policy/guidance file digest에 결합
  - revision, scope, inventory 또는 guidance가 바뀌면 기존 context/cache를 재사용하지 않음
  - 동일 immutable context를 각 discovery worker에 제공하되 worker별 분석 독립성은 유지
  - worker threat-model artifact와 compiled context reference를 WS-C C2 입력으로 전달

**WS-D 비목표:** 두 번째 canonical threat-model assignment/merge, validation, attack-path,
writeup, hardening 또는 WS-C tail state machine을 새로 만들지 않는다. discovery 이후 canonical
synthesis와 authoritative tail provenance는 완료된 WS-C 계약을 그대로 재사용한다.

**WS-D 완료 검증:** repository별 context와 policy/guidance provenance가 snapshot·scope·
inventory/worklist digest에 결합되고, all-six worker에 동일한 immutable context가 전달되는 것을
독립 smoke로 확인했다. 동일 길이 README/manifest/deployment 문서 변경과 source set 변경은
`security_context_changed`로 거부되며, 1MiB 초과 policy는 `security_context_invalid`로 차단된다.
사용 불가능한 context source는 C2 evidence로 승격되지 않고 정상 policy evidence만 허용된다.
7,000개 source scope에서도 bounded provenance payload로 threat-model assignment가 생성되었고,
zero-finding Deep tail 및 Standard/Diff 회귀 smoke도 통과했다. Python compile, Python 3.9 grammar,
`git diff --check`는 통과했다. 환경에 도구가 없어 pytest, jsonschema 및 TypeScript
build/diagnostics는 실행하지 못했으며 의존성을 임의 설치하지 않았다.

---

### WS-E. Standard / Diff 재정의

- [x] **E1. 현 regex scanner를 `Fast Scan`으로 명칭 분리**
  - 대상: `engine/kiro_security/scanner.py`, `package.json` 명령/설정, Webview
  - "빠른 deterministic heuristic pre-screen"으로 정직하게 표기
- [x] **E2. Standard Scan을 모델 workflow로 신설**
  - repository guidance → threat model → ranked worklist → exhaustive discovery → dedupe → validation → attack-path → writeup → hardening → finalization
- [x] **E3. Diff Scan을 모델 workflow로 신설**
  - bounded hunk와 deleted path/line, rename hint, 의미가 확정되지 않은 same-directory supporting sibling path를 model assignment에 제공
  - 대상: `scanner.py`의 diff 경로, `runner.py`

**WS-E 완료 검증:** VSIX/Webview는 deterministic Fast profile을 별도 표시하고 model Standard/Diff는
truthful Kiro Agent runtime attestation 없이는 engine 호출 전에 handoff한다. Standard는 한 번의
six-worker merge 후 saturated로 닫힌다. Diff는 bounded changed/deleted line과 rename hint,
unconfirmed same-directory supporting path를 같은 model tail에 전달하며 shared-auth 의미를 engine이
확정하지 않는다. 실제 Kiro Agent Desktop 실행은 J6에 남는다.

---

### WS-F. Finding identity 안정화

- [x] **F1. Line 기반 fingerprint 제거**
  - 대상: `scanner.py`(`path:sink_line:rule_id:anchor`), `deep.py`(`path:startLine` 기본 instance)
  - `target + rule + semantic anchor + independent instance` 기반 stable fingerprint
- [x] **F2. Rename/line-shift 내성 검증**
  - 수용 기준: 위에 빈 줄 추가·파일 rename 후에도 동일 finding ID 유지 테스트 통과
  - 영향: scan history 추적, duplicate tracking, accepted-risk 연결, Deep novelty 정확도

**WS-F 완료 검증:** Standard/Diff fingerprint를 rule·semantic anchor·lexical scope·normalized
target/statement·scope-local sibling instance 기반으로 전환하고, Deep strict candidate의 path/line
기본 identity를 제거했다. Python 및 named JavaScript/TypeScript arrow/function scope에서 blank-line,
file rename, unrelated-scope insertion 후에도 기존 finding ID가 유지되고 같은 scope의 독립 sibling은
분리되는 것을 독립 smoke로 확인했다. Cross-file semantic collision은 모든 candidate를 보존하며
inventory 순서와 line shift에 안정적이다. Python compile, Python 3.9 grammar, `git diff --check`는
통과했다. 환경에 pytest가 없어 저장 test runner는 실행하지 못했으며 의존성을 설치하지 않았다.
실제 collision 그룹 내부 file rename 또는 clone membership 변경 시 collision identity가 바뀔 수
있는 제한은 persistent identity registry 도입 전까지 관리할 P2로 남긴다.

---

### WS-G. Scope & 보안 표면 확장

- [x] **G1. 비소스 보안 표면 inventory 편입**
  - 대상: `engine/kiro_security/constants.py`(현재 확장자 allowlist)
  - Dockerfile, docker-compose, YAML/JSON/XML, Terraform, K8s/Helm, GitHub/GitLab CI, package/lock 파일, requirements/poetry/pom/gradle, SQL migration, nginx/apache conf, IAM policy, cloud template, .env template, protobuf/OpenAPI
- [x] **G2. Relevance 기반 worklist 구성**
  - 확장자 allowlist가 아니라 runtime·deployment·privilege relevance로 scope 결정
- [x] **G3. "미분석"과 "무취약" 구분을 scope 수준에서도 보장** (WS-A와 연동)

**WS-G 완료 검증:** Deep inventory는 filename/path 기반의 bounded security-surface 분류로 IaC,
deployment, CI, dependency, migration, IAM, environment template 및 API/config surface를 worklist에
포함한다. 근거 없는 privilege/entrypoint는 생성하지 않으며 Fast에서 검토하지 않는 surface와
invalid text는 explicit deferred로 남긴다. Focused inventory/coverage regression이 저장돼 있다.

---

### WS-I. Schema / Contract wire 호환

- [x] **I1. findings/coverage/scan-manifest schema 확장**
  - 대상: `engine/schemas/*.json` (현재 참조 대비 크게 축약: findings 132 vs 359줄 등)
  - strict pattern: finding ID, occurrence ID, fingerprint, safe writeup path
  - root cause / validation / attack-path 구조 강제
  - complete coverage conditional, mandatory canonical artifact cardinality
- [x] **I2. TS/Python protocol 타입 동기화**
  - 대상: `packages/protocol/src/types.ts`, `validate.ts`, `engine/kiro_security/protocol.py`
- [x] **I3. Codex canonical contract와 wire-compatibility 목표 정의**
  - 완전 동일이 목표인지, Kiro 방언 허용인지 결정 후 문서화

**WS-I 완료 검증:** Kiro ID/fingerprint/document dialect를 유지하면서 safe relative path, structured
proof, coverage completeness 및 canonical manifest cardinality를 strict schema로 검증한다. Python과
TypeScript envelope는 integer request ID, exclusive success/failure, known event 및 protocol version을
공유하며 `scan.integrityIssue`가 동기화됐다. Focused schema/protocol regression이 저장돼 있다.

---

## 5. P2 — 후반 workflow

### WS-H. Fix / Triage / Tracking

- [x] **H1. 실제 patch/remediation workflow**
  - 대상: `engine/kiro_security/remediation.py`
  - code drift 확인, patch 계획, repository 수정, targeted/existing test, security validation, patch artifact, verification receipt
- [x] **H2. Proof-chain triage**
  - 대상: `engine/kiro_security/tracking.py` 인접, triage 로직
  - 외부 scanner/SARIF/CVE/GHSA/advisory import, reachability, evidence chain 및 proof gap을 bounded assessment로 저장
- [x] **H3. Connector-safe tracking (GitHub/Linear/Jira)**
  - 대상: `engine/kiro_security/tracking.py`
  - engine은 destination과 exact payload digest를 고정하고 sanitized connector readback을 기록
  - provider credential, duplicate search, 승인 및 network write는 별도 authorized connector 경계에 유지

**WS-H 완료 검증:** remediation은 prepared patch digest, revision/file drift, optimistic version 및
explicit apply/verification gate를 사용한다. Triage intake와 proof-chain assessment는 untrusted external
payload를 bounded하게 보존한다. Tracking은 exact preview와 sanitized readback만 durable하게 기록하며
engine 자체는 model command 또는 provider network write를 실행하지 않는다.

---

## 6. 전 구간 — 테스트 & Release assurance (WS-J)

- [x] **J1. Deep 전용 테스트 스위트 완주**
  - 정확히 6 worker / all-six claim barrier / fresh-context proof / worker idle / 전체 row receipt / merge semantic correctness / ID manipulation 방지 / capped coverage / multi-round convergence / interrupted worker recovery / worker threat-model artifact와 context provenance / dedicated tail workflow
- [x] **J2. Coverage correctness 테스트** (0-file, capped, deferred, all-clean)
- [x] **J3. Finalizer seal / projection 테스트**
- [x] **J4. Finding identity 안정성 테스트** (rename/line-shift)
- [x] **J5. Contract 테스트 확장** (TS↔Python, malformed, version mismatch)
- [ ] **J6. 실제 Kiro desktop delegated agent 실행 검증**
  - `scripts/verify-in-kiro.sh` / `.ps1` 확장, `docs/local-kiro-smoke-test.md` 갱신
  - VSIX Deep 버튼 → Agent orchestration → 6-worker 완주 → finalize 까지 end-to-end
- [ ] **J7. `npm run verify` + `python3 -m pytest` 전체 통과를 release gate로 강제** (0.3.0의 테스트 생략 관행 폐지)

**WS-J 현재 상태:** 저장 regression은 exact six-worker claim, hostile barrier/profile/completion/
sourceRef/identity 입력, receipt/artifact/context, round 1 novelty에서 round 2 zero-novelty saturation 및
retained canonical identity를 검증한다. Coverage, finalizer, finding identity와 protocol regression도
저장돼 있다. 최신 전체 command green 기록과 실제 Kiro Desktop delegated-agent 증거는 아직 완료로
표시하지 않는다. 설치 helper는 UI/Agent 성공을 자동 주장하지 않고 수동 result JSON과
receipt/manifest 증거를 요구한다.

---

## 7. 문서 정합성 (WS-K)

- [x] **K1. `README.md`** — 0.2.0 → 현재 버전 및 실제 기능 반영
- [x] **K2. `CHANGELOG.md`** — unreleased 0.3.0 worktree 항목 추가
- [x] **K3. `docs/migration-matrix.md`** — model workflow와 connector trust boundary로 재대조
- [x] **K4. `docs/security-model.md`** — telemetry/보안 모델 최신화
- [x] **K5. `DESIGN.md`** — Fast/model mode와 실제 durable tail/tool 상태 반영
- [x] **K6. 제품 정의 문구 통일** — Kiro dialect parity와 미검증 Desktop gate를 명시

---

## 8. 권장 실행 순서 (마일스톤)

> 각 마일스톤은 이전 마일스톤의 테스트가 green일 때만 다음으로 진행.

**M1 — 정직성 & 정확성 (P0):** WS-A(전체), WS-B(B1·B2), WS-K(K6, K1) + WS-J(J2, J3)
→ 결과: 더 이상 false `complete`/false assurance 없음. 제품 위치를 정확히 표기.

**M2 — Deep 신뢰성 (P1):** WS-B(B3–B10), WS-F, WS-I(I1·I2) + WS-J(J1, J4, J5)
→ 결과: 6-worker 독립성/동질성 실제 강제, 안정적 identity, 감사 가능한 artifact.

**M3 — 모델 기반 분석 (P1):** WS-C(전체), WS-D, WS-G + WS-J(J6)
→ 결과: snapshot-bound repository policy/context가 독립 discovery worker와 canonical threat-model synthesis에 공급되고, validation/attack-path/writeup/hardening이 실제 모델 workflow로 동작. Kiro desktop end-to-end 검증.

**M4 — Scan mode 재정의 (P1):** WS-E
→ 결과: Fast Scan 분리 + Standard/Diff 모델 workflow.

**M5 — 후반 workflow (P2):** WS-H, WS-K + WS-J(J7 release gate 상시화)
→ 결과: remediation/proof-chain triage와 connector-safe handoff/readback 구현, implemented contract 문서 동기화.

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
