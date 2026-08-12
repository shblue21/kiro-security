# Codex Security Plugin 0.1.11 → 0.1.17 델타 분석

## 문서 지위

이 문서는 `docs/codex-security-plugin-0.1.11-architecture.md`(이하 **0.1.11 문서**)를 기준선으로 두고, 로컬에 설치된 `0.1.17` 패키지와의 차이만 기록한 **델타 참고 자료**다. 0.1.11 문서를 대체하지 않는다. 0.1.11 문서는 해당 버전 시점의 참고 자료로 그대로 보존하고, 현재 버전 기준 판단이 필요할 때 이 문서를 함께 읽는다.

- 기준선: `codex-security@0.1.11` (0.1.11 문서의 서술)
- 대조 대상: `$CODEX_HOME/plugins/cache/openai-curated-remote/codex-security/0.1.17/` (실제 설치 패키지)
- 분석 시점: 2026-08-07
- 근거 우선순위: 0.1.17 설치 패키지의 코드/스키마 → OpenAI 공식 changelog → 0.1.11 문서
- 저작권 경계: 압축된 MCP 런타임은 동작과 인터페이스만 분석했으며 복원한 원본을 이 저장소에 복사하지 않았다.

## 검증 방법과 한계

**0.1.11 패키지는 로컬에 남아 있지 않다.** 따라서 패키지 대 패키지 diff는 수행하지 못했다. 대신 다음 세 근거를 교차 검증했다.

| 축 | 근거 | 확정성 |
|---|---|---|
| 0.1.17 상태 | 설치 패키지 코드/스키마 직접 판독 | 확정 |
| 0.1.11 상태 | 0.1.11 문서 서술 | 대리 근거 |
| 변경 시점 | OpenAI 공식 plugin changelog | 확정 |

0.1.11 문서를 대리 근거로 채택한 이유는 다음 항목이 0.1.17 코드와 **문자 단위로 일치**하기 때문이다. 즉 문서는 작성 시점에 높은 정확도를 가졌다고 판단할 근거가 있다.

- 마이그레이션 v1–v10의 순서와 설명 문자열
- fingerprint 구성 material과 구분자
- finalizer의 파일 기록 순서
- `sealedAt == completedAt` 강제
- canonical schema 3종의 enum 값 전체

또한 workbench 마이그레이션이 **append-only**로 누적되어 v1–v10이 원형 그대로 보존되어 있으므로, 스키마 변경 방향은 0.1.17 코드만으로도 확정할 수 있다.

**남은 한계.** 0.1.11 문서가 서술하지 않은 0.1.11의 세부 동작은 이 델타에 나타나지 않는다. 이 문서의 "변경 없음" 판정은 *0.1.11 문서가 기술한 범위 안에서* 변경이 없다는 뜻이다.

## 핵심 결론

변화의 방향은 여섯 릴리스에 걸쳐 일관된다.

> **플러그인이 자체 UI와 파일시스템 상태를 소유하던 구조에서, 호스트 네이티브 워크플로에 통합되고 상태를 DB로 끌어오는 구조로 이동했다.**

이를 네 축으로 나누면 다음과 같다.

1. **전달 경로:** 임베디드 App 위젯 → 네이티브 워크플로 (기능 삭제가 아니라 경로 이동)
2. **상태 소유:** 파일시스템 아티팩트 → 구조화 MCP 도구 호출 + SQLite (JSONL은 Standard/Diff에 병행 잔존)
3. **실행 게이트:** 엄격한 capability preflight → Deep MCP 자체 워커 런타임
4. **판정 성향:** finding 억제 → finding 보존 (severity 하향으로 대체)
5. **커버리지 전략:** ranked worklist + boundary×family ledger → **전수 파일 리뷰 + 2-pass 압축 검증**

5번은 0.1.11 문서에서 가장 정교하게 기술된 §9.1이 통째로 사라진 것이어서, 이식 시 영향이 크다. 세부는 §8.1을 본다.

0.1.11 문서의 **canonical artifact 계약과 finalization 경계는 변경되지 않았다.** 이식 관점에서 가장 안정적인 영역이다.

## 1. 버전별 귀속

공식 changelog와 코드 증거를 대응시킨 결과다. 코드에서 발견한 변화가 어느 릴리스에서 도입됐는지 확정한다.

| 변화 | 도입 | 코드 증거 |
|---|---|---|
| Deep scan 워커 조정 도입 | 0.1.12 | — |
| model/reasoning 설정 위임 전달 | 0.1.12 | 마이그레이션 v25 `scans.model`, `scans.reasoning_effort` |
| 네이티브 setup flow | 0.1.12 | 마이그레이션 v19 `setup_preferences` |
| validated low-severity finding 보존 | 0.1.12 | `severity-policy.md` |
| 배포/노출 맥락으로 severity 보정 | 0.1.13 | `severity-policy.md:94,111` |
| `define-security-policy` 스킬 | 0.1.14 | `skills/define-security-policy/` |
| 안정 repository/finding identity | 0.1.14 | v16 `security_targets`, `workspaces.target_id`, `scans.target_id` |
| 완료 스캔 비교 | 0.1.14 | v23 `scan_comparisons`, `scan_comparison_matches` |
| 저장된 설정으로 재실행 | 0.1.14 | v22 `scans.recipe_json`, `scans.parent_scan_id` |
| Standard scan 전수 리뷰 전환 | 0.1.14 | `scripts/generate_in_scope_files.py`, `references/repository-wide-scan.md` |
| tracking 선택을 Codex 승인으로 이관 | 0.1.14 | `skills/track-findings/SKILL.md:58` |
| false-positive 피드백 | 0.1.15 | v15 `finding_decisions`, `scripts/workbench_feedback.py` |
| 스캔 lifecycle/model 메타데이터 영속화 | 0.1.15 | v25 |
| 토큰 사용량 측정 | 0.1.16 | v24 `scans.cost_json`, `scripts/workbench_scan_usage.py` |
| Deep 워커 런타임 자체 관리 | 0.1.16 | `scripts/deep_scan_config.py`, v11 `deep_scan_runs` |
| writeup/hardening 필수 → 선택 | 0.1.16 | `skills/security-scan/SKILL.md:39` |
| 스캔 중 guidance 갱신 | 0.1.16 | `update_codex_security_scan_context` |
| 실행 중 target 변경 시 실패 | 0.1.16 | v26 `scans.completion_warnings_json` |
| 엔터프라이즈 프록시/인증서 지원 | 0.1.16 | `.mcp.json` env 화이트리스트 |
| 라이브 진행 뷰 | 0.1.17 | v20 phase별 진행률, v21 preflight 상태 |
| 중단된 deep scan 재개 | 0.1.17 | v27 연속 오류, v11 워커 소유권 |
| **임베디드 위젯 은퇴** | 0.1.17 | `mcp-app.html.br` 부재 |
| 완료 스캔 요약 재사용 | 0.1.17 | `get_codex_security_completed_scan` |

## 2. App/MCP UI 계층 — 3단계 전환

0.1.11 문서에서 가장 분량이 큰 영역(§16.3, §17, §6.1 시퀀스)이 재배치됐다. **기능이 삭제된 것이 아니라 전달 경로가 바뀌었다**는 점이 중요하다.

### 2.1 전환 경과

| 단계 | 버전 | 내용 |
|---|---|---|
| 1 | 0.1.12 | 네이티브 setup flow 도입. 위젯을 열지 않고 스캔 시작 가능 |
| 2 | 0.1.14 | findings workspace의 이슈 생성 권한을 Codex 승인 흐름으로 이관 |
| 3 | 0.1.17 | 임베디드 위젯 최종 은퇴 |

### 2.2 0.1.17 코드 상태

`mcp/mcp-app.html.br` 파일이 존재하지 않는다. 압축 해제한 MCP 런타임(1.47 MB) 전수 검색 결과 다음 토큰이 **모두 0건**이다.

```text
mcp-app  skybridge  text/html  widget  clipboard  sendMessage
```

### 2.3 0.1.11 문서에서 무효가 된 서술

| 위치 | 서술 | 현재 상태 |
|---|---|---|
| §16.3 | App 전용 도구 21개 | 해당 tool surface 없음 |
| §17 | Findings UI 기능 목록 | 기능은 유지, 네이티브 워크플로로 이동 |
| §6.1 | `sendMessage` continuation 3종 | 코드에 `sendMessage` 없음 |
| §1 | App = continuation producer | 해당 브리지 없음 |
| §22-14 | "App은 수동 UI가 아니다" | 전제 소멸 |
| §16.1 | UI CSP / clipboard capability | 대상 없음 |

### 2.4 대체 경로

스캔 시작이 세 개의 명시적 도구로 분리됐다.

```text
start_codex_security_standard_scan
start_codex_security_deep_scan
start_codex_security_prompt_only_scan
```

마이그레이션 v18 `clear legacy delivered handoff claims`와 v19 `persist setup workspace preference`가 이 전환의 정리 흔적이다.

**이식 시 판단.** 0.1.11 문서 §17의 기능 목록(필터/정렬, 증거 열람, export, triage open/close, remediation 요청)은 여전히 유효한 요구사항이다. 무효가 된 것은 그 기능을 **임베디드 HTML 위젯으로 제공한다**는 전제뿐이다.

## 3. Deep scan 재설계

0.1.11 문서 §11 전체가 재작성 대상이다.

| 항목 | 0.1.11 문서 | 0.1.17 코드 |
|---|---|---|
| worker 수 | 6개 고정 | `min(parallelism/2, 6)` auto, 설정 가능 |
| round 상한 | 10 round | `max_discovery_runs=60` |
| 종료 조건 | 첫 zero-novelty round | `stop_after_no_new=6` |
| 연속 오류 처리 | 서술 없음 | `stop_after_consecutive_errors=3` |
| per-worker 위임 | 서술 없음 | `subagents=3` |
| 주도권 | skill orchestration | MCP 도구 `start_codex_security_deep_scan` |
| 상태 저장 | 파일시스템 | DB `deep_scan_runs` / `_workers` / `_dedup_inputs` |
| 사용자 설정 | 없음 | `$CODEX_HOME/codex-security/config.toml [deep_scan]` |
| 워커 아티팩트 경로 | `artifacts/deep_discovery/round-NN/worker-NN/` | 해당 규약 없음 |
| merge bookkeeping | `artifacts/deep_merge/` | 해당 규약 없음 |

근거: `scripts/deep_scan_config.py`

```python
DEFAULT_SUBAGENTS = 3
DEFAULT_STOP_AFTER_NO_NEW = 6
DEFAULT_STOP_AFTER_CONSECUTIVE_ERRORS = 3
DEFAULT_MAX_DISCOVERY_RUNS = 60
MAX_AUTOMATIC_WORKERS = 6
```

### 3.1 phase 소유권 경계

0.1.17에서 Deep MCP와 부모 스레드의 책임이 명시적으로 분리됐다. `skills/deep-security-scan/SKILL.md`:

> Deep MCP owns independent discovery workers and semantic reduction only. Deep MCP does not run centralized validation, attack-path analysis, canonical JSON assembly, completion, or generated reporting.

부모가 discovery 종료 후 수행하는 순서는 다음과 같다.

1. terminal discovery manifest 수령
2. canonical validation threat model 합성
3. `$codex-security:validation` 1회 (compact standard-scan mode)
4. `$codex-security:attack-path-analysis` 1회
5. `record_codex_security_scan_draft`
6. `complete_codex_security_scan`

**주의.** discovery가 반환하는 `manifestPath`는 discovery 증거이지 최종 `scan-manifest.json`이 아니다. SKILL.md가 이 혼동을 명시적으로 경고한다.

0.1.11 문서 §11.1의 "themed lane으로 분할하지 않는다", "worker는 이전 round의 semantic 결과를 보지 않는다", merge의 remediation-subsumption 원칙은 **유지된다.**

## 4. Capability preflight 완화

0.1.11 문서 §8의 프로파일 표가 무효다.

| Profile | 0.1.11 문서 Block | 0.1.17 Block | 0.1.17 Warn | 0.1.17 Suggest |
|---|---|---|---|---|
| Standard | 없음 | 없음 | delegation, slot 6 | goal_tools, goals |
| Diff | 없음 | 없음 | delegation | goal_tools, goals |
| Deep | **4개** | **0개** | 없음 | goal_tools, goals |

0.1.11 문서가 Deep의 blocking으로 기술한 4개(phase skill 부재, delegation 부재, slot 6 미만, V1 depth 2 미만)가 `preflight/capability-profiles.toml`에서 **전부 사라졌다.** 0.1.17 Deep 요구사항은 `suggest` 2개뿐이다.

원인은 0.1.16의 워커 런타임 변경이다. `skills/deep-security-scan/SKILL.md`:

> The discovery tool manages its own workers independently of this thread's delegation runtime and subagent allowance.

이에 따라 0.1.11 문서 §11의 다음 논증이 **전제째로 무효**가 된다.

> V1에서 orchestration depth 2가 blocking requirement인 이유는 discovery worker가 exhaustive file review를 위해 다시 nested delegation을 사용할 수 있어야 하기 때문이다.

한편 0.1.11 changelog가 *"Check deep-scan phase skills, delegated workers, and worker capacity before a deep scan starts"* 를 0.1.11 신규 기능으로 명시하므로, **0.1.11 문서의 서술은 당시 정확했다.** 버전 드리프트이지 문서 오류가 아니다.

### 4.1 유지되는 부분

`blocked` / `incomplete` / `ready` 3-값 판정, 판정 불가 시 성공 추정 금지, interactive 승인 대 non-interactive 1회 적용, `kind = "host_setting"`의 자동 적용 금지, transport별 non-ready recovery 분기는 **변경 없다.**

## 5. Severity matrix 완화

0.1.11 문서 §12.1의 matrix에서 **5개 셀이 `ignore` → `low`로 상향**됐다. 실무 영향이 가장 직접적인 변경이다.

| impact × likelihood | 0.1.11 문서 | 0.1.17 |
|---|---|---|
| high × low | `ignore` | **`low`** |
| medium × low | `ignore` | **`low`** |
| low × high | `ignore` | **`low`** |
| low × medium | `ignore` | **`low`** |
| low × low | `ignore` | **`low`** |

0.1.17 전체 matrix (`skills/attack-path-analysis/references/severity-policy.md:117-143`):

| impact \ likelihood | high | medium | low | ignore | unknown |
|---|---|---|---|---|---|
| high | `critical` 조건 충족 시 `critical`, 아니면 `high` | `medium` | `low` | `ignore` | `medium` |
| medium | `medium` | `low` | `low` | `ignore` | `low` |
| low | `low` | `low` | `low` | `ignore` | `low` |
| ignore | `ignore` | `ignore` | `ignore` | `ignore` | `ignore` |
| unknown | `medium` | `low` | `low` | `ignore` | `low` |

신설 규칙 (`:94`):

> Do not discard an otherwise reportable finding solely because its impact or likelihood is `low`; downgrade its severity instead.

0.1.13이 추가한 억제 금지 규칙 (`:111`):

> Do not suppress solely because the surface is private or internal when repository evidence still shows a meaningful authorization, trust-boundary, identity, or security-control regression.

`ignore`는 이제 impact 또는 likelihood가 **명시적으로 `ignore`** 일 때만 발생한다. hard suppression 목록(self-only, 달성 불가 precondition, privileged/operator/developer/physical-access-only)과 `critical` 유지 조건, **P0–P3 priority 매핑은 변경 없다.**

> **결과:** 동일 코드베이스에서 0.1.17이 0.1.11보다 더 많은 finding을 보고한다. 기존 baseline과 비교할 때 이 차이를 회귀로 오인하지 않아야 한다.

## 6. 스키마 마이그레이션 v11–v27

v1–v10은 0.1.11 문서 §4.2의 표와 **완전히 일치하며 원형 보존**된다. 이후 17개가 append-only로 추가됐다.

| 버전 | 설명 | 추가 구조 |
|---|---|---|
| 11 | deep scan orchestration state | `deep_scan_runs`, `deep_scan_workers`, `deep_scan_dedup_inputs`, `scans.deep_scan_owner_thread_id` |
| 12 | scan continuation threads | `scans.continuation_thread_id` |
| 13 | scan scope file counts | `scan_progress.scope_file_count` |
| 14 | imported triage results | `triage_results` |
| 15 | append-only finding decisions | `finding_decisions` |
| 16 | stable repository targets | `security_targets`, `workspaces.target_id`, `scans.target_id` |
| 17 | scan target summaries | `scans.target_summary` |
| 18 | clear legacy delivered handoff claims | — |
| 19 | persist setup workspace preference | `setup_preferences` |
| 20 | phase-specific scan progress | `scan_progress.phase_items_total/_completed/_progress_unit` |
| 21 | current scan preflight state | `scan_progress.preflight_issues_json/_checks_total/_checks_completed` |
| 22 | replayable scan launch recipes | `scans.recipe_json`, `scans.parent_scan_id` |
| 23 | semantic scan comparison matches | `scan_comparisons`, `scan_comparison_matches` |
| 24 | persist scan cost estimates | `scans.cost_json` |
| 25 | persist scan model settings | `scans.model`, `scans.reasoning_effort` |
| 26 | persist scan completion warnings | `scans.completion_warnings_json` |
| 27 | deep scan consecutive discovery failures | `deep_scan_runs.stop_after_consecutive_errors/.consecutive_errors` |

기능군으로 묶으면 다음과 같다.

- **Deep 오케스트레이션:** v11, v27
- **관측성:** v13, v20, v21, v24, v26
- **재현성/계보:** v22, v25
- **교차 스캔 분석:** v15, v16, v23
- **triage 확장:** v14
- **레거시 정리:** v18, v19

`scan_progress`에 phase별 진행률이 들어오면서 0.1.11 문서 §7.2의 "한 pass 안에서 total/completed monotonic" 모델이 phase 단위로 세분화됐다. `PHASE_PROGRESS_UNITS`(`workbench_constants.py`)가 신설됐다.

```python
PHASE_PROGRESS_UNITS = (
    "checks", "threat_surfaces", "review_receipts",
    "candidate_findings", "validated_findings", "report_artifacts",
)
```

## 7. 아티팩트 전달: 구조화 도구 호출 병행

0.1.17에 `schemas/tools/` 7종과 대응 `record_*` 도구가 신설됐다. 워커 산출물이 파일시스템 JSONL 대신 스키마 검증된 도구 호출로 전달되는 경로가 추가됐다.

| 스키마 | 도구 |
|---|---|
| `worker-threat-model.schema.json` | `record_codex_security_worker_threat_model` |
| `discovery-candidates.schema.json` | `record_codex_security_discovery_candidates` |
| `candidate-validations.schema.json` | `record_codex_security_candidate_validations` |
| `candidate-attack-paths.schema.json` | `record_codex_security_candidate_attack_paths` |
| `deep-reducer.schema.json` | `record_codex_security_deep_reduction` |
| `scan-draft.schema.json` | `record_codex_security_scan_draft` |
| `review-items.schema.json` | `list_codex_security_review_items` |

**완전 대체가 아니라 병행이다.** JSONL 파이프라인(`rank_input`, `deep_review_input.jsonl`)은 Standard/Diff 경로에 잔존하며 `scripts/generate_rank_input.py`도 유지된다. 아티팩트 디렉터리 규약 `01_context` ~ `05_findings`도 그대로다.

## 8. Standard scan 파이프라인 단순화

0.1.14가 Standard/scoped scan을 단순화했다.

> Use one deterministic in-scope file list and a compact candidate ledger for standard repository and scoped-path scans. Preserve the existing manifest, findings, coverage, report, and SARIF outputs while reducing repeated scan stages.

신규 스크립트 `scripts/generate_in_scope_files.py`가 그 산물이다. 0.1.15가 *"Keep standard-scan discovery adaptive to the repository and candidate list"* 와 *"remove the legacy fan-out prompt"* 로 이어졌다.

### 8.1 §9.1 high-impact coverage frontier는 제거됐다

0.1.11 문서 §9.1이 기술한 **high-impact boundary × vulnerability family ledger가 0.1.17에 존재하지 않는다.**

- `skills/security-scan/references/`에 남은 파일은 `repository-wide-scan.md`(60줄)와 `scan-artifacts-and-ledger.md` 둘뿐이다.
- 0.1.11 문서 §23.1이 §9.1의 근거로 인용한 `repo-wide-artifacts-and-ledger.md`는 **파일 자체가 없다.**
- 두 파일 전체에서 `high-impact` 문자열이 **0건**이다. `frontier`는 advisory seed pass 서술에 1회 등장할 뿐 ledger 계약과 무관하다.

대체된 모델은 훨씬 단순하다. `repository-wide-scan.md`:

> Review every file, record the complete candidate set once, then validate and check reachability in two compact passes over those candidates.
>
> Because every file is reviewed, do not create ranking or deep-review worklists.

즉 **ranked worklist + boundary×family ledger** 구조가 **전수 파일 리뷰 + 2-pass 압축 검증**으로 대체됐다. 파일 목록은 `prepare_codex_security_review_items` / `list_codex_security_review_items` 도구가 커서 페이지네이션으로 제공한다. 0.1.11 문서 §9.1의 shard 분해, sibling 확장 우선순위, secondary review 순서 규칙은 **이식 기준으로 사용할 수 없다.**

0.1.11 문서 §9의 "Ranking worker 최대 6개", §9.2의 "immutable ranking pool plan / plan digest"도 같은 이유로 무효다.

### 8.2 writeup / hardening은 Standard에서도 선택적

0.1.16 changelog는 change/deep scan만 언급했으나, 코드는 **Standard를 포함해 전면 선택적**임을 보인다. `skills/security-scan/SKILL.md:39`:

> The finalizer generates `report.md` and SARIF. Do not edit either by hand. Detailed write-ups and hardening plans are optional.

0.1.11 문서 §9(11–12단계)와 §8.1이 "reportable finding마다 전담 writeup worker + 전체 finding set에 hardening 1회"를 **필수 파이프라인 단계**로 기술한 것은 무효다. `vulnerability-writeup`과 `propose-security-hardening`은 0.1.11 문서 §12.2가 이미 기술한 대로 **독립 워크플로**로만 남는다.

## 9. 기타 변경

| 항목 | 0.1.11 문서 | 0.1.17 |
|---|---|---|
| MCP tool timeout | `tool_timeout_sec: 900` (15분) | **86400** (24시간) |
| 스킬 수 | 12 | **13** (`define-security-policy` 추가) |
| plugin homepage | `learn.chatgpt.com` | `developers.openai.com/codex/security` |
| plugin version | `0.1.11` | `0.1.17` |
| 내부 App 컴포넌트 버전 | `0.1.63` 관찰 | 해당 없음 |

### 9.1 신규 스크립트

0.1.11 문서 §23.1의 근거 파일 목록에 없던 9개다.

| 파일 | 책임 |
|---|---|
| `deep_scan_workbench.py` | Deep scan 오케스트레이션 상태 영속화 |
| `workbench_scan_history.py` | 네이티브 workbench용 스캔 이력 projection |
| `workbench_scan_usage.py` | live thread graph에서 scan-owned 토큰 사용량 측정 |
| `workbench_progress.py` | progress 전이 helper |
| `workbench_native_indexes.py` | read-only findings/repository index |
| `windows_scan_local_files.py` | Windows 전용 scan-local 파일 연산 |
| `workbench_source_excerpt.py` | sealed Git revision에서 bounded source 발췌 |
| `workbench_feedback.py` | false-positive 피드백 로드 |
| `finding_preview.py` | 목록 응답용 finding 상세 bounding |

### 9.2 엔터프라이즈 네트워크 지원

0.1.16이 프록시/인증서 환경을 공식 지원한다. `.mcp.json`의 `env_vars` 화이트리스트에 다음이 포함된다.

```text
HTTP_PROXY  HTTPS_PROXY  ALL_PROXY  NO_PROXY
SSL_CERT_FILE  REQUESTS_CA_BUNDLE  NODE_EXTRA_CA_CERTS
```

사내 TLS 인터셉션 환경에서 별도 우회 없이 동작한다.

## 10. 변경 없음 — 이식 시 안전 영역

다음은 0.1.17 코드에서 0.1.11 문서 서술과 일치함을 **직접 확인**했다.

| 영역 | 근거 |
|---|---|
| DB 경로 결정 순서 | `workbench_db.py:151-159` |
| WAL / foreign_keys / busy_timeout 5000 / `0600` | `workbench_db.py:233-237` |
| 마이그레이션 v1–v10 순서·설명 | `workbench_schema.py` |
| phase 6단계 순서 | `workbench_constants.py:7` |
| status enum `running/complete/failed` + `canceled_at` | `workbench_schema.py:48` |
| claim lease 120초 / delivered action lease 900초 | `workbench_constants.py:39-40` |
| fingerprint material 구성 | `finalize_scan_contract.py:690` |
| `findingId` / `occurrenceId` 파생 | `finalize_scan_contract.py:731-732` |
| finalizer 기록 순서 (findings→coverage→report→manifest) | `finalize_scan_contract.py:2424-2428` |
| `sealedAt == completedAt` 강제 | `finalize_scan_contract.py:1984-1985` |
| manifest target kind 4종 | `schemas/scan-manifest.schema.json` |
| coverage mode 7종 / completeness 3종 | `schemas/coverage.schema.json` |
| patch 2 MiB / subprocess buffer 4 MiB | `workbench_constants.py`, MCP 런타임 |
| tracking 25건 batch / advisory 단건 | `skills/track-findings/SKILL.md:58` |
| triage 250건 상한 | `skills/triage-finding/references/ticket-intake.md:37` |
| 아티팩트 디렉터리 `01_context`~`05_findings` | `references/scan-artifacts.md:16-20` |
| `execFile` 사용, shell 미경유 | MCP 런타임 |
| P0–P3 priority 매핑 | `severity-policy.md:146-149` |

0.1.11 문서 **§14(canonical/derived artifact)와 §15(finalization/sealing)는 변경이 확인되지 않았다.** §12.1은 matrix 셀 5개만 갱신하면 유효하다.

## 11. 0.1.11 문서 섹션별 처리 지침

| 섹션 | 판정 | 조치 |
|---|---|---|
| §1 전체 구성 | 부분 무효 | App branch의 `sendMessage` continuation 제거 |
| §2 Authority 모델 | 부분 무효 | App 전용 행의 전달 경로 재서술 |
| §3 workspace 의미 | 유효 | — |
| §4 Workbench 저장 구조 | 확장 | v11–v27 추가 (§6 참조) |
| §5 Target 모델 | 유효 | — |
| §6 Setup→Agent 실행 | 부분 무효 | §6.1 시퀀스 재작성 |
| §7 lifecycle/progress | 확장 | phase별 진행률 반영 (§6 참조) |
| §8 Capability preflight | **무효** | 프로파일 표 재작성 (§4 참조) |
| §9 Standard scan | **무효** | §9.1 제거됨, 전수 리뷰 모델로 대체 (§8.1) |
| §10 Diff scan | 유효 | 보고서 생성 조건만 완화 |
| §11 Deep scan | **무효** | 전면 재작성 (§3 참조) |
| §12 Phase semantic 계약 | 부분 무효 | §12.1 matrix 5개 셀 교체 |
| §13 `SECURITY.md` 계층 | 유효 | `define-security-policy` 스킬 추가 언급 |
| §14 Artifact 구조 | **유효** | 구조화 도구 병행 경로만 추가 |
| §15 Finalization/sealing | **유효** | — |
| §16 MCP/App 인터페이스 | **무효** | tool surface 재작성 |
| §17 Findings UI | 부분 무효 | 기능 유지, 전달 경로 재서술 |
| §18 보안 경계 | 부분 무효 | App-only tool 경계 서술 재검토 |
| §19 동시성/실패/복구 | 확장 | deep scan 재개 반영 |
| §20 두 실행 경로 | 부분 무효 | App 경로 정의 갱신 |
| §21 검증 체크리스트 | 부분 무효 | 1·2·8·10·13·17 항목 재정의 |
| §22 자주 혼동되는 사항 | 부분 무효 | 11·12·14 무효, 9 갱신 |

**이식 우선순위:** §16·§17(전달 경로) → §11·§9·§8(전제 무효) → §12.1(셀 교체) → §14·§15(유지)

## 12. 근거 자료

### 12.1 0.1.17 설치 패키지

```text
$CODEX_HOME/plugins/cache/openai-curated-remote/codex-security/0.1.17/
```

- `.codex-plugin/plugin.json` — version, homepage, skill/app/mcp 선언
- `.mcp.json` — `tool_timeout_sec`, env 화이트리스트
- `scripts/workbench_schema.py` — 마이그레이션 v1–v27
- `scripts/workbench_constants.py` — lease, phase, progress unit, 크기 상한
- `scripts/workbench_db.py` — DB 경로, PRAGMA, 권한
- `scripts/deep_scan_config.py` — Deep 워커/종료 조건 설정
- `scripts/finalize_scan_contract.py` — fingerprint, 기록 순서, seal
- `preflight/capability-profiles.toml` — 프로파일 requirement
- `skills/deep-security-scan/SKILL.md` — phase 소유권 경계
- `skills/security-scan/SKILL.md` — writeup/hardening 선택성
- `skills/security-scan/references/repository-wide-scan.md` — 전수 리뷰 모델
- `skills/security-scan/references/scan-artifacts-and-ledger.md` — subagent handoff, candidate coverage
- `skills/attack-path-analysis/references/severity-policy.md` — severity matrix
- `skills/track-findings/SKILL.md`, `skills/triage-finding/references/ticket-intake.md` — 상한
- `references/scan-artifacts.md` — 아티팩트 경로
- `schemas/`, `schemas/tools/`, `schemas/definitions/` — canonical/도구 스키마
- `mcp/server.mjs` + `server.mjs.br.part-*` — 압축 MCP 런타임 (brotli 해제 후 인터페이스 분석)

### 12.2 OpenAI 공식 자료

- [Codex Security plugin changelog](https://developers.openai.com/codex/security/plugin/changelog) — 0.1.7 ~ 0.1.17 릴리스 노트. 버전별 귀속의 1차 근거
- [Codex Security plugin quickstart](https://developers.openai.com/codex/security/plugin)

### 12.3 저장소 내 관련 문서

- `docs/codex-security-plugin-0.1.11-architecture.md` — 기준선
- `docs/codex-security-0.1.11-rebuild-plan.md` — Kiro 구현 계약

## 13. 재검증이 필요한 항목

이 델타에서 코드로 확정하지 못한 것들이다. 이식 판단에 필요해지면 우선 확인한다.

1. **`triage_results`(v14)와 standalone triage 계약의 관계.** 0.1.11 문서 §12.2의 `triage-finding/v0` 계약이 DB 영속화와 어떻게 결합하는지.
2. **`scan_comparisons`(v23)의 매칭 알고리즘.** fingerprint 기반인지 별도 semantic 매칭인지.
3. **`prepare_codex_security_review_items`의 인벤토리 규칙.** 전수 리뷰 모델에서 in-scope 판정과 binary/generated 파일 처리 기준.
4. **Diff scan의 changed-source 인벤토리.** 0.1.11 문서 §10이 기술한 `rank_input`/`deep_review_input` 고정 방식이 전수 리뷰 전환의 영향을 받았는지.
5. **0.1.12~0.1.16 중간 버전의 실제 패키지.** 이 델타는 0.1.11 → 0.1.17 양 끝점 비교이며, 중간 버전에서 도입 후 철회된 변경은 포착하지 못한다.

## 14. 분석 한계

- 0.1.11 패키지가 없어 패키지 대 패키지 diff를 수행하지 못했다. 0.1.11 측 근거는 0.1.11 문서의 서술이다.
- "변경 없음" 판정은 0.1.11 문서가 기술한 범위 안에서의 판정이다. 문서가 다루지 않은 0.1.11 동작의 변경은 포착되지 않는다.
- 압축된 MCP 런타임은 인터페이스와 토큰 존재 여부를 분석했으며 source reproduction이나 formal verification이 아니다.
- OpenAI가 같은 version label로 재배포하면 재검증이 필요하다.
- 문서상 차이 정리만으로는 Kiro 구현의 부합성이 증명되지 않는다. 각 authority, transaction, failure invariant에 대한 별도 테스트가 필요하다.
