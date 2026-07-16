# 작업 지시: WS-A — Coverage & Finalization Correctness

## 0. 당신에게 (에이전트)

당신은 이 저장소(`kiro-security-power`)의 초안을 작성한 시니어 엔지니어다. 코드 구조는 이미 알고 있다. 이 지시는 초안의 **가장 위험한 정확성 결함(false assurance)**을 닫는 작업이며, Codex Security 참조 구현과의 완전 이관 로드맵(`docs/codex-parity-migration-plan.md`)에서 **P0 마일스톤 M1의 핵심 워크스트림 WS-A**에 해당한다.

이 작업의 최우선 가치는 기능 추가가 아니라 **정직성**이다. 사용자에게 "검토했고 안전하다"는 잘못된 확신을 주는 현재 동작을 제거하고, "검토함 vs 검토 안 함"을 감사 가능한 receipt로 엄격히 구분하는 것이 목표다.

착수 전 다음을 정독하라: `DESIGN.md`(§4.4, §7, §17), `docs/codex-parity-migration-plan.md`(§3 WS-A), `engine/schemas/*.json`.

---

## 1. 목표 (Definition of Done)

아래가 모두 참일 때 WS-A는 완료된다.

1. Coverage가 finding category 집계가 아니라 **worklist row 단위 disposition receipt**로 생성된다.
2. `completeness = complete`는 **모든 in-scope row가 명시적으로 닫힌 경우에만** 산출된다.
3. Deep의 `capped`, 미지원 in-scope 파일, 0-file 상태가 coverage에 정확히 반영된다.
4. `manifest.json / findings.json / coverage.json`이 **strict schema로 검증된 뒤 seal**되고, `report.md`·`hardening.md`는 canonical JSON에서 파생되는 **projection**이며 seal 대상에서 제외된다.
5. manifest의 `status`가 실제 scan 완료 상태와 일치한다(선기록 금지).
6. 위 동작이 신규 테스트로 검증되고 `python3 -m pytest`, `npm run verify`가 green이다.

---

## 2. 스코프 경계

### 이 작업에 포함 (In scope)
- `engine/kiro_security/reporting.py` — coverage 생성 및 finalization 흐름 전면 개편
- 신규 `engine/kiro_security/finalizer.py`(권장) — strict 검증 + seal + projection
- `engine/kiro_security/deep.py` — worker/merge가 **row-level disposition receipt**를 저장하도록 확장 (데이터 모델 + 저장까지. worker 독립성/barrier 강화는 WS-B 소관이니 건드리지 말 것)
- `engine/schemas/coverage.schema.json`, `engine/schemas/scan-manifest.schema.json` — strict 조건 추가
- `engine/migrations/00X_*.sql` — coverage ledger 테이블/컬럼 신규 마이그레이션
- `engine/kiro_security/db.py` — ledger 저장/조회 메서드
- 신규 테스트: `engine/tests/test_coverage.py`, `engine/tests/test_finalizer.py`

### 이 작업에서 제외 (Out of scope — 인터페이스만 맞추고 넘기지 말 것)
- 모델 기반 validation / attack-path / writeup / hardening 품질 개선 (WS-C)
- Deep worker 동질성/claim barrier/host capability (WS-B)
- Standard/Diff를 모델 workflow로 전환 (WS-E)
- finding identity fingerprint 교체 (WS-F) — 단, coverage receipt가 candidate/finding을 참조할 때 **현재 ID 체계를 그대로 사용**하고, F 작업 후 교체 가능하도록 참조를 한 곳에 격리하라.

---

## 3. 현재 상태 (검증된 사실 — 반드시 이 코드 기준으로 작업)

### 3.1 Coverage가 finding category에서 파생됨 — `reporting.py:build_coverage_document`
```python
categories = Counter(item["taxonomy"]["category"] for item in findings)
surfaces = [ ... "disposition": "reported" if count else "no_issue_found",
             "receiptRefs": [item["occurrenceId"] ...] ... ]
if not surfaces:
    surfaces = [{"id": "surface_source_review", ... "disposition": "no_issue_found", "receiptRefs": []}]
...
"completeness": "partial" if inventory_data.get("deferred") else "complete",
```
문제:
- finding이 없으면 검토 깊이와 무관하게 generic surface 하나가 `no_issue_found`가 된다.
- SQL injection 같은 표면에 finding이 없으면 그 표면 row 자체가 생성되지 않는다 → "미분석"이 "무취약"으로 사라진다.
- `receiptRefs`는 occurrence ID일 뿐 실제 receipt가 아니다.
- `completeness`는 `deferred` 유무만 본다. **Deep `capped` 상태, 미지원 in-scope 파일, 0-file을 전혀 반영하지 않는다.**

### 3.2 Producer가 report를 직접 쓰고, manifest에 completed를 선기록 — `reporting.py:write_reporting_bundle`
- `_write_writeups`, `_markdown_report`가 producer 단계에서 직접 파일을 쓴다.
- `report.md`, `hardening.md`가 `records`(→ manifest `artifacts`)에 포함되어 seal 대상에 들어간다.
- manifest를 `"status": "completed"`, `sealedAt = completed_at`로 **하드코딩**한다. 이 시점에 scan DB는 아직 `complete_scan()` 호출 전이다(호출부는 `runner.py:_run`이 `_phase_reporting` 이후 `complete_scan`을 부른다).
- canonical JSON을 seal 전에 schema로 검증하는 단계가 **없다**.
- Deep scan이어도 manifest scope에 `"validationMode": "deterministic-static-trace"`가 무조건 박힌다.

### 3.3 Deep에는 row-level receipt가 없음 — `deep.py`
- worklist row는 `{rowId, path, language, size}` 뿐.
- worker 제출(`submit_worker`)은 `reviewedPaths`(경로 집합)가 worklist 경로 집합과 같은지만 검사한다. per-row disposition/근거/receipt가 없다.
- `deep_scan_state.status`가 `saturated`/`capped`가 될 수 있으나, reporting은 이 상태를 읽지 않는다.

### 3.4 스키마가 permissive함
- `coverage.schema.json`: `surfaces[].additionalProperties: true`, disposition enum에 receipt 강제 없음, `completeness` enum은 있으나 complete일 때 closure를 요구하는 conditional이 없음.
- `scan-manifest.schema.json`: `status` const `"completed"` 고정, seal 시점 검증 로직은 코드에 없음.

---

## 4. 구현 요구사항

### A1. Row-level coverage ledger 데이터 모델

**신규 마이그레이션**(`engine/migrations/`의 다음 번호, 현재 최신은 `007_deep_orchestration.sql`)으로 coverage ledger 테이블을 추가한다.

권장 스키마(컬럼명은 조정 가능하되 의미 보존):
```sql
CREATE TABLE coverage_ledger (
    id           TEXT PRIMARY KEY,
    scan_id      TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    row_id       TEXT NOT NULL,           -- worklist rowId 또는 inventory 파생 id
    path         TEXT NOT NULL,
    surface      TEXT,                    -- 보안 표면 분류
    entrypoint   TEXT,
    root_control TEXT,
    sink         TEXT,
    disposition  TEXT NOT NULL,           -- reportable|suppressed|not_applicable|deferred
    reason       TEXT NOT NULL,           -- disposition 근거 (필수)
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    candidate_ids_json TEXT NOT NULL DEFAULT '[]',
    worker_id    TEXT,
    receipt_digest TEXT NOT NULL,         -- 이 row receipt의 안정적 digest
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    UNIQUE(scan_id, row_id)
);
```
- 마이그레이션은 기존 규칙을 따른다: 앞뒤 backup, 트랜잭션, foreign key, WAL 유지. `db.py`의 마이그레이션 러너/스키마 버전 상승 로직에 맞춰 추가하라.
- `db.py`에 `upsert_coverage_row(...)`, `list_coverage_rows(scan_id)` 등 parameterized 메서드 추가.

`disposition`은 정확히 다음 4개만 허용:
```
reportable | suppressed | not_applicable | deferred
```
`reviewedPaths`(단순 경로 배열)에 의존하는 완결 판정은 **폐기**한다.

### A2. `complete`는 모든 row가 닫힌 경우에만

`build_coverage_document`를 ledger 기반으로 재작성:
- `surfaces`는 category 집계가 아니라 ledger row(또는 표면별 집계)에서 생성. finding이 0이어도 실제 검토된 표면은 `no_issue_found`/`not_applicable`로 남고, **검토 안 된 표면은 표시되거나 completeness를 낮춘다**.
- `receiptRefs`는 `receipt_digest`(또는 ledger row id)를 참조. occurrence ID 직접 사용 금지.
- completeness 판정 규칙:
  - 모든 in-scope row가 4개 disposition 중 하나로 닫힘 → `complete`
  - 닫히지 않은 in-scope row 존재, 또는 `deferred` 존재 → `partial`
  - 아래 A3 조건 → `unknown`/`partial(capped)`

### A3. Deep cap / 미지원 / 0-file 반영

- Deep scan이면 `deep_scan_state.status`를 읽어라:
  - `capped` → `completeness = "partial"` 이고 `openQuestions` 또는 신규 필드에 `"capped"` 사유 명시. **절대 `complete` 금지.**
- 미지원 in-scope 파일(확장자 allowlist 밖이지만 scope 안): `deferred` 또는 `explicitExclusions`에 명시적으로 기록. 조용히 사라지면 안 됨.
- 0 supported files:
  - Deep은 이미 `deep_no_supported_files`로 실패함(유지).
  - **Standard/Diff는 현재 `complete`가 될 수 있다 → `completeness = "unknown"`(또는 scan을 `blocked`)로 바꿔라.** 0-file인데 complete는 금지.

### A4. `receiptRefs`를 실제 receipt로 교체
- A1의 `receipt_digest`를 참조. receipt_digest는 `{rowId, disposition, reason, evidenceRefs, candidateIds}`의 안정적 sha256로 계산(정렬된 JSON 기준). 이미 `security.py`에 sha256 헬퍼가 있으니 재사용.

### A5. Strict canonical finalizer

신규 `engine/kiro_security/finalizer.py`를 만들고 finalization 책임을 `reporting.py`에서 분리한다.

흐름:
```
1. reporting: coverage.json / findings.json / discovery.json / validation.json / attack-path.json 생성 (canonical JSON)
2. finalizer: coverage.json + findings.json + scan-manifest(초안)을 strict schema로 검증
   - 검증 실패 시 EngineError로 명확히 실패 (seal 금지, 부분 상태 보존)
3. finalizer: 검증 통과분만 seal
   - manifest에 각 canonical artifact의 sha256 기록
   - manifest 자체 digest를 workbench에 저장 (기존 save_manifest_digest 활용)
4. finalizer: report.md / hardening.md를 canonical JSON에서 projection으로 생성
   - 이들은 seal 대상(manifest.artifacts의 무결성 seal)에 포함하지 않거나, "derived" 로 명확히 구분
```
- `report.md`를 producer가 직접 쓰지 않도록 `_markdown_report` 호출 위치를 finalizer의 projection 단계로 이동.
- schema 검증기: 외부 의존성 추가 금지(현재 `dependencies`는 `jsonc-parser`뿐, 엔진은 표준 라이브러리 지향). Python 표준 라이브러리로 구현 가능한 경량 검증기를 작성하거나, 이미 존재하는 검증 유틸이 있으면 재사용하라. `jsonschema` 패키지 추가가 필요하다고 판단되면, 추가 대신 필요한 assertion을 명시적 코드로 구현하는 것을 우선하라(엔진의 dependency-light 원칙, `mcp_server.py` 주석 참조).

### A6. manifest 상태 정합성

- manifest의 `scan.status`는 실제 완료 시점 상태를 반영해야 한다. 현재처럼 reporting 단계에서 `"completed"`를 선기록하지 말 것.
- 옵션(택1, 근거와 함께 결정):
  - (a) finalizer를 `complete_scan()` **이후**에 호출하여 실제 상태를 읽어 기록, 또는
  - (b) manifest 작성을 finalize 단계로 미루고 `runner.py`의 phase 흐름을 조정.
- `sealedAt`은 실제 seal 시각. `validationMode`는 mode/실제 검증 방식에 따라 정직하게(예: Deep이 아직 deterministic tail이면 그렇게, WS-C 후 갱신). 하드코딩된 `"deterministic-static-trace"`를 상황과 무관하게 박지 말 것.

---

## 5. 스키마 변경 (`engine/schemas/`)

### coverage.schema.json
- `surfaces[].additionalProperties: false`로 강화하고 다음 required 추가: `disposition`, `reason`, `receiptDigest`.
- `disposition` enum을 ledger와 일치: `["reportable", "suppressed", "not_applicable", "deferred", "reported", "no_issue_found"]` — 표면(surface) 레벨과 row 레벨 용어를 정리하되, 최종적으로 **row disposition은 4개 canonical 값**으로 수렴시켜라. 표면 레벨 요약 disposition을 별도로 둘지 결정하고 문서화.
- `completeness = "complete"`일 때 닫히지 않은 row/`deferred`가 없어야 함을 표현하는 conditional(`if/then` 또는 별도 검증 코드)을 추가.

### scan-manifest.schema.json
- 현재 `status` const `"completed"` 유지 가능하나(완료 manifest만 seal한다면), finalizer가 seal 전 검증에서 이 const를 실제로 강제하도록 코드 연결.
- canonical artifact cardinality: `coverageRef`, `findingsRef`가 정확히 하나씩 존재하고 `artifacts`에 대응 항목이 있어야 함을 검증.

> 참조 Codex schema는 findings 359줄 / coverage 228줄 / manifest 332줄로 훨씬 엄격하다. 이번 작업은 WS-A 범위(coverage/finalization) 필드만 엄격화하고, 나머지 전면 강화는 WS-I로 남긴다. 과도하게 스코프를 넓히지 말 것.

---

## 6. 제약 (반드시 준수)

- **Python 3.9 호환** (`dataclass(slots=True)` 등 3.10+ 문법 금지 — CHANGELOG 0.2.0 참조).
- SQLite: parameterized query만, 명시적 트랜잭션, foreign key, WAL, busy timeout, **마이그레이션 전 backup** 유지.
- subprocess는 이 작업에 불필요하나, 쓰게 되면 shell 문자열 금지(executable+argv).
- 외부 네트워크 호출 금지, 신규 런타임 의존성 추가는 최후수단(위 A5 참조).
- 기존 IDE 경험 회귀 금지: `packages/extension`, `packages/webview`가 소비하는 coverage/manifest 필드를 깨지 말 것. 필드를 바꾸면 `packages/protocol/src/types.ts`와 Webview 소비부를 함께 갱신하고 `tests/`의 관련 테스트를 통과시켜라.
- 하위호환: 기존 artifact를 읽는 코드가 있으면 마이그레이션/기본값으로 안전하게 처리.
- 로그에 secret 노출 금지(기존 redaction 유지).

---

## 7. 테스트 (필수 — J2/J3)

신규 `engine/tests/test_coverage.py`, `engine/tests/test_finalizer.py`. 최소 케이스:

1. **0-file**: 지원 파일 0개 Standard/Diff → `completeness != "complete"` (`unknown` 또는 blocked). Deep은 `deep_no_supported_files` 유지.
2. **capped**: `deep_scan_state.status = "capped"` → coverage `partial`, capped 사유 존재, `complete` 절대 아님.
3. **deferred 존재**: 닫히지 않은 row 존재 → `partial`.
4. **all-clean**: 모든 in-scope row가 receipt로 닫히고 finding 0 → `complete`이며 각 표면이 receipt digest를 가짐. generic single-surface fallback이 아님.
5. **finalizer seal**: 유효 canonical JSON → seal 성공, manifest digest 저장, report.md는 projection으로 생성되고 seal artifact 목록의 무결성 대상과 구분됨.
6. **finalizer 검증 실패**: 필수 필드 누락된 findings.json → seal 거부, EngineError, 부분 상태 보존(scan이 조용히 completed 되지 않음).
7. **manifest 상태 정합성**: manifest `status`/`sealedAt`이 실제 완료 시점과 일치.
8. **회귀**: 기존 `engine/tests/test_exports.py`, `test_integration.py`가 여전히 통과.

기존 테스트 스타일(`conftest.py`, `test_db.py`, `test_integration.py`)을 따르라.

---

## 8. 검증 명령

작업 완료 전 아래가 모두 통과해야 한다.
```bash
python3 -m pytest -q
python3 -m compileall -q engine
npm run build
npm run lint
npm test
npm run test:integration
```
`npm run verify`(lint+test+integration+package)까지 green이면 이상적이다. 통과 못 하면 원인과 함께 보고하라(은폐 금지 — DESIGN.md §24의 "테스트 실패 은폐"는 실패 조건).

---

## 9. 산출물 & 보고

1. 변경/추가 파일 목록과 각 파일의 변경 요지.
2. 신규 마이그레이션 번호와 스키마 diff.
3. coverage completeness 판정 규칙표 (mode × 상태 → completeness).
4. 새 finalizer의 seal/projection 경계 설명 (무엇이 seal되고 무엇이 파생인가).
5. 위 8절 검증 명령의 실제 출력(요약).
6. 하위호환/회귀 영향과 대응.
7. WS-B/WS-F로 넘기는 인터페이스 지점 명시(예: row receipt가 참조하는 candidate/finding ID 격리 위치).

---

## 10. 하지 말 것 (Anti-goals)

- coverage를 여전히 finding category에서 파생시키는 것.
- 0-file/capped인데 `complete`를 산출하는 것.
- schema 검증 없이 seal하는 것.
- report.md/hardening.md를 seal 무결성 대상에 포함한 채 두는 것.
- 스코프를 WS-B/C/E/F/I로 확장하는 것(인터페이스만 맞추고 격리).
- 테스트 없이 "완료" 선언하는 것.
- 새 무거운 의존성을 근거 없이 추가하는 것.
