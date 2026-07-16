# WS-A Coverage & Finalization 구현 리뷰

- 리뷰 일시: 2026-07-15
- 대상: WS-A Coverage & Finalization correctness 반영본
- 결론: **큰 방향은 잘 반영됐지만 P0 결함 2개와 P1 결함 2개가 남아 있어 아직 완료로 승인하기 어렵다.**

## 1. 요약

Durable coverage ledger, capped/0-file 처리, canonical finalizer, projection 분리는 구현됐다. 하지만 다음 문제가 확인됐다.

1. **P0:** coverage frontier를 축소한 문서를 strict finalizer가 `complete`로 seal할 수 있음
2. **P0:** canonical digest 계산 사이의 TOCTOU로 manifest, 실제 파일, DB digest가 불일치해도 completed로 seal됨
3. **P1:** Diff Scan에서 삭제된 파일이 coverage frontier에서 사라짐
4. **P1:** 기존 `reviewedPaths` 기반 진행 중 Deep Scan이 migration 이후 복구되지 않음
5. **P2:** filesystem publication과 SQLite commit 사이에 hard-crash window가 있음

---

## 2. 주요 발견 사항

### P0 — Finalizer가 coverage frontier 축소를 탐지하지 못함

`engine/kiro_security/finalizer.py:59-96`은 coverage surface가 durable ledger에 존재하는지는 확인하지만, 반대 방향은 확인하지 않는다.

현재 검증:

```text
coverage surface → ledger row 존재
```

빠진 검증:

```text
모든 authoritative inventory/worklist row
= coverage surfaces ∪ unclosedRows
```

따라서 `coverage.json`에서 surface를 삭제하고 다음처럼 숫자를 줄여도 seal된다.

```json
{
  "completeness": "complete",
  "supportedFileCount": 1,
  "inScopeRowCount": 0,
  "closedRowCount": 0,
  "surfaces": []
}
```

직접 재현 결과:

```text
accepted: true
status: completed
completeness: complete
claimedRows: 0
durableLedgerRows: 1
```

즉 durable ledger에는 row가 있는데 sealed coverage는 0개 row를 완전 검토했다고 주장할 수 있다.

#### 필수 수정

1. authoritative inventory/worklist row ID 집합을 finalizer에서 다시 계산
2. `surface rowIds`와 `unclosed rowIds`가 중복 없이 정확히 authoritative 집합을 구성하는지 검증
3. `ledger rowIds == surface rowIds` 검증
4. `inScopeRowCount`, `closedRowCount`는 문서 값을 신뢰하지 말고 집합 크기로 재검증
5. 가능하면 `inventory.json`도 manifest의 supporting sealed artifact에 포함

---

### P0 — Canonical digest TOCTOU로 불일치한 bundle이 completed로 seal됨

`engine/kiro_security/finalizer.py:432-453`에서 다음 작업이 분리돼 있다.

1. `_manifest_document()`가 canonical 파일 hash 계산
2. 이후 `_artifact_record()`가 같은 파일 hash를 다시 계산

두 계산 사이에 파일이 변경돼도 결과가 동일한지 비교하지 않는다.

직접 coverage 파일을 두 계산 사이에 변경한 결과:

```text
accepted: true
status: completed
manifestEqualsDisk: false
manifestEqualsDb: false
```

실제로 다음 상태가 가능하다.

```text
manifest의 coverage SHA-256 = A
실제 coverage.json SHA-256 = B
DB artifact registry SHA-256 = B
scan status = completed
```

이는 strict canonical seal의 핵심 불변식을 깨뜨린다.

#### 필수 수정

- canonical 파일을 한 번만 bytes로 읽어 immutable snapshot 생성
- 검증, manifest hash, artifact registry hash를 모두 같은 snapshot에서 계산
- manifest artifact entry를 artifact record 생성에 그대로 재사용
- commit 직전 실제 파일 hash가 snapshot hash와 동일한지 재확인
- 다르면 `canonical_artifact_changed`로 seal 거부

---

### P1 — Diff Scan에서 삭제된 파일이 coverage frontier에서 사라짐

`engine/kiro_security/scanner.py:97,106,116`의 Git 필터:

```text
--diff-filter=ACMRTUXB
```

에는 `D`가 없다. 또한 inventory는 현재 존재하는 파일만 순회한다.

따라서 보안 검사나 authorization helper가 삭제됐더라도 coverage에 나타나지 않는다. 삭제 파일과 수정 파일이 함께 있을 때 직접 재현한 결과:

```text
files: ["kept.py"]
deferred: []
rows: ["kept.py"]
completeness: complete
```

삭제된 `deleted.py`는 완전히 사라졌다.

#### 필수 수정

- Git 변경 경로에 `D` 포함
- 현재 filesystem 순회와 Git changed path 집합의 차이를 계산
- 삭제 경로를 최소한 다음 deferred row로 기록

```json
{
  "path": "deleted.py",
  "surface": "deleted_file",
  "disposition": "deferred",
  "reason": "Deleted changed file was not reviewed from the base revision."
}
```

- 향후 Diff 모델 workflow에서는 base revision 내용을 실제 분석하는 것이 바람직함

---

### P1 — 기존 0.3.0 진행 중 Deep Scan이 migration 후 복구 불가능

새 계약은 `reviewedPaths` 대신 `rowReceipts`를 요구한다.

- 새 계약: `engine/kiro_security/deep.py:277-324`
- merge receipt 조회: `engine/kiro_security/deep.py:622` 부근
- migration: `engine/migrations/008_coverage_ledger.sql`

하지만 migration 008은 테이블만 만들고 기존 completed worker의 `result_json.reviewedPaths`를 backfill하지 않는다.

기존 6 worker가 이미 completed이고 merge 대기 중인 scan을 재현한 결과:

```text
legacyResumeAccepted: false
code: incomplete_deep_row_receipts
message: Semantic merge requires six row-level disposition receipts...
```

completed worker는 immutable이므로 retry도 어렵다.

#### 권장 수정

- migration/runtime compatibility adapter에서 legacy `reviewedPaths` 감지
- 기존 worker row마다 정직하게 `deferred` receipt 생성, 또는
- 해당 round를 명시적으로 `needs_rework`로 전환하고 worker를 재실행 가능하게 처리
- 조용히 `not_applicable`로 변환하지 말 것
- MCP 계약의 breaking change를 명시적인 버전/호환 경계로 기록

---

### P2 — Filesystem과 SQLite 사이 hard-crash window

Finalizer는 SQLite transaction 내부에서 `report.md`, `hardening.md`, manifest를 쓴다. 정상 예외는 cleanup하지만, 파일 작성 후 DB commit 전에 프로세스가 강제 종료되면 다음 상태가 남을 수 있다.

```text
filesystem manifest: completed
SQLite scan: running/interrupted
```

SQLite와 filesystem을 완전한 단일 transaction으로 묶을 수 없으므로 명시적인 prepared/finalizing recovery protocol이 필요하다.

#### 권장 수정

Startup 시 다음을 복구해야 한다.

- DB digest 없는 completed manifest 제거 또는 격리
- DB digest와 파일 digest 불일치 시 scan을 `finalization_failed` 또는 `interrupted`로 처리
- temp/staging manifest를 공식 manifest와 구분

---

## 3. 잘 반영된 부분

다음은 제대로 구현됐다.

- `008_coverage_ledger.sql`의 durable row receipt 테이블
- canonical disposition 4종 강제
- receipt digest를 정렬 JSON 기반 SHA-256으로 생성
- Standard/Diff의 지원 파일별 receipt
- Deep worker별 receipt와 6-worker merge consolidation
- `0 supported files → unknown`
- `Deep capped → partial`
- deferred/unclosed row가 있으면 `partial`
- 미지원 파일을 deferred로 노출
- permissive category 집계를 row-level projection으로 교체
- dependency-free schema validator 추가
- coverage/findings/manifest 검증
- `report.md`, `hardening.md`를 sealed artifact에서 제외하고 derived artifact로 구분
- mode별 validation mode를 정직하게 기록
- DB completed 상태와 manifest digest/artifact registry를 같은 SQLite transaction에 저장
- migration 전후 backup
- Agent runtime은 `.py`, `.sql`, `.json` 전체를 동적으로 수집하므로 신규 모듈과 migration도 포함됨

---

## 4. 검증 결과

### 성공

```text
python3 -m compileall -q engine
```

성공했다.

LSP diagnostics:

- `finalizer.py`: 0건
- `reporting.py`: 0건
- `db.py`: 0건
- `types.ts`: 0건

### 환경 제약으로 실행하지 못한 항목

```text
python3 -m pytest ...
→ No module named pytest

npm run lint
npm run build
→ npm: command not found
```

따라서 전체 테스트와 TypeScript 빌드는 현재 환경에서 확인하지 못했다.

### 직접 수행한 smoke reproduction

- Diff 삭제 파일이 coverage에서 사라지고 `complete`가 되는 문제 재현
- manifest canonical digest와 실제 파일/DB digest가 달라도 completed로 seal되는 문제 재현
- coverage frontier를 0 row로 축소해도 `complete`로 seal되는 문제 재현
- legacy `reviewedPaths` 기반 Deep round가 migration 후 merge되지 않는 문제 재현

---

## 5. 작업 지시 준수 관련 참고

다음 신규 테스트 파일이 추가됐다.

- `engine/tests/test_coverage.py`
- `engine/tests/test_finalizer.py`

품질에는 유익하지만, 이전 작업 지시의 “새 테스트 스위트를 작성하지 말라”는 요구와는 불일치한다.

---

## 6. 최종 판정

| 항목 | 판정 |
|---|---|
| Row-level coverage ledger | 잘 반영 |
| 0-file/capped/deferred 판정 | 잘 반영 |
| 실제 receipt digest | 잘 반영 |
| Projection 분리 | 잘 반영 |
| Manifest 상태 선기록 제거 | 잘 반영 |
| Strict coverage closure | **미완료 — P0** |
| Canonical seal 일관성 | **미완료 — P0** |
| Diff 전체 frontier | **미완료 — P1** |
| 기존 Deep resume 호환성 | **미완료 — P1** |

전체적으로 약 75~80% 수준으로 잘 반영됐지만, **P0 두 건을 수정하기 전에는 WS-A 완료로 체크하면 안 된다.**
