# R4-01 공통 식별자·상태·오류 계약 설계

## 문서 상태

- 범위 승인: Issue #13과 PM 지시에 따라 승인됨
- 문서 상태: 작성 중인 Architecture v5 설계 초안에 반영
- 구현 상태: runtime 미구현
- 담당 역할: PM·아키텍처·워크플로(R4)

## 1. 목적

모든 파트가 같은 분석 실행, 코드 작업공간, Git commit, 가설, 실행 시도와 저장 결과를 같은 이름으로 가리키게 한다. 오류와 정보 부족을 취약점 반증으로 잘못 해석하지 않게 하고, 이전 결과를 덮어쓰지 않고 변경 이력을 추적할 수 있게 한다.

## 2. 범위 밖

- runtime 코드와 데이터베이스 구현
- 특정 UUID·ULID 라이브러리 선정
- 모든 서비스의 영구 API 확정
- `TRUE | FALSE | HOLD` 판정 의미 변경
- Gate·동적 재현·사람 검토 상태를 하나의 enum으로 합치기
- 전문 역할 담당자의 교차 검토를 대신 승인하기

## 3. 공통 식별자 결정

필드명은 짧은 영문 `snake_case`를 사용하고 문서에는 쉬운 한국어를 함께 적는다. ID 값은 불투명 문자열이다. 접두사 예시는 사람이 로그를 읽기 쉽게 하는 표시일 뿐, 값에서 업무 의미를 추론하지 않는다.

| 식별자 | 생성 주체 | 유일 범위 | 변경·재사용 | 정본 저장 위치 |
|---|---|---|---|---|
| `analysis_id` | Orchestration runtime | 전체 시스템 | 변경·재사용 금지 | `runs` |
| `workspace_id` | Repository Loader | 전체 시스템 | 변경·재사용 금지 | `CodeWorkspace`와 `runs` |
| `stored_data_id` | 결과 저장 계층 | 전체 시스템 | 변경·재사용 금지 | 각 논리 저장 영역 |
| `record_id` | record 저장 직전의 runtime | 전체 시스템 | revision마다 새 값 | 각 record |
| `hypothesis_id` | proposal 검증을 통과시킨 runtime | 전체 시스템 | 변경·재사용 금지 | `hypotheses` |
| `attempt_id` | 재시도 가능한 작업을 시작하는 runtime | 전체 시스템 | 시도마다 새 값 | 해당 결과와 debug trace |
| `llm_call_id` | LLM 호출 직전 Agent Runtime | 전체 시스템 | 호출·retry·failover마다 새 값 | `invocations` |
| `revision_number` | 새 revision을 저장하는 runtime | 같은 논리 결과 | 1부터 1씩 증가 | `RecordMeta` |

모든 ID는 생성 뒤 바꾸지 않는다. 로컬 코드 폴더가 삭제돼도 `workspace_id → repository_url + commit_id` 연결 정보는 남긴다. `CodeLocation`, `StoredDataRef`와 모든 핵심 `RecordMeta`는 `workspace_id`와 `commit_id`를 함께 사용한다.

## 4. 가설 관계 결정

초기·Research·체이닝 가설은 모두 독립 `hypothesis_id`를 가진다.

- `origin`: `INITIAL | RESEARCH | CHAINING`
- `parent_hypothesis_ids`: 직접 원인이 된 부모 목록. 초기 가설은 빈 목록이다.
- `root_hypothesis_id`: 가설 계보의 최초 가설. 초기 가설은 자기 자신이다.
- `chain_depth`: 초기 가설은 `0`, 자식은 부모의 최대 깊이보다 `1` 크다.

부모 verdict와 자식 verdict는 서로 덮어쓰지 않는다. `TRUE + TRUE` 결합도 새 가설을 만들며 부모 결과를 수정하지 않는다.

## 5. 시간 결정

- 모든 시각은 UTC RFC 3339 형식으로 저장한다. 예: `2026-08-28T12:34:56.123Z`.
- `created_at`은 record가 처음 저장된 불변 시각이다.
- 작업 실행 시간은 `started_at`과 `finished_at`으로 분리한다.
- 끝나지 않은 작업의 `finished_at`은 `null`이다.
- `elapsed_ms`는 monotonic clock으로 계산한 밀리초이며, 벽시계 시각 차이를 비용·timeout 판단의 정본으로 사용하지 않는다.
- revision은 새 `created_at`을 갖고 이전 record의 시각을 덮어쓰지 않는다.

## 6. 상태 계층 결정

| 계층 | 정본 상태 | 소유 주체 | 다른 계층에 미치는 영향 |
|---|---|---|---|
| 분석 실행 | `RUNNING | COMPLETE | PARTIAL | FAILED | CANCELLED` | Orchestration runtime | 가설 verdict를 직접 만들지 않음 |
| 가설 처리 | `PROPOSED | SCHEMA_VALID | ASSIGNED | VERIFYING | TERMINAL | INVALID_OUTPUT | CANCELLED` | Orchestration runtime | 기술 판정과 분리 |
| 기술 판정 | `TRUE | FALSE | HOLD` | Verification Agent | 오류 상태와 분리 |
| 동적 재현 | `NOT_REQUESTED | RUNNING | SUCCEEDED | PARTIAL | FAILED | BLOCKED | CANCELLED` | Sandbox runtime | `FAILED`만으로 `FALSE` 금지 |
| LLM 호출 | `SUCCEEDED | FAILED | INVALID_OUTPUT | TIMED_OUT | RATE_LIMITED | AUTH_REQUIRED | CANCELLED` | Agent Runtime과 provider adapter | 가설 verdict로 변환 금지 |
| 기술 Gate | `ACCEPT | REVISE | REJECT` | Technical Gate Agent | Verification verdict를 변경하지 않음 |
| 정책·영향 Gate | `PASS | FAIL | UNCERTAIN`과 `ALLOW | DENY` | Rule Scope Impact Gate Agent | 기술 판정과 분리 |
| 보고서 초안 | `NOT_REQUESTED | DRAFTED | FAILED` | Reporter runtime | 공개를 승인하지 않음 |
| 사람 검토 | `PENDING | APPROVED | REJECTED` | Human Reviewer | 최종 공개 여부 결정 |

하나의 필드에서 여러 계층을 표현하지 않는다. 예를 들어 sandbox `FAILED`, provider `AUTH_REQUIRED`와 분석 실행 `FAILED`는 이름이 비슷해도 서로 다른 record의 상태다.

## 7. DataGap과 AnalysisError 결정

`DataGap`은 분석하지 못했거나 일부만 확인한 범위다. 실행 자체가 실패하지 않아도 생길 수 있다. `AnalysisError`는 특정 단계에서 작업이 정상적으로 끝나지 못한 사건이다.

### DataGap

- 생산자: Repository Loader, 정적 분석, 코드 조회, sandbox, 정책 수집
- 소비자: Hypothesis, Verification, Research, Gate, 결과 집계
- 필수 정보: `gap_id`, `stage`, `code`, `reason`, 설명, 영향 위치, retry 가능 여부
- 대표 code: `SUBMODULE_UNAVAILABLE`, `LFS_POINTER_ONLY`, `GENERATED_FILE_UNAVAILABLE`, `STATIC_COVERAGE_PARTIAL`, `CONTEXT_TRUNCATED`, `POLICY_SOURCE_MISSING`

### AnalysisError

- 생산자: 모든 runtime·adapter·sandbox·Gate·Reporter
- 소비자: Orchestration runtime, 결과 집계, 운영자·사람 검토
- 필수 정보: `error_id`, `stage`, `code`, 안전한 메시지, retry 가능 여부, 관련 record, 발생 시각
- credential, 절대 로컬 경로와 민감한 원문은 메시지에 넣지 않는다.

`DataGap`과 `AnalysisError`는 자동으로 `FALSE`가 되지 않는다. `FALSE`는 가설에 이름 붙인 반증 질문과 실제 반증 근거가 연결될 때만 가능하다.

## 8. 동적 실패와 실제 반증

`DynamicReproductionResult.outcome=FAILED`는 환경 준비, 실행 또는 관측에 실패했다는 뜻이다. 실제 반증은 별도 `hypothesis_disproved=true`와 `disproof_evidence_refs`가 필요하다.

- `failure_reason`: 재현 작업이 실패하거나 막힌 이유
- `hypothesis_disproved`: 가설이 실제 관측으로 반증됐는지 여부
- `disproof_evidence_refs`: 어떤 관측이 반증했는지 가리키는 근거

실행하지 못함, timeout, 정책 차단, 빈 stdout과 exit code만으로는 `hypothesis_disproved=true`가 될 수 없다.

## 9. 계약 버전과 revision 결정

`schema_version`은 `MAJOR.MINOR.PATCH` 형식이다.

- MAJOR: 필드 삭제·이름 변경·의미 변경·기존 enum 의미 변경처럼 호환되지 않는 변경
- MINOR: 기존 의미를 바꾸지 않는 선택 필드 추가
- PATCH: 설명·예시·검증 규칙의 명확화처럼 데이터 해석이 바뀌지 않는 변경

소비자는 지원하지 않는 MAJOR를 거절하고 `SCHEMA_UNSUPPORTED`를 기록한다. 알 수 없는 선택 필드는 보존하거나 무시할 수 있지만 의미를 추정하지 않는다. 기존 record를 새 schema 의미로 덮어쓰지 않고 새 `record_id`와 `revision_number`를 만든다. `previous_record_id`는 같은 `record_type`, `analysis_id`, `workspace_id`, `commit_id`, `hypothesis_id`의 바로 이전 revision만 가리킨다.

## 10. 필수 실패 시나리오

1. clone 실패: 분석 실행 `FAILED`, `CLONE_FAILED`, 가설 verdict 없음
2. 일부 SAST 실패: 사용 가능한 사실과 `DataGap`, 분석 실행은 `PARTIAL` 가능
3. 코드 조회 잘림: `CONTEXT_TRUNCATED`, Verification은 `HOLD` 또는 추가 조회 가능
4. provider 인증 실패: `AUTH_REQUIRED`, 가설 verdict 유지
5. sandbox 준비 실패: 동적 `FAILED`, `failure_reason=ENVIRONMENT_SETUP`, 자동 `FALSE` 금지
6. 실제 반증 성공: `hypothesis_disproved=true`와 반증 근거가 있을 때만 `FALSE` 후보
7. 정책 조회 실패: `POLICY_FETCH_ERROR`, 정책 Gate `UNCERTAIN + DENY`
8. workspace·commit 불일치: `WORKSPACE_MISMATCH`, 해당 근거 사용 금지
9. revision 불일치: `RECORD_REVISION_MISMATCH`, 자동 병합 금지
10. schema MAJOR 미지원: `SCHEMA_UNSUPPORTED`, 새 의미 추정 금지

## 11. 완료와 교차 검토

문서 작성과 자동 검증이 끝나도 R4-01은 바로 완료되지 않는다. R2·R6·R7·R3 담당자가 각자 생산·소비하는 필드 의미를 확인한 기록이 있어야 Issue #13의 교차 검토 조건을 충족한다. 그 전까지 H-002는 `IN_PROGRESS`이며 “계약 작성 완료, 교차 검토 대기”로 표시한다.
