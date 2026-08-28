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
| `commit_id` | checkout 뒤 Repository Loader가 확인 | Git 저장소 | 같은 commit을 여러 분석에서 참조 가능, 값 변경 금지 | `CodeWorkspace`, 코드 위치와 모든 핵심 결과 |
| `stored_data_id` | 결과 저장 계층 | 전체 시스템 | 변경·재사용 금지 | 각 논리 저장 영역 |
| `record_id` | record 저장 직전의 runtime | 전체 시스템 | revision마다 새 값 | 각 record와 정확한 revision을 가리키는 `StoredDataRef` |
| `logical_record_id` | 논리 결과를 처음 저장하는 runtime | 전체 시스템 | 같은 결과의 revision에서 유지 | `RunMeta`와 `RecordMeta` |
| `hypothesis_id` | proposal 검증을 통과시킨 runtime | 전체 시스템 | 변경·재사용 금지 | `hypotheses` |
| `attempt_id` | 재시도 가능한 작업을 시작하는 runtime | 전체 시스템 | 시도마다 새 값 | 해당 결과와 debug trace |
| `llm_call_id` | LLM 호출 직전 Agent Runtime | 전체 시스템 | 호출·retry·failover마다 새 값 | `invocations` |
| `symbol_id` | AST·SAST 정규화 계층 | 같은 `workspace_id + commit_id` | 같은 코드 버전의 한 symbol만 가리킴 | `CodeSymbol` |
| `fact_id` | AST·SAST 정규화 계층 | 같은 `workspace_id + commit_id` | 같은 코드 사실에 재사용하고 다른 사실에 재사용 금지 | `CodeFact` |
| `relation_id` | AST·SAST 정규화 계층 | 같은 `workspace_id + commit_id` | 같은 코드 관계에 재사용하고 다른 관계에 재사용 금지 | `CodeRelation` |
| `gap_id` | gap을 발견한 runtime | 전체 시스템 | gap마다 새 값 | `DataGap` |
| `error_id` | 오류를 기록한 runtime | 전체 시스템 | 오류 사건마다 새 값 | `AnalysisError` |
| `proposal_id` | proposal 출력 검증 runtime | 전체 시스템 | proposal마다 새 값 | `HypothesisProposal` |
| `question_id` | proposal 출력 검증 runtime | 전체 시스템 | proposal에서 등록 가설로 유지하고 다른 질문에 재사용 금지 | `FalsificationQuestion/Result` |
| `code_request_id` | Agent Runtime | 전체 시스템 | 요청·응답 한 쌍에서 유지 | `CodeContextRequest/Response` |
| `primitive_id` | primitive 저장 runtime | 전체 시스템 | primitive마다 새 값 | `Primitive` |
| `policy_record_id` | 정책 수집 결과 저장 runtime | 전체 시스템 | 정책 수집본마다 새 값 | `ProgramPolicyRecord` |
| `program_id` | 내부 Program Catalog | 전체 시스템 | 같은 프로그램을 여러 분석에서 재사용 | `ProgramPolicyRecord` |
| `external_program_id` | 외부 플랫폼 | 같은 `program_namespace` | 같은 외부 프로그램을 재참조 가능 | `ProgramPolicyRecord` |
| `revision_number` | 새 revision을 저장하는 runtime | 같은 논리 결과 | 1부터 1씩 증가 | `RunMeta`와 `RecordMeta` |

시스템이 만든 ID는 다른 대상에 재사용하지 않는다. `commit_id`와 `external_program_id`는 외부 대상을 가리키므로 같은 대상을 여러 분석에서 다시 참조할 수 있다. 외부 프로그램은 `(program_namespace, external_program_id)`로 구분하고 내부의 전역 `program_id`에 매핑한다. `root_hypothesis_id`, 부모·source·target 가설 ID와 retry/failover 호출 ID는 기존 ID를 가리키는 참조 필드다. 일반 retry는 `retry_of_llm_call_id`, provider/model 전환은 `failover_from_llm_call_id`로 바로 앞 실패 호출을 가리키며 두 필드는 상호 배타적이다. 로컬 코드 폴더가 삭제돼도 성공한 `workspace_id → repository_url + commit_id` 연결 정보는 남긴다.

분석 시작·clone 실패처럼 코드가 아직 준비되지 않은 실행 record는 `analysis_id`만 필수인 `RunMeta`를 쓴다. `AnalysisRunState`와 `AnalysisRunResult`의 `workspace_id`, `commit_id`는 준비 전 `null`일 수 있고 실제 값이 기록된 뒤에는 바꾸지 않는다. 코드 근거를 담는 record는 두 값이 필수인 `RecordMeta`를 사용하며 `CodeWorkspace.status=READY`인 같은 commit만 참조한다.

`CodeWorkspace.status`는 `PREPARING | READY | FAILED | REMOVED`다. clone·checkout 진행 중에는 `PREPARING`과 `commit_id=null`, 분석 가능한 상태는 `READY`와 확인된 `commit_id`를 사용한다.

R2 교차 검토에 따라 정적 결과는 `CodeFact`, `CodeRelation`, `ToolRunResult`로 구성한다. 각 사실·관계는 producer와 원본 `StoredDataRef`, 정규화된 `CodeLocation`으로 역추적할 수 있어야 한다. `ToolRunResult`는 도구별 상태와 실제 분석·제외 path/language, gap, error를 함께 기록한다. `StaticFactBundle`과 `CodeContextResponse`는 `DataGap`과 `AnalysisError`를 모두 전달한다.

`CodeLocation.file_path`는 `/` 구분자를 사용하는 Git 상대 경로다. 줄은 1부터 시작하고 시작·끝 줄을 포함한다. column은 알 수 없으면 둘 다 `null`이며, 값이 있으면 1-based Unicode code point 단위로 시작 column은 포함하고 끝 column은 제외한다. Context 조회는 depth·fragment·byte·token·요청 횟수·timeout 한도를 모두 적용한다.

실행 자료 참조도 분리한다. `RunStoredDataRef`는 `analysis_id`로 입력 검증, clone·checkout 오류와 전체 debug trace를 가리키며 commit이 없어도 된다. `StoredDataRef`는 `workspace_id + commit_id`가 있는 코드 근거·PoC·보고서용 자료만 가리킨다. `RunStoredDataRef`를 코드 주장 근거로 사용할 수 없다.

저장된 record revision을 가리키는 `StoredDataRef`는 전역 `record_id`를 포함한다. raw 도구 결과나 코드 조각처럼 독립 artifact이면 `record_id=null`이다. Technical Gate의 `verification_result_ref.record_id`는 필수이며 Gate가 읽은 정확한 `VerificationResult` revision을 고정한다. Rule Scope Gate도 `verification_result_ref`, `technical_review_ref`와 nullable `policy_record_ref`로 자신이 읽은 입력 revision을 고정한다. 입력 revision이 수정되면 이전 Gate 결과를 재사용하지 않고, Reporter는 자신이 참조한 네 결과와 두 Gate 내부 참조가 모두 같은 revision chain인지 확인한다.

## 4. 가설 관계 결정

초기·Research·체이닝 가설은 모두 독립 `hypothesis_id`를 가진다.

- `origin`: `INITIAL | RESEARCH | CHAINING`
- `parent_hypothesis_ids`: 직접 원인이 된 부모 목록. 초기 가설은 빈 목록이다.
- `root_hypothesis_id`: 가설 계보의 최초 가설. 초기 가설은 자기 자신이다.
- `chain_depth`: 초기 가설은 `0`, 자식은 부모의 최대 깊이보다 `1` 크다.

부모 verdict와 자식 verdict는 서로 덮어쓰지 않는다. `TRUE + TRUE` 결합도 새 가설을 만들며 부모 결과를 수정하지 않는다.

proposal 출력 검증 runtime은 각 named falsification 질문에 전역 `question_id`를 부여하고 등록 가설까지 유지한다. 최종 `VerificationResult`는 모든 질문을 `DISPROVED | NOT_DISPROVED | INCONCLUSIVE` 중 하나로 평가한다. `DISPROVED`에는 실제 evidence가 필요하다. `FALSE`는 적어도 하나의 근거 있는 `DISPROVED`와 그 질문을 설명하는 판정 이유가 있을 때만 허용한다. `NOT_DISPROVED`는 가설 성립 증거가 아니다.

## 5. 시간 결정

- 모든 시각은 UTC RFC 3339 형식으로 저장한다. 예: `2026-08-28T12:34:56.123Z`.
- `created_at`은 record가 처음 저장된 불변 시각이다.
- 작업 실행 시간은 `started_at`과 `finished_at`으로 분리한다.
- 끝나지 않은 작업의 `finished_at`은 `null`이다.
- `elapsed_ms`는 monotonic clock으로 계산한 밀리초이며, 벽시계 시각 차이를 비용·timeout 판단의 정본으로 사용하지 않는다.
- revision은 새 `created_at`을 갖고 이전 record의 시각을 덮어쓰지 않는다.
- 상태 record에는 `started_at`, `finished_at`, `elapsed_ms`를 둔다. `NOT_REQUESTED`는 두 시각이 `null`이고 `elapsed_ms=0`이다.
- 상세 결과 record는 종료 결과이므로 `finished_at`이 필수다.

## 6. 상태 계층 결정

| 계층 | 정본 record.field | 정본 상태 | 소유 주체 | 다른 계층에 미치는 영향 |
|---|---|---|---|---|
| 분석 실행 | `AnalysisRunState.status` | `RUNNING | COMPLETE | PARTIAL | FAILED | CANCELLED` | Orchestration runtime | 가설 verdict를 직접 만들지 않음 |
| proposal 검증 | `ProposalProcessState.status` | `PROPOSED | SCHEMA_VALID | INVALID_OUTPUT | CANCELLED` | 출력 검증 runtime | 아직 `hypothesis_id`가 없음 |
| 등록 가설 처리 | `HypothesisProcessState.status` | `REGISTERED | ASSIGNED | VERIFYING | TERMINAL | CANCELLED` | Orchestration runtime | 기술 판정과 분리 |
| 기술 판정 | `VerificationResult.verdict` | `TRUE | FALSE | HOLD` | Verification Agent | 오류 상태와 분리 |
| 동적 재현 | `DynamicReproductionState.status` | `NOT_REQUESTED | RUNNING | SUCCEEDED | PARTIAL | FAILED | BLOCKED | CANCELLED` | Sandbox runtime | `FAILED`만으로 `FALSE` 금지 |
| LLM 호출 | `LLMInvocationResult.status` | `SUCCEEDED | FAILED | INVALID_OUTPUT | TIMED_OUT | RATE_LIMITED | AUTH_REQUIRED | CANCELLED` | Agent Runtime과 provider adapter | 가설 verdict로 변환 금지 |
| 기술 Gate | `TechnicalEvidenceReview.status` | `ACCEPT | REVISE | REJECT` | Technical Gate Agent | Verification verdict를 변경하지 않음 |
| 정책·영향 Gate | `RuleScopeImpactReview.review_status`, `report_permission` | `PASS | FAIL | UNCERTAIN`, `ALLOW | DENY` | Rule Scope Impact Gate Agent | 기술 판정과 분리 |
| 보고서 초안 | `ReportProcessState.status` | `NOT_REQUESTED | DRAFTED | FAILED` | Reporter runtime | 공개를 승인하지 않음 |
| 사람 검토 | `ReportDraft.human_review_state` | `PENDING | APPROVED | REJECTED` | Human Reviewer | 최종 공개 여부 결정 |

하나의 필드에서 여러 계층을 표현하지 않는다. 예를 들어 sandbox `FAILED`, provider `AUTH_REQUIRED`와 분석 실행 `FAILED`는 이름이 비슷해도 서로 다른 record의 상태다.

proposal 검증 상태의 `meta.hypothesis_id`는 항상 `null`이다. `SCHEMA_VALID` 뒤 새 `hypothesis_id`를 발급하고 별도 `logical_record_id`의 등록 가설 상태를 `REGISTERED`로 만든다. 두 record는 같은 `proposal_ref`로 연결하며 revision 관계로 취급하지 않는다.

## 7. DataGap과 AnalysisError 결정

`DataGap`은 분석하지 못했거나 일부만 확인한 범위다. 실행 자체가 실패하지 않아도 생길 수 있다. `AnalysisError`는 특정 단계에서 작업이 정상적으로 끝나지 못한 사건이다.

### DataGap

- 생산자: Repository Loader, 정적 분석, 코드 조회, sandbox, 정책 수집
- 소비자: Hypothesis, Verification, Research, Gate, 결과 집계
- 필수 정보: `gap_id`, `stage`, `code`, `reason`, 설명, 영향 path·language·위치, retry 가능 여부
- 대표 code: `SUBMODULE_UNAVAILABLE`, `LFS_POINTER_ONLY`, `GENERATED_FILE_UNAVAILABLE`, `STATIC_COVERAGE_PARTIAL`, `CONTEXT_TRUNCATED`, `POLICY_SOURCE_MISSING`

### AnalysisError

- 생산자: 모든 runtime·adapter·sandbox·Gate·Reporter
- 소비자: Orchestration runtime, 결과 집계, 운영자·사람 검토
- 필수 정보: `error_id`, `stage`, `code`, `safe_message`, retry 가능 여부, 관련 record, 발생 시각
- `safe_message`에는 credential, 절대 로컬 경로, 개인정보와 session secret을 넣지 않는다. 원본 오류는 별도 접근 통제·redaction·보존 정책이 적용된 artifact로 분리한다.
- 모든 오류는 `AnalysisRunResult.errors`와 debug trace에 전달한다. 특정 가설·호출·동적 실행 오류는 해당 전문 결과에도 포함하거나 `related_record_ids`로 연결한다.
- Gate 오류는 보고서 전달을 막고, provider·sandbox·context 오류는 기존 verdict를 자동으로 바꾸지 않는다.

`DataGap`과 `AnalysisError`는 자동으로 `FALSE`가 되지 않는다. `FALSE`는 가설에 이름 붙인 반증 질문과 실제 반증 근거가 연결될 때만 가능하다.

## 8. 동적 실패와 실제 반증

`DynamicReproductionResult.status`는 재현 작업의 완료 정도이고 `hypothesis_outcome: SUPPORTED | DISPROVED | INCONCLUSIVE`은 유효한 관측과 가설의 관계다. 둘 다 Verification verdict가 아니다.

- `failure_reason`: 재현 작업이 실패하거나 막힌 이유
- `hypothesis_outcome`: 관측이 가설을 지지·반증하는지 또는 결론을 주지 못하는지
- `hypothesis_evidence_refs`: outcome을 판단한 실제 관측
- `hypothesis_disproved`: 가설이 실제 관측으로 반증됐는지 여부
- `disproof_evidence_refs`: 어떤 관측이 반증했는지 가리키는 근거

필수 환경이나 공격 경로를 실행하지 못하면 `FAILED + ENVIRONMENT_SETUP`이다. 유효한 관측이 하나 이상 있지만 환경 차이로 전체 확인이 부족하면 `PARTIAL + NONE + INCONCLUSIVE`이며 evidence와 limitations가 각각 하나 이상 필요하다. `DISPROVED`일 때만 `hypothesis_disproved=true`와 비어 있지 않은 `disproof_evidence_refs`를 사용한다. 실행하지 못함, timeout, 정책 차단, 빈 stdout과 exit code만으로는 반증이 될 수 없다.

## 9. 계약 버전과 revision 결정

`schema_version`은 `MAJOR.MINOR.PATCH` 형식이다.

- MAJOR: 필드 삭제·이름 변경·의미 변경과 enum 값의 추가·삭제·이름 변경·의미 변경처럼 호환되지 않는 변경
- MINOR: 기존 의미를 바꾸지 않는 선택 필드 추가
- PATCH: 설명·예시·검증 규칙의 명확화처럼 데이터 해석이 바뀌지 않는 변경

명시된 enum은 모두 닫힌 enum이므로 목록에 없는 값을 추정해 처리하지 않는다. 소비자는 지원하지 않는 MAJOR를 거절하고 `SCHEMA_UNSUPPORTED`를 기록한다. 알 수 없는 선택 필드는 보존하거나 무시할 수 있지만 의미를 추정하지 않는다. 기존 record를 새 schema 의미로 덮어쓰지 않고 같은 `logical_record_id` 아래 새 `record_id`와 `revision_number`를 만든다. revision의 유일 키는 `(logical_record_id, revision_number)`이며 `previous_record_id`는 같은 논리 결과의 바로 이전 revision만 가리킨다. 모든 revision은 같은 `record_type`, `analysis_id`를 유지하고, 코드에 묶인 `RecordMeta`는 `workspace_id`, `commit_id`, `hypothesis_id`도 유지한다. `RunMeta` 기반 record의 workspace·commit은 `null`에서 실제 값으로 한 번만 묶을 수 있다.

## 10. 필수 실패 시나리오

1. clone 실패: 분석 실행 `FAILED`, `CLONE_FAILED`, 가설 verdict 없음
2. 일부 SAST 실패: 사용 가능한 사실과 `DataGap`, 분석 실행은 `PARTIAL` 가능
3. 코드 조회 잘림: `CONTEXT_TRUNCATED`, Verification은 `HOLD` 또는 추가 조회 가능
4. provider 인증 실패: `AUTH_REQUIRED`, 가설 verdict 유지
5. sandbox 준비 실패: 동적 `FAILED`, `failure_reason=ENVIRONMENT_SETUP`, `hypothesis_outcome=INCONCLUSIVE`, 자동 `FALSE` 금지
6. 실제 반증 성공: `hypothesis_outcome=DISPROVED`, `hypothesis_disproved=true`와 반증 근거가 있을 때만 `FALSE` 후보
7. 정책 조회 실패: `POLICY_FETCH_ERROR`, 정책 Gate `UNCERTAIN + DENY`
8. workspace·commit 불일치: `WORKSPACE_MISMATCH`, 해당 근거 사용 금지
9. revision 불일치: `RECORD_REVISION_MISMATCH`, 자동 병합 금지
10. schema MAJOR 미지원: `SCHEMA_UNSUPPORTED`, 새 의미 추정 금지

## 11. 완료와 교차 검토

문서 작성과 자동 검증이 끝나도 R4-01은 바로 완료되지 않는다. R2·R6·R7·R3 담당자가 각자 생산·소비하는 필드 의미를 확인한 기록이 있어야 Issue #13의 교차 검토 조건을 충족한다. 그 전까지 H-002는 `IN_PROGRESS`이며 “계약 작성 완료, 교차 검토 대기”로 표시한다.
