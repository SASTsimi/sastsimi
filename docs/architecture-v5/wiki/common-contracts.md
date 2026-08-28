# 공통 ID·상태·오류를 읽는 방법

이 페이지는 각 파트가 같은 분석 대상과 같은 실패 의미를 사용하도록 정한 R4-01 계약을 쉽게 설명합니다. 정확한 필드와 enum은 [경량 데이터 계약](../08-lightweight-data-contracts.md)이 기준입니다.

## ID는 무엇을 가리키나요?

| ID | 쉬운 의미 | 누가 처음 만드나요? |
|---|---|---|
| `analysis_id` | 전체 분석 한 번의 번호 | Orchestration runtime |
| `workspace_id` | 로컬에서 분석하는 코드 폴더 번호 | Repository Loader |
| `commit_id` | 분석한 Git commit | Repository Loader가 checkout 뒤 확인 |
| `hypothesis_id` | 검증할 취약점 가설 번호 | proposal 검증을 통과시킨 runtime |
| `attempt_id` | 재시도 가능한 작업 한 번의 번호 | 작업을 시작하는 runtime |
| `llm_call_id` | LLM 호출 한 번의 번호 | Agent Runtime |
| `record_id` | 저장한 결과 한 개의 번호 | 결과를 저장하는 runtime |
| `logical_record_id` | 같은 결과의 수정본들을 묶는 번호 | 결과를 처음 저장하는 runtime |
| `stored_data_id` | 결과 파일이나 기록을 찾는 번호 | 결과 저장 계층 |

시스템이 직접 만든 번호는 나중에 다른 대상을 가리키도록 다시 배정하지 않습니다. 같은 논리 결과의 수정본은 같은 `logical_record_id`를 유지하고, 같은 프로그램은 같은 `program_id`를 사용합니다. `commit_id`는 Git이 이미 만든 외부 식별자이므로 같은 commit을 여러 분석에서 다시 참조할 수 있습니다. 로컬 코드 폴더를 지워도 `workspace_id`가 어느 저장소와 commit을 가리켰는지는 남깁니다. `symbol_id`, `gap_id`, `error_id`, `proposal_id`처럼 특정 record에서만 쓰는 나머지 ID의 정확한 범위는 정본인 [경량 데이터 계약](../08-lightweight-data-contracts.md)의 식별자 표를 따릅니다.

clone 전에는 아직 `workspace_id`나 `commit_id`가 없을 수 있습니다. 이때는 `analysis_id`만 필수인 `RunMeta`를 사용합니다. checkout이 끝나 코드가 준비된 뒤의 근거에는 `workspace_id`와 `commit_id`가 모두 있어야 합니다. 외부 버그바운티 프로그램 ID는 출처가 다르면 겹칠 수 있으므로 `(program_namespace, external_program_id)`로 구분하고, 내부에서는 전역 `program_id`로 연결합니다.

`CodeWorkspace`는 준비 중 `PREPARING`, 분석 가능하면 `READY`, 준비 실패 시 `FAILED`, 로컬 폴더 정리 뒤 `REMOVED`입니다. 정적 분석은 `READY`에서만 시작합니다.

clone 전에 생긴 오류 로그와 전체 debug trace는 `RunStoredDataRef`로 가리킵니다. 이 참조에는 `analysis_id`만 필요합니다. 코드 근거·PoC·보고서 자료는 반드시 `workspace_id + commit_id`가 있는 `StoredDataRef`를 사용합니다.

## 가설끼리는 어떻게 연결하나요?

- `parent_hypothesis_ids`: 바로 앞에서 새 가설을 만들게 한 부모들
- `root_hypothesis_id`: 이 가설 계보의 첫 가설
- `chain_depth`: 첫 가설은 0, 한 단계 이어질 때마다 1 증가

`TRUE + TRUE`를 연결해 더 큰 공격 가능성을 찾아도 기존 두 결과를 수정하지 않습니다. 새로운 `hypothesis_id`를 만들고 전체 검증을 다시 거칩니다.

## 시간은 어떻게 적나요?

- 모든 시각은 UTC RFC 3339 형식입니다.
- `created_at`: 결과를 처음 저장한 시각이며 바꾸지 않습니다.
- `started_at`과 `finished_at`: 작업의 시작과 끝입니다.
- `elapsed_ms`: 실제 걸린 시간을 밀리초로 기록합니다.
- 진행 중이면 `finished_at`은 비어 있고, 종료 결과에는 반드시 값이 있어야 합니다.

## 상태를 왜 나누나요?

`FAILED`라는 단어가 나와도 무엇이 실패했는지에 따라 의미가 다릅니다.

| 구분 | 예시 | 취약점 판정인가요? |
|---|---|---|
| 전체 분석 상태 | `COMPLETE`, `PARTIAL`, `FAILED` | 아니요 |
| proposal 검증 상태 | `PROPOSED`, `SCHEMA_VALID`, `INVALID_OUTPUT` | 아니요. 아직 가설 번호가 없을 수 있음 |
| 등록된 가설 처리 상태 | `REGISTERED`, `ASSIGNED`, `VERIFYING`, `TERMINAL` | 아니요 |
| 기술 판정 | `TRUE`, `FALSE`, `HOLD` | 예 |
| 동적 재현 상태 | `SUCCEEDED`, `FAILED`, `BLOCKED` | 아니요 |
| LLM 호출 상태 | `AUTH_REQUIRED`, `RATE_LIMITED`, `TIMED_OUT` | 아니요 |
| 기술 Gate | `ACCEPT`, `REVISE`, `REJECT` | 판정을 검토하지만 바꾸지 않음 |
| 정책·영향 Gate | `PASS`, `FAIL`, `UNCERTAIN`, `ALLOW`, `DENY` | 보고서 전달 조건 |
| 보고서 초안 상태 | `NOT_REQUESTED`, `DRAFTED`, `FAILED` | 아니요. 내부 초안 진행 상태 |
| 사람 검토 | `PENDING`, `APPROVED`, `REJECTED` | 최종 공개 결정 |

## DataGap과 AnalysisError의 차이

- `DataGap`: 분석하지 못했거나 일부만 확인한 범위입니다. 예: Git LFS 실제 파일 없음, 일부 SAST 실패, 잘린 코드 조회.
- `AnalysisError`: 작업이 정상적으로 끝나지 못한 사건입니다. 예: clone 실패, provider 인증 실패, sandbox 오류.

둘 다 자동으로 `FALSE`가 되지 않습니다. `FALSE`는 미리 정한 반증 질문과 실제 반증 근거가 연결될 때만 가능합니다.

정적 분석과 코드 조회 결과는 사용할 수 있는 사실뿐 아니라 도구별 실행 상태, 분석·제외 범위, `DataGap`, `AnalysisError`를 함께 전달합니다. `DataGap`은 영향받은 path·language·코드 위치를 가능한 범위에서 적습니다. 결과가 비어 있거나 일부 도구가 실패했다는 이유로 안전하다고 판단하지 않습니다.

## 동적 재현 실패와 반증은 다릅니다

Docker 환경을 만들지 못했거나 실행이 timeout된 것은 재현 실패입니다. `status`는 실행 완료 정도이고 `hypothesis_outcome`은 관측이 가설을 지지했는지, 반증했는지, 결론을 주지 못했는지 나타냅니다. 둘 다 최종 판정이 아닙니다.

가설을 반증하려면 다음 네 가지가 함께 있어야 합니다.

1. `hypothesis_outcome: DISPROVED`
2. `hypothesis_disproved: true`
3. 실제 관측을 가리키는 `hypothesis_evidence_refs`
4. 그중 반증 관측을 가리키는 `disproof_evidence_refs`

빈 출력, exit code와 `FAILED | BLOCKED | CANCELLED`만으로는 가설을 `FALSE`로 바꿀 수 없습니다.

## 계약이 바뀌면 어떻게 하나요?

- `schema_version`은 `MAJOR.MINOR.PATCH` 형식입니다.
- 기존 의미와 호환되지 않으면 MAJOR가 바뀝니다.
- 이 문서의 enum 목록은 닫혀 있으므로 enum 값 추가·삭제·이름 변경도 MAJOR 변경입니다.
- 지원하지 않는 MAJOR는 추정해서 읽지 않습니다.
- 결과를 수정할 때 덮어쓰지 않습니다. `logical_record_id`는 유지하고 새 `record_id`와 다음 `revision_number`를 만듭니다.
- proposal 검증 record와 등록된 가설 record는 `proposal_ref`로 연결하지만 서로의 수정본으로 취급하지 않습니다.
- 잘못 연결된 revision은 `RECORD_REVISION_MISMATCH`로 거절합니다.

## 현재 검토 상태

계약 문서는 작성됐지만 R2·R6·R7·R3 담당자의 실제 교차 검토 기록이 남아야 Issue #13과 H-002를 완료할 수 있습니다. 그 전까지는 `IN_PROGRESS`입니다.
