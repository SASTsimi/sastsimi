# R4-02 상태 전이·병렬 실행·재시도·복구 설계

## 문서 목적

이 문서는 Issue #14에서 요구한 실행 상태와 복구 의미를 Architecture v5에 반영하기 위한 결정 기록이다. R4-01에서 확정한 공통 식별자·revision·오류 계약을 바꾸지 않고, 여러 작업이 동시에 실행되거나 중간에 실패해도 결과가 중복·누락·뒤섞이지 않는 최소 실행 규칙을 정한다.

상태는 취약점 판정을 대신하지 않는다. 실행 작업의 `SUCCEEDED`는 그 작업이 정해진 출력을 저장했다는 뜻이고, 가설의 기술 판정은 여전히 `VerificationResult.verdict = TRUE | FALSE | HOLD`로만 표현한다.

## 확정된 전제

- 저장소는 실행별 로컬 `CodeWorkspace`로 준비하며 별도 repository snapshot 모듈을 두지 않는다.
- 코드 기준은 `workspace_id + commit_id`로 고정한다.
- Technical Evidence Gate와 Rule Scope Impact Gate는 순서대로 호출하는 두 LLM 검토 단계다.
- Queue, DB, workflow engine과 메시지 broker 제품은 이 설계에서 선택하지 않는다.
- 기존 record를 덮어쓰지 않고 새 `record_id`와 revision으로 보존한다.
- retry와 provider/model failover는 새 `attempt_id`와 필요한 새 `llm_call_id`를 사용한다.
- 오류, 인증 실패, 취소와 실행 실패를 취약점 `FALSE`로 바꾸지 않는다.

## 설계 범위

이번 변경은 다음을 정본으로 만든다.

1. 분석 전체와 개별 작업의 허용·금지 상태 전이
2. AST/SAST, 가설, Pro/Con의 병렬 경계와 결과 합류 조건
3. 같은 요청의 중복 반영 방지와 동시 갱신 충돌 처리
4. 결과 record와 종료 상태가 함께 확정되는 저장 경계
5. retry, failover, 취소, 늦게 도착한 결과와 오래된 revision 처리
6. 프로세스 중단 뒤 마지막 확정 상태에서 재개하는 규칙
7. `COMPLETE | PARTIAL | FAILED | CANCELLED` 전파 기준
8. 반복·예산·chaining·Gate 보완 종료 이유 보존

runtime 구현, 저장 제품, 분산 합의 알고리즘과 성능 수치는 이번 범위가 아니다.

## 접근 방식

### 선택: 공통 실행 상태와 전문 결과 상태 분리

모든 실행 가능한 일을 `WorkExecutionState`로 추적한다. 취약점 판정, Gate 검토 결과, 보고서 작성 여부 같은 전문 의미는 기존 전문 record에 남긴다.

이 방식은 단계마다 서로 다른 실행 enum을 새로 만드는 것보다 단순하고, `SUCCEEDED`를 `TRUE`로 오해하는 일을 막는다. `HypothesisProcessState`, `ReportProcessState`처럼 이미 소비자가 사용하는 상태는 유지하되 정확한 결과 `record_id`를 가리키게 한다.

## 공통 실행 상태

`WorkExecutionState.status`는 다음 값만 사용한다.

| 상태 | 쉬운 의미 | 다음 상태 |
|---|---|---|
| `PENDING` | 필요한 앞 단계가 끝나기를 기다림 | `READY`, `CANCELLED` |
| `READY` | 실행 조건과 예산을 확인해 시작 가능 | `RUNNING`, `BLOCKED`, `CANCELLED` |
| `RUNNING` | 하나의 활성 `attempt_id`가 실행 중 | `SUCCEEDED`, `PARTIAL`, `FAILED`, `BLOCKED`, `CANCELLED` |
| `BLOCKED` | 재시도 대기·인증·승인·필수 입력 등 다음 조건을 기다림 | `READY`, `FAILED`, `CANCELLED` |
| `SUCCEEDED` | 요구한 출력이 완전히 저장됨 | 종료 |
| `PARTIAL` | 신뢰할 수 있는 일부 출력과 누락 사유가 함께 저장됨 | 종료 |
| `FAILED` | 출력 조건을 충족하지 못하고 오류가 저장됨 | 종료; retry는 새 attempt로 별도 시작 |
| `CANCELLED` | 사용자 또는 runtime이 중단하고 이유를 저장함 | 종료 |

종료 상태를 되돌려 재사용하지 않는다. 재시도 가능한 attempt가 실패하면 작업은 실패 원인과 대기 조건을 보존한 채 `BLOCKED`가 되고, 조건을 충족하면 `READY`에서 새 `attempt_id`로 시작한다. 재시도할 수 없거나 한도를 모두 사용한 경우에만 최종 `FAILED`가 된다. 입력 revision이 달라지면 새 논리 작업과 새 `dedupe_key`를 만든다.

## 실행 작업 식별과 중복 방지

`WorkExecutionState`는 최소한 다음 정보를 가진다.

- `work_id`: 논리 작업 하나의 ID
- `work_type`: workspace 준비, static tool, 정규화, hypothesis, verification, dynamic, research, 두 Gate, report 중 하나
- `subject_id`: 작업 대상 analysis, hypothesis 또는 report ID
- `work_generation`: 같은 입력을 사람이 명시적으로 다시 시작한 순서; retry에서는 유지
- `status`와 증가하는 `state_version`
- 현재 상태를 만든 정확한 `last_transition_ref`와 결과 commit이 있으면 `last_transition_commit_ref`
- 현재 실행 중인 `active_attempt_id`
- 정확한 입력과 출력 `StoredDataRef`
- 입력 record ID·hash·설정 revision으로 만든 `input_hash`
- 같은 논리 요청을 식별하는 `dedupe_key`
- 오류, 대기 조건, 중단 이유와 시각

`dedupe_key`는 `analysis_id`, `work_type`, `subject_id`, `work_generation`, 정렬된 입력 `record_id + content_hash`, 적용한 설정·정책 revision을 canonical JSON으로 만든 뒤 SHA-256으로 계산한다. `attempt_id`, 시작 시각과 worker 이름은 포함하지 않는다. 같은 key가 다시 들어오면 runtime은 새 결과를 반영하지 않고 기존 `work_id`와 현재 상태를 반환한다. 재시도 가능한 attempt 실패로 작업이 `BLOCKED`라면 조건을 충족한 뒤 같은 `work_id` 아래 새 attempt를 시작하되 이전 실패 기록을 유지한다. 최종 `FAILED` 작업은 되돌리지 않는다. 사람이 같은 입력의 새 논리 실행을 명시적으로 승인하면 `work_generation`을 1 증가시키고 새 `work_id`와 `dedupe_key`를 만든다.

## 전이 저장과 동시 갱신

모든 상태 변경은 `StateTransition`으로 기록한다.

- `transition_id`
- `work_id`
- `from_status`, `to_status`
- `expected_state_version`, `new_state_version`
- `attempt_id`
- `cause`
- `output_refs`, `gap_ids`, `error_ids`
- `dedupe_key`
- `created_at`

runtime은 현재 `state_version`이 `expected_state_version`과 같을 때만 전이를 승인한다. 다르면 `STATE_VERSION_CONFLICT`로 거절하고 최신 상태를 다시 읽는다. 이 compare-and-set 규칙으로 두 worker가 같은 작업을 동시에 종료시키지 못하게 한다.

결과 record와 그 결과를 가리키는 종료 상태는 하나의 논리적 atomic transition으로 확정한다. 저장소가 단일 transaction을 지원하면 같은 transaction에서 처리한다. 지원하지 않으면 `TransitionCommit` journal을 사용한다. `PREPARED` 출력은 격리하고, state store가 현재 version·active attempt·입력이 그대로라는 조건을 compare-and-set으로 확인하면서 unique `(work_id, target_state_version)` key의 `COMMITTED` revision을 append한다. 경쟁 중 하나만 성공하며 이 marker가 논리적 확정점이다. runtime은 marker를 `WorkExecutionState`와 전문 상태 pointer에 투영하며, 소비자는 COMMITTED marker와 두 pointer가 모두 같은 output을 가리킬 때만 진행한다.

새 전이를 승인하기 전에 같은 work의 다음 version에 남은 journal을 먼저 확인한다. 기존 `COMMITTED` marker는 pointer에 재투영하고 경쟁 요청을 version conflict로 거절한다. 기존 `PREPARED`는 복구 또는 `ABORTED` 처리를 끝내기 전까지 새 전이를 막는다. `TransitionCommit`은 `StateTransition`과 같은 output refs, `gap_ids`, `error_ids`를 고정한다.

- `PREPARED`: 결과 record와 목표 상태를 기록했지만 소비자에게 보이지 않음
- `COMMITTED`: 한 번만 생성되는 논리적 확정 marker. marker와 상태 pointer가 같은 결과를 가리킬 때 소비 가능
- `ABORTED`: 버전 충돌, 취소 또는 검증 실패로 결과를 격리함

`HypothesisProcessState.status=TERMINAL`은 정확히 하나의 final `VerificationResult.record_id`를 가리켜야 한다. `ReportProcessState.status=DRAFTED`는 정확히 하나의 `ReportDraft.record_id`를 가리켜야 한다. Technical·Rule Scope Gate의 완료 상태도 각각 정확한 review `record_id`를 가리킨다.

## 병렬 실행과 결과 합류

### AST와 SAST

- AST와 각 SAST tool은 서로 다른 `work_id`로 병렬 실행한다.
- 정규화 단계는 기대한 tool 목록과 각 상태를 확인한 뒤 시작한다.
- 하나 이상의 신뢰 가능한 결과가 있고 실패 범위가 `DataGap`과 `AnalysisError`로 기록되면 `PARTIAL` 정규화를 허용한다.
- 성공 결과가 하나도 없거나 workspace 기준을 잃으면 `FAILED`다.
- 이미 확정된 `StaticFactBundle`을 늦은 tool 결과로 덮어쓰지 않는다. 받아들일 필요가 있으면 새 bundle revision과 새 downstream 작업을 만든다.

### 가설별 실행

- 서로 다른 `hypothesis_id`는 예산 범위에서 병렬 처리할 수 있다.
- 같은 가설에는 같은 work type의 활성 attempt를 하나만 허용한다.
- Pro와 Con은 서로 다른 `work_id`, `attempt_id`, NEW session으로 병렬 실행한다.
- Verification은 필요한 Pro/Con 종료, 동적 결과 또는 명시된 누락 조건을 확인한 뒤 합류한다. 누락을 `FALSE`로 해석하지 않는다.

### 직렬 구간

한 가설에서는 다음 순서를 바꿀 수 없다.

`final VerificationResult + CWELabel -> TechnicalEvidenceReview ACCEPT -> RuleScopeImpactReview -> Reporter 조건 검사 -> ReportDraft`

Technical `REVISE`는 Verification 또는 Research의 새 evidence/revision을 요구한다. 기존 Gate work는 `REVISE` 결과와 함께 종료하고, Verification이 보완된 `VerificationResult` 또는 `CWELabel` revision을 만든 뒤 새 `input_hash`·`dedupe_key`·`work_id`, `attempt_number=1`, `trigger=INITIAL`로 다시 등록한다. Research evidence도 새 Verification revision에 반영한다. 같은 입력의 retry attempt로 재투표하지 않는다. Rule Scope Gate는 Technical `ACCEPT`와 `TRUE`가 아니면 실행하지 않는다. Reporter는 두 Gate와 공식 정책·영향·권한 조건 및 exact revision 연결이 모두 맞을 때만 실행한다. 모순된 `ALLOW`는 `LLMInvocationResult.status=INVALID_OUTPUT`과 `AnalysisError(stage=GATE, code=INVALID_OUTPUT)`을 기록하고 Gate output commit과 Reporter 호출을 금지한다.

## retry와 failover

- retry와 failover는 항상 새 `attempt_id`를 사용한다.
- LLM retry·failover는 R4-01에서 정한 허용된 바로 앞 실패 호출을 새 `llm_call_id`로 연결한다.
- `retryable=false`, `CANCELLED`, 예산 소진, 반복 한도 도달 상태는 자동 retry하지 않는다.
- `AUTH_REQUIRED`는 재인증 확인 뒤, `RATE_LIMITED`는 backoff 뒤, `INVALID_OUTPUT`은 제한된 repair 뒤에만 후속 실행을 허용한다.
- provider/model 변경은 사전에 허용된 fallback과 전환 이유를 기록한 failover만 허용한다.
- retry 성공이 이전 실패와 오류 record를 삭제하지 않는다.

## 늦은 결과와 오래된 결과

결과를 반영하려면 다음 조건을 모두 만족해야 한다.

1. 결과의 `attempt_id`가 현재 `active_attempt_id`와 같다.
2. 작업 상태가 `RUNNING`이고 취소되지 않았다.
3. 제출한 `expected_state_version`이 현재 값과 같다.
4. `input_hash`, `workspace_id`, `commit_id`, `hypothesis_id`가 작업과 같다.
5. 결과가 가리키는 record revision과 content hash가 실제 저장 대상과 같다.

하나라도 다르면 결과는 `STALE_RESULT` 또는 `ATTEMPT_NOT_ACTIVE`로 거절한다. 디버깅용 격리 기록은 남길 수 있지만 최신 상태·Gate·보고서 입력에 연결하지 않는다.

## 중단 후 재개

재개 시 runtime은 마지막 `COMMITTED` marker와 그 marker에서 투영된 pointer만 신뢰한다.

- `RUNNING`이지만 commit되지 않은 attempt는 `INTERRUPTED` 오류와 함께 실패 처리 후보가 된다.
- `PREPARED` journal은 현재 version·active attempt·입력 hash가 맞으면 compare-and-set 조건으로 unique `COMMITTED` marker를 append하고 pointer를 투영한다. 맞지 않거나 경쟁 전이가 먼저 확정됐으면 `ABORTED`로 격리한다.
- `COMMITTED` marker는 있지만 pointer 투영 전에 중단된 경우에는 같은 marker를 다시 만들지 않고 기존 marker를 상태에 재투영한다.
- 종료 상태와 output pointer가 서로 다르면 다음 단계 호출을 막고 `TRANSITION_INCOMPLETE`를 기록한다.
- 자동 복구가 안전하지 않으면 `RECOVERY_FAILED`로 분석 또는 해당 가설을 멈추며 사람에게 필요한 조치를 전달한다.
- 재개가 허용된 작업만 새 attempt로 실행한다. 이미 `COMMITTED`된 결과는 다시 실행하지 않는다.

## 실패·취소·부분 성공 전파

| 상황 | 개별 작업 | 가설/분석 영향 |
|---|---|---|
| clone·checkout 실패 | `FAILED` | 분석 `FAILED`, AST/SAST 미실행 |
| 일부 AST/SAST 실패 | `PARTIAL` 가능 | `DataGap` 보존, 가설별 분석 계속 가능 |
| 한 가설의 Agent 오류 | `FAILED` | 다른 가설 계속, 분석 `PARTIAL` 가능 |
| 인증 필요 | `BLOCKED` | 자동 `FALSE` 금지, 재인증 또는 승인된 failover 대기 |
| Sandbox 실행 실패 | `FAILED` | 동적 반증 아님, Verification이 남은 근거로 `HOLD` 여부 판단 |
| 정책 조회 실패 | `FAILED` 또는 Gate 입력 부족 | 기술 verdict 유지, `UNCERTAIN + DENY`, Reporter 차단 |
| Gate 보완 한도 초과 | `FAILED` | 기술 verdict 유지, Reporter 차단, 미해결 조건 저장 |
| 보고서 작성 실패 | `FAILED` | 기술·Gate 결과 유지, 보고서만 실패 |
| 사용자 가설 취소 | `CANCELLED` | 그 가설의 새 downstream 작업 금지 |
| 전체 분석 취소 | 진행 작업 `CANCELLED` | 새 작업 생성 금지, 분석 `CANCELLED` |
| 일부 가설·도구 실패 | 각 상태 보존 | 유효 결과가 있으면 분석 `PARTIAL` |

## 반복과 예산 종료

retry, Gate `REVISE`, Research, chaining은 각각 횟수·token·시간 한도를 갖고 전체 분석 예산에도 포함한다. 중복 fingerprint, cycle, chain depth와 조합 수 제한을 적용한다. 제한에 걸리면 `stop_reason`과 사용량을 저장하며 가설을 임의로 `FALSE`로 만들지 않는다.

## 부정 시나리오와 기대 결과

| 시나리오 | 기대 결과 |
|---|---|
| 같은 가설 검증 요청이 동시에 두 번 도착 | 같은 `dedupe_key`의 기존 작업을 반환하고 결과는 한 번만 반영 |
| 이전 attempt 결과가 retry 결과보다 늦게 도착 | `ATTEMPT_NOT_ACTIVE`로 거절·격리 |
| 다른 workspace/commit 결과가 합류 | `WORKSPACE_MISMATCH`로 거절 |
| 취소 뒤 결과가 도착 | `STALE_RESULT`로 거절하고 downstream 미호출 |
| Gate가 읽은 revision보다 오래된 결과가 Reporter로 전달 | `RECORD_REVISION_MISMATCH`로 Reporter 차단 |
| 결과 record만 있고 종료 상태 pointer가 없음 | journal 복구 또는 `TRANSITION_INCOMPLETE`로 차단 |
| 종료 상태만 있고 결과 record가 없음 | `TRANSITION_INCOMPLETE`, 다음 단계 차단 |
| 허용하지 않은 provider failover | `INVOCATION_CHAIN_INVALID`, 결과 사용 금지 |
| crash 뒤 같은 작업 재요청 | committed 결과 재사용 또는 새 attempt; 결과 중복 반영 금지 |
| 예산을 넘긴 무한 Gate/chaining 반복 | 중단 이유 저장, Reporter 차단, `FALSE` 변환 금지 |
| `PARTIAL` 결과에 누락·오류 설명이 없음 | `STATE_TRANSITION_INVALID`, 부분 결과 사용 금지 |
| 분석 종료 시 실행 중 work나 `PREPARED` journal이 남음 | 최종 분석 상태 전이 차단 |
| `COMMITTED` marker 투영 전에 취소·retry가 경쟁 | 기존 marker를 먼저 재투영하고 경쟁 전이는 version conflict로 거절 |

## 문서 배치

- `03-agent-roles-and-orchestration.md`: 상태 흐름, 병렬·직렬 경계와 전이 주체
- `07-results-and-observability.md`: 저장, dedupe, recovery와 오류 전파
- `08-lightweight-data-contracts.md`: `WorkExecutionState`, `StateTransition`, `TransitionCommit` 정본
- `09-llm-provider-session-and-logging.md`: retry/failover와 상태 연결
- `10-security-boundaries.md`: stale result, version 충돌과 취소 후 결과 차단
- `13-architecture-diagrams.md`: 상태도와 결과 commit/복구 흐름
- `wiki/state-and-recovery.md`: 팀원이 읽을 쉬운 요약

## 완료 판정

Issue #14의 모든 기술 완료 조건을 정본 문서, Wiki와 Mermaid에서 추적할 수 있어야 한다. Markdown 링크·fence·Mermaid mirror, enum·필드 이름, 허용·금지 상태 전이, output pointer와 recovery 시나리오를 자동 또는 문서 기반 검사로 확인한다. 남은 구현 제품 선택이나 성능 수치는 구현 단계 결정으로 구분하고 Blocker/High로 남기지 않는다.
