# 공통 ID·상태·오류를 읽는 방법

이 페이지는 각 파트가 같은 분석 대상과 같은 실패 의미를 사용하도록 정한 R4-01 계약을 쉽게 설명합니다. 정확한 필드와 enum은 [경량 데이터 계약](../08-lightweight-data-contracts.md)이 기준입니다.

## ID는 무엇을 가리키나요?

| ID | 쉬운 의미 | 누가 처음 만드나요? |
|---|---|---|
| `analysis_id` | 전체 분석 한 번의 번호 | Orchestration runtime |
| `workspace_id` | 로컬에서 분석하는 코드 폴더 번호 | Repository Loader |
| `commit_id` | 분석한 Git commit | Repository Loader가 checkout 뒤 확인 |
| `hypothesis_id` | 검증할 취약점 가설 번호 | proposal 검증을 통과시킨 runtime |
| `work_id` | 같은 논리 작업을 처음부터 끝까지 묶는 번호 | Orchestration runtime |
| `attempt_id` | 재시도 가능한 작업 한 번의 번호 | 작업을 시작하는 runtime |
| `llm_call_id` | LLM 호출 한 번의 번호 | Agent Runtime |
| `record_id` | 저장한 결과 한 개의 번호 | 결과를 저장하는 runtime |
| `logical_record_id` | 같은 결과의 수정본들을 묶는 번호 | 결과를 처음 저장하는 runtime |
| `stored_data_id` | 결과 파일이나 기록을 찾는 번호 | 결과 저장 계층 |

시스템이 직접 만든 번호는 나중에 다른 대상을 가리키도록 다시 배정하지 않습니다. 같은 논리 결과의 수정본은 같은 `logical_record_id`를 유지하고, 같은 프로그램은 같은 `program_id`를 사용합니다. `commit_id`는 Git이 이미 만든 외부 식별자이므로 같은 commit을 여러 분석에서 다시 참조할 수 있습니다. 로컬 코드 폴더를 지워도 `workspace_id`가 어느 저장소와 commit을 가리켰는지는 남깁니다. `symbol_id`, `gap_id`, `error_id`, `proposal_id`처럼 특정 record에서만 쓰는 나머지 ID의 정확한 범위는 정본인 [경량 데이터 계약](../08-lightweight-data-contracts.md)의 식별자 표를 따릅니다.

clone 전에는 아직 `workspace_id`나 `commit_id`가 없을 수 있습니다. 이때는 `analysis_id`만 필수인 `RunMeta`를 사용합니다. checkout이 끝나 코드가 준비된 뒤의 근거에는 `workspace_id`와 `commit_id`가 모두 있어야 합니다. 외부 버그바운티 프로그램 ID는 출처가 다르면 겹칠 수 있으므로 `(program_namespace, external_program_id)`로 구분하고, 내부에서는 전역 `program_id`로 연결합니다.

`CodeWorkspace`는 준비 중 `PREPARING`, 분석 가능하면 `READY`, 준비 실패 시 `FAILED`, 로컬 폴더 정리 뒤 `REMOVED`입니다. 정적 분석은 `READY`에서만 시작합니다.

clone 전에 생긴 오류 로그와 전체 debug trace는 `RunStoredDataRef`로 가리킵니다. 이 참조에는 `analysis_id`가 필요합니다. raw 실행 자료는 `record_id: null`, `RunMeta`를 가진 저장 결과의 정확한 수정본을 가리킬 때는 그 `record_id`를 넣습니다. 코드 근거·PoC·보고서 자료는 반드시 `workspace_id + commit_id`가 있는 `StoredDataRef`를 사용합니다. raw 결과나 코드 조각은 `record_id: null`, 저장된 결과의 정확한 수정본을 가리킬 때는 그 수정본의 `record_id`를 넣습니다.

## 가설끼리는 어떻게 연결하나요?

- `parent_hypothesis_ids`: 바로 앞에서 새 가설을 만들게 한 부모들
- `source_primitive_match_id`: `origin=CHAINING` 가설을 만든 정확한 Primitive match

한 Primitive의 `result`가 다른 Primitive의 특정 `input`을 충족해 더 큰 공격 가능성을 찾아도 기존 결과를 수정하지 않습니다. Technical `ACCEPT`을 받은 upstream TRUE revision, downstream Primitive와 `matched_input_id`를 확인한 뒤 새로운 `origin=CHAINING` proposal과 `hypothesis_id`를 만들고 전체 검증을 다시 거칩니다. 현재 가설의 부모와 source match를 따라 조상 Primitive를 계산해 현재 match 후보에서 제외하므로 별도 root ID나 depth 숫자를 저장하지 않습니다. Verification이 별도 endpoint·sink·권한 경계를 발견한 경우에는 `origin=VERIFICATION` proposal을 사용합니다.

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
| 공통 실행 작업 상태 | `PENDING`, `READY`, `RUNNING`, `BLOCKED`, `SUCCEEDED`, `PARTIAL`, `FAILED`, `CANCELLED` | 아니요 |
| proposal 검증 상태 | `PROPOSED`, `SCHEMA_VALID`, `INVALID_OUTPUT` | 아니요. 아직 가설 번호가 없을 수 있음 |
| 등록된 가설 처리 상태 | `REGISTERED`, `ASSIGNED`, `VERIFYING`, `TERMINAL`, `FAILED` | 아니요. `FAILED`는 final 판정 없이 검증 절차가 끝난 상태 |
| 기술 판정 | `TRUE`, `FALSE`, `HOLD` | 예 |
| 동적 재현 상태 | `SUCCEEDED`, `FAILED`, `BLOCKED` | 아니요 |
| LLM 호출 상태 | `AUTH_REQUIRED`, `RATE_LIMITED`, `TIMED_OUT` | 아니요 |
| 기술 Gate | `ACCEPT`, `REVISE`, `REJECT` | 판정을 검토하지만 바꾸지 않음 |
| 정책·영향 Gate | `PASS`, `FAIL`, `UNCERTAIN`, `ALLOW`, `DENY` | 보고서 전달 조건 |
| 보고서 초안 상태 | `NOT_REQUESTED`, `DRAFTED`, `FAILED` | 아니요. 내부 초안 진행 상태 |
| 보고서 초안 | `NOT_REQUESTED`, `DRAFTED`, `FAILED` | 아니요. Reporter 작업 상태이며 `DRAFTED` 뒤 결과를 확정하고 자동화를 종료함 |

## DataGap과 AnalysisError의 차이

- `DataGap`: 분석하지 못했거나 일부만 확인한 범위입니다. 예: Git LFS 실제 파일 없음, 일부 SAST 실패, 잘린 코드 조회.
- `AnalysisError`: 작업이 정상적으로 끝나지 못한 사건입니다. 예: clone 실패, provider 인증 실패, sandbox 오류.

둘 다 자동으로 `TRUE`, `FALSE`, `HOLD`가 되지 않습니다. 오류는 “작업이 실패했다”는 기록이고, 취약점 판정 근거가 아닙니다. `FALSE`는 미리 정한 반증 질문과 실제 반증 근거가 연결될 때만 가능합니다.

각 반증 질문에는 `question_id`를 붙입니다. 최종 검증은 모든 질문에 결과를 남기며, 실제 근거가 있는 `DISPROVED` 질문이 하나 이상일 때만 `FALSE`를 허용합니다. `NOT_DISPROVED`는 질문으로 반증하지 못했다는 뜻이며 취약점이 증명됐다는 뜻이 아닙니다.

`SAVE_RESULT(result_kind=verification_result)`는 verdict별 최소 구조를 검사합니다. `TRUE`는 실제 reference가 연결된 supporting evidence, `FALSE`는 근거가 있는 `DISPROVED`, `HOLD`는 하나 이상의 `unresolved_conditions`와 정상적으로 확인한 범위를 설명하는 실제 evidence reference가 필요합니다. 오류·timeout·빈 Context·예산 초과 기록만으로 어떤 final verdict도 저장할 수 없습니다. Runtime Validator는 구조·reference·완료 상태만 검사합니다. final `TRUE` 근거의 의미적 충분성은 Technical Evidence Gate가 exact final TRUE revision을 대상으로 검토하며, `FALSE | HOLD`는 Technical Gate 입력이 아닙니다.

검증 플레이북은 `logical_record_id`로 식별하고 내용이 바뀔 때마다 새 `record_id`, 증가한 `revision_number`와 새 `content_hash`를 만듭니다. `VerificationResult.playbook_ref`는 실제 사용한 exact 플레이북 revision을 가리키며 final Verification 합성 호출과 저장 요청도 같은 reference를 사용해야 합니다. 새 플레이북 revision이 생겨도 과거 판정의 reference는 바꾸지 않습니다.

운영 검증의 Pro와 Con은 각각 `EvidenceAgentResult`라는 독립 결과를 만듭니다. final `VerificationResult`는 `pro_evidence_ref`와 `con_evidence_ref`로 두 결과를 정확히 하나씩 가리키고, `debate_input_hash`로 두 역할이 같은 가설·코드 사실·플레이북·설정·예산 기준을 받았는지 확인합니다. 부모 Verification, generation 또는 공통 입력이 다르면 두 결과를 섞을 수 없습니다.

운영 `ALWAYS_DEBATE`와 실제 Debate를 수행한 평가에서는 두 reference와 hash가 모두 필요합니다. 평가용 `BASIC` 또는 조건이 발생하지 않아 Debate를 생략한 평가에서는 세 값을 모두 비워 둡니다. 운영에서 한쪽 결과가 빠졌다면 `TRUE | FALSE | HOLD`를 만들지 않고, 다시 시도할 수 있으면 기다리고 그렇지 않으면 검증 실패로 끝냅니다.

이 연결 규칙은 기존 운영 결과의 허용 조건을 바꾸므로 새 MAJOR schema로 적용합니다. 예전 형식의 결과는 기록으로 남길 수 있지만 새 운영 결과처럼 자동 보완하거나 Gate로 보내지 않습니다.

정적 분석과 코드 조회 결과는 사용할 수 있는 사실뿐 아니라 도구별 실행 상태, 분석·제외 범위, `DataGap`, `AnalysisError`를 함께 전달합니다. `DataGap`은 영향받은 path·language·코드 위치를 가능한 범위에서 적습니다. 결과가 비어 있거나 일부 도구가 실패했다는 이유로 안전하다고 판단하지 않습니다.

### 검사 결과 0건과 미실행을 어떻게 구분하나요?

CodeQL·OpenGrep은 규칙별 실행 이력을 `RuleExecutionRecord`에 저장하고 `ToolRunResult`가 그 정확한 기록을 가리킵니다.

- `EXECUTED + hit_count=0`: 검사했지만 탐지 결과가 0건입니다.
- `NOT_EXECUTED`: 검사하지 않았습니다. 계획에서 제외했거나 실행하지 못한 이유를 함께 적습니다.
- `UNKNOWN`: 오류나 기록 부족으로 검사했는지 확인할 수 없습니다.

도구 오류나 timeout을 0건으로 바꾸지 않습니다. 다시 실행하면 새 `attempt_id`와 새 기록을 만들며 이전 결과와 합치지 않습니다. R2는 실행 기록을 만들고, R4의 Runtime Validator는 형식·참조·상태 조합을 검사하며, R8은 exact 기록으로 실행률과 평가 지표를 계산합니다. LLM Agent는 이 실행 이력을 만들거나 수정하지 않습니다.

Context 조회가 실패·timeout·권한 오류로 끝나면 실패 사건은 `AnalysisError`, 그 때문에 확인하지 못한 코드 범위는 `DataGap`으로 함께 남깁니다. 가설에는 해야 할 검증마다 고유 `validation_id`가 있고, 결과는 같은 ID로 완료 여부와 실제 근거를 답합니다. 일부 조회가 실패했더라도 재시도·대체 조회·다른 정상 근거로 모든 검증 항목과 운영 Pro/Con을 끝냈다면 실제 근거에 따라 `TRUE | FALSE | HOLD`를 저장할 수 있습니다. 하나라도 끝내지 못했다면 final `VerificationResult`를 만들지 않습니다. 다시 시도할 수 있으면 work를 `BLOCKED`로 두고 가설은 `VERIFYING`을 유지합니다. 더 시도할 수 없으면 work와 가설 처리 상태를 한 번에 `FAILED`로 끝내고 결과 reference는 비워 둡니다. 단순 조회 오류만으로 `HOLD`를 만들지 않습니다.

## 동적 재현 실패와 반증은 다릅니다

Docker 환경을 만들지 못했거나 실행이 timeout된 것은 재현 실패입니다. `status`는 실행 완료 정도이고 `hypothesis_outcome`은 관측이 가설을 지지했는지, 반증했는지, 결론을 주지 못했는지 나타냅니다. 둘 다 최종 판정이 아닙니다.

가설을 반증하려면 다음 네 가지가 함께 있어야 합니다.

1. `hypothesis_outcome: DISPROVED`
2. `hypothesis_disproved: true`
3. 실제 관측을 가리키는 `hypothesis_evidence_refs`
4. 그중 반증 관측을 가리키는 `disproof_evidence_refs`

빈 출력, exit code와 `FAILED | BLOCKED | CANCELLED`만으로는 가설을 `FALSE`로 바꿀 수 없습니다.

### 필요한 환경과 실제 환경을 어떻게 연결하나요?

R6 Verification은 `DynamicReproductionRequest`에 `POC_CONFIRMATION | VERDICT_EVIDENCE` 목적, 재현 목표·필요 환경·`sandbox_profile_ref`와 코드·정적·Pro·Con 근거를 적습니다. R7은 이 요청을 가리키는 `EnvironmentRequirements`, 실행 mode, `ReproductionPlan`과 PoC candidate를 만듭니다. `sandbox_profile_ref`는 Docker 보안 정책이므로 애플리케이션 환경 요구사항을 대신하지 않습니다.

R7은 실제 환경을 만든 뒤 `sandbox_environment.requirements_ref`에 같은 요구사항 수정본을 연결하고, 각 `requirement_id`에 `MATCH | MISMATCH | NOT_CHECKED | ERROR`, 실제 값 또는 artifact, 차이와 Health Check 결과를 기록합니다. 필수 항목이 모두 `MATCH`일 때만 공격 단계를 실행합니다. 환경이나 계획을 고치면 R7이 같은 request·동적 work의 새 attempt에서 새 requirements·plan을 만들고 Runtime Validator와 Sandbox Controller 검사를 다시 받아야 합니다.

credential·cookie·token·password 원문은 요구사항과 실제 값에 저장하지 않습니다. 필요한 비밀은 secret store의 불투명 `secret_ref`만 사용합니다.

### 동적 결과의 참조는 언제 비어 있나요?

- `poc_candidate_ref`: 실행 전에 만든 PoC 스크립트·입력입니다. 실패한 시도에도 남을 수 있으며 검증된 PoC가 아닙니다.
- `poc_ref`: `SUCCEEDED + SUPPORTED`로 재현에 성공한 exact candidate만 가리키는 validated PoC입니다. 그 밖의 상태·관측에서는 반드시 비어 있습니다.
- `runner_invoked`: Runner를 실제 호출했는지 나타냅니다. 거짓이면 `steps_ref`는 비어 있어야 하고, 참이면 첫 단계에서 실패해도 로그가 있어야 합니다.
- `environment_created`: 실제 환경이 만들어졌는지 나타냅니다. 거짓이면 `environment_ref`가 비어 있고, 참이면 실제 생성 환경과 요구사항별 비교 기록을 가리켜야 합니다. 실행 전 요구사항이나 Sandbox profile과는 다릅니다.
- `policy_decision_ref`: Controller가 어떤 정책 버전으로 왜 허용·차단했는지 가리킵니다. `POLICY_BLOCKED`이면 반드시 필요하며 Technical Gate의 판정과 다릅니다.
- `cleanup_required`: 정리할 자원이 생겼는지 나타냅니다. 거짓일 때만 `cleanup_status=NOT_REQUIRED`를 씁니다. 정책에 막혔더라도 임시 자원이 생겼다면 정리 결과를 성공 또는 실패로 남깁니다.

이 참조들은 같은 분석·코드·가설·Verification generation과 정확한 record revision에 속해야 합니다. R6 request와 R7 requirements·plan이 연결되고, R7 정책·실제 환경·PoC candidate·로그·정리 기록은 같은 동적 실행 attempt에서 연결됩니다. plan의 `environment_requirements_ref`와 실제 환경의 `requirements_ref`가 다르거나 다른 attempt의 자료를 섞으면 저장을 거절합니다. R4는 공통 연결 규칙을, R6는 요청과 최종 판정을, R7은 requirements·plan·실제 비교·PoC·환경·정책 판정·단계 로그를 정합니다.

Technical Gate는 현재 generation의 `SUCCEEDED + SUPPORTED` 동적 결과와 validated PoC가 있는 final `TRUE`만 입력으로 받습니다. `FALSE | HOLD`와 검증 실패 가설은 보내지 않습니다. Verification·동적 결과·PoC·CWE 중 하나가 수정되면 이전 Gate 승인을 재사용하지 않습니다. Rule Scope Gate와 보고서 초안도 같은 exact revision을 사용해야 합니다. `AnalysisError`에는 민감정보가 제거된 `safe_message`만 넣고 원본 오류는 별도 보호 저장소로 분리합니다.

Primitive도 exact revision을 사용합니다. HOLD는 final Verification의 부족 조건을 `inputs`에 넣고 `result=null`로 Gate 없이 저장합니다. TRUE는 validated PoC와 같은 revision을 검토한 Technical `ACCEPT` 뒤 제공 능력 하나마다 `result`가 있는 Primitive를 만들고, 그 TRUE의 입력 조건과 restrictions도 함께 보존합니다. Rule Scope 결과는 Reporter만 제어하며 Primitive admission을 취소하지 않습니다. `PrimitiveIndexState`는 current Verification과 Primitive refs만 가리키며 별도 전용 version은 두지 않습니다. 공통 `RecordMeta` revision과 원자적 current pointer 갱신으로 오래된 Chaining 결과를 거절합니다.

## 자주 쓰는 작은 데이터 구조

- `EvidenceClaim`: 찬성·반대 주장, 작성 역할, 실제 근거와 코드 위치를 한 묶음으로 저장합니다.
- `EvidenceAgentResult`: Pro 또는 Con 한쪽이 같은 공통 입력을 읽고 만든 독립 근거 결과입니다. 부모 Verification과 역할별 작업 ID를 함께 남깁니다.
- `VerificationPlaybook`: 취약점 검증에 사용할 사전 조건, 경로·방어 확인, 반증 질문, 근거 요구사항과 HOLD 조건을 묶은 versioned 절차입니다.
- `CandidateRef`: 아직 검증되지 않은 우회·대체 경로·영향 확대 후보입니다. 새 주장이면 별도 가설로 검증하기 전까지 확정 결과로 쓰지 않습니다.
- `VerificationMetrics`: debate의 token·시간·판정 변화와 새로 발견한 항목 수를 저장합니다. 제공되지 않은 token은 `null`입니다.
- `PolicyItem`: 공식 정책의 항목 하나와 원문을 다시 찾을 수 있는 출처 위치를 연결합니다.
- `PrimitiveDraft`: Primitive의 입력 조건이나 실행 결과 하나를 entity·저장소 권한 값·근거·설명으로 나타냅니다.
- `PrimitiveMatchCandidate`: upstream Primitive의 하나뿐인 `result`가 downstream Primitive의 `matched_input_id`를 충족하는지, 양쪽 exact record·부모·workspace·commit·근거와 함께 기록한 미검증 연결 후보입니다.

## 계약이 바뀌면 어떻게 하나요?

- `schema_version`은 `MAJOR.MINOR.PATCH` 형식입니다.
- 기존 의미와 호환되지 않으면 MAJOR가 바뀝니다.
- 이 문서의 enum 목록은 닫혀 있으므로 enum 값 추가·삭제·이름 변경도 MAJOR 변경입니다.
- 지원하지 않는 MAJOR는 추정해서 읽지 않습니다.
- 결과를 수정할 때 덮어쓰지 않습니다. `logical_record_id`는 유지하고 새 `record_id`와 다음 `revision_number`를 만듭니다.
- proposal 검증 record와 등록된 가설 record는 `proposal_ref`로 연결하지만 서로의 수정본으로 취급하지 않습니다.
- 잘못 연결된 revision은 `RECORD_REVISION_MISMATCH`로 거절합니다.

## 현재 검토 상태

R4-01의 공통 ID·상태·오류 계약은 PR #18 병합과 Issue #13 완료 처리로 기준 초안에 반영되었습니다. R4-02는 이 계약을 사용해 병렬 실행·중복 방지·재시도와 복구 의미를 추가합니다. 자세한 쉬운 설명은 [상태·병렬 실행·재시도·복구](state-and-recovery.md)를 확인하세요.
