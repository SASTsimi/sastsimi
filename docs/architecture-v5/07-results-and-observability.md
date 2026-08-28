# 07. 결과 저장과 관측성

- **이 문서는 무엇을 설명하나요?** 분석 결과, 오류, LLM 호출, 자원 사용과 디버깅 정보를 무엇을 저장할지 설명합니다.
- **누가 읽어야 하나요?** 데이터·평가·예산, 통합 개발과 PM 담당자가 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** 저장 영역, 공통 오류 이름, 품질·비용 지표와 보존 범위를 확인합니다.

`observability`는 실행 상태와 오류를 확인할 수 있는 기록을 뜻합니다. 자세한 용어는 [쉬운 용어집](../GLOSSARY.md)을 따릅니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## 목표

결론뿐 아니라 코드 준비가 성공했다면 어떤 `workspace_id`·`commit_id`·문맥·provider·session·도구·근거가 결론에 사용되었고, 준비 전 실패라면 어느 `analysis_id`에서 실패했는지를 재구성할 수 있어야 한다. 저장 계층은 판정을 생성하지 않는다.

## 논리 저장 영역

| 영역 | 내용 |
|---|---|
| `facts` | `StaticFactBundle`, `ToolRunResult`, 원본 AST/SAST refs, coverage, gaps와 errors |
| `hypotheses` | initial/child/chained proposal, validation state와 parent 관계 |
| `contexts` | `CodeContextRequest/Response`, 실제 반환·열람 위치 |
| `verifications` | Pro/Con, initial/final verdict, restriction/capability, CWE |
| `primitives` | HeldHypothesis, ConfirmedCapability와 match candidates |
| `research` | `ResearchResult`, new claim과 validation state |
| `gates` | Technical 및 Rule Scope Impact review와 Verification·CWELabel·정책 input revision refs |
| `policies` | 공식 `ProgramPolicyRecord`과 source refs |
| `reports` | 허용된 내부 `ReportDraft`와 두 Gate가 공통으로 본 CWELabel revision ref |
| `human_reviews` | `HumanReviewPacket`, 사람의 `HumanReviewDecision`과 외부 공개 action 기록 |
| `actions` | `ActionRequest`, validator의 `ActionDecision`, check와 일회성 사용·outcome refs |
| `invocations` | normalized `LLMInvocationLog`와 safe provider/session metadata |
| `dynamic` | sandbox 실행, PoC, output refs와 cleanup |
| `runs` | 전체 요약, `WorkExecutionState`·attempt·transition commit, 자원·오류·시간·debug event |

Primitive DB의 confirmed는 사람 승인 Finding이 아니며 held는 실행 queue가 아니다.

## LLM logging 경로

일반 경로는 `Agent Runtime → LLM Logging Proxy → LLMProviderAdapter`다. Logging Proxy는 호출 전후의 공개 가능한 요청·응답·tool trace를 정규화한다. Proxy를 적용하기 어려운 membership client는 다음 fallback을 사용한다.

```text
Raw provider session log
→ provider-specific parser
→ redaction
→ normalized LLMInvocationLog
```

raw log는 최소 권한과 짧은 보존 기간으로 다루며 parser 실패를 숨기지 않는다. 어느 경로도 hidden chain-of-thought를 수집하거나 추론해 저장하지 않는다.

## LLMInvocationLog

최소 추적 항목은 다음과 같다.

- `llm_call_id`, `analysis_id`, `hypothesis_id`, `attempt_id`와 역할
- provider profile, adapter와 model identifier
- `NEW | RESUME | AUTO` 요청값, 실제 결정과 parent session reference
- prompt template/version과 exposed request/response artifact refs
- 전달된 context refs와 실제 retrieved code locations
- 공개된 tool-call trace와 parsed structured output ref
- schema validation error와 repair attempt
- status, timeout, rate limit, auth requirement와 safe error
- provider가 공개한 token/usage 또는 `unavailable`
- elapsed time, 일반 retry의 `retry_of_llm_call_id`와 provider/model 전환의 `failover_from_llm_call_id`
- redaction 적용·실패 결과

retry/failover reference는 바로 앞 호출의 status가 `FAILED | INVALID_OUTPUT | TIMED_OUT | RATE_LIMITED | AUTH_REQUIRED`일 때만 유효하다. `SUCCEEDED | CANCELLED`를 선행 호출로 연결하거나 재인증·backoff·repair 같은 상태별 조건을 건너뛴 관계는 `INVOCATION_CHAIN_INVALID`로 기록하고 사용하지 않는다.

credential, cookie, reusable authorization header, 전체 browser profile, hidden reasoning과 불필요한 전체 코드 원문은 저장하지 않는다.

## 분석 및 비교 지표

### Hypothesis output

- 생성 proposal 수, schema-valid 비율
- repair retry와 `INVALID_OUTPUT` 수
- hypothesis당 observed fact/assumption/missing information 수

### Retrieval

- 요청·응답 수, relation query와 실제 조회 location 수
- depth/token budget, truncation과 unresolved gap
- 반복 request fingerprint와 `WORKSPACE_MISMATCH`

### Verification/debate

- BASIC/CONDITIONAL/ALWAYS 사용 수와 trigger/skip reason
- Pro/Con 및 종합 token·시간
- debate 전후 verdict 변화
- HOLD 해소, false-positive 감소 후보와 bypass 발견

### Research/chaining

- 호출·skip 이유, new claim 수와 재검증 결과
- REQUIRED/PROVIDED primitive와 match 수
- chain depth·duplicate·budget 제한 도달

### Gates/reporting

- Technical ACCEPT/REVISE/REJECT와 revision 원인
- Rule/Scope PASS/FAIL/UNCERTAIN, impact와 DENY 이유
- `ProgramPolicyRecord` 누락·오래된 정책 경고 상태
- Reporter 조건 통과/차단과 human decision

### Resources

- 역할·provider·model별 invocation, token/동등 usage와 elapsed time
- AST/SAST별 `SUCCEEDED | PARTIAL | FAILED | SKIPPED`, 실제 분석·제외 path/language와 coverage
- sandbox mode별 CPU/memory/disk/network/time와 cleanup

provider가 token이나 비용을 제공하지 않으면 추정치를 확정값처럼 표시하지 않고 metric source와 unavailable reason을 남긴다.

### 실행·복구 지표

- `work_type`별 `PENDING | READY | RUNNING | BLOCKED | SUCCEEDED | PARTIAL | FAILED | CANCELLED` 수와 체류 시간
- 같은 `dedupe_key` 요청을 기존 `work_id`로 돌려보낸 횟수
- `state_version` 충돌, 늦은 결과, 비활성 attempt와 취소 후 결과 거절 수
- retry·resume별 attempt 수와 최종 종료 원인
- `TransitionCommit`의 `PREPARED | COMMITTED | ABORTED` 수와 복구 시간
- 중단 뒤 재사용한 committed 결과, 다시 실행한 attempt와 `RECOVERY_FAILED` 수

### 권한·사람 검토 지표

- action type·요청 역할별 `ALLOW | DENY` 수와 실패한 `ActionCheck.reason_code`
- `ALLOW` decision의 `UNUSED | USED`, outcome 누락과 replay 거절 수
- `AUTHORITY_DENIED`, Gate 순서·Reporter·Sandbox·provider·file·disclosure 차단 수
- HumanReviewPacket의 report-ready/blocked 수와 누락된 policy·PoC·오류·HOLD 조건
- `DISCLOSE | REVISE | WITHHOLD | NEED_MORE_VALIDATION` 사람 결정 수

## 상태와 결과를 함께 저장하는 경계

작업 결과를 저장했다는 사실과 다음 단계가 그 결과를 사용할 수 있다는 사실은 다르다. 다음 단계는 `TransitionCommit.state=COMMITTED`이고 `WorkExecutionState.last_transition_commit_ref.record_id`가 그 COMMITTED revision을 가리키며 `output_refs`가 같은 결과 revision을 가리킬 때만 읽는다.

1. worker가 결과 record와 목표 상태를 제출한다.
2. runtime이 active attempt, `state_version`, `input_hash`, workspace·commit·hypothesis와 결과·gap·오류 reference를 확인한다.
3. 단일 transaction을 지원하면 결과·`StateTransition`·상태 pointer를 함께 확정한다.
4. 단일 transaction을 지원하지 않으면 `TransitionCommit=PREPARED`로 결과를 격리하고 현재 version·attempt·입력을 다시 검사한다.
5. state store가 현재 version·active attempt가 그대로라는 조건을 compare-and-set으로 확인하면서 unique `(work_id, target_state_version)` key의 `COMMITTED` marker를 append한다. 경쟁 중 하나만 성공하며, 그 뒤 marker 내용을 `WorkExecutionState`와 전문 상태 pointer에 투영한다.
6. 소비자는 COMMITTED marker와 pointer가 같은 output·gap·오류를 가리킬 때만 진행한다. marker 뒤 projection 전에 중단되면 recovery가 marker를 재적용한다.
7. version 충돌·취소·검증 실패는 `ABORTED`로 남기고 output을 최신 상태에 연결하지 않는다.

새 전이를 승인하기 전에는 같은 work의 다음 version에 남은 journal을 먼저 정리한다. `COMMITTED` marker가 있으면 이를 재투영하고 경쟁 요청은 version conflict로 거절한다. `PREPARED`가 있으면 복구 또는 `ABORTED`가 끝날 때까지 새 전이를 시작하지 않는다.

Verification work의 `SUCCEEDED`, `HypothesisProcessState.status=TERMINAL`과 final `VerificationResult.record_id`는 같은 atomic transition에 묶인다. Reporter work의 `SUCCEEDED`, `ReportProcessState.status=DRAFTED`와 `ReportDraft.record_id`도 같은 방식으로 묶인다. 두 Gate work는 각각 정확히 하나인 `TechnicalEvidenceReview`와 `RuleScopeImpactReview` revision을 output으로 가리킨다. 상태만 종료되었거나 결과만 저장된 경우에는 다음 단계와 분석 종료를 차단한다.

## 중복·늦은 결과와 격리

- 같은 `dedupe_key` 요청은 새 work를 만들지 않고 기존 `work_id`와 상태를 반환한다.
- 같은 work type과 가설에는 활성 attempt를 하나만 허용한다.
- 결과의 `attempt_id`가 현재 `active_attempt_id`와 다르면 `ATTEMPT_NOT_ACTIVE`다.
- 현재 state version·input hash·workspace·commit·hypothesis·record revision과 다르면 `STALE_RESULT`다.
- 취소 뒤 도착한 결과, 이미 합류가 끝난 이전 결과와 `ABORTED` output은 debug 격리 영역에 보존할 수 있지만 `facts`, `verifications`, `gates`, `reports`의 최신 pointer로 승격하지 않는다.
- 이미 확정된 결과에 새 근거를 반영해야 하면 기존 record를 덮어쓰지 않고 새 input revision, `dedupe_key`, `work_id`와 downstream revision을 만든다.

## 중단 후 재개

재개는 마지막 `COMMITTED` transition에서 시작한다.

| 발견한 상태 | 복구 행동 |
|---|---|
| 종료 상태와 정확한 output ref가 모두 `COMMITTED` | 완료 결과 재사용, 재실행 금지 |
| `RUNNING` attempt가 남고 commit 없음 | `INTERRUPTED` 오류와 실패 attempt 기록; 허용되면 새 attempt |
| `PREPARED` journal과 현재 version·attempt·input이 일치 | compare-and-set 조건의 unique `COMMITTED` marker append 후 pointer projection |
| `COMMITTED` marker는 있지만 pointer projection이 덜 됨 | 같은 marker를 멱등하게 다시 투영 |
| 미완료 journal이 있는데 새 전이가 요청됨 | 기존 journal을 먼저 복구·중단 처리하고 새 요청은 재평가 |
| `PREPARED` journal이 오래되었거나 취소됨 | `ABORTED`, output 격리 |
| 종료 상태지만 output ref가 없거나 존재하지 않음 | `TRANSITION_INCOMPLETE`, 다음 단계 차단 |
| output만 있고 상태 pointer가 없음 | journal로 복구하거나 `TRANSITION_INCOMPLETE`로 차단 |
| 안전한 자동 복구 여부를 판단할 수 없음 | `RECOVERY_FAILED`, 해당 범위 중단과 사람 확인 |

복구가 새 attempt를 만들면 이전 실패·중단 record를 유지하고 `trigger=RESUME`을 기록한다. 이미 `COMMITTED`된 결과를 재실행해 두 번 반영하지 않는다.

## AnalysisRunResult

최종 분석 결과에는 repository, nullable `commit_id`·`workspace_id`, `started_at`, `finished_at`, `elapsed_ms`, 초기·파생·chain·invalid hypothesis 수, verdict별 수, 두 Gate별 수, PoC/report refs, 공식 정책 상태, Research/Primitive 요약, LLM·static·sandbox 자원, work state·attempt·transition commit·action decision refs, 반복·예산 중단 이유, 모든 오류와 `RunStoredDataRef` debug trace를 포함한다. `COMPLETE | PARTIAL`이면 workspace·commit이 필수이고 clone·checkout 전 `FAILED | CANCELLED`이면 비어 있을 수 있다.

분석 종료 뒤 review packet assembler가 exact `AnalysisRunResult`에서 `HumanReviewPacket`을 만든다. packet은 Finding·Verification, 두 Gate, 정책·CWE, dynamic·redacted PoC, report 또는 차단 이유, 자원, 오류·DataGap·HOLD 조건과 LLM 호출·action decision·work state/attempt·transition commit·debug trace reference를 함께 보존한다. `HumanReviewDecision`은 이 packet과 별도 record이며 ReportDraft를 수정하지 않는다.

| 최종 상태 | 저장 조건 |
|---|---|
| `COMPLETE` | 필요한 work가 모두 종료되고 각 소비 대상 output의 `COMMITTED` marker와 상태 pointer가 일치함 |
| `PARTIAL` | 신뢰할 수 있는 결과가 하나 이상 있지만 일부 도구·가설·보완 work가 실패·제한되어 누락과 오류를 함께 저장함 |
| `FAILED` | clone/checkout 실패, workspace 기준 상실 또는 복구 실패로 신뢰 가능한 분석 결과를 만들 수 없음 |
| `CANCELLED` | 사용자가 전체 분석을 취소했고 새 work 생성을 중단했으며 이미 확정된 결과·오류는 보존함 |

일부 가설이 실패해도 나머지는 계속할 수 있고 분석은 `PARTIAL`로 끝날 수 있다. clone 또는 checkout에 실패하거나 작업공간이 바뀌어 코드 기준을 잃으면 전체 분석은 `FAILED`다. Agent·sandbox·policy fetch 오류는 `FALSE`로 변환하지 않는다. 전체 분석을 닫기 전에는 `RUNNING` work, 복구되지 않은 `PREPARED` journal과 결과 pointer가 없는 종료 상태가 없어야 한다.

## 단계별 실패·취소·부분 성공 전파

| 상황 | work 상태 | 가설·분석·다음 단계 영향 |
|---|---|---|
| clone·checkout 실패 | `FAILED` | 분석 `FAILED`, AST/SAST를 시작하지 않음 |
| 일부 AST/SAST 실패 | tool `FAILED`, normalize `PARTIAL` 가능 | `DataGap`과 오류를 포함하고 가설 분석 계속 가능 |
| 가설 Agent·Verification 오류 | retry 가능하면 `BLOCKED`, 아니면 `FAILED` | 다른 가설 계속, 해당 가설은 근거 없이 `FALSE`가 되지 않으며 분석 `PARTIAL` 가능 |
| provider 인증 필요 | `BLOCKED`, `waiting_for=AUTH` | 재인증 또는 승인된 failover 전까지 대기, verdict 변경 금지 |
| rate limit·timeout | retry 가능하면 `BLOCKED`, 아니면 `FAILED` | backoff·예산 확인 뒤 새 attempt, 이전 실패 보존 |
| Sandbox 환경·실행 실패 | `FAILED`와 실패 `DynamicReproductionResult` 가능 | 동적 반증이 아님, Verification이 남은 근거로 unresolved condition을 판단 |
| 정책 조회 실패 | policy work `FAILED` | 기술 verdict 유지, Rule Scope `UNCERTAIN + DENY`, Reporter 차단 |
| Technical Gate 실행 오류·보완 한도 초과 | Gate work `FAILED` | 기술 verdict 유지, Rule Scope Gate와 Reporter 차단 |
| Rule Scope Gate 실행 오류 | Gate work `FAILED` | 기술 verdict 유지, Reporter 차단 |
| 보고서 작성 실패 | report work·`ReportProcessState` `FAILED` | Verification과 두 Gate 결과 유지, 초안만 실패 |
| 개별 가설 취소 | 해당 미종료 work `CANCELLED` | 새 downstream work 금지, 다른 가설 계속 가능 |
| 전체 분석 취소 | 미종료 work `CANCELLED` | 새 work 생성 금지, 분석 `CANCELLED`, committed 결과 보존 |
| retry·Gate·chain·시간 예산 초과 | retry 가능하지 않으면 `FAILED` | 중단 이유·사용량·미해결 조건 저장, `FALSE` 변환 금지, 분석 `PARTIAL` 가능 |

## DataGap과 오류 분류

`DataGap`은 분석하지 못한 범위이고 `AnalysisError`는 실행 실패 사건이다. 둘 다 `created_at`을 UTC RFC 3339로 기록하며 자동으로 취약점 `FALSE`가 되지 않는다.

| code | 주 생산자 | 실행·상태에 미치는 영향 | 기본 복구 방향 |
|---|---|---|---|
| `INPUT_ERROR` | 입력 검증기 | 분석 시작 전 `FAILED` | 입력 수정 뒤 새 분석 |
| `CLONE_FAILED` | Repository Loader | 분석 `FAILED`, AST/SAST 미실행 | 네트워크·권한 확인 뒤 새 분석 |
| `CHECKOUT_FAILED` | Repository Loader | 분석 `FAILED`, AST/SAST 미실행 | 유효한 commit 확인 뒤 새 분석 |
| `WORKSPACE_MISMATCH` | runtime validator | 해당 record 사용 금지 | 올바른 workspace·commit 결과 재요청 |
| `WORKSPACE_CHANGED` | Repository Loader·validator | 분석 `FAILED`, 변경 뒤 결과 사용 금지 | 새 작업공간에서 새 분석 |
| `WORKSPACE_MISSING` | 코드 조회·runtime | 해당 작업 실패 | 보존 결과로 판단하거나 새 분석 |
| `STATIC_TOOL_ERROR` | AST/SAST runner | 사용 가능한 결과가 있으면 분석 `PARTIAL` 가능 | 제한 retry 또는 gap 보존 |
| `CONTEXT_RETRIEVAL_ERROR` | Context Retrieval Service | 오류와 누락 범위를 Verification에 전달 | 범위·요청을 고쳐 제한 retry; Verification Agent가 다른 근거와 함께 `HOLD` 여부 결정 |
| `INVALID_OUTPUT` | Agent Runtime | 해당 LLM 출력 사용 금지 | 제한 repair 뒤 종료 |
| `INVOCATION_CHAIN_INVALID` | Agent Runtime·log validator | retry/failover 관계 record 사용 금지 | 유효한 바로 앞 호출을 연결하거나 새 독립 호출로 다시 시작 |
| `AGENT_ERROR` | Agent Runtime | 해당 Agent 작업 실패 | 새 `attempt_id`로 제한 retry |
| `PROVIDER_ERROR` | provider adapter | LLM 호출 실패 | 명시적 retry·fallback |
| `AUTH_REQUIRED` | provider adapter | LLM 호출 중단 | 사용자 재인증 뒤 새 시도 |
| `RATE_LIMITED` | provider adapter | LLM 호출 지연·중단 | backoff 또는 명시적 fallback |
| `TIMED_OUT` | 각 runtime | 해당 작업 시간 초과 | 예산 안에서 새 시도 또는 중단 |
| `SANDBOX_ERROR` | Sandbox runtime | 동적 재현 `FAILED` | 안전 조건 확인 뒤 제한 retry |
| `RESEARCH_ERROR` | Research runtime | Research 실패, 부모 verdict 유지 | 제한 retry 또는 결과 없음 기록 |
| `TECHNICAL_GATE_ERROR` | Technical Gate runtime | 보고서 단계 차단 | Gate 재시도 또는 사람 확인 |
| `POLICY_FETCH_ERROR` | 정책 수집 계층 | 정책 Gate `UNCERTAIN + DENY` | 공식 출처 재확인 |
| `RULE_SCOPE_GATE_ERROR` | 정책·영향 Gate runtime | 보고서 단계 차단 | Gate 재시도 또는 사람 확인 |
| `REPORT_ERROR` | Reporter runtime | 초안 `FAILED`, 기술 판정 유지 | 조건 보존 후 초안 재작성 |
| `BUDGET_EXCEEDED` | Orchestration runtime | 작업 중단과 남은 검증 조건을 Verification에 전달; 분석은 `PARTIAL` 가능 | Verification Agent가 근거와 함께 가설 `HOLD` 여부를 결정하고, 새 예산 승인 뒤에만 재시도 |
| `CANCELLED` | 사용자·runtime | 해당 작업 또는 분석 `CANCELLED` | 자동 재시도 금지 |
| `SCHEMA_UNSUPPORTED` | schema validator | 해당 record 사용 금지 | 지원 schema로 다시 생성 |
| `RECORD_REVISION_MISMATCH` | record validator | revision 자동 병합 금지 | 올바른 이전 revision에서 재생성 |
| `STATE_TRANSITION_INVALID` | state transition validator | 허용하지 않은 상태 변경 거절 | 현재 상태에서 허용된 전이를 새로 요청 |
| `STATE_VERSION_CONFLICT` | state store | 동시 갱신 중 뒤늦은 전이 거절 | 최신 state version을 읽고 중복 여부 확인 |
| `ATTEMPT_NOT_ACTIVE` | state transition validator | 이전·다른 attempt 결과 사용 금지 | 최신 active attempt 결과만 사용 |
| `STALE_RESULT` | record·state validator | 취소·입력 변경·오래된 revision 결과 격리 | 새 입력 기준으로 새 work 생성 여부 판단 |
| `TRANSITION_INCOMPLETE` | recovery runtime | 결과와 종료 상태 중 하나만 있는 상태를 다음 단계에서 차단 | journal과 pointer를 복구하거나 abort |
| `RECOVERY_FAILED` | recovery runtime | 안전한 자동 복구가 불가능한 범위 중단 | 사람 확인 뒤 새 분석 또는 명시적 복구 |
| `INTERRUPTED` | recovery runtime | commit되지 않은 실행 attempt 실패 기록 | retryable·예산·취소 상태 확인 뒤 새 attempt |
| `AUTHORITY_DENIED` | runtime validator | 역할이 생산·호출할 수 없는 action 거절 | 허용 역할에서 새 action 요청 |
| `ACTION_NOT_ALLOWED` | runtime validator | action과 현재 전제 불일치로 실행 금지 | 요구 상태·입력·권한을 고쳐 새 요청 |
| `GATE_ORDER_INVALID` | runtime validator | 두 Gate 순서 또는 선행 exact ref가 맞지 않아 호출 금지 | Verification·CWE·Technical 결과 확정 뒤 새 요청 |
| `REPORT_NOT_READY` | runtime validator | Reporter 호출 금지, 기술 verdict 유지 | Rule Scope와 report 조건 보완 |
| `TOOL_NOT_ALLOWED` | tool validator | tool·command 실행 금지 | allowlist의 안전한 도구로 새 요청 |
| `FILE_ACCESS_DENIED` | path validator | workspace 밖 파일 접근 금지 | workspace 상대 허용 경로로 새 요청 |
| `SANDBOX_POLICY_DENIED` | Sandbox policy validator | 동적 실행 또는 network 변경 금지 | 승인된 image·network·resource profile 사용 |
| `PROVIDER_PROFILE_DENIED` | provider policy validator | LLM 호출·silent failover 금지 | 허용 profile과 explicit 새 action 사용 |
| `DISCLOSURE_DENIED` | disclosure validator | 외부 제출·공개 action 금지 | exact 사람 결정과 report-ready packet 확인 |
| `UNTRUSTED_INSTRUCTION` | prompt/action validator | 저장소·LLM 지시를 policy 변경으로 실행하지 않음 | data로 격리하고 승인된 설정만 사용 |

모든 `AnalysisError`에는 `stage`, `code`, `retryable`, 민감정보가 제거된 `safe_message`, 관련된 `work_id`·`attempt_id`, `related_record_ids`와 `created_at`을 남긴다. 실행 작업과 무관하면 두 실행 식별자는 `null`이다. 원본 오류는 일반 record에 복사하지 않고 별도 접근 통제·redaction·보존 정책이 적용된 결과로 분리한다. 표의 어떤 오류도 가설 `FALSE`를 직접 만들지 않는다.

상태 전이·version·active attempt 오류는 `stage=STATE`, 결과와 pointer 일부 저장은 `stage=STORAGE`, 재시작·journal 정리는 `stage=RECOVERY`, action 권한·실행 범위·공개 차단은 `stage=AUTHORITY`로 기록한다.

## Debug trace와 보존

trace는 상태 전이, 공개 가능한 rationale, `RunStoredDataRef`·`StoredDataRef`, tool event와 자원 사용을 시간순으로 연결한다. run 참조는 코드 근거로 승격하지 않는다. raw source·prompt·response·PoC는 민감도와 재현 필요성에 따라 별도 접근통제와 보존기간을 적용한다. 코드 전체 대신 저장소 상대 `CodeLocation`을 우선하고, 실제 credential·개인정보·session secret은 redaction 또는 저장 제외한다.
