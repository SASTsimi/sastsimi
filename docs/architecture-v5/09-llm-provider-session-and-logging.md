# 09. LLM provider, session과 logging

- **이 문서는 무엇을 설명하나요?** 회원 로그인·API 방식의 LLM 연결, 로그인·대화 상태와 호출 기록 방법을 설명합니다.
- **누가 읽어야 하나요?** 단독 구현·통합 개발, PM과 데이터·평가 담당자가 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** 지원할 연결 방식, 새 대화·이어가기 규칙, 인증 실패와 기록 범위를 확인합니다.

`provider`는 LLM 서비스 연결 방식이고 `session`은 로그인 또는 대화 상태입니다. `logging`은 호출과 오류를 남기는 기록입니다. 자세한 용어는 [쉬운 용어집](../GLOSSARY.md)을 따릅니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## 목표

Agent 역할을 특정 로그인 방식이나 API에 결합하지 않고, provider별 인증을 공통 invocation 경계 뒤에 둔다. API provider는 공식 API/SDK 경계이며, membership session은 공식 지원·이용약관·동시성·session/log 가용성 검토를 통과해야 채택할 수 있는 **optional experimental adapter**다. 어느 방식도 아직 구현·검증 완료 또는 기본 provider로 선언하지 않는다.

## 연결 구조

```text
Agent Runtime
→ LLM Logging Proxy
→ LLMProviderAdapter
   ├─ MembershipSessionAdapter
   └─ APIProviderAdapter
```

Agent Runtime은 역할·structured-output 요구·context reference·budget·session policy를 요청한다. Adapter는 provider별 인증·호출·오류·usage를 공통 결과로 정규화한다. Logging Proxy는 양쪽에서 노출된 요청·응답·tool trace와 실제 선택을 `LLMInvocationLog`로 연결한다.

`REPRODUCTION_AGENT`도 같은 provider 경계를 사용하지만 두 종류의 log를 분리한다. `LLMInvocationLog`는 provider 호출·session·usage·노출된 tool trace를 기록하고, Reproduction Session Manager는 기존 runtime/tool 및 lifecycle event를 수동 수집해 R7 `AgentLog`에 실제 shell·파일/환경 변경·image build·PoC·관찰·retry·cleanup 사건을 기록한다. 어느 쪽도 hidden chain-of-thought를 요구하거나 복원하지 않는다.

## provider 호출 전 권한 검사

일반 Agent Runtime은 provider를 직접 호출하지 않고 `CALL_LLM` `ActionRequest`를 만든다. Technical Gate, Rule Scope Gate와 Reporter의 호출은 각각 `CALL_TECHNICAL_GATE`, `CALL_RULE_SCOPE_GATE`, `CREATE_REPORT_DRAFT` action이 LLM 실행까지 직접 허가하며 별도 `CALL_LLM`으로 우회하지 않는다. 모든 LLM 실행 action은 수정할 수 없는 exact `LLMCallSpec`을 입력으로 갖고 비-LLM Runtime Validator가 다음 `ActionCheck`를 수행한다.

- `SCHEMA`: 요청 형식, output schema와 필수 필드
- `AUTHORITY`: 신뢰 runtime이 붙인 실제 호출자 identity·등록 역할·요청 LLM 역할 일치
- `IDENTITY`·`REVISION`: analysis·hypothesis·workspace·commit·input record 일치
- `STATE`: current work, active attempt와 state version
- `BUDGET`: token·시간·retry·repair 한도
- `PROVIDER`: 허용 provider/model/profile과 adapter capability
- `SESSION`: NEW/RESUME/AUTO, parent session, retry/failover 선행 호출
- `REDACTION`: prompt와 context에 credential·절대 경로·금지 정보가 없는지

모든 check가 `PASS`인 `ActionDecision=ALLOW`를 runtime이 `USED`로 claim한 뒤에만 `LLMInvocationRequest`를 만든다. 요청의 `action_decision_ref`는 그 exact claim revision, `call_spec_ref`와 `provider_profile_ref`는 검사한 exact spec과 versioned provider profile revision을 가리킨다. runtime은 provider 호출 직전에 role·model·session·context·prompt·output schema·token budget·timeout이 spec과 모두 같은지 다시 검사한다. `LLMInvocationLog`도 같은 action decision·spec·profile ref를 보존한다. 다른 action, 이전 state version, retry 또는 failover에 같은 decision을 재사용하지 않는다.

저장소 텍스트나 LLM output이 provider·model·session mode·fallback·budget을 바꾸라고 요구해도 configuration 변경으로 해석하지 않는다. 요청된 값이 versioned provider policy와 다르면 `PROVIDER_PROFILE_DENIED` 또는 `UNTRUSTED_INSTRUCTION`으로 호출하지 않는다.

## 공통 adapter 책임

- provider profile과 model을 명시적으로 선택
- `LLMInvocationRequest`를 provider 호출로 변환
- structured response와 status를 공통 결과로 정규화
- timeout, cancellation, rate limit와 auth-required 전달
- provider가 공개한 usage만 출처와 함께 기록
- credential을 Agent prompt/result/log에서 제외
- retry와 failover를 새 `llm_call_id`로 식별하고 바로 앞의 허용된 실패 호출을 reference로 연결

provider/model을 조용히 바꾸는 failover는 금지한다. 허용된 fallback이 있더라도 원래 실패, 새 provider/model, 이유, 새 session과 결과를 별도 `llm_call_id`로 남긴다. 같은 provider/model의 일반 retry는 `retry_of_llm_call_id`, provider/model을 바꾸는 failover는 `failover_from_llm_call_id`로 바로 앞의 허용된 실패 호출을 가리킨다. 두 reference를 동시에 사용하지 않는다.

retry와 failover마다 새 `llm_call_id`의 `LLMCallSpec`, `ActionRequest`, `ActionDecision`과 `attempt_id`가 필요하다. 이전 ALLOW decision, spec 또는 provider 요청을 그대로 다시 보내는 것은 `ACTION_NOT_ALLOWED`다.

선행 호출 status는 다음과 같이 제한한다.

| 선행 status | 같은 provider/model retry | provider/model failover | 추가 조건 |
|---|---|---|---|
| `FAILED` | 허용 | 허용 | 오류와 전환 이유 기록 |
| `INVALID_OUTPUT` | 허용 | 허용 | 제한된 schema/semantic repair가 끝난 뒤 |
| `TIMED_OUT` | 허용 | 허용 | 남은 시간·시도 예산 확인 |
| `RATE_LIMITED` | 허용 | 허용 | retry는 backoff 뒤, failover는 허용된 fallback만 사용 |
| `AUTH_REQUIRED` | 재인증 뒤 허용 | 조건부 허용 | failover 대상 provider의 유효한 인증이 별도로 준비되어 있어야 함 |
| `SUCCEEDED` | 금지 | 금지 | 정상 결과 뒤의 새 작업은 독립 호출 |
| `CANCELLED` | 금지 | 금지 | 사용자가 다시 요청하면 독립 호출 |

retry/failover 선행 호출은 같은 분석·가설·역할의 바로 앞 호출이어야 한다. `SUCCEEDED`, `CANCELLED`, 존재하지 않는 호출, 더 이전 호출, 자기 자신과 이후 호출을 연결하면 `INVOCATION_CHAIN_INVALID`다.

LLM 호출은 상위 `WorkExecutionState`의 한 attempt 안에서 실행한다. 호출이 성공하면 runtime은 structured-output 검증과 output 저장을 끝낸 뒤에만 work를 `SUCCEEDED` 또는 다음 전문 상태로 확정한다. 재시도 가능한 호출 실패라면 `WorkAttempt.status=FAILED`와 `LLMInvocationLog`를 저장하고 work는 `BLOCKED`로 이동한다. `waiting_for` 조건을 충족한 뒤 `READY -> RUNNING`으로 새 `attempt_id`를 발급한다. 재시도할 수 없거나 한도를 모두 사용한 경우에만 work를 최종 `FAILED`로 끝낸다.

## MembershipSessionAdapter

현재 상태는 `EXPERIMENTAL / FEASIBILITY_REQUIRED`다. 아래 조건을 만족하기 전에는 supported runtime path로 표시하거나 운영 기본값으로 선택하지 않는다.

- 사용자가 공식적으로 로그인한 client/session을 사용할 수 있는 구현 경계
- password를 받거나 session credential을 Agent에 전달하지 않음
- session 만료·재인증 필요를 `AUTH_REQUIRED`로 반환
- provider client가 공개하는 범위에서 response와 usage 정규화
- 공식 지원·이용약관·조직 정책·동시성 제한을 구현 전에 확인

UI 자동화나 session 재사용이 공식 지원 범위 밖이라면 구현 완료로 표시하지 않는다. raw cookie, token, browser profile path를 결과에 포함하지 않는다.

## APIProviderAdapter

- 공식 API/SDK를 통한 호출 경계
- API key, service credential과 organization identifier는 secret manager 또는 승인된 실행 환경에서만 주입
- repository, fixture, prompt, report와 일반 log에 secret을 저장하지 않음
- provider/model/version, request id, 공개 usage와 rate-limit 상태 정규화
- key 부재는 membership adapter 선택과 별개의 configuration 상태

API 방식이 허용되어도 특정 provider를 기본값으로 확정하는 것은 별도 ADR 대상이다.

## SessionPolicy

각 invocation은 `NEW | RESUME | AUTO` 중 하나를 요청한다.

- `NEW`: 이전 대화 문맥을 상속하지 않는 새 session
- `RESUME`: 명시한 parent session을 계속 사용; adapter가 지원하지 않으면 오류 또는 명시적 새 호출로 처리
- `AUTO`: 역할·가설·작업 관계를 바탕으로 runtime policy가 선택

### AUTO 기본 규칙

| 관계 | 기본 결정 |
|---|---|
| 같은 역할·같은 가설의 추가 retrieval | `RESUME` 가능 |
| 같은 Verification의 Technical Gate revision 대응 | `RESUME` 가능 |
| 서로 다른 hypothesis | `NEW` |
| 같은 가설의 한 R7 동적 attempt 안에서 환경 수정·PoC 개선·재시도 | `RESUME` 가능 |
| 서로 다른 R7 가설 또는 attempt | `NEW` |
| Pro와 Con | `AUTO` 사용 금지, 각각 명시적 `NEW` |
| Verification과 Technical Gate | `NEW` |
| Technical Gate와 Rule Scope Impact Gate | `NEW` |
| Verification과 Chaining | `NEW` |
| Gate와 Reporter | `NEW` |

정책은 설정 가능하며 실제 결정, 이유, parent session reference를 기록한다. session reuse는 반복 context token을 줄일 수 있지만 confirmation bias와 prompt contamination을 키울 수 있으므로 품질·비용 평가 없이 광범위하게 적용하지 않는다.

Pro/Con 독립성은 설정으로 완화할 수 없는 예외다. 두 역할의 `CALL_LLM` action은 `requested_by`, call spec role과 일치해야 하고 action `session_mode=NEW`, spec `session_policy=NEW`, `parent_session_ref=null`이어야 `SESSION` check를 통과한다. 두 호출은 서로 다른 `llm_call_id`와 실제 `session_ref`, 각자의 action·decision을 사용한다. provider가 session ID를 노출하지 않아도 adapter가 호출별로 서로 다른 불투명 local `session_ref`를 만든다. retry·repair·failover도 같은 역할의 새 `NEW` session으로 만들고 상대 역할의 session·output·decision을 predecessor, parent 또는 context로 사용하지 않는다.

Pro/Con prompt는 trusted prompt builder가 역할별 template과 허용된 공통 입력 reference만 사용해 immutable `prompt_payload_ref`로 만든다. 두 역할은 같은 `debate_input_hash`를 공유하지만 서로의 `EvidenceAgentResult`, 결론, session, action/decision, work·attempt·call log를 `context_refs`, prompt payload, predecessor/parent, 결과 저장소 조회, retrieval/tool 요청이나 tool output으로 받을 수 없다. 호출 직전과 결과 저장 전에 이 경계를 검사하며 위반하면 `CROSS_ROLE_INPUT_DENIED`로 합류를 중단한다.

성공한 Pro/Con 호출의 `LLMInvocationResult.parsed_output_ref`와 `LLMInvocationLog.parsed_output_ref`는 각각 exact `EvidenceAgentResult(role=PRO | CON)` revision을 가리킨다. 해당 child work의 `output_refs`도 같은 result를 가리키며, result는 invocation record나 종료 work revision을 역참조하지 않는다. 부모 Verification의 final 합성 호출은 같은 부모·generation·`debate_input_hash`의 두 exact result reference만 context에 포함한다.

## 역할별 모델 선택

- Hypothesis Agent에는 저비용 모델 profile을 구성할 수 있다.
- Verification, Reproduction, Chaining과 두 Gate에는 과업 위험도에 맞는 별도 상위 model profile을 구성할 수 있다.
- Reproduction Agent profile은 shell·file·service·HTTP·DB·PoC tool 사용과 structured `DynamicReproductionResult` 초안을 지원해야 한다. Sandbox 외부 권한은 model profile이 아니라 Sandbox Controller가 강제한다.
- 특정 역할의 가격 등급이 정확도를 보장하지 않는다.
- 모델·provider 변경은 versioned configuration과 evaluation 대상으로 관리한다.

## Logging Proxy와 fallback parser

Logging Proxy는 다음만 기록한다.

- exposed request/response artifact reference
- provider/model/role/session metadata
- 실제 전달된 context와 retrieved code locations
- exposed tool-call trace
- parsed output exact reference, schema error와 repair attempt
- status, 공개 usage, elapsed, retry/failover relation
- redaction 결과

membership client에 proxy를 안정적으로 배치할 수 없으면 `raw session log → provider-specific parser → redaction → normalized LLMInvocationLog` fallback을 사용한다. raw log 접근 권한과 보존기간을 최소화하고 parser 버전·누락·실패를 기록한다.

hidden chain-of-thought를 요구·수집·복원하지 않는다. 사용자에게 노출된 응답과 tool trace만 저장 대상으로 삼는다.

## 인증·오류 lifecycle

LLM 호출 상태는 `SUCCEEDED | FAILED | INVALID_OUTPUT | TIMED_OUT | RATE_LIMITED | AUTH_REQUIRED | CANCELLED`다. 이 상태는 provider 호출의 결과이며 취약점 가설의 `TRUE | FALSE | HOLD`와 별개다.

| 호출 상태 | 쉬운 의미 | Orchestration 처리 |
|---|---|---|
| `SUCCEEDED` | 호출과 공통 형식 변환이 끝남 | schema·semantic 검증 후 다음 단계 진행 |
| `FAILED` | provider 또는 adapter가 호출을 끝내지 못함 | 오류 저장, 허용된 retry 검토 |
| `INVALID_OUTPUT` | 응답은 왔지만 요구한 형식·의미 검사를 통과하지 못함 | 제한 repair 뒤에도 실패하면 해당 출력 사용 금지 |
| `TIMED_OUT` | 정해진 시간 안에 끝나지 않음 | 새 `attempt_id`의 retry 또는 중단 |
| `RATE_LIMITED` | provider 호출량 제한에 걸림 | backoff 또는 명시적 fallback |
| `AUTH_REQUIRED` | 로그인·키·session이 없거나 만료됨 | 재인증 필요 상태로 반환 |
| `CANCELLED` | 사용자 또는 runtime이 취소함 | 취소 기록 후 실행 종료 |

1. Runtime이 adapter capability와 인증 사용 가능 여부를 확인한다.
2. 호출할 수 없으면 `AUTH_REQUIRED` 또는 명시적 provider error를 반환한다.
3. Orchestration은 어떤 LLM 호출 상태도 가설 `FALSE`로 바꾸지 않는다.
4. 제한 retry, 사용자 재인증 또는 구성된 explicit fallback을 선택한다.
5. 모든 시도는 독립 `llm_call_id`와 `attempt_id`로 저장하고 같은 논리 요청의 `work_id`·`dedupe_key`는 유지한다.
6. retry 가능한 실패는 work를 `BLOCKED`로 두고 `FAILED` attempt와 오류를 보존한다. `AUTH_REQUIRED`는 재인증, `RATE_LIMITED`는 backoff, `INVALID_OUTPUT`은 제한된 repair 조건을 `waiting_for`와 함께 기록한다.
7. 조건을 충족하면 work를 `READY`로 전환하고 새 `attempt_id`에서 후속 호출을 시작한다. 후속 호출은 위 표에서 허용한 바로 앞의 실패 호출 reference와 1씩 증가하는 `retry_count`를 저장하며, runtime은 status·같은 분석·가설·역할·호출 순서와 순환이 없는지 검사한다.
8. work나 분석이 `CANCELLED`이면 도착한 응답을 `STALE_RESULT`로 격리하고 output pointer, Gate와 Reporter 입력에 연결하지 않는다.

인증·rate limit·형식·provider 오류가 발생한 `LLMInvocationResult`는 실행 오류다. 그 호출만을 이유로 `SAVE_RESULT` action이 `VerificationResult.verdict=FALSE`를 만들려고 하면 Runtime Validator가 거절한다. `FALSE`는 final Verification의 named falsification과 실제 `DISPROVED` 근거가 있을 때만 별도로 저장할 수 있다.

동시성·rate limit의 backpressure도 취약점 판정과 분리한다.

## 구현 전 검토 항목

- provider별 공식 지원과 이용약관
- membership/API credential 저장·회전·폐기 방식
- session resume 지원 여부와 session identifier 민감도
- structured-output/tool-call 차이
- raw log parser의 안정성·redaction·retention
- 역할별 비용/정확도, session reuse와 debate 정책의 실험 결과
