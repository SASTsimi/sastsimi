# 07. 결과 저장과 관측성

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## 목표

결론뿐 아니라 어떤 snapshot·문맥·provider·session·도구·근거가 결론에 사용되었고 어디서 실패했는지를 run과 hypothesis 단위로 재구성할 수 있어야 한다. 저장 계층은 판정을 생성하지 않는다.

## 논리 저장 영역

| 영역 | 내용 |
|---|---|
| `facts` | `StaticFactBundle`, 원본 AST/SAST artifact refs와 gaps |
| `hypotheses` | initial/child/chained proposal, validation state와 parent 관계 |
| `contexts` | `CodeContextRequest/Response`, 실제 반환·열람 위치 |
| `verifications` | Pro/Con, initial/final verdict, restriction/capability, CWE |
| `primitives` | HeldHypothesis, ConfirmedCapability와 match candidates |
| `research` | `ResearchResult`, new claim과 validation state |
| `gates` | Technical 및 Rule Scope Impact review와 revision |
| `policies` | 공식 `ProgramPolicySnapshot`과 source refs |
| `reports` | 허용된 `ReportDraft`와 human state |
| `invocations` | normalized `LLMInvocationLog`와 safe provider/session metadata |
| `dynamic` | sandbox 실행, PoC, output refs와 cleanup |
| `runs` | 전체 요약·자원·오류·시간·debug event |

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

- invocation/run/hypothesis/attempt/role id
- provider profile, adapter와 model identifier
- `NEW | RESUME | AUTO` 요청값, 실제 결정과 parent session reference
- prompt template/version과 exposed request/response artifact refs
- 전달된 context refs와 실제 retrieved code locations
- 공개된 tool-call trace와 parsed structured output ref
- schema validation error와 repair attempt
- status, timeout, rate limit, auth requirement와 safe error
- provider가 공개한 token/usage 또는 `unavailable`
- elapsed time, retry와 explicit failover relation
- redaction 적용·실패 결과

credential, cookie, reusable authorization header, 전체 browser profile, hidden reasoning과 불필요한 전체 코드 원문은 저장하지 않는다.

## 분석 및 비교 지표

### Hypothesis output

- 생성 proposal 수, schema-valid 비율
- repair retry와 `INVALID_OUTPUT` 수
- hypothesis당 observed fact/assumption/missing information 수

### Retrieval

- 요청·응답 수, relation query와 실제 조회 location 수
- depth/token budget, truncation과 unresolved gap
- 반복 request fingerprint와 snapshot mismatch

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
- 정책 snapshot 누락·stale 상태
- Reporter 조건 통과/차단과 human decision

### Resources

- 역할·provider·model별 invocation, token/동등 usage와 elapsed time
- AST/SAST 성공·부분 성공·실패와 coverage
- sandbox mode별 CPU/memory/disk/network/time와 cleanup

provider가 token이나 비용을 제공하지 않으면 추정치를 확정값처럼 표시하지 않고 metric source와 unavailable reason을 남긴다.

## AnalysisRunResult

최종 run 결과에는 repository/commit/snapshot, 시작·종료/총 시간, 초기·파생·chain·invalid hypothesis 수, verdict별 수, 두 Gate별 수, PoC/report refs, 공식 정책 상태, Research/Primitive 요약, LLM·static·sandbox 자원, 모든 오류와 debug trace를 포함한다.

일부 가설이 실패해도 나머지는 계속할 수 있고 run은 `PARTIAL`로 끝날 수 있다. snapshot 고정 실패처럼 모든 근거 기준을 잃는 오류는 전체 `FAILED`다. Agent·sandbox·policy fetch 오류는 `FALSE`로 변환하지 않는다.

## 오류 분류

- `INPUT_ERROR`
- `STATIC_TOOL_ERROR`
- `CONTEXT_RETRIEVAL_ERROR`
- `INVALID_OUTPUT`
- `AGENT_ERROR`
- `PROVIDER_ERROR`
- `AUTH_REQUIRED`
- `SANDBOX_ERROR`
- `RESEARCH_ERROR`
- `TECHNICAL_GATE_ERROR`
- `POLICY_SNAPSHOT_ERROR`
- `RULE_SCOPE_GATE_ERROR`
- `REPORT_ERROR`
- `BUDGET_EXCEEDED`
- `CANCELLED`

오류에는 stage, scope, retryable 여부, safe message, cause ref와 발생 시각을 남긴다.

## Debug trace와 보존

trace는 상태 전이, 공개 가능한 rationale, artifact reference, tool event와 자원 사용을 시간순으로 연결한다. raw source·prompt·response·PoC는 민감도와 재현 필요성에 따라 별도 접근통제와 보존기간을 적용한다. 코드 전체 대신 snapshot location reference를 우선하고, 실제 credential·개인정보·session secret은 redaction 또는 저장 제외한다.
