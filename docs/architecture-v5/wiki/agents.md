# Agent 역할

## 쉽게 말하면

각 LLM Agent가 맡는 일과 직접 결정하면 안 되는 일을 한눈에 보여 줍니다. 프로그램 규칙 검사기를 LLM Agent가 대신하지 않으며 자동화는 Reporter 초안 뒤에 끝납니다.

**상세 기준:** [03. Agent 역할과 오케스트레이션](../03-agent-roles-and-orchestration.md), [R3-05 Agent 프롬프트 구조](../implementation/05-prompt-runtime.md)

모르는 단어는 [쉬운 용어집](../../GLOSSARY.md)에서 확인하세요.

| Agent | 쉽게 말한 핵심 책임 | 직접 할 수 없는 일 |
|---|---|---|
| Orchestration | proposal 검증·중복 후보 조회·전역 가설 등록·Verification 배정 제안 | 중복 결론 생성, 가설 내부 Pro/Con·dynamic·Gate·Chaining 결정, runtime enforcement, Finding·공개 결정 |
| Hypothesis | schema-valid `HYPOTHESIS_ONLY` 제안과 후보가 있을 때 `HypothesisDuplicateReview` 생성 | 후보 목록 밖 중복 대상 선택, verdict, Finding, exploitability 확정 |
| Verification | 한 가설의 Context·Pro/Con, 목적별 `DynamicReproductionRequest`, 반환 결과 소비·판정·Gate 보완·Chaining handoff와 material child 제안 | 환경 요구사항·실행 계획·PoC·동적 결과 생산, Sandbox 직접 실행, 새 claim 무검증 승격 |
| R7 Agent | 환경 요구사항·간단한 계획·PoC 초안·동적 근거 해석, Sandbox 안의 자율 실행 | R6 요청 변경, 외부 경계 우회 또는 최종 verdict 판단 |
| R7 Setup Automation | recipe·image·container 생성/재사용/재생성과 정리 실제 수행 | Agent 분석, host/Docker 직접 권한 부여 또는 최종 verdict 판단 |
| Sandbox Controller | R7 `sandbox_profile_ref`의 외부 접근·격리와 CPU·RAM·disk·PID·요청 가능 최대 시간 강제 | 내부 command allowlist, R7 profile 값, R8 잔여 예산·새 attempt, 재현 전략 또는 최종 verdict 판단 |
| Reproduction Session Manager | 실제 event의 append-only AgentLog, same-attempt validated PoC와 동적 결과 확정 | Agent 호출·command·retry·cleanup 전략 결정 또는 다른 attempt 혼합 |
| Pro | 가설 성립 근거 탐색 | 최종 verdict |
| Con | 반증·보호·도달 불가·restriction 탐색 | 최종 verdict |
| Chaining | upstream Primitive 결과→downstream Primitive 입력 matching과 새 가설 제안 | 일반 research, dynamic, REVISE, verdict/CWE/Gate/Finding/report 확정 |
| R5-01 CWE Labeling | final TRUE를 exact CWE 분류 record로 정리 | Verification verdict 변경, 과거 label 재사용, Gate 판정 생성 |
| Technical Evidence Gate | verdict-evidence·코드/동적 연결·CWE·restriction 검토 | verdict 변경 |
| Rule Scope Impact Gate | 공식 rule/scope·금지 테스트·실제 impact·report permission 검토 | 공식 자료 없는 추정 승인 |
| Primitive Admission Runtime | Rule Scope의 금지 테스트 판정과 정책 수집 상태를 정해진 표로 바꿔 체이닝 재료 사용 허용·거절 | 정책 원문 재해석, Gate 결과 변경 |
| Reporter | 통과한 근거로 내부 보고서 초안 작성 | 새 근거 확정, 제출·공개 |

```text
Orchestration → proposal validation → runtime narrows duplicate candidates
Hypothesis → compare exact candidates when needed → registration or duplicate stop
Orchestration → assign Verification for registered hypotheses
Verification → context → Pro and Con → initial assessment
Initial assessment → PoC confirmation request / verdict evidence request / final FALSE or HOLD synthesis
R7 planning before Sandbox → dependency file contents → EnvironmentRequirements and simple ReproductionPlan
Runtime Validator → enforce one dynamic work per generation → authorize Sandbox call
Sandbox Controller checks external boundary → Setup Automation prepares recipe and clean environment
R7 Agent creates PoC candidate → structured Sandbox turns repeat inside the boundary → R7 conclusion
Session Manager checks conclusion against AgentLog and stores same-attempt result → Verification final verdict
HOLD + required candidates → inputs plus null result Primitive → Chaining
HOLD + no required candidates → no Primitive and no Chaining work
TRUE → R5-01 CWE_LABELING → current CWELabel → Technical Gate → policy and Rule Scope review
Technical-accepted TRUE → PrimitiveAdmissionDecision ALLOW → result Primitive → Chaining
Rule Scope review committed → trusted runtime normalizes current Finding (any review_status)
Verification or Chaining material claim → new hypothesis → new Verification
current Finding + all report conditions → Reporter → ReportDraft → AnalysisRunResult → Agent automation end
```

자동화 종료 뒤의 검토·수정·제출·공개는 이 Agent 목록 밖에서 사람이 수행합니다.

각 역할은 공통 `LLMProviderAdapter`를 사용하며 역할 독립성이 필요한 조합은 NEW session을 기본으로 한다. 상세 경계는 [Agent 역할과 오케스트레이션](../03-agent-roles-and-orchestration.md)을 따른다.

프롬프트가 필요한 역할은 Hypothesis, Pro, Con, Verification, R7 Agent, Chaining, CWE Labeling, Technical Gate, Rule Scope Gate, Reporter의 10개입니다. Orchestration은 화면과 문서에서 전체 조정 기능을 부르는 이름이지만, 실제 등록·중복 후보 축소·배정·상태·권한 관리는 정해진 프로그램이 수행하므로 별도 LLM 프롬프트를 만들지 않습니다.

프롬프트는 문장 파일만 두지 않습니다. “어느 역할의 어떤 작업인지, 어떤 입력만 읽는지, 어떤 형식으로 답해야 하는지”를 `PromptRegistryEntry`에 등록하고, 실제 호출마다 exact template과 입력으로 `PromptPayload`를 만듭니다. API 또는 구독 Provider를 바꿔도 이 논리 내용과 출력 형식은 같아야 합니다.

Verification은 Pro·Con 뒤 `ASSESS_INITIAL`로 PoC 확인, 판정용 동적 근거, 동적 실행 없는 final FALSE/HOLD 합성 중 하나를 고릅니다. 이 중간 결과는 final 판정이나 Gate 입력이 아닙니다. Chaining은 여러 current Primitive index와 가설·부모 ChainingResult 계보를 함께 받아 실제 조상 제외를 계산할 수 있어야 합니다.

R7의 requirements·plan 작성은 Sandbox 밖에서 tool 없이 수행합니다. Dockerfile·README·manifest·lockfile의 실제 redacted 내용과 조회 gap을 입력으로 받고, 외부 경계 허용 뒤에만 구조화된 Sandbox tool request를 한 번에 하나씩 반환합니다. Runtime이 container 안에서 실행하고 Session Manager가 기록합니다. 마지막 R7 conclusion과 동적 결과의 outcome·evidence·linkage·limitations가 다르면 저장하지 않습니다.

모든 LLM 출력은 비신뢰 입력이다. 비-LLM Runtime Validator가 schema·호출 권한·상태 전이·예산·provider/session·Gate/Reporter 순서를 강제한다. Runtime Validator는 `RUN_SANDBOX`의 exact request·current requirements·current exact plan과 두 profile revision을 고정합니다. Runtime Validator는 R8 lifecycle profile의 호출 전 잔여 시간·새 attempt 한도를 검사합니다. Sandbox Controller는 R7 `sandbox_profile_ref`의 host·Docker·mount/namespace·secret·egress·workspace 격리와 CPU·RAM·disk·PID·요청 가능 최대 시간을 강제하며 Sandbox 내부 command를 allowlist로 제한하지 않습니다.

배정은 ACTIVE `VerificationAssignment`로 저장한다. 같은 역할의 다른 Agent가 아니라 그 assignment의 논리 owner만 가설 내부 action과 `REVISE` 보완을 요청할 수 있다.

R5-01 `CWE_LABELING`은 final TRUE 뒤 별도 `CWE_LABEL` work로 실행합니다. label은 exact `VerificationResult`, generation, work와 LLM 호출을 가리킵니다. 새 Verification이 생기면 같은 CWE를 유지하더라도 새 label revision을 만들며 Technical Gate는 label을 수정하지 않습니다.
