# Agent 역할

## 쉽게 말하면

각 LLM Agent가 맡는 일과 직접 결정하면 안 되는 일을 한눈에 보여 줍니다. 프로그램 규칙 검사기를 LLM Agent가 대신하지 않으며 자동화는 Reporter 초안 뒤에 끝납니다.

**상세 기준:** [03. Agent 역할과 오케스트레이션](../03-agent-roles-and-orchestration.md)

모르는 단어는 [쉬운 용어집](../../GLOSSARY.md)에서 확인하세요.

| Agent | 쉽게 말한 핵심 책임 | 직접 할 수 없는 일 |
|---|---|---|
| Orchestration | proposal 검증·중복 후보 조회·전역 가설 등록·Verification 배정 제안 | 중복 결론 생성, 가설 내부 Pro/Con·dynamic·Gate·Chaining 결정, runtime enforcement, Finding·공개 결정 |
| Hypothesis | schema-valid `HYPOTHESIS_ONLY` 제안과 후보가 있을 때 `HypothesisDuplicateReview` 생성 | 후보 목록 밖 중복 대상 선택, verdict, Finding, exploitability 확정 |
| Verification | 한 가설의 Context·Pro/Con, 목적별 `DynamicReproductionRequest`, 반환 결과 소비·판정·Gate 보완·Chaining handoff와 material child 제안 | 환경 요구사항·실행 계획·PoC·동적 결과 생산, Sandbox 직접 실행, 새 claim 무검증 승격 |
| R7 Agent | 환경 요구사항·간단한 계획·PoC 초안·동적 근거 해석, Sandbox 안의 자율 실행 | R6 요청 변경, 외부 경계 우회 또는 최종 verdict 판단 |
| R7 Setup Automation | recipe·image·container 생성/재사용/재생성과 정리 실제 수행 | Agent 분석, host/Docker 직접 권한 부여 또는 최종 verdict 판단 |
| Sandbox Controller | host·Docker·mount/namespace·secret·egress·workspace·resource/lifecycle 외부 경계 검사 | 내부 command allowlist, 재현 전략 또는 최종 verdict 판단 |
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
Verification → context → Pro and Con → DynamicReproductionRequest
R7 planning → EnvironmentRequirements and simple ReproductionPlan
Runtime Validator → enforce one dynamic work per generation → authorize Sandbox call
Sandbox Controller checks external boundary → Setup Automation prepares recipe and clean environment
R7 Agent creates PoC candidate and autonomously runs it → Session Manager stores AgentLog and same-attempt result → Verification final verdict
HOLD → inputs plus null result Primitive → Chaining
TRUE → R5-01 CWE_LABELING → current CWELabel → Technical Gate → policy and Rule Scope review
Technical-accepted TRUE → PrimitiveAdmissionDecision ALLOW → result Primitive → Chaining
Verification or Chaining material claim → new hypothesis → new Verification
all report conditions → Reporter → ReportDraft → AnalysisRunResult → Agent automation end
```

자동화 종료 뒤의 검토·수정·제출·공개는 이 Agent 목록 밖에서 사람이 수행합니다.

각 역할은 공통 `LLMProviderAdapter`를 사용하며 역할 독립성이 필요한 조합은 NEW session을 기본으로 한다. 상세 경계는 [Agent 역할과 오케스트레이션](../03-agent-roles-and-orchestration.md)을 따른다.

모든 LLM 출력은 비신뢰 입력이다. 비-LLM Runtime Validator가 schema·호출 권한·상태 전이·예산·provider/session·Gate/Reporter 순서를 강제한다. Sandbox Controller는 host·Docker·mount/namespace·secret·egress·workspace·resource/lifecycle 같은 외부 격리 경계를 강제하며 Sandbox 내부 command를 allowlist로 제한하지 않는다.

배정은 ACTIVE `VerificationAssignment`로 저장한다. 같은 역할의 다른 Agent가 아니라 그 assignment의 논리 owner만 가설 내부 action과 `REVISE` 보완을 요청할 수 있다.

R5-01 `CWE_LABELING`은 final TRUE 뒤 별도 `CWE_LABEL` work로 실행합니다. label은 exact `VerificationResult`, generation, work와 LLM 호출을 가리킵니다. 새 Verification이 생기면 같은 CWE를 유지하더라도 새 label revision을 만들며 Technical Gate는 label을 수정하지 않습니다.
