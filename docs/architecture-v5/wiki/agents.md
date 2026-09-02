# Agent 역할

## 쉽게 말하면

각 LLM Agent가 맡는 일과 직접 결정하면 안 되는 일을 한눈에 보여 줍니다. 프로그램 규칙 검사기와 사람의 최종 결정을 LLM Agent가 대신하지 않습니다.

**상세 기준:** [03. Agent 역할과 오케스트레이션](../03-agent-roles-and-orchestration.md)

모르는 단어는 [쉬운 용어집](../../GLOSSARY.md)에서 확인하세요.

| Agent | 쉽게 말한 핵심 책임 | 직접 할 수 없는 일 |
|---|---|---|
| Orchestration | proposal 검증·전역 가설 등록·Verification 배정 제안 | 가설 내부 Pro/Con·dynamic·Gate·Chaining 결정, runtime enforcement, Finding·공개 결정 |
| Hypothesis | schema-valid `HYPOTHESIS_ONLY` 제안 생성 | verdict, Finding, exploitability 확정 |
| Verification | 한 가설의 Context·Pro/Con, 환경 요구사항·최소 `ReproductionPlan`, 판정·Gate 보완·Chaining handoff와 material child 제안 | Sandbox 직접 실행·동적 결과 생산, runtime 검사 우회, 새 claim 무검증 승격 |
| R7 Sandbox Controller | host·Docker daemon·secret·egress·다른 workspace·자원·lifecycle의 Sandbox 외부 경계 적용 | 내부 명령별 사전 허가, 환경 요구사항·최종 verdict 변경 또는 경계 미적용 실행 |
| Reproduction Agent | 격리 경계 내부에서 환경·package·계정/fixture/mock·PoC·명령·관찰·retry를 자율 수행하고 AgentLog와 동적 outcome 생산 | Sandbox 외부 접근, final `TRUE | FALSE | HOLD` 판단, 숨은 추론 기록 |
| Dynamic Result Finalizer | trusted runtime fact를 채우고 같은 attempt의 recipe·AgentLog·실행 PoC·cleanup·digest·redaction 연결 검사 | 동적 의미 재판단, 다른 attempt 혼합 또는 참조만으로 성공 판단 |
| Pro | 가설 성립 근거 탐색 | 최종 verdict |
| Con | 반증·보호·도달 불가·restriction 탐색 | 최종 verdict |
| Chaining | Gate-qualified TRUE+HOLD·TRUE+TRUE Primitive matching과 새 가설 제안 | 일반 research, dynamic, REVISE, verdict/CWE/Gate/Finding/report 확정 |
| Technical Evidence Gate | verdict-evidence·코드/동적 연결·CWE·restriction 검토 | verdict 변경 |
| Rule Scope Impact Gate | 공식 rule/scope·금지 테스트·실제 impact·report permission 검토 | 공식 자료 없는 추정 승인 |
| Reporter | 통과한 근거로 내부 보고서 초안 작성 | 새 근거 확정, 제출·공개 |
| Human Reviewer | 수정·추가 검증·보류·공개 결정 | — |

```text
Orchestration → Hypothesis proposal validation and registration → assign Verification
Verification → context → Pro and Con → EnvironmentRequirements and minimal ReproductionPlan
Runtime Validator → commit current references → authorize R7 call
R7 Controller → apply external boundary → Reproduction Agent works autonomously inside Sandbox
EnvironmentRecipe and AgentLog → executed PoC and observations → finalizer → Verification final verdict
HOLD → REQUIRED Primitive → Chaining
TRUE → CWE → Technical Gate → Rule Scope Impact Gate
Gate-qualified TRUE → PROVIDED Primitive → Chaining
Verification or Chaining material claim → new hypothesis → new Verification
all report conditions → Reporter → Human
```

각 역할은 공통 `LLMProviderAdapter`를 사용하며 역할 독립성이 필요한 조합은 NEW session을 기본으로 한다. 상세 경계는 [Agent 역할과 오케스트레이션](../03-agent-roles-and-orchestration.md)을 따른다.

모든 LLM 출력은 비신뢰 입력이다. 비-LLM Runtime Validator가 schema·호출 권한·상태 전이·예산·provider/session·Gate/Reporter 순서를 강제하고, Sandbox Controller가 image·command·file·network·resource·cleanup 정책을 전담한다.

배정은 ACTIVE `VerificationAssignment`로 저장한다. 같은 역할의 다른 Agent가 아니라 그 assignment의 논리 owner만 가설 내부 action과 `REVISE` 보완을 요청할 수 있다.
