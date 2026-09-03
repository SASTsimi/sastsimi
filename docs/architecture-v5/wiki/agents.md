# Agent 역할

## 쉽게 말하면

각 LLM Agent가 맡는 일과 직접 결정하면 안 되는 일을 한눈에 보여 줍니다. 프로그램 규칙 검사기를 LLM Agent가 대신하지 않으며 자동화는 Reporter 초안 뒤에 끝납니다.

**상세 기준:** [03. Agent 역할과 오케스트레이션](../03-agent-roles-and-orchestration.md)

모르는 단어는 [쉬운 용어집](../../GLOSSARY.md)에서 확인하세요.

| Agent | 쉽게 말한 핵심 책임 | 직접 할 수 없는 일 |
|---|---|---|
| Orchestration | proposal 검증·전역 가설 등록·Verification 배정 제안 | 가설 내부 Pro/Con·dynamic·Gate·Chaining 결정, runtime enforcement, Finding·공개 결정 |
| Hypothesis | schema-valid `HYPOTHESIS_ONLY` 제안 생성 | verdict, Finding, exploitability 확정 |
| Verification | 한 가설의 Context·Pro/Con, 환경 요구사항·최소 `ReproductionPlan`, 판정·Gate 보완·Chaining handoff와 material child 제안 | Sandbox 직접 실행·동적 결과 생산, runtime 검사 우회, 새 claim 무검증 승격 |
| Sandbox Controller | host·Docker daemon·secret·egress·다른 workspace·자원·lifecycle의 외부 경계 정책 결정·강제 | Sandbox 생성·폐기, Agent 호출, 내부 명령별 사전 허가 또는 최종 verdict 변경 |
| Reproduction Agent | 격리 경계 내부에서 환경·package·계정/fixture/mock·PoC·명령·관찰·retry를 자율 수행하고 동적 outcome 초안 생산 | Sandbox 외부 접근, final `TRUE | FALSE | HOLD` 판단, AgentLog·공식 결과 문서 변경 |
| Reproduction Session Manager | runtime/tool event를 수동 기록하고 Agent 초안과 실행 사실로 최종 결과 문서 확정 | Agent 호출·중단, command 허용·거절, 실행·retry·cleanup 결정 또는 동적 의미 재판단 |
| Pro | 가설 성립 근거 탐색 | 최종 verdict |
| Con | 반증·보호·도달 불가·restriction 탐색 | 최종 verdict |
| Chaining | Gate-qualified TRUE+HOLD·TRUE+TRUE Primitive matching과 새 가설 제안 | 일반 research, dynamic, REVISE, verdict/CWE/Gate/Finding/report 확정 |
| Technical Evidence Gate | verdict-evidence·코드/동적 연결·CWE·restriction 검토 | verdict 변경 |
| Rule Scope Impact Gate | 공식 rule/scope·금지 테스트·실제 impact·report permission 검토 | 공식 자료 없는 추정 승인 |
| Reporter | 통과한 근거로 내부 보고서 초안 작성 | 새 근거 확정, 제출·공개 |

```text
Orchestration → Hypothesis proposal validation and registration → assign Verification
Verification → context → Pro and Con → EnvironmentRequirements and minimal ReproductionPlan
Runtime Validator → commit current references → authorize R7 call
Sandbox Controller → decide and enforce external boundary policy → R7 setup automation creates clean Sandbox
Reproduction Agent works autonomously → runtime and tool events → Reproduction Session Manager records logs and final result document → Verification final verdict
HOLD → REQUIRED Primitive → Chaining
TRUE → CWE → Technical Gate → Rule Scope Impact Gate
Gate-qualified TRUE → PROVIDED Primitive → Chaining
Verification or Chaining material claim → new hypothesis → new Verification
all report conditions → Reporter → ReportDraft → AnalysisRunResult → Agent automation end
```

자동화 종료 뒤의 검토·수정·제출·공개는 이 Agent 목록 밖에서 사람이 수행합니다.

각 역할은 공통 `LLMProviderAdapter`를 사용하며 역할 독립성이 필요한 조합은 NEW session을 기본으로 한다. 상세 경계는 [Agent 역할과 오케스트레이션](../03-agent-roles-and-orchestration.md)을 따른다.

모든 LLM 출력은 비신뢰 입력이다. 비-LLM Runtime Validator가 schema·호출 권한·상태 전이·예산·provider/session·Gate/Reporter 순서를 강제하고, Sandbox Controller가 host·Docker daemon·secret·egress·resource·lifecycle의 외부 경계 정책만 전담한다. Sandbox 생성·cleanup은 R7 자동화가 수행하고 Reproduction Session Manager는 event 기록과 최종 문서화만 담당한다.

배정은 ACTIVE `VerificationAssignment`로 저장한다. 같은 역할의 다른 Agent가 아니라 그 assignment의 논리 owner만 가설 내부 action과 `REVISE` 보완을 요청할 수 있다.
