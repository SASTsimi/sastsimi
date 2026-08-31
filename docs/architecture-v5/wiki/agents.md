# Agent 역할

## 쉽게 말하면

각 LLM Agent가 맡는 일과 직접 결정하면 안 되는 일을 한눈에 보여 줍니다. 프로그램 규칙 검사기와 사람의 최종 결정을 LLM Agent가 대신하지 않습니다.

**상세 기준:** [03. Agent 역할과 오케스트레이션](../03-agent-roles-and-orchestration.md)

모르는 단어는 [쉬운 용어집](../../GLOSSARY.md)에서 확인하세요.

| Agent | 쉽게 말한 핵심 책임 | 직접 할 수 없는 일 |
|---|---|---|
| Orchestration | proposal 검증·전역 가설 등록·Verification 배정 제안 | 가설 내부 Pro/Con·dynamic·Gate·Chaining 결정, runtime enforcement, Finding·공개 결정 |
| Hypothesis | schema-valid `HYPOTHESIS_ONLY` 제안 생성 | verdict, Finding, exploitability 확정 |
| Verification | 한 가설의 Context·Pro/Con, 동적 모드·`ReproductionPlan`, 판정·Gate 보완·Chaining handoff와 material child 제안 | Sandbox 직접 실행·동적 결과 생산, runtime 검사 우회, 새 claim 무검증 승격 |
| Sandbox Controller | exact `ReproductionPlan`의 image·명령·파일·네트워크·자원·정리 정책 검사 | 재현 필요성·모드·계획·최종 verdict 변경 또는 정책 미검사 실행 |
| Sandbox Runner | Controller가 승인한 exact 계획 실행, step log·동적 결과·PoC 생산 | 정책 변경, 계획 밖 명령 실행 또는 최종 verdict 판단 |
| Pro | 가설 성립 근거 탐색 | 최종 verdict |
| Con | 반증·보호·도달 불가·restriction 탐색 | 최종 verdict |
| Chaining | Gate-qualified TRUE+HOLD·TRUE+TRUE Primitive matching과 새 가설 제안 | 일반 research, dynamic, REVISE, verdict/CWE/Gate/Finding/report 확정 |
| Technical Evidence Gate | verdict-evidence·코드/동적 연결·CWE·restriction 검토 | verdict 변경 |
| Rule Scope Impact Gate | 공식 rule/scope·금지 테스트·실제 impact·report permission 검토 | 공식 자료 없는 추정 승인 |
| Reporter | 통과한 근거로 내부 보고서 초안 작성 | 새 근거 확정, 제출·공개 |
| Human Reviewer | current `HumanReviewPacket`의 exact provenance를 검토하고 별도 결정을 기록 | Agent 결정 승인, 과거 packet 결정 재사용, 자동화에 외부 제출·공개 권한 위임 |

```text
Orchestration → Hypothesis proposal validation and registration → assign Verification
Verification → context → Pro and Con → dynamic mode and ReproductionPlan
Runtime Validator → commit plan and authorize Sandbox call
Sandbox Controller → check detailed policy → Sandbox Runner executes exact plan
Sandbox Runner → return result → Verification final verdict
HOLD → REQUIRED Primitive → Chaining
TRUE → CWE → Technical Gate → Rule Scope Impact Gate
Gate-qualified TRUE → PROVIDED Primitive → Chaining
Verification or Chaining material claim → new hypothesis → new Verification
all report conditions → Reporter → Human
```

Human Review 자료의 canonical record는 공통 `HumanReviewPacket`이다. Packet은 `ReportDraft`와 exact upstream reference graph를 담아 주요 claim의 verified Evidence, final Verification, 두 Gate, CWE·official policy, Dynamic/PoC, restriction과 unresolved condition을 역추적하게 한다. 이는 새 claim-mapping field가 아니라 기존 reference graph의 semantic invariant다. 미검증 proposal은 confirmed provenance가 아니며 secret·불필요한 PII·hidden private reasoning 또는 stale reference가 있으면 packet 준비를 차단한다. 빈 `finding_refs` 자체는 차단 사유가 아니다. Gate `ALLOW` → 내부 ReportDraft, `report_ready` → current packet의 draft 준비 여부, `HumanReviewDecision=DISCLOSE` → 사람 결정이며 실제 외부 action은 별도 권한 검사라는 경계를 유지한다.

각 역할은 공통 `LLMProviderAdapter`를 사용하며 역할 독립성이 필요한 조합은 NEW session을 기본으로 한다. 상세 경계는 [Agent 역할과 오케스트레이션](../03-agent-roles-and-orchestration.md)을 따른다.

모든 LLM 출력은 비신뢰 입력이다. 비-LLM Runtime Validator가 schema·호출 권한·상태 전이·예산·provider/session·Gate/Reporter 순서를 강제하고, Sandbox Controller가 image·command·file·network·resource·cleanup 정책을 전담한다.

배정은 ACTIVE `VerificationAssignment`로 저장한다. 같은 역할의 다른 Agent가 아니라 그 assignment의 논리 owner만 가설 내부 action과 `REVISE` 보완을 요청할 수 있다.
