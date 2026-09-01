# Agent 역할

## 쉽게 말하면

각 LLM Agent가 맡는 일과 직접 결정하면 안 되는 일을 한눈에 보여 줍니다. 프로그램 규칙 검사기와 사람의 최종 결정을 LLM Agent가 대신하지 않습니다.

**상세 기준:** [03. Agent 역할과 오케스트레이션](../03-agent-roles-and-orchestration.md)

모르는 단어는 [쉬운 용어집](../../GLOSSARY.md)에서 확인하세요.

| Agent | 쉽게 말한 핵심 책임 | 직접 할 수 없는 일 |
|---|---|---|
| Orchestration | proposal 검증·전역 가설 등록·Verification 배정 제안 | 가설 내부 Pro/Con·dynamic·Gate·Chaining 결정, runtime enforcement, Finding·공개 결정 |
| Hypothesis | schema-valid `HYPOTHESIS_ONLY` 제안 생성 | verdict, Finding, exploitability 확정 |
| Verification | 한 가설의 Context·Pro/Con, 환경 요구사항·동적 모드·`ReproductionPlan`, 환경 차이 수용·판정·Gate 보완·Chaining handoff와 material child 제안 | Sandbox 직접 실행·동적 결과 생산, runtime 검사 우회, 새 claim 무검증 승격 |
| Sandbox Controller | exact plan·requirements closure의 보안 정책을 검사하고 허용·차단 이유 저장 | 환경 요구사항·재현 필요성·모드·계획·최종 verdict 변경 또는 정책 미검사 실행 |
| Sandbox Runner | Controller가 승인한 exact 계획으로 환경 구성·요구사항 비교·Health Check 후 필수 일치 시 공격 단계 실행, 실제 환경·step log·PoC 사실 생산 | 환경 차이 임의 수용·허용되지 않은 fallback·정책 변경·계획 밖 명령 또는 최종 verdict 판단 |
| Sandbox Result Assembler | exact R6 plan closure와 같은 R7 실행 시도의 정책·환경 비교·log·PoC·정리 참조를 동적 결과로 조립 | reference 존재만으로 성공 판단, 다른 plan·requirements·실행 attempt 결과 혼합 |
| Pro | 가설 성립 근거 탐색 | 최종 verdict |
| Con | 반증·보호·도달 불가·restriction 탐색 | 최종 verdict |
| Chaining | Gate-qualified TRUE+HOLD·TRUE+TRUE Primitive matching과 새 가설 제안 | 일반 research, dynamic, REVISE, verdict/CWE/Gate/Finding/report 확정 |
| Technical Evidence Gate | verdict-evidence·코드/동적 연결·CWE·restriction 검토 | verdict 변경 |
| Rule Scope Impact Gate | 공식 rule/scope·금지 테스트·실제 impact·report permission 검토 | 공식 자료 없는 추정 승인 |
| Reporter | 통과한 근거로 내부 보고서 초안 작성 | 새 근거 확정, 제출·공개 |
| Human Reviewer | current `HumanReviewPacket`의 exact provenance를 검토하고 별도 결정을 기록 | Agent 결정 승인, 과거 packet 결정 재사용, 자동화에 외부 제출·공개 권한 위임 |

```text
Orchestration → Hypothesis proposal validation and registration → assign Verification
Verification → context → Pro and Con → EnvironmentRequirements and ReproductionPlan
Runtime Validator → commit exact requirements and plan → authorize Sandbox call
Sandbox Controller → store exact policy decision → Sandbox Runner compares actual environment
required MATCH → execute exact attack steps → result assembler → Verification final verdict
HOLD → REQUIRED Primitive → Chaining
TRUE → CWE → Technical Gate → Rule Scope Impact Gate
Gate-qualified TRUE → PROVIDED Primitive → Chaining
Verification or Chaining material claim → new hypothesis → new Verification
all report conditions → Reporter → Human
```

Human Review 자료의 canonical record는 공통 `HumanReviewPacket`이다. 프로그램은 Packet의 전체 reference set·exact current revision과 `ReportDraft`의 upstream closure를 검사하고, Human Reviewer는 주요 문장과 verified Evidence, restriction·counter evidence의 실제 대응을 확인한다. 현재 schema에는 문장별 claim mapping field가 없으므로 이를 자동 강제하지 않는다. 미검증 proposal은 confirmed provenance가 아니다. 보고서 근거가 부족하면 `report_ready=false`와 차단 사유를 안전한 packet에 담고, packet 자체에 secret·불필요한 PII·hidden private reasoning·stale reference가 있으면 준비를 거부한다. 빈 `finding_refs` 자체는 차단 사유가 아니다. Gate `ALLOW` → 내부 ReportDraft, `report_ready` → current packet의 draft 준비 여부, `HumanReviewDecision=DISCLOSE` → 사람 결정이며 실제 외부 action은 upstream current revision을 다시 확인하는 별도 권한 검사라는 경계를 유지한다.

각 역할은 공통 `LLMProviderAdapter`를 사용하며 역할 독립성이 필요한 조합은 NEW session을 기본으로 한다. 상세 경계는 [Agent 역할과 오케스트레이션](../03-agent-roles-and-orchestration.md)을 따른다.

모든 LLM 출력은 비신뢰 입력이다. 비-LLM Runtime Validator가 schema·호출 권한·상태 전이·예산·provider/session·Gate/Reporter 순서를 강제하고, Sandbox Controller가 image·command·file·network·resource·cleanup 정책을 전담한다.

배정은 ACTIVE `VerificationAssignment`로 저장한다. 같은 역할의 다른 Agent가 아니라 그 assignment의 논리 owner만 가설 내부 action과 `REVISE` 보완을 요청할 수 있다.
