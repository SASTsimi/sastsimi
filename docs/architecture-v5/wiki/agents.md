# Agent 역할

## 쉽게 말하면

각 LLM Agent가 맡는 일과 직접 결정하면 안 되는 일을 한눈에 보여 줍니다. 프로그램 규칙 검사기와 사람의 최종 결정을 LLM Agent가 대신하지 않습니다.

**상세 기준:** [03. Agent 역할과 오케스트레이션](../03-agent-roles-and-orchestration.md)

모르는 단어는 [쉬운 용어집](../../GLOSSARY.md)에서 확인하세요.

| Agent | 쉽게 말한 핵심 책임 | 직접 할 수 없는 일 |
|---|---|---|
| Orchestration | run·가설 lifecycle과 다음 action 제안·조정 | runtime enforcement, Finding·공개 결정 |
| Hypothesis | schema-valid `HYPOTHESIS_ONLY` 제안 생성 | verdict, Finding, exploitability 확정 |
| Verification | 위치 기반 근거와 동적 결과 종합, verdict·restriction·capability 기록 | 새 claim 무검증 승격 |
| Pro | 가설 성립 근거 탐색 | 최종 verdict |
| Con | 반증·보호·도달 불가·restriction 탐색 | 최종 verdict |
| Research | bypass·alternate path·impact·chain 후보 제안 | verdict/CWE/Gate/Finding/report 확정 |
| Technical Evidence Gate | verdict-evidence·코드/동적 연결·CWE·restriction 검토 | verdict 변경 |
| Rule Scope Impact Gate | 공식 rule/scope·금지 테스트·실제 impact·report permission 검토 | 공식 자료 없는 추정 승인 |
| Reporter | 통과한 근거로 내부 보고서 초안 작성 | 새 근거 확정, 제출·공개 |
| Human Reviewer | 수정·추가 검증·보류·공개 결정 | — |

```text
Orchestration → Hypothesis → Verification per hypothesis
Verification → optional Pro and Con → optional Docker
Verification TRUE/HOLD → Primitive DB and Research → new hypothesis
Verification → CWE → Technical Gate → Rule Scope Impact Gate
all report conditions → Reporter → Human
```

각 역할은 공통 `LLMProviderAdapter`를 사용하며 역할 독립성이 필요한 조합은 NEW session을 기본으로 한다. 상세 경계는 [Agent 역할과 오케스트레이션](../03-agent-roles-and-orchestration.md)을 따른다.

모든 LLM 출력은 비신뢰 입력이다. 비-LLM trusted runtime validator가 schema·상태 전이·예산·sandbox·provider/session·Gate/Reporter 순서를 실제로 강제한다.
