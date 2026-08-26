# 5분 이해

## 핵심 변경

- 정적 분석은 취약점 판단기가 아니라 LLM이 사용할 사실 수집 계층이다.
- 저비용 Hypothesis Agent는 `HYPOTHESIS_ONLY / NON_FINAL` schema만 출력한다.
- 필요한 코드는 동일 snapshot에서 entity·location·path 기준으로 조회한다.
- Verification은 restriction, bypass, required/provided capability와 impact 후보까지 본다.
- 기본값은 `CONDITIONAL_DEBATE`이며 Pro/Con은 필요할 때 독립 NEW session으로 실행한다.
- `TRUE/HOLD`의 조건과 능력은 Primitive DB에서 연결하고 Research Agent가 새 가설 후보를 만든다.
- Technical Evidence Gate와 Rule Scope Impact Gate를 분리한다.
- 공식 프로그램 정책이 없으면 rule/scope는 `UNCERTAIN`, report permission은 `DENY`다.
- Membership session과 API는 공통 provider adapter의 선택지다.
- Reporter는 모든 조건을 통과한 내부 초안만 만들고 사람이 공개를 결정한다.

## 핵심 흐름

```text
Repository → Snapshot → AST and SAST → StaticFactBundle
→ constrained hypotheses → per-hypothesis Verification
→ on-demand context → BASIC or conditional Pro/Con → optional Docker
→ TRUE/FALSE/HOLD → Primitive DB and Research → new hypothesis loop
→ CWE → Technical Gate → Rule Scope Impact Gate
→ ReportDraft when allowed → Human decision
```

## 분리된 상태

| 질문 | 상태 |
|---|---|
| 가설이 성립하는가? | `TRUE | FALSE | HOLD` |
| 기술 근거가 연결되는가? | `ACCEPT | REVISE | REJECT` |
| 공식 rule/scope에 맞는가? | `PASS | FAIL | UNCERTAIN` |
| 실제 영향이 충분한가? | `SUFFICIENT | INSUFFICIENT | UNCERTAIN` |
| Reporter를 호출할 수 있는가? | `ALLOW | DENY` |
| 외부에 공개할 것인가? | 사람이 결정 |

상세 단계는 [전체 파이프라인](pipeline.md), 계약은 [경량 데이터 계약](../08-lightweight-data-contracts.md)을 따른다.
