# 5분 이해

## 쉽게 말하면

코드 도구가 사실을 모으고, LLM이 취약점 가능성을 제안·검증하며, 필요한 경우 Docker에서 재현합니다. 근거와 공식 정책을 모두 확인한 결과만 보고서 초안으로 만들고 결과를 저장한 뒤 Agent 자동화를 끝냅니다.

**상세 기준:** [Architecture v5 설계 허브](../README.md)와 [전체 시스템 개요](../01-system-overview.md)

모르는 단어는 [쉬운 용어집](../../GLOSSARY.md)에서 확인하세요.

## 핵심 변경

- 정적 분석은 취약점 판단기가 아니라 LLM이 사용할 사실 수집 계층이다.
- 저비용 가설 Agent는 ‘아직 최종 결과가 아님’을 뜻하는 `HYPOTHESIS_ONLY / NON_FINAL` 형식만 출력한다.
- 필요한 코드는 같은 `workspace_id`와 `commit_id`에서 코드 요소·위치·경로를 기준으로 조회한다.
- Orchestration은 가설을 검증·등록하고 Verification에 배정하는 데서 가설별 역할이 끝난다.
- 검증(`Verification`)은 한 가설의 Context·찬반, 동적 재현 목적 요청·결과 소비·판정·Gate 보완·연계 handoff를 관리한다. R7 Agent는 환경 요구사항·간단한 재현 전략·PoC candidate를 만들고 Sandbox 안에서 명령·관찰·재시도를 자율적으로 정한다. Setup Automation이 환경을 만들고 Session Manager가 실제 기록과 결과를 확정한다. 모든 final TRUE에는 재현 성공과 validated PoC가 필요하며, 생성·환경·실행 실패는 verdict 없이 `BLOCKED | FAILED`다.
- 운영 기본값은 `ALWAYS_DEBATE`이며 모든 유효 가설에서 Pro/Con을 독립 NEW session으로 실행한다. BASIC과 조건부 debate는 격리된 평가 전용이다.
- HOLD의 필요 조건은 `inputs`, 결과는 `null`인 Primitive로 즉시 저장한다. TRUE는 validated PoC와 Technical `ACCEPT`가 있는 exact revision만 `result`가 있는 Primitive가 된다. 한 Primitive의 result가 다른 Primitive의 특정 input을 충족할 때만 연결한다.
- 기술 근거 검토와 공식 정책·영향 검토를 분리한다.
- 공식 프로그램 정책이 없으면 rule/scope는 `UNCERTAIN`, report permission은 `DENY`다.
- Membership session과 API는 공통 provider adapter의 선택지다.
- Reporter는 모든 조건을 통과한 내부 초안을 만드는 마지막 Agent이며, 이후 사람 주도 과정은 자동화 밖이다.

## 핵심 흐름

```text
Repository → Repository Loader → CodeWorkspace → AST and SAST → StaticFactBundle
→ constrained hypotheses → trusted registration → Orchestration assigns Verification
→ Verification owns context → Pro/Con → POC_CONFIRMATION or VERDICT_EVIDENCE request
→ R7 requirements and simple plan → external boundary approval → autonomous Sandbox reproduction and AgentLog
→ supported success and validated PoC → Verification TRUE; disproof or inconclusive → FALSE/HOLD
→ HOLD inputs plus null result Primitive → Chaining
→ TRUE → CWE → Technical Gate → result Primitive → Chaining → new hypothesis loop
→ Technical ACCEPT → independent Rule Scope Impact Gate for report eligibility
→ ReportDraft when allowed → AnalysisRunResult → Agent automation end
```

## 분리된 상태

| 질문 | 상태 |
|---|---|
| 가설이 성립하는가? | `TRUE | FALSE | HOLD` |
| 기술 근거가 연결되는가? | `ACCEPT | REVISE | REJECT` |
| 공식 rule/scope에 맞는가? | `PASS | FAIL | UNCERTAIN` |
| 실제 영향이 충분한가? | `SUFFICIENT | INSUFFICIENT | UNCERTAIN` |
| Reporter를 호출할 수 있는가? | `ALLOW | DENY` |
| Agent 자동화는 어디서 끝나는가? | `ReportDraft`와 `AnalysisRunResult` 확정 뒤 종료 |

상세 단계는 [전체 파이프라인](pipeline.md), 계약은 [경량 데이터 계약](../08-lightweight-data-contracts.md)을 따른다.
