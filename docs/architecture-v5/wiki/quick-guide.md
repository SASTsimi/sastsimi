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
- 검증(`Verification`)은 한 가설의 Context·찬반, 환경 요구사항·동적 재현 모드·`ReproductionPlan`, 환경 차이 수용·판정·Gate 보완·연계 handoff를 관리한다. Runtime Validator는 exact requirements·plan과 Sandbox 호출 전제를 확인하고, R7 Controller가 세부 정책을 검사한다. Runner는 실제 환경을 요구사항과 비교하고 필수 항목이 맞을 때만 공격 단계를 실행해 결과를 반환한다.
- 운영 기본값은 `ALWAYS_DEBATE`이며 모든 유효 가설에서 Pro/Con을 독립 NEW session으로 실행한다. BASIC과 조건부 debate는 격리된 평가 전용이다.
- HOLD의 필요 조건은 즉시 REQUIRED가 된다. TRUE는 두 Gate를 정상 통과한 exact revision만 PROVIDED가 된다. TRUE+TRUE는 앞 PROVIDED가 뒤 TRUE의 exact 선행 조건을 충족할 때만 연결한다.
- 기술 근거 검토와 공식 정책·영향 검토를 분리한다.
- 공식 프로그램 정책이 없으면 rule/scope는 `UNCERTAIN`, report permission은 `DENY`다.
- Membership session과 API는 공통 provider adapter의 선택지다.
- Reporter는 모든 조건을 통과한 내부 초안을 만드는 마지막 Agent이며, 이후 사람 주도 과정은 자동화 밖이다.

## 핵심 흐름

```text
Repository → Repository Loader → CodeWorkspace → AST and SAST → StaticFactBundle
→ constrained hypotheses → trusted registration → Orchestration assigns Verification
→ Verification owns context → Pro/Con → EnvironmentRequirements and ReproductionPlan
→ runtime approval → R7 environment comparison → exact attack execution → Verification TRUE/FALSE/HOLD
→ HOLD REQUIRED → Chaining
→ TRUE → CWE → Technical Gate → Rule Scope Impact Gate
→ gate-qualified TRUE PROVIDED → Chaining → new hypothesis loop
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
