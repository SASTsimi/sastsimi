# R6 구현 인계 문서

## 담당 범위

R6는 등록된 가설 하나의 Verification 흐름을 소유한다. Pro·Con을 독립 실행해 찬반 근거를 수집하고, initial assessment에서 동적 재현 필요 여부를 선택하며, R7에 동적 요청을 전달하고, 반환된 결과까지 종합해 `TRUE | FALSE | HOLD` 기술 판정을 만든다. Technical Gate가 `REVISE`를 반환하면 같은 ACTIVE owner가 새 generation에서 보완한다.

R6는 공개·제보 여부, CWE, Gate, Finding, 보고서, 동적 재현 계획·명령·PoC를 확정하지 않는다.

## 파일 위치

- Prompt 6개: `prompts/`
- 정상·실패·보안 경계 fixture: `samples/`
- 채점 기준: `evaluation-criteria.md`
- 전체 목록과 사용법: `README.md`

## 입력·출력 연결

| 단계 | 주요 입력 | R6 출력 | 다음 소비자 |
|---|---|---|---|
| Pro | assignment, hypothesis, facts/context, playbook | `EvidenceAgentResult(PRO)` | Verification |
| Con | Pro와 동일한 common input, 상대 결과 제외 | `EvidenceAgentResult(CON)` | Verification |
| Initial assessment | current Pro·Con, facts/context, playbook | `VerificationInitialAssessment` | R4 runtime routing |
| Dynamic request | assessment, current evidence, sandbox profile | `DynamicReproductionRequest` | R7 |
| Final verdict | current evidence, optional current dynamic/PoC | `VerificationResult` | FALSE/HOLD 결과 또는 R5 CWE/Technical Gate |
| Technical revise | previous result, Technical REVISE, 새 generation 전체 | 새 `VerificationResult` | R5 재검토 |

## Pro·Con join 조건

- 같은 analysis·workspace·commit·hypothesis·parent verification work·generation
- 같은 policy·playbook·application과 canonical common input
- 같은 `debate_input_hash`
- 서로 다른 template·call·session, 모두 `NEW`
- 두 결과 모두 COMMITTED
- 상대 역할 output·session·tool 결과가 다른 역할 입력에 없음

한쪽만 성공하거나 hash/reference가 다르면 합성하지 않는다. 오류는 verdict로 바꾸지 않는다.

## R6와 R7 경계

R6가 전달하는 값:

- `POC_CONFIRMATION | VERDICT_EVIDENCE` purpose
- current hypothesis·generation
- 재현 목표와 관찰 조건
- 필요한 환경 능력과 approved `sandbox_profile_ref`
- code/static/Pro/Con evidence reference

R7이 생산하는 값:

- `EnvironmentRequirements`, `ReproductionPlan`, recipe
- command, payload, PoC candidate와 실제 실행
- AgentLog, validated PoC, `DynamicReproductionResult`

## 판정 경계

- final TRUE: current generation의 exact request, `SUCCEEDED + SUPPORTED` dynamic result와 same-attempt validated PoC 필수
- FALSE: named falsification의 필수 조건이 실제 evidence로 DISPROVED
- HOLD: 필수 검증은 정상 완료했지만 중요한 조건이 부족·상충
- BLOCKED/FAILED: Context·provider·budget·Sandbox 등 실행을 완료하지 못한 상태이며 verdict 아님

## Runtime 인계

- Agent는 runtime-owned meta, record/work/attempt/call ID, content hash와 상태 전이를 생성하지 않는다.
- Prompt Registry/Builder가 slot projection, trust class, redaction과 exact reference를 고정한다.
- JSON Schema 실패 뒤 제한 repair를 할 수 있지만 role·input set·schema는 바꾸지 않는다.
- semantic-invalid, stale, mixed-reference output은 저장하지 않는다.
- PRODUCTION ACTIVE 전환에는 R8 평가 recommendation과 사람 승인이 필요하다.

## 미결정·교차 검토 요청

| 항목 | 확인 역할 |
|---|---|
| next-major output schema와 runtime-owned field 제외 범위 | R3, R4 |
| Pro·Con common slot set과 `debate_input_hash` 계산 구현 | R3, R4, R8 |
| `DynamicReproductionRequest` field와 R7 입력 호환성 | R4, R7 |
| same-attempt dynamic result·validated PoC 검증 기준 | R4, R7 |
| final TRUE와 CWE·Technical Gate 입력 closure | R5, R4 |
| corpus·grader·quality/time/usage/cost 기준과 retry 한도 | R8 |
| 첫 지원 취약점 유형과 exact PlaybookPolicy mapping | R6, R8, 사람 승인 |

위 항목은 이 handoff 자료에서 임의로 확정하지 않는다. 현재 파일의 logical schema·validator 이름은 승인 설계를 따르는 식별자이며 activation 때 exact stored reference로 교체한다.

## 권장 검토자

- R1: initial hypothesis·Chaining에서 들어오는 가설 경계
- R2: StaticFactBundle·CodeContextResponse projection
- R3: registry·template 형식·provider-neutral 통합
- R4: schema·exact ref·상태·저장·join validator
- R5: final TRUE·Technical REVISE 인계
- R7: dynamic request와 결과 provenance
- R8: fixture·예산·평가 기준
