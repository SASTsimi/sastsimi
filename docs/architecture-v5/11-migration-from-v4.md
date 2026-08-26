# 11. v4에서 v5로의 설계 계보

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

> 이 문서는 비규범적 설계 계보와 향후 구현 migration 제안이다. 이 검토 저장소에는 v4 bundle이 포함되지 않으며 아래 비교가 v4 파일이나 구현의 존재를 의미하지 않는다.

## 전략

원본 프로젝트의 v4 자료는 과거 설계와 검토 이력을 위한 historical bundle로 취급한다. 이 저장소의 v5는 candidate baseline이며 v4의 Gate PASS, 구현 상태 또는 계약을 자동 승계하지 않는다.

## 유지하는 의미

| 유지할 의미 | v5 적용 |
|---|---|
| repository snapshot 고정 | facts, context, verdict, PoC를 같은 commit에 연결 |
| AST/SAST 정규화 | LLM이 사용할 entity/location/path/auth 사실 계층 |
| 역할 분리된 LLM 분석 | Hypothesis, Verification, Pro/Con, Research, 두 Gate, Reporter |
| 격리된 동적 검증 | Docker `LIMITED_REPRO | FULL_REPRO` |
| 조건부 연계 탐색 | Primitive DB match가 새 가설만 생성 |
| 사람의 공개 승인 | 자동 결과는 FindingCandidate/ReportDraft에 머묾 |
| 오류·근거·자원 보존 | normalized invocation과 run/debug records |

## 현재 설계로 승계하지 않는 것

- deterministic final Gate와 고정 점수 기반 취약점 판정
- LLM이 아닌 Gate만 최종 권위라는 정의
- Finding 전 필수 `ProofResolution`/proof-routing 서비스
- `TRUE + VERIFIED` 같은 무거운 이중 terminal state
- deterministic CWE authority
- queue 사용 여부 자체를 핵심 아키텍처 정체성으로 삼는 설명
- Hypothesis Registry 주변의 과도한 admission/CAS/receipt 구조
- 모든 artifact의 서명·digest·authority registry·fixture graph 의무화
- 대규모 계약·정책 정합성을 실제 Agent pipeline보다 앞세우는 방식

이 표현은 v4 역사 설명에 남을 수 있지만 v5의 current behavior로 해석하지 않는다.

## 역할 대응

| v4 또는 초기 v5 개념 | 수정 v5 |
|---|---|
| 자유 형식 Exploration | constrained low-cost Hypothesis Agent |
| Analyst/Skeptic quorum | Verification + 조건부 독립 Pro/Con |
| 선택 code fragment 전달 | same-snapshot on-demand location retrieval |
| Semantic Judge/Synthesis | bypass-aware Verification Agent |
| Proof Router/Resolver | VerificationResult의 evidence/gap/restriction |
| confirmed/held 목록 | REQUIRED/PROVIDED Primitive DB records |
| chaining 내부 탐색 | 별도 Research Agent + 새 가설 환류 |
| 하나의 LLM Gate | Technical Evidence Gate + Rule Scope Impact Gate |
| membership 중심 연결 | Membership/API 공통 `LLMProviderAdapter` |
| 암묵적 대화 유지 | configurable `NEW | RESUME | AUTO` |
| 호출 집계 | Logging Proxy/parser 기반 `LLMInvocationLog` |
| render-only report | 엄격한 두 Gate 조건 뒤 Reporter 초안 |

## 상태 대응

```text
v4 TRUE | FALSE | PENDING
→ v5 TRUE | FALSE | HOLD

초기 v5 Gate ACCEPT | REVISE | REJECT + ALLOW | DENY
→ TechnicalEvidenceReview ACCEPT | REVISE | REJECT
→ RuleScopeImpactReview PASS | FAIL | UNCERTAIN
  + rule_compliance PASS | FAIL | UNCERTAIN
  + scope_compliance PASS | FAIL | UNCERTAIN
  + security_impact SUFFICIENT | INSUFFICIENT | UNCERTAIN
  + report_permission ALLOW | DENY
```

과거 결과는 자동 변환하지 않는다. 같은 snapshot과 원문 근거를 확인해 새 record로 재검토해야 한다.

## 문서 경로 변경

- 이 저장소의 candidate baseline: `docs/architecture-v5/`
- 파생·비규범적 Wiki: `docs/architecture-v5/wiki/`
- v4 자료: 이 저장소에 복사하지 않으며 원본 프로젝트의 역사 자료로만 유지
- 초기 v5 `09-membership-llm-connection.md`는 범위가 확장되어 `09-llm-provider-session-and-logging.md`로 이름을 바꿨다.

이 v5는 아직 고정된 버전 계약이 아니므로 옛 09 경로를 active 문서로 유지하지 않는다. 저장소 내부 link는 새 경로를 사용한다.

## 구현 migration 순서 제안

1. snapshot, AST/SAST와 `StaticFactBundle`
2. Context Retrieval Service와 location audit
3. constrained Hypothesis output validation
4. Verification과 BASIC/CONDITIONAL debate
5. Docker LIMITED/FULL reproduction
6. Primitive DB와 Research loop
7. CWE와 Technical Evidence Gate
8. official `ProgramPolicySnapshot` 수집 경계와 Rule Scope Impact Gate
9. provider adapters, session policy와 Logging Proxy/parser
10. Reporter, result stores와 human review UI

각 단계는 구현 위협 모델, 평가 corpus, resource budget과 rollback을 별도 승인받는다. 현재 문서는 runtime migration 완료를 주장하지 않는다.
