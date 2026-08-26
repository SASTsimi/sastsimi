# SASTSIMI

SASTSIMI는 AST·SAST가 수집한 코드 사실을 LLM Agent가 가설화하고, 검증·동적 재현·근거 검토를 거쳐 사람이 최종 공개 여부를 판단하는 **LLM 중심 차세대 SAST 연구 프로젝트**입니다.

이 저장소는 현재 실행 가능한 제품을 배포하기 위한 저장소가 아니라, 팀이 구상한 전체 시스템을 구현하기 전에 각 파트의 책임·입출력·오류·보안 경계와 데이터 계약을 함께 검토하고 확정하기 위한 설계 협업 공간입니다.

## 현재 단계

```text
DESIGN_AUTHORED
REVIEW_REQUIRED
NOT_IMPLEMENTED
```

- v5 설계 초안은 작성되었습니다.
- 각 파트 담당자가 자신의 영역과 인접 계약을 검토하는 단계입니다.
- 설계 검토가 끝나기 전에는 Architecture PASS, 구현 완료 또는 runtime-ready를 주장하지 않습니다.
- 자동 분석 결과를 외부에 제출하거나 공개하지 않습니다. 최종 공개 여부는 사람이 결정합니다.

## 현재 목표

첫 번째 목표는 코드를 바로 구현하는 것이 아니라 다음을 먼저 완성하는 것입니다.

1. LLM 중심 분석 파이프라인의 단계와 역할 경계를 팀 전체가 동일하게 이해합니다.
2. 정적 분석, 가설 생성, 검증, 동적 재현, Research, 두 Gate, 보고의 입출력 계약을 명확히 합니다.
3. HOLD restriction과 TRUE capability를 연결하는 Primitive DB와 chaining 규칙을 검토합니다.
4. Membership/API provider, session, logging과 비용·평가 정책을 구현 가능한 수준으로 구체화합니다.
5. 파트 간 모순과 Blocker/High 이슈를 제거한 뒤 전체 설계를 승인합니다.
6. 승인된 설계를 기준으로 구현 계획과 검증 계획을 별도 수립합니다.

## Architecture v5 개요

```text
Repository input
→ RepositorySnapshot 고정
→ AST parse와 SAST 병렬 실행
→ StaticFactBundle
→ constrained HypothesisProposal
→ 가설별 Verification과 on-demand code retrieval
→ BASIC 또는 conditional Pro/Con
→ 필요 시 Docker LIMITED_REPRO / FULL_REPRO
→ final TRUE / FALSE / HOLD
→ Primitive DB와 Research Agent
→ 새 material claim은 새 가설로 재검증
→ CWE labeling
→ Technical Evidence Gate
→ Rule Scope Impact Gate
→ 조건 충족 시 ReportDraft
→ Human final review and disclosure decision
```

정적 분석 도구는 취약점 최종 판정자가 아니라 entity, 위치, source/sink, 호출·데이터 흐름, 인증·인가와 같은 사실 정보를 제공하는 계층입니다. Hypothesis·Research 결과는 Finding이 아니며, 새 공격 주장은 전체 검증 흐름을 다시 거칩니다.

## 설계 검토 운영 방식

이 프로젝트는 **통합 브랜치 + 파트별 PR** 방식으로 설계를 완성합니다.

```text
main
└─ docs/architecture-v5-review
   ├─ review/static-context
   ├─ review/hypothesis-research
   ├─ review/verification
   ├─ review/dynamic-sandbox
   ├─ review/gate-reporting
   ├─ review/provider-integration
   └─ review/data-evaluation
```

- 전체 설계 초안은 `docs/architecture-v5-review` 브랜치의 Draft PR에서 관리합니다.
- 각 담당자는 통합 브랜치에서 파트 브랜치를 만들고 통합 브랜치 대상으로 PR을 엽니다.
- 하나의 파트 PR은 담당 영역과 필요한 인접 계약만 수정합니다.
- 입력을 제공하는 파트와 결과를 소비하는 파트의 교차 리뷰를 받습니다.
- Blocker/High가 0이 된 뒤 전체 시나리오 검토를 수행합니다.
- 최종 통합 검토 전에는 Draft PR을 Ready로 전환하지 않습니다.

전체 절차는 [CONTRIBUTING.md](./CONTRIBUTING.md)를 따릅니다.

## 담당 영역

| 역할 | 핵심 책임 |
|---|---|
| LLM 탐색·체이닝 | 가설 후보, 탐색 방식, Research·Primitive chaining, token 최적화 |
| 정적분석·컨텍스트 | AST, CodeQL/OpenGrep, 정규화, 정적 사실과 위치 기반 context |
| 통합·구현 개발 | provider/runtime 경계, 구현 가능성, 테스트와 모듈 통합 |
| PM·아키텍처·워크플로 | 전체 흐름, 중앙 계약, 사람·LLM 경계, 병렬/직렬, 오류 정책 |
| Gate·Finding·보고서 | Technical/Rule-Scope Gate, FindingCandidate, ReportDraft, 사람 검토 |
| 검증·반박·플레이북 | Verification, Pro/Con, 근거 부족 판정, 검증 절차 |
| 동적검증·Sandbox | Docker 재현, PoC, sandbox와 동적 결과 연결 |
| 데이터·평가·예산 | 평가셋, 품질 지표, token/time/retry/chain budget |

Gate는 Verification verdict를 변경하거나 공개를 승인하지 않습니다. Reporter는 보고서 초안만 작성하며, 사람만 최종 공개를 결정합니다.

## 설계 초안

Architecture v5 정본과 Wiki는 통합 브랜치에서 검토합니다.

- [Architecture v5 review branch](https://github.com/SASTsimi/sastsimi/tree/docs/architecture-v5-review)
- [Architecture v5 design hub](https://github.com/SASTsimi/sastsimi/tree/docs/architecture-v5-review/docs/architecture-v5)

## 안전 원칙

- 공개 저장소 분석과 운영 서비스 테스트는 별개입니다.
- 공식 scope·rule이 없으면 내용을 추측하지 않고 보고 권한을 거부합니다.
- API key, membership credential, session cookie와 실제 개인정보를 저장하지 않습니다.
- Docker 재현은 승인된 범위의 격리 환경에서만 수행합니다.
- AI 결과와 PoC는 사람의 검토 전 외부에 공개하지 않습니다.
