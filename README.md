# SASTSIMI

SASTSIMI는 AST·SAST가 수집한 코드 사실을 LLM Agent가 가설화하고, 검증·동적 재현·근거 검토를 거쳐 사람이 최종 공개 여부를 판단하는 **LLM 중심 차세대 SAST 연구 프로젝트**입니다.

현재 단계에서는 실행 가능한 제품을 배포하기 위한 저장소가 아니라, 팀이 구상한 전체 시스템을 구현하기 전에 각 파트의 책임·입출력·오류·보안 경계와 데이터 계약을 함께 검토하고 확정하기 위한 설계 협업 공간입니다.

## 현재 단계

```text
DESIGN_AUTHORED
REVIEW_REQUIRED
NOT_IMPLEMENTED
```

- v5 설계 초안은 별도 작업 트리에서 가져온 **검토 대상 candidate baseline**입니다.
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

가져온 원본은 커밋에 포함되지 않은 작업 트리였으므로 특정 소스 커밋의 산출물이라고 주장하지 않습니다. 원본 상태와 파일별 SHA-256은 [PROVENANCE.md](./docs/review/PROVENANCE.md)에 기록하며, 이 저장소에서 승인된 snapshot만 명시적인 동기화 PR을 통해 구현 저장소로 전달합니다.

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

LLM Agent의 출력은 모두 비신뢰 입력입니다. 예산, 상태 전이, sandbox 정책, provider/session 정책, Gate 순서와 Reporter 호출 조건은 Agent의 자연어 판단이 아니라 신뢰 경계 안의 runtime validator가 강제해야 합니다.

## 설계 검토 운영 방식

이 프로젝트는 **main의 공개 초안 + 파트별 PR** 방식으로 설계를 완성합니다.

```text
main  ← Architecture v5 candidate baseline
├─ review/static-context
├─ review/hypothesis-research
├─ review/integration-feasibility
├─ review/control-plane
├─ review/verification
├─ review/dynamic-sandbox
├─ review/gate-reporting
└─ review/data-evaluation
```

- 전체 설계 초안은 `main`에서 누구나 확인할 수 있게 유지합니다.
- 각 담당자는 최신 `main`에서 파트 브랜치를 만들고 `main` 대상으로 PR을 엽니다.
- 하나의 파트 PR은 담당 영역과 필요한 인접 계약만 수정합니다.
- 입력을 제공하는 파트와 결과를 소비하는 파트의 교차 리뷰를 받습니다.
- Blocker/High가 0이 된 뒤 전체 시나리오 검토를 수행합니다.
- 설계 상태 변경은 모든 파트 검토가 끝난 뒤 별도의 최종 승인 PR에서 수행합니다.

전체 절차는 [CONTRIBUTING.md](./CONTRIBUTING.md)를 따릅니다.

검토 현황과 역할별 작업은 [Parent Epic #1](https://github.com/SASTsimi/sastsimi/issues/1), [실제 Issue tracker](./docs/review/ISSUE_TRACKER.md), [역할별 Issue 카탈로그](./docs/review/ISSUE_CATALOG.md)에서 추적합니다. Blocker/High가 모두 닫히고 Medium이 해결되거나 근거와 owner를 갖고 명시적으로 연기된 뒤에만 candidate baseline의 최종 승인 PR을 엽니다.

## 담당 영역

| 역할 | 핵심 책임 |
|---|---|
| LLM 탐색·체이닝 | 제약형 가설 후보, Research·Primitive chaining, token 최적화 |
| 정적분석·컨텍스트 | 정적 사실 계층과 동일 snapshot 위치 기반 context |
| 통합·구현 개발 | 통합 구현 가능성, 계약 준수 테스트와 모듈 조립 검토 |
| PM·아키텍처·워크플로 | Control Plane, 중앙 계약, 사람·LLM 경계, 오류 정책 |
| Gate·Finding·보고서 | 이중 Gate, 내부 FindingCandidate/ReportDraft, human handoff |
| 검증·반박·플레이북 | Verification 판정, 독립 Pro/Con 근거와 검증 절차 |
| 동적검증·Sandbox | 승인된 Docker 재현, PoC와 sandbox evidence |
| 데이터·평가·예산 | 평가 corpus, 품질·관측 지표와 자원 budget |

Gate는 Verification verdict를 변경하거나 공개를 승인하지 않습니다. Reporter는 보고서 초안만 작성하며, 사람만 최종 공개를 결정합니다.

## 설계 초안

Architecture v5 candidate baseline과 파생 Wiki는 `main`에서 확인하고 파트별 PR로 검토합니다.

- [Architecture v5 design hub](./docs/architecture-v5/README.md)
- [역할별 검토 Issue 구조](./docs/review/ISSUE_CATALOG.md)
- [실제 Issue 배정·진행 현황](./docs/review/ISSUE_TRACKER.md)
- [GitHub Parent Epic #1](https://github.com/SASTsimi/sastsimi/issues/1)

## 안전 원칙

- 공개 저장소 분석과 운영 서비스 테스트는 별개입니다.
- 공식 scope·rule이 없으면 내용을 추측하지 않고 보고 권한을 거부합니다.
- API key, membership credential, session cookie와 실제 개인정보를 저장하지 않습니다.
- Docker 재현은 승인된 범위의 격리 환경에서만 수행합니다.
- AI 결과와 PoC는 사람의 검토 전 외부에 공개하지 않습니다.
