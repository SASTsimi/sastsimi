# Architecture v5 역할 및 소유권

## 현재 상태

GitHub에서 확인 가능한 repository steward는 `@taehyeon-git`입니다. 전체 검토는 [Parent Epic #1](https://github.com/SASTsimi/sastsimi/issues/1)에서 추적합니다. 나머지 팀원의 GitHub username과 역할 매핑은 아직 확인되지 않았으므로 추측해서 assignee 또는 CODEOWNERS로 등록하지 않습니다.

- Repository steward / design review coordinator: `@taehyeon-git`
- Independent final reviewer: `UNASSIGNED` — [Final Issue #10](https://github.com/SASTsimi/sastsimi/issues/10)에서 지정
- Domain owner GitHub usernames: `UNASSIGNED`
- `.github/CODEOWNERS`: 실제 계정 매핑 확정 후 추가

Issue 본문에는 담당 역할을 미리 배정하고, 해당 역할의 팀원이 자신의 GitHub 계정으로 Issue를 claim합니다. 실제 assignee가 정해지기 전에도 책임 범위와 필수 리뷰 관계는 유지합니다.

## 역할별 소유권

| 담당 역할 | Primary 영역 | 직접 소유 문서 | 필수 교차 리뷰 역할 | GitHub assignee | Review Issue |
|---|---|---|---|---|---|
| LLM 탐색·체이닝 | Hypothesis, Research, Primitive/chaining, token 최적화 | `03`, `06` | 정적분석, 검증, 데이터·평가 | UNASSIGNED | [#2](https://github.com/SASTsimi/sastsimi/issues/2) |
| 정적분석·컨텍스트 | AST/SAST, normalization, StaticFactBundle, retrieval | `02` | LLM 탐색, 검증 | UNASSIGNED | [#3](https://github.com/SASTsimi/sastsimi/issues/3) |
| 통합·구현 개발 | provider/runtime 경계, 구현 가능성, 테스트·모듈 통합 | `09`, 구현 feasibility | PM, 데이터·평가, 동적검증 | UNASSIGNED | [#4](https://github.com/SASTsimi/sastsimi/issues/4) |
| PM·아키텍처·워크플로 | 전체 pipeline, 중앙 계약, 역할·사람 경계, 오류·병렬성 | root README, `01`, `08`, `11`, `13`, Wiki 통합 | 전체 파트 | `@taehyeon-git` (initial coordinator) | [#5](https://github.com/SASTsimi/sastsimi/issues/5) |
| Gate·Finding·보고서 | Technical/Rule-Scope Gate, policy, FindingCandidate, ReportDraft | `05`, `12` | 검증, PM, 데이터·평가 | UNASSIGNED | [#6](https://github.com/SASTsimi/sastsimi/issues/6) |
| 검증·반박·플레이북 | Verification, BASIC/Pro/Con, verdict, bypass 검증 | `04` 검증 영역 | LLM 탐색, 동적검증, Gate | UNASSIGNED | [#7](https://github.com/SASTsimi/sastsimi/issues/7) |
| 동적검증·Sandbox | LIMITED/FULL 재현, PoC, Docker와 runtime evidence | `04` 동적 영역, `10` sandbox 영역 | 검증, PM, 통합 개발 | UNASSIGNED | [#8](https://github.com/SASTsimi/sastsimi/issues/8) |
| 데이터·평가·예산 | 평가셋, 품질 지표, LLM/resource logging과 budget | `07`, `08/09` 관련 지표 | 전체 LLM 역할, PM | UNASSIGNED | [#9](https://github.com/SASTsimi/sastsimi/issues/9) |

번호는 `docs/architecture-v5/` 아래 정본 문서를 의미합니다.

## 중앙 통합 파일

다음 파일은 한 명의 domain owner가 단독 확정하지 않습니다.

- `README.md`
- `docs/architecture-v5/README.md`
- `docs/architecture-v5/01-system-overview.md`
- `docs/architecture-v5/08-lightweight-data-contracts.md`
- `docs/architecture-v5/13-architecture-diagrams.md`
- `docs/architecture-v5/wiki/diagrams.md`

변경을 제안한 생산자 역할과 해당 데이터를 소비하는 역할이 의미를 승인한 후 design review coordinator가 `main` 대상 PR을 병합합니다.

## 권한 분리

- Hypothesis Agent는 verdict·Finding을 만들지 않습니다.
- Verification Agent가 기술 verdict를 생성하지만 외부 공개를 결정하지 않습니다.
- Research Agent와 Primitive match는 새 가설만 제안합니다.
- Technical Evidence Gate와 Rule Scope Impact Gate는 verdict를 직접 변경하지 않습니다.
- Reporter는 내부 초안만 만듭니다.
- 사람만 최종 공개를 승인합니다.

## GitHub 계정 매핑 완료 조건

각 역할에 대해 다음을 기록한 뒤 CODEOWNERS를 추가합니다.

1. GitHub username
2. Primary role
3. 대체 reviewer
4. 중앙 계약 승인 가능 여부
5. branch merge 권한 여부

독립 reviewer가 지정되기 전에는 candidate baseline의 최종 승인 PR을 Ready로 전환하지 않습니다.
