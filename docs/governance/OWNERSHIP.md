# Architecture v5 역할 및 소유권

## 현재 상태

팀이 제공한 역할표를 기준으로 8개 역할의 담당자와 GitHub 계정을 매핑했습니다. 전체 검토는 [Parent Epic #1](https://github.com/SASTsimi/sastsimi/issues/1)에서 추적합니다.

- Repository steward: 김태현 `@taehyeon-git`
- Design review coordinators: 김태현 `@taehyeon-git`, 윤희섭 `@v1sion`
- Independent final reviewer: `UNASSIGNED` — [Final Issue #10](https://github.com/SASTsimi/sastsimi/issues/10)에서 지정
- Domain owner GitHub usernames: 역할별 표에 매핑 완료
- `.github/CODEOWNERS`: 대체 reviewer와 중앙 계약 승인·merge 권한을 확정한 뒤 별도 PR로 추가

각 역할 Issue는 아래 담당자에게 배정합니다. 담당자가 같더라도 통합 개발과 PM·아키텍처 Issue는 산출물과 승인 경계가 다르므로 별도로 유지합니다.

## 역할별 소유권

| 담당 역할 | 담당자 | Primary 영역 | 직접 소유 문서 | 필수 교차 리뷰 역할 | Review Issue |
|---|---|---|---|---|---|
| LLM 탐색·체이닝 | 배승원 `@baeseungwon1010` | Hypothesis, Research, Primitive/chaining, token 최적화 | `03`, `06` | 정적분석, 검증, 데이터·평가 | [#2](https://github.com/SASTsimi/sastsimi/issues/2) |
| 정적분석·컨텍스트 | 김나연 `@meow` | AST/SAST, normalization, StaticFactBundle, retrieval | `02` | LLM 탐색, 검증 | [#3](https://github.com/SASTsimi/sastsimi/issues/3) |
| 단독 구현·통합 개발 | 김태현 `@taehyeon-git`, 윤희섭 `@v1sion` | provider/runtime 경계, 구현 가능성, 테스트·모듈 통합 | `09`, 구현 feasibility | PM, 데이터·평가, 동적검증 | [#4](https://github.com/SASTsimi/sastsimi/issues/4) |
| PM·아키텍처·워크플로 | 김태현 `@taehyeon-git`, 윤희섭 `@v1sion` | 전체 pipeline, 중앙 계약, 역할·사람 경계, 오류·병렬성 | root README, `01`, `08`, `11`, `13`, Wiki 통합 | 전체 파트 | [#5](https://github.com/SASTsimi/sastsimi/issues/5) |
| Gate·Finding·보고서 | 김혜령 `@kimhr8465` | Technical/Rule-Scope Gate, policy, FindingCandidate, ReportDraft | `05`, `12` | 검증, PM, 데이터·평가 | [#6](https://github.com/SASTsimi/sastsimi/issues/6) |
| 검증·반박·플레이북 | 임채민 `@UltraPaechKeen` | Verification, BASIC/Pro/Con, verdict, bypass 검증 | `04` 검증 영역 | LLM 탐색, 동적검증, Gate | [#7](https://github.com/SASTsimi/sastsimi/issues/7) |
| 동적검증·Sandbox | 조근석 `@Potatonion` | LIMITED/FULL 재현, PoC, Docker와 runtime evidence | `04` 동적 영역, `10` sandbox 영역 | 검증, PM, 통합 개발 | [#8](https://github.com/SASTsimi/sastsimi/issues/8) |
| 데이터·평가·예산 | 성병찬 `@gitterable` | 평가셋, 품질 지표, LLM/resource logging과 budget | `07`, `08/09` 관련 지표 | 전체 LLM 역할, PM | [#9](https://github.com/SASTsimi/sastsimi/issues/9) |

번호는 `docs/architecture-v5/` 아래 정본 문서를 의미합니다.

## GitHub Issue 배정 상태

- 배정 완료: `@taehyeon-git`(#1, #4, #5), `@baeseungwon1010`(#2), `@Potatonion`(#8), `@gitterable`(#9)
- 역할·본문 연결 완료, assignee 선택 불가: `@v1sion`(#1, #4, #5), `@meow`(#3), `@kimhr8465`(#6), `@UltraPaechKeen`(#7)
- 의도적 미배정: [Final #10](https://github.com/SASTsimi/sastsimi/issues/10)의 independent final reviewer

`assignee 선택 불가`는 역할 미배정을 뜻하지 않습니다. GitHub Issue 선택기에 계정이 나타나지 않은 상태이므로 저장소 접근 권한 또는 username을 확인한 뒤 실제 assignee로 추가해야 합니다.

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

## 남은 GitHub governance 결정

역할과 GitHub 계정은 매핑했습니다. 다음 항목을 정한 뒤 CODEOWNERS를 추가합니다.

1. 각 역할의 대체 reviewer
2. 중앙 계약 승인 가능 여부
3. branch merge 권한 여부

독립 reviewer가 지정되기 전에는 candidate baseline의 최종 승인 PR을 Ready로 전환하지 않습니다.
