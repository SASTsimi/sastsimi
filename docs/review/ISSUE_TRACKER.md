# Architecture v5 실제 Issue tracker

GitHub가 실제 상태, 담당자와 토론의 기준입니다. 이 문서는 역할별 시작점을 한눈에 찾기 위한 요약입니다. 내용이 다르면 각 GitHub Issue를 우선합니다.

## Issue 네 단계

| 단계 | 누가 관리하나요? | 무엇을 하나요? | 언제 끝나나요? |
|---|---|---|---|
| [#1 PM 전체 관리](https://github.com/SASTsimi/sastsimi/issues/1) | PM·아키텍처 담당 | 전체 목표, 역할 경계, 역할 간 충돌과 진행 상태를 관리합니다. | #2–#9와 #10의 완료 조건이 충족될 때 끝납니다. |
| #2–#9 역할별 상위 Issue | 각 역할 담당자 | 파트의 큰 작업 범위와 공통 완료 조건을 관리합니다. | 담당자가 만든 모든 하위 Issue와 연결 PR이 끝날 때 닫습니다. |
| 담당자 생성 하위 Issue | 하위 Issue를 만든 역할 담당자 | 한 번에 완료 여부를 판단할 수 있는 구체적인 문서 검토·수정 작업을 수행합니다. | Issue의 완료 조건과 연결 PR이 끝날 때 닫습니다. |
| [#10 전체 최종 검토](https://github.com/SASTsimi/sastsimi/issues/10) | 팀 전체와 독립 최종 검토자 | 모든 파트가 하나의 흐름으로 모순 없이 연결되는지 확인합니다. | 고정된 최신 commit에 대한 팀·독립 검토가 끝날 때 닫습니다. |

| 구분 | 역할·목적 | GitHub Issue | 역할 담당자 / GitHub 배정 상태 | 작업 브랜치 | 우선 검토할 문서 | 반드시 함께 검토할 역할 | 현재 상태 |
|---|---|---|---|---|---|---|---|
| Epic | Architecture v5 candidate baseline 전체 검토·승인 | [#1](https://github.com/SASTsimi/sastsimi/issues/1) | 김태현 `@taehyeon-git` 배정, 윤희섭 `@v1sion` 본문 연결 | — | `README.md`, `docs/architecture-v5/README.md`, governance/review | R1–R8, independent reviewer | OPEN |
| R1 | LLM 탐색·Research·Primitive chaining | [#2](https://github.com/SASTsimi/sastsimi/issues/2) | 배승원 `@baeseungwon1010` | `review/hypothesis-research` | `03`, `06`, `08`, `09`, `13` | R2, R6, R4, R8 | OPEN |
| R2 | AST/SAST 정적 사실·위치 기반 context | [#3](https://github.com/SASTsimi/sastsimi/issues/3) | 김나연 `@meow` 본문 연결, assignee 선택 불가 | `review/static-context` | `02`, `07`, `08`, `10`, `13` | R1, R6, R4, R3 | OPEN |
| R3 | 통합 구현 가능성·계약 준수 테스트 | [#4](https://github.com/SASTsimi/sastsimi/issues/4) | 김태현 `@taehyeon-git` 배정, 윤희섭 `@v1sion` 본문 연결 | `review/integration-feasibility` | `01`, `03`, `08`, `09`, `10`, `11`, `13` | R4, 변경 영향 역할, R8 | OPEN |
| R4 | PM·Control Plane·중앙 계약·워크플로 | [#5](https://github.com/SASTsimi/sastsimi/issues/5) | 김태현 `@taehyeon-git` 배정, 윤희섭 `@v1sion` 본문 연결 | `review/control-plane` | root README, `01`, `03`, `08`, `09`, `10`, `11`, `13`, governance/review | 전체 역할 | OPEN |
| R5 | 두 Gate·FindingCandidate·ReportDraft | [#6](https://github.com/SASTsimi/sastsimi/issues/6) | 김혜령 `@kimhr8465` 본문 연결, assignee 선택 불가 | `review/gate-reporting` | `05`, `07`, `08`, `10`, `12`, `13` | R6, R2, R7, R4, R8 | OPEN |
| R6 | Verification·독립 Pro/Con·판정 | [#7](https://github.com/SASTsimi/sastsimi/issues/7) | 임채민 `@UltraPaechKeen` 본문 연결, assignee 선택 불가 | `review/verification` | `03`, `04`, `07`, `08`, `13` | R2, R7, R1, R4, R5, R8 | OPEN |
| R7 | Docker LIMITED/FULL 재현·Sandbox | [#8](https://github.com/SASTsimi/sastsimi/issues/8) | 조근석 `@Potatonion` | `review/dynamic-sandbox` | `04`, `07`, `08`, `10`, `13` | R6, R4, R8, R3, R5 | OPEN |
| R8 | 평가 corpus·지표·자원 예산 | [#9](https://github.com/SASTsimi/sastsimi/issues/9) | 성병찬 `@gitterable` | `review/data-evaluation` | `04`, `06`, `07`, `08`, `09` | R4, 각 LLM 역할, R3 | OPEN |
| Final | 전체 교차 시나리오·freeze SHA·최종 승인 | [#10](https://github.com/SASTsimi/sastsimi/issues/10) | Independent reviewer `UNASSIGNED` — 의도적 미배정 | — | 전체 정본·Wiki·Mermaid·findings | R1–R8 담당자 전원, independent reviewer | OPEN |

번호 문서는 `docs/architecture-v5/` 아래 파일을 뜻합니다. 세부 입력·출력, 금지 권한과 완료 조건은 [ISSUE_CATALOG.md](./ISSUE_CATALOG.md)에 있습니다.

## 역할 담당자의 작업 순서

1. 배정된 역할별 상위 Issue를 확인하고 대체 검토자를 댓글로 남깁니다.
2. 필요한 작업을 2–4개 정도의 세부 하위 Issue로 직접 나누어 만들고 상위 Issue에 연결합니다.
3. 각 하위 Issue에 담당자, 쉬운 설명, 수정 문서, 완료 조건과 상위 Issue 번호를 적습니다.
4. 최신 `main`에서 표의 `review/<domain>` 브랜치를 만듭니다.
5. 우선 검토할 문서와 연결된 파트 사이의 입출력 약속을 확인하고 변경 근거·영향·남은 질문을 기록합니다.
6. `main` 대상 PR을 열고 `Closes #<하위 Issue>`와 `Refs #<역할별 상위 Issue>`를 함께 적습니다.
7. 반드시 필요한 교차 검토와 Blocker/High 0을 확인한 뒤 병합합니다.
8. 모든 하위 Issue와 PR이 끝난 뒤 역할별 상위 Issue를 닫습니다.
9. R1–R8이 끝나면 #10에서 전체 시나리오와 검토 대상을 고정한 commit SHA를 확인합니다.
10. 설계 상태 변경은 별도의 최종 승인 PR에서만 수행합니다.

현재 문서와 Issue는 설계 검토용이며 구현 완료 또는 Architecture PASS를 의미하지 않습니다.

GitHub assignee 선택이 불가능한 계정은 역할과 `@username`을 Issue 본문에 연결했습니다. 실제 assignee 배정에는 해당 계정의 저장소 접근 권한 또는 username 확인이 필요합니다.
