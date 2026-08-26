# Architecture v5 실제 Issue tracker

GitHub가 상태·담당자·토론의 정본입니다. 이 문서는 역할별 진입점을 한눈에 찾기 위한 탐색용 snapshot이며, 상태가 다르면 각 GitHub Issue를 우선합니다.

| 구분 | 역할·목적 | GitHub Issue | 역할 담당자 / GitHub 배정 상태 | 작업 브랜치 | Primary 문서 | 필수 교차 리뷰 | 현재 상태 |
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

## 역할 담당자 작업 순서

1. 배정된 역할 Issue를 확인하고 대체 reviewer를 댓글로 남깁니다.
2. 최신 `main`에서 표의 `review/<domain>` 브랜치를 만듭니다.
3. Primary 문서와 인접 계약을 검토하고, 변경 근거·영향·남은 질문을 기록합니다.
4. `main` 대상 PR을 열고 본문에 `Closes #<역할 Issue>` 또는 `Refs #<역할 Issue>`를 적습니다.
5. 필수 교차 리뷰와 Blocker/High 0을 확인한 뒤 병합합니다.
6. R1–R8이 끝나면 #10에서 전체 시나리오와 freeze SHA를 검토합니다.
7. 설계 상태 변경은 별도의 최종 승인 PR에서만 수행합니다.

현재 문서와 Issue는 설계 검토용이며 구현 완료 또는 Architecture PASS를 의미하지 않습니다.

GitHub assignee 선택이 불가능한 계정은 역할과 `@username`을 Issue 본문에 연결했습니다. 실제 assignee 배정에는 해당 계정의 저장소 접근 권한 또는 username 확인이 필요합니다.
