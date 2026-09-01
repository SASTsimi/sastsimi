# Architecture v5 실제 Issue tracker

GitHub가 실제 상태, 담당자와 토론의 기준입니다. 이 문서는 역할별 시작점을 한눈에 찾기 위한 요약입니다. 내용이 다르면 각 GitHub Issue를 우선합니다.

## Issue 네 단계

| 단계 | 누가 관리하나요? | 무엇을 하나요? | 언제 끝나나요? |
|---|---|---|---|
| [#1 PM 전체 관리](https://github.com/SASTsimi/sastsimi/issues/1) | PM·아키텍처 담당 | 전체 목표, 역할 경계, 역할 간 충돌과 진행 상태를 관리합니다. | #2–#9와 #10의 완료 조건이 충족될 때 끝납니다. |
| #2–#9 역할별 상위 Issue | 각 역할 담당자 | 파트의 큰 작업 범위와 공통 완료 조건을 관리합니다. | 담당자가 만든 모든 하위 Issue와 연결 PR이 끝날 때 닫습니다. |
| 담당자 생성 하위 Issue | 하위 Issue를 만든 역할 담당자 | 한 번에 완료 여부를 판단할 수 있는 구체적인 문서 검토·수정 작업을 수행합니다. | Issue의 완료 조건과 연결 PR이 끝날 때 닫습니다. |
| [#10 전체 최종 검토](https://github.com/SASTsimi/sastsimi/issues/10) | 팀 전체와 최종 검토·승인 담당자 | 모든 파트가 하나의 흐름으로 모순 없이 연결되는지 확인합니다. | 파트 간 교차 검토와 고정된 최신 commit에 대한 최종 확인이 끝날 때 닫습니다. |

| 구분 | 역할·목적 | GitHub Issue | 역할 담당자 / GitHub 배정 상태 | 작업 브랜치 | 우선 검토할 문서 | 반드시 함께 검토할 역할 | 현재 상태 |
|---|---|---|---|---|---|---|---|
| 전체 관리 | Architecture v5 검토 중 설계 초안 전체 검토·승인 | [#1](https://github.com/SASTsimi/sastsimi/issues/1) | 김태현 `@taehyeon-git` 배정, 윤희섭 `@YHS-Sec` 공동 역할 담당 | — | `README.md`, `docs/architecture-v5/README.md`, 협업·검토 문서 | R1–R8, 최종 검토·승인 담당자 | OPEN |
| R1 | 최초 가설·HOLD REQUIRED/Gate-qualified TRUE PROVIDED Chaining | [#2](https://github.com/SASTsimi/sastsimi/issues/2) | 배승원 `@baeseungwon1010` | `review/hypothesis-research` | `03`, `06`, `08`, `09`, `13` | R2, R6, R4, R8 | OPEN |
| R2 | AST/SAST 정적 사실·위치 기반 분석 정보 | [#3](https://github.com/SASTsimi/sastsimi/issues/3) | 김나연 `@zv9uvr` | `review/static-context` | `02`, `07`, `08`, `10`, `13` | R1, R6, R4, R3 | OPEN |
| R3 | 통합 구현 가능성·계약 준수 테스트 | [#4](https://github.com/SASTsimi/sastsimi/issues/4) | 김태현 `@taehyeon-git` 배정, 윤희섭 `@YHS-Sec` 공동 역할 담당 | `review/integration-feasibility` | `01`, `03`, `08`, `09`, `10`, `11`, `13` | R4, 변경 영향 역할, R8 | OPEN |
| R4 | PM·Control Plane·중앙 계약·워크플로 | [#5](https://github.com/SASTsimi/sastsimi/issues/5) | 김태현 `@taehyeon-git` 배정, 윤희섭 `@YHS-Sec` 공동 역할 담당 | `review/r4-04-governance-audit` | root README, `01`, `03`, `08`, `09`, `10`, `11`, `13`, governance/review | 전체 역할 | IN REVIEW — R4-01~03 완료, [R4-04 PR #48](https://github.com/SASTsimi/sastsimi/pull/48) 교차 검토 중 |
| R5 | 두 Gate·같은 R6 owner REVISE·보고서 초안 | [#6](https://github.com/SASTsimi/sastsimi/issues/6) | 김혜령 `@kimhr8463` | `review/gate-reporting` | `05`, `07`, `08`, `10`, `12`, `13` | R6, R2, R7, R4, R8 | OPEN |
| R6 | 찬반 근거·동적 모드와 `ReproductionPlan`·최종 판정 | [#7](https://github.com/SASTsimi/sastsimi/issues/7) | 임채민 `@UltraPeachKeen` | `review/verification` | `03`, `04`, `07`, `08`, `13` | R2, R7, R1, R4, R5, R8 | OPEN |
| R7 | Controller 정책 판정·Runner exact 실행·환경/log/PoC 상세 artifact와 동적 결과 조립 | [#8](https://github.com/SASTsimi/sastsimi/issues/8) | 조근석 `@Potatonion` | `review/dynamic-sandbox` | `04`, `07`, `08`, `10`, `13` | R6, R4, R8, R3, R5 | OPEN |
| R8 | 평가 corpus·지표·예산 profile | [#9](https://github.com/SASTsimi/sastsimi/issues/9) | 성병찬 `@gitterable` | `review/data-evaluation` | `04`, `06`, `07`, `08`, `09` | R4, 각 LLM 역할, R3 | OPEN |
| 최종 | 전체 교차 시나리오·고정 commit SHA·최종 승인 | [#10](https://github.com/SASTsimi/sastsimi/issues/10) | 최종 검토·승인 담당자 김태현 `@taehyeon-git` | — | 전체 기준 문서·Wiki·Mermaid·발견사항 | R1–R8 담당자 전원, 김태현 `@taehyeon-git` | OPEN |

번호 문서는 `docs/architecture-v5/` 아래 파일을 뜻합니다. 세부 입력·출력, 금지 권한과 완료 조건은 [ISSUE_CATALOG.md](./ISSUE_CATALOG.md)에 있습니다.

R6가 동적 재현 모드와 계획을 결정하고, R4 trusted runtime이 계획 schema·reference·호출 권한·상태·예산을 검사합니다. R7의 Sandbox Controller는 세부 실행 정책을 검사하고 Runner는 승인된 exact 계획만 실행합니다. R8이 만든 예산 profile도 R4 runtime을 통해 강제됩니다. 연결 역할은 상대 역할의 전문 결정을 대신하지 않고 생산자·소비자 계약을 교차 검토합니다.

R4-04의 역할별 확인 범위, 승인으로 인정하는 기록과 병합 조건은 [R4-04 교차 검토 기록](./R4-04_CROSS_REVIEW.md)에서 확인합니다.

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

GitHub 담당자 지정 상태는 실제 Issue 화면을 확인해 적었습니다. #3 `@zv9uvr`, #6 `@kimhr8463`, #7 `@UltraPeachKeen`을 해당 역할의 실제 계정으로 확정했습니다. `@YHS-Sec`은 #1·#4·#5의 공동 역할 담당자이며 GitHub 공동 assignee 지정 여부는 역할 확정과 별개입니다. #10은 김태현 `@taehyeon-git`이 최종 검토·승인 담당자로 관리합니다.
