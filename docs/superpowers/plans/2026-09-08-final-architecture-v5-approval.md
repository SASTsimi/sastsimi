# Architecture v5 최종 승인 PR 실행 계획

> 기준 브랜치: `final/architecture-v5-approval`
>
> 설계 검토 기준 main: `07bd6549a676419c0e720f940ba7abd1b82aea0d`

## 목표

R1–R8 역할 Issue가 모두 종료된 최신 main을 기준으로 Architecture v5의 문서 추적 검토를 마치고, 구현 완료와 혼동하지 않는 최종 설계 승인 PR을 만든다. 이 PR에서는 새 기능·필드·상태·권한·역할을 추가하지 않는다.

## 작업 순서

1. GitHub Issue #2–#9, PR #116, Issue #92와 최신 main SHA를 다시 확인한다.
2. `FINDINGS.md`의 열린 Blocker/High를 현재 정본과 대조한다. 설계로 닫힌 위험과 구현 단계에서 실제 시험해야 할 증거를 분리한다.
3. `ISSUE_TRACKER.md`, `OPEN_QUESTIONS.md`, 관련 ADR의 상태를 실제 GitHub 상태와 일치시킨다.
4. 정확한 freeze SHA, 전체 시나리오 추적 결과, 역할별 승인 방법, 남은 후속 항목을 `FINAL_ARCHITECTURE_V5_APPROVAL.md`에 기록한다.
5. root README, Architecture v5 README, 번호 문서, 구현 준비 문서와 Wiki의 상태를 `DESIGN_APPROVED / NOT_IMPLEMENTED`로 일관되게 변경한다.
6. 문서 검증 스크립트에 최종 승인 상태와 기록의 일관성 검사를 추가한다.
7. 문서 검증, 링크·상태 검색, `git diff --check`를 실행하고 독립 재검토를 받는다.
8. 검토 결과를 반영한 뒤 커밋·푸시하고 Draft Final PR을 연다. PR에는 `Closes #10`, `Refs #1`, freeze SHA, 필수 역할 검토자를 명시한다.
9. Issue #10 본문을 최신 진행 상태와 Final PR 링크로 갱신한다. Issue는 Final PR 병합 전까지 열어 둔다.

## 완료 조건

- 열린 Architecture Blocker/High가 0이며, 실제 구현·운영 시험은 `NOT_IMPLEMENTED` 후속 항목으로 명시되어 있다.
- R1–R8 역할 Issue의 실제 GitHub 상태가 문서와 일치한다.
- 최종 검토 기록과 PR이 같은 freeze SHA를 가리킨다.
- 정본, Wiki, Mermaid, 구현 준비 문서가 승인 상태와 Agent 자동화 종료 경계를 동일하게 설명한다.
- 검증 스크립트와 `git diff --check`가 통과한다.
- Final PR은 설계 상태·검토 기록만 바꾸며 구현 완료나 실제 보안 검증 성공을 주장하지 않는다.
