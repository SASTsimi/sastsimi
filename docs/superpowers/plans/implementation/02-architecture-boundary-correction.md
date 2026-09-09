# T02 Architecture Boundary Correction

- 상태: `IMPLEMENTATION_COMPLETE / REVIEW_PENDING`
- Issue: [#124](https://github.com/SASTsimi/sastsimi/issues/124)
- 입력: [승인된 유지보수 구현 설계](../../specs/2026-09-08-sastsimi-maintainable-implementation-design.md) §4·5·10, [master plan Task 2](../2026-09-08-sastsimi-complete-implementation.md), [ADR-015](../../../review/decisions/ADR-015-r3-implementation-baseline.md)
- 산출: [ADR-016](../../../review/decisions/ADR-016-maintainable-workflow-packages.md), 정본의 exact module·import 경계와 문서 회귀 검증

## 범위

기존 업무 흐름 서비스 6개의 물리 module과 import 방향을 명시하고 ADR-015에서 이미 확정한 저장·직렬화·run-init 경계를 현재 문서에 반영한다. Agent 권한, schema field, enum, verdict, Gate, Primitive, PoC 의미는 변경하지 않는다. 코드·Provider·Docker capability 구현은 후속 Task다.

ADR-016의 `ACCEPTED`는 PR #119에서 승인·병합한 결정을 기록한다. T02 자체의 독립 검토·PR·병합은 대기 중이다.

## TDD 실행

- [x] spec의 6개 literal service/module mapping과 import allowlist를 validator에 먼저 추가한다. 검사 책임을 `Assert-MaintainableWorkflowBoundaries`로 묶고 `T02` 오류 접두사로 구분한다.
- [x] 현재 Architecture·governance의 오래된 저장·직렬화·Docker 준비·adapter 연결 표현을 탐지한다.
- [x] 문서 수정 전 RED: `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate-architecture-docs.ps1`을 실행한다. 관측 결과 exit 1, T02 관련 46개 실패이며 기존 검사 실패는 없다.
- [x] 최소 정본 수정: 03 run-init, 08 저장 기준, module map, baseline tree·책임·import, governance, ADR-016과 index를 동기화한다.
- [x] GREEN: 같은 Architecture validator 명령으로 `Failures: 0`을 확인했다.
- [x] `powershell -NoProfile -File scripts/audit-doc-inventory.ps1 -RepositoryRoot . -CheckLinks`로 전체 inventory와 로컬 링크를 검사했다. 새 문서도 Git index에 추가했고 `Missing local Markdown links: 0`을 확인했다.
- [x] `git diff --check`, `git diff --cached --check`와 staged diff를 확인했다. 로컬 커밋 SHA는 T02 작업 보고서에 기록한다.
- [ ] R3·R4와 영향 역할의 exact commit 독립 검토를 완료한다.
- [ ] PR·CI·병합을 완료한다. 구현 담당자의 로컬 커밋 단계에는 포함하지 않는다.

## 파일과 후속 검증

변경 파일은 번호 문서 `03`·`08`, 구현 문서 `01`·`06`, `OPEN_QUESTIONS.md`, ADR-016·ADR index, 구현 인계 index, superpowers index, 이 계획과 Architecture validator다. 전체 저장소 검색 결과 현재 정본의 모순 3곳과 module map의 호출/import 혼동 1곳을 수정했다. 승인 spec의 수정 지시는 현재 동작을 선언하는 문장이 아니므로 보존하며, 과거 작업 기록의 지위와 정본 링크는 `docs/superpowers/README.md`가 안내한다.

후속 Python 구현은 `tests/contract/test_architecture_imports.py`에서 실제 import를 검사한다. 문서 검사 통과를 실행 capability나 취약점 탐지 성공으로 해석하지 않는다.
