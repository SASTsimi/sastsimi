# 설계·구현 작업 기록 안내

- 이 문서는 무엇을 설명하나요? `docs/superpowers/specs/`와 `docs/superpowers/plans/`의 현재 구현 자료와 과거 기록을 구분합니다.
- 누가 읽어야 하나요? 구현 작업을 진행하거나 과거 설계 변경 근거를 확인하는 사람입니다.
- 읽은 뒤 무엇을 결정해야 하나요? 현재 실행할 구현 계획과 기술 의미의 정본을 각각 어디서 확인할지 결정합니다.

## 이 폴더의 문서 지위

이 폴더에는 현재 구현을 제어하는 자료와 설계 과정의 역사적 작업 기록이 함께 있습니다. 문서 상단의 상태와 아래 목록으로 구분합니다.

현재 구현 자료는 다음 두 파일입니다. 파일 상단 상태가 `APPROVED_FOR_IMPLEMENTATION`인 자료만 실행 기준이며, `DRAFT_FOR_REVIEW`는 검토 중인 초안입니다.

- [`specs/2026-09-08-sastsimi-maintainable-implementation-design.md`](./specs/2026-09-08-sastsimi-maintainable-implementation-design.md): 승인된 유지보수 구현 구조
- [`plans/2026-09-08-sastsimi-complete-implementation.md`](./plans/2026-09-08-sastsimi-complete-implementation.md): 승인된 전체 Task·PR 의존 순서와 완료 조건

그 밖의 완료된 기존 문서는 당시 검토한 대안, 변경 순서와 PR 상태를 남긴 역사적 기록입니다.

- `specs/`: 특정 변경을 검토할 당시의 설계 제안과 근거
- `plans/`: 그 변경을 문서와 저장소에 적용하기 위해 사용한 작업 순서

역사적 문서는 현재 공통 계약이나 구현 기준이 아닙니다. 현재 구현 자료도 Architecture v5의 기술 의미를 바꿀 수 없습니다. 내용이 다르면 다음 순서로 판단합니다.

1. [`docs/architecture-v5/README.md`](../architecture-v5/README.md)와 Architecture 01–13 정본
2. [`docs/architecture-v5/implementation/README.md`](../architecture-v5/implementation/README.md)와 R3 구현 기준선
3. [`docs/review/decisions/README.md`](../review/decisions/README.md)의 현재 `ACCEPTED` ADR
4. [`docs/review/FINAL_ARCHITECTURE_V5_APPROVAL.md`](../review/FINAL_ARCHITECTURE_V5_APPROVAL.md)의 최종 승인 기록

과거 문서를 삭제하지 않는 이유는 결정 과정과 변경 근거를 추적하기 위해서입니다. 과거 문서의 명령문이나 상태 표현을 현재 작업 지시로 사용하면 안 됩니다.
