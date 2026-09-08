# 설계 작업 기록 안내

- 이 문서는 무엇을 설명하나요? `docs/superpowers/specs/`와 `docs/superpowers/plans/`의 문서 지위를 설명합니다.
- 누가 읽어야 하나요? 과거 설계 변경의 이유나 작업 순서를 확인하려는 사람입니다.
- 읽은 뒤 무엇을 결정해야 하나요? 현재 구현 기준은 이 폴더가 아니라 Architecture v5 정본과 승인된 ADR에서 확인해야 합니다.

## 이 폴더의 문서 지위

이 폴더는 설계 과정에서 작성한 **역사적 작업 기록**입니다. 당시 검토한 대안, 변경 순서, 아직 병합되지 않았던 PR 상태가 남아 있을 수 있습니다.

- `specs/`: 특정 변경을 검토할 당시의 설계 제안과 근거
- `plans/`: 그 변경을 문서와 저장소에 적용하기 위해 사용한 작업 순서

이 문서들은 현재 공통 계약이나 구현 기준이 아닙니다. 내용이 현재 정본과 다르면 다음 순서로 판단합니다.

1. [`docs/architecture-v5/README.md`](../architecture-v5/README.md)와 Architecture 01–13 정본
2. [`docs/architecture-v5/implementation/README.md`](../architecture-v5/implementation/README.md)와 R3 구현 기준선
3. [`docs/review/decisions/README.md`](../review/decisions/README.md)의 현재 `ACCEPTED` ADR
4. [`docs/review/FINAL_ARCHITECTURE_V5_APPROVAL.md`](../review/FINAL_ARCHITECTURE_V5_APPROVAL.md)의 최종 승인 기록

과거 문서를 삭제하지 않는 이유는 결정 과정과 변경 근거를 추적하기 위해서입니다. 과거 문서의 명령문이나 상태 표현을 현재 작업 지시로 사용하면 안 됩니다.
