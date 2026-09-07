# Architecture v5 구현 준비 문서

- **이 문서는 무엇을 설명하나요?** Architecture v5 설계를 실제 코드와 시험으로 옮길 때 읽을 R3 구현 문서의 순서를 안내합니다.
- **누가 읽어야 하나요?** R3 통합 구현자와 R1~R8 역할 검토자가 읽습니다.
- **읽은 뒤 무엇을 확인하나요?** 설계, 시험 계획, Provider, 프롬프트와 최종 구현 기준선을 구분하고 자기 역할의 검토 범위를 확인합니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

이 폴더의 문서는 구현을 위한 설계와 시험 계획입니다. 문서가 병합되어도 실제 프로그램, 실제 Provider 연결, Docker 운영 또는 탐지 성능이 구현·검증됐다는 뜻은 아닙니다. 의미가 충돌하면 Architecture v5 번호 문서 `01`~`13`과 공통 계약이 우선합니다.

## 읽는 순서

| 순서 | 문서 | 용도 | 구현 상태 |
|---|---|---|---|
| 1 | [01-module-map.md](./01-module-map.md) | 22단계의 모듈·입출력·저장·오류 연결 | 설계 완료, 코드 미구현 |
| 2 | [02-contract-test-plan.md](./02-contract-test-plan.md) | 파트 간 정상·실패·보안 부정 시험 | 계획 완료, 시험 코드 미구현 |
| 3 | [03-recovery-test-plan.md](./03-recovery-test-plan.md) | 중단·재시도·복구·오래된 결과 격리 시험 | 계획 완료, 시험 코드 미구현 |
| 4 | [04-provider-decision.md](./04-provider-decision.md) | Provider·인증 경로와 실제 지원 판정 기준 | 설계 완료, capability 시험 필요 |
| 5 | [05-prompt-runtime.md](./05-prompt-runtime.md) | 11개 LLM 역할의 프롬프트 등록·조립·검증 | 설계 완료, 역할별 프롬프트·코드 필요 |
| 6 | [06-implementation-baseline.md](./06-implementation-baseline.md) | 기술, 파일 구조, 저장, 실행, CLI, CI와 구현 순서 | 후보 기준선, 역할 검토 필요 |

## 검토 책임

- R3는 문서 간 경로·입출력·실행 순서와 통합 가능성을 관리합니다.
- 각 역할 담당자는 자기 영역의 의미와 권한을 R3 문서가 바꾸지 않았는지 검토합니다.
- R4는 저장·상태·권한·원자적 확정 경계를 검토합니다.
- 구현을 막는 미확정 사항이 남아 있으면 `06`을 최종 승인하거나 #92를 닫지 않습니다.

