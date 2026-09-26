# 현재 설계 결정

이 디렉터리에는 현재 구현의 의미를 설명하는 `ACCEPTED` ADR만 둡니다. 실행 흐름과
코드 위치는 [현재 구현 아키텍처](../architecture/README.md)를 먼저 확인하세요.

ADR은 결정을 내린 배경과 바꾸면 안 되는 경계를 보존합니다. 실제 필드와 동작은
`src/sastsimi`, `schemas/generated`와 테스트가 기준이며, 대체된 과거 ADR은 Git 이력에서
확인할 수 있습니다.

## 결정 목록

- [ADR-005: 통합 Primitive와 Chaining](./ADR-005-unified-primitive-chaining.md)
- [ADR-006: 정적 규칙 실행 기록](./ADR-006-static-rule-execution-record.md)
- [ADR-007: 자율 동적 재현 session](./ADR-007-r7-autonomous-reproduction-session.md)
- [ADR-008: 가설 restriction과 중복 판정](./ADR-008-hypothesis-restriction-duplicate-contract.md)
- [ADR-009: CWE labeling provenance](./ADR-009-r5-01-cwe-labeling-provenance.md)
- [ADR-010: 정적 사실 종류 분리](./ADR-010-static-fact-kind-partition.md)
- [ADR-012: Primitive match 중복 키](./ADR-012-primitive-match-duplicate-key.md)
- [ADR-013: 분석 정책 준비와 재사용](./ADR-013-run-policy-preparation-and-reuse.md)
- [ADR-014: Primitive admission 1회 판정](./ADR-014-primitive-admission-single-decision.md)
- [ADR-015: 단일 애플리케이션 구현 기준선](./ADR-015-r3-implementation-baseline.md)
- [ADR-016: 유지보수 가능한 workflow package 경계](./ADR-016-maintainable-workflow-packages.md)
- [ADR-017: Technical Gate의 종료 판정과 PoC 보완](./ADR-017-terminal-gate-outcomes.md)

새 ADR은 하나의 중요한 결정만 다루고, 상태·영향받는 코드와 대체 관계를 명시합니다.
기존 결정을 대체하면 현재 목록에서는 새 ADR만 안내하고 과거 문서는 Git 이력으로
보존합니다.
