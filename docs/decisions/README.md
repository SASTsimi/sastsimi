<a id="현재-설계-결정"></a>

# 결정과 과거 설계

현재 목록에는 상태가 `ACCEPTED`인 ADR 13개와 작성 당시의 설계 기록 3개가 함께
있습니다. ADR은 확정한 결정의 배경과 경계를, 날짜가 붙은 설계는 당시의 문제와
접근 방식을 보존합니다. 설계 기록을 현재 파이프라인의 구현 설명으로 읽지 마세요.
실행 흐름과 코드 위치는 [현재 구현 아키텍처](../architecture/README.md), 실제 필드와
동작은 `src/sastsimi`, `schemas/generated`와 테스트를 확인하세요.

ADR 번호는 원래 번호를 유지합니다. 현재 목록에 없는 번호를 당겨 쓰지 않으며,
대체되어 이 폴더에서 제거된 ADR은 Git 이력에서 확인할 수 있습니다.

<a id="결정-목록"></a>

## 채택된 결정: `ACCEPTED` ADR 13개

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
- [ADR-018: 검증된 Finding의 보수적 묶음](./ADR-018-verified-finding-grouping.md)

새 ADR은 하나의 중요한 결정만 다루고, 상태·영향받는 코드와 대체 관계를 명시합니다.
기존 결정을 대체하면 현재 목록에서는 새 ADR만 안내하고 과거 문서는 Git 이력으로
보존합니다.

## 작성 당시의 설계 기록 3개

- [2026-09-25: PR #198에 `impl/e2e-run` 기능을 선택적으로 통합하는 설계](./2026-09-25-e2e-handoff-selective-integration-design.md) — 당시 브랜치와 PR의 통합 범위 및 검토 조건.
- [2026-10-01: 스트리밍 파이프라인 최적화 설계](./2026-10-01-streaming-pipeline-optimization-design.md) — 당시 파이프라인 기준선, 후보 묶음과 검증 흐름의 제안.
- [2026-10-04: 근거를 보존하는 중복 제거·검증 설계](./2026-10-04-evidence-preserving-dedup-and-verification-design.md) — 보수적 그룹화가 구현되었다고 기록하며 저장 분석의 별도 재검증 경계를 명시한 문서.

이 세 문서의 상태·측정·제안은 각 문서의 작성 시점에 묶여 있습니다. 후속 계획은
[계획 기록 색인](../plans/README.md), 실제 시험 결과는
[검증 기록 색인](../validation/README.md)에서 따로 찾으세요.
