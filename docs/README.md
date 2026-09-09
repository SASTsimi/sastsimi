# SASTSIMI 설계 문서 안내

이 폴더에는 승인된 Architecture v5 구현 기준 설계와 팀 검토 기록이 들어 있습니다. 실행 코드는 아직 구현되지 않았습니다.

## 처음이라면 여기부터 읽으세요

1. [전체 문서 지도](./DOCUMENT_GUIDE.md) — 각 파일이 무엇을 위한 것인지 알려 줍니다.
2. [쉬운 용어집](./GLOSSARY.md) — 모르는 기술 용어를 쉬운 말로 설명합니다.
3. [역할과 담당자](./governance/OWNERSHIP.md) — 누가 어떤 영역과 Issue를 맡는지 보여 줍니다.
4. [실제 Issue 현황](./review/ISSUE_TRACKER.md) — GitHub Issue, 담당자와 진행 상태를 보여 줍니다.
5. [Architecture v5 설계 입구](./architecture-v5/README.md) — 전체 기술 흐름과 번호 문서를 안내합니다.

## 역할별 빠른 탐색 경로

- **구현 담당자**: [Architecture v5 설계 입구](./architecture-v5/README.md) → [구현 인계 안내](./architecture-v5/implementation/README.md) → [유지보수 구현 설계](./superpowers/specs/2026-09-08-sastsimi-maintainable-implementation-design.md) → [현재 Task 순서](./superpowers/plans/2026-09-08-sastsimi-complete-implementation.md) 순서로 읽습니다.
- **문서 작성자·검토자**: [전체 문서 지도](./DOCUMENT_GUIDE.md)에서 문서 지위를 확인한 뒤 [문서 인벤토리 감사](../scripts/audit-doc-inventory.ps1), [Architecture validator](../scripts/validate-architecture-docs.ps1), [문서 CI](../.github/workflows/docs.yml)를 실행합니다.
- **설계 결정·승인 검토자**: [설계 결정 기록](./review/decisions/README.md)의 `ACCEPTED` ADR → [최종 승인 기록](./review/FINAL_ARCHITECTURE_V5_APPROVAL.md) → [출처 기록](./review/PROVENANCE.md) 순서로 정확한 결정과 승인 근거를 확인합니다.
- **과거 변경 근거 확인자**: [설계·구현 작업 기록 안내](./superpowers/README.md)에서 역사 문서의 지위를 먼저 확인합니다. 역사 문서는 현재 기술 계약을 바꾸지 않습니다.

## 문서 종류

- **기준 문서**: `docs/architecture-v5/01`부터 `13`까지의 번호 문서입니다. 실제 설계 의미와 데이터 형식은 이 문서를 우선합니다.
- **협업 규칙**: `docs/governance/`와 `CONTRIBUTING.md`입니다. 역할, Issue, PR과 승인 방법을 정합니다.
- **검토 기록**: `docs/review/`입니다. 실제 Issue 현황, 발견된 문제, 출처와 설계 결정을 기록합니다.
- **쉬운 요약**: `docs/architecture-v5/wiki/`입니다. 번호 문서를 빠르게 이해하도록 돕지만 새로운 규칙을 만들지는 않습니다.
- **작업 기록**: `docs/superpowers/`입니다. 문서를 어떻게 검토하고 수정했는지 남긴 설계·계획 기록입니다.

## 현재 상태

- `DESIGN_APPROVED`: 역할별 검토와 전체 문서 추적 검토를 거쳐 구현 기준 설계로 승인되었습니다.
- `NOT_IMPLEMENTED`: 실행 코드는 아직 구현되지 않았습니다.

GitHub Issue와 PR에서 결정한 내용은 관련 번호 문서와 [설계 결정 기록](./review/decisions/README.md)에 반영되어야 실제 기준으로 인정됩니다.
