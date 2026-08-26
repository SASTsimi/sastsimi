# SASTSIMI 설계 문서 안내

이 폴더에는 Architecture v5 설계 초안과 팀 검토 기록이 들어 있습니다. 아직 실행 가능한 제품이나 승인된 최종 설계가 아닙니다.

## 처음이라면 여기부터 읽으세요

1. [전체 문서 지도](./DOCUMENT_GUIDE.md) — 각 파일이 무엇을 위한 것인지 알려 줍니다.
2. [쉬운 용어집](./GLOSSARY.md) — 모르는 기술 용어를 쉬운 말로 설명합니다.
3. [역할과 담당자](./governance/OWNERSHIP.md) — 누가 어떤 영역과 Issue를 맡는지 보여 줍니다.
4. [실제 Issue 현황](./review/ISSUE_TRACKER.md) — GitHub Issue, 담당자와 진행 상태를 보여 줍니다.
5. [Architecture v5 설계 입구](./architecture-v5/README.md) — 전체 기술 흐름과 번호 문서를 안내합니다.

## 문서 종류

- **기준 문서**: `docs/architecture-v5/01`부터 `13`까지의 번호 문서입니다. 실제 설계 의미와 데이터 형식은 이 문서를 우선합니다.
- **협업 규칙**: `docs/governance/`와 `CONTRIBUTING.md`입니다. 역할, Issue, PR과 승인 방법을 정합니다.
- **검토 기록**: `docs/review/`입니다. 실제 Issue 현황, 발견된 문제, 출처와 설계 결정을 기록합니다.
- **쉬운 요약**: `docs/architecture-v5/wiki/`입니다. 번호 문서를 빠르게 이해하도록 돕지만 새로운 규칙을 만들지는 않습니다.
- **작업 기록**: `docs/superpowers/`입니다. 문서를 어떻게 검토하고 수정했는지 남긴 설계·계획 기록입니다.

## 현재 상태

- `DESIGN_AUTHORED`: 설계 초안이 작성되었습니다.
- `REVIEW_REQUIRED`: 팀 검토와 독립 검토가 더 필요합니다.
- `NOT_IMPLEMENTED`: 실행 코드는 아직 구현되지 않았습니다.

GitHub Issue와 PR에서 결정한 내용은 관련 번호 문서와 [설계 결정 기록](./review/decisions/README.md)에 반영되어야 실제 기준으로 인정됩니다.
