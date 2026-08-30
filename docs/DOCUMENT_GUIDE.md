# SASTSIMI 전체 문서 지도

이 문서는 저장소에 있는 각 파일이 무엇을 위한 것인지 쉽게 설명합니다. 처음 참여했다면 먼저 [프로젝트 README](../README.md), [협업 가이드](../CONTRIBUTING.md), [쉬운 용어집](./GLOSSARY.md) 순서로 읽으세요.

## 기준 표시

- **기준 문서**: 설계 의미와 협업 규칙을 판단할 때 우선합니다.
- **쉬운 요약**: 기준 문서를 빠르게 찾고 이해하도록 돕습니다.
- **작업 기록**: 설계·문서 변경 과정과 검토 계획입니다.
- **보조 파일**: Issue, PR 또는 Wiki 화면을 작동시키는 설정 파일입니다.

## 저장소 첫 화면과 협업

| 파일 | 쉽게 말하면 | 주로 읽는 사람 | 구분 |
|---|---|---|---|
| [`README.md`](../README.md) | 프로젝트 목적, 현재 상태, 전체 흐름, 팀 역할과 업무 시작 방법을 소개합니다. | 모든 팀원 | 기준 문서 |
| [`CONTRIBUTING.md`](../CONTRIBUTING.md) | Issue를 나누고 브랜치·PR·리뷰를 진행하는 실제 순서를 설명합니다. | 작업을 시작하는 팀원 | 기준 문서 |
| [Issue 작성 양식](../.github/ISSUE_TEMPLATE/architecture-review.yml) | GitHub에서 설계 검토 Issue를 만들 때 필요한 입력 칸을 정의합니다. | Issue 작성자 | 보조 파일 |
| [Issue 화면 설정](../.github/ISSUE_TEMPLATE/config.yml) | GitHub Issue 작성 화면의 선택 항목을 설정합니다. | 저장소 관리 담당 | 보조 파일 |
| [PR 작성 양식](../.github/PULL_REQUEST_TEMPLATE.md) | PR에 목적·영향·검증 내용을 빠뜨리지 않도록 기본 양식을 제공합니다. | PR 작성자·검토자 | 보조 파일 |
| [`scripts/validate-architecture-docs.ps1`](../scripts/validate-architecture-docs.ps1) | Markdown 링크·Mermaid 사본, R4 상태·복구·권한 계약과 운영 Pro/Con 정책 누락을 한 번에 검사합니다. | 문서 작성자·검토자 | 검증 도구 |

## 문서 안내와 공통 용어

| 파일 | 쉽게 말하면 | 주로 읽는 사람 | 구분 |
|---|---|---|---|
| [`docs/README.md`](./README.md) | 설계 문서를 어디서부터 읽어야 하는지 알려 주는 입구입니다. | 모든 팀원 | 쉬운 요약 |
| [`docs/DOCUMENT_GUIDE.md`](./DOCUMENT_GUIDE.md) | 저장소의 모든 문서와 보조 파일이 무엇을 위한 것인지 설명합니다. | 처음 참여한 팀원 | 쉬운 요약 |
| [`docs/GLOSSARY.md`](./GLOSSARY.md) | 프로젝트 전문용어를 쉬운 말로 설명합니다. | 모든 팀원 | 쉬운 요약 |

## 협업·승인 규칙

| 파일 | 쉽게 말하면 | 주로 읽는 사람 | 구분 |
|---|---|---|---|
| [`docs/governance/OWNERSHIP.md`](./governance/OWNERSHIP.md) | 역할별 담당자, 담당 문서, 검토자와 권한 경계를 정리합니다. | PM·역할 담당자 | 기준 문서 |
| [`docs/governance/OPEN_QUESTIONS.md`](./governance/OPEN_QUESTIONS.md) | 아직 결정하지 못한 사항과 결정하지 않았을 때의 영향을 모읍니다. | PM·관련 역할 담당자 | 기준 문서 |
| [`docs/governance/REVIEW_CHECKLIST.md`](./governance/REVIEW_CHECKLIST.md) | 파트 검토와 최종 검토에서 빠뜨리면 안 되는 항목을 확인합니다. | 작성자·검토자 | 기준 문서 |

## 검토 업무와 기록

| 파일 | 쉽게 말하면 | 주로 읽는 사람 | 구분 |
|---|---|---|---|
| [`docs/review/ISSUE_TRACKER.md`](./review/ISSUE_TRACKER.md) | 실제 GitHub Issue 번호, 담당자, 브랜치와 진행 상태를 한눈에 보여 줍니다. | PM·모든 역할 담당자 | 쉬운 요약 |
| [`docs/review/ISSUE_CATALOG.md`](./review/ISSUE_CATALOG.md) | 역할별 상위 Issue에서 무엇을 검토하고 어떤 하위 Issue를 만들지 자세히 설명합니다. | 역할 담당자 | 기준 문서 |
| [`docs/review/R4-04_CROSS_REVIEW.md`](./review/R4-04_CROSS_REVIEW.md) | R4-04에서 역할별로 무엇을 확인하고 어떤 GitHub 기록을 승인으로 인정하는지 설명합니다. | R1~R8 담당자·최종 검토 담당자 | 검토 기록 |
| [`docs/review/FINDINGS.md`](./review/FINDINGS.md) | 현재 설계에서 발견된 큰 문제와 해결 조건을 정리합니다. | PM·문제 담당자 | 기준 문서 |
| [`docs/review/PROVENANCE.md`](./review/PROVENANCE.md) | Architecture v5 파일을 어디에서 가져왔는지와 원본 해시를 기록합니다. | PM·최종 검토 담당자 | 기준 기록 |
| [`docs/review/decisions/README.md`](./review/decisions/README.md) | 팀이 확정한 중요한 설계 결정과 근거를 기록하는 방법을 설명합니다. | 결정 담당자·검토자 | 기준 문서 |

## Architecture v5 기술 기준 문서

| 파일 | 쉽게 말하면 | 주로 읽는 사람 | 구분 |
|---|---|---|---|
| [`docs/architecture-v5/README.md`](./architecture-v5/README.md) | Architecture v5 전체 흐름과 번호 문서의 읽는 순서를 소개합니다. | 모든 설계 참여자 | 기준 문서 |
| [`01-system-overview.md`](./architecture-v5/01-system-overview.md) | 저장소 입력부터 사람의 최종 판단까지 전체 23단계를 설명합니다. | PM·모든 역할 담당자 | 기준 문서 |
| [`02-static-fact-layer.md`](./architecture-v5/02-static-fact-layer.md) | AST와 SAST 결과를 LLM이 사용할 코드 사실로 정리하는 방법을 설명합니다. | 정적분석·탐색·검증 담당 | 기준 문서 |
| [`03-agent-roles-and-orchestration.md`](./architecture-v5/03-agent-roles-and-orchestration.md) | Orchestration의 전역 등록·배정과 Verification의 가설 내부 제어권을 포함해 각 Agent 역할을 설명합니다. | PM·LLM 역할·통합 담당 | 기준 문서 |
| [`04-verification-and-dynamic-reproduction.md`](./architecture-v5/04-verification-and-dynamic-reproduction.md) | Verification이 가설 내부 Context·찬반·동적 재현·판정·Gate 보완을 관리하는 절차를 설명합니다. | 검증·동적검증 담당 | 기준 문서 |
| [`05-llm-gate-and-reporting.md`](./architecture-v5/05-llm-gate-and-reporting.md) | 기술 근거와 공식 정책을 검토하고 보고서 초안을 만드는 조건을 설명합니다. | Gate·검증·PM 담당 | 기준 문서 |
| [`06-chaining.md`](./architecture-v5/06-chaining.md) | HOLD REQUIRED와 Gate-qualified TRUE PROVIDED의 TRUE+HOLD·TRUE+TRUE matching 및 제한을 설명합니다. | 탐색·체이닝·검증 담당 | 기준 문서 |
| [`07-results-and-observability.md`](./architecture-v5/07-results-and-observability.md) | 분석 결과, 오류, 비용과 디버깅 기록을 무엇을 저장할지 설명합니다. | 데이터·평가·통합 담당 | 기준 문서 |
| [`08-lightweight-data-contracts.md`](./architecture-v5/08-lightweight-data-contracts.md) | 파트 사이에 주고받는 데이터 묶음과 필드 이름을 정의합니다. | 모든 구현·설계 담당자 | 기준 문서 |
| [`09-llm-provider-session-and-logging.md`](./architecture-v5/09-llm-provider-session-and-logging.md) | 회원 로그인·API 연결, 대화 상태와 LLM 호출 기록 방법을 설명합니다. | 통합·PM·데이터 담당 | 기준 문서 |
| [`10-security-boundaries.md`](./architecture-v5/10-security-boundaries.md) | LLM, 저장소, 비밀정보, Docker와 공식 정책을 안전하게 다루는 경계를 설명합니다. | 모든 역할·보안 검토자 | 기준 문서 |
| [`11-migration-from-v4.md`](./architecture-v5/11-migration-from-v4.md) | v4에서 유지한 생각과 v5에서 버린 구조를 역사적 맥락으로 설명합니다. | PM·기존 설계 참여자 | 참고 문서 |
| [`12-report-draft-template.md`](./architecture-v5/12-report-draft-template.md) | Gate를 통과한 결과를 사람이 검토할 보고서 초안으로 정리하는 양식입니다. | Gate·보고서 담당 | 기준 문서 |
| [`13-architecture-diagrams.md`](./architecture-v5/13-architecture-diagrams.md) | 전체 흐름과 역할 관계를 Mermaid 그림으로 보여 줍니다. | 모든 팀원 | 기준 문서 |

## Architecture v5 쉬운 Wiki

Wiki는 번호 문서의 쉬운 요약입니다. Wiki만 수정해 새로운 규칙을 만들 수 없습니다.

| 파일 | 쉽게 말하면 | 주로 읽는 사람 | 구분 |
|---|---|---|---|
| [`wiki/README.md`](./architecture-v5/wiki/README.md) | Wiki의 성격과 추천 읽기 순서를 설명합니다. | 처음 설계를 읽는 팀원 | 쉬운 요약 |
| [`wiki/_Sidebar.md`](./architecture-v5/wiki/_Sidebar.md) | Wiki 왼쪽 메뉴를 구성합니다. | Wiki 이용자 | 보조 파일 |
| [`wiki/quick-guide.md`](./architecture-v5/wiki/quick-guide.md) | Architecture v5를 약 5분 안에 이해하도록 핵심만 요약합니다. | 처음 참여한 팀원 | 쉬운 요약 |
| [`wiki/pipeline.md`](./architecture-v5/wiki/pipeline.md) | 23단계 전체 흐름을 짧게 설명합니다. | 모든 팀원 | 쉬운 요약 |
| [`wiki/agents.md`](./architecture-v5/wiki/agents.md) | Agent별 역할과 금지 권한을 표로 요약합니다. | LLM·PM 담당 | 쉬운 요약 |
| [`wiki/verification-and-dynamic.md`](./architecture-v5/wiki/verification-and-dynamic.md) | 가설 판정과 Docker 재현을 짧게 설명합니다. | 검증·동적검증 담당 | 쉬운 요약 |
| [`wiki/gate-and-reporting.md`](./architecture-v5/wiki/gate-and-reporting.md) | 두 검토 단계와 보고서 작성 조건을 요약합니다. | Gate·보고서 담당 | 쉬운 요약 |
| [`wiki/chaining.md`](./architecture-v5/wiki/chaining.md) | 여러 취약점의 조건을 연결하는 방법과 중단 조건을 요약합니다. | 탐색·체이닝 담당 | 쉬운 요약 |
| [`wiki/providers-and-logging.md`](./architecture-v5/wiki/providers-and-logging.md) | LLM 연결 방식, 로그인 상태와 기록 방법을 요약합니다. | 통합·데이터 담당 | 쉬운 요약 |
| [`wiki/common-contracts.md`](./architecture-v5/wiki/common-contracts.md) | 공통 ID, 시간, 상태, 분석 공백·오류와 계약 변경 규칙을 쉽게 설명합니다. | 모든 구현·검토 담당 | 쉬운 요약 |
| [`wiki/state-and-recovery.md`](./architecture-v5/wiki/state-and-recovery.md) | 병렬 작업, 중복 방지, 재시도와 중단 후 안전한 재개 규칙을 쉽게 설명합니다. | PM·통합·모든 역할 담당 | 쉬운 요약 |
| [`wiki/authority-boundaries.md`](./architecture-v5/wiki/authority-boundaries.md) | LLM이 제안할 일, 프로그램이 검사할 일과 사람이 결정할 일을 쉽게 설명합니다. | 모든 역할 담당·보안 검토자 | 쉬운 요약 |
| [`wiki/results.md`](./architecture-v5/wiki/results.md) | 최종 저장 결과와 디버깅 정보를 요약합니다. | 데이터·평가·통합 담당 | 쉬운 요약 |
| [`wiki/diagrams.md`](./architecture-v5/wiki/diagrams.md) | 기준 다이어그램을 Wiki에서 그대로 보여 줍니다. | 모든 팀원 | 쉬운 요약 사본 |
| [`wiki/index.html`](./architecture-v5/wiki/index.html) | 로컬 Wiki 화면을 여는 HTML 파일입니다. | Wiki 관리 담당 | 보조 파일 |
| [`wiki/theme.css`](./architecture-v5/wiki/theme.css) | Wiki 화면의 글꼴·색상·간격을 정합니다. | Wiki 관리 담당 | 보조 파일 |
| [`wiki/serve.ps1`](./architecture-v5/wiki/serve.ps1) | 로컬 컴퓨터에서 Wiki를 실행하는 PowerShell 스크립트입니다. | Wiki 확인자 | 보조 파일 |
| [`wiki/.nojekyll`](./architecture-v5/wiki/.nojekyll) | GitHub Pages가 Wiki 파일을 그대로 제공하도록 알리는 빈 설정 파일입니다. | 저장소 관리 담당 | 보조 파일 |

## 설계·작업 과정 기록

아래 문서는 작업을 어떻게 설계하고 진행했는지 남기는 기록입니다. Architecture v5 기술 의미의 기준으로 사용하지 않습니다.

| 파일 | 쉽게 말하면 | 구분 |
|---|---|---|
| [`2026-08-27-role-review-governance.md`](./superpowers/plans/2026-08-27-role-review-governance.md) | 초기 역할별 Issue와 협업·승인 규칙 연결 작업 계획입니다. | 작업 기록 |
| [`2026-08-27-team-role-issue-readability.md`](./superpowers/plans/2026-08-27-team-role-issue-readability.md) | 팀원·GitHub 계정 연결과 Issue 문장 단순화 작업 계획입니다. | 작업 기록 |
| [`2026-08-27-collaboration-and-readable-docs-design.md`](./superpowers/specs/2026-08-27-collaboration-and-readable-docs-design.md) | 담당자 생성 하위 Issue와 쉬운 문서 체계를 정의한 설계입니다. | 작업 기록 |
| [`2026-08-27-collaboration-and-readable-docs.md`](./superpowers/plans/2026-08-27-collaboration-and-readable-docs.md) | 이 설계를 저장소 전체에 적용하는 작업 순서입니다. | 작업 기록 |
| [`2026-08-28-remove-repository-snapshot-design.md`](./superpowers/specs/2026-08-28-remove-repository-snapshot-design.md) | 저장소 스냅샷 기능을 제거하고 로컬 코드 작업공간으로 전환한 결정입니다. | 작업 기록 |
| [`2026-08-28-remove-repository-snapshot.md`](./superpowers/plans/2026-08-28-remove-repository-snapshot.md) | 로컬 코드 작업공간 전환을 문서와 Issue에 적용한 순서입니다. | 작업 기록 |
| [`2026-08-28-r4-01-common-contracts-design.md`](./superpowers/specs/2026-08-28-r4-01-common-contracts-design.md) | R4-01 공통 ID·시간·상태·오류·버전 계약 결정입니다. | 작업 기록 |
| [`2026-08-28-r4-01-common-contracts.md`](./superpowers/plans/2026-08-28-r4-01-common-contracts.md) | R4-01 계약을 정본·Wiki·검토 문서에 적용하는 작업 순서입니다. | 작업 기록 |
| [`2026-08-28-r4-02-state-recovery-design.md`](./superpowers/specs/2026-08-28-r4-02-state-recovery-design.md) | R4-02 상태 전이·중복 방지·atomic 저장·복구 설계 결정입니다. | 작업 기록 |
| [`2026-08-28-r4-02-state-recovery.md`](./superpowers/plans/2026-08-28-r4-02-state-recovery.md) | R4-02 설계를 정본·Wiki·Mermaid에 적용하고 검증하는 작업 순서입니다. | 작업 기록 |
| [`2026-08-28-r4-03-authority-boundary-design.md`](./superpowers/specs/2026-08-28-r4-03-authority-boundary-design.md) | R4-03 LLM·프로그램·사람 권한 경계와 action 검사 설계 결정입니다. | 작업 기록 |
| [`2026-08-28-r4-03-authority-boundary.md`](./superpowers/plans/2026-08-28-r4-03-authority-boundary.md) | R4-03 권한 경계를 정본·Wiki·Mermaid에 적용하고 검증하는 작업 순서입니다. | 작업 기록 |

## 무엇부터 읽으면 되나요?

1. [프로젝트 README](../README.md)에서 목적과 현재 상태를 확인합니다.
2. [협업 가이드](../CONTRIBUTING.md)에서 자기 Issue와 PR 작성 순서를 확인합니다.
3. [역할과 담당자](./governance/OWNERSHIP.md)에서 자기 역할별 상위 Issue를 찾습니다.
4. [Issue 카탈로그](./review/ISSUE_CATALOG.md)에서 세부 하위 Issue를 어떻게 나눌지 확인합니다.
5. 모르는 단어는 [쉬운 용어집](./GLOSSARY.md)에서 찾습니다.
6. 실제 기술 기준은 자기 역할에 연결된 Architecture v5 번호 문서에서 확인합니다.
