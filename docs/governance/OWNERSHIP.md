# Architecture v5 역할 및 소유권

이 문서는 누가 어떤 영역을 맡고, 어떤 문서를 검토하며, 누구의 확인을 받아야 하는지 설명합니다. 역할은 모두 정해졌지만 일부 GitHub 계정은 저장소의 담당자 선택 목록에 아직 나타나지 않습니다.

## 현재 상태

팀이 제공한 역할표를 기준으로 8개 역할의 담당자와 GitHub 계정을 연결했습니다. 전체 검토는 [PM 전체 관리 Issue #1](https://github.com/SASTsimi/sastsimi/issues/1)에서 확인합니다.

- 저장소 관리 담당: 김태현 `@taehyeon-git`
- 설계 검토 진행 담당: 김태현 `@taehyeon-git`, 윤희섭 `@v1sion`
- 독립 최종 검토자: 아직 정하지 않음 — [전체 최종 검토 Issue #10](https://github.com/SASTsimi/sastsimi/issues/10)에서 지정
- 역할 담당자: 아래 표의 8개 역할 모두 확정
- `.github/CODEOWNERS`: 대체 검토자와 중앙 문서 승인·병합 권한을 정한 뒤 별도 PR로 추가

각 역할별 상위 Issue는 아래 담당자가 관리합니다. 담당자는 필요한 세부 작업을 직접 하위 Issue로 만듭니다. 담당자가 같더라도 통합 개발과 PM·아키텍처 Issue는 결과물과 승인 권한이 다르므로 별도로 유지합니다.

## 역할별 담당 범위

| 담당 역할 | 담당자 | 주요 담당 영역 | 우선 검토할 문서 | 반드시 함께 검토할 역할 | 역할별 상위 Issue |
|---|---|---|---|---|---|
| LLM 탐색·체이닝 | 배승원 `@baeseungwon1010` | 취약점 가설, 추가 탐색, 연계 공격과 token 최적화 | `03`, `06` | 정적분석, 검증, 데이터·평가 | [#2](https://github.com/SASTsimi/sastsimi/issues/2) |
| 정적분석·컨텍스트 | 김나연 `@meow` | AST/SAST 결과 정리, 코드 사실 묶음과 필요한 코드 조회 | `02` | LLM 탐색, 검증 | [#3](https://github.com/SASTsimi/sastsimi/issues/3) |
| 단독 구현·통합 개발 | 김태현 `@taehyeon-git`, 윤희섭 `@v1sion` | LLM 연결과 실행 경계, 구현 가능성, 테스트·모듈 통합 | `09`, 구현 가능성 검토 | PM, 데이터·평가, 동적검증 | [#4](https://github.com/SASTsimi/sastsimi/issues/4) |
| PM·아키텍처·워크플로 | 김태현 `@taehyeon-git`, 윤희섭 `@v1sion` | 전체 분석 흐름, 공통 입출력 약속, 사람·LLM 경계, 오류·병렬 처리 | root README, `01`, `08`, `11`, `13`, Wiki 통합 | 전체 파트 | [#5](https://github.com/SASTsimi/sastsimi/issues/5) |
| Gate·Finding·보고서 | 김혜령 `@kimhr8465` | 기술 근거·공식 정책 검토, 취약점 결과와 보고서 초안 | `05`, `12` | 검증, PM, 데이터·평가 | [#6](https://github.com/SASTsimi/sastsimi/issues/6) |
| 검증·반박·플레이북 | 임채민 `@UltraPaechKeen` | 찬성·반대 근거, 기술 판정과 우회 가능성 검증 | `04` 검증 영역 | LLM 탐색, 동적검증, Gate | [#7](https://github.com/SASTsimi/sastsimi/issues/7) |
| 동적검증·Sandbox | 조근석 `@Potatonion` | 제한·전체 재현, PoC, Docker 실행 근거 | `04` 동적 영역, `10` 격리 실행 영역 | 검증, PM, 통합 개발 | [#8](https://github.com/SASTsimi/sastsimi/issues/8) |
| 데이터·평가·예산 | 성병찬 `@gitterable` | 평가 자료, 품질 지표, LLM 실행 기록과 자원 한도 | `07`, `08/09` 관련 지표 | 전체 LLM 역할, PM | [#9](https://github.com/SASTsimi/sastsimi/issues/9) |

번호는 `docs/architecture-v5/` 아래 정본 문서를 의미합니다.

## 역할 배정과 GitHub 담당자 지정 상태

역할 담당은 8개 모두 확정되었습니다. 아래 목록은 역할 배정 여부가 아니라 GitHub 화면에서 실제 담당자로 선택할 수 있었는지를 보여 줍니다.

- 배정 완료: `@taehyeon-git`(#1, #4, #5), `@baeseungwon1010`(#2), `@Potatonion`(#8), `@gitterable`(#9)
- 역할·본문 연결 완료, GitHub 담당자 선택 불가: `@v1sion`(#1, #4, #5), `@meow`(#3), `@kimhr8465`(#6), `@UltraPaechKeen`(#7)
- 의도적 미배정: [최종 #10](https://github.com/SASTsimi/sastsimi/issues/10)의 독립 최종 검토자

`GitHub 담당자 선택 불가`는 역할 미배정을 뜻하지 않습니다. GitHub Issue 선택기에 계정이 나타나지 않은 상태이므로 저장소 접근 권한 또는 정확한 사용자명을 확인한 뒤 실제 담당자로 추가해야 합니다.

## 담당자가 하위 Issue를 관리하는 방법

1. 자신의 역할별 상위 Issue(#2–#9)를 읽고 작업을 나눕니다.
2. 한 번에 완료 여부를 판단할 수 있는 크기로 하위 Issue를 직접 만듭니다.
3. 하위 Issue에 담당자, 쉬운 설명, 수정할 문서, 완료 조건과 상위 Issue 번호를 적습니다.
4. 작업 PR에 `Closes #하위-Issue`와 `Refs #역할별-상위-Issue`를 함께 적습니다.
5. 모든 하위 Issue와 연결 PR이 끝난 뒤 역할별 상위 Issue를 닫습니다.

PM은 하위 Issue를 대신 세세하게 작성하지 않습니다. PM은 역할 사이의 충돌, 공통 문서 변경과 전체 진행 상태를 관리합니다.

## 중앙 통합 파일

다음 파일은 한 명의 역할 담당자(`domain owner`)가 혼자 확정하지 않습니다.

- `README.md`
- `docs/architecture-v5/README.md`
- `docs/architecture-v5/01-system-overview.md`
- `docs/architecture-v5/08-lightweight-data-contracts.md`
- `docs/architecture-v5/13-architecture-diagrams.md`
- `docs/architecture-v5/wiki/diagrams.md`

변경을 제안한 데이터 생산 역할과 그 데이터를 받는 역할이 모두 의미를 확인한 뒤 설계 검토 진행 담당이 `main` 대상 PR을 병합합니다.

## 권한 분리

- Hypothesis Agent는 verdict·Finding을 만들지 않습니다.
- Verification Agent가 기술 verdict를 생성하지만 외부 공개를 결정하지 않습니다.
- Research Agent와 Primitive match는 새 가설만 제안합니다.
- Technical Evidence Gate와 Rule Scope Impact Gate는 verdict를 직접 변경하지 않습니다.
- Reporter는 내부 초안만 만듭니다.
- 사람만 최종 공개를 승인합니다.

## 아직 필요한 GitHub 협업·승인 규칙 결정

역할과 GitHub 계정은 매핑했습니다. 다음 항목을 정한 뒤 CODEOWNERS를 추가합니다.

1. 각 역할의 대체 검토자
2. 중앙 계약 승인 가능 여부
3. 브랜치 병합 권한 여부

독립 최종 검토자가 정해지기 전에는 검토 중인 설계 초안의 최종 승인 PR을 ‘검토 준비 완료’ 상태로 바꾸지 않습니다.
