# Architecture v5 역할 및 소유권

이 문서는 누가 어떤 영역을 맡고, 어떤 문서를 검토하며, 누구의 확인을 받아야 하는지 설명합니다. 역할과 실제 GitHub 계정은 모두 정해졌습니다.

## 현재 상태

팀이 제공한 역할표를 기준으로 8개 역할의 담당자와 GitHub 계정을 연결했습니다. 전체 검토는 [PM 전체 관리 Issue #1](https://github.com/SASTsimi/sastsimi/issues/1)에서 확인합니다.

- 저장소 관리 담당: 김태현 `@taehyeon-git`
- 설계 검토 진행 담당: 김태현 `@taehyeon-git`, 윤희섭 `@YHS-Sec`
- 최종 검토·승인 담당자: 김태현 `@taehyeon-git` — [전체 최종 검토 Issue #10](https://github.com/SASTsimi/sastsimi/issues/10) 관리
- 역할 담당자: 아래 표의 8개 역할 모두 확정
- `.github/CODEOWNERS`: 대체 검토자와 자동 검토 요청이 필요해질 때 별도 PR로 추가하는 후속 개선이며 현재 작업의 Blocker가 아님

각 역할별 상위 Issue는 아래 담당자가 관리합니다. 담당자는 필요한 세부 작업을 직접 하위 Issue로 만듭니다. 담당자가 같더라도 통합 개발과 PM·아키텍처 Issue는 결과물과 승인 권한이 다르므로 별도로 유지합니다.

## 역할별 담당 범위

| 담당 역할 | 담당자 | 주요 담당 영역 | 우선 검토할 문서 | 반드시 함께 검토할 역할 | 역할별 상위 Issue |
|---|---|---|---|---|---|
| LLM 탐색·체이닝 | 배승원 `@baeseungwon1010` | 최초 가설과 HOLD REQUIRED·Gate-qualified TRUE PROVIDED의 방향성 연계 후보 | `03`, `06` | 정적분석, 검증, 데이터·평가 | [#2](https://github.com/SASTsimi/sastsimi/issues/2) |
| 정적분석·컨텍스트 | 김나연 `@zv9uvr` | AST/SAST 결과 정리, 코드 사실 묶음과 필요한 코드 조회 | `02` | LLM 탐색, 검증 | [#3](https://github.com/SASTsimi/sastsimi/issues/3) |
| 단독 구현·통합 개발 | 김태현 `@taehyeon-git`, 윤희섭 `@YHS-Sec` | LLM 연결과 실행 경계, 구현 가능성, 테스트·모듈 통합 | `09`, 구현 가능성 검토 | PM, 데이터·평가, 동적검증 | [#4](https://github.com/SASTsimi/sastsimi/issues/4) |
| PM·아키텍처·워크플로 | 김태현 `@taehyeon-git`, 윤희섭 `@YHS-Sec` | 전체 분석 흐름, 공통 입출력 약속, 사람·LLM 경계, 오류·병렬 처리 | root README, `01`, `08`, `11`, `13`, Wiki 통합 | 전체 파트 | [#5](https://github.com/SASTsimi/sastsimi/issues/5) |
| Gate·Finding·보고서 | 김혜령 `@kimhr8463` | 기술 근거·공식 정책 검토, 같은 Verification owner로의 REVISE와 보고서 초안 | `05`, `12` | 검증, PM, 데이터·평가 | [#6](https://github.com/SASTsimi/sastsimi/issues/6) |
| 검증·반박·플레이북 | 임채민 `@UltraPeachKeen` | 찬성·반대 근거, 환경 요구사항·동적 재현 모드·`ReproductionPlan`, 환경 차이 수용 여부, 최종 기술 판정과 보완 | `04` 검증 영역 | LLM 탐색, 동적검증, Gate | [#7](https://github.com/SASTsimi/sastsimi/issues/7) |
| 동적검증·Sandbox | 조근석 `@Potatonion` | 외부 경계 정책 판정, clean Sandbox 생성 자동화, 자율 Reproduction Agent 실행, 환경·Health Check·PoC artifact와 Session Manager의 수동적 log·최종 result 문서화 | `04` 동적 영역, `10` 격리 실행 영역 | 검증, PM, 통합 개발 | [#8](https://github.com/SASTsimi/sastsimi/issues/8) |
| 데이터·평가·예산 | 성병찬 `@gitterable` | 평가 자료·품질 지표·예산 profile; 실제 action 예산은 runtime이 강제 | `07`, `08/09` 관련 지표 | 전체 LLM 역할, PM | [#9](https://github.com/SASTsimi/sastsimi/issues/9) |

번호는 `docs/architecture-v5/` 아래 정본 문서를 의미합니다.

## 역할 연결 기준

- R4는 `EnvironmentRequirements`, `ReproductionPlan`, 실제 `sandbox_environment`의 공통 필드·exact reference·상태·생산자/소비자와 오류 규칙을 담당합니다.
- R6 Verification이 `NOT_REQUIRED | LIMITED_REPRO | FULL_REPRO`를 고르고, 동적 재현이 필요하면 필요한 환경 조건과 미리 허용할 대체 버전을 `EnvironmentRequirements`로 기록한 뒤 이를 가리키는 exact `ReproductionPlan`을 생산합니다. 환경 조건을 바꾸면 새 요구사항과 이를 가리키는 새 계획을 함께 만들고, 실행 단계만 바꾸면 새 계획만 만듭니다.
- R4의 trusted runtime은 계획과 current requirements의 schema·reference·호출 권한·상태·예산을 검사해 `COMMITTED`와 `RUN_SANDBOX ALLOW`를 확정합니다. 환경 조건의 의미나 image·command·file·network·resource·cleanup 세부 정책은 판단하지 않습니다.
- R7의 Sandbox Controller는 host·Docker socket·mount·namespace·secret·금지된 egress·범위 밖 workspace 같은 Sandbox 외부 경계 정책을 판정·강제하고 exact 판정을 저장합니다. Controller는 Sandbox를 만들거나 Reproduction Agent를 호출·통제하지 않습니다. R7 Sandbox Setup Automation이 승인된 경계 안에서 image와 clean Sandbox의 생성·정리를 수행하고, Reproduction Agent가 내부 환경 구성·PoC·실행·관찰·재시도를 자율적으로 수행합니다. Reproduction Session Manager는 runtime/tool/lifecycle event를 append-only로 기록하고 Agent의 의미 초안과 실행 사실로 `DynamicReproductionResult` 문서를 확정할 뿐 Agent 실행에 간섭하지 않습니다. R6는 `COMMITTED` 결과를 소비해 최종 판정을 만듭니다.
- R7은 요구사항을 수정하거나 허용되지 않은 version fallback·환경 차이를 임의 수용할 수 없고, R6의 차이 수용은 Sandbox 정책 검사를 우회하는 권한이 아닙니다.
- R8은 예산 profile과 회귀 기준을 설계하고 각 전문 역할은 최소 품질 요구를 제공합니다. 실제 예산 차단·허용은 R4 trusted runtime의 책임입니다.
- Technical `REVISE`는 Orchestration이나 R7이 목적지를 고르지 않고 같은 ACTIVE `VerificationAssignment`의 R6 owner에게 돌아갑니다.

## 역할 배정과 GitHub 담당자 지정 상태

역할 담당은 8개 모두 확정되었습니다. 실제 GitHub 계정을 기준으로 #3은 `@zv9uvr`, #6은 `@kimhr8463`, #7은 `@UltraPeachKeen`으로 확정했습니다. #1·#4·#5의 윤희섭 `@YHS-Sec`은 공동 역할 담당자이며, GitHub 공동 담당자(assignee) 지정 여부와 역할 배정은 별개입니다.

[최종 #10](https://github.com/SASTsimi/sastsimi/issues/10)은 최종 검토·승인 담당자인 김태현 `@taehyeon-git`에게 배정합니다. 김태현은 PM과 문서 통합도 맡으므로 `독립 검토자`라는 표현은 사용하지 않습니다. 대신 각 파트의 다른 역할 담당자가 교차 검토한 기록을 먼저 남기고, 김태현이 마지막 전체 흐름과 완료 조건을 확인합니다.

## 담당자가 하위 Issue를 관리하는 방법

1. 자신의 역할별 상위 Issue(#2–#9)를 읽고 작업을 나눕니다.
2. 한 번에 완료 여부를 판단할 수 있는 크기로 하위 Issue를 직접 만듭니다.
3. 하위 Issue에 담당자, 쉬운 설명, 수정할 문서, 완료 조건과 상위 Issue 번호를 적습니다.
4. 작업 PR에 `Closes #하위-Issue`와 `Refs #역할별-상위-Issue`를 함께 적습니다.
5. 모든 하위 Issue와 연결 PR이 끝난 뒤 역할별 상위 Issue를 닫습니다.

PM은 하위 Issue를 대신 세세하게 작성하지 않습니다. PM은 역할 사이의 충돌, 공통 문서 변경과 전체 진행 상태를 관리합니다.

## 중앙 통합 파일

다음 파일은 한 명의 역할 담당자가 혼자 확정하지 않습니다.

- `README.md`
- `docs/architecture-v5/README.md`
- `docs/architecture-v5/01-system-overview.md`
- `docs/architecture-v5/08-lightweight-data-contracts.md`
- `docs/architecture-v5/13-architecture-diagrams.md`
- `docs/architecture-v5/wiki/diagrams.md`

변경을 제안한 데이터 생산 역할과 그 데이터를 받는 역할이 모두 의미를 확인한 뒤 설계 검토 진행 담당이 `main` 대상 PR을 병합합니다.

## 권한 분리

- Hypothesis Agent는 verdict·Finding을 만들지 않습니다.
- Orchestration Agent는 proposal을 검증·등록하고 Verification 배정을 제안하지만 가설 내부 작업을 선택하지 않습니다. 실제 owner는 trusted runtime의 ACTIVE `VerificationAssignment`로 저장합니다.
- Verification Agent가 가설 내부 Context·찬반·동적 재현·Gate 보완 흐름과 기술 verdict를 소유하지만 Runtime Validator를 우회하거나 외부 공개를 결정하지 않습니다. `REVISE`도 같은 assignment owner의 새 VERIFICATION work로 처리합니다.
- Chaining Agent는 Gate-qualified TRUE+HOLD 또는 앞 TRUE 능력→뒤 TRUE exact 선행 조건 match와 새 가설만 제안합니다. current Primitive index가 바뀐 결과는 저장할 수 없습니다.
- Technical Evidence Gate와 Rule Scope Impact Gate는 verdict를 직접 변경하지 않습니다.
- Reporter는 안전 요구사항을 지킨 내부 `ReportDraft`만 만들며 이 결과가 마지막 Agent 산출물입니다.
- `AnalysisRunResult` 확정 뒤 Agent 자동화가 끝나며, 사람의 검토·수정·제출·공개는 이 자동화 밖에서 수행합니다.
- Agent와 service는 실행을 `ActionRequest`로 제안하고 비-LLM Runtime Validator가 실행 범위만 허용·차단합니다.
- Runtime Validator는 verdict·CWE·공식 정책 의미를 판단하지 않으며 `ActionDecision`은 exact action에 한 번만 사용합니다.

## 후속 GitHub 협업 자동화

역할과 GitHub 계정, 최종 검토 담당자는 확정했습니다. 다음 항목은 필요해질 때 정하고 CODEOWNERS를 추가합니다. 현재 설계 검토와 개발 착수의 Blocker는 아닙니다.

1. 각 역할의 대체 검토자
2. 중앙 계약 승인 가능 여부
3. 브랜치 병합 권한 여부

최종 승인 전에는 각 파트의 교차 검토 기록과 김태현 `@taehyeon-git`의 최신 검토 대상 commit 확인이 모두 있어야 합니다.
