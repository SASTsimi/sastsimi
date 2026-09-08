# Architecture v5 구현·운영 전 남은 설정과 증거

Architecture v5의 구조·역할·공통 계약은 승인됐습니다. 이 문서는 설계를 다시 정하는 미결정 목록이 아니라, 실제 코드를 만들고 기능을 켜기 전에 채워야 할 설정값과 시험 증거를 모아 둡니다. 과거 승인 과정은 [PM 전체 관리 Issue #1](https://github.com/SASTsimi/sastsimi/issues/1), [최종 Issue #10](https://github.com/SASTsimi/sastsimi/issues/10)과 [Issue 현황](../review/ISSUE_TRACKER.md)에 보존합니다. 새 구현 결정은 별도 구현 Issue·PR에 남깁니다.

각 항목은 ‘실제로 채울 값이나 증거’, ‘미완료 시 차단할 기능’, ‘확인할 역할’ 순서로 읽으면 됩니다.

## Blocker

현재 구현 시작을 막는 미결정 Blocker는 없습니다. R3-06에서 다음 두 항목을 확정했습니다.

- 핵심 결과 네 종류의 `SAVE_RESULT` result-owner, exact pointer와 atomic commit 연결
- run-init Docker baseline branch 제거와 실제 Docker 준비를 가설별 `DYNAMIC_REPRO`로 한정하는 경계

PR #116 병합과 Issue #92·R3 상위 Issue #4 종료로 구현 기준 설계까지 확정했습니다. 실제 Provider capability, 평가 실행과 Docker 보안 시험처럼 코드와 실행 환경이 있어야 얻을 수 있는 증거는 아래 담당 역할이 구현 단계에서 확인합니다. 미실행 시험을 성공으로 표시하지 않으며, 통과 전 기능은 문서의 fail-closed 기본값으로 비활성화합니다.

## 이번에 확정한 운영 사항

1. 담당자 계정
   - #3 김나연은 `@zv9uvr`, #6 김혜령은 `@kimhr8463`, #7 임채민은 `@UltraPeachKeen`을 실제 GitHub 계정으로 사용합니다.
   - 윤희섭 `@YHS-Sec`은 #1·#4·#5의 공동 역할 담당자입니다. GitHub 공동 담당자(assignee) 지정 여부는 역할 확정이나 작업 시작을 막지 않습니다.
   - 대체 검토자와 `CODEOWNERS`(파일별 자동 검토 요청 설정)는 협업 자동화를 위한 후속 개선으로 관리하며 현재 설계 검토의 Blocker로 보지 않습니다.
2. 최종 검토·승인 담당자
   - 김태현 `@taehyeon-git`이 [전체 최종 검토 Issue #10](https://github.com/SASTsimi/sastsimi/issues/10)을 관리하고 최종 결과를 확인합니다.
   - 김태현은 PM과 문서 통합도 맡으므로 이 역할을 `독립 검토자`라고 부르지 않습니다.
   - 각 파트는 다른 역할 담당자의 교차 검토를 먼저 받아야 하며, 김태현은 그 기록과 전체 흐름을 마지막에 확인합니다.

## 공개·외부 기여 전에 결정할 사항

1. 저장소 라이선스와 외부 기여 범위
   - 현재 팀 내부의 설계·개발·실행을 시작하기 위해 라이선스를 먼저 정할 필요는 없습니다.
   - 외부인의 코드 사용·수정·재배포 또는 외부 기여를 공식적으로 허용하기 전에는 라이선스와 기여 범위를 정해야 합니다.
   - 결정 전에는 `LICENSE` 파일을 추가하지 않습니다. 오픈소스 공개를 결정할 때 Apache-2.0 같은 후보를 비교하고 `LICENSE`와 `CONTRIBUTING.md`에 함께 반영합니다.
   - 참고: [GitHub의 저장소 라이선스 안내](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository)
   - 담당 역할: 저장소 관리 담당. 외부 공개를 준비할 때 별도 Issue를 만듭니다. 완료된 설계 Issue #5를 다시 열어 관리하지 않습니다.

## 구현·운영에서 채울 실제 설정과 증거

아래 항목은 Architecture v5의 구조를 다시 정해야 하는 Blocker가 아닙니다. 승인된 schema·권한·실패 규칙 안에서 실제 설정값과 시험 증거를 만들기 위한 구현 작업입니다. 운영 활성화 조건을 만족하지 못하면 해당 기능을 켜지 않습니다.

| 번호 | 쉽게 말하면 무엇을 정해야 하나 | 정확한 기술 항목 |
|---|---|---|
| 1 | 역할별로 어떤 LLM 서비스와 모델을 쓸지 정합니다. | `provider_profile_ref`가 가리키는 provider 설정과 호출 시점의 `model`, 공식 지원 범위 |
| 2 | 회원 로그인·API 인증정보와 로그인 상태를 어디까지 저장할지 정합니다. | Membership/API credential와 session 저장 경계 |
| 3 | 새 대화, 이어서 대화, 자동 선택을 어떻게 비교하고 기본 한도를 얼마로 할지 정합니다. | `NEW / RESUME / AUTO` 평가와 기본 limit |
| 4 | LLM이 잘못된 형식으로 답했을 때 몇 번 고치게 할지와 구조화된 출력의 합격 기준을 정합니다. | Hypothesis schema repair 횟수와 structured-output 합격 기준 |
| 5 | 필요한 코드를 얼마나 깊고 많이 가져올 수 있는지 정합니다. | Context retrieval depth/fragment/byte/request/time 제한; token은 관측만 함 |
| 6 | 운영은 항상 찬성·반대 검증을 실행합니다. BASIC·조건부 방식의 비용·효과를 비교할 평가 자료와 운영 전환 합격선만 정합니다. | `ALWAYS_DEBATE` 운영 고정, BASIC/CONDITIONAL 비교 corpus와 acceptance threshold |
| 7 | 연계 공격의 필요 조건과 확인된 능력을 어떤 단어로 기록하고 연결할지 정합니다. | Primitive vocabulary와 scope/capability matching |
| 8 | 연계 탐색이 끝없이 늘어나지 않도록 전체 실행 한도와 중복 기준을 정합니다. | 전체 time·cost·work와 duplicate/ancestor 기준; 체이닝 전용 depth·count·조합·token 상한은 두지 않음 |
| 9 | Docker 이미지, 네트워크, 자원과 종료 후 정리 방법을 정합니다. | image/network/resource/cleanup 정책 |
| 10 | 공식 정책의 출처별 최대 허용 나이와 확인 방법을 정합니다. 공통 처리 규칙은 이미 확정되어, run 시작 때 오래된 cache는 재사용하지 않고 최신성을 확인하지 못한 현재 run은 `UNCERTAIN + DENY`입니다. | `ProgramPolicyRecord` source·freshness threshold·collector failure; `STALE cache -> 새 수집`, `UNVERIFIED run -> UNCERTAIN + DENY` 고정 |
| 11 | 두 Gate가 사용할 질문, 보완 반복 횟수와 평가 자료를 정합니다. | Gate prompt, revision limit와 dataset |
| 12 | LLM 호출 기록에서 비밀정보를 가리고 얼마나 보관할지 정합니다. | logging proxy/parser, redaction, retention, access control |
| 13 | 데이터를 저장하고 버전을 바꿀 때 호환성을 어떻게 지킬지 정합니다. | serialization, schema versioning, result storage |
| 14 | 승인된 식별 규칙을 실제 clone·경로 조회 코드와 시험으로 증명합니다. | 확정된 `CodeWorkspace`, `workspace_id`, `commit_id`, `StoredDataRef`, `CodeLocation`, `CodeSymbol` 계약 구현 |
| 15 | 승인된 중복 방지·복구 규칙을 실제 저장소와 장애 주입 시험으로 증명합니다. | 확정된 atomic state transition, idempotency, crash resume 계약 구현 |
| 16 | 회원제 LLM 연결이 공식적으로 허용되고 안정적으로 동작하는지 확인할 종료 조건을 정합니다. | Membership adapter 지원·약관·동시성·session/log 검증 |
| 17 | 승인된 Docker·정책 수집 위협 대응이 실제로 차단되는지 부정 시험합니다. | daemon/image/build provenance, policy 인증·freshness·Parser failure 시험 |
| 18 | 세션·Gate·모델 선택이 실제 품질을 높이는지 같은 예제로 비교할 합격선을 정합니다. | versioned corpus, 지표와 acceptance threshold |

## 어느 역할이 구현에서 확인하나요?

| 구현·검증 영역 | 담당 역할과 완료된 설계 Issue |
|---|---|
| provider/model, membership/session, 상태 저장·복구 | [R3 #4](https://github.com/SASTsimi/sastsimi/issues/4), [R4 #5](https://github.com/SASTsimi/sastsimi/issues/5) |
| Hypothesis, Primitive와 Chaining 한도 | [R1 #2](https://github.com/SASTsimi/sastsimi/issues/2) |
| clone·checkout, static fact, location/context retrieval | [R2 #3](https://github.com/SASTsimi/sastsimi/issues/3) |
| Verification, debate와 falsification | [R6 #7](https://github.com/SASTsimi/sastsimi/issues/7) |
| Docker sandbox와 동적 재현 | [R7 #8](https://github.com/SASTsimi/sastsimi/issues/8) |
| Gate, 공식 정책과 보고서 전달 | [R5 #6](https://github.com/SASTsimi/sastsimi/issues/6) |
| corpus, 지표, 합격 기준과 자원 예산 | [R8 #9](https://github.com/SASTsimi/sastsimi/issues/9) |

## 결정을 남기는 형식

각 결정 Issue는 다음을 포함합니다.

- 현재 상황과 문제(`Context`)
- 선택할 수 있는 방법(`Options`)
- 보안·품질·비용의 장단점(`trade-off`)
- 결정 담당자
- 반드시 확인할 검토자
- 목표 날짜
- 최종 결정과 근거
- 반영한 PR과 commit

설계 의미를 바꾸지 않는 실제 시험 결과와 설정 revision은 구현 Issue·PR에 남깁니다. field·enum·권한·상태 전이를 바꿔야 하면 새 ADR과 영향 역할 검토를 먼저 진행합니다.
