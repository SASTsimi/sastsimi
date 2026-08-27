# Architecture v5 미결정 사항

이 문서는 아직 팀이 결정하지 못한 내용을 모아 둡니다. 실제 토론, 담당자, 기한과 결정 결과는 [PM 전체 관리 Issue #1](https://github.com/SASTsimi/sastsimi/issues/1)과 [실제 Issue 현황](../review/ISSUE_TRACKER.md)에서 관리합니다. 결정한 내용은 관련 기준 문서와 PR에 반영해야 합니다.

각 항목은 ‘무엇을 정해야 하는가’, ‘정하지 않으면 어떤 문제가 생기는가’, ‘누가 어느 Issue에서 다루는가’ 순서로 읽으면 됩니다.

## Blocker

현재 이 문서에서 관리하는 열린 Blocker는 없습니다.

## 이번에 확정한 운영 사항

1. 담당자 계정
   - #3 김나연은 `@zv9uvr`, #6 김혜령은 `@kimhr8463`, #7 임채민은 `@UltraPeachKeen`을 실제 GitHub 계정으로 사용합니다.
   - 윤희섭 `@v1sion`은 #1·#4·#5의 공동 역할 담당자입니다. GitHub 공동 담당자(assignee) 지정 여부는 역할 확정이나 작업 시작을 막지 않습니다.
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
   - 담당 역할과 Issue: 저장소 관리 담당, [#5](https://github.com/SASTsimi/sastsimi/issues/5)

## 구현 전 필수 결정

| 번호 | 쉽게 말하면 무엇을 정해야 하나 | 정확한 기술 항목 |
|---|---|---|
| 1 | 역할별로 어떤 LLM 서비스와 모델을 쓸지 정합니다. | provider/model profile과 공식 지원 범위 |
| 2 | 회원 로그인·API 인증정보와 로그인 상태를 어디까지 저장할지 정합니다. | Membership/API credential와 session 저장 경계 |
| 3 | 새 대화, 이어서 대화, 자동 선택을 어떻게 비교하고 기본 한도를 얼마로 할지 정합니다. | `NEW / RESUME / AUTO` 평가와 기본 limit |
| 4 | LLM이 잘못된 형식으로 답했을 때 몇 번 고치게 할지와 신뢰도 평가 방법을 정합니다. | Hypothesis schema repair 횟수와 confidence 기준 |
| 5 | 필요한 코드를 얼마나 깊고 많이 가져올 수 있는지 정합니다. | Context retrieval depth/token/request 제한 |
| 6 | 찬성·반대 검증을 언제 실행할지와 효과를 비교할 예제 모음을 정합니다. | `CONDITIONAL_DEBATE` trigger와 비교 corpus |
| 7 | 연계 공격의 필요 조건과 확인된 능력을 어떤 단어로 기록하고 연결할지 정합니다. | Primitive vocabulary와 scope/capability matching |
| 8 | 연계 탐색이 끝없이 늘어나지 않도록 한도를 정합니다. | Research/chain depth·count·token·time·duplicate 제한 |
| 9 | Docker 이미지, 네트워크, 자원과 종료 후 정리 방법을 정합니다. | image/network/resource/cleanup 정책 |
| 10 | 공식 프로그램 정책을 어디서 가져오고 최신 여부와 실패를 어떻게 처리할지 정합니다. | `ProgramPolicySnapshot` source·freshness·failure |
| 11 | 두 Gate가 사용할 질문, 보완 반복 횟수와 평가 자료를 정합니다. | Gate prompt, revision limit와 dataset |
| 12 | LLM 호출 기록에서 비밀정보를 가리고 얼마나 보관할지 정합니다. | logging proxy/parser, redaction, retention, access control |
| 13 | 데이터를 저장하고 버전을 바꿀 때 호환성을 어떻게 지킬지 정합니다. | serialization, schema versioning, result storage |
| 14 | 저장소·파일·코드 위치를 같은 분석 시점에 묶는 식별 규칙을 정합니다. | `RepositorySnapshot`, `ArtifactRef`, `LocationRef`, `EntityRef`, submodule/LFS/generated dependency 계약 |
| 15 | 병렬 실행·재시도·중단 복구 중 같은 작업이 중복 처리되지 않도록 정합니다. | atomic state transition, idempotency, crash resume |
| 16 | 회원제 LLM 연결이 공식적으로 허용되고 안정적으로 동작하는지 확인할 종료 조건을 정합니다. | Membership adapter 지원·약관·동시성·session/log 검증 |
| 17 | Docker 실행과 공식 정책 수집에서 생길 위협과 대응을 별도 결정 기록으로 남깁니다. | daemon/image/build provenance, policy 인증·freshness threat model/ADR |
| 18 | 세션·Gate·모델 선택이 실제 품질을 높이는지 같은 예제로 비교할 합격선을 정합니다. | versioned corpus, 지표와 acceptance threshold |

## 어느 Issue에서 결정하나요?

| 결정 영역 | 담당 역할별 상위 Issue |
|---|---|
| provider/model, membership/session, 상태 저장·복구 | [R3 #4](https://github.com/SASTsimi/sastsimi/issues/4), [R4 #5](https://github.com/SASTsimi/sastsimi/issues/5) |
| Hypothesis, Primitive, Research와 chaining 한도 | [R1 #2](https://github.com/SASTsimi/sastsimi/issues/2) |
| snapshot, static fact, location/context retrieval | [R2 #3](https://github.com/SASTsimi/sastsimi/issues/3) |
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
