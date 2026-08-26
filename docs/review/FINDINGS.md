# Architecture v5 검토 발견사항

이 문서는 현재 설계에서 발견된 문제와 해결 조건을 한곳에 모읍니다. 실제 담당자, 토론, 결정과 완료 증거는 연결된 GitHub Issue와 PR에서 관리합니다.

- `OPEN`: 아직 시작하지 않았거나 해결되지 않음
- `IN_PROGRESS`: 담당자가 해결 중
- `RESOLVED`: 완료 근거가 확인됨
- `DEFERRED`: 이유, 담당자와 다시 볼 시점을 정하고 미룸

## Blocker

| ID | 상태 | 쉽게 말하면 | 정확한 문제 | 처리·완료 조건 | 담당 역할 | Issue |
|---|---|---|---|---|---|---|
| B-001 | IN_PROGRESS | 역할은 정했지만 일부 계정을 GitHub 담당자로 선택할 수 없고 대체 검토자·승인 권한도 정하지 못했습니다. | 4개 계정은 Issue assignee 선택 불가이며 대체 reviewer·승인·merge 권한도 미확정 | 계정 접근 권한과 사용자명, 대체 검토자와 권한을 확인하고 assignee, `CODEOWNERS`, 필수 검토 규칙에 반영 | PM·아키텍처·워크플로 | [#5](https://github.com/SASTsimi/sastsimi/issues/5) |
| B-002 | OPEN | 최종 설계를 독립적으로 확인할 사람이 아직 없습니다. | 독립 최종 검토자 미지정 | 작성자·설계 검토 진행 담당과 다른 검토자를 지정하고 고정된 최신 commit을 승인 | 저장소 관리 담당 | [#10](https://github.com/SASTsimi/sastsimi/issues/10) |
| B-003 | OPEN | 외부 사람이 이 저장소를 수정·재사용해도 되는 범위가 없습니다. | 공개 저장소의 라이선스와 외부 기여 정책 미결정 | 허용 범위를 결정하고 `LICENSE`와 `CONTRIBUTING.md`에 반영 | 저장소 관리 담당 | [#5](https://github.com/SASTsimi/sastsimi/issues/5) |
| B-004 | RESOLVED | 가져온 원본이 commit에 없었기 때문에 특정 commit에서 나온 파일이라고 말할 수 없습니다. | 원본이 commit되지 않은 작업 폴더라 commit 출처를 주장할 수 없음 | [가져온 출처 기록](./PROVENANCE.md)에 원본 상태와 파일 해시를 기록 | PM·아키텍처·워크플로 | [#5](https://github.com/SASTsimi/sastsimi/issues/5) |
| B-005 | RESOLVED | 검토 중인 초안이 승인된 최종 설계처럼 보였습니다. | candidate가 승인된 기준 문서처럼 표현됨 | root/v5/Wiki에 검토 중인 설계 초안과 승인·동기화 경계를 명시 | PM·아키텍처·워크플로 | [#5](https://github.com/SASTsimi/sastsimi/issues/5) |
| B-006 | RESOLVED | LLM이 보안 규칙을 마음대로 바꿀 수 있는 것처럼 읽힐 수 있었습니다. | LLM Orchestration이 보안 강제 권한을 가진 것으로 해석될 수 있음 | 비-LLM 프로그램 규칙 검사기와 모든 LLM 출력의 비신뢰 경계를 명시 | PM·아키텍처·워크플로 | [#5](https://github.com/SASTsimi/sastsimi/issues/5) |

## High

| ID | 상태 | 쉽게 말하면 | 정확한 문제 | 처리·완료 조건 | 담당 역할 | Issue |
|---|---|---|---|---|---|---|
| H-001 | OPEN | 같은 분석 안에서 저장소·파일·코드 위치가 같은 시점을 가리킨다는 보장이 부족합니다. | `RepositorySnapshot`, `ArtifactRef`, `LocationRef`, `EntityRef`의 식별자·불변성 약속 부족 | submodule, LFS, 생성된 의존성과 revision 연결을 포함한 입출력 약속과 실패 시나리오 합의 | 정적분석·컨텍스트 + PM | [#3](https://github.com/SASTsimi/sastsimi/issues/3), [#5](https://github.com/SASTsimi/sastsimi/issues/5) |
| H-002 | IN_PROGRESS | 정적분석·동적검증·판정 파트가 생성 시각과 실패 상태를 서로 다르게 부릅니다. | 공통 생성 시각, static gap 이름, dynamic failure/falsification 구분 충돌 | `created_at`, 공통 `gaps`, `failure_class/falsification_observed` 반영 후 결과를 받는 역할의 교차 검토 | PM + 정적/동적/검증 | [#3](https://github.com/SASTsimi/sastsimi/issues/3), [#5](https://github.com/SASTsimi/sastsimi/issues/5), [#7](https://github.com/SASTsimi/sastsimi/issues/7), [#8](https://github.com/SASTsimi/sastsimi/issues/8) |
| H-003 | OPEN | 여러 LLM 검토 방식이 실제로 품질을 높이는지 판단할 합격 기준이 없습니다. | 조건부 debate, 독립 session, LLM Gate, provider/model 선택의 평가 종료 기준 없음 | 버전이 있는 예제 모음, 공격적 예제, 지표와 합격선을 합의 | 데이터·평가·예산 | [#9](https://github.com/SASTsimi/sastsimi/issues/9) |
| H-004 | OPEN | 회원 로그인 방식의 LLM 연결이 공식적으로 허용되고 안정적인지 확인되지 않았습니다. | Membership adapter의 지원·약관·동시성·log 가용성 미검증 | 구현 가능성과 보안을 확인하기 전 선택 실험으로 제한하고 중단·성공 조건 정의 | 단독 구현·통합 개발 | [#4](https://github.com/SASTsimi/sastsimi/issues/4) |
| H-005 | OPEN | Docker 재현과 공식 정책 수집의 안전 설계가 아직 요구사항 수준입니다. | Docker reproduction과 policy capture의 threat model/ADR 미완료 | daemon, image, 외부 통신, 정리와 정책 출처 인증·최신성·해석 실패에 대한 설계 결정 승인 | 동적검증·Sandbox + Gate | [#6](https://github.com/SASTsimi/sastsimi/issues/6), [#8](https://github.com/SASTsimi/sastsimi/issues/8) |
| H-006 | OPEN | 병렬 실행이나 중단 뒤 재시작할 때 같은 작업이 중복되거나 사라질 수 있습니다. | 병렬 가설·재시도·Gate 보완의 저장·복구 의미 부족 | 한 번에 반영되는 상태 변경, 중복 실행 방지, 동시성, revision 연결과 중단 복구 약속 승인 | PM + 통합 개발 | [#4](https://github.com/SASTsimi/sastsimi/issues/4), [#5](https://github.com/SASTsimi/sastsimi/issues/5) |

## Medium/Low backlog

- Wiki는 사용자 요구에 따라 포함했으나 파생·비규범적으로 유지한다. 장기적으로 번호 문서에서 생성·검증하는 방식을 결정한다.
- `11-migration-from-v4.md`는 비규범적 설계 계보로 전환했으며 로컬 v4 경로 주장을 제거했다.
- Primitive 입력은 `TRUE`의 PROVIDED와 `HOLD`의 REQUIRED로 명확화했다. `FALSE`를 chaining 근거로 승격하지 않는다.
- Docsify가 사용하는 외부 CDN dependency의 version pinning과 offline rendering 정책은 별도 결정한다.
- 표현·예시·문서 미세 보정은 Blocker/High 검토보다 후순위다.

## 최종 승인 검토를 시작할 조건

1. 열린 Blocker와 High가 0이다.
2. Medium은 해결되거나 담당자·근거·목표 시점과 함께 명시적으로 연기된다.
3. [최종 Issue #10](https://github.com/SASTsimi/sastsimi/issues/10)과 최종 승인 PR에 검토 대상을 고정한 commit SHA를 기록한다.
4. 검토 대상을 고정한 뒤 변경이 생기면 기존 승인을 무효화하고 재검토한다.
5. 독립 최종 검토자가 최신 SHA를 승인한다.
6. 별도 승인 PR에서만 상태를 변경한다.
