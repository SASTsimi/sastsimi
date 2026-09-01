# Architecture v5 검토 발견사항

이 문서는 현재 설계에서 발견된 문제와 해결 조건을 한곳에 모읍니다. 실제 담당자, 토론, 결정과 완료 증거는 연결된 GitHub Issue와 PR에서 관리합니다.

- `OPEN`: 아직 시작하지 않았거나 해결되지 않음
- `IN_PROGRESS`: 담당자가 해결 중
- `RESOLVED`: 완료 근거가 확인됨
- `DEFERRED`: 이유, 담당자와 다시 볼 시점을 정하고 미룸

## Blocker

| ID | 상태 | 쉽게 말하면 | 정확한 문제 | 처리·완료 조건 | 담당 역할 | Issue |
|---|---|---|---|---|---|---|
| B-001 | RESOLVED | 역할 담당자와 실제 GitHub 계정을 확정했습니다. | #3 `@zv9uvr`, #6 `@kimhr8463`, #7 `@UltraPeachKeen`, 윤희섭 `@YHS-Sec`을 실제 계정으로 확정하고 역할과 assignee 상태를 분리함 | 역할표·Issue·tracker를 실제 계정으로 통일하고 CODEOWNERS는 후속 개선으로 관리 | PM·아키텍처·워크플로 | [#5](https://github.com/SASTsimi/sastsimi/issues/5) |
| B-002 | RESOLVED | 최종 결과를 확인하고 승인 준비를 관리할 담당자를 정했습니다. | 최종 검토·승인 담당자 미지정 | 김태현 `@taehyeon-git`을 지정하고, 파트 간 교차 검토 후 전체 검토를 수행하는 절차를 문서화 | 저장소 관리 담당 | [#10](https://github.com/SASTsimi/sastsimi/issues/10) |
| B-004 | RESOLVED | 가져온 원본이 commit에 없었기 때문에 특정 commit에서 나온 파일이라고 말할 수 없습니다. | 원본이 commit되지 않은 작업 폴더라 commit 출처를 주장할 수 없음 | [가져온 출처 기록](./PROVENANCE.md)에 원본 상태와 파일 해시를 기록 | PM·아키텍처·워크플로 | [#5](https://github.com/SASTsimi/sastsimi/issues/5) |
| B-005 | RESOLVED | 검토 중인 초안이 승인된 최종 설계처럼 보였습니다. | candidate가 승인된 기준 문서처럼 표현됨 | root/v5/Wiki에 검토 중인 설계 초안과 승인·동기화 경계를 명시 | PM·아키텍처·워크플로 | [#5](https://github.com/SASTsimi/sastsimi/issues/5) |
| B-006 | RESOLVED | LLM이 보안 규칙이나 공개 절차를 마음대로 바꾸지 못하게 실행 권한을 분리했습니다. | LLM Orchestration이 보안 강제 권한을 가진 것으로 해석될 수 있음 | R4-03에서 역할 권한표, `ActionRequest`·`ActionDecision`, 비신뢰 입력, 두 Gate·Reporter·사람 경계와 29개 권한 시나리오를 정의함 | PM·아키텍처·워크플로 | [#15](https://github.com/SASTsimi/sastsimi/issues/15), [#5](https://github.com/SASTsimi/sastsimi/issues/5) |

현재 열린 Blocker는 0개입니다.

## High

| ID | 상태 | 쉽게 말하면 | 정확한 문제 | 처리·완료 조건 | 담당 역할 | Issue |
|---|---|---|---|---|---|---|
| H-002 | RESOLVED | 공통 타입, 상태·오류 의미와 두 Gate·보고서의 정확한 수정본 연결을 통일했습니다. | Verification 세부 타입과 Primitive/정책 항목을 정의하고, 두 Gate·ReportDraft가 같은 Verification·CWELabel·정책 revision을 사용하도록 고정했으며 retry/failover는 허용된 바로 앞 실패 상태만 연결함 | PR #18 병합, R2·R3·R6·R7 교차 검토 기록과 Issue #13 완료 처리로 R4-01 기준에 반영함 | PM + 정적/동적/검증/통합 | [#13](https://github.com/SASTsimi/sastsimi/issues/13), [#18](https://github.com/SASTsimi/sastsimi/pull/18) |
| H-003 | OPEN | 여러 LLM 검토 방식이 실제로 품질을 높이는지 판단할 합격 기준이 없습니다. | 운영은 ALWAYS_DEBATE로 고정했지만 BASIC/CONDITIONAL 비교, 독립 session, LLM Gate, provider/model 선택의 평가 종료 기준은 없음 | 격리된 버전 예제 모음, 공격적 예제, 지표와 운영 정책 변경 합격선을 합의 | 데이터·평가·예산 | [#9](https://github.com/SASTsimi/sastsimi/issues/9) |
| H-004 | OPEN | 회원 로그인 방식의 LLM 연결이 공식적으로 허용되고 안정적인지 확인되지 않았습니다. | Membership adapter의 지원·약관·동시성·log 가용성 미검증 | R4-03에서 허용 provider/profile·session·explicit failover와 일회성 action 경계는 정의함. 구현 가능성과 보안을 확인하기 전 선택 실험으로 제한하고 중단·성공 조건은 R3가 확정 | 단독 구현·통합 개발 | [#4](https://github.com/SASTsimi/sastsimi/issues/4), [#15](https://github.com/SASTsimi/sastsimi/issues/15) |
| H-005 | OPEN | Docker 재현과 공식 정책 수집의 안전 설계가 아직 요구사항 수준입니다. | Docker reproduction과 policy capture의 threat model/ADR 미완료 | R4는 PoC·Controller 정책 판정·실제 환경·Runner log의 exact reference, nullable 조건과 cleanup 상태 조합을 정의함. daemon·image 공급망·외부 통신·자원별 정리와 네 artifact 상세 schema는 R7이, 정책 출처 인증·최신성 ADR은 R5가 확정 | 동적검증·Sandbox + Gate | [#6](https://github.com/SASTsimi/sastsimi/issues/6), [#8](https://github.com/SASTsimi/sastsimi/issues/8), [#21](https://github.com/SASTsimi/sastsimi/issues/21), [#22](https://github.com/SASTsimi/sastsimi/issues/22) |
| H-006 | RESOLVED | 병렬 실행·retry·중단 뒤에도 같은 작업과 결과를 한 번만 반영하도록 설계했습니다. | 공통 `WorkExecutionState`·attempt·state version·dedupe·atomic output binding·journal recovery와 stale result 차단 규칙이 필요했음 | `03`, `07`, `08`, `10`, `13`과 Wiki에 허용 전이, `dedupe_key`, compare-and-set, `TransitionCommit`, exact output pointer, crash-resume와 16개 상태·복구 부정 시나리오를 정의함. 실제 저장 제품·성능 검증은 R3 구현 단계에서 확인 | PM + 통합 개발 | [#14](https://github.com/SASTsimi/sastsimi/issues/14), [#4](https://github.com/SASTsimi/sastsimi/issues/4), [#5](https://github.com/SASTsimi/sastsimi/issues/5) |
| H-007 | RESOLVED | TRUE+TRUE 방향, 같은 검증 담당자, REVISE 재진입과 오래된 체이닝 결과 차단을 계약으로 고정했습니다. | 두 PROVIDED만 비교하면 뒤 TRUE의 선행 조건을 증명하지 못하고, assignment·새 Verification work·commit-time Primitive index 검사가 없으면 다른 owner나 stale 결과가 반영될 수 있었음 | `VerificationAssignment`, 새 VERIFICATION generation의 `TERMINAL -> VERIFYING`, PROVIDED `required_preconditions`, `PrimitiveIndexState`와 commit-time CAS를 정본·Wiki·검증 시나리오에 추가 | PM + LLM 탐색·체이닝 + 검증·통합 | [#2](https://github.com/SASTsimi/sastsimi/issues/2), [#5](https://github.com/SASTsimi/sastsimi/issues/5), [#7](https://github.com/SASTsimi/sastsimi/issues/7) |

## Medium/Low backlog

- B-003에서 제기한 저장소 라이선스와 외부 기여 범위는 설계·개발의 Blocker가 아니므로 공개 배포 또는 외부 기여를 받기 전 결정사항으로 재분류했다. 결정 전에는 `LICENSE`를 추가하지 않으며, 공개 방침을 정할 때 라이선스 후보와 `CONTRIBUTING.md` 범위를 함께 확정한다.
- Wiki는 사용자 요구에 따라 포함했으나 파생·비규범적으로 유지한다. 장기적으로 번호 문서에서 생성·검증하는 방식을 결정한다.
- `11-migration-from-v4.md`는 비규범적 설계 계보로 전환했으며 로컬 v4 경로 주장을 제거했다.
- Primitive 입력은 final HOLD의 REQUIRED와 두 Gate를 정상 통과한 exact TRUE revision의 PROVIDED로 명확화했다. TRUE+TRUE는 앞 PROVIDED와 뒤 TRUE의 exact 선행 조건을 방향성 있게 비교하고 current index를 commit 시 재확인한다. `FALSE`, Gate 전 TRUE와 오래된 Gate revision을 chaining 근거로 승격하지 않는다.
- Docsify가 사용하는 외부 CDN dependency의 version pinning과 offline rendering 정책은 별도 결정한다.
- 표현·예시·문서 미세 보정은 Blocker/High 검토보다 후순위다.

## 최종 승인 검토를 시작할 조건

1. 열린 Blocker와 High가 0이다.
2. Medium은 해결되거나 담당자·근거·목표 시점과 함께 명시적으로 연기된다.
3. [최종 Issue #10](https://github.com/SASTsimi/sastsimi/issues/10)과 최종 승인 PR에 검토 대상을 고정한 commit SHA를 기록한다.
4. 검토 대상을 고정한 뒤 변경이 생기면 기존 승인을 무효화하고 재검토한다.
5. 각 파트의 교차 검토 기록을 확인한 뒤 최종 검토·승인 담당자 김태현 `@taehyeon-git`이 최신 SHA를 확인한다.
6. 별도 승인 PR에서만 상태를 변경한다.
