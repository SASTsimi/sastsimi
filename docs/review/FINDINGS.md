# Architecture v5 검토 발견사항

이 문서는 현재 설계에서 발견된 문제와 해결 조건을 한곳에 모읍니다. 실제 담당자, 토론, 결정과 완료 증거는 연결된 GitHub Issue와 PR에서 관리합니다.

- `OPEN`: 아직 시작하지 않았거나 해결되지 않음
- `IN_PROGRESS`: 담당자가 해결 중
- `RESOLVED`: 완료 근거가 확인됨
- `DEFERRED`: 이유, 담당자와 다시 볼 시점을 정하고 미룸

## Blocker

| ID | 상태 | 쉽게 말하면 | 정확한 문제 | 처리·완료 조건 | 담당 역할 | Issue |
|---|---|---|---|---|---|---|
| B-001 | RESOLVED | 역할 담당자와 실제 GitHub 계정을 확정했습니다. | #1·#4·#5 `@YHS-Sec`, #3 `@zv9uvr`, #6 `@kimhr8463`, #7 `@UltraPeachKeen`을 실제 계정으로 확정하고 역할과 assignee 상태를 분리함 | 역할표·Issue·tracker를 실제 계정으로 통일하고 CODEOWNERS는 후속 개선으로 관리 | PM·아키텍처·워크플로 | [#5](https://github.com/SASTsimi/sastsimi/issues/5) |
| B-002 | RESOLVED | 최종 결과를 확인하고 승인 준비를 관리할 담당자를 정했습니다. | 최종 검토·승인 담당자 미지정 | 김태현 `@taehyeon-git`을 지정하고, 파트 간 교차 검토 후 전체 검토를 수행하는 절차를 문서화 | 저장소 관리 담당 | [#10](https://github.com/SASTsimi/sastsimi/issues/10) |
| B-004 | RESOLVED | 가져온 원본이 commit에 없었기 때문에 특정 commit에서 나온 파일이라고 말할 수 없습니다. | 원본이 commit되지 않은 작업 폴더라 commit 출처를 주장할 수 없음 | [가져온 출처 기록](./PROVENANCE.md)에 원본 상태와 파일 해시를 기록 | PM·아키텍처·워크플로 | [#5](https://github.com/SASTsimi/sastsimi/issues/5) |
| B-005 | RESOLVED | 검토 중인 초안이 승인된 최종 설계처럼 보였습니다. | candidate가 승인된 기준 문서처럼 표현됨 | root/v5/Wiki에 검토 중인 설계 초안과 승인·동기화 경계를 명시 | PM·아키텍처·워크플로 | [#5](https://github.com/SASTsimi/sastsimi/issues/5) |
| B-006 | RESOLVED | LLM이 보안 규칙이나 공개 절차를 마음대로 바꾸지 못하게 실행 권한을 분리했습니다. | LLM이 전역 실행 제어와 보안 강제 권한을 가진 것으로 해석될 수 있음 | R4-03에서 역할 권한표, `ActionRequest`·`ActionDecision`, 비신뢰 입력, 두 Gate·Reporter·사람 경계와 29개 권한 시나리오를 정의함 | PM·아키텍처·워크플로 | [#15](https://github.com/SASTsimi/sastsimi/issues/15), [#5](https://github.com/SASTsimi/sastsimi/issues/5) |
| B-007 | RESOLVED | 핵심 결과 네 종류의 저장 주체와 완료 지점을 확정했습니다. | `CodeWorkspace`, `ToolRunResult`, schema-valid `HypothesisProposal`, `AnalysisRunResult`의 result-owner·저장 action·current 선택점·atomic output binding이 필요했음 | `08` registry와 output binding에 REPOSITORY_LOADER·STATIC_ANALYSIS·ORCHESTRATION owner, exact source/work/attempt와 `TransitionCommit` 연결을 추가하고 R3-01 B3·R3-02 Q-01에 시험 기준을 반영 | R4 공통 계약 + R2·R3·R8 검토 | [#5](https://github.com/SASTsimi/sastsimi/issues/5), [#4](https://github.com/SASTsimi/sastsimi/issues/4), [#92](https://github.com/SASTsimi/sastsimi/issues/92) |
| B-008 | RESOLVED | 가설 전 Docker 준비를 없애 기존 Sandbox 권한 우회를 막았습니다. | run-init Docker baseline이 가설별 exact request와 attempt가 필요한 `RUN_SANDBOX`를 우회할 수 있었음 | run-init은 static·policy 두 branch만 등록하고 Docker pull/build/cache warm/container는 exact `DynamicReproductionRequest`가 생긴 Step 12에서만 수행하도록 R3-01·R3-02·R3-06에 확정 | R3·R4·R7·R8 | [#4](https://github.com/SASTsimi/sastsimi/issues/4), [#5](https://github.com/SASTsimi/sastsimi/issues/5), [#8](https://github.com/SASTsimi/sastsimi/issues/8), [#9](https://github.com/SASTsimi/sastsimi/issues/9), [#92](https://github.com/SASTsimi/sastsimi/issues/92) |

현재 열린 Blocker는 0개입니다.

## High

| ID | 상태 | 쉽게 말하면 | 정확한 문제 | 처리·완료 조건 | 담당 역할 | Issue |
|---|---|---|---|---|---|---|
| H-002 | RESOLVED | 공통 타입, 상태·오류 의미와 두 Gate·보고서의 정확한 수정본 연결을 통일했습니다. | Verification 세부 타입과 Primitive/정책 항목을 정의하고, 두 Gate·ReportDraft가 같은 Verification·CWELabel·정책 revision을 사용하도록 고정했으며 retry/failover는 허용된 바로 앞 실패 상태만 연결함 | PR #18 병합, R2·R3·R6·R7 교차 검토 기록과 Issue #13 완료 처리로 R4-01 기준에 반영함 | PM + 정적/동적/검증/통합 | [#13](https://github.com/SASTsimi/sastsimi/issues/13), [#18](https://github.com/SASTsimi/sastsimi/pull/18) |
| H-003 | RESOLVED | 운영 방식과 모델을 품질 근거 없이 바꾸지 못하게 했습니다. | debate·session·Gate·provider/model 선택의 평가 종료 기준과 운영 승격 권한이 필요했음 | 운영은 `ALWAYS_DEBATE`로 고정했다. 같은 versioned corpus·정답·grader·schema·예산을 사용하는 격리 평가, `EvaluationRecommendation=ACCEPT_FOR_PRODUCTION`과 사람 승인이 있어야만 새 Prompt·Provider 설정을 운영에 활성화하도록 R8·R3 기준을 확정했다. 실제 평가 실행은 `NOT_IMPLEMENTED` 후속 증거다. | 데이터·평가·예산 + 통합 구현 | [#9](https://github.com/SASTsimi/sastsimi/issues/9), [#4](https://github.com/SASTsimi/sastsimi/issues/4), [#92](https://github.com/SASTsimi/sastsimi/issues/92) |
| H-004 | RESOLVED | 검증되지 않은 회원 로그인 연결은 사용할 수 없도록 막았습니다. | Membership adapter의 공식 지원·약관·동시성·session·log 가능 여부를 확인하기 전에 운영에서 선택할 위험이 있었음 | 회원 로그인 경로를 optional experimental adapter로 제한하고, 공식 CLI/SDK 외 browser cookie·profile 재사용을 금지했다. exact provider·product·transport·auth·client·model·environment 조합이 PVD-01~15와 필요한 경우 PVD-16을 통과하기 전에는 ACTIVE/SUPPORTED profile을 만들지 않고 `CAPABILITY_UNSUPPORTED`로 차단한다. 실제 시험 결과는 `NOT_IMPLEMENTED` 후속 증거다. | 단독 구현·통합 개발 + 데이터·평가 | [#4](https://github.com/SASTsimi/sastsimi/issues/4), [#15](https://github.com/SASTsimi/sastsimi/issues/15), [#92](https://github.com/SASTsimi/sastsimi/issues/92) |
| H-005 | RESOLVED | Docker와 공식 정책을 신뢰하지 않고 안전 경계 밖에서 확인하도록 설계를 확정했습니다. | Docker reproduction과 policy capture의 threat model, 권한·출처·최신성·실패 처리와 추적 규칙이 필요했음 | ADR-007·ADR-013과 `10-security-boundaries.md`에서 local-only, non-root, default-deny network, Docker daemon/socket·host mount/namespace·secret·live target 차단, same-attempt provenance, cleanup, 공식 출처 원문·Parser 분리, cache freshness와 `UNCERTAIN + DENY`를 확정했다. 실제 격리·부정 시험과 공식 출처 연결은 `NOT_IMPLEMENTED` 후속 증거다. | 동적검증·Sandbox + Gate·정책 + 통합 구현 | [#6](https://github.com/SASTsimi/sastsimi/issues/6), [#8](https://github.com/SASTsimi/sastsimi/issues/8), [#21](https://github.com/SASTsimi/sastsimi/issues/21), [#22](https://github.com/SASTsimi/sastsimi/issues/22), [PR #110](https://github.com/SASTsimi/sastsimi/pull/110) |
| H-006 | RESOLVED | 병렬 실행·retry·중단 뒤에도 같은 작업과 결과를 한 번만 반영하도록 설계했습니다. | 공통 `WorkExecutionState`·attempt·state version·dedupe·atomic output binding·journal recovery와 stale result 차단 규칙이 필요했음 | `03`, `07`, `08`, `10`, `13`과 Wiki에 허용 전이, `dedupe_key`, compare-and-set, `TransitionCommit`, exact output pointer, crash-resume와 16개 상태·복구 부정 시나리오를 정의함. 실제 저장 제품·성능 검증은 R3 구현 단계에서 확인 | PM + 통합 개발 | [#14](https://github.com/SASTsimi/sastsimi/issues/14), [#4](https://github.com/SASTsimi/sastsimi/issues/4), [#5](https://github.com/SASTsimi/sastsimi/issues/5) |
| H-007 | RESOLVED | 연계 방향, 같은 검증 담당자, REVISE 재진입과 다른 작업의 체이닝 결과 차단을 계약으로 고정했습니다. | 연결 방향·부모 revision·새 Verification work 확인이 없으면 다른 owner나 다른 Chaining work의 결과가 반영될 수 있었음 | `VerificationAssignment`, 새 VERIFICATION generation의 `TERMINAL -> VERIFYING`, upstream `result`→downstream `input`, Chaining work 시작 시 exact input 고정과 same-work `SAVE_RESULT` 검사를 정본·Wiki·검증 시나리오에 반영 | PM + LLM 탐색·체이닝 + 검증·통합 | [#2](https://github.com/SASTsimi/sastsimi/issues/2), [#5](https://github.com/SASTsimi/sastsimi/issues/5), [#7](https://github.com/SASTsimi/sastsimi/issues/7) |
| H-008 | RESOLVED | 분석 시작 입력에서 대상 프로그램을 확정하고 정책 수집 work의 중복 방지 키를 정했습니다. | 정책은 분석 시작에 프로그램마다 한 번만 수집하는데, 그 프로그램을 식별하는 값이 `POLICY_FETCH` 등록 시점에 어디서 오는지 정의되어 있지 않았다. `AnalysisRunState`에 `program_id` 필드가 없고 `WorkExecutionState.subject_type`에 프로그램을 가리키는 값이 없으며, `program_id`가 나오는 곳은 `ProgramPolicyRecord`와 `PolicyCollectionResult`로 둘 다 `POLICY_FETCH` 자신의 출력물이었다. 한 분석이 여러 프로그램을 다룰 수 있는지도 정해져 있지 않았다. | PR #110이 `AnalysisStartRequest.program_id`와 `AnalysisRunState.program_id`를 정의하고 한 분석이 프로그램 하나만 다루도록 고정했다. `POLICY_FETCH`는 `subject_type=ANALYSIS`, `subject_id=analysis_id`이고 `dedupe_key`는 `analysis_id`·`program_id`·source 설정·parser 설정으로 계산한다. 같은 저장소의 다른 프로그램은 별도 run으로 요청한다. | PM + Gate·Finding·보고서 | [#5](https://github.com/SASTsimi/sastsimi/issues/5) |
| H-010 | RESOLVED | 정책을 가져오는 주체를 아키텍처 구성요소와 역할 배정에 올렸습니다. | `POLICY_COLLECTOR`는 `08`에서 `FETCH_POLICY`·`RUN_TOOL` 권한 주체이고 `policy_parser_result`·`policy_collection_result`·`program_policy_record`의 유일한 저장 주체지만, `01`의 구성요소, `03`의 역할·산출물 표, `docs/governance/OWNERSHIP.md`의 역할 배정 어디에도 없었다. 어떤 출처에서 어떤 방법으로 수집하는지도 `FETCH_POLICY`라는 action 이름과 "공식 source"라는 표현뿐이었다. | PR #110이 Policy Collector를 비-LLM 수집 서비스로, Policy Parser를 LLM 구조화 역할로 `01` 구성요소 표·`03` 권한 표·`OWNERSHIP.md`에 배치했다. 출처 인증·최신성과 fail-closed 처리는 ACCEPTED ADR-013과 H-005 해결 근거에 포함했다. | PM + Gate·Finding·보고서 | [#5](https://github.com/SASTsimi/sastsimi/issues/5), [#6](https://github.com/SASTsimi/sastsimi/issues/6) |
| H-011 | RESOLVED | 가설을 만드는 LLM과 전체 순서를 관리하는 프로그램을 명확히 분리했습니다. | 문서의 LLM 오케스트레이션 역할 표현과 실제 비-LLM runtime 권한, prompt·role registry가 서로 달라 구현자가 실행 제어를 LLM에 맡길 수 있었음 | `Orchestration Runtime`을 prompt·provider·`agent_role`이 없는 비-LLM 전역 제어 구성요소로 확정하고, 가설 생성은 `Hypothesis Agent`, 가설별 판단은 Verification에 유지했다. 번호 문서·Wiki·Mermaid·구현 지도와 자동 검증을 같은 기준으로 통일 | R3 통합 + R4 공통 계약 | [#4](https://github.com/SASTsimi/sastsimi/issues/4), [#5](https://github.com/SASTsimi/sastsimi/issues/5) |
| H-009 | RESOLVED | 발동할 수 없는 체이닝 재료 회수 절차를 제거하고 admission을 등록 시점 1회 판정으로 확정했습니다. | current `PrimitiveIndexState`에서 Primitive를 빼는 트리거는 `PrimitiveAdmissionDecision`이 `DENY`로 바뀌는 것 하나뿐이다. `af6ffc0`이 정책을 run 안에서 고정한 뒤 남은 조건은 `VerificationResult`·`TechnicalEvidenceReview`·`RuleScopeImpactReview`의 검증 근거 revision 변경인데, 새 Verification generation은 `DYNAMIC_INPUT_CHANGED` 또는 Technical `REVISE`에서만 만들 수 있고 두 경로 모두 Technical `ACCEPT`와 result Primitive 등록 전이다. `05`는 사람 주도 과정을 `AnalysisRunResult` 확정 뒤로 두고, 중단·재개는 저장된 Primitive를 취소하지 않는다. | ADR-014로 admission을 Primitive 등록 시점의 1회 판정으로 확정하고 회수 절차를 제거했다. 정책이나 판정이 달라졌으면 다음 run에서 새로 판정한다. run 도중 회수가 필요해지면 트리거·권한·전파 범위를 함께 설계한다. | PM + Gate·Finding·보고서 + 검증·반박·플레이북 | [#5](https://github.com/SASTsimi/sastsimi/issues/5) |

현재 열린 High는 0개입니다. `RESOLVED`는 설계상 안전 경계와 활성화 조건을 닫았다는 뜻이며, 아래 실제 구현·운영 시험까지 실행됐다는 뜻은 아닙니다.

## Medium/Low backlog

- B-003에서 제기한 저장소 라이선스와 외부 기여 범위는 설계·개발의 Blocker가 아니므로 공개 배포 또는 외부 기여를 받기 전 결정사항으로 재분류했다. 결정 전에는 `LICENSE`를 추가하지 않으며, 공개 방침을 정할 때 라이선스 후보와 `CONTRIBUTING.md` 범위를 함께 확정한다.
- Wiki는 사용자 요구에 따라 포함했으나 파생·비규범적으로 유지한다. 장기적으로 번호 문서에서 생성·검증하는 방식을 결정한다.
- `11-migration-from-v4.md`는 비규범적 설계 계보로 전환했으며 로컬 v4 경로 주장을 제거했다.
- Primitive는 non-empty `required_primitive_candidates`를 가진 final HOLD의 `inputs + result=null`과 validated PoC·Technical `ACCEPT` 뒤 current `PrimitiveAdmissionDecision=ALLOW`인 TRUE의 `inputs + result`를 같은 형식으로 표현한다. 빈 후보인 HOLD는 Primitive와 Chaining work를 만들지 않는다. upstream `result`와 downstream의 특정 `input`을 방향성 있게 비교하고, Chaining work는 시작 시 current index에서 후보를 고정하고, 저장 시점에는 고정하지 않은 reference가 결과에 섞이지 않았는지만 확인한다. admission은 Primitive 등록 시점의 1회 판정이라 저장 시점에 다시 보지 않는다. `FALSE`, Gate 전 TRUE, admission `DENY`와 오래된 Technical review revision을 chaining 근거로 승격하지 않는다. Rule Scope의 금지 테스트 `FAIL`만 체이닝을 막고 다른 판단은 보고 가능성에 적용한다.
- Docsify가 사용하는 외부 CDN dependency의 version pinning과 offline rendering 정책은 별도 결정한다.
- R3·R8은 ProviderProfile을 활성화하기 전에 해당 exact 조합의 PVD-01~15 결과와, 동적 재현에 사용할 조합의 PVD-16 결과를 저장한다. 시험 전 상태는 `UNSUPPORTED | UNVERIFIED`이며 활성화하지 않는다.
- R8과 각 LLM 역할 담당자는 운영 설정을 바꾸기 전에 versioned corpus·정답·grader·예산으로 실제 평가를 실행하고 `ACCEPT_FOR_PRODUCTION` 추천과 사람 승인을 남긴다. 평가 전에는 `ALWAYS_DEBATE` 기본값을 유지한다.
- R7·R5·R3은 untrusted PoC 또는 공식 정책 연결을 운영에서 켜기 전에 Sandbox 격리·egress·daemon/socket·cleanup 부정 시험과 공식 출처·freshness·Parser 실패 시험을 실행한다. 통과하지 못한 기능은 fail-closed 상태로 둔다.
- 표현·예시·문서 미세 보정은 Blocker/High 검토보다 후순위다.

## 최종 승인 검토를 시작할 조건

1. 열린 Blocker와 High가 0이다.
2. Medium은 해결되거나 담당자·근거·목표 시점과 함께 명시적으로 연기된다.
3. [최종 Issue #10](https://github.com/SASTsimi/sastsimi/issues/10)과 최종 승인 PR에 검토 대상을 고정한 commit SHA를 기록한다.
4. 검토 대상을 고정한 뒤 변경이 생기면 기존 승인을 무효화하고 재검토한다.
5. 각 파트의 교차 검토 기록을 확인한 뒤 최종 검토·승인 담당자 김태현 `@taehyeon-git`이 최신 SHA를 확인한다.
6. 별도 승인 PR에서만 상태를 변경한다.
