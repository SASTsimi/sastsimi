# Architecture v5 설계 리뷰 체크리스트

이 문서는 역할별 작업과 전체 설계 검토에서 빠뜨리면 안 되는 항목을 확인합니다. 모르는 용어는 [쉬운 용어집](../GLOSSARY.md)에서 확인하세요.

전체 검토 현황은 [PM 전체 관리 Issue #1](https://github.com/SASTsimi/sastsimi/issues/1)과 [실제 Issue 현황](../review/ISSUE_TRACKER.md)에서 확인하고, 마지막 전체 흐름 검토는 [최종 Issue #10](https://github.com/SASTsimi/sastsimi/issues/10)에서 수행합니다.

R4-04는 체크박스를 미리 채우는 방식으로 완료 처리하지 않습니다. [R4-04 교차 검토 기록](../review/R4-04_CROSS_REVIEW.md)에 연결된 실제 GitHub 승인과 마지막 검토 commit을 확인한 뒤에만 Issue #16과 상위 Issue #5를 닫습니다.

## Issue와 PR 준비

- [ ] 담당자는 자신의 역할별 상위 Issue(#2–#9)를 확인했습니다.
- [ ] 담당자가 필요한 세부 작업을 하위 Issue로 직접 만들었습니다.
- [ ] 각 하위 Issue에 담당자, 쉬운 설명, 수정 문서, 완료 조건과 상위 Issue 번호가 있습니다.
- [ ] PR에 `Closes #하위-Issue`와 `Refs #역할별-상위-Issue`가 함께 있습니다.
- [ ] 모든 하위 Issue와 연결 PR이 끝난 뒤에만 역할별 상위 Issue를 닫습니다.

## 파트 리뷰

- [ ] 담당 역할, 범위와 비목표가 명확합니다.
- [ ] 역할 담당자 이름·GitHub 계정·Issue 번호가 `OWNERSHIP.md`, tracker와 실제 GitHub에서 일치합니다.
- [ ] Issue 상단만 읽어도 한 줄 설명, 이번에 할 일과 완료 산출물을 이해할 수 있습니다.
- [ ] 입력과 출력 데이터 묶음·상태(`record/state`)를 만드는 역할과 받는 역할이 명확합니다.
- [ ] 역할이 가질 수 없는 권한이 명시되었습니다.
- [ ] action을 요청한 역할, Runtime Validator의 필수 검사와 허용·차단 결과가 추적됩니다.
- [ ] 오류, 미지원, 시간 초과(`timeout`)와 자원 한도(`budget`) 소진을 `FALSE`와 구분합니다.
- [ ] AST·SAST·코드 조회·동적 근거가 같은 `workspace_id`와 `commit_id`를 사용합니다.
- [ ] 앞 단계와 뒤 단계(`upstream/downstream`)의 필수 검토를 받았습니다.
- [ ] 담당 하위 Issue와 역할별 상위 Issue(#2–#9)를 PR에 연결했습니다.
- [ ] Wiki와 Mermaid 영향을 확인했습니다.
- [ ] Blocker/High가 0입니다.
- [ ] 남은 Medium/Low에 owner와 후속 계획이 있습니다.

## 전체 설계에서 바뀌면 안 되는 조건

- [ ] HypothesisProposal은 `HYPOTHESIS_ONLY / NON_FINAL`입니다.
- [ ] 필요한 코드는 위치를 기준으로 필요할 때만 조회(`on-demand retrieval`)합니다.
- [ ] 운영 기본 검증 모드는 모든 유효 가설에서 찬성·반대 근거를 독립적으로 모으는 `ALWAYS_DEBATE`입니다. `BASIC | CONDITIONAL_DEBATE`는 격리된 평가 전용입니다.
- [ ] Pro와 Con은 독립 NEW session을 사용합니다.
- [ ] 새 우회·영향·연계 공격(`bypass/impact/chain`) 주장은 새 가설로 재검증합니다.
- [ ] Primitive DB는 queue 또는 Finding 저장소가 아닙니다.
- [ ] Orchestration은 proposal 검증·등록·Verification 배정 뒤 가설 내부 호출을 결정하지 않습니다.
- [ ] Verification이 Context·Pro/Con·동적 재현·판정·Technical `REVISE`·Gate 제출과 Chaining handoff를 소유합니다.
- [ ] R6 Verification은 목적·목표·필요 환경·Sandbox profile·근거 reference를 가진 exact `DynamicReproductionRequest`만 만들고, R7 Agent가 외부 경계 검사 전에 이를 가리키는 `EnvironmentRequirements`·간단한 `ReproductionPlan`을 만듭니다. PoC candidate는 경계 승인 뒤 Sandbox 실행 단계에서 만듭니다.
- [ ] `EnvironmentRequirements`는 애플리케이션 조건이고 `sandbox_profile_ref`는 Sandbox 보안 정책이며 서로 대신하지 않습니다.
- [ ] 한 Verification generation에 동적 재현 work가 하나뿐이며, retry는 같은 work의 새 attempt입니다.
- [ ] final TRUE에는 현재 generation의 `SUCCEEDED + SUPPORTED` 결과와 validated `poc_ref`가 필수이고, 없으면 저장과 Technical Gate 호출이 모두 차단됩니다.
- [ ] `ReproductionPlan`에 mode·exact command·step·payload·cleanup allowlist가 없고 선택적 `requested_evidence`가 Agent의 추가 관찰을 막지 않습니다.
- [ ] R7 Setup Automation은 recipe의 base/built image digest를 구분하고 실제 `sandbox_environment`에 container instance·생성/재사용 사유·requirement별 비교를 남깁니다.
- [ ] Sandbox Controller는 host·Docker·mount/namespace·secret·egress·workspace·R8 resource/lifecycle 외부 경계만 검사하고 내부 command allowlist를 운영하지 않습니다.
- [ ] Reproduction Session Manager만 append-only `AgentLog`, validated PoC와 `DynamicReproductionResult`를 확정합니다.
- [ ] Chaining Agent는 upstream Primitive의 `result`→downstream Primitive의 특정 `input` matching만 수행하고 일반 research·동적 재현·Gate 보완을 하지 않습니다.
- [ ] HOLD는 Gate 없이 `inputs`와 `result=null`인 Primitive가 되고, FALSE는 Primitive나 Chaining으로 들어가지 않습니다.
- [ ] TRUE는 validated PoC와 Technical `ACCEPT`가 있는 exact revision만 `result`를 가진 Primitive가 됩니다. Rule Scope는 Reporter만 제어합니다.
- [ ] 새 Verification generation/revision에는 오래된 Technical review나 Primitive를 재사용하지 않고, 공통 record revision과 원자적 current pointer 갱신으로 오래된 Chaining 결과를 거절합니다.
- [ ] Technical Evidence Gate와 Rule Scope Impact Gate가 분리됩니다.
- [ ] 공식 정책이 없거나 `STALE | UNVERIFIED`이면 판단과 보고서 전달을 허용하지 않는 `UNCERTAIN + DENY`입니다.
- [ ] Sandbox의 `POLICY_BLOCKED`는 자동 `FALSE | HOLD`나 Technical `REJECT`가 아니며, validated PoC가 없으므로 final verdict와 Technical Gate 없이 `BLOCKED | FAILED`로 처리됩니다.
- [ ] Reporter의 모든 선행 조건이 명시됩니다.
- [ ] ReportDraft가 current Finding·Verification·CWE·두 Gate·정책 revision을 정확히 참조합니다.
- [ ] restriction·limitation·남은 불확실성과 redaction 결과가 ReportDraft에 보존됩니다.
- [ ] Finding이 없으면 Reporter를 호출하지 않고 `AnalysisRunResult.report_draft_refs=[]`를 유지합니다.
- [ ] Finding·Verification·CWE·두 Gate·정책 중 하나가 새 revision이면 기존 ReportDraft는 감사 이력으로만 남고 다시 생성합니다.
- [ ] ReportDraft 뒤 `AnalysisRunResult`를 확정하면 Agent 자동화가 끝나고, 이후 사람 주도 과정에는 자동 action·상태를 두지 않습니다.
- [ ] Runtime Validator는 취약점·CWE·정책 의미를 판단하는 세 번째 Gate가 아닙니다.

## 전체 시나리오

- [ ] 미리 정한 반증 조건이 실제 코드에서 확인되었을 때만 `FALSE`가 됩니다.
- [ ] 판단을 보류한 가설의 입력 조건을 Technical-accepted TRUE Primitive의 결과가 채울 때만, 바로 합치지 않고 새로운 연계 가설로 다시 검증합니다.
- [ ] TRUE에서 나온 두 Primitive를 연결할 때 upstream 결과와 downstream의 특정 입력, 양쪽 exact parent revision을 확인하고 새 가설로 검증합니다.
- [ ] 새 연계 가설의 부모 계보를 따라가 조상 Primitive를 현재 match 후보에서 제외하며, 체이닝 전용 임의 깊이 제한 대신 R8 전역 예산을 적용합니다.
- [ ] PoC candidate와 재현 성공 뒤 validated PoC를 구분하고, validated PoC가 어떤 가설·코드 위치·관찰 결과를 뒷받침하는지 추적됩니다.
- [ ] 동적 결과의 Agent 호출·plan/recipe/환경 생성·정리 필요 상태와 nullable 환경·정책·PoC reference 및 필수 AgentLog가 모순되지 않습니다.
- [ ] Sandbox 정책 차단은 exact 정책 결정과 미실행 상태를 남기며, 그 사실만으로 Technical `REJECT`나 가설 `FALSE`가 되지 않습니다.
- [ ] 최초 attempt는 clean container이고 다른 가설은 writable container를 공유하지 않으며, reuse/recreate 사유와 이전·새 환경이 AgentLog에 연결됩니다.
- [ ] R7 자율 retry는 외부 대기가 없으면 `BLOCKED`를 쓰지 않고, 외부 설정·정책·승인·resource profile 변경을 기다릴 때만 `BLOCKED`입니다.
- [ ] PoC 생성·환경 구성·실행 실패는 validated `poc_ref=null`입니다. 내부에서 해결 가능하면 같은 work를 자동 retry하고, 외부 조건을 기다릴 때만 `BLOCKED`, 복구 불가능하거나 한도를 소진하면 verdict 없는 `FAILED`이며 `FALSE | HOLD`로 변환하지 않습니다.
- [ ] 환경 구성 실패·차이·허용되지 않은 version fallback·오래된 requirements를 가설 `FALSE`로 바꾸지 않습니다.
- [ ] 환경 요구사항·실제 값·Health Check·AgentLog에 credential·cookie·token·password 원문이 없습니다.
- [ ] candidate와 validated PoC를 구분하고, validated PoC의 request·plan·recipe·환경·AgentLog·digest가 모두 같은 attempt입니다.
- [ ] 기술적으로 `TRUE`여도 공식 정책을 확인할 수 없으면 보고서 전달을 허용하지 않습니다.
- [ ] Finding이 아직 없거나 ReportDraft의 선행 revision이 바뀌면 current 초안을 만들거나 재사용하지 않고 원인을 결과·오류 기록에 남깁니다.
- [ ] 기술 검토에서 보완이 필요하면 같은 ACTIVE `VerificationAssignment` owner에게 직접 돌아가 새 VERIFICATION work와 `TERMINAL -> VERIFYING` 전이를 만든 뒤 새 revision을 확정합니다.
- [ ] LLM 로그인·인증 실패를 취약점이 아니라는 뜻의 `FALSE`로 바꾸지 않고 별도 오류로 남깁니다.
- [ ] [Final Issue #10](https://github.com/SASTsimi/sastsimi/issues/10)의 전체 종단 시나리오를 통과합니다.

## 최종 통합 확인

- [ ] 정본 22단계와 Agent 자동화 종료 지점이 README, overview, Wiki와 Mermaid에서 일치합니다.
- [ ] 정본/Wiki Mermaid가 동일하며 실제 렌더링됩니다.
- [ ] broken local link와 Markdown fence 오류가 0입니다.
- [ ] [PM 전체 관리 Issue #1](https://github.com/SASTsimi/sastsimi/issues/1)의 역할별 상위 Issue, 모든 하위 Issue와 `main` 대상 PR이 [최종 Issue #10](https://github.com/SASTsimi/sastsimi/issues/10)에 연결됩니다.
- [ ] 모든 Blocker/High가 닫혔습니다.
- [ ] Medium은 해결되었거나 owner·근거·목표 시점과 함께 연기되었습니다.
- [ ] 최종 검토 대상을 고정한 commit SHA(`review freeze SHA`)를 PR에 기록했습니다.
- [ ] 검토 대상 고정 이후 새 commit이 생기면 영향받는 역할의 교차 검토와 최종 검토를 다시 받았습니다.
- [ ] 각 파트의 교차 검토 기록과 최종 검토·승인 담당자 김태현 `@taehyeon-git`의 최신 확인이 있습니다.
- [ ] 상태 변경은 별도 최종 승인 PR에서 수행합니다.
