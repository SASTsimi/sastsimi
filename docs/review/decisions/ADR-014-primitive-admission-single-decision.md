# ADR-014. Primitive admission을 등록 시점의 1회 판정으로 확정한다

- 상태: `ACCEPTED`
- 결정일: 2026-09-06
- 기준 main: `773fa49`
- 결정 담당: LLM 탐색·체이닝(R1)
- 함께 검토할 역할: PM·아키텍처·워크플로(R4), Gate·Finding·보고서(R5), 검증·반박·플레이북(R6), 데이터·평가·예산(R8)
- 연결 Issue/PR: #108, ADR-011, PR #102
- 반영 commit: `docs: make primitive admission a one-time decision`

## Context

`PrimitiveAdmissionDecision`이 `ALLOW`에서 `DENY`로 바뀔 때를 대비한 회수 장치가 문서 여러 곳에 있습니다.

- `ChainingResult.source_admission_refs`가 실제 match와 그 계보의 admission decision을 모아 두고, 저장 직전에 전부 current `ALLOW`인지 다시 확인합니다.
- 후보 pool을 만들 때도 계보를 재귀 추적해 모든 result Primitive의 admission을 확인합니다.
- `DENY`가 되면 그 Primitive와 파생 Primitive를 current `PrimitiveIndexState`에서 제거하고, 그 Primitive를 고정한 진행 중 Chaining을 `STALE_RESULT`로 거절하며, `AnalysisRunResult`에서도 제외합니다.

정책을 run 안에서 고정한 `af6ffc0`과 PR #110이 새 decision revision의 조건을 하나로 좁혔습니다 — 같은 run에서 `VerificationResult`, `TechnicalEvidenceReview`, `RuleScopeImpactReview`의 검증 근거 revision이 바뀐 경우입니다. 이 조건이 admission 확정 이후에 성립할 수 있는지 확인했습니다.

**Rule Scope review.** `08`의 `REVISION` 검사는 `VerificationResult`, `CWELabel`, `TechnicalEvidenceReview`, `PolicyCollectionResult`, `ProgramPolicyRecord` 다섯을 domain input으로 고정합니다. 입력이 그대로면 같은 `dedupe_key`로 기존 work가 반환되어 새 review가 만들어지지 않습니다.

**정책 두 입력.** `08`이 "같은 analysis run에서 policy collection·record revision은 최초 확정 뒤 교체하지 않는다"로 고정했습니다. 만료와 parser version 변경은 다음 run의 재사용 판단 조건이므로 run 안에서 새 revision이 생기지 않습니다.

**`TechnicalEvidenceReview`.** 새 review를 만들려면 새 Technical Gate 호출이 필요하고, 그러려면 `VerificationResult`나 `CWELabel`이 새 revision이어야 합니다.

**`CWELabel`.** 새 Verification generation에서만 새 revision이 만들어집니다.

**`VerificationResult`.** 새 generation은 Technical `REVISE`에서만 만들어집니다. `REVISE`는 `ACCEPT`의 대안이므로 그 시점에는 admission도 result Primitive도 아직 없습니다. PR #102가 자식 impact 흡수를 제거해 Technical `ACCEPT` 이후 같은 Verification을 다시 여는 경로도 없어졌습니다.

**중단·재개.** 파이프라인이 중단되었다가 재개되어도 이미 저장된 Primitive는 취소하지 않습니다. `Primitive`는 불변 append-only record이고 재개는 미완료 work를 이어서 실행하는 것이지 확정된 결과를 되돌리거나 admission을 다시 판정하는 절차가 아닙니다.

**사람 개입.** `05`는 Agent 자동화가 `AnalysisRunResult` 확정으로 끝나고 이후 사람 주도 과정의 schema·상태·결정 enum을 정의하지 않는다고 명시합니다. run 도중 사람이 자격을 회수하는 자리가 없습니다.

admission은 Technical `ACCEPT` 뒤에 확정되는데, 남은 트리거의 세 record는 `ACCEPT` 이전으로 돌아가야만 새 revision이 됩니다. 따라서 회수 장치는 발동하지 않는 상태로 유지되고 있습니다. 문서만 읽는 구현자는 이를 살아 있는 경로로 보고 전부 구현하며, 체이닝은 결과마다 파생 admission 집합을 만들어 set-equality를 검사하는 비용을 계속 냅니다.

이 결정은 "Technical `ACCEPT` 이후 같은 Verification을 다시 여는 경로를 만들지 않는다"를 전제로 합니다. 그 경로가 새로 생기면 회수 필요성을 다시 판단해야 합니다.

## Options

### 1. 그대로 둔다

발동하지 않는 장치를 여러 문서에 유지합니다. 같은 사건을 index와 `source_admission_refs` 두 경로가 각각 처리하는 상태도 남습니다. 선택하지 않습니다.

### 2. 체이닝의 추적만 없애고 index 회수는 남긴다

같은 근거로 절반만 제거하는 것이라 "그럼 나머지는 왜 두는가"에 답할 수 없습니다. 자격 상실을 표현하는 자리가 index 하나로 줄지만 그 index 회수도 발동하지 않습니다. 그리고 회수가 남아 있는 한 저장 시점 index 소속 재확인과 전파 중간 상태 문제가 따라옵니다. 선택하지 않습니다.

### 3. admission을 1회 판정으로 확정한다

등록 시점에 판정하고, 등록된 Primitive는 run 안에서 자격을 잃지 않는 것으로 계약을 명시합니다. 회수 절차를 문서에서 제거합니다. 이 방식을 선택합니다.

## Decision

**admission은 Primitive 등록 시점의 1회 판정입니다.** `decision=DENY`이면 result Primitive를 만들지 않습니다. 한 번 등록된 Primitive는 같은 run 안에서 자격을 잃지 않습니다.

따라서 다음을 제거합니다.

- `ChainingResult.source_admission_refs` 필드와 그 set-equality 검사
- 후보 pool 선정 단계의 계보 재귀 admission 확인
- 체이닝 저장 직전의 admission·index 소속 재확인
- `origin=CHAINING` 가설의 후속 work 등록·저장 시 부모 계보 admission 재확인
- `DENY` 발생 시 Primitive와 파생 Primitive를 current index에서 제거하는 절차
- `AnalysisRunResult`에서 회수된 계보를 제외하는 검사
- `10`의 N41·N43

`PrimitiveIndexState`는 남습니다. 자격 필터가 아니라 **가설별 Primitive pool의 진입점**이며, Chaining work가 후보를 읽고 고정하는 자리입니다. 그래서 정의도 바로잡습니다 — HOLD Primitive는 admission decision 없이 등록되므로 index 소속은 "등록되었다"는 뜻이지 "admission이 허용했다"는 뜻이 아닙니다.

`Primitive.admission_decision_ref`도 남습니다. 어떤 판정으로 등록됐는지는 감사에 필요합니다.

저장 무결성은 기존 검사가 그대로 담당합니다 — `considered_primitive_refs`가 `REGISTER_WORK`에서 고정한 집합과 set-equal한지, 결과에 work가 고정하지 않은 reference가 섞이지 않았는지.

정책이나 판정이 실제로 달라졌다면 다음 run에서 새로 판정합니다.

ADR-011은 금지 테스트 전용 판정과 admission 분리를 정하면서 `DENY`로 바뀔 때의 회수 절차도 함께 두었습니다. 그중 회수 부분을 이 ADR이 대체하고 절차 자체를 제거합니다. ADR-011 본문은 결정 당시 기록으로 그대로 둡니다. `testing_restriction_compliance`와 `PrimitiveAdmissionDecision`의 매핑, `ALLOW`일 때만 result Primitive를 만드는 규칙, `Primitive.admission_decision_ref` 요구는 ADR-011 그대로 유지합니다.

필드 제거는 기존 `ChainingResult`의 필수 필드를 없애므로 새 MAJOR schema에서만 사용합니다. 이전 MAJOR 결과의 목록을 다시 계산해 채우지 않고 감사 이력으로만 보존합니다.

## Consequences

체이닝 재료 자격이 "current index에 등록된 Primitive인가" 하나로 줄어듭니다. 체이닝 결과마다 파생 admission 집합을 만들고 검사하는 절차, 후보 선정과 저장 시점의 계보 재귀 확인이 없어집니다. 회수가 없으므로 전파 순서나 중간 상태를 다룰 규칙도 필요 없습니다.

이 결정은 세 전제 위에 있습니다.

- 정책을 run당 한 번만 수집한다
- Rule Scope review의 domain input set이 run 안에서 고정된다
- 파이프라인이 중단·재개되어도 이미 Primitive DB에 저장된 record를 취소하지 않는다

하나라도 바뀌어 run 도중 admission이 뒤집힐 수 있게 되면 회수 경로를 다시 설계해야 합니다. 그때는 트리거·권한·전파 범위와 진행 중 work 처리를 함께 정합니다.

run 도중 사람이 개입해 자격을 회수하는 기능은 이 결정으로 만들어지지 않습니다. 필요하다고 판단되면 `05`의 사람 주도 과정 경계와 함께 별도로 설계합니다.

## Responsibility

- R1: `06-chaining.md`의 `ChainingResult` schema와 재료 자격·저장 검사 서술을 맞춥니다.
- R4: `08-lightweight-data-contracts.md`의 admission 계약, `PrimitiveIndexState` 정의, `chaining_result` 저장 검사, `AnalysisRunResult` 확정 조건과 MAJOR schema 처리를 확정합니다. `af6ffc0`이 정책을 run 안에서 고정했으므로 `08:1225`의 남은 재판정 조건도 함께 정리합니다.
- R5: Gate 2 domain input 고정이 이 전제와 어긋나지 않는지 확인합니다.
- R6: Technical `ACCEPT` 이후 같은 Verification을 다시 여는 경로가 없다는 관찰이 맞는지 확인합니다.
- R8: `07`의 체이닝 관측 항목에서 회수 서술을 뺀 것을 확인합니다.
