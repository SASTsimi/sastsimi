# 검증과 동적 재현

## 쉽게 말하면

검증 Agent가 배정된 가설 안에서 코드·찬성·반대·동적 근거와 Gate 보완 흐름을 직접 관리하는 과정입니다.

**상세 기준:** [04. 검증과 동적 재현](../04-verification-and-dynamic-reproduction.md)

모르는 단어는 [쉬운 용어집](../../GLOSSARY.md)에서 확인하세요.

## 코드 위치와 우회를 함께 확인하는 검증

검증 Agent는 가설에 연결된 코드 요소·위치·경로에서 호출하는 함수, 호출되는 함수, 데이터 흐름, 인증·권한 검사와 요청 경로를 조회합니다. 실제로 확인한 사실과 아직 확인하지 못한 가정을 나눕니다. 입력 검사·안전 처리·인증·권한·소유권이 공격을 막는 조건인지, 우회 경로가 있는지, 다른 공격에 필요한 능력과 영향 확대 후보가 있는지 기록합니다.

새 endpoint, sink, 권한 경계 또는 독립 영향은 `HypothesisProposal(origin=VERIFICATION)`으로 분리하고 trusted validation·전역 등록 뒤 새 Verification에서 다시 검증한다.

## Debate 모드

- `BASIC`: Verification이 직접 찬반을 검토하는 격리된 평가 전용 모드
- `CONDITIONAL_DEBATE`: trigger가 있을 때 Pro/Con을 부르는 격리된 평가 전용 모드
- `ALWAYS_DEBATE`: 모든 유효 가설에 Pro/Con을 부르는 운영의 유일한 허용 모드

운영에서는 예산 부족을 이유로 Pro/Con을 생략하지 않습니다. `BUDGET_EXCEEDED`로 현재 검증 작업을 중단하고, 새 예산이 승인된 작업에서 다시 진행합니다. 평가 모드의 BASIC·조건부 결과는 Gate, Primitive 또는 보고서 입력으로 사용하지 않습니다.

Pro와 Con은 서로의 결과를 받지 않는 별도 NEW session이다. trigger/skip reason, token·시간, verdict 변화, HOLD 해소, 오탐 감소 후보와 bypass 발견을 기록한다.

## 판정과 동적 재현

- `TRUE`: 명시된 경로와 전제가 evidence로 지지되고 현재 generation의 실행 성공·validated PoC가 있음
- `FALSE`: named falsification이 가설을 반증함
- `HOLD`: 핵심 문맥·환경·조건이 부족하거나 충돌함

판정 뒤 흐름도 다릅니다. `FALSE`는 terminal이며 Primitive와 Chaining으로 가지 않습니다. `HOLD`는 Gate 없이 REQUIRED Primitive를 즉시 저장합니다. `TRUE`는 CWE와 두 Gate를 정상 통과한 exact revision만 PROVIDED Primitive가 됩니다.

판정에는 최소 근거가 필요합니다. TRUE는 핵심 공격 경로와 필요한 조건을 지지하는 근거가 있어야 합니다. FALSE는 이름이 있는 반증 질문이 실제 근거로 `DISPROVED`된 경우에만 가능합니다. 오류·timeout·정보 부족·Sandbox 실패는 FALSE 근거가 아닙니다. HOLD는 판단에 필요한 조건이나 환경이 아직 부족하다는 뜻입니다.

기본 Context가 부족하면 검증 Agent가 같은 workspace·commit을 기준으로 추가 Context를 요청합니다. 조회 실패·timeout·권한 오류는 `AnalysisError`로, 그 때문에 확인하지 못한 범위는 `DataGap`으로 기록하며 오류 자체를 verdict 근거로 사용하지 않습니다. 일부 조회가 실패했더라도 제한 retry·대체 조회·다른 정상 근거로 모든 `ValidationCheck`, 반증 질문과 운영 Pro/Con을 완료했다면 실제 근거에 따라 final `TRUE | FALSE | HOLD`를 만들 수 있습니다. 하나라도 완료하지 못했다면 final `VerificationResult`를 만들지 않고, 재시도 가능 시 `BLOCKED + VERIFYING`, 복구 불가능 시 work와 가설 처리 상태를 `FAILED`로 끝냅니다. 정상 검증을 모두 마친 뒤에도 부족한 조건이 남는 경우에만 실제 근거와 `unresolved_conditions`를 연결해 `HOLD`로 판정할 수 있습니다. 운영 Pro/Con 전에 예산이 부족한 경우도 `BUDGET_EXCEEDED`로 작업을 중단하고 final verdict를 저장하지 않습니다.

`initial_verdict`는 중간 판단이며 운영 Gate·Primitive·보고서 입력으로 사용할 수 없습니다. initial TRUE이면 동적 근거가 별도로 필요하지 않아도 PoC 확인을 요청합니다. final TRUE는 독립 Pro/Con과 현재 generation의 성공한 동적 결과·validated PoC를 종합한 최종 판단입니다.

지원 취약점 유형 목록은 R8의 versioned evaluation corpus에서 확정합니다. 목록이 확정되기 전이나 적용 가능한 유형별 플레이북이 없는 경우에는 공통 플레이북을 사용합니다. 플레이북 후보는 R6 담당이 작성하고, 신뢰할 수 있는 runtime이 형식과 revision을 검사해 변경 불가능한 record로 등록합니다.

검증 작업을 등록할 때 trusted runtime이 사용할 정확한 플레이북 revision을 선택해 작업 입력에 고정합니다. 직접 검증, Pro 검토, Con 검토, 최종 판정과 결과 저장은 모두 처음 고정한 동일한 revision을 사용합니다. 최종 `VerificationResult.playbook_ref`에는 실제 사용한 플레이북의 정확한 `record_id`와 `content_hash`가 기록됩니다.

검증 도중 새 플레이북 revision이 등록돼도 진행 중인 검증에는 섞지 않습니다. 단순 재시도는 처음 고정한 revision을 유지하며, 새 revision을 적용하려면 새로운 Verification work 또는 verification generation을 만들어야 합니다.

각 반증 질문에는 `question_id`가 있습니다. 검증 결과는 질문마다 `DISPROVED`, `NOT_DISPROVED`, `INCONCLUSIVE` 중 하나와 근거를 남깁니다. 실제 근거가 있는 `DISPROVED`가 하나 이상일 때만 `FALSE`가 가능합니다. `NOT_DISPROVED`는 반증하지 못했다는 뜻일 뿐 가설을 증명하지 않습니다.

가설의 각 필수 검증 항목에는 `validation_id`가 있습니다. final 결과는 같은 ID의 결과가 빠짐없이 한 번씩 있고, 모두 `COMPLETE`이며 실제 근거를 가리킬 때만 저장합니다. 하나라도 완료하지 못하면 final 판정을 만들지 않습니다. 다시 시도할 수 있으면 work를 `BLOCKED`로 두고 가설은 `VERIFYING`을 유지하며, 더 시도할 수 없으면 work와 가설을 함께 `FAILED`로 끝냅니다. 이 실패는 `FALSE`나 `HOLD`가 아니며 Gate 입력도 아닙니다.

Pro와 Con은 항상 별도의 새 대화에서 실행합니다. 상대 역할의 결론이나 대화를 이어받지 않으며, 실패 후 재시도나 provider 변경도 같은 역할의 새 대화로 시작합니다. Verification Agent만 두 결과를 함께 읽고 최종 판정을 만듭니다.

결과를 저장하기 전에는 결과 종류, 저장 담당 역할, 정확한 작업·시도·코드 버전, 플레이북 revision과 후보 내용 hash를 함께 검사합니다. `TRUE`는 supporting evidence와 현재 generation의 `SUCCEEDED + SUPPORTED` 결과·validated `poc_ref`, `FALSE`는 근거가 있는 `DISPROVED`, `HOLD`는 `unresolved_conditions`와 정상 확인 근거가 필요합니다. 오류·timeout·빈 Context·예산 초과 상태만으로 어떤 final verdict도 저장할 수 없습니다. validated PoC 없는 TRUE는 저장과 Technical Gate 호출이 모두 차단됩니다.

| 요청 목적 | 뜻 |
|---|---|
| `POC_CONFIRMATION` | 정적·Pro·Con으로 initial TRUE가 된 가설을 실제 PoC로 확인 |
| `VERDICT_EVIDENCE` | 최종 판정에 꼭 필요한 실행 관측 확보 |

R6는 목적·재현 목표·필요 환경·Sandbox profile·관련 근거를 `DynamicReproductionRequest`로 만듭니다. R7은 이 exact 요청에서 `EnvironmentRequirements`, `LIMITED_REPRO | FULL_REPRO` mode, `ReproductionPlan`과 PoC candidate를 생산합니다. 한 Verification generation에는 동적 work 하나만 허용하며 retry는 같은 work의 새 attempt입니다. Technical `REVISE`로 새 generation이 시작되면 한도를 새로 적용합니다.

Docker는 ephemeral/non-root, network default-deny와 자원·시간 제한을 사용합니다. Runtime Validator와 Sandbox Controller를 통과한 exact plan만 실행합니다. R7은 실제 환경·Health Check를 requirement별로 비교하고 필수 항목이 맞을 때만 공격 단계를 실행합니다.

`poc_candidate_ref`는 실행 전 스크립트·입력입니다. exact candidate 실행이 `SUCCEEDED + SUPPORTED`로 끝난 경우에만 validated `poc_ref`를 만듭니다. 생성 실패, 실행 실패, `DISPROVED | INCONCLUSIVE`에서는 `poc_ref=null`입니다. candidate와 실패 로그는 남겨도 최종 PoC로 부르지 않습니다.

`POC_CONFIRMATION` 또는 `VERDICT_EVIDENCE`가 `SUPPORTED`이면 R6는 정적·Pro·Con·동적 근거와 validated PoC를 합쳐 final TRUE를 만듭니다. 실제 반증이면 FALSE, 정상 실행했지만 결론이 부족하면 HOLD가 될 수 있습니다. PoC 생성·환경 구성·정책·실행 자체가 실패했다면 final verdict를 만들지 않습니다. 다시 시도할 수 있으면 같은 work를 `BLOCKED`, 복구할 수 없거나 한도를 소진하면 `FAILED`로 끝내며 Gate를 호출하지 않습니다.

Technical Gate가 `REVISE`를 반환하면 같은 ACTIVE `VerificationAssignment` owner가 직접 받습니다. 프로그램은 새 generation의 Verification work와 `TERMINAL -> VERIFYING` 전이를 먼저 원자적으로 만들고, 필요한 Context·Pro/Con·정적 근거와 설명을 보완합니다. final TRUE를 다시 만들려면 새 generation의 동적 work와 validated PoC도 필요합니다. CWE 보완이 있으면 기존 CWE producer와 새 revision을 조정한 뒤 새 Gate work를 요청합니다. 이는 provider retry나 동일 입력 재투표가 아닙니다.

`status`는 실행 완료 정도이고 `hypothesis_outcome: SUPPORTED | DISPROVED | INCONCLUSIVE`은 관측과 가설의 관계입니다. 둘 다 최종 판정이 아닙니다. `FAILED | BLOCKED | CANCELLED`는 `INCONCLUSIVE`이며 가설 반증이 아닙니다. 실제 반증은 `DISPROVED`, `hypothesis_disproved: true`, 관측 근거 `hypothesis_evidence_refs`와 `disproof_evidence_refs`가 함께 있어야 합니다. 생성·환경·실행 실패는 관측 반증이 아니므로 `FALSE | HOLD`로 바꾸지 않습니다. Verification Agent는 정상 관측과 다른 근거를 종합하되, final TRUE에는 current generation의 request, `SUCCEEDED + SUPPORTED` 결과와 validated PoC를 반드시 포함합니다. 상세 내용은 [검증과 동적 재현](../04-verification-and-dynamic-reproduction.md)을 따릅니다.

공통 작업 상태와 동적 결과 상태는 다르게 읽습니다. 부분 실행은 결과의 `limitations`로 한계를 설명하며 실제 오류가 없으면 오류 record를 만들지 않습니다. 정책 차단 결과 `BLOCKED + POLICY_BLOCKED`는 Sandbox가 요청을 처리해 만든 종료 결과이므로 공통 작업은 `SUCCEEDED`로 닫지만, 재현 성공은 아닙니다. 공통 작업의 `BLOCKED`는 승인이나 입력을 기다리는 비종료 상태에만 사용합니다. 취소 결과는 공통 `CANCELLED`와 함께 저장하며, 저장 확정 marker와 모든 결과 reference가 일치할 때만 Verification이 읽습니다.

최종 Verification은 `hypothesis_ref`로 검토한 등록 완료 가설 record를 고정합니다. 등록 뒤 material content는 수정하지 않고 의미가 달라지면 새 proposal·새 `hypothesis_id`로 전체 Verification을 시작합니다. decision/result/status/PoC 조합의 정본은 [경량 데이터 계약의 compatibility matrix](../08-lightweight-data-contracts.md#dynamic-decisionresultpoc-compatibility)입니다. 저장 확정 marker와 current generation의 request·plan·result·PoC reference가 모두 일치할 때만 Verification이 읽습니다. 종료된 실행의 실패·부분·차단·취소 결과는 성공이나 반증으로 과장하지 않으며 `poc_candidate_ref`는 validated `poc_ref`로 취급하지 않습니다.
