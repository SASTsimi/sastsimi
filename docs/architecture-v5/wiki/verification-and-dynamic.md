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

- `TRUE`: 명시된 경로와 전제가 evidence로 지지됨
- `FALSE`: named falsification이 가설을 반증함
- `HOLD`: 핵심 문맥·환경·조건이 부족하거나 충돌함

판정 뒤 흐름도 다릅니다. `FALSE`는 terminal이며 Primitive와 Chaining으로 가지 않습니다. `HOLD`는 Gate 없이 REQUIRED Primitive를 즉시 저장합니다. `TRUE`는 CWE와 두 Gate를 정상 통과한 exact revision만 PROVIDED Primitive가 됩니다.

판정에는 최소 근거가 필요합니다. TRUE는 핵심 공격 경로와 필요한 조건을 지지하는 근거가 있어야 합니다. FALSE는 이름이 있는 반증 질문이 실제 근거로 `DISPROVED`된 경우에만 가능합니다. 오류·timeout·정보 부족·Sandbox 실패는 FALSE 근거가 아닙니다. HOLD는 판단에 필요한 조건이나 환경이 아직 부족하다는 뜻입니다.

기본 Context가 부족하면 검증 Agent가 같은 workspace·commit을 기준으로 추가 Context를 요청합니다. 조회 실패·timeout·권한 오류는 `AnalysisError`로, 그 때문에 확인하지 못한 범위는 `DataGap`으로 기록하며 오류 자체를 verdict 근거로 사용하지 않습니다. 일부 조회가 실패했더라도 제한 retry·대체 조회·다른 정상 근거로 모든 `ValidationCheck`, 반증 질문과 운영 Pro/Con을 완료했다면 실제 근거에 따라 final `TRUE | FALSE | HOLD`를 만들 수 있습니다. 하나라도 완료하지 못했다면 final `VerificationResult`를 만들지 않고, 재시도 가능 시 `BLOCKED + VERIFYING`, 복구 불가능 시 work와 가설 처리 상태를 `FAILED`로 끝냅니다. 정상 검증을 모두 마친 뒤에도 부족한 조건이 남는 경우에만 실제 근거와 `unresolved_conditions`를 연결해 `HOLD`로 판정할 수 있습니다. 운영 Pro/Con 전에 예산이 부족한 경우도 `BUDGET_EXCEEDED`로 작업을 중단하고 final verdict를 저장하지 않습니다.

`initial_verdict`는 중간 판단이며 운영 Gate·Primitive·보고서 입력으로 사용할 수 없습니다. final verdict는 독립 Pro/Con과 필요한 동적 결과를 종합한 최종 판단입니다.

지원 취약점 유형 목록은 R8의 versioned evaluation corpus에서 확정합니다. 목록이 확정되기 전이나 적용 가능한 유형별 플레이북이 없는 경우에는 공통 플레이북을 사용합니다. 플레이북 후보는 R6 담당이 작성하고, 신뢰할 수 있는 runtime이 형식과 revision을 검사해 변경 불가능한 record로 등록합니다.

검증 작업을 등록할 때 trusted runtime이 사용할 정확한 플레이북 revision을 선택해 작업 입력에 고정합니다. 직접 검증, Pro 검토, Con 검토, 최종 판정과 결과 저장은 모두 처음 고정한 동일한 revision을 사용합니다. 최종 `VerificationResult.playbook_ref`에는 실제 사용한 플레이북의 정확한 `record_id`와 `content_hash`가 기록됩니다.

검증 도중 새 플레이북 revision이 등록돼도 진행 중인 검증에는 섞지 않습니다. 단순 재시도는 처음 고정한 revision을 유지하며, 새 revision을 적용하려면 새로운 Verification work 또는 verification generation을 만들어야 합니다.

각 반증 질문에는 `question_id`가 있습니다. 검증 결과는 질문마다 `DISPROVED`, `NOT_DISPROVED`, `INCONCLUSIVE` 중 하나와 근거를 남깁니다. 실제 근거가 있는 `DISPROVED`가 하나 이상일 때만 `FALSE`가 가능합니다. `NOT_DISPROVED`는 반증하지 못했다는 뜻일 뿐 가설을 증명하지 않습니다.

가설의 각 필수 검증 항목에는 `validation_id`가 있습니다. final 결과는 같은 ID의 결과가 빠짐없이 한 번씩 있고, 모두 `COMPLETE`이며 실제 근거를 가리킬 때만 저장합니다. 하나라도 완료하지 못하면 final 판정을 만들지 않습니다. 다시 시도할 수 있으면 work를 `BLOCKED`로 두고 가설은 `VERIFYING`을 유지하며, 더 시도할 수 없으면 work와 가설을 함께 `FAILED`로 끝냅니다. 이 실패는 `FALSE`나 `HOLD`가 아니며 Gate 입력도 아닙니다.

Pro와 Con은 항상 별도의 새 대화에서 실행합니다. 상대 역할의 결론이나 대화를 이어받지 않으며, 실패 후 재시도나 provider 변경도 같은 역할의 새 대화로 시작합니다. Verification Agent만 두 결과를 함께 읽고 최종 판정을 만듭니다.

결과를 저장하기 전에는 결과 종류, 저장 담당 역할, 정확한 작업·시도·코드 버전, 플레이북 revision과 후보 내용 hash를 함께 검사합니다. `TRUE`는 실제 근거 reference가 연결된 supporting evidence, `FALSE`는 근거가 있는 `DISPROVED`, `HOLD`는 하나 이상의 `unresolved_conditions`와 정상적으로 확인한 범위를 설명하는 실제 evidence reference가 필요합니다. 오류·timeout·빈 Context·예산 초과 상태만으로 어떤 final verdict도 저장할 수 없습니다. Runtime Validator는 구조·reference·완료 상태만 검사합니다. final `TRUE` 근거의 기술적 충분성은 Technical Evidence Gate가 exact final TRUE revision을 대상으로 검토하며, `FALSE | HOLD`는 Technical Gate 입력이 아닙니다.

동적 재현이 필요하면 Verification Agent가 `EnvironmentRequirements`와 이를 가리키는 목표 중심의 최소 `ReproductionPlan`을 만듭니다. plan에는 가설·요구사항·Sandbox profile·재현 목표·관련 문맥을 담고, 원하는 사실을 편향 없이 적는 `requested_evidence`는 선택 필드로 둡니다. exact step·command·payload·target·cleanup policy는 R6가 지정하지 않습니다. `LIMITED_REPRO | FULL_REPRO` mode를 공통 계약에 둘지는 PL 교차 검토에서 확정합니다.

Runtime Validator는 요청자·상태·예산과 current plan·requirements·profile reference를 확인해 R7 호출을 허가합니다. R7 Controller는 host·Docker socket/daemon·mount/namespace·production secret·허용되지 않은 egress·다른 workspace를 차단하고 R8의 CPU·memory·disk·PID·wall-clock 값을 적용합니다. Agent에게 Docker daemon 권한은 주지 않으며 trusted runtime이 image build와 Sandbox lifecycle을 수행합니다.

`REPRODUCTION_AGENT`는 이 외부 경계 안에서 package·계정·fixture/mock·PoC·command·공격 입력·관찰·retry를 자율적으로 결정합니다. 자주 쓰는 도구가 있는 Toolbox Image를 시작점으로 삼고, 저장소별 Dockerfile·manifest·setup/account/fixture/mock/healthcheck를 불변 `EnvironmentRecipe`로 묶습니다. 누락 package를 발견하면 실패를 `AgentLog`에 남기고 recipe를 갱신해 새 baseline image digest와 clean Sandbox attempt를 만듭니다. package download는 baseline build 단계에서 수행하고 검증된 `PERSISTENT_BASELINE`은 이후에도 보존합니다.

가설이나 attempt 사이에는 writable state를 공유하지 않습니다. 가설마다 새 container를 강제할지는 PL 결정 사항이지만, 어떤 구현이든 각 시도는 snapshot처럼 깨끗한 상태에서 시작해야 합니다. 하나의 Sandbox는 하나의 가설·attempt만 처리합니다. session container·network·volume·tmp는 cleanup하고 baseline recipe/image는 `PRESERVED`로 구분합니다.

실제 shell·파일·환경 변경·image build·서비스·HTTP·DB·PoC 생성/수정/실행·관찰·retry·cleanup은 append-only `AgentLog`에 남깁니다. 숨은 chain-of-thought는 저장하지 않습니다. 만들기만 한 PoC는 log에만 남기고, 실행을 시작한 최종 exact `PoCBundle`만 `poc_ref`로 전달합니다. 실행이 실패해도 시작했다면 bundle을 연결하고 성공 여부는 log·status·outcome으로 구분합니다.

Agent는 plan 자체가 실행 가능한지 `EXECUTABLE | EXECUTABLE_WITH_LIMITATIONS | NEEDS_REVISION`으로 기록하고 문제는 결과의 범용 string 목록과 근거 refs로 반환합니다. 별도 `PlanIssue` record는 만들지 않습니다. Agent가 의미 필드를 초안 작성하고 trusted code가 runtime facts·refs·시간·cleanup·digest를 채우며, 작은 finalizer가 schema·authority·attempt·hash·redaction·reference 불변식만 검사합니다. Verification은 `COMMITTED` 결과만 읽어 final `TRUE | FALSE | HOLD`에 사용합니다.

Technical Gate가 `REVISE`를 반환하면 같은 ACTIVE `VerificationAssignment` owner가 직접 받습니다. 프로그램은 새 generation의 Verification work와 `TERMINAL -> VERIFYING` 전이를 먼저 원자적으로 만들고, 필요한 Context·Pro/Con·정적·동적 근거와 설명을 보완해 새 Verification revision·work 종료·current pointer를 함께 확정합니다. CWE 보완이 있으면 기존 CWE producer와 새 revision을 조정한 뒤 새 Gate work를 요청합니다. 이는 provider retry나 동일 입력 재투표가 아닙니다.

`status`는 실행 완료 정도이고 `hypothesis_outcome: SUPPORTED | DISPROVED | INCONCLUSIVE`은 관측과 가설의 관계입니다. 둘 다 최종 판정이 아닙니다. `FAILED | BLOCKED | CANCELLED`는 `INCONCLUSIVE`이며 가설 반증이 아닙니다. 실제 반증은 `DISPROVED`, `hypothesis_disproved: true`, 관측 근거 `hypothesis_evidence_refs`와 `disproof_evidence_refs`가 함께 있어야 합니다. Verification Agent가 이 정보와 다른 근거를 종합해 `TRUE | FALSE | HOLD`를 결정합니다. 상세 내용은 [검증과 동적 재현](../04-verification-and-dynamic-reproduction.md)을 따릅니다.

공통 작업 상태와 동적 결과 상태는 다르게 읽습니다. 부분 실행은 결과의 `limitations`로 한계를 설명하며 실제 오류가 없으면 오류 record를 만들지 않습니다. 외부 경계 차단 결과 `BLOCKED + failure_category=POLICY`는 요청을 정상 처리해 만든 종료 결과이므로 공통 작업은 `SUCCEEDED`로 닫지만 재현 성공은 아닙니다. 공통 작업의 `BLOCKED`는 승인이나 입력을 기다리는 비종료 상태에만 사용합니다. 취소 결과는 공통 `CANCELLED`와 함께 저장하며, 저장 확정 marker와 모든 결과 reference가 일치할 때만 Verification이 읽습니다.
