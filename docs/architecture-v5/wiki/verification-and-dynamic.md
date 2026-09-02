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

| 모드 | 목적 |
|---|---|
| `NOT_REQUIRED` | 정적 근거로 현재 판정 가능 |
| `LIMITED_REPRO` | guard, sink, 권한 조건 등 작은 질문 확인 |
| `FULL_REPRO` | 안전한 end-to-end 재현과 PoC |

Verification Agent가 세 모드 중 하나를 결정합니다. 동적 재현이 필요하면 Verification이 필요한 환경을 exact `EnvironmentRequirements`로 기록하고 이를 가리키는 `ReproductionPlan`을 만듭니다. trusted runtime은 두 record의 schema·reference·권한·예산을 검사해 확정합니다. Sandbox는 요구사항·허용 대체 버전·모드·계획을 다시 선택하거나 수정하지 않습니다.

Docker는 ephemeral/non-root, network default-deny와 자원·시간 제한을 사용합니다. R7은 실제 환경·Health Check를 requirement별로 비교합니다. 필수 항목이 `MISMATCH | NOT_CHECKED | ERROR`이면 공격 단계 전에 멈추고 `FAILED + ENVIRONMENT_SETUP`으로 R6에 돌려보냅니다. 공격 경로를 실제로 일부 실행해 믿을 수 있는 관측을 얻은 뒤 전체 확인이 부족한 경우에만 `PARTIAL + NONE`이며, 관측과 한계를 함께 남깁니다.

실행 전에 Verification이 `EnvironmentRequirements`에 애플리케이션 역할·인증 방식·데이터·DB/service·fixture/mock·필수/대체 버전·Health Check와 근거를 고정합니다. `ReproductionPlan`에는 그 exact reference와 LIMITED/FULL mode, 가설, 순서가 있는 단계, 각 단계의 명령·공격 입력, cleanup 정책을 고정합니다. Runtime Validator의 `RUN_SANDBOX` 허가는 요청자·상태·예산과 current 계획·requirements reference를 확인합니다. Sandbox Controller가 image·명령·파일·네트워크·자원·cleanup 정책을 검사하고 exact 판정을 저장한 뒤, 통과한 계획만 Sandbox Runner가 실행합니다. Runner는 환경 비교가 끝나기 전 공격 단계를 시작하지 않으며 실제 단계·명령·공격 입력을 `SandboxStepLog`에 남깁니다. 비-LLM Result Assembler는 같은 분석·가설의 exact R6 plan closure와 같은 R7 실행 attempt의 정책·환경 비교·log·PoC·정리 reference를 동적 결과로 묶고 저장 때 조합을 다시 대조합니다. Verification은 `COMMITTED`된 결과만 읽어 최종 판정에 사용합니다.

필수 환경 차이가 생기면 R7은 요구사항을 고치거나 차이를 승인하지 않고 exact 비교 결과를 R6에 반환합니다. R6이 환경 조건이나 허용 대체값을 바꾸려면 기존 record를 덮어쓰지 않고 새 `EnvironmentRequirements`와 이를 가리키는 새 `ReproductionPlan`을 함께 만듭니다. 조건은 유지하고 실행 단계만 바꾸면 새 plan만 만듭니다. 두 경우 모두 Runtime Validator와 Sandbox Controller를 다시 통과해야 하며, R6의 수용은 Sandbox 보안 정책을 우회하지 않습니다.

동적 결과는 정확한 PoC·Controller 정책 판정·실제 생성 환경·Runner 단계 로그를 reference로 전달합니다. 요구사항 reference는 결과에 중복 저장하지 않고 `reproduction_plan_ref → environment_requirements_ref`와 `environment_ref → requirements_ref`가 같은지 확인합니다. Runner가 호출되지 않았으면 단계 로그는 비어 있고, 호출됐다면 환경 차이로 첫 공격 단계 전에 멈춰도 로그가 필요합니다. 실제 환경이 없으면 환경 reference도 비어 있습니다. 정리할 자원이 전혀 없을 때만 `cleanup_status=NOT_REQUIRED`를 사용합니다. PoC reference가 있어도 정책에 막혀 실행되지 않았을 수 있으므로 상태와 로그를 함께 확인합니다. R4는 공통 필드·null·상태·reference 조합을, R6는 필요한 조건과 허용 차이를, R7은 실제 비교와 각 artifact의 상세 내용을 작성합니다.

Technical Gate가 `REVISE`를 반환하면 같은 ACTIVE `VerificationAssignment` owner가 직접 받습니다. 프로그램은 새 generation의 Verification work와 `TERMINAL -> VERIFYING` 전이를 먼저 원자적으로 만들고, 필요한 Context·Pro/Con·정적·동적 근거와 설명을 보완해 새 Verification revision·work 종료·current pointer를 함께 확정합니다. CWE 보완이 있으면 기존 CWE producer와 새 revision을 조정한 뒤 새 Gate work를 요청합니다. 이는 provider retry나 동일 입력 재투표가 아닙니다.

`status`는 실행 완료 정도이고 `hypothesis_outcome: SUPPORTED | DISPROVED | INCONCLUSIVE`은 관측과 가설의 관계입니다. 둘 다 최종 판정이 아닙니다. `FAILED | BLOCKED | CANCELLED`는 `INCONCLUSIVE`이며 가설 반증이 아닙니다. 실제 반증은 `DISPROVED`, `hypothesis_disproved: true`, 관측 근거 `hypothesis_evidence_refs`와 `disproof_evidence_refs`가 함께 있어야 합니다. Verification Agent가 이 정보와 다른 근거를 종합해 `TRUE | FALSE | HOLD`를 결정합니다. 상세 내용은 [검증과 동적 재현](../04-verification-and-dynamic-reproduction.md)을 따릅니다.

공통 작업 상태와 동적 결과 상태는 다르게 읽습니다. 부분 실행은 결과의 `limitations`로 한계를 설명하며 실제 오류가 없으면 오류 record를 만들지 않습니다. 정책 차단 결과 `BLOCKED + POLICY_BLOCKED`는 Sandbox가 요청을 처리해 만든 종료 결과이므로 공통 작업은 `SUCCEEDED`로 닫지만, 재현 성공은 아닙니다. 공통 작업의 `BLOCKED`는 승인이나 입력을 기다리는 비종료 상태에만 사용합니다. 취소 결과는 공통 `CANCELLED`와 함께 저장하며, 저장 확정 marker와 모든 결과 reference가 일치할 때만 Verification이 읽습니다.
