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

판정에는 최소 근거가 필요합니다. TRUE는 핵심 공격 경로와 필요한 조건을 지지하는 근거가 있어야 합니다. FALSE는 이름이 있는 반증 질문이 실제 근거로 `DISPROVED`된 경우에만 가능합니다. 오류·timeout·정보 부족·Sandbox 실패는 FALSE 근거가 아닙니다. HOLD는 판단에 필요한 조건이나 환경이 아직 부족하다는 뜻입니다.

기본 Context가 부족하면 검증 Agent가 같은 workspace·commit을 기준으로 추가 Context를 요청합니다. 조회가 정상적으로 끝났지만 정보가 부족하면 필수 검증을 계속하고, 검증 완료 후에도 부족한 조건이 남으면 `unresolved_conditions`와 `HOLD`를 기록합니다. 조회 자체가 실패·timeout·권한 오류로 끝나면 `AnalysisError`와 실행 상태만 기록하며 final verdict를 만들지 않습니다. 운영 Pro/Con 전에 예산이 부족한 경우도 `BUDGET_EXCEEDED`로 작업을 중단하고 final verdict를 저장하지 않습니다.

`initial_verdict`는 중간 판단이며 운영 Gate·Primitive·보고서 입력으로 사용할 수 없습니다. final verdict는 독립 Pro/Con과 필요한 동적 결과를 종합한 최종 판단입니다.

지원 취약점 유형 목록은 R8의 versioned evaluation corpus에서 확정합니다. 목록이 확정되기 전이나 미지원 유형을 검증할 때는 source, sink, 방어 로직, 반증 질문, 필요한 정적·동적 근거와 HOLD 조건을 담은 공통 플레이북의 exact revision을 사용합니다. 유형별 플레이북도 같은 구조로 작성하며 각 revision을 덮어쓰지 않습니다.

최종 `VerificationResult.playbook_ref`는 실제 사용한 플레이북의 정확한 `record_id`와 `content_hash`를 가리킵니다. 같은 reference를 final Verification 합성 호출과 결과 저장 요청에도 사용합니다. 이후 플레이북이 변경되더라도 과거 판정은 당시 사용한 기존 플레이북 revision을 계속 가리킵니다.

각 반증 질문에는 `question_id`가 있습니다. 검증 결과는 질문마다 `DISPROVED`, `NOT_DISPROVED`, `INCONCLUSIVE` 중 하나와 근거를 남깁니다. 실제 근거가 있는 `DISPROVED`가 하나 이상일 때만 `FALSE`가 가능합니다. `NOT_DISPROVED`는 반증하지 못했다는 뜻일 뿐 가설을 증명하지 않습니다.

Pro와 Con은 항상 별도의 새 대화에서 실행합니다. 상대 역할의 결론이나 대화를 이어받지 않으며, 실패 후 재시도나 provider 변경도 같은 역할의 새 대화로 시작합니다. Verification Agent만 두 결과를 함께 읽고 최종 판정을 만듭니다.

결과를 저장하기 전에는 결과 종류, 저장 담당 역할, 정확한 작업·시도·코드 버전, 플레이북 revision과 후보 내용 hash를 함께 검사합니다. `TRUE`는 실제 근거 reference가 연결된 supporting evidence, `FALSE`는 근거가 있는 `DISPROVED`, `HOLD`는 하나 이상의 `unresolved_conditions`가 필요합니다. 오류·timeout·빈 Context·예산 초과 상태만으로 `TRUE`나 `FALSE`를 저장할 수 없습니다. Runtime Validator는 필드와 reference의 최소 구조만 검사하며, final TRUE 근거의 기술적 충분성은 Technical Evidence Gate가 별도로 검토합니다.

| 모드 | 목적 |
|---|---|
| `NOT_REQUIRED` | 정적 근거로 현재 판정 가능 |
| `LIMITED_REPRO` | guard, sink, 권한 조건 등 작은 질문 확인 |
| `FULL_REPRO` | 안전한 end-to-end 재현과 PoC |

Verification Agent가 세 모드 중 하나를 결정합니다. 동적 재현이 필요하면 Verification이 exact `ReproductionPlan`을 만들고, trusted runtime이 계획·reference·권한·예산을 검사해 확정합니다. Sandbox는 모드를 다시 선택하거나 계획을 수정하지 않습니다.

Docker는 ephemeral/non-root, network default-deny와 자원·시간 제한을 사용합니다. 필수 환경이나 공격 경로를 실행하지 못하면 `FAILED + ENVIRONMENT_SETUP`입니다. 공격 경로를 일부 실행해 믿을 수 있는 관측은 얻었지만 환경 차이 때문에 전체 확인이 부족하면 `PARTIAL + NONE`이며, 관측과 한계를 함께 남깁니다.

실행 전에 Verification이 만든 `ReproductionPlan`에 LIMITED/FULL mode, 가설, 순서가 있는 단계, 각 단계의 명령·공격 입력과 cleanup 정책의 정확한 reference를 고정합니다. Runtime Validator의 `RUN_SANDBOX` 허가는 요청자·상태·예산과 exact 계획 reference만 확인합니다. Sandbox Controller가 image·명령·파일·네트워크·자원·cleanup 정책을 검사하고, 통과한 계획만 Sandbox Runner가 실행합니다. Runner는 실제 단계·명령·공격 입력을 `SandboxStepLog`에 남기고, 결과 저장 때 승인 계획과 로그를 다시 대조합니다. Sandbox만 동적 결과를 만들며 Verification은 `COMMITTED`된 결과만 읽어 최종 판정에 사용합니다. 계획 변경이 필요하면 Controller나 Runner가 이유를 반환하고 Verification이 새 계획과 새 실행 요청을 만듭니다.

Technical Gate가 `REVISE`를 반환하면 같은 ACTIVE `VerificationAssignment` owner가 직접 받습니다. 프로그램은 새 generation의 Verification work와 `TERMINAL -> VERIFYING` 전이를 먼저 원자적으로 만들고, 필요한 Context·Pro/Con·정적·동적 근거와 설명을 보완해 새 Verification revision·work 종료·current pointer를 함께 확정합니다. CWE 보완이 있으면 기존 CWE producer와 새 revision을 조정한 뒤 새 Gate work를 요청합니다. 이는 provider retry나 동일 입력 재투표가 아닙니다.

`status`는 실행 완료 정도이고 `hypothesis_outcome: SUPPORTED | DISPROVED | INCONCLUSIVE`은 관측과 가설의 관계입니다. 둘 다 최종 판정이 아닙니다. `FAILED | BLOCKED | CANCELLED`는 `INCONCLUSIVE`이며 가설 반증이 아닙니다. 실제 반증은 `DISPROVED`, `hypothesis_disproved: true`, 관측 근거 `hypothesis_evidence_refs`와 `disproof_evidence_refs`가 함께 있어야 합니다. Verification Agent가 이 정보와 다른 근거를 종합해 `TRUE | FALSE | HOLD`를 결정합니다. 상세 내용은 [검증과 동적 재현](../04-verification-and-dynamic-reproduction.md)을 따릅니다.

공통 작업 상태와 동적 결과 상태는 다르게 읽습니다. 부분 실행은 결과의 `limitations`로 한계를 설명하며 실제 오류가 없으면 오류 record를 만들지 않습니다. 정책 차단 결과 `BLOCKED + POLICY_BLOCKED`는 Sandbox가 요청을 처리해 만든 종료 결과이므로 공통 작업은 `SUCCEEDED`로 닫지만, 재현 성공은 아닙니다. 공통 작업의 `BLOCKED`는 승인이나 입력을 기다리는 비종료 상태에만 사용합니다. 취소 결과는 공통 `CANCELLED`와 함께 저장하며, 저장 확정 marker와 모든 결과 reference가 일치할 때만 Verification이 읽습니다.
