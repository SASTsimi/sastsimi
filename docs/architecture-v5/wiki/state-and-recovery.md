# 상태·병렬 실행·재시도·복구

## 쉽게 말하면

같은 분석 작업이 실수로 두 번 실행되거나, 취소한 작업의 늦은 결과가 최신 결과를 덮어쓰지 못하게 하는 규칙입니다. 프로그램이 중간에 종료되어도 마지막으로 완전히 저장된 지점부터 안전하게 다시 시작합니다.

**상세 기준:** [03. Agent 역할과 오케스트레이션](../03-agent-roles-and-orchestration.md), [07. 결과 저장과 관측성](../07-results-and-observability.md), [08. 경량 데이터 계약](../08-lightweight-data-contracts.md)

## 작업 상태와 취약점 판정은 다릅니다

`WorkExecutionState`는 “작업이 실행되었는가?”를 나타냅니다.

- `PENDING`: 앞 단계 대기
- `READY`: 시작 가능
- `RUNNING`: 실행 중
- `BLOCKED`: 재시도·인증·승인·입력·예산 조건 대기
- `SUCCEEDED`: 필요한 결과를 모두 저장
- `PARTIAL`: 일부 결과와 누락 사유를 함께 저장
- `FAILED`: 더 진행할 수 없는 최종 실패
- `CANCELLED`: 사용자 또는 프로그램이 취소

`SUCCEEDED`는 취약점이 맞다는 뜻이 아닙니다. 검증 작업이 성공했더라도 실제 판정은 그 결과 안의 `TRUE | FALSE | HOLD`를 읽어야 합니다.

## 같은 요청은 한 번만 반영합니다

프로그램은 입력 record와 설정을 이용해 `dedupe_key`(같은 요청인지 확인하는 값)를 만듭니다. 같은 key가 다시 들어오면 새 작업을 만들지 않고 기존 `work_id`와 상태를 반환합니다.

같은 작업에는 실행 중인 `attempt_id`가 하나만 있습니다. retry할 때는 새 attempt를 만들지만 이전 실패와 오류는 지우지 않습니다.

최종 종료 뒤 같은 입력으로 완전히 새 작업을 시작하려면 사람이 명시적으로 승인해야 합니다. 이때만 `work_generation`을 1 증가시키고 새 `work_id`와 key를 만듭니다.

## 동시에 실행할 수 있는 부분

- AST와 여러 SAST 도구
- 서로 다른 가설의 검증
- 같은 가설의 독립 Pro와 Con 조사
- 서로 다른 연계 가설

다음은 순서를 지켜야 합니다.

`최종 검증 + CWE → Technical Gate → Rule Scope Gate → Reporter → 사람 검토`

## 결과를 안전하게 합칩니다

결과가 도착하면 프로그램은 다음을 확인합니다.

1. 현재 실행 중인 attempt의 결과인가?
2. 작업 상태 version이 바뀌지 않았는가?
3. 처음 사용한 입력 record와 hash가 같은가?
4. `workspace_id`, `commit_id`, `hypothesis_id`가 같은가?
5. 취소되거나 이미 끝난 작업이 아닌가?

하나라도 맞지 않으면 최신 결과에 연결하지 않고 `STALE_RESULT` 또는 `ATTEMPT_NOT_ACTIVE`로 격리합니다.

## 결과와 종료 상태는 함께 확정합니다

예를 들어 가설 검증이 끝났다면 다음 두 가지가 함께 저장되어야 합니다.

- final `VerificationResult`의 정확한 `record_id`
- `HypothesisProcessState.status=TERMINAL`과 위 결과를 가리키는 reference

한쪽만 저장되면 다음 Gate를 호출하지 않습니다. 저장 제품이 한 번에 처리할 수 없으면 결과를 `PREPARED`로 격리한 뒤, 같은 상태 version에서 하나만 만들 수 있는 `COMMITTED` marker(저장이 확정됐다는 표시)를 먼저 남기고 상태가 그 결과를 가리키게 합니다. marker와 상태가 같은 결과·누락·오류를 가리킬 때만 다른 단계가 읽습니다.

검증을 끝내지 못한 경우도 상태를 반쪽만 바꾸지 않습니다. 다시 시도할 수 있으면 work를 `BLOCKED`로 두고 가설은 계속 `VERIFYING`입니다. 더 시도할 수 없으면 failed work와 `HypothesisProcessState.status=FAILED`를 함께 확정하고 `verification_result_ref`는 비워 둡니다. 이 가설에는 `TRUE | FALSE | HOLD`가 없으며 Gate도 호출하지 않습니다.

marker를 남긴 직후 프로그램이 꺼졌다면 재시작할 때 기존 marker를 상태에 다시 반영합니다. 이 복구가 끝나기 전에는 취소·재시도 같은 새 상태 변경도 받지 않습니다.

같은 규칙을 Technical Gate, Rule Scope Gate와 `ReportDraft`에도 적용합니다.

Context 조회 실패·timeout·권한 오류가 있어도 정상 근거로 모든 `validation_checks`를 완료할 수 있으면 현재 Verification work를 계속합니다. 반대로 필수 Context 또는 운영 Pro/Con을 확보하지 못해 검증을 끝낼 수 없으면 final `VerificationResult`를 만들지 않습니다. retry·재인증·새 입력을 기다릴 수 있으면 work는 `BLOCKED`이고 가설은 `VERIFYING`, 허용된 재시도를 모두 소진했거나 복구할 수 없으면 work와 가설 모두 `FAILED`입니다. 단순 오류를 `HOLD`로 바꾸지 않습니다.

동적 재현은 같은 단어의 뜻을 구분해야 합니다.

- 동적 결과 `FAILED + ENVIRONMENT_SETUP`: 필수 환경이 다르거나 확인되지 않아 공격 단계를 시작하지 못한 상태입니다. 가설 반증이나 `PARTIAL`이 아니며, R6가 조건을 바꾸면 새 요구사항과 이를 가리키는 새 계획을 함께 만들어 다시 검사받습니다.
- 동적 결과 `PARTIAL`: 일부 공격 단계를 실행해 믿을 수 있는 관측을 얻었지만 환경 차이 같은 한계가 남은 상태입니다. 결과의 `limitations`가 빠진 범위를 설명하므로 실제 오류가 없다면 오류나 `DataGap`을 억지로 만들지 않습니다.
- 동적 결과 `BLOCKED`: Sandbox 정책 때문에 실행하지 못했다는 종료 결과입니다. 요청을 정상 처리해 이 결과를 만들었으므로 공통 작업은 `SUCCEEDED`로 끝나지만, 재현 성공을 뜻하지는 않습니다.
- 공통 작업 `BLOCKED`: 재시도·인증·승인·입력을 기다리는 중이며 아직 끝나지 않은 상태입니다.
- 동적 결과 `CANCELLED`: 공통 취소 상태와 함께 저장합니다. 취소 확정 뒤 도착한 결과는 사용하지 않습니다.

동적 결과를 Verification에 넘기려면 저장 확정 marker, 공통 작업의 출력 reference와 동적 상태의 `dynamic_result_ref`가 모두 같은 결과 수정본을 가리켜야 합니다.

Gate 작업은 시작할 때 읽은 Verification, CWE, 앞 Gate와 정책의 정확한 수정본을 `input_refs`와 `input_hash`로 고정합니다. Gate 결과 안의 reference가 이 입력과 다르면 저장을 취소하고 다음 단계로 넘기지 않습니다.

## retry는 실패를 지우지 않습니다

재시도할 수 있는 attempt가 실패하면 작업은 `BLOCKED`가 됩니다.

- 인증 실패: 사용자 재인증 대기
- 호출량 제한: 정한 시간만큼 대기
- 잘못된 LLM 형식: 제한된 형식 수정 시도
- 예산 부족: 새 예산 승인 대기

조건이 해결되면 `READY`에서 새 `attempt_id`로 다시 시작합니다. 재시도할 수 없거나 한도를 모두 사용하면 최종 `FAILED`가 됩니다. 취소된 작업은 자동 재시도하지 않습니다.

Pro와 Con은 부모 Verification 아래의 별도 child work입니다. 한쪽이 재시도를 기다리면 그 child와 부모 Verification을 모두 `BLOCKED`로 두고 가설은 `VERIFYING`을 유지합니다. 성공한 다른 쪽 결과는 부모·generation·공통 입력·플레이북·설정·예산 기준이 그대로일 때만 보존합니다. 하나라도 바뀌면 두 역할을 모두 다시 실행합니다.

한쪽이 복구 불가능하게 실패하면 child 실패를 먼저 확정해 부모 진행을 막습니다. 이어 부모 Verification과 가설을 함께 `FAILED`로 끝냅니다. 중간에 프로그램이 멈추면 복구가 이 전파를 끝낼 때까지 부모를 다시 실행하지 않습니다. final `VerificationResult`는 없고 Gate도 호출하지 않습니다. 취소되거나 부모가 교체된 뒤 늦게 도착한 결과는 보관할 수 있지만 현재 결과로 사용하지 않습니다.

Technical Gate의 `REVISE`는 이 retry와 다릅니다. `REVISE` 작업은 결과를 저장하고 끝낸 뒤 같은 ACTIVE `VerificationAssignment` owner에게 직접 전달합니다. 프로그램은 종료된 기존 Verification work를 되돌리지 않고 새 generation의 Verification work를 만들며, 가설 상태와 새 work pointer를 한 번에 `TERMINAL -> VERIFYING`으로 바꿉니다. 새 결과·work 종료·가설의 current result pointer도 함께 확정한 다음 새 `input_hash`, `dedupe_key`, `work_id`와 첫 attempt로 Gate를 다시 시작합니다. 같은 입력에 attempt만 추가해 다시 투표하거나 오래된 Gate 결과를 새 Verification revision에 재사용하지 않습니다.

## 프로그램이 중단되면

마지막 `COMMITTED` 상태부터 다시 확인합니다.

- 완전히 저장된 결과: 재사용하고 다시 실행하지 않음
- 실행 중이었지만 저장되지 않은 attempt: 중단 오류를 남기고 허용된 경우만 새 attempt
- `PREPARED` 상태: 현재 version과 입력이 맞으면 확정 marker와 상태 연결을 마무리하고, 아니면 취소·격리
- `COMMITTED` marker만 있고 상태 연결이 덜 됨: 기존 marker를 다시 반영하고 새 상태 변경은 그 뒤 재평가
- 결과와 상태가 맞지 않음: 다음 단계 차단
- 안전하게 판단할 수 없음: `RECOVERY_FAILED`로 중단하고 사람 확인

## 기억할 원칙

- 오류, 인증 실패, timeout, 취소와 정보 부족은 취약점 `FALSE`가 아닙니다.
- 늦은 성공 결과도 취소를 되돌리지 않습니다.
- 이미 확정한 record를 덮어쓰지 않습니다.
- Queue나 특정 DB 제품을 전제로 하지 않습니다.
- 실행 구현과 성능 검증은 아직 완료되지 않았습니다.
