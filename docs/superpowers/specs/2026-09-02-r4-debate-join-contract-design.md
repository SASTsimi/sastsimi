# R4 Pro·Con 합류 공통 계약 설계

## 상태

- 설계 상태: `DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED`
- 관련 Issue: [#56](https://github.com/SASTsimi/sastsimi/issues/56)
- 관련 PR: [#69](https://github.com/SASTsimi/sastsimi/pull/69)
- 담당 역할: R4 PM·아키텍처·워크플로

## 목표

R6이 정한 Pro·Con 병렬 검증 흐름을 trusted runtime이 검사할 수 있는 공통 계약으로 고정한다. 운영 final `VerificationResult`는 같은 가설·Verification generation·공통 입력을 사용한 exact Pro·Con 결과가 모두 정상 완료된 경우에만 저장한다.

## 범위

포함한다.

- Pro·Con이 각각 생산하는 `EvidenceAgentResult`
- 상위 `VERIFICATION` work와 하위 `PRO_EVIDENCE | CON_EVIDENCE` work의 연결
- final `VerificationResult`가 사용하는 exact Pro·Con 결과와 공통 입력 hash
- 한쪽 실패·retry·failover·취소·예산 대기 때의 상위·하위 상태
- 역할별 prompt와 결과 조회를 통한 교차 오염 차단
- 운영·평가 모드별 null 및 필수 reference 조합
- 관찰성, 오류, Wiki와 자동 문서 검증

포함하지 않는다.

- Pro·Con의 취약점 분석 내용과 prompt 문장
- provider·model 선택
- R8이 소유한 구체적인 예산 수치
- 실제 병렬 실행 코드
- Gate의 의미적 판단 기준 변경
- 전체 Mermaid 흐름 변경

## 계약 구조

### EvidenceAgentResult

Pro 또는 Con Agent 한쪽이 만든 불변 결과다. 쉬운 영문 필드를 사용한다.

- `meta`: 현재 analysis·workspace·commit·hypothesis를 고정한다.
- `role`: `PRO | CON` 중 하나다.
- `parent_work_id`: current `VERIFICATION` work ID다.
- `evidence_work_id`: 현재 역할의 `PRO_EVIDENCE | CON_EVIDENCE` work ID다.
- `verification_generation`: 부모 Verification이 속한 가설 검증 세대다.
- `llm_call_id`: 결과를 만든 성공 LLM 호출 ID다.
- `debate_input_hash`: 두 역할에 공통으로 고정한 입력의 SHA-256이다. 역할별 work의 일반 `input_hash`와 구분한다.
- `evidence`: 역할에 맞는 `EvidenceClaim[]`이다.
- `summary`, `limitations`: 한쪽 역할의 결과 요약과 남은 한계다.

Pro는 supporting claim만, Con은 counter claim만 생산한다. `meta.attempt_id`로 결과를 만든 attempt를 확인한다. child work의 `output_refs`와 호출 log의 `parsed_output_ref`가 exact 결과를 단방향으로 가리키므로 결과가 다시 log나 종료 work를 참조해 content hash 순환을 만들지 않는다. 결과는 연결된 work·attempt·call이 모두 current이고 `SUCCEEDED`, schema-valid, `COMMITTED`일 때만 사용할 수 있다.

### WorkExecutionState 부모·자식 연결

공통 `WorkExecutionState`에 nullable `parent_work_ref`를 둔다. `PRO_EVIDENCE | CON_EVIDENCE`에서는 current `VERIFICATION` work가 필수이고 다른 work type에서는 기본적으로 `null`이다.

상위 Verification work의 입력에는 ACTIVE assignment, exact hypothesis, 코드·Context·정적 근거, 반증 질문, exact playbook, versioned Debate 설정과 versioned budget profile이 들어간다. 그 정렬된 reference와 설정으로 `input_hash`를 만든다. 두 하위 work와 호출은 같은 값을 사용한다.

### VerificationResult 연결

`VerificationResult`에 다음 필드를 추가한다.

- `debate_input_hash`
- `pro_evidence_ref`
- `con_evidence_ref`

`PRODUCTION + ALWAYS_DEBATE`와 Debate를 실제 실행한 평가 작업에서는 두 evidence reference가 모두 필수다. `EVALUATION + BASIC` 또는 trigger가 없어 조건부 Debate를 생략한 경우에는 두 reference와 `debate_input_hash`가 모두 `null`이다.

두 reference는 서로 다른 역할의 결과를 정확히 하나씩 가리키고, 같은 analysis·workspace·commit·hypothesis·parent Verification work·Verification generation·`input_hash`를 가져야 한다. final Verification 합성 호출과 `SAVE_RESULT(result_kind=verification_result)`는 두 exact result reference를 입력으로 포함한다.

## 상태와 오류

한쪽 호출이 재시도 가능한 오류로 끝나면 해당 하위 work를 `BLOCKED`로 두고 상위 Verification work도 `BLOCKED`로 전환한다. 상위 `waiting_for`에는 실제 원인인 `RETRY | AUTH | BUDGET | DEPENDENCY`를 기록하고 가설은 `VERIFYING`을 유지한다. 성공한 반대쪽 결과는 공통 입력과 generation이 그대로인 동안만 보존한다.

대기 조건이 해결되면 실패한 역할만 새 attempt·call·NEW session으로 다시 실행한다. 유효한 두 결과가 모이면 상위 Verification을 `READY -> RUNNING`으로 진행한다.

하위 실패를 복구할 수 없거나 허용된 시도를 모두 사용하면 실패한 하위 work를 자기 `COMMITTED` `TransitionCommit`으로 먼저 확정해 상위 진행을 막는다. 이어 상위 Verification work와 `HypothesisProcessState.status=FAILED`를 기존 atomic 경계에서 함께 확정하고 `verification_result_ref=null`로 둔다. 중간에 중단되면 recovery가 이 전파를 완료하기 전까지 부모를 실행하지 않는다. 취소된 호출은 retry/failover predecessor가 될 수 없고, 취소·종료 뒤 늦게 도착한 결과는 `STALE_RESULT`로 격리한다.

가설·Context·코드·플레이북·Debate 설정·budget profile 또는 Verification generation이 바뀌면 이전 두 결과를 새 합성에 사용할 수 없다. 새 Verification work에서 두 역할을 모두 다시 실행한다.

## 독립 입력과 조회 경계

Pro와 Con은 상대 역할의 output·결론·session·action decision·work·attempt·call log를 다음 경로로 받을 수 없다.

- `context_refs`
- `prompt_payload_ref`
- parent 또는 predecessor
- provider session
- 결과 저장소 조회
- 일반 tool 결과

trusted prompt builder가 역할, 고정된 prompt template과 허용된 공통 입력 reference로 immutable payload를 만든다. Agent가 prompt payload나 허용 입력 목록을 직접 확장하지 않는다. runtime은 상대 역할 record가 payload·context·action input 또는 조회 결과에 포함되면 `CROSS_ROLE_INPUT_DENIED`로 호출과 저장을 거절한다.

## 역할 경계

- R4는 위 필드·reference·상태·오류·강제 규칙을 소유한다.
- R6는 Pro·Con evidence의 내용과 final 합성 의미를 소유한다.
- R3는 부모·자식 work, 병렬 실행, join과 trusted prompt builder를 구현한다.
- R8은 versioned budget profile, 두 최초 호출의 사전 예산 확보와 사용량 평가를 소유한다.
- R5는 exact final `VerificationResult`만 받으며 Pro·Con을 직접 다시 호출하거나 별도 결과를 선택하지 않는다.
- R2는 두 역할이 읽을 같은 immutable Context·정적 근거 reference를 제공한다.
- R7의 Sandbox 책임은 바뀌지 않는다.

## 완료 조건

- 공통 데이터 계약에서 exact Pro·Con 결과와 상위 Verification을 추적할 수 있다.
- 운영 final 결과는 두 유효한 결과 없이는 저장할 수 없다.
- 평가 생략과 운영 실행의 null 조합이 모호하지 않다.
- 하위 오류가 상위 상태와 가설 상태에 어떻게 반영되는지 한 가지 의미로 정해져 있다.
- prompt·조회·session을 통한 교차 오염이 모두 차단된다.
- Gate는 기존처럼 exact final TRUE Verification만 받는다.
- 정본, Wiki와 자동 문서 검증이 같은 규칙을 확인한다.
