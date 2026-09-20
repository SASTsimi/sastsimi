# SimpleRuntime 기반 로컬 E2E 실행 설계

## 목적

확정된 SASTSIMI Agent·데이터 계약·판정 규칙을 유지하면서, 실제 저장소 분석을 빠르고 안정적으로 끝낼 수 있는 단순 순차 실행 관리자를 추가한다. 기존 Runtime은 변경하지 않고 동결한다. 로컬 실제 분석은 명시적으로 SimpleRuntime을 선택할 수 있으며, 성공한 단계는 재사용하고 실패한 단계부터 다시 시작한다.

## 범위

- 현재 PyGoat 분석의 동일한 `analysis_id`, 데이터 디렉터리, 정적 결과, 가설, Pro·Con 결과와 Docker 이미지를 재사용한다.
- PyGoat를 PoC, 최종 Verification, CWE, 두 Gate, Finding, Markdown 보고서까지 완주한다.
- PyGoat 완료 후 ItsDangerous를 실제 저장소 입력으로 실행한다.
- 첫 버전은 가설을 순차 처리한다. 병렬 처리는 안정화 이후 후속 범위로 둔다.
- 기존 분산 Runtime, worker lease, dispatch 복구 구조는 삭제하거나 변경하지 않는다.

## 유지하는 안전·정확성 규칙

- 실행 오류, 인증 실패, 환경 실패를 취약점 `FALSE`로 바꾸지 않는다.
- 모든 단계 입력과 출력은 정확한 `analysis_id`, `workspace_id`, `commit_id`, `hypothesis_id`, `attempt_id`, `StoredDataRef`로 연결한다.
- 현재 단계 입력 reference가 checkpoint에 저장된 입력 reference와 다르면 이전 성공 결과를 재사용하지 않는다.
- PoC 후보와 validated PoC를 구분한다.
- PoC 실행이 성공하고 가설을 지지하는 동적 근거가 같은 attempt에 연결된 경우에만 validated PoC를 만든다.
- 민감정보 검사를 통과한 결과만 다음 단계와 보고서에 전달한다.
- 이전 근거가 바뀌면 Gate, Finding, ReportDraft와 Markdown 보고서를 오래된 결과로 보고 재사용하지 않는다.

## 계약 단순화 원칙

기존 계약은 구현 자산이지 SimpleRuntime의 의무 호출 경로가 아니다. 로컬 순차 실행에서 정확성이나 안전성에 기여하지 않고 실행·복구만 복잡하게 만드는 계약은 사용하지 않거나 작은 내부 DTO로 대체한다.

반드시 유지하는 계약은 다음과 같다.

- 단계 입력·출력의 exact reference와 동일 분석·가설·attempt 연결
- LLM 출력의 최소 구조 검증과 민감정보 제거
- PoC candidate와 validated PoC 구분
- 최종 `TRUE`의 성공한 동적 실행·validated PoC 조건
- 오류·인증 실패·환경 실패를 `FALSE`로 바꾸지 않는 규칙
- 두 Gate를 통과한 Finding만 Reporter에 전달하는 규칙
- 오래된 결과와 보고서의 재사용 차단

SimpleRuntime에서 제거하거나 대체할 수 있는 계약은 다음과 같다.

- 분산 worker 소유권·lease·heartbeat 계약
- 외부 dispatch 준비·반환·reconciliation 계약
- 단계마다 반복되는 action request·decision·budget reservation 묶음
- 같은 단일 프로세스 안에서 중복되는 transition commit·revision 체인
- 로컬 실행에서도 요구되던 다중 owner·handoff 상태
- 실행 결과와 직접 관계없는 과도한 provenance 중복 필드

대체 DTO는 `StageCheckpoint`, `StageResult`, `StageFailure` 세 종류로 제한한다. 기존 Agent 출력은 단계 경계에서 한 번만 검증하고, 이후 SimpleRuntime 내부에서는 이 DTO로 진행 상태를 관리한다. 기존 결과를 불필요하게 복사하지 않고 exact reference만 저장한다.

## SimpleRuntime 책임

SimpleRuntime은 다음 네 가지 일만 한다.

1. 현재 checkpoint 다음 단계를 호출한다.
2. 성공 결과와 정확한 입력·출력 reference를 저장한다.
3. 실패한 단계만 새 attempt로 재시도한다.
4. 분석과 가설별 현재 진행 위치를 기록한다.

SimpleRuntime은 취약점 판정, CWE 선택, Gate 판단 또는 보고서 사실 생성을 직접 수행하지 않는다. 각 기존 Agent가 해당 결정을 계속 담당한다. 기존 trusted service가 단순 호출을 막는 경우에는 해당 service 전체를 우회하고, 같은 핵심 검사만 수행하는 작은 단계 어댑터로 교체한다.

## 단계 모델

분석 공통 단계:

1. `STATIC_DONE`
2. `HYPOTHESIS_DONE`

가설별 단계:

1. `PRO_CON_DONE`
2. `VERIFICATION_INITIAL_DONE`
3. `POC_CANDIDATE_DONE`
4. `POC_EXECUTION_DONE`
5. `VERIFICATION_FINAL_DONE`
6. `CWE_DONE`
7. `TECH_GATE_DONE`
8. `SCOPE_GATE_DONE`
9. `FINDING_DONE`
10. `REPORT_DONE`

각 단계는 `PENDING | RUNNING | SUCCEEDED | BLOCKED | FAILED` 상태를 갖는다. 실패한 단계는 이전 성공 checkpoint를 유지하며, 동일 단계만 새 attempt로 재실행한다.

## Checkpoint 데이터

분석별 단일 checkpoint와 가설별 checkpoint를 저장한다. 최소 필드는 다음과 같다.

- 분석·workspace·commit·가설 식별자
- 현재 단계와 상태
- 단계 입력 reference 목록과 입력 hash
- 단계 출력 reference 목록
- attempt 식별자와 시도 횟수
- 마지막 안전 오류 코드와 재시도 가능 여부
- Docker recipe reference, image digest, 재사용 가능한 container 식별자
- validated PoC reference
- Finding reference, ReportDraft reference, Markdown 경로
- 갱신 시각

checkpoint 갱신과 단계 결과 저장은 같은 SQLite transaction으로 확정한다. 프로세스가 중단되면 `RUNNING` 단계만 `BLOCKED`로 복구하고 이전 `SUCCEEDED` 단계는 유지한다.

## 재사용과 무효화

- clone·checkout은 `workspace_id + commit_id`가 같고 무결성 확인을 통과하면 재사용한다.
- 정적 분석, 가설, Pro·Con과 Verification 결과는 exact input reference 집합이 같을 때만 재사용한다.
- Docker 이미지는 `commit_id + EnvironmentRecipe content_hash`가 같으면 재사용한다.
- 정상 상태인 같은 가설의 container는 재사용할 수 있다. 상태 변경·비정상 종료·health check 실패 시에만 다시 생성한다.
- 실패한 PoC 후보는 validated PoC로 승격하지 않는다. 후보 내용이 실행 불가능하면 `POC_CANDIDATE_DONE`을 무효화하고 후보 생성 단계만 한 번 다시 실행한다.
- Gate 이전 입력이 달라지면 Gate 이후의 성공 checkpoint를 모두 무효화한다.

## PoC 재시도

PoC 후보는 현재 Sandbox 안에서 자체 실행 가능해야 한다. 외부 URL, 쿠키, secret 또는 미리 준비되지 않은 환경변수를 요구하는 placeholder 스크립트는 성공 후보로 저장하지 않는다. 저장소에 포함된 코드와 설정을 우선 사용하고, 필요한 무해한 fixture와 mock은 candidate가 Sandbox 내부에서 생성한다.

구조화 출력 오류는 위반 필드와 오류 코드를 저장한다. 자동 수정 가능한 단일 필드 오류는 그 필드만 수정하여 같은 단계에서 한 번 재시도한다. exact reference, 민감정보 검사, candidate/validated 구분 오류는 자동 완화하지 않는다.

## 실행 방식

- 첫 버전은 한 프로세스·가설 순차 실행이다.
- 회원제 LLM 호출은 한 번에 하나만 실행하여 인증 갱신 충돌을 막는다.
- 기존 Runtime용 budget reservation, worker lease, action decision 체인과 external dispatch reconciliation은 SimpleRuntime의 로컬 순차 경로에 사용하지 않는다.
- 전체 분석 재시작 명령과 단계 재개 명령을 구분한다.
- Fake 실행 경로와 기존 Runtime 경로는 유지하되 SimpleRuntime과 상태 파일을 공유하지 않는다.

## 현재 PyGoat 상태 이관

현재 저장 DB를 읽어 다음 성공 결과를 checkpoint에 등록한다.

- repository clone과 고정 commit
- RepositoryProfile 및 정적 분석 결과
- 세 가설과 Pro·Con 결과
- 초기 Verification 및 동적 재현 요청
- 재사용 가능한 Docker recipe와 image digest

현재 실패 상태는 다음처럼 이관한다.

- SQL injection: 실행 불가능한 후보를 폐기하고 `POC_CANDIDATE_DONE`부터 재시도
- Command injection: Provider 실패로 `POC_CANDIDATE_DONE`부터 재시도
- Path traversal: 외부 환경변수를 요구한 후보를 폐기하고 `POC_CANDIDATE_DONE`부터 재시도

이관은 기존 record를 수정하지 않고 checkpoint가 exact reference로 가리키는 방식으로 수행한다.

## 오류 처리

- 인증·rate limit·Provider 실패: `BLOCKED`, 동일 단계 재개
- schema 오류: 위반 필드 기록 후 허용된 경우 한 번 수정 재시도, 아니면 `BLOCKED`
- Docker build·실행 실패: `FAILED` 또는 `BLOCKED`, 취약점 verdict 미생성
- 동적 반증: Agent의 최종 Verification에서만 `FALSE`
- 동적 결론 불충분: Agent의 최종 Verification에서만 `HOLD`
- exact reference 불일치·다른 attempt 혼합·민감정보 저장 실패: 즉시 `FAILED`, 뒤 단계 실행 금지

## 파일 경계

- `src/sastsimi/simple_runtime/models.py`: 단계·checkpoint 모델
- `src/sastsimi/simple_runtime/store.py`: SQLite checkpoint 저장과 원자적 갱신
- `src/sastsimi/simple_runtime/runner.py`: 순차 단계 실행과 재개
- `src/sastsimi/simple_runtime/migration.py`: 기존 PyGoat 결과의 read-only 이관
- `src/sastsimi/simple_runtime/stages.py`: 기존 Agent 호출과 필요한 핵심 검사만 제공하는 단계 어댑터
- `src/sastsimi/cli/`: SimpleRuntime 선택과 재개 명령 연결
- `tests/simple_runtime/`: 정상 재개와 실패 차단 테스트

기존 Agent, artifact 형식과 Docker adapter는 가능한 범위에서 재사용한다. 기존 공통 contract가 SimpleRuntime의 실행을 불필요하게 막으면 외부 저장 형식은 유지하되 내부 실행 DTO로 변환한다. 기존 Runtime 전용 contract를 새 경로에 다시 구현하지 않는다.

## 검증 기준

핵심 자동 테스트는 두 개로 제한한다.

1. 정상 흐름: 앞 단계가 성공한 가설은 건너뛰고 실패한 PoC 단계부터 시작하여 보고서까지 진행한다.
2. 실패 흐름: PoC 실행 또는 Provider 실패가 `FALSE`가 되지 않고, validated PoC·Gate·Finding을 만들지 않는다.

실제 검증은 같은 PyGoat `analysis_id`에서 실패 단계부터 재개하여 Markdown 보고서를 생성하고, 이어서 ItsDangerous를 실행한다. 두 실제 E2E가 끝난 뒤 전체 테스트와 CI를 한 번 수행한다.

## 완료 조건

- 현재 PyGoat의 완료된 결과와 Docker 이미지를 재사용한다.
- 세 가설 중 최소 하나가 validated PoC, 두 Gate, Finding, Markdown 보고서까지 완주한다.
- 실패 가설은 정확한 실패 단계에 머물며 앞 단계를 다시 실행하지 않는다.
- ItsDangerous 실제 분석이 Fake Adapter 없이 실행된다.
- 핵심 정상·실패 테스트가 통과한다.
- 마지막 한 번의 전체 테스트와 CI 전까지 리팩터링, 문서 미세 보정, Medium/Low 개선을 하지 않는다.
