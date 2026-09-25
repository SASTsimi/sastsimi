# Runtime과 실패 지점 재개

## 구현된 책임

`SimpleRuntime`은 다음 네 가지 일에 집중합니다.

1. 다음 stage 호출
2. 입력·출력 reference와 결과 저장
3. 실패한 stage부터 재시도
4. 현재 진행 위치와 안전한 오류 코드 기록

각 checkpoint에는 stage, 상태, 입력 reference, 입력 hash, 출력 reference, attempt,
오류 코드와 PoC·보고서 연결 정보가 저장됩니다. 상태는 `PENDING`, `RUNNING`,
`SUCCEEDED`, `BLOCKED`, `FAILED`입니다.

`resume`은 성공한 checkpoint의 입력과 version이 그대로면 결과를 재사용합니다. 입력이
달라졌거나 불완전한 PoC attempt가 확인되면 그 지점부터 뒤 결과만 무효화합니다.
예상하지 못한 예외는 재시도 가능한 `BLOCKED`로 저장하며 `FALSE`로 바꾸지 않습니다.

재시도 가능한 오류는 LLM 복구 결정으로 도구 재시도, 생성 입력 재작성 또는 일회용
Docker 환경 재구성을 최대 3회 수행합니다. 각 결정과 변경은 artifact와 checkpoint에
남고 대시보드에는 현재 복구 시도 횟수가 표시됩니다. 한 계보가 소진되면
`RECOVERY_EXHAUSTED`로 중단하지만 다른 독립 가설은 계속 처리합니다.

Technical Gate의 `REVISE`는 같은 가설의 최종 Verification을 다시 수행하도록
checkpoint를 준비합니다. 이전 Pro·Con과 PoC 결과는 exact reference로 전달하되,
새 Verification 출력이 확정되기 전까지 current 결과로 취급하지 않습니다.

## 코드 위치

- 실행기: `src/sastsimi/simple_runtime/runner.py`
- checkpoint 저장: `src/sastsimi/simple_runtime/store.py`
- 분석 단위 제어: `src/sastsimi/simple_runtime/application.py`
- 이전 실행 자료 연결: `src/sastsimi/simple_runtime/migration.py`
- 진행률 계산: `src/sastsimi/progress/projector.py`

## 지켜야 하는 계약

- `input_hash`는 exact `StoredDataRef` 목록에서 계산합니다.
- PoC 후보와 실행은 같은 attempt에 연결합니다.
- 늦게 도착한 이전 attempt 결과를 current checkpoint에 섞지 않습니다.
- `BLOCKED`는 재시도 가능 상태이고 `FAILED`는 해당 stage의 복구 불가 종료입니다.
- 이전 성공 결과의 입력이 바뀌면 뒤 checkpoint를 최신 결과처럼 재사용하지 않습니다.

## 현재 제한

프로세스가 종료된 뒤 외부 Docker 자원을 자동으로 모두 회수하는 범위와 여러 host의
분산 worker는 현재 구현 범위가 아닙니다. 남은 운영 검증은 후속 목록에서 관리합니다.
