# Runtime과 실패 지점 재개

## 구현된 책임

`SimpleRuntime`은 다음 네 가지 일에 집중합니다.

1. 다음 stage 호출
2. 입력·출력 reference와 결과 저장
3. 실패한 stage부터 재시도
4. 현재 진행 위치와 안전한 오류 코드 기록

각 checkpoint에는 stage, 상태, 입력 reference, 입력 hash, 출력 reference, attempt,
오류 코드와 PoC·보고서 연결 정보가 저장됩니다. Technical Gate에는 유효한 결정
(`ACCEPT`·`REVISE`·`REJECT`)과 별도의 Gate 수정 횟수도 저장합니다. 상태는 `PENDING`, `RUNNING`,
`SUCCEEDED`, `BLOCKED`, `FAILED`입니다.

`resume`은 성공한 checkpoint의 입력과 version이 그대로면 결과를 재사용합니다. 입력이
달라졌거나 불완전한 PoC attempt가 확인되면 그 지점부터 뒤 결과만 무효화합니다.
예상하지 못한 예외는 재시도 가능한 `BLOCKED`로 저장하며 `FALSE`로 바꾸지 않습니다.

재시도 가능한 오류는 LLM 복구 결정으로 도구 재시도, 생성 입력 재작성 또는 일회용
Docker 환경 재구성을 최대 3회 수행합니다. 각 결정과 변경은 artifact와 checkpoint에
남고 `status`와 대시보드에는 현재 복구 시도 횟수가 표시됩니다. 한 계보가 소진되면
`RECOVERY_EXHAUSTED`로 중단하지만 다른 독립 가설은 계속 처리합니다. 단,
복구 상한에 이른 마지막 PoC가 종료 코드 0으로 실행됐는데 해석이
`INCONCLUSIVE`라면 이는
실행 오류가 아니라 근거 부족이므로 해당 가설을 제보 불가로 종료합니다.
`POC_EXECUTION_FAILED`·Docker build·Provider 오류는 여전히 `BLOCKED` 또는
`FAILED`이며 미확정 판정으로 전환하지 않습니다. 재개 시 예전
`RECOVERY_EXHAUSTED` PoC 기록도 실행 성공·시도 ID·해석 artifact의 정확한 연결이
확인된 경우에만 미확정으로 정리합니다.

Technical Gate의 `REVISE`는 같은 Gate만 반복 호출하지 않습니다. 저장소가
Gate 피드백과 기존 실행 근거를 exact reference로 보존하면서 해당 가설의
`POC_CANDIDATE_DONE`을 새 시도로 원자적으로 준비하고, 이후 PoC 실행·최종
Verification·CWE·Gate를 다시 수행합니다. 준비된 Docker 이미지·recipe가 유효하면
재사용하지만 새 PoC 후보와 기존 실행 결과를 섞지 않습니다. Gate 수정 횟수는
PoC 스크립트 자체의 오류 복구 횟수와 분리되어 재개 후에도 유지됩니다.

Gate 결정은 최대 세 번입니다. `ACCEPT`는 이후 단계로 진행하고, `REJECT`는
제보 불가로 끝납니다. 세 번째 결정도 `REVISE`이면 가설을 `INCONCLUSIVE`로
끝내며 Finding·보고서를 만들지 않습니다. 이는 정상적인 분석 종료이며
`RECOVERY_EXHAUSTED`가 아닙니다. 반면 Provider·Docker·DB 오류나 잘못된 Gate
출력은 기존의 제한된 실행 오류 복구 경로를 따르며 분석을 `BLOCKED` 또는
`FAILED`로 남깁니다. 완료된 가설과 운영 오류가 섞이면 분석 전체도 완료가 아닙니다.

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
