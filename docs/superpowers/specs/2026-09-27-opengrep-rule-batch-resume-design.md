# OpenGrep 규칙 배치와 재개 설계

## 목적과 범위

공개 `sastsimi analyze`/`resume`의 SimpleRuntime 정적 분석에서 큰 저장소
검사가 시간 초과되면 완료된 규칙 묶음을 재검사하지 않고 이어서 실행한다.
현재 PR #202에서 Dify의 고정 커밋
`8387590ace4a094de812b7847fc6a4c3a27cd52b`로 시험하되 Dify 전용
규칙·경로 제외는 넣지 않는다. 기존 Agent, 프롬프트, 다른 정적 도구, 보고서,
Production의 파일 배치 어댑터는 변경하지 않는다.

원본 `rules.yml`의 모든 고유 규칙 ID가 정확히 한 묶음에 속하고, 모든 묶음이
원래와 동일한 저장소 루트에서 성공한 경우에만 `STATIC_DONE`을 완료한다.
범위 유지란 새 경로 제외를 더하지 않는다는 뜻이다. OpenGrep의 기존 ignore
정책이나 후속 Agent의 최대 500개 스니펫 제한을 전 파일 검증이라고 주장하지
않는다.

## 실행 방식

원본 YAML의 규칙 ID를 순서대로 읽고 중복·형식을 검증한 뒤 고정 크기의
연속 묶음으로 나눈다. 매 호출은 원본 config와 동일한 workspace 루트를
사용하며 `--no-rewrite-rule-ids`와 묶음 밖 ID를 나열한 반복
`--exclude-rule`만 추가한다. 구성 파일 재생성은 ID/config 의미를 바꿀
수 있고, 경로 분할은 ignore·상대 경로 의미를 바꿀 수 있어 채택하지 않는다.
단순 시간 한도 증가는 실패한 전체 스캔을 매번 처음부터 반복한다.

묶음은 순차 실행한다. 병렬로 실행하면 OpenGrep의 기본 작업자끼리 CPU와
메모리를 과다 사용할 수 있다. 묶음 크기와 계획 버전은 코드 상수로 두어
사용자 설정을 늘리지 않는다. 분할은 진행 보존과 문제 규칙 격리를 위한
것이며 전체 처리시간 단축이나 Dify 완료를 보장하지 않는다.

## 완료 기록과 재개

계획 fingerprint는 계획 버전, 원본 규칙 파일 SHA-256, 순서 있는 전체
규칙 ID, OpenGrep의 설정 버전·실행 파일 SHA-256으로 만든다. 기록의 키에는
분석 ID, 저장소 URL, workspace ID, exact commit, 계획 fingerprint,
묶음 ID 목록을 포함한다. 재사용 전 ready marker, 실제 checkout HEAD,
작업트리 상태를 확인한다. 런타임 marker 이외의 수정·비추적 파일이 있으면
캐시 재사용을 중단한다. 이미 성공한 `STATIC_DONE`은 기존 불변 snapshot
으로 유지하며 새로운 규칙·도구로 재분석하려면 새 분석을 시작한다.

각 묶음이 허용 종료 코드로 끝나고 JSON 구조, 결과 규칙 ID의 묶음 소속,
실행 오류와 출력 해시를 확인한 뒤 원본 JSON을 content-addressed
artifact에 저장한다. 별도 SQLite 진행 테이블에 키와 artifact 참조를
원자적으로 기록한다. DB에 없는 임시 출력은 재개에 쓰지 않는다. 재개 때
정확한 키, artifact 해시·형식·규칙 ID를 다시 검증하고 일치하는 묶음만
건너뛴다. 손상된 기록은 해당 묶음만 재실행하고 다른 유효 묶음은 보존한다.
동시 실행은 기존 analysis lease로 차단한다.

묶음별 출력은 `process-output/simple-static/<analysis_id>/` 아래 다른
파일에 기록하고, 다시 실행할 해당 묶음의 오래된 파일만 제거한다. 모든
묶음이 완료되면 원본 `results`를 중복 제거 없이 결정적인 순서로 합친
aggregate JSON을 만든다. aggregate에는 원본 artifact 참조, 규칙 ID,
scanned/skipped/error 메타데이터와 500개 스니펫 절단 여부를 기록한다.
서로 다른 규칙의 동일 위치 결과는 별개로 보존한다. 기존 static bundle의
OpenGrep 참조는 aggregate ref로 유지하고 후속 파서는 최상위 `results`
를 계속 읽는다.

## 오류와 한도

잘못된 YAML, 중복 ID, CLI 선택 오류, 비정상 종료, 누락·손상된 JSON,
예상 밖 rule ID 또는 도구가 보고한 실행 오류는 완료로 기록하지 않는다.
정적 단계는 `BLOCKED`가 되고 가설·Finding·보고서는 생성하지 않는다.
무해한 ignore/skip 정보는 묶음별로 보존하되 전체 파일 검사를 주장하지
않는다.

현재 한 번의 OpenGrep 호출 상한인 프로필 한도와 1시간 중 작은 값을
한 번의 정적 단계 호출에서 모든 묶음이 나눠 사용한다. 묶음마다 새 1시간을
부여하지 않는다. timeout/cancel은 기존 process-tree 종료 경로를 쓴다.
기존 복구 횟수·예산 제한은 유지하고, 소진 시 `COMPLETE`로 위장하지 않고
`BLOCKED`로 보고한다.

## 검증과 실제 시험

모의 프로세스 테스트로 규칙 전수·무중복 배정, 명령 인자, 결과 합치기,
중간 실패 뒤 완료 묶음 재사용, fingerprint 변경·캐시 손상, timeout/cancel,
잘못된 JSON·rule ID·실행 오류를 검증한다. 설치된 OpenGrep이 있으면 작은
fixture에서 배치 합집합과 동일 옵션의 단일 스캔을 비교한다. 관련 및 전체
테스트, 문서 검사를 실행한다.

PR #202에 범용 변경과 README/운영 문서를 반영하고 Dify 고정 커밋으로
다시 실행한다. static 완료 여부, 재사용 묶음, 잔여 오류 및 분석 최종
상태를 구분해 보고한다. Codex `gpt-6-sol` 설정을 유지하며 승인되지 않은
LLM 예산 증액은 하지 않는다.
