# ADR-017. Technical Gate의 종료 판정과 PoC 보완

- 상태: `ACCEPTED`
- 기록일: 2026-09-26
- 영향 범위: `simple_runtime`의 Gate·checkpoint·runner, 진행률, CLI, 대시보드, 보고서

## 배경

Technical Gate가 실제 재현 경로와 소스 흐름 보강을 요청해도 과거 재시도는 최종
Verification만 다시 수행했습니다. 같은 근거 부족을 Gate가 재차 지적하면 이를
실행 오류인 `RECOVERY_EXHAUSTED`로 처리해 분석 전체가 `BLOCKED`로 남았습니다.
분석 근거가 부족한 결과와 Provider·Docker 같은 운영 실패는 구분해야 합니다.

## 결정

유효한 `ACCEPT`·`REVISE`·`REJECT`를 실행 상태와 별도로 checkpoint와 artifact에
저장합니다. `ACCEPT`일 때만 Scope Gate, TRUE Primitive, Finding, 보고서로 진행합니다.
`REJECT`는 해당 가설을 제보 불가로 끝냅니다. `REVISE`는 정확한 Gate 요청과 고정
commit의 제한된 source 근거를 전달해 PoC 후보부터 Docker 실행·최종 Verification·
CWE·Gate를 다시 수행합니다. 재시작은 하위 checkpoint를 원자적으로 무효화하며
새 PoC 후보를 이전 실행 결과와 결합하지 않습니다.

Gate 결정은 가설당 최대 세 번으로 제한하고 수정 횟수를 PoC 스크립트 복구 횟수와
별도로 영속화합니다. 세 번째 결정도 `REVISE`이면 `INCONCLUSIVE`로 종료합니다.
또한 복구 상한에 이른 마지막 PoC가 Docker 안에서 종료 코드 0으로 실행됐지만
해석 결과가 `INCONCLUSIVE`이면 해당 가설을 `HOLD`·제보 불가로 종료합니다. 실행 자체의
실패와 timeout은 이 조건에 포함하지 않습니다.
`REJECT`와 `INCONCLUSIVE`는 Finding·보고서가 없는 분석상 종료입니다. 다른 가설도
모두 종료하고 운영 오류가 없을 때 분석은 `COMPLETE`가 되지만 이는 취약점 발견,
반증 또는 외부 제보 승인을 의미하지 않습니다. 실행 실패, 잘못된 출력, 인증·Docker·
DB 문제는 기존 오류 코드와 `BLOCKED`/`FAILED`로 남으며 `INCONCLUSIVE`로
바꾸지 않습니다.

## 결과와 경계

CLI, 진행률, 대시보드는 같은 Gate 종료 규칙을 사용합니다. 현재 Gate의 checkpoint와
artifact가 모두 `ACCEPT`가 아니면 과거 Finding·보고서 파일이 남아 있어도 최신
결과로 노출하지 않습니다. 완료된 Agent·PoC 작업은 `resume`에서 중복 실행하지
않습니다. 일반적인 과거 분석 기록을 소급 변경하지 않습니다. 다만 명시적
`resume` 시 과거 PoC의 `RECOVERY_EXHAUSTED` 기록이 세 번째 실행 성공과
`INCONCLUSIVE` 해석을 같은 attempt·정확한 artifact 참조로 증명하면 그
checkpoint만 미확정으로 정리합니다. 다른 오류는 그대로 유지합니다.

이 결정은 [ADR-016](./ADR-016-maintainable-workflow-packages.md)에 적힌 과거
Technical `REVISE` 실행 경로 설명을 현재 `simple_runtime`에 한해 대체합니다.
어떤 저장소든 외부 서비스와 실행 환경에 관계없이 `COMPLETE`가 된다는 보장은
하지 않습니다.
