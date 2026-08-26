# 검증과 동적 재현

## 위치·우회 중심 Verification

Verification Agent는 가설의 entity/location/path에서 필요한 caller, callee, data-flow, auth guard와 route를 조회한다. observed fact와 assumption을 분리하고 validator·sanitizer·인증·인가·ownership의 restriction과 우회 후보, alternate path, required/provided capability와 impact 상승 후보를 기록한다.

새 endpoint, sink, 권한 경계 또는 영향은 새 가설로 다시 검증한다.

## Debate 모드

- `BASIC`: Verification이 직접 찬반을 검토
- `CONDITIONAL_DEBATE`: 충돌·고영향·HOLD·우회·근거 편향·Gate 요청 때 Pro/Con 호출; 기본값
- `ALWAYS_DEBATE`: 비교 평가나 별도 운영 profile

Pro와 Con은 서로의 결과를 받지 않는 별도 NEW session이다. trigger/skip reason, token·시간, verdict 변화, HOLD 해소, 오탐 감소 후보와 bypass 발견을 기록한다.

## 판정과 동적 재현

- `TRUE`: 명시된 경로와 전제가 evidence로 지지됨
- `FALSE`: named falsification이 가설을 반증함
- `HOLD`: 핵심 문맥·환경·조건이 부족하거나 충돌함

| 모드 | 목적 |
|---|---|
| `NOT_REQUIRED` | 정적 근거로 현재 판정 가능 |
| `LIMITED_REPRO` | guard, sink, 권한 조건 등 작은 질문 확인 |
| `FULL_REPRO` | 안전한 end-to-end 재현과 PoC |

Docker는 ephemeral/non-root, network default-deny와 자원·시간 제한을 사용한다. 실행 환경 실패를 `FALSE`로 바꾸지 않는다. 상세 내용은 [검증과 동적 재현](../04-verification-and-dynamic-reproduction.md)을 따른다.
