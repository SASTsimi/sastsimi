# 검증과 동적 재현

## 쉽게 말하면

검증 Agent가 코드와 찬성·반대 근거를 모아 가설을 판단하고, 정적 근거만으로 부족할 때 격리된 Docker 환경에서 제한적으로 재현하는 과정입니다.

**상세 기준:** [04. 검증과 동적 재현](../04-verification-and-dynamic-reproduction.md)

모르는 단어는 [쉬운 용어집](../../GLOSSARY.md)에서 확인하세요.

## 코드 위치와 우회를 함께 확인하는 검증

검증 Agent는 가설에 연결된 코드 요소·위치·경로에서 호출하는 함수, 호출되는 함수, 데이터 흐름, 인증·권한 검사와 요청 경로를 조회합니다. 실제로 확인한 사실과 아직 확인하지 못한 가정을 나눕니다. 입력 검사·안전 처리·인증·권한·소유권이 공격을 막는 조건인지, 우회 경로가 있는지, 다른 공격에 필요한 능력과 영향 확대 후보가 있는지 기록합니다.

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

Docker는 ephemeral/non-root, network default-deny와 자원·시간 제한을 사용한다. 동적 상태 `FAILED | BLOCKED | CANCELLED`는 가설 반증이 아니다. 실제 반증은 `hypothesis_disproved: true`와 관측 근거 `disproof_evidence_refs`가 함께 있어야 한다. 상세 내용은 [검증과 동적 재현](../04-verification-and-dynamic-reproduction.md)을 따른다.
