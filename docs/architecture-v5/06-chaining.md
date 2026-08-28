# 06. Primitive DB, Research와 chaining

- **이 문서는 무엇을 설명하나요?** 보류된 가설의 부족 조건과 확인된 공격 능력을 연결해 새 가설을 만드는 방법을 설명합니다.
- **누가 읽어야 하나요?** LLM 탐색·체이닝, 검증과 데이터·평가 담당자가 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** 무엇을 저장·연결할지와 깊이·횟수·token·시간 중단 기준을 확인합니다.

`Primitive`는 연계 공격의 필요 조건 또는 확인된 능력이고, `Research`는 우회·영향·연계 가능성을 추가로 조사하는 작업입니다. 자세한 용어는 [쉬운 용어집](../GLOSSARY.md)을 따릅니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## 목적

단일 취약점의 restriction을 다른 검증 결과가 제공하는 capability로 충족하거나, 검증된 취약점의 우회·대체 경로·실질 영향을 확장할 수 있는지를 탐색한다. Primitive DB와 Research Agent는 후보를 만들 뿐 chain Finding을 직접 확정하지 않는다.

## Primitive 모델

Primitive는 공격 경로에서 필요하거나 제공되는 최소 능력을 표현한다.

```yaml
primitive:
  primitive_id: prim-001
  primitive_type: object_identifier_read
  target:
    workspace_id: ws-001
    asset: order-service
    entity_refs: [entity:OrderController.update]
    privilege_level: authenticated_user
  status: REQUIRED | PROVIDED
  source_hypothesis_id: hyp-001
  evidence_refs: []
  confidence: MEDIUM
  description: ability to read an internal order identifier
```

vocabulary는 `identifier_read`, `request_forge`, `role_assume`, `code_execute` 같은 작은 초기 예시로 시작할 수 있으나 이 문서는 완전한 ontology를 고정하지 않는다. 구현 전 corpus로 명칭·포함 관계·matching 규칙을 검토한다.

### HeldHypothesis

`HOLD` 결과와 결론을 막는 조건을 저장한다. 각 조건은 가능한 경우 REQUIRED Primitive로 표현하며 미표현 조건도 잃지 않는다.

### ConfirmedCapability

`TRUE` 결과가 실제로 제공하는 능력을 PROVIDED Primitive로 저장한다. `TRUE` 전체가 공개 Finding이라는 의미는 아니며 restriction과 evidence scope를 함께 유지한다.

Primitive DB는 worker가 항목을 꺼내 실행하는 queue가 아니다. hypothesis lifecycle은 Orchestration Agent가 관리하고 DB는 호환 후보를 찾는 분석 인덱스다.

## matching 원칙

REQUIRED와 PROVIDED의 문자열이 같다는 이유만으로 연결하지 않는다. 최소한 다음을 확인한다.

- 동일한 `workspace_id`와 `commit_id`
- 같은 asset 또는 설명 가능한 asset 간 이동
- entity/endpoint와 데이터 형식의 호환성
- provided privilege가 required privilege를 충족하는지
- 공격 순서상 capability가 requirement보다 먼저 획득되는지
- restriction이 결합 후에도 유지되는지
- 기존 chain과 normalized fingerprint가 중복되지 않는지

match 결과는 `PrimitiveMatchCandidate`이며 새 `ChainedHypothesisProposal`을 만드는 입력이다. match 자체는 verdict, Finding 또는 impact 확정이 아니다.

## Research Agent

### 호출 조건

- final `TRUE`: 우회 경로, alternate path, impact 상승과 PROVIDED primitive 탐색
- final `HOLD`: restriction 해소와 REQUIRED/PROVIDED match 탐색
- Technical Gate의 restriction·누락 보완 요청
- 기술적으로 성립하지만 실질 impact가 낮아 확장 가능성을 확인할 가치가 있는 경우
- Primitive DB가 scope-compatible match 후보를 찾은 경우

예산이나 명확한 non-material condition 때문에 호출하지 않으면 skip reason을 기록한다.

### 입력과 출력

Research는 현재 hypothesis/result, 위치 기반 문맥, Primitive 후보와 명시된 목적을 받는다. 출력은 다음 후보를 구분한다.

- validator/auth/authorization restriction의 bypass candidate
- alternate endpoint·input·call path
- 실제 impact escalation candidate
- scope-compatible primitive match
- 새로 검증할 chained hypothesis proposal
- 추가 정적·동적 validation request
- 의미 있는 확장이 없다는 `no_material_extension_reason`

### 금지 권한

Research Agent는 기존 verdict를 변경하거나 Finding을 생성하지 않는다. CWE를 확정하거나 어느 Gate도 통과시키지 않으며 Reporter를 호출하거나 공개할 수 없다. Research의 material claim은 16단계에서 Orchestration Agent에 새 가설로 반환되어 8단계부터 검증한다.

## TRUE와 HOLD 처리

```text
TRUE -> ConfirmedCapability(PROVIDED) -> match Held REQUIRED
                                      -> Research -> chained proposal

HOLD -> HeldHypothesis(REQUIRED) -> match Confirmed PROVIDED
                                  -> Research -> chained proposal

chained proposal -> Orchestration -> schema validation -> Verification 전체 반복
```

예를 들어 `TRUE` A가 일반 사용자에게 내부 객체 ID 열람 능력을 제공하고, `HOLD` B가 유효 ID를 알 때 타인 객체를 수정할 가능성을 가진다면 A의 PROVIDED와 B의 REQUIRED를 연결한 새 가설을 만든다. B를 자동 `TRUE`로 바꾸지 않는다.

## 새 주장과 subtask 구분

- 같은 가설의 기존 경로에서 한 guard의 실제 동작을 확인하는 작은 조회·재현은 Verification subtask다.
- 새로운 endpoint, sink, 권한 경계, 공격 단계 또는 별도 영향은 새 hypothesis다.
- Research가 제안한 영향 상승은 재검증되기 전 보고서의 실제 impact로 사용하지 않는다.
- Technical Gate revision에서 발견한 새 공격 주장은 기존 revision에 몰래 합치지 않는다.

## 확장 제한과 순환 방지

모든 run은 다음 제한을 설정한다.

- maximum chain depth
- 전체 및 parent당 파생 가설 수
- Research 호출 수
- 누적 LLM token과 wall-clock time
- sandbox 횟수와 실행 시간
- normalized hypothesis/primitive-match fingerprint 중복 횟수
- 동일 ancestor/capability cycle

한도 도달은 `FALSE`가 아니다. 생성하지 않은 후보, 제한 값과 종료 이유를 결과에 기록한다. `A → B → A`처럼 새 사실이나 capability 없이 순환하는 후보와 이미 같은 조건으로 반증된 후보는 다시 생성하지 않는다.

## 사람에게 보이는 결과

사람은 confirmed capability, held requirement, match 이유, Research 후보, 생성된 child hypothesis와 검증 여부를 구분해서 본다. 미검증 후보는 최종 Finding이나 PoC 주장에 섞이지 않는다.
