# 04. 검증과 동적 재현

- **이 문서는 무엇을 설명하나요?** 취약점 가설의 찬성·반대 근거를 확인하고 필요하면 Docker에서 재현하는 절차를 설명합니다.
- **누가 읽어야 하나요?** 검증·반박·플레이북과 동적검증·Sandbox 담당자가 우선 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** `TRUE / FALSE / HOLD` 판정 기준, 추가 근거 요청과 재현 범위를 확인합니다.

`Verification`은 가설을 근거로 확인하는 과정이고 `verdict`는 그 기술 판정입니다. 자세한 용어는 [쉬운 용어집](../GLOSSARY.md)을 따릅니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## Verification의 목적

Verification Agent는 가설이 실제 코드 흐름과 실행 조건에서 성립하는지 검토하고 `TRUE | FALSE | HOLD`를 판정한다. 단순히 source와 sink의 존재를 확인하는 데서 끝나지 않고, 제한 조건·우회 후보·필요 능력·획득 능력·실질 영향의 상승 가능성을 함께 기록한다.

## 기본 검증 순서

1. 가설의 `workspace_id`, 연결된 `commit_id`, entity, location과 suspected path를 확인한다.
2. `CodeContextRequest`로 caller/callee, data flow, auth guard와 route 문맥을 필요한 만큼 조회한다.
3. observed fact와 assumption을 분리하고 각 `FalsificationQuestion.question_id`를 확인한다.
4. BASIC 또는 debate 모드로 supporting/counter evidence를 수집한다.
5. initial verdict와 unresolved condition을 만든다.
6. 정적 근거만으로 부족하고 안전하게 재현할 가치가 있으면 동적 재현을 요청한다.
7. 정적·동적 결과를 종합해 final verdict를 만든다.
8. REQUIRED/PROVIDED capability와 Research seed를 추출한다.

## 우회 인지 검증

각 가설은 다음 항목을 명시적으로 검토한다.

- validator, sanitizer와 canonicalization의 적용 순서 및 누락 경로
- authentication, authorization, role, tenancy와 ownership check
- alternate endpoint, serializer, background job, internal call과 configuration path
- 공격자가 먼저 가져야 하는 권한·상태·자산 접근: required capability
- 가설 성공으로 새로 얻게 되는 권한·동작·정보: provided capability
- 현재 impact를 더 큰 asset·privilege·scope로 확장할 후보
- 성립을 막는 restriction과 아직 확인하지 못한 조건

검증 중 발견한 별도 endpoint 우회, 새로운 sink, 새로운 권한 상승과 chain은 material claim이다. 작은 supporting subtask로 같은 주장만 확인하는 경우를 제외하고 새 hypothesis proposal로 Orchestration Agent에 반환해 독립 검증한다.

## Debate 정책

`verification_mode`는 구성 가능한 세 가지 값이다.

| 모드 | 동작 | 용도 |
|---|---|---|
| `BASIC` | Verification Agent가 직접 찬반 근거를 수집 | 명확하고 영향이 제한적인 가설, 예산 절감 실험 |
| `CONDITIONAL_DEBATE` | trigger 충족 시 Pro/Con을 독립 병렬 호출 | 기본값 |
| `ALWAYS_DEBATE` | 모든 유효 가설에 Pro/Con 호출 | 비교 평가 또는 고위험 운영 프로필 |

조건부 debate trigger 예시는 다음과 같다.

- 상충하는 정적 근거 또는 도구 결과
- 높은 impact나 높은 비용의 후속 조치
- initial `HOLD` 가능성
- 인증·인가·sanitizer 우회 확인 필요
- evidence가 한쪽 주장에만 치우침
- Technical Gate가 반박 또는 restriction 보강을 요구
- Research가 의미 있는 alternate path를 제안

named falsification으로 빠르게 반증되었거나, 명확한 duplicate/unsupported hypothesis이고, 추가 독립 검토의 예상 가치가 낮으며 예산이 부족할 때는 생략 사유를 기록하고 BASIC으로 종료할 수 있다.

Pro와 Con은 context contamination을 막기 위해 항상 서로 다른 `NEW` session에서 시작한다. 각 호출은 `requested_by=PRO | CON`, 같은 역할의 `LLMCallSpec.agent_role`, `session_mode=NEW`, `session_policy=NEW`, `parent_session_ref=null`과 서로 다른 `llm_call_id`·action·decision·실제 session을 사용한다. retry와 failover도 상대 역할의 session·output·decision을 이어받지 않고 같은 역할의 새 `NEW` session으로 실행한다. 동일한 `workspace_id`·`commit_id`와 가설·공통 코드 fact는 받지만 상대 Agent의 결론은 입력받지 않는다. Verification Agent만 두 결과와 직접 확인한 사실을 종합한다.

## Debate 효과 측정

각 가설에 다음을 저장해 조건부 정책을 향후 평가할 수 있게 한다.

- 모드와 trigger/skip reason
- Pro/Con 및 종합에 사용한 token과 wall-clock time
- debate 전후 verdict와 confidence 변화
- `HOLD` 해소 여부
- false-positive 감소 후보
- 새 bypass·restriction·falsification 발견 여부

이는 조건부 debate가 항상 더 정확하거나 저렴하다는 주장이 아니다. 동일 corpus에 대한 비교 평가가 있기 전까지 기본 정책은 검토 대상이다.

## 판정 의미

- `TRUE`: 현재 가설의 핵심 exploit path와 필요한 조건이 evidence로 지지된다. restriction이 있으면 그대로 보존한다.
- `FALSE`: 가설의 필수 조건을 묻는 named falsification 하나 이상이 실제 근거로 `DISPROVED`되었다. 다른 path 가능성까지 부정하지 않는다.
- `HOLD`: 핵심 정보·환경·재현 조건이 부족하거나 상충해 현재 증거로 결론을 낼 수 없다.

`HOLD`는 실패가 아니다. 누락 정보, 필요한 capability와 다음 validation을 구조화해 Primitive DB와 Research에 전달한다.

최종 결과는 등록 가설의 모든 반증 질문에 `DISPROVED | NOT_DISPROVED | INCONCLUSIVE` 중 하나를 기록한다. `DISPROVED`에는 실제 `evidence_refs`가 필요하고, `NOT_DISPROVED`는 가설이 참이라는 증거로 승격하지 않는다. `FALSE`는 적어도 하나의 근거 있는 `DISPROVED` 결과와 그 `question_id`를 설명하는 판정 이유가 있을 때만 허용한다. 오류·timeout·누락만으로는 `DISPROVED`나 `FALSE`를 만들지 않는다.

## Docker 동적 재현

동적 검증은 정적 판단을 대체하지 않고 특정 가설의 조건을 제한된 환경에서 확인한다.

### LIMITED_REPRO

- 한 sanitizer, auth guard, sink 도달 또는 작은 함수 경로 확인
- 초기 verdict의 핵심 불확실성을 최소 실행으로 해소
- 외부 통신·privilege·resource를 최소화

### FULL_REPRO

- 해당 취약점 유형이 end-to-end 재현을 요구하고 안전한 환경이 준비된 경우
- container 내부에 대상과 의존성을 구성하고 공격 입력부터 observable effect까지 재현
- 재현 명령·환경·입력·관찰 결과·제한을 PoC artifact로 정리

### 실행 경계

- 같은 `workspace_id`와 `commit_id`, 승인된 Docker image/digest 사용
- Docker build와 실행은 분석용 `CodeWorkspace`를 직접 수정하지 않고 sandbox 내부 복사본에서 수행
- 기본 network deny, resource/time/process 제한, non-root와 read-only mount 우선
- host socket, host secret, production credential과 범위 밖 target 접근 금지
- 동적 결과의 exit code, stdout/stderr reference, artifact hash와 hypothesis 연결 저장
- 환경 구축 실패와 취약점 반증을 구분

### 동적 재현 상태와 실제 반증

동적 재현 상태는 `NOT_REQUESTED | RUNNING | SUCCEEDED | PARTIAL | FAILED | BLOCKED | CANCELLED`다. 실행이 끝난 결과는 `DynamicReproductionResult.status`에 `SUCCEEDED | PARTIAL | FAILED | BLOCKED | CANCELLED` 중 하나를 기록한다.

- 필수 환경을 만들지 못해 대상 애플리케이션이나 관련 공격 경로를 실행하지 못하면 `FAILED + ENVIRONMENT_SETUP`이다.
- 공격 경로를 일부 실행하고 신뢰할 수 있는 관측을 하나 이상 얻었지만 운영환경 차이 등으로 전체 확인이 부족하면 `PARTIAL + NONE`이다. 이때 `hypothesis_outcome=INCONCLUSIVE`이고 `hypothesis_evidence_refs`와 `limitations`가 각각 하나 이상 있어야 한다.
- `SUCCEEDED`는 계획한 필수 단계와 관측을 끝냈다는 실행 상태다. 관측이 가설을 지지했는지, 반증했는지, 결론을 주지 못했는지는 `hypothesis_outcome`에 따로 기록한다.
- `hypothesis_outcome`은 `SUPPORTED | DISPROVED | INCONCLUSIVE`이며 Verification verdict가 아니다. `SUPPORTED | DISPROVED`는 실제 관측을 가리키는 `hypothesis_evidence_refs`가 필요하다.
- `DISPROVED`일 때만 `hypothesis_disproved=true`와 비어 있지 않은 `disproof_evidence_refs`를 사용한다. 반증 근거는 일반 가설 근거 목록에도 포함한다.
- `FAILED | BLOCKED | CANCELLED`, 실행하지 못함, 빈 출력과 exit code만으로는 `DISPROVED`, `hypothesis_disproved=true` 또는 `FALSE`를 만들 수 없다.
- Sandbox는 outcome까지만 기록한다. Verification Agent가 limitations와 정적·동적·찬반 근거를 함께 보고 최종 `TRUE | FALSE | HOLD`를 결정한다.

## VerificationResult에 남길 정보

최종 결과는 verdict뿐 아니라 질문별 `FalsificationResult`, supporting/counter evidence, restrictions, bypass candidates, required/provided capabilities, impact escalation candidates, unresolved conditions, debate 지표와 동적 재현 reference를 포함한다. 이 정보가 Primitive DB, Research, CWE와 두 Gate의 입력이 된다.

supporting/counter evidence는 자유 형식 문자열이 아니라 `EvidenceClaim`으로 기록한다. 각 claim은 작성 역할, 실제 저장 근거와 코드 주장에 필요한 현재 workspace·commit의 위치를 포함한다. 우회·대체 경로·영향 확대 후보는 `CandidateRef(candidate_state=UNVALIDATED)`로 구분하고 새 material claim이면 별도 가설로 재검증한다. debate token·시간과 판정 변화는 `VerificationMetrics`에 저장하며 provider가 token을 제공하지 않으면 값을 추정하지 않고 `null`로 둔다.
