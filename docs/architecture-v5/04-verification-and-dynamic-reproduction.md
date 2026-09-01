# 04. 검증과 동적 재현

- **이 문서는 무엇을 설명하나요?** 취약점 가설의 찬성·반대 근거를 확인하고 필요하면 Docker에서 재현하는 절차를 설명합니다.
- **누가 읽어야 하나요?** 검증·반박·플레이북과 동적검증·Sandbox 담당자가 우선 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** `TRUE / FALSE / HOLD` 판정 기준, 추가 근거 요청과 재현 범위를 확인합니다.

`Verification`은 가설을 근거로 확인하는 과정이고 `verdict`는 그 기술 판정입니다. 자세한 용어는 [쉬운 용어집](../GLOSSARY.md)을 따릅니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## Verification의 목적과 제어권

Verification Agent는 배정받은 한 가설 안에서 검증 흐름 전체를 소유한다. 가설이 실제 코드 흐름과 실행 조건에서 성립하는지 검토하고 `TRUE | FALSE | HOLD`를 판정하며, 필요한 Context·Pro/Con·동적 재현·보완 작업과 Gate 제출 시점을 선택한다. 제한 조건·우회 후보·필요 능력·제공 가능 능력·실질 영향의 상승 가능성도 함께 기록한다.

이 제어권은 실행 허가 권한이 아니다. Verification이 다음 작업을 제안하면 비-LLM Runtime Validator가 `ActionRequest`, exact revision, 역할, 상태, 예산과 provider/session을 확인한다. `RUN_SANDBOX`가 허가된 뒤에는 Sandbox Controller가 Docker 세부 정책을 검사하며, Controller가 승인한 exact 계획만 Sandbox Runner가 실행한다.

## 기본 검증 순서

1. 배정된 가설의 `workspace_id`, `commit_id`, entity, location과 suspected path를 확인한다.
2. `CodeContextRequest`로 caller/callee, data flow, auth guard와 route 문맥을 필요한 만큼 조회한다.
3. observed fact와 assumption을 분리하고 각 `FalsificationQuestion.question_id`를 확인한다.
4. 운영 분석이면 Pro/Con Agent를 서로 독립된 NEW session으로 병렬 호출해 supporting/counter evidence를 모두 수집한다. BASIC 또는 조건부 debate는 격리된 평가 실행에서만 선택한다.
5. initial verdict와 unresolved condition을 만든다.
6. 정적 근거만으로 부족하고 안전하게 재현할 가치가 있으면 `LIMITED_REPRO | FULL_REPRO`를 요청한다.
7. 정적·찬반·동적 결과를 종합해 final verdict를 만든다.
8. HOLD면 REQUIRED Primitive 후보를, TRUE면 Gate 통과 뒤 등록할 PROVIDED Primitive 후보를 기록한다. FALSE는 Primitive 후보를 만들지 않는다.
9. 새 endpoint·sink·권한 경계·공격 단계·독립 impact를 발견하면 `HypothesisProposal(origin=VERIFICATION)`으로 분리한다.
10. TRUE의 CWE labeling을 조정하고 Technical Evidence Gate를 요청한다. `REVISE`면 같은 Verification owner가 보완한 새 revision으로 다시 제출한다.
11. HOLD는 즉시 Chaining으로 넘길 수 있고, TRUE는 두 Gate를 정상 통과한 exact revision만 Chaining으로 넘길 수 있다.

## 우회 인지 검증

각 가설은 다음 항목을 명시적으로 검토한다.

- validator, sanitizer와 canonicalization의 적용 순서 및 누락 경로
- authentication, authorization, role, tenancy와 ownership check
- alternate endpoint, serializer, background job, internal call과 configuration path
- 공격자가 먼저 가져야 하는 권한·상태·자산 접근: required capability
- 가설 성공으로 새로 얻게 되는 권한·동작·정보: provided capability
- 현재 impact를 더 큰 asset·privilege·scope로 확장할 후보
- 성립을 막는 restriction과 아직 확인하지 못한 조건

검증 중 발견한 별도 endpoint 우회, 새로운 sink, 새로운 권한 상승과 독립 impact path는 material claim이다. 작은 supporting subtask로 같은 주장만 확인하는 경우를 제외하고 `HypothesisProposal(origin=VERIFICATION)`으로 만든다. trusted runtime이 schema·semantic·중복·깊이·예산을 확인해 전역 등록하고, Orchestration Agent가 새 Verification을 배정한다. Verification은 `hypothesis_id`를 직접 발급하거나 child를 자동 TRUE로 만들지 않는다.

## Debate 정책

`verification_mode`는 구성 가능한 세 가지 값이다.

| 모드 | 동작 | 용도 |
|---|---|---|
| `BASIC` | Verification Agent가 직접 찬반 근거를 수집 | 격리된 비교 평가 전용 |
| `CONDITIONAL_DEBATE` | trigger 충족 시 Pro/Con을 독립 병렬 호출 | 격리된 비교 평가 전용 |
| `ALWAYS_DEBATE` | 모든 유효 가설에 Pro/Con 호출 | 운영(`PRODUCTION`)의 유일한 허용값 |

`AnalysisRunState.purpose=PRODUCTION`에서는 `verification_mode=ALWAYS_DEBATE`만 허용한다. `purpose=EVALUATION`에서만 `BASIC | CONDITIONAL_DEBATE`를 사용할 수 있으며, 그 결과는 품질·비용 비교 자료일 뿐 Gate·Primitive admission·Reporter 입력으로 사용할 수 없다.

조건부 debate trigger 예시는 다음과 같다.

- 상충하는 정적 근거 또는 도구 결과
- 높은 impact나 높은 비용의 후속 조치
- initial `HOLD` 가능성
- 인증·인가·sanitizer 우회 확인 필요
- evidence가 한쪽 주장에만 치우침
- Technical Gate가 반박 또는 restriction 보강을 요구
- 같은 Verification의 이전 검토나 Technical `REVISE`가 의미 있는 alternate path 확인을 요구

운영 분석에서는 named falsification으로 빠르게 반증될 가능성이 있거나 duplicate/unsupported 후보여도 Pro/Con을 생략하지 않는다. 예산이 부족하면 `BUDGET_EXCEEDED`로 현재 Verification work를 중단하며 Pro/Con을 생략한 final verdict를 만들지 않는다. 새 예산이 승인된 새 work에서만 이어서 검증한다.

Pro와 Con은 context contamination을 막기 위해 항상 서로 다른 `NEW` session에서 시작한다. 각 호출은 `requested_by=PRO | CON`, 같은 역할의 `LLMCallSpec.agent_role`, `session_mode=NEW`, `session_policy=NEW`, `parent_session_ref=null`과 서로 다른 `llm_call_id`·action·decision·실제 session을 사용한다. retry와 failover도 상대 역할의 session·output·decision을 이어받지 않고 같은 역할의 새 `NEW` session으로 실행한다. 동일한 `workspace_id`·`commit_id`와 가설·공통 코드 fact는 받지만 상대 Agent의 결론은 입력받지 않는다. Verification Agent만 두 결과와 직접 확인한 사실을 종합한다.

## Debate 효과 측정

각 가설에 다음을 저장해 조건부 정책을 향후 평가할 수 있게 한다.

- 모드와 trigger/skip reason
- Pro/Con 및 종합에 사용한 token과 wall-clock time
- debate 전후 verdict와 confidence 변화
- `HOLD` 해소 여부
- false-positive 감소 후보
- 새 bypass·restriction·falsification 발견 여부

`BASIC | CONDITIONAL_DEBATE`가 더 정확하거나 저렴한지는 동일 corpus의 격리된 평가에서만 측정한다. 평가 결과가 운영 기본 변경의 합격선을 통과하고 별도 설계 결정을 남기기 전까지 운영은 `ALWAYS_DEBATE`를 유지한다.

## 판정 의미

- `TRUE`: 현재 가설의 핵심 exploit path와 필요한 조건이 evidence로 지지된다. restriction이 있으면 그대로 보존한다.
- `FALSE`: 가설의 필수 조건을 묻는 named falsification 하나 이상이 실제 근거로 `DISPROVED`되었다. 다른 path 가능성까지 부정하지 않는다.
- `HOLD`: 핵심 정보·환경·재현 조건이 부족하거나 상충해 현재 증거로 결론을 낼 수 없다.

`HOLD`는 실패가 아니다. 누락 정보와 필요한 capability를 구조화해 exact final Verification revision에 연결된 REQUIRED Primitive로 즉시 저장하고 Chaining Agent의 matching 입력으로 사용할 수 있다. HOLD는 두 Gate를 거치지 않으며 PROVIDED 능력이나 확인된 취약점으로 승격되지 않는다.

`TRUE`도 판정 직후에는 Chaining 입력이 아니다. 현재 revision이 Technical `ACCEPT`와 Rule Scope의 정상 통과 조건을 모두 만족한 뒤에만 PROVIDED Primitive가 된다. `FALSE`는 terminal internal result이며 REQUIRED/PROVIDED Primitive와 Chaining work를 만들지 않는다.

최종 결과는 등록 가설의 모든 반증 질문에 `DISPROVED | NOT_DISPROVED | INCONCLUSIVE` 중 하나를 기록한다. `DISPROVED`에는 실제 `evidence_refs`가 필요하고, `NOT_DISPROVED`는 가설이 참이라는 증거로 승격하지 않는다. `FALSE`는 적어도 하나의 근거 있는 `DISPROVED` 결과와 그 `question_id`를 설명하는 판정 이유가 있을 때만 허용한다. 오류·timeout·누락만으로는 `DISPROVED`나 `FALSE`를 만들지 않는다.

## Docker 동적 재현

동적 검증은 정적 판단을 대체하지 않고 특정 가설의 조건을 제한된 환경에서 확인한다.

Verification Agent가 `NOT_REQUIRED | LIMITED_REPRO | FULL_REPRO`를 결정한다. 동적 재현이 필요하면 Verification이 필요한 역할·권한·인증 방식·데이터·DB/service·fixture/mock·버전·Health Check를 exact `EnvironmentRequirements`로 먼저 저장한다. 이어 mode·가설·요구사항·단계·명령·공격 입력·cleanup 정책을 고정한 exact `ReproductionPlan` 후보를 생산하고, trusted runtime이 두 `SAVE_RESULT`에서 schema·reference·권한·예산을 검사해 `COMMITTED`한다. R7의 Controller·Runner·Result Assembler는 요구사항·mode·계획을 다시 선택하거나 수정하지 않고, 허가된 계획의 정책 판정·환경 비교·실행·exact 결과 조립만 수행한다.

### 재현 환경 탐지와 구성

R7은 이 영역을 설계·구현하는 팀 역할이고 직접 Docker를 실행하는 시스템 주체가 아니다. 실제 책임은 다음처럼 나눈다.

- Verification Agent는 필요한 사용자 역할·권한·데이터 상태·인증 여부·외부 서비스·Mock 허용 범위·실제 동작이 필요한 대상·허용 version fallback·Health Check와 판정 영향 설정을 immutable `EnvironmentRequirements`에 고정한다. mode와 단계를 담은 `ReproductionPlan.environment_requirements_ref`는 그 current exact revision을 가리킨다.
- Sandbox Environment Builder는 같은 `workspace_id`·`commit_id`에서 plan 실행에 필요한 설정과 fixture를 준비하고 image를 빌드한다.
- Runtime Validator는 실행 요청의 requester·상태·예산과 exact input reference를 검사한다.
- Sandbox Controller는 기존·생성 설정과 image·command·file·network·resource·cleanup 정책을 검사한다.
- Sandbox Runner는 Controller를 통과한 exact image와 plan만 실행한다.
- Sandbox runtime은 환경·실행 log와 `DynamicReproductionResult`를 만든다.

Environment Builder는 mode나 공격 단계를 새로 결정하지 않고 plan 실행에 필요한 component만 준비한다. 운영환경 전체를 복제하거나 대상 애플리케이션을 다시 구현하지 않는다.

#### 환경 설정 고정과 image 승인 순서

환경 build 결과와 실제 Sandbox 환경은 서로 다른 artifact다. Environment Builder는 Docker 설정과 image를 고정한 immutable `EnvironmentBuildArtifact`를 만들고 `RUN_SANDBOX.input_refs`에 그 exact reference와 image digest를 포함한다. 공통 `DynamicReproductionResult.environment_ref`는 build 설정이 아니라 Runner가 실제 생성한 `SandboxEnvironment`를 가리킨다. 이 actual environment의 `requirements_ref`는 plan의 `environment_requirements_ref`와 같고 모든 `requirement_id`의 충족·차이를 연결한다. `EnvironmentBuildArtifact`가 보존할 최소 의미는 다음과 같다.

- 환경 설정 식별자(identity), schema version, revision, 생성 시각과 생성 주체
- exact `ReproductionPlan`, `EnvironmentRequirements`, `workspace_id`, `commit_id` reference
- 원본 Dockerfile·Compose hash, 생성하거나 수정한 설정 hash와 build context hash
- runtime·package manager·lockfile·주요 dependency version과 선택 근거
- builder base image digest와 빌드된 application image digest
- 적용한 R8 budget profile reference와 단계별 time·retry limit
- 계획한 DB·service·fixture·테스트 계정·Mock 구성과 요구사항 대비 예상 차이
- `EnvironmentRequirements`에서 가져온 Health Check 입력
- fallback 사용 여부, limitations와 입력 변경 시 무효화 기준
- 환경 구성 단계별 상태·log reference와 cleanup 결과

trusted 저장 runtime은 build candidate의 필수 reference와 hash가 모두 결정되고 image build가 끝난 뒤에만 atomic commit한다. 중간 실패 candidate를 실행 준비가 끝난 artifact로 승격하지 않는다. build 단계에서 실제 Sandbox 환경이 만들어지지 않았다면 `environment_created=false`, `environment_ref=null`이고 실패 log는 build work output과 오류 record에 보존한다. Runner가 환경을 일부라도 만들었다면 그 actual snapshot만 `environment_ref`가 가리킨다.

환경 build와 실제 취약점 재현 실행은 다음 순서로 분리한다.

1. Verification Agent가 exact `EnvironmentRequirements`와 이를 가리키는 `ReproductionPlan`을 각각 `COMMITTED`한다.
2. Environment Builder가 Repository 설정을 읽기 전용으로 탐지하고 build candidate를 만든다. 요구사항을 만족할 수 없거나 허용 범위 밖 fallback이 필요하면 차이만 반환하고 임의 변경하지 않는다.
3. Sandbox Controller가 원본·생성 Docker 설정, build context와 builder 정책을 검사한다.
4. 통과한 설정만 격리된 builder에서 image로 빌드한다.
5. Environment Builder가 application image digest와 `EnvironmentBuildArtifact` candidate를 반환하고 trusted 저장 runtime이 schema·hash·exact plan/requirements reference를 검증해 atomic commit한다.
6. Verification은 exact build artifact가 원 요구사항과 같거나 요구사항에 미리 허용된 fallback만 사용했는지 확인한다. 허용 범위 밖 차이면 실행하지 않고 필요에 따라 새 requirements와 plan을 만든다.
7. 실제 재현용 `RUN_SANDBOX` action은 Verification이 확인한 exact plan·requirements·build artifact·application image digest를 입력으로 고정한다.
8. Runtime Validator가 requester·상태·예산·identity·revision을 검사하고, Sandbox Controller가 exact image·command·file·network·resource·cleanup 실행 정책을 검사한다.
9. Sandbox Runner가 actual `SandboxEnvironment`를 만들고 모든 requirement를 `MATCH | MISMATCH | NOT_CHECKED | ERROR`로 비교한다. required 항목이 모두 `MATCH`일 때만 PoC·공격 단계를 실행한다.
10. required 차이가 있으면 공격을 실행하지 않고 `FAILED + ENVIRONMENT_SETUP + INCONCLUSIVE`와 actual comparison을 R6에 반환한다.

따라서 application image가 만들어지기 전에 그 digest를 가정해 실제 재현용 `RUN_SANDBOX`를 허가하지 않는다. Verification의 build artifact 확인은 환경 차이의 보안 의미를 판단하는 경계이고, Sandbox 정책 허가를 대신하거나 우회하지 않는다. 별도 환경 build work/action의 공통 이름·권한과 atomic 저장 계약은 R4·R3와 확정하기 전까지 자동 build를 허용하지 않는다.

#### 탐지와 version 선택

환경 구성 전에 다음 항목을 읽기 전용으로 탐지한다.

| 영역 | 탐지 항목 |
|---|---|
| Python·dependency | Python version 선언, `requirements.txt`, `pyproject.toml`, lockfile과 설치 방식 |
| Django 실행점 | `manage.py`, settings module, WSGI/ASGI entrypoint, URL routing, middleware와 필요한 환경변수 이름 |
| container 설정 | Dockerfile, Compose file, base image, build context, entrypoint, healthcheck와 service dependency |
| DB | Django `DATABASES`, DB driver dependency, SQLite file 또는 PostgreSQL·MySQL service와 migration 상태 |
| 보조 서비스 | cache·queue·worker·OAuth·외부 API·browser·callback 중 plan 경로에 실제 필요한 항목 |

runtime과 dependency version은 다음 우선순위로 선택한다.

1. lockfile과 `.python-version`, runtime version 고정 파일
2. Repository의 Dockerfile·Compose
3. CI 설정
4. `pyproject.toml`, package metadata 등 프로젝트 선언
5. 공식 framework 설정
6. versioned Sandbox profile의 승인된 기본 version

선택 결과에는 runtime·package manager·주요 dependency version, lockfile hash, base image digest, 선택 근거와 fallback 여부를 기록한다. 상위 근거와 충돌하면 임의로 병합하지 않고 환경 설정을 실패 처리하거나 차이를 limitation으로 남긴다. 승인된 기본 version을 사용했거나 실제 환경과의 차이가 가설 결과에 영향을 줄 수 있으면 실패·미재현을 `DISPROVED`나 `FALSE`로 바꾸지 않는다.

#### 기존 설정과 자동 구성의 안전 경계

Repository의 Dockerfile·Compose도 비신뢰 입력으로 취급하며 다음 순서로 처리한다.

1. 원본 설정과 build context를 읽기 전용으로 분석하고 hash를 기록한다.
2. Sandbox Controller가 base image digest, command/tool, mount·file path, network target, resource와 cleanup 정책을 검사한다.
3. Docker 설정이 없거나 안전하게 실행할 수 없으면 CodeWorkspace 밖의 Sandbox 작업영역에 일회성 실행 설정(overlay)을 만든다. 이는 원본 Repository를 수정하지 않고 실행에 필요한 Dockerfile·Compose 설정을 Sandbox에만 덧붙이는 방식이다.
4. 일회성 실행 설정은 탐지한 runtime·dependency·entrypoint와 plan에 필요한 service만 포함하고 원본 source tree에 commit하지 않는다. plan의 실행 단계·공격 입력을 추가하거나 바꿀 수 없으며 결과 image digest는 `RUN_SANDBOX` 허가 값과 일치해야 한다.
5. build context는 정규화한 workspace 내부 allowlist 경로로 제한하고 symlink escape를 거절한다. Docker socket·host secret·host 환경변수 전달, `privileged`, 임의 capability, 승인되지 않은 host mount와 운영 endpoint는 금지한다. network는 default-deny이고 승인된 목적지만 열며 CPU·memory·disk·process·time limit를 적용한다.
6. 기존 설정을 안전하게 변환하면 원본과 변환본 hash, 변경 이유와 의미 차이를 모두 남긴다. 안전한 대체가 없으면 환경 한계로 반환하고 정책을 완화하지 않는다.
7. 기존 설정과 일회성 설정 모두 적용 근거, dependency·service, image digest, 예상 환경 차이와 폐기 결과를 `EnvironmentBuildArtifact`에 남긴다.

#### mode별 범위와 테스트 상태

mode는 환경 범위를 제한하는 입력이다.

| mode | 구성 범위 |
|---|---|
| `LIMITED_REPRO` | plan의 작은 실행 사실에 필요한 runtime·dependency·fixture·관측 지점만 준비하고 관계없는 HTTP·DB·service는 시작하지 않음 |
| `FULL_REPRO` | plan에 명시된 HTTP 요청부터 routing·middleware·인증·권한·handler/view·DB 또는 sink·observable effect까지 연결하는 최소 E2E component를 준비 |

DB와 테스트 상태는 다음 원칙을 따른다.

- SQLite는 원본 DB 파일이나 사용자 데이터를 직접 사용하지 않고 격리된 writable 영역에 migration과 test record를 준비한다.
- PostgreSQL·MySQL은 settings와 driver에서 engine을 탐지하고 Sandbox 내부의 일회성 service에 schema·migration·test record를 구성한다.
- fixture, 권한별 테스트 계정, 소유 객체와 로그인 세션은 `EnvironmentRequirements`에 고정된 역할·권한·인증·데이터 전제조건을 그대로 만족하는 최소 데이터만 만들고 실행마다 격리한다.
- Redis·Celery 같은 로컬 의존성은 requirements와 plan에 필요할 때만 격리 실행한다. OAuth·외부 API·SSRF target은 requirements가 허용하고 관측 목표를 유지하는 Sandbox 내부 Mock으로만 대체하며 production credential·운영 DB·실제 개인정보를 사용하지 않는다.
- Environment Builder는 다른 계정·권한·fixture·Mock을 임의로 선택하거나 차이를 수락하지 않는다. 대체가 필요하면 변경 내용·이유·원 요구사항과의 차이를 객관적으로 기록해 Verification에 반환한다. R6가 공격 의미가 달라진다고 판단하면 실행하지 않고 필요에 따라 `HOLD`를 검토하거나 새 requirements와 plan을 만든다.

#### Health Check

Health Check 설정은 실행 중 추측하지 않고 Verification이 `EnvironmentRequirements.items[]`의 `kind=HEALTH_CHECK` 항목과 그 `expected | expected_ref | alternatives | check_ref`에 고정한다. Environment Builder와 Runner는 이 입력을 임의로 완화하거나 바꾸지 않는다. 최소 입력은 다음과 같다.

- 확인 방식과 exact command reference 또는 격리된 요청 URL
- 예상 상태 코드와 필요한 응답 내용
- R8 budget profile이 정한 최대 대기 시간·확인 주기·최대 확인 횟수
- 반드시 실행 중이어야 하는 application·DB·보조 service 목록
- DB connection·migration·필수 schema 준비 조건
- 실패 시 수집할 application·service·DB log reference
- 모든 필수 조건을 만족해야 한다는 성공 판정식

프로세스가 살아 있거나 port가 열렸다는 사실만으로 성공 처리하지 않는다. 고정된 주기의 반복 확인은 한 attempt 안의 Health Check 관측이며 숨은 재시도가 아니다. 최대 대기 시간이나 확인 횟수를 넘기면 Health Check는 실패하고, 공격 경로를 실행하지 못한 결과는 `FAILED + ENVIRONMENT_SETUP`이다. Health Check 성공은 plan 실행 준비 상태일 뿐 취약점 재현 성공 신호가 아니다.

#### 단계별 실패와 재시도

환경 구성 수명주기는 `build -> dependency 설치 -> DB·보조 service 시작 -> migration -> fixture·계정 준비 -> application start -> Health Check -> plan 실행 준비` 순서다. 각 단계는 시작·종료·exit code·timeout·환경 차이를 관측하며, build·migration·Health Check와 retry의 실제 한도는 R8 budget profile을 적용한다. container 권한·network·resource·mount 제한의 실제 enforcement는 Sandbox policy가 담당한다.

| 상황 | 전문 결과 기록 | retry와 판정 경계 |
|---|---|---|
| build·dependency·DB·migration·application start·Health Check 실패 | `FAILED + ENVIRONMENT_SETUP` | transient이고 R8 한도 안이면 같은 입력의 새 attempt. 반증으로 사용하지 않음 |
| 준비 완료 뒤 application·PoC step 실행 실패 | `FAILED + EXECUTION` | 실제 실패 단계와 log를 보존하고 새 attempt 여부 판단 |
| 실행했지만 필요한 관측을 읽지 못함 | `FAILED + OBSERVATION` | 관측 채널을 임의 변경하지 않고 새 plan 필요 여부를 Verification이 판단 |
| Sandbox 정책 거절 | `BLOCKED + POLICY_BLOCKED` | 정책을 완화하지 않음. profile/policy revision 또는 plan closure가 바뀌면 새 plan·work·action 필요 |
| 단계별 time limit 초과 | `FAILED + TIMEOUT` | timeout 위치와 사용 예산을 기록하고 R8 한도 안에서만 새 attempt |
| 사용자·runtime 취소 | `CANCELLED + NONE` | 자동 retry 금지, 늦은 결과는 stale로 격리 |
| 전체 budget 소진 | 공통 `AnalysisError=BUDGET_EXCEEDED`와 work 상태로 기록 | `DynamicReproductionResult.failure_reason`에 새 enum을 만들지 않으며 새 예산 승인 전 retry 금지 |

한 attempt 안에서 build·migration·실행을 몰래 다시 시작하지 않는다. Health Check의 고정된 polling만 같은 attempt 안에서 수행한다. 기존 plan을 재사용할 수 있는 경우는 requirements, Sandbox profile/policy revision, image digest, command/tool, file/mount/network, resource/time/process limit, cleanup policy와 나머지 plan closure exact reference가 모두 같고 build·dependency 설치 같은 일시적 실패만 발생한 때다. 이때도 기존 실패 log를 보존하고 새 attempt·action·decision을 만든다.

역할·권한·인증·데이터·fixture·계정·Mock/실제 service·DB/schema/migration·보안 관련 Health Check·허용 fallback처럼 환경 전제조건이 바뀌면 Verification이 새 `EnvironmentRequirements`와 이를 가리키는 새 `ReproductionPlan`을 함께 만든다. 요구사항은 같아도 command·attack input·cleanup policy·Sandbox profile/policy revision 또는 다른 plan closure reference가 바뀌면 새 plan을 만든다. 기존 build artifact와 실패·차단 결과는 덮어쓰지 않고, 새 record의 trusted runtime commit 뒤 새 build work·attempt·`RUN_SANDBOX` action·Runtime decision·Controller decision을 거친 결과만 새 plan에 연결한다. 최대 시간과 retry 횟수는 R8 profile을 참조하며 Environment Builder나 Agent가 늘릴 수 없다.

`PARTIAL`은 애플리케이션이 단순히 실행된 상태가 아니라, R6가 requirements에서 optional 또는 허용 fallback으로 미리 명시한 차이 안에서 공격 경로 일부까지 실제 실행해 신뢰 가능한 관측을 얻었지만 전체 확인이 부족한 경우에만 `PARTIAL + NONE + INCONCLUSIVE`와 limitation을 사용한다. required 차이면 공격을 시작하지 않고 `FAILED + ENVIRONMENT_SETUP`이다. Health Check를 통과했더라도 공격 경로에 진입하지 못했다면 `PARTIAL`로 기록하지 않는다.

#### 정리와 재사용 금지

성공·실패·timeout·취소 뒤에는 exact cleanup policy에 따라 container, 임시 image·volume·network·file, fixture·테스트 계정·생성 credential과 민감 log를 정리하거나 보존 정책에 맞게 redaction한다. 정리 결과는 actual `SandboxEnvironment`의 자원 ledger 및 `DynamicReproductionResult.cleanup_status`와 연결한다.

cleanup이 실패하면 오류와 남은 자원을 기록하고 해당 환경·image·volume을 재사용하지 않으며 격리한다. Recovery runtime에 후속 강제 정리를 요청하고 필요한 운영 알림을 남긴다. cleanup 실패는 재현의 가설 관측과 별개이므로 `cleanup_status=FAILED`로 보존하되 재현 상태나 `hypothesis_outcome`을 임의로 바꾸지 않는다. 결과의 유효성 영향은 Verification Agent가 limitations와 관측을 함께 보고 판단한다.

#### 관련 Issue와 계약 경계

- #21은 actual `SandboxEnvironment`, 동적 관측·PoC·cleanup 상세 schema와 공통 `environment_ref` 연결을 관리한다.
- #22는 Sandbox Controller의 image·command·file·network·resource·cleanup 정책 enforcement를 확정한다.
- R8은 build·migration·Health Check·retry의 숫자 예산과 상한을 확정한다.
- R3는 Environment Builder·Controller·Runner의 실제 모듈 통합 가능성을 검증한다.
- R6는 `EnvironmentRequirements`, 허용 차이와 fallback을 생산하고 build/actual 차이의 공격 의미 및 결과를 해석한다.
- R4는 별도 환경 build work/action의 공통 ID·revision·authority·atomic commit 계약을 확정한다.

이 의존 계약과 교차 검토가 끝나기 전에는 #20을 완료로 닫지 않는다.

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
- Verification이 생산한 current exact `EnvironmentRequirements`와 이를 가리키는 `ReproductionPlan`에 mode, exact 가설, 단계별 command·공격 입력과 정리 정책 reference를 고정하고 `RUN_SANDBOX.input_refs`에 전체 계획 closure를 포함
- Runtime Validator는 `RUN_SANDBOX` 요청자의 권한·상태·예산, exact 계획과 current requirements revision만 확인하며 환경 조건이나 image·command·file·network·resource·cleanup 정책의 의미를 대신 판단하지 않음
- Sandbox Controller가 exact plan·requirements reference와 image digest, command/tool allowlist, mount·file path, default-deny network, resource/time/process, non-root와 cleanup 정책을 검사하고 통과한 계획만 Runner에 전달
- Sandbox Runner는 실제 환경과 모든 requirement·Health Check를 기록하고 필수 항목이 모두 `MATCH`일 때만 공격 단계를 실행하며, 요구사항·허용 대체값·정책·명령·입력을 임의로 바꾸지 않음
- Docker build와 실행은 분석용 `CodeWorkspace`를 직접 수정하지 않고 sandbox 내부 복사본에서 수행
- 기본 network deny, resource/time/process 제한, non-root와 read-only mount 우선
- host socket, host secret, production credential과 범위 밖 target 접근 금지
- 동적 결과의 exit code, stdout/stderr reference, artifact hash와 hypothesis 연결 저장
- Sandbox 실행 log는 실제 `step_id`·command·공격 입력 reference를 승인 계획과 연결하고 계획에 없는 단계나 입력을 실행하지 않음
- 환경 구축 실패·필수 요구사항 차이와 취약점 반증을 구분
- 필수 차이·실행 불가능·정책 차단·계획 변경이 필요하면 Sandbox Controller나 Runner가 exact 상태와 이유를 반환한다. Verification Agent가 환경 조건이나 허용 대체값을 바꾸면 새 requirements와 이를 가리키는 새 plan을 함께 만들고, 단계만 바꾸면 새 plan만 만든다. 두 경우 모두 새 실행 요청이 필요하며 이 R6 판단은 Sandbox 정책 검사를 우회하지 않는다.

### 동적 결과를 Verification에 전달하는 방법

R7은 PoC·환경·요구사항별 실제 값과 차이·Health Check·정책 판정·단계 로그의 상세 파일 형식을 설계한다. R4 공통 계약은 `EnvironmentRequirements`, plan과 실제 `sandbox_environment`의 exact 연결 및 `DynamicReproductionResult`의 reference·상태 조합만 고정한다.

- `poc_ref`: 이번 재현과 연결된 exact PoC 묶음. 생성되지 않았거나 필요하지 않으면 `null`이며, 존재만으로 실행·성공을 뜻하지 않는다.
- `policy_decision_ref`: Sandbox Controller의 exact 정책 판정. `POLICY_BLOCKED`이면 필수이며 Technical Gate 결과와 섞지 않는다.
- `runner_invoked`: Runner 실제 호출 여부. `false`이면 `steps_ref=null`, `true`이면 첫 단계 실패를 포함해 `steps_ref`가 필수다.
- `environment_created`: 실제 Sandbox 환경 생성 여부. `false`이면 `environment_ref=null`, `true`이면 실제 생성 환경과 requirement별 `MATCH | MISMATCH | NOT_CHECKED | ERROR`를 담은 reference가 필수다. `environment_ref`는 계획용 요구사항이나 Sandbox 보안 profile과 같은 개념이 아니다.
- `cleanup_required`: 정리 대상 발생 여부. `false`일 때만 `cleanup_status=NOT_REQUIRED`이며, 실제 자원이 생겼으면 `SUCCEEDED | FAILED`로 정리 결과를 남긴다.

Sandbox runtime의 비-LLM result assembler는 같은 analysis·workspace·commit·hypothesis에 속한 exact R6 plan closure와, `DynamicReproductionResult.meta.attempt_id`와 같은 R7 실행 attempt의 정책 판정·환경·step log·실행 PoC만 결과에 넣는다. R6가 먼저 만든 계획·요구사항의 `attempt_id`를 R7 실행 attempt와 억지로 같게 만들지 않는다. `DynamicReproductionResult`에 요구사항 reference를 중복 저장하지 않고 `reproduction_plan_ref -> environment_requirements_ref`와 `environment_ref -> requirements_ref`가 같은 record revision인지 검사한다. `DynamicReproductionState`, work output과 `TransitionCommit`이 같은 COMMITTED 결과를 가리킨 뒤 Verification Agent가 `dynamic_result_ref`, 환경 차이와 exact `poc_ref`를 읽는다. Technical Evidence Gate Agent는 Verification에 연결된 정책 판정·환경·step log·PoC와 outcome이 서로 맞는지 검토하고, Reporter는 두 Gate를 통과한 결과만 보고서 초안에 사용한다. Provider 오류, 정책 차단, setup·환경 차이·실행·관측 실패는 이 전달 과정에서 `FALSE`로 바뀌지 않는다.

### 동적 재현 상태와 실제 반증

동적 재현 상태는 `NOT_REQUESTED | RUNNING | SUCCEEDED | PARTIAL | FAILED | BLOCKED | CANCELLED`다. 실행이 끝난 결과는 `DynamicReproductionResult.status`에 `SUCCEEDED | PARTIAL | FAILED | BLOCKED | CANCELLED` 중 하나를 기록한다.

- 필수 환경을 만들지 못하거나 필수 requirement가 `MISMATCH | NOT_CHECKED | ERROR`이면 공격 단계를 시작하지 않고 `FAILED + ENVIRONMENT_SETUP`으로 R6에 돌려보낸다.
- 공격 경로를 일부 실행하고 신뢰할 수 있는 관측을 하나 이상 얻었지만 운영환경 차이 등으로 전체 확인이 부족하면 `PARTIAL + NONE`이다. 이때 `hypothesis_outcome=INCONCLUSIVE`이고 `hypothesis_evidence_refs`와 `limitations`가 각각 하나 이상 있어야 한다.
- `SUCCEEDED`는 계획한 필수 단계와 관측을 끝냈다는 실행 상태다. 관측이 가설을 지지했는지, 반증했는지, 결론을 주지 못했는지는 `hypothesis_outcome`에 따로 기록한다.
- `hypothesis_outcome`은 `SUPPORTED | DISPROVED | INCONCLUSIVE`이며 Verification verdict가 아니다. `SUPPORTED | DISPROVED`는 실제 관측을 가리키는 `hypothesis_evidence_refs`가 필요하다.
- `DISPROVED`일 때만 `hypothesis_disproved=true`와 비어 있지 않은 `disproof_evidence_refs`를 사용한다. 반증 근거는 일반 가설 근거 목록에도 포함한다.
- `FAILED | BLOCKED | CANCELLED`, 실행하지 못함, 빈 출력과 exit code만으로는 `DISPROVED`, `hypothesis_disproved=true` 또는 `FALSE`를 만들 수 없다.

동적 결과 상태와 공통 실행 상태는 뜻이 다르다. `DYNAMIC_REPRO`의 `PARTIAL`은 신뢰 관측과 `limitations`를 가진 `DynamicReproductionResult` 자체가 누락 범위를 설명하므로 실제 오류가 없으면 `AnalysisError`나 `DataGap`을 만들지 않는다. `BLOCKED + POLICY_BLOCKED`는 정책에 막힌 사실을 Sandbox가 정상적으로 기록한 종료 결과이므로 공통 `WorkExecutionState`는 `SUCCEEDED`로 끝난다. 여기서 `SUCCEEDED`는 요청 처리가 완료되었다는 뜻일 뿐 재현 성공이나 가설 지지를 뜻하지 않는다. retry·승인·입력을 기다리는 경우에만 공통 상태 `BLOCKED`를 사용한다. `CANCELLED`는 취소 결과와 공통 취소 상태를 같은 atomic transition에서 저장하고, 취소 뒤 늦게 도착한 결과는 격리한다.

모든 종료 결과는 `DynamicReproductionState.dynamic_result_ref`, `WorkExecutionState.output_refs`와 `TransitionCommit.output_refs`가 같은 `DynamicReproductionResult.record_id`를 가리킬 때만 Verification에 전달한다. Verification Agent는 이 결과를 정적·찬반 근거와 함께 읽어 최종 `TRUE | FALSE | HOLD`를 결정한다.
- Sandbox Controller는 exact 정책 판정을 저장하고 통과한 계획만 Runner에 전달한다. Runner는 exact 요구사항과 실제 환경·Health Check를 비교하고 필수 차이가 있으면 공격 단계 전에 멈춘다. 비-LLM Sandbox Result Assembler는 Runner 호출 여부와 실제 환경 비교·정리 여부를 포함한 `DynamicReproductionResult`를 조립한다. 결과 저장 전 `SAVE_RESULT`가 계획·requirements·정책 판정·실제 환경·단계·공격 입력·PoC·정리 조합을 다시 대조하며, Verification Agent는 `COMMITTED`된 결과를 소비할 뿐 요구사항 비교나 동적 결과를 직접 생산하지 않는다. Sandbox는 outcome까지만 기록한다. Verification Agent가 환경 차이를 허용해 환경 조건을 바꾸면 새 요구사항과 이를 가리키는 새 계획을 함께 만들고, 실행 단계만 바꾸면 새 계획만 만든 뒤 limitations와 정적·동적·찬반 근거를 함께 보고 최종 `TRUE | FALSE | HOLD`를 결정한다.

## Technical `REVISE` 처리

Technical Evidence Gate의 `REVISE`는 Orchestration이나 Chaining Agent가 받을 작업이 아니다. 같은 hypothesis의 ACTIVE `VerificationAssignment` owner가 직접 받고 누락된 Context·Pro/Con·정적 근거·동적 재현·PoC 연결·restriction·설명을 보완한다. runtime은 종료된 기존 work를 되돌리지 않고 새 generation의 VERIFICATION work를 만들고 hypothesis 상태를 `TERMINAL -> VERIFYING`으로 원자 전환한다. CWE 보완이 필요하면 CWE producer와 새 label revision을 조정하되 CWE 소유권을 가져오지 않는다.

```text
VerificationResult revision N
-> Technical Gate REVISE
-> same Verification owner
-> new evidence and/or revised CWE
-> VerificationResult revision N+1
-> new Technical Gate work
```

`REVISE`는 provider retry나 동일 입력 재투표가 아니다. 새 work는 새 `input_hash`, `dedupe_key`, `work_id`, `attempt_number=1`, `trigger=INITIAL`을 사용한다. 이전 Gate 결과가 N을 가리키면 N+1에 재사용할 수 없다.

## VerificationResult에 남길 정보

최종 결과는 verdict뿐 아니라 질문별 `FalsificationResult`, supporting/counter evidence, restrictions, bypass·alternate path·impact 후보, REQUIRED/PROVIDED Primitive 후보, `origin=VERIFICATION` material child proposal, unresolved conditions, debate 지표와 동적 재현 reference를 포함한다. HOLD의 REQUIRED 후보는 즉시 admission할 수 있다. TRUE의 REQUIRED 후보는 그 취약점의 악용 선행 조건으로만 보존되고, PROVIDED 후보가 두 Gate를 정상 통과해 admission될 때 `required_preconditions`에 복사된다. 이 정보가 CWE, 두 Gate, Primitive admission과 사람 검토의 입력이 된다.

supporting/counter evidence는 자유 형식 문자열이 아니라 `EvidenceClaim`으로 기록한다. 각 claim은 작성 역할, 실제 저장 근거와 코드 주장에 필요한 현재 workspace·commit의 위치를 포함한다. 우회·대체 경로·영향 확대 후보는 `CandidateRef(candidate_state=UNVALIDATED)`로 구분하고 새 material claim이면 별도 가설로 재검증한다. debate token·시간과 판정 변화는 `VerificationMetrics`에 저장하며 provider가 token을 제공하지 않으면 값을 추정하지 않고 `null`로 둔다.
