# R3-06. 구현 기술·파일 구조·저장·설정·실행 기준선

- **이 문서는 무엇을 설명하나요?** Architecture v5를 실제 코드로 옮길 때 사용할 기술, repository 구조, 저장·복구, 설정, CLI, 테스트와 구현 순서를 확정합니다.
- **누가 읽어야 하나요?** 한 명의 전체 구현 담당자와 R1~R8 역할 검토자가 읽습니다.
- **읽은 뒤 무엇을 확인하나요?** 실제 구현이 아래 승인된 단일안과 일치하는지 확인하고, 변경이 필요하면 영향받는 계약·시험을 새 ADR에서 검토합니다.

> 상태: **DESIGN_APPROVED / NOT_IMPLEMENTED**

## 1. 문서 권한과 현재 상태

이 문서는 R3-01~R3-05의 논리 설계를 물리 기술과 실제 파일 위치에 연결하는 **구현 기준선**이다. 새로운 취약점 판정 기준, Gate 의미, Chaining 규칙 또는 Sandbox 정책을 만들지 않는다.

충돌할 때 우선순위는 다음과 같다.

1. 데이터 이름·상태·필수값: [08. 경량 데이터 계약](../08-lightweight-data-contracts.md)
2. 권한·허용 action·Sandbox 외부 경계: [10. 보안 경계](../10-security-boundaries.md)
3. 전체 순서: [01. 시스템 개요](../01-system-overview.md)
4. 역할별 의미: Architecture v5 번호 문서 `02`~`07`, `09`
5. 구현 연결: R3 구현 문서 `01`~`05`
6. 물리 기술·파일 구조·CLI·CI: 이 문서

선행 문서는 다음과 같다.

- [R3-01 모듈 맵](./01-module-map.md): 정본 22단계의 주체·입출력·저장·오류 연결
- [R3-02 계약 시험 계획](./02-contract-test-plan.md): 정상·부정 fixture와 계약 시험
- [R3-03 복구 시험 계획](./03-recovery-test-plan.md): 중단·재시도·복구 시험. PR #107 병합 결과를 이 기준선의 물리 저장·CLI·복구 결정과 대조했다.
- [R3-04 Provider 결정](./04-provider-decision.md): API Key·구독 로그인 연결 후보와 capability 시험
- [R3-05 Prompt Runtime](./05-prompt-runtime.md): Prompt Registry·Builder·11개 LLM 역할과 출력 검증

R3-06을 병합한 PR #116과 Issue #92·R3 상위 Issue #4의 종료를 확인했다. Architecture v5 최종 승인 검토를 시작한 `main`은 `07bd6549a676419c0e720f940ba7abd1b82aea0d`다. 리뷰에서 기존 계약을 명확히 한 수정까지 포함한 승인 대상은 Final PR #117 head `0647514f9d3d288fbedfa983c5b828d88c909df8`이고 merge commit은 `2de1f6767d8bc25ee7383adacb3082b4ff761f8a`다. 필수 역할 검토를 마쳤으므로 이 문서의 기술 선택과 [ADR-015](../../review/decisions/ADR-015-r3-implementation-baseline.md)는 구현 기준 `ACCEPTED`다. 실제 라이브러리 설치·Provider 연결·Docker 실행과 품질 시험은 여전히 `NOT_IMPLEMENTED`다.

- 구현 차단 `DEFERRED`: 없음
- 실제 코드: 없음
- 실제 ProviderProfile 활성화: 없음
- 실제 탐지 정확도·성능 측정: 없음

## 2. 결정 원칙

### 2.1 역할과 모델을 분리한다

Agent의 이름·역할·입출력 계약은 특정 Provider 또는 모델에 종속되지 않는다. 실제 LLM Provider와 인증·전송 설정은 exact `provider_profile_ref`, 모델은 `LLMCallSpec.model`로 호출 시점에 고정한다. 두 값이 가리키는 `ProviderProfile.model`과 실제 호출 모델은 같아야 한다. 이 문서와 Agent 코드, prompt template에는 특정 모델 ID를 넣지 않는다.

### 2.2 LLM과 프로그램 권한을 분리한다

LLM 역할 11개는 분석·분류·검토·초안 작성을 수행한다.

- `Hypothesis Agent`
- `Pro Agent`
- `Con Agent`
- `Verification Agent`
- `Policy Parser Agent`
- `Dynamic Reproduction Agent`
- `Chaining Agent`
- `CWE Labeling Agent`
- `Technical Evidence Gate Agent`
- `Rule Scope Impact Gate Agent`
- `Reporter Agent`

다음 구성요소는 비-LLM이며 prompt를 갖지 않는다.

- `Orchestration Runtime`: 전역 work·가설 등록, 배정과 합류
- `Runtime Validator`: action·상태·권한·exact reference 검사
- `Prompt Registry Runtime`: 승인된 prompt 설정 선택
- `Playbook Registry Runtime`: 승인된 플레이북 적용
- `Policy Preparation Service`·`Policy Collector`: run-init 정책 work 등록·상태 관찰과 공식 원문 수집·cache·run-local 정책 결과 확정
- `Context Retrieval Service`: exact workspace·commit 범위의 코드 문맥 조회
- `Budget Runtime`·`Budget Profile Registry`: R8 승인 profile 게시, 실행 전 예약과 실제 사용 장부 확정
- `R8 Evaluation Runtime`: 격리된 평가 실행·비교·추천 결과 확정
- `Reproduction Setup Automation`: recipe·image·container·cleanup 실행
- `Sandbox Controller`: Sandbox 밖의 강제 경계 검사
- `Reproduction Session Manager`: event 기록과 동적 결과 확정
- `Primitive Admission Runtime`: Gate 결과의 기계적 체이닝 허용 매핑

### 2.3 첫 구현은 로컬 단일 애플리케이션이다

Agent별 서버, 분산 scheduler와 외부 message queue 제품을 도입하지 않는다. 하나의 Python process가 제한된 worker를 운영하고 SQLite work table에서 claim·retry·resume을 관리한다. LLM·정적 도구·Docker는 port/adapter 뒤의 외부 dependency다.

### 2.4 코드와 실행 자료를 분리한다

분석 대상은 실행별 로컬 Git clone과 checkout으로 준비한다. 별도 Repository Snapshot 모듈을 만들지 않는다. repository source tree에는 source·config·migration·test fixture만 두고, clone·DB·artifact·log·secret은 runtime data directory에 둔다.

### 2.5 오류를 취약점 판정으로 바꾸지 않는다

인증, timeout, 예산, 저장, 정적 도구, 정책 준비, 환경 구성과 Sandbox 실행 실패는 실행 상태와 오류 record다. 이 오류만으로 `TRUE | FALSE | HOLD`를 만들지 않는다.

## 3. 기술 결정 요약

이 표의 `ACCEPTED`는 구현에서 따라야 할 선택을 확정했다는 뜻이다. 정확한 package patch version과 외부 도구 version은 실제 구현의 lock과 승인된 profile에 고정하며, 설치·실행 성공을 미리 주장하지 않는다.

| 영역 | 단일안 | 상태 | 선택 이유 | 채택하지 않는 첫 구현안 |
|---|---|---|---|---|
| 언어 | 64-bit CPython, Python `>=3.12,<3.13` | ACCEPTED | Pydantic 2, 표준 `tomllib`, async I/O와 타입 도구를 안정적으로 사용 | 다중 언어 core, Python 3.13 즉시 채택 |
| dependency | `uv` + `pyproject.toml` + 커밋된 `uv.lock` | ACCEPTED | 한 명 구현자가 설치·lock·실행 명령을 하나로 유지 | requirements 파일 중복, 런타임 자동 설치 |
| 품질 도구 | Ruff format/lint, mypy strict, pytest | ACCEPTED | 빠른 로컬 검증과 CI 명령 통일 | formatter·linter 복수 조합 |
| schema | Pydantic 2 계열 + JSON Schema 2020-12 | ACCEPTED | 공통 Python type과 외부 JSON 계약을 함께 생성 | dict 직접 조립, 역할별 독립 schema 정의 |
| JSON hash | SASTSIMI Canonical JSON v1 + SHA-256 | ACCEPTED | work dedupe와 exact content reference를 동일 bytes로 계산 | 기본 `json.dumps()` 출력에 의존 |
| 상태 DB | SQLite + SQLAlchemy 2 계열 | ACCEPTED | 로컬 단일 host transaction·constraint·CAS를 명시적으로 구현 | PostgreSQL, 문서 DB, in-memory 상태 |
| migration | Alembic + revision별 upgrade/downgrade | ACCEPTED | DB 변경 이력·검토·rollback 명령 표준화 | 앱 시작 시 임의 schema 변경 |
| 큰 artifact | 로컬 content-addressed file store | ACCEPTED | 큰 raw output·PoC·log를 DB blob과 분리하고 hash로 검증 | 모든 데이터를 SQLite blob에 저장 |
| 동시성 | `asyncio` bounded task + SQLite claim | ACCEPTED | 외부 I/O 병렬성과 가설별 제한 병렬 처리 | Celery·RabbitMQ·Kafka |
| CLI | 표준 `argparse` | ACCEPTED | 첫 구현 의존성 최소화와 명시적 exit code | Web/API 우선, CLI framework 추가 |
| 설정 | TOML + 승인된 YAML registry + 환경 변수 secret | ACCEPTED | 사람이 읽는 설정, prompt/playbook registry와 secret 분리 | Python 설정 코드, 저장소의 `.env` 비밀값 |
| 외부 실행 | `asyncio.create_subprocess_exec`, `shell=False` | ACCEPTED | Git·CodeQL·OpenGrep·Docker 명령 인자 경계와 취소 가능 | shell 문자열 연결, LLM의 직접 command 실행 |
| 로그 | 표준 logging 기반 JSON Lines | ACCEPTED | secret redaction 뒤 구조화 event를 파일·CI에서 동일 처리 | 자유 형식 로그만 저장, hidden reasoning 저장 |
| 초기 UI | CLI | ACCEPTED | core와 계약을 먼저 안정화 | Web UI·HTTP server 동시 구현 |

각 Python package의 정확한 patch version은 `uv.lock`, 각 외부 실행 도구의 정확한 version은 승인된 tool profile에 고정한다. “2 계열” 같은 범위는 설계 호환 범위이며 실제 실행은 lock과 profile의 exact version만 허용한다.

첫 `pyproject.toml`의 호환 범위는 다음과 같이 고정한다. lock 생성 시 이 범위 안의 exact version이 `uv.lock`에 기록된다.

| group | package 범위 | 목적 |
|---|---|---|
| core | `pydantic>=2.8,<3` | 공통 contract와 JSON Schema |
| core | `sqlalchemy>=2.0,<3` | SQLite repository와 transaction |
| core | `alembic>=1.13,<2` | DB migration·rollback |
| core | `PyYAML>=6,<7` | 승인된 YAML registry의 safe parsing |
| core | `platformdirs>=4,<5` | OS별 runtime data root 계산 |
| dev | `pytest>=8,<9`, `pytest-asyncio>=0.24,<1` | unit·contract·integration 시험 |
| dev | `ruff>=0.12,<1`, `mypy>=1.11,<2` | format·lint·type 검사 |
| adapter optional group | 공식 Provider SDK | R3-04 capability 시험에서 선택한 adapter만 별도 group에 exact lock |

Provider SDK는 이름만 설치해 지원으로 간주하지 않는다. 해당 adapter의 client version·model·environment 조합이 R3-04 시험을 통과해야 profile을 발급한다.

## 4. 지원 실행 환경

첫 구현의 지원 범위는 다음으로 제한한다.

- 개발 host: Windows 11 x86-64 또는 Ubuntu 24.04 LTS x86-64
- CI core 계약 시험: Ubuntu 24.04 LTS와 Windows Server 2022
- Docker 통합·보안 부정 시험: Ubuntu 24.04 LTS의 Linux container
- Python: 64-bit CPython `>=3.12,<3.13`
- 파일 encoding: UTF-8, repository Markdown·Python·JSON·YAML·TOML은 LF로 커밋

Windows 개발 환경은 Docker Desktop 또는 동등한 팀 승인 Docker Engine 연결을 사용할 수 있지만, Dynamic Reproduction Agent와 container에 host Docker socket을 노출하지 않는다. OS별 path는 `pathlib.Path`와 `platformdirs` adapter로 계산하며 domain record에 host 절대 경로를 저장하지 않는다.

지원 환경 밖에서는 `sastsimi doctor`가 `CAPABILITY_UNSUPPORTED`를 반환한다. 자동으로 다른 실행 방식이나 외부 host로 전환하지 않는다.

## 5. 실제 repository 구조

```text
sastsimi/
├─ pyproject.toml
├─ uv.lock
├─ README.md
├─ .gitignore
├─ .gitattributes
├─ src/
│  └─ sastsimi/
│     ├─ __init__.py
│     ├─ bootstrap.py
│     ├─ contracts/
│     │  ├─ ids.py
│     │  ├─ refs.py
│     │  ├─ records.py
│     │  ├─ work.py
│     │  ├─ actions.py
│     │  ├─ static.py
│     │  ├─ verification.py
│     │  ├─ dynamic.py
│     │  ├─ gates.py
│     │  ├─ chaining.py
│     │  ├─ reporting.py
│     │  ├─ policy.py
│     │  ├─ budget.py
│     │  ├─ evaluation.py
│     │  └─ schema_export.py
│     ├─ ports/
│     │  ├─ clock.py
│     │  ├─ id_generator.py
│     │  ├─ unit_of_work.py
│     │  ├─ record_store.py
│     │  ├─ artifact_store.py
│     │  ├─ llm_provider.py
│     │  ├─ static_tool.py
│     │  ├─ policy_source.py
│     │  ├─ budget_ledger.py
│     │  ├─ work_handler.py
│     │  └─ sandbox.py
│     ├─ runtime/
│     │  ├─ work_service.py
│     │  ├─ attempt_service.py
│     │  ├─ action_validator.py
│     │  ├─ transition_service.py
│     │  ├─ generation_transition.py
│     │  ├─ recovery_service.py
│     │  ├─ budget_registry.py
│     │  ├─ budget_service.py
│     │  ├─ worker_pool.py
│     │  └─ errors.py
│     ├─ orchestration/
│     │  ├─ analysis_service.py
│     │  ├─ run_initialization.py
│     │  ├─ hypothesis_workflow.py
│     │  ├─ verification_assignment.py
│     │  └─ result_aggregation.py
│     ├─ verification/
│     │  ├─ debate_service.py
│     │  ├─ service.py
│     │  ├─ verdict_router.py
│     │  └─ revision_workflow.py
│     ├─ reproduction/
│     │  └─ service.py
│     ├─ chaining/
│     │  └─ service.py
│     ├─ storage/
│     │  ├─ database.py
│     │  ├─ models.py
│     │  ├─ repositories.py
│     │  ├─ unit_of_work.py
│     │  ├─ artifact_store.py
│     │  ├─ migrations.py
│     │  └─ integrity.py
│     ├─ providers/
│     │  ├─ base.py
│     │  ├─ openai_api.py
│     │  ├─ codex_subscription.py
│     │  ├─ anthropic_api.py
│     │  ├─ claude_subscription.py
│     │  ├─ fake.py
│     │  └─ normalization.py
│     ├─ prompts/
│     │  ├─ registry.py
│     │  ├─ loader.py
│     │  ├─ builder.py
│     │  ├─ redaction.py
│     │  ├─ validation.py
│     │  └─ templates/
│     ├─ agents/
│     │  ├─ hypothesis.py
│     │  ├─ pro.py
│     │  ├─ con.py
│     │  ├─ verification.py
│     │  ├─ policy_parser.py
│     │  ├─ dynamic_reproduction.py
│     │  ├─ chaining.py
│     │  ├─ cwe_labeling.py
│     │  ├─ technical_gate.py
│     │  ├─ rule_scope_gate.py
│     │  └─ reporter.py
│     ├─ static_analysis/
│     │  ├─ repository_loader.py
│     │  ├─ coordinator.py
│     │  ├─ ast_adapter.py
│     │  ├─ codeql_adapter.py
│     │  ├─ open_grep_adapter.py
│     │  ├─ normalizer.py
│     │  └─ context_retrieval.py
│     ├─ policy/
│     │  ├─ preparation_service.py
│     │  ├─ collector.py
│     │  ├─ cache_service.py
│     │  └─ adapters/
│     │     └─ official_http.py
│     ├─ sandbox/
│     │  ├─ setup_automation.py
│     │  ├─ controller.py
│     │  ├─ session_manager.py
│     │  ├─ docker_adapter.py
│     │  ├─ recipe_store.py
│     │  ├─ health_check.py
│     │  └─ cleanup.py
│     ├─ reporting/
│     │  ├─ cwe_workflow.py
│     │  ├─ technical_gate_workflow.py
│     │  ├─ rule_scope_gate_workflow.py
│     │  ├─ finding_normalizer.py
│     │  ├─ primitive_admission.py
│     │  └─ report_workflow.py
│     ├─ evaluation/
│     │  ├─ service.py
│     │  ├─ runner.py
│     │  ├─ grader.py
│     │  └─ recommendation.py
│     ├─ config/
│     │  ├─ models.py
│     │  ├─ loader.py
│     │  ├─ precedence.py
│     │  └─ secrets.py
│     └─ interfaces/
│        └─ cli/
│           ├─ main.py
│           ├─ commands.py
│           ├─ evaluation_commands.py
│           ├─ output.py
│           └─ exit_codes.py
├─ tests/
│  ├─ unit/
│  ├─ contract/
│  ├─ integration/
│  ├─ e2e/
│  ├─ security_negative/
│  └─ fixtures/
├─ config/
│  ├─ profiles/
│  ├─ prompts/
│  │  └─ registry.yaml
│  ├─ playbooks/
│  └─ static-rules/
├─ schemas/
│  └─ generated/
├─ evals/
│  ├─ corpus/
│  ├─ graders/
│  ├─ scenarios/
│  └─ configs/
├─ migrations/
│  ├─ env.py
│  └─ versions/
├─ docker/
│  ├─ base/
│  └─ profiles/
└─ docs/
   └─ architecture-v5/
      └─ implementation/
```

### 5.1 디렉터리 책임

| 디렉터리 | 책임 | 금지 |
|---|---|---|
| `contracts/` | Pydantic schema, enum, ID와 exact reference | DB·Provider·Docker import, business workflow 실행 |
| `ports/` | 외부·저장 경계 Protocol | 구체 adapter 생성, domain 판단 |
| `runtime/` | work·attempt·Action·transition·복구·bounded worker | 취약점·CWE·정책 의미 판정 |
| `orchestration/` | 분석 시작, 전역 work 등록, 가설 등록·배정, 전체 결과 집계 | hypothesis-local verdict·Gate 목적지 판단 |
| `verification/` | Debate·initial/final 검증·판정별 work 요청·Technical REVISE 흐름 | Agent 권한 확장, concrete reporting·chaining import |
| `reproduction/` | R6 요청과 R7 실행 구성요소의 동적 재현 순서 연결 | Sandbox Controller·Session Manager 권한 대체, final verdict 생성 |
| `chaining/` | exact Primitive 조회·matching·새 가설 proposal 전달 | Primitive admission 의미 변경, 전체 Verification 생략 |
| `storage/` | SQLite·artifact·migration·무결성 구현 | domain 결과 의미 변경 |
| `providers/` | 공식 API·CLI·SDK 전송과 공통 결과 정규화 | prompt 판단 기준 변경, 내장 tool로 host 접근 |
| `prompts/` | registry·loader·builder·redaction·schema/의미 검사 연결 | 역할 담당자의 판단 기준을 임의 작성 |
| `agents/` | 11개 LLM 역할의 얇은 wrapper와 output parser | DB·Docker 직접 호출, 전역 ID·상태 발급 |
| `static_analysis/` | Git·AST·CodeQL·OpenGrep·Context 실행과 사실 정규화 | 취약점 verdict 생성 |
| `policy/` | 공식 정책 source 수집·cache 호환성 검사·run-local 정책 준비. LLM Policy Parser 호출 결과를 검증·취합 | Rule Scope·보고 허용 의미 판정, R3 run-init이 정책 record를 대신 생산 |
| `sandbox/` | R7 환경·실행·event·PoC provenance | 최종 `TRUE | FALSE | HOLD`, Gate·정책 의미 판정 |
| `reporting/` | CWE·두 Gate 호출 흐름, Finding 정규화, admission, ReportDraft 연결 | 사람 승인·외부 제출·공개 |
| `evaluation/` | R8 corpus 실행, grader 호출, 품질·시간·사용량·비용 결과와 채택 제안 생성 | 운영 Finding·Primitive·ReportDraft current pointer 변경, Provider capability를 품질 승인으로 간주 |
| `config/` | versioned 설정, precedence와 secret handle | raw secret 저장, untrusted 입력의 설정 변경 |
| `interfaces/cli/` | 사용자 입력·출력과 exit code | DB table·artifact path 직접 조작 |
| `tests/` | 자동 시험과 fake | 운영 credential·실제 비공개 저장소 포함 |
| `config/` repository 폴더 | 승인 가능한 profile·prompt·playbook·rule source | API key·cookie·token 포함 |
| `schemas/generated/` | 공통 Pydantic model에서 생성한 JSON Schema | 손으로 별도 의미를 추가 |
| `evals/` | 운영과 격리된 평가 corpus·grader·scenario | 운영 Gate·Finding 입력으로 승격 |
| `migrations/` | Alembic revision과 rollback | 앱 시작 중 무기록 자동 변경 |
| `docker/` | R7 검토 대상 base asset·profile | 실제 run의 writable container·PoC 결과 저장 |

### 5.2 이름 규칙

- Python package·module·함수·field: `snake_case`
- class·Pydantic model·Protocol: `PascalCase`
- enum 값·공식 역할값·work/action 종류: `UPPER_SNAKE_CASE`
- prompt logical key: 점으로 구분한 소문자 key
- template path: `templates/<role>/<task>/<semver>.md`
- migration: `<revision>_<short_description>.py`
- test: `test_<행동>_<기대결과>.py`
- artifact 파일명은 사용자 입력 이름이 아니라 content hash를 사용

기존 계약 field를 Python에서 다른 이름으로 바꾸지 않는다. alias는 외부 migration 입력을 읽을 때만 허용하며 새 출력은 정본 이름만 사용한다.

### 5.3 Git에 포함하는 파일과 제외하는 파일

반드시 commit한다.

- `pyproject.toml`, `uv.lock`, source, migration과 test
- 비밀값이 없는 승인 후보 config·prompt·playbook·static rule source
- 생성된 JSON Schema와 생성 명령
- 작고 비식별화된 deterministic fixture
- Architecture·ADR·운영 안내

반드시 `.gitignore`로 제외한다.

- `.venv/`, Python·test·type cache와 coverage 출력
- runtime DB, artifact, staging, quarantine, workspaces와 JSON Lines 실행 log
- 실제 분석 대상 clone, 실제 PoC·보고서·Provider request/response
- API key, cookie, token, login session, browser profile과 local secret file
- local override config와 운영 capability 시험의 비공개 원문

`schemas/generated/`는 source Pydantic model과 함께 검토하기 위해 commit한다. runtime 결과는 예제처럼 보여도 fixtures로 자동 승격하지 않고 redaction·소유권·재현성 검토를 거친 별도 PR에서만 추가한다. 저장소 라이선스와 외부 재사용 범위는 governance 결정이며 내부 구현 기준선이 임의로 만들거나 바꾸지 않는다.

### 5.4 업무 흐름 서비스의 exact module

[ADR-016](../../review/decisions/ADR-016-maintainable-workflow-packages.md)은 승인된 유지보수 구현 설계의 물리 위치를 반영한다. 경로는 `src/sastsimi/` 기준이며 서비스 이름과 기존 권한은 유지한다.

| 서비스 | module | 책임 |
|---|---|---|
| `DebateService` | `verification/debate_service.py` | 같은 입력의 Pro·Con child work fan-out과 결과 join |
| `VerificationService` | `verification/service.py` | initial assessment와 최종 검증 결과 합성 |
| `VerdictRouter` | `verification/verdict_router.py` | final FALSE·HOLD·TRUE에 맞는 다음 work 등록 요청 생성 |
| `RevisionWorkflow` | `verification/revision_workflow.py` | Technical `REVISE`의 같은 owner·새 generation 전환 |
| `DynamicReproductionService` | `reproduction/service.py` | R6 요청과 R7 구성요소의 실행 순서 연결 |
| `ChainingService` | `chaining/service.py` | exact Primitive index 고정, Chaining 호출과 새 proposal 전달 |

## 6. 허용 의존 방향

아래 `A → B`는 A가 B의 public interface를 import할 수 있다는 뜻이다.

```text
ports → contracts
config → contracts
prompts → contracts, ports, config
agents → contracts, ports, prompts
runtime → contracts, ports, config
orchestration → contracts, ports, runtime
verification → contracts, ports, runtime, agents
reproduction → contracts, ports, runtime, agents
chaining → contracts, ports, runtime, agents
reporting → contracts, ports, runtime, agents
policy → contracts, ports, runtime, agents, config
evaluation → contracts, ports, runtime, agents, config
providers → contracts, ports, config
static_analysis → contracts, ports, config
sandbox → contracts, ports, config
storage → contracts, ports, config
interfaces/cli → orchestration, runtime, evaluation
bootstrap → 위 concrete 구현을 조립
```

정확한 규칙은 다음과 같다.

1. `contracts`는 다른 `sastsimi` package를 import하지 않는다.
2. `ports`는 `contracts`만 import한다.
3. `agents`는 `contracts`, `ports`, `prompts`의 public interface만 사용한다.
4. `runtime`은 `contracts`, `ports`, `config`를 사용하며 전문 의미를 판정하지 않는다.
5. `orchestration`은 `runtime` service와 port를 호출하지만 concrete storage·provider·Docker adapter를 import하지 않는다.
6. `static_analysis`, `providers`, `sandbox`, `storage`와 `policy/adapters`는 port 구현이다. 서로를 직접 호출하지 않는다.
7. `policy`는 `PolicySourcePort`로 공식 원문을 가져오고 Policy Parser를 runtime을 통해 호출한다. R3 run-init은 `PolicyPreparationService` 등록·상태 관찰만 하고 정책 record를 생산하지 않는다.
8. `reporting`은 current contract와 LLM role port를 조합하지만 외부 공개 adapter를 갖지 않는다.
9. `evaluation`은 production workflow를 직접 호출하지 않고 `purpose=EVALUATION` runtime 경로와 exact 평가 설정만 사용한다.
10. `interfaces/cli`는 application service만 호출한다.
11. concrete wiring은 위 repository tree에 포함된 `src/sastsimi/bootstrap.py` 하나에서 수행한다.
12. import cycle은 CI의 architecture dependency test로 차단한다.

`bootstrap.py`는 생성 순서와 dependency injection만 담당한다. 취약점 판단, state 전이와 권한 검사를 구현하지 않는다.

실행 호출 흐름은 이 Python import allowlist와 구분한다. runtime worker는 `ports/work_handler.py`의 `WorkHandler` port만 호출하며 업무 흐름 concrete service를 import하지 않는다. 업무 흐름은 주입된 port와 runtime public interface를 사용한다. 실제 handler 선택과 concrete instance 연결은 worker registry와 `bootstrap.py`의 dependency injection으로 수행한다.

`VerdictRouter`는 `reporting`이나 `chaining`의 concrete service를 import하지 않는다. `VerdictRouter`는 current final result를 읽어 정본의 `ActionRequest`와 work 등록 요청을 runtime public interface에 제출한다. Runtime Validator의 허가 전에는 CWE·Primitive·Chaining work를 만들지 않는다. `tests/contract/test_architecture_imports.py`는 이 import 경계와 외부 adapter 간 직접 의존 금지를 검사한다.

## 7. public interface 기준

구체 구현은 다음 Protocol 경계를 유지한다. 함수명은 물리 구현 기준이며 데이터 의미는 `contracts` 정본을 따른다.

```python
RecordRef = RunStoredDataRef | StoredDataRef | PolicyCacheRef
BudgetScopeRef = RunStoredDataRef | StoredDataRef

class RecordStore(Protocol):
    def get_exact(self, ref: RecordRef) -> Record: ...
    def stage_record(self, record: Record) -> RecordRef: ...
    def commit_transition(self, request: TransitionCommitRequest) -> TransitionCommit: ...

class ArtifactStore(Protocol):
    def stage_bytes(self, data: bytes, media_type: str) -> StagedArtifact: ...
    def commit(self, staged: StagedArtifact) -> StoredDataRef: ...
    def open_verified(self, ref: StoredDataRef) -> BinaryIO: ...

class LLMProviderAdapter(Protocol):
    async def probe(self, profile: ProviderProfile) -> CapabilityProbeResult: ...
    async def invoke(self, request: LLMInvocationRequest) -> LLMInvocationResult: ...
    async def cancel(self, invocation_id: str) -> CancellationResult: ...

class StaticToolAdapter(Protocol):
    async def probe(self, profile_ref: StoredDataRef) -> ToolCapabilityResult: ...
    async def run(self, request: StaticToolRequest) -> ToolRunResult: ...
    async def cancel(self, attempt_id: str) -> CancellationResult: ...

class PolicySourcePort(Protocol):
    async def fetch_official(self, request: OfficialPolicyFetchRequest) -> OfficialPolicySource: ...

class BudgetLedgerPort(Protocol):
    def reserve(self, request: BudgetReservationRequest) -> BudgetReservation: ...
    def commit_usage(self, request: BudgetCommitRequest) -> BudgetLedgerEntry: ...
    def release(self, request: BudgetReleaseRequest) -> BudgetReservation: ...
    def remaining(self, budget_scope_ref: BudgetScopeRef, analysis_id: str) -> BudgetRemaining: ...

class SandboxPort(Protocol):
    async def prepare(self, request: SandboxPrepareRequest) -> SandboxEnvironment: ...
    async def execute(self, request: ApprovedSandboxCommand) -> SandboxCommandRecord: ...
    async def cleanup(self, request: SandboxCleanupRequest) -> CleanupResult: ...
```

내부 application service의 최소 진입점은 다음과 같다. 이 service도 저장소나 외부 도구를 직접 만들지 않고 위 port와 Runtime Validator를 주입받는다.

```python
BudgetProfile = ExecutionBudgetProfile | WorkBudgetProfile | VerificationBudgetProfile | DynamicReproductionLifecycleProfile | BudgetProfileBinding
AnalysisPurpose = Literal["PRODUCTION", "EVALUATION"]

class PolicyPreparationService:
    async def start_or_reuse(self, analysis_ref: RunStoredDataRef) -> WorkExecutionState: ...

class BudgetProfileRegistry:
    def publish_draft(self, profile: BudgetProfile) -> RecordRef: ...
    def pin_execution_for_run(self, analysis_id: str, purpose: AnalysisPurpose, approval_ref: RunStoredDataRef | StoredDataRef) -> RunStoredDataRef: ...
    def activate_for_run(self, analysis_state_ref: RunStoredDataRef, binding_ref: StoredDataRef, approval_ref: RunStoredDataRef | StoredDataRef) -> StoredDataRef: ...
    def current_execution(self, analysis_id: str) -> RunStoredDataRef | None: ...
    def current_binding(self, analysis_id: str) -> StoredDataRef | None: ...

class EvaluationService:
    async def run(self, config_ref: StoredDataRef) -> EvaluationRunResult: ...
    def compare(self, result_refs: list[StoredDataRef]) -> EvaluationRecommendation: ...
```

`BudgetProfileRegistry.pin_execution_for_run`은 새로 발급한 `analysis_id`와 purpose를 받아 승인 근거에 맞는 run-local `ExecutionBudgetProfile`을 만들고 그 exact `RunStoredDataRef`를 반환한다. Orchestration Runtime은 같은 분석 시작 transaction에서 이 reference를 첫 `AnalysisRunState.execution_budget_profile_ref`에 기록하며, 그 transaction이 확정되기 전에는 `WORKSPACE_PREP`을 등록하지 않는다. `publish_draft`는 `status=DRAFT`만 받아 full binding 초안을 포함한 profile record를 만들 수 있고 이를 직접 ACTIVE로 만들지 않는다. `activate_for_run`은 workspace READY인 exact `AnalysisRunState`와 binding 초안, R8·사람 승인 reference를 받아 execution·work-kind·Verification·dynamic profile의 analysis·workspace·commit·purpose·상태·revision을 검사한다. 통과한 경우에만 승인 reference를 보존한 full ACTIVE binding revision과 `AnalysisRunState.budget_binding_ref` 갱신을 같은 CAS transaction으로 확정하고 exact `StoredDataRef`를 반환한다. `current_execution`과 `current_binding`은 반드시 `analysis_id`로 조회하며 purpose만으로 다른 실행의 current pointer를 찾지 않는다. `EvaluationService`는 Orchestration Runtime의 일반 분석 시작 경로를 호출해 `purpose=EVALUATION` analysis만 만들 수 있다. R8 Evaluation Runtime은 평가 결과를 집계·저장할 뿐 일반 `WorkExecutionState`를 직접 등록하거나 변경하지 않으며, 운영 registry current pointer도 바꾸지 않는다.

Protocol은 raw SDK client, SQLAlchemy Session, Docker client와 host path를 반환하지 않는다. `LLMProviderAdapter.invoke`는 schema·semantic 검사 전의 결과를 반환할 수 있지만 domain output 저장 권한은 없다.

`RecordRef`는 저장 계층의 공통 transport type일 뿐 domain별 허용 reference를 넓히지 않는다. `CodeWorkspace`·`AnalysisRunResult` 같은 run-level record는 `RunStoredDataRef`, 코드·가설·검증 결과는 `StoredDataRef`, 실행 간 정책 cache는 `PolicyCacheRef`만 사용한다. repository adapter는 요청한 record kind와 reference 종류가 맞지 않으면 I/O 전에 `RECORD_REVISION_MISMATCH`로 거절한다. `tests/contract/test_record_ref_kinds.py`와 `tests/security_negative/test_cross_domain_record_ref.py`에서 세 reference의 정상 경로와 교차 사용 거절을 각각 확인한다.

`PolicySourcePort`는 Program Catalog가 승인한 공식 URL과 source 설정만 받아 raw bytes·최종 URL·조회 시각·ETag·Last-Modified·게시 주체 근거를 반환한다. `policy/adapters/official_http.py`가 HTTP 구현이고, `Policy Collector`만 이를 호출해 exact 원문과 `PolicyCollectionResult`를 생산한다. `Policy Parser`는 Collector가 저장한 원문을 구조화한 `PolicyParserResult`만 만들며 `RunPolicyState`·`ProgramPolicyRecord`를 저장하지 않는다. 시험은 `tests/unit/policy/`, `tests/integration/test_run_policy_preparation.py`, `tests/contract/test_policy_source_port.py`, `tests/security_negative/test_unapproved_policy_source.py`에 둔다.

`BudgetLedgerPort`는 R8 trusted Budget Profile Registry가 게시한 exact profile만 사용한다. `BudgetService`는 `WORKSPACE_PREP`에는 `AnalysisRunState.execution_budget_profile_ref`의 run-level profile을, workspace READY 이후 모든 work에는 full `BudgetProfileBinding`을 사용한다. 후속 실행에서는 `WorkBudgetProfile`의 trusted `operation_kind`·역할 한도와 분석 전체·Verification·dynamic 한도를 함께 검사하고 가장 먼저 소진되는 제한을 적용한다. 새 work·attempt·외부 호출 전에 reservation을 원자 생성하고 실행 뒤 실제 사용량을 한 번만 commit하거나 미사용 예약을 release한다. 필요한 profile, 작업별 limit 또는 잔여량을 입증할 수 없으면 실행을 시작하지 않고 `BLOCKED + waiting_for=BUDGET`으로 둔다. token 사용량 하나가 제공되지 않았다는 이유만으로 차단하지 않는다. reservation·ledger·profile table과 migration은 `storage/models.py`, `storage/repositories.py`, `migrations/versions/`에 두고, bootstrap·작업별 한도 선택·동시 예약·취소·crash·중복 commit은 `tests/integration/budget/`와 `tests/security_negative/test_budget_double_debit.py`에서 검사한다.

## 8. schema·직렬화·ID

### 8.1 Pydantic과 JSON Schema

- 공통 model은 `src/sastsimi/contracts/`에서만 정의한다.
- `extra='forbid'`, 엄격 enum, timezone-aware datetime과 명시적 null을 기본으로 한다.
- JSON Schema는 `schemas/generated/<data_kind>/<major>.schema.json`으로 생성한다.
- 생성 schema는 직접 수정하지 않는다. model 변경 뒤 재생성하고 diff를 검토한다.
- schema version과 record revision은 서로 다른 값이다.
- MAJOR 변경은 기존 record에 현재 값을 추정해 채우지 않는다.

### 8.2 SASTSIMI Canonical JSON v1

hash·dedupe 계산 입력은 다음 순서로 만든다.

1. Pydantic model을 alias 없는 정본 field 이름으로 dump한다.
2. `exclude_none=False`로 null을 보존한다.
3. datetime은 UTC RFC 3339, 소수점 이하 6자리 고정 후 `Z`로 기록한다.
4. UUID는 소문자 hyphen 형식, enum은 정본 문자열 값으로 기록한다.
5. `NaN`, 양·음의 무한대와 binary float 기반 금액은 거절한다.
6. object key는 Unicode code point 순으로 정렬한다.
7. 배열 순서가 의미 없는 field는 schema별 semantic validator가 정한 key로 먼저 정렬한다. 순서가 의미 있는 배열은 원래 순서를 보존한다.
8. JSON number는 정수만 허용한다. 소수 정밀도가 필요한 값은 schema가 정한 scale의 decimal 문자열로 저장하며 exponent·앞자리 0·`-0`을 허용하지 않는다.
9. 문자열은 입력 code point를 그대로 보존하고 Unicode 정규화를 암묵적으로 수행하지 않는다. JSON control character만 RFC 8259 방식으로 escape하며 non-ASCII 문자를 `\u`로 강제 변환하지 않는다.
10. UTF-8, BOM 없음, `ensure_ascii=false`, 공백 없는 JSON bytes로 직렬화한다.
11. SHA-256 lowercase hex를 `content_hash` 또는 `input_hash`로 사용한다.

canonicalizer version은 `canonical-json-v1`로 configuration revision에 포함한다. version이 바뀌면 같은 logical record도 새 content hash가 되므로 별도 migration과 ADR이 필요하다.

최소 승인 fixture는 다음 값을 exact bytes와 hash로 고정한다.

```text
bytes: {"a":null,"b":"한글","n":1,"t":"2026-09-07T00:00:00.000000Z"}
utf8_length: 63
sha256: 957b116406dddaf7928bd028a12602346873237f935f866530949547422122da
```

테스트는 key 입력 순서 변경이 같은 bytes를 만드는 경우, 배열 순서 보존, set 성격 배열의 정렬, null 보존, Unicode code point 차이, timezone 변환, 금지된 float·NaN·infinity와 content hash 자기 포함 거절을 각각 독립 fixture로 둔다.

### 8.3 ID 생성

- `analysis_id`, `workspace_id`, `hypothesis_id`, `work_id`, `attempt_id`, `record_id`, `action_id`, `event_id`, `llm_call_id`는 `IdGenerator`가 발급하는 대표 예시다. 이것은 완전 목록이 아니며, 각 ID의 정확한 생성 주체·유일 범위·재사용 규칙은 [08 공통 계약의 식별자 표](../08-lightweight-data-contracts.md#식별자-생성저장참조-기준)가 유일한 정본이다. 구현은 별도 목록을 만들어 그 표와 경쟁시키지 않는다.
- LLM은 `proposal_id`, `question_id`, `validation_id`를 발급하지 않는다. 08번 표가 지정한 trusted 출력 검증 runtime 또는 application 생성 runtime이 source candidate를 source 결과에 넣기 전에 ID를 한 번 부여한다. ORCHESTRATION 등록 runtime은 source 결과가 COMMITTED된 뒤 같은 ID와 내용을 정본 record에 그대로 사용하며 다시 발급하지 않는다.
- `logical_record_id`는 최초 record 생성 시 발급하고 후속 revision이 보존한다.
- `program_id`는 승인된 Program Catalog가 발급하며, `commit_id`는 Git이 확정한 commit hash이므로 UUID로 다시 만들지 않는다.
- `dedupe_key`, `content_hash`, `input_hash`는 정해진 canonical bytes의 SHA-256이며 임의 ID가 아니다.
- 사용자가 준 문자열, LLM output과 tool output을 내부 ID로 채택하지 않는다.
- test는 deterministic fake generator를 주입하고 운영 generator와 섞지 않는다.

### 8.4 오류 코드 선택 순서

Runtime Validator는 같은 위반을 실행 위치마다 다른 코드로 만들지 않는다. 여러 검사가 동시에 실패하면 아래 순서에서 가장 먼저 확인된 근본 원인 하나를 `AnalysisError.code`로 쓰고, 나머지 실패는 `ActionCheck`에 모두 보존한다.

1. 지원하지 않는 MAJOR schema는 `SCHEMA_UNSUPPORTED`다.
2. 사람·CLI·외부 API 입력의 형식·필수값 오류는 `INPUT_ERROR`, LLM 출력의 schema·semantic 오류는 `INVALID_OUTPUT`이다.
3. 생산 권한·owner 위반은 `AUTHORITY_DENIED`, 현재 action에서 허용되지 않은 작업·선행조건 위반은 `ACTION_NOT_ALLOWED`다.
4. workspace·commit 불일치는 `WORKSPACE_MISMATCH`다.
5. 존재하는 record의 revision·content hash·previous link 불일치는 `RECORD_REVISION_MISMATCH`다.
6. 형식은 맞지만 current input·generation·config와 달라진 결과는 `STALE_RESULT`다.
7. current work의 active attempt가 아니면 `ATTEMPT_NOT_ACTIVE`다.
8. compare-and-set version 경쟁은 `STATE_VERSION_CONFLICT`, 허용표에 없는 상태 이동은 `STATE_TRANSITION_INVALID`다.
9. versioned 시간·비용·work·retry 상한 소진은 `BUDGET_EXCEEDED`다. token 계획값 초과만으로 이 코드를 만들지 않는다.
10. Provider·Git·정적 도구·정책·Sandbox·storage의 실행 실패는 각 adapter가 실제 원인을 공통 `AnalysisError.stage`와 기존 provider/tool error code로 변환한다. 알 수 없는 실패를 `FALSE | HOLD`나 `INVALID_OUTPUT`으로 바꾸지 않는다.

전용 오류 코드는 기존 코드로 원인을 구분할 수 없고 retry·상태·사용자 조치가 달라질 때만 ADR과 공통 계약 변경으로 추가한다. 메시지 문자열을 분기 조건으로 사용하지 않는다.

## 9. 저장 위치와 runtime data

repository 밖 runtime root는 `SASTSIMI_DATA_DIR`이 있으면 그 경로, 없으면 `platformdirs.user_state_dir('sastsimi')`로 계산한다. 실제 절대 경로는 local runtime registry에서만 사용한다.

```text
<runtime-root>/
├─ db/
│  └─ sastsimi.sqlite3
├─ artifacts/
│  └─ sha256/<first-2>/<remaining-hash>
├─ staging/
│  └─ <analysis-id>/<work-id>/<attempt-id>/<random-name>
├─ workspaces/
│  └─ <workspace-id>/repository
├─ logs/
│  └─ <analysis-id>.jsonl
├─ locks/
└─ quarantine/
```

- `runtime-root`, clone path와 credential path는 domain record·prompt·일반 log에 저장하지 않는다.
- record는 `StoredDataRef`와 content hash로 artifact를 가리킨다.
- 같은 hash의 immutable artifact는 공유할 수 있지만 writable workspace·container는 가설 간 공유하지 않는다.
- staging과 committed artifact는 같은 filesystem volume에 둬 atomic rename을 사용한다.
- quarantine은 hash 불일치·부분 파일을 보관하며 일반 consumer가 읽지 못한다.

## 10. 저장·transaction·복구

### 10.1 SQLite 설정

connection마다 다음을 강제한다.

```text
PRAGMA foreign_keys = ON
PRAGMA journal_mode = WAL
PRAGMA synchronous = FULL
PRAGMA busy_timeout = 5000
```

DB는 local filesystem에서만 지원한다. network share와 여러 host의 동시 writer는 `doctor`에서 거절한다. write transaction은 storage service가 짧게 유지하고 외부 LLM·tool·Docker 호출 중 열어 두지 않는다.

### 10.2 핵심 table 책임

| 논리 영역 | 물리 table | 핵심 constraint |
|---|---|---|
| run·workspace | `analysis_runs`, `code_workspaces` | `analysis_id`, `(workspace_id, commit_id)` |
| work·attempt | `work_states`, `work_attempts` | dedupe unique, work별 active attempt 최대 1 |
| record | `records`, `record_revisions` | `record_id` 전역 unique, logical revision unique |
| current pointer | `current_records` | logical key별 한 행, `state_version` CAS |
| action | `action_requests`, `action_decisions`, `action_checks` | action decision 1회 claim |
| transition | `transition_commits` | work·attempt·candidate binding unique |
| artifact | `artifacts` | content hash unique, committed path 불변 |
| LLM | `llm_invocations` | `llm_call_id` unique, retry/failover predecessor 검사 |
| event | `agent_log_events` | `event_id` 전역 unique, attempt별 sequence unique |
| migration | `alembic_version` | 현재 DB revision 하나 |

Pydantic domain model과 SQLAlchemy persistence model을 같은 class로 사용하지 않는다. repository adapter가 명시적으로 변환한다.

#### 10.2.1 핵심 result owner와 current 선택점

| result kind | 유일 저장 identity | source와 current 선택점 |
|---|---|---|
| `code_workspace` | `REPOSITORY_LOADER` | current `WORKSPACE_PREP` attempt → `AnalysisRunState.workspace_ref` |
| `tool_run_result` | `STATIC_ANALYSIS` | current `STATIC_TOOL` attempt → COMMITTED work output |
| `hypothesis_proposal` | 비-LLM `ORCHESTRATION` 등록 runtime | COMMITTED source output의 exact proposal → `ProposalProcessState.proposal_ref` |
| `analysis_run_result` | 비-LLM `ORCHESTRATION` run finalization runtime | 종료 시 current 결과 closure → `AnalysisRunState.analysis_result_ref` |

proposal의 의미와 문장은 Hypothesis·Verification·Chaining 역할이 만든다. trusted proposal 출력 검증 runtime이 source 결과 확정 전에 전역 ID를 한 번 부여하며, ORCHESTRATION 등록 runtime은 COMMITTED source 안의 같은 ID·문장·목록·순서를 별도 immutable record에 그대로 저장한다. 둘은 source result와 proposal 정본을 각각 확정하는 별도 atomic transition이고, 등록 단계가 새 가설 내용을 만들거나 바꾸지 않는다.

### 10.3 결과 확정 순서

```text
1. candidate record와 artifact를 staging에 작성
2. canonical bytes와 SHA-256 재계산
3. DB transaction A에서 candidate metadata와 TransitionCommit=PREPARED 기록
4. active attempt·state_version·input refs·ActionDecision claim을 CAS로 재검사
5. artifact를 content-addressed final path로 atomic rename
6. DB transaction B를 시작하고 record revision을 삽입
7. 같은 transaction B에서 current pointer, work output, 종료 state와 action outcome을 갱신
8. 같은 transaction B에서 TransitionCommit=COMMITTED로 바꾼 뒤 transaction을 commit
9. COMMITTED exact output만 consumer 조회에 노출
```

3~4에서 실패하면 `ABORTED`로 확정하고 staging을 정리한다. 5 뒤 6 전에 crash가 나면 final path의 orphan artifact는 reference가 없으므로 startup recovery가 hash를 확인해 재연결하거나 retention 뒤 정리한다. 6~8 중 crash가 나면 `PREPARED` journal과 DB transaction 결과를 대조한다. 일부 pointer를 임의 선택하지 않는다.

### 10.4 work claim과 중복 방지

- 등록 key: `analysis_id + work_type + subject_id + work_generation + dedupe_key`
- claim: `READY` 또는 허용된 retry/resume 상태이고 lease가 없을 때 `state_version` 조건부 UPDATE
- heartbeat: worker identity와 lease 만료만 갱신하며 domain 결과를 만들지 않음
- retry: 같은 work의 새 `attempt_id`, 입력과 `work_generation` 유지
- restart: 종료 뒤 사람이 승인한 새 generation과 새 work
- late result: active attempt와 다르면 `ATTEMPT_NOT_ACTIVE`, current pointer 갱신 금지
- 같은 dedupe key: 기존 work 반환, 새 파생 record·LLM 호출 생성 금지

### 10.5 startup recovery

1. migration revision과 DB integrity를 검사한다.
2. COMMITTED artifact hash와 file 존재를 표본이 아닌 전체 신규·미검사 집합에서 확인한다.
3. `PREPARED` transition을 candidate·artifact·CAS와 대조해 COMMITTED 재투영 또는 ABORTED로 끝낸다.
4. 만료 lease를 찾고 기존 attempt를 종료한 뒤 허용된 새 retry/resume attempt를 등록한다.
5. work output, domain state와 current pointer가 같은 exact ref인지 검사한다.
6. stale·late event를 이전 attempt history로 격리한다.
7. unresolved corruption은 `RECOVERY_FAILED`로 run을 차단한다.
8. 없는 근거, command 종료 event, PoC와 verdict를 복구 과정에서 만들지 않는다.

세부 recovery fixture는 [R3-03 복구 시험 계획](./03-recovery-test-plan.md)의 `R3-REC-*` ID를 사용한다.

### 10.6 migration

- 모든 변경은 Alembic revision 파일과 upgrade·downgrade 시험을 갖는다.
- 앱 시작은 pending migration이 있으면 자동 적용하지 않고 종료 코드 3으로 중단한다.
- 운영자는 `sastsimi db upgrade`로 명시 적용한다.
- downgrade가 record 의미를 잃으면 실행 전 백업을 요구하고 자동 실행을 거절한다.
- MAJOR contract 변경은 새 column/table에 저장하고 과거 record를 추정 backfill하지 않는다.
- CI는 빈 DB upgrade, 직전 release upgrade, downgrade 후 재-upgrade와 데이터 보존을 시험한다.

### 10.7 R3-03 복구 질문의 확정 기준

R3-03의 `RQ-01`~`RQ-10`은 아래 기준으로 구현한다. 이는 구현을 막는 미결정 목록이 아니라, 실제 fixture가 확인할 승인 후보 기준이다.

| RQ | 확정 기준 |
|---|---|
| `RQ-01` 저장 | §10.3의 staging → hash → `PREPARED` → CAS → atomic rename → SQLite transaction B → `COMMITTED` 순서를 사용한다. 파일은 rename 전에 flush·file sync하고, 시작 복구가 orphan·DB pointer·hash를 전수 대조한다. 네 core result owner와 current 선택점은 §10.2.1을 따른다. |
| `RQ-02` 오류 | §8.4의 우선순위로 한 개의 근본 `AnalysisError.code`를 선택하고 모든 실패 check는 `ActionCheck`에 남긴다. 원인을 알 수 없거나 안전한 복구를 입증하지 못하면 `stage=RECOVERY`, `code=RECOVERY_FAILED`로 후속 소비를 차단한다. |
| `RQ-03` migration | Alembic revision만 schema를 바꾼다. 앱 시작 중 자동 migration은 금지하고 pending·중단·현재 revision 불일치 시 exit 3으로 멈춘다. 검증된 upgrade/downgrade만 실행하며 의미 손실 rollback은 백업과 사람 승인이 없으면 거절한다. |
| `RQ-04` worker·외부 호출 불확실성 | SQLite의 `worker_id + lease_expires_at + state_version`을 한 transaction에서 비교해 lease를 회수한다. 외부 요청 전송 뒤 결과를 모르면 exact provider request ID로 공식 상태 조회가 가능할 때만 재조정한다. 조회·idempotency를 증명할 수 없으면 자동 재전송하지 않고 `RECOVERY_FAILED`, `BLOCKED`, `waiting_for=INPUT`으로 사람의 명시적 재시도·failover 결정을 기다린다. |
| `RQ-05` cancel·resume | `resume`은 같은 입력을 유지한 non-terminal `BLOCKED` run의 허용 work만 재개한다. `CANCELLED | COMPLETE | PARTIAL | FAILED` run은 되살리지 않는다. 같은 입력을 다시 실행하려면 사용자가 새 `run`을 요청해 새 `analysis_id`를 만든다. cancelled 조회는 exit 7, terminal 재개 요청은 exit 2다. |
| `RQ-06` 시간·비용 | `analysis_id` 발급 직후 exact ACTIVE run-level `ExecutionBudgetProfile`을 고정하고 이것으로만 `WORKSPACE_PREP`을 허용한다. workspace READY 뒤 exact ACTIVE `BudgetProfileBinding`을 고정하며, 이 binding은 execution·work-kind·Verification·dynamic profile을 모두 가리킨다. 후속 work는 trusted operation/role에 맞는 `WorkBudgetLimit` 하나와 적용 가능한 상위 한도를 함께 검사한다. attempt 실행 중 monotonic elapsed를 durable heartbeat 구간별로 누적하고 process off·BLOCKED 대기는 제외한다. 새 work·attempt·외부 호출은 `BudgetService`가 COMMITTED ledger와 active reservation을 한 transaction에서 읽고 reservation을 만든 뒤에만 시작한다. 성공·실패로 자원을 썼으면 actual usage를 한 번 commit하고, 실행 전 취소·거절이면 release한다. 같은 reservation의 중복 debit은 unique constraint로 차단한다. profile·작업별 limit·가격·잔여량을 입증하지 못하면 `BLOCKED + waiting_for=BUDGET`, 실제 한도 소진만 `BUDGET_EXCEEDED`다. crash 직전 미기록 구간과 provider가 주지 않은 token usage는 구조화된 unavailable 사유로 보존하며 token usage 미제공만으로 차단하지 않는다. |
| `RQ-07` repair | schema·semantic 실패 응답과 validation error를 먼저 durable invocation log로 남긴다. 각 repair는 같은 domain work의 새 `WorkAttempt`, `llm_call_id`, spec, action, decision과 `NEW` session을 사용하고 바로 앞 invalid call을 연결한다. 성공 output 하나만 current로 확정하며 중단·소진 시 invalid output을 승격하지 않는다. |
| `RQ-08` Sandbox 재생성·cleanup | health 또는 소유 상태를 확인할 수 없으면 `STATE_UNCERTAIN`으로 새 environment binding을 만들고 기존 writable container를 재사용하지 않는다. 자원은 analysis·hypothesis·work·attempt ownership label과 exact environment ref가 모두 맞을 때만 정리한다. cleanup 재호출은 같은 자원에 멱등이고, 실패·불확실 자원은 quarantine하여 다음 실행에 연결하지 않는다. |
| `RQ-09` AgentLog append | 같은 `event_id`와 같은 canonical hash의 재전달은 기존 durable ACK를 반환한다. 같은 ID의 다른 bytes 또는 같은 attempt의 같은 sequence에 다른 event가 오면 `RECOVERY_FAILED`로 거절한다. start만 있고 finish가 없으면 미확인 상태로 남기고 finish를 만들지 않으며 environment를 `STATE_UNCERTAIN`으로 처리한다. |
| `RQ-10` 동적 입력 변경 | Technical `REVISE`와 별도인 `RESTART_VERIFICATION_GENERATION` action을 같은 ACTIVE Verification owner만 요청한다. current process가 `VERIFYING`이고 reason이 request/profile exact revision 변경일 때 expected generation·부모 state version·old work/attempt/pointer를 CAS한다. 한 SQLite transaction에서 old DYNAMIC_REPRO·부모 VERIFICATION active attempt와 work를 `CANCELLED/INPUT_SUPERSEDED`로 닫고, generation+1의 새 VERIFICATION work·PlaybookApplication·질문·Pro/Con, 새 `DynamicReproductionState(NOT_REQUESTED)`와 두 current pointer를 확정한다. 기존 `verification_result_ref`가 null이면 유지하고 Technical REVISE 보완 중의 직전 final ref도 history reference로만 그대로 둔다. 새 request/dynamic work는 새 Pro·Con·initial assessment 뒤 별도 생성한다. old action·attempt·environment·PoC·CWE·Gate는 history로 격리하고, generation당 successor unique와 한 transaction으로 crash 전 rollback/후 complete를 보장한다. Recovery는 저장된 exact action을 재투영할 뿐 입력 변경 의미를 판단하지 않는다. |

adapter별 실제 request 상태 조회·idempotency, filesystem directory sync와 Docker health probe 지원 여부는 capability 시험 결과로 기록한다. 지원하지 않는 기능은 위 fail-closed 경로를 사용하며, 시험 미실행을 지원 성공으로 표시하지 않는다.

## 11. 설정과 secret

### 11.1 설정 precedence

```text
허용된 CLI option
→ 운영 환경 변수
→ 승인된 versioned TOML/YAML configuration
→ 코드의 안전한 기본값
```

상위 값이 하위 값을 덮을 수 있는 field는 allowlist로 제한한다. repository code·README, LLM output과 tool output은 configuration source가 아니다.

### 11.2 파일 형식

- 일반 실행 설정: `config/profiles/*.toml`
- Prompt Registry: `config/prompts/registry.yaml`
- prompt template: `src/sastsimi/prompts/templates/<role>/<task>/<semver>.md`
- Verification playbook: `config/playbooks/*.yaml`
- 정적 rule/query source: `config/static-rules/`
- JSON Schema: `schemas/generated/`

YAML은 `safe_load`만 사용하고 tag·object constructor·merge key를 거절한다. 각 파일은 canonical content hash와 schema validation을 통과해야 ACTIVE revision이 될 수 있다.

### 11.3 secret

- API key, cookie, OAuth token, password와 reusable session credential을 repository 파일에 넣지 않는다.
- config에는 환경 변수 이름이나 secret-store handle만 넣는다.
- API adapter는 호출 직전에 secret을 주입하고 PromptPayload·artifact·log에는 전달하지 않는다.
- 구독 adapter는 공식 CLI/SDK가 관리하는 인증 경계만 사용하며 browser cookie·profile을 읽지 않는다.
- redaction 실패는 `SECRET_EXPOSURE_BLOCKED`로 호출·저장을 차단한다.
- fake credential은 실제 secret과 구분되는 test-only sentinel을 사용한다.

## 12. Provider·모델·Prompt 기준

### 12.1 초기 구현 경로

1. `FakeProviderAdapter`로 22단계 vertical slice를 먼저 통과한다.
2. 실제 Provider 중 첫 구현 순서는 `OpenAIResponsesApiAdapter`다.
3. `PVD-01`~`PVD-15`를 통과한 exact environment·client·model 조합만 ProviderProfile로 등록한다.
4. Dynamic Reproduction의 runtime tool loop에 쓰려면 `PVD-16`도 통과해야 한다.
5. 구독 로그인과 다른 API Provider는 같은 port의 별도 adapter로 추가한다.

여기서 “첫 구현 순서”는 운영 기본 Provider 확정이나 품질 우위를 뜻하지 않는다. 통과한 ProviderProfile이 없으면 prompt registry entry는 `DRAFT`이고 실제 LLM 호출을 시작하지 않는다. PVD를 통과한 profile은 먼저 `purpose=EVALUATION` entry에서만 사용할 수 있으며, 이것만으로 PRODUCTION entry를 활성화하지 않는다.

### 12.2 모델 선택

- role·task별 PromptRegistryEntry가 허용 `provider_profile_refs`를 primary와 explicit fallback 순으로 가리킨다.
- 실제 호출은 그중 하나의 exact `provider_profile_ref + model`을 사용한다.
- Agent code와 template는 model ID를 알지 못한다.
- model 변경은 새 LLMCallSpec·ActionRequest·ActionDecision·call·session을 만든다.
- provider/model을 조용히 바꾸는 fallback은 금지한다.
- R8 평가가 품질·시간·실제 usage·비용을 비교해 registry 새 revision을 제안한다.

### 12.3 Prompt

- `agent_role + task_kind + purpose`마다 ACTIVE registry entry는 최대 하나다.
- template, context slot, output schema, semantic validator, provider refs, limits, retry, tool, redaction, session policy를 exact reference로 고정한다.
- EVALUATION entry는 평가 run에서만 사용하고, PRODUCTION ACTIVE entry는 같은 실행 의미를 검증한 exact R8 `ACCEPT_FOR_PRODUCTION` recommendation과 사람 승인을 요구한다.
- Pro와 Con은 같은 `debate_input_hash`, 서로 다른 template·call ID·`NEW` session을 사용한다.
- repository·정책 원문·도구 출력·이전 LLM 결과는 `UNTRUSTED_DATA`다.
- schema failure와 semantic failure는 domain output 미저장 후 제한 repair로 처리한다.
- 비-LLM 구성요소용 prompt entry는 만들지 않는다.

### 12.4 R8 예산·평가 구현

예산은 `runtime/budget_registry.py`, `runtime/budget_service.py`와 `ports/budget_ledger.py`를 통해서만 게시·검사·차감한다. R8 owner가 profile 내용을 승인하면 trusted `BudgetProfileRegistry`가 exact `ExecutionBudgetProfile`, 역할·작업 종류별 `WorkBudgetProfile`, `VerificationBudgetProfile`, `DynamicReproductionLifecycleProfile`과 `BudgetProfileBinding` revision을 저장한다. `analysis_id` 생성 직후에는 그 analysis의 run-local execution profile을 먼저 고정해 `WORKSPACE_PREP`만 허용하고, workspace READY 뒤 같은 analysis의 full ACTIVE binding을 최대 하나 고정한 뒤 나머지 work를 시작한다. 같은 purpose의 분석이 동시에 실행돼도 각 analysis는 자기 execution profile·binding·reservation·ledger만 조회한다. Runtime Validator는 후속 action마다 full binding과 선택한 exact work-kind limit을 `checked_config_refs`에 고정한다. 숫자가 아직 승인되지 않은 profile은 `DRAFT`이고 새 실행을 허용하지 않으며, 07번 역할표의 숫자를 코드 상수나 숨은 별도 설정으로 사용하지 않는다.

```text
WORKSPACE_PREP: run-level ACTIVE execution profile 확인
후속 work: full ACTIVE binding + exact work-kind limit 확인
→ COMMITTED ledger + active reservation으로 잔여량 계산
→ BudgetReservation=RESERVED를 atomic 생성
→ action claim과 실제 실행
→ 실제 사용이면 BudgetLedgerEntry append + reservation COMMITTED
→ 실행 전 취소·거절이면 reservation RELEASED
```

- profile이나 비용·잔여량을 확인할 수 없으면 `BLOCKED + waiting_for=BUDGET`이며 새 side effect를 만들지 않는다.
- 승인 한도를 실제로 소진한 경우만 `BUDGET_EXCEEDED`다.
- 같은 `reservation_id`에는 ledger entry가 최대 하나이고 commit/release 재호출은 기존 terminal 결과를 반환한다.
- crash 뒤 실제 사용 여부를 확인할 수 없으면 예약을 임의 해제하거나 0원으로 확정하지 않는다.
- token usage 미제공은 구조화된 unavailable 사유로 남기며, 그것만으로 호출을 차단하지 않는다.
- `LLMInvocationResult`·`LLMInvocationLog`는 `UsageMeasurement`, 최종 결과는 `ResourceUsageSummary`를 사용한다. 비용은 금액·통화·가격 revision과 함께 기록한다.

R8 평가는 `evaluation/service.py`가 `evals/configs/`의 exact `EvaluationRunConfig`를 읽어 `evaluation/runner.py`에 전달한다. runner는 같은 corpus·ground truth·grader·output schema·budget을 고정하고 비교 대상의 Provider·model·session·prompt 조합만 바꾼 `purpose=EVALUATION` 분석을 실행한다. `evaluation/grader.py`가 사람 정답과 결과를 비교하고 `evaluation/recommendation.py`가 `EvaluationRunResult`와 `EvaluationRecommendation`을 만든다.

- CLI는 `sastsimi eval run <config-ref>`, `sastsimi eval result <evaluation-run-id>`, `sastsimi eval compare <evaluation-run-id>...`를 제공한다.
- 평가 설정·결과·추천은 record/artifact store에 exact reference로 저장한다.
- PVD 통과는 기술적 호출 가능성만 뜻한다. 평가 전 조합은 `PromptRegistryEntry(purpose=EVALUATION)`에서만 사용할 수 있다.
- `PromptRegistryEntry(purpose=PRODUCTION,status=ACTIVE)`는 exact `ACCEPT_FOR_PRODUCTION` 추천과 사람 승인이 있어야 한다.
- Evaluation Runtime은 운영 Finding·Primitive·Gate·ReportDraft와 production registry current pointer를 바꾸지 못한다.
- 시험은 `tests/unit/evaluation/`, `tests/integration/evaluation/`, `tests/e2e/test_evaluation_comparison.py`, `tests/security_negative/test_evaluation_production_isolation.py`에 둔다.

## 13. 정적 도구와 외부 process

모든 외부 명령은 인자 배열로 `asyncio.create_subprocess_exec`를 사용하고 `shell=False`를 강제한다. command 원문을 LLM output에서 직접 조립하지 않는다.

| dependency | adapter 책임 | preflight | timeout·취소 | 오류 결과 |
|---|---|---|---|---|
| Git | clone·checkout·HEAD 확인 | version, URL scheme, destination 경계 | process group 종료 | `CLONE_FAILED`, `CHECKOUT_FAILED` |
| AST parser | 지원 언어 parse와 위치 | parser version·언어 | file·run 한도 | tool error·DataGap |
| CodeQL CLI | DB·query pack 실행 | CLI·pack exact version | 단계별 timeout | `ToolRunResult` 실패/부분 |
| OpenGrep CLI | ruleset 실행 | CLI·catalog exact ref | 단계별 timeout | `ToolRunResult` 실패/부분 |
| Docker | build·container·network·cleanup | Engine API·Linux container·profile | controller 취소·kill | dynamic `BLOCKED | FAILED` |
| LLM SDK/CLI | 호출·session·usage 정규화 | ProviderProfile capability | adapter 취소 | `AUTH_REQUIRED`, `RATE_LIMITED`, `TIMED_OUT`, `FAILED` |

도구가 0건을 반환한 것과 미실행·실패를 분리한다. 정적 도구는 verdict를 만들지 않고 `StaticFactBundle`에 사실·gap·오류를 함께 제공한다.

## 14. R7 구현 경계

```text
R6 DynamicReproductionRequest
→ Dynamic Reproduction Agent가 Sandbox 경계 밖에서 requirements·plan 생성
→ Runtime Validator가 action·exact 입력·예산 검사
→ Sandbox Controller가 외부 격리 경계 검사
→ Reproduction Setup Automation이 승인된 recipe·image·container·environment 준비
→ 승인된 Sandbox 안에서 Dynamic Reproduction Agent가 candidate·tool request·command·관찰 생성·실행
→ Dynamic Reproduction Agent가 실행 관측에 대한 conclusion 생성
→ Reproduction Session Manager가 실제 AgentLog와 대조해 validated PoC·DynamicReproductionResult 확정
→ R6가 DynamicReproductionResult를 소비해 final verdict 결정
```

- Dynamic Reproduction Agent는 Docker daemon·host filesystem을 직접 호출하지 않는다.
- Reproduction Setup Automation은 동적 결과의 `SUPPORTED | DISPROVED | INCONCLUSIVE`를 판단하지 않는다.
- Sandbox Controller는 공식 정책 의미·CWE·verdict를 판단하지 않는다.
- Reproduction Session Manager는 Agent conclusion과 실제 log를 대조하지만 새 의미 결론을 만들지 않는다.
- validated `poc_ref`는 같은 attempt의 `SUCCEEDED + SUPPORTED`, 실제 candidate 실행 event, exact environment·recipe·command·digest·commit이 모두 있을 때만 생성한다.
- final `TRUE`는 같은 generation의 exact `DynamicReproductionRequest`, `DynamicReproductionResult`와 validated PoC가 모두 있어야 한다.
- 한 Verification generation에는 `DYNAMIC_REPRO` work를 최대 하나만 만든다. `POC_CONFIRMATION`과 `VERDICT_EVIDENCE`를 같은 generation에서 둘 다 등록하지 않는다.
- Agent가 같은 session에서 command·PoC·관찰을 조정하는 것은 같은 attempt다. container 상태를 신뢰할 수 없을 때의 재생성도 AgentLog에 이전·새 환경을 연결하고 같은 session 정책이 허용하는 범위에서는 같은 attempt로 처리한다.
- provider·process crash로 session을 다시 시작하면 같은 work의 새 `attempt_id`, `trigger=RETRY`다. 끝난 attempt의 실패 결과·log는 history에 남고 current 결과로 합치지 않는다.
- 재인증·승인·외부 환경·resource처럼 runtime 밖 조건을 기다리면 work를 `BLOCKED`로 두고, 조건이 해결된 뒤 같은 input으로 새 `attempt_id`, `trigger=RESUME`를 사용한다.
- current `DynamicReproductionRequest`를 교체해야 하거나 승인된 새 `sandbox_profile_ref`를 적용해야 하면 retry/resume이 아니다. 같은 ACTIVE Verification owner가 old current 입력과 exact 변경 근거를 고정해 새 generation을 요청한다. runtime은 old work 종료와 새 Verification·application·질문·Pro/Con을 원자 확정하며, 새 Pro·Con과 초기 판단 뒤 여전히 필요할 때만 새 request와 `DYNAMIC_REPRO` work를 만든다.
- run-init에서는 Docker image·container를 준비하지 않는다. R7의 모든 변경 작업은 current 가설의 exact request·generation·attempt 안에서만 허용한다.

## 15. Gate·Chaining·Reporter 구현 경계

```text
current final TRUE Verification
→ CWE Labeling Agent
→ Technical Evidence Gate Agent
→ Rule Scope Impact Gate Agent
→ trusted Finding normalization
→ Reporter Agent
→ ReportDraft
→ Agent automation end
```

- Technical `REVISE`는 같은 ACTIVE Verification owner의 새 generation으로 직접 돌아간다.
- `FALSE | HOLD`는 CWE·두 Gate·Reporter 입력이 아니다.
- Rule Scope 결과와 testing restriction mapping은 Primitive Admission Runtime이 기계적으로 적용한다.
- Chaining Agent가 낸 `ChainingResult.chained_hypothesis_proposals`는 전역 runtime이 `origin=CHAINING` 새 가설로 등록하고 전체 Verification을 다시 수행한다. `VerificationResult.material_child_proposals`는 `origin=VERIFICATION` 출력이므로 이 경로와 섞지 않는다.
- Reporter는 current final `TRUE`, current CWE, 두 Gate와 exact Finding만 소비한다.
- `ReportDraft`에서 Agent 자동화가 끝난다. 사람 검토·수정·제출·공개용 자동 state/action/API를 만들지 않는다.

## 16. CLI 계약

### 16.1 명령

```text
sastsimi doctor [--format text|json]
sastsimi run <repository> --revision <commit> --program <program-id> [--profile <profile-key>]
sastsimi status <analysis-id> [--watch]
sastsimi cancel <analysis-id>
sastsimi resume <analysis-id>
sastsimi result <analysis-id> --format json|summary
sastsimi eval run <config-ref>
sastsimi eval result <evaluation-run-id>
sastsimi eval compare <evaluation-run-id>...
sastsimi cleanup <analysis-id> [--artifacts] [--workspace]
sastsimi db current
sastsimi db upgrade [revision]
sastsimi db downgrade <revision>
```

`run`은 repository URL 또는 local Git repository와 정확한 revision을 요구한다. branch 이름을 받더라도 clone 뒤 commit hash로 확정한다. `resume`은 기존 입력을 바꾸지 않으며 외부 조건 해소 후 허용된 work에 새 RESUME attempt를 만든다.

### 16.2 exit code

| code | 의미 | 예 |
|---:|---|---|
| 0 | 명령 성공 | run 등록, 상태 조회, 결과 출력, cleanup 성공 |
| 2 | 사용자 입력 오류 | 잘못된 ID·option·repository 형식 |
| 3 | 설정·schema·migration 오류 | 잘못된 config, pending migration |
| 4 | 인증·Provider capability 오류 | credential 없음, 미지원 profile |
| 5 | 복구 가능한 차단 | 외부 설정·resource 대기, retry 가능 |
| 6 | 복구 불가능한 실행 실패 | clone·tool·storage retry 소진 |
| 7 | 취소됨 | 사용자 취소가 확정됨 |
| 8 | 결과 미완료 | 아직 final result 없음 |
| 9 | 무결성·stale 오류 | hash, attempt, current pointer 불일치 |
| 10 | 예상하지 못한 내부 오류 | 구조화 오류 record와 trace ID 생성 |

취약점이 발견되지 않은 정상 분석은 code 0이다. final `TRUE`가 있어도 명령 성공이면 code 0이다. verdict를 process 오류로 표현하지 않는다.

### 16.3 출력

- `text`: 사람이 읽는 짧은 상태와 다음 행동
- `json`: versioned CLI envelope, ID·상태·오류 코드·exact result ref
- stdout: 요청한 정상 결과
- stderr: 오류와 진단
- secret·host 절대 경로·hidden reasoning: 어느 출력에도 없음

## 17. 테스트와 CI

### 17.1 로컬 명령

```text
uv sync --frozen --all-groups
uv run ruff format --check .
uv run ruff check .
uv run mypy --strict src tests
uv run pytest tests/unit -q
uv run pytest tests/contract -q
uv run pytest tests/integration -q
uv run pytest tests/e2e -q
uv run pytest tests/security_negative -q
powershell -File scripts/validate-architecture-docs.ps1
git diff --check
```

Windows PowerShell과 PowerShell 7에서 문서 validator가 같은 결과를 내야 한다. Markdown과 설정 파일은 LF로 커밋해도 checkout의 CRLF 변환으로 검사 결과가 달라지지 않아야 한다.

### 17.2 CI job

1. `docs`: Markdown link, architecture validator, diff whitespace
2. `quality`: Ruff format/lint, mypy strict
3. `unit-contract`: unit + Pydantic schema + canonical JSON fixture
4. `storage`: migration, transaction, CAS, crash recovery와 artifact corruption
5. `integration-fake`: fake Provider·static tool·Sandbox
6. `e2e-fake`: 한 가설 22단계와 여러 가설 bounded parallel
7. `security-negative`: prompt injection, secret, stale, path, Sandbox 외부 경계
8. `capability`: 명시 실행 시 실제 Git·CodeQL·OpenGrep·Docker·Provider probe

PR 필수 job은 1~7이다. 실제 credential·외부 서비스가 필요한 8은 격리된 승인 환경에서 실행하고, 미실행을 성공으로 표시하지 않는다.

### 17.3 fixture 규칙

- 정상 fixture와 각 필수 field 누락 fixture
- 다른 analysis·workspace·commit·hypothesis·generation·attempt 혼합
- schema-valid이지만 semantic-invalid인 reference
- provider auth·rate limit·timeout·invalid output
- 정적 0건·미실행·부분 실패
- dynamic candidate만 존재·실행 실패·INCONCLUSIVE·validated PoC
- Gate REVISE 새 generation과 이전 결과 재사용 차단
- Chaining 최초 빈 lineage와 조상 closure 누락·추가
- Reporter upstream 변경 뒤 stale draft 재사용 차단
- crash 지점별 PREPARED·pointer·late event 복구

## 18. 한 명 구현 순서

각 단계는 앞 단계 test와 회귀 검사를 통과한 뒤 시작한다.

1. `pyproject.toml`, package, config와 test skeleton
2. 공통 Pydantic contract, JSON Schema export, canonical JSON과 exact reference validator
3. SQLite·SQLAlchemy·Alembic, artifact store, work/attempt, Action, TransitionCommit와 startup recovery
4. fake Provider·static tool·Sandbox로 한 가설의 22단계 vertical slice
5. Repository Loader, AST·CodeQL·OpenGrep adapter와 StaticFactBundle
6. Provider adapter 첫 경로, Prompt Registry·Builder와 11개 Agent wrapper
7. R6 요청과 R7 네 구성요소, AgentLog·validated PoC
8. CWE Labeling, 두 Gate, Finding normalization과 Reporter
9. Primitive Admission, Chaining과 여러 가설 bounded parallel 처리
10. cancel·retry·resume·explicit failover·crash recovery와 security-negative 전체
11. 추가 API·구독 Provider adapter의 capability 시험
12. R8 corpus로 Provider·모델·session·prompt의 품질·시간·실제 usage·비용 평가

## 19. 첫 vertical slice 완료 조건

- repository와 exact commit을 입력해 CodeWorkspace를 준비한다.
- fake AST·SAST 결과를 StaticFactBundle로 정규화한다.
- Hypothesis·Pro·Con·Verification의 schema·semantic validation을 통과한다.
- fake 동적 결과가 같은 generation·attempt의 validated PoC와 연결된다.
- current final TRUE가 CWE와 두 Gate를 순서대로 통과한다.
- Finding normalization 뒤 Reporter가 ReportDraft를 만든다.
- ReportDraft 이후 자동 제출·공개 action이 없다.
- 상태·결과·TransitionCommit과 current pointer가 같은 exact reference를 가리킨다.
- 중간 오류가 FALSE나 HOLD로 바뀌지 않는다.
- 취소·재시작 뒤 duplicate·stale·late 결과가 current로 연결되지 않는다.
- AnalysisRunResult가 소요 시간·사용량·가설 수·오류·결과 reference를 보존한다.

이 완료 조건은 모듈 연결 증거다. 실제 취약점 탐지 정확도, 실제 Provider 운영 지원, 실제 Docker 보안 검증과 성능 완료를 뜻하지 않는다.

## 20. 운영 전 추가 Gate

구현 완료만으로 운영하지 않는다. 다음 증거가 필요하다.

- R1~R8 계약 시험과 security-negative 통과
- 실제 static tool version·rule/query pack 승인
- 실제 ProviderProfile capability와 약관·credential 경계 검토
- R7 Docker 외부 경계와 cleanup 시험
- R8 evaluation corpus의 품질·시간·usage·비용 기준 충족
- secret redaction과 log 보존 정책 승인
- migration·backup·restore·crash recovery rehearsal
- 사람이 ReportDraft를 검토하는 운영 절차

## 21. 검토 책임

| 역할 | 반드시 확인할 범위 |
|---|---|
| R1 | Hypothesis·Chaining wrapper, Primitive·lineage·새 가설 등록 |
| R2 | Git·AST·CodeQL·OpenGrep, StaticFactBundle·Context·tool 0건/미실행 |
| R3 | repository 구조, port/adapter, Provider·Prompt, CLI·통합·복구 |
| R4 | schema·ID·exact ref·상태·Action·transaction·권한·오류 |
| R5 | CWE·두 Gate·Finding·Reporter TRUE-only·ReportDraft 종료 |
| R6 | Pro·Con·Verification·playbook·동적 요청·final verdict |
| R7 | Dynamic Reproduction Agent·Reproduction Setup Automation·Controller·Session Manager |
| R8 | evaluation·budget·elapsed·usage·비용·resource profile |

각 검토는 검토한 commit SHA와 담당 section을 남긴다. “전체적으로 문제없음”만으로 필수 검토를 대신하지 않는다.

## 22. 최종 검토와 동기화 결과

1. PR #116이 `main`의 `07bd6549a676419c0e720f940ba7abd1b82aea0d`로 병합됐다.
2. R3-03 복구 계획의 `RQ-01`~`RQ-10`은 §10.7의 확정 기준을 가리킨다.
3. Issue #89, Issue #92와 R3 상위 Issue #4가 모두 종료됐다.
4. Primitive가 COMMITTED된 뒤에만 Chaining을 시작하는 규칙과 R1~R8 역할 경계를 최종 기준에 보존했다.
5. Final PR #117은 위 main SHA를 검토 시작 기준으로 사용했고, exact head `0647514...`와 merge 뒤 `main`에서 전체 validator와 diff check를 실행했다.

이 완료 기록은 설계와 구현 준비 기준의 확정이다. 실제 모듈·시험·Provider·Sandbox가 구현됐다는 뜻은 아니다.
