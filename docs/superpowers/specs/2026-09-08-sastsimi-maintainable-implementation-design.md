# SASTSIMI 유지보수 중심 구현 전환 설계

- 상태: `APPROVED_FOR_IMPLEMENTATION`
- 승인 근거: PR #119, merge commit `5657fc7b51af33271a940af37ca48bbfcdc14553`
- 기준 `main`: `691585cd4bd26d6f7bc4d173868e5a710d829126`
- 구현 기준: Architecture v5 `DESIGN_APPROVED / NOT_IMPLEMENTED`
- 범위: 저장소 정리, 구현 패키지 경계, 구현·검토·PR 순서

## 1. 목적

Architecture v5의 역할·데이터·상태·보안 계약을 실제 Python 프로그램으로 옮긴다. 첫 구현은 한 사람이 로컬에서 실행할 수 있는 모듈형 단일 애플리케이션으로 만들되, Provider·저장소·정적 도구·Sandbox를 좁은 port 뒤에 둬 교체와 시험이 쉽도록 한다.

유지보수 목표는 다음과 같다.

- 한 모듈은 한 가지 책임만 가진다.
- Agent, 업무 흐름, 외부 도구와 저장 구현을 서로 분리한다.
- 공통 계약과 권한 검사를 여러 위치에 복사하지 않는다.
- 외부 서비스 없이 fake adapter로 전체 흐름을 재현할 수 있다.
- 파일 위치와 import 방향을 자동 시험으로 강제한다.
- 현재 구현에 필요한 문서와 과거 작업 기록을 쉽게 구분한다.

## 2. 정리 범위와 안전 경계

정리 대상은 `SASTsimi/sastsimi` Git 저장소 내부로 한정한다. 상위 `SAST시미` 폴더의 발표자료, 이미지, 다른 저장소, 임시 산출물과 개인 파일은 건드리지 않는다.

### 유지

- `README.md`, `CONTRIBUTING.md`
- `docs/architecture-v5/01`~`13`, `verification-playbooks.md`, 구현 기준선
- `docs/review/decisions/`의 ADR과 상태 인덱스
- 최종 승인·출처·미해결 위험을 증명하는 review 문서
- `docs/governance/`, `docs/GLOSSARY.md`, `docs/DOCUMENT_GUIDE.md`
- 쉬운 설명을 제공하는 Architecture v5 Wiki

### 현재 작업 트리에서 제거할 수 있는 항목

완료된 과거 설계 작업 문서는 Architecture v5 정본이나 구현 입력이 아니지만, 현재 validator와 provenance가 일부 파일을 검토 이력으로 요구한다. 따라서 `docs/superpowers/plans/`와 `docs/superpowers/specs/`를 폴더 단위로 일괄 삭제하지 않는다.

첫 정리 PR은 삭제 후보를 파일별 allowlist로 명시하고 다음 조건을 모두 만족한 파일만 제거한다.

- 정본·ACCEPTED ADR·최종 승인 문서가 해당 파일의 내용에 의존하지 않는다.
- `rg`로 확인한 inbound link가 없거나 새 정본·ADR 링크로 안전하게 교체됐다.
- Architecture validator가 해당 파일을 요구하지 않도록 provenance 검사를 안전하게 이전했다.
- `DOCUMENT_GUIDE.md`와 `docs/superpowers/README.md`를 같은 PR에서 동기화했다.
- clean checkout에서 문서 validator, 로컬 Markdown 링크 검사와 `git diff --check`가 통과한다.

조건을 하나라도 입증하지 못한 기록은 삭제하지 않고 현재 위치에 보존한다. Git history에서 조회할 수 있다는 이유만으로 현재 validator가 요구하는 승인 증거를 제거하지 않는다.

### 이동 또는 이름 변경

- 구현 중 장기 진행 기록은 `.superpowers/sdd/sastsimi-complete-implementation/progress.md` 한곳에서 관리한다.
- 현재 구현 설계와 실행 계획은 날짜와 목적이 드러나는 이름을 사용한다.
- 같은 내용을 담은 두 개의 prompt template, schema 또는 설정 파일을 만들지 않는다.
- 파일 이동이 외부 링크를 깨뜨릴 때는 불필요한 이동보다 현재 위치 유지와 인덱스 정리를 우선한다.

### 삭제하지 않는 항목

- ACCEPTED ADR
- 최종 승인 근거
- 데이터 provenance와 역할별 승인 기록
- 미해결 위험과 운영 전 활성화 조건
- 정본을 쉽게 설명하는 Wiki

## 3. 구현 방식 선택

### 선택 A. 승인된 계층형 모듈 단일 애플리케이션 — 채택

하나의 Python process 안에서 역할별 package를 분리하고 SQLite work claim으로 제한된 병렬 처리를 수행한다. 외부 의존성은 port/adapter로 분리한다.

장점은 로컬 실행, transaction, 복구와 전체 추적이 단순하고 Architecture v5의 권한 경계와 일치한다는 점이다. 첫 구현에 필요한 운영 복잡도가 가장 작다.

### 선택 B. 과거 MVP 코드를 가져와 점진적으로 교체 — 채택하지 않음

초기 파일 수는 줄일 수 있지만 과거 저장소는 v0.x 계약과 이전 Agent 흐름을 구현한다. 이를 가져오면 이름은 같지만 의미가 다른 schema와 상태가 섞이고, 기존 동작을 보존하기 위한 호환 코드가 새 구조를 복잡하게 만든다.

공통 subprocess·redaction처럼 의미가 독립된 유틸리티만 새 계약 시험을 먼저 만든 뒤 선택적으로 이식할 수 있다.

### 선택 C. Agent별 서비스와 외부 Queue — 채택하지 않음

분산 확장은 쉽지만 network failure, 중복 전달, 분산 transaction과 운영 배포를 첫 구현부터 추가한다. 현재 측정된 확장 요구가 없으며 ADR-015와도 충돌한다.

## 4. 코드 구조

승인된 R3-06 구조를 기본으로 사용한다. 다만 구현 모듈 맵에 등장하지만 물리 위치가 없던 가설 내부 업무 흐름을 아래 세 package에 명시적으로 둔다.

```text
src/sastsimi/
├─ contracts/          Pydantic 데이터, enum, ID, exact reference
├─ ports/              저장·Provider·도구·Sandbox·work handler Protocol
├─ config/             typed 설정, 우선순위, secret handle
├─ runtime/            work·attempt·action·transition·예산·복구
├─ orchestration/      분석 시작, 전역 가설 등록·배정·전체 집계
├─ verification/       Debate, initial/final 판정, REVISE generation 흐름
├─ reproduction/       R6 요청과 R7 실행 구성요소를 잇는 동적 재현 흐름
├─ chaining/           Primitive 조회·matching·새 가설 제안 흐름
├─ prompts/            registry·projection·builder·출력 검사
├─ agents/             11개 LLM 역할의 얇은 wrapper
├─ policy/             공식 정책 준비·수집·cache
├─ reporting/          CWE·두 Gate·Finding·admission·ReportDraft 흐름
├─ evaluation/         운영과 격리된 R8 평가
├─ providers/          Provider adapter
├─ static_analysis/    Git·AST·CodeQL·OpenGrep·Context adapter
├─ sandbox/            Setup Automation·Controller·Session Manager·Docker adapter
├─ storage/            SQLite·Alembic·artifact adapter
├─ interfaces/cli/     argparse 입력·출력 adapter
└─ bootstrap.py        concrete 구현 조립만 수행
```

`verification/`, `reproduction/`, `chaining/`은 새 Agent나 새 권한이 아니다. 기존 설계에 있던 업무 흐름 서비스의 물리 위치만 고정한다.

서비스의 exact 위치는 다음과 같이 고정한다.

| 서비스 | module | 책임 |
|---|---|---|
| `DebateService` | `verification/debate_service.py` | 같은 입력의 Pro·Con child work fan-out과 결과 join |
| `VerificationService` | `verification/service.py` | initial assessment와 최종 검증 결과 합성 |
| `VerdictRouter` | `verification/verdict_router.py` | final FALSE·HOLD·TRUE에 맞는 다음 work 등록 요청 생성 |
| `RevisionWorkflow` | `verification/revision_workflow.py` | Technical `REVISE`의 같은 owner·새 generation 전환 |
| `DynamicReproductionService` | `reproduction/service.py` | R6 요청과 R7 구성요소의 실행 순서 연결 |
| `ChainingService` | `chaining/service.py` | exact Primitive index 고정, Chaining 호출과 새 proposal 전달 |

`VerdictRouter`는 `reporting`이나 `chaining`의 concrete service를 import하지 않는다. current final result를 읽어 정본에 이미 정의된 `ActionRequest`와 work 등록 요청을 runtime public interface에 제출할 뿐이며, Runtime Validator의 허가 전에는 CWE·Primitive·Chaining work를 만들지 않는다. 실제 handler 선택과 concrete instance 연결은 worker registry와 `bootstrap.py`의 dependency injection으로 수행한다.

## 5. 의존 방향

아래 화살표는 왼쪽 package가 오른쪽 package의 공개 인터페이스를 import할 수 있다는 뜻이다.

```text
ports -> contracts
config -> contracts
runtime -> contracts, ports, config
prompts -> contracts, ports, config
agents -> contracts, ports, prompts
orchestration -> contracts, ports, runtime
verification -> contracts, ports, runtime, agents
reproduction -> contracts, ports, runtime, agents
chaining -> contracts, ports, runtime, agents
policy -> contracts, ports, runtime, agents, config
reporting -> contracts, ports, runtime, agents
evaluation -> contracts, ports, runtime, agents, config
providers/static_analysis/sandbox/storage -> contracts, ports, config
interfaces/cli -> orchestration, runtime, evaluation
bootstrap -> 모든 concrete 구현의 생성·주입
```

핵심 규칙은 다음과 같다.

- `contracts`는 다른 SASTSIMI package를 import하지 않는다.
- 외부 adapter끼리는 직접 호출하지 않는다.
- LLM Agent는 DB, SQLAlchemy, Docker SDK, Provider SDK와 전역 상태를 직접 사용하지 않는다.
- runtime worker는 `WorkHandler` port만 호출한다.
- `bootstrap.py`는 handler와 adapter를 연결하지만 상태 전이·취약점 판정·권한 검사를 구현하지 않는다.
- import 경계는 `tests/contract/test_architecture_imports.py`에서 검사한다.

## 6. 책임이 커지는 파일 방지

승인 문서의 `storage/models.py`와 `storage/repositories.py`는 공개 진입점으로 유지하되 내부 구현은 크기가 커질 때 aggregate별 private module로 분리한다.

- run·workspace
- work·attempt
- record revision·current pointer
- action·transition
- invocation·AgentLog
- budget·evaluation

`__init__.py`는 필요한 공개 타입만 export한다. 다른 package가 private module이나 SQLAlchemy model을 직접 import하면 계약 시험에서 실패시킨다.

## 7. 설정·Prompt·Provider

- 일반 설정은 TOML, 승인 registry는 safe YAML, secret은 환경 변수 이름 또는 opaque handle만 저장한다.
- prompt template 정본은 `src/sastsimi/prompts/templates/<role>/<task>/<semver>.md` 한곳만 사용한다.
- 역할과 모델을 결합하지 않는다. 호출은 exact `provider_profile_ref + model`로 고정한다.
- fake Provider를 첫 전체 흐름의 기본값으로 사용한다.
- 실제 capability 시험을 통과하지 않은 adapter는 `SUPPORTED`나 `ACTIVE`로 표시하지 않는다.
- Issue #118의 R1 prompt 작업은 공통 계약을 다시 정의하지 않고, Prompt Runtime의 template·fixture·semantic validator 입력으로 연결한다.

## 8. 저장·복구

- Pydantic domain model과 SQLAlchemy persistence model을 분리한다.
- 외부 LLM·도구·Docker 호출 동안 DB transaction을 열어 두지 않는다.
- 큰 artifact는 content-addressed file store에 저장한다.
- 저장은 `staging -> hash -> PREPARED -> CAS -> atomic rename -> DB commit -> COMMITTED` 순서를 따른다.
- migration은 Alembic으로만 수행하고 앱 시작 시 자동 upgrade하지 않는다.
- crash 시험은 sleep이 아니라 주입 가능한 checkpoint로 재현한다.
- stale·late·다른 attempt 결과는 current pointer를 변경하지 못한다.

## 9. 시험 전략

- `unit`: model validator, canonical JSON, 전이표, config, redaction
- `contract`: exact reference, result owner, port, import 경계, prompt 입력·출력
- `integration`: 실제 SQLite·filesystem·Alembic과 fake 외부 adapter
- `e2e`: fake 한 가설 22단계, 이후 다중 가설·판정별 경로
- `security_negative`: path escape, secret, prompt injection, stale, 권한·Sandbox 경계
- `capability`: 실제 credential·외부 도구가 있는 승인 환경에서만 명시 실행

건너뛴 capability 시험을 성공으로 집계하지 않는다. race와 crash 시험에는 barrier와 fault checkpoint를 사용한다.

## 10. 문서 모순 선행 수정

첫 코드 PR 전에 다음을 문서에서 정리한다.

1. `08-lightweight-data-contracts.md`와 `docs/governance/OPEN_QUESTIONS.md`에 남은 “serialization·schema·database·result storage가 아직 미정”이라는 과거 문장을 ADR-015에서 확정한 Canonical JSON v1·Pydantic·SQLite·Alembic·artifact store 기준으로 바꾼다.
2. `03-agent-roles-and-orchestration.md`의 run-init “공통 Docker/환경 준비” 표현을 제거한다. Docker는 current 가설의 승인된 `DYNAMIC_REPRO`에서만 준비한다.
3. module map의 `DebateService`, `VerificationService`, `DynamicReproductionService`, `VerdictRouter`, `RevisionWorkflow`, `ChainingService`를 `verification/`, `reproduction/`, `chaining/`에 연결한다.
4. dependency 설명을 runtime 호출 흐름과 Python import 방향으로 나눠 concrete adapter 직접 import 오해를 막는다.
5. 저장소 전체를 검색해 같은 과거 표현이 남지 않았는지 확인한다. 역사 문서에는 현재 정본으로 오해하지 않도록 상태와 정본 링크가 있는지 검사한다.
6. 서비스와 module의 exact mapping, 특히 concrete reporting·chaining import가 금지된 `VerdictRouter` 경계를 기록한다.
7. 이 물리 구조 보완을 새 ACCEPTED ADR로 기록하고 Architecture validator에 회귀 검사를 추가한다.

이 수정은 Agent, schema field, enum, verdict, Gate 또는 권한을 바꾸지 않는다.

## 11. PR 진행 순서

1. 저장소 정리: 파일별 삭제 allowlist, 문서 인덱스·provenance·validator 동기화만 수행
2. 구현 경계 보정: stale 정본 표현 수정, 업무 흐름 package ADR, module map·의존 방향·validator 반영
3. Python foundation, lock, CLI skeleton, logging, lint·type·pytest·CI
4. 공통 Pydantic 계약, canonical JSON, generated schema와 run-level·work-level 예산 계약
5. SQLite·Alembic·artifact·work/attempt·action·transition·복구와 최소 Budget Registry·binding·reservation·ledger
6. fake adapter 기반 한 가설 22단계 vertical slice. 모든 work는 실제 ACTIVE 예산 binding과 reservation을 통과
7. Repository Loader·AST·CodeQL·OpenGrep·StaticFactBundle
8. Provider port 첫 실제 API adapter·Prompt Runtime·Agent wrapper
9. R6 Verification과 R7 동적 재현·validated PoC
10. CWE·두 Gate·Finding·Reporter
11. Primitive Admission·Chaining·다중 가설 병렬 처리
12. 예산 한도·동시 예약·이중 차감, 취소·재시도·복구·security-negative 추가 강화
13. 실제 Provider·정적 도구·Docker capability와 평가 corpus E2E

각 PR은 하나의 책임만 가지며 앞 PR의 public contract가 병합된 뒤 그 계약에 의존하는 PR을 시작한다. 서로 같은 공통 파일을 수정하지 않는 조사·fixture 준비만 병렬로 진행한다.

## 12. 완료 조건

- 현재 정본과 구현 자료를 문서 지도에서 바로 찾을 수 있다.
- 금지 import가 자동 시험에서 실패한다.
- Agent wrapper는 외부 concrete dependency를 직접 import하지 않는다.
- fake adapter만으로 설치 후 전체 22단계를 재현할 수 있다.
- 오류·timeout·인증·Sandbox 실패가 취약점 판정으로 바뀌지 않는다.
- final TRUE, validated PoC, CWE, 두 Gate, Finding, ReportDraft의 exact provenance가 이어진다.
- 중단 후 복구해도 duplicate·stale·late 결과가 current가 되지 않는다.
- 실제 Provider와 외부 도구는 capability 증거 전까지 비활성 상태다.
- 각 PR의 검토 SHA와 시험 결과가 진행 기록에 남는다.

## 13. 변경 관리

구현 중 field, enum, 권한, 상태 전이 또는 Gate 의미를 바꿔야 하면 코드에서 임시 우회하지 않는다. 별도 Issue와 ADR에서 영향 역할을 검토한 뒤 계약과 시험을 먼저 변경한다.

현재 정본과 다른 구현 편의 기능, Web UI, 외부 Queue, 다중 host, 자동 외부 제출은 첫 완성 범위에 추가하지 않는다.
