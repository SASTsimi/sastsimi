# ADR-015. R3 단일 애플리케이션 구현 기준선

- 상태: `ACCEPTED`
- 제안일: 2026-09-07
- 기준 main: `07bd6549a676419c0e720f940ba7abd1b82aea0d` (PR #116 병합)
- 결정 담당: 구현·통합(R3, `@YHS-Sec`), PM·공통 아키텍처(R4, `@taehyeon-git`)
- 반드시 확인할 역할: R1 `@baeseungwon1010`, R2 `@zv9uvr`, R5 `@kimhr8463`, R6 `@UltraPeachKeen`, R7 `@Potatonion`, R8 `@gitterable`
- 연결 Issue/PR: #4, #24, #25, #89, #90, #91, #92, PR #107, PR #116
- 반영 commit: `07bd6549a676419c0e720f940ba7abd1b82aea0d`

PR #116 병합과 Issue #92·R3 상위 Issue #4 종료를 확인해 이 단일안을 구현 기준으로 승인했다. Provider capability, 품질 평가, Docker 보안과 전체 실행은 실제 구현에서 별도로 증명해야 한다.

## Context

Architecture v5 번호 문서는 역할·데이터·상태·권한을 정했고 R3-01~R3-05는 22단계 mapping, 계약 시험, 복구 시험, Provider와 Prompt 구조를 설계했다. 그러나 실제 언어, repository tree, 저장 기술, migration, CLI와 CI가 하나의 정본으로 확정되지 않으면 한 명의 구현 담당자가 개발 중에 다시 결정을 내려야 한다.

또한 Agent를 각각 별도 서비스로 만들거나, 모델명을 역할 코드에 넣거나, 구조화 record와 큰 artifact를 같은 저장 방식으로 처리하면 현재 계약의 권한·복구 경계가 구현에서 약해질 수 있다.

## Options

### Option A. 단일 Python 애플리케이션 + port/adapter + SQLite·파일 artifact

- 하나의 process 안에서 module을 나누고 bounded worker를 사용한다.
- domain contract와 concrete Provider·storage·Docker를 port/adapter로 분리한다.
- SQLite는 구조화 상태·record·CAS를, content-addressed file store는 큰 artifact를 저장한다.
- CLI로 먼저 제공하고 Web/API는 같은 application service의 후속 adapter로 둔다.

장점은 한 명 구현·로컬 실행·transaction·crash recovery가 단순하고, 현재 queue-less 방향과 맞는다는 점이다. 단점은 여러 host 분산 확장이 즉시 가능하지 않다는 점이다.

### Option B. Agent별 서비스 + 외부 Queue + 서버 DB

각 역할을 별도 service로 배포하고 message broker와 서버 DB로 연결한다. 확장성은 높지만 아직 구현·부하 근거가 없는 상태에서 network failure, message 중복, distributed transaction과 운영 비용을 추가한다.

### Option C. 단일 process + JSON 파일만 사용

초기 구현은 빠르지만 CAS, unique constraint, migration, 부분 저장과 crash recovery를 정확하게 구현하기 어렵다. 큰 artifact와 current pointer도 같은 파일에 섞이기 쉽다.

### Option D. 특정 Provider·모델을 역할에 고정

초기 wiring은 단순하지만 API Key·구독 경로와 모델 접근성이 바뀔 때 Agent 코드·prompt·평가 기준까지 수정해야 한다. R3-04·R3-05의 Provider 중립 계약과 충돌한다.

## Decision

Option A를 구현 기준 단일안으로 채택한다.

- 64-bit CPython `>=3.12,<3.13`
- `uv`, `pyproject.toml`, 커밋된 `uv.lock`
- Pydantic 2 계열과 생성 JSON Schema
- SQLAlchemy 2 계열, SQLite와 Alembic
- content-addressed file artifact store
- `asyncio` bounded worker와 SQLite work claim
- 표준 `argparse` CLI
- TOML 일반 설정, 안전하게 읽는 YAML registry, 환경 변수·secret store 주입
- 공식 SDK/CLI와 `asyncio.create_subprocess_exec(shell=False)` adapter
- exact `provider_profile_ref + model`; 특정 모델 ID를 역할에 고정하지 않음
- 별도 Repository Snapshot 모듈과 외부 message queue 제품 없음
- `RecordStore`의 transport 참조는 `RecordRef = RunStoredDataRef | StoredDataRef | PolicyCacheRef`로 통합하되, 각 domain validator가 허용 reference 종류와 scope를 I/O 전에 제한
- 공식 정책 수집은 `PolicySourcePort`와 `policy/adapters/official_http.py` 뒤에 두고 Policy Collector만 원문·수집 결과를 소유
- 예산은 R8 trusted profile registry의 run-level `ExecutionBudgetProfile`, 역할·작업별 `WorkBudgetProfile`, workspace READY 뒤 full `BudgetProfileBinding`, `BudgetReservation`과 append-only ledger로 예약·확정·해제하며 bootstrap 순환과 중복 차감을 차단
- R8 평가는 운영 분석과 분리된 `purpose=EVALUATION` 경로와 전용 service·runner·CLI를 사용하고, Provider capability 증거만으로 운영 Prompt를 활성화하지 않음
- 운영 Prompt 활성화는 exact R8 품질 추천과 사람 승인을 요구하며 특정 Provider·모델을 역할에 고정하지 않음
- current 동적 request 교체 또는 승인된 Sandbox profile revision 변경은 Technical `REVISE`와 구분한 `RESTART_VERIFICATION_GENERATION` action으로 처리한다. request 교체는 새 request가 아니라 exact 변경 근거를 선행 입력으로 고정하고, old work 종료와 새 application·질문·Pro/Con·current pointer를 한 transaction으로 확정한다. 새 request/work는 재검증 뒤 필요할 때만 만든다.
- run-init은 정적 분석과 정책 준비만 시작하며 Docker 준비는 current 가설의 승인된 동적 재현 경로에서만 수행

R3-04의 실제 capability 시험을 통과하지 않은 ProviderProfile은 ACTIVE로 만들지 않는다. 구현 순서는 fake adapter 뒤 API adapter 한 경로부터 시작하되, 이것을 운영 지원 완료나 품질 우위로 표현하지 않는다.

## Consequences

### Positive

- 한 명 구현 담당자가 하나의 repository와 실행 환경에서 전체 흐름을 완주할 수 있다.
- LLM 역할과 Provider·모델을 독립적으로 교체·평가할 수 있다.
- SQLite transaction·constraint와 TransitionCommit을 함께 사용해 중복·stale·부분 저장을 차단할 수 있다.
- 큰 artifact를 DB에서 분리하면서 exact content hash와 provenance를 유지한다.
- Web/API나 서버 DB가 필요해져도 port 구현을 추가하는 migration 경로가 남는다.
- 예산 예약과 평가 provenance가 명시되어 동시 실행·crash·운영 승격에서 중복 비용과 평가 결과의 운영 오염을 차단할 수 있다.

### Negative

- 첫 구현은 단일 host와 local filesystem으로 제한된다.
- SQLite와 file store 사이에는 물리적 단일 transaction이 없으므로 PREPARED journal과 startup recovery가 필수다.
- Provider·Docker·static tool의 실제 설치와 capability 증거는 별도 검증이 필요하다.
- async 외부 호출과 짧은 sync DB transaction의 경계를 storage service가 엄격히 지켜야 한다.
- 예약·ledger·평가 result·recommendation용 table과 migration, crash recovery test가 초기 구현 범위에 추가된다.

### Rejected implications

- 이 결정은 Agent가 DB·Docker·Provider를 직접 호출하도록 허용하지 않는다.
- 특정 Provider·모델의 운영 지원을 승인하지 않는다.
- 실제 취약점 탐지 정확도나 성능을 증명하지 않는다.
- 사람의 외부 제출·공개를 자동화 범위에 넣지 않는다.

## Compatibility

이 ADR은 Architecture v5의 field·enum·verdict·Gate·Chaining 의미를 바꾸지 않는다. 물리 파일과 기술을 R3-01~R3-05에 연결한다. 향후 PostgreSQL, 외부 Queue, 분산 worker 또는 HTTP API를 도입하려면 다음을 포함한 새 ADR이 필요하다.

- 기존 SQLite·artifact record와 exact reference migration
- 중복 delivery와 distributed claim 규칙
- transaction·current pointer·TransitionCommit 의미 보존
- secret·tenant·network 경계
- 성능·운영 필요성의 측정 증거

## Verification

- Architecture 문서 validator가 구현 기준선·인덱스·이 ADR의 존재와 핵심 결정을 확인한다.
- `git diff --check`와 상대 링크 검사를 통과한다.
- R3-02 계약 시험과 병합된 R3-03 복구 시험을 물리 table·artifact·CLI 결정에 연결한다.
- `R3-CT-COM-015`, `R3-CT-DYN-013`, `R3-CT-BUD-006`~`007`, `R3-CT-EVAL-001`~`003`과 `R3-REC-WRK-008`, `R3-REC-DYN-010`이 참조·세대 전이·예산 bootstrap·작업별 한도·평가·복구 결정을 검증한다.
- R1~R8이 자기 영역 section과 검토 commit SHA를 기록한다.
- PR #116 병합과 Issue #92·R3 상위 Issue #4 종료를 반영한 `07bd6549a676419c0e720f940ba7abd1b82aea0d` 기준으로 최종 문서 검증을 수행한다.
- 승인 뒤 구현이 이 결정을 바꿔야 하면 새 ADR에서 migration·보안·시험 영향을 다시 검토한다.
