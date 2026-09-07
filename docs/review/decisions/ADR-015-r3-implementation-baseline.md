# ADR-015. R3 단일 애플리케이션 구현 기준선

- 상태: `PROPOSED`
- 제안일: 2026-09-07
- 기준 main: `0c1b59b5f74fb2c76171167940640d10ca5155b0`
- 결정 담당: 구현·통합(R3, `@YHS-Sec`), PM·공통 아키텍처(R4, `@taehyeon-git`)
- 반드시 확인할 역할: R1 `@baeseungwon1010`, R2 `@zv9uvr`, R5 `@kimhr8463`, R6 `@UltraPeachKeen`, R7 `@Potatonion`, R8 `@gitterable`
- 연결 Issue/PR: #4, #24, #25, #89, #90, #91, #92, PR #107, 이 ADR을 추가하는 Draft PR

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

Option A를 채택할 단일안으로 제안한다.

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

R3-04의 실제 capability 시험을 통과하지 않은 ProviderProfile은 ACTIVE로 만들지 않는다. 구현 순서는 fake adapter 뒤 API adapter 한 경로부터 시작하되, 이것을 운영 지원 완료나 품질 우위로 표현하지 않는다.

## Consequences

### Positive

- 한 명 구현 담당자가 하나의 repository와 실행 환경에서 전체 흐름을 완주할 수 있다.
- LLM 역할과 Provider·모델을 독립적으로 교체·평가할 수 있다.
- SQLite transaction·constraint와 TransitionCommit을 함께 사용해 중복·stale·부분 저장을 차단할 수 있다.
- 큰 artifact를 DB에서 분리하면서 exact content hash와 provenance를 유지한다.
- Web/API나 서버 DB가 필요해져도 port 구현을 추가하는 migration 경로가 남는다.

### Negative

- 첫 구현은 단일 host와 local filesystem으로 제한된다.
- SQLite와 file store 사이에는 물리적 단일 transaction이 없으므로 PREPARED journal과 startup recovery가 필수다.
- Provider·Docker·static tool의 실제 설치와 capability 증거는 별도 검증이 필요하다.
- async 외부 호출과 짧은 sync DB transaction의 경계를 storage service가 엄격히 지켜야 한다.

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
- R3-02 계약 시험과 PR #107 복구 시험을 물리 table·artifact·CLI 결정에 연결한다.
- R1~R8이 자기 영역 section과 검토 commit SHA를 기록한다.
- PR #107 병합 뒤 최신 main 기준으로 재검증한다.
- PR #107 동기화와 필수 검토를 마친 최종 review-freeze commit에서 상태를 `ACCEPTED`로 바꾸고 decisions README의 기준 commit·PR 정보를 갱신한 뒤 병합한다.
