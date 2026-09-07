# R3-06. 구현 기술·파일 구조·저장·설정·실행 기준선

- **이 문서는 무엇을 설명하나요?** Architecture v5를 코드로 옮길 때 사용할 기술, 파일 위치, 저장 방식, 실행 순서와 시험 기준을 한곳에 정리합니다.
- **누가 읽어야 하나요?** R3 통합 구현자와 R1~R8 역할 담당자가 읽습니다.
- **읽은 뒤 무엇을 결정하나요?** 아래 결정표와 역할별 경계를 승인하고, 남은 저장 경계를 확정한 뒤 구현을 시작합니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## 1. 기준과 사실 구분

- 검토 기준 `main`: `35729d3185cf46cdbf9c94ce2be646ae11f26446`
- 연결 Issue: [R3-06 #92](https://github.com/SASTsimi/sastsimi/issues/92)
- 선행 문서: [R3-01](./01-module-map.md), [R3-02](./02-contract-test-plan.md), [R3-03](./03-recovery-test-plan.md), [R3-04](./04-provider-decision.md), [R3-05](./05-prompt-runtime.md)

이 문서는 **구현 기준 설계**다. 현재 완료된 것은 문서화와 검토 준비이며 Python package, DB, Provider adapter, 정적 분석기, Sandbox와 Agent는 아직 구현 완료로 주장하지 않는다.

## 2. 결정표

| 항목 | 결정 | 상태 | 근거·안전한 기본 동작 |
|---|---|---|---|
| 언어 | CPython 3.12 64-bit | ACCEPTED | type hint와 비동기 실행 기반을 통일한다. 첫 지원 환경은 Windows 개발과 Linux CI·Docker다. |
| 의존성 | `uv`, `pyproject.toml`, 커밋된 `uv.lock` | ACCEPTED | lock 변경은 dependency PR에서 검토한다. |
| 품질 도구 | Ruff format/lint, Pyright type check, pytest | ACCEPTED | 어느 필수 검사든 실패하면 병합하지 않는다. |
| 실행 구조 | 하나의 Python 앱과 역할별 모듈 | ACCEPTED | 첫 구현에서 Agent별 서버와 외부 message queue를 만들지 않는다. |
| 계약 | Pydantic v2 model을 정본으로 두고 JSON Schema export | ACCEPTED | LLM·외부 도구 출력은 schema와 semantic validator를 모두 통과해야 한다. |
| 직렬화·hash | UTF-8 canonical JSON과 SHA-256 | ACCEPTED | key 정렬, UTC 시간, Unicode·null fixture를 고정하고 검증 실패 결과를 연결하지 않는다. |
| 구조화 저장 | SQLite transaction, foreign key, unique constraint, compare-and-set | ACCEPTED | 단일 host 기준이며 current pointer는 COMMITTED revision만 가리킨다. |
| 큰 artifact | SHA-256 content-addressed file store | ACCEPTED | staging 후 hash 검증과 atomic rename에 성공한 artifact만 참조한다. |
| 작업 실행 | in-process bounded worker와 SQLite work table | ACCEPTED | process 재시작 시 COMMITTED 상태부터 복구한다. |
| Provider 선택 | exact `provider_profile_ref + model` | ACCEPTED | 실제 capability 증거가 없는 조합은 `SUPPORTED`가 아니다. 조용한 fallback은 금지한다. |
| 별도 모델 전용 profile | 만들지 않음 | REJECTED | 모델은 `ProviderProfile.model` 및 `LLMCallSpec.model`의 일치로 검사한다. |
| Repository Snapshot | 별도 모듈을 만들지 않음 | REJECTED | `CodeWorkspace`가 exact checkout을 나타낸다. |
| 외부 queue·분산 worker | 첫 구현에서 사용하지 않음 | REJECTED | 필요성이 측정되면 ADR과 migration 계획으로 재검토한다. |
| Web/API UI | 첫 vertical slice 뒤로 연기 | DEFERRED | 담당 R3, 재검토 조건은 CLI 기반 core가 E2E를 통과하는 때다. 기본 동작은 CLI만 제공한다. 구현을 막지 않는다. |
| 초기 운영 ProviderProfile | capability 시험 후 하나를 선택 | DEFERRED | 담당 R3·R8, 완료 조건은 R3-04 필수 시험 증거다. 그 전에는 fake provider만 사용하고 운영 LLM 실행은 fail-closed한다. |
| 저장 producer·atomic boundary 세부 binding | R4 승인 필요 | DEFERRED | 담당 R4·R3. 아래 7절의 다섯 항목이 확정되기 전 저장 구현과 #92 종료를 차단한다. |

## 3. 저장소와 package 구조

```text
sastsimi/
├─ pyproject.toml
├─ uv.lock
├─ src/sastsimi/
│  ├─ contracts/          # 공통 Pydantic model, ID, exact reference
│  ├─ runtime/            # work, attempt, Action, transition, recovery
│  ├─ orchestration/      # 전역 work 등록, 가설 등록·배정, 합류
│  ├─ storage/            # SQLite, artifact, pointer, migration adapter
│  ├─ providers/          # 공통 port와 Provider별 adapter
│  ├─ prompts/            # Registry, Loader, Builder, validator
│  ├─ agents/             # 11개 LLM 역할 wrapper
│  ├─ static_analysis/    # Git, AST, CodeQL, OpenGrep, 정규화
│  ├─ sandbox/            # setup, controller, session manager 연결
│  ├─ reporting/          # CWE, Gate, admission, Reporter 연결
│  ├─ config/             # versioned 설정 loader
│  └─ interfaces/cli/     # 명령, 출력, exit code
├─ tests/{unit,contract,integration,e2e,security_negative,fixtures}/
├─ config/{profiles,prompts,playbooks,static-rules}/
├─ evals/{corpus,graders,scenarios}/
├─ migrations/
├─ docker/
└─ docs/architecture-v5/implementation/
```

런타임 데이터는 source tree 밖의 사용자 지정 data directory에 둔다. DB는 `<data>/sastsimi.sqlite3`, artifact는 `<data>/artifacts/sha256/<앞 2자>/<digest>`, 임시는 `<data>/staging/`, 분석 checkout은 `<data>/workspaces/<analysis_id>/`를 사용한다. secret, 실제 실행 결과, checkout과 staging은 Git에 포함하지 않는다.

## 4. public interface와 의존 방향

허용 방향은 `interfaces → application/orchestration → domain port → adapter`다.

- `contracts`는 provider, SQLite, Docker와 Agent 구현을 import하지 않는다.
- Agent wrapper는 contract와 runtime port만 사용하고 DB·Docker·Provider SDK를 직접 호출하지 않는다.
- `runtime`은 권한·상태·revision·예산을 검사하지만 취약점과 정책 의미를 판단하지 않는다.
- `orchestration`은 등록·배정·합류를 조정하지만 전문 verdict·CWE·Gate 결과를 만들지 않는다.
- `reporting`은 current exact 결과만 읽고 외부 제출·공개 기능을 제공하지 않는다.
- CLI는 application service만 호출하고 DB와 artifact를 직접 고치지 않는다.

첫 public port는 `RecordStore`, `ArtifactStore`, `WorkQueue`, `LLMProviderAdapter`, `StaticToolAdapter`, `SandboxPort`, `PromptRegistry`로 제한한다. adapter의 예외는 공통 실행 오류로 변환하고 `FALSE | HOLD`로 바꾸지 않는다.

## 5. 승인된 R2 연계 위치

| 구성요소 | 위치 | 소유·호출 | 입력 → 출력 |
|---|---|---|---|
| Repository Loader | `src/sastsimi/static_analysis/repository_loader.py` | R3 통합 구현, `WorkspaceService.prepare`에서 호출 | repository·revision → `CodeWorkspace` |
| Context Retrieval Service | `src/sastsimi/static_analysis/context_retrieval.py` | R2 구현, `ContextService.retrieve`에서 호출 | exact workspace·commit·location request → `CodeContextResponse` |

Context Retrieval은 다른 workspace나 commit의 코드를 반환해서는 안 된다. Repository Loader는 별도 Snapshot을 만들지 않고 실제 checkout과 identity를 `CodeWorkspace`로 고정한다.

## 6. 저장·원자성·복구 기준

1. immutable record와 큰 artifact를 먼저 staging한다.
2. schema, semantic rule, exact reference와 content hash를 검사한다.
3. 한 SQLite transaction에서 output binding, 상태, `TransitionCommit`과 current pointer를 compare-and-set으로 확정한다.
4. 성공한 transaction만 `COMMITTED`이며 다음 단계가 읽을 수 있다.
5. crash 뒤 `PREPARED`를 검사해 완결 가능한 것은 commit하고 아니면 `ABORTED`로 격리한다.
6. retry는 새 `attempt_id`를 사용하며 이전 실패와 late result를 보존하되 current에 연결하지 않는다.
7. migration은 순방향 script, rollback 가능 범위, backup·복구 시험을 함께 둔다. 기존 immutable record를 덮어쓰지 않는다.

Artifact는 임시 파일 작성 → flush → SHA-256 검증 → 최종 경로 atomic rename 순서로 저장한다. DB가 존재하지만 artifact가 없거나 hash가 다르면 `ARTIFACT_INTEGRITY_ERROR`로 기록하고 downstream을 막는다.

## 7. 병합 전 R4와 확정할 저장 binding

다음은 구현을 막는 미확정 항목이다. 담당자의 댓글 또는 승인된 PR 근거로 producer, application service, record table, pointer 갱신과 transaction 범위를 채운 뒤 이 절과 결정표를 `ACCEPTED`로 바꾼다.

| record | 확인할 내용 | 현재 안전 동작 |
|---|---|---|
| `CodeWorkspace` | Repository Loader 결과를 저장·current로 지정하는 service와 commit 경계 | 저장 binding이 없으면 정적 분석 시작 금지 |
| `ToolRunResult` | 도구별 raw artifact와 구조화 record를 함께 확정하는 producer | partial·미실행을 0건으로 변환하지 않음 |
| 최초 `HypothesisProposal` | LLM 출력 검증 뒤 전역 등록하는 producer와 dedupe transaction | 등록 전 결과를 Verification에 전달하지 않음 |
| 파생 `HypothesisProposal` | Verification/Chaining origin과 parent lineage를 atomic하게 저장하는 경계 | lineage가 없으면 등록 차단 |
| `AnalysisRunResult` | Result Aggregator의 final snapshot과 current pointer 확정 시점 | non-current·stale output이 있으면 완료 처리 금지 |

## 8. Provider·Prompt 구현 기준

- 지원 상태는 Provider·product·transport·인증·client version·model·환경 조합별 실제 증거로 정한다.
- API key와 공식 구독 session은 별도 adapter/profile이다.
- Pro와 Con은 같은 모델을 사용해도 서로 다른 payload, call ID와 `NEW` session을 사용한다.
- retry와 Provider/model 변경은 새 호출·session·attempt로 기록한다.
- 11개 LLM 역할은 template, `PromptRegistryEntry`, allowlist 입력 model, 출력 schema, semantic validator와 wrapper를 한 세트로 구현한다.
- 비-LLM Runtime, Validator, Registry Runtime, Setup Automation, Sandbox Controller, Session Manager와 Primitive Admission Runtime에는 Agent prompt를 만들지 않는다.
- repository text, 정책 원문과 LLM 출력은 모두 비신뢰 데이터 slot으로만 넣으며 instruction으로 승격하지 않는다.

초기 Provider가 승인되기 전 fake provider로 contract/E2E를 수행한다. 실제 Provider 실행은 `doctor` capability 검사를 통과하지 못하면 명확한 실행 오류로 끝낸다.

## 9. 정적 분석·Sandbox·보고 순서

- Git checkout은 `workspace_id + commit_id`로 추적한다.
- AST·CodeQL·OpenGrep는 실행 여부, version, rule/query revision, raw 수와 오류를 각각 기록하고 `StaticFactBundle`로 정규화한다.
- Dynamic Reproduction Agent가 계획과 후보를 제안하고 Setup Automation, Sandbox Controller와 Session Manager가 실행·경계·log·validated PoC를 담당한다.
- timeout, 인증 실패, 정책 준비 실패와 Sandbox 실패는 취약점 `FALSE`가 아니다.
- final TRUE 이후 순서는 `CWE Labeling → Technical Gate → Rule Scope Gate → Reporter`로 고정한다.
- Reporter는 current final TRUE와 current CWE·두 Gate·정책 chain만 읽고 `ReportDraft`를 만든다. 외부 공개는 사람이 수행한다.

## 10. 설정·secret

우선순위는 `허용된 CLI option → 운영 환경 변수 → 승인된 versioned profile → 안전한 코드 기본값`이다. 시작 시 exact config revision을 실행에 고정한다. API key, cookie, reusable token과 로그인 session은 저장소·prompt·artifact·일반 log에 저장하지 않는다. redaction 실패 시 호출과 저장을 fail-closed한다.

## 11. CLI 기준

| 명령 | 목적 | 대표 실패 exit code |
|---|---|---|
| `sastsimi doctor` | Git·도구·Docker·Provider capability 확인 | `2` 설정/의존성 오류 |
| `sastsimi run <repo> --revision <commit>` | 새 분석 시작 | `2` 입력 오류, `3` 실행 시작 실패 |
| `sastsimi status <analysis-id>` | current 상태 조회 | `4` 대상을 찾지 못함 |
| `sastsimi cancel <analysis-id>` | 취소 요청 기록 | `5` 상태 충돌 |
| `sastsimi resume <analysis-id>` | COMMITTED 지점부터 재개 | `5` 복구 불가 상태 |
| `sastsimi result <analysis-id> --format json` | current 결과 출력 | `4` 결과 없음 |
| `sastsimi cleanup <analysis-id>` | 정책에 맞는 workspace·임시 자원 정리 | `6` 일부 정리 실패 |

`0`은 명령 자체 성공을 뜻하며 취약점 발견 여부를 뜻하지 않는다. JSON 출력에는 오류 code와 analysis 상태를 분리한다.

## 12. 테스트와 CI

```text
uv sync --frozen
uv run ruff format --check .
uv run ruff check .
uv run pyright
uv run pytest tests/unit tests/contract
uv run pytest tests/integration
uv run pytest tests/e2e
uv run pytest tests/security_negative
pwsh -File scripts/validate-architecture-docs.ps1
```

첫 package가 만들어지기 전에는 위 Python 명령은 **확정된 목표 명령**이지 현재 통과 증거가 아니다. 문서 단계에서는 마지막 validator만 실행한다. 실제 dependency capability 시험은 fake 기반 CI와 분리하며, secret이 없는 PR에서 자동 실행하지 않는다.

필수 fixture는 canonical JSON, 잘못된 hash·revision, 다른 workspace/commit, schema·semantic 실패, prompt injection, timeout·인증·Sandbox 실패, duplicate, crash, stale·late result와 Gate/Reporter 순서 위반을 포함한다.

## 13. 한 명의 구현 담당자 실행 순서

1. Python package, config, CLI와 test 뼈대
2. Pydantic contract, schema export, canonical JSON과 exact reference validator
3. SQLite, artifact store, work/attempt, Action, atomic transition과 startup recovery
4. fake adapter로 한 가설의 22단계 최소 vertical slice
5. Repository Loader, AST·CodeQL·OpenGrep와 `StaticFactBundle`
6. Provider adapter, Prompt Registry·Builder와 11개 Agent wrapper
7. 동적 재현 4구성요소와 validated PoC
8. CWE, 두 Gate와 Reporter
9. Primitive Admission, Chaining과 제한된 병렬 처리
10. cancel, retry, explicit failover, crash-resume와 security-negative test
11. 추가 Provider capability 시험
12. R8 corpus로 품질·시간·사용량·비용을 측정해 최적화

각 단계는 이전 단계 회귀 시험을 통과해야 다음 단계로 간다. 첫 vertical slice 완료는 모듈 연결 증거일 뿐 실제 탐지 정확도나 운영 준비 완료를 뜻하지 않는다.

## 14. 역할별 검토 요청

| 역할 | 확인할 내용 |
|---|---|
| R1 | 가설·Primitive·Chaining 경계와 새 material claim 등록 |
| R2 | Repository Loader, 정적 도구, Context Retrieval 경로·계약 |
| R4 | 저장 producer, current pointer, transaction, recovery와 권한 |
| R5 | CWE, 두 Gate, Finding·Reporter 순서와 입력 |
| R6 | Pro/Con·Verification·동적 요청과 final verdict |
| R7 | Setup·Sandbox Controller·Session Manager·validated PoC |
| R8 | Provider capability, 예산, 평가 corpus와 최적화 |

## 15. 완료 조건

- [x] #107 병합 뒤 최신 `main` SHA를 기록했다.
- [x] 기술, package, 직렬화, SQLite·artifact, worker와 CLI 후보를 결정표로 정리했다.
- [x] R2가 승인한 Repository Loader와 Context Retrieval 위치·소유권을 반영했다.
- [x] 문서 상태와 실제 구현 완료를 구분했다.
- [ ] R4가 7절의 저장 producer·pointer·atomic boundary를 확정했다.
- [ ] R3-04 capability 증거로 초기 ProviderProfile을 승인했다.
- [ ] R1·R2·R4·R5·R6·R7·R8 검토 기록을 남겼다.
- [ ] 구현 차단 `DEFERRED`를 0개로 만들었다.
- [ ] 문서 validator와 PR 검토를 통과했다.
