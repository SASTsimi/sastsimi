# Repository Cleanup and Implementation Documentation Design

**Status:** PROPOSED_FOR_REVIEW  
**Baseline:** `origin/main` at `c5e501a9995811d6db7a143542cd0a418779ddca`  
**Scope:** repository cleanup, documentation synchronization, and proven-dead artifact removal  
**Non-goal:** changing the behavior, authority boundaries, verdict rules, storage format, or public CLI

## 1. Goal

SASTSIMI의 현재 실행 기능을 그대로 보존하면서 저장소에서 더 이상 현재 구현을
설명하지 않는 과거 작업 기록, 대체된 설계, 중복된 안내와 실제로 도달할 수 없는
코드·계약만 제거한다.

정리 뒤에는 처음 보는 개발자가 다음 세 종류를 명확하게 구분할 수 있어야 한다.

1. 사용자가 설치하고 실행할 때 읽는 문서
2. 현재 코드가 실제로 구현한 구조와 계약을 설명하는 문서
3. 아직 구현되지 않았거나 외부 환경 검증이 필요한 후속 작업

완료된 작업 계획과 과거 검토 기록은 저장소 안에 계속 복제하지 않는다. 필요한 변경
이력은 Git commit과 병합 PR에서 확인한다.

## 2. Safety invariants

정리 과정은 다음 규칙을 바꾸지 않는다.

- 공개 CLI의 `setup`, `analyze`, `status`, `resume`, `result`, `poc`, `report`,
  `dashboard` 동작과 기존 고급 명령을 보존한다.
- 분석 오류, 인증 실패, 도구 실패와 환경 실패를 취약점 `FALSE`로 변환하지 않는다.
- `TRUE` 결과에는 같은 가설·generation·attempt에 연결된 validated PoC가 필요하다.
- analysis, workspace, commit, hypothesis, attempt, record exact reference 검사를 유지한다.
- LLM Agent는 의미 판단과 제안을 담당하고 Runtime은 호출·검사·상태·저장을 담당한다.
- Sandbox 외부 경계, 민감정보 제거, stale 결과 및 stale 보고서 차단을 유지한다.
- 기존 데이터베이스와 생성된 결과를 현재 코드가 계속 읽을 수 있어야 한다.
- Provider와 model은 `provider_profile_ref + model`로 선택하며 Agent 역할과 분리한다.

현재 계약이나 테스트가 복잡해 보인다는 이유만으로 완화하거나 제거하지 않는다.
복잡성은 삭제 근거가 아니다.

## 3. Source-of-truth after cleanup

정리 후 문서는 다음 순서로 해석한다.

1. `README.md`: 프로젝트 설명과 빠른 시작
2. `docs/installation.md`, `docs/usage.md`, `docs/provider-setup.md`,
   `docs/troubleshooting.md`: 실제 운영자 안내
3. 현재 구현 아키텍처 문서: 실행 파이프라인, Runtime, Agent, 데이터 계약,
   Sandbox와 보고서 경계
4. 코드와 생성 스키마: 실행 가능한 최종 계약
5. `docs/release-follow-ups.md`: 실제로 남은 제한과 후속 검증
6. ACCEPTED ADR: 현재 구조를 선택한 이유

과거 Issue 진행표, 역할별 교차 검토, 완료된 implementation plan과 superseded ADR은
현재 정본이 아니다. 정리 후 저장소에서는 제거하고 Git 이력으로만 보존한다.

## 4. Classification rules

### 4.1 Always preserve

- `src/sastsimi`에서 현재 public CLI 또는 그 런타임 경로가 도달하는 코드
- 데이터베이스 migration과 이전 결과 호환성에 필요한 코드
- 현재 producer 또는 consumer가 있는 Pydantic 계약
- schema export 테스트가 생성·검증하는 JSON schema
- prompt registry가 읽는 prompt template
- package build에 포함되는 정적 분석 자료와 대시보드 asset
- 현재 기능, 실패 격리, 보안 경계와 reference 무결성을 검증하는 테스트
- 사용자 설치·실행·문제 해결 문서
- 현재 구현과 일치하는 ACCEPTED ADR

### 4.2 Remove after reference migration

- 완료된 과거 `docs/superpowers/plans`와 `docs/superpowers/specs`
- `.superpowers` 아래 완료 상태 추적 파일
- 닫힌 Issue를 복제한 catalog, tracker와 역할별 교차 검토 기록
- 최종 승인 당시 상태만 기록하고 현재 동작을 설명하지 않는 review snapshot
- 현재 결정으로 대체된 `SUPERSEDED` ADR
- v4에서 v5로 이동하던 시점만 설명하는 migration 문서
- 현재 후속 목록으로 유효 내용을 옮긴 과거 handoff 문서
- 삭제된 파일만 검사하도록 하드코딩된 문서 validator 규칙
- 다른 현재 문서와 동일한 내용을 수동 복제하면서 별도 소비자가 없는 안내

### 4.3 Remove only with executable evidence

Python 코드, 계약, schema, prompt와 테스트는 아래 조건을 모두 만족할 때만 삭제한다.

1. public CLI와 package entry point에서 정적 도달 경로가 없다.
2. `src`, `scripts`, `config`, migration과 runtime registry에서 참조하지 않는다.
3. 문자열 기반 registry, package resource, schema export나 dynamic import 대상이 아니다.
4. 현재 데이터 또는 DB row를 decode하는 데 필요하지 않다.
5. 해당 파일을 삭제한 상태에서 전체 테스트, build와 CLI smoke가 통과한다.
6. 삭제가 지원 기능을 줄이지 않으며 사용자 문서에 제거 기능으로 기록할 필요가 없다.

테스트에서만 사용된다는 사실만으로 production code를 즉시 삭제하지 않는다. 테스트가
미래 계약이나 보안 경계를 고정한다면 코드와 테스트를 모두 보존한다.

## 5. Planned cleanup groups

### Group A: historical process records

예상 대상은 완료된 작업 계획, 과거 설계 승인용 spec, Issue 진행 기록과 교차 검토
문서다. 각 파일의 현재 문서 링크를 먼저 찾고, 현재 동작에 필요한 내용은 현재 문서나
`release-follow-ups.md`로 이동한 뒤 삭제한다.

초기 조사에서 다음 규모가 확인됐다.

- `docs/superpowers`: 58 files
- `docs/review`의 ADR 외 기록: 8 files
- `SUPERSEDED` ADR: 5 files
- `.superpowers` 진행 기록: 1 tree

숫자는 삭제 목표가 아니다. 파일별 증거를 갖춘 allowlist만 삭제한다.

### Group B: outdated handoff and migration material

`docs/handoff`의 유효한 known limitation과 후속 검증을
`docs/release-follow-ups.md`로 합친다. 이미 해결된 장애 기록은 제거한다.
`docs/architecture-v5/11-migration-from-v4.md`는 현재 구현 설명이 아니므로 링크를
정리한 뒤 제거한다. 나머지 문서 번호는 외부 링크 안정성을 위해 바꾸지 않는다.

### Group C: implementation-aligned architecture

남길 아키텍처 문서는 실제 코드에서 확인한 다음 내용을 기준으로 갱신한다.

- public CLI와 `SimpleRuntime` 중심 사용자 실행 경로
- repository preparation과 static analysis adapter 선택
- Hypothesis, Pro, Con, Verification, dynamic reproduction, Chaining, CWE,
  Technical Gate, Rule Scope Gate, Finding과 Reporter의 실제 연결
- 실패한 단계부터 재개하고 완료 결과를 재사용하는 현재 상태 모델
- Markdown 보고서와 읽기 전용 dashboard
- API Key와 공식 subscription provider 경계
- 현재 CodeQL 활성화 조건과 외부 도구 제한

구현되지 않은 경로는 현재 기능처럼 쓰지 않고 `release-follow-ups.md`에 둔다.

### Group D: code, contract and schema reachability

모듈 import graph, registry, package data, schema export와 DB compatibility를 함께
검사한다. 명백한 미참조 파일만 코드 삭제 후보로 올린다.

특히 다음은 이름만 보고 삭제하지 않는다.

- `local_evaluation`: 실제 외부 조합 검증과 회귀 시험에서 사용하는 내부 경로일 수 있음
- `production_*`: 고급 명령, onboarding, capability와 복구 경로에서 사용될 수 있음
- `snapshot`: repository snapshot과 무관한 resource state record일 수 있음
- generated schema: 현재 contract의 배포 표현일 수 있음

확실한 후보가 없으면 이 그룹에서는 아무 코드도 삭제하지 않는 것이 올바른 결과다.

### Group E: repository navigation and validation

`README.md`, `docs/README.md`, `docs/DOCUMENT_GUIDE.md`, architecture index,
ADR index와 CONTRIBUTING 링크를 동기화한다. 문서 validator는 과거 파일의 존재를
강제하지 않고 아래만 검사하도록 줄인다.

- 현재 정본 파일 존재
- Markdown 상대 링크 유효성
- 금지된 과거 용어가 현재 문서에 다시 들어오지 않음
- 실제 CLI 명령과 문서 명령 일치
- 현재 accepted decision과 implementation boundary 일치

## 6. Validation strategy

### Baseline

최신 main에서 이미 다음 기준을 확보했다.

```text
3209 passed, 23 skipped, 12 warnings
```

skip은 외부 Docker, 실제 provider와 OS 전용 capability 조건에 따른 기존 skip이며
cleanup에서 새 skip을 추가하지 않는다.

### During cleanup

각 삭제 묶음마다 다음을 실행한다.

- 끊어진 Markdown link 검사
- architecture/document validator
- 관련 contract 및 import test
- `ruff check`와 `mypy`

삭제 때문에 실패한 테스트를 단순히 제거하거나 느슨하게 만들지 않는다. 과거 파일의
존재만 확인하던 테스트라면 현재 정본 검증으로 교체한다.

### Final gate

PR을 만들기 전에 다음을 모두 실행한다.

1. `uv run pytest`
2. `uv run ruff check .`
3. `uv run mypy src`
4. architecture/document validator
5. wheel build와 새 가상환경 설치
6. `sastsimi --help`, `setup --help`, `analyze --help`, `dashboard --help`
7. DB upgrade와 report command smoke
8. baseline과 test count 차이 설명

전체 테스트 실패, 새 skip, schema drift, migration 손상, public CLI 축소 또는
Blocker/High 문서 불일치가 하나라도 있으면 PR을 준비 상태로 표시하지 않는다.

## 7. Git and review policy

- 최신 `origin/main`에서 만든 `chore/repository-cleanup` worktree에서만 수정한다.
- 삭제는 기능 단위의 작은 commit으로 나눈다.
- PR에는 삭제 파일 목록, 보존한 레거시처럼 보이는 파일과 이유, 검증 결과를 적는다.
- PR까지만 생성하고 main에는 병합하지 않는다.
- 리뷰 중 기능 손상 가능성이 발견되면 삭제 범위를 줄이는 쪽을 선택한다.

## 8. Acceptance criteria

- 저장소 최상위와 `docs`에서 현재 사용자·구현 문서를 쉽게 찾을 수 있다.
- 과거 계획과 완료 검토 기록이 현재 계약처럼 노출되지 않는다.
- 남은 모든 설계 설명은 현재 구현 또는 명시된 후속 제한과 일치한다.
- 삭제한 계약·코드에는 활성 producer, consumer, registry, migration 의존성이 없다.
- baseline과 동일한 기능·보안·복구 테스트가 통과한다.
- 현재 wheel과 공개 CLI가 Windows 환경에서 설치·실행된다.
- PR이 생성되지만 main에는 병합되지 않는다.
