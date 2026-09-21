# 한국어 취약점 보고서·Agent 감사 로그·읽기 전용 대시보드 설계

> **상태:** 이 문서의 최초 WSL 전용 지원 범위는 이후
> `2026-09-21-simple-runtime-productization-design.md`에서 대체됐습니다. 현재 공개
> CLI와 실제 지원 상태는 루트 `README.md`와 `docs/installation.md`를 따릅니다.

## 목적

WSL 기반 SASTSIMI 실제 분석에서 사람이 분석 진행 상황과 각 Agent의 검증 가능한 작업 과정을 실시간으로 확인하고, 최종 결과를 바로 검토할 수 있는 한국어 Markdown 보고서로 제공한다.

이 기능은 LLM의 숨겨진 내부 사고 과정을 노출하거나 저장하지 않는다. 시스템이 실제로 사용한 정확한 입력·근거, 요청한 작업, 도구 실행 결과, 구조화된 판정 이유만 감사 가능한 형태로 기록한다.

## 최초 설계 당시 지원 환경

- 첫 구현과 실제 E2E 검증 대상은 WSL2의 Linux 사용자 공간과 Linux Docker 컨테이너다.
- Windows 사용자는 WSL2 안에서 SASTSIMI와 대시보드를 실행하고 Windows 브라우저에서 `localhost`로 접속한다.
- Windows 네이티브 PowerShell만으로 실제 LLM·OpenGrep·CodeQL·Docker·PoC 전체 흐름이 동작한다고 선언하지 않는다.
- 동적 PoC는 기존 계약대로 POSIX `/bin/sh`와 `/workspace`가 있는 Linux 컨테이너에서 실행한다.

## 범위

1. 최종 Markdown 보고서를 한국어 중심의 네 구역으로 단순화한다.
2. 보고서 파일에 분석별 안정적인 사람용 Finding 번호를 부여한다.
3. Agent와 Runtime의 검증 가능한 활동을 append-only 감사 이벤트로 저장한다.
4. 현재 분석 상태, Agent 활동, 가설, PoC, Gate, Finding과 보고서를 읽기 전용 웹 대시보드에서 조회한다.
5. 기존 SimpleRuntime의 성공 단계 재사용과 실패 단계 재개 방식을 유지한다.

다음은 범위에 포함하지 않는다.

- LLM의 비공개 chain-of-thought 또는 전체 원문 프롬프트 표시
- 대시보드에서 분석 취소, 재시도, 판정 변경, 보고서 수정 또는 외부 공개 수행
- 외부 네트워크에 대시보드 공개
- Windows 네이티브 전체 E2E 지원
- 새로운 취약점 사실 또는 기존 Agent 판정 생성

## 최종 보고서

### 파일 이름

보고서는 다음 경로에 저장한다.

```text
<data-dir>/reports/<analysis_id>/F-001.md
<data-dir>/reports/<analysis_id>/F-002.md
```

`F-001`은 분석별 사람용 표시 번호다. Runtime은 Finding이 처음 확정될 때 `analysis_id + exact finding reference`에 번호를 원자적으로 할당한다. 같은 Finding을 다시 조회하거나 보고서를 다시 내보내도 번호가 바뀌지 않는다. 새로운 Finding은 기존 번호를 재사용하지 않고 다음 번호를 받는다.

기존 content hash 이름의 보고서 파일은 자동 삭제하지 않는다. 새 보고서 목록과 대시보드는 현재 Finding에 연결된 `F-###` 파일만 현재 보고서로 노출한다.

### 언어와 구조

제목과 본문은 한국어로 생성한다. 최상위 섹션 이름은 익숙한 취약점 제보 형식을 유지하기 위해 다음 네 개로 고정한다.

```markdown
### Summary
### Details
### PoC
### Impact
```

각 섹션의 내용은 다음과 같다.

- `Summary`: 취약점 유형, 공격 조건, 직접적인 영향과 심각도를 짧은 한국어 문장으로 설명한다.
- `Details`: 영향받는 코드 위치, source → propagation → sink 흐름, 정적 분석 근거, Pro·Con 근거, Verification 이유, CWE와 두 Gate 결과를 설명한다.
- `PoC`: validated PoC로 승격된 실제 스크립트 전체, 실행 명령, 실행 상태, 관찰 결과와 재현에 필요한 제한사항을 포함한다.
- `Impact`: 영향을 받는 사용자·기능·데이터, 공격자가 가능한 행동, 정책상 공개 제한과 사람이 추가로 확인할 내용을 설명한다.

Reporter는 exact Finding, Verification, CWE, validated PoC, 동적 결과와 두 Gate 기록에 존재하는 사실만 정리한다. 새로운 공격 경로, 영향 또는 재현 결과를 만들지 않는다.

### PoC 표시 규칙

- final `TRUE`와 같은 attempt에 연결된 validated PoC만 최종 보고서에 표시한다.
- 후보 생성 또는 실행에 실패한 스크립트는 최종 PoC로 표시하지 않는다.
- 스크립트는 Markdown 코드 블록으로 출력한다.
- 실제 실행 명령은 저장된 command record 또는 SimpleRuntime의 exact 실행 기록에서 가져온다.
- stdout·stderr는 민감정보 제거 후 재현 판단에 필요한 부분만 표시한다.
- validated PoC reference, 실행 attempt와 결과 reference를 보고서에 보존한다.
- validated PoC가 없으면 final `TRUE` 보고서를 생성하지 않는다.

### Rule Scope 제한

Technical Gate를 통과한 기술적 `TRUE`는 Rule Scope 결과가 `DENY | UNCERTAIN`이어도 내부 검토 보고서를 만들 수 있다. 이 경우 다음을 강제한다.

- 보고서 상태는 `CONFIRMED_RESTRICTED`다.
- 외부 제출·공개 불가 문구를 `Summary`와 `Impact`에 표시한다.
- Rule Scope 판정을 `ALLOW`로 바꾸거나 숨기지 않는다.
- 대시보드에서도 제한 상태를 명확하게 표시한다.

## Agent 감사 로그

### 기록 원칙

감사 로그는 사람이 Agent의 결론을 검토하고 실행 오류를 추적할 수 있는 구조화된 작업 요약이다. 내부 chain-of-thought 원문이 아니다.

각 이벤트는 최소한 다음 값을 가진다.

- 전역 고유 `event_id`
- `analysis_id`, `workspace_id`, `commit_id`
- nullable `hypothesis_id`
- `stage`, `agent_role`, `attempt_id`
- 이벤트 종류와 상태
- 안전한 한국어 요약
- 사용한 exact input/evidence reference 목록
- 생성한 output reference 목록
- 도구 이름, tool/action reference와 결과 reference
- LLM 호출의 `prompt_digest`, `output_digest`, provider와 model
- 시작·종료 시각과 경과 시간
- 재시도 번호와 안전한 오류 코드

허용 이벤트 종류는 다음처럼 제한한다.

- `STAGE_STARTED`: Agent 또는 도구 단계가 어떤 exact 입력으로 시작됐는지
- `EVIDENCE_REVIEWED`: 어떤 코드·정적·동적 근거를 확인했는지
- `CONTEXT_REQUESTED`: 무엇이 부족해 어떤 추가 코드나 근거를 요청했는지
- `EVIDENCE_RECORDED`: Pro·Con 또는 다른 Agent가 어떤 검증 가능한 근거를 기록했는지
- `TOOL_REQUESTED`: 어떤 도구를 어떤 목적으로 요청했는지
- `TOOL_COMPLETED`: 도구가 어떤 상태와 결과 reference를 반환했는지
- `DECISION_RECORDED`: 구조화된 판정과 짧은 근거
- `STAGE_BLOCKED | STAGE_FAILED | STAGE_COMPLETED`: 단계 종료 상태

현재 실행 경로에서 발생하지 않은 이벤트를 채우기 위해 가짜 로그를 만들지 않는다. 예를 들어 Agent가 추가 컨텍스트를 요청하지 않았다면 `CONTEXT_REQUESTED`를 생성하지 않는다.

### 저장 금지 정보

- LLM의 숨겨진 사고 과정 또는 chain-of-thought 원문
- 전체 프롬프트와 전체 모델 응답
- API Key, access/refresh token, 로그인 세션 또는 쿠키
- 민감정보 검사를 통과하지 않은 코드·stdout·stderr
- 호스트의 로컬 절대 경로
- 다른 분석·가설·attempt의 결과

### 저장과 복구

- 이벤트는 SQLite에 append-only로 저장한다.
- 이미 저장된 이벤트를 수정하거나 덮어쓰지 않는다.
- 이벤트 순서는 같은 `analysis_id + hypothesis_id + attempt_id` 안에서 증가한다.
- stage checkpoint 성공과 완료 이벤트는 같은 transaction에서 확정한다.
- 프로세스 중단 후에도 이전 이벤트는 유지하고 실패 단계부터 새 attempt로 재개한다.
- 대시보드는 정확한 분석·가설 범위의 이벤트만 읽는다.

## 읽기 전용 웹 대시보드

### 실행 방법

```bash
sastsimi dashboard --host 127.0.0.1 --port 8765
sastsimi analyze --repo <URL-or-path> --commit <SHA> --profile <profile.toml>
```

첫 번째 WSL 터미널에서 대시보드를 실행하고 두 번째 터미널에서 분석을 실행한다. 브라우저는 Windows에서 `http://localhost:8765`로 접속할 수 있다. 분석이 끝난 뒤에도 대시보드는 저장된 결과를 계속 조회한다.

### 화면

대시보드는 다음 정보를 제공한다.

- 분석 대상 저장소, commit, 시작 시각과 경과 시간
- 분석 전체 상태와 현재 단계
- 실제 완료 작업 수, 실행 중 작업 수, 실패·차단·재시도 대기 수
- 전체 가설 수와 가설별 현재 단계·판정
- 현재 실행 중인 Agent와 도구
- Agent별 감사 이벤트 시간선
- 확인한 evidence reference와 안전한 판단 요약
- Pro·Con 근거 비교
- 정적 분석, Docker, PoC 실행 상태와 결과
- CWE, Technical Gate, Rule Scope Gate와 Finding 상태
- `F-###` 보고서 목록과 Markdown 링크
- 안전한 오류 코드와 재시도 횟수

정확한 전체 작업량을 알 수 없으면 가짜 퍼센트를 표시하지 않는다. 대신 현재 단계와 완료·실행 중·남은 것으로 확인된 작업 수를 보여준다.

### 갱신 방식

- 브라우저는 2초 간격으로 읽기 전용 JSON endpoint를 조회한다.
- API는 SQLite와 artifact 저장소의 현재 확정 데이터만 읽는다.
- 실행 중인 Agent 메모리나 모델 세션을 직접 들여다보지 않는다.
- 새 이벤트 또는 checkpoint가 없으면 화면 상태를 바꾸지 않는다.
- 분석 프로세스와 대시보드 프로세스는 서로 독립적으로 실행한다.

### 권한 경계

- 기본 bind 주소는 `127.0.0.1`로 고정한다.
- 첫 버전에서는 외부 bind 옵션을 제공하지 않는다.
- 허용 HTTP method는 `GET`과 `HEAD`뿐이다.
- POST·PUT·PATCH·DELETE 요청은 거부한다.
- 대시보드는 Runtime 상태, 판정, checkpoint와 artifact를 생성·수정·삭제하지 않는다.
- Markdown 파일은 등록된 현재 보고서 mapping을 통해서만 제공하고 임의 경로를 받지 않는다.
- JSON과 HTML 출력에는 민감정보, 전체 프롬프트, 전체 코드 원문과 로컬 절대 경로를 포함하지 않는다.

### 구현 형태

첫 버전은 별도 Node.js 빌드나 프론트엔드 프레임워크 없이 Python 서버와 정적 HTML·CSS·JavaScript로 구성한다. 데이터 조회 계층과 HTML 표현 계층을 분리하고, 화면은 JSON API만 사용한다.

공개 조회 모델은 다음 네 가지로 제한한다.

- `AnalysisSummaryView`
- `HypothesisProgressView`
- `AgentActivityView`
- `FindingReportView`

이 모델은 내부 DB row나 artifact 원문을 그대로 반환하지 않고 허용된 필드만 투영한다.

## 기존 구조와의 연결

- SimpleRuntime runner는 stage 시작·완료·차단·실패 이벤트를 기록한다.
- 구조화된 LLM stage는 prompt/output 원문 대신 digest, exact refs, 역할, 안전한 결과 요약을 기록한다.
- PoC 단계는 candidate 생성, Docker 실행, 해석과 validated 승격을 별도 이벤트로 기록한다.
- 기존 `LLMInvocationLog`와 `AgentLog`가 존재하는 전체 Runtime 경로에서는 같은 공개 조회 모델로 투영하되 원본 계약을 바꾸지 않는다.
- 대시보드는 SimpleRuntime과 전체 Runtime의 저장 데이터를 판정 없이 읽는 adapter를 각각 둔다.
- Reporter와 대시보드는 공통 Finding 표시 번호 registry를 사용한다.

## 파일 경계

- `src/sastsimi/observability/agent_activity.py`: 감사 이벤트 모델과 안전한 요약 규칙
- `src/sastsimi/storage/agent_activity.py`: append-only 이벤트 저장·조회
- `src/sastsimi/reporting/finding_display_id.py`: 분석별 `F-###` 할당과 조회
- `src/sastsimi/simple_runtime/runner.py`: stage lifecycle 이벤트 연결
- `src/sastsimi/simple_runtime/provider.py`: LLM 호출 digest·상태 이벤트 연결
- `src/sastsimi/simple_runtime/stages.py`: 한국어 Reporter와 exact PoC 보고서 렌더링
- `src/sastsimi/reporting/markdown_export.py`: 기존 Runtime 보고서의 같은 네 구역 렌더링
- `src/sastsimi/dashboard/`: 읽기 전용 query, HTTP server와 정적 화면
- `src/sastsimi/interfaces/cli/main.py`: `dashboard` 명령
- `tests/observability/`, `tests/reporting/`, `tests/dashboard/`: 핵심 정상·실패 테스트

실제 구현 중 기존 디렉터리 책임과 더 잘 맞는 위치가 확인되면 파일 이름은 조정할 수 있지만, 저장·조회·표현 계층의 분리는 유지한다.

## 오류 처리

- 감사 로그 저장 실패는 해당 stage 성공과 함께 확정할 수 없으므로 stage를 성공 처리하지 않는다.
- 로그 민감정보 검사 실패는 안전한 오류 코드만 저장하고 원문은 폐기한다.
- 대시보드 조회 오류는 분석 상태를 바꾸지 않고 안전한 오류 화면을 반환한다.
- 손상되거나 다른 분석의 reference는 화면에서 제외하지 않고 `REFERENCE_INVALID` 상태로 표시하되 원문을 열지 않는다.
- 보고서에 validated PoC 내용 또는 exact execution 연결이 없으면 보고서를 생성하지 않는다.
- Finding 번호 할당 충돌은 transaction에서 재시도하며 같은 Finding에 새 번호를 중복 할당하지 않는다.

## 테스트

### 보고서

- 한국어 본문과 네 개의 고정 섹션이 생성된다.
- validated PoC 실제 내용, 명령과 실행 결과가 포함된다.
- 후보 또는 실패 PoC는 최종 PoC로 표시되지 않는다.
- 같은 Finding은 반복 export에서도 같은 `F-###`를 사용한다.
- 다른 Finding과 다른 분석의 번호가 섞이거나 덮어써지지 않는다.
- Rule Scope `DENY | UNCERTAIN` 보고서는 외부 공개 금지를 표시한다.

### 감사 로그

- Agent stage 시작·결과·판정이 exact reference와 attempt에 연결된다.
- 실패와 재시도는 이전 이벤트를 덮어쓰지 않는다.
- 전체 프롬프트, token, 민감정보와 로컬 절대 경로가 저장되지 않는다.
- 다른 분석·가설·attempt의 이벤트를 조회할 수 없다.

### 대시보드

- 실행 중 checkpoint와 새 이벤트가 다음 조회에서 반영된다.
- 분석, 가설, Agent, PoC, Gate, Finding과 보고서 링크가 표시된다.
- POST·PUT·PATCH·DELETE를 거부한다.
- 임의 파일 경로와 다른 분석의 보고서를 열 수 없다.
- 대시보드 장애가 분석 실행을 중단하거나 상태를 변경하지 않는다.

### 실제 WSL 검증

- 대시보드 프로세스와 분석 프로세스를 별도 터미널에서 실행한다.
- PyGoat의 저장된 정상 단계와 Docker 이미지를 재사용한다.
- 실패 단계부터 재개해 Agent 활동이 실시간으로 갱신되는지 확인한다.
- final `TRUE`가 validated PoC와 `F-###.md` 보고서로 연결되는지 확인한다.

## 완료 조건

- WSL에서 `sastsimi dashboard`가 localhost 읽기 전용 화면을 제공한다.
- 실제 분석 중 현재 단계와 감사 이벤트가 저장된 사실을 기준으로 갱신된다.
- Agent 로그에 숨겨진 사고 과정, 전체 프롬프트 또는 비밀정보가 없다.
- 최종 보고서는 한국어 본문과 `Summary`, `Details`, `PoC`, `Impact` 구조를 사용한다.
- 보고서에 실제 validated PoC 내용·명령·결과가 포함된다.
- 보고서 파일 이름이 분석별 안정적인 `F-###.md`다.
- 오류를 취약점 `FALSE`로 바꾸지 않고 exact reference와 attempt 경계를 유지한다.
- 읽기 전용 경계와 분석 간 데이터 분리가 자동 테스트와 WSL smoke test로 확인된다.
