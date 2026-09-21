# SimpleRuntime 제품화·체이닝·간편 CLI·Windows 지원 설계

## 문서 상태

- 상태: 구현 전 승인 설계
- 기준 브랜치: `main`
- 기준 commit: `5e11eb6`
- 선택한 접근: SimpleRuntime을 일반 사용자의 기본 실행기로 확장
- 대체 범위: 기존 WSL 전용 실행 안내와 SimpleRuntime의 재개 전용 사용 방식을 확장한다. 기존 Runtime과 고급 명령은 호환 경로로 유지한다.

## 1. 목적

SASTSIMI를 GitHub에서 내려받은 사용자가 운영용 경로와 설정 파일 위치를 미리 알지 않아도 설치 후 다음 명령만으로 설정, 분석, 재개, 결과 확인과 대시보드 조회를 수행할 수 있게 한다.

```text
sastsimi setup
sastsimi analyze <repository> --commit <commit>
sastsimi status <analysis_id>
sastsimi resume <analysis_id>
sastsimi dashboard
sastsimi result <analysis_id>
sastsimi poc <finding_id>
sastsimi report <finding_id>
sastsimi report <finding_id> --export markdown
```

현재의 SimpleRuntime 정확성 규칙과 기존 데이터 계약은 유지한다. 분산 실행을 위한 복잡한 Runtime을 일반 사용자 기본 경로에서 제외하고, 설정과 명령 해석을 담당하는 얇은 사용자 계층을 SimpleRuntime 앞에 둔다.

## 2. 설계 원칙

1. SimpleRuntime은 다음 단계 호출, 결과 저장, 실패 단계 재시도, 현재 위치 기록만 담당한다.
2. Agent는 취약점 분석과 구조화된 판단을 담당하고 Runtime은 판정을 새로 만들지 않는다.
3. 오류, 인증 실패, 도구 미설치와 환경 실패를 취약점 `FALSE`로 바꾸지 않는다.
4. 단계 결과는 정확한 분석·workspace·commit·가설·attempt·record reference로 연결한다.
5. PoC 후보와 validated PoC를 분리하고, 실제 실행이 가설을 지지한 경우에만 validated PoC를 만든다.
6. 완료된 단계와 동일한 Docker image는 exact input이 일치할 때 재사용한다.
7. 일반 사용자 명령을 단순화하되 기존 명령과 저장 데이터는 삭제하거나 변환을 강요하지 않는다.
8. Windows, Linux와 WSL은 같은 공개 CLI를 사용한다. 동적 재현은 지원 호스트 모두에서 Linux Docker container 안에서 실행한다.
9. 설정 파일에는 비밀정보, 로그인 세션, token 또는 브라우저 cookie를 저장하지 않는다.
10. 대시보드는 저장된 사실을 읽기만 하며 분석 상태나 판정을 변경하지 않는다.

## 3. 선택한 구조

```text
Public CLI
  -> UserConfig Loader
  -> Preflight / Tool Discovery
  -> Analysis Bootstrap
  -> SimpleRuntime
       -> Repository + Static Analysis
       -> Hypothesis Agent
       -> Pro / Con + Verification
       -> Dynamic Reproduction + validated PoC
       -> CWE + Technical Gate + Rule Scope Gate
       -> Primitive Admission + Chaining
       -> Finding + Reporter
  -> SQLite / Artifact Store
  -> Read-only Dashboard
```

### 3.1 일반 사용자 경로

일반 사용자 명령은 사용자 설정을 읽어 내부 서비스에 명시적인 실행 인자를 전달한다. 내부 코드가 전역 설정을 암묵적으로 읽지 않게 하고, CLI 경계에서만 기본값을 해석한다.

```text
간단한 사용자 명령
-> 기본 설정 병합
-> 입력과 설치 상태 확인
-> 기존 Agent·Adapter·계약 호출
-> SimpleRuntime checkpoint 갱신
-> 사람이 읽는 출력 또는 JSON 출력
```

### 3.2 고급·호환 경로

다음 기능은 제거하지 않는다.

- 기존 `evaluate analyze`, `evaluate resume`, `evaluate simple-resume`
- 기존 `results`, `reports`, `report show`, `report export`
- 명시적인 `--data-dir`, `--profile`과 상세 Provider 설정
- 기존 전체 Runtime과 work dispatch 계약
- 기존 DB, artifact와 분석 식별자

새 공개 명령과 이름이 겹치는 기존 명령은 인자 형태로 구분하고, 고급 사용자를 위한 `advanced` 진입점도 제공한다. 기존 자동화 스크립트가 사용하는 명령은 deprecation 경고 없이 계속 동작하게 한다.

## 4. 설정 시스템

### 4.1 설정 위치

플랫폼별 사용자 설정 디렉터리를 사용한다.

- Windows: `%APPDATA%\SASTSIMI\config.toml`
- Linux·WSL: `$XDG_CONFIG_HOME/sastsimi/config.toml` 또는 `~/.config/sastsimi/config.toml`

기본 데이터 디렉터리는 설정 파일에 기록하며, 플랫폼 표준 data 디렉터리를 초기값으로 사용한다. 프로젝트 checkout 내부 경로와 특정 사용자의 절대 경로는 기본값으로 저장하지 않는다.

### 4.2 `sastsimi setup`

대화형 설정은 다음 항목을 한 번 결정한다.

- 기본 데이터 저장 위치
- 인증 방식: API Key 환경변수 또는 공식 회원제 CLI 로그인
- Provider와 model
- 기본 실행 profile
- 비용, token과 실행 시간 제한
- Docker network 허용 범위
- OpenGrep, CodeQL과 Docker 사용 여부

설정 과정에서 다음 프로그램을 자동 탐지하고 버전을 기록한다.

- Git
- Python
- OpenGrep
- CodeQL
- Docker와 Docker daemon
- 선택한 공식 Provider CLI(예: Codex CLI)

탐지 결과는 실행 capability 정보이지 보안 비밀이 아니다. 설치되지 않았거나 실제 probe가 실패한 도구는 자동 활성화하지 않고, 설치 또는 로그인에 필요한 다음 명령을 출력한다. 외부 프로그램을 사용자 확인 없이 자동 설치하지 않는다.

### 4.3 비밀정보

- API Key는 환경변수 이름만 `credential_ref`로 저장한다.
- 회원제 방식은 공식 CLI·SDK 로그인 상태만 확인한다.
- access token, refresh token, session, cookie와 API Key 원문을 TOML·DB·로그에 저장하지 않는다.
- 브라우저 cookie 복사 방식은 지원하지 않는다.

### 4.4 실행 profile

`setup`은 절대 경로가 박힌 기존 수동 profile 대신 현재 호스트에서 검증된 실행 profile을 생성한다. profile은 Provider·model·도구 capability·예산·Docker network 값을 포함하되 비밀정보는 참조만 한다.

CodeQL과 OpenGrep은 별도 정적 분석 도구다. 기본 full profile은 둘을 모두 요구한다. 한 도구가 없으면 이를 조용히 생략하지 않고 분석을 `BLOCKED`로 만들며 정확한 설치·설정 안내를 제공한다. 명시적인 경량 profile을 선택한 경우에만 사용 가능한 도구 집합으로 실행한다.

## 5. 공개 CLI

### 5.1 설치 후 명령

README는 패키지를 한 번 설치해 console script를 PATH에 등록하는 방법을 먼저 안내한다. 이후 실행 예시에는 `uv run`, `UV_PROJECT_ENVIRONMENT`, 반복 `--data-dir`, 반복 `--profile`을 사용하지 않는다.

### 5.2 명령 의미

- `sastsimi setup`: 사용자 기본 설정과 검증된 실행 profile 생성
- `sastsimi analyze <repo> --commit <sha>`: 저장소 입력부터 SimpleRuntime 분석 시작
- `sastsimi status <analysis_id>`: 현재 단계, 완료·실패·차단 항목 조회
- `sastsimi resume <analysis_id>`: 완료 단계를 재사용하고 실패·차단 단계부터 재개
- `sastsimi dashboard`: 설정된 data directory의 읽기 전용 로컬 화면 실행
- `sastsimi result <analysis_id>`: 분석 요약, 가설과 Finding 조회
- `sastsimi poc <finding_id>`: validated PoC와 안전한 실행 정보를 조회
- `sastsimi report <finding_id>`: 현재 Markdown 보고서를 터미널에 표시
- `sastsimi report <finding_id> --export markdown`: Markdown 파일을 생성하거나 현재 파일 경로 표시

모든 조회 명령은 내부 정확한 ID와 사람용 표시 ID를 모두 받을 수 있다.

### 5.3 사람용 식별자

- 분석: `A-001`, `A-002`
- Finding: 기존 `F-001`, `F-002`

사람용 분석 ID는 사용자 편의를 위한 alias다. 내부 `analysis_id`를 대체하지 않는다. 저장 계층은 `display_id -> exact analysis_id` mapping을 원자적으로 할당하고 모든 계약과 Agent 입력에는 기존 exact ID를 사용한다.

### 5.4 출력 형식

기본 출력은 한국어 텍스트다.

```text
분석이 시작되었습니다.

분석 ID: A-001
대상: OWASP PyGoat
Commit: 19d17cc...
현재 단계: 저장소 준비
대시보드: http://127.0.0.1:8765/analyses/A-001
```

분석이 차단되거나 실패하면 원인, 실패 단계, 재시도 가능 여부와 다음 명령을 함께 표시한다.

```text
PoC 실행 단계에서 중단되었습니다.
앞 단계를 다시 실행하지 않고 이어서 실행하려면:

sastsimi resume A-001
```

`--format json`을 지정한 경우에는 설명 문장과 animation을 출력하지 않고 기존 구조화 envelope만 출력한다.

### 5.5 실제 작업 기반 진행률

CLI와 대시보드는 같은 `ProgressSnapshot` 조회 모델을 사용한다. 진행률은 경과 시간이나 LLM의 예측값이 아니라 현재 분석에 등록된 실제 work unit과 durable checkpoint를 기준으로 계산한다.

work unit은 최소한 다음처럼 사람이 확인할 수 있는 실행 단위로 나눈다.

- 저장소 준비와 profile 생성
- AST, OpenGrep, CodeQL과 정규화
- 가설 생성
- 가설별 Pro, Con과 Verification
- PoC 생성, Docker build·실행과 최종 Verification
- CWE, 두 Gate, Primitive admission과 Chaining
- Finding과 보고서 생성

`SUCCEEDED` 또는 실행 경로상 정당하게 `SKIPPED`로 확정된 unit만 완료로 센다. `RUNNING`, `BLOCKED`와 `FAILED`는 완료로 세지 않는다. 분석이 `COMPLETE`일 때만 100%가 된다. 실패하거나 차단된 분석은 마지막으로 실제 완료된 퍼센트와 실패 단계를 함께 표시한다.

가설과 체이닝 자식이 새로 등록되면 현재 확인된 전체 work unit 수가 증가할 수 있다. 이 경우 퍼센트가 낮아질 수 있으며, UI에는 `완료 18 / 현재 확인된 27개 작업`처럼 분자와 분모를 함께 표시해 이유를 알 수 있게 한다. 아직 발견되지 않은 가설 수를 임의로 추정하지 않는다.

TTY 터미널에서는 일정 간격으로 저장된 progress snapshot을 다시 읽고 같은 줄의 bar와 현재 단계를 갱신한다.

```text
[████████████░░░░░░░░] 60%  18/30
현재 단계: SQL Injection 가설 · PoC 실행
```

하나의 긴 단계 안에서 확정 이벤트가 없으면 bar 값을 임의로 증가시키지 않고 activity indicator만 움직인다. 비-TTY 환경에서는 animation 대신 단계가 바뀔 때 한 줄씩 출력한다. `--format json`에서는 bar와 ANSI 제어 문자를 완전히 끄고 구조화된 progress event 또는 최종 envelope만 출력한다. 자동화 환경을 위해 `--no-progress`도 제공한다.

## 6. SimpleRuntime의 처음부터 실행

현재의 재개 중심 SimpleRuntime을 실제 분석 시작점으로 확장한다.

1. 입력 repository와 commit 검증
2. 분석 ID와 사람용 ID 할당
3. repository 준비와 RepositoryProfile 생성
4. AST·OpenGrep·CodeQL 실행과 StaticFactBundle 생성
5. Hypothesis Agent 실행과 가설 등록
6. 가설별 SimpleRuntime stage 실행
7. 체이닝으로 생긴 자식 가설을 같은 분석 처리 목록에 추가
8. 최종 상태, Finding과 보고서 확정

분석 record와 최초 checkpoint는 외부 도구 호출 전에 저장한다. 따라서 설치 상태나 Provider 인증으로 차단돼도 `status`와 대시보드에서 실패 지점과 안전한 오류를 확인할 수 있다.

## 7. 체이닝

### 7.1 재사용 경계

체이닝 규칙을 SimpleRuntime 안에 새로 재작성하지 않는다. 기존의 다음 계약과 서비스를 호출하는 adapter를 둔다.

- Primitive와 Primitive DB의 논리적 index
- `PrimitiveAdmissionDecision`
- exact primitive input snapshot/reference
- Chaining proposal과 duplicate 판정
- child hypothesis 등록 계약
- 깊이, 생성 횟수, token·시간과 중복 제한

### 7.2 실행 흐름

```text
가설 검증 결과와 Gate 결과 확정
-> 기존 Admission 규칙으로 Primitive 등록 가능 여부 판단
-> Primitive 등록 또는 보류
-> 현재 eligible Primitive 집합으로 Chaining Agent 호출
-> material child proposal 검증
-> 중복이 아닌 child hypothesis 등록
-> SimpleRuntime 처리 목록에 추가
-> 자식 가설의 Pro·Con 단계부터 실행
```

TRUE와 HOLD의 등록 시점과 Rule Scope 영향은 기존 `PrimitiveAdmissionDecision`을 그대로 따른다. 금지된 testing method의 근거는 체이닝 재료로 사용하지 않는다. 단순한 out-of-scope 결과는 기존 계약이 허용하는 경우 체이닝을 통해 in-scope 자식이 되는 가능성을 유지한다.

### 7.3 SimpleRuntime 단계

기존 단계에 다음 관찰 가능한 단계를 추가한다.

- `PRIMITIVE_ADMISSION_DONE`
- `CHAINING_DONE`

체이닝 결과가 없어도 검토한 exact primitive 집합과 `NO_MATERIAL_CHILD` 상태를 저장한다. 자식 가설이 생기면 부모 가설·부모 primitive·chain depth와 생성 proposal reference를 저장한다.

### 7.4 처리 전략

첫 제품화 버전은 가설을 순차 처리한다. 자식 가설은 중복 검사를 통과한 후 같은 분석의 durable queue 끝에 추가한다. 회원제 Provider 인증 충돌과 데이터 혼합을 막은 뒤에만 제한 병렬 처리를 후속으로 허용한다.

## 8. 대시보드

대시보드는 설정된 기본 data directory를 자동 사용한다. 공개 route는 사람용 ID와 exact ID를 모두 허용한다.

기존 정보에 다음 체이닝 정보를 추가한다.

- `PRIMITIVE_ADMISSION_DONE`, `CHAINING_DONE` 단계
- Primitive 등록·제외 상태와 안전한 이유
- 부모 가설과 자식 가설 연결
- chain depth와 생성된 자식 수
- Chaining Agent 활동 요약과 exact input/output reference
- 중복·한도 초과·자식 없음 상태

대시보드 상단에는 동일한 `ProgressSnapshot`으로 계산한 퍼센트 bar, 완료 작업 수, 현재 확인된 전체 작업 수와 현재 단계를 표시한다. 브라우저 animation은 CSS transition만 사용하며 서버에서 확인되지 않은 중간 값을 생성하지 않는다. 새 가설로 분모가 늘어난 경우 `새 가설이 추가되어 전체 작업 수가 갱신됨`을 표시한다.

화면은 append-only event와 확정 checkpoint를 조회한다. 저장되지 않은 추론을 만들어 표시하지 않으며, 분석 취소·재시도·판정 수정 기능을 제공하지 않는다. 기본 bind는 `127.0.0.1:8765`다.

## 9. Windows·Linux·WSL 지원

### 9.1 공통 원칙

- 경로 생성과 비교는 `pathlib`와 플랫폼 adapter를 사용한다.
- repository profile과 실행 profile에 개발자 PC의 절대 경로를 넣지 않는다.
- subprocess 실행은 shell 문자열 조합 대신 인자 배열을 사용한다.
- POSIX shell이 필요한 PoC는 host가 아니라 Linux Docker container 안에서 실행한다.

### 9.2 Windows

- PowerShell 또는 cmd에서 설치된 `sastsimi` console script를 실행한다.
- Git, OpenGrep, CodeQL과 공식 Provider CLI는 Windows executable을 탐지한다.
- Docker Desktop Linux container backend를 사용한다.
- Docker daemon은 Windows 기본 연결 방식(named pipe 또는 Docker client 기본 context)을 사용한다.
- WSL 경로(`/mnt/c/...`)를 Windows native profile에 저장하지 않는다.

### 9.3 Linux와 WSL

- 동일한 public CLI와 설정 schema를 사용한다.
- Docker socket과 executable은 현재 Linux 환경에서 탐지한다.
- WSL 실행은 계속 지원하지만 필수 조건으로 두지 않는다.

## 10. 설치와 GitHub 사용자 경험

README 첫 화면은 다음 순서로 구성한다.

1. SASTSIMI가 무엇을 분석하는지
2. 현재 구현·검증된 범위와 미지원 기능
3. Windows, Linux·WSL 필수 프로그램
4. 저장소 clone과 console script 설치
5. `sastsimi setup`
6. 첫 실제 저장소 분석
7. 상태, 재개, 대시보드, PoC와 보고서 확인
8. API Key와 공식 회원제 Provider 로그인
9. OpenGrep, CodeQL과 Docker 문제 해결
10. 고급·기존 명령 문서 링크

“바로 사용”은 외부 프로그램과 Provider 인증이 자동으로 생긴다는 의미가 아니다. `setup`이 현재 상태를 탐지하고 실행 가능 여부와 다음 조치를 정확히 안내하며, 필요한 프로그램과 인증이 준비되면 추가 경로 인자 없이 분석할 수 있다는 의미다.

## 11. 오류 처리

- 설정 없음: `sastsimi setup` 실행 안내와 함께 종료
- API Key·회원제 로그인 실패: `BLOCKED`, 취약점 verdict 없음
- OpenGrep·CodeQL 미설치 또는 probe 실패: 선택 profile이 요구하면 `BLOCKED`
- Docker daemon·build·container 실패: 동적 단계 `BLOCKED | FAILED`, `FALSE` 생성 금지
- exact reference·attempt 혼합: 해당 단계 `FAILED`, 이후 단계 실행 금지
- 체이닝 입력 혼합·중복 child: child 미등록, 안전 오류와 근거 reference 저장
- 대시보드 장애: 분석 상태에 영향 없음
- 보고서가 오래된 경우: 현재 보고서로 표시하거나 export하지 않음

## 12. 구현 경계

### 포함

- SimpleRuntime의 새 분석 시작 경로
- 기존 체이닝 계약 연결과 dashboard projection
- 사용자 설정·tool discovery·profile 생성
- 간단한 public CLI와 한국어 기본 출력
- Windows native host control과 Docker Desktop 지원
- README와 문제 해결 문서
- 기존 명령과 데이터 호환

### 제외

- 기존 전체 Runtime 삭제
- 대시보드 쓰기 기능과 외부 공개
- 외부 도구의 무확인 자동 설치
- 브라우저 cookie 기반 회원제 인증
- 검증하지 않은 Provider·모델 조합의 지원 선언
- 정확하지 않은 진행률 퍼센트
- 새로운 판정 규칙이나 공통 데이터 계약 재설계
- 추가 리팩터링과 Medium·Low 개선

## 13. 테스트 전략

개발 중에는 변경과 직접 관련된 핵심 정상 흐름과 실패 흐름만 실행한다.

1. 설정 정상: 비밀정보 없이 config/profile이 생성되고 다시 읽힌다.
2. 설정 실패: 필수 tool 또는 인증 누락이 `FALSE`가 아닌 실행 차단으로 보인다.
3. 분석 정상: repository 입력에서 checkpoint와 가설이 만들어지고 SimpleRuntime이 보고서까지 진행한다.
4. 재개 정상: 성공 단계는 재사용하고 실패 단계만 새 attempt로 실행한다.
5. 체이닝 정상: eligible Primitive가 child hypothesis를 만들고 같은 분석에서 이어서 처리된다.
6. 체이닝 실패: 다른 분석·attempt 입력 또는 중복 child가 등록되지 않는다.
7. 대시보드: 체이닝 부모·자식과 현재 stage가 저장된 사실대로 보인다.
8. 진행률: CLI와 dashboard가 같은 완료·전체 work unit으로 같은 퍼센트를 표시하고, 실패 상태를 100%로 표시하지 않는다.
9. 진행률 확장: 체이닝 자식 등록 시 전체 작업 수가 늘고 표시가 정확히 갱신된다.
10. Windows smoke: wheel 설치, setup, DB 초기화, help, dashboard query와 외부 도구 탐지가 동작한다.
11. Linux·WSL smoke: 같은 public CLI와 profile schema가 동작한다.
12. 실제 E2E: PyGoat에서 OpenGrep·CodeQL·LLM·Docker 경로와 validated PoC·보고서를 확인한다.

전체 테스트와 CI는 통합 PR의 마지막에 한 번 실행한다. Blocker·High만 즉시 수정하고 Medium·Low는 후속 목록에 남긴다.

## 14. 완료 조건

- 새 환경에서 패키지 설치 후 `sastsimi setup`이 실행 가능한 profile을 만든다.
- 일반 분석에 `uv run`, `UV_PROJECT_ENVIRONMENT`, 반복 `--data-dir`·`--profile`이 필요하지 않다.
- `sastsimi analyze <repo> --commit <sha>`가 SimpleRuntime으로 새 분석을 시작한다.
- 실패 후 `sastsimi resume <analysis_id>`가 성공 단계를 반복하지 않는다.
- 기존 Primitive admission·Chaining 계약으로 자식 가설이 생성되고 같은 분석에서 검증된다.
- 대시보드가 체이닝 관계와 실제 저장 상태를 보여준다.
- CLI의 animation bar와 대시보드가 같은 실제 work unit 기반 진행률을 표시한다.
- 실패·차단 상태는 100%로 표시하지 않고 실패 단계와 `resume` 명령을 안내한다.
- 기존 상세 명령과 기존 DB·artifact를 계속 읽을 수 있다.
- Windows native와 Linux·WSL에서 public CLI smoke test가 통과한다.
- README만 보고 설치, 설정, 분석, 재개, 대시보드, PoC와 보고서 확인을 수행할 수 있다.
- 마지막 통합 CI가 통과하고 남은 Blocker·High가 없다.
