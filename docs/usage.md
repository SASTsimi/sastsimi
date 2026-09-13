# 저장소 분석 실행 안내

이 문서는 저장소 URL 또는 로컬 Git 경로와 정확한 commit을 입력해 분석하고, 상태·결과·Markdown 보고서를 확인하는 순서를 설명합니다.

## 1. 먼저 설치본의 기능을 확인합니다

```text
sastsimi --help
sastsimi analyze --help
```

production 분석이 가능한 설치본은 `analyze`에 `--repo`, `--commit`, `--profile`을 모두 필수 입력으로 표시합니다. `analyze --scenario`만 보이면 현재 설치본은 Fake 전용이므로 실제 저장소에 사용하지 않습니다.

이 문서 branch를 만든 시점의 `main`에서 `analyze`는 아직 Fake 전용입니다. 아래 production 명령은 T14 orchestration, T16 capability/onboarding과 필요한 선행 구현이 모두 병합된 설치본에서만 사용할 수 있습니다. 현재 전체 Fake 없는 live E2E는 아직 출시 완료로 증명되지 않았습니다.

## 2. 실행 준비 순서

1. [설치 안내](./installation.md)에 따라 Python, Git, 필요한 정적 도구와 Docker를 준비합니다.
2. [`production.example.toml`](../config/profiles/production.example.toml)을 복사해 실제 환경의 승인값으로 고칩니다.
3. `capability probe`와 `capability approve`로 사용할 host 도구를 확인합니다.
4. [Provider 안내](./provider-setup.md)에 따라 실제 PVD·평가·정책·Prompt 승인 근거를 준비합니다.
5. `onboarding requirements` → `prepare` → `status` 순서로 profile이 현재도 `READY`인지 확인합니다.
6. 정확한 저장소와 commit으로 `analyze`를 실행합니다.

OpenAI 인증 smoke가 성공해도 Provider onboarding은 생략할 수 없습니다. CodeQL과 Codex 회원제는 현재 자동 production 활성화가 불가능합니다.

## 3. 분석 입력을 준비합니다

필수 입력은 다음과 같습니다.

- 읽을 권한이 있는 `https` 저장소 URL 또는 로컬 Git 저장소 경로
- 소문자 40자리 또는 64자리의 정확한 commit SHA
- secret이 없는 production profile TOML
- 같은 `data-dir`에 저장된 현재 capability와 onboarding 승인 기록

현재 로컬 저장소의 commit은 다음처럼 확인할 수 있습니다.

```text
git -C <repository-path> rev-parse HEAD
```

branch, tag, 짧은 SHA, 대문자 SHA 또는 working tree의 미커밋 변경은 `--commit` 입력으로 허용하지 않습니다. 원격 URL에 사용자명·password·token을 넣지 않습니다.

## 4. 실제 분석을 시작합니다

전역 `--data-dir`은 하위 명령 앞에 둡니다.

```text
sastsimi --data-dir <data-dir> analyze --repo <URL-or-local-path> --commit <exact-SHA> --profile <production-profile.toml> --format json
```

접수 출력의 `analysis_id`를 기록합니다. 같은 저장소·commit을 다시 실행해도 별도 분석은 새 `analysis_id`를 사용합니다.

production orchestration의 목표 흐름은 다음과 같습니다.

```text
안전한 clone과 exact commit checkout
→ 추적된 파일만 읽어 RepositoryProfile 생성
→ 언어·package·Dockerfile 탐지
→ ACTIVE capability와 교집합인 AST·CodeQL·OpenGrep 선택·실행
→ StaticFactBundle과 필요한 코드 context
→ Hypothesis Agent 가설 생성
→ 독립 Pro·Con과 Verification
→ POC_CONFIRMATION 또는 VERDICT_EVIDENCE 동적 요청
→ EnvironmentRecipe와 Docker build context 준비
→ Sandbox 외부 경계 검사
→ image build·container·health check·PoC 실행·cleanup
→ 같은 attempt의 AgentLog·동적 결과·validated PoC 확정
→ final TRUE이면 CWE Labeling과 두 Gate
→ Finding과 ReportDraft
→ 사람이 Markdown으로 확인
```

언어·build 방식을 확실히 알 수 없거나 필요한 ACTIVE 도구가 없으면 임의 추정하지 않고 gap 또는 `BLOCKED`로 남깁니다. 도구·package·image build·Docker·인증 실패를 취약점 `FALSE`로 바꾸지 않습니다.

모든 final `TRUE`에는 현재 Verification generation과 같은 attempt에 연결된 성공한 동적 결과와 validated PoC가 필요합니다. 실제 재현이 성공하지 않으면 Gate와 Reporter로 보내지 않습니다.

## 5. 진행 상태를 확인합니다

```text
sastsimi --data-dir <data-dir> status <analysis_id> --format json
```

주요 출력은 다음과 같습니다.

- `status`: 분석 전체 상태
- `work_counts`: 작업 상태별 개수
- `waiting_for`: 사람이 해결해야 하는 외부 조건
- `cancel_requested`: 취소 요청 여부
- `result_record_id`: terminal 결과가 확정됐을 때의 정확한 record ID

`BLOCKED`이면 `waiting_for`와 [문제 해결 안내](./troubleshooting.md)를 확인합니다. 원인을 고치지 않고 같은 명령을 반복해 결과를 덮어쓰지 않습니다.

## 6. 최종 결과를 확인합니다

분석이 terminal 상태가 된 뒤 실행합니다.

```text
sastsimi --data-dir <data-dir> results <analysis_id> --format json
```

결과에는 가설·판정·Gate·Finding·보고서 개수, 오류·gap 코드, 실행 시간과 exact 결과 식별자가 포함됩니다. 아직 끝나지 않았거나 exact 결과가 없으면 내용을 추측해 만들지 않고 오류로 종료합니다.

## 7. 보고서를 읽고 Markdown으로 내보냅니다

분석별 보고서 목록을 확인합니다.

```text
sastsimi --data-dir <data-dir> reports <analysis_id> --format json
```

목록의 `finding_id`로 터미널에서 읽습니다.

```text
sastsimi --data-dir <data-dir> report show <finding_id>
```

Markdown 파일을 생성합니다.

```text
sastsimi --data-dir <data-dir> report export <finding_id> --format markdown
```

기본 위치는 다음과 같습니다.

```text
<data-dir>/reports/<analysis_id>/<finding_id>.md
```

Markdown은 current ReportDraft, Finding, VerificationResult, CWELabel, validated PoC와 두 Gate 결과만 사용합니다. Reporter가 새 보안 사실을 만들지 않습니다. 선행 근거가 바뀌었거나 민감정보 제거와 exact reference를 확인하지 못하면 `show`와 `export`는 차단됩니다.

ReportDraft와 Markdown은 사람이 검토할 내부 결과입니다. HTML·PDF 출력과 자동 외부 제출·공개는 첫 버전 범위가 아닙니다.

## 8. Fake 시나리오는 따로 사용합니다

현재 `main`의 Fake 전용 설치본은 다음 기존 명령만 제공합니다.

```text
sastsimi --data-dir <demo-data-dir> analyze --scenario TRUE --format json
sastsimi --data-dir <demo-data-dir> results --format json
```

T14 production CLI가 포함된 설치본에서는 Fake가 다음과 같이 `demo` 아래로 이동합니다.

```text
sastsimi --data-dir <demo-data-dir> demo analyze --scenario TRUE --format json
sastsimi --data-dir <demo-data-dir> demo results --format json
```

Fake 결과는 실제 clone, LLM, CodeQL·OpenGrep·Docker capability나 출시 완료의 증거가 아닙니다. production 준비가 실패했을 때 Fake로 자동 대체하지 않습니다.
