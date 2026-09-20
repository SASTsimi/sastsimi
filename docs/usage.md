# 저장소 분석 실행 안내

이 문서는 저장소 URL 또는 로컬 Git 경로와 정확한 commit을 입력해 분석하고, 상태·결과·Markdown 보고서를 확인하는 순서를 설명합니다.

아래 명령은 소스 설치 기준입니다. 검증된 wheel을 가상 환경에 설치한 사용자는
각 명령의 `uv run sastsimi`를 `sastsimi`로 바꿔 실행합니다.

## 1. 먼저 설치본의 기능을 확인합니다

```text
uv run sastsimi --help
uv run sastsimi analyze --help
```

production 분석이 가능한 설치본은 `analyze`에 `--repo`, `--commit`, `--profile`을 모두 필수 입력으로 표시합니다. Fake 시나리오는 `demo analyze` 아래에만 있어야 하며 실제 저장소 분석과 섞이지 않습니다.

아래 production 명령은 T14 orchestration, T16 capability/onboarding과 필요한 선행 구현이 모두 포함된 release에서 사용합니다. 명령이 보이더라도 Fake 없는 live E2E 출시 증거가 없으면 연구·검증 환경 밖에서 운영 완료로 간주하지 않습니다.

## 2. 실행 준비 순서

1. [설치 안내](./installation.md)에 따라 Python, Git, 필요한 정적 도구와 Docker를 준비합니다.
2. [`production.example.toml`](../config/profiles/production.example.toml)을 복사해 실제 환경의 승인값으로 고칩니다.
3. `capability probe`와 `capability approve`로 사용할 host 도구를 확인합니다.
4. [Provider 안내](./provider-setup.md)에 따라 실제 PVD·평가·정책·Prompt 승인 근거를 준비합니다.
5. `onboarding requirements` → `prepare` → `status` 순서로 profile이 현재도 `READY`인지 확인합니다.
6. 정확한 저장소와 commit으로 `analyze`를 실행합니다.

OpenAI 인증 smoke가 성공해도 Provider onboarding은 생략할 수 없습니다. CodeQL과 Codex 회원제도 설치·로그인만으로 활성화하지 않으며, 해당 exact 실행 파일·환경·모델에 대한 검증 근거와 사람 승인이 필요합니다.

## 3. 분석 입력을 준비합니다

필수 입력은 다음과 같습니다.

- 읽을 권한이 있는 `https` 저장소 URL 또는 로컬 Git 저장소 경로
- 소문자 40자리 또는 64자리의 정확한 commit SHA
- secret이 없는 production profile TOML
- 같은 `data-dir`에 저장된 현재 capability와 onboarding 승인 기록

원격 `https` 저장소가 기본입니다. 로컬 Git 경로를 사용하려면 production profile에서 `allow_local_repository = true`를 명시적으로 설정하고, 그 경로가 승인된 분석 입력인지 먼저 확인합니다. 기본 예시는 안전하게 `false`입니다.

현재 로컬 저장소의 commit은 다음처럼 확인할 수 있습니다.

```text
git -C <repository-path> rev-parse HEAD
```

branch, tag, 짧은 SHA, 대문자 SHA 또는 working tree의 미커밋 변경은 `--commit` 입력으로 허용하지 않습니다. 원격 URL에 사용자명·password·token을 넣지 않습니다.

## 4. 실제 분석을 시작합니다

전역 `--data-dir`은 하위 명령 앞에 둡니다.

```text
uv run sastsimi --data-dir <data-dir> analyze --repo <URL-or-local-path> --commit <exact-SHA> --profile <production-profile.toml> --format json
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
uv run sastsimi --data-dir <data-dir> status <analysis_id> --format json
```

주요 출력은 다음과 같습니다.

- `status`: 분석 전체 상태
- `work_counts`: 작업 상태별 개수
- `waiting_for`: 사람이 해결해야 하는 외부 조건
- `cancel_requested`: 취소 요청 여부
- `result_record_id`: terminal 결과가 확정됐을 때의 정확한 record ID

`BLOCKED`이면 `waiting_for`와 [문제 해결 안내](./troubleshooting.md)를 확인합니다. 원인을 고치지 않고 같은 명령을 반복해 결과를 덮어쓰지 않습니다.

### 취소 요청과 재시작 입력 확인

```text
uv run sastsimi --data-dir <data-dir> cancel <analysis_id> --format json
uv run sastsimi --data-dir <data-dir> resume <analysis_id> --format json
```

`cancel`은 run metadata를 읽기 전에 취소 요청을 영구 저장합니다. 실행 중인
owner는 이 요청을 관찰합니다. `CANCELLING`은 외부 작업의 종료 확인을 의미하지
않습니다. owner가 이미 종료된 경우 이 명령이 외부 resource 정리나 quiescence를
대신 수행하지 않습니다. metadata 오류로 명령이 실패해도 저장된 취소 요청은 유지됩니다.

현재 `resume`은 저장된 exact 입력·profile·승인·evidence와 작업 상태를 읽어서
검사하는 단계까지만 제공됩니다. 검사에 성공해도
`PRODUCTION_RESUME_DISPATCH_NOT_AVAILABLE`과 종료 코드 `4`를 반환합니다.
새 attempt, Provider 또는 worker를 시작하지 않으며 복구 기록을 변경하지 않습니다.
기존 run에 재시작 descriptor가 없으면 `PRODUCTION_DESCRIPTOR_REQUIRED`로 차단합니다.
네 descriptor 필드만 있는 기존 입력도 bytes와 hash는 유지되지만, 새 authority
catalog가 없으면 `PRODUCTION_AUTHORITY_CATALOG_REQUIRED`로 차단합니다.
catalog는 새 실행의 정확한 예산 profile과 전체 역할 identity를 보존하며,
아직 workspace READY 뒤의 full binding이 고정되지 않았다면
`PRODUCTION_AUTHORITY_BINDING_NOT_PINNED`를 반환합니다. 현재 설정으로 보충하거나
새 identity·binding을 만들어 기존 실행을 복구하지 않습니다.
두 명령 모두 `--profile`로 저장된 설정을 교체할 수 없습니다.

## 6. 최종 결과를 확인합니다

분석이 terminal 상태가 된 뒤 실행합니다.

```text
uv run sastsimi --data-dir <data-dir> results <analysis_id> --format json
```

결과에는 가설·판정·Gate·Finding·보고서 개수, 오류·gap 코드, 실행 시간과 exact 결과 식별자가 포함됩니다. 아직 끝나지 않았거나 exact 결과가 없으면 내용을 추측해 만들지 않고 오류로 종료합니다.

## 7. 보고서를 읽고 Markdown으로 내보냅니다

분석별 보고서 목록을 확인합니다.

```text
uv run sastsimi --data-dir <data-dir> reports <analysis_id> --format json
```

목록의 `finding_id`로 터미널에서 읽습니다.

```text
uv run sastsimi --data-dir <data-dir> report show <finding_id>
```

Markdown 파일을 생성합니다.

```text
uv run sastsimi --data-dir <data-dir> report export <finding_id> --format markdown
```

기본 위치는 다음과 같습니다.

```text
<data-dir>/reports/<analysis_id>/F-001.md
```

Markdown은 current ReportDraft, Finding, VerificationResult, CWELabel, validated PoC와 두 Gate 결과만 사용합니다. Reporter가 새 보안 사실을 만들지 않습니다. 선행 근거가 바뀌었거나 민감정보 제거와 exact reference를 확인하지 못하면 `show`와 `export`는 차단됩니다.

ReportDraft와 Markdown은 사람이 검토할 내부 결과입니다. HTML·PDF 출력과 자동 외부 제출·공개는 첫 버전 범위가 아닙니다.

## 8. Fake 시나리오는 따로 사용합니다

Fake는 다음과 같이 `demo` 아래에서만 실행합니다.

```text
uv run sastsimi --data-dir <demo-data-dir> demo analyze --scenario TRUE --format json
uv run sastsimi --data-dir <demo-data-dir> demo results --format json
```

Fake 결과는 실제 clone, LLM, CodeQL·OpenGrep·Docker capability나 출시 완료의 증거가 아닙니다. production 준비가 실패했을 때 Fake로 자동 대체하지 않습니다.

## 9. 실시간 진행 화면 (WSL2)

분석과 별도의 WSL 터미널에서 읽기 전용 대시보드를 실행합니다.

```text
uv run sastsimi --data-dir <data-dir> dashboard --host 127.0.0.1 --port 8765
```

Windows 브라우저에서 `http://localhost:8765`를 엽니다. 이 화면은 실제로
저장된 단계 상태와 Agent의 근거·도구·판단 요약만 읽습니다. 취소,
재시도, 판정 변경과 공개 승인은 할 수 없습니다. Windows native 전체
E2E는 아직 지원 완료 범위가 아니며, WSL2 Linux를 기준으로 사용합니다.
