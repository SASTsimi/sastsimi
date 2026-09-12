# 저장소 분석 실행 안내

이 문서는 저장소 URL 또는 로컬 경로와 정확한 commit을 입력해 분석을 시작하고, 진행 상태·결과·Markdown 보고서를 확인하는 순서를 설명합니다.

## 1. production 명령이 포함된 설치본인지 확인

먼저 다음 명령을 확인합니다.

```text
sastsimi analyze --help
```

운영 분석이 가능한 설치본은 `--repo`, `--commit`, `--profile`을 모두 필수 입력으로 표시해야 합니다. `analyze --scenario`만 보인다면 Fake 시나리오 전용인 이전 개발 상태이므로 실제 저장소 분석에 사용하지 않습니다.

Fake 시나리오는 테스트·시연용 `sastsimi demo analyze` 아래에만 있어야 합니다. production composition이 없을 때 Fake로 조용히 대체 실행하는 동작은 허용하지 않습니다.

## 2. 실행 전 확인

- 분석 권한이 있는 저장소 URL 또는 로컬 경로
- 소문자 40자리 또는 64자리의 정확한 commit SHA
- secret 값이 없는 승인 production profile TOML
- 실행 host에서 승인된 Git·AST·CodeQL·OpenGrep·Docker capability
- 승인된 ProviderProfile, model, Prompt와 예산 설정
- 충분한 로컬 data directory와 workspace directory

branch 이름, tag, 짧은 SHA 또는 대문자 SHA는 commit 입력으로 사용하지 않습니다. 로컬 저장소의 현재 commit은 다음처럼 확인할 수 있습니다.

```text
git rev-parse HEAD
```

## 3. 분석 시작

전역 옵션인 `--data-dir`은 `analyze` 앞에 둡니다.

```text
sastsimi --data-dir <data-dir> analyze --repo <URL-or-local-path> --commit <exact-SHA> --profile <production-profile.toml> --format json
```

정상적으로 접수되면 출력의 `analysis_id`를 기록합니다. 같은 저장소를 다시 분석해도 새 실행은 새 `analysis_id`를 사용합니다.

분석은 다음 순서로 진행됩니다.

```text
safe clone/checkout
→ RepositoryProfile
→ AST·CodeQL·OpenGrep 선택과 실행
→ StaticFactBundle
→ Hypothesis Agent
→ Pro·Con과 Verification
→ 필요한 경우 Docker 동적 재현과 validated PoC
→ CWE Labeling
→ Technical Gate와 Rule Scope Gate
→ Finding
→ ReportDraft
→ Markdown 보고서
```

도구·환경·인증 실패는 취약점 `FALSE`로 바뀌지 않습니다. 해결 가능한 외부 조건이면 `BLOCKED`, 복구 불가능하거나 한도를 소진하면 verdict 없이 `FAILED`입니다.

## 4. 진행 상태 확인

```text
sastsimi --data-dir <data-dir> status <analysis_id> --format json
```

확인할 값은 다음과 같습니다.

- `status`: 전체 실행 상태
- `work_counts`: 단계·상태별 작업 수
- `waiting_for`: 사용자가 해결해야 할 조건
- `cancel_requested`: 취소 요청 여부
- `result_ref`: terminal 결과가 확정됐을 때의 정확한 참조

`BLOCKED`일 때는 `waiting_for`와 [오류 대응 안내](./troubleshooting.md)를 확인합니다. 실패 원인을 고치지 않고 같은 명령을 반복해 결과를 덮어쓰지 않습니다.

## 5. 최종 결과 확인

terminal 결과가 확정된 뒤 실행합니다.

```text
sastsimi --data-dir <data-dir> results <analysis_id> --format json
```

아직 terminal이 아니거나 exact 결과가 없으면 결과를 추측해 만들지 않고 오류로 종료합니다.

## 6. 보고서 확인과 Markdown 내보내기

분석별 보고서 목록을 봅니다.

```text
sastsimi --data-dir <data-dir> reports <analysis_id> --format json
```

목록에서 `finding_id`를 확인한 뒤 터미널에서 읽습니다.

```text
sastsimi --data-dir <data-dir> report show <finding_id>
```

Markdown 파일을 만듭니다.

```text
sastsimi --data-dir <data-dir> report export <finding_id> --format markdown
```

기본 출력 위치는 다음과 같습니다.

```text
<data-dir>/reports/<analysis_id>/<finding_id>.md
```

보고서는 current non-stale ReportDraft, Finding, VerificationResult, CWELabel, validated PoC와 두 Gate 결과에서만 작성됩니다. 근거가 바뀌어 오래된 보고서이거나 민감정보 제거가 증명되지 않으면 `show`와 `export`는 차단됩니다.

ReportDraft와 Markdown은 사람이 검토할 내부 산출물입니다. 외부 제출·공개는 SASTSIMI 자동화 범위가 아닙니다.

## 7. Fake 시나리오 사용

Fake는 테스트·시연에서만 명시적으로 실행합니다.

```text
sastsimi --data-dir <demo-data-dir> demo analyze --scenario TRUE --format json
sastsimi --data-dir <demo-data-dir> demo results --format json
```

Fake 결과는 production capability, 실제 LLM, 실제 CodeQL·OpenGrep·Docker 또는 release 완료의 증거가 아닙니다.

