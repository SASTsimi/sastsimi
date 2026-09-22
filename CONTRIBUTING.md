# SASTSIMI 기여 안내

현재 동작을 유지하면서 작은 변경을 독립적으로 검토하고 병합하기 위한 절차입니다.
처음 참여한다면 [문서 지도](./docs/DOCUMENT_GUIDE.md)와
[구현 위치 지도](./docs/architecture/implementation-map.md)를 먼저 확인하세요.

## 작업 시작

1. 최신 `main`에서 별도 브랜치 또는 worktree를 만듭니다.
2. 하나의 Issue에는 완료 여부를 독립적으로 판단할 수 있는 한 가지 목표만 둡니다.
3. 변경 전 관련 코드, 계약, 생성 schema와 테스트를 확인합니다.
4. 이미 제거되거나 대체된 설계를 현재 계약처럼 다시 추가하지 않습니다.

```text
git fetch origin
git switch main
git pull --ff-only
git switch -c <type>/<short-name>
```

권장 branch prefix는 `feat/`, `fix/`, `docs/`, `test/`, `chore/`입니다.

## 변경 원칙

- Agent 출력은 제안이며 ID, 상태, 저장, 재시도와 권한은 Runtime이 결정합니다.
- 오류·인증 실패·도구 실패를 취약점 `FALSE`로 바꾸지 않습니다.
- final `TRUE`에는 같은 attempt의 실행 성공과 validated PoC가 필요합니다.
- analysis, workspace, commit, hypothesis, generation, attempt와 record reference를 섞지 않습니다.
- secret, 전체 credential, 로컬 절대 경로와 민감한 코드를 로그·문서·예제에 넣지 않습니다.
- Dashboard와 Reporter가 새로운 판정이나 보안 사실을 만들게 하지 않습니다.
- Provider와 model을 Agent 역할에 고정하지 않습니다.

공통 의미를 바꾸는 결정은 [현재 ADR](./docs/decisions/README.md)을 확인하고, 필요한 경우
새 ADR을 함께 제안합니다. 문서만 수정해 새 계약을 만들지 않습니다.

## 테스트

변경 범위에 맞는 가장 작은 테스트부터 실행합니다.

```text
uv run pytest <관련-test> -q
```

문서만 바꿨다면 다음을 확인합니다.

```text
pwsh -File scripts/validate-current-docs.ps1
uv run pytest tests/contract/test_current_documentation.py tests/contract/test_operator_docs.py -q
git diff --check
```

Python 코드, 계약, schema 또는 migration을 바꿨다면 병합 전 전체 검사를 실행합니다.

```text
uv run pytest -q
uv run ruff check .
uv run mypy src
```

배포·설치 경로를 바꿨다면 wheel build와 smoke test도 실행합니다. 외부 LLM, CodeQL,
OpenGrep 또는 Docker가 필요한 검증을 실행하지 못했다면 성공했다고 쓰지 말고 PR에 이유와
남은 조건을 기록합니다.

## PR 작성과 검토

PR에는 다음 내용을 짧게 적습니다.

- 무엇을 왜 바꿨는지
- 영향받는 사용자 명령 또는 Runtime stage
- 바꾸지 않은 계약과 보안 경계
- 실행한 테스트와 결과
- 실행하지 못한 테스트와 이유
- 후속 작업이 있다면 Issue 번호

작성자는 먼저 self-review를 하고, 영향받는 코드 owner와 앞·뒤 단계 담당자의 검토를
요청합니다. 공통 계약, 판정, exact reference, Provider 인증 또는 Docker 경계를 바꾼
PR은 해당 영역 검토 없이 병합하지 않습니다. Blocker와 High 문제는 병합 전에 해결하고,
Medium과 Low는 별도 Issue로 분리할 수 있습니다.

## 문서 작성

- 짧은 한국어 문장을 우선합니다.
- 처음 나오는 전문용어에는 쉬운 설명을 붙입니다.
- 코드 필드명과 상태값은 영문 원문을 유지합니다.
- 현재 지원하지 않거나 검증하지 않은 기능을 사용할 수 있다고 쓰지 않습니다.
- 과거 경로 대신 `docs/architecture/`, `docs/decisions/`와 실제 코드 경로를 연결합니다.
