# SASTSIMI 기여 안내

SASTSIMI의 현재 실행 기능을 유지하면서 코드와 문서를 안전하게 개선하기 위한 안내입니다.
처음 참여한다면 [문서 지도](./docs/DOCUMENT_GUIDE.md),
[현재 구현 아키텍처](./docs/architecture/README.md),
[구현 위치 지도](./docs/architecture/implementation-map.md)를 먼저 확인하세요.

## 현재 기준

- 일반 사용자 흐름은 `setup → analyze → status/resume → dashboard → result/poc/report`입니다.
- 분석 실행은 `SimpleRuntime`이 stage 호출, 결과 저장, 실패 지점 재시도와 진행 위치 기록을 담당합니다.
- 실제 stage 순서는 [파이프라인 문서](./docs/architecture/pipeline.md)를 기준으로 확인합니다.
- 공통 필드와 상태는 문서가 아니라 `src/sastsimi/contracts`,
  `src/sastsimi/simple_runtime/models.py`와 `schemas/generated`가 기준입니다.
- 과거 설계안과 역할별 검토 기록은 현재 계약이 아닙니다. 제거된 문서를 복원하거나 새 코드의
  근거로 사용하지 않습니다.

## 개발 환경 준비

```text
git clone https://github.com/SASTsimi/sastsimi.git
cd sastsimi
python -m pip install uv
uv sync --frozen --all-groups
uv run sastsimi --help
```

외부 LLM, OpenGrep, CodeQL 또는 Docker를 사용하는 변경은
[설치 문서](./docs/installation.md)와 [Provider 설정](./docs/provider-setup.md)을 함께 확인합니다.
API key, 로그인 token과 세션 파일은 저장소에 추가하지 않습니다.

## 작업 시작

1. 최신 `main`에서 별도 브랜치 또는 worktree를 만듭니다.
2. 하나의 Issue에는 완료 여부를 독립적으로 판단할 수 있는 한 가지 목표만 둡니다.
3. 변경 전 관련 코드, 계약, 생성 schema와 테스트를 확인합니다.
4. 사용자 명령을 바꾼다면 기존 데이터와 고급 명령의 호환 범위를 먼저 확인합니다.
5. 아직 지원하지 않거나 검증하지 않은 외부 도구 조합을 사용할 수 있다고 문서화하지 않습니다.

```text
git fetch origin
git switch main
git pull --ff-only
git switch -c <type>/<short-name>
```

권장 branch prefix는 `feat/`, `fix/`, `docs/`, `test/`, `chore/`입니다.

## 변경 원칙

- Agent 출력은 제안입니다. ID 발급, 상태 변경, 저장, 재시도와 실행 권한은 Runtime이 결정합니다.
- 오류·인증 실패·도구 실패를 취약점 `FALSE`로 바꾸지 않습니다.
- final `TRUE`에는 같은 attempt의 성공한 동적 실행과 validated PoC가 필요합니다.
- PoC candidate와 validated PoC를 같은 결과로 취급하지 않습니다.
- analysis, workspace, commit, hypothesis, generation, attempt와 record reference를 섞지 않습니다.
- 성공한 checkpoint는 exact input reference와 stage version이 같을 때만 재사용합니다.
- secret, credential, 전체 prompt, 민감한 코드와 로컬 절대 경로를 로그·문서·예제에 넣지 않습니다.
- Dashboard와 Reporter는 저장된 결과를 표현할 뿐 새로운 판정이나 보안 사실을 만들지 않습니다.
- Provider와 model을 Agent 역할에 고정하지 않습니다.
- 외부 공개와 제보 여부는 자동화하지 않으며 사람이 최종 결정합니다.

공통 의미를 바꾸는 결정은 [현재 ADR](./docs/decisions/README.md)을 확인하고, 필요한 경우
새 ADR을 함께 제안합니다. 문서만 수정해 새 계약을 만들지 않습니다.

## 사용자 흐름을 바꿀 때

다음 명령은 일반 사용자용 진입점입니다.

```text
sastsimi setup
sastsimi analyze <repository> --commit <exact-SHA>
sastsimi status <analysis_id>
sastsimi resume <analysis_id>
sastsimi dashboard
sastsimi result <analysis_id>
sastsimi poc <finding_id>
sastsimi report <finding_id> --export markdown
```

CLI나 설정을 수정할 때는 Windows와 Linux/WSL 경로 처리, 기존 분석 데이터 조회,
`--format json`의 구조화 출력과 비밀정보 비노출을 함께 확인합니다. 대시보드는 로컬 읽기
전용이며 Runtime 상태를 자체적으로 변경하면 안 됩니다.

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

Python 코드, 계약, schema 또는 migration을 바꿨다면 관련 테스트가 통과한 뒤 병합 전
전체 검사를 실행합니다.

```text
uv run pytest -q
uv run ruff check .
uv run mypy src
```

설치·패키징 경로를 바꿨다면 wheel build와 깨끗한 가상환경 smoke test도 실행합니다.
외부 LLM, CodeQL, OpenGrep 또는 Docker가 필요한 검증을 실행하지 못했다면 성공했다고
쓰지 말고 PR에 이유와 남은 조건을 기록합니다.

## PR 작성과 검토

PR에는 다음 내용을 짧게 적습니다.

- 무엇을 왜 바꿨는지
- 영향받는 사용자 명령 또는 Runtime stage
- 바꾸지 않은 계약과 보안 경계
- 실행한 테스트와 결과
- 실행하지 못한 테스트와 이유
- 남은 Blocker/High와 후속 Issue

작성자는 먼저 self-review를 하고 영향받는 코드 owner와 앞·뒤 단계 담당자의 검토를
요청합니다. 공통 계약, 판정, exact reference, Provider 인증 또는 Docker 경계를 바꾼
PR은 해당 영역 검토 없이 병합하지 않습니다. Blocker와 High 문제는 병합 전에 해결하고,
Medium과 Low는 별도 Issue로 분리할 수 있습니다.

## 문서 작성

- 짧은 한국어 문장을 우선합니다.
- 처음 나오는 전문용어에는 쉬운 설명을 붙입니다.
- 코드 필드명과 상태값은 영문 원문을 유지합니다.
- 현재 지원하지 않거나 검증하지 않은 기능을 사용할 수 있다고 쓰지 않습니다.
- 실제 동작, 사용자 명령, 기본 경로와 생성 파일명을 코드와 맞춥니다.
- 과거 경로 대신 `docs/architecture/`, `docs/decisions/`와 실제 코드 경로를 연결합니다.
- 문서를 삭제하거나 옮겼다면 `docs/DOCUMENT_GUIDE.md`와 내부 링크도 함께 수정합니다.
