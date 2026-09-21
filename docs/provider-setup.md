# LLM Provider 설정

Agent 이름·역할·입출력은 특정 Provider나 model에 고정되지 않습니다. 실제 연결은 setup이 만든 `provider_profile_ref + model` 설정으로 선택합니다.

현재 SimpleRuntime에서 직접 사용할 수 있는 경로는 다음 두 가지입니다.

- OpenAI Responses API: 환경변수의 API key 사용
- 공식 Codex CLI: ChatGPT 회원 로그인 사용

Anthropic API나 Claude Code 회원 로그인을 위한 검증된 SimpleRuntime adapter는 현재 포함하지 않습니다. 이름만 설정해 사용할 수 있는 것처럼 취급하지 않습니다.

공식 안내:

- [OpenAI API quickstart](https://developers.openai.com/api/docs/quickstart)
- [Codex 인증](https://developers.openai.com/codex/auth)

## OpenAI API

key를 TOML, Markdown, Git, 로그에 쓰지 않습니다.

```powershell
$env:OPENAI_API_KEY = "<key>"
sastsimi setup --auth api-key --provider openai --model <model>
```

```bash
export OPENAI_API_KEY='<key>'
sastsimi setup --auth api-key --provider openai --model <model>
```

설정 파일에는 `env:OPENAI_API_KEY`라는 환경변수 참조만 저장됩니다. 분석을 실행하는 각 터미널이나 서비스에도 해당 환경변수가 있어야 합니다.

## Codex 회원 로그인

공식 Codex CLI에서 로그인합니다.

```text
codex login
codex login status
sastsimi setup --auth subscription --provider codex --model <model>
```

SASTSIMI는 현재 컴퓨터의 공식 CLI 실행 파일과 SHA-256을 profile에 기록하고 호출 직전에 다시 확인합니다. 브라우저 cookie를 읽거나 browser profile, 다른 사용자의 인증 파일을 복사하지 않습니다.

## Claude 구독 로그인 — 공식 `claude -p` 경로, LOCAL_EVALUATION 한정

Claude 구독은 공식 Claude Code CLI 경로만 허용합니다. credential 파일·cookie·token을 직접 읽거나 다른 HTTP client에 재사용하지 않습니다. 공식 인증 안내는 [Claude Code 인증 문서](https://code.claude.com/docs/en/authentication)를 참고하세요.

자격 증명은 분석 저장소와 겹치지 않는 **격리된 설정 디렉터리**에 둡니다. 이는 Codex의 `CODEX_HOME` 격리와 같은 역할입니다.

```text
mkdir -p ~/.sastsimi/claude-home
CLAUDE_CONFIG_DIR=~/.sastsimi/claude-home claude auth login
CLAUDE_CONFIG_DIR=~/.sastsimi/claude-home claude auth status
```

`auth status`가 `loggedIn=true`, `authMethod="claude.ai"`, `apiProvider="firstParty"`, non-empty `subscriptionType`이고 `apiKeySource`가 **없을** 때만 구독 경로로 인정합니다. `authMethod`가 `api_key`·`oauth_token`이거나 `apiKeySource`가 있으면 adapter가 호출 전에 `AUTH_REQUIRED`로 거절합니다. 환경에 `ANTHROPIC_API_KEY`가 있어도 child 환경 allowlist에 없으므로 전달되지 않습니다.

adapter는 다음 경계를 강제합니다. 이 값들은 client가 `system/init` 이벤트로 **스스로 보고**하며, 보고값이 다르면 호출을 중단합니다.

| 경계 | 강제 방법 | init 보고값 |
|---|---|---|
| `tool_mode=DISABLED` | `--tools ""` | `tools` ⊆ `["StructuredOutput"]` |
| `mcp_mode=DISABLED` | `--strict-mcp-config`, `--mcp-config` 미전달 | `mcp_servers=[]` |
| `plugin_mode=DISABLED` | `--safe-mode` | `plugins=[]` |
| `hooks_mode=DISABLED` | `--safe-mode` | — |
| `instruction_sources=EXPLICIT_SASTSIMI_PAYLOAD_ONLY` | `--disable-slash-commands`, `--setting-sources ""`, `CLAUDE_CODE_DISABLE_*` | `slash_commands=[]`, `skills=[]`, `memory_paths` 없음 |
| `working_directory_mode=ISOLATED_EMPTY` | 빈 임시 디렉터리를 cwd로 사용 후 폐기 | `cwd` |
| `provider_fallback=DISABLED` | `--fallback-model` 미전달, `CLAUDE_CODE_DISABLE_*_FALLBACK` | `model`, `claude_code_version` |

`--settings`는 절대 전달하지 않습니다. settings 문서의 `apiKeyHelper`는 API 자격 증명 경로이자 임의 명령 실행 통로이기 때문입니다. 같은 이유로 `CLAUDE_CODE_MANAGED_SETTINGS_PATH`를 무력화합니다. 다만 관리자 정책(managed settings)은 설계상 `--safe-mode`로도 꺼지지 않으므로, `/etc/claude-code/managed-settings.json`을 신뢰할 수 없는 host에서는 이 경로를 쓰지 않습니다.

현재 상태는 **LOCAL_EVALUATION 전용**입니다. 프롬프트는 stdin으로만 전달되고 session은 항상 `NEW`이며 `RESUME`은 지원하지 않습니다.

profile은 먼저 `EXPERIMENTAL`로 발급되고, 실행 시작 시 bounded live probe(구조화 출력, 서로 다른 NEW session, timeout 분류, 빈 자격 증명 디렉터리의 `AUTH_REQUIRED` 분류)를 통과해야만 **local-only `SUPPORTED`** 수정본이 생깁니다. 이 수정본에는 `LOCAL_EVALUATION_ONLY`, `LOCAL_VALIDATION_NOT_PRODUCTION_PVD`, `PRODUCTION_APPROVAL_NOT_GRANTED` 제한이 항상 붙습니다. production `SUPPORTED` 승격에는 `PVD-01`~`PVD-15`와 사람 승인이 별도로 필요합니다.

`[claude]` 절이 있는 profile은 `evaluate analyze`와 `evaluate simple-resume` 양쪽에서 Claude 경로로 실행됩니다. 한 profile에 `[claude]`와 `[codex]`를 동시에 두거나 둘 다 비우면 로드 시점에 거절됩니다. 예시는 [`config/profiles/local-evaluation.claude.example.toml`](../config/profiles/local-evaluation.claude.example.toml)에 있습니다.

실제 로그인된 CLI로 경계를 확인하는 opt-in smoke test가 있습니다. 기본 테스트는 외부 호출을 하지 않습니다.

```text
SASTSIMI_CLAUDE_LIVE=1 \
SASTSIMI_CLAUDE_LIVE_EXECUTABLE=<claude 실행 파일 절대 경로> \
SASTSIMI_CLAUDE_LIVE_CONFIG_DIR=~/.sastsimi/claude-home \
SASTSIMI_CLAUDE_LIVE_CLIENT_VERSION=<claude --version 의 버전> \
SASTSIMI_CLAUDE_LIVE_MODEL=<검증에 사용할 model id> \
uv run pytest tests/integration/providers/test_claude_subscription_live.py
```

## onboarding 명령의 역할

onboarding 명령은 “시험을 대신 수행해 PASS를 만들어 주는 명령”이 아닙니다. 외부에서 실제로 수집하고 사람이 승인한 근거를 가져와, 현재 profile·Provider·model·Prompt와 정확히 같은지 다시 확인합니다.

먼저 secret 없는 준비 계획을 만들고 필요한 항목을 조회합니다. `init`은 실행할 probe와 검토 항목을 적은 계획만 만들며 어떤 항목도 승인하지 않습니다.

```text
uv run sastsimi --data-dir <data-dir> onboarding init --profile <production-profile.toml> --output-dir <onboarding-work-dir> --format json
```

같은 `output-dir`의 기존 계획을 덮어쓰지 않습니다. 이어서 현재 profile과 Prompt hash에 필요한 항목을 조회합니다.

```text
uv run sastsimi --data-dir <data-dir> onboarding requirements --profile <production-profile.toml> --format json
```

이 명령은 필요한 PVD 번호, Prompt route와 template hash를 보여 주고 `BLOCKED`로 끝납니다. 준비 완료를 뜻하지 않습니다.

운영 담당자는 다음을 별도 승인 절차에서 준비합니다.

Agent 호출은 같은 인증 파일을 동시에 갱신하는 충돌을 줄이기 위해 SimpleRuntime에서 순차 처리합니다. 각 역할은 독립 Prompt와 구조화 출력 계약을 사용하지만, 사람이 Codex Desktop에서 채팅 창을 직접 여는 방식은 아닙니다.

## model 변경

model은 setup을 다시 실행해 바꿉니다.

```text
sastsimi setup --auth subscription --provider codex --model <new-model>
```

model을 바꿔도 Hypothesis·Pro·Con·Verification·Gate·Reporter 역할은 바뀌지 않습니다. 다만 현재 계정에 model 접근 권한이 없거나 구조화 출력이 맞지 않으면 분석은 `AUTH_REQUIRED`, `BLOCKED` 또는 verdict 없는 `FAILED`로 중단됩니다. 이를 취약점 `FALSE`로 바꾸지 않습니다.

## 호출 기록

각 LLM 호출은 다음 감사 정보를 저장합니다.

- 역할과 단계
- 사용한 Provider와 model
- prompt·output digest
- 시작·종료 시각과 소요 시간
- 확인한 exact artifact reference
- 사람이 읽을 수 있는 근거·행동·판정 이유 요약

숨겨진 내부 사고 원문, 전체 prompt, API key, token, 로그인 session과 민감한 전체 코드는 대시보드에 표시하지 않습니다.
