# LLM Provider 설정

Agent 이름·역할·입출력은 특정 Provider나 model에 고정되지 않습니다. 실제 연결은 setup이 만든 `provider_profile_ref + model` 설정으로 선택합니다.

현재 SimpleRuntime에서 직접 사용할 수 있는 경로는 다음 네 가지입니다.

- OpenAI Responses API: 환경변수의 API key 사용
- 공식 Codex CLI: ChatGPT 회원 로그인 사용
- Cursor SDK API key 또는 Cursor Agent CLI 회원 로그인
- 공식 Claude Code CLI: 본인의 claude.ai 유료 구독 로그인 사용 (`2.1.280` 검증 경계)

Claude 경로는 별도의 Anthropic API key를 사용하지 않습니다. 아직 실제 유료 계정 smoke test는 하지 않았으므로, 모의 CLI 테스트 통과와 실제 계정에서의 동작 검증을 구분해야 합니다.

공식 안내:

- [OpenAI API quickstart](https://developers.openai.com/api/docs/quickstart)
- [Codex 인증](https://developers.openai.com/codex/auth)
- [Claude Code CLI](https://code.claude.com/docs/en/cli-reference)
- [Claude Code 시작 및 로그인](https://code.claude.com/docs/en/setup)
- [Claude Code 환경변수](https://code.claude.com/docs/en/env-vars)

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

Agent 호출은 같은 인증 파일을 동시에 갱신하는 충돌을 줄이기 위해 SimpleRuntime에서 순차 처리합니다. 각 역할은 독립 Prompt와 구조화 출력 계약을 사용하지만, 사람이 Codex Desktop에서 채팅 창을 직접 여는 방식은 아닙니다.

## Claude 회원 로그인 (선택형)

현재 검증된 Claude Code CLI 버전은 `2.1.280`입니다. 다른 버전이면 setup은 `CLAUDE_CLI_UNSUPPORTED_VERSION`으로 차단하며 자동 업그레이드하거나 추측해 호출하지 않습니다. 무료 claude.ai 계정만으로는 Claude Code를 사용할 수 없을 수 있습니다. 본인 계정으로 로그인하고 구독·추가 사용량 설정을 먼저 확인하세요. API key나 다른 팀원의 로그인 세션을 공유하지 않습니다.

PowerShell에서 각 줄을 따로 실행합니다.

```powershell
.\.venv\Scripts\Activate.ps1
npm install -g @anthropic-ai/claude-code@2.1.280
claude --version
claude auth login
claude auth status --json
sastsimi setup --non-interactive --auth subscription --provider claude --model <본인-계정에서-확인한-모델> --profile full
sastsimi analyze https://github.com/owner/repository.git --commit <정확한-40자리-SHA>
```

Claude CLI에서 직접 `/model` 명령으로 계정에 보이는 모델을 확인한 뒤 `--model`에 입력하세요. SASTSIMI는 Claude 모델 ID를 코드에 고정하지 않습니다. 최종 검증 Agent만 다른 모델을 쓸 경우 setup에 `--agent-model verification_result=<확인한-모델>`을 추가합니다. 나머지 Agent는 `--model`의 공통 모델을 사용합니다.

`ANTHROPIC_API_KEY`는 Claude 회원 로그인 경로에 필요하지 않습니다. CLI 호출 시 이 변수와 `PATH`, 저장소 설정·MCP·도구를 자식 프로세스에 전달하지 않고, 빈 임시 작업 디렉터리에서 실행합니다. 출력 이벤트가 이 격리를 증명하지 못하면 분석 Agent는 성공하지 않습니다. 응답 원문·검증된 JSON·시도 메타데이터는 별도 artifact/DB에 기록하며, 일반 로그에는 프롬프트와 인증정보를 기록하지 않습니다. 실패한 Agent는 제한 횟수만 재시도하고 체크포인트에 실패를 남겨 resume할 수 있습니다.

Claude 구독에서도 사용량 제한이나 추가 사용량 과금이 가능하므로 대시보드에는 잠재 추가 사용량으로 표시됩니다. 실제 비용 정보가 CLI에서 제공되지 않으면 0으로 추정하지 않고 미확인으로 남깁니다.

분석별 대시보드는 Provider와 무관하게 호출 수, 확인된 입력·출력 토큰, 확인된 비용과 비용 미제공 호출 수를 분리해 보여 줍니다. 비용 미제공은 무료나 0원이 아닙니다. `max_cost_minor_units`는 확인된 비용에만 적용되며, Provider가 비용을 보내지 않으면 실제 청구액을 보장할 수 없습니다.

운영 제한: 공식 문서에 따르면 `--safe-mode`에서도 조직의 managed policy hook은 적용될 수 있습니다. 현재 격리 검사는 도구·MCP·플러그인 이벤트를 검증하지만, 그 hook의 실행 부재까지 증명하지는 못합니다. 조직 관리형 Claude 환경에서는 관리자의 hook 정책을 확인하기 전까지 이 경로를 안전한 무도구 실행으로 간주하지 마세요. 실제 구독 계정의 최소 호출 검증도 아직 수행하지 않았습니다.

## model 변경

model은 setup을 다시 실행해 바꿉니다.

```text
sastsimi setup --auth subscription --provider codex --model <new-model>
```

model을 바꿔도 Hypothesis·Pro·Con·Verification·Gate·Reporter 역할은 바뀌지 않습니다. 다만 현재 계정에 model 접근 권한이 없거나 구조화 출력이 맞지 않으면 분석은 `AUTH_REQUIRED`, `BLOCKED` 또는 verdict 없는 `FAILED`로 중단됩니다. 이를 취약점 `FALSE`로 바꾸지 않습니다.

## 선택형 분석 설정

기존 설정은 그대로 작동합니다. 새 분석에서만 다른 가설 생성 방식을 시험하려면 setup 후 `profile.toml`을 열어 `hypothesis_feed = "facts_survey"`로 바꿉니다. 기본값 `current`는 기존 가설 생성 경로입니다. `facts_survey`는 Git 추적 파일에서 사실 후보를 만들고 각 후보의 판단을 저장해 재개 시 완료된 판단을 재사용합니다. 입력은 크기 제한이 있어 큰 저장소에서 `FACTS_BUDGET_EXHAUSTED`가 남으면 전체 저장소를 조사했다고 간주하지 마세요.

PowerShell에서 다음은 각각 한 줄 명령입니다.

```powershell
.\.venv\Scripts\Activate.ps1
notepad "$env:LOCALAPPDATA\sastsimi\sastsimi\profile.toml"
sastsimi status A-001
sastsimi resume A-001
```

같은 파일의 `max_parallel_hypotheses`, `max_parallel_builds`, `max_parallel_containers`는 각각 동시에 처리할 가설, Docker 빌드, 실행 중인 소유 컨테이너 상한입니다. 모두 기본값 `1`이며, 가설 병렬 처리를 늘리면 LLM 사용량과 Docker 자원 사용이 빨라질 수 있습니다. `llm_max_concurrency`는 이와 별도의 전체 LLM 호출 상한입니다. 진행 중인 분석의 설정을 바꾸기보다 새 분석에서 시험하세요.

## 호출 기록

각 LLM 호출은 다음 감사 정보를 저장합니다.

- 역할과 단계
- 사용한 Provider와 model
- prompt·output digest
- 시작·종료 시각과 소요 시간
- 확인한 exact artifact reference
- 사람이 읽을 수 있는 근거·행동·판정 이유 요약

숨겨진 내부 사고 원문, 전체 prompt, API key, token, 로그인 session과 민감한 전체 코드는 대시보드에 표시하지 않습니다.
