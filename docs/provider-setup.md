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
