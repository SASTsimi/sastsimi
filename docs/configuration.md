# SASTSIMI 설정과 인증

## 설정 우선순위

설정은 뒤에 있는 값이 앞의 값을 덮습니다.

```text
기본값 < --config로 지정한 TOML < SASTSIMI_* 환경변수 < CLI 옵션
```

TOML은 자동 검색하지 않습니다. 반드시 `--config`로 승인한 파일을 지정합니다.

```powershell
sastsimi --config config/sastsimi.example.toml doctor --format json
```

현재 허용하는 TOML field는 다음 네 개뿐입니다.

| field | 값 | 기본값 |
|---|---|---|
| `schema_version` | 정수 `1` | `1`; 명시한 TOML에는 필수 |
| `log_level` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` | `INFO` |
| `output_format` | `text`, `json` | `text` |
| `data_dir` | 로컬 경로 | 운영체제별 user state directory |

예제는 [`config/sastsimi.example.toml`](../config/sastsimi.example.toml)에 있습니다.
알 수 없는 field는 fail-closed로 거절합니다.

## 환경변수와 CLI override

허용 환경변수는 다음 세 개뿐입니다.

```text
SASTSIMI_LOG_LEVEL
SASTSIMI_OUTPUT_FORMAT
SASTSIMI_DATA_DIR
```

그 밖의 `SASTSIMI_*` 환경변수가 있으면 설정 오류가 납니다. CLI에서는
`--log-level`, `--data-dir`, 각 명령의 `--format`만 override할 수 있습니다.

## data directory

`data_dir` 아래에는 다음 자료가 생깁니다.

```text
db/sastsimi.sqlite3     SQLite 상태와 기록
artifacts/              hash로 검증하는 artifact
staging/                원자적 저장 전 임시 자료
quarantine/             검증 실패 자료
reports/                사람이 검토할 Markdown export
```

이 폴더에는 코드, PoC, 로그와 보고서가 들어갈 수 있습니다. source control이나
공유 폴더에 두지 말고 사용자별 접근 권한과 backup 정책을 적용하세요.

## secret 금지

API key, Codex 인증 파일, session cookie, 비밀번호를 TOML, `SASTSIMI_*`, CLI
인자 또는 repository에 넣지 않습니다. 현재 `AppConfig`에는 secret field가 없으며
public fake `analyze`는 외부 provider 인증을 사용하지 않습니다.

## OpenAI와 Codex 인증

두 방식은 별개입니다.

### OpenAI API key

OpenAI API는 usage-based billing을 사용합니다. 공식
[API quickstart](https://developers.openai.com/api/docs/quickstart)에서
key를 만들고 `OPENAI_API_KEY` 같은 process 환경으로 주입합니다. key를 파일이나
명령 history에 남기지 않습니다.

현재 SASTSIMI public CLI는 `OPENAI_API_KEY`를 읽어 production 분석을 시작하는
명령을 제공하지 않습니다. `capability probe OPENAI_API`도 secret 값을 받지 않고,
`--credential-ref`에는 secret 자체가 아닌 외부 secret manager의 reference만
허용합니다.

### ChatGPT 구독으로 Codex 로그인

Codex CLI는 공식
[Codex 인증 안내](https://developers.openai.com/codex/auth)에 따라 브라우저에서
`codex login`하고 `codex login status`로 상태를 확인할 수 있습니다. ChatGPT
구독 로그인은 subscription access이고 API key 사용은 별도 API billing입니다.

Codex 인증 cache는 운영체제 credential store 또는 `~/.codex/auth.json`에
있을 수 있으며 password처럼 다뤄야 합니다. 복사·commit하거나 SASTSIMI 설정에
경로를 넣지 않습니다. 현재 SASTSIMI가 이 로그인 정보를 자동 발견하거나
재사용한다고 주장하지 않습니다.

외부 도구의 실제 probe와 승인은 [외부 도구 안내](./external-tools.md)를
확인하세요.
