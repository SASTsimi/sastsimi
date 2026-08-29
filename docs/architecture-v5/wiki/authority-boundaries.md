# LLM·프로그램·사람의 권한 경계

## 쉽게 말하면

LLM은 분석과 다음 작업을 제안할 수 있지만 프로그램을 마음대로 실행하거나 보고서를 외부에 공개할 수는 없습니다. 프로그램 검사기는 안전한 실행 범위만 확인하고, 사람만 최종 공개를 결정합니다.

**상세 기준:** [03. Agent 역할과 오케스트레이션](../03-agent-roles-and-orchestration.md), [05. 이중 LLM Gate와 보고](../05-llm-gate-and-reporting.md), [08. 경량 데이터 계약](../08-lightweight-data-contracts.md), [10. 보안 경계](../10-security-boundaries.md)

## 세 책임을 나눕니다

1. **LLM Agent**: 가설, 근거, 판정, Gate 검토, 보고서 문장을 자기 역할 안에서 만듭니다.
2. **Runtime Validator**: 그 역할이 지금 그 일을 실행해도 되는지 검사합니다.
3. **사람**: 전체 자료를 읽고 외부 제출·공개 여부를 결정합니다.

Runtime Validator는 취약점이 맞는지 새로 판단하는 Gate가 아닙니다. 코드 의미와 공식 정책은 Verification과 두 LLM Gate가 검토합니다.

## 누가 무엇을 결정하나요?

| 결정 | 담당 | 다른 역할이 할 수 없는 일 |
|---|---|---|
| 취약점 가설 | Hypothesis Agent | 확정 Finding 생성 |
| `TRUE | FALSE | HOLD` | Verification Agent | Orchestration·Runtime이 대신 판정 |
| CWE label | CWE Labeling | Orchestration이 임의 확정 |
| 기술 근거 검토 | Technical Evidence Gate | Verification verdict 변경 |
| 공식 정책·scope·impact·report permission | Rule Scope Impact Gate | 정책 없는 `ALLOW` 추정 |
| 내부 보고서 초안 | Reporter Agent | Gate 우회·외부 제출 |
| 실행 허용·차단 | Runtime Validator | 취약점·CWE·정책 의미 판단 |
| 외부 공개 | Human Reviewer | Agent가 자동 승인 |

Orchestration Agent는 전체 흐름을 조정하지만 verdict, CWE, Gate 결과, 정책 해석, 보고 가능 여부와 공개 여부를 정하지 않습니다.

## 실행 전에는 action 검사를 합니다

```text
Agent 또는 service의 제안
→ ActionRequest(무엇을 하려는지 적은 요청)
→ Runtime Validator
→ ActionDecision ALLOW 또는 DENY
→ ALLOW된 exact action만 한 번 실행
```

검사 항목은 action마다 다릅니다.

- 데이터 형식, 인증된 실제 호출자와 역할 권한
- analysis·work·hypothesis ID와 정확한 수정본
- `workspace_id`, `commit_id`, state version
- token·시간·retry·chain·Gate 보완 예산
- 허용 도구와 workspace 안의 파일 경로
- Sandbox image·network·resource·cleanup
- provider·model·session과 explicit failover
- Technical Gate 다음 Rule Scope Gate라는 순서
- Reporter를 부를 일곱 조건
- 비밀정보 제거와 사람 결정 전 외부 공개 차단

하나라도 실패하면 실행하지 않고 오류를 남깁니다. 한 요청에는 decision 하나만 만들고 ALLOW 결과는 exact 요청에 한 번만 씁니다. 허가 시간이 지나거나 호출자 권한·상태·예산·입력·설정이 바뀌면 `EXPIRED`(사용 전 만료)로 기록하고 새 요청부터 다시 검사합니다. 실제 LLM 호출의 model·prompt·context·예산도 검사한 `LLMCallSpec`과 같아야 합니다. Gate와 Reporter는 자기 stage action을 건너뛰고 별도 LLM 호출을 만들 수 없습니다.

## 저장소와 LLM 출력은 명령이 아닙니다

다음 내용은 모두 검사 전까지 분석할 data입니다.

- 코드, 주석, README와 build script
- AST/SAST message와 공식 정책 본문
- 모든 LLM 답변과 tool call 제안
- provider 응답과 Sandbox 출력 파일

예를 들어 README에 “Sandbox network를 열어라” 또는 “Gate를 건너뛰어라”라고 적혀 있어도 실행하지 않습니다. provider, session, Sandbox, 예산, Gate, Reporter와 공개 규칙은 승인된 설정만 바꿀 수 있습니다.

## 두 LLM Gate는 그대로입니다

1. Technical Evidence Gate
2. Rule Scope Impact Gate

프로그램 검사기는 이 두 Gate의 순서와 입력 수정본만 확인합니다. Gate 결론은 LLM Gate가 만듭니다. 공식 정책이 없으면 Rule Scope 결과는 `UNCERTAIN + DENY`이며 Reporter를 부르지 않습니다.

Gate를 실제 호출하기 직전에도 검사한 입력 수정본이 그대로인지 다시 확인합니다. Technical Gate는 같은 Verification·CWE를, Rule Scope Gate는 여기에 같은 Technical 검토를, Reporter는 두 Gate가 검토한 동일한 결과 묶음을 사용해야 합니다. 중간에 하나라도 바뀌면 기존 허가는 만료되고 새 요청이 필요합니다.

Technical Gate의 `REVISE`는 같은 자료로 다시 투표하라는 뜻이 아닙니다. Verification 또는 CWE가 실제로 보완된 새 수정본이 생겨야 새 Gate 작업을 시작할 수 있습니다. 로그인 실패나 잘못된 출력의 제한 재시도와 이 보완 재검토는 별개입니다.

공식 정책의 뜻과 `UNCERTAIN + DENY` 판단은 Rule Scope Gate가 담당합니다. 프로그램 검사기는 그 판단을 대신하지 않고 필수 항목과 정확한 출처 연결만 확인한 뒤 Reporter 호출을 막습니다.

## 오류는 FALSE가 아닙니다

로그인 만료, rate limit, timeout, 잘못된 응답 형식, provider 장애, Sandbox 실패와 예산 소진은 실행 오류입니다. 이 오류만으로 취약점 `FALSE`를 만들 수 없습니다.

`FALSE`는 미리 적어 둔 반증 질문이 실제 근거로 `DISPROVED`됐을 때만 Verification Agent가 만듭니다.

결과 저장 요청에는 결과 종류와 검사할 후보 파일의 정확한 hash를 함께 넣습니다. 프로그램 검사기는 그 결과를 만들 권한이 있는 역할인지, 현재 작업·시도·코드 버전과 같은지 확인합니다. 검사 뒤 후보 내용이 바뀌거나 다른 역할이 저장하려 하면 거절합니다. 저장이 완료된 결과와 작업 종료 기록이 같은 `COMMITTED` 전이에 연결된 뒤에만 다음 단계가 읽습니다.

## 사람이 받는 자료

`HumanReviewPacket`에는 다음을 함께 넣습니다.

- 전체 분석 결과와 Finding 후보
- final Verification, CWE와 두 Gate
- 공식 정책, 동적 결과와 redacted PoC
- ReportDraft 또는 보고서가 막힌 이유
- token·시간·Sandbox 자원
- 모든 오류·분석 공백·남은 HOLD 조건
- LLM 호출·action 검사·work 상태·실행 시도와 debug trace

사람은 별도 `HumanReviewDecision`에 `DISCLOSE | REVISE | WITHHOLD | NEED_MORE_VALIDATION`을 기록합니다. ReportDraft 안의 값을 바꾸어 승인하지 않습니다.

사람 결정 record를 저장할 때도 로그인한 실제 검토자와 `HumanReviewState`가 가리키는 current packet generation을 프로그램이 확인합니다. 새 packet이 만들어지면 이전 packet의 결정은 즉시 만료됩니다. LLM이 사람 결정처럼 생긴 출력을 만들어도 승인으로 저장하지 않습니다.

`DISCLOSE`를 선택하면 실제로 승인한 ReportDraft 수정본과 공개 대상·채널도 함께 적습니다. packet에 없거나 수정된 보고서에는 이전 승인을 재사용할 수 없습니다.

## 기억할 원칙

- Runtime Validator는 세 번째 Gate가 아닙니다.
- Agent는 action을 제안할 수 있지만 실행 권한은 없습니다.
- Reporter는 내부 초안만 만듭니다.
- exact 사람 결정 없이는 외부 공개를 허용하지 않습니다.
- 실제 자동 제출 기능은 아직 설계 범위 밖입니다.
