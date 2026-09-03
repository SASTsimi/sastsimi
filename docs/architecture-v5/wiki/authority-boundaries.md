# LLM·프로그램·사람의 권한 경계

## 쉽게 말하면

LLM은 분석과 다음 작업을 제안할 수 있지만 프로그램을 마음대로 실행하거나 보고서를 외부에 공개할 수는 없습니다. 프로그램 검사기는 안전한 실행 범위만 확인하고 `ReportDraft` 뒤에 Agent 자동화를 종료합니다.

**상세 기준:** [03. Agent 역할과 오케스트레이션](../03-agent-roles-and-orchestration.md), [05. 이중 LLM Gate와 보고](../05-llm-gate-and-reporting.md), [08. 경량 데이터 계약](../08-lightweight-data-contracts.md), [10. 보안 경계](../10-security-boundaries.md)

## 세 책임을 나눕니다

1. **LLM Agent**: 가설, 근거, 판정, Gate 검토, 보고서 문장을 자기 역할 안에서 만듭니다.
2. **Runtime Validator**: 그 역할이 지금 그 일을 실행해도 되는지 검사합니다.
3. **사람**: 자동화 종료 뒤 결과를 검토·수정하고 제출·공개 여부를 시스템 밖에서 결정합니다.

Runtime Validator는 취약점이 맞는지 새로 판단하는 Gate가 아닙니다. 코드 의미와 공식 정책은 Verification과 두 LLM Gate가 검토합니다.

## 누가 무엇을 결정하나요?

| 결정 | 담당 | 다른 역할이 할 수 없는 일 |
|---|---|---|
| 취약점 가설 | Hypothesis Agent | 확정 Finding 생성 |
| `TRUE | FALSE | HOLD` | Verification Agent | Orchestration·Runtime이 대신 판정 |
| 필요한 환경 조건·허용 차이와 계획 revision | R6 Verification | R7이 요구사항·허용 대체값을 수정하거나 차이를 임의 승인 |
| CWE label | CWE Labeling | Orchestration이 임의 확정 |
| 기술 근거 검토 | Technical Evidence Gate | Verification verdict 변경 |
| 공식 정책·scope·impact·report permission | Rule Scope Impact Gate | 정책 없는 `ALLOW` 추정 |
| 내부 보고서 초안 | Reporter Agent | Gate 우회·외부 제출 |
| 일반 실행 허용·차단과 exact plan·requirements Sandbox 호출 전제 확인 | Runtime Validator | 환경 의미·취약점·CWE·정책 또는 Sandbox 세부 정책 판단 |
| Sandbox 세부 안전 정책 검사 | Sandbox Controller | 환경 요구사항·재현 모드·계획·취약점 판정 변경 |
| 실제 환경 구성·요구사항 비교·Health Check와 승인된 공격 단계 실행 | Sandbox Runner | 환경 차이 수용, 허용되지 않은 fallback, 정책 변경 또는 계획 밖 명령 실행 |
| 동적 결과 reference 조립 | Sandbox Result Assembler | 다른 attempt 자료 혼합 또는 참조만으로 성공 판단 |

Orchestration Agent는 proposal 검증·전역 등록·Verification 배정을 조정하지만 배정 뒤 가설 내부 Context·Pro/Con·dynamic·Gate·Chaining, verdict, CWE, 정책 해석, 보고 가능 여부와 공개 여부를 정하지 않습니다. Verification이 가설 내부 다음 작업을 정해도 프로그램 검사를 우회할 수 없습니다.

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
- Sandbox 재현 계획·단계·공격 입력·cleanup(실행 후 정리)과 image·network·resource
- provider·model·session과 explicit failover
- Technical Gate 다음 Rule Scope Gate라는 순서
- Reporter를 부를 일곱 조건
- ReportDraft의 exact provenance, restriction·limitation 보존과 비밀정보 제거

하나라도 실패하면 실행하지 않고 오류를 남깁니다. 한 요청에는 decision 하나만 만들고 ALLOW 결과는 exact 요청에 한 번만 씁니다. 허가 시간이 지나거나 호출자 권한·상태·예산·입력·설정이 바뀌면 `EXPIRED`(사용 전 만료)로 기록하고 새 요청부터 다시 검사합니다. 실제 LLM 호출의 model·prompt·context·예산도 검사한 `LLMCallSpec`과 같아야 합니다. Gate와 Reporter는 자기 stage action을 건너뛰고 별도 LLM 호출을 만들 수 없습니다.

## 저장소와 LLM 출력은 명령이 아닙니다

다음 내용은 모두 검사 전까지 분석할 data입니다.

- 코드, 주석, README와 build script
- AST/SAST message와 공식 정책 본문
- 모든 LLM 답변과 tool call 제안
- provider 응답과 Sandbox 출력 파일

예를 들어 README에 “Sandbox network를 열어라” 또는 “Gate를 건너뛰어라”라고 적혀 있어도 실행하지 않습니다. provider, session, Sandbox, 예산, Gate, Reporter와 자동화 종료 경계는 승인된 설정만 바꿀 수 있습니다.

## 두 LLM Gate는 그대로입니다

1. Technical Evidence Gate
2. Rule Scope Impact Gate

프로그램 검사기는 이 두 Gate의 순서와 입력 수정본만 확인합니다. Gate 결론은 LLM Gate가 만듭니다. 공식 정책이 없으면 Rule Scope 결과는 `UNCERTAIN + DENY`이며 Reporter를 부르지 않습니다.

Gate를 실제 호출하기 직전에도 검사한 입력 수정본이 그대로인지 다시 확인합니다. Technical Gate는 같은 Verification·CWE를, Rule Scope Gate는 여기에 같은 Technical 검토를, Reporter는 두 Gate가 검토한 동일한 결과 묶음을 사용해야 합니다. 중간에 하나라도 바뀌면 기존 허가는 만료되고 새 요청이 필요합니다.

Technical Gate의 `REVISE`는 같은 자료로 다시 투표하라는 뜻이 아닙니다. 같은 가설의 Verification owner가 직접 받고, Verification 또는 CWE가 실제로 보완된 새 수정본이 생겨야 새 Gate 작업을 시작할 수 있습니다. Orchestration이나 Chaining이 목적지를 다시 고르지 않습니다. 로그인 실패나 잘못된 출력의 제한 재시도와 이 보완 재검토는 별개입니다.

공식 정책의 뜻과 `UNCERTAIN + DENY` 판단은 Rule Scope Gate가 담당합니다. 프로그램 검사기는 그 판단을 대신하지 않고 필수 항목과 정확한 출처 연결만 확인한 뒤 Reporter 호출을 막습니다.

## 오류는 FALSE가 아닙니다

로그인 만료, rate limit, timeout, 잘못된 응답 형식, provider 장애, Sandbox 실패와 예산 소진은 실행 오류입니다. 이 오류만으로 취약점 `FALSE`를 만들 수 없습니다.

`FALSE`는 미리 적어 둔 반증 질문이 실제 근거로 `DISPROVED`됐을 때만 Verification Agent가 만듭니다.

결과 저장 요청에는 결과 종류와 검사할 후보 파일의 정확한 hash를 함께 넣습니다. 프로그램 검사기는 그 결과를 만들 권한이 있는 역할인지, 현재 작업·시도·코드 버전과 같은지 확인합니다. 검사 뒤 후보 내용이 바뀌거나 다른 역할이 저장하려 하면 거절합니다. 저장이 완료된 결과와 작업 종료 기록이 같은 `COMMITTED` 전이에 연결된 뒤에만 다음 단계가 읽습니다.

동적 재현 전에는 R6 Verification이 `EnvironmentRequirements`(애플리케이션에 필요한 조건)와 이를 가리키는 `ReproductionPlan`(어떤 단계와 공격 입력을 실행하고 어떻게 정리할지 적은 계획)의 정확한 수정본을 고정합니다. Runtime Validator는 요청자·상태·예산과 exact plan·current requirements reference를 확인해 Sandbox 호출만 허가합니다. Sandbox Controller는 실행 직전에 image·명령·파일·네트워크·자원·정리 정책을 한 번 검사하고 exact 판정을 저장합니다. 통과한 계획을 받은 Runner는 실제 환경·Health Check를 각 요구사항과 비교하고 필수 항목이 모두 맞을 때만 공격 단계를 실행합니다. 차이가 있으면 R7이 고치거나 허용하지 않고 R6에 돌려보냅니다. R6가 환경 조건을 바꿔 허용하면 새 요구사항과 이를 가리키는 새 계획을 함께 만들고, 단계만 바꾸면 새 계획만 만든 뒤 새 Sandbox 검사를 거칩니다. Sandbox Result Assembler는 같은 분석·가설의 exact R6 plan closure와 같은 R7 실행 attempt에서 나온 정책 판정·실제 환경 비교·step log·PoC·cleanup reference만 동적 결과에 연결합니다. plan과 실제 환경의 requirements revision이 다르면 저장하지 않습니다. 계획에 없던 명령·공격 입력은 실행하거나 저장하지 않으며 환경 실패·차이는 `FALSE`가 아닙니다. Verification은 저장이 확정된 결과를 읽어 판정합니다.

## 자동화가 끝나는 지점

Reporter는 current Finding·Verification·CWE·두 Gate·정책을 정확히 참조하고 restriction·limitation·남은 불확실성과 redaction 결과를 보존한 `ReportDraft`를 만듭니다. 선행 결과가 바뀌면 기존 초안은 감사 이력으로만 남고 current 결과에서 제외합니다.

이 초안과 실행 결과·PoC·자원·오류·HOLD 조건·debug trace를 `AnalysisRunResult`에 확정하면 Agent 자동화가 끝납니다. 이후 검토·수정·제출·공개는 사람이 시스템 밖에서 수행하며, 이를 위한 Agent action이나 상태는 없습니다.

## 기억할 원칙

- Runtime Validator는 세 번째 Gate가 아닙니다.
- Agent는 action을 제안할 수 있지만 실행 권한은 없습니다.
- Reporter는 안전한 내부 초안을 만드는 마지막 Agent입니다.
- Agent 자동화는 외부 제출·공개 action을 제공하지 않습니다.
- 사람 주도 후속 과정은 현재 설계 범위 밖입니다.
