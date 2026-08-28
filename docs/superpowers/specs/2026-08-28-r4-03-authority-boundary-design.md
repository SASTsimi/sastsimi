# R4-03 프로그램 검사기와 사람·LLM 권한 경계 설계

## 상태

- 설계 상태: `DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED`
- 대상 Issue: [#15](https://github.com/SASTsimi/sastsimi/issues/15)
- 상위 Issue: [#5](https://github.com/SASTsimi/sastsimi/issues/5)
- 선행 기준: R4-01 공통 ID·상태·오류, R4-02 실행 상태·복구

## 목표

LLM Agent가 분석과 검토를 담당하는 현재 구조는 유지한다. 다만 Agent·저장소 문구·provider 응답이 실행 권한, 상태, 예산, Sandbox, 두 Gate 순서, 보고서 생성 또는 외부 공개 결정을 직접 바꾸지 못하게 한다.

이 설계는 세 책임을 분리한다.

1. LLM Agent와 서비스는 분석 결과 또는 다음 action을 **제안**한다.
2. 비-LLM runtime validator는 실행 가능한 action의 구조·순서·범위만 **검사하고 강제**한다.
3. 사람은 외부 제출·공개 여부를 **최종 결정**한다.

runtime validator는 취약점 진위, CWE 내용, 공식 정책 해석 또는 보고서 품질을 새로 판정하는 Gate가 아니다. Technical Evidence Gate와 Rule Scope Impact Gate는 기존처럼 서로 다른 LLM 검토 Agent 두 개다.

## 범위

포함한다.

- 역할별 제안·판단·검토·강제·사람 전용 권한
- 실행 요청과 runtime 허용·차단 결과의 최소 계약
- schema, ID, revision, 실행 상태, 예산, 도구, 경로, Sandbox, provider, Gate, Reporter, redaction, 공개 조건
- 저장소 내용과 LLM 출력의 비신뢰 처리
- provider 오류가 기술 verdict로 바뀌지 않는 조건
- 사람이 받을 결과 묶음과 최종 결정의 별도 계약
- 권한 우회 부정 시나리오

포함하지 않는다.

- 새로운 결정론적 Gate
- 취약점 판단 규칙 엔진
- provider·Sandbox·저장 제품 선택
- 외부 버그바운티 플랫폼 자동 제출 구현
- R5가 소유한 Finding 본문과 보고서 품질 기준의 세부 설계

## 역할 권한

| 역할 | 제안할 수 있음 | 직접 판단할 수 있음 | 검토할 수 있음 | 강제할 수 있음 | 사람만 결정 |
|---|---|---|---|---|---|
| Orchestration Agent | 실행 계획, 다음 작업, 병렬화, retry 후보 | 없음 | 진행 상태 요약 | 없음 | 없음 |
| Hypothesis Agent | 취약점 가설 | 없음 | static 사실을 입력으로 읽음 | 없음 | 없음 |
| Pro·Con Agent | 찬성·반대 근거 | 없음 | 자기 역할의 근거 | 없음 | 없음 |
| Verification Agent | 동적 재현·Research 요청 | `TRUE | FALSE | HOLD` | Pro·Con·static·dynamic 근거 | 없음 | 없음 |
| CWE Labeling | CWE 후보와 근거 | CWE label revision 생성 | Verification 결과 | 없음 | 없음 |
| Research Agent | bypass·alternate path·chain 후보 | 없음 | 기존 verdict와 Primitive | 없음 | 없음 |
| Technical Evidence Gate Agent | 보완 요청 | 없음 | verdict·근거·코드 흐름·CWE | 없음 | 없음 |
| Rule Scope Impact Gate Agent | 정책 누락·보완 사유 | `PASS | FAIL | UNCERTAIN`, `ALLOW | DENY` | 공식 정책·scope·impact | 없음 | 없음 |
| Reporter Agent | 내부 보고서 문장과 구성 | 없음 | 통과한 결과와 두 Gate | 없음 | 없음 |
| Runtime Validator | 허용 가능한 대체 action 안내 | 없음 | 실행 전제와 exact reference | 실행 허용·차단 | 없음 |
| Human Reviewer | 재검증·보완 요청 | 외부 제출·공개 결정 | 전체 결과 묶음 | 외부 공개 승인 | `DISCLOSE | REVISE | WITHHOLD | NEED_MORE_VALIDATION` |

Orchestration Agent는 `TRUE/FALSE/HOLD`, CWE, Gate 결과, 공식 정책의 의미, 보고 가능 여부와 공개 여부를 확정할 수 없다. runtime validator도 이 값을 대신 정하지 않고, 해당 값을 만들 권한이 있는 역할과 필요한 선행 record가 맞는지만 검사한다.

## 실행 요청과 검사 결과

### ActionRequest

Agent 또는 서비스가 부작용이 있는 실행을 원할 때 만드는 요청이다.

핵심 필드는 다음과 같다.

- `action_id`: 요청 하나의 ID
- `requested_by`: 요청한 역할
- `action_type`: 수행하려는 일
- `work_ref`: 연결된 현재 work와 state version
- `input_refs`: 실제로 읽을 record revision
- `tool_name`, `file_paths`, `network_targets`: 필요한 실행 범위
- `provider_profile_ref`, `session_mode`: LLM 호출 조건
- `reason`, `requested_at`

허용 action은 다음으로 제한한다.

`REGISTER_WORK | CHANGE_WORK_STATE | START_ATTEMPT | CANCEL_WORK | READ_CODE | RUN_TOOL | CALL_LLM | FETCH_POLICY | RUN_SANDBOX | SAVE_RESULT | CALL_TECHNICAL_GATE | CALL_RULE_SCOPE_GATE | CREATE_REPORT_DRAFT | PREPARE_HUMAN_REVIEW | SAVE_HUMAN_DECISION | EXTERNAL_DISCLOSURE`

action별로 쓰지 않는 필드는 `null` 또는 빈 배열이어야 한다. 예를 들어 `CALL_LLM`에는 provider profile과 session mode가 필요하고, `RUN_SANDBOX`에는 sandbox profile·image digest·network target이 필요하다. `EXTERNAL_DISCLOSURE`는 Human Reviewer만 요청할 수 있고 exact `HumanReviewDecision`을 입력으로 가져야 한다. 한 번이라도 `ActionDecision`이 저장된 요청은 수정하지 않는다. 범위를 바꾸거나 다시 시도하려면 새 `action_id`를 사용한다.

### ActionDecision

runtime validator의 검사 결과다.

- `decision_id`
- 정확한 `action_ref`
- `decision: ALLOW | DENY`
- 수행한 `ActionCheck[]`
- `error_ids`
- 검사한 `state_version`, 설정과 정책 revision
- `use_status: UNUSED | USED | NOT_USED | EXPIRED`
- `decided_at`

`ActionCheck`는 `check_type`, `result: PASS | FAIL`, `reason_code`, 민감정보가 제거된 `safe_message`를 갖는다. 각 action type의 필수 check는 모두 한 번씩 있어야 하고, 하나라도 `FAIL`이면 decision은 `DENY`다. `ALLOW`는 exact action과 state version에만 유효하며 다른 action·retry·revision에 재사용할 수 없다.

결정 내용과 검사 결과는 이후 revision에서 바꾸지 않는다. 실행 직전에 state·input·configuration이 달라졌으면 `UNUSED -> EXPIRED`로 바꾸고 실행을 거절한다. 그대로이면 compare-and-set으로 `UNUSED -> USED`를 먼저 저장한 뒤 exact action을 한 번만 실행한다. `USED`, `NOT_USED`, `EXPIRED`는 다시 사용할 수 없다.

## runtime validator가 강제할 항목

| check | 쉽게 말하면 | 검사 대상 |
|---|---|---|
| `SCHEMA` | 필요한 필드와 enum이 맞는가 | 모든 action과 결과 |
| `AUTHORITY` | 이 역할이 이 action을 요청할 수 있는가 | 모든 action |
| `IDENTITY` | analysis·work·hypothesis ID가 같은 대상을 가리키는가 | 모든 action |
| `REVISION` | workspace·commit·record ID·hash가 정확한가 | code-bound action과 결과 |
| `STATE` | 현재 상태와 version에서 허용되는 전이인가 | work 시작·저장·retry·취소 |
| `BUDGET` | token·시간·retry·repair·chain·Gate 보완 한도 안인가 | LLM·Research·Gate·Sandbox |
| `TOOL` | 허용 도구와 명령인가 | static·retrieval·Sandbox |
| `FILE_PATH` | 로컬 workspace 밖을 읽거나 쓰지 않는가 | 코드·파일 접근 |
| `SANDBOX` | image·network·resource·cleanup 제한이 맞는가 | 동적 재현 |
| `PROVIDER` | 허용 provider/model/profile인가 | LLM 호출 |
| `SESSION` | NEW/RESUME/AUTO와 failover 선행 호출이 맞는가 | LLM 호출 |
| `GATE_ORDER` | Technical 다음 Rule Scope 순서인가 | 두 Gate 호출 |
| `REPORT_READY` | TRUE와 두 Gate 통과 조건이 모두 맞는가 | 보고서 초안 |
| `REDACTION` | secret·절대 경로·민감정보가 제거됐는가 | 로그·PoC·보고서·사람 전달 |
| `DISCLOSURE` | 사람이 정확한 결과 묶음에 DISCLOSE를 결정했는가 | 외부 공개 |

runtime validator가 할 수 없는 일은 다음과 같다.

- static hit만으로 취약점을 확정
- 근거 내용을 읽어 `TRUE/FALSE/HOLD`를 새로 선택
- CWE가 의미상 가장 좋은지 자체 판단
- 공식 정책 문장을 LLM Gate 대신 해석
- 보고서 문장의 품질이나 공격 영향도를 새로 평가
- 사람 대신 외부 공개 결정

## action별 최소 검사

| action | 필수 check | 추가 불변조건 |
|---|---|---|
| `REGISTER_WORK` | SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET | 같은 `dedupe_key`면 기존 work 반환 |
| `CHANGE_WORK_STATE` | SCHEMA, AUTHORITY, IDENTITY, STATE | 준비·대기·복구의 허용 전이만 수행 |
| `START_ATTEMPT` | SCHEMA, AUTHORITY, STATE, BUDGET | active attempt 하나, 종료 work 재시작 금지 |
| `CANCEL_WORK` | SCHEMA, AUTHORITY, IDENTITY, STATE | 취소 범위 확인, 종료 work 변경 금지 |
| `READ_CODE` | SCHEMA, AUTHORITY, IDENTITY, REVISION, BUDGET, FILE_PATH | workspace root 밖 경로 금지 |
| `RUN_TOOL` | SCHEMA, AUTHORITY, REVISION, BUDGET, TOOL, FILE_PATH | allowlist tool만 실행 |
| `CALL_LLM` | SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET, PROVIDER, SESSION, REDACTION | 새 `llm_call_id`, explicit retry/failover |
| `FETCH_POLICY` | SCHEMA, AUTHORITY, BUDGET, TOOL, REDACTION | 승인된 공식 source만 정책 후보로 저장 |
| `RUN_SANDBOX` | SCHEMA, AUTHORITY, REVISION, STATE, BUDGET, TOOL, FILE_PATH, SANDBOX | default-deny network, resource·cleanup 고정 |
| `SAVE_RESULT` | SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, REDACTION | 생산 권한, exact input, atomic commit |
| `CALL_TECHNICAL_GATE` | SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET, GATE_ORDER | final Verification+CWE COMMITTED 필요 |
| `CALL_RULE_SCOPE_GATE` | SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET, GATE_ORDER | TRUE+Technical ACCEPT exact refs 필요 |
| `CREATE_REPORT_DRAFT` | SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET, REPORT_READY, REDACTION | PASS/PASS/PASS/SUFFICIENT/ALLOW 필요 |
| `PREPARE_HUMAN_REVIEW` | SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, REDACTION | 분석 종료·오류·누락·비용 포함 |
| `SAVE_HUMAN_DECISION` | SCHEMA, AUTHORITY, IDENTITY, REVISION, REDACTION | 인증된 Human Reviewer와 exact packet 필요 |
| `EXTERNAL_DISCLOSURE` | SCHEMA, AUTHORITY, IDENTITY, REVISION, DISCLOSURE, REDACTION | exact HumanReviewDecision=DISCLOSE 필요 |

## 비신뢰 입력 경계

다음은 모두 validation 전까지 data일 뿐 instruction이 아니다.

- 저장소 코드·주석·README·Issue text·build script
- AST/SAST message와 외부 정책 본문
- 모든 LLM의 자연어·structured output·tool call 제안
- membership/API provider 응답과 raw session log
- Sandbox stdout·stderr·생성 파일

이 입력은 provider, model, session, Sandbox image/network, Gate 순서, Reporter 조건, budget 또는 disclosure policy를 바꾸지 못한다. 정책 변경은 versioned configuration과 승인된 운영 절차로만 반영한다. 저장소 문구가 이를 요구하면 `UNTRUSTED_INSTRUCTION`으로 기록하고 실행하지 않는다.

## 두 LLM Gate와 Reporter

순서는 고정한다.

`final VerificationResult + CWELabel -> Technical Evidence Gate -> Rule Scope Impact Gate -> Reporter`

- Technical Gate는 verdict·근거·코드 연결·CWE를 검토하지만 verdict를 수정하지 않는다.
- Rule Scope Gate는 Technical `ACCEPT`인 `TRUE`만 받는다.
- 공식 정책 record가 없거나 핵심 출처가 부족하면 Rule Scope output은 `UNCERTAIN + DENY`여야 한다.
- runtime은 위 출력의 구조와 불변조건을 검사할 뿐 정책을 대신 해석하지 않는다.
- Reporter는 모든 report 조건을 통과한 exact revision만 읽어 내부 초안을 만든다.
- Reporter는 새 취약점 주장, Gate 우회, 자동 제출을 할 수 없다.

## 사람 검토 경계

`ReportDraft` 안에 사람 결정을 섞지 않는다. 다음 두 record로 분리한다.

### HumanReviewPacket

한 분석을 사람이 검토하는 데 필요한 자료 묶음이다.

- exact `AnalysisRunResult`
- Finding 후보와 final Verification refs
- Technical·Rule Scope Gate refs
- ReportDraft refs 또는 보고서가 차단된 이유
- dynamic result와 redacted PoC refs
- evidence와 CWE·정책 refs
- token·시간·Sandbox 등 자원 요약
- 모든 오류·DataGap과 남은 HOLD 조건
- `report_ready: true | false`

### HumanReviewDecision

사람이 packet을 읽고 내린 별도 결정이다.

`DISCLOSE | REVISE | WITHHOLD | NEED_MORE_VALIDATION`

사람 결정 저장 자체도 `SAVE_HUMAN_DECISION` action을 거친다. 인증된 사람 identity와 exact packet을 확인한 뒤에만 `HumanReviewDecision` record를 만들 수 있다. `DISCLOSE`는 `report_ready=true`이고 사람이 `approved_report_refs`와 `disclosure_targets`에 실제 공개 범위를 명시했을 때만 시스템의 외부 disclosure action에 사용할 수 있다. 승인 report는 모두 packet 안에 있고 두 Gate의 통과 조건을 만족해야 한다. Agent가 만든 결정, 다른 packet의 결정, 수정 전 revision의 결정은 사용할 수 없다. 실제 자동 제출 integration은 이 설계 범위 밖이다.

## 오류와 verdict 분리

- `AUTH_REQUIRED`, `RATE_LIMITED`, `TIMED_OUT`, `INVALID_OUTPUT`, `PROVIDER_ERROR`, `AGENT_ERROR`는 실행 오류다.
- 이 오류만으로 `VerificationResult.verdict=FALSE`를 저장할 수 없다.
- `FALSE`는 R4-01의 named falsification이 실제 근거로 `DISPROVED`된 final Verification만 허용한다.
- provider 오류 뒤 retry가 가능하면 work는 `BLOCKED`; 한도를 다 쓰면 work는 `FAILED`다.
- 오류·차단·예산 소진은 `AnalysisRunResult`와 HumanReviewPacket에 보존한다.

R4-03에서 추가하는 주요 오류는 다음과 같다.

`AUTHORITY_DENIED | ACTION_NOT_ALLOWED | GATE_ORDER_INVALID | REPORT_NOT_READY | TOOL_NOT_ALLOWED | FILE_ACCESS_DENIED | SANDBOX_POLICY_DENIED | PROVIDER_PROFILE_DENIED | DISCLOSURE_DENIED | UNTRUSTED_INSTRUCTION`

어떤 오류도 가설 `FALSE`를 직접 만들지 않는다.

## 부정 시나리오

| 시나리오 | 기대 결과 |
|---|---|
| Orchestration이 `TRUE`를 저장하려 함 | `AUTHORITY_DENIED`, verdict 미변경 |
| Hypothesis Agent가 final verdict를 냄 | invalid output, 가설 제안만 보존 |
| Technical Gate가 Verification verdict를 바꿈 | `ACTION_NOT_ALLOWED`, 기존 verdict 보존 |
| Technical Gate 없이 Rule Scope Gate 호출 | `GATE_ORDER_INVALID` |
| Rule Scope Gate 없이 Reporter 호출 | `REPORT_NOT_READY` |
| 공식 정책이 없는데 `ALLOW` 출력 | invalid Gate output, `UNCERTAIN + DENY` 재생성 또는 차단 |
| 저장소 문구가 Sandbox network를 열라고 함 | `UNTRUSTED_INSTRUCTION` 또는 `SANDBOX_POLICY_DENIED` |
| LLM이 workspace 밖 파일을 요청 | `FILE_ACCESS_DENIED` |
| 허용되지 않은 provider/model로 silent failover | `PROVIDER_PROFILE_DENIED`와 호출 미실행 |
| 인증 실패를 `FALSE`로 저장 | `AUTHORITY_DENIED` 또는 invalid result, 실행 오류 유지 |
| Reporter가 새 공격 경로를 확정 | invalid output, 새 hypothesis proposal 없이는 사용 금지 |
| LLM이 `HumanReviewDecision` 형태의 승인을 출력 | `AUTHORITY_DENIED`, 사람 결정 record 생성 금지 |
| Agent가 외부 공개를 요청 | `DISCLOSURE_DENIED` |
| 사람이 다른 revision의 승인 결정을 재사용 | `DISCLOSURE_DENIED` |
| redaction 실패 PoC를 사람·외부로 전달 | action `DENY`, 제한 저장소에 격리 |

## 문서 배치

- `03-agent-roles-and-orchestration.md`: 역할 권한표와 action 요청 흐름
- `05-llm-gate-and-reporting.md`: 두 Gate·Reporter·사람의 경계
- `07-results-and-observability.md`: action decision·오류·사람 검토 기록
- `08-lightweight-data-contracts.md`: 네 가지 새 정본 contract
- `09-llm-provider-session-and-logging.md`: provider/session action 검사
- `10-security-boundaries.md`: 비신뢰 입력과 권한 우회 부정 시나리오
- `12-report-draft-template.md`: ReportDraft와 사람 결정 분리
- `13-architecture-diagrams.md`: 권한 검사와 사람 공개 경계
- `wiki/authority-boundaries.md`: 쉬운 한국어 요약

## 완료 판정

Issue #15의 완료 조건을 정본·Wiki·Mermaid에서 모두 추적할 수 있어야 한다. 자동 검증은 새 계약 이름, 역할 권한표, 필수 action check, 오류 코드, 두 Gate 순서, HumanReviewPacket·Decision, 15개 부정 시나리오와 canonical/Wiki Mermaid mirror를 검사한다. 구현 제품이나 성능 수치는 별도 구현 단계로 남기고 R4-03 완료를 막지 않는다.
