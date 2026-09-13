# R6 Pro·Con·Verification 프롬프트·구현 검증 자료

## 목적

Architecture v5의 R6 검증·반박·플레이북 담당 기능을 실제 LLM Prompt Runtime에 연결할 수 있도록, 역할별 prompt template과 검증 fixture, 평가 기준 및 구현 인계 사항을 정리한다.

이 자료는 현재 승인된 설계를 구현하기 위한 handoff 초안이다. JSON fixture는 prompt와 semantic validator를 검토하기 위한 synthetic projection이며 실제 저장 record가 아니다. 최종 schema·registry revision은 R3·R4 검토 뒤 확정한다.

## 기준 문서

- `docs/architecture-v5/03-agent-roles-and-orchestration.md`
- `docs/architecture-v5/04-verification-and-dynamic-reproduction.md`
- `docs/architecture-v5/08-lightweight-data-contracts.md`
- `docs/architecture-v5/09-llm-provider-session-and-logging.md`
- `docs/architecture-v5/implementation/05-prompt-runtime.md`
- `docs/architecture-v5/implementation/06-implementation-baseline.md`
- `docs/architecture-v5/verification-playbooks.md`
- `docs/review/decisions/ADR-003-r6-r7-environment-requirements-handoff.md`
- `docs/review/decisions/ADR-004-r6-request-r7-poc-production.md`

## Prompt 목록

| ID | role / task | 파일 | result kind |
|---|---|---|---|
| `PMT-PRO-01` | PRO / `COLLECT_SUPPORT` | `prompts/pro-collect-support.md` | `pro_evidence_result` |
| `PMT-CON-01` | CON / `COLLECT_COUNTEREVIDENCE` | `prompts/con-collect-counterevidence.md` | `con_evidence_result` |
| `PMT-VER-CTX-00` | VERIFICATION / `ASSESS_CONTEXT` | `prompts/verification-assess-context.md` | `verification_context_assessment` |
| `PMT-VER-CTX-01` | VERIFICATION / `CREATE_CONTEXT_REQUEST` | `prompts/verification-create-context-request.md` | `code_context_request_content` |
| `PMT-VER-00` | VERIFICATION / `ASSESS_INITIAL` | `prompts/verification-assess-initial.md` | `verification_initial_assessment` |
| `PMT-VER-01` | VERIFICATION / `CREATE_DYNAMIC_REQUEST` | `prompts/verification-create-dynamic-request.md` | `dynamic_reproduction_request` |
| `PMT-VER-02` | VERIFICATION / `FINAL_VERDICT` | `prompts/verification-final-verdict.md` | `verification_result` |
| `PMT-VER-03` | VERIFICATION / `TECHNICAL_REVISE` | `prompts/verification-technical-revise.md` | `verification_result` |

## Prompt Registry metadata

아래 값은 여덟 template을 Prompt Registry에 등록할 때 필요한 DRAFT metadata다. 두 context 출력은 routing용 prompt output이며, `CREATE_CONTEXT_REQUEST`가 통과하면 runtime이 canonical `CodeContextRequest`의 ID·승인 reference·limits를 결합한다.

| prompt_key | template_version | output_schema_ref | semantic_validator_ref | result_kind | session_policy | tool_policy_ref |
|---|---|---|---|---|---|---|
| `pro.collect-support.r6-v1` | `1.0.0` | `schema.evidence-agent-result.next-major` | `validator.pro-evidence.v1` | `pro_evidence_result` | `NEW` | `NO_TOOLS` |
| `con.collect-counterevidence.r6-v1` | `1.0.0` | `schema.evidence-agent-result.next-major` | `validator.con-evidence.v1` | `con_evidence_result` | `NEW` | `NO_TOOLS` |
| `verification.assess-context.r6-v1` | `1.0.0` | `schema.verification-context-assessment.next-major` | `validator.verification-context-assessment.v1` | `verification_context_assessment` | `NEW` | `NO_TOOLS` |
| `verification.create-context-request.r6-v1` | `1.0.0` | `schema.code-context-request-content.next-major` | `validator.code-context-request-content.v1` | `code_context_request_content` | `NEW` | `NO_TOOLS` |
| `verification.assess-initial.r6-v1` | `1.0.0` | `schema.verification-initial-assessment.next-major` | `validator.verification-initial-assessment.v1` | `verification_initial_assessment` | `NEW` | `NO_TOOLS` |
| `verification.create-dynamic-request.r6-v1` | `1.0.0` | `schema.dynamic-reproduction-request.next-major` | `validator.dynamic-request.v1` | `dynamic_reproduction_request` | `NEW` | `NO_TOOLS` |
| `verification.final-verdict.r6-v1` | `1.0.0` | `schema.verification-result.next-major` | `validator.verification-result.v1` | `verification_result` | `NEW` | `NO_TOOLS` |
| `verification.technical-revise.r6-v1` | `1.0.0` | `schema.verification-result.next-major` | `validator.verification-revise.v1` | `verification_result` | `NEW` | `NO_TOOLS` |

각 template은 R3 공통 형식의 다음 9개 구역을 모두 가진다.

1. `ROLE_AND_SCOPE`
2. `TASK`
3. `TRUSTED_RULES`
4. `INPUT_SLOTS`
5. `UNTRUSTED_DATA_BOUNDARY`
6. `DECISION_CRITERIA`
7. `OUTPUT_SCHEMA`
8. `UNCERTAINTY_AND_ERRORS`
9. `FORBIDDEN_BEHAVIOR`

## Fixture 목록

| fixture | 검증 목적 | 기대 처리 |
|---|---|---|
| `01-supported` | 정적·Pro·Con 근거가 initial TRUE를 지지하지만 PoC가 아직 없음 | `POC_CONFIRMATION` 선택 후 dynamic request |
| `02-contradicted` | named falsification이 실제 근거로 반증됨 | final `FALSE` |
| `03-insufficient` | 검증은 완료됐지만 핵심 조건이 확인되지 않음 | final `HOLD` |
| `04-execution-failure` | 필수 Context timeout으로 검증 미완료 | verdict 없이 `BLOCKED` |
| `05-boundary-failures` | schema·semantic·injection·stale·Pro/Con join 오류 | domain result 저장 차단 |
| `06-dynamic-supported` | current generation의 성공 동적 결과와 same-attempt PoC 존재 | final `TRUE` |
| `07-technical-revise` | Technical Gate REVISE를 새 generation에서 보완 | 이전 result 불변, 새 VerificationResult 후보 |
| `08-verdict-evidence` | 정적 근거만으로 핵심 조건을 판정할 수 없음 | `proposed_verdict=HOLD`, `VERDICT_EVIDENCE` 요청 |
| `09-context-cycle` | 가설 수신 직후 필수 Context 부족 | assessment 후 최소 context request content |
| `10-poc-provenance-failures` | 다른 attempt PoC·미실행 candidate | final TRUE 저장 차단 |
| `11-task-coverage-matrix` | 여덟 prompt별 정상·schema·semantic·injection·stale 범위 | 활성화 전 다섯 case class 필수 |

각 `.input.json`은 입력 상황이고 `.expected.json`은 문장 전체 일치가 아닌 필수 projection·판정 조건이다. 상세 채점 규칙은 `evaluation-criteria.md`를 따른다.

## 구현 순서

1. R3 registry가 role·task별 DRAFT entry와 exact template ref를 등록한다.
2. Prompt Builder가 허용 slot과 field projection만 사용해 payload를 만든다.
3. JSON Schema와 역할별 semantic validator로 fixture를 검증한다.
4. R8이 같은 corpus에서 품질·시간·usage·비용을 평가한다.
5. 관련 역할 검토와 사람 승인 뒤에만 PRODUCTION entry를 ACTIVE로 전환한다.

## 핵심 경계

- Pro와 Con은 같은 common input reference 집합을 사용하되 서로 다른 `NEW` session에서 독립 실행한다.
- Verification은 R7에 목적·목표·환경 능력만 요청하며 plan·command·payload·PoC를 만들지 않는다.
- final TRUE에는 current generation의 `SUCCEEDED + SUPPORTED` 동적 결과와 same-attempt validated PoC가 필요하다.
- Con이 방어를 찾으면 같은 source·sink·권한 경계의 우회·alternate path와 방어 적용 범위를 추가로 확인한다.
- 실행 실패·누락·timeout은 `FALSE`나 `HOLD`가 아니다.
- R6 verdict는 기술 판정이며 공개·제보 승인이 아니다.

## 제출 전 확인

- 모든 JSON이 파싱되는가?
- 모든 prompt에 공통 9개 구역이 정확히 한 번 존재하는가?
- prompt와 fixture에 실제 secret·host 절대 경로·실제 분석 결과가 없는가?
- 다른 generation·attempt·workspace·commit의 근거를 섞지 않는가?
- `handoff.md`의 미결정 사항을 PR에서 관련 담당자에게 요청했는가?
