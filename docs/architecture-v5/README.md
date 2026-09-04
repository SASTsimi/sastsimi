# SASTSIMI Architecture v5

- **이 문서는 무엇을 설명하나요?** Architecture v5 전체 흐름과 상세 문서를 읽는 순서를 설명합니다.
- **누가 읽어야 하나요?** 프로젝트에 참여하는 모든 팀원이 먼저 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** 자신의 역할이 전체 흐름의 어디에 있고 어떤 번호 문서를 검토해야 하는지 확인합니다.

전문용어는 [쉬운 용어집](../GLOSSARY.md)에서 확인할 수 있습니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

Architecture v5는 정적 분석 결과를 최종 판정으로 사용하지 않습니다. 정적 분석은 LLM Agent가 검증할 취약점 가설을 만들 때 참고하는 코드 사실을 제공합니다. 이 문서 묶음은 **검토 중인 설계 초안(`candidate baseline`)**이며 아직 승인된 최종 설계, 구현 완료 또는 성능 개선을 뜻하지 않습니다.

번호 문서 `01`–`13`이 설계 의미의 기준입니다. Wiki는 빠르게 이해하기 위한 쉬운 요약이며 새로운 입출력 약속이나 결정을 만들 수 없습니다. 검토 결정은 이 저장소의 Issue, 설계 결정 기록(`ADR`)과 PR에서 먼저 확정합니다. 승인된 설계 commit만 별도 PR로 구현 저장소에 반영합니다.

## 전체 흐름을 쉽게 나누면

1. **입력과 코드 사실 수집**: 저장소를 실행별 로컬 폴더에 clone하고 분석할 commit을 checkout한 뒤 AST와 SAST를 함께 실행합니다. 규칙 기반 SAST는 검사 0건·미실행·확인 불가를 구분해 기록합니다.
2. **가설과 검증**: LLM이 취약점 가능성을 제안하고, Orchestration이 등록·배정한 뒤 Verification Agent가 코드·찬성·반대 근거를 검토하고 필요한 동적 재현 목적을 R7에 요청합니다.
3. **동적 재현과 연계 탐색**: R7 Agent가 환경·간단한 plan을 준비하고 외부 경계 안의 Docker에서 PoC를 자율 실행합니다. Session Manager가 AgentLog·validated PoC·동적 결과를 확정합니다. 모든 final TRUE에는 validated PoC가 필요하며, HOLD는 즉시, TRUE는 Technical `ACCEPT` 뒤에 Primitive matching에 사용합니다.
4. **CWE와 최종 검토·자동화 종료**: R5-01이 final TRUE마다 exact Verification에 맞는 current CWELabel을 만들고 기술 근거와 공식 정책을 차례로 검토한 뒤, Reporter가 내부 초안을 만들고 결과를 저장하면 Agent 자동화가 끝납니다.

## 정확한 22단계 기준 흐름

1. 저장소를 입력받는다.
2. `Repository Loader`가 저장소를 `git clone`하고 분석할 `commit_id`를 checkout해 `CodeWorkspace`를 준비한다.
3. AST parse와 SAST 도구를 병렬 실행하고 `ToolRunResult`와 규칙 기반 도구의 `RuleExecutionRecord`를 저장한다.
4. 결과를 exact 규칙 실행 기록이 연결된 `StaticFactBundle`로 정규화한다.
5. Orchestration Agent가 초기 가설 생성 실행을 시작한다.
6. 저비용 Hypothesis Agent를 호출한다.
7. schema-valid `HypothesisProposal(origin=INITIAL)`을 전역 등록한다.
8. 각 등록 가설에 Verification owner를 할당하고 가설 내부 제어권을 넘긴다.
9. Verification이 entity·위치·경로를 기준으로 필요한 코드 문맥을 조회한다.
10. 운영 분석의 Verification이 Pro/Con을 독립 NEW session으로 병렬 실행한다.
11. 초기 `TRUE | FALSE | HOLD` 판정을 만든다.
12. Initial TRUE이면 R6가 `POC_CONFIRMATION`, 판정에 동적 근거가 필요하면 `VERDICT_EVIDENCE` 요청을 만든다. 한 Verification generation에는 동적 work가 최대 하나다. R7 Agent는 exact request를 바탕으로 `EnvironmentRequirements`와 mode·exact command가 없는 `ReproductionPlan`을 생산한다. Sandbox Controller가 외부 격리 경계를 확인하면 Setup Automation이 환경을 만들고 Agent가 PoC candidate·command·관찰·재시도를 자율적으로 정한다. 비-LLM Reproduction Session Manager는 같은 attempt의 AgentLog·recipe·환경·validated PoC와 동적 결과를 반환한다.
13. 최종 `TRUE | FALSE | HOLD`와 별도 material claim을 확정한다.
14. `FALSE`는 terminal로 끝내고, `HOLD`는 inputs만 있고 result가 없는 Primitive를 즉시 저장해 Chaining 자격을 준다. TRUE는 R5-01 `CWE_LABELING` work에서 exact Verification에 대응하는 current `CWELabel`을 만든다.
15. validated PoC와 `SUCCEEDED + SUPPORTED` 동적 결과가 연결된 final TRUE와 그 Verification을 직접 가리키는 current CWELabel만 Technical Evidence Gate Agent가 검토한다.
16. `REVISE`이면 같은 Verification owner가 근거를 보완해 새 Verification을 만들고 R5-01이 CWE를 다시 평가해 새 label revision으로 제출한다. CWE 값이 같아도 이전 label은 재사용하지 않는다.
17. Technical `ACCEPT`인 exact TRUE는 제공 능력을 result로 가진 Primitive로 저장한다. 동시에 Rule Scope Impact Gate 요청을 시작할 수 있으며 두 경로는 서로 독립이다.
18. Chaining Agent가 upstream result가 downstream input을 실제 코드 근거로 충족하는지 방향성 있게 matching한다.
19. Rule Scope Impact Gate Agent가 공식 정책·범위·실질 영향을 검토하지만 이미 저장된 Primitive 자격은 바꾸지 않는다.
20. Verification-origin 또는 Chaining-origin material claim은 trusted validation 뒤 새 가설로 등록하고 새 Verification을 배정한다.
21. 모든 전달 조건을 만족한 결과에만 Reporter Agent가 보고서 초안을 작성한다.
22. 결과·자원·LLM 호출 기록·PoC·오류·디버깅 정보를 `AnalysisRunResult`에 저장하고 초기·파생 가설에 8–21단계를 반복한 뒤 Agent 자동화를 종료한다.

자동화 종료 뒤 사람이 `AnalysisRunResult`와 current `ReportDraft`를 검토·수정하거나 외부에 제출·공개하는 과정은 Agent 공통 계약과 action lifecycle 밖에 있습니다.

## 핵심 원칙

- AST와 SAST는 source, sink, entity, 위치, 호출·데이터 흐름, 인증·인가와 같은 사실 후보를 제공한다. 규칙 기반 SAST는 선택·실행 여부와 raw 탐지 수를 별도 record로 남기며 미실행·확인 불가를 탐지 0건으로 바꾸지 않는다.
- Hypothesis Agent는 항상 `HYPOTHESIS_ONLY / NON_FINAL` 제안만 만들며 Finding이나 확정 판정을 만들 수 없다.
- 코드 문맥은 같은 `workspace_id`와 `commit_id`에서 위치 기반으로 필요할 때 조회하고, 조회 범위와 반환 위치를 기록한다.
- Verification은 가설 내부 Context·Pro/Con, 목적별 `DynamicReproductionRequest`, 반환 결과 소비, 최종 판정·Technical `REVISE`·Gate 제출과 Chaining handoff를 소유한다. R7 Agent는 `EnvironmentRequirements`, 간단한 `ReproductionPlan`, PoC candidate와 동적 근거 해석을 만든다. Setup Automation은 recipe·image·container·cleanup, Sandbox Controller는 외부 격리 경계, Reproduction Session Manager는 append-only AgentLog·validated PoC·동적 결과 확정을 맡는다.
- 운영(`PRODUCTION`) 기본 검증 모드는 `ALWAYS_DEBATE`다. 모든 유효 가설에서 Pro와 Con을 독립 NEW session으로 실행한다. `BASIC | CONDITIONAL_DEBATE`는 격리된 평가(`EVALUATION`)에서만 비교한다.
- Primitive DB는 queue가 아니라 HOLD의 inputs-only Primitive와 Technical-accepted TRUE의 result Primitive를 연결하는 인덱스다. Gate 전 TRUE와 FALSE는 matching에 사용할 수 없다.
- Chaining Agent는 upstream Primitive의 `result`가 downstream Primitive의 특정 `input`을 충족하는지 matching만 수행하며 일반 취약점·우회·impact research, 동적 재현, Gate 보완이나 verdict를 수행할 수 없다.
- Verification과 Chaining이 발견한 새 material claim은 각각 `origin=VERIFICATION | CHAINING`인 새 가설로 등록되어 처음부터 검증된다. 부모 판정은 바뀌지 않는다.
- R5-01 `CWE_LABELING`은 final TRUE와 Gate 사이에서 exact Verification에 맞는 current `CWELabel`을 만드는 유일한 생산자다. Technical Evidence Gate와 Rule Scope Impact Gate는 서로 다른 LLM 검토 단계이며 어느 Gate도 Verification verdict나 CWELabel을 직접 바꾸지 않는다.
- 공식 프로그램 정책이 없으면 rule/scope를 추정하지 않으며 보고서 전달 권한은 `DENY`다.
- Membership session과 API provider는 공통 adapter 경계를 사용한다. Membership path는 feasibility/security 검토 전 experimental이며, provider 전환은 명시적으로 기록하고 조용한 failover는 금지한다.
- Reporter는 `ReportDraft`를 만드는 마지막 Agent다. 이후 신뢰 runtime이 `AnalysisRunResult`를 확정하면 자동화가 끝난다.
- 모든 LLM 출력은 비신뢰 입력이다. 신뢰 경계 안의 Runtime Validator가 schema·호출 권한·상태 전이·예산·provider/session·Gate 순서·Reporter 전제조건을 강제하고, Sandbox Controller가 host·Docker daemon/socket·mount/namespace·secret·egress·workspace·resource/lifecycle 외부 경계를 전담한다.
- Agent와 service는 실행을 `ActionRequest`로 제안하고 runtime validator가 요청당 하나의 `ActionDecision=ALLOW | DENY`를 만든다. 실제 LLM 호출은 검사한 `LLMCallSpec`과 같아야 하며 ALLOW는 exact action과 state version에 한 번만 사용한다.
- `ReportDraft`는 current Finding·Verification·CWELabel·두 Gate·정책 revision을 정확히 참조하고 restriction·limitation·남은 불확실성과 redaction 결과를 보존한다. 오래된 초안은 current `AnalysisRunResult`에 넣지 않는다.
- 분석 공백, 실행 오류, LLM·sandbox 실패와 취소는 기술 판정 `FALSE`와 분리한다. 공통 ID·시간·상태·오류 기준은 [경량 데이터 계약](./08-lightweight-data-contracts.md)을 따른다.
- 같은 논리 요청은 `dedupe_key`로 한 번만 반영하고, 한 작업에는 활성 attempt를 하나만 둔다. 결과와 종료 상태는 atomic하게 연결하며 `COMMITTED` output만 다음 단계가 읽는다.
- retry는 새 `attempt_id`로 실행하고 이전 실패를 보존한다. 취소·입력 변경·오래된 revision 뒤 도착한 결과는 격리하며, 중단 후에는 마지막으로 확정 저장된 상태에서 재개한다.

## 문서 지도

1. [시스템 개요](./01-system-overview.md)
2. [정적 사실 계층과 코드 문맥 조회](./02-static-fact-layer.md)
3. [Agent 역할과 오케스트레이션](./03-agent-roles-and-orchestration.md)
4. [검증과 동적 재현](./04-verification-and-dynamic-reproduction.md)
5. [R6 검증 플레이북](./verification-playbooks.md)
6. [이중 LLM Gate와 보고](./05-llm-gate-and-reporting.md)
7. [Primitive DB와 Chaining](./06-chaining.md)
8. [결과 저장과 관측성](./07-results-and-observability.md)
9. [경량 데이터 계약](./08-lightweight-data-contracts.md)
10. [LLM provider, session과 logging](./09-llm-provider-session-and-logging.md)
11. [보안 경계](./10-security-boundaries.md)
12. [v4에서의 마이그레이션](./11-migration-from-v4.md)
13. [보고서 초안 템플릿](./12-report-draft-template.md)
14. [아키텍처 다이어그램](./13-architecture-diagrams.md)
15. [Wiki](./wiki/README.md)
16. [검토 운영과 발견사항](../review/FINDINGS.md)

## 문서 적용 범위

이 디렉터리는 v5 candidate baseline의 번호 문서를 보관한다. 이 저장소의 검토가 끝나기 전에는 승인된 정본이 아니다. v4는 [설계 계보 문서](./11-migration-from-v4.md)에 요약된 역사적 맥락일 뿐 현재 파이프라인을 정의하지 않는다. 실제 adapter, sandbox, Primitive DB, 정책 수집기, Agent와 Gate 구현은 별도 구현·보안 검토·평가가 필요하다.
