# Architecture v5 역할별 Issue 카탈로그

이 문서는 역할별 상위 Issue에서 무엇을 검토하고 어떤 세부 하위 Issue를 만들지 안내합니다. 실제 Issue와 담당자 상태는 [Issue 현황](./ISSUE_TRACKER.md)에서 확인합니다. 현재 단계는 **설계 검토**이며 실행 코드(`runtime`) 구현은 범위 밖입니다. 역할 담당자는 모두 정해졌습니다. GitHub 담당자 선택 목록에 나타나지 않는 계정은 저장소 접근 권한이나 정확한 사용자명을 확인한 뒤 실제 담당자로 추가합니다. 독립 최종 검토자는 지정 전까지 비워 둡니다.

## 공통 작업 방식

모든 역할별 상위 Issue는 다음 순서를 따릅니다.

1. 자신의 우선 문서와 연결된 앞 단계·뒤 단계의 입출력 약속을 읽습니다.
2. 필요한 작업을 한 번에 완료 여부를 판단할 수 있는 세부 하위 Issue로 직접 나눕니다.
3. 하위 Issue에 담당자, 쉬운 설명, 수정 문서, 완료 조건과 상위 Issue 번호를 적습니다.
4. 현재 설계가 실제 구현 가능한지, 책임과 금지 권한이 충돌하지 않는지 검토합니다.
5. 문제를 Blocker/High/Medium/Low로 기록합니다. 뜻은 [협업 가이드](../../CONTRIBUTING.md)를 따릅니다.
6. 한 가지 의미 변경마다 `review/<domain>` 브랜치에서 PR을 엽니다.
7. 앞 단계와 뒤 단계의 검토자가 입출력 약속 양쪽을 확인합니다.
8. 작업을 막는 문제와 중요한 문제를 모두 해결하고 나머지 문제의 담당자와 계획을 남깁니다.
9. 변경된 번호 문서, Wiki와 Mermaid의 의미를 맞춥니다.

하위 Issue를 PM이 대신 만들지는 않습니다. PM은 역할 사이의 충돌과 전체 진행 상태를 관리합니다.

## 하위 Issue 공통 형식

제목은 `[R번호-순번] 구체적인 작업` 형식을 권장합니다. 본문에는 `한 줄 설명`, `필요한 이유`, `이번에 할 일`, `수정 문서`, `완료 조건`, `상위 Issue 번호`를 포함합니다. PR에는 `Closes #하위-Issue`와 `Refs #역할별-상위-Issue`를 함께 적습니다.

공통 금지 사항은 runtime 구현 완료 주장, 자동 외부 테스트·제출, 오류를 `FALSE`로 변환, 미검증 LLM 출력을 권위 있는 결정으로 사용하는 것이다.

---

## Parent Epic — Architecture v5 candidate baseline 검토와 승인

- Live Issue: [#1](https://github.com/SASTsimi/sastsimi/issues/1)
- Coordinators: 김태현 `@taehyeon-git`, 윤희섭 `@v1sion`

### 쉽게 말하면

팀원별 설계 검토가 따로 놀지 않도록 R1–R8의 작업, 교차 리뷰와 마지막 전체 검토를 한곳에서 관리한다. 이 Epic이 끝나야 구현을 시작할 설계 기준을 확정할 수 있다.

### 목적

23단계 LLM 중심 파이프라인을 역할, 입출력 계약, 오류, 예산, 보안 경계와 human handoff 관점에서 검토하여 구현 가능한 승인 baseline을 만든다.

### 범위

- RepositorySnapshot부터 human disclosure decision까지의 23단계
- 정적 사실, 가설, retrieval, Verification, sandbox, Primitive/Research, 두 Gate, report 계약
- provider/session/logging과 resource budget
- snapshot, prompt injection, credential, sandbox, official policy trust boundary
- 역할 간 producer/consumer 계약과 종단 실패 시나리오

### 비범위

- runtime 코드 구현과 배포
- v4 상태·Gate 결과 자동 승계
- 자동 외부 자산 테스트, 보고서 제출 또는 공개
- 공식 정책이 없을 때 LLM 기억이나 저장소 문서로 정책 추정
- fine-tuning/training dataset 구축

### 완료 조건

- [ ] R1–R8 역할 Issue가 모두 완료되고 관련 PR이 `main`에 merge됨
- [ ] 23단계 각각에 owner, 입력, 출력, 오류와 금지 권한이 있음
- [ ] 모든 핵심 artifact가 run/snapshot/hypothesis/attempt와 추적 가능함
- [ ] 오류·timeout·auth·sandbox setup 실패가 `FALSE`로 변환되지 않음
- [ ] 두 Gate와 Reporter의 순서·전제조건이 분리되고 runtime validator가 강제함
- [ ] 새 Research/Primitive claim이 새 가설로 전체 검증됨
- [ ] 모든 Blocker/High가 닫히고 Medium은 명시적으로 처리됨
- [ ] freeze commit SHA와 independent final reviewer 승인 기록이 있음
- [ ] 별도 승인 PR 전까지 `REVIEW_REQUIRED / NOT_IMPLEMENTED`를 유지함

---

## R1 — 제약형 가설 생성·Research/Primitive chaining·LLM 효율화

- Live Issue: [#2](https://github.com/SASTsimi/sastsimi/issues/2)

### 쉽게 말하면

정적 분석이 모은 코드 사실을 보고 LLM이 **검증할 취약점 후보 목록**을 만드는 방법을 정한다. 이미 확인된 취약점들이 서로 연결될 가능성이 있으면 바로 확정하지 않고 새로운 연계 가설로 다시 검증하게 만든다.

### 담당자가 나눌 수 있는 하위 Issue 예시

- `[R1-01] 취약점 가설에 반드시 들어갈 정보 확정`
- `[R1-02] 연계 공격 후보를 새 가설로 만드는 조건 확정`
- `[R1-03] 연계 탐색의 token·시간·중복 중단 기준 확정`

### 역할 소유권

- Owner role: LLM 탐색·체이닝
- 담당자: 배승원 `@baeseungwon1010`
- Primary branch: `review/hypothesis-research`
- 관련 흐름: 정적 사실 묶음 → 취약점 가설 목록 → 검증 결과에서 연계 조건 추출 → 새 가설 반환

### 검토 문서

- `03-agent-roles-and-orchestration.md`
- `06-chaining.md`
- `08-lightweight-data-contracts.md`의 Hypothesis/Primitive/Research 계약
- `09-llm-provider-session-and-logging.md`의 역할별 profile
- `13-architecture-diagrams.md`의 관련 흐름

### 검토할 입력·출력

- 입력: `StaticFactBundle` refs, 최소 code context, Scope, budget, final VerificationResult, Technical revision, Primitive match
- 출력: schema-valid `HypothesisProposal[]`, `INVALID_OUTPUT`, `Primitive`, `ResearchResult`, child/chained proposal, bounded-stop reason

### 확인할 권한 경계

- proposal은 `HYPOTHESIS_ONLY / NON_FINAL`이며 verdict·Finding·CWE·Gate·report를 확정하지 않는다.
- confidence는 scheduling hint이며 진위 확률이나 verdict가 아니다.
- `TRUE`는 PROVIDED, `HOLD`는 REQUIRED Primitive 후보를 만든다. `FALSE`는 chaining 근거로 승격하지 않는다.
- 문자열 일치만으로 chain을 확정하지 않고 snapshot·asset·entity·privilege·attack order·restriction을 확인한다.
- 새 endpoint, sink, 권한 경계, 공격 단계나 impact는 새 가설로 반환한다.

### 필수 교차 리뷰

- 정적분석·컨텍스트: location/fact grounding
- 검증·반박·플레이북: falsification과 새 claim 경계
- PM·아키텍처·워크플로: lifecycle/schema/runtime enforcement
- 데이터·평가·예산: token/time/quality 기준

### 완료 조건

- [ ] proposal 필수 field, semantic validation, repair retry와 `INVALID_OUTPUT`이 명확함
- [ ] facts와 assumptions, restriction, missing information, falsification question이 구분됨
- [ ] Primitive match compatibility와 duplicate/cycle 규칙이 문서화됨
- [ ] depth/count/token/time/research/sandbox 한도와 중단 이유가 정의됨
- [ ] Research skip/no-material-extension도 관측 가능함
- [ ] token 최적화가 동일 corpus의 품질 저하 여부와 함께 평가됨
- [ ] Wiki/Mermaid 및 인접 계약이 일치함

---

## R2 — 정적 사실 계층·동일 snapshot 위치 기반 Context Retrieval

- Live Issue: [#3](https://github.com/SASTsimi/sastsimi/issues/3)

### 쉽게 말하면

AST·CodeQL·OpenGrep 결과를 LLM이 바로 사용할 수 있도록 **파일 위치, 함수, 호출 흐름과 source/sink 중심의 사실 묶음**으로 정리한다. 분석 도중 코드가 더 필요할 때 같은 저장소 버전에서 필요한 부분만 안전하게 가져오게 한다.

### 담당자가 나눌 수 있는 하위 Issue 예시

- `[R2-01] 저장소 분석 시점과 코드 위치 식별 방법 확정`
- `[R2-02] AST·CodeQL·OpenGrep 결과를 하나의 형식으로 정리`
- `[R2-03] 필요한 코드만 다시 가져오는 범위와 한도 확정`

### 역할 소유권

- Owner role: 정적분석·컨텍스트
- 담당자: 김나연 `@meow`
- Primary branch: `review/static-context`
- 관련 흐름: 저장소 버전 고정 → AST/SAST 병렬 실행 → 사실 묶음 생성 → 필요한 코드 위치 조회

### 검토 문서

- `02-static-fact-layer.md`
- `08-lightweight-data-contracts.md`의 StaticFactBundle/Context 계약
- `07-results-and-observability.md`의 static/retrieval metric
- `10-security-boundaries.md`의 snapshot/retrieval 경계
- `13-architecture-diagrams.md`의 정적 분석 흐름

### 검토할 입력·출력

- 입력: 고정 `RepositorySnapshot`, AST/SAST raw artifact, exclusion policy, `CodeContextRequest`, budget
- 출력: `StaticFactBundle`, entity/location/relation refs, `AnalysisGap`, `CodeContextResponse`, tool/coverage 상태

### 확인할 권한 경계

- AST/SAST severity와 rule hit은 verdict가 아니다.
- empty/truncated/unresolved 결과를 안전 또는 `FALSE`로 해석하지 않는다.
- 서로 다른 snapshot/submodule revision을 혼합하지 않는다.
- path traversal, symlink escape, snapshot root 밖 조회와 무제한 repository dump를 금지한다.

### 필수 교차 리뷰

- LLM 탐색·체이닝: Hypothesis 입력의 충분성과 최소성
- 검증·반박·플레이북: evidence/gap 표현
- PM·아키텍처·워크플로: identity·Scope·error 계약
- 통합·구현 개발: parser/runner/normalizer/retrieval feasibility

### 완료 조건

- [ ] `RepositorySnapshot`, Entity/Location/Artifact ref의 정체성과 불변성이 정의됨
- [ ] submodule, LFS, generated dependency와 분석 범위 고정 규칙이 있음
- [ ] 모든 사실을 producer/raw artifact/location/snapshot으로 역추적할 수 있음
- [ ] AST/SAST 부분 실패와 충돌·불확실성이 gap/error로 보존됨
- [ ] relation query와 depth/fragment/byte/token/request/time 제한이 정의됨
- [ ] snapshot mismatch와 path/symlink negative scenario가 문서화됨
- [ ] `gaps` 이름과 소비자 의미가 일관됨

---

## R3 — 통합 구현 가능성·계약 준수 테스트·모듈 조립 검토

- Live Issue: [#4](https://github.com/SASTsimi/sastsimi/issues/4)

### 쉽게 말하면

각 파트의 설계가 실제 코드 모듈로 이어질 수 있는지 확인하고, 모듈 사이의 입력·출력과 오류가 서로 맞는지 테스트 계획을 만든다. 현재는 설계 검토 단계이므로 전체 코드를 구현하는 것이 아니라 **구현 가능한 설계인지 확인하는 작업**이다.

### 담당자가 나눌 수 있는 하위 Issue 예시

- `[R3-01] 전체 단계를 실제 모듈과 연결하는 표 작성`
- `[R3-02] 파트 사이의 입출력 약속을 검사할 테스트 설계`
- `[R3-03] 중단·재시도·복구 시나리오와 통합 시험 설계`

### 역할 소유권

- Owner role: 단독 구현·통합 개발
- 담당자: 김태현 `@taehyeon-git`, 윤희섭 `@v1sion`
- Primary branch: `review/integration-feasibility`
- 관련 흐름: 저장소 입력부터 사람의 최종 검토까지 전체 흐름의 모듈·저장·복구·테스트 연결

### 검토 문서

- `01-system-overview.md`, `03`, `08`, `09`, `10`, `11`, `13`
- 전문 역할 문서는 소비자 관점에서 검토하되 의미를 단독 변경하지 않음

### 검토할 입력·출력

- 입력: 모든 역할 contract, state transition, budget, provider/storage/sandbox 제약
- 출력: module boundary/sequence 검토, contract conformance test plan, E2E/rollback 시나리오, implementation dependency map

### 확인할 권한 경계

- 통합 편의를 위해 enum, 권한, Gate/Reporter 전제를 임의 변경하지 않는다.
- 설계 검토 단계에서 실행 가능한 구현이나 성능 완료를 주장하지 않는다.
- 전문 의미 변경은 해당 owner와 PM 리뷰를 요구한다.

### 필수 교차 리뷰

- PM·아키텍처·워크플로: 전체 state machine
- 변경 영향을 받는 모든 전문 owner
- 데이터·평가·예산: instrumentation/testability
- 동적검증·Sandbox 또는 Gate 경계 변경 시 해당 역할

### 완료 조건

- [ ] 23단계가 예상 module/entry point/contract/store/test에 매핑됨
- [ ] run/hypothesis/parent-child/attempt correlation과 revision binding을 재구성할 수 있음
- [ ] 병렬·직렬 지점과 atomic transition/idempotency/crash-resume 요구가 정의됨
- [ ] partial/failed/cancelled/auth/rate-limit/sandbox/policy 오류의 전파가 명확함
- [ ] cross-snapshot, Research 오승격, Reporter bypass negative test plan이 있음
- [ ] Membership adapter를 검증 전 optional experiment로 취급하고 feasibility 종료 조건을 정의함
- [ ] 구현 상태 변경에 필요한 증거 기준이 문서화됨

---

## R4 — PM·Control Plane·I/O 계약·워크플로·Human/LLM 경계

- Live Issue: [#5](https://github.com/SASTsimi/sastsimi/issues/5)

### 쉽게 말하면

전체 파트가 같은 상태 이름과 데이터 형식을 사용하도록 중앙 기준을 정한다. 어떤 작업을 병렬로 돌릴지, 오류나 재시도를 어떻게 기록할지, LLM이 제안만 하고 프로그램과 사람이 최종 통제해야 하는 경계를 관리한다.

### 담당자가 나눌 수 있는 하위 Issue 예시

- `[R4-01] 전체 단계의 성공·보류·실패 상태 이름 통일`
- `[R4-02] 병렬 실행과 재시도·복구 규칙 확정`
- `[R4-03] 사람·LLM·프로그램의 권한 경계 최종 확인`
- `[R4-04] 공통 문서 변경과 승인 절차 확정`

### 역할 소유권

- Owner role: PM·아키텍처·워크플로
- 담당자: 김태현 `@taehyeon-git`, 윤희섭 `@v1sion`
- Primary branch: `review/control-plane`
- 관련 흐름: 전체 분석 흐름의 공통 계약, 상태 전이, 병렬·직렬 실행, 오류 정책과 사람·LLM 권한 경계

### 검토 문서

- root `README.md`
- `01-system-overview.md`, `03`, `08`, `09`, `10`, `11`, `13`
- `docs/governance/`와 `docs/review/`

### 검토할 입력·출력

- 입력: 모든 전문 역할 contract 요구, budget/eval 결과, provider/sandbox/storage 제한, human review 요구
- 출력: versioned Scope/state/error contract, orchestration state machine, RACI, review map, ADR와 run closure 기준

### 확인할 권한 경계

- LLM Orchestration은 action을 제안·조정하며 비-LLM runtime validator가 enforcement한다.
- PM/Orchestration은 verdict, CWE, Gate result, 공식 정책 또는 공개 결정을 대신하지 않는다.
- silent provider/model failover와 repository prompt에 의한 policy 변경을 금지한다.

### 필수 교차 리뷰

- 통합·구현 개발: 구현 가능성
- 데이터·평가·예산: 측정·예산 enforcement
- 변경되는 전문 계약의 owner
- report/human 경계는 Gate 담당, sandbox 경계는 동적검증 담당

### 완료 조건

- [ ] 23단계별 호출 조건, 성공/partial/retry/terminal 상태가 명확함
- [ ] verdict, Gate, rule/scope, impact, permission, report와 human state가 분리됨
- [ ] retry/failover가 새 attempt/invocation이며 이력을 보존함
- [ ] chain/repair/Gate revision/sandbox/token/time 한도의 enforcement owner가 비-LLM runtime으로 명시됨
- [ ] persistence/recovery/atomicity/idempotency 계약이 합의됨
- [ ] team username, 대체 reviewer와 independent reviewer가 매핑됨
- [ ] conflict resolution, freeze SHA와 승인·구현 저장소 동기화 규칙이 확정됨

---

## R5 — 이중 Gate·FindingCandidate/ReportDraft·Human handoff

- Live Issue: [#6](https://github.com/SASTsimi/sastsimi/issues/6)

### 쉽게 말하면

검증 결과의 근거가 코드·동적 재현과 제대로 연결됐는지 확인하고, 공식 정책 범위 안에서 보고 가능한지 검토한다. 조건을 통과한 결과만 Finding과 보고서 초안으로 정리하며 **취약점 판정을 바꾸거나 외부 공개를 결정하지는 않는다**.

### 담당자가 나눌 수 있는 하위 Issue 예시

- `[R5-01] 기술 근거 Gate의 입력·출력과 보완 요청 기준 확정`
- `[R5-02] 공식 정책·범위·영향 검토 기준 확정`
- `[R5-03] Finding과 보고서 초안 생성 조건 확인`
- `[R5-04] 사람이 검토할 자료와 비밀정보 제거 기준 확정`

### 역할 소유권

- Owner role: Gate·Finding·보고서
- 담당자: 김혜령 `@kimhr8465`
- Primary branch: `review/gate-reporting`
- 관련 흐름: CWE 라벨링 → 기술 근거 검토 → 공식 정책·영향 검토 → 보고서 초안 → 사람 검토용 자료 저장

### 검토 문서

- `05-llm-gate-and-reporting.md`
- `12-report-draft-template.md`
- `08-lightweight-data-contracts.md`의 CWE/Gate/Report 계약
- `07-results-and-observability.md`, `10-security-boundaries.md`
- `13-architecture-diagrams.md`의 Gate/report 흐름

### 검토할 입력·출력

- 입력: final VerificationResult, evidence, dynamic/PoC, CWE, restrictions, official ProgramPolicySnapshot
- 출력: TechnicalEvidenceReview, RuleScopeImpactReview, revision requests, ReportDraft, human review packet

### 확인할 권한 경계

- Gate는 Verification verdict를 변경하지 않는다.
- Gate 2는 final `TRUE + Technical ACCEPT`에서만 호출한다.
- 공식 정책이 없거나 핵심 정보가 누락되면 `UNCERTAIN + DENY`다.
- Reporter는 새 공격 주장을 만들거나 외부 제출·공개·human decision을 수행하지 않는다.

### 필수 교차 리뷰

- 검증·반박: verdict/revision/evidence 의미
- 정적분석: code-flow/location linkage
- 동적검증: dynamic/PoC linkage와 redaction
- PM: 호출 전제와 authority
- 데이터·평가: Gate 품질·오류·비용 평가

### 완료 조건

- [ ] Technical Gate가 verdict/evidence, code flow, dynamic, CWE, restriction과 handoff readiness를 검토함
- [ ] REVISE는 구체적인 새 evidence/revision을 요구하며 무한 재투표가 아님
- [ ] policy source 인증·freshness·parser failure threat model/ADR 요구가 있음
- [ ] 모순된 `ALLOW` 출력은 semantic `INVALID_OUTPUT`이며 Reporter가 차단됨
- [ ] Reporter 조건 `TRUE + ACCEPT + PASS + PASS + PASS + SUFFICIENT + ALLOW`가 runtime validator에서 강제됨
- [ ] 핵심 report claim이 evidence/PoC/Gate/policy artifact로 추적됨
- [ ] secret·PII·hidden chain-of-thought가 report와 trace에 포함되지 않음

---

## R6 — Verification 판정·독립 Pro/Con 근거·검증 플레이북

- Live Issue: [#7](https://github.com/SASTsimi/sastsimi/issues/7)

### 쉽게 말하면

가설마다 찬성 근거와 반대 근거를 따로 모으고, 부족하면 추가 코드나 동적 재현을 요청한다. 모든 근거를 종합해 `TRUE`, `FALSE`, `HOLD` 중 하나로 판정하는 기준과 취약점 유형별 검증 절차를 만든다.

### 담당자가 나눌 수 있는 하위 Issue 예시

- `[R6-01] TRUE·FALSE·HOLD 판정에 필요한 최소 근거 확정`
- `[R6-02] 찬성·반대 Agent를 호출하는 조건과 독립성 확인`
- `[R6-03] 취약점 유형별 검증 절차와 우회 확인 항목 작성`

### 역할 소유권

- Owner role: 검증·반박·플레이북
- 담당자: 임채민 `@UltraPaechKeen`
- Primary branch: `review/verification`
- 관련 흐름: 가설별 검증 시작 → 찬성·반대 근거 수집 → 필요 시 동적 재현 → 최종 판정 → 근거 보완 요청 처리

### 검토 문서

- `04-verification-and-dynamic-reproduction.md`의 Verification/debate 영역
- `08-lightweight-data-contracts.md`의 VerificationResult
- `03-agent-roles-and-orchestration.md`, `07`, `13`

### 검토할 입력·출력

- 입력: VulnerabilityHypothesis, same-snapshot context, debate trigger/budget, Pro/Con, DynamicReproductionResult, revision request
- 출력: supporting/counter evidence, initial/final verdict, dynamic decision, restrictions, capabilities, material child proposal

### 확인할 권한 경계

- Pro/Con은 독립 근거를 만들고 Verification만 `TRUE/FALSE/HOLD`를 합성한다.
- 오류, empty retrieval와 sandbox setup failure를 `FALSE`로 만들지 않는다.
- 별도 endpoint/sink/권한/impact를 기존 verdict에 몰래 합치지 않는다.
- 정책, Gate, report와 disclosure 결정을 수행하지 않는다.

### 필수 교차 리뷰

- 정적분석: context/flow/gap
- 동적검증: 재현 결정과 outcome 해석
- LLM 탐색·체이닝: material claim 환류
- PM: lifecycle/session/error
- Gate: handoff readiness
- 데이터·평가: debate 효과

### 완료 조건

- [ ] BASIC/CONDITIONAL_DEBATE/ALWAYS_DEBATE와 기본값·trigger·skip reason이 정의됨
- [ ] Pro/Con은 상대 결론을 받지 않는 독립 NEW session임
- [ ] `TRUE`는 핵심 path evidence, `FALSE`는 named falsification, `HOLD`는 unresolved condition을 요구함
- [ ] initial/final verdict와 revision history가 분리됨
- [ ] dynamic `FAILED`와 `falsification_observed`가 구분됨
- [ ] material new claim과 같은 가설의 작은 validation subtask 경계가 있음
- [ ] Technical REVISE가 새 evidence 또는 설명 revision을 남김

---

## R7 — 승인된 Docker 동적 재현·Sandbox evidence

- Live Issue: [#8](https://github.com/SASTsimi/sastsimi/issues/8)

### 쉽게 말하면

정적 근거만으로 부족한 가설을 격리된 Docker 환경에서 제한적으로 재현한다. 실행 명령, 환경, 관찰 결과와 정리된 PoC를 남기되 host·실서비스·비밀정보에 접근하지 못하도록 안전 경계를 정한다.

### 담당자가 나눌 수 있는 하위 Issue 예시

- `[R7-01] 제한 재현과 전체 재현을 선택하는 기준 확정`
- `[R7-02] Docker 네트워크·자원·파일 접근 제한 확정`
- `[R7-03] 실행 결과·PoC·정리 상태 기록 형식 확정`

### 역할 소유권

- Owner role: 동적검증·Sandbox
- 담당자: 조근석 `@Potatonion`
- Primary branch: `review/dynamic-sandbox`
- 관련 흐름: 재현 필요성 결정 → 승인된 Docker 실행 → 관찰 결과·PoC 반환 → Verification 근거로 사용

### 검토 문서

- `04-verification-and-dynamic-reproduction.md`의 dynamic 영역
- `08-lightweight-data-contracts.md`의 DynamicReproductionResult
- `07-results-and-observability.md`, `10-security-boundaries.md`, `13`

### 검토할 입력·출력

- 입력: hypothesis-linked reproduction request, snapshot/image digest, steps, approved target/network/resource policy
- 출력: DynamicReproductionResult, environment/step/observation refs, redacted PoC, limitation/cleanup/error

### 확인할 권한 경계

- sandbox는 evidence만 생산하며 verdict를 결정하지 않는다.
- host root/home, Docker socket, host process namespace, host secret, production credential와 범위 밖 target 접근을 금지한다.
- LLM 요청만으로 network/resource policy를 완화하지 않는다.

### 필수 교차 리뷰

- 검증·반박: hypothesis linkage/관측 해석
- PM: request/error/runtime enforcement
- 데이터·평가: resource/time budget
- 통합 개발: feasibility/cleanup
- Gate: PoC redaction과 report linkage

### 완료 조건

- [ ] ephemeral non-root/read-only 우선, CPU/memory/disk/process/time 제한이 기본값임
- [ ] network default-deny이며 예외 승인·scope·log가 정의됨
- [ ] image/build provenance, daemon isolation과 writable mount 정책 threat model이 있음
- [ ] LIMITED와 FULL의 선택 조건과 observable effect 차이가 명확함
- [ ] setup/execution/observation/policy/timeout failure와 반증이 다른 상태임
- [ ] snapshot/command/input/observation/cleanup이 hypothesis에 추적됨
- [ ] escape/socket/secret/out-of-scope network negative scenario가 있음

---

## R8 — 평가 코퍼스·품질/관측 지표·자원 예산

- Live Issue: [#9](https://github.com/SASTsimi/sastsimi/issues/9)

### 쉽게 말하면

각 Agent와 분석 단계가 실제로 잘 동작하는지 같은 평가 데이터로 비교할 기준을 만든다. 정확도뿐 아니라 token, 시간, 재시도, chaining과 sandbox 자원 제한을 정하고 변경 전후 품질이 나빠지지 않았는지 확인한다.

### 담당자가 나눌 수 있는 하위 Issue 예시

- `[R8-01] 평가에 사용할 취약점·오류 예제 모음 확정`
- `[R8-02] 역할별 품질·오류·비용 지표 확정`
- `[R8-03] token·시간·재시도·연계 탐색 한도 확정`
- `[R8-04] 변경 전후를 같은 조건으로 비교하는 절차 확정`

### 역할 소유권

- Owner role: 데이터·평가·예산
- 담당자: 성병찬 `@gitterable`
- Primary branch: `review/data-evaluation`
- 관련 흐름: 전체 단계의 실행 기록 수집 → 품질·비용 평가 → 예산 초과 처리 → 같은 corpus로 회귀 비교

### 검토 문서

- `07-results-and-observability.md`
- `09-llm-provider-session-and-logging.md`의 usage/evaluation
- `04`, `06`, `08`의 metric/budget 항목
- 각 역할의 정량 limit은 해당 owner와 공동 검토

### 검토할 입력·출력

- 입력: provenance-known/redacted corpus, logs, role/provider/model/session config, human reference label
- 출력: versioned scenario matrix, metric definition, budget profile, comparison plan, regression threshold

### 확인할 권한 경계

- metric은 verdict/Gate/human decision을 대신하지 않는다.
- unavailable usage를 추정 확정값으로 표시하지 않는다.
- 평가 없이 session reuse, debate 생략 또는 model/provider 변경을 정당화하지 않는다.
- credential, raw session secret와 hidden chain-of-thought를 수집하지 않는다.

### 필수 교차 리뷰

- PM: budget enforcement/state 의미
- LLM 탐색·검증·Gate: 단계별 품질 기준
- 통합 개발: instrumentation 가능성
- 개인정보/학습 범위가 생기면 별도 보안·법무 검토

### 완료 조건

- [ ] corpus가 TRUE/FALSE/HOLD, gap, conflicting evidence, Research child, policy absence, sandbox failure를 포함함
- [ ] schema validity/repair, retrieval gap/snapshot mismatch, debate 전후 품질, chaining 중단, Gate-human 차이를 측정함
- [ ] conditional debate, 독립 session, 두 Gate와 provider/model 선택에 acceptance threshold가 있음
- [ ] adversarial prompt-injection, contradictory Gate, redaction failure case가 있음
- [ ] role별 token/time/retry/chain/sandbox budget과 `BUDGET_EXCEEDED` 의미가 있음
- [ ] config 변경은 versioned config와 동일 corpus 비교를 요구함
- [ ] training 활용은 별도 ADR/data lineage/license/redaction 없이는 범위 밖임

---

## Final — 전체 교차 시나리오·Freeze SHA·승인 검토

- Live Issue: [#10](https://github.com/SASTsimi/sastsimi/issues/10)

### 쉽게 말하면

각 파트 문서를 따로 읽는 데서 끝내지 않고 실제 분석 한 건이 처음부터 마지막까지 모순 없이 흐르는지 팀 전체가 확인한다. 검토할 commit을 고정한 뒤 독립 검토자가 최신 상태를 승인해야 최종 승인 PR로 넘어갈 수 있다.

### 역할 소유권

- Owner role: independent final reviewer
- GitHub assignee: `UNASSIGNED`
- 필수 참여자: `@baeseungwon1010`, `@meow`, `@taehyeon-git`, `@v1sion`, `@kimhr8465`, `@UltraPaechKeen`, `@Potatonion`, `@gitterable`
- 전제: R1–R8 완료, 열린 Blocker/High 0, 최종 승인 PR에 freeze SHA 게시

### 필수 시나리오

| 시나리오 | 기대 상태와 금지 동작 |
|---|---|
| 정상 TRUE | `TRUE → Technical ACCEPT → Gate2 PASS/PASS/SUFFICIENT/ALLOW → ReportDraft`; human 전 외부 공개 없음 |
| 정책 없는 TRUE | Gate2 `UNCERTAIN + DENY`; Reporter 미호출 |
| schema repair 실패 | `INVALID_OUTPUT`; Verification 미할당 |
| empty/truncated context | gap 또는 HOLD 가능; 자동 FALSE 금지 |
| snapshot mismatch | context/dynamic evidence 폐기와 오류 기록 |
| 상충 Pro/Con | 독립 NEW session과 근거 기반 verdict/HOLD |
| sandbox setup 실패 | explicit dynamic failure; vulnerability FALSE 금지 |
| Research 새 claim | child hypothesis로 8단계부터 재검증; parent 불변 |
| Primitive scope 불일치 | match 거절/후보 유지 |
| chain budget/cycle | bounded stop reason; FALSE 금지 |
| Technical REVISE | 새 evidence/revision 전 Gate2/Reporter 차단 |
| 모순된 ALLOW | semantic invalid; Reporter 차단 |
| provider auth/rate-limit | explicit attempt/fallback; silent failover/FALSE 금지 |
| AST/SAST 일부 실패 | gap 포함 PARTIAL 가능 |
| snapshot 고정 실패 | run FAILED |
| repository prompt injection | provider/session/Gate/sandbox/disclosure 정책 불변 |
| secret/redaction 실패 | 일반 log/report 전달 차단 |
| human review | Agent가 disclose 결정을 생성하지 않음 |

### 완료 조건

- [ ] 번호 문서, root/v5 README, Wiki와 Mermaid의 23단계 의미가 일치함
- [ ] 모든 핵심 claim을 원본 artifact와 decision PR에 추적 가능함
- [ ] `FINDINGS.md`의 Blocker/High가 0이고 Medium deferral이 적절함
- [ ] freeze SHA 이후 unreviewed commit이 없음
- [ ] R1–R8 lead 및 independent reviewer의 최신 승인 기록이 있음
- [ ] 상태 변경은 별도 승인 PR로 수행함

## 역할별 의존 관계

```text
R8 평가/예산 기준 ─┐
                    ├─> R4 중앙 계약·runtime enforcement
R4 ─────────────────┼─> R2 snapshot/static/context
R2 + R4 + R8 ───────┴─> R1-A Hypothesis
R1-A + R2 + R4 + R8 ──> R6 Verification
R4 + R8 ──────────────> R7 Sandbox
R6 + R7 ──────────────> R1-B Research/Primitive
R6 + R7 + R1-B + R4 ──> R5 Gates/report/human handoff
R3는 모든 계약의 구현 가능성과 종단 조립을 교차 검토
R1–R8 완료 ───────────> Final cross-scenario review
```
