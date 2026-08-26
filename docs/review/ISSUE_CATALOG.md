# Architecture v5 역할별 Issue 카탈로그

이 카탈로그는 GitHub에 생성한 Parent Epic, 8개 역할별 설계 리뷰 Issue와 최종 교차 시나리오 Issue의 기준 본문이다. 생성된 Issue와 배정 현황은 [ISSUE_TRACKER.md](./ISSUE_TRACKER.md)에서 확인한다. 현재 단계는 **설계 검토**이며 runtime 구현은 범위 밖이다. GitHub username이 확인되지 않은 역할은 역할 소유권만 배정하고 assignee는 비워 둔다.

## 공통 작업 방식

모든 역할 Issue는 다음 순서를 따른다.

1. 자신의 primary 문서와 인접 생산자·소비자 계약을 읽는다.
2. 현재 설계가 실제 구현 가능한지, 책임과 금지 권한이 충돌하지 않는지 검토한다.
3. Blocker/High/Medium/Low로 발견사항을 기록한다.
4. 한 의미 변경마다 `review/<domain>` 브랜치의 focused PR을 연다.
5. upstream·downstream reviewer가 계약 양쪽을 확인한다.
6. Blocker/High를 모두 해결하고 Medium/Low를 문서화한다.
7. 변경된 번호 문서, Wiki와 Mermaid의 의미를 동기화한다.

공통 금지 사항은 runtime 구현 완료 주장, 자동 외부 테스트·제출, 오류를 `FALSE`로 변환, 미검증 LLM 출력을 권위 있는 결정으로 사용하는 것이다.

---

## Parent Epic — Architecture v5 candidate baseline 검토와 승인

- Live Issue: [#1](https://github.com/SASTsimi/sastsimi/issues/1)

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

- [ ] R1~R8 역할 Issue가 모두 완료되고 관련 PR이 `main`에 merge됨
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

### 역할 소유권

- Owner role: LLM 탐색·체이닝
- GitHub assignee: `UNASSIGNED` — 역할 담당자가 claim
- Primary branch: `review/hypothesis-research`
- Pipeline: 6~7, 14~16, 22

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

### 역할 소유권

- Owner role: 정적분석·컨텍스트
- GitHub assignee: `UNASSIGNED` — 역할 담당자가 claim
- Primary branch: `review/static-context`
- Pipeline: 2~4, 9

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

### 역할 소유권

- Owner role: 통합·구현 개발
- GitHub assignee: `UNASSIGNED` — 역할 담당자가 claim
- Primary branch: `review/integration-feasibility`
- Pipeline: 1~23 전체 구현 가능성

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

### 역할 소유권

- Owner role: PM·아키텍처·워크플로
- GitHub assignee: `@taehyeon-git` (repository steward가 초기 coordination 담당)
- Primary branch: `review/control-plane`
- Pipeline: 1~23 중앙 통합

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

### 역할 소유권

- Owner role: Gate·Finding·보고서
- GitHub assignee: `UNASSIGNED` — 역할 담당자가 claim
- Primary branch: `review/gate-reporting`
- Pipeline: 17~21, 23

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

### 역할 소유권

- Owner role: 검증·반박·플레이북
- GitHub assignee: `UNASSIGNED` — 역할 담당자가 claim
- Primary branch: `review/verification`
- Pipeline: 8~13, Technical REVISE 환류

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

### 역할 소유권

- Owner role: 동적검증·Sandbox
- GitHub assignee: `UNASSIGNED` — 역할 담당자가 claim
- Primary branch: `review/dynamic-sandbox`
- Pipeline: 12~13

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

### 역할 소유권

- Owner role: 데이터·평가·예산
- GitHub assignee: `UNASSIGNED` — 역할 담당자가 claim
- Primary branch: `review/data-evaluation`
- Pipeline: 전 단계의 평가와 예산

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

### 역할 소유권

- Owner role: independent final reviewer
- GitHub assignee: `UNASSIGNED`
- 전제: R1~R8 완료, 열린 Blocker/High 0, 최종 승인 PR에 freeze SHA 게시

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
- [ ] R1~R8 lead 및 independent reviewer의 최신 승인 기록이 있음
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
R1~R8 완료 ───────────> Final cross-scenario review
```
