# Architecture v5 역할별 Issue 카탈로그

이 문서는 역할별 상위 Issue에서 무엇을 검토하고 어떤 세부 하위 Issue를 만들지 안내합니다. 실제 Issue와 담당자 상태는 [Issue 현황](./ISSUE_TRACKER.md)에서 확인합니다. 현재 단계는 **설계 검토**이며 실행 코드(`runtime`) 구현은 범위 밖입니다. 역할 담당자와 실제 GitHub 계정, 최종 검토·승인 담당자는 모두 정해졌습니다. 모르는 기술 용어는 [쉬운 용어집](../GLOSSARY.md)에서 확인합니다.

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

## 전체 관리 Issue — Architecture v5 검토 중 설계 초안 승인 준비

- 실제 Issue: [#1](https://github.com/SASTsimi/sastsimi/issues/1)
- 진행 담당: 김태현 `@taehyeon-git`, 윤희섭 `@YHS-Sec`

### 쉽게 말하면

팀원별 설계 검토가 따로 놀지 않도록 R1–R8의 작업, 교차 리뷰와 마지막 전체 검토를 한곳에서 관리한다. 이 Epic이 끝나야 구현을 시작할 설계 기준을 확정할 수 있다.

### 목적

22단계 LLM 중심 흐름을 역할, 입출력 약속, 오류, 예산, 보안 경계와 Agent 자동화 종료 지점 관점에서 검토하여 구현을 시작할 수 있는 설계 기준을 만든다.

### 범위

- Repository input과 `CodeWorkspace` 준비부터 `ReportDraft`·`AnalysisRunResult` 확정 및 Agent 자동화 종료까지의 22단계
- 정적 사실, 가설, Verification-owned workflow, sandbox, Primitive/Chaining, 두 Gate, report 계약
- provider/session/logging과 resource budget
- local workspace, prompt injection, credential, sandbox, official policy trust boundary
- 역할 간 producer/consumer 계약과 종단 실패 시나리오

### 비범위

- runtime 코드 구현과 배포
- v4 상태·Gate 결과 자동 승계
- 자동 외부 자산 테스트, 보고서 제출 또는 공개
- 공식 정책이 없을 때 LLM 기억이나 저장소 문서로 정책 추정
- fine-tuning/training dataset 구축

### 완료 조건

- [ ] R1–R8 역할 Issue가 모두 완료되고 관련 PR이 `main`에 merge됨
- [ ] 22단계 각각에 owner, 입력, 출력, 오류와 금지 권한이 있음
- [ ] 모든 핵심 결과가 `analysis_id`, `workspace_id`, `hypothesis_id`, `attempt_id`와 추적 가능함
- [ ] 오류·timeout·auth·sandbox setup 실패가 `FALSE`로 변환되지 않음
- [ ] 두 Gate와 보고서 Agent의 순서·전제조건을 프로그램 내부 규칙 검사기(`runtime validator`)가 강제함
- [ ] Verification-origin과 Chaining-origin material claim이 새 가설로 전체 검증됨
- [ ] HOLD는 `required_primitive_candidates`가 하나 이상일 때만 `inputs + result=null` Primitive로 연결 후보가 되고, 후보가 비어 있으면 Primitive·Chaining work가 생기지 않음. TRUE는 validated PoC·Technical `ACCEPT`·current admission `ALLOW` 뒤에만 `inputs + result` Primitive로 연결되며 FALSE는 체이닝되지 않음
- [ ] 모든 Blocker/High가 닫히고 Medium은 명시적으로 처리됨
- [ ] freeze commit SHA, 역할 간 교차 검토와 최종 검토·승인 담당자의 최신 확인 기록이 있음
- [ ] 별도 승인 PR 전까지 `REVIEW_REQUIRED / NOT_IMPLEMENTED`를 유지함

---

## R1 — 제약형 가설 생성·Primitive Chaining·LLM 효율화

- 실제 Issue: [#2](https://github.com/SASTsimi/sastsimi/issues/2)

### 쉽게 말하면

정적 분석이 모은 코드 사실을 보고 LLM이 **검증할 취약점 후보 목록**을 만드는 방법을 정한다. 이미 확인된 취약점들이 서로 연결될 가능성이 있으면 바로 확정하지 않고 새로운 연계 가설로 다시 검증하게 만든다.

### 담당자가 나눌 수 있는 하위 Issue 예시

- `[R1-01] 취약점 가설에 반드시 들어갈 정보 확정`
- `[R1-02] 연계 공격 후보를 새 가설로 만드는 조건 확정`
- `[R1-03] 연계 탐색의 시간·작업·중복 중단 기준 확정`

### 역할 소유권

- 담당 역할: LLM 탐색·체이닝
- 담당자: 배승원 `@baeseungwon1010`
- 주요 작업 브랜치: `review/hypothesis-research`
- 관련 흐름: 정적 사실 묶음 → 최초 취약점 가설 목록, 그리고 current Primitive의 upstream `result`→downstream `input` matching → 새 가설 반환
- 세부 연결 Issue: [#78](https://github.com/SASTsimi/sastsimi/issues/78), [#79](https://github.com/SASTsimi/sastsimi/issues/79), [#80](https://github.com/SASTsimi/sastsimi/issues/80)

### 검토 문서

- `03-agent-roles-and-orchestration.md`
- `06-chaining.md`
- `08-lightweight-data-contracts.md`의 Hypothesis/Primitive/Chaining 계약
- `09-llm-provider-session-and-logging.md`의 역할별 profile
- `13-architecture-diagrams.md`의 관련 흐름

### 검토할 입력·출력

- 입력: 최초 가설용 `StaticFactBundle` refs, `RecordMeta`, 전역 budget, current `Primitive`와 direct·ancestor ALLOW admission refs
- 출력: schema-valid `HypothesisProposal[]`, `INVALID_OUTPUT`, `PrimitiveMatchCandidate`, `source_admission_refs`를 포함한 `ChainingResult`, chained proposal과 no-match 결과

### 확인할 권한 경계

- proposal은 `HYPOTHESIS_ONLY / NON_FINAL`이며 verdict·Finding·CWE·Gate·report를 확정하지 않는다.
- 등록된 가설은 점수로 제외하거나 순서를 매기지 않고 모두 검증한다.
- HOLD는 `required_primitive_candidates`가 하나 이상일 때만 전체 후보를 `inputs`, `result=null`로 둔 Primitive로 matching 가능하다. 후보가 비어 있으면 Primitive와 Chaining work를 만들지 않는다. TRUE는 validated PoC와 Technical `ACCEPT`가 있고 금지 테스트 위반이 확정되지 않아 current admission이 `ALLOW`인 exact revision만 `result` Primitive가 된다. 다른 Rule Scope 판단은 보고 가능성만 바꾸며 FALSE와 admission `DENY`는 chaining 근거로 승격하지 않는다.
- 문자열 일치나 전역 권한 서열로 chain을 확정하지 않는다. 같은 `workspace_id`·`commit_id`에서 upstream result가 downstream의 `matched_input_id`를 실제로 충족하는지 저장소의 entity·역할/권한 상수·검사 위치·restriction 근거로 확인한다.
- Chaining Agent는 upstream result→downstream input matching만 하며 일반 bypass·alternate path·impact·Technical revision을 조사하지 않는다.
- chained proposal은 `origin=CHAINING`이며 새 가설로 전체 검증한다.

### 필수 교차 리뷰

- 정적분석·컨텍스트: location/fact grounding
- 검증·반박·플레이북: falsification과 새 claim 경계
- PM·아키텍처·워크플로: lifecycle/schema/runtime enforcement
- 데이터·평가·예산: time/cost/work/quality 기준과 token 사용량 관측

### 완료 조건

- [ ] proposal 필수 field, semantic validation, repair retry와 `INVALID_OUTPUT`이 명확함
- [ ] facts와 assumptions, restriction, missing information, falsification question이 구분됨
- [ ] Primitive match compatibility와 duplicate/cycle 규칙이 문서화됨
- [ ] `parent_hypothesis_ids`와 `source_primitive_match_id`에서 조상 계보를 계산해 조상 Primitive를 현재 후보에서 제외함
- [ ] 체이닝 전용 임의 depth/count/call/combination/token 상한을 두지 않고 R8 전역 time/cost/work budget과 중단 이유를 사용함
- [ ] no-match와 전역 예산 중단도 관측 가능함
- [ ] token 최적화가 동일 corpus의 품질 저하 여부와 함께 평가됨
- [ ] Wiki/Mermaid 및 인접 계약이 일치함

---

## R2 — 정적 사실 계층·동일 workspace와 commit 기반 Context Retrieval

- 실제 Issue: [#3](https://github.com/SASTsimi/sastsimi/issues/3)

### 쉽게 말하면

AST·CodeQL·OpenGrep 결과를 LLM이 바로 사용할 수 있도록 **파일 위치, 함수, 호출 흐름과 source/sink/방어 로직 후보 중심의 사실 묶음**으로 정리한다. 분석 도중 코드가 더 필요할 때 같은 저장소 버전에서 필요한 부분만 안전하게 가져오게 한다.

### 담당자가 나눌 수 있는 하위 Issue 예시

- `[R2-01] 저장소 분석 시점과 코드 위치 식별 방법 확정`
- `[R2-02] AST·CodeQL·OpenGrep 결과를 하나의 형식으로 정리`
- `[R2-03] 필요한 코드만 다시 가져오는 범위와 한도 확정`

### 역할 소유권

- 담당 역할: 정적분석·컨텍스트
- 담당자: 김나연 `@zv9uvr`
- 주요 작업 브랜치: `review/static-context`
- 관련 흐름: `git clone`과 commit checkout → `CodeWorkspace` → AST/SAST 병렬 실행 → 사실 묶음 생성 → 필요한 코드 위치 조회

### 검토 문서

- `02-static-fact-layer.md`
- `08-lightweight-data-contracts.md`의 StaticFactBundle/Context 계약
- `07-results-and-observability.md`의 static/retrieval metric
- `10-security-boundaries.md`의 workspace/retrieval 경계
- `13-architecture-diagrams.md`의 정적 분석 흐름

### 검토할 입력·출력

- 입력: `CodeWorkspace`, AST/SAST raw result, exclusion policy, `CodeContextRequest`, budget
- 출력: `StaticFactBundle`의 `source_candidates | sink_candidates | sanitizer_candidates | validator_candidates | auth_and_permission_checks | other_facts`, `CodeSymbol`/`CodeLocation`/relation refs, `DataGap`, `CodeContextResponse`, tool/coverage 상태

### 확인할 권한 경계

- AST/SAST severity와 rule hit은 verdict가 아니다.
- empty/truncated/unresolved 결과를 안전 또는 `FALSE`로 해석하지 않는다.
- 서로 다른 `workspace_id` 또는 `commit_id`를 혼합하지 않는다.
- path traversal, symlink escape, `workspace_root` 밖 조회와 무제한 repository dump를 금지한다.

### 필수 교차 리뷰

- LLM 탐색·체이닝: Hypothesis 입력의 충분성과 최소성
- 검증·반박·플레이북: evidence/gap 표현
- PM·아키텍처·워크플로: identity·RecordMeta·error 계약
- 통합·구현 개발: parser/runner/normalizer/retrieval feasibility

### 완료 조건

- [ ] `CodeWorkspace`, `StoredDataRef`, `CodeLocation`, `CodeSymbol`의 식별자와 생성 주체가 정의됨
- [ ] clone/checkout, submodule, LFS와 generated dependency의 gap 처리 규칙이 있음
- [ ] 모든 사실을 producer, `StoredDataRef`, `CodeLocation`, `workspace_id`로 역추적할 수 있음
- [ ] 여섯 사실 목록이 `CodeFact.fact_kind`를 빠짐없이 나누고 전체 `fact_id`가 중복되지 않음
- [ ] sanitizer·validator는 방어 로직 후보로만 전달하며 실제 적용·순서·우회 가능성은 R6가 검증함
- [ ] 후보가 없는 목록도 `[]`로 전달하고 빈 배열을 안전함이나 검사 완료로 해석하지 않음
- [ ] AST/SAST 부분 실패와 충돌·불확실성이 gap/error로 보존됨
- [ ] relation query와 depth/fragment/byte/request/time 제한이 정의되고 token 추정치는 비차단 관측값으로 구분됨
- [ ] `WORKSPACE_MISMATCH`, `WORKSPACE_CHANGED`와 path/symlink negative scenario가 문서화됨
- [ ] `gaps` 이름과 소비자 의미가 일관됨

---

## R3 — 통합 구현 가능성·계약 준수 테스트·모듈 조립 검토

- 실제 Issue: [#4](https://github.com/SASTsimi/sastsimi/issues/4)

### 쉽게 말하면

각 파트의 설계가 실제 코드 모듈로 이어질 수 있는지 확인하고, 모듈 사이의 입력·출력과 오류가 서로 맞는지 테스트 계획을 만든다. 현재는 설계 검토 단계이므로 전체 코드를 구현하는 것이 아니라 **구현 가능한 설계인지 확인하는 작업**이다.

### 담당자가 나눌 수 있는 하위 Issue 예시

- `[R3-01] 전체 단계를 실제 모듈과 연결하는 표 작성`
- `[R3-02] 파트 사이의 입출력 약속을 검사할 테스트 설계`
- `[R3-03] 중단·재시도·복구 시나리오와 통합 시험 설계`

### 역할 소유권

- 담당 역할: 단독 구현·통합 개발
- 담당자: 김태현 `@taehyeon-git`, 윤희섭 `@YHS-Sec`
- 주요 작업 브랜치: `review/integration-feasibility`
- 관련 흐름: 저장소 입력부터 `ReportDraft`·`AnalysisRunResult` 확정과 Agent 자동화 종료까지의 모듈·저장·복구·테스트 연결

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

- [ ] 22단계와 Agent 자동화 종료 경계가 예상 module/entry point/contract/store/test에 매핑됨
- [ ] analysis/hypothesis/parent-child/attempt correlation과 record revision을 재구성할 수 있음
- [ ] 병렬·직렬 지점과 atomic transition/idempotency/crash-resume 요구가 정의됨
- [ ] partial/failed/cancelled/auth/rate-limit/sandbox/policy 오류의 전파가 명확함
- [ ] 다른 workspace/commit 혼합, Gate 전·stale TRUE Primitive admission, Chaining 일반 research, Reporter bypass negative test plan이 있음
- [ ] Membership adapter를 검증 전 optional experiment로 취급하고 feasibility 종료 조건을 정의함
- [ ] 구현 상태 변경에 필요한 증거 기준이 문서화됨

---

## R4 — PM·Control Plane·I/O 계약·워크플로·Agent/Runtime 경계

- 실제 Issue: [#5](https://github.com/SASTsimi/sastsimi/issues/5)

### 쉽게 말하면

전체 파트가 같은 상태 이름과 데이터 형식을 사용하도록 중앙 기준을 정한다. Orchestration의 전역 등록·배정과 Verification의 가설 내부 제어권을 나누고, 오류나 재시도를 어떻게 기록할지, LLM 제안과 프로그램 강제 규칙 및 Agent 자동화 종료 경계를 관리한다.

### 담당자가 나눌 수 있는 하위 Issue 예시

- `[R4-01] 전체 단계의 성공·보류·실패 상태 이름 통일`
- `[R4-02] 병렬 실행과 재시도·복구 규칙 확정`
- `[R4-03] Agent·프로그램의 권한과 자동화 종료 경계 최종 확인`
- `[R4-04] 공통 문서 변경과 승인 절차 확정`

### 역할 소유권

- 담당 역할: PM·아키텍처·워크플로
- 담당자: 김태현 `@taehyeon-git`, 윤희섭 `@YHS-Sec`
- 주요 작업 브랜치: `review/control-plane`
- 관련 흐름: 전체 분석 흐름의 공통 계약, 상태 전이, 병렬·직렬 실행, 오류 정책과 Agent·Runtime 권한 경계

### 검토 문서

- root `README.md`
- `01-system-overview.md`, `03`, `08`, `09`, `10`, `11`, `13`
- `docs/governance/`와 `docs/review/`

### 검토할 입력·출력

- 입력: 모든 전문 역할 contract 요구, budget/eval 결과와 provider/sandbox/storage 제한
- 출력: versioned RecordMeta/state/error contract, `WorkExecutionState`·attempt·transition commit, `ActionRequest`·`ActionDecision`, 동적 결과의 공통 exact reference·null·상태 조합, `ReportDraft`·`AnalysisRunResult` 종료 경계, orchestration state machine, RACI, review map, ADR와 run closure 기준

### 확인할 권한 경계

- Orchestration은 proposal 검증·전역 등록·Verification 배정까지만 담당하고, 가설 내부 다음 행동은 Verification이 제안·조정한다.
- Verification ownership과 관계없이 LLM이 아닌 프로그램 내부 규칙 검사기(`runtime validator`)가 action 규칙 준수를 강제한다.
- PM/Orchestration은 가설 내부 Pro/Con·dynamic·Gate·Chaining, verdict, CWE, Gate result, 공식 정책 또는 공개 결정을 대신하지 않는다.
- silent provider/model failover와 repository prompt에 의한 policy 변경을 금지한다.
- Runtime Validator는 action의 호출 권한·상태·예산·reference 범위를 강제하며 verdict·CWE·정책 의미를 대신 판단하지 않는다. Sandbox의 image·command·file·network·resource·cleanup 세부 정책은 R7의 Sandbox Controller가 전담한다.
- Reporter는 안전 요구사항을 지킨 내부 초안만 만들고 이후 Agent action을 계속하지 않는다. 사람의 검토·수정·제출·공개는 자동화 밖이다.

### 필수 교차 리뷰

- 통합·구현 개발: 구현 가능성
- 데이터·평가·예산: 측정·예산 enforcement
- 변경되는 전문 계약의 owner
- ReportDraft와 자동화 종료 경계는 Gate 담당, sandbox 경계는 동적검증 담당

### 완료 조건

- [ ] 22단계별 호출 조건, 성공/partial/retry/terminal 상태가 명확함
- [ ] verdict, Gate, rule/scope, impact, permission과 report 상태가 분리됨
- [ ] retry/failover가 새 attempt/invocation이며, 바로 앞 실패 호출 reference로 순서와 원인을 복원할 수 있음
- [ ] 같은 요청은 canonical `dedupe_key`로 기존 `work_id`를 재사용하고 한 work에는 active attempt가 하나임
- [ ] 상태 변경은 `state_version` compare-and-set을 사용하고 stale·취소·다른 workspace/commit 결과를 거절함
- [ ] 중복·ancestor 재사용·repair/Gate revision과 R8 전역 time/cost/work budget의 enforcement owner가 비-LLM Runtime Validator로, Sandbox 세부 정책의 enforcement owner가 Sandbox Controller로 명시됨. token은 관측값이며 초과·누락만으로 action을 차단하지 않음
- [ ] Technical `REVISE`가 Orchestration을 경유해 재배정되지 않고 같은 ACTIVE VerificationAssignment owner의 새 VERIFICATION work로 돌아감
- [ ] non-empty `required_primitive_candidates`를 가진 HOLD의 `inputs + result=null`과 Technical-accepted + 같은 Verification의 current `PrimitiveAdmissionDecision=ALLOW` TRUE의 `inputs + result` Primitive admission·supersede 규칙이 있으며, 빈 HOLD 후보에는 Primitive·Chaining work가 없음
- [ ] persistence/recovery/atomicity/idempotency 계약이 합의되고 `TERMINAL`·`DRAFTED` 상태가 정확한 결과 `record_id`를 가리킴
- [ ] 결과 record 저장과 종료 상태 변경 중 하나만 성공했을 때의 crash-resume 복구와 오래되거나 취소된 결과의 연결 거절 규칙이 있음
- [ ] `TransitionCommit`이 `COMMITTED`된 결과만 downstream과 최종 결과에서 사용함
- [ ] 역할별 `ActionRequest`가 필수 check를 모두 통과한 `ActionDecision`에서만 한 번 실행됨
- [ ] 두 LLM Gate 순서, Reporter 조건과 공식 정책 부재 `UNCERTAIN + DENY`를 runtime이 검사함
- [ ] R6 request와 R7 requirements·plan·동적 결과가 같은 analysis·workspace·commit·hypothesis·Verification generation에 묶이고, recipe·정책·환경·AgentLog·PoC candidate·cleanup이 같은 R7 attempt로 검증됨
- [ ] 모든 final TRUE가 현재 generation의 `SUCCEEDED + SUPPORTED` 결과와 validated PoC를 가지며, 실패는 verdict 없이 `BLOCKED | FAILED`로 처리됨
- [ ] `ReportDraft`가 exact provenance, restriction·limitation·남은 불확실성과 redaction 결과를 보존하고 마지막 Agent 산출물로 종료됨
- [ ] 실제 GitHub 계정과 최종 검토·승인 담당자가 문서와 Issue에서 일치함
- [ ] conflict resolution, freeze SHA와 승인·구현 저장소 동기화 규칙이 확정됨

---

## R5 — 이중 Gate·FindingCandidate·ReportDraft

- 실제 Issue: [#6](https://github.com/SASTsimi/sastsimi/issues/6)

### 쉽게 말하면

검증 결과의 근거가 코드·동적 재현과 제대로 연결됐는지 확인하고, 공식 정책 범위 안에서 보고 가능한지 검토한다. 조건을 통과한 결과만 Finding과 보고서 초안으로 정리하며 **취약점 판정을 바꾸거나 외부 공개를 결정하지는 않는다**.

### 담당자가 나눌 수 있는 하위 Issue 예시

- `[R5-01] CWE labeling과 기술 근거 Gate의 입력·출력·보완 요청 기준 확정`
- `[R5-02] 공식 정책·범위·영향 검토 기준 확정`
- `[R5-03] Finding과 안전한 보고서 초안 생성 및 자동화 종료 조건 확인`

R5 자동화는 세 번째 세부 작업의 `ReportDraft` 생성에서 끝난다. 기존 사람 검토 자동화 작업은 제거했으며, 출처 추적·오래된 참조 차단·restriction/limitation 보존·민감정보 제거 요구는 R5-03에 포함한다.

### 역할 소유권

- 담당 역할: Gate·Finding·보고서
- 담당자: 김혜령 `@kimhr8463`
- 주요 작업 브랜치: `review/gate-reporting`
- 관련 흐름: final TRUE → R5-01 `CWE_LABELING` current label 생성 → 기술 근거 검토 → 공식 정책·영향 검토 → 안전한 보고서 초안 → 결과 저장 → Agent 자동화 종료

### 검토 문서

- `05-llm-gate-and-reporting.md`
- `12-report-draft-template.md`
- `08-lightweight-data-contracts.md`의 CWE/Gate/Report 계약
- `07-results-and-observability.md`, `10-security-boundaries.md`
- `13-architecture-diagrams.md`의 Gate/report 흐름

### 검토할 입력·출력

- 입력: final VerificationResult, evidence, dynamic/PoC, restrictions, taxonomy와 official ProgramPolicyRecord
- 출력: R5-01의 current CWELabel, TechnicalEvidenceReview, RuleScopeImpactReview, revision requests와 안전 요구사항을 충족한 ReportDraft

### 확인할 권한 경계

- Gate는 Verification verdict를 변경하지 않는다.
- R5-01 `CWE_LABELING`만 `CWELabel`을 생산하며 Technical Gate는 생성·수정하지 않는다.
- 새 Verification에는 CWE 값이 같아도 exact Verification을 가리키는 새 label revision을 확정한다.
- Gate 1은 final TRUE에서만, Gate 2는 같은 `TRUE + Technical ACCEPT`에서만 호출한다.
- 공식 정책이 없거나 핵심 정보가 누락되면 `UNCERTAIN + DENY`다.
- Technical `REVISE`는 Orchestration이나 R7이 목적지를 고르지 않고 같은 ACTIVE `VerificationAssignment`의 R6 owner에게 직접 돌아간다.
- Reporter는 새 공격 주장을 만들거나 외부 제출·공개를 수행하지 않으며 ReportDraft 뒤 자동 Agent 작업을 만들지 않는다.

### 필수 교차 리뷰

- 검증·반박: verdict/revision/evidence 의미
- 정적분석: code-flow/location linkage
- 동적검증: dynamic/PoC linkage와 redaction
- PM: 호출 전제와 authority
- 데이터·평가: Gate 품질·오류·비용 평가

### 완료 조건

- [ ] Technical Gate가 verdict/evidence, code flow, dynamic, CWE, restriction과 handoff readiness를 검토함
- [ ] `CWELabel.verification_result_ref`, generation, CWE work·attempt·LLM invocation provenance가 current final TRUE와 일치함
- [ ] 성공한 `CWE_LABEL` work의 유일한 output만 current label이며, 새 Verification에 과거 label을 재사용하지 않음
- [ ] `verification_result_ref.record_id`와 `cwe_label_ref.record_id`로 실제 검토한 Verification·CWELabel revision을 고정하고, 두 Gate와 ReportDraft가 같은 revision을 사용함
- [ ] REVISE는 구체적인 새 evidence/revision을 요구하며 무한 재투표가 아님
- [ ] REVISE는 같은 ACTIVE VerificationAssignment owner에게 직접 전달되고 새 VERIFICATION work·Verification/CWELabel revision 전에는 재호출되지 않음
- [ ] result Primitive은 Technical `ACCEPT` + current `PrimitiveAdmissionDecision=ALLOW`를, Reporter는 Technical·Rule Scope의 별도 보고 조건 전체를 요구하며 두 자격을 혼합하지 않음
- [ ] policy source 인증·freshness·parser failure threat model/ADR 요구가 있음
- [ ] 모순된 `ALLOW` 출력은 semantic `INVALID_OUTPUT`이며 Reporter가 차단됨
- [ ] 보고서 Agent 호출 조건 `TRUE + ACCEPT + PASS + PASS + PASS + SUFFICIENT + ALLOW`를 프로그램 내부 규칙 검사기(`runtime validator`)가 강제함
- [ ] 핵심 report claim이 evidence/PoC/Gate/policy artifact로 추적됨
- [ ] restriction·limitation·남은 불확실성이 초안에서 빠지거나 약화되지 않음
- [ ] secret·PII·hidden chain-of-thought가 report와 trace에 포함되지 않음
- [ ] ReportDraft가 마지막 Agent 산출물이며 이후 사람 주도 과정은 자동 action·상태 계약 밖에 있음

---

## R6 — Verification 판정·독립 Pro/Con 근거·검증 플레이북

- 실제 Issue: [#7](https://github.com/SASTsimi/sastsimi/issues/7)

### 쉽게 말하면

배정받은 가설마다 Context·찬성·반대 근거를 관리한다. initial TRUE이면 PoC 확인을, 판정에 실행 근거가 필요하면 동적 근거 확보를 `DynamicReproductionRequest`로 R7에 요청한다. R7이 돌려준 `COMMITTED` 결과를 다른 근거와 종합해 `TRUE`, `FALSE`, `HOLD` 중 하나로 판정한다. 모든 final TRUE에는 성공한 재현과 validated PoC가 필요하다. 새 material claim은 별도 가설로 분리한다.

### 담당자가 나눌 수 있는 하위 Issue 예시

- `[R6-01] TRUE·FALSE·HOLD 판정에 필요한 최소 근거 확정`
- `[R6-02] 찬성·반대 Agent를 호출하는 조건과 독립성 확인`
- `[R6-03] 동적 재현 요청과 결과 소비 계약 확정`
- `[R6-04] Gate REVISE·Primitive·Chaining 연결과 Verification 수명주기 확정`
- `[R6-05] 공통·웹 취약점 6종 검증 플레이북 작성`

### 역할 소유권

- 담당 역할: 검증·반박·플레이북
- 담당자: 임채민 `@UltraPeachKeen`
- 주요 작업 브랜치: `review/verification`
- 관련 흐름: 가설별 검증 시작 → Context·찬성·반대 근거 → initial verdict → `POC_CONFIRMATION | VERDICT_EVIDENCE` 요청 → runtime 검사·R7 결과 소비 → 최종 판정 → validated PoC가 있는 TRUE만 CWE/Gate 요청 → REVISE 직접 보완 → 조건부 Chaining handoff

### 검토 문서

- `04-verification-and-dynamic-reproduction.md`의 Verification/debate 영역
- `08-lightweight-data-contracts.md`의 VerificationResult
- `03-agent-roles-and-orchestration.md`, `07`, `13`

### 검토할 입력·출력

- 입력: VulnerabilityHypothesis, 같은 workspace/commit의 context, 운영 Pro/Con budget, 평가용 debate trigger, R7의 DynamicReproductionResult, revision request
- 출력: supporting/counter evidence, 질문별 `FalsificationResult`, initial/final verdict, `DynamicReproductionRequest`, restrictions, `required_primitive_candidates`, `provided_primitive_candidates`, `origin=VERIFICATION` material child proposal와 exact Gate action/reference

### 확인할 권한 경계

- Pro/Con은 독립 근거를 만들고 Verification만 `TRUE/FALSE/HOLD`를 합성한다.
- 오류, empty retrieval와 sandbox setup failure를 `FALSE`로 만들지 않는다.
- 별도 endpoint/sink/권한/impact를 기존 verdict에 몰래 합치지 않는다.
- R6는 동적 재현 purpose·목표·필요 환경·Sandbox profile·근거 reference를 요청하지만 `EnvironmentRequirements`·`ReproductionPlan`·recipe·command·PoC·동적 결과를 생산하지 않는다. R7의 `COMMITTED` 결과만 소비한다.
- 모든 TRUE에는 validated PoC가 필요하다. PoC 생성·환경 구성·실행 실패는 `FALSE | HOLD`가 아니다. R7이 자체 해결할 수 있으면 자동 retry하고, 외부 조건을 기다릴 때만 `BLOCKED`, 복구 불가능하거나 한도를 소진하면 verdict 없는 `FAILED`다.
- Gate 결과·정책 의미·공개 결정을 대신 만들지 않는다. Gate·Reporter 호출을 제안해도 Runtime Validator 검사를 우회하지 않는다.

### 필수 교차 리뷰

- 정적분석: context/flow/gap
- 동적검증: R6 요청의 재현 가능성, 자율 실행 log·outcome·PoC 반환 계약
- LLM 탐색·체이닝: material claim 환류
- PM: lifecycle/session/error
- Gate: handoff readiness
- 데이터·평가: debate 효과

### 완료 조건

- [ ] 운영은 ALWAYS_DEBATE만 허용하고 BASIC/CONDITIONAL_DEBATE는 Gate·Primitive·Reporter로 전달하지 않는 격리 평가 전용임
- [ ] Pro/Con은 상대 결론을 받지 않는 독립 NEW session임
- [ ] `TRUE`는 핵심 path evidence, `FALSE`는 `question_id`와 실제 근거가 있는 `DISPROVED`, `HOLD`는 unresolved condition을 요구함
- [ ] initial/final verdict와 revision history가 분리됨
- [ ] dynamic 실행 `status`, 관측 `hypothesis_outcome`, `hypothesis_disproved`와 Verification verdict가 구분됨
- [ ] R6가 current generation의 exact `DynamicReproductionRequest`만 생산하고 R7의 `COMMITTED` 결과만 소비함
- [ ] 한 Verification generation에 동적 work 하나만 있고 retry는 같은 work의 새 attempt이며, Technical `REVISE` 새 generation에는 한도가 새로 적용됨
- [ ] final TRUE는 현재 generation의 `SUCCEEDED + SUPPORTED` 동적 결과와 validated `poc_ref`를 요구함
- [ ] PoC 생성·환경 구성·실행 실패는 final verdict와 Gate 없이 `BLOCKED | FAILED`이며 `FALSE | HOLD`로 바뀌지 않음
- [ ] material new claim과 같은 가설의 작은 validation subtask 경계가 있음
- [ ] material new claim은 `origin=VERIFICATION` proposal로 trusted registration 뒤 새 Verification을 받음
- [ ] Technical REVISE를 같은 ACTIVE VerificationAssignment owner가 새 VERIFICATION work에서 받고 새 evidence 또는 설명 revision을 남김
- [ ] `FALSE`는 Primitive·Gate·Chaining 없이 종료하고, `HOLD`는 `required_primitive_candidates`가 하나 이상일 때만 `inputs + result=null` Primitive로 저장되며 후보가 비어 있으면 Primitive·Chaining work 없이 종료함. `TRUE`는 Technical `ACCEPT` + current admission `ALLOW`일 때만 `inputs + result` Primitive로 저장됨
- [ ] Rule Scope의 보고 적격성과 Primitive·Chaining admission이 분리되며, admission `DENY`만 result Primitive·Chaining을 차단함
- [ ] R6는 후보·Gate action·exact reference를 만들고 trusted runtime이 commit·current pointer·Primitive·`PrimitiveIndexState`를 갱신함
- [ ] 새 generation에서 과거 동적 결과·PoC·CWE·Gate·admission 자격을 재사용하지 않음
- [ ] `TRUE + HOLD`, `TRUE + TRUE`만 current Primitive로 연결하며 child·Chaining 결과가 부모 verdict를 변경하지 않음

---

## R7 — 자율 동적 재현 Agent·Clean Sandbox evidence

- 실제 Issue: [#8](https://github.com/SASTsimi/sastsimi/issues/8)

### 쉽게 말하면

R6의 `DynamicReproductionRequest`를 받아 R7 Agent가 먼저 exact `EnvironmentRequirements`와 간단한 `ReproductionPlan`을 만든다. Controller가 외부 경계를 허용하면 Setup Automation이 recipe·image·container·cleanup을 수행하고, Agent는 격리된 Docker 안에서 PoC candidate·command·관찰·재시도를 자율적으로 선택한다. Session Manager가 실제 AgentLog와 validated PoC·동적 결과를 같은 attempt로 확정한다.

### 하위 Issue

- `[#19 R7-01] 자율 동적 재현 session·결과 반환 흐름 설계`
- `[#20 R7-02] 공통 재현 recipe·clean Sandbox 최소 E2E 구성 설계`
- `[#22 R7-03] Docker Sandbox 격리·네트워크·자원 제한 설계`
- `[#21 R7-04] 동적 Evidence·PoC·실패 상태 기록 설계`

### 역할 소유권

- 담당 역할: 동적검증·Sandbox
- 담당자: 조근석 `@Potatonion`
- 주요 작업 브랜치: `review/dynamic-sandbox`
- 관련 흐름: R6의 exact `DynamicReproductionRequest` 수신 → R7 Agent가 requirements·간단한 plan 생성 → Controller 외부 경계 검사 → Setup Automation의 recipe·환경 구성 → Agent 자율 재현 → Session Manager의 AgentLog·validated PoC·동적 결과 확정

### 검토 문서

- `04-verification-and-dynamic-reproduction.md`의 dynamic 영역
- `08-lightweight-data-contracts.md`의 DynamicReproductionResult
- `07-results-and-observability.md`, `10-security-boundaries.md`, `13`

### 검토할 입력·출력

- 입력: R6가 생산하고 runtime이 확정한 exact `DynamicReproductionRequest`, 같은 hypothesis/workspace/commit/generation의 R7 실행 work/attempt, image digest와 승인된 target/network/resource policy
- 출력: `EnvironmentRequirements`, 간단한 `ReproductionPlan`, `EnvironmentRecipe`, `poc_candidate_ref`, container lifecycle과 요구사항 비교를 담은 `SandboxEnvironment`, append-only `AgentLog`, `DynamicReproductionResult`, 성공 시 validated `poc_ref`, plan issue/limitation/cleanup/error

### 확인할 권한 경계

- sandbox는 evidence만 생산하며 verdict를 결정하지 않는다.
- R7은 R6 요청의 목적·가설·profile을 바꾸지 않지만 실행 가능한 requirements·간단한 plan·PoC candidate와 동적 해석을 만든다. plan은 mode나 exact command allowlist가 아니다.
- Runtime Validator는 `RUN_SANDBOX` 호출 권한·상태·예산·current request/requirements를 검사하고, Sandbox Controller는 host·Docker daemon/socket·mount/namespace·secret·egress·workspace·R8 resource/lifecycle 외부 경계를 전담한다.
- Setup Automation은 recipe·image·container·cleanup을 수행하고, R7 Agent는 Sandbox 안의 command·PoC·관찰·재시도를 자율적으로 정한다.
- Reproduction Session Manager는 AgentLog를 append-only로 저장하고 same-attempt reference만으로 validated PoC와 `DynamicReproductionResult`를 확정한다.
- R4는 request·requirements·plan·recipe·환경·AgentLog·candidate/validated PoC와 nullable reference·상태·result-owner 조합을 확정하고, R7은 실제 환경 구성·실행·관찰·정리 세부 절차를 정의한다.
- version fallback은 R7이 exact requirements에 미리 적은 `alternatives`만 허용하며, 요구사항·환경 기록에 credential·cookie·token·password 원문을 저장하지 않는다.
- host root/home, Docker socket, host process namespace, host secret, production credential와 범위 밖 target 접근을 금지한다.
- LLM 요청만으로 network/resource policy를 완화하지 않는다.

### 필수 교차 리뷰

- R6 검증·반박: request와 outcome/최종 verdict 경계, 실패 결과 소비
- R4 PM·아키텍처: producer authority·Session Manager·SAVE_RESULT 계약
- R8 데이터·평가: resource/time/retry budget 값과 지표
- R3 통합 개발: Docker Controller·recipe/image lifecycle·cleanup 구현 가능성
- R5 Gate·보고: AgentLog·validated PoC·evidence와 Reporter 소비·redaction

### 완료 조건

- [ ] ephemeral non-root/read-only 우선, CPU/memory/disk/process/time 제한이 기본값임
- [ ] network default-deny이며 예외 승인·scope·log가 정의됨
- [ ] image/build provenance, daemon isolation과 writable mount 정책 threat model이 있음
- [ ] R6 purpose와 R7 plan의 재현 목표·선택적인 requested evidence·실제 observable effect 연결이 명확함
- [ ] exact request/requirements/plan/recipe/action/work/attempt가 일치하고 내부 command는 AgentLog로 추적되며 Sandbox 외부 경계를 넘지 않음
- [ ] setup/execution/observation/policy/timeout failure와 반증이 다른 상태임
- [ ] 필수 환경 불일치는 R7 Agent가 recipe·환경을 보완해 같은 work에서 자율 retry하고, 외부 수정이 필요할 때만 `BLOCKED`, 복구 불가능하거나 한도를 소진하면 `FAILED`로 끝내며 final verdict를 만들지 않음
- [ ] 모든 requirement가 `SandboxEnvironment.checks`에 정확히 한 번 나타나고 차이·오류가 `failure_category`, 자유형 `failure_reason`, `plan_issues`와 일치함
- [ ] workspace/commit, recipe, container, command, input, observation과 cleanup이 AgentLog와 hypothesis에 추적됨
- [ ] Agent 미호출/호출, plan·recipe·환경 미생성/생성, cleanup 불필요/필요 조합이 R4 nullable reference 계약과 일치함
- [ ] PoC candidate와 `SUCCEEDED + SUPPORTED`일 때만 생기는 validated PoC, Controller 정책 판정, 환경과 AgentLog의 R7 상세 artifact schema가 정의됨
- [ ] escape/socket/secret/out-of-scope network negative scenario가 있음

---

## R8 — 평가 코퍼스·품질/관측 지표·자원 예산

- 실제 Issue: [#9](https://github.com/SASTsimi/sastsimi/issues/9)

### 쉽게 말하면

각 Agent와 분석 단계가 실제로 잘 동작하는지 같은 평가 데이터로 비교할 기준을 만든다. 각 전문 역할이 제공한 최소 품질·실행 요구와 함께 시간, 비용, 호출, 재시도, chaining과 sandbox 예산 profile을 정하고 token 사용량은 관측한다. 실제 action 허용·차단은 R4 trusted runtime이 담당하지만 token 계획값 초과·누락만으로 차단하지 않는다.

### 담당자가 나눌 수 있는 하위 Issue 예시

- `[R8-01] 평가에 사용할 취약점·오류 예제 모음 확정`
- `[R8-02] 역할별 품질·오류·비용 지표 확정`
- `[R8-03] 시간·비용·호출·재시도·연계 탐색 한도와 token 관측 기준 확정`
- `[R8-04] 변경 전후를 같은 조건으로 비교하는 절차 확정`

### 역할 소유권

- 담당 역할: 데이터·평가·예산
- 담당자: 성병찬 `@gitterable`
- 주요 작업 브랜치: `review/data-evaluation`
- 관련 흐름: 전문 역할의 최소 품질·실행 요구 수집 → 실행 기록과 품질·비용 평가 → 예산 profile 제안 → R4 runtime 강제 → 같은 corpus로 회귀 비교

### 검토 문서

- `07-results-and-observability.md`
- `09-llm-provider-session-and-logging.md`의 usage/evaluation
- `04`, `06`, `08`의 metric/budget 항목
- 각 역할의 정량 limit은 해당 owner와 공동 검토

### 검토할 입력·출력

- 입력: provenance-known/redacted corpus, logs, role/provider/model/session config, human reference label
- 출력: versioned scenario matrix, metric definition, budget profile, comparison plan, regression threshold

### 확인할 권한 경계

- metric과 오프라인 사람 정답은 verdict·Gate·자동화 상태를 대신하지 않는다.
- R8은 budget profile과 합격 기준을 설계하지만 action 예산을 직접 허용·차단하지 않는다. R4 trusted runtime이 승인된 profile을 강제한다.
- 전문 역할의 최소 품질·실행 요구 없이 예산만 줄여 debate·동적 재현·Gate 의미를 바꾸지 않는다.
- unavailable usage를 추정 확정값으로 표시하지 않는다.
- 평가 없이 session reuse, debate 생략 또는 model/provider 변경을 정당화하지 않는다.
- credential, raw session secret와 hidden chain-of-thought를 수집하지 않는다.

### 필수 교차 리뷰

- PM: budget enforcement/state 의미
- LLM 탐색·검증·Gate: 단계별 품질 기준
- 통합 개발: instrumentation 가능성
- 개인정보/학습 범위가 생기면 별도 보안·법무 검토

### 완료 조건

- [ ] corpus가 TRUE/FALSE/HOLD, gap, conflicting evidence, Verification-origin child, Chaining-origin child, policy absence, sandbox failure를 포함함
- [ ] schema validity/repair, retrieval gap/`WORKSPACE_MISMATCH`, debate 전후 품질, required candidate가 있는 HOLD의 chaining과 빈 candidate HOLD의 무작업 종료, Technical-accepted + current `PrimitiveAdmissionDecision=ALLOW` TRUE admission과 전역 예산에 따른 chaining 중단을 측정함
- [ ] conditional debate, 독립 session, 두 Gate와 provider/model 선택에 acceptance threshold가 있음
- [ ] adversarial prompt-injection, contradictory Gate, redaction failure case가 있음
- [ ] role별 time/cost/call/retry/chain/sandbox budget과 `BUDGET_EXCEEDED` 의미가 있고 token은 비차단 관측값으로 구분됨
- [ ] config 변경은 `AnalysisRunResult.eval_config_refs`의 exact versioned reference set과 동일 corpus 비교를 요구함
- [ ] training 활용은 별도 ADR/data lineage/license/redaction 없이는 범위 밖임

---

## Final — 전체 교차 시나리오·Freeze SHA·승인 검토

- 실제 Issue: [#10](https://github.com/SASTsimi/sastsimi/issues/10)

### 쉽게 말하면

각 파트 문서를 따로 읽는 데서 끝내지 않고 실제 분석 한 건이 처음부터 마지막까지 모순 없이 흐르는지 팀 전체가 확인한다. 각 파트가 서로 교차 검토하고, 검토할 commit을 고정한 뒤 최종 검토·승인 담당자가 최신 상태를 확인해야 최종 승인 PR로 넘어갈 수 있다.

### 역할 소유권

- 담당 역할: 최종 검토·승인 담당자
- GitHub 담당자: 김태현 `@taehyeon-git`
- 필수 참여자: `@baeseungwon1010`, `@zv9uvr`, `@taehyeon-git`, `@YHS-Sec`, `@kimhr8463`, `@UltraPeachKeen`, `@Potatonion`, `@gitterable`
- 전제: R1–R8 완료, 열린 Blocker/High 0, 최종 승인 PR에 freeze SHA 게시

### 필수 시나리오

| 시나리오 | 기대 상태와 금지 동작 |
|---|---|
| 정상 TRUE | `initial TRUE → R7 PoC 실행 성공 → validated PoC가 있는 final TRUE → Technical ACCEPT → Gate2 PASS/PASS/SUFFICIENT/ALLOW → ReportDraft → AnalysisRunResult → Agent 자동화 종료` |
| 정책 없는 TRUE | Gate2 `UNCERTAIN + DENY`; Reporter 미호출 |
| schema repair 실패 | `INVALID_OUTPUT`; Verification 미할당 |
| empty/truncated context | gap 또는 HOLD 가능; 자동 FALSE 금지 |
| workspace 또는 commit 불일치 | context/dynamic evidence 폐기와 `WORKSPACE_MISMATCH` 기록 |
| 상충 Pro/Con | 독립 NEW session과 근거 기반 verdict/HOLD |
| PoC 생성·sandbox setup·실행 실패 | 자체 해결 가능하면 같은 work 자동 retry, 외부 조건 대기만 `BLOCKED`, 복구 불가능·한도 소진은 verdict 없는 `FAILED`; vulnerability FALSE/HOLD와 Gate 금지 |
| 동적 재현 요청·계획 생성 | R6가 purpose·goal·needs를 요청하고 R7 Agent가 exact requirements와 mode·exact command가 없는 간단한 plan을 만든 뒤 runtime이 generation당 단일 work와 RUN_SANDBOX 외부 경계 입력을 검사 |
| 동적 재현 실행·반환 | Controller 외부 경계 허용 뒤 Setup Automation이 환경을 만들고 R7 Agent가 PoC candidate·command·관찰·재시도를 자율 선택; Session Manager가 same-attempt AgentLog·validated PoC·동적 결과를 확정하고 R6가 최종 판정 |
| 동적 plan·candidate 변경과 stale 실행 | 같은 attempt의 변경은 새 불변 revision과 AgentLog에 남기고 최종 결과가 exact revision을 가리켜야 함. request·requirements·profile·resource/lifecycle 또는 attempt가 바뀌면 기존 action/result를 재사용하지 않고 새 RUN_SANDBOX action 필요 |
| HOLD + non-empty `required_primitive_candidates` | Gate 없이 전체 후보를 `inputs`, `result=null`로 둔 Primitive 저장과 Chaining 조회 |
| HOLD + `required_primitive_candidates=[]` | Primitive를 저장하지 않고 Chaining work도 만들지 않은 채 HOLD 처리 종료 |
| FALSE | terminal internal result; Primitive/Chaining 금지 |
| Gate 전 TRUE | result Primitive admission과 Chaining 금지 |
| Technical ACCEPT만 받은 TRUE | 정책 수집·Rule Scope의 금지 테스트 판정과 `PrimitiveAdmissionDecision`이 끝날 때까지 result Primitive·Chaining·Reporter 금지 |
| Verification 새 claim | `origin=VERIFICATION` child hypothesis로 8단계부터 재검증; parent 불변 |
| TRUE result→HOLD input | upstream TRUE가 exact Technical-accepted·admission-allowed이고 그 result가 HOLD Primitive의 특정 input을 충족할 때만 `origin=CHAINING` child 생성 |
| TRUE result→TRUE input | upstream result와 downstream TRUE Primitive의 특정 input이 근거로 연결될 때만 새 chain hypothesis 생성 |
| stale Gate/admission revision | 새 Verification revision에 과거 Gate·Primitive admission 자격 재사용 금지 |
| Primitive scope 불일치 | match 거절/후보 유지 |
| chain budget/reuse | R8 전역 예산 중단 또는 ancestor 재사용 제외; FALSE 금지 |
| Technical REVISE | 같은 ACTIVE VerificationAssignment owner의 새 VERIFICATION work로 직접 반환; 새 evidence/revision 전 result Primitive·Rule Scope·Reporter 차단 |
| Chaining 시작 뒤 parent/index 새 revision 생성 | 진행 중인 work는 시작 시 고정한 exact reference로 계속 처리; 새 revision은 새 Chaining work에서 사용하고, 고정하지 않은 reference가 기존 결과에 섞인 경우만 `STALE_RESULT` 처리 |
| 실제 match가 사용한 admission decision 변경 | direct·ancestor `source_admission_refs` 중 하나가 오래됐거나 `DENY`이면 진행 결과·새 child 사용 차단; 이미 저장된 파생 결과는 감사 이력으로만 보존 |
| Chaining의 일반 research 출력 | invalid output; bypass·impact·dynamic·Gate 보완은 Verification 책임 |
| 모순된 ALLOW | semantic invalid; Reporter 차단 |
| provider auth/rate-limit | explicit attempt/fallback; silent failover/FALSE 금지 |
| AST/SAST 일부 실패 | gap 포함 PARTIAL 가능 |
| clone 또는 checkout 실패 | 분석 `FAILED`; AST/SAST 미실행 |
| 분석 중 코드 변경 | `WORKSPACE_CHANGED`; 변경 뒤 결과 사용 금지 |
| repository prompt injection | provider/session/Gate/Sandbox와 Agent 자동화 종료 경계 불변 |
| secret/redaction 실패 | 일반 log/report 전달 차단 |
| 자동화 종료 뒤 후속 과정 | Agent는 검토·수정·제출·공개 action을 생성하지 않음 |

### 완료 조건

- [ ] 번호 문서, root/v5 README, Wiki와 Mermaid의 22단계 의미와 자동화 종료 지점이 일치함
- [ ] 모든 핵심 claim을 원본 artifact와 decision PR에 추적 가능함
- [ ] `FINDINGS.md`의 Blocker/High가 0이고 Medium deferral이 적절함
- [ ] freeze SHA 이후 unreviewed commit이 없음
- [ ] R1–R8 담당자의 교차 검토와 김태현 `@taehyeon-git`의 최신 확인 기록이 있음
- [ ] 상태 변경은 별도 승인 PR로 수행함

## 역할별 의존 관계

```text
R8 평가/예산 기준 ─┐
                    ├─> R4 중앙 계약·runtime enforcement
R4 ─────────────────┼─> R2 workspace/static/context
R2 + R4 + R8 ───────┴─> R1-A Hypothesis
R1-A + R2 + R4 + R8 ──> R6 Verification
R6 DynamicReproductionRequest + R4 runtime + R8 budget ─> R7 requirements/simple plan, external boundary, autonomous Sandbox reproduction and AgentLog
R7 COMMITTED dynamic result ──────────────────> R6 final Verification
R6 final Verification ─────────────────────────> R5 Technical/Rule Scope Gate
R6 HOLD + required candidate 있음 ───────────────> R1-B Primitive Chaining
R6 HOLD + required candidate 없음 ──────────────> Primitive·Chaining 없이 종료
R6 + R7 + R1-B + R4 + R5 ─> ReportDraft·AnalysisRunResult·Agent 자동화 종료
R3는 모든 계약의 구현 가능성과 종단 조립을 교차 검토
R1–R8 완료 ───────────> Final cross-scenario review
```
