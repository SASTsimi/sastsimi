# R4 PR #81 공통 계약 보완 설계

## 목표

PR #81의 가설 생성 계약을 현재 `main`과 합치고, R4 최종 리뷰에서 남은 제약 근거 추적·중복 가설 판정 lifecycle·`confidence` 제거를 공통 계약으로 확정한다.

## 확정 결정

### 1. 제약은 근거를 가진 구조로 저장한다

`Restriction`은 단순 문자열이 아니다. 사람이 읽는 `statement`, 정확한 정적 사실을 찾는 `CodeFactRef`, 그 밖의 검증 근거를 찾는 `evidence_refs`를 함께 가진다.

- `CodeFactRef.bundle_ref`는 exact `StaticFactBundle` revision을 가리킨다.
- `CodeFactRef.fact_id`는 그 bundle 안의 `CodeFact.fact_id` 하나를 가리킨다.
- 각 restriction에는 `fact_refs` 또는 `evidence_refs`가 하나 이상 있어야 한다.
- 가설 proposal에서 같은 CodeFact를 `observed_facts`와 `restrictions[].fact_refs`에 동시에 넣지 않는다.
- `restriction_id`와 내용·근거를 바꾸면 새 restriction으로 취급한다. Verification·Primitive·Chaining·ReportDraft로 승계할 때는 구조 전체를 보존한다.

### 2. 중복 판정은 별도 LLM 결과와 proposal 상태로 추적한다

schema-valid proposal이 만들어지면 trusted runtime이 같은 분석·workspace·commit의 등록 가설 중 `symbol_id`, 겹치는 `CodeLocation`, `relation_id`로 비교 후보를 좁힌다.

- 후보가 없으면 LLM 호출 없이 새 가설을 등록한다.
- 후보가 있으면 exact proposal과 exact 기존 가설 refs를 새 `HYPOTHESIS` 역할 `CALL_LLM` 입력으로 고정한다.
- 성공한 출력은 `HypothesisDuplicateReview`로 저장한다.
- `DUPLICATE`는 실제 등록 가설 exact ref가 있을 때만 허용하며 proposal을 새 가설로 등록하지 않는다.
- `UNIQUE | UNCERTAIN`, 호출 실패, invalid output 또는 잘못된 duplicate target은 미탐 방지를 위해 신규 등록한다. 실패·fallback 이유는 proposal 상태와 LLM/error 기록으로 남긴다.

### 3. 가설의 `missing_information`과 `confidence`를 제거한다

- 관측된 사실은 `observed_facts`, 관측된 공격 제한은 `restrictions`, 관측되지 않았지만 가설이 의존하는 조건은 `assumptions`에 둔다.
- 가설이 의존하지 않는 공백은 가설에 넣지 않는다. 정적 도구가 보지 못한 범위는 `StaticFactBundle.gaps`의 `DataGap`으로 구분한다.
- 모든 등록 가설은 전수 검증한다. 가설 단계의 `confidence`로 선별하거나 순서를 매기지 않는다.
- `confidence`를 가리키던 정본·Wiki·평가·구현 전 질문 문구를 제거한다.

### 4. 가설 생성 순서를 고정한다

가설 생성 work는 `STATIC_NORMALIZE`가 최종 `SUCCEEDED | PARTIAL` 상태에 도달한 뒤에만 시작한다. PARTIAL이면 exact final bundle과 gaps를 함께 입력으로 사용한다.

## 호환성

`HypothesisProposal`, `ProposalProcessState`, `VerificationResult`, `Primitive`, `ReportDraft`와 관련 결과 registry는 새 MAJOR schema다. 이전 MAJOR의 문자열 restriction, `missing_information`, `confidence` 또는 중복 판정 부재를 자동 추정·변환하지 않는다.

## 역할 경계

- R1은 가설과 중복 판단의 의미를 제안한다.
- R2는 exact `StaticFactBundle`과 `CodeFact`를 생산한다.
- R4는 공통 구조, exact reference, 상태, 실패 fallback과 Runtime Validator 검사를 정의한다.
- R6는 restriction을 검증 결과에서 갱신하고 최종 판정과 함께 보존한다.
- R5는 Gate와 ReportDraft에서 exact restriction을 검토·보존한다.
- R8은 전수 검증과 중복 판정 호출에 공통 예산을 적용한다.
