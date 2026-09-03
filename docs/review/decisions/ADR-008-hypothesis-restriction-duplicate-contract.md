# ADR-008. 가설 restriction 근거와 중복 판정 lifecycle

- 상태: `ACCEPTED`
- 결정일: 2026-09-04
- 결정 담당: R4 PM·아키텍처·공통 계약
- 필수 확인 역할: R1 LLM 탐색·체이닝, R2 정적분석·컨텍스트, R3 통합 개발, R6 검증·반박, R8 데이터·평가·예산
- 연결 검토: PR #81

## 쉽게 설명하면

공격 제한 조건을 문장만으로 저장하면 어떤 코드 근거에서 나온 조건인지 잃어버립니다. 또한 “기존 가설과 같은가”를 LLM이 판단하더라도 비교 대상과 실패 처리가 정해져 있지 않으면 새 취약점을 실수로 버릴 수 있습니다. 그래서 제한 조건의 근거와 중복 판정의 시작·종료를 공통 계약으로 고정합니다.

## 결정

1. restriction은 문자열이 아니라 `restriction_id`, 설명과 exact 코드·검증 근거를 가진 `Restriction` 객체로 저장합니다.
2. `CodeFactRef`는 final `StaticFactBundle`의 exact revision과 그 안의 `fact_id`를 함께 가리킵니다.
3. 같은 코드 사실을 `HypothesisProposal.observed_facts`와 restriction 근거 양쪽에 중복 분류하지 않습니다.
4. Verification, Primitive, Chaining과 ReportDraft는 `restriction_id`와 전체 객체를 그대로 보존합니다.
5. trusted runtime은 같은 analysis·workspace·commit에서 symbol·location·relation이 겹치는 기존 등록 가설만 중복 비교 후보로 좁힙니다.
6. 후보가 있으면 Hypothesis Agent가 exact proposal과 후보 reference를 받아 `HypothesisDuplicateReview`를 만듭니다.
7. `DUPLICATE`는 후보 목록 안의 exact 기존 가설을 지목할 때만 새 가설 등록을 막습니다.
8. `UNIQUE | UNCERTAIN`, 호출 실패, 형식 오류와 유효하지 않은 중복 대상은 기록을 보존한 뒤 fail-open 등록합니다.
9. Hypothesis confidence는 가설 선별·검증 순서·판정 계약으로 사용하지 않으며 등록 가설은 전수 검증합니다.

## 권한과 저장

- HYPOTHESIS 역할만 `HypothesisDuplicateReview`를 생산합니다.
- Runtime Validator가 후보 집합, LLM 호출, proposal과 기존 가설의 exact revision을 검사합니다.
- Orchestration은 후보 조회와 등록을 제안하지만 중복 review 내용을 생성하거나 바꾸지 않습니다.
- `ProposalProcessState.status=DUPLICATE`이면 새 `hypothesis_id`와 `HypothesisProcessState`를 만들지 않습니다.
- fail-open 등록 사유는 `UNCERTAIN | CHECK_FAILED | INVALID_DUPLICATE_TARGET` 중 실제 값으로 남깁니다.

## 호환성

문자열 restriction 제거, duplicate state·record 추가와 confidence 계약 제거는 의미가 바뀌는 변경입니다. 관련 `HypothesisProposal`, `ProposalProcessState`, `VerificationResult`, `Primitive`, `ReportDraft`와 Chaining 결과를 새 MAJOR schema로 배포합니다. 이전 문자열 restriction에 근거를 추정해 붙이거나 이전 confidence를 새 판정 입력으로 자동 변환하지 않습니다.

## 검증 조건

- 근거 없는 restriction 저장 차단
- observed fact와 restriction fact의 중복 분류 차단
- 다른 workspace·commit이나 오래된 bundle·가설 reference 차단
- 후보 밖 `DUPLICATE` 대상이 새 가설을 삭제하지 못함
- 중복 LLM 오류·불확실성이 취약점 누락으로 바뀌지 않음
- 정본, Wiki, Mermaid, governance와 validator가 같은 의미를 설명함
