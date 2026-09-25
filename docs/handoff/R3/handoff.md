# R3 공통 프롬프트·구현 검증 자료 인계

## 담당 범위

R3는 모든 역할이 만든 프롬프트와 샘플을 같은 방식으로 실제 모듈에 연결할 수 있도록 다음을 담당합니다.

1. 공통 프롬프트 작성 골격
2. template·registry·schema·validator의 파일·version 관리 기준
3. 각 파트의 입력 slot과 출력 result kind 검토
4. 형식 오류·필수값 누락·시간 초과 처리 기준
5. R1~R8 제출 현황과 공통 계약 검토 결과 종합

R3의 Orchestration Runtime, Runtime Validator, Prompt Registry Runtime과 Prompt Builder는 비-LLM입니다. 따라서 R3 전용 전문 Agent prompt를 새로 만들지 않고 `prompt.md`에 각 전문 Agent 담당자가 사용할 공통 골격을 제공합니다.

## 기준 문서

- [R3-05 Agent 프롬프트 등록·조립·전달 구조](../../architecture-v5/implementation/05-prompt-runtime.md)
- [R3-06 구현 기준선](../../architecture-v5/implementation/06-implementation-baseline.md)
- [08 경량 데이터 계약](../../architecture-v5/08-lightweight-data-contracts.md)
- [09 Provider·session·logging](../../architecture-v5/09-llm-provider-session-and-logging.md)
- [10 보안 경계](../../architecture-v5/10-security-boundaries.md)

검토 기준 `main`은 `b3b2d9918ea815b9b936c09c98e4c53fd54937dc`다.

## 파일 목록

| 파일 | 설명 |
|---|---|
| [`prompt.md`](./prompt.md) | 각 전문 Agent 담당자가 채우는 공통 프롬프트 골격 |
| [`normal.input.json`](./normal.input.json) | 정상 입력 조립 합성 fixture |
| [`normal.expected.json`](./normal.expected.json) | 정상 입력의 기대 검사 결과 |
| [`failure.input.json`](./failure.input.json) | 형식 오류·누락·timeout 합성 fixture |
| [`failure.expected.json`](./failure.expected.json) | 실패 사례의 기대 차단·상태 처리 |
| [`review-checklist.md`](./review-checklist.md) | 각 역할 자료를 검토하는 R3 공통 표 |
| [`aggregation.md`](./aggregation.md) | R1~R8 PR·SHA·검토 상태 종합표 |

JSON 자료는 실제 운영 결과가 아니라 Architecture v5에서 만든 **합성 검토 fixture**입니다.

## 파일·version 기준

최종 운영 후보 prompt는 다음 위치로 옮길 수 있어야 합니다.

```text
config/prompts/templates/<role>/<task>/<semver>.md
```

- UTF-8 Markdown이고 첫 version은 `1.0.0`입니다.
- 병합된 파일을 덮어쓰지 않고 변경 시 새 version과 content hash를 만듭니다.
- 실행본은 파일명만 믿지 않고 exact `StoredDataRef(record_id + content_hash)`로 고정합니다.
- 특정 모델·Provider·API key·host 경로는 prompt 본문에 넣지 않습니다.
- Registry·입력 allowlist·출력 schema·semantic validator를 함께 검토합니다.
- R8 평가와 사람 승인 전에는 `PRODUCTION + ACTIVE`로 전환하지 않습니다.

## 정상·실패 사례

### 정상

같은 workspace와 commit의 `StaticFactBundle`을 `UNTRUSTED_DATA`로 넣고, 허용된 field만 조립하면 Provider 호출 전 검사를 통과합니다.

### 형식 오류

닫힌 enum에 없는 값, SHA-256이 아닌 hash, 허용되지 않은 field, untrusted 입력의 instruction 승격은 Provider 호출 전에 차단합니다.

### 필수값 누락

REQUIRED 입력이 없으면 빈 정상 결과를 만들지 않고 호출을 차단합니다. 입력 누락과 분석 결과 0건을 구분합니다.

### 시간 초과

Provider가 제한 시간을 넘기면 `TIMED_OUT`을 기록하고 domain output을 저장하지 않습니다. retry는 새 call·action·decision·attempt로 수행하며 timeout을 `FALSE | HOLD`로 바꾸지 않습니다.

## R3 종합 절차

```text
각 역할이 docs/handoff/R번호/에 PR 생성
→ R3가 파일 목록과 PR HEAD SHA 고정
→ JSON 파싱·필수 파일 검사
→ Prompt Registry task 행과 slot·result kind 대조
→ 정상·실패 기대 결과와 권한·revision·timeout 검사
→ 다음 소비 역할의 교차 검토 확인
→ aggregation.md에 READY 또는 수정 요청 기록
→ 모든 역할 자료를 하나의 인계 목록으로 전달
```

## 현재 상태

- R1: PR #141 제출, 검토 대기
- R2: PR #138 제출, 검토 대기
- R5: PR #140 제출, 검토 대기
- R4·R6·R7·R8: 2026-09-10 확인 시 열린 handoff PR 없음
- R3: 공통 골격·정상·실패 fixture·검토표·종합표 준비 완료

## 아직 구현되지 않은 부분

이 자료는 구현 인계 문서입니다. 실제 `src/sastsimi/prompts/`, `src/sastsimi/agents/`, `config/prompts/` 구현과 11개 Agent prompt의 운영 활성화를 완료했다는 뜻이 아닙니다. 각 역할 자료가 병합되고 계약 검토가 끝난 뒤 Prompt Registry·Builder와 자동 시험에 연결해야 합니다.

