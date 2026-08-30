# Architecture v5 설계 결정 기록

이 문서는 전체 흐름, 데이터 형식, 역할 권한이나 안전 규칙에 영향을 주는 중요한 설계 결정을 기록합니다. 중요한 결정(`material decision`)은 GitHub Issue에서 선택지와 영향을 논의하고, 한 가지 결정에 집중한 브랜치와 PR로 번호 문서에 반영합니다. 아래 목록에는 검토 중인 제안과 병합이 끝난 결정을 상태와 함께 기록합니다.

## 언제 기록해야 하나요?

- 둘 이상의 역할이 같은 데이터나 상태를 다르게 이해할 때
- LLM, 프로그램 또는 사람의 권한 경계를 바꿀 때
- Docker, 비밀정보, 공식 정책이나 외부 공개의 안전 규칙을 바꿀 때
- 비용·정확도·운영 방식 사이에서 한 가지 방법을 선택할 때
- 이전 설계 결정을 바꾸거나 폐기할 때

## 결정 상태

- `PROPOSED`: 선택지와 영향을 검토 중
- `ACCEPTED`: 반드시 필요한 검토자가 승인하고 문서 PR이 병합됨
- `REJECTED`: 근거와 함께 채택하지 않음
- `DEFERRED`: 담당자, 사유와 다시 검토할 시점을 정하고 미룸
- `SUPERSEDED`: 새 결정이 이전 결정을 대체함

## 필수 기록 항목

- ID와 제목
- 현재 상황(`Context`)과 문제
- 고려한 선택지(`Options`)
- 보안·품질·비용·운영의 장단점(`trade-off`)
- 결정 담당자와 반드시 필요한 검토자
- 최종 결과(`Outcome`)와 근거
- 영향을 받은 분석 단계·입출력 약속·문서
- 결정 Issue, PR와 commit SHA
- 후속 검증 또는 재검토 조건

## 결정 목록

| ID | 제목 | 상태 | Issue | 반영 PR/commit |
|---|---|---|---|---|
| [ADR-001](./ADR-001-verification-owned-chaining-admission.md) | Verification 중심 제어권과 Gate-qualified Chaining | PROPOSED | #1, #2, #4–#7, #9, #10 | `review/verification-owned-chaining-flow` |
