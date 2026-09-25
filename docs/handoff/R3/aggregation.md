# R1-R8 인계 자료 종합 현황

검토일: 2026-09-10  
검토 기준 `main`: `b3b2d9918ea815b9b936c09c98e4c53fd54937dc`

## 종합 방식

다른 역할의 원본 prompt·sample을 `R3/`에 복사하지 않습니다. 각 역할의 `docs/handoff/R번호/`를 정본 위치로 유지하고, R3는 PR·검토 SHA·자료 목록·공통 계약 판정과 남은 수정만 이 문서에 종합합니다.

## 현재 제출 현황

| 역할 | 담당 자료 | 현재 확인된 제출 | R3 종합 상태 |
|---|---|---|---|
| R1 | Hypothesis·Chaining | [PR #141](https://github.com/SASTsimi/sastsimi/pull/141) | 검토 대기 |
| R2 | StaticFactBundle·CodeContext·정적 도구 | [PR #138](https://github.com/SASTsimi/sastsimi/pull/138) | 검토 대기 |
| R3 | 공통 형식·파일/version·통합 오류 사례 | 이 폴더 | 초안 준비 완료 |
| R4 | 공통 contract·state·authority | 아직 열린 handoff PR 확인 안 됨 | 제출 대기 |
| R5 | CWE·두 Gate·Reporter | [PR #140](https://github.com/SASTsimi/sastsimi/pull/140) | 검토 대기 |
| R6 | Pro·Con·Verification | 아직 열린 handoff PR 확인 안 됨 | 제출 대기 |
| R7 | Dynamic Reproduction·Sandbox | 아직 열린 handoff PR 확인 안 됨 | 제출 대기 |
| R8 | 평가 목록·채점·품질·시간·비용 | 아직 열린 handoff PR 확인 안 됨 | 제출 대기 |

## 역할별 검토 기록 형식

```text
역할:
PR:
검토한 HEAD SHA:
파일 목록:
정상 fixture:
실패 fixture:
공통 계약 판정: READY | CHANGES_REQUESTED | WAITING
수정 요청:
다음 소비 역할의 검토 기록:
```

## 최종 인계 조건

- [ ] R1~R8 폴더가 모두 존재하거나 비-LLM이라 prompt가 불필요한 이유가 기록됨
- [ ] 각 LLM Agent의 prompt owner가 명확함
- [ ] 정상·실패 입력과 기대 결과가 쌍으로 존재함
- [ ] R3 공통 검토표를 모두 통과함
- [ ] 다음 소비 역할의 교차 검토 기록이 있음
- [ ] 미결정 사항에 담당자와 안전한 기본 동작이 있음
- [ ] 실제 구현 전 자료를 구현 완료라고 표현하지 않음

