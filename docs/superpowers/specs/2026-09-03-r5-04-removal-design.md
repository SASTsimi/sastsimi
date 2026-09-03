# R5-04 제거와 Agent 자동화 종료 경계 설계

**상태:** 승인됨  
**적용 대상:** Architecture v5 정본, Wiki, Mermaid, R4 공통 계약, Governance, Review 안내  
**결정일:** 2026-09-03

## 결정

R5 Agent 자동화는 R5-03 Reporter가 `ReportDraft`를 생성하는 지점에서 끝난다. 신뢰할 수 있는 runtime은 생성된 결과와 로그를 `AnalysisRunResult`에 확정한 뒤 실행을 종료한다. 그 이후의 검토, 문서 수정, 제출과 공개는 Agent 자동화 밖에서 사람이 수행한다.

다음 Human Review 자동화 계약은 현재 설계에서 제거한다.

- `HumanReviewPacket`, `HumanReviewState`, `HumanReviewDecision`
- `PREPARE_HUMAN_REVIEW`, `SAVE_HUMAN_DECISION`, `EXTERNAL_DISCLOSURE`
- `PACKET_READY`, `DECIDED`, `DISCLOSE`, `WITHHOLD`, `NEED_MORE_VALIDATION`, `DISCLOSURE_DENIED`
- Human Reviewer를 자동 action 요청자로 취급하는 권한과 lifecycle

## 최종 자동화 흐름

`Verification -> Technical Evidence Gate -> Rule Scope Impact Gate -> R5-03 Reporter -> ReportDraft -> AnalysisRunResult 확정 -> Agent 자동화 종료`

`ReportDraft`는 마지막 Agent 산출물이다. `AnalysisRunResult` 확정은 새로운 Agent 판단이 아니라 이미 생성된 결과와 관측 기록을 묶는 신뢰 runtime 작업이다.

## ReportDraft 안전 요구사항

R5-04에 있던 다음 요구사항은 R5-03 Reporter와 `CREATE_REPORT_DRAFT` 검증 경계로 이동한다.

- 출처 추적: 정확한 `VerificationResult`, CWE, 두 Gate, 정책과 Finding 수정본을 참조한다.
- 오래된 참조 차단: 선행 결과가 바뀌면 기존 초안을 current 결과로 재사용하지 않는다.
- 제한 보존: Verification의 restriction, limitation, 남은 불확실성을 초안에서 숨기지 않는다.
- 민감정보 제거: 저장 전에 redaction 검사를 통과해야 한다.
- 권한 제한: Reporter는 새 취약점 사실을 만들거나 외부 제출·공개를 수행하지 않는다.

## 사람 주도 후속 과정

사람은 자동화가 끝난 뒤 `AnalysisRunResult`와 current `ReportDraft`를 참고할 수 있다. 검토 방식, 수정본 형식, 승인 상태, 제출 대상과 공개 결정은 현재 Agent 공통 계약으로 표현하지 않는다. 따라서 자동화 안에는 사람 승인 상태, 공개 action 또는 공개 허용 판단이 존재하지 않는다.

## 유지하는 계약

이번 변경은 다음 계약을 수정하지 않는다.

- PROVIDED Primitive와 Chaining
- exact revision과 `StoredDataRef`
- `ActionRequest -> Runtime Validator -> ActionDecision`
- Verification 중심 제어권과 두 LLM Gate 순서
- Docker Sandbox와 동적 재현 계약
- 상태, 재시도, 복구와 관측성 계약

## 이전 설계 기록 처리

과거 spec과 plan은 당시 결정을 보여 주는 감사 기록이므로 본문을 소급 변경하지 않는다. 대신 현재 설계가 이 문서로 대체됐음을 각 기록 상단에 표시한다. 구현 기준은 Architecture v5 정본과 현재 문서다.

