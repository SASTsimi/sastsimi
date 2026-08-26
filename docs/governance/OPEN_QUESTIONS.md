# Architecture v5 미결정 사항

이 문서는 현재 열린 질문의 색인입니다. 실제 토론·owner·기한·결정은 GitHub Issue에서 관리하고, 결정된 결과는 관련 정본 문서와 PR에 반영합니다.

## Blocker

1. 팀 역할과 GitHub username 매핑
   - 필요한 결정: 8개 역할 owner, 대체 reviewer, independent final reviewer
   - 현재 owner: `@taehyeon-git`이 계정 목록 수집
   - 제약: 확정 전 CODEOWNERS 및 실제 assignee 자동화 불가

## 구현 전 필수 결정

1. 역할별 provider/model profile과 공식 지원 범위
2. Membership/API credential와 session 저장 경계
3. `NEW | RESUME | AUTO` 평가 방법과 기본 limit
4. Hypothesis schema repair 횟수와 confidence 평가 기준
5. Context retrieval depth/token/request 제한
6. CONDITIONAL_DEBATE trigger와 비용·정확도 비교 corpus
7. Primitive vocabulary와 scope/capability matching 규칙
8. Research/chain depth·count·token·time·duplicate 제한
9. Docker image, network, resource와 cleanup 정책
10. ProgramPolicySnapshot 공식 source 수집·freshness·실패 처리
11. 두 Gate prompt, revision limit와 평가 dataset
12. LLM logging proxy/parser, redaction, retention과 접근통제
13. serialization, schema versioning과 result storage

## 결정 기록 형식

각 결정 Issue는 다음을 포함합니다.

- Context
- 선택 가능한 Options
- Security/quality/cost trade-off
- Decision owner
- Required reviewers
- Target date
- Outcome
- 반영한 PR/commit
