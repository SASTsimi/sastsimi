# 정본 23단계 파이프라인

## 쉽게 말하면

저장소를 로컬에 clone하고 분석할 commit을 checkout해 코드 사실을 모은 뒤, 가설별 검증·재현·연계 탐색과 근거·공식 정책 검토를 거쳐 사람에게 전달하는 전체 순서입니다.

**상세 기준:** [01. 시스템 개요](../01-system-overview.md)

아래 목록은 데이터 형식과 구현 순서를 맞추기 위해 정확한 이름을 사용합니다. 뜻은 [쉬운 용어집](../../GLOSSARY.md)에서 확인하세요.

1. 저장소 입력
2. `Repository Loader`가 `git clone`과 `commit_id` checkout으로 `CodeWorkspace` 준비
3. AST parse와 SAST 도구 병렬 실행
4. `StaticFactBundle` 생성
5. Orchestration Agent 시작
6. 저비용 Hypothesis Agent 호출
7. schema-valid `HypothesisProposal[]` 생성
8. 가설별 Verification Agent 할당
9. 코드 위치 기반 on-demand retrieval
10. `BASIC` 또는 조건부 Pro/Con 검증
11. initial `TRUE | FALSE | HOLD`
12. 필요 시 Docker `LIMITED_REPRO | FULL_REPRO`
13. final `TRUE | FALSE | HOLD`
14. `TRUE`의 PROVIDED 또는 `HOLD`의 REQUIRED Primitive DB 갱신
15. `TRUE | HOLD`, Technical revision 또는 Primitive match 조건에서 Research Agent의 bypass·impact·chain 탐색
16. 새 주장을 `VulnerabilityHypothesis`로 Orchestration Agent에 반환
17. CWE labeling
18. Technical Evidence Gate Agent 검토
19. Technical `ACCEPT`인 `TRUE`에 Rule Scope Impact Gate Agent 검토
20. 모든 전달 조건을 만족한 결과에 Reporter Agent 호출
21. 결과·자원·LLM log·PoC·오류·debug 정보 저장
22. 모든 초기·파생·체이닝 가설에 반복
23. 사람이 최종 검토 및 공개 여부 결정

Technical Gate의 `REVISE`는 Verification 또는 Research로 돌아갈 수 있다. Research의 material claim은 16단계에서 새 가설이 되며 기존 verdict에 직접 합쳐지지 않는다. 독립 가설은 예산 범위에서 병렬 처리할 수 있다.

상세 책임과 종료 조건은 [시스템 개요](../01-system-overview.md)를 따른다.
