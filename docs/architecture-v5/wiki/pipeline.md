# 정본 22단계 파이프라인

## 쉽게 말하면

저장소를 로컬에 clone하고 분석할 commit을 checkout해 코드 사실을 모은 뒤, 가설별 검증·재현·연계 탐색과 근거·공식 정책 검토를 거쳐 Agent 자동화를 종료하는 전체 순서입니다.

**상세 기준:** [01. 시스템 개요](../01-system-overview.md)

아래 목록은 데이터 형식과 구현 순서를 맞추기 위해 정확한 이름을 사용합니다. 뜻은 [쉬운 용어집](../../GLOSSARY.md)에서 확인하세요.

1. 저장소 입력
2. `Repository Loader`가 `git clone`과 `commit_id` checkout으로 `CodeWorkspace` 준비
3. AST parse와 SAST 도구 병렬 실행
4. `StaticFactBundle` 생성
5. Orchestration Agent가 초기 가설 생성 시작
6. 저비용 Hypothesis Agent 호출
7. schema-valid INITIAL proposal 검증·전역 등록
8. 가설별 ACTIVE VerificationAssignment 저장과 owner 할당
9. Verification의 코드 위치 기반 on-demand retrieval
10. 운영 Verification의 독립 Pro/Con 병렬 검증
11. initial `TRUE | FALSE | HOLD`
12. initial TRUE이면 Verification이 `POC_CONFIRMATION`, 판정에 실행 근거가 필요하면 `VERDICT_EVIDENCE` 요청 → R7이 `EnvironmentRequirements`·LIMITED/FULL plan·PoC candidate 생산 → Runtime Validator와 Controller 검사 → Runner 실행 → Result Assembler 반환; generation당 동적 work는 하나
13. 성공한 `SUPPORTED` 실행과 validated PoC를 가진 final TRUE 또는 근거 기반 final FALSE/HOLD; 생성·환경·실행 실패는 verdict 없이 BLOCKED/FAILED
14. FALSE terminal / HOLD REQUIRED 즉시 admission / TRUE CWE 분기
15. final TRUE를 Technical Evidence Gate Agent가 검토
16. `REVISE`이면 같은 Verification owner가 새 Verification/CWE revision 생성 후 재제출
17. Technical `ACCEPT`인 TRUE를 Rule Scope Impact Gate Agent가 검토
18. 두 Gate를 정상 통과한 exact TRUE만 PROVIDED Primitive admission
19. Chaining Agent가 current ACTIVE Primitive만 matching; TRUE+TRUE는 앞 PROVIDED가 뒤 TRUE의 exact 선행 조건을 충족해야 함
20. Verification-origin 또는 Chaining-origin 새 주장을 trusted validation·전역 등록하고 새 Verification 배정
21. 모든 전달 조건을 만족한 결과에 Reporter Agent 호출
22. 결과·자원·LLM log·PoC·오류·debug 정보를 `AnalysisRunResult`에 저장하고 모든 가설에 반복한 뒤 Agent 자동화 종료

Technical Gate의 `REVISE`는 같은 hypothesis의 Verification owner에게 직접 돌아가 새 generation을 시작한다. final TRUE를 다시 만들려면 그 generation의 동적 결과와 validated PoC도 새로 필요하다. HOLD는 Gate 없이 Chaining에 들어가지만 TRUE는 두 Gate를 정상 통과하기 전에는 Chaining에 들어갈 수 없다. Verification과 Chaining의 material claim은 새 가설이 되며 기존 verdict에 직접 합쳐지지 않는다. 독립 가설은 예산 범위에서 병렬 처리할 수 있다.

`ReportDraft` 이후의 검토·수정·제출·공개는 Agent 자동화 밖에서 사람이 진행한다.

상세 책임과 종료 조건은 [시스템 개요](../01-system-overview.md)를 따른다.
