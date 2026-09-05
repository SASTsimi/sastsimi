# SASTSIMI Architecture v5 Wiki

이 Wiki는 Architecture v5의 **검토 중인 설계 초안(`candidate baseline`)을 쉽게 이해하기 위한 요약**입니다. 실제 기준은 [v5 설계 허브](../README.md)와 번호 문서를 따릅니다. Wiki만 수정해서 새로운 입출력 약속, 상태나 승인 결정을 만들 수 없습니다.

모르는 단어는 [쉬운 용어집](../../GLOSSARY.md)에서 확인하세요.

## 한 문장으로

AST와 SAST가 코드 사실을 모으면 LLM이 취약점 가능성을 제안합니다. Orchestration은 가설을 등록해 Verification에 배정하고, Verification은 코드·찬성·반대·Docker 재현·Gate 보완을 관리해 `TRUE / FALSE / HOLD`를 판정합니다. HOLD는 하나 이상의 `required_primitive_candidates`가 있을 때만 `result=null`인 Primitive로 저장하고 Chaining에 사용하며, 후보가 없으면 Primitive와 Chaining 작업을 만들지 않습니다. TRUE는 Technical `ACCEPT` 뒤 금지된 테스트로 얻은 근거인지 따로 확인하며, 위반이 확정되지 않아 `PrimitiveAdmissionDecision=ALLOW`인 결과만 Chaining에 사용합니다. Rule Scope의 나머지 판단은 보고 가능성만 바꿉니다. 새 공격 주장은 새 가설로 다시 검증하며 Reporter의 `ReportDraft`와 결과 저장 뒤 Agent 자동화가 끝납니다.

## 먼저 볼 문서

- [5분 이해](quick-guide.md)
- [정본 22단계 파이프라인](pipeline.md)
- [Agent 역할](agents.md)
- [검증과 동적 재현](verification-and-dynamic.md)
- [이중 LLM Gate와 보고](gate-and-reporting.md)
- [Primitive DB와 Chaining](chaining.md)
- [Provider, session과 logging](providers-and-logging.md)
- [공통 ID·상태·오류](common-contracts.md)
- [상태·병렬 실행·재시도·복구](state-and-recovery.md)
- [LLM·프로그램·사람의 권한 경계](authority-boundaries.md)
- [결과와 디버깅](results.md)
- [Mermaid 다이어그램](diagrams.md)

## 현재 상태

- 설계 작성: `DESIGN_AUTHORED`
- 독립 검토: `REVIEW_REQUIRED`
- 구현: `NOT_IMPLEMENTED`

[v4에서 v5로의 설계 계보](../11-migration-from-v4.md)는 과거 결정의 맥락만 설명한다. Wiki는 새로운 정책·상태·계약을 만들지 않으며, 번호 문서와 불일치하면 번호 문서와 [검토 결정 기록](../../review/decisions/README.md)을 우선한다.
