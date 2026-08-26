# SASTSIMI Architecture v5 Wiki

이 Wiki는 Architecture v5 candidate baseline을 빠르게 탐색하는 **파생·비규범적 설명 계층**이다. 상세 기준은 [v5 설계 허브](../README.md)와 번호 문서를 따르며, Wiki 단독 변경으로 계약·상태·승인 결정을 만들 수 없다.

## 한 문장으로

AST와 SAST가 사실 정보를 만들면 constrained Hypothesis Agent가 가설만 제안하고, 가설별 Verification Agent가 위치 기반 문맥·조건부 Pro/Con·필요한 Docker 재현을 종합해 `TRUE | FALSE | HOLD`를 판정한다. Research 후보는 새 가설로 재검증하고, Technical Evidence Gate와 Rule Scope Impact Gate를 모두 통과한 결과만 Reporter가 초안으로 만들며 사람이 공개를 결정한다.

## 먼저 볼 문서

- [5분 이해](quick-guide.md)
- [정본 23단계 파이프라인](pipeline.md)
- [Agent 역할](agents.md)
- [검증과 동적 재현](verification-and-dynamic.md)
- [이중 LLM Gate와 보고](gate-and-reporting.md)
- [Primitive DB와 Research](chaining.md)
- [Provider, session과 logging](providers-and-logging.md)
- [결과와 디버깅](results.md)
- [Mermaid 다이어그램](diagrams.md)

## 현재 상태

- 설계 작성: `DESIGN_AUTHORED`
- 독립 검토: `REVIEW_REQUIRED`
- 구현: `NOT_IMPLEMENTED`

[v4에서 v5로의 설계 계보](../11-migration-from-v4.md)는 과거 결정의 맥락만 설명한다. Wiki는 새로운 정책·상태·계약을 만들지 않으며, 번호 문서와 불일치하면 번호 문서와 [검토 결정 기록](../../review/decisions/README.md)을 우선한다.
