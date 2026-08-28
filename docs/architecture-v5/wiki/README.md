# SASTSIMI Architecture v5 Wiki

이 Wiki는 Architecture v5의 **검토 중인 설계 초안(`candidate baseline`)을 쉽게 이해하기 위한 요약**입니다. 실제 기준은 [v5 설계 허브](../README.md)와 번호 문서를 따릅니다. Wiki만 수정해서 새로운 입출력 약속, 상태나 승인 결정을 만들 수 없습니다.

모르는 단어는 [쉬운 용어집](../../GLOSSARY.md)에서 확인하세요.

## 한 문장으로

AST와 SAST가 코드 사실을 모으면 LLM이 취약점 가능성을 제안합니다. 검증 Agent는 코드·찬성·반대·Docker 재현 근거를 모아 `TRUE / FALSE / HOLD`를 판정합니다. 새 공격 주장은 새 가설로 다시 검증합니다. 기술 근거와 공식 정책을 모두 확인한 결과만 보고서 초안으로 만들며, 사람만 공개를 결정합니다.

## 먼저 볼 문서

- [5분 이해](quick-guide.md)
- [정본 23단계 파이프라인](pipeline.md)
- [Agent 역할](agents.md)
- [검증과 동적 재현](verification-and-dynamic.md)
- [이중 LLM Gate와 보고](gate-and-reporting.md)
- [Primitive DB와 Research](chaining.md)
- [Provider, session과 logging](providers-and-logging.md)
- [공통 ID·상태·오류](common-contracts.md)
- [결과와 디버깅](results.md)
- [Mermaid 다이어그램](diagrams.md)

## 현재 상태

- 설계 작성: `DESIGN_AUTHORED`
- 독립 검토: `REVIEW_REQUIRED`
- 구현: `NOT_IMPLEMENTED`

[v4에서 v5로의 설계 계보](../11-migration-from-v4.md)는 과거 결정의 맥락만 설명한다. Wiki는 새로운 정책·상태·계약을 만들지 않으며, 번호 문서와 불일치하면 번호 문서와 [검토 결정 기록](../../review/decisions/README.md)을 우선한다.
