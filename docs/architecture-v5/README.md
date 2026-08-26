# SASTSIMI Architecture v5

- **이 문서는 무엇을 설명하나요?** Architecture v5 전체 흐름과 상세 문서를 읽는 순서를 설명합니다.
- **누가 읽어야 하나요?** 프로젝트에 참여하는 모든 팀원이 먼저 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** 자신의 역할이 전체 흐름의 어디에 있고 어떤 번호 문서를 검토해야 하는지 확인합니다.

전문용어는 [쉬운 용어집](../GLOSSARY.md)에서 확인할 수 있습니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

Architecture v5는 정적 분석 결과를 최종 판정으로 사용하지 않습니다. 정적 분석은 LLM Agent가 검증할 취약점 가설을 만들 때 참고하는 코드 사실을 제공합니다. 이 문서 묶음은 **검토 중인 설계 초안(`candidate baseline`)**이며 아직 승인된 최종 설계, 구현 완료 또는 성능 개선을 뜻하지 않습니다.

번호 문서 `01`–`13`이 설계 의미의 기준입니다. Wiki는 빠르게 이해하기 위한 쉬운 요약이며 새로운 입출력 약속이나 결정을 만들 수 없습니다. 검토 결정은 이 저장소의 Issue, 설계 결정 기록(`ADR`)과 PR에서 먼저 확정합니다. 승인된 저장소 사본(`snapshot`)만 별도 PR로 구현 저장소에 반영합니다.

## 전체 흐름을 쉽게 나누면

1. **입력과 코드 사실 수집**: 분석할 저장소 시점을 고정하고 AST와 SAST를 함께 실행합니다.
2. **가설과 검증**: LLM이 취약점 가능성을 제안하고 검증 Agent가 코드·찬성·반대 근거를 확인합니다.
3. **동적 재현과 연계 탐색**: 필요하면 Docker에서 재현하고 확인된 조건을 연결해 새 가설을 만듭니다.
4. **최종 검토와 보고서 초안**: 취약점 종류를 붙이고 기술 근거와 공식 정책을 차례로 검토합니다.
5. **사람의 결정**: 사람이 모든 결과와 디버깅 정보를 보고 외부 공개 여부를 결정합니다.

## 정확한 23단계 기준 흐름

1. 저장소를 입력받는다.
2. 분석할 `RepositorySnapshot`을 고정한다.
3. AST parse와 SAST 도구를 병렬 실행한다.
4. 결과를 `StaticFactBundle`로 정규화한다.
5. Orchestration Agent가 분석 실행을 시작한다.
6. 저비용 Hypothesis Agent를 호출한다.
7. schema-valid `HypothesisProposal[]`을 생성한다.
8. 각 가설에 Verification Agent를 할당한다.
9. 가설의 entity·위치·경로를 기준으로 필요한 코드 문맥을 조회한다.
10. `BASIC` 또는 조건부 Pro/Con 검증을 수행한다.
11. 초기 `TRUE | FALSE | HOLD` 판정을 만든다.
12. 필요하면 Docker sandbox에서 `LIMITED_REPRO | FULL_REPRO`를 수행한다.
13. 최종 `TRUE | FALSE | HOLD` 판정을 확정한다.
14. `TRUE`의 PROVIDED 또는 `HOLD`의 REQUIRED Primitive를 Primitive DB에 반영한다. `FALSE`는 Primitive/Research 입력으로 승격하지 않는다.
15. `TRUE | HOLD` 또는 명시적인 Technical revision/Primitive match 조건에서 Research Agent가 우회·영향 확대·연계 가능성을 조사한다.
16. 새 material claim은 새 `VulnerabilityHypothesis`로 Orchestration Agent에 반환한다.
17. 검증된 취약점 유형에 CWE를 라벨링한다.
18. Technical Evidence Gate Agent가 기술 근거와 판정의 연결성을 검토한다.
19. Technical `ACCEPT`인 `TRUE`만 Rule Scope Impact Gate Agent가 공식 정책·범위·실질 영향을 검토한다.
20. 모든 전달 조건을 만족한 결과에만 Reporter Agent가 보고서 초안을 작성한다.
21. 결과·자원·LLM 호출 기록·PoC·오류·디버깅 정보를 저장한다.
22. 초기·파생·체이닝 가설 모두에 8–21단계를 반복한다.
23. 사람이 Finding과 디버깅 정보를 검토하고 최종 공개 여부를 결정한다.

## 핵심 원칙

- AST와 SAST는 source, sink, entity, 위치, 호출·데이터 흐름, 인증·인가와 같은 사실 후보를 제공한다.
- Hypothesis Agent는 항상 `HYPOTHESIS_ONLY / NON_FINAL` 제안만 만들며 Finding이나 확정 판정을 만들 수 없다.
- 코드 문맥은 고정 snapshot에서 위치 기반으로 필요할 때 조회하고, 조회 범위와 반환 위치를 기록한다.
- Verification은 제한 조건과 우회 가능성을 함께 조사한다. 새 공격 주장은 새 가설로 다시 검증한다.
- 기본 검증 모드는 `CONDITIONAL_DEBATE`다. Pro와 Con은 필요한 경우에만 독립 세션으로 실행한다.
- Primitive DB는 queue가 아니라 제한 조건과 검증된 능력을 연결하는 인덱스다. match는 새 가설만 만든다.
- Research Agent는 후보를 제안할 뿐 verdict, Finding, CWE, Gate 결과나 공개 결정을 확정할 수 없다.
- Technical Evidence Gate와 Rule Scope Impact Gate는 서로 다른 LLM 검토 단계다. 어느 Gate도 Verification verdict를 직접 바꾸지 않는다.
- 공식 프로그램 정책이 없으면 rule/scope를 추정하지 않으며 보고서 전달 권한은 `DENY`다.
- Membership session과 API provider는 공통 adapter 경계를 사용한다. Membership path는 feasibility/security 검토 전 experimental이며, provider 전환은 명시적으로 기록하고 조용한 failover는 금지한다.
- Reporter는 초안 작성자이고, 사람만 최종 공개 여부를 결정한다.
- 모든 LLM 출력은 비신뢰 입력이다. 신뢰 경계 안의 runtime validator가 schema·상태 전이·예산·sandbox·provider/session·Gate 순서·Reporter 전제조건을 강제한다.

## 문서 지도

1. [시스템 개요](./01-system-overview.md)
2. [정적 사실 계층과 코드 문맥 조회](./02-static-fact-layer.md)
3. [Agent 역할과 오케스트레이션](./03-agent-roles-and-orchestration.md)
4. [검증과 동적 재현](./04-verification-and-dynamic-reproduction.md)
5. [이중 LLM Gate와 보고](./05-llm-gate-and-reporting.md)
6. [Primitive DB, Research와 chaining](./06-chaining.md)
7. [결과 저장과 관측성](./07-results-and-observability.md)
8. [경량 데이터 계약](./08-lightweight-data-contracts.md)
9. [LLM provider, session과 logging](./09-llm-provider-session-and-logging.md)
10. [보안 경계](./10-security-boundaries.md)
11. [v4에서의 마이그레이션](./11-migration-from-v4.md)
12. [보고서 초안 템플릿](./12-report-draft-template.md)
13. [아키텍처 다이어그램](./13-architecture-diagrams.md)
14. [Wiki](./wiki/README.md)
15. [검토 운영과 발견사항](../review/FINDINGS.md)

## 문서 적용 범위

이 디렉터리는 v5 candidate baseline의 번호 문서를 보관한다. 이 저장소의 검토가 끝나기 전에는 승인된 정본이 아니다. v4는 [설계 계보 문서](./11-migration-from-v4.md)에 요약된 역사적 맥락일 뿐 현재 파이프라인을 정의하지 않는다. 실제 adapter, sandbox, Primitive DB, 정책 수집기, Agent와 Gate 구현은 별도 구현·보안 검토·평가가 필요하다.
