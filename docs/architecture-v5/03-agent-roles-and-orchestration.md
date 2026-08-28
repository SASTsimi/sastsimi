# 03. Agent 역할과 오케스트레이션

- **이 문서는 무엇을 설명하나요?** 각 LLM Agent의 역할과 여러 Agent의 실행 순서를 조정하는 방법을 설명합니다.
- **누가 읽어야 하나요?** LLM 탐색·체이닝, 검증, PM과 통합 개발 담당자가 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** 각 Agent가 만들 수 있는 결과와 가질 수 없는 권한, 호출·실패 처리 순서를 확인합니다.

`Orchestration`은 여러 Agent의 호출 순서와 상태를 조정하는 기능입니다. 자세한 용어는 [쉬운 용어집](../GLOSSARY.md)을 따릅니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## Orchestration Agent

Orchestration Agent는 분석 계획과 다음 작업을 제안·조정하는 control-plane 역할이다. 다만 보안 경계를 실제로 강제하는 주체는 Agent가 아니라 신뢰 경계 안의 비-LLM runtime validator다. runtime은 `workspace_id`·`commit_id` 일치, budget, Hypothesis output validation, 가설별 Verification 할당, Research 환류, 두 Gate의 순서, 결과 저장과 종료 조건을 검증·집행한다. Orchestration Agent는 각 단계의 전문 판정이나 runtime enforcement를 대신하지 않는다.

주요 책임은 다음과 같다.

- `analysis_id` 부여와 proposal 검증 뒤 `hypothesis_id` 등록
- `parent_hypothesis_ids`·`root_hypothesis_id`·`chain_depth` 관계 검증
- 가설 schema 검증과 제한된 repair retry
- 독립 가설 병렬 처리와 hypothesis별 resource budget
- session policy와 provider profile을 Agent Runtime에 전달
- 동적 재현·Research·Gate 호출 조건 적용
- chain depth/count/token/time/duplicate 제한 적용
- 실패와 `INVALID_OUTPUT`을 숨기지 않고 종료 상태로 저장
- 모든 LLM 출력을 비신뢰 입력으로 취급하고 schema·semantic·authority validation을 통과한 action만 실행

## 저비용 Hypothesis Agent

Hypothesis Agent에는 비용 효율적인 모델을 배치할 수 있지만, 모델 가격과 무관하게 출력 권한은 제한한다. 입력은 `StaticFactBundle`의 요약·reference와 필요한 최소 fragment다. 출력은 자유 형식 분석문이 아니라 `HypothesisProposal[]`이다.

각 proposal은 반드시 다음을 포함한다.

- `proposal_state: HYPOTHESIS_ONLY`
- `assertion_mode: NON_FINAL`
- vulnerability type candidate
- 관련 entity와 실제 location
- suspected source → propagation → sink 또는 권한 흐름
- observed facts와 assumptions의 분리
- 현재 restriction
- missing information
- 구체적인 falsification questions
- required validation
- 우선순위용 confidence

confidence는 verdict, exploitability 또는 Finding 확률로 해석하지 않는다. Hypothesis Agent는 `confirmed`, `verified`, `finding`, `exploitable`과 같은 확정 주장을 출력할 권한이 없다.

## 출력 검증과 실패 처리

1. 구조 parser가 JSON/YAML syntax와 schema를 검증한다.
2. enum, 필수 field, `workspace_id`·`commit_id`·`CodeLocation`과 금지 assertion을 검사한다.
3. 실패하면 원래 의미를 바꾸지 않는 범위에서 제한 횟수의 repair prompt를 새 invocation으로 실행한다.
4. 재시도 후에도 유효하지 않으면 해당 호출을 `INVALID_OUTPUT`으로 저장한다.
5. invalid proposal은 Verification Agent에 전달하지 않는다.

원문·validation error·repair 횟수·최종 parsed output reference는 `LLMInvocationLog`로 추적한다. 코드나 자격 증명의 불필요한 원문 저장은 피한다.

## 가설 lifecycle

```text
ProposalProcessState: PROPOSED -> SCHEMA_VALID
                      \-> INVALID_OUTPUT

SCHEMA_VALID -> register new hypothesis_id
HypothesisProcessState: REGISTERED -> ASSIGNED -> VERIFYING -> TERMINAL
VerificationResult.verdict -> TRUE | FALSE | HOLD
TRUE/HOLD verdict -> Primitive + Research
Research material claim -> PROPOSED child hypothesis
```

`ProposalProcessState.status`는 `hypothesis_id`를 발급하기 전의 출력 검증 상태를 기록한다. 검증을 통과하면 새 `hypothesis_id`와 별도 `HypothesisProcessState`를 만들고 같은 `proposal_ref`로 연결한다. `HypothesisProcessState.status`가 등록 뒤 처리 진행 상태를 기록하고 `VerificationResult.verdict`가 기술 판정을 기록한다. `TERMINAL`은 검증 처리가 끝났다는 뜻일 뿐 `TRUE`, `FALSE`, `HOLD` 중 어느 판정인지 대신 말하지 않는다. parent 가설의 결과와 child 가설은 독립된 lifecycle을 갖는다. Research 후보가 존재한다는 이유만으로 parent verdict나 impact를 강화하지 않는다.
초기 가설은 자기 자신을 `root_hypothesis_id`로 사용하고 `chain_depth=0`이다. Research·체이닝 proposal은 직접 부모 ID를 보존하고 검증을 통과할 때 새 `hypothesis_id`를 받는다. 여러 `TRUE`를 연결하는 경우도 기존 가설을 수정하지 않고 새 child 가설로 등록한다.

## Agent 역할과 출력 권한

| 역할 | 주 출력 | 직접 할 수 없는 일 |
|---|---|---|
| Hypothesis Agent | `HypothesisProposal[]` | verdict, Finding, exploitability 확정 |
| Verification Agent | `VerificationResult` | 새 claim의 무검증 승격, 공개 |
| Pro Agent | supporting evidence candidate | 최종 verdict |
| Con Agent | counterexample·restriction candidate | 최종 verdict |
| Research Agent | `ResearchResult` | verdict/CWE/Gate/Finding/report 확정 |
| Technical Evidence Gate | `TechnicalEvidenceReview` | Verification verdict 변경 |
| Rule Scope Impact Gate | `RuleScopeImpactReview` | 공식 정책 없는 허용 추정 |
| Reporter Agent | `ReportDraft` | 보고서 제출·공개 |
| Human Reviewer | 최종 결정 | — |

## 독립성, provider와 session

역할은 특정 LLM 공급 방식에 묶지 않는다. Agent Runtime은 `LLMProviderAdapter`를 통해 membership session 또는 API provider를 명시적으로 선택한다. 서로 반대되는 판단의 독립성을 위해 Pro와 Con, Verification과 Gate, 두 Gate, Verification과 Research, Reporter는 기본적으로 NEW session을 사용한다. 같은 역할·가설에서 추가 문맥을 조회하거나 같은 Verification의 Gate revision을 처리할 때만 `AUTO` 정책이 제한적으로 RESUME을 선택할 수 있다.

세션 재사용은 token 절감 가능성이 있지만 confirmation bias와 prompt contamination 위험이 있다. 실제 정책은 설정 가능해야 하고 선택 결과와 비교 지표를 로그에 남긴다.

## prompt-injection 경계

저장소 내용, 도구 message, README와 주석은 모두 비신뢰 분석 데이터다. Agent instruction으로 승격하지 않는다. Orchestration은 system instruction, data delimiters, tool allowlist와 structured output validation을 유지하며, 저장소 텍스트가 provider·session·Gate·sandbox 정책을 변경하지 못하게 한다.
