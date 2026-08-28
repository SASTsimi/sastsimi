# 01. 시스템 개요

- **이 문서는 무엇을 설명하나요?** 저장소 입력부터 사람의 최종 공개 판단까지 전체 23단계를 설명합니다.
- **누가 읽어야 하나요?** PM·아키텍처 담당과 모든 역할 담당자가 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** 단계 순서, 각 역할의 책임과 어디에서 작업이 끝나는지 확인합니다.

정확한 데이터 이름은 유지하며, 뜻은 [쉬운 용어집](../GLOSSARY.md)에서 확인할 수 있습니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## 목표와 경계

SASTSIMI v5는 저장소를 실행별 로컬 폴더에 clone하고 지정한 Git commit을 checkout한 뒤 정적 사실을 수집한다. 이후 LLM Agent가 가설 생성·검증·기술 검토·프로그램 정책 검토·보고서 초안을 단계적으로 수행한다. 정적 분석 도구와 LLM 출력 모두 단독으로 Finding이 되지 않으며, 공개 결정은 사람에게 남는다.

## 정본 23단계

| 단계 | 처리 | 주 산출물 또는 조건 |
|---:|---|---|
| 1 | 저장소 입력 | repository reference |
| 2 | 저장소 clone과 commit checkout | `CodeWorkspace` |
| 3 | AST parse와 SAST 도구 병렬 실행 | raw AST/SAST outputs |
| 4 | 정적 사실 정규화 | `StaticFactBundle` |
| 5 | 분석 실행 시작 | Orchestration run |
| 6 | 저비용 가설 생성 모델 호출 | constrained invocation |
| 7 | 출력 schema 검증 | `HypothesisProposal[]` 또는 `INVALID_OUTPUT` |
| 8 | 가설별 검증 작업 할당 | `VulnerabilityHypothesis` + Verification Agent |
| 9 | 위치 기반 코드 문맥 조회 | `CodeContextRequest/Response` |
| 10 | BASIC 또는 조건부 Pro/Con | supporting/counter evidence |
| 11 | 초기 판정 | `TRUE | FALSE | HOLD` |
| 12 | 필요 시 제한/전체 동적 재현 | `LIMITED_REPRO | FULL_REPRO`, PoC evidence |
| 13 | 최종 판정 | final `VerificationResult` |
| 14 | `TRUE/HOLD` Primitive DB 갱신 | TRUE의 PROVIDED / HOLD의 REQUIRED primitives |
| 15 | 조건부 우회·영향·연계 조사 | `TRUE/HOLD`, Technical revision 또는 Primitive match 기반 `ResearchResult` |
| 16 | 새 주장 환류 | new hypothesis proposal |
| 17 | 취약점 유형 라벨링 | CWE candidate with evidence |
| 18 | 기술 근거 검토 | `TechnicalEvidenceReview` |
| 19 | 공식 규칙·범위·영향 검토 | `RuleScopeImpactReview` |
| 20 | 조건 충족 시 보고서 작성 | `ReportDraft` |
| 21 | 결과와 디버깅 정보 저장 | result/resource/log/PoC/error records |
| 22 | 모든 가설에 반복 | bounded parallel hypothesis processing |
| 23 | 사람의 최종 검토 | disclose, revise, hold, or close |

## 주요 실행 흐름

```text
Repository Loader -> CodeWorkspace
  ├─ AST Parser ─┐
  └─ SAST Tools ─┴─> StaticFactBundle
                           │
                           v
Orchestration -> Hypothesis Agent -> schema validation -> hypotheses
                                                        │ per hypothesis
                                                        v
       on-demand context -> Verification -> optional dynamic reproduction
                                      │
                                      ├─> Primitive DB update
                                      └─> Research -> new hypothesis -> Orchestration
                                      │
                                      v
        CWE -> Technical Evidence Gate -> Rule Scope Impact Gate -> Reporter
                                                                  │
                                                                  v
                                                         Result Stores -> Human
```

Technical Evidence Gate의 `REVISE`가 restriction, 누락 근거 또는 추가 재현을 요구하면 같은 가설의 Verification 또는 Research 단계로 돌아간다. Research와 Primitive match가 만든 새 material claim은 기존 결과에 붙여 확정하지 않고 8단계부터 전체 검증을 새로 거친다.

## 구성 요소와 책임

Orchestration Agent는 분석 계획과 다음 작업을 제안·조정하지만 enforcement authority를 갖지 않는다. 신뢰 경계 안의 비-LLM runtime validator가 schema, 상태 전이, 예산, 병렬성, sandbox 정책, provider/session 정책, Gate 순서와 Reporter 호출 전제조건을 강제한다. 모든 LLM 출력은 validation 전까지 비신뢰 입력이다.

| 구성 요소 | 책임 | 금지 경계 |
|---|---|---|
| Repository Loader | 실행별 `git clone`, `commit_id` checkout과 HEAD 확인 | 실행 중 작업공간 변경 또는 다른 commit 혼합 |
| AST/SAST runners | 구조·규칙 일치·경로 후보 수집 | 취약점 최종 판정 |
| Static Fact Normalizer | 공통 entity/location/path 표현 생성 | 증거가 없는 의미 확정 |
| Context Retrieval Service | 같은 `workspace_id`와 `commit_id`에서 제한된 추가 문맥 조회 | 작업공간 밖 무제한 repository dump |
| Orchestration Agent | 가설 lifecycle, 병렬성, 예산과 loop 관리 | Finding 공개 결정 |
| Hypothesis Agent | schema-constrained 가설 후보 생성 | verdict·Finding·exploitability 확정 |
| Verification Agent | 증거 종합, 판정, restriction/capability 기록 | 새 주장의 무검증 승격 |
| Pro/Con Agents | 독립적인 성립·반박 근거 조사 | 동일 session 공유 |
| Sandbox Controller | 승인된 Docker 제한/전체 재현 | host 또는 허용 범위 밖 실행 |
| Primitive DB | REQUIRED와 PROVIDED 연결 | 작업 queue 또는 자동 Finding 생성 |
| Research Agent | 우회·대체 경로·영향·chain 후보 제안 | verdict, CWE, Gate, report 확정 |
| Technical Evidence Gate | 기술적 연결성과 handoff 품질 검토 | Verification verdict 직접 변경 |
| Rule Scope Impact Gate | 공식 정책·scope·실질 impact·전달 권한 검토 | 공식 자료 없는 추정 승인 |
| Reporter Agent | 통과한 결과의 보고서 초안 작성 | 공개 또는 제출 |
| Result Stores | 결과·로그·PoC·오류·debug 저장 | secret와 불필요한 전체 코드 저장 |
| Human Reviewer | 최종 수정·보류·공개 결정 | — |

## 상태 축은 분리한다

- 분석 판정: `TRUE | FALSE | HOLD`
- Technical Gate: `ACCEPT | REVISE | REJECT`
- Rule/Scope: `PASS | FAIL | UNCERTAIN`
- impact: `SUFFICIENT | INSUFFICIENT | UNCERTAIN`
- report permission: `ALLOW | DENY`
- 보고서: `NOT_REQUESTED | DRAFTED | HUMAN_REVIEWED`

한 축의 값으로 다른 축을 암묵적으로 추론하지 않는다. 예를 들어 기술적으로 `TRUE`여도 out-of-scope이거나 실질 영향이 부족하면 Reporter를 호출하지 않는다.

## 병렬성과 종료 조건

- AST와 복수 SAST 실행은 병렬화할 수 있다.
- 서로 독립된 가설의 Verification은 예산 범위에서 병렬화할 수 있다.
- 한 가설의 Pro/Con은 조건이 충족될 때 서로 독립된 NEW session으로 병렬화할 수 있다.
- 같은 가설의 `workspace_id`와 `commit_id`, initial verdict 전후, 두 Gate의 순서와 Reporter 조건은 의존성을 지킨다.
- 모든 초기·파생 가설이 종료 상태에 도달하고 저장이 끝나면 Orchestration run을 닫는다.
- chaining은 깊이·개수·토큰·시간·중복 fingerprint 제한을 넘으면 새 가설을 만들지 않고 중단 이유를 기록한다.
