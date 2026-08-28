# 13. 아키텍처 다이어그램

- **이 문서는 무엇을 설명하나요?** Architecture v5 전체 흐름과 역할·데이터 관계를 그림으로 보여 줍니다.
- **누가 읽어야 하나요?** 전체 흐름을 빠르게 파악하려는 모든 팀원이 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** 번호 문서의 단계와 화살표가 같은 의미인지, 빠진 흐름이 없는지 확인합니다.

정확한 Mermaid 이름은 번호 문서의 데이터·상태 이름과 맞추기 위해 유지합니다. 모르는 이름은 [쉬운 용어집](../GLOSSARY.md)에서 확인하세요.

## 다이어그램 읽는 법

- 사각형은 실행 단계나 결과를 나타냅니다.
- 마름모는 조건에 따라 다음 흐름이 달라지는 판단 지점을 나타냅니다.
- 원통 모양은 데이터 저장소를 나타냅니다.
- 실선 화살표는 다음 호출·처리 순서를 나타냅니다.
- 점선 화살표는 검토·보완·새 가설처럼 기본 흐름으로 되돌아가는 관계를 나타냅니다.
- `TRUE / FALSE / HOLD` 같은 영문 상태값은 구현에서 정확히 맞춰야 하므로 그림에서 그대로 사용합니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## 1. 정본 23단계 파이프라인

```mermaid
flowchart TB
    S01[1 Repository input] --> S02[2 Repository Loader git clone and commit checkout]
    S02 --> WORK[CodeWorkspace READY]
    WORK --> S03A[3 AST parse]
    WORK --> S03B[3 SAST tools]
    S03A --> S04[4 StaticFactBundle]
    S03B --> S04
    S04 --> S05[5 Orchestration Agent plans]
    S05 --> RUNTIME[[Trusted Runtime Validator]]
    RUNTIME --> S06[6 Low-cost Hypothesis Agent]
    S06 --> S07[7 Schema-valid HypothesisProposal list]
    S07 --> S08[8 Verification Agent per hypothesis]
    S08 --> S09[9 On-demand code retrieval]
    S09 --> S10[10 BASIC or conditional Pro and Con]
    S10 --> S11[11 Initial TRUE FALSE HOLD]
    S11 --> S12{12 Dynamic reproduction needed}
    S12 -->|No| S13[13 Final TRUE FALSE HOLD]
    S12 -->|LIMITED| DL[Docker LIMITED_REPRO]
    S12 -->|FULL| DF[Docker FULL_REPRO and PoC]
    DL --> S13
    DF --> S13
    S13 --> S14[14 Update Primitive DB]
    S14 --> RC{TRUE HOLD or Research trigger}
    RC -->|Yes| S15[15 Research bypass impact chain]
    RC -->|No| S17
    S15 --> S16{16 New material claim}
    S16 -->|Yes| S05
    S16 -->|No| S17[17 CWE labeling]
    S17 --> S18[18 Technical Evidence Gate]
    S18 -->|REVISE| S08
    S18 -->|ACCEPT and TRUE| S19[19 Rule Scope Impact Gate]
    S18 -->|Other| S21[21 Store results logs PoC errors debug]
    S19 -->|All report conditions| S20[20 Reporter draft]
    S19 -->|Blocked| S21
    S20 --> S21
    S21 --> S22{22 More hypotheses}
    S22 -->|Yes| S08
    S22 -->|No| S23[23 Human review and disclosure decision]
```

가설들은 예산 범위에서 병렬화할 수 있지만, 한 가설 안의 `workspace_id`·`commit_id`·판정·Gate 순서와 Reporter 전제는 유지한다.

## 2. 정적 사실과 위치 기반 조회

```mermaid
flowchart LR
    LOAD[Repository Loader] --> WORK[CodeWorkspace]
    WORK --> AST[AST Parser]
    WORK --> SAST1[SAST Tool 1]
    WORK --> SASTN[SAST Tool N]
    AST --> NORMAL[Static Fact Normalizer]
    SAST1 --> NORMAL
    SASTN --> NORMAL
    NORMAL --> FACTS[StaticFactBundle]
    FACTS --> HYP[Hypothesis anchor entity location path]
    HYP --> REQ[CodeContextRequest]
    REQ --> CHECK{Same workspace and commit within budget}
    CHECK -->|No| GAP[Error or explicit gap]
    CHECK -->|Yes| RET[Context Retrieval Service]
    RET --> REL[Callers Callees Data flow Auth guards Routes]
    REL --> RESP[CodeContextResponse]
    RESP --> AGENT[Verification Pro Con Research or Technical Gate]
    AGENT --> LOG[Log retrieved locations]
```

empty, truncated와 unresolved response는 안전함 또는 `FALSE`로 자동 변환하지 않는다.

## 3. 저비용 가설 생성과 출력 통제

```mermaid
flowchart TB
    FACTS[StaticFactBundle refs] --> HA[Low-cost Hypothesis Agent]
    HA --> RAW[Candidate output]
    RAW --> SCHEMA{Syntax schema enums locations valid}
    SCHEMA -->|Yes| ASSERT{HYPOTHESIS_ONLY and NON_FINAL}
    ASSERT -->|Yes| REGISTER[Register VulnerabilityHypothesis]
    REGISTER --> VERIFY[Assign Verification Agent]
    SCHEMA -->|No| RETRY{Repair retries remain}
    ASSERT -->|No| RETRY
    RETRY -->|Yes| REPAIR[Constrained repair invocation]
    REPAIR --> SCHEMA
    RETRY -->|No| INVALID[INVALID_OUTPUT]
    INVALID --> STORE[Store errors and invocation refs]
```

proposal은 facts와 assumptions, restrictions, missing information, falsification questions와 required validation을 분리한다. confidence는 우선순위 힌트일 뿐 verdict가 아니다.

## 4. 조건부 검증과 Docker 재현

```mermaid
flowchart TB
    HYP[VulnerabilityHypothesis] --> CTX[On-demand context]
    CTX --> MODE{Verification mode}
    MODE -->|BASIC| BASIC[Verification direct evidence]
    MODE -->|CONDITIONAL_DEBATE| TRIGGER{Debate trigger present}
    MODE -->|ALWAYS_DEBATE| FORK[Independent NEW sessions]
    TRIGGER -->|No and skip recorded| BASIC
    TRIGGER -->|Yes| FORK
    FORK --> PRO[Pro Agent]
    FORK --> CON[Con Agent]
    PRO --> SYN[Verification synthesis]
    CON --> SYN
    BASIC --> SYN
    SYN --> INITIAL[Initial TRUE FALSE HOLD]
    INITIAL --> DYN{Dynamic evidence needed}
    DYN -->|No| FINAL[Final VerificationResult]
    DYN -->|Small question| LIMITED[Docker LIMITED_REPRO]
    DYN -->|End to end| FULL[Docker FULL_REPRO and PoC]
    LIMITED --> SYN2[Re-synthesize evidence]
    FULL --> SYN2
    SYN2 --> FINAL
    FINAL --> OUT[Restrictions bypass candidates required and provided capabilities impact candidates]
```

별도 endpoint·sink·권한 경계·impact 주장은 같은 verdict에 합치지 않고 새 가설로 보낸다.

## 5. Primitive DB와 Research loop

```mermaid
flowchart TB
    VR[Final VerificationResult] --> KIND{Verdict}
    KIND -->|FALSE| CLOSED[Store terminal result]
    KIND -->|TRUE| PROVIDED[ConfirmedCapability PROVIDED]
    KIND -->|HOLD| REQUIRED[HeldHypothesis REQUIRED]
    PROVIDED --> PDB[(Primitive DB)]
    PROVIDED --> RESEARCH[Research Agent]
    REQUIRED --> PDB
    REQUIRED --> RESEARCH
    PDB --> MATCH{Workspace asset capability and attack order match}
    MATCH -->|No| RESEARCH[Research Agent]
    MATCH -->|Yes| RESEARCH
    TGREV[Technical Gate revision request] --> RESEARCH
    RESEARCH --> CAND[Bypass alternate path impact and chain candidates]
    CAND --> MATERIAL{Material new claim}
    MATERIAL -->|No| RECORD[Record no material extension or validation request]
    MATERIAL -->|Yes| NEW[Chained or child HypothesisProposal]
    NEW --> LIMIT{Depth count token time duplicate limits}
    LIMIT -->|Within limits| ORCH[Orchestration Agent]
    LIMIT -->|Exceeded| STOP[Record bounded stop]
    ORCH --> VERIFY[Full verification pipeline]
```

Primitive DB는 queue가 아니며 Research·match 결과는 Finding이 아니다.

## 6. 이중 LLM Gate와 사람 결정

```mermaid
flowchart TB
    VR[Final VerificationResult plus CWE] --> TECH[Technical Evidence Gate Agent]
    TECH --> TS{ACCEPT REVISE REJECT}
    TS -->|REVISE| BACK[Verification or Research revision]
    BACK --> VR
    TS -->|REJECT| BLOCK[Report blocked]
    TS -->|ACCEPT but not TRUE| INTERNAL[Internal terminal record]
    TS -->|ACCEPT and TRUE| RULE[Rule Scope Impact Gate Agent]
    POLICY[Official ProgramPolicyRecord] --> RULE
    NOPOL[Missing official policy] --> UNCERTAIN[Rule and scope UNCERTAIN permission DENY]
    UNCERTAIN --> BLOCK
    RULE --> READY{Review PASS Rule PASS Scope PASS Impact SUFFICIENT Permission ALLOW}
    READY -->|No| BLOCK
    READY -->|Yes| REPORTER[Reporter Agent]
    REPORTER --> DRAFT[Internal ReportDraft]
    BLOCK --> HUMAN[Human Reviewer]
    INTERNAL --> HUMAN
    DRAFT --> HUMAN
    HUMAN --> DECIDE[Disclose Revise Withhold or More validation]
```

두 Gate 모두 LLM 검토 Agent이고 Verification verdict를 직접 바꾸지 않는다. 공식 정책이 없으면 Reporter 경로는 닫힌다.

## 7. Provider, session과 logging

```mermaid
flowchart LR
    AGENT[Agent proposed invocation] --> TRUST[Trusted Runtime Validator]
    TRUST --> REQ[LLMInvocationRequest]
    REQ --> POLICY{SessionPolicy NEW RESUME AUTO}
    POLICY --> LOGPROXY[LLM Logging Proxy]
    LOGPROXY --> ADAPTER[LLMProviderAdapter]
    ADAPTER --> MEMBER[MembershipSessionAdapter]
    ADAPTER --> API[APIProviderAdapter]
    MEMBER --> RESULT[Normalized LLMInvocationResult]
    API --> RESULT
    RESULT --> LOG[LLMInvocationLog]
    RAW[Membership raw session log] --> PARSER[Provider Session Parser]
    PARSER --> REDACT[Redaction]
    REDACT --> LOG
    LOG --> OBS[Invocation and resource store]
    FAIL[Explicit retry or failover] --> REQ
```

provider/model과 실제 session 결정은 기록한다. trusted runtime이 허용 profile·budget·session policy를 검증하며 silent failover, credential logging과 hidden chain-of-thought 수집은 허용하지 않는다.

## 8. 결과·자원·디버깅 저장

```mermaid
flowchart LR
    STATIC[AST SAST facts] --> FACTS[(facts)]
    CONTEXT[Context retrieval] --> CONTEXTS[(contexts)]
    AGENTS[Hypothesis Verification Pro Con] --> RESULTS[(hypotheses and verifications)]
    DYNAMIC[Docker and PoC] --> DYNSTORE[(dynamic artifacts)]
    PR[Primitive and Research] --> PRSTORE[(primitives and research)]
    GATES[Technical and Rule Scope Gates] --> GATESTORE[(gates and policies)]
    REPORT[Reporter] --> REPORTS[(report drafts)]
    LLM[Logging Proxy or parser] --> INV[(invocation logs)]
    FACTS --> RUN[(AnalysisRunResult and debug trace)]
    CONTEXTS --> RUN
    RESULTS --> RUN
    DYNSTORE --> RUN
    PRSTORE --> RUN
    GATESTORE --> RUN
    REPORTS --> RUN
    INV --> RUN
    RUN --> HUMAN[Human review]
```

## Rendering check

이 문서는 Mermaid 블록 8개를 포함한다. Wiki diagrams 페이지는 이 파일과 동일한 Mermaid 블록을 사용하며 최종 검증에서 8개 SVG와 parse error 0개를 확인한다.
