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
    S04 --> S05[5 Orchestration starts initial hypothesis work]
    S05 --> RUNTIME[[Trusted Runtime Validator]]
    RUNTIME --> S06[6 Low-cost Hypothesis Agent]
    S06 --> S07[7 Validate and register INITIAL proposals]
    S07 --> S08[8 Runtime stores ACTIVE VerificationAssignment]
    S08 --> S09[9 Verification requests on-demand context]
    S09 --> S10[10 Production Verification runs independent Pro and Con]
    S10 --> S11[11 Initial TRUE FALSE HOLD]
    S11 --> S12{12 Verification chooses dynamic mode}
    S12 -->|No| S13[13 Final verdict and material claim split]
    S12 -->|LIMITED| DL[Verification LIMITED Requirements and Plan]
    S12 -->|FULL| DF[Verification FULL Requirements Plan and PoC draft]
    DL --> DAUTH[Runtime Validator call authorization]
    DF --> DAUTH
    DAUTH --> DCTRL[Sandbox Controller policy check]
    DCTRL --> DPD[Exact SandboxPolicyDecision]
    DPD -->|Pass| DENV[Sandbox Runner prepares environment and Health Checks]
    DPD -->|Policy blocked no Runner| DASM[Sandbox Result Assembler]
    DENV --> DCHK{All required items MATCH}
    DCHK -->|Yes| DRUN[Sandbox Runner executes exact attack steps]
    DCHK -->|No| DFAIL[Stop before attack with ENVIRONMENT_SETUP]
    DFAIL --> DASM
    DRUN --> DASM
    DASM --> DRES[Dynamic result with exact nullable refs]
    DRES --> DMIS{Required environment mismatch}
    DMIS -->|Yes| DRET[R6 reviews exact differences]
    DMIS -->|No| S13
    DRET -->|New requirements plus plan or plan-only revision| DAUTH
    DRET -->|No retry| S13
    S13 --> S14{14 Final verdict}
    S14 -->|FALSE| CLOSED[Terminal internal result]
    S14 -->|HOLD| REQUIRED[HOLD REQUIRED Primitive admitted]
    S14 -->|TRUE| CWE[14 CWE labeling for TRUE]
    CWE --> S15[15 Technical Evidence Gate]
    S15 -->|REVISE| S16[16 Same assignment starts new Verification work and revision]
    S16 --> S13
    S15 -->|REJECT| S22[22 Store results logs PoC errors debug]
    S15 -->|ACCEPT| S17[17 Rule Scope Impact Gate]
    S17 -->|FAIL UNCERTAIN or DENY| S22
    S17 -->|Normal pass| S18[18 Gate-qualified TRUE PROVIDED admitted]
    REQUIRED --> S19[19 Chaining with current index and directional requirement]
    S18 --> S19
    S17 -->|All report conditions| RREQ[Verification requests Reporter]
    RREQ --> S21[21 Reporter draft]
    S19 -->|Match| S20[20 Validate child proposal and assign new Verification]
    S19 -->|No match or bounded stop| S22
    S20 --> S08
    S13 -. origin VERIFICATION material claim .-> S20
    S21 --> S22
    CLOSED --> S22
    S22 --> MORE{22 More hypotheses}
    MORE -->|Yes| S08
    MORE -->|No| S23[23 Human review and disclosure decision]
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
    CHECK -->|No| ERROR[AnalysisError plus affected DataGap]
    CHECK -->|Yes| RET[Context Retrieval Service]
    RET --> REL[Callers Callees Data flow Auth guards Routes]
    REL --> RESP[CodeContextResponse]
    RET -->|Failure timeout denied| ERROR
    RESP --> COMPLETE{Can all validation checks finish with valid evidence}
    ERROR --> COMPLETE
    COMPLETE -->|Retry or alternate lookup| REQ
    COMPLETE -->|Required input missing| RETRYABLE{Can retry or wait for input}
    RETRYABLE -->|Yes| BLOCK[Work BLOCKED hypothesis stays VERIFYING]
    BLOCK -->|Condition resolved| REQ
    RETRYABLE -->|No| FAIL[Atomic work FAILED plus hypothesis FAILED no final result]
    COMPLETE -->|Yes| AGENT[Verification Pro and Con]
    AGENT --> LOG[Log retrieved locations]
```

empty, truncated, gap와 error는 `TRUE | FALSE | HOLD`의 근거로 자동 변환하지 않는다. 일부 조회 실패가 있어도 정상 근거로 모든 검증 항목을 완료하면 판정할 수 있다. 필수 입력이 없지만 다시 시도할 수 있으면 work만 `BLOCKED`로 두고 가설은 `VERIFYING`을 유지한다. 더 시도할 수 없으면 work와 가설을 함께 `FAILED`로 끝내고 final `VerificationResult`를 만들지 않는다.

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

proposal은 facts와 assumptions, restrictions, missing information, falsification questions, 고유 `validation_id`가 있는 `validation_checks`를 분리한다. confidence는 우선순위 힌트일 뿐 verdict가 아니다.

## 4. 운영 상시 찬반 검증과 평가 모드

```mermaid
flowchart TB
    HYP[VulnerabilityHypothesis plus ACTIVE assignment] --> CTX[On-demand context]
    CTX --> PURPOSE{Analysis purpose}
    PURPOSE -->|PRODUCTION| BUDGET{Pro and Con budget available}
    BUDGET -->|No| STOP[BUDGET_EXCEEDED no final verdict]
    BUDGET -->|Yes ALWAYS_DEBATE| FORK[Independent NEW sessions]
    PURPOSE -->|EVALUATION only| MODE{Comparison mode}
    MODE -->|BASIC| BASIC[Verification direct evidence evaluation only]
    MODE -->|CONDITIONAL_DEBATE| TRIGGER{Debate trigger present}
    MODE -->|ALWAYS_DEBATE| FORK
    TRIGGER -->|No and skip recorded| BASIC
    TRIGGER -->|Yes| FORK
    FORK --> PRO[Pro Agent]
    FORK --> CON[Con Agent]
    PRO --> SYN[Verification synthesis]
    CON --> SYN
    BASIC --> SYN
    BASIC -. no Gate Primitive or Reporter .-> METRICS[Evaluation metrics only]
    SYN --> INITIAL[Initial TRUE FALSE HOLD]
    INITIAL --> DYN{Verification chooses dynamic mode}
    DYN -->|No| FINAL[Final VerificationResult]
    DYN -->|Small question| LIMITED[Verification LIMITED Requirements and Plan]
    DYN -->|End to end| FULL[Verification FULL Requirements Plan and PoC draft]
    LIMITED --> AUTH[Runtime Validator call authorization]
    FULL --> AUTH
    AUTH --> CTRL[Sandbox Controller policy check]
    CTRL --> PDEC[Exact SandboxPolicyDecision]
    PDEC -->|Pass| ENV[Sandbox Runner prepares environment and Health Checks]
    PDEC -->|Policy blocked no Runner| ASSEMBLER[Sandbox Result Assembler]
    ENV --> CHECK{All required items MATCH}
    CHECK -->|Yes| RUNNER[Sandbox Runner executes exact attack steps]
    CHECK -->|No| EFAIL[Stop before attack with ENVIRONMENT_SETUP]
    EFAIL --> ASSEMBLER
    RUNNER --> ASSEMBLER
    ASSEMBLER --> DRESULT[Dynamic result with exact nullable refs]
    DRESULT --> EMIS{Required environment mismatch}
    EMIS -->|Yes| EREVIEW[R6 reviews exact differences]
    EMIS -->|No| SYN2[Verification re-synthesizes evidence]
    EREVIEW -->|New requirements plus plan or plan-only revision| AUTH
    EREVIEW -->|No retry| SYN2
    SYN2 --> FINAL
    FINAL --> OUT[Restrictions candidates PrimitiveDraft and VERIFICATION origin child proposals]
```

별도 endpoint·sink·권한 경계·impact 주장은 같은 verdict에 합치지 않고 새 가설로 보낸다.

## 5. Primitive DB와 Chaining admission

```mermaid
flowchart TB
    VR[Final VerificationResult] --> KIND{Verdict}
    KIND -->|FALSE| CLOSED[Terminal no Primitive no Chaining]
    KIND -->|HOLD| REQUIRED[Immediate REQUIRED with exact Verification ref]
    KIND -->|TRUE| CWE[CWE labeling]
    CWE --> TECH[Technical Evidence Gate]
    TECH -->|REVISE| SAME[Same assignment new Verification work and revision]
    SAME --> VR
    TECH -->|REJECT| NOCHAIN[No Chaining]
    TECH -->|ACCEPT| RULE[Rule Scope Impact Gate]
    RULE -->|FAIL UNCERTAIN DENY| NOCHAIN
    RULE -->|PASS PASS PASS SUFFICIENT ALLOW| PROVIDED[PROVIDED with exact Gate refs]
    REQUIRED --> PDB[(Primitive records)]
    PROVIDED --> PDB
    PDB --> INDEX[Current PrimitiveIndexState]
    INDEX --> MATCH{Upstream PROVIDED satisfies downstream requirement}
    MATCH -->|No| RECORD[ChainingResult no match or bounded stop]
    MATCH -->|Yes| CHAIN[Chaining Agent matching only]
    CHAIN --> NEW[HypothesisProposal origin CHAINING]
    NEW --> LIMIT{Runtime validation depth budget duplicate cycle}
    LIMIT -->|Pass| REGISTER[Global registration]
    LIMIT -->|Fail| STOP[Reject or bounded stop]
    REGISTER --> ORCH[Orchestration assigns Verification]
    ORCH --> VERIFY[Full Verification pipeline]
    VMAT[Verification material claim] --> VNEW[HypothesisProposal origin VERIFICATION]
    VNEW --> LIMIT
```

Primitive DB는 queue가 아니며 Chaining match와 child proposal은 Finding이 아니다. Gate 전 TRUE와 오래된 Gate revision은 ACTIVE PROVIDED가 될 수 없다.

## 6. 이중 LLM Gate와 사람 결정

```mermaid
flowchart TB
    VR[Final TRUE VerificationResult plus CWE] --> TECH[Technical Evidence Gate Agent]
    TECH --> TS{ACCEPT REVISE REJECT}
    TS -->|REVISE| BACK[Same hypothesis Verification owner]
    BACK --> VR
    TS -->|REJECT| BLOCK[Report blocked]
    TS -->|ACCEPT| RULE[Rule Scope Impact Gate Agent]
    POLICY[Official ProgramPolicyRecord] --> RULE
    NOPOL[Missing official policy] --> UNCERTAIN[Rule and scope UNCERTAIN permission DENY]
    UNCERTAIN --> BLOCK
    RULE --> READY{Review PASS Rule PASS Scope PASS Impact SUFFICIENT Permission ALLOW}
    READY -->|No| BLOCK
    READY -->|Yes| RREQ[Verification requests Reporter]
    RREQ --> REPORTER[Reporter Agent]
    REPORTER --> DRAFT[Internal ReportDraft]
    BLOCK --> SPACKET[Safe HumanReviewPacket report ready false with blocked reasons]
    DRAFT --> SAFE{Exact provenance restrictions and redaction valid}
    SAFE -->|Report content insufficient| BLOCK
    SAFE -->|Packet schema refs stale or redaction invalid| DENY[PREPARE HUMAN REVIEW denied]
    SAFE -->|Yes| PACKET[HumanReviewPacket current generation]
    SPACKET --> HUMAN
    PACKET --> HUMAN[Human Reviewer]
    HUMAN --> DECIDE[Separate HumanReviewDecision]
```

두 Gate 모두 LLM 검토 Agent이고 Verification verdict를 직접 바꾸지 않는다. 공식 정책이 없으면 Reporter 경로는 닫힌다. `ALLOW`와 `report_ready`는 사람 결정이 아니며, current packet의 `DISCLOSE` 결정도 외부 action 자체가 아니다.
두 Gate 모두 LLM 검토 Agent이고 Verification verdict를 직접 바꾸지 않는다. Technical Gate는 exact final `TRUE`만 검토하며 `FALSE | HOLD`와 실패 가설은 입력으로 받지 않는다. 공식 정책이 없으면 Reporter 경로는 닫힌다.

## 7. Provider, session과 logging

```mermaid
flowchart LR
    AGENT[Agent proposed invocation] --> ACTION[CALL LLM or Gate Reporter stage action]
    SPEC[Immutable LLMCallSpec] --> ACTION
    ACTION --> TRUST[Trusted Runtime Validator]
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
    FAIL[Explicit retry or failover] --> ACTION
```

provider/model과 실제 session 결정은 기록한다. trusted runtime이 허용 profile·budget·session policy를 검증하며 silent failover, credential logging과 hidden chain-of-thought 수집은 허용하지 않는다.

## 8. 결과·자원·디버깅 저장

```mermaid
flowchart LR
    STATIC[AST SAST facts] --> FACTS[(facts)]
    CONTEXT[Context retrieval] --> CONTEXTS[(contexts)]
    AGENTS[Hypothesis Verification Pro Con] --> RESULTS[(hypotheses and verifications)]
    DYNAMIC[Docker and PoC] --> DYNSTORE[(dynamic artifacts)]
    PR[Primitive and Chaining] --> PRSTORE[(primitives and chaining)]
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

## 9. 공통 식별자와 revision 추적

```mermaid
flowchart TB
    INPUT[Analysis request] --> ORCH[Orchestration Runtime]
    ORCH --> ANA[analysis_id]
    ANA --> RUNMETA[RunMeta before code binding]
    ANA --> LOADER[Repository Loader]
    LOADER -->|READY| WORK[workspace_id plus commit_id]
    ANA --> HYP[hypothesis_id]
    HYP --> REL[parent IDs root ID chain depth]
    HYP --> ATT[attempt_id]
    ATT --> CALL[llm_call_id]
    WORK --> META
    HYP --> META
    ATT --> META
    RUNMETA --> LOGICAL[logical_record_id]
    META[RecordMeta for code bound records] --> LOGICAL
    LOGICAL --> REC[record_id plus schema_version]
    REC --> REV[revision_number plus previous_record_id]
    REC --> DATA[stored_data_id plus content_hash]
    REV --> RUN[AnalysisRunResult]
    DATA --> RUN
```

clone 전 실행 기록은 `RunMeta`, 준비된 코드 근거는 `RecordMeta`를 사용한다. 시스템이 생성한 ID는 다른 대상에 재사용하지 않는다. 외부 Git ID인 `commit_id`는 같은 commit을 여러 분석에서 참조할 수 있다. 새 revision은 `logical_record_id`를 유지하고 새 `record_id`로 연결하며, chain 가설은 새 `hypothesis_id`를 사용한다.

## 10. 공통 실행 상태

```mermaid
stateDiagram-v2
    [*] --> PENDING
    PENDING --> READY: dependencies ready
    PENDING --> CANCELLED: cancelled
    READY --> RUNNING: start new attempt
    READY --> BLOCKED: prerequisite missing
    READY --> CANCELLED: cancelled
    RUNNING --> BLOCKED: retryable attempt failure
    RUNNING --> SUCCEEDED: full output committed
    RUNNING --> PARTIAL: partial output committed
    RUNNING --> FAILED: terminal failure
    RUNNING --> CANCELLED: cancelled
    BLOCKED --> READY: waiting condition resolved
    BLOCKED --> FAILED: cannot continue
    BLOCKED --> CANCELLED: cancelled
    SUCCEEDED --> [*]
    PARTIAL --> [*]
    FAILED --> [*]
    CANCELLED --> [*]
```

작업 상태는 전문 판정과 분리한다. retry 가능한 attempt 실패는 work를 `BLOCKED`로 두고, 조건을 해결한 뒤 새 `attempt_id`로 다시 시작한다. `SUCCEEDED | PARTIAL | FAILED | CANCELLED`는 되돌리지 않는다.

## 11. 중복 방지와 atomic 저장·복구

```mermaid
flowchart LR
    REQUEST[Work request] --> DEDUPE{Same dedupe key exists}
    DEDUPE -->|Yes| EXISTING[Return existing work and state]
    DEDUPE -->|No| READY[Create READY work]
    READY --> ATTEMPT[Start one active attempt]
    ATTEMPT --> RESULT[Worker submits result]
    RESULT --> VALIDATE{Attempt version input workspace commit match}
    VALIDATE -->|No| STALE[Reject and quarantine stale result]
    VALIDATE -->|Yes| PREPARED[TransitionCommit PREPARED]
    PREPARED --> COMMITTED[CAS append unique COMMITTED marker]
    COMMITTED --> POINTER[Project output ref and target state]
    POINTER --> NEXT[Allow downstream consumer]
    PREPARED -->|Version conflict or cancel| ABORTED[ABORTED and quarantine output]
    CRASH[Process restart] --> RECOVER[Read last COMMITTED marker and pointer]
    RECOVER -->|Valid PREPARED| COMMITTED
    RECOVER -->|Committed marker missing projection| POINTER
    RECOVER -->|Unsafe or inconsistent| STOP[TRANSITION INCOMPLETE or RECOVERY FAILED]
```

다음 단계는 `COMMITTED` marker와 상태 pointer가 같은 output을 가리킬 때만 읽는다. Verification `TERMINAL`, 두 Gate 완료와 Report `DRAFTED`는 각각 정확한 결과 `record_id`에 atomic하게 연결되어야 한다.

## 12. LLM 제안과 프로그램 실행 권한

```mermaid
flowchart LR
    INPUT[Repository LLM provider or sandbox output] --> UNTRUSTED[Untrusted data]
    AGENT[Agent or service proposal] --> REQUEST[ActionRequest]
    STAGE[Gate or Reporter stage action includes LLM call] --> REQUEST
    UNTRUSTED --> REQUEST
    SPEC[Exact LLMCallSpec for every LLM action] --> REQUEST
    REQUEST --> UNIQUE{Decision already exists for action ref}
    UNIQUE -->|Yes| EXISTING[Return existing ActionDecision]
    UNIQUE -->|No| CHECK{Runtime Validator required checks}
    CHECK -->|Any FAIL| DENY[ActionDecision DENY]
    DENY --> ERROR[AnalysisError and no execution]
    ERROR --> KEEP[Do not change domain verdict]
    CHECK -->|All PASS| ALLOW[ActionDecision ALLOW UNUSED]
    ALLOW --> CLAIM{CAS claim UNUSED to USED}
    CLAIM -->|Conflict or stale| REJECT[Expire and reject replay or stale action]
    CLAIM -->|Claimed| EXECUTE[Execute exact action once]
    EXECUTE --> OUTCOME[Store outcome refs and state transition]
    DOMAIN[Verification Gates Reporter Human keep domain decisions] -. not decided by validator .-> CHECK
```

Runtime Validator는 schema·권한·ID·revision·상태·예산·일반 도구·경로·provider·Gate 순서·Reporter·redaction·공개 전제를 검사한다. `RUN_SANDBOX`에서는 호출 권한·상태·예산·exact plan reference까지만 확인하고, image·command·file·network·resource·cleanup 정책은 Sandbox Controller가 검사한다. 취약점 진위, CWE, 정책 의미와 보고서 내용은 판단하지 않는다.

## 13. 사람 검토와 외부 공개 경계

```mermaid
flowchart TB
    RUN[Final AnalysisRunResult] --> PACKET[HumanReviewPacket]
    FIND[Findings verification and evidence] --> PACKET
    GATES[Technical and Rule Scope Gate refs] --> PACKET
    DYNAMIC[Dynamic results and redacted PoC] --> PACKET
    RESOURCE[Resources errors gaps and HOLD] --> PACKET
    REPORT[ReportDrafts or blocked reasons] --> PACKET
    PACKET --> CURRENT[HumanReviewState current packet generation]
    CURRENT --> HUMAN[Human Reviewer]
    HUMAN --> SAVE[Validated SAVE HUMAN DECISION action]
    SAVE --> DECISION[HumanReviewDecision]
    DECISION --> STATE[CAS current decision into HumanReviewState]
    STATE --> KIND{DISCLOSE REVISE WITHHOLD or MORE VALIDATION}
    KIND -->|REVISE or MORE VALIDATION| RETURN[Return to allowed analysis stage]
    KIND -->|WITHHOLD| STOP[Keep internal]
    KIND -->|DISCLOSE| DISCLOSE{Still current packet decision report ready and upstream refs}
    DISCLOSE -->|No| BLOCK[DISCLOSURE DENIED]
    DISCLOSE -->|Yes| BOUNDARY[External disclosure action boundary]
    AGENT[Agent Gate or Reporter] -->|Cannot save human decision or disclose| BLOCK
```

사람 결정은 ReportDraft와 분리한다. 새 packet generation은 이전 결정을 supersede한다. 실제 자동 제출 integration은 이 설계에 포함하지 않으며, 향후 추가해도 current `DISCLOSE` 결정과 redaction 검사를 건너뛸 수 없다.

## Rendering check

이 문서는 Mermaid 블록 13개를 포함한다. Wiki diagrams 페이지는 이 파일과 동일한 Mermaid 블록을 사용하며 최종 검증에서 13개 SVG와 parse error 0개를 확인한다.
