# R3-02. 파트 간 계약 준수·부정 테스트 계획

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**
>
> 정상·실패 입력을 어떻게 검사할지 정리한 **검토용 설계 초안**이다. 이 문서에 적은 fixture, 검사기, 자동 테스트와 실제 Provider·Sandbox 실행은 아직 구현·실행하지 않았다. 문서 검사 통과는 프로그램 시험 통과가 아니다.

## 1. 목적·기준·권한

- R3 역할 담당: 윤희섭 (@YHS-Sec, 표시 닉네임 @v1sion).
- 공통 아키텍처 검토·대행 수행: 김태현 (@taehyeon-git). 다른 담당자가 작성한 PR을 R3 본인의 구현 실적으로 표시하지 않는다.
- 상위 [#4](https://github.com/SASTsimi/sastsimi/issues/4), 본 작업 [#25](https://github.com/SASTsimi/sastsimi/issues/25), 선행 [#24](https://github.com/SASTsimi/sastsimi/issues/24), 후속 [#89](https://github.com/SASTsimi/sastsimi/issues/89)·[#92](https://github.com/SASTsimi/sastsimi/issues/92).
- 작성·대조 기준 main: `750287e4ae103129c4f53548ff5bc336cc467386` (2026-09-07 조회).
- 선행 정본: [01-module-map.md](01-module-map.md). 현재 파이프라인은 **22단계**다. 옛 23단계 댓글을 그대로 구현하지 않는다.
- [#25 작성 범위 댓글](https://github.com/SASTsimi/sastsimi/issues/25#issuecomment-5556392596)을 문서화하며, 이전 `db1ec85` 댓글의 OK/BAD 이력은 §7에서 연결한다.
- main 이후 변경이나 미병합 PR을 확정 계약으로 취급하지 않는다. 아래 PR 묶음에서는 #96으로 병합된 Provider 계약과 아직 미병합인 #97 Prompt 제안을 구분한다.

여기서 **계약**은 모듈이 데이터를 주고받을 때 지켜야 할 형식·의미·권한·순서의 약속이다. **fixture**는 테스트에 넣을 예제 데이터, **producer/consumer**는 데이터 생산자/소비자, **current pointer**는 현재 유효한 결과를 가리키는 연결이다. **revision**은 같은 논리 기록의 새 버전, **attempt**는 같은 작업의 한 번의 실행 시도다. **CAS**는 예상한 상태 버전과 실제 저장 버전이 같을 때만 변경하는 검사다. **atomic commit**은 결과와 상태를 일부만 성공시키지 않고 하나의 확정 경계로 처리하는 것이다.

R3는 입력·검사·예상 결과를 구체화한다. 새로운 schema·enum·오류 코드·취약점 판단·Gate 의미를 단독 결정하지 않는다. 공통 계약은 R4, 전문 의미는 해당 owner, 예산 정책은 R8의 검토를 받는다.

### 1.1 근거 정본과 우선순위

1. 전체 순서: [01 시스템 개요](../01-system-overview.md).
2. 데이터·권한·상태·참조: [08 경량 데이터 계약](../08-lightweight-data-contracts.md), [10 보안 경계](../10-security-boundaries.md).
3. 전문 의미: [02 정적 사실](../02-static-fact-layer.md), [03 역할·등록](../03-agent-roles-and-orchestration.md), [04 검증·재현](../04-verification-and-dynamic-reproduction.md), [05 Gate·Finding·보고](../05-llm-gate-and-reporting.md), [06 Chaining](../06-chaining.md), [07 결과·예산](../07-results-and-observability.md), [09 LLM 호출](../09-llm-provider-session-and-logging.md), [12 보고서 형식](../12-report-draft-template.md).
4. module map의 진입점은 논리 이름이다. 실제 Python package·DB·artifact 위치는 #92에서 확정한다. 본 문서의 논리 저장 영역을 DB 테이블명으로 간주하지 않는다.
5. 정본끼리도 모순이 남으면 유리한 문장을 골라 구현하지 말고 §8 질문으로 연결한다.

이 문서의 상태·시험 ID·fixture 별명·Q 번호는 **문서 관리 표기**이며 runtime의 새 enum이나 schema가 아니다.

### 1.2 최신 main에서 반영한 변화

| 변경 근거 | 시험 계획에 반영한 내용 |
|---|---|
| [#93](https://github.com/SASTsimi/sastsimi/pull/93) | HOLD 후보가 빈 배열이면 Primitive/Chaining work 없이 정상 종료 |
| [#100](https://github.com/SASTsimi/sastsimi/pull/100) | R7 lifecycle·실행/cleanup 기록과 같은 attempt의 연결 |
| [#101](https://github.com/SASTsimi/sastsimi/pull/101) | FINDING_NORMALIZE·FindingIndexState·CAS; Finding 생성과 Reporter 자격 분리 |
| [#102](https://github.com/SASTsimi/sastsimi/pull/102) | 자식 결과를 부모 verdict/impact에 흡수하지 않음 |
| [#103](https://github.com/SASTsimi/sastsimi/pull/103) | 자식 등록 전 시작점 검사와 Context 조회 시 exact 부모 reference 검사 구분 |
| [#105](https://github.com/SASTsimi/sastsimi/pull/105) | match triple 중복 key, trigger/pool 처리 책임, 구조화 no_match_reasons |
| [#109](https://github.com/SASTsimi/sastsimi/pull/109) | Primitive admission을 등록 시점 1회 판정으로 확정하고 등록 뒤 재판정·회수 절차 제거 |
| [#60](https://github.com/SASTsimi/sastsimi/pull/60) | token 계획값을 사용량 중단 상한으로 쓰지 않음; R7 입장 정책과 R8 lifecycle 분리 |
| [#113](https://github.com/SASTsimi/sastsimi/pull/113) | Dynamic Reproduction Agent 명칭, program policy의 감사 전용 연결, SandboxProfile 외부 경계와 새 generation 규칙 |
| [#96](https://github.com/SASTsimi/sastsimi/pull/96) | ProviderProfile·CapabilityTestResult·API/공식 구독 인증 경로·runtime tool-loop 지원 판정 계약 |
| [main@6122567](https://github.com/SASTsimi/sastsimi/commit/6122567c7203c5fb601d795db9a8bc0ee1606aeb) | `Orchestration Runtime`을 비-LLM 구성요소로 확정하고 Hypothesis Agent·Verification Agent와 권한 분리 |
| [main@ba9e6e7](https://github.com/SASTsimi/sastsimi/commit/ba9e6e7a36b1abb58413d584ecf390055b779376) | Hypothesis Agent·CWE Labeling Agent·두 Gate 등 구성요소 공식 이름과 LLM/비-LLM 구분 통일 |
| [main@750287e](https://github.com/SASTsimi/sastsimi/commit/750287e4ae103129c4f53548ff5bc336cc467386) | 비-LLM Docker 실행 구성요소를 `Reproduction Setup Automation`·`REPRODUCTION_SETUP_AUTOMATION`으로 통일 |

ADR의 자체 승인 상태와 PR 병합 여부는 별개다. 예를 들어 #105 관련 ADR-012의 PROPOSED 표기를 본 문서가 ACCEPTED로 바꾸지 않는다.

## 2. 시험 작성·실행 규칙

### 2.1 ID·계층·증거

ID는 `R3-CT-<묶음>-<세 자리 번호>`이며 삭제된 번호를 다른 의미로 재사용하지 않는다. 각 card의 13개 항목은 #25 요구사항에 대응한다. 여러 변형이 있으면 실행 구현 시 해당 ID에 `/variant-name`을 붙여 **각 변형을 독립 시험**한다. 한 case에 한두 변형만 통과하고 전체 통과로 표시하지 않는다.

- unit: 순수 hash/집합/상태 검사 같은 작은 단위.
- contract: 생산·소비 데이터의 형식과 의미.
- integration: 여러 모듈·저장 경계 연결.
- E2E: fake 도구로 시작부터 내부 결과 확정까지 연결.
- security-negative: 권한·비밀·경로·참조 우회를 의도적으로 시도.

모든 case는 현재 **미실행**이다. 아래 ‘기대’는 관찰된 시험 결과가 아니다. fake adapter는 외부 네트워크·실계정·host 명령을 실행하지 않고 정해진 응답/호출 기록을 반환해야 한다. 실계정/실제 Sandbox 시험은 별도 승인 환경과 #90·R7 capability 판정 뒤 수행한다.

### 2.2 정상·실패의 공통 판정 기준

- 호출 전 차단은 adapter/controller 호출 횟수 0으로 확인한다. 결과 제출 차단은 output/current pointer 변화 0으로 확인한다.
- 부정 입력을 거절했다는 사실만으로 기존 정상 work·가설을 임의 FAILED/FALSE로 바꾸지 않는다. 실제 실행 오류에 따른 상태 전이는 해당 case의 규칙을 따로 적용한다.
- 한 record의 attempt는 그 **생산 work의 attempt**다. Pro와 Con, R6 요청과 R7 실행처럼 서로 다른 work의 attempt ID를 전부 같게 요구하지 않는다.
- generation은 실제 work/가설/CWE 계약으로 확인한다. 편의를 위해 RecordMeta에 없는 generation 필드를 추가하지 않는다.
- run/debug에 허용된 RunStoredDataRef를 코드·검증·Gate evidence로 승격하지 않는다. StoredDataRef가 가리키는 record를 해석해 meta.analysis_id까지 확인한다.
- current를 요구하는 입력은 정확한 current revision을 확인한다. historical provenance·진행 work의 고정 application까지 최신 게시본으로 교체하지 않는다.
- 거절·stale artifact는 history/감사 목적 보존과 downstream 유효성에서의 제외를 구분한다. secret이 있는 원문은 감사 명목으로 남기지 않는다.
- 실행 오류·정보 부족·예산 소진은 FALSE의 근거가 아니다. 정상 검증 완료와 실제 반증이 있는 FALSE, 정상 관측이 불충분한 HOLD는 허용되는 전문 판정이다.
- 미정 오류에 적은 `Q-02`는 오류 코드가 아니다. 의미·차단 여부는 정리하되 정확한 코드가 미정인 case를 자동 시험 구현 완료로 표시하지 않는다.

### 2.3 계획 fixture의 정확한 참조 규칙

아래 R-A/W-A/C-A/r1/h1 같은 문자열은 **설계 별명**이지 실제 schema-valid ID/hash/commit 값이 아니다. 아직 JSON fixture 파일이나 schema registry는 생성하지 않았다.

구현할 때 fixture manifest에 다음 정보를 고정한다.

1. 실제 분석/작업/시도/가설 ID와 실제 테스트 저장소의 commit SHA.
2. 논리 별명→record_id·logical_record_id·schema_version·revision_number·previous_record_id.
3. StoredDataRef의 stored_data_id·data_kind·record_id·content_hash·workspace_id·commit_id.
4. 원본 bytes를 승인된 canonical serialization으로 hash한 값. content_hash 필드를 포함한 순환 hash를 만들지 않는다.
5. work input_refs/input_hash·current output·TransitionCommit·StateTransition·state_version 연결.
6. provider/model/prompt/playbook/budget/sandbox exact profile refs와 승인 상태.
7. 정상 기준 fixture가 먼저 schema/semantic 검사를 통과한 뒤, 부정 시험은 지정한 값만 한 번에 변경.
8. state/DB/artifact/외부 호출 전후 비교 자료. 이전 시험 잔여 state를 다음 시험에 공유하지 않음.

정확한 serialization/필드별 오류/저장 경계가 없는 부분은 Q-01~Q-04를 해결한 뒤 executable fixture를 만든다. 본 문서에 예제 fixture가 있다고 실제 테스트 데이터를 만들었다고 보고하지 않는다.

- **F-COM (공통 참조·상태·저장)**: 독립 run R-A, 준비된 workspace W-A/commit C-A, 가설 H-A(해당 시험에 필요할 때만), consumer work K-A(RUNNING, active_attempt=A-A, state_version=v). ref R1은 immutable record r1/hash h1, COMMITTED marker와 producer output이 같은 r1을 가리킨다. 이전 r0는 history에만 있다.
- **F-STA (저장소·정적 분석·Context)**: run R-A, CodeWorkspace W-A/C-A가 READY. AST/CodeQL/OpenGrep는 K-AST/K-CQL/K-OG와 서로 다른 attempt를 사용한다. 각 raw artifact·ToolRunResult·규칙 도구의 RuleExecutionRecord가 같은 workspace/commit과 자기 도구 attempt에 연결된다. 정규화 bundle B1, Context 요청 QCTX1/응답 CTX1/fragment X1은 이 코드 범위를 사용한다. 아직 가설이 없는 정적 단계에서는 hypothesis_id=null.
- **F-HYP (가설 등록·배정)**: current COMMITTED StaticFactBundle B1과 INITIAL proposal candidate HP1, exact 근거 refs·질문·제약·missing information을 준비한다. 등록 뒤 H-A와 ACTIVE Assignment AS1이 생긴다. Verification 등록은 H-A/HP1/PlaybookPolicy PP1/VerificationPlaybook PB1을 고정하고 PlaybookApplication PA1을 생성한다. 각 시험은 등록 전/후 중 본문이 지정한 지점에서 시작한다.
- **F-LLM (Prompt·Provider·session·권한)**: 정상 역할 HYPOTHESIS의 consumer work K-H/active attempt A-H. exact template/payload P1/LLMCallSpec S1/ProviderProfile PV1 및 ALLOW 후 USED decision AD1을 준비한다. 실제 outbound request O1은 S1과 필드별 동일하다. fake adapter는 미리 정한 성공/실패 응답만 반환한다. PR97의 Registry 세부 필드는 F-PR에서만 사용한다.
- **F-VER (Pro/Con·최종 판정·REVISE)**: ACTIVE owner AS1, hypothesis H-A=VERIFYING, VERIFICATION work KV1/generation G1, 같은 고정 B1/CTX1/PP1/PB1/PA1 및 versioned debate 설정 DP1. 기본 run은 `purpose=PRODUCTION`, `verification_mode=ALWAYS_DEBATE`, `debate_triggers=[]`, `debate_skip_reason=null`이다. PRO work KP1/attempt AP1/session SP1과 CON KC1/AC1/SC1은 서로 다르며 common input hash DH1만 동일하다. 각각의 result EPRO1/ECON1은 자기 work의 COMMITTED output. final TRUE용 DX1/POC1은 F-DYN의 정상 chain이다. 평가 변형은 별도 `purpose=EVALUATION` run과 비어 있지 않은 exact `eval_config_refs`를 사용하며 운영 결과와 섞지 않는다.
- **F-DYN (동적 재현·Sandbox·PoC)**: H-A의 verification generation G1 아래 R6가 만든 exact DynamicReproductionRequest DQ1과 단 하나의 DYNAMIC_REPRO work KD1을 준비한다. 현재 attempt ADYN1에서 Dynamic Reproduction Agent는 requirements ER1·plan PL1·candidate PC1·동적 관측 해석을 만들고, Reproduction Setup Automation은 recipe RC1·image/container 환경 ENV1·CleanupResult CL1을 만든다. Sandbox Controller는 exact SandboxProfile SP1의 host·Docker·mount·namespace·secret·egress·workspace 외부 경계를 검사한 SandboxPolicyDecision SPD1을 만들며, Reproduction Session Manager는 append-only AgentLog LOG1·validated PoC POC1·DynamicReproductionResult DX1을 확정한다. RunPolicyState RPS1은 RUN_SANDBOX 시점의 감사 reference로만 기록하고 KD1 불변 입력이나 Controller 허가 조건에 넣지 않는다. 각 record의 producer identity와 result-owner registry가 이 구분과 같고 candidate·command·environment·관찰·SandboxProfile·cleanup은 같은 work/attempt로 연결된다. R6 request의 producer attempt와 동적 재현 실행 attempt를 같다고 강요하지 않는다. recipe baseline 재사용은 새 attempt binding과 previous environment를 따로 검사한다.
- **F-GAT (CWE·두 Gate·정책·Finding)**: H-A TERMINAL, exact final TRUE V1, current generation DX1(SUCCEEDED,SUPPORTED)/POC1, V1을 직접 가리키는 current CWELabel CW1. 실행 시작 때 `POLICY_FETCH`가 확정한 current RunPolicyState RPS1은 COL1과 POL1을 가리킨다. Technical TG1은 V1/CW1을 가리키고 `status=ACCEPT`, `handoff_readiness=READY`와 비어 있지 않은 네 검토 설명을 가진다. 그 뒤 RuleScope RS1은 같은 V1/CW1/TG1/RPS1/COL1/POL1 chain을 참조하고 각 정책 판정을 exact `PolicyItem`·공식 원문 위치·실행 근거에 연결한다. 기본 COL1=FOUND/ProgramPolicyRecord POL1 존재. 기본 RS1 6축은 PASS/PASS/PASS/PASS/SUFFICIENT/ALLOW. 각 case가 지정한 완료 직전부터 시작한다.
- **F-CHN (Primitive·Chaining·자식)**: 같은 R-A/W-A/C-A의 가설 HA(TRUE)와 HB(HOLD), 각각 current Primitive PRA(result 있음)/PRB(inputs 있음,result=null), initial origins. PRA는 Technical ACCEPT와 current ALLOW admission ADA를 가진다. PrimitiveUpdate COMMITTED 뒤 trigger/index refs를 고정한 CHAINING work KCH1(RUNNING/active ACH1), pair PRA.result→PRB.inputs의 draft_id를 matched_input_id로 사용한다. ancestor 추가 변형에는 source match와 parent hypothesis/result를 모두 연결한다.
- **F-REP (Reporter·집계·사람 경계)**: F-GAT 정상 closure에서 trusted Finding normalization이 만든 current Finding FN1 및 FindingIndexState FI1. Reporter가 참조하는 V1/CW1/TG1/RS1/COL1/POL1/DX1/POC1이 모두 동일. ReportDraft 후보 RD1에 restriction/limitation/provenance 보존. 기본 종료 run에는 RUNNING work/미복구 PREPARED/잘못된 pointer가 없고 다른 실패도 없다. 변형마다 필요한 부분만 변경한다.
- **F-BUD (예산·관측성)**: AnalysisRunState 시작 때 versioned eval_config_refs ESET1 고정. 작업 ActionDecision.checked_config_refs는 필요한 정확한 부분집합, budget/lifecycle/sandbox profile은 각각 별도 ref. monotonic 실행 시간과 provider가 공개한 usage만 입력한다. token 계획값과 실제 사용량, R7 입장 보호 설정과 R8 실행 lifecycle 한도를 분리한다. 정책 변형에는 program/source/Parser/freshness 설정이 정확히 맞고 run 시작 시 유효한 PolicyCacheRecord PCACHE1과, 별도 cache miss·만료·설정 불일치·closure 손상 fixture를 사용한다. Collect·Parse 재시도 횟수는 fixture가 고정한 versioned R8 설정을 따른다.
- **F-PR (Provider main·미병합 Prompt 제안 시험)**: 기준 main의 #96 ProviderProfile·capability·runtime tool-loop 계약에 #97 HEAD `a9fd2e14edb9f52465947151e0208718a42d83e7`이 제안한 Prompt Registry·assessment slot을 덧붙인 계획 fixture다. 실행할 때 main과 #97의 exact SHA를 fixture manifest에 기록하며 서로 다른 revision을 섞지 않는다. Provider 계약이 main에 있다는 사실은 실제 adapter/profile/template/schema/validator가 구현·지원된다는 뜻이 아니며, #97 전용 필드는 병합 전 main 합격 조건으로 승격하지 않는다.

## 3. 22단계 coverage 색인

이 표는 계획의 연결표이며 실행 coverage 수치가 아니다.

| 단계 | 확인 대상 | 계획 ID 묶음 |
|---|---|---|
| 1 | 분석 시작·설정·run identity | COM-001~004, BUD-003~005 |
| 2 | clone/checkout·READY | STA-001 |
| 3 | AST/SAST·정책 준비 병렬 실행 이력 | STA-002~005, BUD-004~005 |
| 4 | 정규화·오류/gap 합류 | STA-002~006, COM-011~013 |
| 5 | 초기 work 등록·고정 입력 | HYP-001~002 |
| 6 | Hypothesis 호출 | LLM-001~008 |
| 7 | proposal 검증·중복·등록 | HYP-001~004 |
| 8 | Verification 배정·application·운영 mode preflight | HYP-001/005, VER-001/008 |
| 9 | Context·자식 계보 | STA-006~007, CHN-008 |
| 10 | Pro/Con 정책·독립·합류 | VER-001~004, VER-008~011 |
| 11 | initial 판단·동적 요청 | VER-006/009/011, DYN-001~002; PR-002의 Prompt 부분은 제안 |
| 12 | R7 동적 실행·정책·PoC·container lifecycle | DYN-001~012; PR-001의 Provider 조건은 main, PR-005의 Prompt 부분은 제안 |
| 13 | 최종 판정·근거 집합 완전성 | VER-005~006, VER-009~013 |
| 14 | FALSE/HOLD/TRUE 분기·CWE | CHN-001, GAT-001~003 |
| 15 | Technical Gate | GAT-001~003, GAT-009 |
| 16 | REVISE 새 generation | VER-007 |
| 17 | 정책·Rule Scope·admission | GAT-004~006, GAT-010, BUD-004~005 |
| 18 | Primitive·Chaining | CHN-001~007; PR-003~004 미병합 제안 |
| 19 | Finding 정규화·보고 자격 | GAT-007~008, GAT-011, REP-002 |
| 20 | 새 material child 등록 | HYP-001~004, CHN-008~009 |
| 21 | ReportDraft | REP-001~004 |
| 22 | 집계·자동화 종료 | REP-001/005, COM-006/012, BUD-003~005 |

표의 축약 ID 앞에는 모두 `R3-CT-`를 붙인다. 식별자·상태·권한·비밀·예산 검사는 해당되는 모든 단계에 공통 적용한다.

## 4. main 기준 시험 card

### COM. 공통 참조·상태·저장

근거: 08·10. 모든 사례는 **미실행 / 역할 검토 필요**.

#### R3-CT-COM-001 — 정확한 record 참조 정상 전달

- **1. ID·유형·설명**: R3-CT-COM-001 / 정상 / 정확한 record 참조 정상 전달
- **2. 단계·계약 경계**: 1–22 공통; 공통 참조·상태·저장
- **3. producer → consumer**: 각 모듈의 명시된 record producer → 다음 consumer / State Store
- **4. 선행 상태·exact refs**: F-COM(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: F-COM의 정상 ref를 그대로 소비한다.
- **6. 검사 주체**: schema validator + Runtime Validator + State Store
- **7. 허용·차단·격리 기대**: record_id와 hash가 같은 immutable record로 해석되고 다음 처리 허용.
- **8. work·attempt·가설 기대**: 소비 중인 work/attempt RUNNING 유지; 읽기만으로 가설 상태 변화 없음.
- **9. 오류·DataGap 기대**: 없음
- **10. 저장·갱신 금지 pointer**: 읽기 action/trace만 저장; 원본 record·current pointer 불변.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R4; 적용 모듈 owner. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-COM-002 — 다른 작업 범위 데이터 혼합

- **1. ID·유형·설명**: R3-CT-COM-002 / 부정 / 다른 작업 범위 데이터 혼합
- **2. 단계·계약 경계**: 1–22 공통; 공통 참조·상태·저장
- **3. producer → consumer**: 각 모듈의 명시된 record producer → 다음 consumer / State Store
- **4. 선행 상태·exact refs**: F-COM(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 정상 fixture에서 analysis_id, workspace_id, commit_id, hypothesis_id, generation을 각각 하나씩 다른 값으로 교체한다. hypothesis-local record에만 hypothesis 일치를 요구한다.
- **6. 검사 주체**: schema validator + Runtime Validator + State Store
- **7. 허용·차단·격리 기대**: 각 변형을 독립 실행해 호출/저장 거절. 정책 등 비종속 record의 hypothesis_id=null은 이 실패에 넣지 않는다.
- **8. work·attempt·가설 기대**: 거절 자체로 정상 work·가설을 종료하지 않음; 기존 active attempt/현재 결과 유지.
- **9. 오류·DataGap 기대**: generation 혼합 STALE_RESULT; 나머지 검사별 오류 매핑 Q-02
- **10. 저장·갱신 금지 pointer**: 거절 근거와 변형 필드를 안전한 trace로 기록; 모든 domain output/current pointer 갱신 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R4; 적용 모듈 owner. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-COM-003 — 없는 record·손상 hash·옛 revision

- **1. ID·유형·설명**: R3-CT-COM-003 / 부정 / 없는 record·손상 hash·옛 revision
- **2. 단계·계약 경계**: 1–22 공통; 공통 참조·상태·저장
- **3. producer → consumer**: 각 모듈의 명시된 record producer → 다음 consumer / State Store
- **4. 선행 상태·exact refs**: F-COM(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 각각 record_id를 없는 것으로 변경, content_hash 한 글자 변조, current를 요구하는 slot에 이전 revision 연결.
- **6. 검사 주체**: schema validator + Runtime Validator + State Store
- **7. 허용·차단·격리 기대**: 없는 record를 합성하지 않고 불일치 차단. history 조회와 current 소비를 구분.
- **8. work·attempt·가설 기대**: 작업/시도/가설의 유효 상태 유지; 소비 진행 금지.
- **9. 오류·DataGap 기대**: RECORD_REVISION_MISMATCH 또는 STALE_RESULT는 해당 규칙에 따라 적용; not-found/hash 세부 Q-02
- **10. 저장·갱신 금지 pointer**: 수정된 domain record를 저장하지 않음; 원본·history 보존; 거절 log.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R4; 적용 모듈 owner. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-COM-004 — 필수 값·닫힌 enum·schema MAJOR

- **1. ID·유형·설명**: R3-CT-COM-004 / 부정 / 필수 값·닫힌 enum·schema MAJOR
- **2. 단계·계약 경계**: 1–22 공통; 공통 참조·상태·저장
- **3. producer → consumer**: 각 모듈의 명시된 record producer → 다음 consumer / State Store
- **4. 선행 상태·exact refs**: F-COM(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: RecordMeta.record_id 누락, WorkExecutionState.status에 정의 밖 값 삽입, 지원하지 않는 schema MAJOR를 각각 독립 입력한다.
- **6. 검사 주체**: schema validator + Runtime Validator + State Store
- **7. 허용·차단·격리 기대**: schema 검사에서 차단. schema 밖 enum을 자동 정상값으로 바꾸거나 구 MAJOR를 묵시 변환하지 않음.
- **8. work·attempt·가설 기대**: 호출 전 거절; 기존 work/attempt/가설 불변.
- **9. 오류·DataGap 기대**: 미지원 MAJOR: SCHEMA_UNSUPPORTED; 필수 값/enum 세부 Q-02
- **10. 저장·갱신 금지 pointer**: 검증 실패 log만; invalid record/current pointer 생성 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R4; 적용 모듈 owner. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-COM-005 — RunStoredDataRef를 코드 근거로 사용

- **1. ID·유형·설명**: R3-CT-COM-005 / 부정 / RunStoredDataRef를 코드 근거로 사용
- **2. 단계·계약 경계**: 1–22 공통; 공통 참조·상태·저장
- **3. producer → consumer**: 각 모듈의 명시된 record producer → 다음 consumer / State Store
- **4. 선행 상태·exact refs**: F-COM(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 코드 evidence slot의 StoredDataRef를 run/debug용 RunStoredDataRef로 바꾼다.
- **6. 검사 주체**: schema validator + Runtime Validator + State Store
- **7. 허용·차단·격리 기대**: 근거로 사용 차단. run/debug 집계에 적법한 RunStoredDataRef 사용은 별개 허용.
- **8. work·attempt·가설 기대**: 소비 단계 시작 또는 저장 차단; 가설 판정 불변.
- **9. 오류·DataGap 기대**: reference kind 검사 오류 Q-02
- **10. 저장·갱신 금지 pointer**: run/debug 기록은 보존하되 code evidence와 결과 pointer에 연결 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R4; 적용 모듈 owner. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-COM-006 — PREPARED·ABORTED 결과 소비 차단

- **1. ID·유형·설명**: R3-CT-COM-006 / 부정 / PREPARED·ABORTED 결과 소비 차단
- **2. 단계·계약 경계**: 1–22 공통; 공통 참조·상태·저장
- **3. producer → consumer**: 각 모듈의 명시된 record producer → 다음 consumer / State Store
- **4. 선행 상태·exact refs**: F-COM(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 서로 다른 변형으로 output commit marker를 PREPARED 또는 ABORTED로 둔다.
- **6. 검사 주체**: schema validator + Runtime Validator + State Store
- **7. 허용·차단·격리 기대**: COMMITTED가 아니면 다음 단계가 읽어 유효 결과로 사용하지 못함.
- **8. work·attempt·가설 기대**: 현재 유효 work/attempt 상태 유지; PREPARED는 #89 복구 대상.
- **9. 오류·DataGap 기대**: commit-state 거절 코드 Q-02
- **10. 저장·갱신 금지 pointer**: journal/artifact는 증거로 보존; current output/후속 work 등록 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R4; 적용 모듈 owner. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-COM-007 — 취소되거나 과거 시도의 늦은 결과

- **1. ID·유형·설명**: R3-CT-COM-007 / 부정 / 취소되거나 과거 시도의 늦은 결과
- **2. 단계·계약 경계**: 1–22 공통; 공통 참조·상태·저장
- **3. producer → consumer**: 각 모듈의 명시된 record producer → 다음 consumer / State Store
- **4. 선행 상태·exact refs**: F-COM(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 현재 attempt=a2; a1의 지연 응답을 제출한다. 별도 변형은 취소된 a1 응답이다.
- **6. 검사 주체**: schema validator + Runtime Validator + State Store
- **7. 허용·차단·격리 기대**: 결과 제출 시 active attempt 검사로 거절하고 감사용으로 격리.
- **8. work·attempt·가설 기대**: a2 상태 유지; CANCELLED인 종료 work를 되살리지 않음; 가설 verdict 생성 없음.
- **9. 오류·DataGap 기대**: ATTEMPT_NOT_ACTIVE / STALE_RESULT: 제출/소비 경계별 적용
- **10. 저장·갱신 금지 pointer**: 늦은 invocation과 거절 사유만 보존; a1 output을 current로 연결 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R4; 적용 모듈 owner. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-COM-008 — 동시에 두 attempt claim

- **1. ID·유형·설명**: R3-CT-COM-008 / 부정 / 동시에 두 attempt claim
- **2. 단계·계약 경계**: 1–22 공통; 공통 참조·상태·저장
- **3. producer → consumer**: 각 모듈의 명시된 record producer → 다음 consumer / State Store
- **4. 선행 상태·exact refs**: F-COM(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 같은 READY work/state_version에 worker A/B가 동시 START_ATTEMPT를 시도한다.
- **6. 검사 주체**: schema validator + Runtime Validator + State Store
- **7. 허용·차단·격리 기대**: CAS 한 건만 성공; active attempt는 정확히 하나.
- **8. work·attempt·가설 기대**: 승자 RUNNING/active attempt 하나; 패자 새 active 상태 없음; 가설 불변.
- **9. 오류·DataGap 기대**: STATE_VERSION_CONFLICT
- **10. 저장·갱신 금지 pointer**: 승자 transition/attempt만 유효 확정; 패자 충돌 log, 두 번째 active pointer 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R4; 적용 모듈 owner. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-COM-009 — ActionDecision 재사용·요청자 위조

- **1. ID·유형·설명**: R3-CT-COM-009 / 부정 / ActionDecision 재사용·요청자 위조
- **2. 단계·계약 경계**: 1–22 공통; 공통 참조·상태·저장
- **3. producer → consumer**: 각 모듈의 명시된 record producer → 다음 consumer / State Store
- **4. 선행 상태·exact refs**: F-COM(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 이미 USED된 decision을 다시 사용하거나 인증 identity와 requested_by를 다르게 제출한다.
- **6. 검사 주체**: schema validator + Runtime Validator + State Store
- **7. 허용·차단·격리 기대**: 중복 부작용과 권한 위조 차단; LLM의 자기 역할 주장으로 권한 인정하지 않음.
- **8. work·attempt·가설 기대**: 기존 work/attempt/가설 유지; 새 도구/LLM 실행 없음.
- **9. 오류·DataGap 기대**: ACTION_NOT_ALLOWED; identity 세부 Q-02
- **10. 저장·갱신 금지 pointer**: 거절 action/trace; 두 번째 provider request·domain output 생성 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R4; 적용 모듈 owner. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-COM-010 — 종료 상태 재개·version 충돌

- **1. ID·유형·설명**: R3-CT-COM-010 / 부정 / 종료 상태 재개·version 충돌
- **2. 단계·계약 경계**: 1–22 공통; 공통 참조·상태·저장
- **3. producer → consumer**: 각 모듈의 명시된 record producer → 다음 consumer / State Store
- **4. 선행 상태·exact refs**: F-COM(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: SUCCEEDED/FAILED/CANCELLED work를 RUNNING으로 되돌리거나 expected_state_version을 1 낮춘다.
- **6. 검사 주체**: schema validator + Runtime Validator + State Store
- **7. 허용·차단·격리 기대**: 허용되지 않는 전이·CAS 차단. 사람 승인 새 논리 work는 별도 흐름.
- **8. work·attempt·가설 기대**: 기존 종료 상태/attempt history/가설 유지.
- **9. 오류·DataGap 기대**: STATE_TRANSITION_INVALID / STATE_VERSION_CONFLICT
- **10. 저장·갱신 금지 pointer**: 원본 transition·current pointer 불변; 거절 log.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R4; 적용 모듈 owner. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-COM-011 — revision과 상태 pointer 원자 확정

- **1. ID·유형·설명**: R3-CT-COM-011 / 정상 / revision과 상태 pointer 원자 확정
- **2. 단계·계약 경계**: 1–22 공통; 공통 참조·상태·저장
- **3. producer → consumer**: 각 모듈의 명시된 record producer → 다음 consumer / State Store
- **4. 선행 상태·exact refs**: F-COM(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 저장 계약이 이미 있는 StaticFactBundle 결과를 새 immutable revision으로 확정한다.
- **6. 검사 주체**: schema validator + Runtime Validator + State Store
- **7. 허용·차단·격리 기대**: 이전 record를 덮어쓰지 않고 revision+1/previous_record_id와 work output·commit pointer가 같은 결과를 가리킴.
- **8. work·attempt·가설 기대**: 해당 STATIC_NORMALIZE work·attempt SUCCEEDED; 가설 아직 없음.
- **9. 오류·DataGap 기대**: 없음
- **10. 저장·갱신 금지 pointer**: 새 record·StateTransition·COMMITTED TransitionCommit·output pointer 함께 확정. 실패 지점별 시험은 #89.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R4; 적용 모듈 owner. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-COM-012 — record·pointer·commit 불일치

- **1. ID·유형·설명**: R3-CT-COM-012 / 부정 / record·pointer·commit 불일치
- **2. 단계·계약 경계**: 1–22 공통; 공통 참조·상태·저장
- **3. producer → consumer**: 각 모듈의 명시된 record producer → 다음 consumer / State Store
- **4. 선행 상태·exact refs**: F-COM(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: COMMITTED.output_refs는 r2인데 WorkExecutionState.output_refs/current는 r1 또는 없는 record를 가리키게 한다.
- **6. 검사 주체**: schema validator + Runtime Validator + State Store
- **7. 허용·차단·격리 기대**: 결과 사용·후속 단계 차단 후 #89의 복구/재투영으로 전달.
- **8. work·attempt·가설 기대**: 정상 종료로 간주해 진행하지 않음; 가설 판정 덮어쓰기 없음.
- **9. 오류·DataGap 기대**: revision/state/pointer 매핑 Q-02
- **10. 저장·갱신 금지 pointer**: 불일치 evidence 보존; 새 Gate/Reporter/최종 result pointer 갱신 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R4; 적용 모듈 owner. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-COM-013 — PARTIAL을 아무 work에나 사용

- **1. ID·유형·설명**: R3-CT-COM-013 / 정상·부정 / PARTIAL을 아무 work에나 사용
- **2. 단계·계약 경계**: 1–22 공통; 공통 참조·상태·저장
- **3. producer → consumer**: 각 모듈의 명시된 record producer → 다음 consumer / State Store
- **4. 선행 상태·exact refs**: F-COM(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: STATIC_NORMALIZE는 신뢰 output+DataGap으로 PARTIAL, VERIFICATION은 같은 PARTIAL 상태를 시도한다.
- **6. 검사 주체**: schema validator + Runtime Validator + State Store
- **7. 허용·차단·격리 기대**: 정적 부분 결과는 한계와 함께 허용; PARTIAL 비허용 work는 거절.
- **8. work·attempt·가설 기대**: 정적 work PARTIAL, 해당 attempt 종료; VERIFICATION 위조 전이 차단.
- **9. 오류·DataGap 기대**: 정상은 해당 STATIC_ANALYSIS DataGap; 잘못된 전이 STATE_TRANSITION_INVALID
- **10. 저장·갱신 금지 pointer**: 정적 output/gap/commit 보존; 가짜 VerificationResult/current verdict 생성 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R4; 적용 모듈 owner. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

### STA. 저장소·정적 분석·Context

근거: 01·02·08·10, ADR-006·010. 모든 사례는 **미실행 / 역할 검토 필요**.

#### R3-CT-STA-001 — clone·checkout과 준비 전 실행

- **1. ID·유형·설명**: R3-CT-STA-001 / 정상·부정 / clone·checkout과 준비 전 실행
- **2. 단계·계약 경계**: 2–4, 9; 저장소·정적 분석·Context
- **3. producer → consumer**: Repository Loader·Static Tool Adapter·Normalizer·Context Service → Hypothesis/Verification
- **4. 선행 상태·exact refs**: F-STA(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 성공 fixture는 요청 commit과 실제 HEAD 일치. 변형: clone 실패, checkout 실패, READY 전 STATIC_TOOL 호출, 준비 뒤 HEAD 변경.
- **6. 검사 주체**: 도구 adapter + schema validator + Context 경계 검사 + Runtime Validator
- **7. 허용·차단·격리 기대**: 정상만 분석 진입; 실패/변경 workspace의 정적 실행 차단.
- **8. work·attempt·가설 기대**: 성공 WORKSPACE_PREP 종료 후 도구 준비; clone/checkout 실패는 분석 FAILED, 가설 없음. 정확한 저장 경계 Q-01.
- **9. 오류·DataGap 기대**: CLONE_FAILED / CHECKOUT_FAILED / WORKSPACE_CHANGED; 준비 전 호출 Q-02
- **10. 저장·갱신 금지 pointer**: CodeWorkspace/registry 성공 연결은 Q-01 결정 필요; 실패 오류는 runs, 절대 local path/secret 노출 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R2·R4·R6·R8. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-STA-002 — 병렬 AST·SAST 결과 합류

- **1. ID·유형·설명**: R3-CT-STA-002 / 정상 / 병렬 AST·SAST 결과 합류
- **2. 단계·계약 경계**: 2–4, 9; 저장소·정적 분석·Context
- **3. producer → consumer**: Repository Loader·Static Tool Adapter·Normalizer·Context Service → Hypothesis/Verification
- **4. 선행 상태·exact refs**: F-STA(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: AST·CodeQL·OpenGrep의 별도 work/attempt COMMITTED 결과를 역순 도착시켜 정규화한다.
- **6. 검사 주체**: 도구 adapter + schema validator + Context 경계 검사 + Runtime Validator
- **7. 허용·차단·격리 기대**: 도착 순서와 무관하게 같은 workspace/commit의 기대 도구 결과가 한 번씩 포함.
- **8. work·attempt·가설 기대**: 도구 상태 각 종료, STATIC_NORMALIZE SUCCEEDED; 가설 생성은 이후.
- **9. 오류·DataGap 기대**: 없음
- **10. 저장·갱신 금지 pointer**: facts의 bundle에 각 tool/rule refs와 raw artifact 연결; 도구별 attempt ID는 서로 달라도 정상.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R2·R4·R6·R8. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-STA-003 — 규칙 실행 0건과 미실행 구분

- **1. ID·유형·설명**: R3-CT-STA-003 / 정상·부정 / 규칙 실행 0건과 미실행 구분
- **2. 단계·계약 경계**: 2–4, 9; 저장소·정적 분석·Context
- **3. producer → consumer**: Repository Loader·Static Tool Adapter·Normalizer·Context Service → Hypothesis/Verification
- **4. 선행 상태·exact refs**: F-STA(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: SELECTED+EXECUTED+hit_count=0, NOT_SELECTED+NOT_EXECUTED+hit_count=null을 별개 fixture로 둔다. 후자를 EXECUTED+0으로 조작한다.
- **6. 검사 주체**: 도구 adapter + schema validator + Context 경계 검사 + Runtime Validator
- **7. 허용·차단·격리 기대**: 앞의 정상 둘은 의미를 구분해 보존; 실제 실행 증거 없는 0건 주장은 거절.
- **8. work·attempt·가설 기대**: 정상 도구 상태를 사실대로 유지; 거절로 ‘취약점 없음’ 가설 생성 안 함.
- **9. 오류·DataGap 기대**: 누락/허위 실행 이력 오류 Q-02
- **10. 저장·갱신 금지 pointer**: RuleExecutionRecord·ToolRunResult 연결 유지; 조작된 normalized current bundle 생성 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R2·R4·R6·R8. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-STA-004 — 도구 일부 실패의 정직한 부분 결과

- **1. ID·유형·설명**: R3-CT-STA-004 / 정상·부정 / 도구 일부 실패의 정직한 부분 결과
- **2. 단계·계약 경계**: 2–4, 9; 저장소·정적 분석·Context
- **3. producer → consumer**: Repository Loader·Static Tool Adapter·Normalizer·Context Service → Hypothesis/Verification
- **4. 선행 상태·exact refs**: F-STA(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: AST 정상, SAST 한 도구 FAILED/timeout; AST 신뢰 결과는 존재한다. 변형은 전체 성공/gap 없음으로 저장 시도.
- **6. 검사 주체**: 도구 adapter + schema validator + Context 경계 검사 + Runtime Validator
- **7. 허용·차단·격리 기대**: 정상은 실패 정보 포함 PARTIAL 합류; 변형은 거절.
- **8. work·attempt·가설 기대**: 도구 실패는 그대로, STATIC_NORMALIZE PARTIAL; 이후 가설은 한계를 입력으로 받음.
- **9. 오류·DataGap 기대**: STATIC_ANALYSIS DataGap(reason=FAILED 또는 TIMEOUT) 및 실제 AnalysisError
- **10. 저장·갱신 금지 pointer**: 신뢰 facts와 실패 log/gap 모두 보존; 전체 성공으로 덮어쓰기 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R2·R4·R6·R8. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-STA-005 — fact 종류·생산 이력 누락

- **1. ID·유형·설명**: R3-CT-STA-005 / 부정 / fact 종류·생산 이력 누락
- **2. 단계·계약 경계**: 2–4, 9; 저장소·정적 분석·Context
- **3. producer → consumer**: Repository Loader·Static Tool Adapter·Normalizer·Context Service → Hypothesis/Verification
- **4. 선행 상태·exact refs**: F-STA(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 규칙 기반 fact의 RuleExecutionRecord ref 누락, 다른 tool attempt 사용, source/sink/sanitizer/validator를 서로 다른 목록에 오배치한다.
- **6. 검사 주체**: 도구 adapter + schema validator + Context 경계 검사 + Runtime Validator
- **7. 허용·차단·격리 기대**: fact kind와 해당 목록·원본 provenance를 검사해 정규화/저장 차단.
- **8. work·attempt·가설 기대**: 정규화 결과 미확정; 이전 유효 bundle 유지, 가설 verdict 없음.
- **9. 오류·DataGap 기대**: 다른 attempt STALE_RESULT; 누락/semantic 오류 Q-02
- **10. 저장·갱신 금지 pointer**: 잘못된 fact를 current facts로 승격하지 않음; 안전한 오류·raw 진단 보존.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R2·R4·R6·R8. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-STA-006 — entity·location·call edge 참조 검사

- **1. ID·유형·설명**: R3-CT-STA-006 / 부정 / entity·location·call edge 참조 검사
- **2. 단계·계약 경계**: 2–4, 9; 저장소·정적 분석·Context
- **3. producer → consumer**: Repository Loader·Static Tool Adapter·Normalizer·Context Service → Hypothesis/Verification
- **4. 선행 상태·exact refs**: F-STA(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: bundle/context의 entity·location·호출 관계 참조를 없는 ID로 바꾸거나 CodeContextResponse에 다른 commit fragment 삽입.
- **6. 검사 주체**: 도구 adapter + schema validator + Context 경계 검사 + Runtime Validator
- **7. 허용·차단·격리 기대**: 참조 존재·scope·관계 endpoint 검사 후 거절.
- **8. work·attempt·가설 기대**: 현재 소비 작업은 해당 근거로 진행하지 않음; 가설 판정 불변.
- **9. 오류·DataGap 기대**: 참조/범위 검사 Q-02
- **10. 저장·갱신 금지 pointer**: invalid context/fact는 current 근거에 연결 금지; 거절 위치 기록.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R2·R4·R6·R8. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-STA-007 — 허용 범위 Context 조회와 경로 탈출

- **1. ID·유형·설명**: R3-CT-STA-007 / 정상·부정 / 허용 범위 Context 조회와 경로 탈출
- **2. 단계·계약 경계**: 2–4, 9; 저장소·정적 분석·Context
- **3. producer → consumer**: Repository Loader·Static Tool Adapter·Normalizer·Context Service → Hypothesis/Verification
- **4. 선행 상태·exact refs**: F-STA(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 정상은 같은 workspace 안의 요청 entity/location 최소 조각 조회. 변형은 ../ 경로, symlink 외부 탈출, 조회 범위/설정 한도 초과.
- **6. 검사 주체**: 도구 adapter + schema validator + Context 경계 검사 + Runtime Validator
- **7. 허용·차단·격리 기대**: 정상 fragment/ref 반환; 외부 읽기 차단, 한도 부족은 잘림/한계 명시.
- **8. work·attempt·가설 기대**: 정상 CONTEXT_RETRIEVAL SUCCEEDED; 신뢰 부분 조회는 PARTIAL, 차단은 실제 오류 정책대로 처리하고 가설 판정 안 함.
- **9. 오류·DataGap 기대**: CONTEXT DataGap(reason=TRUNCATED/BLOCKED 등 실제 원인); 경로 오류 Q-02
- **10. 저장·갱신 금지 pointer**: contexts와 exact fragment refs; host file·secret 저장 금지; 실패를 빈 정상 응답으로 위장하지 않음.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R2·R4·R6·R8. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

### HYP. 가설 등록·배정

근거: 03·06·08·10. 모든 사례는 **미실행 / 역할 검토 필요**.

#### R3-CT-HYP-001 — 정상 INITIAL proposal 등록과 배정

- **1. ID·유형·설명**: R3-CT-HYP-001 / 정상 / 정상 INITIAL proposal 등록과 배정
- **2. 단계·계약 경계**: 5–8, 20; 가설 등록·배정
- **3. producer → consumer**: Hypothesis/Verification/Chaining proposal producer → Proposal Validator·Hypothesis Registry·Assignment Runtime
- **4. 선행 상태·exact refs**: F-HYP(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 정상 schema·근거·질문을 가진 새 INITIAL proposal, 기존 중복 없음.
- **6. 검사 주체**: schema/semantic validator + trusted Registry·Assignment Runtime; 의미 중복 판단은 해당 LLM 역할
- **7. 허용·차단·격리 기대**: 검증된 proposal을 등록하고 새 hypothesis_id와 ACTIVE Verification owner 배정.
- **8. work·attempt·가설 기대**: proposal 등록, hypothesis REGISTERED 후 해당 배정 흐름; 새 VERIFICATION 준비, final verdict 없음.
- **9. 오류·DataGap 기대**: 없음; proposal 독립 저장 권한 Q-01
- **10. 저장·갱신 금지 pointer**: hypotheses/process/assignment/work의 정확한 연결. 저장 identity는 Q-01 해결 후 구현.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R1·R4·R6. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-HYP-002 — 같은 등록 요청 재전달

- **1. ID·유형·설명**: R3-CT-HYP-002 / 정상 / 같은 등록 요청 재전달
- **2. 단계·계약 경계**: 5–8, 20; 가설 등록·배정
- **3. producer → consumer**: Hypothesis/Verification/Chaining proposal producer → Proposal Validator·Hypothesis Registry·Assignment Runtime
- **4. 선행 상태·exact refs**: F-HYP(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 동일 입력·generation·설정 refs로 work 등록을 두 번 실행한다.
- **6. 검사 주체**: schema/semantic validator + trusted Registry·Assignment Runtime; 의미 중복 판단은 해당 LLM 역할
- **7. 허용·차단·격리 기대**: 기존 dedupe key의 work와 application 반환; 새 가설/작업이 중복 생성되지 않음.
- **8. work·attempt·가설 기대**: 기존 work/attempt/가설 상태 유지.
- **9. 오류·DataGap 기대**: 없음
- **10. 저장·갱신 금지 pointer**: 기존 IDs/current refs 보존; 새 application 때문에 dedupe key가 달라지지 않음.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R1·R4·R6. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-HYP-003 — 중복 가설과 중복 판단 실패 구분

- **1. ID·유형·설명**: R3-CT-HYP-003 / 정상·부정 / 중복 가설과 중복 판단 실패 구분
- **2. 단계·계약 경계**: 5–8, 20; 가설 등록·배정
- **3. producer → consumer**: Hypothesis/Verification/Chaining proposal producer → Proposal Validator·Hypothesis Registry·Assignment Runtime
- **4. 선행 상태·exact refs**: F-HYP(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: exact 중복 target이 있는 proposal과, duplicate review가 실패/UNCERTAIN인 proposal을 분리한다.
- **6. 검사 주체**: schema/semantic validator + trusted Registry·Assignment Runtime; 의미 중복 판단은 해당 LLM 역할
- **7. 허용·차단·격리 기대**: 명백한 중복만 신규 가설 미생성; 의미 중복 판정 실패는 오류 보존 후 main의 fail-open 등록. schema-invalid는 fail-open 대상 아님.
- **8. work·attempt·가설 기대**: exact duplicate는 해당 proposal 종료; 정상 schema의 미확정 중복은 새 가설 검증으로 진입.
- **9. 오류·DataGap 기대**: duplicate review 실패 원인 AnalysisError; 코드 Q-02
- **10. 저장·갱신 금지 pointer**: HypothesisDuplicateReview/오류와 등록 판단 trace; 기존 가설 verdict 수정 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R1·R4·R6. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-HYP-004 — 무효 proposal과 Hypothesis 권한·전수 등록 경계

- **1. ID·유형·설명**: R3-CT-HYP-004 / 정상·부정 / 무효 proposal과 Hypothesis Agent 권한·전수 등록 경계
- **2. 단계·계약 경계**: 5–8, 20; 가설 등록·배정
- **3. producer → consumer**: Hypothesis/Verification/Chaining proposal producer → Proposal Validator·Hypothesis Registry·Assignment Runtime
- **4. 선행 상태·exact refs**: F-HYP(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 정상 변형은 같은 호출에서 서로 다른 우선도처럼 보이는 schema-valid proposal 두 개를 반환한다. 부정 변형은 필수 반증 질문/근거 누락, 허용되지 않은 origin, `confirmed | verified | finding | exploitable` 확정 주장, 정책·scope record를 Hypothesis 입력에 주입하거나 scope/점수를 이유로 유효 proposal 하나를 등록 대상에서 제거, 비-LLM Orchestration Runtime이 final TRUE 저장을 각각 시도한다.
- **6. 검사 주체**: schema/semantic validator + trusted Registry·Assignment Runtime; 의미 중복 판단은 해당 LLM 역할
- **7. 허용·차단·격리 기대**: 정상 proposal 두 개는 모두 trusted validation과 중복 검토를 거쳐 각각 등록·Verification 배정 대상으로 남긴다. 모든 부정 변형은 schema/semantic/authority 검사 또는 호출 전 context 검사로 거절하며 Hypothesis Agent와 순서 조정 모듈이 scope·verdict·Finding을 대신 결정하지 않는다.
- **8. work·attempt·가설 기대**: 정상은 유효·비중복 proposal마다 독립 가설 lifecycle을 시작한다. 부정 proposal·입력은 처리 실패/거절하며 기존 가설에 영향 없고 새 final verdict도 없다.
- **9. 오류·DataGap 기대**: INVALID_OUTPUT / ACTION_NOT_ALLOWED: 각 경계 적용
- **10. 저장·갱신 금지 pointer**: 안전한 invalid invocation/log와 제거 시도 trace는 보존하되 확정 주장·정책 사전 필터 결과를 유효 proposal·가설·VerificationResult·Finding으로 승격하지 않는다. 정상 유효 proposal을 점수 때문에 누락하지 않는다.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R1·R4·R6. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-HYP-005 — 검증 work와 PlaybookApplication 고정

- **1. ID·유형·설명**: R3-CT-HYP-005 / 정상 / 검증 work와 PlaybookApplication 고정
- **2. 단계·계약 경계**: 5–8, 20; 가설 등록·배정
- **3. producer → consumer**: Hypothesis/Verification/Chaining proposal producer → Proposal Validator·Hypothesis Registry·Assignment Runtime
- **4. 선행 상태·exact refs**: F-HYP(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 새 VERIFICATION 등록 시 hypothesis/proposal/policy/playbook refs로 dedupe, 새 application 생성. 검증 중 최신 policy만 게시한다.
- **6. 검사 주체**: schema/semantic validator + trusted Registry·Assignment Runtime; 의미 중복 판단은 해당 LLM 역할
- **7. 허용·차단·격리 기대**: 새 work/application 원자 등록. policy 게시만으로 진행 중 고정 application/질문을 바꾸지 않고 같은 work retry에 재사용.
- **8. work·attempt·가설 기대**: 기존 work 진행·hypothesis VERIFYING 유지; 새 generation은 별도 새 work.
- **9. 오류·DataGap 기대**: 없음
- **10. 저장·갱신 금지 pointer**: input_refs/input_hash 고정; application 신규 ref는 자신의 등록 dedupe key에 넣지 않음.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R1·R4·R6. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

### LLM. Prompt·Provider·session·권한

근거: 08·09·10; PR별 추가 필드는 PR 묶음 참조. 모든 사례는 **미실행 / 역할 검토 필요**.

#### R3-CT-LLM-001 — 정상 spec·payload·request 연결

- **1. ID·유형·설명**: R3-CT-LLM-001 / 정상 / 정상 spec·payload·request 연결
- **2. 단계·계약 경계**: 6, 10–13, 15, 17–18, 21; Prompt·Provider·session·권한
- **3. producer → consumer**: trusted Prompt Builder·Agent Runtime → Provider Adapter → parser·소비 역할
- **4. 선행 상태·exact refs**: F-LLM(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 동일 exact LLMCallSpec/prompt payload/provider profile과 USED decision으로 호출하며 응답 fixture는 해당 역할 schema-valid이다.
- **6. 검사 주체**: Runtime Validator + Prompt Builder allowlist/redaction + adapter/parser
- **7. 허용·차단·격리 기대**: role/model/session/input/template/schema/설정이 승인된 spec과 동일한 경우만 adapter 호출·parser 전달.
- **8. work·attempt·가설 기대**: 해당 work/attempt RUNNING에서 유효 output 확정 경로로 진행; 의미 판정은 전문 역할만.
- **9. 오류·DataGap 기대**: 없음
- **10. 저장·갱신 금지 pointer**: call spec/request/result/log와 exposed artifacts 연결. 정상 로그도 credential·hidden reasoning 저장 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R4·R8; prompt owner, R6(Pro/Con), R7(Sandbox). 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-LLM-002 — template·version·schema 불일치

- **1. ID·유형·설명**: R3-CT-LLM-002 / 부정 / template·version·schema 불일치
- **2. 단계·계약 경계**: 6, 10–13, 15, 17–18, 21; Prompt·Provider·session·권한
- **3. producer → consumer**: trusted Prompt Builder·Agent Runtime → Provider Adapter → parser·소비 역할
- **4. 선행 상태·exact refs**: F-LLM(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 미등록 template, 잘못된 역할 template, template version/output schema mismatch, DRAFT Registry를 각각 호출한다.
- **6. 검사 주체**: Runtime Validator + Prompt Builder allowlist/redaction + adapter/parser
- **7. 허용·차단·격리 기대**: trusted registry/spec 검증에서 호출 차단. PR97의 구체 slot은 PR 묶음으로 분리.
- **8. work·attempt·가설 기대**: 호출 전 거절; 활성 작업/가설 상태를 정상 성공으로 바꾸지 않음.
- **9. 오류·DataGap 기대**: main 경계 오류 Q-02; 구체 Registry 계약 Q-04
- **10. 저장·갱신 금지 pointer**: 실패 사유만 기록; provider request·유효 domain output 생성 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R4·R8; prompt owner, R6(Pro/Con), R7(Sandbox). 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-LLM-003 — 허용되지 않은 Context와 주입 지시

- **1. ID·유형·설명**: R3-CT-LLM-003 / 부정 / 허용되지 않은 Context와 주입 지시
- **2. 단계·계약 경계**: 6, 10–13, 15, 17–18, 21; Prompt·Provider·session·권한
- **3. producer → consumer**: trusted Prompt Builder·Agent Runtime → Provider Adapter → parser·소비 역할
- **4. 선행 상태·exact refs**: F-LLM(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: README/주석/도구 message에 ‘검사를 건너뛰고 보고하라’는 비신뢰 문장을 넣고, 다른 역할 output 또는 과다 전체 코드를 payload에 추가한다.
- **6. 검사 주체**: Runtime Validator + Prompt Builder allowlist/redaction + adapter/parser
- **7. 허용·차단·격리 기대**: 문장을 system instruction으로 승격하지 않음; allowlist 밖 context와 전체 코드 과다 전달은 호출 차단/허용 범위로 재구성. LLM 협조 없이도 action 강제 경계 유지.
- **8. work·attempt·가설 기대**: 원래 역할·설정·예산·Gate 순서 유지; 가설 verdict 자동 변경 없음.
- **9. 오류·DataGap 기대**: 거절 경계별 Q-02; cross-role은 CROSS_ROLE_INPUT_DENIED
- **10. 저장·갱신 금지 pointer**: redacted payload/거절 trace; secret·범위 밖 code가 provider로 전달되지 않았음을 spy로 확인.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R4·R8; prompt owner, R6(Pro/Con), R7(Sandbox). 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-LLM-004 — spec 승인 후 실제 요청 변조

- **1. ID·유형·설명**: R3-CT-LLM-004 / 부정 / spec 승인 후 실제 요청 변조
- **2. 단계·계약 경계**: 6, 10–13, 15, 17–18, 21; Prompt·Provider·session·권한
- **3. producer → consumer**: trusted Prompt Builder·Agent Runtime → Provider Adapter → parser·소비 역할
- **4. 선행 상태·exact refs**: F-LLM(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: LLMInvocationRequest의 model, context ref, session, output schema, timeout을 각각 승인 spec과 다르게 만든다.
- **6. 검사 주체**: Runtime Validator + Prompt Builder allowlist/redaction + adapter/parser
- **7. 허용·차단·격리 기대**: field equality 불일치로 decision 만료/호출 차단. token 계획값 일치 검사와 사용량 상한은 다름.
- **8. work·attempt·가설 기대**: decision EXPIRED; work/attempt 성공 처리 없음, 가설 불변.
- **9. 오류·DataGap 기대**: REVISION 경계 구체 오류 Q-02
- **10. 저장·갱신 금지 pointer**: 변조 안전 요약 기록; adapter 호출 횟수 0, 정상 output/current pointer 불변.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R4·R8; prompt owner, R6(Pro/Con), R7(Sandbox). 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-LLM-005 — secret 유출과 redaction 실패

- **1. ID·유형·설명**: R3-CT-LLM-005 / 부정 / secret 유출과 redaction 실패
- **2. 단계·계약 경계**: 6, 10–13, 15, 17–18, 21; Prompt·Provider·session·권한
- **3. producer → consumer**: trusted Prompt Builder·Agent Runtime → Provider Adapter → parser·소비 역할
- **4. 선행 상태·exact refs**: F-LLM(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: synthetic API key/password/cookie/session token을 prompt·raw 응답·일반 log·보고 후보에 넣는다. 실제 secret 사용 금지.
- **6. 검사 주체**: Runtime Validator + Prompt Builder allowlist/redaction + adapter/parser
- **7. 허용·차단·격리 기대**: redaction/허용 저장 경계 검사. 제거 보장 못 하면 호출 또는 저장 차단.
- **8. work·attempt·가설 기대**: work 성공 처리 금지; 가설 판정은 바뀌지 않음.
- **9. 오류·DataGap 기대**: REDACTION 경계 Q-02
- **10. 저장·갱신 금지 pointer**: 유출 대상 원문을 실패 log에도 저장하지 않음. 알려진 가짜 sentinel이 outbound/log/artifact에 없는지 검사.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R4·R8; prompt owner, R6(Pro/Con), R7(Sandbox). 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-LLM-006 — 인증·rate limit·timeout·invalid output

- **1. ID·유형·설명**: R3-CT-LLM-006 / 부정 / 인증·rate limit·timeout·invalid output
- **2. 단계·계약 경계**: 6, 10–13, 15, 17–18, 21; Prompt·Provider·session·권한
- **3. producer → consumer**: trusted Prompt Builder·Agent Runtime → Provider Adapter → parser·소비 역할
- **4. 선행 상태·exact refs**: F-LLM(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: fake provider가 네 오류를 각각 반환. 별도 variant는 이를 VerificationResult(FALSE)로 포장한다.
- **6. 검사 주체**: Runtime Validator + Prompt Builder allowlist/redaction + adapter/parser
- **7. 허용·차단·격리 기대**: 원래 invocation 실패 종류와 원인을 보존; 허용된 retry/repair만 적용. FALSE 포장은 거절.
- **8. work·attempt·가설 기대**: 일반 work는 retry 가능한 실패 attempt FAILED/work BLOCKED; 한도 소진은 work FAILED. R7 같은 session 예외는 DYN 참조. final verdict 없음.
- **9. 오류·DataGap 기대**: 실제 provider/parse 오류; INVALID_OUTPUT은 해당 변형. 나머지 정확한 code Q-02
- **10. 저장·갱신 금지 pointer**: LLMInvocationResult/Log·오류·retry 연결 저장; 정상 domain output/current verdict 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R4·R8; prompt owner, R6(Pro/Con), R7(Sandbox). 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-LLM-007 — 명시적 retry/failover와 silent fallback

- **1. ID·유형·설명**: R3-CT-LLM-007 / 정상·부정 / 명시적 retry/failover와 silent fallback
- **2. 단계·계약 경계**: 6, 10–13, 15, 17–18, 21; Prompt·Provider·session·권한
- **3. producer → consumer**: trusted Prompt Builder·Agent Runtime → Provider Adapter → parser·소비 역할
- **4. 선행 상태·exact refs**: F-LLM(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 정상은 바로 앞 실패 호출을 retry_of 또는 failover_from으로 연결한 새 call/spec/action. 변형은 모델 무기록 교체·이전 decision 재사용·두 predecessor 필드 동시 설정.
- **6. 검사 주체**: Runtime Validator + Prompt Builder allowlist/redaction + adapter/parser
- **7. 허용·차단·격리 기대**: 허용된 변경만 새 호출로 추적; silent fallback·비정상 chain 거절.
- **8. work·attempt·가설 기대**: 새 시도 정책에 따름; 기존 실패 history 유지, 가설 자동 판정 없음.
- **9. 오류·DataGap 기대**: INVOCATION_CHAIN_INVALID / ACTION_NOT_ALLOWED
- **10. 저장·갱신 금지 pointer**: 새 llm_call_id·새 decision/profile refs 저장; 실패 기록 삭제 금지. 일반 work와 R7 session attempt 정책 구분.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R4·R8; prompt owner, R6(Pro/Con), R7(Sandbox). 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-LLM-008 — API·구독 경로의 의미 동등성

- **1. ID·유형·설명**: R3-CT-LLM-008 / 정상·부정 / API·구독 경로의 의미 동등성
- **2. 단계·계약 경계**: 6, 10–13, 15, 17–18, 21; Prompt·Provider·session·권한
- **3. producer → consumer**: trusted Prompt Builder·Agent Runtime → Provider Adapter → parser·소비 역할
- **4. 선행 상태·exact refs**: F-LLM(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 동일 논리 payload·schema·오류 fixture를 두 fake adapter에 공급한다. 실제 경로는 #90 지원 판정 뒤 별도 시험.
- **6. 검사 주체**: Runtime Validator + Prompt Builder allowlist/redaction + adapter/parser
- **7. 허용·차단·격리 기대**: provider transport가 달라도 참조·오류·금지 권한 의미가 같음. 자유문장 byte 일치나 실계정 지원 성공을 요구하지 않음.
- **8. work·attempt·가설 기대**: 동일 fixture에 동일한 domain allow/reject 기대; 오류를 가설 FALSE로 변환하지 않음.
- **9. 오류·DataGap 기대**: 각 provider 원인 보존 및 공통 오류 매핑; 미지원 경로는 Q-04
- **10. 저장·갱신 금지 pointer**: 논리 payload hash·normalized result·usage 출처 비교. 실제 계정 결과와 fake 결과를 별도 기록.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R4·R8; prompt owner, R6(Pro/Con), R7(Sandbox). 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

### VER. Pro/Con·최종 판정·REVISE

근거: 03·04·08·09. 모든 사례는 **미실행 / 역할 검토 필요**.

#### R3-CT-VER-001 — 독립 Pro/Con 정상 합류

- **1. ID·유형·설명**: R3-CT-VER-001 / 정상 / 독립 Pro/Con 정상 합류
- **2. 단계·계약 경계**: 8, 10–13, 16; Pro/Con·최종 판정·REVISE
- **3. producer → consumer**: Pro Agent·Con Agent·R7 결과 → 같은 Verification owner → 후속 router
- **4. 선행 상태·exact refs**: F-VER(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 같은 parent VERIFICATION/generation/common input hash의 PRO/CON을 서로 다른 work·attempt·NEW session으로 실행한다.
- **6. 검사 주체**: Runtime Validator의 exact join + R6 semantic validator; 기술적 판단은 Verification Agent
- **7. 허용·차단·격리 기대**: 두 current SUCCEEDED/COMMITTED EvidenceAgentResult를 정확히 한 번 합류. 두 역할 attempt ID가 같을 필요는 없음.
- **8. work·attempt·가설 기대**: 자식 work/attempt SUCCEEDED; 부모 검증 진행, hypothesis VERIFYING; 합류 자체는 final TRUE가 아님.
- **9. 오류·DataGap 기대**: 없음
- **10. 저장·갱신 금지 pointer**: pro/con refs·debate_input_hash·calls/sessions 유지. 반대 역할 output/session은 각각 입력에 없음.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / E2E
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R6·R4·R7·R5. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-VER-002 — 한쪽 Pro/Con 실패

- **1. ID·유형·설명**: R3-CT-VER-002 / 부정 / 한쪽 Pro/Con 실패
- **2. 단계·계약 경계**: 8, 10–13, 16; Pro/Con·최종 판정·REVISE
- **3. producer → consumer**: Pro Agent·Con Agent·R7 결과 → 같은 Verification owner → 후속 router
- **4. 선행 상태·exact refs**: F-VER(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: PRO 성공, CON retryable timeout. CON 결과 없이 최종 verdict를 제출한다.
- **6. 검사 주체**: Runtime Validator의 exact join + R6 semantic validator; 기술적 판단은 Verification Agent
- **7. 허용·차단·격리 기대**: 단독 합성/최종 저장 차단. 동일 고정 입력이면 성공 sibling 보존, 실패 child만 재시도.
- **8. work·attempt·가설 기대**: CON attempt FAILED/work BLOCKED; 부모 BLOCKED, hypothesis VERIFYING, final result 없음. 복구불가면 child commit 후 부모/가설 FAILED 계약 적용.
- **9. 오류·DataGap 기대**: 실제 timeout 오류; 누락 join 거절 Q-02
- **10. 저장·갱신 금지 pointer**: PRO exact 결과 history 유지; child/부모 상태 조정 trace. 불일치 짧은 구간도 합성 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / E2E
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R6·R4·R7·R5. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-VER-003 — 상대 역할 입력·session 노출

- **1. ID·유형·설명**: R3-CT-VER-003 / 부정 / 상대 역할 입력·session 노출
- **2. 단계·계약 경계**: 8, 10–13, 16; Pro/Con·최종 판정·REVISE
- **3. producer → consumer**: Pro Agent·Con Agent·R7 결과 → 같은 Verification owner → 후속 router
- **4. 선행 상태·exact refs**: F-VER(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: PRO에 CON parsed output/log/session을 넣거나 반대로 전달한다.
- **6. 검사 주체**: Runtime Validator의 exact join + R6 semantic validator; 기술적 판단은 Verification Agent
- **7. 허용·차단·격리 기대**: 모든 입력 경로에서 독립성 위반 차단.
- **8. work·attempt·가설 기대**: 오염된 결과를 합류하지 않음; 부모 final verdict 없음.
- **9. 오류·DataGap 기대**: CROSS_ROLE_INPUT_DENIED
- **10. 저장·갱신 금지 pointer**: 위반 trace를 secret 없이 기록; 유효 pro/con pointer로 승격 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / E2E
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R6·R4·R7·R5. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-VER-004 — 서로 다른 검증 입력의 결과 재사용

- **1. ID·유형·설명**: R3-CT-VER-004 / 부정 / 서로 다른 검증 입력의 결과 재사용
- **2. 단계·계약 경계**: 8, 10–13, 16; Pro/Con·최종 판정·REVISE
- **3. producer → consumer**: Pro Agent·Con Agent·R7 결과 → 같은 Verification owner → 후속 router
- **4. 선행 상태·exact refs**: F-VER(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: generation/parent/common input/application/debate 설정을 실제로 바꾼 뒤 이전 성공 sibling을 사용한다.
- **6. 검사 주체**: Runtime Validator의 exact join + R6 semantic validator; 기술적 판단은 Verification Agent
- **7. 허용·차단·격리 기대**: 과거 두 결과 stale 격리, 새 입력에 대한 Pro/Con 둘 다 필요. 단순 최신 policy 게시만으로 stale 처리하지 않음.
- **8. work·attempt·가설 기대**: 새 검증 VERIFYING; 과거 결과로 final 전환 금지.
- **9. 오류·DataGap 기대**: STALE_RESULT
- **10. 저장·갱신 금지 pointer**: 옛 결과 history 보존; 새 input refs/hash와 새 결과만 current join 후보.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / E2E
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R6·R4·R7·R5. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-VER-005 — 세 최종 판정의 정상 근거

- **1. ID·유형·설명**: R3-CT-VER-005 / 정상 / 세 최종 판정의 정상 근거
- **2. 단계·계약 경계**: 8, 10–13, 16; Pro/Con·최종 판정·REVISE
- **3. producer → consumer**: Pro Agent·Con Agent·R7 결과 → 같은 Verification owner → 후속 router
- **4. 선행 상태·exact refs**: F-VER(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 변형 A: current SUCCEEDED+SUPPORTED dynamic+validated PoC; B: 필수 검증 완료와 실제 DISPROVED 근거/question_id; C: 필수 검증 완료와 정상 관측의 불충분 근거.
- **6. 검사 주체**: Runtime Validator의 exact join + R6 semantic validator; 기술적 판단은 Verification Agent
- **7. 허용·차단·격리 기대**: R6 fixture의 A TRUE/B FALSE/C HOLD를 schema·근거 의미 검사 후 허용. runtime이 직접 판정하지 않음.
- **8. work·attempt·가설 기대**: VERIFICATION work/attempt SUCCEEDED, hypothesis TERMINAL, exact final result 연결; TRUE만 CWE 경로.
- **9. 오류·DataGap 기대**: 없음; C의 부족 조건은 근거/limitations로 기록
- **10. 저장·갱신 금지 pointer**: verifications/current final pointer·commit. FALSE/HOLD에 CWE·Gate를 만들지 않음.
- **11. FALSE 변환 금지**: 정상 완료와 실제 반증이 있는 B만 전문 R6 FALSE 허용. timeout·미완료·환경 실패를 B의 근거로 대신 쓰지 않음.
- **12. 실행 계층**: contract / integration / E2E
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R6·R4·R7·R5. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-VER-006 — 검증 미완료·PoC 없는 TRUE

- **1. ID·유형·설명**: R3-CT-VER-006 / 부정 / 검증 미완료·PoC 없는 TRUE
- **2. 단계·계약 경계**: 8, 10–13, 16; Pro/Con·최종 판정·REVISE
- **3. producer → consumer**: Pro Agent·Con Agent·R7 결과 → 같은 Verification owner → 후속 router
- **4. 선행 상태·exact refs**: F-VER(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 필수 check 미완료, 현재 generation validated PoC 없음, initial assessment를 final 결과로 사용, dynamic 실패를 FALSE/HOLD로 포장하는 변형.
- **6. 검사 주체**: Runtime Validator의 exact join + R6 semantic validator; 기술적 판단은 Verification Agent
- **7. 허용·차단·격리 기대**: final 저장과 Technical Gate 호출 차단. TRUE는 정적 추정만으로 확정 불가.
- **8. work·attempt·가설 기대**: 검증 미완료는 해당 원인에 따른 BLOCKED/FAILED; 가설 final result 없음.
- **9. 오류·DataGap 기대**: INVALID_OUTPUT 또는 선행조건 오류 Q-02; 이전 generation은 STALE_RESULT
- **10. 저장·갱신 금지 pointer**: 실패·누락 근거 보존; final/current VerificationResult·Gate output 없음.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / E2E
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R6·R4·R7·R5. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-VER-007 — Technical REVISE 새 generation

- **1. ID·유형·설명**: R3-CT-VER-007 / 정상·부정 / Technical REVISE 새 generation
- **2. 단계·계약 경계**: 8, 10–13, 16; Pro/Con·최종 판정·REVISE
- **3. producer → consumer**: Pro Agent·Con Agent·R7 결과 → 같은 Verification owner → 후속 router
- **4. 선행 상태·exact refs**: F-VER(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: Technical REVISE를 같은 ACTIVE Verification owner에 전달. 변형은 종료 work 재사용/다른 owner 배정/옛 ProCon·PoC·CWE 재사용.
- **6. 검사 주체**: Runtime Validator의 exact join + R6 semantic validator; 기술적 판단은 Verification Agent
- **7. 허용·차단·격리 기대**: 정상은 새 generation·VERIFICATION work·application·질문, 새 Pro/Con. final TRUE면 새 dynamic/PoC/CWE 필요. 변형 차단.
- **8. work·attempt·가설 기대**: hypothesis VERIFYING; verification_work_ref 새 work. 진행 중 previous verification_result_ref는 history 기준으로 유지하되 새 판정 자격 없음.
- **9. 오류·DataGap 기대**: 정상 없음; 변형 STATE_TRANSITION_INVALID / STALE_RESULT / 권한 Q-02
- **10. 저장·갱신 금지 pointer**: 새 work/state 전이 원자 확정, 이전 generation 불변. 다음 final에서 새 result/current를 원자 연결.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / E2E
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R6·R4·R7·R5. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-VER-008 — 운영 목적의 Debate mode 강제

- **1. ID·유형·설명**: R3-CT-VER-008 / 정상·부정 / 운영 목적의 Debate mode 강제
- **2. 단계·계약 경계**: 1, 5, 8, 10; AnalysisRunState purpose·Verification 등록·Debate preflight
- **3. producer → consumer**: Analysis Entry의 고정 purpose·versioned Debate 설정 → Orchestration Runtime / Verification Runtime
- **4. 선행 상태·exact refs**: F-VER(§2.3)의 정상 `purpose=PRODUCTION`, DP1과 exact run/work/application refs. 각 변형은 mode만 바꾸고 다른 입력은 고정한다.
- **5. 정상/잘못된 fixture**: A는 `PRODUCTION + ALWAYS_DEBATE`; B는 `PRODUCTION + BASIC`; C는 `PRODUCTION + CONDITIONAL_DEBATE`. B/C가 평가에서 가능하다는 이유로 운영 run에 사용되는지 검사한다.
- **6. 검사 주체**: Analysis Entry + Orchestration Runtime / Runtime Validator의 purpose·mode preflight; R6는 mode 허용 규칙의 의미 검토
- **7. 허용·차단·격리 기대**: A만 Analysis/Verification 등록과 두 child 준비 허용. B/C는 Provider 호출 전에 분석 또는 Verification 등록을 차단하며 `ALWAYS_DEBATE`로 조용히 바꿔 계속하지 않는다.
- **8. work·attempt·가설 기대**: A는 정상 Verification 진행. B/C에는 유효 Verification child work·attempt·final result를 만들지 않고 기존 가설 verdict를 변경하지 않는다.
- **9. 오류·DataGap 기대**: purpose·mode 계약 위반. exact 오류·상태 매핑은 Q-02이며 `FALSE | HOLD` 근거가 아니다.
- **10. 저장·갱신 금지 pointer**: 거절된 설정을 current run/Verification 설정으로 확정하지 않고 Pro/Con·final·Gate·Primitive·Reporter pointer를 만들지 않는다.
- **11. FALSE 변환 금지**: 운영 mode 오류를 취약점 반증 또는 불확실 판정으로 변환하지 않는다. Runtime은 전문 verdict를 대신 생성하지 않는다.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R6·R4·R8. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-VER-009 — 운영 ALWAYS_DEBATE 실행 완전성과 예산 부족

- **1. ID·유형·설명**: R3-CT-VER-009 / 부정 / 운영 ALWAYS_DEBATE 실행 완전성과 예산 부족
- **2. 단계·계약 경계**: 8, 10, 13; Debate preflight·두 child 실행·final 합성
- **3. producer → consumer**: Verification owner의 요청 → PRO·CON child work → Debate Join Runtime → Verification final 저장
- **4. 선행 상태·exact refs**: F-VER(§2.3)의 운영 `ALWAYS_DEBATE`; 정상은 두 최초 호출을 시작할 권한·시간·비용·호출/work 예산이 있고 triggers는 `[]`, skip reason은 `null`이다.
- **5. 정상/잘못된 fixture**: A는 Pro와 Con 모두 실행·합류. B는 Pro만 실행, C는 Con만 실행, D는 Pro/Con 시작 전 실제 비-token 예산 부족인데 한쪽 또는 둘 다 생략하고 final 후보를 제출한다. 별도 변형으로 `debate_triggers`를 채우거나 skip reason을 기록한다.
- **6. 검사 주체**: R8 budget preflight + Verification owner의 child 등록 요청 + Runtime Validator·Debate Join Runtime exact join + R6 semantic validator
- **7. 허용·차단·격리 기대**: A만 final 합성 진행. B/C는 누락 child 때문에 저장 차단. D는 어느 child도 시작하지 않고 현재 Verification을 실제 예산 상태로 중단한다. mode를 BASIC으로 낮추거나 단독 결과로 계속하지 않는다.
- **8. work·attempt·가설 기대**: B/C는 누락 child 복구 가능성에 따라 부모 BLOCKED 또는 실패 전파 계약을 적용하고 hypothesis는 임의 TERMINAL이 되지 않는다. D는 `BUDGET_EXCEEDED`, final result 없음. 새 예산 승인 시 새 work 규칙을 따른다.
- **9. 오류·DataGap 기대**: D는 `BUDGET_EXCEEDED`; B/C 및 mode 기록 모순의 exact 오류는 Q-02. token 계획 초과·usage 미제공만으로 D를 만들지 않는다.
- **10. 저장·갱신 금지 pointer**: 한쪽 EvidenceAgentResult history는 보존할 수 있으나 final/current Verification·CWE·Gate·Primitive·Reporter pointer 갱신은 금지한다.
- **11. FALSE 변환 금지**: Pro/Con 누락과 예산 부족은 실제 반증이 아니므로 `FALSE | HOLD` 결과를 만들지 않는다.
- **12. 실행 계층**: contract / integration / E2E / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R6·R4·R8. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-VER-010 — 평가 결과의 운영 경계 차단

- **1. ID·유형·설명**: R3-CT-VER-010 / 부정 / 평가 결과의 운영 Gate·Primitive·Reporter 사용 차단
- **2. 단계·계약 경계**: 10, 13–15, 17–21; EVALUATION provenance와 운영 후속 입력 권한
- **3. producer → consumer**: EVALUATION Verification 결과 → Technical Gate / Primitive Admission / Reporter 요청
- **4. 선행 상태·exact refs**: 별도 `purpose=EVALUATION` run에 exact 비어 있지 않은 eval_config_refs를 고정한다. BASIC 또는 CONDITIONAL_DEBATE 평가 결과를 정상적으로 저장하되 운영 F-GAT/F-REP와 analysis identity를 섞지 않는다.
- **5. 정상/잘못된 fixture**: A는 평가 결과를 품질·비용 비교 자료로만 조회한다. B/C/D는 같은 평가 결과 또는 그 복사본을 각각 Gate, Primitive admission, Reporter의 input/evidence ref로 제출한다. E는 purpose만 PRODUCTION으로 바꿔 재포장한다.
- **6. 검사 주체**: Runtime Validator의 purpose·analysis·authority·exact reference 검사 + 각 Gate/Admission/Reporter 전용 입력 검사
- **7. 허용·차단·격리 기대**: A만 평가 저장/비교 허용. B~E는 후속 action·LLM 호출·결과 저장 전 차단한다. 평가 결과를 운영 결과로 복제하거나 current 운영 pointer로 승격하지 않는다.
- **8. work·attempt·가설 기대**: 평가 work의 실제 완료 상태는 유지할 수 있으나 운영 가설·Gate·Primitive·Report 상태는 불변이다.
- **9. 오류·DataGap 기대**: purpose/authority/reference 계약 위반의 exact 오류는 Q-02. 평가 결과 자체를 실패·FALSE로 바꾸지 않는다.
- **10. 저장·갱신 금지 pointer**: 평가 provenance와 eval_config_refs는 보존하되 운영 current Verification·Gate·PrimitiveIndexState·Finding/report pointer 갱신은 모두 0이다.
- **11. FALSE 변환 금지**: 평가 결과 차단은 취약점 의미 판정이 아니다. 운영 verdict를 새로 만들거나 기존 verdict를 덮어쓰지 않는다.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R6·R4·R5·R8. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-VER-011 — 평가 mode의 trigger·실행·skip reason 조합

- **1. ID·유형·설명**: R3-CT-VER-011 / 정상·부정 / 평가 CONDITIONAL_DEBATE·BASIC 기록 정합성
- **2. 단계·계약 경계**: 8, 10, 13; EVALUATION Debate 정책·Pro/Con 실행·VerificationResult 기록
- **3. producer → consumer**: versioned Debate trigger 평가 → PRO·CON child work → Debate Join Runtime → VerificationResult 저장 검사
- **4. 선행 상태·exact refs**: `purpose=EVALUATION`, exact DP-EVAL1과 eval_config_refs를 고정한다. trigger code는 승인된 설정에 있는 값만 사용하며 중복 없이 기록한다.
- **5. 정상/잘못된 fixture**: 정상 A는 CONDITIONAL+trigger 충족+두 Agent 실행+충족 code+skip null, 정상 B는 CONDITIONAL+trigger 없음+미실행+`[]`+`NO_TRIGGER_MATCH`, 정상 C는 BASIC+미실행+`[]`+`MODE_BASIC`. 부정 변형은 trigger가 있는데 생략, trigger가 없는데 실행, 실행하면서 skip reason 기록, 생략하면서 skip reason null, BASIC에서 호출 또는 임의 trigger 기록이다.
- **6. 검사 주체**: trusted trigger evaluator + PRO·CON 호출 spy + Runtime Validator·Debate Join Runtime + R6 semantic validator
- **7. 허용·차단·격리 기대**: A~C의 정확한 조합만 평가 결과 저장 허용. 부정 변형은 Provider 호출 전 또는 결과 저장 전에 차단하며 Runtime이 trigger/skip reason을 추정 보정하지 않는다.
- **8. work·attempt·가설 기대**: A는 두 child 성공 뒤 평가 합성, B/C는 child work 없이 평가 Verification만 정상 완료 가능. 부정 변형은 current 평가 result로 연결하지 않는다.
- **9. 오류·DataGap 기대**: mode·trigger·skip 기록 semantic 위반. exact 오류는 Q-02이며 운영 FALSE/HOLD와 무관하다.
- **10. 저장·갱신 금지 pointer**: 정상 평가 result에는 실제 조합과 eval refs를 보존. 부정 후보·관계없는 trigger·누락 skip reason은 current pointer 갱신 금지.
- **11. FALSE 변환 금지**: 평가 mode의 기록 오류나 호출 생략은 운영 취약점 반증이 아니며 운영 결과로 승격하지 않는다.
- **12. 실행 계층**: unit / contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R6·R4·R8. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-VER-012 — ValidationCheck ID 집합과 evidence 완전성

- **1. ID·유형·설명**: R3-CT-VER-012 / 부정 / final validation ID 집합·완료·근거 완전성
- **2. 단계·계약 경계**: 11, 13; 가설 ValidationCheck → final ValidationCheckResult → VerificationResult 저장
- **3. producer → consumer**: exact VulnerabilityHypothesis의 validation checks와 각 검증 결과 → R6 final 합성 / Runtime Validator
- **4. 선행 상태·exact refs**: F-VER(§2.3)의 같은 work·generation·application. 가설 validation_id 집합 `VID={v1,v2,v3}`과 각 ID의 COMPLETE·비어 있지 않은 실제 evidence를 가진 정상 final 후보를 준비한다.
- **5. 정상/잘못된 fixture**: 정상은 결과 ID가 VID와 중복 없이 set-equal. 변형 A는 v3 누락, B는 v2 중복, C는 무관한 vx 추가, D는 `completion=INCOMPLETE`, E는 COMPLETE이지만 `evidence_refs=[]`, F는 다른 work/generation/application의 evidence를 연결한다.
- **6. 검사 주체**: Runtime Validator의 exact set/work/generation/reference 검사 + R6 validation semantic validator
- **7. 허용·차단·격리 기대**: 정상만 final 후보 저장 허용. A~F는 누락을 추정하거나 중복 제거·근거 대체를 하지 않고 전체 final 저장을 차단한다.
- **8. work·attempt·가설 기대**: 부정 후보로 Verification work를 SUCCEEDED 또는 가설을 TERMINAL로 만들지 않는다. 복구 정책에 따른 BLOCKED/FAILED 여부는 실제 원인과 Q-02로 결정한다.
- **9. 오류·DataGap 기대**: validation 집합·completion·evidence semantic/reference 오류. exact code는 Q-02이며 빠진 검사는 DataGap/미완료 근거로만 보존한다.
- **10. 저장·갱신 금지 pointer**: 잘못된 VerificationResult와 current verification_result_ref, CWE·Gate·Primitive·Reporter 후속 pointer를 만들지 않는다.
- **11. FALSE 변환 금지**: check 누락·중복·빈 evidence·stale evidence를 실제 DISPROVED 근거로 사용하지 않는다.
- **12. 실행 계층**: unit / contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R6·R4·R2·R7. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-VER-013 — Falsification 질문 집합과 FALSE·HOLD 근거 완전성

- **1. ID·유형·설명**: R3-CT-VER-013 / 정상·부정 / final falsification 질문·근거·rationale·HOLD 조건 완전성
- **2. 단계·계약 경계**: 8, 11, 13; 가설 질문+PlaybookApplication 질문 → FalsificationResult → final verdict
- **3. producer → consumer**: VulnerabilityHypothesis·current PlaybookApplication 질문 → Verification Agent / Runtime Validator → final 저장
- **4. 선행 상태·exact refs**: F-VER(§2.3)의 exact H-A/PA1/work/generation. 기대 질문 집합 `QSET`은 가설 질문 ID와 PA1 질문 ID의 중복 없는 합집합이며 각 질문에는 정확히 하나의 결과·실제 evidence·비어 있지 않은 rationale이 있다.
- **5. 정상/잘못된 fixture**: 정상 A는 실제 반증 evidence와 rationale을 가진 `DISPROVED` 질문으로 FALSE, 정상 B는 완료된 정상 확인 근거와 비어 있지 않은 `unresolved_conditions`로 HOLD. 부정 변형은 질문 하나 누락, ID 중복, 관계없는 ID 추가, 다른 work/generation/application 질문 또는 evidence 사용, DISPROVED의 빈 evidence/rationale, HOLD의 빈 unresolved_conditions, HOLD에 정상 확인 evidence 없음이다.
- **6. 검사 주체**: Runtime Validator의 QSET set-equality·exact application/work/generation 검사 + R6 falsification/verdict semantic validator
- **7. 허용·차단·격리 기대**: 정상 A/B만 전문 의미 검사 뒤 저장 후보가 된다. 모든 부정 변형은 final 저장을 차단하며 Runtime이 질문·근거·rationale·미해결 조건을 만들어 채우거나 verdict를 바꾸지 않는다.
- **8. work·attempt·가설 기대**: 정상은 해당 전문 검증이 모두 완료됐을 때만 TERMINAL 가능. 부정 후보에는 current final result가 없고 기존 가설/Verification 상태를 임의 FALSE/HOLD로 끝내지 않는다.
- **9. 오류·DataGap 기대**: 질문 집합·근거·rationale·verdict semantic/reference 오류. exact code는 Q-02; 실제 미해결 조건은 DataGap/limitations와 구분해 보존한다.
- **10. 저장·갱신 금지 pointer**: 부정 VerificationResult, current pointer, CWE·Gate·Primitive·Reporter 입력 생성 금지. 정상 FALSE/HOLD도 허용된 종료 경로 외 후속 Gate로 보내지 않는다.
- **11. FALSE 변환 금지**: 오류·누락을 FALSE로 만들지 않는다. FALSE는 모든 필수 검사를 정상 완료하고 실제 질문별 반증 evidence와 rationale이 있을 때만 허용한다.
- **12. 실행 계층**: contract / integration / E2E / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R6·R4·R2·R7. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

### DYN. 동적 재현·Sandbox·PoC

근거: 04·08·10. 모든 사례는 **미실행 / 역할 검토 필요**.

#### R3-CT-DYN-001 — 요청·recipe·AgentLog·PoC 정상 연결

- **1. ID·유형·설명**: R3-CT-DYN-001 / 정상 / 요청·recipe·AgentLog·PoC 정상 연결
- **2. 단계·계약 경계**: 11–13; 동적 재현·Sandbox·PoC
- **3. producer → consumer**: R6 요청 → Dynamic Reproduction Agent(requirements·plan·candidate·해석) / Setup Automation(recipe·image·container·cleanup) / Sandbox Controller(SandboxProfile 외부 경계 판정) / Reproduction Session Manager(log·validated PoC·dynamic result) → R6
- **4. 선행 상태·exact refs**: F-DYN(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 같은 verification generation의 exact R6 request 아래 역할별 producer가 자기 record를 만든다. 정상 DX1은 `status=SUCCEEDED`, `hypothesis_outcome=SUPPORTED`, `agent_invoked=true`이고 LOG1이 exact PC1 revision·content_digest를 실제 실행해 지지 관측을 만든다. POC1의 request·plan·recipe·environment·log·candidate·execution action/digest는 DX1과 같은 work/attempt에서 exact match하며 생성 자원이 있으면 CL1도 같은 attempt에 연결된다.
- **6. 검사 주체**: Runtime Validator의 producer/authority 검사 + Sandbox Controller의 SandboxProfile 외부 경계 검사 + Setup Automation lifecycle 검사 + Session Manager same-attempt/provenance/result-owner 검사; 관측 의미는 Dynamic Reproduction Agent
- **7. 허용·차단·격리 기대**: Session Manager가 producer identity, `SUCCEEDED + SUPPORTED + agent_invoked=true`, same-attempt candidate·command·environment·관찰·digest와 cleanup을 확인한 뒤에만 POC1과 DX1을 확정한다. Dynamic Reproduction Agent가 recipe/environment/validated PoC/final result를 직접 저장하려 하면 차단한다.
- **8. work·attempt·가설 기대**: DYNAMIC_REPRO work/attempt SUCCEEDED; R6는 아직 최종 판정 전 VERIFYING.
- **9. 오류·DataGap 기대**: 없음
- **10. 저장·갱신 금지 pointer**: dynamic result·validated poc_ref·AgentLog·environment/recipe/candidate refs·cleanup 결과와 COMMITTED pointer 일치.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R7·R4·R6·R8. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-DYN-002 — 같은 generation의 중복 dynamic work

- **1. ID·유형·설명**: R3-CT-DYN-002 / 부정 / 같은 generation의 중복 dynamic work
- **2. 단계·계약 경계**: 11–13; 동적 재현·Sandbox·PoC
- **3. producer → consumer**: R6 요청 → Dynamic Reproduction Agent(requirements·plan·candidate·해석) / Setup Automation(recipe·image·container·cleanup) / Sandbox Controller(SandboxProfile 외부 경계 판정) / Reproduction Session Manager(log·validated PoC·dynamic result) → R6
- **4. 선행 상태·exact refs**: F-DYN(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 동일 verification generation에 두 개의 서로 다른 DYNAMIC_REPRO work를 등록하려 한다.
- **6. 검사 주체**: Runtime Validator의 producer/authority 검사 + Sandbox Controller의 SandboxProfile 외부 경계 검사 + Setup Automation lifecycle 검사 + Session Manager same-attempt/provenance/result-owner 검사; 관측 의미는 Dynamic Reproduction Agent
- **7. 허용·차단·격리 기대**: 기존 logical work 재사용/중복 등록 거절; 일반 retry는 새 work가 아님.
- **8. work·attempt·가설 기대**: 기존 work·attempt 상태 유지; 두 번째 active dynamic work 없음.
- **9. 오류·DataGap 기대**: 중복 등록 경계 Q-02
- **10. 저장·갱신 금지 pointer**: 중복 방지 trace; request/work 연결 한 개 유지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R7·R4·R6·R8. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-DYN-003 — Sandbox 밖 강제 경계 우회

- **1. ID·유형·설명**: R3-CT-DYN-003 / 부정 / Sandbox 밖 강제 경계 우회
- **2. 단계·계약 경계**: 11–13; 동적 재현·Sandbox·PoC
- **3. producer → consumer**: R6 요청 → Dynamic Reproduction Agent(requirements·plan·candidate·해석) / Setup Automation(recipe·image·container·cleanup) / Sandbox Controller(SandboxProfile 외부 경계 판정) / Reproduction Session Manager(log·validated PoC·dynamic result) → R6
- **4. 선행 상태·exact refs**: F-DYN(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: Controller 검사 없이 host command·Docker socket·비허용 mount/namespace·secret·egress·다른 workspace 사용을 요청한다. 별도 변형은 plan을 내부 command allowlist로 강제하거나 R6가 exact command를 지시한다. 반대 변형은 program policy가 `ABSENT | UNVERIFIED | BLOCKED | FAILED`여도 exact SandboxProfile 외부 경계를 지키는 `LOCAL_ONLY` 실행을 제출한다.
- **6. 검사 주체**: Runtime Validator의 producer/authority 검사 + Sandbox Controller의 SandboxProfile 외부 경계 검사 + Setup Automation lifecycle 검사 + Session Manager same-attempt/provenance/result-owner 검사; 관측 의미는 Dynamic Reproduction Agent
- **7. 허용·차단·격리 기대**: exact SandboxProfile 외부 경계 우회만 Controller가 차단한다. R6는 목적만 요청하고 Dynamic Reproduction Agent가 허가된 Sandbox 안의 실행 방식을 정한다. Controller는 program policy나 container 내부 command 의미를 다시 판정하지 않으며, policy 준비 상태만으로 `LOCAL_ONLY` 실행을 차단하지 않는다. LLM이 직접 host 도구를 실행하지 않는다.
- **8. work·attempt·가설 기대**: SandboxProfile 외부 경계 차단은 실제 대기 가능성에 따라 BLOCKED 또는 FAILED이며 R6 final verdict는 없다. program policy 상태만 다른 정상 LOCAL_ONLY fixture는 같은 work를 계속할 수 있다.
- **9. 오류·DataGap 기대**: SANDBOX_POLICY_DENIED / ACTION_NOT_ALLOWED; plan schema 매핑 Q-02
- **10. 저장·갱신 금지 pointer**: 적용한 exact SandboxProfile·DynamicReproductionLifecycleProfile을 action checked refs와 SPD1에서 추적하고 DX1.policy_decision_ref로 같은 SPD1에 연결한다. RunPolicyState는 별도 audit ref로만 남긴다. 차단 action·최소 AgentLog·반환 dynamic result를 경계 계약대로 기록하며 실제 host 실행은 없다.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R7·R4·R6·R8. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-DYN-004 — 실행 실패를 반증으로 오인

- **1. ID·유형·설명**: R3-CT-DYN-004 / 부정 / 실행 실패를 반증으로 오인
- **2. 단계·계약 경계**: 11–13; 동적 재현·Sandbox·PoC
- **3. producer → consumer**: R6 요청 → Dynamic Reproduction Agent(requirements·plan·candidate·해석) / Setup Automation(recipe·image·container·cleanup) / Sandbox Controller(SandboxProfile 외부 경계 판정) / Reproduction Session Manager(log·validated PoC·dynamic result) → R6
- **4. 선행 상태·exact refs**: F-DYN(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: SandboxProfile 외부 경계 차단·환경 구성 실패·container 실패·timeout을 각각 주입하고 DISPROVED/FALSE/HOLD 또는 non-null poc_ref를 제출한다. 실행 전에 exact request 또는 SandboxProfile revision이 바뀌었는데 기존 ALLOW/SPD1이나 기존 work를 재사용하는 변형도 포함한다.
- **6. 검사 주체**: Runtime Validator의 producer/authority 검사 + Sandbox Controller의 SandboxProfile 외부 경계 검사 + Setup Automation lifecycle 검사 + Session Manager same-attempt/provenance/result-owner 검사; 관측 의미는 Dynamic Reproduction Agent
- **7. 허용·차단·격리 기대**: 실행 실패와 기술적 반증을 구분해 제출 거절하고 신뢰 관측 없는 verdict를 금지한다. exact request 또는 SandboxProfile revision 변경은 기존 action/decision을 만료시키며, 기존 immutable work를 RESUME하지 않고 새 Verification generation과 새 동적 work를 요구한다.
- **8. work·attempt·가설 기대**: 외부 대기 BLOCKED, session 재시작 가능 RETRY, 소진/복구불가 FAILED를 원인별 적용; hypothesis final result 없음.
- **9. 오류·DataGap 기대**: 실제 SANDBOX/PROVIDER/POLICY 오류·DataGap. 상태 조합 세부 Q-02
- **10. 저장·갱신 금지 pointer**: poc_ref=null, 최소 log·failure 원인·dynamic result/history 보존; validated/current final verdict 생성 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R7·R4·R6·R8. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-DYN-005 — PoC candidate와 validated PoC 분리

- **1. ID·유형·설명**: R3-CT-DYN-005 / 부정 / PoC candidate와 validated PoC 분리
- **2. 단계·계약 경계**: 11–13; 동적 재현·Sandbox·PoC
- **3. producer → consumer**: R6 요청 → Dynamic Reproduction Agent(requirements·plan·candidate·해석) / Setup Automation(recipe·image·container·cleanup) / Sandbox Controller(SandboxProfile 외부 경계 판정) / Reproduction Session Manager(log·validated PoC·dynamic result) → R6
- **4. 선행 상태·exact refs**: F-DYN(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: candidate만 존재하거나 `status!=SUCCEEDED`, `hypothesis_outcome!=SUPPORTED`, `agent_invoked=false`인데 poc_ref를 non-null로 제출한다. 별도 변형은 LOG1에 exact candidate revision·content_digest의 실제 실행 event가 없거나 candidate·command·environment·관찰 중 하나를 다른 work/attempt ref로 바꾼다.
- **6. 검사 주체**: Runtime Validator의 producer/authority 검사 + Sandbox Controller의 SandboxProfile 외부 경계 검사 + Setup Automation lifecycle 검사 + Session Manager same-attempt/provenance/result-owner 검사; 관측 의미는 Dynamic Reproduction Agent
- **7. 허용·차단·격리 기대**: 다섯 확정 조건을 모두 만족하지 않으면 `poc_ref=null`이어야 한다. candidate를 validated PoC로 승격하거나 latest lookup·추정으로 누락 연결을 채우는 저장은 차단한다.
- **8. work·attempt·가설 기대**: 실제 실행 상태는 보존; 가짜 TRUE/Gate 경로 진입 없음.
- **9. 오류·DataGap 기대**: semantic INVALID_OUTPUT; 참조 세부 Q-02
- **10. 저장·갱신 금지 pointer**: candidate와 실제 실패/관찰 history는 감사용으로 보존할 수 있으나 validated poc_ref·current TRUE·Technical Gate 입력 생성은 금지한다.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R7·R4·R6·R8. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-DYN-006 — 옛 attempt·digest·변조 AgentLog

- **1. ID·유형·설명**: R3-CT-DYN-006 / 부정 / 옛 attempt·digest·변조 AgentLog
- **2. 단계·계약 경계**: 11–13; 동적 재현·Sandbox·PoC
- **3. producer → consumer**: R6 요청 → Dynamic Reproduction Agent(requirements·plan·candidate·해석) / Setup Automation(recipe·image·container·cleanup) / Sandbox Controller(SandboxProfile 외부 경계 판정) / Reproduction Session Manager(log·validated PoC·dynamic result) → R6
- **4. 선행 상태·exact refs**: F-DYN(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 이전 attempt candidate/log/PoC 혼합, 다른 image digest, AgentLog event 수정·삭제·재정렬/sequence/action 불일치, exact candidate revision 또는 content_digest 불일치, command·environment·관찰 ref의 work/attempt 불일치를 각각 주입한다.
- **6. 검사 주체**: Runtime Validator의 producer/authority 검사 + Sandbox Controller의 SandboxProfile 외부 경계 검사 + Setup Automation lifecycle 검사 + Session Manager same-attempt/provenance/result-owner 검사; 관측 의미는 Dynamic Reproduction Agent
- **7. 허용·차단·격리 기대**: same-attempt·candidate revision·content/command digest·environment·관찰·append-only provenance 검사로 PoC/result commit을 차단한다. 승인된 baseline recipe 재사용은 현재 attempt의 새 recipe/environment binding과 previous_environment_ref 확인 후 별도 허용한다.
- **8. work·attempt·가설 기대**: current attempt의 정상 성공 확정 금지; 가설 판정 불변.
- **9. 오류·DataGap 기대**: STALE_RESULT 및 provenance/sequence 세부 Q-02
- **10. 저장·갱신 금지 pointer**: 원본 log/history 보존; 변조 결과와 current dynamic/PoC pointer 갱신 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R7·R4·R6·R8. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-DYN-007 — 같은 session의 자율 조정

- **1. ID·유형·설명**: R3-CT-DYN-007 / 정상 / 같은 session의 자율 조정
- **2. 단계·계약 경계**: 11–13; 동적 재현·Sandbox·PoC
- **3. producer → consumer**: R6 요청 → Dynamic Reproduction Agent(requirements·plan·candidate·해석) / Setup Automation(recipe·image·container·cleanup) / Sandbox Controller(SandboxProfile 외부 경계 판정) / Reproduction Session Manager(log·validated PoC·dynamic result) → R6
- **4. 선행 상태·exact refs**: F-DYN(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: Agent가 Sandbox 안에서 command→관찰→PoC/환경 수정→재실행한다.
- **6. 검사 주체**: Runtime Validator의 producer/authority 검사 + Sandbox Controller의 SandboxProfile 외부 경계 검사 + Setup Automation lifecycle 검사 + Session Manager same-attempt/provenance/result-owner 검사; 관측 의미는 Dynamic Reproduction Agent
- **7. 허용·차단·격리 기대**: 외부 경계와 예산 내에서 같은 work·attempt/session event로 기록. 매 명령마다 새 attempt 만들지 않음.
- **8. work·attempt·가설 기대**: DYNAMIC_REPRO work/attempt RUNNING 유지; 완료 때만 결과 확정.
- **9. 오류·DataGap 기대**: 정상 조정은 실행 오류로 억지 변환하지 않음
- **10. 저장·갱신 금지 pointer**: append-only AgentLog/action/observation 연결. Dynamic Reproduction Agent 결론과 Session Manager 조립을 분리.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R7·R4·R6·R8. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-DYN-008 — session 재시작과 외부 대기 재개

- **1. ID·유형·설명**: R3-CT-DYN-008 / 정상·부정 / session 재시작과 외부 대기 재개
- **2. 단계·계약 경계**: 11–13; 동적 재현·Sandbox·PoC
- **3. producer → consumer**: R6 요청 → Dynamic Reproduction Agent(requirements·plan·candidate·해석) / Setup Automation(recipe·image·container·cleanup) / Sandbox Controller(SandboxProfile 외부 경계 판정) / Reproduction Session Manager(log·validated PoC·dynamic result) → R6
- **4. 선행 상태·exact refs**: F-DYN(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: A: session crash 후 외부 입력 없이 새 시도 가능하며 runtime이 환경을 STATE_UNCERTAIN으로 강제한다. B: 현재 work 입력을 바꾸지 않는 재인증·외부 환경 정비·resource 확보 대기 후 조건이 해결된다. C: exact request 또는 SandboxProfile revision을 바꾼 뒤 기존 work와 policy decision을 재사용한다. D: program policy 준비 상태만 달라진 LOCAL_ONLY work를 불필요하게 중단한다.
- **6. 검사 주체**: Runtime Validator의 producer/authority 검사 + Sandbox Controller의 SandboxProfile 외부 경계 검사 + Setup Automation lifecycle 검사 + Session Manager same-attempt/provenance/result-owner 검사; 관측 의미는 Dynamic Reproduction Agent
- **7. 허용·차단·격리 기대**: A는 RUNNING→READY→RUNNING, 새 attempt `trigger=RETRY`이며 clean container를 재생성한다. B는 input_refs/input_hash가 같을 때만 BLOCKED→READY→RUNNING과 `trigger=RESUME`를 허용한다. C는 기존 action을 만료시키고 새 Verification generation·새 동적 work로 분리한다. D는 program policy 상태를 Sandbox 허가 조건으로 쓰지 않고 기존 LOCAL_ONLY 실행을 계속한다. 모든 경로에 한도·cleanup 검사가 필요하다.
- **8. work·attempt·가설 기대**: A/B는 같은 work_id에서 과거 attempt 종료/history와 새 active attempt 하나를 유지한다. C는 기존 work를 재개하지 않고 새 generation/work를 등록한다. final verdict는 없다.
- **9. 오류·DataGap 기대**: 이전 오류 보존; 한도 소진 BUDGET_EXCEEDED 또는 해당 종료 오류
- **10. 저장·갱신 금지 pointer**: 이전 log/결과 보존, 새 환경/provenance 연결. BLOCKED work.finished_at=null이지만 반환된 attempt 결과의 finished_at은 기록.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R7·R4·R6·R8. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-DYN-009 — R7 구성요소별 생산 권한 분리

- **1. ID·유형·설명**: R3-CT-DYN-009 / 정상·부정 / Dynamic Reproduction Agent·Setup Automation·Controller·Session Manager 생산 책임 분리
- **2. 단계·계약 경계**: 11–13; R7 result-owner registry·SAVE_RESULT authority·동적 결과 조립
- **3. producer → consumer**: Dynamic Reproduction Agent(requirements·plan·candidate·해석) / Setup Automation(recipe·image·container·cleanup) / Sandbox Controller(SandboxProfile 외부 경계 판정) / Reproduction Session Manager(log·validated PoC·dynamic result) → R6
- **4. 선행 상태·exact refs**: F-DYN(§2.3)의 정상 역할별 record와 같은 KD1/ADYN1. 각 action requested_by, result kind, schema와 result-owner registry를 exact revision으로 고정한다.
- **5. 정상/잘못된 fixture**: 정상은 네 구성요소가 자기 소유 결과만 생산한다. 부정 변형은 Dynamic Reproduction Agent가 recipe/environment/cleanup/PoCBundle/DynamicReproductionResult를 저장하거나, Setup Automation이 AgentLog/판정, Controller가 recipe/result, Session Manager가 requirements/plan/candidate/실행 전략을 생산한다.
- **6. 검사 주체**: Runtime Validator의 requested_by·action·result-kind·schema·owner·input refs 검사 + State Store의 단일 producer 검사
- **7. 허용·차단·격리 기대**: 정상 역할별 결과만 저장·조립 허용. 권한 밖 결과는 provider/host 실행 또는 저장 전에 차단하며 Session Manager가 Dynamic Reproduction Agent의 동적 해석을 새 결론으로 바꾸지 않는다.
- **8. work·attempt·가설 기대**: 잘못된 producer의 action/result는 DYNAMIC_REPRO 성공으로 연결되지 않는다. 기존 current attempt와 가설은 실제 실패 전파 규칙 외에는 불변이다.
- **9. 오류·DataGap 기대**: `AUTHORITY_DENIED | ACTION_NOT_ALLOWED` 또는 result-owner 위반. exact 조합은 Q-02.
- **10. 저장·갱신 금지 pointer**: 권한 밖 record·current pointer·validated PoC·final dynamic result 저장 금지. 거절 trace에는 요청 역할·result kind·expected owner를 비밀 없이 기록한다.
- **11. FALSE 변환 금지**: 생산 권한 위반을 기술적 반증으로 사용하지 않고 R6 final verdict를 생성하지 않는다.
- **12. 실행 계층**: unit / contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R7·R4·R6. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-DYN-010 — validated PoC exact 확정 조건

- **1. ID·유형·설명**: R3-CT-DYN-010 / 정상·부정 / validated PoC의 상태·관측·same-attempt 완전성
- **2. 단계·계약 경계**: 12–13; PoCCandidate 실행 → PoCBundle 확정 → DynamicReproductionResult.poc_ref
- **3. producer → consumer**: Dynamic Reproduction Agent candidate·Setup Automation environment·Runtime command/observation → Session Manager PoCBundle/result → R6
- **4. 선행 상태·exact refs**: F-DYN(§2.3)의 정상 DQ1/PL1/RC1/ENV1/PC1/LOG1/POC1/DX1. PC1 revision과 content_digest, 실행 command/action, 환경과 관찰 refs를 ADYN1에 고정한다.
- **5. 정상/잘못된 fixture**: 정상은 `status=SUCCEEDED`, `hypothesis_outcome=SUPPORTED`, `agent_invoked=true`, same-attempt LOG1의 PC1 exact revision·content_digest 실제 실행과 지지 관측, candidate·command·environment·observation exact 연결을 모두 만족한다. 부정 변형은 이 다섯 조건을 하나씩 제거·변조한다.
- **6. 검사 주체**: Session Manager의 PoCBundle/result 조립 검사 + Runtime Validator의 status/outcome/agent event/exact ref·digest·work/attempt 검사
- **7. 허용·차단·격리 기대**: 정상만 non-null `poc_ref`와 validated POC1 확정. 어떤 조건이든 빠지면 `poc_ref=null`; candidate 존재·exit code 0·최신 결과라는 이유만으로 성공을 추정하지 않는다.
- **8. work·attempt·가설 기대**: 정상 dynamic attempt는 SUCCEEDED. 부정 후보는 validated PoC 성공으로 끝내지 않고 실제 실행 상태와 오류를 보존하며 가설은 R6 final 전 VERIFYING이다.
- **9. 오류·DataGap 기대**: status/outcome/agent log/provenance semantic 오류 또는 `STALE_RESULT`; 세부 매핑 Q-02.
- **10. 저장·갱신 금지 pointer**: 부정 PoCBundle·DX1.poc_ref·Verification TRUE·Technical Gate pointer 갱신 금지. PC1과 유효 log history는 역할 계약에 따라 보존한다.
- **11. FALSE 변환 금지**: PoC 확정 실패는 반증이 아니다. 실제 DISPROVED 관측과 named falsification이 없는 한 FALSE를 만들지 않는다.
- **12. 실행 계층**: contract / integration / E2E / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R7·R4·R6·R5. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-DYN-011 — SandboxProfile 경계와 program policy 감사 분리

- **1. ID·유형·설명**: R3-CT-DYN-011 / 정상·부정 / SandboxProfile 외부 경계 판정과 RunPolicyState 감사 reference 분리
- **2. 단계·계약 경계**: 12; RUN_SANDBOX action/decision → SandboxPolicyDecision·AgentLog·dynamic result
- **3. producer → consumer**: R7 SandboxProfile registry·R8 lifecycle profile registry·Runtime 감사 context → Sandbox Controller·Setup Automation·Session Manager → R6
- **4. 선행 상태·exact refs**: DQ1, current ER1·PL1, exact SandboxProfile SP1과 DynamicReproductionLifecycleProfile LP1을 RUN_SANDBOX input/checked refs에 고정한다. current RunPolicyState RPS1은 별도 audit ref로만 기록하고 KD1 input_refs/input_hash·Controller 허가·R6 verdict 근거에는 넣지 않는다.
- **5. 정상/잘못된 fixture**: 정상 A는 SP1이 허용한 LOCAL_ONLY 실행과 SPD1→LOG1→DX1 same-attempt 연결이다. 정상 B는 RPS1이 `ABSENT | UNVERIFIED | BLOCKED | FAILED`여도 SP1 경계를 지키면 실행한다. 부정 변형은 SP1 없는 실행, host/Docker/mount/namespace/secret/egress/workspace 위반, SPD1 refs 불일치, `POLICY_BLOCKED`인데 `decision!=DENY`, program policy 상태만으로 Controller가 차단하는 경우다.
- **6. 검사 주체**: Runtime Validator의 exact config·action·audit ref 분리 검사 + Sandbox Controller의 SandboxProfile 외부 경계 검사 + Session Manager same-attempt provenance 검사
- **7. 허용·차단·격리 기대**: SP1 경계를 지킨 A/B만 허용한다. 외부 경계 위반은 Agent 시작 전에 `POLICY_BLOCKED + SANDBOX_POLICY_DENIED`로 차단하지만 program policy의 testing restriction은 여기서 해석하지 않고 Technical ACCEPT 뒤 Rule Scope Gate가 검토한다.
- **8. work·attempt·가설 기대**: 외부 경계 차단은 대기 가능한 동일 입력 조건이면 BLOCKED, 최종 거절이면 FAILED이고 `agent_invoked=false`다. program policy 상태만으로 work를 중단하거나 새 attempt를 만들지 않는다.
- **9. 오류·DataGap 기대**: 외부 경계 위반은 `POLICY_BLOCKED`와 `SANDBOX_POLICY_DENIED`; audit/current reference 불일치는 Q-02. program policy 없음·불확실은 이 오류로 바꾸지 않는다.
- **10. 저장·갱신 금지 pointer**: exact SPD1·차단 event·AgentLog·dynamic result와 audit RPS1을 보존하되 외부 경계 차단이면 `poc_ref=null`. program policy를 DQ1이나 KD1 immutable input으로 복사하지 않는다.
- **11. FALSE 변환 금지**: 외부 경계 차단, policy 부재·불확실과 audit reference 문제는 가설 반증이 아니며 `DISPROVED | FALSE | HOLD`로 전환하지 않는다.
- **12. 실행 계층**: contract / integration / E2E / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R7·R4·R5·R6·R8. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-DYN-012 — container lifecycle·재생성·cleanup

- **1. ID·유형·설명**: R3-CT-DYN-012 / 정상·부정 / clean container·격리·재사용·재생성·정리 완전성
- **2. 단계·계약 경계**: 12; Setup Automation environment lifecycle·AgentLog·CleanupResult·DynamicReproductionResult
- **3. producer → consumer**: Setup Automation의 recipe/image/container/cleanup → Session Manager log/result → R6
- **4. 선행 상태·exact refs**: F-DYN(§2.3)의 KD1/ADYN1과 Setup Automation 소유 RC1/ENV1/CL1. 생성 자원 목록, container_instance_id, container_action/reason, previous_environment_ref와 cleanup_required/status/ref를 고정한다.
- **5. 정상/잘못된 fixture**: A 첫 attempt는 `CREATED + INITIAL_CLEAN + previous_environment_ref=null`; B 안전한 같은 가설/work 재사용은 `REUSED + NO_RELEVANT_CHANGE`와 이전 환경 ref; C `STATE_CHANGED | CONFIG_CHANGED | STATE_UNCERTAIN`은 재생성과 이전/새 환경·log event; crash·비정상 종료·사후 Health Check 실패는 STATE_UNCERTAIN 강제. 부정 변형은 다른 가설 writable container 공유, 상태 변화 뒤 재사용, previous ref/event 누락, 생성 자원이 있는데 cleanup 생략/NOT_REQUIRED, 자원이 없는데 cleanup 성공/실패 기록이다.
- **6. 검사 주체**: Setup Automation lifecycle/자원 목록 + Runtime Validator의 가설/work/attempt/container 관계 + Session Manager AgentLog·CleanupResult·final cleanup field 검사
- **7. 허용·차단·격리 기대**: A~C의 정확한 lifecycle만 허용. 다른 가설 공유와 부적절한 재사용은 실행 전 차단 또는 환경 재생성을 요구한다. 생성 자원이 하나라도 있으면 실패·차단 뒤에도 cleanup을 수행하고 exact CL1을 보존한다.
- **8. work·attempt·가설 기대**: cleanup 성공 여부와 재현 성공 여부를 분리한다. cleanup 실패는 자원 격리·운영 오류로 남기고 가설 verdict를 바꾸지 않는다. 새 attempt에는 current environment binding 하나만 사용한다.
- **9. 오류·DataGap 기대**: 환경 격리/lifecycle/provenance/cleanup 계약 위반, cleanup 실패 원인. exact code는 Q-02이며 crash는 STATE_UNCERTAIN을 강제한다.
- **10. 저장·갱신 금지 pointer**: 실제 자원이 있으면 `cleanup_required=true`, `cleanup_status=SUCCEEDED | FAILED`, non-null cleanup_ref. 아무 자원도 없을 때만 `false + NOT_REQUIRED + null` 허용. 위반 결과와 environment/current PoC pointer 갱신 금지.
- **11. FALSE 변환 금지**: container·Health Check·cleanup 실패는 동적 실행 오류이지 기술적 반증이 아니다.
- **12. 실행 계층**: unit / contract / integration / E2E / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R7·R4·R6·R8. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

### GAT. CWE·두 Gate·정책·Finding

근거: 05·06·08·10. 모든 사례는 **미실행 / 역할 검토 필요**.

#### R3-CT-GAT-001 — TRUE→CWE→Technical→Rule Scope 정상 순서

- **1. ID·유형·설명**: R3-CT-GAT-001 / 정상 / TRUE→CWE→Technical→Rule Scope 정상 순서
- **2. 단계·계약 경계**: 14–17, 19; CWE·두 Gate·정책·Finding
- **3. producer → consumer**: run-init Policy Collector·Policy Parser → RunPolicyState; Verification → CWE_LABELING → TECHNICAL_GATE → RULE_SCOPE_GATE → Admission/Finding trusted runtime
- **4. 선행 상태·exact refs**: F-GAT(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: run 시작의 `POLICY_FETCH`가 FOUND collection·ProgramPolicyRecord·current RunPolicyState를 먼저 고정한다. 이후 final TRUE와 current validated PoC→동일 Verification CWE→Technical ACCEPT→고정한 정책을 읽는 Rule Scope PASS/ALLOW fixture를 순서대로 공급한다.
- **6. 검사 주체**: Runtime Validator·domain semantic validator·Finding normalizer; Gate 의미 판단은 R5 LLM
- **7. 허용·차단·격리 기대**: 각 exact 선행 결과와 owner action을 확인하고 다음 work 허용. Gate 의미는 R5 담당.
- **8. work·attempt·가설 기대**: 각 해당 work/attempt SUCCEEDED; 가설 TERMINAL TRUE 유지.
- **9. 오류·DataGap 기대**: 없음
- **10. 저장·갱신 금지 pointer**: cwe_labels/gates/policies에 각 exact record·commit. 서로 다른 결과 revision으로 pointer 혼합 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / E2E
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R5·R4·R6·R1. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-GAT-002 — 잘못된 verdict·CWE·Gate 순서

- **1. ID·유형·설명**: R3-CT-GAT-002 / 부정 / 잘못된 verdict·CWE·Gate 순서
- **2. 단계·계약 경계**: 14–17, 19; CWE·두 Gate·정책·Finding
- **3. producer → consumer**: run-init Policy Collector·Policy Parser → RunPolicyState; Verification → CWE_LABELING → TECHNICAL_GATE → RULE_SCOPE_GATE → Admission/Finding trusted runtime
- **4. 선행 상태·exact refs**: F-GAT(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: FALSE/HOLD/실패 가설에 CWE/Gate, CWE 없는 Technical, 오래된 CWE, Technical 이전 Rule Scope, Gate가 CWE 직접 수정하는 변형.
- **6. 검사 주체**: Runtime Validator·domain semantic validator·Finding normalizer; Gate 의미 판단은 R5 LLM
- **7. 허용·차단·격리 기대**: 호출/저장 차단; producer·순서·same-Verification 검사를 모두 유지.
- **8. work·attempt·가설 기대**: 기존 판정 유지; 부적격 Gate/CWE work 성공 없음.
- **9. 오류·DataGap 기대**: STALE_RESULT / ACTION_NOT_ALLOWED; 선행조건 Q-02
- **10. 저장·갱신 금지 pointer**: 거절 trace. 잘못된 CWE/Gate/current pointer 생성 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / E2E
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R5·R4·R6·R1. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-GAT-003 — CWE나 Gate 호출 장애

- **1. ID·유형·설명**: R3-CT-GAT-003 / 부정 / CWE나 Gate 호출 장애
- **2. 단계·계약 경계**: 14–17, 19; CWE·두 Gate·정책·Finding
- **3. producer → consumer**: run-init Policy Collector·Policy Parser → RunPolicyState; Verification → CWE_LABELING → TECHNICAL_GATE → RULE_SCOPE_GATE → Admission/Finding trusted runtime
- **4. 선행 상태·exact refs**: F-GAT(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: final TRUE 이후 CWE 또는 Technical 호출이 timeout/auth/invalid output으로 실패한다.
- **6. 검사 주체**: Runtime Validator·domain semantic validator·Finding normalizer; Gate 의미 판단은 R5 LLM
- **7. 허용·차단·격리 기대**: 이후 Gate/보고 흐름은 멈추되 이미 검증된 TRUE를 FALSE로 덮어쓰지 않음.
- **8. work·attempt·가설 기대**: 해당 work retryable BLOCKED, 소진 FAILED; hypothesis 기존 TERMINAL TRUE 유지.
- **9. 오류·DataGap 기대**: 실제 invocation 오류 Q-02
- **10. 저장·갱신 금지 pointer**: 실패 호출/한계 기록; 실패 CWE/Gate를 current 정상 결과로 사용 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / E2E
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R5·R4·R6·R1. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-GAT-004 — 공식 정책 부재 확인

- **1. ID·유형·설명**: R3-CT-GAT-004 / 정상·부정 / 공식 정책 부재 확인
- **2. 단계·계약 경계**: 14–17, 19; CWE·두 Gate·정책·Finding
- **3. producer → consumer**: run-init Policy Collector·Policy Parser → RunPolicyState; Verification → CWE_LABELING → TECHNICAL_GATE → RULE_SCOPE_GATE → Admission/Finding trusted runtime
- **4. 선행 상태·exact refs**: F-GAT(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 공식 근거로 PolicyCollectionResult=ABSENT_CONFIRMED, policy_record_ref=null. 변형은 정책 record를 붙이거나 PASS/ALLOW 보고 허용.
- **6. 검사 주체**: Runtime Validator·domain semantic validator·Finding normalizer; Gate 의미 판단은 R5 LLM
- **7. 허용·차단·격리 기대**: 정상 Rule Scope UNCERTAIN+DENY, Reporter 차단. 변형 semantic 거절. 부재를 추정으로 만들지 않음.
- **8. work·attempt·가설 기대**: 정상 review work는 처리 완료 SUCCEEDED일 수 있음; hypothesis TRUE 불변.
- **9. 오류·DataGap 기대**: 정상 부재 자체 오류 아님; 불일치 INVALID_OUTPUT
- **10. 저장·갱신 금지 pointer**: collection/review/admission 기록. testing restriction UNCERTAIN의 admission ALLOW와 report DENY 구분.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / E2E
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R5·R4·R6·R1. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-GAT-005 — 정책 수집 실패는 공식 부재 아님

- **1. ID·유형·설명**: R3-CT-GAT-005 / 정상·부정 / 정책 수집 실패는 공식 부재 아님
- **2. 단계·계약 경계**: 14–17, 19; CWE·두 Gate·정책·Finding
- **3. producer → consumer**: run-init Policy Collector·Policy Parser → RunPolicyState; Verification → CWE_LABELING → TECHNICAL_GATE → RULE_SCOPE_GATE → Admission/Finding trusted runtime
- **4. 선행 상태·exact refs**: F-GAT(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: PolicyCollectionResult=COLLECTION_FAILED; 변형은 ABSENT_CONFIRMED/PASS로 위장하거나 Rule Scope 호출.
- **6. 검사 주체**: Runtime Validator·domain semantic validator·Finding normalizer; Gate 의미 판단은 R5 LLM
- **7. 허용·차단·격리 기대**: Rule Scope 미호출, admission testing status NOT_EVALUATED/decision ALLOW; Finding·Reporter 없음. 위장 거절.
- **8. work·attempt·가설 기대**: policy 수집 실패 원인 보존; hypothesis TRUE 유지; 보고 work 성공 없음.
- **9. 오류·DataGap 기대**: POLICY 수집 오류/DataGap; 위장 INVALID_OUTPUT/선행조건 Q-02
- **10. 저장·갱신 금지 pointer**: collection failure·admission 기록; RuleScopeImpactReview·Finding·ReportDraft를 만들어내지 않음.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / E2E
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R5·R4·R6·R1. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-GAT-006 — Primitive admission과 보고 자격 분리

- **1. ID·유형·설명**: R3-CT-GAT-006 / 정상·부정 / Primitive admission과 보고 자격 분리
- **2. 단계·계약 경계**: 14–17, 19; CWE·두 Gate·정책·Finding
- **3. producer → consumer**: run-init Policy Collector·Policy Parser → RunPolicyState; Verification → CWE_LABELING → TECHNICAL_GATE → RULE_SCOPE_GATE → Admission/Finding trusted runtime
- **4. 선행 상태·exact refs**: F-GAT(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: Rule Scope testing restriction PASS/UNCERTAIN/FAIL을 각각 사용. 다른 보고 축은 별개로 실패시킨다.
- **6. 검사 주체**: Runtime Validator·domain semantic validator·Finding normalizer; Gate 의미 판단은 R5 LLM
- **7. 허용·차단·격리 기대**: PASS/UNCERTAIN은 admission ALLOW, FAIL은 DENY. ALLOW만으로 Reporter 자격 생기지 않음.
- **8. work·attempt·가설 기대**: 가설 TRUE 유지; DENY이면 result Primitive 생성/소비 금지.
- **9. 오류·DataGap 기대**: 정상 정책 결정 자체는 실행 오류 아님
- **10. 저장·갱신 금지 pointer**: PrimitiveAdmissionDecision과 exact source review refs 저장; DENY의 Primitive/current index 승격 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / E2E
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R5·R4·R6·R1. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-GAT-007 — Finding 생성과 Reporter 차단 양립

- **1. ID·유형·설명**: R3-CT-GAT-007 / 정상 / Finding 생성과 Reporter 차단 양립
- **2. 단계·계약 경계**: 14–17, 19; CWE·두 Gate·정책·Finding
- **3. producer → consumer**: run-init Policy Collector·Policy Parser → RunPolicyState; Verification → CWE_LABELING → TECHNICAL_GATE → RULE_SCOPE_GATE → Admission/Finding trusted runtime
- **4. 선행 상태·exact refs**: F-GAT(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: current TRUE+dynamic/PoC+CWE+Technical ACCEPT+Rule Scope review가 있고 report_permission=DENY이다.
- **6. 검사 주체**: Runtime Validator·domain semantic validator·Finding normalizer; Gate 의미 판단은 R5 LLM
- **7. 허용·차단·격리 기대**: Finding은 trusted normalization으로 생성; Reporter는 여전히 차단. Finding은 새 취약점 판정이 아님.
- **8. work·attempt·가설 기대**: FINDING_NORMALIZE work/attempt SUCCEEDED, hypothesis TRUE; REPORT_DRAFT 성공 없음.
- **9. 오류·DataGap 기대**: REPORT_NOT_READY는 실제 보고 시도 시 적용
- **10. 저장·갱신 금지 pointer**: result_kind=finding, 생산 VERIFICATION service identity, 단일 output·FindingIndexState·commit CAS. review output은 한 개 유지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / E2E
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R5·R4·R6·R1. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-GAT-008 — Finding producer·closure·current index 검사

- **1. ID·유형·설명**: R3-CT-GAT-008 / 정상·부정 / Finding producer·closure·current index 검사
- **2. 단계·계약 경계**: 14–17, 19; CWE·두 Gate·정책·Finding
- **3. producer → consumer**: run-init Policy Collector·Policy Parser → RunPolicyState; Verification → CWE_LABELING → TECHNICAL_GATE → RULE_SCOPE_GATE → Admission/Finding trusted runtime
- **4. 선행 상태·exact refs**: F-GAT(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: R5 Gate/LLM이 Finding을 직접 저장, core upstream 누락, 서로 다른 Verification refs 혼합, CAS 경쟁을 각각 시험. 정상 정책 비종속 hypothesis_id=null도 별도 시험.
- **6. 검사 주체**: Runtime Validator·domain semantic validator·Finding normalizer; Gate 의미 판단은 R5 LLM
- **7. 허용·차단·격리 기대**: 잘못된 producer/closure/CAS 거절; 비종속 policy record에는 가설 ID equality를 강요하지 않음.
- **8. work·attempt·가설 기대**: 실패 normalization은 성공/current로 확정하지 않음; 기존 가설·Finding history 유지.
- **9. 오류·DataGap 기대**: ACTION_NOT_ALLOWED / STALE_RESULT / STATE_VERSION_CONFLICT; 세부 Q-02
- **10. 저장·갱신 금지 pointer**: 옛 Finding 불변; upstream 변경 시 current index stale 처리. 정확한 하나만 current, malformed Finding 제외.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / E2E
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R5·R4·R6·R1. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-GAT-009 — Technical 상태·전달 준비·REJECT 의미

- **1. ID·유형·설명**: R3-CT-GAT-009 / 정상·부정 / Technical Gate 상태와 handoff readiness 조합 및 REJECT 후속 차단
- **2. 단계·계약 경계**: 15–17, 19; Technical Gate output semantic과 후속 자격
- **3. producer → consumer**: Technical Evidence Gate Agent → Verification owner·Runtime Validator·Rule Scope/Primitive/Finding runtime
- **4. 선행 상태·exact refs**: F-GAT(§2.3)의 exact final TRUE V1, current CWELabel CW1, current dynamic/PoC와 성공한 Technical Gate work. 각 변형은 같은 exact pair와 action decision을 사용한다.
- **5. 정상/잘못된 fixture**: 정상 A는 `ACCEPT + READY`, 정상 B는 `REVISE + NOT_READY`, 정상 C는 `REJECT + NOT_READY`이며 evidence/verdict alignment·code flow·dynamic·CWE·restriction 설명과 rationale을 가진다. 부정 변형은 `ACCEPT + NOT_READY`, `REVISE | REJECT + READY`, 필수 검토 설명 누락, 다른 Verification/CWE revision 연결, REJECT 뒤 Rule Scope·Primitive·Finding·Reporter 요청이다.
- **6. 검사 주체**: Runtime Validator의 exact revision·status/readiness·Gate 순서 검사 + R5 Technical semantic validator
- **7. 허용·차단·격리 기대**: A만 같은 exact pair의 Rule Scope 입력 자격을 가진다. B는 VER-007의 같은 Verification owner 보완 경로로 보내고, C는 현재 자료의 후속 사용을 막는다. 모순 output은 review 저장을 차단하며 Gate가 verdict나 CWE를 바꾸지 않는다.
- **8. work·attempt·가설 기대**: 정상 Gate review work는 자기 review를 COMMITTED하고 SUCCEEDED로 끝난다. B는 새 Verification generation을 준비하고 C는 hypothesis의 기존 TERMINAL TRUE를 유지하되 downstream 성공 work는 만들지 않는다. 부정 output은 current review가 되지 않는다.
- **9. 오류·DataGap 기대**: 모순·필수 설명 누락은 INVALID_OUTPUT, stale pair는 STALE_RESULT 또는 RECORD_REVISION_MISMATCH, 후속 우회는 GATE_ORDER_INVALID/ACTION_NOT_ALLOWED; exact code 충돌은 Q-02
- **10. 저장·갱신 금지 pointer**: 정상 review와 action/log provenance만 보존한다. REVISE/REJECT 또는 invalid review를 RuleScopeImpactReview·Primitive·Finding·ReportDraft current pointer에 연결하지 않는다.
- **11. FALSE 변환 금지**: Technical `REJECT`, status/readiness 불일치와 Gate 출력 오류는 Verification의 실제 반증이 아니므로 기존 TRUE를 FALSE나 HOLD로 바꾸지 않는다.
- **12. 실행 계층**: contract / integration / E2E / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R5·R4·R6·R1. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-GAT-010 — Rule Scope 공식 정책·근거 연결

- **1. ID·유형·설명**: R3-CT-GAT-010 / 정상·부정 / Rule Scope 각 판단의 exact PolicyItem·공식 원문·실행 근거 연결
- **2. 단계·계약 경계**: 17, 19; Rule Scope semantic, evidence link와 missing information
- **3. producer → consumer**: Policy Collector·Policy Parser·Technical ACCEPT → Rule Scope Impact Gate Agent → Primitive Admission/Reporter runtime
- **4. 선행 상태·exact refs**: F-GAT(§2.3)의 current RPS1/COL1/POL1과 TG1. POL1의 각 PolicyItem은 공식 `source_ref + source_locator`를 가지며 RS1은 같은 exact policy/result revision만 사용한다.
- **5. 정상/잘못된 fixture**: 정상은 PASS/FAIL/SUFFICIENT/INSUFFICIENT인 각 판단 영역에 같은 area의 유일한 `RuleScopeEvidenceLink`와 실제 policy item·evidence를 연결하고, UNCERTAIN 영역에는 대응 `PolicyMissingInfo`를 둔다. 부정 변형은 link 누락·중복, 존재하지 않는 policy_item_id, 빈 evidence, area 불일치, source_ref/source_locator 누락, parser output만 공식 근거로 사용, 원문과 parser 모순인데 PASS/ALLOW, UNCERTAIN인데 missing_information 없음, `blocks_allow=true`인데 ALLOW, reward_conditions만으로 ALLOW를 각각 시험한다.
- **6. 검사 주체**: Runtime Validator의 ID·reference·area·revision 집합 검사 + R5 Rule Scope semantic validator
- **7. 허용·차단·격리 기대**: 정확한 link/missing-information 조합만 저장한다. 공식 원문 확인 불가·parser 모순은 해당 영역 `UNCERTAIN`, `report_permission=DENY`, `PolicyMissingInfo(area=SOURCE, blocks_allow=true)`로 fail-closed한다. 이를 PASS/ALLOW로 위장한 output은 invalid다.
- **8. work·attempt·가설 기대**: 유효 review work는 실제 결론과 무관하게 SUCCEEDED일 수 있고 hypothesis TRUE는 유지한다. invalid review는 current로 확정하지 않으며 Primitive admission·Finding·Reporter를 진행하지 않는다.
- **9. 오류·DataGap 기대**: semantic/reference 위반은 INVALID_OUTPUT 또는 revision 오류 Q-02. 정상 UNCERTAIN과 PolicyMissingInfo는 실행 오류가 아니다.
- **10. 저장·갱신 금지 pointer**: exact policy·source·evidence provenance와 유효 review만 보존한다. 근거 없는 PASS/ALLOW·잘못된 policy revision을 admission·Finding·ReportDraft에 연결하지 않는다.
- **11. FALSE 변환 금지**: 정책 근거 누락·모순·UNCERTAIN·DENY와 Gate output 오류는 기술 가설의 반증이 아니므로 Verification verdict를 바꾸지 않는다.
- **12. 실행 계층**: contract / integration / E2E / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R5·R4·R8·R1. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-GAT-011 — Finding 조건·근거·주장 강도 보존

- **1. ID·유형·설명**: R3-CT-GAT-011 / 정상·부정 / Finding normalization이 upstream 조건·근거·주장 강도를 보존
- **2. 단계·계약 경계**: 19; Rule Scope COMMITTED → Finding normalization → current index
- **3. producer → consumer**: Verification trusted runtime의 Finding normalization service → FindingIndexState·Reporter
- **4. 선행 상태·exact refs**: F-GAT(§2.3)의 same-generation exact closure와 해당 가설의 expected revision을 가진 `FindingIndexState`. 정상 candidate FN1의 expected set은 final Verification의 evidence transitive closure와 restriction·limitation·unresolved-condition source/path 합집합이다.
- **5. 정상/잘못된 fixture**: 정상은 `evidence_refs`와 `condition_sources`가 expected set과 중복 없이 set-equal하고 upstream claim 강도 이하인 Finding이다. 부정 변형은 condition 하나 삭제·완화, evidence 누락·추가·다른 generation 혼합, 실패한 PoC candidate나 미검증 child를 사실로 승격, upstream보다 강한 impact/exploitability 또는 새 공격 경로 생성이다.
- **6. 검사 주체**: Finding normalization semantic validator + Runtime Validator의 exact closure·set-equality·current index CAS 검사
- **7. 허용·차단·격리 기대**: 정상 Finding만 COMMITTED/current가 된다. 모든 부정 변형은 저장·current 승격을 차단하며 normalizer가 새 취약점 사실·공격 경로·영향을 만들지 않는다.
- **8. work·attempt·가설 기대**: 정상 FINDING_NORMALIZE는 SUCCEEDED이고 hypothesis TRUE는 유지한다. 실패 normalization은 기존 Finding history를 보존하며 Reporter work를 성공시키지 않는다.
- **9. 오류·DataGap 기대**: 잘못된 closure·claim은 INVALID_OUTPUT 또는 STALE_RESULT, CAS 경쟁은 STATE_VERSION_CONFLICT; exact semantic code는 Q-02
- **10. 저장·갱신 금지 pointer**: malformed candidate는 current Finding/AnalysisRunResult/ReportDraft에 연결하지 않는다. 이미 저장된 유효 history와 upstream record는 수정하지 않는다.
- **11. FALSE 변환 금지**: Finding normalization 실패·stale·과장된 claim은 가설 반증이 아니므로 기존 TRUE를 FALSE나 HOLD로 바꾸지 않는다.
- **12. 실행 계층**: contract / integration / E2E / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R5·R4·R6·R8. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

### CHN. Primitive·Chaining·자식

근거: 03·06·08; PR #93·102·103·105 반영 main. 모든 사례는 **미실행 / 역할 검토 필요**.

#### R3-CT-CHN-001 — HOLD 빈 후보와 inputs-only Primitive

- **1. ID·유형·설명**: R3-CT-CHN-001 / 정상 / HOLD 빈 후보와 inputs-only Primitive
- **2. 단계·계약 경계**: 14, 18, 20, 자식의 9; Primitive·Chaining·자식
- **3. producer → consumer**: Primitive Runtime → Chaining Agent·Runtime → Registry·Assignment·Context Service
- **4. 선행 상태·exact refs**: F-CHN(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: HOLD required_primitive_candidates=[]와 유효한 nonempty 후보를 별개로 시험한다.
- **6. 검사 주체**: Runtime Validator의 admission·집합·계보·중복 검사 + R1 match 의미 검사 + Context lineage 검사
- **7. 허용·차단·격리 기대**: 빈 배열은 Primitive/Chaining work 없이 정상 종료. nonempty면 result=null inputs-only Primitive 생성 가능; TRUE admission decision 강요 안 함.
- **8. work·attempt·가설 기대**: hypothesis TERMINAL HOLD; nonempty PRIMITIVE_UPDATE 성공 후 CHAINING 후보, 빈 배열은 새 work 없음.
- **9. 오류·DataGap 기대**: 없음
- **10. 저장·갱신 금지 pointer**: 빈 배열은 VerificationResult만 보존; nonempty는 Primitive/index/commit, validated TRUE result를 임의 생성하지 않음.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R1·R4·R6·R2·R5. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-CHN-002 — 허용된 TRUE와 방향성 match

- **1. ID·유형·설명**: R3-CT-CHN-002 / 정상 / 허용된 TRUE와 방향성 match
- **2. 단계·계약 경계**: 14, 18, 20, 자식의 9; Primitive·Chaining·자식
- **3. producer → consumer**: Primitive Runtime → Chaining Agent·Runtime → Registry·Assignment·Context Service
- **4. 선행 상태·exact refs**: F-CHN(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: Technical ACCEPT와 current ALLOW를 가진 TRUE Primitive + HOLD input, 별도 TRUE result→TRUE input을 exact 방향으로 제시한다.
- **6. 검사 주체**: Runtime Validator의 admission·집합·계보·중복 검사 + R1 match 의미 검사 + Context lineage 검사
- **7. 허용·차단·격리 기대**: R1 의미 검사를 통과한 match를 저장하고 child proposal 후보 생성. result가 없는 쌍을 TRUE result처럼 사용 안 함.
- **8. work·attempt·가설 기대**: CHAINING work/attempt SUCCEEDED; 부모 TRUE/HOLD 유지; child는 아직 final verdict 없음.
- **9. 오류·DataGap 기대**: 없음
- **10. 저장·갱신 금지 pointer**: ChainingResult의 work 시작 시 고정한 `considered_primitive_refs`, 실제 match 입력의 `input_primitive_refs`, source result·parent refs, match와 restriction을 정확히 기록한다.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R1·R4·R6·R2·R5. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-CHN-003 — 등록되지 않은 DENY·stale Primitive 주입

- **1. ID·유형·설명**: R3-CT-CHN-003 / 부정 / current PrimitiveIndexState에 없는 DENY·stale Primitive 주입
- **2. 단계·계약 경계**: 14, 18, 20, 자식의 9; Primitive·Chaining·자식
- **3. producer → consumer**: Primitive Runtime → Chaining Agent·Runtime → Registry·Assignment·Context Service
- **4. 선행 상태·exact refs**: F-CHN(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: `PrimitiveAdmissionDecision=DENY`여서 등록되지 않은 result Primitive, 과거 index에만 있던 Primitive 또는 work 시작 때 고정하지 않은 Primitive를 match/result/child 입력에 주입한다. 이미 current index에 등록된 Primitive의 admission을 run 중 다시 판정하는 변형은 만들지 않는다.
- **6. 검사 주체**: Runtime Validator의 admission·집합·계보·중복 검사 + R1 match 의미 검사 + Context lineage 검사
- **7. 허용·차단·격리 기대**: 고정 입력에 없는 Primitive를 사용한 결과 저장과 child 등록을 차단한다. 등록된 Primitive의 admission을 다시 확인하거나 이미 만들어진 자식·후손을 취소하지 않는다.
- **8. work·attempt·가설 기대**: 잘못된 결과·child 등록만 거절하고 기존 work 입력, 부모·후손 상태와 verdict는 불변이다.
- **9. 오류·DataGap 기대**: STALE_RESULT; admission 거절 세부 Q-02
- **10. 저장·갱신 금지 pointer**: history 삭제 금지. 잘못 주입한 Primitive·match·child를 current 결과나 집계에 연결하지 않는다.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R1·R4·R6·R2·R5. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-CHN-004 — 사용하지 않은 후보의 변경

- **1. ID·유형·설명**: R3-CT-CHN-004 / 정상 / 사용하지 않은 후보의 변경
- **2. 단계·계약 경계**: 14, 18, 20, 자식의 9; Primitive·Chaining·자식
- **3. producer → consumer**: Primitive Runtime → Chaining Agent·Runtime → Registry·Assignment·Context Service
- **4. 선행 상태·exact refs**: F-CHN(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: work 시작 때 current index에서 후보 A/B/C를 고정하고 실제 match는 A→B다. 이후 새 Primitive D가 등록되어 index revision만 갱신된다.
- **6. 검사 주체**: Runtime Validator의 admission·집합·계보·중복 검사 + R1 match 의미 검사 + Context lineage 검사
- **7. 허용·차단·격리 기대**: 이후 index revision에 D가 추가됐다는 이유만으로 A→B 결과를 거절하지 않는다. D는 다음 Chaining work에서 처리하고 현재 결과는 시작 때 고정한 A/B/C 집합으로만 검사한다.
- **8. work·attempt·가설 기대**: 유효 CHAINING 결과 성공 허용; 부모 판정 불변.
- **9. 오류·DataGap 기대**: 없음
- **10. 저장·갱신 금지 pointer**: `considered_primitive_refs`는 시작 고정 A/B/C를 보존하고 `input_primitive_refs`에는 실제 match에 쓴 A/B만 기록한다. 나중에 추가된 D를 현재 결과에 섞지 않는다.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R1·R4·R6·R2·R5. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-CHN-005 — 전체 후보·계보·제외 집합 불일치

- **1. ID·유형·설명**: R3-CT-CHN-005 / 부정 / 전체 후보·계보·제외 집합 불일치
- **2. 단계·계약 경계**: 14, 18, 20, 자식의 9; Primitive·Chaining·자식
- **3. producer → consumer**: Primitive Runtime → Chaining Agent·Runtime → Registry·Assignment·Context Service
- **4. 선행 상태·exact refs**: F-CHN(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: considered에서 시작 후보 누락·추가, input_primitive_refs와 실제 match 불일치, source/parent ref 합집합 불일치, `excluded_lineage_refs`를 가장 깊은 성립 match에서 계산한 기대 집합과 다르게 만든다.
- **6. 검사 주체**: Runtime Validator의 admission·집합·계보·중복 검사 + R1 match 의미 검사 + Context lineage 검사
- **7. 허용·차단·격리 기대**: 각 set-equality/lineage 검사로 저장 차단. 의미 없다고 임의로 후보/제외 사유를 지우지 않음.
- **8. work·attempt·가설 기대**: 성공/current CHAINING 결과 없음; 부모 판정 불변.
- **9. 오류·DataGap 기대**: STALE_RESULT 또는 semantic 오류 Q-02
- **10. 저장·갱신 금지 pointer**: 오류/원본 고정 입력 보존; 잘못된 match·child 등록 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R1·R4·R6·R2·R5. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-CHN-006 — 이벤트 등록·중복 key·처리 책임

- **1. ID·유형·설명**: R3-CT-CHN-006 / 정상·부정 / 이벤트 등록·중복 key·처리 책임
- **2. 단계·계약 경계**: 14, 18, 20, 자식의 9; Primitive·Chaining·자식
- **3. producer → consumer**: Primitive Runtime → Chaining Agent·Runtime → Registry·Assignment·Context Service
- **4. 선행 상태·exact refs**: F-CHN(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 동일 PrimitiveUpdate 이벤트 재전달, 두 trigger가 서로의 pool을 포함, 동일 match triple 재저장을 시험한다.
- **6. 검사 주체**: Runtime Validator의 admission·집합·계보·중복 검사 + R1 match 의미 검사 + Context lineage 검사
- **7. 허용·차단·격리 기대**: COMMITTED PrimitiveUpdate 뒤에만 등록; dedupe key는 analysis/workspace/commit/trigger/index 집합. 쌍 책임은 pool 포함 관계 후 필요한 경우 큰 record ID trigger. match 중복은 분석 범위의 (upstream_result_ref, downstream_input_ref, matched_input_id).
- **8. work·attempt·가설 기대**: 같은 등록 work 재사용; 비담당 work는 해당 쌍을 처리하지 않음. 중복 match는 구현 오류이며 정상 no-match 아님.
- **9. 오류·DataGap 기대**: 중복 match AnalysisError(stage=ORCHESTRATION), 구체 code Q-02
- **10. 저장·갱신 금지 pointer**: 등록/ownership trace, 단일 match 유지. 비담당 쌍을 no_match_reasons에 넣지 않음.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R1·R4·R6·R2·R5. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-CHN-007 — 구조화된 no-match

- **1. ID·유형·설명**: R3-CT-CHN-007 / 정상·부정 / 구조화된 no-match
- **2. 단계·계약 경계**: 14, 18, 20, 자식의 9; Primitive·Chaining·자식
- **3. producer → consumer**: Primitive Runtime → Chaining Agent·Runtime → Registry·Assignment·Context Service
- **4. 선행 상태·exact refs**: F-CHN(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 담당 쌍이지만 정상 의미 검사상 match 불성립; 별도 변형은 LLM timeout을 빈 정상 no-match로 제출한다.
- **6. 검사 주체**: Runtime Validator의 admission·집합·계보·중복 검사 + R1 match 의미 검사 + Context lineage 검사
- **7. 허용·차단·격리 기대**: 정상 불성립만 구조화 no_match_reasons로 기록; 실행 오류를 불성립 증거로 변환하지 않음.
- **8. work·attempt·가설 기대**: 정상 CHAINING SUCCEEDED 가능; timeout은 retry/실패 흐름, 부모 판정 불변.
- **9. 오류·DataGap 기대**: 정상 없음; timeout 실제 호출 오류
- **10. 저장·갱신 금지 pointer**: 정상 considered·no_match_reasons 보존; 실패를 성공 빈 ChainingResult로 저장 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R1·R4·R6·R2·R5. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-CHN-008 — 자식 등록 전 시작점·Context exact 계보 검사

- **1. ID·유형·설명**: R3-CT-CHN-008 / 정상·부정 / 자식 등록 전 시작점과 Context exact 부모 reference 검사
- **2. 단계·계약 경계**: 14, 18, 20, 자식의 9; Primitive·Chaining·자식
- **3. producer → consumer**: Primitive Runtime → Chaining Agent·Runtime → Registry·Assignment·Context Service
- **4. 선행 상태·exact refs**: F-CHN(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 정상 match의 entity/location 시작점으로 child를 등록하고 Context가 `source_primitive_match_id`를 따라 exact 부모 Primitive·Verification·entity/location을 읽는다. 변형 A는 등록 전 시작점 없음/잘못된 commit, B는 Context 요청에 다른 record revision·workspace·commit 또는 끊어진 부모 reference를 주입한다.
- **6. 검사 주체**: Runtime Validator의 admission·집합·계보·중복 검사 + R1 match 의미 검사 + Context lineage 검사
- **7. 허용·차단·격리 기대**: A는 Validator/Registry/Assignment가 등록·배정을 차단한다. B는 Context Service가 요청에 고정된 exact reference 불일치를 차단한다. 부모 admission을 다시 판정하지 않으며 정상이면 새 hypothesis로 전체 검증한다.
- **8. work·attempt·가설 기대**: 정상 child REGISTERED→VERIFYING; 부모 상태 유지. 실패 child는 부적격 다음 단계 진행 안 함.
- **9. 오류·DataGap 기대**: STALE_RESULT / 시작점 오류 Q-02
- **10. 저장·갱신 금지 pointer**: 정상 parent/source_match/exact entity refs 연결; 등록 전 실패는 새 가설 없음. 자식 결과를 부모 verdict/impact에 흡수 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R1·R4·R6·R2·R5. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-CHN-009 — 자식 proposal 내용과 restriction 승계

- **1. ID·유형·설명**: R3-CT-CHN-009 / 정상·부정 / Chaining 자식 proposal의 계보·남은 조건·restriction·반증 질문 검사
- **2. 단계·계약 경계**: 18, 20, 자식의 9; Primitive match → CHAINING origin proposal → 등록·Verification
- **3. producer → consumer**: Chaining Agent → Proposal Validator·Hypothesis Registry·Assignment Runtime·Technical Evidence Gate Agent
- **4. 선행 상태·exact refs**: F-CHN(§2.3)의 COMMITTED match candidate와 같은 work에 고정된 upstream/downstream Primitive. matched downstream input, 양쪽 remaining inputs, restriction 합집합과 exact entity/location 계보를 expected set으로 계산한다.
- **5. 정상/잘못된 fixture**: 정상 proposal은 `origin=CHAINING`, exact `source_primitive_match_id`·부모 set, `observed_facts=[]`, 부모 계보 안의 선택적 target/path, match에서 유도한 vulnerability type 후보, 충족된 downstream input을 뺀 나머지 input description의 assumptions, 양쪽 restriction의 중복 없는 합집합, 비어 있지 않은 결합 지점 반증 질문을 가진다. 부정 변형은 observed fact 추가, 계보 밖 entity/location/path, matched input을 assumptions에 유지, 남은 input 누락·추가, restriction 누락, 같은 restriction_id의 다른 내용·근거, 빈 반증 질문, match 없는 material claim이다. 질문은 비어 있지 않지만 실제 결합 지점을 겨냥하지 않은 의미 변형도 별도로 둔다.
- **6. 검사 주체**: Runtime Validator의 exact match·부모·집합·reference·비어 있지 않은 질문 검사 + R1 Chaining semantic validator; 질문의 실제 결합 지점 적절성은 R5 Technical semantic validator
- **7. 허용·차단·격리 기대**: 구조·계보·남은 조건·restriction이 정확한 proposal만 등록한다. Runtime은 질문 목록의 존재만 확인하고 질문 의미를 대신 판정하지 않는다. 의미상 결합 지점을 겨냥하지 않은 질문은 자식의 독립 Verification 뒤 Technical review에서 ACCEPT 자격을 얻지 못한다.
- **8. work·attempt·가설 기대**: 정상 child는 REGISTERED→VERIFYING으로 새 lifecycle을 시작하고 부모는 불변이다. 등록 전 부정 변형은 새 hypothesis/work를 만들지 않으며, 질문 의미 부족 변형은 자동 TRUE가 아니라 독립 검증·Gate 결과를 따른다.
- **9. 오류·DataGap 기대**: 구조·계보·restriction 충돌은 INVALID_OUTPUT 또는 STALE_RESULT, 권한 밖 claim은 AUTHORITY_DENIED, 질문 의미 부족은 Technical `REVISE | REJECT`; exact code 충돌은 Q-02
- **10. 저장·갱신 금지 pointer**: 정상 proposal·parent/source-match refs만 저장한다. 부정 proposal을 current child·Verification 입력으로 승격하지 않고 부모 Primitive·가설·Finding을 수정하지 않는다.
- **11. FALSE 변환 금지**: 자식 proposal 오류·질문 부족·등록 실패는 부모나 자식의 실제 반증이 아니므로 부모 verdict를 바꾸거나 새 FALSE를 만들지 않는다.
- **12. 실행 계층**: contract / integration / E2E / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R1·R4·R6·R2·R5. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

### REP. Reporter·집계·사람 경계

근거: 05·07·08·10·12. 모든 사례는 **미실행 / 역할 검토 필요**.

#### R3-CT-REP-001 — 정상 내부 보고서와 자동화 종료

- **1. ID·유형·설명**: R3-CT-REP-001 / 정상 / 정상 내부 보고서와 자동화 종료
- **2. 단계·계약 경계**: 19, 21–22; Reporter·집계·사람 경계
- **3. producer → consumer**: current Finding/Gates → Reporter → Result Aggregator; 사람 공개는 자동화 밖
- **4. 선행 상태·exact refs**: F-REP(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 동일 current Finding/Verification/CWE/두 Gate/정책/PoC와 6축 PASS 조건, 모든 work/journal 정리된 run.
- **6. 검사 주체**: Runtime Validator REPORT_READY/REVISION/REDACTION + Reporter semantic validator + finalization 검사
- **7. 허용·차단·격리 기대**: Reporter가 근거 범위 내 내부 draft 생성; Aggregator가 exact current 결과를 확정하면 Agent 자동화 종료.
- **8. work·attempt·가설 기대**: REPORT_DRAFT work/attempt SUCCEEDED, ReportProcessState DRAFTED; run COMPLETE(부분 실패 없는 fixture), 가설 TRUE.
- **9. 오류·DataGap 기대**: 없음; 최종 집계 저장 authority는 Q-01
- **10. 저장·갱신 금지 pointer**: ReportDraft·report pointer·COMMITTED; AnalysisRunResult/state/result pointer 연결은 Q-01 결정 뒤 구현.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / E2E / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R5·R4·R6·R8. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-REP-002 — 6축 보고 조건·Gate 우회

- **1. ID·유형·설명**: R3-CT-REP-002 / 부정 / 6축 보고 조건·Gate 우회
- **2. 단계·계약 경계**: 19, 21–22; Reporter·집계·사람 경계
- **3. producer → consumer**: current Finding/Gates → Reporter → Result Aggregator; 사람 공개는 자동화 밖
- **4. 선행 상태·exact refs**: F-REP(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 6축(review_status,rule_compliance,scope_compliance,testing_restriction_compliance,security_impact,report_permission)을 한 번에 하나씩 실패/불확실/거절로 변경; 별도 missing Gate/Finding.
- **6. 검사 주체**: Runtime Validator REPORT_READY/REVISION/REDACTION + Reporter semantic validator + finalization 검사
- **7. 허용·차단·격리 기대**: PASS/PASS/PASS/PASS/SUFFICIENT/ALLOW와 current Finding 모두 충족할 때만 호출. Finding 존재만으로 호출 허용 안 함.
- **8. work·attempt·가설 기대**: Reporter 호출 없음; 기존 hypothesis TRUE·유효 Finding 유지.
- **9. 오류·DataGap 기대**: REPORT_NOT_READY; 순서 권한 오류 Q-02
- **10. 저장·갱신 금지 pointer**: 구체 차단 이유/action 기록; ReportDraft/current DRAFTED 승격 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / E2E / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R5·R4·R6·R8. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-REP-003 — 보고 도중 선행 결과 변경

- **1. ID·유형·설명**: R3-CT-REP-003 / 부정 / 보고 도중 선행 결과 변경
- **2. 단계·계약 경계**: 19, 21–22; Reporter·집계·사람 경계
- **3. producer → consumer**: current Finding/Gates → Reporter → Result Aggregator; 사람 공개는 자동화 밖
- **4. 선행 상태·exact refs**: F-REP(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: Reporter 시작 뒤 Verification/CWE/Gate/정책/Finding 중 하나를 새 revision으로 변경한 다음 과거 draft 제출.
- **6. 검사 주체**: Runtime Validator REPORT_READY/REVISION/REDACTION + Reporter semantic validator + finalization 검사
- **7. 허용·차단·격리 기대**: 호출 전뿐 아니라 저장 시 current exact chain 재검사, 과거 draft를 현행으로 재사용 금지.
- **8. work·attempt·가설 기대**: 옛 draft work 성공/current 연결 차단; 가설 자체 FALSE 전환 없음.
- **9. 오류·DataGap 기대**: STALE_RESULT / RECORD_REVISION_MISMATCH
- **10. 저장·갱신 금지 pointer**: raw 응답은 보안 기준 내 history; current ReportDraft·ReportProcessState 부적격 갱신 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / E2E / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R5·R4·R6·R8. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-REP-004 — 제약·근거 누락과 외부 공개 시도

- **1. ID·유형·설명**: R3-CT-REP-004 / 부정 / 제약·근거 누락과 외부 공개 시도
- **2. 단계·계약 경계**: 19, 21–22; Reporter·집계·사람 경계
- **3. producer → consumer**: current Finding/Gates → Reporter → Result Aggregator; 사람 공개는 자동화 밖
- **4. 선행 상태·exact refs**: F-REP(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: draft에서 restriction/limitation/provenance 삭제 또는 secret 포함, upstream 근거보다 강한 security impact 주장, 검증되지 않은 동적 재현·PoC 성공 주장, upstream에 없는 새 공격 경로 생성을 각각 시험한다. Reporter가 외부 제출/공개 action을 제안하는 변형도 둔다.
- **6. 검사 주체**: Runtime Validator REPORT_READY/REVISION/REDACTION + Reporter semantic validator + finalization 검사
- **7. 허용·차단·격리 기대**: semantic/claim-strength/redaction 검사로 부적격 draft 차단; Reporter는 upstream 근거보다 강한 주장을 만들지 못한다. 공개/제출은 자동 파이프라인 범위 밖이며 사람 권한을 대행하지 않는다.
- **8. work·attempt·가설 기대**: 보고 성공 처리 없음; run 종료 뒤 새 Agent action 없음; 기존 판정 불변.
- **9. 오류·DataGap 기대**: REPORT_ERROR / ACTION_NOT_ALLOWED; redaction 세부 Q-02
- **10. 저장·갱신 금지 pointer**: 안전한 오류 log만; 비밀 원문/공개 요청 전송 금지. 사람 승인 기록을 Agent가 생성하지 않음.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / E2E / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R5·R4·R6·R8. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-REP-005 — Finding-only·오류 포함 집계와 종료 차단

- **1. ID·유형·설명**: R3-CT-REP-005 / 정상·부정 / Finding-only·오류 포함 집계와 종료 차단
- **2. 단계·계약 경계**: 19, 21–22; Reporter·집계·사람 경계
- **3. producer → consumer**: current Finding/Gates → Reporter → Result Aggregator; 사람 공개는 자동화 밖
- **4. 선행 상태·exact refs**: F-REP(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 정상 변형은 current Finding 있으나 report-ready 아님. 실패 변형은 RUNNING work/미복구 PREPARED/없는 output pointer/stale descendant가 남은 종료 요청.
- **6. 검사 주체**: Runtime Validator REPORT_READY/REVISION/REDACTION + Reporter semantic validator + finalization 검사
- **7. 허용·차단·격리 기대**: 정상은 report_draft_refs=[]와 차단 사유를 포함해 종료 가능; 실패 변형은 finalization 차단 후 복구/정리.
- **8. work·attempt·가설 기대**: 정상 run COMPLETE/PARTIAL 등 실제 전체 상태에 맞게 선택; 실패 변형은 기존 run 종료 전 상태 유지.
- **9. 오류·DataGap 기대**: 보고 차단 사유 보존; unresolved state 오류 Q-02
- **10. 저장·갱신 금지 pointer**: finding_refs는 current index 집합; errors/gaps/resources 포함. 미해결 상태에서 final pointer 확정 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / E2E / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R5·R4·R6·R8. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

### BUD. 예산·관측성

근거: 07·08·09·10; PR #60 반영 main. 모든 사례는 **미실행 / 역할 검토 필요**.

#### R3-CT-BUD-001 — token 계획값 초과·usage 미제공

- **1. ID·유형·설명**: R3-CT-BUD-001 / 정상 / token 계획값 초과·usage 미제공
- **2. 단계·계약 경계**: 1–22 호출 전·종료; 예산·관측성
- **3. producer → consumer**: R8 versioned 설정·실제 usage → Runtime Validator·metrics·Result Aggregator
- **4. 선행 상태·exact refs**: F-BUD(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: token_budget=null, 계획값보다 실제 사용량 많음, provider usage 미제공을 각각 시험한다.
- **6. 검사 주체**: Runtime Validator BUDGET/config 검사 + 관측 기록 검증
- **7. 허용·차단·격리 기대**: token만으로 BUDGET FAIL/DENY/중단하지 않음; 미제공 usage는 null, 추정값을 실제값으로 만들지 않음.
- **8. work·attempt·가설 기대**: 다른 시간/비용/work 한도 내 정상 실행 유지; 가설 판정 영향 없음.
- **9. 오류·DataGap 기대**: token 이유 BUDGET_EXCEEDED 금지
- **10. 저장·갱신 금지 pointer**: 실측 usage와 출처/미제공 null 기록; 승인 spec과 request의 계획값 equality는 별도로 유지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: unit / contract / integration
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R8·R4·R7. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-BUD-002 — 실제 잔여 예산·새 attempt 소진

- **1. ID·유형·설명**: R3-CT-BUD-002 / 부정 / 실제 잔여 예산·새 attempt 소진
- **2. 단계·계약 경계**: 1–22 호출 전·종료; 예산·관측성
- **3. producer → consumer**: R8 versioned 설정·실제 usage → Runtime Validator·metrics·Result Aggregator
- **4. 선행 상태·exact refs**: F-BUD(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: 고정 R8 profile의 시간/비용/work 또는 새 attempt 한도를 소진한 상태에서 새 호출/재시도를 요청한다.
- **6. 검사 주체**: Runtime Validator BUDGET/config 검사 + 관측 기록 검증
- **7. 허용·차단·격리 기대**: 해당 실제 한도 검사로 추가 실행 차단; token/임의 체이닝 전용 상한으로 대체하지 않음.
- **8. work·attempt·가설 기대**: 해당 work 종료/정리 규칙 적용; 새 active attempt 없음, 가설 FALSE 생성 없음.
- **9. 오류·DataGap 기대**: BUDGET_EXCEEDED
- **10. 저장·갱신 금지 pointer**: 고정 profile/ref·소진 원인·실측 자원 보존; 무기록 새 work/호출 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: unit / contract / integration
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R8·R4·R7. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-BUD-003 — 설정 고정과 R7 입장 정책 분리

- **1. ID·유형·설명**: R3-CT-BUD-003 / 정상·부정 / 설정 고정과 R7 입장 정책 분리
- **2. 단계·계약 경계**: 1–22 호출 전·종료; 예산·관측성
- **3. producer → consumer**: R8 versioned 설정·실제 usage → Runtime Validator·metrics·Result Aggregator
- **4. 선행 상태·exact refs**: F-BUD(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: run eval_config_refs 전체, 작업 checked_config_refs 부분집합, final 전체 집합을 맞춘다. 변형은 profile 교체/누락, R8 한도를 R7 host 격리 완화 근거로 사용.
- **6. 검사 주체**: Runtime Validator BUDGET/config 검사 + 관측 기록 검증
- **7. 허용·차단·격리 기대**: 정상 exact 설정 보존; 바뀐/누락 설정·SandboxProfile 외부 경계 완화는 거절.
- **8. work·attempt·가설 기대**: 정상 작업 진행; 위반 작업 시작/최종 집계 차단, 가설 불변.
- **9. 오류·DataGap 기대**: revision/config 오류 Q-02; 입장 정책 SANDBOX_POLICY_DENIED
- **10. 저장·갱신 금지 pointer**: final eval_config_refs는 초기 집합과 set-equal. R7 policy와 R8 lifecycle record 각각 보존.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: unit / contract / integration
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R8·R4·R7. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-BUD-004 — 정책 cache 선택·freshness·run-local 고정

- **1. ID·유형·설명**: R3-CT-BUD-004 / 정상·부정 / run 시작의 정책 cache 선택과 freshness·고정 규칙
- **2. 단계·계약 경계**: 1, 3, 17, 22; `POLICY_FETCH`·PolicyCacheRecord·RunPolicyState·Rule Scope
- **3. producer → consumer**: 실행 시작 runtime → Policy Collector·Policy Parser → current RunPolicyState → Rule Scope Gate·Reporter·관측 지표
- **4. 선행 상태·exact refs**: F-BUD(§2.3)의 PCACHE1과 exact program/source 설정·Parser 이름/버전·freshness criterion, AnalysisRunState.started_at을 고정한다. 각 부정 변형은 5번의 한 조건만 변경한다.
- **5. 정상/잘못된 fixture**: 정상 cache hit은 새 run 시작 때 cache를 정확히 한 번 조회하고 program·source 설정 hash·Parser 이름/버전·freshness criterion hash·`freshness_valid_until > started_at`·closure를 모두 만족한다. 이때 추가 Collect·Parse 없이 현재 run의 새 `PolicyCollectionResult`, `ProgramPolicyRecord`(FOUND일 때), `RunPolicyState`를 `REUSED_CACHE`로 만든다. 부정 변형은 cache 없음, 시작 시 만료, source/Parser/freshness 설정 불일치, target/content hash/schema/closure 손상을 각각 주고 cache를 거절해 같은 `POLICY_FETCH` work에서 새 Collect·Parse로 전환한다. 준비 완료 뒤 같은 run에서 TTL 만료·Parser 배포가 발생해도 고정 state를 교체하지 않는 변형도 둔다.
- **6. 검사 주체**: Policy Collector의 cache 호환성·closure 검사, Runtime Validator의 exact ref·atomic commit 검사, R8 metric/config 검사
- **7. 허용·차단·격리 기대**: 정상 hit은 새 Parser 호출 없이 run-local 결과만 확정한다. invalid cache는 거절 이유를 trace에 남기고 새 준비 경로만 허용한다. 과거 RunPolicyState 직접 재사용, run 중 cache 재조회·state 교체, invalid cache의 Gate/Reporter 직접 소비는 차단한다.
- **8. work·attempt·가설 기대**: analysis·program별 active `POLICY_FETCH` work 하나. 정상 hit/miss 성공은 실제 준비 결과에 맞게 SUCCEEDED이고 가설 verdict에 영향 없음. run 중 freshness 변화로 새 policy work/generation을 만들지 않는다.
- **9. 오류·DataGap 기대**: cache miss·비호환은 수집 실행 오류가 아니라 구조화된 거절 이유다. 손상된 closure를 성공 cache로 사용하면 STALE_RESULT 계열 exact-reference 위반이며 세부 code는 Q-02다.
- **10. 저장·갱신 금지 pointer**: cache hit에서도 다른 run의 state를 current로 복사하지 않는다. current-run collection·policy·state를 같은 TransitionCommit으로 확정하고, cache miss/거절이면 PCACHE1을 새 run의 policy_cache_ref로 연결하지 않는다. 준비 완료 뒤 current pointer 교체 금지.
- **11. FALSE 변환 금지**: cache 없음·만료·불일치·손상과 freshness 변화는 가설 `FALSE | HOLD`가 아니다. 로컬 전용 Sandbox 결과도 이 이유만으로 폐기하지 않는다.
- **12. 실행 계층**: unit / contract / integration / security-negative
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R8·R4·R5. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-BUD-005 — Policy Collect·Parse 재시도와 실패 관측

- **1. ID·유형·설명**: R3-CT-BUD-005 / 정상·부정 / Policy Collect·Parse의 versioned 재시도 한도와 실패 결과
- **2. 단계·계약 경계**: 1, 3, 17, 22; `POLICY_FETCH` attempt lifecycle·예산·관측성
- **3. producer → consumer**: R8 versioned retry 설정 → Runtime Validator·Policy Collector·Policy Parser → RunPolicyState·AnalysisRunResult·metrics
- **4. 선행 상태·exact refs**: F-BUD(§2.3)의 current R8 설정과 하나의 `POLICY_FETCH` work를 사용한다. 현재 후보 기준은 Collect 최초 1회 뒤 추가 2회, Parse 최초 1회 뒤 추가 3회이며 실제 fixture는 승인된 설정 revision의 값을 exact하게 고정한다.
- **5. 정상/잘못된 fixture**: 재시도 가능 Collect 또는 Parse 오류 뒤 같은 work의 새 attempt가 허용 한도 안에서 성공하는 정상 변형, 허용된 추가 횟수를 모두 소진하는 변형, 복구 불가능 오류 변형, 전체 run 예산이 호출 전에 이미 소진된 변형을 각각 시험한다. attempt별 `PolicyCollectionResult` 최대 1개, 성공하지 못한 Parser/collection 이력, fetch failure와 parser failure 구분도 확인한다.
- **6. 검사 주체**: Runtime Validator BUDGET/state 검사, Policy Collector·Policy Parser result validator, TransitionCommit·관측 집계 검사
- **7. 허용·차단·격리 기대**: 재시도 가능하면 같은 work를 BLOCKED로 두고 새 attempt로 재개한다. 한도 소진·복구 불가능은 FAILED와 `COLLECTION_FAILED`로 끝낸다. 성공하지 못한 attempt와 `COLLECTION_FAILED | UNVERIFIED` 결과를 cache로 게시하거나 Rule Scope Gate·Reporter 입력으로 쓰지 않는다.
- **8. work·attempt·가설 기대**: 새 policy work/generation을 만들지 않고 active attempt는 하나만 둔다. 종료 실패 뒤 재활성화하지 않으며 이미 존재하는 기술 가설·판정은 바꾸지 않는다.
- **9. 오류·DataGap 기대**: fetch/parser 원인별 `POLICY_FETCH_ERROR`와 실제 error refs를 보존한다. 전체 run 예산 사전 소진일 때만 `BUDGET_EXCEEDED`를 적용하고, 재시도 횟수 소진을 정책 부재로 바꾸지 않는다.
- **10. 저장·갱신 금지 pointer**: 완료된 attempt마다 collection 결과 최대 하나, final RunPolicyState는 선택한 exact collection 하나만 가리킨다. 실패 이력은 AnalysisRunResult에 남기되 current policy/cache/Gate pointer로 승격하지 않는다.
- **11. FALSE 변환 금지**: 수집·Parser·예산·저장 실패를 `ABSENT_CONFIRMED`, `FALSE | HOLD`, 정적 분석 성공으로 바꾸지 않는다. `LOCAL_ONLY` Sandbox는 정책 준비 실패만으로 차단하지 않는다.
- **12. 실행 계층**: unit / contract / integration / E2E
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R8·R4·R5. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

## 5. main Provider 계약과 미병합 Prompt 제안 card

[#96](https://github.com/SASTsimi/sastsimi/pull/96)은 merge commit `64062aec3f9ea190df93d2e5eb240c036371cd65`로 main에 반영됐다. 따라서 ProviderProfile·capability·runtime tool-loop 조건은 main 계약으로 시험한다. [#97](https://github.com/SASTsimi/sastsimi/pull/97)은 HEAD `a9fd2e14edb9f52465947151e0208718a42d83e7`의 미병합 Prompt 제안이다. #97 최신 HEAD에서는 [본인 수정 요청](https://github.com/SASTsimi/sastsimi/pull/97#issuecomment-5556385502)의 빈 최초 계보 문제가 `OPTIONAL_MANY`와 exact closure 검사로 보완됐다. #97 전용 Registry·Builder 필드는 병합 뒤 main 기준으로 다시 대조하기 전에는 main 통과 조건으로 승격하지 않는다.

### PR. Provider 계약·Prompt 제안 시험

근거: main #96 merge `64062ae`·미병합 #97@`a9fd2e1`. 모든 사례는 **미실행 / 역할 검토 필요**이며, 각 card에서 main 조건과 제안 조건을 구분한다.

#### R3-CT-PR-001 — Provider 지원 판정과 runtime tool-loop

- **1. ID·유형·설명**: R3-CT-PR-001 / main 계약 계획 / Provider 지원 판정과 runtime tool-loop / #96 병합 main 기준
- **2. 단계·계약 경계**: 6, 10–13, 18; Provider 계약 시험
- **3. producer → consumer**: main ProviderProfile·capability registry·Provider Adapter·Runtime tool-loop → 해당 역할 wrapper
- **4. 선행 상태·exact refs**: F-PR(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: main 계약을 만족하는 승인 profile, 미시험 profile, runtime_tool_loop 미지원 profile로 R7 execution task를 시도한다.
- **6. 검사 주체**: main schema/semantic validator·Runtime tool-loop; 아직 구현되지 않음
- **7. 허용·차단·격리 기대**: 실제 capability 시험 전 profile 발급/운영 지원 선언 금지; R7 실행은 검증된 SUPPORTED capability만 선택.
- **8. work·attempt·가설 기대**: 미지원 호출 차단; domain work·가설 성공 판정 없음.
- **9. 오류·DataGap 기대**: 제안 schema/오류 Q-04
- **10. 저장·갱신 금지 pointer**: PVD-16 등 시험 증거가 있을 때만 profile 참조. fake test가 실제 인증/약관 검증을 대신하지 않음.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative (후속 구현)
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R4·R8·R7; Chaining R1, Verification R6. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-PR-002 — initial assessment와 exact playbook 입력

- **1. ID·유형·설명**: R3-CT-PR-002 / PR 제안 / initial assessment와 exact playbook 입력 / #97 HEAD 기준 제안·미병합
- **2. 단계·계약 경계**: 6, 10–13, 18; main Provider·미병합 Prompt 제안 시험
- **3. producer → consumer**: main Provider 경계·PR #97 Prompt Builder → 해당 역할 wrapper
- **4. 선행 상태·exact refs**: F-PR(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: #97 ASSESS_INITIAL/CREATE_DYNAMIC_REQUEST에 current policy/playbook/application을 넣고 다른 work application으로 교체한다.
- **6. 검사 주체**: 제안된 schema/semantic validator·Runtime tool-loop; 아직 구현되지 않음
- **7. 허용·차단·격리 기대**: 제안 기준: R6가 동적 요청 필요성을 결정; 정상 initial 결과는 final/Gate 입력 아님. 다른 application은 거절.
- **8. work·attempt·가설 기대**: Verification 진행 전 assessment; initial을 TERMINAL final로 사용 금지.
- **9. 오류·DataGap 기대**: 제안 semantic 오류 Q-04
- **10. 저장·갱신 금지 pointer**: assessment·prompt/spec trace만; initial VerificationResult/current final 생성 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative (후속 구현)
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R4·R8·R7; Chaining R1, Verification R6. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-PR-003 — 최초 Chaining의 빈 lineage_results

- **1. ID·유형·설명**: R3-CT-PR-003 / PR 제안 / 최초 Chaining의 빈 lineage_results / #97 최신 HEAD 보완 확인
- **2. 단계·계약 경계**: 6, 10–13, 18; main Provider·미병합 Prompt 제안 시험
- **3. producer → consumer**: main Provider 경계·PR #97 Prompt Builder → 해당 역할 wrapper
- **4. 선행 상태·exact refs**: F-PR(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: INITIAL TRUE와 INITIAL HOLD, 둘 다 source_primitive_match_id=null, 필요한 과거 ChainingResult 집합이 비어 있음.
- **6. 검사 주체**: 제안된 schema/semantic validator·Runtime tool-loop; 아직 구현되지 않음
- **7. 허용·차단·격리 기대**: #97@`a9fd2e1` 제안 기준으로 `lineage_results=[]`를 허용한다. `OPTIONAL_MANY`는 0개 이상이며 관계없는 결과로 개수만 맞추지 않는다. 아직 main 미병합이므로 main 구현 통과 기준으로 활성화하지 않는다.
- **8. work·attempt·가설 기대**: 제안 기준 정상 호출 진행; 부모 TRUE/HOLD와 source_primitive_match_id=null 유지. 실제 호출 가능 판정은 #97 병합·구현 뒤 수행한다.
- **9. 오류·DataGap 기대**: 정상 없음. PR 제안 활성화 전 main에는 해당 Registry 구현이 없다는 상태를 보존한다.
- **10. 저장·갱신 금지 pointer**: fixture 설계만 보존; 관련 없는 과거 결과를 억지 삽입 금지.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative (후속 구현)
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R4·R8·R7; Chaining R1, Verification R6. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-PR-004 — 필요한 계보 누락·관계없는 계보 추가

- **1. ID·유형·설명**: R3-CT-PR-004 / PR 제안 / 필요한 계보 누락·관계없는 계보 추가 / #97 계보/cardinality 후속 확인
- **2. 단계·계약 경계**: 6, 10–13, 18; main Provider·미병합 Prompt 제안 시험
- **3. producer → consumer**: main Provider 경계·PR #97 Prompt Builder → 해당 역할 wrapper
- **4. 선행 상태·exact refs**: F-PR(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: CHAINING-origin 조상이 있는 입력에서 필요한 ChainingResult를 하나 빼거나 무관한 결과를 추가한다.
- **6. 검사 주체**: 제안된 schema/semantic validator·Runtime tool-loop; 아직 구현되지 않음
- **7. 허용·차단·격리 기대**: 제안 closure set과 정확히 같지 않으면 거절. 빈 집합 허용과 필요한 조상 누락 허용은 다름.
- **8. work·attempt·가설 기대**: 호출/저장 성공 처리 없음; 부모 판정 불변.
- **9. 오류·DataGap 기대**: #97@`a9fd2e1` 제안의 closure semantic 거절; exact 오류 매핑은 Q-04
- **10. 저장·갱신 금지 pointer**: 거절 trace와 expected/actual 참조 집합. 무관 결과로 cardinality만 맞추지 않음.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative (후속 구현)
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R4·R8·R7; Chaining R1, Verification R6. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

#### R3-CT-PR-005 — R7 단계별 도구·의존성·결론 연결

- **1. ID·유형·설명**: R3-CT-PR-005 / main·PR 혼합 계획 / R7 단계별 도구·의존성·결론 연결 / main Provider·#97 Prompt 제안 기준
- **2. 단계·계약 경계**: 6, 10–13, 18; Provider 계약·Prompt 제안 시험
- **3. producer → consumer**: main Provider 경계·PR #97 Prompt Builder → 해당 역할 wrapper
- **4. 선행 상태·exact refs**: F-PR(§2.3)의 정상 상태와 exact ref 묶음. 5번이 지정한 시작 지점·변경만 적용하고 나머지 식별자·참조·설정은 그대로 고정한다.
- **5. 정상/잘못된 fixture**: #97의 환경/plan 작성은 실제 dependency context, 실행은 Runtime tool-loop, 해석은 log/관찰 입력으로 구성. 결론과 조립 결과 outcome 불일치 변형 추가.
- **6. 검사 주체**: 제안된 schema/semantic validator·Runtime tool-loop; 아직 구현되지 않음
- **7. 허용·차단·격리 기대**: 제안 기준: 단계별 도구 권한 분리, raw provider host tool 차단, Agent 결론과 dynamic result 의미 일치. Session Manager가 다른 기술 결론 생성 못 함.
- **8. work·attempt·가설 기대**: 정상 실행은 같은 session/attempt; 불일치 result 저장 차단, final verdict 없음.
- **9. 오류·DataGap 기대**: 제안 semantic/provenance 오류 Q-04
- **10. 저장·갱신 금지 pointer**: R7 request/관찰/AgentLog/결론/result exact linkage; PVD-16/PMT-R7 연계 시험. 실제 구현 아님.
- **11. FALSE 변환 금지**: 입력 위반·조회/호출/실행 오류·정책 차단·예산/저장 실패를 새 FALSE 근거로 사용하지 않음. 이미 존재하는 부모/가설 verdict는 해당 case의 명시적 검증 경로 외에는 변경하지 않음.
- **12. 실행 계층**: contract / integration / security-negative (후속 구현)
- **13. 구현 담당·필수 리뷰**: R3 통합 구현 윤희섭 @YHS-Sec; R4·R8·R7; Chaining R1, Verification R6. 계정과 검토 범위는 §9. 역할 owner가 fixture 의미를 승인해야 함.

## 6. 시험 구현으로 옮기는 순서와 #89 연결

이번 PR은 설계 문서만 추가한다. 아래는 **이후 구현 순서 제안**이며 현재 구현 완료 목록이 아니다.

1. R4와 정상 fixture의 ID/refs/schema/state/commit graph 및 Q 항목을 확정한다.
2. 테스트 전용 저장소·정상 manifest·fake provider/static tool/Sandbox와 외부 호출 spy를 만든다. 운영 계정·외부 공격 대상은 사용하지 않는다.
3. COM의 schema/reference/state 검사를 먼저 구현한다. 정상 fixture도 거절되는 잘못된 validator를 막기 위해 정상·부정 시험을 짝으로 실행한다.
4. STA/HYP/VER/DYN/GAT/CHN/REP 순으로 contract→integration을 연결한다. 도구와 LLM의 의미 결과는 fixture로 주입하며 runtime이 의미를 대신 판정하지 않게 검사한다.
5. #89에서 아래 장애 시나리오를 같은 fixture·test ID에 연결한다.
6. fake E2E와 security-negative를 실행한 뒤 별도 실제 dependency capability 시험을 한다.
7. 실제 실행한 case/variant 수, 실행 SHA, schema/profile refs, 통과·실패·건너뜀, log 위치를 결과표로 기록한다. 지금 단계에서 ‘93개 테스트 통과’라고 쓰지 않는다.

| 본 문서 경계 | #89에 연결할 중단 지점 | 복구 후 확인 |
|---|---|---|
| COM-006/011/012 | artifact staging/hash/PREPARED/COMMITTED 전후 | 미확정 결과 소비 금지, marker와 pointer 일치, 중복 투영 방지 |
| COM-007~010 | claim 경쟁·취소·늦은 결과·상태 충돌 | active attempt 하나, old 결과 격리, terminal work 재활성 금지 |
| HYP-002/005 | dedupe 계산·work/application 저장 사이 | 기존 work 재사용, application만 남거나 work만 활성화되지 않음 |
| VER-002 | 한 child 종료 뒤 부모 상태 반영 전 | 합성/새 final 금지, 부모 BLOCKED/FAILED 전파 |
| DYN-006~012 | AgentLog 기록·session crash·PoC 검증·request/profile 변경·container 생성/정리 전후 | same-attempt 계보, RETRY/RESUME와 새 generation 분리, exact SandboxProfile·PoC, 재생성·cleanup 완전성 |
| VER-007 | REVISE generation·새 work 확정 사이 | 같은 owner, 새 application/질문/ProCon, old final 자동 승격 금지 |
| GAT-008/CHN-003 | Finding/Primitive current index CAS·계보 무효화 사이 | stale 결과가 Reporter·자식·최종 집계에 들어가지 않음 |
| REP-003/005 | draft 저장 중 upstream 변경·최종 run 확정 전 | exact chain 재검사, 미해결 journal/work 없는 종료 |

기술 선택 전까지는 logical transaction 기대값을 정리한다. SQLite나 파일 저장을 이미 사용 중이라고 쓰지 않는다. 물리 staging/DB/migration·rollback 구현 및 손상 복구는 #92 선택과 #89 상세 설계의 후속이다.

## 7. 이전 댓글 OK/BAD 이력 대응

근거: [기존 #25 댓글](https://github.com/SASTsimi/sastsimi/issues/25#issuecomment-5543506516).
아래 ID 대응은 과거 검토 이력용이며 그 댓글의 오래된 기대값이 본문/최신 main보다 우선하지 않는다.

| 이전 ID | 현재 ID(앞에 R3-CT-) | 보완 사항 |
|---|---|---|
| OK-13 | VER-001 | 별도 work·attempt·NEW session, 동일 common input |
| OK-14 | DYN-007 | 같은 session 자율 조정은 동일 attempt event |
| OK-15 | DYN-001, VER-005 | SUPPORTED+validated PoC와 current generation |
| OK-16 | GAT-005/006 | admission과 보고 자격 분리, COLLECTION_FAILED 별도 |
| OK-17 | GAT-006, CHN-003 | FAIL→DENY, 기존 verdict 유지 |
| OK-18 | REP-001 | Finding/CWE/two-Gate/policy exact chain 및 최종 저장 Q-01 |
| BAD-51 | VER-002 | 한쪽 실패·합류 차단·부모 전파 |
| BAD-52 | VER-003, LLM-003 | 상대 역할의 결과/session/log 차단 |
| BAD-53 | VER-004, HYP-005 | 실제 고정 입력 혼합은 stale; 최신 policy 게시만으로 교체하지 않음 |
| BAD-54 | STA-003/005 | 실행 이력과 fact kind·producer 연결 |
| BAD-55/56 | DYN-003 | R6 목적 요청·R7 내부 실행·외부 Controller 분리 |
| BAD-57 | DYN-006 | append-only log·sequence/action 검사 |
| BAD-58 | DYN-006/008 | old attempt 혼합 금지; baseline recipe의 적법한 새 binding은 구분 |
| BAD-59 | DYN-005 | candidate와 validated PoC 분리 |
| BAD-60 | DYN-004, LLM-006 | 실행 오류를 FALSE/HOLD로 전환 금지 |
| BAD-61 | VER-006 | current PoC 없는 TRUE/Gate 차단 |
| BAD-62 | GAT-005 | COLLECTION_FAILED와 ABSENT_CONFIRMED 분리 |
| BAD-63 | GAT-004 | 부재 확인 시 policy ref null·UNCERTAIN/DENY |
| BAD-64 | GAT-006, CHN-003 | DENY Primitive 사용 금지 |
| BAD-65 | CHN-003/005 | work가 고정하지 않은 Primitive와 잘못된 계보 제외 집합 차단 |
| BAD-66 | COM-006/007, REP-003/005 | 미확정·취소·stale 결과의 보고/집계 금지 |
| 옛 BAD-31/32 관련 설명 | DYN-003 | Controller를 container 내부 command allowlist 검사기로 구현하지 않음 |
| 옛 BAD-38/39 관련 설명 | GAT-004/005, REP-002 | 공식 부재와 수집 실패 구분, Gate 우회 금지 |
| 옛 OK-10 관련 설명 | DYN-003/004 | SandboxProfile 외부 경계 차단 시 최소 log/decision/result, FALSE 아님 |

현재 남아 있는 댓글에 전체 상세 본문이 없는 OK-01~12/BAD-01~50은 원래 의미를 임의로 복원하지 않았다. 위에서 직접 설명이 남은 항목만 연결했다. 따라서 옛 번호의 모든 내용이 그대로 복구됐다고 주장하지 않는다. 현재 요구사항 coverage는 §3 및 #25 본문으로 확인한다.

## 8. 미결정·검토 요청

아래는 **새로 만든 GitHub 이슈가 아니라 문서 내 추적 항목**이다. unresolved 항목을 해결했다고 표시하거나 임의 오류를 구현하지 않는다.

| ID | 현재 근거·설계 | 확인할 핵심·선택지 | 담당·영향·완료 조건 |
|---|---|---|---|
| Q-01 | module map B3: CodeWorkspace/ToolRunResult/HypothesisProposal/AnalysisRunResult 저장 연결 공백. #97은 INITIAL proposal 저장 제안을 추가했으나 main 미반영 | 새 result-kind registry인지 기존 전용 저장 경계인지, 유일 producer·정확한 저장 action·단일 output·current pointer·원자 경계 확정. VERIFICATION/CHAINING nested child proposal의 독립 record 등록도 별도 확인 | R4 @taehyeon-git, R2/R1/R8. STA-001/HYP-001/REP-001 및 #89/#92 물리 저장 기대값 확정 전 필요. [이미 남긴 질문](https://github.com/SASTsimi/sastsimi/issues/92#issuecomment-5556395217)에 연결 |
| Q-02 | 공통 문서의 확인 가능한 오류는 사용했지만 각 schema 필드/권한/reference 거절이 어떤 exact code·ActionCheck·상태 전파를 쓰는지 case별 매핑은 불완전 | 기존 오류 재사용과 전용 오류 필요 여부를 R4가 결정. 검사 실패와 실제 work 실행 실패를 분리하고 error stage/retryable/related refs를 확정 | R4+해당 owner. 본문에서 Q-02로 표시한 case의 실행 가능한 assertion 작성 전 해결; 문서 초안은 진행 가능 |
| Q-03 | deterministic JSON+SHA-256은 #92 제안; executable schema version/fixture bytes는 아직 없음 | Unicode/숫자/null/시간/key 순서·hash 대상 bytes·동일 값 직렬화 fixture를 승인. 단순 key 정렬만으로 모든 runtime 동일 hash를 가정하지 않음 | R4·R3·R8. 실제 schema registry·정상 fixture 및 content hash 기대값 확정 전 필요 |
| Q-04 | #96 Provider role/spec/profile/action 경계는 merge commit `64062ae`로, 비-LLM Orchestration Runtime 경계는 main `6122567`로 반영됐다. current main `750287e`의 공식 구성요소 이름을 사용하며 Prompt Registry·Builder 세부 구조는 #97 제안에 의존 | main의 Provider·Orchestration Runtime 계약과 #97 Prompt 제안을 분리해 대조한다. 실제 profile 발급에는 provider 지원 시험이 필요하며 특정 모델/구독 경로를 실제 사용 가능하다고 단정하지 않음 | R4·R3·R7·R8, 전문 prompt owner. main Provider·Orchestration case는 계획으로 활성화하고 #97 전용 case는 병합 SHA에서 재대조 |
| Q-05 | #97@`a9fd2e1`은 최초 Chaining의 빈 조상 결과 집합에 `lineage_results=OPTIONAL_MANY`를 적용하고 cardinality 최소 개수와 exact closure 검사를 추가함 | PR-003의 빈 집합 허용, PR-004의 필요한 실제 조상 누락·관계없는 결과 추가 차단을 함께 유지. 아직 main 미병합이므로 병합 SHA에서 재대조 | R1 @baeseungwon1010·R4 @taehyeon-git. [수정 요청](https://github.com/SASTsimi/sastsimi/pull/97#issuecomment-5556385502)은 제안 문서상 보완됐고 main 활성화 확인만 남음 |
| Q-06 | #96은 `64062ae`로 main에 반영됐고 #97@`a9fd2e1`은 열려 있음 | #97을 최신 main에 동기화할 때 main Provider 계약과 양쪽 validator 규칙·출력을 함께 보존해 다시 실행. 문서 검사만으로 runtime 동작을 보증하지 않음 | #97 작성자·R3. 실제 #97 병합 SHA를 통합 Provider/Prompt 시험 기준으로 기록할 때 완료 |

### 8.1 main 해석 시 주의할 항목

- module map B2 Finding은 **이미 main에서 해결된 설계**다. ‘Finding producer 미정’으로 다시 차단하지 않는다.
- R7 정상 자율 조정·session 재시작·외부 대기 재개를 분리한다. 일반 work 모두에 RUNNING→READY를 허용하지 않는다.
- 검증 중 새 playbook/policy 게시와 기존 work의 고정 input을 실제 변경하는 것은 다르다.
- CodeWorkspace READY와 WorkExecutionState READY는 서로 다른 객체의 상태다. 도구의 SKIPPED와 work 공통 enum도 섞지 않는다.
- ‘한 generation에 dynamic work 하나’는 R6 요청 attempt와 R7 attempt를 같은 값으로 쓰라는 뜻이 아니다.
- 정책 수집 실패는 공식 부재가 아니다. 빈 정책 record로 Gate를 억지 호출하지 않는다.
- Finding 생성, 6축 Reporter readiness, Primitive admission은 서로 다른 검사다.
- 토큰 계획값은 강제 중단 상한이 아니다. 미확정 시간/비용/work 수치를 문서에서 임의로 확정하지 않는다.
- Primitive admission은 등록 시점의 1회 판정이다. Chaining은 current index에서 시작 때 고정한 exact Primitive 집합만 검사하고 부모 admission을 다시 판정하거나 등록된 Primitive·자식을 회수하지 않는다.

## 9. 필수 교차 검토와 완료 조건

| 역할 | 계정 | 요청할 검토 |
|---|---|---|
| R4 공통 계약 | @taehyeon-git | COM 전체, 모든 상태/오류/authority/current·atomic 경계, Q-01~04 |
| R1 탐색·Chaining | @baeseungwon1010 | HYP/CHN, 최초 빈 계보/처리 책임/중복 키·자식 |
| R2 정적분석·Context | @zv9uvr | STA, rule 실행 이력·참조·Context·등록 후 lineage |
| R5 CWE·Gate·Reporter | @kimhr8463 | GAT/REP, Finding·6축·정책 수집/부재·제약 보존 |
| R6 Verification·Pro/Con | @UltraPeachKeen | VER, 독립성·same work/application·최종 근거·REVISE |
| R7 Sandbox·동적 재현 | @Potatonion | DYN, 외부 경계·AgentLog·PoC·retry/RESUME·PR tool-loop |
| R8 평가·예산 | @gitterable | BUD, 오류/usage·평가 fixture·환경별 provider 지원 증거 |

검토자는 ‘좋습니다’뿐 아니라 검토한 문서 commit SHA, 담당 case IDs, 수정 요구/미결정 항목을 남긴다. 자동 문서 검사는 담당자의 승인을 대신하지 않는다.

- [x] 기준 main과 현재 22단계 연결, 93개 case card 초안 작성
- [x] case별 13개 필수 항목과 계획 fixture·저장 효과 명시
- [x] 정상·부정·보안·오류·예산 및 미병합 PR 시험 분리
- [x] 알려진 이전 OK/BAD 이력과 #89 복구 연결
- [x] 계약 부족을 Q 항목과 기존 질문으로 분리
- [ ] 각 Q 항목의 담당자 답변과 정확한 오류/저장 기대값 반영
- [ ] R1·R2·R4·R5·R6·R7·R8 교차 검토 기록 확보
- [ ] 최신 main 또는 병합 완료 SHA에서 최종 대조
- [ ] #25 전체 완료 조건 충족 후 이슈 종료 여부 확인

위의 체크된 항목은 **문서 초안 작성 여부**만 표시한다. 실제 fixture 파일·자동 테스트·Provider 인증·Sandbox 실행·복구 코드는 하나도 완료 표시하지 않는다. #25는 테스트 계획 이슈이므로 실행 코드 구현 자체를 이 문서 PR의 완료 실적으로 주장하지 않는다.

## 10. 현재 상태 한 줄 요약

22단계 모듈 사이에서 무엇을 허용·차단·보존해야 하는지 계획을 작성했다. 현재 산출물은 검토용 Markdown 문서이며, 미결정 계약의 답변과 역할별 검토가 남아 있고 실제 자동 테스트·프로그램은 아직 구현하지 않았다.
