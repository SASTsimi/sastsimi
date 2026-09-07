# R3-03. 중단·재시도·복구 통합 시험 계획

> 상태: **DESIGN_APPROVED / NOT_IMPLEMENTED**
>
> 프로그램이 중간에 멈췄을 때 어떤 기록을 확인하고 어디서 다시 시작해야 하는지 정리한 **검토용 설계 초안**이다. 실제 runtime·복구 코드·fixture·자동 테스트를 구현하거나 실행한 결과가 아니다.

## 1. 목적과 기준

- 담당: R3 윤희섭 (@YHS-Sec, @v1sion). 공통 아키텍처 검토·대행 수행: 김태현 (@taehyeon-git).
- 본 작업: [#89](https://github.com/SASTsimi/sastsimi/issues/89). 상위 [#4](https://github.com/SASTsimi/sastsimi/issues/4), 선행 [#24](https://github.com/SASTsimi/sastsimi/issues/24)·[#25](https://github.com/SASTsimi/sastsimi/issues/25), 후속 [#92](https://github.com/SASTsimi/sastsimi/issues/92).
- main 대조 기준: `35729d3185cf46cdbf9c94ce2be646ae11f26446` (PR #107 병합 commit, R3-06에서 재대조).
- #25 시험 계획 의존성: [PR #106](https://github.com/SASTsimi/sastsimi/pull/106), 최종 HEAD `0e2e7fef3699692d6c849fa770127b349b0e076b`, main 병합 commit `9e0a7efc73d9a9b1e83d6e70049c6d35ab8fa8b1`.
- Prompt 실행 구조 의존성: [PR #97](https://github.com/SASTsimi/sastsimi/pull/97), 최종 HEAD `fbf023691073cce7cd9ced421b69e219b5c5c8d9`, main 병합 commit `0c1b59b5f74fb2c76171167940640d10ca5155b0`.
- **#106과 #97은 main에 병합됐다.** 이번 문서는 병합된 최종 계약을 기준으로 CT ID·fixture·역할명·Prompt 입력·복구 기대값을 다시 대조한다.
- 이번 변경은 `03-recovery-test-plan.md` 한 파일이다. #106의 02 문서를 복사해 다른 PR에서 다시 추가하지 않는다.

#25는 **잘못된 입력을 어디서 막는지**, #89는 **그 검사를 하거나 저장하는 도중 프로그램이 멈춰도 같은 안전 조건이 유지되는지**를 다룬다. 실제 설계는 22단계이며, 분기 때문에 한 가설이 모든 22단계를 순서대로 한 번씩 거치는 구조는 아니다.

### 1.1 용어

- **work**: 목적과 입력이 고정된 하나의 논리 작업.
- **attempt**: 그 작업을 실행하는 한 번의 시도.
- **revision**: 같은 논리 기록의 새 버전. 과거 기록을 덮어쓰지 않는다.
- **current pointer**: 지금 유효한 결과를 가리키는 연결.
- **journal**: 저장이 어디까지 확정됐는지 남기는 기록.
- **PREPARED**: 저장 준비 기록. 다음 단계가 결과로 사용하면 안 된다.
- **COMMITTED**: 논리적으로 확정된 저장 기록. 소비하려면 상태와 결과 pointer도 같은 결과를 가리켜야 한다.
- **ABORTED**: 충돌·취소·검증 실패 등으로 확정하지 않는 준비 기록.
- **projection(투영)**: 확정 journal을 읽어 work 상태와 전문 결과 pointer를 맞추는 처리.
- **CAS**: 예상한 상태 버전과 실제 버전이 같을 때만 갱신하는 방식.
- **fault injection(장애 주입)**: 테스트가 정한 지점에서 실패·종료를 일부러 발생시키는 것.
- **fixture**: 테스트에 쓸 예제 데이터. 여기서는 아직 구조와 별명만 정했으며 실제 파일은 만들지 않았다.

### 1.2 정본과 소유권

우선 근거는 같은 main의 [01 시스템 개요](../01-system-overview.md), [03 역할·등록·배정](../03-agent-roles-and-orchestration.md), [04 Verification·동적 재현](../04-verification-and-dynamic-reproduction.md), [05 Gate·Finding·보고](../05-llm-gate-and-reporting.md), [06 Chaining](../06-chaining.md), [07 결과·관측·예산](../07-results-and-observability.md), [08 공통 계약](../08-lightweight-data-contracts.md), [09 Provider·session](../09-llm-provider-session-and-logging.md), [10 보안 경계](../10-security-boundaries.md), [01 module map](01-module-map.md)이다.

R3는 장애 지점과 검사 기대값을 설계한다. R4가 상태·권한·atomic commit 의미를, R8이 예산·시간 정책을, 전문 owner가 결과 의미를 확정한다. RECOVERY가 승인된 생산자의 journal을 복구하는 것은 새 Verification/Finding/Gate 판단을 만드는 것과 다르다.

§8의 RQ 번호와 시험 ID, 아래 checkpoint 별명은 문서 관리 표기일 뿐 새로운 runtime enum/action/schema가 아니다.

## 2. 반드시 구분할 재실행 종류

| 종류 | 유지하는 것 | 새로 만드는 것 | 허용/금지 핵심 |
|---|---|---|---|
| COMMITTED 재투영 | 같은 marker·record·논리 결과 | 필요한 상태 projection만 복원 | 도구/LLM 재호출·새 결과 revision 생성 아님 |
| 일반 work retry | 같은 work_id·고정 입력 | 새 attempt, LLM이면 새 call/spec/action/decision/session | 실패 attempt 보존. retryable 일반 work는 BLOCKED 경로, 모든 work에 RUNNING→READY 허용 금지 |
| Dynamic Reproduction Agent 같은 session의 자율 조정 | work·attempt·session | 해당 실행 event/관찰 | `EXECUTE_REPRODUCTION` 첫 turn은 `NEW`, 같은 work·attempt의 후속 turn만 `RESUME`; command·PoC·환경 조정과 same-session container 재생성은 새 attempt를 만들지 않음 |
| Dynamic Reproduction Agent session 재시작 | work_id·verification generation | 새 attempt, trigger=RETRY | RUNNING→READY→RUNNING. 고정 입력을 유지하고 R8 한도가 남아 있어야 함 |
| 동적 재현 외부 조건 해소 후 재개 | work_id·고정 input refs/hash | 새 attempt, trigger=RESUME | BLOCKED→READY→RUNNING. 실제 waiting_for 조건이 해소되고 input refs/hash가 그대로여야 함 |
| 동적 request/profile 변경 | hypothesis_id·기존 Verification history | 같은 ACTIVE Verification owner가 CAS로 새 generation·VERIFICATION work·application·Pro/Con을 생성 | 기존 work의 RETRY·RESUME과 과거 action·decision·attempt·PoC·CWE·Gate 재사용 금지. R3-06 §10.7 RQ-10 적용 |
| Technical REVISE | hypothesis_id·ACTIVE Verification owner | 새 verification generation·VERIFICATION work·application·질문·Pro/Con, TRUE면 새 dynamic/PoC/CWE | 종료 work 부활 또는 이전 결과 자동 승격 금지 |
| 새 material claim | 부모 history·계보 | 등록 검증을 거친 새 hypothesis_id와 검증 흐름 | 자식 결과를 부모 verdict/impact에 합치지 않음 |
| 사람이 승인한 새 논리 실행 | 과거 terminal history | 증가한 work_generation·새 work_id, 승인된 run 경계 | 기존 terminal work 자체를 RUNNING으로 되돌리지 않음 |

#89 본문의 “retry 가능하면 BLOCKED”는 Dynamic Reproduction Agent의 같은-session 조정과 session 재시작까지 한 상태로 묶는 뜻으로 적용하지 않는다. 또한 정책 수집 실패와 공식 부재 확인은 별개 fixture다. 오래된 이슈 본문을 최신 08 계약보다 우선해 구현하지 않는다.

## 3. 공통 복구 판정 기준

### 3.1 authoritative state와 결과 소비

1. 마지막 유효 COMMITTED marker와 그 marker가 고정한 exact record/입력을 확인한다.
2. 같은 work의 next version에 미완료 journal이 있으면 취소·retry를 포함한 새 전이보다 먼저 처리한다.
3. PREPARED는 복구 또는 ABORTED 처리가 끝날 때까지 소비하지 않는다.
4. COMMITTED marker 뒤 projection이 덜 됐으면 **같은 marker를 재적용**한다.
5. marker·work output·전문 pointer가 모두 같은 exact 결과를 가리킬 때만 후속 처리를 허용한다.
6. version 충돌·취소·검증 실패는 미확정 후보를 ABORTED/격리한다. 이미 확정된 immutable history를 취소 명목으로 되돌리지 않는다.
7. 안전한 자동 복구를 증명하지 못하면 `RECOVERY_FAILED`로 중단한다. 없는 근거·output·command 종료 event를 만들어 성공처럼 보이지 않는다.
8. run 종료 전 RUNNING work, 미해결 PREPARED, 잘못된 output pointer와 미반영 stale invalidation을 정리한다.

이는 **검사 순서 설계**이지 구현된 RecoveryService 함수나 DB transaction 코드가 아니다.

### 3.2 계획 checkpoint

| 문서 별명 | 정확한 관찰 지점 |
|---|---|
| BEFORE_STAGE / MID_STAGE / AFTER_STAGE | 후보 artifact 쓰기 전/일부 bytes 후/완료 후 |
| BEFORE_HASH / AFTER_HASH | 원본 bytes의 hash 검증 전/검증 결과 확인 후 |
| BEFORE_PREPARE / AFTER_PREPARE | PREPARED journal durable 기록 전/후 |
| BEFORE_COMMIT / AFTER_COMMIT | CAS·유일 COMMITTED marker 확정 전/후 |
| MID_PROJECTION / AFTER_PROJECTION | work·전문 pointer 투영 일부/완료 |
| BEFORE_CHILD_REGISTER / AFTER_CHILD_REGISTER | child 등록·배정의 원자 경계 전/후 |
| BEFORE_DOWNSTREAM / BEFORE_FINALIZE | 소비/도구/Gate/Reporter 호출 직전 또는 최종 run 확정 직전 |

실제 hook 위치·flush/fsync/DB durability는 #92의 저장 방식 선택 뒤 연결한다. RAM에 쓰기 완료한 시점을 durable commit으로 가정하지 않는다.

### 3.3 fixture·참조 별명

#106 §2.3의 F-COM/F-STA/F-HYP/F-LLM/F-VER/F-DYN/F-GAT/F-CHN/F-REP/F-BUD 정의를 상속한다. 아래 R1/W1/C1/H1/K1/A1/r1/h1/v/IH1은 이해를 위한 별명이며 실제 hash/commit/schema 값이 아니다. 실제 fixture manifest에는 별명→real ID/record/ref/hash/schema/profile 연결을 고정해야 한다.

각 card는 2~4번의 기준에 5번 장애 변형을 적용한다. 다른 값은 바꾸지 않아 **복구 실패 원인을 한 변형으로 특정**한다. 여러 장애 지점/변형이 적힌 card는 구현 시 variant별 독립 시험이며, 일부만 실행하고 전체 통과로 세지 않는다.

- **STO 기준 (F-COM/F-STA)**: work K1=RUNNING, active attempt A1, state_version=v, input hash IH1. current output은 마지막 확정 r0. 새 결과 r1은 단계별 staging 후보이며 COMMITTED 전에는 current 아님. analysis R1/workspace W1/commit C1, K1/A1/G1(가설 작업일 때만)/IH1; r0/h0, r1/h1 및 T1(expected=v,target=v+1). 이름은 설계 별명이며 실제 ID·hash는 미생성.
- **WRK 기준 (F-COM/F-HYP/F-BUD)**: 같은 analysis/가설에 논리 work K1 하나, 이전 attempt A0 history, 현재 A1. case가 READY/종료/취소를 지정하면 그 상태가 우선. 확정된 current r0 외 늦은 응답은 후보. R1/W1/C1/H1/G1, K1, A0/A1, IH1, state_version=v, 고정 configuration E1, application PA1. 모든 결과는 자기 producer work의 attempt와 연결.
- **LLM 기준 (F-LLM/F-VER)**: 일반 K1/A1 RUNNING 또는 부모 KV1과 PRO KP1/AP1, CON KC1/AC1. 고정 공통 입력 DH1/application PA1, 각 역할 NEW session과 별도 call/decision. final result는 아직 없음. R1/W1/C1/H1/G1; spec S1/payload P1/profile PV1/USED decision AD1; Pro/Con DH1 동일, work·attempt·session은 각각 독립.
- **DYN 기준 (F-DYN)**: R6 exact request DQ1이 generation G1에 고정됨. dynamic work KD1 하나, 실행 attempt AD1, session SD1. `EXECUTE_REPRODUCTION`의 첫 turn은 `session_policy=AUTO`가 `NEW`로, 같은 work·attempt의 후속 turn은 직전 성공 session을 부모로 둔 `RESUME`으로 해석된다. requirements ER1/plan PL1/recipe RC1/environment ENV1/log L1/candidate PC1/PoC POC1와 DynamicReproductionResult DX1은 case의 저장 지점까지만 존재한다. R1/W1/C1/H1/G1, KD1/AD1/IHD1, exact DQ1, R7 소유 SandboxProfile SP1, R8 lifecycle LP1, command record CMD1/digest CD1을 사용한다. RunPolicyState RPS1은 RUN_SANDBOX 시점의 감사 reference일 뿐 KD1의 불변 입력·Controller 허가·R6 verdict 근거가 아니다. request 생산 attempt와 동적 실행 attempt는 같을 필요가 없다.
- **FLW 기준 (F-STA/F-VER/F-GAT/F-CHN/F-REP)**: 해당 단계 직전까지의 exact COMMITTED 결과만 준비. H1 final TRUE이면 V1/DX1/POC1/CW1/TG1/RS1의 current chain을 사용한다. HOLD 가설 HH와 새 child HC는 서로 다른 hypothesis_id로 구분한다. 동일 R1/W1/C1을 쓰며, Finding FN1/index FI1과 Primitive PRA/PRB·match M1·child HC는 각 source record를 정확히 가리킨다.
- **E2E 기준 (F-STA/F-HYP/F-VER/F-DYN/F-GAT/F-CHN/F-REP/F-BUD)**: 새 run R1에서 시작. 중간 장애 전까지는 각 단계의 정상 COMMITTED chain. TRUE/HOLD/FALSE는 미리 정한 전문 결과 fixture이고 runtime이 직접 판정하지 않음. 동일 R1/W1/C1, 각 가설 Hn/generation Gn/work Kn/attempt An/고정 input hash IHn. schema/profile과 case별 장애 지점은 아래 연결된 REC card를 따름.

### 3.4 모든 card의 추가 불변 조건

- 서로 다른 producer work의 attempt ID를 같게 강요하지 않는다. 같은 결과 chain의 각 record는 자기 producer의 올바른 attempt에 묶는다.
- same work retry는 고정 PlaybookApplication/질문을 유지한다. 새 policy 게시만으로 중간 입력을 바꾸지 않는다.
- `DYNAMIC_REPRO`의 `BLOCKED → RESUME`은 work의 `input_refs/input_hash`가 그대로일 때만 허용한다. exact DynamicReproductionRequest 또는 SandboxProfile revision을 바꿔야 하면 기존 work를 재개하지 않는다. 같은 ACTIVE Verification owner가 CAS로 새 generation·VERIFICATION work·application·Pro/Con을 만들고, 필요하면 새 request와 dynamic work를 만드는 R3-06 §10.7 RQ-10을 적용한다.
- 결과 저장 거절과 work 실행 실패를 구분한다. 단순 부정 입력 거절 때문에 정상 가설을 임의 FAILED/FALSE로 바꾸지 않는다.
- **실행 오류·timeout·예산·정책 차단은 FALSE/HOLD의 근거가 아니다.** 정상 필수 검증 완료와 실제 반증이면 R6 FALSE, 정상 관측 불충분이면 R6 HOLD가 가능한 것은 별도다.
- 모든 새 외부 실행 전에 exact 설정·권한·R8 잔여 시간/비용/work/새 attempt 한도를 검사한다. token 계획 초과만으로 중단하지 않으며 제공되지 않은 usage는 null이다.
- COMMITTED 재투영으로 provider/tool을 다시 호출하거나 usage/완료 attempt 실행 시간을 중복 집계하지 않는다.
- block 대기·프로세스가 꺼진 시간은 실행 elapsed에 더하지 않는다. crash 도중 미완료 attempt의 실제 사용량을 모르면 추정값을 실측으로 바꾸지 않는다(RQ-06).
- repo text·LLM 출력으로 복구 정책·Sandbox 보호·Gate·공개 권한을 바꾸지 않는다.
- secret은 synthetic sentinel만 사용한다. 실패 기록에도 원문 secret·cookie·host 절대 경로를 유출하지 않는다.

## 4. 단계별 복구 coverage

이 표는 **계획 범위**다. E2E 실행 coverage나 통과 결과가 아니다. 아래 복구 번호 앞에는 R3-REC-를 붙인다.

| 단계 | 주요 중단·복구 시험 |
|---|---|
| 전 단계 공통 | STO-008 migration, WRK-003 취소·결과 경합 |
| 1 시작·설정 | WRK-001/004/006, E2E-001 |
| 2 clone/checkout | FLW-001, STO-001/007/009 |
| 3 run-init 정적·정책 두 branch 병렬(Docker 준비 없음) | FLW-001/005, STO-007, WRK-006 |
| 4 정규화 | STO-001~006, FLW-001 |
| 5 초기 work 준비 | WRK-001/007 |
| 6 Hypothesis 호출 | LLM-001~003/006, WRK-002 |
| 7 proposal·중복·등록 | WRK-007, FLW-007, RQ-01 |
| 8 Verification 배정 | WRK-007, FLW-004/007 |
| 9 Context | FLW-001/007, WRK-005 |
| 10 Pro/Con | LLM-004/005 |
| 11 initial·동적 요청 | DYN-001, LLM-003 |
| 12 동적 재현 실행 | DYN-002~011 |
| 13 final Verification | FLW-002 |
| 14 verdict·CWE·HOLD | FLW-003/006, E2E-008 |
| 15 Technical Gate | FLW-003 |
| 16 REVISE | FLW-004, E2E-007 |
| 17 고정 정책 사용·RuleScope·admission | FLW-005/006 |
| 18 Chaining | FLW-006/007 |
| 19 Finding·보고 자격 | FLW-008, E2E-009 |
| 20 material child | FLW-007, E2E-008 |
| 21 ReportDraft | FLW-009 |
| 22 최종 집계·종료 | STO-010, FLW-009, E2E-010 |

## 5. 장애·복구 상세 card 43개

모든 card는 **미실행 / 검토 필요**다. case별 1~12번은 #89 본문의 필수 항목이다.
- ‘CT 연결’의 축약 번호 앞에는 `R3-CT-`를 붙이며 #106의 시험 ID다.
- card 본문에서 다른 복구 card를 가리키는 STO/WRK/LLM/DYN/FLW/E2E 번호 앞에는 `R3-REC-`를 붙인다.
- `RQ-*`는 문서 내 질문이지 실제 오류 코드가 아니다.

### STO. 저장·journal·복구 강제 경계

#### R3-REC-STO-001 — artifact 생성 전·부분 쓰기·완료 직후 종료

- **1. ID·단계·work**: R3-REC-STO-001; 4 / STATIC_NORMALIZE. CT 연결: COM-006/007/011, STA-002.
- **2. 중단 전 상태·current**: STO 기준(§3.3): work K1=RUNNING, active attempt A1, state_version=v, input hash IH1. current output은 마지막 확정 r0. 새 결과 r1은 단계별 staging 후보이며 COMMITTED 전에는 current 아님. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: analysis R1/workspace W1/commit C1, K1/A1/G1(가설 작업일 때만)/IH1; r0/h0, r1/h1 및 T1(expected=v,target=v+1). 이름은 설계 별명이며 실제 ID·hash는 미생성. 자세한 정상 graph는 F-COM/F-STA(#106 §2.3).
- **4. 저장된 record·artifact·marker**: r0만 COMMITTED. r1은 없거나 부분 bytes 또는 완료 bytes; 새 commit marker 없음.
- **5. 정확한 장애 주입 지점**: artifact staging 직전/첫 chunk 뒤/마지막 chunk 뒤에 각각 프로세스를 종료한다.
- **6. 재시작 검사 조건**: staging 존재·길이·hash·producer attempt; 이전 COMMITTED r0의 무결성.
- **7. 복구 조치**: r1을 성공 결과로 추정하지 않음. 미확정 자원은 격리하고 승인된 저장 복구 정책 적용. 재실행 필요 시 새 attempt 규칙. orphan 정리/재활용 정책은 RQ-01.
- **8. 기대 state·current/격리 결과**: current=r0 유지. 종료된 프로세스를 A1 실행 중이라고 무기한 믿지 않음; 실패 원인 기록 후 retry/중단 정책, 새 domain 성공 없음.
- **9. 다음 단계 호출**: r1 소비 금지; 다른 독립 작업은 자기 안전 조건 충족 때만 가능.
- **10. 기대 오류·관측 log**: STORAGE/RECOVERY 원인 기록; 자동 복구 안전성 미증명 시 RECOVERY_FAILED. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음. 적용 기준: R3-06 §10.7 RQ-01.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4; STA는 R2, 저장·시간은 R8. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-STO-002 — hash 검증 전 종료·hash 불일치

- **1. ID·단계·work**: R3-REC-STO-002; 4 / STATIC_NORMALIZE. CT 연결: COM-003/006/011.
- **2. 중단 전 상태·current**: STO 기준(§3.3): work K1=RUNNING, active attempt A1, state_version=v, input hash IH1. current output은 마지막 확정 r0. 새 결과 r1은 단계별 staging 후보이며 COMMITTED 전에는 current 아님. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: analysis R1/workspace W1/commit C1, K1/A1/G1(가설 작업일 때만)/IH1; r0/h0, r1/h1 및 T1(expected=v,target=v+1). 이름은 설계 별명이며 실제 ID·hash는 미생성. 자세한 정상 graph는 F-COM/F-STA(#106 §2.3).
- **4. 저장된 record·artifact·marker**: r1 bytes만 저장; PREPARED 없음. 이전 r0/commit 정상.
- **5. 정확한 장애 주입 지점**: 완료 staging에 대해 hash 검사 직전 종료, 별도 변형은 bytes 한 개 변조.
- **6. 재시작 검사 조건**: content-addressed hash·정확한 참조·schema/producer 검증. 단순 파일 존재와 검증 완료 구별.
- **7. 복구 조치**: 정상 bytes는 검사부터 다시 수행 가능하되 commit 전 상태/권한 재검사. 불일치 bytes는 격리; 정상 record로 수선했다고 꾸미지 않음.
- **8. 기대 state·current/격리 결과**: 정상은 검증 후 저장 경로 재진입; 불일치는 r0 유지. 성공/실패 pointer 분리.
- **9. 다음 단계 호출**: 완전한 COMMITTED 및 pointer 일치 전 소비 금지.
- **10. 기대 오류·관측 log**: hash 검증 오류의 exact code RQ-02; 안전성 판단 불가 RECOVERY_FAILED. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음. 적용 기준: R3-06 §10.7 RQ-01/02.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4; STA는 R2, 저장·시간은 R8. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-STO-003 — PREPARED 직전·직후 종료

- **1. ID·단계·work**: R3-REC-STO-003; 4 / STATIC_NORMALIZE. CT 연결: COM-006/011/012.
- **2. 중단 전 상태·current**: STO 기준(§3.3): work K1=RUNNING, active attempt A1, state_version=v, input hash IH1. current output은 마지막 확정 r0. 새 결과 r1은 단계별 staging 후보이며 COMMITTED 전에는 current 아님. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: analysis R1/workspace W1/commit C1, K1/A1/G1(가설 작업일 때만)/IH1; r0/h0, r1/h1 및 T1(expected=v,target=v+1). 이름은 설계 별명이며 실제 ID·hash는 미생성. 자세한 정상 graph는 F-COM/F-STA(#106 §2.3).
- **4. 저장된 record·artifact·marker**: 변형 A journal 없음; B PREPARED T1·exact output refs 있음. COMMITTED 없음.
- **5. 정확한 장애 주입 지점**: 유효 r1 검증 후 PREPARED 쓰기 직전, 또는 PREPARED durable 확인 직후 종료.
- **6. 재시작 검사 조건**: 현재 v/active A1/IH1·identity·artifact hash·requester/decision·journal target v+1 모두 재확인.
- **7. 복구 조치**: A는 저장 프로토콜을 다시 확인. B는 새 전이를 막은 채 복구 또는 ABORTED 처리. 재검증 모두 통과한 commit 허용 조건·staging 수명은 RQ-01로 확정. 무조건 성공 commit 아님.
- **8. 기대 state·current/격리 결과**: commit 가능하면 r1/target v+1로 한 번 확정. 충돌/취소/검증 실패면 ABORTED, current=r0. 아직 불확실하면 소비 차단.
- **9. 다음 단계 호출**: PREPARED 상태에서 도구/Gate/Reporter/다음 소비 불가.
- **10. 기대 오류·관측 log**: 충돌 STATE_VERSION_CONFLICT, stale STALE_RESULT, 복구 불명 RECOVERY_FAILED. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음. 적용 기준: R3-06 §10.7 RQ-01.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4; STA는 R2, 저장·시간은 R8. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-STO-004 — COMMITTED marker 뒤 pointer 투영 전 종료

- **1. ID·단계·work**: R3-REC-STO-004; 4 및 확정 output 공통 / STATIC_NORMALIZE. CT 연결: COM-011/012.
- **2. 중단 전 상태·current**: STO 기준(§3.3): work K1=RUNNING, active attempt A1, state_version=v, input hash IH1. current output은 마지막 확정 r0. 새 결과 r1은 단계별 staging 후보이며 COMMITTED 전에는 current 아님. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: analysis R1/workspace W1/commit C1, K1/A1/G1(가설 작업일 때만)/IH1; r0/h0, r1/h1 및 T1(expected=v,target=v+1). 이름은 설계 별명이며 실제 ID·hash는 미생성. 자세한 정상 graph는 F-COM/F-STA(#106 §2.3).
- **4. 저장된 record·artifact·marker**: T1은 r1과 target v+1을 확정. 하나 또는 두 pointer는 r0에 남음.
- **5. 정확한 장애 주입 지점**: T1 COMMITTED durable 기록 직후, WorkExecutionState/전문 pointer 투영 전에 종료.
- **6. 재시작 검사 조건**: unique (K1,v+1) marker·output bytes·state transition·전문 pointer의 불일치 위치.
- **7. 복구 조치**: 같은 COMMITTED marker를 재투영한다. 같은 작업을 다시 실행하거나 새 의미 결과를 생산하지 않음. 재투영 도중 재종료도 반복 시험.
- **8. 기대 state·current/격리 결과**: work/output/전문 pointer 모두 r1, v+1. 재복구해도 revision·시도·부작용 추가 없음.
- **9. 다음 단계 호출**: marker와 필요한 모든 pointer가 일치한 뒤에만 후속 허용.
- **10. 기대 오류·관측 log**: 경쟁 전이 STATE_VERSION_CONFLICT; marker 손상은 RECOVERY_FAILED. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4; STA는 R2, 저장·시간은 R8. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-STO-005 — 미완료 journal 동안 취소·retry 경합

- **1. ID·단계·work**: R3-REC-STO-005; 4 및 상태 전이 공통 / STATIC_NORMALIZE. CT 연결: COM-006/008/009/010/012.
- **2. 중단 전 상태·current**: STO 기준(§3.3): work K1=RUNNING, active attempt A1, state_version=v, input hash IH1. current output은 마지막 확정 r0. 새 결과 r1은 단계별 staging 후보이며 COMMITTED 전에는 current 아님. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: analysis R1/workspace W1/commit C1, K1/A1/G1(가설 작업일 때만)/IH1; r0/h0, r1/h1 및 T1(expected=v,target=v+1). 이름은 설계 별명이며 실제 ID·hash는 미생성. 자세한 정상 graph는 F-COM/F-STA(#106 §2.3).
- **4. 저장된 record·artifact·marker**: PREPARED 또는 아직 미투영 COMMITTED T1; competing action 후보들.
- **5. 정확한 장애 주입 지점**: STO-003/004 중 취소·retry·다른 결과 저장 요청을 같은 next version에 동시에 보낸다.
- **6. 재시작 검사 조건**: 새 전이 전에 (K1,current_version+1) journal 우선 조회·unique marker 확인.
- **7. 복구 조치**: PREPARED는 복구/ABORTED 후 처리. COMMITTED면 먼저 재투영하고 경쟁 요청을 거절. 취소 요청을 과거 version에 끼워 넣지 않음.
- **8. 기대 state·current/격리 결과**: v+1의 확정 결과 한 개; 경쟁 요청이 동일 version·active attempt를 대체하지 않음.
- **9. 다음 단계 호출**: 미완료 구간 후속 금지. 재투영 후 취소 재요청은 최신 state/권한으로 별도 검사.
- **10. 기대 오류·관측 log**: STATE_VERSION_CONFLICT 및 journal 대기 trace. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4; STA는 R2, 저장·시간은 R8. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-STO-006 — record 저장 중 종료와 다른 output binding

- **1. ID·단계·work**: R3-REC-STO-006; 4 및 output binding 공통 / STATIC_NORMALIZE. CT 연결: COM-003/006/012.
- **2. 중단 전 상태·current**: STO 기준(§3.3): work K1=RUNNING, active attempt A1, state_version=v, input hash IH1. current output은 마지막 확정 r0. 새 결과 r1은 단계별 staging 후보이며 COMMITTED 전에는 current 아님. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: analysis R1/workspace W1/commit C1, K1/A1/G1(가설 작업일 때만)/IH1; r0/h0, r1/h1 및 T1(expected=v,target=v+1). 이름은 설계 별명이며 실제 ID·hash는 미생성. 자세한 정상 graph는 F-COM/F-STA(#106 §2.3).
- **4. 저장된 record·artifact·marker**: 잘린 candidate record 또는 잘못된 projection. 과거 immutable r0 정상.
- **5. 정확한 장애 주입 지점**: record 쓰기 중 종료 또는 work terminal output=r1/전문 pointer=r2로 오류 주입.
- **6. 재시작 검사 조건**: 완전한 record/schema/hash, marker의 exact output, work type별 필수 output binding.
- **7. 복구 조치**: 유효 marker가 있으면 해당 exact output으로 재투영; marker 없는 후보는 current 금지. 근거 없이 r1/r2 중 하나를 선택하지 않음.
- **8. 기대 state·current/격리 결과**: 신뢰할 수 있는 마지막 commit 유지. 검증 불가 상태는 RECOVERY_FAILED; 가설 final/보고 성공을 합성하지 않음.
- **9. 다음 단계 호출**: 정확한 binding 회복 전 후속 차단.
- **10. 기대 오류·관측 log**: RECORD_REVISION_MISMATCH 또는 RECOVERY_FAILED; 세부 RQ-02. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음. 적용 기준: R3-06 §10.7 RQ-01/02.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4; STA는 R2, 저장·시간은 R8. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-STO-007 — 여러 output의 한쪽만 보임

- **1. ID·단계·work**: R3-REC-STO-007; 3 / STATIC_TOOL(RULE_BASED). CT 연결: STA-003/005, COM-012.
- **2. 중단 전 상태·current**: STO 기준(§3.3): work K1=RUNNING, active attempt A1, state_version=v, input hash IH1. current output은 마지막 확정 r0. 새 결과 r1은 단계별 staging 후보이며 COMMITTED 전에는 current 아님. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: analysis R1/workspace W1/commit C1, K1/A1/G1(가설 작업일 때만)/IH1; r0/h0, r1/h1 및 T1(expected=v,target=v+1). 이름은 설계 별명이며 실제 ID·hash는 미생성. 자세한 정상 graph는 F-COM/F-STA(#106 §2.3).
- **4. 저장된 record·artifact·marker**: 해당 작업의 journal 및 한쪽 record/참조; rule 기반 SUCCEEDED/PARTIAL/SKIPPED fixture.
- **5. 정확한 장애 주입 지점**: STATIC_TOOL ToolRunResult와 RuleExecutionRecord 중 하나만 보이는 시점에 종료한다.
- **6. 재시작 검사 조건**: 두 exact outputs의 같은 tool/attempt/workspace/commit·rule ref, target marker.
- **7. 복구 조치**: 한 transaction이면 rollback/commit 전부 여부 확인; journal이면 승인된 binding을 모두 재투영. 한쪽만 성공으로 소비시키지 않음.
- **8. 기대 state·current/격리 결과**: ToolRunResult/rule record/commit 동일 연결이 복구되면 해당 도구 상태 유지. 저장 entry point 세부는 RQ-01.
- **9. 다음 단계 호출**: 정규화 합류는 두 결과 확인 뒤 허용.
- **10. 기대 오류·관측 log**: STORAGE/RECOVERY 원인; 안전성 미증명 RECOVERY_FAILED. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음. 적용 기준: R3-06 §10.7 RQ-01.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4; STA는 R2, 저장·시간은 R8. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-STO-008 — migration 도중 종료와 rollback

- **1. ID·단계·work**: R3-REC-STO-008; domain work 시작 전 / 저장소 migration. CT 연결: COM-004/012.
- **2. 중단 전 상태·current**: 이 card는 공통 STO 기준(§3.3)을 덮어쓴다. domain work 시작 전이므로 `work_id`, `attempt_id`, `hypothesis_id`, `verification_generation`, CodeWorkspace와 분석 commit은 아직 존재한다고 가정하지 않는다. 시작 조건은 이전 schema version으로 저장된 기존 immutable record와 저장소 metadata·backup뿐이다.
- **3. work·attempt·generation·input**: domain work·attempt 입력은 없다. 이전/목표 Alembic revision, migration journal, 저장소 상태와 승인된 설정만 사용한다. migration은 별도 운영 명령이며 기존 `WorkType`을 임의로 재사용하지 않는다.
- **4. 저장된 record·artifact·marker**: 이전 schema version·기존 immutable records·선택 기술이 제공하는 migration marker와 backup. marker·journal·transaction 구조가 정해지지 않은 상태에서 `WorkAttempt`나 `TransitionCommit`을 migration 기록으로 가장하지 않는다.
- **5. 정확한 장애 주입 지점**: schema migration의 준비/부분 적용/완료 기록 전 지점별로 종료한다. 별도 rollback 불가능 변형.
- **6. 재시작 검사 조건**: 선택 DB의 실제 원자성·schema marker·하위호환·artifact 해석 가능성·backup 여부.
- **7. 복구 조치**: R3-06 §10.6·§10.7 RQ-03에 따라 검증된 forward/rollback만 허용한다. 의미 손실 rollback은 백업과 사람 승인이 없으면 거절하고, 불가능하면 시작 차단·수동 복구한다.
- **8. 기대 state·current/격리 결과**: 기존 근거/history 보존; 손상 schema를 정상으로 열지 않음. migration 복구가 끝나기 전 새 analysis·domain work·attempt·current output을 만들지 않는다.
- **9. 다음 단계 호출**: schema/기록 호환성 검증 완료 전 도메인 work 실행 금지.
- **10. 기대 오류·관측 log**: RECOVERY_FAILED, migration 원인 코드 RQ-02. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: domain work·attempt가 없으므로 분석 work 예산이나 LLM usage를 만들지 않는다. migration 작업 시간과 자원은 운영 log로 별도 계측한다.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4; STA는 R2, 저장·시간은 R8. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-STO-009 — DB·artifact 일부를 읽지 못함

- **1. ID·단계·work**: R3-REC-STO-009; 4·9·13·19·21·22 소비 전 / 해당 consumer work. CT 연결: COM-003/012, REP-005.
- **2. 중단 전 상태·current**: STO 기준(§3.3): work K1=RUNNING, active attempt A1, state_version=v, input hash IH1. current output은 마지막 확정 r0. 새 결과 r1은 단계별 staging 후보이며 COMMITTED 전에는 current 아님. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: analysis R1/workspace W1/commit C1, K1/A1/G1(가설 작업일 때만)/IH1; r0/h0, r1/h1 및 T1(expected=v,target=v+1). 이름은 설계 별명이며 실제 ID·hash는 미생성. 자세한 정상 graph는 F-COM/F-STA(#106 §2.3).
- **4. 저장된 record·artifact·marker**: marker는 존재하지만 참조 record/bytes를 검증할 수 없음.
- **5. 정확한 장애 주입 지점**: 현재 결과 artifact 누락·권한 오류·저장소 읽기 실패를 각각 주입한다.
- **6. 재시작 검사 조건**: 재시도 가능한 IO인지 영구 손상인지, 정확한 hash/record 복구 가능성.
- **7. 복구 조치**: 허용된 IO retry는 같은 논리 복구로 기록; 증명 못 하면 RECOVERY_FAILED. 빈 정상 결과나 다른 revision으로 대체하지 않음.
- **8. 기대 state·current/격리 결과**: current라 쓰인 pointer도 소비 가능하다고 간주하지 않음. 신뢰 history는 보존, 자동 domain 성공 없음.
- **9. 다음 단계 호출**: 영향받는 downstream/Gate/Reporter/최종화 차단.
- **10. 기대 오류·관측 log**: RECOVERY_FAILED 및 실제 STORAGE 오류; FALSE 생성 금지. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음. 적용 기준: R3-06 §10.7 RQ-01/02.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4; STA는 R2, 저장·시간은 R8. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-STO-010 — 복구 전에 Gate·Reporter·최종화 요청

- **1. ID·단계·work**: R3-REC-STO-010; 15·19·21·22 / TECHNICAL_GATE·REPORT_DRAFT·run finalization. CT 연결: COM-006/012, GAT-008, REP-002/005.
- **2. 중단 전 상태·current**: STO 기준(§3.3): work K1=RUNNING, active attempt A1, state_version=v, input hash IH1. current output은 마지막 확정 r0. 새 결과 r1은 단계별 staging 후보이며 COMMITTED 전에는 current 아님. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: analysis R1/workspace W1/commit C1, K1/A1/G1(가설 작업일 때만)/IH1; r0/h0, r1/h1 및 T1(expected=v,target=v+1). 이름은 설계 별명이며 실제 ID·hash는 미생성. 자세한 정상 graph는 F-COM/F-STA(#106 §2.3).
- **4. 저장된 record·artifact·marker**: 불완전 journal/state와 직전 current 결과.
- **5. 정확한 장애 주입 지점**: PREPARED·잘못된 output pointer·미투영 invalidation 중 세 요청을 시도한다.
- **6. 재시작 검사 조건**: consumer의 COMMITTED/pointer/현재 chain 검사, outstanding work/재투영·stale 의존성.
- **7. 복구 조치**: 복구 완료 전 요청 거절. RECOVERY identity가 Gate 의미 판단이나 Finding 새 생산자를 대신하지 않음.
- **8. 기대 state·current/격리 결과**: 복구 중에는 기존 run 종료 전 상태; Reporter/DRAFTED·final AnalysisRunResult 새 pointer 없음.
- **9. 다음 단계 호출**: 관련 후속 호출 0건; 복구 후에도 권한/6축/예산 다시 검사.
- **10. 기대 오류·관측 log**: RECOVERY_FAILED 또는 선행조건 거절 RQ-02; REPORT_NOT_READY 해당 경계. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4; STA는 R2, 저장·시간은 R8. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

### WRK. work·attempt·취소·예산

#### R3-REC-WRK-001 — 두 worker의 active attempt 경쟁

- **1. ID·단계·work**: R3-REC-WRK-001; 5·8 및 claim 공통 / HYPOTHESIS_PROPOSAL·VERIFICATION. CT 연결: COM-008/010.
- **2. 중단 전 상태·current**: WRK 기준(§3.3): 같은 analysis/가설에 논리 work K1 하나, 이전 attempt A0 history, 현재 A1. case가 READY/종료/취소를 지정하면 그 상태가 우선. 확정된 current r0 외 늦은 응답은 후보. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: R1/W1/C1/H1/G1, K1, A0/A1, IH1, state_version=v, 고정 configuration E1, application PA1. 모든 결과는 자기 producer work의 attempt와 연결. 자세한 정상 graph는 F-COM/F-HYP/F-BUD(#106 §2.3).
- **4. 저장된 record·artifact·marker**: 승자의 attempt/transition marker와 패자의 미확정 요청.
- **5. 정확한 장애 주입 지점**: 같은 READY K1/v에서 동시 claim 후 한 worker를 종료한다.
- **6. 재시작 검사 조건**: CAS v·active attempt 하나·미완료 journal 존재·승자 생존/실행 불확실성.
- **7. 복구 조치**: 승자 marker 복구가 먼저. 패자는 같은 version으로 실행 금지. 사망 worker 판별/lease 정책은 RQ-04, 단순 timeout으로 외부 실행 미발생 단정 금지.
- **8. 기대 state·current/격리 결과**: 동일 work에 active attempt 최대 하나; 재시도하면 이전 종료 기록과 새 ID. 가설 자동 판정 없음.
- **9. 다음 단계 호출**: claim/복구 확정 전 provider/tool 중복 호출 금지.
- **10. 기대 오류·관측 log**: STATE_VERSION_CONFLICT; uncertain execution RQ-04. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음. 적용 기준: R3-06 §10.7 RQ-04.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R8; Verification는 R6. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-WRK-002 — timeout 후 새 시도 중 이전 응답 도착

- **1. ID·단계·work**: R3-REC-WRK-002; 6·10·12 결과 제출 / 해당 LLM work·DYNAMIC_REPRO. CT 연결: COM-007, LLM-006/007.
- **2. 중단 전 상태·current**: WRK 기준(§3.3): 같은 analysis/가설에 논리 work K1 하나, 이전 attempt A0 history, 현재 A1. case가 READY/종료/취소를 지정하면 그 상태가 우선. 확정된 current r0 외 늦은 응답은 후보. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: R1/W1/C1/H1/G1, K1, A0/A1, IH1, state_version=v, 고정 configuration E1, application PA1. 모든 결과는 자기 producer work의 attempt와 연결. 자세한 정상 graph는 F-COM/F-HYP/F-BUD(#106 §2.3).
- **4. 저장된 record·artifact·marker**: A1 실패 invocation/history, A2 current active attempt.
- **5. 정확한 장애 주입 지점**: A1 timeout 처리→A2 시작 후 A1 응답을 반환한다.
- **6. 재시작 검사 조건**: 제출 attempt와 active attempt, request/spec/decision과 current input/gen 비교.
- **7. 복구 조치**: A1을 ATTEMPT_NOT_ACTIVE로 거절·격리. A2 결과만 현재 계약으로 검사. A1 성공처럼 보인다고 A2를 바꾸지 않음.
- **8. 기대 state·current/격리 결과**: A2 정상 상태 유지; old response는 current output/가설 final에 연결 안 됨.
- **9. 다음 단계 호출**: A2가 유효 commit될 때만 후속 허용.
- **10. 기대 오류·관측 log**: ATTEMPT_NOT_ACTIVE; 취소/입력 변경 변형 STALE_RESULT. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R8; Verification는 R6. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-WRK-003 — 취소 직전·직후 결과와 종료 경합

- **1. ID·단계·work**: R3-REC-WRK-003; 공통 취소 및 12 / 해당 work·DYNAMIC_REPRO. CT 연결: COM-007/010, DYN-008.
- **2. 중단 전 상태·current**: WRK 기준(§3.3): 같은 analysis/가설에 논리 work K1 하나, 이전 attempt A0 history, 현재 A1. case가 READY/종료/취소를 지정하면 그 상태가 우선. 확정된 current r0 외 늦은 응답은 후보. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: R1/W1/C1/H1/G1, K1, A0/A1, IH1, state_version=v, 고정 configuration E1, application PA1. 모든 결과는 자기 producer work의 attempt와 연결. 자세한 정상 graph는 F-COM/F-HYP/F-BUD(#106 §2.3).
- **4. 저장된 record·artifact·marker**: 경합 중 journal, 결과 후보, cancel transition 중 하나가 먼저 유효 확정.
- **5. 정확한 장애 주입 지점**: 결과 COMMITTED 직전/직후 CANCEL_WORK를 요청하고, 취소 확정 후 결과를 늦게 제출한다.
- **6. 재시작 검사 조건**: 현재 version/journal·active attempt·terminal 여부. 선행 COMMITTED는 먼저 재투영.
- **7. 복구 조치**: 유효 상태 전이 순서를 존중. 취소가 먼저 확정되면 후속 늦은 output은 STALE_RESULT. dynamic 취소 전이가 현재 attempt CANCELLED 결과를 함께 확정하는 정상 경로도 시험.
- **8. 기대 state·current/격리 결과**: CANCELLED work를 성공으로 되살리지 않음. 결과가 먼저 성공한 terminal work에 취소 전이 강요 안 함.
- **9. 다음 단계 호출**: 취소된 작업은 새 domain 후속 없음; 이미 확정된 결과 사용은 run/current 조건 별도 검사.
- **10. 기대 오류·관측 log**: STALE_RESULT / STATE_TRANSITION_INVALID / STATE_VERSION_CONFLICT. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R8; Verification는 R6. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-WRK-004 — terminal work·취소 run 재시작

- **1. ID·단계·work**: R3-REC-WRK-004; 1 및 terminal work / 새 논리 work 등록. CT 연결: COM-010, LLM-007.
- **2. 중단 전 상태·current**: WRK 기준(§3.3): 같은 analysis/가설에 논리 work K1 하나, 이전 attempt A0 history, 현재 A1. case가 READY/종료/취소를 지정하면 그 상태가 우선. 확정된 current r0 외 늦은 응답은 후보. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: R1/W1/C1/H1/G1, K1, A0/A1, IH1, state_version=v, 고정 configuration E1, application PA1. 모든 결과는 자기 producer work의 attempt와 연결. 자세한 정상 graph는 F-COM/F-HYP/F-BUD(#106 §2.3).
- **4. 저장된 record·artifact·marker**: 과거 terminal work·result·fail/cancel 기록, 과거 call chain.
- **5. 정확한 장애 주입 지점**: FAILED/CANCELLED/SUCCEEDED work를 resume 명령으로 RUNNING 전환 시도. 별도 사람의 새 논리 실행 승인 fixture.
- **6. 재시작 검사 조건**: work_generation·새 work_id·명시적 승인·run 종료 상태·예산/config 권한.
- **7. 복구 조치**: terminal work rollback 금지. non-terminal `BLOCKED`이고 입력이 같을 때만 `resume`한다. terminal run에서 동일 입력을 다시 실행하려면 사용자가 새 `run`을 요청해 새 `analysis_id`를 만들며, 기존 run을 자동 재개하지 않는다.
- **8. 기대 state·current/격리 결과**: 옛 terminal 상태 유지. 승인된 새 실행은 새 식별자/독립 호출; 취소 invocation predecessor 재사용 금지.
- **9. 다음 단계 호출**: 유효 새 run/work 등록 조건 충족 뒤만 가능.
- **10. 기대 오류·관측 log**: STATE_TRANSITION_INVALID / INVOCATION_CHAIN_INVALID; run 재시작 세부 RQ-05. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음. 적용 기준: R3-06 §10.7 RQ-05.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R8; Verification는 R6. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-WRK-005 — 재시작 중 identity·generation·입력 변경

- **1. ID·단계·work**: R3-REC-WRK-005; 8·10·13·16 / VERIFICATION·PRO_EVIDENCE·CON_EVIDENCE. CT 연결: COM-002/003, HYP-005, VER-004.
- **2. 중단 전 상태·current**: WRK 기준(§3.3): 같은 analysis/가설에 논리 work K1 하나, 이전 attempt A0 history, 현재 A1. case가 READY/종료/취소를 지정하면 그 상태가 우선. 확정된 current r0 외 늦은 응답은 후보. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: R1/W1/C1/H1/G1, K1, A0/A1, IH1, state_version=v, 고정 configuration E1, application PA1. 모든 결과는 자기 producer work의 attempt와 연결. 자세한 정상 graph는 F-COM/F-HYP/F-BUD(#106 §2.3).
- **4. 저장된 record·artifact·marker**: 옛 exact input의 PREPARED 후보 또는 늦은 결과. 별도 최신 policy 게시만 있는 정상 변형.
- **5. 정확한 장애 주입 지점**: W/C/H/generation/input refs 중 하나씩 변경한 상태에서 저장 중이던 r1을 복구한다.
- **6. 재시작 검사 조건**: current를 요구하는 refs와 고정 work 입력의 구분; 지원 schema/producer scope·record hash.
- **7. 복구 조치**: 실제 고정 input 혼합은 ABORTED/stale 격리. 검증 중 policy 게시만으로 기존 PlaybookApplication을 바꾸지 않음. 이미 COMMITTED였으면 새로운 invalidation 절차와 구분.
- **8. 기대 state·current/격리 결과**: old 후보 current 승격 없음; 정상 pinned application retry는 같은 질문/refs 유지.
- **9. 다음 단계 호출**: 잘못된 scope의 다음 단계 금지; 정상 고정 입력만 재검사 후 진행.
- **10. 기대 오류·관측 log**: STALE_RESULT / RECORD_REVISION_MISMATCH; scope 코드 RQ-02. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R8; Verification는 R6. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-WRK-006 — 예산 소진 전후 fan-out·process off 시간

- **1. ID·단계·work**: R3-REC-WRK-006; 공통 호출·fan-out 전 / 신규 work·attempt. CT 연결: BUD-001~003.
- **2. 중단 전 상태·current**: WRK 기준(§3.3): 같은 analysis/가설에 논리 work K1 하나, 이전 attempt A0 history, 현재 A1. case가 READY/종료/취소를 지정하면 그 상태가 우선. 확정된 current r0 외 늦은 응답은 후보. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: R1/W1/C1/H1/G1, K1, A0/A1, IH1, state_version=v, 고정 configuration E1, application PA1. 모든 결과는 자기 producer work의 attempt와 연결. 자세한 정상 graph는 F-COM/F-HYP/F-BUD(#106 §2.3).
- **4. 저장된 record·artifact·marker**: 초기 eval_config refs, 실측 usage·완료 attempt elapsed·미해결 호출 기록.
- **5. 정확한 장애 주입 지점**: 새 work/attempt 생성 직전 잔여 시간·비용·work 한도를 소진시킨다. 재시작 중 벽시계도 변경한다.
- **6. 재시작 검사 조건**: 승인된 profile·잔여 예산·completed attempts 합계. monotonic 기준이며 종료 중 unknown 실행 시간 복원은 RQ-06.
- **7. 복구 조치**: 시간/비용/work 한도 없어진 척 초기화하지 않음. block 대기와 process off 시간을 실행 elapsed에 더하지 않음. token 계획 초과/usage null만으로 중단하지 않음.
- **8. 기대 state·current/격리 결과**: 한도 소진은 추가 fan-out/attempt 금지, 해당 정리/종료 규칙; 가설 FALSE 없음.
- **9. 다음 단계 호출**: 예산 확인 없는 호출 0건; 부분 유효 결과는 오류 포함 보존.
- **10. 기대 오류·관측 log**: BUDGET_EXCEEDED; 측정 불확실성은 RQ-06. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음. 적용 기준: R3-06 §10.7 RQ-06.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R8; Verification는 R6. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-WRK-007 — work·application 등록 중 종료·재전달

- **1. ID·단계·work**: R3-REC-WRK-007; 8·16 / VERIFICATION 등록·PlaybookApplication. CT 연결: HYP-002/005, COM-011.
- **2. 중단 전 상태·current**: WRK 기준(§3.3): 같은 analysis/가설에 논리 work K1 하나, 이전 attempt A0 history, 현재 A1. case가 READY/종료/취소를 지정하면 그 상태가 우선. 확정된 current r0 외 늦은 응답은 후보. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: R1/W1/C1/H1/G1, K1, A0/A1, IH1, state_version=v, 고정 configuration E1, application PA1. 모든 결과는 자기 producer work의 attempt와 연결. 자세한 정상 graph는 F-COM/F-HYP/F-BUD(#106 §2.3).
- **4. 저장된 record·artifact·marker**: 기존 work/application 둘 다 없음 또는 같은 commit으로 존재; 부분 후보는 미확정.
- **5. 정확한 장애 주입 지점**: dedupe 조회→work_id/application 생성→원자 저장 사이에서 종료 후 동일 요청을 재전달한다.
- **6. 재시작 검사 조건**: dedupe key가 기존 hypothesis/proposal/policy/playbook 기반인지, 새 application ref로 달라지지 않는지.
- **7. 복구 조치**: 기존 확정 work와 application 반환. 부분 저장은 활성화 금지·정상 transaction/journal 복구. 후보가 있다는 이유로 새 work를 중복 생성하지 않음.
- **8. 기대 state·current/격리 결과**: 새 work 한 개와 pinned application 한 개; 둘 중 하나 없는 READY/RUNNING 상태 금지.
- **9. 다음 단계 호출**: 등록 pair의 원자 확정 후 배정/검증 허용.
- **10. 기대 오류·관측 log**: STORAGE/RECOVERY 원인 또는 conflict; exact code RQ-02. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R8; Verification는 R6. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-WRK-008 — 예산 reservation·commit·release 중 종료

- **1. ID·단계·work**: R3-REC-WRK-008; 모든 외부 실행 직전·직후 / 해당 work·attempt. CT 연결: BUD-001/002/003/006.
- **2. 중단 전 상태·current**: WORKSPACE_PREP 변형은 `AnalysisRunState.execution_budget_profile_ref`의 ACTIVE run-level profile, 그 뒤 변형은 같은 `analysis_id`의 ACTIVE `BudgetProfileBinding`과 exact work-kind limit, committed ledger 합계와 active reservation 집합을 고정한다. 같은 purpose의 다른 analysis에는 별도 execution profile·binding·ledger를 두며 새 action은 아직 미claim 또는 자기 analysis의 reservation을 가진 상태다.
- **3. work·attempt·generation·input**: 같은 analysis/action/work/attempt와 exact reservation_id, profile refs, reserved units, 실제 usage evidence를 연결한다.
- **4. 저장된 record·artifact·marker**: `BudgetReservation(RESERVED | COMMITTED | RELEASED)`, 선택적 `BudgetLedgerEntry`, action claim/side-effect/usage marker를 지점별로 남긴다.
- **5. 정확한 장애 주입 지점**: A reservation 전, B RESERVED 저장 뒤 action claim 전, C 외부 side effect 뒤 usage 저장 전, D ledger 저장과 COMMITTED 전이 사이, E 실행 전 거절 뒤 RELEASED 전, F commit/release 직후 응답 전 종료한다.
- **6. 재시작 검사 조건**: reservation 상태, ledger unique key, action claim/attempt 상태, durable side-effect·usage evidence, WORKSPACE_PREP의 run-level execution profile 또는 후속 work의 full binding·exact work-kind limit과 remaining 계산을 확인한다. registry와 ledger 조회는 `analysis_id`를 필수로 사용하고 같은 purpose의 다른 analysis current pointer나 reservation을 반환하지 않는지 함께 확인한다.
- **7. 복구 조치**: A는 새 reserve부터 시작한다. B/E에서 미실행이 증명되면 같은 reservation을 RELEASED로 끝낸다. D/F는 기존 ledger/state를 멱등 재투영한다. C처럼 실제 사용 여부를 증명하지 못하면 release·재실행하지 않고 `BLOCKED + waiting_for=BUDGET`으로 둔다. Recovery가 가격·사용량을 추정하지 않는다.
- **8. 기대 state·current/격리 결과**: reservation 하나당 ledger entry 최대 하나, terminal reservation 전이 한 번, action claim 최대 한 번이다. 동시 재시작도 unique constraint로 두 번째 debit을 거절한다.
- **9. 다음 단계 호출**: 안전한 reservation 상태가 확인되기 전 새 attempt·Provider·Sandbox·도구 호출은 0건이다.
- **10. 기대 오류·관측 log**: actual exhausted만 `BUDGET_EXCEEDED`; 증거 불명은 budget waiting/block 사유, storage 충돌은 실제 오류를 기록한다. token usage 미제공만으로 차단하지 않는다.
- **11. R8 예산·시간·비용**: 복구 재투영은 새 사용량이 아니다. 동일 reservation의 재전달로 elapsed·cost·work·call을 두 번 집계하지 않는다.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R8·R4와 해당 실행 owner. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

### LLM. 인증·Provider·Pro/Con

#### R3-REC-LLM-001 — AUTH_REQUIRED 뒤 재인증

- **1. ID·단계·work**: R3-REC-LLM-001; 6·10 및 LLM 호출 공통 / HYPOTHESIS_PROPOSAL·PRO_EVIDENCE·CON_EVIDENCE. CT 연결: LLM-005/006/007.
- **2. 중단 전 상태·current**: LLM 기준(§3.3): 일반 K1/A1 RUNNING 또는 부모 KV1과 PRO KP1/AP1, CON KC1/AC1. 고정 공통 입력 DH1/application PA1, 각 역할 NEW session과 별도 call/decision. final result는 아직 없음. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: R1/W1/C1/H1/G1; spec S1/payload P1/profile PV1/USED decision AD1; Pro/Con DH1 동일, work·attempt·session은 각각 독립. 자세한 정상 graph는 F-LLM/F-VER(#106 §2.3).
- **4. 저장된 record·artifact·marker**: 실패 call/spec/decision/log, 작업 BLOCKED·실제 waiting_for. 비밀 자체는 없음.
- **5. 정확한 장애 주입 지점**: 첫 provider 응답 AUTH_REQUIRED 기록 뒤 종료, 재시작 후 승인된 credential 갱신.
- **6. 재시작 검사 조건**: 인증 조건 해소·profile·권한·예산·새 invocation linkage. 이전 인증 재사용으로 위장하지 않음.
- **7. 복구 조치**: 조건 충족 후 허용된 새 attempt/call/spec/action/decision/session. token/cookie를 log나 prompt에 넣지 않음. Dynamic Reproduction Agent session 예외는 DYN 규칙.
- **8. 기대 state·current/격리 결과**: 일반 실패 attempt FAILED, 기존 work BLOCKED→READY→RUNNING; 새 결과 확정까지 가설 VERIFYING.
- **9. 다음 단계 호출**: 재인증 확인 전 provider 호출 금지, 후속은 유효 새 결과 뒤.
- **10. 기대 오류·관측 log**: AUTH_REQUIRED invocation 보존; authority/provider 세부 오류 RQ-02. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R6·R8; 해당 prompt owner. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-LLM-002 — rate limit·explicit failover 복원

- **1. ID·단계·work**: R3-REC-LLM-002; LLM 호출 공통 / 해당 역할 work. CT 연결: LLM-006/007, BUD-002.
- **2. 중단 전 상태·current**: LLM 기준(§3.3): 일반 K1/A1 RUNNING 또는 부모 KV1과 PRO KP1/AP1, CON KC1/AC1. 고정 공통 입력 DH1/application PA1, 각 역할 NEW session과 별도 call/decision. final result는 아직 없음. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: R1/W1/C1/H1/G1; spec S1/payload P1/profile PV1/USED decision AD1; Pro/Con DH1 동일, work·attempt·session은 각각 독립. 자세한 정상 graph는 F-LLM/F-VER(#106 §2.3).
- **4. 저장된 record·artifact·marker**: 원래 실패와 바로 앞 predecessor ref, versioned retry/failover policy.
- **5. 정확한 장애 주입 지점**: RATE_LIMITED→backoff 대기 중 종료; 별도 변형은 허용된 provider/model 변경 직전 종료.
- **6. 재시작 검사 조건**: same provider retry인지 허용된 failover인지, retry_count+1·단일 predecessor·새 spec/decision·고정 domain input.
- **7. 복구 조치**: 승인된 backoff 뒤 새 호출. 일반 retry는 retry_of, failover는 failover_from 하나만. silent fallback/old USED decision 재사용 거절. 호출 발생 여부 불명은 RQ-04.
- **8. 기대 state·current/격리 결과**: 기존 실패 history 보존; 허용 retry/실패 상태 정책. 사용량·비용 중복 집계 금지.
- **9. 다음 단계 호출**: 조건·예산 확인 전 호출 금지, 다음 모듈은 성공 commit 뒤.
- **10. 기대 오류·관측 log**: INVOCATION_CHAIN_INVALID / ACTION_NOT_ALLOWED, 원래 RATE_LIMITED. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음. 적용 기준: R3-06 §10.7 RQ-04.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R6·R8; 해당 prompt owner. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-LLM-003 — invalid output repair 중 종료·소진

- **1. ID·단계·work**: R3-REC-LLM-003; 6·10·13 / HYPOTHESIS_PROPOSAL·PRO_EVIDENCE·CON_EVIDENCE·VERIFICATION. CT 연결: LLM-002/006, HYP-004.
- **2. 중단 전 상태·current**: LLM 기준(§3.3): 일반 K1/A1 RUNNING 또는 부모 KV1과 PRO KP1/AP1, CON KC1/AC1. 고정 공통 입력 DH1/application PA1, 각 역할 NEW session과 별도 call/decision. final result는 아직 없음. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: R1/W1/C1/H1/G1; spec S1/payload P1/profile PV1/USED decision AD1; Pro/Con DH1 동일, work·attempt·session은 각각 독립. 자세한 정상 graph는 F-LLM/F-VER(#106 §2.3).
- **4. 저장된 record·artifact·marker**: 원래 invalid response의 안전한 기록·repair 시도 기록·call/attempt/session linkage.
- **5. 정확한 장애 주입 지점**: schema/semantic 실패 후 repair 단계 전/중/후 종료; 허용 횟수 소진 변형.
- **6. 재시작 검사 조건**: 실제 실행된 repair 증거·승인된 제한·새 호출 경계. 검증되지 않은 parsed output은 없다고 취급.
- **7. 복구 조치**: 규정된 repair 범위만 적용; 실제 새 provider 호출에는 현재 08/09 계약의 spec/action/session 기록 요구. repair와 retry 세부 대응은 RQ-07. 소진은 INVALID_OUTPUT 유지.
- **8. 기대 state·current/격리 결과**: 유효 output 확정 전 work SUCCEEDED/가설 final 금지. 복구불가 또는 한도 소진은 해당 FAILED 전파.
- **9. 다음 단계 호출**: invalid candidate 후속 소비 0건.
- **10. 기대 오류·관측 log**: INVALID_OUTPUT; 복구 불명 RECOVERY_FAILED. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음. 적용 기준: R3-06 §10.7 RQ-07.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R6·R8; 해당 prompt owner. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-LLM-004 — Pro/Con 한쪽 종료와 부모 반영 사이

- **1. ID·단계·work**: R3-REC-LLM-004; 10·13 / PRO_EVIDENCE·CON_EVIDENCE·부모 VERIFICATION. CT 연결: VER-001/002/004, COM-012.
- **2. 중단 전 상태·current**: LLM 기준(§3.3): 일반 K1/A1 RUNNING 또는 부모 KV1과 PRO KP1/AP1, CON KC1/AC1. 고정 공통 입력 DH1/application PA1, 각 역할 NEW session과 별도 call/decision. final result는 아직 없음. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: R1/W1/C1/H1/G1; spec S1/payload P1/profile PV1/USED decision AD1; Pro/Con DH1 동일, work·attempt·session은 각각 독립. 자세한 정상 graph는 F-LLM/F-VER(#106 §2.3).
- **4. 저장된 record·artifact·marker**: 독립 PRO 결과, CON 실패/오류, 부모 KV1 아직 이전 상태.
- **5. 정확한 장애 주입 지점**: PRO COMMITTED 성공, CON retryable 실패 commit 뒤 부모 BLOCKED 반영 전 종료. 별도 CON 최종 FAILED 변형.
- **6. 재시작 검사 조건**: 동일 parent/generation/DH1/application·각 child의 COMMITTED state. 상대 결과 노출 없음.
- **7. 복구 조치**: 합성·부모 새 attempt/최종 저장을 먼저 차단하고 상태 전파 복구. 입력 같으면 PRO 보존·CON만 새 attempt/NEW session. 최종 실패는 child 먼저 확정 뒤 부모/가설 FAILED atomic.
- **8. 기대 state·current/격리 결과**: retryable은 child/parent BLOCKED, H1 VERIFYING. 소진은 H1 FAILED·verification_result_ref=null. 성공 sibling만으로 verdict 만들지 않음.
- **9. 다음 단계 호출**: 둘 다 current SUCCEEDED/COMMITTED이고 같은 고정 입력일 때 합류.
- **10. 기대 오류·관측 log**: 원래 호출 오류·state projection trace; old result STALE_RESULT. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R6·R8; 해당 prompt owner. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-LLM-005 — 재개 시 Pro/Con context 오염

- **1. ID·단계·work**: R3-REC-LLM-005; 10 / PRO_EVIDENCE·CON_EVIDENCE. CT 연결: VER-003/004, LLM-003.
- **2. 중단 전 상태·current**: LLM 기준(§3.3): 일반 K1/A1 RUNNING 또는 부모 KV1과 PRO KP1/AP1, CON KC1/AC1. 고정 공통 입력 DH1/application PA1, 각 역할 NEW session과 별도 call/decision. final result는 아직 없음. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: R1/W1/C1/H1/G1; spec S1/payload P1/profile PV1/USED decision AD1; Pro/Con DH1 동일, work·attempt·session은 각각 독립. 자세한 정상 graph는 F-LLM/F-VER(#106 §2.3).
- **4. 저장된 record·artifact·marker**: 정상 PRO history와 오염된 CON payload/후보. provider 호출 전/후 변형.
- **5. 정확한 장애 주입 지점**: CON retry session에 PRO log/output/session을 연결하거나 옛 application 결과를 재사용한다.
- **6. 재시작 검사 조건**: 입력 allowlist·NEW session·상대 predecessor 금지·common hash·application 정확성.
- **7. 복구 조치**: 호출 전이면 0회 차단, 이미 응답이면 오염 결과 격리. 같은 역할의 clean session으로만 허용된 재시도.
- **8. 기대 state·current/격리 결과**: 가설 VERIFYING 또는 원인별 실패; 오염 결과로 합류/최종 verdict 없음.
- **9. 다음 단계 호출**: 정상 독립 결과 둘을 다시 확보해야 허용.
- **10. 기대 오류·관측 log**: CROSS_ROLE_INPUT_DENIED / INVOCATION_CHAIN_INVALID / STALE_RESULT. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R6·R8; 해당 prompt owner. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-LLM-006 — membership log parser 실패·부분 usage

- **1. ID·단계·work**: R3-REC-LLM-006; LLM 호출 공통 / 해당 역할 work. CT 연결: LLM-005/008, BUD-001.
- **2. 중단 전 상태·current**: LLM 기준(§3.3): 일반 K1/A1 RUNNING 또는 부모 KV1과 PRO KP1/AP1, CON KC1/AC1. 고정 공통 입력 DH1/application PA1, 각 역할 NEW session과 별도 call/decision. final result는 아직 없음. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: R1/W1/C1/H1/G1; spec S1/payload P1/profile PV1/USED decision AD1; Pro/Con DH1 동일, work·attempt·session은 각각 독립. 자세한 정상 graph는 F-LLM/F-VER(#106 §2.3).
- **4. 저장된 record·artifact·marker**: 노출 가능한 raw transcript·call/profile refs, 실제 제공된 usage 일부. secret은 synthetic sentinel만 사용.
- **5. 정확한 장애 주입 지점**: fake 구독 adapter의 log 일부가 손상/미제공된 상태로 프로세스 종료. domain 응답 정상 여부도 나눠 시험.
- **6. 재시작 검사 조건**: 실제 payload/output 검증 가능성·log 필수 provenance·누락 usage와 필수 계약 누락 구별.
- **7. 복구 조치**: usage 미제공만으로 실패/추정 금지. 필수 call/output provenance를 복원 못 하면 성공 결과 사용 차단. 실제 계정 지원은 #90과 별도.
- **8. 기대 state·current/격리 결과**: usage null은 허용될 수 있음; parser로 필수 참조 검증 불가이면 실패/복구 중단, 가설 FALSE 아님.
- **9. 다음 단계 호출**: 신뢰 가능한 parsed output·필수 refs가 확인된 경우만 진행.
- **10. 기대 오류·관측 log**: provider/parser 원인 RQ-02; 복구 안전성 불명 RECOVERY_FAILED. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음. 적용 기준: R3-06 §10.7 RQ-02/08.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R6·R8; 해당 prompt owner. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

### DYN. Sandbox·AgentLog·PoC·cleanup

#### R3-REC-DYN-001 — 요청 확정 뒤 Dynamic Reproduction Agent 시작 전 종료

- **1. ID·단계·work**: R3-REC-DYN-001; 11·12 / DYNAMIC_REPRO 등록·시작. CT 연결: DYN-001/002, HYP-002.
- **2. 중단 전 상태·current**: DYN 기준(§3.3): R6 exact request DQ1이 generation G1에 고정됨. dynamic work KD1 하나, 실행 attempt AD1, session SD1. requirements ER1/plan PL1/recipe RC1/environment ENV1/log L1/candidate PC1/PoC POC1는 case의 저장 지점까지만 존재. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: R1/W1/C1/H1/G1, KD1/AD1/IHD1, exact DQ1, SandboxProfile SP1, R8 lifecycle LP1, command record CMD1/digest CD1. request 생산 attempt와 동적 실행 attempt는 같을 필요 없음. 자세한 정상 graph는 F-DYN(#106 §2.3).
- **4. 저장된 record·artifact·marker**: DQ1 exact record; KD1 등록 여부, 초기 attempt/ActionDecision 유무가 지점별 다름.
- **5. 정확한 장애 주입 지점**: DynamicReproductionRequest가 저장되고 dynamic work 등록/시작 전후에 각각 종료.
- **6. 재시작 검사 조건**: 같은 generation dynamic work 단일성, request/current inputs·dedupe·실행 여부.
- **7. 복구 조치**: 기존 KD1 재사용. 등록/claim 기록을 확인한 뒤에만 start. 요청이 있다는 이유로 두 번째 dynamic work 생성 금지.
- **8. 기대 state·current/격리 결과**: generation당 KD1 하나, active attempt 최대 하나; R6 아직 VERIFYING.
- **9. 다음 단계 호출**: 실제 Sandbox 진입은 exact SandboxProfile SP1과 R8 예산 새 검사 뒤.
- **10. 기대 오류·관측 log**: 중복/상태 오류 RQ-02, STATE_VERSION_CONFLICT 해당 경계. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R7·R4·R6·R8. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-DYN-002 — requirements·recipe·build·container 단계 실패

- **1. ID·단계·work**: R3-REC-DYN-002; 12 / DYNAMIC_REPRO. CT 연결: DYN-003/004/007/008.
- **2. 중단 전 상태·current**: DYN 기준(§3.3): R6 exact request DQ1이 generation G1에 고정됨. dynamic work KD1 하나, 실행 attempt AD1, session SD1. requirements ER1/plan PL1/recipe RC1/environment ENV1/log L1/candidate PC1/PoC POC1는 case의 저장 지점까지만 존재. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: R1/W1/C1/H1/G1, KD1/AD1/IHD1, exact DQ1, SandboxProfile SP1, R8 lifecycle LP1, command record CMD1/digest CD1. request 생산 attempt와 동적 실행 attempt는 같을 필요 없음. 자세한 정상 graph는 F-DYN(#106 §2.3).
- **4. 저장된 record·artifact·marker**: 해당 지점까지 생긴 exact artifacts/logs·실제 자원 ledger. 실패 candidate는 validated PoC 아님.
- **5. 정확한 장애 주입 지점**: requirements 작성, recipe 확정, image build, container 생성/health check 직후 실패를 각각 주입.
- **6. 재시작 검사 조건**: requirements/plan/request·baseline/built digest·생성 자원·health checks·exact SandboxProfile과 lifecycle profile.
- **7. 복구 조치**: Dynamic Reproduction Agent가 같은 session에서 해결 가능한 조정은 현재 attempt event다. session 불능은 `RETRY` 새 attempt, 고정 입력을 바꾸지 않는 외부 조건은 `BLOCKED` 후 `RESUME` 새 attempt다. 재구성/cleanup은 승인된 전용 경계로 수행한다.
- **8. 기대 state·current/격리 결과**: work RUNNING 유지/새 RETRY/외부 BLOCKED/소진 FAILED를 원인별 구분. 환경 실패를 FALSE/HOLD로 변환 안 함.
- **9. 다음 단계 호출**: 검증된 환경과 승인 경계 없이 공격/PoC 실행 없음.
- **10. 기대 오류·관측 log**: 실제 SANDBOX/PROVIDER 실패·failure_category·한계, exact code RQ-02. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R7·R4·R6·R8. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-DYN-003 — Dynamic Reproduction Agent 시작 전 Sandbox 경계 차단

- **1. ID·단계·work**: R3-REC-DYN-003; 12 / DYNAMIC_REPRO. CT 연결: DYN-003/004.
- **2. 중단 전 상태·current**: DYN 기준(§3.3): R6 exact request DQ1이 generation G1에 고정됨. dynamic work KD1 하나, 실행 attempt AD1, session SD1. requirements ER1/plan PL1/recipe RC1/environment ENV1/log L1/candidate PC1/PoC POC1는 case의 저장 지점까지만 존재. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: R1/W1/C1/H1/G1, KD1/AD1/IHD1, exact DQ1, SandboxProfile SP1, R8 lifecycle LP1, command record CMD1/digest CD1. request 생산 attempt와 동적 실행 attempt는 같을 필요 없음. RunPolicyState는 감사 reference로만 둔다. 자세한 정상 graph는 F-DYN(#106 §2.3).
- **4. 저장된 record·artifact·marker**: exact SandboxPolicyDecision, POLICY_BLOCKED event; build 자원은 있는/없는 변형. Dynamic Reproduction Agent의 Sandbox 실행 단계는 미호출.
- **5. 정확한 장애 주입 지점**: 경계 전 requirements/plan 호출은 끝났으나 Controller DENY 뒤 결과 commit 전에 종료.
- **6. 재시작 검사 조건**: agent_invoked=false와 경계 전 invocation 구별·실제 자원/cleanup_required·request/plan/profile refs.
- **7. 복구 조치**: 최소 AgentLog/차단 decision/반환 dynamic result를 같은 attempt 계약으로 복구. 실행하지 않은 command/PoC를 꾸미지 않음.
- **8. 기대 state·current/격리 결과**: 외부 대기 또는 최종 실패 상태를 실제 원인에 따라 확정; 가설 final 없음. 자원 없을 때만 cleanup NOT_REQUIRED.
- **9. 다음 단계 호출**: Controller DENY에서 Sandbox 실행 통로 호출 0건; Reporter/Gate 금지.
- **10. 기대 오류·관측 log**: SANDBOX_POLICY_DENIED·SandboxProfile 외부 경계 차단 근거 보존, FALSE 근거나 프로그램 정책 위반 판정이 아님. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R7·R4·R6·R8. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-DYN-004 — container crash·상태 변경·불확실 환경

- **1. ID·단계·work**: R3-REC-DYN-004; 12 / DYNAMIC_REPRO. CT 연결: DYN-004/006/008/012.
- **2. 중단 전 상태·current**: DYN 기준(§3.3): R6 exact request DQ1이 generation G1에 고정됨. dynamic work KD1 하나, 실행 attempt AD1, session SD1. requirements ER1/plan PL1/recipe RC1/environment ENV1/log L1/candidate PC1/PoC POC1는 case의 저장 지점까지만 존재. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: R1/W1/C1/H1/G1, KD1/AD1/IHD1, exact DQ1, SandboxProfile SP1, R8 lifecycle LP1, command record CMD1/digest CD1. request 생산 attempt와 동적 실행 attempt는 같을 필요 없음. 자세한 정상 graph는 F-DYN(#106 §2.3).
- **4. 저장된 record·artifact·marker**: 실행 event 일부·old environment/recipe·Sandbox 경계/관측 기록. command 종료 여부는 불명일 수 있음.
- **5. 정확한 장애 주입 지점**: 실행 중 container crash, STATE_CHANGED/CONFIG_CHANGED/STATE_UNCERTAIN 후 종료를 각각 주입.
- **6. 재시작 검사 조건**: 살아 있는 자원·health check·환경 변경·실제 command event와 digest·새 환경 필요 조건.
- **7. 복구 조치**: 불확실 환경을 healthy라 추정해 계속하지 않는다. 같은 Agent session에서 요청한 container 재생성은 같은 attempt에서 새 environment binding을 만들고 계속한다. session 자체를 재시작하면 `RETRY` 새 attempt와 새 binding을 만든다.
- **8. 기대 state·current/격리 결과**: 유효 current attempt 환경만 사용; old log/PoC를 새 결과에 섞지 않음. 실패 자체 verdict 없음.
- **9. 다음 단계 호출**: 재검증된 환경·SandboxProfile·예산 확인 전에는 실행 금지.
- **10. 기대 오류·관측 log**: SANDBOX 원인·환경 상태 event. 복구 증명 불가 RECOVERY_FAILED. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음. 적용 기준: R3-06 §10.7 RQ-08.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R7·R4·R6·R8. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-DYN-005 — 동일 session 조정·RETRY·RESUME 분리

- **1. ID·단계·work**: R3-REC-DYN-005; 12 / DYNAMIC_REPRO. CT 연결: DYN-007/008/012, COM-010, BUD-002.
- **2. 중단 전 상태·current**: DYN 기준(§3.3): R6 exact request DQ1이 generation G1에 고정됨. dynamic work KD1 하나, 실행 attempt AD1, session SD1. requirements ER1/plan PL1/recipe RC1/environment ENV1/log L1/candidate PC1/PoC POC1는 case의 저장 지점까지만 존재. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: R1/W1/C1/H1/G1, KD1/AD1/IHD1, exact DQ1, SandboxProfile SP1, R8 lifecycle LP1, command record CMD1/digest CD1. request 생산 attempt와 동적 실행 attempt는 같을 필요 없음. 자세한 정상 graph는 F-DYN(#106 §2.3).
- **4. 저장된 record·artifact·marker**: A 현재 attempt event, B 실패 attempt history, C BLOCKED waiting_for. 각각 마지막 durable refs.
- **5. 정확한 장애 주입 지점**: A 같은 session command/PoC/container 조정, B session crash, C current work의 `input_refs/input_hash`를 바꾸지 않는 재인증·승인·외부 환경 정비·resource 확보 대기 후 복구를 각각 시험한다. program policy 상태 변경만으로 C를 만들지 않는다.
- **6. 재시작 검사 조건**: session 생존·외부 조건 필요 여부·active attempt·generation·동일 `input_refs/input_hash`·R8 잔여 시간/새 attempt 한도.
- **7. 복구 조치**: A 같은 attempt 유지. B RUNNING→READY→RUNNING, trigger RETRY/새 attempt. C BLOCKED→READY→RUNNING, trigger RESUME/새 attempt. old attempt 경계 완결을 확인한다. exact request나 SandboxProfile이 달라졌다면 C로 재개하지 않고 DYN-010의 새 generation 경로를 사용한다.
- **8. 기대 state·current/격리 결과**: 같은 KD1, active attempt 하나. work BLOCKED.finished_at=null; 각 반환 DynamicReproductionResult.finished_at은 기록. 소진은 final FAILED/no verdict.
- **9. 다음 단계 호출**: 정상 실행 재진입 전 각 외부/예산 조건 확인.
- **10. 기대 오류·관측 log**: 원래 실패 보존·BUDGET_EXCEEDED 해당 경우. 일반 work에 B의 전이 일반화 금지. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R7·R4·R6·R8. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-DYN-006 — AgentLog append 도중 종료·늦은 event

- **1. ID·단계·work**: R3-REC-DYN-006; 12 / DYNAMIC_REPRO. CT 연결: DYN-006.
- **2. 중단 전 상태·current**: DYN 기준(§3.3): R6 exact request DQ1이 generation G1에 고정됨. dynamic work KD1 하나, 실행 attempt AD1, session SD1. requirements ER1/plan PL1/recipe RC1/environment ENV1/log L1/candidate PC1/PoC POC1는 case의 저장 지점까지만 존재. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: R1/W1/C1/H1/G1, KD1/AD1/IHD1, exact DQ1, SandboxProfile SP1, R8 lifecycle LP1, command record CMD1/digest CD1. request 생산 attempt와 동적 실행 attempt는 같을 필요 없음. 자세한 정상 graph는 F-DYN(#106 §2.3).
- **4. 저장된 record·artifact·marker**: durable prefix log와 SandboxCommandRecord, 동일 action_id/command_ref/digest/environment/recipe refs.
- **5. 정확한 장애 주입 지점**: COMMAND_STARTED durable 뒤 COMMAND_FINISHED 전 종료; append 완료 응답 직전 종료·old attempt event 재전달도 시험.
- **6. 재시작 검사 조건**: sequence 1부터 증가·event ID 전역 고유·start/finish 결합·redacted command digest·durability ACK 경계.
- **7. 복구 조치**: 확정 prefix를 수정·삭제·재정렬하지 않음. 없는 종료/관찰을 만들어내지 않음. 동일 event 재전달 처리/불확실 끝 event 정책 RQ-09; old attempt event는 current에 미첨부.
- **8. 기대 state·current/격리 결과**: 검증 가능한 log만 보존, 새 attempt면 별도 sequence/session 연결. 미완성 실행은 성공/PoC 증거 아님.
- **9. 다음 단계 호출**: log/provenance 확인 전 current dynamic result 소비 금지.
- **10. 기대 오류·관측 log**: STALE_RESULT 또는 log/provenance 오류 RQ-02; 불명 RECOVERY_FAILED. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음. 적용 기준: R3-06 §10.7 RQ-09.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R7·R4·R6·R8. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-DYN-007 — candidate·validated PoC 확정 전 종료

- **1. ID·단계·work**: R3-REC-DYN-007; 12·13 / DYNAMIC_REPRO·VERIFICATION. CT 연결: DYN-001/004/005/006, VER-005/006.
- **2. 중단 전 상태·current**: DYN 기준(§3.3): R6 exact request DQ1이 generation G1에 고정됨. dynamic work KD1 하나, 실행 attempt AD1, session SD1. requirements ER1/plan PL1/recipe RC1/environment ENV1/log L1/candidate PC1/PoC POC1는 case의 저장 지점까지만 존재. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: R1/W1/C1/H1/G1, KD1/AD1/IHD1, exact DQ1, SandboxProfile SP1, R8 lifecycle LP1, command record CMD1/digest CD1. request 생산 attempt와 동적 실행 attempt는 같을 필요 없음. 자세한 정상 graph는 F-DYN(#106 §2.3).
- **4. 저장된 record·artifact·marker**: 각 단계의 PC1/실제 관찰/log; validated POC1 후보 또는 완전 COMMITTED DX1·POC1 pair.
- **5. 정확한 장애 주입 지점**: candidate 생성/실행 실패, 정상 DISPROVED/INCONCLUSIVE, POC 검증 후 dynamic commit 직전을 각각 시험.
- **6. 재시작 검사 조건**: same-attempt exact request·plan·recipe·environment·AgentLog·candidate revision/digest·실행 action·지지 관찰·validated 요건·commit binding.
- **7. 복구 조치**: candidate만 있으면 승격하지 않는다. `SUCCEEDED + SUPPORTED`이고 위 same-attempt closure를 모두 재검증한 확정 pair만 소비한다. 실패 candidate는 history로 남기고 실패를 정상 INCONCLUSIVE로 위장하지 않는다.
- **8. 기대 state·current/격리 결과**: 정상 DISPROVED/INCONCLUSIVE는 poc_ref=null; 실제 관측·검증 완료 후에만 R6 FALSE/HOLD 가능. 실행 오류는 final 없음.
- **9. 다음 단계 호출**: TRUE/Gate는 current generation의 정상 DX1+POC1 exact commit 후만 허용.
- **10. 기대 오류·관측 log**: INVALID_OUTPUT / STALE_RESULT; 실제 실패 원인 보존. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R7·R4·R6·R8. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-DYN-008 — cleanup 중 종료·잘못된 NOT_REQUIRED

- **1. ID·단계·work**: R3-REC-DYN-008; 12 / DYNAMIC_REPRO. CT 연결: DYN-001/003/004/006/012.
- **2. 중단 전 상태·current**: DYN 기준(§3.3): R6 exact request DQ1이 generation G1에 고정됨. dynamic work KD1 하나, 실행 attempt AD1, session SD1. requirements ER1/plan PL1/recipe RC1/environment ENV1/log L1/candidate PC1/PoC POC1는 case의 저장 지점까지만 존재. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: R1/W1/C1/H1/G1, KD1/AD1/IHD1, exact DQ1, SandboxProfile SP1, R8 lifecycle LP1, command record CMD1/digest CD1. request 생산 attempt와 동적 실행 attempt는 같을 필요 없음. 자세한 정상 graph는 F-DYN(#106 §2.3).
- **4. 저장된 record·artifact·marker**: exact 자원 식별자·cleanup 요청/결과/refs·attempt log. 목록 밖 host 자원은 범위 밖.
- **5. 정확한 장애 주입 지점**: container/network/volume/build 임시 자원 생성 후 cleanup 중 프로세스 종료; 이미 정리된 자원 재확인 변형.
- **6. 재시작 검사 조건**: 정리 대상 존재와 소유권·cleanup_required/status/ref·실제 성공 여부·정리의 중복 안전성.
- **7. 복구 조치**: 승인된 cleanup 경계만 복구. 실제 자원이 있었으면 NOT_REQUIRED 금지. 반복 정리는 소유한 정확한 테스트 자원에만 적용. 실패의 후속 격리 정책 RQ-08.
- **8. 기대 state·current/격리 결과**: cleanup_required=true이면 SUCCEEDED/FAILED+exact ref, 없을 때만 false/NOT_REQUIRED. 성공 기록 없이 깨끗하다고 선언하지 않음.
- **9. 다음 단계 호출**: cleanup 불확실/실패에서 새 환경 재사용이나 정상 완료는 R7/R4 확정 조건 전 차단.
- **10. 기대 오류·관측 log**: 실제 cleanup failure와 refs 보존; FAILED를 지우거나 FALSE 근거로 사용 안 함. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음. 적용 기준: R3-06 §10.7 RQ-08.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R7·R4·R6·R8. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-DYN-009 — 동적 결과 commit과 R6 current pointer 사이 종료

- **1. ID·단계·work**: R3-REC-DYN-009; 12·13 / DYNAMIC_REPRO·VERIFICATION. CT 연결: COM-011/012, DYN-001/006, VER-005/006.
- **2. 중단 전 상태·current**: DYN 기준(§3.3). Reproduction Session Manager가 DX1 candidate와 transition을 준비했거나 COMMITTED했지만 `DynamicReproductionState.dynamic_result_ref`, KD1 `output_refs`, `last_transition_commit_ref` 중 일부 projection이 끝나지 않은 변형을 사용한다.
- **3. work·attempt·generation·input**: R1/W1/C1/H1/G1, KD1/AD1/IHD1, exact DQ1, DX1, TransitionCommit TC1. DX1·WorkAttempt·StateTransition·TC1은 모두 같은 AD1과 exact output reference를 사용한다.
- **4. 저장된 record·artifact·marker**: DX1, AD1 output, PREPARED 또는 COMMITTED TC1, 지점별로 아직 갱신되지 않은 work/state pointer.
- **5. 정확한 장애 주입 지점**: A DX1 저장 뒤 PREPARED 전, B PREPARED 뒤 COMMITTED 전, C COMMITTED 뒤 work output 투영 전, D work 투영 뒤 `DynamicReproductionState.dynamic_result_ref` 투영 전에 종료한다.
- **6. 재시작 검사 조건**: TC1 state·attempt_id·output_refs, KD1 active attempt·input hash, WorkAttempt output, work의 `last_transition_commit_ref`, DynamicReproductionState request/result pointer가 같은 exact record를 가리키는지 확인한다.
- **7. 복구 조치**: A/B는 후보를 재검증해 같은 transition을 COMMITTED하거나 ABORTED한다. C/D는 LLM·Sandbox를 다시 실행하지 않고 같은 TC1을 멱등 재투영한다. 다른 attempt 결과나 latest lookup으로 빈 pointer를 채우지 않는다.
- **8. 기대 state·current/격리 결과**: COMMITTED TC1, KD1 output, WorkAttempt output과 `DynamicReproductionState.dynamic_result_ref`가 모두 DX1 하나를 가리킬 때만 R6가 소비한다. PREPARED·ABORTED·active attempt 불일치는 current가 아니다.
- **9. 다음 단계 호출**: exact 네 방향 결합이 확인되기 전 final Verification 합성·TRUE 저장·Technical Gate 호출은 0건이다. 복구 뒤에도 DX1을 한 번만 소비한다.
- **10. 기대 오류·관측 log**: 불일치는 `STALE_RESULT | ATTEMPT_NOT_ACTIVE | STATE_VERSION_CONFLICT | RECORD_REVISION_MISMATCH`, 안전한 결정을 못 하면 `RECOVERY_FAILED`다. 오류를 FALSE/HOLD로 바꾸지 않는다.
- **11. R8 예산·시간·비용**: projection 복구는 새 attempt·새 Sandbox 실행이 아니므로 usage·elapsed를 중복 집계하지 않는다.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R6·R7·R8. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-DYN-010 — exact request 또는 SandboxProfile 변경 뒤 RESUME 차단과 새 generation

- **1. ID·단계·work**: R3-REC-DYN-010; 10–13 / 기존 VERIFICATION·DYNAMIC_REPRO의 입력 변경 감지, old work 종료와 새 Verification generation. CT 연결: DYN-004/008/011/013.
- **2. 중단 전 상태·current**: H1은 VERIFYING이고 G1의 ACTIVE Verification owner, old VERIFICATION work KV1, DYNAMIC_REPRO work KD1·attempt AD1, DQ1·SP1, `HypothesisProcessState.current_generation=G1`, `DynamicReproductionState.verification_generation=G1`과 current pointers가 고정돼 있다. DQ2 또는 SP2가 필요한 상황을 각각 만든다.
- **3. work·attempt·generation·input**: action은 `RESTART_VERIFICATION_GENERATION`, requester는 같은 H1/G1의 ACTIVE Verification owner, `generation_restart_reason`은 `DYNAMIC_REQUEST_REPLACEMENT_REQUIRED | SANDBOX_PROFILE_REVISION_CHANGED`다. old process/assignment/work/attempt/request/profile/application/playbook exact refs, 하나 이상의 `generation_restart_basis_refs`, `expected_verification_generation=G1`, expected state version을 고정한다. request 교체 사유는 새 DQ2를 선행 입력으로 요구하지 않고 old DQ1과 변경 근거만 검사한다. profile 사유는 old SP1과 승인된 새 SP2 exact ref가 실제로 다름을 검사한다. RunPolicyState만 달라지는 변형은 입력 변경으로 취급하지 않는다.
- **4. 저장된 record·artifact·marker**: G1의 old action/decision/attempt/environment/AgentLog/result/PoC/CWE/Gate history와 변경 사유를 보존한다. G2 transaction이 COMMITTED되기 전 새 current pointer나 일부 G2 work는 보이지 않아야 한다.
- **5. 정확한 장애 주입 지점**: A action 저장 전, B validator ALLOW 뒤 transaction 전, C old attempt/work CANCELLED 처리 중, D G2/VERIFICATION/Application/질문/Pro·Con 생성 중, E process pointer 갱신 중, F 새 DynamicReproductionState 초기화 중, G transaction commit 직후 응답 전 종료한다. 같은 expected generation으로 두 요청을 동시에 보내는 변형도 둔다.
- **6. 재시작 검사 조건**: ACTIVE Verification owner, H1 VERIFYING, expected generation/state version, old current closure, 닫힌 사유와 exact 변경 근거를 확인한다. request 교체는 새 request ref 없이 교체 필요 근거를, profile 변경은 old/new exact profile 차이를 검사한다. 이어서 action USED 여부와 `(hypothesis_id, expected_generation)` successor unique key를 확인한다.
- **7. 복구 조치**: B 이전은 같은 요청을 재검사한다. C–F는 SQLite transaction rollback 때문에 G1 current를 유지한다. G는 LLM·Sandbox를 다시 실행하지 않고 기존 G2와 USED action을 반환한다. Recovery는 DQ/SP 변경 필요나 새 질문 의미를 결정하지 않고 저장된 ACTIVE Verification 요청만 멱등 재생한다.
- **8. 기대 state·current/격리 결과**: commit 뒤 KV1/KD1 active attempt·work는 `CANCELLED/INPUT_SUPERSEDED`, G1은 history다. G2 VERIFICATION work, 새 PlaybookApplication, 전역 고유 질문, 독립 Pro/Con work, process pointer가 함께 current가 되고 G2 DynamicReproductionState는 `NOT_REQUESTED`, request/work/result refs null이다. 중복 요청은 G3를 만들지 않는다.
- **9. 다음 단계 호출**: G2 전이가 COMMITTED되기 전 호출은 0건이다. 이후 새 Pro/Con·initial assessment를 먼저 수행하고, G2가 동적 재현을 요구할 때만 새 DQ2/KD2를 별도 전이로 만든다. old result로 final TRUE·CWE·Gate·Primitive·Reporter를 호출하지 않는다.
- **10. 기대 오류·관측 log**: wrong requester/reason은 `AUTHORITY_DENIED | ACTION_NOT_ALLOWED`, stale version/generation은 `STATE_VERSION_CONFLICT | STALE_RESULT`, old RESUME은 `STATE_TRANSITION_INVALID`, old action 재사용은 `ACTION_NOT_ALLOWED`다. 여러 위반이면 R3-06 §8.4 우선순위를 적용한다.
- **11. R8 예산·시간·비용**: rollback·멱등 반환은 새 사용량이 아니다. G2의 실제 새 work/attempt/LLM 호출은 각각 실행 전 ACTIVE budget binding과 reservation을 새로 검사한다.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R6·R7·R8. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-DYN-011 — validated PoC same-attempt provenance 복구

- **1. ID·단계·work**: R3-REC-DYN-011; 12·13 / DYNAMIC_REPRO·VERIFICATION. CT 연결: DYN-005/006/010, VER-005/006.
- **2. 중단 전 상태·current**: DYN 기준(§3.3). AD1의 DQ1/PL1/RC1/ENV1/LOG1/PC1/CMD1/POC1/DX1 중 PoCBundle 또는 dynamic result 확정 전후에 종료한다.
- **3. work·attempt·generation·input**: 모든 validated PoC 구성요소는 R1/W1/C1/H1/G1/KD1/AD1과 exact candidate revision·content digest·실행 action·환경 digest를 공유한다.
- **4. 저장된 record·artifact·marker**: candidate·command start/finish·SUPPORTED 관찰·AgentLog durable prefix, POC1/DX1 candidate와 transition 상태. old attempt A0의 동일해 보이는 candidate·digest도 부정 fixture로 둔다.
- **5. 정확한 장애 주입 지점**: A candidate 작성 뒤 실행 전, B 실행 start 뒤 finish 전, C 지지 관찰 뒤 PoCBundle commit 전, D POC1 commit 뒤 DX1 commit 전, E DX1 commit 뒤 R6 pointer 전 종료한다.
- **6. 재시작 검사 조건**: request·plan·recipe·environment·AgentLog·candidate exact revision/digest·action·SUPPORTED 관찰·PoCBundle·DX1이 모두 AD1에 연결되는지, log가 실제 실행과 redaction을 입증하는지 검사한다.
- **7. 복구 조치**: 완전한 COMMITTED closure만 validated `poc_ref`로 재투영한다. candidate·부분 log·old attempt 결과를 PoC로 승격하지 않고, 없는 finish/관찰 event를 생성하지 않는다.
- **8. 기대 state·current/격리 결과**: `SUCCEEDED + SUPPORTED + agent_invoked=true`와 same-attempt closure를 모두 만족할 때만 DX1.poc_ref=POC1이다. 실패·DISPROVED·INCONCLUSIVE·불완전 log에서는 validated poc_ref=null이다.
- **9. 다음 단계 호출**: validated PoC와 exact DX1이 current generation에 함께 확정되기 전 R6 final TRUE와 Technical Gate 호출은 0건이다.
- **10. 기대 오류·관측 log**: old attempt·digest·environment 혼합은 `STALE_RESULT | RECORD_REVISION_MISMATCH`; 불완전 실행은 실제 failure category와 safe log로 남기며 FALSE/HOLD로 자동 변환하지 않는다.
- **11. R8 예산·시간·비용**: COMMITTED 재투영은 무료 복구로 집계하고, 실제 session 재시작만 새 attempt 예산을 소비한다.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R6·R7·R8. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

### FLW. 단계 연결·Gate·Chaining·보고

#### R3-REC-FLW-001 — 정적 병렬 합류·Context 중단

- **1. ID·단계·work**: R3-REC-FLW-001; 2·3·4·9 / WORKSPACE_PREP·STATIC_TOOL·STATIC_NORMALIZE·CONTEXT_RETRIEVAL. CT 연결: STA-001~007, COM-011/012.
- **2. 중단 전 상태·current**: FLW 기준(§3.3): 해당 단계 직전까지의 exact COMMITTED 결과만 준비. H1은 final TRUE chain, HOLD 가설 HH와 새 child HC는 서로 다른 hypothesis_id를 사용한다. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: 동일 R1/W1/C1; V1↔CW1↔TG1↔RS1↔RunPolicyState RPS1↔COL1/POL1 exact chain; Finding FN1/index FI1. Primitive PRA/PRB·match M1·child HC는 각 source record를 가리킴. 자세한 정상 graph는 F-STA/F-VER/F-GAT/F-CHN/F-REP(#106 §2.3).
- **4. 저장된 record·artifact·marker**: 도구별 immutable results/rule records와 current bundle/Context 후보; 일부 도구 실패 변형.
- **5. 정확한 장애 주입 지점**: AST만 완료한 시점·SAST 결과 합류 중·Context fragment 저장 직후 종료.
- **6. 재시작 검사 조건**: 모든 기대 tool 상태·각 자기 attempt·W/C refs·gaps/errors·Context 경로/한도·재개 중 HEAD 동일성.
- **7. 복구 조치**: 성공 도구를 중복 실행하지 않고 확정 output 재사용; 미확정 도구는 안전한 retry. 신뢰 부분 결과는 gap/error 포함 PARTIAL. Context 미완료를 정상 빈 응답으로 위장 안 함.
- **8. 기대 state·current/격리 결과**: STATIC_NORMALIZE의 단일 bundle와 commit이 일치. Context는 성공/신뢰 부분/실패 분리; 가설 판정 자동 변경 없음.
- **9. 다음 단계 호출**: 완전한 binding 및 허용된 partial 근거 확인 뒤 초기 가설/검증 진행.
- **10. 기대 오류·관측 log**: CLONE_FAILED/CHECKOUT_FAILED/WORKSPACE_CHANGED 또는 DataGap/AnalysisError 실제 원인. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음. 적용 기준: R3-06 §10.7 RQ-01.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R5·R6·R8; 정적 R2, Chaining R1, 동적 R7. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-FLW-002 — final TRUE와 상태 확정 도중 종료

- **1. ID·단계·work**: R3-REC-FLW-002; 13 / VERIFICATION. CT 연결: VER-005/006, COM-011/012.
- **2. 중단 전 상태·current**: FLW 기준(§3.3): 해당 단계 직전까지의 exact COMMITTED 결과만 준비. H1은 final TRUE chain, HOLD 가설 HH와 새 child HC는 서로 다른 hypothesis_id를 사용한다. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: 동일 R1/W1/C1; V1↔CW1↔TG1↔RS1↔RunPolicyState RPS1↔COL1/POL1 exact chain; Finding FN1/index FI1. Primitive PRA/PRB·match M1·child HC는 각 source record를 가리킴. 자세한 정상 graph는 F-STA/F-VER/F-GAT/F-CHN/F-REP(#106 §2.3).
- **4. 저장된 record·artifact·marker**: V1 후보 또는 COMMITTED final transition; current generation DX1/validated POC1와 Pro/Con refs.
- **5. 정확한 장애 주입 지점**: VerificationResult 저장 후 VERIFICATION SUCCEEDED/Hypothesis TERMINAL pointer 확정 전 종료.
- **6. 재시작 검사 조건**: 필수 검증 완료·current generation·DX1 SUCCEEDED/SUPPORTED·PoC·output/전문 pointer 결합.
- **7. 복구 조치**: COMMITTED면 정확한 V1으로 상태 투영. PREPARED는 재검증/ABORTED. DX1/PoC current 불일치 후보는 final TRUE로 복구하지 않음.
- **8. 기대 state·current/격리 결과**: VERIFICATION SUCCEEDED와 H1 TERMINAL은 같은 V1을 원자 참조. 실패/미확정이면 새 final 없음.
- **9. 다음 단계 호출**: current final chain 확인 뒤만 CWE/Technical Gate 허용.
- **10. 기대 오류·관측 log**: STALE_RESULT / RECORD_REVISION_MISMATCH / RECOVERY_FAILED. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R5·R6·R8; 정적 R2, Chaining R1, 동적 R7. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-FLW-003 — CWE·Technical 결과와 고정 정책 Gate 사이 종료

- **1. ID·단계·work**: R3-REC-FLW-003; 14·15·17 / CWE_LABEL·TECHNICAL_GATE·RULE_SCOPE_GATE. CT 연결: GAT-001/002/003/009.
- **2. 중단 전 상태·current**: FLW 기준(§3.3): 해당 단계 직전까지의 exact COMMITTED 결과만 준비. H1은 final TRUE chain, HOLD 가설 HH와 새 child HC는 서로 다른 hypothesis_id를 사용한다. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: 동일 R1/W1/C1; V1↔CW1↔TG1↔RS1↔RunPolicyState RPS1↔COL1/POL1 exact chain; Finding FN1/index FI1. Primitive PRA/PRB·match M1·child HC는 각 source record를 가리킴. 자세한 정상 graph는 F-STA/F-VER/F-GAT/F-CHN/F-REP(#106 §2.3).
- **4. 저장된 record·artifact·marker**: CW1/TG1 exact work/marker·input refs; 다음 단계 work 등록 유무.
- **5. 정확한 장애 주입 지점**: CWE result commit 전후, Technical ACCEPT commit 뒤 run-init에서 이미 고정한 RunPolicyState를 Rule Scope 입력에 결합하기 전 종료.
- **6. 재시작 검사 조건**: CWE→V1, TG1→V1/CW1 domain input exact equality·현재 검증·dedupe·권한.
- **7. 복구 조치**: 확정 CWE/TG는 재실행 없이 재투영/기존 결과 사용. run-init 정책을 새로 수집하거나 교체하지 않고 같은 run에 고정한 exact RunPolicyState와 policy closure로 미등록 Rule Scope work만 등록한다. Gate 호출 자체가 미확정이면 무기록 재전송을 금지한다(RQ-04).
- **8. 기대 state·current/격리 결과**: CWE/TG work output 단일 record. 호출 실패가 기존 TRUE를 FALSE로 바꾸지 않음.
- **9. 다음 단계 호출**: ACCEPT exact 확정 전 Rule Scope 금지; 정책 수집 성공/부재 구분 후 적법 호출.
- **10. 기대 오류·관측 log**: 호출 원인·STALE_RESULT·STATE_VERSION_CONFLICT; uncertain call RQ-04. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음. 적용 기준: R3-06 §10.7 RQ-04.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R5·R6·R8; 정적 R2, Chaining R1, 동적 R7. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-FLW-004 — REVISE commit와 새 generation 작업 복구

- **1. ID·단계·work**: R3-REC-FLW-004; 16 및 새 검증 / VERIFICATION·PRO_EVIDENCE·CON_EVIDENCE. CT 연결: VER-007, HYP-005, COM-011/012.
- **2. 중단 전 상태·current**: FLW 기준(§3.3): 해당 단계 직전까지의 exact COMMITTED 결과만 준비. H1은 final TRUE chain, HOLD 가설 HH와 새 child HC는 서로 다른 hypothesis_id를 사용한다. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: 동일 R1/W1/C1; V1↔CW1↔TG1↔RS1↔RunPolicyState RPS1↔COL1/POL1 exact chain; Finding FN1/index FI1. Primitive PRA/PRB·match M1·child HC는 각 source record를 가리킴. 자세한 정상 graph는 F-STA/F-VER/F-GAT/F-CHN/F-REP(#106 §2.3).
- **4. 저장된 record·artifact·marker**: 과거 V1/CW1/TG1 history, ACTIVE owner, 새 generation G2/work KV2/application/질문 candidate.
- **5. 정확한 장애 주입 지점**: Technical REVISE 확정 뒤 새 generation/VERIFICATION 등록 transaction 전·중·후 종료.
- **6. 재시작 검사 조건**: 같은 owner·generation 증가·새 work id·atomic application/input refs·parent pointer.
- **7. 복구 조치**: 미확정 새 work는 활성화 금지, 유효 새 generation commit은 재투영. old terminal work를 되살리지 않음. G2 Pro/Con은 항상 새로, TRUE면 새 dynamic/PoC/CWE.
- **8. 기대 state·current/격리 결과**: H1 VERIFYING/verification_work_ref=KV2. G2 진행 중 과거 result ref 보존 규칙을 따르되 G1을 G2 final로 승격하지 않음.
- **9. 다음 단계 호출**: 새 generation 선행 조건·두 child join·새 근거 전 Gate 재호출 금지.
- **10. 기대 오류·관측 log**: STATE_VERSION_CONFLICT / STALE_RESULT; 복구 불명 RECOVERY_FAILED. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R5·R6·R8; 정적 R2, Chaining R1, 동적 R7. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-FLW-005 — run-init 정책 준비와 Rule Scope 소비 중 종료

- **1. ID·단계·work**: R3-REC-FLW-005; 3·17 / POLICY_FETCH·RULE_SCOPE_GATE·PRIMITIVE_UPDATE. CT 연결: GAT-001/004/005/006/007/010, REP-002, BUD-004/005.
- **2. 중단 전 상태·current**: FLW 기준(§3.3): 해당 단계 직전까지의 exact COMMITTED 결과만 준비. H1은 final TRUE chain, HOLD 가설 HH와 새 child HC는 서로 다른 hypothesis_id를 사용한다. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: 동일 R1/W1/C1; V1↔CW1↔TG1↔RS1↔RunPolicyState RPS1↔COL1/POL1 exact chain; Finding FN1/index FI1. Primitive PRA/PRB·match M1·child HC는 각 source record를 가리킴. 자세한 정상 graph는 F-STA/F-VER/F-GAT/F-CHN/F-REP(#106 §2.3).
- **4. 저장된 record·artifact·marker**: Step 3의 RunPolicyState·parser/collection 결과, FOUND이면 policy, 부재이면 policy null, 실패이면 review 없음. Step 17은 같은 run의 고정 reference만 소비한다.
- **5. 정확한 장애 주입 지점**: A run-init `POLICY_FETCH`의 parser·collection·RunPolicyState/cache atomic commit 전후, B `COLLECTION_FAILED`, C `ABSENT_CONFIRMED`, D Technical ACCEPT 뒤 Rule Scope review commit 전후 종료를 각각 시험한다.
- **6. 재시작 검사 조건**: POLICY_FETCH work의 attempt·output binding, `AnalysisRunState.run_policy_state_ref`, 공식 출처/수집 상태·cache provenance, Step 17 review domain refs·Primitive admission 별도 의미를 확인한다.
- **7. 복구 조치**: COMMITTED 정책 준비는 새 수집 없이 같은 marker를 재투영한다. PREPARED는 검증 후 commit/abort한다. 실패를 부재로 바꿔 review를 만들지 않는다. 부재 확인은 UNCERTAIN+DENY review로 복구한다. COLLECTION_FAILED는 Rule Scope 미호출, NOT_EVALUATED/ALLOW admission을 별도 보존한다.
- **8. 기대 state·current/격리 결과**: 기존 TRUE 유지. 부재 review는 Finding eligibility 가능/Reporter 차단, 수집 실패는 Finding 없음·Reporter 차단.
- **9. 다음 단계 호출**: Report 금지; Primitive는 실제 admission 조건 별도 검사 후 허용 여부 결정.
- **10. 기대 오류·관측 log**: 수집 실패 실제 POLICY 오류·DataGap, 부재 자체 오류 아님. semantic 위조 INVALID_OUTPUT. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R5·R6·R8; 정적 R2, Chaining R1, 동적 R7. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-FLW-006 — Primitive admission·index 원자 저장 도중 종료

- **1. ID·단계·work**: R3-REC-FLW-006; 14·17·18 / PRIMITIVE_UPDATE·CHAINING. CT 연결: GAT-006, CHN-001/003.
- **2. 중단 전 상태·current**: FLW 기준(§3.3): 해당 단계 직전까지의 exact COMMITTED 결과만 준비. H1은 final TRUE chain, HOLD 가설 HH와 새 child HC는 서로 다른 hypothesis_id를 사용한다. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: 동일 R1/W1/C1; V1↔CW1↔TG1↔RS1↔RunPolicyState RPS1↔COL1/POL1 exact chain; Finding FN1/index FI1. Primitive PRA/PRB·match M1·child HC는 각 source record를 가리킴. 자세한 정상 graph는 F-STA/F-VER/F-GAT/F-CHN/F-REP(#106 §2.3).
- **4. 저장된 record·artifact·marker**: decision/Primitive/index candidate와 commit 또는 이전 ALLOW index. 기존 부모 verdict.
- **5. 정확한 장애 주입 지점**: TRUE admission/Primitive/index atomic commit의 각 경계와 HOLD Primitive/index commit 경계에서 종료한다. `DENY`라서 Primitive를 만들지 않는 경로와 HOLD 빈 후보도 별도 변형으로 둔다.
- **6. 재시작 검사 조건**: 해당 TRUE Technical ACCEPT·current testing 결정·target index/version·single commit output binding.
- **7. 복구 조치**: 새 COMMITTED 전체를 재투영한다. DENY면 새 result Primitive와 index 추가가 없고, 이미 등록된 Primitive를 제거하거나 admission을 다시 판정하지 않는다. HOLD nonempty는 decision 없이 Primitive와 index를 함께 확정하고, empty는 새 work 생성 자체가 없다.
- **8. 기대 state·current/격리 결과**: 유효 admission/Primitive/index 한 묶음만 current; 과거 history 보존, 부모 TRUE/HOLD 불변.
- **9. 다음 단계 호출**: Primitive와 PrimitiveIndexState 갱신이 같은 TransitionCommit으로 `COMMITTED`되기 전에는 Chaining을 시작하지 않는다. `PREPARED`이거나 pointer 일부만 반영된 상태이면 소비를 차단하고, exact commit과 pointer 묶음의 복구가 끝난 뒤 진행한다.
- **10. 기대 오류·관측 log**: STATE_VERSION_CONFLICT / STALE_RESULT; 정책 DENY는 FALSE 아님. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R5·R6·R8; 정적 R2, Chaining R1, 동적 R7. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-FLW-007 — Chaining 고정 입력·match·child 등록 중 종료

- **1. ID·단계·work**: R3-REC-FLW-007; 18·20·9 / CHAINING·HYPOTHESIS_PROPOSAL·VERIFICATION·CONTEXT_RETRIEVAL. CT 연결: CHN-002~009, HYP-001/002.
- **2. 중단 전 상태·current**: FLW 기준(§3.3): 해당 단계 직전까지의 exact COMMITTED 결과만 준비. H1은 final TRUE chain, HOLD 가설 HH와 새 child HC는 서로 다른 hypothesis_id를 사용한다. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: 동일 R1/W1/C1; V1↔CW1↔TG1↔RS1↔RunPolicyState RPS1↔COL1/POL1 exact chain; Finding FN1/index FI1. Primitive PRA/PRB·match M1·child HC는 각 source record를 가리킴. 자세한 정상 graph는 F-STA/F-VER/F-GAT/F-CHN/F-REP(#106 §2.3).
- **4. 저장된 record·artifact·marker**: work 시작 때 고정한 index revision과 considered Primitive refs, match triple/owner, child registration 여부. admission은 등록 시점 1회 판정 이력으로만 남고 Chaining 입력에서 다시 검사하지 않는다.
- **5. 정확한 장애 주입 지점**: candidate 조회 후 index 변경, match 저장 뒤 child 등록 전, child 등록 후 Context 전 각각 종료.
- **6. 재시작 검사 조건**: 시작 때 고정하지 않은 Primitive 주입 여부·index revision 단순 증가·triple 중복·pool 처리 책임·시작점 entity/location·등록 후 lineage를 확인한다.
- **7. 복구 조치**: work 시작 뒤 index에 새 Primitive가 추가돼도 기존 match를 무효화하지 않고 새 Primitive는 다음 Chaining work에서 처리한다. 고정 입력 밖 Primitive를 섞은 결과만 거절한다. 이벤트/child 재전달은 중복 등록을 막고, 등록 전 시작점 검사와 등록 뒤 Context 재검사를 수행한다.
- **8. 기대 state·current/격리 결과**: 같은 match/child를 중복 생성하지 않는다. 등록된 Primitive·기존 child를 사후 admission 재판정으로 회수하지 않는다. child는 새 HC로 전체 검증하고 부모 verdict/impact는 불변이다. 저장 registry는 #106 Q-01 및 본 문서 RQ-01 영향 표시.
- **9. 다음 단계 호출**: 등록/계보/Context 검증 완료 전 child 검증 시작/후속 소비 금지.
- **10. 기대 오류·관측 log**: STALE_RESULT, 중복 match는 ORCHESTRATION AnalysisError(정확한 code RQ-02); 정상 no-match로 위장 금지. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음. 적용 기준: R3-06 §10.7 RQ-01/02.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R5·R6·R8; 정적 R2, Chaining R1, 동적 R7. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-FLW-008 — Finding 정규화·upstream invalidation 경합

- **1. ID·단계·work**: R3-REC-FLW-008; 19 / FINDING_NORMALIZE·upstream invalidation. CT 연결: GAT-007/008/011, REP-002/003/005.
- **2. 중단 전 상태·current**: FLW 기준(§3.3): 해당 단계 직전까지의 exact COMMITTED 결과만 준비. H1은 final TRUE chain, HOLD 가설 HH와 새 child HC는 서로 다른 hypothesis_id를 사용한다. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: 동일 R1/W1/C1; V1↔CW1↔TG1↔RS1↔RunPolicyState RPS1↔COL1/POL1 exact chain; Finding FN1/index FI1. Primitive PRA/PRB·match M1·child HC는 각 source record를 가리킴. 자세한 정상 graph는 F-STA/F-VER/F-GAT/F-CHN/F-REP(#106 §2.3).
- **4. 저장된 record·artifact·marker**: Finding 정규화 journal·단일 Finding output 또는 upstream journal의 dependent index invalidation·old FN1 history.
- **5. 정확한 장애 주입 지점**: Finding COMMITTED 뒤 FI1 projection 전, upstream 변경으로 STALE invalidation 투영 전 각각 종료.
- **6. 재시작 검사 조건**: 전용 VERIFICATION service identity·ACTIVE owner·upstream exact closure·work CAS·index expected record/version.
- **7. 복구 조치**: COMMITTED normalization을 재투영. upstream invalidation은 같은 index CAS로 직렬화; 새 upstream을 반영하기 전에 후속 조회 차단. RECOVERY는 승인 service/journal 복구만, 새 Finding 의미 생산 금지.
- **8. 기대 state·current/격리 결과**: CURRENT면 finding_ref/normalization_work_ref/commit 일치. STALE면 finding_ref=null, old ref·invalidated_by refs 보존. RuleScope 없으면 CURRENT로 복원 금지.
- **9. 다음 단계 호출**: current chain·invalidation 모두 일치 후에만 6축 REPORT_READY 검사.
- **10. 기대 오류·관측 log**: STATE_VERSION_CONFLICT / STALE_RESULT / RECOVERY_FAILED. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R5·R6·R8; 정적 R2, Chaining R1, 동적 R7. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-FLW-009 — ReportDraft·최종 run 확정 도중 종료

- **1. ID·단계·work**: R3-REC-FLW-009; 21·22 / REPORT_DRAFT·run finalization. CT 연결: REP-001~005, COM-012, BUD-003.
- **2. 중단 전 상태·current**: FLW 기준(§3.3): 해당 단계 직전까지의 exact COMMITTED 결과만 준비. H1은 final TRUE chain, HOLD 가설 HH와 새 child HC는 서로 다른 hypothesis_id를 사용한다. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: 동일 R1/W1/C1; V1↔CW1↔TG1↔RS1↔RunPolicyState RPS1↔COL1/POL1 exact chain; Finding FN1/index FI1. Primitive PRA/PRB·match M1·child HC는 각 source record를 가리킴. 자세한 정상 graph는 F-STA/F-VER/F-GAT/F-CHN/F-REP(#106 §2.3).
- **4. 저장된 record·artifact·marker**: draft candidate/COMMITTED report transition, run 결과 candidate/marker, outstanding work/journal 목록.
- **5. 정확한 장애 주입 지점**: draft bytes 저장 전후 upstream revision 변경, AnalysisRunResult commit 직전/후 pointer 투영 전 종료.
- **6. 재시작 검사 조건**: report exact chain·6축/redaction·ReportProcessState binding·모든 work 정리·current finding/lineage·run config 집합.
- **7. 복구 조치**: stale draft는 current 금지. 유효 report commit 재투영. final result는 모든 작업/미완료 journal 정리 뒤 정확한 run state/result로 atomic 확정; 구체 저장 authority RQ-01.
- **8. 기대 state·current/격리 결과**: REPORT_DRAFT SUCCEEDED와 DRAFTED 같은 draft. final run/state/pointer 일치; report 없으면 이유 포함 empty list 허용. Agent 자동화 종료.
- **9. 다음 단계 호출**: 미해결 RUNNING/PREPARED/pointer가 있으면 최종화 금지; 종료 뒤 새 Agent/외부 공개 action 없음.
- **10. 기대 오류·관측 log**: REPORT_NOT_READY / STALE_RESULT / RECOVERY_FAILED, exact aggregation 오류 RQ-02. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음. 적용 기준: R3-06 §10.7 RQ-01/02.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R5·R6·R8; 정적 R2, Chaining R1, 동적 R7. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

## 6. 최소 E2E 복구 10묶음

fake provider·fake static tool·fake Sandbox로 먼저 구성할 계획이다. 각 scenario는 선택된 실제 dependency에서 수행할 별도 capability 시험과 구별한다. 아래 정상/실패 결과는 기대값이며 실제로 실행해 관찰한 결과가 아니다.

### E2E. 최소 종단 복구 10묶음

#### R3-REC-E2E-001 — 정상 분기별 전체 흐름

- **1. ID·단계·work**: R3-REC-E2E-001; 1–22 (분기별 해당 경로); fixture가 선택한 전체 run의 work 집합. CT 연결: STA/HYP/LLM/VER/DYN/GAT/CHN/REP/BUD 전체.
- **2. 중단 전 상태·current**: E2E 기준(§3.3): 새 run R1에서 시작. 중간 장애 전까지는 각 단계의 정상 COMMITTED chain. TRUE/HOLD/FALSE는 미리 정한 전문 결과 fixture이고 runtime이 직접 판정하지 않음. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: 동일 R1/W1/C1, 각 가설 Hn/generation Gn/work Kn/attempt An/고정 input hash IHn. schema/profile과 case별 장애 지점은 아래 연결된 REC card를 따름. 자세한 정상 graph는 F-STA/F-HYP/F-VER/F-DYN/F-GAT/F-CHN/F-REP/F-BUD(#106 §2.3).
- **4. 저장된 record·artifact·marker**: 각 정상 단계의 COMMITTED 결과. 분기 전체로 22단계 coverage를 확인하며 한 가설이 모든 상호배타 분기를 지나간다고 가정하지 않음.
- **5. 정확한 장애 주입 지점**: 장애 없이 TRUE→두 Gate→ReportDraft를 수행하고, 별도 fixture로 FALSE/HOLD/child 경로를 실행한다.
- **6. 재시작 검사 조건**: 정상 22단계 연결·각 exact output·runtime 권한·current·제약·예산.
- **7. 복구 조치**: 정상 producer 결과를 fake adapter로 주입하고 COMMITTED/상태를 단계별 관찰.
- **8. 기대 state·current/격리 결과**: 모든 work/commit/pointer 정합. 정상 TRUE 보고 경로는 COMPLETE·내부 draft; 다른 분기는 이유와 결과 집합을 사실대로 보존.
- **9. 다음 단계 호출**: 정상 선행 조건이 충족된 경로만 실행; 외부 공개 없음.
- **10. 기대 오류·관측 log**: 없음(정상 fixture); 발견된 mismatch는 시험 실패. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음. 적용 기준: 선행 REC card와 R3-06 §10.7.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R5·R6·R7·R8, 연결 경로 R1·R2. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-E2E-002 — LLM timeout 뒤 retry 성공

- **1. ID·단계·work**: R3-REC-E2E-002; 1–22 (분기별 해당 경로); fixture가 선택한 전체 run의 work 집합. CT 연결: LLM-006/007, COM-007.
- **2. 중단 전 상태·current**: E2E 기준(§3.3): 새 run R1에서 시작. 중간 장애 전까지는 각 단계의 정상 COMMITTED chain. TRUE/HOLD/FALSE는 미리 정한 전문 결과 fixture이고 runtime이 직접 판정하지 않음. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: 동일 R1/W1/C1, 각 가설 Hn/generation Gn/work Kn/attempt An/고정 input hash IHn. schema/profile과 case별 장애 지점은 아래 연결된 REC card를 따름. 자세한 정상 graph는 F-STA/F-HYP/F-VER/F-DYN/F-GAT/F-CHN/F-REP/F-BUD(#106 §2.3).
- **4. 저장된 record·artifact·marker**: 원래 timeout·old response와 새 call/attempt.
- **5. 정확한 장애 주입 지점**: LLM-002/WRK-002의 timeout과 늦은 응답을 주입한 뒤 다음 호출만 정상 반환.
- **6. 재시작 검사 조건**: predecessor·active attempt·same domain input·예산.
- **7. 복구 조치**: 제한된 새 retry를 수행하고 이전 성공처럼 보이는 응답은 격리.
- **8. 기대 state·current/격리 결과**: 후속 정상 결과만 current, 실패 trace 보존. 최종 run 상태는 실제 실패 집계 규칙에 따름.
- **9. 다음 단계 호출**: 새 유효 commit 뒤 흐름 재개.
- **10. 기대 오류·관측 log**: 원래 timeout/ATTEMPT_NOT_ACTIVE 보존; FALSE 없음. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음. 적용 기준: 선행 REC card와 R3-06 §10.7.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R5·R6·R7·R8, 연결 경로 R1·R2. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-E2E-003 — 재시도 소진·판정 미생성

- **1. ID·단계·work**: R3-REC-E2E-003; 1–22 (분기별 해당 경로); fixture가 선택한 전체 run의 work 집합. CT 연결: VER-002, LLM-006, BUD-002.
- **2. 중단 전 상태·current**: E2E 기준(§3.3): 새 run R1에서 시작. 중간 장애 전까지는 각 단계의 정상 COMMITTED chain. TRUE/HOLD/FALSE는 미리 정한 전문 결과 fixture이고 runtime이 직접 판정하지 않음. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: 동일 R1/W1/C1, 각 가설 Hn/generation Gn/work Kn/attempt An/고정 input hash IHn. schema/profile과 case별 장애 지점은 아래 연결된 REC card를 따름. 자세한 정상 graph는 F-STA/F-HYP/F-VER/F-DYN/F-GAT/F-CHN/F-REP/F-BUD(#106 §2.3).
- **4. 저장된 record·artifact·marker**: 모든 실패 attempt/call/log·잔여 예산.
- **5. 정확한 장애 주입 지점**: 같은 검증/child에서 R8 한도까지 허용 실패를 반복한다.
- **6. 재시작 검사 조건**: 실제 소진과 설정 revision·부모 실패 원자 전파.
- **7. 복구 조치**: 추가 retry 차단, child→부모/가설 실패와 남은 work 정리.
- **8. 기대 state·current/격리 결과**: 실패 가설 verification_result_ref=null; TRUE/FALSE/HOLD 새 생성 없음. run FAILED/PARTIAL 선택은 유효 다른 결과에 따름.
- **9. 다음 단계 호출**: 해당 가설 CWE/Gate/Reporter 없음.
- **10. 기대 오류·관측 log**: BUDGET_EXCEEDED 또는 실제 최종 실패 코드; 전체 history 보존. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음. 적용 기준: 선행 REC card와 R3-06 §10.7.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R5·R6·R7·R8, 연결 경로 R1·R2. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-E2E-004 — 저장 중 crash 뒤 resume

- **1. ID·단계·work**: R3-REC-E2E-004; 1–22 (분기별 해당 경로); fixture가 선택한 전체 run의 work 집합. CT 연결: COM-006/011/012.
- **2. 중단 전 상태·current**: E2E 기준(§3.3): 새 run R1에서 시작. 중간 장애 전까지는 각 단계의 정상 COMMITTED chain. TRUE/HOLD/FALSE는 미리 정한 전문 결과 fixture이고 runtime이 직접 판정하지 않음. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: 동일 R1/W1/C1, 각 가설 Hn/generation Gn/work Kn/attempt An/고정 input hash IHn. schema/profile과 case별 장애 지점은 아래 연결된 REC card를 따름. 자세한 정상 graph는 F-STA/F-HYP/F-VER/F-DYN/F-GAT/F-CHN/F-REP/F-BUD(#106 §2.3).
- **4. 저장된 record·artifact·marker**: 지점별 staging/PREPARED/COMMITTED/부분 projection.
- **5. 정확한 장애 주입 지점**: STO-001~006 장애 지점을 각각 하나씩 선택해 동일 정상 run을 재시작한다.
- **6. 재시작 검사 조건**: journal 우선순위·hash·상태 CAS·권한·exact output.
- **7. 복구 조치**: marker 재투영 또는 ABORTED/안전 중단. 동일 복구를 다시 실행해 중복 유무 검사.
- **8. 기대 state·current/격리 결과**: 성공 복구는 같은 확정 결과 한 개, 불확실 복구는 RECOVERY_FAILED. 증거 없이 성공으로 간주하지 않음.
- **9. 다음 단계 호출**: 안전한 commit+pointer 일치 후만 재개.
- **10. 기대 오류·관측 log**: 해당 STO 원인, 실패를 verdict로 변환 금지. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음. 적용 기준: 선행 REC card와 R3-06 §10.7.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R5·R6·R7·R8, 연결 경로 R1·R2. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-E2E-005 — 사용자 취소·늦은 결과

- **1. ID·단계·work**: R3-REC-E2E-005; 1–22 (분기별 해당 경로); fixture가 선택한 전체 run의 work 집합. CT 연결: COM-007/010, REP-005.
- **2. 중단 전 상태·current**: E2E 기준(§3.3): 새 run R1에서 시작. 중간 장애 전까지는 각 단계의 정상 COMMITTED chain. TRUE/HOLD/FALSE는 미리 정한 전문 결과 fixture이고 runtime이 직접 판정하지 않음. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: 동일 R1/W1/C1, 각 가설 Hn/generation Gn/work Kn/attempt An/고정 input hash IHn. schema/profile과 case별 장애 지점은 아래 연결된 REC card를 따름. 자세한 정상 graph는 F-STA/F-HYP/F-VER/F-DYN/F-GAT/F-CHN/F-REP/F-BUD(#106 §2.3).
- **4. 저장된 record·artifact·marker**: cancel transition·old invocation·정리 기록.
- **5. 정확한 장애 주입 지점**: WRK-003의 취소 경합과 취소 뒤 provider 응답을 주입한다.
- **6. 재시작 검사 조건**: 동일 version 경쟁과 terminal 불변성.
- **7. 복구 조치**: 선행 marker부터 복구 후 취소 순서 적용, late result 격리.
- **8. 기대 state·current/격리 결과**: CANCELLED work/run을 몰래 재개하지 않음; current에 취소 뒤 output 없음.
- **9. 다음 단계 호출**: 새 run은 별도 승인된 절차, 기존 자동화 계속 안 함.
- **10. 기대 오류·관측 log**: STALE_RESULT·정리 실패는 별도 보존. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음. 적용 기준: 선행 REC card와 R3-06 §10.7.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R5·R6·R7·R8, 연결 경로 R1·R2. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-E2E-006 — 동적 재현 실패 뒤 새 attempt·validated PoC

- **1. ID·단계·work**: R3-REC-E2E-006; 1–22 (분기별 해당 경로); fixture가 선택한 전체 run의 work 집합. CT 연결: DYN-001/006/008, VER-005.
- **2. 중단 전 상태·current**: E2E 기준(§3.3): 새 run R1에서 시작. 중간 장애 전까지는 각 단계의 정상 COMMITTED chain. TRUE/HOLD/FALSE는 미리 정한 전문 결과 fixture이고 runtime이 직접 판정하지 않음. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: 동일 R1/W1/C1, 각 가설 Hn/generation Gn/work Kn/attempt An/고정 input hash IHn. schema/profile과 case별 장애 지점은 아래 연결된 REC card를 따름. 자세한 정상 graph는 F-STA/F-HYP/F-VER/F-DYN/F-GAT/F-CHN/F-REP/F-BUD(#106 §2.3).
- **4. 저장된 record·artifact·marker**: old 실패 환경/log와 새 recipe binding·AgentLog·PoC.
- **5. 정확한 장애 주입 지점**: DYN-004/005의 session crash 후 새 clean attempt에서 정상 실행 fixture를 반환한다.
- **6. 재시작 검사 조건**: 같은 dynamic work·새 attempt·budget·same-attempt provenance.
- **7. 복구 조치**: 허용된 RETRY 또는 외부 조건 RESUME를 구분하고 새 검증 근거로 계속.
- **8. 기대 state·current/격리 결과**: 새 DX/validated PoC만 current; 기존 candidate·log는 history. R6가 유효 근거로만 final TRUE.
- **9. 다음 단계 호출**: 새 current TRUE/CWE/Gate 조건 후 보고 가능.
- **10. 기대 오류·관측 log**: 과거 Sandbox 실패 보존, old PoC 섞이면 STALE_RESULT. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음. 적용 기준: 선행 REC card와 R3-06 §10.7.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R5·R6·R7·R8, 연결 경로 R1·R2. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-E2E-007 — Technical REVISE 새 generation 완주

- **1. ID·단계·work**: R3-REC-E2E-007; 1–22 (분기별 해당 경로); fixture가 선택한 전체 run의 work 집합. CT 연결: VER-007, HYP-005, GAT-001.
- **2. 중단 전 상태·current**: E2E 기준(§3.3): 새 run R1에서 시작. 중간 장애 전까지는 각 단계의 정상 COMMITTED chain. TRUE/HOLD/FALSE는 미리 정한 전문 결과 fixture이고 runtime이 직접 판정하지 않음. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: 동일 R1/W1/C1, 각 가설 Hn/generation Gn/work Kn/attempt An/고정 input hash IHn. schema/profile과 case별 장애 지점은 아래 연결된 REC card를 따름. 자세한 정상 graph는 F-STA/F-HYP/F-VER/F-DYN/F-GAT/F-CHN/F-REP/F-BUD(#106 §2.3).
- **4. 저장된 record·artifact·marker**: 기존 final history와 G2 work/application/질문·ProCon/Dynamic.
- **5. 정확한 장애 주입 지점**: FLW-004 중단 지점 후 새 generation에서 정상 검증 fixture 수행.
- **6. 재시작 검사 조건**: same owner·new IDs/input hash·old artifacts 격리.
- **7. 복구 조치**: 복구 뒤 G2 전체 필수 검증/새 PoC/CWE/Technical을 수행.
- **8. 기대 state·current/격리 결과**: 새 final/current chain만 G2 자격. old 결과를 최신 generation으로 바꾸지 않음.
- **9. 다음 단계 호출**: 새 Technical ACCEPT와 정책/보고 조건 후만 다음 단계.
- **10. 기대 오류·관측 log**: stale/revision 오류 없으면 정상; 과거 REVISE 기록 유지. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음. 적용 기준: 선행 REC card와 R3-06 §10.7.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R5·R6·R7·R8, 연결 경로 R1·R2. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-E2E-008 — HOLD·Chaining child 복구

- **1. ID·단계·work**: R3-REC-E2E-008; 1–22 (분기별 해당 경로); fixture가 선택한 전체 run의 work 집합. CT 연결: CHN-001~008, HYP-001/002.
- **2. 중단 전 상태·current**: E2E 기준(§3.3): 새 run R1에서 시작. 중간 장애 전까지는 각 단계의 정상 COMMITTED chain. TRUE/HOLD/FALSE는 미리 정한 전문 결과 fixture이고 runtime이 직접 판정하지 않음. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: 동일 R1/W1/C1, 각 가설 Hn/generation Gn/work Kn/attempt An/고정 input hash IHn. schema/profile과 case별 장애 지점은 아래 연결된 REC card를 따름. 자세한 정상 graph는 F-STA/F-HYP/F-VER/F-DYN/F-GAT/F-CHN/F-REP/F-BUD(#106 §2.3).
- **4. 저장된 record·artifact·marker**: Primitive/index/match/child 여부가 장애 시점별 다름.
- **5. 정확한 장애 주입 지점**: FLW-006/007 중단 후 TRUE+HOLD match/child를 등록. 별도 HOLD 빈 후보 fixture.
- **6. 재시작 검사 조건**: nonempty required 후보·admission·계보·중복 key·등록 전후 검사.
- **7. 복구 조치**: 유효 match/child 한 개만 재사용/등록하고 새 child 전체 검증. 최초 체이닝은 `lineage_results=[]`를 허용하고 CHAINING-origin 조상이 있으면 계산한 exact lineage closure 누락·추가를 거절한다.
- **8. 기대 state·current/격리 결과**: 부모 판정 불변, child 독립; 빈 HOLD는 work 없이 종료. PR 입력 계약 미해결이면 관련 실행은 미구현/차단으로 보고.
- **9. 다음 단계 호출**: lineage 확인 전 child Context/검증 금지.
- **10. 기대 오류·관측 log**: STALE_RESULT/중복 구현 오류; 정상 no-match와 구분. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음. 적용 기준: 선행 REC card와 R3-06 §10.7.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R5·R6·R7·R8, 연결 경로 R1·R2. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-E2E-009 — Rule Scope DENY·Finding-only 종료

- **1. ID·단계·work**: R3-REC-E2E-009; 1–22 (분기별 해당 경로); fixture가 선택한 전체 run의 work 집합. CT 연결: GAT-007/008, REP-002/005.
- **2. 중단 전 상태·current**: E2E 기준(§3.3): 새 run R1에서 시작. 중간 장애 전까지는 각 단계의 정상 COMMITTED chain. TRUE/HOLD/FALSE는 미리 정한 전문 결과 fixture이고 runtime이 직접 판정하지 않음. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: 동일 R1/W1/C1, 각 가설 Hn/generation Gn/work Kn/attempt An/고정 input hash IHn. schema/profile과 case별 장애 지점은 아래 연결된 REC card를 따름. 자세한 정상 graph는 F-STA/F-HYP/F-VER/F-DYN/F-GAT/F-CHN/F-REP/F-BUD(#106 §2.3).
- **4. 저장된 record·artifact·marker**: 유효 current TRUE/CWE/Technical/RuleScope와 Finding normalization journal.
- **5. 정확한 장애 주입 지점**: RuleScope report_permission=DENY 정상 검토 뒤 Finding/index 저장 중 종료한다.
- **6. 재시작 검사 조건**: Finding eligibility와 Reporter 6축의 독립성.
- **7. 복구 조치**: Finding commit/index 복구; Reporter 호출 차단 이유를 보존하고 전체 work 정리.
- **8. 기대 state·current/격리 결과**: current Finding 유지, report_draft_refs=[]로 적법 종료 가능. DENY는 기술 FALSE가 아님.
- **9. 다음 단계 호출**: Reporter/외부 공개 호출 없음.
- **10. 기대 오류·관측 log**: 실제 보고 시도에는 REPORT_NOT_READY; DENY 자체 실행 오류 아님. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음. 적용 기준: 선행 REC card와 R3-06 §10.7.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R5·R6·R7·R8, 연결 경로 R1·R2. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

#### R3-REC-E2E-010 — 보고서 확정·자동화 종료 후 중복 재시작

- **1. ID·단계·work**: R3-REC-E2E-010; 1–22 (분기별 해당 경로); fixture가 선택한 전체 run의 work 집합. CT 연결: REP-001/003/004/005, COM-012.
- **2. 중단 전 상태·current**: E2E 기준(§3.3): 새 run R1에서 시작. 중간 장애 전까지는 각 단계의 정상 COMMITTED chain. TRUE/HOLD/FALSE는 미리 정한 전문 결과 fixture이고 runtime이 직접 판정하지 않음. 5번이 지정한 시작 지점이 우선한다.
- **3. work·attempt·generation·input**: 동일 R1/W1/C1, 각 가설 Hn/generation Gn/work Kn/attempt An/고정 input hash IHn. schema/profile과 case별 장애 지점은 아래 연결된 REC card를 따름. 자세한 정상 graph는 F-STA/F-HYP/F-VER/F-DYN/F-GAT/F-CHN/F-REP/F-BUD(#106 §2.3).
- **4. 저장된 record·artifact·marker**: ReportDraft와 run final commit/state pointer의 지점별 상태.
- **5. 정확한 장애 주입 지점**: FLW-009의 report/run 최종 marker 뒤 종료한 다음 startup recovery를 두 번 실행한다.
- **6. 재시작 검사 조건**: exact final binding·outstanding work 없음·current refs·config set.
- **7. 복구 조치**: 동일 확정 기록만 재투영; 완료 run의 Agent pipeline을 다시 시작하지 않음.
- **8. 기대 state·current/격리 결과**: report/run 결과 개수·현재 refs 불변, 추가 LLM/Sandbox 호출 0건. 실제 공개는 시스템 밖 사람 절차.
- **9. 다음 단계 호출**: 자동화 종료; 공개/제출 자동 action 없음.
- **10. 기대 오류·관측 log**: 불일치면 RECOVERY_FAILED, 정상은 새 오류 없음. 복구 전후 exact refs·journal·검사 사유를 안전한 trace에 연결한다. secret/없는 관측은 기록하지 않는다.
- **11. R8 예산·시간·비용**: §3.4의 고정 profile·잔여 시간/비용/work/새 attempt 한도 적용. 재투영은 새 실행이 아니며 usage·elapsed 중복 집계 금지. token 계획값/미제공 usage만으로 중단하지 않음. 적용 기준: 선행 REC card와 R3-06 §10.7.
- **12. 구현자·필수 리뷰**: R3 윤희섭 @YHS-Sec. R4·R5·R6·R7·R8, 연결 경로 R1·R2. 계정·담당 의미는 §9. 실제 구현/교차 검토 미완료.

## 7. 실제 시험 구현 계획과 증거 형식

### 7.1 안전한 장애 주입 경계

아직 실행 코드는 없다. 이후 구현 시 다음 조건을 지킨다.

- 기본은 fake adapter/fake storage/fake clock의 반환값과 checkpoint hook으로 장애를 주입한다. 실제 사용자 프로그램이나 운영 DB를 종료하지 않는다.
- 프로세스 crash 시험이 필요하면 테스트가 직접 시작한 child process와 테스트 전용 data directory만 대상으로 한다. 종료 PID·절대 경로가 해당 테스트 소유인지 확인한다.
- Sandbox 시험은 승인된 테스트 image/network/resource profile과 disposable 자원만 사용한다. host Docker socket·운영 secret·범위 밖 egress는 시험을 위해서도 허용하지 않는다.
- cleanup은 테스트 자원 manifest의 exact ID만 대상으로 한다. 전체 container/image/volume 삭제나 사용자 폴더 정리는 하지 않는다.
- 실제 provider 로그인·과금 호출·설치·외부 서비스 요청은 fake 시험과 별도로 계획하고 계정·권한·지원 경로를 확인한다. 이 문서 작성이 해당 작업 실행 승인은 아니다.

### 7.2 구현 순서 제안

1. R4와 #106의 fixture·Q 항목, 본 문서 RQ 항목을 맞춘다.
2. #92가 실제 저장 방식·durability·migration·실행 진입점을 확정하면 checkpoint를 실제 함수/transaction 경계에 연결한다.
3. 정상 fixture의 schema/reference 검사를 먼저 실행한다. 부정 fixture를 만들기 전 정상 fixture가 원래 유효해야 한다.
4. STO/WRK부터 deterministic fault-injection harness를 만든다. 명시적 순서 barrier를 사용하여 재현 가능한 경합을 만들고 임의 sleep만으로 race 통과를 주장하지 않는다.
5. LLM/DYN/FLW를 연결하고, replay를 두 번 이상 적용해 결과·외부 호출·usage가 중복되지 않는지 확인한다.
6. E2E-001~010의 각 variant를 fake 환경에서 실행한다.
7. Git·정적 도구·DB·filesystem·Docker·실제 Provider는 선택된 환경별 별도 capability 시험을 수행한다.
8. runtime 구현 SHA·문서 SHA·fixture/schema/profile refs와 관찰 결과를 함께 남긴다.

### 7.3 실행 결과표 템플릿

다음 표는 **아직 비어 있는 기록 형식**이다. 실행하지 않은 case를 PASS로 채우지 않는다.

| 필드 | 실행 후 기록할 값 |
|---|---|
| scenario/variant | R3-REC ID + 실제 장애 지점/입력 변형 이름 |
| source baseline | runtime commit, 본 문서 commit, #106 또는 후속 계약 commit |
| environment | fake/실제 구분, OS·DB/filesystem·도구/provider version 및 지원 판정 |
| exact fixture manifest | analysis/workspace/commit/hypothesis/generation/work/attempt·record/hash·profile refs |
| fault evidence | checkpoint 도달·durable ACK·프로세스 종료/예외 증거 |
| before/after | authoritative marker, work 상태, 전문 pointer, current/격리 결과 집합 |
| outbound calls | provider/tool/Sandbox 호출 전후 횟수, 각 call/action refs |
| accounting | 실행 elapsed·대기·process off·실측 usage 및 unknown/null 구분 |
| outcome | PASS/FAIL/SKIPPED/BLOCKED + 기대값과 관찰값 차이 |
| evidence | 안전한 log/artifact 경로와 content hash, secret 없음 |
| review | 담당 검토자·검토 SHA·미해결 사항 |

외부 호출이 실제로 실행됐는지 모르는 상태에서는 ‘정확히 한 번 실행 보장’을 선언하지 않는다. 알려진 COMMITTED 재투영의 무중복과 uncertain provider 요청 처리는 별개로 검증한다(RQ-04).

## 8. R3-06에서 확정한 복구 기준

`RQ-01`~`RQ-10`은 runtime enum이 아니라 복구 설계 항목을 추적하는 문서 ID다. 구현 기준은 [R3-06 §10.7](./06-implementation-baseline.md#107-r3-03-복구-질문의-확정-기준)과 아래 표로 확정하며, 각 역할 검토자는 자기 영역의 실제 구현 가능성과 기존 계약 보존 여부를 확인한다.

| 항목 | 상태 | 확정 기준 | 필수 검토 |
|---|---|---|---|
| RQ-01 저장 프로토콜·core output | `RESOLVED` | SQLite metadata transaction과 content-addressed artifact의 staging → hash → `PREPARED` → CAS → atomic rename → `COMMITTED` → current 재투영 순서를 사용한다. core result owner와 current 선택점은 R3-06 §10.2.1을 따른다. | R4, R2·R1·R8 |
| RQ-02 오류/거절 상태 매핑 | `RESOLVED` | R3-06 §8.4 우선순위로 근본 `AnalysisError.code` 하나를 선택하고 모든 실패 검사는 `ActionCheck`에 남긴다. 안전한 복구를 입증하지 못하면 `RECOVERY_FAILED`로 후속 소비를 막는다. | R4와 각 전문 owner |
| RQ-03 migration·rollback | `RESOLVED` | Alembic revision만 schema를 변경한다. pending·중단·revision 불일치 상태에서는 앱을 시작하지 않으며, 검증된 upgrade/downgrade만 실행한다. 의미 손실 rollback은 백업과 사람 승인 없이는 거절한다. | R3·R4·R8 |
| RQ-04 worker·외부 호출 불확실성 | `RESOLVED` | SQLite lease와 `state_version` CAS로 worker claim을 회수한다. 외부 전송 뒤 결과가 불명확하면 exact request ID의 공식 조회가 가능할 때만 재조정하고, 아니면 자동 재전송하지 않고 `RECOVERY_FAILED`와 `BLOCKED + waiting_for=INPUT`으로 명시적 결정을 기다린다. | R3·R4·R8, Provider는 R3-04 |
| RQ-05 취소 run·사용자 진입점 | `RESOLVED` | `resume`은 입력이 같은 non-terminal `BLOCKED` run만 대상으로 한다. terminal run은 되살리지 않고, 재실행은 새 `analysis_id`의 새 `run`으로 시작한다. | R3·R4·R8 |
| RQ-06 crash 중 시간·비용 | `RESOLVED` | durable heartbeat에 기록된 monotonic 실행 구간만 누적하고 process off·BLOCKED 대기는 제외한다. 미기록 구간과 provider 미제공 usage는 `null`과 사유로 남긴다. hard budget 잔여량을 입증하지 못하면 새 work를 시작하지 않는다. | R8·R4 |
| RQ-07 repair 저장 경계 | `RESOLVED` | invalid 응답과 validation error를 먼저 durable log에 남긴다. 각 repair는 새 `WorkAttempt`·`llm_call_id`·spec·action·decision·`NEW` session으로 실행하고, 성공 output 하나만 current로 확정한다. | R3·R4·R6·R1·R8 |
| RQ-08 Sandbox 재생성·cleanup | `RESOLVED` | 건강·소유 상태를 확인할 수 없으면 `STATE_UNCERTAIN`으로 새 environment binding을 만들고 기존 writable container를 재사용하지 않는다. 정확한 ownership label과 environment ref가 일치하는 자원만 멱등 정리하며, 실패 자원은 격리한다. | R7·R4·R8 |
| RQ-09 append 재전달 | `RESOLVED` | 같은 `event_id`와 canonical hash는 기존 ACK를 반환한다. 같은 ID/sequence의 다른 bytes는 `RECOVERY_FAILED`로 거절한다. finish가 없는 event에는 종료 사실을 만들어 넣지 않고 environment를 `STATE_UNCERTAIN`으로 처리한다. | R7·R4 |
| RQ-10 동적 입력 변경 후 후속 전이 | `RESOLVED` | 기존 dynamic work는 history로 종료한다. 같은 ACTIVE Verification owner가 CAS로 새 generation·VERIFICATION work·application·Pro/Con을 만들고, 필요할 때만 새 request와 dynamic work를 만든다. 과거 action·attempt·environment·PoC·CWE·Gate는 재사용하지 않는다. | R4·R6·R7·R1·R3 |

### 8.1 이미 해결된 내용과 구분

- Finding 생산과 저장 권한은 main B2에서 확정됐다. **다시 미결정으로 돌리지 않는다.** RECOVERY는 승인된 service/journal을 복구하며 다른 producer로 새 Finding을 만들지 않는다.
- HOLD 빈 후보는 Primitive/Chaining work가 없는 정상 종료다.
- policy COLLECTION_FAILED는 ABSENT_CONFIRMED가 아니다. 전자는 RuleScope/Finding 없음, 후자는 current review에 따른 Finding 정규화 가능·Reporter DENY다.
- match 중복 키는 분석 scope의 (upstream_result_ref, downstream_input_ref, matched_input_id)다. 예전 fingerprint 문구를 그대로 사용하지 않는다.
- Primitive admission은 등록 시점의 1회 판정이다. Chaining 시작 뒤 index revision이 증가해도 고정한 후보에는 영향이 없고, 등록된 Primitive·자식을 사후 판정으로 회수하지 않는다.
- 최초 Chaining의 `lineage_results`는 빈 목록을 허용하고, CHAINING-origin 조상이 있는 경우에만 계산한 exact lineage closure를 요구하도록 병합된 #97 최종 HEAD `fbf0236`에서 정리됐다. Primitive admission은 등록 시점의 1회 판정이므로 Chaining Prompt 입력에 넣거나 다시 판정하지 않는다.
- 위 RQ 기준은 문서상 확정됐지만 실제 runtime·migration·Provider·Sandbox 시험은 아직 수행하지 않았다. 문서 확정과 구현·실행 PASS를 혼동하지 않는다.

## 9. 역할별 검토·완료 조건

| 역할 | 계정 | 필수 검토 범위 |
|---|---|---|
| R4 공통 상태·복구 | @taehyeon-git | STO/WRK, 모든 CAS/journal/권한/current·오류/RQ 경계 |
| R5 CWE·Gate·Reporter | @kimhr8463 | FLW-003/005/008/009, E2E-007/009/010 |
| R6 Verification·ProCon | @UltraPeachKeen | LLM-004/005, DYN 결과 소비, FLW-002/004, final 미생성/REVISE |
| R7 Sandbox | @Potatonion | DYN 전체, AgentLog·PoC·재생성·cleanup, RQ-08/09 |
| R8 예산·관측 | @gitterable | WRK-006, retry 소진·usage·clock·fake/실제 평가 분리 |
| R1 탐색·Chaining (해당 범위 추가) | @baeseungwon1010 | WRK-007, FLW-006/007, E2E-008 |
| R2 정적·Context (해당 범위 추가) | @zv9uvr | STO-007, FLW-001/007, workspace/정적 합류/Context 경계 |

검토 기록에는 문서 SHA·case ID·확인한 의미·남은 질문을 적는다. 자동 검사나 작성자의 자기 점검은 전문 owner 승인을 대신하지 않는다.

### 문서 초안 작성 상태

- [x] main 기준 22단계 coverage와 #106 test ID/fixture 연결
- [x] 일반 retry·Dynamic Reproduction Agent session 조정/재시작/RESUME·새 generation·REVISE·새 가설 구분
- [x] 장애 card 43개 + 최소 E2E card 10개 작성
- [x] case별 12개 필수 항목과 상태·current/격리·후속 호출 기준 작성
- [x] fake 장애 주입과 실제 dependency 시험 분리
- [x] 저장/오류/복구 질문을 RQ 항목으로 분리하고 R3-06 §10.7에서 구현 기준 확정
- [x] 병합된 #106 최종 HEAD `0e2e7fe` 기준으로 의존 ID/fixture 재대조
- [x] 병합된 #97 최종 HEAD `fbf0236` 기준으로 역할명·Prompt lineage·Sandbox tool-loop 재대조
- [ ] R4·R5·R6·R7·R8 및 영향받는 R1/R2 검토 기록 확보
- [x] 구현을 막는 RQ 항목의 exact 기대값·저장 경계 확정
- [x] PR #107 병합 commit `35729d3` 기준 정합성 재확인

체크된 항목은 문서 작성 여부일 뿐 실행 시험 통과가 아니다. 실제 fixture·runtime·Recovery code·migration·자동 시험·실제 Provider/Sandbox 검증은 아직 구현/수행하지 않았다. 이 PR을 만들었다는 이유로 #89나 상위 #4를 바로 닫지 않는다.

## 10. 발표·상태 보고용 요약

세부 장애·복구 card 43개와 전체 흐름 E2E card 10개를 계획으로 정리했다. 저장 준비 상태의 결과는 다음 단계에 넘기지 않고, 이미 확정된 기록은 같은 기록으로 상태를 복원하도록 검사 지점을 정했다. 저장·오류·불확실 실행의 구현 기준은 R3-06에서 확정했지만, 실제 복구 프로그램·자동 테스트·Provider/Sandbox 시험과 역할별 검토는 아직 남아 있다.
