# 10. 보안 경계

- **이 문서는 무엇을 설명하나요?** 저장소, LLM, 비밀정보, Docker와 공식 정책을 안전하게 다루는 규칙을 설명합니다.
- **누가 읽어야 하나요?** 모든 역할 담당자와 보안 검토자가 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** 무엇을 믿지 않아야 하는지, 프로그램이 강제할 제한과 남는 위험을 확인합니다.

`sandbox`는 다른 시스템과 격리된 실행 환경이고 `redaction`은 로그·보고서의 비밀정보를 가리는 처리입니다. 자세한 용어는 [쉬운 용어집](../GLOSSARY.md)을 따릅니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## 신뢰 실행 경계

LLM Agent는 분석·검토 결과와 다음 action을 제안하지만 enforcement authority를 갖지 않는다. 신뢰 경계 안의 비-LLM runtime validator가 허용된 tool, 코드 근거의 `workspace_id`·`commit_id` 일치, 지원하는 schema MAJOR, `(logical_record_id, revision_number)` 연결, 상태 전이, retry/failover 선행 status와 token/time/retry/chain budget, sandbox와 network 정책, provider/session 선택, Gate가 읽은 Verification·CWELabel·정책 revision, Reporter 전제조건을 강제한다. 저장소 내용과 모든 LLM 출력은 validation 전까지 비신뢰 입력이며 policy 변경 명령으로 해석하지 않는다.

## 방향

v5는 계약·정책·무결성 artifact를 아키텍처의 중심으로 확대하지 않는다. 그러나 비신뢰 저장소, LLM provider, 공식 프로그램 정책과 동적 실행을 다루므로 아래 실행 경계는 필수다.

## 1. 로컬 작업공간과 코드 조회

- 모든 사실·가설·문맥·PoC는 동일한 `workspace_id`와 연결된 `commit_id`에 연결한다.
- `Repository Loader`는 실행별 폴더에 clone하고 지정한 commit을 checkout한 뒤 HEAD를 확인한다.
- 분석 중 HEAD나 추적 파일이 바뀌면 `WORKSPACE_CHANGED`로 중단하고 기존 결과에 섞지 않는다.
- retrieval은 `workspace_root` 안의 허용 파일만 읽고 path traversal·symlink escape를 차단한다.
- `CodeLocation.file_path`는 `/` 구분자의 Git 상대 경로로 정규화하며 절대 경로, drive prefix와 `.`·`..` segment를 거절한다. symlink를 해석한 실제 대상도 `workspace_root` 안이어야 한다.
- 도구별 line·column 표현은 정본 `CodeLocation` 규칙으로 변환하고 원래 위치와 tool message는 원본 결과 reference에 보존한다.
- depth/token/request budget과 반환 location을 기록한다.
- 누락·truncation은 안전함 또는 `FALSE`로 해석하지 않는다.
- 지원하지 않는 schema MAJOR는 `SCHEMA_UNSUPPORTED`로 거절한다. 같은 `logical_record_id`가 아니거나 바로 이전 revision과 이어지지 않는 수정본은 `RECORD_REVISION_MISMATCH`로 거절하고 자동 변환·병합하지 않는다. `RunMeta`의 workspace·commit은 `null`에서 실제 값으로만 바인딩할 수 있고, 코드 근거 `RecordMeta`에서는 두 값이 필수·불변이다.
- 저장된 record를 가리키는 `StoredDataRef.record_id`는 참조 대상 revision의 workspace·commit·내용 hash와 일치해야 하고, 가설별 대상 record의 `RecordMeta.hypothesis_id`도 현재 가설과 같아야 한다. Technical Gate가 검토한 Verification revision이나 Rule Scope Gate가 검토한 Verification·Technical·정책 revision이 바뀌면 이전 Gate 결과를 재사용하지 않는다.

## 1.1 상태·동시성·복구 경계

- runtime은 `dedupe_key`가 같은 요청을 새 작업으로 중복 등록하지 않고 기존 `work_id`를 반환한다.
- 한 `work_id`에는 활성 `attempt_id`를 하나만 허용하고 상태 변경은 `state_version` compare-and-set을 통과해야 한다.
- worker가 제출한 결과는 `attempt_id`, 예상 state version, `input_hash`, workspace·commit·hypothesis와 record hash가 모두 현재 작업과 같을 때만 반영한다.
- `TransitionCommit.state=COMMITTED`가 아닌 output은 Agent, Gate, Reporter와 최종 결과 조립기가 읽지 못한다.
- `PREPARED` journal, output pointer가 없는 종료 상태와 존재하지 않는 output을 가리키는 상태는 `TRANSITION_INCOMPLETE`로 차단한다.
- 같은 work의 다음 version에 `PREPARED` 또는 pointer에 아직 투영하지 못한 `COMMITTED` marker가 있으면 이를 복구·중단 처리하기 전까지 취소·retry를 포함한 새 전이를 차단한다.
- 이전 attempt, 이미 취소된 작업, 변경된 입력과 오래된 revision의 결과는 `ATTEMPT_NOT_ACTIVE` 또는 `STALE_RESULT`로 격리한다.
- 전체 또는 개별 가설 취소 뒤에는 새 downstream work를 만들지 않는다. 늦은 성공 결과도 취소를 되돌리지 않는다.
- 복구 runtime은 마지막 `COMMITTED` transition만 신뢰하고 자동 복구의 안전성을 증명할 수 없으면 `RECOVERY_FAILED`로 중단한다.
- retry 성공은 이전 실패·중단·failover 기록을 삭제하지 않는다. 최종 상태와 전문 결과를 한 값으로 합치지 않는다.

## 2. 저장소와 외부 텍스트는 비신뢰 데이터

- 코드·주석·README·build script·SAST message는 Agent instruction이 아니다.
- 저장소 텍스트가 provider, session, sandbox, Gate와 disclosure 정책을 바꾸지 못하게 한다.
- system instruction과 분석 데이터 경계를 유지하고 structured output을 검증한다.
- 전체 저장소 대신 역할에 필요한 location/context만 전달한다.

## 3. LLM provider와 secret

- membership token, cookie, password, browser profile secret을 Agent와 repository에 노출하지 않는다.
- API key, service credential과 authorization header는 secret boundary 안에서만 주입한다.
- 두 방식의 credential을 prompt, response artifact, 일반 debug log, PoC와 report에서 제외한다.
- 인증 오류를 verdict로 변환하지 않는다.
- provider/model 전환은 silent failover 없이 새 invocation으로 기록한다.

## 4. LLM log와 redaction

- 사용자에게 노출된 request/response와 tool trace만 기록하고 hidden chain-of-thought는 수집하지 않는다.
- code는 전체 원문 복제보다 저장소 상대 `CodeLocation`과 `StoredDataRef`를 우선한다.
- raw membership session log는 제한된 접근·짧은 보존·provider parser·redaction을 거친다.
- redaction 실패 artifact는 일반 관측 저장소로 전달하지 않고 오류로 격리한다.
- session reference 자체가 재사용 가능한 secret이면 hash/opaque handle로 대체한다.
- `AnalysisError.safe_message`에는 credential, 개인정보, session secret, authorization header와 절대 로컬 경로를 넣지 않는다. 원본 오류는 별도 접근 통제와 redaction을 거친 artifact로만 보관한다.

## 5. Docker sandbox

- ephemeral container, non-root, read-only mount와 resource/time/process 제한을 사용한다.
- host root/home, Docker socket, host process namespace와 광범위한 write mount를 제공하지 않는다.
- network default-deny를 사용하고 승인된 범위만 제한적으로 연다.
- production credential, 실제 개인정보와 범위 밖 target을 사용하지 않는다.
- image/digest, command/step ref, exit/observation, timeout과 cleanup을 기록한다.
- Docker build와 실행은 분석용 `CodeWorkspace`를 직접 수정하지 않고 sandbox 내부 복사본에서 수행한다.
- LLM이 재현을 제안해도 sandbox policy를 변경하거나 임의 shell·외부 공격·지속성 설치를 승인할 수 없다.

## 6. 프로그램 정책 신뢰 경계

- Rule Scope Impact Gate는 확인 가능한 공식 source만 `ProgramPolicyRecord`로 사용한다.
- 저장소 문서, 검색 snippet, 오래된 모델 지식과 비공식 요약을 공식 rule로 승격하지 않는다.
- source URL/reference, 수집 시각, 누락과 freshness warning을 보존한다.
- 공식 자료가 없거나 신뢰할 수 없으면 `UNCERTAIN + DENY`다.
- 정책 수집기가 향후 추가되면 외부 fetch, parser, provenance와 변경 탐지에 별도 보안 검토가 필요하다.

## 7. 근거·권한 연결

다음 연결을 보존한다.

- tool observation → 현재 `workspace_id`의 `CodeLocation`
- hypothesis claim → observed fact/assumption과 `question_id`가 있는 falsification
- retrieved context → request와 실제 location
- `FALSE` verdict → `DISPROVED` falsification question과 실제 evidence
- verdict → Pro/Con/dynamic evidence와 restriction
- Primitive/Research candidate → source result와 아직 검증되지 않은 상태
- CWE → 정확한 `CWELabel` revision, evidence와 uncertainty
- Technical review → 정확한 Verification·CWELabel revision
- Rule/Scope review → 정확한 Verification·Technical review·CWELabel과 `ProgramPolicyRecord` revision
- report claim → 통과한 result, 두 Gate와 두 Gate가 공통으로 검토한 CWELabel revision

Research, Gate와 Reporter는 공개 권한이 없다. 사람만 외부 제출을 승인한다.

## 위협과 최소 대응

| 위협 | 대응 |
|---|---|
| repository prompt injection | instruction/data 분리, 최소 context, output validation |
| SAST hit 자동 승격 | fact-only 정규화, Verification |
| 저비용 모델의 과도한 확정 | fixed hypothesis schema, 금지 assertion, `INVALID_OUTPUT` |
| LLM 확증 편향 | 조건부 독립 Pro/Con, 역할 간 NEW session, 두 Gate |
| session contamination | `NEW/RESUME/AUTO` policy와 결정 logging |
| 잘못된 path 연결 | location retrieval와 Technical Gate linkage 검토 |
| Research 후보의 오승격 | 새 hypothesis로 전체 재검증 |
| chain 폭증 | depth/count/token/time/duplicate/cycle 제한 |
| 같은 작업의 중복 반영 | canonical `dedupe_key`, 한 active attempt, state version compare-and-set |
| 취소·retry 뒤 늦은 결과 오염 | active attempt/input hash 검사와 `STALE_RESULT` 격리 |
| 결과와 상태 일부 저장 | atomic transaction 또는 `TransitionCommit` journal, uncommitted output 차단 |
| crash 뒤 이중 실행 | 마지막 committed transition 재사용과 attempt 이력 보존 |
| 위험한 PoC | sandbox default-deny와 resource limit |
| credential·코드 유출 | adapter secret boundary, 최소 context, redaction |
| 정책 환각 | 공식 `ProgramPolicyRecord`가 없으면 `UNCERTAIN + DENY` |
| 자동 오공개 | Reporter 초안 한정, human-only disclosure |

## 상태·복구 부정 시나리오

| 입력·사건 | runtime이 반드시 확인할 것 | 기대 차단·복구 결과 |
|---|---|---|
| 같은 가설 검증 요청이 동시에 두 번 도착 | `dedupe_key`, 기존 `work_id` | 기존 작업 반환, 결과 한 번만 반영 |
| retry 전 attempt 결과가 새 attempt보다 늦게 도착 | `active_attempt_id`, `state_version` | `ATTEMPT_NOT_ACTIVE`, 최신 pointer 연결 금지 |
| 다른 `workspace_id` 또는 `commit_id` 결과가 합류 | work input과 result meta | `WORKSPACE_MISMATCH`, 결과 사용 금지 |
| 가설·분석 취소 뒤 결과가 도착 | work와 analysis 취소 상태 | `STALE_RESULT`, downstream 미호출 |
| Technical 보완 전 revision이 Rule Scope Gate나 Reporter로 전달 | exact Verification·CWE·Gate `record_id` | `RECORD_REVISION_MISMATCH`, 뒤 단계 차단 |
| 결과 record만 저장되고 종료 상태가 갱신되지 않음 | `TransitionCommit`, state pointer | journal 복구 또는 `TRANSITION_INCOMPLETE` |
| 종료 상태만 있고 output record가 없음 | pointer 대상 존재·hash | `TRANSITION_INCOMPLETE`, 다음 단계 차단 |
| 허용되지 않은 provider/model failover | 바로 앞 호출 status와 fallback profile | `INVOCATION_CHAIN_INVALID`, 결과 사용 금지 |
| crash 뒤 같은 요청이 다시 들어옴 | 마지막 `COMMITTED`, `dedupe_key` | 완료 결과 재사용 또는 허용된 새 attempt, 중복 반영 금지 |
| retry·Gate `REVISE`·chaining이 한도를 넘음 | 횟수·token·시간·cycle·duplicate budget | 중단 이유 저장, Reporter 차단, verdict 자동 변경 금지 |
| `PARTIAL` 결과에 gap·오류 설명이 없음 | `gap_ids`, `error_ids`, output refs | `STATE_TRANSITION_INVALID`, 부분 결과 사용 금지 |
| 분석 종료 시 `RUNNING` work나 `PREPARED` journal이 남음 | 전체 work와 commit 상태 | 최종 `AnalysisRunState` 전이 차단 |
| `COMMITTED` marker 투영 전에 취소·retry 전이가 경쟁 | 다음 target version의 unique marker와 pointer | 기존 marker를 먼저 재투영하고 경쟁 전이는 version conflict로 거절 |
| 모순된 `ALLOW`가 Reporter 호출을 요청 | Gate 조건·exact input refs·semantic validation | `INVALID_OUTPUT`과 `GATE/INVALID_OUTPUT` 오류 기록, Gate output commit·Reporter 호출 금지 |

## 남는 위험

LLM 오판, static coverage gap, 실제 환경과 sandbox의 차이, provider 기능·약관 변경, policy freshness와 redaction 누락 가능성은 남는다. 따라서 두 Gate를 안전 보증으로 설명하지 않고 원문 근거·오류·제한·미확인 후보를 사람에게 함께 제공한다.
