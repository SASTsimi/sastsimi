# 10. 보안 경계

- **이 문서는 무엇을 설명하나요?** 저장소, LLM, 비밀정보, Docker와 공식 정책을 안전하게 다루는 규칙을 설명합니다.
- **누가 읽어야 하나요?** 모든 역할 담당자와 보안 검토자가 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** 무엇을 믿지 않아야 하는지, 프로그램이 강제할 제한과 남는 위험을 확인합니다.

`sandbox`는 다른 시스템과 격리된 실행 환경이고 `redaction`은 로그·보고서의 비밀정보를 가리는 처리입니다. 자세한 용어는 [쉬운 용어집](../GLOSSARY.md)을 따릅니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## 신뢰 실행 경계

LLM Agent는 분석·검토 결과와 다음 action을 제안하지만 enforcement authority를 갖지 않는다. 신뢰 경계 안의 비-LLM runtime validator가 허용된 tool, 코드 근거의 `workspace_id`·`commit_id` 일치, 지원하는 schema MAJOR, `(logical_record_id, revision_number)` 연결, 상태 전이, token/time/retry/chain budget, sandbox와 network 정책, provider/session 선택, Gate 순서, Reporter 전제조건을 강제한다. 저장소 내용과 모든 LLM 출력은 validation 전까지 비신뢰 입력이며 policy 변경 명령으로 해석하지 않는다.

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
- CWE → evidence와 uncertainty
- Technical review → 정확한 Verification revision
- Rule/Scope review → 정확한 Verification·Technical review와 `ProgramPolicyRecord` revision
- report claim → 통과한 result와 두 Gate

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
| 위험한 PoC | sandbox default-deny와 resource limit |
| credential·코드 유출 | adapter secret boundary, 최소 context, redaction |
| 정책 환각 | 공식 `ProgramPolicyRecord`가 없으면 `UNCERTAIN + DENY` |
| 자동 오공개 | Reporter 초안 한정, human-only disclosure |

## 남는 위험

LLM 오판, static coverage gap, 실제 환경과 sandbox의 차이, provider 기능·약관 변경, policy freshness와 redaction 누락 가능성은 남는다. 따라서 두 Gate를 안전 보증으로 설명하지 않고 원문 근거·오류·제한·미확인 후보를 사람에게 함께 제공한다.
