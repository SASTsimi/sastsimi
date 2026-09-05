# SASTSIMI 쉬운 용어집

이 문서는 프로젝트 문서에서 자주 쓰는 기술 용어를 쉬운 말로 설명합니다. 데이터 이름과 상태값은 구현할 때 정확히 맞아야 하므로 영문 이름을 없애지 않고 쉬운 설명과 함께 사용합니다.

## 분석 흐름과 데이터

| 용어 | 쉽게 말하면 | 사용할 때 주의할 점 |
|---|---|---|
| `candidate baseline` | 아직 승인되지 않은 설계 초안 | 최종 설계나 구현 완료 상태로 부르지 않습니다. |
| `contract` | 파트 사이의 입출력 약속 | 어떤 데이터를 누가 만들고 누가 받는지 포함합니다. |
| `Repository Loader` | 저장소를 로컬로 가져오고 분석할 commit을 준비하는 프로그램 | 별도 저장소 복사본을 만들지 않습니다. |
| `CodeWorkspace` | AST와 SAST가 읽는 실행별 로컬 코드 폴더 | `workspace_id`와 `commit_id`로 구분합니다. |
| `ProgramPolicyRecord` | 공식 버그바운티 정책을 확인해 남긴 기록 | 저장소 코드 복사본이 아니며 공식 출처와 수집 시각을 기록합니다. |
| `freshness_status` | 정책을 현재 자료로 믿을 수 있는지 나타내는 상태 | `STALE` 또는 `UNVERIFIED`이면 보고 허용에 쓰지 않고 `UNCERTAIN + DENY`로 처리합니다. |
| `handoff_readiness` | Technical Gate 결과를 다음 단계에 전달해도 되는지 나타내는 값 | `ACCEPT`일 때만 `READY`이며 `REVISE | REJECT`는 `NOT_READY`입니다. |
| `StoredDataRef` | 도구가 만든 결과 파일이나 기록을 가리키는 번호 | 내부 저장 경로 대신 결과 번호와 내용 hash를 사용합니다. 저장된 결과 수정본을 가리킬 때는 `record_id`도 넣습니다. |
| `RecordMeta` | 결과마다 붙는 공통 식별 정보 | 분석·작업공간·가설·재시도·수정본을 연결합니다. |
| `RunMeta` | 코드 준비 전에도 쓸 수 있는 분석 실행 식별 정보 | `analysis_id`로 실행을 추적하며 clone 성공 전에는 workspace·commit을 요구하지 않습니다. |
| `AnalysisRunState.purpose` | 분석 실행이 실제 결과를 만드는 운영인지 방식 비교를 위한 평가인지 표시 | `PRODUCTION`은 운영, `EVALUATION`은 격리 평가이며 실행 중 바꾸지 않습니다. |
| `RunStoredDataRef` | commit 준비 전에도 생기는 실행 로그·결과 참조 | `analysis_id`로 찾고 저장 record의 정확한 수정본이면 `record_id`도 넣습니다. 코드 근거에는 쓰지 않습니다. |
| `CodeLocation` | 저장소 안의 파일과 줄·열 위치 | `/` 구분자의 저장소 상대 경로를 사용하고, 도구가 열을 모르면 임의 값 대신 `null`로 둡니다. |
| `CodeSymbol` | 함수·클래스·변수처럼 분석 대상이 되는 코드 요소 | 이름뿐 아니라 `CodeLocation`과 연결합니다. |
| `DataGap` | 분석하지 못했거나 정보가 부족한 범위 | 안전함이나 `FALSE`를 뜻하지 않습니다. |
| `AnalysisError` | 실행 중 발생한 오류 기록 | 오류 단계, 코드, 재시도 가능 여부와 비밀정보를 제거한 `safe_message`를 남깁니다. |
| `created_at` | 결과를 처음 저장한 UTC 시각 | 수정본이 생겨도 이전 결과의 시각을 바꾸지 않습니다. |
| `schema_version` | 데이터 형식의 버전 | 지원하지 않는 큰 버전은 추정해서 읽지 않습니다. |
| `revision_number` | 같은 논리 결과의 수정 순서 | 기존 결과를 덮어쓰지 않고 1부터 증가시킵니다. |
| `logical_record_id` | 같은 결과의 여러 수정본을 묶는 번호 | 수정해도 유지하며 `(logical_record_id, revision_number)`로 한 수정본을 찾습니다. |
| `record` | 정해진 형식의 데이터 묶음 | 필드명은 구현에서 정확히 유지합니다. |
| `entity` | 함수·클래스·변수처럼 분석 대상이 되는 코드 요소 | 이름뿐 아니라 실제 코드 위치와 연결합니다. |
| `source` | 외부 입력이 시작되는 곳 | 사용자 입력, 요청 값, 파일 값 등이 될 수 있습니다. |
| `sink` | 위험한 동작이 실행될 수 있는 곳 | 명령 실행, DB 질의, 응답 출력 등이 될 수 있습니다. |
| **Sanitizer candidate** | 위험할 수 있는 입력을 바꾸거나 정리하는 코드 후보 | 실제 공격 값을 안전하게 만드는지는 경로·순서·우회 가능성을 검증해야 합니다. |
| **Validator candidate** | 입력이나 상태를 조건에 따라 허용·거절하는 코드 후보 | 후보가 존재한다는 이유만으로 안전 또는 `FALSE`로 판정하지 않습니다. |
| `StaticFactBundle` | AST와 SAST가 찾은 코드 사실을 한데 모은 데이터 묶음 | 취약점 최종 판정이 아니라 LLM이 검토할 자료입니다. |
| `RuleExecutionRecord` | SAST가 어떤 규칙을 선택하고 실제 실행했는지 남긴 기록 | 실행 0건, 미실행, 확인 불가를 구분하고 정확한 도구 시도와 연결합니다. |
| `hit_count` | 한 규칙이 raw 도구 결과에서 만든 탐지 수 | `EXECUTED`일 때만 0 이상의 값을 쓰며 0은 미실행이 아닙니다. |
| `retrieval` | 필요한 코드만 위치를 기준으로 다시 가져오는 작업 | 저장소 전체를 무제한으로 보내지 않습니다. |
| `context` | 판단에 필요한 주변 코드와 관련 정보 | 원본 위치와 조회 범위를 함께 기록합니다. |
| `schema` | 데이터에 어떤 항목이 있어야 하는지 정한 형식 | 형식에 맞지 않는 LLM 출력은 그대로 사용하지 않습니다. |
| `state transition` | 작업 상태가 다음 상태로 바뀌는 규칙 | 허용된 순서와 실패 상태를 프로그램이 검사합니다. |
| `work_id` | 같은 논리 작업을 처음부터 끝까지 묶는 번호 | retry해도 유지하며 입력 revision이 달라지면 새 번호를 만듭니다. |
| `work_generation` | 같은 입력의 작업을 사람이 새로 다시 시작한 순서 | 일반 retry에는 바꾸지 않고 종료 뒤 명시적으로 restart할 때만 증가합니다. |
| `dedupe_key` | 같은 요청이 이미 들어왔는지 확인하는 hash 값 | attempt·시각은 빼고 실제 입력 record와 설정으로 만듭니다. |
| `state_version` | 작업 상태가 몇 번 바뀌었는지 나타내는 번호 | 동시에 들어온 오래된 상태 변경을 거절하는 데 사용합니다. |
| `atomic transition` | 결과와 그 결과를 가리키는 종료 상태를 함께 확정하는 저장 | 한쪽만 저장되면 다음 단계를 호출하지 않습니다. |
| `TransitionCommit` | 한 번에 저장하기 어려울 때 결과와 상태를 안전하게 묶는 기록 | `COMMITTED` 전의 결과는 다른 단계가 사용하지 않습니다. |
| `stale result` | 취소·재시도·입력 변경 뒤 늦게 도착한 오래된 결과 | 최신 결과를 덮어쓰지 못하게 격리합니다. |
| `crash-resume` | 프로그램 중단 뒤 마지막으로 확정 저장한 지점에서 다시 시작하는 절차 | 이미 끝난 작업을 중복 반영하지 않습니다. |
| `ActionRequest` | Agent나 service가 프로그램에 “이 일을 실행해 달라”고 적는 요청 | 요청 자체에는 실행 권한이 없습니다. |
| `ActionCheck` | 실행 전에 확인하는 권한·상태·예산·도구 같은 검사 하나 | action마다 필요한 검사를 빠뜨리지 않습니다. |
| `ActionDecision` | 프로그램 검사기가 action을 허용하거나 막은 결과 | 요청 하나당 logical decision 하나이며 exact action과 state version에 한 번만 사용합니다. |
| `LLMCallSpec` | 실제 LLM 호출에 쓸 model·prompt·context·형식·예산·시간을 묶은 수정 불가 명세 | 허가 뒤 호출 내용을 바꾸지 못하게 합니다. |

## 가설과 검증

| 용어 | 쉽게 말하면 | 사용할 때 주의할 점 |
|---|---|---|
| `Hypothesis` | 검증이 필요한 취약점 가능성 | 아직 확정 취약점이나 Finding이 아닙니다. |
| `HypothesisDuplicateReview` | 새 가설 제안이 기존 등록 가설과 같은지 LLM이 비교해 남긴 결과 | 프로그램이 먼저 좁힌 exact 후보만 비교하며, 애매하거나 검토에 실패하면 탐지 누락을 막기 위해 새 가설로 등록합니다. |
| `Verification` | 배정된 가설 안에서 코드·찬반·동적 근거와 보완 흐름을 관리해 판정하는 과정 | 다음 작업은 선택하지만 Runtime Validator의 실행 검사를 우회하거나 공개를 결정하지 않습니다. |
| `VerificationPlaybook` | 취약점 유형별로 빠뜨리지 말아야 할 확인 항목과 반증 질문을 묶은 수정 가능한 절차 | 플레이북이 등록됐다는 이유만으로 운영 지원 유형이 되지는 않습니다. |
| `PlaybookPolicy` | 운영에서 허용한 취약점 유형과 사용할 정확한 플레이북 수정본을 연결한 사람 승인 설정 | R6가 플레이북을 작성해도 이 정책 없이는 유형별 플레이북을 자동 활성화하지 않습니다. |
| `PlaybookApplication` | 이번 Verification 작업에 어떤 policy·playbook·질문 ID를 적용했는지 고정한 기록 | retry에서는 그대로 사용하고 새 work나 generation에서는 새 기록과 질문 ID를 만듭니다. |
| `verdict` | 검증 Agent가 내린 기술 판정 | `TRUE`, `FALSE`, `HOLD` 중 하나입니다. |
| `TRUE` | 코드·찬반 근거와 실제 PoC 재현으로 취약점이 성립한다고 판단한 상태 | 모든 final TRUE에는 현재 검증 차수의 validated PoC가 필요하며 사람의 공개 결정과는 다릅니다. |
| `FALSE` | 미리 정한 반증 조건이 실제 근거로 확인된 상태 | 도구 실패나 정보 부족을 `FALSE`로 바꾸면 안 됩니다. |
| `HOLD` | 필요한 정보나 조건이 부족해 판단을 보류한 상태 | 무엇이 부족한지 함께 기록합니다. |
| `Restriction` | 공격을 막거나 제한하는 조건과 실제 코드·검증 근거를 함께 담은 객체 | `restriction_id`와 exact reference를 Verification·Primitive·Chaining·ReportDraft에서 그대로 보존합니다. |
| `capability` | 다른 공격에 필요한 권한이나 접근 능력 | 검증된 범위 안에서만 연계 가능성을 확인합니다. |
| `falsification` | 확인되면 가설이 틀렸다고 볼 수 있는 구체적 질문 | 각 질문에 `question_id`를 붙이고 실제 근거가 있는 `DISPROVED` 결과가 있어야 `FALSE`가 됩니다. |
| `hypothesis_outcome` | Docker 관측이 가설을 지지·반증하는지 또는 결론을 주지 못하는지 표시 | `SUPPORTED`, `DISPROVED`, `INCONCLUSIVE` 중 하나이며 최종 verdict는 아닙니다. |
| `Pro / Con` | 가설에 찬성하는 근거와 반대하는 근거 | 서로의 결론을 보지 않는 독립 실행을 기본으로 합니다. |
| `debate` | 찬성·반대 근거를 따로 모아 비교하는 검증 방법 | 운영에서는 모든 유효 가설에 Pro/Con을 실행합니다. BASIC·조건부 방식은 격리 평가에서만 사용합니다. |
| `EvidenceClaim` | 주장 하나와 그 주장을 확인할 실제 근거·코드 위치를 묶은 데이터 | 근거가 없는 설명을 찬성·반대 근거로 저장하지 않습니다. |
| `EvidenceAgentResult` | Pro 또는 Con 한쪽이 만든 독립 근거 결과 | 부모 Verification, 역할별 작업·호출, 공통 입력 기준과 연결합니다. |
| `debate_input_hash` | Pro와 Con이 같은 공통 검증 입력을 받았는지 비교하는 값 | 역할별 지시문은 달라도 가설·코드 사실·플레이북·설정·예산 기준은 같아야 합니다. |
| `parent_work_ref` | 현재 작업을 만든 직접 부모 작업의 정확한 수정본을 가리키는 값 | Pro/Con child work에서는 현재 Verification work를 가리킵니다. |
| `CROSS_ROLE_INPUT_DENIED` | Pro와 Con 사이에 서로의 결과가 입력으로 넘어가 차단됐다는 오류 | 새 대화만 분리하는 것이 아니라 prompt·조회·도구 결과까지 분리합니다. |
| `CandidateRef` | 아직 검증되지 않은 우회·대체 경로·영향 확대 후보 | 새 공격 주장이면 별도 가설로 검증하기 전까지 확정 사실로 쓰지 않습니다. |
| `VerificationMetrics` | 검증에 사용한 token·시간과 판정 변화 기록 | provider가 알려 주지 않은 token을 임의로 추정하지 않습니다. |
| `PoC` | 취약점이 어떻게 재현되는지 보여 주는 절차와 증거 | 승인된 격리 환경에서 만든 자료만 사용합니다. |
| `DynamicReproductionRequest` | R6가 R7에 무엇을 왜 재현할지 전달하는 요청 | `POC_CONFIRMATION`은 initial TRUE 확인, `VERDICT_EVIDENCE`는 최종 판정에 필요한 실행 근거 확보입니다. |
| `poc_candidate_ref` | R7 Agent가 작성했거나 실행을 시도한 PoC 초안 번호 | 실패한 시도에도 남을 수 있으며 검증된 PoC가 아닙니다. |
| `poc_ref` | 실제 실행에 성공해 가설을 지지한 validated PoC 번호 | 같은 attempt의 AgentLog가 exact candidate와 digest 실행을 입증할 때만 생기며 모든 final TRUE에 필수입니다. |
| `agent_invoked` | 외부 경계 승인을 받은 뒤 Sandbox 안의 R7 Agent 실행 단계가 실제로 시작됐는지 나타내는 값 | 사전 requirements·plan 작성 호출과 구분하며 AgentLog의 `AGENT_STARTED` event와 반드시 일치해야 합니다. |
| `AgentLog` | R7 Agent·도구·환경 구성 과정에서 실제로 일어난 일을 순서대로 남긴 기록 | 비-LLM Session Manager가 append-only로 저장해 이전 event를 지우거나 다른 attempt와 섞지 않습니다. |
| `EnvironmentRecipe` | Docker 실행 환경을 다시 만들 수 있는 불변 build 방법 | 시작 image digest와 실제 완성 image digest를 구분하고 저장소가 선언한 의존성을 우선합니다. |
| `EnvironmentRequirements` | R7이 R6 요청을 실제 환경 구성·검사 항목으로 구체화한 조건 묶음 | 역할·인증 방식·데이터·DB/service·fixture/mock·버전·Health Check를 근거와 함께 기록합니다. |
| `environment_requirements_ref` | ReproductionPlan과 recipe가 사용하는 정확한 환경 요구사항 수정본 번호 | 오래된 수정본이나 다른 attempt의 요구사항을 재사용하지 않습니다. |
| `EnvironmentCheck` | R7이 요구사항 하나와 실제 환경을 비교한 결과 | `MATCH`, `MISMATCH`, `NOT_CHECKED`, `ERROR` 중 하나와 실제 값·차이·근거를 남깁니다. |
| `sandbox_profile_ref` | R7이 소유·확정하는 Sandbox의 host·Docker·mount·namespace·secret·egress·workspace 외부 접근·격리와 CPU·RAM·disk·PID·요청 가능 최대 시간 정책 번호 (`data_kind=sandbox_profile`) | R8 호출 전 잔여 예산·새 attempt 한도나 내부 command allowlist, 애플리케이션 환경 조건을 뜻하지 않습니다. |
| `DynamicReproductionLifecycleProfile` | R8이 소유하는 호출 전 work 잔여 시간 검사 정책과 새 attempt 한도의 versioned record (`data_kind=dynamic_reproduction_lifecycle_profile`) | 같은 session 조정은 세지 않고 session 재시작 `RETRY`와 외부 조건 해소 뒤 `RESUME`만 새 attempt로 세며, CPU·RAM·disk·PID·요청 가능 최대 시간은 포함하지 않습니다. |
| `environment_ref` | 이번 시도에서 실제 생성된 Sandbox 환경 기록 번호 | 실행 전 환경 설정이나 최신 환경을 가리키지 않습니다. |
| `secret_ref` | 비밀값 원문 대신 secret store의 항목을 가리키는 불투명 번호 | credential·cookie·token·password를 요구사항이나 일반 log에 저장하지 않습니다. |
| `policy_decision_ref` | Sandbox Controller가 허용·차단한 이유를 가리키는 번호 | Technical Gate 판정과 다른 기록이며 정책 차단이면 반드시 필요합니다. |
| `cleanup_status` | 실행 뒤 자원 정리 결과 | `NOT_REQUIRED`는 정리할 자원이 하나도 생기지 않았을 때만 사용합니다. |
| `CWE` | 취약점 유형을 나타내는 국제 분류 번호 | R5-01이 final TRUE의 근거를 기준으로 분류하고 Technical Gate가 정합성을 확인합니다. |
| `CWELabel` | 한 final TRUE Verification에 붙인 CWE 분류 기록 | `verification_result_ref`로 자신이 분류한 정확한 Verification 수정본을 가리킵니다. |
| current `CWELabel` | 현재 Verification에 사용할 수 있는 CWELabel 수정본 | 해당 Verification으로 성공한 `CWE_LABEL` 작업의 유일한 결과입니다. 같은 CWE라도 새 Verification에는 새 수정본을 만듭니다. |
| `CWE_LABELING` / `CWE_LABEL` | 앞은 R5-01 생산 역할, 뒤는 그 역할을 실행하는 작업 종류 | 역할과 작업 상태 이름을 구분합니다. |

## 연계 공격과 Agent

| 용어 | 쉽게 말하면 | 사용할 때 주의할 점 |
|---|---|---|
| `Agent` | 한 가지 분석 역할을 맡는 LLM 작업 단위 | 프로그램의 강제 규칙이나 사람의 결정을 대신하지 않습니다. |
| `Orchestration` | 가설 제안을 확인·등록하고 각 가설에 Verification을 배정하는 전역 조정 기능 | 배정 뒤 가설 내부 Pro/Con·동적 재현·Gate·Chaining을 결정하지 않습니다. |
| `PrimitiveDraft` | 연계 공격의 입력 조건 또는 실행 뒤 얻는 결과를 표현한 작은 데이터 | 코드 entity, 필요하면 저장소에 정의된 권한 값, 근거와 쉬운 설명을 함께 둡니다. |
| `Primitive` | 한 가설의 필요한 입력들과 실행 결과를 한 형식으로 묶은 연계 재료 | HOLD는 `result=null`, TRUE는 Technical `ACCEPT`와 current admission `ALLOW` 뒤 `result`가 있습니다. `REQUIRED/PROVIDED` 같은 별도 종류 필드는 저장하지 않습니다. |
| `PrimitiveAdmissionDecision` | TRUE 결과를 체이닝 재료로 써도 되는지 프로그램이 `ALLOW | DENY`로 기록한 값 | Rule Scope의 전용 금지 테스트 판정과 정책 수집 상태를 정해진 표로 변환하며 정책 뜻을 새로 해석하지 않습니다. |
| `source_admission_refs` | 한 체이닝 결과가 직접 또는 부모 체인을 통해 실제로 사용한 모든 허용 결정 목록 | 하나라도 오래됐거나 `DENY`로 바뀌면 그 체이닝과 파생 결과를 current 입력으로 쓰지 않습니다. |
| `PrimitiveIndexState` | 가설의 현재 Verification과 현재 Primitive 수정본들을 가리키는 목록 | 별도 전용 version 필드 없이 공통 `RecordMeta` revision과 원자적 current pointer 갱신을 사용합니다. |
| `PrimitiveMatchCandidate` | 한 Primitive의 결과가 다른 Primitive의 특정 입력을 채울 수 있는지 나타낸 미검증 후보 | `upstream_result_ref`, `downstream_input_ref`, `matched_input_id`와 실제 근거를 기록하며 아직 취약점 확정 결과가 아닙니다. |
| `Chaining Agent` | upstream 결과와 downstream 입력이 이어지는 조합만 찾는 Agent | 일반 취약점·우회·영향 탐색, 동적 재현, Gate 보완과 판정은 하지 않습니다. |
| `chaining` | 확인된 결과가 다른 가설의 입력 조건을 충족할 때 새 공격 가설을 만드는 과정 | 이미 포함된 얕은 조상 조합을 후보에서 제외해 중복 제안을 줄이고 전체 비용은 R8 전역 예산으로 제한합니다. |
| `origin=VERIFICATION` | Verification이 검증 중 발견한 별도 material claim에서 나온 새 가설 | trusted validation과 새 가설 등록 뒤 처음부터 검증합니다. |
| `origin=CHAINING` | Chaining Agent의 Primitive match에서 나온 새 가설 | 부모 판정을 바꾸지 않고 별도 lifecycle로 검증합니다. |
| `material claim` | 기존 가설과 구분해 따로 검증해야 할 새로운 공격 주장 | 기존 판정에 바로 합치지 않고 새 가설로 만듭니다. |

## 검토와 보고

| 용어 | 쉽게 말하면 | 사용할 때 주의할 점 |
|---|---|---|
| `Finding` | 사람이 검토할 수 있게 정리한 취약점 결과 | Hypothesis, Verification-origin 또는 Chaining-origin 후보와 구분합니다. |
| `Gate` | 다음 단계로 보내도 되는지 확인하는 검토 단계 | Verification 판정을 직접 바꾸지 않습니다. |
| `Technical Evidence Gate` | 판정과 코드·실행 근거가 서로 맞는지 확인하는 기술 검토 | 공식 정책을 읽지 않으므로 금지 테스트 여부는 판단하지 않습니다. 코드 경로·동적 결과·제한 조건의 연결을 확인합니다. |
| `Rule Scope Impact Gate` | 공식 정책 범위·금지 테스트 여부와 실제 영향을 확인하는 검토 | 금지 테스트 위반은 별도 필드로 판단해 TRUE Primitive admission에 전달하고, 다른 결과는 Reporter 가능성에 적용합니다. 공식 정책이 없으면 추측하지 않습니다. |
| `PolicyItem` | 공식 정책에서 뽑은 항목 하나와 원문 위치를 묶은 데이터 | 반드시 공식 출처 기록으로 다시 확인할 수 있어야 합니다. |
| `VerificationAssignment` | 한 가설의 내부 검증 흐름을 맡은 논리 owner의 저장 기록 | 같은 역할의 다른 Agent가 아니라 ACTIVE assignment와 일치하는 owner만 Gate·보완·보고 요청을 제안할 수 있습니다. |
| `REVISE` | 부족한 근거를 같은 Verification owner가 새 Verification work에서 보완한 뒤 새 revision으로 다시 검토하라는 결과 | provider retry나 동일 입력 재투표가 아니며 오래된 Gate 결과를 재사용하지 않습니다. |
| `UNCERTAIN + DENY` | 공식 정책을 확인하지 못해 결론과 보고서 전달을 허용하지 않는 상태 | LLM의 기억으로 정책을 채우지 않습니다. |
| `Reporter` | 통과한 결과를 사람이 읽을 `ReportDraft`로 정리하는 마지막 Agent | 외부 제출과 공개는 하지 않습니다. |
| `Agent automation end` | `ReportDraft`를 포함한 `AnalysisRunResult`와 `AnalysisRunState`를 원자적으로 확정한 뒤 Agent 작업을 끝내는 경계 | 이후 검토·수정·제출·공개는 시스템 밖에서 사람이 진행합니다. |

## 실행·보안·평가

| 용어 | 쉽게 말하면 | 사용할 때 주의할 점 |
|---|---|---|
| `runtime` | 설계가 실제로 실행되는 프로그램 부분 | 현재 저장소에는 구현되어 있지 않습니다. |
| `runtime validator` | 프로그램 내부 실행 범위 검사기 | 데이터 형식, 상태 순서, 예산과 권한을 강제하지만 취약점·CWE·정책 의미는 판단하지 않습니다. |
| `sandbox` | 다른 시스템과 격리해 안전하게 코드를 실행하는 환경 | host, 비밀정보와 범위 밖 네트워크 접근을 막습니다. |
| `Sandbox Controller` | 격리 환경 밖의 안전 경계를 강제하는 모듈 | R7 `sandbox_profile_ref`의 host·Docker daemon/socket·mount/namespace·secret·egress·workspace 격리와 CPU·RAM·disk·PID·요청 가능 최대 시간을 강제하며 내부 command allowlist, R7 profile 값, R8 잔여 예산·새 attempt는 결정하지 않습니다. |
| `R7 Setup Automation` | Docker image·container·환경 재생성과 정리를 실제 수행하는 비-LLM 모듈 | Agent가 Docker daemon을 직접 다루지 않도록 격리된 실행 통로를 제공합니다. |
| `Reproduction Session Manager` | 한 동적 재현 attempt의 실제 event와 최종 결과를 확정하는 비-LLM 모듈 | AgentLog, validated PoC와 DynamicReproductionResult의 result owner이며 Agent의 실행 전략은 결정하지 않습니다. |
| `provider` | LLM을 제공하는 서비스나 연결 방식 | API 방식과 회원 로그인 방식을 같은 경계에서 관리합니다. |
| `session` | LLM 서비스와 이어지는 로그인 또는 대화 상태 | 인증정보와 session 비밀값을 일반 로그에 남기지 않습니다. |
| `token` | LLM이 입력과 출력을 처리할 때 쓰는 계산 단위 | 실제 사용량을 관측하며 token만으로 실행을 자르지 않습니다. |
| `token_budget` | 한 LLM 호출의 예상 token 사용량을 적는 선택 계획값 | 강제 상한이 아니며 값이 없거나 실제 사용량이 더 많아도 token만으로 차단하지 않습니다. |
| `budget` | 시간, 비용, 호출, 재시도, 작업 수와 실행 자원에 둔 한도 | 초과를 취약점 `FALSE`로 바꾸지 않습니다. |
| `eval_config_refs` | 평가 실행에 사용한 장면·지표·정답·채점·LLM 설정의 정확한 수정본 목록 | 목록이 같은 평가 결과끼리만 직접 비교하며 생산 Gate·Primitive·Reporter 입력으로 쓰지 않습니다. |
| `corpus` | 반복 평가에 사용하는 예제 모음 | 버전과 정답 근거를 기록해 같은 조건으로 비교합니다. |
| `observability` | 실행 상태와 오류를 확인할 수 있는 기록 | 비밀정보와 숨은 사고 과정은 저장하지 않습니다. |
| `redaction` | 로그나 보고서에서 비밀정보를 가리는 처리 | 가리기 실패 시 일반 전달을 중단합니다. |
| `provenance` | 파일이나 근거를 어디에서 가져왔는지 보여 주는 출처와 변경 이력 | 원본 commit에 포함되지 않은 파일을 포함됐다고 주장하지 않습니다. |
| `migration` | 이전 설계에서 새 설계로 옮기는 과정 | v4의 상태나 판정을 v5로 자동 승계하지 않습니다. |
| `upstream / downstream` | 현재 단계보다 앞에서 입력을 만드는 단계 / 뒤에서 결과를 받는 단계 | 문서에서는 가능한 한 ‘앞 단계/뒤 단계’라고 씁니다. |
| `owner / reviewer` | 작업 담당자 / 결과 검토자 | 같은 사람이 혼자 작성하고 승인하지 않습니다. |

## 문서 상태 구분

| 표시 | 뜻 |
|---|---|
| `DESIGN_AUTHORED` | 설계 초안이 작성되었습니다. |
| `REVIEW_REQUIRED` | 팀 검토와 독립 검토가 더 필요합니다. |
| `NOT_IMPLEMENTED` | 실행 코드는 아직 구현되지 않았습니다. |
| 기준 문서 | 실제 설계 의미와 계약을 판단할 때 우선하는 문서입니다. |
| 쉬운 요약 | 기준 문서를 빠르게 이해하도록 돕는 설명이며 새 규칙을 만들지 않습니다. |
| 작업 기록 | 설계와 문서를 어떻게 바꿨는지 남긴 계획·검토 기록입니다. |
