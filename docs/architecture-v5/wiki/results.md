# 결과와 디버깅

## 쉽게 말하면

분석 한 건에서 어떤 저장소를 봤는지, 어떤 가설과 판정이 나왔는지, 자원은 얼마나 썼고 어디서 오류가 났는지를 다시 확인할 수 있게 저장합니다.

**상세 기준:** [07. 결과 저장과 관측성](../07-results-and-observability.md)

평가 장면·합격 지표·역할별 한도·설정 재비교는 `07`을 따른다. Wiki에 표를 복제하지 않는다.

`artifact`는 도구가 만든 결과 파일이나 기록이고 `debug trace`는 단계와 근거를 이어 보는 디버깅 기록입니다. 자세한 용어는 [쉬운 용어집](../../GLOSSARY.md)을 따릅니다.

`AnalysisRunResult`는 다음을 함께 찾을 수 있게 한다.

- repository, `commit_id`, `workspace_id`, `started_at`, `finished_at`, `elapsed_ms`
- INITIAL/VERIFICATION/CHAINING/invalid 가설 수, 중복 검토 판정·exact review reference, verdict별 개수와 final 판정 없이 끝난 `failed_hypothesis_count`
- 위치 기반 context 요청·응답과 실제 조회 location
- Verification, debate mode/trigger/skip, restriction와 capability
- 동적 재현 요청, R7 requirements·간단한 plan·recipe·PoC candidate, Controller 외부 경계 판정·실제 환경·append-only AgentLog, validated PoC와 cleanup
- `required_primitive_candidates`가 있는 HOLD의 `result=null` Primitive, result가 있는 Technical-accepted·admission-allowed TRUE Primitive, `PrimitiveAdmissionDecision`, match가 직접·부모 체인에서 사용한 `source_admission_refs`, upstream result→downstream input match와 재검증 여부
- R5-01 `CWE_LABELING` work와 `CWELabel`의 exact Verification·generation·work·호출 provenance, 과거/current label revision
- Technical 및 Rule Scope Impact Gate, `FOUND | ABSENT_CONFIRMED | COLLECTION_FAILED` 정책 수집 결과, parser 결과, 공식 `ProgramPolicyRecord`과 두 Gate·보고서가 사용한 서로 일치하는 Verification·current CWELabel revision reference
- current 보고서 초안, 오래된 초안 제외와 Agent 자동화 종료 상태
- 역할/provider/model/session별 LLM invocation log
- AST/SAST·LLM·sandbox 자원과 모든 오류
- `work_id`, attempt 이력, 상태 전이, 중복 요청과 중단 후 복구 결과
- retry·같은 Verification의 Gate 보완·Chaining no-match/제한·예산으로 멈춘 이유
- 평가 실행이면 장면·지표·정답·채점·provider·model·session의 exact `eval_config_refs`; 생산 실행이면 빈 목록
- `COMMITTED` 상태와 artifact reference를 연결한 debug trace

Proxy가 어려운 membership 호출은 raw session log → provider parser → redaction 경로를 쓴다. 사용자에게 노출된 request/response/tool trace만 기록하고 hidden chain-of-thought와 credential은 저장하지 않는다. 일반 결과에는 credential, 개인정보, 인증 헤더, 로컬 절대 경로가 없는 `AnalysisError.safe_message`만 넣는다. 꼭 필요한 원본 오류는 별도의 접근 제한·민감정보 제거 저장소에 두며 일반 결과와 분리한다. 오류는 `TRUE | FALSE | HOLD`와 구분한다.

평가 결과 둘은 `eval_config_refs`가 exact reference 기준으로 같은 경우에만 직접 비교합니다. token은 사용량을 관측하지만 계획값 초과·누락만으로 실행을 차단하지 않습니다. 이 평가 정보는 Gate·Primitive·Reporter 입력이 아닙니다.

Context 조회 실패·timeout·권한 오류는 `AnalysisError`로, 그 때문에 확인하지 못한 범위는 `DataGap`으로 함께 찾을 수 있어야 합니다. 일부 조회 실패가 있어도 모든 `validation_checks`를 실제 근거로 완료했다면 판정을 저장할 수 있습니다. 하나라도 완료하지 못했으면 final `VerificationResult`는 저장하지 않고, 재시도 가능 여부에 따라 가설을 `VERIFYING`으로 유지하거나 work와 함께 `FAILED`로 끝냅니다. 실패 가설 수는 verdict 수와 섞지 않고 `failed_hypothesis_count`로 따로 보입니다.

동적 결과에서는 request·plan·recipe·환경·AgentLog·PoC와 attempt가 서로 맞는지 확인합니다. 정책 차단이면 Controller 판정과 AgentLog가 필수입니다. `poc_candidate_ref`는 작성하거나 실행을 시도한 자료이고, `SUCCEEDED + SUPPORTED`이며 같은 attempt의 AgentLog가 exact candidate digest 실행을 증명할 때만 validated `poc_ref`를 가집니다. 모든 final TRUE는 이 validated PoC를 가져야 합니다.

상세 내용은 [결과 저장과 관측성](../07-results-and-observability.md)을 따른다.
ID 생성 주체, 상태 계층과 gap/error 차이는 [공통 ID·상태·오류](common-contracts.md)에서 쉽게 확인할 수 있다. 병렬 합류, 재시도, 늦은 결과와 crash-resume은 [상태·병렬 실행·재시도·복구](state-and-recovery.md)를 따른다.
