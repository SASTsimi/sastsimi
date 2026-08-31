# 결과와 디버깅

## 쉽게 말하면

분석 한 건에서 어떤 저장소를 봤는지, 어떤 가설과 판정이 나왔는지, 자원은 얼마나 썼고 어디서 오류가 났는지를 다시 확인할 수 있게 저장합니다.

**상세 기준:** [07. 결과 저장과 관측성](../07-results-and-observability.md)

평가에 넣을 상황 종류(장면 표)는 `07`의 **평가 장면 종류**를 따른다. Wiki에 표를 복제하지 않는다.

`artifact`는 도구가 만든 결과 파일이나 기록이고 `debug trace`는 단계와 근거를 이어 보는 디버깅 기록입니다. 자세한 용어는 [쉬운 용어집](../../GLOSSARY.md)을 따릅니다.

`AnalysisRunResult`는 다음을 함께 찾을 수 있게 한다.

- repository, `commit_id`, `workspace_id`, `started_at`, `finished_at`, `elapsed_ms`
- INITIAL/VERIFICATION/CHAINING/invalid 가설 수와 verdict별 개수
- 위치 기반 context 요청·응답과 실제 조회 location
- Verification, debate mode/trigger/skip, restriction와 capability
- Docker 결과, redacted PoC와 cleanup
- HOLD REQUIRED, Gate-qualified TRUE PROVIDED, TRUE+HOLD·TRUE+TRUE Chaining match와 재검증 여부
- `CWELabel`, Technical 및 Rule Scope Impact Gate, 공식 `ProgramPolicyRecord`과 두 Gate·보고서가 사용한 정확한 revision reference
- 보고서 초안과 사람 검토 상태
- 역할/provider/model/session별 LLM invocation log
- AST/SAST·LLM·sandbox 자원과 모든 오류
- `work_id`, attempt 이력, 상태 전이, 중복 요청과 중단 후 복구 결과
- retry·같은 Verification의 Gate 보완·Chaining no-match/제한·예산으로 멈춘 이유
- `COMMITTED` 상태와 artifact reference를 연결한 debug trace

Proxy가 어려운 membership 호출은 raw session log → provider parser → redaction 경로를 쓴다. 사용자에게 노출된 request/response/tool trace만 기록하고 hidden chain-of-thought와 credential은 저장하지 않는다. 일반 결과에는 credential, 개인정보, 인증 헤더, 로컬 절대 경로가 없는 `AnalysisError.safe_message`만 넣는다. 꼭 필요한 원본 오류는 별도의 접근 제한·민감정보 제거 저장소에 두며 일반 결과와 분리한다. 오류는 `FALSE`와 구분한다.

상세 내용은 [결과 저장과 관측성](../07-results-and-observability.md)을 따른다.
ID 생성 주체, 상태 계층과 gap/error 차이는 [공통 ID·상태·오류](common-contracts.md)에서 쉽게 확인할 수 있다. 병렬 합류, 재시도, 늦은 결과와 crash-resume은 [상태·병렬 실행·재시도·복구](state-and-recovery.md)를 따른다.
