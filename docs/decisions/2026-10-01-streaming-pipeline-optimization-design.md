# SASTSIMI 스트리밍 파이프라인 최적화 설계

작성일: 2026-10-01

## 목적과 불변조건

Python 제품 코드의 신규 취약점 탐지 가능성을 최대한 유지하면서 후보별 중복 문맥, 전 소스 재탐색, 가설 선생성 장벽을 제거한다. 빠른 Finding 도달과 토큰·시간 절감은 검증되지 않은 범위를 완료로 표시하지 않는 조건 아래에서만 추구한다. 사용자가 선택하는 FAST/FULL/DEEP 모드와 별도의 LLM Cheap Gate는 만들지 않는다. 기존 Agent 역할, Pro/Con 분리, PoC·기술·정책·primitive gate, chaining, Finding 및 보고서 흐름을 보존한다.

기존 Dify A-001의 DB·artifact·checkpoint는 읽거나 수정하거나 resume하지 않는다. 실제 Dify 전체 스캔과 실제 provider 호출 없이 fixture와 mock으로 구현을 검증한다. 실패 호출의 사용량이 불명확하면 NULL로 남긴다.

## 확인된 현재 구조와 선택지

현재 새 후보 경로는 정적 결과와 AST manifest를 보존하고 Discovery를 모두 마친 뒤, INCLUDE/UNDECIDED 후보마다 별도 가설 호출을 한다. 이어서 모든 Python 제품 소스를 32KB 단위로 자유 탐색하고, HYPOTHESIS_DONE을 성공시킨 다음에야 자식 가설의 Pro/Con·Verification을 실행한다. 후보별 호출과 전 소스 자유 탐색은 감사된 입력 토큰의 약 83.25%를 사용했다. 현재 후보 결과에는 candidate_id별 독립 출력 계약이 없다. progress 분모는 가설마다 12개 작업을 더해 동적으로 커진다.

선택지는 (A) 현재 checkpoint/store/runner를 유지하며 생산자 순서와 입력 계약만 교체, (B) 별도 신규 파이프라인을 병행, (C) 저장소·큐를 새 이벤트 시스템으로 전면 재작성이다. A를 채택한다. B는 단일 파이프라인 조건과 운영 복잡도를 해치고, C는 재개·PoC·chaining 의미를 넓게 흔든다. 기존 기록 형식은 이전 실행의 재개를 위한 호환 경로로만 남긴다. 신규 실행 경로는 하나다.

## 데이터 흐름

정적 결과와 Python 범위 확정 → 버전이 있는 attack-surface index → 원본 후보 수집 및 Discovery → 파일별 적응형 후보 묶음 → 증거 요건을 적용한 가설 생성 → 등록된 자식 즉시 검증 및 제한된 대기열 비우기 → 후보가 다룬 surface의 coverage 판정 → 미검토 보안 surface에 한정한 자유 탐색과 즉시 검증 → 전체 가설 공급 완료 checkpoint → 검증된 primitive의 global chaining 확인 → Finding·보고서·최종 상태 판정.

HYPOTHESIS_DONE은 모든 가설 공급원의 탐색 완료를 의미한다. 자식 검증의 시작 조건은 아니다. 최종 COMPLETE/PARTIAL은 공급 완료, 자식 대기열의 종료, 정적 범위와 surface coverage 및 기존 terminal gate 조건을 모두 평가한다. 기존 Python 외 제품 코드는 범위 밖이라는 사실을 유지한다.

## 구성 요소와 계약

### 1. 호출 소유권과 시도 계측

공통 LLM 호출 계약에 불변의 logical-task owner를 전달한다. owner에는 analysis/stage/agent와 선택적인 candidate/hypothesis/surface/file/batch/context 식별자가 있다. attempt 원장에는 nullable owner 필드, retry_of, 요청 문맥의 분류별 바이트 수, 실제 provider가 보고한 토큰·비용·경과시간 및 상태를 기록한다. 분류별 바이트는 토큰 추정치로 표시하지 않는다. Codex call ID, provider invocation ID, checkpoint attempt ID를 연결하고, 실제 자식 PID는 생성 시점에 기록한다. 재시도는 종료가 확인된 호출만 허용한다. 정리가 불확실하면 BLOCKED이며 같은 logical task를 중복 실행하지 않는다. Claude·Cursor·Codex 모두 동일한 owner 계약을 전파하고 중복 계측은 방지한다. 기존 행의 새 컬럼은 NULL로 마이그레이션한다.

Codex 원장은 현재 분석당 IN_FLIGHT 1개만 안전하게 허용한다. 우선 이 제한을 유지한다. 4개 동시 호출은 정확한 call/child 소유권, 종료 증명, 중복 claim 테스트가 통과할 때에만 활성화한다. 설정은 bounded concurrency를 허용하되 실제 provider별 안전 상한을 적용한다.

### 2. 파일별 후보 묶음과 문맥

선별 후보를 파일 경로별로 안정 정렬한다. 페이지 경계에 걸친 같은 파일의 후보가 누락되지 않도록 조회 또는 스트리밍 그룹화한다. 묶음은 보통 8~20개를 목표로 하지만 직렬화 바이트 예산과 모델 문맥 headroom에 따라 자동 축소·분할한다. 한 후보만으로도 한도를 넘으면 조용히 자르지 않고 명시적으로 실패·미검토로 남긴다.

FileAnalysisContext는 기존 CAS AST manifest에서 필요한 함수·class·import·호출 관계와 후보 주변의 bounded, redacted source를 한 번 구성해 artifact로 보관한다. 프롬프트에는 공유 문맥 한 번과 후보별 작은 근거만 직렬화한다. 긴 대화 history를 누적하지 않는다. candidate_results는 요청 후보 ID별로 정확히 한 건이어야 하며 누락·중복·불명 ID를 검증한다. 부분적으로 유효한 결과는 후보별로 보존하고 누락 ID만 제한적으로 재요청한다. overflow는 해당 묶음만 재분할한다. 각 가설의 ID는 candidate ID와 해당 proposal의 정규화 값으로 안정화하고, 후보별 proposal/ref 및 원자 checkpoint를 유지한다. 같은 코드 위치라도 attack path가 다르면 합치지 않는다.

### 3. Qualified hypothesis

별도 LLM 선별 단계 없이 기존 Hypothesis Agent의 출력 계약에 source의 공격자 통제성, 민감 동작, 코드 기반 reachability, 경계, 발견된 control, exploit precondition을 요구한다. 생성기가 근거 없는 추측은 NO_HYPOTHESIS 또는 INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS로 남긴다. 명백한 방어가 있으면 근거 없이 가설을 만들지 않는다. 완전한 경로 증명이나 PoC는 이 단계에서 요구하지 않으며, 불확실하지만 구체적 코드 근거가 있는 흐름은 후속 검증으로 보낸다. Discovery 결정과 가설 verdict는 분리한다.

### 4. 즉시 검증과 backpressure

각 후보 묶음의 valid proposal을 내구성 있게 등록한 직후 기존 child runner를 호출한다. 뒤 묶음과 자유 탐색 종료를 기다리지 않는다. pending/실행 중 가설 수가 설정된 임계값에 닿으면 생산을 멈추고 기존 queue를 비운다. 단일 분석의 실행 lease와 logical-task claim으로 같은 자식의 중복 실행을 막는다. 한 실행 턴에서 실패한 자식을 묶음마다 다시 호출하지 않으며, 재시도 가능한 pending과 중단된 blocked를 구분해 backpressure 교착을 막는다. 실패·예산 중단은 이미 성공한 결과를 보존하고 해당 묶음과 자식만 재개한다. Pro와 Con은 각자의 역할·독립 결과를 유지하면서 같은 파일/근거의 소수 가설에 한해 공유 문맥 묶음을 지원한다. 누락된 hypothesis ID만 재요청한다.

검증된 primitive만 chaining pool에 넣는다. 초기에 2개 미만이라는 이유로 저장된 NO_MATERIAL_CHILD가 이후 primitive 유입을 영구 차단하지 않도록, 공급 종료 후 bounded global pass 또는 pool revision 기반 무효화를 한다. 추측성 가설은 chaining 입력으로 쓰지 않는다.

### 5. Attack surface와 범위 공백 탐색

정적 bundle과 후보 위치·규칙·AST 사실에서 deterministic, 확장 가능한 primitive 분류를 구축한다. surface ID, 유형, 파일, 심볼, 줄, 연결 후보, 정적 근거 및 coverage 상태를 scope fingerprint와 함께 버전 있는 CAS artifact로 저장한다. 이는 전체 Python 파일 목록이 아니라 보안 민감 위치의 인덱스다. 같은 이름의 다른 경계/흐름을 무분별하게 병합하지 않는다.

Coverage는 파일을 읽었다는 사실만으로 인정하지 않는다. 후보/가설의 실제 source·operation·boundary 검토 근거를 surface에 연결하고 중요한 entry/sink 또는 control이 남으면 UNCOVERED/INSUFFICIENT로 둔다. 해당 surface만 의미 있는 bounded code context로 targeted free exploration한다. 기존 임의 32KB 페이지 덤프는 신규 기본 경로에서 사용하지 않는다. 단순 helper·formatting·constant는 자동 재탐색 대상이 아니다. 새 가설은 즉시 검증한다. 미검토 보안 surface와 정적 미검증 Python 제품 조합은 별도로 남기고 COMPLETE를 허용하지 않는다.

### 6. 호환성과 사용자 표시

기존 candidate v1의 HYPOTHESIS_DONE, free-page cursor/done marker, proposal hash와 ref, 완성된 자식 checkpoint는 재개 시 그대로 인정한다. 신규 실행은 candidate pipeline v2와 새 marker kind/version/scope/context hash를 사용해 기존 marker를 다른 뜻으로 재해석하지 않는다. 기존 run의 재개가 필요한 경우에는 완료된 작업 재사용과 남은 기존 계획 이행을 보장하는 호환 처리를 한다. 신규 실행에서만 최적화된 단일 경로를 생성한다. v2 terminal은 정확한 surface coverage artifact hash와 미검토 수를 결합하고 후보 개수만으로 COMPLETE를 만들지 않는다. A-001은 이 작업에서 열지 않는다.

대시보드·CLI에는 정적 상태, 후보 triage, 후보 심층 처리, 가설 생성/검증, PoC 시도, 보안 surface coverage, Finding, 미검증 범위를 각각 개수로 표시한다. 기존 percentage를 남긴다면 동적 분모의 '현재 알려진 checkpoint 비율'이라고 명시하고 비용·시간·저장소 전체 coverage로 해석되지 않게 한다. 완료 건수는 resume 후 중복 집계하지 않는다.

## 오류 처리와 검증

스키마 누락·잘못된 ID·문맥 한도 초과는 묶음을 분할하거나 누락 ID만 유한 재요청한다. 소스·artifact 손상, 미해결 Codex 자식, 중복 claim, Agent 실패는 범위 공백이나 취약점 부재로 바꾸지 않는다. 정적 미검증·surface 미검토는 PARTIAL 또는 기존 실패 규칙에 따라 처리한다.

테스트는 임시 DB/fixture/mock만 사용한다. 후보 동일 파일 묶음·ID 완전성·overflow·qualified positive/negative/ambiguous·첫 검증 선행·backpressure·targeted free exploration·보수적 dedup·cleanup/timeout/idempotency·owner 집계·legacy resume·chaining 새 primitive·progress 분모를 다룬다. 대표 synthetic 저장소로 이전/신규 경로의 호출 수, prompt bytes, 검증 시작 지연, pending peak 및 known-positive 보존을 측정한다. formatter, lint, mypy, 관련 unit/integration을 실행한다. 전체 Dify 분석 또는 실제 LLM smoke test는 실행하지 않는다.

## 예상 효과와 위험

후보별 공유 AST 반복과 전 Python 소스 second pass를 없애면 가장 큰 입력 토큰 집중 지점을 줄일 수 있다. 절감률은 fixture 측정값과 설계상 기대를 구분한다. 가장 큰 false-negative 위험은 보안 surface 분류 누락과 qualified 기준의 과도한 기각이다. 이를 막기 위해 미분류/미검토 surface를 완료로 승격하지 않고, ambiguous-but-grounded 가설을 후속 검증하며, known-positive 회귀와 사람 검토 가능한 coverage 목록을 유지한다.

## 작업 경계

현재 최신 코드 작업 폴더는 다른 브랜치의 변경 파일 27개가 이미 수정된 상태다. 그 변경을 덮어쓰거나 초기화하지 않는다. 구현은 별도의 격리 작업 폴더에 정확한 기준 상태를 복제하고, 기존 변경을 보존한 채 진행한다. 문서와 결과는 새 작업 브랜치에만 반영한다.
