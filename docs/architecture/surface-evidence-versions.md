# 저장된 분석의 보안 표면 근거 버전

이 문서는 이미 저장된 Python 분석을 `sastsimi resume A-001 --enrich-saved-surface-evidence`로
보강할 때 사용하는 증거 버전을 설명합니다. 일반 checkpoint 재개와 잠금·오류 처리는
[Runtime과 실패 지점 재개](./runtime-and-recovery.md#저장된-분석의-보안-표면-근거-보강)를,
새 분석에서 표면 인덱스를 만드는 순서는 [실제 분석 파이프라인](./pipeline.md)을 봅니다.
아래 버전은 같은 저장 결과를 덮어쓰는 순서가 아니라, 고정된 전임 근거에 새 계획과
검증 가능한 종료 근거를 더하는 회차입니다.

`REVIEWED`는 Agent가 조각을 유효하게 검토했다는 집계입니다. `COVERED`는 정해진
Python 검사 범위에서 한 연결 경로의 입력 지점·신뢰 경계·위험 동작과 모든 조각·자식
상태를 다시 검증한 집계입니다. `COVERED`도 취약점 `TRUE`, 제보 가능한 Finding,
Scope Gate 승인이나 저장소 전체의 안전성 증명이 아닙니다. 미검토 경로·Python 정적
검사 공백·미해결 자식 `HOLD`는 `PARTIAL`의 이유가 될 수 있고, 저장 근거 손상이나
Agent 실행 실패는 `PARTIAL`로 바꾸지 않습니다.

<a id="surface-v4"></a>
## v4: 고정 범위와 근거 조각

`sastsimi resume A-001 --enrich-saved-surface-evidence`는 이미 저장된 Python 분석의
보안 표면 근거를 별도 회차로 보강하는 명시적 경로입니다. 초기 회차는 근거 부족
표면을 중심으로 검토하고, 후속 회차는 기존 `COVERED` 표면도 다시 검증할 수 있습니다. 일반 `resume`과
달리 먼저 분석 잠금을 획득하고 고정 커밋·추적 파일의 SHA-256·기존 정적 결과·AST·
표면 인덱스·후보 범위와 이전 결과 참조를 대조합니다. 범위가 달라졌거나 참조가
손상됐으면 새 분석처럼 다시 계획하지 않고 차단합니다. 범위가 일치하면 변경할 수 없는
v4 계획과 Python 검사 범위 인증서를 저장하고, 최대 64 KiB의 코드·AST·호출 경로
문맥 조각마다 결과를 원자적으로 기록합니다. 재개 시 유효한 조각과 완료된 자식 작업은
재사용하고 누락된 조각만 처리합니다. 기존 정적 검사, v1–v3 표면 결과, Finding,
PoC, Scope Gate 기록은 덮어쓰지 않습니다.

검사 범위 인증서는 원본 제외 목록과 정적 검사 공백을 그대로 보존하고 **유효한 Python
범위**를 별도로 표시합니다. 고정 커밋의 파일 내용과 제외 사유가 확인된 비Python
제품 파일만 Python 전용 검사 범위 밖으로 판정할 수 있습니다. Python 파싱·규칙 오류,
출처 불명의 제외, 누락된 파일은 완료로 바꾸지 않습니다. v2 보안 표면 증거에서는
같은 그래프 경로의 입력 지점·신뢰 경계·위험 동작을 실제 코드 위치와 간선에 대조하고,
모든 문맥 조각과 연결된 자식 가설의 상태를 확인합니다. 한 조각에서 가설을 만들지
못했다는 사실만으로 검증 실패나 취약점 부재로 판정하지 않으며, 서로 무관한 경로의
역할 증거를 합쳐 `COVERED`로 만들지도 않습니다.

<a id="surface-v5"></a>
## v5: 소스 경로와 조건부 운영 경로

v5 보강은 이전 v2 범위 증거와 v4 계획을 고정 참조로 잇고, 표면마다 소스 해시가
확인된 경로 그래프와 문맥 조각을 저장합니다. HTTP의 요청 입력 경로와 XML의 운영
라우트·클래스 바인딩은 서로 다른 근거입니다. XML 바인딩만으로 요청에서 위험 동작까지
호출됐다고 주장하지 않으며, 동적 디스패치가 풀리지 않으면 명시적 공백으로 남깁니다.
새로 생성하는 HTTP 경로 그래프에는 해시가 일치하는 같은 함수의 인접 구문 줄을
최대 16개까지 보조 문맥으로 덧붙입니다. 민감정보를 가린 이 줄들은 Agent가 입력값과
분기 조건을 읽는 데만 쓰며, 검증된 경로 간선이나 `COVERED` 판정으로 승격하지
않습니다. 이미 저장된 그래프·계획은 불변이므로 기존 분석에 소급 적용하지 않습니다.
운영 XML 라우트는 고정 커밋의 파서·XML·대상 코드·Dockerfile 사이의 조건부
소스 근거입니다. 실제 Docker 빌드 컨텍스트나 배포 이미지의 바이트 일치는
증명하지 않습니다. 최종 이미지 단계의 파일 변경 명령, `.dockerignore`, 파서의
작업 디렉터리 변경이나 import 재바인딩 가능성이 있으면 경로를 추정하지 않고
검증 공백으로 보존합니다. 이 보수적 기준은 정상적인 Dockerfile도 미증명으로
남길 수 있습니다.
이전 판별 코드로 이미 저장한 v5 그래프는 원본 검토 이력으로만 유지합니다.
새 의미론 버전 표식이 없는 저장 경로는 해시가 맞더라도 `COVERED`의 근거로
재사용하지 않습니다. 새 평가에서는 미증명으로 남기고, 과거 `COVERED` 종료
증거와 충돌하는 경우 공개 읽기에서 실패로 닫습니다. 새 근거가 생겼다고 가정해
기존 결과를 자동으로 완료 처리하지 않습니다.
Agent가 조각을 유효하게 검토한 `REVIEWED`와 한 연결 경로의 입력 지점·신뢰 경계·
위험 동작, 모든 조각 및 자식 상태까지 재검증된 `COVERED`는 별도 집계입니다. 저장된
v3 표면 증거의 공개 수치는 읽기 시에도 고정 그래프·Agent 결과·현재 자식 상태를
다시 대조한 경우에만 표시하며, 확인할 수 없는 수치를 완료로 추정하지 않습니다.
CLI·대시보드·보고서는 검토 수와 입증 수, 남은 이유를 구분해 보여줍니다.
현재 v5 표면 검토 결과는 기존 자식 가설의 `HOLD` 사유를 반증하는 자료가
아닙니다. 재실행 판별기와 일회성 저장 절차가 있어도, 별도의 신뢰 가능한 반증·
새 시험 입력 생산자가 입증되지 않은 `HOLD`는 재실행하지 않고 그대로 보존합니다.

<a id="surface-v6"></a>
## v6: 종료된 인증서 이후의 새 경로

이미 v3 표면 인증서로 종료된 분석에서 새 소스 경로 증거가 필요한 경우에는
후속 v6 계획을 기존 v3 인증서·v5 계획과 해시로 묶어 별도로 저장합니다.
기존 결과를 재해석하거나 덮어쓰지 않고 `INSUFFICIENT` 표면의 새 조각만
검토합니다. 클래스 수준 XML 등록, HTTP 요청 경로, 상속된 호출과 실제 오버라이드가
고정 소스에서 연결될 때만 해당 경로를 인정하며, 속성 재대입·동적 디스패치 등
증명되지 않은 경우는 공백으로 남깁니다. 새 경로 증거는 과거 PoC·검증 `HOLD`의
반증이 아니므로 별도 신뢰 가능한 실행 증거가 없으면 전체 `PARTIAL`을 유지합니다.

<a id="surface-v7"></a>
## v7: 전임 경로의 독립 재검토

v7 계획은 저장된 v6 coverage·계획·진행 기록과 그래프 의미론 버전을 고정 참조합니다.
전임의 누락 조각이 있거나 소스·범위·참조가 달라졌으면 새 회차를 시작하지 않습니다.
이전 `COVERED` 또는 자식 가설이 있는 표면도 새 경로의 역할 근거를 독립적으로
검토합니다. 같은 sink의 다른 관련 경로, 아직 구체화되지 않은 경로 공백, 미해결
자식은 한 경로의 유효한 Agent 응답만으로 지우지 않습니다. `REQUEST_CONTEXT`는
요청·라우트 경계의 검토 근거이지 sink로의 taint 전파나 안전성 판정이 아닙니다.
완료된 조각과 자식은 정확한 입력·해시가 맞으면 재사용합니다. 구현 근거는
`src/sastsimi/simple_runtime/surface_enrichment_v7.py`,
`src/sastsimi/simple_runtime/surface_coverage_v5.py`입니다.

<a id="surface-v8"></a>
## v8: 표면 역할별 근거

v8은 완료된 v7 계획·coverage·진행 snapshot에 결속된 별도 계획을 만들고,
`SOURCE`·`CONTROL` 표면의 역할 근거를 다시 검토합니다. 경로에 연결된 역할과
위치에서만 `CONNECTED` 근거가 성립합니다. `LOCAL_ONLY` 검토나 확인하지 못한
표면 역할은 경로 완료 근거가 아니며, 관련 경로가 모두 검증되지 않으면
`INSUFFICIENT`가 남습니다. 새 자식의 상태를 이전 v7의 고정된 자식 집계에
소급해서 섞지 않습니다. 구현 근거는
`src/sastsimi/simple_runtime/surface_enrichment_v8.py`,
`src/sastsimi/simple_runtime/surface_coverage_v6.py`입니다.

<a id="surface-v9"></a>
## v9: 고정 소스의 적용 가능성과 경로 증명

v9는 v8 인증서와 고정된 커밋·범위·후보 목록에 새 계획을 더합니다. 선택형 HTTP·XML
분석기의 적용 가능성은 고정 Python 소스를 모두 읽고 해시·파싱을 확인한 뒤에만
판정합니다. 적용되지 않는 분석기라는 증거는 그 분석기의 공백만 제거하며 HTTP
경로나 취약점의 부재를 증명하지 않습니다. 이전 연결 경로는 소스·AST의 위치와
간선을 다시 대조하고, 관련 경로가 하나라도 미증명이라면 한 경로의 좋은 검토로
전체 표면을 `COVERED`로 올리지 않습니다. 고정 SQL 문자열 호출과 Flask route
선언의 개별 증명도 그 호출·선언만을 설명합니다. 잘린 함수 문맥은 누락 없이
제한된 조각으로 나눠 검토하고, 빠지거나 모호한 조각은 공백으로 남깁니다. 누락된
검토·자식 `HOLD`·정적 공백은 별도 판정이며 이전 v8 결과나 Finding은 변경하지
않습니다. 구현 근거는 `src/sastsimi/simple_runtime/surface_enrichment_v9.py`,
`src/sastsimi/simple_runtime/surface_applicability_v9.py`,
`src/sastsimi/simple_runtime/surface_intrinsic_proof_v9.py`,
`src/sastsimi/simple_runtime/surface_path_proof_v9.py`,
`src/sastsimi/simple_runtime/surface_coverage_v7.py`입니다.

<a id="surface-v10"></a>
## v10: 요청 경로와 템플릿 경계

v9 검토가 끝난 분석은 기존 v9 계획·coverage·종료 근거·진행 기록의 해시에 결속된
불변 v10 계획을 별도로 저장할 수 있습니다. v10은 고정된 Python 소스에서 요청별
라우트와 호출 간선을 대조해 같은 파일의 무관한 초기화 동작을 분리하고, Python
응답 또는 검증된 리터럴 템플릿 호출 경계까지만 증명합니다. 템플릿 HTML/Jinja
내용은 `TEMPLATE_CONTENT_NOT_ANALYZED`로 별도 표시합니다. 공개 수치는 v9 전임
근거와 v10 결과를 독립적으로 재검증한 뒤에만 표시합니다. 동적·외부 호출 등
증명하지 못한 경로와 기존 자식 `HOLD`는 자동으로 해제하지 않으며, 이전
v9·PoC·Finding 기록도 변경하지 않습니다.

<a id="surface-v11"></a>
## v11: 자식 재검증의 별도 원장

v10 전임 근거가 검증되면 후속 자식 재검증 계획은 연결된 과거 `HOLD`
체크포인트와 증거 해시를 고정합니다. 자식별 `PENDING/RUNNING/RESOLVED/`
`STILL_HOLD/ERROR`는 별도 원장에 저장하고, 이전 체크포인트나 PoC를
덮어쓰지 않습니다. 대시보드·CLI의 중간 집계는 검토 진행 상황일 뿐
보안 표면의 완료 근거가 아닙니다. 현재 후속 버전은 실행·해석 체인이
독립적으로 재생되는 PoC의 `INCONCLUSIVE`만 완료 처리합니다. 초기
`HOLD`와 새 최종 `TRUE`는 후속 PoC·검증·Gate·보고서가 입증되지 않으면
계속 미해결로 남고, 기존 보고서는 현재 보고서로 노출하지 않습니다.

## 재개와 최종 상태

재부팅 뒤 미배달된 Codex 호출은 정확한 호출·하위 프로세스 동일성과
재부팅 이후 종료를 확인한 경우에만 별도 감사 기록으로 정리합니다.
과거 성공 응답의 호출별 원문 참조가 없으면 결과를 복원하거나 완료로
계산하지 않습니다. 해당 표면·문맥의 미완료 작업은 한 번의 논리적
재시도만 허용하고, 재시도가 다시 중단되면 중복 호출을 막고 차단
상태로 남깁니다. 재시도에는 추가 모델 사용량이 발생할 수 있습니다.

모든 보강 호출이 끝나도 근거 부족, 실제 Python 검사 공백, 미해결 자식 `HOLD`가
남으면 `PARTIAL`은 올바른 최종 상태입니다. 인증서·저장 근거 손상이나 Agent 실행
실패는 `PARTIAL`로 덮지 않고 `BLOCKED`·`FAILED` 또는 한도에 따른 `PAUSED`로
기록합니다. 별도 보강 상태와 오류 코드는 원래 성공한 v1 종료 근거를 손상시키지
않고 저장됩니다. v2의 `COVERED`는 정해진 검사 범위의 표면 검토 근거이지 취약점
`TRUE`, 제보 가능한 Finding, Scope Gate 승인 또는 저장소 전체 보안 보증이 아닙니다.

## 코드 위치

- 고정 Python 범위 재인증: `src/sastsimi/simple_runtime/surface_scope_recertification.py`
- v4 그래프·계획·검증: `src/sastsimi/simple_runtime/surface_evidence_graph_v4.py`,
  `src/sastsimi/simple_runtime/surface_enrichment_v4.py`,
  `src/sastsimi/simple_runtime/surface_evidence_validation_v4.py`
- v5 그래프·계획·검증: `src/sastsimi/simple_runtime/surface_evidence_graph_v5.py`,
  `src/sastsimi/simple_runtime/surface_enrichment_v5.py`,
  `src/sastsimi/simple_runtime/surface_evidence_validation_v5.py`
- v6 계획·coverage: `src/sastsimi/simple_runtime/surface_enrichment_v6.py`,
  `src/sastsimi/simple_runtime/surface_coverage_v4.py`
- v7–v9의 계획·coverage: `src/sastsimi/simple_runtime/surface_enrichment_v7.py`,
  `src/sastsimi/simple_runtime/surface_coverage_v5.py`,
  `src/sastsimi/simple_runtime/surface_enrichment_v8.py`,
  `src/sastsimi/simple_runtime/surface_coverage_v6.py`,
  `src/sastsimi/simple_runtime/surface_enrichment_v9.py`,
  `src/sastsimi/simple_runtime/surface_coverage_v7.py`
- v10 요청 경로·계획·독립 읽기 검증: `src/sastsimi/simple_runtime/surface_route_boundary_v10.py`,
  `src/sastsimi/simple_runtime/surface_enrichment_v10.py`,
  `src/sastsimi/simple_runtime/surface_coverage_v8.py`,
  `src/sastsimi/simple_runtime/surface_coverage_v8_read.py`
- v11 자식 계획·재검증·독립 읽기 검증: `src/sastsimi/simple_runtime/surface_child_evidence_v11.py`,
  `src/sastsimi/simple_runtime/surface_child_revalidation_v11.py`,
  `src/sastsimi/simple_runtime/surface_coverage_v9.py`,
  `src/sastsimi/simple_runtime/surface_coverage_v9_read.py`
