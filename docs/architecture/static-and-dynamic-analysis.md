# 정적 분석과 동적 재현

## 구현된 책임

Repository Loader는 URL 또는 로컬 경로의 저장소를 고정 commit으로 준비하고 추적 파일을
기준으로 Python 제품 파일과 실행에 필요한 package manifest를 식별합니다. 정적 코드 범위는
제품용 `.py` 파일뿐입니다. 테스트 전용 파일은 제외 경로·이유를 별도 기록하며 검사 성공으로 세지 않고, 테스트 포함 옵션은 제공하지 않습니다. 배포 manifest가 제품 진입점으로 선언한 `tests/` 경로는 제품 코드로 검사하고 PoC 소스 범위에도 포함합니다. manifest가 손상되어 구분할 수 없는 파일은 미지원 제품 범위로 보존해 전체 완료를 주장하지 않습니다. AST, OpenGrep과 활성화 조건을 충족한
CodeQL 결과를 `StaticFactBundle`로 정규화합니다.
SimpleRuntime의 OpenGrep은 로컬 규칙을 제품 파일 묶음별로 실행하며 고정 commit의 선택된 제품 파일과
규칙 언어를 결합한 `파일 × 규칙` 커버리지 artifact를 남깁니다. 도구가 0건을 찾았더라도
파일을 실제 검사하고 해당 규칙을 건너뛰지 않았으며 파싱 오류가 없을 때만 검증된
조합으로 셉니다. OpenGrep 실패 뒤에도 AST와 설정된 CodeQL 결과를 독립 수집합니다.
선택형 Semgrep CE는 미검증 조합만 동일한 로컬 규칙으로 재검사합니다. 정적 검사
전체 종료 시각은 없고, 호출별 제한과 유한한 묶음 분할·재시도만 적용합니다. 검증된 조합의 원본 결과만 후보로 등록합니다. 후보는 입력 지점, 확인된 source→sink 흐름, 단순 도구 힌트로 나누고 Discovery가 작은 배치로 선별한 뒤 기존 가설 흐름에 연결합니다. 서로 다른 힌트를 임의의 흐름으로 합치지 않으며, 미검증 조합의 raw hit는 검증된 후보가 아닙니다. 유효한 검증 부분과 정확한 coverage artifact가
있으면 누락된 Python 파일·규칙을 남긴 `PARTIAL` 결과로 진행하며, 증거 무결성이
깨졌거나 검증된 조합이 전혀 없으면 `BLOCKED`입니다. 현재 CodeQL 질의는
Python만 대상으로 하며 OpenGrep 규칙의 커버리지 대체 증거가 아닙니다.
비Python 파일은 Python 파일×규칙 커버리지 분모에 넣지 않습니다. JS/TS 제품 코드는 대상 밖 코드로 경로·이유를 별도 표시하며, 혼합 저장소의 전체 결과는 `PARTIAL`로 제한합니다.
검증/예상 수와 전체 누락은 별도 coverage artifact가 보유하며 대시보드는 이를
페이지 단위로 보여 줍니다. 영문·국문 Finding 보고서는 같은 간략한 coverage
수치·이유·해시와 `PARTIAL` 경고를 표시하고 큰 목록은 복제하지 않습니다.

동적 재현은 RepositoryProfile, 코드 근거와 Verification 요구를 이용해 환경 recipe와
PoC 후보를 만들고 Docker에서 실행합니다. 작성된 script는 PoC 후보이며, 같은 attempt와
환경에서 실행되어 가설을 지지한 경우에만 validated PoC가 됩니다.
Pro·Con의 `requested_paths`는 고정 commit의 검증된 PoC 소스 manifest로 제한해 조회하고,
본문은 변경될 수 있는 작업 폴더 파일이 아닌 해당 commit의 일반 Git blob에서 읽습니다.
읽은 본문과 거부 사유를 exact artifact로 저장한 뒤 PoC 후보 생성·재생성에 전달합니다.
경로 이탈·심볼릭 링크·비추적 파일을 읽지 않고, PoC용 본문 총량은
원본 128,000바이트·최대 32개 요청으로 제한합니다. JSON 변환·민감정보 제거 후
PoC 프롬프트에 들어가는 source artifact는 96,000바이트 이하로 다시 제한하고,
Pro·Con·초기 Verification 근거도 앞쪽에 배치합니다.

## 코드 위치

- 저장소 준비와 profile: `src/sastsimi/static_analysis/repository_loader.py`,
  `src/sastsimi/static_analysis/repository_profile.py`
- 기존 AST·OpenGrep·CodeQL 구성 요소: `src/sastsimi/static_analysis`
- SimpleRuntime 정적 실행·커버리지·대체 검사:
  `src/sastsimi/simple_runtime/bootstrap_stages.py`,
  `src/sastsimi/simple_runtime/static_coverage.py`,
  `src/sastsimi/simple_runtime/semgrep_fallback.py`
- 정적 실행 구성: `src/sastsimi/composition/simple_runtime_composition.py`
- 후보 정규화·선별: `src/sastsimi/simple_runtime/candidates.py`,
  `src/sastsimi/simple_runtime/discovery.py`
- PoC 검사: `src/sastsimi/simple_runtime/poc.py`
- 요청 소스 경계: `src/sastsimi/simple_runtime/retrieval.py`,
  `src/sastsimi/simple_runtime/facts.py`
- Docker 실행: `src/sastsimi/simple_runtime/portable_docker.py`,
  `src/sastsimi/sandbox/docker_adapter.py`
- 동적 stage: `src/sastsimi/simple_runtime/stages.py`

## 지켜야 하는 계약

- 도구 미설치와 실행 실패를 취약점 없음으로 바꾸지 않습니다.
- CodeQL은 승인된 실행량·출력 제한 조건을 만족한 profile에서만 활성화합니다.
- PoC에 host 경로, 외부 URL, 선언되지 않은 입력이나 민감정보를 허용하지 않습니다.
- recipe, image digest, container와 PoC 실행 결과를 같은 attempt에 연결합니다.
- `DISPROVED`는 실제 반증 근거가 있을 때만 판정에 사용합니다.

## 현재 제한

외부 도구 설치 여부와 실제 활성화 조합은 `sastsimi setup`과 capability 확인 결과에
따릅니다. 운영 검증되지 않은 언어와 build 방식은 자동으로 지원된다고 간주하지 않습니다.
