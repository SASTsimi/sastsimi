# 후보 발견 실제 시험 (2026-09-29 KST)

두 저장소를 각각 격리된 `runtime-data`에서 분석했다. 아래 수치는 저장된 DB와 정적 커버리지 artifact를 읽기 전용으로 대조한 결과다. 후보와 가설은 취약점 판정이 아니며, 확인된 Finding이나 외부 제보는 없다.
`runtime-data`의 DB·원본 artifact는 로컬 증거이며 Git에 포함하지 않는다. 이 문서에는 고정 commit과 집계값만 남긴다.

## python-multipart

- 대상: `https://github.com/Kludex/python-multipart.git`의 고정 commit `212819d3b8f4c6b1e6f210232098681a5d8d8a56`.
- 분석 ID: `A-001` (`4089b27ca7164a97a3a1aafd2f737429`). 정적 상태 `FULL`; 파일·규칙 조합 **150/150 검증**, 미검증 0.
- 정적 후보 **1개**: `UNDECIDED` 1, 나머지 결정 0. 심층 분석 상태는 `RUNNING` 1이다. 등록 가설 **9개** 중 1개는 최종 검증 `FALSE`, 나머지는 미완료다. Finding **0개**.
- 마지막 `PRO_CON_DONE` 체크포인트는 `LLM_TOKEN_BUDGET_EXHAUSTED`로 실패했고, 표시 상태는 `PAUSED`다. 기록된 LLM 호출 12건의 누적 사용량은 **277,831토큰**이다.
- 이 실행 뒤 OpenGrep 규칙 YAML이 바뀌었다. 현재 코드의 정적 범위 지문 검사는 기존 실행과 다른 규칙을 허용하지 않으므로 **현재 작업트리에서 이 ID를 그대로 재개할 수 없다**. 저장된 결과를 새 규칙 범위의 완료 근거로 쓰지 않는다.

근거: `runtime-data/python-multipart-candidate-live/db/sastsimi.sqlite3`, `runtime-data/python-multipart-candidate-live/artifacts/sha256/77/f2c6099c417ad8f705786a494ecd68e4b843f08491c859f766220bd8f9b008`(커버리지), 같은 데이터 디렉터리의 `workspaces/a13a8930ab5049a69e833f428d9a2dec/.sastsimi-ready.json`(고정 commit). 규칙 차이는 `config/static-analysis/candidate-v1/opengrep/rules.yml`의 작업트리 diff로 확인했다.

## Dify

- 대상: `https://github.com/langgenius/dify`의 고정 commit `bfd5636bf080cea83515d649e70f36dfa6c0f0d8`.
- 첫 격리 실행은 Windows의 긴 파일 경로 때문에 Git checkout에서 실패했다. 특정 저장소 경로를 예외 처리하지 않고 Git checkout에 `core.longpaths=true`를 적용한 뒤 두 번째 격리 실행에서 고정 commit checkout에 성공했다. 실패한 첫 실행 데이터는 삭제하지 않았다.
- 분석 ID: 격리된 별도 DB의 `A-001` (`041efdeee36b4ee4900b2538f23c93e0`). 제품 Python 파일 **2,324개**를 AST로 파싱했고 파싱 오류는 0이다. AST 사실 목록은 절단됐으므로 이 수치만으로 모든 사실이 보존됐다고 주장하지 않는다.
- 당시 선택된 Python 범위의 파일·규칙 조합 **23,240/23,240 검증**, 미검증 0. AST 사실 목록은 10,000건 상한에서 절단됐으며, 당시 범위에서 제외된 테스트 경로 **4,784개**, 범위 밖 비Python 제품 파일 **4,447개**가 기록됐다. 따라서 실행의 정적 처분은 `PARTIAL`이며 저장소 전체의 정적 검사 완료가 아니다.
- OpenGrep 원본 실행에는 `PartialParsing` 경고 114건(고유 Python 파일 87개)이 있었지만, 선택형 Semgrep 재검사 11개 묶음이 성공해 최종 파일×규칙 누락은 0건이다. CodeQL 실행 오류도 0건으로 기록됐다. 이 재검사 성공은 AST 사실 절단이나 비Python 제품 코드까지 검증했다는 뜻은 아니다.
- 정적 후보 **1,392개**: `INCLUDE` 10, `EXCLUDE` 9, `UNDECIDED` 5, `PENDING` 1,368, `ERROR` 0. 등록 가설과 Finding은 각각 **0개**다.
- 시험용 누적 한도 **50,000토큰** 아래에서 호출 전 검사는 통과했지만, 마지막 Discovery 호출 뒤 기록된 사용량이 **63,212토큰**이 됐다(앞선 Recovery 9,030 + Discovery 54,182). 초과분 13,212토큰은 한 번의 호출에서 발생했다. 다음 호출 전에 `LLM_TOKEN_BUDGET_EXHAUSTED`로 멈춰 표시 상태는 `PAUSED`다. 이 한도는 사후 사용량을 검사하는 소프트 한도이며, 50,000토큰 이내 사용을 보장한 시험은 아니다.
- 이후 `file_scope.py`의 범위 분류가 바뀌어 생성 코드 3개가 기존 `제외 테스트`에서 `범위 밖 제품 코드`로 재분류됐고, 후보의 서로 다른 매치 근거를 더 정확하게 구분하도록 ID 계산도 보강했다. Python 검사 대상 파일은 같지만 범위 지문이 달라질 수 있으므로 **현재 코드에서 같은 ID의 재개를 검증 완료로 간주하지 않는다**. 범위 지문이 다르면 새 분석 ID가 필요하다. 기존 23,240/23,240과 후보 1,392건은 당시 코드·범위의 관측값이며, 현재 코드로 새로 실행한 결과 수치를 뜻하지 않는다.

근거: `runtime-data/dify2/db/sastsimi.sqlite3`, `runtime-data/dify2/artifacts/sha256/80/ab5c247ec3f3f87e3930c4265c157d53796a3ab0461630acb126cc3309fafb`(커버리지). 현재 범위 분류 변경은 `src/sastsimi/static_analysis/file_scope.py`의 작업트리 diff로 확인했다.

## 확인 방법과 한계

두 SQLite DB를 `sqlite3 -readonly`로 조회해 분석 행, 후보 결정, 가설, 체크포인트와 LLM 시도별 토큰을 대조했다. 위 커버리지 artifact JSON의 `expected_count`, `verified_count`, `ast_parsed_file_count`, `excluded_test_files`, `out_of_scope_product_files`도 확인했다. 대상 checkout의 `git rev-parse HEAD`와 저장된 commit을 대조했다.

이 문서 작성 시 Discovery 집중 테스트 **12개 통과**를 확인했다. 이후 정적 분석·범위 회귀에서는 **617개 통과·16개 건너뜀**과 변경된 기대값 1개를 확인해 해당 기대값을 수정하고 재검증했다. 최종 전체 테스트는 **4,180개 통과·28개 건너뜀**이며 보고서 fixture의 Pydantic 직렬화 경고 42개가 있었다. Ruff 검사·서식, mypy(465개 소스 파일), 문서 링크 및 정적 규칙 manifest 검증도 통과했다. 이 기록을 위해 LLM 호출, `resume`, 새 정적 검사, PoC 또는 제보는 실행하지 않았고 기존 데이터도 삭제하지 않았다.
