# 후보 누락 감사의 읽기 전용 기준선 (2026-10-04)

이 문서는 기존 두 시험 분석의 저장된 DB·보고서와 분석 당시 커밋의 소스 코드만 읽어 확인한 사실이다. 분석을 다시 실행하거나 PoC를 재실행하지 않았다. 두 대상의 checkout은 GitHub 원격이 아니라 `runtime-data/blind-e2e-20261003/fixtures/` 아래 로컬 fixture를 `file:///` 원격으로 가리킨다. 따라서 아래 사례는 내부 회귀용 고정 기준이지, 현재 공개 저장소의 취약점 현황이나 제보 허가를 뜻하지 않는다.

| 시험 분석 | 고정 커밋 | 정적 검사 | 후보 판정 | 저장된 가설·Finding·보고서 | 후보 파이프라인 최종 상태 |
| --- | --- | --- | --- | --- | --- |
| Antony Flask (`7f6b817f4b684cafaf66892788ad2b84`) | `834b5c549c20cf616df967bf20d6d79e8653ffb6` | `FULL` | 20개: INCLUDE 13, EXCLUDE 4, UNDECIDED 3 | 초기 검증 체크포인트 43개, 최종 검증 체크포인트 29개, Finding/보고서 각 11개 | `PARTIAL` |
| GNU Python Vulns (`169fe76abce84fd588c58527f1348b79`) | `6b6d48e3f464477ab6bc2cac529c12f44a7b844c` | `FULL` | 33개: INCLUDE 14, EXCLUDE 11, UNDECIDED 8 | 초기 검증 체크포인트 31개, 최종 검증 체크포인트 20개, Finding/보고서 각 12개 | `PARTIAL` |

DB는 원래 실행 작업 폴더의 각 `runtime-data/blind-e2e-20261003/targets/<target>/data/db/sastsimi.sqlite3`에 있다. 분석 시 사용한 소스는 같은 target의 `data/workspaces/` 아래 고정 checkout에 있다. 이 `runtime-data`는 저장소에 커밋되지 않으므로 새 checkout에서 경로가 바로 존재하지 않을 수 있다. 위 건수는 DB의 `simple_analysis_runs`, `simple_static_candidates`, `simple_runtime_checkpoints`와 보고서 파일을 대조했다. 초기·최종 검증 체크포인트 수의 차이만으로 미처리 건수를 계산할 수는 없다. 앞 단계 판정에 따라 뒤 단계를 건너뛸 수 있기 때문이다.

## 소스로 확인한 비교 사례

아래의 입력→위험 동작은 고정 checkout의 실제 코드로 확인했다. 이는 자동 Finding의 진위나 완전한 공격 영향도를 일괄 승인한다는 뜻이 아니다. 특히 PoC를 이 감사에서 다시 실행하지 않았다.

| 대상 | 서로 구분해야 할 경로 | 입력 위치 → 위험 동작 위치 | CWE | 저장 후보의 상태 |
| --- | --- | --- | --- | --- |
| Antony | `POST /login` | `app.py:33`의 `request.form.username` → 문자열 조립 SQL의 `cursor.execute` `app.py:37` | CWE-89 | FLOW 후보 `ba9eb34bb89a…`: INCLUDE, COMPLETE |
| Antony | `GET /query` | `app.py:54`의 `request.args.username` → 별도 SQL의 `cursor.execute` `app.py:57` | CWE-89 | FLOW 후보 `4d00fe6fc452…`: INCLUDE, COMPLETE |
| Antony | `GET /ping` | `app.py:64`의 `request.args.target` → f-string을 받는 `os.system` `app.py:65` | CWE-78 | FLOW 후보 `7d495d0cf23a…`: INCLUDE, COMPLETE |
| GNU | `GET /sql_vuln` | `app_vulns.py:46`의 `request.args.username` → 문자열 조립 SQL의 `c.execute` `app_vulns.py:53` | CWE-89 | FLOW 후보 `774a5c750328…`: INCLUDE, COMPLETE |
| GNU | `POST /rce_vuln` | `app_vulns.py:85–86`의 JSON `cmd` → `subprocess.run(..., shell=True)` `app_vulns.py:93` | CWE-78 | FLOW 후보 `2cb2e5dc13c0…`: INCLUDE, COMPLETE |
| GNU | `GET /fetch_vuln` | `app_vulns.py:158`의 `request.args.url` → 목적지 제한 없는 `requests.get` `app_vulns.py:164` | CWE-918 | HINT 후보 `bfc7a42196f7…`: INCLUDE, INCONCLUSIVE, 후보→가설 링크 0개 |

Antony의 `/login`과 `/query`는 CWE와 SQL 실행 API가 같아도 입력 라우트와 SQL sink 위치가 다르다. 후보나 Finding을 CWE·파일명만으로 합치면 이 두 경로를 잘못 병합할 수 있다.

GNU의 `/fetch_vuln`은 반대 방향의 예다. 저장된 HINT 후보는 `INCONCLUSIVE`이고 후보→가설 링크가 없지만, 자유 탐색 가설 `hypothesis-789c2268655f7432121f78c3c6916c7e`에서 `data/reports/169fe76abce84fd588c58527f1348b79/F-011.md`가 생성됐다. 이 보고서는 CWE-918, 로컬 루프백 PoC의 종료 코드 0, 기술 게이트 `ACCEPT`를 기록한다. **후보 링크만 조회하면 이미 생성된 Finding을 미탐으로 잘못 셀 수 있다.** 감사 도구는 자유 탐색 결과도 별도 출처로 대조하고, 연결을 추정해 만들어 넣지 않아야 한다.

새 읽기 전용 감사기를 이 두 저장 DB에 적용하면, Antony `/login`과 GNU `/fetch_vuln` 모두 정적 검사 근거는 읽히지만 전체 후보 파이프라인이 끝나지 않아 `INCOMPLETE / PIPELINE_UNFINISHED`다. GNU 자유 탐색 가설 ID를 수작업으로 연결하여 다시 조회해도 `INCOMPLETE / FINDING_EVIDENCE_UNVERIFIED`다. 저장된 `VERIFICATION_FINAL_DONE`의 단계 버전은 2이고 현재 코드는 3을 요구하므로 과거의 F-011 파일을 **현재 검증 완료**로 승격하지 않는다. 이는 보고서 존재나 PoC 종료 코드만으로 최신 근거의 유효성을 단정하지 않는 보수적 판정이다. 두 조회는 SQLite `mode=ro`로 수행했고 새 분석·LLM 호출·DB 변경은 없었다.

## 수치 해석 제한

후보 수, 가설 수, Finding 수, 보고서 수는 서로 다른 단위다. 파일×규칙 검사 횟수도 후보 수와 동일하지 않다. 저장된 보고서 제목을 라우트별로 분류하면 Antony의 11개는 `/ping` 6개, `/query` 3개, `/login` 1개, `/deserialize` 1개이고, GNU의 12개는 `/sql_vuln` 5개, `/rce_vuln` 3개, `/xss_vuln` 3개, `/fetch_vuln` 1개다. 이 분포는 반복 보고의 실마리일 뿐, 라우트별 파일을 자동으로 동일 근본 원인이라고 판정한 결과가 아니다.

**두 저장 분석 모두 후보 파이프라인 상태가 `PARTIAL`이다.** 정적 검사 `FULL`만으로 전체 검증이 끝났다고 볼 수 없다. 이 데이터로 `탐지 N건 / 정답 M건` 형태의 탐지율·미탐률·오탐률을 계산하거나 두 저장소에서 미탐이 해소됐다고 주장하지 않는다. 분모를 만들려면 고정 커밋의 개별 입력→sink 사례를 사람이 검토하고, 자유 탐색 Finding까지 대조하며, 해당 분석의 미완료·실패 범위를 해결하거나 별도로 `INCOMPLETE`로 표시해야 한다. 보안 정책·제보 가능성 역시 이 fixture 결과로 판단하지 않는다.
