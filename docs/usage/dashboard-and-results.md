# 대시보드와 결과 읽기

분석을 시작하거나 중단된 작업을 재개하려면 [분석·재개 안내](../usage.md#analyze)를 먼저 확인하세요. 이 페이지는 저장된 분석을 조회하고 검증된 자료를 내보내는 운영자용 상세 안내입니다. 대시보드는 읽기 전용이며 보고서와 ZIP은 저장된 Gate·manifest·해시 검증을 통과한 자료만 제공합니다.

<a id="dashboard"></a>

## 읽기 전용 대시보드

다른 터미널에서 실행합니다.

```text
sastsimi dashboard
```

브라우저에서 `http://127.0.0.1:8765`를 엽니다. 분석별 주소는 `/analyses/A-001`입니다.

화면에서 다음을 확인할 수 있습니다.

- `개요 / 진행 / Finding∙검증 / Coverage / 아티팩트 / LLM / PoC∙증거∙보고서 / 로그`로 구분된 상세 화면. 공통 요약에는 TRUE Finding, 검증된 PoC, 최종 판정이 저장된 가설, LLM 호출·토큰·비용을 표시합니다.
- 왼쪽 분석 목록의 저장소명, 글자와 색상을 함께 사용한 상태, 실행 시각, 상태별 핵심 수치. 좁은 화면에서는 분석 목록이 서랍으로 전환됩니다.
- 현재 단계·상태·기본 분석 작업 진행률(v2) 또는 기존 checkpoint 진행률과 AST·OpenGrep·CodeQL 상태
- 정적 파일×규칙 검증 수, 후보 총수와 `INCLUDE`·`EXCLUDE`·`UNDECIDED`·`PENDING`·`ERROR`별 수, 심층 분석 진행·완료 수, 가설·Finding 수
- Agent가 확인한 근거·행동·판정 이유 요약 및 검색 가능한 실행 로그
- 단계별 JSON·텍스트 아티팩트와 비밀값을 제거한 LLM 요청·응답
- LLM 호출 상세의 Agent·모델·시각·상태·재시도·토큰·연결 가설/Finding과 응답 결과, 시스템/사용자 프롬프트, 저장 원문 요청/응답 JSON
- 저장된 reference를 기반으로 한 아티팩트 입력→출력 관계 추적과 발표 패키지 ZIP
- 검증된 PoC와 정적·동적 증거의 분리된 목록 및 개별 다운로드
- 허용·제외된 Primitive와 Chaining 부모·자식 관계
- 렌더링/원문 전환이 가능한 Markdown 보고서
- 항목을 선택한 ZIP 또는 `전체 결과 ZIP 다운로드`를 통한 로그·아티팩트·보고서 일괄 저장
- Finding과 기존 Markdown 보고서 링크; 검증된 새 보고서라면 영문·국문·PoC·근거 파일 및 ZIP 다운로드 링크
- Scope Gate의 정책 수집 상태, 출처 URL·개정, 다섯 검토 항목의 판정·인용·이유와 비공개 제보 조건 표시
- Provider별 호출 수·확인된 토큰/비용·비용 미제공 호출 수와 추가 사용량 가능성
- 정적 검사 검증/예상 파일·규칙 수, 엔진별 검증 수, 미검증 파일×규칙 조합과 스캔 불가 Python 제품 파일의 별도 개수·경로·이유, 제외 테스트·대상 밖 JS/TS 제품 코드 및 coverage artifact 참조. 화면의 원장 버튼으로 각 목록을 페이지 단위로 조회

대시보드는 저장 데이터를 읽기만 합니다. 취소·재시도·판정 변경·공개 승인을 수행하지 않으며 기본적으로 외부 네트워크에 공개하지 않습니다.

CLI 진행 로그는 분석별로 data directory의 `logs/<analysis-id>.log`에도
저장됩니다. 새 분석에서 발생한 LLM 요청·응답은 credential, token, host 절대
경로와 숨겨진 추론을 제거한 뒤 아티팩트로 저장합니다. 이전 분석에는 이 항목이
없을 수 있습니다.
CLI와 웹의 정적 검사 세부 단계·수량은 확인된 스캐너 결과와 저장 이벤트만 사용합니다. 일부 과거 분석이나 누락된 계측은 `—` 또는 미기록으로 표시하며 추정값을 만들지 않습니다. 후보는 후보로 표시하고, 확정 Finding 수에는 포함하지 않습니다.

대시보드는 처음에 선택한 탭만 조회합니다. 가설·아티팩트·LLM 호출·로그 목록은 페이지 단위로 불러오고, 긴 아티팩트·프롬프트·저장 JSON은 사용자가 선택했을 때만 조회합니다. 탭 메뉴만 스크롤 고정하며 핵심 결과와 LLM 사용량은 페이지 최상단에서 작은 아이콘과 숫자로 표시합니다. 아이콘에 마우스를 올리거나 키보드 초점을 두면 수치의 의미가 나타납니다.

영문 Markdown은 현재 Finding의 검증된 첨부 manifest에 있을 때만 전체·선택 결과 ZIP의
`reports/en/`에 포함됩니다. 디스크에 남은 단독 `F-NNN.en.md`는 검증 없이 포함하지
않습니다. 보고서 미리보기·다운로드·ZIP은 동일한 Scope Gate 보호를 적용합니다.
아티팩트가 표시 한도를 넘어 일부만 보이면 대시보드가 최소 누락 개수를 알리고
불완전한 전체 ZIP을 차단합니다. 표시된 자료는 선택 ZIP으로 받을 수 있습니다.

짧은 발표용 실행 순서와 고정된 취약 저장소 예시는
[대시보드 발표 시나리오](../dashboard-demo.md)를 참고합니다.

<a id="results"></a>

## 결과·PoC·보고서

```text
sastsimi result A-001
sastsimi poc F-001
sastsimi report show F-001
sastsimi report export F-001 --format markdown
sastsimi report export-group A-001 <group-id> --format json
```

`result`는 분석 상태와 Finding 목록을, `poc`는 실제 실행에 성공한 validated PoC만 보여 줍니다. `report show`는 current Finding의 기존 한국어 Markdown을 보여 주고 `report export`는 파일 위치를 반환합니다. 검증된 새 번들이 있으면 export 출력에 `bundle_path`가 추가됩니다. 첨부파일은 대시보드에서 개별 다운로드하거나 `bundle.zip`으로 받을 수도 있습니다. 기존 `F-NNN.md` 경로와 저장된 과거 보고서는 그대로 유지합니다.

`report export-group`은 `result A-001 --format json`의 `finding_groups`에서 확인한
64자리 `group_id`를 사용합니다. 현재 분석에 속한 둘 이상의 Finding이 같은
입력→위험 동작 경로임이 입증되고, 각 Finding의 보고서·PoC·증거와
대상 commit·CWE·영향 버전·심각도·Scope 판정이 모두 다시 검증될 때만
`reports/<analysis_id>/groups/<group_id>/<archive-sha256>/bundle.zip`을 만듭니다.
JSON 출력의 `bundle_path`는 이 상대 경로입니다. ZIP에는 영문·국문 검토 초안,
`evidence/group-manifest.json`, `members/F-NNN/` 아래의 원본별 첨부가
들어갑니다. 내용이 충돌하거나 오래되었으면 명시적 오류를 반환하고,
일부만 담은 ZIP을 만들지 않습니다. 같은 내용은 같은 경로를 재사용합니다.
대시보드의 `PoC∙증거∙보고서` 탭에서도 유효한 그룹 ZIP과 각 원본 Finding의
보고서·첨부 링크를 함께 볼 수 있습니다. 그룹 초안은 첫 번째 Finding의
검증된 주장만 사용하므로, 제출 전 모든 원본과 영향 범위를 사람이 확인해야
합니다. 그룹화는 취약점 확정이나 정책상 제보 허가를 부여하지 않습니다.
기본 전체 결과 ZIP은 입증된 그룹의 대표 보고서만 최상위 보고서로 선택하고
나머지 그룹 멤버를 `reports/originals/`에 보존합니다. 그룹 근거가 없는 과거
보고서가 함께 있으면 그 보고서는 원래 경로를 유지합니다.
`reports/export-selection.json`과 발표 ZIP의 `presentation/summary.json`에
그룹 적용 범위(`FULL`/`PARTIAL`/`UNVERIFIED`) 및 원본 유지 ID를 기록합니다. 개별 보고서
ID를 명시해 ZIP을 받으면 그룹 요약 대신 요청한 원본만 내보냅니다.

새 Finding의 보고서 번들은 다음과 같이 저장됩니다.

```text
reports/<analysis_id>/F-001.md
reports/<analysis_id>/F-001/report_en.md
reports/<analysis_id>/F-001/report_kr.md
reports/<analysis_id>/F-001/poc.sh
reports/<analysis_id>/F-001/evidence/provenance.json
reports/<analysis_id>/F-001/evidence/stdout.txt  (안전할 때만)
reports/<analysis_id>/F-001/evidence/stderr.txt  (안전할 때만)
reports/<analysis_id>/F-001/manifest.json
reports/<analysis_id>/F-001/bundle.zip
```

`report_en.md`는 GitHub 비공개 security advisory에 옮기기 쉽고 `report_kr.md`는 사람이 읽기 쉬운 표현을 사용합니다. 두 파일 모두 같은 순서로 요약, 영향 대상·테스트 버전, 심각도·CWE, 기술 설명, 재현·PoC, 근거, 영향, Scope Gate·한계, 수정 제안을 담습니다. 현재 분석 경로의 실제 검증된 셸 후보는 `poc.sh`입니다. 번들 형식은 `poc.py`도 허용하지만 현재 분석 경로에서 Python PoC를 자동 선택하지는 않습니다. `evidence/provenance.json`과 `manifest.json`에는 출처 참조·해시를 기록합니다.

두 언어는 같은 검증/예상 수, 미검증 파일×규칙 조합과 스캔 불가 Python 제품 파일의 별도 수·이유·경로 예시, 제외 테스트·대상 밖 제품 코드, coverage artifact 해시를 사용합니다. `PARTIAL` 경고는 정적 검사가 불완전함을 뜻하며, confirmed Finding도 저장소 전체 검사가 끝났다는 뜻이 아닙니다. 전체 경로별 목록은 크기가 제한된 보고서 번들에 넣지 않고 별도 coverage artifact에 둡니다. 과거 coverage 정보가 없는 보고서는 전체 검사 완료를 주장하지 않습니다.

분석한 commit만으로 영향받는 전체 버전 범위, 수정 버전, 심각도나 CVSS를 확정하지 않습니다. 근거가 없는 필드는 `Needs review`/`검토 필요`로 남기며 GitHub 제보 양식에 제출하기 전에 사람이 채워야 합니다. 첨부 PoC에서 민감정보가 가려져 실제 실행된 바이트와 달라졌다면 두 보고서가 이를 알리고 원본·첨부 해시를 구분합니다. 임의의 저장소 파일이나 raw 출력은 첨부하지 않습니다.

외부 정책이 없거나 범위 밖인 결과는 내부 기술 보고서로 생성할 수 있지만 외부 제출·공개가 제한됐다고 표시합니다. 대시보드는 current Finding, Gate와 정책, manifest·첨부 참조·해시를 확인한 후에만 다운로드를 제공하며, 기존 공개 보고서가 제한되는 경우 첨부파일로 이를 우회할 수 없습니다. 과거 단일 보고서에는 새 번들이 자동 생성되지 않습니다. SASTSIMI가 자동으로 외부에 제출하지 않습니다.

이전 버전에서 만든 첨부 묶음에 로컬 `file:` URL이 남아 있으면 묶음과 개별 첨부의 공개 다운로드를 차단합니다. 원본 분석 기록은 삭제하지 않으며, 화면의 저장소·정책·이벤트·로그 URL은 가려서 표시합니다. 해당 묶음이 필요하면 현재 버전으로 안전하게 다시 생성·검증해야 합니다. 컨테이너 내부 `/tmp`만 사용하는 검증된 셸 PoC는 이 차단 대상이 아닙니다.

공개 GitHub 저장소는 분석 시작 시 기본 브랜치의 `.github/SECURITY.md`, 루트 `SECURITY.md`, `docs/SECURITY.md` 순서로 확인하고, 셋 다 없으면 같은 소유자의 공개 `.github` 저장소를 확인합니다. 정책은 분석한 코드 commit과 다른 개정일 수 있어 출처 URL과 Git blob SHA를 따로 기록합니다. 저장소 내 임의의 링크나 GitHub의 비공개 취약점 제보 버튼을 시험·공개 허가로 간주하지 않습니다. GitHub 외 URL과 로컬 Git 경로에서는 이 자동 수집을 지원하지 않아 정책 상태가 `UNVERIFIED`로 남습니다.

Scope Gate는 정책의 자격·규칙(`rules`), 자산 범위(`asset_scope`), 영향 조건(`impact`), 시험 제한(`testing`), 비공개 제보 조건(`reporting`)을 각각 확인합니다. `PASS` 또는 `FAIL`에는 저장된 정책의 정확한 행과 인용이 필요합니다. 검증된 공식 정책에서 다섯 항목이 모두 `PASS`이고 명시적 제한 문구가 없을 때만 예비 판정 `ALLOW`, 명시적으로 근거가 확인된 제외 항목이 있으면 `DENY`, 정책 부재·조회 실패·근거 부족은 `UNCERTAIN`입니다. 명시적 제한이 있으면 Agent가 준수했다고 판단해도 모든 PoC 동작을 자동 증명할 수 없으므로 사람 검토 전에는 `UNCERTAIN`입니다. `ABSENT`나 `UNVERIFIED`는 명시적 금지인 `DENY`와 다릅니다. `ALLOW`도 자동 제보 허가가 아니며 외부 공개 허용이나 자동 제출을 뜻하지 않습니다. 기술적 `TRUE`나 분석 `COMPLETE`/`PARTIAL`만으로도 제보 가능하다는 뜻이 아닙니다.

새 보고서와 대시보드는 정책 수집 상태, 출처, 개정, 항목별 인용과 판단 이유를 보여 줍니다. 예전 기록의 근거 없는 `ALLOW`는 공개 조회에서 제보 불가로 제한됩니다. `sastsimi report export F-001 --format markdown`은 이 경우 기존 원본을 덮어쓰지 않고 `F-001.restricted.md`를 만듭니다. 정책 근거를 못 찾았던 A-005의 두 보고서는 역사적으로 `UNCERTAIN`이며, 새 정책 검토를 적용하려면 별도의 새 분석이 필요합니다. 최종 외부 제출 여부는 사람이 정책과 기술 근거를 직접 검토해 결정합니다.
