# Gate·Chaining·Finding·보고서

## 구현된 책임

final TRUE와 validated PoC가 준비되면 CWE Labeling이 현재 Verification에 연결된 CWE를
만듭니다. Technical Gate는 근거·PoC·CWE의 연결성을 검토하고, 보완이 필요하면
`REVISE`와 정확한 보완 요청을 저장한 뒤 같은 가설의 PoC 후보부터 다시 실행합니다.
새 Docker 실행 결과로 최종 Verification과 CWE를 갱신한 뒤 Gate를 재검토합니다.
Gate 결정은 가설당 최대 세 번이며, 마지막까지 `REVISE`이면 `INCONCLUSIVE`,
명시적인 `REJECT`이면 제보 불가로 종료합니다. 두 경우 모두 Finding·보고서를
만들지 않습니다.

PoC 실행 자체는 끝났지만 보강 상한까지 관찰 근거가 부족한 경우도
`INCONCLUSIVE`로 종료하고 Final Verification·CWE·Gate·Finding·Reporter를
건너뜁니다. 이는 Docker·Provider 실행 실패를 미확정으로 바꾸는 규칙이 아닙니다.

공개 GitHub 저장소는 bootstrap에서 기본 브랜치의 `.github/SECURITY.md`, 루트
`SECURITY.md`, `docs/SECURITY.md` 순서와 같은 소유자의 공개 `.github` 저장소를
확인합니다. 공식 출처의 전체 본문과 수집 상태·Git blob SHA를 분석별 불변 snapshot에
저장합니다. 분석 대상 코드 commit과 정책 개정은 별도로 기록하며, `resume`은 저장된
snapshot을 다시 사용합니다. GitHub 외 저장소, 정책 부재 또는 조회 실패는
`UNVERIFIED`·`ABSENT`·`FETCH_FAILED`로 기록하고 Scope Gate는 `UNCERTAIN`입니다.

Rule Scope Gate Agent는 공식 정책의 자격·규칙, 자산 범위, 영향, 시험 제한, 제보
조건을 항목별로 검토하고 각 `PASS`/`FAIL`에 정확한 정책 행과 인용을 붙입니다.
Runtime은 snapshot의 분석·저장소 결속, 본문 hash와 Git blob SHA, 출처 및 전체
본문 포함 여부를 검사하고 인용을 원문과 대조합니다. 실제 검증된 PoC 코드의
시험 방식 인용도 대조하며, 정책의 명시적 제한 후보 문장을 누락한 판정은
`UNCERTAIN`으로 제한합니다. 제한 문구가 있으면 PoC의 모든 동작이 이를 지키는지
자동으로 증명하기 어려우므로, Agent가 준수한다고 판단해도 사람 검토 전에는
`UNCERTAIN`입니다. 명시적 제한이 없고 다섯 항목이 모두 근거 있는 `PASS`일 때만
예비 판정 `ALLOW`, 명시적으로 인용된 제외는 `DENY`, 근거가 모자라면
`UNCERTAIN`으로 결정합니다. Agent가 제안한 최종 상태를
그대로 믿지 않습니다. Scope Gate 결과는 기술적 `TRUE`를 `FALSE`로 바꾸지
않으며, `DENY`와 `UNCERTAIN`에서도 제한된 내부 Finding·보고서를 만들 수 있습니다.
자연어 정책과 PoC가 모든 조건에서 일치하는지는 자동으로 증명할 수 없으므로
`ALLOW`도 자동 제보 허가가 아니며 사람의 최종 검토가 필요합니다.

Primitive Admission Runtime은 저장된 Gate 결과를 정해진 허용 규칙에 적용합니다.
Chaining Agent는 허용된 TRUE Primitive와 HOLD Primitive의 조건을 조합해 새 가설을
제안하고, 자식 가설은 정적 근거 조립부터 전체 검증을 다시 수행합니다.

Reporter Agent는 upstream artifact에 존재하는 사실만 사용해 한 번의 구조화된
응답으로 영어·한국어 설명을 만듭니다. Runtime이 공통 검증 사실을 같은 순서의
아홉 섹션에 주입해 영문 제보 초안 `report_en.md`와 국문 검토용
`report_kr.md`를 만들고, 검증된 PoC·근거 파일과 함께 게시합니다. 기존 한국어
`F-NNN.md` 경로도 유지하며, 저장된 예전 단일 보고서를 새 Agent 호출로
몰래 재작성하지 않습니다. 정책 수집 상태·출처·개정, 항목별 인용과 누락된
근거도 보고서와 대시보드에 표시합니다. 미확정 영향 버전·심각도·패치 버전은
사람 검토 항목으로 남깁니다.
`ALLOW`는 비공개 제보의 정책 조건을 뜻하며 외부 공개 허가는 별도로 확인해야 합니다.
공개 조회 경로는 Gate와 정책의 exact reference를 다시 확인합니다. 이전 기록의 검증
되지 않은 `ALLOW`는 제보 가능한 결과로 내보내지 않으며 제한된 Markdown을 별도
`.restricted.md` 파일로 export합니다. 기존 내부 원본은 그대로 보존합니다.

## 검증된 Finding 묶음

Finding 생성 후의 **읽기 전용 표시 투영**은 원본 Finding과 보고서를 변경하지
않습니다. 현재 `FINDING_DONE`의 TRUE·검증된 PoC·승인된 Technical Gate와
원본 제안·CWE·후보 출처를 다시 확인합니다. AST manifest의 파일별 SHA-256과
현재 고정 workspace의 실제 Python 파일이 일치할 때만, AST에서 해당 요청
입력의 키·함수/route·def-use 경로·분기·위험 호출의 위치와 인자 번호를
식별합니다. CodeQL 경로가 있으면 실제 입력 줄과 끝 위험 호출 줄이 경로에
존재하는지도 확인합니다. 동일한 전체 anchor만 버전이 붙은 안정적인 그룹
ID로 묶고, 대표는 가장 작은 기존 `F-NNN`입니다. 다른 입력 키·분기·위험
호출 또는 모호한 경로는 합치지 않습니다. 지원되지 않는 CWE/표현과 예전
기록의 부족한 출처는 `GROUPING_UNDETERMINED` 단독 항목으로 남습니다.

`finding_count`는 원본 Finding 수, `finding_group_count`는 입증된 그룹과
미확정 단독 항목을 합친 표시 묶음 수, `finding_group_undetermined_count`는
근거 부족·미지원 패턴의 단독 항목 수입니다. 현재 resolver는 CWE-78의
직접 import된 Flask `request`와 단일 정적 Flask route, 제한된 명령 호출만
지원합니다. 대시보드는 현재 보고서를 열 수 있는 Finding만 묶음 투영하므로
보고서 생성 전에는 원본 Finding 수와 표시 묶음 수가 다를 수 있습니다.
독립 저장소의 이전 시험 기록을 읽기 전용으로 재생했을 때 Antony Flask는
원본 11건→표시 6묶음(6건 동일 경로, 미확정 단독 5건), Python Vulns GNU는
원본 12건→표시 10묶음(3건 동일 경로, 미확정 단독 9건)이었습니다. 이는
두 시험 기록의 표시 결과이지 전체 중복 탐지율이 아닙니다. DB 해시는
재생 전후 동일했습니다. 각 원본 `F-NNN`의 PoC·국문/영문 보고서·직접 URL·
ZIP 포함 여부는 유지됩니다. 그룹은 취약점 확정 판정이나 외부 제보 허가가
아니고 `COMPLETE`/`PARTIAL`에도 영향을 주지 않습니다.

## 코드 위치

- CWE·Gate·Finding·Reporter stage: `src/sastsimi/simple_runtime/stages.py`
- 공식 GitHub 정책 조회: `src/sastsimi/simple_runtime/github_policy.py`
- 정책 근거 검증·공개 조회: `src/sastsimi/simple_runtime/scope_policy.py`
- Primitive와 Chaining: `src/sastsimi/simple_runtime/chaining.py`
- 보고서 저장: `src/sastsimi/reporting/markdown_export.py`
- 영·국문 렌더링과 첨부 검증: `src/sastsimi/reporting/bilingual_bundle.py`,
  `src/sastsimi/reporting/bundle_files.py`
- Finding ID: `src/sastsimi/reporting/finding_display_id.py`
- 흐름 anchor·보수적 묶음·조회 투영: `src/sastsimi/simple_runtime/finding_flow.py`,
  `src/sastsimi/simple_runtime/finding_groups.py`,
  `src/sastsimi/simple_runtime/finding_group_projection.py`
- 읽기 전용 조회: `src/sastsimi/dashboard/query.py`

## 지켜야 하는 계약

- Gate는 CWE를 생성하거나 수정하지 않고 정합성만 검토합니다.
- Technical `REVISE`는 같은 가설의 PoC 후보·실행·최종 Verification을 보완하는
  흐름입니다. Gate 요청과 고정 commit의 제한된 source artifact를 exact reference로
  전달하고, 재시작 시 이전 PoC 이후 checkpoint를 원자적으로 무효화합니다.
- TRUE Finding·TRUE Primitive·보고서는 현재 Technical Gate checkpoint와 artifact가
  모두 `ACCEPT`일 때만 만들거나 조회합니다. 실행 오류는 Gate의 `REJECT`나
  `INCONCLUSIVE`로 바꾸지 않습니다.
- 금지된 시험 방법으로 얻은 근거는 Primitive 재료로 사용하지 않습니다.
- Report는 새 보안 사실을 만들지 않고 exact upstream reference만 표현합니다.
- 공식 정책의 정확한 출처와 인용이 없으면 외부 제보 허가를 확정하지 않습니다.
- 민감정보 제거 실패나 stale upstream 결과가 있으면 Markdown을 최신 보고서로 내보내지 않습니다.
- 번들은 manifest·정확한 Finding/PoC/실행 근거·파일 해시가 모두 맞을 때만 현재
  결과로 게시·다운로드합니다. 기존 공개 보고서가 제한되면 첨부로 우회하지 않습니다.

## 현재 제한

외부 제출과 공개 승인은 자동화하지 않습니다. 보고서 이후 검토·수정·제출은 사람의
권한입니다. HTML과 PDF는 필수 출력 형식이 아니며 Markdown이 현재 기본입니다.
