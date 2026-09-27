# Finding별 이중 언어 보고서와 첨부파일 설계

## 목적과 성공 기준

최종 Finding을 검토하거나 비공개 제보할 때 보고서 본문에서 PoC와 근거를
수작업으로 분리하지 않아도 되게 한다. 새 분석의 각 보고 가능한 Finding은
같은 검증 근거에서 영문 제보용 보고서, 국문 검토용 보고서, PoC, 근거 파일을
만들고 대시보드에서 개별 파일과 ZIP을 내려받을 수 있어야 한다. 기존 분석
파이프라인과 Agent 역할, 단일 Markdown 보고서, 저장된 옛 결과는 유지한다.

영문 파일은 GitHub 비공개 보안 제보 양식에 맞춰 복사하기 쉬운 구조로
제공한다. 그러나 테스트한 커밋만으로 전체 영향 버전 범위, CVSS 심각도,
패치 버전을 확정하지 않는다. 확인되지 않은 필수 입력은 Needs review로
표시한다. 파일 생성은 외부 제보 허가를 뜻하지 않으며 Scope Gate 결과와
사람의 최종 검토 필요성을 두 언어에 모두 표시한다.

## 선택한 방식과 대안

기존 Reporter 호출 한 번에서 영어·한국어 설명을 구조화된 응답으로 받고,
공통의 검증된 사실과 참조를 결정적 템플릿 두 개에 주입한다. 두 언어 파일은
같은 섹션 순서, Finding ID, 테스트 커밋, PoC/근거 해시, Gate 결론을 가진다.
기존 보고서를 별도 LLM 호출로 번역하면 비용과 사실 불일치 위험이 증가한다.
기존 Markdown 전체를 기계적으로 번역하면 기술 의미와 제보 형식을 검증하기
어려워 둘 다 채택하지 않는다.

Reporter의 목적과 앞선 Agent 흐름은 바꾸지 않는다. 생산 경로의 기존
ReportContent v1 아티팩트는 계속 읽고, 신규 응답은 명시적인 bilingual v2
형식으로 검증·저장한다. 단순 런타임 Reporter도 현재 초안 필드에 대응하는
영어·한국어 필드를 하나의 JSON 응답으로 받는다. 이미 완료된 과거 보고서에
LLM을 몰래 다시 호출해 번역하지 않는다.

## 파일 구성과 데이터 흐름

새 보고서의 저장 형태:

    reports/<analysis_id>/F-002.md
    reports/<analysis_id>/F-002/report_en.md
    reports/<analysis_id>/F-002/report_kr.md
    reports/<analysis_id>/F-002/poc.sh
    reports/<analysis_id>/F-002/evidence/provenance.json
    reports/<analysis_id>/F-002/evidence/stdout.txt       (안전할 때만)
    reports/<analysis_id>/F-002/evidence/stderr.txt       (안전할 때만)
    reports/<analysis_id>/F-002/manifest.json
    reports/<analysis_id>/F-002/bundle.zip

PoC 파일의 확장자는 실제 검증·실행된 후보의 언어를 따른다. 현재 PoC 실행
경로는 셸 스크립트이므로 기본 파일명은 poc.sh이다. Python 후보가 실제로
검증된 경우에만 poc.py를 사용한다.

공통 bundle 생성기는 두 보고 경로의 검증된 입력만 받는다. 생산 경로는 현재
CurrentReport의 exact closure와 기존 내보내기 경계를, 단순 런타임은
성공한 Reporter checkpoint, Finding/Technical Gate/validated PoC 참조를
사용한다. PoC는 실행된 후보의 원본 해시와 출처를 manifest에 기록하되,
파일에는 기존 redaction 정책을 통과한 내용만 넣는다. 가림 처리로 코드가
바뀌면 두 보고서와 manifest에 알리고 원본과 동일하게 실행된 PoC라고
주장하지 않는다.

evidence/provenance.json에는 테스트 커밋, 정확한 아티팩트 참조와 해시,
실행 명령·종료 코드, 검증/게이트 상태를 기록한다. stdout/stderr는 참조를
검증하고 민감정보를 제거할 수 있을 때만 별도 파일로 넣는다. 임의의 raw
아티팩트나 저장소 전체 파일을 복사하지 않는다. manifest.json은 번들
버전, 각 파일의 SHA-256, 출처 참조, redaction 상태를 담는다. ZIP은
manifest가 가리키는 파일만 정해진 순서와 경로로 포함한다.

두 Markdown은 동일한 섹션을 같은 순서로 갖는다: 요약, 영향 대상·테스트
버전, 심각도·CWE, 기술 설명, 재현 방법·PoC, 근거, 영향, Scope Gate·한계,
수정 제안. 한국어는 읽기 쉬운 설명으로, 영어는 GitHub advisory에 옮기기
쉬운 문장으로 표현한다. 확인되지 않은 버전 범위·심각도·패치 버전은
미확인으로 표기하고 추측으로 메우지 않는다. 코드 위치와 증거 참조는
양쪽에서 동일한 검증을 거친다.

## 게시, 다운로드, 실패 처리

파일별로 임시 파일에 기록한 뒤 교체하고 manifest를 마지막에 게시한다.
manifest가 없거나 파일 해시·Finding identity·참조가 맞지 않으면 번들을
완성된 것으로 표시하지 않는다. 완료된 checkpoint를 resume할 때는 같은
LLM 작업을 중복 실행하지 않고 저장된 산출물의 상태를 확인한다.

대시보드는 기존 단일 Markdown 경로를 유지한다. 추가 다운로드는 현재
Finding, Technical Gate, Scope Gate, report checkpoint와 manifest의
정확한 참조를 다시 확인한 뒤 허용된 상대 파일명만 제공한다. 기존
safe_public_report가 원문을 제한하는 경우 새 첨부로 우회할 수 없다.
응답에는 올바른 MIME 형식, Content-Disposition: attachment, nosniff,
no-store를 설정한다. 경로 순회, symlink/reparse, 오래된 보고서, 해시
불일치, 민감정보 감지 시 명확하게 실패하고 raw 파일을 내보내지 않는다.
CLI의 기존 단일 보고서 출력 계약도 유지하며 새 번들 경로를 추가로 안내한다.

## 검증과 실제 분석

단위 테스트는 v1 호환성, bilingual v2 스키마와 근거 검증, 동일 섹션/참조,
미확인 버전·심각도, 셸 확장자, redaction, 파일 해시와 ZIP 일치,
부분 실패의 비게시를 확인한다. 통합 테스트는 두 보고 경로의 생성·resume,
대시보드 개별/ZIP 다운로드, 허용되지 않은 파일명·경로 순회·오래된 Finding·
Scope Gate 제한을 확인한다. 기존 보고서/대시보드 테스트와 전체 테스트,
정적 검사도 실행한다.

구현과 PR 검증 후에는 공개 Dify 저장소의 고정 커밋을 로컬 입력으로
분석을 시작한다. 대상 서비스에 직접 요청하거나 외부 제보를 보내지 않는다.
GitHub 연결·Docker·OpenGrep 접근을 실행 전 점검하고, 환경 권한으로
실행이 막히면 이유와 재현 명령을 기록한다. 분석 시작과 완료는 구분해
보고한다.
