# 데이터 계약과 저장

## 구현된 책임

공통 계약은 Pydantic model로 정의하고 JSON schema로 내보냅니다. 핵심 연결 단위는
`StoredDataRef`이며 record ID뿐 아니라 kind, schema version과 content hash를 함께
확인합니다.

`SimpleRuntime`은 분석 실행, stage checkpoint, artifact, Agent activity, 사람이 보는
분석 ID와 Finding ID를 SQLite에 저장합니다. 보고서 파일은
`<data-dir>/reports/<analysis_id>/F-NNN.md`에 저장하며 데이터베이스의 exact Finding과
연결합니다. 새 Finding은 호환성을 위해 이 파일을 유지하면서
`<data-dir>/reports/<analysis_id>/F-NNN/` 아래에 `report_en.md`,
`report_kr.md`, 실제 검증된 언어의 `poc.sh` 또는 `poc.py`,
`evidence/provenance.json`, 안전하게 가린 출력 파일, `manifest.json`과
`bundle.zip`도 게시합니다. 기존 v1 보고서는 자동 재번역하거나 다시 실행하지
않습니다.

번들 manifest는 각 파일의 상대 경로, media type, 크기, SHA-256과 exact artifact
reference를 기록합니다. 파일과 ZIP을 확인한 뒤 manifest를 마지막에 게시하며,
checkpoint에는 선택적 manifest·ZIP reference를 보관합니다. 열람 시 현재 Finding,
Technical Gate, Scope Gate와 checkpoint 결속 및 파일·아티팩트 해시를 다시 확인합니다.
경로 순회·reparse/symlink·민감정보 가림 실패 또는 제한된 공개 보고서를 첨부파일로
우회하는 요청은 거부합니다. ZIP은 manifest에 기록된 허용 파일만 포함합니다.
공식 정책 본문과 출처·개정·수집 상태는 별도 exact artifact로 저장하고 분석 실행이
그 snapshot을 가리킵니다. 공개 `report`·export·대시보드는 읽을 때 Gate와 정책
출처를 다시 검증합니다. 이전 기록의 검증되지 않은 `ALLOW`에 대한 제한된 export는
원본을 덮어쓰지 않는 `F-NNN.restricted.md` 파일입니다.

## 코드 위치

- 공통 계약: `src/sastsimi/contracts`
- SimpleRuntime 계약: `src/sastsimi/simple_runtime/models.py`
- checkpoint 저장: `src/sastsimi/simple_runtime/store.py`
- artifact 저장: `src/sastsimi/simple_runtime/artifacts.py`
- migration: `src/sastsimi/storage/alembic`
- 생성 schema: `schemas/generated`
- 보고서 ID·기존 Markdown·번들 렌더링/게시: `src/sastsimi/reporting`

## 지켜야 하는 계약

- ID 의미는 analysis, workspace, commit, hypothesis, attempt, record 사이에서 섞지 않습니다.
- immutable record를 덮어쓰지 않고 current pointer와 새 revision을 구분합니다.
- content hash가 다른 reference는 같은 결과로 취급하지 않습니다.
- 오래된 CWE, Gate, Finding과 ReportDraft를 새 Verification에 재사용하지 않습니다.
- 로컬 절대 경로와 비밀정보는 보고서나 Agent 로그로 내보내지 않습니다.
- 테스트 commit만으로 영향 버전 범위·패치 버전·심각도/CVSS를 만들어 저장하지 않습니다.

## 현재 제한

생성 schema는 배포 계약이므로 파일 수가 많아 보여도 임의로 지우지 않습니다. schema를
제거하려면 Pydantic producer와 consumer, 저장 호환성과 export test가 모두 없어야 합니다.
