# 데이터 계약과 저장

## 구현된 책임

공통 계약은 Pydantic model로 정의하고 JSON schema로 내보냅니다. 핵심 연결 단위는
`StoredDataRef`이며 record ID뿐 아니라 kind, schema version과 content hash를 함께
확인합니다.

`SimpleRuntime`은 분석 실행, stage checkpoint, artifact, Agent activity, 사람이 보는
분석 ID와 Finding ID를 SQLite에 저장합니다. 보고서 파일은
`<data-dir>/reports/<analysis_id>/F-NNN.md`에 저장하며 데이터베이스의 exact Finding과
연결합니다.

## 코드 위치

- 공통 계약: `src/sastsimi/contracts`
- SimpleRuntime 계약: `src/sastsimi/simple_runtime/models.py`
- checkpoint 저장: `src/sastsimi/simple_runtime/store.py`
- artifact 저장: `src/sastsimi/simple_runtime/artifacts.py`
- migration: `src/sastsimi/storage/alembic`
- 생성 schema: `schemas/generated`
- 보고서 ID와 파일: `src/sastsimi/reporting`

## 지켜야 하는 계약

- ID 의미는 analysis, workspace, commit, hypothesis, attempt, record 사이에서 섞지 않습니다.
- immutable record를 덮어쓰지 않고 current pointer와 새 revision을 구분합니다.
- content hash가 다른 reference는 같은 결과로 취급하지 않습니다.
- 오래된 CWE, Gate, Finding과 ReportDraft를 새 Verification에 재사용하지 않습니다.
- 로컬 절대 경로와 비밀정보는 보고서나 Agent 로그로 내보내지 않습니다.

## 현재 제한

생성 schema는 배포 계약이므로 파일 수가 많아 보여도 임의로 지우지 않습니다. schema를
제거하려면 Pydantic producer와 consumer, 저장 호환성과 export test가 모두 없어야 합니다.
