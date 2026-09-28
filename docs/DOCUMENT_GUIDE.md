# 문서 지도

현재 저장소 문서는 사용법, 구현 구조, 확정 결정의 세 종류로 나눕니다. 과거 회의 자료,
역할별 검토 기록과 대체된 설계는 Git 이력에만 남깁니다.

## 처음 사용하는 사람

| 문서 | 설명 |
|---|---|
| [`README.md`](../README.md) | 프로젝트 소개와 가장 짧은 설치·분석·결과 확인 방법 |
| [`installation.md`](./installation.md) | Windows와 Linux/WSL 설치, 외부 프로그램 준비 |
| [`provider-setup.md`](./provider-setup.md) | API Key와 공식 Codex 회원 로그인 설정 |
| [`usage.md`](./usage.md) | `setup`, `analyze`, `status`, `resume`, 대시보드와 보고서 사용법 |
| [`dashboard-demo.md`](./dashboard-demo.md) | 고정된 취약 저장소와 짧은 대시보드 발표 순서 |
| [`troubleshooting.md`](./troubleshooting.md) | 인증·정적 도구·Docker·보고서 오류의 안전한 해결 방법 |

## 운영·공통 안내

| 문서 | 설명 |
|---|---|
| [`README.md`](./README.md) | 이 문서 폴더의 시작점 |
| [`GLOSSARY.md`](./GLOSSARY.md) | 공통 이름과 상태값의 쉬운 뜻 |
| [`onboarding-evidence.md`](./onboarding-evidence.md) | 고급 production profile 승인 근거 형식 |
| [`release-follow-ups.md`](./release-follow-ups.md) | 현재 제한과 검증하지 않은 후속 범위 |
| [`CONTRIBUTING.md`](../CONTRIBUTING.md) | 코드·문서 변경, 테스트와 PR 절차 |

## 현재 구현 아키텍처

| 문서 | 설명 |
|---|---|
| [`architecture/README.md`](./architecture/README.md) | 구현 문서의 읽는 순서와 기준 |
| [`architecture/pipeline.md`](./architecture/pipeline.md) | 저장소 입력부터 보고서까지 실제 stage 순서 |
| [`architecture/runtime-and-recovery.md`](./architecture/runtime-and-recovery.md) | checkpoint 재사용과 실패 지점 재개 |
| [`architecture/agents-and-providers.md`](./architecture/agents-and-providers.md) | LLM Agent 역할과 Provider 독립성 |
| [`architecture/contracts-and-storage.md`](./architecture/contracts-and-storage.md) | exact reference, schema와 저장 방식 |
| [`architecture/static-and-dynamic-analysis.md`](./architecture/static-and-dynamic-analysis.md) | 정적 분석, PoC 후보와 Docker 재현 |
| [`architecture/gates-chaining-reporting.md`](./architecture/gates-chaining-reporting.md) | 두 Gate, Primitive, Chaining, Finding과 보고서 |
| [`architecture/security-boundaries.md`](./architecture/security-boundaries.md) | Runtime 권한, secret, workspace와 Docker 경계 |
| [`architecture/implementation-map.md`](./architecture/implementation-map.md) | 기능별 실제 코드와 테스트 위치 |

## 확정 설계 결정

[`decisions/README.md`](./decisions/README.md)는 현재 유효한 ADR 11개를 안내합니다.
ADR은 결정 배경을 보존하고, 실제 동작과 필드는 코드·생성 schema·테스트를 기준으로
확인합니다. 대체된 ADR은 현재 문서 목록에 두지 않습니다.

## 자동 생성·검증 자료

- `schemas/generated/`: Pydantic 계약에서 생성한 JSON Schema
- `schemas/result-owner-inventory.json`: result kind, model과 owner 목록
- `scripts/validate-current-docs.ps1`: 현재 문서 경로와 로컬 링크 검사
- `.github/workflows/docs.yml`: 문서 검증 CI

문서 삭제나 이름 변경 전에는 `validate-current-docs.ps1`과 관련 계약 테스트를 실행합니다.
공통 계약이나 Python 코드를 바꿨다면 전체 테스트와 품질 검사를 추가로 실행합니다.
