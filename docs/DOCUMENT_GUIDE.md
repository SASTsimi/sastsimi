# 문서 지도

필요한 작업부터 문서를 고르세요. 현재 문서는 사용법, 구현 구조, 확정 결정으로
나뉩니다. 과거 회의 자료·역할별 검토 기록·대체된 설계는 Git 이력에 남깁니다.

## 시작·실행

- [프로젝트 README](../README.md): 가장 짧은 소개·설치·분석·결과 확인
- [설치](./installation.md): Windows·Linux/WSL 환경과 외부 프로그램 준비
- [Provider 인증·모델](./provider-setup.md): API Key와 공식 Codex 회원 로그인
- [CLI·대시보드 사용법](./usage.md): `setup`, `analyze`, `status`, `resume`, 보고서
- [대시보드 시연](./dashboard-demo.md): 고정된 취약 저장소와 짧은 발표 순서
- [문제 해결](./troubleshooting.md): 인증·정적 도구·Docker·보고서 오류

## 운영·공통 안내

- [문서 시작점](./README.md): 사용자 문서와 구현 문서로 가는 길
- [용어집](./GLOSSARY.md): 공통 이름과 상태값
- [onboarding 근거](./onboarding-evidence.md): 고급 production profile 승인 근거 형식
- [현재 제한과 후속 작업](./release-follow-ups.md): 지원하지 않거나 검증하지 않은 범위
- [기여 안내](../CONTRIBUTING.md): 코드·문서 변경, 테스트와 PR 절차

## 구현 구조·확정 결정

- [아키텍처 시작점](./architecture/README.md): 구현 문서의 읽는 순서와 기준
- [파이프라인](./architecture/pipeline.md): 저장소 입력부터 보고서까지의 실제 stage
- [Runtime·재개](./architecture/runtime-and-recovery.md): checkpoint 재사용과 실패 지점 재개
- [Agent·Provider](./architecture/agents-and-providers.md): Agent 역할과 Provider 독립성
- [계약·저장](./architecture/contracts-and-storage.md): exact reference, schema와 저장 방식
- [정적·동적 분석](./architecture/static-and-dynamic-analysis.md): 정적 분석, PoC 후보와 Docker 재현
- [Gate·Chaining·보고](./architecture/gates-chaining-reporting.md): 두 Gate, Primitive, Chaining, Finding
- [보안 경계](./architecture/security-boundaries.md): Runtime 권한, secret, workspace와 Docker 경계
- [구현 위치](./architecture/implementation-map.md): 기능별 코드와 테스트

[확정 설계 결정](./decisions/README.md)은 현재 유효한 ADR 11개를 안내합니다.
ADR은 결정 배경을 보존하고, 실제 동작과 필드는 코드·생성 schema·테스트를 기준으로
확인합니다. 대체된 ADR은 현재 문서 목록에 두지 않습니다.

## 자동 생성·검증 자료

- `schemas/generated/`: Pydantic 계약에서 생성한 JSON Schema
- `schemas/result-owner-inventory.json`: result kind, model과 owner 목록
- `scripts/validate-current-docs.ps1`: 현재 문서 경로와 로컬 링크 검사
- `.github/workflows/docs.yml`: 문서 검증 CI

문서 삭제나 이름 변경 전에는 `validate-current-docs.ps1`과 관련 계약 테스트를 실행합니다.
공통 계약이나 Python 코드를 바꿨다면 전체 테스트와 품질 검사를 추가로 실행합니다.
