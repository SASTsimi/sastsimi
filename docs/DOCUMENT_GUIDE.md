# 문서 지도

필요한 작업부터 문서를 고르세요. 이 지도는 **현재 사용법·구현**과
**작성 당시의 설계·검증 기록**을 구분합니다. 대체된 자료는 Git 이력에 남깁니다.

## 시작·실행

- [프로젝트 README](../README.md): 가장 짧은 소개·설치·분석·결과 확인
- [설치](./installation.md): Windows·Linux/WSL 환경과 외부 프로그램 준비
- [Provider 인증·모델](./provider-setup.md): API Key와 공식 Codex 회원 로그인
- [CLI·대시보드 사용법](./usage.md): `setup`, `analyze`, `status`, `resume`, 보고서
- [대시보드와 결과 상세](./usage/dashboard-and-results.md): 화면별 수치, Finding·PoC·첨부 번들
- [대시보드 시연](./dashboard-demo.md): 고정된 취약 저장소와 짧은 발표 순서
- [문제 해결](./troubleshooting.md): 인증·정적 도구·Docker·보고서 오류
- [PoC 환경](./troubleshooting/poc-environment.md): wheel·오프라인 이미지·격리 빌드
- [PoC 복구](./troubleshooting/poc-recovery.md): 오류별 제한 재시도와 근거 보존

## 운영·공통 안내

- [문서 시작점](./README.md): 사용자 문서와 구현 문서로 가는 길
- [용어집](./GLOSSARY.md): 공통 이름과 상태값
- [대시보드 목록 인덱스](./dashboard-read-model.md): 재구축·백필·상태를 다루는 운영자용 절차
- [onboarding 근거](./onboarding-evidence.md): 고급 production profile 승인 근거 형식
- [현재 제한과 후속 작업](./release-follow-ups.md): 지원하지 않거나 검증하지 않은 범위
- [기여 안내](../CONTRIBUTING.md): 코드·문서 변경, 테스트와 PR 절차

## 구현 구조·확정 결정

- [아키텍처 시작점](./architecture/README.md): 구현 문서의 읽는 순서와 기준
- [파이프라인](./architecture/pipeline.md): 저장소 입력부터 보고서까지의 실제 stage
- [Runtime·재개](./architecture/runtime-and-recovery.md): checkpoint 재사용과 실패 지점 재개
- [저장 분석의 보안 표면 근거](./architecture/surface-evidence-versions.md): v4–v11 버전별 증거와 경계
- [Agent·Provider](./architecture/agents-and-providers.md): Agent 역할과 Provider 독립성
- [계약·저장](./architecture/contracts-and-storage.md): exact reference, schema와 저장 방식
- [정적·동적 분석](./architecture/static-and-dynamic-analysis.md): 정적 분석, PoC 후보와 Docker 재현
- [Gate·Chaining·보고](./architecture/gates-chaining-reporting.md): 두 Gate, Primitive, Chaining, Finding
- [보안 경계](./architecture/security-boundaries.md): Runtime 권한, secret, workspace와 Docker 경계
- [구현 위치](./architecture/implementation-map.md): 기능별 코드와 테스트

[확정 설계 결정](./decisions/README.md)은 채택된 ADR 13개와 과거 설계 기록을 구분합니다.
ADR은 결정 배경을 보존하고, 실제 동작과 필드는 코드·생성 schema·테스트를 기준으로
확인합니다. 대체된 ADR은 현재 문서 목록에 두지 않습니다.

## 작성 당시의 설계·검증 기록

- [설계·구현 계획 색인](./plans/README.md): 과거 작업의 원본과 미완료 체크박스의 해석
- [검증 기록 색인](./validation/README.md): 대상 커밋·분모·환경을 고정한 과거 시험

두 색인의 수치는 현재 탐지율이나 보안 보증이 아닙니다. 대상·버전이 같은 기록만
그 조건에서 대조하세요.

## 자동 생성·검증 자료

- `schemas/generated/`: Pydantic 계약에서 생성한 JSON Schema
- `schemas/result-owner-inventory.json`: result kind, model과 owner 목록
- `scripts/validate-current-docs.ps1`: 현재 문서 경로, 로컬 링크와 프래그먼트 검사
- `.github/workflows/docs.yml`: 문서 검증 CI

문서 삭제나 이름 변경 전에는 `validate-current-docs.ps1`과 관련 계약 테스트를 실행합니다.
공통 계약이나 Python 코드를 바꿨다면 전체 테스트와 품질 검사를 추가로 실행합니다.
