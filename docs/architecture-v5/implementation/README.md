# Architecture v5 구현 인계 문서

- **이 문서는 무엇을 설명하나요?** Architecture v5를 실제 코드로 옮길 때 읽을 R3 문서의 순서와 각 문서의 책임을 설명합니다.
- **누가 읽어야 하나요?** 전체 구현 담당자와 R1~R8 역할 검토자가 읽습니다.
- **읽은 뒤 무엇을 결정해야 하나요?** 자신의 구현·검토 범위에 해당하는 문서와 아직 남은 선행 조건을 확인합니다.

> 상태: **DESIGN_APPROVED / NOT_IMPLEMENTED**

## 문서 권한

번호 문서 `01`~`13`과 공통 계약이 데이터·역할·상태 의미의 정본이다. 이 폴더는 그 의미를 실제 module, 시험, Provider, Prompt와 물리 기술에 연결한다. 구현 문서가 번호 문서의 verdict·권한·Gate·Chaining 의미를 바꿀 수 없다.

## 읽는 순서

1. [01. 모듈 맵](./01-module-map.md) — 전체 22단계를 실행 주체, 입력·출력, 저장, 오류와 test 위치에 연결합니다.
2. [02. 계약 시험 계획](./02-contract-test-plan.md) — 각 계약의 정상·실패·권한 위반 fixture와 기대 결과를 정의합니다.
3. [03. 복구 시험 계획](./03-recovery-test-plan.md) — 중단·재시도·복구 시험과 장애 주입 지점을 설명합니다. PR #107 병합본이며 RQ-01~RQ-10의 물리 기준은 `06` §10.7에 연결됩니다.
4. [04. Provider 결정](./04-provider-decision.md) — API Key·구독 로그인 연결 후보와 실제 지원 판정 시험을 설명합니다.
5. [05. Prompt Runtime](./05-prompt-runtime.md) — Prompt Registry·Builder와 11개 LLM 역할의 입력·출력 검증을 설명합니다.
6. [06. 구현 기준선](./06-implementation-baseline.md) — 위 설계를 실제 언어·파일 구조·저장·설정·CLI·CI와 구현 순서로 확정합니다.

## 어떤 문서를 먼저 수정하나요?

- field·enum·필수값 변경: `08-lightweight-data-contracts.md`와 R4 검토가 먼저입니다.
- Agent 판단 기준 변경: 해당 역할 번호 문서와 역할 담당자 검토가 먼저입니다.
- Provider·session 변경: `09`, 구현 문서 `04`·`05`와 R3·R4·R8 검토가 필요합니다.
- 저장 제품·파일 구조·CLI·CI 변경: 구현 문서 `06`과 ADR을 수정합니다.
- recovery 기대값 변경: 구현 문서 `03`의 시나리오와 `06`의 물리 복구 기준을 함께 수정합니다.

## 현재 완료 상태와 남은 조건

- PR #116 병합과 Issue #92·R3 상위 Issue #4 종료: 완료
- R1~R8 역할 Issue #2~#9 종료: 완료
- 구현 기준 설계의 내용 고정 SHA: `07bd6549a676419c0e720f940ba7abd1b82aea0d`
- Architecture v5 전체 문서 추적과 validator·`git diff --check`: 최종 승인 PR에서 확인

`DESIGN_APPROVED`는 이 문서를 구현 기준으로 사용할 수 있다는 뜻입니다. Provider capability, 평가 결과, Docker 보안 시험과 실제 실행 코드는 아직 `NOT_IMPLEMENTED`이며 해당 기능을 활성화하기 전에 문서에 적힌 시험을 통과해야 합니다.
