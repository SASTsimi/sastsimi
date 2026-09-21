# Legacy Fake Pipeline Isolation Design

Status: APPROVED DESIGN — implementation planning pending

## 목적

SASTSIMI의 실제 제품 실행 경로를 `SimpleRuntime` 하나로 단순화한다. 과거 데모와
계약 검증을 위해 만들었던 Fake 파이프라인은 실제 LLM·OpenGrep·CodeQL·Docker
분석에 사용되지 않으므로 제품 패키지, 공개 CLI, 기본 테스트와 CI에서 제거한다.

이 정리의 목표는 기능을 추가하는 것이 아니라 다음 문제를 없애는 것이다.

- 사용자가 Fake 실행을 실제 분석으로 오해하는 문제
- 과거 Runtime과 SimpleRuntime이 동시에 유지되어 생기는 중복 구현
- Fake 파이프라인 전체를 반복 실행하느라 테스트와 CI가 오래 걸리는 문제
- 실제 구현과 무관한 Fake 전용 계약이 새 코드 변경을 막는 문제

## 유지하는 것

- 실제 저장소 분석을 수행하는 `SimpleRuntime`
- 실제 Provider, OpenGrep, CodeQL, Docker 연결
- 분석 단계 저장, 실패 단계 재개, 정확한 reference, validated PoC 규칙
- 실제 CLI와 읽기 전용 대시보드
- 외부 프로그램이나 실패 상황을 빠르게 시험하기 위한 작은 단위 테스트 stub
  - 예: 테스트 파일 안의 `FakeRunner`, `StubClient`, 메모리 저장소
  - 이들은 사용자에게 노출되는 Fake 분석 기능이 아니므로 유지한다.

## 제거하거나 격리하는 것

### 공개 실행 경로

- `sastsimi demo ...` 명령
- `build_fake_pipeline` 및 `load_fake_progress` 공개 bootstrap 경로
- Fake 시나리오 결과를 실제 분석 결과처럼 조회하는 CLI 연결
- README와 사용 문서의 Fake/demo 실행 안내

### 제품 패키지의 Fake 전용 구현

다음 범주의 모듈은 import 사용처를 확인한 뒤 의존성 순서대로 제거한다.

- Fake orchestration pipeline과 scenario runtime
- Fake Provider, Sandbox, Static Analysis adapter
- Fake action validator와 Fake workflow port
- Fake LLM configuration/invocation/support
- Fake reproduction closure와 Fake chaining runtime
- Fake 실행에만 사용되는 verification/reporting/policy 조립 코드

공유 계약이나 실제 SimpleRuntime에서 사용하는 구현은 이름에 `fake`가 포함되어
있더라도 무조건 삭제하지 않는다. 실제 import graph와 호출 경로로 판단한다.

### 테스트와 CI

- Fake 전체 파이프라인 E2E 테스트 제거
- Fake 파이프라인을 준비하기 위해 전체 과거 Runtime을 실행하는 통합 테스트 제거
- Fake 전용 소유권·계약 테스트 제거
- 실제 SimpleRuntime과 공유 코드의 단위·통합·보안 테스트는 유지
- 기본 CI에는 실제 제품 경로와 직접 관련된 테스트만 포함

Git 기록이 삭제된 코드의 복구 가능한 이력을 제공하므로, 제품 저장소 안에 실행
가능한 Fake 사본을 별도 보관하지 않는다. 설명이 필요한 경우 문서에 제거 사실과
마지막 commit만 남긴다.

## 작업 순서

1. Fake 공개 CLI와 bootstrap 진입점 제거
2. Fake import graph의 시작점부터 사용처를 따라 의존성 폐쇄 집합 계산
3. 실제 SimpleRuntime에서 사용하지 않는 Fake 제품 모듈 제거
4. Fake 파이프라인 전용 테스트와 CI 경로 제거
5. 남은 import, architecture boundary, 패키지 export 정리
6. README·설치·사용·문제 해결 문서에서 Fake/demo 설명 제거
7. 형식·타입·아키텍처 검사와 SimpleRuntime 핵심 테스트 실행
8. 마지막 PR에서 전체 CI를 한 번 실행

## 안전 경계

- 실제 분석 데이터와 기존 SimpleRuntime checkpoint는 삭제하지 않는다.
- API Key, 회원제 로그인 정보와 Provider 설정 형식은 변경하지 않는다.
- 오류를 `FALSE`로 바꾸지 않는 규칙을 유지한다.
- `TRUE`에는 실제 실행에 성공한 validated PoC가 필요하다.
- analysis·hypothesis·attempt·record reference 일치 검사를 유지한다.
- Fake 코드 제거를 이유로 실제 Sandbox 경계나 민감정보 검사를 약화하지 않는다.

## 완료 조건

- 공개 CLI 도움말에 `demo` 또는 Fake 분석 명령이 없다.
- 제품 코드에서 Fake 파이프라인을 생성하거나 호출할 수 없다.
- `build_fake_pipeline`과 `load_fake_progress`가 공개 API에서 제거된다.
- 제품 코드의 Fake 전용 모듈과 import가 제거된다.
- 남은 `Fake*` 이름은 테스트 파일 내부의 작은 test double로 제한된다.
- README는 실제 SimpleRuntime 사용법만 안내한다.
- 실제 분석 핵심 테스트, 정상 흐름 1개, 중요한 실패·재개 흐름 1개가 통과한다.
- 형식, 린트, 엄격 타입, 아키텍처 경계 검사가 통과한다.
- 최종 GitHub CI가 통과한다.

## 제외 범위

- 새로운 Runtime 기능 추가
- 모델 품질 개선
- 새로운 취약점 유형 지원
- 웹 대시보드 쓰기 기능
- Medium/Low 수준의 리팩터링과 문서 미세 보정
