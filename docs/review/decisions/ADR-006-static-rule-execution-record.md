# ADR-006. 정적분석 규칙 실행 이력 분리

- 상태: `ACCEPTED`
- 결정일: 2026-09-03
- 기준 main: `9c7e3fc456926bdb40872ea10887e6fa98d35cc0`
- 결정 담당: PM·아키텍처·워크플로(R4)
- 함께 검토할 역할: 정적분석·컨텍스트(R2), 데이터·평가·예산(R8)
- 연결 Issue: #3, #5, #9, #82
- 반영 commit: `docs: define static rule execution history contract`

## Context

`CodeFact.producer.rule_id`는 SAST 규칙이 hit을 만들었을 때만 존재합니다. 따라서 이 필드만으로는 다음 두 경우를 구분할 수 없습니다.

1. 규칙을 실제로 실행했지만 탐지 결과가 0건인 경우
2. 규칙이 분석 계획에서 제외됐거나 실행되지 않은 경우

이 구분이 없으면 Hypothesis·Verification과 R8 평가가 “검사했지만 없음”과 “검사하지 않음”을 같은 의미로 읽어 잘못된 확신을 가질 수 있습니다.

## Options

### 1. `RunMeta`에 규칙 목록 추가

공통 실행 ID와 도구별 대규모 규칙 목록이 섞이고, 도구 attempt별 실행 상태를 정확히 연결하기 어렵습니다. 선택하지 않습니다.

### 2. 모든 규칙을 `ToolRunResult` 안에 직접 저장

연결은 단순하지만 `StaticFactBundle` 안의 `ToolRunResult`가 커지고, 평가나 감사만 필요한 전체 규칙 목록이 Agent 입력까지 반복 전달될 수 있습니다. 선택하지 않습니다.

### 3. 별도 `RuleExecutionRecord`를 만들고 `ToolRunResult`가 참조

규칙 이력을 attempt별 불변 record로 보존하면서 `StaticFactBundle`에는 정확한 참조만 연결할 수 있습니다. 설정·catalog·retry도 exact reference로 검사할 수 있어 이 방식을 선택합니다.

## Decision

규칙 기반 SAST는 attempt마다 하나의 `RuleExecutionRecord`를 만들고 `ToolRunResult.rule_execution_ref`가 그 exact revision을 가리킵니다.

- `ToolRunResult.tool_kind`는 `RULE_BASED | STRUCTURE`로 구분합니다. `STRUCTURE`에는 규칙 실행 record를 연결하지 않습니다.
- record에는 도구·버전, exact 분석 설정, exact 규칙 catalog, 선택한 rule pack과 규칙별 상태를 저장합니다.
- 규칙별 `selection_status`는 `SELECTED | NOT_SELECTED`입니다.
- 규칙별 `execution_status`는 `EXECUTED | NOT_EXECUTED | UNKNOWN`입니다.
- `EXECUTED`에서만 `hit_count`를 0 이상의 정수로 저장합니다. `EXECUTED + hit_count=0`이 실행 후 탐지 0건입니다.
- 미실행·확인 불가 상태에는 `hit_count=null`과 이유를 저장합니다.
- `CodeFact`가 없다는 사실만으로 실행 여부나 0건을 추정하지 않습니다.
- `CodeFact.producer.attempt_id`는 자신을 만든 exact `ToolRunResult.attempt_id`와 같아야 합니다.
- retry는 새 `attempt_id`와 새 record를 사용하고 이전 attempt의 수치를 합치지 않습니다.
- `RuleExecutionRecord`는 STATIC_ANALYSIS만 생산합니다. LLM Agent는 읽을 수 있지만 만들거나 수정할 수 없습니다.

`rule_catalog_ref`는 R8이 계획 coverage의 분모로 사용할 이번 분석의 규칙 목록과 버전을 고정합니다. 실행 coverage는 선택한 규칙 중 실제 실행한 비율이고, 계획 coverage는 catalog 중 선택한 비율이므로 두 값을 섞지 않습니다.

## Responsibility

- R2: adapter에서 실제 규칙 선택·실행·raw hit 수를 수집하고 record를 생산합니다.
- R4: 필드, 상태 조합, exact reference, 오류·retry·권한 검사를 유지합니다.
- R8: exact record를 사용해 계획 coverage와 실행 coverage를 별도로 계산합니다.

## Compatibility

새 record, `ToolRunResult.tool_kind`·규칙 기반 `rule_execution_ref`와 `ToolSource.attempt_id` 의무화는 기존 운영 결과의 유효 조건을 바꾸므로 새 MAJOR schema입니다. 이전 결과에서 hit이 없다는 이유로 0건을 추정해 새 형식으로 자동 변환하지 않습니다.

## Verification

- 실행 후 0건은 `SELECTED + EXECUTED + hit_count=0`이어야 합니다.
- 계획 제외는 `NOT_SELECTED + NOT_EXECUTED + hit_count=null`이어야 합니다.
- 실행 여부를 증명할 수 없으면 `SELECTED + UNKNOWN + hit_count=null`이어야 합니다.
- selected 규칙이 일부 빠졌는데 `ToolRunResult.status=SUCCEEDED`인 결과를 거절합니다.
- 다른 attempt·도구·설정·catalog record를 연결한 결과를 거절합니다.
- retry별 record와 수치를 분리합니다.
