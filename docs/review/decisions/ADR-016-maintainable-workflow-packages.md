# ADR-016. 유지보수 가능한 업무 흐름 package 경계

- 상태: `ACCEPTED`
- 기록일: 2026-09-08
- 결정 근거: [PR #119](https://github.com/SASTsimi/sastsimi/pull/119), merge commit `5657fc7b51af33271a940af37ca48bbfcdc14553`
- 근거 설계: [승인된 유지보수 구현 설계 §4·5·10](../../superpowers/specs/2026-09-08-sastsimi-maintainable-implementation-design.md)
- 정본 반영 Issue: [T02 #124](https://github.com/SASTsimi/sastsimi/issues/124)
- 결정 담당: R3 구현·통합, R4 공통 아키텍처
- 반영 검토 역할: R3·R4, 영향 영역 R1·R5·R6·R7·R8

`ACCEPTED`는 PR #119에서 이미 승인·병합된 물리 package 결정의 상태다. 이 ADR은 해당 결정을 정본 구현 문서에 연결하며, Agent나 데이터 계약을 새로 승인하지 않는다. T02 문서 반영의 검토·병합 상태는 [T02 실행 계획](../../superpowers/plans/implementation/02-architecture-boundary-correction.md)과 연결 Issue에서 별도로 추적한다.

## Context

[R3-01 모듈 맵](../../architecture-v5/implementation/01-module-map.md)은 가설 내부 Debate·Verification·REVISE·동적 재현·Chaining 서비스를 논리 이름으로 정의했지만 [R3-06 구현 기준선](../../architecture-v5/implementation/06-implementation-baseline.md)의 물리 tree에는 해당 workflow package가 빠져 있었다. 호출 순서와 import 방향을 같은 화살표로 설명하면 runtime이나 adapter가 concrete 업무 흐름·저장 구현을 직접 참조하도록 읽힐 수 있었다.

[ADR-015](./ADR-015-r3-implementation-baseline.md)가 확정한 저장·직렬화 기술과 run-init Docker 경계도 일부 현재 문서에 과거 표현으로 남아 있었다. 승인된 유지보수 구현 설계는 코드 구현 전에 이 모순을 정리하도록 정했다.

## Options

1. 기존 workflow를 `verification/`, `reproduction/`, `chaining/`에 배치하고 공개 port와 runtime interface로 연결한다. PR #119에서 채택했다.
2. 가설 내부 흐름을 `orchestration/` 또는 Agent wrapper에 합친다. 전역 배정·집계, 역할 판단과 업무 흐름 책임이 섞이므로 채택하지 않았다.
3. Agent별 서비스와 외부 Queue를 도입한다. ADR-015의 로컬 단일 애플리케이션 범위를 벗어나므로 채택하지 않았다.

## Decision

기존 서비스의 exact module을 다음과 같이 고정한다. 모든 경로는 `src/sastsimi/` 기준이다.

| 서비스 | module | 책임 |
|---|---|---|
| `DebateService` | `verification/debate_service.py` | 같은 입력의 Pro·Con child work fan-out과 결과 join |
| `VerificationService` | `verification/service.py` | initial assessment와 최종 검증 결과 합성 |
| `VerdictRouter` | `verification/verdict_router.py` | final FALSE·HOLD·TRUE에 맞는 다음 work 등록 요청 생성 |
| `RevisionWorkflow` | `verification/revision_workflow.py` | Technical `REVISE`의 같은 owner·새 generation 전환 |
| `DynamicReproductionService` | `reproduction/service.py` | R6 요청과 R7 구성요소의 실행 순서 연결 |
| `ChainingService` | `chaining/service.py` | exact Primitive index 고정, Chaining 호출과 새 proposal 전달 |

다음 화살표는 왼쪽 package가 오른쪽 공개 인터페이스만 import할 수 있음을 뜻한다. 전체 package allowlist는 R3-06 §6을 따른다.

```text
verification → contracts, ports, runtime, agents
reproduction → contracts, ports, runtime, agents
chaining → contracts, ports, runtime, agents
```

`VerdictRouter`는 `reporting`이나 `chaining`의 concrete service를 import하지 않는다. `VerdictRouter`는 current final result를 읽어 정본의 `ActionRequest`와 work 등록 요청을 runtime public interface에 제출한다. Runtime Validator의 허가 전에는 CWE·Primitive·Chaining work를 만들지 않는다. 실제 handler 선택과 concrete instance 연결은 worker registry와 `bootstrap.py`의 dependency injection으로 수행한다.

실행 호출 흐름은 Python import 방향과 구분한다. runtime worker는 `WorkHandler` port만 호출한다. 외부 adapter끼리는 직접 호출하지 않으며 Agent는 DB·SQLAlchemy·Docker SDK·Provider SDK·전역 상태를 직접 사용하지 않는다. `contracts`는 다른 SASTSIMI package를 import하지 않는다. `bootstrap.py`는 concrete 생성·주입만 수행하며 상태 전이·취약점 판정·권한 검사를 구현하지 않는다.

저장·직렬화는 ADR-015와 R3-06의 SASTSIMI Canonical JSON v1 + SHA-256, Pydantic 2 + JSON Schema 2020-12, schema versioning, SQLite + SQLAlchemy 2, Alembic, content-addressed file store를 따른다. run-init은 정적 분석과 정책 준비만 시작하며 Docker 준비는 current 가설의 승인된 `DYNAMIC_REPRO`에서만 수행한다.

## Compatibility

이 결정은 Agent 권한, schema field, enum, verdict, 상태 전이, Gate, Primitive 또는 validated PoC 의미를 바꾸지 않는다. 11개 LLM 역할과 기존 result-owner는 그대로다.

- final TRUE는 current generation의 `SUCCEEDED + SUPPORTED` 동적 결과와 validated PoC를 요구한다.
- Technical `REVISE`는 같은 owner의 새 generation에서 Pro·Con을 다시 실행한다.
- HOLD Primitive는 `result=null`이며 TRUE result Primitive는 Technical `ACCEPT`와 current `PrimitiveAdmissionDecision=ALLOW`가 필요하다.
- 두 Gate의 순서·정책 의미와 Reporter의 내부 `ReportDraft` 종료 경계는 유지한다.
- 오류·timeout·인증·예산·Sandbox 실패를 취약점 verdict로 바꾸지 않는다.

이 의미를 바꿔야 하는 구현은 별도 Issue·ADR과 영향 역할 검토를 먼저 거친다.

## Consequences

가설 내부 workflow의 담당 파일과 import 방향이 명확해지고 Agent wrapper·전역 Orchestration·외부 adapter의 책임을 분리할 수 있다. runtime이 concrete workflow를 import하지 않도록 worker registry와 bootstrap 주입을 구현해야 한다. 문서 검증은 정본의 mapping 회귀를 막지만 실제 Python import나 Provider·Docker capability의 성공을 증명하지 않는다.

## Verification

- Architecture validator의 `Assert-MaintainableWorkflowBoundaries`가 6개 exact mapping, import allowlist, VerdictRouter의 권한 검사·주입 경계, ADR index와 stale 표현을 검사한다.
- T01 inventory의 `-CheckLinks`와 `git diff --check`로 문서 연결과 diff를 검사한다.
- 실제 Python 구현의 `tests/contract/test_architecture_imports.py`에서 금지 import·adapter 직접 의존을 검사한다.
- R3·R4와 영향 역할은 T02의 exact commit을 독립 검토하고 결과를 연결 Issue·PR에 기록한다. 이 단계는 PR #119의 결정 승인과 별개다.
