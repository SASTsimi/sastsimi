# Architecture v5와 코드 연결 지도

이 문서는 설계 단계가 현재 코드의 어느 모듈에 있는지 찾는 운영 지도입니다.
“내부 모듈 구현”과 “public CLI에서 production 연결 완료”는 다른 상태입니다.

| 설계 단계 | 현재 코드 위치 | 핵심 검증 위치 | public 상태 |
|---|---|---|---|
| 설정·runtime path | `src/sastsimi/config/` | `tests/unit/config/`, `tests/integration/test_cli.py` | CLI 연결됨 |
| 저장소 입력·profile | `src/sastsimi/static_analysis/repository_loader.py`, `repository_profile.py` | `tests/unit/static_analysis/`, `tests/integration/static_analysis/` | production `analyze` 연결; 승인 profile 필요 |
| AST·CodeQL·OpenGrep | `src/sastsimi/static_analysis/` | `tests/contract/test_static_tool_real_adapter_conformance.py`, `tests/integration/static_analysis/` | capability별 승인 필요 |
| LLM provider·prompt | `src/sastsimi/providers/`, `src/sastsimi/prompts/` | `tests/integration/providers/`, `tests/contract/prompts/` | production route 연결; exact 승인 필요 |
| Hypothesis·Orchestration | `src/sastsimi/orchestration/`, `src/sastsimi/runtime/` | `tests/integration/orchestration/` | production 작업 그래프 연결 |
| Pro·Con·Verification | `src/sastsimi/verification/` | `tests/integration/verification/` | production 작업 그래프 연결 |
| 동적 재현·PoC | `src/sastsimi/reproduction/`, `src/sastsimi/sandbox/` | `tests/integration/sandbox/`, `tests/e2e/test_dynamic_reproduction.py` | Docker 경계 승인 필요 |
| CWE·Technical Gate·Rule Scope Gate | `src/sastsimi/reporting/` | `tests/integration/reporting/`, `tests/contract/domain/` | production 보고 작업 그래프 연결 |
| Chaining | `src/sastsimi/chaining/` | `tests/integration/chaining/` | production handoff 연결 |
| Finding·ReportDraft·Markdown | `src/sastsimi/reporting/`, `src/sastsimi/storage/report_export.py` | `tests/unit/reporting/`, `tests/simple_runtime/` | CLI 조회·export 연결됨 |
| 상태·복구·권한 | `src/sastsimi/runtime/`, `src/sastsimi/storage/` | `tests/integration/recovery/`, `tests/security_negative/` | 단계별 연결됨 |
| 운영 CLI | `src/sastsimi/interfaces/cli/` | `tests/unit/interfaces/`, `tests/integration/cli/` | `SimpleRuntime` 기반 `analyze` 단일 제품 경로 |

## 구현 상태를 판단하는 기준

1. Pydantic schema만 있으면 단계 구현 완료로 보지 않습니다.
2. Runtime이 exact reference와 권한을 검사하고 결과를 저장해야 합니다.
3. public CLI에서 해당 기능으로 들어가는 경로가 없으면 “내부 구현”으로 표시합니다.
4. 실제 provider·정적 도구·Docker를 쓰려면 현재 host에서 probe와 승인이 필요합니다.
5. 최종 production 완료는 실제 저장소 입력부터 Markdown 보고서까지 이어지는
   acceptance evidence가 있어야 합니다.

과거의 별도 Fake/demo 제품 경로는 제거됐습니다. 작은 test double은 외부 실패를
재현하는 단위 테스트 안에서만 사용할 수 있으며, 설치된 CLI의 분석 경로가 아닙니다.

설계 의미는 [Architecture v5](./architecture-v5/README.md), 사용 방법은
[CLI 안내](./usage.md), 미지원 경계는 [README](../README.md)를 우선 확인합니다.
