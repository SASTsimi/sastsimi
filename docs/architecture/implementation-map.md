# 현재 구현 위치 지도

## 사용자 진입점

- 패키지 명령: `pyproject.toml`의 `sastsimi.interfaces.cli.main:main`
- 명령 parser와 dispatch: `src/sastsimi/interfaces/cli/main.py`
- 간단한 출력: `src/sastsimi/interfaces/cli/public.py`
- 초기 설정: `src/sastsimi/interfaces/cli/setup.py`, `src/sastsimi/setup`

## 기본 분석 경로

```text
CLI
→ simple_runtime_composition.build_simple_analysis_application
→ SimpleAnalysisApplication
→ StaticBootstrap + HypothesisBootstrap
→ SimpleRuntimeRunner
→ build_default_handlers
→ SimpleCheckpointStore + SimpleArtifactRepository
```

- 조립: `src/sastsimi/composition/simple_runtime_composition.py`
- 분석 단위: `src/sastsimi/simple_runtime/application.py`
- 재개 실행기: `src/sastsimi/simple_runtime/runner.py`
- stage 구현: `src/sastsimi/simple_runtime/stages.py`
- 상태·계약: `src/sastsimi/simple_runtime/models.py`
- 저장: `src/sastsimi/simple_runtime/store.py`, `artifacts.py`

## 기능별 위치

- Repository Loader와 정적 도구: `src/sastsimi/static_analysis`
- LLM 연결: `src/sastsimi/simple_runtime/provider.py`, `src/sastsimi/providers`
- PoC와 Docker: `src/sastsimi/simple_runtime/poc.py`, `portable_docker.py`,
  `src/sastsimi/sandbox`
- Chaining: `src/sastsimi/simple_runtime/chaining.py`
- Markdown 보고서: `src/sastsimi/reporting`
- 진행률: `src/sastsimi/progress`
- 읽기 전용 웹 화면: `src/sastsimi/dashboard`
- 공통 계약: `src/sastsimi/contracts`
- DB migration: `src/sastsimi/storage/alembic`

## 고급·내부 경로

capability probe, onboarding, 명시적 CodeQL DB 관리와 상세 production runtime 명령은
기본 사용자 흐름과 분리된 고급 경로로 유지합니다. `evaluate`와 `local_evaluation`은
실제 외부 조합을 검증하기 위한 내부 평가 경로이며 일반 분석 명령의 대체물이 아닙니다.

## 변경 시 확인할 테스트

- 공개 CLI: `tests/unit/interfaces`, `tests/integration/cli`
- SimpleRuntime: `tests/simple_runtime`, `tests/unit/simple_runtime`
- 저장·복구: `tests/integration/storage`, `tests/integration/recovery`
- 정적·동적 분석: `tests/unit/static_analysis`, `tests/integration/sandbox`
- Gate·보고서·Chaining: `tests/integration/reporting`, `tests/integration/chaining`
- 권한·민감정보·reference: `tests/security_negative`
