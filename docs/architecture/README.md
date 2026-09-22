# 현재 구현 아키텍처

이 디렉터리는 현재 설치되는 SASTSIMI 코드가 실제로 어떻게 동작하는지 설명합니다.
과거 설계안이나 작업 계획이 아니라 `src/sastsimi`의 실행 경로를 기준으로 합니다.

## 먼저 읽을 문서

1. [전체 파이프라인](./pipeline.md)
2. [Runtime과 재개](./runtime-and-recovery.md)
3. [Agent와 LLM Provider](./agents-and-providers.md)
4. [계약과 저장](./contracts-and-storage.md)
5. [정적 분석과 동적 재현](./static-and-dynamic-analysis.md)
6. [Gate·Chaining·Finding·보고서](./gates-chaining-reporting.md)
7. [보안 경계](./security-boundaries.md)
8. [구현 위치 지도](./implementation-map.md)

정확한 필드 형식은 `src/sastsimi/contracts`, `src/sastsimi/simple_runtime/models.py`와
`schemas/generated`가 기준입니다. 문서와 코드가 다르면 코드를 고치거나 문서를
갱신해야 하며, 문서만으로 새 계약을 만들지 않습니다.

현재 외부 도구와 Provider 조합의 검증 범위는
[후속 작업과 제한](../release-follow-ups.md)에 따로 기록합니다.
