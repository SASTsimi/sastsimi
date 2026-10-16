# 현재 구현 아키텍처

이 디렉터리는 현재 설치되는 SASTSIMI 코드가 실제로 어떻게 동작하는지 설명합니다.
과거 설계안이나 작업 계획이 아니라 `src/sastsimi`의 실행 경로를 기준으로 합니다.

<a id="먼저-읽을-문서"></a>

처음에는 [전체 파이프라인](./pipeline.md)에서 단계와 상태를 확인하고,
[Runtime과 재개](./runtime-and-recovery.md)에서 checkpoint의 재사용 조건을 읽으세요.
저장된 Python 분석의 v4–v11 표면 보강을 살펴볼 때는
[보안 표면 근거 버전](./surface-evidence-versions.md)으로 이어집니다.

## 작업별 읽기 경로

- 순서와 완료 조건: [전체 파이프라인](./pipeline.md)
- 실패 지점과 증거 재사용: [Runtime과 재개](./runtime-and-recovery.md) →
  [보안 표면 근거 버전](./surface-evidence-versions.md)
- 호출 역할과 모델 선택: [Agent와 LLM Provider](./agents-and-providers.md)
- 아티팩트·checkpoint 형식: [계약과 저장](./contracts-and-storage.md)
- 입력 범위와 PoC: [정적 분석과 동적 재현](./static-and-dynamic-analysis.md)
- 판정·표시·보고: [Gate·Chaining·Finding·보고서](./gates-chaining-reporting.md)
- 신뢰 경계: [보안 경계](./security-boundaries.md)
- 변경할 코드를 찾기: [구현 위치 지도](./implementation-map.md)

정확한 필드 형식은 `src/sastsimi/contracts`, `src/sastsimi/simple_runtime/models.py`와
`schemas/generated`가 기준입니다. 문서와 코드가 다르면 코드를 고치거나 문서를
갱신해야 하며, 문서만으로 새 계약을 만들지 않습니다.

현재 외부 도구와 Provider 조합의 검증 범위는
[후속 작업과 제한](../release-follow-ups.md)에 따로 기록합니다.
