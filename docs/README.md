# SASTSIMI 문서

현재 설치되는 SASTSIMI의 사용법과 구현 구조를 안내합니다. 처음 사용한다면
[설치](./installation.md)부터 시작하세요.

## 무엇을 하려나요?

- 환경을 준비한다 → [설치](./installation.md)
- 계정과 모델을 설정한다 → [Provider 인증·모델](./provider-setup.md)
- 분석·재개·보고서를 사용한다 → [CLI·대시보드 사용법](./usage.md)
- 오류를 진단한다 → [문제 해결](./troubleshooting.md)

운영 승인용 세부 근거가 필요한 경우에는 [onboarding 근거 안내](./onboarding-evidence.md),
고정 커밋의 Python 취약점 사례를 독립 검토하려면
[탐지율 평가 방법](./validation/2026-10-08-python-recall-methodology.md)을 읽으세요.

## 구현을 살펴보려면

- [현재 아키텍처](./architecture/README.md): 파이프라인·Runtime·Agent·저장·Gate·Chaining·보안 경계
- [현재 설계 결정](./decisions/README.md): 구현 의미를 바꾸는 확정 ADR
- [현재 제한과 후속 작업](./release-follow-ups.md): 아직 지원하거나 검증하지 않은 범위
- [용어집](./GLOSSARY.md): 공통 용어와 상태값
- [전체 문서 지도](./DOCUMENT_GUIDE.md): 문서별 목적과 독자

실제 저장소 실행 검증 기록은 [`validation`](./validation/2026-09-26-changedetection-trial.md)에
따로 둡니다. 과거 아키텍처 초안은 Git 이력에서 확인할 수 있습니다.

정확한 필드 형식은 `src/sastsimi/contracts`, `src/sastsimi/simple_runtime/models.py`와
`schemas/generated`가 기준입니다. 문서와 코드가 다르면 문서만 근거로 구현하지 말고
코드·schema·테스트를 함께 확인하세요.
