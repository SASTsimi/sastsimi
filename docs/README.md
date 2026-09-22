# SASTSIMI 문서

이 폴더는 현재 설치되는 SASTSIMI의 사용법과 구현 구조를 설명합니다. 과거 설계안과
작업별 검토 기록은 현재 문서 트리에서 제거했으며 Git 이력으로 확인할 수 있습니다.

## 사용자 문서

1. [설치](./installation.md)
2. [Provider 인증](./provider-setup.md)
3. [실행과 결과 확인](./usage.md)
4. [문제 해결](./troubleshooting.md)

운영 승인용 세부 근거 파일이 필요한 경우에만
[onboarding 근거 안내](./onboarding-evidence.md)를 읽습니다.

## 구현 문서

- [현재 아키텍처](./architecture/README.md): 실제 코드의 파이프라인, Runtime, Agent,
  저장, Gate, Chaining과 보안 경계
- [현재 설계 결정](./decisions/README.md): 구현 의미를 바꾸는 확정 ADR
- [전체 문서 지도](./DOCUMENT_GUIDE.md): 각 문서의 목적과 독자
- [용어집](./GLOSSARY.md): 코드와 문서에서 사용하는 공통 용어
- [현재 제한과 후속 작업](./release-follow-ups.md): 아직 지원하거나 검증했다고 말할 수
  없는 범위

정확한 필드 형식은 `src/sastsimi/contracts`, `src/sastsimi/simple_runtime/models.py`와
`schemas/generated`가 기준입니다. 문서가 코드와 다르면 문서를 그대로 구현하지 말고
코드·schema·테스트를 함께 확인합니다.
