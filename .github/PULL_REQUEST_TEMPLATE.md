## 연결 Issue

Closes #

## 변경 요약

- 무엇을 왜 바꿨는지:
- 영향받는 사용자 명령 또는 Runtime stage:
- 변경하지 않은 범위:

## 공통 계약과 안전성

- [ ] 오류·인증·도구 실패를 취약점 `FALSE`로 바꾸지 않습니다.
- [ ] exact analysis·workspace·commit·hypothesis·attempt·record 연결을 유지합니다.
- [ ] final `TRUE`와 validated PoC 조건을 유지합니다.
- [ ] Agent와 Runtime의 판정·실행 권한 경계를 유지합니다.
- [ ] secret, 민감정보와 로컬 절대 경로를 노출하지 않습니다.
- [ ] Docker 또는 외부 실행 경계를 바꿨다면 관련 보안 검토를 받았습니다.

해당하지 않는 항목은 이유를 적어주세요.

## 검증

- 실행한 테스트와 결과:
- 정상 흐름:
- 중요한 실패 흐름:
- 실행하지 못한 검증과 이유:

## 문서와 호환성

- [ ] 사용자 명령 또는 출력이 바뀌면 README와 운영 문서를 갱신했습니다.
- [ ] 공통 의미가 바뀌면 현재 아키텍처와 ADR 영향을 확인했습니다.
- [ ] 생성 schema·migration·기존 저장 데이터 영향을 확인했습니다.
- [ ] `scripts/validate-current-docs.ps1`과 `git diff --check`를 실행했습니다.

## 후속 작업

- 이번 PR에 포함하지 않은 Medium/Low 개선 또는 후속 Issue:
