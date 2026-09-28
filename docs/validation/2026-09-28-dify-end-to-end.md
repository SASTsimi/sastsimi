# Dify 분석 파이프라인 검증 (2026-09-28 KST)

## 실제 분석과 별도 재시험

- 대상: `https://github.com/langgenius/dify.git`, 고정 commit `8387590ace4a094de812b7847fc6a4c3a27cd52b`.
- 기존 분석 `A-007`은 `STATIC_DONE · BLOCKED · OPENGREP_PARTIAL_SCAN`이다. 이 분석의 체크포인트나 사용자 설정은 변경하지 않았다.
- `statictrial20260927dify`는 같은 commit의 정적 단계만 검사하는 별도 시험 ID다. 새 누적시간 기본값과 선택형 Semgrep 복구를 시험 프로필 복사본에 적용했고, 원문·DB 시도를 보존해 재개한다. 현재 결과와 미검증 조합은 [정적 재시험 기록](2026-09-28-dify-static-retest.md)에 남긴다.

## 파이프라인 판정 기준

정적 단계가 적용 가능한 파일·규칙 조합 전체의 완료 증거를 만들기 전에는 `A-007`을 후속 Agent 단계로 재개하지 않는다. AST와 현재 Python 범위 CodeQL 결과는 보존하지만 JavaScript·TypeScript 규칙의 미검증 조합을 대신 완료 처리하지 않는다. 정적 단계가 통과한 경우에만 동일 분석 ID로 후속 Agent·PoC·Gate·보고서 단계를 이어 실행한다. 이때도 동적 실행과 근거가 실제로 검증되기 전에는 `confirmed`나 제보 가능이라고 표시하지 않는다.

외부 Git·LLM·Docker만 합성 응답으로 대체한 [종단 재개 회귀 테스트](../../tests/simple_runtime/test_static_to_report_resume.py)는 정적 `BLOCKED`에서 후속 호출이 시작되지 않는 점, 같은 ID의 재개, PoC 실행 오류 뒤 재시도, 완료된 단계의 중복 실행 방지, 영문·한국어·PoC·증거 번들 생성을 확인한다. 정책 근거가 없는 합성 사례는 `UNCERTAIN` 및 `CONFIRMED_RESTRICTED`로 남는다. 이 테스트는 실제 Dify 취약점이나 실제 Docker PoC의 증거가 아니다.

## 현재 실제 결과

2026-09-28 11:15 KST 기준 Dify의 별도 정적 재시험은 64파일 상한의 OpenGrep 분할 코드로 재개됐고 최종 coverage artifact가 아직 없다. 따라서 실제 Dify에 대해 전체 파이프라인 `COMPLETE`, confirmed Finding, 제출 가능한 보고서가 생성됐다고 주장하지 않는다. 정적 검사가 종료되면 검증·미검증 조합 수와 경로·규칙별 사유를 확인해 이 문서를 갱신한다. 미검증이 남으면 실제 분석은 `BLOCKED`를 유지한다.
