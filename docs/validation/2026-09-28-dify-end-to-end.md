# Dify 분석 파이프라인 검증 (2026-09-28 KST)

## 실제 분석과 별도 재시험

- 대상: `https://github.com/langgenius/dify.git`, 고정 commit `8387590ace4a094de812b7847fc6a4c3a27cd52b`.
- 기존 분석 `A-007`은 `STATIC_DONE · BLOCKED · OPENGREP_PARTIAL_SCAN`이다. 이 분석의 체크포인트나 사용자 설정은 변경하지 않았다.
- `statictrial20260927dify`는 같은 commit의 기존 전체 파일 범위 정적 시험이며 `BLOCKED`로 종료됐다. `statictrial20260928product`는 제품 코드 범위의 별도 시험 ID였지만 커버리지 정책 v2 적용 전 최종 coverage 없이 중단됐다. 사용자 프로필이나 A-007을 바꾸지 않고 시험 프로필 복사본을 사용했다. 현재 결과와 미검증 조합은 [정적 재시험 기록](2026-09-28-dify-static-retest.md)에 남긴다.

15:36 KST에 별도 시험 ID `statictrial20260928productv2`를 시작했으나, 16:37 KST에 패키지의 배포 선언이 가리키는 제품 파일 세 개를 추가로 확인해 범위가 달라졌다. 이전 시험을 종료했고, 선택 파일 9,467개와 적용 조합 58,534개는 폐기된 범위의 실행 전 계산으로만 보존한다. 최신 범위는 선택 파일 9,470개와 적용 조합 58,558개이며, 이것도 최종 스캔 결과가 아니다. 기존 A-007과 다른 시험 ID의 증거를 섞지 않는다.

새 범위 ID `statictrial20260928productv3`로 정적 재시험을 진행했으나, 대용량 테스트 파일 하나가 제품 범위에 남은 것을 확인해 최종 coverage 없이 종료했다. 범용 분류기 수정 후 선택 제품 파일은 9,469개, 적용 조합은 58,550개로 바뀌었다. 이는 실행 전 선별 계산이다. 새 시험 ID `statictrial20260928productv4`로 실제 정적 검사를 시작했지만 당시에는 엔진별 최종 coverage와 후속 Agent 결과가 없어 `COMPLETE`나 제보 가능한 Finding을 주장하지 않았다.

그 뒤 새 부분 분석 경로로 실제 Dify 분석 `A-008`을 실행했다. 이 분석은 별도
범위·지문을 사용하며 앞선 시험의 예비 선별 수치를 최종 coverage로 사용하지 않는다.

## 파이프라인 판정 기준

정적 단계는 유효한 bundle·coverage artifact와 최소 한 개의 검증된 파일·규칙
조합이 있으면 신뢰할 수 있는 부분을 게시하고 후속 Agent로 진행할 수 있다.
미검증·미지원 경로는 `PARTIAL`로 남고, 해당 조합의 raw hit는 Agent 후보가
아니다. 테스트 전용 파일은 입력에서 제외한다. AST와 Python 범위 CodeQL은
JavaScript·TypeScript 규칙의 미검증 조합을 대신 완료하지 않는다. 같은
commit·제품 범위·규칙·도구 지문의 증거만 재사용하며, 손상된 증거와 다른
분석 ID의 근거는 섞지 않는다. 필수 Agent가 모두 종료해야 최종 `PARTIAL` 또는
`COMPLETE`를 판정한다. 동적 실행과 Gate 근거가 실제로 검증되기 전에는
`confirmed` Finding이나 제출 가능한 보고서를 주장하지 않는다.

외부 Git·LLM·Docker만 합성 응답으로 대체한 [종단 재개 회귀 테스트](../../tests/simple_runtime/test_static_to_report_resume.py)는 정적 `BLOCKED`에서 후속 호출이 시작되지 않는 점, 같은 ID의 재개, PoC 실행 오류 뒤 재시도, 완료된 단계의 중복 실행 방지, 영문·한국어·PoC·증거 번들 생성을 확인한다. 정책 근거가 없는 합성 사례는 `UNCERTAIN` 및 `CONFIRMED_RESTRICTED`로 남는다. 이 테스트는 실제 Dify 취약점이나 실제 Docker PoC의 증거가 아니다.

## 현재 실제 결과

기존 전체 파일 범위의 별도 정적 재시험은 97,227/97,328 조합만 검증하고 101개 시간 초과로 `BLOCKED` 종료됐다. 제품 범위 시험 `statictrial20260928product`부터 `productv3`까지는 범위 정책 변경으로 최종 coverage 없이 중단됐다. 앞선 59,310개 적용 조합과 미지원 73개는 옛 정책의 예비 선별이며 현재 결과가 아니다.

실제 Dify 분석 `A-008` (`statictrial20260928productv5`)은 후속 Agent와
Docker PoC를 끝까지 실행한 뒤 최종 `PARTIAL`로 종료됐다. 정적 coverage
artifact는 파일·규칙 조합 58,338개 중 13,710개만 검증했고 44,628개가
미검증이라고 기록했다. 사유는 시험 실행에서 짧게 설정한 검사 패스로 인한
`NOT_ATTEMPTED_BUDGET` 44,595개, `parse_or_scan_error` 15개,
`scan_timeout` 18개다. 미지원 제품 파일은 245개다. CodeQL은 구성됐지만
`CODEQL_ANALYZE_FAILED`로 실행 완료 증거가 없어 검증으로 계산하지 않았다.
OpenGrep 13,257개와 Semgrep 453개의 성공 조합은 보존됐다.

가설 3개의 `POC_EXECUTION_DONE`과 `VERIFICATION_FINAL_DONE`은 모두
`SUCCEEDED`였지만 최종 판정은 전부 `HOLD`다. 이 실행에서 confirmed Finding은
0개, 제출용 보고서는 0개다. 따라서 보고서 생성의 형식과 첨부파일 경로는
합성 회귀 테스트로만 검증됐으며, 실제 Dify 취약점 제보용 보고서가 나왔다고
주장하지 않는다. 미검증 정적 범위가 남은 동안 `COMPLETE`도 아니다.
