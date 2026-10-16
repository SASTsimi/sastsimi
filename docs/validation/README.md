# 검증 기록 색인

이 폴더의 Markdown 12건은 고정 커밋·저장 분석·로컬 fixture에서 작성한 당시의
검증 기록입니다. 대상, 도구 버전, 분석 ID, 범위와 환경이 다른 기록의 수치를
합치거나 현재 성능으로 일반화하지 마세요. 현재 실행 절차는
[사용법](../usage.md), 구현 근거는 [현재 아키텍처](../architecture/README.md),
아직 검증되지 않은 범위는 [현재 제한](../release-follow-ups.md)을 확인하세요.

## 날짜별 원본 12건

| 기록 | 무엇을 확인했나 |
| --- | --- |
| [2026-09-26 changedetection.io 고정 분석 시험](./2026-09-26-changedetection-trial.md) | 고정 커밋의 실행·재개와 관찰된 상태·오류. |
| [2026-09-26 정책 근거 Scope Gate](./2026-09-26-policy-backed-scope-gate.md) | 읽기 전용 실제 정책 조회와 로컬 검증. 기술 판정과 제보 허가는 별개. |
| [2026-09-27 Dify 정적 커버리지](./2026-09-27-dify-static-coverage.md) | 당시 정적 검사 범위, 복구 재시험과 미검증 조합. |
| [2026-09-28 Dify E2E](./2026-09-28-dify-end-to-end.md) | 실제 분석과 별도 재시험의 단계별 판정 경계. |
| [2026-09-28 Dify 정적 재시험](./2026-09-28-dify-static-retest.md) | 누적 시간 제한 변경 뒤 제품 범위별 재시험과 엔진 한계. |
| [2026-09-29 후보 발견 시험](./2026-09-29-candidate-discovery-trial.md) | python-multipart와 Dify에서 관찰한 후보 처리·한계. |
| [2026-09-30 AST 사실·Dify](./2026-09-30-ast-facts-dify.md) | 파일별 AST 근거와 저장 분석의 중단·재개. |
| [2026-10-04 그룹 보고서 읽기 전용 재생](./2026-10-04-grouped-report-replay.md) | 두 저장 분석의 개별 보고서 11·12건, 검증 그룹·그룹 ZIP 0건. 실측 중복 보고서 감소도 0건. |
| [2026-10-04 후보 누락 감사 기준선](./2026-10-04-recall-gap-baseline.md) | 두 로컬 fixture의 저장 DB·소스 읽기 전용 대조. 재실행이나 탐지율 측정은 아님. |
| [2026-10-05 Python 저장소 세 곳의 시험](./2026-10-05-three-python-repository-trial.md) | 고정 커밋의 첫 실행과 후속 재개·수정 효과. 단계별 결과를 각 분석 ID에 묶어 읽어야 함. |
| [2026-10-07 BreakableFlask blind 시험](./2026-10-07-breakableflask-blind-trial.md) | `PARTIAL` 실행에서 동결된 8개 경로와 8/8 도구 Finding 경로 일치. 이는 취약점 재현율 100%나 제보 가능한 8건을 뜻하지 않음. |
| [2026-10-08 Python 고정 사례 평가](./2026-10-08-python-recall-methodology.md) | 실행 전 동결 정답과 실행 후 별도 검토·실측을 한 파일에서 구분. 아래 해석 경계 참조. |

## 동결 정답과 후속 실측의 경계

[Python 고정 사례 평가 원본](./2026-10-08-python-recall-methodology.md)은 두
저장소의 대상 커밋과 oracle 파일 SHA-256을 **분석 전에** 고정했습니다. 이
`DOCUMENTED_CASES` 정답지는 분석, PoC, Finding 또는 탐지율을 증명하지 않으며
전체 저장소의 취약점 목록도 아닙니다. 분석 후 검토 원장과 score 파일은 같은
문서에서 별도로 연결합니다. 현재 평가 절차를 읽을 때도 이 순서와 분모를
유지하세요.

| 시험 대상 | 동결된 문서 사례 | 실행 후 측정·독립 검토 |
| --- | --- | --- |
| DSVPWA 개발 시험 | 14건 중 Python 평가 대상 12건, 사전 범위 제외 2건 | 후속 격리 실행은 `PARTIAL`; **1 TP, 0 확정 FN, 11 HOLD, 2 OUT_OF_SCOPE**. `recall`은 **null**이며 `1/12`가 아닙니다. 초기 `BLOCKED` 실행도 완료된 탐지율 측정이 아닙니다. |
| VulnShop held-out 시험 | 5건 중 Python 평가 대상 4건, 사전 범위 제외 1건 | 격리 실행은 `PARTIAL`; **4 TP, 0 FN, 0 HOLD, 1 OUT_OF_SCOPE**. `4/4 = 100%`는 문서화된 평가 가능 Python 사례에만 대한 값입니다. 전체 저장소 탐지율이나 완전한 공격 표면 검증을 뜻하지 않습니다. |

두 시험 모두 별도 오탐률은 측정하지 않았습니다. 정답지에 없는 Finding을 자동으로
오탐 처리하지 않으며, 기술적 확인만으로 외부 제보가 허가되지 않습니다. 정확한
분석 ID, oracle 해시, 검토 원장과 score 파일은 [원본의 해당 절](./2026-10-08-python-recall-methodology.md)에서 확인하세요.
