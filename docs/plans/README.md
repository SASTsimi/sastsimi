# 설계·구현 계획 색인

이 폴더의 날짜별 문서는 작성 당시의 설계와 실행 계획을 보존합니다. 이전 작업의
미완료 체크박스는 현재의 미완료 작업 목록이 아닙니다. 구현 여부와 현재 동작은
[현재 아키텍처](../architecture/README.md), 코드·테스트,
[현재 제한](../release-follow-ups.md)을 확인하세요. 시험에서 실제로 관찰한 결과는
[검증 기록](../validation/README.md)에 별도로 있습니다.

## 이번 문서 정리의 작업 자료

- [2026-10-16 설계](./2026-10-16-comprehensive-docs-readability-design.md)
- [2026-10-16 구현 계획](./2026-10-16-comprehensive-docs-readability.md)

## 이전 날짜별 설계·계획 54건

아래 링크는 원본 54건을 작성 날짜와 주제별로 묶은 것입니다. 한 항목에 설계와
구현 계획이 함께 있으면 두 원본을 각각 연결했습니다. 각 문서의 예전 브랜치,
커밋, 분석 ID, 수치와 체크리스트는 당시 기록 그대로 읽어야 합니다.

### 2026-09-25~2026-09-30: 통합·정적 범위·초기 복구

- 09-25 PR #198 E2E 인수인계: [구현 계획](./2026-09-25-e2e-handoff-pr198-implementation.md)
- 09-26 정책 근거 Scope Gate: [설계](./2026-09-26-policy-backed-scope-gate-design.md) · [구현 계획](./2026-09-26-policy-backed-scope-gate-implementation.md)
- 09-27 대형 저장소 정적 커버리지 복구: [설계](./2026-09-27-adaptive-static-coverage-recovery-design.md) · [구현 계획](./2026-09-27-adaptive-static-coverage-recovery.md)
- 09-27 Finding별 영·한 보고서 묶음: [설계](./2026-09-27-bilingual-report-bundles-design.md) · [구현 계획](./2026-09-27-bilingual-report-bundles.md)
- 09-27 범용 정적 커버리지와 선택적 재검사: [설계](./2026-09-27-generic-static-coverage-fallback-design.md) · [구현 계획](./2026-09-27-generic-static-coverage-fallback.md)
- 09-27 OpenGrep 규칙 묶음 재개: [설계](./2026-09-27-opengrep-rule-batch-resume-design.md) · [구현 계획](./2026-09-27-opengrep-rule-batch-resume.md)
- 09-28 부분 정적 분석과 정직한 종료 상태: [설계](./2026-09-28-partial-static-analysis-design.md) · [구현 계획](./2026-09-28-partial-static-analysis-implementation.md)
- 09-28 제품 코드만의 정적 검사 범위: [설계](./2026-09-28-product-code-static-scope-design.md) · [구현 계획](./2026-09-28-product-code-static-scope.md)
- 09-28 누적 시간 제한 없는 재개 가능 분석: [설계](./2026-09-28-reliable-unbounded-analysis-design.md) · [구현 계획](./2026-09-28-reliable-unbounded-analysis-implementation.md)
- 09-29 후보 발견: [설계](./2026-09-29-candidate-discovery-design.md) · [구현 계획](./2026-09-29-candidate-discovery-implementation.md)
- 09-29 Python 제품 코드 정적 전체 패스: [설계](./2026-09-29-python-only-static-full-pass-design.md) · [구현 계획](./2026-09-29-python-only-static-full-pass-implementation.md)
- 09-30 파일별 AST 사실 보존: [설계](./2026-09-30-ast-fact-shards-design.md) · [구현 계획](./2026-09-30-ast-fact-shards-implementation.md)

### 2026-10-01~2026-10-09: 스트리밍·보고·평가

- 10-01 스트리밍 파이프라인 최적화: [구현 계획](./2026-10-01-streaming-pipeline-optimization.md) · [당시 설계](../decisions/2026-10-01-streaming-pipeline-optimization-design.md)
- 10-02 AST·surface·문맥 정교화: [구현 계획](./2026-10-02-ast-surface-context-refinement.md)
- 10-02 오프라인 PoC 환경과 E2E 검증: [구현 계획](./2026-10-02-offline-poc-and-e2e-verification.md)
- 10-02 실제 저장소 E2E 안정화: [설계](./2026-10-02-real-repository-e2e-hardening-design.md)
- 10-04 근거 보존 중복 제거와 검증: [구현 계획](./2026-10-04-evidence-preserving-dedup-and-verification.md) · [당시 설계](../decisions/2026-10-04-evidence-preserving-dedup-and-verification-design.md)
- 10-04 미탐 우선 개선과 보고서 묶음: [설계](./2026-10-04-recall-first-grouped-reports-design.md)
- 10-04 후보 누락 감사: [구현 계획](./2026-10-04-recall-gap-audit.md)
- 10-04 검증된 Finding 묶음: [구현 계획](./2026-10-04-verified-finding-grouping.md)
- 10-04 검증 그룹 보고서 내보내기: [구현 계획](./2026-10-04-verified-group-report-export.md)
- 10-08 Python 전용 탐지율 평가: [설계](./2026-10-08-python-only-recall-evaluation-design.md) · [구현 계획](./2026-10-08-python-only-recall-evaluation.md) · [고정 정답과 후속 실측 기록](../validation/2026-10-08-python-recall-methodology.md)
- 10-09 같은 Provider 안의 모델 선택: [설계](./2026-10-09-same-provider-model-routing-design.md) · [구현 계획](./2026-10-09-same-provider-model-routing.md)

### 2026-10-11~2026-10-15: 저장 분석의 버전별 근거와 투영

- 10-11 A-001의 버전별 surface 근거: [설계](./2026-10-11-a001-versioned-surface-evidence-design.md) · [구현 계획](./2026-10-11-a001-versioned-surface-evidence.md)
- 10-12 A-001 범용 proof 재생: [기록](./2026-10-12-a001-generic-proof-replay.md)
- 10-12 A-001 `HOLD` 투영 묶음 처리: [구현 계획](./2026-10-12-a001-hold-projection-batching.md)
- 10-12 A-001 v5 surface proof와 `HOLD` 복구: [구현 계획](./2026-10-12-a001-v5-surface-proof-and-hold-recovery.md)
- 10-12 A-001 v7 surface overlay: [구현 계획](./2026-10-12-a001-v7-surface-overlay.md)
- 10-12 A-002 안전한 늦은 PoC 재생: [구현 계획](./2026-10-12-a002-safe-late-poc-replay.md)
- 10-12 저장 분석 두 건의 근거 보존 복구: [설계](./2026-10-12-live-analysis-proof-recovery-design.md)
- 10-13 sound surface successor: [설계](./2026-10-13-sound-surface-successor-design.md) · [구현 계획](./2026-10-13-sound-surface-successor.md)
- 10-14 route-bound surface 근거: [설계](./2026-10-14-route-bound-surface-evidence-design.md)
- 10-15 기본 작업 진행률과 판정 분리: [설계](./2026-10-15-core-work-progress-separate-from-verdict-design.md) · [구현 계획](./2026-10-15-core-work-progress-separate-from-verdict.md)
- 10-15 route-bound Python surface 근거: [구현 계획](./2026-10-15-route-bound-surface-evidence.md)
- 10-15 v9 대시보드 투영 묶음 처리: [설계](./2026-10-15-v9-dashboard-projection-batching-design.md) · [구현 계획](./2026-10-15-v9-dashboard-projection-batching.md)
- 10-15 버전별 child 근거 재검증: [설계](./2026-10-15-versioned-child-evidence-revalidation-design.md) · [구현 계획](./2026-10-15-versioned-child-evidence-revalidation.md)

## 파일명에 날짜가 없는 이전 설계·계획

아래 다섯 원본은 `docs/` 바로 아래에 남아 있습니다. 파일명에 날짜가 없더라도
내용은 당시 작업의 설계·계획이므로 현재 사용 절차로 분류하지 않습니다.

- 선택형 Claude Provider: [설계](../claude-provider-design.md) · [구현 계획](../claude-provider-implementation-plan.md). 설계에는 2026-09-25 당시 구현과 미검증 경계가 적혀 있습니다. 현재 인증 절차는 [Provider 안내](../provider-setup.md)를 확인하세요.
- changedetection.io 모델과 실분석: [안정화 설계](../changedetection-stability-design.md) · [모델·시험 계획](../changedetection-model-trial-plan.md) · [후속 수정 계획](../changedetection-stability-fix-plan.md). 당시 시험의 관찰 결과는 [검증 기록](../validation/2026-09-26-changedetection-trial.md)을 확인하세요.
