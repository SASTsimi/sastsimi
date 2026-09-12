# T13 Primitive and Chaining Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` or `superpowers:executing-plans`.

**Goal:** final TRUE와 근거가 남은 HOLD를 정확한 Primitive로 등록하고,
고정된 전체 후보군에서 방향성 있는 `result -> input` 연결만 새 가설로
전달한다.

**Architecture:** 비-LLM Primitive Admission Runtime이 등록 자격과 원자적
Primitive index 갱신을 소유한다. Chaining Agent는 runtime이 고정한 비교와
근거만 읽어 content-only match를 제안한다. 신뢰 workflow와 저장 계층은
계보·중복·exact reference를 검사하고, `ChainingResult`를 먼저 COMMITTED로
저장한 뒤 자식 가설과 READY Verification work를 멱등 등록한다.

**Spec:** [Issue #157](https://github.com/SASTsimi/sastsimi/issues/157),
[Task 13](../2026-09-08-sastsimi-complete-implementation.md#task-13-primitive-and-chaining),
[Chaining architecture](../../../architecture-v5/06-chaining.md),
[Data contracts](../../../architecture-v5/08-lightweight-data-contracts.md)

## 필수 경계

- FALSE와 candidate가 없는 HOLD는 Primitive·Chaining work를 만들지 않는다.
- HOLD는 admission decision 없이 모든 required candidate를 `inputs`로 가진
  result 없는 Primitive 하나를 등록한다.
- TRUE는 같은 generation의 final result, validated PoC, Technical ACCEPT와
  정책 수집 closure를 검사한다. testing restriction 결과만 정해진 표로
  `PrimitiveAdmissionDecision`에 매핑하며 ALLOW일 때만 provided candidate별
  result Primitive를 등록한다.
- Primitive와 새 가설별 current `PrimitiveIndexState`는 하나의
  `PRIMITIVE_UPDATE` COMMITTED transition으로 저장한다.
- 새 trigger work는 같은 analysis/workspace/commit의 모든 current hypothesis
  index와 중복 없는 전체 Primitive set을 exact reference로 고정한다.
- work 시작 뒤 새 index revision이 생겨도 고정한 과거 work는 무효가 되지
  않는다. 대신 고정하지 않은 reference가 결과에 섞이면 거절한다.
- Chaining Agent는 upstream result가 특정 downstream input을 충족하는지만
  판단한다. 일반 탐색·verdict·CWE·Gate·도구 실행·ID 발급 권한은 없다.
- 성공한 가장 깊은 후보의 양쪽 조상은 해당 순회에서 제외하되, match가
  실패한 후보의 조상과 독립 후보는 유지한다.
- match ID와 `(upstream, downstream, matched_input_id)`는 결과와 같은 저장
  transaction에서 예약한다. 중복이면 결과도 함께 rollback한다.
- `ChainingResult` COMMITTED 후에만 origin=CHAINING proposal을 등록한다.
  `(source_result_ref, proposal_id)` 재처리는 같은 등록과 READY Verification
  work를 반환하며 중복 budget·work를 만들지 않는다.
- Provider·저장 실패는 NO_MATCH나 보안 verdict로 바꾸지 않는다.

## 병렬 구현 단위

- Lane A: Primitive admission과 원자적 index 갱신.
- Lane B: 전체 후보군 고정, cohort 등록, historical pool, match reservation.
- Lane C: 방향성 matching, 양쪽 lineage 제외, content-only Agent 경계.
- Lane D: claimed work handler, result 저장, 자식 handoff와 recovery.
- Integration: prompt, concrete adapters, bootstrap, exports와 실제 slice.

각 lane은 파일 소유권을 겹치지 않게 유지하고 focused 정상 흐름과 중요한
실패 흐름만 실행한다. 전체 suite는 PR CI에서 한 번 실행한다.

## 완료 검사

- [x] 방향성 match와 양쪽 lineage 제외를 구현한다.
- [x] Agent 출력에서 runtime-owned 식별자·reference를 받지 않는다.
- [x] TRUE/HOLD admission의 public 경계와 원자적 projection을 구현한다.
- [ ] HOLD·TRUE가 섞인 analysis-wide immutable candidate pool을 저장한다.
- [ ] claimed RUNNING work가 같은 stable work의 historical pool을 읽는다.
- [ ] source generation과 cohort generation의 exact 일치를 검사한다.
- [ ] 이후 generation이 과거 pinned work를 무효화하지 않는지 검사한다.
- [ ] result와 match reservation을 같은 transaction으로 확정한다.
- [ ] COMMITTED result에서 자식 가설·READY Verification을 멱등 등록한다.
- [x] content-only Chaining prompt와 경계 시험을 추가한다.
- [ ] bootstrap에 production handler와 adapter를 연결한다.
- [ ] TRUE+HOLD, TRUE+TRUE, no-match, duplicate, stale/cross-scope와 recovery의
  focused test를 통과한다.
- [ ] Ruff, strict mypy, architecture/diff check를 통과한다.
- [ ] 독립 Blocker/High 검토 후 PR CI를 한 번 실행해 병합한다.

## 후속 목록

Medium/Low 리팩터링, 추가 최적화, 문서 표현 미세 보정과 대규모 성능 시험은
T13 완료 조건에서 제외하고 후속 작업으로 남긴다.
