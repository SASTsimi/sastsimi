# Architecture v5 검토 발견사항

상태 값은 `OPEN | IN_PROGRESS | RESOLVED | DEFERRED`다. 이 문서는 색인이고 실제 owner, 토론, 결정과 완료 증거는 연결된 GitHub Issue/PR에서 관리한다.

## Blocker

| ID | 상태 | 발견사항 | 처리/완료 조건 | Owner role | Issue |
|---|---|---|---|---|---|
| B-001 | OPEN | 8개 역할의 GitHub username과 대체 reviewer 미확정 | 실제 username을 역할과 매핑하고, 이후에만 CODEOWNERS 추가 | PM·아키텍처·워크플로 | [#5](https://github.com/SASTsimi/sastsimi/issues/5) |
| B-002 | OPEN | independent final reviewer 미지정 | 작성자·design review coordinator와 다른 reviewer 지정 및 freeze SHA 승인 | Repository steward | [#10](https://github.com/SASTsimi/sastsimi/issues/10) |
| B-003 | OPEN | 공개 저장소의 license/외부 기여 정책 미결정 | 허용 범위를 결정하고 LICENSE/CONTRIBUTING에 반영 | Repository steward | [#5](https://github.com/SASTsimi/sastsimi/issues/5) |
| B-004 | RESOLVED | 원본이 uncommitted working tree여서 commit provenance를 주장할 수 없음 | [PROVENANCE.md](./PROVENANCE.md)에 working-tree 상태와 원본 파일 hash 기록 | PM·아키텍처·워크플로 | [#5](https://github.com/SASTsimi/sastsimi/issues/5) |
| B-005 | RESOLVED | candidate가 승인된 정본처럼 표현됨 | root/v5/Wiki에 candidate baseline과 승인·동기화 경계 명시 | PM·아키텍처·워크플로 | [#5](https://github.com/SASTsimi/sastsimi/issues/5) |
| B-006 | RESOLVED | LLM Orchestration이 security enforcement authority로 해석될 수 있음 | 비-LLM runtime validator와 모든 LLM output 비신뢰 경계 명시 | PM·아키텍처·워크플로 | [#5](https://github.com/SASTsimi/sastsimi/issues/5) |

## High

| ID | 상태 | 발견사항 | 처리/완료 조건 | Owner role | Issue |
|---|---|---|---|---|---|
| H-001 | OPEN | `RepositorySnapshot`, `ArtifactRef`, `LocationRef`, `EntityRef` identity·immutability 계약 부족 | submodule/LFS/generated dependency와 revision binding을 포함한 계약·negative scenario 합의 | 정적분석·컨텍스트 + PM | [#3](https://github.com/SASTsimi/sastsimi/issues/3), [#5](https://github.com/SASTsimi/sastsimi/issues/5) |
| H-002 | IN_PROGRESS | 공통 생성 시각, static gap 이름, dynamic failure/falsification 구분의 계약 충돌 | `created_at`, 공통 `gaps`, `failure_class/falsification_observed` 반영 후 소비자 교차 리뷰 | PM + 정적/동적/검증 | [#3](https://github.com/SASTsimi/sastsimi/issues/3), [#5](https://github.com/SASTsimi/sastsimi/issues/5), [#7](https://github.com/SASTsimi/sastsimi/issues/7), [#8](https://github.com/SASTsimi/sastsimi/issues/8) |
| H-003 | OPEN | conditional debate, 독립 session, LLM Gate, provider/model 선택의 경험적 exit criteria 없음 | versioned corpus, adversarial cases, metrics와 합격 임계값 합의 | 데이터·평가·예산 | [#9](https://github.com/SASTsimi/sastsimi/issues/9) |
| H-004 | OPEN | Membership adapter의 공식 지원·약관·동시성·log 가용성이 검증되지 않음 | feasibility/security 검토 전 optional experiment로 제한하고 종료 조건 정의 | 통합·구현 개발 | [#4](https://github.com/SASTsimi/sastsimi/issues/4) |
| H-005 | OPEN | Docker reproduction과 policy capture가 요구사항 수준이며 threat model/ADR 미완료 | daemon/image/egress/cleanup과 source auth/freshness/parser failure ADR 승인 | 동적검증·Sandbox + Gate | [#6](https://github.com/SASTsimi/sastsimi/issues/6), [#8](https://github.com/SASTsimi/sastsimi/issues/8) |
| H-006 | OPEN | 병렬 가설·retry·Gate revision의 persistence/recovery 의미 부족 | atomic transition, idempotency, concurrency, revision binding, crash-resume 계약 승인 | PM + 통합 개발 | [#4](https://github.com/SASTsimi/sastsimi/issues/4), [#5](https://github.com/SASTsimi/sastsimi/issues/5) |

## Medium/Low backlog

- Wiki는 사용자 요구에 따라 포함했으나 파생·비규범적으로 유지한다. 장기적으로 번호 문서에서 생성·검증하는 방식을 결정한다.
- `11-migration-from-v4.md`는 비규범적 설계 계보로 전환했으며 로컬 v4 경로 주장을 제거했다.
- Primitive 입력은 `TRUE`의 PROVIDED와 `HOLD`의 REQUIRED로 명확화했다. `FALSE`를 chaining 근거로 승격하지 않는다.
- Docsify가 사용하는 외부 CDN dependency의 version pinning과 offline rendering 정책은 별도 결정한다.
- 표현·예시·문서 미세 보정은 Blocker/High 검토보다 후순위다.

## Gate 확정 조건

1. 열린 Blocker와 High가 0이다.
2. Medium은 해결되거나 owner·근거·목표 시점과 함께 명시적으로 연기된다.
3. [Final Issue #10](https://github.com/SASTsimi/sastsimi/issues/10)과 최종 승인 PR에 freeze commit SHA를 기록한다.
4. freeze 이후 변경은 기존 승인을 무효화하고 재검토한다.
5. independent reviewer가 최신 SHA를 승인한다.
6. 별도 승인 PR에서만 상태를 변경한다.
