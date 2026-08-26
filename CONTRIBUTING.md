# Architecture v5 설계 협업 가이드

## 1. 브랜치와 PR

전체 설계 초안의 통합 브랜치는 `docs/architecture-v5-review`입니다.

1. 파트 담당자는 통합 브랜치에서 자신의 브랜치를 생성합니다.
2. 브랜치 이름은 `review/<domain>` 형식을 사용합니다.
3. PR base는 `main`이 아니라 `docs/architecture-v5-review`로 지정합니다.
4. 통합 브랜치와 `main`에 직접 push하지 않습니다.
5. 전체 Draft PR만 최종 검토 후 `main`으로 병합합니다.

예시:

```bash
git fetch origin
git switch docs/architecture-v5-review
git pull --ff-only
git switch -c review/static-context
```

## 2. 문서 소유와 중앙 통합

각 파트 담당자는 자신의 번호 문서와 Wiki 요약을 우선 검토합니다. 다음 중앙 파일은 충돌을 방지하기 위해 PM·아키텍처 담당자가 최종 통합합니다.

- `README.md`
- `docs/architecture-v5/README.md`
- `docs/architecture-v5/01-system-overview.md`
- `docs/architecture-v5/08-lightweight-data-contracts.md`
- `docs/architecture-v5/13-architecture-diagrams.md`
- `docs/architecture-v5/wiki/diagrams.md`

중앙 계약 변경이 필요하면 파트 PR에 생산자·소비자 영향과 제안 필드를 작성합니다. PM 담당자는 양쪽의 승인을 받은 후 중앙 파일을 반영합니다.

## 3. 필수 리뷰

각 PR에는 최소 다음 검토가 필요합니다.

- 담당자 self-review
- 입력을 제공하는 upstream 파트 리뷰 1명
- 결과를 소비하는 downstream 파트 리뷰 1명
- 중앙 계약·권한 경계 변경 시 PM·아키텍처 리뷰
- 보안 또는 외부 공개 경계 변경 시 Gate/동적검증 담당 리뷰

본인 혼자 작성하고 승인한 PR은 병합하지 않습니다.

## 4. 리뷰 심각도

- `[BLOCKER]`: 전체 흐름, 권한 또는 안전 경계가 성립하지 않음
- `[HIGH]`: 파트 간 계약 충돌, 잘못된 verdict/report 경로 또는 중요한 누락
- `[MEDIUM]`: 구현 전에 결정해야 하는 모호성 또는 평가 부족
- `[LOW]`: 표현, 예시, 문서 가독성
- `[QUESTION]`: 설명이나 근거 요청

병합 전 Blocker/High는 0이어야 합니다. Medium/Low는 `OPEN_QUESTIONS.md` 또는 후속 Issue에 남길 수 있습니다.

## 5. PR에서 반드시 설명할 내용

- 영향받는 정본 pipeline 단계
- 변경한 역할의 책임과 금지 권한
- 입력·출력 record와 상태 변화
- 오류·HOLD·timeout·budget 처리
- upstream/downstream 영향
- 보안·자격 증명·sandbox·공개 경계
- Wiki와 Mermaid 반영 여부
- 검증한 시나리오와 남은 질문

## 6. 전체 시나리오 검토

파트 검토가 끝나면 다음 시나리오를 문서만 보고 처음부터 끝까지 추적합니다.

1. named falsification으로 FALSE가 되는 가설
2. HOLD restriction을 TRUE capability가 충족해 새 chain 가설이 생기는 경우
3. Docker FULL_REPRO와 PoC까지 성공한 TRUE
4. 기술적으로 TRUE지만 공식 정책이 없어 UNCERTAIN + DENY가 되는 경우
5. Technical Gate REVISE가 Verification/Research로 돌아가는 경우
6. provider 인증 실패가 FALSE로 바뀌지 않는 경우

## 7. 설계와 구현의 분리

현재 설계 변경 PR에 runtime 구현을 섞지 않습니다. 설계가 승인되면 별도 구현 Issue와 PR을 만듭니다. 검증되지 않은 비용·정확도 개선이나 provider 지원 완료를 주장하지 않습니다.
