# 대시보드 목록 read model 운영 안내

대시보드 목록 read model은 기존 JSON/CAS 결과를 대체하지 않는 **재구축 가능한 보조 인덱스**입니다. 상세 데이터와 다운로드는 기존 원본에서 조회합니다.

운영 순서는 [사전 점검](#사전-점검dry-run) → [명시적 재구축](#생성백필재구축) → [원본·인덱스 개수와 상태 확인](#검증-체크리스트)입니다. 인덱스 오류를 분석 원본의 성공이나 실패로 바꾸지 않습니다.

## 스키마와 안전성

`dashboard_index_state`, `dashboard_list_summaries`, `dashboard_list_items` 테이블과 페이지·상태·종류 조회용 인덱스만 추가합니다. 기존 테이블, 컬럼, JSON/CAS를 삭제하거나 변환하지 않습니다. 서버 시작 및 `setup` 시에는 생성·백필하지 않습니다. 새 데이터 폴더는 첫 분석 저장소 생성 시 빈 인덱스 스키마만 준비합니다. 기존 분석 DB의 최초 백필은 아래 명시적 명령으로 수행합니다.

## 사전 점검(dry-run)

```powershell
uv run sastsimi --data-dir <DATA_DIR> dashboard-index rebuild --dry-run --all
uv run sastsimi --data-dir <DATA_DIR> dashboard-index rebuild --dry-run --analysis-id <ANALYSIS_ID>
```

Dry-run은 원본을 읽고 투영 예정 개수만 계산하며 SQLite와 JSON/CAS에 쓰지 않습니다.

## 생성·백필·재구축

```powershell
uv run sastsimi --data-dir <DATA_DIR> dashboard-index rebuild --all
uv run sastsimi --data-dir <DATA_DIR> dashboard-index rebuild --analysis-id <ANALYSIS_ID>
```

분석별 트랜잭션으로 기존 인덱스 행을 교체하며 `(analysis_id, list_kind, item_id)` 기본 키로 중복을 방지합니다. 출력의 원본 개수와 인덱스 개수를 비교하십시오. 재구축 중 원본이 다시 변경되면 이전 스냅샷을 `READY`로 게시하지 않습니다. 이 충돌은 `STALE`로 반환되며 명령 결과의 `skipped`에 집계됩니다. 원본 쓰기가 끝난 뒤 재구축을 다시 실행하십시오. 한 분석의 투영이 실패하면 원본은 보존되고 색인은 `INCOMPLETE`로 남습니다. 원인을 수정한 뒤 같은 재구축 명령을 다시 실행할 수 있습니다.

## 저장 시 투영

원본 SQLite 변경과 색인의 `INCOMPLETE` 표시는 같은 트랜잭션에 저장합니다. 원본 JSON/CAS 및 SQLite 커밋이 성공한 다음 read model을 갱신합니다. read model 갱신 실패는 이미 성공한 원본 저장을 되돌리지 않으며, 검증되지 않은 이전 목록을 현재 결과로 표시하지 않습니다.

V9 공격 표면 검토는 한 *문맥 묶음*의 제안·가설 자식 처리 중 원본 기록과 LLM 시도를 각각 즉시 저장하고, 그 묶음이 끝날 때 대시보드 상세 목록을 한 번 재구축합니다. 따라서 긴 묶음의 중간에는 상세 목록이 잠시 보이지 않을 수 있지만 진행률과 로그 조회는 유지됩니다. 중단 후에는 완료된 Agent 호출을 반복하지 않고, 남은 작업을 재개하며 `INCOMPLETE` 색인을 다시 구성합니다.

상세 목록(특히 보고서가 보이는 `outputs`)의 HTTP 409 의미는 다음과 같습니다.

- `index_not_ready`: 최초 백필이 필요하거나 실행 상태를 확인할 수 없습니다. 상태를 확인한 뒤 `dashboard-index rebuild --analysis-id <ANALYSIS_ID>`를 실행합니다.
- `index_updating`: 분석이 실행 중이며 색인이 갱신 중입니다. 잠시 후 다시 조회합니다.
- `index_resume_required`: 분석 실행이 멈춘 채 색인이 미완료입니다. 원인 확인 후 분석을 재개하거나 명시적으로 색인을 재구축합니다.

기존 DB에서 색인 스키마가 아직 생성되지 않았다면 원본 저장을 막지 않고 HTTP 409로 명시적 재구축을 안내합니다. 서버와 기존 DB에 대한 자동 마이그레이션은 수행하지 않습니다.

## 비활성화와 임시 롤백

문제가 발생하면 새 테이블을 삭제하지 말고 대시보드 서버 프로세스에 다음 환경변수를 설정해 기존 JSON/CAS 투영 조회로 전환합니다.

```powershell
$env:SASTSIMI_DASHBOARD_INDEX_MODE='source'
uv run sastsimi --data-dir <DATA_DIR> dashboard
```

이 전환은 데이터 삭제 없이 목록 조회 경로만 변경합니다. 상세 API와 원본 분석 결과는 계속 사용할 수 있습니다. 복구 후 환경변수를 제거하고 `dashboard-index rebuild`를 실행한 다음 서버를 다시 시작하십시오.

```powershell
Remove-Item Env:SASTSIMI_DASHBOARD_INDEX_MODE
uv run sastsimi --data-dir <DATA_DIR> dashboard-index rebuild --all
uv run sastsimi --data-dir <DATA_DIR> dashboard
```

## 검증 체크리스트

- dry-run 전후 JSON/CAS와 SQLite 원본 테이블 체크섬이 같은지 확인
- 재구축 출력의 원본/인덱스 항목 수 비교
- 재구축을 두 번 실행해 항목 수와 고유 항목 수가 같은지 확인
- 목록 API가 페이지당 최대 10개만 반환하는지 확인
- 상세 항목 선택 시에만 기존 JSON/CAS 상세 API가 호출되는지 확인
- 실패 분석이 0건으로 표시되지 않고 `index_not_ready`로 안내되는지 확인
