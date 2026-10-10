# 대시보드 목록 read model 운영 안내

대시보드 목록 read model은 기존 JSON/CAS 분석 결과를 대체하지 않는 재구축 가능한 보조 인덱스입니다. 원본 상세 데이터와 다운로드는 계속 기존 JSON/CAS에서 조회합니다.

## 스키마와 안전성

`dashboard_index_state`, `dashboard_list_summaries`, `dashboard_list_items` 테이블과 페이지·상태·종류 조회용 인덱스만 추가합니다. 기존 테이블, 컬럼, JSON/CAS를 삭제하거나 변환하지 않습니다. 스키마 생성과 최초 백필은 서버 시작 시 자동 수행되지 않으며 아래 명시적 명령으로만 수행합니다.

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

분석별 트랜잭션으로 기존 인덱스 행을 교체하며 `(analysis_id, list_kind, item_id)` 기본 키로 중복을 방지합니다. 출력의 원본 개수와 인덱스 개수를 비교하십시오. 한 분석의 투영이 실패하면 해당 분석은 `INCOMPLETE`로 기록되고 목록 API는 빈 목록 대신 HTTP 409 `index_not_ready`를 반환합니다. 원인을 수정한 뒤 같은 재구축 명령을 다시 실행할 수 있습니다.

## 저장 시 투영

원본 JSON/CAS 저장과 SQLite 커밋이 성공한 다음 read model을 갱신합니다. read model 갱신 실패는 이미 성공한 원본 저장을 되돌리지 않습니다. 스키마가 아직 생성되지 않은 환경에서는 투영을 건너뛰므로 실제 환경에 자동 마이그레이션이 일어나지 않습니다.

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
