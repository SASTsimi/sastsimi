# 저장소 분석과 결과 확인

먼저 [설치 안내](installation.md)에 따라 `sastsimi setup`을 완료합니다.

## 1. 분석 시작

저장소 URL 또는 로컬 Git 경로와 정확한 commit SHA를 전달합니다.

```text
sastsimi analyze <URL-or-local-path> --commit <exact-SHA>
```

예시:

```text
sastsimi analyze https://github.com/adeyosemanputra/pygoat.git --commit 19d17cc8874861142b330636d068bbde54e86b85
```

사람이 보는 기본 출력은 다음처럼 간단합니다.

```text
[██████------------------] 25% 4/16 PRO_CON_DONE
분석 ID: A-001
현재 단계: PRO_CON_DONE
대시보드: http://127.0.0.1:8765/analyses/A-001
```

진행률은 시간으로 만든 가짜 값이 아니라 저장에 성공한 작업 수와 현재 알려진 전체 작업 수로 계산합니다. Chaining이 새 가설을 만들면 전체 작업 수가 늘어 일시적으로 비율이 낮아질 수 있습니다.

자동화에서 구조화된 값만 필요하면 다음을 사용합니다.

```text
sastsimi analyze <repo> --commit <exact-SHA> --format json
```

이때 진행 애니메이션은 출력하지 않습니다. 사람용 출력에서도 진행 표시를 끄려면 `--no-progress`를 사용합니다.

## 2. 상태와 실패 단계 재개

```text
sastsimi status A-001
sastsimi resume A-001
```

`resume`은 저장된 성공 결과와 같은 commit의 Docker image를 재사용하고 실패하거나 끝나지 않은 단계부터 이어갑니다. 성공한 clone·정적 분석·가설·Pro·Con을 다시 실행하지 않습니다.

다음 변경은 이전 실행을 억지로 재사용하지 않고 새 분석이 필요할 수 있습니다.

- 저장소 또는 commit 변경
- Provider·model 변경
- 정적 분석 규칙 변경
- 이전 데이터의 exact reference 불일치

## 3. 읽기 전용 대시보드

다른 터미널에서 실행합니다.

```text
sastsimi dashboard
```

브라우저에서 `http://127.0.0.1:8765`를 엽니다. 분석별 주소는 `/analyses/A-001`입니다.

화면에서 다음을 확인할 수 있습니다.

- 현재 단계·상태·실제 진행률과 AST·OpenGrep·CodeQL 상태
- 가설 수와 가설별 최종 판정
- Agent가 확인한 근거·행동·판정 이유 요약 및 검색 가능한 실행 로그
- 단계별 JSON·텍스트 아티팩트와 비밀값을 제거한 LLM 요청·응답
- 검증된 PoC와 정적·동적 증거의 분리된 목록 및 개별 다운로드
- 허용·제외된 Primitive와 Chaining 부모·자식 관계
- 렌더링/원문 전환이 가능한 Markdown 보고서
- 항목을 선택한 ZIP 또는 `전체 결과 ZIP 다운로드`를 통한 로그·아티팩트·보고서 일괄 저장

대시보드는 저장 데이터를 읽기만 합니다. 취소·재시도·판정 변경·공개 승인을 수행하지 않으며 기본적으로 외부 네트워크에 공개하지 않습니다.

CLI 진행 로그는 분석별로 data directory의 `logs/<analysis-id>.log`에도
저장됩니다. 새 분석에서 발생한 LLM 요청·응답은 credential, token, host 절대
경로와 숨겨진 추론을 제거한 뒤 아티팩트로 저장합니다. 이전 분석에는 이 항목이
없을 수 있습니다.

영문 Markdown 보고서가 `reports/<analysis-id>/F-NNN.en.md`에 준비되어 있으면
같은 Finding을 선택하거나 전체 ZIP을 받을 때 `reports/en/`에 함께 포함됩니다.
대시보드는 영문 내용을 새로 번역하거나 판정을 변경하지 않습니다.

짧은 발표용 실행 순서와 고정된 취약 저장소 예시는
[대시보드 발표 시나리오](dashboard-demo.md)를 참고합니다.

## 4. 결과·PoC·보고서

```text
sastsimi result A-001
sastsimi poc F-001
sastsimi report F-001
sastsimi report F-001 --export markdown
```

`result`는 분석 상태와 Finding 목록을, `poc`는 실제 실행에 성공한 validated PoC만 보여 줍니다. `report`는 current Finding의 한국어 Markdown을 보여 주거나 파일 위치를 반환합니다.

보고서는 다음 내용을 포함합니다.

- `Summary`: 상태, CWE와 영향 요약
- `Details`: 코드 근거, Pro·Con과 최종 판단, 두 Gate 결과
- `PoC`: 검증된 코드, 실행 명령, 종료 코드와 출력
- `Impact`: 영향, 제한사항과 사람이 확인할 항목

외부 정책이 없거나 범위 밖인 결과는 내부 기술 보고서로 생성할 수 있지만 외부 제출·공개가 제한됐다고 표시합니다. SASTSIMI가 자동으로 외부에 제출하지 않습니다.

## 5. 실행 경로

저장소 분석은 `SimpleRuntime` 한 경로만 사용합니다. `setup`이 저장한 기본 설정을
읽어 실제 저장소 분석을 시작하며, 준비 실패를 다른 시험용 분석 경로로 대체하지
않습니다.

`--data-dir`, `--profile`, `evaluate`, `capability`, `onboarding` 같은 세부 명령과
옵션은 문제 진단 또는 고급 운영을 위해 유지합니다. 일반 사용자는 위의 공개 명령만
사용하면 됩니다.
