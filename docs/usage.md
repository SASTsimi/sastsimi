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

Windows PowerShell에서 Dify의 고정된 공개 소스 commit을 분석하려면, 각 줄을 별도 한 줄 명령으로 실행합니다. 먼저 기존 설정의 Provider가 Codex `gpt-6-sol`인지 확인하세요. 이 명령은 저장소 코드를 로컬에서 분석하며 Dify 서비스에 요청하거나 제보를 전송하지 않습니다.

```powershell
.\.venv\Scripts\Activate.ps1
sastsimi analyze https://github.com/langgenius/dify.git --commit 8387590ace4a094de812b7847fc6a4c3a27cd52b
```

사람이 보는 기본 출력은 다음처럼 간단합니다.

```text
[██████------------------] 25% 4/16 PRO_CON_DONE
분석 ID: A-001
현재 단계: PRO_CON_DONE
대시보드: http://127.0.0.1:8765/analyses/A-001
```

진행률은 시간으로 만든 가짜 값이 아니라 저장에 성공한 작업 수와 현재 알려진 전체 작업 수로 계산합니다. Chaining이 새 가설을 만들면 전체 작업 수가 늘어 일시적으로 비율이 낮아질 수 있습니다.
한 가설이 `BLOCKED`여도 다른 가설의 단계가 실제로 실행 중이면 전체 상태는 `RUNNING`과 현재 가설을 표시합니다. 실행이 끝나면 남은 `FAILED` 또는 `BLOCKED`를 표시합니다.

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
OpenGrep 규칙 묶음은 원본 규칙 파일과 동일한 전체 저장소 루트를 순차 검사합니다. 중단 뒤 `sastsimi resume A-001`을 실행하면 정확한 분석 ID·저장소·commit·도구 지문과 CAS가 일치하는 완료된 묶음과 재검증된 부분 결과를 재사용합니다. 모든 엔진을 마친 뒤에도 미검증 파일·규칙 조합이 남거나 설정된 CodeQL이 실패하면 전체 성공 전이므로 `STATIC_DONE`이 `BLOCKED`이고 가설·Finding·보고서를 생성하지 않습니다. 저장소별 별도 설정은 필요 없지만 묶음별 시작 비용 때문에 총 실행시간이 늘 수 있으며, 모든 저장소의 `COMPLETE`는 보장하지 않습니다.
파싱 경고 파일이 `paths.scanned`에 있어도 해당 파일·규칙은 완료로 세지 않습니다. 위치가 확인된 파싱 경고와 미검사 파일이 함께 있으면, 선택형 Semgrep fallback이 켜진 경우 검증된 OpenGrep 부분 결과만 유지하고 나머지 파일·규칙 조합을 Semgrep으로 넘깁니다. fallback이 꺼져 있으면 미검사 파일이 있는 묶음은 OpenGrep으로 재시도합니다. OpenGrep이 실패해도 Python AST와 설정된 CodeQL을 독립 실행해 성공 결과를 보존합니다. Semgrep마저 실패·건너뛰면 누락 목록을 남긴 채 `BLOCKED`입니다. 같은 입력·도구 지문에서 파싱 경고 외 누락이 없는 결정적 결과는 `resume`으로 무한 반복하지 않으며, 규칙·추적 파일·도구 지문이 바뀌면 필요한 범위를 다시 검사합니다.

분석 중에는 데이터 디렉터리의 전용 `workspaces/<workspace-id>` checkout을 다른 프로세스나 편집기로 수정하지 마세요. 실행 전 commit과 작업 트리 상태를 확인하지만, 검사 도중 변경된 파일을 분석하는 작업은 지원하지 않습니다. 동시 수정이 의심되면 그 결과를 제보 근거로 쓰지 말고 새 분석 ID에서 다시 시작하세요.

Semgrep fallback을 켜면 OpenGrep 규칙 묶음의 각 실행을 최대 120초로 제한해 한 묶음이 전체 시간을 독점하지 않게 합니다. 이어지는 Semgrep 재검사 묶음은 최대 128파일과 Windows 명령줄 24,000 UTF-16 단위로 제한합니다. 길이 제한을 넘는 단일 경로는 별도 미검증으로 남기고 다른 경로는 계속 검사합니다. 결과 JSON을 크기 제한이 있는 분석별 임시 파일에 받으며, 이전 32파일 성공 기록과 새 묶음의 부분 성공은 원본을 다시 검증한 뒤에만 인정합니다. Semgrep 한 묶음이 120초 안에 끝나지 않으면 남은 실행시간 안에서 더 작게 나누고, 단일 파일의 프로세스 시간 초과 또는 JSON `Timeout`은 `--timeout 30`으로 한 번만 재시도합니다. 같은 파일의 결정적 파싱 오류나 길이 제한·전체 시간 제한은 억지로 성공 처리하지 않습니다. `sastsimi dashboard`의 정적 검사 항목에서 미검증 상대 경로·규칙·이유를 최대 100개 확인할 수 있고 전체 목록은 해당 분석의 coverage artifact에 보존됩니다.

Windows PowerShell의 선택형 설정 명령은 각각 한 줄입니다. `.venv`를 활성화한 터미널에서 실행하고 기존 `setup`의 사용 제한·모델 옵션이 있다면 다시 지정하세요. [Semgrep CE](https://semgrep.dev/products/community-edition/)는 Windows에서 Python으로 설치할 수 있고 로컬 규칙 실행에 로그인이 필요하지 않습니다.

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install semgrep
semgrep --version
sastsimi setup --non-interactive --auth subscription --provider codex --model gpt-6-sol --profile full --docker-network none --semgrep-fallback
sastsimi resume A-001
```

설정 변경 전 이미 진행 중인 분석은 먼저 종료될 때까지 기다리세요. `--semgrep-fallback`을 사용하지 않으면 Semgrep은 필수가 아니며, 누락이 있으면 명확히 `BLOCKED`로 표시됩니다.
최초 분석에서 수집해 저장한 공식 정책도 분석마다 하나의 고정된 snapshot으로 재사용합니다. `resume`은 정책을 다시 조회하지 않으며, 인터넷의 정책이 바뀌었더라도 이전 Scope Gate와 PoC 기록을 조용히 바꾸지 않습니다. 새 정책으로 판단하려면 새 분석을 시작합니다.
같은 분석을 다른 PowerShell에서 이미 실행 중이면 두 번째 `resume`은 중복 분석을 시작하지 않고 현재 상태와 `ANALYSIS_ALREADY_RUNNING` 이유를 반환합니다. 첫 번째 프로세스가 끝난 뒤 다시 재개할 수 있습니다. 잠금은 프로세스가 비정상 종료돼도 운영체제가 해제합니다.
자동 복구 횟수를 이미 소진한 PoC는 `resume`만으로 새 시도를 만들지 않습니다. 실행 오류는 계속 `BLOCKED`로 남고 취약점 `FALSE` 판정이 아닙니다. 다만 과거 기록의 마지막 PoC가 정상 실행됐고 근거 부족 해석이 정확한 artifact로 검증되면, 명시적 `resume`에서 그 가설만 `INCONCLUSIVE`로 종결할 수 있습니다.
분석 프로세스가 강제로 종료되면 마지막 `RUNNING` 체크포인트가 남을 수 있습니다. 프로세스가 실제로 끝났는지 확인한 뒤 `resume`으로 중단 단계를 조정하세요. 새 Agent 호출이 발생할 수 있으므로 사용량도 확인해야 합니다. 시간만 보고 정상적인 장시간 PoC를 실패로 간주하지는 않습니다.

선택형 `facts_survey`와 병렬 처리 설정도 성공한 가설·Agent 단계를 중복 실행하지 않도록 체크포인트를 사용합니다. 기본값은 기존 `current` 가설 생성과 가설 1개씩 처리입니다. 설정과 주의사항은 [Provider 설정](provider-setup.md#선택형-분석-설정)을 참조하세요.

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

- 현재 단계·상태·실제 진행률
- 가설 수와 가설별 최종 판정
- Agent가 확인한 근거·행동·판정 이유 요약
- 허용·제외된 Primitive와 Chaining 부모·자식 관계
- Finding과 기존 Markdown 보고서 링크; 검증된 새 보고서라면 영문·국문·PoC·근거 파일 및 ZIP 다운로드 링크
- Scope Gate의 정책 수집 상태, 출처 URL·개정, 다섯 검토 항목의 판정·인용·이유와 비공개 제보 조건 표시
- Provider별 호출 수·확인된 토큰/비용·비용 미제공 호출 수와 추가 사용량 가능성
- 정적 검사 파일·규칙 검증 수, 엔진별 검증 수, 최대 100개의 상대 경로·누락 이유, 알려진 소스 확장자 중 현재 규칙 범위 밖인 파일, Python AST 파싱 오류와 CodeQL의 Python-only 범위

대시보드는 저장 데이터를 읽기만 합니다. 취소·재시도·판정 변경·공개 승인을 수행하지 않으며 기본적으로 외부 네트워크에 공개하지 않습니다.

## 4. 결과·PoC·보고서

```text
sastsimi result A-001
sastsimi poc F-001
sastsimi report show F-001
sastsimi report export F-001 --format markdown
```

`result`는 분석 상태와 Finding 목록을, `poc`는 실제 실행에 성공한 validated PoC만 보여 줍니다. `report show`는 current Finding의 기존 한국어 Markdown을 보여 주고 `report export`는 파일 위치를 반환합니다. 검증된 새 번들이 있으면 export 출력에 `bundle_path`가 추가됩니다. 첨부파일은 대시보드에서 개별 다운로드하거나 `bundle.zip`으로 받을 수도 있습니다. 기존 `F-NNN.md` 경로와 저장된 과거 보고서는 그대로 유지합니다.

새 Finding의 보고서 번들은 다음과 같이 저장됩니다.

```text
reports/<analysis_id>/F-001.md
reports/<analysis_id>/F-001/report_en.md
reports/<analysis_id>/F-001/report_kr.md
reports/<analysis_id>/F-001/poc.sh
reports/<analysis_id>/F-001/evidence/provenance.json
reports/<analysis_id>/F-001/evidence/stdout.txt  (안전할 때만)
reports/<analysis_id>/F-001/evidence/stderr.txt  (안전할 때만)
reports/<analysis_id>/F-001/manifest.json
reports/<analysis_id>/F-001/bundle.zip
```

`report_en.md`는 GitHub 비공개 security advisory에 옮기기 쉽고 `report_kr.md`는 사람이 읽기 쉬운 표현을 사용합니다. 두 파일 모두 같은 순서로 요약, 영향 대상·테스트 버전, 심각도·CWE, 기술 설명, 재현·PoC, 근거, 영향, Scope Gate·한계, 수정 제안을 담습니다. 현재 분석 경로의 실제 검증된 셸 후보는 `poc.sh`입니다. 번들 형식은 `poc.py`도 허용하지만 현재 분석 경로에서 Python PoC를 자동 선택하지는 않습니다. `evidence/provenance.json`과 `manifest.json`에는 출처 참조·해시를 기록합니다.

분석한 commit만으로 영향받는 전체 버전 범위, 수정 버전, 심각도나 CVSS를 확정하지 않습니다. 근거가 없는 필드는 `Needs review`/`검토 필요`로 남기며 GitHub 제보 양식에 제출하기 전에 사람이 채워야 합니다. 첨부 PoC에서 민감정보가 가려져 실제 실행된 바이트와 달라졌다면 두 보고서가 이를 알리고 원본·첨부 해시를 구분합니다. 임의의 저장소 파일이나 raw 출력은 첨부하지 않습니다.

외부 정책이 없거나 범위 밖인 결과는 내부 기술 보고서로 생성할 수 있지만 외부 제출·공개가 제한됐다고 표시합니다. 대시보드는 current Finding, Gate와 정책, manifest·첨부 참조·해시를 확인한 후에만 다운로드를 제공하며, 기존 공개 보고서가 제한되는 경우 첨부파일로 이를 우회할 수 없습니다. 과거 단일 보고서에는 새 번들이 자동 생성되지 않습니다. SASTSIMI가 자동으로 외부에 제출하지 않습니다.

공개 GitHub 저장소는 분석 시작 시 기본 브랜치의 `.github/SECURITY.md`, 루트 `SECURITY.md`, `docs/SECURITY.md` 순서로 확인하고, 셋 다 없으면 같은 소유자의 공개 `.github` 저장소를 확인합니다. 정책은 분석한 코드 commit과 다른 개정일 수 있어 출처 URL과 Git blob SHA를 따로 기록합니다. 저장소 내 임의의 링크나 GitHub의 비공개 취약점 제보 버튼을 시험·공개 허가로 간주하지 않습니다. GitHub 외 URL과 로컬 Git 경로에서는 이 자동 수집을 지원하지 않아 정책 상태가 `UNVERIFIED`로 남습니다.

Scope Gate는 정책의 자격·규칙(`rules`), 자산 범위(`asset_scope`), 영향 조건(`impact`), 시험 제한(`testing`), 비공개 제보 조건(`reporting`)을 각각 확인합니다. `PASS` 또는 `FAIL`에는 저장된 정책의 정확한 행과 인용이 필요합니다. 검증된 공식 정책에서 다섯 항목이 모두 `PASS`이고 명시적 제한 문구가 없을 때만 예비 판정 `ALLOW`, 명시적으로 근거가 확인된 제외 항목이 있으면 `DENY`, 정책 부재·조회 실패·근거 부족은 `UNCERTAIN`입니다. 명시적 제한이 있으면 Agent가 준수했다고 판단해도 모든 PoC 동작을 자동 증명할 수 없으므로 사람 검토 전에는 `UNCERTAIN`입니다. `ABSENT`나 `UNVERIFIED`는 명시적 금지인 `DENY`와 다릅니다. `ALLOW`도 자동 제보 허가가 아니며 외부 공개 허용이나 자동 제출을 뜻하지 않습니다. 기술적 `TRUE`나 분석 `COMPLETE`만으로도 제보 가능하다는 뜻이 아닙니다.

새 보고서와 대시보드는 정책 수집 상태, 출처, 개정, 항목별 인용과 판단 이유를 보여 줍니다. 예전 기록의 근거 없는 `ALLOW`는 공개 조회에서 제보 불가로 제한됩니다. `report F-001 --export markdown`은 이 경우 기존 원본을 덮어쓰지 않고 `F-001.restricted.md`를 만듭니다. 정책 근거를 못 찾았던 A-005의 두 보고서는 역사적으로 `UNCERTAIN`이며, 새 정책 검토를 적용하려면 별도의 새 분석이 필요합니다. 최종 외부 제출 여부는 사람이 정책과 기술 근거를 직접 검토해 결정합니다.

## 5. 실행 경로

저장소 분석은 `SimpleRuntime` 한 경로만 사용합니다. `setup`이 저장한 기본 설정을
읽어 실제 저장소 분석을 시작하며, 준비 실패를 다른 시험용 분석 경로로 대체하지
않습니다.

`--data-dir`, `--profile`, `evaluate`, `capability`, `onboarding` 같은 세부 명령과
옵션은 문제 진단 또는 고급 운영을 위해 유지합니다. 일반 사용자는 위의 공개 명령만
사용하면 됩니다.
