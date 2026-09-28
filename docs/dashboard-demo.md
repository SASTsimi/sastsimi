# 대시보드 시연·녹화 안내 (Windows PowerShell)

시연용 가상 데이터와 실제 저장 분석은 별개입니다. `--demo`는 DB를 읽거나 쓰지 않는 고정 샘플로 레이아웃과 조작만 연습합니다. 상단의 `DEMO` 표식이 있는 화면은 실제 취약점 결과나 제출 가능한 보고서가 아닙니다. 실제 결과를 발표하려면 `--demo` 없이 이미 완료한 분석을 여세요.

## 준비와 실행

다음은 각각 PowerShell 한 줄 명령입니다. 새 터미널에서 저장소 폴더로 이동한 뒤 실행하세요.

```powershell
.\.venv\Scripts\Activate.ps1
sastsimi dashboard --demo
```

브라우저에서 `http://127.0.0.1:8765/`를 엽니다. 실제 저장 분석을 대신 보여 주려면 서버를 `Ctrl+C`로 종료한 뒤 `sastsimi dashboard`를 한 줄로 실행합니다. 이미 8765 포트를 사용 중이면 기존 서버를 종료하거나 `sastsimi dashboard --demo --port 8766`으로 다른 포트를 사용하세요.

실제 분석 시연에 사용할 공개 테스트 저장소의 예시는 아래와 같습니다. 분석은 오래 걸릴 수 있으므로 발표 당일 처음 시작하지 말고, 미리 완료한 분석 ID를 확인하세요.

```powershell
sastsimi analyze https://github.com/adeyosemanputra/pygoat.git --commit 19d17cc8874861142b330636d068bbde54e86b85
sastsimi status A-001
```

실제 분석의 Finding·PoC·보고서는 실행 환경과 검증 결과에 따라 달라집니다. 시연용 가상 데이터는 이를 대신 보증하지 않습니다.

## 화면 녹화

녹화 도우미는 Windows의 FFmpeg `gdigrab`로 **전체 데스크톱**을 촬영합니다. 다른 창, 알림, 파일 경로, 계정명, 토큰이 영상에 보일 수 있으므로 숨긴 뒤 시작하세요. 스크립트는 브라우저를 자동으로 열지 않습니다. 브라우저에서 로컬 대시보드를 먼저 띄우고 녹화 중에는 필요한 창만 표시하세요.

FFmpeg가 설치되어 `ffmpeg.exe`가 PATH에 있는지 확인한 뒤, 저장소 밖의 절대 경로를 지정합니다. 아래 명령은 예시 경로이며 각 줄이 독립적인 한 줄입니다.

```powershell
ffmpeg -version
.\scripts\record-dashboard.ps1 -Url http://127.0.0.1:8765/ -OutputPath 'C:\Users\Public\Videos\sastsimi-demo.mp4' -DurationSeconds 180 -DryRun
.\scripts\record-dashboard.ps1 -Url http://127.0.0.1:8765/ -OutputPath 'C:\Users\Public\Videos\sastsimi-demo.mp4' -DurationSeconds 180 -ConfirmCapture
```

FFmpeg가 PATH에 없다면 `-FfmpegPath 'C:\path\to\ffmpeg.exe'`를 추가할 수 있습니다. FFmpeg가 없으면 [공식 다운로드 안내](https://ffmpeg.org/download.html)를 참고하거나 운영체제의 신뢰할 수 있는 수동 화면 녹화 도구를 사용하세요. `-DryRun`은 ffmpeg의 존재와 인수를 확인할 뿐 촬영하지 않습니다. 실제 촬영에는 `-ConfirmCapture`가 필요합니다. 최대 촬영 시간은 600초이고 기존 MP4는 덮어쓰지 않습니다. 촬영을 중단하려면 녹화를 실행한 터미널에서 `Ctrl+C`를 누릅니다. MP4는 Git/PR에 포함하지 말고 별도 검토·전달하세요.

## 3–5분 발표 순서

1. `DEMO` 표식을 확인하고 가상 데이터임을 알립니다. 실제 결과 시연이라면 `--demo` 없이 저장된 분석 ID, 저장소와 commit을 확인합니다.
2. 상단 4개 카드에서 정적 검사 커버리지, 가설 검증 진행, 남은 가설, 확정 Finding 수를 설명합니다. `—`는 미집계이지 0이 아닙니다.
3. 상태 격자를 선택하고 정적 도구별 결과, 단계별 수량과 최근 실행 이력을 보여 줍니다. 발견 수는 후보와 확정 판정을 구분합니다.
4. 파이프라인·가설·Source→Sink 흐름과 저장된 Agent 활동을 보여 줍니다. 가상 모드에는 실제 PoC/보고서가 없습니다.
5. 실제 완료한 분석으로 바꾼 경우에만 검증된 PoC·근거·국문/영문 Markdown 보고서와 첨부파일을 열고 원문·렌더링 뷰를 전환합니다. 정책 Scope Gate와 외부 제보 가능 여부를 사람이 다시 확인해야 합니다.
6. `P`로 발표 모드에 들어가 핵심 결과를 요약하고 `Esc`로 나옵니다. 실제 분석의 ZIP은 비밀정보와 권한을 검토한 뒤에만 내려받습니다.

발표 전에 모델·Provider·도구 버전, 저장된 아티팩트, 보고서 언어, 브라우저 화면 비율을 다시 확인하세요. 네트워크/Provider가 불안정할 때는 이미 완료된 실제 분석을 조회하되, 가상 데모를 실제 Finding인 것처럼 보여 주지 마세요.
