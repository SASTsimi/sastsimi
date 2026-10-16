# PoC 환경과 Docker 의존성

Docker 엔진 연결부터 확인하려면 [원래 문제 해결 항목](../troubleshooting.md#docker-또는-poc-실패)을 먼저 보세요. 이 페이지는 PoC Python 의존성·오프라인 이미지·격리 빌드·브라우저 환경의 상세 절차를 담습니다. 환경 실패는 취약점 반증이 아니며 기존 분석과 근거를 삭제하지 않습니다.

## 환경 준비와 실행 전 검사

### Python 의존성 준비: `AUTO`와 `OFFLINE_ONLY`

새 실행 프로필의 기본
`poc_dependency_bundle_mode = "AUTO"`는 `python:3.12-slim` 태그를 확인하고 로컬에 없을
때만 한 번 받은 뒤 그 실행의 local digest를 고정하고, 안전한 Python 요구사항을 별도
일회용 resolver 컨테이너에서 binary wheel로
수집합니다. resolver에는 대상 저장소를 마운트하거나 실행하지 않고, 완성된 PoC 이미지와
PoC 컨테이너는 계속 `--network none`입니다. 외부 통신을 전혀 허용하지 않거나 자동
resolver가 지원하지 않는 프로젝트라면 `OFFLINE_ONLY`를 선택하고 승인된 Python wheel을
미리 준비할 수 있습니다.

Windows의 `AUTO`에서 `WHEEL_ARCHIVE_INVALID`가 나면
실제 wheel 손상뿐 아니라 Docker가 임시 폴더에 만든 파일의 호스트 읽기 권한 문제일 수
있습니다. 현재 버전은 Windows 임시 폴더 권한을 상속해 받은 파일을 다시 검증합니다.
이전 버전에서 막힌 동일 분석 ID는 오류가 난 초기 검증 단계를 최초 시도 포함 총 3회까지만 재개할 수
있으며, 정적 검사와 앞서 완료된 단계는 보존합니다. 같은 오류가 계속되면 손상된 wheel
또는 권한 문제를 확인해야 하며 PoC 성공이나 취약점 반증으로 취급하지 않습니다.

다음 PowerShell 명령은 지정한 폴더의 `.whl` 파일만 평탄한 TAR로 묶고
SHA-256을 출력합니다. `C:\approved-wheels`는 실제 wheel 폴더로 바꾸고, 그 폴더에는
필요한 직접·전이·빌드 의존성 wheel을 모두 준비하세요. 빈 폴더나 하위 폴더를 포함한
TAR는 사용할 수 없습니다.

```powershell
$wheelDir = (Resolve-Path 'C:\approved-wheels').Path
$wheelNames = @(Get-ChildItem -LiteralPath $wheelDir -File -Filter '*.whl' | Sort-Object Name | Select-Object -ExpandProperty Name)
tar -cf (Join-Path $wheelDir 'poc-wheels.tar') --format ustar -C $wheelDir @wheelNames
$archive = (Resolve-Path (Join-Path $wheelDir 'poc-wheels.tar')).Path
(Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
docker image inspect python:3.12-slim --format '{{.Id}}'
```

`sastsimi setup` 출력의 실행 프로필 `profile.toml`에서 기존 `docker_network`을
`NONE`으로 확인하고, 자동 resolver 대신 수동 묶음만 쓰려면 아래처럼
`poc_dependency_bundle_mode`와 wheel 관련 최상위 필드 두 개를 추가합니다.
`docker_network`을 중복해서 추가하지 마세요. Windows 경로는 TOML에서 `/`로 적고,
출력된 SHA-256을 소문자 64자리로 붙여 넣으세요. 두 wheel 필드는 반드시 함께 있어야
하고 `setup` 옵션으로는 입력할 수 없습니다. `setup`을 다시 실행하면
`profile.toml`이 새로 쓰이므로 두 필드를 다시 지정해야 합니다.

```toml
docker_network = "NONE"
poc_dependency_bundle_mode = "OFFLINE_ONLY"
poc_wheel_archive_path = "C:/approved-wheels/poc-wheels.tar"
poc_wheel_archive_sha256 = "<소문자 SHA-256 64자리>"
```

`AUTO`는 먼저 Linux `python:3.12-slim` 이미지를 확인하고 없을 때만 그 고정 이름으로
내려받은 뒤 digest로 고정합니다. 이어서 평탄한 `requirements.txt`, 기본 PEP 621
`pyproject.toml`, 또는 PoC가 명시한 `pip:<PEP 508 requirement>`의 요구사항을 binary
wheel만으로 수집합니다. resolver는 `bridge` 네트워크가 필요한 유일한 Docker 작업이며,
읽기 전용 컨테이너·capability 제거·리소스 제한으로 실행되고 대상 저장소를 받지 않습니다.

### 비기본 Python 버전과 오프라인 이미지

고정 소스 근거가 다른 Python 버전을 요구하면 초기 Verification은
`python:X.Y[.Z]`를 기록할 수 있습니다. 기본 `AUTO`의 Python 3.12 동작은
그대로이며, 비기본 버전은 운영자가 신뢰 가능한 Linux 이미지를 **미리 로컬에
준비**해 `profile.toml`의 최상위 `poc_offline_base_image_digest = "sha256:..."`로
지정해야 합니다. 도구는 그 digest로만 `--pull never`·`--network none`인
격리 컨테이너를 실행해 실제 인터프리터 버전을 확인합니다. 서로 충돌하는
버전 요구는 `POC_OFFLINE_PYTHON_RUNTIME_CONFLICT`, digest 부재는
`POC_OFFLINE_PYTHON_RUNTIME_DIGEST_REQUIRED`, 이미지 실행 실패는
`POC_OFFLINE_PYTHON_RUNTIME_UNAVAILABLE`, 실제 버전 불일치는
`POC_OFFLINE_PYTHON_RUNTIME_MISMATCH`로 남깁니다. 수동 오프라인 경로에
필요한 wheel 묶음이 없으면 `POC_OFFLINE_PYTHON_RUNTIME_BUNDLE_REQUIRED`입니다.

버전 변경만으로 오래된 고정 의존성의 binary wheel이 생기지는 않습니다.
형식이 맞지 않는 `python:` 또는 `python ` 런타임 요청은 다른 Python 버전으로
조용히 실행하지 않고 `POC_OFFLINE_PYTHON_RUNTIME_INVALID`로 거부합니다.

설치할 패키지가 없는 저장소(패키징 manifest가 없거나 빈 `requirements.txt`)는
검증된 로컬 이미지와 고정 commit의 파일만으로 네트워크 없는 이미지를 만들며,
선택한 manifest가 `.dockerignore`로 제외되면 빌드 성공으로 처리하지 않고
`POC_OFFLINE_MANIFEST_EXCLUDED`로 중단합니다. 이미지의 기본 `ENTRYPOINT`는
PoC 컨테이너 시작 명령에 영향을 주지 않도록 덮어씁니다.

일치하는 wheel을 구할 수 없는 경우에는 sdist·OS 패키지 설치나 PoC 컨테이너의
네트워크 개방으로 우회하지 않고 해당 시도를 미확정 또는 실패 상태로 보존합니다.

### wheel 검증과 빌드 경계

수집한 wheel의 해시·base digest·입력 hash는 artifact로 기록되며, resolver 실패 시에는
해당 시도의 stderr/stdout도 별도 artifact로 보존됩니다.

고정 commit의 제품 manifest와
PEP 621 build-system 요구사항은 권위 있는 입력이라 제거·대체하지 않습니다. 정확한
`No matching distribution` 진단이 있고 manifest와 정규화한 패키지명이 겹치지 않으며
다른 요구사항이 남는 경우에만 Agent가 추가한 `pip:` 항목을 제외할 수 있습니다. 이때
recipe에는 `dependency_resolution_omitted_agent_requirements`와
`dependency_resolution_omission_attempt_refs`가 남습니다.

DB·Redis·메시지 브로커 등
외부 서비스는 이 모드에서 자동으로 기동하지 않으므로, 실제로 필요하면 `INCONCLUSIVE`
또는 환경 미검증으로 남습니다.

`OFFLINE_ONLY`는 로컬에 이미 있는 이미지와 검증된 wheel만
사용합니다. 두 모드 모두 TAR 크기와 TAR 안의 wheel 데이터는 각각 최대 64 MiB이고,
wheel은 최대 20,000개입니다. 대상 Linux 이미지와 호환되는 wheel이어야 하며 대상
태그를 확인할 수 없으면 범용 `py3-none-any` wheel만 허용합니다. 저장소 Dockerfile
대신 생성된 Dockerfile과 고정 commit의 파일로 분리된 빌드 문맥을 만들고,
`pip --no-index --find-links`로 설치합니다. Docker build와 PoC 컨테이너는 모두
`--network none`입니다.

제품 패키지를 wheel로 만들 때 ZIP 형식의 최소 시각보다 오래된
파일 때문에 실패하지 않도록, 이미지 안에 복사된 소스 파일의 수정 시각만 고정된
1980년 값으로 맞춥니다. 파일 내용과 대상 commit은 변경하지 않습니다.

현재 선택된
Buildx 빌더가 로컬 Docker 엔진 드라이버인지 `docker buildx inspect`로 확인하며,
지원되지 않는 빌더면 `POC_OFFLINE_BUILDER_UNSUPPORTED`로 중단합니다.

고정 저장소에
추적된 비밀파일은 Docker 문맥에 넣지 않습니다. 공통 테스트 파일 판정과 지원하는
Flit 패키지 경계를 통해 제품 데이터가 아니라고 확인된 테스트용 비밀파일만
제외합니다. 패키지 데이터 여부가 불명확하거나 그 밖의 비밀파일이면
`PINNED_CONTEXT_SECRET_FILE_DENIED`로 차단합니다.

필요한 wheel·전이 의존성·빌드
의존성 또는 로컬 base image가 없으면 명시적으로 `BLOCKED`로 남습니다. sdist,
VCS·apt 설치, uv/Poetry lock 및 지원되지 않는 manifest는 이 모드에서 설치하지
않습니다. 실패를 PoC 반증이나 `confirmed` Finding으로 바꾸지 않습니다.

두 PoC 빌드 경로는 고정된 저장소의 `.dockerignore`를 문맥에서 제외할 파일을 고르는 데 사용합니다. 단일 `*`와 영숫자 문자 클래스(예: `*.py[cod]`, `cache[12]/`)를 지원하지만 `!` 재포함, `**`, `?`, 범위·부정 문자 클래스는 지원하지 않습니다. 지원하지 않는 패턴은 임의로 해석하거나 무시하지 않고 `DOCKERIGNORE_UNSUPPORTED`로 중단합니다. 필요한 파일이 제외됐다면 해당 commit의 패턴을 확인하고 새 분석에서 수정된 commit을 사용하세요.

`AUTO`가 지원하지 않는 설치 방식(예: VCS/URL, sdist, OS 패키지, uv/Poetry)에는
resolver를 임의로 확장하거나 대상 Dockerfile의 네트워크를 열지 않습니다.

`POC_AUTO_BUNDLE_DOWNLOAD_FAILED` attempt receipt가 있다고 항상 PoC가 차단된 것은
아닙니다. 위 조건을 만족하는 Agent 추가 항목은 receipt를 보존한 뒤 나머지 요구사항으로
계속할 수 있습니다. 반대로 고정 manifest·build 요구사항의 no-match는 제외하거나 같은
source·PoC 입력의 다운로드를 자동 재시도하지 않습니다. 해당 initial Verification과 같은
시도에 정확히 연결된 receipt가 검증되면 가설은 PoC·Finding 없이 `INCONCLUSIVE`로
종료합니다. timeout·receipt 연결 실패·지원하지 않는 manifest는 이 종료로 바꾸지 않고
`BLOCKED`로 남습니다. 이 경우 `POC_AUTO_BUNDLE_MANIFEST_UNSUPPORTED` 또는
`POC_AUTO_BUNDLE_DOWNLOAD_FAILED` artifact를 확인한 뒤 수동 wheel 묶음을 사용하거나
새 분석으로 재시도하세요.

`OFFLINE_ONLY`에서 wheel 묶음 없이 쓰는 기존
경로는 저장소 Dockerfile이 있으면 우선 사용하고, 없으면 Python package 파일을
바탕으로 기본 Dockerfile을 만듭니다. 하위 프로젝트 설치가 실패하면 의존성 없는
이미지로 성공을 가장하지 않고 빌드 오류와 시도 기록을 남깁니다. 그 외 의존성 설치
단계의 빌드 실패가 확인된 경우에만 설치를 생략한 Python 소스 전용 image를 한 번 더
시도합니다. 이 경우 recipe의 `dockerfile_source`가 `GENERATED_NO_INSTALL`,
`degraded`가 `true`가 되고 두 빌드 시도와 원본 진단이 artifact에 남습니다. 소스 전용
image가 만들어졌다는 사실만으로 PoC 검증이나 취약점 판정이 성공한 것은 아닙니다.

두 빌드가 모두 실패하거나 실패 원인이 의존성 설치가 아니면 `DOCKER_BUILD_FAILED`로
중단하고 환경을 확인한 뒤 `sastsimi resume A-001`을 실행합니다.

### 환경 미검증과 실행 전 검사

소스 전용 image만 만들 수 있고 제품 의존성이 재현되지 않았다면 PoC 실행 전에
`POC_ENVIRONMENT_UNVERIFIED`로 차단합니다. 이 환경의 결과를 검증된 PoC나 취약점
부재의 근거로 승격하지 않습니다. `AUTO`는 안전한 Python binary wheel 설치만
제한적으로 처리하며, 최종 build·PoC 네트워크 정책은 자동으로 완화하지 않습니다.

이미 재시도 불가로 저장된 이 PoC는 profile에 wheel 묶음을 추가해도 같은 ID의
`resume`으로 다시 실행되지 않습니다. 기존 분석을 보존하고 검증 가능한 의존성 환경을
준비한 뒤 새 분석을 시작해야 합니다.

`POC_RUNTIME_IMPORT_FAILED`는 컨테이너에서 PoC 또는 대상 앱을 불러오는 중 Python import가 실패했다는 뜻입니다. 실행·stderr·컨테이너 정리 근거를 보존한 `BLOCKED` 상태이며, 실제 공격 요청이 실행됐거나 취약점이 반증됐다는 뜻은 아닙니다.

누락된 모듈이 제품 의존성인지 PoC 코드 의존성인지는 고정 소스와 이미지 입력을 함께 확인해야 합니다. 패키지를 임의로 설치하거나 네트워크 격리를 풀지 않으며, 승인된 의존성·wheel로 환경을 다시 만들 수 있는 경우에만 재검증하세요. 단순 `resume`이 기존 이미지 digest를 재사용한다면 환경 변경이 반영되지 않으므로 같은 오류를 반복할 수 있습니다.

`POC_OFFLINE_BASE_IMAGE_UNAVAILABLE`은 PoC 실행 전 로컬 Python base image를
확인하거나 고정하는 과정이 실패했다는 뜻입니다. 이미지가 실제로 없을 수도
있고 Docker 응답 지연일 수도 있으므로 이 코드만으로 원인을 단정하지 않습니다.
Docker가 정상이고 설정된 이미지가 로컬에 있는지 확인한 뒤 `resume`을
실행하면, 도구가 base-image 준비 상태를 다시 검사한 경우에만 실패한 초기
검증 단계를 제한된 횟수 내에서 재시도합니다.

기존 가설과 PoC 결과를 지우거나
강제로 `COMPLETE`로 바꾸지 않습니다.

이 안전 검사보다 앞서 완료된 PoC는 DB와 아티팩트를 보존하되 현재 검증으로 표시하지 않습니다. 상태가 `POC_REVALIDATION_REQUIRED`라면 같은 분석 ID를 `sastsimi resume A-001`로 재개하세요. 완료된 정적 검사·후보 선별·Pro/Con·초기 검증·PoC 후보는 재사용하고 PoC 실행과 후속 판정만 새 기준으로 확인합니다. 필요한 의존성을 오프라인에서 구할 수 없으면 재검증도 `BLOCKED`로 남으며, 이전 보고서를 제보 근거로 다시 사용해서는 안 됩니다.

PoC 종료 후에는 현재 가설·시도에 정확히 속한 컨테이너만 확인하고 정리합니다. `OWNED_CONTAINER_CLEANUP_FAILED`나 `DOCKER_CONTAINER_LIMIT_REACHED`가 나오면 소유 라벨이 확인되지 않은 컨테이너를 임의로 지우지 말고 상태를 확인하세요. Windows에서 종료된 프로세스의 PID 소유 여부를 확실히 증명할 수 없는 오래된 컨테이너는 자동 정리하지 않습니다. Docker 실행 오류는 가설 반증(`FALSE`)으로 처리하지 않습니다.

`DOCKER_OWNED_LIST_FAILED`는 PoC 전 소유 컨테이너 목록을 읽지 못했다는 뜻입니다.
이 읽기 전용 조회만 짧게 최대 세 번 시도하며, 모두 실패하면 기존 오류를 보존합니다.
세 번째 복구 시도가 **컨테이너 생성 전** 이 오류로 소진된 경우에 한해,
정확한 가설·시도·후보·정적 근거와 Docker 소유 라벨 조회에서 컨테이너가
없음을 확인한 뒤 다음처럼 명시적으로 한 번 재개할 수 있습니다.

```powershell
sastsimi resume A-001 --repair-docker-owned-list-exhaustion hypothesis-...
```

실제 PoC가 실행됐거나 컨테이너가 남아 있거나 부재를 확인할 수 없으면 거부합니다.
해당 가설의 PoC 후보는 이전 오류 근거를 전달받아 다시 만들고, 완료된 다른
가설과 과거 실행 기록은 보존합니다. 이 조치가 취약점 판정이나 Docker의 정상
상태를 보장하지는 않습니다.

Windows에서 Docker 소유 리소스 journal 파일의 원자적 교체가 일시적인 공유 거부로 실패하면 최대 5회 재시도합니다. 계속 `Access denied`가 나면 권한이나 보안 프로그램 점유를 확인하세요. 이때 다른 분석의 컨테이너를 임의로 정리하지 않습니다.

### 브라우저 실행 환경

wheel 묶음을 지정하지 않은 기존 경로에서 Python Playwright가 PoC 실행 중
`BrowserType.launch: Executable doesn't exist` 오류를 내고 실제 실행 stderr가
누락된 Chromium·Firefox·WebKit 바이너리를 가리키면, 해당 가설의 일회용 Docker
이미지에만 공식 브라우저와 시스템 의존성을 설치해 재시도합니다. 오프라인 wheel
모드는 브라우저 다운로드 복구를 지원하지 않으므로 이 오류를 `BLOCKED`로 남깁니다.
지원되는 환경을 준비한 뒤 새 분석을 시작해야 하며, 네트워크 차단을 자동으로 풀지
않습니다. 기존 경로의 설치 위치는 비루트 PoC 사용자도 읽을 수 있는 이미지 내부의 공유
경로로 고정합니다. [Playwright 공식 문서](https://playwright.dev/python/docs/browsers)의
설치·공유 경로 방식을 따르며, Docker 빌드에서 다운로드가 불가능하거나 이미지가
지원되지 않으면 실행 오류로 `BLOCKED`에 남깁니다. 대상 저장소나 호스트 파일은
수정하지 않고 PoC 런타임 네트워크 차단도 해제하지 않습니다.
