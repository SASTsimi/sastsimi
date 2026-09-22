# 정적 분석과 동적 재현

## 구현된 책임

Repository Loader는 URL 또는 로컬 경로의 저장소를 고정 commit으로 준비하고 추적 파일을
기준으로 언어와 package manifest를 식별합니다. AST, OpenGrep과 활성화 조건을 충족한
CodeQL 결과를 `StaticFactBundle`로 정규화합니다.

동적 재현은 RepositoryProfile, 코드 근거와 Verification 요구를 이용해 환경 recipe와
PoC 후보를 만들고 Docker에서 실행합니다. 작성된 script는 PoC 후보이며, 같은 attempt와
환경에서 실행되어 가설을 지지한 경우에만 validated PoC가 됩니다.

## 코드 위치

- 저장소 준비와 profile: `src/sastsimi/static_analysis/repository_loader.py`,
  `src/sastsimi/static_analysis/repository_profile.py`
- AST·OpenGrep·CodeQL: `src/sastsimi/static_analysis`
- 정적 실행 구성: `src/sastsimi/composition/simple_runtime_composition.py`
- PoC 검사: `src/sastsimi/simple_runtime/poc.py`
- Docker 실행: `src/sastsimi/simple_runtime/portable_docker.py`,
  `src/sastsimi/sandbox/docker_adapter.py`
- 동적 stage: `src/sastsimi/simple_runtime/stages.py`

## 지켜야 하는 계약

- 도구 미설치와 실행 실패를 취약점 없음으로 바꾸지 않습니다.
- CodeQL은 승인된 실행량·출력 제한 조건을 만족한 profile에서만 활성화합니다.
- PoC에 host 경로, 외부 URL, 선언되지 않은 입력이나 민감정보를 허용하지 않습니다.
- recipe, image digest, container와 PoC 실행 결과를 같은 attempt에 연결합니다.
- `DISPROVED`는 실제 반증 근거가 있을 때만 판정에 사용합니다.

## 현재 제한

외부 도구 설치 여부와 실제 활성화 조합은 `sastsimi setup`과 capability 확인 결과에
따릅니다. 운영 검증되지 않은 언어와 build 방식은 자동으로 지원된다고 간주하지 않습니다.
