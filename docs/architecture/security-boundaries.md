# 보안 경계

## 구현된 책임

SASTSIMI는 저장소 내용, 정적 분석 출력과 Agent 입력을 신뢰하지 않는 데이터로 다룹니다.
LLM 출력은 제안이며 Runtime 검사를 통과해야 다음 호출, Docker 실행과 저장이 가능합니다.

동적 재현은 Docker 안에서 실행하되 host 경로, Docker socket, 다른 workspace, secret과
허용되지 않은 network 접근을 차단합니다. 로그와 보고서는 민감정보와 로컬 절대 경로를
제거한 내용만 노출합니다. Dashboard는 기본적으로 `127.0.0.1`에 바인딩되는 읽기 전용
화면이며 판정이나 상태를 변경하지 않습니다.

## 코드 위치

- prompt redaction: `src/sastsimi/contracts/prompt_redaction.py`
- 안전 로그: `src/sastsimi/logging.py`
- PoC 입력 검사: `src/sastsimi/simple_runtime/poc.py`
- Docker 경계: `src/sastsimi/sandbox`, `src/sastsimi/simple_runtime/portable_docker.py`
- Dashboard 조회: `src/sastsimi/dashboard`
- 부정 보안 테스트: `tests/security_negative`

## 지켜야 하는 계약

- 자격증명, token, session과 API Key를 profile·로그·보고서에 저장하지 않습니다.
- workspace와 code location은 저장소 root 밖으로 탈출할 수 없습니다.
- Agent가 직접 Finding, validated PoC나 final TRUE를 저장 권한으로 확정하지 않습니다.
- Gate 순서와 현재 revision을 건너뛸 수 없습니다.
- 다른 analysis, hypothesis, generation과 attempt 결과를 섞지 않습니다.

## 현재 제한

로컬 Docker daemon은 강한 host 권한을 가질 수 있으므로 실행 환경 운영자가 Docker 접근
권한을 관리해야 합니다. 원격 Dashboard 공개와 쓰기 기능은 별도 인증·권한 설계 전까지
지원하지 않습니다.
