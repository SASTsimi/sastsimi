# Policy-backed Scope Gate 검증 기록 (2026-09-26)

범위: PR의 정책 출처 발견·고정 스냅샷·인용 검증·보고서 읽기 경계. 이 검증은 새로운 저장소 전체 분석이나 LLM 호출을 수행하지 않았습니다.

## 읽기 전용 실제 조회

인증정보 없이 `GitHubPolicyDiscovery`의 실제 pinned HTTPS 경로로 GitHub의 기본 브랜치·Contents·Git Trees API를 조회했습니다. Contents 응답은 고정 commit의 Git tree와 blob SHA로 대조해 symlink 역참조를 공식 정책으로 오인하지 않도록 확인합니다.

- `microsoft/vscode-docs`: `FOUND`, 저장소 루트 `SECURITY.md`, 발행자 `microsoft/vscode-docs`, Git blob `869fdfe2b246991a053fab9cfec1bed3ab532ab1`; 다운로드한 전체 바이트의 SHA-256이 반환된 해시와 일치했습니다.
- `dgtlmoon/changedetection.io`: `ABSENT` / `POLICY_NOT_PUBLISHED`; 조회 시점의 대상 저장소와 동일 소유자 기본 정책 위치에 게시된 `SECURITY.md`를 발견하지 못했습니다. 이는 시험 또는 외부 제보 허가의 부정이 아니라 허가 근거 미확인(`UNCERTAIN`)입니다.

두 결과 모두 조회 당시 기본 브랜치의 정책 상태이며, 과거 분석의 고정 commit이나 기존 A-005 분석을 다시 판정한 결과가 아닙니다. 기존 분석의 정책 스냅샷은 `resume`에서 다시 조회하지 않습니다.

## 로컬 검증

- 정책 출처, Gate, 보고서, 대시보드, `resume`의 mock 기반 집중 테스트: 106개 통과. 보수적 제한 처리 보강 후 관련 집중 테스트 58개 통과.
- `ruff format --check .`: 통과.
- `ruff check .`: 통과.
- `mypy --strict src tests`: 811개 파일 검사, 통과.
- `scripts/validate-current-docs.ps1`: 필수 문서 21개와 Markdown 링크 검사, 통과.
- PowerShell에서 `.venv` 활성화 후 `python -m pytest -q -n 4`: 3,518개 통과, 24개 건너뜀, 기존 reporting fixture의 Pydantic 직렬화 경고 12개. 실패 없음.

제한: `SECURITY.md`가 존재해도 다섯 정책 축의 명시적·적용 가능한 근거가 없으면 `ALLOW`를 만들지 않습니다. 명시적 제한 문구가 있으면 PoC의 모든 동작이 준수하는지 자동으로 증명할 수 없어 `UNCERTAIN`으로 남깁니다. 자연어 제한 탐지는 완전하지 않으므로 `ALLOW`도 자동 제보 허가가 아닌 사람 검토 대상입니다. `ALLOW`는 비공개 제보 정책 조건의 예비 판정이며 공개 허가가 아닙니다. 자동 외부 제출·공개 기능은 없습니다.
