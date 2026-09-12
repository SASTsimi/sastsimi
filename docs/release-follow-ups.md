# 첫 실행 버전 이후 후속 목록

아래 항목은 첫 production 실행을 막지 않는 범위에서만 후속 작업으로 둡니다. 실제 안전성·정확성 문제로 확인되면 근거와 함께 우선순위를 다시 정합니다.

- HTML·PDF 보고서 출력: Markdown 출력이 첫 버전의 필수 형식이므로 후속입니다.
- 추가 Provider와 model: exact capability·평가·사람 승인 없이 활성화하지 않습니다.
- Python·JavaScript 밖의 언어와 framework: RepositoryProfile과 실제 도구 probe를 함께 추가해야 합니다.
- UI와 dashboard: 현재 CLI의 status·results·reports를 대체하지 않습니다.
- 원격 Sandbox와 분산 worker: host·secret·network·resource 경계를 새로 검증해야 합니다.
- 자동 외부 제출·공개: 사람의 최종 권한 경계를 바꾸므로 현재 자동화 범위에 포함하지 않습니다.

