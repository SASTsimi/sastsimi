# 현재 제한과 후속 작업

이 목록은 현재 코드와 README에 남아 있는 실제 제한만 기록합니다. 구현되지 않았거나
검증하지 않은 기능을 지원한다고 간주하지 않습니다.

- HTML·PDF 보고서 출력: Markdown 출력이 첫 버전의 필수 형식이므로 후속입니다.
- 추가 Provider와 model: exact capability·평가·사람 승인 없이 활성화하지 않습니다.
- Python·JavaScript 밖의 언어와 framework: RepositoryProfile과 실제 도구 probe를 함께 추가해야 합니다.
- 대시보드 쓰기 기능: 로컬 읽기 전용 진행·가설·Chaining·보고서 화면은
  구현됐습니다. 취소·재시도·판정 변경·공개 승인 UI는 권한 설계 전까지
  추가하지 않습니다.
- 원격 Sandbox와 분산 worker: host·secret·network·resource 경계를 새로 검증해야 합니다.
- 자동 외부 제출·공개: 사람의 최종 권한 경계를 바꾸므로 현재 자동화 범위에 포함하지 않습니다.
- CodeQL 조합 확대: 공식 platform bundle과 query pack, 실행량·출력 제한을 확인한
  profile에서만 활성화합니다.
- 배포 전 보안 검토: 권한 우회, 다른 분석의 reference 혼합, secret 노출과 Docker 경계를
  실제 배포 환경에서 다시 확인해야 합니다.

README에 기록된 실제 Provider·OpenGrep·CodeQL·Docker 조합 외의 깨끗한 환경도
정식 출시 전에 추가 검증합니다. 제품의 clone→Markdown 통합 실행 경로가 존재한다는
이유만으로 검증하지 않은 조합까지 production-ready라고 표시하지 않습니다.
