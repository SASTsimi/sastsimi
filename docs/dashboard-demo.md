# 대시보드 발표 시나리오

짧은 시연에서 같은 결과를 설명할 수 있도록 저장소와 commit을 고정합니다.

```text
저장소: https://github.com/adeyosemanputra/pygoat.git
commit: 19d17cc8874861142b330636d068bbde54e86b85
```

두 개의 터미널을 준비합니다. 첫 번째 터미널에서 분석을 시작합니다.

```text
sastsimi analyze https://github.com/adeyosemanputra/pygoat.git --commit 19d17cc8874861142b330636d068bbde54e86b85
```

두 번째 터미널에서 대시보드를 실행하고 `http://127.0.0.1:8765`를 엽니다.

```text
sastsimi dashboard
```

## 3분 발표 순서

1. 상단에서 저장소, commit, 실제 진행률과 마지막 갱신 시간을 보여 줍니다.
2. `정적분석 도구`와 `분석 파이프라인`에서 현재 단계를 설명합니다.
3. `Agent 활동·로그`에서 한 가설을 검색하고 LLM 요청·응답의 안전한 사본을 엽니다.
4. PoC와 정적·동적 증거를 각각 열어 판정의 근거를 보여 줍니다.
5. Markdown 보고서를 렌더링 화면과 원문으로 전환합니다.
6. `전체 결과 ZIP 다운로드`로 로그, JSON 아티팩트, PoC·증거와 보고서를 한 번에 받습니다.

분석 결과는 Provider, model, 도구 버전과 실행 환경에 따라 달라질 수 있습니다.
발표 전에 동일한 환경에서 한 번 끝까지 실행해 분석 ID와 예상 Finding을 확인하고,
네트워크나 Provider 문제가 생기면 완료된 분석의 저장 데이터를 대시보드로 보여 줍니다.
