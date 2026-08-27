# Architecture v5 설계 리뷰 체크리스트

이 문서는 역할별 작업과 전체 설계 검토에서 빠뜨리면 안 되는 항목을 확인합니다. 모르는 용어는 [쉬운 용어집](../GLOSSARY.md)에서 확인하세요.

전체 검토 현황은 [PM 전체 관리 Issue #1](https://github.com/SASTsimi/sastsimi/issues/1)과 [실제 Issue 현황](../review/ISSUE_TRACKER.md)에서 확인하고, 마지막 전체 흐름 검토는 [최종 Issue #10](https://github.com/SASTsimi/sastsimi/issues/10)에서 수행합니다.

## Issue와 PR 준비

- [ ] 담당자는 자신의 역할별 상위 Issue(#2–#9)를 확인했습니다.
- [ ] 담당자가 필요한 세부 작업을 하위 Issue로 직접 만들었습니다.
- [ ] 각 하위 Issue에 담당자, 쉬운 설명, 수정 문서, 완료 조건과 상위 Issue 번호가 있습니다.
- [ ] PR에 `Closes #하위-Issue`와 `Refs #역할별-상위-Issue`가 함께 있습니다.
- [ ] 모든 하위 Issue와 연결 PR이 끝난 뒤에만 역할별 상위 Issue를 닫습니다.

## 파트 리뷰

- [ ] 담당 역할, 범위와 비목표가 명확합니다.
- [ ] 역할 담당자 이름·GitHub 계정·Issue 번호가 `OWNERSHIP.md`, tracker와 실제 GitHub에서 일치합니다.
- [ ] Issue 상단만 읽어도 한 줄 설명, 이번에 할 일과 완료 산출물을 이해할 수 있습니다.
- [ ] 입력과 출력 데이터 묶음·상태(`record/state`)를 만드는 역할과 받는 역할이 명확합니다.
- [ ] 역할이 가질 수 없는 권한이 명시되었습니다.
- [ ] 오류, 미지원, 시간 초과(`timeout`)와 자원 한도(`budget`) 소진을 `FALSE`와 구분합니다.
- [ ] 같은 시점으로 고정한 저장소 사본(`RepositorySnapshot`)을 유지합니다.
- [ ] 앞 단계와 뒤 단계(`upstream/downstream`)의 필수 검토를 받았습니다.
- [ ] 담당 하위 Issue와 역할별 상위 Issue(#2–#9)를 PR에 연결했습니다.
- [ ] Wiki와 Mermaid 영향을 확인했습니다.
- [ ] Blocker/High가 0입니다.
- [ ] 남은 Medium/Low에 owner와 후속 계획이 있습니다.

## 전체 설계에서 바뀌면 안 되는 조건

- [ ] HypothesisProposal은 `HYPOTHESIS_ONLY / NON_FINAL`입니다.
- [ ] 필요한 코드는 위치를 기준으로 필요할 때만 조회(`on-demand retrieval`)합니다.
- [ ] 기본 검증 모드는 필요할 때 찬성·반대 근거를 따로 모으는 `CONDITIONAL_DEBATE`입니다.
- [ ] Pro와 Con은 독립 NEW session을 사용합니다.
- [ ] 새 우회·영향·연계 공격(`bypass/impact/chain`) 주장은 새 가설로 재검증합니다.
- [ ] Primitive DB는 queue 또는 Finding 저장소가 아닙니다.
- [ ] Research Agent가 verdict·CWE·Gate·Report를 확정하지 않습니다.
- [ ] Technical Evidence Gate와 Rule Scope Impact Gate가 분리됩니다.
- [ ] 공식 정책이 없으면 판단과 보고서 전달을 허용하지 않는 `UNCERTAIN + DENY`입니다.
- [ ] Reporter의 모든 선행 조건이 명시됩니다.
- [ ] 사람만 최종 공개를 결정합니다.

## 전체 시나리오

- [ ] 미리 정한 반증 조건이 실제 코드에서 확인되었을 때만 `FALSE`가 됩니다.
- [ ] 판단을 보류한 가설의 부족 조건을 다른 `TRUE` 결과가 채우면, 바로 합치지 않고 새로운 연계 가설로 다시 검증합니다.
- [ ] Docker 전체 재현과 PoC가 어떤 가설·코드 위치·관찰 결과를 뒷받침하는지 추적됩니다.
- [ ] 기술적으로 `TRUE`여도 공식 정책을 확인할 수 없으면 보고서 전달을 허용하지 않습니다.
- [ ] 기술 검토에서 보완이 필요하면 구체적인 요청과 함께 검증 또는 추가 탐색 단계로 돌아갑니다.
- [ ] LLM 로그인·인증 실패를 취약점이 아니라는 뜻의 `FALSE`로 바꾸지 않고 별도 오류로 남깁니다.
- [ ] [Final Issue #10](https://github.com/SASTsimi/sastsimi/issues/10)의 전체 종단 시나리오를 통과합니다.

## 최종 통합 확인

- [ ] 정본 23단계가 README, overview, Wiki와 Mermaid에서 일치합니다.
- [ ] 정본/Wiki Mermaid가 동일하며 실제 렌더링됩니다.
- [ ] broken local link와 Markdown fence 오류가 0입니다.
- [ ] [PM 전체 관리 Issue #1](https://github.com/SASTsimi/sastsimi/issues/1)의 역할별 상위 Issue, 모든 하위 Issue와 `main` 대상 PR이 [최종 Issue #10](https://github.com/SASTsimi/sastsimi/issues/10)에 연결됩니다.
- [ ] 모든 Blocker/High가 닫혔습니다.
- [ ] Medium은 해결되었거나 owner·근거·목표 시점과 함께 연기되었습니다.
- [ ] 최종 검토 대상을 고정한 commit SHA(`review freeze SHA`)를 PR에 기록했습니다.
- [ ] 검토 대상 고정 이후 새 commit이 생기면 독립 검토를 다시 받았습니다.
- [ ] 독립 최종 검토자의 최신 승인이 있습니다.
- [ ] 상태 변경은 별도 최종 승인 PR에서 수행합니다.
