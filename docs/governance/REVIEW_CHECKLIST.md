# Architecture v5 설계 리뷰 체크리스트

## 파트 리뷰

- [ ] 담당 역할, 범위와 비목표가 명확합니다.
- [ ] 입력과 출력 record/state의 생산자·소비자가 명확합니다.
- [ ] 역할이 가질 수 없는 권한이 명시되었습니다.
- [ ] 오류, 미지원, timeout과 budget 소진을 FALSE와 구분합니다.
- [ ] 같은 RepositorySnapshot을 유지합니다.
- [ ] upstream·downstream 필수 리뷰를 받았습니다.
- [ ] Wiki와 Mermaid 영향을 확인했습니다.
- [ ] Blocker/High가 0입니다.
- [ ] 남은 Medium/Low에 owner와 후속 계획이 있습니다.

## 공통 불변조건

- [ ] HypothesisProposal은 `HYPOTHESIS_ONLY / NON_FINAL`입니다.
- [ ] 필요한 코드는 위치 기반 on-demand retrieval로 조회합니다.
- [ ] 기본 검증 모드는 `CONDITIONAL_DEBATE`입니다.
- [ ] Pro와 Con은 독립 NEW session을 사용합니다.
- [ ] 새 bypass·impact·chain 주장은 새 가설로 재검증합니다.
- [ ] Primitive DB는 queue 또는 Finding 저장소가 아닙니다.
- [ ] Research Agent가 verdict·CWE·Gate·Report를 확정하지 않습니다.
- [ ] Technical Evidence Gate와 Rule Scope Impact Gate가 분리됩니다.
- [ ] 공식 정책이 없으면 `UNCERTAIN + DENY`입니다.
- [ ] Reporter의 모든 선행 조건이 명시됩니다.
- [ ] 사람만 최종 공개를 결정합니다.

## 전체 시나리오

- [ ] named falsification으로 FALSE가 되는 가설
- [ ] HOLD restriction과 TRUE capability가 새 chain 가설을 만드는 흐름
- [ ] Docker FULL_REPRO와 PoC가 현재 가설에 연결되는 TRUE
- [ ] TRUE지만 공식 정책이 없어 Rule Scope Gate가 보고를 차단하는 흐름
- [ ] Technical Gate REVISE가 Verification/Research로 돌아가는 흐름
- [ ] provider 인증 실패가 FALSE로 변환되지 않는 흐름

## 최종 통합

- [ ] 정본 23단계가 README, overview, Wiki와 Mermaid에서 일치합니다.
- [ ] 정본/Wiki Mermaid가 동일하며 실제 렌더링됩니다.
- [ ] broken local link와 Markdown fence 오류가 0입니다.
- [ ] 모든 역할 Issue와 `main` 대상 파트 PR이 최종 승인 Issue/PR에 연결됩니다.
- [ ] 모든 Blocker/High가 닫혔습니다.
- [ ] Medium은 해결되었거나 owner·근거·목표 시점과 함께 연기되었습니다.
- [ ] 최종 review freeze commit SHA를 PR에 기록했습니다.
- [ ] freeze 이후 commit이 생기면 독립 리뷰를 다시 받았습니다.
- [ ] independent final reviewer의 최신 승인이 있습니다.
- [ ] 상태 변경은 별도 최종 승인 PR에서 수행합니다.
