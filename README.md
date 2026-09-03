# SASTSIMI

SASTSIMI는 정적 분석 도구가 모은 코드 정보를 LLM이 검토하고, 필요하면 격리된 환경에서 재현한 뒤, 사람이 최종 판단하는 보안 분석 연구 프로젝트입니다.

이 저장소는 실행 프로그램을 배포하는 곳이 아닙니다. 팀이 실제 구현을 시작하기 전에 전체 흐름, 역할, 파트 사이의 입출력 약속과 안전 규칙을 함께 검토하는 공간입니다.

## 30초 요약

- AST와 SAST는 코드에서 찾은 사실을 제공합니다. 취약점 여부를 최종 판단하지 않습니다.
- LLM Agent는 취약점 가능성을 제안하고 코드·실행 근거를 검토합니다.
- Docker sandbox(다른 시스템과 격리된 실행 환경)는 필요한 경우에만 사용합니다.
- Gate(다음 단계로 보내도 되는지 확인하는 검토 단계)는 근거와 공식 정책을 확인합니다.
- Reporter의 `ReportDraft`가 마지막 Agent 산출물입니다. 결과 저장 뒤 자동화가 끝나며 외부 공개 여부는 사람이 결정합니다.
- 지금은 **설계 검토 단계**이며 실행 코드는 아직 없습니다.

모르는 용어는 [쉬운 용어집](./docs/GLOSSARY.md), 각 파일의 목적은 [전체 문서 지도](./docs/DOCUMENT_GUIDE.md)에서 확인할 수 있습니다.

## 현재 단계

```text
DESIGN_AUTHORED
REVIEW_REQUIRED
NOT_IMPLEMENTED
```

- v5 설계 초안은 별도 작업 폴더에서 가져온 **검토 중인 설계 초안(`candidate baseline`)**입니다.
- 각 파트 담당자가 자신의 영역과 인접 계약을 검토하는 단계입니다.
- 설계 검토가 끝나기 전에는 Architecture PASS, 구현 완료 또는 runtime-ready를 주장하지 않습니다.
- 자동 분석 결과를 외부에 제출하거나 공개하지 않습니다. 최종 공개 여부는 사람이 결정합니다.

## 현재 목표

첫 번째 목표는 코드를 바로 구현하는 것이 아니라 다음을 먼저 완성하는 것입니다.

1. LLM 중심 분석 파이프라인의 단계와 역할 경계를 팀 전체가 동일하게 이해합니다.
2. 정적 분석, 가설 생성, Verification 중심 검증, 동적 재현, 두 검토 단계(`Gate`)와 보고 사이의 입출력 약속을 명확히 합니다.
3. 보류된 가설의 부족 조건과 두 Gate를 통과한 공격 능력을 연결하는 연계 탐색(`Primitive DB`와 `Chaining Agent`) 규칙을 검토합니다.
4. 회원 로그인·API 방식의 LLM 연결(`provider`), 로그인·대화 상태(`session`), 실행 기록(`logging`)과 비용·평가 정책을 구현 가능한 수준으로 구체화합니다.
5. 파트 간 모순과 Blocker/High 이슈를 제거한 뒤 전체 설계를 승인합니다.
6. 승인된 설계를 기준으로 구현 계획과 검증 계획을 별도 수립합니다.

가져온 원본은 commit에 포함되지 않은 작업 폴더의 파일이었습니다. 따라서 특정 commit에서 나온 파일이라고 주장하지 않습니다. 원본 상태와 파일별 SHA-256은 [가져온 출처 기록](./docs/review/PROVENANCE.md)에 남깁니다. 이 저장소에서 승인된 설계 commit만 별도 PR을 통해 구현 저장소로 전달합니다.

## 전체 분석 흐름

쉽게 나누면 다음과 같습니다.

1. **코드 사실 수집**: 저장소를 실행별 로컬 폴더에 clone하고 분석할 commit을 checkout한 뒤 AST와 SAST를 함께 실행합니다.
2. **가설 생성과 검증**: Orchestration이 가설을 등록해 Verification에 배정하고, Verification이 찬성·반대 근거와 필요한 후속 작업을 관리합니다.
3. **필요한 경우 재현**: Verification 판단에 따라 Docker 격리 환경에서 제한적으로 공격 흐름을 재현합니다.
4. **판정별 연계 탐색**: HOLD의 필요 조건은 즉시, TRUE의 제공 능력은 두 Gate를 모두 통과한 뒤에만 연결해 새 가설을 만듭니다.
5. **근거·정책 검토와 자동화 종료**: 두 Gate를 통과한 결과만 보고서 초안으로 만들고, 결과와 디버깅 정보를 저장한 뒤 Agent 자동화를 끝냅니다.

그 이후의 검토·수정·제출·공개는 Agent 자동화와 공통 action 계약 밖에서 사람이 수행합니다.

아래는 문서와 데이터 형식에서 사용하는 정확한 이름을 포함한 상세 흐름입니다.

```text
Repository input
→ Repository Loader가 git clone과 commit checkout
→ CodeWorkspace 준비
→ AST parse와 SAST 병렬 실행
→ StaticFactBundle
→ constrained HypothesisProposal
→ Orchestration이 가설을 등록하고 가설별 Verification owner를 배정
→ Verification이 on-demand context와 운영 기본 Pro/Con 병렬 검증 관리
→ 필요 시 Verification이 환경 요구사항과 최소 ReproductionPlan 생성
→ Runtime Validator가 plan reference, 호출 권한·상태·예산을 확인해 R7 호출 허가
→ R7 Controller가 host·Docker daemon·secret·egress·resource·lifecycle의 Sandbox 외부 경계를 적용
→ Reproduction Agent가 격리된 Sandbox 내부에서 환경 구성·PoC 작성·실행·관찰·retry를 자율 수행
→ 작은 Dynamic Result Finalizer가 EnvironmentRecipe·AgentLog·실행 PoC·cleanup과 같은 attempt 연결을 검사해 결과 반환
→ final TRUE / FALSE / HOLD
→ FALSE는 terminal
→ HOLD는 REQUIRED Primitive로 즉시 Chaining
→ TRUE는 CWE → Technical Evidence Gate → Rule Scope Impact Gate
→ 두 Gate를 정상 통과한 exact TRUE revision만 PROVIDED Primitive로 Chaining
→ Verification 또는 Chaining의 새 material claim은 새 가설로 등록·재검증
→ 조건 충족 시 ReportDraft
→ AnalysisRunResult에 결과·로그 확정
→ Agent automation end
```

정적 분석 도구는 취약점 최종 판정자가 아닙니다. 함수·클래스 같은 코드 요소(`entity`), 코드 위치, 입력 시작점(`source`), 위험 동작 지점(`sink`), 호출·데이터 흐름과 인증·권한 정보를 제공합니다. 가설(`Hypothesis`)과 체이닝 후보는 아직 사람이 검토할 취약점 결과(`Finding`)가 아닙니다. 새로운 공격 주장은 새 가설로 등록되어 전체 검증을 다시 거칩니다.

LLM Agent의 출력은 그대로 믿지 않습니다. 프로그램 내부 규칙 검사기(`Runtime Validator`)는 token·시간 한도, 호출 권한, 상태가 바뀌는 순서, LLM 연결·로그인 정책, Gate 순서와 Reporter 호출 조건을 확인합니다. R7 Controller는 host·Docker daemon·secret·허용되지 않은 egress·다른 workspace와 자원·lifecycle을 Sandbox 외부에서 차단하고, Reproduction Agent는 그 격리 경계 내부에서 재현 작업을 자율 수행합니다.

## 설계 검토 운영 방식

이 프로젝트는 **main의 공개 초안 + 파트별 PR** 방식으로 설계를 완성합니다.

### Issue와 작업의 관계

```text
#1 PM 전체 관리 Issue
├─ #2–#9 역할별 상위 Issue
│  └─ 각 담당자가 직접 만드는 세부 하위 Issue
│      └─ 세부 작업 PR
└─ #10 전체 최종 검토 Issue
```

1. PM은 전체 목표와 역할 경계가 담긴 #1을 관리합니다.
2. #2–#9는 각 파트의 큰 작업을 나타내는 역할별 상위 Issue입니다.
3. 각 담당자는 자기 역할별 상위 Issue를 읽고 필요한 세부 작업을 하위 Issue로 직접 만듭니다.
4. 하위 Issue에는 담당자, 쉬운 설명, 수정할 문서, 완료 조건과 상위 Issue 번호를 적습니다.
5. 작업 PR은 하위 Issue를 닫고 역할별 상위 Issue를 참고로 연결합니다.
6. PM은 세부 작업을 대신 작성하지 않고 역할 간 충돌과 전체 진행 상태를 관리합니다.
7. 모든 하위 Issue와 연결 PR이 끝나야 역할별 상위 Issue를 닫습니다.
8. #2–#9가 끝나면 #10에서 전체 흐름을 검토합니다.

```text
main  ← Architecture v5 candidate baseline
├─ review/static-context
├─ review/hypothesis-research
├─ review/integration-feasibility
├─ review/control-plane
├─ review/verification
├─ review/dynamic-sandbox
├─ review/gate-reporting
└─ review/data-evaluation
```

- 전체 설계 초안은 `main`에서 누구나 확인할 수 있게 유지합니다.
- 각 담당자는 먼저 자기 세부 작업의 하위 Issue를 만들고, 최신 `main`에서 파트 브랜치를 만든 뒤 `main` 대상으로 PR을 엽니다.
- 하나의 파트 PR은 담당 영역과 필요한 인접 계약만 수정합니다.
- 입력을 제공하는 파트와 결과를 소비하는 파트의 교차 리뷰를 받습니다.
- Blocker/High가 0이 된 뒤 전체 시나리오 검토를 수행합니다.
- 설계 상태 변경은 모든 파트 검토가 끝난 뒤 별도의 최종 승인 PR에서 수행합니다.

전체 절차는 [CONTRIBUTING.md](./CONTRIBUTING.md)를 따릅니다.

검토 현황과 역할별 작업은 [PM 전체 관리 Issue #1](https://github.com/SASTsimi/sastsimi/issues/1), [실제 Issue 현황](./docs/review/ISSUE_TRACKER.md), [역할별 작업 안내](./docs/review/ISSUE_CATALOG.md)에서 확인합니다. 작업을 막는 문제(`Blocker`)와 중요한 문제(`High`)가 모두 해결되어야 최종 승인 PR을 열 수 있습니다. 중간·낮은 문제는 담당자와 후속 계획을 명확히 남겨야 합니다.

## 담당 영역

| 역할 | 담당자 | 핵심 책임 |
|---|---|---|
| LLM 탐색·체이닝 | 배승원 ([@baeseungwon1010](https://github.com/baeseungwon1010)) | 최초 취약점 후보 생성, HOLD REQUIRED 및 Gate-qualified TRUE PROVIDED의 방향성 matching과 token 최적화 |
| 정적분석·컨텍스트 | 김나연 ([@zv9uvr](https://github.com/zv9uvr)) | AST·CodeQL·OpenGrep 결과 정리, 코드 위치·호출 흐름과 LLM용 context 조립 |
| 단독 구현·통합 개발 | 김태현 ([@taehyeon-git](https://github.com/taehyeon-git)), 윤희섭 ([@YHS-Sec](https://github.com/YHS-Sec)) | 전체 모듈의 구현 가능성, 계약 준수 테스트와 통합 계획 검토 |
| PM·아키텍처·워크플로 | 김태현 ([@taehyeon-git](https://github.com/taehyeon-git)), 윤희섭 ([@YHS-Sec](https://github.com/YHS-Sec)) | 전체 구조, 공통 입출력 계약, 사람·LLM 경계, 병렬·직렬 흐름과 오류 정책 |
| Gate·Finding·보고서 | 김혜령 ([@kimhr8463](https://github.com/kimhr8463)) | 검증 근거·정책 범위 검토, 내부 Finding과 안전한 보고서 초안 작성 |
| 검증·반박·플레이북 | 임채민 ([@UltraPeachKeen](https://github.com/UltraPeachKeen)) | 가설별 Context·찬반, 환경 요구사항·최소 `ReproductionPlan`, 최종 판정·Gate 보완 |
| 동적검증·Sandbox | 조근석 ([@Potatonion](https://github.com/Potatonion)) | Sandbox 외부 안전 경계, 자율 Reproduction Agent, versioned 환경 recipe·clean Sandbox·AgentLog·PoC·동적 결과 생산 |
| 데이터·평가·예산 | 성병찬 ([@gitterable](https://github.com/gitterable)) | 평가 데이터·품질 지표와 예산 profile 설계; 실제 예산 강제는 trusted runtime 담당 |

Gate는 Verification verdict를 변경하거나 공개를 승인하지 않습니다. Reporter는 보고서 초안만 작성하고 이후 Agent 자동화는 종료됩니다. 사람의 검토·수정·제출·공개는 이 자동화 밖에서 진행합니다.

동적 재현의 역할 연결은 `R6 Verification의 환경 요구사항·최소 계획 작성 → R4 Runtime Validator의 reference·호출 전제 확인 → R7 Controller의 Sandbox 외부 안전 경계 적용 → R7 Reproduction Agent의 내부 환경 구성·PoC 작성·실행·관찰·retry → 작은 finalizer의 recipe·AgentLog·실행 PoC·cleanup 연결 검사 → R6의 추가 판단`입니다. R7은 실행 증거를 `SUPPORTED | DISPROVED | INCONCLUSIVE`로 해석해 전달하지만 최종 `TRUE | FALSE | HOLD`를 만들거나 바꾸지 않습니다.

## 설계 초안

Architecture v5 candidate baseline과 파생 Wiki는 `main`에서 확인하고 파트별 PR로 검토합니다.

- [Architecture v5 design hub](./docs/architecture-v5/README.md)
- [역할별 검토 Issue 구조](./docs/review/ISSUE_CATALOG.md)
- [실제 Issue 배정·진행 현황](./docs/review/ISSUE_TRACKER.md)
- [GitHub Parent Epic #1](https://github.com/SASTsimi/sastsimi/issues/1)

## 안전 원칙

- 공개 저장소 분석과 운영 서비스 테스트는 별개입니다.
- 공식 scope·rule이 없으면 내용을 추측하지 않고 보고 권한을 거부합니다.
- API key, membership credential, session cookie와 실제 개인정보를 저장하지 않습니다.
- Docker 재현은 승인된 범위의 격리 환경에서만 수행합니다.
- AI 결과와 PoC는 사람의 검토 전 외부에 공개하지 않습니다.
