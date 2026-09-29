# 실제 분석 파이프라인

## 구현된 책임

일반 사용자는 `sastsimi analyze <repository> --commit <SHA>`를 실행합니다. CLI는
기본 설정을 읽고 `SimpleAnalysisApplication`을 구성한 뒤 다음 순서로 진행합니다.

```text
저장소 준비 + AST/OpenGrep/CodeQL 정적 분석 + 공식 정책 snapshot 수집
→ STATIC_DONE
→ 정적 후보 등록·Discovery 선별 + 보조 자유 탐색
→ Hypothesis Agent
→ HYPOTHESIS_DONE
→ Pro·Con Agents
→ PRO_CON_DONE
→ Verification Agent 초기 판단
→ VERIFICATION_INITIAL_DONE
→ Dynamic Reproduction Agent의 PoC 후보
→ POC_CANDIDATE_DONE
→ Reproduction Runtime의 Docker 실행
→ POC_EXECUTION_DONE
→ Verification Agent 최종 판단
→ VERIFICATION_FINAL_DONE
→ CWE Labeling Agent
→ CWE_DONE
→ Technical Gate Agent
→ TECH_GATE_DONE
→ Rule Scope Gate Agent
→ SCOPE_GATE_DONE
→ Primitive Admission Runtime
→ PRIMITIVE_ADMISSION_DONE
→ Chaining Agent
→ CHAINING_DONE
→ Finding Runtime
→ FINDING_DONE
→ Reporter Agent
→ REPORT_DONE
```

정적 분석은 취약점을 확정하지 않고 Agent가 검토할 코드 사실을 만듭니다. 새 분석은 검증된 원본 결과를 근거 수준별 후보로 저장하고 Discovery가 후보별 판정과 이유를 남깁니다.
AST 수집은 파싱에 성공한 Python 제품 파일마다 사실 전체를 별도 content-addressed 아티팩트에 저장합니다. 정렬된 manifest에는 파일 경로·사실 건수·아티팩트 참조가, 정적 번들의 소형 AST 요약에는 manifest 참조·총건수·파싱 실패/초과 크기 경로가 들어갑니다. 10,000건 같은 분석 전체 사실 상한은 없으며, 파일당 2 MiB 입력 제한은 유지합니다. 파싱 실패나 초과 크기의 제품 파일은 빈 결과가 아니라 미검증 범위입니다.
후보 가설에는 후보 파일·줄 주변의 AST 사실만 최대 8 KiB로 골라 붙이고 전체 건수·생략 건수·원본 파일 참조를 명시합니다. 큰 manifest나 파일 전체 사실을 프롬프트에 넣거나 256 KiB 문맥 절단에 맡기지 않습니다. 분석 단계에서 검증된 manifest 경로 인덱스는 후보 간 재사용합니다. 새 manifest의 파일별 참조와 경로·건수를 검증하고 근거가 누락·손상되면 성공이나 `PARTIAL`로 덮지 않고 근거 오류로 멈춥니다. 기존 인라인 AST 형식의 분석은 해당 형식대로 재개하며 새 근거와 혼합하지 않습니다. 이미 후보 처리를 끝낸 구형 `PARTIAL` 분석은 정적 재검사가 새 AST 형식을 도입하려 할 때 기존 상태를 보존하고 새 분석 시작을 요구합니다.
Python 요청 입력 규칙처럼 `candidate_kind=ENTRY_POINT`가 명시된 결과만 입력 지점으로 분류합니다. CodeQL SARIF 결과 하나에 여러 `codeFlows`·`threadFlows`가 있으면 개별 trace마다 다른 후보 ID를 만들고 동일 위치·trace의 중복만 합칩니다. 각 후보의 출처는 원본 아티팩트 참조와 결과 행 인덱스로 추적합니다. 원본 결과나 별도 source·sink 힌트를 임의로 연결해 흐름을 만들지 않습니다.
`INCLUDE`·`UNDECIDED` 후보와 보조 자유 탐색의 가설은 기존 Pro·Con·PoC 흐름에 연결됩니다.
Discovery 판정은 취약점 확정이 아니며, 이전 분석은 저장된 옛 경로로 재개합니다. 각 가설은
자기 checkpoint를 가지며, Chaining이 만든 자식 가설도 같은 전체 검증을 다시 거칩니다.
공개 GitHub 정책 수집은 분석 시작 시 한 번 수행하고 같은 분석의 Scope Gate가 저장된
snapshot을 공유합니다. `resume`은 외부 정책을 다시 조회하지 않습니다.

새 분석의 누적 LLM 시간 설정 기본값은 `unlimited`입니다. 정적 검사 전체에
별도의 180초 종료 시각을 적용하지 않습니다. 기존 설정의
`static_scan_pass_seconds`는 호환을 위해 읽되 일정에는 반영하지 않습니다.
개별 LLM·정적 검사·Docker 호출은 별도의 유한한 timeout과 재시도 한도를 유지합니다.
정적 검사는 Python `.py` 제품 파일만 대상으로 하며 저장된 원문과
커밋·규칙·도구 지문을 다시 검증해 파일/규칙별 성공 증거만 재사용합니다. 선택형
Semgrep fallback을 켜면 OpenGrep이 검증하지 못한 제품 코드 조합만 넘깁니다.
구문 오류나 시간 초과의 전체 경로·규칙·이유는 coverage artifact에 남습니다.
미검증 파일×규칙 조합과 스캔 불가 Python 제품 파일(`unavailable_paths`)은 별도 범위 항목입니다. CLI·대시보드는 각각의 개수와 경로·이유를 표시하고, 대시보드 원장은 전체 목록을 페이지로 읽습니다. 영문·국문 보고서는 같은 개수·이유·경로 예시와 coverage artifact 해시를 담으며, 미리보기만으로 전체 커버리지를 주장하지 않습니다.
검증된 조합의 후보만 Agent에 전달하고, 유효한 증거가 일부 있으면 후속 단계로
진행합니다. 무결성 실패나 검증 근거 부재는 `BLOCKED`입니다. 완료된 Agent는
원래 정적 입력 참조에 묶어 유지하고 새 근거에서 나온 가설만 추가합니다.

최종 `FALSE`는 `VERIFICATION_FINAL_DONE`에서 끝납니다. `HOLD`는 Primitive와
Chaining에는 사용할 수 있지만 CWE, 두 Gate, Finding과 보고서로 진행하지 않습니다.
`TRUE`는 실행에 성공한 validated PoC가 있어야 뒤 단계로 진행합니다.
Technical Gate의 `ACCEPT`만 Scope Gate와 Finding으로 이어집니다. `REJECT`는
제보 불가로 종료하고, `REVISE`는 해당 가설의 PoC 후보부터 다시 검증합니다.
세 번째 Gate 결정까지도 `REVISE`이면 `INCONCLUSIVE`로 종료합니다. 이 두 종료는
보고서를 만들지 않지만, 다른 가설에도 실행 오류가 없고 모두 종료됐다면 분석 상태는
후보 `PENDING`·`ERROR`가 없고 정적 범위가 완전할 때 `COMPLETE`, 검증 가능한 정적 누락·JS/TS 제품 코드가 남으면 `PARTIAL`입니다. Agent 오류가
남으면 `BLOCKED`/`FAILED`가 우선합니다. 어느 상태도 취약점 확정이 아닙니다.

## 코드 위치

- CLI: `src/sastsimi/interfaces/cli/main.py`
- 분석 시작과 가설 등록: `src/sastsimi/simple_runtime/application.py`
- 파일별 AST 수집·manifest 검증·후보 문맥 선택: `src/sastsimi/simple_runtime/ast_facts.py`
- 후보 정규화·Discovery: `src/sastsimi/simple_runtime/candidates.py`,
  `src/sastsimi/simple_runtime/discovery.py`
- stage 순서와 상태: `src/sastsimi/simple_runtime/models.py`
- stage 실행: `src/sastsimi/simple_runtime/runner.py`
- stage별 구현: `src/sastsimi/simple_runtime/stages.py`
- Chaining: `src/sastsimi/simple_runtime/chaining.py`

## 지켜야 하는 계약

- 오류나 인증·환경 실패를 `FALSE`로 바꾸지 않습니다.
- 완료 checkpoint는 입력 reference hash와 stage version이 같을 때만 재사용합니다.
- PoC 후보와 실제 실행 성공으로 검증된 PoC를 구분합니다.
- 모든 결과는 동일 analysis, workspace, commit, hypothesis와 attempt에 연결됩니다.

## 현재 제한

가설은 안정성을 위해 기본적으로 순차 처리합니다. 전체 후보·가설 수의 고정 상한 대신 개별 호출·페이지 크기, Chaining 깊이와 중복·순환 방지를 적용합니다. 진행률은 실제 생성된 checkpoint 수를
기준으로 계산하며, 앞으로 생길 가설 수를 추정한 가짜 퍼센트는 사용하지 않습니다.
