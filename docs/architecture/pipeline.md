# 실제 분석 파이프라인

## 구현된 책임

일반 사용자는 `sastsimi analyze <repository> --commit <SHA>`를 실행합니다. CLI는
기본 설정을 읽고 `SimpleAnalysisApplication`을 구성한 뒤 다음 순서로 진행합니다.

```text
저장소 준비 + AST/OpenGrep/CodeQL 정적 분석 + 공식 정책 snapshot 수집
→ STATIC_DONE
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

정적 분석은 취약점을 확정하지 않고 Agent가 검토할 코드 사실을 만듭니다. 각 가설은
자기 checkpoint를 가지며, Chaining이 만든 자식 가설도 같은 전체 검증을 다시 거칩니다.
공개 GitHub 정책 수집은 분석 시작 시 한 번 수행하고 같은 분석의 Scope Gate가 저장된
snapshot을 공유합니다. `resume`은 외부 정책을 다시 조회하지 않습니다.

새 분석의 시간 설정 기본값은 `unlimited`입니다. 유한한 숫자를 설정하면 기록된
LLM 호출시간 누적과 OpenGrep·Semgrep 각 단계의 종료 시각에 적용되며, 하나의
전체 분석 wall-clock 타이머는 아닙니다. 개별 LLM·정적 검사·Docker 호출은
별도의 유한한 timeout과 재시도 한도를 유지합니다.
정적 검사 한 회 예산 `static_scan_pass_seconds`는 기본 180초입니다. 예산에
도달한 파일·규칙은 `not_attempted_budget`로 기록하며 같은 범위의 `resume`에서
다시 시도합니다. 누적 LLM 시간이나 전체 분석 종료 시각과 별개입니다.
기존 설정의 양의 정수 시간 제한도 그대로 유효합니다. 정적 검사는 저장된 원문과
커밋·규칙·도구 지문을 다시 검증해 파일/규칙별 성공 증거만 재사용합니다. 선택형
Semgrep fallback을 켜면 OpenGrep이 검증하지 못한 제품 코드 조합만 넘깁니다.
구문 오류나 시간 초과의 전체 경로·규칙·이유는 coverage artifact에 남습니다.
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
정적 범위가 완전할 때 `COMPLETE`, 누락이 남으면 `PARTIAL`입니다. Agent 오류가
남으면 `BLOCKED`/`FAILED`가 우선합니다. 어느 상태도 취약점 확정이 아닙니다.

## 코드 위치

- CLI: `src/sastsimi/interfaces/cli/main.py`
- 분석 시작과 가설 등록: `src/sastsimi/simple_runtime/application.py`
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

가설은 안정성을 위해 기본적으로 순차 처리합니다. 진행률은 실제 생성된 checkpoint 수를
기준으로 계산하며, 앞으로 생길 가설 수를 추정한 가짜 퍼센트는 사용하지 않습니다.
