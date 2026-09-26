# SASTSIMI 용어집

코드 필드명과 상태값은 영문 원문을 유지하고, 문서에서는 아래의 쉬운 뜻을 함께
사용합니다.

## 실행과 저장

| 용어 | 쉬운 뜻 |
|---|---|
| `SimpleRuntime` | 다음 단계를 호출하고, 결과와 현재 위치를 저장하며, 실패 지점부터 재개하는 실행 관리자 |
| `stage` | 분석 파이프라인의 한 단계 |
| `checkpoint` | 특정 가설이 어느 단계까지 끝났는지 저장한 기록 |
| `artifact` | 정적 분석 결과, Agent 출력, PoC, Gate 결과처럼 실행이 만든 자료 |
| `StoredDataRef` | artifact의 종류·수정본·내용 hash를 함께 가리키는 정확한 참조 |
| `analysis_id` | 분석 실행 하나를 구분하는 내부 ID |
| `workspace_id` | 준비된 코드 작업공간을 구분하는 ID |
| `commit_id` | 실제로 분석한 Git commit |
| `hypothesis_id` | 취약점 가설 하나를 구분하는 ID |
| `attempt_id` | 같은 단계의 실행 또는 재시도 한 번을 구분하는 ID |
| `record_id` | 저장된 결과의 정확한 수정본을 구분하는 ID |
| 자동 복구 | 재시도 가능한 실행 오류를 분류하고, 제한된 수정 또는 재생성 후 같은 분석을 다시 진행하는 절차 |
| 복구 결정 | 오류 증거와 저장소 설정을 바탕으로 재시도·입력 재생성·일회용 환경 재구성·중단 중 하나를 선택해 저장한 기록 |

## 상태와 판정

| 용어 | 쉬운 뜻 |
|---|---|
| `PENDING` | 실행을 기다리는 상태 |
| `RUNNING` | 현재 실행 중인 상태 |
| `SUCCEEDED` | 단계가 정상적으로 끝난 상태 |
| `BLOCKED` | 인증·환경·외부 조건을 해결한 뒤 재시도할 수 있는 상태 |
| `FAILED` | 해당 입력과 시도에서는 복구할 수 없이 끝난 상태 |
| `TRUE` | 근거와 validated PoC로 취약점 성립을 확정한 판정 |
| `FALSE` | 실제 반증 근거로 가설이 성립하지 않음을 확정한 판정 |
| `HOLD` | 정보나 조건이 부족해 판단을 보류한 판정 |
| `REVISE` | Technical Gate가 같은 가설의 Verification 보완을 요구한 결과 |
| `RECOVERY_EXHAUSTED` | 같은 복구 계보가 최대 3회에 도달해 자동 재시도를 안전하게 중단한 상태 |

오류, 인증 실패, 도구 미설치, timeout과 Docker 실패는 `FALSE`의 근거가 아닙니다.
이러한 실행 오류는 취약점 판정이 아니라 미검증 상태로 남습니다. 한 가설의 복구가
끝나도 독립적인 다른 가설은 계속 실행하며, 입력과 오류가 바뀌지 않은 소진 계보는
무한히 다시 시도하지 않습니다.

## Agent와 비-LLM 구성요소

| 공식 이름 | 종류 | 역할 |
|---|---|---|
| `Hypothesis Agent` | LLM | 정적 사실에서 취약점 가설 생성 |
| `Pro Agent` | LLM | 가설이 성립하는 근거 수집 |
| `Con Agent` | LLM | 가설을 반박하는 근거 수집 |
| `Verification Agent` | LLM | Pro·Con과 동적 결과를 종합해 판정 |
| `Dynamic Reproduction Agent` | LLM | 환경 요구와 PoC 후보 제안 |
| `CWE Labeling Agent` | LLM | final TRUE에 맞는 CWE 분류 제안 |
| `Technical Gate Agent` | LLM | 근거·PoC·CWE 연결성 검토 |
| `Rule Scope Gate Agent` | LLM | 공식 정책의 범위와 시험 제한 검토 |
| `Chaining Agent` | LLM | Primitive를 연결해 자식 가설 제안 |
| `Reporter Agent` | LLM | 검증된 사실을 한국어 보고서로 정리 |
| `Runtime` | 비-LLM | ID, 순서, 상태, 저장, 재시도와 권한 검사 |
| `Primitive Admission Runtime` | 비-LLM | Gate 결과를 정해진 규칙에 적용해 체이닝 재료 허용 여부 기록 |
| `Reproduction Runtime` | 비-LLM | 검증된 PoC 후보를 Docker에서 실행하고 실제 결과 기록 |

Agent 이름과 역할은 특정 Provider나 model에 고정되지 않습니다.

## 분석 자료

| 용어 | 쉬운 뜻 |
|---|---|
| `RepositoryProfile` | 저장소 언어, package 파일과 실행 관련 설정을 정리한 자료 |
| `StaticFactBundle` | AST·OpenGrep·CodeQL 결과를 코드 위치와 흐름 중심으로 묶은 정적 사실 |
| `source` | 외부 입력이 들어오는 위치 |
| `propagation` | 입력이 함수와 객체 사이를 이동하는 경로 |
| `sink` | 위험한 동작이 실행될 수 있는 위치 |
| `sanitizer` | 위험한 입력을 안전하게 바꾸거나 제거하는 처리 |
| `validator` | 입력이 허용 조건을 만족하는지 확인하는 처리 |
| `PoC candidate` | Agent가 작성했지만 아직 실행 성공이 확인되지 않은 재현 코드 |
| `validated PoC` | 같은 attempt의 Docker 실행에서 가설을 실제로 지지한 PoC |
| `CWE` | 취약점 종류를 나타내는 국제 분류 번호 |
| `Primitive` | 연계 취약점에서 필요한 조건과 얻는 결과를 표현하는 재료 |
| `Finding` | Technical Gate가 승인한 기술적 취약점과 Scope Gate의 제보 가능 여부를 함께 기록한 결과. Scope가 `UNCERTAIN` 또는 `DENY`여도 내부 검토용으로 생성될 수 있음 |
| `ReportDraft` | Finding과 검증 자료만 사용해 만든 보고서 초안 |

## 검토와 출력

| 용어 | 쉬운 뜻 |
|---|---|
| `Technical Gate` | 기술 근거, validated PoC와 CWE가 서로 맞는지 확인하는 단계 |
| `Rule Scope Gate` | 공식 정책상 범위, 금지 시험과 비공개 제보 조건을 근거별로 예비 판정하는 단계 |
| 정책 snapshot | 분석 시작 시 공식 정책의 출처·개정·본문 hash·수집 상태를 저장한 불변 기록. `resume`에서는 같은 기록을 사용 |
| `Chaining` | 기존 Primitive를 연결해 더 큰 영향을 낼 수 있는 새 가설을 만드는 과정 |
| `F-NNN` | 사람이 보기 쉬운 Finding 번호와 Markdown 파일명 |
| `Dashboard` | 분석 상태, Agent 활동과 결과를 보여 주는 로컬 읽기 전용 화면 |
| `Agent activity` | 숨겨진 생각 원문이 아니라 확인한 근거·행동·판정 이유를 정리한 감사 기록 |

외부 제출과 공개 여부는 자동화하지 않으며 사람이 최종 결정합니다.
