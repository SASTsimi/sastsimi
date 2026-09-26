# Gate·Chaining·Finding·보고서

## 구현된 책임

final TRUE와 validated PoC가 준비되면 CWE Labeling이 현재 Verification에 연결된 CWE를
만듭니다. Technical Gate는 근거·PoC·CWE의 연결성을 검토하고, 보완이 필요하면
`REVISE`와 정확한 보완 요청을 저장한 뒤 같은 가설의 PoC 후보부터 다시 실행합니다.
새 Docker 실행 결과로 최종 Verification과 CWE를 갱신한 뒤 Gate를 재검토합니다.
Gate 결정은 가설당 최대 세 번이며, 마지막까지 `REVISE`이면 `INCONCLUSIVE`,
명시적인 `REJECT`이면 제보 불가로 종료합니다. 두 경우 모두 Finding·보고서를
만들지 않습니다.

Rule Scope Gate는 공식 정책에 따라 범위와 금지 시험 방식을 검토합니다. 정책상 외부
제보가 허용되지 않아도 기술 검증 결과를 `FALSE`로 바꾸지 않습니다. Gate 결과는
Finding과 보고서에 남아 사람이 공개 여부를 판단할 수 있게 합니다.

Primitive Admission Runtime은 저장된 Gate 결과를 정해진 허용 규칙에 적용합니다.
Chaining Agent는 허용된 TRUE Primitive와 HOLD Primitive의 조건을 조합해 새 가설을
제안하고, 자식 가설은 정적 근거 조립부터 전체 검증을 다시 수행합니다.

Reporter Agent는 upstream artifact에 존재하는 사실만 사용해 한국어 Markdown 보고서를
만듭니다. 보고서는 Summary, Details, PoC, Impact를 포함하고 파일명은 `F-NNN.md`입니다.

## 코드 위치

- CWE·Gate·Finding·Reporter stage: `src/sastsimi/simple_runtime/stages.py`
- Primitive와 Chaining: `src/sastsimi/simple_runtime/chaining.py`
- 보고서 저장: `src/sastsimi/reporting/markdown_export.py`
- Finding ID: `src/sastsimi/reporting/finding_display_id.py`
- 읽기 전용 조회: `src/sastsimi/dashboard/query.py`

## 지켜야 하는 계약

- Gate는 CWE를 생성하거나 수정하지 않고 정합성만 검토합니다.
- Technical `REVISE`는 같은 가설의 PoC 후보·실행·최종 Verification을 보완하는
  흐름입니다. Gate 요청과 고정 commit의 제한된 source artifact를 exact reference로
  전달하고, 재시작 시 이전 PoC 이후 checkpoint를 원자적으로 무효화합니다.
- TRUE Finding·TRUE Primitive·보고서는 현재 Technical Gate checkpoint와 artifact가
  모두 `ACCEPT`일 때만 만들거나 조회합니다. 실행 오류는 Gate의 `REJECT`나
  `INCONCLUSIVE`로 바꾸지 않습니다.
- 금지된 시험 방법으로 얻은 근거는 Primitive 재료로 사용하지 않습니다.
- Report는 새 보안 사실을 만들지 않고 exact upstream reference만 표현합니다.
- 민감정보 제거 실패나 stale upstream 결과가 있으면 Markdown을 최신 보고서로 내보내지 않습니다.

## 현재 제한

외부 제출과 공개 승인은 자동화하지 않습니다. 보고서 이후 검토·수정·제출은 사람의
권한입니다. HTML과 PDF는 필수 출력 형식이 아니며 Markdown이 현재 기본입니다.
