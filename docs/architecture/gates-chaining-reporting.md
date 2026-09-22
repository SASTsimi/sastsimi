# Gate·Chaining·Finding·보고서

## 구현된 책임

final TRUE와 validated PoC가 준비되면 CWE Labeling이 현재 Verification에 연결된 CWE를
만듭니다. Technical Gate는 근거·PoC·CWE의 연결성을 검토하고, 보완이 필요하면
`TECH_GATE_REVISE`로 같은 가설의 Verification에 돌려보냅니다.

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
- Technical `REVISE`는 Orchestration이 새 목적지를 고르는 흐름이 아니라 같은 가설의
  Verification 보완 흐름입니다.
- 금지된 시험 방법으로 얻은 근거는 Primitive 재료로 사용하지 않습니다.
- Report는 새 보안 사실을 만들지 않고 exact upstream reference만 표현합니다.
- 민감정보 제거 실패나 stale upstream 결과가 있으면 Markdown을 최신 보고서로 내보내지 않습니다.

## 현재 제한

외부 제출과 공개 승인은 자동화하지 않습니다. 보고서 이후 검토·수정·제출은 사람의
권한입니다. HTML과 PDF는 필수 출력 형식이 아니며 Markdown이 현재 기본입니다.
