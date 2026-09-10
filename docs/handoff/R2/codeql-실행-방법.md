# R2 검증 자료 — CodeQL 실행 방법

정상/실패 사례(`r2-verification/`)를 만들 때 실제로 CodeQL을 돌린 과정 기록. 값을 손으로 지어낸 게 아니라 실제 도구 실행 결과를 스키마에 맞춰 옮긴 것.

## 1. CodeQL CLI 준비

github/codeql-action 최신 릴리스에서 CLI 번들을 받아 압축 해제.

```bash
curl -sL -o codeql-bundle.tar.gz \
  "https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz"
tar xzf codeql-bundle.tar.gz
```

- CodeQL CLI: **2.26.4**
- 쿼리팩: `codeql/python-queries` **1.8.9**

## 2. 취약한 샘플 코드 작성

Flask `get_order` 핸들러 하나. `/orders/<id>`의 `id` 파라미터를 문자열로 이어붙여 SQL 쿼리를 만드는 전형적 SQL Injection.

```python
@app.route('/orders/<id>')
def get_order(id):
    conn = get_db()
    cursor = conn.cursor()
    query = "SELECT * FROM orders WHERE id = '" + id + "'"
    cursor.execute(query)
    ...
```

git repo를 별도로 init해서 실제 커밋 해시 확보 (`99c66f2`).

## 3. CodeQL 데이터베이스 생성

```bash
codeql database create orders-db --language=python --source-root=sample-app --overwrite
```

## 4. 정상 사례 — 쿼리 실행

```bash
codeql database analyze orders-db \
  codeql/python-queries/1.8.9/Security/CWE-089/SqlInjection.ql \
  --format=sarif-latest --output=sqli-result.sarif
```

`py/sql-injection` 쿼리가 실제로 SQL Injection을 탐지 → SARIF 결과의 줄/열 번호·메시지를 그대로 사용.

## 5. 실패 사례 — 존재하지 않는 DB로 실행

```bash
codeql database analyze orders-db-corrupted \
  codeql/python-queries/1.8.9/Security/CWE-089/SqlInjection.ql \
  --format=sarif-latest --output=sqli-fail.sarif
```

결과: `exit code 2`, `"A fatal error occurred: Database root ... does not exist."` — 실제 에러 그대로 사용.

## 6. route 정보 추출

`@app.route('/orders/<id>')` 위치는 CodeQL이 아니라 Python 표준 `ast` 모듈로 직접 코드 파싱해서 추출 (정식 도구 아님, 임시 스텁).

## 7. 정규화

위에서 나온 실제 SARIF/에러/route 정보를 파이썬 스크립트로 `02-static-fact-layer.md` / `08-lightweight-data-contracts.md`의 `StaticFactBundle` 스키마에 맞게 변환. 모든 `content_hash`는 실제 파일 내용의 sha256을 직접 계산.

## 산출물

`docs/handoff/R2/`

| 파일 | 내용 |
|---|---|
| `sample-app/src/orders.py` | 취약 코드 샘플 |
| `normal.input.json` | 정상 사례 원본 (실제 SARIF) |
| `normal.expected.json` | 정상 사례 정규화 결과 — `StaticFactBundle` 단독 |
| `normal.rule_execution_record.expected.json` | 정상 사례의 `RuleExecutionRecord` 단독 |
| `normal.code_context_response.expected.json` | 코드 문맥 전달 예시 — `CodeContextResponse` 단독 |
| `failure.input.json` | 실패 사례 원본 (실제 CLI 에러) |
| `failure.expected.json` | 실패 사례 정규화 결과 — `StaticFactBundle` 단독 |
| `failure.rule_execution_record.expected.json` | 실패 사례의 `RuleExecutionRecord` 단독 |
| `handoff.md` | 출처·통과 조건·미결정사항 설명서 |

파일 하나 = record 하나입니다(2026-09-10, PR #138 R3 리뷰 반영). `*.expected.json`은 각각 대응하는 Pydantic model(`StaticFactBundle`/`RuleExecutionRecord`/`CodeContextResponse`, `src/sastsimi/contracts/static.py`)로 `model_validate_json` 검증을 통과하며, `tests/contract/domain/test_r2_handoff_fixtures.py`가 이를 자동으로 확인합니다.
