# R5-03 (Reporter/ReportDraft 생성 조건) — R2 관점 교차 검토

- 검토자: 김나연 (R2 정적분석·컨텍스트, `@zv9uvr`)
- 검토 대상: Issue R5-03 "함께 검토할 역할 — R2" 항목
  > ReportDraft에 포함된 코드 위치와 code-flow claim이 실제 정적분석 Evidence로 추적 가능한지 검토
- 검토 기준 커밋: `SASTsimi/sastsimi` `main` `2c63d1557c50220f90739c2b89bcb21a048cb880`(2026-09-04) — 최초 작성(2026-08-30, `main` `16e834a` 기준)에서 line 인용만 갱신, 결론은 변경 없음.
- 참고: 검토 시점 기준 `review/r5-03-reporter` 브랜치가 `dd56d53`까지 진행됐고(R7 동적 재현 provenance 필드 정합, 실패 분류 세분화 등) `05-llm-gate-and-reporting.md`/`12-report-draft-template.md`에 상당한 내용이 반영됐다. 다만 아래 4번에서 제안한 `content_ref`의 `path:line` ↔ upstream `EvidenceClaim.code_locations` 일치 검사 규칙은 이 브랜치에도 아직 반영되지 않은 것으로 확인된다(4번 참고).

## 결론 요약

ReportDraft의 코드 위치·code-flow claim은 **`ReportDraft.verification_result_ref → VerificationResult.EvidenceClaim → CodeLocation/evidence_refs → StaticFactBundle 내 CodeFact/CodeRelation.producer`** 경로로 정적분석 Evidence까지 역추적 가능한 구조가 이미 계약 문서에 있음을 확인했다. 다만 이 추적 가능성은 **`VerificationResult`라는 구조화된 record 수준**에서만 스키마로 보장되고, Reporter가 실제로 사람이 읽는 `content_ref`(보고서 본문, 12번 문서의 표/코드 흐름 블록)에 옮겨 적은 `path:line` 값이 그 upstream `EvidenceClaim.code_locations`와 실제로 일치하는지를 검사하는 규칙은 현재 문서에 명시돼 있지 않다. 이 부분을 R5-03의 "output contract validation" 범위에 명시적으로 포함할 것을 제안한다(아래 4번).

## 1. 확인된 것: claim provenance 경로가 실제로 존재함

R5-03 이슈가 그린 provenance 체인(`Report claim → VerificationResult → Evidence/Dynamic/PoC`)은 다음 스키마로 실제 뒷받침된다.

- `ReportDraft`는 `verification_result_ref: StoredDataRef` 하나로 검토 시점의 정확한 `VerificationResult` revision을 고정한다 — `08-lightweight-data-contracts.md` L1681부터(스키마 블록)
- `VerificationResult.supporting_evidence` / `counter_evidence`는 `EvidenceClaim[]`이고, 각 `EvidenceClaim`은 `evidence_refs: [StoredDataRef]`와 함께 "코드 주장이면 현재 `workspace_id`+`commit_id`의 `code_locations`를 하나 이상 가져야 한다"는 필수 규칙이 있다 — `08-lightweight-data-contracts.md` L952-958(스키마), L1061(필수 규칙 설명)
- `CodeLocation`은 `workspace_id`, `commit_id`, `file_path`, `start_line`/`end_line`(1-based, inclusive)로 구성되어 위치 자체가 코드 버전에 고정된다 — `08-lightweight-data-contracts.md` L566-573, 규칙 설명 L702
- `evidence_refs`가 가리키는 정적 근거의 원본은 `StaticFactBundle`(`CodeFact`/`CodeRelation`)이며, 각 `CodeFact`/`CodeRelation`은 `producer: ToolSource`(`tool_name`, `tool_version`, `rule_id`, `raw_result_ref`)를 가져 실제 AST/SAST 도구 원본 결과까지 역추적된다 — `08-lightweight-data-contracts.md` L621-626(스키마), L704(도구 역추적 설명), L788-804(`StaticFactBundle`)

즉 "Reporter가 참조하는 코드 위치·흐름이 실제 정적분석 결과에서 나왔는가"라는 질문에는, `VerificationResult` 레벨까지는 **예**라고 답할 수 있는 근거가 있다.

## 2. 확인된 것: 보고서 템플릿이 같은 형식을 그대로 요구함

`12-report-draft-template.md`의 "4. 취약 위치"(L68-75)와 "5. 코드 및 호출 흐름"(L77-86)은 Source/Propagation/Guard/Sink 각 행에 `{path:line}`을 요구하고, L86에서 "각 단계가 동일 `workspace_id`와 `commit_id`에서 연결되는 근거와 `CodeLocation`"을 명시하도록 되어 있다. 이는 1번의 `CodeLocation` 스키마와 형식이 정확히 일치한다 — 즉 템플릿이 요구하는 표현 단위가 R2가 소유한 `CodeLocation` 개념과 어긋나지 않는다.

## 3. 확인된 것: Reporter 금지 권한과 표현 제약이 R2 도메인과 충돌하지 않음

`05-llm-gate-and-reporting.md` L185 "Reporter는 새로운 공격 경로를 확정하거나 미검증 material child 또는 Chaining 후보를 실제 영향으로 쓰지 않는다. 초안의 핵심 주장은 ... exact revision에 연결한다"는 R2가 R2-02/R2-03에서 이미 확정한 "SAST severity/rule hit을 verdict로 승격하지 않는다"(`02-static-fact-layer.md` L25) 원칙과 방향이 같다. Reporter가 스스로 새 코드 경로나 sink를 "발견"하는 것이 아니라 이미 검증된 `EvidenceClaim.code_locations`만 재사용한다는 전제이므로, R2 쪽에서 별도로 막아야 할 충돌 지점은 없다.

## 4. 미확정 사항 (R2가 제기): `content_ref`와 upstream `code_locations`의 일치 검증이 명시돼 있지 않음

`ReportDraft` record 자체는 `content_ref: StoredDataRef` 하나로 실제 보고서 본문(사람이 읽는 markdown 등)을 가리킬 뿐, 그 본문에 적힌 `path:line`들을 구조화된 필드로 다시 담지 않는다 — `08-lightweight-data-contracts.md` L1509-1526. 즉:

- 스키마 레벨에서 보장되는 것: `ReportDraft`가 가리키는 `VerificationResult` revision이 정확하다는 것, 그리고 그 `VerificationResult` 안의 `EvidenceClaim`들이 각각 `code_locations`/`evidence_refs`를 갖고 있다는 것.
- 스키마 레벨에서 보장되지 않는 것: Reporter LLM이 `content_ref` 본문(템플릿 4번/5번 섹션)에 실제로 적어 넣은 `{path:line}` 문자열이, 참조된 `VerificationResult.EvidenceClaim.code_locations`에 존재하는 값과 실제로 일치하는지.

`07-results-and-observability.md`(`REPORT_NOT_READY` 서술 L203, `REPORT_ERROR` 표 행 L282, `REPORT_NOT_READY` 표 행 L297)와 `10-security-boundaries.md`(`REPORT_READY` check 목록 L50, Reporter exact revision 요구 L131)에서 확인한 관련 검사는 모두 "Reporter를 호출해도 되는가"(선행조건, Gate 순서)에 대한 것이지, "Reporter가 생성한 본문 내용이 upstream evidence와 위치 단위로 일치하는가"에 대한 것이 아니다.

**갱신(2026-09-03)**: `review/r5-03-reporter` 브랜치(`23ed763`)가 이후 `05-llm-gate-and-reporting.md`에 severity/exploitability가 upstream evidence보다 강해지면 안 된다는 semantic invariant, restriction/limitation 보존 규칙, redaction 세부 목록을 추가했지만, 위에서 제기한 `path:line` ↔ `code_locations` 일치 검사 규칙은 diff에 포함되지 않았다. 이 항목은 여전히 열려 있다.

**갱신(2026-09-04)**: 같은 브랜치가 `dd56d53`까지 더 진행되어(R7 동적 재현 provenance 필드 정합, `failure_category` enum 등) `05-llm-gate-and-reporting.md`/`12-report-draft-template.md`에 추가로 반영됐지만, 위 결론은 그대로다 — `path:line` ↔ `code_locations` 일치 검사 규칙은 여전히 없다(위 참고 항목과 동일).

**제안**: R5-03의 "report claim의 evidence/PoC/Gate/policy provenance 기준 확정" 항목에서, code-flow claim에 한해 "본문에 등장하는 모든 `path:line`은 참조된 `VerificationResult`의 `EvidenceClaim.code_locations`(같은 `workspace_id`+`commit_id`) 중 하나와 정확히 일치해야 하며, 일치하지 않으면 `INVALID_OUTPUT`/`REPORT_ERROR`로 처리한다"는 규칙을 output contract validation 항목에 명시적으로 추가할 것을 제안한다. 이는 새로운 스키마 필드 추가 없이(= R5-03이 우려하는 "새 `FindingCandidate` 스키마 독자 신설" 문제와 무관하게) 기존 `content_ref` 검증 규칙에 조건 하나를 더하는 정도로 처리 가능해 보인다.

## 5. 참고: line 번호 갱신 이력

최초 작성(main `16e834a`) 시점에는 `issue3-static-context-sub-issues.md`와 `r2-static-context-confirmation.md`가 인용한 옛 line 번호(예: `CodeLocation`/`CodeSymbol` → L170-184, `StaticFactBundle` → L323-343)가 그 시점 `main`과도 이미 어긋나 있었다. 이 문서의 모든 인용은 그 뒤 `main`이 여러 차례 재구성될 때마다(가장 최근 `312fcb2`) 함께 갱신했으며, 파일 재구성 외에 내용상 모순은 발견되지 않았다.

## 6. 참고 (R2 소관 아님, 확인 중 발견): `FindingCandidate` 소유권은 이미 공통 계약에 명시돼 있음

R5-03의 "착수 전 확인" 체크리스트 1~2번(독립 Finding record 필요 여부, schema 소유권 합의)과 관련해, `08-lightweight-data-contracts.md` L1715에 "`FindingCandidate` 본문과 품질 기준은 R5가 소유한다. R4는 이미 저장된 Finding revision과 다른 exact 결과를 `AnalysisRunResult`로 전달할 뿐 새 Finding claim을 만들거나 빠진 Finding을 추정하지 않는다"라는 문장이 이미 있다. 즉 독립 Finding record 존재가 공통 계약에 이미 전제되어 있고, 그 내용 스키마 소유권도 R5로 이미 지정되어 있다. R2 도메인은 아니지만 R5-03 착수 전 확인 항목과 바로 관련되어 있어 참고로 남긴다(R4와의 교차 확인은 별도로 필요).

---

*이 문서는 R2(정적분석·컨텍스트) 담당자가 R5-03 이슈의 "함께 검토할 역할" 요청에 따라 작성한 교차 검토 기록이다. 2026-08-30 최초 작성, 2026-09-03 line 인용 갱신, 2026-09-04 `main` `2c63d15` 기준 line 인용 재갱신(내용 변경 없음).*
