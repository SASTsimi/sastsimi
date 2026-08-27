# 12. 보고서 초안 템플릿

- **이 문서는 무엇을 설명하나요?** 모든 검토 조건을 통과한 결과를 사람이 읽을 보고서 초안으로 정리하는 양식입니다.
- **누가 읽어야 하나요?** Gate·Finding·보고서 담당과 최종 사람 검토자가 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** 어떤 근거·정책·영향·재현 정보가 있어야 초안을 만들 수 있는지 확인합니다.

`Finding`은 사람이 검토할 수 있게 정리한 취약점 결과이고 `human handoff`는 사람이 검토할 자료를 전달하는 단계입니다. 이 양식은 자동 외부 제출을 허용하지 않습니다. 자세한 용어는 [쉬운 용어집](../GLOSSARY.md)을 따릅니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

Reporter Agent는 다음 조건이 모두 참일 때만 이 내부 초안을 작성한다.

```text
Verification TRUE
+ Technical Evidence Gate ACCEPT
+ Rule Scope Impact Gate review_status PASS
+ rule_compliance PASS
+ scope_compliance PASS
+ security_impact SUFFICIENT
+ report_permission ALLOW
```

중괄호 값은 검증된 artifact에서 채우며 미검증 Research 후보를 확정 사실로 표현하지 않는다.

---

# {취약점 제목}

## 1. 요약

- 대상 snapshot: `{repository}@{commit} / {snapshot_id}`
- 취약점 유형: `{vulnerability type}`
- CWE: `{primary CWE}`
- 영향 entity/endpoint: `{entity or endpoint}`
- Verification: `TRUE`
- Technical Evidence Gate: `ACCEPT`
- Rule/Scope/Impact: `rule_compliance PASS / scope_compliance PASS / security_impact SUFFICIENT`
- 보고서 전달 권한: `ALLOW`

`{공격 전제, 검증된 동작과 실제 보안 영향을 한 문단으로 설명}`

## 2. 공식 프로그램 정책과 범위

- ProgramPolicySnapshot: `{policy snapshot ref}`
- 공식 source: `{official source refs}`
- capture 시각/freshness: `{timestamp and warning}`
- 적용 rule: `{rule and eligibility}`
- 대상 asset/class scope: `{scope evidence}`
- 금지 테스트 준수: `{assessment}`
- disclosure 조건: `{requirements}`

## 3. 실제 영향과 제한

- 공격자에게 필요한 권한·상태: `{required capabilities}`
- 제공되는 능력: `{provided capabilities}`
- 영향받는 자산: `{data, account, service or boundary}`
- 검증된 실제 결과: `{confidentiality, integrity, availability or privilege impact}`
- restriction: `{restrictions}`
- 검토한 bypass/alternate path: `{validated outcomes}`
- 남은 불확실성: `{unresolved conditions or none}`

과장된 최악 시나리오 대신 재검증된 경로와 재현 범위만 실제 영향으로 쓴다.

## 4. 취약 위치

| 역할 | Entity | 위치 | 설명 |
|---|---|---|---|
| Source | `{entity}` | `{path:line}` | `{attacker-controlled input}` |
| Propagation | `{entity}` | `{path:line}` | `{call or data transformation}` |
| Guard | `{entity}` | `{path:line}` | `{missing, insufficient or bypassed guard}` |
| Sink | `{entity}` | `{path:line}` | `{security-sensitive operation}` |

## 5. 코드 및 호출 흐름

```text
{source}
→ {propagation/call step 1}
→ {guard/bypass step}
→ {sink}
```

`{각 단계가 동일 snapshot에서 연결되는 근거와 location reference}`

## 6. 검증 근거

### 찬성 근거

- `{claim}` — `{fact/code/dynamic ref}`

### 반대 근거와 처리

- `{counterclaim}` — `{accepted, refuted or bounded explanation}`

### Debate

- 모드와 trigger: `{BASIC | CONDITIONAL_DEBATE | ALWAYS_DEBATE / reasons}`
- 독립 Pro/Con 결과: `{summary or documented skip reason}`
- 전후 verdict/HOLD/bypass 변화: `{comparison}`

### Verification 판정

`{TRUE 이유, 충족된 전제와 남은 restriction}`

## 7. 동적 재현과 PoC

- 모드: `{NOT_REQUIRED | LIMITED_REPRO | FULL_REPRO}`
- Docker 환경: `{image digest and relevant configuration}`
- 전제: `{account, data, route or build condition}`
- 결과: `{success, partial or not run}`
- 가설 연결: `{관측이 지지하는 정확한 claim}`
- 환경 차이/제한: `{limitations}`

### 재현 단계

1. `{setup/action}`
2. `{action}`
3. `{observation}`

### 입력 또는 요청

```text
{redacted PoC input or request}
```

실제 credential, session cookie, API key와 개인정보를 포함하지 않는다.

## 8. CWE

- primary: `{CWE-ID and name}`
- taxonomy version: `{version}`
- 선택 이유와 evidence: `{rationale and refs}`
- alternatives/uncertainty: `{alternatives or none}`

## 9. Research와 chaining

- Research 호출 이유: `{trigger or skipped}`
- 제안된 bypass/alternate/impact/primitive match: `{candidate refs}`
- 새 가설로 재검증 완료: `{validated child hypotheses and results}`
- 아직 미검증: `{candidate refs; report claim으로 사용하지 않음}`
- material extension 없음: `{reason if applicable}`

## 10. 두 Gate 검토

### Technical Evidence Gate

- 상태: `ACCEPT`
- verdict-evidence/코드 흐름/동적 연결: `{assessment}`
- CWE/restriction/handoff: `{assessment}`
- revision 이력: `{history or none}`

### Rule Scope Impact Gate

- overall/rule/scope: `PASS / PASS / PASS`
- impact: `SUFFICIENT`
- 정책 근거와 판단 이유: `{policy refs and rationale}`
- report permission: `ALLOW`

## 11. LLM invocation trace와 오류

- 역할별 invocation refs: `{Hypothesis, Verification, Pro/Con, Research, Gates, Reporter}`
- provider/model/session mode: `{safe metadata}`
- retrieved code locations: `{location refs}`
- schema repair/failover: `{attempt refs or none}`
- 관련 error/resource limit: `{safe summary or none}`

hidden chain-of-thought와 secret은 포함하지 않는다.

## 12. 완화와 회귀 테스트

- `{root-cause-linked remediation}`
- `{authorization/validation/control remediation}`
- `{regression test recommendation}`

## 13. 사람 최종 검토

- 결정: `{DISCLOSE | REVISE | WITHHOLD | NEED_MORE_VALIDATION}`
- 검토자: `{authorized reviewer}`
- 의견: `{decision rationale}`
- 승인한 공개 범위와 채널: `{target or none}`

---

Reporter Agent는 13절을 채우거나 외부 제출을 수행하지 않는다.
