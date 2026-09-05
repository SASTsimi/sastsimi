# R6 검증 플레이북

이 문서는 R6 Verification, Pro Agent, Con Agent가 같은 가설을 검토할 때 참고하는 공통 및 웹 취약점 유형별 검증 절차의 정본입니다.

- **이 문서는 무엇을 설명하나요?** 공통 플레이북과 웹 취약점 6종의 검증 절차를 설명합니다.
- **누가 읽어야 하나요?** R6 검증 담당과 Pro·Con·R7·Gate·구현 담당자가 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** 적용할 플레이북의 확인 항목, 반증 질문과 필요한 정적·동적 근거를 확인합니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## 적용 원칙

- 플레이북은 점수표나 자동 판정표가 아니라 누락을 줄이는 참고 절차입니다. 질문을 더 많이 충족한 Agent가 이기는 구조가 아니며, verdict는 현재 코드와 실제 evidence로 결정합니다.
- Verification work 등록 시 trusted runtime은 exact `VulnerabilityHypothesis.proposal_ref`가 가리키는 `HypothesisProposal.vulnerability_type_candidates`와 current exact `PlaybookPolicy`를 확인합니다.
- 유형 후보가 정확히 하나이고 current `PlaybookPolicy.type_playbooks`에 같은 유형의 유효한 mapping이 있을 때만 `TYPE_SPECIFIC`을 선택합니다. 후보가 없거나 여러 개이거나 policy가 허용하지 않으면 current exact `COMMON`을 선택합니다.
- runtime은 선택한 policy·playbook과 질문별 실제 `question_id`를 `PlaybookApplication`으로 고정합니다. Verification 직접 검증·Pro·Con·최종 합성은 동일한 exact `PlaybookPolicy`, `VerificationPlaybook`, `PlaybookApplication`을 사용합니다.
- final `VerificationResult`는 `playbook_ref`와 `playbook_application_ref`를 모두 기록하며, 가설 자체의 반증 질문과 application 질문의 합집합을 빠짐없이 정확히 한 번씩 처리합니다.
- 진행 중인 work에 새로운 플레이북 revision을 섞지 않습니다. 새 revision은 새 Verification work 또는 새 generation부터 적용합니다.
- 오류, timeout, 빈 Context, Sandbox 실패는 가설의 반증 evidence가 아닙니다.
- FALSE는 named falsification question이 실제 evidence로 DISPROVED 되었을 때만 가능합니다. 필수 검증을 완료한 뒤 남은 조건이 있으면 HOLD와 unresolved_conditions를 사용합니다.
- R6 플레이북은 동적 검증의 목적과 판정에 필요한 관측을 정의합니다. PoC, command, 환경 계획과 DynamicReproductionResult의 생산은 R7 책임입니다.
- final TRUE에는 current generation의 SUCCEEDED + SUPPORTED 동적 결과와 validated poc_ref가 필요합니다.

## 식별과 revision

| 문서용 playbook_key | scope | vulnerability_type |
| --- | --- | --- |
| COMMON | COMMON | null |
| WEB-SQLI | TYPE_SPECIFIC | SQL_INJECTION |
| WEB-XSS | TYPE_SPECIFIC | XSS |
| WEB-OS-CMD | TYPE_SPECIFIC | OS_COMMAND_INJECTION |
| WEB-PATH-TRAVERSAL | TYPE_SPECIFIC | PATH_TRAVERSAL |
| WEB-SSRF | TYPE_SPECIFIC | SSRF |
| WEB-IDOR-BOLA | TYPE_SPECIFIC | IDOR_BOLA |

`playbook_key`는 이 문서에서 사람이 플레이북을 쉽게 구분하기 위한 읽기 쉬운 이름입니다. `VerificationPlaybook` 계약의 실제 식별자 필드가 아니며, runtime이 플레이북의 동일성이나 revision을 판단하는 데 사용하지 않습니다.

플레이북은 기존 공통 계약에 따라 다음과 같이 식별합니다.

- 플레이북의 논리 식별자: `meta.logical_record_id`
- 플레이북 내용 수정본: `meta.revision_number`
- 플레이북 데이터 구조 버전: `meta.schema_version`
- 실행에 사용한 정확한 수정본: `StoredDataRef.record_id + content_hash`

플레이북 내용이 변경되면 기존 record를 덮어쓰지 않고 새로운 `record_id`, 증가한 `meta.revision_number`, 새로운 `content_hash`를 생성합니다.

---

## 선택과 적용 기록

1. runtime은 exact `VulnerabilityHypothesis.proposal_ref`를 따라 `HypothesisProposal.vulnerability_type_candidates`를 읽습니다.
2. 후보가 정확히 하나이고 current `PlaybookPolicy`에 같은 유형의 mapping이 있으면 `selection=TYPE_SPECIFIC`, `selection_reason=TYPE_MATCH`로 해당 exact 플레이북을 선택합니다.
3. 후보가 없으면 `NO_TYPE`, 여러 개면 `MULTIPLE_TYPES`, 하나지만 policy에 없으면 `TYPE_NOT_ALLOWED`로 `selection=COMMON`을 사용합니다.
4. runtime은 exact hypothesis·proposal·policy·playbook과 적용된 질문을 `PlaybookApplication`에 고정합니다.
5. 같은 Verification work의 직접 검증·Pro·Con·최종 합성과 저장은 모두 같은 application을 사용합니다.
6. final `VerificationResult.playbook_ref`는 application의 playbook과 같아야 하며 `playbook_application_ref`도 함께 기록합니다.
7. final `falsification_results[].question_id` 집합은 가설 자체 질문과 application 질문의 중복 없는 합집합과 같아야 하며, 각 질문을 정확히 한 번 평가합니다.

## COMMON

### 사전 조건

- 현재 가설과 exact 코드·정적 근거 reference가 같은 workspace_id와 commit_id를 가리킨다.
- 공격자가 제어할 수 있다고 의심되는 입력, 위험 동작 또는 보안 영향, 필요한 권한·환경 조건이 식별되어 있다.
- 가설의 observed fact와 assumption, FalsificationQuestion이 구분되어 있다.

### Source

HTTP query, path, body, header, cookie, 업로드 파일, 메시지, 데이터베이스의 저장 데이터, 외부 서비스 응답처럼 신뢰 경계를 넘어 들어오는 값과 그 변환값을 후보로 확인합니다.

### Sink

코드·명령·질의 실행, 파일·네트워크·객체 접근, HTML·템플릿 출력, 역직렬화, 권한이 필요한 상태 변경 등 가설의 보안 영향이 실제로 발생하는 지점을 확인합니다.

### 경로 확인

- source에서 sink까지 같은 commit의 caller/callee, data flow, route를 연결합니다.
- decode, parse, normalize, concatenate, cast, encode 등 중간 변환과 분기 조건을 기록합니다.
- 비동기 작업, 저장 후 재사용, 서비스 간 전달처럼 끊어져 보이는 경로도 reference로 연결합니다.
- 실행되지 않는 코드, 테스트 전용 코드, 불가능한 설정인지 확인합니다.

### 방어 확인

입력 검증, allowlist, sanitizer, canonicalization, parameterization, 인증·인가, tenant·소유권 검사, 안전한 기본 설정이 위험 동작 전에 모든 도달 가능 경로에 적용되는지 확인합니다. 방어 함수의 이름만으로 안전하다고 판단하지 않습니다.

### 반증 질문 템플릿 이름과 실제 question_id

`COM-FQ-01`, `SQLI-FQ-01`, `XSS-FQ-01` 같은 값은 `PlaybookQuestionTemplate.template_key`입니다. 같은 플레이북 revision 안에서 사람이 질문 템플릿을 구분하기 위한 이름이며 실제 `FalsificationQuestion.question_id`가 아닙니다.

Verification work를 처음 등록할 때 trusted runtime은 선택한 플레이북의 모든 `PlaybookQuestionTemplate`을 `PlaybookApplication.questions`에 한 번씩 복사하고, 각 질문에 새로운 전역 고유 `question_id`를 발급합니다. `AppliedPlaybookQuestion`은 `template_key`, 새 `question_id`, 원래 질문 문장을 함께 보존합니다. 같은 work의 retry는 동일 application과 질문 ID를 유지하지만, 새 work 또는 새 generation은 새 application과 새 질문 ID를 만듭니다.

### Named falsification questions

- COM-FQ-01: 의심한 source가 공격자 또는 낮은 권한 사용자에게 실제로 제어되지 않는가?
- COM-FQ-02: 현재 commit에서 source에서 sink까지 도달 가능한 경로가 존재하지 않는가?
- COM-FQ-03: 모든 도달 가능 경로에서 적절한 방어가 우회 없이 강제되는가?
- COM-FQ-04: 가설에 필요한 권한, 설정, 상태 또는 환경 조건을 만족시키는 것이 불가능한가?

### 필요한 정적 evidence

source와 sink 위치, call/data-flow reference, route와 guard, 중간 변환, 방어 구현, 권한·설정 조건, 도달 불가 경로의 근거를 수집합니다.

### 동적 evidence

정적·Pro·Con evidence만으로 핵심 조건을 확정할 수 없거나 initial TRUE의 PoC 확인이 필요할 때 R7에 요청합니다. R6는 재현할 가설, 재현 목표, 필요한 환경 조건, Sandbox profile, 관련 문맥, 지지·반증·미확정 관측 기준을 전달합니다.

- SUPPORTED: 통제된 입력이 예상 경로를 거쳐 보안 영향 또는 명확한 대리 관측을 만든다.
- DISPROVED: 요구 조건을 충족한 실행에서 위험 경로가 적절한 방어로 일관되게 차단되고 named question을 입증한다.
- INCONCLUSIVE: 환경·관측·재현 조건이 부족하여 어느 쪽도 입증하지 못한다.

### Restriction

필요한 권한, 설정, 배포 형태, 입력 형식, 도달 가능한 endpoint와 영향 범위를 evidence reference와 함께 기록합니다.

### HOLD 조건

필수 확인은 완료했으나 공격자 제어성, 경로, 방어 적용 범위, 환경 조건 또는 영향 중 하나 이상을 현재 evidence로 결정할 수 없을 때 HOLD로 두고 unresolved_conditions에 남깁니다.

---

## SQL_INJECTION

### 사전 조건

외부 또는 저장된 입력이 SQL statement의 값, 식별자, 절, 정렬·필터 표현식에 영향을 줄 가능성과 실제 데이터베이스 실행 지점이 식별되어 있어야 합니다.

### Source

query/body/path/header/cookie, 검색·필터·정렬 값, object identifier, 업로드·저장 후 사용되는 데이터, 다른 서비스에서 받은 값입니다.

### Sink

직접 query/execute 호출, raw SQL API, 문자열로 조립한 ORM query, 동적 table·column·ORDER BY 식별자, SQL을 생성하는 저장 프로시저 호출입니다.

### 경로 확인

입력의 decode와 type conversion부터 SQL 생성 및 실행까지 추적합니다. 문자열 결합, format/interpolation, raw API 전환, 2차 저장 후 실행, 조건부 query builder 분기를 확인합니다.

### 방어 확인

값에는 실제 parameter binding이 적용되는지, 동적 식별자에는 고정 매핑 또는 allowlist가 적용되는지 확인합니다. escape 함수, ORM 사용, 저장 프로시저라는 이름만으로 안전하다고 보지 않습니다. 데이터베이스 계정 권한은 영향을 제한할 수 있지만 injection 자체의 반증은 아닙니다.

### Named falsification questions

- SQLI-FQ-01: 공격자 입력이 SQL 구조가 아니라 바인딩된 값으로만 전달되는가?
- SQLI-FQ-02: 동적 식별자가 고정 allowlist 매핑 밖의 값을 받아들일 수 없는가?
- SQLI-FQ-03: 의심 경로가 현재 commit의 실행 가능한 query sink에 도달하지 않는가?
- SQLI-FQ-04: 모든 도달 경로에서 SQL 문맥에 맞는 방어가 실행 전에 강제되는가?

### 필요한 정적 evidence

입력 위치, query 구성 코드, parameter API 호출, raw query 여부, identifier 매핑, ORM이 생성하는 statement의 근거, 실행 계정과 영향 제한을 연결합니다.

### 동적 evidence

정적 evidence로 생성 query와 입력 영향이 불명확하거나 PoC 확인이 필요할 때 요청합니다. R7은 격리된 데이터와 비파괴 입력을 사용합니다.

- SUPPORTED: 통제 입력에 따라 query 구조·행 선택·오류·시간 또는 안전한 대리 관측이 재현되고 validated PoC가 연결된다.
- DISPROVED: 같은 전제에서 입력이 데이터 값으로만 처리되고 구조 변경이 차단됨을 관측한다.
- INCONCLUSIVE: 데이터베이스·driver·관측 로그 또는 전제 조건 부족으로 결론을 낼 수 없다.

### Restriction

특정 DBMS, driver, query branch, 계정 권한, 인증 역할, 저장 데이터 선행 조건과 실제 영향 범위를 기록합니다.

### HOLD 조건

실행 query, driver의 binding 동작, 2차 injection 경로 또는 접근 가능한 DB 권한을 확인할 evidence가 부족할 때 사용합니다.

---

## XSS

### 사전 조건

공격자 제어 값이 reflected, stored 또는 DOM 흐름을 통해 브라우저가 해석하는 HTML, 속성, JavaScript, CSS 또는 URL 문맥에 도달할 가능성이 있어야 합니다.

### Source

URL query/path/fragment, form과 JSON body, header, 저장된 게시물·프로필, 외부 API 응답, postMessage, local/session storage와 DOM 속성입니다.

### Sink

서버 템플릿 출력, HTML 속성·script·URL 문맥, innerHTML, outerHTML, document.write, insertAdjacentHTML, eval 계열과 문자열 기반 script 실행 지점입니다.

### 경로 확인

source에서 최종 렌더링 문맥까지 서버와 클라이언트 흐름을 함께 추적합니다. 저장형은 쓰기와 읽기 경로를 연결하고, DOM형은 브라우저 측 source와 sink를 연결합니다. encode 후 decode 또는 sanitizer 이후 재조립도 확인합니다.

### 방어 확인

최종 sink 문맥에 맞는 output encoding, 검증된 sanitizer, template auto-escape와 bypass 설정을 확인합니다. HTML·속성·JavaScript·URL encoding은 서로 대체할 수 없습니다. CSP만으로 취약점이 반증되지는 않습니다.

### Named falsification questions

- XSS-FQ-01: 값이 브라우저 실행 문맥에 도달하지 않고 텍스트로만 처리되는가?
- XSS-FQ-02: 최종 sink 직전에 문맥에 맞는 encoding 또는 sanitizer가 모든 경로에 강제되는가?
- XSS-FQ-03: DOM source에서 실행 가능한 sink로 이어지는 경로가 없는가?
- XSS-FQ-04: 저장값을 쓰거나 피해자가 읽는 데 필요한 조건을 공격자가 만족할 수 없는가?

### 필요한 정적 evidence

source, template·DOM sink, 렌더링 문맥, auto-escape 설정, sanitizer와 버전, bypass API, 저장·조회 route, CSP는 제한 근거로 연결합니다.

### 동적 evidence

렌더링 문맥과 sanitizer 결과가 정적으로 불명확하거나 PoC 확인이 필요할 때 브라우저 Sandbox에서 비파괴 marker로 요청합니다.

- SUPPORTED: marker가 예상 사용자·문맥에서 script 실행 또는 그에 준하는 안전한 실행 관측을 만든다.
- DISPROVED: 동일 전제에서 marker가 문맥별 방어로 inert text가 되고 우회 경로가 없음을 관측한다.
- INCONCLUSIVE: 브라우저 상태, 인증, 렌더링 조건 또는 관측 장치 부족으로 결론을 낼 수 없다.

### Restriction

reflected/stored/DOM 구분, 피해자 역할, 필요한 사용자 상호작용, 브라우저·CSP·템플릿 설정, 실행 가능한 문맥과 영향 범위를 기록합니다.

### HOLD 조건

최종 출력 문맥, sanitizer의 실제 결과, 저장 후 피해자 노출, DOM runtime 경로를 확정할 evidence가 부족할 때 사용합니다.

---

## OS_COMMAND_INJECTION

### 사전 조건

공격자 제어 값이 운영체제 명령 또는 process 실행의 executable, argument, option, environment, shell string에 영향을 줄 가능성이 있어야 합니다.

### Source

웹 입력, 파일명, job parameter, 저장 데이터, 외부 서비스 응답, 관리 화면 설정과 webhook payload입니다.

### Sink

system·exec 계열, shell=true process 실행, command interpreter 호출, 문자열 명령 조합, script wrapper와 외부 도구 실행입니다.

### 경로 확인

입력에서 process API까지 변환을 추적하고 shell 해석 여부를 구분합니다. 문자열 command와 executable/argv 분리 호출, option injection, 환경 변수, wrapper script, 플랫폼별 shell을 확인합니다.

### 방어 확인

shell을 사용하지 않는 고정 executable과 분리된 argv, 값·옵션 allowlist, 강제 type·range, 최소 권한과 Sandbox를 확인합니다. quoting이나 blacklist만으로 안전하다고 판단하지 않습니다.

### Named falsification questions

- CMD-FQ-01: 입력이 shell이 해석하지 않는 분리 argv의 단순 데이터로만 전달되는가?
- CMD-FQ-02: executable과 option이 고정되고 외부 값이 엄격한 allowlist 밖으로 벗어날 수 없는가?
- CMD-FQ-03: 의심 경로가 실제 process 실행 sink에 도달하지 않는가?
- CMD-FQ-04: 모든 도달 경로에서 shell metacharacter와 option 주입 가능성이 제거되는가?

### 필요한 정적 evidence

process API와 shell 옵션, command 구성, executable/argv 경계, validation, wrapper script, 실행 계정·컨테이너 권한과 호출 경로를 수집합니다.

### 동적 evidence

shell 해석 또는 option 영향이 불명확하거나 PoC 확인이 필요할 때 격리 Sandbox에서 무해한 marker만 사용하도록 요청합니다.

- SUPPORTED: 통제 입력이 의도하지 않은 command·argument 동작 또는 안전한 대리 관측을 만든다.
- DISPROVED: 값이 shell에 해석되지 않고 허용된 argument 범위로만 처리됨을 관측한다.
- INCONCLUSIVE: 실행 도구·OS·권한·관측 환경 부족으로 결론을 낼 수 없다.

### Restriction

OS와 shell, 실행 계정, container profile, 사용 가능한 binary, 필요한 endpoint·역할, 명령 영향 범위를 기록합니다.

### HOLD 조건

실제 shell 사용, wrapper 동작, option 해석 또는 배포 환경의 실행 권한을 확정할 수 없을 때 사용합니다.

---

## PATH_TRAVERSAL

### 사전 조건

공격자 제어 값이 파일·디렉터리·archive entry 경로의 전부 또는 일부에 영향을 주고 파일 시스템 작업으로 이어질 가능성이 있어야 합니다.

### Source

filename, URL path, query/body의 경로, 업로드 metadata, archive entry, 저장된 경로와 외부 서비스에서 받은 객체 key입니다.

### Sink

file open/read/write/delete, directory listing, upload/download, template·static file 제공, archive extract와 파일 이동 API입니다.

### 경로 확인

decode 순서, separator 변환, normalize/canonicalize, base directory 결합, real path 비교, symlink, absolute·UNC 경로, archive extraction을 sink까지 추적합니다. validation 뒤 다시 decode 또는 경로 결합하는지 확인합니다.

### 방어 확인

최종 decode·canonicalization 뒤 허용 root 내부인지 component-aware 비교하는지, symlink와 archive entry를 안전하게 처리하는지 확인합니다. 문자열 prefix 검사나 ../ blacklist만으로 충분하다고 보지 않습니다.

### Named falsification questions

- PATH-FQ-01: 외부 값이 파일 경로 결정에 사용되지 않고 고정 ID 매핑으로만 처리되는가?
- PATH-FQ-02: 최종 canonical path가 허용 root 내부로 강제되고 symlink 우회도 차단되는가?
- PATH-FQ-03: 의심 경로가 실제 파일 시스템 sink에 도달하지 않는가?
- PATH-FQ-04: 중복 encoding, 절대 경로, separator, archive entry 우회가 모두 불가능한가?

### 필요한 정적 evidence

입력·decode·normalize 순서, base path 계산, containment 검사, symlink 정책, file API, archive library와 권한·노출 범위를 연결합니다.

### 동적 evidence

정규화·symlink·플랫폼 동작이 불명확하거나 PoC 확인이 필요할 때 Sandbox의 허용 root 밖에 둔 무해한 sentinel로 요청합니다.

- SUPPORTED: 통제 경로가 허용 root 밖의 sentinel에 접근하거나 의도하지 않은 파일 작업을 만든다.
- DISPROVED: 모든 지원 경로 표현이 최종 containment 검사에서 차단됨을 관측한다.
- INCONCLUSIVE: 파일 배치, OS, 권한 또는 symlink 조건 부족으로 결론을 낼 수 없다.

### Restriction

OS·filesystem, read/write/delete 종류, 필요한 권한, 허용 root, symlink·archive 조건과 접근 가능한 파일 범위를 기록합니다.

### HOLD 조건

배포 OS, canonicalization 결과, symlink 정책, archive library 또는 실제 root 경계를 확인할 evidence가 부족할 때 사용합니다.

---

## SSRF

### 사전 조건

공격자 제어 값이 서버 측 URL, host, scheme, port, redirect target 또는 request option에 영향을 주고 서버가 네트워크 요청을 수행할 가능성이 있어야 합니다.

### Source

URL·host 입력, webhook·callback, image/document import, feed, proxy, redirect, avatar fetch, 외부 연동 설정과 저장된 URL입니다.

### Sink

HTTP client, generic URL opener, socket·proxy, headless browser, cloud SDK, metadata·service discovery 접근과 URL을 받아 원격 자원을 읽는 library입니다.

### 경로 확인

parse·normalize, scheme/host/port 결정, DNS resolution, proxy, redirect follow, credential·header 전달을 실제 request sink까지 추적합니다. 최초 검증 뒤 redirect와 DNS 재해석이 일어나는지 확인합니다.

### 방어 확인

허용 scheme·host·port, resolve된 모든 IP의 내부·loopback·link-local 제한, redirect마다 재검증, DNS rebinding 방어, egress 정책과 credential 전달 제한을 확인합니다. 문자열 URL prefix나 blocklist만으로 안전하다고 보지 않습니다.

### Named falsification questions

- SSRF-FQ-01: 외부 값이 서버 측 요청 목적지 선택에 영향을 주지 않는가?
- SSRF-FQ-02: canonical URL과 resolve된 모든 IP가 allowlist·network policy로 강제되는가?
- SSRF-FQ-03: redirect, DNS 변화, alternate scheme을 거쳐 제한 대상을 요청할 수 없는가?
- SSRF-FQ-04: 의심 경로가 실제 network sink에 도달하지 않는가?

### 필요한 정적 evidence

URL source, parser와 validation 순서, client 설정, DNS·redirect 처리, proxy·egress 정책, credential·header 전달, network sink와 호출 경로를 수집합니다.

### 동적 evidence

실제 DNS·redirect·egress 동작이 불명확하거나 PoC 확인이 필요할 때 R7이 관리하는 통제 endpoint만 대상으로 요청합니다. 실제 cloud metadata나 제3자 내부망을 공격 대상으로 사용하지 않습니다.

- SUPPORTED: 서버가 통제 endpoint 또는 안전한 내부 대리 대상에 예상치 못한 요청을 보내고 관측 가능한 marker가 남는다.
- DISPROVED: 동일 전제에서 목적지·redirect·resolve 결과가 일관되게 차단된다.
- INCONCLUSIVE: DNS, network policy, proxy 또는 관측 endpoint 부족으로 결론을 낼 수 없다.

### Restriction

지원 scheme, 인증 역할, egress가 열린 배포 환경, redirect/DNS 조건, 전달되는 credential, 도달 가능한 네트워크 범위를 기록합니다.

### HOLD 조건

운영 egress 정책, DNS·redirect 처리, proxy 또는 credential 전달 동작을 확인할 evidence가 부족할 때 사용합니다.

---

## IDOR_BOLA

### 사전 조건

사용자가 제공하는 object identifier가 조회·수정·삭제·행동 수행 대상 선택에 사용되고, 다른 사용자·tenant·역할의 객체에 대한 object-level authorization이 의심되어야 합니다.

### Source

URL path/query, body, GraphQL variable, batch ID 목록, hidden field, cookie·token claim에서 파생된 tenant 또는 object ID입니다.

### Sink

객체 조회·목록·download, 수정·삭제, 상태 변경, 결제·초대·권한 변경 같은 object action과 repository/service의 object access입니다.

### 경로 확인

route에서 object lookup과 action까지 연결하고, 인증 identity가 owner·tenant·role 조건에 결합되는 위치를 확인합니다. 단건뿐 아니라 list, batch, nested resource, indirect reference, 캐시 경로도 확인합니다.

### 방어 확인

객체를 찾은 뒤 현재 주체에 대한 object-level authorization이 모든 action에서 강제되는지 확인합니다. 추측하기 어려운 ID, UI에서 숨김, 로그인 여부만으로 인가가 입증되지는 않습니다. service/repository 계층 우회와 tenant 필터 누락을 확인합니다.

### Named falsification questions

- AUTHZ-FQ-01: 현재 identity가 접근 가능한 객체만 선택하도록 query와 action에 owner·tenant 조건이 강제되는가?
- AUTHZ-FQ-02: 모든 읽기·쓰기·삭제·batch·nested 경로에서 같은 object-level policy가 적용되는가?
- AUTHZ-FQ-03: 공격자가 다른 주체의 object identifier를 획득하거나 제출해도 접근할 수 없는가?
- AUTHZ-FQ-04: 의심 route가 보호 대상 object action에 도달하지 않는가?

### 필요한 정적 evidence

route, identifier binding, authentication identity, object query, owner·tenant·role policy, policy 호출 순서, list/batch/nested endpoint와 우회 경로를 연결합니다.

### 동적 evidence

정책의 runtime 적용 또는 cross-user 영향이 불명확하거나 PoC 확인이 필요할 때 Sandbox의 두 통제 계정과 각 계정 소유 객체로 요청합니다.

- SUPPORTED: 낮은 권한 계정이 다른 계정·tenant의 통제 객체를 읽거나 변경하는 안전한 관측이 재현된다.
- DISPROVED: 모든 대상 action에서 cross-user·cross-tenant 요청이 일관되게 거부된다.
- INCONCLUSIVE: 두 계정, 객체 소유 관계, 역할 또는 관측 가능한 action 부족으로 결론을 낼 수 없다.

### Restriction

필요한 인증 상태, 공격자·피해자 역할, tenant 관계, 알려진 object ID, 허용되는 action과 실제 데이터·상태 영향 범위를 기록합니다.

### HOLD 조건

소유 관계, tenant 정책, 숨은 service authorization, list/batch 경로 또는 실행 가능한 두 계정 조건을 확인할 evidence가 부족할 때 사용합니다.

---

## 참고 기준

플레이북은 아래 공개 기준을 참고하되 현재 저장소 코드와 evidence보다 우선하지 않습니다.

- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/latest/
- OWASP Top 10: https://owasp.org/Top10/
- CWE-89 SQL Injection: https://cwe.mitre.org/data/definitions/89.html
- CWE-79 Cross-site Scripting: https://cwe.mitre.org/data/definitions/79.html
- CWE-78 OS Command Injection: https://cwe.mitre.org/data/definitions/78.html
- CWE-22 Path Traversal: https://cwe.mitre.org/data/definitions/22.html
- CWE-918 SSRF: https://cwe.mitre.org/data/definitions/918.html
- CWE-639 Authorization Bypass Through User-Controlled Key: https://cwe.mitre.org/data/definitions/639.html
