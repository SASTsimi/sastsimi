# R7 PoC 생성 코드 입력 및 Runtime 저장 연결 보완

상태: 작업 범위 협의 초안. 이 문서는 구현 완료나 Prompt Registry의 ACTIVE
전환을 의미하지 않는다. 관련 이슈는 #162이며, 프롬프트 인계 PR #148과
분리하여 검토한다.

## 목적과 기존 계약

[08 공통 계약](../../architecture-v5/08-lightweight-data-contracts.md)의
`CodeContextRequest/Response`는 같은 workspace·commit의 코드 조회와
`code_fragment_refs` 반환을 이미 정의한다. `PoCCandidate`의 runtime 소유 ID와
`RecordMeta`도 trusted domain finalizer가 결합하도록 정의되어 있다.

이번 작업은 새 공통 스키마를 전제로 하지 않고, 기존 계약을 PoC 생성 호출의
입력 조립과 candidate 저장 과정에 연결하는 누락을 보완한다.

## 제안하는 작업 범위

1. 실제 코드 입력 연결
   - 기존 `CodeContextResponse.code_fragment_refs`의 exact artifact를 읽어
     redaction된 코드 내용을 `CREATE_POC_CANDIDATE` 입력에 전달한다.
   - 어떤 field projection과 cardinality를 사용할지는 R3와 확정한다.
   - 코드의 workspace·commit을 확인하고, 호출에 사용한 source reference와
     현재 hypothesis·work·attempt의 연결을 보존한다. 원본 조회 record의
     attempt를 R7 attempt로 임의 변경하지 않는다.
   - 코드 원문은 비신뢰 입력이며 지시문으로 취급하지 않는다.
2. Runtime 저장 연결
   - Agent는 PoC 내용을 생성하고 저장 reference·digest·timestamp·call ID를
     임의 발급하지 않는다.
   - Runtime이 exact candidate bytes를 저장하고 digest·reference를 발급한 뒤
     현재 호출의 runtime metadata와 결합해 기존 `PoCCandidate`를 완성한다.
   - LLM artifact와 candidate bytes의 대응·serialization 규칙 및 저장 실패
     처리를 R3와 확정한다. 내용·digest 불일치와 다른 work·attempt metadata
     혼합은 차단하며, 실패를 가설의 반증으로 바꾸지 않는다.
3. 등록안과 검증 자료 보완
   - #148의 프롬프트 입력 등록안과 인계 문서를 위 결정에 맞춰 보완한다.
   - 정상 저장, 코드 reference 불일치, digest 불일치, 저장 실패 및 attempt
     혼합의 정상·오류 테스트를 준비한다.
   - 같은 session의 조정은 현재 attempt를 유지하며 candidate revision과
     생성 LLM call의 연결을 보존한다.

## 협의 및 완료 조건

- R7: 코드 입력의 충분성, candidate 사용 및 same-attempt 실행 연결 확인.
- R3: 입력 assembler, Runtime 저장·metadata 결합 및 semantic validator 확인.
- R4: 기존 공통 계약으로 표현 가능한지 및 reference·소유권 정합성 확인.
- 기존 계약으로 표현하지 못하는 항목은 별도 변경 건으로 협의한다.
- 필요한 연결과 정상·오류 테스트가 완료되기 전에는 관련 R7 Prompt Registry
  entry를 ACTIVE로 전환하지 않는다.

이 초안에는 runtime 구현, registry 활성화 또는 테스트 완료 결과가 포함되지
않는다.
