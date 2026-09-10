# R6 fixture 사용법

각 번호의 `.input.json`과 `.expected.json`을 한 쌍으로 사용한다. 파일은 Prompt Registry와 semantic validator 구현 전 검토를 위한 synthetic projection이며 실제 database record나 canonical JSON Schema fixture가 아니다.

| 번호 | 주 대상 prompt | 목적 |
|---|---|---|
| 01 | Pro, Con, Assess Initial, Create Dynamic Request | initial TRUE 뒤 PoC 확인 요청 |
| 02 | Pro, Con, Final Verdict | 실제 반증 근거로 FALSE |
| 03 | Pro, Con, Final Verdict | 정상 검증 완료 후 HOLD |
| 04 | 호출 전 runtime validation | 필수 Context 실패를 verdict로 바꾸지 않음 |
| 05 | 전체 | schema·semantic·injection·stale·join 차단 |
| 06 | Final Verdict | current dynamic + same-attempt PoC로 TRUE |
| 07 | Technical Revise | 새 generation에서 REVISE 보완 |

검증 순서는 다음과 같다.

1. JSON 파싱
2. registry의 role·task·purpose와 template exact revision 확인
3. required input slot·projection·trust class 확인
4. JSON Schema 확인
5. role별 semantic validator 확인
6. exact reference·generation·attempt·debate join 확인
7. 금지 행동이 output에 포함되지 않았는지 확인

자연어 문장 전체 일치는 요구하지 않는다. `evaluation-criteria.md`의 enum·reference·근거·권한 조건을 비교한다.
