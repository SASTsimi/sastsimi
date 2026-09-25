# R3 파트별 인계 검토표

R3는 각 역할의 판단이 맞는지를 대신 결정하지 않고, 자료가 공통 입출력 계약에 맞고 실제 모듈에 연결 가능한지를 검토합니다.

## 공통 파일

- [ ] 역할 폴더가 `docs/handoff/R1/`부터 `docs/handoff/R8/` 중 자기 역할 위치에 있다.
- [ ] 담당 Agent별 `prompt*.md`가 있다. 비-LLM 역할은 prompt가 없다는 이유를 `handoff.md`에 적었다.
- [ ] `normal.input.json`과 `normal.expected.json`이 짝을 이룬다.
- [ ] `failure.input.json`과 `failure.expected.json`이 짝을 이룬다.
- [ ] 입력이 실제 자료인지 합성 fixture인지 출처를 표시했다.
- [ ] `handoff.md`에 기준 문서·파일 위치·통과 조건·미결정 사항이 있다.

## Prompt·Registry

- [ ] `agent_role + task_kind + purpose`가 R3-05 공식 task 표와 같다.
- [ ] 역할·목적·입력·근거 기준·금지 사항·출력·실패 처리가 있다.
- [ ] template 경로가 `config/prompts/templates/<role>/<task>/<semver>.md`로 옮겨질 수 있다.
- [ ] 첫 version은 `1.0.0`이고 병합된 version을 덮어쓰지 않는다.
- [ ] template, input allowlist, output schema와 semantic validator가 한 세트다.
- [ ] `DRAFT`를 `ACTIVE` 또는 구현 완료라고 표시하지 않는다.

## 입력 연결

- [ ] slot·data kind·cardinality·field path가 공식 task 행과 같다.
- [ ] REQUIRED 입력이 빠지지 않았다.
- [ ] 같은 analysis·workspace·commit·hypothesis·generation의 exact reference다.
- [ ] Registry에 없는 추가 context와 금지 data kind가 없다.
- [ ] 코드·README·정책·도구·LLM 출력은 `UNTRUSTED_DATA`다.
- [ ] secret과 host 절대 경로가 없다.

## 출력과 오류

- [ ] 한 호출은 등록된 result kind 하나만 만든다.
- [ ] JSON Schema와 semantic validator의 통과 조건이 있다.
- [ ] 다른 workspace·commit·generation·attempt 결과를 차단한다.
- [ ] 필수값 누락을 빈 정상 결과로 보정하지 않는다.
- [ ] timeout은 `TIMED_OUT`이며 domain output을 commit하지 않는다.
- [ ] 오류·누락·timeout을 `FALSE | HOLD`로 바꾸지 않는다.
- [ ] retry·repair·failover는 새 call/action/attempt를 사용한다.

## 종합 판정

각 역할은 다음 중 하나로 기록합니다.

- `READY`: 공통 형식과 계약을 충족하여 구현 인계 가능
- `CHANGES_REQUESTED`: 수정 위치와 이유가 구체적으로 있음
- `WAITING`: 아직 PR 또는 필수 자료가 없음

