# Agent와 LLM Provider

## 구현된 책임

Agent 이름은 역할을 뜻하며 특정 회사나 모델 이름이 아닙니다. 실제 Provider와 model은
설정에서 선택합니다. 같은 역할을 다른 지원 Provider/model로 바꿔도 Agent 계약은
변하지 않습니다.

현재 파이프라인의 LLM 역할은 다음과 같습니다.

- Hypothesis Agent: 정적 사실에서 취약점 가설 생성
- Pro·Con Agents: 성립 근거와 반박 근거 수집
- Verification Agent: 초기·최종 판정과 동적 재현 필요성 정리
- Dynamic Reproduction Agent: 환경 요구와 PoC 후보 생성
- CWE Labeling Agent: final TRUE에 맞는 CWE 후보 생성
- Technical Gate Agent: 근거·PoC·CWE 연결성 검토
- Rule Scope Gate Agent: 공식 정책 범위와 시험 제한 검토
- Chaining Agent: Primitive 조합으로 자식 가설 제안
- Reporter Agent: 검증된 사실만으로 영문·국문 설명을 한 번에 작성; Runtime이
  같은 근거를 두 Markdown과 검증된 첨부파일에 반영

비-LLM Runtime은 ID 발급, 순서, 상태, 저장, 재시도, 권한 및 exact reference 검사를
담당합니다. Agent 출력만으로 Docker 실행이나 최종 결과 저장을 승인하지 않습니다.
신규 후보 파이프라인(v2)은 같은 파일의 후보에 공유 문맥을 사용하고 결과의
candidate ID 누락·중복·불명 ID를 검증합니다. 근거가 있는 가설을 등록한 뒤
각 자식을 기존 Agent 순서로 검증합니다. Pro·Con은 같은 문맥의 여러 가설을
묶어 호출할 수 있어도 서로 독립된 역할과 가설 ID별 증거를 저장하며, 빠진 ID만
다시 요청합니다. 묶음 호출이 불가능하면 기존 개별 호출 경로를 사용합니다.

## 같은 Provider 안의 모델 라우팅

분석의 기본 모델은 `model`입니다. 선택 항목인 `light_model`을 설정하면
`cwe_label`과 `report_draft`만 기본적으로 그 모델을 사용합니다. 그 밖의 역할과
알 수 없는 역할은 기본 모델을 사용합니다. `agent_models[agent_name]`에 명시한
모델이 있으면 이 기본 규칙보다 우선합니다. 모델 ID는 설정에서 가져오며 라우팅
때문에 분석의 Provider나 인증 경로가 바뀌지 않습니다. 별도로 설정한 Provider
fallback은 기존 오류 처리 규칙을 따릅니다.

Codex와 OpenAI는 선택한 모델별 client를 실행 제한 wrapper로 감싸 호출하고,
Claude와 Cursor는 기존 역할별 모델 라우팅을 사용합니다. 어느 모델로 호출하든
분석의 동시성 semaphore와 예산을 공유하며, 호출 기록에는 실제 사용한 모델과
제공된 토큰·시간·비용 정보를 남깁니다. 지원하지 않는 모델이라는 Provider 오류를
식별할 수 있으면 해당 Agent 호출은 최종 실패로 처리하며 다른 모델로 자동
대체하지 않습니다.

새 분석은 버전이 있는 유효 모델 경로 snapshot을 저장합니다. 재개할 때는 로컬
설정이 바뀌었어도 저장된 기본 모델과 역할별 경로를 사용하고, 설정된 Provider가
저장된 Provider와 다르면 LLM 호출 전에 `BLOCKED`로 처리합니다. 이미 완료된
checkpoint는 모델 경로 때문에 다시 실행하지 않습니다. 이 기능 이전에 생성되어
snapshot이 없는 분석에는 `light_model`의 자동 역할 배정을 소급 적용하지 않으며,
기존의 명시적 `agent_models` override는 계속 사용할 수 있습니다.

가벼운 모델을 사용해도 입력 토큰 수가 줄어든다는 보장은 없습니다. 실제 모델별
사용량과 지연 시간, 적용 가능한 가격을 확인한 뒤 절감 효과를 판단해야 합니다.

## 코드 위치

- 단순 Runtime LLM client: `src/sastsimi/simple_runtime/provider.py`
- 역할별 모델 정책: `src/sastsimi/config/model_roles.py`
- Codex/OpenAI 모델별 호출 라우팅: `src/sastsimi/simple_runtime/model_routing.py`
- stage prompt와 구조화 출력: `src/sastsimi/simple_runtime/stages.py`
- Provider 구성: `src/sastsimi/composition/simple_runtime_composition.py`
- 사용자 설정: `src/sastsimi/config/user_config.py`
- 세부 prompt registry: `src/sastsimi/prompts`

## 지켜야 하는 계약

- Agent 입력에는 검증·민감정보 제거를 마친 exact artifact만 넣습니다.
- 구조화 출력이 schema와 맞지 않으면 정상 결과로 저장하지 않습니다.
- API Key는 환경 또는 공식 credential 경로에서 읽고 TOML에 직접 저장하지 않습니다.
- 회원제 연결은 브라우저 cookie 복사가 아니라 공식 Codex CLI 로그인을 사용합니다.
- Pro와 Con은 독립된 역할 입력과 결과로 저장합니다.
- 요청·응답의 식별자와 저장된 입력 hash가 다르면 다른 가설의 증거로 재사용하지 않습니다.

## 현재 제한

실제로 검증하지 않은 Provider/model 조합은 지원된다고 표시하지 않습니다. Anthropic과
Claude 연결은 공통 인터페이스 설계와 별개로 현재 설치본에서 운영 검증된 기본 경로가
아닙니다.
Codex CLI는 분석당 미해결 호출 하나만 허용합니다. 현재 신규 v2의 자식 검증은
순차 실행하고, OpenAI API 요청도 분석별 예산 잠금으로 직렬화합니다. 설정의
가설·LLM 동시성 상한은 실제 Provider 병렬 호출을 보장하지 않습니다.
