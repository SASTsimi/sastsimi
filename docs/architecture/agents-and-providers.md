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
- Reporter Agent: 검증된 사실만 한국어 보고서로 구성

비-LLM Runtime은 ID 발급, 순서, 상태, 저장, 재시도, 권한 및 exact reference 검사를
담당합니다. Agent 출력만으로 Docker 실행이나 최종 결과 저장을 승인하지 않습니다.

## 코드 위치

- 단순 Runtime LLM client: `src/sastsimi/simple_runtime/provider.py`
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

## 현재 제한

실제로 검증하지 않은 Provider/model 조합은 지원된다고 표시하지 않습니다. Anthropic과
Claude 연결은 공통 인터페이스 설계와 별개로 현재 설치본에서 운영 검증된 기본 경로가
아닙니다.
