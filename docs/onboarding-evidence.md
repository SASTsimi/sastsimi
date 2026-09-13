# 운영 onboarding manifest와 근거 작성 안내

이 문서는 production profile을 `READY`로 검사할 때 필요한 secret 없는 파일과 각 필드의 의미를 설명합니다. 여기의 값은 예시이며 실제 시험·평가·사람 승인을 대신하지 않습니다.

현재 실행 계약은 `src/sastsimi/orchestration/production_onboarding.py`의 `ProductionOnboardingManifest`, `ProductionProvisioningManifest`, `PVDObservation`과 `src/sastsimi/orchestration/production_provisioning.py`의 슬롯별 문서 모델입니다. Provider와 Prompt 판단 기준은 [Provider 결정](./architecture-v5/implementation/04-provider-decision.md)과 [Prompt Runtime](./architecture-v5/implementation/05-prompt-runtime.md)을 함께 따릅니다.

## 1. 먼저 필요한 값을 조회합니다

저장소 루트에서 실행합니다.

```text
uv run sastsimi --data-dir <data-dir> onboarding requirements --profile <production-profile.toml> --format json
```

출력에서 다음 값을 그대로 기록합니다.

- `profile_hash`: 현재 TOML 전체의 정확한 hash입니다.
- `required_pvd_tests`: Provider별로 관측해야 하는 PVD 번호입니다.
- `required_routes`: 빠짐없이 승인해야 하는 역할·작업, model, Prompt key, template 경로와 hash입니다.

이 명령의 `BLOCKED`는 정상입니다. 필요한 근거 목록을 보여 줄 뿐 PASS를 만들어 주지 않습니다.

## 2. 근거 파일의 공통 규칙

근거 파일에는 API key, access token, cookie, 로그인 session, browser profile, 환경변수의 실제 값, 원본 LLM 입력·출력 또는 저장소 비밀을 넣지 않습니다. 허용되는 내용은 시험 식별자, 실행 환경·client·model 식별자, 시각, PASS·FAIL 결과와 민감정보가 제거된 짧은 요약입니다.

예를 들어 PVD 한 건의 외부 근거는 다음처럼 만들 수 있습니다.

```json
{
  "schema_version": 1,
  "provider_profile_key": "approved-openai-profile",
  "model": "replace-with-tested-model-id",
  "test_id": "PVD-01",
  "result": "PASS",
  "observed_at": "2026-09-13T00:00:00Z",
  "safe_summary": "Approved client authenticated without exposing credentials."
}
```

이 파일은 `PVDObservation` 자체가 아니라 사람이 보관한 관측 근거입니다. 그 파일의 실제 SHA-256을 onboarding manifest의 같은 PVD 항목 `evidence_sha256`에 적습니다. 파일을 고치면 hash도 바뀌므로 이전 승인을 재사용하지 않습니다.

파일 hash는 다음처럼 확인할 수 있습니다.

```text
uv run python -c "import hashlib,pathlib; p=pathlib.Path(r'<evidence-file>'); print(hashlib.sha256(p.read_bytes()).hexdigest())"
```

PVD-01부터 PVD-15까지 각각 결과가 필요합니다. API Provider의 PVD-13만 실제로 적용되지 않는 경우 `NOT_APPLICABLE`을 사용할 수 있습니다. 그 밖의 누락·`FAIL`·허용되지 않은 `NOT_APPLICABLE`은 `READY`가 아닙니다. Sandbox 동적 tool loop를 사용하는 Provider는 PVD-16 근거도 추가합니다.

## 3. `ProductionProvisioningManifest`

이 manifest는 “이번 host와 profile에서 어떤 승인된 capability와 설정 파일을 정확히 사용할지”를 고정합니다. 최소 구조는 다음과 같습니다. 꺾쇠 값과 hash는 실제 승인값으로 바꿔야 합니다.

```json
{
  "schema_version": 1,
  "profile_hash": "<onboarding-requirements가 출력한 64자리 hash>",
  "host_id": "<production profile의 host_id>",
  "created_at": "2026-09-13T00:00:00Z",
  "expires_at": "2026-10-13T00:00:00Z",
  "approved_by": "<승인자 식별자>",
  "capabilities": [
    {"slot": "GIT_CLONE", "profile_ref": {"stored_data_id": "<id>", "data_kind": "runtime_capability_profile", "content_hash": "<sha256>", "configuration_scope": "HOST", "host_id": "<같은 host_id>", "publication_analysis_id": "<id>", "publication_workspace_id": "<id>", "publication_commit_id": "<id>", "record_id": "<id>"}},
    {"slot": "GIT_CHECKOUT", "profile_ref": {"stored_data_id": "<id>", "data_kind": "runtime_capability_profile", "content_hash": "<sha256>", "configuration_scope": "HOST", "host_id": "<같은 host_id>", "publication_analysis_id": "<id>", "publication_workspace_id": "<id>", "publication_commit_id": "<id>", "record_id": "<id>"}},
    {"slot": "PYTHON_RUNTIME", "profile_ref": {"stored_data_id": "<id>", "data_kind": "runtime_capability_profile", "content_hash": "<sha256>", "configuration_scope": "HOST", "host_id": "<같은 host_id>", "publication_analysis_id": "<id>", "publication_workspace_id": "<id>", "publication_commit_id": "<id>", "record_id": "<id>"}},
    {"slot": "AST", "profile_ref": {"stored_data_id": "<id>", "data_kind": "static_tool_profile", "content_hash": "<sha256>", "configuration_scope": "HOST", "host_id": "<같은 host_id>", "publication_analysis_id": "<id>", "publication_workspace_id": "<id>", "publication_commit_id": "<id>", "record_id": "<id>"}}
  ],
  "artifacts": [
    {"slot": "WORKSPACE_STORAGE", "content_sha256": "<slot 파일 sha256>"},
    {"slot": "STATIC_ANALYSIS", "content_sha256": "<slot 파일 sha256>"},
    {"slot": "VERIFICATION_PLAYBOOKS", "content_sha256": "<slot 파일 sha256>"},
    {"slot": "SANDBOX_PROFILE", "content_sha256": "<slot 파일 sha256>"},
    {"slot": "POLICY_CATALOG", "content_sha256": "<slot 파일 sha256>"},
    {"slot": "PROVIDER_CONFIGURATION", "content_sha256": "<slot 파일 sha256>"},
    {"slot": "PROMPT_ROUTES", "content_sha256": "<slot 파일 sha256>"}
  ]
}
```

필드 의미는 다음과 같습니다.

- `profile_hash`: 현재 production TOML과 정확히 같은지 확인합니다.
- `host_id`: capability가 승인된 실행 host를 고정합니다.
- `created_at`, `expires_at`, `approved_by`: 누가 어느 기간 사용을 승인했는지 기록합니다.
- `capabilities`: registry에 이미 저장된 정확한 host capability revision을 가리킵니다. 기본적으로 Git clone·checkout, Python runtime, AST가 필요하며 실제 사용하는 CodeQL·OpenGrep·Docker만 추가합니다.
- `artifacts`: 아래 일곱 설정 파일의 실제 byte hash입니다. 파일 이름이나 “최신 버전”이 아니라 hash가 같은 파일만 사용합니다.

각 provisioning slot 파일은 공통으로 `schema_version=1`, 자기 `slot`, 같은 `profile_hash`, 실행 시 발급될 `analysis_id`, `workspace_id`, `commit_id`, 필요한 exact `record_refs`, 추가 근거의 `evidence_sha256`를 가집니다. 슬롯별 추가 필드는 다음과 같습니다.

- `WORKSPACE_STORAGE`: `backend=SQLITE_RECORDS_AND_CAS`
- `STATIC_ANALYSIS`: 실제 활성 도구를 담은 `enabled_tools`; `AST`는 필수
- `VERIFICATION_PLAYBOOKS`: 하나 이상의 `verification_playbook`과 정확히 하나의 `playbook_policy` reference
- `SANDBOX_PROFILE`: 정확히 하나의 `sandbox_profile` reference, `container_user`, `max_execute_turns`
- `POLICY_CATALOG`: `source_configuration_sha256`, `freshness_criterion_sha256`; 둘 다 `evidence_sha256`에도 포함
- `PROVIDER_CONFIGURATION`: Provider마다 `provider_validation_evidence`와 `provider_profile` reference, 구독 client이면 필요한 `client_execution_profile`
- `PROMPT_ROUTES`: Prompt 실행 계약과 `prompt_registry_entry`, `evaluation_recommendation` reference 및 `semantic_validator_keys`

이 일곱 파일은 빈 예시를 복사해 만드는 일반 설정이 아닙니다. 해당 analysis scope에 공통 계약 record를 먼저 발행한 trusted provisioning 단계가 exact reference를 넣어 생성해야 합니다. 임의 ID나 다른 analysis의 reference를 쓰면 production 구성 단계에서 차단됩니다.

## 4. `ProductionOnboardingManifest`

운영에는 provisioning manifest를 연결하는 schema version 2를 사용합니다.

```json
{
  "schema_version": 2,
  "profile_hash": "<같은 profile hash>",
  "created_at": "2026-09-13T00:00:00Z",
  "expires_at": "2026-10-13T00:00:00Z",
  "approved_by": "<승인자 식별자>",
  "policy_artifact_sha256": "<공식 정책 원문 artifact sha256>",
  "provisioning_manifest_sha256": "<ProductionProvisioningManifest 파일 sha256>",
  "provider_approvals": [
    {
      "provider_profile_key": "approved-openai-profile",
      "product": "OPENAI_API",
      "environment": "PERSONAL_LOCAL",
      "model": "<실제로 시험한 model>",
      "client_name": "openai-python",
      "client_version": "<실제로 시험한 version>",
      "credential_ref": "env:OPENAI_API_KEY",
      "checked_at": "2026-09-13T00:00:00Z",
      "checked_by": "<시험 담당자>",
      "approved_by": "<승인자 식별자>",
      "approved_at": "2026-09-13T00:00:00Z",
      "expires_at": "2026-10-13T00:00:00Z",
      "terms_approved_by": "<약관 확인자>",
      "terms_approved_at": "2026-09-13T00:00:00Z",
      "terms_valid_until": "2026-10-13T00:00:00Z",
      "tests": [
        {"test_id": "PVD-01", "result": "PASS", "evidence_sha256": "<PVD-01 근거 sha256>", "safe_summary": "Authentication preflight passed without secret output."}
      ]
    }
  ],
  "route_approvals": [
    {
      "role": "HYPOTHESIS",
      "task_kind": "GENERATE_INITIAL",
      "provider_profile_key": "approved-openai-profile",
      "model": "<같은 model>",
      "prompt_key": "hypothesis.generate-initial.production-v1",
      "template_path": "<requirements 출력의 경로>",
      "template_sha256": "<requirements 출력의 hash>",
      "evaluation_result_sha256": "<R8 평가 근거 sha256>",
      "recommendation_sha256": "<ACCEPT_FOR_PRODUCTION 추천 근거 sha256>",
      "decision": "ACCEPT_FOR_PRODUCTION",
      "approved_by": "<승인자 식별자>",
      "approved_at": "2026-09-13T00:00:00Z"
    }
  ]
}
```

위 JSON은 반복 구조를 한 항목만 보여 주는 최소 설명 예시이므로 그대로 제출하면 안 됩니다. `tests`에는 requirements가 요구한 PVD-01~PVD-15 전체를 넣고, `route_approvals`에는 `required_routes`가 출력한 모든 route를 정확히 한 번씩 넣습니다. profile의 Provider/model/client/version/credential reference와 한 글자라도 다르면 stale로 거부됩니다. `credential_ref`에는 `env:NAME`만 쓰며 실제 값은 쓰지 않습니다.

## 5. 가져오기와 `READY` 확인

onboarding manifest가 참조하는 모든 파일을 `--evidence`로 전달합니다. 최소한 공식 정책 원문, PVD 근거, R8 평가·추천, provisioning manifest와 일곱 provisioning slot 파일이 포함됩니다.

```text
uv run sastsimi --data-dir <data-dir> onboarding prepare --profile <production-profile.toml> --manifest <production-onboarding.json> --evidence <policy-artifact> --evidence <pvd-evidence> --evidence <evaluation-evidence> --evidence <recommendation-evidence> --evidence <production-provisioning.json> --evidence <slot-document> --format json
uv run sastsimi --data-dir <data-dir> onboarding status --profile <production-profile.toml> --format json
```

여러 PVD·route·slot 파일은 `--evidence`를 반복해 모두 전달합니다. `status=READY`는 현재 profile과 가져온 승인 근거가 일치한다는 뜻입니다. 실제 분석 시작 때는 capability reference와 일곱 slot 문서도 다시 해석하므로, 임의 reference나 잘못된 slot 내용은 분석 전에 `BLOCKED`됩니다.

다음 변경이 생기면 새 hash와 새 승인이 필요합니다.

- production TOML, Provider, model, client 또는 인증 방식 변경
- Prompt template, 실행 제한, validator 또는 redaction 정책 변경
- PVD·R8 결과 또는 공식 정책 변경
- capability revision, host 또는 provisioning slot 파일 변경
- manifest나 승인 유효 기한 만료
