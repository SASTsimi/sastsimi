[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$failures = [System.Collections.Generic.List[string]]::new()

function Add-Failure {
    param([string]$Message)
    $failures.Add($Message)
}

$markdownFiles = Get-ChildItem -LiteralPath $repoRoot -Recurse -File -Filter '*.md' |
    Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' }

foreach ($file in $markdownFiles) {
    $text = Get-Content -Raw -LiteralPath $file.FullName
    $fenceCount = [regex]::Matches($text, '(?m)^```').Count
    if (($fenceCount % 2) -ne 0) {
        Add-Failure "unclosed Markdown fence: $($file.FullName)"
    }

    $links = [regex]::Matches($text, '\[[^\]]+\]\((?!https?://|mailto:|#)([^)]+)\)')
    foreach ($match in $links) {
        $target = $match.Groups[1].Value.Split('#')[0]
        if ([string]::IsNullOrWhiteSpace($target)) {
            continue
        }
        $decodedTarget = [uri]::UnescapeDataString($target)
        $resolved = Join-Path $file.DirectoryName $decodedTarget
        if (-not (Test-Path -LiteralPath $resolved)) {
            Add-Failure "missing local link: $($file.FullName) -> $target"
        }
    }
}

$diagramPath = Join-Path $repoRoot 'docs/architecture-v5/13-architecture-diagrams.md'
$wikiDiagramPath = Join-Path $repoRoot 'docs/architecture-v5/wiki/diagrams.md'
$diagramText = Get-Content -Raw -LiteralPath $diagramPath
$wikiDiagramText = Get-Content -Raw -LiteralPath $wikiDiagramPath
$mermaidPattern = '(?ms)^```mermaid\s*(.*?)^```'
$diagramBlocks = [regex]::Matches($diagramText, $mermaidPattern) |
    ForEach-Object { $_.Groups[1].Value.Trim() }
$wikiDiagramBlocks = [regex]::Matches($wikiDiagramText, $mermaidPattern) |
    ForEach-Object { $_.Groups[1].Value.Trim() }

if ($diagramBlocks.Count -ne $wikiDiagramBlocks.Count) {
    Add-Failure "Mermaid block count differs: main=$($diagramBlocks.Count), wiki=$($wikiDiagramBlocks.Count)"
} elseif ((Compare-Object $diagramBlocks $wikiDiagramBlocks).Count -ne 0) {
    Add-Failure 'Mermaid blocks differ between the canonical diagram and Wiki copy'
}

$declaredCount = "Mermaid 블록 $($diagramBlocks.Count)개"
if (-not $diagramText.Contains($declaredCount)) {
    Add-Failure "canonical diagram count text is not '$declaredCount'"
}
if (-not $wikiDiagramText.Contains($declaredCount)) {
    Add-Failure "Wiki diagram count text is not '$declaredCount'"
}

$activeContractPaths = @(
    (Join-Path $repoRoot 'docs/architecture-v5'),
    (Join-Path $repoRoot 'docs/review')
)
$forbiddenPatterns = @('RepositorySnapshot', 'snapshot_id', 'deterministic Gate', 'Gate는 규칙 기반 서비스', 'ReportDraft.human_review_state', 'human_review_state:')
foreach ($path in $activeContractPaths) {
    $files = Get-ChildItem -LiteralPath $path -Recurse -File -Filter '*.md'
    foreach ($file in $files) {
        $text = Get-Content -Raw -LiteralPath $file.FullName
        foreach ($pattern in $forbiddenPatterns) {
            if ($text.Contains($pattern)) {
                Add-Failure "forbidden repository snapshot contract '$pattern': $($file.FullName)"
            }
        }
    }
}

$contractPath = Join-Path $repoRoot 'docs/architecture-v5/08-lightweight-data-contracts.md'
$contractText = Get-Content -Raw -LiteralPath $contractPath
$overviewPath = Join-Path $repoRoot 'docs/architecture-v5/01-system-overview.md'
$overviewText = Get-Content -Raw -LiteralPath $overviewPath
$verificationPath = Join-Path $repoRoot 'docs/architecture-v5/04-verification-and-dynamic-reproduction.md'
$verificationText = Get-Content -Raw -LiteralPath $verificationPath
$activeDebateFiles = @(
    (Get-Item -LiteralPath (Join-Path $repoRoot 'README.md'))
) + @(
    Get-ChildItem -LiteralPath (Join-Path $repoRoot 'docs/architecture-v5') -Recurse -File -Filter '*.md'
) + @(
    Get-ChildItem -LiteralPath (Join-Path $repoRoot 'docs/governance') -Recurse -File -Filter '*.md'
)
$activeDebateText = ($activeDebateFiles | ForEach-Object { Get-Content -Raw -LiteralPath $_.FullName }) -join "`n"
$requiredContractNames = @(
    'WorkExecutionState:',
    'WorkAttempt:',
    'StateTransition:',
    'TransitionCommit:',
    'work_id:',
    'work_generation:',
    'dedupe_key:',
    'state_version:',
    'active_attempt_id:',
    'last_transition_ref:',
    'last_transition_commit_ref:'
)
foreach ($name in $requiredContractNames) {
    if (-not $contractText.Contains($name)) {
        Add-Failure "missing R4-02 contract name: $name"
    }
}

$requiredDebateContractNames = @(
    'EvidenceAgentResult:',
    'parent_work_ref:',
    'parent_work_id:',
    'evidence_work_id:',
    'verification_generation:',
    'llm_call_id:',
    'debate_input_hash:',
    'pro_evidence_ref:',
    'con_evidence_ref:'
)
foreach ($name in $requiredDebateContractNames) {
    if (-not $contractText.Contains($name)) {
        Add-Failure "missing R4 Pro/Con join contract name: $name"
    }
}

$workExecutionBlock = [regex]::Match($contractText, '(?ms)^WorkExecutionState:\s*(.*?)^WorkAttempt:').Groups[1].Value
if (-not $workExecutionBlock.Contains('parent_work_ref:')) {
    Add-Failure 'WorkExecutionState is missing parent_work_ref'
}

$evidenceAgentResultBlock = [regex]::Match($contractText, '(?ms)^EvidenceAgentResult:\s*(.*?)^CandidateRef:').Groups[1].Value
$requiredEvidenceAgentResultFields = @(
    'role:',
    'parent_work_id:',
    'evidence_work_id:',
    'verification_generation:',
    'llm_call_id:',
    'debate_input_hash:',
    'evidence:',
    'summary:',
    'limitations:'
)
foreach ($field in $requiredEvidenceAgentResultFields) {
    if (-not $evidenceAgentResultBlock.Contains($field)) {
        Add-Failure "EvidenceAgentResult is missing field: $field"
    }
}

$verificationResultBlock = [regex]::Match($contractText, '(?ms)^VerificationResult:\s*(.*?)^```').Groups[1].Value
$requiredVerificationDebateFields = @(
    'debate_input_hash:',
    'pro_evidence_ref:',
    'con_evidence_ref:'
)
foreach ($field in $requiredVerificationDebateFields) {
    if (-not $verificationResultBlock.Contains($field)) {
        Add-Failure "VerificationResult is missing Pro/Con join field: $field"
    }
}

$requiredDebateContractMarkers = @(
    '운영 `purpose=PRODUCTION`은 항상 `verification_mode=ALWAYS_DEBATE`이며 `debate_input_hash`, `pro_evidence_ref`, `con_evidence_ref`가 모두 필수다',
    '평가용 `BASIC` 또는 trigger가 발생하지 않은 `CONDITIONAL_DEBATE`는 세 필드를 모두 `null`',
    'final Verification 합성용 `LLMCallSpec.context_refs`와 `SAVE_RESULT.input_refs`에는 이 두 exact result reference를 각각 한 번 포함한다',
    '`pro_evidence_result -> EvidenceAgentResult(role=PRO) -> PRO`',
    '`con_evidence_result -> EvidenceAgentResult(role=CON) -> CON`',
    '`result_kind=pro_evidence_result | con_evidence_result`',
    '`LLMInvocationResult.parsed_output_ref` 및 `LLMInvocationLog.parsed_output_ref`',
    '각 record의 새 MAJOR schema로 배포한다',
    '운영 Pro/Con 자식 중 하나가 재시도 가능한 오류로 `BLOCKED`가 되면 부모 `VERIFICATION` work도 `BLOCKED`',
    '먼저 그 자식 work의 `FAILED`를 자기 `COMMITTED` `TransitionCommit`으로 확정',
    '부모 work의 `FAILED`와 `HypothesisProcessState.status=FAILED`를 기존 Verification 실패 atomic 경계로 함께 확정',
    'trusted prompt builder',
    '`CROSS_ROLE_INPUT_DENIED`'
)
foreach ($marker in $requiredDebateContractMarkers) {
    if (-not $contractText.Contains($marker)) {
        Add-Failure "missing or weakened R4 Pro/Con join rule: $marker"
    }
}

$transitionCommitBlock = [regex]::Match($contractText, '(?ms)^TransitionCommit:\s*(.*?)^```').Groups[1].Value
$requiredTransitionCommitFields = @(
    'output_refs:',
    'gap_ids:',
    'error_ids:'
)
foreach ($field in $requiredTransitionCommitFields) {
    if (-not $transitionCommitBlock.Contains($field)) {
        Add-Failure "missing TransitionCommit atomic field: $field"
    }
}

$requiredStateRows = @(
    '| `PENDING` | `READY`, `CANCELLED` |',
    '| `READY` | `RUNNING`, `BLOCKED`, `CANCELLED` |',
    '| `RUNNING` | `BLOCKED`, `SUCCEEDED`, `PARTIAL`, `FAILED`, `CANCELLED` |',
    '| `BLOCKED` | `READY`, `FAILED`, `CANCELLED` |',
    '| `SUCCEEDED`, `PARTIAL`, `FAILED`, `CANCELLED` | 없음 |'
)
foreach ($row in $requiredStateRows) {
    if (-not $contractText.Contains($row)) {
        Add-Failure "missing or changed allowed-transition row: $row"
    }
}

$requiredBindingRules = @(
    '`VERIFICATION`의 `SUCCEEDED`와 `HypothesisProcessState.status=TERMINAL`',
    '`DYNAMIC_REPRO`의 종료 transition',
    '`TECHNICAL_GATE`의 `SUCCEEDED`',
    '`RULE_SCOPE_GATE`의 `SUCCEEDED`',
    '`REPORT_DRAFT`의 `SUCCEEDED`와 `ReportProcessState.status=DRAFTED`',
    '`AnalysisRunState.analysis_result_ref`'
)
foreach ($rule in $requiredBindingRules) {
    if (-not $contractText.Contains($rule)) {
        Add-Failure "missing exact output binding rule: $rule"
    }
}

$reviewRemediationPatterns = @(
    @{
        Name = 'all terminal dynamic states require the exact result pointer'
        Pattern = '(?s)`DynamicReproductionState.status=SUCCEEDED \| PARTIAL \| FAILED \| BLOCKED \| CANCELLED`.*?`dynamic_result_ref.record_id`가 필수.*?`NOT_REQUESTED \| RUNNING`에서는 `dynamic_result_ref=null`'
    },
    @{
        Name = 'dynamic PARTIAL uses structured limitations without fake errors'
        Pattern = '(?s)`DYNAMIC_REPRO`는 정확히 하나의 `DynamicReproductionResult\(status=PARTIAL, failure_category=NONE \| OBSERVATION\)`.*?`hypothesis_evidence_refs`와 `limitations`가 각각 하나 이상.*?억지로 `error_ids`나 `gap_ids`로 만들지 않는다'
    },
    @{
        Name = 'terminal dynamic BLOCKED maps to completed common work'
        Pattern = '(?s)`BLOCKED` \+ `failure_category=POLICY` \| `SUCCEEDED`.*?공통 `WorkExecutionState.status=BLOCKED`는.*?비종료 상태에만 사용'
    },
    @{
        Name = 'dynamic cancellation result is atomically bound and late output is stale'
        Pattern = '(?s)`DYNAMIC_REPRO` 취소 전이.*?`DynamicReproductionResult\(status=CANCELLED\)`.*?같은 atomic transition.*?이미 `CANCELLED`가 확정된 뒤 늦게 도착한 output.*?연결하지 않는다'
    },
    @{
        Name = 'exact Technical and Rule Scope domain input sets'
        Pattern = '(?s)Gate domain input set.*?`TECHNICAL_GATE`에서는 `VerificationResult`와 `CWELabel` reference가 정확한 domain input set.*?`RULE_SCOPE_GATE`에서는 `VerificationResult`, `TechnicalEvidenceReview`, `CWELabel`과 존재하는 `ProgramPolicyRecord` reference가 정확한 domain input set'
    },
    @{
        Name = 'Gate result references match the frozen work inputs'
        Pattern = '(?s)`TechnicalEvidenceReview` 안의 `verification_result_ref`와 `cwe_label_ref`.*?Technical Gate work의 domain input 두 개와 각각 exact match.*?`RuleScopeImpactReview` 안의 `verification_result_ref`, `technical_review_ref`, `cwe_label_ref`, `policy_record_ref`.*?Rule Scope Gate work의 domain input set과 exact match'
    },
    @{
        Name = 'REVISE creates a new work while retry keeps the same work'
        Pattern = '(?s)`REVISE`는 일반 retry나 resume이 아니다\..*?같은 hypothesis의 ACTIVE `VerificationAssignment` owner.*?새 `WorkExecutionState\(work_type=VERIFICATION\)`.*?새 `VerificationResult`.*?새 `CWELabel` revision.*?(?:새 Gate 작업은 )?달라진 `input_refs`, `input_hash`, `dedupe_key`, `work_id`.*?`attempt_number=1`, `trigger=INITIAL`.*?일반 retry.*?같은 `work_id`.*?`trigger=RETRY`'
    },
    @{
        Name = 'contradictory ALLOW becomes INVALID_OUTPUT and blocks Reporter'
        Pattern = '(?s)Gate LLM 출력.*?`LLMInvocationResult.status=INVALID_OUTPUT`.*?`AnalysisError.stage=GATE`, `AnalysisError.code=INVALID_OUTPUT`.*?`WorkAttempt.status=FAILED`.*?`RuleScopeImpactReview`를 `COMMITTED`하지 않는다.*?Reporter 호출.*?금지'
    }
)
foreach ($rule in $reviewRemediationPatterns) {
    if (-not [regex]::IsMatch($contractText, $rule.Pattern)) {
        Add-Failure "missing or weakened PR #26 review remediation rule: $($rule.Name)"
    }
}

$resultPath = Join-Path $repoRoot 'docs/architecture-v5/07-results-and-observability.md'
$resultText = Get-Content -Raw -LiteralPath $resultPath
$commonWikiPath = Join-Path $repoRoot 'docs/architecture-v5/wiki/common-contracts.md'
$commonWikiText = Get-Content -Raw -LiteralPath $commonWikiPath
$requiredErrorCodes = @(
    'STATE_TRANSITION_INVALID',
    'STATE_VERSION_CONFLICT',
    'ATTEMPT_NOT_ACTIVE',
    'STALE_RESULT',
    'TRANSITION_INCOMPLETE',
    'RECOVERY_FAILED',
    'INTERRUPTED',
    'CROSS_ROLE_INPUT_DENIED'
)
foreach ($code in $requiredErrorCodes) {
    if (-not $resultText.Contains($code)) {
        Add-Failure "missing R4-02 error code: $code"
    }
}

$securityPath = Join-Path $repoRoot 'docs/architecture-v5/10-security-boundaries.md'
$securityText = Get-Content -Raw -LiteralPath $securityPath
$negativeScenarioMarkers = @(
    '같은 가설 검증 요청이 동시에 두 번 도착',
    'retry 전 attempt 결과가 새 attempt보다 늦게 도착',
    '다른 `workspace_id` 또는 `commit_id` 결과가 합류',
    '가설·분석 취소 뒤 결과가 도착',
    'Technical 보완 전 revision이 Rule Scope Gate나 Reporter로 전달',
    '결과 record만 저장되고 종료 상태가 갱신되지 않음',
    '종료 상태만 있고 output record가 없음',
    '허용되지 않은 provider/model failover',
    'crash 뒤 같은 요청이 다시 들어옴',
    'retry·Gate `REVISE`·chaining이 한도를 넘음',
    '`PARTIAL` 결과에 누락 설명이 없음',
    '동적 `BLOCKED + failure_category=POLICY` 결과를 공통 work `BLOCKED`에 연결',
    '동적 종료 결과와 work·전문 상태 pointer가 다름',
    '분석 종료 시 `RUNNING` work나 `PREPARED` journal이 남음',
    '`COMMITTED` marker 투영 전에 취소·retry 전이가 경쟁',
    '모순된 `ALLOW`가 Reporter 호출을 요청',
    'Pro 또는 Con prompt·context·조회·tool 결과에 상대 역할 output을 넣음',
    'final Verification에 Pro 또는 Con exact result reference가 빠짐',
    'Pro·Con 결과의 부모·generation·공통 입력 hash가 서로 다름',
    'Pro/Con child가 `BLOCKED`인데 부모 Verification은 `RUNNING`으로 계속됨',
    'Pro/Con child가 최종 실패했는데 부모나 가설을 계속 진행'
)
foreach ($marker in $negativeScenarioMarkers) {
    if (-not $securityText.Contains($marker)) {
        Add-Failure "missing R4-02 negative scenario: $marker"
    }
}

$requiredR403ContractNames = @(
    'ActionRequest:',
    'ActionCheck:',
    'ActionDecision:',
    'EnvironmentRequirements:',
    'ReproductionPlan:',
    'EnvironmentRecipe:',
    'SandboxEnvironment:',
    'AgentLogEntry:',
    'AgentLog:',
    'PoCBundle:',
    'CleanupEntry:',
    'CleanupLog:',
    'LLMCallSpec:',
    'HumanReviewState:',
    'action_id:',
    'decision_id:',
    'action_decision_ref:',
    'use_status:',
    'HumanReviewPacket:',
    'HumanReviewDecision:',
    'review_packet_id:',
    'review_decision_id:',
    'reviewer_identity_ref:',
    'approved_report_refs:',
    'disclosure_targets:'
)
foreach ($name in $requiredR403ContractNames) {
    if (-not $contractText.Contains($name)) {
        Add-Failure "missing R4-03 contract name: $name"
    }
}

$requiredActionTypes = @(
    'REGISTER_WORK',
    'CHANGE_WORK_STATE',
    'START_ATTEMPT',
    'CANCEL_WORK',
    'READ_CODE',
    'RUN_TOOL',
    'CALL_LLM',
    'FETCH_POLICY',
    'RUN_SANDBOX',
    'SAVE_RESULT',
    'CALL_TECHNICAL_GATE',
    'CALL_RULE_SCOPE_GATE',
    'CREATE_REPORT_DRAFT',
    'PREPARE_HUMAN_REVIEW',
    'SAVE_HUMAN_DECISION',
    'EXTERNAL_DISCLOSURE'
)
$actionRequestBlock = [regex]::Match($contractText, '(?ms)^ActionRequest:\s*(.*?)^ActionCheck:').Groups[1].Value
$requiredActionRequestFields = @(
    'requester_identity_ref:',
    'input_refs:',
    'reproduction_plan_ref:',
    'result_kind:',
    'candidate_result_ref:',
    'llm_call_spec_ref:',
    'provider_profile_ref:',
    'sandbox_profile_ref:',
    'disclosure_targets:'
)
foreach ($field in $requiredActionRequestFields) {
    if (-not $actionRequestBlock.Contains($field)) {
        Add-Failure "missing R4-03 ActionRequest field: $field"
    }
}

$environmentRequirementBlock = [regex]::Match($contractText, '(?ms)^EnvironmentRequirement:\s*(.*?)^EnvironmentRequirements:').Groups[1].Value
$environmentRequirementsBlock = [regex]::Match($contractText, '(?ms)^EnvironmentRequirements:\s*(.*?)^ReproductionPlan:').Groups[1].Value
$reproductionPlanBlock = [regex]::Match($contractText, '(?ms)^ReproductionPlan:\s*(.*?)^EnvironmentRecipe:').Groups[1].Value
$environmentRecipeBlock = [regex]::Match($contractText, '(?ms)^EnvironmentRecipe:\s*(.*?)^EnvironmentCheck:').Groups[1].Value
$environmentCheckBlock = [regex]::Match($contractText, '(?ms)^EnvironmentCheck:\s*(.*?)^SandboxEnvironment:').Groups[1].Value
$sandboxEnvironmentBlock = [regex]::Match($contractText, '(?ms)^SandboxEnvironment:\s*(.*?)^AgentLogEntry:').Groups[1].Value
$agentLogEntryBlock = [regex]::Match($contractText, '(?ms)^AgentLogEntry:\s*(.*?)^AgentLog:').Groups[1].Value
$agentLogBlock = [regex]::Match($contractText, '(?ms)^AgentLog:\s*(.*?)^PoCBundle:').Groups[1].Value
$pocBundleBlock = [regex]::Match($contractText, '(?ms)^PoCBundle:\s*(.*?)^CleanupEntry:').Groups[1].Value
$cleanupEntryBlock = [regex]::Match($contractText, '(?ms)^CleanupEntry:\s*(.*?)^CleanupLog:').Groups[1].Value
$cleanupLogBlock = [regex]::Match($contractText, '(?ms)^CleanupLog:\s*(.*?)^DynamicReproductionResult:').Groups[1].Value
$dynamicResultBlock = [regex]::Match($contractText, '(?ms)^DynamicReproductionResult:\s*(.*?)^```').Groups[1].Value
foreach ($fieldPattern in @(
    'requirement_id:\s*string',
    'kind:\s*APP_ROLE \| AUTH \| DATA \| DATABASE \| SERVICE \| FIXTURE \| MOCK \| VERSION \| HEALTH_CHECK',
    'name:\s*string',
    'required:\s*boolean',
    'expected:\s*string \| null',
    'expected_ref:\s*StoredDataRef \| null',
    'alternatives:\s*\[string\]',
    'check_ref:\s*StoredDataRef \| null',
    'secret_ref:\s*StoredDataRef \| null',
    'source_refs:\s*\[StoredDataRef\]'
)) {
    if (-not [regex]::IsMatch($environmentRequirementBlock, $fieldPattern)) {
        Add-Failure "missing or invalid EnvironmentRequirement field: $fieldPattern"
    }
}
foreach ($fieldPattern in @('meta:\s*RecordMeta', 'items:\s*\[EnvironmentRequirement\]')) {
    if (-not [regex]::IsMatch($environmentRequirementsBlock, $fieldPattern)) {
        Add-Failure "missing or invalid EnvironmentRequirements field: $fieldPattern"
    }
}
foreach ($field in @('meta:', 'hypothesis_ref:', 'environment_requirements_ref:', 'sandbox_profile_ref:', 'reproduction_goal:', 'context_refs:', 'requested_evidence:')) {
    if (-not $reproductionPlanBlock.Contains($field)) {
        Add-Failure "missing ReproductionPlan field: $field"
    }
}
foreach ($forbiddenField in @('mode:', 'steps:', 'cleanup_policy_ref:', 'target_refs:')) {
    if ($reproductionPlanBlock.Contains($forbiddenField)) {
        Add-Failure "ReproductionPlan must not prescribe R7 execution field: $forbiddenField"
    }
}
foreach ($field in @('meta:', 'requirements_ref:', 'base_image_digest:', 'dockerfile_ref:', 'package_manifest_refs:', 'setup_script_refs:', 'account_setup_refs:', 'fixture_refs:', 'mock_service_refs:', 'healthcheck_refs:', 'parent_recipe_ref:', 'change_summary:', 'recipe_digest:')) {
    if (-not $environmentRecipeBlock.Contains($field)) {
        Add-Failure "missing EnvironmentRecipe field: $field"
    }
}
foreach ($fieldPattern in @(
    'requirement_id:\s*string',
    'status:\s*PASSED \| FAILED \| NOT_CHECKED',
    'actual:\s*string \| null',
    'actual_ref:\s*StoredDataRef \| null',
    'difference:\s*string \| null',
    'evidence_refs:\s*\[StoredDataRef\]',
    'check_result_ref:\s*StoredDataRef \| null'
)) {
    if (-not [regex]::IsMatch($environmentCheckBlock, $fieldPattern)) {
        Add-Failure "missing or invalid EnvironmentCheck field: $fieldPattern"
    }
}
foreach ($fieldPattern in @(
    'meta:\s*RecordMeta',
    'reproduction_plan_ref:\s*StoredDataRef',
    'requirements_ref:\s*StoredDataRef',
    'environment_recipe_ref:\s*StoredDataRef',
    'image_digest:\s*string',
    'status:\s*READY \| FAILED',
    'checks:\s*\[EnvironmentCheck\]',
    'limitations:\s*\[string\]',
    'created_at:\s*timestamp'
)) {
    if (-not [regex]::IsMatch($sandboxEnvironmentBlock, $fieldPattern)) {
        Add-Failure "missing or invalid SandboxEnvironment field: $fieldPattern"
    }
}
foreach ($field in @('event_id:', 'sequence:', 'timestamp:', 'action_type:', 'command_ref:', 'input_refs:', 'output_refs:', 'observation_refs:', 'execution_status:', 'exit_code:', 'error_ref:')) {
    if (-not $agentLogEntryBlock.Contains($field)) {
        Add-Failure "missing AgentLogEntry field: $field"
    }
}
foreach ($field in @('meta:', 'reproduction_plan_ref:', 'entries:')) {
    if (-not $agentLogBlock.Contains($field)) {
        Add-Failure "missing AgentLog field: $field"
    }
}
foreach ($field in @('meta:', 'reproduction_plan_ref:', 'environment_recipe_ref:', 'file_refs:', 'entrypoint_ref:', 'execution_command_ref:', 'attack_input_refs:', 'bundle_digest:')) {
    if (-not $pocBundleBlock.Contains($field)) {
        Add-Failure "missing PoCBundle field: $field"
    }
}
foreach ($field in @('resource_type:', 'resource_ref:', 'lifecycle:', 'status:', 'details:')) {
    if (-not $cleanupEntryBlock.Contains($field)) {
        Add-Failure "missing CleanupEntry field: $field"
    }
}
foreach ($field in @('meta:', 'entries:')) {
    if (-not $cleanupLogBlock.Contains($field)) {
        Add-Failure "missing CleanupLog field: $field"
    }
}
foreach ($fieldPattern in @(
    'action_decision_ref:\s*StoredDataRef',
    'reproduction_plan_ref:\s*StoredDataRef',
    'policy_decision_ref:\s*StoredDataRef \| null',
    'agent_invoked:\s*boolean',
    'environment_created:\s*boolean',
    'environment_ref:\s*StoredDataRef \| null',
    'environment_recipe_ref:\s*StoredDataRef \| null',
    'agent_log_ref:\s*StoredDataRef \| null',
    'poc_ref:\s*StoredDataRef \| null',
    'attack_input_refs:\s*\[StoredDataRef\]',
    'observation_refs:\s*\[StoredDataRef\]',
    'failure_category:\s*NONE \| PLAN \| ENVIRONMENT \| EXECUTION \| OBSERVATION \| POLICY \| TIMEOUT \| CANCELLED \| OTHER',
    'failure_reason:\s*string \| null',
    'plan_execution_status:\s*EXECUTABLE \| EXECUTABLE_WITH_LIMITATIONS \| NEEDS_REVISION',
    'plan_issues:\s*\[string\]',
    'plan_issue_evidence_refs:\s*\[StoredDataRef\]',
    'cleanup_required:\s*boolean',
    'cleanup_status:\s*SUCCEEDED \| FAILED \| NOT_REQUIRED',
    'cleanup_log_ref:\s*StoredDataRef \| null'
)) {
    if (-not [regex]::IsMatch($dynamicResultBlock, $fieldPattern)) {
        Add-Failure "missing or invalid DynamicReproductionResult field: $fieldPattern"
    }
}
if ($dynamicResultBlock.Contains('environment_requirements_ref:')) {
    Add-Failure 'DynamicReproductionResult must not duplicate environment_requirements_ref; follow reproduction_plan_ref and environment_ref instead'
}
foreach ($actionType in $requiredActionTypes) {
    if (-not $actionRequestBlock.Contains($actionType)) {
        Add-Failure "missing R4-03 action type: $actionType"
    }
    $tableRowPattern = '(?m)^\| `' + [regex]::Escape($actionType) + '`\s*\|'
    $tableRowCount = [regex]::Matches($contractText, $tableRowPattern).Count
    if ($tableRowCount -ne 2) {
        Add-Failure "R4-03 action type must have exactly one required-check row and one requester row: $actionType"
    }
}

$requiredActionCheckBindings = [ordered]@{
    REGISTER_WORK = 'SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET'
    CHANGE_WORK_STATE = 'SCHEMA, AUTHORITY, IDENTITY, STATE'
    START_ATTEMPT = 'SCHEMA, AUTHORITY, STATE, BUDGET'
    CANCEL_WORK = 'SCHEMA, AUTHORITY, IDENTITY, STATE'
    READ_CODE = 'SCHEMA, AUTHORITY, IDENTITY, REVISION, BUDGET, FILE_PATH'
    RUN_TOOL = 'SCHEMA, AUTHORITY, REVISION, BUDGET, TOOL, FILE_PATH'
    CALL_LLM = 'SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET, PROVIDER, SESSION, REDACTION'
    FETCH_POLICY = 'SCHEMA, AUTHORITY, BUDGET, TOOL, REDACTION'
    RUN_SANDBOX = 'SCHEMA, AUTHORITY, REVISION, STATE, BUDGET'
    SAVE_RESULT = 'SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, REDACTION'
    CALL_TECHNICAL_GATE = 'SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET, PROVIDER, SESSION, GATE_ORDER, REDACTION'
    CALL_RULE_SCOPE_GATE = 'SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET, PROVIDER, SESSION, GATE_ORDER, REDACTION'
    CREATE_REPORT_DRAFT = 'SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET, PROVIDER, SESSION, REPORT_READY, REDACTION'
    PREPARE_HUMAN_REVIEW = 'SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, REDACTION'
    SAVE_HUMAN_DECISION = 'SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, REDACTION'
    EXTERNAL_DISCLOSURE = 'SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, DISCLOSURE, REDACTION'
}
foreach ($binding in $requiredActionCheckBindings.GetEnumerator()) {
    $rowPattern = '(?m)^\| `' + [regex]::Escape($binding.Key) + '`\s*\|\s*' + [regex]::Escape($binding.Value) + '\s*\|'
    if ([regex]::Matches($contractText, $rowPattern).Count -ne 1) {
        Add-Failure "wrong R4-03 required checks for action: $($binding.Key)"
    }
}

$requiredActionRequesterBindings = [ordered]@{
    REGISTER_WORK = 'ORCHESTRATION, VERIFICATION, RECOVERY'
    CHANGE_WORK_STATE = 'ORCHESTRATION, VERIFICATION, RECOVERY'
    START_ATTEMPT = 'ORCHESTRATION, VERIFICATION, RECOVERY'
    CANCEL_WORK = 'ORCHESTRATION, VERIFICATION, RECOVERY, HUMAN_REVIEWER'
    READ_CODE = 'HYPOTHESIS, PRO, CON, VERIFICATION, REPRODUCTION_AGENT, CWE_LABELING, TECHNICAL_GATE'
    RUN_TOOL = 'REPOSITORY_LOADER, STATIC_ANALYSIS, POLICY_COLLECTOR'
    CALL_LLM = 'HYPOTHESIS, PRO, CON, VERIFICATION, REPRODUCTION_AGENT, CWE_LABELING, CHAINING'
    FETCH_POLICY = 'POLICY_COLLECTOR'
    RUN_SANDBOX = 'VERIFICATION'
    SAVE_RESULT = 'ORCHESTRATION, HYPOTHESIS, PRO, CON, VERIFICATION, REPRODUCTION_AGENT, CWE_LABELING, CHAINING, TECHNICAL_GATE, RULE_SCOPE_GATE, REPORTER, REPOSITORY_LOADER, STATIC_ANALYSIS, POLICY_COLLECTOR, SANDBOX, RECOVERY'
    CALL_TECHNICAL_GATE = 'VERIFICATION'
    CALL_RULE_SCOPE_GATE = 'VERIFICATION'
    CREATE_REPORT_DRAFT = 'VERIFICATION'
    PREPARE_HUMAN_REVIEW = 'ORCHESTRATION'
    SAVE_HUMAN_DECISION = 'HUMAN_REVIEWER'
    EXTERNAL_DISCLOSURE = 'HUMAN_REVIEWER'
}
foreach ($binding in $requiredActionRequesterBindings.GetEnumerator()) {
    $rowPattern = '(?m)^\| `' + [regex]::Escape($binding.Key) + '`\s*\|\s*' + [regex]::Escape($binding.Value) + '\s*\|\s*$'
    if ([regex]::Matches($contractText, $rowPattern).Count -ne 1) {
        Add-Failure "wrong R4-03 requester authority for action: $($binding.Key)"
    }
}

$requiredActionChecks = @(
    'SCHEMA',
    'AUTHORITY',
    'IDENTITY',
    'REVISION',
    'STATE',
    'BUDGET',
    'TOOL',
    'FILE_PATH',
    'PROVIDER',
    'SESSION',
    'GATE_ORDER',
    'REPORT_READY',
    'REDACTION',
    'DISCLOSURE'
)
$actionCheckBlock = [regex]::Match($contractText, '(?ms)^ActionCheck:\s*(.*?)^ActionDecision:').Groups[1].Value
foreach ($check in $requiredActionChecks) {
    if (-not $actionCheckBlock.Contains($check)) {
        Add-Failure "missing R4-03 ActionCheck: $check"
    }
}

$actionDecisionBlock = [regex]::Match($contractText, '(?ms)^ActionDecision:\s*(.*?)^```').Groups[1].Value
$requiredActionDecisionFields = @('action_ref:', 'required_checks:', 'check_results:', 'checked_state_version:', 'checked_config_refs:', 'valid_until:', 'use_status:', 'used_at:', 'expired_at:', 'expire_reason:', 'outcome_refs:')
foreach ($field in $requiredActionDecisionFields) {
    if (-not $actionDecisionBlock.Contains($field)) {
        Add-Failure "missing R4-03 ActionDecision field: $field"
    }
}

$llmSpecBlock = [regex]::Match($contractText, '(?ms)^LLMCallSpec:\s*(.*?)^LLMInvocationRequest:').Groups[1].Value
$llmRequestBlock = [regex]::Match($contractText, '(?ms)^LLMInvocationRequest:\s*(.*?)^```').Groups[1].Value
foreach ($block in @($llmSpecBlock, $llmRequestBlock)) {
    foreach ($field in @('llm_call_id:', 'agent_role:', 'provider_profile_ref:', 'model:', 'session_policy:', 'context_refs:', 'prompt_payload_ref:', 'output_schema:', 'token_budget:', 'timeout_ms:')) {
        if (-not $block.Contains($field)) {
            Add-Failure "missing exact LLM call field: $field"
        }
    }
    if (-not $block.Contains('CWE_LABELING')) {
        Add-Failure 'CWE_LABELING missing from LLM call role enum'
    }
    if (-not $block.Contains('CHAINING')) {
        Add-Failure 'CHAINING missing from LLM call role enum'
    }
}
if (-not $llmRequestBlock.Contains('call_spec_ref:')) {
    Add-Failure 'LLMInvocationRequest missing call_spec_ref'
}
$llmLogBlock = [regex]::Match($contractText, '(?ms)^LLMInvocationLog:\s*(.*?)^```').Groups[1].Value
if (-not $llmLogBlock.Contains('parsed_output_ref:')) {
    Add-Failure 'LLMInvocationLog missing parsed_output_ref'
}
foreach ($pair in @(
    @{ Name = 'TechnicalEvidenceReview'; End = '## 9.' },
    @{ Name = 'RuleScopeImpactReview'; End = '```' },
    @{ Name = 'ReportDraft'; End = '```' }
)) {
    $outputPattern = '(?ms)^' + [regex]::Escape($pair.Name) + ':\s*(.*?)^' + [regex]::Escape($pair.End)
    $outputBlock = [regex]::Match($contractText, $outputPattern).Groups[1].Value
    if (-not $outputBlock.Contains('action_decision_ref:')) {
        Add-Failure "$($pair.Name) missing action_decision_ref"
    }
    if ($outputBlock.Contains('llm_invocation_log_ref:')) {
        Add-Failure "$($pair.Name) must not reverse-reference LLMInvocationLog"
    }
}

$humanPacketBlock = [regex]::Match($contractText, '(?ms)^HumanReviewPacket:\s*(.*?)^HumanReviewDecision:').Groups[1].Value
$humanDecisionBlock = [regex]::Match($contractText, '(?ms)^HumanReviewDecision:\s*(.*?)^```').Groups[1].Value
$analysisRunResultBlock = [regex]::Match($contractText, '(?ms)^AnalysisRunResult:\s*(.*?)^```').Groups[1].Value
$requiredSharedReviewFields = @('finding_refs:', 'verification_refs:', 'cwe_label_refs:', 'technical_review_refs:', 'rule_scope_review_refs:', 'policy_record_refs:', 'dynamic_result_refs:', 'poc_refs:', 'report_draft_refs:', 'llm_invocation_log_refs:', 'action_decision_refs:', 'work_state_refs:', 'work_attempt_refs:', 'transition_commit_refs:', 'debug_trace_ref:')
foreach ($field in $requiredSharedReviewFields) {
    if (-not $humanPacketBlock.Contains($field)) {
        Add-Failure "missing HumanReviewPacket field: $field"
    }
    if (-not $analysisRunResultBlock.Contains($field)) {
        Add-Failure "missing AnalysisRunResult review field: $field"
    }
}
if (-not $humanPacketBlock.Contains('review_generation:') -or -not $humanDecisionBlock.Contains('review_generation:')) {
    Add-Failure 'Human review packet and decision must share review_generation'
}
$humanReviewStateBlock = [regex]::Match($contractText, '(?ms)^HumanReviewState:\s*(.*?)^ProposalProcessState:').Groups[1].Value
foreach ($field in @('state_version:', 'packet_generation:', 'status:', 'current_packet_ref:', 'current_decision_ref:')) {
    if (-not $humanReviewStateBlock.Contains($field)) {
        Add-Failure "missing HumanReviewState field: $field"
    }
}

$requiredAuthorityErrors = @(
    'AUTHORITY_DENIED',
    'ACTION_NOT_ALLOWED',
    'GATE_ORDER_INVALID',
    'REPORT_NOT_READY',
    'TOOL_NOT_ALLOWED',
    'FILE_ACCESS_DENIED',
    'SANDBOX_POLICY_DENIED',
    'PROVIDER_PROFILE_DENIED',
    'DISCLOSURE_DENIED',
    'UNTRUSTED_INSTRUCTION'
)
foreach ($code in $requiredAuthorityErrors) {
    if (-not $resultText.Contains($code)) {
        Add-Failure "missing R4-03 authority error code: $code"
    }
}

$authorityScenarioMarkers = @(
    'Orchestration이 `TRUE`를 저장하려 함',
    'Hypothesis Agent가 final verdict를 출력',
    'Technical Gate가 Verification verdict를 바꾸려 함',
    'Technical Gate 없이 Rule Scope Gate 호출',
    'Rule Scope Gate 없이 Reporter 호출',
    '공식 정책이 없는데 `ALLOW` 출력',
    'repository prompt가 Sandbox network를 열라고 함',
    'LLM이 workspace 밖 파일을 요청',
    '허용하지 않은 provider/model로 silent failover',
    '인증 실패를 `FALSE`로 저장하려 함',
    'Reporter가 새 공격 경로를 확정',
    'LLM이 `HumanReviewDecision` 형식의 승인을 출력',
    'Agent가 외부 공개 action을 요청',
    '사람이 다른 packet·과거 revision의 승인을 재사용',
    'redaction 실패 PoC를 사람 또는 외부로 전달',
    '같은 ActionRequest를 동시에 두 번 검사',
    'Gate 또는 Reporter가 별도 CALL_LLM으로 우회',
    '사람 결정 뒤 새 HumanReviewPacket 생성',
    'Technical Gate `REVISE` 뒤 같은 입력으로 재투표',
    'action 허가 뒤 Gate 입력 revision이 바뀜',
    'Runtime Validator가 공식 정책 의미를 다시 판단',
    'Pro와 Con이 같은 session 또는 parent를 공유',
    '`SAVE_RESULT` 검사 뒤 candidate bytes를 바꿈',
    '실행 오류만 든 `FALSE` 후보를 저장',
    '다른 역할이 만든 결과 후보를 저장'
    '`RUN_SANDBOX` 허가 뒤 plan·requirements·profile revision이 바뀜'
    'Agent가 Sandbox 내부에서 plan에 없는 command·payload를 실행'
    '동적 결과의 recipe·environment·Agent Log·PoC digest가 서로 다름'
    'Verification이 `DynamicReproductionResult`를 직접 저장'
)
foreach ($marker in $authorityScenarioMarkers) {
    if (-not $securityText.Contains($marker)) {
        Add-Failure "missing R4-03 authority scenario: $marker"
    }
}

$sandboxReviewPatterns = @(
    @{
        Name = 'Runtime Validator authorizes current references while R7 Controller owns the external boundary'
        Pattern = '(?s)`RUN_SANDBOX`의 `ActionDecision=ALLOW`.*?Runtime Validator.*?권한.*?상태와 예산.*?exact `ReproductionPlan`.*?current `EnvironmentRequirements`.*?Sandbox profile.*?Sandbox Controller.*?Docker daemon.*?network egress.*?resource profile.*?개별 command.*?사전 allowlist'
    },
    @{
        Name = 'RUN_SANDBOX freezes the minimal reproduction request closure'
        Pattern = '(?s)`RUN_SANDBOX`만 `reproduction_plan_ref`를 사용.*?action `input_refs`에는 exact `ReproductionPlan`.*?`hypothesis_ref`.*?`environment_requirements_ref`.*?`sandbox_profile_ref`.*?`context_refs`.*?Agent가 사용할 command·package·PoC를 요구하거나 의미 판단하지 않는다'
    },
    @{
        Name = 'invoked reproduction agent always produces an exact AgentLog'
        Pattern = '(?s)`agent_invoked=false`이면 `agent_log_ref=null`.*?`agent_invoked=true`이면.*?exact `AgentLog`가 필수.*?shell.*?PoC 생성·수정·실행.*?관찰.*?재시도.*?cleanup.*?chain-of-thought.*?저장하지 않는다'
    },
    @{
        Name = 'dynamic result save uses the hybrid trusted finalizer'
        Pattern = '(?s)`SAVE_RESULT\(requested_by=REPRODUCTION_AGENT, result_kind=dynamic_reproduction_result\)`.*?finalizer.*?plan, policy, recipe, environment, Agent Log, 실행 PoC, observation과 cleanup.*?attempt·digest.*?Verification은 `COMMITTED` 결과만 소비'
    },
    @{
        Name = 'Reproduction Agent owns dynamic result semantics and Verification only consumes'
        Pattern = '(?s)`dynamic_reproduction_result -> DynamicReproductionResult -> REPRODUCTION_AGENT`.*?trusted finalizer.*?domain producer authority는 `REPRODUCTION_AGENT`.*?Verification은 `COMMITTED` 결과만 소비하며 R7 결과를 직접 만들거나 수정하지 않는다'
    },
    @{
        Name = 'dynamic result nullable references follow lifecycle facts'
        Pattern = '(?s)`agent_invoked=false`이면 `agent_log_ref=null`.*?`agent_invoked=true`이면.*?exact `AgentLog`가 필수.*?`environment_created=false`이면 `environment_ref=null`.*?`true`이면.*?`SandboxEnvironment`와 `environment_recipe_ref`가 모두 필수'
    },
    @{
        Name = 'cleanup NOT_REQUIRED is limited to attempts without cleanup targets'
        Pattern = '(?s)session의 container·network·volume·tmp·임시 build.*?`cleanup_required=true`.*?`cleanup_log_ref`.*?`SUCCEEDED \| FAILED`.*?정리 대상이 전혀 없을 때만 `NOT_REQUIRED`.*?`PERSISTENT_BASELINE`.*?`PRESERVED`'
    },
    @{
        Name = 'policy blocked result retains the exact Controller decision'
        Pattern = '(?s)`failure_category=POLICY`이면 `policy_decision_ref`가 필수.*?Controller 판단 전에 취소.*?`null`'
    },
    @{
        Name = 'PoC reference points only to the final execution-started bundle'
        Pattern = '(?s)`poc_ref`는 Agent가 실제 실행을 시작한 최종 exact `PoCBundle`만 가리킨다.*?만들기만 한 draft.*?결과의 `poc_ref`로 전달하지 않는다.*?PoC 실행이 실패.*?bundle.*?`POC_EXECUTE` event와 같아야 한다'
    },
    @{
        Name = 'Verification owns minimal plans while Reproduction Agent owns dynamic artifacts'
        Pattern = '(?s)`reproduction_plan -> ReproductionPlan -> VERIFICATION`.*?`environment_recipe -> EnvironmentRecipe -> REPRODUCTION_AGENT`.*?`agent_log -> AgentLog -> REPRODUCTION_AGENT`.*?`dynamic_reproduction_result -> DynamicReproductionResult -> REPRODUCTION_AGENT`'
    }
)
foreach ($rule in $sandboxReviewPatterns) {
    if (-not [regex]::IsMatch($contractText, $rule.Pattern)) {
        Add-Failure "missing or weakened PR #27 Sandbox review rule: $($rule.Name)"
    }
}

$environmentHandoffPatterns = @(
    @{
        Name = 'R6 owns immutable environment requirements'
        Pattern = '(?s)`EnvironmentRequirements`는 R6 Verification이.*?불변 요구사항 record.*?R7은 이 record를 만들거나 수정할 수 없다'
    },
    @{
        Name = 'minimal reproduction plan binds current exact requirements'
        Pattern = '(?s)`ReproductionPlan`은 R6 Verification이.*?`environment_requirements_ref`.*?current exact `EnvironmentRequirements`.*?`reproduction_goal`.*?exact step·command·attack input·cleanup policy를 넣지 않으며'
    },
    @{
        Name = 'RUN_SANDBOX closure includes requirements'
        Pattern = '(?s)action `input_refs`에는 exact `ReproductionPlan`.*?`environment_requirements_ref`.*?current exact `EnvironmentRequirements` revision'
    },
    @{
        Name = 'actual environment compares every requirement'
        Pattern = '(?s)EnvironmentCheck:.*?status: PASSED \| FAILED \| NOT_CHECKED.*?SandboxEnvironment:.*?requirements_ref: StoredDataRef.*?environment_recipe_ref: StoredDataRef.*?checks: \[EnvironmentCheck\].*?모든 `requirement_id`를 중복 없이 정확히 한 번씩 포함'
    },
    @{
        Name = 'versioned environment recipe supports package repair and retry'
        Pattern = '(?s)`EnvironmentRecipe`는 R7이.*?불변 build recipe.*?package 누락.*?Agent Log에 실패.*?Dockerfile·manifest·setup.*?새 baseline image와 recipe revision'
    },
    @{
        Name = 'environment failure is not falsification'
        Pattern = '(?s)`SandboxEnvironment`.*?`FAILED`.*?환경 실패·미확인·version 차이는 그 자체로 `DISPROVED \| FALSE`가 아니다'
    },
    @{
        Name = 'R6 revision cannot bypass sandbox policy'
        Pattern = '(?s)R6가 requirements나 최소 plan의 새 revision.*?새 `RUN_SANDBOX` action.*?R7 Controller 외부 경계 검사를 다시.*?이전 허가를 재사용할 수 없다'
    },
    @{
        Name = 'environment secrets use opaque handles only'
        Pattern = '(?s)credential·cookie·token·password.*?저장하지 않는다.*?`secret_ref\(data_kind=secret_handle\)`'
    },
    @{
        Name = 'reproduction plan has a new major schema'
        Pattern = '(?s)exact step/command 실행 모델에서 자율 Agent artifact 모델.*?`ReproductionPlan`.*?새 MAJOR schema.*?`EnvironmentRecipe`, `AgentLog`, `PoCBundle`, `CleanupLog`'
    }
)
foreach ($rule in $environmentHandoffPatterns) {
    if (-not [regex]::IsMatch($contractText, $rule.Pattern)) {
        Add-Failure "missing or weakened R6-R7 environment handoff rule: $($rule.Name)"
    }
}

$environmentNegativeMarkers = @(
    'ReproductionPlan에 `environment_requirements_ref`가 없음',
    'R7이 EnvironmentRequirements를 만들거나 수정함',
    'plan과 실제 환경이 다른 requirements revision을 가리킴',
    '환경 문제를 고치며 recipe revision을 바꿨지만 결과가 이전 image를 가리킴',
    '오래된 EnvironmentRequirements revision을 재사용함',
    '환경 구성 실패나 차이를 `DISPROVED | FALSE`로 변환함',
    '환경 요구사항·실제 값에 credential·token 원문을 저장함',
    '정리 대상이 생겼는데 `NOT_REQUIRED`로 기록',
    'baseline image를 session ephemeral로 삭제하거나 임시 자원을 baseline으로 보존',
    '실행하지 않은 PoC draft를 최종 `poc_ref`로 연결'
)
foreach ($marker in $environmentNegativeMarkers) {
    $rowPattern = '(?m)^\|\s*' + [regex]::Escape($marker) + '\s*\|'
    if ([regex]::Matches($securityText, $rowPattern).Count -ne 1) {
        Add-Failure "missing R6-R7 environment negative scenario: $marker"
    }
}

$orchestrationPath = Join-Path $repoRoot 'docs/architecture-v5/03-agent-roles-and-orchestration.md'
$orchestrationText = Get-Content -Raw -LiteralPath $orchestrationPath
$gatePath = Join-Path $repoRoot 'docs/architecture-v5/05-llm-gate-and-reporting.md'
$gateText = Get-Content -Raw -LiteralPath $gatePath
$gateWikiPath = Join-Path $repoRoot 'docs/architecture-v5/wiki/gate-and-reporting.md'
$gateWikiText = Get-Content -Raw -LiteralPath $gateWikiPath
$requiredAuthorityRules = @(
    '## 역할별 권한 경계',
    '## action 요청과 실행',
    'final VerificationResult + CWELabel',
    '-> Technical Evidence Gate',
    '-> Rule Scope Impact Gate',
    'HumanReviewPacket',
    'HumanReviewDecision',
    'UNUSED -> USED',
    'UNUSED -> EXPIRED',
    'requester_identity_ref',
    'valid_until',
    'work_attempt_refs',
    '한 `action_ref.record_id`에는 정확히 하나의 `decision_id`',
    'llm_call_spec_ref',
    'current_packet_ref',
    'output은 log를 역참조하지 않는다',
    '아직 `outcome_refs`가 비어 있는 revision',
    'SAVE_HUMAN_DECISION',
    'Technical action의 `REVISION`은 exact Verification+CWE',
    '같은 Verification·CWE revision 또는 같은 domain input hash',
    '오류 층은 섞어 기록하지 않는다',
    '정책 문장이나 정책의 의미를 대신 해석하지 않는다',
    'Pro와 Con의 `SESSION` check는 독립성을 선택값이 아닌 필수 불변조건으로 검사한다',
    '`candidate_result_ref.record_id`에는 저장 runtime이 미리 발급한 결과 revision ID',
    '`VerificationResult.verdict=FALSE`이면 `falsification_results`',
    '`TransitionCommit.state=COMMITTED`가 된 뒤에만 소비할 수 있다'
)
foreach ($rule in $requiredAuthorityRules) {
    if (-not ($orchestrationText.Contains($rule) -or $gateText.Contains($rule) -or $contractText.Contains($rule) -or $resultText.Contains($rule))) {
        Add-Failure "missing R4-03 authority rule: $rule"
    }
}

$requiredR504CrossReviewRules = @(
    @{
        Name = 'Technical Gate status fixes handoff readiness'
        Text = $contractText
        Marker = '`status=ACCEPT`는 `handoff_readiness=READY`, `status=REVISE | REJECT`는 `handoff_readiness=NOT_READY`만 허용한다.'
    },
    @{
        Name = 'policy-blocked dynamic reproduction is not automatic rejection or falsification'
        Text = $contractText
        Marker = '`DynamicReproductionResult(status=BLOCKED, failure_category=POLICY)`는 자동 `REJECT` 조건이 아니다.'
    },
    @{
        Name = 'policy freshness is explicit in the shared contract'
        Text = $contractText
        Marker = 'freshness_status: CURRENT | STALE | UNVERIFIED'
    },
    @{
        Name = 'stale or unverified policy blocks report permission'
        Text = $contractText
        Marker = '`freshness_status=STALE | UNVERIFIED`이면 `rule_compliance`, `scope_compliance`, `review_status`는 `UNCERTAIN`, permission은 `DENY`다.'
    },
    @{
        Name = 'changed upstream revisions supersede report drafts'
        Text = $contractText
        Marker = '오래된 draft는 current `HumanReviewPacket.report_draft_refs`와 `approved_report_refs`에 넣을 수 없다.'
    },
    @{
        Name = 'missing Finding creates a non-disclosable blocked packet'
        Text = $contractText
        Marker = '`blocked_reasons`에 `FINDING_NOT_CREATED`를 남긴다.'
    },
    @{
        Name = 'Wiki exposes Technical Gate handoff readiness'
        Text = $gateWikiText
        Marker = '`handoff_readiness: READY | NOT_READY`'
    }
)
foreach ($rule in $requiredR504CrossReviewRules) {
    if (-not $rule.Text.Contains($rule.Marker)) {
        Add-Failure "missing or weakened PR #48 cross-review rule: $($rule.Name)"
    }
}

$requiredVerificationChainingContracts = @(
    'VerificationAssignment:',
    'verification_assignment_ref:',
    'ChainingResult:',
    'trigger: HOLD_MATCH | TRUE_HOLD_MATCH | TRUE_TRUE_MATCH',
    'source_result_refs:',
    'input_primitive_refs:',
    'input_primitive_index_refs:',
    'primitive_match_candidates:',
    'chained_hypothesis_proposals:',
    'no_match_reasons:',
    'bounded_stop_reason:',
    'origin: INITIAL | VERIFICATION | CHAINING',
    'material_child_proposals:',
    'source_verification_ref:',
    'technical_review_ref:',
    'rule_scope_review_ref:',
    'required_preconditions:',
    'PrimitiveIndexState:',
    'eligibility: ACTIVE | SUPERSEDED',
    'superseded_by_verification_ref:',
    'primitive_and_chaining_refs:'
)
foreach ($marker in $requiredVerificationChainingContracts) {
    if (-not $contractText.Contains($marker)) {
        Add-Failure "missing Verification/Chaining contract: $marker"
    }
}

foreach ($forbidden in @('ResearchResult:', 'origin: INITIAL | RESEARCH | CHAINING', 'work_type: WORKSPACE_PREP | STATIC_TOOL | STATIC_NORMALIZE | HYPOTHESIS_PROPOSAL | CONTEXT_RETRIEVAL | PRO_EVIDENCE | CON_EVIDENCE | VERIFICATION | DYNAMIC_REPRO | PRIMITIVE_UPDATE | RESEARCH', 'research_requests:')) {
    if ($contractText.Contains($forbidden)) {
        Add-Failure "obsolete active Research contract remains: $forbidden"
    }
}

$verificationChainingScenarioMarkers = @(
    '| N1 | final HOLD |',
    '| N2 | final FALSE |',
    '| N3 | final TRUE, Gate 미실행 |',
    '| N4 | TRUE + Technical `ACCEPT`, Rule Scope 미실행 |',
    '| N5 | TRUE + Technical `ACCEPT` + Rule Scope `FAIL | UNCERTAIN | DENY` |',
    '| N6 | TRUE + Technical `ACCEPT` + Rule Scope `PASS/PASS/PASS/SUFFICIENT/ALLOW` |',
    '| N7 | Gate-qualified TRUE PROVIDED + HOLD REQUIRED |',
    '| N8 | 서로 다른 Gate-qualified TRUE PROVIDED 둘 |',
    '| N9 | TRUE_TRUE 입력 중 한 부모가 Gate 전 또는 비정상 Gate 결과 |',
    '| N10 | Verification N은 Gate-qualified지만 N+1이 새로 생성됨 |',
    '| N10-A | Chaining이 N의 ACTIVE Primitive를 읽은 뒤 commit 전에 새 Verification generation/index revision 생성 |',
    '| N11 | Verification이 새 endpoint·sink·권한 경계를 발견 |',
    '| N12 | chained child가 FALSE |',
    '| N13 | Verification이 budget·Sandbox·Gate 순서를 우회하려 함 |',
    '| N13-A | 같은 역할이지만 배정되지 않은 Verification identity가 Gate·Reporter·새 verification work를 요청 |',
    '| N14 | Chaining Agent가 Primitive match 없는 bypass·impact·dynamic 요청을 출력 |',
    '| N15 | `purpose=PRODUCTION`인데 `verification_mode=BASIC | CONDITIONAL_DEBATE`를 요청 |',
    '| N16 | 운영 Pro/Con 중 하나를 실행할 예산이 부족 |',
    '| N17 | Context 조회 실패·timeout·권한 오류만으로 `HOLD`를 저장하려 함 |',
    '| N18 | 일부 Context 조회는 실패했지만 대체 조회·다른 정상 근거와 운영 Pro/Con으로 필수 검증을 완료 |',
    '| N19 | 필수 Context 또는 운영 Pro/Con을 확보하지 못했는데 final `VerificationResult`를 저장하려 함 |'
)
foreach ($marker in $verificationChainingScenarioMarkers) {
    if (-not $securityText.Contains($marker)) {
        Add-Failure "missing Verification/Chaining scenario: $marker"
    }
}

$requiredVerificationChainingRules = @(
    'Orchestration Agent는 한 가설 안에서 Pro/Con·동적 재현·두 Gate·Reporter·Chaining의 호출 여부나 Technical `REVISE` 목적지를 결정하지 않는다.',
    '같은 hypothesis의 ACTIVE `VerificationAssignment` owner에게 전달',
    'Gate 전 TRUE와 오래된 Gate revision은 ACTIVE PROVIDED가 될 수 없다.',
    'origin=VERIFICATION',
    'origin=CHAINING',
    'TRUE_HOLD',
    'TRUE_TRUE',
    '앞 TRUE의 제공 능력이 뒤 TRUE를 악용하기 위해 exact Verification에서 명시한 선행 조건을 충족',
    'HypothesisProcessState.status=TERMINAL',
    'VerificationAssignment.owner_identity_ref',
    'commit-time CAS 검사가 최종 강제 경계',
    'child가 FALSE여도 부모 판정은 바뀌지 않는다'
)
foreach ($rule in $requiredVerificationChainingRules) {
    if (-not ($orchestrationText.Contains($rule) -or $gateText.Contains($rule) -or $contractText.Contains($rule) -or $securityText.Contains($rule) -or $diagramText.Contains($rule))) {
        Add-Failure "missing Verification/Chaining rule: $rule"
    }
}

$requiredDebatePolicyRules = @(
    'purpose: PRODUCTION | EVALUATION',
    'PRODUCTION에서는 `verification_mode=ALWAYS_DEBATE`만 허용한다.',
    'EVALUATION의 `BASIC | CONDITIONAL_DEBATE` 결과는 Gate·Primitive admission·Reporter 입력으로 사용할 수 없다.',
    '예산이 부족하면 `BUDGET_EXCEEDED`로 현재 Verification work를 중단하며 Pro/Con을 생략한 final verdict를 만들지 않는다.'
)
foreach ($rule in $requiredDebatePolicyRules) {
    if (-not ($overviewText.Contains($rule) -or $verificationText.Contains($rule) -or $contractText.Contains($rule) -or $securityText.Contains($rule))) {
        Add-Failure "missing production debate rule: $rule"
    }
}

$obsoleteDebatePolicyPhrases = @(
    '기본 검증 모드는 `CONDITIONAL_DEBATE`다.',
    '| `CONDITIONAL_DEBATE` | trigger 충족 시 Pro/Con을 독립 병렬 호출 | 기본값 |',
    '예산이 부족할 때는 생략 사유를 기록하고 BASIC으로 종료할 수 있다.'
)
foreach ($phrase in $obsoleteDebatePolicyPhrases) {
    if ($activeDebateText.Contains($phrase)) {
        Add-Failure "obsolete production debate rule remains: $phrase"
    }
}

$requiredContextFailureRules = @(
    @{
        Name = 'Context errors and affected gaps are both recorded'
        Text = $contractText
        Marker = '실패 사건은 `AnalysisError(stage=CONTEXT)`로, 그 때문에 확인하지 못한 코드 범위는 `DataGap(stage=CONTEXT)`으로 각각 기록한다.'
    },
    @{
        Name = 'Context errors and gaps are not verdict evidence'
        Text = $resultText
        Marker = '`AnalysisError`와 `DataGap` 자체는 supporting evidence, counter evidence 또는 falsification evidence가 아니다.'
    },
    @{
        Name = 'Partial Context failure may still allow a final verdict after required validation'
        Text = $contractText
        Marker = '일부 요청이 실패했어도 제한 retry·대체 조회 또는 다른 정상 근거로 가설의 모든 `validation_checks`, 모든 반증 질문과 운영 Pro/Con을 완료했다면 Verification은 실제 근거에 따라 final `TRUE | FALSE | HOLD`를 만들 수 있다.'
    },
    @{
        Name = 'Missing required Context or production debate blocks the final VerificationResult'
        Text = $contractText
        Marker = '필수 Context나 운영 Pro/Con을 확보하지 못해 검증 절차 자체를 완료하지 못했다면 final `VerificationResult`를 만들지 않는다.'
    },
    @{
        Name = 'Retryable and exhausted Context failures map to BLOCKED and FAILED'
        Text = $contractText
        Marker = '재시도할 수 있으면 해당 Verification work를 `BLOCKED`로 두고 `HypothesisProcessState.status=VERIFYING`을 유지한다. 허용된 재시도를 소진했거나 복구할 수 없으면 같은 atomic transition에서 work와 가설 처리 상태를 `FAILED`로 남긴다.'
    },
    @{
        Name = 'Simple Wiki explains that a Context error alone is not HOLD'
        Text = $commonWikiText
        Marker = '단순 조회 오류만으로 `HOLD`를 만들지 않습니다.'
    },
    @{
        Name = 'Canonical Context diagram has the no-final-verdict failure branch'
        Text = $diagramText
        Marker = 'FAIL[Atomic work FAILED plus hypothesis FAILED no final result]'
    }
)
foreach ($rule in $requiredContextFailureRules) {
    if (-not $rule.Text.Contains($rule.Marker)) {
        Add-Failure "missing or weakened Context failure contract: $($rule.Name)"
    }
}

$requiredVerificationCompletionRules = @(
    'ValidationCheck:',
    'validation_id: string',
    'instruction: string',
    'ValidationCheckResult:',
    'completion: COMPLETE | INCOMPLETE',
    'validation_checks: [ValidationCheck]',
    'validation_results: [ValidationCheckResult]'
)
foreach ($marker in $requiredVerificationCompletionRules) {
    if (-not $contractText.Contains($marker)) {
        Add-Failure "missing enforceable validation completion contract: $marker"
    }
}

$requiredVerificationCompletionSemantics = @(
    '가설의 모든 `ValidationCheck.validation_id`와 candidate의 `ValidationCheckResult.validation_id`가 중복 없이 set-equal',
    '모든 `ValidationCheckResult.completion=COMPLETE`',
    '각 결과의 `evidence_refs`가 하나 이상',
    '`INCOMPLETE` 항목이 하나라도 있으면 final candidate를 `COMMITTED`하지 않는다.'
)
foreach ($marker in $requiredVerificationCompletionSemantics) {
    if (-not $contractText.Contains($marker)) {
        Add-Failure "missing structural validation completion rule: $marker"
    }
}

$requiredHypothesisFailureRules = @(
    'status: REGISTERED | ASSIGNED | VERIFYING | TERMINAL | FAILED | CANCELLED',
    '`HypothesisProcessState.status=FAILED`',
    '`verification_result_ref=null`',
    '같은 `VERIFICATION` work의 `FAILED` revision',
    '`VERIFICATION`의 `FAILED`와 `HypothesisProcessState.status=FAILED`',
    '`failed_hypothesis_count`'
)
foreach ($marker in $requiredHypothesisFailureRules) {
    if (-not ($contractText.Contains($marker) -or $resultText.Contains($marker) -or $orchestrationText.Contains($marker) -or $commonWikiText.Contains($marker))) {
        Add-Failure "missing no-verdict hypothesis failure contract: $marker"
    }
}

$requiredTechnicalGateScopeRules = @(
    'final `TRUE` 근거의 의미적 충분성과 코드·실행 근거 연결은 Technical Evidence Gate가 exact final TRUE revision을 대상으로 별도로 검토한다.',
    '`FALSE | HOLD`는 Technical Gate 입력이 아니며, 구조 검사를 통과했다는 사실이 Gate 승인을 의미하지 않는다.'
)
foreach ($marker in $requiredTechnicalGateScopeRules) {
    if (-not $contractText.Contains($marker)) {
        Add-Failure "missing exact Technical Gate TRUE-only scope rule: $marker"
    }
}

$obsoleteContextFailurePhrases = @(
    '잘림·조회 실패를 숨기지 않고 HOLD 또는 추가 조회 판단에 전달',
    'Verification Agent가 다른 근거와 함께 `HOLD` 여부 결정',
    'required_validation:',
    '근거가 verdict를 의미상 충분히 지지하는지는 Technical Evidence Gate가 검토한다.'
)
foreach ($phrase in $obsoleteContextFailurePhrases) {
    if ($activeDebateText.Contains($phrase)) {
        Add-Failure "obsolete Context failure contract remains: $phrase"
    }
}

$savedErrorAction = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$gitCheck = & git -C $repoRoot diff --check 2>&1
$gitCheckExitCode = $LASTEXITCODE
$ErrorActionPreference = $savedErrorAction
if ($gitCheckExitCode -ne 0) {
    Add-Failure "git diff --check failed: $($gitCheck -join [Environment]::NewLine)"
}

Write-Output "Markdown files: $($markdownFiles.Count)"
Write-Output "Mermaid blocks: $($diagramBlocks.Count) canonical / $($wikiDiagramBlocks.Count) Wiki"
Write-Output "R4-02 required contract names: $($requiredContractNames.Count)"
Write-Output "R4 Pro/Con result fields: $($requiredEvidenceAgentResultFields.Count)"
Write-Output "R4 Verification join fields: $($requiredVerificationDebateFields.Count)"
Write-Output "R4 Pro/Con join rules: $($requiredDebateContractMarkers.Count)"
Write-Output "R4-02 TransitionCommit atomic fields: $($requiredTransitionCommitFields.Count)"
Write-Output "R4-02 exact output bindings: $($requiredBindingRules.Count)"
Write-Output "R4-02 review remediation rules: $($reviewRemediationPatterns.Count)"
Write-Output "R4-02 required error codes: $($requiredErrorCodes.Count)"
Write-Output "R4-02 negative scenarios: $($negativeScenarioMarkers.Count)"
Write-Output "R4-03 required contract names: $($requiredR403ContractNames.Count)"
Write-Output "R4-03 action types: $($requiredActionTypes.Count)"
Write-Output "R4-03 exact action check bindings: $($requiredActionCheckBindings.Count)"
Write-Output "R4-03 exact requester bindings: $($requiredActionRequesterBindings.Count)"
Write-Output "R4-03 ActionCheck types: $($requiredActionChecks.Count)"
Write-Output "R4-03 shared human review fields: $($requiredSharedReviewFields.Count)"
Write-Output 'R4-03 exact LLM call blocks: 2'
Write-Output "R4-03 authority errors: $($requiredAuthorityErrors.Count)"
Write-Output "R4-03 authority scenarios: $($authorityScenarioMarkers.Count)"
Write-Output "R4-03 authority rules: $($requiredAuthorityRules.Count)"
Write-Output "R4-03 Sandbox review rules: $($sandboxReviewPatterns.Count)"
Write-Output "R6-R7 environment handoff rules: $($environmentHandoffPatterns.Count)"
Write-Output "R6-R7 environment negative scenarios: $($environmentNegativeMarkers.Count)"
Write-Output "Verification/Chaining contract markers: $($requiredVerificationChainingContracts.Count)"
Write-Output "Verification/Chaining scenarios: $($verificationChainingScenarioMarkers.Count)"
Write-Output "Verification/Chaining semantic rules: $($requiredVerificationChainingRules.Count)"
Write-Output "Production debate policy rules: $($requiredDebatePolicyRules.Count)"
Write-Output "Context failure contract rules: $($requiredContextFailureRules.Count)"
Write-Output "Validation completion contract rules: $($requiredVerificationCompletionRules.Count)"
Write-Output "Validation completion semantic rules: $($requiredVerificationCompletionSemantics.Count)"
Write-Output "No-verdict hypothesis failure rules: $($requiredHypothesisFailureRules.Count)"
Write-Output "Technical Gate TRUE-only scope rules: $($requiredTechnicalGateScopeRules.Count)"
Write-Output "Obsolete Context failure phrases: $($obsoleteContextFailurePhrases.Count)"
Write-Output "Failures: $($failures.Count)"

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Output "FAIL: $_" }
    $failures | ForEach-Object { Write-Error $_ }
    exit 1
}

Write-Output 'Architecture document validation passed.'
