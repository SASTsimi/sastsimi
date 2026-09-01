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
        Pattern = '(?s)`DYNAMIC_REPRO`는 정확히 하나의 `DynamicReproductionResult\(status=PARTIAL, failure_reason=NONE\)`.*?`hypothesis_evidence_refs`와 `limitations`가 각각 하나 이상.*?억지로 `error_ids`나 `gap_ids`로 만들지 않는다'
    },
    @{
        Name = 'terminal dynamic BLOCKED maps to completed common work'
        Pattern = '(?s)`BLOCKED` \+ `POLICY_BLOCKED` \| `SUCCEEDED`.*?공통 `WorkExecutionState.status=BLOCKED`는.*?비종료 상태에만 사용'
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
$requiredErrorCodes = @(
    'STATE_TRANSITION_INVALID',
    'STATE_VERSION_CONFLICT',
    'ATTEMPT_NOT_ACTIVE',
    'STALE_RESULT',
    'TRANSITION_INCOMPLETE',
    'RECOVERY_FAILED',
    'INTERRUPTED'
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
    '동적 `BLOCKED + POLICY_BLOCKED` 결과를 공통 work `BLOCKED`에 연결',
    '동적 종료 결과와 work·전문 상태 pointer가 다름',
    '분석 종료 시 `RUNNING` work나 `PREPARED` journal이 남음',
    '`COMMITTED` marker 투영 전에 취소·retry 전이가 경쟁'
    '모순된 `ALLOW`가 Reporter 호출을 요청'
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
    'ReproductionPlan:',
    'SandboxStepLog:',
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

$reproductionStepBlock = [regex]::Match($contractText, '(?ms)^ReproductionStep:\s*(.*?)^ReproductionPlan:').Groups[1].Value
$reproductionPlanBlock = [regex]::Match($contractText, '(?ms)^ReproductionPlan:\s*(.*?)^SandboxStepEntry:').Groups[1].Value
$sandboxStepLogBlock = [regex]::Match($contractText, '(?ms)^SandboxStepLog:\s*(.*?)^DynamicReproductionResult:').Groups[1].Value
$dynamicResultBlock = [regex]::Match($contractText, '(?ms)^DynamicReproductionResult:\s*(.*?)^```').Groups[1].Value
foreach ($field in @('step_id:', 'command_ref:', 'attack_input_refs:', 'required:')) {
    if (-not $reproductionStepBlock.Contains($field)) {
        Add-Failure "missing ReproductionStep field: $field"
    }
}
foreach ($field in @('mode:', 'hypothesis_ref:', 'sandbox_profile_ref:', 'steps:', 'cleanup_policy_ref:')) {
    if (-not $reproductionPlanBlock.Contains($field)) {
        Add-Failure "missing ReproductionPlan field: $field"
    }
}
foreach ($field in @('meta:', 'reproduction_plan_ref:', 'entries:')) {
    if (-not $sandboxStepLogBlock.Contains($field)) {
        Add-Failure "missing SandboxStepLog field: $field"
    }
}
foreach ($fieldPattern in @(
    'action_decision_ref:\s*StoredDataRef',
    'reproduction_plan_ref:\s*StoredDataRef',
    'mode:\s*LIMITED_REPRO \| FULL_REPRO',
    'policy_decision_ref:\s*StoredDataRef \| null',
    'runner_invoked:\s*boolean',
    'environment_created:\s*boolean',
    'environment_ref:\s*StoredDataRef \| null',
    'steps_ref:\s*StoredDataRef \| null',
    'poc_ref:\s*StoredDataRef \| null',
    'attack_input_refs:\s*\[StoredDataRef\]',
    'cleanup_policy_ref:\s*StoredDataRef',
    'cleanup_required:\s*boolean',
    'cleanup_status:\s*SUCCEEDED \| FAILED \| NOT_REQUIRED'
)) {
    if (-not [regex]::IsMatch($dynamicResultBlock, $fieldPattern)) {
        Add-Failure "missing or invalid DynamicReproductionResult field: $fieldPattern"
    }
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
    READ_CODE = 'HYPOTHESIS, PRO, CON, VERIFICATION, CWE_LABELING, TECHNICAL_GATE'
    RUN_TOOL = 'REPOSITORY_LOADER, STATIC_ANALYSIS, POLICY_COLLECTOR'
    CALL_LLM = 'HYPOTHESIS, PRO, CON, VERIFICATION, CWE_LABELING, CHAINING'
    FETCH_POLICY = 'POLICY_COLLECTOR'
    RUN_SANDBOX = 'VERIFICATION'
    SAVE_RESULT = 'ORCHESTRATION, HYPOTHESIS, PRO, CON, VERIFICATION, CWE_LABELING, CHAINING, TECHNICAL_GATE, RULE_SCOPE_GATE, REPORTER, REPOSITORY_LOADER, STATIC_ANALYSIS, POLICY_COLLECTOR, SANDBOX, RECOVERY'
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
    '`RUN_SANDBOX` 허가 뒤 재현 계획·공격 입력·cleanup revision이 바뀜'
    'Sandbox가 계획에 없는 command·공격 입력을 실행하려 함'
    '동적 결과의 step log·공격 입력·cleanup 정책이 승인 계획과 다름'
    'Verification이 `DynamicReproductionResult`를 직접 저장'
)
foreach ($marker in $authorityScenarioMarkers) {
    if (-not $securityText.Contains($marker)) {
        Add-Failure "missing R4-03 authority scenario: $marker"
    }
}

$sandboxReviewPatterns = @(
    @{
        Name = 'Runtime Validator authorizes Sandbox calls without duplicating detailed policy checks'
        Pattern = '(?s)`RUN_SANDBOX`의 `ActionDecision=ALLOW`.*?Runtime Validator.*?권한.*?상태.*?예산.*?exact `ReproductionPlan` reference까지만 검사.*?Sandbox Controller.*?image digest.*?command/tool allowlist.*?network target.*?CPU·memory·disk·process·time limit.*?cleanup 정책을 전담 검사'
    },
    @{
        Name = 'RUN_SANDBOX freezes the complete reproduction plan closure'
        Pattern = '(?s)`RUN_SANDBOX`만 `reproduction_plan_ref`를 사용.*?`input_refs`에는 exact `ReproductionPlan`.*?`hypothesis_ref`.*?`sandbox_profile_ref`.*?`command_ref`.*?`attack_input_refs`.*?`cleanup_policy_ref`'
    },
    @{
        Name = 'invoked sandbox execution log exactly matches the authorized plan'
        Pattern = '(?s)`runner_invoked=true`이면.*?exact `SandboxStepLog`를 가리키는 `steps_ref`가 필수.*?`step_id`, `command_ref`, `attack_input_refs`.*?field-by-field exact match.*?계획에 없는 entry를 허용하지 않는다'
    },
    @{
        Name = 'dynamic result save repeats plan and execution checks'
        Pattern = '(?s)`SAVE_RESULT\(requested_by=SANDBOX, result_kind=dynamic_reproduction_result\)`.*?`SCHEMA`.*?`AUTHORITY`.*?`IDENTITY`.*?`REVISION`.*?`STATE`.*?`REDACTION`.*?계획.*?실제 log.*?`COMMITTED`하지 않는다'
    },
    @{
        Name = 'Sandbox result assembler produces and Verification only consumes dynamic results'
        Pattern = '(?s)Sandbox runtime의 비-LLM result assembler만 exact reference를 `DynamicReproductionResult`에 조립.*?Verification은.*?경우에만 이를 읽으며 `DynamicReproductionResult`를 직접 만들거나 수정하지 않는다'
    },
    @{
        Name = 'dynamic result nullable references follow lifecycle facts'
        Pattern = '(?s)`runner_invoked=false`이면 `steps_ref=null`.*?`runner_invoked=true`이면.*?`steps_ref`가 필수.*?`environment_created`.*?`false`이면 `environment_ref=null`.*?`true`이면 `environment_ref`가 필수'
    },
    @{
        Name = 'cleanup NOT_REQUIRED is limited to attempts without cleanup targets'
        Pattern = '(?s)`cleanup_required`.*?`false`이면 `cleanup_status=NOT_REQUIRED`.*?`true`이면 `cleanup_status=SUCCEEDED \| FAILED`만 허용.*?실제 자원이 있는데.*?계약 위반'
    },
    @{
        Name = 'policy blocked result retains the exact Controller decision'
        Pattern = '(?s)`failure_reason=POLICY_BLOCKED`이면.*?`policy_decision_ref`.*?반드시 존재.*?정책의 exact revision.*?`ALLOW \| DENY` 결과와 사유 코드'
    },
    @{
        Name = 'PoC reference does not imply execution or success'
        Pattern = '(?s)`poc_ref`.*?exact `poc_bundle`.*?존재 자체는 실행이나 재현 성공을 뜻하지 않는다.*?`poc_ref`와 `SandboxStepLog`.*?같은 revision 또는 digest'
    },
    @{
        Name = 'Verification owns plans while Sandbox owns dynamic results'
        Pattern = '(?s)`reproduction_plan -> ReproductionPlan -> VERIFICATION`.*?`dynamic_reproduction_result -> DynamicReproductionResult -> SANDBOX`.*?`SAVE_RESULT\(result_kind=reproduction_plan\)`'
    }
)
foreach ($rule in $sandboxReviewPatterns) {
    if (-not [regex]::IsMatch($contractText, $rule.Pattern)) {
        Add-Failure "missing or weakened PR #27 Sandbox review rule: $($rule.Name)"
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
        Marker = '`DynamicReproductionResult(status=BLOCKED, failure_reason=POLICY_BLOCKED)`는 자동 `REJECT` 조건이 아니다.'
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
    '| N16 | 운영 Pro/Con 중 하나를 실행할 예산이 부족 |'
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
Write-Output "Verification/Chaining contract markers: $($requiredVerificationChainingContracts.Count)"
Write-Output "Verification/Chaining scenarios: $($verificationChainingScenarioMarkers.Count)"
Write-Output "Verification/Chaining semantic rules: $($requiredVerificationChainingRules.Count)"
Write-Output "Production debate policy rules: $($requiredDebatePolicyRules.Count)"
Write-Output "Failures: $($failures.Count)"

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Output "FAIL: $_" }
    $failures | ForEach-Object { Write-Error $_ }
    exit 1
}

Write-Output 'Architecture document validation passed.'
