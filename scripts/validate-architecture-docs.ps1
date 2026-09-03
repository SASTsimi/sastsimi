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
    (Join-Path $repoRoot 'docs/review'),
    (Join-Path $repoRoot 'docs/governance')
)
$forbiddenPatterns = @(
    'RepositorySnapshot',
    'snapshot_id',
    'deterministic Gate',
    'Gate는 규칙 기반 서비스',
    'ReportDraft.human_review_state',
    'human_review_state:',
    'HumanReviewPacket',
    'HumanReviewState',
    'HumanReviewDecision',
    'HUMAN_REVIEWER',
    'PREPARE_HUMAN_REVIEW',
    'SAVE_HUMAN_DECISION',
    'EXTERNAL_DISCLOSURE',
    'PACKET_READY',
    'DISCLOSURE_DENIED',
    'review_packet_id',
    'review_decision_id',
    'reviewer_identity_ref',
    'approved_report_refs',
    'disclosure_targets',
    'NEED_MORE_VALIDATION',
    'WITHHOLD',
    'decision: DISCLOSE',
    'human_reviews'
)
foreach ($path in $activeContractPaths) {
    $files = Get-ChildItem -LiteralPath $path -Recurse -File -Filter '*.md'
    foreach ($file in $files) {
        $text = Get-Content -Raw -LiteralPath $file.FullName
        foreach ($pattern in $forbiddenPatterns) {
            if ($text.Contains($pattern)) {
                Add-Failure "forbidden obsolete active contract '$pattern': $($file.FullName)"
            }
        }
    }
}
foreach ($filePath in @((Join-Path $repoRoot 'README.md'), (Join-Path $repoRoot 'docs/GLOSSARY.md'))) {
    $text = Get-Content -Raw -LiteralPath $filePath
    foreach ($pattern in $forbiddenPatterns) {
        if ($text.Contains($pattern)) {
            Add-Failure "forbidden obsolete active contract '$pattern': $filePath"
        }
    }
}

# Current documentation must not reintroduce the pre-ADR-005 Primitive model.
# Decision records are historical and are intentionally excluded from this scan.
$activeUnifiedPrimitiveFiles = @(
    (Get-Item -LiteralPath (Join-Path $repoRoot 'README.md')),
    (Get-Item -LiteralPath (Join-Path $repoRoot 'docs/GLOSSARY.md')),
    (Get-Item -LiteralPath (Join-Path $repoRoot 'docs/DOCUMENT_GUIDE.md'))
) + @(
    Get-ChildItem -LiteralPath (Join-Path $repoRoot 'docs/architecture-v5') -Recurse -File -Filter '*.md'
) + @(
    Get-ChildItem -LiteralPath (Join-Path $repoRoot 'docs/governance') -Recurse -File -Filter '*.md'
) + @(
    Get-ChildItem -LiteralPath (Join-Path $repoRoot 'docs/review') -Recurse -File -Filter '*.md' |
        Where-Object { $_.FullName -notmatch '[\\/]decisions[\\/]' }
)
$obsoleteUnifiedPrimitivePatterns = @(
    'Gate-qualified',
    'active_required_refs',
    'active_provided_refs',
    'HeldHypothesis',
    'ConfirmedCapability',
    'root_hypothesis_id',
    'chain_depth',
    'bounded_stop_reason',
    'required_preconditions',
    'commit-time Primitive index',
    'PROVIDED Primitive',
    'REQUIRED Primitive'
)
foreach ($file in $activeUnifiedPrimitiveFiles) {
    $text = Get-Content -Raw -LiteralPath $file.FullName
    foreach ($pattern in $obsoleteUnifiedPrimitivePatterns) {
        if ($text.Contains($pattern)) {
            Add-Failure "obsolete pre-ADR-005 Primitive term '$pattern': $($file.FullName)"
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
if (-not $contractText.Contains('`PRO_EVIDENCE | CON_EVIDENCE | DYNAMIC_REPRO`에서는 필수')) {
    Add-Failure 'dynamic reproduction work is not bound to the current Verification parent'
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
        Name = 'dynamic state requires request and uses an exact result pointer when a result exists'
        Pattern = '(?s)동적 재현을 요청하면 `DynamicReproductionState.request_ref`.*?current generation의 exact `DynamicReproductionRequest`.*?`SUCCEEDED \| PARTIAL`에는 `dynamic_result_ref.record_id`가 필수.*?`BLOCKED \| FAILED`.*?결과를 조립하지 못했다면 `dynamic_result_ref=null`'
    },
    @{
        Name = 'dynamic PARTIAL uses structured limitations without fake errors'
        Pattern = '(?s)`DYNAMIC_REPRO`는 정확히 하나의 `DynamicReproductionResult\(status=PARTIAL, failure_reason=NONE\)`.*?`hypothesis_evidence_refs`와 `limitations`가 각각 하나 이상.*?억지로 `error_ids`나 `gap_ids`로 만들지 않는다'
    },
    @{
        Name = 'retryable dynamic failure remains the same blocked work'
        Pattern = '(?s)`BLOCKED` \| `BLOCKED`.*?같은 work의 새 attempt.*?final verdict와 Gate는 없다.*?같은 `work_id`에서 새 `attempt_id`'
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
    'PoC 생성·환경 구성·실행 실패를 `FALSE | HOLD`로 변환함',
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
    'DynamicReproductionRequest:',
    'EnvironmentRequirements:',
    'ReproductionPlan:',
    'EnvironmentRecipe:',
    'SandboxEnvironment:',
    'AgentLog:',
    'PoCBundle:',
    'CleanupLog:',
    'LLMCallSpec:',
    'action_id:',
    'decision_id:',
    'action_decision_ref:',
    'use_status:'
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
    'REQUEST_DYNAMIC_REPRO',
    'RUN_SANDBOX',
    'SAVE_RESULT',
    'CALL_TECHNICAL_GATE',
    'CALL_RULE_SCOPE_GATE',
    'CREATE_REPORT_DRAFT'
)
$actionRequestBlock = [regex]::Match($contractText, '(?ms)^ActionRequest:\s*(.*?)^ActionCheck:').Groups[1].Value
$requiredActionRequestFields = @(
    'requester_identity_ref:',
    'input_refs:',
    'dynamic_request_ref:',
    'reproduction_plan_ref:',
    'result_kind:',
    'candidate_result_ref:',
    'llm_call_spec_ref:',
    'provider_profile_ref:',
    'sandbox_profile_ref:'
)
foreach ($field in $requiredActionRequestFields) {
    if (-not $actionRequestBlock.Contains($field)) {
        Add-Failure "missing R4-03 ActionRequest field: $field"
    }
}

$environmentNeedBlock = [regex]::Match($contractText, '(?ms)^EnvironmentNeed:\s*(.*?)^DynamicReproductionRequest:').Groups[1].Value
$dynamicRequestBlock = [regex]::Match($contractText, '(?ms)^DynamicReproductionRequest:\s*(.*?)^EnvironmentRequirement:').Groups[1].Value
$environmentRequirementBlock = [regex]::Match($contractText, '(?ms)^EnvironmentRequirement:\s*(.*?)^EnvironmentRequirements:').Groups[1].Value
$environmentRequirementsBlock = [regex]::Match($contractText, '(?ms)^EnvironmentRequirements:\s*(.*?)^ReproductionPlan:').Groups[1].Value
$reproductionPlanBlock = [regex]::Match($contractText, '(?ms)^ReproductionPlan:\s*(.*?)^EnvironmentRecipe:').Groups[1].Value
$environmentRecipeBlock = [regex]::Match($contractText, '(?ms)^EnvironmentRecipe:\s*(.*?)^EnvironmentCheck:').Groups[1].Value
$environmentCheckBlock = [regex]::Match($contractText, '(?ms)^EnvironmentCheck:\s*(.*?)^SandboxEnvironment:').Groups[1].Value
$sandboxEnvironmentBlock = [regex]::Match($contractText, '(?ms)^SandboxEnvironment:\s*(.*?)^AgentLogEntry:').Groups[1].Value
$agentLogEntryBlock = [regex]::Match($contractText, '(?ms)^AgentLogEntry:\s*(.*?)^AgentLog:').Groups[1].Value
$agentLogBlock = [regex]::Match($contractText, '(?ms)^AgentLog:\s*(.*?)^PoCBundle:').Groups[1].Value
$pocBundleBlock = [regex]::Match($contractText, '(?ms)^PoCBundle:\s*(.*?)^CleanupEntry:').Groups[1].Value
$cleanupLogBlock = [regex]::Match($contractText, '(?ms)^CleanupLog:\s*(.*?)^DynamicReproductionResult:').Groups[1].Value
$dynamicResultBlock = [regex]::Match($contractText, '(?ms)^DynamicReproductionResult:\s*(.*?)^```').Groups[1].Value
foreach ($field in @('need_id:', 'kind:', 'description:', 'required:', 'source_refs:')) {
    if (-not $environmentNeedBlock.Contains($field)) {
        Add-Failure "missing EnvironmentNeed field: $field"
    }
}
foreach ($field in @('verification_assignment_ref:', 'verification_generation:', 'hypothesis_ref:', 'purpose:', 'initial_verdict:', 'goal:', 'environment_needs:', 'sandbox_profile_ref:', 'code_refs:', 'static_evidence_refs:', 'pro_evidence_ref:', 'con_evidence_ref:')) {
    if (-not $dynamicRequestBlock.Contains($field)) {
        Add-Failure "missing DynamicReproductionRequest field: $field"
    }
}
foreach ($fieldPattern in @(
    'requirement_id:\s*string',
    'kind:\s*APP_ROLE \| AUTH \| DATA \| DATABASE \| SERVICE \| FIXTURE \| MOCK \| VERSION \| HEALTH_CHECK',
    'required:\s*boolean',
    'secret_ref:\s*StoredDataRef \| null',
    'source_refs:\s*\[StoredDataRef\]'
)) {
    if (-not [regex]::IsMatch($environmentRequirementBlock, $fieldPattern)) {
        Add-Failure "missing or invalid EnvironmentRequirement field: $fieldPattern"
    }
}
foreach ($fieldPattern in @('meta:\s*RecordMeta', 'request_ref:\s*StoredDataRef', 'items:\s*\[EnvironmentRequirement\]')) {
    if (-not [regex]::IsMatch($environmentRequirementsBlock, $fieldPattern)) {
        Add-Failure "missing or invalid EnvironmentRequirements field: $fieldPattern"
    }
}
foreach ($field in @('request_ref:', 'purpose:', 'hypothesis_ref:', 'environment_requirements_ref:', 'sandbox_profile_ref:', 'reproduction_goal:', 'context_refs:', 'requested_evidence:')) {
    if (-not $reproductionPlanBlock.Contains($field)) {
        Add-Failure "missing ReproductionPlan field: $field"
    }
}
foreach ($field in @('base_image_digest:', 'built_image_digest:', 'dockerfile_ref:', 'package_manifest_refs:', 'setup_script_refs:', 'account_setup_refs:', 'fixture_refs:', 'mock_service_refs:', 'healthcheck_refs:', 'parent_recipe_ref:', 'recipe_digest:')) {
    if (-not $environmentRecipeBlock.Contains($field)) {
        Add-Failure "missing EnvironmentRecipe field: $field"
    }
}
foreach ($fieldPattern in @(
    'requirement_id:\s*string',
    'status:\s*MATCH \| MISMATCH \| NOT_CHECKED \| ERROR',
    'actual:\s*string \| null',
    'evidence_refs:\s*\[StoredDataRef\]'
)) {
    if (-not [regex]::IsMatch($environmentCheckBlock, $fieldPattern)) {
        Add-Failure "missing or invalid EnvironmentCheck field: $fieldPattern"
    }
}
foreach ($fieldPattern in @(
    'reproduction_plan_ref:\s*StoredDataRef',
    'requirements_ref:\s*StoredDataRef',
    'environment_recipe_ref:\s*StoredDataRef',
    'image_digest:\s*string',
    'container_instance_id:\s*string',
    'container_lifecycle:\s*CREATED \| REUSED',
    'container_creation_reason:\s*INITIAL \| STATE_CHANGED \| CONFIG_CHANGED \| STATE_UNCERTAIN \| null',
    'status:\s*READY \| MISMATCH \| ERROR',
    'checks:\s*\[EnvironmentCheck\]'
)) {
    if (-not [regex]::IsMatch($sandboxEnvironmentBlock, $fieldPattern)) {
        Add-Failure "missing or invalid SandboxEnvironment field: $fieldPattern"
    }
}
foreach ($field in @('event_id:', 'action_id:', 'sequence:', 'action_type:', 'recreation_requested_by:', 'recreation_reason:', 'recreation_details:', 'execution_status:', 'input_refs:', 'output_refs:', 'observation_refs:')) {
    if (-not $agentLogEntryBlock.Contains($field)) {
        Add-Failure "missing AgentLogEntry field: $field"
    }
}
foreach ($field in @('meta:', 'reproduction_plan_ref:', 'entries:')) {
    if (-not $agentLogBlock.Contains($field)) {
        Add-Failure "missing AgentLog field: $field"
    }
}
foreach ($field in @('reproduction_plan_ref:', 'environment_recipe_ref:', 'sandbox_environment_ref:', 'file_refs:', 'entrypoint_ref:', 'execution_command_ref:', 'attack_input_refs:', 'bundle_digest:')) {
    if (-not $pocBundleBlock.Contains($field)) {
        Add-Failure "missing PoCBundle field: $field"
    }
}
if (-not $cleanupLogBlock.Contains('entries:')) {
    Add-Failure 'missing CleanupLog entries field'
}
foreach ($fieldPattern in @(
    'action_decision_ref:\s*StoredDataRef',
    'request_ref:\s*StoredDataRef',
    'reproduction_plan_ref:\s*StoredDataRef',
    'purpose:\s*POC_CONFIRMATION \| VERDICT_EVIDENCE',
    'policy_decision_ref:\s*StoredDataRef \| null',
    'agent_invoked:\s*boolean',
    'environment_created:\s*boolean',
    'environment_ref:\s*StoredDataRef \| null',
    'environment_recipe_ref:\s*StoredDataRef \| null',
    'agent_log_ref:\s*StoredDataRef \| null',
    'poc_candidate_ref:\s*StoredDataRef \| null',
    'poc_ref:\s*StoredDataRef \| null',
    'failure_reason:\s*string \| null',
    'plan_execution_status:\s*EXECUTABLE \| EXECUTABLE_WITH_LIMITATIONS \| NEEDS_REVISION',
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
    REQUEST_DYNAMIC_REPRO = 'SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET'
    RUN_SANDBOX = 'SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET'
    SAVE_RESULT = 'SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, REDACTION'
    CALL_TECHNICAL_GATE = 'SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET, PROVIDER, SESSION, GATE_ORDER, REDACTION'
    CALL_RULE_SCOPE_GATE = 'SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET, PROVIDER, SESSION, GATE_ORDER, REDACTION'
    CREATE_REPORT_DRAFT = 'SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET, PROVIDER, SESSION, REPORT_READY, REDACTION'
}
foreach ($binding in $requiredActionCheckBindings.GetEnumerator()) {
    $rowPattern = '(?m)^\| `' + [regex]::Escape($binding.Key) + '`\s*\|\s*' + [regex]::Escape($binding.Value) + '\s*\|'
    if ([regex]::Matches($contractText, $rowPattern).Count -ne 1) {
        Add-Failure "wrong R4-03 required checks for action: $($binding.Key)"
    }
}

$requiredActionRequesterBindings = [ordered]@{
    REGISTER_WORK = 'ORCHESTRATION, VERIFICATION, RECOVERY'
    CHANGE_WORK_STATE = 'ORCHESTRATION, VERIFICATION, REPRODUCTION_SESSION_MANAGER, RECOVERY'
    START_ATTEMPT = 'ORCHESTRATION, VERIFICATION, REPRODUCTION_SESSION_MANAGER, RECOVERY'
    CANCEL_WORK = 'ORCHESTRATION, VERIFICATION, REPRODUCTION_SESSION_MANAGER, RECOVERY'
    READ_CODE = 'HYPOTHESIS, PRO, CON, VERIFICATION, CWE_LABELING, TECHNICAL_GATE'
    RUN_TOOL = 'REPOSITORY_LOADER, STATIC_ANALYSIS, POLICY_COLLECTOR'
    CALL_LLM = 'HYPOTHESIS, PRO, CON, VERIFICATION, CWE_LABELING, CHAINING, REPRODUCTION_AGENT'
    FETCH_POLICY = 'POLICY_COLLECTOR'
    REQUEST_DYNAMIC_REPRO = 'VERIFICATION'
    RUN_SANDBOX = 'REPRODUCTION_AGENT'
    SAVE_RESULT = 'ORCHESTRATION, HYPOTHESIS, PRO, CON, VERIFICATION, CWE_LABELING, CHAINING, TECHNICAL_GATE, RULE_SCOPE_GATE, REPORTER, REPOSITORY_LOADER, STATIC_ANALYSIS, POLICY_COLLECTOR, REPRODUCTION_AGENT, REPRODUCTION_SESSION_MANAGER, RECOVERY'
    CALL_TECHNICAL_GATE = 'VERIFICATION'
    CALL_RULE_SCOPE_GATE = 'VERIFICATION'
    CREATE_REPORT_DRAFT = 'VERIFICATION'
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
    'REDACTION'
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

$analysisRunResultBlock = [regex]::Match($contractText, '(?ms)^AnalysisRunResult:\s*(.*?)^```').Groups[1].Value
$requiredAnalysisResultFields = @('finding_refs:', 'verification_refs:', 'cwe_label_refs:', 'technical_review_refs:', 'rule_scope_review_refs:', 'policy_record_refs:', 'dynamic_request_refs:', 'dynamic_result_refs:', 'poc_candidate_refs:', 'poc_refs:', 'report_draft_refs:', 'llm_invocation_log_refs:', 'action_decision_refs:', 'work_state_refs:', 'work_attempt_refs:', 'transition_commit_refs:', 'debug_trace_ref:')
foreach ($field in $requiredAnalysisResultFields) {
    if (-not $analysisRunResultBlock.Contains($field)) {
        Add-Failure "missing AnalysisRunResult handoff field: $field"
    }
}
if ($contractText -match 'POLICY_BLOCKED[^\r\n]*정적·찬반[^\r\n]*`ACCEPT`') {
    Add-Failure 'POLICY_BLOCKED without a validated PoC must not reach Technical ACCEPT'
}
if (-not $contractText.Contains('한도를 소진하면 `DynamicReproductionResult(status=FAILED, hypothesis_outcome=INCONCLUSIVE, poc_ref=null)`로 반환하며 R6가 후속 흐름을 결정한다.')) {
    Add-Failure 'R7 retry exhaustion result handling is missing'
}
$reportDraftBlock = [regex]::Match($contractText, '(?ms)^ReportDraft:\s*(.*?)^```').Groups[1].Value
foreach ($field in @('finding_ref:', 'dynamic_result_ref:', 'poc_ref:', 'restrictions:', 'limitations:', 'unresolved_conditions:', 'redaction_status: PASSED')) {
    if (-not $reportDraftBlock.Contains($field)) {
        Add-Failure "missing ReportDraft safety field: $field"
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
    'ReportDraft 이후 Agent 자동화를 계속하려 함',
    'Agent가 사람 검토·외부 제출·공개 action을 요청',
    '선행 결과가 바뀐 오래된 ReportDraft를 current 결과로 사용',
    'restriction·limitation 또는 redaction 상태가 빠진 초안을 저장',
    '같은 ActionRequest를 동시에 두 번 검사',
    'Gate 또는 Reporter가 별도 CALL_LLM으로 우회',
    'Technical Gate `REVISE` 뒤 같은 입력으로 재투표',
    'action 허가 뒤 Gate 입력 revision이 바뀜',
    'Runtime Validator가 공식 정책 의미를 다시 판단',
    'Pro와 Con이 같은 session 또는 parent를 공유',
    '`SAVE_RESULT` 검사 뒤 candidate bytes를 바꿈',
    '실행 오류만 든 `FALSE` 후보를 저장',
    '다른 역할이 만든 결과 후보를 저장'
    '`RUN_SANDBOX` 허가 뒤 request·plan·requirements·profile revision이 바뀜'
    'Agent가 Sandbox 외부 경계에 접근하려 함'
    'AgentLog·환경·PoC·cleanup이 서로 다른 attempt를 가리킴'
    'Verification 또는 Agent가 최종 `DynamicReproductionResult`를 직접 저장'
)
foreach ($marker in $authorityScenarioMarkers) {
    if (-not $securityText.Contains($marker)) {
        Add-Failure "missing R4-03 authority scenario: $marker"
    }
}

$sandboxReviewPatterns = @(
    @{
        Name = 'Sandbox Controller enforces only external boundaries'
        Pattern = '(?s)`RUN_SANDBOX`의 ALLOW.*?Sandbox Controller.*?Docker socket.*?host mount.*?production secret.*?다른 workspace.*?외부 경계.*?개별 command.*?실행 순서를 사전 허가하지 않는다'
    },
    @{
        Name = 'Setup Automation creates a clean Sandbox and Agent runs autonomously'
        Pattern = '(?s)R7 Sandbox Setup Automation이 clean Sandbox를 만들고 Reproduction Agent가 내부 환경·PoC·command·관찰·재시도를 자율 수행'
    },
    @{
        Name = 'Session Manager finalizes pre-agent failures and requires AgentLog after invocation'
        Pattern = '(?s)`agent_invoked=false`이면 `agent_log_ref=null`.*?Session Manager.*?실패·차단·취소 결과를 확정.*?`agent_invoked=true`이면.*?`AgentLog`가 필수'
    },
    @{
        Name = 'AgentLog events are durable and attempt scoped'
        Pattern = '(?s)`event_id`는 전역.*?`sequence`는 attempt 안에서 단조 증가.*?`action_id`.*?crash.*?이전 attempt event를 현재 결과에 연결하지 않는다'
    },
    @{
        Name = 'cleanup NOT_REQUIRED is limited to attempts without targets'
        Pattern = '(?s)cleanup은 R6 요청이 아니라 R7 lifecycle 책임.*?`cleanup_required=true`.*?`cleanup_log_ref`.*?정리 대상이 전혀 없을 때만 `NOT_REQUIRED`'
    },
    @{
        Name = 'PoC candidate and validated PoC are distinct'
        Pattern = '(?s)`poc_candidate_ref`.*?성공을 뜻하지 않는다.*?`poc_ref`는 `SUCCEEDED \+ SUPPORTED`.*?같은 candidate digest.*?`poc_ref=null`'
    },
    @{
        Name = 'R7 producer authority is split between Agent and Session Manager'
        Pattern = '(?s)`environment_requirements -> EnvironmentRequirements -> REPRODUCTION_AGENT`.*?`reproduction_plan -> ReproductionPlan -> REPRODUCTION_AGENT`.*?`agent_log -> AgentLog -> REPRODUCTION_SESSION_MANAGER`.*?`dynamic_reproduction_result -> DynamicReproductionResult -> REPRODUCTION_SESSION_MANAGER`'
    }
)
foreach ($rule in $sandboxReviewPatterns) {
    if (-not [regex]::IsMatch($contractText, $rule.Pattern)) {
        Add-Failure "missing or weakened PR #27 Sandbox review rule: $($rule.Name)"
    }
}

$environmentHandoffPatterns = @(
    @{
        Name = 'R6 owns the immutable request and R7 Agent owns requirements and plan'
        Pattern = '(?s)`DynamicReproductionRequest`는 R6 Verification.*?불변 record.*?`EnvironmentRequirements`와 `ReproductionPlan`은 R7 Reproduction Agent'
    },
    @{
        Name = 'R7 plan binds the exact request and current requirements'
        Pattern = '(?s)plan의 `request_ref`, `purpose`, `hypothesis_ref`와 `sandbox_profile_ref`는 request와 exact match.*?`environment_requirements_ref`는 같은 R7 work'
    },
    @{
        Name = 'R7 uses one Sandbox path and plan does not prescribe exact commands'
        Pattern = '(?s)exact command·payload·실행 순서·cleanup policy를 계약으로 고정하지 않는다.*?모든 동적 재현은 같은 Sandbox 실행 경로'
    },
    @{
        Name = 'EnvironmentRecipe records base and built image digests'
        Pattern = '(?s)`EnvironmentRecipe`.*?base·built image digest.*?`PERSISTENT_BASELINE`.*?writable container는 가설 work를 넘겨 재사용하지 않는다'
    },
    @{
        Name = 'Sandbox reuse and recreation are auditable'
        Pattern = '(?s)container_instance_id:\s*string.*?container_lifecycle:\s*CREATED \| REUSED.*?container_creation_reason:\s*INITIAL \| STATE_CHANGED \| CONFIG_CHANGED \| STATE_UNCERTAIN \| null.*?action_type:.*?SANDBOX_RECREATE.*?recreation_requested_by:\s*REPRODUCTION_AGENT \| R7_RUNTIME \| null.*?recreation_reason:\s*STATE_CHANGED \| CONFIG_CHANGED \| STATE_UNCERTAIN \| null'
    },
    @{
        Name = 'actual environment is tied to the built recipe image'
        Pattern = '(?s)`SandboxEnvironment`.*?`environment_recipe_ref`.*?`image_digest`.*?`built_image_digest`'
    },
    @{
        Name = 'environment secrets use opaque handles only'
        Pattern = '(?s)credential·cookie·token·password.*?저장하지 않는다.*?`secret_ref\(data_kind=secret_handle\)`'
    },
    @{
        Name = 'autonomous execution contracts use a new major schema'
        Pattern = '(?s)exact step/command 대리 실행 모델에서 자율 Agent artifact 모델로 바뀌므로 관련 계약은 새 MAJOR schema'
    }
)
foreach ($rule in $environmentHandoffPatterns) {
    if (-not [regex]::IsMatch($contractText, $rule.Pattern)) {
        Add-Failure "missing or weakened R6-R7 environment handoff rule: $($rule.Name)"
    }
}

$environmentNegativeMarkers = @(
    'ReproductionPlan에 `request_ref` 또는 `environment_requirements_ref`가 없음',
    'R6가 EnvironmentRequirements를 만들거나 수정함',
    'plan과 실제 환경이 다른 requirements revision을 가리킴',
    'Agent가 Sandbox 외부 경계에 접근하려 함',
    'AgentLog·환경·PoC·cleanup이 서로 다른 attempt를 가리킴',
    'Verification 또는 Agent가 최종 `DynamicReproductionResult`를 직접 저장',
    '필수 환경 차이를 숨기거나 `MATCH`로 조작함',
    'PoC 생성·환경 구성·실행 실패를 `FALSE | HOLD`로 변환함',
    '환경 요구사항·실제 값에 credential·token 원문을 저장함',
    'R7이 요구사항·계획을 바꾸고 Sandbox 정책 재검사를 생략함'
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
    '`ReportDraft`는 마지막 Agent 산출물',
    'Agent 자동화 밖에서 사람이 수행한다',
    'UNUSED -> USED',
    'UNUSED -> EXPIRED',
    'requester_identity_ref',
    'valid_until',
    'work_attempt_refs',
    '한 `action_ref.record_id`에는 정확히 하나의 `decision_id`',
    'llm_call_spec_ref',
    'output은 log를 역참조하지 않는다',
    '아직 `outcome_refs`가 비어 있는 revision',
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
        Marker = '`DynamicReproductionResult(status=BLOCKED, failure_reason=POLICY_BLOCKED)`는 가설 반증이나 Technical `REJECT`가 아니다.'
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
        Marker = '오래된 draft는 `AnalysisRunResult.report_draft_refs`의 current 결과에 넣을 수 없다.'
    },
    @{
        Name = 'missing Finding blocks ReportDraft creation'
        Text = $contractText
        Marker = 'Finding이 없으면 `CREATE_REPORT_DRAFT`를 허용하지 않고 `AnalysisRunResult.report_draft_refs=[]`를 유지한다.'
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

$requiredAutomationBoundaryRules = @(
    @{
        Name = 'common contract ends Agent automation after ReportDraft and result finalization'
        Text = $contractText
        Marker = '`ReportDraft`는 마지막 Agent 산출물이고 `AnalysisRunResult` 확정은 새 판단을 생성하지 않는 저장 작업이다. 그 다음 Agent 자동화는 종료된다.'
    },
    @{
        Name = 'Gate and reporting document assigns ReportDraft safety to R5-03'
        Text = $gateText
        Marker = '`ReportDraft`는 R5-03 Reporter와 전체 Agent 파이프라인의 마지막 Agent 산출물이다.'
    },
    @{
        Name = 'overview canonical flow ends automation'
        Text = $overviewText
        Marker = 'Reporter -> ReportDraft -> AnalysisRunResult -> Agent automation end'
    },
    @{
        Name = 'canonical Mermaid shows the Reporter boundary'
        Text = $diagramText
        Marker = 'REPORTER --> DRAFT[ReportDraft with restrictions limitations and redaction passed]'
    },
    @{
        Name = 'Wiki reporting summary ends automation'
        Text = $gateWikiText
        Marker = '`ReportDraft`가 마지막 Agent 산출물이며 `AnalysisRunResult` 확정 뒤 자동화가 끝납니다.'
    }
)
foreach ($rule in $requiredAutomationBoundaryRules) {
    if (-not $rule.Text.Contains($rule.Marker)) {
        Add-Failure "missing or weakened R5-03 automation boundary: $($rule.Name)"
    }
}

$requiredVerificationChainingContracts = @(
    'VerificationAssignment:',
    'verification_assignment_ref:',
    'ChainingResult:',
    'source_result_refs:',
    'input_primitive_refs:',
    'primitive_match_candidates:',
    'chained_hypothesis_proposals:',
    'no_match_reasons:',
    'origin: INITIAL | VERIFICATION | CHAINING',
    'source_primitive_match_id: string | null',
    'material_child_proposals:',
    'source_verification_ref:',
    'technical_review_ref:',
    'inputs: [PrimitiveDraft]',
    'result: PrimitiveDraft | null',
    'restrictions: [string]',
    'PrimitiveIndexState:',
    'primitive_refs: [StoredDataRef]',
    'upstream_result_ref: StoredDataRef',
    'downstream_input_ref: StoredDataRef',
    'matched_input_id: string',
    'primitive_and_chaining_refs:'
)
foreach ($marker in $requiredVerificationChainingContracts) {
    if (-not $contractText.Contains($marker)) {
        Add-Failure "missing Verification/Chaining contract: $marker"
    }
}

$primitiveDraftBlock = [regex]::Match($contractText, '(?ms)^PrimitiveDraft:\s*(.*?)^VerificationMetrics:').Groups[1].Value
foreach ($field in @('draft_id:', 'entity_refs:', 'privilege_level: string | null', 'evidence_refs:', 'description:')) {
    if (-not $primitiveDraftBlock.Contains($field)) {
        Add-Failure "PrimitiveDraft is missing unified field: $field"
    }
}
foreach ($field in @('primitive_type:', 'target_asset:', 'endpoint:', 'data_type:')) {
    if ($primitiveDraftBlock.Contains($field)) {
        Add-Failure "PrimitiveDraft still contains obsolete field: $field"
    }
}

$primitiveBlock = [regex]::Match($contractText, '(?ms)^Primitive:\s*(.*?)^PrimitiveIndexState:').Groups[1].Value
foreach ($field in @('workspace_id:', 'commit_id:', 'inputs:', 'result:', 'restrictions:', 'source_hypothesis_id:', 'source_verification_ref:', 'technical_review_ref:', 'evidence_refs:', 'description:')) {
    if (-not $primitiveBlock.Contains($field)) {
        Add-Failure "Primitive is missing unified field: $field"
    }
}
foreach ($field in @('primitive_type:', 'target:', 'status:', 'rule_scope_review_ref:', 'required_preconditions:', 'eligibility:', 'superseded_by_verification_ref:', 'confidence:')) {
    if ($primitiveBlock.Contains($field)) {
        Add-Failure "Primitive still contains obsolete field: $field"
    }
}

$primitiveIndexBlock = [regex]::Match($contractText, '(?ms)^PrimitiveIndexState:\s*(.*?)^PrimitiveMatchCandidate:').Groups[1].Value
foreach ($field in @('current_verification_ref:', 'primitive_refs:', 'updated_at:')) {
    if (-not $primitiveIndexBlock.Contains($field)) {
        Add-Failure "PrimitiveIndexState is missing field: $field"
    }
}
foreach ($field in @('state_version:', 'active_required_refs:', 'active_provided_refs:')) {
    if ($primitiveIndexBlock.Contains($field)) {
        Add-Failure "PrimitiveIndexState still contains obsolete field: $field"
    }
}

$primitiveMatchBlock = [regex]::Match($contractText, '(?ms)^PrimitiveMatchCandidate:\s*(.*?)^ChainingResult:').Groups[1].Value
foreach ($field in @('upstream_result_ref:', 'downstream_input_ref:', 'matched_input_id:', 'parent_hypothesis_ids:', 'parent_verification_refs:', 'workspace_id:', 'commit_id:', 'normalized_fingerprint:', 'evidence_refs:', 'candidate_state: UNVALIDATED')) {
    if (-not $primitiveMatchBlock.Contains($field)) {
        Add-Failure "PrimitiveMatchCandidate is missing field: $field"
    }
}
foreach ($field in @('match_kind:', 'input_primitive_index_refs:', 'upstream_provided_ref:', 'matched_requirement_id:', 'asset_check:', 'entity_check:', 'endpoint_check:', 'privilege_check:', 'data_check:', 'attack_order_check:', 'restriction_check:', 'unresolved_conditions:')) {
    if ($primitiveMatchBlock.Contains($field)) {
        Add-Failure "PrimitiveMatchCandidate still contains obsolete field: $field"
    }
}

$chainingResultBlock = [regex]::Match($contractText, '(?ms)^ChainingResult:\s*(.*?)^```').Groups[1].Value
foreach ($field in @('trigger:', 'input_primitive_index_refs:', 'bounded_stop_reason:')) {
    if ($chainingResultBlock.Contains($field)) {
        Add-Failure "ChainingResult still contains obsolete field: $field"
    }
}

foreach ($record in @('HeldHypothesis:', 'ConfirmedCapability:')) {
    if ($contractText.Contains($record)) {
        Add-Failure "obsolete duplicate Chaining record remains: $record"
    }
}
foreach ($field in @('root_hypothesis_id:', 'chain_depth:')) {
    if ($contractText.Contains($field)) {
        Add-Failure "obsolete derived hypothesis lineage field remains: $field"
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
    '| N7 | result가 있는 TRUE Primitive + result가 없는 HOLD Primitive |',
    '| N8 | result가 있는 서로 다른 TRUE Primitive 둘 |',
    '| N9 | TRUE+TRUE 입력 중 한 부모가 Gate 전 또는 Technical 비정상 결과 |',
    '| N10 | match의 entity 또는 privilege 충족 근거가 없음 |',
    '| N10-A | 후보가 조상 경로에서 이미 사용한 Primitive를 다시 사용 |',
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
    'Gate 전 TRUE는 result가 있는 Primitive가 될 수 없다.',
    'origin=VERIFICATION',
    'origin=CHAINING',
    'TRUE_HOLD',
    'TRUE_TRUE',
    'upstream result가 downstream input을 충족',
    'HypothesisProcessState.status=TERMINAL',
    'VerificationAssignment.owner_identity_ref',
    'ancestor Primitive를 현재 순회의 후보에서 제외한다.',
    'Technical `ACCEPT`은 체이닝 재료의 자격을 확정하고 Rule Scope는 보고 가능성만 판단한다.',
    'Rule Scope 결과는 이미 admission된 Primitive를 취소하지 않는다.',
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

$requiredValidatedPocContractMarkers = @(
    'DynamicReproductionRequest:',
    'purpose: POC_CONFIRMATION | VERDICT_EVIDENCE',
    'dynamic_request_ref: StoredDataRef | null',
    'request_ref: StoredDataRef',
    'poc_candidate_ref: StoredDataRef | null',
    '`dynamic_reproduction_request -> DynamicReproductionRequest -> VERIFICATION`',
    '`environment_requirements -> EnvironmentRequirements -> REPRODUCTION_AGENT`',
    '`reproduction_plan -> ReproductionPlan -> REPRODUCTION_AGENT`',
    'final `TRUE`에는 current Verification generation의 exact `DynamicReproductionRequest`',
    '`SUCCEEDED + SUPPORTED`',
    'validated `poc_ref`',
    '한 Verification generation에는 `DYNAMIC_REPRO` work를 최대 하나만',
    'candidate 생성·환경 구성·실행 실패'
)
foreach ($marker in $requiredValidatedPocContractMarkers) {
    if (-not $contractText.Contains($marker)) {
        Add-Failure "missing validated PoC contract marker: $marker"
    }
}

$requiredValidatedPocCrossDocumentMarkers = @(
    @{
        Name = 'R6 sends purpose-bound dynamic request and R7 owns production'
        Text = $verificationText
        Marker = 'R6는 `DynamicReproductionRequest`만 생산하고 R7은 `EnvironmentRequirements`, `ReproductionPlan`, PoC candidate와 `DynamicReproductionResult`를 생산한다.'
    },
    @{
        Name = 'overview blocks TRUE without validated PoC'
        Text = $overviewText
        Marker = 'validated PoC가 없는 `TRUE`는 저장하거나 Technical Gate로 전달하지 않는다.'
    },
    @{
        Name = 'canonical diagram shows the validated PoC gate'
        Text = $diagramText
        Marker = 'POCOK{Validated PoC and supported result}'
    },
    @{
        Name = 'security negative scenario rejects PoC-less TRUE'
        Text = $securityText
        Marker = 'validated PoC 없이 `TRUE` 저장 또는 Technical Gate 호출'
    }
)
foreach ($rule in $requiredValidatedPocCrossDocumentMarkers) {
    if (-not $rule.Text.Contains($rule.Marker)) {
        Add-Failure "missing validated PoC cross-document rule: $($rule.Name)"
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
Write-Output "R4-03 AnalysisRunResult handoff fields: $($requiredAnalysisResultFields.Count)"
Write-Output 'R5-03 ReportDraft safety fields: 7'
Write-Output 'R4-03 exact LLM call blocks: 2'
Write-Output "R4-03 authority errors: $($requiredAuthorityErrors.Count)"
Write-Output "R4-03 authority scenarios: $($authorityScenarioMarkers.Count)"
Write-Output "R4-03 authority rules: $($requiredAuthorityRules.Count)"
Write-Output "R5-03 automation boundary rules: $($requiredAutomationBoundaryRules.Count)"
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
Write-Output "Validated PoC contract markers: $($requiredValidatedPocContractMarkers.Count)"
Write-Output "Validated PoC cross-document rules: $($requiredValidatedPocCrossDocumentMarkers.Count)"
Write-Output "Obsolete Context failure phrases: $($obsoleteContextFailurePhrases.Count)"
Write-Output "Failures: $($failures.Count)"

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Output "FAIL: $_" }
    $failures | ForEach-Object { Write-Error $_ }
    exit 1
}

Write-Output 'Architecture document validation passed.'
